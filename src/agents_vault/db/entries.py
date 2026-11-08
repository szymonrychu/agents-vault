"""Entries and versions: the SQL under the write protocol in `store.py`.

Every function takes a connection and runs inside the caller's transaction. Rows come back as
dicts. A readable env value is stored in `entry_envs.value`; no protected value, nor its hash or
length, is ever stored here (spec 3.2).
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

Row = dict[str, Any]

ENTRY_COLUMNS = "id, name, description, labels, current_version, created_at, updated_at, deleted_at"


async def _one(conn: psycopg.AsyncConnection, query: str, params: Any) -> Row | None:
    cur = conn.cursor(row_factory=dict_row)
    await cur.execute(query, params)
    return await cur.fetchone()


async def _all(conn: psycopg.AsyncConnection, query: str, params: Any) -> list[Row]:
    cur = conn.cursor(row_factory=dict_row)
    await cur.execute(query, params)
    return await cur.fetchall()


async def insert_entry(
    conn: psycopg.AsyncConnection, entry_id: UUID, name: str, description: str, labels: list[str]
) -> None:
    """Insert an entry with current_version 0; a live duplicate name (case-insensitive) raises
    UniqueViolation."""
    await conn.execute(
        "INSERT INTO entries (id, name, description, labels) VALUES (%s, %s, %s, %s)",
        (entry_id, name, description, labels),
    )


async def lock_entry(conn: psycopg.AsyncConnection, entry_id: UUID) -> Row | None:
    """Row lock plus the advisory lock of one entry, both held until the transaction ends."""
    row = await _one(
        conn, f"SELECT {ENTRY_COLUMNS} FROM entries WHERE id = %s FOR UPDATE", (entry_id,)
    )
    await conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended('vault/' || %s::text, 0))", (entry_id,)
    )
    return row


async def lock_live_entry(conn: psycopg.AsyncConnection, entry_id: UUID) -> Row | None:
    """Lock the live, readable entry `entry_id` (deleted_at null, a current version)."""
    row = await lock_entry(conn, entry_id)
    if row is None or row["deleted_at"] is not None or row["current_version"] < 1:
        return None
    return row


async def get_entry(conn: psycopg.AsyncConnection, entry_id: UUID) -> Row | None:
    return await _one(
        conn,
        f"SELECT {ENTRY_COLUMNS} FROM entries"
        " WHERE id = %s AND deleted_at IS NULL AND current_version > 0",
        (entry_id,),
    )


async def live_by_ids(conn: psycopg.AsyncConnection, entry_ids: list[UUID]) -> list[Row]:
    """Live, readable entries `entry_ids` (no lock: read-only resolve)."""
    return await _all(
        conn,
        f"SELECT {ENTRY_COLUMNS} FROM entries"
        " WHERE id = ANY(%s) AND deleted_at IS NULL AND current_version > 0",
        (entry_ids,),
    )


async def insert_envs(
    conn: psycopg.AsyncConnection, entry_id: UUID, envs: list[tuple[str, bool, str | None]]
) -> None:
    """The entry's ordered env set: (env, protected, readable value or None when protected)."""
    async with conn.cursor() as cur:
        await cur.executemany(
            "INSERT INTO entry_envs (entry_id, env, position, protected, value)"
            " VALUES (%s, %s, %s, %s, %s)",
            [
                (entry_id, env, position, protected, value)
                for position, (env, protected, value) in enumerate(envs)
            ],
        )


async def envs_of(conn: psycopg.AsyncConnection, entry_ids: list[UUID]) -> list[Row]:
    """The env rows of `entry_ids`, in entry order then env position."""
    return await _all(
        conn,
        "SELECT entry_id, env, protected, value, updated_at FROM entry_envs"
        " WHERE entry_id = ANY(%s) ORDER BY entry_id, position",
        (entry_ids,),
    )


async def update_env_values(
    conn: psycopg.AsyncConnection, entry_id: UUID, values: dict[str, str]
) -> None:
    """New values of readable envs, in place (no version); call under `lock_entry`."""
    async with conn.cursor() as cur:
        await cur.executemany(
            "UPDATE entry_envs SET value = %s, updated_at = now()"
            " WHERE entry_id = %s AND env = %s AND NOT protected",
            [(value, entry_id, env) for env, value in values.items()],
        )


def _like(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


async def list_entries(
    conn: psycopg.AsyncConnection,
    q: str | None = None,
    labels: list[str] | None = None,
    name: str | None = None,
) -> list[Row]:
    """Live entries by name; `q` is a case-insensitive substring of name, description or a
    label, `labels` keeps entries sharing at least one of them, `name` is an exact
    case-insensitive name."""
    where = ["deleted_at IS NULL", "current_version > 0"]
    params: dict[str, Any] = {}
    if name is not None:
        where.append("lower(name) = lower(%(name)s)")
        params["name"] = name
    if q:
        where.append(
            "(name ILIKE %(q)s OR description ILIKE %(q)s"
            " OR EXISTS (SELECT 1 FROM unnest(labels) AS l WHERE l ILIKE %(q)s))"
        )
        params["q"] = _like(q)
    if labels:
        where.append("labels && %(labels)s::text[]")
        params["labels"] = labels
    return await _all(
        conn,
        f"SELECT {ENTRY_COLUMNS} FROM entries WHERE {' AND '.join(where)}"
        " ORDER BY lower(name), name",
        params,
    )


async def entry_versions(conn: psycopg.AsyncConnection, entry_id: UUID) -> list[Row]:
    """Every version of an entry, newest first, with its count of live (unreleased) pins."""
    return await _all(
        conn,
        "SELECT v.version, v.state, v.created_at, v.retired_at, v.deleted_at,"
        " (SELECT count(*) FROM pins p WHERE p.entry_id = v.entry_id AND p.version = v.version"
        "  AND p.released_at IS NULL)::int AS pins"
        " FROM versions v WHERE v.entry_id = %s ORDER BY v.version DESC",
        (entry_id,),
    )


async def pinned_sessions_count(conn: psycopg.AsyncConnection, entry_id: UUID) -> int:
    row = await _one(
        conn,
        "SELECT count(DISTINCT session_id)::int AS n FROM pins"
        " WHERE entry_id = %s AND released_at IS NULL",
        (entry_id,),
    )
    return row["n"] if row else 0


async def behind_count(conn: psycopg.AsyncConnection, entry_id: UUID) -> int:
    """Live pins on a version below the entry's current version."""
    row = await _one(
        conn,
        "SELECT count(*)::int AS n FROM pins p JOIN entries e ON e.id = p.entry_id"
        " WHERE p.entry_id = %s AND p.released_at IS NULL AND p.version < e.current_version",
        (entry_id,),
    )
    return row["n"] if row else 0


async def next_version(conn: psycopg.AsyncConnection, entry_id: UUID) -> int:
    """max(version) + 1; call under `lock_entry`."""
    row = await _one(
        conn,
        "SELECT COALESCE(max(version), 0) + 1 AS n FROM versions WHERE entry_id = %s",
        (entry_id,),
    )
    assert row is not None
    return row["n"]


async def insert_writing(conn: psycopg.AsyncConnection, entry_id: UUID, version: int) -> None:
    await conn.execute(
        "INSERT INTO versions (entry_id, version, state) VALUES (%s, %s, 'writing')",
        (entry_id, version),
    )


async def version_state(conn: psycopg.AsyncConnection, entry_id: UUID, version: int) -> str | None:
    row = await _one(
        conn,
        "SELECT state FROM versions WHERE entry_id = %s AND version = %s",
        (entry_id, version),
    )
    return row["state"] if row else None


async def retire_failed_version(
    conn: psycopg.AsyncConnection, entry_id: UUID, version: int
) -> None:
    """A version whose Secret was never written: retired and its Secret marked gone."""
    await conn.execute(
        "UPDATE versions SET state = 'retired', retired_at = now(), deleted_at = now()"
        " WHERE entry_id = %s AND version = %s",
        (entry_id, version),
    )


async def unstamp_version(conn: psycopg.AsyncConnection, entry_id: UUID, version: int) -> None:
    """A retired version whose Secret may exist again: GC owns its delete once more."""
    await conn.execute(
        "UPDATE versions SET deleted_at = NULL WHERE entry_id = %s AND version = %s"
        " AND state = 'retired'",
        (entry_id, version),
    )


async def stamp_version_deleted(
    conn: psycopg.AsyncConnection, entry_id: UUID, version: int
) -> None:
    """A retired version whose Secret was just deleted by the writer: record it gone."""
    await conn.execute(
        "UPDATE versions SET deleted_at = now() WHERE entry_id = %s AND version = %s"
        " AND state = 'retired' AND deleted_at IS NULL",
        (entry_id, version),
    )


async def soft_delete_entry(conn: psycopg.AsyncConnection, entry_id: UUID) -> None:
    await conn.execute(
        "UPDATE entries SET deleted_at = now(), updated_at = now() WHERE id = %s", (entry_id,)
    )


async def retire_unwritten_version(
    conn: psycopg.AsyncConnection, entry_id: UUID, version: int
) -> None:
    """A written version that lost a race: retired at once, its Secret left for the sweeper."""
    await conn.execute(
        "UPDATE versions SET state = 'retired', retired_at = now()"
        " WHERE entry_id = %s AND version = %s",
        (entry_id, version),
    )


async def make_current(conn: psycopg.AsyncConnection, entry_id: UUID, version: int) -> None:
    """Version `version` live, every other live version retired, current_version moved."""
    await conn.execute(
        "UPDATE versions SET state = 'retired', retired_at = now()"
        " WHERE entry_id = %s AND state = 'live' AND version <> %s",
        (entry_id, version),
    )
    await conn.execute(
        "UPDATE versions SET state = 'live' WHERE entry_id = %s AND version = %s",
        (entry_id, version),
    )
    await conn.execute(
        "UPDATE entries SET current_version = %s, updated_at = now() WHERE id = %s",
        (version, entry_id),
    )


async def update_fields(
    conn: psycopg.AsyncConnection, entry_id: UUID, name: str, description: str, labels: list[str]
) -> None:
    """A live duplicate name (case-insensitive) raises UniqueViolation."""
    await conn.execute(
        "UPDATE entries SET name = %s, description = %s, labels = %s, updated_at = now()"
        " WHERE id = %s",
        (name, description, labels, entry_id),
    )


async def touch(conn: psycopg.AsyncConnection, entry_id: UUID) -> None:
    await conn.execute("UPDATE entries SET updated_at = now() WHERE id = %s", (entry_id,))


async def retire_live_versions(conn: psycopg.AsyncConnection, entry_id: UUID) -> None:
    await conn.execute(
        "UPDATE versions SET state = 'retired', retired_at = now()"
        " WHERE entry_id = %s AND state = 'live'",
        (entry_id,),
    )


async def live_pins(conn: psycopg.AsyncConnection, entry_id: UUID) -> list[Row]:
    """Unreleased pins of an entry, oldest first."""
    return await _all(
        conn,
        "SELECT session_id, env, entry_env, version, created_at FROM pins"
        " WHERE entry_id = %s AND released_at IS NULL ORDER BY created_at, session_id, env",
        (entry_id,),
    )
