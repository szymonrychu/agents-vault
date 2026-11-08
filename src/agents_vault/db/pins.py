"""Pins: which session uses which version of an entry (spec 5.1). Functions take a connection
and run inside the caller's transaction. Only names, versions and ids are stored."""

from __future__ import annotations

from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

Row = dict[str, Any]


async def lock_session(conn: psycopg.AsyncConnection, session_id: UUID) -> None:
    """Serialise concurrent pin calls of one session until the transaction ends."""
    await conn.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended('vault-pins/' || %s::text, 0))",
        (session_id,),
    )


async def session_pins(conn: psycopg.AsyncConnection, session_id: UUID) -> list[Row]:
    """Every pin row of a session (released or not) with its entry name."""
    cur = conn.cursor(row_factory=dict_row)
    await cur.execute(
        "SELECT p.env, p.entry_id, p.version, e.name FROM pins p"
        " JOIN entries e ON e.id = p.entry_id WHERE p.session_id = %s ORDER BY p.env",
        (session_id,),
    )
    return await cur.fetchall()


async def share_lock_live_entries(conn: psycopg.AsyncConnection, names: list[str]) -> list[Row]:
    """Live, readable entries called `names`, row-locked FOR SHARE: a rotate or delete (FOR
    UPDATE) waits until this transaction ends, so the version read here cannot be retired and
    collected before the pin commits."""
    cur = conn.cursor(row_factory=dict_row)
    await cur.execute(
        "SELECT id, name, labels, current_version FROM entries"
        " WHERE name = ANY(%s) AND deleted_at IS NULL AND current_version > 0"
        " ORDER BY id FOR SHARE",
        (names,),
    )
    return await cur.fetchall()


async def insert_pin(
    conn: psycopg.AsyncConnection, session_id: UUID, env: str, entry_id: UUID, version: int
) -> None:
    await conn.execute(
        "INSERT INTO pins (session_id, env, entry_id, version) VALUES (%s, %s, %s, %s)",
        (session_id, env, entry_id, version),
    )


async def release_session(conn: psycopg.AsyncConnection, session_id: UUID) -> int:
    """Release the live pins of one session; returns how many rows changed."""
    cur = await conn.execute(
        "UPDATE pins SET released_at = now() WHERE session_id = %s AND released_at IS NULL",
        (session_id,),
    )
    return cur.rowcount
