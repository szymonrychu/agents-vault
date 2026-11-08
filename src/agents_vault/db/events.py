"""The events table: names, versions and ids only, never a value (readable values included)."""

from __future__ import annotations

from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


async def add_event(
    conn: psycopg.AsyncConnection,
    kind: str,
    actor: str,
    entry_id: UUID | None,
    entry_name: str | None,
    data: dict[str, Any],
) -> None:
    """Insert one event row; callers build `data` from names, versions and ids only."""
    await conn.execute(
        "INSERT INTO events (kind, actor, entry_id, entry_name, data) VALUES (%s, %s, %s, %s, %s)",
        (kind, actor, entry_id, entry_name, Jsonb(data)),
    )


async def list_events(
    conn: psycopg.AsyncConnection,
    entry: UUID | None = None,
    before_id: int | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Events newest first, optionally of one entry id and older than `before_id`."""
    cur = conn.cursor(row_factory=dict_row)
    await cur.execute(
        "SELECT id, ts, kind, actor, entry_id, entry_name, data FROM events"
        " WHERE (%(entry)s::uuid IS NULL OR entry_id = %(entry)s)"
        " AND (%(before)s::bigint IS NULL OR id < %(before)s)"
        " ORDER BY id DESC LIMIT %(limit)s",
        {"entry": entry, "before": before_id, "limit": limit},
    )
    return await cur.fetchall()
