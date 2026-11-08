import uuid

import pytest

from agents_vault.db import entries as entries_repo
from agents_vault.db import pins as pins_repo


async def _entry(pool, name="A_KEY"):
    entry_id = uuid.uuid4()
    async with pool.connection() as conn, conn.transaction():
        await entries_repo.insert_entry(conn, entry_id, name, "d", [])
        await conn.execute("UPDATE entries SET current_version = 1 WHERE id = %s", (entry_id,))
    return entry_id


async def test_insert_list_and_release(pool):
    entry_id = await _entry(pool)
    sid = uuid.uuid4()
    async with pool.connection() as conn, conn.transaction():
        await pins_repo.insert_pin(conn, sid, "A", entry_id, 1)
        rows = await pins_repo.session_pins(conn, sid)
        assert [(r["env"], r["name"], r["version"]) for r in rows] == [("A", "A_KEY", 1)]
        assert await pins_repo.release_session(conn, sid) == 1
        assert await pins_repo.release_session(conn, sid) == 0


async def test_share_lock_skips_deleted_and_unwritten_entries(pool):
    await _entry(pool, "LIVE_KEY")
    gone = await _entry(pool, "GONE_KEY")
    async with pool.connection() as conn, conn.transaction():
        await entries_repo.soft_delete_entry(conn, gone)
        rows = await pins_repo.share_lock_live_entries(conn, ["LIVE_KEY", "GONE_KEY", "NOPE"])
    assert [r["name"] for r in rows] == ["LIVE_KEY"]


async def test_one_pin_per_session_and_env(pool):
    import psycopg

    entry_id = await _entry(pool)
    sid = uuid.uuid4()
    async with pool.connection() as conn:
        await pins_repo.insert_pin(conn, sid, "A", entry_id, 1)
        with pytest.raises(psycopg.errors.UniqueViolation):
            await pins_repo.insert_pin(conn, sid, "A", entry_id, 1)
