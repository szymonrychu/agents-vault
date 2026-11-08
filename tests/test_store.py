import asyncio
import logging
import secrets
import uuid

import pytest
from fakes.fake_kube import FakeKube, FlakyKube
from psycopg.rows import dict_row
from pydantic import SecretStr

from agents_vault import store
from agents_vault.k8s import KubeError, secret_name

canary = secrets.token_hex(16)
NS = "agents"
MAX = 1024


async def create(
    pool, kube, name="API_KEY", value=canary, labels=None, max_bytes=MAX, actor="user"
):
    return await store.create_entry(
        pool,
        kube,
        NS,
        actor,
        name=name,
        description="a key",
        labels=labels or [],
        value=SecretStr(value),
        max_value_bytes=max_bytes,
    )


async def rotate(pool, kube, name="API_KEY", value=canary):
    return await store.rotate_entry(
        pool, kube, NS, "user", name=name, value=SecretStr(value), max_value_bytes=MAX
    )


async def rows(pool, query, params=()):
    async with pool.connection() as conn:
        cur = conn.cursor(row_factory=dict_row)
        await cur.execute(query, params)
        return await cur.fetchall()


async def versions(pool, entry_id):
    return await rows(
        pool, "SELECT * FROM versions WHERE entry_id = %s ORDER BY version", (entry_id,)
    )


async def test_create_makes_version_one_live(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube, labels=["Team-A"])
    entry = await store.get_entry(pool, "API_KEY")
    assert entry["id"] == entry_id
    assert entry["current_version"] == 1
    assert entry["labels"] == ["team-a"]
    (v,) = await versions(pool, entry_id)
    assert (v["version"], v["state"], v["deleted_at"]) == (1, "live", None)
    assert kube.has("Secret", secret_name(entry_id, 1))
    (event,) = await store.list_events(pool, "API_KEY")
    assert event["kind"] == "entry_created"
    assert event["actor"] == "user"
    assert event["data"] == {"name": "API_KEY", "labels": ["team-a"]}
    assert canary not in str(event)


async def test_duplicate_live_name_is_taken(pool):
    kube = FakeKube()
    await create(pool, kube)
    with pytest.raises(store.NameTaken):
        await create(pool, kube)


async def test_recreate_after_delete_gets_a_new_uuid_and_version_one(pool):
    kube = FakeKube()
    first = await create(pool, kube)
    await store.delete_entry(pool, "user", name="API_KEY")
    second = await create(pool, kube)
    assert second != first
    entry = await store.get_entry(pool, "API_KEY")
    assert entry["id"] == second
    assert entry["current_version"] == 1


async def test_size_is_checked_in_utf8_bytes_before_any_row_or_kube_call(pool):
    kube = FakeKube()
    with pytest.raises(store.SecretTooLarge):
        await create(pool, kube, value="x" * (MAX + 1))
    # 513 two-byte characters: 1026 bytes, over the cap although only 513 characters
    with pytest.raises(store.SecretTooLarge):
        await create(pool, kube, value="\u00e9" * 513)
    assert kube.calls == []
    assert await rows(pool, "SELECT 1 FROM entries") == []
    # exactly the cap passes, multi-byte characters included
    await create(pool, kube, value="\u00e9" * 512)
    assert len(kube.applies) == 1


async def test_value_with_whitespace_is_stored_unchanged(pool):
    kube = FakeKube()
    value = f" {canary}\n"
    await create(pool, kube, value=value)
    assert kube.applies[0].obj["stringData"] == {"value": value}


async def test_create_failure_soft_deletes_the_entry(pool, caplog, monkeypatch):
    caplog.set_level(logging.DEBUG)
    kube = FakeKube()
    fixed = uuid.uuid4()
    ids = iter([fixed])
    monkeypatch.setattr(store.uuid, "uuid4", lambda: next(ids, None) or uuid.UUID(int=7))
    kube.fail("Secret", secret_name(fixed, 1), KubeError(f"422: body {canary}"), verbs=["patch"])
    with pytest.raises(store.SecretStoreFailed) as exc:
        await create(pool, kube)
    assert canary not in str(exc.value)
    assert exc.value.__cause__ is None and exc.value.__context__ is None
    (entry,) = await rows(pool, "SELECT * FROM entries")
    assert entry["id"] == fixed
    assert entry["deleted_at"] is not None
    (v,) = await versions(pool, entry["id"])
    assert v["state"] == "retired"
    assert v["deleted_at"] is not None
    assert await store.get_entry(pool, "API_KEY") is None
    assert canary not in caplog.text
    assert "KubeError" in caplog.text
    await create(pool, kube)  # the name is free again


async def test_rotate_makes_version_two_current(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube)
    assert await rotate(pool, kube, value="new") == 2
    v1, v2 = await versions(pool, entry_id)
    assert (v1["state"], v1["retired_at"] is not None) == ("retired", True)
    assert v2["state"] == "live"
    assert (await store.get_entry(pool, "API_KEY"))["current_version"] == 2
    kinds = [e["kind"] for e in await store.list_events(pool, "API_KEY")]
    assert kinds == ["entry_rotated", "entry_created"]


async def test_rotate_unknown_entry(pool):
    with pytest.raises(store.EntryNotFound):
        await rotate(pool, FakeKube(), name="NOPE")


async def test_rotate_failure_keeps_version_one_current(pool, caplog):
    caplog.set_level(logging.DEBUG)
    kube = FakeKube()
    entry_id = await create(pool, kube)
    kube.fail("Secret", secret_name(entry_id, 2), KubeError(f"500: body {canary}"), verbs=["patch"])
    with pytest.raises(store.SecretStoreFailed) as exc:
        await rotate(pool, kube, value=canary)
    assert canary not in str(exc.value)
    v1, v2 = await versions(pool, entry_id)
    assert v1["state"] == "live"
    assert (v2["state"], v2["deleted_at"] is not None) == ("retired", True)
    assert (await store.get_entry(pool, "API_KEY"))["current_version"] == 1
    assert canary not in caplog.text


async def test_concurrent_rotates_leave_one_live_version(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube)
    entered, release = asyncio.Event(), asyncio.Event()
    kube.apply_gate[secret_name(entry_id, 2)] = (entered, release)
    first = asyncio.create_task(rotate(pool, kube, value="one"))
    await entered.wait()  # version 2 is `writing`, its Secret not yet applied
    assert await rotate(pool, kube, value="two") == 3
    release.set()
    assert await first == 2
    vs = await versions(pool, entry_id)
    assert [v["version"] for v in vs] == [1, 2, 3]
    assert [v["version"] for v in vs if v["state"] == "live"] == [3]
    assert (await store.get_entry(pool, "API_KEY"))["current_version"] == 3


async def test_update_normalises_labels_and_records_before_after(pool):
    kube = FakeKube()
    await create(pool, kube, labels=["old"])
    before, after = await store.update_entry(
        pool, "user", name="API_KEY", description="new text", labels=[" A ", "a"]
    )
    assert (before, after) == (["old"], ["a"])
    entry = await store.get_entry(pool, "API_KEY")
    assert entry["labels"] == ["a"]
    assert entry["description"] == "new text"
    event = (await store.list_events(pool, "API_KEY"))[0]
    assert event["kind"] == "entry_updated"
    assert event["data"] == {
        "name": "API_KEY",
        "description_changed": True,
        "labels_before": ["old"],
        "labels_after": ["a"],
    }


async def test_update_rejects_bad_labels(pool):
    kube = FakeKube()
    await create(pool, kube)
    with pytest.raises(ValueError):
        await store.update_entry(pool, "user", name="API_KEY", labels=["project:bad_slug"])
    with pytest.raises(ValueError):
        await store.update_entry(pool, "user", name="API_KEY", labels=[f"l{i}" for i in range(21)])
    with pytest.raises(ValueError):
        await create(pool, kube, name="OTHER", labels=["project:bad_slug"])


async def test_delete_soft_deletes_and_retires_the_live_version(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube)
    await store.delete_entry(pool, "user", name="API_KEY")
    assert await store.get_entry(pool, "API_KEY") is None
    assert await store.list_entries(pool) == []
    (v,) = await versions(pool, entry_id)
    assert v["state"] == "retired"
    assert v["retired_at"] is not None
    assert v["deleted_at"] is None  # the sweeper deletes the Secret once no pin holds it
    with pytest.raises(store.EntryNotFound):
        await store.delete_entry(pool, "user", name="API_KEY")
    assert (await store.list_events(pool, "API_KEY"))[0]["kind"] == "entry_deleted"


async def test_list_entries_filters(pool):
    kube = FakeKube()
    await create(pool, kube, name="B_KEY", labels=["alpha"])
    await create(pool, kube, name="A_KEY", labels=["beta", "gamma"])
    await create(pool, kube, name="C_PCT", labels=[])
    assert [e["name"] for e in await store.list_entries(pool)] == ["A_KEY", "B_KEY", "C_PCT"]
    assert [e["name"] for e in await store.list_entries(pool, q="b_k")] == ["B_KEY"]
    assert [e["name"] for e in await store.list_entries(pool, q="GAMM")] == ["A_KEY"]
    assert [e["name"] for e in await store.list_entries(pool, q="_")] == [
        "A_KEY",
        "B_KEY",
        "C_PCT",
    ]
    assert await store.list_entries(pool, q="%") == []
    assert await store.list_entries(pool, q="\\") == []
    got = await store.list_entries(pool, labels=["alpha", "beta"])
    assert [e["name"] for e in got] == ["A_KEY", "B_KEY"]


async def test_versions_pins_and_behind_count(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube)
    await rotate(pool, kube)
    session = uuid.uuid4()
    other = uuid.uuid4()
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO pins (session_id, env, entry_id, version) VALUES"
            " (%s, 'A', %s, 1), (%s, 'B', %s, 1), (%s, 'A', %s, 2)",
            (session, entry_id, session, entry_id, other, entry_id),
        )
    vs = await store.entry_versions(pool, entry_id)
    assert [(v["version"], v["pins"]) for v in vs] == [(2, 1), (1, 2)]
    assert await store.pinned_sessions_count(pool, entry_id) == 2
    assert await store.behind_count(pool, entry_id) == 2


async def test_list_events_pages_newest_first(pool):
    kube = FakeKube()
    await create(pool, kube)
    await rotate(pool, kube)
    await rotate(pool, kube)
    events = await store.list_events(pool, "API_KEY", limit=2)
    assert [e["kind"] for e in events] == ["entry_rotated", "entry_rotated"]
    older = await store.list_events(pool, "API_KEY", before_id=events[-1]["id"])
    assert [e["kind"] for e in older] == ["entry_created"]


async def test_the_value_is_in_no_row(pool):
    kube = FakeKube()
    await create(pool, kube, value=canary)
    await rotate(pool, kube, value=canary)
    await store.update_entry(pool, "user", name="API_KEY", description="d")
    await store.delete_entry(pool, "user", name="API_KEY")
    for table in ("entries", "versions", "pins", "events"):
        found = await rows(pool, f"SELECT row_to_json(t)::text AS j FROM {table} t")  # noqa: S608
        assert all(canary not in r["j"] for r in found), table


async def reap(pool, entry_id, version):
    """What the sweeper does to a stale `writing` row: retire it and record the Secret gone."""
    async with pool.connection() as conn:
        await conn.execute(
            "UPDATE versions SET state = 'retired', retired_at = now(), deleted_at = now()"
            " WHERE entry_id = %s AND version = %s",
            (entry_id, version),
        )


async def test_rotate_reaped_while_writing_deletes_the_secret(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube)
    name = secret_name(entry_id, 2)
    entered, release = asyncio.Event(), asyncio.Event()
    kube.apply_gate[name] = (entered, release)
    task = asyncio.create_task(rotate(pool, kube, value="one"))
    await entered.wait()
    await reap(pool, entry_id, 2)
    release.set()
    with pytest.raises(store.SecretStoreFailed):
        await task
    assert not kube.has("Secret", name)  # our apply landed after the reap: we delete it
    assert (await store.get_entry(pool, "API_KEY"))["current_version"] == 1


async def test_create_reaped_while_writing_deletes_the_secret(pool, monkeypatch):
    kube = FakeKube()
    fixed = uuid.uuid4()
    monkeypatch.setattr(store.uuid, "uuid4", lambda: fixed)
    name = secret_name(fixed, 1)
    entered, release = asyncio.Event(), asyncio.Event()
    kube.apply_gate[name] = (entered, release)
    task = asyncio.create_task(create(pool, kube))
    await entered.wait()
    await reap(pool, fixed, 1)
    release.set()
    with pytest.raises(store.SecretStoreFailed):
        await task
    assert not kube.has("Secret", name)
    assert await store.get_entry(pool, "API_KEY") is None


async def test_create_apply_landed_and_cleanup_failed_keeps_the_row_for_gc(pool):
    kube = FlakyKube()
    kube.land_then_fail = True
    original = kube.apply

    async def apply_then_block(obj):
        kube.block_delete = True  # the cleanup delete that follows the failed apply fails
        return await original(obj)

    kube.apply = apply_then_block
    with pytest.raises(store.SecretStoreFailed):
        await create(pool, kube)
    (entry,) = await rows(pool, "SELECT * FROM entries")
    assert entry["deleted_at"] is not None
    (v,) = await versions(pool, entry["id"])
    assert v["state"] == "retired"
    assert v["deleted_at"] is None  # still named: the GC deletes the live Secret later
    assert kube.has("Secret", secret_name(entry["id"], 1))


async def test_rotate_apply_landed_and_cleanup_failed_keeps_the_row_for_gc(pool):
    kube = FlakyKube()
    entry_id = await create(pool, kube)
    kube.land_then_fail = True
    original = kube.apply

    async def apply_then_block(obj):
        kube.block_delete = True
        return await original(obj)

    kube.apply = apply_then_block
    with pytest.raises(store.SecretStoreFailed):
        await rotate(pool, kube, value="new")
    v1, v2 = await versions(pool, entry_id)
    assert v1["state"] == "live"
    assert (v2["state"], v2["deleted_at"]) == ("retired", None)
    assert kube.has("Secret", secret_name(entry_id, 2))


async def test_rotate_failure_with_clean_delete_still_stamps_the_row(pool):
    kube = FlakyKube()
    entry_id = await create(pool, kube)
    kube.land_then_fail = True
    with pytest.raises(store.SecretStoreFailed):
        await rotate(pool, kube, value="new")
    _v1, v2 = await versions(pool, entry_id)
    assert v2["deleted_at"] is not None
    assert not kube.has("Secret", secret_name(entry_id, 2))


async def test_rotate_reaped_and_post_delete_failed_leaves_row_for_gc(pool):
    kube = FlakyKube()
    entry_id = await create(pool, kube)
    name = secret_name(entry_id, 2)
    entered, release = asyncio.Event(), asyncio.Event()
    kube.apply_gate[name] = (entered, release)
    task = asyncio.create_task(rotate(pool, kube, value="one"))
    await entered.wait()
    await reap(pool, entry_id, 2)
    kube.block_delete = True
    release.set()
    with pytest.raises(store.SecretStoreFailed):
        await task
    assert kube.has("Secret", name)
    _v1, v2 = await versions(pool, entry_id)
    assert (v2["state"], v2["deleted_at"]) == ("retired", None)


async def test_create_reaped_and_post_delete_failed_leaves_row_for_gc(pool, monkeypatch):
    kube = FlakyKube()
    fixed = uuid.uuid4()
    monkeypatch.setattr(store.uuid, "uuid4", lambda: fixed)
    name = secret_name(fixed, 1)
    entered, release = asyncio.Event(), asyncio.Event()
    kube.apply_gate[name] = (entered, release)
    task = asyncio.create_task(create(pool, kube))
    await entered.wait()
    await reap(pool, fixed, 1)
    kube.block_delete = True
    release.set()
    with pytest.raises(store.SecretStoreFailed):
        await task
    assert kube.has("Secret", name)
    (v,) = await versions(pool, fixed)
    assert (v["state"], v["deleted_at"]) == ("retired", None)
    assert await store.get_entry(pool, "API_KEY") is None
