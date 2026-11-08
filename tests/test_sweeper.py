import asyncio
import logging
import uuid

import httpx
import pytest
from agents_common.orchestrator import OrchestratorClient
from conftest import ORCHESTRATOR_TOKEN
from psycopg.rows import dict_row
from pydantic import SecretStr

from agents_vault import store, sweeper
from agents_vault.k8s import secret_name

NS = "agents"


def orch_client(fake, settings, token=ORCHESTRATOR_TOKEN):
    return OrchestratorClient(
        settings.orchestrator_url, token, transport=httpx.ASGITransport(app=fake.app)
    )


class Factory:
    def __init__(self, kube):
        self.kube = kube
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return self.kube


@pytest.fixture
def factory(kube):
    return Factory(kube)


@pytest.fixture
async def orch(settings, fake_orch):
    client = orch_client(fake_orch, settings)
    yield client
    await client.aclose()


async def rows(pool, query, params=()):
    async with pool.connection() as conn:
        cur = conn.cursor(row_factory=dict_row)
        await cur.execute(query, params)
        return await cur.fetchall()


async def run(pool, sets, orch, factory):
    return await sweeper.sweep_once(pool, sets, orch, factory)


async def make(pool, kube, name="API_KEY"):
    return await store.create_entry(
        pool,
        kube,
        NS,
        "user",
        name=name,
        description="d",
        labels=[],
        value=SecretStr("v"),
        max_value_bytes=1024,
    )


async def pin(pool, entry_id, version=1, env="E", age_seconds=3600, sid=None):
    sid = sid or uuid.uuid4()
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO pins (session_id, env, entry_id, version, created_at)"
            " VALUES (%s, %s, %s, %s, now() - make_interval(secs => %s))",
            (sid, env, entry_id, version, age_seconds),
        )
    return sid


def list_session(fake, sid, desired="active"):
    fake.sessions[str(sid)] = {"id": str(sid), "slug": "s", "desired": desired}


async def released(pool, sid):
    r = await rows(pool, "SELECT released_at FROM pins WHERE session_id = %s", (sid,))
    return [x["released_at"] is not None for x in r]


async def test_young_pin_kept_even_when_unlisted(pool, settings, orch, kube, factory):
    entry_id = await make(pool, kube)
    sid = await pin(pool, entry_id, age_seconds=5)
    report = await run(pool, settings, orch, factory)
    assert await released(pool, sid) == [False]
    assert report.sessions_released == 0


async def test_old_unlisted_pin_released_with_one_event(pool, settings, orch, kube, factory):
    entry_id = await make(pool, kube)
    sid = await pin(pool, entry_id, env="A")
    await pin(pool, entry_id, env="B", sid=sid)
    await run(pool, settings, orch, factory)
    assert await released(pool, sid) == [True, True]
    ev = await rows(pool, "SELECT * FROM events WHERE kind = 'pins_released'")
    assert len(ev) == 1
    assert ev[0]["actor"] == "sweeper"
    assert ev[0]["data"] == {"session_id": str(sid), "reason": "reconcile"}


async def test_listed_sessions_keep_pins_including_deleting(
    pool, settings, orch, fake_orch, kube, factory
):
    entry_id = await make(pool, kube)
    active = await pin(pool, entry_id, env="A")
    deleting = await pin(pool, entry_id, env="B")
    list_session(fake_orch, active)
    list_session(fake_orch, deleting, "deleting")
    await run(pool, settings, orch, factory)
    assert await released(pool, active) == [False]
    assert await released(pool, deleting) == [False]


async def test_orchestrator_error_releases_nothing_but_gc_and_reap_run(
    pool, settings, orch, fake_orch, kube, factory
):
    entry_id = await make(pool, kube)
    sid = await pin(pool, entry_id)
    await store.rotate_entry(
        pool, kube, NS, "user", name="API_KEY", value=SecretStr("w"), max_value_bytes=1024
    )
    # v1 retired but pinned: stays; a stale writing row is reaped
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO versions (entry_id, version, state, created_at)"
            " VALUES (%s, 9, 'writing', now() - interval '1 hour')",
            (entry_id,),
        )
    fake_orch.fail_next("list_sessions", 500)
    report = await run(pool, settings, orch, factory)
    assert await released(pool, sid) == [False]
    assert report.release_skipped is True
    assert report.writing_reaped == 1
    vs = {r["version"]: r for r in await rows(pool, "SELECT * FROM versions")}
    assert vs[9]["state"] == "retired"
    assert vs[1]["deleted_at"] is None


async def test_unauthorized_releases_nothing(pool, settings, fake_orch, kube, factory):
    entry_id = await make(pool, kube)
    sid = await pin(pool, entry_id)
    client = orch_client(fake_orch, settings, token="wrong")
    try:
        report = await run(pool, settings, client, factory)
    finally:
        await client.aclose()
    assert await released(pool, sid) == [False]
    assert report.release_skipped is True


async def test_gc_deletes_only_retired_versions_without_live_pins(
    pool, settings, orch, fake_orch, kube, factory
):
    entry_id = await make(pool, kube)
    sid = await pin(pool, entry_id, version=1)
    list_session(fake_orch, sid)
    for v in ("b", "c"):
        await store.rotate_entry(
            pool, kube, NS, "user", name="API_KEY", value=SecretStr(v), max_value_bytes=1024
        )
    kube.reset_records()
    report = await run(pool, settings, orch, factory)
    assert report.versions_deleted == 1  # v2; v1 pinned, v3 live
    assert kube.deleted("Secret") == [secret_name(entry_id, 2)]
    assert kube.has("Secret", secret_name(entry_id, 1))
    assert kube.has("Secret", secret_name(entry_id, 3))
    # the session goes away: v1 is released and collected on the next pass
    fake_orch.remove_session(str(sid))
    await run(pool, settings, orch, factory)
    assert not kube.has("Secret", secret_name(entry_id, 1))
    ev = await rows(pool, "SELECT data FROM events WHERE kind = 'version_deleted' ORDER BY id")
    assert [e["data"] for e in ev] == [
        {"name": "API_KEY", "version": 2},
        {"name": "API_KEY", "version": 1},
    ]
    assert kube.forbidden == []
    assert all(n.startswith("vault-") for n in kube.deleted("Secret"))
    assert {c.verb for c in kube.calls} == {"delete"}


async def test_gc_kube_failure_leaves_row_for_next_pass(
    pool, settings, orch, kube, factory, caplog
):
    entry_id = await make(pool, kube)
    await store.rotate_entry(
        pool, kube, NS, "user", name="API_KEY", value=SecretStr("b"), max_value_bytes=1024
    )
    kube.fail("Secret", secret_name(entry_id, 1), verbs=["delete"], times=1)
    with caplog.at_level(logging.WARNING):
        report = await run(pool, settings, orch, factory)
    assert report.versions_deleted == 0
    assert report.failures == 1
    r = await rows(pool, "SELECT deleted_at FROM versions WHERE version = 1")
    assert r[0]["deleted_at"] is None
    assert "KubeError" in caplog.text
    assert "injected failure" not in caplog.text
    await run(pool, settings, orch, factory)
    r = await rows(pool, "SELECT deleted_at FROM versions WHERE version = 1")
    assert r[0]["deleted_at"] is not None


async def test_deleted_entry_collected_after_pins_release(pool, settings, orch, kube, factory):
    entry_id = await make(pool, kube)
    sid = await pin(pool, entry_id)
    await store.delete_entry(pool, "user", name="API_KEY")
    await run(pool, settings, orch, factory)
    # the pin is old and unlisted: released in unit 1, collected by GC in the same pass
    assert await released(pool, sid) == [True]
    assert not kube.has("Secret", secret_name(entry_id, 1))
    r = await rows(pool, "SELECT deleted_at FROM versions")
    assert r[0]["deleted_at"] is not None


async def test_deleted_entry_with_live_pin_keeps_its_secret(
    pool, settings, orch, fake_orch, kube, factory
):
    entry_id = await make(pool, kube)
    sid = await pin(pool, entry_id)
    list_session(fake_orch, sid)
    await store.delete_entry(pool, "user", name="API_KEY")
    await run(pool, settings, orch, factory)
    assert kube.has("Secret", secret_name(entry_id, 1))


async def test_stale_writing_row_reaped_and_never_completed_create_soft_deleted(
    pool, settings, orch, kube, factory
):
    entry_id = uuid.uuid4()
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO entries (id, name, description) VALUES (%s, 'NEW_KEY', 'd')", (entry_id,)
        )
        await conn.execute(
            "INSERT INTO versions (entry_id, version, state, created_at)"
            " VALUES (%s, 1, 'writing', now() - interval '11 minutes')",
            (entry_id,),
        )
    name = secret_name(entry_id, 1)
    await kube.apply({"kind": "Secret", "metadata": {"name": name, "namespace": NS}})
    await run(pool, settings, orch, factory)
    assert not kube.has("Secret", name)
    v = (await rows(pool, "SELECT * FROM versions"))[0]
    assert v["state"] == "retired"
    assert v["retired_at"] is not None and v["deleted_at"] is not None
    e = (await rows(pool, "SELECT deleted_at FROM entries WHERE id = %s", (entry_id,)))[0]
    assert e["deleted_at"] is not None
    ev = await rows(pool, "SELECT data FROM events WHERE kind = 'writing_reaped'")
    assert ev[0]["data"] == {"name": "NEW_KEY", "version": 1}


async def test_reaped_rotate_keeps_entry_live(pool, settings, orch, kube, factory):
    entry_id = await make(pool, kube)
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO versions (entry_id, version, state, created_at)"
            " VALUES (%s, 2, 'writing', now() - interval '11 minutes')",
            (entry_id,),
        )
    await run(pool, settings, orch, factory)
    e = (await rows(pool, "SELECT * FROM entries"))[0]
    assert e["deleted_at"] is None and e["current_version"] == 1


async def test_recent_writing_row_untouched(pool, settings, orch, kube, factory):
    entry_id = await make(pool, kube)
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO versions (entry_id, version, state, created_at)"
            " VALUES (%s, 2, 'writing', now() - interval '5 minutes')",
            (entry_id,),
        )
    report = await run(pool, settings, orch, factory)
    assert report.writing_reaped == 0
    v = (await rows(pool, "SELECT state FROM versions WHERE version = 2"))[0]
    assert v["state"] == "writing"
    assert factory.calls == 0


async def _age_deleted(pool, entry_id, days):
    async with pool.connection() as conn:
        await conn.execute(
            "UPDATE entries SET deleted_at = now() - make_interval(days => %s) WHERE id = %s",
            (days, entry_id),
        )


async def test_purge_after_thirty_days_keeps_events(pool, settings, orch, kube, factory):
    entry_id = await make(pool, kube)
    await pin(pool, entry_id)
    await store.delete_entry(pool, "user", name="API_KEY")
    await run(pool, settings, orch, factory)  # releases the pin, collects the version
    await _age_deleted(pool, entry_id, 31)
    report = await run(pool, settings, orch, factory)
    assert report.entries_purged == 1
    for table in ("entries", "versions", "pins"):
        assert await rows(pool, f"SELECT 1 FROM {table}") == []  # noqa: S608
    assert len(await rows(pool, "SELECT 1 FROM events")) >= 2


async def test_purge_keeps_a_29_day_old_entry(pool, settings, orch, kube, factory):
    entry_id = await make(pool, kube)
    await store.delete_entry(pool, "user", name="API_KEY")
    await run(pool, settings, orch, factory)
    await _age_deleted(pool, entry_id, 29)
    report = await run(pool, settings, orch, factory)
    assert report.entries_purged == 0
    assert len(await rows(pool, "SELECT 1 FROM entries")) == 1


async def test_purge_waits_for_undeleted_versions(pool, settings, orch, fake_orch, kube, factory):
    entry_id = await make(pool, kube)
    sid = await pin(pool, entry_id)
    list_session(fake_orch, sid)
    await store.delete_entry(pool, "user", name="API_KEY")
    await _age_deleted(pool, entry_id, 40)
    await run(pool, settings, orch, factory)
    assert len(await rows(pool, "SELECT 1 FROM entries")) == 1
    assert len(await rows(pool, "SELECT 1 FROM pins")) == 1


async def test_no_kube_client_when_nothing_to_delete(pool, settings, orch, kube, factory):
    await make(pool, kube)
    await run(pool, settings, orch, factory)
    assert factory.calls == 0


async def test_kube_client_built_once_per_pass(pool, settings, orch, kube, factory):
    await make(pool, kube, "A_KEY")
    await make(pool, kube, "B_KEY")
    for name in ("A_KEY", "B_KEY"):
        await store.rotate_entry(
            pool, kube, NS, "user", name=name, value=SecretStr("b"), max_value_bytes=1024
        )
    report = await run(pool, settings, orch, factory)
    assert report.versions_deleted == 2
    assert factory.calls == 1


async def test_run_singleton_runs_one_sweeper_at_a_time(db_url, settings, kube):
    from agents_common.db.pool import open_pool

    pools = [await open_pool(db_url, min_size=2, max_size=4) for _ in range(2)]
    running = 0
    peak = 0
    passes = 0

    async def fake_sweep(pool, sets, orchestrator, factory):
        nonlocal running, peak, passes
        running += 1
        peak = max(peak, running)
        passes += 1
        await asyncio.sleep(0.05)
        running -= 1
        return sweeper.SweepReport()

    stop = asyncio.Event()
    orchestrator = object()
    tasks = [
        asyncio.create_task(
            sweeper.run_singleton(
                p,
                settings.model_copy(update={"sweeper_interval_seconds": 5}),
                orchestrator,
                lambda: kube,
                stop,
                sweep=fake_sweep,
            )
        )
        for p in pools
    ]
    try:
        await asyncio.sleep(0.6)
        assert passes >= 1
        assert peak == 1
    finally:
        stop.set()
        await asyncio.wait(tasks, timeout=10)
        for t in tasks:
            t.cancel()
        for p in pools:
            await p.close()
