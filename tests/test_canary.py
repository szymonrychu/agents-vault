"""Canary test (spec 7.3): a secret value goes in, and appears nowhere except the `stringData`
of the Secret applied to Kubernetes.

The first test runs on fakes only (no database): the 422 and 413 refusals happen before the
store touches Postgres. The second test drives the whole life (create, rotate, refusals, a
failing Secret write, pins, release, delete, sweeper passes) and also scans every table row;
it needs Postgres (testcontainers, so Docker or PR CI).
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
import uuid
from dataclasses import dataclass, field

import httpx
import pytest
from agents_common.orchestrator import OrchestratorClient
from conftest import ORCHESTRATOR_TOKEN, SERVICE_TOKEN
from fakes.fake_kube import FakeKube

from agents_vault import sweeper
from agents_vault.api.app import PREFIX, create_web_app
from agents_vault.k8s import KubeError, secret_name
from agents_vault.settings import Settings

CANARY = f"CANARY-{secrets.token_hex(16)}"
E = f"{PREFIX}/entries"
P = f"{PREFIX}/pins"
CAP = 256
LOGGERS = ("", "uvicorn", "uvicorn.error", "uvicorn.access", "httpx", "httpcore", "agents_vault")


def forms() -> list[str]:
    """The canary as written, and base64 and URL-safe base64 of it."""
    raw = CANARY.encode()
    return [CANARY, base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode()]


def contains(text: str) -> list[str]:
    return [f for f in forms() if f in text]


@dataclass
class Seen:
    """Every response (status, headers, body) the test received."""

    texts: list[tuple[str, str]] = field(default_factory=list)

    def record(self, label: str, r: httpx.Response) -> httpx.Response:
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.multi_items())
        self.texts.append((f"{label} headers", headers))
        self.texts.append((f"{label} body", r.text))
        return r


def assert_absent(where: str, text: str) -> None:
    found = contains(text)
    assert not found, f"canary leaked into {where}"


def assert_logs_clean(caplog: pytest.LogCaptureFixture) -> None:
    for record in caplog.records:
        parts = [record.getMessage(), str(record.args), record.name, record.pathname]
        if record.exc_info:
            parts.append(repr(record.exc_info[1]))
            parts.append(str(record.exc_info[1]))
        if record.exc_text:
            parts.append(record.exc_text)
        if record.stack_info:
            parts.append(record.stack_info)
        parts.append(str(record.__dict__.get("extra", "")))
        assert_absent(f"log record of {record.name}", "\n".join(parts))
    assert_absent("caplog text", caplog.text)


def assert_kube_clean(kube: FakeKube, expected_applies: int) -> None:
    assert_absent("kube objects", json.dumps(kube.objects, default=str))
    assert_absent("kube deletes", repr(kube.deletes))
    assert_absent("kube calls", repr(kube.calls))
    assert_absent("kube forbidden", repr(kube.forbidden))
    assert kube.forbidden == []
    carrying = 0
    for i, applied in enumerate(kube.applies):
        obj = dict(applied.obj)
        data = obj.pop("stringData")
        assert set(data) == {"value"}, f"apply {i} has keys {set(data)}"
        assert_absent(f"apply {i} outside stringData", json.dumps(obj, default=str))
        assert_absent(f"apply {i} field manager", applied.field_manager)
        carrying += CANARY in data["value"]
    assert carrying == expected_applies


def assert_responses_clean(seen: Seen) -> None:
    assert seen.texts
    for label, text in seen.texts:
        assert_absent(label, text)


def arm_logging(caplog: pytest.LogCaptureFixture) -> None:
    for name in LOGGERS:
        caplog.set_level(logging.DEBUG, logger=name)


async def test_refusals_without_a_database_leak_nothing(caplog):
    """422 and 413 on fakes: no pool, no Postgres. The kube fake must see no call at all."""
    arm_logging(caplog)
    settings = Settings(
        database_url="postgresql://unused/db",
        orchestrator_url="http://orchestrator.invalid",
        orchestrator_token=ORCHESTRATOR_TOKEN,
        namespace="agents",
        max_value_bytes=CAP,
    )
    kube = FakeKube()
    app = create_web_app(settings, None, kube_factory=lambda: kube)  # type: ignore[arg-type]
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
    seen = Seen()
    async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
        good = {"name": "API_KEY", "description": "d", "labels": []}
        bad_name = await client.post(E, json={**good, "name": "bad-name", "value": CANARY})
        seen.record("bad name", bad_name)
        assert bad_name.status_code == 422

        wrong_type = await client.post(E, json={**good, "value": [CANARY]})
        seen.record("wrong type", wrong_type)
        assert wrong_type.status_code == 422

        extra = await client.post(E, json={**good, "value": CANARY, CANARY: CANARY})
        seen.record("extra field", extra)
        assert extra.status_code == 422

        not_json = await client.post(E, content=f'{{"value": "{CANARY}"'.encode())
        seen.record("not json", not_json)
        assert not_json.status_code == 422

        big = CANARY * (CAP // len(CANARY) + 2)
        too_large = await client.post(E, json={**good, "value": big})
        seen.record("create over cap", too_large)
        assert too_large.status_code == 413
        assert too_large.json()["error"]["code"] == "secret_too_large"

        rotate = await client.put(f"{E}/API_KEY/value", json={"value": big})
        seen.record("rotate over cap", rotate)
        assert rotate.status_code == 413
    assert_responses_clean(seen)
    assert_logs_clean(caplog)
    assert kube.calls == [] and kube.applies == []
    assert_kube_clean(kube, expected_applies=0)


async def table_rows(conn) -> dict[str, list[str]]:
    cur = await conn.execute(
        "SELECT table_name FROM information_schema.tables"
        " WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
    )
    out = {}
    for (table,) in await cur.fetchall():
        cur = await conn.execute(f'SELECT row_to_json(t)::text FROM "{table}" t')  # noqa: S608
        out[table] = [r[0] for r in await cur.fetchall()]
    return out


@pytest.fixture
def settings(db_url: str) -> Settings:
    return Settings(
        database_url=db_url,
        orchestrator_url="http://orchestrator.invalid",
        orchestrator_token=ORCHESTRATOR_TOKEN,
        namespace="agents",
        max_value_bytes=CAP,
    )


async def test_canary_through_the_whole_life(
    pool, settings, web_client, service_client, fake_orch, kube, caplog, monkeypatch
):
    """Needs Postgres (CI). One canary value through every path that handles a value."""
    arm_logging(caplog)
    seen = Seen()

    async def call(label, client, method, path, expect, **kw):
        r = seen.record(label, await client.request(method, path, **kw))
        assert r.status_code == expect, (label, r.status_code)
        return r

    good = {"name": "API_KEY", "description": "an api key", "labels": ["team-a"]}

    # create, rotate
    await call("create", web_client, "POST", E, 201, json={**good, "value": CANARY})
    async with pool.connection() as conn:
        cur = await conn.execute("SELECT id FROM entries WHERE name = 'API_KEY'")
        entry_id = (await cur.fetchone())[0]
    await call(
        "rotate", web_client, "PUT", f"{E}/API_KEY/value", 200, json={"value": CANARY + "-2"}
    )

    # refusals: 422 (bad name plus canary), 413 (canary repeated over the cap)
    await call(
        "422", web_client, "POST", E, 422, json={**good, "name": "bad-name", "value": CANARY}
    )
    big = CANARY * (CAP // len(CANARY) + 2)
    await call("413 create", web_client, "POST", E, 413, json={**good, "name": "BIG", "value": big})
    await call("413 rotate", web_client, "PUT", f"{E}/API_KEY/value", 413, json={"value": big})

    # 502 on rotate: the kube error text itself contains the canary
    async with pool.connection() as conn:
        cur = await conn.execute(
            "SELECT max(version) FROM versions WHERE entry_id = %s", (entry_id,)
        )
        next_version = (await cur.fetchone())[0] + 1
    kube.fail(
        "Secret",
        secret_name(entry_id, next_version),
        KubeError(f"apply refused, body: {CANARY}"),
        verbs=["patch"],
        times=1,
    )
    await call("502 rotate", web_client, "PUT", f"{E}/API_KEY/value", 502, json={"value": CANARY})

    # 502 on create: pin the new entry id so the failure can be aimed at its Secret
    fixed = uuid.uuid4()
    kube.fail(
        "Secret", secret_name(fixed, 1), KubeError(f"create refused, body: {CANARY}"), times=None
    )
    with monkeypatch.context() as m:
        m.setattr("agents_vault.store.uuid.uuid4", lambda: fixed)
        await call(
            "502 create",
            web_client,
            "POST",
            E,
            502,
            json={**good, "name": "OTHER_KEY", "value": CANARY},
        )
    kube.heal("Secret", secret_name(fixed, 1))

    # a good rotate after the failure, then reads
    await call("rotate again", web_client, "PUT", f"{E}/API_KEY/value", 200, json={"value": CANARY})
    await call("list", web_client, "GET", E, 200)
    await call("detail", web_client, "GET", f"{E}/API_KEY", 200)
    await call("events", web_client, "GET", f"{PREFIX}/events", 200)
    await call("entry pins", web_client, "GET", f"{E}/API_KEY/pins", 200)

    # pins (service listener), resolve, release
    sid = uuid.uuid4()
    body = {"session_id": str(sid), "preset_labels": ["team-a"], "refs": {"MY_ENV": "API_KEY"}}
    resolve = {k: v for k, v in body.items() if k != "session_id"}
    await call("resolve", service_client, "POST", f"{E}/resolve", 200, json=resolve)
    await call("pin", service_client, "POST", P, 200, json=body)
    await call("entry pins live", web_client, "GET", f"{E}/API_KEY/pins", 200)
    await call("release", service_client, "DELETE", f"{P}/{sid}", 204)
    sid2 = uuid.uuid4()
    await call("pin 2", service_client, "POST", P, 200, json={**body, "session_id": str(sid2)})
    await call("service list", service_client, "GET", E, 200)

    # sweeper: the second pin is old and its session unknown, so it is released; old versions
    # are collected, first with a delete failure whose text holds the canary, then healed
    async with pool.connection() as conn:
        await conn.execute("UPDATE pins SET created_at = now() - interval '1 hour'")
    orch = OrchestratorClient(
        settings.orchestrator_url,
        ORCHESTRATOR_TOKEN,
        transport=httpx.ASGITransport(app=fake_orch.app),
    )
    try:
        stale = secret_name(entry_id, 1)
        kube.fail("Secret", stale, KubeError(f"delete refused, body: {CANARY}"), verbs=["delete"])
        failing = await sweeper.sweep_once(pool, settings, orch, lambda: kube)
        assert failing.failures >= 1
        kube.heal("Secret", stale)
        await sweeper.sweep_once(pool, settings, orch, lambda: kube)
    finally:
        await orch.aclose()

    # delete the entry, then collect it
    await call("delete", web_client, "DELETE", f"{E}/API_KEY", 204)
    orch = OrchestratorClient(
        settings.orchestrator_url,
        ORCHESTRATOR_TOKEN,
        transport=httpx.ASGITransport(app=fake_orch.app),
    )
    try:
        await sweeper.sweep_once(pool, settings, orch, lambda: kube)
    finally:
        await orch.aclose()
    await call("events end", web_client, "GET", f"{PREFIX}/events", 200)

    # the scans
    assert any(CANARY in a.obj["stringData"]["value"] for a in kube.applies), (
        "the canary must reach a Secret"
    )
    carrying = sum(CANARY in a.obj["stringData"]["value"] for a in kube.applies)
    assert carrying == 3  # create, rotate, rotate again
    assert_responses_clean(seen)
    assert_logs_clean(caplog)
    assert_kube_clean(kube, expected_applies=carrying)
    async with pool.connection() as conn:
        tables = await table_rows(conn)
    assert {"entries", "versions", "pins", "events"} <= set(tables)
    for table, rows in tables.items():
        for i, row in enumerate(rows):
            assert_absent(f"row {i} of table {table}", row)
    assert SERVICE_TOKEN not in caplog.text
