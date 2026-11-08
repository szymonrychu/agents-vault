import secrets
import uuid

import httpx
import pytest
from conftest import SERVICE_TOKEN
from pydantic import SecretStr

from agents_vault import store
from agents_vault.api.app import PREFIX, create_service_app, create_web_app
from agents_vault.k8s import secret_name
from agents_vault.settings import Settings

canary = secrets.token_hex(16)
E = f"{PREFIX}/entries"
P = f"{PREFIX}/pins"
NS = "agents"


async def make(pool, kube, name, labels=None, description="d"):
    return await store.create_entry(
        pool,
        kube,
        NS,
        "user",
        name=name,
        description=description,
        labels=labels or [],
        value=SecretStr(canary),
        max_value_bytes=1024,
    )


def pin_body(session_id=None, labels=None, **refs):
    return {
        "session_id": str(session_id or uuid.uuid4()),
        "preset_labels": labels or [],
        "refs": refs,
    }


async def events(conn, kind):
    return [r for r in conn.execute("SELECT * FROM events WHERE kind = %s", (kind,)).fetchall()]


# gate


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("GET", E, None),
        ("POST", f"{E}/resolve", {"refs": {}}),
        ("POST", P, pin_body()),
        ("DELETE", f"{P}/{uuid.uuid4()}", None),
    ],
)
async def test_gate_rejects_missing_and_wrong_bearer(service_client, method, path, body):
    for headers in ({}, {"Authorization": "Bearer nope"}):
        r = await service_client.request(
            method, path, json=body, headers={"Authorization": "", **headers}
        )
        assert r.status_code == 401, (method, path, headers)


async def test_gate_accepts_the_token_file_token(service_client):
    assert (await service_client.get(E)).status_code == 200


# resolve


async def test_resolve_known_unknown_mismatched_in_one_call(service_client, pool, kube):
    await make(pool, kube, "OPEN_KEY")
    await make(pool, kube, "TEAM_KEY", labels=["team-a"])
    await make(pool, kube, "OTHER_KEY", labels=["team-b"])
    r = await service_client.post(
        f"{E}/resolve",
        json={
            "preset_labels": ["Team-A"],
            "refs": {"A": "OPEN_KEY", "B": "TEAM_KEY", "C": "OTHER_KEY", "D": "NOPE", "F": "NOPE"},
        },
    )
    assert r.status_code == 200
    out = r.json()
    assert out["unknown"] == ["NOPE"]
    assert out["mismatched"] == ["C"]
    assert set(out["resolved"]) == {"A", "B", "C"}
    assert out["resolved"]["B"] == {
        "name": "TEAM_KEY",
        "labels": ["team-a"],
        "version": 1,
        "matches": True,
    }
    assert out["resolved"]["C"]["matches"] is False
    assert canary not in r.text


@pytest.mark.parametrize("preset_labels", [[], ["anything"]])
async def test_unlabelled_entry_matches_every_preset(service_client, pool, kube, preset_labels):
    await make(pool, kube, "OPEN_KEY")
    r = await service_client.post(
        f"{E}/resolve", json={"preset_labels": preset_labels, "refs": {"A": "OPEN_KEY"}}
    )
    assert r.json()["mismatched"] == []


async def test_labelled_entry_against_unlabelled_preset_is_mismatched(service_client, pool, kube):
    await make(pool, kube, "TEAM_KEY", labels=["team-a"])
    r = await service_client.post(f"{E}/resolve", json={"refs": {"A": "TEAM_KEY"}})
    assert r.json()["mismatched"] == ["A"]


async def test_project_label_matches_a_preset_carrying_it(service_client, pool, kube):
    await make(pool, kube, "PROJ_KEY", labels=["project:x"])
    ok = await service_client.post(
        f"{E}/resolve", json={"preset_labels": ["project:x"], "refs": {"A": "PROJ_KEY"}}
    )
    bad = await service_client.post(
        f"{E}/resolve", json={"preset_labels": ["project:y"], "refs": {"A": "PROJ_KEY"}}
    )
    assert ok.json()["mismatched"] == []
    assert bad.json()["mismatched"] == ["A"]


async def test_preset_label_outside_the_project_slug_rule_is_accepted_literally(
    service_client, pool, kube, conn
):
    await make(pool, kube, "SLUG_KEY", labels=["project:ab"])
    await make(pool, kube, "TEAM_KEY", labels=["team-a"])
    await make(pool, kube, "OPEN_KEY")
    refs = {"A": "SLUG_KEY", "B": "TEAM_KEY", "C": "OPEN_KEY"}
    r = await service_client.post(
        f"{E}/resolve", json={"preset_labels": ["Project:A_B"], "refs": refs}
    )
    assert r.status_code == 200
    assert r.json()["mismatched"] == ["A", "B"]  # no normalisation to another label
    conn.execute("UPDATE entries SET labels = ARRAY['project:a_b'] WHERE name = 'SLUG_KEY'")
    r = await service_client.post(
        f"{E}/resolve", json={"preset_labels": ["project:a_b"], "refs": refs}
    )
    assert r.json()["mismatched"] == ["B"]  # the same literal label matches
    pinned = await service_client.post(P, json=pin_body(labels=["project:a_b"], A="SLUG_KEY"))
    assert pinned.status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        {"preset_labels": ["bad label!"], "refs": {}},
        {"refs": {f"E{i}": "NAME" for i in range(51)}},
        {"refs": {"lower": "NAME"}},
        {"refs": {"A": "lower"}},
    ],
)
async def test_resolve_validation_is_422(service_client, body):
    r = await service_client.post(f"{E}/resolve", json=body)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_request"


async def test_fifty_refs_are_allowed(service_client):
    r = await service_client.post(
        f"{E}/resolve", json={"refs": {f"E{i}": "NAME" for i in range(50)}}
    )
    assert r.status_code == 200


async def test_resolve_ignores_deleted_entries(service_client, pool, kube):
    await make(pool, kube, "GONE_KEY")
    await store.delete_entry(pool, "user", name="GONE_KEY")
    r = await service_client.post(f"{E}/resolve", json={"refs": {"A": "GONE_KEY"}})
    assert r.json()["unknown"] == ["GONE_KEY"]


# pins


async def test_pins_return_secret_names_and_one_event(service_client, pool, kube, conn):
    entry_id = await make(pool, kube, "TEAM_KEY", labels=["team-a"])
    sid = uuid.uuid4()
    r = await service_client.post(
        P, json=pin_body(sid, labels=["team-a"], GPG="TEAM_KEY", OTHER="TEAM_KEY")
    )
    assert r.status_code == 200
    pins = r.json()["pins"]
    expected = {"secret": f"vault-{entry_id}-v1", "name": "TEAM_KEY", "version": 1}
    assert pins == {"GPG": expected, "OTHER": expected}
    assert canary not in r.text
    rows = await events(conn, "pins_created")
    assert len(rows) == 1
    event = conn.execute("SELECT actor, data FROM events WHERE kind = 'pins_created'").fetchone()
    assert event[0] == "orchestrator"
    assert event[1] == {
        "session_id": str(sid),
        "envs": ["GPG", "OTHER"],
        "names": ["TEAM_KEY", "TEAM_KEY"],
        "versions": [1, 1],
    }


async def test_pins_are_idempotent_per_session_and_survive_a_rotate(
    service_client, pool, kube, conn
):
    entry_id = await make(pool, kube, "TEAM_KEY")
    await make(pool, kube, "SECOND_KEY")
    sid = uuid.uuid4()
    first = await service_client.post(P, json=pin_body(sid, A="TEAM_KEY"))
    await store.rotate_entry(
        pool, kube, NS, "user", name="TEAM_KEY", value=SecretStr("x"), max_value_bytes=1024
    )
    again = await service_client.post(P, json=pin_body(sid, B="SECOND_KEY", C="NOPE"))
    assert again.status_code == 200
    assert again.json() == first.json()
    assert again.json()["pins"]["A"]["secret"] == secret_name(entry_id, 1)
    assert conn.execute("SELECT count(*) FROM pins").fetchone()[0] == 1
    assert len(await events(conn, "pins_created")) == 1
    # a new session after the rotate sees the new version
    fresh = await service_client.post(P, json=pin_body(A="TEAM_KEY"))
    assert fresh.json()["pins"]["A"]["version"] == 2


async def test_pins_unknown_entry_is_422_with_names(service_client, pool, kube, conn):
    await make(pool, kube, "REAL_KEY")
    r = await service_client.post(P, json=pin_body(A="REAL_KEY", B="ZED", C="ALPHA"))
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "vault_entry_unknown"
    assert err["names"] == ["ALPHA", "ZED"]
    assert conn.execute("SELECT count(*) FROM pins").fetchone()[0] == 0


async def test_pins_deleted_entry_is_unknown(service_client, pool, kube):
    await make(pool, kube, "GONE_KEY")
    await store.delete_entry(pool, "user", name="GONE_KEY")
    r = await service_client.post(P, json=pin_body(A="GONE_KEY"))
    assert r.json()["error"]["names"] == ["GONE_KEY"]


async def test_pins_label_mismatch_is_422_with_envs(service_client, pool, kube, conn):
    await make(pool, kube, "TEAM_KEY", labels=["team-a"])
    r = await service_client.post(P, json=pin_body(labels=["team-b"], X="TEAM_KEY"))
    assert r.status_code == 422
    err = r.json()["error"]
    assert (err["code"], err["envs"]) == ("vault_label_mismatch", ["X"])
    assert conn.execute("SELECT count(*) FROM pins").fetchone()[0] == 0


async def test_unknown_is_checked_before_mismatch(service_client, pool, kube):
    await make(pool, kube, "TEAM_KEY", labels=["team-a"])
    r = await service_client.post(P, json=pin_body(labels=["team-b"], X="TEAM_KEY", Y="NOPE"))
    assert r.json()["error"]["code"] == "vault_entry_unknown"


@pytest.mark.parametrize(
    "body",
    [
        {"session_id": "not-a-uuid", "refs": {}},
        {"preset_labels": [], "refs": {}},
        {"session_id": str(uuid.uuid4()), "refs": {"lower": "NAME"}},
    ],
)
async def test_pins_validation_is_422(service_client, body):
    r = await service_client.post(P, json=body)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_request"


async def test_pin_holds_for_share_so_a_rotate_waits_and_the_version_is_kept(pool, kube, db_url):
    import asyncio

    import psycopg

    from agents_vault.db import pins as pins_repo

    entry_id = await make(pool, kube, "TEAM_KEY")
    sid = uuid.uuid4()
    aconn = await psycopg.AsyncConnection.connect(db_url)
    try:
        async with aconn.transaction():
            rows = await pins_repo.share_lock_live_entries(aconn, ["TEAM_KEY"])
            assert rows[0]["current_version"] == 1
            rotating = asyncio.create_task(
                store.rotate_entry(
                    pool,
                    kube,
                    NS,
                    "user",
                    name="TEAM_KEY",
                    value=SecretStr("two"),
                    max_value_bytes=1024,
                )
            )
            await asyncio.sleep(0.5)
            assert not rotating.done()  # tx B waits for our share lock
            await pins_repo.insert_pin(aconn, sid, "A", entry_id, 1)
        assert await asyncio.wait_for(rotating, 10) == 2
    finally:
        await aconn.close()
    versions = {v["version"]: v for v in await store.entry_versions(pool, entry_id)}
    assert versions[1]["state"] == "retired"
    assert versions[1]["pins"] == 1  # a live pin keeps the retired version from GC
    assert versions[2]["state"] == "live"


# release


async def test_release_only_that_session_and_repeat_is_quiet(service_client, pool, kube, conn):
    await make(pool, kube, "TEAM_KEY")
    mine, other = uuid.uuid4(), uuid.uuid4()
    await service_client.post(P, json=pin_body(mine, A="TEAM_KEY"))
    await service_client.post(P, json=pin_body(other, A="TEAM_KEY"))
    r = await service_client.delete(f"{P}/{mine}")
    assert r.status_code == 204
    assert r.content == b""
    live = conn.execute("SELECT session_id FROM pins WHERE released_at IS NULL").fetchall()
    assert [str(row[0]) for row in live] == [str(other)]
    again = await service_client.delete(f"{P}/{mine}")
    assert again.status_code == 204
    assert (await service_client.delete(f"{P}/{uuid.uuid4()}")).status_code == 204
    released = conn.execute("SELECT data FROM events WHERE kind = 'pins_released'").fetchall()
    assert [row[0] for row in released] == [{"session_id": str(mine), "reason": "orchestrator"}]


async def test_release_with_a_bad_session_id_is_422(service_client):
    assert (await service_client.delete(f"{P}/nope")).status_code == 422


# entries summary


async def test_summary_shape_attachments_and_q(service_client, pool, kube, fake_orch):
    await make(pool, kube, "ALPHA_KEY", labels=["team-a"], description="first")
    await make(pool, kube, "BETA_KEY", description="second")
    preset = fake_orch.add_preset("p1", spec={"env": {"GPG": {"vault": "ALPHA_KEY"}}})
    r = await service_client.get(E)
    assert r.status_code == 200
    out = r.json()
    assert [e["name"] for e in out] == ["ALPHA_KEY", "BETA_KEY"]
    assert set(out[0]) == {"name", "description", "labels", "version", "updated_at", "attachments"}
    assert out[0]["attachments"] == [
        {"preset_id": str(preset.id), "preset_name": "p1", "env": "GPG"}
    ]
    assert out[1]["attachments"] == []
    only = await service_client.get(E, params={"q": "second"})
    assert [e["name"] for e in only.json()] == ["BETA_KEY"]
    assert canary not in r.text


async def test_summary_attachments_none_when_orchestrator_unavailable(settings, pool, kube):
    await make(pool, kube, "ALPHA_KEY")

    def refuse(request):
        raise httpx.ConnectError("down")

    from agents_common.orchestrator import OrchestratorClient

    orch = OrchestratorClient(settings.orchestrator_url, "t", transport=httpx.MockTransport(refuse))
    app = create_service_app(settings, pool, [SERVICE_TOKEN], orchestrator=orch)
    transport = httpx.ASGITransport(app=app, client=("10.1.2.3", 1))
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://vault",
        headers={"Authorization": f"Bearer {SERVICE_TOKEN}"},
    ) as c:
        r = await c.get(E)
    assert r.status_code == 200
    assert r.json()[0]["attachments"] is None
    await orch.aclose()


# route sets


def _routes(app):
    return {(m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops}


def _apps():
    settings = Settings(
        database_url="postgresql://u:p@db.invalid/vault",
        orchestrator_url="http://orchestrator.invalid",
        orchestrator_token="orch",
        namespace="agents",
    )
    return create_web_app(settings, None), create_service_app(settings, None, ["tok"])


def test_service_app_has_none_of_the_web_mutation_routes():
    _, service = _apps()
    have = _routes(service)
    for forbidden in [
        ("POST", E),
        ("PATCH", f"{E}/{{name}}"),
        ("PUT", f"{E}/{{name}}/value"),
        ("DELETE", f"{E}/{{name}}"),
        ("GET", f"{E}/{{name}}"),
        ("GET", f"{E}/{{name}}/pins"),
        ("GET", f"{PREFIX}/events"),
    ]:
        assert forbidden not in have


def test_web_app_has_no_resolve_or_pins_routes():
    web, _ = _apps()
    paths = {p for _, p in _routes(web)}
    assert f"{E}/resolve" not in paths
    assert not any(p.startswith(P) for p in paths)
