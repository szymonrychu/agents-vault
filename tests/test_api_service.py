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


async def make(pool, kube, name, labels=None, description="d", envs=None):
    return await store.create_entry(
        pool,
        kube,
        NS,
        "user",
        name=name,
        description=description,
        labels=labels or [],
        envs=envs if envs is not None else [store.EnvIn("KEY", True, SecretStr(canary))],
        max_value_bytes=1024,
    )


def r(entry_id, env="KEY"):
    return {"entry": str(entry_id), "env": env}


def pin_body(session_id=None, labels=None, **refs):
    return {
        "session_id": str(session_id or uuid.uuid4()),
        "preset_labels": labels or [],
        "refs": refs,
    }


async def events(conn, kind):
    return [r for r in conn.execute("SELECT * FROM events WHERE kind = %s", (kind,)).fetchall()]


MIXED = [
    store.EnvIn("HARBOR_URL", False, SecretStr("https://harbor.example")),
    store.EnvIn("HARBOR_PASSWORD", True, SecretStr(canary)),
    store.EnvIn("HARBOR_USERNAME", False, SecretStr("robot-user")),
]


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


async def test_resolve_known_unknown_bad_env_and_mismatched_in_one_call(service_client, pool, kube):
    open_key = await make(pool, kube, "open key")
    team = await make(pool, kube, "team key", labels=["project:a"])
    other = await make(pool, kube, "other key", labels=["project:b"])
    nope = uuid.uuid4()
    r_ = await service_client.post(
        f"{E}/resolve",
        json={
            "preset_labels": ["Project:A"],
            "refs": {
                "A": r(open_key),
                "B": r(team),
                "C": r(other),
                "D": r(nope),
                "F": r(nope),
                "G": r(team, "NOPE"),
            },
        },
    )
    assert r_.status_code == 200
    out = r_.json()
    assert out["unknown"] == ["D", "F"]
    assert out["bad_env"] == ["G"]
    assert out["mismatched"] == ["C"]
    assert set(out["resolved"]) == {"A", "B", "C"}
    assert out["resolved"]["B"] == {
        "entry": str(team),
        "name": "team key",
        "env": "KEY",
        "protected": True,
        "labels": ["project:a"],
        "version": 1,
        "matches": True,
    }
    assert out["resolved"]["C"]["matches"] is False
    assert canary not in r_.text


@pytest.mark.parametrize("preset_labels", [[], ["anything"]])
async def test_unlabelled_entry_matches_every_preset(service_client, pool, kube, preset_labels):
    open_key = await make(pool, kube, "open key")
    out = await service_client.post(
        f"{E}/resolve", json={"preset_labels": preset_labels, "refs": {"A": r(open_key)}}
    )
    assert out.json()["mismatched"] == []


async def test_project_labelled_entry_against_unlabelled_preset_is_mismatched(
    service_client, pool, kube
):
    proj = await make(pool, kube, "proj key", labels=["project:a"])
    out = await service_client.post(f"{E}/resolve", json={"refs": {"A": r(proj)}})
    assert out.json()["mismatched"] == ["A"]


@pytest.mark.parametrize("preset_labels", [[], ["project:x"], ["team-b"]])
async def test_tag_only_entry_matches_every_preset(service_client, pool, kube, preset_labels):
    tagged = await make(pool, kube, "tagged key", labels=["admin", "github", "credentials"])
    out = await service_client.post(
        f"{E}/resolve", json={"preset_labels": preset_labels, "refs": {"A": r(tagged)}}
    )
    assert out.json()["mismatched"] == []
    pinned = await service_client.post(P, json=pin_body(labels=preset_labels, A=r(tagged)))
    assert pinned.status_code == 200


async def test_mixed_tags_and_project_label_restrict_by_project_only(service_client, pool, kube):
    mixed = await make(pool, kube, "mixed key", labels=["admin", "project:x"])
    refs = {"A": r(mixed)}
    ok = await service_client.post(
        f"{E}/resolve", json={"preset_labels": ["project:x"], "refs": refs}
    )
    tag_only_preset = await service_client.post(
        f"{E}/resolve", json={"preset_labels": ["admin"], "refs": refs}
    )
    assert ok.json()["mismatched"] == []
    assert tag_only_preset.json()["mismatched"] == ["A"]  # a shared tag does not satisfy project:x


async def test_project_label_matches_a_preset_carrying_it(service_client, pool, kube):
    proj = await make(pool, kube, "proj key", labels=["project:x"])
    ok = await service_client.post(
        f"{E}/resolve", json={"preset_labels": ["project:x"], "refs": {"A": r(proj)}}
    )
    bad = await service_client.post(
        f"{E}/resolve", json={"preset_labels": ["project:y"], "refs": {"A": r(proj)}}
    )
    assert ok.json()["mismatched"] == []
    assert bad.json()["mismatched"] == ["A"]


async def test_preset_label_outside_the_project_slug_rule_is_accepted_literally(
    service_client, pool, kube, conn
):
    slug = await make(pool, kube, "slug key", labels=["project:ab"])
    team = await make(pool, kube, "team key", labels=["team-a"])
    open_key = await make(pool, kube, "open key")
    refs = {"A": r(slug), "B": r(team), "C": r(open_key)}
    out = await service_client.post(
        f"{E}/resolve", json={"preset_labels": ["Project:A_B"], "refs": refs}
    )
    assert out.status_code == 200
    assert out.json()["mismatched"] == ["A"]  # no normalisation; tag entry B matches
    conn.execute("UPDATE entries SET labels = ARRAY['project:a_b'] WHERE id = %s", (slug,))
    out = await service_client.post(
        f"{E}/resolve", json={"preset_labels": ["project:a_b"], "refs": refs}
    )
    assert out.json()["mismatched"] == []  # the same literal label matches
    pinned = await service_client.post(P, json=pin_body(labels=["project:a_b"], A=r(slug)))
    assert pinned.status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        {"preset_labels": ["bad label!"], "refs": {}},
        {"refs": {f"E{i}": r(uuid.uuid4()) for i in range(101)}},
        {"refs": {"lower": r(uuid.uuid4())}},
        {"refs": {"A": r(uuid.uuid4(), "lower")}},
        {"refs": {"A": {"entry": "not-a-uuid", "env": "KEY"}}},
        {"refs": {"A": "NAME"}},
        {"refs": {"A": {"entry": str(uuid.uuid4())}}},
        {"refs": {"A": {**r(uuid.uuid4()), "name": "x"}}},
    ],
)
async def test_resolve_validation_is_422(service_client, body):
    out = await service_client.post(f"{E}/resolve", json=body)
    assert out.status_code == 422
    assert out.json()["error"]["code"] == "invalid_request"


async def test_hundred_refs_are_allowed(service_client):
    out = await service_client.post(
        f"{E}/resolve", json={"refs": {f"E{i}": r(uuid.uuid4()) for i in range(100)}}
    )
    assert out.status_code == 200


async def test_resolve_ignores_deleted_entries(service_client, pool, kube):
    gone = await make(pool, kube, "gone key")
    await store.delete_entry(pool, "user", entry_id=gone)
    out = await service_client.post(f"{E}/resolve", json={"refs": {"A": r(gone)}})
    assert out.json()["unknown"] == ["A"]


# pins


async def test_pins_return_secrets_for_protected_and_values_for_readable(
    service_client, pool, kube, conn
):
    entry_id = await make(pool, kube, "Harbor", labels=["team-a"], envs=MIXED)
    sid = uuid.uuid4()
    out = await service_client.post(
        P,
        json=pin_body(
            sid,
            labels=["team-a"],
            URL=r(entry_id, "HARBOR_URL"),
            PASSWORD=r(entry_id, "HARBOR_PASSWORD"),
            OTHER_PASSWORD=r(entry_id, "HARBOR_PASSWORD"),
        ),
    )
    assert out.status_code == 200
    expected = {"secret": f"vault-{entry_id}-v1", "key": "HARBOR_PASSWORD", "version": 1}
    assert out.json() == {
        "pins": {"PASSWORD": expected, "OTHER_PASSWORD": expected},
        "values": {"URL": "https://harbor.example"},
    }
    assert canary not in out.text
    stored = conn.execute(
        "SELECT env, entry_env, version FROM pins WHERE session_id = %s ORDER BY env", (sid,)
    ).fetchall()
    assert stored == [
        ("OTHER_PASSWORD", "HARBOR_PASSWORD", 1),
        ("PASSWORD", "HARBOR_PASSWORD", 1),
        ("URL", "HARBOR_URL", 1),
    ]
    rows = await events(conn, "pins_created")
    assert len(rows) == 1
    event = conn.execute("SELECT actor, data FROM events WHERE kind = 'pins_created'").fetchone()
    assert event[0] == "orchestrator"
    assert event[1] == {
        "session_id": str(sid),
        "envs": ["OTHER_PASSWORD", "PASSWORD", "URL"],
        "entries": [str(entry_id)] * 3,
        "names": ["Harbor"] * 3,
        "entry_envs": ["HARBOR_PASSWORD", "HARBOR_PASSWORD", "HARBOR_URL"],
        "versions": [1, 1, 1],
    }
    assert "https://" not in str(event[1])


async def test_pins_are_idempotent_per_session_and_survive_a_rotate(
    service_client, pool, kube, conn
):
    entry_id = await make(pool, kube, "team key")
    second = await make(pool, kube, "second key")
    sid = uuid.uuid4()
    first = await service_client.post(P, json=pin_body(sid, A=r(entry_id)))
    await store.rotate_entry(
        pool,
        kube,
        NS,
        "user",
        entry_id=entry_id,
        values={"KEY": SecretStr("x-value-1")},
        max_value_bytes=1024,
    )
    again = await service_client.post(P, json=pin_body(sid, B=r(second), C=r(uuid.uuid4())))
    assert again.status_code == 200
    assert again.json() == first.json()
    assert again.json()["pins"]["A"]["secret"] == secret_name(entry_id, 1)
    assert conn.execute("SELECT count(*) FROM pins").fetchone()[0] == 1
    assert len(await events(conn, "pins_created")) == 1
    # a new session after the rotate sees the new version
    fresh = await service_client.post(P, json=pin_body(A=r(entry_id)))
    assert fresh.json()["pins"]["A"]["version"] == 2


async def test_pins_zero_protected_entry_answers_values_only(service_client, pool, kube):
    entry_id = await make(
        pool, kube, "config", envs=[store.EnvIn("URL", False, SecretStr("https://cfg"))]
    )
    out = await service_client.post(P, json=pin_body(U=r(entry_id, "URL")))
    assert out.json() == {"pins": {}, "values": {"U": "https://cfg"}}


async def test_pins_unknown_entry_is_422_with_envs_and_entries(service_client, pool, kube, conn):
    real = await make(pool, kube, "real key")
    zed, alpha = uuid.uuid4(), uuid.uuid4()
    out = await service_client.post(P, json=pin_body(A=r(real), B=r(zed), C=r(alpha)))
    assert out.status_code == 422
    err = out.json()["error"]
    assert err["code"] == "vault_entry_unknown"
    assert err["envs"] == ["B", "C"]
    assert err["entries"] == sorted([str(zed), str(alpha)])
    assert conn.execute("SELECT count(*) FROM pins").fetchone()[0] == 0


async def test_pins_unknown_env_is_422(service_client, pool, kube, conn):
    real = await make(pool, kube, "real key")
    out = await service_client.post(P, json=pin_body(A=r(real), B=r(real, "OTHER")))
    assert out.status_code == 422
    err = out.json()["error"]
    assert (err["code"], err["envs"]) == ("vault_env_unknown", ["B"])
    assert conn.execute("SELECT count(*) FROM pins").fetchone()[0] == 0


async def test_pins_deleted_entry_is_unknown(service_client, pool, kube):
    gone = await make(pool, kube, "gone key")
    await store.delete_entry(pool, "user", entry_id=gone)
    out = await service_client.post(P, json=pin_body(A=r(gone)))
    assert out.json()["error"]["entries"] == [str(gone)]


async def test_pins_label_mismatch_is_422_with_envs(service_client, pool, kube, conn):
    team = await make(pool, kube, "team key", labels=["project:a"])
    out = await service_client.post(P, json=pin_body(labels=["project:b"], X=r(team)))
    assert out.status_code == 422
    err = out.json()["error"]
    assert (err["code"], err["envs"]) == ("vault_label_mismatch", ["X"])
    assert conn.execute("SELECT count(*) FROM pins").fetchone()[0] == 0


async def test_unknown_entry_then_unknown_env_then_mismatch(service_client, pool, kube):
    team = await make(pool, kube, "team key", labels=["project:a"])
    both = pin_body(labels=["project:b"], X=r(team), Y=r(uuid.uuid4()), Z=r(team, "NOPE"))
    out = await service_client.post(P, json=both)
    assert out.json()["error"]["code"] == "vault_entry_unknown"
    env_and_label = pin_body(labels=["project:b"], X=r(team), Z=r(team, "NOPE"))
    out = await service_client.post(P, json=env_and_label)
    assert out.json()["error"]["code"] == "vault_env_unknown"


@pytest.mark.parametrize(
    "body",
    [
        {"session_id": "not-a-uuid", "refs": {}},
        {"preset_labels": [], "refs": {}},
        {"session_id": str(uuid.uuid4()), "refs": {"lower": r(uuid.uuid4())}},
        {"session_id": str(uuid.uuid4()), "refs": {"A": "NAME"}},
    ],
)
async def test_pins_validation_is_422(service_client, body):
    out = await service_client.post(P, json=body)
    assert out.status_code == 422
    assert out.json()["error"]["code"] == "invalid_request"


async def test_pin_holds_for_share_so_a_rotate_waits_and_the_version_is_kept(pool, kube, db_url):
    import asyncio

    import psycopg

    from agents_vault.db import pins as pins_repo

    entry_id = await make(pool, kube, "team key")
    sid = uuid.uuid4()
    aconn = await psycopg.AsyncConnection.connect(db_url)
    try:
        async with aconn.transaction():
            rows = await pins_repo.share_lock_live_entries(aconn, [entry_id])
            assert rows[0]["current_version"] == 1
            rotating = asyncio.create_task(
                store.rotate_entry(
                    pool,
                    kube,
                    NS,
                    "user",
                    entry_id=entry_id,
                    values={"KEY": SecretStr("two-value")},
                    max_value_bytes=1024,
                )
            )
            await asyncio.sleep(0.5)
            assert not rotating.done()  # tx A waits for our share lock
            await pins_repo.insert_pin(aconn, sid, "A", entry_id, "KEY", 1)
        assert await asyncio.wait_for(rotating, 10) == 2
    finally:
        await aconn.close()
    versions = {v["version"]: v for v in await store.entry_versions(pool, entry_id)}
    assert versions[1]["state"] == "retired"
    assert versions[1]["pins"] == 1  # a live pin keeps the retired version from GC
    assert versions[2]["state"] == "live"


# release


async def test_release_only_that_session_and_repeat_is_quiet(service_client, pool, kube, conn):
    team = await make(pool, kube, "team key")
    mine, other = uuid.uuid4(), uuid.uuid4()
    await service_client.post(P, json=pin_body(mine, A=r(team)))
    await service_client.post(P, json=pin_body(other, A=r(team)))
    out = await service_client.delete(f"{P}/{mine}")
    assert out.status_code == 204
    assert out.content == b""
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


async def test_summary_shape_envs_attachments_q_and_name(service_client, pool, kube, fake_orch):
    alpha = await make(pool, kube, "Alpha key", labels=["team-a"], description="first", envs=MIXED)
    await make(pool, kube, "Beta key", description="second")
    preset = fake_orch.add_preset(
        "p1", spec={"env": {"GPG": {"vault": str(alpha), "env": "HARBOR_PASSWORD"}}}
    )
    out = await service_client.get(E)
    assert out.status_code == 200
    body = out.json()
    assert [e["name"] for e in body] == ["Alpha key", "Beta key"]
    assert set(body[0]) == {
        "id",
        "name",
        "description",
        "labels",
        "envs",
        "version",
        "updated_at",
        "attachments",
    }
    assert body[0]["id"] == str(alpha)
    assert [(e["env"], e["protected"], e["value"]) for e in body[0]["envs"]] == [
        ("HARBOR_URL", False, "https://harbor.example"),
        ("HARBOR_PASSWORD", True, None),
        ("HARBOR_USERNAME", False, "robot-user"),
    ]
    assert body[0]["attachments"] == [
        {
            "preset_id": str(preset.id),
            "preset_name": "p1",
            "env": "GPG",
            "entry_env": "HARBOR_PASSWORD",
        }
    ]
    assert body[1]["attachments"] == []
    only = await service_client.get(E, params={"q": "second"})
    assert [e["name"] for e in only.json()] == ["Beta key"]
    named = await service_client.get(E, params={"name": "ALPHA KEY"})
    assert [e["id"] for e in named.json()] == [str(alpha)]
    assert (await service_client.get(E, params={"name": "alpha"})).json() == []
    assert canary not in out.text


async def test_summary_attachments_none_when_orchestrator_unavailable(settings, pool, kube):
    await make(pool, kube, "alpha key")

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
        out = await c.get(E)
    assert out.status_code == 200
    assert out.json()[0]["attachments"] is None
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
        ("PATCH", f"{E}/{{entry_id}}"),
        ("PUT", f"{E}/{{entry_id}}/value"),
        ("DELETE", f"{E}/{{entry_id}}"),
        ("GET", f"{E}/{{entry_id}}"),
        ("GET", f"{E}/{{entry_id}}/pins"),
        ("GET", f"{PREFIX}/events"),
    ]:
        assert forbidden not in have


def test_web_app_has_no_resolve_or_pins_routes():
    web, _ = _apps()
    paths = {p for _, p in _routes(web)}
    assert f"{E}/resolve" not in paths
    assert not any(p.startswith(P) for p in paths)


async def test_scope_of_several_projects_matches_an_entry_of_any_of_them(
    service_client, pool, kube
):
    # a session in several projects is a full member of each (T-120): an entry of any project
    # in the scope matches, an entry of a project outside it does not
    a = await make(pool, kube, "a key", labels=["project:a"])
    b = await make(pool, kube, "b key", labels=["project:b", "team"])
    c = await make(pool, kube, "c key", labels=["project:c"])
    scope = ["project:a", "Project:b", "team-x"]
    resolved = await service_client.post(
        f"{E}/resolve", json={"preset_labels": scope, "refs": {"A": r(a), "B": r(b), "C": r(c)}}
    )
    assert resolved.status_code == 200
    assert resolved.json()["mismatched"] == ["C"]
    pinned = await service_client.post(P, json=pin_body(labels=scope, A=r(a), B=r(b)))
    assert pinned.status_code == 200
    assert sorted(pinned.json()["pins"]) == ["A", "B"]
    outside = await service_client.post(P, json=pin_body(labels=scope, A=r(a), C=r(c)))
    assert outside.status_code == 422
    assert outside.json()["error"]["code"] == "vault_label_mismatch"
    assert outside.json()["error"]["envs"] == ["C"]
