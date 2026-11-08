import json
import secrets
import uuid

import pytest

from agents_vault import store
from agents_vault.api.app import PREFIX, create_service_app
from agents_vault.api.entries import router
from agents_vault.k8s import secret_name
from agents_vault.settings import Settings

canary = secrets.token_hex(16)
E = f"{PREFIX}/entries"
REF = {"env": {"GPG_KEY": {"vault": "RESEARCH_GPG_KEY"}}}


def body(**over):
    data = {"name": "RESEARCH_GPG_KEY", "description": "gpg key", "labels": [], "value": canary}
    data.update(over)
    return data


async def create(client, **over):
    return await client.post(E, json=body(**over))


def presets_calls(fake):
    return [r for r in fake.requests if r.url.path == "/api/v1/presets"]


async def test_create_shape_and_no_value_anywhere(web_client, kube):
    r = await create(web_client, labels=["Team-A"])
    assert r.status_code == 201
    out = r.json()
    assert set(out) == {
        "name",
        "description",
        "labels",
        "version",
        "created_at",
        "updated_at",
        "attachments_count",
        "pinned_sessions_count",
        "behind_count",
    }
    assert (out["name"], out["labels"], out["version"]) == ("RESEARCH_GPG_KEY", ["team-a"], 1)
    assert out["attachments_count"] == 0
    assert canary not in r.text
    assert len(kube.applied("Secret")) == 1


async def test_list_search_and_label_filter(web_client):
    await create(web_client, name="ALPHA", description="first thing", labels=["team-a"])
    await create(web_client, name="BETA", description="second", labels=["team-b", "shared"])
    await create(web_client, name="GAMMA", description="third", labels=["shared"])

    async def names(**params):
        r = await web_client.get(E, params=params)
        assert r.status_code == 200
        return [e["name"] for e in r.json()]

    assert await names() == ["ALPHA", "BETA", "GAMMA"]
    assert await names(q="alp") == ["ALPHA"]
    assert await names(q="SECOND") == ["BETA"]
    assert await names(q="team-b") == ["BETA"]
    assert await names(label="shared") == ["BETA", "GAMMA"]
    assert await names(label=["team-a", "team-b"]) == ["ALPHA", "BETA"]
    assert await names(q="a", label="shared") == ["BETA", "GAMMA"]


async def test_detail_with_versions(web_client):
    await create(web_client)
    await web_client.put(f"{E}/RESEARCH_GPG_KEY/value", json={"value": "two"})
    r = await web_client.get(f"{E}/RESEARCH_GPG_KEY")
    assert r.status_code == 200
    out = r.json()
    assert out["version"] == 2
    assert [v["version"] for v in out["versions"]] == [2, 1]
    assert out["versions"][0]["state"] == "live"
    assert set(out["versions"][0]) == {"version", "state", "created_at", "retired_at", "pins"}
    assert out["attachments"] == []
    assert out["mismatched_attachments"] == []
    assert canary not in r.text


async def test_detail_404(web_client):
    r = await web_client.get(f"{E}/NOPE")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"


async def test_duplicate_is_409(web_client):
    await create(web_client)
    r = await create(web_client)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "vault_name_taken"


async def test_too_large_is_413(web_client, settings):
    r = await create(web_client, value="x" * (settings.max_value_bytes + 1))
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "secret_too_large"


@pytest.mark.parametrize(
    "over",
    [
        {"name": "lower"},
        {"description": ""},
        {"labels": ["project:Bad"]},
        {"labels": ["bad label"]},
        {"extra": 1},
    ],
)
async def test_create_422(web_client, over):
    r = await create(web_client, **over)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_request"
    assert canary not in r.text


async def test_missing_value_is_422_without_echo(web_client):
    r = await web_client.post(E, json={"name": "A", "description": "d", "value": 5})
    assert r.status_code == 422
    assert "5" not in r.json()["error"]["message"]


async def test_kube_failure_is_502_and_name_is_free(web_client, kube, monkeypatch):
    fixed = uuid.uuid4()
    monkeypatch.setattr(uuid, "uuid4", lambda: fixed)
    kube.fail("Secret", secret_name(fixed, 1))
    r = await create(web_client)
    assert r.status_code == 502
    assert r.json()["error"]["code"] == "secret_store_failed"
    assert canary not in r.text
    assert (await web_client.get(f"{E}/RESEARCH_GPG_KEY")).status_code == 404
    kube.heal("Secret", secret_name(fixed, 1))
    monkeypatch.undo()
    assert (await create(web_client)).status_code == 201


async def test_rotate_bumps_version(web_client, kube):
    await create(web_client)
    r = await web_client.put(f"{E}/RESEARCH_GPG_KEY/value", json={"value": "new"})
    assert r.status_code == 200
    assert r.json()["version"] == 2
    assert "new" not in json.dumps(r.json().get("value", ""))
    assert len(kube.applied("Secret")) == 2


async def test_rotate_errors(web_client, settings):
    missing = await web_client.put(f"{E}/NOPE/value", json={"value": "x"})
    assert missing.status_code == 404
    await create(web_client)
    big = await web_client.put(
        f"{E}/RESEARCH_GPG_KEY/value", json={"value": "x" * (settings.max_value_bytes + 1)}
    )
    assert big.status_code == 413


async def test_rotate_kube_failure_is_502(web_client, kube):
    await create(web_client)
    app = web_client.app
    row = await store.get_entry(app.state.pool, "RESEARCH_GPG_KEY")
    kube.fail("Secret", secret_name(row["id"], 2))
    r = await web_client.put(f"{E}/RESEARCH_GPG_KEY/value", json={"value": "new"})
    assert r.status_code == 502
    assert r.json()["error"]["code"] == "secret_store_failed"
    assert (await web_client.get(f"{E}/RESEARCH_GPG_KEY")).json()["version"] == 1


async def test_patch_description_only_and_labels_only(web_client):
    await create(web_client, labels=["a"])
    d = await web_client.patch(f"{E}/RESEARCH_GPG_KEY", json={"description": "new text"})
    assert d.status_code == 200
    assert d.json()["description"] == "new text"
    assert d.json()["labels"] == ["a"]
    assert d.json()["version"] == 1
    lab = await web_client.patch(f"{E}/RESEARCH_GPG_KEY", json={"labels": ["B", "c"]})
    assert lab.json()["labels"] == ["b", "c"]
    assert lab.json()["description"] == "new text"


@pytest.mark.parametrize(
    "payload", [{}, {"name": "X"}, {"description": ""}, {"labels": ["project:Bad"]}]
)
async def test_patch_422(web_client, payload):
    await create(web_client)
    r = await web_client.patch(f"{E}/RESEARCH_GPG_KEY", json=payload)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_request"


async def test_patch_404(web_client):
    r = await web_client.patch(f"{E}/NOPE", json={"description": "x"})
    assert r.status_code == 404


async def test_attachment_matches_on_shared_label(web_client, fake_orch):
    fake_orch.add_preset("research", spec=REF, labels=["team-a", "x"])
    await create(web_client, labels=["team-a"])
    out = (await web_client.get(f"{E}/RESEARCH_GPG_KEY")).json()
    [att] = out["attachments"]
    assert att["matches"] is True
    assert (att["preset_name"], att["env"], att["preset_labels"]) == (
        "research",
        "GPG_KEY",
        ["team-a", "x"],
    )
    assert out["mismatched_attachments"] == []
    assert out["attachments_count"] == 1


async def test_attachment_disjoint_labels_do_not_match(web_client, fake_orch):
    fake_orch.add_preset("research", spec=REF, labels=["team-b"])
    await create(web_client, labels=["team-a"])
    out = (await web_client.get(f"{E}/RESEARCH_GPG_KEY")).json()
    assert out["attachments"][0]["matches"] is False
    assert [a["preset_name"] for a in out["mismatched_attachments"]] == ["research"]


async def test_unlabelled_entry_matches_a_preset_without_labels(web_client, fake_orch):
    fake_orch.add_preset("research", spec=REF)
    await create(web_client)
    out = (await web_client.get(f"{E}/RESEARCH_GPG_KEY")).json()
    assert out["attachments"][0]["matches"] is True


async def test_attachments_count_counts_refs(web_client, fake_orch):
    fake_orch.add_preset("one", spec=REF)
    fake_orch.add_preset("two", spec={"env": {"A": {"vault": "RESEARCH_GPG_KEY"}}})
    fake_orch.add_preset("other", spec={"env": {"A": {"vault": "OTHER"}}})
    await create(web_client)
    await create(web_client, name="OTHER")
    await create(web_client, name="UNUSED")
    counts = {e["name"]: e["attachments_count"] for e in (await web_client.get(E)).json()}
    assert counts == {"OTHER": 1, "RESEARCH_GPG_KEY": 2, "UNUSED": 0}


async def test_patch_relabel_reports_mismatched(web_client, fake_orch):
    fake_orch.add_preset("research", spec=REF, labels=["team-a"])
    await create(web_client, labels=["team-a"])
    r = await web_client.patch(f"{E}/RESEARCH_GPG_KEY", json={"labels": ["team-z"]})
    assert r.status_code == 200
    assert [a["preset_name"] for a in r.json()["mismatched_attachments"]] == ["research"]
    ok = await web_client.patch(f"{E}/RESEARCH_GPG_KEY", json={"labels": ["team-a"]})
    assert ok.json()["mismatched_attachments"] == []


async def test_orchestrator_failure_gives_null_attachments(web_client, fake_orch):
    await create(web_client)
    fake_orch.fail_next("list_presets", 500)
    r = await web_client.get(E)
    assert r.status_code == 200
    assert r.json()[0]["attachments_count"] is None
    fake_orch.fail_next("list_presets", 500)
    d = await web_client.get(f"{E}/RESEARCH_GPG_KEY")
    assert d.status_code == 200
    assert d.json()["attachments"] is None
    assert d.json()["mismatched_attachments"] is None
    assert d.json()["attachments_count"] is None


async def test_delete_409_lists_attachments(web_client, fake_orch):
    ref = fake_orch.add_preset("research", spec=REF)
    await create(web_client)
    r = await web_client.delete(f"{E}/RESEARCH_GPG_KEY")
    assert r.status_code == 409
    error = r.json()["error"]
    assert error["code"] == "vault_entry_attached"
    assert error["attachments"] == [
        {"preset_id": str(ref.id), "preset_name": "research", "env": "GPG_KEY"}
    ]
    assert (await web_client.get(f"{E}/RESEARCH_GPG_KEY")).status_code == 200


async def test_delete_503_when_orchestrator_fails(web_client, fake_orch):
    await create(web_client)
    fake_orch.fail_next("list_presets", 500)
    r = await web_client.delete(f"{E}/RESEARCH_GPG_KEY")
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "orchestrator_unavailable"
    assert (await web_client.get(f"{E}/RESEARCH_GPG_KEY")).status_code == 200


async def test_delete_503_on_wrong_token(web_client, fake_orch):
    await create(web_client)
    fake_orch.token = "something-else"
    r = await web_client.delete(f"{E}/RESEARCH_GPG_KEY")
    assert r.status_code == 503
    fake_orch.token = "orchestrator-secret"
    assert (await web_client.get(f"{E}/RESEARCH_GPG_KEY")).status_code == 200


async def test_delete_204_then_404(web_client):
    await create(web_client)
    assert (await web_client.delete(f"{E}/RESEARCH_GPG_KEY")).status_code == 204
    assert (await web_client.get(f"{E}/RESEARCH_GPG_KEY")).status_code == 404
    assert (await web_client.delete(f"{E}/RESEARCH_GPG_KEY")).status_code == 404


async def test_cache_hit_on_lists_and_delete_always_asks(web_client, fake_orch):
    await create(web_client)
    fake_orch.requests.clear()
    await web_client.get(E)
    await web_client.get(E)
    assert len(presets_calls(fake_orch)) == 1
    await web_client.delete(f"{E}/RESEARCH_GPG_KEY")
    assert len(presets_calls(fake_orch)) == 2


async def test_pins_route_lists_only_unreleased(web_client):
    await create(web_client)
    pool = web_client.app.state.pool
    entry = await store.get_entry(pool, "RESEARCH_GPG_KEY")
    live, released = uuid.uuid4(), uuid.uuid4()
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO pins (session_id, env, entry_id, version) VALUES (%s, 'A', %s, 1)",
            (live, entry["id"]),
        )
        await conn.execute(
            "INSERT INTO pins (session_id, env, entry_id, version, released_at)"
            " VALUES (%s, 'B', %s, 1, now())",
            (released, entry["id"]),
        )
    r = await web_client.get(f"{E}/RESEARCH_GPG_KEY/pins")
    assert r.status_code == 200
    [pin] = r.json()
    assert (pin["session_id"], pin["env"], pin["version"]) == (str(live), "A", 1)
    assert "created_at" in pin
    view = (await web_client.get(f"{E}/RESEARCH_GPG_KEY")).json()
    assert view["pinned_sessions_count"] == 1
    assert (await web_client.get(f"{E}/NOPE/pins")).status_code == 404


async def test_events_newest_first_paging_filter_and_limits(web_client):
    await create(web_client, name="ONE")
    await create(web_client, name="TWO")
    await web_client.put(f"{E}/ONE/value", json={"value": "v"})
    url = f"{PREFIX}/events"
    allr = (await web_client.get(url)).json()
    assert [e["kind"] for e in allr] == ["entry_rotated", "entry_created", "entry_created"]
    assert set(allr[0]) == {"id", "ts", "kind", "actor", "entry_name", "data"}
    assert allr[0]["actor"] == "user"
    assert [e["id"] for e in allr] == sorted((e["id"] for e in allr), reverse=True)
    older = (await web_client.get(url, params={"before_id": allr[0]["id"]})).json()
    assert [e["id"] for e in older] == [e["id"] for e in allr[1:]]
    one = (await web_client.get(url, params={"entry": "ONE"})).json()
    assert {e["entry_name"] for e in one} == {"ONE"}
    assert len((await web_client.get(url, params={"limit": 1})).json()) == 1
    assert (await web_client.get(url, params={"limit": 0})).status_code == 422
    assert (await web_client.get(url, params={"limit": 201})).status_code == 422
    assert canary not in json.dumps(allr)


async def test_no_value_in_any_response_or_event(web_client):
    r = await create(web_client)
    texts = [
        r.text,
        (await web_client.get(E)).text,
        (await web_client.get(f"{E}/RESEARCH_GPG_KEY")).text,
        (await web_client.get(f"{PREFIX}/events")).text,
    ]
    assert all(canary not in t for t in texts)


def test_web_routes_are_absent_from_the_service_app():
    settings = Settings(
        database_url="postgresql://u:p@db.invalid/vault",
        orchestrator_url="http://orchestrator.invalid",
        orchestrator_token="orch",
        namespace="agents",
    )
    service = create_service_app(settings, None, ["tok"])
    have = {(m, route.path) for route in service.routes for m in getattr(route, "methods", ())}
    mine = {(m, PREFIX + route.path) for route in router.routes for m in route.methods}
    assert mine
    assert not mine & have
