import json
import secrets
import uuid

import httpx
import pytest
from agents_common.orchestrator import OrchestratorClient

from agents_vault.api.app import PREFIX, create_service_app
from agents_vault.api.entries import router
from agents_vault.k8s import secret_name
from agents_vault.settings import Settings

canary = secrets.token_hex(16)
E = f"{PREFIX}/entries"
NAME = "Research GPG key"


def body(**over):
    data = {
        "name": NAME,
        "description": "gpg key",
        "labels": [],
        "envs": [{"env": "GPG_KEY", "protected": True, "value": canary}],
    }
    data.update(over)
    return data


def ref(entry_id, env="GPG_KEY"):
    return {"vault": str(entry_id), "env": env}


async def create(client, **over):
    return await client.post(E, json=body(**over))


async def make(client, **over) -> str:
    r = await create(client, **over)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def presets_calls(fake):
    return [r for r in fake.requests if r.url.path == "/api/v1/presets"]


MIXED = [
    {"env": "HARBOR_URL", "protected": False, "value": "https://harbor.example"},
    {"env": "HARBOR_PASSWORD", "protected": True, "value": canary},
    {"env": "HARBOR_USERNAME", "protected": False, "value": "robot-user"},
]


async def test_create_shape_and_no_protected_value_anywhere(web_client, kube):
    r = await create(web_client, labels=["Team-A"])
    assert r.status_code == 201
    out = r.json()
    assert set(out) == {
        "id",
        "name",
        "description",
        "labels",
        "envs",
        "version",
        "created_at",
        "updated_at",
        "attachments_count",
        "pinned_sessions_count",
        "behind_count",
    }
    uuid.UUID(out["id"])
    assert (out["name"], out["labels"], out["version"]) == (NAME, ["team-a"], 1)
    assert [(e["env"], e["protected"], e["value"]) for e in out["envs"]] == [
        ("GPG_KEY", True, None)
    ]
    assert set(out["envs"][0]) == {"env", "protected", "value", "updated_at"}
    assert out["attachments_count"] == 0
    assert canary not in r.text
    assert len(kube.applied("Secret")) == 1


async def test_create_mixed_envs_shows_readable_values_only(web_client, kube):
    r = await create(web_client, name="Harbor admin credentials", envs=MIXED)
    assert r.status_code == 201
    out = r.json()
    assert [(e["env"], e["protected"], e["value"]) for e in out["envs"]] == [
        ("HARBOR_URL", False, "https://harbor.example"),
        ("HARBOR_PASSWORD", True, None),
        ("HARBOR_USERNAME", False, "robot-user"),
    ]
    assert canary not in r.text
    (applied,) = kube.applied("Secret")
    assert applied.obj["stringData"] == {"HARBOR_PASSWORD": canary}
    listed = (await web_client.get(E)).json()
    assert listed[0]["envs"][0]["value"] == "https://harbor.example"
    detail = await web_client.get(f"{E}/{out['id']}")
    assert detail.json()["envs"][2]["value"] == "robot-user"
    assert canary not in detail.text


async def test_zero_protected_entry_is_allowed(web_client, kube):
    r = await create(web_client, envs=[{"env": "URL", "protected": False, "value": "u"}])
    assert r.status_code == 201
    assert kube.applied("Secret")[0].obj["stringData"] == {}
    rot = await web_client.put(f"{E}/{r.json()['id']}/value", json={"values": {}})
    assert rot.status_code == 422
    assert rot.json()["error"]["code"] == "vault_nothing_to_rotate"
    assert len(kube.applied("Secret")) == 1
    assert (await web_client.get(f"{E}/{r.json()['id']}")).json()["version"] == 1


@pytest.mark.parametrize(
    "over", [{"name": "a\x00b"}, {"description": "d\x00"}, {"labels": ["a\x00b"]}]
)
async def test_nul_in_name_description_or_label_is_422(web_client, over):
    r = await create(web_client, **over)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_request"
    entry_id = await make(web_client)
    patched = await web_client.patch(f"{E}/{entry_id}", json=over)
    assert patched.status_code == 422
    assert patched.json()["error"]["code"] == "invalid_request"


async def test_same_env_name_in_two_entries(web_client):
    one = await make(web_client, name="GitHub infra", envs=[MIXED[1] | {"env": "GITHUB_TOKEN"}])
    two = await make(web_client, name="GitHub lerobot", envs=[MIXED[1] | {"env": "GITHUB_TOKEN"}])
    assert one != two


async def test_list_search_and_label_filter(web_client):
    await make(web_client, name="ALPHA", description="first thing", labels=["team-a"])
    await make(web_client, name="BETA", description="second", labels=["team-b", "shared"])
    await make(web_client, name="GAMMA", description="third", labels=["shared"])

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
    entry_id = await make(web_client)
    await web_client.put(f"{E}/{entry_id}/value", json={"values": {"GPG_KEY": "two"}})
    r = await web_client.get(f"{E}/{entry_id}")
    assert r.status_code == 200
    out = r.json()
    assert out["version"] == 2
    assert [v["version"] for v in out["versions"]] == [2, 1]
    assert out["versions"][0]["state"] == "live"
    assert set(out["versions"][0]) == {"version", "state", "created_at", "retired_at", "pins"}
    assert out["attachments"] == []
    assert out["mismatched_attachments"] == []
    assert canary not in r.text


async def test_detail_404_and_bad_id_422(web_client):
    r = await web_client.get(f"{E}/{uuid.uuid4()}")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"
    assert (await web_client.get(f"{E}/NOPE")).status_code == 422


async def test_duplicate_is_409_case_insensitively(web_client):
    await create(web_client)
    for name in (NAME, NAME.upper(), f"  {NAME.lower()} "):
        r = await create(web_client, name=name)
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "vault_name_taken"


async def test_too_large_is_413(web_client, settings):
    big = "x" * (settings.max_value_bytes // 2 + 1)
    envs = [{"env": e, "protected": True, "value": big} for e in ("A", "B")]
    r = await create(web_client, envs=envs)
    assert r.status_code == 413
    assert r.json()["error"]["code"] == "secret_too_large"


@pytest.mark.parametrize(
    "over",
    [
        {"name": ""},
        {"name": "   "},
        {"name": "x" * 121},
        {"description": ""},
        {"labels": ["project:Bad_Slug"]},
        {"labels": ["bad label"]},
        {"extra": 1},
        {"envs": []},
        {"envs": [{"env": f"E{i}", "protected": True, "value": "v"} for i in range(21)]},
        {"envs": [{"env": "lower", "protected": True, "value": canary}]},
        {"envs": [{"env": "A", "protected": True, "value": canary}] * 2},
        {"envs": [{"env": "A", "value": canary}]},
        {"envs": [{"env": "A", "protected": False, "value": "x" * 4097}]},
    ],
)
async def test_create_422(web_client, over):
    r = await create(web_client, **over)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_request"
    assert canary not in r.text


async def test_missing_value_is_422_without_echo(web_client):
    r = await web_client.post(
        E,
        json={
            "name": "A",
            "description": "d",
            "envs": [{"env": "A", "protected": True, "value": 5}],
        },
    )
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
    assert (await web_client.get(f"{E}/{fixed}")).status_code == 404
    kube.heal("Secret", secret_name(fixed, 1))
    monkeypatch.undo()
    assert (await create(web_client)).status_code == 201


async def test_rotate_bumps_version(web_client, kube):
    entry_id = await make(web_client)
    r = await web_client.put(f"{E}/{entry_id}/value", json={"values": {"GPG_KEY": "new-value"}})
    assert r.status_code == 200
    assert r.json()["version"] == 2
    assert "new-value" not in r.text
    assert len(kube.applied("Secret")) == 2
    assert kube.applied("Secret")[1].obj["stringData"] == {"GPG_KEY": "new-value"}


async def test_rotate_must_name_exactly_the_protected_envs(web_client, kube):
    envs = [*MIXED, {"env": "HARBOR_TOKEN", "protected": True, "value": "t"}]
    entry_id = await make(web_client, envs=envs)
    url = f"{E}/{entry_id}/value"
    missing = await web_client.put(url, json={"values": {"HARBOR_PASSWORD": canary}})
    assert missing.status_code == 422
    err = missing.json()["error"]
    assert (err["code"], err["missing"], err["extra"]) == (
        "vault_envs_mismatch",
        ["HARBOR_TOKEN"],
        [],
    )
    extra = await web_client.put(
        url,
        json={"values": {"HARBOR_PASSWORD": canary, "HARBOR_TOKEN": "t", "HARBOR_URL": "u"}},
    )
    assert extra.status_code == 422
    assert (extra.json()["error"]["missing"], extra.json()["error"]["extra"]) == (
        [],
        ["HARBOR_URL"],
    )
    assert canary not in missing.text + extra.text
    assert len(kube.applied("Secret")) == 1
    ok = await web_client.put(
        url, json={"values": {"HARBOR_PASSWORD": canary, "HARBOR_TOKEN": "t"}}
    )
    assert ok.status_code == 200
    assert ok.json()["version"] == 2


async def test_rotate_errors(web_client, settings):
    missing = await web_client.put(f"{E}/{uuid.uuid4()}/value", json={"values": {"GPG_KEY": "x"}})
    assert missing.status_code == 404
    entry_id = await make(web_client)
    big = await web_client.put(
        f"{E}/{entry_id}/value",
        json={"values": {"GPG_KEY": "x" * (settings.max_value_bytes + 1)}},
    )
    assert big.status_code == 413
    old = await web_client.put(f"{E}/{entry_id}/value", json={"value": "x"})
    assert old.status_code == 422


async def test_rotate_kube_failure_is_502(web_client, kube):
    entry_id = await make(web_client)
    kube.fail("Secret", secret_name(uuid.UUID(entry_id), 2))
    r = await web_client.put(f"{E}/{entry_id}/value", json={"values": {"GPG_KEY": "new"}})
    assert r.status_code == 502
    assert r.json()["error"]["code"] == "secret_store_failed"
    assert (await web_client.get(f"{E}/{entry_id}")).json()["version"] == 1


async def test_patch_description_only_and_labels_only(web_client):
    entry_id = await make(web_client, labels=["a"])
    d = await web_client.patch(f"{E}/{entry_id}", json={"description": "new text"})
    assert d.status_code == 200
    assert d.json()["description"] == "new text"
    assert d.json()["labels"] == ["a"]
    assert d.json()["version"] == 1
    lab = await web_client.patch(f"{E}/{entry_id}", json={"labels": ["B", "c"]})
    assert lab.json()["labels"] == ["b", "c"]
    assert lab.json()["description"] == "new text"


async def test_patch_rename_free_but_unique(web_client, fake_orch):
    entry_id = await make(web_client)
    other = await make(web_client, name="Other key")
    fake_orch.add_preset("research", spec={"env": {"GPG": ref(entry_id)}})
    web_client.app.state.attachments = None
    r = await web_client.patch(f"{E}/{entry_id}", json={"name": " Renamed GPG key "})
    assert r.status_code == 200  # attached, still renamed: refs carry the id
    assert r.json()["name"] == "Renamed GPG key"
    assert r.json()["attachments_count"] == 1
    taken = await web_client.patch(f"{E}/{other}", json={"name": "renamed gpg KEY"})
    assert taken.status_code == 409
    assert taken.json()["error"]["code"] == "vault_name_taken"


async def test_patch_readable_value_and_refuse_protected(web_client, kube):
    entry_id = await make(web_client, envs=MIXED)
    r = await web_client.patch(
        f"{E}/{entry_id}", json={"envs": {"HARBOR_URL": "https://new.example"}}
    )
    assert r.status_code == 200
    out = r.json()
    assert out["envs"][0]["value"] == "https://new.example"
    assert out["version"] == 1
    assert len(kube.applied("Secret")) == 1
    refused = await web_client.patch(
        f"{E}/{entry_id}", json={"envs": {"HARBOR_PASSWORD": canary, "HARBOR_URL": "x"}}
    )
    assert refused.status_code == 422
    err = refused.json()["error"]
    assert (err["code"], err["envs"]) == ("vault_env_protected", ["HARBOR_PASSWORD"])
    assert canary not in refused.text
    unknown = await web_client.patch(f"{E}/{entry_id}", json={"envs": {"NOPE": "x"}})
    assert unknown.status_code == 422
    assert unknown.json()["error"]["code"] == "vault_env_unknown"
    after = (await web_client.get(f"{E}/{entry_id}")).json()
    assert after["envs"][0]["value"] == "https://new.example"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"name": ""},
        {"description": ""},
        {"labels": ["project:Bad_Slug"]},
        {"envs": {"A": 5}},
        {"value": "x"},
    ],
)
async def test_patch_422(web_client, payload):
    entry_id = await make(web_client)
    r = await web_client.patch(f"{E}/{entry_id}", json=payload)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "invalid_request"


async def test_patch_404(web_client):
    r = await web_client.patch(f"{E}/{uuid.uuid4()}", json={"description": "x"})
    assert r.status_code == 404


async def test_attachment_matches_on_shared_label(web_client, fake_orch):
    entry_id = await make(web_client, labels=["team-a"])
    fake_orch.add_preset("research", spec={"env": {"GPG": ref(entry_id)}}, labels=["team-a", "x"])
    web_client.app.state.attachments = None
    out = (await web_client.get(f"{E}/{entry_id}")).json()
    [att] = out["attachments"]
    assert att["matches"] is True
    assert (att["preset_name"], att["env"], att["entry_env"], att["preset_labels"]) == (
        "research",
        "GPG",
        "GPG_KEY",
        ["team-a", "x"],
    )
    assert out["mismatched_attachments"] == []
    assert out["attachments_count"] == 1


async def test_attachments_listed_per_env(web_client, fake_orch):
    entry_id = await make(web_client, envs=MIXED)
    fake_orch.add_preset(
        "harbor",
        spec={
            "env": {
                "URL": ref(entry_id, "HARBOR_URL"),
                "PASSWORD": ref(entry_id, "HARBOR_PASSWORD"),
            }
        },
    )
    web_client.app.state.attachments = None
    out = (await web_client.get(f"{E}/{entry_id}")).json()
    assert [(a["env"], a["entry_env"]) for a in out["attachments"]] == [
        ("URL", "HARBOR_URL"),
        ("PASSWORD", "HARBOR_PASSWORD"),
    ]


async def test_attachment_disjoint_labels_do_not_match(web_client, fake_orch):
    entry_id = await make(web_client, labels=["project:a"])
    fake_orch.add_preset("research", spec={"env": {"GPG": ref(entry_id)}}, labels=["project:b"])
    web_client.app.state.attachments = None
    out = (await web_client.get(f"{E}/{entry_id}")).json()
    assert out["attachments"][0]["matches"] is False
    assert [a["preset_name"] for a in out["mismatched_attachments"]] == ["research"]


async def test_attachment_tag_only_entry_matches_any_preset(web_client, fake_orch):
    entry_id = await make(web_client, labels=["admin", "github"])
    fake_orch.add_preset("research", spec={"env": {"GPG": ref(entry_id)}}, labels=["team-b"])
    web_client.app.state.attachments = None
    out = (await web_client.get(f"{E}/{entry_id}")).json()
    assert out["attachments"][0]["matches"] is True
    assert out["mismatched_attachments"] == []


async def test_unlabelled_entry_matches_a_preset_without_labels(web_client, fake_orch):
    entry_id = await make(web_client)
    fake_orch.add_preset("research", spec={"env": {"GPG": ref(entry_id)}})
    web_client.app.state.attachments = None
    out = (await web_client.get(f"{E}/{entry_id}")).json()
    assert out["attachments"][0]["matches"] is True


async def test_attachments_count_counts_refs_by_id(web_client, fake_orch):
    research = await make(web_client)
    other = await make(web_client, name="OTHER")
    await make(web_client, name="UNUSED")
    fake_orch.add_preset("one", spec={"env": {"GPG": ref(research)}})
    fake_orch.add_preset("two", spec={"env": {"A": ref(research)}})
    fake_orch.add_preset("other", spec={"env": {"A": ref(other)}})
    fake_orch.add_preset("by-name", spec={"env": {"A": {"vault": "UNUSED", "env": "GPG_KEY"}}})
    web_client.app.state.attachments = None
    counts = {e["name"]: e["attachments_count"] for e in (await web_client.get(E)).json()}
    assert counts == {"OTHER": 1, NAME: 2, "UNUSED": 0}


async def test_patch_relabel_reports_mismatched(web_client, fake_orch):
    entry_id = await make(web_client, labels=["project:a"])
    fake_orch.add_preset("research", spec={"env": {"GPG": ref(entry_id)}}, labels=["project:a"])
    web_client.app.state.attachments = None
    r = await web_client.patch(f"{E}/{entry_id}", json={"labels": ["project:z"]})
    assert r.status_code == 200
    assert [a["preset_name"] for a in r.json()["mismatched_attachments"]] == ["research"]
    ok = await web_client.patch(f"{E}/{entry_id}", json={"labels": ["project:a"]})
    assert ok.json()["mismatched_attachments"] == []


async def test_patch_retag_never_reports_mismatched(web_client, fake_orch):
    entry_id = await make(web_client, labels=["project:a"])
    fake_orch.add_preset("research", spec={"env": {"GPG": ref(entry_id)}}, labels=["project:a"])
    web_client.app.state.attachments = None
    r = await web_client.patch(f"{E}/{entry_id}", json={"labels": ["team-z", "admin"]})
    assert r.status_code == 200
    assert r.json()["mismatched_attachments"] == []


async def test_orchestrator_failure_gives_null_attachments(web_client, fake_orch):
    entry_id = await make(web_client)
    web_client.app.state.attachments = None  # create warmed the 15 s cache; start cold
    fake_orch.fail_next("list_presets", 500)
    r = await web_client.get(E)
    assert r.status_code == 200
    assert r.json()[0]["attachments_count"] is None
    web_client.app.state.attachments = None  # the failed list is not cached; rebuild cold
    fake_orch.fail_next("list_presets", 500)
    d = await web_client.get(f"{E}/{entry_id}")
    assert d.status_code == 200
    assert d.json()["attachments"] is None
    assert d.json()["mismatched_attachments"] is None
    assert d.json()["attachments_count"] is None


async def test_delete_409_lists_attachments(web_client, fake_orch):
    entry_id = await make(web_client)
    preset = fake_orch.add_preset("research", spec={"env": {"GPG": ref(entry_id)}})
    r = await web_client.delete(f"{E}/{entry_id}")
    assert r.status_code == 409
    error = r.json()["error"]
    assert error["code"] == "vault_entry_attached"
    assert error["attachments"] == [
        {
            "preset_id": str(preset.id),
            "preset_name": "research",
            "env": "GPG",
            "entry_env": "GPG_KEY",
        }
    ]
    assert (await web_client.get(f"{E}/{entry_id}")).status_code == 200


async def test_delete_503_when_orchestrator_fails(web_client, fake_orch):
    entry_id = await make(web_client)
    fake_orch.fail_next("list_presets", 500)
    r = await web_client.delete(f"{E}/{entry_id}")
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "orchestrator_unavailable"
    assert (await web_client.get(f"{E}/{entry_id}")).status_code == 200


async def test_delete_503_on_wrong_token(web_client, fake_orch):
    entry_id = await make(web_client)
    fake_orch.token = "something-else"
    r = await web_client.delete(f"{E}/{entry_id}")
    assert r.status_code == 503
    fake_orch.token = "orchestrator-secret"
    assert (await web_client.get(f"{E}/{entry_id}")).status_code == 200


async def test_delete_204_then_404(web_client):
    entry_id = await make(web_client)
    assert (await web_client.delete(f"{E}/{entry_id}")).status_code == 204
    assert (await web_client.get(f"{E}/{entry_id}")).status_code == 404
    assert (await web_client.delete(f"{E}/{entry_id}")).status_code == 404


async def test_cache_hit_on_lists_and_delete_always_asks(web_client, fake_orch):
    entry_id = await make(web_client)
    web_client.app.state.attachments = None  # create warmed the cache; the first list asks
    fake_orch.requests.clear()
    await web_client.get(E)
    await web_client.get(E)
    assert len(presets_calls(fake_orch)) == 1
    await web_client.delete(f"{E}/{entry_id}")
    assert len(presets_calls(fake_orch)) == 2


async def test_pins_route_lists_only_unreleased(web_client):
    entry_id = await make(web_client)
    pool = web_client.app.state.pool
    live, released = uuid.uuid4(), uuid.uuid4()
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO pins (session_id, env, entry_id, entry_env, version)"
            " VALUES (%s, 'A', %s, 'GPG_KEY', 1)",
            (live, entry_id),
        )
        await conn.execute(
            "INSERT INTO pins (session_id, env, entry_id, entry_env, version, released_at)"
            " VALUES (%s, 'B', %s, 'GPG_KEY', 1, now())",
            (released, entry_id),
        )
    r = await web_client.get(f"{E}/{entry_id}/pins")
    assert r.status_code == 200
    [pin] = r.json()
    assert (pin["session_id"], pin["env"], pin["entry_env"], pin["version"]) == (
        str(live),
        "A",
        "GPG_KEY",
        1,
    )
    assert "created_at" in pin
    view = (await web_client.get(f"{E}/{entry_id}")).json()
    assert view["pinned_sessions_count"] == 1
    assert (await web_client.get(f"{E}/{uuid.uuid4()}/pins")).status_code == 404


async def test_events_newest_first_paging_filter_and_limits(web_client):
    one = await make(web_client, name="ONE")
    await make(web_client, name="TWO")
    await web_client.put(f"{E}/{one}/value", json={"values": {"GPG_KEY": "v"}})
    await web_client.patch(f"{E}/{one}", json={"name": "ONE renamed"})
    url = f"{PREFIX}/events"
    allr = (await web_client.get(url)).json()
    assert [e["kind"] for e in allr] == [
        "entry_updated",
        "entry_rotated",
        "entry_created",
        "entry_created",
    ]
    assert set(allr[0]) == {"id", "ts", "kind", "actor", "entry_id", "entry_name", "data"}
    assert allr[0]["actor"] == "user"
    assert [e["id"] for e in allr] == sorted((e["id"] for e in allr), reverse=True)
    older = (await web_client.get(url, params={"before_id": allr[0]["id"]})).json()
    assert [e["id"] for e in older] == [e["id"] for e in allr[1:]]
    mine = (await web_client.get(url, params={"entry": one})).json()
    assert {e["entry_id"] for e in mine} == {one}
    assert {e["entry_name"] for e in mine} == {"ONE", "ONE renamed"}
    assert len(mine) == 3
    assert len((await web_client.get(url, params={"limit": 1})).json()) == 1
    assert (await web_client.get(url, params={"limit": 0})).status_code == 422
    assert (await web_client.get(url, params={"limit": 201})).status_code == 422
    assert (await web_client.get(url, params={"entry": "ONE"})).status_code == 422
    assert canary not in json.dumps(allr)


async def test_no_protected_value_in_any_response_or_event(web_client):
    r = await create(web_client, envs=MIXED)
    entry_id = r.json()["id"]
    await web_client.patch(f"{E}/{entry_id}", json={"envs": {"HARBOR_URL": "https://v2"}})
    texts = [
        r.text,
        (await web_client.get(E)).text,
        (await web_client.get(f"{E}/{entry_id}")).text,
    ]
    assert all(canary not in t for t in texts)
    events = (await web_client.get(f"{PREFIX}/events")).text
    assert canary not in events
    assert "https://" not in events and "robot-user" not in events  # names only, no values
    assert "HARBOR_URL" in events


def test_web_routes_are_absent_from_the_service_app():
    settings = Settings(
        database_url="postgresql://u:p@db.invalid/vault",
        orchestrator_url="http://orchestrator.invalid",
        orchestrator_token="orch",
        namespace="agents",
    )
    service = create_service_app(settings, None, ["tok"])
    # included routers are opaque in app.routes (newer FastAPI): compare the OpenAPI operations
    have = {(m.upper(), p) for p, ops in service.openapi()["paths"].items() for m in ops}
    mine = {(m, PREFIX + route.path) for route in router.routes for m in route.methods}
    assert mine
    # GET /entries exists on both listeners with different shapes (the service one is a
    # summary); every other web route is absent from the service app
    assert mine & have == {("GET", E)}


async def test_delete_503_on_a_200_with_a_bad_body(web_client, fake_orch):
    entry_id = await make(web_client)
    web_client.app.state.attachments = None
    web_client.app.state.orchestrator = OrchestratorClient(
        "http://orch",
        "t",
        transport=httpx.MockTransport(lambda request: httpx.Response(200, text="not json")),
    )
    r = await web_client.delete(f"{E}/{entry_id}")
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "orchestrator_unavailable"
    listed = await web_client.get(E)
    assert listed.status_code == 200
    assert listed.json()[0]["attachments_count"] is None
