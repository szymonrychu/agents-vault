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


NAME = "API key"


def protected(env="API_KEY", value=canary):
    return store.EnvIn(env, True, SecretStr(value))


def readable(env, value):
    return store.EnvIn(env, False, SecretStr(value))


async def create(
    pool, kube, name=NAME, value=canary, labels=None, max_bytes=MAX, actor="user", envs=None
):
    return await store.create_entry(
        pool,
        kube,
        NS,
        actor,
        name=name,
        description="a key",
        labels=labels or [],
        envs=envs if envs is not None else [protected(value=value)],
        max_value_bytes=max_bytes,
    )


async def rotate(pool, kube, entry_id, value=canary, values=None):
    return await store.rotate_entry(
        pool,
        kube,
        NS,
        "user",
        entry_id=entry_id,
        values=values if values is not None else {"API_KEY": SecretStr(value)},
        max_value_bytes=MAX,
    )


async def only(pool):
    (entry,) = await store.list_entries(pool)
    return entry


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
    entry = await store.get_entry(pool, entry_id)
    assert entry["name"] == NAME
    assert entry["current_version"] == 1
    assert entry["labels"] == ["team-a"]
    (v,) = await versions(pool, entry_id)
    assert (v["version"], v["state"], v["deleted_at"]) == (1, "live", None)
    assert kube.has("Secret", secret_name(entry_id, 1))
    (event,) = await store.list_events(pool, entry_id)
    assert event["kind"] == "entry_created"
    assert event["actor"] == "user"
    assert event["entry_id"] == entry_id
    assert event["data"] == {
        "name": NAME,
        "labels": ["team-a"],
        "envs": ["API_KEY"],
        "protected": ["API_KEY"],
    }
    assert canary not in str(event)


async def test_create_with_mixed_envs_keeps_order_and_splits_values(pool):
    kube = FakeKube()
    envs = [
        readable("HARBOR_URL", "https://harbor.example"),
        protected("HARBOR_PASSWORD", canary),
        readable("HARBOR_USERNAME", "robot-user"),
        protected("HARBOR_TOKEN", "token-01"),
    ]
    entry_id = await create(pool, kube, name="Harbor admin credentials", envs=envs)
    entry = await store.get_entry(pool, entry_id)
    assert [(e["env"], e["protected"], e["value"]) for e in entry["envs"]] == [
        ("HARBOR_URL", False, "https://harbor.example"),
        ("HARBOR_PASSWORD", True, None),
        ("HARBOR_USERNAME", False, "robot-user"),
        ("HARBOR_TOKEN", True, None),
    ]
    (applied,) = kube.applied("Secret")
    assert applied.obj["stringData"] == {"HARBOR_PASSWORD": canary, "HARBOR_TOKEN": "token-01"}
    (event,) = await store.list_events(pool, entry_id)
    assert event["data"]["envs"] == [
        "HARBOR_URL",
        "HARBOR_PASSWORD",
        "HARBOR_USERNAME",
        "HARBOR_TOKEN",
    ]
    assert event["data"]["protected"] == ["HARBOR_PASSWORD", "HARBOR_TOKEN"]
    assert "https://harbor.example" not in str(event) and "robot-user" not in str(event)


async def test_zero_protected_entry_still_writes_an_empty_secret(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube, envs=[readable("URL", "https://x")])
    assert (await store.get_entry(pool, entry_id))["current_version"] == 1
    (applied,) = kube.applied("Secret")
    assert applied.obj["stringData"] == {}
    assert kube.has("Secret", secret_name(entry_id, 1))
    with pytest.raises(store.NothingToRotate):
        await rotate(pool, kube, entry_id, values={})
    with pytest.raises(store.NothingToRotate):
        await rotate(pool, kube, entry_id, values={"URL": SecretStr("x")})
    assert len(kube.applies) == 1
    assert [v["version"] for v in await versions(pool, entry_id)] == [1]


@pytest.mark.parametrize(
    "over",
    [{"name": "a\x00b"}, {"description": "d\x00"}, {"labels": ["a\x00b"]}],
)
async def test_nul_in_name_description_or_label_is_a_value_error(pool, over):
    kube = FakeKube()
    args = {"name": NAME, "description": "a key", "labels": []} | over
    with pytest.raises(ValueError):
        await store.create_entry(
            pool,
            kube,
            NS,
            "user",
            envs=[protected()],
            max_value_bytes=MAX,
            **args,
        )
    assert kube.calls == []
    entry_id = await create(pool, kube)
    with pytest.raises(ValueError):
        await store.update_entry(pool, "user", entry_id=entry_id, **over)


async def test_env_names_may_repeat_across_entries(pool):
    kube = FakeKube()
    one = await create(
        pool, kube, name="GitHub infra", envs=[protected("GITHUB_TOKEN", "value-aaa")]
    )
    two = await create(
        pool, kube, name="GitHub lerobot", envs=[protected("GITHUB_TOKEN", "value-bbb")]
    )
    assert one != two
    assert [e["name"] for e in await store.list_entries(pool)] == ["GitHub infra", "GitHub lerobot"]


@pytest.mark.parametrize(
    "envs",
    [
        [],
        [protected(f"E{i}", "v") for i in range(21)],
        [protected("lower", "v")],
        [protected("A" * 129, "v")],
        [protected("DUP", "v"), readable("DUP", "w")],
        [readable("BIG", "x" * 4097)],
        [readable("NUL", "a\x00b")],
    ],
)
async def test_bad_env_sets_are_refused_before_any_row_or_kube_call(pool, envs):
    kube = FakeKube()
    with pytest.raises(ValueError):
        await create(pool, kube, envs=envs)
    assert kube.calls == []
    assert await rows(pool, "SELECT 1 FROM entries") == []


async def test_twenty_envs_and_a_4096_byte_readable_value_are_allowed(pool):
    kube = FakeKube()
    envs = [readable("BIG", "é" * 2048)] + [protected(f"E{i}", "value-001") for i in range(19)]
    entry_id = await create(pool, kube, envs=envs)
    assert len((await store.get_entry(pool, entry_id))["envs"]) == 20


@pytest.mark.parametrize("name", ["", "   ", "x" * 121])
async def test_bad_names_are_refused(pool, name):
    with pytest.raises(ValueError):
        await create(pool, FakeKube(), name=name)


async def test_name_is_trimmed_free_text(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube, name="  Harbor admin: prod (eu-1)  ")
    assert (await store.get_entry(pool, entry_id))["name"] == "Harbor admin: prod (eu-1)"
    await create(pool, kube, name="x" * 120)


async def test_duplicate_live_name_is_taken_case_insensitively(pool):
    kube = FakeKube()
    await create(pool, kube)
    with pytest.raises(store.NameTaken):
        await create(pool, kube)
    with pytest.raises(store.NameTaken):
        await create(pool, kube, name=" API KEY ")
    assert len(kube.applies) == 1


async def test_recreate_after_delete_gets_a_new_uuid_and_version_one(pool):
    kube = FakeKube()
    first = await create(pool, kube)
    await store.delete_entry(pool, "user", entry_id=first)
    second = await create(pool, kube)
    assert second != first
    assert await store.get_entry(pool, first) is None
    entry = await store.get_entry(pool, second)
    assert entry["current_version"] == 1


async def test_size_is_the_sum_of_protected_utf8_bytes_checked_before_any_row_or_kube_call(
    pool,
):
    kube = FakeKube()
    with pytest.raises(store.SecretTooLarge):
        await create(pool, kube, value="x" * (MAX + 1))
    # 513 two-byte characters: 1026 bytes, over the cap although only 513 characters
    with pytest.raises(store.SecretTooLarge):
        await create(pool, kube, value="é" * 513)
    # two protected envs that fit alone but not together
    half = "x" * (MAX // 2 + 1)
    with pytest.raises(store.SecretTooLarge):
        await create(pool, kube, envs=[protected("A", half), protected("B", half)])
    assert kube.calls == []
    assert await rows(pool, "SELECT 1 FROM entries") == []
    # exactly the cap passes, multi-byte characters included; readable bytes do not count
    await create(pool, kube, envs=[protected("A", "é" * 512), readable("URL", "y" * 4096)])
    assert len(kube.applies) == 1


async def test_value_with_whitespace_is_stored_unchanged(pool):
    kube = FakeKube()
    value = f" {canary}\n"
    await create(pool, kube, value=value)
    assert kube.applies[0].obj["stringData"] == {"API_KEY": value}


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
    assert await store.get_entry(pool, fixed) is None
    assert canary not in caplog.text
    assert "KubeError" in caplog.text
    await create(pool, kube)  # the name is free again


async def test_rotate_makes_version_two_current(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube)
    assert await rotate(pool, kube, entry_id, value="new-value") == 2
    v1, v2 = await versions(pool, entry_id)
    assert (v1["state"], v1["retired_at"] is not None) == ("retired", True)
    assert v2["state"] == "live"
    assert (await store.get_entry(pool, entry_id))["current_version"] == 2
    events = await store.list_events(pool, entry_id)
    assert [e["kind"] for e in events] == ["entry_rotated", "entry_created"]
    assert events[0]["data"] == {"name": NAME, "version": 2, "envs": ["API_KEY"]}


async def test_rotate_takes_exactly_the_protected_set(pool):
    kube = FakeKube()
    envs = [
        protected("USER", "user-001"),
        protected("PASS", "pass-001"),
        readable("URL", "https://x"),
    ]
    entry_id = await create(pool, kube, envs=envs)
    for values, missing, extra in [
        ({"USER": "u2"}, ["PASS"], []),
        ({"USER": "u2", "PASS": "p2", "OTHER": "o"}, [], ["OTHER"]),
        ({"USER": "u2", "PASS": "p2", "URL": "y"}, [], ["URL"]),
        ({}, ["PASS", "USER"], []),
    ]:
        with pytest.raises(store.EnvsMismatch) as exc:
            await rotate(pool, kube, entry_id, values={k: SecretStr(v) for k, v in values.items()})
        assert (exc.value.missing, exc.value.extra) == (missing, extra)
    assert len(kube.applies) == 1
    assert [v["version"] for v in await versions(pool, entry_id)] == [1]
    version = await rotate(
        pool, kube, entry_id, values={"PASS": SecretStr(canary), "USER": SecretStr("user-002")}
    )
    assert version == 2
    assert kube.applies[-1].obj["stringData"] == {"PASS": canary, "USER": "user-002"}


async def test_rotate_unknown_entry(pool):
    with pytest.raises(store.EntryNotFound):
        await rotate(pool, FakeKube(), uuid.uuid4())


async def test_rotate_failure_keeps_version_one_current(pool, caplog):
    caplog.set_level(logging.DEBUG)
    kube = FakeKube()
    entry_id = await create(pool, kube)
    kube.fail("Secret", secret_name(entry_id, 2), KubeError(f"500: body {canary}"), verbs=["patch"])
    with pytest.raises(store.SecretStoreFailed) as exc:
        await rotate(pool, kube, entry_id, value=canary)
    assert canary not in str(exc.value)
    v1, v2 = await versions(pool, entry_id)
    assert v1["state"] == "live"
    assert (v2["state"], v2["deleted_at"] is not None) == ("retired", True)
    assert (await store.get_entry(pool, entry_id))["current_version"] == 1
    assert canary not in caplog.text


async def test_concurrent_rotates_leave_one_live_version(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube)
    entered, release = asyncio.Event(), asyncio.Event()
    kube.apply_gate[secret_name(entry_id, 2)] = (entered, release)
    first = asyncio.create_task(rotate(pool, kube, entry_id, value="one-value"))
    await entered.wait()  # version 2 is `writing`, its Secret not yet applied
    assert await rotate(pool, kube, entry_id, value="two-value") == 3
    release.set()
    assert await first == 2
    vs = await versions(pool, entry_id)
    assert [v["version"] for v in vs] == [1, 2, 3]
    assert [v["version"] for v in vs if v["state"] == "live"] == [3]
    assert (await store.get_entry(pool, entry_id))["current_version"] == 3


async def test_update_normalises_labels_and_records_before_after(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube, labels=["old"])
    await store.update_entry(
        pool, "user", entry_id=entry_id, description="new text", labels=[" A ", "a"]
    )
    entry = await store.get_entry(pool, entry_id)
    assert entry["labels"] == ["a"]
    assert entry["description"] == "new text"
    event = (await store.list_events(pool, entry_id))[0]
    assert event["kind"] == "entry_updated"
    assert event["data"] == {
        "name": NAME,
        "name_before": NAME,
        "description_changed": True,
        "labels_before": ["old"],
        "labels_after": ["a"],
    }


async def test_rename_is_free_and_case_insensitively_unique(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube)
    other = await create(pool, kube, name="Other key")
    await store.update_entry(pool, "user", entry_id=entry_id, name="  Renamed key ")
    entry = await store.get_entry(pool, entry_id)
    assert entry["name"] == "Renamed key"
    assert entry["current_version"] == 1  # a rename is no new version
    event = (await store.list_events(pool, entry_id))[0]
    assert (event["entry_name"], event["data"]["name"], event["data"]["name_before"]) == (
        "Renamed key",
        "Renamed key",
        NAME,
    )
    with pytest.raises(store.NameTaken):
        await store.update_entry(pool, "user", entry_id=other, name="RENAMED KEY")
    assert (await store.get_entry(pool, other))["name"] == "Other key"
    # a case-only rename of itself is fine
    await store.update_entry(pool, "user", entry_id=entry_id, name="renamed KEY")
    # the events of an entry follow its id across renames
    assert len(await store.list_events(pool, entry_id)) == 3


async def test_readable_values_edit_in_place_without_a_version(pool):
    kube = FakeKube()
    envs = [protected("PASS", canary), readable("URL", "https://old"), readable("USER", "u")]
    entry_id = await create(pool, kube, envs=envs)
    before = {e["env"]: e for e in (await store.get_entry(pool, entry_id))["envs"]}
    await store.update_entry(
        pool, "user", entry_id=entry_id, envs={"URL": SecretStr("https://new")}
    )
    entry = await store.get_entry(pool, entry_id)
    after = {e["env"]: e for e in entry["envs"]}
    assert after["URL"]["value"] == "https://new"
    assert after["URL"]["updated_at"] > before["URL"]["updated_at"]
    assert after["USER"]["updated_at"] == before["USER"]["updated_at"]
    assert entry["current_version"] == 1
    assert len(kube.applies) == 1
    (event,) = [e for e in await store.list_events(pool, entry_id) if e["kind"] != "entry_created"]
    assert event["kind"] == "entry_envs_updated"
    assert event["data"] == {"name": NAME, "envs": ["URL"]}
    assert "https" not in str(event)


async def test_editing_a_protected_or_unknown_env_is_refused_whole(pool):
    kube = FakeKube()
    envs = [protected("PASS", "pass-001"), readable("URL", "https://old")]
    entry_id = await create(pool, kube, envs=envs)
    with pytest.raises(store.EnvProtected) as exc:
        await store.update_entry(
            pool,
            "user",
            entry_id=entry_id,
            description="changed",
            envs={"URL": SecretStr("https://new"), "PASS": SecretStr(canary)},
        )
    assert exc.value.envs == ["PASS"]
    with pytest.raises(store.EnvUnknown) as exc2:
        await store.update_entry(pool, "user", entry_id=entry_id, envs={"NOPE": SecretStr("x")})
    assert exc2.value.envs == ["NOPE"]
    with pytest.raises(ValueError):
        await store.update_entry(
            pool, "user", entry_id=entry_id, envs={"URL": SecretStr("x" * 4097)}
        )
    entry = await store.get_entry(pool, entry_id)
    assert entry["description"] == "a key"
    assert [e["value"] for e in entry["envs"]] == [None, "https://old"]
    assert [e["kind"] for e in await store.list_events(pool, entry_id)] == ["entry_created"]


async def test_update_rejects_bad_labels(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube)
    with pytest.raises(ValueError):
        await store.update_entry(pool, "user", entry_id=entry_id, labels=["project:bad_slug"])
    with pytest.raises(ValueError):
        await store.update_entry(
            pool, "user", entry_id=entry_id, labels=[f"l{i}" for i in range(21)]
        )
    with pytest.raises(ValueError):
        await create(pool, kube, name="OTHER", labels=["project:bad_slug"])


async def test_delete_soft_deletes_and_retires_the_live_version(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube)
    await store.delete_entry(pool, "user", entry_id=entry_id)
    assert await store.get_entry(pool, entry_id) is None
    assert await store.list_entries(pool) == []
    (v,) = await versions(pool, entry_id)
    assert v["state"] == "retired"
    assert v["retired_at"] is not None
    assert v["deleted_at"] is None  # the sweeper deletes the Secret once no pin holds it
    with pytest.raises(store.EntryNotFound):
        await store.delete_entry(pool, "user", entry_id=entry_id)
    assert (await store.list_events(pool, entry_id))[0]["kind"] == "entry_deleted"


async def test_list_entries_filters(pool):
    kube = FakeKube()
    await create(pool, kube, name="b key", labels=["alpha"])
    await create(pool, kube, name="A_KEY", labels=["beta", "gamma"])
    await create(pool, kube, name="C_PCT", labels=[])
    assert [e["name"] for e in await store.list_entries(pool)] == ["A_KEY", "b key", "C_PCT"]
    assert [e["name"] for e in await store.list_entries(pool, q="B K")] == ["b key"]
    assert [e["name"] for e in await store.list_entries(pool, q="GAMM")] == ["A_KEY"]
    assert [e["name"] for e in await store.list_entries(pool, q="_")] == ["A_KEY", "C_PCT"]
    assert await store.list_entries(pool, q="%") == []
    assert await store.list_entries(pool, q="\\") == []
    got = await store.list_entries(pool, labels=["alpha", "beta"])
    assert [e["name"] for e in got] == ["A_KEY", "b key"]
    assert [e["name"] for e in await store.list_entries(pool, name="B KEY")] == ["b key"]
    assert await store.list_entries(pool, name="b ke") == []
    assert [e["env"] for e in (await store.list_entries(pool))[0]["envs"]] == ["API_KEY"]


async def test_versions_pins_and_behind_count(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube)
    await rotate(pool, kube, entry_id)
    session = uuid.uuid4()
    other = uuid.uuid4()
    async with pool.connection() as conn:
        await conn.execute(
            "INSERT INTO pins (session_id, env, entry_id, entry_env, version) VALUES"
            " (%s, 'A', %s, 'API_KEY', 1), (%s, 'B', %s, 'API_KEY', 1),"
            " (%s, 'A', %s, 'API_KEY', 2)",
            (session, entry_id, session, entry_id, other, entry_id),
        )
    vs = await store.entry_versions(pool, entry_id)
    assert [(v["version"], v["pins"]) for v in vs] == [(2, 1), (1, 2)]
    assert await store.pinned_sessions_count(pool, entry_id) == 2
    assert await store.behind_count(pool, entry_id) == 2


async def test_list_events_pages_newest_first(pool):
    kube = FakeKube()
    entry_id = await create(pool, kube)
    await rotate(pool, kube, entry_id)
    await rotate(pool, kube, entry_id)
    events = await store.list_events(pool, entry_id, limit=2)
    assert [e["kind"] for e in events] == ["entry_rotated", "entry_rotated"]
    older = await store.list_events(pool, entry_id, before_id=events[-1]["id"])
    assert [e["kind"] for e in older] == ["entry_created"]


async def test_the_protected_value_is_in_no_row(pool):
    kube = FakeKube()
    envs = [protected("API_KEY", canary), readable("URL", "https://visible")]
    entry_id = await create(pool, kube, envs=envs)
    await rotate(pool, kube, entry_id, value=canary)
    await store.update_entry(
        pool, "user", entry_id=entry_id, description="d", envs={"URL": SecretStr("https://v2")}
    )
    await store.delete_entry(pool, "user", entry_id=entry_id)
    found_readable = False
    for table in ("entries", "entry_envs", "versions", "pins", "events"):
        found = await rows(pool, f"SELECT row_to_json(t)::text AS j FROM {table} t")  # noqa: S608
        assert all(canary not in r["j"] for r in found), table
        found_readable |= any("https://v2" in r["j"] for r in found)
        if table == "events":
            assert all("https://" not in r["j"] for r in found)
    assert found_readable  # the readable value is in Postgres, the protected one is not


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
    task = asyncio.create_task(rotate(pool, kube, entry_id, value="one-value"))
    await entered.wait()
    await reap(pool, entry_id, 2)
    release.set()
    with pytest.raises(store.SecretStoreFailed):
        await task
    assert not kube.has("Secret", name)  # our apply landed after the reap: we delete it
    assert (await store.get_entry(pool, entry_id))["current_version"] == 1


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
    assert await store.get_entry(pool, fixed) is None


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
        await rotate(pool, kube, entry_id, value="new-value")
    v1, v2 = await versions(pool, entry_id)
    assert v1["state"] == "live"
    assert (v2["state"], v2["deleted_at"]) == ("retired", None)
    assert kube.has("Secret", secret_name(entry_id, 2))


async def test_rotate_failure_with_clean_delete_still_stamps_the_row(pool):
    kube = FlakyKube()
    entry_id = await create(pool, kube)
    kube.land_then_fail = True
    with pytest.raises(store.SecretStoreFailed):
        await rotate(pool, kube, entry_id, value="new-value")
    _v1, v2 = await versions(pool, entry_id)
    assert v2["deleted_at"] is not None
    assert not kube.has("Secret", secret_name(entry_id, 2))


async def test_rotate_reaped_and_post_delete_failed_leaves_row_for_gc(pool):
    kube = FlakyKube()
    entry_id = await create(pool, kube)
    name = secret_name(entry_id, 2)
    entered, release = asyncio.Event(), asyncio.Event()
    kube.apply_gate[name] = (entered, release)
    task = asyncio.create_task(rotate(pool, kube, entry_id, value="one-value"))
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
    assert await store.get_entry(pool, fixed) is None
