import uuid

import httpx
from agents_common.fake_orchestrator import FakeOrchestrator
from agents_common.orchestrator import OrchestratorClient

from agents_vault.attachments import ATTACHMENTS_TTL_SECONDS, AttachmentIndex

TOKEN = "t"
ENTRY = uuid.uuid4()
REF = {
    "env": {
        "GPG_KEY": {"vault": str(ENTRY), "env": "GPG_PRIVATE"},
        "GPG_PASS": {"vault": str(ENTRY).upper(), "env": "GPG_PASSPHRASE"},
        "PLAIN": "x",
    }
}


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def build(fake, clock=None, token=TOKEN):
    client = OrchestratorClient("http://orch", token, transport=httpx.ASGITransport(app=fake.app))
    return AttachmentIndex(client.list_presets, clock=clock or Clock())


def presets_calls(fake):
    return [r for r in fake.requests if r.url.path == "/api/v1/presets"]


async def test_scans_env_for_vault_refs_by_entry_id_per_env():
    fake = FakeOrchestrator(TOKEN)
    ref = fake.add_preset("research", spec=REF, labels=["team-a"])
    fake.add_preset(
        "plain",
        spec={
            "env": {
                "A": "b",
                "B": {"other": "x"},
                "C": {"vault": 3, "env": "X"},
                "D": {"vault": "NOT_A_UUID", "env": "X"},
                "E": {"vault": str(uuid.uuid4())},
                "F": {"vault": str(uuid.uuid4()), "env": 7},
            }
        },
    )
    fake.add_preset("nospec")
    got = await build(fake).by_entry()
    assert list(got) == [str(ENTRY)]
    atts = got[str(ENTRY)]
    assert [(a.preset_id, a.preset_name, a.env, a.entry_env, a.preset_labels) for a in atts] == [
        (str(ref.id), "research", "GPG_KEY", "GPG_PRIVATE", ["team-a"]),
        (str(ref.id), "research", "GPG_PASS", "GPG_PASSPHRASE", ["team-a"]),
    ]


async def test_list_shaped_env_refs():
    fake = FakeOrchestrator(TOKEN)
    fake.add_preset(
        "listy", spec={"env": [{"name": "K", "value": {"vault": str(ENTRY), "env": "KEY"}}]}
    )
    got = await build(fake).by_entry()
    [att] = got[str(ENTRY)]
    assert (att.env, att.entry_env) == ("K", "KEY")


async def test_no_refs_is_empty_not_none():
    fake = FakeOrchestrator(TOKEN)
    fake.add_preset("plain", spec={"env": {"A": "b"}})
    assert await build(fake).by_entry() == {}


async def test_cached_for_the_ttl_then_refetched():
    fake, clock = FakeOrchestrator(TOKEN), Clock()
    index = build(fake, clock)
    await index.by_entry()
    clock.now += ATTACHMENTS_TTL_SECONDS - 1
    await index.by_entry()
    assert len(presets_calls(fake)) == 1
    clock.now += 2
    await index.by_entry()
    assert len(presets_calls(fake)) == 2


async def test_fresh_bypasses_the_cache():
    fake = FakeOrchestrator(TOKEN)
    index = build(fake)
    await index.by_entry()
    await index.by_entry(fresh=True)
    assert len(presets_calls(fake)) == 2


async def test_server_error_is_none_and_not_cached():
    fake = FakeOrchestrator(TOKEN)
    index = build(fake)
    fake.fail_next("list_presets", 500)
    assert await index.by_entry() is None
    assert await index.by_entry() == {}


async def test_unauthorized_is_none():
    fake = FakeOrchestrator(TOKEN)
    assert await build(fake, token="wrong").by_entry() is None


async def test_unreachable_is_none():
    def refuse(request):
        raise httpx.ConnectError("down")

    client = OrchestratorClient("http://orch", TOKEN, transport=httpx.MockTransport(refuse))
    assert await AttachmentIndex(client.list_presets).by_entry() is None


async def test_a_200_with_a_bad_body_is_none_and_not_cached():
    bodies = iter([httpx.Response(200, text="<html>oops</html>"), httpx.Response(200, json={})])

    client = OrchestratorClient(
        "http://orch", TOKEN, transport=httpx.MockTransport(lambda request: next(bodies))
    )
    index = AttachmentIndex(client.list_presets)
    assert await index.by_entry() is None  # not JSON
    assert await index.by_entry() is None  # JSON of the wrong shape (an object, not a list)
