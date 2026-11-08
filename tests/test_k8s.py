import secrets
from uuid import UUID

import pytest
from fakes.fake_kube import FakeKube
from pydantic import SecretStr

from agents_vault.k8s import (
    ENTRY_LABEL,
    MANAGED_BY,
    MANAGED_BY_LABEL,
    KubeError,
    secret_name,
    write_secret,
)

canary = secrets.token_hex(16)
ENTRY = UUID("12345678-1234-5678-1234-567812345678")


def test_secret_name():
    assert secret_name(ENTRY, 3) == "vault-12345678-1234-5678-1234-567812345678-v3"


async def test_write_secret_deletes_then_applies_one_immutable_secret():
    kube = FakeKube()
    name = secret_name(ENTRY, 1)
    await write_secret(kube, "agents", name, ENTRY, SecretStr(canary))
    assert [c.verb for c in kube.calls] == ["delete", "patch"]
    (applied,) = kube.applies
    assert applied.field_manager == "agents-vault"
    obj = applied.obj
    assert obj["type"] == "Opaque"
    assert obj["immutable"] is True
    assert obj["stringData"] == {"value": canary}
    assert obj["metadata"]["namespace"] == "agents"
    assert obj["metadata"]["name"] == name
    assert obj["metadata"]["labels"] == {MANAGED_BY_LABEL: MANAGED_BY, ENTRY_LABEL: str(ENTRY)}
    assert "stringData" not in kube.get("Secret", name)
    assert kube.forbidden == []


async def test_write_secret_keeps_the_value_byte_for_byte():
    kube = FakeKube()
    value = f"  {canary}\n"
    await write_secret(kube, "agents", secret_name(ENTRY, 1), ENTRY, SecretStr(value))
    assert kube.applies[0].obj["stringData"] == {"value": value}


async def test_write_secret_never_reads():
    kube = FakeKube()
    await write_secret(kube, "agents", secret_name(ENTRY, 1), ENTRY, SecretStr(canary))
    assert {c.verb for c in kube.calls} <= {"delete", "patch"}
    assert kube.forbidden == []


async def test_applying_over_an_existing_immutable_secret_fails_without_the_delete():
    kube = FakeKube()
    name = secret_name(ENTRY, 1)
    await write_secret(kube, "agents", name, ENTRY, SecretStr(canary))
    with pytest.raises(KubeError, match="immutable"):
        await kube.apply(kube.applies[0].obj)
    # write_secret itself deletes the leftover first, so a rewrite succeeds
    await write_secret(kube, "agents", name, ENTRY, SecretStr("other"))
    assert len(kube.applies) == 2


async def test_fake_refuses_secret_reads_and_records_them():
    from agents_vault.k8s import Forbidden

    kube = FakeKube()
    with pytest.raises(Forbidden):
        await kube.get_object("Secret", "agents", "x")
    with pytest.raises(Forbidden):
        await kube.list_objects("Secret", "agents")
    assert [c.verb for c in kube.forbidden] == ["get", "list"]
