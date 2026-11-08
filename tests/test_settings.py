import os

import pytest
from agents_common.settings import SettingsError

from agents_vault.settings import Settings, load_settings

REQUIRED = {
    "VAULT_DATABASE_URL": "postgresql://u:p@db/vault",
    "VAULT_ORCHESTRATOR_URL": "http://agents-orchestrator-services:8002",
    "VAULT_ORCHESTRATOR_TOKEN": "orch-secret",
    "VAULT_NAMESPACE": "agents",
}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in list(os.environ):
        if key.startswith("VAULT_"):
            monkeypatch.delenv(key)


def set_env(monkeypatch, **extra):
    for key, value in {**REQUIRED, **extra}.items():
        monkeypatch.setenv(key, value)


def problems(monkeypatch, **extra) -> dict[str, str]:
    set_env(monkeypatch, **extra)
    with pytest.raises(SettingsError) as exc:
        load_settings()
    return exc.value.problems


def test_defaults(monkeypatch):
    set_env(monkeypatch)
    s = load_settings()
    assert isinstance(s, Settings)
    assert s.http_port == 8000
    assert s.service_port == 8002
    assert s.allowed_cidrs == ["127.0.0.1/32"]
    assert s.service_tokens_file == ""
    assert s.namespace == "agents"
    assert s.sweeper_interval_seconds == 60
    assert s.pin_grace_seconds == 600
    assert s.max_value_bytes == 1048576


@pytest.mark.parametrize(
    "missing",
    ["VAULT_DATABASE_URL", "VAULT_ORCHESTRATOR_URL", "VAULT_ORCHESTRATOR_TOKEN", "VAULT_NAMESPACE"],
)
def test_required_variable_is_named(monkeypatch, missing):
    set_env(monkeypatch)
    monkeypatch.delenv(missing)
    with pytest.raises(SettingsError) as exc:
        load_settings()
    assert missing in exc.value.problems


def test_allowed_cidrs_csv(monkeypatch):
    set_env(monkeypatch, VAULT_ALLOWED_CIDRS="127.0.0.1/32, 10.0.0.0/8")
    assert load_settings().allowed_cidrs == ["127.0.0.1/32", "10.0.0.0/8"]


def test_bad_cidr(monkeypatch):
    found = problems(monkeypatch, VAULT_ALLOWED_CIDRS="127.0.0.1/32,nope")
    assert found == {"VAULT_ALLOWED_CIDRS": "not a CIDR: 'nope'"}


def test_equal_ports(monkeypatch):
    found = problems(monkeypatch, VAULT_HTTP_PORT="9000", VAULT_SERVICE_PORT="9000")
    assert found == {"VAULT_SERVICE_PORT": "must differ from VAULT_HTTP_PORT"}


@pytest.mark.parametrize("value", ["0", "65536"])
def test_service_port_range(monkeypatch, value):
    assert set(problems(monkeypatch, VAULT_SERVICE_PORT=value)) == {"VAULT_SERVICE_PORT"}


@pytest.mark.parametrize(
    ("var", "ok", "bad"),
    [
        ("VAULT_SWEEPER_INTERVAL_SECONDS", ["5", "3600"], ["4.9", "3601"]),
        ("VAULT_PIN_GRACE_SECONDS", ["60", "86400"], ["59", "86401"]),
        ("VAULT_MAX_VALUE_BYTES", ["1", "1048576"], ["0", "1048577"]),
    ],
)
def test_bounds(monkeypatch, var, ok, bad):
    for value in ok:
        set_env(monkeypatch, **{var: value})
        load_settings()
    for value in bad:
        assert set(problems(monkeypatch, **{var: value})) == {var}


@pytest.mark.parametrize("value", ["Agents", "-a", "a-", "a_b", "a" * 64, "a.b"])
def test_namespace_must_be_dns_label(monkeypatch, value):
    assert set(problems(monkeypatch, VAULT_NAMESPACE=value)) == {"VAULT_NAMESPACE"}


def test_namespace_longest_label(monkeypatch):
    set_env(monkeypatch, VAULT_NAMESPACE="a" * 63)
    assert load_settings().namespace == "a" * 63


def test_repr_hides_secrets(monkeypatch):
    set_env(monkeypatch)
    text = repr(load_settings())
    assert "orch-secret" not in text
    assert "postgresql://u:p" not in text
