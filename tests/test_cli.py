import os

import pytest

from agents_vault import runtime
from agents_vault.cli import EXIT_CONFIG, build_parser, main

ORCH_TOKEN = "orch-token-value"
SERVICE_TOKEN = "service-token-value"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for key in list(os.environ):
        if key.startswith("VAULT_"):
            monkeypatch.delenv(key)


@pytest.fixture
def valid_env(monkeypatch):
    for key, value in {
        "DATABASE_URL": "postgresql://u:p@db.invalid/vault",
        "ORCHESTRATOR_URL": "http://o.invalid",
        "ORCHESTRATOR_TOKEN": ORCH_TOKEN,
        "NAMESPACE": "agents",
    }.items():
        monkeypatch.setenv(f"VAULT_{key}", value)


@pytest.fixture
def served(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(runtime, "service_main", lambda s, tokens: calls.append(tokens) or 0)
    monkeypatch.setattr(runtime, "web_main", lambda s: calls.append(None) or 0)
    return calls


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.startswith("vault ")


def test_no_command_exits_2(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


@pytest.mark.parametrize("command", ["migrate", "serve-web", "serve-service"])
def test_bad_config_exits_78_naming_variables(command, capsys):
    assert main([command]) == EXIT_CONFIG
    err = capsys.readouterr().err
    for name in ("DATABASE_URL", "ORCHESTRATOR_URL", "ORCHESTRATOR_TOKEN", "NAMESPACE"):
        assert f"VAULT_{name}" in err


def test_serve_web_serves(valid_env, served):
    assert main(["serve-web"]) == 0
    assert served == [None]


def test_serve_service_without_tokens_file(valid_env, served, capsys):
    assert main(["serve-service"]) == EXIT_CONFIG
    assert "VAULT_SERVICE_TOKENS_FILE" in capsys.readouterr().err
    assert served == []


def test_serve_service_unreadable_tokens_file(valid_env, served, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("VAULT_SERVICE_TOKENS_FILE", str(tmp_path / "missing"))
    assert main(["serve-service"]) == EXIT_CONFIG
    assert "VAULT_SERVICE_TOKENS_FILE" in capsys.readouterr().err
    assert served == []


def test_serve_service_empty_tokens_file(valid_env, served, monkeypatch, tmp_path, capsys):
    path = tmp_path / "tokens"
    path.write_text("\n  \n")
    monkeypatch.setenv("VAULT_SERVICE_TOKENS_FILE", str(path))
    assert main(["serve-service"]) == EXIT_CONFIG
    captured = capsys.readouterr()
    assert "VAULT_SERVICE_TOKENS_FILE" in captured.err
    assert served == []


def test_serve_service_token_equal_to_orchestrator_token(
    valid_env, served, monkeypatch, tmp_path, capsys
):
    path = tmp_path / "tokens"
    path.write_text(f"{SERVICE_TOKEN}\n{ORCH_TOKEN}\n")
    monkeypatch.setenv("VAULT_SERVICE_TOKENS_FILE", str(path))
    assert main(["serve-service"]) == EXIT_CONFIG
    captured = capsys.readouterr()
    assert "must differ from VAULT_ORCHESTRATOR_TOKEN" in captured.err
    for token in (ORCH_TOKEN, SERVICE_TOKEN):
        assert token not in captured.err + captured.out
    assert served == []


def test_serve_service_passes_tokens(valid_env, served, monkeypatch, tmp_path):
    path = tmp_path / "tokens"
    path.write_text(f"{SERVICE_TOKEN}\n")
    monkeypatch.setenv("VAULT_SERVICE_TOKENS_FILE", str(path))
    assert main(["serve-service"]) == 0
    assert served == [[SERVICE_TOKEN]]
