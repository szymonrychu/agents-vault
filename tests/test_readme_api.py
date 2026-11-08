"""README API coverage: every route of both apps is documented, none invented."""

from __future__ import annotations

import re
from pathlib import Path

from test_openapi_current import app_routes

from agents_vault.api.app import PREFIX, create_service_app, create_web_app
from agents_vault.settings import Settings

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
SETTINGS = Settings(
    database_url="postgresql://unused/db",
    orchestrator_url="http://orchestrator.invalid",
    orchestrator_token="t",
    namespace="agents",
)


def section(title: str) -> str:
    match = re.search(rf"^## {re.escape(title)}\s*$", README, re.MULTILINE)
    assert match, f"README has no '## {title}' section"
    rest = README[match.end() :]
    nxt = re.search(r"^## ", rest, re.MULTILINE)
    return rest[: nxt.start()] if nxt else rest


def readme_routes(title: str) -> set[tuple[str, str]]:
    found = re.findall(
        rf"^### `(GET|POST|PATCH|PUT|DELETE) ({PREFIX}\S*)`\s*$", section(title), re.MULTILINE
    )
    return {(m.lower(), p) for m, p in found}


def test_web_api_section_lists_every_web_route():
    expected = app_routes(create_web_app(SETTINGS, None))  # type: ignore[arg-type]
    documented = readme_routes("Web API")
    assert expected - documented == set(), "undocumented web routes"
    assert documented - expected == set(), "README documents web routes the app lacks"


def test_service_api_section_lists_every_service_route():
    expected = app_routes(create_service_app(SETTINGS, None, ["t"]))  # type: ignore[arg-type]
    documented = readme_routes("Service API")
    assert expected - documented == set(), "undocumented service routes"
    assert documented - expected == set(), "README documents service routes the app lacks"


def test_readme_documents_commands_and_settings():
    commands = section("Commands")
    for name in ("migrate", "serve-web", "serve-service", "sweeper"):
        assert f"`vault {name}`" in commands
    config = section("Configuration")
    for name in Settings.model_fields:
        assert f"`VAULT_{name.upper()}`" in config, name


def test_readme_states_the_rbac_and_regenerate_commands():
    text = README
    assert "`create`, `patch` and `delete`" in text
    assert "uv run python -m agents_vault.api.openapi > openapi.json" in text
    assert "uv run python -m agents_vault.api.openapi --service > openapi-service.json" in text
