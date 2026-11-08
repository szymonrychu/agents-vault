"""The committed OpenAPI documents match the apps (spec 4, 7.3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.routing import APIRoute

from agents_vault.api.app import PREFIX, create_service_app, create_web_app
from agents_vault.api.openapi import document, export
from agents_vault.settings import Settings

ROOT = Path(__file__).resolve().parent.parent
SETTINGS = Settings(
    database_url="postgresql://unused/db",
    orchestrator_url="http://orchestrator.invalid",
    orchestrator_token="t",
    namespace="agents",
)
REQUEST_ONLY = {"EnvIn", "EntryIn", "EntryPatch", "ValuesIn"}
# The response schemas carrying values: a readable env's value (null for a protected env) in
# the views, and the readable values a pin call answers (protected envs come back as refs).
READABLE_VIEW = "EnvView"
READABLE_PINS = "PinsOut"


def _walk(router, prefix: str = ""):
    for route in router.routes:
        if isinstance(route, APIRoute):
            yield prefix + route.path, route.methods
        elif hasattr(route, "original_router"):
            yield from _walk(route.original_router, prefix + route.include_context.prefix)


def app_routes(app) -> set[tuple[str, str]]:
    return {
        (m.lower(), p)
        for p, methods in _walk(app)
        if p.startswith(PREFIX)
        for m in methods - {"HEAD"}
    }


def doc_routes(doc: dict) -> set[tuple[str, str]]:
    return {(m, p) for p, methods in doc["paths"].items() for m in methods}


@pytest.mark.parametrize(
    ("filename", "service", "flag"),
    [("openapi.json", False, ""), ("openapi-service.json", True, " --service")],
)
def test_committed_document_is_current(filename, service, flag):
    committed = (ROOT / filename).read_text(encoding="utf-8")
    assert committed == export(service), (
        f"{filename} is stale; regenerate: "
        f"uv run python -m agents_vault.api.openapi{flag} > {filename}"
    )


def test_web_document_covers_the_web_routes():
    app = create_web_app(SETTINGS, None)  # type: ignore[arg-type]
    assert doc_routes(document()) == app_routes(app)


def test_service_document_covers_the_service_routes():
    app = create_service_app(SETTINGS, None, ["t"])  # type: ignore[arg-type]
    assert doc_routes(document(service=True)) == app_routes(app)


def test_service_document_has_no_entry_writes_except_resolve():
    writes = {"post", "patch", "put", "delete"}
    offenders = {
        (m, p)
        for p, methods in document(service=True)["paths"].items()
        if p.startswith(f"{PREFIX}/entries")
        for m in methods
        if m in writes and (m, p) != ("post", f"{PREFIX}/entries/resolve")
    }
    assert offenders == set()


@pytest.mark.parametrize("service", [False, True])
def test_no_response_schema_has_a_value_property(service):
    schemas = document(service)["components"]["schemas"]
    for name, schema in schemas.items():
        if name in REQUEST_ONLY or name in (READABLE_VIEW, READABLE_PINS):
            continue
        for banned in ("value", "values"):
            assert banned not in schema.get("properties", {}), name
    assert set(schemas[READABLE_VIEW]["properties"]) == {"env", "protected", "value", "updated_at"}
    if service:
        assert set(schemas[READABLE_PINS]["properties"]) == {"pins", "values"}
        assert set(schemas["PinOut"]["properties"]) == {"secret", "key", "version"}


def test_request_values_are_write_only_and_never_in_a_response():
    doc = document()
    schemas = doc["components"]["schemas"]
    secret = {"format": "password", "type": "string", "writeOnly": True}
    assert schemas["EnvIn"]["properties"]["value"] == {**secret, "title": "Value"}
    assert schemas["ValuesIn"]["properties"]["values"]["additionalProperties"] == secret
    patch_envs = schemas["EntryPatch"]["properties"]["envs"]["anyOf"][0]
    assert patch_envs["additionalProperties"] == secret
    for path, methods in doc["paths"].items():
        for method, op in methods.items():
            for status, response in op["responses"].items():
                text = json.dumps(response)
                for name in REQUEST_ONLY:
                    assert f"/{name}" not in text, (method, path, status)
