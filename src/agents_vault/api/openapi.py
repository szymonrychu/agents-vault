"""Deterministic OpenAPI export per listener.

`python -m agents_vault.api.openapi > openapi.json` documents the web listener (users);
`--service` documents the service listener (the orchestrator). FastAPI documents a validation
error as its own `HTTPValidationError`; this service answers every error with
`{"error": {"code", "message"}}` (see `errors.py`), so the export replaces the generated error
responses with that shape and the statuses each route really returns. The probes (`/healthz`,
`/readyz`) are not part of the documents.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from agents_vault.api.app import PREFIX, create_service_app, create_web_app
from agents_vault.settings import Settings

ERROR_REF = {"$ref": "#/components/schemas/ErrorResponse"}

ERROR_SCHEMAS: dict[str, Any] = {
    "ErrorBody": {
        "type": "object",
        "title": "ErrorBody",
        "required": ["code", "message"],
        "additionalProperties": True,
        "properties": {
            "code": {"type": "string", "title": "Code"},
            "message": {"type": "string", "title": "Message"},
        },
    },
    "ErrorResponse": {
        "type": "object",
        "title": "ErrorResponse",
        "required": ["error"],
        "properties": {"error": {"$ref": "#/components/schemas/ErrorBody"}},
    },
}

WEB_ERRORS = {
    403: "source address is not allowed on the web listener (forbidden)",
    404: "no such entry (not_found)",
    409: "name taken (vault_name_taken) or entry still attached to presets (vault_entry_attached)",
    413: "value larger than VAULT_MAX_VALUE_BYTES (secret_too_large)",
    422: "invalid request (invalid_request)",
    502: "the Kubernetes Secret could not be written (secret_store_failed)",
    503: "attachments cannot be checked, nothing was deleted (orchestrator_unavailable)",
}
SERVICE_ERRORS = {
    401: "no or an unknown bearer service token (unauthorized)",
    422: "invalid request (invalid_request, vault_entry_unknown, vault_label_mismatch)",
}

WEB_GUARD = (403,)
SERVICE_GUARD = (401,)

ROUTE_ERRORS: dict[bool, dict[tuple[str, str], tuple[int, ...]]] = {
    False: {
        ("get", "/entries"): (422,),
        ("post", "/entries"): (409, 413, 422, 502),
        ("get", "/entries/{name}"): (404,),
        ("patch", "/entries/{name}"): (404, 422),
        ("put", "/entries/{name}/value"): (404, 413, 422, 502),
        ("delete", "/entries/{name}"): (404, 409, 503),
        ("get", "/entries/{name}/pins"): (404,),
        ("get", "/events"): (422,),
    },
    True: {
        ("get", "/entries"): (),
        ("post", "/entries/resolve"): (422,),
        ("post", "/pins"): (422,),
        ("delete", "/pins/{session_id}"): (422,),
    },
}


def document(service: bool = False) -> dict[str, Any]:
    """The OpenAPI document of the web listener, or of the service listener with `service`."""
    settings = Settings(
        database_url="postgresql://openapi/export",
        orchestrator_url="http://orchestrator.invalid",
        orchestrator_token="openapi-export",
        namespace="agents",
    )
    if service:
        app = create_service_app(settings, None, ["openapi-export"])  # type: ignore[arg-type]
        guard, errors = SERVICE_GUARD, SERVICE_ERRORS
    else:
        app = create_web_app(settings, None)  # type: ignore[arg-type]
        guard, errors = WEB_GUARD, WEB_ERRORS
    route_errors = ROUTE_ERRORS[service]
    doc = app.openapi()
    doc["paths"] = {p: m for p, m in doc["paths"].items() if p.startswith(PREFIX)}
    for path, methods in doc["paths"].items():
        for method, operation in methods.items():
            responses = operation["responses"]
            for status in [s for s in responses if not s.startswith("2")]:
                del responses[status]
            statuses = (*guard, *route_errors[(method, path.removeprefix(PREFIX))])
            for status in sorted(statuses):
                responses[str(status)] = {
                    "description": errors[status],
                    "content": {"application/json": {"schema": ERROR_REF}},
                }
    schemas = doc["components"]["schemas"]
    for name in ("HTTPValidationError", "ValidationError"):
        schemas.pop(name, None)
    schemas.update(ERROR_SCHEMAS)
    return doc


def export(service: bool = False) -> str:
    """The listener's OpenAPI document as JSON with sorted keys and a trailing newline."""
    return json.dumps(document(service), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    print(export(service="--service" in sys.argv[1:]), end="")
