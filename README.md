# agents-vault

Part of the workdir project (python).

## What this is

A write-only secret vault for the agents system. Users create and rotate named secrets through the web UI; the value goes straight into an immutable Kubernetes Secret (one per version) and is never stored in Postgres, logged or returned by any route. The orchestrator pins versions to sessions through the service listener. The service has its own Postgres database (entries, versions, pins, events).

## Development

Run from this directory with mise:

- `mise run test` - tests (the database tests start Postgres 18 through testcontainers and need Docker)
- `mise run lint` - ruff check and format check
- `mise run fmt` - ruff format

## Commands

The `vault` entry point (`uv run vault <command>`):

- `vault migrate` - apply the schema migrations to the service's own database and exit.
- `vault serve-web` - serve the user-facing api on `VAULT_HTTP_PORT` (source allowlist).
- `vault serve-service` - serve the orchestrator-facing api on `VAULT_SERVICE_PORT` (bearer tokens from `VAULT_SERVICE_TOKENS_FILE`; exits 78 when the file is unset, unreadable or empty, or holds the orchestrator token).
- `vault sweeper` - run the singleton sweeper loop: release pins of sessions the orchestrator no longer lists, delete unpinned old versions, reap stale writes.

## Configuration

Every process reads one validated `VAULT_*` environment. A bad or missing variable makes the process exit with code 78 and one line per variable. Secrets are never logged.

| Variable | Default | Meaning |
|---|---|---|
| `VAULT_DATABASE_URL` | required | Postgres DSN of the service's own database |
| `VAULT_ORCHESTRATOR_URL` | required | orchestrator service port (presets, sessions) |
| `VAULT_ORCHESTRATOR_TOKEN` | - | orchestrator service token; exactly one of this and the `_FILE` variable is required |
| `VAULT_ORCHESTRATOR_TOKEN_FILE` | - | path of a file holding the token |
| `VAULT_NAMESPACE` | required | namespace the Secrets are written to (DNS-1123 label, at most 63) |
| `VAULT_SERVICE_TOKENS_FILE` | empty | file with one bearer token per line for the service listener; each must differ from the orchestrator token; `serve-service` needs it |
| `VAULT_ALLOWED_CIDRS` | `127.0.0.1/32` | comma-separated CIDRs allowed on the web listener |
| `VAULT_HTTP_HOST` | `0.0.0.0` | bind address of both listeners |
| `VAULT_HTTP_PORT` | `8000` | web listener port |
| `VAULT_SERVICE_PORT` | `8002` | service listener port (1..65535, different from the web port) |
| `VAULT_SWEEPER_INTERVAL_SECONDS` | `60` | sweeper pass interval (5..3600) |
| `VAULT_PIN_GRACE_SECONDS` | `600` | grace before an unregistered pin is treated as lost (60..86400) |
| `VAULT_MAX_VALUE_BYTES` | `1048576` | largest accepted secret value in UTF-8 bytes (1..1048576) |
| `VAULT_LOG_LEVEL` | `INFO` | log level |
| `VAULT_SHUTDOWN_GRACE_SECONDS` | `20` | graceful shutdown wait |

`GET /healthz` and `GET /readyz` (`503 not_ready` when the database is unreachable) are served on both listeners under no prefix and are exempt from both gates. The routes under `/vault/v1` are documented below.

## RBAC

The vault's Kubernetes Role on `secrets` grants exactly the verbs `create`, `patch` and `delete`. It never grants `get`, `list` or `watch`: the code applies and deletes Secrets by deterministic name (`vault-<entry uuid>-v<n>`) and never reads one back.

## Errors

Every error is `{"error": {"code": "...", "message": "...", ...extra}}`. A validation error is `422 invalid_request` with a message built from the field location and the rule, never from the input.

## Web API

Served by `vault serve-web` for users, behind the source allowlist (`403 forbidden` outside it). No route returns a secret value; `value` appears only in request bodies. Documented in `openapi.json`.

### `GET /vault/v1/entries`

Query: `q` (substring of name or description), `label` (repeatable). Returns the list of entry views. Statuses: 200, 403, 422.

### `POST /vault/v1/entries`

Body `{name, description, labels, value}`. Name `^[A-Z_][A-Z0-9_]{0,127}$`, description 1..500 characters, value at most `VAULT_MAX_VALUE_BYTES` bytes. Creates the entry and version 1. Statuses: 201, 403, 409 `vault_name_taken`, 413 `secret_too_large`, 422, 502 `secret_store_failed`.

### `GET /vault/v1/entries/{name}`

Entry detail: view, versions, attachments and mismatched attachments. Statuses: 200, 403, 404.

### `PATCH /vault/v1/entries/{name}`

Body `{description?, labels?}`, at least one. Statuses: 200, 403, 404, 422.

### `PUT /vault/v1/entries/{name}/value`

Body `{value}`. Writes a new immutable version and makes it current. Statuses: 200, 403, 404, 413, 422, 502.

### `DELETE /vault/v1/entries/{name}`

Refused while a preset references the entry. Statuses: 204, 403, 404, 409 `vault_entry_attached` (with `attachments`), 503 `orchestrator_unavailable`.

### `GET /vault/v1/entries/{name}/pins`

Sessions pinning a version of the entry. Statuses: 200, 403, 404.

### `GET /vault/v1/events`

Query: `entry`, `before_id`, `limit` (1..200, default 50). Newest first. Statuses: 200, 403, 422.

## Service API

Served by `vault serve-service` for the orchestrator, behind the bearer gate (`401 unauthorized` without a known token). It cannot create, rotate, edit or delete an entry. Documented in `openapi-service.json`.

### `GET /vault/v1/entries`

Query: `q`. Entry summaries with attachments. Statuses: 200, 401.

### `POST /vault/v1/entries/resolve`

Body `{preset_labels, refs}` where `refs` maps env name to entry name (at most 50). Returns `{resolved, unknown, mismatched}`. Statuses: 200, 401, 422.

### `POST /vault/v1/pins`

Body `{session_id, preset_labels, refs}`. Pins the current version of each entry to the session and returns the Secret name per env; a repeat call for the same session returns the first answer. Statuses: 200, 401, 422 (`vault_entry_unknown` with `names`, `vault_label_mismatch` with `envs`).

### `DELETE /vault/v1/pins/{session_id}`

Releases every pin of the session. Statuses: 204, 401, 422.

## OpenAPI documents

`openapi.json` is the web contract and `openapi-service.json` the orchestrator's. After any route or schema change regenerate both; a test fails on drift:

    uv run python -m agents_vault.api.openapi > openapi.json
    uv run python -m agents_vault.api.openapi --service > openapi-service.json
