# agents-vault

Part of the workdir project (python).

## What this is

A write-only secret vault for the agents system. An entry is a free-text name (unique case-insensitively among live entries), a description, labels and an ordered set of 1..20 envs fixed at create. Each env is protected or readable:

- a protected env's value goes straight into an immutable Kubernetes Secret (one per version, one data key per protected env) and is never stored in Postgres (no value, hash or length), logged or returned by any route;
- a readable env's value (at most 4096 bytes) is stored in Postgres, shown in the web and service views, edited in place without a new version, and never put into an event.

Label rule: only labels with the reserved prefix `project:` restrict where an entry may be attached. All other labels are descriptive tags: stored, normalised, searchable and shown, but never restricting. An entry without a `project:` label matches every preset; one with `project:` labels matches a preset only when the preset's effective labels (its own plus `project:<slug>`) share at least one of them (`agents_common.labels.labels_match`, agents-common v0.13.0).

The orchestrator pins versions to sessions through the service listener: a protected env comes back as a Secret ref, a readable env as its value. The service has its own Postgres database (entries, entry envs, versions, pins, events).

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
| `VAULT_MAX_VALUE_BYTES` | `1048576` | largest accepted sum of an entry's protected values in UTF-8 bytes (1..1048576) |
| `VAULT_LOG_LEVEL` | `INFO` | log level |
| `VAULT_SHUTDOWN_GRACE_SECONDS` | `20` | graceful shutdown wait |

`GET /healthz` and `GET /readyz` (`503 not_ready` when the database is unreachable) are served on both listeners under no prefix and are exempt from both gates. The routes under `/vault/v1` are documented below.

## RBAC

The vault's Kubernetes Role on `secrets` grants exactly the verbs `create`, `patch` and `delete`. It never grants `get`, `list` or `watch`: the code applies and deletes Secrets by deterministic name (`vault-<entry uuid>-v<n>`) and never reads one back.

## Trust boundary

The vault protects a value from the vault's own API, database, events and logs, and from the agents that only see entry names. It does not protect a value from anything that can read Secrets in the agents namespace through the Kubernetes API or the node: sessions with cluster-admin access, privileged or docker-in-docker sessions, node root and cluster operators are outside the model, because the entries' Secrets carry the `app.kubernetes.io/managed-by=agents-vault` label and deterministic names. After such access, rotate the affected entries and restart the sessions that pin them. Prefer entries scoped to one `project:` label for presets that run with these privileges.

## Errors

Every error is `{"error": {"code": "...", "message": "...", ...extra}}`. A validation error is `422 invalid_request` with a message built from the field location and the rule, never from the input; a caller-chosen key (an env name in `values`, `envs` or `refs`) is cut from the location.

## Web API

Served by `vault serve-web` for users, behind the source allowlist (`403 forbidden` outside it). Entries are addressed by id (`{entry_id}`, a uuid; anything else is 422). No route returns a protected value; readable env values are part of the views. Documented in `openapi.json`.

An entry view is `{id, name, description, labels, envs, version, created_at, updated_at, attachments_count, pinned_sessions_count, behind_count}`, each env `{env, protected, value, updated_at}` with `value` null for a protected env.

### `GET /vault/v1/entries`

Query: `q` (substring of name, description or a label), `label` (repeatable). Returns the list of entry views. Statuses: 200, 403, 422.

### `POST /vault/v1/entries`

Body `{name, description, labels, envs: [{env, protected, value}]}`. Name is free text, trimmed, 1..120 characters; no NUL character in the name, description, labels or a readable value; description 1..500 characters; 1..20 envs, each name `^[A-Z_][A-Z0-9_]{0,127}$` and unique within the entry (names may repeat across entries); a readable value is at most 4096 bytes; the protected values together are at most `VAULT_MAX_VALUE_BYTES` bytes. Creates the entry and version 1 (its Secret holds the protected envs, possibly none). Statuses: 201, 403, 409 `vault_name_taken` (case-insensitive), 413 `secret_too_large`, 422, 502 `secret_store_failed`.

### `GET /vault/v1/entries/{entry_id}`

Entry detail: view, versions, attachments (one per preset env referencing an env of the entry, with `entry_env`) and mismatched attachments. Statuses: 200, 403, 404, 422.

### `PATCH /vault/v1/entries/{entry_id}`

Body `{name?, description?, labels?, envs?: {ENV: value}}`, at least one. A labels change that adds, changes or drops a `project:` label of an entry that presets reference is refused with `409 vault_entry_attached` (with `attachments`) unless the query has `force=true`; `503 orchestrator_unavailable` when the attachments cannot be checked. A rename is free (refs carry the id) but stays unique case-insensitively. `envs` sets readable values in place: no new version, `updated_at` per env. Statuses: 200, 403, 404, 409 `vault_name_taken` or `vault_entry_attached`, 503, 422 (`vault_env_protected` or `vault_env_unknown` with `envs`, `invalid_request`).

### `PUT /vault/v1/entries/{entry_id}/value`

Body `{values: {ENV: value}}` naming exactly the protected envs of the entry (`422 vault_envs_mismatch` with `missing` and `extra` otherwise; an entry without a protected env has nothing to rotate, `422 vault_nothing_to_rotate`). Writes a new immutable version holding the whole protected set and makes it current. Statuses: 200, 403, 404, 413, 422, 502.

### `DELETE /vault/v1/entries/{entry_id}`

Refused while a preset references the entry. Statuses: 204, 403, 404, 409 `vault_entry_attached` (with `attachments`), 422, 503 `orchestrator_unavailable`.

### `GET /vault/v1/entries/{entry_id}/pins`

Sessions pinning a version of the entry, with the preset env and the entry env. Statuses: 200, 403, 404, 422.

### `GET /vault/v1/events`

Query: `entry` (entry id), `before_id`, `limit` (1..200, default 50). Newest first. An event's `actor` is `user:<email>` (the SSO identity from the `X-Forwarded-Email`, else `X-Forwarded-User`, header of the loopback-only sidecar; the web listener serves allowlisted peers only), `user` without one, `orchestrator` or `sweeper`. Events carry entry and env names, versions and ids, never a value. Statuses: 200, 403, 422.

## Service API

Served by `vault serve-service` for the orchestrator, behind the bearer gate (`401 unauthorized` without a known token). It cannot create, rotate, edit or delete an entry. A preset references one env of an entry as `{"vault": "<entry id>", "env": "ENV"}`; the refs below are `{PRESET_ENV: {entry: <entry id>, env: ENV}}` (at most 50). Documented in `openapi-service.json`.

### `GET /vault/v1/entries`

Query: `q`, `name` (exact, case-insensitive: binds a name to its id). Entry summaries `{id, name, description, labels, envs, version, updated_at, attachments}` with readable values. Statuses: 200, 401.

### `POST /vault/v1/entries/resolve`

Body `{preset_labels, refs}`; `preset_labels` carries at most one `project:` label (422 `invalid_request` otherwise). Returns `{resolved, unknown, bad_env, mismatched}`: `resolved` per preset env, and the preset envs whose entry is unknown, whose entry has no such env, or whose entry labels do not match. Statuses: 200, 401, 422.

### `POST /vault/v1/pins`

Body `{session_id, preset_labels, refs}`. Pins the current version of each entry to the session and returns `{pins: {PRESET_ENV: {secret, key, version}}, values: {PRESET_ENV: value}}`: a Secret name and data key per protected env, the value per readable env. A repeat call for the same session returns the first pins (readable values as they are now). Statuses: 200, 401, 422 (`vault_entry_unknown` with `envs` and `entries`, then `vault_env_unknown` with `envs`, then `vault_label_mismatch` with `envs`).

### `DELETE /vault/v1/pins/{session_id}`

Releases every pin of the session. Statuses: 204, 401, 422.

## OpenAPI documents

`openapi.json` is the web contract and `openapi-service.json` the orchestrator's. After any route or schema change regenerate both; a test fails on drift:

    uv run python -m agents_vault.api.openapi > openapi.json
    uv run python -m agents_vault.api.openapi --service > openapi-service.json
