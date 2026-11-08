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

`GET /healthz` and `GET /readyz` (`503 not_ready` when the database is unreachable) are served on both listeners under no prefix and are exempt from both gates. The routes under `/vault/v1` are documented here as they are added.
