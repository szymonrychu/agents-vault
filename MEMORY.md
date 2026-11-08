# agents-vault memory

Lessons that outlive a session. Newest first.

## 2026-11-08 - scaffold decisions

- Template: the process split (one process per listener, one Deployment per component) is agents-taskboard's. The service listener's token file (`VAULT_SERVICE_TOKENS_FILE`, one raw token per line, loaded with `agents_common.service_gate.load_tokens`) is agents-history's pattern, not taskboard's single env token: a file mounted from a Secret lets the hash/rotation story stay in helmfile.
- The service listener has no Kubernetes access on purpose: it only records pins and reads state from Postgres. Only the web listener (create, rotate, delete) and the sweeper hold a Role on `secrets` (`create`, `patch`, `delete`, never `get`/`list`/`watch`), so a compromised orchestrator credential cannot create or delete Secrets.
- `serve-service` exits 78 when a service token equals `VAULT_ORCHESTRATOR_TOKEN`: the token the vault sends to the orchestrator must not also open the vault's own service port.
- Settings bounds: sweeper interval 5..3600 s (below 5 hammers the orchestrator session list, above an hour leaves pins unreleased too long); pin grace 60..86400 s (the window between session create and pin registration); max value 1..1048576 bytes (a Kubernetes Secret is capped at 1 MiB). `VAULT_NAMESPACE` must be a DNS-1123 label (at most 63) because it names the namespace Secrets are written to.
- Migration 0001 has no column for a value, hash or length of a value; `tests/test_migrations.py` scans `information_schema.columns` for such names.
- The chart, its mise tasks and the CI `chart` job are added in the chart task; until then `chart-publish` exists in CI but cannot run without `chart/agents-vault`.
