# agents-vault

Component `agents-vault` (python) of the workdir project. Its own tests, `MEMORY.md` and `ROADMAP.md` live here.

Run `mise run test`, `mise run lint` and `mise run fmt` from this directory.

## Commands

- `mise run test` / `lint` / `fmt`.
- `vault migrate | serve-web | serve-service | sweeper` (see README); the image entrypoint is `vault`.
- Release: the `release` job of `.github/workflows/ci.yaml` runs last on a push to main and tags the image and the repo `vX.Y.Z` from conventional commits (`scripts/next_version.py`, byte-identical in every component that releases this way). Deploy only semver tags.

- OpenAPI: after any route or schema change run `uv run python -m agents_vault.api.openapi > openapi.json` and `uv run python -m agents_vault.api.openapi --service > openapi-service.json`; a test fails on drift.

## Hard rules

- A protected env value is held only as a `SecretStr` until it goes into a Kubernetes Secret. It is never logged, returned, stored in Postgres or put into an event or an error text. No hash or length of a value is stored either. Readable env values are stored in `entry_envs.value` and shown in views, but never put into an event or a log line.
- RBAC on `secrets` is `create`, `patch`, `delete` only: code never reads or lists a Secret.
- Trust boundary: whatever can read Secrets in the agents namespace (cluster-admin sessions, privileged or docker-in-docker sessions, node root, cluster operators) is outside the vault's protection; rotation is the response after such access. State it in the README and keep it there.
- The audit actor of a web action is `user:<email>` from the loopback-only SSO sidecar headers (`X-Forwarded-Email`, else `X-Forwarded-User`), else `user`; never trust these headers for the allowlist decision.
- On the service listener `preset_labels` carries one `project:` label per project of the caller's scope (home plus extra projects, T-120); an entry matches when one of its `project:` labels is in that set; a labels PATCH that changes or drops a `project:` label of an attached entry needs `?force=true`.
