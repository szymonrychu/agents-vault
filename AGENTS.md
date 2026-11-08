# agents-vault

Component `agents-vault` (python) of the workdir project. Its own tests, `MEMORY.md` and `ROADMAP.md` live here.

Run `mise run test`, `mise run lint` and `mise run fmt` from this directory.

## Commands

- `mise run test` / `lint` / `fmt`.
- `vault migrate | serve-web | serve-service | sweeper` (see README); the image entrypoint is `vault`.
- Release: the `release` job of `.github/workflows/ci.yaml` runs last on a push to main and tags the image and the repo `vX.Y.Z` from conventional commits (`scripts/next_version.py`, byte-identical in every component that releases this way). Deploy only semver tags.

- OpenAPI: after any route or schema change run `uv run python -m agents_vault.api.openapi > openapi.json` and `uv run python -m agents_vault.api.openapi --service > openapi-service.json`; a test fails on drift.

## Hard rules

- A secret value is held only as a `SecretStr` until it goes into a Kubernetes Secret. It is never logged, returned, stored in Postgres or put into an event or an error text. No hash or length of a value is stored either.
- RBAC on `secrets` is `create`, `patch`, `delete` only: code never reads or lists a Secret.
