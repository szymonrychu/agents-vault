# agents-vault memory

Lessons that outlive a session. Newest first.

## 2026-11-08 - multi-env entries (0.2.0, T-72 addendum)

- Entry model fixed by the user: free-text name (trimmed, 1..120, unique case-insensitively among live entries via `entries_live_name` on `lower(name)`), description, labels and an ordered set of 1..20 envs. Each env is protected (value only in the version's Secret, data key = env name) or readable (`entry_envs.value`, at most 4096 bytes, shown in web and service views). Env names may repeat across entries (two `GITHUB_TOKEN` entries for two orgs).
- `tests/test_migrations.py` allows exactly one value column, `entry_envs.value`: the old "no value column at all" scan is no longer accurate for readable envs. A CHECK makes the value NULL for a protected env, and the protected hard rule (no value, hash or length) still holds.
- The env set (names, protected flags) is fixed at create (Q21 A): refs name envs and the attachment index is a 15 s cache, so a removal or a readable-to-protected flip cannot be refused reliably. A different shape is a new entry.
- Rotate takes exactly the protected set (`vault_envs_mismatch` with `missing`/`extra`): the Role has no `get` on Secrets, so an untouched protected value cannot be copied into the new immutable Secret. Readable edits are in place and bump no version for the same reason; sessions get readable values at pin time, and a pin replay answers the current readable value (only protected envs are versioned).
- An entry with zero protected envs still writes an (empty) version Secret at create: one code path for create, pins and GC. Rotating it is refused (422 `vault_nothing_to_rotate`, review of PR 2): a new empty version changes nothing and only churns Secrets. The size cap `VAULT_MAX_VALUE_BYTES` is the sum of protected bytes, checked before Postgres.
- Entries are identified by id (Q19 C): web routes take `{entry_id}`, service refs are `{PRESET_ENV: {entry, env}}`, preset refs `{"vault": "<uuid>", "env": "ENV"}`; a rename is free (no attachment check). The service `GET /entries?name=` binds a name to its id for the cut-over. `events` gained `entry_id` (filter `?entry=<id>`) so an entry's history follows it across renames; `entry_name` keeps the name at the time.
- Events carry env names only (Q20 A): `entry_created {envs, protected}`, `entry_envs_updated {envs}`, `entry_rotated {version, envs}`; readable values are never in an event.
- `resolve` reports `unknown`, `bad_env` and `mismatched` as preset env names. `POST /pins` refuses in the order `vault_entry_unknown` (`envs`, `entries`), `vault_env_unknown`, `vault_label_mismatch`, and pins every preset env (readable ones too, storing `entry_env`), so the session holds the version it started with.
- 422 messages cut the location at the first caller-chosen key (a dict key in `values`, `envs` or `refs` could be a value); only known field and parameter names are shown.
- A NUL character in a name, description, label or readable value is a 422, not a 500: Postgres text cannot hold it.
- Migration 0002 is strict: it refuses to run while any entry or pin row exists (no backfill; the live database had none).

## 2026-11-08 - write protocol decisions

- Writing-row protocol: tx A inserts the `writing` version row under the entry's `FOR UPDATE` plus `pg_advisory_xact_lock` and commits, then Kubernetes gets the Secret, then tx B (locks again) makes it live. The row names the Secret before it exists, so a crash leaves a `writing` row the sweeper (Task 7) can reap; no blind probing for orphan Secrets. `write_secret` deletes the name first because an immutable Secret cannot be applied over, and a leftover can only be a write whose row never committed.
- A failed create soft-deletes the entry (`deleted_at = now()`, version `retired` with `deleted_at`) in the same transaction (plan correction 6): otherwise the entry row with `current_version = 0` keeps the live name taken (`entries_live_name`). Every read helper ignores `current_version = 0` and deleted entries. A failed rotate only retires the new row; the old version stays live and current.
- Rotate race rule: tx B makes version n current only when `n > current_version` (read under the lock). A rotate whose Secret write finished after a higher version committed retires its row at once (`retired_at` set, `deleted_at` null) so the sweeper deletes that Secret; it never moves `current_version` backwards. A rotate whose entry was deleted meanwhile retires its row the same way and answers not found. A row the sweeper reaped (no longer `writing`) answers 502.
- Errors raised for a failed Kubernetes write are raised outside the `except` block, so no exception chain carries the Kubernetes body; only the secret name and the exception type name are logged.
- `FakeKube` refuses Secret reads on purpose: the real Role has no `get`/`list`/`watch` on secrets, so the KubeApi protocol has no read methods and the fake exposes `get_object`/`list_objects` only to record a `Forbidden` attempt in `forbidden`. A test that asserts `forbidden == []` proves no code path reads a Secret.

## 2026-11-08 - scaffold decisions

- Template: the process split (one process per listener, one Deployment per component) is agents-taskboard's. The service listener's token file (`VAULT_SERVICE_TOKENS_FILE`, one raw token per line, loaded with `agents_common.service_gate.load_tokens`) is agents-history's pattern, not taskboard's single env token: a file mounted from a Secret lets the hash/rotation story stay in helmfile.
- The service listener has no Kubernetes access on purpose: it only records pins and reads state from Postgres. Only the web listener (create, rotate, delete) and the sweeper hold a Role on `secrets` (`create`, `patch`, `delete`, never `get`/`list`/`watch`), so a compromised orchestrator credential cannot create or delete Secrets.
- `serve-service` exits 78 when a service token equals `VAULT_ORCHESTRATOR_TOKEN`: the token the vault sends to the orchestrator must not also open the vault's own service port.
- Settings bounds: sweeper interval 5..3600 s (below 5 hammers the orchestrator session list, above an hour leaves pins unreleased too long); pin grace 60..86400 s (the window between the pin call and the session insert commit, plus the orchestrator slug retries); max value 1..1048576 bytes (a Kubernetes Secret is capped at 1 MiB). `VAULT_NAMESPACE` must be a DNS-1123 label (at most 63) because it names the namespace Secrets are written to.
- Migration 0001 has no column for a value, hash or length of a value; `tests/test_migrations.py` scans `information_schema.columns` for such names.
- The chart, its mise tasks and the CI `chart` job are added in the chart task; until then `chart-publish` exists in CI but cannot run without `chart/agents-vault`.

## 2026-11-08 web routes and attachments (task 5)
- Attachments come from the orchestrator (`GET /api/v1/presets`) and are cached 15 s in the web
  process (`ATTACHMENTS_TTL_SECONDS`). A failed read is never cached.
- When the orchestrator cannot be asked (unreachable, any error, 401 included) `attachments` and
  `attachments_count` are null and list/detail still answer 200. The spec is silent; null is the
  honest "unknown" and keeps the page usable while the orchestrator hash is not yet applied.
- DELETE always reads fresh (`by_entry(fresh=True)`): a stale cache could miss a ref attached
  seconds ago. Unknown attachments refuse with 503 `orchestrator_unavailable`; nothing is deleted.
- The Kubernetes client and the orchestrator client are built lazily on first use (in-cluster
  ServiceAccount), so a web pod without cluster access still serves reads.

## 2026-11-08 service listener routes (task 6)
- `POST /pins` is idempotent per `session_id`: if any pin row of the session exists (released or not) those rows are returned and nothing is written, the body of the retry is ignored. Existing pins win so an orchestrator retry after a rotate cannot move a session to a newer version than the one its pod was started with. A per-session advisory lock serialises concurrent first calls.
- The live entry rows are read `FOR SHARE` in the pin transaction. A rotate or delete takes `FOR UPDATE` on the entry row (`lock_entry`), so it waits until the pin commits: the version the pin names cannot be retired and collected by the sweeper before the pin row is visible (spec 5.1).
- `POST /entries/resolve` never answers 422 for an unknown name or a label mismatch: it reports them in `unknown` and `mismatched` and the orchestrator maps them to its own errors. Only a malformed request is 422. `POST /pins` does 422 (`vault_entry_unknown` before `vault_label_mismatch`) because it must not create a half-pinned session.
- Label matching (`agents_common.labels.labels_match`) is evaluated only in the vault; the orchestrator sends preset labels and never decides.
- FastAPI hides included routers from `app.routes`; route-set tests compare `app.openapi()["paths"]`.

## 2026-11-08 sweeper (task 7)
- Pin release is a pull (reconcile against `GET /api/v1/sessions`), not a push: the orchestrator's discard path already has a fragile hook chain and a missed push would leak a Secret for ever, while the pull is idempotent and self-healing. Fail safe: an unreachable or 401 orchestrator, or a non-list answer, releases nothing that pass. `pin_grace_seconds` is compared with the vault's own clock (`pins.created_at < now() - grace`); it covers the window between the pin call and the session insert. A younger pin is kept even when unlisted; Secrets are released late, never early.
- Each unit works one row per transaction under `lock_entry` (row lock plus the advisory lock of the write protocol) and re-checks its condition after taking it. The Secret delete happens inside the transaction so a failure rolls the row back untouched and the next pass retries. Delete of a Secret that is already gone is fine.
- A stale `writing` row (older than 600 s) is reaped by the sweeper: Secret deleted by name, row `retired` with `deleted_at`, and an entry still at `current_version = 0` is soft-deleted (correction 6). The create/rotate writers delete the Secret themselves when they find their row reaped, so the two never fight over bookkeeping.
- Purge window is 30 days after the entry's `deleted_at`, and only when every version has `deleted_at` (so no live pin can exist). Pins, versions and the entry row go; `events` stay for audit.
- The Kubernetes client is built lazily once per pass and only when a Secret must be deleted.

## 2026-11-08 openapi, readme, canary (task 8)
- The canary test found one real leak, fixed: a 422 for a forbidden extra field put the caller's own key (the last `loc` element) into the error message, and a caller can name a key after a value. `extra_forbidden` errors now drop that element. Other 422 messages use only fixed field names.
- The canary is split: the refusals that happen before the store touches Postgres (422 variants, 413 on create and rotate) run on fakes with no database; the full life (create, rotate, 502 with the canary in the Kubernetes error text, pins, release, delete, sweeper passes, row scan of every table) needs Postgres and runs in CI. It also searches for the base64 forms of the canary.
- The OpenAPI documents list the statuses per route by hand (`ROUTE_ERRORS`); a test compares the documented paths with the apps' routes, so a new route fails until it is listed.

## 2026-11-08 chart (task 9)
- `web` and `sweeper` pods mount the ServiceAccount token (they create/patch and delete Secrets through the Kubernetes API); `service` sets `automountServiceAccountToken: false` because it only reads Postgres and never talks to the API server. The ServiceAccount object itself stays non-automounting.
- The Role grants exactly `create`, `patch`, `delete` on `secrets` in the release namespace: no get, list or watch, so a compromised vault pod cannot read any Secret back (write-only by construction). `patch` is for server-side apply.
- `serviceListener.tokensSecret.name` is required and the Secret is external (never rendered by the chart); it is mounted only into the `service` container, as in agents-history.

## 2026-11-09 only project: labels restrict (T-72, user decision Q25 A)
- Entries carry descriptive tags (admin, credentials, github, ...) and presets have none, so the old rule (any labelled entry needs a shared label) made every attach and session start fail 422 `vault_label_mismatch`. agents-common v0.13.0 `labels_match` now treats only `project:` labels as a scope: no `project:` label on the entry means match, otherwise the sets must intersect. Pin bumped to v0.13.0.
- Vault label validation (`clean_labels`) already rejects only malformed `project:` labels and accepts any normalised tag, so it needed no change; the attachment `matches` marker and `mismatched_attachments` in `api/entries.py`, and resolve/pins in `api/service.py`, follow the new rule through `labels_match`.
- Tests that used tag labels (`team-a`/`team-b`) to force a mismatch now use `project:` labels; new tests cover tag-only and mixed entries.
