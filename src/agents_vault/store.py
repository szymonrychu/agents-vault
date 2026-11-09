"""The versioned write protocol (spec 3.3), used by the web routes and the sweeper.

Create and rotate write one immutable Secret per version under the entry's row lock and
advisory lock: tx A inserts a `writing` version row (so a crash leaves a row naming a Secret
that may exist), Kubernetes gets the Secret, tx B makes the version live. A Kubernetes failure
retires the row and answers `SecretStoreFailed`; a failed create also soft-deletes the entry so
its name is free again (plan correction 6).

An entry holds an ordered env set fixed at create: a protected env's value lives only in the
version's Secret (one data key per protected env), a readable env's value lives in Postgres
(`entry_envs.value`) and is edited in place without a version. Every value arrives as a
`SecretStr`; a protected one only becomes plain text inside `write_secret`. No protected value,
and no Kubernetes error body, reaches a log line, an event, an exception text or Postgres: the
only thing logged about a failed write is the secret name and the exception type name. Events
carry env names, never a value (readable values included).
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import psycopg
from agents_common.labels import PROJECT_PREFIX, is_project_label, normalize_labels
from psycopg_pool import AsyncConnectionPool
from pydantic import SecretStr

from agents_vault.db import entries as repo
from agents_vault.db import events as events_repo
from agents_vault.k8s import KubeApi, KubeError, secret_name, write_secret

log = logging.getLogger(__name__)

Row = dict[str, Any]

_ENV = re.compile(r"[A-Z_][A-Z0-9_]{0,127}")
NAME_MAX = 120
DESCRIPTION_MAX = 500
ENVS_MAX = 20
PROTECTED_MIN_CHARS = 8
READABLE_MAX_BYTES = 4096


class StoreError(Exception):
    """Base of the store's errors; messages are fixed text, never a value or an API body."""


class NameTaken(StoreError):
    """A live entry already has this name (409 `vault_name_taken`)."""


class EntryNotFound(StoreError):
    """No live entry has this id (404 `not_found`)."""


class SecretTooLarge(StoreError):
    """The protected values together are over the size cap (413 `secret_too_large`)."""


class EnvsMismatch(StoreError):
    """A rotate did not supply exactly the protected env set (422 `vault_envs_mismatch`)."""

    def __init__(self, missing: list[str], extra: list[str]) -> None:
        super().__init__("the values must name exactly the protected envs of the entry")
        self.missing = missing
        self.extra = extra


class NothingToRotate(StoreError):
    """The entry has no protected env, so a rotate has nothing to write (422
    `vault_nothing_to_rotate`)."""


class ValueTooShort(StoreError):
    """A protected env value is under the minimum length (422 `vault_value_too_short`). The
    message names the envs only, never a value or its length."""

    def __init__(self, envs: list[str]) -> None:
        super().__init__(
            f"the value of {', '.join(envs)} is too short for a protected env"
            f" (minimum {PROTECTED_MIN_CHARS} characters)"
        )
        self.envs = envs


class EnvProtected(StoreError):
    """An edit named a protected env; its value changes only by rotate (422)."""

    def __init__(self, envs: list[str]) -> None:
        super().__init__("protected env values change only by rotate")
        self.envs = envs


class EnvUnknown(StoreError):
    """An edit named an env the entry does not have (422 `vault_env_unknown`)."""

    def __init__(self, envs: list[str]) -> None:
        super().__init__("the entry has no such env")
        self.envs = envs


@dataclass(frozen=True)
class EnvIn:
    """One env of a new entry. The value is a SecretStr even for a readable env, so that no
    value is shown by a repr; only a protected value is kept out of Postgres."""

    env: str
    protected: bool
    value: SecretStr


class SecretStoreFailed(StoreError):
    """Kubernetes refused or failed the Secret write (502 `secret_store_failed`)."""


def clean_labels(raw: list[str]) -> list[str]:
    """Normalised labels; ValueError (the routes answer 422) on a bad label or project label."""
    labels = normalize_labels(raw)
    for label in labels:
        if label.startswith(PROJECT_PREFIX) and not is_project_label(label):
            raise ValueError(f"invalid project label {label!r}")
    return labels


def clean_name(name: str) -> str:
    """The trimmed free-text name, 1..NAME_MAX characters."""
    name = _no_nul(name.strip(), "a name")
    if not 1 <= len(name) <= NAME_MAX:
        raise ValueError(f"name must be 1 to {NAME_MAX} characters after trimming")
    return name


def _no_nul(text: str, what: str) -> str:
    """Postgres text cannot hold a NUL character: refuse it as a 422, never a 500."""
    if "\x00" in text:
        raise ValueError(f"{what} must not contain a NUL character")
    return text


def _require_min_length(values: Mapping[str, SecretStr]) -> None:
    """Refuse a protected value under PROTECTED_MIN_CHARS; `values` keys are validated env names."""
    short = sorted(e for e, v in values.items() if len(v.get_secret_value()) < PROTECTED_MIN_CHARS)
    if short:
        raise ValueTooShort(short)


def _protected_bytes(values: Mapping[str, SecretStr]) -> int:
    return sum(len(v.get_secret_value().encode()) for v in values.values())


def _readable(value: str) -> str:
    """A readable value as stored: at most READABLE_MAX_BYTES UTF-8 bytes, no NUL character.
    The message never carries the value."""
    if len(value.encode()) > READABLE_MAX_BYTES:
        raise ValueError(f"a readable env value must be at most {READABLE_MAX_BYTES} bytes")
    return _no_nul(value, "a readable env value")


def _clean_envs(envs: list[EnvIn]) -> list[EnvIn]:
    if not 1 <= len(envs) <= ENVS_MAX:
        raise ValueError(f"an entry has 1 to {ENVS_MAX} envs")
    seen: set[str] = set()
    for item in envs:
        if not _ENV.fullmatch(item.env):
            raise ValueError("env names must match ^[A-Z_][A-Z0-9_]{0,127}$")
        if item.env in seen:
            raise ValueError("env names must be unique within an entry")
        seen.add(item.env)
        if not item.protected:
            _readable(item.value.get_secret_value())
    return envs


def _clean_description(description: str) -> str:
    _no_nul(description, "a description")
    if not description.strip() or len(description) > DESCRIPTION_MAX:
        raise ValueError(f"description must be 1 to {DESCRIPTION_MAX} characters")
    return description


async def _write_or_cleanup(
    kube: KubeApi,
    namespace: str,
    entry_id: uuid.UUID,
    version: int,
    data: Mapping[str, SecretStr],
) -> tuple[bool, bool]:
    """Write the version's Secret; returns (failed, cleaned).

    On failure the name is deleted best-effort (the apply may have landed); `cleaned` says
    whether that delete succeeded. An uncleaned Secret must stay named by an undeleted row.
    """
    name = secret_name(entry_id, version)
    try:
        await write_secret(kube, namespace, name, entry_id, data)
    except KubeError as exc:
        log.warning("secret write failed for %s: %s", name, type(exc).__name__)
    else:
        return False, True
    return True, await _delete_quietly(kube, namespace, name)


async def _delete_quietly(kube: KubeApi, namespace: str, name: str) -> bool:
    """Best-effort delete; True when the call succeeded (a missing Secret counts)."""
    try:
        await kube.delete("Secret", namespace, name)
    except Exception as exc:
        log.warning("secret cleanup failed for %s: %s", name, type(exc).__name__)
        return False
    return True


async def _stamp_after_reap(
    pool: AsyncConnectionPool, kube: KubeApi, namespace: str, entry_id: uuid.UUID, version: int
) -> None:
    """Fast-path delete of a Secret that landed after the sweeper reaped its row.

    The row was left unstamped (see the callers), so if this delete fails the GC retries it.
    """
    if await _delete_quietly(kube, namespace, secret_name(entry_id, version)):
        async with pool.connection() as conn, conn.transaction():
            await repo.lock_entry(conn, entry_id)
            await repo.stamp_version_deleted(conn, entry_id, version)


async def _retire_failed(
    conn: psycopg.AsyncConnection, entry_id: uuid.UUID, version: int, cleaned: bool
) -> None:
    if cleaned:
        await repo.retire_failed_version(conn, entry_id, version)
    else:  # the Secret may exist: keep the row undeleted so the GC deletes the name
        await repo.retire_unwritten_version(conn, entry_id, version)


async def create_entry(
    pool: AsyncConnectionPool,
    kube: KubeApi,
    namespace: str,
    actor: str,
    *,
    name: str,
    description: str,
    labels: list[str],
    envs: list[EnvIn],
    max_value_bytes: int,
) -> uuid.UUID:
    """Create entry `name` with its env set and version 1 (a Secret holding the protected
    values, possibly none); returns the entry id."""
    protected = {e.env: e.value for e in envs if e.protected}
    if _protected_bytes(protected) > max_value_bytes:
        raise SecretTooLarge("the protected values are over the size limit")
    name = clean_name(name)
    envs = _clean_envs(envs)
    _require_min_length({e.env: e.value for e in envs if e.protected})
    description = _clean_description(description)
    labels = clean_labels(labels)
    rows = [(e.env, e.protected, None if e.protected else e.value.get_secret_value()) for e in envs]
    entry_id = uuid.uuid4()
    taken = False
    async with pool.connection() as conn:
        try:
            async with conn.transaction():
                await repo.insert_entry(conn, entry_id, name, description, labels)
                await repo.lock_entry(conn, entry_id)
                await repo.insert_envs(conn, entry_id, rows)
                await repo.insert_writing(conn, entry_id, 1)
        except psycopg.errors.UniqueViolation as exc:
            if exc.diag.constraint_name != "entries_live_name":
                raise
            taken = True
    if taken:
        raise NameTaken("an entry with this name already exists")

    failed, cleaned = await _write_or_cleanup(kube, namespace, entry_id, 1, protected)
    async with pool.connection() as conn, conn.transaction():
        await repo.lock_entry(conn, entry_id)
        reaped = not failed and await repo.version_state(conn, entry_id, 1) != "writing"
        if failed or reaped:
            if failed:
                await _retire_failed(conn, entry_id, 1, cleaned)
            else:  # the sweeper retired and stamped the row; our apply landed after it
                await repo.unstamp_version(conn, entry_id, 1)
            await repo.soft_delete_entry(conn, entry_id)
        else:
            await repo.make_current(conn, entry_id, 1)
            await events_repo.add_event(
                conn,
                "entry_created",
                actor,
                entry_id,
                name,
                {
                    "name": name,
                    "labels": labels,
                    "envs": [e.env for e in envs],
                    "protected": sorted(protected),
                },
            )
    if reaped:
        await _stamp_after_reap(pool, kube, namespace, entry_id, 1)
    if failed or reaped:
        raise SecretStoreFailed("the secret could not be stored")
    return entry_id


async def rotate_entry(
    pool: AsyncConnectionPool,
    kube: KubeApi,
    namespace: str,
    actor: str,
    *,
    entry_id: uuid.UUID,
    values: Mapping[str, SecretStr],
    max_value_bytes: int,
) -> int:
    """Write a new version holding exactly the entry's protected envs and make it current;
    returns the version."""
    if _protected_bytes(values) > max_value_bytes:
        raise SecretTooLarge("the protected values are over the size limit")
    async with pool.connection() as conn, conn.transaction():
        entry = await repo.lock_live_entry(conn, entry_id)
        if entry is None:
            raise EntryNotFound("no such entry")
        wanted = {r["env"] for r in await repo.envs_of(conn, [entry_id]) if r["protected"]}
        if not wanted:
            raise NothingToRotate("the entry has no protected env to rotate")
        if set(values) != wanted:
            raise EnvsMismatch(sorted(wanted - set(values)), sorted(set(values) - wanted))
        _require_min_length(values)
        version = await repo.next_version(conn, entry_id)
        await repo.insert_writing(conn, entry_id, version)

    failed, cleaned = await _write_or_cleanup(kube, namespace, entry_id, version, values)
    gone = False
    async with pool.connection() as conn, conn.transaction():
        current = await repo.lock_entry(conn, entry_id)
        if current is None:
            raise EntryNotFound("no such entry")
        reaped = not failed and await repo.version_state(conn, entry_id, version) != "writing"
        if failed:
            await _retire_failed(conn, entry_id, version, cleaned)
        elif reaped:  # the sweeper retired and stamped the row; our apply landed after it
            await repo.unstamp_version(conn, entry_id, version)
        elif current["deleted_at"] is not None:
            gone = True  # the entry was deleted while the Secret was written
            await repo.retire_unwritten_version(conn, entry_id, version)
        elif version > current["current_version"]:
            await repo.make_current(conn, entry_id, version)
        else:  # a concurrent rotate committed a higher version first
            await repo.retire_unwritten_version(conn, entry_id, version)
        if not (failed or reaped or gone):
            await events_repo.add_event(
                conn,
                "entry_rotated",
                actor,
                entry_id,
                current["name"],
                {"name": current["name"], "version": version, "envs": sorted(values)},
            )
    if reaped:
        await _stamp_after_reap(pool, kube, namespace, entry_id, version)
    if failed or reaped:
        raise SecretStoreFailed("the secret could not be stored")
    if gone:
        raise EntryNotFound("no such entry")
    return version


async def update_entry(
    pool: AsyncConnectionPool,
    actor: str,
    *,
    entry_id: uuid.UUID,
    name: str | None = None,
    description: str | None = None,
    labels: list[str] | None = None,
    envs: Mapping[str, SecretStr] | None = None,
) -> None:
    """Rename, change description and/or labels, and set readable env values in place (no
    version bump). A protected or unknown env refuses the whole edit."""
    new_name = clean_name(name) if name is not None else None
    new_description = _clean_description(description) if description is not None else None
    new_labels = clean_labels(labels) if labels is not None else None
    new_values = {k: _readable(v.get_secret_value()) for k, v in (envs or {}).items()}
    taken = False
    async with pool.connection() as conn:
        try:
            async with conn.transaction():
                entry = await repo.lock_live_entry(conn, entry_id)
                if entry is None:
                    raise EntryNotFound("no such entry")
                if new_values:
                    have = {r["env"]: r for r in await repo.envs_of(conn, [entry_id])}
                    unknown = sorted(set(new_values) - set(have))
                    if unknown:
                        raise EnvUnknown(unknown)
                    protected = sorted(e for e in new_values if have[e]["protected"])
                    if protected:
                        raise EnvProtected(protected)
                    await repo.update_env_values(conn, entry_id, new_values)
                    await repo.touch(conn, entry_id)
                if (new_name, new_description, new_labels) != (None, None, None):
                    before = list(entry["labels"])
                    after = before if new_labels is None else new_labels
                    renamed = new_name if new_name is not None else entry["name"]
                    await repo.update_fields(
                        conn,
                        entry_id,
                        renamed,
                        entry["description"] if new_description is None else new_description,
                        after,
                    )
                    await events_repo.add_event(
                        conn,
                        "entry_updated",
                        actor,
                        entry_id,
                        renamed,
                        {
                            "name": renamed,
                            "name_before": entry["name"],
                            "description_changed": new_description is not None
                            and new_description != entry["description"],
                            "labels_before": before,
                            "labels_after": after,
                        },
                    )
                if new_values:
                    current = renamed if new_name is not None else entry["name"]
                    await events_repo.add_event(
                        conn,
                        "entry_envs_updated",
                        actor,
                        entry_id,
                        current,
                        {"name": current, "envs": sorted(new_values)},
                    )
        except psycopg.errors.UniqueViolation as exc:
            if exc.diag.constraint_name != "entries_live_name":
                raise
            taken = True
    if taken:
        raise NameTaken("an entry with this name already exists")


async def delete_entry(pool: AsyncConnectionPool, actor: str, *, entry_id: uuid.UUID) -> None:
    """Soft-delete the entry and retire its live version (the attachment check is the route's).

    The Secret stays until the sweeper finds no live pin on the version.
    """
    async with pool.connection() as conn, conn.transaction():
        entry = await repo.lock_live_entry(conn, entry_id)
        if entry is None:
            raise EntryNotFound("no such entry")
        await repo.soft_delete_entry(conn, entry_id)
        await repo.retire_live_versions(conn, entry_id)
        await events_repo.add_event(
            conn, "entry_deleted", actor, entry_id, entry["name"], {"name": entry["name"]}
        )


async def _with_envs(conn: psycopg.AsyncConnection, rows: list[Row]) -> list[Row]:
    """Each entry row with its ordered `envs` (env, protected, value, updated_at)."""
    by_entry: dict[uuid.UUID, list[Row]] = {r["id"]: [] for r in rows}
    for env in await repo.envs_of(conn, list(by_entry)):
        by_entry[env["entry_id"]].append(env)
    return [{**r, "envs": by_entry[r["id"]]} for r in rows]


async def list_entries(
    pool: AsyncConnectionPool,
    q: str | None = None,
    labels: list[str] | None = None,
    name: str | None = None,
) -> list[Row]:
    wanted = clean_labels(labels) if labels else None
    async with pool.connection() as conn:
        return await _with_envs(conn, await repo.list_entries(conn, q, wanted, name))


async def get_entry(pool: AsyncConnectionPool, entry_id: uuid.UUID) -> Row | None:
    async with pool.connection() as conn:
        row = await repo.get_entry(conn, entry_id)
        return None if row is None else (await _with_envs(conn, [row]))[0]


async def entry_versions(pool: AsyncConnectionPool, entry_id: uuid.UUID) -> list[Row]:
    async with pool.connection() as conn:
        return await repo.entry_versions(conn, entry_id)


async def pinned_sessions_count(pool: AsyncConnectionPool, entry_id: uuid.UUID) -> int:
    async with pool.connection() as conn:
        return await repo.pinned_sessions_count(conn, entry_id)


async def behind_count(pool: AsyncConnectionPool, entry_id: uuid.UUID) -> int:
    async with pool.connection() as conn:
        return await repo.behind_count(conn, entry_id)


async def live_pins(pool: AsyncConnectionPool, entry_id: uuid.UUID) -> list[Row]:
    async with pool.connection() as conn:
        return await repo.live_pins(conn, entry_id)


async def list_events(
    pool: AsyncConnectionPool,
    entry: uuid.UUID | None = None,
    before_id: int | None = None,
    limit: int = 50,
) -> list[Row]:
    async with pool.connection() as conn:
        return await events_repo.list_events(conn, entry, before_id, limit)
