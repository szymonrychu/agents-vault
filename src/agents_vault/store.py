"""The versioned write protocol (spec 3.3), used by the web routes and the sweeper.

Create and rotate write one immutable Secret per version under the entry's row lock and
advisory lock: tx A inserts a `writing` version row (so a crash leaves a row naming a Secret
that may exist), Kubernetes gets the Secret, tx B makes the version live. A Kubernetes failure
retires the row and answers `SecretStoreFailed`; a failed create also soft-deletes the entry so
its name is free again (plan correction 6).

A value is a `SecretStr` here and only becomes plain text inside `write_secret`. No value, and
no Kubernetes error body, reaches a log line, an event, an exception text or Postgres: the only
thing logged about a failed write is the secret name and the exception type name.
"""

from __future__ import annotations

import logging
import re
import uuid
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

_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,127}")
DESCRIPTION_MAX = 500


class StoreError(Exception):
    """Base of the store's errors; messages are fixed text, never a value or an API body."""


class NameTaken(StoreError):
    """A live entry already has this name (409 `vault_name_taken`)."""


class EntryNotFound(StoreError):
    """No live entry has this name (404 `not_found`)."""


class SecretTooLarge(StoreError):
    """The value is over the size cap (413 `secret_too_large`)."""


class SecretStoreFailed(StoreError):
    """Kubernetes refused or failed the Secret write (502 `secret_store_failed`)."""


def clean_labels(raw: list[str]) -> list[str]:
    """Normalised labels; ValueError (the routes answer 422) on a bad label or project label."""
    labels = normalize_labels(raw)
    for label in labels:
        if label.startswith(PROJECT_PREFIX) and not is_project_label(label):
            raise ValueError(f"invalid project label {label!r}")
    return labels


def _clean_description(description: str) -> str:
    if not description.strip() or len(description) > DESCRIPTION_MAX:
        raise ValueError(f"description must be 1 to {DESCRIPTION_MAX} characters")
    return description


async def _write_or_cleanup(
    kube: KubeApi, namespace: str, entry_id: uuid.UUID, version: int, value: SecretStr
) -> tuple[bool, bool]:
    """Write the version's Secret; returns (failed, cleaned).

    On failure the name is deleted best-effort (the apply may have landed); `cleaned` says
    whether that delete succeeded. An uncleaned Secret must stay named by an undeleted row.
    """
    name = secret_name(entry_id, version)
    try:
        await write_secret(kube, namespace, name, entry_id, value)
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
    value: SecretStr,
    max_value_bytes: int,
) -> uuid.UUID:
    """Create entry `name` with version 1 holding `value`; returns the entry id."""
    if len(value.get_secret_value().encode()) > max_value_bytes:
        raise SecretTooLarge("secret value is over the size limit")
    if not _NAME.fullmatch(name):
        raise ValueError("invalid entry name")
    description = _clean_description(description)
    labels = clean_labels(labels)
    entry_id = uuid.uuid4()
    taken = False
    async with pool.connection() as conn:
        try:
            async with conn.transaction():
                await repo.insert_entry(conn, entry_id, name, description, labels)
                await repo.lock_entry(conn, entry_id)
                await repo.insert_writing(conn, entry_id, 1)
        except psycopg.errors.UniqueViolation as exc:
            if exc.diag.constraint_name != "entries_live_name":
                raise
            taken = True
    if taken:
        raise NameTaken("an entry with this name already exists")

    failed, cleaned = await _write_or_cleanup(kube, namespace, entry_id, 1, value)
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
                conn, "entry_created", actor, name, {"name": name, "labels": labels}
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
    name: str,
    value: SecretStr,
    max_value_bytes: int,
) -> int:
    """Write a new version of entry `name` and make it current; returns the version."""
    if len(value.get_secret_value().encode()) > max_value_bytes:
        raise SecretTooLarge("secret value is over the size limit")
    async with pool.connection() as conn, conn.transaction():
        entry = await repo.lock_live_entry(conn, name)
        if entry is None:
            raise EntryNotFound("no such entry")
        entry_id = entry["id"]
        version = await repo.next_version(conn, entry_id)
        await repo.insert_writing(conn, entry_id, version)

    failed, cleaned = await _write_or_cleanup(kube, namespace, entry_id, version, value)
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
                conn, "entry_rotated", actor, name, {"name": name, "version": version}
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
    name: str,
    description: str | None = None,
    labels: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Change description and/or labels; returns (labels before, labels after)."""
    new_description = _clean_description(description) if description is not None else None
    new_labels = clean_labels(labels) if labels is not None else None
    async with pool.connection() as conn, conn.transaction():
        entry = await repo.lock_live_entry(conn, name)
        if entry is None:
            raise EntryNotFound("no such entry")
        before = list(entry["labels"])
        after = before if new_labels is None else new_labels
        changed = new_description is not None and new_description != entry["description"]
        await repo.update_fields(
            conn,
            entry["id"],
            entry["description"] if new_description is None else new_description,
            after,
        )
        await events_repo.add_event(
            conn,
            "entry_updated",
            actor,
            name,
            {
                "name": name,
                "description_changed": changed,
                "labels_before": before,
                "labels_after": after,
            },
        )
    return before, after


async def delete_entry(pool: AsyncConnectionPool, actor: str, *, name: str) -> None:
    """Soft-delete the entry and retire its live version (the attachment check is the route's).

    The Secret stays until the sweeper finds no live pin on the version.
    """
    async with pool.connection() as conn, conn.transaction():
        entry = await repo.lock_live_entry(conn, name)
        if entry is None:
            raise EntryNotFound("no such entry")
        await repo.soft_delete_entry(conn, entry["id"])
        await repo.retire_live_versions(conn, entry["id"])
        await events_repo.add_event(conn, "entry_deleted", actor, name, {"name": name})


async def list_entries(
    pool: AsyncConnectionPool, q: str | None = None, labels: list[str] | None = None
) -> list[Row]:
    wanted = clean_labels(labels) if labels else None
    async with pool.connection() as conn:
        return await repo.list_entries(conn, q, wanted)


async def get_entry(pool: AsyncConnectionPool, name: str) -> Row | None:
    async with pool.connection() as conn:
        return await repo.get_entry(conn, name)


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
    entry: str | None = None,
    before_id: int | None = None,
    limit: int = 50,
) -> list[Row]:
    async with pool.connection() as conn:
        return await events_repo.list_events(conn, entry, before_id, limit)
