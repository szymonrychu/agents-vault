"""The sweeper: pin release by reconciliation, version GC, stale `writing` reap, purge.

One pass (`sweep_once`) runs four units in order, each row in its own transaction; a failing
unit is logged (exception type name, entry name, version: never a value or an error body) and
the pass goes on, the next pass retries. Kubernetes is only asked to delete a Secret by name,
and the client is built only when something must be deleted.

Fail safe: if the orchestrator cannot be asked, nothing is released; a pin younger than the
grace is kept even when unlisted; Secrets are released late, never early (spec 5.3).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from uuid import UUID

from agents_common.db import open_pool
from agents_common.orchestrator import (
    OrchestratorClient,
    OrchestratorError,
    OrchestratorUnavailable,
)
from agents_common.runtime import advisory_singleton, run_service
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from agents_vault.db import entries as entries_repo
from agents_vault.db import pins as pins_repo
from agents_vault.db.events import add_event
from agents_vault.k8s import KubeApi, LightkubeApi, secret_name
from agents_vault.orchestrator import make_client
from agents_vault.settings import Settings

log = logging.getLogger(__name__)

LOCK_NAME = "agents-vault-sweeper"
ACTOR = "sweeper"
WRITING_STALE_SECONDS = 600
PURGE_AFTER_DAYS = 30

KubeFactory = Callable[[], KubeApi]


@dataclass
class SweepReport:
    sessions_released: int = 0
    release_skipped: bool = False
    versions_deleted: int = 0
    writing_reaped: int = 0
    entries_purged: int = 0
    failures: int = 0


class _Kube:
    """The Kubernetes client of one pass, built on first use and closed at the end."""

    def __init__(self, factory: KubeFactory) -> None:
        self._factory = factory
        self._api: KubeApi | None = None

    def get(self) -> KubeApi:
        if self._api is None:
            self._api = self._factory()
        return self._api

    async def aclose(self) -> None:
        if self._api is not None:
            try:
                await self._api.aclose()
            except Exception as exc:
                log.warning("kubernetes client close failed: %s", type(exc).__name__)


def _failed(report: SweepReport, unit: str, exc: Exception, **ids: object) -> None:
    report.failures += 1
    where = " ".join(f"{k}={v}" for k, v in ids.items())
    log.warning("sweeper %s failed %s: %s", unit, where, type(exc).__name__)


async def _release_pins(
    pool: AsyncConnectionPool,
    settings: Settings,
    orchestrator: OrchestratorClient,
    report: SweepReport,
) -> None:
    try:
        listed = await orchestrator.list_sessions()
    except (OrchestratorUnavailable, OrchestratorError, ValueError) as exc:
        report.release_skipped = True
        log.warning("sweeper cannot list sessions, releasing nothing: %s", type(exc).__name__)
        return
    live = [s.id for s in listed]
    grace = settings.pin_grace_seconds
    async with pool.connection() as conn:
        stale = await pins_repo.stale_unlisted_sessions(conn, live, grace)
    for session_id in stale:
        try:
            async with pool.connection() as conn, conn.transaction():
                changed = await pins_repo.release_stale_session(conn, session_id, grace)
                if changed:
                    await add_event(
                        conn,
                        "pins_released",
                        ACTOR,
                        None,
                        None,
                        {"session_id": str(session_id), "reason": "reconcile"},
                    )
            if changed:
                report.sessions_released += 1
        except Exception as exc:
            _failed(report, "release", exc, session=session_id)


async def _candidates(pool: AsyncConnectionPool, query: str) -> list[dict]:
    async with pool.connection() as conn:
        cur = conn.cursor(row_factory=dict_row)
        await cur.execute(query)
        return await cur.fetchall()


async def _collect_versions(
    pool: AsyncConnectionPool, settings: Settings, kube: _Kube, report: SweepReport
) -> None:
    found = await _candidates(
        pool,
        "SELECT v.entry_id, v.version FROM versions v"
        " WHERE v.state = 'retired' AND v.deleted_at IS NULL AND NOT EXISTS ("
        "  SELECT 1 FROM pins p WHERE p.entry_id = v.entry_id AND p.version = v.version"
        "  AND p.released_at IS NULL) ORDER BY v.entry_id, v.version",
    )
    for cand in found:
        entry_id, version = cand["entry_id"], cand["version"]
        try:
            async with pool.connection() as conn, conn.transaction():
                entry = await entries_repo.lock_entry(conn, entry_id)
                # re-check under the lock: a pin or another sweeper may have moved on
                cur = conn.cursor(row_factory=dict_row)
                await cur.execute(
                    "SELECT 1 FROM versions v WHERE v.entry_id = %s AND v.version = %s"
                    " AND v.state = 'retired' AND v.deleted_at IS NULL AND NOT EXISTS ("
                    "  SELECT 1 FROM pins p WHERE p.entry_id = v.entry_id"
                    "  AND p.version = v.version AND p.released_at IS NULL)",
                    (entry_id, version),
                )
                if entry is None or await cur.fetchone() is None:
                    continue
                await kube.get().delete(
                    "Secret", settings.namespace, secret_name(entry_id, version)
                )
                await conn.execute(
                    "UPDATE versions SET deleted_at = now() WHERE entry_id = %s AND version = %s",
                    (entry_id, version),
                )
                await add_event(
                    conn,
                    "version_deleted",
                    ACTOR,
                    entry_id,
                    entry["name"],
                    {"name": entry["name"], "version": version},
                )
            report.versions_deleted += 1
        except Exception as exc:
            _failed(report, "gc", exc, entry=entry_id, version=version)


async def _reap_writing(
    pool: AsyncConnectionPool, settings: Settings, kube: _Kube, report: SweepReport
) -> None:
    stale_sql = "state = 'writing' AND created_at < now() - make_interval(secs => %s)"
    async with pool.connection() as conn:
        cur = conn.cursor(row_factory=dict_row)
        await cur.execute(
            f"SELECT entry_id, version FROM versions WHERE {stale_sql}"  # noqa: S608
            " ORDER BY entry_id, version",
            (WRITING_STALE_SECONDS,),
        )
        found = await cur.fetchall()
    for cand in found:
        entry_id, version = cand["entry_id"], cand["version"]
        try:
            async with pool.connection() as conn, conn.transaction():
                entry = await entries_repo.lock_entry(conn, entry_id)
                cur = conn.cursor(row_factory=dict_row)
                await cur.execute(
                    f"SELECT 1 FROM versions WHERE entry_id = %s AND version = %s AND {stale_sql}",  # noqa: S608
                    (entry_id, version, WRITING_STALE_SECONDS),
                )
                if entry is None or await cur.fetchone() is None:
                    continue  # completed or reaped meanwhile
                await kube.get().delete(
                    "Secret", settings.namespace, secret_name(entry_id, version)
                )
                await entries_repo.retire_failed_version(conn, entry_id, version)
                if entry["current_version"] == 0 and entry["deleted_at"] is None:
                    await entries_repo.soft_delete_entry(conn, entry_id)
                await add_event(
                    conn,
                    "writing_reaped",
                    ACTOR,
                    entry_id,
                    entry["name"],
                    {"name": entry["name"], "version": version},
                )
            report.writing_reaped += 1
        except Exception as exc:
            _failed(report, "reap", exc, entry=entry_id, version=version)


async def _purge(pool: AsyncConnectionPool, report: SweepReport) -> None:
    due = (
        "deleted_at < now() - make_interval(days => %s)"
        " AND NOT EXISTS (SELECT 1 FROM versions v WHERE v.entry_id = entries.id"
        "  AND v.deleted_at IS NULL)"
    )
    async with pool.connection() as conn:
        cur = conn.cursor(row_factory=dict_row)
        await cur.execute(
            f"SELECT id FROM entries WHERE {due} ORDER BY id",  # noqa: S608
            (PURGE_AFTER_DAYS,),
        )
        found = await cur.fetchall()
    for cand in found:
        entry_id: UUID = cand["id"]
        try:
            async with pool.connection() as conn, conn.transaction():
                if await entries_repo.lock_entry(conn, entry_id) is None:
                    continue
                cur = conn.cursor(row_factory=dict_row)
                await cur.execute(
                    f"SELECT 1 FROM entries WHERE id = %s AND {due}",  # noqa: S608
                    (entry_id, PURGE_AFTER_DAYS),
                )
                if await cur.fetchone() is None:
                    continue
                await conn.execute("DELETE FROM pins WHERE entry_id = %s", (entry_id,))
                await conn.execute("DELETE FROM versions WHERE entry_id = %s", (entry_id,))
                await conn.execute("DELETE FROM entry_envs WHERE entry_id = %s", (entry_id,))
                await conn.execute("DELETE FROM entries WHERE id = %s", (entry_id,))
            report.entries_purged += 1
        except Exception as exc:
            _failed(report, "purge", exc, entry=entry_id)


async def sweep_once(
    pool: AsyncConnectionPool,
    settings: Settings,
    orchestrator: OrchestratorClient,
    kube_factory: KubeFactory,
) -> SweepReport:
    """One pass of the four units; never raises for a failing unit."""
    report = SweepReport()
    kube = _Kube(kube_factory)
    try:
        await _release_pins(pool, settings, orchestrator, report)
        await _collect_versions(pool, settings, kube, report)
        await _reap_writing(pool, settings, kube, report)
        await _purge(pool, report)
    finally:
        await kube.aclose()
    if report != SweepReport():
        log.info("sweeper pass: %s", report)
    return report


Sweep = Callable[..., Awaitable[SweepReport]]


async def run_sweeper(
    pool: AsyncConnectionPool,
    settings: Settings,
    orchestrator: OrchestratorClient,
    kube_factory: KubeFactory,
    stop: asyncio.Event,
    *,
    sweep: Sweep = sweep_once,
) -> None:
    """Sweep, then wait `sweeper_interval_seconds` or `stop`; until `stop` is set."""
    while not stop.is_set():
        try:
            await sweep(pool, settings, orchestrator, kube_factory)
        except Exception as exc:
            log.warning("sweeper pass failed: %s", type(exc).__name__)
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=settings.sweeper_interval_seconds)


async def run_singleton(
    pool: AsyncConnectionPool,
    settings: Settings,
    orchestrator: OrchestratorClient,
    kube_factory: KubeFactory,
    stop: asyncio.Event,
    *,
    sweep: Sweep = sweep_once,
) -> None:
    """One sweeper cluster-wide: wait for the advisory lock, then run."""
    async with advisory_singleton(pool, LOCK_NAME):
        await run_sweeper(pool, settings, orchestrator, kube_factory, stop, sweep=sweep)


async def serve(settings: Settings, stop: asyncio.Event) -> None:
    """The `vault sweeper` process body."""
    pool = await open_pool(settings.database_url.get_secret_value(), min_size=2, max_size=4)
    orchestrator = make_client(settings)
    try:
        await run_singleton(pool, settings, orchestrator, LightkubeApi, stop)
    finally:
        await orchestrator.aclose()
        await pool.close()


def main(settings: Settings) -> int:
    """Run the sweeper until SIGTERM or SIGINT; the exit code."""
    logging.basicConfig(level=settings.log_level.upper(), force=True)
    return asyncio.run(
        run_service(
            lambda stop: serve(settings, stop), grace_seconds=settings.shutdown_grace_seconds
        )
    )
