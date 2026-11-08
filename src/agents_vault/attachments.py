"""Which presets reference which vault entries, read from the orchestrator (spec 4.1).

A preset env references one env of an entry with a value `{"vault": "<entry uuid>", "env": "ENV"}`;
attachments are keyed by the entry id (canonical uuid text) and name the entry env they read.
A ref whose `vault` is not a uuid or whose `env` is not a string matches no entry. Nothing is
stored here: the answer is computed from `GET /api/v1/presets` and cached for
`ATTACHMENTS_TTL_SECONDS`. `None` means the orchestrator could not be asked (unreachable or any
error, a 401 included): callers show unknown attachments and `DELETE` refuses.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from agents_common.orchestrator import OrchestratorError, OrchestratorUnavailable, Preset

log = logging.getLogger(__name__)

ATTACHMENTS_TTL_SECONDS = 15


@dataclass(frozen=True)
class Attachment:
    preset_id: str
    preset_name: str
    env: str
    entry_env: str
    preset_labels: list[str] = field(default_factory=list)


def _entry_id(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    try:
        return str(uuid.UUID(raw))
    except ValueError:
        return None


def _refs(spec: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(preset env, entry id, entry env) for every vault ref in the preset's `env`."""
    env = spec.get("env")
    if isinstance(env, dict):
        items = list(env.items())
    elif isinstance(env, list):
        items = [(item.get("name"), item.get("value")) for item in env if isinstance(item, dict)]
    else:
        return []
    found = []
    for key, value in items:
        if not (isinstance(key, str) and isinstance(value, dict)):
            continue
        entry_id = _entry_id(value.get("vault"))
        if entry_id is not None and isinstance(value.get("env"), str):
            found.append((key, entry_id, value["env"]))
    return found


def index_presets(presets: list[Preset]) -> dict[str, list[Attachment]]:
    by_entry: dict[str, list[Attachment]] = {}
    for preset in presets:
        for env, entry_id, entry_env in _refs(preset.spec):
            by_entry.setdefault(entry_id, []).append(
                Attachment(str(preset.id), preset.name, env, entry_env, list(preset.labels))
            )
    return by_entry


class AttachmentIndex:
    def __init__(
        self,
        list_presets: Callable[[], Awaitable[list[Preset]]],
        *,
        ttl: float = ATTACHMENTS_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._list_presets = list_presets
        self._ttl = ttl
        self._clock = clock
        self._cached: dict[str, list[Attachment]] | None = None
        self._at = 0.0
        self._lock = asyncio.Lock()

    async def by_entry(self, fresh: bool = False) -> dict[str, list[Attachment]] | None:
        """Attachments by entry id, or None when the orchestrator cannot be asked. A failure
        is never cached."""
        async with self._lock:
            if not fresh and self._cached is not None and self._clock() - self._at < self._ttl:
                return self._cached
            try:
                presets = await self._list_presets()
            except (OrchestratorUnavailable, OrchestratorError, ValueError) as exc:
                # ValueError: a 200 whose body is not JSON or has the wrong shape
                log.warning("attachments unknown: %s", type(exc).__name__)
                self._cached = None
                return None
            self._cached = index_presets(presets)
            self._at = self._clock()
            return self._cached
