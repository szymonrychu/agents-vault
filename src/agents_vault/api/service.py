"""Service listener routes (spec 4.2): used only by the orchestrator, behind the bearer gate.
Nothing here creates, rotates, edits or deletes an entry, and no route returns a value."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from agents_common.labels import labels_match, normalize_labels
from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, field_validator

from agents_vault import store
from agents_vault.api.entries import _index, _mapped
from agents_vault.api.errors import ApiError
from agents_vault.db import entries as entries_repo
from agents_vault.db import events as events_repo
from agents_vault.db import pins as pins_repo
from agents_vault.k8s import secret_name

ACTOR = "orchestrator"
REFS_MAX = 50

_ENV = re.compile(r"[A-Z_][A-Z0-9_]*")
_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,127}")

router = APIRouter()


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _check_refs(refs: dict[str, str]) -> dict[str, str]:
    if len(refs) > REFS_MAX:
        raise ValueError(f"at most {REFS_MAX} refs are allowed")
    for env, name in refs.items():
        if not _ENV.fullmatch(env):
            raise ValueError("env names must match [A-Z_][A-Z0-9_]*")
        if not _NAME.fullmatch(name):
            raise ValueError("entry names must match [A-Z_][A-Z0-9_]{0,127}")
    return refs


class ResolveIn(_Strict):
    preset_labels: list[str] = []
    refs: dict[str, str]

    _refs = field_validator("refs")(_check_refs)


class PinsIn(ResolveIn):
    session_id: uuid.UUID


class AttachmentRef(BaseModel):
    preset_id: str
    preset_name: str
    env: str


class EntrySummary(BaseModel):
    name: str
    description: str
    labels: list[str]
    version: int
    updated_at: datetime
    attachments: list[AttachmentRef] | None


class Resolved(BaseModel):
    name: str
    labels: list[str]
    version: int
    matches: bool


class ResolveOut(BaseModel):
    resolved: dict[str, Resolved]
    unknown: list[str]
    mismatched: list[str]


class PinOut(BaseModel):
    secret: str
    name: str
    version: int


class PinsOut(BaseModel):
    pins: dict[str, PinOut]


def _preset_labels(raw: list[str]) -> list[str]:
    """Preset labels follow the orchestrator's grammar only; the `project:` slug rule is for
    entry labels, so a preset label such as `project:a_b` is matched literally."""
    with _mapped():
        return normalize_labels(raw)


def _classify(
    refs: dict[str, str], rows: list[dict[str, Any]], preset_labels: list[str]
) -> tuple[dict[str, dict[str, Any]], list[str], list[str]]:
    """(env -> live entry row, sorted unknown names, mismatched envs)."""
    by_name = {r["name"]: r for r in rows}
    found = {env: by_name[name] for env, name in refs.items() if name in by_name}
    unknown = sorted({name for name in refs.values() if name not in by_name})
    mismatched = [
        env for env, row in found.items() if not labels_match(row["labels"], preset_labels)
    ]
    return found, unknown, mismatched


@router.get("/entries", response_model=list[EntrySummary])
async def entries_summary(request: Request, q: str | None = None) -> list[EntrySummary]:
    rows = await store.list_entries(request.app.state.pool, q)
    attached = await _index(request).by_entry()
    return [
        EntrySummary(
            name=row["name"],
            description=row["description"],
            labels=row["labels"],
            version=row["current_version"],
            updated_at=row["updated_at"],
            attachments=None
            if attached is None
            else [
                AttachmentRef(preset_id=a.preset_id, preset_name=a.preset_name, env=a.env)
                for a in attached.get(row["name"], [])
            ],
        )
        for row in rows
    ]


@router.post("/entries/resolve", response_model=ResolveOut)
async def resolve(request: Request, body: ResolveIn) -> ResolveOut:
    preset_labels = _preset_labels(body.preset_labels)
    async with request.app.state.pool.connection() as conn:
        rows = await entries_repo.live_by_names(conn, sorted(set(body.refs.values())))
    found, unknown, mismatched = _classify(body.refs, rows, preset_labels)
    return ResolveOut(
        resolved={
            env: Resolved(
                name=row["name"],
                labels=row["labels"],
                version=row["current_version"],
                matches=env not in mismatched,
            )
            for env, row in found.items()
        },
        unknown=unknown,
        mismatched=mismatched,
    )


@router.post("/pins", response_model=PinsOut)
async def create_pins(request: Request, body: PinsIn) -> PinsOut:
    preset_labels = _preset_labels(body.preset_labels)
    session_id = body.session_id
    async with request.app.state.pool.connection() as conn, conn.transaction():
        await pins_repo.lock_session(conn, session_id)
        existing = await pins_repo.session_pins(conn, session_id)
        if existing:
            # idempotent: the first call wins and the body of a retry is ignored
            return PinsOut(
                pins={
                    r["env"]: PinOut(
                        secret=secret_name(r["entry_id"], r["version"]),
                        name=r["name"],
                        version=r["version"],
                    )
                    for r in existing
                }
            )
        rows = await pins_repo.share_lock_live_entries(conn, sorted(set(body.refs.values())))
        found, unknown, mismatched = _classify(body.refs, rows, preset_labels)
        if unknown:
            raise ApiError(
                422, "vault_entry_unknown", "some entries do not exist", {"names": unknown}
            )
        if mismatched:
            raise ApiError(
                422,
                "vault_label_mismatch",
                "some entries do not match the preset labels",
                {"envs": mismatched},
            )
        for env, row in found.items():
            await pins_repo.insert_pin(conn, session_id, env, row["id"], row["current_version"])
        await events_repo.add_event(
            conn,
            "pins_created",
            ACTOR,
            None,
            {
                "session_id": str(session_id),
                "envs": sorted(found),
                "names": [found[e]["name"] for e in sorted(found)],
                "versions": [found[e]["current_version"] for e in sorted(found)],
            },
        )
        return PinsOut(
            pins={
                env: PinOut(
                    secret=secret_name(row["id"], row["current_version"]),
                    name=row["name"],
                    version=row["current_version"],
                )
                for env, row in found.items()
            }
        )


@router.delete("/pins/{session_id}", status_code=204)
async def release_pins(request: Request, session_id: uuid.UUID) -> Response:
    async with request.app.state.pool.connection() as conn, conn.transaction():
        if await pins_repo.release_session(conn, session_id):
            await events_repo.add_event(
                conn,
                "pins_released",
                ACTOR,
                None,
                {"session_id": str(session_id), "reason": "orchestrator"},
            )
    return Response(status_code=204)
