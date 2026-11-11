"""Service listener routes (spec 4.2): used only by the orchestrator, behind the bearer gate.
Nothing here creates, rotates, edits or deletes an entry. A preset env refers to one env of an
entry by entry id; protected envs come back as Secret refs, readable envs as their values. No
route returns a protected value."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from agents_common.labels import labels_match, normalize_labels
from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agents_vault import store
from agents_vault.api.entries import _index, _mapped
from agents_vault.api.errors import ApiError
from agents_vault.api.schemas import EnvView, env_views
from agents_vault.db import entries as entries_repo
from agents_vault.db import events as events_repo
from agents_vault.db import pins as pins_repo
from agents_vault.k8s import secret_name

ACTOR = "orchestrator"
REFS_MAX = 100

_PRESET_ENV = re.compile(r"[A-Z_][A-Z0-9_]*")
_ENV = re.compile(r"[A-Z_][A-Z0-9_]{0,127}")

router = APIRouter()


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RefIn(_Strict):
    entry: uuid.UUID
    env: str

    @field_validator("env")
    @classmethod
    def _env(cls, env: str) -> str:
        if not _ENV.fullmatch(env):
            raise ValueError("entry env names must match [A-Z_][A-Z0-9_]{0,127}")
        return env


def _check_refs(refs: dict[str, RefIn]) -> dict[str, RefIn]:
    if len(refs) > REFS_MAX:
        raise ValueError(f"at most {REFS_MAX} refs are allowed")
    for env in refs:
        if not _PRESET_ENV.fullmatch(env):
            raise ValueError("preset env names must match [A-Z_][A-Z0-9_]*")
    return refs


class ResolveIn(_Strict):
    preset_labels: list[str] = Field(
        default=[],
        description="The preset's labels plus one project: label per project of the scope"
        " (home and extra projects, at most 20 labels in all); an entry with project: labels"
        " matches when one of them is in the scope.",
    )
    refs: dict[str, RefIn]

    _refs = field_validator("refs")(_check_refs)


class PinsIn(ResolveIn):
    session_id: uuid.UUID


class AttachmentRef(BaseModel):
    preset_id: str
    preset_name: str
    env: str
    entry_env: str


class EntrySummary(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    labels: list[str]
    envs: list[EnvView]
    version: int
    updated_at: datetime
    attachments: list[AttachmentRef] | None


class Resolved(BaseModel):
    entry: uuid.UUID
    name: str
    env: str
    protected: bool
    labels: list[str]
    version: int
    matches: bool


class ResolveOut(BaseModel):
    resolved: dict[str, Resolved]
    unknown: list[str]
    bad_env: list[str]
    mismatched: list[str]


class PinOut(BaseModel):
    secret: str
    key: str
    version: int


class PinsOut(BaseModel):
    pins: dict[str, PinOut]
    values: dict[str, str]


def _preset_labels(raw: list[str]) -> list[str]:
    """Preset labels follow the orchestrator's grammar only; the `project:` slug rule is for
    entry labels, so a preset label such as `project:a_b` is matched literally. The labels carry
    one `project:` label per project of the caller's scope (home plus extra projects); an entry
    matches when one of its `project:` labels is in that scope."""
    with _mapped():
        return normalize_labels(raw)


class _Classified:
    """Each preset env of the refs sorted into found (entry row and env row), unknown entry,
    unknown env (bad_env) or label mismatch; the three lists hold preset env names."""

    def __init__(
        self,
        refs: dict[str, RefIn],
        rows: list[dict[str, Any]],
        envs: list[dict[str, Any]],
        preset_labels: list[str],
    ) -> None:
        by_id = {r["id"]: r for r in rows}
        env_rows = {(e["entry_id"], e["env"]): e for e in envs}
        self.found: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
        self.unknown: list[str] = []
        self.bad_env: list[str] = []
        for preset_env in sorted(refs):
            ref = refs[preset_env]
            row = by_id.get(ref.entry)
            if row is None:
                self.unknown.append(preset_env)
            elif (ref.entry, ref.env) not in env_rows:
                self.bad_env.append(preset_env)
            else:
                self.found[preset_env] = (row, env_rows[(ref.entry, ref.env)])
        self.mismatched = [
            env
            for env, (row, _) in self.found.items()
            if not labels_match(row["labels"], preset_labels)
        ]
        self.unknown_entries = sorted({str(refs[e].entry) for e in self.unknown})


def _entry_ids(refs: dict[str, RefIn]) -> list[uuid.UUID]:
    return sorted({ref.entry for ref in refs.values()})


@router.get("/entries", response_model=list[EntrySummary])
async def entries_summary(
    request: Request, q: str | None = None, name: str | None = None
) -> list[EntrySummary]:
    rows = await store.list_entries(request.app.state.pool, q, name=name)
    attached = await _index(request).by_entry()
    return [
        EntrySummary(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            labels=row["labels"],
            envs=env_views(row),
            version=row["current_version"],
            updated_at=row["updated_at"],
            attachments=None
            if attached is None
            else [
                AttachmentRef(
                    preset_id=a.preset_id,
                    preset_name=a.preset_name,
                    env=a.env,
                    entry_env=a.entry_env,
                )
                for a in attached.get(str(row["id"]), [])
            ],
        )
        for row in rows
    ]


@router.post("/entries/resolve", response_model=ResolveOut)
async def resolve(request: Request, body: ResolveIn) -> ResolveOut:
    preset_labels = _preset_labels(body.preset_labels)
    ids = _entry_ids(body.refs)
    async with request.app.state.pool.connection() as conn:
        rows = await entries_repo.live_by_ids(conn, ids)
        envs = await entries_repo.envs_of(conn, ids)
    got = _Classified(body.refs, rows, envs, preset_labels)
    return ResolveOut(
        resolved={
            preset_env: Resolved(
                entry=row["id"],
                name=row["name"],
                env=env["env"],
                protected=env["protected"],
                labels=row["labels"],
                version=row["current_version"],
                matches=preset_env not in got.mismatched,
            )
            for preset_env, (row, env) in got.found.items()
        },
        unknown=got.unknown,
        bad_env=got.bad_env,
        mismatched=got.mismatched,
    )


def _pins_out(items: list[tuple[str, uuid.UUID, str, int, bool, str | None]]) -> PinsOut:
    """(preset env, entry id, entry env, version, protected, readable value) -> the answer."""
    pins: dict[str, PinOut] = {}
    values: dict[str, str] = {}
    for preset_env, entry_id, entry_env, version, protected, value in items:
        if protected:
            pins[preset_env] = PinOut(
                secret=secret_name(entry_id, version), key=entry_env, version=version
            )
        else:
            values[preset_env] = value or ""
    return PinsOut(pins=pins, values=values)


@router.post("/pins", response_model=PinsOut)
async def create_pins(request: Request, body: PinsIn) -> PinsOut:
    preset_labels = _preset_labels(body.preset_labels)
    session_id = body.session_id
    async with request.app.state.pool.connection() as conn, conn.transaction():
        await pins_repo.lock_session(conn, session_id)
        existing = await pins_repo.session_pins(conn, session_id)
        if existing:
            # idempotent: the first call wins and the body of a retry is ignored; a readable
            # env answers its current value (readable values are not versioned)
            return _pins_out(
                [
                    (
                        r["env"],
                        r["entry_id"],
                        r["entry_env"],
                        r["version"],
                        r["protected"],
                        r["value"],
                    )
                    for r in existing
                ]
            )
        ids = _entry_ids(body.refs)
        rows = await pins_repo.share_lock_live_entries(conn, ids)
        envs = await entries_repo.envs_of(conn, ids)
        got = _Classified(body.refs, rows, envs, preset_labels)
        if got.unknown:
            raise ApiError(
                422,
                "vault_entry_unknown",
                "some entries do not exist",
                {"envs": got.unknown, "entries": got.unknown_entries},
            )
        if got.bad_env:
            raise ApiError(
                422, "vault_env_unknown", "some entries have no such env", {"envs": got.bad_env}
            )
        if got.mismatched:
            raise ApiError(
                422,
                "vault_label_mismatch",
                "some entries do not match the preset labels",
                {"envs": got.mismatched},
            )
        items = []
        for preset_env, (row, env) in got.found.items():
            version = row["current_version"]
            await pins_repo.insert_pin(conn, session_id, preset_env, row["id"], env["env"], version)
            items.append(
                (preset_env, row["id"], env["env"], version, env["protected"], env["value"])
            )
        found = sorted(got.found)
        await events_repo.add_event(
            conn,
            "pins_created",
            ACTOR,
            None,
            None,
            {
                "session_id": str(session_id),
                "envs": found,
                "entries": [str(got.found[e][0]["id"]) for e in found],
                "names": [got.found[e][0]["name"] for e in found],
                "entry_envs": [got.found[e][1]["env"] for e in found],
                "versions": [got.found[e][0]["current_version"] for e in found],
            },
        )
        return _pins_out(items)


@router.delete("/pins/{session_id}", status_code=204)
async def release_pins(request: Request, session_id: uuid.UUID) -> Response:
    async with request.app.state.pool.connection() as conn, conn.transaction():
        if await pins_repo.release_session(conn, session_id):
            await events_repo.add_event(
                conn,
                "pins_released",
                ACTOR,
                None,
                None,
                {"session_id": str(session_id), "reason": "orchestrator"},
            )
    return Response(status_code=204)
