"""Web listener routes (spec 4.1): the user-facing entry API. Entries are addressed by id. No
route returns a protected value; readable env values are part of the views."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Annotated, Any

from agents_common.labels import labels_match
from fastapi import APIRouter, Query, Request, Response

from agents_vault import store
from agents_vault.api.errors import ApiError
from agents_vault.api.schemas import (
    AttachmentView,
    EntryDetail,
    EntryIn,
    EntryPatch,
    EntryView,
    EventView,
    PinView,
    ValuesIn,
    VersionView,
    env_views,
)
from agents_vault.attachments import Attachment, AttachmentIndex
from agents_vault.k8s import KubeApi, LightkubeApi
from agents_vault.orchestrator import make_client

log = logging.getLogger(__name__)

ACTOR = "user"
ACTOR_MAX = 200
PROJECT_PREFIX = "project:"

router = APIRouter()


@contextmanager
def _mapped() -> Iterator[None]:
    """Store errors as API errors. Messages are fixed text, env names or label text, never a
    value."""
    try:
        yield
    except store.NameTaken as exc:
        raise ApiError(409, "vault_name_taken", str(exc)) from None
    except store.SecretTooLarge as exc:
        raise ApiError(413, "secret_too_large", str(exc)) from None
    except store.SecretStoreFailed as exc:
        raise ApiError(502, "secret_store_failed", str(exc)) from None
    except store.EntryNotFound:
        raise ApiError(404, "not_found", "no such entry") from None
    except store.EnvsMismatch as exc:
        raise ApiError(
            422, "vault_envs_mismatch", str(exc), {"missing": exc.missing, "extra": exc.extra}
        ) from None
    except store.NothingToRotate as exc:
        raise ApiError(422, "vault_nothing_to_rotate", str(exc)) from None
    except store.EnvProtected as exc:
        raise ApiError(422, "vault_env_protected", str(exc), {"envs": exc.envs}) from None
    except store.EnvUnknown as exc:
        raise ApiError(422, "vault_env_unknown", str(exc), {"envs": exc.envs}) from None
    except ValueError as exc:
        raise ApiError(422, "invalid_request", str(exc)) from None


def actor_of(request: Request) -> str:
    """The audit actor: `user:<email>` from the identity headers of the loopback-only SSO
    sidecar (the web listener serves allowlisted peers only), else `user`. Control characters
    and over-long values are dropped."""
    for header in ("x-forwarded-email", "x-forwarded-user"):
        who = request.headers.get(header, "").strip()
        if who and len(who) <= ACTOR_MAX and who.isprintable():
            return f"{ACTOR}:{who}"
    return ACTOR


def _kube(request: Request) -> KubeApi:
    state = request.app.state
    if getattr(state, "kube", None) is None:
        state.kube = state.kube_factory() if state.kube_factory is not None else LightkubeApi()
    return state.kube


def _index(request: Request) -> AttachmentIndex:
    state = request.app.state
    if getattr(state, "attachments", None) is None:
        if state.orchestrator is None:
            state.orchestrator = make_client(state.settings)
        state.attachments = AttachmentIndex(state.orchestrator.list_presets)
    return state.attachments


def _attachment_ref(a: Attachment) -> dict[str, str]:
    return {
        "preset_id": a.preset_id,
        "preset_name": a.preset_name,
        "env": a.env,
        "entry_env": a.entry_env,
    }


def _attachment_view(att: Attachment, entry_labels: list[str]) -> AttachmentView:
    return AttachmentView(
        preset_id=att.preset_id,
        preset_name=att.preset_name,
        env=att.env,
        entry_env=att.entry_env,
        preset_labels=att.preset_labels,
        matches=labels_match(entry_labels, att.preset_labels),
    )


async def _view(
    request: Request, entry: dict[str, Any], attached: dict[str, list[Attachment]] | None
) -> EntryView:
    pool = request.app.state.pool
    return EntryView(
        id=entry["id"],
        name=entry["name"],
        description=entry["description"],
        labels=entry["labels"],
        envs=env_views(entry),
        version=entry["current_version"],
        created_at=entry["created_at"],
        updated_at=entry["updated_at"],
        attachments_count=None if attached is None else len(attached.get(str(entry["id"]), [])),
        pinned_sessions_count=await store.pinned_sessions_count(pool, entry["id"]),
        behind_count=await store.behind_count(pool, entry["id"]),
    )


async def _detail(request: Request, entry: dict[str, Any]) -> EntryDetail:
    attached = await _index(request).by_entry()
    view = await _view(request, entry, attached)
    versions = await store.entry_versions(request.app.state.pool, entry["id"])
    attachments = mismatched = None
    if attached is not None:
        attachments = [
            _attachment_view(a, entry["labels"]) for a in attached.get(str(entry["id"]), [])
        ]
        mismatched = [a for a in attachments if not a.matches]
    return EntryDetail(
        **view.model_dump(),
        versions=[VersionView(**{k: v[k] for k in VersionView.model_fields}) for v in versions],
        attachments=attachments,
        mismatched_attachments=mismatched,
    )


async def _live(request: Request, entry_id: uuid.UUID) -> dict[str, Any]:
    entry = await store.get_entry(request.app.state.pool, entry_id)
    if entry is None:
        raise ApiError(404, "not_found", "no such entry")
    return entry


@router.get("/entries", response_model=list[EntryView])
async def list_entries(
    request: Request, q: str | None = None, label: Annotated[list[str] | None, Query()] = None
) -> list[EntryView]:
    with _mapped():
        rows = await store.list_entries(request.app.state.pool, q, label or [])
    attached = await _index(request).by_entry()
    return [await _view(request, row, attached) for row in rows]


@router.post("/entries", status_code=201, response_model=EntryView)
async def create_entry(request: Request, body: EntryIn) -> EntryView:
    settings = request.app.state.settings
    with _mapped():
        entry_id = await store.create_entry(
            request.app.state.pool,
            _kube(request),
            settings.namespace,
            actor_of(request),
            name=body.name,
            description=body.description,
            labels=body.labels,
            envs=[store.EnvIn(e.env, e.protected, e.value) for e in body.envs],
            max_value_bytes=settings.max_value_bytes,
        )
    return await _view(request, await _live(request, entry_id), await _index(request).by_entry())


@router.get("/entries/{entry_id}", response_model=EntryDetail)
async def get_entry(request: Request, entry_id: uuid.UUID) -> EntryDetail:
    return await _detail(request, await _live(request, entry_id))


def _projects(labels: list[str]) -> set[str]:
    return {label for label in labels if label.startswith(PROJECT_PREFIX)}


async def _guard_scope_change(request: Request, entry_id: uuid.UUID, labels: list[str]) -> None:
    """Changing or dropping a `project:` label of an attached entry needs `force=true`."""
    entry = await _live(request, entry_id)
    with _mapped():
        new = _projects(store.clean_labels(labels))
    if new == _projects(entry["labels"]):
        return
    attached = await _index(request).by_entry(fresh=True)
    if attached is None:
        raise ApiError(
            503, "orchestrator_unavailable", "attachments cannot be checked, nothing was changed"
        )
    refs = attached.get(str(entry_id), [])
    if refs:
        raise ApiError(
            409,
            "vault_entry_attached",
            "the entry is referenced by presets, its project scope needs force=true to change",
            {"attachments": [_attachment_ref(a) for a in refs]},
        )


@router.patch("/entries/{entry_id}", response_model=EntryDetail)
async def patch_entry(
    request: Request,
    entry_id: uuid.UUID,
    body: EntryPatch,
    force: Annotated[bool, Query()] = False,
) -> EntryDetail:
    if body.labels is not None and not force:
        await _guard_scope_change(request, entry_id, body.labels)
    with _mapped():
        await store.update_entry(
            request.app.state.pool,
            actor_of(request),
            entry_id=entry_id,
            name=body.name,
            description=body.description,
            labels=body.labels,
            envs=body.envs,
        )
    return await _detail(request, await _live(request, entry_id))


@router.put("/entries/{entry_id}/value", response_model=EntryView)
async def rotate_entry(request: Request, entry_id: uuid.UUID, body: ValuesIn) -> EntryView:
    settings = request.app.state.settings
    with _mapped():
        await store.rotate_entry(
            request.app.state.pool,
            _kube(request),
            settings.namespace,
            actor_of(request),
            entry_id=entry_id,
            values=body.values,
            max_value_bytes=settings.max_value_bytes,
        )
    return await _view(request, await _live(request, entry_id), await _index(request).by_entry())


@router.delete("/entries/{entry_id}", status_code=204)
async def delete_entry(request: Request, entry_id: uuid.UUID) -> Response:
    await _live(request, entry_id)
    # fresh read: a cached answer could miss a ref attached seconds ago
    attached = await _index(request).by_entry(fresh=True)
    if attached is None:
        raise ApiError(
            503, "orchestrator_unavailable", "attachments cannot be checked, nothing was deleted"
        )
    refs = attached.get(str(entry_id), [])
    if refs:
        raise ApiError(
            409,
            "vault_entry_attached",
            "the entry is referenced by presets",
            {"attachments": [_attachment_ref(a) for a in refs]},
        )
    with _mapped():
        await store.delete_entry(request.app.state.pool, actor_of(request), entry_id=entry_id)
    return Response(status_code=204)


@router.get("/entries/{entry_id}/pins", response_model=list[PinView])
async def entry_pins(request: Request, entry_id: uuid.UUID) -> list[PinView]:
    entry = await _live(request, entry_id)
    rows = await store.live_pins(request.app.state.pool, entry["id"])
    return [PinView(**{k: r[k] for k in PinView.model_fields}) for r in rows]


@router.get("/events", response_model=list[EventView])
async def events(
    request: Request,
    entry: uuid.UUID | None = None,
    before_id: int | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[EventView]:
    rows = await store.list_events(request.app.state.pool, entry, before_id, limit)
    return [EventView(**{k: r[k] for k in EventView.model_fields}) for r in rows]
