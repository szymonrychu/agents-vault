"""Web listener routes (spec 4.1): the user-facing entry API. No route returns a value."""

from __future__ import annotations

import logging
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
    ValueIn,
    VersionView,
)
from agents_vault.attachments import Attachment, AttachmentIndex
from agents_vault.k8s import KubeApi, LightkubeApi
from agents_vault.orchestrator import make_client

log = logging.getLogger(__name__)

ACTOR = "user"

router = APIRouter()


@contextmanager
def _mapped() -> Iterator[None]:
    """Store errors as API errors. Messages are fixed text or label text, never a value."""
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
    except ValueError as exc:
        raise ApiError(422, "invalid_request", str(exc)) from None


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


def _attachment_view(att: Attachment, entry_labels: list[str]) -> AttachmentView:
    return AttachmentView(
        preset_id=att.preset_id,
        preset_name=att.preset_name,
        env=att.env,
        preset_labels=att.preset_labels,
        matches=labels_match(entry_labels, att.preset_labels),
    )


async def _view(
    request: Request, entry: dict[str, Any], attached: dict[str, list[Attachment]] | None
) -> EntryView:
    pool = request.app.state.pool
    return EntryView(
        name=entry["name"],
        description=entry["description"],
        labels=entry["labels"],
        version=entry["current_version"],
        created_at=entry["created_at"],
        updated_at=entry["updated_at"],
        attachments_count=None if attached is None else len(attached.get(entry["name"], [])),
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
            _attachment_view(a, entry["labels"]) for a in attached.get(entry["name"], [])
        ]
        mismatched = [a for a in attachments if not a.matches]
    return EntryDetail(
        **view.model_dump(),
        versions=[VersionView(**{k: v[k] for k in VersionView.model_fields}) for v in versions],
        attachments=attachments,
        mismatched_attachments=mismatched,
    )


async def _live(request: Request, name: str) -> dict[str, Any]:
    entry = await store.get_entry(request.app.state.pool, name)
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
        await store.create_entry(
            request.app.state.pool,
            _kube(request),
            settings.namespace,
            ACTOR,
            name=body.name,
            description=body.description,
            labels=body.labels,
            value=body.value,
            max_value_bytes=settings.max_value_bytes,
        )
    return await _view(request, await _live(request, body.name), await _index(request).by_entry())


@router.get("/entries/{name}", response_model=EntryDetail)
async def get_entry(request: Request, name: str) -> EntryDetail:
    return await _detail(request, await _live(request, name))


@router.patch("/entries/{name}", response_model=EntryDetail)
async def patch_entry(request: Request, name: str, body: EntryPatch) -> EntryDetail:
    with _mapped():
        await store.update_entry(
            request.app.state.pool,
            ACTOR,
            name=name,
            description=body.description,
            labels=body.labels,
        )
    return await _detail(request, await _live(request, name))


@router.put("/entries/{name}/value", response_model=EntryView)
async def rotate_entry(request: Request, name: str, body: ValueIn) -> EntryView:
    settings = request.app.state.settings
    with _mapped():
        await store.rotate_entry(
            request.app.state.pool,
            _kube(request),
            settings.namespace,
            ACTOR,
            name=name,
            value=body.value,
            max_value_bytes=settings.max_value_bytes,
        )
    return await _view(request, await _live(request, name), await _index(request).by_entry())


@router.delete("/entries/{name}", status_code=204)
async def delete_entry(request: Request, name: str) -> Response:
    await _live(request, name)
    # fresh read: a cached answer could miss a ref attached seconds ago
    attached = await _index(request).by_entry(fresh=True)
    if attached is None:
        raise ApiError(
            503, "orchestrator_unavailable", "attachments cannot be checked, nothing was deleted"
        )
    refs = attached.get(name, [])
    if refs:
        raise ApiError(
            409,
            "vault_entry_attached",
            "the entry is referenced by presets",
            {
                "attachments": [
                    {"preset_id": a.preset_id, "preset_name": a.preset_name, "env": a.env}
                    for a in refs
                ]
            },
        )
    with _mapped():
        await store.delete_entry(request.app.state.pool, ACTOR, name=name)
    return Response(status_code=204)


@router.get("/entries/{name}/pins", response_model=list[PinView])
async def entry_pins(request: Request, name: str) -> list[PinView]:
    entry = await _live(request, name)
    rows = await store.live_pins(request.app.state.pool, entry["id"])
    return [PinView(**{k: r[k] for k in PinView.model_fields}) for r in rows]


@router.get("/events", response_model=list[EventView])
async def events(
    request: Request,
    entry: str | None = None,
    before_id: int | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[EventView]:
    rows = await store.list_events(request.app.state.pool, entry, before_id, limit)
    return [EventView(**{k: r[k] for k in EventView.model_fields}) for r in rows]
