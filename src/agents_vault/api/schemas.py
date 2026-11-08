"""Request and response models of the web routes. A value is a SecretStr in requests and is
not a field of any response."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, SecretStr, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EntryIn(_Strict):
    name: str
    description: str
    labels: list[str] = []
    value: SecretStr


class EntryPatch(_Strict):
    description: str | None = None
    labels: list[str] | None = None

    @model_validator(mode="after")
    def _something(self) -> EntryPatch:
        if self.description is None and self.labels is None:
            raise ValueError("give description or labels")
        return self


class ValueIn(_Strict):
    value: SecretStr


class EntryView(BaseModel):
    name: str
    description: str
    labels: list[str]
    version: int
    created_at: datetime
    updated_at: datetime
    attachments_count: int | None
    pinned_sessions_count: int
    behind_count: int


class VersionView(BaseModel):
    version: int
    state: str
    created_at: datetime
    retired_at: datetime | None
    pins: int


class AttachmentView(BaseModel):
    preset_id: str
    preset_name: str
    env: str
    preset_labels: list[str]
    matches: bool


class EntryDetail(EntryView):
    versions: list[VersionView]
    attachments: list[AttachmentView] | None
    mismatched_attachments: list[AttachmentView] | None


class PinView(BaseModel):
    session_id: uuid.UUID
    env: str
    version: int
    created_at: datetime


class EventView(BaseModel):
    id: int
    ts: datetime
    kind: str
    actor: str
    entry_name: str | None
    data: dict[str, Any]
