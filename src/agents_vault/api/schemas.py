"""Request and response models of the web routes. Every value is a SecretStr in requests; a
response carries only readable env values, never a protected one."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, SecretStr, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnvIn(_Strict):
    env: str
    protected: bool
    value: SecretStr


class EntryIn(_Strict):
    name: str
    description: str
    labels: list[str] = []
    envs: list[EnvIn]


class EntryPatch(_Strict):
    name: str | None = None
    description: str | None = None
    labels: list[str] | None = None
    envs: dict[str, SecretStr] | None = None

    @model_validator(mode="after")
    def _something(self) -> EntryPatch:
        if (self.name, self.description, self.labels, self.envs) == (None, None, None, None):
            raise ValueError("give name, description, labels or envs")
        return self


class ValuesIn(_Strict):
    values: dict[str, SecretStr]


class EnvView(BaseModel):
    env: str
    protected: bool
    value: str | None
    updated_at: datetime


class EntryView(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    labels: list[str]
    envs: list[EnvView]
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
    entry_env: str
    preset_labels: list[str]
    matches: bool


class EntryDetail(EntryView):
    versions: list[VersionView]
    attachments: list[AttachmentView] | None
    mismatched_attachments: list[AttachmentView] | None


class PinView(BaseModel):
    session_id: uuid.UUID
    env: str
    entry_env: str
    version: int
    created_at: datetime


class EventView(BaseModel):
    id: int
    ts: datetime
    kind: str
    actor: str
    entry_id: uuid.UUID | None
    entry_name: str | None
    data: dict[str, Any]


def env_views(entry: dict[str, Any]) -> list[EnvView]:
    """The entry's envs; a protected env has no value (none is stored)."""
    return [
        EnvView(
            env=e["env"], protected=e["protected"], value=e["value"], updated_at=e["updated_at"]
        )
        for e in entry["envs"]
    ]
