"""In-memory KubeApi that behaves like the vault's production Role.

- The Role grants Secrets in `namespace` only the verbs `patch` (apply) and `delete`. Every
  other call raises Forbidden and is recorded in `forbidden`, so a test can assert none were
  made even when the caller swallowed the error. `get`, `list` and `watch` are not part of
  the KubeApi protocol on purpose: the vault never reads a Secret, and a Secret's data is
  write-only for this fake (stored objects drop `stringData`).
- Applying over an existing immutable Secret raises KubeError("field is immutable"), which
  proves the delete-first step of `write_secret`.
- `fail(kind, name)` injects an error for one object; `apply_gate` lets a test hold an apply.
"""

from __future__ import annotations

import asyncio
import copy
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agents_vault.k8s import FIELD_MANAGER, Forbidden, KubeError

READ_VERBS = frozenset({"get", "list", "watch"})


@dataclass(frozen=True)
class Call:
    verb: str
    kind: str
    namespace: str
    name: str | None = None


@dataclass(frozen=True)
class Apply:
    obj: dict[str, Any]
    field_manager: str
    force: bool

    @property
    def kind(self) -> str:
        return self.obj["kind"]

    @property
    def name(self) -> str:
        return self.obj["metadata"]["name"]


@dataclass
class _Failure:
    exc: Exception
    verbs: frozenset[str] | None
    times: int | None


@dataclass
class FakeKube:
    namespace: str = "agents"
    objects: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    applies: list[Apply] = field(default_factory=list)
    deletes: list[tuple[str, str, str]] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    forbidden: list[Call] = field(default_factory=list)
    # name -> (entered, release): the apply of that Secret sets `entered` then awaits `release`
    apply_gate: dict[str, tuple[asyncio.Event, asyncio.Event]] = field(default_factory=dict)
    _failures: dict[tuple[str, str], _Failure] = field(default_factory=dict)

    def fail(
        self,
        kind: str,
        name: str,
        exc: Exception | None = None,
        *,
        verbs: Iterable[str] | None = None,
        times: int | None = None,
    ) -> None:
        """Make calls on one object raise `exc` (all verbs unless `verbs`; `times` then heal)."""
        self._failures[(kind, name)] = _Failure(
            exc or KubeError(f"injected failure for {kind}/{name}"),
            frozenset(verbs) if verbs is not None else None,
            times,
        )

    def heal(self, kind: str, name: str) -> None:
        self._failures.pop((kind, name), None)

    def has(self, kind: str, name: str, namespace: str | None = None) -> bool:
        return (kind, namespace or self.namespace, name) in self.objects

    def get(self, kind: str, name: str, namespace: str | None = None) -> dict[str, Any]:
        return self.objects[(kind, namespace or self.namespace, name)]

    def names(self, kind: str) -> list[str]:
        return sorted(n for (k, ns, n) in self.objects if k == kind and ns == self.namespace)

    def applied(self, kind: str | None = None) -> list[Apply]:
        return [a for a in self.applies if kind is None or a.kind == kind]

    def deleted(self, kind: str | None = None) -> list[str]:
        return [n for (k, _ns, n) in self.deletes if kind is None or k == kind]

    def reset_records(self) -> None:
        self.applies.clear()
        self.deletes.clear()
        self.calls.clear()
        self.forbidden.clear()

    def _check(self, verb: str, kind: str, namespace: str, name: str | None = None) -> None:
        call = Call(verb, kind, namespace, name)
        self.calls.append(call)
        if kind != "Secret" or namespace != self.namespace or verb in READ_VERBS:
            self.forbidden.append(call)
            raise Forbidden(f"{verb} {kind} in namespace {namespace!r} is outside the Role")
        if name is not None:
            failure = self._failures.get((kind, name))
            if failure is not None and (failure.verbs is None or verb in failure.verbs):
                if failure.times is not None:
                    failure.times -= 1
                    if failure.times <= 0:
                        self.heal(kind, name)
                raise failure.exc

    async def apply(self, obj: dict[str, Any]) -> dict[str, Any]:
        meta = obj["metadata"]
        namespace = meta.get("namespace", "")
        self._check("patch", obj["kind"], namespace, meta["name"])
        gate = self.apply_gate.get(meta["name"])
        if gate is not None:
            entered, release = gate
            entered.set()
            await release.wait()
        key = (obj["kind"], namespace, meta["name"])
        if key in self.objects and self.objects[key].get("immutable"):
            raise KubeError("field is immutable")
        stored = copy.deepcopy(obj)
        stored.pop("stringData", None)  # a Secret's data is write-only for this fake
        self.applies.append(Apply(copy.deepcopy(obj), FIELD_MANAGER, True))
        self.objects[key] = stored
        return copy.deepcopy(stored)

    async def delete(self, kind: str, namespace: str, name: str) -> bool:
        self._check("delete", kind, namespace, name)
        if self.objects.pop((kind, namespace, name), None) is None:
            return False
        self.deletes.append((kind, namespace, name))
        return True

    async def aclose(self) -> None:
        return None

    # The Role has no read verbs; these exist so a test (or a bug) calling them is recorded.
    async def get_object(self, kind: str, namespace: str, name: str) -> None:
        self._check("get", kind, namespace, name)

    async def list_objects(self, kind: str, namespace: str) -> None:
        self._check("list", kind, namespace)


class FlakyKube(FakeKube):
    """The apply lands server-side but reports an error; deletes fail while `block_delete`."""

    block_delete = False
    land_then_fail = False

    async def apply(self, obj):
        result = await super().apply(obj)
        if self.land_then_fail:
            raise KubeError("timeout after the write landed")
        return result

    async def delete(self, kind, namespace, name):
        if self.block_delete:
            raise KubeError("delete failed")
        return await super().delete(kind, namespace, name)
