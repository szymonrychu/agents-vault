"""The Kubernetes calls the vault makes: apply and delete one Secret by name, nothing else.

The Role grants Secrets only create, patch and delete, so a Secret is never read or listed:
it is applied and deleted by its deterministic name `vault-<entry uuid>-v<n>`, one data key per
protected env of the entry. A value is held as a `SecretStr` until it goes into `stringData`;
the apply response is dropped and no Kubernetes error body is ever logged.

`LightkubeApi` is the production implementation; `tests/fakes/fake_kube.py:FakeKube` is the
in-memory one that also enforces the Role.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterator, Mapping
from typing import Any, Protocol
from uuid import UUID

import httpx2
from lightkube import ApiError, AsyncClient, codecs
from lightkube.core.exceptions import LoadResourceError
from lightkube.resources.core_v1 import Secret
from pydantic import SecretStr

log = logging.getLogger(__name__)

FIELD_MANAGER = "agents-vault"
MANAGED_BY_LABEL = "app.kubernetes.io/managed-by"
MANAGED_BY = "agents-vault"
ENTRY_LABEL = "vault.agents.szymonrichert.pl/entry"

Obj = dict[str, Any]

RESOURCES: dict[str, Any] = {"Secret": Secret}


class KubeError(Exception):
    """A Kubernetes call failed. The message may carry an API body: never log it."""


class Forbidden(KubeError):
    """The vault's Role does not grant this call (HTTP 403)."""


class NotFound(KubeError):
    """The object does not exist (HTTP 404)."""


class KubeApi(Protocol):
    async def apply(self, obj: Obj) -> Obj:
        """Server-side apply `obj` into `obj.metadata.namespace`; returns the stored object."""
        ...

    async def delete(self, kind: str, namespace: str, name: str) -> bool:
        """Delete by name; False when it did not exist."""
        ...

    async def aclose(self) -> None: ...


def secret_name(entry_id: UUID, version: int) -> str:
    return f"vault-{entry_id}-v{version}"


def _resource(kind: str) -> Any:
    try:
        return RESOURCES[kind]
    except KeyError:
        raise KubeError(f"unsupported kind {kind!r}") from None


@contextlib.contextmanager
def _mapped() -> Iterator[None]:
    """Translate lightkube and transport errors into KubeError, Forbidden and NotFound."""
    try:
        yield
    except ApiError as exc:
        code = exc.status.code if exc.status is not None else None
        message = (exc.status.message if exc.status is not None else None) or str(exc)
        if code == 403:
            raise Forbidden(message) from exc
        if code == 404:
            raise NotFound(message) from exc
        raise KubeError(f"{code}: {message}") from exc
    except (httpx2.HTTPError, LoadResourceError) as exc:
        raise KubeError(str(exc)) from exc


class LightkubeApi:
    """KubeApi on the lightkube AsyncClient: in-cluster config, else the kubeconfig."""

    def __init__(self, client: AsyncClient | None = None) -> None:
        self.client = client if client is not None else AsyncClient(field_manager=FIELD_MANAGER)

    async def apply(self, obj: Obj) -> Obj:
        with _mapped():
            res = codecs.from_dict(obj)
            out = await self.client.apply(res, field_manager=FIELD_MANAGER, force=True)
        return out.to_dict()

    async def delete(self, kind: str, namespace: str, name: str) -> bool:
        res = _resource(kind)
        try:
            with _mapped():
                await self.client.delete(res, name, namespace=namespace)
        except NotFound:
            return False
        return True

    async def aclose(self) -> None:
        await self.client.close()


async def write_secret(
    kube: KubeApi, namespace: str, name: str, entry_id: UUID, data: Mapping[str, SecretStr]
) -> None:
    """Apply the immutable Secret `name` holding `data` (env name -> protected value), first
    deleting a leftover of that name. An empty `data` still writes the Secret (one code path).

    The name is never live when this runs (its version row is `writing`), so a leftover is a
    write whose row never committed; an immutable Secret cannot be applied over. Raises
    KubeError; callers turn it into a generic error and log only the exception type name.
    """
    await kube.delete("Secret", namespace, name)
    await kube.apply(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {MANAGED_BY_LABEL: MANAGED_BY, ENTRY_LABEL: str(entry_id)},
            },
            "type": "Opaque",
            "immutable": True,
            "stringData": {env: value.get_secret_value() for env, value in data.items()},
        }
    )
