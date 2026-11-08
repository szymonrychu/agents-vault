"""The FastAPI apps: web listener (users, behind the source allowlist) and service listener
(orchestrator, behind the service-token bearer gate). Both share the error shape and probes."""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable
from typing import Any

from agents_common.service_gate import EXEMPT_PATHS, ServiceTokenGate
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from psycopg_pool import AsyncConnectionPool
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Receive, Scope, Send

from agents_vault.api import entries
from agents_vault.api.errors import ApiError, error_response
from agents_vault.settings import Settings

log = logging.getLogger(__name__)

PREFIX = "/vault/v1"


class SourceAllowlist:
    """Refuses peers outside the allowlist. Only the socket peer is read: Forwarded,
    X-Forwarded-For and X-Real-IP are never consulted."""

    def __init__(self, app: ASGIApp, networks: list) -> None:
        self.app = app
        self.networks = list(networks)

    def allowed(self, scope: Scope) -> bool:
        client = scope.get("client")
        if not client:
            return False
        try:
            addr = ipaddress.ip_address(client[0])
        except ValueError:
            return False
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        return any(addr.version == n.version and addr in n for n in self.networks)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        if (scope["type"] == "http" and scope.get("path") in EXEMPT_PATHS) or self.allowed(scope):
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        response = error_response(403, "forbidden", "source address is not allowed")
        await response(scope, receive, send)


def _base_app(
    settings: Settings,
    pool: AsyncConnectionPool,
    title: str,
    orchestrator: Any = None,
    kube_factory: Callable[[], Any] | None = None,
) -> FastAPI:
    app = FastAPI(title=title, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.pool = pool
    # None means "build the real client lazily on first use" (orchestrator client, kube client)
    app.state.orchestrator = orchestrator
    app.state.kube_factory = kube_factory

    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        return error_response(exc.status, exc.code, exc.message, exc.extra)

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, exc: RequestValidationError) -> JSONResponse:
        # loc and msg only: the input of a failed field can be a secret value
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(p) for p in first.get("loc", ()) if p != "body")
        message = f"{where}: {first.get('msg', 'invalid request')}" if where else "invalid request"
        return error_response(422, "invalid_request", message)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "error")
        return error_response(exc.status_code, code, str(exc.detail))

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        try:
            async with pool.connection() as conn:
                await conn.execute("SELECT 1")
        except Exception:
            log.error("readiness check failed")
            return error_response(503, "not_ready", "database is not reachable")
        return JSONResponse({"status": "ok"})

    return app


def create_web_app(
    settings: Settings,
    pool: AsyncConnectionPool,
    *,
    orchestrator: Any = None,
    kube_factory: Callable[[], Any] | None = None,
) -> FastAPI:
    """The user-facing app: source allowlist, no bearer, the entry routes under PREFIX."""
    app = _base_app(settings, pool, "agents-vault", orchestrator, kube_factory)
    app.include_router(entries.router, prefix=PREFIX)
    app.add_middleware(SourceAllowlist, networks=settings.api_networks())
    return app


def create_service_app(
    settings: Settings,
    pool: AsyncConnectionPool,
    tokens: list[str],
    *,
    orchestrator: Any = None,
) -> FastAPI:
    """The orchestrator-facing app: bearer gate on the service tokens, no Kubernetes access."""
    app = _base_app(settings, pool, "agents-vault-service", orchestrator)
    app.add_middleware(ServiceTokenGate, tokens=tokens)
    return app
