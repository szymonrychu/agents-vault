"""Process entry points of the two http listeners: web (users) and service (orchestrator)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable, Iterator

import uvicorn
from agents_common.db import open_pool
from agents_common.runtime import run_service
from fastapi import FastAPI
from psycopg_pool import AsyncConnectionPool

from agents_vault.api.app import create_service_app, create_web_app
from agents_vault.settings import Settings

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"

AppFactory = Callable[[Settings, AsyncConnectionPool], FastAPI]


class _Server(uvicorn.Server):
    """uvicorn without its own signal handling: run_service owns SIGTERM and SIGINT."""

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


def _config(settings: Settings, app: FastAPI, port: int) -> uvicorn.Config:
    return uvicorn.Config(
        app,
        host=settings.http_host,
        port=port,
        log_level=settings.log_level.lower(),
        timeout_graceful_shutdown=int(settings.shutdown_grace_seconds),
        proxy_headers=False,  # the allowlist must see the socket peer, never X-Forwarded-For
    )


async def _serve(settings: Settings, stop: asyncio.Event, factory: AppFactory, port: int) -> None:
    pool = await open_pool(settings.database_url.get_secret_value(), min_size=1, max_size=10)
    try:
        server = _Server(_config(settings, factory(settings, pool), port))
        serving = asyncio.create_task(server.serve())
        stopping = asyncio.create_task(stop.wait())
        await asyncio.wait({serving, stopping}, return_when=asyncio.FIRST_COMPLETED)
        server.should_exit = True
        stopping.cancel()
        await serving
    finally:
        await pool.close()


def _main(settings: Settings, factory: AppFactory, port: int) -> int:
    logging.basicConfig(level=settings.log_level.upper(), format=LOG_FORMAT, force=True)
    return asyncio.run(
        run_service(
            lambda stop: _serve(settings, stop, factory, port),
            grace_seconds=settings.shutdown_grace_seconds,
        )
    )


def web_main(settings: Settings) -> int:
    """Serve the user-facing app on VAULT_HTTP_PORT until SIGTERM or SIGINT."""
    return _main(settings, create_web_app, settings.http_port)


def service_main(settings: Settings, tokens: list[str]) -> int:
    """Serve the orchestrator-facing app on VAULT_SERVICE_PORT until SIGTERM or SIGINT."""

    def factory(s: Settings, pool: AsyncConnectionPool) -> FastAPI:
        return create_service_app(s, pool, tokens)

    return _main(settings, factory, settings.service_port)
