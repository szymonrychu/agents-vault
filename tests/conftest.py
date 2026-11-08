import uuid
from collections.abc import AsyncIterator, Callable, Iterator

import httpx
import psycopg
import pytest
from agents_common.db.pool import open_pool
from psycopg import sql
from psycopg_pool import AsyncConnectionPool

from agents_vault.settings import Settings

PACKAGE = "agents_vault"
SERVICE_TOKEN = "service-secret"
ORCHESTRATOR_TOKEN = "orchestrator-secret"


@pytest.fixture
def db_url(migrated_db: Callable[[str], str]) -> str:
    """A fresh database cloned from the migrated template."""
    return migrated_db(PACKAGE)


@pytest.fixture
def conn(db_url: str) -> Iterator[psycopg.Connection]:
    with psycopg.connect(db_url, autocommit=True) as connection:
        yield connection


@pytest.fixture
def empty_db_url(pg_url: str) -> Iterator[str]:
    """A fresh database with no schema at all."""
    name = f"e_{uuid.uuid4().hex}"
    with psycopg.connect(pg_url, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        yield f"{pg_url.rsplit('/', 1)[0]}/{name}"
        admin.execute(
            sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
        )


@pytest.fixture
def settings(db_url: str) -> Settings:
    return Settings(
        database_url=db_url,
        orchestrator_url="http://orchestrator.invalid",
        orchestrator_token=ORCHESTRATOR_TOKEN,
        namespace="agents",
    )


@pytest.fixture
async def pool(db_url: str) -> AsyncIterator[AsyncConnectionPool]:
    opened = await open_pool(db_url)
    yield opened
    await opened.close()


@pytest.fixture
def kube():
    from fakes.fake_kube import FakeKube

    return FakeKube()


@pytest.fixture
def fake_orch():
    from agents_common.fake_orchestrator import FakeOrchestrator

    return FakeOrchestrator(ORCHESTRATOR_TOKEN)


@pytest.fixture
async def web_client(settings, pool, kube, fake_orch) -> AsyncIterator[httpx.AsyncClient]:
    """The web app on a FakeKube and a FakeOrchestrator, called from an allowed peer."""
    from agents_common.orchestrator import OrchestratorClient

    from agents_vault.api.app import create_web_app

    orchestrator = OrchestratorClient(
        settings.orchestrator_url,
        ORCHESTRATOR_TOKEN,
        transport=httpx.ASGITransport(app=fake_orch.app),
    )
    app = create_web_app(settings, pool, orchestrator=orchestrator, kube_factory=lambda: kube)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
        client.app = app  # type: ignore[attr-defined]
        yield client
    await orchestrator.aclose()
