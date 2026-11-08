import uuid
from collections.abc import AsyncIterator, Callable, Iterator

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
