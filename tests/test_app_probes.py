import httpx
import pytest

from agents_vault.api.app import create_service_app, create_web_app
from agents_vault.settings import Settings

TOKEN = "service-secret"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="postgresql://u:p@db.invalid/vault",
        orchestrator_url="http://orchestrator.invalid",
        orchestrator_token="orch",
        namespace="agents",
    )


def client(app, peer: str = "127.0.0.1", **kw) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=(peer, 1)), base_url="http://test", **kw
    )


async def test_web_healthz(settings):
    async with client(create_web_app(settings, None)) as c:
        response = await c.get("/healthz")
    assert response.status_code == 200


async def test_web_forbids_peer_outside_allowlist(settings):
    app = create_web_app(settings, None)
    async with client(app, "10.0.0.1") as c:
        denied = await c.get("/vault/v1/entries")
        probe = await c.get("/healthz")
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "forbidden"
    assert probe.status_code == 200
    async with client(app, "127.0.0.1") as c:
        allowed = await c.get("/vault/v1/nothing-here")
    assert allowed.status_code == 404


async def test_service_healthz(settings):
    async with client(create_service_app(settings, None, [TOKEN])) as c:
        assert (await c.get("/healthz")).status_code == 200


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}])
async def test_service_requires_bearer(settings, headers):
    async with client(create_service_app(settings, None, [TOKEN]), headers=headers) as c:
        response = await c.get("/vault/v1/anything")
        probe = await c.get("/healthz")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"
    assert probe.status_code == 200


async def test_service_accepts_token(settings):
    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with client(create_service_app(settings, None, [TOKEN]), headers=headers) as c:
        assert (await c.get("/vault/v1/anything")).status_code == 404
