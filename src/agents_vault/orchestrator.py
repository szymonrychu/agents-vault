"""The orchestrator client factory (service port, bearer token)."""

from __future__ import annotations

from agents_common.orchestrator import OrchestratorClient

from agents_vault.settings import Settings

CLIENT_TIMEOUT_SECONDS = 10


def make_client(settings: Settings) -> OrchestratorClient:
    return OrchestratorClient(
        settings.orchestrator_url,
        settings.orchestrator_token.get_secret_value(),
        timeout=CLIENT_TIMEOUT_SECONDS,
    )
