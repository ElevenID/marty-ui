"""Shared operator configuration for authenticated first-party gateway tools."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class GatewayActor:
    base_url: str
    api_key: str


class GatewayActorConfigurationError(ValueError):
    """Raised when a first-party tool has no gateway actor credential."""


def resolve_gateway_actor(
    environment: Mapping[str, str] | None = None,
    *,
    required_scopes: tuple[str, ...],
) -> GatewayActor:
    values = os.environ if environment is None else environment
    base_url = (
        values.get("MARTY_API_BASE_URL", "").strip() or "http://localhost:8000"
    ).rstrip("/")
    api_key = values.get("MARTY_API_KEY", "").strip()
    if not api_key:
        scopes = ", ".join(required_scopes)
        raise GatewayActorConfigurationError(
            f"MARTY_API_KEY is required and must identify an organization-scoped "
            f"gateway actor with scopes: {scopes}. ISSUANCE_API_KEY is a service "
            "credential and is not accepted by the gateway."
        )
    return GatewayActor(base_url=base_url, api_key=api_key)
