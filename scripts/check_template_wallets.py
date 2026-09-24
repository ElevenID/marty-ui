#!/usr/bin/env python3
"""Check a credential template's effective wallet compatibility via the gateway."""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

if __package__:
    from .operator_gateway import GatewayActorConfigurationError, resolve_gateway_actor
else:
    from operator_gateway import GatewayActorConfigurationError, resolve_gateway_actor


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_TEMPLATE_ID = "50000000-0000-0000-0000-000000000010"
DEFAULT_ORGANIZATION_ID = "00000000-0000-0000-0000-000000000001"


def _wallet_config(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    wallet_id = value.get("wallet_id")
    deep_link_scheme = value.get("deep_link_scheme")
    format_variant = value.get("format_variant")
    if not isinstance(wallet_id, str) or not wallet_id.strip():
        return None
    if not isinstance(deep_link_scheme, str) or not deep_link_scheme.strip():
        return None
    if format_variant is not None and not isinstance(format_variant, str):
        return None
    return value


def main(client_factory=httpx.Client) -> int:
    try:
        gateway = resolve_gateway_actor(required_scopes=("templates:read",))
    except GatewayActorConfigurationError as error:
        logger.error("%s", error)
        return 2

    template_id = os.environ.get(
        "MARTY_CREDENTIAL_TEMPLATE_ID", DEFAULT_TEMPLATE_ID
    ).strip()
    organization_id = os.environ.get(
        "MARTY_ORGANIZATION_ID", DEFAULT_ORGANIZATION_ID
    ).strip()
    try:
        with client_factory(timeout=10) as client:
            response = client.get(
                f"{gateway.base_url}/v1/credential-templates/{template_id}/wallet-compatibility",
                params={"organization_id": organization_id},
                headers={"X-API-Key": gateway.api_key},
            )
    except httpx.HTTPError:
        logger.error("Wallet compatibility request failed.")
        return 1

    if response.status_code != 200:
        logger.error(
            "Wallet compatibility endpoint returned status %s.", response.status_code
        )
        return 1

    try:
        body = response.json()
    except ValueError:
        logger.error("Wallet compatibility endpoint returned malformed JSON.")
        return 1
    if not isinstance(body, dict):
        logger.error("Wallet compatibility response must be a JSON object.")
        return 1
    values = body.get("template_wallet_configs")
    if not isinstance(values, list):
        logger.error("template_wallet_configs must be an array.")
        return 1

    entries = [_wallet_config(value) for value in values]
    if any(entry is None for entry in entries):
        logger.error("template_wallet_configs contains a malformed wallet entry.")
        return 1
    if not entries:
        logger.warning("No template wallet configurations are effective.")
        return 0

    logger.info("Effective template wallet configurations (%s):", len(entries))
    for index, entry in enumerate(entries):
        assert entry is not None
        logger.info(
            "  [%s] wallet_id=%s, format_variant=%s, deep_link_scheme=%s",
            index,
            entry["wallet_id"],
            entry.get("format_variant"),
            entry["deep_link_scheme"],
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
