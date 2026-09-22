#!/usr/bin/env python3
"""Check a credential template's wallet configuration through the gateway."""

import json
import logging
import os

import httpx


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

API_BASE_URL = os.environ.get("MARTY_API_BASE_URL", "http://localhost:8000").rstrip("/")
API_KEY = os.environ.get("MARTY_API_KEY", "").strip()
TEMPLATE_ID = os.environ.get(
    "MARTY_CREDENTIAL_TEMPLATE_ID", "50000000-0000-0000-0000-000000000010"
)
ORG_ID = os.environ.get("MARTY_ORGANIZATION_ID", "00000000-0000-0000-0000-000000000001")


def main() -> int:
    if not API_KEY:
        logger.error(
            "MARTY_API_KEY is required and must be authorized for "
            "templates:read in MARTY_ORGANIZATION_ID"
        )
        return 2

    try:
        with httpx.Client(timeout=10) as client:
            response = client.get(
                f"{API_BASE_URL}/v1/credential-templates/{TEMPLATE_ID}",
                params={"organization_id": ORG_ID},
                headers={"X-API-Key": API_KEY},
            )
    except httpx.HTTPError as error:
        logger.error("Template request failed: %s", error)
        return 1

    if response.status_code != 200:
        logger.error(
            "Template endpoint returned %s: %s",
            response.status_code,
            response.text,
        )
        return 1

    template = response.json()
    logger.info("Template found via credential-template gateway route:")
    logger.info("  ID: %s", template.get("id"))
    logger.info("  Name: %s", template.get("name"))
    logger.info("  Type: %s", template.get("type"))

    wallet_configs_json = template.get("wallet_configs_json")
    wallet_configs = template.get("wallet_configs")
    logger.info("  wallet_configs (field): %s", wallet_configs)
    logger.info("  wallet_configs_json (field): %s", wallet_configs_json)

    if not wallet_configs_json:
        logger.warning("wallet_configs_json is empty or missing")
        logger.info("This explains why per-wallet offers are not being generated")
        return 0

    try:
        entries = json.loads(wallet_configs_json)
    except json.JSONDecodeError as error:
        logger.error("Failed to parse wallet_configs_json: %s", error)
        return 1

    logger.info("  Parsed wallet_configs (%s entries):", len(entries))
    for index, entry in enumerate(entries):
        logger.info(
            "    [%s] wallet_id=%s, format_variant=%s, deep_link_scheme=%s",
            index,
            entry.get("wallet_id"),
            entry.get("format_variant"),
            entry.get("deep_link_scheme"),
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
