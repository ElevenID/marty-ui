#!/usr/bin/env python3
"""Debug the gateway's InitiateIssuance response without logging secrets."""

import json
import logging

import httpx

if __package__:
    from .operator_gateway import GatewayActorConfigurationError, resolve_gateway_actor
else:
    from operator_gateway import GatewayActorConfigurationError, resolve_gateway_actor


logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

TEMPLATE_ID = "50000000-0000-0000-0000-000000000010"
ORG_ID = "00000000-0000-0000-0000-000000000001"
APP_ID = "ca65845a-5ec7-4e1c-bb90-4fce6e429a4f"


def main(client_factory=httpx.Client) -> int:
    try:
        gateway = resolve_gateway_actor(required_scopes=("credentials:issue",))
    except GatewayActorConfigurationError as error:
        logger.error("%s", error)
        return 2

    payload = {
        "organization_id": ORG_ID,
        "credential_template_id": TEMPLATE_ID,
        "applicant_id": APP_ID,
        "subject_did": "",
        "holder_did": "",
        "claims": {},
    }
    logger.info("Calling gateway InitiateIssuance endpoint.")
    logger.info("POST %s/v1/issuance/initiate", gateway.base_url)
    logger.info("Payload: %s", json.dumps(payload, indent=2))

    try:
        with client_factory(timeout=15) as client:
            response = client.post(
                f"{gateway.base_url}/v1/issuance/initiate",
                json=payload,
                headers={"X-API-Key": gateway.api_key},
                timeout=15,
            )
    except httpx.HTTPError:
        logger.error("Gateway initiation request failed.")
        return 1

    logger.info("Status: %s", response.status_code)
    if response.status_code != 200:
        logger.error(
            "Gateway initiation was rejected with status %s.", response.status_code
        )
        return 1

    try:
        body = response.json()
    except ValueError:
        logger.error("Gateway initiation returned malformed JSON.")
        return 1
    if not isinstance(body, dict):
        logger.error("Gateway initiation response must be a JSON object.")
        return 1
    logger.info("Response fields: %s", sorted(body))
    credential_offer_uri = body.get("credential_offer_uri", "")
    credential_offer_uris = body.get("credential_offer_uris", {})
    credential_offer_labels = body.get("credential_offer_labels", {})

    if credential_offer_uri:
        logger.info("credential_offer_uri is present (value redacted).")
    else:
        logger.warning("credential_offer_uri is missing.")

    if credential_offer_uris:
        logger.info(
            "credential_offer_uris contains %s wallet(s): %s",
            len(credential_offer_uris),
            sorted(credential_offer_uris),
        )
    else:
        logger.warning("credential_offer_uris is empty or missing.")
        logger.info("Per-wallet offers are not being generated.")

    if credential_offer_labels:
        logger.info(
            "credential_offer_labels contains %s label(s).",
            len(credential_offer_labels),
        )
    else:
        logger.warning("credential_offer_labels is missing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
