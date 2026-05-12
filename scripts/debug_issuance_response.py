#!/usr/bin/env python3
"""Debug issuance service InitiateIssuance response."""

import json
import httpx
import logging

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

ISSUANCE_URL = "http://localhost:8005"
TEMPLATE_ID = "50000000-0000-0000-0000-000000000010"
ORG_ID = "00000000-0000-0000-0000-000000000001"
APP_ID = "ca65845a-5ec7-4e1c-bb90-4fce6e429a4f"

logger.info("Calling issuance service InitiateIssuance endpoint...\n")

try:
    with httpx.Client(timeout=15) as client:
        payload = {
            "organization_id": ORG_ID,
            "credential_template_id": TEMPLATE_ID,
            "applicant_id": APP_ID,
            "subject_did": "",
            "holder_did": "",
            "claims": {},
        }
        
        logger.info(f"POST {ISSUANCE_URL}/v1/issuance/initiate")
        logger.info(f"Payload: {json.dumps(payload, indent=2)}\n")
        
        resp = client.post(
            f"{ISSUANCE_URL}/v1/issuance/initiate",
            json=payload,
            headers={"X-API-Key": "dev-issuance-api-key"},
            timeout=15
        )
        
        logger.info(f"Status: {resp.status_code}\n")
        
        if resp.status_code != 200:
            logger.error(f"Error: {resp.text}")
            exit(1)
        
        body = resp.json()
        
        logger.info("Response:")
        logger.info(json.dumps(body, indent=2))
        
        logger.info("\n" + "="*60)
        logger.info("Analysis:")
        logger.info("="*60)
        
        # Check key fields
        credential_offer_uri = body.get("credential_offer_uri", "")
        credential_offer_uris = body.get("credential_offer_uris", {})
        credential_offer_labels = body.get("credential_offer_labels", {})
        
        if credential_offer_uri:
            logger.info(f"✓ credential_offer_uri present: {credential_offer_uri[:80]}...")
        else:
            logger.warning("✗ credential_offer_uri missing")
        
        if credential_offer_uris:
            logger.info(f"✓ credential_offer_uris present with {len(credential_offer_uris)} wallet(s):")
            for wallet_id, uri in credential_offer_uris.items():
                logger.info(f"  - {wallet_id}")
                if "spruce" in wallet_id.lower():
                    logger.info(f"    ✓ SpruceID wallet found!")
        else:
            logger.warning("✗ credential_offer_uris is empty or missing")
            logger.info("  This is the root cause of the SpruceID parsing error!")
            logger.info("  Per-wallet offers are not being generated.")
        
        if credential_offer_labels:
            logger.info(f"✓ credential_offer_labels present: {credential_offer_labels}")
        else:
            logger.warning("✗ credential_offer_labels missing")
        
except Exception as e:
    logger.error(f"Error: {e}", exc_info=True)
    exit(1)
