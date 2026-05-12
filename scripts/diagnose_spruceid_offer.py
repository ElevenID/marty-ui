#!/usr/bin/env python3
"""
Diagnose SpruceID wallet credential offer parsing error.

This script:
1. Calls the applicant /issue endpoint for a CREDENTIALED application
2. Inspects the response structure
3. Decodes and examines the credential_offer_uri
4. Checks for per-wallet offers (credential_offer_uris)
5. Reports what wallets are configured and which offers exist
"""

import json
import base64
import urllib.parse
import sys
from pathlib import Path

# Add services to path
sys.path.insert(0, str(Path(__file__).parent.parent / "services"))

import httpx
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

APPLICANT_URL = "http://localhost:8006"
# Sample credentialed application ID from test data
APP_ID = "ca65845a-5ec7-4e1c-bb90-4fce6e429a4f"

def decode_offer_uri(uri: str) -> dict | None:
    """Decode credential_offer_uri to inspect the structure."""
    if not uri:
        return None
    
    try:
        parsed = urllib.parse.urlparse(uri)
        params = urllib.parse.parse_qs(parsed.query)
        
        if "credential_offer" in params:
            offer_json = params["credential_offer"][0]
            # Try decoding as URL-encoded JSON first
            try:
                return json.loads(offer_json)
            except:
                # Try as base64
                try:
                    decoded = base64.urlsafe_b64decode(offer_json + '==')
                    return json.loads(decoded)
                except:
                    return {"_raw": offer_json}
        
        if "credential_offer_uri" in params:
            offer_uri = params["credential_offer_uri"][0]
            logger.info(f"  credential_offer_uri param: {offer_uri}")
            return {"_redirect_to": offer_uri}
    
    except Exception as e:
        logger.error(f"Failed to decode offer URI: {e}")
    
    return None

def main():
    logger.info(f"Diagnosing credential offer for app: {APP_ID}")
    logger.info(f"Calling {APPLICANT_URL}/v1/applicants/applications/{APP_ID}/issue")
    
    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                f"{APPLICANT_URL}/v1/applicants/applications/{APP_ID}/issue"
            )
            
            logger.info(f"Status: {resp.status_code}")
            
            if resp.status_code != 200:
                logger.error(f"Error response: {resp.text}")
                return 1
            
            body = resp.json()
            
            # Extract offer information
            logger.info("\n=== Response Structure ===")
            
            status = body.get("status")
            logger.info(f"Application status: {status}")
            
            credential_offer_uri = body.get("credential_offer_uri")
            if credential_offer_uri:
                logger.info(f"\ncredential_offer_uri: {credential_offer_uri[:100]}...")
                offer = decode_offer_uri(credential_offer_uri)
                if offer:
                    logger.info("Decoded credential_offer:")
                    for key, value in offer.items():
                        if key == 'credential_offer' or key.startswith('_'):
                            logger.info(f"  {key}: {str(value)[:80]}...")
                        else:
                            logger.info(f"  {key}: {value}")
            else:
                logger.warning("No credential_offer_uri in response")
            
            credential_offer_uris = body.get("credential_offer_uris", {})
            if credential_offer_uris:
                logger.info(f"\ncredential_offer_uris (per-wallet):")
                for wallet_id, uri in credential_offer_uris.items():
                    logger.info(f"  {wallet_id}: {uri[:60]}...")
                    # Check if this is SpruceID
                    if "spruce" in wallet_id.lower():
                        offer = decode_offer_uri(uri)
                        if offer:
                            logger.info(f"    -> Decoded SpruceID offer:")
                            for key, value in offer.items():
                                if not key.startswith('_'):
                                    logger.info(f"       {key}: {value}")
            else:
                logger.warning("No credential_offer_uris (per-wallet mapping) in response!")
            
            credential_offer_labels = body.get("credential_offer_labels", {})
            if credential_offer_labels:
                logger.info(f"\ncredential_offer_labels:")
                for wallet_id, label in credential_offer_labels.items():
                    logger.info(f"  {wallet_id}: {label}")
            else:
                logger.warning("No credential_offer_labels in response")
            
            # Check if SpruceID is missing
            logger.info("\n=== Analysis ===")
            spruce_in_uris = any("spruce" in wid.lower() for wid in credential_offer_uris.keys())
            if not spruce_in_uris and credential_offer_uris:
                logger.warning("⚠️  SpruceID wallet NOT in credential_offer_uris!")
                logger.warning(f"   Available wallets: {list(credential_offer_uris.keys())}")
            elif not credential_offer_uris:
                logger.warning("⚠️  credential_offer_uris is empty or missing!")
                logger.info("   This means no per-wallet offers were generated")
                logger.info("   SpruceID wallet may not be properly configured for this template")
            else:
                logger.info("✓ Per-wallet offers exist")
                spruce_uris = {k: v for k, v in credential_offer_uris.items() if "spruce" in k.lower()}
                if spruce_uris:
                    logger.info(f"✓ SpruceID wallets found: {list(spruce_uris.keys())}")
                else:
                    logger.warning("⚠️  SpruceID wallet not configured in this template")
            
            return 0
    
    except Exception as e:
        logger.error(f"Failed to get offer: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
