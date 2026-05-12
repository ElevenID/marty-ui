#!/usr/bin/env python3
"""Check if credential template has wallet configurations."""

import httpx
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

TEMPLATE_ID = '50000000-0000-0000-0000-000000000010'
ORG_ID = '00000000-0000-0000-0000-000000000001'

try:
    with httpx.Client(timeout=10) as client:
        # Try issuance service
        resp = client.get(f'http://localhost:8005/v1/issuance/templates/{TEMPLATE_ID}?org_id={ORG_ID}')
        
        if resp.status_code == 200:
            tmpl = resp.json()
            logger.info('Template found via issuance service:')
            logger.info(f"  ID: {tmpl.get('id')}")
            logger.info(f"  Name: {tmpl.get('name')}")
            logger.info(f"  Type: {tmpl.get('type')}")
            
            wallet_configs_json = tmpl.get('wallet_configs_json')
            wallet_configs = tmpl.get('wallet_configs')
            
            logger.info(f"  wallet_configs (field): {wallet_configs}")
            logger.info(f"  wallet_configs_json (field): {wallet_configs_json}")
            
            if wallet_configs_json:
                try:
                    wc_list = json.loads(wallet_configs_json)
                    logger.info(f"  Parsed wallet_configs ({len(wc_list)} entries):")
                    for i, wc_entry in enumerate(wc_list):
                        logger.info(f"    [{i}] wallet_id={wc_entry.get('wallet_id')}, "
                                  f"format_variant={wc_entry.get('format_variant')}, "
                                  f"deep_link_scheme={wc_entry.get('deep_link_scheme')}")
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse wallet_configs_json: {e}")
            else:
                logger.warning("⚠️  wallet_configs_json is empty or None!")
                logger.info("   This explains why per-wallet offers are not being generated")
        else:
            logger.error(f'Template endpoint returned {resp.status_code}: {resp.text}')
            
except Exception as e:
    logger.error(f'Error: {e}', exc_info=True)
