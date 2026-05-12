#!/usr/bin/env python3
"""Diagnose credential template retrieval and wallet_configs via gRPC."""

import sys
import logging
import asyncio
import json
from pathlib import Path

# Add services to path
sys.path.insert(0, str(Path(__file__).parent.parent / "services"))

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

TEMPLATE_ID = '50000000-0000-0000-0000-000000000010'
ORG_ID = '00000000-0000-0000-0000-000000000001'

async def test_grpc_template_fetch():
    """Test gRPC template fetch."""
    try:
        import grpc.aio as grpc_aio
        from marty_proto.v1 import credential_template_service_pb2 as ct_pb2
        from marty_proto.v1 import credential_template_service_pb2_grpc as ct_grpc
        
        ct_grpc_target = "localhost:9003"
        logger.info(f"Connecting to credential-template gRPC at {ct_grpc_target}...")
        
        async with grpc_aio.insecure_channel(ct_grpc_target) as channel:
            ct_stub = ct_grpc.CredentialTemplateServiceStub(channel)
            
            logger.info(f"Fetching template {TEMPLATE_ID}...")
            tmpl_resp = await ct_stub.GetTemplate(
                ct_pb2.GetTemplateRequest(template_id=TEMPLATE_ID)
            )
            
            if not tmpl_resp.id:
                logger.error(f"Template {TEMPLATE_ID} not found!")
                return False
            
            logger.info(f"Template found!")
            logger.info(f"  ID: {tmpl_resp.id}")
            logger.info(f"  Name: {tmpl_resp.name}")
            logger.info(f"  Type: {tmpl_resp.credential_type}")
            logger.info(f"  wallet_configs_json: {tmpl_resp.wallet_configs_json}")
            
            if tmpl_resp.wallet_configs_json:
                try:
                    wc_list = json.loads(tmpl_resp.wallet_configs_json)
                    logger.info(f"  Parsed wallet configs ({len(wc_list)} entries):")
                    for wc in wc_list:
                        wallet_id = wc.get("wallet_id", "?")
                        format_variant = wc.get("format_variant", "?")
                        logger.info(f"    - {wallet_id}: format_variant={format_variant}")
                        if "spruce" in wallet_id.lower() or "spruce" in format_variant.lower():
                            logger.info(f"      ✓ SpruceID wallet found!")
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse wallet_configs_json: {e}")
                    return False
            else:
                logger.warning("⚠️  wallet_configs_json is empty!")
                return False
            
            return True
    
    except ImportError as e:
        logger.error(f"protobuf import failed: {e}")
        logger.error("Make sure marty_proto is installed")
        return False
    except Exception as e:
        logger.error(f"gRPC error: {e}", exc_info=True)
        return False

async def main():
    logger.info("Testing credential template retrieval...\n")
    success = await test_grpc_template_fetch()
    
    if success:
        logger.info("\n✓ Template and wallet configs available!")
        return 0
    else:
        logger.error("\n✗ Failed to retrieve template or wallet configs")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
