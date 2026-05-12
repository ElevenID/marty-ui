#!/usr/bin/env python3
"""Check wallet_configs in the database."""

import asyncio
import json
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

TEMPLATE_ID = '50000000-0000-0000-0000-000000000010'
ORG_ID = '00000000-0000-0000-0000-000000000001'

async def main():
    database_url = "postgresql+asyncpg://marty:marty@localhost/marty_local"
    engine = create_async_engine(database_url)
    
    try:
        async with engine.begin() as conn:
            result = await conn.execute(
                text("""
                    SELECT id, name, credential_type, wallet_configs
                    FROM credential_template_service.credential_templates
                    WHERE id = :template_id
                """),
                {"template_id": TEMPLATE_ID}
            )
            row = result.fetchone()
            
            if not row:
                print(f"Template {TEMPLATE_ID} not found in database!")
                return 1
            
            template_id, name, credential_type, wallet_configs = row
            
            print(f"Template found:")
            print(f"  ID: {template_id}")
            print(f"  Name: {name}")
            print(f"  Type: {credential_type}")
            print(f"  wallet_configs (raw): {wallet_configs}")
            
            if wallet_configs:
                if isinstance(wallet_configs, dict):
                    print(f"  wallet_configs (parsed):")
                    for wc in wallet_configs:
                        wallet_id = wc.get("wallet_id")
                        fmt_variant = wc.get("format_variant")
                        print(f"    - {wallet_id}: {fmt_variant}")
                        if "spruce" in str(wallet_id).lower() or "spruce" in str(fmt_variant).lower():
                            print(f"      ✓ SpruceID wallet!")
                elif isinstance(wallet_configs, list):
                    print(f"  wallet_configs (list with {len(wallet_configs)} entries):")
                    for i, wc in enumerate(wallet_configs):
                        print(f"    [{i}] {wc}")
                else:
                    print(f"  wallet_configs type: {type(wallet_configs)}")
            else:
                print(f"  ⚠️  wallet_configs is empty/null!")
            
            return 0
    except Exception as e:
        print(f"Error: {e}", exc_info=True)
        return 1
    finally:
        await engine.dispose()

if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main()))
