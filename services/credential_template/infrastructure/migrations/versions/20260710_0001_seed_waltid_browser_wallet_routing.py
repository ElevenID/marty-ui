"""Seed walt.id browser wallet routing metadata.

Revision ID: 20260710_0001
Revises: 20260607_0001
Create Date: 2026-07-10 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260710_0001"
down_revision = "20260607_0001"
branch_labels = None
depends_on = None

SCHEMA = "credential_template_service"
TABLE = f"{SCHEMA}.wallet_registry"
WALTID_WALLET_ID = "wr-waltid-001"
WALTID_GENERIC_ROUTE = "openid-credential-offer://?{credential_offer_param}={offer_encoded}"
WALTID_WEB_ROUTE = "https://wallet.demo.walt.id/api/siop/initiateIssuance?{credential_offer_param}={offer_encoded}"


def _wallet_registry_exists(conn) -> bool:
    return bool(
        conn.execute(
            sa.text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = :schema AND table_name = 'wallet_registry' LIMIT 1"
            ),
            {"schema": SCHEMA},
        ).scalar()
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _wallet_registry_exists(conn):
        return

    routing_templates = {
        "generic": WALTID_GENERIC_ROUTE,
        "web": WALTID_WEB_ROUTE,
        "desktop": WALTID_WEB_ROUTE,
    }

    conn.execute(
        sa.text(
            f"""
            UPDATE {TABLE}
               SET deep_link_template = :deep_link_template,
                   routing_templates = COALESCE(routing_templates::jsonb, '{{}}'::jsonb)
                                       || CAST(:routing_templates AS jsonb),
                   updated_at = NOW()
             WHERE id = :wallet_id
            """
        ),
        {
            "wallet_id": WALTID_WALLET_ID,
            "deep_link_template": WALTID_GENERIC_ROUTE,
            "routing_templates": json.dumps(routing_templates),
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    if not _wallet_registry_exists(conn):
        return

    conn.execute(
        sa.text(
            f"""
            UPDATE {TABLE}
               SET routing_templates = COALESCE(routing_templates::jsonb, '{{}}'::jsonb)
                                       - 'generic'
                                       - 'web'
                                       - 'desktop',
                   updated_at = NOW()
             WHERE id = :wallet_id
            """
        ),
        {"wallet_id": WALTID_WALLET_ID},
    )
