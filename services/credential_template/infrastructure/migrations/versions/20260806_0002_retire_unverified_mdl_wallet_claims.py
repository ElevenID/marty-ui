"""Retire demo mDL issuance and unverified wallet compatibility claims.

Revision ID: 20260806_0002
Revises: 20260801_0003
Create Date: 2026-08-06 00:00:00.000000+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260806_0002"
down_revision = "20260801_0003"
branch_labels = None
depends_on = None

SCHEMA = "credential_template_service"
MDL_TEMPLATE_IDS = (
    "40000000-0000-0000-0000-000000000008",
    "50000000-0000-0000-0000-000000000020",
)


def _table_exists(connection, table_name: str) -> bool:
    return bool(
        connection.execute(
            sa.text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = :schema AND table_name = :table_name LIMIT 1"
            ),
            {"schema": SCHEMA, "table_name": table_name},
        ).scalar()
    )


def upgrade() -> None:
    connection = op.get_bind()

    if _table_exists(connection, "credential_templates"):
        connection.execute(
            sa.text(
                f"""
                UPDATE {SCHEMA}.credential_templates
                   SET status = 'deprecated',
                       name = 'Legacy mDL Issuance Prototype',
                       description = 'Legacy prototype retained for migration history. It is not an authorized AAMVA mDL issuer, does not establish wallet compatibility, and must not be used for production issuance.',
                       wallet_configs = CAST('[]' AS jsonb),
                       updated_at = now()
                 WHERE id IN :template_ids
                """
            ).bindparams(sa.bindparam("template_ids", expanding=True)),
            {"template_ids": list(MDL_TEMPLATE_IDS)},
        )

    if _table_exists(connection, "wallet_registry"):
        connection.execute(
            sa.text(
                f"""
                UPDATE {SCHEMA}.wallet_registry
                   SET description = 'Inactive compatibility placeholder. Apple Wallet identity provisioning and Verify with Wallet presentation are program-specific paths and are not generic OID4VCI compatibility.',
                       specifications = CAST('["ISO 18013-5", "Verify with Wallet"]' AS jsonb),
                       supported_protocols = CAST('["APPLE_WALLET"]' AS jsonb),
                       deep_link_template = '',
                       routing_templates = CAST('{{}}' AS jsonb),
                       supports_deeplink = false,
                       is_active = false,
                       updated_at = now()
                 WHERE id = 'wr-apple-001'
                """
            )
        )
        connection.execute(
            sa.text(
                f"""
                UPDATE {SCHEMA}.wallet_registry
                   SET description = 'Generic OID4VCI handoff for configured and tested SD-JWT VC or JWT VC wallets; this entry does not assert compatibility with every wallet or mdoc profile.',
                       supported_formats = CAST('["sd_jwt_vc", "jwt_vc"]' AS jsonb),
                       updated_at = now()
                 WHERE id = 'wr-default'
                """
            )
        )


def downgrade() -> None:
    # A downgrade must not revive an unauthorized issuer or compatibility claim.
    pass
