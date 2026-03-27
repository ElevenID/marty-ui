"""Add MIP-compliance columns to wallet_registry table.

Adds organization_id, is_override, override_precedence, merge_strategy,
credential_format, issuance_protocol, compliance_profile_code, description,
wallet_apps, and specifications columns required for MIP protocol compliance.

Revision ID: 20260321_0000
Revises: 20260316_0000
Create Date: 2026-03-21 00:00:00.000000+00:00
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20260321_0000"
down_revision = "20260316_0000"
branch_labels = None
depends_on = None

SCHEMA = "credential_template_service"
TABLE = f"{SCHEMA}.wallet_registry"


def upgrade() -> None:
    op.add_column(
        "wallet_registry",
        sa.Column("organization_id", sa.String(64), nullable=True),
        schema=SCHEMA,
    )
    op.add_column(
        "wallet_registry",
        sa.Column("is_override", sa.Boolean, nullable=False, server_default="false"),
        schema=SCHEMA,
    )
    op.add_column(
        "wallet_registry",
        sa.Column("override_precedence", sa.Integer, nullable=False, server_default="50"),
        schema=SCHEMA,
    )
    op.add_column(
        "wallet_registry",
        sa.Column("merge_strategy", sa.String(16), nullable=False, server_default="APPEND"),
        schema=SCHEMA,
    )
    op.add_column(
        "wallet_registry",
        sa.Column("credential_format", sa.String(64), nullable=True),
        schema=SCHEMA,
    )
    op.add_column(
        "wallet_registry",
        sa.Column("issuance_protocol", sa.String(64), nullable=True),
        schema=SCHEMA,
    )
    op.add_column(
        "wallet_registry",
        sa.Column("compliance_profile_code", sa.String(128), nullable=True),
        schema=SCHEMA,
    )
    op.add_column(
        "wallet_registry",
        sa.Column("description", sa.Text, nullable=True),
        schema=SCHEMA,
    )
    op.add_column(
        "wallet_registry",
        sa.Column("wallet_apps", sa.JSON, nullable=False, server_default="[]"),
        schema=SCHEMA,
    )
    op.add_column(
        "wallet_registry",
        sa.Column("specifications", sa.JSON, nullable=False, server_default="[]"),
        schema=SCHEMA,
    )

    op.create_index(
        "ix_wallet_registry_organization_id",
        "wallet_registry",
        ["organization_id"],
        schema=SCHEMA,
    )
    op.create_index(
        "ix_wallet_registry_credential_format",
        "wallet_registry",
        ["credential_format"],
        schema=SCHEMA,
    )
    op.create_index(
        "ix_wallet_registry_issuance_protocol",
        "wallet_registry",
        ["issuance_protocol"],
        schema=SCHEMA,
    )
    op.create_index(
        "ix_wallet_registry_compliance_profile_code",
        "wallet_registry",
        ["compliance_profile_code"],
        schema=SCHEMA,
    )


def downgrade() -> None:
    op.drop_index("ix_wallet_registry_compliance_profile_code", table_name="wallet_registry", schema=SCHEMA)
    op.drop_index("ix_wallet_registry_issuance_protocol", table_name="wallet_registry", schema=SCHEMA)
    op.drop_index("ix_wallet_registry_credential_format", table_name="wallet_registry", schema=SCHEMA)
    op.drop_index("ix_wallet_registry_organization_id", table_name="wallet_registry", schema=SCHEMA)

    op.drop_column("wallet_registry", "specifications", schema=SCHEMA)
    op.drop_column("wallet_registry", "wallet_apps", schema=SCHEMA)
    op.drop_column("wallet_registry", "description", schema=SCHEMA)
    op.drop_column("wallet_registry", "compliance_profile_code", schema=SCHEMA)
    op.drop_column("wallet_registry", "issuance_protocol", schema=SCHEMA)
    op.drop_column("wallet_registry", "credential_format", schema=SCHEMA)
    op.drop_column("wallet_registry", "merge_strategy", schema=SCHEMA)
    op.drop_column("wallet_registry", "override_precedence", schema=SCHEMA)
    op.drop_column("wallet_registry", "is_override", schema=SCHEMA)
    op.drop_column("wallet_registry", "organization_id", schema=SCHEMA)
