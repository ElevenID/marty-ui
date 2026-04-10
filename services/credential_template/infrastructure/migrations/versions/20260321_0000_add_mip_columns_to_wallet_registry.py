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


def _wallet_registry_has_column(conn, column_name: str) -> bool:
    return bool(
        conn.execute(
            sa.text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_schema = :schema AND table_name = 'wallet_registry' "
                "AND column_name = :column_name LIMIT 1"
            ),
            {"schema": SCHEMA, "column_name": column_name},
        ).scalar()
    )


def _wallet_registry_has_index(conn, index_name: str) -> bool:
    return bool(
        conn.execute(
            sa.text(
                "SELECT 1 FROM pg_indexes "
                "WHERE schemaname = :schema AND tablename = 'wallet_registry' "
                "AND indexname = :index_name LIMIT 1"
            ),
            {"schema": SCHEMA, "index_name": index_name},
        ).scalar()
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _wallet_registry_exists(conn):
        return

    if not _wallet_registry_has_column(conn, "organization_id"):
        op.add_column(
            "wallet_registry",
            sa.Column("organization_id", sa.String(64), nullable=True),
            schema=SCHEMA,
        )
    if not _wallet_registry_has_column(conn, "is_override"):
        op.add_column(
            "wallet_registry",
            sa.Column("is_override", sa.Boolean, nullable=False, server_default="false"),
            schema=SCHEMA,
        )
    if not _wallet_registry_has_column(conn, "override_precedence"):
        op.add_column(
            "wallet_registry",
            sa.Column("override_precedence", sa.Integer, nullable=False, server_default="50"),
            schema=SCHEMA,
        )
    if not _wallet_registry_has_column(conn, "merge_strategy"):
        op.add_column(
            "wallet_registry",
            sa.Column("merge_strategy", sa.String(16), nullable=False, server_default="APPEND"),
            schema=SCHEMA,
        )
    if not _wallet_registry_has_column(conn, "credential_format"):
        op.add_column(
            "wallet_registry",
            sa.Column("credential_format", sa.String(64), nullable=True),
            schema=SCHEMA,
        )
    if not _wallet_registry_has_column(conn, "issuance_protocol"):
        op.add_column(
            "wallet_registry",
            sa.Column("issuance_protocol", sa.String(64), nullable=True),
            schema=SCHEMA,
        )
    if not _wallet_registry_has_column(conn, "compliance_profile_code"):
        op.add_column(
            "wallet_registry",
            sa.Column("compliance_profile_code", sa.String(128), nullable=True),
            schema=SCHEMA,
        )
    if not _wallet_registry_has_column(conn, "description"):
        op.add_column(
            "wallet_registry",
            sa.Column("description", sa.Text, nullable=True),
            schema=SCHEMA,
        )
    if not _wallet_registry_has_column(conn, "wallet_apps"):
        op.add_column(
            "wallet_registry",
            sa.Column("wallet_apps", sa.JSON, nullable=False, server_default="[]"),
            schema=SCHEMA,
        )
    if not _wallet_registry_has_column(conn, "specifications"):
        op.add_column(
            "wallet_registry",
            sa.Column("specifications", sa.JSON, nullable=False, server_default="[]"),
            schema=SCHEMA,
        )

    if _wallet_registry_has_column(conn, "organization_id") and not _wallet_registry_has_index(conn, "ix_wallet_registry_organization_id"):
        op.create_index(
            "ix_wallet_registry_organization_id",
            "wallet_registry",
            ["organization_id"],
            schema=SCHEMA,
        )
    if _wallet_registry_has_column(conn, "credential_format") and not _wallet_registry_has_index(conn, "ix_wallet_registry_credential_format"):
        op.create_index(
            "ix_wallet_registry_credential_format",
            "wallet_registry",
            ["credential_format"],
            schema=SCHEMA,
        )
    if _wallet_registry_has_column(conn, "issuance_protocol") and not _wallet_registry_has_index(conn, "ix_wallet_registry_issuance_protocol"):
        op.create_index(
            "ix_wallet_registry_issuance_protocol",
            "wallet_registry",
            ["issuance_protocol"],
            schema=SCHEMA,
        )
    if _wallet_registry_has_column(conn, "compliance_profile_code") and not _wallet_registry_has_index(conn, "ix_wallet_registry_compliance_profile_code"):
        op.create_index(
            "ix_wallet_registry_compliance_profile_code",
            "wallet_registry",
            ["compliance_profile_code"],
            schema=SCHEMA,
        )


def downgrade() -> None:
    conn = op.get_bind()
    if not _wallet_registry_exists(conn):
        return

    if _wallet_registry_has_index(conn, "ix_wallet_registry_compliance_profile_code"):
        op.drop_index("ix_wallet_registry_compliance_profile_code", table_name="wallet_registry", schema=SCHEMA)
    if _wallet_registry_has_index(conn, "ix_wallet_registry_issuance_protocol"):
        op.drop_index("ix_wallet_registry_issuance_protocol", table_name="wallet_registry", schema=SCHEMA)
    if _wallet_registry_has_index(conn, "ix_wallet_registry_credential_format"):
        op.drop_index("ix_wallet_registry_credential_format", table_name="wallet_registry", schema=SCHEMA)
    if _wallet_registry_has_index(conn, "ix_wallet_registry_organization_id"):
        op.drop_index("ix_wallet_registry_organization_id", table_name="wallet_registry", schema=SCHEMA)

    if _wallet_registry_has_column(conn, "specifications"):
        op.drop_column("wallet_registry", "specifications", schema=SCHEMA)
    if _wallet_registry_has_column(conn, "wallet_apps"):
        op.drop_column("wallet_registry", "wallet_apps", schema=SCHEMA)
    if _wallet_registry_has_column(conn, "description"):
        op.drop_column("wallet_registry", "description", schema=SCHEMA)
    if _wallet_registry_has_column(conn, "compliance_profile_code"):
        op.drop_column("wallet_registry", "compliance_profile_code", schema=SCHEMA)
    if _wallet_registry_has_column(conn, "issuance_protocol"):
        op.drop_column("wallet_registry", "issuance_protocol", schema=SCHEMA)
    if _wallet_registry_has_column(conn, "credential_format"):
        op.drop_column("wallet_registry", "credential_format", schema=SCHEMA)
    if _wallet_registry_has_column(conn, "merge_strategy"):
        op.drop_column("wallet_registry", "merge_strategy", schema=SCHEMA)
    if _wallet_registry_has_column(conn, "override_precedence"):
        op.drop_column("wallet_registry", "override_precedence", schema=SCHEMA)
    if _wallet_registry_has_column(conn, "is_override"):
        op.drop_column("wallet_registry", "is_override", schema=SCHEMA)
    if _wallet_registry_has_column(conn, "organization_id"):
        op.drop_column("wallet_registry", "organization_id", schema=SCHEMA)
