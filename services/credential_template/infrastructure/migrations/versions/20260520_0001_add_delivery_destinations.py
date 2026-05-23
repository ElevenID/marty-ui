"""Add delivery destination registry.

Revision ID: 20260520_0001
Revises: 20260518_0001
Create Date: 2026-05-20 00:00:00.000000+00:00
"""

from __future__ import annotations

from alembic import op


revision = "20260520_0001"
down_revision = "20260518_0001"
branch_labels = None
depends_on = None

SCHEMA = "credential_template_service"


def upgrade() -> None:
    op.execute(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA}")
    op.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {SCHEMA}.delivery_destinations (
            id VARCHAR(128) PRIMARY KEY,
            organization_id VARCHAR(64),
            is_system BOOLEAN NOT NULL DEFAULT false,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            provider VARCHAR(64) NOT NULL,
            mode VARCHAR(40) NOT NULL,
            setup_actor VARCHAR(40) NOT NULL,
            delivery_target VARCHAR(64) NOT NULL,
            wallet_profile_id VARCHAR(128),
            credential_format VARCHAR(64),
            issuance_protocol VARCHAR(64),
            compliance_profile_code VARCHAR(128),
            connector_type VARCHAR(64),
            connector_id VARCHAR(128),
            requires_consent BOOLEAN NOT NULL DEFAULT false,
            claim_projection_policy JSONB NOT NULL DEFAULT '{{}}'::jsonb,
            setup_requirements JSONB NOT NULL DEFAULT '[]'::jsonb,
            capabilities JSONB NOT NULL DEFAULT '{{}}'::jsonb,
            docs_url TEXT,
            is_enabled BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    for name, column in (
        ("ix_delivery_destinations_organization_id", "organization_id"),
        ("ix_delivery_destinations_provider", "provider"),
        ("ix_delivery_destinations_mode", "mode"),
        ("ix_delivery_destinations_delivery_target", "delivery_target"),
        ("ix_delivery_destinations_credential_format", "credential_format"),
        ("ix_delivery_destinations_issuance_protocol", "issuance_protocol"),
        ("ix_delivery_destinations_compliance_profile_code", "compliance_profile_code"),
    ):
        op.execute(
            f"CREATE INDEX IF NOT EXISTS {name} ON {SCHEMA}.delivery_destinations ({column})"
        )


def downgrade() -> None:
    for name in (
        "ix_delivery_destinations_compliance_profile_code",
        "ix_delivery_destinations_issuance_protocol",
        "ix_delivery_destinations_credential_format",
        "ix_delivery_destinations_delivery_target",
        "ix_delivery_destinations_mode",
        "ix_delivery_destinations_provider",
        "ix_delivery_destinations_organization_id",
    ):
        op.execute(f"DROP INDEX IF EXISTS {SCHEMA}.{name}")
    op.execute(f"DROP TABLE IF EXISTS {SCHEMA}.delivery_destinations")
