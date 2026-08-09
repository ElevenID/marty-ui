"""Persist application-flow reservations and OID4VCI artifacts.

Revision ID: 20260809_0001
Revises: 20260712_0001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "20260809_0001"
down_revision = "20260712_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "flow_instances",
        sa.Column("application_flow_key_hash", sa.String(length=64), nullable=True),
        schema="flow_service",
    )
    op.create_check_constraint(
        "ck_flow_instances_application_flow_key_hash",
        "flow_instances",
        "application_flow_key_hash IS NULL OR "
        "application_flow_key_hash ~ '^[0-9a-f]{64}$'",
        schema="flow_service",
    )
    op.create_index(
        "ux_flow_instances_org_application_flow_key",
        "flow_instances",
        ["organization_id", "application_flow_key_hash"],
        unique=True,
        schema="flow_service",
    )
    op.create_table(
        "flow_application_event_receipts",
        sa.Column("event_id_sha256", sa.String(length=64), nullable=False),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("organization_id", sa.String(length=255), nullable=False),
        sa.Column("application_id", sa.String(length=255), nullable=False),
        sa.Column(
            "flow_plan",
            postgresql.JSON(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.CheckConstraint(
            "event_id_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_flow_application_event_receipts_event_hash",
        ),
        sa.CheckConstraint(
            "payload_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_flow_application_event_receipts_payload_hash",
        ),
        sa.PrimaryKeyConstraint("event_id_sha256"),
        schema="flow_service",
    )
    op.create_index(
        "ix_flow_application_event_receipts_org_application",
        "flow_application_event_receipts",
        ["organization_id", "application_id"],
        unique=False,
        schema="flow_service",
    )
    op.create_table(
        "flow_instance_artifacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("flow_instance_id", sa.String(length=36), nullable=False),
        sa.Column("issuance_transaction_id", sa.String(length=36), nullable=True),
        sa.Column("credential_offer_uri", sa.Text(), nullable=True),
        sa.Column(
            "credential_offer_uris",
            postgresql.JSON(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column(
            "credential_offer_labels",
            postgresql.JSON(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("pre_authorized_code", sa.String(length=255), nullable=True),
        sa.Column("issuance_status", sa.String(length=50), nullable=True),
        sa.Column("qr_payload", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("state", sa.String(length=255), nullable=True),
        sa.Column(
            "wallet_metadata",
            postgresql.JSON(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("attempt_number", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.ForeignKeyConstraint(
            ["flow_instance_id"],
            ["flow_service.flow_instances.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="flow_service",
    )
    op.create_index(
        "ux_flow_instance_artifacts_issuance_transaction_id",
        "flow_instance_artifacts",
        ["issuance_transaction_id"],
        unique=True,
        schema="flow_service",
    )
    op.create_index(
        "ix_flow_instance_artifacts_pre_authorized_code",
        "flow_instance_artifacts",
        ["pre_authorized_code"],
        unique=False,
        schema="flow_service",
    )


def downgrade() -> None:
    op.drop_index(
        "ux_flow_instance_artifacts_issuance_transaction_id",
        table_name="flow_instance_artifacts",
        schema="flow_service",
    )
    op.drop_index(
        "ix_flow_instance_artifacts_pre_authorized_code",
        table_name="flow_instance_artifacts",
        schema="flow_service",
    )
    op.drop_table("flow_instance_artifacts", schema="flow_service")
    op.drop_index(
        "ix_flow_application_event_receipts_org_application",
        table_name="flow_application_event_receipts",
        schema="flow_service",
    )
    op.drop_table(
        "flow_application_event_receipts",
        schema="flow_service",
    )
    op.drop_index(
        "ux_flow_instances_org_application_flow_key",
        table_name="flow_instances",
        schema="flow_service",
    )
    op.drop_constraint(
        "ck_flow_instances_application_flow_key_hash",
        "flow_instances",
        schema="flow_service",
        type_="check",
    )
    op.drop_column(
        "flow_instances",
        "application_flow_key_hash",
        schema="flow_service",
    )
