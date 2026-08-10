"""Persist verification callbacks with terminal flow decisions.

Revision ID: 20260808_0002
Revises: 20260808_0001
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260808_0002"
down_revision = "20260808_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "flow_callback_outbox",
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("flow_instance_id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=255), nullable=False),
        sa.Column("destination_url", sa.Text(), nullable=False),
        sa.Column("audience", sa.String(length=255), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("payload", postgresql.JSON(), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            nullable=False,
            server_default="pending",
        ),
        sa.Column(
            "attempt_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_token", sa.String(length=36), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending', 'delivering', 'retry', 'delivered', 'dead_letter', 'expired')",
            name="ck_flow_callback_outbox_status",
        ),
        sa.ForeignKeyConstraint(
            ["flow_instance_id"],
            ["flow_service.flow_instances.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("event_id"),
        sa.UniqueConstraint("flow_instance_id"),
        schema="flow_service",
    )
    op.create_index(
        "ix_flow_callback_outbox_due",
        "flow_callback_outbox",
        ["status", "next_attempt_at"],
        unique=False,
        schema="flow_service",
    )
    op.create_index(
        "ix_flow_callback_outbox_expires_at",
        "flow_callback_outbox",
        ["expires_at"],
        unique=False,
        schema="flow_service",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_flow_callback_outbox_expires_at",
        table_name="flow_callback_outbox",
        schema="flow_service",
    )
    op.drop_index(
        "ix_flow_callback_outbox_due",
        table_name="flow_callback_outbox",
        schema="flow_service",
    )
    op.drop_table("flow_callback_outbox", schema="flow_service")
