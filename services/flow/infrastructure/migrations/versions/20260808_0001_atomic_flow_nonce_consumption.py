"""Commit flow nonce consumption with the terminal verification result.

Revision ID: 20260808_0001
Revises: 20260712_0001
"""

from alembic import op
import sqlalchemy as sa


revision = "20260808_0001"
down_revision = "20260712_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "flow_nonce_consumptions",
        sa.Column("nonce_digest", sa.String(length=64), nullable=False),
        sa.Column("flow_instance_id", sa.String(length=36), nullable=False),
        sa.Column(
            "consumed_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("nonce_digest"),
        sa.UniqueConstraint(
            "flow_instance_id",
            name="uq_flow_nonce_consumptions_flow_instance_id",
        ),
        schema="flow_service",
    )
    op.create_index(
        "ix_flow_nonce_consumptions_expires_at",
        "flow_nonce_consumptions",
        ["expires_at"],
        unique=False,
        schema="flow_service",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_flow_nonce_consumptions_expires_at",
        table_name="flow_nonce_consumptions",
        schema="flow_service",
    )
    op.drop_table("flow_nonce_consumptions", schema="flow_service")
