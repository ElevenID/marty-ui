"""Add plan and plan_expires_at columns to organizations.

Revision ID: 20260327_0000
Revises: 20260323_0002
Create Date: 2026-03-27 00:00:00.000000+00:00

Adds plan tier tracking and expiration to support feature gating
and usage-based billing.
"""

from alembic import op
import sqlalchemy as sa


revision = "20260327_0000"
down_revision = "20260323_0002"
branch_labels = None
depends_on = None

SCHEMA = "organization_service"


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column("plan", sa.String(50), nullable=False, server_default="free"),
        schema=SCHEMA,
    )
    op.add_column(
        "organizations",
        sa.Column("plan_expires_at", sa.DateTime(timezone=True), nullable=True),
        schema=SCHEMA,
    )
    op.create_index(
        "ix_organizations_plan",
        "organizations",
        ["plan"],
        schema=SCHEMA,
    )


def downgrade() -> None:
    op.drop_index("ix_organizations_plan", table_name="organizations", schema=SCHEMA)
    op.drop_column("organizations", "plan_expires_at", schema=SCHEMA)
    op.drop_column("organizations", "plan", schema=SCHEMA)
