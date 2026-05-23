"""Add missing owner_id column to organizations.

Revision ID: 20260513_0001
Revises: 20260507_0002
Create Date: 2026-05-13 00:00:00.000000+00:00

Some long-lived self-host databases were initialized from an older copy of the
initial organization migration that did not include owner_id, while Alembic now
reports them at the latest revision. Keep this migration idempotent so those
deployments can converge without affecting fresh databases that already have
the column.
"""

from __future__ import annotations

from alembic import op


revision = "20260513_0001"
down_revision = "20260507_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE organization_service.organizations
        ADD COLUMN IF NOT EXISTS owner_id VARCHAR(255)
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE organization_service.organizations
        DROP COLUMN IF EXISTS owner_id
        """
    )