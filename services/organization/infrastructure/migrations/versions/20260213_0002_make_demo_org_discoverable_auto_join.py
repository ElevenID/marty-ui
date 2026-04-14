"""Make demo organizations discoverable and auto-joinable.

Revision ID: 20260213_0002
Revises: 20260203_0001
Create Date: 2026-02-13 00:00:00.000000+00:00
"""

from alembic import op
import sqlalchemy as sa
from marty_common.migration_profile import skip_demo_migrations


# revision identifiers, used by Alembic.
revision = "20260213_0002"
down_revision = "20260203_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if skip_demo_migrations():
        return

    # Backfill demonstration organizations so they are:
    # - publicly discoverable
    # - open to automatic membership activation (no approval gate)
    op.execute(
        sa.text(
            """
            UPDATE organization_service.organizations
            SET
                join_mechanism = 'open',
                requires_approval = 'false',
                is_discoverable = 'true',
                updated_at = NOW()
            WHERE
                LOWER(name) IN ('demo vendor org', 'e2e test org')
                OR slug IN ('demo-vendor-org', 'e2e-org')
                OR id = '11111111-1111-1111-1111-111111111111'::uuid
            """
        )
    )


def downgrade() -> None:
    if skip_demo_migrations():
        return

    # Revert demonstration organizations to invite-only and hidden defaults.
    op.execute(
        sa.text(
            """
            UPDATE organization_service.organizations
            SET
                join_mechanism = 'invite',
                requires_approval = 'false',
                is_discoverable = 'false',
                updated_at = NOW()
            WHERE
                LOWER(name) IN ('demo vendor org', 'e2e test org')
                OR slug IN ('demo-vendor-org', 'e2e-org')
                OR id = '11111111-1111-1111-1111-111111111111'::uuid
            """
        )
    )
