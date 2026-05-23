"""Archive showcase templates from the self-host production catalog.

Self-host production should ship with only the Open Badge login credential in
the applicant catalog.  Beta/dev keep the broader showcase catalog, but the
self-host customer deployment should not expose those demo/product examples by
default.

This migration is intentionally forward-only and scoped to known built-in Marty
system template IDs so customer-created templates are not touched.

Revision ID: 20260518_0001
Revises: 20260517_0001
Create Date: 2026-05-18 00:00:00.000000+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

from marty_common.migration_profile import migration_profile


revision = "20260518_0001"
down_revision = "20260517_0001"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"
SELFHOST_ARCHIVED_TEMPLATE_IDS = (
    "50000000-0000-0000-0000-000000000010",  # Member Login Credential (legacy SD-JWT)
    "50000000-0000-0000-0000-000000000020",  # Mobile Driving Licence (mDL)
    "50000000-0000-0000-0000-000000000030",  # Membership ID (mDoc)
    "50000000-0000-0000-0000-000000000050",  # Employee Access Badge
    "50000000-0000-0000-0000-000000000060",  # ICAO ePassport / MRV
    "50000000-0000-0000-0000-000000000070",  # ICAO DTC Type 1
    "50000000-0000-0000-0000-000000000080",  # ICAO DTC Type 2
    "50000000-0000-0000-0000-000000000090",  # ICAO Visa
    "50000000-0000-0000-0000-0000000000a0",  # ICAO Emergency Travel Document
)


def _has_table(conn) -> bool:
    return bool(
        conn.execute(
            sa.text("SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL")
        ).scalar()
    )


def upgrade() -> None:
    if migration_profile() != "selfhost-production":
        return

    conn = op.get_bind()
    if not _has_table(conn):
        return

    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET status = 'archived',
                   updated_at = NOW()
             WHERE organization_id = :organization_id
               AND id = ANY(:template_ids)
               AND status <> 'archived'
            """
        ),
        {
            "organization_id": MARTY_ORG_ID,
            "template_ids": list(SELFHOST_ARCHIVED_TEMPLATE_IDS),
        },
    )
    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET status = 'active',
                   updated_at = NOW()
             WHERE organization_id = :organization_id
               AND id = :open_badge_template_id
               AND status <> 'active'
            """
        ),
        {
            "organization_id": MARTY_ORG_ID,
            "open_badge_template_id": OPEN_BADGE_TEMPLATE_ID,
        },
    )


def downgrade() -> None:
    # Do not reactivate archived showcase templates in persistent self-host data.
    pass