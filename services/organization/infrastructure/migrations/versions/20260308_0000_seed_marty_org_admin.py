"""Seed the Marty org admin member from MARTY_ORG_ADMIN_EMAIL env var.

Revision ID: 20260308_0000
Revises: 20260303_0001
Create Date: 2026-03-08 00:00:00.000000+00:00

Inserts (or promotes) a member record for the configured admin email address
so that the first person to log in with that email is immediately granted the
'admin' role in the Marty organisation.

If the member already exists (e.g. they logged in before this migration ran)
their role is updated to 'admin'.  If the env var is not set the migration is
a no-op.
"""

import os
import uuid
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260308_0000"
down_revision = "20260303_0001"
branch_labels = None
depends_on = None

MARTY_ORG_ID = os.environ.get("MARTY_ORG_ID", "00000000-0000-0000-0000-000000000001")
MARTY_ORG_ADMIN_EMAIL = os.environ.get("MARTY_ORG_ADMIN_EMAIL", "").strip().lower()

SCHEMA = "organization_service"


def upgrade() -> None:
    if not MARTY_ORG_ADMIN_EMAIL:
        return

    conn = op.get_bind()
    now = datetime.now(timezone.utc)

    # Promote to admin if they're already a member (e.g. logged in before this ran)
    result = conn.execute(
        sa.text(
            f"""
            UPDATE {SCHEMA}.members
               SET role       = 'admin',
                   updated_at = :now
             WHERE organization_id = CAST(:org_id AS uuid)
               AND LOWER(email)    = :email
            """
        ),
        {"org_id": MARTY_ORG_ID, "email": MARTY_ORG_ADMIN_EMAIL, "now": now},
    )

    if result.rowcount > 0:
        return  # Already existed — role upgraded, done

    # Not a member yet — pre-seed so the first login links this record
    conn.execute(
        sa.text(
            f"""
            INSERT INTO {SCHEMA}.members
                (id, organization_id, user_id, email, role, status, created_at, updated_at)
            VALUES
                (CAST(:id AS uuid), CAST(:org_id AS uuid), '', :email, 'admin', 'active', :now, :now)
            ON CONFLICT DO NOTHING
            """
        ),
        {
            "id": str(uuid.uuid4()),
            "org_id": MARTY_ORG_ID,
            "email": MARTY_ORG_ADMIN_EMAIL,
            "now": now,
        },
    )


def downgrade() -> None:
    if not MARTY_ORG_ADMIN_EMAIL:
        return

    conn = op.get_bind()
    conn.execute(
        sa.text(
            f"""
            UPDATE {SCHEMA}.members
               SET role       = 'member',
                   updated_at = NOW()
             WHERE organization_id = CAST(:org_id AS uuid)
               AND LOWER(email)    = :email
               AND role            = 'admin'
            """
        ),
        {"org_id": MARTY_ORG_ID, "email": MARTY_ORG_ADMIN_EMAIL},
    )
