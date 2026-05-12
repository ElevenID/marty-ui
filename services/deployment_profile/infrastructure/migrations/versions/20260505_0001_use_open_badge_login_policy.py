"""Use OpenBadgeLogin policy in the Marty login deployment profile.

Revision ID: 20260505_0001
Revises: 20260416_0003
Create Date: 2026-05-05 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260505_0001"
down_revision = "20260416_0003"
branch_labels = None
depends_on = None


MARTY_DEPLOYMENT_PROFILE_ID = "70000000-0000-0000-0000-000000000001"
LEGACY_MEMBER_POLICY_ID = "50000000-0000-0000-0000-000000000002"
LEGACY_MEMBER_TEMPLATE_ID = "50000000-0000-0000-0000-000000000010"
OPEN_BADGE_POLICY_ID = "50000000-0000-0000-0000-000000000004"
OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"
NOW = "2026-05-05T00:00:00+00:00"


def _has_table(conn) -> bool:
    return bool(
        conn.execute(
            sa.text(
                "SELECT to_regclass('deployment_profile_service.deployment_profiles') IS NOT NULL"
            )
        ).scalar()
    )


def _set_profile(conn, *, policy_id: str, template_id: str) -> None:
    conn.execute(
        sa.text(
            """
            UPDATE deployment_profile_service.deployment_profiles
               SET presentation_policy_ids = CAST(:presentation_policy_ids AS json),
                   credential_template_ids = CAST(:credential_template_ids AS json),
                   default_policy_id = :policy_id,
                   default_presentation_policy_id = :policy_id,
                   updated_at = :updated_at
             WHERE id = :id
            """
        ),
        {
            "id": MARTY_DEPLOYMENT_PROFILE_ID,
            "policy_id": policy_id,
            "presentation_policy_ids": json.dumps([policy_id]),
            "credential_template_ids": json.dumps([template_id]),
            "updated_at": NOW,
        },
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return
    _set_profile(conn, policy_id=OPEN_BADGE_POLICY_ID, template_id=OPEN_BADGE_TEMPLATE_ID)


def downgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return
    _set_profile(conn, policy_id=LEGACY_MEMBER_POLICY_ID, template_id=LEGACY_MEMBER_TEMPLATE_ID)
