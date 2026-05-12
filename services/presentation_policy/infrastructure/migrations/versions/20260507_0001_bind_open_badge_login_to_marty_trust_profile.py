"""Bind OpenBadgeLogin to the Marty DID-backed trust profile.

Revision ID: 20260507_0001
Revises: 20260505_0001
Create Date: 2026-05-07 00:00:00.000000+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260507_0001"
down_revision = "20260505_0001"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
MARTY_TRUST_PROFILE_ID = "60000000-0000-0000-0000-000000000001"
OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"
OPEN_BADGE_POLICY_ID = "50000000-0000-0000-0000-000000000004"


def _has_table(conn) -> bool:
    return bool(
        conn.execute(
            sa.text(
                "SELECT to_regclass('presentation_policy_service.presentation_policies') IS NOT NULL"
            )
        ).scalar()
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    conn.execute(
        sa.text(
            """
            UPDATE presentation_policy_service.presentation_policies AS pp
                    SET credential_requirements = patched.requirements,
                   updated_at = NOW()
              FROM (
                    SELECT id,
                           json_agg(
                               CASE
                                   WHEN elem->>'id' = 'req-marty-open-badge-login'
                                     OR elem->>'credential_template_id' = :template_id
                                   THEN jsonb_set(elem::jsonb, '{trust_profile_id}', to_jsonb(CAST(:trust_profile_id AS text)), true)::json
                                   ELSE elem
                               END
                           ) AS requirements
                      FROM presentation_policy_service.presentation_policies,
                           json_array_elements(credential_requirements) AS elem
                     WHERE id = :policy_id
                       AND organization_id = :organization_id
                     GROUP BY id
                   ) AS patched
             WHERE pp.id = patched.id
            """
        ),
        {
            "policy_id": OPEN_BADGE_POLICY_ID,
            "organization_id": MARTY_ORG_ID,
            "template_id": OPEN_BADGE_TEMPLATE_ID,
            "trust_profile_id": MARTY_TRUST_PROFILE_ID,
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    conn.execute(
        sa.text(
            """
            UPDATE presentation_policy_service.presentation_policies AS pp
                    SET credential_requirements = patched.requirements,
                   updated_at = NOW()
              FROM (
                    SELECT id,
                           json_agg(
                               CASE
                                   WHEN elem->>'id' = 'req-marty-open-badge-login'
                                     OR elem->>'credential_template_id' = :template_id
                                   THEN jsonb_set(elem::jsonb, '{trust_profile_id}', 'null'::jsonb, true)::json
                                   ELSE elem
                               END
                           ) AS requirements
                      FROM presentation_policy_service.presentation_policies,
                           json_array_elements(credential_requirements) AS elem
                     WHERE id = :policy_id
                       AND organization_id = :organization_id
                     GROUP BY id
                   ) AS patched
             WHERE pp.id = patched.id
            """
        ),
        {
            "policy_id": OPEN_BADGE_POLICY_ID,
            "organization_id": MARTY_ORG_ID,
            "template_id": OPEN_BADGE_TEMPLATE_ID,
        },
    )