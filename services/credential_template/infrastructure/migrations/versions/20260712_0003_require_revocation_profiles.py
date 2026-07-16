"""Require active Credential Templates to have a Revocation Profile.

Revision ID: 20260712_0003
Revises: 20260712_0002
Create Date: 2026-07-12 19:22:00.000000+00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "20260712_0003"
down_revision = "20260712_0002"
branch_labels = None
depends_on = None

SCHEMA = "credential_template_service"
TABLE = "credential_templates"


def upgrade() -> None:
    op.execute(
        sa.text(
            f"""
            WITH sole_active_profile AS (
                SELECT organization_id, min(id) AS profile_id
                FROM revocation_profile_service.revocation_profiles
                WHERE lower(status) = 'active'
                GROUP BY organization_id
                HAVING count(*) = 1
            )
            UPDATE {SCHEMA}.{TABLE} AS template
            SET revocation_profile_id = profile.profile_id,
                updated_at = now()
            FROM sole_active_profile AS profile
            WHERE template.organization_id = profile.organization_id
              AND lower(template.status) = 'active'
              AND nullif(trim(template.revocation_profile_id), '') IS NULL
            """
        )
    )
    op.execute(
        sa.text(
            f"""
            UPDATE {SCHEMA}.{TABLE}
            SET status = 'deprecated',
                updated_at = now()
            WHERE lower(status) = 'active'
              AND nullif(trim(revocation_profile_id), '') IS NULL
            """
        )
    )


def downgrade() -> None:
    raise RuntimeError("The MIP 0.3 revocation dependency migration is one-way.")
