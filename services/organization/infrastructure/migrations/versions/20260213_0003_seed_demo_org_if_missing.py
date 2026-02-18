"""Seed demo organization if missing and enforce discoverable auto-join settings.

Revision ID: 20260213_0003
Revises: 20260213_0002
Create Date: 2026-02-13 00:10:00.000000+00:00
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260213_0003"
down_revision = "20260213_0002"
branch_labels = None
depends_on = None


DEMO_ORG_ID = "22222222-2222-2222-2222-222222222222"
DEMO_ORG_NAME = "Demo Vendor Org"
DEMO_ORG_SLUG = "demo-vendor-org"


def upgrade() -> None:
    # Insert Demo Vendor Org if it is missing.
    conn = op.get_bind()
    conn.execute(
        sa.text(
            f"""
            INSERT INTO organization_service.organizations (
                id,
                name,
                display_name,
                slug,
                description,
                org_type,
                status,
                join_mechanism,
                requires_approval,
                is_discoverable,
                settings,
                created_at,
                updated_at
            )
            SELECT
                '{DEMO_ORG_ID}'::uuid,
                '{DEMO_ORG_NAME}',
                '{DEMO_ORG_NAME}',
                '{DEMO_ORG_SLUG}',
                'Demo organization for context switching and join/discovery demonstrations',
                'startup',
                'active',
                'open',
                false,
                true,
                '{{}}'::jsonb,
                NOW(),
                NOW()
            WHERE NOT EXISTS (
                SELECT 1
                FROM organization_service.organizations
                WHERE id = '{DEMO_ORG_ID}'::uuid
                   OR slug = '{DEMO_ORG_SLUG}'
                   OR LOWER(name) = LOWER('{DEMO_ORG_NAME}')
            )
            """
        )
    )

    # Ensure both demo orgs are discoverable + auto-joinable.
    conn.execute(
        sa.text(
            f"""
            UPDATE organization_service.organizations
            SET
                join_mechanism = 'open',
                requires_approval = false,
                is_discoverable = true,
                updated_at = NOW()
            WHERE
                LOWER(name) IN ('demo vendor org', 'e2e test org')
                OR slug IN ('demo-vendor-org', 'e2e-org')
                OR id IN (
                    '11111111-1111-1111-1111-111111111111'::uuid,
                    '{DEMO_ORG_ID}'::uuid
                )
            """
        )
    )


def downgrade() -> None:
    # Revert demo org settings.
    conn = op.get_bind()
    conn.execute(
        sa.text(
            f"""
            UPDATE organization_service.organizations
            SET
                join_mechanism = 'invite',
                requires_approval = false,
                is_discoverable = false,
                updated_at = NOW()
            WHERE
                LOWER(name) IN ('demo vendor org', 'e2e test org')
                OR slug IN ('demo-vendor-org', 'e2e-org')
                OR id IN (
                    '11111111-1111-1111-1111-111111111111'::uuid,
                    '{DEMO_ORG_ID}'::uuid
                )
            """
        )
    )

    # Remove seeded demo org only if it matches our seed identifiers.
    conn.execute(
        sa.text(
            f"""
            DELETE FROM organization_service.organizations
            WHERE id = '{DEMO_ORG_ID}'::uuid
              AND slug = '{DEMO_ORG_SLUG}'
              AND LOWER(name) = LOWER('{DEMO_ORG_NAME}')
            """
        )
    )
