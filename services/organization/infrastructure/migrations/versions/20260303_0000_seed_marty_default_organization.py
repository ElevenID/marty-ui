"""Seed Marty default organization that all users join automatically.

Revision ID: 20260303_0000
Revises: 20260217_0000
Create Date: 2026-03-03 00:00:00.000000+00:00

This migration creates the "Marty" organization, which serves as the default
organization that every user is automatically added to upon registration.
The organization represents the Marty platform itself and provides essential
capabilities like user authentication credentials in its catalog.
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260303_0000"
down_revision = "20260217_0000"
branch_labels = None
depends_on = None


# Stable ID for Marty default organization
MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
MARTY_ORG_NAME = "Marty"
MARTY_ORG_SLUG = "marty"


def upgrade() -> None:
    """
    Insert the Marty default organization if it doesn't exist.
    
    The Marty organization is the platform's default organization that:
    - All users are automatically members of
    - Provides the user login credential in its catalog
    - Represents the core Marty platform services
    - Is configured for internal system use (not discoverable for browsing)
    """
    conn = op.get_bind()
    conn.execute(
        sa.text(
            """
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
                contact_email,
                website,
                settings,
                created_at,
                updated_at
            )
            SELECT
                CAST(:org_id AS uuid),
                :name,
                :display_name,
                :slug,
                :description,
                'enterprise',
                'active',
                'invite',
                false,
                false,
                'support@marty.com',
                'https://marty.com',
                '{}'::jsonb,
                NOW(),
                NOW()
            WHERE NOT EXISTS (
                SELECT 1
                FROM organization_service.organizations
                WHERE id = CAST(:org_id AS uuid)
                   OR slug = :slug
                   OR LOWER(name) = LOWER(:name)
            )
            """
        ),
        {
            "org_id": MARTY_ORG_ID,
            "name": MARTY_ORG_NAME,
            "display_name": "Marty Identity Platform",
            "slug": MARTY_ORG_SLUG,
            "description": "The Marty Identity Platform provides secure, privacy-preserving digital identity solutions. All users are members of this organization and have access to core authentication capabilities.",
        }
    )


def downgrade() -> None:
    """
    Remove the Marty default organization.
    
    Note: This will also cascade delete all memberships and related data.
    Use with caution in production environments.
    """
    conn = op.get_bind()
    conn.execute(
        sa.text(
            """
            DELETE FROM organization_service.organizations
            WHERE id = CAST(:org_id AS uuid)
               OR slug = :slug
               OR LOWER(name) = LOWER(:name)
            """
        ),
        {
            "org_id": MARTY_ORG_ID,
            "slug": MARTY_ORG_SLUG,
            "name": MARTY_ORG_NAME,
        }
    )
