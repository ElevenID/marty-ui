"""Fix Open Badge claim types to use valid ClaimType enum values.

Revision ID: 20260217_0003
Revises: 20260216_0002
Create Date: 2026-02-17 12:00:00.000000+00:00

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260217_0003"
down_revision = "20260216_0002"
branch_labels = None
depends_on = None


DEMO_ORG_ID = "22222222-2222-2222-2222-222222222222"
OPEN_BADGE_TEMPLATE_ID = "40000000-0000-0000-0000-000000000007"


def upgrade() -> None:
    """Fix any 'number' claim types to 'integer' in Open Badge template."""
    conn = op.get_bind()

    # Update any claims with claim_type='number' to claim_type='integer'
    # This is idempotent - safe to run multiple times
    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
            SET claims = (
                SELECT jsonb_agg(
                    CASE 
                        WHEN elem->>'claim_type' = 'number' 
                        THEN jsonb_set(elem, '{claim_type}', '"integer"')
                        ELSE elem
                    END
                )
                FROM jsonb_array_elements(claims::jsonb) elem
            )::json,
            updated_at = NOW()
            WHERE id = :template_id
              AND organization_id = :organization_id
              AND claims::jsonb::text LIKE '%"number"%'
            """
        ),
        {
            "template_id": OPEN_BADGE_TEMPLATE_ID,
            "organization_id": DEMO_ORG_ID,
        },
    )


def downgrade() -> None:
    """No downgrade needed - this is a data fix."""
    pass
