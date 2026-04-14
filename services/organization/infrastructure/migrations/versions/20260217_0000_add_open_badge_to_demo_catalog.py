"""Update Open Badge credential template to education-specific use case.

Revision ID: 20260217_0000
Revises: 20260216_0001
Create Date: 2026-02-17 00:00:00.000000+00:00
"""

from alembic import op
import sqlalchemy as sa
import json
from marty_common.migration_profile import skip_demo_migrations


# revision identifiers, used by Alembic.
revision = "20260217_0000"
down_revision = "20260216_0001"
branch_labels = None
depends_on = None


DEMO_ORG_ID = "22222222-2222-2222-2222-222222222222"
OPEN_BADGE_TEMPLATE_ID = "40000000-0000-0000-0000-000000000007"

OPEN_BADGE_CLAIMS = [
    {"id": "family-name", "name": "family_name", "required": True, "derivable": False, "claim_type": "string", "description": "Recipient last name", "display_name": "Family Name", "selectively_disclosable": False},
    {"id": "given-name", "name": "given_name", "required": True, "derivable": False, "claim_type": "string", "description": "Recipient first name", "display_name": "Given Name", "selectively_disclosable": False},
    {"id": "achievement-name", "name": "achievement_name", "required": True, "derivable": False, "claim_type": "string", "description": "Name of the achievement or certification", "display_name": "Achievement Name", "selectively_disclosable": False},
    {"id": "course-name", "name": "course_name", "required": True, "derivable": False, "claim_type": "string", "description": "Course or program name", "display_name": "Course Name", "selectively_disclosable": False},
    {"id": "completion-date", "name": "completion_date", "required": True, "derivable": False, "claim_type": "date", "description": "Date of course completion", "display_name": "Completion Date", "selectively_disclosable": False},
    {"id": "institution-name", "name": "institution_name", "required": True, "derivable": False, "claim_type": "string", "description": "Name of issuing institution", "display_name": "Institution Name", "selectively_disclosable": False},
    {"id": "badge-image", "name": "badge_image", "required": False, "derivable": False, "claim_type": "string", "description": "URL to badge image", "display_name": "Badge Image", "selectively_disclosable": False},
    {"id": "achievement-criteria", "name": "achievement_criteria", "required": False, "derivable": False, "claim_type": "string", "description": "Criteria for earning the badge", "display_name": "Achievement Criteria", "selectively_disclosable": False},
    {"id": "grade", "name": "grade", "required": False, "derivable": False, "claim_type": "string", "description": "Grade or score received", "display_name": "Grade", "selectively_disclosable": False},
    {"id": "credit-hours", "name": "credit_hours", "required": False, "derivable": False, "claim_type": "integer", "description": "Credit hours earned", "display_name": "Credit Hours", "selectively_disclosable": False},
    {"id": "instructor-name", "name": "instructor_name", "required": False, "derivable": False, "claim_type": "string", "description": "Name of the instructor", "display_name": "Instructor Name", "selectively_disclosable": False},
    {"id": "certificate-id", "name": "certificate_id", "required": False, "derivable": False, "claim_type": "string", "description": "Unique certificate identifier", "display_name": "Certificate ID", "selectively_disclosable": False},
]


def upgrade() -> None:
    if skip_demo_migrations():
        return

    conn = op.get_bind()

    # Check if credential_template_service.credential_templates table exists
    has_credential_templates = conn.execute(
        sa.text("SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL")
    ).scalar()

    if not has_credential_templates:
        return

    # Update Open Badge template to education sector use case
    update_sql = sa.text(
        """
        UPDATE credential_template_service.credential_templates
        SET
            name = :name,
            description = :description,
            claims = CAST(:claims AS json),
            updated_at = NOW()
        WHERE id = :template_id
          AND organization_id = :organization_id
        """
    )

    params = {
        "template_id": OPEN_BADGE_TEMPLATE_ID,
        "organization_id": DEMO_ORG_ID,
        "name": "Professional Development Certificate",
        "description": "Professional Development Certificate - Open Badge 3.0 credential for continuing education and professional development",
        "claims": json.dumps(OPEN_BADGE_CLAIMS),
    }
    
    conn.execute(update_sql, params)


def downgrade() -> None:
    if skip_demo_migrations():
        return

    conn = op.get_bind()

    has_credential_templates = conn.execute(
        sa.text("SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL")
    ).scalar()

    if has_credential_templates:
        # Revert to original Open Badge template (with basic claims)
        original_claims = [
            {"id": "open_badge-claim-given-name", "name": "given_name", "required": True, "derivable": False, "claim_type": "string", "description": "First name", "display_name": "Given Name", "selectively_disclosable": True},
            {"id": "open_badge-claim-family-name", "name": "family_name", "required": True, "derivable": False, "claim_type": "string", "description": "Last name", "display_name": "Family Name", "selectively_disclosable": True},
            {"id": "open_badge-claim-date-of-birth", "name": "date_of_birth", "required": True, "derivable": True, "claim_type": "date", "description": "Birth date", "display_name": "Date of Birth", "selectively_disclosable": True},
        ]
        
        conn.execute(
            sa.text(
                """
                UPDATE credential_template_service.credential_templates
                SET
                    name = 'Open Badge',
                    description = 'Open Badge credential aligned with the Open Badges standard',
                    claims = CAST(:claims AS json),
                    updated_at = NOW()
                WHERE id = :template_id
                  AND organization_id = :organization_id
                """
            ),
            {
                "template_id": OPEN_BADGE_TEMPLATE_ID,
                "organization_id": DEMO_ORG_ID,
                "claims": json.dumps(original_claims),
            },
        )
