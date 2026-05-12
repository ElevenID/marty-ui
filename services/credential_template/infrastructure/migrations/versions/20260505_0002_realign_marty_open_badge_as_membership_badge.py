"""Realign Marty open_badge template with membership/login semantics.

Revision ID: 20260505_0002
Revises: 20260503_0001
Create Date: 2026-05-05 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260505_0002"
down_revision = "20260503_0001"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"
UPDATED_AT = "2026-05-05T00:00:00+00:00"
LEGACY_UPDATED_AT = "2026-03-23T00:00:00+00:00"

UPDATED_CLAIMS = [
    {
        "id": "marty-ob-member-id",
        "name": "member_id",
        "display_name": "Member ID",
        "description": "Opaque member identifier issued by the organization",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-ob-email",
        "name": "email",
        "display_name": "Email Address",
        "description": "Holder email address used to resolve the account during login",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-ob-given-name",
        "name": "given_name",
        "display_name": "Given Name",
        "description": "Holder first name",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-ob-family-name",
        "name": "family_name",
        "display_name": "Family Name",
        "description": "Holder last name",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-ob-organization-id",
        "name": "organization_id",
        "display_name": "Organization ID",
        "description": "UUID of the issuing organization",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-ob-organization-name",
        "name": "organization_name",
        "display_name": "Organization Name",
        "description": "Human-readable name of the issuing organization",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-ob-role",
        "name": "role",
        "display_name": "Role",
        "description": "Organization role conveyed during credential-based login",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
        "enum_values": ["applicant", "vendor", "administrator"],
    },
    {
        "id": "marty-ob-achievement-name",
        "name": "achievement_name",
        "display_name": "Achievement Name",
        "description": "Badge title describing the holder's verified membership recognition",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-ob-achievement-description",
        "name": "achievement_description",
        "display_name": "Achievement Description",
        "description": "Description of the membership recognition represented by this badge",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-ob-issued-at",
        "name": "issued_at",
        "display_name": "Issued At",
        "description": "ISO-8601 timestamp when the badge was issued",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
]

LEGACY_CLAIMS = [
    {
        "id": "marty-ob-given-name",
        "name": "given_name",
        "display_name": "Given Name",
        "description": "Recipient first name",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-ob-family-name",
        "name": "family_name",
        "display_name": "Family Name",
        "description": "Recipient last name",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-ob-email",
        "name": "email",
        "display_name": "Email Address",
        "description": "Recipient email",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-ob-achievement-name",
        "name": "achievement_name",
        "display_name": "Achievement Name",
        "description": "Name of the achievement or certification",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-ob-course-name",
        "name": "course_name",
        "display_name": "Course Name",
        "description": "Course or program name",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-ob-completion-date",
        "name": "completion_date",
        "display_name": "Completion Date",
        "description": "Date of course completion",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-ob-institution-name",
        "name": "institution_name",
        "display_name": "Institution Name",
        "description": "Name of issuing institution",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-ob-certificate-id",
        "name": "certificate_id",
        "display_name": "Certificate ID",
        "description": "Unique certificate identifier",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-ob-grade",
        "name": "grade",
        "display_name": "Grade",
        "description": "Grade or score received",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-ob-credit-hours",
        "name": "credit_hours",
        "display_name": "Credit Hours",
        "description": "Credit hours earned",
        "claim_type": "integer",
        "required": False,
        "selectively_disclosable": False,
        "derivable": False,
    },
]


def _has_table(conn) -> bool:
    return bool(
        conn.execute(
            sa.text(
                "SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL"
            )
        ).scalar()
    )


def _apply_template(conn, *, name: str, description: str, claims: list[dict], version: int, updated_at: str) -> None:
    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET name = :name,
                   description = :description,
                   claims = CAST(:claims AS jsonb),
                   selective_disclosure_fields = CAST(:selective_disclosure_fields AS jsonb),
                   version = :version,
                   updated_at = :updated_at
             WHERE id = :id
               AND organization_id = :organization_id
            """
        ),
        {
            "id": OPEN_BADGE_TEMPLATE_ID,
            "organization_id": MARTY_ORG_ID,
            "name": name,
            "description": description,
            "claims": json.dumps(claims),
            "selective_disclosure_fields": json.dumps(
                [claim["name"] for claim in claims if claim.get("selectively_disclosable")]
            ),
            "version": version,
            "updated_at": updated_at,
        },
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    _apply_template(
        conn,
        name="Verified Member Badge",
        description=(
            "Open Badge 3.0-compatible membership credential — verifiable proof "
            "of active organization membership that can be presented for "
            "passwordless sign-in where accepted."
        ),
        claims=UPDATED_CLAIMS,
        version=2,
        updated_at=UPDATED_AT,
    )


def downgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    _apply_template(
        conn,
        name="Professional Certificate (Open Badge)",
        description=(
            "Open Badge 3.0 professional development certificate — instantly "
            "issued, recognized by employers and institutions worldwide."
        ),
        claims=LEGACY_CLAIMS,
        version=1,
        updated_at=LEGACY_UPDATED_AT,
    )
