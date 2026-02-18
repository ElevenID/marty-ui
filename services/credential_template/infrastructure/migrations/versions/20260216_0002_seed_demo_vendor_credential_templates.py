"""Seed demo vendor credential templates for applicant catalog.

Revision ID: 20260216_0002
Revises: 1d669d3ded39
Create Date: 2026-02-16 17:40:00.000000+00:00

"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "20260216_0002"
down_revision = "1d669d3ded39"
branch_labels = None
depends_on = None


DEMO_ORG_ID = "22222222-2222-2222-2222-222222222222"

TEMPLATES = [
    {
        "id": "40000000-0000-0000-0000-000000000001",
        "name": "Passport",
        "description": "ICAO 9303 compliant digital travel credential with NFC capability",
        "credential_type": "passport",
        "doctype": "org.iso.18013.5.1.PASSPORT",
    },
    {
        "id": "40000000-0000-0000-0000-000000000002",
        "name": "Driver's License",
        "description": "ISO/IEC 18013-5 compliant mobile driving license",
        "credential_type": "drivers_license",
        "doctype": "org.iso.18013.5.1.mDL",
    },
    {
        "id": "40000000-0000-0000-0000-000000000003",
        "name": "National ID",
        "description": "National identity credential for verified applicants",
        "credential_type": "national_id",
        "doctype": "org.iso.18013.5.1.NID",
    },
    {
        "id": "40000000-0000-0000-0000-000000000004",
        "name": "Travel Visa",
        "description": "Digitally issued travel visa credential for approved applicants",
        "credential_type": "travel_visa",
        "doctype": "org.iso.18013.5.1.VISA",
    },
    {
        "id": "40000000-0000-0000-0000-000000000005",
        "name": "Access Badge",
        "description": "Corporate access badge credential for authorized personnel",
        "credential_type": "access_badge",
        "doctype": "com.enterprise.access.badge",
    },
    {
        "id": "40000000-0000-0000-0000-000000000006",
        "name": "Digital Travel Credential",
        "description": "Digital Travel Credential per ICAO DTC specification",
        "credential_type": "dtc",
        "doctype": "org.icao.dtc",
    },
    {
        "id": "40000000-0000-0000-0000-000000000007",
        "name": "Open Badge",
        "description": "Open Badge credential aligned with the Open Badges standard",
        "credential_type": "open_badge",
        "doctype": "org.openbadges.v3",
    },
]


def _claims_for(credential_type: str) -> list[dict]:
    common = [
        {
            "id": f"{credential_type}-claim-given-name",
            "name": "given_name",
            "display_name": "Given Name",
            "description": "First name",
            "claim_type": "string",
            "required": True,
            "selectively_disclosable": True,
            "derivable": False,
        },
        {
            "id": f"{credential_type}-claim-family-name",
            "name": "family_name",
            "display_name": "Family Name",
            "description": "Last name",
            "claim_type": "string",
            "required": True,
            "selectively_disclosable": True,
            "derivable": False,
        },
        {
            "id": f"{credential_type}-claim-date-of-birth",
            "name": "date_of_birth",
            "display_name": "Date of Birth",
            "description": "Birth date",
            "claim_type": "date",
            "required": True,
            "selectively_disclosable": True,
            "derivable": True,
        },
    ]

    if credential_type in {"passport", "travel_visa", "dtc"}:
        common.append(
            {
                "id": f"{credential_type}-claim-document-number",
                "name": "document_number",
                "display_name": "Document Number",
                "description": "Government document identifier",
                "claim_type": "string",
                "required": True,
                "selectively_disclosable": False,
                "derivable": False,
            }
        )

    return common


def upgrade() -> None:
    conn = op.get_bind()

    has_templates_table = conn.execute(
        sa.text("SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL")
    ).scalar_one()
    if not has_templates_table:
        return

    update_sql = sa.text(
        """
        UPDATE credential_template_service.credential_templates
        SET
            name = :name,
            description = :description,
            status = 'active',
            vct = :vct,
            doctype = :doctype,
            claims = CAST(:claims AS jsonb),
            privacy_posture = 'selective_disclosure',
            selective_disclosure_fields = CAST(:selective_disclosure_fields AS jsonb),
            derived_attributes = CAST(:derived_attributes AS jsonb),
            display_style = CAST(:display_style AS jsonb),
            validity_rules = CAST(:validity_rules AS jsonb),
            issuer_requirements = CAST(:issuer_requirements AS jsonb),
            supported_formats = CAST(:supported_formats AS jsonb),
            version = 1,
            updated_at = NOW()
        WHERE organization_id = :organization_id
          AND credential_type = :credential_type
        """
    )

    insert_sql = sa.text(
        """
        INSERT INTO credential_template_service.credential_templates (
            id,
            organization_id,
            name,
            description,
            status,
            credential_type,
            vct,
            doctype,
            claims,
            privacy_posture,
            selective_disclosure_fields,
            derived_attributes,
            display_style,
            validity_rules,
            issuer_requirements,
            supported_formats,
            version,
            created_at,
            updated_at
        )
        SELECT
            :id,
            :organization_id,
            :name,
            :description,
            'active',
            :credential_type,
            :vct,
            :doctype,
            CAST(:claims AS jsonb),
            'selective_disclosure',
            CAST(:selective_disclosure_fields AS jsonb),
            CAST(:derived_attributes AS jsonb),
            CAST(:display_style AS jsonb),
            CAST(:validity_rules AS jsonb),
            CAST(:issuer_requirements AS jsonb),
            CAST(:supported_formats AS jsonb),
            1,
            NOW(),
            NOW()
        WHERE NOT EXISTS (
            SELECT 1
            FROM credential_template_service.credential_templates
            WHERE organization_id = :organization_id
              AND credential_type = :credential_type
        )
        """
    )

    for template in TEMPLATES:
        claims = _claims_for(template["credential_type"])
        selective_disclosure_fields = [claim["name"] for claim in claims if claim["selectively_disclosable"]]

        payload = {
            "id": template["id"],
            "organization_id": DEMO_ORG_ID,
            "name": template["name"],
            "description": template["description"],
            "credential_type": template["credential_type"],
            "vct": f"https://marty.example/credentials/{template['credential_type']}",
            "doctype": template["doctype"],
            "claims": json.dumps(claims),
            "selective_disclosure_fields": json.dumps(selective_disclosure_fields),
            "derived_attributes": json.dumps([]),
            "display_style": json.dumps({"background_color": "#1a1a2e", "text_color": "#ffffff"}),
            "validity_rules": json.dumps({
                "default_validity_days": 365,
                "max_validity_days": 1095,
                "renewable": True,
                "renewal_window_days": 30,
                "require_revalidation": False,
            }),
            "issuer_requirements": json.dumps({"allowed_issuer_dids": []}),
            "supported_formats": json.dumps(["sd_jwt_vc", "jwt_vc"]),
        }

        conn.execute(update_sql, payload)
        conn.execute(insert_sql, payload)


def downgrade() -> None:
    conn = op.get_bind()

    has_templates_table = conn.execute(
        sa.text("SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL")
    ).scalar_one()
    if not has_templates_table:
        return

    conn.execute(
        sa.text(
            """
            DELETE FROM credential_template_service.credential_templates
            WHERE organization_id = :organization_id
              AND id = ANY(:template_ids)
            """
        ),
        {
            "organization_id": DEMO_ORG_ID,
            "template_ids": [template["id"] for template in TEMPLATES],
        },
    )
