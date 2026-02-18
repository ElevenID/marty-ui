"""Expand demo vendor catalog artifacts with additional credential types.

Revision ID: 20260216_0001
Revises: 20260216_0000
Create Date: 2026-02-16 00:30:00.000000+00:00
"""

from alembic import op
import sqlalchemy as sa
import json


# revision identifiers, used by Alembic.
revision = "20260216_0001"
down_revision = "20260216_0000"
branch_labels = None
depends_on = None


DEMO_ORG_ID = "22222222-2222-2222-2222-222222222222"

ADDITIONAL_DEMO_CREDENTIAL_ROWS = [
    {
        "id": "demo-travel-visa-credential-type",
        "name": "travel_visa",
        "description": "Demo Travel Visa Credential",
        "format": "jwt_vc_json",
        "schema_definition": {
            "required_fields": [
                "given_name",
                "family_name",
                "birth_date",
                "nationality",
                "document_number",
            ],
            "optional_fields": [
                "portrait",
                "visa_type",
                "valid_from",
                "valid_until",
                "issuing_country",
            ],
            "doctype": "org.marty.travel.visa.1",
        },
        "display_config": {
            "display_name": "Demo Travel Visa Credential",
            "is_published": True,
            "is_system_template": False,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "2-3 business days",
        },
    },
    {
        "id": "demo-access-badge-credential-type",
        "name": "access_badge",
        "description": "Demo Access Badge Credential",
        "format": "jwt_vc_json",
        "schema_definition": {
            "required_fields": [
                "given_name",
                "family_name",
                "employee_id",
            ],
            "optional_fields": [
                "portrait",
                "department",
                "access_level",
                "valid_from",
                "valid_until",
            ],
            "doctype": "org.marty.access.badge.1",
        },
        "display_config": {
            "display_name": "Demo Access Badge Credential",
            "is_published": True,
            "is_system_template": False,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "1-2 business days",
        },
    },
    {
        "id": "demo-dtc-credential-type",
        "name": "dtc",
        "description": "Demo DTC Credential",
        "format": "jwt_vc_json",
        "schema_definition": {
            "required_fields": [
                "passport_number",
                "issuing_authority",
                "issue_date",
                "expiry_date",
                "dtc_type",
            ],
            "optional_fields": [
                "personal_details",
                "data_groups",
                "access_control",
                "access_key",
            ],
            "doctype": "org.icao.dtc.1",
        },
        "display_config": {
            "display_name": "Demo DTC Credential",
            "is_published": True,
            "is_system_template": False,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "2-3 business days",
        },
    },
    {
        "id": "demo-open-badge-credential-type",
        "name": "open_badge",
        "description": "Demo Open Badge Credential",
        "format": "jwt_vc_json",
        "schema_definition": {
            "required_fields": [
                "version",
                "payload_json",
            ],
            "optional_fields": [
                "document_store_json",
                "recipient_identity",
                "signing_json",
            ],
            "doctype": "openbadges",
        },
        "display_config": {
            "display_name": "Demo Open Badge Credential",
            "is_published": True,
            "is_system_template": False,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "1-2 business days",
        },
    },
]


def upgrade() -> None:
    conn = op.get_bind()

    has_credential_types = conn.execute(
        sa.text("SELECT to_regclass('credential_service.credential_types') IS NOT NULL")
    ).scalar()

    if not has_credential_types:
        return

    update_sql = sa.text(
        """
        UPDATE credential_service.credential_types
        SET
            description = :description,
            format = :format,
            status = 'active',
            schema_definition = CAST(:schema_definition AS jsonb),
            display_config = CAST(:display_config AS jsonb),
            validity_days = 365,
            revocable = true,
            updated_at = NOW()
        WHERE organization_id = :organization_id
          AND name = :name
        """
    )

    insert_sql = sa.text(
        """
        INSERT INTO credential_service.credential_types (
            id,
            organization_id,
            name,
            description,
            format,
            status,
            schema_definition,
            display_config,
            validity_days,
            revocable,
            created_at,
            updated_at
        )
        SELECT
            :id,
            :organization_id,
            :name,
            :description,
            :format,
            'active',
            CAST(:schema_definition AS jsonb),
            CAST(:display_config AS jsonb),
            365,
            true,
            NOW(),
            NOW()
        WHERE NOT EXISTS (
            SELECT 1
            FROM credential_service.credential_types
            WHERE organization_id = :organization_id
              AND name = :name
        )
        """
    )

    for row in ADDITIONAL_DEMO_CREDENTIAL_ROWS:
        params = {
            "id": row["id"],
            "organization_id": DEMO_ORG_ID,
            "name": row["name"],
            "description": row["description"],
            "format": row["format"],
            "schema_definition": json.dumps(row["schema_definition"]),
            "display_config": json.dumps(row["display_config"]),
        }
        conn.execute(update_sql, params)
        conn.execute(insert_sql, params)


def downgrade() -> None:
    conn = op.get_bind()

    has_credential_types = conn.execute(
        sa.text("SELECT to_regclass('credential_service.credential_types') IS NOT NULL")
    ).scalar()

    if has_credential_types:
        conn.execute(
            sa.text(
                """
                DELETE FROM credential_service.credential_types
                WHERE organization_id = :organization_id
                  AND id IN (
                      'demo-travel-visa-credential-type',
                      'demo-access-badge-credential-type',
                      'demo-dtc-credential-type',
                      'demo-open-badge-credential-type'
                  )
                """
            ),
            {"organization_id": DEMO_ORG_ID},
        )
