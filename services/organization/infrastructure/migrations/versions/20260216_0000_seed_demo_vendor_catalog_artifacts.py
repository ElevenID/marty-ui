"""Seed demo vendor catalog artifacts as part of DB migrations.

Revision ID: 20260216_0000
Revises: 20260215_0001
Create Date: 2026-02-16 00:00:00.000000+00:00
"""

from alembic import op
import sqlalchemy as sa
import json
from marty_common.migration_profile import skip_demo_migrations


# revision identifiers, used by Alembic.
revision = "20260216_0000"
down_revision = "20260215_0001"
branch_labels = None
depends_on = None


DEMO_ORG_ID = "22222222-2222-2222-2222-222222222222"

# Keep IDs stable so upgrade/downgrade are deterministic.
DEMO_CREDENTIAL_ROWS = [
    {
        "id": "demo-passport-credential-type",
        "name": "passport",
        "description": "Demo Passport Credential",
        "format": "jwt_vc_json",
        "schema_definition": {
            "required_fields": [
                "given_name",
                "family_name",
                "birth_date",
                "nationality",
                "document_number",
                "expiry_date",
            ],
            "optional_fields": [
                "portrait",
                "sex",
                "birth_place",
                "issuing_authority",
            ],
            "doctype": "org.icao.mrtd.passport",
        },
        "display_config": {
            "display_name": "Demo Passport Credential",
            "is_published": True,
            "is_system_template": False,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "2-3 business days",
        },
    },
    {
        "id": "demo-drivers-license-credential-type",
        "name": "drivers_license",
        "description": "Demo Driver License Credential",
        "format": "jwt_vc_json",
        "schema_definition": {
            "required_fields": [
                "given_name",
                "family_name",
                "birth_date",
                "document_number",
                "issue_date",
                "expiry_date",
            ],
            "optional_fields": [
                "portrait",
                "address",
                "vehicle_categories",
                "restrictions",
            ],
            "doctype": "org.iso.18013.5.1.mDL",
        },
        "display_config": {
            "display_name": "Demo Driver License Credential",
            "is_published": True,
            "is_system_template": False,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "2-3 business days",
        },
    },
    {
        "id": "demo-national-id-credential-type",
        "name": "national_id",
        "description": "Demo National ID Credential",
        "format": "jwt_vc_json",
        "schema_definition": {
            "required_fields": [
                "given_name",
                "family_name",
                "birth_date",
                "document_number",
                "nationality",
            ],
            "optional_fields": [
                "portrait",
                "sex",
                "birth_place",
                "address",
            ],
            "doctype": "org.marty.national_id.1",
        },
        "display_config": {
            "display_name": "Demo National ID Credential",
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
        "description": "Professional Development Certificate - Open Badge 3.0 credential for professional development and continuing education",
        "format": "jwt_vc_json",
        "schema_definition": {
            "required_fields": [
                "family_name",
                "given_name",
                "achievement_name",
                "course_name",
                "completion_date",
                "institution_name",
            ],
            "optional_fields": [
                "badge_image",
                "achievement_criteria",
                "grade",
                "credit_hours",
                "instructor_name",
                "certificate_id",
            ],
            "doctype": "openbadges",
        },
        "display_config": {
            "display_name": "Professional Development Certificate",
            "is_published": True,
            "is_system_template": False,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "1-2 business days",
        },
    },
]


def upgrade() -> None:
    if skip_demo_migrations():
        return

    conn = op.get_bind()

    # Ensure Demo Vendor Org remains discoverable and open join as part of demo UX.
    conn.execute(
        sa.text(
            """
            UPDATE organization_service.organizations
            SET
                join_mechanism = 'open',
                requires_approval = false,
                is_discoverable = true,
                updated_at = NOW()
            WHERE id = CAST(:org_id AS uuid)
            """
        ),
        {"org_id": DEMO_ORG_ID},
    )

    # Some deployments do not have credential_service tables (or use different services).
    # Guard inserts so migration is safe everywhere.
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

    for row in DEMO_CREDENTIAL_ROWS:
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
    if skip_demo_migrations():
        return

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
                  AND id IN ('demo-passport-credential-type', 'demo-drivers-license-credential-type', 'demo-national-id-credential-type', 'demo-open-badge-credential-type')
                """
            ),
            {"organization_id": DEMO_ORG_ID},
        )
