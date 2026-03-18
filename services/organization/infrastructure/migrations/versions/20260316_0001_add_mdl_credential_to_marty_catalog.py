"""Add mDL (ISO 18013-5) credential type to Marty organization catalog.

Revision ID: 20260316_0001
Revises: 20260314_0000
Create Date: 2026-03-16 00:10:00.000000+00:00

Adds the Mobile Driving Licence credential type to the Marty org so that it
appears in the applicant credential catalog alongside the existing user_login
(MemberCredential) entry.
"""

from alembic import op
import sqlalchemy as sa
import json


revision = "20260316_0001"
down_revision = "20260314_0000"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"

MDL_CREDENTIAL = {
    "id": "marty-mdl-credential-type",
    "name": "drivers_license",
    "description": "ISO/IEC 18013-5 Mobile Driving Licence — verifiable mDoc identity credential",
    "format": "mso_mdoc",
    "schema_definition": {
        "required_fields": [
            "family_name",
            "given_name",
            "birth_date",
            "issue_date",
            "expiry_date",
            "issuing_country",
            "issuing_authority",
            "document_number",
            "driving_privileges",
            "un_distinguishing_sign",
        ],
        "optional_fields": [
            "portrait",
            "resident_address",
            "age_over_21",
        ],
        "doctype": "org.iso.18013.5.1.mDL",
    },
    "display_config": {
        "display_name": "Mobile Driving Licence",
        "is_published": True,
        "is_system_template": True,
        "is_active": True,
        "visibility": "public",
        "estimated_processing_time": "Instant",
        "description": (
            "ISO/IEC 18013-5 Mobile Driving Licence in mDoc format. "
            "A verifiable digital credential that proves your driving "
            "privileges — issued instantly to your mobile wallet."
        ),
        "icon": "directions-car",
        "category": "identity",
    },
}


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
            validity_days = 1825,
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
            1825,
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

    params = {
        "id": MDL_CREDENTIAL["id"],
        "organization_id": MARTY_ORG_ID,
        "name": MDL_CREDENTIAL["name"],
        "description": MDL_CREDENTIAL["description"],
        "format": MDL_CREDENTIAL["format"],
        "schema_definition": json.dumps(MDL_CREDENTIAL["schema_definition"]),
        "display_config": json.dumps(MDL_CREDENTIAL["display_config"]),
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
                  AND name = :name
                """
            ),
            {
                "organization_id": MARTY_ORG_ID,
                "name": MDL_CREDENTIAL["name"],
            },
        )
