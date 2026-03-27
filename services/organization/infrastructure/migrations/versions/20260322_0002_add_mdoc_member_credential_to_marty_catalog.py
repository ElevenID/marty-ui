"""Add mDoc MemberCredential to Marty organization catalog.

Revision ID: 20260322_0002
Revises: 20260316_0001
Create Date: 2026-03-22 00:10:00.000000+00:00

Adds the mDoc-format Membership ID credential type to the Marty org so that it
appears in the applicant credential catalog alongside the existing SD-JWT
MemberCredential and mDL entries.
"""

from alembic import op
import sqlalchemy as sa
import json


revision = "20260322_0002"
down_revision = "20260316_0001"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"

MDOC_MEMBER_CREDENTIAL = {
    "id": "marty-mdoc-member-credential-type",
    "name": "member_credential_mdoc",
    "description": "mDoc-format membership identity credential — same data as the Login Credential but in ISO 18013-5 container format",
    "format": "mso_mdoc",
    "schema_definition": {
        "required_fields": [
            "member_id",
            "email",
            "organization_id",
            "role",
            "issued_at",
        ],
        "optional_fields": [
            "given_name",
            "family_name",
            "organization_name",
        ],
        "doctype": "com.elevenid.member_credential",
    },
    "display_config": {
        "display_name": "Membership ID (mDoc)",
        "is_published": True,
        "is_system_template": True,
        "is_active": True,
        "visibility": "public",
        "estimated_processing_time": "Instant",
        "description": (
            "mDoc-format membership credential compatible with Apple & Google "
            "Wallet style experiences. Contains the same identity data as "
            "the SD-JWT Login Credential — issued instantly to your wallet."
        ),
        "icon": "badge",
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

    params = {
        "id": MDOC_MEMBER_CREDENTIAL["id"],
        "organization_id": MARTY_ORG_ID,
        "name": MDOC_MEMBER_CREDENTIAL["name"],
        "description": MDOC_MEMBER_CREDENTIAL["description"],
        "format": MDOC_MEMBER_CREDENTIAL["format"],
        "schema_definition": json.dumps(MDOC_MEMBER_CREDENTIAL["schema_definition"]),
        "display_config": json.dumps(MDOC_MEMBER_CREDENTIAL["display_config"]),
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
                "name": MDOC_MEMBER_CREDENTIAL["name"],
            },
        )
