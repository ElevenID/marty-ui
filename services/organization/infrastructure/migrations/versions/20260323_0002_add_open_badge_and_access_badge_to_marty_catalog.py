"""Add Open Badge and Employee Access Badge to Marty organization catalog.

Revision ID: 20260323_0002
Revises: 20260322_0002
Create Date: 2026-03-23 00:10:00.000000+00:00

Adds two new credential types to the Marty org so applicants see them in the
credential catalog alongside the existing login credential and mDL.
"""

from alembic import op
import sqlalchemy as sa
import json


revision = "20260323_0002"
down_revision = "20260322_0002"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"

CREDENTIAL_TYPES = [
    {
        "id": "marty-open-badge-credential-type",
        "name": "open_badge",
        "description": "Open Badge 3.0 professional development certificate — education sector credential",
        "format": "ietf_sd_jwt",
        "schema_definition": {
            "required_fields": [
                "given_name",
                "family_name",
                "email",
                "achievement_name",
                "course_name",
                "completion_date",
                "institution_name",
            ],
            "optional_fields": [
                "certificate_id",
                "grade",
                "credit_hours",
            ],
            "doctype": "org.openbadges.v3",
        },
        "display_config": {
            "display_name": "Professional Certificate (Open Badge)",
            "is_published": True,
            "is_system_template": True,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "Instant",
            "description": (
                "Open Badge 3.0 professional development certificate — "
                "instantly issued, recognized by employers and institutions."
            ),
            "icon": "school",
            "category": "education",
        },
        "validity_days": 365,
    },
    {
        "id": "marty-access-badge-credential-type",
        "name": "access_badge",
        "description": "Corporate access badge — verifiable proof of employment and building access",
        "format": "ietf_sd_jwt",
        "schema_definition": {
            "required_fields": [
                "given_name",
                "family_name",
                "email",
                "employee_id",
                "department",
                "job_title",
                "clearance_level",
                "issue_date",
                "expiry_date",
            ],
            "optional_fields": [
                "building_access",
            ],
            "doctype": "com.enterprise.access.badge",
        },
        "display_config": {
            "display_name": "Employee Access Badge",
            "is_published": True,
            "is_system_template": True,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "Instant",
            "description": (
                "Corporate access badge credential — verifiable proof of "
                "employment, department, and building access."
            ),
            "icon": "badge",
            "category": "enterprise",
        },
        "validity_days": 365,
    },
]


def upgrade() -> None:
    conn = op.get_bind()

    has_credential_types = conn.execute(
        sa.text("SELECT to_regclass('credential_service.credential_types') IS NOT NULL")
    ).scalar()

    if not has_credential_types:
        return

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
            :validity_days,
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

    for ct in CREDENTIAL_TYPES:
        conn.execute(
            insert_sql,
            {
                "id": ct["id"],
                "organization_id": MARTY_ORG_ID,
                "name": ct["name"],
                "description": ct["description"],
                "format": ct["format"],
                "schema_definition": json.dumps(ct["schema_definition"]),
                "display_config": json.dumps(ct["display_config"]),
                "validity_days": ct["validity_days"],
            },
        )


def downgrade() -> None:
    conn = op.get_bind()

    has_credential_types = conn.execute(
        sa.text("SELECT to_regclass('credential_service.credential_types') IS NOT NULL")
    ).scalar()

    if has_credential_types:
        for ct in CREDENTIAL_TYPES:
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
                    "name": ct["name"],
                },
            )
