"""Add user login credential to Marty organization catalog.

Revision ID: 20260303_0001
Revises: 20260303_0000
Create Date: 2026-03-03 00:10:00.000000+00:00

This migration adds the user login credential type to the Marty organization's
catalog. This credential represents authenticated user identity and serves as
the foundation for user authentication flows across the platform.
"""

from alembic import op
import sqlalchemy as sa
import json


# revision identifiers, used by Alembic.
revision = "20260303_0001"
down_revision = "20260303_0000"
branch_labels = None
depends_on = None


# Marty organization ID (must match the seed migration)
MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"


# User Login Credential definition
USER_LOGIN_CREDENTIAL = {
    "id": "marty-user-login-credential-type",
    "name": "user_login",
    "description": "Marty User Login Credential - Authenticated digital identity for platform access",
    "format": "jwt_vc_json",
    "schema_definition": {
        "required_fields": [
            "user_id",
            "email",
            "given_name",
            "family_name",
        ],
        "optional_fields": [
            "username",
            "phone_number",
            "email_verified",
            "phone_verified",
            "preferred_language",
            "account_created_at",
        ],
        "doctype": "com.marty.identity.user_login",
    },
    "display_config": {
        "display_name": "User Login Credential",
        "is_published": True,
        "is_system_template": True,
        "is_active": True,
        "visibility": "internal",
        "estimated_processing_time": "Instant upon authentication",
        "description": "Verifiable credential representing your authenticated identity on the Marty platform. This credential is issued automatically upon successful login and can be used to prove your identity to relying parties.",
        "icon": "user-check",
        "category": "identity",
    },
}


def upgrade() -> None:
    """
    Add the user login credential type to the Marty organization's catalog.
    
    This credential type is essential for authentication workflows and is
    issued automatically to users upon successful login.
    """
    conn = op.get_bind()
    
    # Check if credential_service tables exist
    has_credential_types = conn.execute(
        sa.text("SELECT to_regclass('credential_service.credential_types') IS NOT NULL")
    ).scalar()
    
    if not has_credential_types:
        # Credential service tables don't exist in this deployment
        return
    
    # First, try to update existing credential type
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
    
    # Then, insert if it doesn't exist
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
        "id": USER_LOGIN_CREDENTIAL["id"],
        "organization_id": MARTY_ORG_ID,
        "name": USER_LOGIN_CREDENTIAL["name"],
        "description": USER_LOGIN_CREDENTIAL["description"],
        "format": USER_LOGIN_CREDENTIAL["format"],
        "schema_definition": json.dumps(USER_LOGIN_CREDENTIAL["schema_definition"]),
        "display_config": json.dumps(USER_LOGIN_CREDENTIAL["display_config"]),
    }
    
    conn.execute(update_sql, params)
    conn.execute(insert_sql, params)


def downgrade() -> None:
    """
    Remove the user login credential type from the Marty organization's catalog.
    
    Note: Use with caution as this may break authentication workflows
    that depend on this credential type.
    """
    conn = op.get_bind()
    
    # Check if credential_service tables exist
    has_credential_types = conn.execute(
        sa.text("SELECT to_regclass('credential_service.credential_types') IS NOT NULL")
    ).scalar()
    
    if has_credential_types:
        conn.execute(
            sa.text(
                """
                DELETE FROM credential_service.credential_types
                WHERE organization_id = :organization_id
                  AND id = :credential_id
                """
            ),
            {
                "organization_id": MARTY_ORG_ID,
                "credential_id": USER_LOGIN_CREDENTIAL["id"],
            },
        )
