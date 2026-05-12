"""Realign Marty open_badge catalog entry with membership/login semantics.

Revision ID: 20260505_0001
Revises: 20260327_0000
Create Date: 2026-05-05 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260505_0001"
down_revision = "20260327_0000"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
CREDENTIAL_NAME = "open_badge"

UPDATED_SCHEMA_DEFINITION = {
    "required_fields": [
        "member_id",
        "email",
        "organization_id",
        "role",
        "achievement_name",
        "issued_at",
    ],
    "optional_fields": [
        "given_name",
        "family_name",
        "organization_name",
        "achievement_description",
    ],
    "doctype": "org.openbadges.v3",
}

UPDATED_DISPLAY_CONFIG = {
    "display_name": "Verified Member Badge",
    "is_published": True,
    "is_system_template": True,
    "is_active": True,
    "visibility": "public",
    "estimated_processing_time": "Instant",
    "description": (
        "Open Badge 3.0-compatible membership credential — "
        "verifiable proof of active organization membership for "
        "wallet-first sign-in and membership verification."
    ),
    "icon": "badge",
    "category": "identity",
}

LEGACY_SCHEMA_DEFINITION = {
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
}

LEGACY_DISPLAY_CONFIG = {
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
}


def _has_table(conn) -> bool:
    return bool(
        conn.execute(
            sa.text("SELECT to_regclass('credential_service.credential_types') IS NOT NULL")
        ).scalar()
    )


def _apply_catalog_entry(conn, *, description: str, schema_definition: dict, display_config: dict) -> None:
    conn.execute(
        sa.text(
            """
            UPDATE credential_service.credential_types
               SET description = :description,
                   schema_definition = CAST(:schema_definition AS jsonb),
                   display_config = CAST(:display_config AS jsonb),
                   updated_at = NOW()
             WHERE organization_id = :organization_id
               AND name = :name
            """
        ),
        {
            "organization_id": MARTY_ORG_ID,
            "name": CREDENTIAL_NAME,
            "description": description,
            "schema_definition": json.dumps(schema_definition),
            "display_config": json.dumps(display_config),
        },
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    _apply_catalog_entry(
        conn,
        description="Open Badge 3.0-compatible membership credential — verifiable proof of active organization membership",
        schema_definition=UPDATED_SCHEMA_DEFINITION,
        display_config=UPDATED_DISPLAY_CONFIG,
    )


def downgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    _apply_catalog_entry(
        conn,
        description="Open Badge 3.0 professional development certificate — education sector credential",
        schema_definition=LEGACY_SCHEMA_DEFINITION,
        display_config=LEGACY_DISPLAY_CONFIG,
    )
