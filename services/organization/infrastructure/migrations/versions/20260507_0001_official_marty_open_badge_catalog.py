"""Make Marty open_badge catalog entry official.

Revision ID: 20260507_0001
Revises: 20260505_0001
Create Date: 2026-05-07 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260507_0001"
down_revision = "20260505_0001"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
CREDENTIAL_NAME = "open_badge"
BADGE_NAME = "Marty Verified Member Badge"
BADGE_DESCRIPTION = "Verified membership credential issued by Marty Identity Platform for secure passwordless sign-in."


def _has_table(conn) -> bool:
    return bool(
        conn.execute(
            sa.text("SELECT to_regclass('credential_service.credential_types') IS NOT NULL")
        ).scalar()
    )


def _as_json(value, default):
    if value is None:
        return default
    if isinstance(value, str):
        return json.loads(value)
    return value


def upgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    row = conn.execute(
        sa.text(
            """
            SELECT schema_definition, display_config
              FROM credential_service.credential_types
             WHERE organization_id = :organization_id
               AND name = :name
            """
        ),
        {"organization_id": MARTY_ORG_ID, "name": CREDENTIAL_NAME},
    ).fetchone()
    if not row:
        return

    schema_definition = _as_json(row[0], {})
    display_config = _as_json(row[1], {})
    if isinstance(schema_definition, dict):
        optional_fields = list(schema_definition.get("optional_fields") or [])
        if "badge_image_url" not in optional_fields:
            optional_fields.append("badge_image_url")
        schema_definition["optional_fields"] = optional_fields
    if isinstance(display_config, dict):
        display_config.update(
            {
                "display_name": BADGE_NAME,
                "description": BADGE_DESCRIPTION,
                "icon": "verified",
                "category": "identity",
            }
        )

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
            "description": BADGE_DESCRIPTION,
            "schema_definition": json.dumps(schema_definition),
            "display_config": json.dumps(display_config),
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    display_config = {
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

    conn.execute(
        sa.text(
            """
            UPDATE credential_service.credential_types
               SET description = :description,
                   display_config = CAST(:display_config AS jsonb),
                   updated_at = NOW()
             WHERE organization_id = :organization_id
               AND name = :name
            """
        ),
        {
            "organization_id": MARTY_ORG_ID,
            "name": CREDENTIAL_NAME,
            "description": "Open Badge 3.0-compatible membership credential — verifiable proof of active organization membership",
            "display_config": json.dumps(display_config),
        },
    )
