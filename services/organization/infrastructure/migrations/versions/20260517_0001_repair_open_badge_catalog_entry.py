"""Repair Marty Open Badge legacy catalog metadata.

Revision ID: 20260517_0001
Revises: 20260513_0001
Create Date: 2026-05-17 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260517_0001"
down_revision = "20260513_0001"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
CREDENTIAL_NAME = "open_badge"

BADGE_NAME = "Marty Verified Member Badge"
BADGE_DESCRIPTION = (
    "Open Badge 3.0 membership badge issued by Marty Identity Platform; "
    "presents verified membership for wallet-based passwordless login/sign-in."
)

PREVIOUS_DESCRIPTION = (
    "Verified membership credential issued by Marty Identity Platform for "
    "secure passwordless sign-in."
)


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


def _apply_catalog_metadata(conn, *, description: str) -> None:
    row = conn.execute(
        sa.text(
            """
            SELECT display_config
              FROM credential_service.credential_types
             WHERE organization_id = :organization_id
               AND name = :name
            """
        ),
        {"organization_id": MARTY_ORG_ID, "name": CREDENTIAL_NAME},
    ).fetchone()
    if not row:
        return

    display_config = _as_json(row[0], {})
    if not isinstance(display_config, dict):
        display_config = {}
    display_config.update(
        {
            "display_name": BADGE_NAME,
            "description": description,
            "icon": "verified",
            "category": "identity",
        }
    )

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
            "description": description,
            "display_config": json.dumps(display_config),
        },
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return
    _apply_catalog_metadata(conn, description=BADGE_DESCRIPTION)


def downgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return
    _apply_catalog_metadata(conn, description=PREVIOUS_DESCRIPTION)