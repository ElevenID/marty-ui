"""Repair Marty Open Badge catalog metadata for discoverability.

This is a stable system seed repair, not a demo/test seed.  The template is a
platform record with a stable id used by the login flow.  Keep the badge name as
an Open Badges-style achievement/credential display name, while making the
description searchable for the passwordless-login use case.

Revision ID: 20260517_0001
Revises: 20260507_0001
Create Date: 2026-05-17 00:00:00.000000+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260517_0001"
down_revision = "20260507_0001"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"

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
            sa.text("SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL")
        ).scalar()
    )


def _apply_metadata(conn, *, name: str, description: str) -> None:
    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET name = :name,
                   description = :description,
                   updated_at = NOW()
             WHERE id = :id
               AND organization_id = :organization_id
               AND credential_type = 'open_badge'
            """
        ),
        {
            "id": OPEN_BADGE_TEMPLATE_ID,
            "organization_id": MARTY_ORG_ID,
            "name": name,
            "description": description,
        },
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return
    _apply_metadata(conn, name=BADGE_NAME, description=BADGE_DESCRIPTION)


def downgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return
    _apply_metadata(conn, name=BADGE_NAME, description=PREVIOUS_DESCRIPTION)