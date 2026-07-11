"""Use public type metadata for the Marty MemberCredential.

Revision ID: 20260710_0002
Revises: 20260710_0001
Create Date: 2026-07-10 00:00:00.000000+00:00
"""

from __future__ import annotations

import os

from alembic import op
import sqlalchemy as sa


revision = "20260710_0002"
down_revision = "20260710_0001"
branch_labels = None
depends_on = None

MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
MARTY_MEMBER_TEMPLATE_ID = "50000000-0000-0000-0000-000000000010"
LEGACY_MEMBER_VCT = "https://marty.example/credentials/MemberCredential"
BADGE_SLUG = "marty-verified-member-badge"


def _public_api_url() -> str:
    return (
        os.environ.get("PUBLIC_API_URL")
        or os.environ.get("ISSUER_BASE_URL")
        or os.environ.get("PUBLIC_BASE_URL")
        or "https://beta.elevenidllc.com"
    ).rstrip("/")


def _badge_vct() -> str:
    return f"{_public_api_url()}/credentials/{BADGE_SLUG}"


def _has_table(conn) -> bool:
    return bool(
        conn.execute(
            sa.text("SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL")
        ).scalar()
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET vct = :vct,
                   version = GREATEST(version, 2),
                   updated_at = NOW()
             WHERE id = :id
               AND organization_id = :organization_id
               AND credential_type = 'MemberCredential'
               AND credential_payload_format IN ('ietf_sd_jwt', 'sd_jwt_vc', 'w3c_vcdm_v2_sd_jwt')
               AND (vct = :legacy_vct OR vct IS NULL OR vct = '')
            """
        ),
        {
            "id": MARTY_MEMBER_TEMPLATE_ID,
            "organization_id": MARTY_ORG_ID,
            "vct": _badge_vct(),
            "legacy_vct": LEGACY_MEMBER_VCT,
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET vct = :legacy_vct,
                   version = CASE WHEN version = 2 THEN 1 ELSE version END,
                   updated_at = NOW()
             WHERE id = :id
               AND organization_id = :organization_id
               AND credential_type = 'MemberCredential'
               AND credential_payload_format IN ('ietf_sd_jwt', 'sd_jwt_vc', 'w3c_vcdm_v2_sd_jwt')
               AND vct = :vct
            """
        ),
        {
            "id": MARTY_MEMBER_TEMPLATE_ID,
            "organization_id": MARTY_ORG_ID,
            "vct": _badge_vct(),
            "legacy_vct": LEGACY_MEMBER_VCT,
        },
    )
