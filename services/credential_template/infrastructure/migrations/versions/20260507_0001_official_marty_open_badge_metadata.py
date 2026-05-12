"""Make Marty open_badge metadata official and wallet-friendly.

Revision ID: 20260507_0001
Revises: 20260505_0002
Create Date: 2026-05-07 00:00:00.000000+00:00
"""

from __future__ import annotations

import json
import os

from alembic import op
import sqlalchemy as sa


revision = "20260507_0001"
down_revision = "20260505_0002"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"
BADGE_SLUG = "marty-verified-member-badge"
BADGE_NAME = "Marty Verified Member Badge"
BADGE_DESCRIPTION = "Verified membership credential issued by Marty Identity Platform for secure passwordless sign-in."
BADGE_BACKGROUND = "#3B1C8F"
BADGE_TEXT = "#FFFFFF"


def _public_api_url() -> str:
    return (
        os.environ.get("PUBLIC_API_URL")
        or os.environ.get("ISSUER_BASE_URL")
        or os.environ.get("PUBLIC_BASE_URL")
        or "https://beta.elevenidllc.com"
    ).rstrip("/")


def _badge_vct() -> str:
    return f"{_public_api_url()}/credentials/{BADGE_SLUG}"


def _badge_image_url() -> str:
    return f"{_badge_vct()}/image.svg"


def _has_table(conn) -> bool:
    return bool(
        conn.execute(
            sa.text("SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL")
        ).scalar()
    )


def _updated_claims(existing_claims: object) -> list[dict]:
    claims = existing_claims or []
    if isinstance(claims, str):
        claims = json.loads(claims)
    if not isinstance(claims, list):
        claims = []

    updated: list[dict] = []
    for claim in claims:
        if not isinstance(claim, dict):
            continue
        item = dict(claim)
        if item.get("name") == "achievement_name":
            item["display_name"] = "Badge Name"
            item["description"] = "Official badge title displayed to the holder"
        elif item.get("name") == "achievement_description":
            item["display_name"] = "Badge Description"
            item["description"] = "Description of the verified membership represented by this badge"
        elif item.get("name") == "organization_name":
            item["display_name"] = "Organization"
        updated.append(item)

    if not any(claim.get("name") == "badge_image_url" for claim in updated):
        updated.append(
            {
                "id": "marty-ob-badge-image-url",
                "name": "badge_image_url",
                "display_name": "Badge Image",
                "description": "Public image associated with the badge",
                "claim_type": "string",
                "required": False,
                "selectively_disclosable": False,
                "derivable": False,
            }
        )
    return updated


def upgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    row = conn.execute(
        sa.text(
            """
            SELECT claims
              FROM credential_template_service.credential_templates
             WHERE id = :id
               AND organization_id = :organization_id
            """
        ),
        {"id": OPEN_BADGE_TEMPLATE_ID, "organization_id": MARTY_ORG_ID},
    ).fetchone()
    if not row:
        return

    claims = _updated_claims(row[0])
    display_style = {
        "background_color": BADGE_BACKGROUND,
        "text_color": BADGE_TEXT,
        "border_color": None,
        "logo_url": _badge_image_url(),
        "background_image_url": None,
    }

    conn.execute(
        sa.text(
            """
            UPDATE credential_template_service.credential_templates
               SET name = :name,
                   description = :description,
                   vct = :vct,
                   claims = CAST(:claims AS jsonb),
                   selective_disclosure_fields = CAST(:selective_disclosure_fields AS jsonb),
                   display_style = CAST(:display_style AS jsonb),
                   credential_payload_format = :credential_payload_format,
                   version = GREATEST(version, 3),
                   updated_at = NOW()
             WHERE id = :id
               AND organization_id = :organization_id
            """
        ),
        {
            "id": OPEN_BADGE_TEMPLATE_ID,
            "organization_id": MARTY_ORG_ID,
            "name": BADGE_NAME,
            "description": BADGE_DESCRIPTION,
            "vct": _badge_vct(),
            "claims": json.dumps(claims),
            "selective_disclosure_fields": json.dumps(
                [claim["name"] for claim in claims if claim.get("selectively_disclosable")]
            ),
            "display_style": json.dumps(display_style),
            "credential_payload_format": "sd_jwt_vc",
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
               SET name = 'Verified Member Badge',
                   description = 'Open Badge 3.0-compatible membership credential — verifiable proof of active organization membership that can be presented for passwordless sign-in where accepted.',
                   vct = 'https://marty.example/credentials/open_badge',
                   display_style = CAST(:display_style AS jsonb),
                   credential_payload_format = 'ietf_sd_jwt',
                   version = 2,
                   updated_at = NOW()
             WHERE id = :id
               AND organization_id = :organization_id
            """
        ),
        {
            "id": OPEN_BADGE_TEMPLATE_ID,
            "organization_id": MARTY_ORG_ID,
            "display_style": json.dumps(
                {
                    "logo_url": None,
                    "text_color": "#ffffff",
                    "border_color": None,
                    "background_color": "#6a1b9a",
                    "background_image_url": None,
                }
            ),
        },
    )
