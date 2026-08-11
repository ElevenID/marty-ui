"""Require a conformant Open Badges 3.0 credential for Marty login.

Revision ID: 20260717_pp_0001
Revises: 20260507_0002
Create Date: 2026-07-17 23:05:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260717_pp_0001"
down_revision = "20260507_0002"
branch_labels = None
depends_on = None

MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"
OPEN_BADGE_POLICY_ID = "50000000-0000-0000-0000-000000000004"


def _patch(conn, payload_format: str, selective_disclosure: bool, purpose: str) -> None:
    row = conn.execute(
        sa.text(
            """SELECT display_metadata, credential_requirements
                 FROM presentation_policy_service.presentation_policies
                WHERE id = :policy_id AND organization_id = :organization_id"""
        ),
        {"policy_id": OPEN_BADGE_POLICY_ID, "organization_id": MARTY_ORG_ID},
    ).fetchone()
    if not row:
        return
    display = row[0] if isinstance(row[0], dict) else json.loads(row[0] or "{}")
    requirements = row[1] if isinstance(row[1], list) else json.loads(row[1] or "[]")
    display["title"] = "Marty Open Badge Login"
    display["purpose"] = purpose
    for requirement in requirements:
        if not isinstance(requirement, dict):
            continue
        if requirement.get("credential_template_id") != OPEN_BADGE_TEMPLATE_ID:
            continue
        requirement["credential_payload_format"] = payload_format
        requirement["display_name"] = "Marty Verified Member Badge"
        for claim in requirement.get("requested_claims") or []:
            if isinstance(claim, dict):
                claim["selective_disclosure"] = selective_disclosure
    conn.execute(
        sa.text(
            """UPDATE presentation_policy_service.presentation_policies
                  SET name = 'OpenBadgeLogin',
                      description = :description,
                      display_metadata = CAST(:display AS json),
                      credential_requirements = CAST(:requirements AS json),
                      version = GREATEST(version, 2),
                      updated_at = NOW()
                WHERE id = :policy_id AND organization_id = :organization_id"""
        ),
        {
            "policy_id": OPEN_BADGE_POLICY_ID,
            "organization_id": MARTY_ORG_ID,
            "description": "Passwordless login using a trusted, active Open Badges 3.0 membership credential.",
            "display": json.dumps(display),
            "requirements": json.dumps(requirements),
        },
    )


def upgrade() -> None:
    _patch(
        op.get_bind(),
        "openbadge-v3",
        False,
        "Present your membership badge and account email to sign in without a password.",
    )


def downgrade() -> None:
    _patch(
        op.get_bind(),
        "sd_jwt_vc",
        True,
        "Present your membership credential. Only your email address will be shared.",
    )
