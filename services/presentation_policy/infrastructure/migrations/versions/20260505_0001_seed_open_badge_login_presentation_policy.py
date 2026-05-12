"""Seed OpenBadgeLogin presentation policy for Marty credential login.

Revision ID: 20260505_0001
Revises: 20260501_0004
Create Date: 2026-05-05 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260505_0001"
down_revision = "20260501_0004"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"
OPEN_BADGE_POLICY_ID = "50000000-0000-0000-0000-000000000004"
NOW = "2026-05-05T00:00:00+00:00"

DISPLAY_METADATA = {
    "title": "Open Badge Login Verification",
    "purpose": (
        "Verify your Open Badge 3.0 membership credential to log in without "
        "a password. Only your email will be shared."
    ),
    "verifier_name": "ElevenID LLC",
    "privacy_url": None,
    "tos_url": None,
    "logo_url": None,
}

CREDENTIAL_REQUIREMENTS = [
    {
        "id": "req-marty-open-badge-login",
        "credential_template_id": OPEN_BADGE_TEMPLATE_ID,
        "display_name": "Verified Member Badge",
        "description": "Present your Open Badge 3.0 verified membership badge.",
        "credential_payload_format": "openbadge-v3",
        "required": True,
        "trust_profile_id": None,
        "max_age_seconds": None,
        "require_fresh_issuance": False,
        "requested_claims": [
            {
                "claim_name": "email",
                "display_name": "Email Address",
                "purpose": "Identify your account",
                "required": True,
                "selective_disclosure": True,
                "accept_derived": False,
                "intent_to_retain": False,
                "constraints": [],
            }
        ],
    }
]


def _has_table(conn) -> bool:
    return bool(
        conn.execute(
            sa.text(
                "SELECT to_regclass('presentation_policy_service.presentation_policies') IS NOT NULL"
            )
        ).scalar()
    )


def upgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    conn.execute(
        sa.text(
            """
            INSERT INTO presentation_policy_service.presentation_policies (
                id,
                organization_id,
                name,
                description,
                status,
                display_metadata,
                credential_requirements,
                alternative_requirements,
                compliance_profile_id,
                version,
                created_at,
                updated_at
            ) VALUES (
                :id,
                :organization_id,
                :name,
                :description,
                :status,
                CAST(:display_metadata AS json),
                CAST(:credential_requirements AS json),
                CAST(:alternative_requirements AS json),
                :compliance_profile_id,
                :version,
                :created_at,
                :updated_at
            )
            ON CONFLICT (id) DO UPDATE SET
                organization_id = EXCLUDED.organization_id,
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                status = EXCLUDED.status,
                display_metadata = EXCLUDED.display_metadata,
                credential_requirements = EXCLUDED.credential_requirements,
                alternative_requirements = EXCLUDED.alternative_requirements,
                compliance_profile_id = EXCLUDED.compliance_profile_id,
                version = EXCLUDED.version,
                updated_at = EXCLUDED.updated_at
            """
        ),
        {
            "id": OPEN_BADGE_POLICY_ID,
            "organization_id": MARTY_ORG_ID,
            "name": "OpenBadgeLogin",
            "description": (
                "Marty organisation credential-based login policy for the "
                "Verified Member Badge (Open Badge 3.0). Requests only email; "
                "membership, organisation, and role context are represented by "
                "the Open Badge credential and resolved from Keycloak during login."
            ),
            "status": "active",
            "display_metadata": json.dumps(DISPLAY_METADATA),
            "credential_requirements": json.dumps(CREDENTIAL_REQUIREMENTS),
            "alternative_requirements": json.dumps([]),
            "compliance_profile_id": None,
            "version": 1,
            "created_at": NOW,
            "updated_at": NOW,
        },
    )


def downgrade() -> None:
    conn = op.get_bind()
    if not _has_table(conn):
        return

    conn.execute(
        sa.text(
            """
            DELETE FROM presentation_policy_service.presentation_policies
            WHERE id = :id
            """
        ),
        {"id": OPEN_BADGE_POLICY_ID},
    )
