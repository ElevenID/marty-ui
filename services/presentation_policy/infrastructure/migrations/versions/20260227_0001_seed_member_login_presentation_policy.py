"""Seed MemberLogin presentation policy for credential-based authentication.

This policy defines which claims the verifier (auth service) requests from
a holder's MemberCredential during the "Login with Credential" flow.

The policy requests:
    - email          (required — used to look up / create the Keycloak user)

The well-known policy ID (CREDENTIAL_LOGIN_POLICY_ID env var) is seeded as:
  50000000-0000-0000-0000-000000000001

Revision ID: 20260227_0001
Revises: cd86d0505323
Create Date: 2026-02-27 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


# ---------------------------------------------------------------------------
# Alembic revision metadata
# ---------------------------------------------------------------------------
revision = "20260227_0001"
down_revision = "cd86d0505323"
branch_labels = None
depends_on = None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ELEVNID_ORG_ID = "22222222-2222-2222-2222-222222222222"
MEMBER_TEMPLATE_ID = "40000000-0000-0000-0000-000000000010"
POLICY_ID = "50000000-0000-0000-0000-000000000001"
NOW = "2026-02-27T00:00:00+00:00"

DISPLAY_METADATA = {
    "title": "Member Login Verification",
    "purpose": (
        "Verify your membership credential to log in without a password. "
        "Only your email will be shared."
    ),
    "verifier_name": "ElevenID LLC",
    "privacy_url": None,
    "tos_url": None,
    "logo_url": None,
}

CREDENTIAL_REQUIREMENTS = [
    {
        "id": "req-member-credential",
        "credential_template_id": MEMBER_TEMPLATE_ID,
        "display_name": "Member Credential",
        "credential_payload_format": "ietf_sd_jwt",
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
            },
        ],
    }
]


def upgrade() -> None:
    connection = op.get_bind()

    existing = connection.execute(
        sa.text(
            "SELECT id FROM presentation_policy_service.presentation_policies WHERE id = :id"
        ),
        {"id": POLICY_ID},
    ).fetchone()

    if existing:
        return  # idempotent

    connection.execute(
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
                :display_metadata,
                :credential_requirements,
                :alternative_requirements,
                :compliance_profile_id,
                :version,
                :created_at,
                :updated_at
            )
            """
        ),
        {
            "id": POLICY_ID,
            "organization_id": ELEVNID_ORG_ID,
            "name": "MemberLogin",
            "description": (
                "Credential-based login policy. Requests only email from a "
                "MemberCredential. Organisation and role context are resolved "
                "from Keycloak during login."
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
    op.get_bind().execute(
        sa.text(
            "DELETE FROM presentation_policy_service.presentation_policies WHERE id = :id"
        ),
        {"id": POLICY_ID},
    )
