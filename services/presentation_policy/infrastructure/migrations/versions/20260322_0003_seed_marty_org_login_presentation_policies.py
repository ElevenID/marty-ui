"""Seed presentation policies for Marty-org credential-based login.

The original MemberLogin policy (20260227_0001) was seeded for the ElevenID
demo organisation and references the ElevenID SD-JWT MemberCredential template.
The Marty organisation now has member credential templates of its own:

  - 50000000-0000-0000-0000-000000000010  SD-JWT  Member Login Credential
  - 50000000-0000-0000-0000-000000000030  mDoc    Membership ID (mDoc)
    - 50000000-0000-0000-0000-000000000040  Open Badge Verified Member Badge

This migration seeds presentation policies so that applicants who hold a
supported standards-based membership credential can use credential-based login:

  50000000-0000-0000-0000-000000000002  MemberLogin (SD-JWT) — Marty org
  50000000-0000-0000-0000-000000000003  MemberLogin (mDoc)   — Marty org
    50000000-0000-0000-0000-000000000004  OpenBadgeLogin       — Marty org

Set CREDENTIAL_LOGIN_POLICY_ID to the appropriate policy ID in the
environment configuration.

Revision ID: 20260322_0003
Revises: 20260227_0001
Create Date: 2026-03-22 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260322_0003"
down_revision = "20260227_0001"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
NOW = "2026-03-22T00:00:00+00:00"

# Marty org credential template IDs
MARTY_SD_JWT_TEMPLATE_ID = "50000000-0000-0000-0000-000000000010"
MARTY_MDOC_TEMPLATE_ID = "50000000-0000-0000-0000-000000000030"
MARTY_OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"

# New policy IDs
SD_JWT_POLICY_ID = "50000000-0000-0000-0000-000000000002"
MDOC_POLICY_ID = "50000000-0000-0000-0000-000000000003"
OPEN_BADGE_POLICY_ID = "50000000-0000-0000-0000-000000000004"

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

OPEN_BADGE_DISPLAY_METADATA = {
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

# Common claim definitions shared by both policies
_REQUESTED_CLAIMS = [
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
]


def _build_credential_requirements(template_id, display_name, payload_format, req_id):
    return [
        {
            "id": req_id,
            "credential_template_id": template_id,
            "display_name": display_name,
            "credential_payload_format": payload_format,
            "required": True,
            "trust_profile_id": None,
            "max_age_seconds": None,
            "require_fresh_issuance": False,
            "requested_claims": _REQUESTED_CLAIMS,
        }
    ]


POLICIES = [
    {
        "id": SD_JWT_POLICY_ID,
        "name": "MemberLogin-SD-JWT",
        "description": (
            "Marty organisation credential-based login policy (SD-JWT format). "
            "Requests only email from a MemberCredential. Organisation and "
            "role context are resolved from Keycloak during login."
        ),
        "credential_requirements": _build_credential_requirements(
            template_id=MARTY_SD_JWT_TEMPLATE_ID,
            display_name="Member Login Credential",
            payload_format="ietf_sd_jwt",
            req_id="req-marty-member-sd-jwt",
        ),
    },
    {
        "id": MDOC_POLICY_ID,
        "name": "MemberLogin-mDoc",
        "description": (
            "Marty organisation credential-based login policy (mDoc format). "
            "Requests only email from a Membership ID (mDoc) credential. "
            "Organisation and role context are resolved from Keycloak during login."
        ),
        "credential_requirements": _build_credential_requirements(
            template_id=MARTY_MDOC_TEMPLATE_ID,
            display_name="Membership ID (mDoc)",
            payload_format="mso_mdoc",
            req_id="req-marty-member-mdoc",
        ),
    },
    {
        "id": OPEN_BADGE_POLICY_ID,
        "name": "OpenBadgeLogin",
        "description": (
            "Marty organisation credential-based login policy for the "
            "Verified Member Badge (Open Badge 3.0). Requests only email; "
            "membership, organisation, and role context are represented by "
            "the Open Badge credential and resolved from Keycloak during login."
        ),
        "display_metadata": OPEN_BADGE_DISPLAY_METADATA,
        "credential_requirements": _build_credential_requirements(
            template_id=MARTY_OPEN_BADGE_TEMPLATE_ID,
            display_name="Verified Member Badge",
            payload_format="openbadge-v3",
            req_id="req-marty-open-badge-login",
        ),
    },
]


def upgrade() -> None:
    conn = op.get_bind()

    for policy in POLICIES:
        existing = conn.execute(
            sa.text(
                "SELECT id FROM presentation_policy_service.presentation_policies WHERE id = :id"
            ),
            {"id": policy["id"]},
        ).fetchone()

        if existing:
            continue

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
                "id": policy["id"],
                "organization_id": MARTY_ORG_ID,
                "name": policy["name"],
                "description": policy["description"],
                "status": "active",
                "display_metadata": json.dumps(policy.get("display_metadata", DISPLAY_METADATA)),
                "credential_requirements": json.dumps(policy["credential_requirements"]),
                "alternative_requirements": json.dumps([]),
                "compliance_profile_id": None,
                "version": 1,
                "created_at": NOW,
                "updated_at": NOW,
            },
        )


def downgrade() -> None:
    conn = op.get_bind()
    for policy in POLICIES:
        conn.execute(
            sa.text(
                "DELETE FROM presentation_policy_service.presentation_policies WHERE id = :id"
            ),
            {"id": policy["id"]},
        )
