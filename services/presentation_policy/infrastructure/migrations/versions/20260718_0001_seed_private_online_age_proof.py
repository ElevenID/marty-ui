"""Seed the minimum-disclosure mDL age proof policy.

Revision ID: 20260718_pp_0001
Revises: 20260717_pp_0001
Create Date: 2026-07-18 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260718_pp_0001"
down_revision = "20260717_pp_0001"
branch_labels = None
depends_on = None

MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
MDL_TEMPLATE_ID = "50000000-0000-0000-0000-000000000020"
AGE_POLICY_ID = "50000000-0000-0000-0000-000000000005"
MARTY_TRUST_PROFILE_ID = "60000000-0000-0000-0000-000000000001"


def upgrade() -> None:
    conn = op.get_bind()
    if not conn.execute(
        sa.text(
            "SELECT to_regclass('presentation_policy_service.presentation_policies') IS NOT NULL"
        )
    ).scalar():
        return
    display = {
        "title": "Private Online Age Proof",
        "purpose": "Confirm age eligibility by requesting only the age_over_21 mDL element.",
        "verifier_name": "ElevenID LLC",
        "privacy_url": None,
        "tos_url": None,
        "logo_url": None,
    }
    requirements = [
        {
            "id": "req-private-online-age-over-21",
            "credential_template_id": MDL_TEMPLATE_ID,
            "display_name": "Mobile Driving Licence",
            "description": "Present only the pre-issued age_over_21 element from a trusted mDL.",
            "credential_payload_format": "mso_mdoc",
            "required": True,
            "trust_profile_id": MARTY_TRUST_PROFILE_ID,
            "max_age_seconds": None,
            "require_fresh_issuance": False,
            "requested_claims": [
                {
                    "claim_name": "age_over_21",
                    "display_name": "Age Over 21",
                    "purpose": "Confirm eligibility without disclosing date of birth or identity details",
                    "required": True,
                    "selective_disclosure": True,
                    "accept_derived": True,
                    "intent_to_retain": False,
                    "constraints": [],
                }
            ],
        }
    ]
    conn.execute(
        sa.text(
            """
            INSERT INTO presentation_policy_service.presentation_policies (
                id, organization_id, name, description, status, display_metadata,
                credential_requirements, alternative_requirements, compliance_profile_id,
                version, created_at, updated_at
            ) VALUES (
                :id, :organization_id, :name, :description, 'active',
                CAST(:display AS json), CAST(:requirements AS json), CAST('[]' AS json),
                NULL, 1, NOW(), NOW()
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
                updated_at = NOW()
            """
        ),
        {
            "id": AGE_POLICY_ID,
            "organization_id": MARTY_ORG_ID,
            "name": "Private Online Age Proof",
            "description": "Requests only age_over_21 from a trusted mDL; no date of birth, predicates, range proofs, or ZKP are requested.",
            "display": json.dumps(display),
            "requirements": json.dumps(requirements),
        },
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text(
            "DELETE FROM presentation_policy_service.presentation_policies WHERE id = :id"
        ),
        {"id": AGE_POLICY_ID},
    )
