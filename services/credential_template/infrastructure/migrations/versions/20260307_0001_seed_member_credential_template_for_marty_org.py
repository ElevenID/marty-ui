"""Seed MemberCredential template for the Marty default organisation.

The MemberCredential is the credential used in the "Login with Credential"
(OID4VP) flow.  It was first seeded for the 11id demo org in revision
20260227_0001.  This migration seeds the *same credential type* for the Marty
organisation (MARTY_ORG_ID ``00000000-0000-0000-0000-000000000001``) so that
applicants who join the Marty org can apply for it through the applicant
catalog.  The credential is free — no processing fee is associated with it.

To avoid duplicating the claim schema we import the canonical constants
directly from the base migration module rather than redefining them.

Revision ID: 20260307_0001
Revises: 20260227_0001
Create Date: 2026-03-07 00:00:00.000000+00:00
"""

from __future__ import annotations

import importlib.util
import json
import pathlib

from alembic import op
import sqlalchemy as sa


# ---------------------------------------------------------------------------
# Alembic revision metadata
# ---------------------------------------------------------------------------
revision = "20260307_0001"
down_revision = "20260227_0001"
branch_labels = None
depends_on = None


# ---------------------------------------------------------------------------
# Import shared constants from the base MemberCredential migration so we keep
# a single source of truth for the claim schema and wallet configs.
# ---------------------------------------------------------------------------
def _load_base_migration():
    base_path = pathlib.Path(__file__).parent / "20260227_0001_seed_member_credential_template.py"
    spec = importlib.util.spec_from_file_location("_member_cred_base", base_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_base = _load_base_migration()

CLAIMS = _base.CLAIMS
DISPLAY_STYLE = _base.DISPLAY_STYLE
VALIDITY_RULES = _base.VALIDITY_RULES
ISSUER_REQUIREMENTS = _base.ISSUER_REQUIREMENTS

# ---------------------------------------------------------------------------
# Marty-org-specific constants
# ---------------------------------------------------------------------------
MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
TEMPLATE_ID = "50000000-0000-0000-0000-000000000010"
NOW = "2026-03-07T00:00:00+00:00"

# Wallet configs are the same shape; credential_configuration_id tags stay the
# same because they reference the credential type, not the org.
WALLET_CONFIGS = _base.WALLET_CONFIGS


# ---------------------------------------------------------------------------
# Upgrade / downgrade
# ---------------------------------------------------------------------------

def upgrade() -> None:
    connection = op.get_bind()

    existing = connection.execute(
        sa.text(
            "SELECT id FROM credential_template_service.credential_templates WHERE id = :id"
        ),
        {"id": TEMPLATE_ID},
    ).fetchone()

    if existing:
        return  # idempotent — already seeded

    connection.execute(
        sa.text(
            """
            INSERT INTO credential_template_service.credential_templates (
                id,
                organization_id,
                name,
                description,
                credential_type,
                vct,
                doctype,
                claims,
                privacy_posture,
                selective_disclosure_fields,
                derived_attributes,
                version,
                display_style,
                validity_rules,
                issuer_requirements,
                supported_formats,
                wallet_configs,
                credential_payload_format,
                zk_predicate_claims,
                status,
                created_at,
                updated_at
            ) VALUES (
                :id,
                :organization_id,
                :name,
                :description,
                :credential_type,
                :vct,
                :doctype,
                :claims,
                :privacy_posture,
                CAST(:selective_disclosure_fields AS jsonb),
                CAST(:derived_attributes AS jsonb),
                :version,
                :display_style,
                :validity_rules,
                :issuer_requirements,
                :supported_formats,
                :wallet_configs,
                :credential_payload_format,
                :zk_predicate_claims,
                :status,
                :created_at,
                :updated_at
            )
            """
        ),
        {
            "id": TEMPLATE_ID,
            "organization_id": MARTY_ORG_ID,
            "name": "Member Login Credential",
            "description": (
                "Free credential issued to Marty platform members. Use it to log in "
                "to the platform with your wallet instead of a password."
            ),
            "credential_type": "MemberCredential",
            "vct": "https://marty.example/credentials/MemberCredential",
            "doctype": "com.elevenid.member_credential",
            "claims": json.dumps(CLAIMS),
            "privacy_posture": "selective_disclosure",
            "display_style": json.dumps(DISPLAY_STYLE),
            "validity_rules": json.dumps(VALIDITY_RULES),
            "issuer_requirements": json.dumps(ISSUER_REQUIREMENTS),
            "supported_formats": json.dumps(["sd_jwt_vc"]),
            "wallet_configs": json.dumps(WALLET_CONFIGS),
            "credential_payload_format": "ietf_sd_jwt",
            "zk_predicate_claims": json.dumps([]),
            "status": "active",
            "created_at": NOW,
            "updated_at": NOW,
            "selective_disclosure_fields": json.dumps(
                [c["name"] for c in CLAIMS if c.get("selectively_disclosable")]
            ),
            "derived_attributes": json.dumps([]),
            "version": 1,
        },
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text(
            "DELETE FROM credential_template_service.credential_templates WHERE id = :id"
        ),
        {"id": TEMPLATE_ID},
    )
