"""Seed MemberCredential template for SD-JWT-based login.

This template represents an organisation-issued membership credential that
identifies the holder as an active member of that organisation.  It is the
credential used in the "Login with Credential" flow — an org admin issues it
to a member via the standard OID4VCI pipeline; the holder then presents it
(via OID4VP) to authenticate instead of a password.

Claims
------
member_id               - Opaque per-organisation member identifier
email                   - Holder email (used to resolve the Keycloak user)
given_name              - First name
family_name             - Last name
organization_id         - Issuing organisation UUID
organization_name       - Human-readable org name
role                    - Keycloak realm role granted on login
                          (applicant | vendor | administrator)
issued_at               - ISO-8601 issuance timestamp

All claims are selectively disclosable; the login policy only requires
email, organization_id, and role.

Revision ID: 20260227_0001
Revises: 20260226_0002
Create Date: 2026-02-27 00:00:00.000000+00:00
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa


# ---------------------------------------------------------------------------
# Alembic revision metadata
# ---------------------------------------------------------------------------
revision = "20260227_0001"
down_revision = "20260226_0002"
branch_labels = None
depends_on = None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ELEVNID_ORG_ID = "22222222-2222-2222-2222-222222222222"
TEMPLATE_ID = "40000000-0000-0000-0000-000000000010"
NOW = "2026-02-27T00:00:00+00:00"

CLAIMS = [
    {
        "id": "member-claim-member-id",
        "name": "member_id",
        "display_name": "Member ID",
        "description": "Opaque per-organisation member identifier",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": None,
        "mdoc_element_identifier": None,
    },
    {
        "id": "member-claim-email",
        "name": "email",
        "display_name": "Email Address",
        "description": "Holder email address (used to resolve the Keycloak user on login)",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": None,
        "mdoc_element_identifier": None,
    },
    {
        "id": "member-claim-given-name",
        "name": "given_name",
        "display_name": "Given Name",
        "description": "First name",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": None,
        "mdoc_element_identifier": None,
    },
    {
        "id": "member-claim-family-name",
        "name": "family_name",
        "display_name": "Family Name",
        "description": "Last name",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": None,
        "mdoc_element_identifier": None,
    },
    {
        "id": "member-claim-organization-id",
        "name": "organization_id",
        "display_name": "Organisation ID",
        "description": "UUID of the issuing organisation",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": None,
        "mdoc_element_identifier": None,
    },
    {
        "id": "member-claim-organization-name",
        "name": "organization_name",
        "display_name": "Organisation Name",
        "description": "Human-readable name of the issuing organisation",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": None,
        "mdoc_element_identifier": None,
    },
    {
        "id": "member-claim-role",
        "name": "role",
        "display_name": "Role",
        "description": "Keycloak realm role granted on credential login (applicant | vendor | administrator)",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
        "enum_values": ["applicant", "vendor", "administrator"],
        "mdoc_namespace": None,
        "mdoc_element_identifier": None,
    },
    {
        "id": "member-claim-issued-at",
        "name": "issued_at",
        "display_name": "Issued At",
        "description": "ISO-8601 timestamp when the credential was issued",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
        "mdoc_namespace": None,
        "mdoc_element_identifier": None,
    },
]

WALLET_CONFIGS = [
    {
        "id": "member-wc-default",
        "wallet_id": "wr-default",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "sd_jwt_vc",
        "credential_configuration_id": "MemberCredential#sd-jwt",
        "display_name": "Any OID4VCI Wallet",
        "issuer_url_suffix": None,
        "custom_metadata": {},
    },
    {
        "id": "member-wc-spruce",
        "wallet_id": "wr-spruce-001",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "spruce-vc+sd-jwt",
        "credential_configuration_id": "MemberCredential#spruce-sd-jwt",
        "display_name": "SpruceKit",
        "issuer_url_suffix": "/spruce",
        "custom_metadata": {},
    },
    {
        "id": "member-wc-marty",
        "wallet_id": "wr-marty-001",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "spruce-vc+sd-jwt",
        "credential_configuration_id": "MemberCredential#spruce-sd-jwt",
        "display_name": "Marty Authenticator",
        "issuer_url_suffix": "/spruce",
        "custom_metadata": {},
    },
]

VALIDITY_RULES = {
    "ttl_days": 365,
    "expiration_mode": "absolute",
    "reissue_window_days": 30,
    "max_uses": None,
    "require_fresh_issuance_for_presentation": False,
}

DISPLAY_STYLE = {
    "background_color": "#1976d2",
    "text_color": "#ffffff",
    "logo_url": None,
    "background_image_url": None,
    "border_color": None,
}

ISSUER_REQUIREMENTS = {
    "required_attributes": ["email"],
    "identity_verification_level": "self_attested",
    "approval_required": False,
    "approval_roles": [],
}


def upgrade() -> None:
    connection = op.get_bind()

    existing = connection.execute(
        sa.text("SELECT id FROM credential_template_service.credential_templates WHERE id = :id"),
        {"id": TEMPLATE_ID},
    ).fetchone()

    if existing:
        return  # idempotent

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
            "organization_id": ELEVNID_ORG_ID,
            "name": "Member Credential",
            "description": (
                "Organisation-issued membership credential that can be used "
                "in place of a password to log in to the Marty platform."
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
                [c["name"] for c in CLAIMS if c["selectively_disclosable"]]
            ),
            "derived_attributes": json.dumps([]),
            "version": 1,
        },
    )


def downgrade() -> None:
    op.get_bind().execute(
        sa.text("DELETE FROM credential_template_service.credential_templates WHERE id = :id"),
        {"id": TEMPLATE_ID},
    )
