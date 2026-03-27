"""Seed mDoc MemberCredential template for the Marty default organisation.

Adds an mDoc-format membership credential template that mirrors the existing
SD-JWT MemberCredential (template 50000000-...-10).  This gives applicants a
choice between the Open Badge (SD-JWT) and mDoc (ISO 18013-5 container)
versions of the same membership identity credential.

The claim schema is identical to the SD-JWT MemberCredential but with
mdoc_namespace / mdoc_element_identifier populated for mDoc encoding.

Revision ID: 20260322_0001
Revises: 20260321_0000
Create Date: 2026-03-22 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260322_0001"
down_revision = "20260321_0000"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
TEMPLATE_ID = "50000000-0000-0000-0000-000000000030"
NOW = "2026-03-22T00:00:00+00:00"

CREDENTIAL_TYPE = "com.elevenid.member_credential"
DOCTYPE = "com.elevenid.member_credential"
VCT = "https://marty.example/credentials/com.elevenid.member_credential"
MDOC_NAMESPACE = "com.elevenid.member_credential.1"

CLAIMS = [
    {
        "id": "marty-mdoc-member-member-id",
        "name": "member_id",
        "display_name": "Member ID",
        "description": "Opaque per-organisation member identifier",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": MDOC_NAMESPACE,
        "mdoc_element_identifier": "member_id",
    },
    {
        "id": "marty-mdoc-member-email",
        "name": "email",
        "display_name": "Email Address",
        "description": "Holder email address (used to resolve the Keycloak user on login)",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": MDOC_NAMESPACE,
        "mdoc_element_identifier": "email",
    },
    {
        "id": "marty-mdoc-member-given-name",
        "name": "given_name",
        "display_name": "Given Name",
        "description": "First name",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": MDOC_NAMESPACE,
        "mdoc_element_identifier": "given_name",
    },
    {
        "id": "marty-mdoc-member-family-name",
        "name": "family_name",
        "display_name": "Family Name",
        "description": "Last name",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": MDOC_NAMESPACE,
        "mdoc_element_identifier": "family_name",
    },
    {
        "id": "marty-mdoc-member-organization-id",
        "name": "organization_id",
        "display_name": "Organisation ID",
        "description": "UUID of the issuing organisation",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": MDOC_NAMESPACE,
        "mdoc_element_identifier": "organization_id",
    },
    {
        "id": "marty-mdoc-member-organization-name",
        "name": "organization_name",
        "display_name": "Organisation Name",
        "description": "Human-readable name of the issuing organisation",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": MDOC_NAMESPACE,
        "mdoc_element_identifier": "organization_name",
    },
    {
        "id": "marty-mdoc-member-role",
        "name": "role",
        "display_name": "Role",
        "description": "Keycloak realm role granted on credential login (applicant | vendor | administrator)",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
        "enum_values": ["applicant", "vendor", "administrator"],
        "mdoc_namespace": MDOC_NAMESPACE,
        "mdoc_element_identifier": "role",
    },
    {
        "id": "marty-mdoc-member-issued-at",
        "name": "issued_at",
        "display_name": "Issued At",
        "description": "ISO-8601 timestamp when the credential was issued",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
        "mdoc_namespace": MDOC_NAMESPACE,
        "mdoc_element_identifier": "issued_at",
    },
]

SELECTIVE_DISCLOSURE_FIELDS = [
    c["name"] for c in CLAIMS if c["selectively_disclosable"]
]

WALLET_CONFIGS = [
    {
        "id": "marty-mdoc-member-wc-default",
        "wallet_id": "wr-default",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "mso_mdoc",
        "credential_configuration_id": "com.elevenid.member_credential#mdoc",
        "display_name": "Any OID4VCI Wallet",
        "issuer_url_suffix": None,
        "custom_metadata": {},
    },
    {
        "id": "marty-mdoc-member-wc-spruce",
        "wallet_id": "wr-spruce-001",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "mso_mdoc",
        "credential_configuration_id": "com.elevenid.member_credential#mdoc",
        "display_name": "SpruceKit",
        "issuer_url_suffix": None,
        "custom_metadata": {},
    },
    {
        "id": "marty-mdoc-member-wc-marty",
        "wallet_id": "wr-marty-001",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "mso_mdoc",
        "credential_configuration_id": "com.elevenid.member_credential#mdoc",
        "display_name": "Marty Authenticator",
        "issuer_url_suffix": None,
        "custom_metadata": {},
    },
]

DISPLAY_STYLE = {
    "background_color": "#2e7d32",
    "text_color": "#ffffff",
    "logo_url": None,
    "background_image_url": None,
    "border_color": None,
}

VALIDITY_RULES = {
    "ttl_days": 365,
    "expiration_mode": "absolute",
    "reissue_window_days": 30,
    "max_uses": None,
    "require_fresh_issuance_for_presentation": False,
}

ISSUER_REQUIREMENTS = {
    "required_attributes": ["email"],
    "identity_verification_level": "self_attested",
    "approval_required": False,
    "approval_roles": [],
}


def upgrade() -> None:
    conn = op.get_bind()

    has_table = conn.execute(
        sa.text(
            "SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL"
        )
    ).scalar()
    if not has_table:
        return

    existing = conn.execute(
        sa.text(
            "SELECT id FROM credential_template_service.credential_templates WHERE id = :id"
        ),
        {"id": TEMPLATE_ID},
    ).fetchone()
    if existing:
        return

    has_wallet_col = conn.execute(
        sa.text(
            """
            SELECT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_schema = 'credential_template_service'
                  AND table_name   = 'credential_templates'
                  AND column_name  = 'wallet_configs'
            )
            """
        )
    ).scalar()

    wallet_insert_col = ", wallet_configs" if has_wallet_col else ""
    wallet_insert_val = ", CAST(:wallet_configs AS jsonb)" if has_wallet_col else ""

    conn.execute(
        sa.text(
            f"""
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
                credential_payload_format,
                zk_predicate_claims,
                status,
                created_at,
                updated_at
                {wallet_insert_col}
            ) VALUES (
                :id,
                :organization_id,
                :name,
                :description,
                :credential_type,
                :vct,
                :doctype,
                CAST(:claims AS jsonb),
                :privacy_posture,
                CAST(:selective_disclosure_fields AS jsonb),
                CAST(:derived_attributes AS jsonb),
                :version,
                CAST(:display_style AS jsonb),
                CAST(:validity_rules AS jsonb),
                CAST(:issuer_requirements AS jsonb),
                CAST(:supported_formats AS jsonb),
                :credential_payload_format,
                CAST(:zk_predicate_claims AS jsonb),
                :status,
                :created_at,
                :updated_at
                {wallet_insert_val}
            )
            """
        ),
        {
            "id": TEMPLATE_ID,
            "organization_id": MARTY_ORG_ID,
            "name": "Membership ID (mDoc)",
            "description": (
                "mDoc-format membership credential — the same identity data as the "
                "SD-JWT Login Credential but in ISO 18013-5 mDoc container format, "
                "compatible with Apple & Google Wallet style experiences."
            ),
            "credential_type": CREDENTIAL_TYPE,
            "vct": VCT,
            "doctype": DOCTYPE,
            "claims": json.dumps(CLAIMS),
            "privacy_posture": "selective_disclosure",
            "selective_disclosure_fields": json.dumps(SELECTIVE_DISCLOSURE_FIELDS),
            "derived_attributes": json.dumps([]),
            "version": 1,
            "display_style": json.dumps(DISPLAY_STYLE),
            "validity_rules": json.dumps(VALIDITY_RULES),
            "issuer_requirements": json.dumps(ISSUER_REQUIREMENTS),
            "supported_formats": json.dumps(["mso_mdoc"]),
            "credential_payload_format": "mso_mdoc",
            "zk_predicate_claims": json.dumps([]),
            "wallet_configs": json.dumps(WALLET_CONFIGS),
            "status": "active",
            "created_at": NOW,
            "updated_at": NOW,
        },
    )


def downgrade() -> None:
    conn = op.get_bind()

    has_table = conn.execute(
        sa.text(
            "SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL"
        )
    ).scalar()
    if not has_table:
        return

    conn.execute(
        sa.text(
            "DELETE FROM credential_template_service.credential_templates WHERE id = :id"
        ),
        {"id": TEMPLATE_ID},
    )
