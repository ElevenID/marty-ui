"""Seed mDL (ISO 18013-5) credential template for the Marty default organisation.

Adds a Mobile Driving Licence credential template to the Marty org catalog so
that members can be issued an mDoc-format identity credential alongside the
existing MemberCredential (SD-JWT login badge).

This template mirrors the demo org mDL template (20260226_0002) but is scoped
to the Marty org and configured for instant issuance via the applicant catalog
UI (no review required, free, instant).

Revision ID: 20260316_0000
Revises: 20260314_0000
Create Date: 2026-03-16 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260316_0000"
down_revision = "20260309_0002"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
TEMPLATE_ID = "50000000-0000-0000-0000-000000000020"
NOW = "2026-03-16T00:00:00+00:00"

CREDENTIAL_TYPE = "org.iso.18013.5.1.mDL"
VCT = "https://marty.example/credentials/org.iso.18013.5.1.mDL"

CLAIMS = [
    {
        "id": "marty-mdl-family-name",
        "name": "family_name",
        "display_name": "Family Name",
        "description": "Last name(s) or surname(s) of the mDL holder",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-mdl-given-name",
        "name": "given_name",
        "display_name": "Given Name",
        "description": "First name(s) of the mDL holder",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-mdl-birth-date",
        "name": "birth_date",
        "display_name": "Date of Birth",
        "description": "Birth date of the mDL holder (YYYY-MM-DD)",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": True,
        "derivable": True,
    },
    {
        "id": "marty-mdl-issue-date",
        "name": "issue_date",
        "display_name": "Issue Date",
        "description": "Date on which the mDL was issued (YYYY-MM-DD)",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-mdl-expiry-date",
        "name": "expiry_date",
        "display_name": "Expiry Date",
        "description": "Date on which the mDL expires (YYYY-MM-DD)",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-mdl-issuing-country",
        "name": "issuing_country",
        "display_name": "Issuing Country",
        "description": "Alpha-2 country code of the issuing authority (ISO 3166-1)",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-mdl-issuing-authority",
        "name": "issuing_authority",
        "display_name": "Issuing Authority",
        "description": "Name of the issuing authority",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-mdl-document-number",
        "name": "document_number",
        "display_name": "Document Number",
        "description": "Unique document number assigned by the issuing authority",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-mdl-driving-privileges",
        "name": "driving_privileges",
        "display_name": "Driving Privileges",
        "description": "Vehicle categories and conditions the holder is authorised to drive",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-mdl-un-distinguishing-sign",
        "name": "un_distinguishing_sign",
        "display_name": "UN Distinguishing Sign",
        "description": "UN distinguishing sign of the issuing country (e.g. USA, GBR)",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-mdl-portrait",
        "name": "portrait",
        "display_name": "Portrait Photo",
        "description": "Facial image of the mDL holder",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-mdl-resident-address",
        "name": "resident_address",
        "display_name": "Resident Address",
        "description": "Permanent place of residence",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-mdl-age-over-21",
        "name": "age_over_21",
        "display_name": "Age Over 21",
        "description": "Whether the holder is over 21 years old",
        "claim_type": "boolean",
        "required": False,
        "selectively_disclosable": True,
        "derivable": True,
    },
]

SELECTIVE_DISCLOSURE_FIELDS = [
    c["name"] for c in CLAIMS if c["selectively_disclosable"]
]

WALLET_CONFIGS = [
    {
        "id": "marty-mdl-wc-default",
        "wallet_id": "wr-default",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "mso_mdoc",
        "credential_configuration_id": "org.iso.18013.5.1.mDL#mdoc",
        "display_name": "Any OID4VCI Wallet",
        "issuer_url_suffix": None,
        "custom_metadata": {},
    },
    {
        "id": "marty-mdl-wc-spruce",
        "wallet_id": "wr-spruce-001",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "mso_mdoc",
        "credential_configuration_id": "org.iso.18013.5.1.mDL#mdoc",
        "display_name": "SpruceKit",
        "issuer_url_suffix": None,
        "custom_metadata": {},
    },
    {
        "id": "marty-mdl-wc-marty",
        "wallet_id": "wr-marty-001",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "mso_mdoc",
        "credential_configuration_id": "org.iso.18013.5.1.mDL#mdoc",
        "display_name": "Marty Authenticator",
        "issuer_url_suffix": None,
        "custom_metadata": {},
    },
]

DISPLAY_STYLE = {
    "background_color": "#0f4c81",
    "text_color": "#ffffff",
    "logo_url": None,
    "background_image_url": None,
    "border_color": None,
}

VALIDITY_RULES = {
    "ttl_days": 1825,
    "expiration_mode": "absolute",
    "reissue_window_days": 90,
    "max_uses": None,
    "require_fresh_issuance_for_presentation": False,
}

ISSUER_REQUIREMENTS = {
    "required_attributes": ["given_name", "family_name", "birth_date"],
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
            "name": "Mobile Driving Licence (mDL)",
            "description": (
                "ISO/IEC 18013-5 Mobile Driving Licence credential. "
                "Verifiable mDoc identity credential that proves your "
                "driving privileges — issued instantly to your wallet."
            ),
            "credential_type": CREDENTIAL_TYPE,
            "vct": VCT,
            "doctype": CREDENTIAL_TYPE,
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
    op.get_bind().execute(
        sa.text(
            "DELETE FROM credential_template_service.credential_templates WHERE id = :id"
        ),
        {"id": TEMPLATE_ID},
    )
