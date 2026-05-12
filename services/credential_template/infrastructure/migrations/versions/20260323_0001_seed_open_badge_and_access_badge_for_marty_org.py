"""Seed Open Badge and Employee Access Badge templates for the Marty organisation.

Adds two new one-click-issuable credential templates that showcase different
verticals:

    50000000-…-0040  Verified Member Badge (Open Badge 3.0) — membership/login
    50000000-…-0050  Employee Access Badge                  — enterprise

Both are SD-JWT format with instant issuance, no approval required.

Revision ID: 20260323_0001
Revises: 20260322_0001
Create Date: 2026-03-23 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260323_0001"
down_revision = "20260322_0001"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
NOW = "2026-03-23T00:00:00+00:00"

# ==========================================================================
# Open Badge — Verified Member Badge
# ==========================================================================
OPEN_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000040"
OPEN_BADGE_TYPE = "open_badge"
OPEN_BADGE_VCT = "https://marty.example/credentials/open_badge"

OPEN_BADGE_CLAIMS = [
    {
        "id": "marty-ob-member-id",
        "name": "member_id",
        "display_name": "Member ID",
        "description": "Opaque member identifier issued by the organization",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-ob-email",
        "name": "email",
        "display_name": "Email Address",
        "description": "Holder email address used to resolve the account during login",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-ob-given-name",
        "name": "given_name",
        "display_name": "Given Name",
        "description": "Holder first name",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-ob-family-name",
        "name": "family_name",
        "display_name": "Family Name",
        "description": "Holder last name",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-ob-organization-id",
        "name": "organization_id",
        "display_name": "Organization ID",
        "description": "UUID of the issuing organization",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-ob-organization-name",
        "name": "organization_name",
        "display_name": "Organization Name",
        "description": "Human-readable name of the issuing organization",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-ob-role",
        "name": "role",
        "display_name": "Role",
        "description": "Organization role conveyed during credential-based login",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
        "enum_values": ["applicant", "vendor", "administrator"],
    },
    {
        "id": "marty-ob-achievement-name",
        "name": "achievement_name",
        "display_name": "Achievement Name",
        "description": "Badge title describing the holder's verified membership recognition",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-ob-achievement-description",
        "name": "achievement_description",
        "display_name": "Achievement Description",
        "description": "Description of the membership recognition represented by this badge",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-ob-issued-at",
        "name": "issued_at",
        "display_name": "Issued At",
        "description": "ISO-8601 timestamp when the badge was issued",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
]

OPEN_BADGE_WALLET_CONFIGS = [
    {
        "id": "marty-ob-wc-default",
        "wallet_id": "wr-default",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "sd_jwt_vc",
        "credential_configuration_id": "open_badge#sd-jwt",
        "display_name": "Any OID4VCI Wallet",
        "issuer_url_suffix": None,
        "custom_metadata": {},
    },
    {
        "id": "marty-ob-wc-spruce",
        "wallet_id": "wr-spruce-001",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "spruce-vc+sd-jwt",
        "credential_configuration_id": "open_badge#spruce-sd-jwt",
        "display_name": "SpruceKit",
        "issuer_url_suffix": "/spruce",
        "custom_metadata": {},
    },
    {
        "id": "marty-ob-wc-marty",
        "wallet_id": "wr-marty-001",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "spruce-vc+sd-jwt",
        "credential_configuration_id": "open_badge#spruce-sd-jwt",
        "display_name": "Marty Authenticator",
        "issuer_url_suffix": "/spruce",
        "custom_metadata": {},
    },
]

# ==========================================================================
# Employee Access Badge — enterprise IAM
# ==========================================================================
ACCESS_BADGE_TEMPLATE_ID = "50000000-0000-0000-0000-000000000050"
ACCESS_BADGE_TYPE = "access_badge"
ACCESS_BADGE_VCT = "https://marty.example/credentials/access_badge"

ACCESS_BADGE_CLAIMS = [
    {
        "id": "marty-badge-given-name",
        "name": "given_name",
        "display_name": "Given Name",
        "description": "Employee first name",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-badge-family-name",
        "name": "family_name",
        "display_name": "Family Name",
        "description": "Employee last name",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-badge-email",
        "name": "email",
        "display_name": "Email Address",
        "description": "Corporate email address",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-badge-employee-id",
        "name": "employee_id",
        "display_name": "Employee ID",
        "description": "Unique employee identifier",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-badge-department",
        "name": "department",
        "display_name": "Department",
        "description": "Department or team assignment",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-badge-title",
        "name": "job_title",
        "display_name": "Job Title",
        "description": "Employee job title",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "marty-badge-clearance",
        "name": "clearance_level",
        "display_name": "Clearance Level",
        "description": "Security clearance level (general / restricted / confidential)",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
        "enum_values": ["general", "restricted", "confidential"],
    },
    {
        "id": "marty-badge-building-access",
        "name": "building_access",
        "display_name": "Building Access",
        "description": "Comma-separated building codes the employee can access",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-badge-issue-date",
        "name": "issue_date",
        "display_name": "Issue Date",
        "description": "Date the badge was issued",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "marty-badge-expiry-date",
        "name": "expiry_date",
        "display_name": "Expiry Date",
        "description": "Date the badge expires",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
]

ACCESS_BADGE_WALLET_CONFIGS = [
    {
        "id": "marty-badge-wc-default",
        "wallet_id": "wr-default",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "sd_jwt_vc",
        "credential_configuration_id": "access_badge#sd-jwt",
        "display_name": "Any OID4VCI Wallet",
        "issuer_url_suffix": None,
        "custom_metadata": {},
    },
    {
        "id": "marty-badge-wc-spruce",
        "wallet_id": "wr-spruce-001",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "spruce-vc+sd-jwt",
        "credential_configuration_id": "access_badge#spruce-sd-jwt",
        "display_name": "SpruceKit",
        "issuer_url_suffix": "/spruce",
        "custom_metadata": {},
    },
    {
        "id": "marty-badge-wc-marty",
        "wallet_id": "wr-marty-001",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "spruce-vc+sd-jwt",
        "credential_configuration_id": "access_badge#spruce-sd-jwt",
        "display_name": "Marty Authenticator",
        "issuer_url_suffix": "/spruce",
        "custom_metadata": {},
    },
]

# ==========================================================================
# Shared styling / rules
# ==========================================================================

OPEN_BADGE_DISPLAY_STYLE = {
    "background_color": "#6a1b9a",
    "text_color": "#ffffff",
    "logo_url": None,
    "background_image_url": None,
    "border_color": None,
}

ACCESS_BADGE_DISPLAY_STYLE = {
    "background_color": "#e65100",
    "text_color": "#ffffff",
    "logo_url": None,
    "background_image_url": None,
    "border_color": None,
}

VALIDITY_RULES_1Y = {
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


# ==========================================================================
# Templates data
# ==========================================================================

TEMPLATES = [
    {
        "id": OPEN_BADGE_TEMPLATE_ID,
        "name": "Verified Member Badge",
        "description": (
            "Open Badge 3.0-compatible membership credential — verifiable proof "
            "of active organization membership that can be presented for "
            "passwordless sign-in where accepted."
        ),
        "credential_type": OPEN_BADGE_TYPE,
        "vct": OPEN_BADGE_VCT,
        "doctype": "org.openbadges.v3",
        "claims": OPEN_BADGE_CLAIMS,
        "wallet_configs": OPEN_BADGE_WALLET_CONFIGS,
        "display_style": OPEN_BADGE_DISPLAY_STYLE,
    },
    {
        "id": ACCESS_BADGE_TEMPLATE_ID,
        "name": "Employee Access Badge",
        "description": (
            "Corporate access badge credential — verifiable proof of employment, "
            "department, and building access issued instantly to your wallet."
        ),
        "credential_type": ACCESS_BADGE_TYPE,
        "vct": ACCESS_BADGE_VCT,
        "doctype": "com.enterprise.access.badge",
        "claims": ACCESS_BADGE_CLAIMS,
        "wallet_configs": ACCESS_BADGE_WALLET_CONFIGS,
        "display_style": ACCESS_BADGE_DISPLAY_STYLE,
    },
]


def upgrade() -> None:
    conn = op.get_bind()

    has_table = conn.execute(
        sa.text(
            "SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL"
        )
    ).scalar()
    if not has_table:
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

    for tmpl in TEMPLATES:
        existing = conn.execute(
            sa.text(
                "SELECT id FROM credential_template_service.credential_templates WHERE id = :id"
            ),
            {"id": tmpl["id"]},
        ).fetchone()
        if existing:
            continue

        claims = tmpl["claims"]
        sd_fields = [c["name"] for c in claims if c.get("selectively_disclosable")]

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
                "id": tmpl["id"],
                "organization_id": MARTY_ORG_ID,
                "name": tmpl["name"],
                "description": tmpl["description"],
                "credential_type": tmpl["credential_type"],
                "vct": tmpl["vct"],
                "doctype": tmpl["doctype"],
                "claims": json.dumps(claims),
                "privacy_posture": "selective_disclosure",
                "selective_disclosure_fields": json.dumps(sd_fields),
                "derived_attributes": json.dumps([]),
                "version": 2,
                "display_style": json.dumps(tmpl["display_style"]),
                "validity_rules": json.dumps(VALIDITY_RULES_1Y),
                "issuer_requirements": json.dumps(ISSUER_REQUIREMENTS),
                "supported_formats": json.dumps(["sd_jwt_vc"]),
                "credential_payload_format": "ietf_sd_jwt",
                "zk_predicate_claims": json.dumps([]),
                "wallet_configs": json.dumps(tmpl["wallet_configs"]),
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

    for tmpl in TEMPLATES:
        conn.execute(
            sa.text(
                "DELETE FROM credential_template_service.credential_templates WHERE id = :id"
            ),
            {"id": tmpl["id"]},
        )
