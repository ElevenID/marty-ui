"""Add ISO 18013-5 mDL demo template for SpruceKit.

Adds a canonical ``org.iso.18013.5.1.mDL`` credential template to the demo
organisation so that the SpruceKit OID4VCI flow can issue a properly-typed
Mobile Driving Licence credential.

The key difference from the existing ``drivers_license`` demo template:

* ``credential_type`` = ``org.iso.18013.5.1.mDL``  (the full ISO doctype as
  the credential-type identifier)
* ``vct`` = ``https://marty.example/credentials/org.iso.18013.5.1.mDL``  (the
  vct advertised in the per-org ``/spruce`` issuer metadata under the
  ``org.iso.18013.5.1.mDL#spruce-sd-jwt`` configuration entry)
* Claims follow ISO 18013-5 mandatory + common optional data elements.
* ``wallet_configs`` includes the SpruceKit ``spruce-vc+sd-jwt`` entry so the
  issuance service generates the correct ``openid-credential-offer://`` URI
  pointing at the ``/spruce`` issuer URL.

Flow (SpruceKit perspective):
  1. Marty initiates issuance via this template.
  2. Offer URI: ``openid-credential-offer://?credential_offer={...}``
     with ``credential_issuer = .../org/<id>/spruce``
     and ``credential_configuration_ids = ["org.iso.18013.5.1.mDL#spruce-sd-jwt"]``
  3. SpruceKit fetches ``.well-known/openid-credential-issuer`` from the
     spruce issuer URL, finds ``org.iso.18013.5.1.mDL#spruce-sd-jwt`` with
     ``format: "spruce-vc+sd-jwt"`` + ``vct``.
  4. Token exchange + credential request succeed.

Revision ID: 20260226_0002
Revises: 20260226_0001
Create Date: 2026-02-26 12:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa
from marty_common.migration_profile import skip_demo_migrations


# revision identifiers, used by Alembic.
revision = "20260226_0002"
down_revision = "20260226_0001"
branch_labels = None
depends_on = None


DEMO_ORG_ID = "22222222-2222-2222-2222-222222222222"

# Stable UUID for this template — never reuse.
TEMPLATE_ID = "40000000-0000-0000-0000-000000000008"

# ISO 18013-5 credential type — the full doctype string used as the
# credential_configuration_id base in OID4VCI metadata.
CREDENTIAL_TYPE = "org.iso.18013.5.1.mDL"

# VCT must match what the /org/<id>/spruce issuer metadata advertises under
# org.iso.18013.5.1.mDL#spruce-sd-jwt.
VCT = "https://marty.example/credentials/org.iso.18013.5.1.mDL"

# ISO 18013-5 mDL data elements (mandatory + common optional).
# Selective-disclosure is enabled on all PII fields; document_number and
# driving_privileges are marked non-disclosable (always included in proof).
CLAIMS = [
    {
        "id": "mdl-claim-family-name",
        "name": "family_name",
        "display_name": "Family Name",
        "description": "Last name(s) or surname(s) of the mDL holder",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "mdl-claim-given-name",
        "name": "given_name",
        "display_name": "Given Name",
        "description": "First name(s) of the mDL holder",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "mdl-claim-birth-date",
        "name": "birth_date",
        "display_name": "Date of Birth",
        "description": "Birth date of the mDL holder (YYYY-MM-DD)",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": True,
        "derivable": True,
    },
    {
        "id": "mdl-claim-issue-date",
        "name": "issue_date",
        "display_name": "Issue Date",
        "description": "Date on which the mDL was issued (YYYY-MM-DD)",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "mdl-claim-expiry-date",
        "name": "expiry_date",
        "display_name": "Expiry Date",
        "description": "Date on which the mDL expires (YYYY-MM-DD)",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "mdl-claim-issuing-country",
        "name": "issuing_country",
        "display_name": "Issuing Country",
        "description": "Alpha-2 country code of the issuing authority (ISO 3166-1)",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "mdl-claim-issuing-authority",
        "name": "issuing_authority",
        "display_name": "Issuing Authority",
        "description": "Name of the issuing authority",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "mdl-claim-document-number",
        "name": "document_number",
        "display_name": "Document Number",
        "description": "Unique document number assigned by the issuing authority",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "mdl-claim-driving-privileges",
        "name": "driving_privileges",
        "display_name": "Driving Privileges",
        "description": "Vehicle categories and conditions the holder is authorised to drive",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "mdl-claim-un-distinguishing-sign",
        "name": "un_distinguishing_sign",
        "display_name": "UN Distinguishing Sign",
        "description": "UN distinguishing sign of the issuing country (e.g. USA, GBR)",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    # --- Common optional elements ---
    {
        "id": "mdl-claim-resident-address",
        "name": "resident_address",
        "display_name": "Resident Address",
        "description": "Permanent place of residence",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "mdl-claim-birth-place",
        "name": "birth_place",
        "display_name": "Place of Birth",
        "description": "Country and municipality or state/province where the holder was born",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "mdl-claim-age-over-21",
        "name": "age_over_21",
        "display_name": "Age Over 21",
        "description": "Whether the holder is over 21 years old",
        "claim_type": "boolean",
        "required": False,
        "selectively_disclosable": True,
        "derivable": True,
    },
]

# Fields the wallet may request individually via selective disclosure.
SELECTIVE_DISCLOSURE_FIELDS = [
    c["name"] for c in CLAIMS if c["selectively_disclosable"]
]

# SpruceKit wallet configuration — format_variant "mso_mdoc" selects
# the org.iso.18013.5.1.mDL#mdoc entry in the standard issuer metadata, which
# advertises format: "mso_mdoc" and doctype: "org.iso.18013.5.1.mDL".
# deep_link_scheme "openid-credential-offer://" is the standard OID4VCI scheme
# registered by the SpruceKit identity wallet app.
WALLET_CONFIGS = [
    {
        "wallet_id": "sprucekit",
        "deep_link_scheme": "openid-credential-offer://",
        "format_variant": "mso_mdoc",
    }
]


def upgrade() -> None:
    if skip_demo_migrations():
        return

    conn = op.get_bind()

    # Safety guard: skip if the credential_templates table does not exist yet.
    has_table = conn.execute(
        sa.text(
            "SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL"
        )
    ).scalar_one()
    if not has_table:
        return

    # Guard: skip if wallet_configs column is absent (pre-20260224_0001).
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
    ).scalar_one()

    payload = {
        "id": TEMPLATE_ID,
        "organization_id": DEMO_ORG_ID,
        "name": "ISO 18013-5 mDL",
        "description": "ISO/IEC 18013-5 Mobile Driving Licence — full doctype identifier for SpruceKit compatibility",
        "credential_type": CREDENTIAL_TYPE,
        "vct": VCT,
        "doctype": CREDENTIAL_TYPE,
        "claims": json.dumps(CLAIMS),
        "selective_disclosure_fields": json.dumps(SELECTIVE_DISCLOSURE_FIELDS),
        "derived_attributes": json.dumps([]),
        "display_style": json.dumps({"background_color": "#0f4c81", "text_color": "#ffffff"}),
        "validity_rules": json.dumps(
            {
                "default_validity_days": 1825,   # 5 years — typical driving licence validity
                "max_validity_days": 3650,
                "renewable": True,
                "renewal_window_days": 90,
                "require_revalidation": True,
            }
        ),
        "issuer_requirements": json.dumps({"allowed_issuer_dids": []}),
        "supported_formats": json.dumps(["mso_mdoc"]),
        "credential_payload_format": "mso_mdoc",
        "wallet_configs": json.dumps(WALLET_CONFIGS) if has_wallet_col else json.dumps([]),
    }

    # UPDATE existing row (idempotent re-run).
    update_cols = """
        name                      = :name,
        description               = :description,
        status                    = 'active',
        vct                       = :vct,
        doctype                   = :doctype,
        claims                    = CAST(:claims AS jsonb),
        privacy_posture           = 'selective_disclosure',
        selective_disclosure_fields = CAST(:selective_disclosure_fields AS jsonb),
        derived_attributes        = CAST(:derived_attributes AS jsonb),
        display_style             = CAST(:display_style AS jsonb),
        validity_rules            = CAST(:validity_rules AS jsonb),
        issuer_requirements       = CAST(:issuer_requirements AS jsonb),
        supported_formats         = CAST(:supported_formats AS jsonb),
        credential_payload_format = :credential_payload_format,
        version                   = 1,
        updated_at                = NOW()
    """
    if has_wallet_col:
        update_cols += ", wallet_configs = CAST(:wallet_configs AS jsonb)"

    conn.execute(
        sa.text(
            f"""
            UPDATE credential_template_service.credential_templates
            SET {update_cols}
            WHERE organization_id = :organization_id
              AND credential_type = :credential_type
            """
        ),
        payload,
    )

    # INSERT if row doesn't exist yet.
    conn.execute(
        sa.text(
            f"""
            INSERT INTO credential_template_service.credential_templates (
                id,
                organization_id,
                name,
                description,
                status,
                credential_type,
                vct,
                doctype,
                claims,
                privacy_posture,
                selective_disclosure_fields,
                derived_attributes,
                display_style,
                validity_rules,
                issuer_requirements,
                supported_formats,
                credential_payload_format,
                {"wallet_configs," if has_wallet_col else ""}
                version,
                created_at,
                updated_at
            )
            SELECT
                :id,
                :organization_id,
                :name,
                :description,
                'active',
                :credential_type,
                :vct,
                :doctype,
                CAST(:claims AS jsonb),
                'selective_disclosure',
                CAST(:selective_disclosure_fields AS jsonb),
                CAST(:derived_attributes AS jsonb),
                CAST(:display_style AS jsonb),
                CAST(:validity_rules AS jsonb),
                CAST(:issuer_requirements AS jsonb),
                CAST(:supported_formats AS jsonb),
                :credential_payload_format,
                {"CAST(:wallet_configs AS jsonb)," if has_wallet_col else ""}
                1,
                NOW(),
                NOW()
            WHERE NOT EXISTS (
                SELECT 1
                FROM credential_template_service.credential_templates
                WHERE organization_id = :organization_id
                  AND credential_type = :credential_type
            )
            """
        ),
        payload,
    )


def downgrade() -> None:
    if skip_demo_migrations():
        return

    conn = op.get_bind()

    has_table = conn.execute(
        sa.text(
            "SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL"
        )
    ).scalar_one()
    if not has_table:
        return

    conn.execute(
        sa.text(
            """
            DELETE FROM credential_template_service.credential_templates
            WHERE organization_id = :org_id
              AND id = :template_id
            """
        ),
        {"org_id": DEMO_ORG_ID, "template_id": TEMPLATE_ID},
    )
