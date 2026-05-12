"""Seed VDS-NC credential templates for the Marty default organisation.

Adds five ICAO VDS-NC travel-document credential templates that cover the full
set of credential types the Marty issuance stack can now issue via the
VDSNC-RUST signing pipeline:

  50000000-…-0060  ICAO ePassport / MRV  (VDS-NC + mso_mdoc dual-format)
  50000000-…-0070  ICAO DTC Type 1       (VDS-NC only — biographic DTC)
  50000000-…-0080  ICAO DTC Type 2       (VDS-NC only — biographic + biometric DTC)
  50000000-…-0090  ICAO Visa             (VDS-NC only — machine-readable visa)
  50000000-…-00a0  ICAO Emergency Travel Document (VDS-NC only)

Each template carries:
  • VDS-NC format in ``supported_formats``
  • ``credential_payload_format = "vds_nc"`` (routes to VDSNC-RUST signer)
  • ICAO-aligned claim schema with VDS-NC field names
  • mDoc namespace / element identifiers on dual-format templates
  • Marty Authenticator wallet_config entry pointing at the ``#vds-nc``
    credential_configuration_id emitted by the OID4VCI metadata endpoint

Revision ID: 20260417_0001
Revises: 20260403_0003
Create Date: 2026-04-17 00:00:00.000000+00:00
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "20260417_0001"
down_revision = "20260403_0003"
branch_labels = None
depends_on = None


MARTY_ORG_ID = "00000000-0000-0000-0000-000000000001"
NOW = "2026-04-17T00:00:00+00:00"

# ---------------------------------------------------------------------------
# Shared wallet config builder helpers
# ---------------------------------------------------------------------------

def _vdsnc_wallet_config(cred_type: str, wc_id_prefix: str) -> list[dict]:
    """Standard wallet configs for a VDS-NC credential type."""
    config_id = f"{cred_type}#vds-nc"
    return [
        {
            "id": f"{wc_id_prefix}-wc-default",
            "wallet_id": "wr-default",
            "deep_link_scheme": "openid-credential-offer://",
            "format_variant": "vds_nc",
            "credential_configuration_id": config_id,
            "display_name": "Any OID4VCI Wallet",
            "issuer_url_suffix": None,
            "custom_metadata": {},
        },
        {
            "id": f"{wc_id_prefix}-wc-marty",
            "wallet_id": "wr-marty-001",
            "deep_link_scheme": "openid-credential-offer://",
            "format_variant": "vds_nc",
            "credential_configuration_id": config_id,
            "display_name": "Marty Authenticator",
            "issuer_url_suffix": None,
            "custom_metadata": {},
        },
    ]


def _dual_wallet_config(cred_type: str, wc_id_prefix: str) -> list[dict]:
    """Wallet configs for a template that supports both VDS-NC and mso_mdoc."""
    vdsnc = _vdsnc_wallet_config(cred_type, wc_id_prefix)
    mdoc = [
        {
            "id": f"{wc_id_prefix}-wc-mdoc-default",
            "wallet_id": "wr-default",
            "deep_link_scheme": "openid-credential-offer://",
            "format_variant": "mso_mdoc",
            "credential_configuration_id": f"{cred_type}#mdoc",
            "display_name": "Any OID4VCI Wallet (mDoc)",
            "issuer_url_suffix": None,
            "custom_metadata": {},
        },
        {
            "id": f"{wc_id_prefix}-wc-mdoc-marty",
            "wallet_id": "wr-marty-001",
            "deep_link_scheme": "openid-credential-offer://",
            "format_variant": "mso_mdoc",
            "credential_configuration_id": f"{cred_type}#mdoc",
            "display_name": "Marty Authenticator (mDoc)",
            "issuer_url_suffix": None,
            "custom_metadata": {},
        },
    ]
    return vdsnc + mdoc


# ============================================================================
# Template 1 — ICAO ePassport / Machine Readable Visa (dual: VDS-NC + mDoc)
# ============================================================================

EPASSPORT_TEMPLATE_ID = "50000000-0000-0000-0000-000000000060"
EPASSPORT_TYPE = "com.icao.mrv"
EPASSPORT_VCT = "https://marty.example/credentials/com.icao.mrv"
EPASSPORT_DOCTYPE = "com.icao.mrv"
EPASSPORT_MDOC_NS = "com.icao.mrv.1"

EPASSPORT_CLAIMS = [
    {
        "id": "icao-mrv-surname",
        "name": "surname",
        "display_name": "Surname",
        "description": "Holder surname (family name) as in travel document",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": EPASSPORT_MDOC_NS,
        "mdoc_element_identifier": "surname",
    },
    {
        "id": "icao-mrv-given-names",
        "name": "given_names",
        "display_name": "Given Names",
        "description": "Holder given names as in travel document",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": EPASSPORT_MDOC_NS,
        "mdoc_element_identifier": "given_names",
    },
    {
        "id": "icao-mrv-nationality",
        "name": "nationality",
        "display_name": "Nationality",
        "description": "3-letter ISO 3166-1 alpha-3 nationality code",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": EPASSPORT_MDOC_NS,
        "mdoc_element_identifier": "nationality",
    },
    {
        "id": "icao-mrv-date-of-birth",
        "name": "date_of_birth",
        "display_name": "Date of Birth",
        "description": "Holder date of birth (YYMMDD)",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": EPASSPORT_MDOC_NS,
        "mdoc_element_identifier": "date_of_birth",
    },
    {
        "id": "icao-mrv-sex",
        "name": "sex",
        "display_name": "Sex",
        "description": "Holder sex (M / F / <)",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
        "enum_values": ["M", "F", "<"],
        "mdoc_namespace": EPASSPORT_MDOC_NS,
        "mdoc_element_identifier": "sex",
    },
    {
        "id": "icao-mrv-document-number",
        "name": "document_number",
        "display_name": "Document Number",
        "description": "Travel document number",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
        "mdoc_namespace": EPASSPORT_MDOC_NS,
        "mdoc_element_identifier": "document_number",
    },
    {
        "id": "icao-mrv-issuing-state",
        "name": "issuing_state",
        "display_name": "Issuing State",
        "description": "3-letter ICAO country code of issuing state",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
        "mdoc_namespace": EPASSPORT_MDOC_NS,
        "mdoc_element_identifier": "issuing_state",
    },
    {
        "id": "icao-mrv-date-of-issue",
        "name": "date_of_issue",
        "display_name": "Date of Issue",
        "description": "Document issue date (YYMMDD)",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
        "mdoc_namespace": EPASSPORT_MDOC_NS,
        "mdoc_element_identifier": "date_of_issue",
    },
    {
        "id": "icao-mrv-date-of-expiry",
        "name": "date_of_expiry",
        "display_name": "Date of Expiry",
        "description": "Document expiry date (YYMMDD)",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
        "mdoc_namespace": EPASSPORT_MDOC_NS,
        "mdoc_element_identifier": "date_of_expiry",
    },
    {
        "id": "icao-mrv-mrz-line-1",
        "name": "mrz_line_1",
        "display_name": "MRZ Line 1",
        "description": "Machine-readable zone line 1 (44 chars)",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": False,
        "derivable": False,
        "mdoc_namespace": EPASSPORT_MDOC_NS,
        "mdoc_element_identifier": "mrz_line_1",
    },
    {
        "id": "icao-mrv-mrz-line-2",
        "name": "mrz_line_2",
        "display_name": "MRZ Line 2",
        "description": "Machine-readable zone line 2 (44 chars)",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": False,
        "derivable": False,
        "mdoc_namespace": EPASSPORT_MDOC_NS,
        "mdoc_element_identifier": "mrz_line_2",
    },
]

# ============================================================================
# Template 2 — ICAO DTC Type 1 (biographic data only, VDS-NC)
# ============================================================================

DTC1_TEMPLATE_ID = "50000000-0000-0000-0000-000000000070"
DTC1_TYPE = "com.icao.dtc.1"
DTC1_VCT = "https://marty.example/credentials/com.icao.dtc.1"

DTC1_CLAIMS = [
    {
        "id": "icao-dtc1-surname",
        "name": "surname",
        "display_name": "Surname",
        "description": "Holder surname",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "icao-dtc1-given-names",
        "name": "given_names",
        "display_name": "Given Names",
        "description": "Holder given names",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "icao-dtc1-nationality",
        "name": "nationality",
        "display_name": "Nationality",
        "description": "ISO 3166-1 alpha-3 nationality code",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "icao-dtc1-date-of-birth",
        "name": "date_of_birth",
        "display_name": "Date of Birth",
        "description": "YYMMDD",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "icao-dtc1-sex",
        "name": "sex",
        "display_name": "Sex",
        "description": "M / F / <",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
        "enum_values": ["M", "F", "<"],
    },
    {
        "id": "icao-dtc1-document-number",
        "name": "document_number",
        "display_name": "Document Number",
        "description": "DTC document number",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "icao-dtc1-issuing-state",
        "name": "issuing_state",
        "display_name": "Issuing State",
        "description": "3-letter ICAO issuing state code",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "icao-dtc1-date-of-expiry",
        "name": "date_of_expiry",
        "display_name": "Date of Expiry",
        "description": "YYMMDD",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "icao-dtc1-source-document-type",
        "name": "source_document_type",
        "display_name": "Source Document Type",
        "description": "Type of underlying MRTD (P=passport, TD1=ID card, TD2=ID card, V=visa)",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": False,
        "derivable": False,
        "enum_values": ["P", "TD1", "TD2", "V"],
    },
]

# ============================================================================
# Template 3 — ICAO DTC Type 2 (biographic + biometric link, VDS-NC)
# ============================================================================

DTC2_TEMPLATE_ID = "50000000-0000-0000-0000-000000000080"
DTC2_TYPE = "com.icao.dtc.2"
DTC2_VCT = "https://marty.example/credentials/com.icao.dtc.2"

DTC2_CLAIMS = DTC1_CLAIMS + [
    {
        "id": "icao-dtc2-face-image-hash",
        "name": "face_image_hash",
        "display_name": "Face Image Hash",
        "description": "SHA-256 hash of the holder portrait image (DTC-2 biometric link)",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "icao-dtc2-biometric-capture-date",
        "name": "biometric_capture_date",
        "display_name": "Biometric Capture Date",
        "description": "ISO date of biometric capture",
        "claim_type": "date",
        "required": False,
        "selectively_disclosable": False,
        "derivable": False,
    },
]

# ============================================================================
# Template 4 — ICAO Conventional Visa (VDS-NC)
# ============================================================================

VISA_TEMPLATE_ID = "50000000-0000-0000-0000-000000000090"
VISA_TYPE = "com.icao.visa"
VISA_VCT = "https://marty.example/credentials/com.icao.visa"

VISA_CLAIMS = [
    {
        "id": "icao-visa-surname",
        "name": "surname",
        "display_name": "Surname",
        "description": "Visa applicant surname",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "icao-visa-given-names",
        "name": "given_names",
        "display_name": "Given Names",
        "description": "Visa applicant given names",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "icao-visa-nationality",
        "name": "nationality",
        "display_name": "Nationality",
        "description": "ISO 3166-1 alpha-3 nationality",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "icao-visa-date-of-birth",
        "name": "date_of_birth",
        "display_name": "Date of Birth",
        "description": "YYMMDD",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "icao-visa-sex",
        "name": "sex",
        "display_name": "Sex",
        "description": "M / F / <",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
        "enum_values": ["M", "F", "<"],
    },
    {
        "id": "icao-visa-visa-number",
        "name": "visa_number",
        "display_name": "Visa Number",
        "description": "Visa document number",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "icao-visa-issuing-state",
        "name": "issuing_state",
        "display_name": "Issuing State",
        "description": "3-letter ICAO code of issuing state",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "icao-visa-date-of-issue",
        "name": "date_of_issue",
        "display_name": "Date of Issue",
        "description": "YYMMDD",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "icao-visa-date-of-expiry",
        "name": "date_of_expiry",
        "display_name": "Date of Expiry",
        "description": "YYMMDD",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "icao-visa-type",
        "name": "visa_type",
        "display_name": "Visa Type",
        "description": "Visa category (tourist, business, transit, student, etc.)",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "icao-visa-duration-of-stay",
        "name": "duration_of_stay",
        "display_name": "Duration of Stay",
        "description": "Permitted duration of stay in days",
        "claim_type": "integer",
        "required": False,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "icao-visa-number-of-entries",
        "name": "number_of_entries",
        "display_name": "Number of Entries",
        "description": "Permitted entries (1, 2, M=multiple)",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": False,
        "derivable": False,
        "enum_values": ["1", "2", "M"],
    },
]

# ============================================================================
# Template 5 — ICAO Emergency Travel Document (VDS-NC)
# ============================================================================

ETD_TEMPLATE_ID = "50000000-0000-0000-0000-0000000000a0"
ETD_TYPE = "com.icao.etd"
ETD_VCT = "https://marty.example/credentials/com.icao.etd"

ETD_CLAIMS = [
    {
        "id": "icao-etd-surname",
        "name": "surname",
        "display_name": "Surname",
        "description": "Holder surname",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "icao-etd-given-names",
        "name": "given_names",
        "display_name": "Given Names",
        "description": "Holder given names",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "icao-etd-nationality",
        "name": "nationality",
        "display_name": "Nationality",
        "description": "ISO 3166-1 alpha-3 nationality",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "icao-etd-date-of-birth",
        "name": "date_of_birth",
        "display_name": "Date of Birth",
        "description": "YYMMDD",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": True,
        "derivable": False,
    },
    {
        "id": "icao-etd-sex",
        "name": "sex",
        "display_name": "Sex",
        "description": "M / F / <",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": True,
        "derivable": False,
        "enum_values": ["M", "F", "<"],
    },
    {
        "id": "icao-etd-document-number",
        "name": "document_number",
        "display_name": "Document Number",
        "description": "ETD document number",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "icao-etd-issuing-state",
        "name": "issuing_state",
        "display_name": "Issuing State",
        "description": "3-letter ICAO issuing state code",
        "claim_type": "string",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "icao-etd-date-of-issue",
        "name": "date_of_issue",
        "display_name": "Date of Issue",
        "description": "YYMMDD",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "icao-etd-date-of-expiry",
        "name": "date_of_expiry",
        "display_name": "Date of Expiry",
        "description": "YYMMDD",
        "claim_type": "date",
        "required": True,
        "selectively_disclosable": False,
        "derivable": False,
    },
    {
        "id": "icao-etd-issuing-authority",
        "name": "issuing_authority",
        "display_name": "Issuing Authority",
        "description": "Consulate or authority that issued the ETD",
        "claim_type": "string",
        "required": False,
        "selectively_disclosable": False,
        "derivable": False,
    },
]

# ============================================================================
# Template specs table
# ============================================================================

TEMPLATES: list[dict] = [
    {
        "id": EPASSPORT_TEMPLATE_ID,
        "name": "ICAO ePassport / MRV",
        "description": (
            "ICAO Machine Readable Travel Document credential issued as both "
            "VDS-NC (tilde-barcode) and ISO 18013-5 mDoc. Suitable for "
            "ePassport, emergency travel document, and machine-readable visa "
            "use cases aligned with ICAO Doc 9303."
        ),
        "credential_type": EPASSPORT_TYPE,
        "vct": EPASSPORT_VCT,
        "doctype": EPASSPORT_DOCTYPE,
        "claims": EPASSPORT_CLAIMS,
        "supported_formats": ["vds_nc", "mso_mdoc"],
        "credential_payload_format": "vds_nc",
        "display_style": {
            "background_color": "#1a237e",
            "text_color": "#ffffff",
            "logo_url": None,
            "background_image_url": None,
            "border_color": "#283593",
        },
        "wallet_configs": _dual_wallet_config(EPASSPORT_TYPE, "icao-mrv"),
        "wc_id_prefix": "icao-mrv",
    },
    {
        "id": DTC1_TEMPLATE_ID,
        "name": "ICAO Digital Travel Credential Type 1",
        "description": (
            "ICAO DTC-1 biographic credential in VDS-NC format. Contains "
            "personal data from a source MRTD. Complies with ICAO Technical "
            "Report on Digital Travel Credentials (DTC) Part 3."
        ),
        "credential_type": DTC1_TYPE,
        "vct": DTC1_VCT,
        "doctype": None,
        "claims": DTC1_CLAIMS,
        "supported_formats": ["vds_nc"],
        "credential_payload_format": "vds_nc",
        "display_style": {
            "background_color": "#0d47a1",
            "text_color": "#ffffff",
            "logo_url": None,
            "background_image_url": None,
            "border_color": "#1565c0",
        },
        "wallet_configs": _vdsnc_wallet_config(DTC1_TYPE, "icao-dtc1"),
        "wc_id_prefix": "icao-dtc1",
    },
    {
        "id": DTC2_TEMPLATE_ID,
        "name": "ICAO Digital Travel Credential Type 2",
        "description": (
            "ICAO DTC-2 biographic + biometric-link credential in VDS-NC format. "
            "Extends DTC-1 with a cryptographic hash linking to the holder portrait, "
            "enabling offline biometric verification at border checkpoints."
        ),
        "credential_type": DTC2_TYPE,
        "vct": DTC2_VCT,
        "doctype": None,
        "claims": DTC2_CLAIMS,
        "supported_formats": ["vds_nc"],
        "credential_payload_format": "vds_nc",
        "display_style": {
            "background_color": "#1565c0",
            "text_color": "#ffffff",
            "logo_url": None,
            "background_image_url": None,
            "border_color": "#1976d2",
        },
        "wallet_configs": _vdsnc_wallet_config(DTC2_TYPE, "icao-dtc2"),
        "wc_id_prefix": "icao-dtc2",
    },
    {
        "id": VISA_TEMPLATE_ID,
        "name": "ICAO Machine Readable Visa",
        "description": (
            "ICAO conventional visa credential in VDS-NC format. Encodes visa "
            "type, permitted stay, entry count, and holder biographic data "
            "in a signed VDS-NC barcode."
        ),
        "credential_type": VISA_TYPE,
        "vct": VISA_VCT,
        "doctype": None,
        "claims": VISA_CLAIMS,
        "supported_formats": ["vds_nc"],
        "credential_payload_format": "vds_nc",
        "display_style": {
            "background_color": "#4a148c",
            "text_color": "#ffffff",
            "logo_url": None,
            "background_image_url": None,
            "border_color": "#6a1b9a",
        },
        "wallet_configs": _vdsnc_wallet_config(VISA_TYPE, "icao-visa"),
        "wc_id_prefix": "icao-visa",
    },
    {
        "id": ETD_TEMPLATE_ID,
        "name": "ICAO Emergency Travel Document",
        "description": (
            "ICAO Emergency Travel Document (ETD) credential in VDS-NC format. "
            "Issued by consulates and border authorities as a temporary travel "
            "document. Short validity, typically 30–90 days."
        ),
        "credential_type": ETD_TYPE,
        "vct": ETD_VCT,
        "doctype": None,
        "claims": ETD_CLAIMS,
        "supported_formats": ["vds_nc"],
        "credential_payload_format": "vds_nc",
        "display_style": {
            "background_color": "#b71c1c",
            "text_color": "#ffffff",
            "logo_url": None,
            "background_image_url": None,
            "border_color": "#c62828",
        },
        "wallet_configs": _vdsnc_wallet_config(ETD_TYPE, "icao-etd"),
        "wc_id_prefix": "icao-etd",
    },
]

VALIDITY_RULES_BY_TYPE = {
    EPASSPORT_TYPE: {"ttl_days": 3650, "expiration_mode": "absolute", "reissue_window_days": 180},
    DTC1_TYPE: {"ttl_days": 3650, "expiration_mode": "absolute", "reissue_window_days": 180},
    DTC2_TYPE: {"ttl_days": 3650, "expiration_mode": "absolute", "reissue_window_days": 180},
    VISA_TYPE: {"ttl_days": 365, "expiration_mode": "absolute", "reissue_window_days": 30},
    ETD_TYPE: {"ttl_days": 90, "expiration_mode": "absolute", "reissue_window_days": 14},
}

ISSUER_REQUIREMENTS = {
    "required_attributes": ["surname", "given_names", "date_of_birth", "nationality"],
    "identity_verification_level": "government_issued",
    "approval_required": True,
    "approval_roles": ["administrator"],
}


# ============================================================================
# Migration helpers
# ============================================================================

def _has_table(conn) -> bool:
    return bool(
        conn.execute(
            sa.text(
                "SELECT to_regclass('credential_template_service.credential_templates') IS NOT NULL"
            )
        ).scalar()
    )


def _has_wallet_col(conn) -> bool:
    return bool(
        conn.execute(
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
    )


def _insert_template(conn, tmpl: dict, has_wc: bool) -> None:
    ctype = tmpl["credential_type"]
    claims = tmpl["claims"]
    sd_fields = [c["name"] for c in claims if c.get("selectively_disclosable")]
    validity = VALIDITY_RULES_BY_TYPE.get(ctype, {"ttl_days": 365, "expiration_mode": "absolute", "reissue_window_days": 30})

    wallet_col = ", wallet_configs" if has_wc else ""
    wallet_val = ", CAST(:wallet_configs AS jsonb)" if has_wc else ""

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
                {wallet_col}
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
                {wallet_val}
            )
            """
        ),
        {
            "id": tmpl["id"],
            "organization_id": MARTY_ORG_ID,
            "name": tmpl["name"],
            "description": tmpl["description"],
            "credential_type": ctype,
            "vct": tmpl["vct"],
            "doctype": tmpl.get("doctype"),
            "claims": json.dumps(claims),
            "privacy_posture": "selective_disclosure",
            "selective_disclosure_fields": json.dumps(sd_fields),
            "derived_attributes": json.dumps([]),
            "version": 1,
            "display_style": json.dumps(tmpl["display_style"]),
            "validity_rules": json.dumps(validity),
            "issuer_requirements": json.dumps(ISSUER_REQUIREMENTS),
            "supported_formats": json.dumps(tmpl["supported_formats"]),
            "credential_payload_format": tmpl["credential_payload_format"],
            "zk_predicate_claims": json.dumps([]),
            "wallet_configs": json.dumps(tmpl["wallet_configs"]),
            "status": "active",
            "created_at": NOW,
            "updated_at": NOW,
        },
    )


# ============================================================================
# Upgrade / Downgrade
# ============================================================================

def upgrade() -> None:
    conn = op.get_bind()

    if not _has_table(conn):
        return

    has_wc = _has_wallet_col(conn)

    for tmpl in TEMPLATES:
        existing = conn.execute(
            sa.text(
                "SELECT id FROM credential_template_service.credential_templates WHERE id = :id"
            ),
            {"id": tmpl["id"]},
        ).fetchone()
        if existing:
            continue
        _insert_template(conn, tmpl, has_wc)


def downgrade() -> None:
    conn = op.get_bind()

    if not _has_table(conn):
        return

    for tmpl in TEMPLATES:
        conn.execute(
            sa.text(
                "DELETE FROM credential_template_service.credential_templates WHERE id = :id"
            ),
            {"id": tmpl["id"]},
        )
