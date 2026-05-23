"""Reset-friendly demo vendor fixture definitions.

This module is the start of the explicit seed-pack path for beta/dev resets.
It mirrors the current effective demo vendor org/catalog/template state that
was previously spread across several Alembic revisions.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Final


DEMO_VENDOR_ORG_ID: Final[str] = "22222222-2222-2222-2222-222222222222"
DEMO_VENDOR_ORG_NAME: Final[str] = "Demo Vendor Org"
DEMO_VENDOR_ORG_SLUG: Final[str] = "demo-vendor-org"

DEMO_VENDOR_ORGANIZATION: Final[dict[str, Any]] = {
    "id": DEMO_VENDOR_ORG_ID,
    "name": DEMO_VENDOR_ORG_NAME,
    "display_name": DEMO_VENDOR_ORG_NAME,
    "slug": DEMO_VENDOR_ORG_SLUG,
    "description": "Demo organization for context switching and join/discovery demonstrations",
    "org_type": "startup",
    "status": "active",
    "join_mechanism": "open",
    "requires_approval": False,
    "is_discoverable": True,
    "settings": {},
}

DEMO_VENDOR_WALLET_CONFIG: Final[dict[str, str]] = {
    "wallet_id": "marty",
    "deep_link_scheme": "openid-credential-offer://",
    "format_variant": "spruce-vc+sd-jwt",
}

DEMO_VENDOR_SPRUCEKIT_MDL_WALLET_CONFIG: Final[dict[str, str]] = {
    "wallet_id": "sprucekit",
    "deep_link_scheme": "openid-credential-offer://",
    "format_variant": "mso_mdoc",
}


def _base_claim(
    claim_id: str,
    name: str,
    description: str,
    claim_type: str,
    *,
    required: bool = True,
    selectively_disclosable: bool = True,
    derivable: bool = False,
) -> dict[str, Any]:
    return {
        "id": claim_id,
        "name": name,
        "display_name": description,
        "description": description,
        "claim_type": claim_type,
        "required": required,
        "selectively_disclosable": selectively_disclosable,
        "derivable": derivable,
    }


def _common_template_claims(credential_type: str) -> list[dict[str, Any]]:
    claims = [
        _base_claim(f"{credential_type}-claim-given-name", "given_name", "Given Name", "string"),
        _base_claim(f"{credential_type}-claim-family-name", "family_name", "Family Name", "string"),
        _base_claim(
            f"{credential_type}-claim-date-of-birth",
            "date_of_birth",
            "Date of Birth",
            "date",
            derivable=True,
        ),
    ]

    if credential_type in {"passport", "travel_visa", "dtc"}:
        claims.append(
            _base_claim(
                f"{credential_type}-claim-document-number",
                "document_number",
                "Document Number",
                "string",
                selectively_disclosable=False,
            )
        )

    return claims


OPEN_BADGE_PROFESSIONAL_DEVELOPMENT_CLAIMS: Final[list[dict[str, Any]]] = [
    {
        "id": "family-name",
        "name": "family_name",
        "required": True,
        "derivable": False,
        "claim_type": "string",
        "description": "Recipient last name",
        "display_name": "Family Name",
        "selectively_disclosable": False,
    },
    {
        "id": "given-name",
        "name": "given_name",
        "required": True,
        "derivable": False,
        "claim_type": "string",
        "description": "Recipient first name",
        "display_name": "Given Name",
        "selectively_disclosable": False,
    },
    {
        "id": "achievement-name",
        "name": "achievement_name",
        "required": True,
        "derivable": False,
        "claim_type": "string",
        "description": "Name of the achievement or certification",
        "display_name": "Achievement Name",
        "selectively_disclosable": False,
    },
    {
        "id": "course-name",
        "name": "course_name",
        "required": True,
        "derivable": False,
        "claim_type": "string",
        "description": "Course or program name",
        "display_name": "Course Name",
        "selectively_disclosable": False,
    },
    {
        "id": "completion-date",
        "name": "completion_date",
        "required": True,
        "derivable": False,
        "claim_type": "date",
        "description": "Date of course completion",
        "display_name": "Completion Date",
        "selectively_disclosable": False,
    },
    {
        "id": "institution-name",
        "name": "institution_name",
        "required": True,
        "derivable": False,
        "claim_type": "string",
        "description": "Name of issuing institution",
        "display_name": "Institution Name",
        "selectively_disclosable": False,
    },
    {
        "id": "badge-image",
        "name": "badge_image",
        "required": False,
        "derivable": False,
        "claim_type": "string",
        "description": "URL to badge image",
        "display_name": "Badge Image",
        "selectively_disclosable": False,
    },
    {
        "id": "achievement-criteria",
        "name": "achievement_criteria",
        "required": False,
        "derivable": False,
        "claim_type": "string",
        "description": "Criteria for earning the badge",
        "display_name": "Achievement Criteria",
        "selectively_disclosable": False,
    },
    {
        "id": "grade",
        "name": "grade",
        "required": False,
        "derivable": False,
        "claim_type": "string",
        "description": "Grade or score received",
        "display_name": "Grade",
        "selectively_disclosable": False,
    },
    {
        "id": "credit-hours",
        "name": "credit_hours",
        "required": False,
        "derivable": False,
        "claim_type": "integer",
        "description": "Credit hours earned",
        "display_name": "Credit Hours",
        "selectively_disclosable": False,
    },
    {
        "id": "instructor-name",
        "name": "instructor_name",
        "required": False,
        "derivable": False,
        "claim_type": "string",
        "description": "Name of the instructor",
        "display_name": "Instructor Name",
        "selectively_disclosable": False,
    },
    {
        "id": "certificate-id",
        "name": "certificate_id",
        "required": False,
        "derivable": False,
        "claim_type": "string",
        "description": "Unique certificate identifier",
        "display_name": "Certificate ID",
        "selectively_disclosable": False,
    },
]

ISO_18013_MDL_SPRUCEKIT_CLAIMS: Final[list[dict[str, Any]]] = [
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

DEMO_VENDOR_CREDENTIAL_TYPES: Final[tuple[dict[str, Any], ...]] = (
    {
        "id": "demo-passport-credential-type",
        "name": "passport",
        "description": "Demo Passport Credential",
        "format": "jwt_vc_json",
        "schema_definition": {
            "required_fields": [
                "given_name",
                "family_name",
                "birth_date",
                "nationality",
                "document_number",
                "expiry_date",
            ],
            "optional_fields": [
                "portrait",
                "sex",
                "birth_place",
                "issuing_authority",
            ],
            "doctype": "org.icao.mrtd.passport",
        },
        "display_config": {
            "display_name": "Demo Passport Credential",
            "is_published": True,
            "is_system_template": False,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "2-3 business days",
        },
    },
    {
        "id": "demo-drivers-license-credential-type",
        "name": "drivers_license",
        "description": "Demo Driver License Credential",
        "format": "jwt_vc_json",
        "schema_definition": {
            "required_fields": [
                "given_name",
                "family_name",
                "birth_date",
                "document_number",
                "issue_date",
                "expiry_date",
            ],
            "optional_fields": [
                "portrait",
                "address",
                "vehicle_categories",
                "restrictions",
            ],
            "doctype": "org.iso.18013.5.1.mDL",
        },
        "display_config": {
            "display_name": "Demo Driver License Credential",
            "is_published": True,
            "is_system_template": False,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "2-3 business days",
        },
    },
    {
        "id": "demo-national-id-credential-type",
        "name": "national_id",
        "description": "Demo National ID Credential",
        "format": "jwt_vc_json",
        "schema_definition": {
            "required_fields": [
                "given_name",
                "family_name",
                "birth_date",
                "document_number",
                "nationality",
            ],
            "optional_fields": [
                "portrait",
                "sex",
                "birth_place",
                "address",
            ],
            "doctype": "org.marty.national_id.1",
        },
        "display_config": {
            "display_name": "Demo National ID Credential",
            "is_published": True,
            "is_system_template": False,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "2-3 business days",
        },
    },
    {
        "id": "demo-travel-visa-credential-type",
        "name": "travel_visa",
        "description": "Demo Travel Visa Credential",
        "format": "jwt_vc_json",
        "schema_definition": {
            "required_fields": [
                "given_name",
                "family_name",
                "birth_date",
                "nationality",
                "document_number",
            ],
            "optional_fields": [
                "portrait",
                "visa_type",
                "valid_from",
                "valid_until",
                "issuing_country",
            ],
            "doctype": "org.marty.travel.visa.1",
        },
        "display_config": {
            "display_name": "Demo Travel Visa Credential",
            "is_published": True,
            "is_system_template": False,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "2-3 business days",
        },
    },
    {
        "id": "demo-access-badge-credential-type",
        "name": "access_badge",
        "description": "Demo Access Badge Credential",
        "format": "jwt_vc_json",
        "schema_definition": {
            "required_fields": [
                "given_name",
                "family_name",
                "employee_id",
            ],
            "optional_fields": [
                "portrait",
                "department",
                "access_level",
                "valid_from",
                "valid_until",
            ],
            "doctype": "org.marty.access.badge.1",
        },
        "display_config": {
            "display_name": "Demo Access Badge Credential",
            "is_published": True,
            "is_system_template": False,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "1-2 business days",
        },
    },
    {
        "id": "demo-dtc-credential-type",
        "name": "dtc",
        "description": "Demo DTC Credential",
        "format": "jwt_vc_json",
        "schema_definition": {
            "required_fields": [
                "passport_number",
                "issuing_authority",
                "issue_date",
                "expiry_date",
                "dtc_type",
            ],
            "optional_fields": [
                "personal_details",
                "data_groups",
                "access_control",
                "access_key",
            ],
            "doctype": "org.icao.dtc.1",
        },
        "display_config": {
            "display_name": "Demo DTC Credential",
            "is_published": True,
            "is_system_template": False,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "2-3 business days",
        },
    },
    {
        "id": "demo-open-badge-credential-type",
        "name": "open_badge",
        "description": "Demo Open Badge Credential",
        "format": "jwt_vc_json",
        "schema_definition": {
            "required_fields": [
                "version",
                "payload_json",
            ],
            "optional_fields": [
                "document_store_json",
                "recipient_identity",
                "signing_json",
            ],
            "doctype": "openbadges",
        },
        "display_config": {
            "display_name": "Demo Open Badge Credential",
            "is_published": True,
            "is_system_template": False,
            "is_active": True,
            "visibility": "public",
            "estimated_processing_time": "1-2 business days",
        },
    },
)

DEFAULT_TEMPLATE_DISPLAY_STYLE: Final[dict[str, str]] = {
    "background_color": "#1a1a2e",
    "text_color": "#ffffff",
}

DEFAULT_TEMPLATE_VALIDITY_RULES: Final[dict[str, Any]] = {
    "default_validity_days": 365,
    "max_validity_days": 1095,
    "renewable": True,
    "renewal_window_days": 30,
    "require_revalidation": False,
}

DEFAULT_TEMPLATE_ISSUER_REQUIREMENTS: Final[dict[str, list[str]]] = {
    "allowed_issuer_dids": [],
}

DEFAULT_TEMPLATE_SUPPORTED_FORMATS: Final[list[str]] = ["sd_jwt_vc", "jwt_vc"]


def _template_row(
    *,
    template_id: str,
    credential_type: str,
    name: str,
    description: str,
    doctype: str,
    claims: list[dict[str, Any]],
    vct: str | None = None,
    display_style: dict[str, Any] | None = None,
    validity_rules: dict[str, Any] | None = None,
    issuer_requirements: dict[str, Any] | None = None,
    supported_formats: list[str] | None = None,
    wallet_configs: list[dict[str, Any]] | None = None,
    credential_payload_format: str | None = None,
) -> dict[str, Any]:
    selective_disclosure_fields = [claim["name"] for claim in claims if claim["selectively_disclosable"]]
    return {
        "id": template_id,
        "organization_id": DEMO_VENDOR_ORG_ID,
        "name": name,
        "description": description,
        "status": "active",
        "credential_type": credential_type,
        "vct": vct or f"https://marty.example/credentials/{credential_type}",
        "doctype": doctype,
        "claims": claims,
        "privacy_posture": "selective_disclosure",
        "selective_disclosure_fields": selective_disclosure_fields,
        "derived_attributes": [],
        "display_style": dict(display_style or DEFAULT_TEMPLATE_DISPLAY_STYLE),
        "validity_rules": dict(validity_rules or DEFAULT_TEMPLATE_VALIDITY_RULES),
        "issuer_requirements": dict(issuer_requirements or DEFAULT_TEMPLATE_ISSUER_REQUIREMENTS),
        "supported_formats": list(supported_formats or DEFAULT_TEMPLATE_SUPPORTED_FORMATS),
        "credential_payload_format": credential_payload_format,
        "version": 1,
        "wallet_configs": [dict(entry) for entry in (wallet_configs or [DEMO_VENDOR_WALLET_CONFIG])],
    }


DEMO_VENDOR_CREDENTIAL_TEMPLATES: Final[tuple[dict[str, Any], ...]] = (
    _template_row(
        template_id="40000000-0000-0000-0000-000000000001",
        credential_type="passport",
        name="Passport",
        description="ICAO 9303 compliant digital travel credential with NFC capability",
        doctype="org.iso.18013.5.1.PASSPORT",
        claims=_common_template_claims("passport"),
    ),
    _template_row(
        template_id="40000000-0000-0000-0000-000000000002",
        credential_type="drivers_license",
        name="Driver's License",
        description="ISO/IEC 18013-5 compliant mobile driving license",
        doctype="org.iso.18013.5.1.mDL",
        claims=_common_template_claims("drivers_license"),
    ),
    _template_row(
        template_id="40000000-0000-0000-0000-000000000003",
        credential_type="national_id",
        name="National ID",
        description="National identity credential for verified applicants",
        doctype="org.iso.18013.5.1.NID",
        claims=_common_template_claims("national_id"),
    ),
    _template_row(
        template_id="40000000-0000-0000-0000-000000000004",
        credential_type="travel_visa",
        name="Travel Visa",
        description="Digitally issued travel visa credential for approved applicants",
        doctype="org.iso.18013.5.1.VISA",
        claims=_common_template_claims("travel_visa"),
    ),
    _template_row(
        template_id="40000000-0000-0000-0000-000000000005",
        credential_type="access_badge",
        name="Access Badge",
        description="Corporate access badge credential for authorized personnel",
        doctype="com.enterprise.access.badge",
        claims=_common_template_claims("access_badge"),
    ),
    _template_row(
        template_id="40000000-0000-0000-0000-000000000006",
        credential_type="dtc",
        name="Digital Travel Credential",
        description="Digital Travel Credential per ICAO DTC specification",
        doctype="org.icao.dtc",
        claims=_common_template_claims("dtc"),
    ),
    _template_row(
        template_id="40000000-0000-0000-0000-000000000007",
        credential_type="open_badge",
        name="Professional Development Certificate",
        description="Professional Development Certificate - Open Badge 3.0 credential for continuing education and professional development",
        doctype="org.openbadges.v3",
        claims=OPEN_BADGE_PROFESSIONAL_DEVELOPMENT_CLAIMS,
    ),
    _template_row(
        template_id="40000000-0000-0000-0000-000000000008",
        credential_type="org.iso.18013.5.1.mDL",
        name="ISO 18013-5 mDL",
        description="ISO/IEC 18013-5 Mobile Driving Licence — full doctype identifier for SpruceKit compatibility",
        doctype="org.iso.18013.5.1.mDL",
        claims=ISO_18013_MDL_SPRUCEKIT_CLAIMS,
        vct="https://marty.example/credentials/org.iso.18013.5.1.mDL",
        display_style={"background_color": "#0f4c81", "text_color": "#ffffff"},
        validity_rules={
            "default_validity_days": 1825,
            "max_validity_days": 3650,
            "renewable": True,
            "renewal_window_days": 90,
            "require_revalidation": True,
        },
        supported_formats=["mso_mdoc"],
        wallet_configs=[DEMO_VENDOR_SPRUCEKIT_MDL_WALLET_CONFIG],
        credential_payload_format="mso_mdoc",
    ),
)

DEMO_VENDOR_TEMPLATE_IDS: Final[tuple[str, ...]] = tuple(
    template["id"] for template in DEMO_VENDOR_CREDENTIAL_TEMPLATES
)


def get_demo_vendor_seed_bundle() -> dict[str, Any]:
    """Return a deep-copied demo vendor fixture bundle for explicit seeding."""
    return {
        "organization": deepcopy(DEMO_VENDOR_ORGANIZATION),
        "credential_types": deepcopy(list(DEMO_VENDOR_CREDENTIAL_TYPES)),
        "credential_templates": deepcopy(list(DEMO_VENDOR_CREDENTIAL_TEMPLATES)),
    }