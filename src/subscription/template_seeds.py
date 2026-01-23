"""Standard template library seed data.

Pre-built credential templates for common standards:
- ISO 18013-5 mDL (all namespaces)
- ICAO 9303 eMRTD
- W3C Verifiable Credentials
- SD-JWT profiles

All templates are marked as system templates (read-only, clone-only).
"""

from typing import Any

from subscription.models import CredentialType

# ISO 18013-5 Mobile Driver's License
MDL_TEMPLATE = {
    "credential_type": CredentialType.DRIVERS_LICENSE,
    "display_name": "ISO 18013-5 Mobile Driver's License",
    "doctype": "org.iso.18013.5.1.mDL",
    "description": "ISO/IEC 18013-5 compliant mobile driver's license with all standard namespaces",
    "eligibility_criteria": "Valid driver's license from issuing authority",
    "submission_instructions": "Upload a clear photo of your current driver's license and provide all required information",
    "estimated_processing_time": "2-3 business days",
    "visibility": "public",
    "is_system_template": True,
    "is_published": True,
    "required_fields": [
        "family_name",
        "given_name",
        "birth_date",
        "issue_date",
        "expiry_date",
        "issuing_country",
        "issuing_authority",
        "document_number",
        "portrait",
        "driving_privileges",
    ],
    "optional_fields": [
        "un_distinguishing_sign",
        "administrative_number",
        "sex",
        "height",
        "weight",
        "eye_colour",
        "hair_colour",
        "birth_place",
        "resident_address",
        "portrait_capture_date",
        "age_in_years",
        "age_birth_year",
        "age_over_18",
        "age_over_21",
        "issuing_jurisdiction",
        "nationality",
        "resident_city",
        "resident_state",
        "resident_postal_code",
        "resident_country",
    ],
    "custom_fields": [
        {
            "name": "driving_privileges",
            "label": "Driving Privileges",
            "type": "json",
            "namespace": "org.iso.18013.5.1",
            "display_order": 100,
            "validation": {
                "required": True,
            }
        }
    ],
    "field_validation_rules": {
        "family_name": {
            "min_length": 1,
            "max_length": 150,
            "pattern": "^[a-zA-Z\\s'-]+$",
        },
        "given_name": {
            "min_length": 1,
            "max_length": 150,
            "pattern": "^[a-zA-Z\\s'-]+$",
        },
        "document_number": {
            "min_length": 5,
            "max_length": 20,
            "pattern": "^[A-Z0-9-]+$",
        },
        "height": {
            "min_value": 50,
            "max_value": 300,
        },
        "weight": {
            "min_value": 20,
            "max_value": 500,
        },
        "age_over_18": {
            "allowed_values": [True, False],
        },
        "age_over_21": {
            "allowed_values": [True, False],
        },
    },
    "vetting_config": {
        "auto_run_checks": ["identity_verification", "license_verification"],
        "manual_checks": ["photo_quality", "document_authenticity"],
    },
}

# ICAO 9303 eMRTD (Electronic Machine Readable Travel Document)
EMRTD_TEMPLATE = {
    "credential_type": CredentialType.PASSPORT,
    "display_name": "ICAO 9303 Electronic Passport",
    "doctype": "org.icao.mrtd.passport",
    "description": "ICAO 9303 compliant electronic machine-readable travel document (eMRTD)",
    "eligibility_criteria": "Valid passport from issuing country with citizenship documentation",
    "submission_instructions": "Provide passport information page scan, biometric photo, and citizenship proof",
    "estimated_processing_time": "5-10 business days",
    "visibility": "public",
    "is_system_template": True,
    "is_published": True,
    "required_fields": [
        "family_name",
        "given_name",
        "birth_date",
        "nationality",
        "document_number",
        "issue_date",
        "expiry_date",
        "issuing_country",
        "portrait",
    ],
    "optional_fields": [
        "sex",
        "birth_place",
        "issuing_authority",
        "personal_number",
        "height",
        "eye_colour",
    ],
    "field_validation_rules": {
        "family_name": {
            "min_length": 1,
            "max_length": 39,
            "pattern": "^[A-Z<]+$",  # ICAO MRZ format
        },
        "given_name": {
            "min_length": 1,
            "max_length": 39,
            "pattern": "^[A-Z<]+$",
        },
        "document_number": {
            "min_length": 9,
            "max_length": 9,
            "pattern": "^[A-Z0-9<]+$",
        },
        "nationality": {
            "min_length": 3,
            "max_length": 3,
            "pattern": "^[A-Z]{3}$",  # ISO 3166-1 alpha-3
        },
    },
    "vetting_config": {
        "auto_run_checks": ["identity_verification", "citizenship_verification"],
        "manual_checks": ["biometric_verification", "document_authenticity"],
    },
}

# W3C Verifiable Credentials - Permanent Resident Card
PRC_TEMPLATE = {
    "credential_type": CredentialType.PERMANENT_RESIDENT_CARD,
    "display_name": "W3C Permanent Resident Card",
    "doctype": "PermanentResidentCard",
    "description": "W3C Verifiable Credentials compliant permanent resident card",
    "eligibility_criteria": "Approved permanent resident status from immigration authority",
    "submission_instructions": "Provide immigration approval documents and supporting identification",
    "estimated_processing_time": "7-14 business days",
    "visibility": "public",
    "is_system_template": True,
    "is_published": True,
    "required_fields": [
        "family_name",
        "given_name",
        "birth_date",
        "resident_since",
        "legal_category",
    ],
    "optional_fields": [
        "image",
        "country_of_residence",
        "gender",
    ],
    "custom_fields": [
        {
            "name": "resident_since",
            "label": "Resident Since",
            "type": "date",
            "namespace": "w3c.vc",
            "display_order": 50,
            "validation": {
                "required": True,
            }
        },
        {
            "name": "legal_category",
            "label": "Legal Category",
            "type": "select",
            "namespace": "w3c.vc",
            "display_order": 51,
            "validation": {
                "required": True,
                "allowed_values": ["permanent_resident", "conditional_resident", "lawful_permanent_resident"],
            }
        },
    ],
    "field_validation_rules": {
        "family_name": {
            "min_length": 1,
            "max_length": 100,
        },
        "given_name": {
            "min_length": 1,
            "max_length": 100,
        },
    },
    "vetting_config": {
        "auto_run_checks": ["identity_verification", "immigration_status_check"],
        "manual_checks": ["document_review"],
    },
}

# W3C Verifiable Credentials - University Degree
DEGREE_TEMPLATE = {
    "credential_type": CredentialType.UNIVERSITY_DEGREE,
    "display_name": "W3C University Degree Credential",
    "doctype": "UniversityDegreeCredential",
    "description": "W3C Verifiable Credentials compliant university degree credential",
    "eligibility_criteria": "Completed degree program from accredited university",
    "submission_instructions": "Provide transcript, student ID, and degree certificate",
    "estimated_processing_time": "3-5 business days",
    "visibility": "public",
    "is_system_template": True,
    "is_published": True,
    "required_fields": [
        "family_name",
        "given_name",
    ],
    "optional_fields": [
        "email",
    ],
    "custom_fields": [
        {
            "name": "degree_type",
            "label": "Degree Type",
            "type": "select",
            "namespace": "university",
            "display_order": 10,
            "validation": {
                "required": True,
                "allowed_values": ["BachelorDegree", "MasterDegree", "DoctorateDegree", "AssociateDegree"],
            }
        },
        {
            "name": "degree_name",
            "label": "Degree Name",
            "type": "text",
            "namespace": "university",
            "display_order": 11,
            "validation": {
                "required": True,
                "min_length": 3,
                "max_length": 200,
            }
        },
        {
            "name": "graduation_date",
            "label": "Graduation Date",
            "type": "date",
            "namespace": "university",
            "display_order": 12,
            "validation": {
                "required": True,
            }
        },
        {
            "name": "gpa",
            "label": "GPA",
            "type": "number",
            "namespace": "university",
            "display_order": 13,
            "validation": {
                "required": False,
                "min_value": 0.0,
                "max_value": 4.0,
            }
        },
    ],
    "field_validation_rules": {
        "email": {
            "pattern": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
        },
    },
    "vetting_config": {
        "auto_run_checks": ["student_enrollment_verification"],
        "manual_checks": ["transcript_review", "degree_verification"],
    },
}

# W3C Verifiable Credentials - Employment Credential
EMPLOYMENT_TEMPLATE = {
    "credential_type": CredentialType.EMPLOYMENT_AUTHORIZATION,
    "display_name": "W3C Employment Authorization Document",
    "doctype": "EmploymentAuthorizationDocument",
    "description": "W3C Verifiable Credentials compliant employment authorization credential",
    "eligibility_criteria": "Work authorization from immigration or labor authority",
    "submission_instructions": "Provide work permit, visa documentation, and employer verification",
    "estimated_processing_time": "5-7 business days",
    "visibility": "public",
    "is_system_template": True,
    "is_published": True,
    "required_fields": [
        "family_name",
        "given_name",
        "birth_date",
        "nationality",
    ],
    "optional_fields": [
        "portrait",
    ],
    "custom_fields": [
        {
            "name": "authorization_type",
            "label": "Authorization Type",
            "type": "select",
            "namespace": "employment",
            "display_order": 20,
            "validation": {
                "required": True,
                "allowed_values": ["work_permit", "visa", "ead", "green_card"],
            }
        },
        {
            "name": "valid_from",
            "label": "Valid From",
            "type": "date",
            "namespace": "employment",
            "display_order": 21,
            "validation": {
                "required": True,
            }
        },
        {
            "name": "valid_until",
            "label": "Valid Until",
            "type": "date",
            "namespace": "employment",
            "display_order": 22,
            "validation": {
                "required": True,
            }
        },
        {
            "name": "employer_name",
            "label": "Employer Name",
            "type": "text",
            "namespace": "employment",
            "display_order": 23,
            "validation": {
                "required": False,
                "max_length": 200,
            }
        },
    ],
    "field_validation_rules": {
        "family_name": {
            "min_length": 1,
            "max_length": 100,
        },
        "given_name": {
            "min_length": 1,
            "max_length": 100,
        },
    },
    "vetting_config": {
        "auto_run_checks": ["work_authorization_check"],
        "manual_checks": ["employer_verification", "visa_verification"],
    },
}

# All system templates
SYSTEM_TEMPLATES = [
    MDL_TEMPLATE,
    EMRTD_TEMPLATE,
    PRC_TEMPLATE,
    DEGREE_TEMPLATE,
    EMPLOYMENT_TEMPLATE,
]


def get_system_templates() -> list[dict[str, Any]]:
    """Get all system templates for seeding.
    
    Returns:
        List of template configuration dictionaries
    """
    return SYSTEM_TEMPLATES
