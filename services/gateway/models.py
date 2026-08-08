"""
Pydantic models for the API Gateway.

All request/response schemas used by gateway route modules.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import (
    AliasChoices,
    AwareDatetime,
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)

# =============================================================================
# Base Classes
# =============================================================================


class BaseResourceCreate(BaseModel):
    """Base class for creating organization-scoped resources."""

    organization_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)


class BaseResourceResponse(BaseModel):
    """Base class for resource responses."""

    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    created_at: str
    updated_at: str


# =============================================================================
# Trust Profile
# =============================================================================


class RegistrySyncConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: Literal["MARTY_TRUST_REGISTRY_SYNC_V1"]
    refresh_interval_hours: int = Field(ge=1, le=720)


class TrustSourceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_type: Literal["TRUST_LIST", "PINNED_ISSUER", "ROOT_CA", "PKD_URL"]
    url: str | None = None
    certificate_pem: str | None = None
    issuer_did: str | None = None
    description: str | None = Field(default=None, max_length=256)
    registry_sync: RegistrySyncConfigModel | None = None

    @field_validator("source_type", mode="before")
    @classmethod
    def normalize_source_type(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_source(self) -> "TrustSourceModel":
        if (
            sum(
                value is not None
                for value in (self.url, self.certificate_pem, self.issuer_did)
            )
            != 1
        ):
            raise ValueError(
                "exactly one of url, certificate_pem, or issuer_did is required"
            )
        if self.url is not None:
            try:
                parsed = urlsplit(self.url)
                port = parsed.port
            except ValueError as exc:
                raise ValueError("registry URL is invalid") from exc
            if (
                parsed.scheme.lower() != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or port not in {None, 443}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(
                    "URL trust sources require a credential-free standard-port HTTPS URL without query or fragment"
                )
        if self.registry_sync is not None and (
            self.url is None or self.source_type not in {"TRUST_LIST", "PKD_URL"}
        ):
            raise ValueError("registry_sync requires a TRUST_LIST or PKD_URL URL")
        if (
            self.registry_sync is None
            and self.url is not None
            and self.source_type in {"TRUST_LIST", "PKD_URL"}
        ):
            raise ValueError(
                "URL trust registries require an explicit supported registry_sync protocol"
            )
        if self.certificate_pem is not None and not self.certificate_pem.startswith(
            "-----BEGIN CERTIFICATE-----"
        ):
            raise ValueError("certificate_pem must contain a PEM certificate")
        if self.issuer_did is not None and not self.issuer_did.startswith("did:"):
            raise ValueError("issuer_did must be a DID")
        return self


class ValidationRulesModel(BaseModel):
    allowed_algorithms: list[str] = Field(
        default_factory=lambda: ["ES256", "ES384", "EdDSA"]
    )
    min_key_size_rsa: int = 2048
    min_key_size_ec: int = 256
    require_key_usage: bool = True
    max_chain_depth: int = 5
    allow_self_signed: bool = False


class RevocationPolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_mode: Literal["HARD_FAIL", "SOFT_FAIL", "SKIP"] = "HARD_FAIL"


class TrustProfileCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    profile_type: str = Field(default="CUSTOM", max_length=50)
    compliance_status: str = Field(default="SETUP_REQUIRED", max_length=50)
    trust_sources: list[TrustSourceModel] = Field(default_factory=list)
    validation_rules: ValidationRulesModel | None = None
    allowed_algorithms: list[str] | None = None
    min_key_size_rsa: int | None = None
    min_key_size_ec: int | None = None
    require_key_usage: bool | None = None
    max_chain_depth: int | None = None
    allow_self_signed: bool | None = None
    revocation_policy: RevocationPolicyModel | None = None
    revocation_profile_id: str | None = None
    supported_formats: list[str] = Field(default_factory=lambda: ["SD_JWT_VC", "MDOC"])
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    system_issuer_overrides: dict[str, dict] = Field(default_factory=dict)
    compatible_compliance_codes: list[str] = Field(default_factory=list)
    verification_policy_set_id: str | None = None
    auto_generated: bool = False


class TrustProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    profile_type: str | None = Field(None, max_length=50)
    compliance_status: str | None = Field(None, max_length=50)
    trust_sources: list[TrustSourceModel] | None = None
    validation_rules: ValidationRulesModel | None = None
    allowed_algorithms: list[str] | None = None
    min_key_size_rsa: int | None = None
    min_key_size_ec: int | None = None
    require_key_usage: bool | None = None
    max_chain_depth: int | None = None
    allow_self_signed: bool | None = None
    revocation_policy: RevocationPolicyModel | None = None
    revocation_profile_id: str | None = None
    supported_formats: list[str] | None = None
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    system_issuer_overrides: dict[str, dict] | None = None
    compatible_compliance_codes: list[str] | None = None
    verification_policy_set_id: str | None = None
    auto_generated: bool | None = None


class TrustProfileResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    profile_type: str
    compliance_status: str
    trust_sources: list[dict]
    validation_rules: dict
    allowed_algorithms: list[str]
    min_key_size_rsa: int
    min_key_size_ec: int
    require_key_usage: bool
    max_chain_depth: int
    allow_self_signed: bool
    revocation_policy: dict
    revocation_profile_id: str | None = None
    supported_formats: list[str]
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    system_issuer_overrides: dict[str, dict] = Field(default_factory=dict)
    compatible_compliance_codes: list[str] = Field(default_factory=list)
    verification_policy_set_id: str | None = None
    auto_generated: bool = False
    created_at: str
    updated_at: str


class TrustProfileIssuerCreate(BaseModel):
    """Create a protocol-defined link to an existing IssuerEntity."""

    model_config = ConfigDict(extra="forbid")

    issuer_id: str = Field(
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    trust_level: int = Field(default=100, ge=0, le=100)
    relationship_status: Literal["TRUSTED", "DENIED", "UNDER_REVIEW"] = "TRUSTED"
    cascade_revocation_policy: Literal["AUTO_CASCADE", "MANUAL", "NOTIFY_ONLY"] = (
        "NOTIFY_ONLY"
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_private_custody_metadata(self) -> "TrustProfileIssuerCreate":
        _reject_private_custody_metadata(self.metadata)
        return self


class TrustProfileIssuerUpdate(BaseModel):
    """Update relationship policy without mutating the linked issuer entity."""

    model_config = ConfigDict(extra="forbid")

    trust_level: int | None = Field(default=None, ge=0, le=100)
    relationship_status: Literal["TRUSTED", "DENIED", "UNDER_REVIEW"] | None = None
    cascade_revocation_policy: (
        Literal["AUTO_CASCADE", "MANUAL", "NOTIFY_ONLY"] | None
    ) = None
    metadata: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_update(self) -> "TrustProfileIssuerUpdate":
        if not self.model_fields_set:
            raise ValueError("at least one trust relationship field is required")
        if "metadata" in self.model_fields_set and self.metadata is None:
            raise ValueError("metadata cannot be null")
        _reject_private_custody_metadata(self.metadata)
        return self


class TrustProfileIssuerResponse(BaseModel):
    """marty-protocol TrustProfileIssuer resource."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    trust_profile_id: str = Field(
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    issuer_id: str = Field(
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    trust_level: int = Field(ge=0, le=100)
    relationship_status: Literal["TRUSTED", "DENIED", "UNDER_REVIEW"]
    cascade_revocation_policy: Literal["AUTO_CASCADE", "MANUAL", "NOTIFY_ONLY"]
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str | None = None

    @model_validator(mode="after")
    def reject_private_custody_metadata(self) -> "TrustProfileIssuerResponse":
        _reject_private_custody_metadata(self.metadata)
        return self


_PRIVATE_CUSTODY_METADATA_FIELDS = {
    "issuer_algorithm",
    "issuer_profile_id",
    "issuer_key_id",
    "key_access_mode",
    "key_binding",
    "key_management",
    "key_name",
    "key_reference",
    "key_version",
    "kms_arn",
    "kms_provider",
    "kms_region",
    "managed_key_id",
    "provider",
    "service_id",
    "signing_agent_auth",
    "signing_agent_url",
    "signing_key_reference",
    "signing_service_id",
    "transit_mount",
    "verification_method_id",
}

_PRIVATE_JWK_PARAMETERS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}


def _find_private_custody_metadata(value: Any) -> str | None:
    if isinstance(value, dict):
        normalized_keys = {str(key).lower() for key in value}
        if "kty" in normalized_keys:
            private_parameters = normalized_keys & _PRIVATE_JWK_PARAMETERS
            if private_parameters:
                return f"private JWK parameter '{sorted(private_parameters)[0]}'"
        for key, nested_value in value.items():
            if str(key).lower() in _PRIVATE_CUSTODY_METADATA_FIELDS:
                return str(key)
            found = _find_private_custody_metadata(nested_value)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_private_custody_metadata(item)
            if found is not None:
                return found
    return None


def _reject_private_custody_metadata(metadata: dict[str, Any] | None) -> None:
    field = _find_private_custody_metadata(metadata)
    if field is not None:
        raise ValueError(
            f"Public metadata cannot contain private custody selector or private key material '{field}'; "
            "signing is resolved from the issuer DID through an issuer profile"
        )


def _normalize_accreditations(values: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("accreditation identifiers cannot be blank")
        if len(cleaned) > 128:
            raise ValueError("accreditation identifiers cannot exceed 128 characters")
        comparison_key = cleaned.casefold()
        if comparison_key in seen:
            raise ValueError(
                "accreditation identifiers must be unique case-insensitively"
            )
        seen.add(comparison_key)
        normalized.append(cleaned)
    return normalized


class IssuerEntityCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str
    issuer_id: str = Field(min_length=1, max_length=512)
    issuer_type: Literal["ORGANIZATION", "GOVERNMENT", "DEVICE"] = "ORGANIZATION"
    display_name: str = Field(min_length=1, max_length=256)
    description: str | None = Field(None, max_length=1024)
    compliance_status: Literal["ACCREDITED", "COMPLIANT", "SUSPENDED"] = "COMPLIANT"
    accreditation_body: str | None = Field(None, max_length=256)
    accreditations: list[str] = Field(default_factory=list, max_length=64)
    accreditation_date: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    trust_anchor_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("accreditations")
    @classmethod
    def validate_accreditations(cls, values: list[str]) -> list[str]:
        return _normalize_accreditations(values)

    @model_validator(mode="after")
    def reject_private_custody_metadata(self) -> "IssuerEntityCreate":
        _reject_private_custody_metadata(self.metadata)
        return self


class IssuerEntityUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str
    display_name: str | None = Field(None, min_length=1, max_length=256)
    description: str | None = Field(None, max_length=1024)
    issuer_type: Literal["ORGANIZATION", "GOVERNMENT", "DEVICE"] | None = None
    compliance_status: (
        Literal["ACCREDITED", "COMPLIANT", "SUSPENDED", "REVOKED"] | None
    ) = None
    accreditation_body: str | None = Field(None, max_length=256)
    accreditations: list[str] | None = Field(None, max_length=64)
    accreditation_date: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    trust_anchor_id: str | None = None
    metadata: dict[str, Any] | None = None
    revocation_reason: str | None = Field(None, max_length=512)

    @field_validator("accreditations")
    @classmethod
    def validate_accreditations(cls, values: list[str] | None) -> list[str] | None:
        return None if values is None else _normalize_accreditations(values)

    @model_validator(mode="after")
    def validate_update(self) -> "IssuerEntityUpdate":
        if not (self.model_fields_set - {"organization_id"}):
            raise ValueError("at least one issuer entity field is required")
        for field_name in (
            "display_name",
            "issuer_type",
            "compliance_status",
            "accreditations",
            "valid_from",
            "metadata",
        ):
            if (
                field_name in self.model_fields_set
                and getattr(self, field_name) is None
            ):
                raise ValueError(f"{field_name} cannot be null")
        if self.compliance_status == "REVOKED" and not self.revocation_reason:
            raise ValueError("revocation_reason is required when revoking an issuer")
        if self.revocation_reason is not None and self.compliance_status != "REVOKED":
            raise ValueError("revocation_reason is valid only for a revocation")
        _reject_private_custody_metadata(self.metadata)
        return self


class IssuerEntityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    organization_id: str | None = None
    issuer_id: str
    issuer_type: str
    display_name: str
    description: str | None = None
    is_system_issuer: bool
    compliance_status: str
    accreditation_body: str | None = None
    accreditations: list[str] = Field(max_length=64)
    accreditation_date: str | None = None
    valid_from: str
    valid_until: str | None = None
    trust_anchor_id: str | None = None
    revoked_at: str | None = None
    revocation_reason: str | None = None
    revoked_by: str | None = None
    metadata: dict[str, Any]
    created_at: str
    updated_at: str

    @model_validator(mode="after")
    def reject_private_custody_metadata(self) -> "IssuerEntityResponse":
        _reject_private_custody_metadata(self.metadata)
        return self

    @field_validator("accreditations")
    @classmethod
    def validate_accreditations(cls, values: list[str]) -> list[str]:
        return _normalize_accreditations(values)


class IssuerIdentityResponse(BaseModel):
    """DID-only projection of an active organization issuer profile."""

    model_config = ConfigDict(extra="forbid")

    issuer_did: str = Field(pattern=r"^did:", max_length=2048)
    key_purpose: Literal[
        "vc_jwt_issuer",
        "mdoc_dsc",
        "x509_doc_signer",
        "holder_binding",
        "presentation_signing",
        "oid4vp_request_signing",
        "vdsnc_signing",
        "csca",
        "jwks_signing",
        "lti_tool_signing",
    ]
    algorithm: Literal["ES256", "ES384", "RS256", "EdDSA"]
    credential_format: Literal[
        "MDOC", "SD_JWT_VC", "VC_JWT", "JSON_LD", "ZK_MDOC", "ICAO_EMRTD"
    ]
    status: Literal["active"]


class IssuerIdentityOperationRequest(BaseModel):
    """Complete public selector for exactly one managed issuer identity."""

    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1, max_length=255)
    issuer_did: str = Field(pattern=r"^did:", max_length=2048)
    key_purpose: Literal[
        "vc_jwt_issuer",
        "mdoc_dsc",
        "x509_doc_signer",
        "holder_binding",
        "presentation_signing",
        "oid4vp_request_signing",
        "vdsnc_signing",
        "csca",
        "jwks_signing",
        "lti_tool_signing",
    ]
    credential_format: Literal[
        "MDOC", "SD_JWT_VC", "VC_JWT", "JSON_LD", "ZK_MDOC", "ICAO_EMRTD"
    ]
    algorithm: Literal["ES256", "ES384", "RS256", "EdDSA"]


class KeyAttestationPolicy(BaseModel):
    """Public holder-key trust policy; never an issuer custody selector."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["disabled", "optional", "required"]
    trusted_root_certificates_pem: list[str] = Field(
        default_factory=list, max_length=64
    )
    allowed_algorithms: list[Literal["ES256", "ES384", "RS256", "EdDSA"]] = Field(
        default_factory=list
    )
    required_key_storage: list[str] = Field(default_factory=list)
    required_user_authentication: list[str] = Field(default_factory=list)
    max_age_seconds: int = Field(default=300, ge=1, le=86_400)
    require_nonce: bool = True
    status_validation: Literal["disabled", "if_present", "required"] = "required"
    status_list_allowed_origins: list[str] = Field(default_factory=list)
    status_list_trusted_root_certificates_pem: list[str] = Field(
        default_factory=list, max_length=64
    )
    status_list_allowed_algorithms: list[
        Literal["ES256", "ES384", "RS256", "EdDSA"]
    ] = Field(default_factory=list)
    status_list_max_age_seconds: int = Field(default=86_400, ge=1, le=604_800)
    status_list_allow_private_hosts: bool = False
    status_list_tls_ca_certificates_pem: list[str] = Field(
        default_factory=list, max_length=64
    )


class IssuerIdentityCreateRequest(IssuerIdentityOperationRequest):
    """Provider-neutral request to ensure a managed issuer identity."""

    key_attestation_policy: KeyAttestationPolicy | None = None


class IssuerIdentityCertificateRequest(IssuerIdentityOperationRequest):
    """Attach a public certificate chain to a DID-selected managed identity."""

    cert_pem: str = Field(min_length=1, max_length=1_048_576)
    cert_chain_pem: str | None = Field(default=None, max_length=1_048_576)


class IssuerIdentityCreateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity: IssuerIdentityResponse
    created: bool


class IssuerIdentityResolutionResponse(BaseModel):
    """Provider-neutral public key resolved from the complete identity tuple."""

    model_config = ConfigDict(extra="forbid")

    identity: IssuerIdentityResponse
    public_jwk: dict[str, Any]

    @model_validator(mode="after")
    def reject_private_key_material(self) -> "IssuerIdentityResolutionResponse":
        _reject_private_custody_metadata(self.public_jwk)
        return self


class IssuerIdentityDeleteResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deleted: IssuerIdentityResponse


class IssuerIdentityListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identities: list[IssuerIdentityResponse]


class TrustFrameworkResponse(BaseModel):
    id: str
    code: str
    display_name: str
    description: str | None = None
    pkd_endpoints: list[str] = Field(default_factory=list)
    default_algorithms: list[str] = Field(default_factory=list)
    default_formats: list[str] = Field(default_factory=list)
    validation_ruleset: dict = Field(default_factory=dict)
    sync_config: dict = Field(default_factory=dict)
    is_system: bool = True
    created_at: str
    updated_at: str


class OrganizationTrustProfileCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework_id: str
    name: str
    display_name: str | None = None
    description: str | None = None
    enabled: bool = True
    use_case_tags: list[str] = Field(default_factory=list)
    compliance_status: str = "SETUP_REQUIRED"
    auto_generated: bool = False
    revocation_policy: dict | None = None
    time_policy: dict | None = None
    allowed_algorithms: list[str] | None = None
    allowed_formats: list[str] | None = None
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    jurisdiction_filter: list[str] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_private_custody_metadata(self) -> OrganizationTrustProfileCreate:
        _reject_private_custody_metadata(self.metadata)
        return self


class OrganizationTrustProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    display_name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    use_case_tags: list[str] | None = None
    compliance_status: str | None = None
    auto_generated: bool | None = None
    revocation_policy: dict | None = None
    time_policy: dict | None = None
    allowed_algorithms: list[str] | None = None
    allowed_formats: list[str] | None = None
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    jurisdiction_filter: list[str] | None = None
    metadata: dict[str, Any] | None = None

    @model_validator(mode="after")
    def reject_private_custody_metadata(self) -> OrganizationTrustProfileUpdate:
        _reject_private_custody_metadata(self.metadata)
        return self


class OrganizationTrustProfileResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    organization_id: str
    framework_id: str
    name: str
    display_name: str | None = None
    description: str | None = None
    enabled: bool = True
    use_case_tags: list[str] = Field(default_factory=list)
    compliance_status: str
    auto_generated: bool = False
    revocation_policy: dict | None = None
    time_policy: dict | None = None
    allowed_algorithms: list[str] | None = None
    allowed_formats: list[str] | None = None
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    jurisdiction_filter: list[str] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str | None = None

    @model_validator(mode="after")
    def reject_private_custody_metadata(self) -> OrganizationTrustProfileResponse:
        _reject_private_custody_metadata(self.metadata)
        return self


class CreateApiKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    scopes: list[str] | None = None
    is_test: bool = False


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    description: str | None = None
    key_prefix: str
    scopes: list[str]
    status: str
    last_used_at: str | None = None
    expires_at: str | None = None
    created_at: str


class ApiKeyCreatedResponse(ApiKeyResponse):
    key: str


class IssuedCredentialRecordResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    organization_id: str
    credential_id: str
    credential_type: str
    credential_format: Literal["MDOC", "SD_JWT_VC", "VC_JWT", "JSON_LD"]
    flow_execution_id: str
    credential_template_id: str
    application_id: str | None = None
    revocation_profile_id: str | None = None
    renewed_from_credential_id: str | None = None
    renewed_to_credential_id: str | None = None
    renewable: bool = False
    renewal_eligible_at: str | None = None
    can_renew: bool = False
    subject_id: str
    subject_claims_hash: str | None = None
    issued_at: str
    valid_from: str | None = None
    valid_until: str | None = None
    status: Literal["ACTIVE", "SUSPENDED", "REVOKED", "EXPIRED"]
    status_list_entries: list[dict]
    credential_hash: str | None = None
    revoked_at: str | None = None
    revocation_reason: str | None = None
    issuer_did: str | None = None
    revoked_by: str | None = None
    created_at: str
    updated_at: str | None = None


class TrustRegistryEntryResponse(BaseModel):
    entry_id: str
    anchor_type: str
    operation: str
    country_code: str
    certificate_pem: str | None = None
    subject_key_id: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    source: str


class TrustRegistrySyncResponse(BaseModel):
    sync_token: str
    sequence: int
    entries: list[TrustRegistryEntryResponse] = Field(default_factory=list)
    has_more: bool = False
    generated_at: str


class TrustRegistryStatusResponse(BaseModel):
    status: str
    current_sequence: int
    total_entries: int
    current_entries: int
    csca_entries: int
    dsc_entries: int
    generated_at: str


class TrustProfileRegistrySourceSyncResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(pattern=r"^https://")
    protocol: Literal["MARTY_TRUST_REGISTRY_SYNC_V1"]
    sequence: int = Field(ge=0)
    csca_entries: int = Field(ge=0)
    dsc_entries: int = Field(ge=0)
    synchronized_at: AwareDatetime

    @field_validator("url")
    @classmethod
    def validate_result_url(cls, value: str) -> str:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("registry URL is invalid") from exc
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or port not in {None, 443}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("registry result URL is unsafe")
        return value


class TrustProfileRegistrySyncResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trust_profile_id: UUID
    sources: list[TrustProfileRegistrySourceSyncResponse] = Field(min_length=1)
    synchronized_at: AwareDatetime


# =============================================================================
# Credential Template
# =============================================================================


class ClaimDisplayModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str | None = Field(None, min_length=1, max_length=255)
    icon: str | None = Field(None, min_length=1, max_length=2048)


class ClaimDefinitionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str | None = None
    derived_from: str | None = Field(None, min_length=1, max_length=255)
    display: ClaimDisplayModel | None = None
    display_name: str | None = None
    claim_type: str = "string"
    type: str | None = Field(None, exclude=True)
    required: bool = True
    selectively_disclosable: bool = True
    namespace: str | None = Field(None, min_length=1, max_length=255)
    # Backward-compatible input names used before marty-protocol defined the
    # canonical mdoc claim fields. They are never emitted publicly.
    mdoc_namespace: str | None = Field(
        None,
        min_length=1,
        max_length=255,
        exclude=True,
    )
    mdoc_element_identifier: str | None = Field(
        None,
        min_length=1,
        max_length=255,
        exclude=True,
    )
    # Older internal clients used a capability flag rather than identifying
    # the source claim. Retain it as input compatibility, but never expose it
    # as part of the public marty-protocol representation.
    derivable: bool | None = Field(None, exclude=True)
    pattern: str | None = Field(None, exclude=True)
    enum_values: list[str] | None = Field(None, exclude=True)
    min_value: float | None = Field(None, exclude=True)
    max_value: float | None = Field(None, exclude=True)

    @model_validator(mode="after")
    def normalize_claim(self) -> "ClaimDefinitionModel":
        if (
            self.display
            and self.display.label
            and self.display_name
            and self.display.label != self.display_name
        ):
            raise ValueError(
                "display.label and legacy display_name must identify the same label"
            )
        if self.display and self.display.label:
            self.display_name = self.display.label
        if not self.display_name:
            self.display_name = (
                " ".join(
                    part.capitalize()
                    for part in self.name.replace("-", "_").split("_")
                    if part
                )
                or self.name
            )
        if self.type:
            normalized_type = self.type.lower()
            self.claim_type = (
                "integer" if normalized_type == "number" else normalized_type
            )
        if (
            self.namespace
            and self.mdoc_namespace
            and self.namespace != self.mdoc_namespace
        ):
            raise ValueError(
                "namespace and legacy mdoc_namespace must identify the same namespace"
            )
        self.namespace = self.namespace or self.mdoc_namespace
        if self.mdoc_element_identifier and not self.namespace:
            raise ValueError(
                "namespace is required when mdoc_element_identifier is provided"
            )
        if self.derived_from == self.name:
            raise ValueError("derived_from must identify a different source claim")
        return self


def _validate_claim_set(claims: list[ClaimDefinitionModel]) -> None:
    names = [claim.name for claim in claims]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise ValueError(f"claim names must be unique: {', '.join(duplicates)}")
    known_names = set(names)
    for claim in claims:
        if claim.derived_from and claim.derived_from not in known_names:
            raise ValueError(
                f"claim {claim.name!r} derives from unknown claim "
                f"{claim.derived_from!r}"
            )


class TemplateValidityRules(BaseModel):
    ttl_days: int = 365
    expiration_mode: str = "hard"
    reissue_window_days: int = 30
    default_validity_days: int | None = None
    max_validity_days: int | None = None
    renewable: bool | None = None
    renewal_window_days: int | None = None
    ttl_seconds: int | None = None
    reissue_within_seconds: int | None = None
    not_before_offset_seconds: int | None = None
    not_before_offset: int | None = None
    max_validity_seconds: int | None = None
    require_revalidation: bool | None = None
    revalidation_interval_days: int | None = None


class CredentialTemplateCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    """Create a Credential Template (complete issuance definition).

    Credential Template is the master configuration combining:
    - Schema/claims definition
    - Compliance Profile (embedded - format, framework rules)
    - Application Template reference (optional - for application-based flows)
    - Public issuer DID; signing custody is resolved internally
    - Validity and revocation settings
    """
    organization_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)

    # Schema & Claims
    credential_type: str = Field(min_length=1, max_length=500)
    vct: str | None = Field(None, min_length=1, max_length=2048)
    doctype: str | None = Field(None, max_length=2048)
    claims: list[ClaimDefinitionModel] = []
    privacy_posture: str = Field(default="selective_disclosure", max_length=50)
    selective_disclosure_fields: list[str] = []
    supported_formats: list[str] = ["sd_jwt_vc"]

    # INVERTED RELATIONSHIP: Credential Template references Application Template
    application_template_id: str | None = Field(None, max_length=255)

    # Canonical profile references
    compliance_profile_id: str = Field(min_length=1, max_length=255)
    trust_profile_id: str | None = Field(None, max_length=255)
    revocation_profile_id: str | None = Field(None, max_length=255)

    # Validity configuration
    validity_rules: TemplateValidityRules | None = None

    # Public signing identity. Algorithm, profile, provider, key, and
    # certificate routing are resolved internally from this DID.
    issuer_did: str = Field(pattern=r"^did:[a-z0-9]+:.+", max_length=2048)

    derived_attributes: list[dict] = []
    display_style: dict | None = None
    # ZK-specific fields
    zk_predicate_claims: list[str] = []
    schema_uri: dict | None = None
    # Derived payload format. Wallet compatibility is not client-authored.
    credential_payload_format: str | None = Field(default=None, max_length=100)

    @model_validator(mode="after")
    def validate_format_identity(self) -> "CredentialTemplateCreate":
        _validate_claim_set(self.claims)
        candidates = [
            value
            for value in [self.credential_payload_format, *self.supported_formats]
            if isinstance(value, str) and value.strip()
        ]
        normalized = {value.strip().lower().replace("-", "_") for value in candidates}
        if normalized & {"mdoc", "mso_mdoc", "iso_mdoc", "zk_mdoc"}:
            if not (self.doctype and self.doctype.strip()):
                raise ValueError("doctype is required for an MDOC credential template")
        if normalized & {
            "sd_jwt_vc",
            "dc+sd_jwt",
            "vc+sd_jwt",
            "w3c_vcdm_v2_sd_jwt",
            "ietf_sd_jwt_vc",
        }:
            if not (self.vct and self.vct.strip()):
                raise ValueError("vct is required for an SD_JWT_VC credential template")
        return self


class CredentialTemplateUpdate(BaseModel):
    """Public draft-template update; custody routing remains service-internal."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    claims: list[ClaimDefinitionModel] | None = None
    privacy_posture: str | None = Field(None, max_length=50)
    selective_disclosure_fields: list[str] | None = None
    zk_predicate_claims: list[str] | None = None
    derived_attributes: list[dict] | None = None
    display_style: dict | None = None
    validity_rules: TemplateValidityRules | None = None
    supported_formats: list[str] | None = None
    application_template_id: str | None = Field(None, max_length=255)
    trust_profile_id: str | None = Field(None, max_length=255)
    revocation_profile_id: str | None = Field(None, max_length=255)
    issuer_did: str | None = Field(
        None,
        pattern=r"^did:[a-z0-9]+:.+",
        max_length=2048,
    )
    credential_payload_format: str | None = Field(None, max_length=100)

    @model_validator(mode="after")
    def validate_claim_references(self) -> "CredentialTemplateUpdate":
        if self.claims is not None:
            _validate_claim_set(self.claims)
        return self


class CredentialTemplateResponse(BaseModel):
    """Marty Protocol public Credential Template representation."""

    model_config = ConfigDict(extra="forbid")

    id: str
    organization_id: str
    name: str
    description: str | None = None
    status: str

    credential_type: str
    vct: str | None = None
    doctype: str | None = None
    claims: list[dict]
    privacy_posture: dict | None = None
    application_template_id: str | None = None
    compliance_profile_id: str
    trust_profile_id: str | None = None
    revocation_profile_id: str | None = None
    validity_rules: dict
    issuer_did: str = Field(pattern=r"^did:[a-z0-9]+:.+", max_length=2048)
    credential_payload_format: str | None = None
    created_at: str
    updated_at: str | None = None


# =============================================================================
# Compliance Profile
# =============================================================================


class DataRetentionModel(BaseModel):
    retention_period: str = "session"
    retain_metadata_only: bool = False


class IssuerArtifactRequirementsModel(BaseModel):
    requires_x509_cert: bool = False
    requires_did: bool = False
    requires_jwk: bool = False
    cert_key_usage: list[str] = Field(default_factory=list)
    recommended_algorithms: list[str] = Field(default_factory=list)


class TrustProfileConstraintsModel(BaseModel):
    compatible_profile_types: list[str] = Field(default_factory=list)
    required_source_types: list[str] = Field(default_factory=list)
    required_formats: list[str] = Field(default_factory=list)


class ApiSurfaceEndpointModel(BaseModel):
    rel: str
    path_template: str
    method: str = "GET"
    auth_required: bool = True
    org_scoped_path: str | None = None
    response_schema_ref: str | None = None
    standard_ref: str | None = None


class ComplianceProfileCreate(BaseModel):
    """Create a Compliance Profile for regulatory rules and format abstraction."""

    model_config = ConfigDict(extra="forbid")

    organization_id: str | None = Field(None, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    compliance_code: str | None = Field(None, max_length=100)
    credential_format: str = Field(default="SD_JWT_VC", max_length=50)
    issuance_protocol: str | None = Field(None, max_length=100)
    issuer_artifact_requirements: IssuerArtifactRequirementsModel | None = None
    verification_policy_set_id: str | None = Field(None, max_length=255)
    frameworks: list[str] = Field(default_factory=list)
    data_retention: DataRetentionModel | None = None
    trust_profile_constraints: TrustProfileConstraintsModel | None = None
    api_surface: list[ApiSurfaceEndpointModel] = Field(default_factory=list)
    discoverable: bool = True
    is_system: bool = False
    system_profile: bool | None = None


class ComplianceProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    description: str | None = None
    compliance_code: str | None = None
    credential_format: str | None = None
    issuance_protocol: str | None = None
    issuer_artifact_requirements: IssuerArtifactRequirementsModel | None = None
    verification_policy_set_id: str | None = None
    trust_profile_constraints: TrustProfileConstraintsModel | None = None
    api_surface: list[ApiSurfaceEndpointModel] | None = None
    discoverable: bool | None = None
    is_system: bool | None = None
    frameworks: list[str] | None = None
    data_retention: DataRetentionModel | None = None


class ComplianceProfileResponse(BaseModel):
    id: str
    organization_id: str | None
    name: str
    description: str | None
    status: str
    compliance_code: str | None
    credential_format: str
    issuance_protocol: str | None = None
    issuer_artifact_requirements: dict | None = None
    verification_policy_set_id: str | None = None
    trust_profile_constraints: dict = Field(default_factory=dict)
    api_surface: list[dict] = Field(default_factory=list)
    discoverable: bool = True
    is_system: bool = False
    system_profile: bool = False
    frameworks: list[str] = Field(default_factory=list)
    data_retention: dict = Field(default_factory=dict)
    consent_requirement: dict = Field(default_factory=dict)
    audit_configuration: dict = Field(default_factory=dict)
    created_at: str
    updated_at: str


# =============================================================================
# Device Registration
# =============================================================================


class DevicePreferencesModel(BaseModel):
    credential_notifications: bool = True
    verification_notifications: bool = True
    system_notifications: bool = True
    quiet_hours_start: str | None = None
    quiet_hours_end: str | None = None


class DeviceRegistrationCreate(BaseModel):
    user_id: str | None = Field(None, max_length=255)
    organization_id: str | None = Field(None, max_length=255)
    device_id: str = Field(min_length=1, max_length=500)
    platform: Literal["ios", "android", "web"]
    fcm_token: str = Field(min_length=1, max_length=4096)
    app_version: str | None = Field(None, max_length=50)
    os_version: str | None = Field(None, max_length=50)
    device_model: str | None = Field(None, max_length=255)
    preferences: DevicePreferencesModel = Field(default_factory=DevicePreferencesModel)
    public_key_der: str | None = Field(None, max_length=8192)
    public_key_kid: str | None = Field(None, max_length=255)
    key_valid_from: str | None = Field(None, max_length=50)
    key_valid_until: str | None = Field(None, max_length=50)
    is_active: bool = True


class DeviceRegistrationUpdate(BaseModel):
    fcm_token: str | None = Field(None, max_length=4096)
    app_version: str | None = Field(None, max_length=50)
    os_version: str | None = Field(None, max_length=50)
    device_model: str | None = Field(None, max_length=255)
    preferences: DevicePreferencesModel | None = None
    public_key_der: str | None = Field(None, max_length=8192)
    public_key_kid: str | None = Field(None, max_length=255)
    key_valid_from: str | None = Field(None, max_length=50)
    key_valid_until: str | None = Field(None, max_length=50)
    is_active: bool | None = None
    last_seen_at: str | None = Field(None, max_length=50)


class DeviceRegistrationResponse(BaseModel):
    id: str
    user_id: str
    organization_id: str | None = None
    device_id: str
    platform: str
    fcm_token: str
    app_version: str | None = None
    os_version: str | None = None
    device_model: str | None = None
    preferences: dict = Field(default_factory=dict)
    public_key_der: str | None = None
    public_key_kid: str | None = None
    key_valid_from: str | None = None
    key_valid_until: str | None = None
    is_active: bool
    created_at: str
    updated_at: str
    last_seen_at: str | None = None


# =============================================================================
# Presentation Policy
# =============================================================================


class ClaimConstraintModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_name: str = Field(min_length=1, max_length=255)
    constraint_type: Literal[
        "equals",
        "not_equals",
        "greater_than",
        "less_than",
        "greater_or_equal",
        "less_or_equal",
        "in_set",
        "not_in_set",
        "presence",
        "regex",
        "age_over",
    ] = "presence"
    value: Any | None = None
    description: str | None = Field(None, max_length=2000)


class PredicateSpecModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    predicate_type: Literal[
        "RANGE_PROOF",
        "MEMBERSHIP",
        "EQUALITY",
        "NON_MEMBERSHIP",
        "INEQUALITY",
    ]
    params: dict[str, Any]
    supported_circuits: list[str] = Field(default_factory=list)
    fallback_policy: Literal["REQUIRE_PREDICATE", "ACCEPT_RAW", "DENY"] | None = None


class RequestedClaimModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_name: str = Field(min_length=1, max_length=255)
    display_name: str = Field(default="", max_length=255)
    description: str | None = Field(None, max_length=2000)
    required: bool = True
    selective_disclosure: bool = True
    accept_derived: bool = True
    predicate_spec: PredicateSpecModel | None = None
    constraints: list[ClaimConstraintModel] = Field(default_factory=list)


class CredentialRequirementModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_template_id: str = Field(min_length=1, max_length=255)
    display_name: str = Field(default="", max_length=255)
    description: str | None = Field(None, max_length=2000)
    required: bool = True
    credential_payload_format: str = Field(
        default="w3c_vcdm_v2_sd_jwt",
        min_length=1,
        max_length=100,
    )
    requested_claims: list[RequestedClaimModel] = Field(min_length=1)
    trust_profile_id: str | None = Field(None, max_length=255)
    max_age_seconds: int | None = Field(None, gt=0)
    require_fresh_issuance: bool = False


class AlternativeRequirementModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    credential_requirements: list[CredentialRequirementModel] = Field(min_length=1)
    min_satisfied: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def validate_min_satisfied(self) -> "AlternativeRequirementModel":
        if self.min_satisfied > len(self.credential_requirements):
            raise ValueError(
                "min_satisfied cannot exceed the number of credential requirements"
            )
        return self


class PresentationDisplayMetadataModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(default="", max_length=255)
    description: str = Field(default="", max_length=2000)
    purpose: Literal[
        "identity_verification",
        "age_verification",
        "employment_verification",
        "address_verification",
        "qualification_verification",
        "authorization",
        "compliance",
        "other",
    ] = "identity_verification"
    purpose_description: str | None = Field(None, max_length=2000)
    verifier_name: str = Field(default="", max_length=255)
    verifier_logo_url: str | None = Field(None, max_length=2000)
    privacy_policy_url: str | None = Field(None, max_length=2000)
    terms_of_service_url: str | None = Field(None, max_length=2000)


class ProtocolRequiredClaimModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_name: str = Field(min_length=1, max_length=255)
    credential_type: str | None = None
    value_constraint: Any | None = None
    predicate_spec: PredicateSpecModel | None = None


class ProofFreshnessModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_required: bool = True
    audience_binding_required: bool = True
    replay_detection_required: bool = True
    max_proof_age_seconds: int | None = Field(None, gt=0)


class HolderBindingModel(BaseModel):
    """How to verify the presenter is the legitimate holder."""

    model_config = ConfigDict(extra="forbid")

    required: bool = False
    binding_methods: list[
        Literal["CREDENTIAL_KEY", "DEVICE_KEY", "SESSION_BINDING"]
    ] = Field(default_factory=list)
    proof_profiles: list[
        Literal[
            "OID4VP_VERIFIABLE_PRESENTATION",
            "SD_JWT_KEY_BINDING",
            "MDOC_DEVICE_AUTHENTICATION",
            "CUSTOM",
        ]
    ] = Field(default_factory=list)
    proof_freshness: ProofFreshnessModel | None = None

    @model_validator(mode="after")
    def validate_binding_configuration(self) -> "HolderBindingModel":
        if self.required:
            if not self.binding_methods or not self.proof_profiles:
                raise ValueError(
                    "required holder binding needs binding_methods and proof_profiles"
                )
            if self.proof_freshness is None:
                raise ValueError(
                    "required holder binding needs proof_freshness controls"
                )
        elif (
            self.binding_methods
            or self.proof_profiles
            or self.proof_freshness is not None
        ):
            raise ValueError(
                "disabled holder binding cannot configure proof requirements"
            )
        return self


class IssuerConstraintsModel(BaseModel):
    """Constraints on accepted issuers."""

    model_config = ConfigDict(extra="forbid")

    min_trust_level: int | None = Field(None, ge=0, le=100)
    required_compliance_statuses: list[Literal["ACCREDITED", "COMPLIANT"]] = Field(
        default_factory=list
    )
    required_accreditations: list[str] = Field(default_factory=list)


class FreshnessConstraintsModel(BaseModel):
    """How fresh credentials must be."""

    model_config = ConfigDict(extra="forbid")

    max_age_seconds: int | None = Field(None, gt=0)
    require_not_revoked: bool = False
    revocation_grace_seconds: int | None = Field(None, ge=0)


class PresentationPolicyCreate(BaseModel):
    """Create a Presentation Policy defining what credentials to request."""

    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    purpose: str | None = Field(None, max_length=2000)
    display_metadata: PresentationDisplayMetadataModel | None = None
    required_claims: list[ProtocolRequiredClaimModel] = Field(default_factory=list)
    accepted_credential_types: list[str] = Field(default_factory=list)
    trust_profile_id: str | None = Field(None, max_length=255)
    credential_requirements: list[CredentialRequirementModel] = Field(
        default_factory=list
    )
    alternative_requirements: list[AlternativeRequirementModel] = Field(
        default_factory=list
    )
    compliance_profile_id: str | None = Field(None, max_length=255)
    prefer_predicates: bool = False
    fallback_policy: Literal["REQUIRE_PREDICATE", "ACCEPT_RAW", "DENY"] | None = None
    supported_circuits: list[str] = Field(default_factory=list)
    credential_ranking_strategy: Literal[
        "FRESHEST_FIRST", "HIGHEST_TRUST_FIRST", "CUSTOM"
    ] = "FRESHEST_FIRST"
    credential_ranking_weights: dict[str, float] | None = None
    holder_binding: HolderBindingModel | None = None
    issuer_constraints: IssuerConstraintsModel | None = None
    freshness: FreshnessConstraintsModel | None = None

    @model_validator(mode="after")
    def validate_policy_requirements(self) -> "PresentationPolicyCreate":
        if not (
            self.required_claims
            or self.credential_requirements
            or self.alternative_requirements
        ):
            raise ValueError(
                "at least one required claim, credential requirement, or "
                "alternative requirement is required"
            )
        if (
            self.credential_ranking_strategy == "CUSTOM"
            and not self.credential_ranking_weights
        ):
            raise ValueError(
                "credential_ranking_weights are required for CUSTOM ranking"
            )
        return self


class PresentationPolicyUpdate(BaseModel):
    """Update a draft Presentation Policy through its public organization scope."""

    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1, max_length=255)
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    purpose: str | None = Field(None, max_length=2000)
    display_metadata: PresentationDisplayMetadataModel | None = None
    required_claims: list[ProtocolRequiredClaimModel] | None = None
    accepted_credential_types: list[str] | None = None
    trust_profile_id: str | None = Field(None, max_length=255)
    credential_requirements: list[CredentialRequirementModel] | None = None
    alternative_requirements: list[AlternativeRequirementModel] | None = None
    compliance_profile_id: str | None = Field(None, max_length=255)
    prefer_predicates: bool | None = None
    fallback_policy: Literal["REQUIRE_PREDICATE", "ACCEPT_RAW", "DENY"] | None = None
    supported_circuits: list[str] | None = None
    credential_ranking_strategy: (
        Literal["FRESHEST_FIRST", "HIGHEST_TRUST_FIRST", "CUSTOM"] | None
    ) = None
    credential_ranking_weights: dict[str, float] | None = None
    holder_binding: HolderBindingModel | None = None
    issuer_constraints: IssuerConstraintsModel | None = None
    freshness: FreshnessConstraintsModel | None = None

    @model_validator(mode="after")
    def validate_custom_ranking(self) -> "PresentationPolicyUpdate":
        if (
            self.credential_ranking_strategy == "CUSTOM"
            and not self.credential_ranking_weights
        ):
            raise ValueError(
                "credential_ranking_weights are required for CUSTOM ranking"
            )
        return self


class PresentationPolicyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    organization_id: str
    name: str
    status: Literal["draft", "active", "suspended", "archived"]
    description: str | None = None
    purpose: str | None = None
    required_claims: list[ProtocolRequiredClaimModel]
    accepted_credential_types: list[str]
    trust_profile_id: str | None = None
    display_metadata: PresentationDisplayMetadataModel | None = None
    credential_requirements: list[CredentialRequirementModel] | None = None
    alternative_requirements: list[AlternativeRequirementModel] | None = None
    compliance_profile_id: str | None = None
    holder_binding: HolderBindingModel
    issuer_constraints: IssuerConstraintsModel | None = None
    freshness: FreshnessConstraintsModel | None = None
    prefer_predicates: bool
    fallback_policy: Literal["REQUIRE_PREDICATE", "ACCEPT_RAW", "DENY"] | None = None
    supported_circuits: list[str]
    credential_ranking_strategy: Literal[
        "FRESHEST_FIRST", "HIGHEST_TRUST_FIRST", "CUSTOM"
    ]
    credential_ranking_weights: dict[str, float] | None = None
    version: int = Field(ge=1)
    created_at: str
    updated_at: str


# =============================================================================
# Deployment Profile
# =============================================================================


class CallbacksModel(BaseModel):
    issuance_complete_url: str | None = None
    verification_complete_url: str | None = None


class FeatureFlagsModel(BaseModel):
    enable_selective_disclosure: bool = True
    enable_derived_attributes: bool = True
    enable_batch_issuance: bool = False
    enable_deferred_issuance: bool = True
    enable_credential_refresh: bool = True
    enable_qr_code_generation: bool = True
    enable_push_notifications: bool = False
    enable_biometric_binding: bool = False
    enable_canvas_evidence: bool = False
    enable_canvas_lti: bool = False
    enable_canvas_mirror_publish: bool = False
    enable_canvas_mirror_ops: bool = False
    enable_canvas_deep_linking: bool = False
    enable_canvas_ags: bool = False
    enable_canvas_nrps: bool = False
    custom_flags: dict[str, bool] = Field(default_factory=dict)


class DeploymentProfileCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    status: str | None = Field(None, max_length=50)
    activate_immediately: bool | None = None
    environment: str = Field(default="development", max_length=50)
    callbacks: CallbacksModel | None = None
    feature_flags: FeatureFlagsModel | None = None
    trust_profile_id: str | None = Field(None, max_length=255)
    presentation_policy_ids: list[str] = Field(default_factory=list)
    credential_template_ids: list[str] = Field(default_factory=list)
    default_policy_id: str | None = Field(None, max_length=255)
    enabled_flow_ids: list[str] = Field(default_factory=list)
    network_mode: str = Field(default="ONLINE", max_length=50)
    environment_config: dict | None = None
    update_channel: str = Field(default="stable", max_length=50)


class DeploymentProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def reject_mixed_biometric_aliases(cls, data: Any) -> Any:
        if (
            isinstance(data, dict)
            and {
                "operator_biometric_authentication_required",
                "biometric_required",
            }
            <= data.keys()
        ):
            raise ValueError("use only operator_biometric_authentication_required")
        return data

    name: str | None = None
    description: str | None = None
    status: str | None = None
    trust_profile_id: str | None = None
    presentation_policy_ids: list[str] | None = None
    credential_template_ids: list[str] | None = None
    default_policy_id: str | None = None
    network_mode: str | None = None
    key_access_mode: str | None = None
    operator_biometric_authentication_required: bool | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "operator_biometric_authentication_required",
            "biometric_required",
        ),
    )
    environment_config: dict | None = None
    feature_flags: FeatureFlagsModel | None = None


class DeploymentProfileResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None = None
    status: str | None = None
    environment: str | None = None
    callbacks: dict | None = None
    feature_flags: dict | None = None
    trust_profile_id: str | None = None
    presentation_policy_ids: list[str] = Field(default_factory=list)
    credential_template_ids: list[str] = Field(default_factory=list)
    enabled_flow_ids: list[str] = Field(default_factory=list)
    default_policy_id: str | None
    network_mode: str | None = None
    key_access_mode: str | None = None
    environment_config: dict | None = None
    update_channel: str | None = None
    update_policy: dict | None = None
    offline_cache_ttl_hours: int | None = None
    operator_biometric_authentication_required: bool | None = None
    audit_all_events: bool | None = None
    canvas_feature_flags: dict[str, bool] = Field(default_factory=dict)
    lanes: list[dict] = Field(default_factory=list)
    api_key_prefix: str | None = None
    created_at: str
    updated_at: str


class LaneCreate(BaseModel):
    """Create a Lane (logical device grouping) within a Deployment Profile."""

    name: str
    description: str | None = None
    location: str | None = None
    device_type: str = "kiosk"


class LaneResponse(BaseModel):
    """Lane response."""

    id: str
    deployment_profile_id: str
    name: str
    description: str | None
    location: str | None
    device_type: str
    device_count: int
    status: str
    created_at: str
    updated_at: str


class DeviceAssignment(BaseModel):
    """Assign a device to a lane."""

    device_id: str
    device_name: str | None = None


# =============================================================================
# Flow
# =============================================================================


FlowTypeValue = Literal[
    "oid4vci_pre_authorized",
    "oid4vci_authorization_code",
    "mdl_issuance",
    "oid4vp_presentation",
    "mdl_presentation",
    "siopv2",
    "application_approval_issuance",
    "credential_renewal",
    "credential_revocation",
    "physical_document_issuance",
    "combined",
    "custom",
]
FlowDefinitionStatusValue = Literal["DRAFT", "ACTIVE", "PAUSED", "ARCHIVED"]
FlowInstanceStatusValue = Literal[
    "PENDING",
    "IN_PROGRESS",
    "AWAITING_APPROVAL",
    "AWAITING_WALLET",
    "AWAITING_EVIDENCE",
    "COMPLETED",
    "FAILED",
    "EXPIRED",
    "CANCELLED",
]


class FlowExtensionStepModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$", max_length=128)
    action: str = Field(pattern=r"^[a-z][a-z0-9_.:-]*$", max_length=160)
    description: str | None = Field(None, max_length=512)
    config: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int | None = Field(None, ge=1, le=86400)


class FlowExtensionTransitionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    from_step_id: str
    to_step_id: str
    outcome: Literal["SUCCESS", "FAILURE", "APPROVED", "REJECTED", "TIMEOUT", "CUSTOM"]
    condition: dict[str, Any] | None = None


class FlowExtensionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    extension_uri: str
    extension_version: str
    extends_flow_type: str
    entry_step_id: str
    steps: list[FlowExtensionStepModel] = Field(min_length=1)
    transitions: list[FlowExtensionTransitionModel] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)


class FlowHookModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hook_type: Literal["WEBHOOK", "EXTERNAL_API", "SCRIPT"]
    url: str | None = None
    config: dict[str, Any] = Field(default_factory=dict)


class FlowTriggerModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trigger_type: Literal["API_CALL", "WEBHOOK", "SCHEDULE", "APPLICATION_SUBMITTED"]
    config: dict[str, Any] = Field(default_factory=dict)


class FlowDefinitionCreate(BaseModel):
    """Create a Flow Definition for orchestrating credential operations."""

    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    flow_type: FlowTypeValue
    approval_strategy: Literal["AUTO", "MANUAL", "RULES_BASED", "EXTERNAL"] = "AUTO"
    hooks: dict[str, list[FlowHookModel]] = Field(default_factory=dict)
    trigger: FlowTriggerModel | None = None
    extension: FlowExtensionModel | None = None
    trust_profile_id: str | None = None
    credential_template_id: str | None = None
    application_template_id: str | None = None
    presentation_policy_id: str | None = None
    delivery_destination_profile_id: str | None = None
    deployment_profile_ids: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_custom_extension(self) -> "FlowDefinitionCreate":
        if self.flow_type == "custom" and self.extension is None:
            raise ValueError("extension is required for custom flow_type")
        if self.flow_type != "custom" and self.extension is not None:
            raise ValueError("extension is only permitted for custom flow_type")
        return self


class FlowDefinitionUpdate(BaseModel):
    """Partial public Flow patch bound to the owning organization."""

    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1, max_length=255)
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    flow_type: FlowTypeValue | None = None
    approval_strategy: Literal["AUTO", "MANUAL", "RULES_BASED", "EXTERNAL"] | None = (
        None
    )
    hooks: dict[str, list[FlowHookModel]] | None = None
    trigger: FlowTriggerModel | None = None
    extension: FlowExtensionModel | None = None
    trust_profile_id: str | None = None
    credential_template_id: str | None = None
    application_template_id: str | None = None
    presentation_policy_id: str | None = None
    delivery_destination_profile_id: str | None = None
    deployment_profile_ids: list[str] | None = None

    @model_validator(mode="after")
    def require_a_change(self) -> "FlowDefinitionUpdate":
        if self.model_fields_set <= {"organization_id"}:
            raise ValueError("at least one mutable Flow field is required")
        return self


class FlowDefinitionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    organization_id: str
    name: str
    description: str | None = None
    status: FlowDefinitionStatusValue
    flow_type: FlowTypeValue
    flow_category: Literal[
        "ISSUANCE", "VERIFICATION", "RENEWAL", "REVOCATION", "COMBINED"
    ]
    resolved_steps: list[str]
    extension: dict[str, Any] | None = None
    trust_profile_id: str | None = None
    credential_template_id: str | None = None
    application_template_id: str | None = None
    presentation_policy_id: str | None = None
    delivery_destination_profile_id: str | None = None
    approval_strategy: Literal["AUTO", "MANUAL", "RULES_BASED", "EXTERNAL"]
    hooks: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    trigger: dict[str, Any] | None = None
    deployment_profile_ids: list[str] = Field(default_factory=list)
    version: int
    created_at: str
    updated_at: str


_PRIVATE_FLOW_CONTEXT_KEYS = frozenset(
    {
        "issuer_profile_id",
        "issuer_key_id",
        "issuer_algorithm",
        "key_access_mode",
        "verification_method_id",
        "signing_service_id",
        "signing_key_reference",
        "key_reference",
        "kms_provider",
        "provider",
        "key_name",
        "key_version",
        "transit_mount",
        "pre_auth_code",
        "pre_authorized_code",
        "pre-authorized_code",
        "access_token",
        "refresh_token",
        "client_secret",
        "private_key",
        "private_key_jwk",
        "session_token",
        "api_key",
    }
)


def _private_flow_context_path(value: Any, prefix: str = "") -> str | None:
    if isinstance(value, dict):
        for key, entry in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}" if prefix else key_text
            if key_text.casefold() in _PRIVATE_FLOW_CONTEXT_KEYS:
                return path
            nested = _private_flow_context_path(entry, path)
            if nested:
                return nested
    elif isinstance(value, list):
        for index, entry in enumerate(value):
            path = f"{prefix}[{index}]" if prefix else f"[{index}]"
            nested = _private_flow_context_path(entry, path)
            if nested:
                return nested
    return None


class FlowInstanceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1, max_length=255)
    flow_definition_id: str = Field(min_length=1, max_length=255)
    subject_id: str | None = None
    subject_type: str = "applicant"
    external_reference: str | None = None
    initial_context: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_private_context(self) -> "FlowInstanceCreate":
        forbidden_path = _private_flow_context_path(self.initial_context)
        if forbidden_path:
            raise ValueError(
                f"initial_context.{forbidden_path} is private service state and cannot be supplied"
            )
        return self


class FlowInstanceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    flow_id: str | None
    flow_type: FlowTypeValue | None
    organization_id: str
    status: FlowInstanceStatusValue
    current_step: str | None = None
    current_step_index: int | None = None
    context_data: dict
    step_results: dict[str, dict[str, Any]]
    issued_credential_id: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    expires_at: str | None = None
    error_code: str | None = None
    metadata: dict[str, Any]
    state_history: list[dict[str, Any]]
    created_at: str
    updated_at: str

    @model_validator(mode="after")
    def reject_private_service_state(self) -> "FlowInstanceResponse":
        for field_name, value in (
            ("context_data", self.context_data),
            ("step_results", self.step_results),
            ("metadata", self.metadata),
            ("state_history", self.state_history),
        ):
            forbidden_path = _private_flow_context_path(value)
            if forbidden_path:
                raise ValueError(
                    f"{field_name}.{forbidden_path} contains private service state"
                )
        return self


# =============================================================================
# Policy Evaluation
# =============================================================================


class EvaluatePresentationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vp_token: str | dict[str, Any]
    trust_profile_id: str | None = None
    nonce: str | None = None
    audience: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class ClaimEvaluationResult(BaseModel):
    claim_name: str
    satisfied: bool
    presented_value: Any | None = None
    error: str | None = None


class CredentialEvaluationResult(BaseModel):
    credential_template_id: str
    satisfied: bool
    issuer_did: str | None = None
    claim_results: list[ClaimEvaluationResult] = []
    errors: list[str] = []


class PolicyEvaluationResponse(BaseModel):
    result: str
    policy_id: str
    policy_name: str
    credential_results: list[CredentialEvaluationResult]
    decision: str
    decision_reason: str
    verified_claims: dict
    evaluation_timestamp: str


class EvaluateInlineRequest(BaseModel):
    """Request to evaluate a VP with an inline (ad-hoc) policy."""

    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1, max_length=255)
    vp_token: str | dict[str, Any]
    credential_requirements: list[CredentialRequirementModel] = Field(
        min_length=1,
    )
    trust_profile_id: str | None = None
    compliance_profile_id: str | None = None
    nonce: str | None = None
    audience: str | None = None
    context: dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# Verification Flow (async wallet interaction)
# =============================================================================


class StartVerificationFlowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    presentation_policy_id: str | None = None
    organization_id: str = Field(min_length=1, max_length=255)
    issuer_did: str = Field(
        pattern=r"^did:",
        max_length=2048,
        description=(
            "Public verifier DID. Signed transports resolve it to the managed "
            "Request Object signing profile; URL-query uses it only for "
            "organization-scoped verifier authorization."
        ),
    )
    response_type: Literal["vp_token", "id_token"] = "vp_token"
    trust_profile_id: str | None = None
    deployment_profile_id: str | None = None
    external_reference: str | None = None
    callback_url: str | None = None
    expiry_minutes: int = Field(default=15, ge=1, le=1440)
    oid4vp_profile: Literal["standard", "haip"] = "standard"
    request_transport: Literal["request_uri", "request_object", "url_query"] = (
        "request_uri"
    )
    request_uri_method: Literal["get", "post"] = "get"

    @model_validator(mode="after")
    def validate_oid4vp_transport(self) -> "StartVerificationFlowRequest":
        if self.response_type == "vp_token" and not self.presentation_policy_id:
            raise ValueError(
                "presentation_policy_id is required for OID4VP vp_token flows"
            )
        if (
            self.request_transport in {"request_object", "url_query"}
            and self.request_uri_method != "get"
        ):
            raise ValueError(
                f"{self.request_transport} transport cannot use request_uri_method; "
                "use request_uri transport"
            )
        if self.request_transport == "url_query" and self.response_type == "id_token":
            raise ValueError(
                "url_query transport is supported only for OID4VP vp_token flows"
            )
        if self.request_transport == "url_query" and self.oid4vp_profile == "haip":
            raise ValueError(
                "url_query transport is unsigned and cannot be used for HAIP"
            )
        return self


class VerificationRequestResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instance_id: str
    request_uri: str
    qr_code_data: str
    presentation_policy_id: str
    nonce: str
    expires_at: str
    status: str


class SubmitVerificationRequest(BaseModel):
    vp_token: str
    presentation_submission: dict | None = None


class VerificationResultResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instance_id: str
    status: FlowInstanceStatusValue
    result: str | None = None
    decision: str | None = None
    decision_reason: str | None = None
    verified_claims: dict
    evaluation_timestamp: str | None = None


# =============================================================================
# Organization
# =============================================================================


class OrganizationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(
        min_length=2, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$"
    )
    display_name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(None, max_length=1024)
    org_type: Literal[
        "enterprise",
        "startup",
        "individual",
        "government",
        "education",
        "healthcare",
        "financial",
        "other",
    ] = "startup"
    contact_email: EmailStr | None = None
    visibility: Literal["PUBLIC", "PRIVATE"] = "PRIVATE"
    join_mechanism: Literal["open", "code", "invite", "domain"] = "invite"
    requires_approval: bool = False

    @model_validator(mode="after")
    def validate_admission(self) -> "OrganizationCreate":
        if self.join_mechanism == "open" and self.visibility != "PUBLIC":
            raise ValueError("open join requires PUBLIC visibility")
        return self


class OrganizationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str
    name: str | None = Field(
        None, min_length=2, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*[a-z0-9]$"
    )
    display_name: str | None = Field(None, min_length=1, max_length=128)
    description: str | None = Field(None, max_length=1024)
    org_type: (
        Literal[
            "enterprise",
            "startup",
            "individual",
            "government",
            "education",
            "healthcare",
            "financial",
            "other",
        ]
        | None
    ) = None
    contact_email: EmailStr | None = None
    contact_phone: str | None = Field(None, max_length=50)
    website: AnyHttpUrl | None = None
    visibility: Literal["PUBLIC", "PRIVATE"] | None = None
    join_mechanism: Literal["open", "code", "invite", "domain"] | None = None
    requires_approval: bool | None = None

    @model_validator(mode="after")
    def validate_update(self) -> "OrganizationUpdate":
        if not (self.model_fields_set - {"organization_id"}):
            raise ValueError("at least one organization field is required")
        if self.join_mechanism == "open" and self.visibility != "PUBLIC":
            raise ValueError("open join requires PUBLIC visibility")
        return self


class OrganizationRoleSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    display_name: str | None = None


class OrganizationMembershipSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    roles: list[OrganizationRoleSummary]
    status: Literal["active", "pending", "invited", "deactivated"]
    permissions: list[str]
    has_org_console_access: bool
    is_owner: bool
    joined_at: str | None


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    display_name: str
    description: str | None = None
    join_code: str | None = None
    visibility: Literal["PUBLIC", "PRIVATE"]
    owner_id: str
    status: Literal["active", "suspended", "pending"]
    org_type: Literal[
        "enterprise",
        "startup",
        "individual",
        "government",
        "education",
        "healthcare",
        "financial",
        "other",
    ]
    join_mechanism: Literal["open", "code", "invite", "domain"]
    requires_approval: bool
    is_discoverable: bool
    contact_email: str | None = None
    contact_phone: str | None = None
    website: str | None = None
    membership: OrganizationMembershipSummary | None = None
    created_at: str
    updated_at: str | None = None


class RetentionRecordCountsModel(BaseModel):
    issuance_transactions: int = 0
    applications: int = 0
    authorization_sessions: int = 0
    issuance_events: int = 0
    issued_credentials: int = 0
    total: int = 0


class PilotRetentionModel(BaseModel):
    enabled: bool = False
    window_days: int = 30
    scope_summary: str | None = None
    scope_items: list[str] = Field(default_factory=list)
    access_behavior: str | None = None
    last_purged_at: str | None = None
    cutoff_at: str | None = None
    next_expiry_at: str | None = None
    oldest_retained_record_at: str | None = None
    eligible_for_purge: RetentionRecordCountsModel = Field(
        default_factory=RetentionRecordCountsModel
    )
    tracked_scope: list[str] = Field(default_factory=list)


class OrganizationLifecycleResponse(BaseModel):
    created_at: str
    compliance_profiles: list[str] = Field(default_factory=list)
    data_retention_mode: str = "standard"
    audit_retention_days: int = 90
    pilot_retention: PilotRetentionModel | None = None


class HostedPilotPurgeResponse(BaseModel):
    organization_id: str
    retention_days: int
    cutoff_at: str
    purged_at: str
    purged_records: RetentionRecordCountsModel
    next_expiry_at: str | None = None
    oldest_retained_record_at: str | None = None
    tracked_scope: list[str] = Field(default_factory=list)


class JoinByCodeRequest(BaseModel):
    """Request to join an organization by code."""

    code: str = Field(description="8-character join code")


class JoinByCodeResponse(BaseModel):
    """Response after joining an organization."""

    organization: OrganizationResponse
    membership: dict = Field(description="Member information")


class ValidateJoinCodeResponse(BaseModel):
    """Response for join code validation."""

    valid: bool
    organization_id: str | None = None
    organization_name: str | None = None
    expired: bool = False
    message: str | None = None


class InvitationValidateResponse(BaseModel):
    """Response for invitation validation."""

    valid: bool
    organization_id: str | None = None
    organization_name: str | None = None
    role: str | None = None
    expired: bool = False
    message: str | None = None


class InvitationAcceptRequest(BaseModel):
    """Request to accept an invitation."""

    token: str


class InvitationAcceptResponse(BaseModel):
    """Response for invitation acceptance."""

    success: bool
    organization_id: str | None = None
    organization_name: str | None = None
    role: str | None = None
    message: str


# =============================================================================
# Issuance
# =============================================================================


class Oid4vciAuthorizedClientJwk(BaseModel):
    """Public ES256 key defined by the marty-protocol issuance contract."""

    model_config = ConfigDict(extra="forbid")

    kty: Literal["EC"]
    crv: Literal["P-256"]
    kid: str = Field(min_length=1, max_length=256)
    x: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    y: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    alg: Literal["ES256"] | None = None
    use: Literal["sig"] | None = None
    key_ops: list[Literal["verify"]] | None = Field(
        default=None,
        min_length=1,
        max_length=1,
    )

    @model_validator(mode="before")
    @classmethod
    def reject_private_parameters(cls, value: Any) -> Any:
        if isinstance(value, dict) and set(value) & {
            "d",
            "p",
            "q",
            "dp",
            "dq",
            "qi",
            "oth",
            "k",
        }:
            raise ValueError("authorized_client.jwks must contain public keys only")
        return value


class Oid4vciAuthorizedClientJwks(BaseModel):
    """JWKS wrapper with no fields outside the public protocol contract."""

    model_config = ConfigDict(extra="forbid")

    keys: list[Oid4vciAuthorizedClientJwk] = Field(min_length=1)


class Oid4vciAuthorizedClient(BaseModel):
    """Tenant-owned wallet client bound to a credential offer."""

    model_config = ConfigDict(extra="forbid")

    client_id: str = Field(min_length=1, max_length=512)
    jwks: Oid4vciAuthorizedClientJwks

    @model_validator(mode="after")
    def public_keys_only(self) -> "Oid4vciAuthorizedClient":
        key_ids = [key.kid for key in self.jwks.keys]
        if len(set(key_ids)) != len(key_ids):
            raise ValueError("authorized_client.jwks key ids must be unique")
        return self


PUBLIC_ISSUANCE_RESERVED_CLAIMS = frozenset(
    {
        "issuer_profile_id",
        "issuer_key_id",
        "issuer_algorithm",
        "key_access_mode",
        "verification_method_id",
        "signing_service_id",
        "signing_key_reference",
        "key_reference",
        "kms_provider",
        "provider",
        "key_name",
        "key_version",
        "transit_mount",
        "_application_id",
        "_credential_subject",
        "_credential_document",
    }
)


class IssuanceCreate(BaseModel):
    """Create an issuance request."""

    model_config = ConfigDict(extra="forbid")
    organization_id: str = Field(min_length=1, max_length=255)
    credential_template_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
    )
    issuer_did: str | None = Field(
        default=None,
        pattern=r"^did:[a-z0-9]+:.+",
        description=(
            "Public issuer identity. The organization-scoped issuer registry "
            "resolves this DID to the sole authorized active issuer profile."
        ),
    )
    subject_did: str | None = Field(default=None, pattern=r"^did:", max_length=2048)
    holder_did: str | None = Field(  # DIDComm v2: holder's DID for push delivery
        default=None,
        pattern=r"^did:",
        max_length=2048,
    )
    authorized_client: Oid4vciAuthorizedClient | None = None
    application_id: str | None = None
    claims: dict = Field(default_factory=dict)
    credential_subject: dict[str, Any] | list[dict[str, Any]] | None = None
    credential_document: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_credential_content(self) -> "IssuanceCreate":
        for reserved in PUBLIC_ISSUANCE_RESERVED_CLAIMS:
            if reserved in self.claims:
                raise ValueError(f"claims.{reserved} is not a public issuance input")

        if not self.credential_template_id and not self.issuer_did:
            raise ValueError(
                "credential_template_id or issuer_did is required to select "
                "the public signing identity"
            )

        if self.credential_document is not None:
            if "claims" in self.model_fields_set or self.credential_subject is not None:
                raise ValueError(
                    "credential_document cannot be combined with claims or credential_subject"
                )
            if not self.credential_document or "proof" in self.credential_document:
                raise ValueError(
                    "credential_document must be a non-empty unsigned object"
                )
            context = self.credential_document.get("@context")
            if (
                not isinstance(context, list)
                or not context
                or context[0] != "https://www.w3.org/ns/credentials/v2"
            ):
                raise ValueError(
                    "credential_document must use the W3C VC Data Model v2 base context first"
                )
            types = self.credential_document.get("type")
            types = types if isinstance(types, list) else [types]
            if "VerifiableCredential" not in types:
                raise ValueError(
                    "credential_document type must include VerifiableCredential"
                )
            subjects = self.credential_document.get("credentialSubject")
            subjects = subjects if isinstance(subjects, list) else [subjects]
            if not subjects or not all(
                isinstance(subject, dict) and subject for subject in subjects
            ):
                raise ValueError(
                    "credential_document must contain a non-empty credentialSubject"
                )
        elif self.credential_subject is not None:
            if "claims" in self.model_fields_set:
                raise ValueError("credential_subject cannot be combined with claims")
            subjects = (
                self.credential_subject
                if isinstance(self.credential_subject, list)
                else [self.credential_subject]
            )
            if not subjects or not all(
                isinstance(subject, dict) and subject for subject in subjects
            ):
                raise ValueError(
                    "credential_subject must be a non-empty object or list of objects"
                )
        return self


class DidcommDeliverRequest(BaseModel):
    """Deliver a credential via DIDComm v2 push."""

    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1)
    transaction_id: str = Field(min_length=1)
    holder_did: str = Field(min_length=1, pattern=r"^did:")


class DidcommDeliveryResponse(BaseModel):
    """DIDComm v2 delivery result."""

    transaction_id: str
    credential_id: str
    holder_did: str
    service_endpoint: str
    didcomm_message_id: str
    status: str
    error: str | None = None


class IssuanceResponse(BaseModel):
    """Public issuance initiation response; reusable authorization secrets are absent."""

    model_config = ConfigDict(extra="forbid")

    id: str
    organization_id: str
    credential_template_id: str
    status: Literal[
        "pending", "authorized", "signing", "issued", "failed", "expired", "revoked"
    ]
    credential_offer_uri: str
    credential_offer_uris: dict[str, str]
    credential_offer_labels: dict[str, str]
    expires_at: str


class IssuanceTransactionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    organization_id: str
    credential_template_id: str
    applicant_id: str | None = None
    application_id: str | None = None
    subject_did: str | None = None
    status: Literal[
        "pending", "authorized", "signing", "issued", "failed", "expired", "revoked"
    ]
    created_at: str
    expires_at: str | None = None
    issued_at: str | None = None
    revoked_at: str | None = None
    revocation_reason: str | None = None


class IssuedCredentialLifecycleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(None, max_length=2000)


class CredentialRenewalOfferResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_credential_id: str
    transaction_id: str
    credential_offer_uri: str
    credential_offer_uris: dict[str, str]
    credential_offer_labels: dict[str, str]
    expires_at: str


# =============================================================================
# Application Template
# =============================================================================


class EvidenceType(str, Enum):
    """Types of evidence applicants can provide."""

    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"
    ID_CARD = "id_card"
    SELFIE = "selfie"
    LIVENESS_CHECK = "liveness_check"
    PROOF_OF_ADDRESS = "proof_of_address"
    EMAIL_VERIFICATION = "email_verification"
    PHONE_VERIFICATION = "phone_verification"
    BIOMETRIC_SCAN = "biometric_scan"
    DOCUMENT_SCAN = "document_scan"


class ApprovalStrategy(str, Enum):
    """How applications are approved."""

    AUTO = "auto"
    MANUAL = "manual"
    RULES_BASED = "rules_based"


class FormFieldModel(BaseModel):
    """Form field definition."""

    field_id: str
    field_type: str
    label: str
    required: bool = True
    options: list[str] = []
    validation_pattern: str | None = None


class ClaimCollectionModel(BaseModel):
    """Canonical claim sourcing rule."""

    model_config = ConfigDict(extra="forbid")

    claim_name: str
    source: Literal["FORM_FIELD", "EVIDENCE_EXTRACTION", "EXTERNAL_API", "SYSTEM"]
    source_config: dict[str, Any] = Field(default_factory=dict)


class NotificationConfigModel(BaseModel):
    """Notification configuration."""

    send_confirmation: bool = True
    send_status_updates: bool = True
    email_template_id: str | None = None


class ApplicationUIConfigModel(BaseModel):
    """UI configuration for application."""

    theme: str = "default"
    logo_url: str | None = None
    instructions: str | None = None


class ApplicationFormFieldModel(BaseModel):
    """Canonical MIP 0.4 applicant form field."""

    model_config = ConfigDict(extra="forbid")

    field_id: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    label: str = Field(min_length=1, max_length=256)
    field_type: Literal[
        "TEXT",
        "DATE",
        "DATETIME",
        "SELECT",
        "FILE_UPLOAD",
        "INTEGER",
        "NUMBER",
        "BOOLEAN",
        "EMAIL",
        "URL",
    ]
    required: bool
    claim_mapping: str | None = None
    validation_pattern: str | None = None
    options: list[str] | None = None
    minimum: float | None = None
    maximum: float | None = None
    placeholder: str | None = None
    hint: str | None = None


class RequiredApplicationCheckModel(BaseModel):
    """Server-enforced check configured on an Application Template."""

    model_config = ConfigDict(extra="forbid")

    check_type: str = Field(min_length=1)
    is_required: bool = True
    order: int = Field(ge=1)
    config: dict[str, Any] = Field(default_factory=dict)
    external_provider: str | None = None


class ApplicationEvidenceRequirementModel(BaseModel):
    """Canonical evidence requirement on an Application Template."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1)
    evidence_type: Literal[
        "DOCUMENT_SCAN",
        "BIOMETRIC",
        "SELFIE",
        "THIRD_PARTY_VERIFICATION",
        "EXTERNAL_FACT",
        "EXTERNAL_API",
    ]
    description: str
    required: bool
    accepted_formats: list[str] | None = None
    max_file_size_bytes: int | None = Field(default=None, ge=1)
    provider: str | None = None
    fact_type: str | None = None
    scope: dict[str, Any] | None = None
    pass_rule: dict[str, Any] | None = None
    verification_method: str | None = None
    freshness: dict[str, Any] | None = None
    manual_fallback: bool | None = None
    api: dict[str, Any] | None = None
    expected_response: dict[str, Any] | None = None
    response_mapping: dict[str, Any] | None = None
    auto_issue_on_permit: bool | None = None


class ApplicationTemplateCreate(BaseModel):
    """Create an Application Template defining how users apply for credentials.

    Application Template defines what users fill out to apply for credentials.
    This is a PURE USER-FACING entity with NO cryptographic concerns.
    It defines the application workflow, not the credential structure.
    """

    model_config = ConfigDict(extra="forbid")

    organization_id: str
    name: str
    description: str | None = None
    credential_template_id: str | None = None

    # Evidence collection requirements
    evidence_requirements: list[ApplicationEvidenceRequirementModel] = Field(
        default_factory=list
    )

    # Form field definitions
    form_fields: list[ApplicationFormFieldModel] = Field(default_factory=list)

    # Review checks are authoritative template policy, never applicant input.
    required_checks: list[RequiredApplicationCheckModel] = Field(default_factory=list)

    # Claim collection
    claim_collection_rules: list[ClaimCollectionModel] = Field(default_factory=list)

    # Workflow configuration
    approval_strategy: Literal["AUTO", "MANUAL", "RULES_BASED", "EXTERNAL"] = "MANUAL"
    approval_policy_set_id: str | None = None
    application_validity_days: int = Field(default=30, ge=1, le=3650)

    # Notification settings
    notification_config: dict = Field(default_factory=dict)

    # UI/UX configuration
    ui_config: ApplicationUIConfigModel | dict | None = None


class ApplicationTemplatePatch(BaseModel):
    """Patch mutable fields on a draft MIP 0.4 Application Template."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    description: str | None = None
    credential_template_id: str | None = None
    evidence_requirements: list[ApplicationEvidenceRequirementModel] | None = None
    form_fields: list[ApplicationFormFieldModel] | None = None
    required_checks: list[RequiredApplicationCheckModel] | None = None
    claim_collection_rules: list[ClaimCollectionModel] | None = None
    approval_strategy: Literal["AUTO", "MANUAL", "RULES_BASED", "EXTERNAL"] | None = (
        None
    )
    approval_policy_set_id: str | None = None
    application_validity_days: int | None = Field(default=None, ge=1, le=3650)
    notification_config: dict | None = None
    ui_config: ApplicationUIConfigModel | dict | None = None


class ApplicationTemplateResponse(BaseModel):
    """Application Template response."""

    id: str
    organization_id: str
    name: str
    description: str | None
    credential_template_id: str | None
    status: str

    # Evidence collection
    evidence_requirements: list[Any]

    # Form configuration
    form_fields: list[ApplicationFormFieldModel]
    required_checks: list[RequiredApplicationCheckModel] = Field(default_factory=list)

    # Claim collection
    claim_collection_rules: list[dict]

    # Workflow
    approval_strategy: str
    approval_policy_set_id: str | None = None
    application_validity_days: int

    # Notifications
    notifications: dict | None = None
    notification_config: dict = Field(default_factory=dict)

    # UI configuration
    ui_config: dict | None

    # Metadata
    created_at: str
    updated_at: str
    version: int | None = None


# =============================================================================
# Application (Instances of Application Templates)
# =============================================================================


class ApplicationCreate(BaseModel):
    """Create an Application from an Application Template."""

    application_template_id: str
    applicant_data: dict = {}


class EvidenceSubmission(BaseModel):
    """Submit evidence for an application."""

    evidence_type: str
    evidence_data: dict = {}


class ApplicationResponse(BaseModel):
    """Application response."""

    id: str
    organization_id: str
    application_template_id: str
    applicant_identifier: str
    form_data: dict
    evidence_submissions: list[dict]
    status: str
    review_notes: str | None
    reviewer_id: str | None = None
    submitted_at: str
    reviewed_at: str | None = None
    expires_at: str
    issuance_transaction_id: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


# =============================================================================
# Audit Events
# =============================================================================


class AuditEventResponse(BaseModel):
    """Audit event response."""

    id: str
    organization_id: str
    timestamp: str
    actor_id: str | None
    actor_type: str
    action: str
    resource_type: str
    resource_id: str
    resource_name: str | None
    changes: dict | None
    metadata: dict


# =============================================================================
# Preferences
# =============================================================================


class PreferencesResponse(BaseModel):
    """Console context preferences response."""

    last_view_mode: str = Field(
        description="Last selected view mode: 'applicant' or 'org_admin'"
    )
    last_active_org_id: str | None = Field(
        description="Last active organization ID (null if none)"
    )


class UpdatePreferencesRequest(BaseModel):
    """Request to update console context preferences (partial update)."""

    last_view_mode: str | None = Field(
        None, description="View mode to set: 'applicant' or 'org_admin'"
    )
    last_active_org_id: str | None = Field(
        None, description="Organization ID to set as active (explicit null allowed)"
    )
