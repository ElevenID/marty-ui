"""
Pydantic models for the API Gateway.

All request/response schemas used by gateway route modules.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator


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

class TrustSourceModel(BaseModel):
    name: str = ""
    source_type: str = "TRUST_LIST"
    url: str | None = None
    certificate_pem: str | None = None
    issuer_did: str | None = None
    description: str | None = None
    enabled: bool = True


class ValidationRulesModel(BaseModel):
    allowed_algorithms: list[str] = Field(default_factory=lambda: ["ES256", "ES384", "EdDSA"])
    min_key_size_rsa: int = 2048
    min_key_size_ec: int = 256
    require_key_usage: bool = True
    max_chain_depth: int = 5
    allow_self_signed: bool = False


class KeyManagementConfigModel(BaseModel):
    source: Literal["platform_managed", "kms", "signing_agent"]
    algorithm: str | None = "ES256"
    kms_arn: str | None = None
    kms_region: str | None = None
    signing_agent_url: str | None = None
    signing_agent_auth: str | None = None
    managed_key_id: str | None = None
    key_reference: str | None = None
    connection_status: str | None = None
    last_checked_at: str | None = None


class TrustProfileCreate(BaseModel):
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
    supported_formats: list[str] = Field(default_factory=lambda: ["SD_JWT_VC", "MDOC"])
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    system_issuer_overrides: dict[str, dict] = Field(default_factory=dict)
    compatible_compliance_codes: list[str] = Field(default_factory=list)
    verification_policy_set_id: str | None = None
    auto_generated: bool = False


class TrustProfileUpdate(BaseModel):
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
    supported_formats: list[str]
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    system_issuer_overrides: dict[str, dict] = Field(default_factory=dict)
    compatible_compliance_codes: list[str] = Field(default_factory=list)
    verification_policy_set_id: str | None = None
    auto_generated: bool = False
    created_at: str
    updated_at: str


class TrustedIssuerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    issuer_did: str = Field(min_length=1, max_length=2048)
    issuer_url: str | None = Field(None, max_length=2048)
    credential_template_ids: list[str] = Field(default_factory=list)


class TrustedIssuerUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    issuer_did: str | None = None
    issuer_url: str | None = None
    credential_template_ids: list[str] | None = None
    verification_keys: list[dict] | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    trust_level: int | None = None
    relationship_status: str | None = None
    cascade_revocation_policy: str | None = None


class TrustedIssuerResponse(BaseModel):
    id: str
    trust_profile_id: str
    issuer_id: str | None = None
    issuer_entity_id: str | None = None
    name: str
    description: str | None = None
    issuer_did: str
    issuer_type: str | None = None
    issuer_url: str | None = None
    status: str
    compliance_status: str | None = None
    trust_level: int = 100
    relationship_status: str = "TRUSTED"
    cascade_revocation_policy: str = "NOTIFY_ONLY"
    credential_template_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class IssuerEntityCreate(BaseModel):
    organization_id: str | None = None
    issuer_id: str
    issuer_type: str = "ORGANIZATION"
    display_name: str
    description: str | None = None
    is_system_issuer: bool = False
    compliance_status: str = "COMPLIANT"
    accreditation_body: str | None = None
    accreditation_date: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    trust_anchor_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class IssuerEntityUpdate(BaseModel):
    display_name: str | None = None
    description: str | None = None
    issuer_type: str | None = None
    is_system_issuer: bool | None = None
    compliance_status: str | None = None
    accreditation_body: str | None = None
    accreditation_date: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    trust_anchor_id: str | None = None
    metadata: dict[str, Any] | None = None
    revocation_reason: str | None = None
    revoked_by: str | None = None


class IssuerEntityResponse(BaseModel):
    id: str
    organization_id: str | None = None
    issuer_id: str
    issuer_type: str
    display_name: str
    description: str | None = None
    is_system_issuer: bool = False
    compliance_status: str
    accreditation_body: str | None = None
    accreditation_date: str | None = None
    valid_from: str
    valid_until: str | None = None
    trust_anchor_id: str | None = None
    revoked_at: str | None = None
    revocation_reason: str | None = None
    revoked_by: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


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
    key_management: KeyManagementConfigModel | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class OrganizationTrustProfileUpdate(BaseModel):
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
    key_management: KeyManagementConfigModel | None = None
    metadata: dict[str, Any] | None = None


class OrganizationTrustProfileResponse(BaseModel):
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
    key_management: KeyManagementConfigModel | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class KeyConnectionTestRequest(BaseModel):
    key_management: KeyManagementConfigModel


class KeyConnectionTestResponse(BaseModel):
    success: bool
    message: str
    source: str


class KeyCreateAssociateRequest(BaseModel):
    key_management: KeyManagementConfigModel | None = None
    algorithm: str = "ES256"
    key_reference: str | None = None


class KeyCreateAssociateResponse(BaseModel):
    success: bool
    action: str
    key_id: str
    source: str
    message: str
    key_management: KeyManagementConfigModel


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
    id: str
    organization_id: str
    credential_id: str
    credential_type: str
    credential_format: str
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
    status: str
    status_list_entries: list[dict] = Field(default_factory=list)
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


# =============================================================================
# Credential Template
# =============================================================================

class ClaimDefinitionModel(BaseModel):
    name: str
    display_name: str | None = None
    claim_type: str = "string"
    type: str | None = Field(None, exclude=True)
    required: bool = True
    selectively_disclosable: bool = True

    @model_validator(mode="after")
    def normalize_claim(self) -> "ClaimDefinitionModel":
        if not self.display_name:
            self.display_name = " ".join(
                part.capitalize()
                for part in self.name.replace("-", "_").split("_")
                if part
            ) or self.name
        if self.type:
            normalized_type = self.type.lower()
            self.claim_type = "integer" if normalized_type == "number" else normalized_type
        return self


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
    - Cryptographic configuration (keys, certs, DIDs)
    - Validity and revocation settings
    """
    organization_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)

    # Schema & Claims
    credential_type: str = Field(min_length=1, max_length=500)
    vct: str = Field(min_length=1, max_length=2048)
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

    # Cryptographic configuration
    issuer_key_id: str | None = Field(None, max_length=255)
    issuer_key_algorithm: str | None = Field(None, max_length=50)
    issuer_algorithm: str | None = Field(None, max_length=50)
    signing_algorithm: str | None = Field(None, max_length=50)
    key_access_mode: str = Field(default="key_vault", max_length=50)
    remote_signing_config: dict[str, Any] | None = None
    issuer_certificate_chain_pem: str | None = Field(None, max_length=65536)
    issuer_did: str | None = Field(None, max_length=2048)
    issuer_profile_id: str | None = Field(None, max_length=255)
    auto_generate_artifacts: bool = False

    derived_attributes: list[dict] = []
    display_style: dict | None = None
    # ZK-specific fields
    zk_predicate_claims: list[str] = []
    schema_uri: dict | None = None
    # Derived payload format. Wallet compatibility is not client-authored.
    credential_payload_format: str | None = Field(default=None, max_length=100)


class CredentialTemplateResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str

    # Schema & Claims
    credential_type: str
    vct: str
    claims: list[dict]
    privacy_posture: str
    supported_formats: list[str]

    # Profile references
    application_template_id: str | None
    compliance_profile: dict | None = None
    compliance_profile_id: str | None = None
    trust_profile_id: str | None
    revocation_profile_id: str | None

    # Validity
    validity_rules: dict | None

    # Cryptographic status
    issuer_key_id: str | None
    issuer_key_algorithm: str | None
    key_access_mode: str
    issuer_certificate_chain_configured: bool
    issuer_did: str | None
    artifacts_status: str

    # ZK-specific fields
    zk_predicate_claims: list[str] = []
    # Payload format and wallet deep-link configuration
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt"
    wallet_configs: list[dict] = []

    # Metadata
    version: int
    created_at: str
    updated_at: str


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

class RequestedClaimModel(BaseModel):
    claim_name: str
    display_name: str = ""
    required: bool = True
    selective_disclosure: bool = True
    predicate_spec: dict | None = None


class CredentialRequirementModel(BaseModel):
    credential_template_id: str
    display_name: str = ""
    required: bool = True
    requested_claims: list[RequestedClaimModel] = Field(default_factory=list)


class ProtocolRequiredClaimModel(BaseModel):
    claim_name: str
    credential_type: str | None = None
    value_constraint: Any | None = None
    predicate_spec: dict | None = None


class HolderBindingModel(BaseModel):
    """How to verify the presenter is the legitimate holder."""
    required: bool = False
    binding_methods: list[str] = Field(default_factory=list)
    proof_profiles: list[str] = Field(default_factory=list)
    proof_freshness: dict[str, Any] = Field(default_factory=dict)


class IssuerConstraintsModel(BaseModel):
    """Constraints on accepted issuers."""
    min_trust_level: int | None = None
    required_compliance_statuses: list[str] = Field(default_factory=list)
    required_accreditations: list[str] = Field(default_factory=list)


class FreshnessConstraintsModel(BaseModel):
    """How fresh credentials must be."""
    max_age_seconds: int | None = None
    require_not_revoked: bool = False
    revocation_grace_seconds: int | None = None


class PresentationPolicyCreate(BaseModel):
    """Create a Presentation Policy defining what credentials to request."""
    organization_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    purpose: str | None = Field(None, max_length=500)
    required_claims: list[ProtocolRequiredClaimModel] = Field(default_factory=list)
    accepted_credential_types: list[str] = Field(default_factory=list)
    trust_profile_id: str | None = Field(None, max_length=255)
    credential_requirements: list[CredentialRequirementModel] = Field(default_factory=list)
    compliance_profile_id: str | None = Field(None, max_length=255)
    prefer_predicates: bool = False
    fallback_policy: str | None = Field(None, max_length=100)
    supported_circuits: list[str] = Field(default_factory=list)
    credential_ranking_strategy: str = Field(default="FRESHEST_FIRST", max_length=50)
    credential_ranking_weights: dict[str, float] | None = None
    holder_binding: HolderBindingModel | None = None
    issuer_constraints: IssuerConstraintsModel | None = None
    freshness: FreshnessConstraintsModel | None = None


class PresentationPolicyResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    purpose: str | None = None
    required_claims: list[dict] = Field(default_factory=list)
    accepted_credential_types: list[str] = Field(default_factory=list)
    trust_profile_id: str | None = None
    credential_requirements: list[dict] = Field(default_factory=list)
    compliance_profile_id: str | None
    holder_binding: dict = Field(default_factory=dict)
    issuer_constraints: dict | None
    freshness: dict | None
    prefer_predicates: bool = False
    fallback_policy: str | None = None
    supported_circuits: list[str] = Field(default_factory=list)
    credential_ranking_strategy: str = "FRESHEST_FIRST"
    credential_ranking_weights: dict[str, float] | None = None
    version: int
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
        if isinstance(data, dict) and {
            "operator_biometric_authentication_required",
            "biometric_required",
        } <= data.keys():
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

    organization_id: str
    name: str
    description: str | None = None
    flow_type: Literal[
        "oid4vci_pre_authorized", "oid4vci_authorization_code", "mdl_issuance",
        "oid4vp_presentation", "mdl_presentation", "siopv2",
        "application_approval_issuance", "credential_renewal", "credential_revocation",
        "physical_document_issuance", "combined", "custom",
    ]
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


class FlowDefinitionResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    flow_type: str
    flow_category: str | None = None
    resolved_steps: list[str] = Field(default_factory=list)
    extension: dict[str, Any] | None = None
    trust_profile_id: str | None
    credential_template_id: str | None
    application_template_id: str | None
    presentation_policy_id: str | None
    delivery_destination_profile_id: str | None = None
    approval_strategy: str | None = None
    hooks: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    trigger: dict[str, Any] | None = None
    deployment_profile_ids: list[str]
    version: int
    created_at: str
    updated_at: str


class FlowInstanceCreate(BaseModel):
    flow_definition_id: str
    subject_id: str | None = None
    subject_type: str = "applicant"
    external_reference: str | None = None
    initial_context: dict = Field(default_factory=dict)


class FlowInstanceResponse(BaseModel):
    id: str
    flow_id: str | None = None
    flow_type: str | None = None
    organization_id: str
    status: str
    current_step: str | None = None
    current_step_index: int | None = None
    context_data: dict = Field(default_factory=dict)
    step_results: dict[str, dict[str, Any]] = Field(default_factory=dict)
    issued_credential_id: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    expires_at: str | None = None
    error_code: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    state_history: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str
    updated_at: str


# =============================================================================
# Policy Evaluation
# =============================================================================

class EvaluatePresentationRequest(BaseModel):
    vp_token: str
    trust_profile_id: str | None = None
    nonce: str | None = None
    audience: str | None = None
    context: dict = {}


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
    vp_token: str
    credential_requirements: list[CredentialRequirementModel] = []
    trust_profile_id: str | None = None
    compliance_profile_id: str | None = None
    nonce: str | None = None
    audience: str | None = None
    context: dict = {}


# =============================================================================
# Verification Flow (async wallet interaction)
# =============================================================================

class StartVerificationFlowRequest(BaseModel):
    presentation_policy_id: str | None = None
    organization_id: str | None = None
    response_type: str = "vp_token"
    trust_profile_id: str | None = None
    deployment_profile_id: str | None = None
    external_reference: str | None = None
    callback_url: str | None = None
    expiry_minutes: int = 15
    oid4vp_profile: Literal["standard", "haip"] = "standard"
    request_uri_method: Literal["get", "post"] = "get"


class VerificationRequestResponse(BaseModel):
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
    instance_id: str
    status: str
    result: str
    decision: str
    decision_reason: str
    verified_claims: dict
    evaluation_timestamp: str


# =============================================================================
# Organization
# =============================================================================

class OrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    display_name: str | None = Field(None, max_length=255)


class OrganizationResponse(BaseModel):
    id: str
    name: str
    display_name: str | None
    slug: str | None = None
    description: str | None = None
    org_type: str | None = None
    status: str | None = None
    contact_email: str | None = None
    contact_phone: str | None = None
    website: str | None = None
    join_mechanism: str | None = None
    requires_approval: bool | None = None
    is_discoverable: bool | None = None
    created_at: str
    updated_at: str


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
    eligible_for_purge: RetentionRecordCountsModel = Field(default_factory=RetentionRecordCountsModel)
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

class IssuanceCreate(BaseModel):
    """Create an issuance request."""
    organization_id: str
    credential_template_id: str | None = None
    issuer_profile_id: str | None = None
    subject_did: str | None = None
    holder_did: str | None = None  # DIDComm v2: holder's DID for push delivery
    application_id: str | None = None
    claims: dict = {}


class DidcommDeliverRequest(BaseModel):
    """Deliver a credential via DIDComm v2 push."""
    transaction_id: str
    holder_did: str
    universal_resolver_url: str | None = None


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
    """Issuance response."""
    id: str
    organization_id: str
    credential_template_id: str
    subject_did: str | None
    application_id: str | None
    status: str
    credential_offer_uri: str | None
    issued_credential: dict | None = None
    created_at: str


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
    """Canonical MIP 0.3 applicant form field."""

    model_config = ConfigDict(extra="forbid")

    field_id: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    label: str = Field(min_length=1, max_length=256)
    field_type: Literal[
        "TEXT", "DATE", "DATETIME", "SELECT", "FILE_UPLOAD",
        "INTEGER", "NUMBER", "BOOLEAN", "EMAIL", "URL",
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
        "DOCUMENT_SCAN", "BIOMETRIC", "SELFIE", "THIRD_PARTY_VERIFICATION",
        "EXTERNAL_FACT", "EXTERNAL_API",
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
    evidence_requirements: list[ApplicationEvidenceRequirementModel] = Field(default_factory=list)

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
    """Patch mutable fields on a draft MIP 0.3 Application Template."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    description: str | None = None
    credential_template_id: str | None = None
    evidence_requirements: list[ApplicationEvidenceRequirementModel] | None = None
    form_fields: list[ApplicationFormFieldModel] | None = None
    required_checks: list[RequiredApplicationCheckModel] | None = None
    claim_collection_rules: list[ClaimCollectionModel] | None = None
    approval_strategy: Literal["AUTO", "MANUAL", "RULES_BASED", "EXTERNAL"] | None = None
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
    last_view_mode: str = Field(description="Last selected view mode: 'applicant' or 'org_admin'")
    last_active_org_id: str | None = Field(description="Last active organization ID (null if none)")


class UpdatePreferencesRequest(BaseModel):
    """Request to update console context preferences (partial update)."""
    last_view_mode: str | None = Field(None, description="View mode to set: 'applicant' or 'org_admin'")
    last_active_org_id: str | None = Field(None, description="Organization ID to set as active (explicit null allowed)")
