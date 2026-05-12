"""
Compliance Profile Service

Manages Compliance Profiles - regulatory and policy rules that govern
how credentials are used.

A Compliance Profile defines:
- Data retention policies (how long, where stored)
- Consent requirements (what consent is needed)
- Audit logging requirements
- Data minimization rules
- Jurisdictional constraints
- Age verification requirements

Port: 8008
"""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Annotated

from marty_common import (
    OrganizationContext,
    ensure_membership_permission,
    require_org_membership,
)
from marty_common.org_authorization import get_organization_client
from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "compliance-profile-service"
SERVICE_PORT = int(os.environ.get("COMPLIANCE_PROFILE_SERVICE_PORT", "8008"))


# =============================================================================
# Domain Layer
# =============================================================================

class ComplianceProfileStatus(str, Enum):
    """Compliance profile status."""
    DRAFT = "draft"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


from marty_common.domain_enums import CredentialFormat  # noqa: E402
from marty_common.domain_enums import parse_credential_format as _parse_credential_format  # noqa: E402


class IssuanceProtocol(str, Enum):
    OID4VCI_PRE_AUTH = "OID4VCI_PRE_AUTH"
    OID4VCI_AUTH_CODE = "OID4VCI_AUTH_CODE"
    DIRECT = "DIRECT"
    CREDENTIAL_MANAGER = "CREDENTIAL_MANAGER"
    APPLE_WALLET = "APPLE_WALLET"


class DataRetentionPeriod(str, Enum):
    """Standard retention periods."""
    NONE = "none"           # Don't retain
    SESSION = "session"     # Delete after session
    DAY = "1_day"
    WEEK = "1_week"
    MONTH = "1_month"
    YEAR = "1_year"
    YEARS_3 = "3_years"
    YEARS_7 = "7_years"
    INDEFINITE = "indefinite"


class ConsentType(str, Enum):
    """Types of consent."""
    EXPLICIT = "explicit"       # Must actively consent
    IMPLICIT = "implicit"       # Implied by action
    OPT_OUT = "opt_out"         # Consent assumed unless opted out
    NONE = "none"               # No consent required


class AuditLevel(str, Enum):
    """Audit logging levels."""
    NONE = "none"
    MINIMAL = "minimal"         # Just transaction IDs
    STANDARD = "standard"       # Transaction + metadata
    DETAILED = "detailed"       # Full audit trail
    FORENSIC = "forensic"       # Everything, for investigation


@dataclass
class DataRetentionPolicy:
    """
    Policy for data retention.
    """
    retention_period: DataRetentionPeriod = DataRetentionPeriod.SESSION
    retain_metadata_only: bool = False  # Keep metadata but not PII
    anonymize_after_days: int | None = None
    deletion_confirmation_required: bool = False
    backup_retention_days: int | None = None


@dataclass
class ConsentRequirement:
    """
    Requirements for user consent.
    """
    consent_type: ConsentType = ConsentType.EXPLICIT
    consent_text: str = ""
    consent_version: str = "1.0"
    require_re_consent_days: int | None = None  # Re-consent after N days
    allow_partial_consent: bool = False
    track_consent_history: bool = True


@dataclass
class AuditConfiguration:
    """
    Audit logging configuration.
    """
    audit_level: AuditLevel = AuditLevel.STANDARD
    log_credential_access: bool = True
    log_verification_results: bool = True
    log_consent_changes: bool = True
    log_data_exports: bool = True
    tamper_evident: bool = True
    retention_days: int = 365


@dataclass
class DataMinimizationRule:
    """
    Rule for data minimization.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    description: str = ""
    applies_to_claims: list[str] = field(default_factory=list)  # Claim names
    action: str = "redact"  # redact, hash, truncate, generalize
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class JurisdictionalConstraint:
    """
    Geographic/jurisdictional constraints.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str | None = None
    allowed_countries: list[str] = field(default_factory=list)  # ISO 3166-1 alpha-2
    blocked_countries: list[str] = field(default_factory=list)
    data_residency_required: bool = False
    allowed_data_regions: list[str] = field(default_factory=list)


@dataclass
class AgeVerificationRule:
    """
    Age verification requirements.
    """
    enabled: bool = False
    minimum_age: int = 18
    verification_method: str = "derived"  # derived (age_over), exact, range
    allow_credential_expiry_check: bool = True


@dataclass
class IssuerArtifactRequirements:
    requires_x509_cert: bool = False
    requires_did: bool = False
    requires_jwk: bool = False
    cert_key_usage: list[str] = field(default_factory=list)
    recommended_algorithms: list[str] = field(default_factory=list)


@dataclass
class TrustProfileConstraints:
    compatible_profile_types: list[str] = field(default_factory=list)
    required_source_types: list[str] = field(default_factory=list)
    required_formats: list[str] = field(default_factory=list)


@dataclass
class ApiSurfaceEndpoint:
    rel: str = ""
    path_template: str = ""
    method: str = "GET"
    auth_required: bool = True
    org_scoped_path: str | None = None
    response_schema_ref: str | None = None
    standard_ref: str | None = None


@dataclass
class ComplianceProfile:
    """
    Compliance Profile - regulatory and policy rules.
    
    This defines the compliance rules for credential operations.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str | None = None
    name: str = ""
    description: str | None = None
    status: ComplianceProfileStatus = ComplianceProfileStatus.DRAFT
    
    # Compliance identification
    compliance_code: str | None = None  # e.g., "AAMVA_MDL"
    credential_format: CredentialFormat = CredentialFormat.SD_JWT_VC
    issuance_protocol: IssuanceProtocol | None = None
    issuer_artifact_requirements: IssuerArtifactRequirements | None = None
    default_verification_rules: dict[str, Any] | None = None
    verification_policy_set_id: str | None = None
    trust_profile_constraints: TrustProfileConstraints = field(default_factory=TrustProfileConstraints)
    api_surface: list[ApiSurfaceEndpoint] = field(default_factory=list)
    discoverable: bool = True
    is_system: bool = False
    
    # Regulatory framework references
    frameworks: list[str] = field(default_factory=list)  # e.g., ["GDPR", "CCPA", "eIDAS"]
    
    # Policies
    data_retention: DataRetentionPolicy = field(default_factory=DataRetentionPolicy)
    consent_requirement: ConsentRequirement = field(default_factory=ConsentRequirement)
    audit_configuration: AuditConfiguration = field(default_factory=AuditConfiguration)
    
    # Rules
    data_minimization_rules: list[DataMinimizationRule] = field(default_factory=list)
    jurisdictional_constraints: list[JurisdictionalConstraint] = field(default_factory=list)
    age_verification: AgeVerificationRule = field(default_factory=AgeVerificationRule)
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def activate(self) -> None:
        self.status = ComplianceProfileStatus.ACTIVE
        self.updated_at = datetime.now(timezone.utc)
    
    def suspend(self) -> None:
        self.status = ComplianceProfileStatus.SUSPENDED
        self.updated_at = datetime.now(timezone.utc)


# =============================================================================
# Application Layer
# =============================================================================

class InMemoryComplianceProfileRepository:
    """In-memory repository for development."""
    
    def __init__(self):
        self._profiles: dict[str, ComplianceProfile] = {}
    
    async def save(self, profile: ComplianceProfile) -> None:
        self._profiles[profile.id] = profile
    
    async def get(self, profile_id: str) -> ComplianceProfile | None:
        return self._profiles.get(profile_id)

    async def get_profile(self, profile_id: str) -> ComplianceProfile | None:
        return await self.get(profile_id)
    
    async def list(self, org_id: str) -> list[ComplianceProfile]:
        return [p for p in self._profiles.values() if p.organization_id == org_id]
    
    async def delete(self, profile_id: str) -> None:
        self._profiles.pop(profile_id, None)


# =============================================================================
# HTTP Adapter - Request/Response Models
# =============================================================================

class DataRetentionPolicyModel(BaseModel):
    retention_period: str = "session"
    retain_metadata_only: bool = False
    anonymize_after_days: int | None = None
    deletion_confirmation_required: bool = False
    backup_retention_days: int | None = None


class ConsentRequirementModel(BaseModel):
    consent_type: str = "explicit"
    consent_text: str = ""
    consent_version: str = "1.0"
    require_re_consent_days: int | None = None
    allow_partial_consent: bool = False
    track_consent_history: bool = True


class AuditConfigurationModel(BaseModel):
    audit_level: str = "standard"
    log_credential_access: bool = True
    log_verification_results: bool = True
    log_consent_changes: bool = True
    log_data_exports: bool = True
    tamper_evident: bool = True
    retention_days: int = 365


class DataMinimizationRuleModel(BaseModel):
    description: str
    applies_to_claims: list[str] = Field(default_factory=list)
    action: str = "redact"
    parameters: dict = Field(default_factory=dict)


class JurisdictionalConstraintModel(BaseModel):
    name: str
    description: str | None = None
    allowed_countries: list[str] = Field(default_factory=list)
    blocked_countries: list[str] = Field(default_factory=list)
    data_residency_required: bool = False
    allowed_data_regions: list[str] = Field(default_factory=list)


class AgeVerificationRuleModel(BaseModel):
    enabled: bool = False
    minimum_age: int = 18
    verification_method: str = "derived"
    allow_credential_expiry_check: bool = True


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


class CreateComplianceProfileRequest(BaseModel):
    organization_id: str | None = Field(None, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    compliance_code: str | None = None
    credential_format: str = "SD_JWT_VC"
    issuance_protocol: str | None = None
    issuer_artifact_requirements: IssuerArtifactRequirementsModel | None = None
    default_verification_rules: dict[str, Any] | None = None
    verification_policy_set_id: str | None = None
    trust_profile_constraints: TrustProfileConstraintsModel | None = None
    api_surface: list[ApiSurfaceEndpointModel] = Field(default_factory=list)
    discoverable: bool = True
    is_system: bool = False
    system_profile: bool | None = None
    frameworks: list[str] = Field(default_factory=list)
    data_retention: DataRetentionPolicyModel | None = None
    consent_requirement: ConsentRequirementModel | None = None
    audit_configuration: AuditConfigurationModel | None = None
    data_minimization_rules: list[DataMinimizationRuleModel] = Field(default_factory=list)
    jurisdictional_constraints: list[JurisdictionalConstraintModel] = Field(default_factory=list)
    age_verification: AgeVerificationRuleModel | None = None


class UpdateComplianceProfileRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    compliance_code: str | None = None
    credential_format: str | None = None
    issuance_protocol: str | None = None
    issuer_artifact_requirements: IssuerArtifactRequirementsModel | None = None
    default_verification_rules: dict[str, Any] | None = None
    verification_policy_set_id: str | None = None
    trust_profile_constraints: TrustProfileConstraintsModel | None = None
    api_surface: list[ApiSurfaceEndpointModel] | None = None
    discoverable: bool | None = None
    is_system: bool | None = None
    frameworks: list[str] | None = None
    data_retention: DataRetentionPolicyModel | None = None
    consent_requirement: ConsentRequirementModel | None = None
    audit_configuration: AuditConfigurationModel | None = None
    data_minimization_rules: list[DataMinimizationRuleModel] | None = None
    jurisdictional_constraints: list[JurisdictionalConstraintModel] | None = None
    age_verification: AgeVerificationRuleModel | None = None


class ComplianceProfileResponse(BaseModel):
    id: str
    organization_id: str | None = None
    compliance_code: str | None = None
    name: str
    description: str | None = None
    credential_format: str = "SD_JWT_VC"
    issuance_protocol: str | None = None
    issuer_artifact_requirements: dict | None = None
    default_verification_rules: dict | None = None
    verification_policy_set_id: str | None = None
    trust_profile_constraints: dict | None = None
    api_surface: list[dict] | None = None
    discoverable: bool | None = None
    is_system: bool
    created_at: str


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/compliance-profiles", tags=["compliance-profiles"])

_repo: InMemoryComplianceProfileRepository | None = None


def get_repo() -> InMemoryComplianceProfileRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


def get_current_user_id(x_user_id: Annotated[str, Header()]) -> str:
    """Extract user ID from X-User-Id header (injected by gateway)."""
    return x_user_id


def _ensure_compliance_profile_permission(membership: Any, action: str) -> None:
    if membership is not None and membership.is_active():
        if (
            membership.has_permission("compliance-profile", action)
            or membership.is_owner
            or membership.has_org_console_access
            or membership.has_role("admin", "owner")
        ):
            return
    ensure_membership_permission(membership, "compliance-profile", action)


@router.post("", response_model=ComplianceProfileResponse, response_model_exclude_none=True)
async def create_compliance_profile(
    request: CreateComplianceProfileRequest,
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryComplianceProfileRepository = Depends(get_repo),
) -> ComplianceProfileResponse:
    """Create a new Compliance Profile."""
    is_system_profile = request.system_profile if request.system_profile is not None else request.is_system
    if request.organization_id is None and not is_system_profile:
        raise HTTPException(status_code=400, detail="organization_id is required for non-system compliance profiles")
    # MIP §10 — system profiles MUST have organization_id=null
    if is_system_profile and request.organization_id is not None:
        raise HTTPException(status_code=400, detail="system profiles must not have an organization_id")
    if request.organization_id is not None:
        org_client = await get_organization_client(fastapi_request)
        membership = await org_client.get_membership(user_id, request.organization_id)
        _ensure_compliance_profile_permission(membership, "create")
    
    profile = ComplianceProfile(
        organization_id=request.organization_id,
        name=request.name,
        description=request.description,
        compliance_code=request.compliance_code,
        credential_format=_parse_credential_format(request.credential_format),
        issuance_protocol=IssuanceProtocol(request.issuance_protocol) if request.issuance_protocol else None,
        issuer_artifact_requirements=IssuerArtifactRequirements(
            requires_x509_cert=request.issuer_artifact_requirements.requires_x509_cert,
            requires_did=request.issuer_artifact_requirements.requires_did,
            requires_jwk=request.issuer_artifact_requirements.requires_jwk,
            cert_key_usage=request.issuer_artifact_requirements.cert_key_usage,
            recommended_algorithms=request.issuer_artifact_requirements.recommended_algorithms,
        ) if request.issuer_artifact_requirements else None,
        default_verification_rules=request.default_verification_rules,
        verification_policy_set_id=request.verification_policy_set_id,
        trust_profile_constraints=TrustProfileConstraints(
            compatible_profile_types=request.trust_profile_constraints.compatible_profile_types,
            required_source_types=request.trust_profile_constraints.required_source_types,
            required_formats=request.trust_profile_constraints.required_formats,
        ) if request.trust_profile_constraints else TrustProfileConstraints(),
        api_surface=[
            ApiSurfaceEndpoint(
                rel=endpoint.rel,
                path_template=endpoint.path_template,
                method=endpoint.method,
                auth_required=endpoint.auth_required,
                org_scoped_path=endpoint.org_scoped_path,
                response_schema_ref=endpoint.response_schema_ref,
                standard_ref=endpoint.standard_ref,
            )
            for endpoint in request.api_surface
        ],
        discoverable=request.discoverable,
        is_system=is_system_profile,
        frameworks=request.frameworks,
    )
    
    # Set data retention
    if request.data_retention:
        profile.data_retention = DataRetentionPolicy(
            retention_period=DataRetentionPeriod(request.data_retention.retention_period),
            retain_metadata_only=request.data_retention.retain_metadata_only,
            anonymize_after_days=request.data_retention.anonymize_after_days,
            deletion_confirmation_required=request.data_retention.deletion_confirmation_required,
            backup_retention_days=request.data_retention.backup_retention_days,
        )
    
    # Set consent requirement
    if request.consent_requirement:
        profile.consent_requirement = ConsentRequirement(
            consent_type=ConsentType(request.consent_requirement.consent_type),
            consent_text=request.consent_requirement.consent_text,
            consent_version=request.consent_requirement.consent_version,
            require_re_consent_days=request.consent_requirement.require_re_consent_days,
            allow_partial_consent=request.consent_requirement.allow_partial_consent,
            track_consent_history=request.consent_requirement.track_consent_history,
        )
    
    # Set audit configuration
    if request.audit_configuration:
        profile.audit_configuration = AuditConfiguration(
            audit_level=AuditLevel(request.audit_configuration.audit_level),
            log_credential_access=request.audit_configuration.log_credential_access,
            log_verification_results=request.audit_configuration.log_verification_results,
            log_consent_changes=request.audit_configuration.log_consent_changes,
            log_data_exports=request.audit_configuration.log_data_exports,
            tamper_evident=request.audit_configuration.tamper_evident,
            retention_days=request.audit_configuration.retention_days,
        )
    
    # Set data minimization rules
    for rule in request.data_minimization_rules:
        profile.data_minimization_rules.append(DataMinimizationRule(
            description=rule.description,
            applies_to_claims=rule.applies_to_claims,
            action=rule.action,
            parameters=rule.parameters,
        ))
    
    # Set jurisdictional constraints
    for constraint in request.jurisdictional_constraints:
        profile.jurisdictional_constraints.append(JurisdictionalConstraint(
            name=constraint.name,
            description=constraint.description,
            allowed_countries=constraint.allowed_countries,
            blocked_countries=constraint.blocked_countries,
            data_residency_required=constraint.data_residency_required,
            allowed_data_regions=constraint.allowed_data_regions,
        ))
    
    # Set age verification
    if request.age_verification:
        profile.age_verification = AgeVerificationRule(
            enabled=request.age_verification.enabled,
            minimum_age=request.age_verification.minimum_age,
            verification_method=request.age_verification.verification_method,
            allow_credential_expiry_check=request.age_verification.allow_credential_expiry_check,
        )
    
    await repo.save(profile)
    logger.info(f"Created Compliance Profile: {profile.id}")
    return _profile_to_response(profile)


@router.get("", response_model=list[ComplianceProfileResponse], response_model_exclude_none=True)
async def list_compliance_profiles(
    organization_id: str = Query(..., description="Organization ID"),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryComplianceProfileRepository = Depends(get_repo),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[ComplianceProfileResponse]:
    """List Compliance Profiles for an organization."""
    # Verify org membership
    await app.state.org_client.get_membership(user_id, organization_id)
    profiles = await repo.list(organization_id)
    return [_profile_to_response(p) for p in profiles[offset:offset + limit]]


@router.get("/{profile_id}", response_model=ComplianceProfileResponse, response_model_exclude_none=True)
async def get_compliance_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryComplianceProfileRepository = Depends(get_repo),
) -> ComplianceProfileResponse:
    """Get a Compliance Profile by ID."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance Profile not found")
    # Verify org membership
    if profile.organization_id is not None:
        await app.state.org_client.get_membership(user_id, profile.organization_id)
    return _profile_to_response(profile)


@router.patch("/{profile_id}", response_model=ComplianceProfileResponse, response_model_exclude_none=True)
async def update_compliance_profile(
    profile_id: str,
    request: UpdateComplianceProfileRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryComplianceProfileRepository = Depends(get_repo),
) -> ComplianceProfileResponse:
    """Update a Compliance Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance Profile not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    _ensure_compliance_profile_permission(membership, "edit")
    
    if request.name is not None:
        profile.name = request.name
    if request.description is not None:
        profile.description = request.description
    if request.compliance_code is not None:
        profile.compliance_code = request.compliance_code
    if request.credential_format is not None:
        profile.credential_format = _parse_credential_format(request.credential_format)
    if request.issuance_protocol is not None:
        profile.issuance_protocol = IssuanceProtocol(request.issuance_protocol)
    if request.issuer_artifact_requirements is not None:
        profile.issuer_artifact_requirements = IssuerArtifactRequirements(
            requires_x509_cert=request.issuer_artifact_requirements.requires_x509_cert,
            requires_did=request.issuer_artifact_requirements.requires_did,
            requires_jwk=request.issuer_artifact_requirements.requires_jwk,
            cert_key_usage=request.issuer_artifact_requirements.cert_key_usage,
            recommended_algorithms=request.issuer_artifact_requirements.recommended_algorithms,
        )
    if request.default_verification_rules is not None:
        profile.default_verification_rules = request.default_verification_rules
    if request.verification_policy_set_id is not None:
        profile.verification_policy_set_id = request.verification_policy_set_id
    if request.trust_profile_constraints is not None:
        profile.trust_profile_constraints = TrustProfileConstraints(
            compatible_profile_types=request.trust_profile_constraints.compatible_profile_types,
            required_source_types=request.trust_profile_constraints.required_source_types,
            required_formats=request.trust_profile_constraints.required_formats,
        )
    if request.api_surface is not None:
        profile.api_surface = [
            ApiSurfaceEndpoint(
                rel=endpoint.rel,
                path_template=endpoint.path_template,
                method=endpoint.method,
                auth_required=endpoint.auth_required,
                org_scoped_path=endpoint.org_scoped_path,
                response_schema_ref=endpoint.response_schema_ref,
                standard_ref=endpoint.standard_ref,
            )
            for endpoint in request.api_surface
        ]
    if request.discoverable is not None:
        profile.discoverable = request.discoverable
    if request.is_system is not None:
        profile.is_system = request.is_system
    if request.frameworks is not None:
        profile.frameworks = request.frameworks
    if request.data_retention is not None:
        profile.data_retention = DataRetentionPolicy(
            retention_period=DataRetentionPeriod(request.data_retention.retention_period),
            retain_metadata_only=request.data_retention.retain_metadata_only,
            anonymize_after_days=request.data_retention.anonymize_after_days,
            deletion_confirmation_required=request.data_retention.deletion_confirmation_required,
            backup_retention_days=request.data_retention.backup_retention_days,
        )
    if request.consent_requirement is not None:
        profile.consent_requirement = ConsentRequirement(
            consent_type=ConsentType(request.consent_requirement.consent_type),
            consent_text=request.consent_requirement.consent_text,
            consent_version=request.consent_requirement.consent_version,
            require_re_consent_days=request.consent_requirement.require_re_consent_days,
            allow_partial_consent=request.consent_requirement.allow_partial_consent,
            track_consent_history=request.consent_requirement.track_consent_history,
        )
    if request.audit_configuration is not None:
        profile.audit_configuration = AuditConfiguration(
            audit_level=AuditLevel(request.audit_configuration.audit_level),
            log_credential_access=request.audit_configuration.log_credential_access,
            log_verification_results=request.audit_configuration.log_verification_results,
            log_consent_changes=request.audit_configuration.log_consent_changes,
            log_data_exports=request.audit_configuration.log_data_exports,
            tamper_evident=request.audit_configuration.tamper_evident,
            retention_days=request.audit_configuration.retention_days,
        )
    if request.data_minimization_rules is not None:
        profile.data_minimization_rules = [
            DataMinimizationRule(
                description=rule.description,
                applies_to_claims=rule.applies_to_claims,
                action=rule.action,
                parameters=rule.parameters,
            )
            for rule in request.data_minimization_rules
        ]
    if request.jurisdictional_constraints is not None:
        profile.jurisdictional_constraints = [
            JurisdictionalConstraint(
                name=constraint.name,
                description=constraint.description,
                allowed_countries=constraint.allowed_countries,
                blocked_countries=constraint.blocked_countries,
                data_residency_required=constraint.data_residency_required,
                allowed_data_regions=constraint.allowed_data_regions,
            )
            for constraint in request.jurisdictional_constraints
        ]
    if request.age_verification is not None:
        profile.age_verification = AgeVerificationRule(
            enabled=request.age_verification.enabled,
            minimum_age=request.age_verification.minimum_age,
            verification_method=request.age_verification.verification_method,
            allow_credential_expiry_check=request.age_verification.allow_credential_expiry_check,
        )
    
    profile.updated_at = datetime.now(timezone.utc)
    await repo.save(profile)
    return _profile_to_response(profile)


@router.post("/{profile_id}/activate", response_model=ComplianceProfileResponse, response_model_exclude_none=True)
async def activate_compliance_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryComplianceProfileRepository = Depends(get_repo),
) -> ComplianceProfileResponse:
    """Activate a Compliance Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance Profile not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    _ensure_compliance_profile_permission(membership, "activate")
    profile.activate()
    await repo.save(profile)
    return _profile_to_response(profile)


@router.post("/{profile_id}/suspend", response_model=ComplianceProfileResponse, response_model_exclude_none=True)
async def suspend_compliance_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryComplianceProfileRepository = Depends(get_repo),
) -> ComplianceProfileResponse:
    """Suspend a Compliance Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance Profile not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    _ensure_compliance_profile_permission(membership, "suspend")
    profile.suspend()
    await repo.save(profile)
    return _profile_to_response(profile)


@router.delete("/{profile_id}")
async def delete_compliance_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryComplianceProfileRepository = Depends(get_repo),
) -> dict:
    """Delete a Compliance Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance Profile not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    _ensure_compliance_profile_permission(membership, "delete")
    
    await repo.delete(profile_id)
    return {"success": True}


def _profile_to_response(profile: ComplianceProfile) -> ComplianceProfileResponse:
    return ComplianceProfileResponse(
        id=profile.id,
        organization_id=profile.organization_id,
        compliance_code=profile.compliance_code,
        name=profile.name,
        description=profile.description,
        credential_format=profile.credential_format.value,
        issuance_protocol=profile.issuance_protocol.value if profile.issuance_protocol else None,
        issuer_artifact_requirements={
            "requires_x509_cert": profile.issuer_artifact_requirements.requires_x509_cert,
            "requires_did": profile.issuer_artifact_requirements.requires_did,
            "requires_jwk": profile.issuer_artifact_requirements.requires_jwk,
            "cert_key_usage": profile.issuer_artifact_requirements.cert_key_usage,
            "recommended_algorithms": profile.issuer_artifact_requirements.recommended_algorithms,
        } if profile.issuer_artifact_requirements else None,
        default_verification_rules=profile.default_verification_rules,
        verification_policy_set_id=profile.verification_policy_set_id,
        trust_profile_constraints={
            "compatible_profile_types": profile.trust_profile_constraints.compatible_profile_types,
            "required_source_types": profile.trust_profile_constraints.required_source_types,
            "required_formats": profile.trust_profile_constraints.required_formats,
        } if (
            profile.trust_profile_constraints.compatible_profile_types
            or profile.trust_profile_constraints.required_source_types
            or profile.trust_profile_constraints.required_formats
        ) else {},
        api_surface=[
            {
                "rel": endpoint.rel,
                "path_template": endpoint.path_template,
                "method": endpoint.method,
                "auth_required": endpoint.auth_required,
                "org_scoped_path": endpoint.org_scoped_path,
                "response_schema_ref": endpoint.response_schema_ref,
                "standard_ref": endpoint.standard_ref,
            }
            for endpoint in profile.api_surface
        ],
        discoverable=profile.discoverable,
        is_system=profile.is_system,
        created_at=profile.created_at.isoformat(),
    )


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo
    logger.info(f"Starting {SERVICE_NAME}...")
    _repo = InMemoryComplianceProfileRepository()
    
    # Initialize gRPC channel to organization service
    from common.di import setup_org_client, teardown_org_client
    await setup_org_client(app, "compliance-profile")
    
    yield
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await teardown_org_client(app)


def create_app() -> FastAPI:
    from marty_common.service_setup import create_service_app
    app = create_service_app(
        title="Compliance Profile Service",
        description="Manages Compliance Profiles - regulatory and policy rules",
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[router],
    )
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("compliance_profile.main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
