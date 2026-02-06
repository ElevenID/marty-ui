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

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

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
class ComplianceProfile:
    """
    Compliance Profile - regulatory and policy rules.
    
    This defines the compliance rules for credential operations.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    name: str = ""
    description: str | None = None
    status: ComplianceProfileStatus = ComplianceProfileStatus.DRAFT
    
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
    applies_to_claims: list[str] = []
    action: str = "redact"
    parameters: dict = {}


class JurisdictionalConstraintModel(BaseModel):
    name: str
    description: str | None = None
    allowed_countries: list[str] = []
    blocked_countries: list[str] = []
    data_residency_required: bool = False
    allowed_data_regions: list[str] = []


class AgeVerificationRuleModel(BaseModel):
    enabled: bool = False
    minimum_age: int = 18
    verification_method: str = "derived"
    allow_credential_expiry_check: bool = True


class CreateComplianceProfileRequest(BaseModel):
    organization_id: str
    name: str
    description: str | None = None
    frameworks: list[str] = []
    data_retention: DataRetentionPolicyModel | None = None
    consent_requirement: ConsentRequirementModel | None = None
    audit_configuration: AuditConfigurationModel | None = None
    data_minimization_rules: list[DataMinimizationRuleModel] = []
    jurisdictional_constraints: list[JurisdictionalConstraintModel] = []
    age_verification: AgeVerificationRuleModel | None = None


class UpdateComplianceProfileRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    frameworks: list[str] | None = None
    data_retention: DataRetentionPolicyModel | None = None
    consent_requirement: ConsentRequirementModel | None = None
    audit_configuration: AuditConfigurationModel | None = None
    age_verification: AgeVerificationRuleModel | None = None


class ComplianceProfileResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    frameworks: list[str]
    data_retention: dict
    consent_requirement: dict
    audit_configuration: dict
    data_minimization_rules: list[dict]
    jurisdictional_constraints: list[dict]
    age_verification: dict
    created_at: str
    updated_at: str


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/compliance-profiles", tags=["compliance-profiles"])

_repo: InMemoryComplianceProfileRepository | None = None


def get_repo() -> InMemoryComplianceProfileRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


@router.post("", response_model=ComplianceProfileResponse)
async def create_compliance_profile(
    request: CreateComplianceProfileRequest,
    repo: InMemoryComplianceProfileRepository = Depends(get_repo),
) -> ComplianceProfileResponse:
    """Create a new Compliance Profile."""
    profile = ComplianceProfile(
        organization_id=request.organization_id,
        name=request.name,
        description=request.description,
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


@router.get("", response_model=list[ComplianceProfileResponse])
async def list_compliance_profiles(
    organization_id: str = Query(..., description="Organization ID"),
    repo: InMemoryComplianceProfileRepository = Depends(get_repo),
) -> list[ComplianceProfileResponse]:
    """List Compliance Profiles for an organization."""
    profiles = await repo.list(organization_id)
    return [_profile_to_response(p) for p in profiles]


@router.get("/{profile_id}", response_model=ComplianceProfileResponse)
async def get_compliance_profile(
    profile_id: str,
    repo: InMemoryComplianceProfileRepository = Depends(get_repo),
) -> ComplianceProfileResponse:
    """Get a Compliance Profile by ID."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance Profile not found")
    return _profile_to_response(profile)


@router.patch("/{profile_id}", response_model=ComplianceProfileResponse)
async def update_compliance_profile(
    profile_id: str,
    request: UpdateComplianceProfileRequest,
    repo: InMemoryComplianceProfileRepository = Depends(get_repo),
) -> ComplianceProfileResponse:
    """Update a Compliance Profile."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance Profile not found")
    
    if request.name is not None:
        profile.name = request.name
    if request.description is not None:
        profile.description = request.description
    if request.frameworks is not None:
        profile.frameworks = request.frameworks
    
    profile.updated_at = datetime.now(timezone.utc)
    await repo.save(profile)
    return _profile_to_response(profile)


@router.post("/{profile_id}/activate", response_model=ComplianceProfileResponse)
async def activate_compliance_profile(
    profile_id: str,
    repo: InMemoryComplianceProfileRepository = Depends(get_repo),
) -> ComplianceProfileResponse:
    """Activate a Compliance Profile."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance Profile not found")
    profile.activate()
    await repo.save(profile)
    return _profile_to_response(profile)


@router.post("/{profile_id}/suspend", response_model=ComplianceProfileResponse)
async def suspend_compliance_profile(
    profile_id: str,
    repo: InMemoryComplianceProfileRepository = Depends(get_repo),
) -> ComplianceProfileResponse:
    """Suspend a Compliance Profile."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Compliance Profile not found")
    profile.suspend()
    await repo.save(profile)
    return _profile_to_response(profile)


@router.delete("/{profile_id}")
async def delete_compliance_profile(
    profile_id: str,
    repo: InMemoryComplianceProfileRepository = Depends(get_repo),
) -> dict:
    """Delete a Compliance Profile."""
    await repo.delete(profile_id)
    return {"success": True}


def _profile_to_response(profile: ComplianceProfile) -> ComplianceProfileResponse:
    return ComplianceProfileResponse(
        id=profile.id,
        organization_id=profile.organization_id,
        name=profile.name,
        description=profile.description,
        status=profile.status.value,
        frameworks=profile.frameworks,
        data_retention={
            "retention_period": profile.data_retention.retention_period.value,
            "retain_metadata_only": profile.data_retention.retain_metadata_only,
            "anonymize_after_days": profile.data_retention.anonymize_after_days,
            "deletion_confirmation_required": profile.data_retention.deletion_confirmation_required,
        },
        consent_requirement={
            "consent_type": profile.consent_requirement.consent_type.value,
            "consent_text": profile.consent_requirement.consent_text,
            "consent_version": profile.consent_requirement.consent_version,
            "allow_partial_consent": profile.consent_requirement.allow_partial_consent,
            "track_consent_history": profile.consent_requirement.track_consent_history,
        },
        audit_configuration={
            "audit_level": profile.audit_configuration.audit_level.value,
            "log_credential_access": profile.audit_configuration.log_credential_access,
            "log_verification_results": profile.audit_configuration.log_verification_results,
            "tamper_evident": profile.audit_configuration.tamper_evident,
            "retention_days": profile.audit_configuration.retention_days,
        },
        data_minimization_rules=[
            {
                "id": r.id,
                "description": r.description,
                "applies_to_claims": r.applies_to_claims,
                "action": r.action,
            }
            for r in profile.data_minimization_rules
        ],
        jurisdictional_constraints=[
            {
                "id": c.id,
                "name": c.name,
                "allowed_countries": c.allowed_countries,
                "blocked_countries": c.blocked_countries,
                "data_residency_required": c.data_residency_required,
            }
            for c in profile.jurisdictional_constraints
        ],
        age_verification={
            "enabled": profile.age_verification.enabled,
            "minimum_age": profile.age_verification.minimum_age,
            "verification_method": profile.age_verification.verification_method,
        },
        created_at=profile.created_at.isoformat(),
        updated_at=profile.updated_at.isoformat(),
    )


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo
    logger.info(f"Starting {SERVICE_NAME}...")
    _repo = InMemoryComplianceProfileRepository()
    yield
    logger.info(f"Shutting down {SERVICE_NAME}...")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Compliance Profile Service",
        description="Manages Compliance Profiles - regulatory and policy rules",
        version="1.0.0",
        lifespan=lifespan,
    )
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    app.include_router(router)
    
    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": SERVICE_NAME}
    
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("compliance_profile.main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
