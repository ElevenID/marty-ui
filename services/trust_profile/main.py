"""
Trust Profile Service

Manages Trust Profiles - the configuration of who is trusted and how
cryptographic validation happens.

A Trust Profile contains:
- Trust sources (registries, pinned roots, issuer allow/deny lists)
- Validation rules (chain building, allowed algorithms, key usage)
- Revocation policy (OCSP/CRL/status list, hard-fail vs soft-fail)
- Time policy (clock skew, freshness windows)
- Format support (mdoc/mDL, VC, SD-JWT)

Port: 8004
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
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from typing import Annotated

from marty_common import (
    OrganizationClient,
    OrganizationContext,
    require_org_membership,
)
from marty_common.org_authorization import get_organization_client
from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware
from trust_profile.infrastructure.adapters import PostgresTrustProfileRepository

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "trust-profile-service"
SERVICE_PORT = int(os.environ.get("TRUST_PROFILE_SERVICE_PORT", "8004"))


def get_config() -> dict:
    """Get service configuration from environment."""
    return {
        "database_url": os.environ.get(
            "DATABASE_URL",
            "postgresql+asyncpg://marty:marty_dev@localhost:5432/marty_credentials"
        ),
    }


# =============================================================================
# Domain Layer
# =============================================================================

class TrustProfileStatus(str, Enum):
    """Trust profile status."""
    DRAFT = "draft"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class RevocationCheckMode(str, Enum):
    """Failure behavior when a revocation check is performed.
    Maps to marty-protocol enum: revocation-check-modes.json
    """
    HARD_FAIL = "HARD_FAIL"
    SOFT_FAIL = "SOFT_FAIL"
    SKIP = "SKIP"


class CredentialFormat(str, Enum):
    """Supported credential formats.
    Maps to marty-protocol enum: credential-formats.json
    """
    MDOC = "MDOC"
    SD_JWT_VC = "SD_JWT_VC"
    VC_JWT = "VC_JWT"
    JSON_LD = "JSON_LD"
    ZK_MDOC = "ZK_MDOC"


class IssuerStatus(str, Enum):
    """Trusted issuer status."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


@dataclass
class TrustSource:
    """
    A source of trust (registry, pinned root, etc.)
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    source_type: str = "registry"  # registry, pinned_root, allowlist
    url: str | None = None
    pinned_certificates: list[str] = field(default_factory=list)
    refresh_interval_hours: int = 24
    enabled: bool = True


@dataclass
class ValidationRules:
    """
    Rules for cryptographic validation.
    """
    allowed_algorithms: list[str] = field(default_factory=lambda: ["ES256", "ES384", "EdDSA"])
    min_key_size_rsa: int = 2048
    min_key_size_ec: int = 256
    require_key_usage: bool = True
    max_chain_depth: int = 5
    allow_self_signed: bool = False


@dataclass
class RevocationPolicy:
    """
    Policy for revocation checking.
    """
    check_mode: RevocationCheckMode = RevocationCheckMode.HARD_FAIL
    check_ocsp: bool = True
    check_crl: bool = True
    check_status_list: bool = True
    offline_grace_period_hours: int = 24
    cache_duration_hours: int = 1


@dataclass
class TimePolicy:
    """
    Time-related validation rules.
    """
    max_clock_skew_seconds: int = 300  # 5 minutes
    credential_freshness_hours: int | None = None  # If set, credentials must be issued within this window
    require_not_before: bool = True
    require_expiration: bool = True


@dataclass
class TrustedIssuer:
    """
    A trusted issuer within a Trust Profile.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    trust_profile_id: str = ""
    name: str = ""
    description: str | None = None
    
    # Issuer identity
    issuer_did: str = ""
    issuer_url: str | None = None
    
    # Trust settings
    status: IssuerStatus = IssuerStatus.ACTIVE
    credential_template_ids: list[str] = field(default_factory=list)  # Which templates this issuer can issue
    
    # Verification keys (JWK format)
    verification_keys: list[dict[str, Any]] = field(default_factory=list)
    
    # Constraints
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TrustProfile:
    """
    Trust Profile - defines who is trusted and how validation happens.
    
    This is the core configuration object for trust management.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    name: str = ""
    description: str | None = None
    status: TrustProfileStatus = TrustProfileStatus.DRAFT
    
    # Trust configuration
    trust_sources: list[TrustSource] = field(default_factory=list)
    validation_rules: ValidationRules = field(default_factory=ValidationRules)
    
    # Revocation configuration
    revocation_policy: RevocationPolicy = field(default_factory=RevocationPolicy)  # DEPRECATED: use revocation_profile_id
    revocation_profile_id: str | None = None  # NEW: links to RevocationProfile
    
    time_policy: TimePolicy = field(default_factory=TimePolicy)
    
    # Supported formats
    supported_formats: list[CredentialFormat] = field(
        default_factory=lambda: [CredentialFormat.SD_JWT_VC, CredentialFormat.MDOC]
    )
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def activate(self) -> None:
        self.status = TrustProfileStatus.ACTIVE
        self.updated_at = datetime.now(timezone.utc)
    
    def suspend(self) -> None:
        self.status = TrustProfileStatus.SUSPENDED
        self.updated_at = datetime.now(timezone.utc)


# =============================================================================
# Application Layer
# =============================================================================

class InMemoryTrustProfileRepository:
    """In-memory repository for development."""
    
    def __init__(self):
        self._profiles: dict[str, TrustProfile] = {}
        self._issuers: dict[str, TrustedIssuer] = {}
    
    # Trust Profile operations
    async def save_profile(self, profile: TrustProfile) -> None:
        self._profiles[profile.id] = profile
    
    async def get_profile(self, profile_id: str) -> TrustProfile | None:
        return self._profiles.get(profile_id)
    
    async def list_profiles(self, org_id: str) -> list[TrustProfile]:
        return [p for p in self._profiles.values() if p.organization_id == org_id]
    
    async def delete_profile(self, profile_id: str) -> None:
        self._profiles.pop(profile_id, None)
        # Also delete associated issuers
        to_delete = [i.id for i in self._issuers.values() if i.trust_profile_id == profile_id]
        for issuer_id in to_delete:
            self._issuers.pop(issuer_id, None)
    
    # Trusted Issuer operations
    async def save_issuer(self, issuer: TrustedIssuer) -> None:
        self._issuers[issuer.id] = issuer
    
    async def get_issuer(self, issuer_id: str) -> TrustedIssuer | None:
        return self._issuers.get(issuer_id)
    
    async def list_issuers(self, profile_id: str) -> list[TrustedIssuer]:
        return [i for i in self._issuers.values() if i.trust_profile_id == profile_id]
    
    async def delete_issuer(self, issuer_id: str) -> None:
        self._issuers.pop(issuer_id, None)


# =============================================================================
# HTTP Adapter - Request/Response Models
# =============================================================================

class TrustSourceModel(BaseModel):
    name: str
    source_type: str = "registry"
    url: str | None = None
    pinned_certificates: list[str] = []
    refresh_interval_hours: int = 24
    enabled: bool = True


class ValidationRulesModel(BaseModel):
    allowed_algorithms: list[str] = ["ES256", "ES384", "EdDSA"]
    min_key_size_rsa: int = 2048
    min_key_size_ec: int = 256
    require_key_usage: bool = True
    max_chain_depth: int = 5
    allow_self_signed: bool = False


class RevocationPolicyModel(BaseModel):
    check_mode: str = "HARD_FAIL"
    check_ocsp: bool = True
    check_crl: bool = True
    check_status_list: bool = True
    offline_grace_period_hours: int = 24
    cache_duration_hours: int = 1


class TimePolicyModel(BaseModel):
    max_clock_skew_seconds: int = 300
    credential_freshness_hours: int | None = None
    require_not_before: bool = True
    require_expiration: bool = True


class CreateTrustProfileRequest(BaseModel):
    organization_id: str
    name: str
    description: str | None = None
    trust_sources: list[TrustSourceModel] = []
    validation_rules: ValidationRulesModel | None = None
    revocation_policy: RevocationPolicyModel | None = None  # DEPRECATED: use revocation_profile_id
    revocation_profile_id: str | None = None  # NEW: links to RevocationProfile
    time_policy: TimePolicyModel | None = None
    supported_formats: list[str] = ["SD_JWT_VC", "MDOC"]


class UpdateTrustProfileRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    trust_sources: list[TrustSourceModel] | None = None
    validation_rules: ValidationRulesModel | None = None
    revocation_policy: RevocationPolicyModel | None = None  # DEPRECATED
    revocation_profile_id: str | None = None  # NEW
    time_policy: TimePolicyModel | None = None
    supported_formats: list[str] | None = None


class TrustProfileResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    trust_sources: list[dict]
    validation_rules: dict
    revocation_policy: dict  # DEPRECATED
    revocation_check_enabled: bool  # Simplified field for tests
    revocation_profile_id: str | None  # NEW
    time_policy: dict
    supported_formats: list[str]
    trusted_issuers: list[dict] = []  # For backwards compatibility
    created_at: str
    updated_at: str


class CreateTrustedIssuerRequest(BaseModel):
    name: str
    description: str | None = None
    issuer_did: str
    issuer_url: str | None = None
    credential_template_ids: list[str] = []
    verification_keys: list[dict] = []
    valid_from: str | None = None
    valid_until: str | None = None


class TrustedIssuerResponse(BaseModel):
    id: str
    trust_profile_id: str
    name: str
    description: str | None
    issuer_did: str
    issuer_url: str | None
    status: str
    credential_template_ids: list[str]
    created_at: str
    updated_at: str


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/trust-profiles", tags=["trust-profiles"])

_repo: InMemoryTrustProfileRepository | None = None


def get_repo() -> InMemoryTrustProfileRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


def get_current_user_id(x_user_id: Annotated[str, Header()]) -> str:
    """Extract user ID from X-User-Id header (injected by gateway)."""
    return x_user_id


# Trust Profile endpoints
@router.post("", response_model=TrustProfileResponse)
async def create_trust_profile(
    request: CreateTrustProfileRequest,
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository = Depends(get_repo),
) -> TrustProfileResponse:
    """Create a new Trust Profile."""
    # Verify org membership
    org_client = await get_organization_client(fastapi_request)
    membership = await org_client.get_membership(user_id, request.organization_id)
    if not membership or not membership.is_active():
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    
    profile = TrustProfile(
        organization_id=request.organization_id,
        name=request.name,
        description=request.description,
        revocation_profile_id=request.revocation_profile_id,
        supported_formats=[CredentialFormat(f) for f in request.supported_formats],
    )
    
    # Set trust sources
    for ts in request.trust_sources:
        profile.trust_sources.append(TrustSource(
            name=ts.name,
            source_type=ts.source_type,
            url=ts.url,
            pinned_certificates=ts.pinned_certificates,
            refresh_interval_hours=ts.refresh_interval_hours,
            enabled=ts.enabled,
        ))
    
    # Set validation rules
    if request.validation_rules:
        profile.validation_rules = ValidationRules(
            allowed_algorithms=request.validation_rules.allowed_algorithms,
            min_key_size_rsa=request.validation_rules.min_key_size_rsa,
            min_key_size_ec=request.validation_rules.min_key_size_ec,
            require_key_usage=request.validation_rules.require_key_usage,
            max_chain_depth=request.validation_rules.max_chain_depth,
            allow_self_signed=request.validation_rules.allow_self_signed,
        )
    
    # Set revocation policy (DEPRECATED - prefer revocation_profile_id)
    if request.revocation_policy:
        profile.revocation_policy = RevocationPolicy(
            check_mode=RevocationCheckMode(request.revocation_policy.check_mode),
            check_ocsp=request.revocation_policy.check_ocsp,
            check_crl=request.revocation_policy.check_crl,
            check_status_list=request.revocation_policy.check_status_list,
            offline_grace_period_hours=request.revocation_policy.offline_grace_period_hours,
            cache_duration_hours=request.revocation_policy.cache_duration_hours,
        )
    
    # Set time policy
    if request.time_policy:
        profile.time_policy = TimePolicy(
            max_clock_skew_seconds=request.time_policy.max_clock_skew_seconds,
            credential_freshness_hours=request.time_policy.credential_freshness_hours,
            require_not_before=request.time_policy.require_not_before,
            require_expiration=request.time_policy.require_expiration,
        )
    
    await repo.save_profile(profile)
    logger.info(f"Created Trust Profile: {profile.id}")
    return _profile_to_response(profile)


@router.get("", response_model=list[TrustProfileResponse])
async def list_trust_profiles(
    organization_id: str = Query(..., description="Organization ID"),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository = Depends(get_repo),
    request: Request = None,
) -> list[TrustProfileResponse]:
    """List Trust Profiles for an organization."""
    # Verify org membership
    await app.state.org_client.get_membership(user_id, organization_id)
    profiles = await repo.list_profiles(organization_id)
    return [_profile_to_response(p) for p in profiles]


@router.get("/{profile_id}", response_model=TrustProfileResponse)
async def get_trust_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository = Depends(get_repo),
) -> TrustProfileResponse:
    """Get a Trust Profile by ID."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify org membership
    await app.state.org_client.get_membership(user_id, profile.organization_id)
    return _profile_to_response(profile)


@router.patch("/{profile_id}", response_model=TrustProfileResponse)
async def update_trust_profile(
    profile_id: str,
    request: UpdateTrustProfileRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository = Depends(get_repo),
) -> TrustProfileResponse:
    """Update a Trust Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if request.name is not None:
        profile.name = request.name
    if request.description is not None:
        profile.description = request.description
    if request.revocation_profile_id is not None:
        profile.revocation_profile_id = request.revocation_profile_id
    if request.supported_formats is not None:
        profile.supported_formats = [CredentialFormat(f) for f in request.supported_formats]
    
    profile.updated_at = datetime.now(timezone.utc)
    await repo.save_profile(profile)
    return _profile_to_response(profile)


@router.post("/{profile_id}/activate", response_model=TrustProfileResponse)
async def activate_trust_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository = Depends(get_repo),
) -> TrustProfileResponse:
    """Activate a Trust Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    profile.activate()
    await repo.save_profile(profile)
    return _profile_to_response(profile)


@router.post("/{profile_id}/suspend", response_model=TrustProfileResponse)
async def suspend_trust_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository = Depends(get_repo),
) -> TrustProfileResponse:
    """Suspend a Trust Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    profile.suspend()
    await repo.save_profile(profile)
    return _profile_to_response(profile)


@router.delete("/{profile_id}")
async def delete_trust_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository = Depends(get_repo),
) -> dict:
    """Delete a Trust Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    await repo.delete_profile(profile_id)
    return {"success": True}


# Trusted Issuer endpoints (sub-resource)
@router.post("/{profile_id}/issuers", response_model=TrustedIssuerResponse)
async def add_trusted_issuer(
    profile_id: str,
    request: CreateTrustedIssuerRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository = Depends(get_repo),
) -> TrustedIssuerResponse:
    """Add a Trusted Issuer to a Trust Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    issuer = TrustedIssuer(
        trust_profile_id=profile_id,
        name=request.name,
        description=request.description,
        issuer_did=request.issuer_did,
        issuer_url=request.issuer_url,
        credential_template_ids=request.credential_template_ids,
        verification_keys=request.verification_keys,
    )
    
    if request.valid_from:
        issuer.valid_from = datetime.fromisoformat(request.valid_from)
    if request.valid_until:
        issuer.valid_until = datetime.fromisoformat(request.valid_until)
    
    await repo.save_issuer(issuer)
    logger.info(f"Added Trusted Issuer: {issuer.id} to profile {profile_id}")
    return _issuer_to_response(issuer)


@router.get("/{profile_id}/issuers", response_model=list[TrustedIssuerResponse])
async def list_trusted_issuers(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository = Depends(get_repo),
) -> list[TrustedIssuerResponse]:
    """List Trusted Issuers for a Trust Profile."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify org membership
    await app.state.org_client.get_membership(user_id, profile.organization_id)
    issuers = await repo.list_issuers(profile_id)
    return [_issuer_to_response(i) for i in issuers]


@router.get("/{profile_id}/issuers/{issuer_id}", response_model=TrustedIssuerResponse)
async def get_trusted_issuer(
    profile_id: str,
    issuer_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository = Depends(get_repo),
) -> TrustedIssuerResponse:
    """Get a Trusted Issuer by ID."""
    issuer = await repo.get_issuer(issuer_id)
    if not issuer or issuer.trust_profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Trusted Issuer not found")
    # Verify org membership via profile
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    await app.state.org_client.get_membership(user_id, profile.organization_id)
    return _issuer_to_response(issuer)


@router.delete("/{profile_id}/issuers/{issuer_id}")
async def remove_trusted_issuer(
    profile_id: str,
    issuer_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository = Depends(get_repo),
) -> dict:
    """Remove a Trusted Issuer from a Trust Profile (requires admin)."""
    issuer = await repo.get_issuer(issuer_id)
    if not issuer or issuer.trust_profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Trusted Issuer not found")
    # Verify admin access
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    await repo.delete_issuer(issuer_id)
    return {"success": True}


# Response builders
def _profile_to_response(profile: TrustProfile) -> TrustProfileResponse:
    return TrustProfileResponse(
        id=profile.id,
        organization_id=profile.organization_id,
        name=profile.name,
        description=profile.description,
        status=profile.status.value,
        trust_sources=[
            {
                "id": ts.id,
                "name": ts.name,
                "source_type": ts.source_type,
                "url": ts.url,
                "enabled": ts.enabled,
            }
            for ts in profile.trust_sources
        ],
        validation_rules={
            "allowed_algorithms": profile.validation_rules.allowed_algorithms,
            "min_key_size_rsa": profile.validation_rules.min_key_size_rsa,
            "min_key_size_ec": profile.validation_rules.min_key_size_ec,
            "require_key_usage": profile.validation_rules.require_key_usage,
            "max_chain_depth": profile.validation_rules.max_chain_depth,
            "allow_self_signed": profile.validation_rules.allow_self_signed,
        },
        revocation_policy={
            "check_mode": profile.revocation_policy.check_mode.value,
            "check_ocsp": profile.revocation_policy.check_ocsp,
            "check_crl": profile.revocation_policy.check_crl,
            "check_status_list": profile.revocation_policy.check_status_list,
            "offline_grace_period_hours": profile.revocation_policy.offline_grace_period_hours,
        },
        revocation_check_enabled=(
            profile.revocation_policy.check_mode != RevocationCheckMode.SKIP
        ),
        revocation_profile_id=profile.revocation_profile_id,
        time_policy={
            "max_clock_skew_seconds": profile.time_policy.max_clock_skew_seconds,
            "credential_freshness_hours": profile.time_policy.credential_freshness_hours,
            "require_not_before": profile.time_policy.require_not_before,
            "require_expiration": profile.time_policy.require_expiration,
        },
        supported_formats=[f.value for f in profile.supported_formats],
        trusted_issuers=[],  # Empty for now, would need async call to fetch
        created_at=profile.created_at.isoformat(),
        updated_at=profile.updated_at.isoformat(),
    )


def _issuer_to_response(issuer: TrustedIssuer) -> TrustedIssuerResponse:
    return TrustedIssuerResponse(
        id=issuer.id,
        trust_profile_id=issuer.trust_profile_id,
        name=issuer.name,
        description=issuer.description,
        issuer_did=issuer.issuer_did,
        issuer_url=issuer.issuer_url,
        status=issuer.status.value,
        credential_template_ids=issuer.credential_template_ids,
        created_at=issuer.created_at.isoformat(),
        updated_at=issuer.updated_at.isoformat(),
    )


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo
    logger.info(f"Starting {SERVICE_NAME}...")
    
    config = get_config()
    
    # Initialize database
    engine = create_async_engine(config["database_url"], echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    
    # Initialize repository
    _repo = PostgresTrustProfileRepository(session_factory)
    
    # Initialize gRPC channel to organization service
    from common.grpc_factory import create_grpc_channel
    org_grpc_target = os.environ.get("ORG_GRPC_TARGET", "organization:9002")
    org_grpc_channel = create_grpc_channel(org_grpc_target, service_name="trust-profile")
    app.state.org_client = OrganizationClient(
        grpc_channel=org_grpc_channel,
    )
    
    yield
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await org_grpc_channel.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Trust Profile Service",
        description="Manages Trust Profiles - who is trusted and how validation happens",
        version="1.0.0",
        lifespan=lifespan,
    )
    
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RequestIdMiddleware)
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

    from common.metrics import init_otel_tracing, mount_metrics
    init_otel_tracing(SERVICE_NAME)
    mount_metrics(app)
    
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
