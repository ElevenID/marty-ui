"""
Deployment Profile Service

Manages Deployment Profiles - runtime configuration for credential operations.

A Deployment Profile defines:
- Environment settings (dev, staging, production)
- Callback URLs (for async flows)
- API authentication settings
- Rate limits and quotas
- Feature flags
- Branding and customization

Port: 8010
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

SERVICE_NAME = "deployment-profile-service"
SERVICE_PORT = int(os.environ.get("DEPLOYMENT_PROFILE_SERVICE_PORT", "8010"))


# =============================================================================
# Domain Layer
# =============================================================================

class ProfileStatus(str, Enum):
    """Deployment profile status."""
    DRAFT = "draft"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class Environment(str, Enum):
    """Deployment environment."""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    SANDBOX = "sandbox"


class AuthMethod(str, Enum):
    """API authentication methods."""
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    MTLS = "mtls"
    JWT = "jwt"


@dataclass
class CallbackConfiguration:
    """
    Callback URL configuration for async operations.
    """
    issuance_complete_url: str | None = None
    issuance_failed_url: str | None = None
    verification_complete_url: str | None = None
    verification_failed_url: str | None = None
    credential_revoked_url: str | None = None
    
    # Callback security
    signing_key_id: str | None = None
    require_signature_verification: bool = True
    
    # Retry settings
    max_retries: int = 3
    retry_delay_seconds: int = 30


@dataclass
class ApiAuthConfiguration:
    """
    API authentication configuration.
    """
    auth_method: AuthMethod = AuthMethod.API_KEY
    
    # For API key auth
    api_key_header: str = "X-API-Key"
    
    # For OAuth2
    oauth2_issuer: str | None = None
    oauth2_audience: str | None = None
    oauth2_scopes: list[str] = field(default_factory=list)
    
    # For mTLS
    mtls_ca_certificate: str | None = None
    
    # For JWT
    jwt_issuer: str | None = None
    jwt_audience: str | None = None


@dataclass
class RateLimitConfiguration:
    """
    Rate limiting configuration.
    """
    enabled: bool = True
    requests_per_minute: int = 100
    requests_per_hour: int = 1000
    requests_per_day: int = 10000
    
    # Burst settings
    burst_size: int = 20
    
    # Per-endpoint limits (optional overrides)
    endpoint_limits: dict[str, int] = field(default_factory=dict)


@dataclass
class FeatureFlags:
    """
    Feature flags for the deployment.
    """
    enable_selective_disclosure: bool = True
    enable_derived_attributes: bool = True
    enable_batch_issuance: bool = False
    enable_deferred_issuance: bool = True
    enable_credential_refresh: bool = True
    enable_qr_code_generation: bool = True
    enable_push_notifications: bool = False
    enable_biometric_binding: bool = False
    custom_flags: dict[str, bool] = field(default_factory=dict)


@dataclass
class BrandingConfiguration:
    """
    Branding and customization settings.
    """
    organization_name: str = ""
    logo_url: str | None = None
    favicon_url: str | None = None
    primary_color: str = "#1a1a2e"
    secondary_color: str = "#4a4a6a"
    custom_css_url: str | None = None
    
    # Email templates
    email_from_name: str = ""
    email_from_address: str | None = None
    
    # Custom domains
    custom_domain: str | None = None
    custom_issuer_domain: str | None = None
    
    # QR Code Customization
    qr_size: int = 256  # Default QR code size in pixels
    qr_foreground_color: str = "#000000"  # QR code foreground (dark squares)
    qr_background_color: str = "#FFFFFF"  # QR code background
    qr_logo_url: str | None = None  # Optional logo to overlay on QR center
    qr_logo_size_percent: int = 20  # Logo size as percentage of QR (0-30)
    qr_border_color: str | None = None  # Optional border color
    qr_border_width: int = 2  # Border width in pixels
    qr_error_correction: str = "H"  # L, M, Q, H (High recommended for logo overlay)
    qr_show_instructions: bool = True  # Show "Scan with Wallet" instructions
    qr_custom_instruction_text: str | None = None  # Custom instruction text


@dataclass
class DeploymentProfile:
    """
    Deployment Profile - runtime configuration.
    
    This defines how credential operations run in a specific environment.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    name: str = ""
    description: str | None = None
    status: ProfileStatus = ProfileStatus.DRAFT
    environment: Environment = Environment.DEVELOPMENT
    
    # Configuration sections
    callbacks: CallbackConfiguration = field(default_factory=CallbackConfiguration)
    api_auth: ApiAuthConfiguration = field(default_factory=ApiAuthConfiguration)
    rate_limits: RateLimitConfiguration = field(default_factory=RateLimitConfiguration)
    feature_flags: FeatureFlags = field(default_factory=FeatureFlags)
    branding: BrandingConfiguration = field(default_factory=BrandingConfiguration)
    
    # Linked configurations (by ID)
    default_trust_profile_id: str | None = None
    default_compliance_profile_id: str | None = None
    
    # API credentials (generated)
    api_key: str | None = None
    api_key_prefix: str = ""  # For display: "mk_live_xxxx"
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def activate(self) -> None:
        self.status = ProfileStatus.ACTIVE
        self.updated_at = datetime.now(timezone.utc)
    
    def suspend(self) -> None:
        self.status = ProfileStatus.SUSPENDED
        self.updated_at = datetime.now(timezone.utc)
    
    def generate_api_key(self) -> str:
        """Generate a new API key."""
        import secrets
        prefix = "mk_live_" if self.environment == Environment.PRODUCTION else "mk_test_"
        key = secrets.token_urlsafe(32)
        self.api_key = f"{prefix}{key}"
        self.api_key_prefix = f"{prefix}{key[:8]}..."
        return self.api_key


# =============================================================================
# Application Layer
# =============================================================================

class InMemoryDeploymentProfileRepository:
    """In-memory repository for development."""
    
    def __init__(self):
        self._profiles: dict[str, DeploymentProfile] = {}
    
    async def save(self, profile: DeploymentProfile) -> None:
        self._profiles[profile.id] = profile
    
    async def get(self, profile_id: str) -> DeploymentProfile | None:
        return self._profiles.get(profile_id)
    
    async def list(self, org_id: str) -> list[DeploymentProfile]:
        return [p for p in self._profiles.values() if p.organization_id == org_id]
    
    async def delete(self, profile_id: str) -> None:
        self._profiles.pop(profile_id, None)


# =============================================================================
# HTTP Adapter - Request/Response Models
# =============================================================================

class CallbackConfigurationModel(BaseModel):
    issuance_complete_url: str | None = None
    issuance_failed_url: str | None = None
    verification_complete_url: str | None = None
    verification_failed_url: str | None = None
    credential_revoked_url: str | None = None
    signing_key_id: str | None = None
    require_signature_verification: bool = True
    max_retries: int = 3
    retry_delay_seconds: int = 30


class ApiAuthConfigurationModel(BaseModel):
    auth_method: str = "api_key"
    api_key_header: str = "X-API-Key"
    oauth2_issuer: str | None = None
    oauth2_audience: str | None = None
    oauth2_scopes: list[str] = []
    jwt_issuer: str | None = None
    jwt_audience: str | None = None


class RateLimitConfigurationModel(BaseModel):
    enabled: bool = True
    requests_per_minute: int = 100
    requests_per_hour: int = 1000
    requests_per_day: int = 10000
    burst_size: int = 20
    endpoint_limits: dict[str, int] = {}


class FeatureFlagsModel(BaseModel):
    enable_selective_disclosure: bool = True
    enable_derived_attributes: bool = True
    enable_batch_issuance: bool = False
    enable_deferred_issuance: bool = True
    enable_credential_refresh: bool = True
    enable_qr_code_generation: bool = True
    enable_push_notifications: bool = False
    enable_biometric_binding: bool = False
    custom_flags: dict[str, bool] = {}


class BrandingConfigurationModel(BaseModel):
    organization_name: str = ""
    logo_url: str | None = None
    favicon_url: str | None = None
    primary_color: str = "#1a1a2e"
    secondary_color: str = "#4a4a6a"
    custom_css_url: str | None = None
    email_from_name: str = ""
    email_from_address: str | None = None
    custom_domain: str | None = None
    
    # QR Code Customization
    qr_size: int = 256
    qr_foreground_color: str = "#000000"
    qr_background_color: str = "#FFFFFF"
    qr_logo_url: str | None = None
    qr_logo_size_percent: int = 20
    qr_border_color: str | None = None
    qr_border_width: int = 2
    qr_error_correction: str = "H"
    qr_show_instructions: bool = True
    qr_custom_instruction_text: str | None = None


class CreateDeploymentProfileRequest(BaseModel):
    organization_id: str
    name: str
    description: str | None = None
    environment: str = "development"
    callbacks: CallbackConfigurationModel | None = None
    api_auth: ApiAuthConfigurationModel | None = None
    rate_limits: RateLimitConfigurationModel | None = None
    feature_flags: FeatureFlagsModel | None = None
    branding: BrandingConfigurationModel | None = None
    default_trust_profile_id: str | None = None
    default_compliance_profile_id: str | None = None


class UpdateDeploymentProfileRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    callbacks: CallbackConfigurationModel | None = None
    api_auth: ApiAuthConfigurationModel | None = None
    rate_limits: RateLimitConfigurationModel | None = None
    feature_flags: FeatureFlagsModel | None = None
    branding: BrandingConfigurationModel | None = None
    default_trust_profile_id: str | None = None
    default_compliance_profile_id: str | None = None


class DeploymentProfileResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    environment: str
    callbacks: dict
    api_auth: dict
    rate_limits: dict
    feature_flags: dict
    branding: dict
    default_trust_profile_id: str | None
    default_compliance_profile_id: str | None
    api_key_prefix: str | None
    created_at: str
    updated_at: str


class ApiKeyResponse(BaseModel):
    api_key: str
    api_key_prefix: str
    environment: str


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/deployment-profiles", tags=["deployment-profiles"])

_repo: InMemoryDeploymentProfileRepository | None = None


def get_repo() -> InMemoryDeploymentProfileRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


@router.post("", response_model=DeploymentProfileResponse)
async def create_deployment_profile(
    request: CreateDeploymentProfileRequest,
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> DeploymentProfileResponse:
    """Create a new Deployment Profile."""
    profile = DeploymentProfile(
        organization_id=request.organization_id,
        name=request.name,
        description=request.description,
        environment=Environment(request.environment),
        default_trust_profile_id=request.default_trust_profile_id,
        default_compliance_profile_id=request.default_compliance_profile_id,
    )
    
    # Set callbacks
    if request.callbacks:
        profile.callbacks = CallbackConfiguration(
            issuance_complete_url=request.callbacks.issuance_complete_url,
            issuance_failed_url=request.callbacks.issuance_failed_url,
            verification_complete_url=request.callbacks.verification_complete_url,
            verification_failed_url=request.callbacks.verification_failed_url,
            credential_revoked_url=request.callbacks.credential_revoked_url,
            signing_key_id=request.callbacks.signing_key_id,
            require_signature_verification=request.callbacks.require_signature_verification,
            max_retries=request.callbacks.max_retries,
            retry_delay_seconds=request.callbacks.retry_delay_seconds,
        )
    
    # Set API auth
    if request.api_auth:
        profile.api_auth = ApiAuthConfiguration(
            auth_method=AuthMethod(request.api_auth.auth_method),
            api_key_header=request.api_auth.api_key_header,
            oauth2_issuer=request.api_auth.oauth2_issuer,
            oauth2_audience=request.api_auth.oauth2_audience,
            oauth2_scopes=request.api_auth.oauth2_scopes,
            jwt_issuer=request.api_auth.jwt_issuer,
            jwt_audience=request.api_auth.jwt_audience,
        )
    
    # Set rate limits
    if request.rate_limits:
        profile.rate_limits = RateLimitConfiguration(
            enabled=request.rate_limits.enabled,
            requests_per_minute=request.rate_limits.requests_per_minute,
            requests_per_hour=request.rate_limits.requests_per_hour,
            requests_per_day=request.rate_limits.requests_per_day,
            burst_size=request.rate_limits.burst_size,
            endpoint_limits=request.rate_limits.endpoint_limits,
        )
    
    # Set feature flags
    if request.feature_flags:
        profile.feature_flags = FeatureFlags(
            enable_selective_disclosure=request.feature_flags.enable_selective_disclosure,
            enable_derived_attributes=request.feature_flags.enable_derived_attributes,
            enable_batch_issuance=request.feature_flags.enable_batch_issuance,
            enable_deferred_issuance=request.feature_flags.enable_deferred_issuance,
            enable_credential_refresh=request.feature_flags.enable_credential_refresh,
            enable_qr_code_generation=request.feature_flags.enable_qr_code_generation,
            enable_push_notifications=request.feature_flags.enable_push_notifications,
            enable_biometric_binding=request.feature_flags.enable_biometric_binding,
            custom_flags=request.feature_flags.custom_flags,
        )
    
    # Set branding
    if request.branding:
        profile.branding = BrandingConfiguration(
            organization_name=request.branding.organization_name,
            logo_url=request.branding.logo_url,
            favicon_url=request.branding.favicon_url,
            primary_color=request.branding.primary_color,
            secondary_color=request.branding.secondary_color,
            custom_css_url=request.branding.custom_css_url,
            email_from_name=request.branding.email_from_name,
            email_from_address=request.branding.email_from_address,
            custom_domain=request.branding.custom_domain,
        )
    
    await repo.save(profile)
    logger.info(f"Created Deployment Profile: {profile.id}")
    return _profile_to_response(profile)


@router.get("", response_model=list[DeploymentProfileResponse])
async def list_deployment_profiles(
    organization_id: str = Query(..., description="Organization ID"),
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> list[DeploymentProfileResponse]:
    """List Deployment Profiles for an organization."""
    profiles = await repo.list(organization_id)
    return [_profile_to_response(p) for p in profiles]


@router.get("/{profile_id}", response_model=DeploymentProfileResponse)
async def get_deployment_profile(
    profile_id: str,
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> DeploymentProfileResponse:
    """Get a Deployment Profile by ID."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    return _profile_to_response(profile)


@router.patch("/{profile_id}", response_model=DeploymentProfileResponse)
async def update_deployment_profile(
    profile_id: str,
    request: UpdateDeploymentProfileRequest,
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> DeploymentProfileResponse:
    """Update a Deployment Profile."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    
    if request.name is not None:
        profile.name = request.name
    if request.description is not None:
        profile.description = request.description
    if request.default_trust_profile_id is not None:
        profile.default_trust_profile_id = request.default_trust_profile_id
    if request.default_compliance_profile_id is not None:
        profile.default_compliance_profile_id = request.default_compliance_profile_id
    
    profile.updated_at = datetime.now(timezone.utc)
    await repo.save(profile)
    return _profile_to_response(profile)


@router.post("/{profile_id}/activate", response_model=DeploymentProfileResponse)
async def activate_deployment_profile(
    profile_id: str,
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> DeploymentProfileResponse:
    """Activate a Deployment Profile."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    profile.activate()
    await repo.save(profile)
    return _profile_to_response(profile)


@router.post("/{profile_id}/suspend", response_model=DeploymentProfileResponse)
async def suspend_deployment_profile(
    profile_id: str,
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> DeploymentProfileResponse:
    """Suspend a Deployment Profile."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    profile.suspend()
    await repo.save(profile)
    return _profile_to_response(profile)


@router.post("/{profile_id}/generate-api-key", response_model=ApiKeyResponse)
async def generate_api_key(
    profile_id: str,
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> ApiKeyResponse:
    """Generate a new API key for the Deployment Profile."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    
    api_key = profile.generate_api_key()
    await repo.save(profile)
    
    return ApiKeyResponse(
        api_key=api_key,
        api_key_prefix=profile.api_key_prefix,
        environment=profile.environment.value,
    )


@router.delete("/{profile_id}")
async def delete_deployment_profile(
    profile_id: str,
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> dict:
    """Delete a Deployment Profile."""
    profile = await repo.get(profile_id)
    if profile and profile.status == ProfileStatus.ACTIVE:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete an active profile. Suspend it first."
        )
    await repo.delete(profile_id)
    return {"success": True}


def _profile_to_response(profile: DeploymentProfile) -> DeploymentProfileResponse:
    return DeploymentProfileResponse(
        id=profile.id,
        organization_id=profile.organization_id,
        name=profile.name,
        description=profile.description,
        status=profile.status.value,
        environment=profile.environment.value,
        callbacks={
            "issuance_complete_url": profile.callbacks.issuance_complete_url,
            "issuance_failed_url": profile.callbacks.issuance_failed_url,
            "verification_complete_url": profile.callbacks.verification_complete_url,
            "verification_failed_url": profile.callbacks.verification_failed_url,
            "max_retries": profile.callbacks.max_retries,
        },
        api_auth={
            "auth_method": profile.api_auth.auth_method.value,
            "api_key_header": profile.api_auth.api_key_header,
        },
        rate_limits={
            "enabled": profile.rate_limits.enabled,
            "requests_per_minute": profile.rate_limits.requests_per_minute,
            "requests_per_hour": profile.rate_limits.requests_per_hour,
            "requests_per_day": profile.rate_limits.requests_per_day,
            "burst_size": profile.rate_limits.burst_size,
        },
        feature_flags={
            "enable_selective_disclosure": profile.feature_flags.enable_selective_disclosure,
            "enable_derived_attributes": profile.feature_flags.enable_derived_attributes,
            "enable_batch_issuance": profile.feature_flags.enable_batch_issuance,
            "enable_deferred_issuance": profile.feature_flags.enable_deferred_issuance,
            "enable_credential_refresh": profile.feature_flags.enable_credential_refresh,
            "enable_qr_code_generation": profile.feature_flags.enable_qr_code_generation,
            "custom_flags": profile.feature_flags.custom_flags,
        },
        branding={
            "organization_name": profile.branding.organization_name,
            "logo_url": profile.branding.logo_url,
            "primary_color": profile.branding.primary_color,
            "secondary_color": profile.branding.secondary_color,
            "custom_domain": profile.branding.custom_domain,
        },
        default_trust_profile_id=profile.default_trust_profile_id,
        default_compliance_profile_id=profile.default_compliance_profile_id,
        api_key_prefix=profile.api_key_prefix if profile.api_key else None,
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
    _repo = InMemoryDeploymentProfileRepository()
    yield
    logger.info(f"Shutting down {SERVICE_NAME}...")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Deployment Profile Service",
        description="Manages Deployment Profiles - runtime configuration",
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
    uvicorn.run("deployment_profile.main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
