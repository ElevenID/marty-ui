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

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from marty_common.dto import DeleteResponse
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine, AsyncEngine
from typing import Annotated

from marty_common import (
    OrganizationContext,
    ensure_membership_permission,
)
from marty_common.org_authorization import get_organization_client
from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware
from marty_common.service_setup import create_service_app
from deployment_profile.infrastructure.adapters import (
    PostgresDeploymentProfileRepository,
    PostgresLaneRepository,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "deployment-profile-service"
SERVICE_PORT = int(os.environ.get("DEPLOYMENT_PROFILE_SERVICE_PORT", "8010"))


def get_config() -> dict[str, Any]:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL environment variable is required")
    if not database_url.startswith("postgresql+asyncpg://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return {"database_url": database_url}


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
    enable_canvas_evidence: bool = False
    enable_canvas_lti: bool = False
    enable_canvas_mirror_publish: bool = False
    enable_canvas_mirror_ops: bool = False
    enable_canvas_deep_linking: bool = False
    enable_canvas_ags: bool = False
    enable_canvas_nrps: bool = False
    custom_flags: dict[str, bool] = field(default_factory=dict)


CANVAS_FEATURE_FLAG_KEYS = (
    "enable_canvas_evidence",
    "enable_canvas_lti",
    "enable_canvas_mirror_publish",
    "enable_canvas_mirror_ops",
    "enable_canvas_deep_linking",
    "enable_canvas_ags",
    "enable_canvas_nrps",
)


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
    
    # Linked protocol configurations
    trust_profile_id: str | None = None
    presentation_policy_ids: list[str] = field(default_factory=list)
    credential_template_ids: list[str] = field(default_factory=list)
    default_policy_id: str | None = None

    # Deployment-specific fields
    site_id: str | None = None
    network_mode: str = "ONLINE"
    key_access_mode: str = "KEY_VAULT"
    environment_config: dict[str, Any] = field(default_factory=dict)
    update_channel: str = "stable"
    update_policy: dict[str, Any] = field(default_factory=dict)
    offline_cache_ttl_hours: int = 24
    operator_biometric_authentication_required: bool = False
    audit_all_events: bool = True
    enabled_flow_ids: list[str] = field(default_factory=list)
    
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


@dataclass
class Lane:
    """A logical device grouping within a deployment profile."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    deployment_profile_id: str = ""
    name: str = ""
    description: str | None = None
    location: str | None = None
    device_type: str = "kiosk"
    default_policy_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    device_ids: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def device_count(self) -> int:
        return len(self.device_ids)


class InMemoryLaneRepository:
    """In-memory repository for lanes."""

    def __init__(self):
        self._lanes: dict[str, Lane] = {}

    async def save(self, lane: Lane) -> None:
        self._lanes[lane.id] = lane

    async def get(self, lane_id: str) -> Lane | None:
        return self._lanes.get(lane_id)

    async def list(self, profile_id: str) -> list[Lane]:
        return [l for l in self._lanes.values() if l.deployment_profile_id == profile_id]

    async def delete(self, lane_id: str) -> None:
        self._lanes.pop(lane_id, None)


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
    oauth2_scopes: list[str] = Field(default_factory=list)
    jwt_issuer: str | None = None
    jwt_audience: str | None = None


class RateLimitConfigurationModel(BaseModel):
    enabled: bool = True
    requests_per_minute: int = 100
    requests_per_hour: int = 1000
    requests_per_day: int = 10000
    burst_size: int = 20
    endpoint_limits: dict[str, int] = Field(default_factory=dict)


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

    organization_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    status: str | None = None
    activate_immediately: bool | None = None
    environment: str = "development"
    trust_profile_id: str | None = None
    presentation_policy_ids: list[str] = Field(default_factory=list)
    credential_template_ids: list[str] = Field(default_factory=list)
    default_policy_id: str | None = None
    site_id: str | None = None
    network_mode: str = "ONLINE"
    key_access_mode: str = "KEY_VAULT"
    environment_config: dict[str, Any] | None = None
    enabled_flow_ids: list[str] = Field(default_factory=list)
    update_channel: str = "stable"
    update_policy: dict | None = None
    offline_cache_ttl_hours: int = 24
    operator_biometric_authentication_required: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "operator_biometric_authentication_required",
            "biometric_required",
        ),
    )
    audit_all_events: bool = True
    callbacks: CallbackConfigurationModel | None = None
    api_auth: ApiAuthConfigurationModel | None = None
    rate_limits: RateLimitConfigurationModel | None = None
    feature_flags: FeatureFlagsModel | None = None
    branding: BrandingConfigurationModel | None = None


class UpdateDeploymentProfileRequest(BaseModel):
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

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
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
    audit_all_events: bool | None = None
    offline_cache_ttl_hours: int | None = None
    environment_config: dict[str, Any] | None = None
    enabled_flow_ids: list[str] | None = None
    update_channel: str | None = None
    update_policy: dict[str, Any] | None = None
    callbacks: CallbackConfigurationModel | None = None
    api_auth: ApiAuthConfigurationModel | None = None
    rate_limits: RateLimitConfigurationModel | None = None
    feature_flags: FeatureFlagsModel | None = None
    branding: BrandingConfigurationModel | None = None


class DeploymentProfileResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None = None
    status: str | None = None
    site_id: str | None = None
    trust_profile_id: str | None = None
    presentation_policy_ids: list[str] = Field(default_factory=list)
    credential_template_ids: list[str] = Field(default_factory=list)
    default_policy_id: str | None = None
    network_mode: str = "ONLINE"
    key_access_mode: str = "KEY_VAULT"
    environment_config: dict[str, Any] = Field(default_factory=dict)
    enabled_flow_ids: list[str] = Field(default_factory=list)
    update_channel: str = "stable"
    update_policy: dict[str, Any] = Field(default_factory=dict)
    offline_cache_ttl_hours: int = 24
    operator_biometric_authentication_required: bool = False
    audit_all_events: bool = True
    canvas_feature_flags: dict[str, bool] = Field(default_factory=dict)
    lanes: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str
    updated_at: str


class ApiKeyResponse(BaseModel):
    api_key: str
    api_key_prefix: str
    environment: str


class CreateLaneRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    location: str | None = None
    device_type: str = "kiosk"
    default_policy_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class UpdateLaneRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    location: str | None = None
    device_type: str | None = None
    default_policy_id: str | None = None
    metadata: dict[str, Any] | None = None


class LaneResponse(BaseModel):
    id: str
    name: str
    deployment_profile_id: str
    description: str | None = None
    location: str | None = None
    device_type: str | None = None
    default_policy_id: str | None = None
    device_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssignDeviceRequest(BaseModel):
    device_id: str
    device_name: str | None = None


NETWORK_MODE_ALIASES = {
    "online": "ONLINE",
    "offline": "OFFLINE",
    "hybrid": "HYBRID",
}

KEY_ACCESS_MODE_ALIASES = {
    "key_vault": "KEY_VAULT",
    "hsm": "HSM",
    "device_keystore": "DEVICE_KEYSTORE",
}


def _normalize_network_mode(value: str) -> str:
    return NETWORK_MODE_ALIASES.get(value.lower(), value.upper())


def _normalize_key_access_mode(value: str) -> str:
    return KEY_ACCESS_MODE_ALIASES.get(value.lower(), value.upper())


def _parse_profile_status(value: str) -> ProfileStatus:
    try:
        return ProfileStatus(value.strip().lower())
    except Exception:
        raise HTTPException(status_code=422, detail=f"Unsupported deployment profile status: {value}")


def _resolve_requested_status(status: str | None, activate_immediately: bool | None) -> ProfileStatus:
    if status:
        return _parse_profile_status(status)
    if activate_immediately is True:
        return ProfileStatus.ACTIVE
    return ProfileStatus.DRAFT


def _normalize_presentation_policy_ids(
    presentation_policy_ids: list[str] | None,
    default_policy_id: str | None,
) -> list[str]:
    policy_ids = list(dict.fromkeys(presentation_policy_ids or []))
    if not policy_ids and default_policy_id:
        policy_ids = [default_policy_id]
    return policy_ids


def _build_environment_config(
    environment_config: dict[str, Any] | None,
    offline_cache_ttl_hours: int | None,
) -> dict[str, Any]:
    merged: dict[str, Any] = {
        "language": "en-US",
        "signage_text": {},
        "operator_mode": False,
        "accessibility_mode": False,
    }
    if environment_config:
        merged.update({k: v for k, v in environment_config.items() if v is not None})
    if offline_cache_ttl_hours is not None and "offline_cache_ttl_seconds" not in merged:
        merged["offline_cache_ttl_seconds"] = offline_cache_ttl_hours * 3600
    return merged

def _sync_update_policy(
    update_channel: str,
    update_policy: dict[str, Any] | None,
) -> dict[str, Any]:
    policy = dict(update_policy or {})
    policy.setdefault("auto_update", True)
    policy["channel"] = update_channel
    return policy


def _feature_flags_from_model(model: FeatureFlagsModel) -> FeatureFlags:
    return FeatureFlags(
        enable_selective_disclosure=model.enable_selective_disclosure,
        enable_derived_attributes=model.enable_derived_attributes,
        enable_batch_issuance=model.enable_batch_issuance,
        enable_deferred_issuance=model.enable_deferred_issuance,
        enable_credential_refresh=model.enable_credential_refresh,
        enable_qr_code_generation=model.enable_qr_code_generation,
        enable_push_notifications=model.enable_push_notifications,
        enable_biometric_binding=model.enable_biometric_binding,
        enable_canvas_evidence=model.enable_canvas_evidence,
        enable_canvas_lti=model.enable_canvas_lti,
        enable_canvas_mirror_publish=model.enable_canvas_mirror_publish,
        enable_canvas_mirror_ops=model.enable_canvas_mirror_ops,
        enable_canvas_deep_linking=model.enable_canvas_deep_linking,
        enable_canvas_ags=model.enable_canvas_ags,
        enable_canvas_nrps=model.enable_canvas_nrps,
        custom_flags=model.custom_flags,
    )


def _canvas_feature_flags(flags: FeatureFlags) -> dict[str, bool]:
    return {key: bool(getattr(flags, key, False)) for key in CANVAS_FEATURE_FLAG_KEYS}


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/deployment-profiles", tags=["deployment-profiles"])

_repo: InMemoryDeploymentProfileRepository | PostgresDeploymentProfileRepository | None = None
_db_engine: AsyncEngine | None = None


def get_repo() -> InMemoryDeploymentProfileRepository | PostgresDeploymentProfileRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


def get_current_user_id(x_user_id: Annotated[str, Header()]) -> str:
    """Extract user ID from X-User-Id header (injected by gateway)."""
    return x_user_id


@router.post("", response_model=DeploymentProfileResponse, response_model_exclude_none=True)
async def create_deployment_profile(
    request: CreateDeploymentProfileRequest,
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> DeploymentProfileResponse:
    """Create a new Deployment Profile."""
    org_client = await get_organization_client(fastapi_request)
    membership = await org_client.get_membership(user_id, request.organization_id)
    ensure_membership_permission(membership, "deployment-profile", "create")
    
    trust_profile_id = request.trust_profile_id
    default_policy_id = request.default_policy_id
    presentation_policy_ids = _normalize_presentation_policy_ids(
        request.presentation_policy_ids,
        default_policy_id,
    )
    if not trust_profile_id:
        raise HTTPException(status_code=422, detail="trust_profile_id is required")
    if not presentation_policy_ids:
        raise HTTPException(status_code=422, detail="presentation_policy_ids must contain at least one policy")
    if default_policy_id and default_policy_id not in presentation_policy_ids:
        raise HTTPException(status_code=422, detail="default_policy_id must be included in presentation_policy_ids")

    environment_config = _build_environment_config(
        request.environment_config,
        request.offline_cache_ttl_hours,
    )

    profile = DeploymentProfile(
        organization_id=request.organization_id,
        name=request.name,
        description=request.description,
        status=_resolve_requested_status(request.status, request.activate_immediately),
        environment=Environment(request.environment),
        trust_profile_id=trust_profile_id,
        presentation_policy_ids=presentation_policy_ids,
        credential_template_ids=request.credential_template_ids,
        default_policy_id=default_policy_id,
        site_id=request.site_id,
        network_mode=_normalize_network_mode(request.network_mode),
        key_access_mode=_normalize_key_access_mode(request.key_access_mode),
        environment_config=environment_config,
        update_channel=request.update_channel,
        update_policy=_sync_update_policy(request.update_channel, request.update_policy),
        offline_cache_ttl_hours=request.offline_cache_ttl_hours,
        operator_biometric_authentication_required=request.operator_biometric_authentication_required,
        audit_all_events=request.audit_all_events,
        enabled_flow_ids=request.enabled_flow_ids,
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
        profile.feature_flags = _feature_flags_from_model(request.feature_flags)
    
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
    return _profile_to_response(profile, [])


@router.get("", response_model=list[DeploymentProfileResponse], response_model_exclude_none=True)
async def list_deployment_profiles(
    organization_id: str = Query(..., description="Organization ID"),
    limit: int = Query(default=100, le=500, description="Max items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> list[DeploymentProfileResponse]:
    """List Deployment Profiles for an organization."""
    membership = await app.state.org_client.get_membership(user_id, organization_id)
    ensure_membership_permission(membership, "deployment-profile", "view")
    profiles = await repo.list(organization_id)
    profiles = profiles[offset:offset + limit]
    lane_repo = get_lane_repo()
    return [_profile_to_response(p, await lane_repo.list(p.id)) for p in profiles]


@router.get("/{profile_id}", response_model=DeploymentProfileResponse, response_model_exclude_none=True)
async def get_deployment_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> DeploymentProfileResponse:
    """Get a Deployment Profile by ID."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    ensure_membership_permission(membership, "deployment-profile", "view")
    lane_repo = get_lane_repo()
    return _profile_to_response(profile, await lane_repo.list(profile.id))


@router.patch("/{profile_id}", response_model=DeploymentProfileResponse, response_model_exclude_none=True)
async def update_deployment_profile(
    profile_id: str,
    request: UpdateDeploymentProfileRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> DeploymentProfileResponse:
    """Update a Deployment Profile (requires admin)."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    ensure_membership_permission(membership, "deployment-profile", "edit")
    
    if request.name is not None:
        profile.name = request.name
    if request.description is not None:
        profile.description = request.description
    if request.status is not None:
        profile.status = _parse_profile_status(request.status)
    if request.trust_profile_id is not None:
        profile.trust_profile_id = request.trust_profile_id
    if request.presentation_policy_ids is not None:
        profile.presentation_policy_ids = list(dict.fromkeys(request.presentation_policy_ids))
    if request.credential_template_ids is not None:
        profile.credential_template_ids = list(dict.fromkeys(request.credential_template_ids))
    if request.default_policy_id is not None:
        profile.default_policy_id = request.default_policy_id
    if request.network_mode is not None:
        profile.network_mode = _normalize_network_mode(request.network_mode)
    if request.key_access_mode is not None:
        profile.key_access_mode = _normalize_key_access_mode(request.key_access_mode)
    if request.operator_biometric_authentication_required is not None:
        profile.operator_biometric_authentication_required = request.operator_biometric_authentication_required
    if request.audit_all_events is not None:
        profile.audit_all_events = request.audit_all_events
    if request.offline_cache_ttl_hours is not None:
        profile.offline_cache_ttl_hours = request.offline_cache_ttl_hours
        profile.environment_config = _build_environment_config(
            profile.environment_config,
            profile.offline_cache_ttl_hours,
        )
    if request.environment_config is not None:
        profile.environment_config = _build_environment_config(
            request.environment_config,
            request.offline_cache_ttl_hours if request.offline_cache_ttl_hours is not None else profile.offline_cache_ttl_hours,
        )
    if request.enabled_flow_ids is not None:
        profile.enabled_flow_ids = list(dict.fromkeys(request.enabled_flow_ids))
    if request.update_channel is not None:
        profile.update_channel = request.update_channel
    if request.update_policy is not None:
        profile.update_policy = _sync_update_policy(profile.update_channel, request.update_policy)
    elif request.update_channel is not None:
        profile.update_policy = _sync_update_policy(profile.update_channel, profile.update_policy)
    if request.feature_flags is not None:
        profile.feature_flags = _feature_flags_from_model(request.feature_flags)

    if not profile.trust_profile_id:
        raise HTTPException(status_code=422, detail="trust_profile_id is required")
    if not profile.presentation_policy_ids:
        raise HTTPException(status_code=422, detail="presentation_policy_ids must contain at least one policy")
    if profile.default_policy_id and profile.default_policy_id not in profile.presentation_policy_ids:
        raise HTTPException(status_code=422, detail="default_policy_id must be included in presentation_policy_ids")
    
    profile.updated_at = datetime.now(timezone.utc)
    await repo.save(profile)
    lane_repo = get_lane_repo()
    return _profile_to_response(profile, await lane_repo.list(profile.id))


@router.post("/{profile_id}/activate", response_model=DeploymentProfileResponse, response_model_exclude_none=True)
async def activate_deployment_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> DeploymentProfileResponse:
    """Activate a Deployment Profile (requires admin)."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    ensure_membership_permission(membership, "deployment-profile", "activate")
    profile.activate()
    await repo.save(profile)
    lane_repo = get_lane_repo()
    return _profile_to_response(profile, await lane_repo.list(profile.id))


@router.post("/{profile_id}/suspend", response_model=DeploymentProfileResponse, response_model_exclude_none=True)
async def suspend_deployment_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> DeploymentProfileResponse:
    """Suspend a Deployment Profile (requires admin)."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    ensure_membership_permission(membership, "deployment-profile", "suspend")
    profile.suspend()
    await repo.save(profile)
    lane_repo = get_lane_repo()
    return _profile_to_response(profile, await lane_repo.list(profile.id))


@router.post("/{profile_id}/generate-api-key", response_model=ApiKeyResponse, response_model_exclude_none=True)
async def generate_api_key(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> ApiKeyResponse:
    """Generate a new API key for the Deployment Profile (requires admin)."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    ensure_membership_permission(membership, "api-key", "create")
    
    api_key = profile.generate_api_key()
    await repo.save(profile)
    
    return ApiKeyResponse(
        api_key=api_key,
        api_key_prefix=profile.api_key_prefix,
        environment=profile.environment.value,
    )


@router.delete("/{profile_id}", response_model=DeleteResponse)
async def delete_deployment_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
) -> DeleteResponse:
    """Delete a Deployment Profile (requires admin)."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    ensure_membership_permission(membership, "deployment-profile", "delete")
    
    if profile.status == ProfileStatus.ACTIVE:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete an active profile. Suspend it first."
        )

    # Cascade check: reject if profile still has lanes
    lane_repo = get_lane_repo()
    lanes = await lane_repo.list(profile_id)
    if lanes:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete profile with {len(lanes)} lane(s). Remove all lanes first."
        )

    await repo.delete(profile_id)
    return DeleteResponse()


def _profile_to_response(profile: DeploymentProfile, lanes: list[Lane] | None = None) -> DeploymentProfileResponse:
    return DeploymentProfileResponse(
        id=profile.id,
        organization_id=profile.organization_id,
        name=profile.name,
        description=profile.description,
        status=profile.status.value if hasattr(profile.status, "value") else str(profile.status),
        site_id=profile.site_id,
        trust_profile_id=profile.trust_profile_id,
        presentation_policy_ids=profile.presentation_policy_ids,
        credential_template_ids=profile.credential_template_ids,
        default_policy_id=profile.default_policy_id,
        network_mode=profile.network_mode,
        key_access_mode=profile.key_access_mode,
        environment_config=profile.environment_config,
        enabled_flow_ids=profile.enabled_flow_ids,
        update_channel=profile.update_channel,
        update_policy=profile.update_policy,
        offline_cache_ttl_hours=profile.offline_cache_ttl_hours,
        operator_biometric_authentication_required=profile.operator_biometric_authentication_required,
        audit_all_events=profile.audit_all_events,
        canvas_feature_flags=_canvas_feature_flags(profile.feature_flags),
        lanes=[_lane_to_response(lane).model_dump(exclude_none=True) for lane in (lanes or [])],
        created_at=profile.created_at.isoformat(),
        updated_at=profile.updated_at.isoformat(),
    )


def _lane_to_response(lane: Lane) -> LaneResponse:
    return LaneResponse(
        id=lane.id,
        name=lane.name,
        deployment_profile_id=lane.deployment_profile_id,
        description=lane.description,
        location=lane.location,
        device_type=lane.device_type if lane.device_type != "kiosk" else None,
        default_policy_id=lane.default_policy_id,
        device_ids=lane.device_ids,
        metadata=lane.metadata,
    )


# =============================================================================
# Lane Endpoints
# =============================================================================

_lane_repo: InMemoryLaneRepository | PostgresLaneRepository | None = None


def get_lane_repo() -> InMemoryLaneRepository | PostgresLaneRepository:
    if _lane_repo is None:
        raise RuntimeError("Service not configured")
    return _lane_repo


@router.post("/{profile_id}/lanes", response_model=LaneResponse, response_model_exclude_none=True)
async def create_lane(
    profile_id: str,
    request: CreateLaneRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
    lane_repo: InMemoryLaneRepository = Depends(get_lane_repo),
) -> LaneResponse:
    """Create a Lane within a Deployment Profile."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    ensure_membership_permission(membership, "deployment-profile", "edit")
    lane = Lane(
        deployment_profile_id=profile_id,
        name=request.name,
        description=request.description,
        location=request.location,
        device_type=request.device_type,
        default_policy_id=request.default_policy_id,
        metadata=request.metadata,
    )
    await lane_repo.save(lane)
    return _lane_to_response(lane)


@router.get("/{profile_id}/lanes", response_model=list[LaneResponse], response_model_exclude_none=True)
async def list_lanes(
    profile_id: str,
    limit: int = Query(default=100, le=500, description="Max items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
    lane_repo: InMemoryLaneRepository = Depends(get_lane_repo),
) -> list[LaneResponse]:
    """List Lanes for a Deployment Profile."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    ensure_membership_permission(membership, "deployment-profile", "view")
    lanes = await lane_repo.list(profile_id)
    return [_lane_to_response(l) for l in lanes[offset:offset + limit]]


@router.get("/{profile_id}/lanes/{lane_id}", response_model=LaneResponse, response_model_exclude_none=True)
async def get_lane(
    profile_id: str,
    lane_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
    lane_repo: InMemoryLaneRepository = Depends(get_lane_repo),
) -> LaneResponse:
    """Get a Lane by ID."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    ensure_membership_permission(membership, "deployment-profile", "view")
    lane = await lane_repo.get(lane_id)
    if not lane or lane.deployment_profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Lane not found")
    return _lane_to_response(lane)


@router.put("/{profile_id}/lanes/{lane_id}", response_model=LaneResponse, response_model_exclude_none=True)
async def update_lane(
    profile_id: str,
    lane_id: str,
    request: UpdateLaneRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
    lane_repo: InMemoryLaneRepository = Depends(get_lane_repo),
) -> LaneResponse:
    """Update a Lane."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    ensure_membership_permission(membership, "deployment-profile", "edit")
    lane = await lane_repo.get(lane_id)
    if not lane or lane.deployment_profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Lane not found")
    if request.name is not None:
        lane.name = request.name
    if request.description is not None:
        lane.description = request.description
    if request.location is not None:
        lane.location = request.location
    if request.device_type is not None:
        lane.device_type = request.device_type
    if request.default_policy_id is not None:
        lane.default_policy_id = request.default_policy_id
    if request.metadata is not None:
        lane.metadata = request.metadata
    lane.updated_at = datetime.now(timezone.utc)
    await lane_repo.save(lane)
    return _lane_to_response(lane)


@router.delete("/{profile_id}/lanes/{lane_id}", response_model=DeleteResponse)
async def delete_lane(
    profile_id: str,
    lane_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
    lane_repo: InMemoryLaneRepository = Depends(get_lane_repo),
) -> DeleteResponse:
    """Delete a Lane."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    ensure_membership_permission(membership, "deployment-profile", "edit")
    lane = await lane_repo.get(lane_id)
    if not lane or lane.deployment_profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Lane not found")

    # Cascade check: reject if devices are assigned to the lane
    if hasattr(lane, "assigned_devices") and lane.assigned_devices:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete lane with {len(lane.assigned_devices)} assigned device(s). Unassign devices first."
        )

    await lane_repo.delete(lane_id)
    return DeleteResponse()


@router.post("/{profile_id}/lanes/{lane_id}/devices")
async def assign_device_to_lane(
    profile_id: str,
    lane_id: str,
    request: AssignDeviceRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryDeploymentProfileRepository = Depends(get_repo),
    lane_repo: InMemoryLaneRepository = Depends(get_lane_repo),
) -> dict:
    """Assign a device to a Lane."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Deployment Profile not found")
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    ensure_membership_permission(membership, "deployment-profile", "edit")
    lane = await lane_repo.get(lane_id)
    if not lane or lane.deployment_profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Lane not found")
    # MIP §8 — device_ids MUST be unique across ALL lanes in the profile
    all_lanes = await lane_repo.list(profile_id)
    for other_lane in all_lanes:
        if other_lane.id != lane_id and request.device_id in other_lane.device_ids:
            raise HTTPException(
                status_code=409,
                detail=f"Device {request.device_id} is already assigned to lane {other_lane.id}",
            )
    if request.device_id not in lane.device_ids:
        lane.device_ids.append(request.device_id)
    lane.updated_at = datetime.now(timezone.utc)
    await lane_repo.save(lane)
    return _lane_to_response(lane).model_dump()


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo, _lane_repo, _db_engine
    logger.info(f"Starting {SERVICE_NAME}...")
    config = get_config()
    _db_engine = create_async_engine(
        config["database_url"],
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        echo=False,
    )
    session_factory = async_sessionmaker(_db_engine, expire_on_commit=False)
    _repo = PostgresDeploymentProfileRepository(session_factory)
    _lane_repo = PostgresLaneRepository(session_factory)
    logger.info("PostgreSQL adapter initialized for deployment profile service")
    
    # Initialize gRPC channel to organization service
    from common.di import setup_org_client, teardown_org_client
    await setup_org_client(app, "deployment-profile")
    
    yield
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await teardown_org_client(app)
    if _db_engine is not None:
        await _db_engine.dispose()


def create_app() -> FastAPI:
    app = create_service_app(
        title="Deployment Profile Service",
        description="Manages Deployment Profiles - runtime configuration",
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[router],
    )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        logger.warning("Validation error on %s %s: %s", request.method, request.url.path, exc.errors())
        return JSONResponse(status_code=400, content={"detail": exc.errors()})

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
