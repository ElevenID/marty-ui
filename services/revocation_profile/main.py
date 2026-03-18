"""
RevocationProfile Service

Manages RevocationProfiles - format-agnostic revocation configuration
that hides complexity and enables automation for both issuers and verifiers.

A RevocationProfile contains:
- Issuer configuration (status list strategy, update mode, publishing)
- Verifier configuration (check mode, caching, offline grace)
- Automation settings (auto-allocate, auto-publish, format defaults)

Port: 8013
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
from typing import Annotated

from marty_common import (
    OrganizationClient,
    OrganizationContext,
    require_org_membership,
    RequestIdMiddleware,
    RequestLoggingMiddleware,
)

from .status_list_manager import (
    StatusListManager,
    StatusListFormat,
    create_status_list_repository,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "revocation-profile-service"
SERVICE_PORT = int(os.environ.get("REVOCATION_PROFILE_SERVICE_PORT", "8013"))


# =============================================================================
# Domain Layer
# =============================================================================

class RevocationProfileStatus(str, Enum):
    """RevocationProfile status."""
    DRAFT = "draft"
    ACTIVE = "active"
    SUSPENDED = "suspended"


class RevocationCheckMode(str, Enum):
    """Failure behavior when a revocation check is performed (verifier-side).
    Maps to marty-protocol enum: revocation-check-modes.json
    """
    HARD_FAIL = "HARD_FAIL"  # Reject credential if revocation check fails
    SOFT_FAIL = "SOFT_FAIL"  # Accept with warning if check unavailable
    SKIP = "SKIP"            # Bypass revocation checking entirely


class RevocationTimingMode(str, Enum):
    """When to perform revocation checks.
    Maps to marty-protocol enum: revocation-timing-modes.json
    """
    ALWAYS = "ALWAYS"              # Live check on every verification
    CACHED = "CACHED"              # Accept cached result within TTL
    OFFLINE_GRACE = "OFFLINE_GRACE"  # Accept last-known within grace period
    DISABLED = "DISABLED"          # No revocation check configured


class RevocationMechanism(str, Enum):
    """Revocation check mechanisms.
    Maps to marty-protocol enum: revocation-methods.json
    """
    OCSP = "OCSP"                                       # Online Certificate Status Protocol
    CRL = "CRL"                                         # Certificate Revocation List
    STATUS_LIST_2021 = "STATUS_LIST_2021"                # W3C Status List 2021
    BITSTRING_STATUS_LIST = "BITSTRING_STATUS_LIST"      # IETF Bitstring Status List
    TOKEN_STATUS_LIST = "TOKEN_STATUS_LIST"              # IETF Token Status List


class StatusListStrategy(str, Enum):
    """How status lists are managed (issuer-side)."""
    AUTO = "auto"        # Fully automated (system manages everything)
    MANUAL = "manual"    # Issuer manages indices and publishing
    REGISTRY = "registry"  # Delegate to external registry service


class UpdateMode(str, Enum):
    """How status list updates are processed."""
    SYNC = "sync"            # Update immediately (blocking)
    ASYNC_QUEUE = "async"    # Queue updates, process async
    BATCH = "batch"          # Batch updates at intervals


class CredentialFormat(str, Enum):
    """Supported credential formats.
    Maps to marty-protocol enum: credential-formats.json
    """
    MDOC = "MDOC"
    SD_JWT_VC = "SD_JWT_VC"
    VC_JWT = "VC_JWT"
    JSON_LD = "JSON_LD"
    ZK_MDOC = "ZK_MDOC"


@dataclass
class IssuerRevocationConfig:
    """Configuration for credential issuers."""
    
    # Status list management
    status_list_strategy: StatusListStrategy = StatusListStrategy.AUTO
    status_list_base_url: str | None = None  # Where to publish status lists
    status_list_size: int = 131072  # Default 16KB bitstring
    
    # Update behavior
    update_mode: UpdateMode = UpdateMode.SYNC
    batch_interval_seconds: int = 300  # For BATCH mode
    
    # List rotation
    enable_rotation: bool = True
    rotation_threshold_percent: int = 80  # Rotate at 80% capacity
    
    # Formats to support
    enable_bitstring_status_list: bool = True  # W3C SD-JWT/VC
    enable_token_status_list: bool = True      # IETF mDoc/CWT
    enable_legacy_revocation_list: bool = False  # RevocationList2020


@dataclass
class VerifierRevocationConfig:
    """Configuration for credential verifiers."""
    
    # Check behavior (what to do when check fails)
    check_mode: RevocationCheckMode = RevocationCheckMode.HARD_FAIL
    
    # Timing behavior (when to perform checks)
    timing_mode: RevocationTimingMode = RevocationTimingMode.ALWAYS
    
    # Mechanism priority (try in order)
    mechanism_priority: list[RevocationMechanism] = field(
        default_factory=lambda: [RevocationMechanism.BITSTRING_STATUS_LIST]
    )
    
    # Caching (used when timing_mode=CACHED)
    cache_status_lists: bool = True
    cache_ttl_seconds: int = 3600
    
    # Offline grace (used when timing_mode=OFFLINE_GRACE)
    offline_grace_seconds: int = 86400  # 24 hours
    
    # Timeout/retry
    check_timeout_seconds: int = 5
    max_retries: int = 2
    
    # Trust requirements
    require_issuer_signature_on_status_list: bool = True
    allow_third_party_registries: bool = False


@dataclass
class RevocationAutomationConfig:
    """Automation settings to reduce manual configuration."""
    
    # Auto-allocate indices when issuing credentials
    auto_allocate_indices: bool = True
    
    # Auto-publish status lists after updates
    auto_publish: bool = True
    
    # Auto-generate status list credentials (VC wrapper)
    auto_generate_status_list_credentials: bool = True
    
    # Auto-discover revocation endpoints from credential
    auto_discover_endpoints: bool = True
    
    # Format-specific defaults
    use_format_defaults: bool = True  # Use spec-recommended defaults per format


@dataclass
class RevocationProfile:
    """
    RevocationProfile - format-agnostic revocation configuration.
    
    Hides complexity of OCSP/CRL/StatusList and provides automation
    for both issuers (publishing) and verifiers (checking).
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    name: str = ""
    description: str | None = None
    status: RevocationProfileStatus = RevocationProfileStatus.DRAFT
    
    # Configuration components
    issuer_config: IssuerRevocationConfig = field(default_factory=IssuerRevocationConfig)
    verifier_config: VerifierRevocationConfig = field(default_factory=VerifierRevocationConfig)
    automation_config: RevocationAutomationConfig = field(default_factory=RevocationAutomationConfig)
    
    # Format support (derived from credential formats)
    supported_formats: list[CredentialFormat] = field(
        default_factory=lambda: [
            CredentialFormat.SD_JWT_VC,
            CredentialFormat.MDOC,
            CredentialFormat.VC_JWT,
        ]
    )
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def activate(self) -> None:
        self.status = RevocationProfileStatus.ACTIVE
        self.updated_at = datetime.now(timezone.utc)
    
    def suspend(self) -> None:
        self.status = RevocationProfileStatus.SUSPENDED
        self.updated_at = datetime.now(timezone.utc)


# =============================================================================
# Application Layer
# =============================================================================

class InMemoryRevocationProfileRepository:
    """In-memory repository for development."""
    
    def __init__(self):
        self._profiles: dict[str, RevocationProfile] = {}
        self._status_list_indices: dict[str, int] = {}  # profile_id:format -> next_index
    
    async def save(self, profile: RevocationProfile) -> None:
        self._profiles[profile.id] = profile
    
    async def get(self, profile_id: str) -> RevocationProfile | None:
        return self._profiles.get(profile_id)
    
    async def list(self, org_id: str) -> list[RevocationProfile]:
        return [p for p in self._profiles.values() if p.organization_id == org_id]
    
    async def delete(self, profile_id: str) -> None:
        self._profiles.pop(profile_id, None)
    
    async def allocate_index(self, profile_id: str, credential_format: str) -> int:
        """Allocate next available index in status list."""
        key = f"{profile_id}:{credential_format}"
        current = self._status_list_indices.get(key, 0)
        self._status_list_indices[key] = current + 1
        return current


# =============================================================================
# HTTP Adapter - Request/Response Models
# =============================================================================

class IssuerRevocationConfigModel(BaseModel):
    status_list_strategy: str = "auto"
    status_list_base_url: str | None = None
    status_list_size: int = 131072
    update_mode: str = "sync"
    batch_interval_seconds: int = 300
    enable_rotation: bool = True
    rotation_threshold_percent: int = 80
    enable_bitstring_status_list: bool = True
    enable_token_status_list: bool = True
    enable_legacy_revocation_list: bool = False


class VerifierRevocationConfigModel(BaseModel):
    check_mode: str = "HARD_FAIL"
    timing_mode: str = "ALWAYS"
    mechanism_priority: list[str] = ["BITSTRING_STATUS_LIST"]
    cache_status_lists: bool = True
    cache_ttl_seconds: int = 3600
    offline_grace_seconds: int = 86400
    check_timeout_seconds: int = 5
    max_retries: int = 2
    require_issuer_signature_on_status_list: bool = True
    allow_third_party_registries: bool = False


class RevocationAutomationConfigModel(BaseModel):
    auto_allocate_indices: bool = True
    auto_publish: bool = True
    auto_generate_status_list_credentials: bool = True
    auto_discover_endpoints: bool = True
    use_format_defaults: bool = True


class CreateRevocationProfileRequest(BaseModel):
    organization_id: str
    name: str
    description: str | None = None
    issuer_config: IssuerRevocationConfigModel | None = None
    verifier_config: VerifierRevocationConfigModel | None = None
    automation_config: RevocationAutomationConfigModel | None = None
    supported_formats: list[str] = ["SD_JWT_VC", "MDOC", "VC_JWT"]


class RevocationProfileResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    issuer_config: dict
    verifier_config: dict
    automation_config: dict
    supported_formats: list[str]
    created_at: str
    updated_at: str


class ProcessRevocationRequest(BaseModel):
    """Internal request for processing revocation."""
    credential_id: str
    index: int  # Status list index for this credential
    status: str  # revoked, suspended, reinstated
    reason: str | None = None
    credential_format: str


class ProcessRevocationResponse(BaseModel):
    """Internal response for revocation processing."""
    success: bool
    status_list_url: str | None = None
    index: int | None = None
    error: str | None = None


class AllocateIndexRequest(BaseModel):
    """Request to allocate a status list index."""
    credential_format: str


class AllocateIndexResponse(BaseModel):
    """Response with allocated index."""
    index: int
    status_list_url: str


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/revocation-profiles", tags=["revocation-profiles"])
internal_router = APIRouter(prefix="/internal/revocation-profiles", tags=["internal"])

_repo: InMemoryRevocationProfileRepository | None = None
_status_list_manager: StatusListManager | None = None


def get_repo() -> InMemoryRevocationProfileRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


def get_status_list_manager() -> StatusListManager:
    if _status_list_manager is None:
        raise RuntimeError("StatusListManager not configured")
    return _status_list_manager


def _to_response(profile: RevocationProfile) -> dict:
    """Convert domain model to response dict."""
    return {
        "id": profile.id,
        "organization_id": profile.organization_id,
        "name": profile.name,
        "description": profile.description,
        "status": profile.status.value,
        "issuer_config": {
            "status_list_strategy": profile.issuer_config.status_list_strategy.value,
            "status_list_base_url": profile.issuer_config.status_list_base_url,
            "status_list_size": profile.issuer_config.status_list_size,
            "update_mode": profile.issuer_config.update_mode.value,
            "batch_interval_seconds": profile.issuer_config.batch_interval_seconds,
            "enable_rotation": profile.issuer_config.enable_rotation,
            "rotation_threshold_percent": profile.issuer_config.rotation_threshold_percent,
            "enable_bitstring_status_list": profile.issuer_config.enable_bitstring_status_list,
            "enable_token_status_list": profile.issuer_config.enable_token_status_list,
            "enable_legacy_revocation_list": profile.issuer_config.enable_legacy_revocation_list,
        },
        "verifier_config": {
            "check_mode": profile.verifier_config.check_mode.value,
            "timing_mode": profile.verifier_config.timing_mode.value,
            "mechanism_priority": [m.value for m in profile.verifier_config.mechanism_priority],
            "cache_status_lists": profile.verifier_config.cache_status_lists,
            "cache_ttl_seconds": profile.verifier_config.cache_ttl_seconds,
            "offline_grace_seconds": profile.verifier_config.offline_grace_seconds,
            "check_timeout_seconds": profile.verifier_config.check_timeout_seconds,
            "max_retries": profile.verifier_config.max_retries,
            "require_issuer_signature_on_status_list": profile.verifier_config.require_issuer_signature_on_status_list,
            "allow_third_party_registries": profile.verifier_config.allow_third_party_registries,
        },
        "automation_config": {
            "auto_allocate_indices": profile.automation_config.auto_allocate_indices,
            "auto_publish": profile.automation_config.auto_publish,
            "auto_generate_status_list_credentials": profile.automation_config.auto_generate_status_list_credentials,
            "auto_discover_endpoints": profile.automation_config.auto_discover_endpoints,
            "use_format_defaults": profile.automation_config.use_format_defaults,
        },
        "supported_formats": [f.value for f in profile.supported_formats],
        "created_at": profile.created_at.isoformat(),
        "updated_at": profile.updated_at.isoformat(),
    }


# =============================================================================
# Public API Endpoints (Admin Configuration)
# =============================================================================


async def get_current_user_id(
    x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None
) -> str:
    """Get current user ID from gateway auth middleware."""
    if not x_user_id:
        raise HTTPException(
            status_code=401,
            detail="Authentication required - missing user context",
        )
    return x_user_id


@router.post("", response_model=RevocationProfileResponse)
async def create_revocation_profile(
    request: CreateRevocationProfileRequest,
    http_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
) -> dict:
    """Create a new RevocationProfile."""
    await require_org_membership(request.organization_id, http_request, user_id)
    profile = RevocationProfile(
        organization_id=request.organization_id,
        name=request.name,
        description=request.description,
    )
    
    # Set issuer config if provided
    if request.issuer_config:
        profile.issuer_config = IssuerRevocationConfig(
            status_list_strategy=StatusListStrategy(request.issuer_config.status_list_strategy),
            status_list_base_url=request.issuer_config.status_list_base_url,
            status_list_size=request.issuer_config.status_list_size,
            update_mode=UpdateMode(request.issuer_config.update_mode),
            batch_interval_seconds=request.issuer_config.batch_interval_seconds,
            enable_rotation=request.issuer_config.enable_rotation,
            rotation_threshold_percent=request.issuer_config.rotation_threshold_percent,
            enable_bitstring_status_list=request.issuer_config.enable_bitstring_status_list,
            enable_token_status_list=request.issuer_config.enable_token_status_list,
            enable_legacy_revocation_list=request.issuer_config.enable_legacy_revocation_list,
        )
    
    # Set verifier config if provided
    if request.verifier_config:
        profile.verifier_config = VerifierRevocationConfig(
            check_mode=RevocationCheckMode(request.verifier_config.check_mode),
            timing_mode=RevocationTimingMode(request.verifier_config.timing_mode),
            mechanism_priority=[RevocationMechanism(m) for m in request.verifier_config.mechanism_priority],
            cache_status_lists=request.verifier_config.cache_status_lists,
            cache_ttl_seconds=request.verifier_config.cache_ttl_seconds,
            offline_grace_seconds=request.verifier_config.offline_grace_seconds,
            check_timeout_seconds=request.verifier_config.check_timeout_seconds,
            max_retries=request.verifier_config.max_retries,
            require_issuer_signature_on_status_list=request.verifier_config.require_issuer_signature_on_status_list,
            allow_third_party_registries=request.verifier_config.allow_third_party_registries,
        )
    
    # Set automation config if provided
    if request.automation_config:
        profile.automation_config = RevocationAutomationConfig(
            auto_allocate_indices=request.automation_config.auto_allocate_indices,
            auto_publish=request.automation_config.auto_publish,
            auto_generate_status_list_credentials=request.automation_config.auto_generate_status_list_credentials,
            auto_discover_endpoints=request.automation_config.auto_discover_endpoints,
            use_format_defaults=request.automation_config.use_format_defaults,
        )
    
    # Set supported formats
    profile.supported_formats = [CredentialFormat(f) for f in request.supported_formats]
    
    await repo.save(profile)
    logger.info(f"Created RevocationProfile: {profile.id}")
    
    return _to_response(profile)


@router.get("", response_model=list[RevocationProfileResponse])
async def list_revocation_profiles(
    organization_id: str = Query(...),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
) -> list[dict]:
    """List all RevocationProfiles for an organization."""
    # Verify org membership
    await app.state.org_client.get_membership(user_id, organization_id)
    profiles = await repo.list(organization_id)
    return [_to_response(p) for p in profiles]


@router.get("/{profile_id}", response_model=RevocationProfileResponse)
async def get_revocation_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
) -> dict:
    """Get a RevocationProfile by ID."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="RevocationProfile not found")
    # Verify org membership
    await app.state.org_client.get_membership(user_id, profile.organization_id)
    return _to_response(profile)


@router.post("/{profile_id}/activate", response_model=RevocationProfileResponse)
async def activate_revocation_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
) -> dict:
    """Activate a RevocationProfile (requires admin)."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="RevocationProfile not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    profile.activate()
    await repo.save(profile)
    logger.info(f"Activated RevocationProfile: {profile_id}")
    
    return _to_response(profile)


@router.delete("/{profile_id}")
async def delete_revocation_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
) -> dict:
    """Delete a RevocationProfile (requires admin)."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="RevocationProfile not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    await repo.delete(profile_id)
    logger.info(f"Deleted RevocationProfile: {profile_id}")
    
    return {"success": True}


# =============================================================================
# Internal API Endpoints (Service-to-Service)
# =============================================================================

@internal_router.post("/{profile_id}/process-revocation", response_model=ProcessRevocationResponse)
async def process_revocation(
    profile_id: str,
    request: ProcessRevocationRequest,
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
    status_mgr: StatusListManager = Depends(get_status_list_manager),
) -> dict:
    """
    Internal endpoint: Process a revocation request.
    
    Called by Issuance Service to handle credential lifecycle changes.
    Performs actual status list updates using StatusListManager.
    """
    profile = await repo.get(profile_id)
    if not profile:
        return {
            "success": False,
            "error": f"RevocationProfile {profile_id} not found",
        }
    
    if profile.status != RevocationProfileStatus.ACTIVE:
        return {
            "success": False,
            "error": f"RevocationProfile {profile_id} is not active (status: {profile.status.value})",
        }
    
    logger.info(
        f"Processing revocation for credential {request.credential_id} "
        f"using profile {profile_id} (mode: {profile.issuer_config.update_mode.value})"
    )
    
    try:
        # Map credential format to status list format
        # credential_format is a string like "sd_jwt_vc" or "mdoc"
        if request.credential_format.lower() == "mdoc":
            sl_format = StatusListFormat.TOKEN_STATUS_LIST
        else:
            sl_format = StatusListFormat.BITSTRING
        
        # Set status (1 = revoked, 2 = suspended for TOKEN_STATUS_LIST)
        # For BITSTRING, 1 = revoked/suspended
        if request.status == "revoked":
            status_value = 1
        elif request.status == "suspended":
            status_value = 2 if sl_format == StatusListFormat.TOKEN_STATUS_LIST else 1
        elif request.status == "reinstated":
            status_value = 0
        else:
            return {"success": False, "error": f"Unknown status: {request.status}"}
        
        # Update status list
        success = await status_mgr.set_status(
            tenant_id=profile.organization_id,
            index=request.index,
            status=status_value,
            format=sl_format,
        )
        
        if not success:
            return {"success": False, "error": "Failed to update status list"}
        
        # Publish if auto-publish enabled
        status_list_url = None
        if profile.automation_config.auto_publish:
            status_list_url = await status_mgr.publish(
                tenant_id=profile.organization_id,
                format=sl_format,
            )
        else:
            # Generate URL without publishing
            status_list_url = profile.issuer_config.status_list_base_url or "https://status.example.com"
            status_list_url = f"{status_list_url}/{request.credential_format}/1"
        
        logger.info(
            f"Updated status list: organization={profile.organization_id} "
            f"index={request.index} status={status_value} format={sl_format.value}"
        )
        
        return {
            "success": True,
            "status_list_url": status_list_url,
            "index": request.index,
        }
        
    except Exception as e:
        logger.error(f"Error processing revocation: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
        }


@internal_router.post("/{profile_id}/allocate-index", response_model=AllocateIndexResponse)
async def allocate_index(
    profile_id: str,
    request: AllocateIndexRequest,
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
    status_mgr: StatusListManager = Depends(get_status_list_manager),
) -> dict:
    """
    Internal endpoint: Allocate a status list index.
    
    Called by Issuance Service when issuing a new credential.
    Uses StatusListManager for real index allocation.
    """
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="RevocationProfile not found")
    
    if not profile.automation_config.auto_allocate_indices:
        raise HTTPException(
            status_code=400,
            detail="Auto-allocation not enabled for this profile"
        )
    
    try:
        # Map credential format to status list format
        # credential_format is a string like "sd_jwt_vc" or "mdoc"
        if request.credential_format.lower() == "mdoc":
            sl_format = StatusListFormat.TOKEN_STATUS_LIST
        else:
            sl_format = StatusListFormat.BITSTRING
        
        # Allocate index using StatusListManager
        index = await status_mgr.allocate_index(
            tenant_id=profile.organization_id,
            format=sl_format,
        )
        
        # Generate status list URL
        if profile.automation_config.auto_publish:
            # If auto-publish, use the published URL
            status_list = await status_mgr.get_or_create(
                tenant_id=profile.organization_id,
                format=sl_format,
            )
            status_list_url = status_list.url or f"{profile.issuer_config.status_list_base_url or 'https://status.example.com'}/{request.credential_format}/1"
        else:
            status_list_url = f"{profile.issuer_config.status_list_base_url or 'https://status.example.com'}/{request.credential_format}/1"
        
        logger.info(
            f"Allocated index {index} for format {request.credential_format} "
            f"in profile {profile_id} (organization: {profile.organization_id})"
        )
        
        return {
            "index": index,
            "status_list_url": status_list_url,
        }
        
    except ValueError as e:
        logger.error(f"Index allocation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error during index allocation: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo, _status_list_manager
    logger.info(f"Starting {SERVICE_NAME}...")
    
    # Initialize repositories
    _repo = InMemoryRevocationProfileRepository()
    
    # Initialize status list repository (Redis with fallback to in-memory)
    status_list_repo = create_status_list_repository()
    logger.info("Initialized status list repository")
    
    # Initialize StatusListManager
    base_url = os.environ.get("STATUS_LIST_BASE_URL", "https://status.example.com")
    _status_list_manager = StatusListManager(
        repository=status_list_repo,
        base_url=base_url,
        default_size=131072,  # 16KB bitstring = 131,072 bits
    )
    logger.info(f"Initialized StatusListManager with base URL: {base_url}")
    
    # Initialize gRPC channel to organization service
    from common.grpc_factory import create_grpc_channel, create_grpc_server, start_grpc_server_port
    org_grpc_target = os.environ.get("ORG_GRPC_TARGET", "organization:9002")
    org_grpc_channel = create_grpc_channel(org_grpc_target, service_name="revocation-profile")
    app.state.org_client = OrganizationClient(
        grpc_channel=org_grpc_channel,
    )
    
    # Start gRPC server
    from revocation_profile.infrastructure.adapters.grpc_adapter import (
        RevocationProfileServiceGrpc,
    )
    from marty_proto.v1.revocation_profile_service_pb2_grpc import (
        add_RevocationProfileServiceServicer_to_server,
    )

    grpc_port = int(os.environ.get("RP_GRPC_PORT", "9013"))
    grpc_server, health_servicer = create_grpc_server("revocation-profile")
    rp_servicer = RevocationProfileServiceGrpc(
        repo=_repo,
        status_list_manager=_status_list_manager,
    )
    add_RevocationProfileServiceServicer_to_server(rp_servicer, grpc_server)
    start_grpc_server_port(
        grpc_server, grpc_port,
        service_names=["marty.ui.revocation_profile.v1.RevocationProfileService"],
        health_servicer=health_servicer,
    )
    await grpc_server.start()
    logger.info(f"RevocationProfile gRPC server listening on :{grpc_port}")
    
    # Create default profiles
    default_profile = RevocationProfile(
        organization_id="system",
        name="Auto Revocation (Default)",
        description="Fully automated revocation with sync updates",
        status=RevocationProfileStatus.ACTIVE,
    )
    await _repo.save(default_profile)
    logger.info(f"Created default RevocationProfile: {default_profile.id}")
    
    yield
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await grpc_server.stop(grace=5)
    await org_grpc_channel.close()

def create_app() -> FastAPI:
    app = FastAPI(
        title="RevocationProfile Service",
        description="Format-agnostic revocation configuration and automation",
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
    app.include_router(internal_router)
    
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
    uvicorn.run("revocation_profile.main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
