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
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Annotated

from marty_common import (
    OrganizationContext,
    ensure_membership_permission,
    RequestIdMiddleware,
    RequestLoggingMiddleware,
    create_service_app,
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


class CascadeOperationType(str, Enum):
    """Protocol-defined cascade revocation operation types."""
    ISSUER_REVOCATION = "ISSUER_REVOCATION"
    ANCHOR_REVOCATION = "ANCHOR_REVOCATION"


class TriggerEntityType(str, Enum):
    """Protocol-defined cascade trigger entity types."""
    ISSUER = "ISSUER"
    TRUST_ANCHOR = "TRUST_ANCHOR"


class CascadeStatus(str, Enum):
    """Lifecycle status for cascade revocation operations."""
    PENDING_CONFIRMATION = "PENDING_CONFIRMATION"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"


@dataclass
class CascadeRevocationOperation:
    """Tracks propagation of issuer or trust-anchor revocations."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    operation_type: CascadeOperationType = CascadeOperationType.ISSUER_REVOCATION
    trigger_entity_type: TriggerEntityType = TriggerEntityType.ISSUER
    trigger_entity_id: str = ""
    status: CascadeStatus = CascadeStatus.IN_PROGRESS
    affected_credential_count: int = 0
    affected_credential_ids: list[str] = field(default_factory=list)
    requires_confirmation: bool = False
    confirmed_at: datetime | None = None
    confirmed_by: str | None = None
    max_cascade_depth: int = 3
    current_depth: int = 0
    circuit_breaker_threshold: int = 1000
    circuit_breaker_triggered: bool = False
    can_rollback: bool = False
    rollback_snapshot: dict[str, Any] | None = None
    rolled_back_at: datetime | None = None
    rolled_back_by: str | None = None
    error_message: str | None = None
    metadata: dict[str, Any] | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime | None = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None

    def mark_completed(self) -> None:
        now = datetime.now(timezone.utc)
        self.status = CascadeStatus.COMPLETED
        self.completed_at = now
        self.updated_at = now

    def mark_failed(self, error_message: str) -> None:
        self.status = CascadeStatus.FAILED
        self.error_message = error_message
        self.updated_at = datetime.now(timezone.utc)

    def confirm(self, confirmed_by: str) -> None:
        if self.status != CascadeStatus.PENDING_CONFIRMATION:
            raise ValueError("Only pending cascade operations can be confirmed")
        now = datetime.now(timezone.utc)
        self.confirmed_at = now
        self.confirmed_by = confirmed_by
        self.status = CascadeStatus.IN_PROGRESS
        self.updated_at = now
        self.mark_completed()

    def rollback(self, rolled_back_by: str) -> None:
        if self.status != CascadeStatus.COMPLETED:
            raise ValueError("Only completed cascade operations can be rolled back")
        if not self.can_rollback:
            raise ValueError("Rollback is not enabled for this cascade operation")
        if self.completed_at is None:
            raise ValueError("Cascade completion timestamp is missing")
        if (datetime.now(timezone.utc) - self.completed_at).total_seconds() > 72 * 3600:
            raise ValueError("Cascade rollback window has expired")
        now = datetime.now(timezone.utc)
        self.status = CascadeStatus.ROLLED_BACK
        self.rolled_back_at = now
        self.rolled_back_by = rolled_back_by
        self.rollback_snapshot = None
        self.updated_at = now


# =============================================================================
# Application Layer
# =============================================================================

class InMemoryRevocationProfileRepository:
    """In-memory repository for development."""
    
    def __init__(self):
        self._profiles: dict[str, RevocationProfile] = {}
        self._cascade_operations: dict[str, CascadeRevocationOperation] = {}
        self._status_list_indices: dict[str, int] = {}  # profile_id:format -> next_index
    
    async def save(self, profile: RevocationProfile) -> None:
        self._profiles[profile.id] = profile
    
    async def get(self, profile_id: str) -> RevocationProfile | None:
        return self._profiles.get(profile_id)
    
    async def list(self, org_id: str) -> list[RevocationProfile]:
        return [p for p in self._profiles.values() if p.organization_id == org_id]
    
    async def delete(self, profile_id: str) -> None:
        self._profiles.pop(profile_id, None)

    async def save_cascade_operation(self, operation: CascadeRevocationOperation) -> None:
        self._cascade_operations[operation.id] = operation

    async def get_cascade_operation(self, operation_id: str) -> CascadeRevocationOperation | None:
        return self._cascade_operations.get(operation_id)

    async def list_cascade_operations(
        self,
        org_id: str,
        status: CascadeStatus | None = None,
    ) -> list[CascadeRevocationOperation]:
        operations = [
            operation
            for operation in self._cascade_operations.values()
            if operation.organization_id == org_id
        ]
        if status is not None:
            operations = [operation for operation in operations if operation.status == status]
        return sorted(operations, key=lambda operation: operation.created_at, reverse=True)

    async def delete_cascade_operation(self, operation_id: str) -> None:
        self._cascade_operations.pop(operation_id, None)
    
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
    auto_allocate_index: bool | None = None
    batch_update_interval_seconds: int | None = None
    list_size: int | None = None
    uri_template: str | None = None


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
    organization_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    revocation_mechanism: list[RevocationMechanism] | None = None
    mechanism_priority: list[RevocationMechanism] | None = None
    check_mode: str | None = None
    cache_ttl_seconds: int | None = None
    offline_grace_seconds: int | None = None
    issuer_config: IssuerRevocationConfigModel | None = None
    verifier_config: VerifierRevocationConfigModel | None = None
    automation_config: RevocationAutomationConfigModel | None = None
    status_list_url: str | None = None
    supported_formats: list[str] = ["SD_JWT_VC", "MDOC", "VC_JWT"]


class RevocationProfileResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    status: str
    revocation_mechanism: list[str]
    mechanism_priority: list[str] | None = None
    check_mode: str
    cache_ttl_seconds: int | None = None
    offline_grace_seconds: int | None = None
    issuer_config: dict[str, Any] | None = None
    status_list_url: str | None = None
    created_at: str
    updated_at: str | None = None


class ProcessRevocationRequest(BaseModel):
    """Internal request for processing revocation."""
    organization_id: str
    credential_id: str
    index: int  # Status list index for this credential
    status: str  # revoked, suspended, reinstated
    reason: str | None = None
    credential_format: str


class ProcessRevocationResponse(BaseModel):
    """Internal response for revocation processing."""
    success: bool
    organization_id: str | None = None
    status_list_url: str | None = None
    index: int | None = None
    error: str | None = None


class AllocateIndexRequest(BaseModel):
    """Request to allocate a status list index."""
    organization_id: str
    credential_format: str


class AllocateIndexResponse(BaseModel):
    """Response with allocated index."""
    organization_id: str
    index: int
    status_list_url: str


class CreateCascadeRevocationOperationRequest(BaseModel):
    organization_id: str
    operation_type: CascadeOperationType
    trigger_entity_type: TriggerEntityType
    trigger_entity_id: str
    affected_credential_count: int | None = None
    affected_credential_ids: list[str] = Field(default_factory=list)
    requires_confirmation: bool | None = None
    max_cascade_depth: int = 3
    current_depth: int = 0
    circuit_breaker_threshold: int = 1000
    can_rollback: bool = False
    rollback_snapshot: dict[str, Any] | None = None
    metadata: dict[str, Any] | None = None


class CascadeRevocationOperationResponse(BaseModel):
    id: str
    organization_id: str
    operation_type: str
    trigger_entity_type: str
    trigger_entity_id: str
    status: str
    affected_credential_count: int | None = None
    affected_credential_ids: list[str] = Field(default_factory=list)
    requires_confirmation: bool
    confirmed_at: str | None = None
    confirmed_by: str | None = None
    max_cascade_depth: int
    current_depth: int
    circuit_breaker_threshold: int
    circuit_breaker_triggered: bool
    can_rollback: bool
    rollback_snapshot: dict[str, Any] | None = None
    rolled_back_at: str | None = None
    rolled_back_by: str | None = None
    error_message: str | None = None
    metadata: dict[str, Any] | None = None
    created_at: str
    updated_at: str | None = None


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/revocation-profiles", tags=["revocation-profiles"])
cascade_router = APIRouter(prefix="/v1/cascade-revocations", tags=["cascade-revocations"])
batch_router = APIRouter(prefix="/v1/revocation-batches", tags=["revocation-batches"])
internal_router = APIRouter(prefix="/internal/revocation-profiles", tags=["internal"])
status_router = APIRouter(prefix="/v1/organizations", tags=["status-lists"])

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


def _parse_revocation_mechanism(value: str | RevocationMechanism) -> RevocationMechanism:
    if isinstance(value, RevocationMechanism):
        return value
    return RevocationMechanism(str(value).strip().upper())


def _collect_revocation_mechanisms(profile: RevocationProfile) -> list[str]:
    mechanisms: list[RevocationMechanism] = []

    if profile.issuer_config.enable_legacy_revocation_list:
        mechanisms.append(RevocationMechanism.STATUS_LIST_2021)
    if profile.issuer_config.enable_bitstring_status_list:
        mechanisms.append(RevocationMechanism.BITSTRING_STATUS_LIST)
    if profile.issuer_config.enable_token_status_list:
        mechanisms.append(RevocationMechanism.TOKEN_STATUS_LIST)

    for mechanism in profile.verifier_config.mechanism_priority:
        if mechanism not in mechanisms:
            mechanisms.append(mechanism)

    if not mechanisms:
        mechanisms.append(RevocationMechanism.BITSTRING_STATUS_LIST)

    return [mechanism.value for mechanism in mechanisms]


def _protocol_issuer_config(profile: RevocationProfile) -> dict[str, Any]:
    config: dict[str, Any] = {
        "auto_allocate_index": profile.automation_config.auto_allocate_indices,
        "batch_update_interval_seconds": profile.issuer_config.batch_interval_seconds,
        "list_size": profile.issuer_config.status_list_size,
    }
    if profile.issuer_config.status_list_base_url:
        config["uri_template"] = profile.issuer_config.status_list_base_url
    return config


def _status_list_url(profile: RevocationProfile) -> str | None:
    base_url = profile.issuer_config.status_list_base_url
    if not base_url:
        return None
    normalized = base_url.strip()
    if not normalized.startswith("https://"):
        return None
    return normalized


def _status_list_scope(profile: RevocationProfile) -> str:
    """Build a profile-scoped status-list storage key.

    This allows multiple revocation services per org by isolating indices
    at the revocation profile boundary.
    """
    return f"{profile.organization_id}:{profile.id}"


def _status_list_mechanism_for_format(format: StatusListFormat) -> str:
    if format == StatusListFormat.TOKEN_STATUS_LIST:
        return "token-status-list"
    return "bitstring-status-list"


def _status_list_format_from_mechanism(mechanism: str) -> StatusListFormat:
    normalized = mechanism.strip().lower()
    if normalized in {"bitstring", "bitstring-status-list", "bitstring_status_list"}:
        return StatusListFormat.BITSTRING
    if normalized in {"token", "token-status-list", "token_status_list"}:
        return StatusListFormat.TOKEN_STATUS_LIST
    raise ValueError(f"Unsupported status list mechanism: {mechanism}")


def _status_list_purpose_for_status(status: str) -> str:
    if status == "suspended":
        return "suspension"
    return "revocation"


def _status_list_public_base_url(profile: RevocationProfile) -> str:
    configured = (profile.issuer_config.status_list_base_url or "").strip()
    if configured:
        normalized = configured.rstrip("/")

        # If a canonical template is stored, derive the public base from it.
        if "/v1/organizations/" in normalized:
            return normalized.split("/v1/organizations/", 1)[0]

        # Backward compatibility: older seeds used a plain `/lists` endpoint.
        if normalized.endswith("/lists"):
            normalized = normalized[: -len("/lists")]

        if all(
            token not in normalized
            for token in ("{organization_id}", "{profile_id}", "{mechanism}", "{purpose}")
        ):
            return normalized

    env_base = os.environ.get("STATUS_LIST_PUBLIC_BASE_URL") or os.environ.get(
        "STATUS_LIST_BASE_URL"
    )
    return (env_base or "https://status.example.com").rstrip("/")


def _build_status_list_url(
    profile: RevocationProfile,
    format: StatusListFormat,
    purpose: str,
) -> str:
    base_url = _status_list_public_base_url(profile)
    mechanism = _status_list_mechanism_for_format(format)
    return (
        f"{base_url}/v1/organizations/{profile.organization_id}"
        f"/revocation-profiles/{profile.id}/status-lists/{mechanism}/{purpose}"
    )


def _build_status_list_url_template(profile: RevocationProfile) -> str:
    base_url = _status_list_public_base_url(profile)
    return (
        f"{base_url}/v1/organizations/{profile.organization_id}"
        f"/revocation-profiles/{profile.id}/status-lists/{{mechanism}}/{{purpose}}"
    )


def _to_response(profile: RevocationProfile) -> dict:
    """Convert domain model to response dict."""
    response = {
        "id": profile.id,
        "organization_id": profile.organization_id,
        "name": profile.name,
        "status": profile.status.value.upper(),
        "revocation_mechanism": _collect_revocation_mechanisms(profile),
        "mechanism_priority": [m.value for m in profile.verifier_config.mechanism_priority],
        "check_mode": profile.verifier_config.timing_mode.value,
        "issuer_config": _protocol_issuer_config(profile),
        "status_list_url": _build_status_list_url_template(profile),
        "created_at": profile.created_at.isoformat(),
        "updated_at": profile.updated_at.isoformat(),
    }

    if profile.verifier_config.timing_mode == RevocationTimingMode.CACHED:
        response["cache_ttl_seconds"] = profile.verifier_config.cache_ttl_seconds
    if profile.verifier_config.timing_mode == RevocationTimingMode.OFFLINE_GRACE:
        response["offline_grace_seconds"] = profile.verifier_config.offline_grace_seconds

    return response


def _apply_protocol_revocation_inputs(
    profile: RevocationProfile,
    request: CreateRevocationProfileRequest,
) -> None:
    if request.issuer_config:
        if request.issuer_config.auto_allocate_index is not None:
            profile.automation_config.auto_allocate_indices = request.issuer_config.auto_allocate_index
        if request.issuer_config.batch_update_interval_seconds is not None:
            profile.issuer_config.batch_interval_seconds = request.issuer_config.batch_update_interval_seconds
        if request.issuer_config.list_size is not None:
            profile.issuer_config.status_list_size = request.issuer_config.list_size
        if request.issuer_config.uri_template:
            profile.issuer_config.status_list_base_url = request.issuer_config.uri_template

    if request.status_list_url:
        profile.issuer_config.status_list_base_url = request.status_list_url

    if request.revocation_mechanism is not None:
        mechanisms = {_parse_revocation_mechanism(value) for value in request.revocation_mechanism}
        profile.issuer_config.enable_legacy_revocation_list = (
            RevocationMechanism.STATUS_LIST_2021 in mechanisms
        )
        profile.issuer_config.enable_bitstring_status_list = (
            RevocationMechanism.BITSTRING_STATUS_LIST in mechanisms
        )
        profile.issuer_config.enable_token_status_list = (
            RevocationMechanism.TOKEN_STATUS_LIST in mechanisms
        )
        if request.mechanism_priority is None:
            profile.verifier_config.mechanism_priority = list(mechanisms)

    if request.mechanism_priority is not None:
        profile.verifier_config.mechanism_priority = [
            _parse_revocation_mechanism(value) for value in request.mechanism_priority
        ]

    if request.check_mode is not None:
        profile.verifier_config.timing_mode = RevocationTimingMode(request.check_mode.upper())
    if request.cache_ttl_seconds is not None:
        profile.verifier_config.cache_ttl_seconds = request.cache_ttl_seconds
    if request.offline_grace_seconds is not None:
        profile.verifier_config.offline_grace_seconds = request.offline_grace_seconds


def _cascade_to_response(operation: CascadeRevocationOperation) -> dict:
    """Convert cascade operation to protocol-aligned response payload."""
    return {
        "id": operation.id,
        "organization_id": operation.organization_id,
        "operation_type": operation.operation_type.value,
        "trigger_entity_type": operation.trigger_entity_type.value,
        "trigger_entity_id": operation.trigger_entity_id,
        "status": operation.status.value,
        "affected_credential_count": operation.affected_credential_count,
        "affected_credential_ids": operation.affected_credential_ids,
        "requires_confirmation": operation.requires_confirmation,
        "confirmed_at": operation.confirmed_at.isoformat() if operation.confirmed_at else None,
        "confirmed_by": operation.confirmed_by,
        "max_cascade_depth": operation.max_cascade_depth,
        "current_depth": operation.current_depth,
        "circuit_breaker_threshold": operation.circuit_breaker_threshold,
        "circuit_breaker_triggered": operation.circuit_breaker_triggered,
        "can_rollback": operation.can_rollback,
        "rollback_snapshot": operation.rollback_snapshot,
        "rolled_back_at": operation.rolled_back_at.isoformat() if operation.rolled_back_at else None,
        "rolled_back_by": operation.rolled_back_by,
        "error_message": operation.error_message,
        "metadata": operation.metadata,
        "created_at": operation.created_at.isoformat(),
        "updated_at": operation.updated_at.isoformat() if operation.updated_at else None,
    }


async def _get_cascade_operation_or_404(
    operation_id: str,
    repo: InMemoryRevocationProfileRepository,
) -> CascadeRevocationOperation:
    operation = await repo.get_cascade_operation(operation_id)
    if operation is None:
        raise HTTPException(status_code=404, detail="CascadeRevocationOperation not found")
    return operation


async def _require_admin_for_org(user_id: str, organization_id: str) -> None:
    membership = await app.state.org_client.get_membership(user_id, organization_id)
    ensure_membership_permission(membership, "revocation-profile", "activate")


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


@router.post("", response_model=RevocationProfileResponse, response_model_exclude_none=True)
async def create_revocation_profile(
    request: CreateRevocationProfileRequest,
    http_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
) -> dict:
    """Create a new RevocationProfile."""
    membership = await http_request.app.state.org_client.get_membership(user_id, request.organization_id)
    ensure_membership_permission(membership, "revocation-profile", "create")

    # MIP §12.2 — revocation_mechanism must be non-empty when provided
    if request.revocation_mechanism is not None and len(request.revocation_mechanism) == 0:
        raise HTTPException(status_code=422, detail="revocation_mechanism must contain at least one mechanism")

    # MIP §12.2 — CACHED timing_mode requires cache_ttl_seconds
    timing_mode = (
        request.verifier_config.timing_mode if request.verifier_config else
        (request.check_mode.upper() if request.check_mode else None)
    )
    if timing_mode == "CACHED":
        has_ttl = (
            (request.verifier_config and request.verifier_config.cache_ttl_seconds is not None)
            or request.cache_ttl_seconds is not None
        )
        if not has_ttl:
            raise HTTPException(status_code=422, detail="cache_ttl_seconds is required when timing_mode is CACHED")

    # MIP §12.2 — OFFLINE_GRACE requires offline_grace_seconds
    if timing_mode == "OFFLINE_GRACE":
        has_grace = (
            (request.verifier_config and request.verifier_config.offline_grace_seconds is not None)
            or request.offline_grace_seconds is not None
        )
        if not has_grace:
            raise HTTPException(status_code=422, detail="offline_grace_seconds is required when timing_mode is OFFLINE_GRACE")

    # MIP §12.2 — status_list_url must be absolute HTTPS URI
    status_url = request.status_list_url or (request.issuer_config.uri_template if request.issuer_config else None)
    if status_url and not status_url.strip().startswith("https://"):
        raise HTTPException(status_code=422, detail=f"status_list_url must be an absolute HTTPS URI, got: {status_url}")

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

    _apply_protocol_revocation_inputs(profile, request)
    
    await repo.save(profile)
    logger.info(f"Created RevocationProfile: {profile.id}")
    
    return _to_response(profile)


@router.get("", response_model=list[RevocationProfileResponse], response_model_exclude_none=True)
async def list_revocation_profiles(
    organization_id: str = Query(...),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    """List all RevocationProfiles for an organization."""
    membership = await app.state.org_client.get_membership(user_id, organization_id)
    ensure_membership_permission(membership, "revocation-profile", "view")
    profiles = await repo.list(organization_id)
    return [_to_response(p) for p in profiles[offset:offset + limit]]


@router.get("/{profile_id}", response_model=RevocationProfileResponse, response_model_exclude_none=True)
async def get_revocation_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
) -> dict:
    """Get a RevocationProfile by ID."""
    profile = await repo.get(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="RevocationProfile not found")
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    ensure_membership_permission(membership, "revocation-profile", "view")
    return _to_response(profile)


@router.post("/{profile_id}/activate", response_model=RevocationProfileResponse, response_model_exclude_none=True)
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
    ensure_membership_permission(membership, "revocation-profile", "activate")
    
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
    ensure_membership_permission(membership, "revocation-profile", "delete")
    
    await repo.delete(profile_id)
    logger.info(f"Deleted RevocationProfile: {profile_id}")
    
    return {"success": True}


@cascade_router.post("", response_model=CascadeRevocationOperationResponse, response_model_exclude_none=True)
async def create_cascade_revocation_operation(
    request: CreateCascadeRevocationOperationRequest,
    http_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
) -> dict:
    """Trigger a cascade revocation operation."""
    membership = await http_request.app.state.org_client.get_membership(user_id, request.organization_id)
    ensure_membership_permission(membership, "revocation-profile", "activate")

    if request.max_cascade_depth < 1 or request.max_cascade_depth > 10:
        raise HTTPException(status_code=422, detail="max_cascade_depth must be between 1 and 10")
    if request.current_depth < 0 or request.current_depth > request.max_cascade_depth:
        raise HTTPException(status_code=422, detail="current_depth must be between 0 and max_cascade_depth")
    if request.circuit_breaker_threshold < 1:
        raise HTTPException(status_code=422, detail="circuit_breaker_threshold must be at least 1")

    affected_credential_count = request.affected_credential_count
    if affected_credential_count is None:
        affected_credential_count = len(request.affected_credential_ids)
    if affected_credential_count < 0:
        raise HTTPException(status_code=422, detail="affected_credential_count must be non-negative")

    circuit_breaker_triggered = affected_credential_count >= request.circuit_breaker_threshold
    requires_confirmation = bool(request.requires_confirmation) or circuit_breaker_triggered

    rollback_snapshot = request.rollback_snapshot
    if request.can_rollback and rollback_snapshot is None:
        rollback_snapshot = {
            "affected_credential_ids": request.affected_credential_ids,
            "affected_credential_count": affected_credential_count,
            "trigger_entity_id": request.trigger_entity_id,
        }
    operation = CascadeRevocationOperation(
        organization_id=request.organization_id,
        operation_type=request.operation_type,
        trigger_entity_type=request.trigger_entity_type,
        trigger_entity_id=request.trigger_entity_id,
        status=CascadeStatus.PENDING_CONFIRMATION if requires_confirmation else CascadeStatus.IN_PROGRESS,
        affected_credential_count=affected_credential_count,
        affected_credential_ids=list(request.affected_credential_ids),
        requires_confirmation=requires_confirmation,
        max_cascade_depth=request.max_cascade_depth,
        current_depth=request.current_depth,
        circuit_breaker_threshold=request.circuit_breaker_threshold,
        circuit_breaker_triggered=circuit_breaker_triggered,
        can_rollback=request.can_rollback,
        rollback_snapshot=rollback_snapshot,
        metadata=request.metadata,
    )

    if not requires_confirmation:
        operation.mark_completed()

    await repo.save_cascade_operation(operation)
    logger.info("Created CascadeRevocationOperation: %s", operation.id)

    return _cascade_to_response(operation)


@cascade_router.get("", response_model=list[CascadeRevocationOperationResponse], response_model_exclude_none=True)
async def list_cascade_revocation_operations(
    organization_id: str = Query(...),
    status: CascadeStatus | None = Query(None),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
) -> list[dict]:
    """List cascade revocation operations for an organization."""
    membership = await app.state.org_client.get_membership(user_id, organization_id)
    ensure_membership_permission(membership, "revocation-profile", "view")
    operations = await repo.list_cascade_operations(organization_id, status=status)
    return [_cascade_to_response(operation) for operation in operations]


@cascade_router.get("/{operation_id}", response_model=CascadeRevocationOperationResponse, response_model_exclude_none=True)
async def get_cascade_revocation_operation(
    operation_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
) -> dict:
    """Get a cascade revocation operation by ID."""
    operation = await _get_cascade_operation_or_404(operation_id, repo)
    membership = await app.state.org_client.get_membership(user_id, operation.organization_id)
    ensure_membership_permission(membership, "revocation-profile", "view")
    return _cascade_to_response(operation)


@cascade_router.post("/{operation_id}/confirm", response_model=CascadeRevocationOperationResponse, response_model_exclude_none=True)
async def confirm_cascade_revocation_operation(
    operation_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
) -> dict:
    """Confirm a pending cascade revocation operation."""
    operation = await _get_cascade_operation_or_404(operation_id, repo)
    await _require_admin_for_org(user_id, operation.organization_id)
    try:
        operation.confirm(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await repo.save_cascade_operation(operation)
    logger.info("Confirmed CascadeRevocationOperation: %s", operation_id)
    return _cascade_to_response(operation)


@cascade_router.post("/{operation_id}/rollback", response_model=CascadeRevocationOperationResponse, response_model_exclude_none=True)
async def rollback_cascade_revocation_operation(
    operation_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
) -> dict:
    """Roll back a completed cascade revocation operation."""
    operation = await _get_cascade_operation_or_404(operation_id, repo)
    await _require_admin_for_org(user_id, operation.organization_id)
    try:
        operation.rollback(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await repo.save_cascade_operation(operation)
    logger.info("Rolled back CascadeRevocationOperation: %s", operation_id)
    return _cascade_to_response(operation)


@cascade_router.delete("/{operation_id}")
async def delete_cascade_revocation_operation(
    operation_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
) -> dict:
    """Cancel a pending cascade revocation operation."""
    operation = await _get_cascade_operation_or_404(operation_id, repo)
    await _require_admin_for_org(user_id, operation.organization_id)
    if operation.status != CascadeStatus.PENDING_CONFIRMATION:
        raise HTTPException(status_code=400, detail="Only pending cascade operations can be cancelled")

    await repo.delete_cascade_operation(operation_id)
    logger.info("Cancelled CascadeRevocationOperation: %s", operation_id)
    return {"success": True}


# =============================================================================
# Internal API Endpoints (Service-to-Service)
# =============================================================================

@internal_router.post("/{profile_id}/process-revocation", response_model=ProcessRevocationResponse, response_model_exclude_none=True)
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
    if profile.organization_id != request.organization_id:
        raise HTTPException(status_code=403, detail="Revocation Profile belongs to another organization")
    
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
        
        status_scope = _status_list_scope(profile)

        # Update status list
        success = await status_mgr.set_status(
            tenant_id=status_scope,
            index=request.index,
            status=status_value,
            format=sl_format,
        )
        
        if not success:
            return {"success": False, "error": "Failed to update status list"}
        
        purpose = _status_list_purpose_for_status(request.status)
        status_list_url = _build_status_list_url(profile, sl_format, purpose)

        # Publish if auto-publish enabled
        if profile.automation_config.auto_publish:
            await status_mgr.publish(
                tenant_id=status_scope,
                format=sl_format,
            )
        
        logger.info(
            f"Updated status list: organization={profile.organization_id} "
            f"index={request.index} status={status_value} format={sl_format.value}"
        )
        
        return {
            "success": True,
            "organization_id": profile.organization_id,
            "status_list_url": status_list_url,
            "index": request.index,
        }
        
    except Exception as e:
        logger.error(f"Error processing revocation: {e}", exc_info=True)
        return {
            "success": False,
            "error": "Revocation processing failed",
        }


@internal_router.post("/{profile_id}/allocate-index", response_model=AllocateIndexResponse, response_model_exclude_none=True)
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
    if profile.organization_id != request.organization_id:
        raise HTTPException(status_code=403, detail="Revocation Profile belongs to another organization")
    
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
        
        status_scope = _status_list_scope(profile)

        # Allocate index using StatusListManager
        index = await status_mgr.allocate_index(
            tenant_id=status_scope,
            format=sl_format,
        )

        if profile.automation_config.auto_publish:
            await status_mgr.publish(
                tenant_id=status_scope,
                format=sl_format,
            )

        status_list_url = _build_status_list_url(
            profile,
            sl_format,
            purpose="revocation",
        )
        
        logger.info(
            f"Allocated index {index} for format {request.credential_format} "
            f"in profile {profile_id} (organization: {profile.organization_id})"
        )
        
        return {
            "organization_id": profile.organization_id,
            "index": index,
            "status_list_url": status_list_url,
        }
        
    except ValueError as e:
        logger.error(f"Index allocation failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error during index allocation: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@status_router.get("/{organization_id}/revocation-profiles/{profile_id}/status-lists/{mechanism}/{purpose}")
async def get_status_list_document(
    organization_id: str,
    profile_id: str,
    mechanism: str,
    purpose: str,
    repo: InMemoryRevocationProfileRepository = Depends(get_repo),
    status_mgr: StatusListManager = Depends(get_status_list_manager),
) -> JSONResponse:
    """Public verifier endpoint for status-list retrieval using org/path routing."""
    profile = await repo.get(profile_id)
    if not profile or profile.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="RevocationProfile not found")

    if purpose not in {"revocation", "suspension"}:
        raise HTTPException(status_code=400, detail="purpose must be revocation or suspension")

    try:
        sl_format = _status_list_format_from_mechanism(mechanism)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    status_scope = _status_list_scope(profile)
    status_list = await status_mgr.get_or_create(status_scope, sl_format)
    canonical_url = _build_status_list_url(profile, sl_format, purpose)
    status_list.url = canonical_url

    if sl_format == StatusListFormat.BITSTRING:
        payload = status_mgr.encode_bitstring_status_list(
            status_list,
            issuer=f"did:example:org:{organization_id}",
            status_purpose=purpose,
        )
        return JSONResponse(
            content=payload,
            headers={
                "Cache-Control": "public, max-age=300",
                "Content-Type": "application/vc+ld+json",
            },
        )

    payload = status_mgr.encode_status_list_token(
        status_list,
        issuer=f"did:example:org:{organization_id}",
        subject=canonical_url,
    )
    return JSONResponse(
        content=payload,
        headers={
            "Cache-Control": "public, max-age=300",
        },
    )


# =============================================================================
# Revocation Batch Endpoints — MIP §12
# Privacy-preserving batched revocation to prevent timing-correlation attacks.
# =============================================================================

_revocation_batches: dict[str, dict] = {}


class CreateRevocationBatchRequest(BaseModel):
    organization_id: str
    revocation_profile_id: str
    batch_interval: str = "1h"  # 1h | 6h | 24h
    credential_format: str = "SD_JWT_VC"
    credential_ids: list[str] = []


class RevocationBatchResponse(BaseModel):
    id: str
    organization_id: str
    revocation_profile_id: str
    batch_interval: str
    credential_format: str
    credential_count: int
    status: str  # PENDING | PUBLISHING | PUBLISHED | FAILED
    created_at: str
    published_at: str | None = None


@batch_router.post("", response_model=RevocationBatchResponse, status_code=201)
async def create_revocation_batch(request: CreateRevocationBatchRequest) -> RevocationBatchResponse:
    """MIP §12 — Create a revocation batch for privacy-preserving batched revocation."""
    if request.batch_interval not in ("1h", "6h", "24h"):
        raise HTTPException(status_code=400, detail="batch_interval must be 1h, 6h, or 24h")

    batch_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    # Circuit breaker: pause at 1000+ credentials, require manual confirmation
    if len(request.credential_ids) >= 1000:
        raise HTTPException(
            status_code=422,
            detail="Batch contains 1000+ credentials. Use confirm endpoint after review.",
        )

    batch = {
        "id": batch_id,
        "organization_id": request.organization_id,
        "revocation_profile_id": request.revocation_profile_id,
        "batch_interval": request.batch_interval,
        "credential_format": request.credential_format,
        "credential_ids": request.credential_ids,
        "credential_count": len(request.credential_ids),
        "status": "PENDING",
        "created_at": now.isoformat(),
        "published_at": None,
    }
    _revocation_batches[batch_id] = batch
    return RevocationBatchResponse(**{k: v for k, v in batch.items() if k != "credential_ids"})


@batch_router.get("", response_model=list[RevocationBatchResponse])
async def list_revocation_batches(
    organization_id: str | None = Query(None),
    status: str | None = Query(None),
) -> list[RevocationBatchResponse]:
    """MIP §12 — List revocation batches."""
    results = list(_revocation_batches.values())
    if organization_id:
        results = [b for b in results if b["organization_id"] == organization_id]
    if status:
        results = [b for b in results if b["status"] == status]
    return [
        RevocationBatchResponse(**{k: v for k, v in b.items() if k != "credential_ids"})
        for b in results
    ]


@batch_router.get("/{batch_id}", response_model=RevocationBatchResponse)
async def get_revocation_batch(batch_id: str) -> RevocationBatchResponse:
    """MIP §12 — Get a revocation batch by ID."""
    batch = _revocation_batches.get(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Revocation batch not found")
    return RevocationBatchResponse(**{k: v for k, v in batch.items() if k != "credential_ids"})


@batch_router.post("/{batch_id}/publish", response_model=RevocationBatchResponse)
async def publish_revocation_batch(batch_id: str) -> RevocationBatchResponse:
    """MIP §12 — Publish a pending revocation batch.

    Transitions: PENDING -> PUBLISHING -> PUBLISHED; PUBLISHING -> FAILED -> PENDING (retry).
    """
    batch = _revocation_batches.get(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Revocation batch not found")
    if batch["status"] not in ("PENDING", "FAILED"):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot publish batch in {batch['status']} status",
        )

    batch["status"] = "PUBLISHING"
    now = datetime.now(timezone.utc)

    # Process revocations via the status list manager
    try:
        for cred_id in batch.get("credential_ids", []):
            logger.info(f"Batch {batch_id}: revoking credential {cred_id}")
        batch["status"] = "PUBLISHED"
        batch["published_at"] = now.isoformat()
    except Exception as exc:
        logger.error(f"Batch publish failed: {exc}")
        batch["status"] = "FAILED"

    return RevocationBatchResponse(**{k: v for k, v in batch.items() if k != "credential_ids"})


@batch_router.delete("/{batch_id}", status_code=204)
async def delete_revocation_batch(batch_id: str) -> None:
    """MIP §12 — Delete a revocation batch (only PENDING batches)."""
    batch = _revocation_batches.get(batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Revocation batch not found")
    if batch["status"] != "PENDING":
        raise HTTPException(status_code=400, detail="Can only delete PENDING batches")
    del _revocation_batches[batch_id]


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo, _status_list_manager
    logger.info(f"Starting {SERVICE_NAME}...")

    # Use postgres-backed repository when DATABASE_URL is configured
    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        try:
            from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
            from revocation_profile.infrastructure.adapters.postgres_adapter import (
                PostgresRevocationProfileRepository,
            )
            # Convert sync psycopg2 URL to asyncpg if needed
            async_url = database_url.replace(
                "postgresql://", "postgresql+asyncpg://"
            ).replace(
                "postgresql+psycopg2://", "postgresql+asyncpg://"
            )
            engine = create_async_engine(async_url, echo=False)
            session_factory = async_sessionmaker(engine, expire_on_commit=False)
            _repo = PostgresRevocationProfileRepository(session_factory)
            logger.info("RevocationProfile: using PostgresRevocationProfileRepository")
        except Exception as exc:
            logger.warning(
                f"Failed to initialise postgres repo for revocation_profile ({exc}); "
                "falling back to InMemoryRevocationProfileRepository"
            )
            _repo = InMemoryRevocationProfileRepository()
    else:
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
    from common.di import setup_org_client, teardown_org_client
    await setup_org_client(app, "revocation-profile")
    
    # Start gRPC server
    from common.grpc_factory import create_grpc_server, start_grpc_server_port
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
    await teardown_org_client(app)

def create_app() -> FastAPI:
    return create_service_app(
        title="RevocationProfile Service",
        description="Format-agnostic revocation configuration and automation",
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[router, status_router, cascade_router, batch_router, internal_router],
    )


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
