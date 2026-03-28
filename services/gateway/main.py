"""
Marty API Gateway

Central API gateway that routes requests to microservices.
All services follow the Digital Identity model architecture.

Services:
- Auth (8001) - Authentication
- Organization (8002) - Organization management
- Credential Template (8003) - Credential blueprints
- Trust Profile (8004) - Trust configuration
- Issuance (8005) - Credential issuance
- Notification (8007) - Notifications
- Compliance Profile (8008) - Regulatory rules
- Presentation Policy (8009) - Verification policies + stateless evaluation
- Deployment Profile (8010) - Runtime configuration
- Flow (8011) - Orchestration + async verification flows

Port: 8000
"""

from __future__ import annotations

import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, List, Literal

import hashlib
import hmac
import uuid as _uuid
from collections import defaultdict

import httpx
from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as aioredis
from marty_common import OrganizationClient, CedarEngine, CedarAuthMiddleware
from marty_common.usage import UsageTracker
from marty_common.plans import PlanTier, get_plan_limits, PLAN_LIMITS, PLAN_INFO
from plan_middleware import UsageTrackingMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

SERVICE_NAME = "api-gateway"
SERVICE_PORT = int(os.environ.get("GATEWAY_PORT", "8000"))


# =============================================================================
# Service Registry
# =============================================================================

class ServiceRegistry:
    """Service registry for routing."""
    
    def __init__(self):
        self._services: dict[str, str] = {}
        self._load_services()
    
    def _load_services(self) -> None:
        """Load service URLs from environment or defaults."""
        self._services = {
            "auth": os.environ.get("AUTH_SERVICE_URL", "http://localhost:8001"),
            "organizations": os.environ.get("ORGANIZATION_SERVICE_URL", "http://localhost:8002"),
            "credential-templates": os.environ.get("CREDENTIAL_TEMPLATE_SERVICE_URL", "http://localhost:8003"),
            "trust-profiles": os.environ.get("TRUST_PROFILE_SERVICE_URL", "http://localhost:8004"),
            "issuance": os.environ.get("ISSUANCE_SERVICE_URL", "http://localhost:8005"),
            "applicant": os.environ.get("APPLICANT_SERVICE_URL", "http://localhost:8006"),
            "notifications": os.environ.get("NOTIFICATION_SERVICE_URL", "http://localhost:8007"),
            "compliance-profiles": os.environ.get("COMPLIANCE_PROFILE_SERVICE_URL", "http://localhost:8008"),
            "presentation-policies": os.environ.get("PRESENTATION_POLICY_SERVICE_URL", "http://localhost:8009"),
            "deployment-profiles": os.environ.get("DEPLOYMENT_PROFILE_SERVICE_URL", "http://localhost:8010"),
            "flows": os.environ.get("FLOW_SERVICE_URL", "http://localhost:8011"),
            "verification": os.environ.get("VERIFICATION_SERVICE_URL", "http://verification:8012"),
            "revocation-profiles": os.environ.get("REVOCATION_PROFILE_SERVICE_URL", "http://localhost:8013"),
            "device-registration": os.environ.get("DEVICE_REGISTRATION_SERVICE_URL", "http://localhost:8014"),
        }
    
    def get_service_url(self, service_name: str) -> str | None:
        return self._services.get(service_name)
    
    def get_all_services(self) -> dict[str, str]:
        return self._services.copy()


# =============================================================================
# Session Cache
# =============================================================================

class SessionCache:
    """Simple in-memory cache for session validation with TTL."""
    
    def __init__(self, ttl_seconds: int = 60):
        self._cache: dict[str, tuple[dict, float]] = {}
        self._ttl_seconds = ttl_seconds
    
    def get(self, session_id: str) -> dict | None:
        """Get cached session data if not expired."""
        if session_id not in self._cache:
            return None
        
        data, expires_at = self._cache[session_id]
        if time.time() > expires_at:
            del self._cache[session_id]
            return None
        
        return data
    
    def set(self, session_id: str, data: dict) -> None:
        """Set session data with TTL."""
        expires_at = time.time() + self._ttl_seconds
        self._cache[session_id] = (data, expires_at)
    
    def clear(self, session_id: str) -> None:
        """Clear cached session."""
        self._cache.pop(session_id, None)


# =============================================================================
# Auth Middleware
# =============================================================================

class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware that validates sessions via gRPC and injects user context headers."""
    
    def __init__(self, app, session_cache: SessionCache):
        super().__init__(app)
        self.session_cache = session_cache
    
    async def dispatch(self, request: Request, call_next):
        """Process request and inject user context headers."""
        import re as _re
        # Get route configuration
        route_config = get_route_config(request.url.path)
        
        # OID4VP wallet-facing endpoints must be public (wallet has no session cookie)
        _WALLET_PUBLIC = _re.compile(
            r"^/v1/flows/instances/[^/]+/(request|submit)$"
        )
        
        # Skip auth for unauthenticated routes or health checks
        if (
            not route_config
            or not route_config.get("requires_auth", False)
            or request.url.path == "/health"
            or request.url.path.startswith("/health/")
            or request.url.path.startswith("/.well-known/")
            or _WALLET_PUBLIC.match(request.url.path)
        ):
            return await call_next(request)
        
        # Extract session ID from cookie
        session_id = request.cookies.get("sessionId")
        if not session_id:
            logger.warning(f"No session cookie for authenticated route: {request.url.path}")
            return mip_error_response(
                status_code=401,
                error="unauthorized",
                message="Authentication required",
            )
        
        # Check cache first
        user_data = self.session_cache.get(session_id)
        
        # Validate with auth service via gRPC if not cached
        if not user_data:
            try:
                stub = request.app.state.auth_grpc_stub
                user_data = await self._validate_session(stub, session_id)

                if user_data is None:
                    return mip_error_response(
                        status_code=401,
                        error="unauthorized",
                        message="Invalid session",
                    )

                # Cache the result
                self.session_cache.set(session_id, user_data)

            except Exception as e:
                logger.error(f"Error validating session: {e}")
                return mip_error_response(
                    status_code=502,
                    error="auth_service_error",
                    message="Auth service unavailable",
                )
        
        # Inject user context headers
        user_id = user_data.get("user_id")
        email = user_data.get("email")
        
        if not user_id:
            logger.error("No user_id in session data")
            return mip_error_response(
                status_code=401,
                error="unauthorized",
                message="Invalid session data",
            )
        
        # Add headers to request for downstream services
        request.state.user_id = user_id
        request.state.user_email = email
        request.state.user_domain = email.split("@")[1] if email and "@" in email else None
        
        # Proceed with request
        response = await call_next(request)
        return response

    async def _validate_session(self, stub, session_id: str) -> dict | None:
        """Validate session via gRPC. Returns user_data dict or None."""
        import grpc
        from marty_proto.v1 import auth_service_pb2

        try:
            resp = await stub.ValidateSession(
                auth_service_pb2.ValidateSessionRequest(session_id=session_id),
                timeout=5.0,
            )
            if not resp.valid:
                return None
            user = resp.user
            return {
                "user_id": user.user_id,
                "email": user.email,
                "username": user.username,
                "given_name": user.given_name,
                "family_name": user.family_name,
                "user_type": user.user_type,
                "applicant_id": user.applicant_id,
                "roles": list(user.roles),
                "organization_id": user.organization_id,
                "organization_name": user.organization_name,
            }
        except grpc.aio.AioRpcError as e:
            logger.error(f"gRPC session validation error: {e.code()} {e.details()}")
            raise


# =============================================================================
# MIP Version Middleware
# =============================================================================

MIP_VERSION = "0.1"
MIP_SUPPORTED_VERSIONS = ["0.1"]


class MIPVersionMiddleware(BaseHTTPMiddleware):
    """Inject X-MIP-Version on responses and check mip_version on requests."""

    async def dispatch(self, request: Request, call_next):
        # Version negotiation: reject unsupported versions if client advertises one
        client_version = request.headers.get("x-mip-version")
        if client_version and client_version not in MIP_SUPPORTED_VERSIONS:
            return mip_error_response(
                status_code=400,
                error="UNSUPPORTED_VERSION",
                message=(
                    f"MIP version {client_version!r} is not supported. "
                    f"Supported: {MIP_SUPPORTED_VERSIONS}"
                ),
                extra={"supported_versions": MIP_SUPPORTED_VERSIONS},
            )
        response = await call_next(request)
        response.headers["X-MIP-Version"] = MIP_VERSION
        return response


# =============================================================================
# MIP §17.7 — Standardized error response envelope
# =============================================================================

def mip_error_response(
    status_code: int,
    error: str,
    message: str,
    *,
    field: str | None = None,
    details: list[dict] | None = None,
    extra: dict | None = None,
) -> JSONResponse:
    """Return a MIP-conformant error response."""
    body: dict[str, Any] = {
        "error": error,
        "error_description": message,
        "message_id": str(_uuid.uuid4()),
    }
    if field:
        body["field"] = field
    if details:
        body["details"] = details
    if extra:
        body.update(extra)
    resp = JSONResponse(status_code=status_code, content=body)
    resp.headers["X-MIP-Version"] = MIP_VERSION
    return resp


# =============================================================================
# MIP §20.4 — Rate Limiting (MUST for all public-facing endpoints)
# =============================================================================

# Configurable limits per window (seconds).  Keyed by (client_key, bucket).
# Bucket is derived from the first two path segments (e.g. "/v1/issuance").
_RATE_LIMIT_RPM = int(os.environ.get("RATE_LIMIT_RPM", "120"))  # requests / minute
_RATE_LIMIT_BURST = int(os.environ.get("RATE_LIMIT_BURST", "20"))  # max burst
_RATE_LIMIT_WINDOW = 60  # 1-minute sliding window


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Token-bucket rate limiter backed by Redis when available, in-process fallback."""

    def __init__(self, app):
        super().__init__(app)
        self._local_buckets: dict[str, list[float]] = defaultdict(list)

    def _client_key(self, request: Request) -> str:
        """Derive a rate-limit key from session or IP."""
        session_id = request.cookies.get("sessionId")
        if session_id:
            return f"sid:{hashlib.sha256(session_id.encode()).hexdigest()[:16]}"
        forwarded = request.headers.get("x-forwarded-for")
        ip = forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")
        return f"ip:{ip}"

    def _bucket_name(self, path: str) -> str:
        parts = path.strip("/").split("/", 2)
        return "/".join(parts[:2]) if len(parts) >= 2 else parts[0] if parts else "root"

    async def _check_redis(self, redis_client, key: str) -> tuple[bool, int]:
        """Sliding-window check via Redis sorted set. Returns (allowed, remaining)."""
        now = time.time()
        window_start = now - _RATE_LIMIT_WINDOW
        pipe = redis_client.pipeline()
        pipe.zremrangebyscore(key, 0, window_start)
        pipe.zcard(key)
        pipe.zadd(key, {f"{now}:{_uuid.uuid4().hex[:8]}": now})
        pipe.expire(key, _RATE_LIMIT_WINDOW + 1)
        results = await pipe.execute()
        count = results[1]  # zcard result before the new add
        if count >= _RATE_LIMIT_RPM:
            # Over limit — remove the optimistically added entry
            await redis_client.zremrangebyscore(key, now, now + 0.001)
            return False, 0
        return True, max(0, _RATE_LIMIT_RPM - count - 1)

    def _check_local(self, key: str) -> tuple[bool, int]:
        """In-process sliding window fallback."""
        now = time.time()
        window_start = now - _RATE_LIMIT_WINDOW
        timestamps = self._local_buckets[key]
        # Prune expired
        self._local_buckets[key] = timestamps = [t for t in timestamps if t > window_start]
        if len(timestamps) >= _RATE_LIMIT_RPM:
            return False, 0
        timestamps.append(now)
        return True, max(0, _RATE_LIMIT_RPM - len(timestamps))

    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for internal health checks
        if request.url.path in ("/health", "/health/services"):
            return await call_next(request)

        client_key = self._client_key(request)
        bucket = self._bucket_name(request.url.path)
        rate_key = f"mip:rl:{client_key}:{bucket}"

        redis_client = getattr(request.app.state, "redis_client", None)
        if redis_client:
            try:
                allowed, remaining = await self._check_redis(redis_client, rate_key)
            except Exception:
                # Redis failure — fall back to local
                allowed, remaining = self._check_local(rate_key)
        else:
            allowed, remaining = self._check_local(rate_key)

        if not allowed:
            return mip_error_response(
                status_code=429,
                error="rate_limit_exceeded",
                message="Too many requests. Please retry after the rate limit window resets.",
                extra={"retry_after_seconds": _RATE_LIMIT_WINDOW},
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(_RATE_LIMIT_RPM)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response


class ContentTypeEnforcementMiddleware(BaseHTTPMiddleware):
    """MIP §17.7: Reject requests with wrong Content-Type for JSON-body endpoints."""

    _METHODS_WITH_BODY = {"POST", "PUT", "PATCH"}
    _EXEMPT_PREFIXES = (
        "/v1/issuance/token",       # OAuth token endpoint: application/x-www-form-urlencoded
        "/v1/flows/instances/",     # OID4VP submit: application/x-www-form-urlencoded
        "/v1/flows/siop/submit",    # SIOPv2 submit
        "/v1/auth/",               # Auth service may use form data
    )

    async def dispatch(self, request: Request, call_next):
        if request.method in self._METHODS_WITH_BODY:
            ct = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
            if ct and ct not in (
                "application/json",
                "application/scim+json",
                "application/x-www-form-urlencoded",
                "multipart/form-data",
            ):
                if not any(request.url.path.startswith(p) for p in self._EXEMPT_PREFIXES):
                    return mip_error_response(
                        status_code=415,
                        error="unsupported_media_type",
                        message=f"Content-Type '{ct}' is not supported. Use application/json.",
                    )
        return await call_next(request)


# =============================================================================
# =============================================================================
# Route Configuration
# =============================================================================

ROUTE_CONFIG = {
    # Auth routes (no auth required)
    "/v1/auth": {"service": "auth", "requires_auth": False},
    "/v1/organizations/invitations/validate": {"service": "auth", "requires_auth": False},
    "/v1/organizations/join/code/validate": {"service": "organizations", "requires_auth": False},
    
    # Organization routes
    "/v1/organizations": {"service": "organizations", "requires_auth": True},
    "/v1/me": {"service": "organizations", "requires_auth": True},
    "/v1/api-keys": {"service": "organizations", "requires_auth": True},
    
    # Digital Identity Model - Configuration Resources
    "/v1/credential-templates": {"service": "credential-templates", "requires_auth": True},
    "/v1/wallet-registry": {"service": "credential-templates", "requires_auth": True},
    "/v1/trust-profiles": {"service": "trust-profiles", "requires_auth": True},
    "/v1/issuer-entities": {"service": "trust-profiles", "requires_auth": True},
    "/v1/trust-frameworks": {"service": "trust-profiles", "requires_auth": True},
    "/v1/trust-registry": {"service": "trust-profiles", "requires_auth": False},
    "/v1/compliance-profiles": {"service": "compliance-profiles", "requires_auth": True},
    "/v1/presentation-policies": {"service": "presentation-policies", "requires_auth": True},
    "/v1/deployment-profiles": {"service": "deployment-profiles", "requires_auth": True},
    "/v1/revocation-profiles": {"service": "revocation-profiles", "requires_auth": True},
    "/v1/revocation-batches": {"service": "revocation-profiles", "requires_auth": True},
    "/v1/cascade-revocations": {"service": "revocation-profiles", "requires_auth": True},
    "/v1/devices": {"service": "device-registration", "requires_auth": True},
    
    # Digital Identity Model - Operational Resources
    "/v1/applicants": {"service": "applicant", "requires_auth": True},
    "/v1/issued-credentials": {"service": "issuance", "requires_auth": True},
    # OID4VCI wallet-facing endpoints must be public (no auth token available on wallet)
    "/v1/issuance/offers": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/token": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/credential": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/nonce": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/notification": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/deferred-credential": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/authorize": {"service": "issuance", "requires_auth": False},
    "/v1/issuance": {"service": "issuance", "requires_auth": True},
    "/v1/application-templates": {"service": "issuance", "requires_auth": True},
    "/v1/applications": {"service": "issuance", "requires_auth": True},
    "/v1/flows/instances": {"service": "flows", "requires_auth": True},  # wallet-facing /request + /submit handled by _WALLET_PUBLIC regex
    "/v1/flows/siop/submit": {"service": "flows", "requires_auth": False},  # SIOPv2 wallet-facing
    "/v1/flows/siop": {"service": "flows", "requires_auth": True},  # SIOPv2 session creation
    "/v1/flows": {"service": "flows", "requires_auth": True},
    
    # Verification & ZK Proof routes
    "/v1/verify": {"service": "verification", "requires_auth": True},
    "/v1/verify/zkp": {"service": "verification", "requires_auth": True},
    
    # Utility routes
    "/v1/notifications": {"service": "notifications", "requires_auth": True},
    "/v1/subscriptions": {"service": "notifications", "requires_auth": True},
    "/v1/webhooks": {"service": "notifications", "requires_auth": True},
    # Cedar Policy Sets
    "/v1/policy-sets": {"service": "organizations", "requires_auth": True},
}


def get_route_config(path: str) -> dict[str, Any] | None:
    """Find matching route configuration for a path."""
    for prefix, config in sorted(ROUTE_CONFIG.items(), key=lambda x: -len(x[0])):
        if path.startswith(prefix):
            return config
    return None


# =============================================================================
# Base Classes for Models
# =============================================================================

class BaseResourceCreate(BaseModel):
    """Base class for creating organization-scoped resources."""
    organization_id: str
    name: str
    description: str | None = None


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
# API Models - Trust Profile
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


class TrustProfileCreate(BaseModel):
    organization_id: str
    name: str
    description: str | None = None
    profile_type: str = "CUSTOM"
    compliance_status: str = "SETUP_REQUIRED"
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
    name: str | None = None
    description: str | None = None
    profile_type: str | None = None
    compliance_status: str | None = None
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
    name: str
    description: str | None = None
    issuer_did: str
    issuer_url: str | None = None
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
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class CreateApiKeyRequest(BaseModel):
    name: str
    description: str | None = None
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
    credential_id: str
    credential_type: str
    credential_format: str
    flow_execution_id: str
    credential_template_id: str
    application_id: str | None = None
    revocation_profile_id: str | None = None
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
# API Models - Credential Template
# =============================================================================

class ClaimDefinitionModel(BaseModel):
    name: str
    display_name: str
    claim_type: str = "string"
    required: bool = True
    selectively_disclosable: bool = True


class TemplateValidityRules(BaseModel):
    ttl_days: int = 365
    expiration_mode: str = "hard"  # hard, soft
    reissue_window_days: int = 30


class TemplateIssuerRequirements(BaseModel):
    allowed_issuer_ids: list[str] = []  # References Trust Profile entries or specific DIDs
    signing_algorithm_constraints: list[str] | None = None


class CredentialTemplateCreate(BaseModel):
    """Create a Credential Template (complete issuance definition).
    
    Credential Template is the master configuration combining:
    - Schema/claims definition
    - Compliance Profile (embedded - format, framework rules)
    - Application Template reference (optional - for application-based flows)
    - Cryptographic configuration (keys, certs, DIDs)
    - Validity and revocation settings
    """
    organization_id: str
    name: str
    description: str | None = None
    
    # Schema & Claims
    credential_type: str
    vct: str  # Verifiable Credential Type identifier
    claims: list[ClaimDefinitionModel] = []
    privacy_posture: str = "selective_disclosure"
    supported_formats: list[str] = ["sd_jwt_vc"]
    
    # INVERTED RELATIONSHIP: Credential Template references Application Template
    application_template_id: str | None = None  # Optional - for application-based issuance
    
    # Embedded Compliance Profile
    compliance_profile: dict | None = None  # Embedded compliance rules
    compliance_profile_id: str | None = None  # Reference to existing compliance profile
    trust_profile_id: str | None = None
    revocation_profile_id: str | None = None
    
    # Validity configuration
    validity_rules: TemplateValidityRules | None = None
    
    # Cryptographic configuration (moved from Application Template)
    issuer_key_id: str | None = None
    issuer_key_algorithm: str | None = None  # RS256, ES256, EdDSA, etc.
    key_access_mode: str = "key_vault"  # key_vault, hsm, local (dev only)
    issuer_certificate_chain_pem: str | None = None  # For mDoc/X.509-based credentials
    issuer_did: str | None = None  # For DID-based credentials
    auto_generate_artifacts: bool = True  # Auto-generate missing artifacts in non-production
    
    # Legacy field for backward compatibility during migration
    issuer_requirements: TemplateIssuerRequirements | None = None
    # ZK-specific fields
    zk_predicate_claims: list[str] = []
    schema_uri: dict | None = None
    # Payload format and wallet deep-link configuration
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt"  # ietf_sd_jwt | w3c_vcdm_v2_sd_jwt | w3c_vcdm_v2_jwt_vc
    wallet_configs: list[dict] = []  # [{"wallet_id": ..., "deep_link_scheme": ...}]


class CredentialTemplateResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    
    # Schema & Claims
    credential_type: str
    vct: str  # Verifiable Credential Type identifier
    claims: list[dict]
    privacy_posture: str
    supported_formats: list[str]
    
    # Profile references
    application_template_id: str | None
    compliance_profile: dict | None = None  # Embedded compliance rules
    compliance_profile_id: str | None = None
    trust_profile_id: str | None
    revocation_profile_id: str | None
    
    # Validity
    validity_rules: dict | None
    
    # Cryptographic status (don't expose raw PEM in responses)
    issuer_key_id: str | None
    issuer_key_algorithm: str | None
    key_access_mode: str
    issuer_certificate_chain_configured: bool  # Whether cert chain is set
    issuer_did: str | None
    artifacts_status: str  # "complete", "partial", "missing"
    
    # Legacy field
    issuer_requirements: dict | None
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
# API Models - Compliance Profile
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
    organization_id: str | None = None
    name: str
    description: str | None = None
    # Compliance code (e.g., ICAO_DTC, AAMVA_MDL, EUDI_PID, ENTERPRISE_VC)
    compliance_code: str | None = None
    # Credential format mapping
    credential_format: str = "SD_JWT_VC"
    issuance_protocol: str | None = None
    issuer_artifact_requirements: IssuerArtifactRequirementsModel | None = None
    default_verification_rules: dict | None = None
    verification_policy_set_id: str | None = None
    # Regulatory frameworks
    frameworks: list[str] = Field(default_factory=list)
    # Data retention policy
    data_retention: DataRetentionModel | None = None
    # Trust profile constraints (which trust profiles can use this)
    trust_profile_constraints: TrustProfileConstraintsModel | None = None
    api_surface: list[ApiSurfaceEndpointModel] = Field(default_factory=list)
    discoverable: bool = True
    is_system: bool = False
    # Whether this is a system-provided profile
    system_profile: bool | None = None


class ComplianceProfileUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    compliance_code: str | None = None
    credential_format: str | None = None
    issuance_protocol: str | None = None
    issuer_artifact_requirements: IssuerArtifactRequirementsModel | None = None
    default_verification_rules: dict | None = None
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
    default_verification_rules: dict | None = None
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
# API Models - Device Registration
# =============================================================================

class DevicePreferencesModel(BaseModel):
    credential_notifications: bool = True
    verification_notifications: bool = True
    system_notifications: bool = True
    quiet_hours_start: str | None = None
    quiet_hours_end: str | None = None


class DeviceRegistrationCreate(BaseModel):
    user_id: str | None = None
    organization_id: str | None = None
    device_id: str
    platform: Literal["ios", "android", "web"]
    fcm_token: str
    app_version: str | None = None
    os_version: str | None = None
    device_model: str | None = None
    preferences: DevicePreferencesModel = Field(default_factory=DevicePreferencesModel)
    public_key_der: str | None = None
    public_key_kid: str | None = None
    key_valid_from: str | None = None
    key_valid_until: str | None = None
    is_active: bool = True


class DeviceRegistrationUpdate(BaseModel):
    fcm_token: str | None = None
    app_version: str | None = None
    os_version: str | None = None
    device_model: str | None = None
    preferences: DevicePreferencesModel | None = None
    public_key_der: str | None = None
    public_key_kid: str | None = None
    key_valid_from: str | None = None
    key_valid_until: str | None = None
    is_active: bool | None = None
    last_seen_at: str | None = None


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
# API Models - Presentation Policy
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
    nonce_required: bool = False


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
    organization_id: str
    name: str
    description: str | None = None
    purpose: str | None = None
    required_claims: list[ProtocolRequiredClaimModel] = Field(default_factory=list)
    accepted_credential_types: list[str] = Field(default_factory=list)
    trust_profile_id: str | None = None
    credential_requirements: list[CredentialRequirementModel] = Field(default_factory=list)
    compliance_profile_id: str | None = None
    prefer_predicates: bool = False
    fallback_policy: str | None = None
    supported_circuits: list[str] = Field(default_factory=list)
    credential_ranking_strategy: str = "FRESHEST_FIRST"
    credential_ranking_weights: dict[str, float] | None = None
    # Holder binding requirements
    holder_binding: HolderBindingModel | None = None
    # Issuer constraints
    issuer_constraints: IssuerConstraintsModel | None = None
    # Freshness requirements
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
# API Models - Deployment Profile
# =============================================================================

class CallbacksModel(BaseModel):
    issuance_complete_url: str | None = None
    verification_complete_url: str | None = None


class FeatureFlagsModel(BaseModel):
    enable_selective_disclosure: bool = True
    enable_qr_code_generation: bool = True


class DeploymentProfileCreate(BaseModel):
    organization_id: str
    name: str
    description: str | None = None
    environment: str = "development"
    callbacks: CallbacksModel | None = None
    feature_flags: FeatureFlagsModel | None = None
    trust_profile_id: str | None = None
    presentation_policy_ids: list[str] = Field(default_factory=list)
    credential_template_ids: list[str] = Field(default_factory=list)
    default_policy_id: str | None = None
    default_presentation_policy_id: str | None = None
    enabled_flow_ids: list[str] = Field(default_factory=list)
    network_mode: str = "ONLINE"
    environment_config: dict | None = None
    ux_config: dict | None = None
    update_channel: str = "stable"  # stable, beta, dev


class DeploymentProfileUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    trust_profile_id: str | None = None
    presentation_policy_ids: list[str] | None = None
    credential_template_ids: list[str] | None = None
    default_policy_id: str | None = None
    network_mode: str | None = None
    key_access_mode: str | None = None
    biometric_required: bool | None = None
    default_presentation_policy_id: str | None = None
    environment_config: dict | None = None
    ux_config: dict | None = None


class DeploymentProfileResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    environment: str
    callbacks: dict
    feature_flags: dict
    trust_profile_id: str | None = None
    presentation_policy_ids: list[str] = Field(default_factory=list)
    credential_template_ids: list[str] = Field(default_factory=list)
    enabled_flow_ids: list[str] = Field(default_factory=list)
    default_policy_id: str | None
    network_mode: str
    key_access_mode: str | None = None
    default_presentation_policy_id: str | None = None
    environment_config: dict | None = None
    ux_config: dict | None
    update_channel: str
    update_policy: dict | None = None
    offline_cache_ttl_hours: int | None = None
    biometric_required: bool | None = None
    audit_all_events: bool | None = None
    lanes: list[dict] = Field(default_factory=list)
    api_key_prefix: str | None
    created_at: str
    updated_at: str


# =============================================================================
# API Models - Flow
# =============================================================================

class FlowStepModel(BaseModel):
    name: str
    step_type: str = "user_input"
    config: dict = Field(default_factory=dict)


class FlowDefinitionCreate(BaseModel):
    """Create a Flow Definition for orchestrating credential operations."""
    organization_id: str
    name: str
    description: str | None = None
    flow_type: str = "oid4vci_pre_authorized"
    steps: list[FlowStepModel] = Field(default_factory=list)
    approval_strategy: str = "AUTO"
    enabled: bool = True
    hooks: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    trigger: dict[str, Any] | None = None
    # Configuration resources this flow uses
    trust_profile_id: str | None = None
    credential_template_id: str | None = None
    application_template_id: str | None = None  # Mutually exclusive with credential_template_id
    presentation_policy_id: str | None = None
    # Deployment profiles where this flow can run
    deployment_profile_ids: list[str] = Field(default_factory=list)


class FlowDefinitionResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    flow_type: str
    flow_category: str | None = None
    steps: list[dict]
    trust_profile_id: str | None
    credential_template_id: str | None
    application_template_id: str | None
    presentation_policy_id: str | None
    approval_strategy: str | None = None
    enabled: bool | None = None
    hooks: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    trigger: dict[str, Any] | None = None
    deployment_profile_ids: list[str]
    version: int
    created_at: str
    updated_at: str


class FlowInstanceCreate(BaseModel):
    flow_definition_id: str
    subject_id: str | None = None
    initial_context: dict = Field(default_factory=dict)


class FlowInstanceResponse(BaseModel):
    id: str
    flow_definition_id: str
    flow_id: str | None = None
    organization_id: str
    status: str
    protocol_status: str | None = None
    flow_type: str | None = None
    current_step_id: str | None
    current_step: str | None = None
    current_step_index: int | None = None
    context: dict
    context_data: dict = Field(default_factory=dict)
    step_results: dict[str, dict[str, Any]] = Field(default_factory=dict)
    step_history: list[dict] = Field(default_factory=list)
    issued_credential_id: str | None = None
    subject_id: str | None = None
    external_reference: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    expires_at: str | None = None
    result: dict | None = None
    error: str | None = None
    error_code: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


# =============================================================================
# API Models - Policy Evaluation
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
    result: str  # passed, failed, partial
    policy_id: str
    policy_name: str
    credential_results: list[CredentialEvaluationResult]
    decision: str  # allow, deny, manual_review
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
# API Models - Verification Flow (async wallet interaction)
# =============================================================================

class StartVerificationFlowRequest(BaseModel):
    presentation_policy_id: str | None = None  # optional for SIOPv2 (response_type=id_token)
    organization_id: str | None = None
    response_type: str = "vp_token"  # id_token for SIOPv2
    trust_profile_id: str | None = None
    deployment_profile_id: str | None = None
    external_reference: str | None = None
    callback_url: str | None = None
    expiry_minutes: int = 15


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
# API Models - Organization
# =============================================================================

class OrganizationCreate(BaseModel):
    name: str
    display_name: str | None = None

    @field_validator("name")
    @classmethod
    def name_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("name must not be empty")
        return v


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


# =============================================================================
# API Models - Issuance
# =============================================================================

class IssuanceCreate(BaseModel):
    """Create an issuance request."""
    organization_id: str
    credential_template_id: str | None = None  # Optional — issuance service falls back to "default"
    subject_did: str | None = None
    application_id: str | None = None
    claims: dict = {}


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
# API Models - Application Template (How users apply for credentials)
# =============================================================================

from enum import Enum


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
    """Claim collection rule."""
    claim_name: str
    source: str  # form_field, evidence, derived
    source_field: str | None = None
    required: bool = True


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


class ApplicationTemplateCreate(BaseModel):
    """Create an Application Template (user-facing workflow definition).
    
    Application Template defines what users fill out to apply for credentials.
    This is a PURE USER-FACING entity with NO cryptographic concerns.
    It defines the application workflow, not the credential structure.
    """
    organization_id: str
    name: str
    description: str | None = None
    credential_template_id: str | None = None  # Added
    
    # Evidence collection requirements - list of string identifiers like ["drivers_license", "selfie"]
    evidence_requirements: Any = Field(
        default=[],
        description="List of evidence type strings required for this application"
    )
    
    # Form field definitions (what users fill out)
    form_fields: List[dict] = Field(default_factory=list)  # Simplified to dict only
    
    # Claim collection (how to gather claim values from applicant)
    claim_collection_rules: List[dict] = Field(default_factory=list)  # Simplified to dict only
    
    # Workflow configuration
    approval_strategy: str = "auto"  # Changed from enum to string
    application_validity_days: int = 30  # How long application remains valid
    auto_approval_rules: list[dict] = []  # Added to match backend
    
    # Notification settings
    notifications: NotificationConfigModel | None = None
    notification_config: dict = {}  # Added as alternative
    
    # UI/UX configuration
    ui_config: ApplicationUIConfigModel | dict | None = None  # Allow dict too


class ApplicationTemplateResponse(BaseModel):
    """Application Template response."""
    id: str
    organization_id: str
    name: str
    description: str | None
    credential_template_id: str | None  # Added
    status: str
    
    # Evidence collection
    evidence_requirements: list[str]
    
    # Form configuration
    form_fields: list[dict]
    
    # Claim collection
    claim_collection_rules: list[dict]
    
    # Workflow
    approval_strategy: str
    application_validity_days: int
    auto_approval_rules: list[dict] = []  # Added
    
    # Notifications
    notifications: dict | None = None
    notification_config: dict = {}  # Added as alternative
    
    # UI configuration
    ui_config: dict | None
    
    # Metadata
    created_at: str
    updated_at: str
    version: int | None = None  # Optional


# =============================================================================
# API Models - Application (Instances of Application Templates)
# =============================================================================

class ApplicationCreate(BaseModel):
    """Create an Application from an Application Template."""
    application_template_id: str
    applicant_data: dict = {}  # Form data from applicant


class EvidenceSubmission(BaseModel):
    """Submit evidence for an application."""
    evidence_type: str  # Changed from EvidenceType enum to string for flexibility
    evidence_data: dict = {}  # Changed from 'data' to 'evidence_data' to match backend


class ApplicationResponse(BaseModel):
    """Application response."""
    id: str
    organization_id: str
    application_template_id: str
    applicant_identifier: str  # Changed from subject_id
    form_data: dict  # Changed from status
    evidence_submissions: list[dict]  # Added
    status: str  # pending, under_review, approved, rejected
    review_notes: str | None
    reviewer_id: str | None = None  # Added
    submitted_at: str  # Added
    reviewed_at: str | None = None  # Added
    expires_at: str  # Added
    issuance_transaction_id: str | None = None  # Added
    created_at: str | None = None  # Optional for compatibility
    updated_at: str | None = None  # Optional for compatibility


# =============================================================================
# API Models - Audit Events (Immutable log)
# =============================================================================

class AuditEventResponse(BaseModel):
    """Audit event response."""
    id: str
    organization_id: str
    timestamp: str
    actor_id: str | None
    actor_type: str  # user, system, api_key
    action: str  # created, updated, deleted, activated, etc.
    resource_type: str  # trust_profile, credential_template, etc.
    resource_id: str
    resource_name: str | None
    changes: dict | None
    metadata: dict


# =============================================================================
# API Models - Lanes (Device groupings for Deployment Profiles)
# =============================================================================

class LaneCreate(BaseModel):
    """Create a Lane (logical device grouping) within a Deployment Profile."""
    name: str
    description: str | None = None
    location: str | None = None
    device_type: str = "kiosk"  # kiosk, mobile, gate, checkpoint


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
# Proxy Implementation
# =============================================================================

_registry: ServiceRegistry | None = None
_http_client: httpx.AsyncClient | None = None


def get_registry() -> ServiceRegistry:
    if _registry is None:
        raise RuntimeError("Service not configured")
    return _registry


def get_http_client() -> httpx.AsyncClient:
    if _http_client is None:
        raise RuntimeError("Service not configured")
    return _http_client


async def proxy_request(
    request: Request,
    service_url: str,
    path: str,
    inject_params: dict | None = None,
    body_override: bytes | None = None,
) -> Response:
    """Proxy a request to a backend service.

    Args:
        request: The incoming FastAPI request.
        service_url: Base URL of the target micro-service.
        path: Path to append to the service URL.
        inject_params: Extra query parameters to merge into the forwarded URL.
            These are appended *in addition to* any query params already present
            on the incoming request, and they override duplicate keys.
    """
    client = get_http_client()
    
    # Build target URL
    url = f"{service_url}{path}"
    # Forward incoming query string, then overlay inject_params
    from urllib.parse import parse_qsl, urlencode
    qs_pairs = list(parse_qsl(request.url.query or ""))
    if inject_params:
        incoming_keys = {k for k, _ in qs_pairs}
        for k, v in inject_params.items():
            if k not in incoming_keys:
                qs_pairs.append((k, v))
    if qs_pairs:
        url = f"{url}?{urlencode(qs_pairs)}"
    
    # Get request body if present
    body = body_override if body_override is not None else await request.body()
    
    # Forward headers (excluding hop-by-hop headers)
    excluded_headers = {"host", "connection", "keep-alive", "transfer-encoding"}
    # Also strip content-length when body_override is provided (size may differ)
    if body_override is not None:
        excluded_headers.add("content-length")
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in excluded_headers
    }
    
    # Inject user context headers from middleware
    if hasattr(request.state, "user_id") and request.state.user_id:
        headers["X-User-Id"] = request.state.user_id
    
    if hasattr(request.state, "user_email") and request.state.user_email:
        headers["X-User-Email"] = request.state.user_email
    
    if hasattr(request.state, "user_domain") and request.state.user_domain:
        headers["X-User-Domain"] = request.state.user_domain
    
    if hasattr(request.state, "org_plan") and request.state.org_plan:
        headers["X-Org-Plan"] = request.state.org_plan
    
    try:
        response = await client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body,
            timeout=30.0,
        )
        
        # Return proxied response
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers={
                k: v for k, v in response.headers.items()
                if k.lower() not in ("content-encoding", "transfer-encoding", "content-length")
            },
            media_type=response.headers.get("content-type"),
        )
    except httpx.ConnectError:
        return mip_error_response(status_code=503, error="service_unavailable", message="Service unavailable")
    except httpx.TimeoutException:
        return mip_error_response(status_code=504, error="service_timeout", message="Service timeout")


async def _resource_exists(service_name: str, path: str, request: Request | None = None) -> bool:
    """Check if a resource exists by issuing a GET to the backend service."""
    registry = get_registry()
    client = get_http_client()
    url = f"{registry.get_service_url(service_name)}{path}"
    headers = _forward_headers(request)
    try:
        resp = await client.get(url, timeout=10.0, headers=headers)
        return resp.status_code < 400
    except (httpx.ConnectError, httpx.TimeoutException):
        return False


async def _resource_org_id(service_name: str, path: str, request: Request | None = None) -> str | None:
    """Fetch a resource and return its organization_id, or None if not found."""
    registry = get_registry()
    client = get_http_client()
    url = f"{registry.get_service_url(service_name)}{path}"
    headers = _forward_headers(request)
    try:
        resp = await client.get(url, timeout=10.0, headers=headers)
        if resp.status_code >= 400:
            return None
        data = resp.json()
        return data.get("organization_id")
    except (httpx.ConnectError, httpx.TimeoutException, Exception):
        return None


def _forward_headers(request: Request | None) -> dict[str, str]:
    """Extract user context headers from the incoming request for internal calls."""
    if request is None:
        return {}
    headers: dict[str, str] = {}
    if hasattr(request.state, "user_id") and request.state.user_id:
        headers["X-User-Id"] = request.state.user_id
    if hasattr(request.state, "user_email") and request.state.user_email:
        headers["X-User-Email"] = request.state.user_email
    if hasattr(request.state, "user_domain") and request.state.user_domain:
        headers["X-User-Domain"] = request.state.user_domain
    if hasattr(request.state, "org_plan") and request.state.org_plan:
        headers["X-Org-Plan"] = request.state.org_plan
    # Forward auth header if present
    auth = request.headers.get("authorization")
    if auth:
        headers["Authorization"] = auth
    return headers


# =============================================================================
# Documented API Routes
# =============================================================================

# Trust Profile routes
trust_profile_router = APIRouter(prefix="/v1/trust-profiles", tags=["Trust Profiles"])
organization_trust_profile_router = APIRouter(prefix="/v1/organizations/{organization_id}/trust-profiles", tags=["Organization Trust Profiles"])
issuer_entity_router = APIRouter(prefix="/v1/issuer-entities", tags=["Issuer Entities"])
trust_framework_router = APIRouter(prefix="/v1/trust-frameworks", tags=["Trust Frameworks"])
api_key_router = APIRouter(prefix="/v1/api-keys", tags=["API Keys"])
trust_registry_router = APIRouter(prefix="/v1/trust-registry", tags=["Trust Registry"])
issued_credential_router = APIRouter(prefix="/v1/issued-credentials", tags=["Issued Credentials"])


@trust_profile_router.post("", response_model=TrustProfileResponse, summary="Create Trust Profile")
async def create_trust_profile(body: TrustProfileCreate, request: Request) -> Response:
    """Create a new Trust Profile for configuring trust relationships."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/trust-profiles")


@trust_profile_router.get("", response_model=list[TrustProfileResponse], summary="List Trust Profiles")
async def list_trust_profiles(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Trust Profiles for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/trust-profiles")


@trust_profile_router.get("/{profile_id}", response_model=TrustProfileResponse, summary="Get Trust Profile")
async def get_trust_profile(profile_id: str, request: Request) -> Response:
    """Get a Trust Profile by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}")


@trust_profile_router.post("/{profile_id}/activate", response_model=TrustProfileResponse, summary="Activate Trust Profile")
async def activate_trust_profile(profile_id: str, request: Request) -> Response:
    """Activate a Trust Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}/activate")


@trust_profile_router.put("/{profile_id}", response_model=TrustProfileResponse, summary="Update Trust Profile")
async def update_trust_profile(profile_id: str, body: TrustProfileUpdate, request: Request) -> Response:
    """Update a Trust Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}")


@trust_profile_router.delete("/{profile_id}", summary="Delete Trust Profile")
async def delete_trust_profile(profile_id: str, request: Request) -> Response:
    """Delete a Trust Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}")


@organization_trust_profile_router.post("", response_model=OrganizationTrustProfileResponse, summary="Create Organization Trust Profile")
async def create_organization_trust_profile(
    organization_id: str,
    body: OrganizationTrustProfileCreate,
    request: Request,
) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/organizations/{organization_id}/trust-profiles")


@organization_trust_profile_router.get("", response_model=list[OrganizationTrustProfileResponse], summary="List Organization Trust Profiles")
async def list_organization_trust_profiles(organization_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/organizations/{organization_id}/trust-profiles")


@organization_trust_profile_router.get("/{profile_id}", response_model=OrganizationTrustProfileResponse, summary="Get Organization Trust Profile")
async def get_organization_trust_profile(organization_id: str, profile_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/organizations/{organization_id}/trust-profiles/{profile_id}")


@organization_trust_profile_router.put("/{profile_id}", response_model=OrganizationTrustProfileResponse, summary="Update Organization Trust Profile")
async def update_organization_trust_profile(
    organization_id: str,
    profile_id: str,
    body: OrganizationTrustProfileUpdate,
    request: Request,
) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/organizations/{organization_id}/trust-profiles/{profile_id}")


@issuer_entity_router.post("", response_model=IssuerEntityResponse, summary="Create Issuer Entity")
async def create_issuer_entity(body: IssuerEntityCreate, request: Request) -> Response:
    """Create a protocol-aligned issuer registry entry."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/issuer-entities")


@issuer_entity_router.get("", response_model=list[IssuerEntityResponse], summary="List Issuer Entities")
async def list_issuer_entities(
    organization_id: str | None = Query(None, description="Optional organization scope"),
    request: Request = None,
) -> Response:
    """List issuer registry entities, optionally scoped to an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/issuer-entities")


@issuer_entity_router.get("/{issuer_entity_id}", response_model=IssuerEntityResponse, summary="Get Issuer Entity")
async def get_issuer_entity(issuer_entity_id: str, request: Request) -> Response:
    """Get a single issuer registry entity."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/issuer-entities/{issuer_entity_id}")


@issuer_entity_router.put("/{issuer_entity_id}", response_model=IssuerEntityResponse, summary="Update Issuer Entity")
async def update_issuer_entity(issuer_entity_id: str, body: IssuerEntityUpdate, request: Request) -> Response:
    """Update an issuer registry entity."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/issuer-entities/{issuer_entity_id}")


@issuer_entity_router.delete("/{issuer_entity_id}", summary="Delete Issuer Entity")
async def delete_issuer_entity(issuer_entity_id: str, request: Request) -> Response:
    """Delete an issuer registry entity."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/issuer-entities/{issuer_entity_id}")


@trust_framework_router.get("", response_model=list[TrustFrameworkResponse], summary="List Trust Frameworks")
async def list_trust_frameworks(request: Request) -> Response:
    """List system-managed trust frameworks."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/trust-frameworks")


@trust_framework_router.get("/{framework_id}", response_model=TrustFrameworkResponse, summary="Get Trust Framework")
async def get_trust_framework(framework_id: str, request: Request) -> Response:
    """Get a trust framework by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-frameworks/{framework_id}")


@trust_registry_router.get("/sync", response_model=TrustRegistrySyncResponse, summary="Sync Trust Registry")
async def sync_trust_registry(request: Request) -> Response:
    """Delta-sync trust anchors for wallet offline verification."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/trust-registry/sync")


@trust_registry_router.get("/csca", response_model=list[TrustRegistryEntryResponse], summary="List CSCAs")
async def list_csca_entries(request: Request) -> Response:
    """List current CSCA trust anchors."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/trust-registry/csca")


@trust_registry_router.get("/dsc", response_model=list[TrustRegistryEntryResponse], summary="List DSCs")
async def list_dsc_entries(request: Request) -> Response:
    """List current DSC trust anchors."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/trust-registry/dsc")


@trust_registry_router.get("/csca/{country_code}", response_model=list[TrustRegistryEntryResponse], summary="List CSCAs By Country")
async def list_country_csca_entries(country_code: str, request: Request) -> Response:
    """List current CSCAs for a specific country."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-registry/csca/{country_code}")


@trust_registry_router.get("/status", response_model=TrustRegistryStatusResponse, summary="Trust Registry Status")
async def get_trust_registry_status(request: Request) -> Response:
    """Get trust registry health and sequence metadata."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/trust-registry/status")


@api_key_router.get("", response_model=list[ApiKeyResponse], summary="List API Keys")
async def list_api_keys(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List API keys for an organization using the protocol top-level route."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{organization_id}/api-keys")


@api_key_router.post("", response_model=ApiKeyCreatedResponse, summary="Create API Key")
async def create_api_key(
    body: CreateApiKeyRequest,
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """Create an API key for an organization using the protocol top-level route."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{organization_id}/api-keys")


@api_key_router.delete("/{key_id}", summary="Delete API Key")
async def delete_api_key(
    key_id: str,
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """Delete or revoke an API key for an organization using the protocol top-level route."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{organization_id}/api-keys/{key_id}")


@trust_profile_router.post("/{profile_id}/issuers", response_model=TrustedIssuerResponse, summary="Add Trusted Issuer")
async def add_trusted_issuer(profile_id: str, body: TrustedIssuerCreate, request: Request) -> Response:
    """Add a Trusted Issuer to a Trust Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}/issuers")


@trust_profile_router.get("/{profile_id}/issuers", response_model=list[TrustedIssuerResponse], summary="List Trusted Issuers")
async def list_trusted_issuers(profile_id: str, request: Request) -> Response:
    """List Trusted Issuers for a Trust Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}/issuers")


@trust_profile_router.get("/{profile_id}/issuers/{issuer_id}", response_model=TrustedIssuerResponse, summary="Get Trusted Issuer")
async def get_trusted_issuer(profile_id: str, issuer_id: str, request: Request) -> Response:
    """Get a Trusted Issuer by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}/issuers/{issuer_id}")


@trust_profile_router.put("/{profile_id}/issuers/{issuer_id}", response_model=TrustedIssuerResponse, summary="Update Trusted Issuer")
async def update_trusted_issuer(profile_id: str, issuer_id: str, body: TrustedIssuerUpdate, request: Request) -> Response:
    """Update a Trusted Issuer."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}/issuers/{issuer_id}")


@trust_profile_router.delete("/{profile_id}/issuers/{issuer_id}", summary="Delete Trusted Issuer")
async def delete_trusted_issuer(profile_id: str, issuer_id: str, request: Request) -> Response:
    """Delete a Trusted Issuer from a Trust Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}/issuers/{issuer_id}")


# Revocation Profile routes
revocation_profile_router = APIRouter(prefix="/v1/revocation-profiles", tags=["Revocation Profiles"])
cascade_revocation_router = APIRouter(prefix="/v1/cascade-revocations", tags=["Cascade Revocations"])


@revocation_profile_router.post("", summary="Create Revocation Profile")
async def create_revocation_profile(request: Request) -> Response:
    """Create a new Revocation Profile for format-agnostic revocation configuration."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, "/v1/revocation-profiles")


@revocation_profile_router.get("", summary="List Revocation Profiles")
async def list_revocation_profiles(request: Request) -> Response:
    """List all Revocation Profiles."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, "/v1/revocation-profiles")


@revocation_profile_router.get("/{profile_id}", summary="Get Revocation Profile")
async def get_revocation_profile(profile_id: str, request: Request) -> Response:
    """Get a Revocation Profile by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/revocation-profiles/{profile_id}")


@revocation_profile_router.post("/{profile_id}/activate", summary="Activate Revocation Profile")
async def activate_revocation_profile(profile_id: str, request: Request) -> Response:
    """Activate a Revocation Profile for use in credential issuance."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/revocation-profiles/{profile_id}/activate")


@revocation_profile_router.delete("/{profile_id}", summary="Delete Revocation Profile")
async def delete_revocation_profile(profile_id: str, request: Request) -> Response:
    """Delete a Revocation Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/revocation-profiles/{profile_id}")


@cascade_revocation_router.post("", summary="Trigger Cascade Revocation")
async def create_cascade_revocation(request: Request) -> Response:
    """Trigger a cascade revocation operation."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, "/v1/cascade-revocations")


@cascade_revocation_router.get("", summary="List Cascade Revocations")
async def list_cascade_revocations(request: Request) -> Response:
    """List cascade revocation operations."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, "/v1/cascade-revocations")


@cascade_revocation_router.get("/{operation_id}", summary="Get Cascade Revocation")
async def get_cascade_revocation(operation_id: str, request: Request) -> Response:
    """Get a cascade revocation operation by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/cascade-revocations/{operation_id}")


@cascade_revocation_router.post("/{operation_id}/confirm", summary="Confirm Cascade Revocation")
async def confirm_cascade_revocation(operation_id: str, request: Request) -> Response:
    """Confirm a paused cascade revocation operation."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/cascade-revocations/{operation_id}/confirm")


@cascade_revocation_router.post("/{operation_id}/rollback", summary="Rollback Cascade Revocation")
async def rollback_cascade_revocation(operation_id: str, request: Request) -> Response:
    """Roll back a completed cascade revocation operation."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/cascade-revocations/{operation_id}/rollback")


@cascade_revocation_router.delete("/{operation_id}", summary="Cancel Cascade Revocation")
async def delete_cascade_revocation(operation_id: str, request: Request) -> Response:
    """Cancel a pending cascade revocation operation."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/cascade-revocations/{operation_id}")


# Credential Template routes
credential_template_router = APIRouter(prefix="/v1/credential-templates", tags=["Credential Templates"])


@credential_template_router.post("", response_model=CredentialTemplateResponse, summary="Create Credential Template")
async def create_credential_template(body: CredentialTemplateCreate, request: Request) -> Response:
    """Create a new Credential Template (master issuance configuration).
    
    Credential Template is the complete definition for issuing credentials, combining:
    - Schema/claims definition
    - Compliance Profile reference (format, framework)
    - Optional Application Template reference (for application-based issuance)
    - Cryptographic configuration (keys, certs, DIDs)
    - Validity and revocation settings
    """
    if body.trust_profile_id:
        if not await _resource_exists("trust-profiles", f"/v1/trust-profiles/{body.trust_profile_id}", request):
            raise HTTPException(status_code=422, detail=f"Trust profile not found: {body.trust_profile_id}")
    if body.compliance_profile_id:
        owner_org = await _resource_org_id("compliance-profiles", f"/v1/compliance-profiles/{body.compliance_profile_id}", request)
        if owner_org is None:
            raise HTTPException(status_code=422, detail=f"Compliance profile not found: {body.compliance_profile_id}")
        if owner_org != body.organization_id:
            raise HTTPException(status_code=403, detail="Access denied: compliance profile belongs to another organization")
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, "/v1/credential-templates", body_override=body.model_dump_json().encode())


@credential_template_router.get("", response_model=list[CredentialTemplateResponse], summary="List Credential Templates")
async def list_credential_templates(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Credential Templates for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, "/v1/credential-templates")


@credential_template_router.get("/{template_id}", response_model=CredentialTemplateResponse, summary="Get Credential Template")
async def get_credential_template(template_id: str, request: Request) -> Response:
    """Get a Credential Template by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}")


@credential_template_router.get("/{template_id}/wallet-compatibility", summary="Get Wallet Compatibility")
async def get_credential_template_wallet_compatibility(template_id: str, request: Request) -> Response:
    """Resolve the protocol-derived wallet compatibility profile for a credential template."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}/wallet-compatibility")


@credential_template_router.put("/{template_id}", response_model=CredentialTemplateResponse, summary="Update Credential Template")
async def update_credential_template(template_id: str, body: CredentialTemplateCreate, request: Request) -> Response:
    """Update a Credential Template."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}")


@credential_template_router.delete("/{template_id}", summary="Delete Credential Template")
async def delete_credential_template(template_id: str, request: Request) -> Response:
    """Delete a Credential Template."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}")


@credential_template_router.post("/{template_id}/validate-artifacts", summary="Validate Cryptographic Artifacts")
async def validate_credential_template_artifacts(template_id: str, request: Request) -> Response:
    """Validate that all required cryptographic artifacts are properly configured.
    
    Checks:
    - Signing key availability
    - Certificate chain validity (for mDoc)
    - DID resolution (for DID-based credentials)
    - Compliance with selected Compliance Profile requirements
    """
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}/validate-artifacts")


@credential_template_router.get("/{template_id}/application-template", summary="Get Linked Application Template")
async def get_credential_template_application_template(template_id: str, request: Request) -> Response:
    """Get the Application Template linked to this Credential Template (if any)."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}/application-template")


# Wallet Registry routes (proxied to credential-template service)
wallet_registry_router = APIRouter(prefix="/v1/wallet-registry", tags=["Wallet Registry"])


@wallet_registry_router.get("", summary="List Wallet Registry")
async def list_wallet_registry(request: Request) -> Response:
    """List all wallets in the global registry."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, "/v1/wallet-registry")


@wallet_registry_router.get("/{wallet_id}", summary="Get Wallet")
async def get_wallet_registry_entry(wallet_id: str, request: Request) -> Response:
    """Get a wallet registry entry by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/wallet-registry/{wallet_id}")


@wallet_registry_router.get("/resolve/profile", summary="Resolve Wallet Compatibility")
async def resolve_wallet_registry_profile(request: Request) -> Response:
    """Resolve a derived wallet compatibility profile with organization-specific overrides."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, "/v1/wallet-registry/resolve/profile")


@wallet_registry_router.post("", summary="Create Wallet Entry")
async def create_wallet_registry_entry(request: Request) -> Response:
    """Create a new wallet registry entry."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, "/v1/wallet-registry")


@wallet_registry_router.patch("/{wallet_id}", summary="Update Wallet Entry")
async def update_wallet_registry_entry(wallet_id: str, request: Request) -> Response:
    """Update a wallet registry entry."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/wallet-registry/{wallet_id}")


@wallet_registry_router.delete("/{wallet_id}", summary="Delete Wallet Entry")
async def delete_wallet_registry_entry(wallet_id: str, request: Request) -> Response:
    """Delete a wallet registry entry."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/wallet-registry/{wallet_id}")


# Compliance Profile routes
compliance_profile_router = APIRouter(prefix="/v1/compliance-profiles", tags=["Compliance Profiles"])


@compliance_profile_router.post("", response_model=ComplianceProfileResponse, summary="Create Compliance Profile")
async def create_compliance_profile(body: ComplianceProfileCreate, request: Request) -> Response:
    """Create a new Compliance Profile defining regulatory rules."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, "/v1/compliance-profiles")


@compliance_profile_router.get("", response_model=list[ComplianceProfileResponse], summary="List Compliance Profiles")
async def list_compliance_profiles(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Compliance Profiles for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, "/v1/compliance-profiles")


@compliance_profile_router.get("/{profile_id}", response_model=ComplianceProfileResponse, summary="Get Compliance Profile")
async def get_compliance_profile(profile_id: str, request: Request) -> Response:
    """Get a Compliance Profile by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, f"/v1/compliance-profiles/{profile_id}")


@compliance_profile_router.post("/{profile_id}/activate", response_model=ComplianceProfileResponse, summary="Activate Compliance Profile")
async def activate_compliance_profile(profile_id: str, request: Request) -> Response:
    """Activate a Compliance Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, f"/v1/compliance-profiles/{profile_id}/activate")


@compliance_profile_router.put("/{profile_id}", response_model=ComplianceProfileResponse, summary="Update Compliance Profile")
async def update_compliance_profile(profile_id: str, body: ComplianceProfileUpdate, request: Request) -> Response:
    """Update a Compliance Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, f"/v1/compliance-profiles/{profile_id}")


@compliance_profile_router.delete("/{profile_id}", summary="Delete Compliance Profile")
async def delete_compliance_profile(profile_id: str, request: Request) -> Response:
    """Delete a Compliance Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, f"/v1/compliance-profiles/{profile_id}")


# Device Registration routes
device_router = APIRouter(prefix="/v1/devices", tags=["Devices"])


@device_router.post("", response_model=DeviceRegistrationResponse, summary="Register Device")
async def register_device(body: DeviceRegistrationCreate, request: Request) -> Response:
    """Register or upsert a device for the current user."""
    registry = get_registry()
    service_url = registry.get_service_url("device-registration")
    return await proxy_request(request, service_url, "/v1/devices")


@device_router.get("", response_model=list[DeviceRegistrationResponse], summary="List Devices")
async def list_devices(
    organization_id: str | None = Query(None, description="Optional organization filter"),
    request: Request = None,
) -> Response:
    """List device registrations for the current user."""
    registry = get_registry()
    service_url = registry.get_service_url("device-registration")
    return await proxy_request(request, service_url, "/v1/devices")


@device_router.get("/{registration_id}", response_model=DeviceRegistrationResponse, summary="Get Device")
async def get_device(registration_id: str, request: Request) -> Response:
    """Get a device registration by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("device-registration")
    return await proxy_request(request, service_url, f"/v1/devices/{registration_id}")


@device_router.patch("/{registration_id}", response_model=DeviceRegistrationResponse, summary="Update Device")
async def update_device(registration_id: str, body: DeviceRegistrationUpdate, request: Request) -> Response:
    """Update a device registration."""
    registry = get_registry()
    service_url = registry.get_service_url("device-registration")
    return await proxy_request(request, service_url, f"/v1/devices/{registration_id}")


@device_router.delete("/{registration_id}", summary="Delete Device")
async def delete_device(registration_id: str, request: Request) -> Response:
    """Delete a device registration."""
    registry = get_registry()
    service_url = registry.get_service_url("device-registration")
    return await proxy_request(request, service_url, f"/v1/devices/{registration_id}")


# Presentation Policy routes
presentation_policy_router = APIRouter(prefix="/v1/presentation-policies", tags=["Presentation Policies"])


@presentation_policy_router.post("", response_model=PresentationPolicyResponse, summary="Create Presentation Policy")
async def create_presentation_policy(body: PresentationPolicyCreate, request: Request) -> Response:
    """Create a new Presentation Policy defining what credentials to request."""
    for req in body.credential_requirements:
        if not await _resource_exists("credential-templates", f"/v1/credential-templates/{req.credential_template_id}", request):
            raise HTTPException(status_code=422, detail=f"Credential template not found: {req.credential_template_id}")
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, "/v1/presentation-policies")


@presentation_policy_router.get("", response_model=list[PresentationPolicyResponse], summary="List Presentation Policies")
async def list_presentation_policies(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Presentation Policies for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, "/v1/presentation-policies")


@presentation_policy_router.get("/{policy_id}", response_model=PresentationPolicyResponse, summary="Get Presentation Policy")
async def get_presentation_policy(policy_id: str, request: Request) -> Response:
    """Get a Presentation Policy by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, f"/v1/presentation-policies/{policy_id}")


@presentation_policy_router.post("/{policy_id}/activate", response_model=PresentationPolicyResponse, summary="Activate Presentation Policy")
async def activate_presentation_policy(policy_id: str, request: Request) -> Response:
    """Activate a Presentation Policy for use in verification."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, f"/v1/presentation-policies/{policy_id}/activate")


@presentation_policy_router.put("/{policy_id}", response_model=PresentationPolicyResponse, summary="Update Presentation Policy")
async def update_presentation_policy(policy_id: str, body: PresentationPolicyCreate, request: Request) -> Response:
    """Update a Presentation Policy."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, f"/v1/presentation-policies/{policy_id}")


@presentation_policy_router.delete("/{policy_id}", summary="Delete Presentation Policy")
async def delete_presentation_policy(policy_id: str, request: Request) -> Response:
    """Delete a Presentation Policy."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, f"/v1/presentation-policies/{policy_id}")


@presentation_policy_router.post("/{policy_id}/evaluate", response_model=PolicyEvaluationResponse, summary="Evaluate Presentation Against Policy")
async def evaluate_presentation_with_policy(policy_id: str, body: EvaluatePresentationRequest, request: Request) -> Response:
    """
    Evaluate a verifiable presentation against a saved policy.
    
    This is the primary endpoint for stateless verification. Submit a VP token
    along with a policy ID, and receive an immediate evaluation result.
    
    The policy defines what credentials and claims are required, and this endpoint
    executes that policy against the submitted presentation.
    """
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, f"/v1/presentation-policies/{policy_id}/evaluate")


@presentation_policy_router.post("/evaluate", response_model=PolicyEvaluationResponse, summary="Evaluate Presentation with Inline Policy")
async def evaluate_presentation_inline(body: EvaluateInlineRequest, request: Request) -> Response:
    """
    Evaluate a verifiable presentation with an inline (ad-hoc) policy.
    
    Use this for one-off verifications where you don't need a saved policy.
    Provide both the policy definition and the VP token in the request body.
    """
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, "/v1/presentation-policies/evaluate")


# Deployment Profile routes
deployment_profile_router = APIRouter(prefix="/v1/deployment-profiles", tags=["Deployment Profiles"])


@deployment_profile_router.post("", response_model=DeploymentProfileResponse, summary="Create Deployment Profile")
async def create_deployment_profile(body: DeploymentProfileCreate, request: Request) -> Response:
    """Create a new Deployment Profile for runtime configuration."""
    raw_body = await request.body()
    raw_data = json.loads(raw_body) if raw_body else {}
    trust_profile_id = raw_data.get("trust_profile_id") or body.trust_profile_id
    if not trust_profile_id:
        raise HTTPException(status_code=422, detail="trust_profile_id is required")
    if not await _resource_exists("trust-profiles", f"/v1/trust-profiles/{trust_profile_id}", request):
        raise HTTPException(status_code=422, detail=f"Trust profile not found: {trust_profile_id}")

    default_policy_id = (
        raw_data.get("default_policy_id")
        or raw_data.get("default_presentation_policy_id")
        or body.default_policy_id
        or body.default_presentation_policy_id
    )
    presentation_policy_ids = raw_data.get("presentation_policy_ids") or body.presentation_policy_ids
    if not presentation_policy_ids and default_policy_id:
        presentation_policy_ids = [default_policy_id]
    if not presentation_policy_ids:
        raise HTTPException(status_code=422, detail="presentation_policy_ids must contain at least one policy")
    if default_policy_id and default_policy_id not in presentation_policy_ids:
        raise HTTPException(status_code=422, detail="default_policy_id must be included in presentation_policy_ids")
    for policy_id in presentation_policy_ids:
        owner_org = await _resource_org_id("presentation-policies", f"/v1/presentation-policies/{policy_id}", request)
        if owner_org is None:
            raise HTTPException(status_code=422, detail=f"Presentation policy not found: {policy_id}")
        if owner_org != body.organization_id:
            raise HTTPException(status_code=403, detail="Access denied: presentation policy belongs to another organization")

    credential_template_ids = raw_data.get("credential_template_ids") or body.credential_template_ids
    for template_id in credential_template_ids:
        owner_org = await _resource_org_id("credential-templates", f"/v1/credential-templates/{template_id}", request)
        if owner_org is None:
            raise HTTPException(status_code=422, detail=f"Credential template not found: {template_id}")
        if owner_org != body.organization_id:
            raise HTTPException(status_code=403, detail="Access denied: credential template belongs to another organization")
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, "/v1/deployment-profiles", body_override=raw_body)


@deployment_profile_router.get("", response_model=list[DeploymentProfileResponse], summary="List Deployment Profiles")
async def list_deployment_profiles(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Deployment Profiles for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, "/v1/deployment-profiles")


@deployment_profile_router.get("/{profile_id}", response_model=DeploymentProfileResponse, summary="Get Deployment Profile")
async def get_deployment_profile(profile_id: str, request: Request) -> Response:
    """Get a Deployment Profile by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}")


@deployment_profile_router.post("/{profile_id}/activate", response_model=DeploymentProfileResponse, summary="Activate Deployment Profile")
async def activate_deployment_profile(profile_id: str, request: Request) -> Response:
    """Activate a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/activate")


@deployment_profile_router.put("/{profile_id}", response_model=DeploymentProfileResponse, summary="Update Deployment Profile")
async def update_deployment_profile(profile_id: str, body: DeploymentProfileUpdate, request: Request) -> Response:
    """Update a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}")


@deployment_profile_router.delete("/{profile_id}", summary="Delete Deployment Profile")
async def delete_deployment_profile(profile_id: str, request: Request) -> Response:
    """Delete a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}")


@deployment_profile_router.post("/{profile_id}/generate-api-key", summary="Generate API Key")
async def generate_deployment_api_key(profile_id: str, request: Request) -> Response:
    """Generate a new API key for the Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/generate-api-key")


# Lanes (nested under Deployment Profiles)
@deployment_profile_router.post("/{profile_id}/lanes", response_model=LaneResponse, summary="Create Lane")
async def create_lane(profile_id: str, body: LaneCreate, request: Request) -> Response:
    """Create a Lane (logical device grouping) within a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes")


@deployment_profile_router.get("/{profile_id}/lanes", response_model=list[LaneResponse], summary="List Lanes")
async def list_lanes(profile_id: str, request: Request) -> Response:
    """List Lanes for a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes")


@deployment_profile_router.get("/{profile_id}/lanes/{lane_id}", response_model=LaneResponse, summary="Get Lane")
async def get_lane(profile_id: str, lane_id: str, request: Request) -> Response:
    """Get a Lane by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}")


@deployment_profile_router.put("/{profile_id}/lanes/{lane_id}", response_model=LaneResponse, summary="Update Lane")
async def update_lane(profile_id: str, lane_id: str, body: LaneCreate, request: Request) -> Response:
    """Update a Lane."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}")


@deployment_profile_router.delete("/{profile_id}/lanes/{lane_id}", summary="Delete Lane")
async def delete_lane(profile_id: str, lane_id: str, request: Request) -> Response:
    """Delete a Lane."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}")


@deployment_profile_router.post("/{profile_id}/lanes/{lane_id}/devices", summary="Assign Device to Lane")
async def assign_device_to_lane(profile_id: str, lane_id: str, body: DeviceAssignment, request: Request) -> Response:
    """Assign a device to a Lane."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}/devices")


# Flow routes
flow_router = APIRouter(prefix="/v1/flows", tags=["Flows"])


@flow_router.post("/definitions", response_model=FlowDefinitionResponse, summary="Create Flow Definition")
async def create_flow_definition(body: FlowDefinitionCreate, request: Request) -> Response:
    """Create a new Flow Definition for orchestrating credential operations."""
    if body.credential_template_id:
        if not await _resource_exists("credential-templates", f"/v1/credential-templates/{body.credential_template_id}", request):
            raise HTTPException(status_code=404, detail=f"Credential template not found: {body.credential_template_id}")
    if body.presentation_policy_id:
        if not await _resource_exists("presentation-policies", f"/v1/presentation-policies/{body.presentation_policy_id}", request):
            raise HTTPException(status_code=422, detail=f"Presentation policy not found: {body.presentation_policy_id}")
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/definitions")


@flow_router.get("/definitions", response_model=list[FlowDefinitionResponse], summary="List Flow Definitions")
async def list_flow_definitions(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Flow Definitions for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/definitions")


@flow_router.get("/definitions/{flow_id}", response_model=FlowDefinitionResponse, summary="Get Flow Definition")
async def get_flow_definition(flow_id: str, request: Request) -> Response:
    """Get a Flow Definition by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/definitions/{flow_id}")


@flow_router.post("/definitions/{flow_id}/activate", response_model=FlowDefinitionResponse, summary="Activate Flow")
async def activate_flow_definition(flow_id: str, request: Request) -> Response:
    """Activate a Flow Definition."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/definitions/{flow_id}/activate")


@flow_router.put("/definitions/{flow_id}", response_model=FlowDefinitionResponse, summary="Update Flow Definition")
async def update_flow_definition(flow_id: str, body: FlowDefinitionCreate, request: Request) -> Response:
    """Update a Flow Definition."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/definitions/{flow_id}")


@flow_router.delete("/definitions/{flow_id}", summary="Delete Flow Definition")
async def delete_flow_definition(flow_id: str, request: Request) -> Response:
    """Delete a Flow Definition."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/definitions/{flow_id}")


@flow_router.post("/instances", response_model=FlowInstanceResponse, summary="Start Flow Instance")
async def start_flow_instance(body: FlowInstanceCreate, request: Request) -> Response:
    """Start a new Flow Instance."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/instances")


@flow_router.get("/instances", response_model=list[FlowInstanceResponse], summary="List Flow Instances")
async def list_flow_instances(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List Flow Instances for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/instances")


@flow_router.get("/instances/{instance_id}", response_model=FlowInstanceResponse, summary="Get Flow Instance")
async def get_flow_instance(instance_id: str, request: Request) -> Response:
    """Get a Flow Instance by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/instances/{instance_id}")


@flow_router.post("/instances/{instance_id}/advance", response_model=FlowInstanceResponse, summary="Advance Flow")
async def advance_flow_instance(instance_id: str, request: Request) -> Response:
    """Advance a Flow Instance to the next step."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/instances/{instance_id}/advance")


@flow_router.post("/verify", response_model=VerificationRequestResponse, summary="Start Verification Flow")
async def start_verification_flow(body: StartVerificationFlowRequest, request: Request) -> Response:
    """
    Start a verification flow for async wallet interactions.
    
    Creates a flow instance with a QR code / request_uri for wallet scanning.
    For stateless verification, use POST /v1/presentation-policies/{id}/evaluate instead.
    """
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/verify")


@flow_router.get("/instances/{instance_id}/request", summary="Get Verification Request Object")
async def get_flow_verification_request(instance_id: str, request: Request) -> Response:
    """Get the OID4VP request object (for wallet to fetch via request_uri)."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/instances/{instance_id}/request")


@flow_router.get("/instances/{instance_id}/result", summary="Get Verification Result")
async def get_flow_instance_result(instance_id: str, request: Request) -> Response:
    """OID4VP-1FINAL §8.7 — Relying-party result polling endpoint for a flow instance."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/instances/{instance_id}/result")


@flow_router.post("/instances/{instance_id}/submit", response_model=VerificationResultResponse, summary="Submit Verification")
async def submit_flow_verification(instance_id: str, request: Request) -> Response:
    """Submit a VP token to complete a verification flow. Accepts JSON or form-encoded data."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/instances/{instance_id}/submit")


@flow_router.post("/siop", summary="Start SIOPv2 Cross-Device Flow")
async def start_siop_flow_gateway(request: Request) -> Response:
    """SIOPv2 Draft 13 §9: Initiate a cross-device SIOPv2 authentication flow."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/siop")


@flow_router.post("/siop/submit", summary="Submit SIOPv2 ID Token")
async def submit_siop_id_token_gateway(request: Request) -> Response:
    """SIOPv2 Draft 13 §11: Validate a self-issued ID token from the wallet (wallet-facing, no auth)."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/siop/submit")


# Issuance routes
issuance_router = APIRouter(prefix="/v1/issuance", tags=["Issuance"])


@issuance_router.post("", response_model=IssuanceResponse, summary="Create Issuance")
async def create_issuance(body: IssuanceCreate, request: Request) -> Response:
    """Initiate credential issuance for a subject (directly or via Application)."""
    if body.credential_template_id:
        owner_org = await _resource_org_id("credential-templates", f"/v1/credential-templates/{body.credential_template_id}", request)
        if owner_org is None:
            raise HTTPException(status_code=404, detail=f"Credential template not found: {body.credential_template_id}")
        if owner_org != body.organization_id:
            raise HTTPException(status_code=403, detail="Access denied: credential template belongs to another organization")
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/initiate")


@issuance_router.get("", response_model=list[IssuanceResponse], summary="List Issuances")
async def list_issuances(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List issuance records for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/transactions")


@issuance_router.get("/{issuance_id}", response_model=IssuanceResponse, summary="Get Issuance")
async def get_issuance(issuance_id: str, request: Request) -> Response:
    """Get an issuance record by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issuance/transactions/{issuance_id}")


@issuance_router.post("/{issuance_id}/revoke", summary="Revoke Issuance")
async def revoke_issuance(issuance_id: str, request: Request) -> Response:
    """Revoke a credential issuance transaction."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issuance/transactions/{issuance_id}/revoke")


@issuance_router.get("/{issuance_id}/revocation-status", summary="Get Revocation Status")
async def get_issuance_revocation_status(issuance_id: str, request: Request) -> Response:
    """Get the revocation status of an issuance transaction."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issuance/transactions/{issuance_id}/revocation-status")


@issued_credential_router.get("", response_model=list[IssuedCredentialRecordResponse], summary="List Issued Credentials")
async def list_issued_credentials(
    organization_id: str = Query(..., description="Organization ID"),
    status: str | None = Query(None),
    request: Request = None,
) -> Response:
    """List issued credential lifecycle records for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issued-credentials")


@issued_credential_router.get("/{credential_id}", response_model=IssuedCredentialRecordResponse, summary="Get Issued Credential")
async def get_issued_credential(credential_id: str, request: Request) -> Response:
    """Get an issued credential lifecycle record by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issued-credentials/{credential_id}")


@issued_credential_router.post("/{credential_id}/revoke", response_model=IssuedCredentialRecordResponse, summary="Revoke Issued Credential")
async def revoke_issued_credential(credential_id: str, request: Request) -> Response:
    """Revoke an issued credential lifecycle record."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issued-credentials/{credential_id}/revoke")


@issued_credential_router.post("/{credential_id}/suspend", response_model=IssuedCredentialRecordResponse, summary="Suspend Issued Credential")
async def suspend_issued_credential(credential_id: str, request: Request) -> Response:
    """Suspend an issued credential lifecycle record."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issued-credentials/{credential_id}/suspend")


@issued_credential_router.post("/{credential_id}/reinstate", response_model=IssuedCredentialRecordResponse, summary="Reinstate Issued Credential")
async def reinstate_issued_credential(credential_id: str, request: Request) -> Response:
    """Reinstate a suspended issued credential lifecycle record."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issued-credentials/{credential_id}/reinstate")


@issuance_router.get("/offers/{tx_id}", summary="Get Credential Offer")
async def get_credential_offer(tx_id: str, request: Request) -> Response:
    """
    Get OID4VCI credential offer for wallet integration.
    
    This endpoint is called by wallets when resolving a credential_offer_uri.
    No authentication required as the pre-authorized code serves as the auth token.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issuance/offers/{tx_id}")


@issuance_router.post("/token", summary="Exchange Token")
async def exchange_token(request: Request) -> Response:
    """
    OID4VCI Token Endpoint.
    
    Exchange pre-authorized code for access token. This is called by wallets
    during the credential issuance flow.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/token")


@issuance_router.post("/credential", summary="Issue Credential")
async def issue_credential(request: Request) -> Response:
    """
    OID4VCI Credential Endpoint.
    
    Issue a credential after successful token exchange. This is called by wallets
    to receive the actual credential.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/credential")


@issuance_router.post("/nonce", summary="Get Fresh Nonce")
async def get_nonce(request: Request) -> Response:
    """
    OID4VCI Nonce Endpoint.

    Returns a fresh c_nonce for use in credential proof JWTs. Called by wallets
    after token exchange to refresh the nonce. No authentication required.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/nonce")


@issuance_router.post("/notification", summary="Credential Notification")
async def credential_notification(request: Request) -> Response:
    """OID4VCI-1FINAL §11 — Wallet notifies issuer of credential lifecycle event."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/notification")


@issuance_router.post("/deferred-credential", summary="Deferred Credential")
async def deferred_credential(request: Request) -> Response:
    """OID4VCI-1FINAL §9.1 — Poll for a deferred credential using a transaction_id."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/deferred-credential")


# Application Template routes (how users apply for credentials)
application_template_router = APIRouter(prefix="/v1/application-templates", tags=["Application Templates"])


@application_template_router.post("", response_model=ApplicationTemplateResponse, summary="Create Application Template")
async def create_application_template(body: ApplicationTemplateCreate, request: Request) -> Response:
    """Create an Application Template defining how users apply for credentials."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/application-templates")


@application_template_router.get("", response_model=list[ApplicationTemplateResponse], summary="List Application Templates")
async def list_application_templates(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List Application Templates for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/application-templates")


@application_template_router.get("/{template_id}", response_model=ApplicationTemplateResponse, summary="Get Application Template")
async def get_application_template(template_id: str, request: Request) -> Response:
    """Get an Application Template by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}")


@application_template_router.put("/{template_id}", response_model=ApplicationTemplateResponse, summary="Update Application Template")
async def update_application_template(template_id: str, body: ApplicationTemplateCreate, request: Request) -> Response:
    """Update an Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}")


@application_template_router.delete("/{template_id}", summary="Delete Application Template")
async def delete_application_template(template_id: str, request: Request) -> Response:
    """Delete an Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}")


@application_template_router.post("/{template_id}/activate", response_model=ApplicationTemplateResponse, summary="Activate Application Template")
async def activate_application_template(template_id: str, request: Request) -> Response:
    """Activate an Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}/activate")


@application_template_router.post("/validate-artifacts", summary="Validate Issuer Artifacts")
async def validate_application_artifacts(request: Request) -> Response:
    """Validate issuer artifacts (keys, certificates, DIDs) for an Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/application-templates/validate-artifacts")


# Application routes (instances of Application Templates)
application_router = APIRouter(prefix="/v1/applications", tags=["Applications"])


@application_router.post("", response_model=ApplicationResponse, summary="Create Application")
async def create_application(body: ApplicationCreate, request: Request) -> Response:
    """Create an Application from an Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/applications")


@application_router.get("", response_model=list[ApplicationResponse], summary="List Applications")
async def list_applications(
    organization_id: str = Query(..., description="Organization ID"),
    status: str | None = Query(None, description="Filter by status"),
    request: Request = None,
) -> Response:
    """List Applications for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/applications")


@application_router.get("/{application_id}", response_model=ApplicationResponse, summary="Get Application")
async def get_application(application_id: str, request: Request) -> Response:
    """Get an Application by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}")


@application_router.post("/{application_id}/submit-evidence", response_model=ApplicationResponse, summary="Submit Evidence")
async def submit_application_evidence(application_id: str, body: EvidenceSubmission, request: Request) -> Response:
    """Submit evidence for an Application."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/submit-evidence")


@application_router.post("/{application_id}/approve", response_model=ApplicationResponse, summary="Approve Application")
async def approve_application(application_id: str, request: Request) -> Response:
    """Approve an Application for credential issuance."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/approve")


@application_router.post("/{application_id}/reject", response_model=ApplicationResponse, summary="Reject Application")
async def reject_application(application_id: str, request: Request) -> Response:
    """Reject an Application."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/reject")


@application_router.post("/{application_id}/issuance-offer", summary="Generate Wallet Invite")
async def generate_issuance_offer(application_id: str, request: Request) -> Response:
    """Generate (or refresh) a wallet credential offer for an approved application.

    Returns offer_url, qr_payload, wallets deep-link list, email_payload, and expires_at.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/issuance-offer")


@application_router.get("/{application_id}/issuance-offer", summary="Get Wallet Invite (Applicant)")
async def get_issuance_offer(application_id: str, request: Request) -> Response:
    """Retrieve the current wallet credential offer for an application (applicant-facing).

    Returns 404 until an admin has generated the offer via POST.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/issuance-offer")


@application_router.get("/{application_id}/issuance-events", summary="List Issuance Events (Admin)")
async def get_application_issuance_events(application_id: str, request: Request) -> Response:
    """List all lifecycle events for an application (admin audit timeline).

    Returns events in chronological order covering the full issuance lifecycle:
    offer_generated, offer_viewed, offer_expired, credential_issued.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/issuance-events")


# Notification routes
notification_router = APIRouter(prefix="/v1/notifications", tags=["Notifications"])
subscription_router = APIRouter(prefix="/v1/subscriptions", tags=["Subscriptions"])
webhook_router = APIRouter(prefix="/v1/webhooks", tags=["Webhooks"])


@notification_router.get("/events/push", summary="SSE Real-time Events")
async def sse_events(
    request: Request,
    tenant_id: str | None = None,
    user_id: str | None = None,
    subscriptions: str | None = None,
) -> Response:
    """
    Server-Sent Events endpoint that bridges browser clients to the
    event-stream gRPC Subscribe RPC.  Filters by organization (tenant_id)
    and optional event_types.
    """
    import json
    from fastapi.responses import StreamingResponse
    from marty_proto.v1 import (
        event_stream_service_pb2,
        event_stream_service_pb2_grpc,
    )

    requested_types = (
        [s.strip() for s in subscriptions.split(",") if s.strip()]
        if subscriptions
        else []
    )

    async def generate():
        try:
            channel = request.app.state.es_grpc_channel
            stub = event_stream_service_pb2_grpc.EventStreamServiceStub(channel)
            sub_req = event_stream_service_pb2.EventSubscription(
                event_types=requested_types,
                organization_id=tenant_id or "",
            )
            # Send initial connection confirmation
            yield "data: {\"type\": \"connected\"}\n\n"
            async for event in stub.Subscribe(sub_req):
                if await request.is_disconnected():
                    break
                payload = {
                    "event_id": event.event_id,
                    "aggregate_id": event.aggregate_id,
                    "aggregate_type": event.aggregate_type,
                    "organization_id": event.organization_id,
                    "data": dict(event.data),
                    "timestamp": event.timestamp,
                }
                yield f"event: {event.event_type}\ndata: {json.dumps(payload)}\n\n"
        except Exception as exc:
            logger.warning("SSE stream error for tenant %s: %s", tenant_id, exc)
            yield f"data: {{\"error\": \"stream_error\"}}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@notification_router.api_route("", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], summary="Notifications")
@notification_router.api_route("/{subpath:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], summary="Notifications")
async def proxy_notifications(request: Request, subpath: str = "") -> Response:
    """Proxy all notification routes to notification service."""
    registry = get_registry()
    service_url = registry.get_service_url("notifications")
    target_path = "/v1/notifications"
    if subpath:
        target_path = f"{target_path}/{subpath}"
    return await proxy_request(request, service_url, target_path)


@subscription_router.api_route("", methods=["GET", "POST"], summary="Subscriptions")
@subscription_router.api_route("/{subpath:path}", methods=["GET", "PUT", "DELETE"], summary="Subscriptions")
async def proxy_subscriptions(request: Request, subpath: str = "") -> Response:
    """Proxy protocol subscription routes to notification service."""
    registry = get_registry()
    service_url = registry.get_service_url("notifications")
    target_path = "/v1/subscriptions"
    if subpath:
        target_path = f"{target_path}/{subpath}"
    return await proxy_request(request, service_url, target_path)


@webhook_router.api_route("", methods=["GET", "POST"], summary="Webhooks")
@webhook_router.api_route("/{subpath:path}", methods=["GET", "PUT", "DELETE"], summary="Webhooks")
async def proxy_webhooks(request: Request, subpath: str = "") -> Response:
    """Proxy protocol webhook routes to notification service."""
    registry = get_registry()
    service_url = registry.get_service_url("notifications")
    target_path = "/v1/webhooks"
    if subpath:
        target_path = f"{target_path}/{subpath}"
    return await proxy_request(request, service_url, target_path)


# Policy Sets routes (Cedar)
policy_set_router = APIRouter(prefix="/v1/policy-sets", tags=["PolicySets"])


@policy_set_router.api_route("", methods=["GET", "POST"], summary="Policy Sets")
@policy_set_router.api_route("/{subpath:path}", methods=["GET", "PATCH", "DELETE", "POST"], summary="Policy Sets")
async def proxy_policy_sets(request: Request, subpath: str = "") -> Response:
    """Proxy policy-set CRUD (including /activate, /archive, /validate) to organization service."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    target_path = "/v1/policy-sets"
    if subpath:
        target_path = f"{target_path}/{subpath}"
    return await proxy_request(request, service_url, target_path)


# Applicant routes (applicant profiles)
applicant_router = APIRouter(prefix="/v1/applicants", tags=["Applicants"])


@applicant_router.post("", summary="Create Applicant")
async def create_applicant(request: Request) -> Response:
    """Create an applicant profile."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/applicants")


@applicant_router.get("/by-user/{user_id}", summary="Get Applicant by User ID")
async def get_applicant_by_user(user_id: str, request: Request) -> Response:
    """Get an applicant profile by user ID."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/by-user/{user_id}")


@applicant_router.get("/profiles/{applicant_id}", summary="Get Applicant")
async def get_applicant(applicant_id: str, request: Request) -> Response:
    """Get an applicant profile by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/profiles/{applicant_id}")


@applicant_router.patch("/profiles/{applicant_id}", summary="Update Applicant")
async def update_applicant(applicant_id: str, request: Request) -> Response:
    """Update an applicant profile."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/profiles/{applicant_id}")


@applicant_router.get("", summary="List Applicants")
async def list_applicants(
    organization_id: str = Query(None, description="Filter by organization"),
    request: Request = None,
) -> Response:
    """List applicant profiles."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/applicants")


@applicant_router.post("/applications", summary="Create Application")
async def create_applicant_application(request: Request) -> Response:
    """Create an application for a credential."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/applicants/applications")


@applicant_router.get("/org-applications", summary="List Organization Applications")
async def list_applicant_applications(request: Request) -> Response:
    """List applications for an organization queue."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/applicants/org-applications")


@applicant_router.get("/applications/{application_id}", summary="Get Application")
async def get_applicant_application(application_id: str, request: Request) -> Response:
    """Get an application by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}")


@applicant_router.post("/applications/{application_id}/submit", summary="Submit Application")
async def submit_applicant_application(application_id: str, request: Request) -> Response:
    """Submit an application for review."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/submit")


@applicant_router.patch("/applications/{application_id}", summary="Update Application")
async def update_applicant_application(application_id: str, request: Request) -> Response:
    """Update application fields (admin)."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}")


@applicant_router.post("/applications/{application_id}/review", summary="Review Application")
async def review_applicant_application(application_id: str, request: Request) -> Response:
    """Review (approve/reject) an application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/review")


@applicant_router.post("/applications/{application_id}/issue", summary="Issue Application")
async def issue_applicant_application(application_id: str, request: Request) -> Response:
    """Issue a credential for an approved application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/issue")


@applicant_router.post("/applications/{application_id}/auto-issue", summary="Auto-Issue Application")
async def auto_issue_applicant_application(application_id: str, request: Request) -> Response:
    """Atomically submit, approve, and issue a credential for an auto-approve application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/auto-issue")


@applicant_router.post("/applications/{application_id}/request-info", summary="Request More Info")
async def request_applicant_info(application_id: str, request: Request) -> Response:
    """Request additional information from an applicant."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/request-info")


@applicant_router.get("/applications/{application_id}/checks", summary="Get Vetting Checks")
async def get_applicant_checks(application_id: str, request: Request) -> Response:
    """Get vetting checks for an application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/checks")


@applicant_router.get("/checks/pending", summary="Get Pending Checks")
async def get_pending_checks(request: Request) -> Response:
    """List pending vetting checks across all applications."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/applicants/checks/pending")


@applicant_router.post("/checks/{check_id}/start", summary="Start Check")
async def start_applicant_check(check_id: str, request: Request) -> Response:
    """Start a vetting check."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/checks/{check_id}/start")


@applicant_router.post("/checks/{check_id}/complete", summary="Complete Check")
async def complete_applicant_check(check_id: str, request: Request) -> Response:
    """Complete a vetting check."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/checks/{check_id}/complete")


@applicant_router.post("/applications/{application_id}/lock", summary="Acquire Reviewer Lock")
async def acquire_applicant_lock(application_id: str, request: Request) -> Response:
    """Acquire a reviewer lock on an application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/lock")


@applicant_router.get("/applications/{application_id}/lock", summary="Get Lock Status")
async def get_applicant_lock(application_id: str, request: Request) -> Response:
    """Get the current reviewer lock status for an application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/lock")


@applicant_router.delete("/applications/{application_id}/lock", summary="Release Reviewer Lock")
async def release_applicant_lock(application_id: str, request: Request) -> Response:
    """Release a reviewer lock on an application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/lock")


@applicant_router.post("/profiles/{applicant_id}/biometrics", summary="Enroll Biometric")
async def enroll_applicant_biometric(applicant_id: str, request: Request) -> Response:
    """Enroll biometric data for an applicant."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/profiles/{applicant_id}/biometrics")


@applicant_router.get("/profiles/{applicant_id}/applications", summary="Get Applicant Applications")
async def get_applicant_applications(applicant_id: str, request: Request) -> Response:
    """Get applications for a specific applicant."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/profiles/{applicant_id}/applications")


# Organization routes
organization_router = APIRouter(prefix="/v1/organizations", tags=["Organizations"])


@organization_router.post("", response_model=OrganizationResponse, summary="Create Organization")
async def create_organization(body: OrganizationCreate, request: Request) -> Response:
    """Create a new Organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations")


@organization_router.get("", response_model=list[OrganizationResponse], summary="List Organizations")
async def list_organizations(request: Request) -> Response:
    """List Organizations."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations")


@organization_router.get("/discover", response_model=list[OrganizationResponse], summary="Discover Organizations")
async def discover_organizations(request: Request) -> Response:
    """Discover publicly available organizations."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations/discover")


@organization_router.get("/mine", response_model=list[dict], summary="My Organizations")
async def get_my_organizations(request: Request) -> Response:
    """Get organizations the current user belongs to with membership details."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations/mine")


@organization_router.get("/{org_id}", response_model=OrganizationResponse, summary="Get Organization")
async def get_organization(org_id: str, request: Request) -> Response:
    """Get an Organization by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}", inject_params={"organization_id": org_id})


@organization_router.put("/{org_id}", response_model=OrganizationResponse, summary="Update Organization")
async def update_organization(org_id: str, body: OrganizationCreate, request: Request) -> Response:
    """Update an Organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}", inject_params={"organization_id": org_id})


@organization_router.delete("/{org_id}", summary="Delete Organization")
async def delete_organization(org_id: str, request: Request) -> Response:
    """Delete an Organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}", inject_params={"organization_id": org_id})


# Join by Code
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


@organization_router.post("/join/code", response_model=JoinByCodeResponse, summary="Join Organization by Code", status_code=201)
async def join_by_code(body: JoinByCodeRequest, request: Request) -> Response:
    """Join an organization using a join code."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations/join/code")


@organization_router.get("/join/code/validate", response_model=ValidateJoinCodeResponse, summary="Validate Join Code")
async def validate_join_code(request: Request) -> Response:
    """Validate join/invitation code without joining."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations/join/code/validate")


@organization_router.post("/{org_id}/join", response_model=JoinByCodeResponse, summary="Join Organization", status_code=201)
async def join_organization(org_id: str, request: Request) -> Response:
    """Join/request to join an organization by ID (open join organizations)."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/join", inject_params={"organization_id": org_id})


@organization_router.get("/invitations/validate", response_model=InvitationValidateResponse, summary="Validate Invitation")
async def validate_organization_invitation(request: Request) -> Response:
    """Validate invitation token (public endpoint)."""
    registry = get_registry()
    service_url = registry.get_service_url("auth")
    return await proxy_request(request, service_url, "/api/onboarding/invitations/validate")


@organization_router.post("/invitations/accept", response_model=InvitationAcceptResponse, summary="Accept Invitation")
async def accept_organization_invitation(body: InvitationAcceptRequest, request: Request) -> Response:
    """Accept invitation and join organization."""
    registry = get_registry()
    service_url = registry.get_service_url("auth")
    return await proxy_request(request, service_url, "/api/onboarding/invitations/accept")


# Audit Events (nested under Organization)
@organization_router.get("/{org_id}/audit-events", response_model=list[AuditEventResponse], summary="List Audit Events")
async def list_audit_events(
    org_id: str,
    resource_type: str | None = Query(None, description="Filter by resource type"),
    action: str | None = Query(None, description="Filter by action"),
    start_date: str | None = Query(None, description="Filter from date (ISO 8601)"),
    end_date: str | None = Query(None, description="Filter to date (ISO 8601)"),
    limit: int = Query(100, description="Max results", le=1000),
    request: Request = None,
) -> Response:
    """List Audit Events for an organization (immutable log)."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/audit-events", inject_params={"organization_id": org_id})


@organization_router.get("/{org_id}/audit-events/{event_id}", response_model=AuditEventResponse, summary="Get Audit Event")
async def get_audit_event(org_id: str, event_id: str, request: Request) -> Response:
    """Get an Audit Event by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/audit-events/{event_id}", inject_params={"organization_id": org_id})


# RBAC: Permissions catalog
@organization_router.get("/{org_id}/permissions", summary="List Permissions")
async def list_permissions(org_id: str, request: Request) -> Response:
    """List the available permission catalog for this organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/permissions", inject_params={"organization_id": org_id})


# RBAC: Roles
@organization_router.get("/{org_id}/roles", summary="List Roles")
async def list_roles(org_id: str, request: Request) -> Response:
    """List roles in this organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/roles", inject_params={"organization_id": org_id})


@organization_router.post("/{org_id}/roles", summary="Create Role", status_code=201)
async def create_role(org_id: str, request: Request) -> Response:
    """Create a custom role in this organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/roles", inject_params={"organization_id": org_id})


@organization_router.get("/{org_id}/roles/{role_id}", summary="Get Role")
async def get_role(org_id: str, role_id: str, request: Request) -> Response:
    """Get a role by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/roles/{role_id}", inject_params={"organization_id": org_id})


@organization_router.patch("/{org_id}/roles/{role_id}", summary="Update Role")
async def update_role(org_id: str, role_id: str, request: Request) -> Response:
    """Update a custom role."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/roles/{role_id}", inject_params={"organization_id": org_id})


@organization_router.delete("/{org_id}/roles/{role_id}", summary="Delete Role")
async def delete_role(org_id: str, role_id: str, request: Request) -> Response:
    """Delete a custom role."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/roles/{role_id}", inject_params={"organization_id": org_id})


# Members CRUD
@organization_router.get("/{org_id}/members", summary="List Members")
async def list_members(org_id: str, request: Request) -> Response:
    """List members of an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members", inject_params={"organization_id": org_id})


@organization_router.post("/{org_id}/members", summary="Add Member", status_code=201)
async def add_member(org_id: str, request: Request) -> Response:
    """Add a member to an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members", inject_params={"organization_id": org_id})


@organization_router.patch("/{org_id}/members/{member_id}", summary="Update Member")
async def update_member(org_id: str, member_id: str, request: Request) -> Response:
    """Update a member (e.g. change role)."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/{member_id}", inject_params={"organization_id": org_id})


@organization_router.delete("/{org_id}/members/{member_id}", summary="Remove Member")
async def remove_member(org_id: str, member_id: str, request: Request) -> Response:
    """Remove a member from an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/{member_id}", inject_params={"organization_id": org_id})


# Invites (pending invitations)
@organization_router.get("/{org_id}/invites", summary="List Invites")
async def list_invites(org_id: str, request: Request) -> Response:
    """List pending invites for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/invites", inject_params={"organization_id": org_id})


@organization_router.post("/{org_id}/invites", summary="Create Invite", status_code=201)
async def create_invite(org_id: str, request: Request) -> Response:
    """Create an invite for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/invites", inject_params={"organization_id": org_id})


@organization_router.post("/{org_id}/invites/{invite_id}/resend", summary="Resend Invite")
async def resend_invite(org_id: str, invite_id: str, request: Request) -> Response:
    """Resend an invite."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/invites/{invite_id}/resend", inject_params={"organization_id": org_id})


@organization_router.delete("/{org_id}/invites/{invite_id}", summary="Revoke Invite")
async def revoke_invite(org_id: str, invite_id: str, request: Request) -> Response:
    """Revoke a pending invite."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/invites/{invite_id}", inject_params={"organization_id": org_id})


# Transfer ownership
@organization_router.post("/{org_id}/transfer-ownership", summary="Transfer Ownership")
async def transfer_ownership(org_id: str, request: Request) -> Response:
    """Transfer organization ownership to another member."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/transfer-ownership", inject_params={"organization_id": org_id})


# Team snapshot (dashboard)
@organization_router.get("/{org_id}/team/snapshot", summary="Team Snapshot")
async def get_team_snapshot(org_id: str, request: Request) -> Response:
    """Get a team snapshot for dashboards."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/team/snapshot", inject_params={"organization_id": org_id})


# RBAC: Member role assignments
@organization_router.put("/{org_id}/members/{member_id}/roles", summary="Set Member Roles")
async def set_member_roles(org_id: str, member_id: str, request: Request) -> Response:
    """Replace all roles for a member."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/{member_id}/roles", inject_params={"organization_id": org_id})


@organization_router.post("/{org_id}/members/{member_id}/roles/{role_id}", summary="Add Role to Member")
async def add_member_role(org_id: str, member_id: str, role_id: str, request: Request) -> Response:
    """Add a role to a member."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/{member_id}/roles/{role_id}", inject_params={"organization_id": org_id})


@organization_router.delete("/{org_id}/members/{member_id}/roles/{role_id}", summary="Remove Role from Member")
async def remove_member_role(org_id: str, member_id: str, role_id: str, request: Request) -> Response:
    """Remove a role from a member."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/{member_id}/roles/{role_id}", inject_params={"organization_id": org_id})


# RBAC: Current user permissions
@organization_router.get("/{org_id}/members/me/permissions", summary="Get My Permissions")
async def get_my_permissions(org_id: str, request: Request) -> Response:
    """Get the current user's permissions in this organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/me/permissions", inject_params={"organization_id": org_id})


@organization_router.api_route(
    "/{org_id}/scim/v2/{scim_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    summary="SCIM 2.0 Proxy",
)
async def proxy_scim(org_id: str, scim_path: str, request: Request) -> Response:
    """Proxy org-scoped SCIM 2.0 requests to the organization service."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    upstream_path = f"/v1/organizations/{org_id}/scim/v2/{scim_path}" if scim_path else f"/v1/organizations/{org_id}/scim/v2"
    return await proxy_request(request, service_url, upstream_path, inject_params={"organization_id": org_id})


# =============================================================================
# Preferences Routes (Console Context)
# =============================================================================

# Pydantic models for preferences
class PreferencesResponse(BaseModel):
    """Console context preferences response."""
    last_view_mode: str = Field(description="Last selected view mode: 'applicant' or 'org_admin'")
    last_active_org_id: str | None = Field(description="Last active organization ID (null if none)")


class UpdatePreferencesRequest(BaseModel):
    """Request to update console context preferences (partial update)."""
    last_view_mode: str | None = Field(None, description="View mode to set: 'applicant' or 'org_admin'")
    last_active_org_id: str | None = Field(None, description="Organization ID to set as active (explicit null allowed)")


preferences_router = APIRouter(prefix="/v1/me", tags=["User Preferences"])


@preferences_router.get("/preferences", response_model=PreferencesResponse, summary="Get Console Context Preferences")
async def get_preferences(request: Request) -> Response:
    """
    Get current user's console context preferences.
    
    Returns existing preferences or defaults if none exist.
    """
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/me/preferences")


@preferences_router.put("/preferences", response_model=PreferencesResponse, summary="Update Console Context Preferences")
async def update_preferences(body: UpdatePreferencesRequest, request: Request) -> Response:
    """
    Update (upsert) current user's console context preferences.
    
    Partial update semantics:
    - Absent field: keep existing value
    - Field present as explicit null for last_active_org_id: set to null
    - Field present as null for last_view_mode: rejected with 400
    """
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/me/preferences")


# =============================================================================
# Health and Status
# =============================================================================

_session_cache: SessionCache | None = None

def get_session_cache() -> SessionCache:
    if _session_cache is None:
        raise RuntimeError("Service not configured")
    return _session_cache


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _registry, _http_client, _session_cache
    logger.info(f"Starting {SERVICE_NAME}...")
    _registry = ServiceRegistry()
    _http_client = httpx.AsyncClient()
    _session_cache = SessionCache(ttl_seconds=60)
    
    # Initialize Redis for membership caching
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    redis_db = int(os.environ.get("REDIS_DB_GATEWAY", "2"))  # Use DB 2 for gateway
    logger.info(f"Connecting to Redis at {redis_url}/{redis_db}")
    redis_client = aioredis.from_url(
        f"{redis_url}/{redis_db}",
        encoding="utf-8",
        decode_responses=True
    )
    
    # Initialize OrganizationClient for membership verification
    from common.grpc_factory import create_grpc_channel
    from marty_proto.v1.auth_service_pb2_grpc import AuthServiceStub
    
    auth_grpc_target = os.environ.get("AUTH_GRPC_TARGET", "localhost:9001")
    org_grpc_target = os.environ.get("ORG_GRPC_TARGET", "localhost:9002")
    
    auth_grpc_channel = create_grpc_channel(auth_grpc_target, service_name="gateway")
    org_grpc_channel = create_grpc_channel(org_grpc_target, service_name="gateway")
    auth_grpc_stub = AuthServiceStub(auth_grpc_channel)
    grpc_tls_enabled = bool(os.environ.get("GRPC_TLS_CA_CERT"))
    logger.info(
        "Gateway gRPC: auth→%s  org→%s  tls=%s",
        auth_grpc_target, org_grpc_target, grpc_tls_enabled,
    )

    # Event-stream gRPC channel for SSE bridging
    es_grpc_target = os.environ.get("ES_GRPC_TARGET", "event-stream:9015")
    es_grpc_channel = create_grpc_channel(es_grpc_target, service_name="gateway")
    app.state.es_grpc_channel = es_grpc_channel
    logger.info("Gateway gRPC: event-stream→%s", es_grpc_target)

    org_client = OrganizationClient(
        grpc_channel=org_grpc_channel,
        redis_client=redis_client,
        cache_ttl=120,
    )
    app.state.org_client = org_client
    app.state.redis_client = redis_client
    app.state.usage_tracker = UsageTracker(redis_client)
    app.state.auth_grpc_stub = auth_grpc_stub
    
    # Initialize Cedar policy engine
    cedar_schema_path = os.environ.get("CEDAR_SCHEMA_PATH")
    cedar_policies_dir = os.environ.get("CEDAR_POLICIES_DIR")
    if cedar_schema_path and cedar_policies_dir:
        cedar_engine = CedarEngine.from_files(cedar_schema_path, [cedar_policies_dir])
        logger.info(f"Cedar engine loaded from {cedar_schema_path}")
    else:
        cedar_engine = CedarEngine.with_defaults()
        logger.info("Cedar engine loaded with default MIP schema and gateway policies")
    app.state.cedar_engine = cedar_engine
    
    logger.info(f"{SERVICE_NAME} started successfully")
    yield
    
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await org_client.close()
    await auth_grpc_channel.close()
    await org_grpc_channel.close()
    await es_grpc_channel.close()
    await redis_client.aclose()
    await _http_client.aclose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Marty API Gateway",
        description="""
## Digital Identity Management API

The Marty API provides a complete platform for digital identity credential management,
following the Digital Identity model architecture.

### Configuration Resources

- **Trust Profiles** - Define who is trusted and how validation happens
- **Revocation Profiles** - Format-agnostic revocation configuration
- **Credential Templates** - Blueprint for credential structure and claims
- **Compliance Profiles** - Regulatory and policy rules
- **Presentation Policies** - Define what credentials to request for verification
- **Deployment Profiles** - Runtime configuration for different environments (including Lanes)

### Operational Resources

- **Flows** - Orchestrate multi-step credential operations (issuance and verification)
- **Issuance** - Issue credentials to holders
- **Applications** - Manage Application Templates and Application instances
- **Audit Events** - Track actions within Organizations

### Verification

Verification is handled through two complementary approaches:

- **Stateless Evaluation**: Use `POST /v1/presentation-policies/{id}/evaluate` to immediately verify a VP token against a policy
- **Async Wallet Flows**: Use `POST /v1/flows/verify` to start a verification flow with QR code / request_uri for wallet interactions

### Getting Started

1. Create an Organization
2. Configure a Trust Profile (who you trust)
3. Create a Credential Template (what to issue)
4. Create an Application Template and instance Application
5. Issue credentials (via Application or direct issuance)
6. Create a Presentation Policy and use `/evaluate` or start a Flow to verify
        """,
        version="1.0.0",
        lifespan=lifespan,
    )
    
    # CORS configuration: Use specific origins when credentials are enabled
    # Cannot use wildcard "*" with credentials per CORS spec
    allowed_origins = os.environ.get(
        "CORS_ORIGINS",
        "http://localhost:3000,https://beta.elevenidllc.com,http://localhost:5173"
    ).split(",")
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[origin.strip() for origin in allowed_origins],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )
    
    # Add auth middleware for session validation and user context injection.
    # NOTE: create_app() runs at import time, before lifespan() initializes globals.
    # So we bootstrap defaults here and let lifespan() refresh them at startup.
    global _registry, _session_cache
    if _registry is None:
        _registry = ServiceRegistry()
    if _session_cache is None:
        _session_cache = SessionCache(ttl_seconds=60)

    registry = _registry
    session_cache = _session_cache

    # Add Cedar auth middleware first, then auth middleware, then rate limiter,
    # then MIP version.  Starlette executes middleware in reverse registration
    # order, so this makes MIPVersionMiddleware run outermost.
    app.add_middleware(UsageTrackingMiddleware)
    app.add_middleware(CedarAuthMiddleware)
    app.add_middleware(ContentTypeEnforcementMiddleware)
    app.add_middleware(AuthMiddleware, session_cache=session_cache)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(MIPVersionMiddleware)
    
    # Include all routers
    app.include_router(trust_profile_router)
    app.include_router(organization_trust_profile_router)
    app.include_router(issuer_entity_router)
    app.include_router(trust_framework_router)
    app.include_router(trust_registry_router)
    app.include_router(api_key_router)
    app.include_router(revocation_profile_router)
    app.include_router(cascade_revocation_router)
    app.include_router(credential_template_router)
    app.include_router(wallet_registry_router)
    app.include_router(compliance_profile_router)
    app.include_router(device_router)
    app.include_router(presentation_policy_router)
    app.include_router(deployment_profile_router)
    app.include_router(flow_router)
    app.include_router(issued_credential_router)
    app.include_router(issuance_router)
    app.include_router(application_template_router)
    app.include_router(application_router)
    app.include_router(subscription_router)
    app.include_router(webhook_router)
    app.include_router(notification_router)
    app.include_router(policy_set_router)
    app.include_router(applicant_router)
    app.include_router(organization_router)
    app.include_router(preferences_router)
    
    # Auth service proxy - forward all /v1/auth/* requests to auth service
    @app.api_route("/v1/auth/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def proxy_auth_requests(request: Request, path: str) -> Response:
        """Proxy auth requests to the auth service.
        
        This handles login/logout redirects and session management.
        """
        registry = get_registry()
        auth_url = registry.get_service_url("auth")
        if not auth_url:
            return mip_error_response(status_code=503, error="service_unavailable", message="Auth service unavailable")
        
        # Clear session cache on logout to prevent stale sessions
        if path.startswith("logout"):
            session_id = request.cookies.get("sessionId")
            if session_id and _session_cache:
                _session_cache.clear(session_id)
        
        client = get_http_client()
        target_url = f"{auth_url}/v1/auth/{path}"
        
        # Forward query parameters
        if request.url.query:
            target_url += f"?{request.url.query}"
        
        # Get request body if present
        body = None
        if request.method in ["POST", "PUT", "PATCH"]:
            body = await request.body()
        
        # Forward headers (excluding hop-by-hop headers)
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in ("host", "connection", "keep-alive", "transfer-encoding")
        }
        
        try:
            # Forward request without following redirects (auth handles redirects)
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                follow_redirects=False,
                timeout=30.0,
            )
            
            # Return proxied response with all headers including Set-Cookie
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers={
                    k: v for k, v in response.headers.items()
                    if k.lower() not in ("content-encoding", "transfer-encoding")
                },
                media_type=response.headers.get("content-type"),
            )
        except httpx.ConnectError:
            logger.error(f"Auth service unavailable at {auth_url}")
            return mip_error_response(status_code=503, error="service_unavailable", message="Auth service unavailable")
        except httpx.TimeoutException:
            logger.error(f"Auth service timeout at {auth_url}")
            return mip_error_response(status_code=504, error="service_timeout", message="Auth service timeout")
        except Exception as e:
            logger.error(f"Error proxying auth request: {e}")
            return mip_error_response(status_code=502, error="auth_service_error", message="Auth service error")
    
    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": SERVICE_NAME}

    # ── Usage & billing analytics ────────────────────────────────────

    @app.get("/v1/usage")
    async def get_usage(request: Request, month: str | None = None) -> dict:
        """Get usage metrics for the authenticated user's organization."""
        org_id = getattr(request.state, "organization_id", None)
        if not org_id:
            return JSONResponse(status_code=401, content={"error": "Not authenticated"})
        tracker: UsageTracker | None = getattr(request.app.state, "usage_tracker", None)
        if not tracker:
            return {"metrics": {}, "plan": "free", "limits": {}}
        metrics = await tracker.get_all(org_id, month)
        plan_str = "free"
        redis_client = getattr(request.app.state, "redis_client", None)
        if redis_client:
            cached = await redis_client.get(f"org:{org_id}:plan")
            if cached:
                plan_str = cached
        try:
            plan = PlanTier(plan_str)
        except ValueError:
            plan = PlanTier.FREE
        limits = get_plan_limits(plan)
        info = PLAN_INFO[plan]
        return {
            "plan": plan.value,
            "plan_name": info.name,
            "plan_tagline": info.tagline,
            "metrics": metrics,
            "limits": {
                "verifications_per_month": limits.verifications_per_month,
                "issued_credentials_per_month": limits.issued_credentials_per_month,
                "active_flows": limits.active_flows,
                "members": limits.members,
            },
        }

    @app.get("/v1/usage/history")
    async def get_usage_history(request: Request, metric: str = "verifications", months: int = 6) -> dict:
        """Get historical usage for a metric over the last N months."""
        org_id = getattr(request.state, "organization_id", None)
        if not org_id:
            return JSONResponse(status_code=401, content={"error": "Not authenticated"})
        tracker: UsageTracker | None = getattr(request.app.state, "usage_tracker", None)
        if not tracker:
            return {"metric": metric, "history": {}}
        allowed_metrics = {"verifications", "issued_credentials", "api_calls", "active_flows"}
        if metric not in allowed_metrics:
            return JSONResponse(status_code=400, content={"error": f"Invalid metric. Use one of: {allowed_metrics}"})
        history = await tracker.get_history(org_id, metric, min(months, 12))
        return {"metric": metric, "history": history}

    @app.get("/v1/plans")
    async def list_plans() -> dict:
        """Return available plan tiers and their limits (public endpoint)."""
        plans = []
        for tier in PlanTier:
            info = PLAN_INFO[tier]
            limits = get_plan_limits(tier)
            plans.append({
                "tier": tier.value,
                "name": info.name,
                "tagline": info.tagline,
                "headline": info.headline,
                "price_monthly": info.price_monthly,
                "differentiator": info.differentiator,
                "limits": {
                    "verifications_per_month": limits.verifications_per_month,
                    "issued_credentials_per_month": limits.issued_credentials_per_month,
                    "active_flows": limits.active_flows,
                    "members": limits.members,
                    "credential_templates": limits.credential_templates,
                    "deployment_profiles": limits.deployment_profiles,
                },
                "features": {
                    "custom_branding": limits.custom_branding,
                    "webhooks": limits.webhooks,
                    "audit_logs": limits.audit_logs,
                    "multi_environment": limits.multi_environment,
                    "custom_cedar_policies": limits.custom_cedar_policies,
                    "scim_provisioning": limits.scim_provisioning,
                    "self_hosted": limits.self_hosted,
                    "zkp_verification": limits.zkp_verification,
                    "device_registration": limits.device_registration,
                },
            })
        return {"plans": plans}

    async def _proxy_to_issuance_well_known(path: str) -> Response:
        """Proxy a well-known request to the issuance service.

        The issuance service is the source of truth for OID4VCI metadata.
        Keeping gateway endpoints as a proxy avoids drift and ensures that
        per-org discovery (OID4VCI v1 §12.2.2 insertion rule) works end-to-end.
        """
        registry = get_registry()
        issuance_url = registry.get_service_url("issuance")
        if not issuance_url:
            raise HTTPException(status_code=503, detail="Issuance service unavailable")

        client = get_http_client()
        try:
            upstream = await client.get(f"{issuance_url}{path}", timeout=10.0)
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="Issuance service timeout")
        except Exception as exc:
            logger.error("Error proxying well-known to issuance (%s): %s", path, exc)
            raise HTTPException(status_code=502, detail="Issuance service error")

        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type"),
            headers={
                k: v
                for k, v in upstream.headers.items()
                if k.lower() not in ("content-encoding", "transfer-encoding")
            },
        )

    # ---------------------------------------------------------------------
    # OID4VCI v1 per-org discovery (insertion rule paths)
    # ---------------------------------------------------------------------

    @app.get("/.well-known/openid-credential-issuer/org/{org_id}")
    async def get_org_issuer_metadata(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/openid-credential-issuer/org/{org_id}")

    @app.get("/.well-known/oauth-authorization-server/org/{org_id}")
    async def get_org_oauth_authorization_server_metadata(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/oauth-authorization-server/org/{org_id}")

    # ---------------------------------------------------------------------
    # SpruceID / SpruceKit wallet — Spruce-specific issuer metadata.
    # credential_issuer = "https://host/org/{org_id}/spruce", so the SDK
    # appends /.well-known/openid-credential-issuer, producing:
    #   https://host/org/{org_id}/spruce/.well-known/openid-credential-issuer
    # nginx rewrites that to:
    #   /.well-known/openid-credential-issuer/org/{org_id}/spruce
    # Both the insertion form AND the appended form are handled here.
    # ---------------------------------------------------------------------

    @app.get("/.well-known/openid-credential-issuer/org/{org_id}/spruce")
    async def get_org_spruce_issuer_metadata(org_id: str) -> Response:
        """SpruceID insertion-form discovery: /.well-known/openid-credential-issuer/org/{org_id}/spruce"""
        return await _proxy_to_issuance_well_known(f"/.well-known/openid-credential-issuer/org/{org_id}/spruce")

    @app.get("/org/{org_id}/spruce/.well-known/openid-credential-issuer")
    async def get_org_spruce_issuer_metadata_appended(org_id: str) -> Response:
        """SpruceID appended-form discovery: /org/{org_id}/spruce/.well-known/openid-credential-issuer"""
        return await _proxy_to_issuance_well_known(f"/.well-known/openid-credential-issuer/org/{org_id}/spruce")

    @app.get("/.well-known/oauth-authorization-server/org/{org_id}/spruce")
    async def get_org_spruce_as_metadata(org_id: str) -> Response:
        """SpruceID insertion-form AS discovery: /.well-known/oauth-authorization-server/org/{org_id}/spruce"""
        return await _proxy_to_issuance_well_known(f"/.well-known/oauth-authorization-server/org/{org_id}/spruce")

    @app.get("/org/{org_id}/spruce/.well-known/oauth-authorization-server")
    async def get_org_spruce_as_metadata_appended(org_id: str) -> Response:
        """SpruceID appended-form AS discovery: /org/{org_id}/spruce/.well-known/oauth-authorization-server"""
        return await _proxy_to_issuance_well_known(f"/.well-known/oauth-authorization-server/org/{org_id}/spruce")

    # ---------------------------------------------------------------------
    # OID4VCI spec §11.2.2 "/.well-known/openid-credential-issuer" appended
    # to the credential_issuer URL (RFC 8414-style discovery).
    # When credential_issuer = "https://host/org/{org_id}", wallets fetch:
    #   https://host/org/{org_id}/.well-known/openid-credential-issuer
    # These two routes satisfy that pattern.
    # ---------------------------------------------------------------------

    @app.get("/org/{org_id}/.well-known/openid-credential-issuer")
    async def get_org_issuer_metadata_oid4vci_style(org_id: str) -> Response:
        """OID4VCI §11.2.2 discovery: <credential_issuer>/.well-known/openid-credential-issuer"""
        return await _proxy_to_issuance_well_known(f"/.well-known/openid-credential-issuer/org/{org_id}")

    @app.get("/org/{org_id}/.well-known/oauth-authorization-server")
    async def get_org_oauth_metadata_oid4vci_style(org_id: str) -> Response:
        """OID4VCI §11.2.2 discovery: <credential_issuer>/.well-known/oauth-authorization-server"""
        return await _proxy_to_issuance_well_known(f"/.well-known/oauth-authorization-server/org/{org_id}")
    
    @app.get("/.well-known/openid-credential-issuer")
    async def get_issuer_metadata() -> Response:
        """OID4VCI Issuer Metadata — proxied to the issuance service (source of truth)."""
        return await _proxy_to_issuance_well_known("/.well-known/openid-credential-issuer")

    @app.get("/.well-known/oauth-authorization-server")
    async def get_oauth_authorization_server_metadata() -> Response:
        """OAuth Authorization Server Metadata — proxied to the issuance service (source of truth)."""
        return await _proxy_to_issuance_well_known("/.well-known/oauth-authorization-server")

    @app.get("/.well-known/openid-configuration")
    async def get_openid_configuration() -> dict:
        """OIDC Discovery metadata (compatibility endpoint used by some wallets)."""
        issuer_url = os.environ.get("ISSUER_BASE_URL", "http://localhost:8000")
        return {
            "issuer": issuer_url,
            "authorization_endpoint": f"{issuer_url}/v1/issuance/authorize",
            "token_endpoint": f"{issuer_url}/v1/issuance/token",
            "jwks_uri": f"{issuer_url}/.well-known/jwks.json",
            "response_types_supported": ["code", "token", "id_token"],
            "subject_types_supported": ["public", "pairwise"],
            # SIOPv2 Draft 13 §6.1: Relying Party (Verifier) MUST advertise
            # the subject syntax types it supports.  jwk-thumbprint is required
            # for wallets that present self-issued credentials without a DID.
            "subject_syntax_types_supported": [
                "urn:ietf:params:oauth:jwk-thumbprint",
                "did:key",
                "did:jwk",
            ],
            "id_token_signing_alg_values_supported": ["EdDSA", "ES256"],
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            ],
            "token_endpoint_auth_methods_supported": ["none"],
        }

    @app.get("/.well-known/jwks.json")
    async def get_jwks() -> Response:
        """JWKS endpoint — proxy to issuance service for real signing keys."""
        return await _proxy_to_issuance_well_known("/.well-known/jwks.json")

    @app.get("/.well-known/mip-configuration")
    async def get_mip_configuration() -> dict:
        """MIP §10 — Every MIP implementation MUST expose this discovery endpoint.

        Returns active compliance profiles, supported versions, and API surface
        declarations so clients can discover available protocol capabilities.
        """
        issuer_url = os.environ.get("ISSUER_BASE_URL", "http://localhost:8000")
        registry = get_registry()

        # Gather active compliance profile codes from the compliance-profiles service
        active_profiles: list[dict] = []
        compliance_url = registry.get_service_url("compliance-profiles")
        if compliance_url:
            client = get_http_client()
            try:
                resp = await client.get(
                    f"{compliance_url}/v1/compliance-profiles",
                    params={"status": "active"},
                    timeout=5.0,
                )
                if resp.status_code == 200:
                    profiles_data = resp.json()
                    items = profiles_data if isinstance(profiles_data, list) else profiles_data.get("items", [])
                    for p in items:
                        entry: dict[str, Any] = {
                            "compliance_code": p.get("compliance_code"),
                            "credential_format": p.get("credential_format"),
                            "issuance_protocol": p.get("issuance_protocol"),
                        }
                        if p.get("api_surface"):
                            entry["api_surface"] = p["api_surface"]
                        active_profiles.append(entry)
            except Exception as exc:
                logger.warning("Failed to fetch compliance profiles for MIP config: %s", exc)

        return {
            "mip_version": "0.1",
            "supported_versions": ["0.1"],
            "issuer": issuer_url,
            "api_base_url": f"{issuer_url}/v1",
            "active_compliance_profiles": active_profiles,
            "supported_credential_formats": [
                "MDOC", "SD_JWT_VC", "VC_JWT", "JSON_LD", "ZK_MDOC",
            ],
            "supported_issuance_protocols": [
                "OID4VCI_PRE_AUTH", "OID4VCI_AUTH_CODE", "DIRECT",
            ],
            "endpoints": {
                "trust_profiles": f"{issuer_url}/v1/trust-profiles",
                "credential_templates": f"{issuer_url}/v1/credential-templates",
                "presentation_policies": f"{issuer_url}/v1/presentation-policies",
                "deployment_profiles": f"{issuer_url}/v1/deployment-profiles",
                "flows": f"{issuer_url}/v1/flows",
                "compliance_profiles": f"{issuer_url}/v1/compliance-profiles",
                "revocation_profiles": f"{issuer_url}/v1/revocation-profiles",
                "issued_credentials": f"{issuer_url}/v1/issued-credentials",
                "trust_registry": f"{issuer_url}/v1/trust-registry",
                "organizations": f"{issuer_url}/v1/organizations",
                "devices": f"{issuer_url}/v1/devices",
                "policy_sets": f"{issuer_url}/v1/policy-sets",
                "wallet_registry": f"{issuer_url}/v1/wallet-registry",
                "notifications": f"{issuer_url}/v1/notifications",
                "scim": f"{issuer_url}/v1/organizations/{{org_id}}/scim/v2",
            },
            "wallet_facing_endpoints": {
                "credential_offer": f"{issuer_url}/v1/issuance/offers/{{tx_id}}",
                "token": f"{issuer_url}/v1/issuance/token",
                "credential": f"{issuer_url}/v1/issuance/credential",
                "nonce": f"{issuer_url}/v1/issuance/nonce",
                "deferred_credential": f"{issuer_url}/v1/issuance/deferred-credential",
                "notification": f"{issuer_url}/v1/issuance/notification",
                "verification_request": f"{issuer_url}/v1/flows/instances/{{id}}/request",
                "verification_submit": f"{issuer_url}/v1/flows/instances/{{id}}/submit",
                "siop_request": f"{issuer_url}/v1/flows/siop/{{id}}/request",
                "siop_submit": f"{issuer_url}/v1/flows/siop/submit",
            },
            "authorization": {
                "policy_language": "cedar",
                "cedar_schema_version": "MIP/1.0",
            },
        }

    @app.get("/health/services")
    async def services_health() -> dict:
        """Check health of all backend services."""
        registry = get_registry()
        client = get_http_client()
        
        results = {}
        for service, url in registry.get_all_services().items():
            try:
                response = await client.get(f"{url}/health", timeout=5.0)
                results[service] = {
                    "status": "healthy" if response.status_code == 200 else "unhealthy",
                    "url": url,
                }
            except Exception as e:
                results[service] = {
                    "status": "unreachable",
                    "url": url,
                    "error": str(e),
                }
        
        return {"services": results}

    # ── MIP §17.7 — Global exception handlers ──────────────────────────
    @app.exception_handler(HTTPException)
    async def _http_exception_handler(request: Request, exc: HTTPException):
        """Wrap FastAPI HTTPException in MIP error envelope."""
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        error_key = {
            400: "bad_request",
            401: "unauthorized",
            403: "forbidden",
            404: "not_found",
            409: "conflict",
            415: "unsupported_media_type",
            422: "validation_error",
            429: "rate_limit_exceeded",
            500: "server_error",
            502: "bad_gateway",
            503: "service_unavailable",
            504: "gateway_timeout",
        }.get(exc.status_code, "error")
        return mip_error_response(
            status_code=exc.status_code,
            error=error_key,
            message=detail,
        )

    @app.exception_handler(RequestValidationError)
    async def _request_validation_error_handler(request: Request, exc: RequestValidationError):
        """Wrap Pydantic/FastAPI validation errors in MIP error envelope."""
        details = []
        for err in exc.errors():
            field = ".".join(str(loc) for loc in err.get("loc", []))
            details.append({"field": field, "message": err.get("msg", "")})
        return mip_error_response(
            status_code=422,
            error="validation_error",
            message="Request validation failed",
            extra={"details": details},
        )

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(request: Request, exc: Exception):
        """Catch-all: return 500 in MIP envelope, never leak stack traces."""
        logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
        return mip_error_response(
            status_code=500,
            error="server_error",
            message="An unexpected error occurred",
        )

    from common.metrics import init_otel_tracing, mount_metrics
    init_otel_tracing(SERVICE_NAME)
    mount_metrics(app)
    
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("gateway.main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
