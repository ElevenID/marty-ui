"""
Gateway Middleware and MIP error helpers.

Contains SessionCache, AuthMiddleware, MIPVersionMiddleware,
RateLimitMiddleware, ContentTypeEnforcementMiddleware, and the
MIP §17.7 error-response builder.
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
import uuid as _uuid
from collections import defaultdict
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from gateway.registry import get_route_config

logger = logging.getLogger(__name__)


# =============================================================================
# Session Cache
# =============================================================================

class SessionCache:
    """Simple in-memory cache for session validation with TTL."""

    def __init__(self, ttl_seconds: int = 60, maxsize: int = 10_000):
        self._cache: dict[str, tuple[dict, float]] = {}
        self._ttl_seconds = ttl_seconds
        self._maxsize = maxsize

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
        # Evict expired entries and enforce maxsize
        if len(self._cache) >= self._maxsize:
            now = time.time()
            expired = [k for k, (_, exp) in self._cache.items() if now > exp]
            for k in expired:
                del self._cache[k]
            # If still over limit, evict oldest entries
            if len(self._cache) >= self._maxsize:
                oldest = sorted(self._cache, key=lambda k: self._cache[k][1])
                for k in oldest[: len(self._cache) - self._maxsize + 1]:
                    del self._cache[k]
        expires_at = time.time() + self._ttl_seconds
        self._cache[session_id] = (data, expires_at)

    def clear(self, session_id: str) -> None:
        """Clear cached session."""
        self._cache.pop(session_id, None)


# =============================================================================
# MIP Version Constants
# =============================================================================

MIP_VERSION = "0.3.1"
MIP_SUPPORTED_VERSIONS = ["0.3.1"]


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
# Auth Middleware
# =============================================================================

class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware that validates sessions via gRPC and injects user context headers."""

    def __init__(self, app, session_cache: SessionCache):
        super().__init__(app)
        self.session_cache = session_cache
        self.api_key_cache = SessionCache(ttl_seconds=int(os.environ.get("API_KEY_AUTH_CACHE_TTL", "30")))

    async def dispatch(self, request: Request, call_next):
        """Process request and inject user context headers."""
        import re as _re
        # Get route configuration
        route_config = get_route_config(request.url.path)

        # OID4VP wallet-facing endpoints must be public (wallet has no session cookie)
        _WALLET_PUBLIC = _re.compile(
            r"^/v1/flows/instances/[^/]+/(request|submit)$"
        )
        _STATUS_LIST_PUBLIC = _re.compile(
            r"^/v1/organizations/[^/]+/revocation-profiles/[^/]+/status-lists/[^/]+/[^/]+$"
        )

        # Skip auth for unauthenticated routes or health checks
        if (
            not route_config
            or not route_config.get("requires_auth", False)
            or request.url.path == "/health"
            or request.url.path.startswith("/health/")
            or request.url.path.startswith("/.well-known/")
            or request.url.path.startswith("/credentials/")
            or request.url.path.endswith("/did.json")
            or _WALLET_PUBLIC.match(request.url.path)
            or _STATUS_LIST_PUBLIC.match(request.url.path)
        ):
            return await call_next(request)

        api_key = self._extract_api_key(request)
        if api_key:
            try:
                api_key_data = await self._validate_api_key(request, api_key)
            except Exception as exc:
                logger.error("Error validating API key: %s", exc)
                return mip_error_response(
                    status_code=503,
                    error="service_unavailable",
                    message="Organization service unavailable",
                )
            if api_key_data is None:
                return mip_error_response(
                    status_code=401,
                    error="unauthorized",
                    message="Invalid or expired API key",
                )
            self._inject_api_key_context(request, api_key_data)
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
        request.state.session_organization_id = user_data.get("organization_id")

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

    @staticmethod
    def _extract_api_key(request: Request) -> str | None:
        header_key = request.headers.get("x-api-key")
        if header_key and header_key.strip():
            return header_key.strip()

        authorization = request.headers.get("authorization") or ""
        if not authorization.lower().startswith("bearer "):
            return None
        token = authorization[7:].strip()
        if token.startswith(("mk_live_", "mk_test_", "pk_live_", "pk_test_")):
            return token
        return None

    async def _validate_api_key(self, request: Request, api_key: str) -> dict | None:
        cache_key = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        cached = self.api_key_cache.get(cache_key)
        if cached:
            return cached

        org_client = getattr(request.app.state, "org_client", None)
        if org_client is None:
            logger.error("Organization client unavailable for API-key authentication")
            raise RuntimeError("Organization client unavailable")

        api_ctx = await org_client.validate_api_key(api_key)
        if not api_ctx:
            return None

        api_key_data = {
            "api_key_id": api_ctx.api_key_id,
            "organization_id": api_ctx.organization_id,
            "key_prefix": api_ctx.key_prefix,
            "scopes": list(api_ctx.scopes or []),
        }
        self.api_key_cache.set(cache_key, api_key_data)
        return api_key_data

    @staticmethod
    def _inject_api_key_context(request: Request, api_key_data: dict) -> None:
        api_key_id = api_key_data.get("api_key_id") or "unknown"
        organization_id = api_key_data.get("organization_id")
        request.state.auth_source = "api_key"
        request.state.api_key_id = api_key_id
        request.state.api_key_prefix = api_key_data.get("key_prefix")
        request.state.api_key_scopes = list(api_key_data.get("scopes") or [])
        request.state.api_key_organization_id = organization_id
        request.state.user_id = f"api_key:{api_key_id}"
        request.state.user_email = None
        request.state.user_domain = None
        request.state.session_organization_id = organization_id
        request.state.organization_id = organization_id


# =============================================================================
# MIP Version Middleware
# =============================================================================

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
# MIP §20.4 — Rate Limiting (MUST for all public-facing endpoints)
# =============================================================================

_RATE_LIMIT_RPM = int(os.environ.get("RATE_LIMIT_RPM", "120"))
_RATE_LIMIT_BURST = int(os.environ.get("RATE_LIMIT_BURST", "20"))
_RATE_LIMIT_WINDOW = 60


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
        """Atomic sliding-window check via Redis Lua script. Returns (allowed, remaining)."""
        now = time.time()
        window_start = now - _RATE_LIMIT_WINDOW
        member = f"{now}:{_uuid.uuid4().hex[:8]}"
        lua = """
        redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[1])
        local count = redis.call('ZCARD', KEYS[1])
        if count < tonumber(ARGV[2]) then
            redis.call('ZADD', KEYS[1], ARGV[3], ARGV[4])
            redis.call('EXPIRE', KEYS[1], tonumber(ARGV[5]))
            return count
        end
        return -1
        """
        result = await redis_client.eval(
            lua, 1, key,
            str(window_start), str(_RATE_LIMIT_RPM),
            str(now), member, str(int(_RATE_LIMIT_WINDOW) + 1),
        )
        if result == -1:
            return False, 0
        return True, max(0, _RATE_LIMIT_RPM - int(result) - 1)

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

        # Rate limiting disabled when RPM is 0 (dev/test mode)
        if _RATE_LIMIT_RPM <= 0:
            return await call_next(request)

        client_key = self._client_key(request)
        bucket = self._bucket_name(request.url.path)
        rate_key = f"mip:rl:{client_key}:{bucket}"

        redis_client = getattr(request.app.state, "redis_client", None)
        if redis_client:
            try:
                allowed, remaining = await self._check_redis(redis_client, rate_key)
            except Exception:
                logger.warning("Redis rate limit check failed, falling back to local", exc_info=True)
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
        "/v1/issuance/par",         # PAR endpoint (RFC 9126): application/x-www-form-urlencoded
        "/v1/issuance/nonce",       # OID4VCI nonce endpoint: wallets may POST empty/non-JSON bodies
        "/v1/issuance/didcomm/",    # DIDComm v2: application/didcomm-plain+json
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
