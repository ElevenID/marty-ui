"""
Common Middleware

Shared middleware components for Marty microservices.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from typing import Any, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)


class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware that ensures every request has a unique request ID.
    
    The request ID is:
    - Extracted from X-Request-ID header if present
    - Generated if not present
    - Added to response headers
    - Available in request.state.request_id
    """
    
    HEADER_NAME = "X-Request-ID"
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Get or generate request ID
        request_id = request.headers.get(self.HEADER_NAME)
        if not request_id:
            request_id = str(uuid.uuid4())
        
        # Store in request state for use in handlers
        request.state.request_id = request_id
        
        # Process request
        response = await call_next(request)
        
        # Add request ID to response headers
        response.headers[self.HEADER_NAME] = request_id
        
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for logging request/response information.
    
    Logs:
    - Request method, path, and timing
    - Response status code
    - Request ID for correlation
    """
    
    def __init__(self, app, service_name: str = "service"):
        super().__init__(app)
        self.service_name = service_name
        self.logger = logging.getLogger(f"{service_name}.requests")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.time()
        request_id = getattr(request.state, "request_id", "unknown")
        
        # Log request
        self.logger.info(
            "Request started",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "query": str(request.query_params),
                "client_ip": request.client.host if request.client else "unknown",
            }
        )
        
        # Process request
        response = await call_next(request)
        
        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000
        
        # Log response
        log_level = logging.INFO if response.status_code < 400 else logging.WARNING
        self.logger.log(
            log_level,
            "Request completed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
            }
        )
        
        return response


class UserContextMiddleware(BaseHTTPMiddleware):
    """
    Middleware that extracts user context from gateway-injected headers.
    
    Expects headers:
    - X-User-ID: User's unique identifier
    - X-Organization-ID: User's organization
    - X-User-Email: User's email
    - X-User-Roles: Comma-separated list of roles
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Extract user context from headers (injected by gateway)
        user_id = request.headers.get("X-User-ID")
        organization_id = request.headers.get("X-Organization-ID")
        user_email = request.headers.get("X-User-Email")
        user_roles_header = request.headers.get("X-User-Roles", "")
        user_roles = [r.strip() for r in user_roles_header.split(",") if r.strip()]
        
        # Store in request state
        request.state.user_id = user_id
        request.state.organization_id = organization_id
        request.state.user_email = user_email
        request.state.user_roles = user_roles
        
        # Create user context dict for convenience
        if user_id:
            request.state.user = {
                "user_id": user_id,
                "organization_id": organization_id,
                "email": user_email,
                "roles": user_roles,
            }
        else:
            request.state.user = None
        
        return await call_next(request)


def get_request_id(request: Request) -> str:
    """Get the request ID from request state."""
    return getattr(request.state, "request_id", str(uuid.uuid4()))


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add standard defensive security headers to every response."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "font-src 'self'; "
            "object-src 'none'; "
            "frame-src 'none';"
        )
        return response


def get_current_user(request: Request) -> dict | None:
    """Get the current user from request state."""
    return getattr(request.state, "user", None)


def require_authenticated(request: Request) -> dict:
    """Require authenticated user, raise if not present."""
    from fastapi import HTTPException
    
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_organization(request: Request) -> str:
    """Require organization context, raise if not present."""
    from fastapi import HTTPException
    
    user = require_authenticated(request)
    org_id = user.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=403, detail="Organization context required")
    return org_id


# ---------------------------------------------------------------------------
#  Idempotency middleware  (H35)
# ---------------------------------------------------------------------------

_IDEMPOTENCY_METHODS = {"POST", "PUT", "PATCH"}
_IDEMPOTENCY_TTL = 86_400  # 24 hours


class _CachedResponse:
    """Lightweight container for a previously-seen response."""

    __slots__ = ("status_code", "body", "content_type", "created_at", "body_hash")

    def __init__(
        self,
        status_code: int,
        body: bytes,
        content_type: str | None,
        body_hash: str,
    ) -> None:
        self.status_code = status_code
        self.body = body
        self.content_type = content_type
        self.created_at = time.monotonic()
        self.body_hash = body_hash


class IdempotencyMiddleware(BaseHTTPMiddleware):
    """
    RFC-style idempotency key support for mutating endpoints.

    Clients supply an ``Idempotency-Key`` header on POST/PUT/PATCH requests.
    * First request with a given key is processed normally and the response
      is cached in-memory for *ttl* seconds.
    * Subsequent requests with the **same key and same body hash** receive
      the cached response immediately (replay).
    * Subsequent requests with the **same key but a different body hash**
      receive ``409 Conflict`` (misuse).

    The cache is process-local (``dict``); for multi-worker deploys an
    external store (Redis) should replace ``_cache``.
    """

    HEADER = "Idempotency-Key"

    def __init__(self, app: Any, *, ttl: int = _IDEMPOTENCY_TTL) -> None:
        super().__init__(app)
        self.ttl = ttl
        self._cache: dict[str, _CachedResponse] = {}
        self._last_eviction = time.monotonic()

    # -- helpers ----------------------------------------------------------

    def _evict_expired(self) -> None:
        now = time.monotonic()
        if now - self._last_eviction < 600:  # run at most every 10 min
            return
        self._last_eviction = now
        expired = [
            k for k, v in self._cache.items() if now - v.created_at > self.ttl
        ]
        for k in expired:
            del self._cache[k]

    @staticmethod
    def _body_hash(body: bytes) -> str:
        return hashlib.sha256(body).hexdigest()

    # -- dispatch ---------------------------------------------------------

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method not in _IDEMPOTENCY_METHODS:
            return await call_next(request)

        idem_key = request.headers.get(self.HEADER)
        if not idem_key:
            return await call_next(request)

        # Namespace per user to prevent cross-tenant replays
        user_id = getattr(request.state, "user_id", None) or ""
        cache_key = f"{user_id}:{idem_key}"

        body = await request.body()
        body_hash = self._body_hash(body)

        self._evict_expired()

        cached = self._cache.get(cache_key)
        if cached is not None:
            # Same key, different payload → conflict
            if cached.body_hash != body_hash:
                return JSONResponse(
                    status_code=409,
                    content={
                        "error": "idempotency_conflict",
                        "error_description": (
                            "Idempotency-Key has already been used with a "
                            "different request body"
                        ),
                    },
                )
            # Replay cached response
            resp = Response(
                content=cached.body,
                status_code=cached.status_code,
                media_type=cached.content_type,
            )
            resp.headers["Idempotency-Replayed"] = "true"
            return resp

        # Process normally
        response = await call_next(request)

        # Cache successful responses (2xx)
        if 200 <= response.status_code < 300:
            resp_body = b""
            async for chunk in response.body_iterator:  # type: ignore[union-attr]
                resp_body += chunk if isinstance(chunk, bytes) else chunk.encode()
            self._cache[cache_key] = _CachedResponse(
                status_code=response.status_code,
                body=resp_body,
                content_type=response.media_type,
                body_hash=body_hash,
            )
            return Response(
                content=resp_body,
                status_code=response.status_code,
                media_type=response.media_type,
                headers=dict(response.headers),
            )

        return response


# ---------------------------------------------------------------------------
#  ETag middleware  (M70)
# ---------------------------------------------------------------------------


class ETagMiddleware(BaseHTTPMiddleware):
    """
    Automatic ETag support for GET responses.

    * Generates a weak ETag (``W/"<sha256-prefix>"``) from the response body.
    * Returns ``304 Not Modified`` when the client sends a matching
      ``If-None-Match`` header, saving bandwidth.
    * Only applies to successful (2xx) GET responses with a body.
    * Skips authenticated requests and responses that explicitly opt out of
      caching via ``Cache-Control``.
    """

    _AUTH_REQUEST_HEADERS = ("authorization", "cookie")
    _DISABLE_CACHE_CONTROL_TOKENS = ("no-store", "no-cache", "private")

    @classmethod
    def _is_authenticated_request(cls, request: Request) -> bool:
        return any(request.headers.get(header_name) for header_name in cls._AUTH_REQUEST_HEADERS)

    @classmethod
    def _cache_control_disables_etag(cls, response: Response) -> bool:
        cache_control = (response.headers.get("Cache-Control") or "").lower()
        return any(token in cache_control for token in cls._DISABLE_CACHE_CONTROL_TOKENS)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method != "GET" or self._is_authenticated_request(request):
            return await call_next(request)

        if_none_match = request.headers.get("If-None-Match")

        response = await call_next(request)

        # Only compute ETags for successful JSON-ish responses
        if not (200 <= response.status_code < 300):
            return response

        if self._cache_control_disables_etag(response):
            return response

        # Collect response body
        body = b""
        async for chunk in response.body_iterator:  # type: ignore[union-attr]
            body += chunk if isinstance(chunk, bytes) else chunk.encode()

        # Generate weak ETag from content hash
        etag = f'W/"{hashlib.sha256(body).hexdigest()[:16]}"'

        if if_none_match and if_none_match == etag:
            return Response(status_code=304, headers={"ETag": etag})

        return Response(
            content=body,
            status_code=response.status_code,
            media_type=response.media_type,
            headers={**dict(response.headers), "ETag": etag},
        )
