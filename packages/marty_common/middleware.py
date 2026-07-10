"""
Common Middleware

Shared middleware components for Marty microservices.
"""

from __future__ import annotations

import base64
import asyncio
from contextlib import suppress
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

    __slots__ = ("status_code", "body", "content_type", "headers", "created_at", "request_hash")

    def __init__(
        self,
        status_code: int,
        body: bytes,
        content_type: str | None,
        request_hash: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.body = body
        self.content_type = content_type
        self.headers = headers or {}
        self.created_at = time.monotonic()
        self.request_hash = request_hash


class IdempotencyMiddleware(BaseHTTPMiddleware):
    """
    RFC-style idempotency key support for mutating endpoints.

    Clients supply an ``Idempotency-Key`` header on POST/PUT/PATCH requests.
    * First request with a given key is processed normally and the response
      is cached in Redis when available, otherwise in memory for *ttl* seconds.
    * Subsequent requests with the **same key and same method/path/query/body**
      receive the cached response immediately (replay).
    * Subsequent requests with the **same key but a different request
      fingerprint** receive ``409 Conflict`` (misuse).

    Redis-backed storage is preferred for gateway/production deployments. The
    process-local ``dict`` remains as a local/dev fallback.
    """

    HEADER = "Idempotency-Key"
    REPLAY_HEADER = "Idempotency-Replayed"
    _REDIS_PREFIX = "idempotency"
    _LOCK_TTL = 300

    def __init__(self, app: Any, *, ttl: int = _IDEMPOTENCY_TTL) -> None:
        super().__init__(app)
        self.ttl = ttl
        self._cache: dict[str, _CachedResponse] = {}
        self._inflight: dict[str, str] = {}
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

    @classmethod
    def _request_hash(cls, request: Request, body: bytes) -> str:
        target = "\n".join(
            [
                request.method.upper(),
                request.url.path,
                request.url.query,
                cls._body_hash(body),
            ]
        )
        return hashlib.sha256(target.encode()).hexdigest()

    @staticmethod
    def _cache_namespace(request: Request, idem_key: str) -> str:
        user_id = (
            getattr(request.state, "user_id", None)
            or request.headers.get("X-User-ID")
            or "anonymous"
        )
        return f"{user_id}:{idem_key}"

    @classmethod
    def _redis_keys(cls, cache_key: str) -> tuple[str, str]:
        digest = hashlib.sha256(cache_key.encode()).hexdigest()
        data_key = f"{cls._REDIS_PREFIX}:{digest}"
        return data_key, f"{data_key}:lock"

    @staticmethod
    def _conflict_response() -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={
                "error": "idempotency_conflict",
                "error_description": (
                    "Idempotency-Key has already been used with a different request"
                ),
            },
        )

    @staticmethod
    def _in_progress_response() -> JSONResponse:
        response = JSONResponse(
            status_code=409,
            content={
                "error": "idempotency_in_progress",
                "error_description": (
                    "An operation with this Idempotency-Key is already in progress. "
                    "Retry with the same key after the first request completes."
                ),
            },
        )
        response.headers["Retry-After"] = "1"
        return response

    @staticmethod
    def _serialise_lock(request_hash: str, token: str) -> str:
        return json.dumps({"request_hash": request_hash, "token": token}, separators=(",", ":"))

    @staticmethod
    def _deserialise_lock(payload: Any) -> dict[str, str]:
        if isinstance(payload, bytes):
            payload = payload.decode()
        if not isinstance(payload, str) or not payload:
            return {}
        try:
            data = json.loads(payload)
            if isinstance(data, dict):
                return {
                    "request_hash": str(data.get("request_hash") or data.get("body_hash") or ""),
                    "token": str(data.get("token") or ""),
                }
        except Exception:
            return {"request_hash": str(payload), "token": ""}
        return {}

    async def _renew_redis_lock(self, redis_client: Any, lock_key: str, lock_token: str) -> None:
        interval = max(1, min(30, self._LOCK_TTL // 3))
        while True:
            await asyncio.sleep(interval)
            current = self._deserialise_lock(await redis_client.get(lock_key))
            if current.get("token") != lock_token:
                return
            expire = getattr(redis_client, "expire", None)
            if expire is None:
                continue
            try:
                await expire(lock_key, self._LOCK_TTL)
            except Exception:
                logger.warning("Failed to renew idempotency lock", exc_info=True)
                return

    async def _release_redis_lock(self, redis_client: Any, lock_key: str, lock_token: str) -> None:
        release_script = """
        local current = redis.call("GET", KEYS[1])
        if not current then
          return 0
        end
        local ok, data = pcall(cjson.decode, current)
        if ok and data["token"] == ARGV[1] then
          return redis.call("DEL", KEYS[1])
        end
        return 0
        """
        try:
            evaluate = getattr(redis_client, "eval", None)
            if evaluate is not None:
                await evaluate(release_script, 1, lock_key, lock_token)
                return
        except Exception:
            logger.debug("Redis lock release script failed; falling back to compare/delete", exc_info=True)

        current = self._deserialise_lock(await redis_client.get(lock_key))
        if current.get("token") == lock_token:
            await redis_client.delete(lock_key)

    @classmethod
    def _response_from_cached(cls, cached: _CachedResponse) -> Response:
        headers = dict(cached.headers)
        headers[cls.REPLAY_HEADER] = "true"
        return Response(
            content=cached.body,
            status_code=cached.status_code,
            media_type=cached.content_type,
            headers=headers,
        )

    @staticmethod
    def _serialise_cached(cached: _CachedResponse) -> str:
        return json.dumps(
            {
                "status_code": cached.status_code,
                "body": base64.b64encode(cached.body).decode(),
                "content_type": cached.content_type,
                "request_hash": cached.request_hash,
                "headers": cached.headers,
            },
            separators=(",", ":"),
        )

    @staticmethod
    def _deserialise_cached(payload: Any) -> _CachedResponse | None:
        if isinstance(payload, bytes):
            payload = payload.decode()
        if not isinstance(payload, str) or not payload:
            return None
        try:
            data = json.loads(payload)
            return _CachedResponse(
                status_code=int(data["status_code"]),
                body=base64.b64decode(data["body"]),
                content_type=data.get("content_type"),
                request_hash=str(data.get("request_hash") or data.get("body_hash")),
                headers=data.get("headers") if isinstance(data.get("headers"), dict) else {},
            )
        except Exception:
            logger.warning("Invalid idempotency cache payload", exc_info=True)
            return None

    @staticmethod
    async def _collect_response(response: Response) -> tuple[bytes, dict[str, str]]:
        resp_body = b""
        async for chunk in response.body_iterator:  # type: ignore[union-attr]
            resp_body += chunk if isinstance(chunk, bytes) else chunk.encode()
        return resp_body, dict(response.headers)

    async def _dispatch_redis(
        self,
        request: Request,
        call_next: Callable,
        *,
        redis_client: Any,
        cache_key: str,
        request_hash: str,
    ) -> Response:
        data_key, lock_key = self._redis_keys(cache_key)
        cached = self._deserialise_cached(await redis_client.get(data_key))
        if cached is not None:
            if cached.request_hash != request_hash:
                return self._conflict_response()
            return self._response_from_cached(cached)

        lock_token = uuid.uuid4().hex
        lock_acquired = await redis_client.set(
            lock_key,
            self._serialise_lock(request_hash, lock_token),
            ex=self._LOCK_TTL,
            nx=True,
        )
        if not lock_acquired:
            lock_state = self._deserialise_lock(await redis_client.get(lock_key))
            if lock_state.get("request_hash") and lock_state.get("request_hash") != request_hash:
                return self._conflict_response()
            return self._in_progress_response()

        renew_task = asyncio.create_task(self._renew_redis_lock(redis_client, lock_key, lock_token))
        try:
            response = await call_next(request)
            if 200 <= response.status_code < 300:
                resp_body, headers = await self._collect_response(response)
                cached = _CachedResponse(
                    status_code=response.status_code,
                    body=resp_body,
                    content_type=response.media_type,
                    request_hash=request_hash,
                    headers=headers,
                )
                await redis_client.setex(data_key, self.ttl, self._serialise_cached(cached))
                return Response(
                    content=resp_body,
                    status_code=response.status_code,
                    media_type=response.media_type,
                    headers=headers,
                )
            return response
        finally:
            renew_task.cancel()
            with suppress(asyncio.CancelledError):
                await renew_task
            try:
                await self._release_redis_lock(redis_client, lock_key, lock_token)
            except Exception:
                logger.warning("Failed to release idempotency lock", exc_info=True)

    # -- dispatch ---------------------------------------------------------

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.method not in _IDEMPOTENCY_METHODS:
            return await call_next(request)

        idem_key = request.headers.get(self.HEADER)
        if not idem_key:
            return await call_next(request)

        cache_key = self._cache_namespace(request, idem_key)
        body = await request.body()
        request_hash = self._request_hash(request, body)

        request_app = getattr(request, "app", None)
        redis_client = getattr(getattr(request_app, "state", None), "redis_client", None)
        if redis_client is not None:
            return await self._dispatch_redis(
                request,
                call_next,
                redis_client=redis_client,
                cache_key=cache_key,
                request_hash=request_hash,
            )

        self._evict_expired()

        cached = self._cache.get(cache_key)
        if cached is not None:
            # Same key, different payload → conflict
            if cached.request_hash != request_hash:
                return self._conflict_response()
            # Replay cached response
            return self._response_from_cached(cached)

        if cache_key in self._inflight:
            if self._inflight[cache_key] != request_hash:
                return self._conflict_response()
            return self._in_progress_response()

        self._inflight[cache_key] = request_hash
        try:
            response = await call_next(request)

            if 200 <= response.status_code < 300:
                resp_body, headers = await self._collect_response(response)
                self._cache[cache_key] = _CachedResponse(
                    status_code=response.status_code,
                    body=resp_body,
                    content_type=response.media_type,
                    request_hash=request_hash,
                    headers=headers,
                )
                return Response(
                    content=resp_body,
                    status_code=response.status_code,
                    media_type=response.media_type,
                    headers=headers,
                )

            return response
        finally:
            self._inflight.pop(cache_key, None)


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
