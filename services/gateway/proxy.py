"""
Proxy implementation and shared HTTP client / registry globals.

Provides ``proxy_request`` and resource-existence helpers used by
all gateway route modules.
"""
from __future__ import annotations

import logging
from urllib.parse import parse_qsl, urlencode

import httpx
from fastapi import Request, Response
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from gateway.middleware import SessionCache, mip_error_response
from gateway.registry import ServiceRegistry

logger = logging.getLogger(__name__)


# =============================================================================
# Module-level globals (set by lifespan in main.py)
# =============================================================================

_registry: ServiceRegistry | None = None
_http_client: httpx.AsyncClient | None = None
_session_cache: SessionCache | None = None


def get_registry() -> ServiceRegistry:
    if _registry is None:
        raise RuntimeError("Service not configured")
    return _registry


def get_http_client() -> httpx.AsyncClient:
    if _http_client is None:
        raise RuntimeError("Service not configured")
    return _http_client


def get_session_cache() -> SessionCache:
    if _session_cache is None:
        raise RuntimeError("Service not configured")
    return _session_cache


# =============================================================================
# Proxy helpers
# =============================================================================

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


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=0.5, min=0.5, max=4),
    retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException)),
    reraise=True,
)
async def _request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict,
    body: bytes,
) -> httpx.Response:
    """Execute an HTTP request with exponential-backoff retry on transient errors."""
    return await client.request(
        method=method,
        url=url,
        headers=headers,
        content=body,
        timeout=30.0,
    )


async def proxy_request(
    request: Request,
    service_url: str,
    path: str,
    inject_params: dict | None = None,
    body_override: bytes | None = None,
    inject_headers: dict | None = None,
) -> Response:
    """Proxy a request to a backend service.

    Args:
        request: The incoming FastAPI request.
        service_url: Base URL of the target micro-service.
        path: Path to append to the service URL.
        inject_params: Extra query parameters to merge into the forwarded URL.
            These are appended *in addition to* any query params already present
            on the incoming request, and they override duplicate keys.
        inject_headers: Extra headers to add to the proxied request.
    """
    client = get_http_client()

    # Build target URL
    url = f"{service_url}{path}"
    # Forward incoming query string, then overlay inject_params
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

    if inject_headers:
        headers.update(inject_headers)

    _RETRYABLE_METHODS = {"GET", "HEAD", "OPTIONS", "PUT", "DELETE"}
    _MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MB

    try:
        if request.method.upper() in _RETRYABLE_METHODS:
            response = await _request_with_retry(client, request.method, url, headers, body)
        else:
            response = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=body,
                timeout=30.0,
            )

        if len(response.content) > _MAX_RESPONSE_BYTES:
            logger.warning(
                "Response from %s exceeded size cap (%d bytes)",
                url, len(response.content),
            )
            return mip_error_response(
                status_code=502,
                error="response_too_large",
                message="Downstream response exceeded size limit",
            )

        # Return proxied response
        if response.status_code >= 400:
            # Normalize downstream error responses to MIP envelope format
            try:
                err_body = response.json()
            except Exception:
                logger.debug("Failed to parse error response body as JSON from %s (status %d)", url, response.status_code)
                err_body = {}
            if "error" in err_body and "error_description" in err_body:
                # Already MIP-format — pass through unchanged
                pass
            else:
                # Wrap FastAPI-style {"detail": "..."} or unknown formats
                detail = err_body.get("detail") if isinstance(err_body, dict) else None
                return mip_error_response(
                    status_code=response.status_code,
                    error=err_body.get("error", "service_error"),
                    message=detail or response.text[:200],
                    details=err_body.get("details"),
                )
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
