"""
Client Error Reporting API.

This module provides an endpoint for the UI to report client-side errors
(JavaScript errors, React component crashes, etc.) to the backend for
monitoring and debugging.

The endpoint is rate-limited to prevent abuse (10 errors per minute per IP).
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

try:
    from marty_plugin.common.errors import (
        ClientErrorAcknowledgment,
        ClientErrorReport,
        ErrorCode,
        ErrorDetail,
        ErrorRecoveryAction,
        ErrorResponse,
        ErrorSeverity,
        get_request_id,
    )
except ImportError:
    # Fallback for standalone testing
    from dataclasses import dataclass
    
    @dataclass
    class ClientErrorReport:
        error_code: str
        message: str
        url: str
        stack_trace: str | None = None
        component_stack: str | None = None
        user_agent: str | None = None
        user_id: str | None = None
        session_id: str | None = None
        timestamp: float | None = None
        context: dict | None = None
    
    @dataclass
    class ClientErrorAcknowledgment:
        received: bool
        error_id: str

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["Client Errors"])


# =============================================================================
# Rate Limiting
# =============================================================================

# In-memory rate limit store (for development/single-instance deployments)
# In production, this should use Redis
_rate_limit_store: dict[str, list[float]] = {}

# Rate limit configuration
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_REQUESTS = 10


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, handling proxies."""
    # Check X-Forwarded-For header (common with reverse proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the chain (original client)
        return forwarded_for.split(",")[0].strip()
    
    # Check X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Fall back to direct client IP
    if request.client:
        return request.client.host
    
    return "unknown"


def _check_rate_limit(client_ip: str) -> tuple[bool, int, int]:
    """
    Check if client is within rate limit.
    
    Returns:
        Tuple of (is_allowed, remaining_requests, retry_after_seconds)
    """
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW_SECONDS
    
    # Get existing timestamps for this client
    timestamps = _rate_limit_store.get(client_ip, [])
    
    # Filter to only timestamps within the current window
    timestamps = [ts for ts in timestamps if ts > window_start]
    
    # Check if over limit
    if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
        # Calculate retry-after (time until oldest request expires)
        oldest_in_window = min(timestamps)
        retry_after = int(oldest_in_window + RATE_LIMIT_WINDOW_SECONDS - now) + 1
        return False, 0, max(1, retry_after)
    
    # Add current request timestamp
    timestamps.append(now)
    _rate_limit_store[client_ip] = timestamps
    
    remaining = RATE_LIMIT_MAX_REQUESTS - len(timestamps)
    return True, remaining, 0


def _cleanup_rate_limit_store() -> None:
    """Remove expired entries from rate limit store."""
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW_SECONDS
    
    expired_ips = []
    for ip, timestamps in _rate_limit_store.items():
        # Filter to only valid timestamps
        valid = [ts for ts in timestamps if ts > window_start]
        if not valid:
            expired_ips.append(ip)
        else:
            _rate_limit_store[ip] = valid
    
    # Remove expired IPs
    for ip in expired_ips:
        del _rate_limit_store[ip]


async def rate_limit_dependency(request: Request) -> None:
    """FastAPI dependency for rate limiting."""
    client_ip = _get_client_ip(request)
    allowed, remaining, retry_after = _check_rate_limit(client_ip)
    
    if not allowed:
        logger.warning(
            "Client error rate limit exceeded: ip=%s retry_after=%d",
            client_ip,
            retry_after,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Try again in {retry_after} seconds.",
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(RATE_LIMIT_MAX_REQUESTS),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(time.time()) + retry_after),
            },
        )
    
    # Add rate limit headers to response (will be added by middleware or handler)
    request.state.rate_limit_remaining = remaining


# =============================================================================
# Endpoints
# =============================================================================


@router.post(
    "/client-errors",
    response_model=ClientErrorAcknowledgment,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Report a client-side error",
    description="""
    Submit a client-side error report for monitoring and debugging.
    
    This endpoint is rate-limited to 10 requests per minute per IP address
    to prevent abuse. Error reports are logged and can be forwarded to
    external monitoring systems (Sentry, DataDog, etc.).
    
    **Rate Limiting:**
    - 10 errors per minute per IP
    - Returns 429 Too Many Requests when exceeded
    - Retry-After header indicates when to retry
    """,
    responses={
        202: {
            "description": "Error report accepted",
            "model": ClientErrorAcknowledgment,
        },
        429: {
            "description": "Rate limit exceeded",
            "content": {
                "application/json": {
                    "example": {
                        "error": {
                            "code": "CLIENT.RATE_LIMITED",
                            "message": "Rate limit exceeded",
                            "user_message": "Too many error reports. Please wait before reporting more.",
                        },
                        "request_id": "550e8400-e29b-41d4-a716-446655440000",
                    }
                }
            },
        },
    },
)
async def report_client_error(
    request: Request,
    error_report: ClientErrorReport,
    _rate_limit: Annotated[None, Depends(rate_limit_dependency)],
) -> ClientErrorAcknowledgment:
    """
    Accept and log a client-side error report.
    
    This endpoint accepts error reports from the UI (JavaScript errors,
    React component crashes, etc.) and logs them for monitoring.
    """
    error_id = str(uuid4())
    client_ip = _get_client_ip(request)
    
    # Log the error with structured data
    logger.warning(
        "Client error reported: error_id=%s code=%s url=%s user_id=%s ip=%s message=%s",
        error_id,
        error_report.error_code,
        error_report.url,
        error_report.user_id or "anonymous",
        client_ip,
        error_report.message[:200],  # Truncate for log readability
        extra={
            "error_id": error_id,
            "error_code": error_report.error_code,
            "url": error_report.url,
            "user_id": error_report.user_id,
            "session_id": error_report.session_id,
            "user_agent": error_report.user_agent,
            "client_ip": client_ip,
            "stack_trace": error_report.stack_trace,
            "component_stack": error_report.component_stack,
            "context": error_report.context,
            "client_timestamp": error_report.timestamp,
        },
    )
    
    # Periodic cleanup of rate limit store (every 100 requests)
    import random
    if random.random() < 0.01:  # 1% chance
        _cleanup_rate_limit_store()
    
    return ClientErrorAcknowledgment(
        received=True,
        error_id=error_id,
    )


@router.get(
    "/client-errors/health",
    summary="Check client error service health",
    description="Health check endpoint for the client error reporting service.",
    include_in_schema=False,
)
async def client_errors_health() -> dict:
    """Health check for client error service."""
    return {
        "status": "healthy",
        "service": "client-errors",
        "rate_limit": {
            "window_seconds": RATE_LIMIT_WINDOW_SECONDS,
            "max_requests": RATE_LIMIT_MAX_REQUESTS,
        },
    }
