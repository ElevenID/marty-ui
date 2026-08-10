"""Authentication helpers for internal HTTP service calls."""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request

from common.grpc_factory import read_service_token

SERVICE_TOKEN_HEADER = "x-service-token"


def internal_service_headers() -> dict[str, str]:
    """Return authentication headers for an outbound internal HTTP call."""
    token = read_service_token()
    return {SERVICE_TOKEN_HEADER: token} if token else {}


def require_internal_service_auth(request: Request) -> None:
    """Reject an internal HTTP call unless it has the configured service token."""
    expected_token = read_service_token()
    if not expected_token:
        return
    supplied_token = request.headers.get(SERVICE_TOKEN_HEADER, "")
    if not hmac.compare_digest(supplied_token, expected_token):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid service token",
        )
