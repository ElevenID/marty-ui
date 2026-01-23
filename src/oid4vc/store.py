"""In-memory store for OID4VP presentation requests."""

from __future__ import annotations

from datetime import datetime
from typing import Any


_presentation_requests: dict[str, dict[str, Any]] = {}


def record_presentation_request(
    request_id: str,
    verifier: str,
    requested_credentials: list[str],
    nonce: str,
    audience: str,
    request_uri: str | None = None,
) -> dict[str, Any]:
    """Record a new presentation request."""
    record = {
        "id": request_id,
        "verifier": verifier,
        "requested_credentials": requested_credentials,
        "nonce": nonce,
        "audience": audience,
        "request_uri": request_uri,
        "status": "pending",
        "presentation": None,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }
    _presentation_requests[request_id] = record
    return record


def mark_presentation_submitted(request_id: str, presentation: Any) -> bool:
    """Mark a presentation request as submitted."""
    record = _presentation_requests.get(request_id)
    if not record:
        return False
    record["status"] = "submitted"
    record["presentation"] = presentation
    record["updated_at"] = datetime.utcnow().isoformat()
    return True


def get_presentation_request(request_id: str) -> dict[str, Any] | None:
    """Get a presentation request record."""
    return _presentation_requests.get(request_id)


def list_presentation_requests() -> list[dict[str, Any]]:
    """List presentation request records."""
    return list(_presentation_requests.values())


def clear_presentation_requests() -> int:
    """Clear all presentation requests."""
    count = len(_presentation_requests)
    _presentation_requests.clear()
    return count
