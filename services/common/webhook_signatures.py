"""Canonical signing helpers for internal MIP webhook events."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

MINIMUM_EVENT_SECRET_BYTES = 32
AUTH_CALLBACK_AUDIENCE = "marty-auth-service"


def is_valid_event_secret(secret: str) -> bool:
    """Return whether a shared secret has enough entropy-bearing capacity."""
    return len(secret.encode("utf-8")) >= MINIMUM_EVENT_SECRET_BYTES


def canonical_event_bytes(
    *,
    audience: str,
    event: str,
    event_id: str,
    timestamp: str,
    payload: dict[str, Any],
) -> bytes:
    """Serialize every security-relevant event field deterministically."""
    return json.dumps(
        {
            "audience": audience,
            "event": event,
            "event_id": event_id,
            "payload": payload,
            "timestamp": timestamp,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sign_event(
    secret: str,
    *,
    audience: str,
    event: str,
    event_id: str,
    timestamp: str,
    payload: dict[str, Any],
) -> str:
    """Return the versioned SHA-256 HMAC header value for an event."""
    if not is_valid_event_secret(secret):
        raise ValueError(
            f"Event signing secrets must be at least {MINIMUM_EVENT_SECRET_BYTES} bytes"
        )
    digest = hmac.new(
        secret.encode("utf-8"),
        canonical_event_bytes(
            audience=audience,
            event=event,
            event_id=event_id,
            timestamp=timestamp,
            payload=payload,
        ),
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={digest}"


def verify_event_signature(
    signature: str,
    secret: str,
    *,
    audience: str,
    event: str,
    event_id: str,
    timestamp: str,
    payload: dict[str, Any],
) -> bool:
    """Compare a supplied event signature without timing-dependent equality."""
    if not signature.startswith("sha256=") or not is_valid_event_secret(secret):
        return False
    expected = sign_event(
        secret,
        audience=audience,
        event=event,
        event_id=event_id,
        timestamp=timestamp,
        payload=payload,
    )
    return hmac.compare_digest(signature, expected)


def payload_digest(payload: dict[str, Any]) -> str:
    """Return a stable digest for a decision or evidence payload."""
    encoded = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
