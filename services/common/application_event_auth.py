"""Authentication for Applicant -> Flow application approval events.

The application-approved message is an issuance authority boundary: accepting it
can create a pre-authorized credential offer.  This module deliberately uses a
dedicated key and a purpose-bound envelope instead of relying on network
location or the platform-wide gRPC service token.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


PRODUCER = "marty-applicant-service"
AUDIENCE = "marty-flow-application-approved"
SIGNATURE_VERSION = "v1"

HEADER_PRODUCER = "x-marty-event-producer"
HEADER_AUDIENCE = "x-marty-event-audience"
HEADER_ID = "x-marty-event-id"
HEADER_TIMESTAMP = "x-marty-event-timestamp"
HEADER_VERSION = "x-marty-event-signature-version"
HEADER_SIGNATURE = "x-marty-event-signature"

_KEY_ENV = "FLOW_APPLICATION_EVENT_HMAC_KEY"
_DEFAULT_MAX_AGE_SECONDS = 60
_DEFAULT_REPLAY_TTL_SECONDS = 300


class ApplicationEventAuthError(Exception):
    """A stable authentication failure suitable for transport mapping."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ApplicationEventEvidence:
    """Minimized evidence retained with a flow instance."""

    producer: str
    audience: str
    event_id_sha256: str
    payload_sha256: str
    authenticated_at: str

    def as_dict(self) -> dict[str, str]:
        return {
            "producer": self.producer,
            "audience": self.audience,
            "event_id_sha256": self.event_id_sha256,
            "payload_sha256": self.payload_sha256,
            "authenticated_at": self.authenticated_at,
        }


def _read_key() -> bytes:
    value = os.environ.get(_KEY_ENV, "").strip()
    if not value:
        file_name = os.environ.get(f"{_KEY_ENV}_FILE", "").strip()
        if file_name:
            try:
                value = Path(file_name).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise ApplicationEventAuthError(
                    "configuration_error", "application event key is unavailable"
                ) from exc
    if len(value.encode("utf-8")) < 32:
        raise ApplicationEventAuthError(
            "configuration_error", "application event key must contain at least 32 bytes"
        )
    return value.encode("utf-8")


def canonical_event_payload(event: Mapping[str, Any]) -> bytes:
    """Serialize the transport-neutral event using a deterministic JSON form."""
    try:
        return json.dumps(
            dict(event),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ApplicationEventAuthError(
            "invalid_payload", "application event payload is not canonicalizable"
        ) from exc


def _signature_input(
    *, event_id: str, timestamp: str, payload_sha256: str
) -> bytes:
    return "\n".join(
        (
            SIGNATURE_VERSION,
            PRODUCER,
            AUDIENCE,
            event_id,
            timestamp,
            payload_sha256,
        )
    ).encode("utf-8")


def sign_application_event(
    event: Mapping[str, Any],
    *,
    event_id: str | None = None,
    now: int | None = None,
) -> dict[str, str]:
    """Return HTTP headers/gRPC metadata authenticating an exact event payload."""
    event_id = event_id or str(uuid.uuid4())
    try:
        uuid.UUID(event_id)
    except (ValueError, AttributeError) as exc:
        raise ApplicationEventAuthError("invalid_event_id", "event id must be a UUID") from exc
    timestamp = str(int(time.time() if now is None else now))
    payload_sha256 = hashlib.sha256(canonical_event_payload(event)).hexdigest()
    signature = hmac.new(
        _read_key(),
        _signature_input(
            event_id=event_id,
            timestamp=timestamp,
            payload_sha256=payload_sha256,
        ),
        hashlib.sha256,
    ).hexdigest()
    return {
        HEADER_PRODUCER: PRODUCER,
        HEADER_AUDIENCE: AUDIENCE,
        HEADER_ID: event_id,
        HEADER_TIMESTAMP: timestamp,
        HEADER_VERSION: SIGNATURE_VERSION,
        HEADER_SIGNATURE: signature,
    }


def _normalized_metadata(metadata: Mapping[str, Any]) -> dict[str, str]:
    return {str(key).lower(): str(value).strip() for key, value in metadata.items()}


def _positive_setting(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ApplicationEventAuthError(
            "configuration_error", f"{name} must be a positive integer"
        ) from exc
    if value <= 0:
        raise ApplicationEventAuthError(
            "configuration_error", f"{name} must be a positive integer"
        )
    return value


def validate_application_event_configuration() -> None:
    """Fail service startup when the dedicated identity is misconfigured."""
    _read_key()
    max_age = _positive_setting(
        "FLOW_APPLICATION_EVENT_MAX_AGE_SECONDS",
        _DEFAULT_MAX_AGE_SECONDS,
    )
    replay_ttl = _positive_setting(
        "FLOW_APPLICATION_EVENT_REPLAY_TTL_SECONDS",
        _DEFAULT_REPLAY_TTL_SECONDS,
    )
    if replay_ttl < max_age:
        raise ApplicationEventAuthError(
            "configuration_error",
            "application event replay TTL must cover the freshness window",
        )


async def authenticate_application_event(
    event: Mapping[str, Any],
    metadata: Mapping[str, Any],
    *,
    replay_store: Any,
    now: int | None = None,
    max_age_seconds: int | None = None,
    replay_ttl_seconds: int | None = None,
) -> ApplicationEventEvidence:
    """Authenticate and atomically consume an application approval event.

    Replay storage is mandatory and must be shared by every Flow replica.  A
    storage outage therefore fails closed rather than creating a process-local
    acceptance window.
    """
    values = _normalized_metadata(metadata)
    required = (
        HEADER_PRODUCER,
        HEADER_AUDIENCE,
        HEADER_ID,
        HEADER_TIMESTAMP,
        HEADER_VERSION,
        HEADER_SIGNATURE,
    )
    if any(not values.get(name) for name in required):
        raise ApplicationEventAuthError(
            "missing_authentication", "application event authentication is required"
        )
    if values[HEADER_PRODUCER] != PRODUCER or values[HEADER_AUDIENCE] != AUDIENCE:
        raise ApplicationEventAuthError(
            "wrong_purpose", "application event producer or audience is invalid"
        )
    if values[HEADER_VERSION] != SIGNATURE_VERSION:
        raise ApplicationEventAuthError(
            "unsupported_version", "application event signature version is unsupported"
        )

    event_id = values[HEADER_ID]
    try:
        uuid.UUID(event_id)
        signed_at = int(values[HEADER_TIMESTAMP])
    except (ValueError, AttributeError) as exc:
        raise ApplicationEventAuthError(
            "invalid_envelope", "application event id or timestamp is invalid"
        ) from exc

    current_time = int(time.time() if now is None else now)
    age_limit = (
        _positive_setting(
            "FLOW_APPLICATION_EVENT_MAX_AGE_SECONDS",
            _DEFAULT_MAX_AGE_SECONDS,
        )
        if max_age_seconds is None
        else max_age_seconds
    )
    if age_limit <= 0 or abs(current_time - signed_at) > age_limit:
        raise ApplicationEventAuthError("stale_event", "application event is outside its freshness window")

    payload_sha256 = hashlib.sha256(canonical_event_payload(event)).hexdigest()
    expected = hmac.new(
        _read_key(),
        _signature_input(
            event_id=event_id,
            timestamp=str(signed_at),
            payload_sha256=payload_sha256,
        ),
        hashlib.sha256,
    ).hexdigest()
    supplied = values[HEADER_SIGNATURE]
    if len(supplied) != 64 or not hmac.compare_digest(expected, supplied):
        raise ApplicationEventAuthError(
            "invalid_signature", "application event signature is invalid"
        )

    if replay_store is None:
        raise ApplicationEventAuthError(
            "replay_store_unavailable", "application event replay store is unavailable"
        )
    ttl = (
        _positive_setting(
            "FLOW_APPLICATION_EVENT_REPLAY_TTL_SECONDS",
            _DEFAULT_REPLAY_TTL_SECONDS,
        )
        if replay_ttl_seconds is None
        else replay_ttl_seconds
    )
    if ttl < age_limit:
        raise ApplicationEventAuthError(
            "configuration_error", "application event replay TTL must cover the freshness window"
        )
    event_id_sha256 = hashlib.sha256(event_id.encode("utf-8")).hexdigest()
    try:
        was_new = await replay_store.set(
            f"marty:application-approved:v1:{event_id_sha256}",
            payload_sha256,
            nx=True,
            ex=ttl,
        )
    except Exception as exc:
        raise ApplicationEventAuthError(
            "replay_store_unavailable", "application event replay store is unavailable"
        ) from exc
    if not was_new:
        raise ApplicationEventAuthError("replayed_event", "application event was already consumed")

    authenticated_at = datetime_from_unix(current_time)
    return ApplicationEventEvidence(
        producer=PRODUCER,
        audience=AUDIENCE,
        event_id_sha256=event_id_sha256,
        payload_sha256=payload_sha256,
        authenticated_at=authenticated_at,
    )


def datetime_from_unix(value: int) -> str:
    """UTC ISO timestamp kept as a helper to make evidence deterministic in tests."""
    from datetime import datetime, timezone

    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
