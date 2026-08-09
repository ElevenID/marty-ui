"""Purpose-scoped authentication for Notification event ingestion."""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass

from fastapi import Header, HTTPException

APPLICANT_PRODUCER_ID = "applicant"
PRODUCER_ID_ENV = "NOTIFICATION_EVENT_PRODUCER_ID"
TOKEN_ENV = "NOTIFICATION_APPLICANT_EVENT_TOKEN"
TOKEN_FILE_ENV = "NOTIFICATION_APPLICANT_EVENT_TOKEN_FILE"
TOKEN_HEADER = "X-Service-Token"
PRODUCER_HEADER = "X-Marty-Event-Producer"
MIN_TOKEN_LENGTH = 32
_PLACEHOLDER_PREFIXES = (
    "change-me",
    "change_me",
    "changeme",
    "replace-me",
    "replace_me",
)


class NotificationEventAuthConfigurationError(RuntimeError):
    """A producer identity or credential is absent, weak, or ambiguous."""


@dataclass(frozen=True)
class NotificationEventProducerPrincipal:
    """Authenticated internal workload allowed to request event ingestion."""

    producer_id: str


def read_applicant_event_token() -> str:
    """Load Applicant's strong, purpose-scoped event-ingest credential."""
    token = os.environ.get(TOKEN_ENV, "").strip()
    token_file = os.environ.get(TOKEN_FILE_ENV, "").strip()
    if token and token_file:
        raise NotificationEventAuthConfigurationError(
            f"Both {TOKEN_ENV} and {TOKEN_FILE_ENV} are configured"
        )
    if token_file:
        try:
            with open(token_file, encoding="utf-8") as token_handle:
                token = token_handle.read().strip()
        except OSError as exc:
            raise NotificationEventAuthConfigurationError(
                f"Unable to read {TOKEN_FILE_ENV}"
            ) from exc
    if not token:
        raise NotificationEventAuthConfigurationError(
            "Applicant event-producer authentication is not configured"
        )
    if len(token) < MIN_TOKEN_LENGTH or token.lower().startswith(_PLACEHOLDER_PREFIXES):
        raise NotificationEventAuthConfigurationError(
            "Applicant event-producer credential is not production-safe"
        )
    return token


def read_notification_event_producer_id() -> str:
    """Load the exact producer role assigned to this publishing workload."""
    producer_id = os.environ.get(PRODUCER_ID_ENV, "").strip()
    if producer_id != APPLICANT_PRODUCER_ID:
        raise NotificationEventAuthConfigurationError(
            "Notification event producer identity is missing or unsupported"
        )
    return producer_id


def notification_event_ingest_headers() -> dict[str, str]:
    """Build authenticated, role-bound producer headers."""
    return {
        TOKEN_HEADER: read_applicant_event_token(),
        PRODUCER_HEADER: read_notification_event_producer_id(),
    }


def require_notification_event_producer(
    x_service_token: str | None = Header(default=None, alias=TOKEN_HEADER),
    x_marty_event_producer: str | None = Header(default=None, alias=PRODUCER_HEADER),
) -> NotificationEventProducerPrincipal:
    """Authenticate one known producer before internal event fan-out."""
    if x_marty_event_producer != APPLICANT_PRODUCER_ID:
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid event producer credential",
        )
    try:
        expected = read_applicant_event_token()
    except NotificationEventAuthConfigurationError as exc:
        raise HTTPException(
            status_code=503,
            detail="Notification event ingestion is unavailable",
        ) from exc
    if not x_service_token or not hmac.compare_digest(x_service_token, expected):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid event producer credential",
        )
    return NotificationEventProducerPrincipal(producer_id=x_marty_event_producer)
