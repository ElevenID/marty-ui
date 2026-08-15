"""Purpose-scoped authentication for Notification event ingestion."""

from __future__ import annotations

import os

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
