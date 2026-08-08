"""Purpose-scoped authentication for Notification event ingestion."""

from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException

TOKEN_ENV = "NOTIFICATION_EVENT_INGEST_TOKEN"
TOKEN_FILE_ENV = "NOTIFICATION_EVENT_INGEST_TOKEN_FILE"
TOKEN_HEADER = "X-Service-Token"
MIN_TOKEN_LENGTH = 32
_PLACEHOLDER_PREFIXES = (
    "change-me",
    "change_me",
    "changeme",
    "replace-me",
    "replace_me",
)


class NotificationEventAuthConfigurationError(RuntimeError):
    """The notification-ingest credential is absent, weak, or ambiguous."""


def read_notification_event_ingest_token() -> str:
    """Load one strong, purpose-scoped event-ingest credential."""
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
            "Notification event-ingest authentication is not configured"
        )
    if len(token) < MIN_TOKEN_LENGTH or token.lower().startswith(_PLACEHOLDER_PREFIXES):
        raise NotificationEventAuthConfigurationError(
            "Notification event-ingest credential is not production-safe"
        )
    return token


def notification_event_ingest_headers() -> dict[str, str]:
    """Build authenticated producer headers without exposing the token."""
    return {TOKEN_HEADER: read_notification_event_ingest_token()}


def require_notification_event_ingest_token(
    x_service_token: str | None = Header(default=None, alias=TOKEN_HEADER),
) -> None:
    """Fail closed before internal event fan-out when authentication is invalid."""
    try:
        expected = read_notification_event_ingest_token()
    except NotificationEventAuthConfigurationError as exc:
        raise HTTPException(
            status_code=503,
            detail="Notification event ingestion is unavailable",
        ) from exc
    if not x_service_token or not hmac.compare_digest(x_service_token, expected):
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid service credential",
        )
