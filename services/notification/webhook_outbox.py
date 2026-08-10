"""Durable state and retry policy for notification webhook delivery."""

from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol

OUTBOX_NAMESPACE = uuid.UUID("b431a1c8-dfd9-44fa-b042-b633f7d9ec6c")


def _bounded_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


def webhook_outbox_retention_seconds() -> int:
    return _bounded_int(
        "NOTIFICATION_WEBHOOK_OUTBOX_RETENTION_SECONDS",
        86400,
        minimum=60,
        maximum=604800,
    )


def webhook_outbox_lease_seconds() -> int:
    return _bounded_int(
        "NOTIFICATION_WEBHOOK_OUTBOX_LEASE_SECONDS",
        30,
        minimum=5,
        maximum=300,
    )


def webhook_outbox_poll_seconds() -> float:
    milliseconds = _bounded_int(
        "NOTIFICATION_WEBHOOK_OUTBOX_POLL_MILLISECONDS",
        1000,
        minimum=100,
        maximum=60000,
    )
    return milliseconds / 1000


def webhook_outbox_batch_size() -> int:
    return _bounded_int(
        "NOTIFICATION_WEBHOOK_OUTBOX_BATCH_SIZE",
        25,
        minimum=1,
        maximum=100,
    )


def logical_webhook_delivery_id(
    *, event_id: str, subscription_id: str, webhook_id: str
) -> str:
    return str(
        uuid.uuid5(
            OUTBOX_NAMESPACE,
            f"{event_id}:{subscription_id}:{webhook_id}",
        )
    )


def webhook_retry_delay(event: WebhookOutboxEvent) -> timedelta:
    """Bounded exponential backoff with stable per-delivery jitter."""
    exponent = max(0, min(event.attempt_count - 1, 16))
    base = min(
        event.max_backoff_seconds,
        event.initial_backoff_seconds * (2**exponent),
    )
    digest = hashlib.sha256(
        f"{event.id}:{event.attempt_count}".encode("utf-8")
    ).digest()
    jitter_ratio = int.from_bytes(digest[:2], "big") / 65535
    jitter = min(event.max_backoff_seconds - base, base * 0.25 * jitter_ratio)
    return timedelta(seconds=base + max(0, jitter))


def new_lease_token() -> str:
    return str(uuid.uuid4())


@dataclass
class WebhookOutboxEvent:
    id: str
    organization_id: str
    webhook_id: str
    subscription_id: str
    event_id: str
    event_type: str
    payload: dict[str, object]
    max_attempts: int
    initial_backoff_seconds: int
    max_backoff_seconds: int
    created_at: datetime
    next_attempt_at: datetime
    expires_at: datetime
    status: str = "pending"
    attempt_count: int = 0
    lease_token: str | None = None
    lease_expires_at: datetime | None = None
    delivered_at: datetime | None = None
    last_error_code: str | None = None
    response_status_code: int | None = None


def new_webhook_outbox_event(
    *,
    organization_id: str,
    webhook_id: str,
    subscription_id: str,
    event_id: str,
    event_type: str,
    payload: dict[str, object],
    max_attempts: int,
    initial_backoff_seconds: int,
    max_backoff_seconds: int,
    created_at: datetime | None = None,
) -> WebhookOutboxEvent:
    timestamp = created_at or datetime.now(timezone.utc)
    delivery_id = logical_webhook_delivery_id(
        event_id=event_id,
        subscription_id=subscription_id,
        webhook_id=webhook_id,
    )
    return WebhookOutboxEvent(
        id=delivery_id,
        organization_id=organization_id,
        webhook_id=webhook_id,
        subscription_id=subscription_id,
        event_id=event_id,
        event_type=event_type,
        payload=payload,
        max_attempts=max_attempts,
        initial_backoff_seconds=initial_backoff_seconds,
        max_backoff_seconds=max_backoff_seconds,
        created_at=timestamp,
        next_attempt_at=timestamp,
        expires_at=timestamp
        + timedelta(seconds=webhook_outbox_retention_seconds()),
    )


class WebhookOutboxRepository(Protocol):
    async def claim_due_webhook_events(
        self,
        *,
        now: datetime,
        lease_expires_at: datetime,
        limit: int,
    ) -> list[WebhookOutboxEvent]: ...

    async def mark_webhook_event_delivered(
        self,
        event_id: str,
        *,
        lease_token: str,
        delivered_at: datetime,
        response_status_code: int,
    ) -> bool: ...

    async def mark_webhook_event_failed(
        self,
        event_id: str,
        *,
        lease_token: str,
        next_attempt_at: datetime,
        terminal: bool,
        error_code: str,
        response_status_code: int | None,
    ) -> bool: ...
