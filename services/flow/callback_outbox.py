"""Durable, tenant-bound delivery for verification completion callbacks."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol
from urllib.parse import urlparse

import httpx

from common.webhook_signatures import (
    AUTH_CALLBACK_AUDIENCE,
    is_valid_event_secret,
    sign_event,
)
from flow.infrastructure.callback_outbox_types import (
    CallbackOutboxEvent,
    new_lease_token,
)

logger = logging.getLogger(__name__)

CALLBACK_EVENT_TYPE = "flow.verification_completed"
CALLBACK_AUDIENCE = AUTH_CALLBACK_AUDIENCE
_TOKEN_MARKER = "__MARTY_TOKEN__"
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,512}")


try:
    from prometheus_client import Counter

    _DELIVERY_ATTEMPTS = Counter(
        "marty_flow_callback_delivery_attempts_total",
        "Verification callback delivery attempts.",
        ("outcome",),
    )
    _OUTBOX_TRANSITIONS = Counter(
        "marty_flow_callback_outbox_transitions_total",
        "Verification callback outbox state transitions.",
        ("state",),
    )
except (ImportError, ValueError):  # pragma: no cover - optional or reloaded metrics
    _DELIVERY_ATTEMPTS = None
    _OUTBOX_TRANSITIONS = None


def _record_attempt(outcome: str) -> None:
    if _DELIVERY_ATTEMPTS is not None:
        _DELIVERY_ATTEMPTS.labels(outcome=outcome).inc()


def _record_transition(state: str) -> None:
    if _OUTBOX_TRANSITIONS is not None:
        _OUTBOX_TRANSITIONS.labels(state=state).inc()


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


def callback_retention_seconds() -> int:
    """Bound how long an undelivered callback may retain minimized claims."""
    return _bounded_int(
        "FLOW_CALLBACK_OUTBOX_RETENTION_SECONDS",
        900,
        minimum=60,
        maximum=86400,
    )


def callback_max_attempts() -> int:
    return _bounded_int(
        "FLOW_CALLBACK_MAX_ATTEMPTS",
        10,
        minimum=1,
        maximum=32,
    )


def callback_lease_seconds() -> int:
    return _bounded_int(
        "FLOW_CALLBACK_LEASE_SECONDS",
        30,
        minimum=5,
        maximum=300,
    )


def callback_poll_seconds() -> float:
    milliseconds = _bounded_int(
        "FLOW_CALLBACK_POLL_MILLISECONDS",
        1000,
        minimum=100,
        maximum=60000,
    )
    return milliseconds / 1000


def callback_retry_delay(attempt_count: int) -> timedelta:
    base_seconds = _bounded_int(
        "FLOW_CALLBACK_RETRY_BASE_SECONDS",
        1,
        minimum=1,
        maximum=60,
    )
    cap_seconds = _bounded_int(
        "FLOW_CALLBACK_RETRY_CAP_SECONDS",
        60,
        minimum=1,
        maximum=900,
    )
    exponent = max(0, min(attempt_count - 1, 16))
    return timedelta(seconds=min(cap_seconds, base_seconds * (2**exponent)))


class CallbackOutboxRepository(Protocol):
    async def claim_due_callback_events(
        self,
        *,
        now: datetime,
        lease_expires_at: datetime,
        limit: int,
    ) -> list[CallbackOutboxEvent]: ...

    async def mark_callback_delivered(
        self,
        event_id: str,
        *,
        lease_token: str,
        delivered_at: datetime,
    ) -> bool: ...

    async def mark_callback_failed(
        self,
        event_id: str,
        *,
        lease_token: str,
        failed_at: datetime,
        next_attempt_at: datetime,
        terminal: bool,
        error_code: str,
    ) -> bool: ...


def new_callback_event(
    *,
    flow_instance_id: str,
    organization_id: str,
    destination_url: str,
    payload: dict[str, Any],
    created_at: datetime,
) -> CallbackOutboxEvent:
    require_registered_callback_destination(organization_id, destination_url)
    return CallbackOutboxEvent(
        event_id=flow_instance_id,
        flow_instance_id=flow_instance_id,
        organization_id=organization_id,
        destination_url=destination_url,
        audience=CALLBACK_AUDIENCE,
        event_type=CALLBACK_EVENT_TYPE,
        payload=payload,
        created_at=created_at,
        next_attempt_at=created_at,
        expires_at=created_at + timedelta(seconds=callback_retention_seconds()),
    )


def _validate_destination_shape(value: str) -> None:
    parsed = urlparse(value.replace(_TOKEN_MARKER, "A" * 32))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise RuntimeError("Callback destinations must be absolute HTTP(S) URLs")
    if parsed.username or parsed.password or parsed.fragment:
        raise RuntimeError(
            "Callback destinations must not contain userinfo or fragments"
        )


def callback_destination_registrations(
    configured: str | None = None,
) -> dict[str, tuple[str, ...]]:
    """Parse ``organization|URL`` registrations separated by semicolons."""
    raw = (
        os.environ.get("FLOW_CALLBACK_DESTINATIONS", "")
        if configured is None
        else configured
    )
    registrations: dict[str, list[str]] = {}
    for entry in raw.split(";"):
        entry = entry.strip()
        if not entry:
            continue
        organization_id, separator, template = entry.partition("|")
        organization_id = organization_id.strip()
        template = template.strip()
        if not separator or not organization_id or not template:
            raise RuntimeError(
                "FLOW_CALLBACK_DESTINATIONS entries must use organization|URL"
            )
        if template.count(_TOKEN_MARKER) > 1:
            raise RuntimeError(
                "Callback destination templates allow one __MARTY_TOKEN__ slot"
            )
        _validate_destination_shape(template)
        registrations.setdefault(organization_id, []).append(template)
    return {key: tuple(values) for key, values in registrations.items()}


def _matches_destination_template(candidate: str, template: str) -> bool:
    if _TOKEN_MARKER not in template:
        return candidate == template
    prefix, suffix = template.split(_TOKEN_MARKER, 1)
    if not candidate.startswith(prefix) or not candidate.endswith(suffix):
        return False
    token_end = len(candidate) - len(suffix) if suffix else len(candidate)
    token = candidate[len(prefix) : token_end]
    return _TOKEN_PATTERN.fullmatch(token) is not None


def require_registered_callback_destination(
    organization_id: str,
    destination_url: str,
) -> None:
    """Reject callbacks not registered for the flow's authoritative tenant."""
    _validate_destination_shape(destination_url)
    templates = callback_destination_registrations().get(organization_id, ())
    if not any(
        _matches_destination_template(destination_url, template)
        for template in templates
    ):
        raise ValueError(
            "callback_url is not registered for the verification organization"
        )


async def _record_delivery_failure(
    repository: CallbackOutboxRepository,
    event: CallbackOutboxEvent,
    *,
    now: datetime,
    error_code: str,
    terminal: bool = False,
) -> None:
    terminal = terminal or event.attempt_count >= callback_max_attempts()
    changed = await repository.mark_callback_failed(
        event.event_id,
        lease_token=event.lease_token or "",
        failed_at=now,
        next_attempt_at=now + callback_retry_delay(event.attempt_count),
        terminal=terminal,
        error_code=error_code[:128],
    )
    if changed:
        _record_transition("dead_letter" if terminal else "retry")


async def deliver_due_callback_events(
    repository: CallbackOutboxRepository,
    *,
    webhook_secret: str,
    limit: int = 10,
    now: datetime | None = None,
) -> int:
    """Claim and deliver due events once; retries remain durable in the outbox."""
    if not is_valid_event_secret(webhook_secret):
        raise RuntimeError("FLOW_WEBHOOK_SECRET must contain at least 32 bytes")
    claimed_at = now or datetime.now(timezone.utc)
    events = await repository.claim_due_callback_events(
        now=claimed_at,
        lease_expires_at=claimed_at + timedelta(seconds=callback_lease_seconds()),
        limit=max(1, min(limit, 100)),
    )
    delivered = 0
    for event in events:
        attempt_time = datetime.now(timezone.utc)
        try:
            require_registered_callback_destination(
                event.organization_id,
                event.destination_url,
            )
        except (RuntimeError, ValueError):
            logger.error(
                "Dead-lettering callback %s because its destination is no longer registered",
                event.event_id,
            )
            _record_attempt("destination_rejected")
            await _record_delivery_failure(
                repository,
                event,
                now=attempt_time,
                error_code="destination_rejected",
                terminal=True,
            )
            continue

        timestamp = attempt_time.isoformat()
        headers = {
            "Content-Type": "application/json",
            "X-MIP-Audience": event.audience,
            "X-MIP-Event": event.event_type,
            "X-MIP-Event-Id": event.event_id,
            "X-MIP-Timestamp": timestamp,
            "X-MIP-Delivery-Attempt": str(event.attempt_count),
            "X-MIP-Signature": sign_event(
                webhook_secret,
                audience=event.audience,
                event=event.event_type,
                event_id=event.event_id,
                timestamp=timestamp,
                payload=event.payload,
            ),
        }
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, connect=3.0),
                follow_redirects=False,
            ) as client:
                response = await client.post(
                    event.destination_url,
                    json=event.payload,
                    headers=headers,
                )
            if 200 <= response.status_code < 300:
                changed = await repository.mark_callback_delivered(
                    event.event_id,
                    lease_token=event.lease_token or "",
                    delivered_at=datetime.now(timezone.utc),
                )
                if changed:
                    delivered += 1
                    _record_attempt("delivered")
                    _record_transition("delivered")
                continue
            error_code = f"http_{response.status_code}"
            _record_attempt(error_code)
        except httpx.TimeoutException:
            error_code = "timeout"
            _record_attempt(error_code)
        except httpx.RequestError:
            error_code = "network_error"
            _record_attempt(error_code)
        await _record_delivery_failure(
            repository,
            event,
            now=datetime.now(timezone.utc),
            error_code=error_code,
        )
    return delivered


async def run_callback_dispatcher(
    repository: CallbackOutboxRepository,
    *,
    secret_provider: Callable[[], str],
    stop_event: asyncio.Event,
) -> None:
    """Poll the durable outbox until service shutdown."""
    while not stop_event.is_set():
        try:
            await deliver_due_callback_events(
                repository,
                webhook_secret=secret_provider(),
            )
        except Exception:
            logger.exception("Verification callback dispatcher iteration failed")
        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=callback_poll_seconds(),
            )
        except TimeoutError:
            continue
