"""Marty-owned durability tests for registered notification webhooks."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from services.notification import main as notification
from services.notification.webhook_outbox import new_webhook_outbox_event


EVENT_TYPE = "credential.issued"


async def _configured_repo() -> tuple[
    notification.InMemoryNotificationRepository,
    notification.Subscription,
    notification.WebhookEndpoint,
]:
    repo = notification.InMemoryNotificationRepository()
    webhook = notification.WebhookEndpoint(
        organization_id="org-1",
        url="https://hooks.example.com/events",
    )
    subscription = notification.Subscription(
        organization_id="org-1",
        event_types=[EVENT_TYPE],
        delivery_target_id=webhook.id,
        retry_policy=notification.RetryPolicy(
            max_attempts=3,
            initial_backoff_seconds=1,
            max_backoff_seconds=5,
        ),
    )
    await repo.save_webhook(webhook)
    await repo.save_subscription(subscription)
    return repo, subscription, webhook


def _event(event_id: str = "event-1") -> notification.EventIngestRequest:
    return notification.EventIngestRequest(
        event_id=event_id,
        event_type=EVENT_TYPE,
        aggregate_id="credential-1",
        aggregate_type="credential",
        organization_id="org-1",
        data={"credential_type": "MemberCredential"},
    )


@pytest.mark.asyncio
async def test_ingest_enqueues_once_without_external_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, subscription, webhook = await _configured_repo()
    network_attempt = AsyncMock(
        side_effect=AssertionError("ingestion must not call the external webhook")
    )
    monkeypatch.setattr(notification, "_attempt_webhook_request", network_attempt)

    first = await notification._dispatch_event_to_subscriptions(_event(), repo)
    duplicate = await notification._dispatch_event_to_subscriptions(_event(), repo)

    assert first == {
        "matched_subscriptions": 1,
        "deliveries": 1,
        "failures": 0,
    }
    assert duplicate == {
        "matched_subscriptions": 1,
        "deliveries": 0,
        "failures": 0,
    }
    delivery_id = notification.logical_webhook_delivery_id(
        event_id="event-1",
        subscription_id=subscription.id,
        webhook_id=webhook.id,
    )
    queued = await repo.get_webhook_outbox_event(delivery_id)
    assert queued is not None
    assert queued.status == "pending"
    assert queued.payload["id"] == "event-1"
    network_attempt.assert_not_awaited()


@pytest.mark.asyncio
async def test_retry_then_success_keeps_stable_identity_and_scrubs_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, _, webhook = await _configured_repo()
    await notification._dispatch_event_to_subscriptions(_event(), repo)
    attempts: list[tuple[str, int]] = []

    async def attempt(
        _payload: dict[str, object],
        _webhook: notification.WebhookEndpoint,
        *,
        delivery_id: str,
        attempt_count: int,
    ) -> notification.WebhookAttemptResult:
        attempts.append((delivery_id, attempt_count))
        if attempt_count == 1:
            return notification.WebhookAttemptResult(
                False, True, "HTTP_503", 503, 4
            )
        return notification.WebhookAttemptResult(True, False, None, 204, 3)

    monkeypatch.setattr(notification, "_attempt_webhook_request", attempt)
    started_at = datetime.now(timezone.utc)

    first = await notification._deliver_due_webhook_outbox(repo, now=started_at)
    delivery_id = attempts[0][0]
    retry = await repo.get_webhook_outbox_event(delivery_id)

    assert first == {"claimed": 1, "delivered": 0, "retried": 1, "dead": 0}
    assert retry is not None
    assert retry.status == "retry"
    assert retry.payload["id"] == "event-1"
    assert retry.next_attempt_at > started_at

    second = await notification._deliver_due_webhook_outbox(
        repo, now=retry.next_attempt_at
    )
    delivered = await repo.get_webhook_outbox_event(delivery_id)
    records = await repo.list_webhook_deliveries(webhook.id)

    assert second == {"claimed": 1, "delivered": 1, "retried": 0, "dead": 0}
    assert attempts == [(delivery_id, 1), (delivery_id, 2)]
    assert delivered is not None
    assert delivered.status == "delivered"
    assert delivered.payload == {}
    assert len(records) == 1
    assert records[0].id == delivery_id
    assert records[0].success is True
    assert records[0].retry_count == 1


@pytest.mark.asyncio
async def test_concurrent_workers_claim_a_logical_delivery_only_once() -> None:
    repo, _, _ = await _configured_repo()
    await notification._dispatch_event_to_subscriptions(_event(), repo)
    now = datetime.now(timezone.utc)

    claims = await asyncio.gather(
        repo.claim_due_webhook_events(
            now=now, lease_expires_at=now + timedelta(seconds=30), limit=10
        ),
        repo.claim_due_webhook_events(
            now=now, lease_expires_at=now + timedelta(seconds=30), limit=10
        ),
    )

    assert sorted(len(batch) for batch in claims) == [0, 1]
    assert sum(event.attempt_count for batch in claims for event in batch) == 1


@pytest.mark.asyncio
async def test_stale_lease_cannot_overwrite_newer_delivery_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, _, webhook = await _configured_repo()
    await notification._dispatch_event_to_subscriptions(_event(), repo)
    claimed_at = datetime.now(timezone.utc)
    first_claim = (
        await repo.claim_due_webhook_events(
            now=claimed_at,
            lease_expires_at=claimed_at + timedelta(seconds=5),
            limit=1,
        )
    )[0]
    second_claim = (
        await repo.claim_due_webhook_events(
            now=claimed_at + timedelta(seconds=6),
            lease_expires_at=claimed_at + timedelta(seconds=36),
            limit=1,
        )
    )[0]
    monkeypatch.setattr(
        notification,
        "_attempt_webhook_request",
        AsyncMock(
            return_value=notification.WebhookAttemptResult(
                True, False, None, 204, 1
            )
        ),
    )

    outcome = await notification._deliver_claimed_webhook_event(
        repo, first_claim, claimed_at=claimed_at
    )
    current = await repo.get_webhook_outbox_event(second_claim.id)

    assert outcome is None
    assert current is not None
    assert current.status == "delivering"
    assert current.lease_token == second_claim.lease_token
    assert await repo.list_webhook_deliveries(webhook.id) == []


@pytest.mark.asyncio
async def test_claimed_batch_starts_network_attempts_concurrently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, _, webhook = await _configured_repo()
    second_subscription = notification.Subscription(
        organization_id="org-1",
        event_types=[EVENT_TYPE],
        delivery_target_id=webhook.id,
    )
    await repo.save_subscription(second_subscription)
    await notification._dispatch_event_to_subscriptions(_event(), repo)
    both_started = asyncio.Event()
    started = 0

    async def attempt(*_args: object, **_kwargs: object) -> notification.WebhookAttemptResult:
        nonlocal started
        started += 1
        if started == 2:
            both_started.set()
        await asyncio.wait_for(both_started.wait(), timeout=1)
        return notification.WebhookAttemptResult(True, False, None, 204, 1)

    monkeypatch.setattr(notification, "_attempt_webhook_request", attempt)

    result = await notification._deliver_due_webhook_outbox(
        repo, now=datetime.now(timezone.utc)
    )

    assert result == {"claimed": 2, "delivered": 2, "retried": 0, "dead": 0}
    assert started == 2


@pytest.mark.asyncio
async def test_expired_payload_is_scrubbed_without_a_network_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NOTIFICATION_WEBHOOK_OUTBOX_RETENTION_SECONDS", "60")
    repo, subscription, webhook = await _configured_repo()
    now = datetime.now(timezone.utc)
    event = new_webhook_outbox_event(
        organization_id="org-1",
        webhook_id=webhook.id,
        subscription_id=subscription.id,
        event_id="expired-event",
        event_type=EVENT_TYPE,
        payload={"id": "expired-event", "type": EVENT_TYPE},
        max_attempts=3,
        initial_backoff_seconds=1,
        max_backoff_seconds=5,
        created_at=now - timedelta(seconds=61),
    )
    await repo.enqueue_webhook_event(event)
    network_attempt = AsyncMock()
    monkeypatch.setattr(notification, "_attempt_webhook_request", network_attempt)

    result = await notification._deliver_due_webhook_outbox(repo, now=now)
    expired = await repo.get_webhook_outbox_event(event.id)

    assert result == {"claimed": 0, "delivered": 0, "retried": 0, "dead": 0}
    assert expired is not None
    assert expired.status == "expired"
    assert expired.payload == {}
    network_attempt.assert_not_awaited()


@pytest.mark.asyncio
async def test_worker_rejects_cross_tenant_endpoint_and_scrubs_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, subscription, webhook = await _configured_repo()
    webhook.organization_id = "org-2"
    await repo.save_webhook(webhook)
    event = new_webhook_outbox_event(
        organization_id="org-1",
        webhook_id=webhook.id,
        subscription_id=subscription.id,
        event_id="event-cross-tenant",
        event_type=EVENT_TYPE,
        payload={
            "id": "event-cross-tenant",
            "type": EVENT_TYPE,
            "organization_id": "org-1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        max_attempts=3,
        initial_backoff_seconds=1,
        max_backoff_seconds=5,
    )
    await repo.enqueue_webhook_event(event)
    network_attempt = AsyncMock()
    monkeypatch.setattr(notification, "_attempt_webhook_request", network_attempt)

    result = await notification._deliver_due_webhook_outbox(
        repo, now=event.created_at
    )
    rejected = await repo.get_webhook_outbox_event(event.id)

    assert result == {"claimed": 1, "delivered": 0, "retried": 0, "dead": 1}
    assert rejected is not None
    assert rejected.status == "dead_letter"
    assert rejected.last_error_code == "WEBHOOK_ENDPOINT_INVALID"
    assert rejected.payload == {}
    assert await repo.list_webhook_deliveries(webhook.id) == []
    network_attempt.assert_not_awaited()


@pytest.mark.asyncio
async def test_worker_rejects_corrupted_payload_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, subscription, webhook = await _configured_repo()
    event = new_webhook_outbox_event(
        organization_id="org-1",
        webhook_id=webhook.id,
        subscription_id=subscription.id,
        event_id="event-corrupt",
        event_type=EVENT_TYPE,
        payload={
            "id": "different-event",
            "type": EVENT_TYPE,
            "organization_id": "org-2",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        max_attempts=3,
        initial_backoff_seconds=1,
        max_backoff_seconds=5,
    )
    await repo.enqueue_webhook_event(event)
    network_attempt = AsyncMock()
    monkeypatch.setattr(notification, "_attempt_webhook_request", network_attempt)

    result = await notification._deliver_due_webhook_outbox(
        repo, now=event.created_at
    )
    rejected = await repo.get_webhook_outbox_event(event.id)

    assert result == {"claimed": 1, "delivered": 0, "retried": 0, "dead": 1}
    assert rejected is not None
    assert rejected.last_error_code == "WEBHOOK_PAYLOAD_INVALID"
    assert rejected.payload == {}
    network_attempt.assert_not_awaited()
