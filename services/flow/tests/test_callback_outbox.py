"""Marty-owned tests for durable verification callback delivery."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

import flow.callback_outbox as callback_outbox
from flow.callback_outbox import (
    deliver_due_callback_events,
    new_callback_event,
    require_registered_callback_destination,
)
from flow.main import FlowInstance, FlowInstanceStatus, InMemoryFlowRepository


SECRET = "test-flow-webhook-secret-at-least-32-bytes"
DESTINATION_TEMPLATE = (
    "org-1|http://auth:8001/internal/v1/auth/credential-verified?nonce=__MARTY_TOKEN__"
)
DESTINATION = "http://auth:8001/internal/v1/auth/credential-verified?nonce=" + "a" * 32


async def _repository_with_event(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[InMemoryFlowRepository, datetime]:
    monkeypatch.setenv("FLOW_CALLBACK_DESTINATIONS", DESTINATION_TEMPLATE)
    now = datetime.now(timezone.utc)
    repository = InMemoryFlowRepository()
    stored = FlowInstance(
        id="90000000-0000-0000-0000-000000000001",
        flow_definition_id="__verification__",
        organization_id="org-1",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={"nonce": "nonce"},
        created_at=now,
        updated_at=now,
    )
    await repository.save_instance(stored)
    terminal = FlowInstance(
        id=stored.id,
        flow_definition_id=stored.flow_definition_id,
        organization_id=stored.organization_id,
        status=FlowInstanceStatus.COMPLETED,
        context=stored.context,
        completed_at=now,
        created_at=stored.created_at,
        updated_at=now,
        result={"evaluation_result": "passed", "decision": "allow"},
    )
    event = new_callback_event(
        flow_instance_id=stored.id,
        organization_id="org-1",
        destination_url=DESTINATION,
        payload={"flow_instance_id": stored.id, "decision": "allow"},
        created_at=now,
    )
    committed = await repository.finalize_verification(
        terminal,
        nonce_digest="a" * 64,
        replay_expires_at=now + timedelta(minutes=15),
        expected_status=FlowInstanceStatus.AWAITING_WALLET,
        callback_event=event,
    )
    assert committed is True
    return repository, now


def test_callback_destination_is_bound_to_tenant_and_constrained_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLOW_CALLBACK_DESTINATIONS", DESTINATION_TEMPLATE)

    require_registered_callback_destination("org-1", DESTINATION)
    with pytest.raises(ValueError, match="not registered"):
        require_registered_callback_destination("org-2", DESTINATION)
    with pytest.raises(ValueError, match="not registered"):
        require_registered_callback_destination(
            "org-1",
            DESTINATION + "&redirect=http://metadata.internal",
        )


@pytest.mark.asyncio
async def test_callback_retries_then_scrubs_claim_payload_after_delivery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, now = await _repository_with_event(monkeypatch)
    captured_headers: list[dict[str, str]] = []
    attempts = 0

    class CallbackResponse:
        status_code = 200

    class CallbackClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def post(self, url, *, json, headers):
            nonlocal attempts
            attempts += 1
            assert url == DESTINATION
            assert json["decision"] == "allow"
            captured_headers.append(headers)
            if attempts == 1:
                raise httpx.ConnectError("temporary outage")
            return CallbackResponse()

    monkeypatch.setattr(
        callback_outbox.httpx,
        "AsyncClient",
        lambda **_kwargs: CallbackClient(),
    )

    first = await deliver_due_callback_events(
        repository,
        webhook_secret=SECRET,
        now=now,
    )
    retry_event = repository._callback_events["90000000-0000-0000-0000-000000000001"]
    assert first == 0
    assert retry_event.status == "retry"
    assert retry_event.payload["decision"] == "allow"
    assert retry_event.last_error_code == "network_error"

    second = await deliver_due_callback_events(
        repository,
        webhook_secret=SECRET,
        now=now + timedelta(minutes=2),
    )
    delivered_event = repository._callback_events[retry_event.event_id]
    assert second == 1
    assert delivered_event.status == "delivered"
    assert delivered_event.payload == {}
    assert delivered_event.destination_url == ""
    assert delivered_event.attempt_count == 2
    assert (
        captured_headers[0]["X-MIP-Event-Id"] == captured_headers[1]["X-MIP-Event-Id"]
    )
    assert captured_headers[1]["X-MIP-Audience"] == "marty-auth-service"


@pytest.mark.asyncio
async def test_expired_callback_payload_is_scrubbed_without_network_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FLOW_CALLBACK_OUTBOX_RETENTION_SECONDS", "60")
    repository, now = await _repository_with_event(monkeypatch)

    delivered = await deliver_due_callback_events(
        repository,
        webhook_secret=SECRET,
        now=now + timedelta(seconds=61),
    )

    event = repository._callback_events["90000000-0000-0000-0000-000000000001"]
    assert delivered == 0
    assert event.status == "expired"
    assert event.payload == {}
    assert event.destination_url == ""
