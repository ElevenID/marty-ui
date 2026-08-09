"""Marty-owned producer tests for authenticated Notification ingestion."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest

from common.events import DomainEvent, EventPublisher, EventType


class _FakeClient:
    def __init__(self, calls: list[dict[str, Any]]) -> None:
        self._calls = calls

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def post(self, url: str, **kwargs: Any) -> SimpleNamespace:
        self._calls.append({"url": url, **kwargs})
        return SimpleNamespace(status_code=202)


def _event() -> DomainEvent:
    return DomainEvent(
        event_type=EventType.APPLICATION_APPROVED,
        aggregate_id="application-1",
        aggregate_type="application",
        organization_id="org-1",
        data={
            "applicant_id": "applicant-1",
            "application_id": "application-1",
            "credential_template_id": "template-1",
            "status": "APPROVED",
        },
        timestamp=datetime(2026, 8, 8, tzinfo=timezone.utc),
    )


@pytest.mark.asyncio
async def test_notification_producer_attaches_the_purpose_scoped_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NOTIFICATION_SERVICE_URL", "http://notification:8007")
    monkeypatch.setenv("NOTIFICATION_EVENT_PRODUCER_ID", "applicant")
    monkeypatch.setenv("NOTIFICATION_APPLICANT_EVENT_TOKEN", "t" * 48)
    monkeypatch.delenv("NOTIFICATION_APPLICANT_EVENT_TOKEN_FILE", raising=False)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "common.events.httpx.AsyncClient",
        lambda **_kwargs: _FakeClient(calls),
    )

    event = _event()
    await EventPublisher()._publish_to_notification_service(event)

    assert len(calls) == 1
    assert calls[0]["url"] == "http://notification:8007/internal/events"
    assert calls[0]["headers"] == {
        "Content-Type": "application/json",
        "X-Service-Token": "t" * 48,
        "X-Marty-Event-Producer": "applicant",
    }
    assert calls[0]["json"]["event_id"] == event.event_id


@pytest.mark.asyncio
async def test_notification_producer_never_sends_without_authentication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NOTIFICATION_SERVICE_URL", "http://notification:8007")
    monkeypatch.setenv("NOTIFICATION_EVENT_PRODUCER_ID", "applicant")
    monkeypatch.delenv("NOTIFICATION_APPLICANT_EVENT_TOKEN", raising=False)
    monkeypatch.delenv("NOTIFICATION_APPLICANT_EVENT_TOKEN_FILE", raising=False)

    def unexpected_client(**_kwargs: object) -> None:
        raise AssertionError("an unauthenticated internal event must not be sent")

    monkeypatch.setattr("common.events.httpx.AsyncClient", unexpected_client)

    await EventPublisher()._publish_to_notification_service(_event())


@pytest.mark.asyncio
async def test_notification_producer_never_sends_with_an_unsupported_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NOTIFICATION_SERVICE_URL", "http://notification:8007")
    monkeypatch.setenv("NOTIFICATION_EVENT_PRODUCER_ID", "credential")
    monkeypatch.setenv("NOTIFICATION_APPLICANT_EVENT_TOKEN", "t" * 48)

    def unexpected_client(**_kwargs: object) -> None:
        raise AssertionError("an unsupported producer must not send an event")

    monkeypatch.setattr("common.events.httpx.AsyncClient", unexpected_client)

    await EventPublisher()._publish_to_notification_service(_event())
