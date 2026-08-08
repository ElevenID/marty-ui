"""Marty-owned tests for the Notification internal-ingest trust boundary."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.notification import main as notification


TOKEN = "n" * 48
EVENT = {
    "event_id": "event-1",
    "event_type": "credential.issued",
    "aggregate_id": "credential-1",
    "aggregate_type": "credential",
    "organization_id": "org-1",
    "data": {"credential_type": "MemberCredential"},
}


def _client(monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, AsyncMock]:
    monkeypatch.setenv("NOTIFICATION_EVENT_INGEST_TOKEN", TOKEN)
    monkeypatch.delenv("NOTIFICATION_EVENT_INGEST_TOKEN_FILE", raising=False)
    dispatch = AsyncMock(
        return_value={
            "matched_subscriptions": 0,
            "deliveries": 0,
            "failures": 0,
        }
    )
    monkeypatch.setattr(notification, "_dispatch_event_to_subscriptions", dispatch)
    app = FastAPI()
    app.include_router(notification.internal_router)
    notification._repo = notification.InMemoryNotificationRepository()
    return TestClient(app), dispatch


@pytest.mark.parametrize("headers", [{}, {"X-Service-Token": "wrong" * 8}])
def test_internal_event_rejects_missing_or_invalid_credentials_before_dispatch(
    monkeypatch: pytest.MonkeyPatch, headers: dict[str, str]
) -> None:
    client, dispatch = _client(monkeypatch)

    response = client.post("/internal/events", json=EVENT, headers=headers)

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing or invalid service credential"}
    dispatch.assert_not_awaited()


def test_internal_event_auth_precedes_body_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, dispatch = _client(monkeypatch)

    response = client.post("/internal/events", json={"untrusted": "body"})

    assert response.status_code == 401
    assert response.json() == {"detail": "Missing or invalid service credential"}
    dispatch.assert_not_awaited()


def test_internal_event_accepts_the_purpose_scoped_service_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, dispatch = _client(monkeypatch)

    response = client.post(
        "/internal/events",
        json=EVENT,
        headers={"X-Service-Token": TOKEN},
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "accepted",
        "matched_subscriptions": 0,
        "deliveries": 0,
        "failures": 0,
    }
    dispatch.assert_awaited_once()


def test_internal_event_requires_a_stable_event_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, dispatch = _client(monkeypatch)
    event_without_id = {key: value for key, value in EVENT.items() if key != "event_id"}

    response = client.post(
        "/internal/events",
        json=event_without_id,
        headers={"X-Service-Token": TOKEN},
    )

    assert response.status_code == 422
    dispatch.assert_not_awaited()


@pytest.mark.parametrize("event_id", [" event-1", "event-1\r\nInjected: true"])
def test_internal_event_rejects_header_unsafe_event_ids(
    monkeypatch: pytest.MonkeyPatch,
    event_id: str,
) -> None:
    client, dispatch = _client(monkeypatch)

    response = client.post(
        "/internal/events",
        json={**EVENT, "event_id": event_id},
        headers={"X-Service-Token": TOKEN},
    )

    assert response.status_code == 422
    dispatch.assert_not_awaited()


def test_internal_event_fails_closed_when_server_auth_is_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, dispatch = _client(monkeypatch)
    monkeypatch.delenv("NOTIFICATION_EVENT_INGEST_TOKEN", raising=False)

    response = client.post(
        "/internal/events",
        json=EVENT,
        headers={"X-Service-Token": TOKEN},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Notification event ingestion is unavailable"}
    dispatch.assert_not_awaited()
