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
    "event_type": "application.approved",
    "aggregate_id": "application-1",
    "aggregate_type": "application",
    "organization_id": "org-1",
    "data": {
        "applicant_id": "applicant-1",
        "application_id": "application-1",
        "credential_template_id": "template-1",
        "status": "APPROVED",
    },
}
AUTH_HEADERS = {
    "X-Service-Token": TOKEN,
    "X-Marty-Event-Producer": "applicant",
}


def _client(monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, AsyncMock]:
    monkeypatch.setenv("NOTIFICATION_APPLICANT_EVENT_TOKEN", TOKEN)
    monkeypatch.delenv("NOTIFICATION_APPLICANT_EVENT_TOKEN_FILE", raising=False)
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


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-Marty-Event-Producer": "applicant"},
        {
            "X-Service-Token": "wrong" * 8,
            "X-Marty-Event-Producer": "applicant",
        },
        {"X-Service-Token": TOKEN, "X-Marty-Event-Producer": "credential"},
    ],
)
def test_internal_event_rejects_missing_or_invalid_credentials_before_dispatch(
    monkeypatch: pytest.MonkeyPatch, headers: dict[str, str]
) -> None:
    client, dispatch = _client(monkeypatch)

    response = client.post("/internal/events", json=EVENT, headers=headers)

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Missing or invalid event producer credential"
    }
    dispatch.assert_not_awaited()


def test_internal_event_auth_precedes_body_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, dispatch = _client(monkeypatch)

    response = client.post("/internal/events", json={"untrusted": "body"})

    assert response.status_code == 401
    assert response.json() == {
        "detail": "Missing or invalid event producer credential"
    }
    dispatch.assert_not_awaited()


def test_internal_event_accepts_the_purpose_scoped_service_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, dispatch = _client(monkeypatch)

    response = client.post(
        "/internal/events",
        json=EVENT,
        headers=AUTH_HEADERS,
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
        headers=AUTH_HEADERS,
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
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 422
    dispatch.assert_not_awaited()


def test_internal_event_fails_closed_when_server_auth_is_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, dispatch = _client(monkeypatch)
    monkeypatch.delenv("NOTIFICATION_APPLICANT_EVENT_TOKEN", raising=False)

    response = client.post(
        "/internal/events",
        json=EVENT,
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Notification event ingestion is unavailable"}
    dispatch.assert_not_awaited()


@pytest.mark.parametrize(
    "event",
    [
        {
            **EVENT,
            "event_type": "credential.issued",
            "aggregate_type": "credential",
            "data": {
                "application_id": "application-1",
                "credential_id": "credential-1",
                "credential_template_id": "template-1",
                "credential_type": "MemberCredential",
                "status": "ISSUED",
            },
        },
        {**EVENT, "aggregate_type": "applicant"},
        {
            **EVENT,
            "data": {**EVENT["data"], "application_id": "application-2"},
        },
        {**EVENT, "data": {**EVENT["data"], "status": "REJECTED"}},
    ],
)
def test_applicant_is_rejected_outside_its_authoritative_event_contract(
    monkeypatch: pytest.MonkeyPatch, event: dict[str, object]
) -> None:
    client, dispatch = _client(monkeypatch)

    response = client.post("/internal/events", json=event, headers=AUTH_HEADERS)

    assert response.status_code == 403
    assert response.json() == {
        "detail": "Event producer is not authorized for this event source"
    }
    dispatch.assert_not_awaited()


def test_applicant_can_publish_a_bound_rejection_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, dispatch = _client(monkeypatch)
    event = {
        **EVENT,
        "event_type": "application.rejected",
        "data": {**EVENT["data"], "status": "REJECTED"},
    }

    response = client.post("/internal/events", json=event, headers=AUTH_HEADERS)

    assert response.status_code == 200
    dispatch.assert_awaited_once()
