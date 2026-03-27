from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.notification import main as notification


def _build_client(repo: notification.InMemoryNotificationRepository) -> TestClient:
    app = FastAPI()
    app.include_router(notification.router)
    notification._repo = repo
    return TestClient(app)


def test_send_notification_supports_structured_target_and_delivery_results():
    repo = notification.InMemoryNotificationRepository()
    client = _build_client(repo)

    response = client.post(
        "/v1/notifications/send",
        json={
            "title": "Your credential is ready",
            "body": "Tap to add it to your wallet.",
            "event_type": "credential.offered",
            "priority": "HIGH",
            "ttl_seconds": 3600,
            "correlation_id": "flow-123",
            "data": {"offer_uri": "openid-credential-offer://example"},
            "target": {
                "user_id": "user-1",
                "email_addresses": ["holder@example.com"],
                "channels": ["EMAIL"]
            }
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {
        "id",
        "title",
        "body",
        "data",
        "event_type",
        "priority",
        "target",
        "ttl_seconds",
        "correlation_id",
        "created_at",
    }
    assert body["title"] == "Your credential is ready"
    assert body["body"] == "Tap to add it to your wallet."
    assert body["data"] == {"offer_uri": "openid-credential-offer://example"}
    assert body["event_type"] == "credential.offered"
    assert body["priority"] == "HIGH"
    assert body["ttl_seconds"] == 3600
    assert body["correlation_id"] == "flow-123"
    assert body["target"] == {
        "user_id": "user-1",
        "device_tokens": [],
        "webhook_endpoints": [],
        "email_addresses": ["holder@example.com"],
        "channels": ["EMAIL"],
    }

    delivery_response = client.get(f"/v1/notifications/{body['id']}/delivery-results")
    assert delivery_response.status_code == 200
    result = delivery_response.json()
    assert len(result) == 1
    assert result[0]["notification_id"] == body["id"]
    assert result[0]["channel"] == "EMAIL"
    assert result[0]["success"] is True
    assert result[0]["should_retry"] is False
    # None fields excluded by exclude_none
    assert "error_code" not in result[0]
    assert "retry_after" not in result[0]


def test_send_notification_rejects_non_https_webhook_targets():
    repo = notification.InMemoryNotificationRepository()
    client = _build_client(repo)

    response = client.post(
        "/v1/notifications/send",
        json={
            "title": "Webhook test",
            "body": "This should fail validation.",
            "target": {
                "webhook_endpoints": ["http://example.com/hook"],
                "channels": ["WEBHOOK"]
            }
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "Webhook endpoints must use HTTPS"


def test_unread_count_alias_and_mark_unread_round_trip():
    repo = notification.InMemoryNotificationRepository()
    client = _build_client(repo)

    send_response = client.post(
        "/v1/notifications/send",
        json={
            "recipient_id": "user-1",
            "recipient_email": "holder@example.com",
            "title": "Read state",
            "body": "Hello",
            "target": {
                "user_id": "user-1",
                "email_addresses": ["holder@example.com"],
                "channels": ["EMAIL"]
            }
        },
    )
    notification_id = send_response.json()["id"]

    unread_before = client.get("/v1/notifications/unread-count", params={"recipient_id": "user-1"})
    assert unread_before.status_code == 200
    assert unread_before.json()["count"] == 1

    mark_read = client.patch(f"/v1/notifications/{notification_id}/read")
    assert mark_read.status_code == 200
    assert mark_read.json()["id"] == notification_id

    unread_after_read = client.get("/v1/notifications/unread-count", params={"recipient_id": "user-1"})
    assert unread_after_read.json()["count"] == 0

    mark_unread = client.delete(f"/v1/notifications/{notification_id}/read")
    assert mark_unread.status_code == 200
    assert mark_unread.json()["id"] == notification_id

    unread_after_unread = client.get("/v1/notifications/unread-count", params={"recipient_id": "user-1"})
    assert unread_after_unread.json()["count"] == 1


def test_get_notification_returns_protocol_payload_shape_only():
    repo = notification.InMemoryNotificationRepository()
    client = _build_client(repo)

    send_response = client.post(
        "/v1/notifications/send",
        json={
            "title": "Credential revoked",
            "body": "A credential was revoked.",
            "event_type": "credential.revoked",
            "priority": "CRITICAL",
            "ttl_seconds": 120,
            "collapse_key": "credential-status",
            "correlation_id": "cred-123",
            "target": {
                "organization_id": "org-1",
                "channels": ["EMAIL"],
                "email_addresses": ["holder@example.com"]
            }
        },
    )
    notification_id = send_response.json()["id"]

    get_response = client.get(f"/v1/notifications/{notification_id}")

    assert get_response.status_code == 200
    body = get_response.json()
    assert set(body) == {
        "id",
        "title",
        "body",
        "data",
        "event_type",
        "priority",
        "target",
        "ttl_seconds",
        "collapse_key",
        "correlation_id",
        "created_at",
    }
    assert body["event_type"] == "credential.revoked"
    assert body["priority"] == "CRITICAL"
    assert body["collapse_key"] == "credential-status"
    assert body["correlation_id"] == "cred-123"
    assert body["target"] == {
        "organization_id": "org-1",
        "device_tokens": [],
        "webhook_endpoints": [],
        "email_addresses": ["holder@example.com"],
        "channels": ["EMAIL"],
    }