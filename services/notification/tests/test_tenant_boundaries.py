from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from services.notification import main as notification


def _build_client() -> TestClient:
    app = FastAPI()
    app.include_router(notification.webhook_router)
    app.include_router(notification.subscription_router)
    notification._repo = notification.InMemoryNotificationRepository()
    return TestClient(app)


def _create_webhook(client: TestClient, organization_id: str, name: str) -> dict:
    response = client.post(
        "/v1/webhooks",
        json={
            "organization_id": organization_id,
            "name": name,
            "url": f"https://hooks.example.com/{organization_id}",
            "event_types": ["credential.issued"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _resolve_test_webhook_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        notification.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (
                notification.socket.AF_INET,
                notification.socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 443),
            )
        ],
    )


def test_webhook_id_routes_fail_closed_for_a_different_organization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _resolve_test_webhook_hostname(monkeypatch)
    client = _build_client()
    webhook = _create_webhook(client, "org-b", "Organization B callback")
    path = f"/v1/webhooks/{webhook['id']}"

    assert client.get(path).status_code == 422
    assert client.get(path, params={"organization_id": "org-a"}).status_code == 404
    assert client.patch(
        path,
        params={"organization_id": "org-a"},
        json={"description": "cross-tenant overwrite"},
    ).status_code == 404
    assert client.delete(path, params={"organization_id": "org-a"}).status_code == 404
    assert client.get(
        f"{path}/deliveries",
        params={"organization_id": "org-a"},
    ).status_code == 404

    allowed = client.get(path, params={"organization_id": "org-b"})
    assert allowed.status_code == 200
    assert allowed.json()["organization_id"] == "org-b"
    assert allowed.json()["name"] == "Organization B callback"


def test_subscription_id_routes_fail_closed_for_a_different_organization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _resolve_test_webhook_hostname(monkeypatch)
    client = _build_client()
    webhook = _create_webhook(client, "org-b", "Organization B callback")
    created = client.post(
        "/v1/subscriptions",
        json={
            "organization_id": "org-b",
            "name": "Organization B events",
            "event_types": ["credential.issued"],
            "delivery_channel": "WEBHOOK",
            "delivery_target_id": webhook["id"],
        },
    )
    assert created.status_code == 200, created.text
    path = f"/v1/subscriptions/{created.json()['id']}"

    assert client.get(path).status_code == 422
    assert client.get(path, params={"organization_id": "org-a"}).status_code == 404
    assert client.patch(
        path,
        params={"organization_id": "org-a"},
        json={"name": "cross-tenant overwrite"},
    ).status_code == 404
    assert client.delete(path, params={"organization_id": "org-a"}).status_code == 404

    allowed = client.get(path, params={"organization_id": "org-b"})
    assert allowed.status_code == 200
    assert allowed.json()["organization_id"] == "org-b"
    assert allowed.json()["name"] == "Organization B events"
