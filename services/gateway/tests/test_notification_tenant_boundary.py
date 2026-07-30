from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.routes.notifications import subscription_router, webhook_router


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(subscription_router)
    app.include_router(webhook_router)
    return TestClient(app)


def test_nested_webhook_routes_require_explicit_organization_scope() -> None:
    client = _client()

    for method, path in (
        ("GET", "/v1/webhooks/webhook-b"),
        ("PATCH", "/v1/webhooks/webhook-b"),
        ("DELETE", "/v1/webhooks/webhook-b"),
        ("GET", "/v1/webhooks/webhook-b/deliveries"),
        ("POST", "/v1/webhooks/webhook-b/test"),
    ):
        response = client.request(method, path, json={} if method in {"PATCH", "POST"} else None)
        assert response.status_code == 422
        assert response.json()["detail"] == "organization_id query parameter is required"


def test_nested_subscription_routes_require_explicit_organization_scope() -> None:
    client = _client()

    for method in ("GET", "PATCH", "DELETE"):
        response = client.request(
            method,
            "/v1/subscriptions/subscription-b",
            json={} if method == "PATCH" else None,
        )
        assert response.status_code == 422
        assert response.json()["detail"] == "organization_id query parameter is required"
