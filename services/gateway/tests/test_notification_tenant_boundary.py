from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse
import pytest

import gateway.routes.notifications as notification_routes
from gateway.routes.notifications import (
    notification_router,
    subscription_router,
    webhook_router,
)


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(notification_router)
    app.include_router(subscription_router)
    app.include_router(webhook_router)

    @app.middleware("http")
    async def authorized_organization(request, call_next):
        request.state.organization_id = "org-a"
        request.state.user_id = "user-a"
        return await call_next(request)

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
        response = client.request(
            method, path, json={} if method in {"PATCH", "POST"} else None
        )
        assert response.status_code == 422
        assert (
            response.json()["detail"] == "organization_id query parameter is required"
        )


def test_nested_subscription_routes_require_explicit_organization_scope() -> None:
    client = _client()

    for method in ("GET", "PATCH", "DELETE"):
        response = client.request(
            method,
            "/v1/subscriptions/subscription-b",
            json={} if method == "PATCH" else None,
        )
        assert response.status_code == 422
        assert (
            response.json()["detail"] == "organization_id query parameter is required"
        )


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "/v1/webhooks?organization_id=org-b", None),
        (
            "POST",
            "/v1/webhooks?organization_id=org-a",
            {"organization_id": "org-b"},
        ),
        ("GET", "/v1/subscriptions?organization_id=org-b", None),
        (
            "POST",
            "/v1/notifications/send?organization_id=org-a",
            {"organization_id": "org-b"},
        ),
        (
            "POST",
            "/v1/notifications/send?organization_id=org-a",
            {
                "organization_id": "org-a",
                "target": {"organization_id": "org-b"},
            },
        ),
    ],
)
def test_forwarded_notification_routes_reject_conflicting_organization_scope(
    method: str,
    path: str,
    body: dict | None,
) -> None:
    response = _client().request(method, path, json=body)

    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "Organization scope does not match authorized organization"
    )


def test_sse_rejects_cross_tenant_and_cross_user_filters() -> None:
    client = _client()

    wrong_tenant = client.get("/v1/notifications/events/push?organization_id=org-b")
    wrong_user = client.get(
        "/v1/notifications/events/push?organization_id=org-a&user_id=user-b"
    )

    assert wrong_tenant.status_code == 403
    assert wrong_user.status_code == 403
    assert wrong_user.json()["detail"] == (
        "User scope does not match authenticated user"
    )


def test_notification_proxy_injects_the_authorized_organization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict = {}

    class Registry:
        @staticmethod
        def get_service_url(service: str) -> str:
            assert service == "notifications"
            return "http://notifications"

    async def fake_proxy(request, service_url, path, **kwargs):
        captured.update(
            {
                "service_url": service_url,
                "path": path,
                "inject_params": kwargs.get("inject_params"),
            }
        )
        return JSONResponse({"ok": True})

    monkeypatch.setattr(notification_routes, "get_registry", Registry)
    monkeypatch.setattr(notification_routes, "proxy_request", fake_proxy)

    response = _client().get("/v1/notifications?limit=10")

    assert response.status_code == 200
    assert captured == {
        "service_url": "http://notifications",
        "path": "/v1/notifications",
        "inject_params": {"organization_id": "org-a"},
    }
