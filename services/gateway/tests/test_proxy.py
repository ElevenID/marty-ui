from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI, Request

from gateway import proxy


@pytest.mark.asyncio
async def test_proxy_request_normalizes_upstream_read_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class Client:
        def __init__(self) -> None:
            self.calls = 0

        async def request(self, *, method, url, headers, content, timeout):
            self.calls += 1
            request = httpx.Request(method, url)
            raise httpx.ReadError("upstream closed the stream", request=request)

    client = Client()
    monkeypatch.setattr(proxy, "_http_client", client)

    app = FastAPI()

    @app.get("/proxy")
    async def proxy_route(request: Request):
        return await proxy.proxy_request(
            request,
            "http://organization:8002",
            "/v1/organizations/org-1/environment",
        )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as test_client:
        response = await test_client.get("/proxy")

    assert response.status_code == 503
    body = response.json()
    assert body["error"] == "service_unavailable"
    assert body["error_description"] == "Service unavailable"
    assert body["message_id"]
    assert client.calls == 3


@pytest.mark.asyncio
async def test_resource_exists_injects_internal_service_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    class Registry:
        def get_service_url(self, service_name: str) -> str:
            assert service_name == "issuance"
            return "http://issuance:8005"

    class Client:
        async def get(self, url, *, timeout, headers):
            captured.update(url=url, timeout=timeout, headers=headers)
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr(proxy, "_registry", Registry())
    monkeypatch.setattr(proxy, "_http_client", Client())

    exists = await proxy._resource_exists(
        "issuance",
        "/v1/application-templates/template-1",
        inject_headers={"X-API-Key": "internal-secret"},
    )

    assert exists is True
    assert captured == {
        "url": "http://issuance:8005/v1/application-templates/template-1",
        "timeout": 10.0,
        "headers": {"X-API-Key": "internal-secret"},
    }


@pytest.mark.asyncio
async def test_proxy_request_replaces_caller_internal_headers_with_trusted_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = {}

    class Client:
        async def request(self, *, method, url, headers, content, timeout):
            captured.update(method=method, url=url, headers=headers, content=content, timeout=timeout)
            return httpx.Response(200, json={"ok": True})

    monkeypatch.setattr(proxy, "_http_client", Client())

    app = FastAPI()

    @app.post("/proxy")
    async def proxy_route(request: Request):
        request.state.user_id = "trusted-user"
        request.state.user_email = "trusted@example.com"
        request.state.user_domain = "example.com"
        request.state.organization_id = "trusted-org"
        request.state.api_key_id = "trusted-key-id"
        request.state.api_key_scopes = ["integrations:write"]
        request.state.org_plan = "enterprise"
        request.state.org_permissions = {"integration-connector:edit"}
        request.state.org_roles = {"integration_admin"}
        request.state.required_permission = "integration-connector:edit"
        return await proxy.proxy_request(
            request,
            "http://issuance:8005",
            "/v1/integrations/canvas/platforms/platform-1",
            inject_headers={"X-API-Key": "internal-secret"},
        )

    spoofed_headers = {
        "X-API-Key": "caller-secret",
        "X-Api-Key-Id": "caller-key-id",
        "X-Api-Key-Scopes": "admin:full",
        "X-User-Id": "caller-user",
        "X-User-Email": "caller@example.net",
        "X-User-Domain": "example.net",
        "X-Organization-ID": "caller-org",
        "X-Org-Plan": "caller-plan",
        "X-Org-Permissions": "admin:full",
        "X-Org-Roles": "owner",
        "X-Required-Permission": "organization:delete",
    }

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as test_client:
        response = await test_client.post("/proxy", headers=spoofed_headers, json={"name": "Canvas"})

    assert response.status_code == 200
    forwarded = httpx.Headers(captured["headers"])
    assert forwarded.get_list("x-api-key") == ["internal-secret"]
    assert forwarded["x-api-key-id"] == "trusted-key-id"
    assert forwarded["x-api-key-scopes"] == "integrations:write"
    assert forwarded["x-user-id"] == "trusted-user"
    assert forwarded["x-user-email"] == "trusted@example.com"
    assert forwarded["x-user-domain"] == "example.com"
    assert forwarded["x-organization-id"] == "trusted-org"
    assert forwarded["x-org-plan"] == "enterprise"
    assert forwarded["x-org-permissions"] == "integration-connector:edit"
    assert forwarded["x-org-roles"] == "integration_admin"
    assert forwarded["x-required-permission"] == "integration-connector:edit"
