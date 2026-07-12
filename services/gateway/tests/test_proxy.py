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
