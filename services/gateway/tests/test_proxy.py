from __future__ import annotations

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
