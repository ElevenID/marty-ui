from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from starlette.requests import Request
from starlette.responses import JSONResponse

from gateway.routes import credentials


class _Registry:
    def get_service_url(self, service_name: str) -> str:
        assert service_name == "credential-templates"
        return "http://credential-template-service"


def _request(path: str = "/v1/delivery-destinations") -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": path,
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "client": ("testclient", 1234),
        "server": ("testserver", 80),
        "state": {},
        "app": SimpleNamespace(state=SimpleNamespace()),
    }

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


@pytest.mark.asyncio
async def test_delivery_destination_gateway_proxy(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _proxy(request, service_url, path):
        captured.update({"service_url": service_url, "path": path})
        return JSONResponse([
            {
                "id": "dd-canvas-credentials-institutional",
                "provider": "canvas_credentials",
                "mode": "organization_mirror",
            }
        ])

    monkeypatch.setattr(credentials, "get_registry", lambda: _Registry())
    monkeypatch.setattr(credentials, "proxy_request", _proxy)

    response = await credentials.list_delivery_destinations(_request())
    body = json.loads(response.body)

    assert captured == {
        "service_url": "http://credential-template-service",
        "path": "/v1/delivery-destinations",
    }
    assert body[0]["provider"] == "canvas_credentials"


@pytest.mark.asyncio
async def test_wallet_open_link_gateway_proxy(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _proxy(request, service_url, path):
        captured.update({"service_url": service_url, "path": path})
        return JSONResponse(
            {
                "wallet_id": "wr-waltid-001",
                "open_uri": "https://wallet.demo.walt.id/api/siop/initiateIssuance?credential_offer_uri=redacted",
            }
        )

    monkeypatch.setattr(credentials, "get_registry", lambda: _Registry())
    monkeypatch.setattr(credentials, "proxy_request", _proxy)

    response = await credentials.build_wallet_registry_open_link(
        "wr-waltid-001",
        _request("/v1/wallet-registry/wr-waltid-001/open-link"),
    )
    body = json.loads(response.body)

    assert captured == {
        "service_url": "http://credential-template-service",
        "path": "/v1/wallet-registry/wr-waltid-001/open-link",
    }
    assert body["wallet_id"] == "wr-waltid-001"
    assert body["open_uri"].startswith("https://wallet.demo.walt.id/api/siop/initiateIssuance")
