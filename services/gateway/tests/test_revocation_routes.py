"""Tests for revocation gateway routes."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from starlette.requests import Request
from starlette.responses import Response

from gateway.routes import revocation


def _build_request(path: str, method: str = "GET") -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
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


class _Registry:
    def get_service_url(self, service_name: str) -> str:
        assert service_name == "revocation-profiles"
        return "http://revocation-profile-service"


@pytest.mark.asyncio
async def test_status_list_document_proxies_to_revocation_profile_service(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, str] = {}

    async def _proxy_request(request, service_url, path):
        captured.update({
            "service_url": service_url,
            "path": path,
        })
        return Response(
            content=b'{"type":"BitstringStatusListCredential"}',
            media_type="application/vc+ld+json",
        )

    monkeypatch.setattr(revocation, "get_registry", lambda: _Registry())
    monkeypatch.setattr(revocation, "proxy_request", _proxy_request)

    response = await revocation.get_status_list_document(
        "00000000-0000-0000-0000-000000000001",
        "70000000-0000-0000-0000-000000000001",
        "bitstring-status-list",
        "revocation",
        _build_request(
            "/v1/organizations/00000000-0000-0000-0000-000000000001"
            "/revocation-profiles/70000000-0000-0000-0000-000000000001"
            "/status-lists/bitstring-status-list/revocation"
        ),
    )

    assert response.status_code == 200
    assert response.media_type == "application/vc+ld+json"
    assert captured == {
        "service_url": "http://revocation-profile-service",
        "path": (
            "/v1/organizations/00000000-0000-0000-0000-000000000001"
            "/revocation-profiles/70000000-0000-0000-0000-000000000001"
            "/status-lists/bitstring-status-list/revocation"
        ),
    }
