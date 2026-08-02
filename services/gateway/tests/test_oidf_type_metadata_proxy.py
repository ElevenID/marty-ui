"""Public gateway routing for OID4VCI SD-JWT VC Type Metadata."""
from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

import gateway.main as gateway_main


class _Registry:
    def get_service_url(self, service_name: str) -> str:
        assert service_name == "issuance"
        return "http://issuance-service"


class _Client:
    async def get(self, url: str, *, timeout: float) -> httpx.Response:
        assert url == "http://issuance-service/credentials/default"
        assert timeout == 10.0
        return httpx.Response(
            200,
            json={"vct": "https://issuer.example.test/credentials/default"},
            headers={"content-type": "application/json"},
        )


def test_gateway_proxies_public_sd_jwt_type_metadata(monkeypatch) -> None:
    monkeypatch.setattr(gateway_main, "get_registry", lambda: _Registry())
    monkeypatch.setattr(gateway_main, "get_http_client", lambda: _Client())

    response = TestClient(gateway_main.create_app()).get("/credentials/default")

    assert response.status_code == 200
    assert response.json()["vct"] == "https://issuer.example.test/credentials/default"


def test_gateway_does_not_publish_obsolete_spruce_discovery_routes() -> None:
    client = TestClient(gateway_main.create_app())

    for path in (
        "/.well-known/openid-credential-issuer/org/org-a/spruce",
        "/org/org-a/spruce/.well-known/openid-credential-issuer",
        "/.well-known/oauth-authorization-server/org/org-a/spruce",
        "/org/org-a/spruce/.well-known/oauth-authorization-server",
    ):
        assert client.get(path).status_code == 404
