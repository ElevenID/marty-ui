from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from gateway.routes import trust as trust_routes


@pytest.mark.asyncio
async def test_update_trust_profile_route_accepts_patch_and_proxies(monkeypatch: pytest.MonkeyPatch):
    app = FastAPI()
    app.include_router(trust_routes.trust_profile_router)

    captured: dict[str, str] = {}

    def fake_get_registry() -> SimpleNamespace:
        return SimpleNamespace(get_service_url=lambda service_name: f"http://{service_name}")

    async def fake_proxy_request(request, service_url: str, path: str, **_kwargs):
        captured["method"] = request.method
        captured["service_url"] = service_url
        captured["path"] = path
        return JSONResponse({"ok": True}, status_code=200)

    monkeypatch.setattr(trust_routes, "get_registry", fake_get_registry)
    monkeypatch.setattr(trust_routes, "proxy_request", fake_proxy_request)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.patch(
            "/v1/trust-profiles/profile-123",
            json={"description": "Updated"},
        )

    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert captured == {
        "method": "PATCH",
        "service_url": "http://trust-profiles",
        "path": "/v1/trust-profiles/profile-123",
    }


@pytest.mark.asyncio
async def test_update_trust_profile_route_no_longer_accepts_put():
    app = FastAPI()
    app.include_router(trust_routes.trust_profile_router)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        response = await client.put(
            "/v1/trust-profiles/profile-123",
            json={"description": "Updated"},
        )

    assert response.status_code == 405