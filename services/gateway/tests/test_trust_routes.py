from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from gateway.models import (
    OrganizationTrustProfileCreate,
    OrganizationTrustProfileResponse,
    TrustProfileCreate,
)
from gateway.routes import trust as trust_routes


@pytest.mark.asyncio
async def test_update_trust_profile_route_accepts_patch_and_proxies(
    monkeypatch: pytest.MonkeyPatch,
):
    app = FastAPI()
    app.include_router(trust_routes.trust_profile_router)

    captured: dict[str, str] = {}

    def fake_get_registry() -> SimpleNamespace:
        return SimpleNamespace(
            get_service_url=lambda service_name: f"http://{service_name}"
        )

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


@pytest.mark.asyncio
async def test_registry_sync_route_proxies_the_authenticated_profile_operation(
    monkeypatch: pytest.MonkeyPatch,
):
    app = FastAPI()
    app.include_router(trust_routes.trust_profile_router)
    captured: dict[str, str] = {}

    monkeypatch.setattr(
        trust_routes,
        "get_registry",
        lambda: SimpleNamespace(
            get_service_url=lambda service_name: f"http://{service_name}"
        ),
    )

    profile_id = "11111111-1111-4111-8111-111111111111"

    async def fake_proxy_request(request, service_url: str, path: str, **_kwargs):
        captured.update(method=request.method, service_url=service_url, path=path)
        return JSONResponse(
            {
                "trust_profile_id": profile_id,
                "sources": [
                    {
                        "url": "https://registry.example/sync",
                        "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
                        "sequence": 1,
                        "csca_entries": 1,
                        "dsc_entries": 0,
                        "synchronized_at": "2026-08-07T12:00:00Z",
                    }
                ],
                "synchronized_at": "2026-08-07T12:00:00Z",
            }
        )

    monkeypatch.setattr(trust_routes, "proxy_request", fake_proxy_request)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(f"/v1/trust-profiles/{profile_id}/registry-sync")

    assert response.status_code == 200
    assert response.json()["trust_profile_id"] == profile_id
    assert captured == {
        "method": "POST",
        "service_url": "http://trust-profiles",
        "path": f"/v1/trust-profiles/{profile_id}/registry-sync",
    }


@pytest.mark.asyncio
async def test_registry_sync_route_fails_closed_on_invalid_service_response(
    monkeypatch: pytest.MonkeyPatch,
):
    app = FastAPI()
    app.include_router(trust_routes.trust_profile_router)
    profile_id = "11111111-1111-4111-8111-111111111111"

    monkeypatch.setattr(
        trust_routes,
        "get_registry",
        lambda: SimpleNamespace(
            get_service_url=lambda service_name: f"http://{service_name}"
        ),
    )

    async def fake_proxy_request(*_args, **_kwargs):
        return JSONResponse(
            {
                "trust_profile_id": profile_id,
                "sources": [
                    {
                        "url": "http://internal.invalid/sync",
                        "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
                        "sequence": 1,
                        "csca_entries": 1,
                        "dsc_entries": 0,
                        "synchronized_at": "2026-08-07T12:00:00Z",
                    }
                ],
                "synchronized_at": "2026-08-07T12:00:00Z",
            }
        )

    monkeypatch.setattr(trust_routes, "proxy_request", fake_proxy_request)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(f"/v1/trust-profiles/{profile_id}/registry-sync")

    assert response.status_code == 502
    assert response.json()["error"] == "invalid_service_response"


def test_public_trust_profile_model_rejects_placeholder_registry_imports() -> None:
    base = {
        "organization_id": "org-1",
        "name": "Registry profile",
        "trust_sources": [
            {
                "source_type": "TRUST_LIST",
                "url": "https://registry.example/sync",
                "registry_sync": {
                    "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
                    "refresh_interval_hours": 24,
                },
            }
        ],
    }
    validated = TrustProfileCreate.model_validate(base)
    assert validated.trust_sources[0].registry_sync is not None

    with pytest.raises(ValidationError, match="extra_forbidden"):
        TrustProfileCreate.model_validate(
            {
                **base,
                "registry_imports": [
                    {"registry_type": "EU_TRUST_LIST", "sync_enabled": True}
                ],
            }
        )

    with pytest.raises(ValidationError, match="HTTPS URL"):
        TrustProfileCreate.model_validate(
            {
                **base,
                "trust_sources": [
                    {
                        "source_type": "TRUST_LIST",
                        "url": "http://127.0.0.1/internal",
                        "registry_sync": {
                            "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
                            "refresh_interval_hours": 24,
                        },
                    }
                ],
            }
        )


def test_organization_trust_profile_models_reject_custody_selectors():
    with pytest.raises(ValidationError, match="extra_forbidden"):
        OrganizationTrustProfileCreate.model_validate(
            {
                "framework_id": "eudi",
                "name": "Public trust profile",
                "key_management": {"source": "kms"},
            }
        )

    with pytest.raises(ValidationError, match="private custody selector"):
        OrganizationTrustProfileCreate.model_validate(
            {
                "framework_id": "eudi",
                "name": "Public trust profile",
                "metadata": {"nested": {"signing_agent_url": "https://signer.invalid"}},
            }
        )

    with pytest.raises(ValidationError, match="private custody selector"):
        OrganizationTrustProfileResponse.model_validate(
            {
                "id": "profile-1",
                "organization_id": "org-1",
                "framework_id": "eudi",
                "name": "Public trust profile",
                "compliance_status": "COMPLIANT",
                "metadata": {"key_binding": {"key_id": "private"}},
                "created_at": "2026-07-30T00:00:00Z",
            }
        )


@pytest.mark.asyncio
async def test_organization_trust_profile_key_utility_routes_are_not_public():
    app = FastAPI()
    app.include_router(trust_routes.organization_trust_profile_router)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        for suffix in ("test-key-connection", "create-or-associate-key"):
            response = await client.post(
                f"/v1/organizations/org-1/trust-profiles/profile-1/{suffix}",
                json={},
            )
            assert response.status_code in {404, 405}
