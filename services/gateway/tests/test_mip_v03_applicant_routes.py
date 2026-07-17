from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from gateway.routes import applicants
from gateway.routes.applicants import applicant_router
from gateway.main import app


def test_gateway_exposes_only_mip_v03_applicant_routes() -> None:
    paths = {route.path for route in applicant_router.routes}
    assert "/v1/me/applicant-profile" in paths
    assert "/v1/me/applications" in paths
    assert "/v1/organizations/{organization_id}/applicants" in paths
    assert "/v1/applicants/applications" not in paths
    assert "/v1/applicants/org-applications" not in paths
    assert all(not path.startswith("/v1/applicants/profiles") for path in paths)


def test_gateway_does_not_publish_generic_application_routes() -> None:
    paths = set(app.openapi()["paths"])

    assert "/v1/me/applications" in paths
    assert all(not path.startswith("/v1/applications") for path in paths)


@pytest.mark.asyncio
async def test_self_profile_forwards_immutable_session_organization(monkeypatch: pytest.MonkeyPatch) -> None:
    proxy = AsyncMock(return_value=SimpleNamespace(status_code=200))
    monkeypatch.setattr(applicants, "proxy_request", proxy)
    monkeypatch.setattr(applicants, "_applicant_url", lambda: "http://applicant:8006")
    request = SimpleNamespace(state=SimpleNamespace(session_organization_id="org-default"))

    response = await applicants.get_my_applicant_profile(request)

    assert response.status_code == 200
    proxy.assert_awaited_once_with(
        request,
        "http://applicant:8006",
        "/v1/me/applicant-profile",
        inject_headers={"X-Organization-ID": "org-default"},
    )


@pytest.mark.asyncio
async def test_application_creation_forwards_immutable_applicant_organization(monkeypatch: pytest.MonkeyPatch) -> None:
    proxy = AsyncMock(return_value=SimpleNamespace(status_code=200))
    monkeypatch.setattr(applicants, "proxy_request", proxy)
    monkeypatch.setattr(applicants, "_applicant_url", lambda: "http://applicant:8006")
    request = SimpleNamespace(state=SimpleNamespace(session_organization_id="org-default"))

    response = await applicants.create_my_application(request)

    assert response.status_code == 200
    proxy.assert_awaited_once_with(
        request,
        "http://applicant:8006",
        "/v1/me/applications",
        inject_headers={"X-Organization-ID": "org-default"},
    )
