"""Tests for dashboard-only organization routes."""
from __future__ import annotations

import json

import httpx
import pytest
from fastapi import FastAPI, Response

from gateway.routes import organizations
from gateway.routes.organizations import organization_router


async def _get(path: str, *, headers: dict[str, str] | None = None) -> httpx.Response:
    app = FastAPI()
    app.include_router(organization_router)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get(path, headers=headers)


@pytest.mark.asyncio
async def test_integration_info_returns_real_configured_quick_start_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PUBLIC_API_URL", "https://beta.elevenidllc.com")

    response = await _get("/v1/organizations/org-123/integration-info")

    assert response.status_code == 200
    body = response.json()
    assert body["org_id"] == "org-123"
    assert body["base_url"] == "https://beta.elevenidllc.com/v1"
    assert "dashboard_dependency_unavailable" not in response.text
    assert "POST \"https://beta.elevenidllc.com/v1/flows/instances\"" in body["example_request"]
    assert "X-API-Key: <api-key>" in body["example_request"]
    assert "X-Organization-ID: org-123" in body["example_request"]


@pytest.mark.asyncio
async def test_integration_info_uses_forwarded_host_when_public_url_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PUBLIC_API_URL", raising=False)
    monkeypatch.delenv("ISSUER_BASE_URL", raising=False)
    monkeypatch.delenv("PUBLIC_BASE_URL", raising=False)

    response = await _get(
        "/v1/organizations/org-123/integration-info",
        headers={"x-forwarded-proto": "https", "x-forwarded-host": "beta.elevenidllc.com"},
    )

    assert response.status_code == 200
    assert response.json()["base_url"] == "https://beta.elevenidllc.com/v1"


@pytest.mark.asyncio
async def test_runtime_status_route_returns_live_derived_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_load_runtime_status_payload(org_id: str, **kwargs):
        assert org_id == "org-123"
        return {
            "can_issue": True,
            "can_verify": True,
            "issuer_keys_valid": True,
            "issuer_active": True,
            "deployment_active": True,
            "policy_reachable": True,
            "last_issuance_timestamp": None,
            "last_verification_timestamp": None,
        }, None

    monkeypatch.setattr(organizations, "_load_runtime_status_payload", fake_load_runtime_status_payload)

    response = await _get("/v1/organizations/org-123/runtime/status")

    assert response.status_code == 200
    assert response.json()["can_issue"] is True


@pytest.mark.asyncio
async def test_applicant_stats_route_returns_live_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_load_applicant_stats_payload(org_id: str, **kwargs):
        assert org_id == "org-123"
        return {"pending": 2, "approved": 1, "issuable": 1, "total": 4}, None

    monkeypatch.setattr(organizations, "_load_applicant_stats_payload", fake_load_applicant_stats_payload)

    response = await _get("/v1/organizations/org-123/dashboard/applicant-stats")

    assert response.status_code == 200
    assert response.json() == {"pending": 2, "approved": 1, "issuable": 1, "total": 4}


@pytest.mark.asyncio
async def test_runtime_status_derives_readiness_from_active_artifacts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_request_service_json_with_headers(service_name, path, **kwargs):
        if service_name == "credential-templates":
            return [
                {
                    "id": "template-1",
                    "status": "ACTIVE",
                    "issuer_profile_id": "issuer-1",
                    "key_access_mode": "REMOTE_SIGNING",
                }
            ], None
        if service_name == "presentation-policies":
            return [{"id": "policy-1", "status": "active"}], None
        if service_name == "deployment-profiles":
            return [{"id": "deployment-1", "status": "active"}], None
        if service_name == "flows":
            return [{"id": "flow-1", "status": "ACTIVE", "credential_template_id": "template-1"}], None
        raise AssertionError(f"unexpected service {service_name}")

    monkeypatch.setattr(organizations, "_request_service_json_with_headers", fake_request_service_json_with_headers)

    payload, error = await organizations._load_runtime_status_payload("org-123")

    assert error is None
    assert payload["can_issue"] is True
    assert payload["can_verify"] is True
    assert payload["artifact_counts"]["kms_backed_credential_templates"] == 1


@pytest.mark.asyncio
async def test_applicant_stats_counts_application_statuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_request_service_json_with_headers(service_name, path, **kwargs):
        assert service_name == "applicant"
        assert path == "/v1/organizations/org-123/applicants"
        return {"items": [
            {"id": "app-1", "status": "SUBMITTED"},
            {"id": "app-2", "status": "UNDER_REVIEW"},
            {"id": "app-3", "status": "APPROVED"},
            {"id": "app-4", "status": "OFFERED"},
            {"id": "app-5", "status": "CREDENTIALED"},
        ]}, None

    monkeypatch.setattr(organizations, "_request_service_json_with_headers", fake_request_service_json_with_headers)

    payload, error = await organizations._load_applicant_stats_payload("org-123")

    assert error is None
    assert payload == {"pending": 2, "approved": 1, "issuable": 2, "total": 5}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "proxied_path"),
    [
        ("/v1/organizations/org-123/environment", "/v1/organizations/org-123/environment"),
        ("/v1/organizations/org-123/team/snapshot", "/v1/organizations/org-123/team/snapshot"),
    ],
)
async def test_dashboard_routes_with_real_sources_proxy_org_service(
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    proxied_path: str,
) -> None:
    observed: dict[str, str] = {}

    class Registry:
        def get_service_url(self, service: str) -> str:
            assert service == "organizations"
            return "http://organization:8002"

    async def fake_proxy_request(request, service_url, requested_path, inject_params=None):
        observed["service_url"] = service_url
        observed["path"] = requested_path
        observed["organization_id"] = (inject_params or {}).get("organization_id")
        return Response(
            content=json.dumps({"proxied": True}),
            status_code=200,
            media_type="application/json",
        )

    monkeypatch.setattr(organizations, "get_registry", lambda: Registry())
    monkeypatch.setattr(organizations, "proxy_request", fake_proxy_request)

    response = await _get(path)

    assert response.status_code == 200
    assert response.json() == {"proxied": True}
    assert observed["service_url"] == "http://organization:8002"
    assert observed["path"] == proxied_path
    assert observed["organization_id"] == "org-123"


@pytest.mark.asyncio
async def test_dashboard_proxy_routes_preserve_upstream_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Registry:
        def get_service_url(self, service: str) -> str:
            assert service == "organizations"
            return "http://organization:8002"

    async def fake_proxy_request(request, service_url, requested_path, inject_params=None):
        return Response(
            content=json.dumps(
                {
                    "error": "service_unavailable",
                    "error_description": "Organization service unavailable",
                    "message_id": "msg-dashboard-1",
                }
            ),
            status_code=503,
            media_type="application/json",
        )

    monkeypatch.setattr(organizations, "get_registry", lambda: Registry())
    monkeypatch.setattr(organizations, "proxy_request", fake_proxy_request)

    response = await _get("/v1/organizations/org-123/environment")

    assert response.status_code == 503
    body = response.json()
    assert body["error"] == "service_unavailable"
    assert body["message_id"] == "msg-dashboard-1"


@pytest.mark.asyncio
async def test_audit_events_route_preserves_precise_filters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class Registry:
        def get_service_url(self, service: str) -> str:
            assert service == "organizations"
            return "http://organization:8002"

    async def fake_proxy_request(request, service_url, requested_path, inject_params=None):
        observed["service_url"] = service_url
        observed["path"] = requested_path
        observed["params"] = inject_params
        return Response(
            content=json.dumps({"events": [], "total": 0}),
            status_code=200,
            media_type="application/json",
        )

    monkeypatch.setattr(organizations, "get_registry", lambda: Registry())
    monkeypatch.setattr(organizations, "proxy_request", fake_proxy_request)

    response = await _get(
        "/v1/organizations/org-123/audit-events"
        "?actor=user-1"
        "&resource_type=api_key"
        "&resource_id=key-1"
        "&action=api_key.created"
        "&severity=warning"
        "&ip_address=127.0.0.1"
        "&start_date=2026-07-10T00:00:00Z"
        "&end_date=2026-07-10T01:00:00Z"
        "&search=Console"
        "&limit=25"
        "&offset=50"
    )

    assert response.status_code == 200
    assert observed["service_url"] == "http://organization:8002"
    assert observed["path"] == "/v1/organizations/audit/events"
    assert observed["params"] == {
        "organization_id": "org-123",
        "per_page": 25,
        "page": 3,
        "resource_type": "api_key",
        "resource_id": "key-1",
        "action": "api_key.created",
        "actor": "user-1",
        "severity": "warning",
        "ip_address": "127.0.0.1",
        "start_date": "2026-07-10T00:00:00Z",
        "end_date": "2026-07-10T01:00:00Z",
        "search": "Console",
    }


@pytest.mark.asyncio
async def test_audit_export_route_preserves_precise_filters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class Registry:
        def get_service_url(self, service: str) -> str:
            assert service == "organizations"
            return "http://organization:8002"

    async def fake_proxy_request(request, service_url, requested_path, inject_params=None):
        observed["service_url"] = service_url
        observed["path"] = requested_path
        observed["params"] = inject_params
        return Response(
            content=json.dumps({"format": "csv", "content": ""}),
            status_code=200,
            media_type="application/json",
        )

    monkeypatch.setattr(organizations, "get_registry", lambda: Registry())
    monkeypatch.setattr(organizations, "proxy_request", fake_proxy_request)

    response = await _get(
        "/v1/organizations/org-123/audit-events/export"
        "?resource_type=api_key"
        "&resource_id=key-1"
        "&action=api_key.created"
        "&format=csv"
    )

    assert response.status_code == 200
    assert observed["service_url"] == "http://organization:8002"
    assert observed["path"] == "/v1/organizations/audit/events/export"
    assert observed["params"] == {
        "organization_id": "org-123",
        "format": "csv",
        "resource_type": "api_key",
        "resource_id": "key-1",
        "action": "api_key.created",
    }


@pytest.mark.asyncio
async def test_dashboard_service_helper_returns_mip_error_when_dependency_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Registry:
        def get_service_url(self, service: str) -> None:
            assert service == "credential-templates"
            return None

    payload, error = await organizations._request_service_json_with_headers(
        "credential-templates",
        "/v1/credential-templates",
        registry=Registry(),
    )

    assert payload == {}
    assert error is not None
    assert error.status_code == 503
    body = json.loads(error.body)
    assert body["error"] == "service_unavailable"
    assert body["service"] == "credential-templates"
    assert body["message_id"]


@pytest.mark.asyncio
async def test_dashboard_service_helper_returns_mip_error_for_invalid_json() -> None:
    class Registry:
        def get_service_url(self, service: str) -> str:
            assert service == "credential-templates"
            return "http://credential-template:8003"

    class Client:
        async def request(self, **kwargs):
            return httpx.Response(200, content=b"not-json")

    payload, error = await organizations._request_service_json_with_headers(
        "credential-templates",
        "/v1/credential-templates",
        registry=Registry(),
        client=Client(),
    )

    assert payload == {}
    assert error is not None
    assert error.status_code == 502
    body = json.loads(error.body)
    assert body["error"] == "invalid_upstream_response"
    assert body["service"] == "credential-templates"


@pytest.mark.asyncio
async def test_lifecycle_preserves_retention_summary_error_for_hosted_pilot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_request_service_json_with_headers(service_name, path, **kwargs):
        if service_name == "organizations":
            return {
                "created_at": "2026-07-09T00:00:00+00:00",
                "compliance_profiles": [],
                "plan_tier": "starter",
                "audit_retention_days": 30,
                "pilot_retention": {"enabled": True, "window_days": 30},
            }, None
        if service_name == "issuance":
            return {}, Response(
                content=json.dumps(
                    {
                        "error": "service_unavailable",
                        "error_description": "Issuance retention summary unavailable",
                        "message_id": "msg-retention-1",
                    }
                ),
                status_code=503,
                media_type="application/json",
            )
        raise AssertionError(f"unexpected service {service_name}")

    monkeypatch.setattr(organizations, "_request_service_json_with_headers", fake_request_service_json_with_headers)

    payload, error = await organizations._load_organization_lifecycle_payload("org-123")

    assert payload == {}
    assert error is not None
    assert error.status_code == 503
    body = json.loads(error.body)
    assert body["message_id"] == "msg-retention-1"
