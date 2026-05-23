"""Tests for gateway issuance route header injection (X-Issuer-Did)."""
from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from starlette.responses import JSONResponse

from gateway.routes import applicants
from gateway.routes import canvas_integrations
from gateway.routes import issuance
from gateway.registry import get_route_config


def _build_request(
    redis_client: AsyncMock | None = None,
    session_org_id: str | None = "org_123",
) -> object:
    """Minimal request stub for gateway issuance helpers."""
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/v1/issuance",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "client": ("testclient", 1234),
        "server": ("testserver", 80),
        "state": {},
        "app": SimpleNamespace(state=SimpleNamespace(redis_client=redis_client)),
    }

    from starlette.requests import Request

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(scope, receive)
    request.state.session_organization_id = session_org_id
    return request


class _Registry:
    def __init__(self, url: str = "http://issuance-service") -> None:
        self.url = url

    def get_service_url(self, service_name: str) -> str:
        assert service_name == "issuance"
        return self.url


class _NamedRegistry:
    def __init__(self, urls: dict[str, str]) -> None:
        self.urls = urls

    def get_service_url(self, service_name: str) -> str:
        return self.urls[service_name]


@pytest.mark.asyncio
async def test_application_evidence_summary_proxy_preserves_metadata(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _proxy(request, service_url, path, inject_headers=None):
        captured.update({
            "service_url": service_url,
            "path": path,
            "inject_headers": inject_headers,
        })
        return JSONResponse({
            "application_id": "app-1",
            "evidence_facts": [{"id": "fact-1", "fact_type": "canvas.course_completion"}],
            "policy_decision": {"allowed": True, "policy_source": "bundled"},
        })

    monkeypatch.setattr(issuance, "get_registry", lambda: _Registry())
    monkeypatch.setattr(issuance, "proxy_request", _proxy)
    monkeypatch.setattr(issuance, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    response = await issuance.get_application_evidence_summary("app-1", _build_request())
    body = json.loads(response.body)

    assert captured["service_url"] == "http://issuance-service"
    assert captured["path"] == "/v1/applications/app-1/evidence-summary"
    assert captured["inject_headers"] == {"X-API-Key": "secret"}
    assert body["evidence_facts"][0]["fact_type"] == "canvas.course_completion"
    assert body["policy_decision"]["allowed"] is True


@pytest.mark.asyncio
async def test_external_evidence_api_check_proxy_preserves_policy_metadata(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _proxy(request, service_url, path, inject_headers=None):
        captured.update({
            "service_url": service_url,
            "path": path,
            "inject_headers": inject_headers,
        })
        return JSONResponse({
            "application_id": "app-1",
            "check_id": "passport-document-check",
            "evidence_fact": {"id": "fact-1", "fact_type": "passport.document_verified"},
            "policy_decision": {"allowed": True, "policy_source": "bundled"},
        })

    monkeypatch.setattr(issuance, "get_registry", lambda: _Registry())
    monkeypatch.setattr(issuance, "proxy_request", _proxy)
    monkeypatch.setattr(issuance, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    response = await issuance.run_external_evidence_api_check(
        "app-1",
        "passport-document-check",
        _build_request(),
    )
    body = json.loads(response.body)

    assert captured["service_url"] == "http://issuance-service"
    assert captured["path"] == "/v1/applications/app-1/evidence/api-checks/passport-document-check/run"
    assert captured["inject_headers"] == {"X-API-Key": "secret"}
    assert body["evidence_fact"]["fact_type"] == "passport.document_verified"
    assert body["policy_decision"]["allowed"] is True


@pytest.mark.asyncio
async def test_canvas_evidence_event_status_proxy_preserves_metadata(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _proxy(request, service_url, path, inject_headers=None):
        captured.update({
            "service_url": service_url,
            "path": path,
            "inject_headers": inject_headers,
        })
        return JSONResponse({
            "provider_event_id": "evt-1",
            "evidence_facts": [{"id": "fact-1", "fact_type": "canvas.course_completion"}],
            "policy_decision": {"allowed": False, "policy_source": "policy_set"},
        })

    monkeypatch.setattr(canvas_integrations, "get_registry", lambda: _Registry())
    monkeypatch.setattr(canvas_integrations, "proxy_request", _proxy)
    monkeypatch.setattr(canvas_integrations, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    response = await canvas_integrations.get_canvas_evidence_event_status("acct-1", "evt-1", _build_request())
    body = json.loads(response.body)

    assert captured["service_url"] == "http://issuance-service"
    assert captured["path"] == "/v1/integrations/canvas/evidence-events/acct-1/evt-1"
    assert captured["inject_headers"] == {"X-API-Key": "secret"}
    assert body["evidence_facts"][0]["fact_type"] == "canvas.course_completion"
    assert body["policy_decision"]["policy_source"] == "policy_set"


@pytest.mark.asyncio
async def test_canvas_ags_score_event_proxy_preserves_signed_payload(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _proxy(request, service_url, path, inject_headers=None):
        captured.update({
            "service_url": service_url,
            "path": path,
            "inject_headers": inject_headers,
        })
        return JSONResponse({
            "source_event_id": "ags-evt-1",
            "evidence_facts": [{"id": "fact-ags-1", "fact_type": "canvas.assignment_score"}],
        })

    monkeypatch.setattr(canvas_integrations, "get_registry", lambda: _Registry())
    monkeypatch.setattr(canvas_integrations, "proxy_request", _proxy)
    monkeypatch.setattr(canvas_integrations, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    response = await canvas_integrations.process_canvas_ags_score_event(_build_request())
    body = json.loads(response.body)

    assert captured["service_url"] == "http://issuance-service"
    assert captured["path"] == "/v1/integrations/canvas/ags/score-events"
    assert captured["inject_headers"] is None
    assert body["evidence_facts"][0]["fact_type"] == "canvas.assignment_score"


@pytest.mark.asyncio
async def test_canvas_nrps_membership_event_proxy_preserves_signed_payload(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _proxy(request, service_url, path, inject_headers=None):
        captured.update({
            "service_url": service_url,
            "path": path,
            "inject_headers": inject_headers,
        })
        return JSONResponse({
            "source_event_id": "nrps-evt-1",
            "evidence_facts": [{"id": "fact-nrps-1", "fact_type": "canvas.nrps_membership"}],
        })

    monkeypatch.setattr(canvas_integrations, "get_registry", lambda: _Registry())
    monkeypatch.setattr(canvas_integrations, "proxy_request", _proxy)
    monkeypatch.setattr(canvas_integrations, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    response = await canvas_integrations.process_canvas_nrps_membership_event(_build_request())
    body = json.loads(response.body)

    assert captured["service_url"] == "http://issuance-service"
    assert captured["path"] == "/v1/integrations/canvas/nrps/membership-events"
    assert captured["inject_headers"] is None
    assert body["evidence_facts"][0]["fact_type"] == "canvas.nrps_membership"


@pytest.mark.asyncio
async def test_canvas_platform_and_program_binding_routes_proxy_with_management_header(monkeypatch: pytest.MonkeyPatch):
    captured: list[dict] = []

    async def _proxy(request, service_url, path, inject_headers=None):
        captured.append({
            "service_url": service_url,
            "path": path,
            "inject_headers": inject_headers,
        })
        return JSONResponse({"ok": True})

    monkeypatch.setattr(canvas_integrations, "get_registry", lambda: _Registry())
    monkeypatch.setattr(canvas_integrations, "proxy_request", _proxy)
    monkeypatch.setattr(canvas_integrations, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    await canvas_integrations.create_canvas_platform(_build_request())
    await canvas_integrations.create_canvas_program_binding("platform-1", _build_request())
    await canvas_integrations.list_canvas_program_bindings(_build_request())

    assert [call["path"] for call in captured] == [
        "/v1/integrations/canvas/platforms",
        "/v1/integrations/canvas/platforms/platform-1/program-bindings",
        "/v1/integrations/canvas/program-bindings",
    ]
    assert all(call["inject_headers"] == {"X-API-Key": "secret"} for call in captured)


@pytest.mark.asyncio
async def test_canvas_lti_bootstrap_route_proxies_to_issuance_without_management_header(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _proxy(request, service_url, path, inject_headers=None):
        captured.update({
            "service_url": service_url,
            "path": path,
            "inject_headers": inject_headers,
        })
        return JSONResponse({"application_id": "app-1", "created": True})

    monkeypatch.setattr(canvas_integrations, "get_registry", lambda: _Registry())
    monkeypatch.setattr(canvas_integrations, "proxy_request", _proxy)
    monkeypatch.setattr(canvas_integrations, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    response = await canvas_integrations.bootstrap_canvas_lti_application("state-1", _build_request())
    body = json.loads(response.body)

    assert captured["service_url"] == "http://issuance-service"
    assert captured["path"] == "/v1/integrations/canvas/lti/experience-sessions/state-1/bootstrap"
    assert captured["inject_headers"] is None
    assert body["application_id"] == "app-1"


@pytest.mark.asyncio
async def test_canvas_lti_deep_linking_route_proxies_to_issuance_without_management_header(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _proxy(request, service_url, path, inject_headers=None):
        captured.update({
            "service_url": service_url,
            "path": path,
            "inject_headers": inject_headers,
        })
        return JSONResponse({"jwt": "signed.jwt", "deep_link_return_url": "https://canvas.example.edu/return"})

    monkeypatch.setattr(canvas_integrations, "get_registry", lambda: _Registry())
    monkeypatch.setattr(canvas_integrations, "proxy_request", _proxy)
    monkeypatch.setattr(canvas_integrations, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    response = await canvas_integrations.create_canvas_lti_deep_linking_response("state-1", _build_request())
    body = json.loads(response.body)

    assert captured["service_url"] == "http://issuance-service"
    assert captured["path"] == "/v1/integrations/canvas/lti/experience-sessions/state-1/deep-linking-response"
    assert captured["inject_headers"] is None
    assert body["jwt"] == "signed.jwt"


@pytest.mark.asyncio
async def test_canvas_mirror_provenance_route_proxies_without_management_header(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _proxy(request, service_url, path, inject_headers=None):
        captured.update({
            "service_url": service_url,
            "path": path,
            "inject_headers": inject_headers,
        })
        return JSONResponse({
            "delivery_record_id": "delivery-1",
            "trust_basis": {"canonical_issuance_backed": True},
        })

    monkeypatch.setattr(issuance, "get_registry", lambda: _Registry())
    monkeypatch.setattr(issuance, "proxy_request", _proxy)
    monkeypatch.setattr(issuance, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    response = await issuance.get_canvas_mirror_provenance(_build_request())
    body = json.loads(response.body)

    assert captured["service_url"] == "http://issuance-service"
    assert captured["path"] == "/v1/issuance/delivery-records/canvas-credentials/provenance"
    assert captured["inject_headers"] is None
    assert body["trust_basis"]["canonical_issuance_backed"] is True


def test_canvas_mirror_provenance_route_is_public_for_employer_demo():
    route_config = get_route_config("/v1/issuance/delivery-records/canvas-credentials/provenance")

    assert route_config is not None
    assert route_config["service"] == "issuance"
    assert route_config["requires_auth"] is False


@pytest.mark.asyncio
async def test_canvas_mirror_automation_cycle_route_proxies_with_management_header(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _proxy(request, service_url, path, inject_headers=None):
        captured.update({
            "service_url": service_url,
            "path": path,
            "inject_headers": inject_headers,
        })
        return JSONResponse({
            "processed_count": 2,
            "publish": {"processed_count": 1},
            "status_sync": {"processed_count": 1},
        })

    monkeypatch.setattr(issuance, "get_registry", lambda: _Registry())
    monkeypatch.setattr(issuance, "proxy_request", _proxy)
    monkeypatch.setattr(issuance, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    response = await issuance.run_canvas_mirror_automation_cycle(_build_request())
    body = json.loads(response.body)

    assert captured["service_url"] == "http://issuance-service"
    assert captured["path"] == "/v1/issuance/delivery-records/canvas-credentials/run-automation-cycle"
    assert captured["inject_headers"] == {"X-API-Key": "secret"}
    assert body["processed_count"] == 2


@pytest.mark.asyncio
async def test_canvas_mirror_retry_routes_proxy_with_management_header(monkeypatch: pytest.MonkeyPatch):
    captured: list[dict] = []

    async def _proxy(request, service_url, path, inject_headers=None):
        captured.append({
            "service_url": service_url,
            "path": path,
            "inject_headers": inject_headers,
        })
        return JSONResponse({"processed_count": 1})

    monkeypatch.setattr(issuance, "get_registry", lambda: _Registry())
    monkeypatch.setattr(issuance, "proxy_request", _proxy)
    monkeypatch.setattr(issuance, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    await issuance.process_pending_canvas_mirror_deliveries(_build_request())
    await issuance.process_canvas_mirror_status_sync_failures(_build_request())

    assert [call["path"] for call in captured] == [
        "/v1/issuance/delivery-records/canvas-credentials/process-pending",
        "/v1/issuance/delivery-records/canvas-credentials/process-status-sync-failures",
    ]
    assert all(call["service_url"] == "http://issuance-service" for call in captured)
    assert all(call["inject_headers"] == {"X-API-Key": "secret"} for call in captured)


@pytest.mark.asyncio
async def test_canvas_mirror_health_route_proxies_with_management_header(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _proxy(request, service_url, path, inject_headers=None):
        captured.update({
            "service_url": service_url,
            "path": path,
            "inject_headers": inject_headers,
        })
        return JSONResponse({"organization_id": "org-1", "pending_publish_count": 1})

    monkeypatch.setattr(issuance, "get_registry", lambda: _Registry())
    monkeypatch.setattr(issuance, "proxy_request", _proxy)
    monkeypatch.setattr(issuance, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    response = await issuance.get_canvas_mirror_health("org-1", _build_request())
    body = json.loads(response.body)

    assert captured["service_url"] == "http://issuance-service"
    assert captured["path"] == "/v1/issuance/organizations/org-1/canvas-mirror-health"
    assert captured["inject_headers"] == {"X-API-Key": "secret"}
    assert body["pending_publish_count"] == 1


@pytest.mark.asyncio
async def test_applicant_evidence_summary_route_reads_from_issuance(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _proxy(request, service_url, path, inject_headers=None):
        captured.update({
            "service_url": service_url,
            "path": path,
            "inject_headers": inject_headers,
        })
        return JSONResponse({
            "application_id": "app-1",
            "evidence_facts": [{"id": "fact-1", "fact_type": "canvas.module_completion"}],
            "policy_decision": {"allowed": True},
        })

    monkeypatch.setattr(applicants, "get_registry", lambda: _Registry())
    monkeypatch.setattr(applicants, "proxy_request", _proxy)
    monkeypatch.setattr(applicants, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    response = await applicants.get_applicant_application_evidence_summary("app-1", _build_request())
    body = json.loads(response.body)

    assert captured["path"] == "/v1/applications/app-1/evidence-summary"
    assert captured["inject_headers"] == {"X-API-Key": "secret"}
    assert body["evidence_facts"][0]["fact_type"] == "canvas.module_completion"


@pytest.mark.asyncio
async def test_applicant_external_evidence_api_check_route_reads_from_issuance(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _proxy(request, service_url, path, inject_headers=None):
        captured.update({
            "service_url": service_url,
            "path": path,
            "inject_headers": inject_headers,
        })
        return JSONResponse({
            "application_id": "app-1",
            "check_id": "passport-document-check",
            "evidence_fact": {"id": "fact-1", "fact_type": "passport.document_verified"},
            "policy_decision": {"allowed": True},
        })

    monkeypatch.setattr(applicants, "get_registry", lambda: _Registry())
    monkeypatch.setattr(applicants, "proxy_request", _proxy)
    monkeypatch.setattr(applicants, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    response = await applicants.run_applicant_application_evidence_api_check(
        "app-1",
        "passport-document-check",
        _build_request(),
    )
    body = json.loads(response.body)

    assert captured["path"] == "/v1/applications/app-1/evidence/api-checks/passport-document-check/run"
    assert captured["inject_headers"] == {"X-API-Key": "secret"}
    assert body["evidence_fact"]["fact_type"] == "passport.document_verified"


@pytest.mark.asyncio
async def test_applicant_supersede_route_reads_from_applicant_service(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _proxy(request, service_url, path, inject_headers=None):
        captured.update({
            "service_url": service_url,
            "path": path,
            "inject_headers": inject_headers,
        })
        return JSONResponse({"id": "app-1", "status": "WITHDRAWN"})

    monkeypatch.setattr(
        applicants,
        "get_registry",
        lambda: _NamedRegistry({"applicant": "http://applicant-service"}),
    )
    monkeypatch.setattr(applicants, "proxy_request", _proxy)

    response = await applicants.supersede_applicant_application("app-1", _build_request())
    body = json.loads(response.body)

    assert captured["service_url"] == "http://applicant-service"
    assert captured["path"] == "/v1/applicants/applications/app-1/supersede"
    assert captured["inject_headers"] is None
    assert body["status"] == "WITHDRAWN"


@pytest.mark.asyncio
async def test_resolve_issuer_did_returns_active_profile_did(monkeypatch: pytest.MonkeyPatch):
    """_resolve_issuer_did should return the DID from the first active profile."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    profiles_doc = json.dumps({
        "profiles": [
            {
                "id": "ip-1",
                "name": "Draft Profile",
                "issuer_did": "did:web:draft",
                "signing_service_id": "svc-1",
                "status": "draft",
            },
            {
                "id": "ip-2",
                "name": "Active Profile",
                "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
                "signing_service_id": "svc-2",
                "status": "active",
            },
        ]
    })

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=profiles_doc)

    request = _build_request(redis_client=redis_mock, session_org_id="org_acme")
    result = await issuance._resolve_issuer_did(request, "org_acme")

    assert result == "did:web:beta.elevenidllc.com:orgs:acme"

    identity = await issuance._resolve_issuer_identity(request, "org_acme")
    assert identity == {
        "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
        "signing_service_id": "svc-2",
        "signing_key_reference": "",
        "verification_method_id": "",
        "key_purpose": "vc_jwt_issuer",
        "algorithm": "",
    }


@pytest.mark.asyncio
async def test_resolve_issuer_identity_prefers_format_scoped_profile(monkeypatch: pytest.MonkeyPatch):
    """_resolve_issuer_identity should not inject a VC profile for mDoc issuance."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    profiles_doc = json.dumps({
        "profiles": [
            {
                "id": "ip-vc",
                "name": "VC Profile",
                "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
                "signing_service_id": "svc-vc",
                "signing_key_reference": "cred-issuer-acme-es256",
                "verification_method_id": "did:web:beta.elevenidllc.com:orgs:acme#cred-issuer-acme-es256",
                "key_purpose": "vc_jwt_issuer",
                "status": "active",
            },
            {
                "id": "ip-mdoc",
                "name": "mDoc Profile",
                "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
                "signing_service_id": "svc-mdoc",
                "signing_key_reference": "cred-dsc-acme-primary",
                "verification_method_id": "did:web:beta.elevenidllc.com:orgs:acme#cred-dsc-acme-primary",
                "key_purpose": "mdoc_dsc",
                "status": "active",
            },
        ]
    })

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=profiles_doc)

    request = _build_request(redis_client=redis_mock, session_org_id="org_acme")
    identity = await issuance._resolve_issuer_identity(
        request,
        "org_acme",
        credential_format="mso_mdoc",
    )

    assert identity["signing_service_id"] == "svc-mdoc"
    assert identity["signing_key_reference"] == "cred-dsc-acme-primary"
    assert identity["verification_method_id"] == "did:web:beta.elevenidllc.com:orgs:acme#cred-dsc-acme-primary"
    assert identity["key_purpose"] == "mdoc_dsc"


@pytest.mark.asyncio
async def test_resolve_issuer_did_returns_none_when_no_active(monkeypatch: pytest.MonkeyPatch):
    """_resolve_issuer_did should return None when no active profile exists."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    profiles_doc = json.dumps({
        "profiles": [
            {"id": "ip-1", "issuer_did": "did:web:x", "status": "draft"},
        ]
    })

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=profiles_doc)

    request = _build_request(redis_client=redis_mock, session_org_id="org_x")
    result = await issuance._resolve_issuer_did(request, "org_x")

    assert result is None


@pytest.mark.asyncio
async def test_resolve_issuer_did_returns_none_when_no_profiles(monkeypatch: pytest.MonkeyPatch):
    """_resolve_issuer_did should return None when no profiles exist at all."""
    monkeypatch.setenv("PUBLIC_DOMAIN", "beta.elevenidllc.com")
    monkeypatch.setenv("ISSUER_BASE_URL", "https://beta.elevenidllc.com")

    redis_mock = AsyncMock()
    redis_mock.get = AsyncMock(return_value=None)

    request = _build_request(redis_client=redis_mock, session_org_id="org_empty")
    result = await issuance._resolve_issuer_did(request, "org_empty")

    assert result is None
