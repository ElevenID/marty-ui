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
from gateway.routes import signing_keys
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
async def test_create_issuance_rejects_missing_issuer_profile_id():
    request = _build_request(session_org_id="org_123")

    with pytest.raises(issuance.HTTPException) as exc_info:
        await issuance.create_issuance(
            issuance.IssuanceCreate(
                organization_id="org_123",
                claims={"credential_format": "sd_jwt_vc"},
            ),
            request,
        )

    assert exc_info.value.status_code == 422
    assert "issuer_profile_id is required" in exc_info.value.detail


@pytest.mark.asyncio
async def test_create_issuance_rejects_claims_only_issuer_profile_id():
    request = _build_request(session_org_id="org_123")

    with pytest.raises(issuance.HTTPException) as exc_info:
        await issuance.create_issuance(
            issuance.IssuanceCreate(
                organization_id="org_123",
                claims={
                    "credential_format": "sd_jwt_vc",
                    "issuer_profile_id": "ip-claims",
                },
            ),
            request,
        )

    assert exc_info.value.status_code == 422
    assert "issuer_profile_id is required for direct issuance" in exc_info.value.detail


@pytest.mark.asyncio
async def test_create_issuance_forwards_explicit_issuer_profile_context(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def fake_resolve_identity(
        request,
        organization_id,
        issuer_profile_id,
        credential_format=None,
        key_purpose=None,
        algorithm=None,
    ):
        captured["resolver"] = {
            "organization_id": organization_id,
            "issuer_profile_id": issuer_profile_id,
            "credential_format": credential_format,
        }
        return {
            "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
            "signing_service_id": "svc-bao",
            "signing_key_reference": "cred-issuer-acme-es256",
            "verification_method_id": "did:web:beta.elevenidllc.com:orgs:acme#cred-issuer-acme-es256",
            "key_purpose": "vc_jwt_issuer",
            "algorithm": "ES256",
        }

    async def _proxy(request, service_url, path, inject_headers=None):
        captured["service_url"] = service_url
        captured["path"] = path
        captured["inject_headers"] = inject_headers
        return JSONResponse({"id": "iss-1", "organization_id": "org_123", "status": "PENDING"})

    monkeypatch.setattr(issuance, "_resolve_issuer_identity", fake_resolve_identity)
    monkeypatch.setattr(issuance, "get_registry", lambda: _Registry())
    monkeypatch.setattr(issuance, "proxy_request", _proxy)
    monkeypatch.setattr(issuance, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    response = await issuance.create_issuance(
        issuance.IssuanceCreate(
            organization_id="org_123",
            issuer_profile_id="ip-1",
            claims={"credential_format": "sd_jwt_vc"},
        ),
        _build_request(session_org_id="org_123"),
    )

    assert response.status_code == 200
    assert captured["resolver"] == {
        "organization_id": "org_123",
        "issuer_profile_id": "ip-1",
        "credential_format": "sd_jwt_vc",
    }
    assert captured["service_url"] == "http://issuance-service"
    assert captured["path"] == "/v1/issuance/initiate"
    assert captured["inject_headers"] == {
        "X-API-Key": "secret",
        "X-Signing-Service-Id": "svc-bao",
        "X-Issuer-Did": "did:web:beta.elevenidllc.com:orgs:acme",
    }


@pytest.mark.asyncio
async def test_create_issuance_uses_template_bound_issuer_profile(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def fake_load_template(template_id, request):
        captured["template_id"] = template_id
        return {
            "id": template_id,
            "organization_id": "org_123",
            "issuer_profile_id": "ip-template",
            "credential_payload_format": "sd_jwt_vc",
        }

    async def fake_resolve_identity(
        request,
        organization_id,
        issuer_profile_id,
        credential_format=None,
        key_purpose=None,
        algorithm=None,
    ):
        captured["resolver"] = {
            "organization_id": organization_id,
            "issuer_profile_id": issuer_profile_id,
            "credential_format": credential_format,
        }
        return {
            "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
            "signing_service_id": "svc-bao",
        }

    async def _proxy(request, service_url, path, inject_headers=None):
        captured["inject_headers"] = inject_headers
        return JSONResponse({"id": "iss-1", "organization_id": "org_123", "status": "PENDING"})

    monkeypatch.setattr(issuance, "_load_credential_template", fake_load_template)
    monkeypatch.setattr(issuance, "_resolve_issuer_identity", fake_resolve_identity)
    monkeypatch.setattr(issuance, "get_registry", lambda: _Registry())
    monkeypatch.setattr(issuance, "proxy_request", _proxy)
    monkeypatch.setattr(issuance, "_ISSUANCE_HEADERS", {"X-API-Key": "secret"})

    response = await issuance.create_issuance(
        issuance.IssuanceCreate(
            organization_id="org_123",
            credential_template_id="template-1",
            claims={"credential_format": "vc_jwt"},
        ),
        _build_request(session_org_id="org_123"),
    )

    assert response.status_code == 200
    assert captured["template_id"] == "template-1"
    assert captured["resolver"] == {
        "organization_id": "org_123",
        "issuer_profile_id": "ip-template",
        "credential_format": "sd_jwt_vc",
    }
    assert captured["inject_headers"]["X-Signing-Service-Id"] == "svc-bao"


@pytest.mark.asyncio
async def test_create_issuance_rejects_body_issuer_profile_override_for_template(monkeypatch: pytest.MonkeyPatch):
    async def fake_load_template(template_id, request):
        return {
            "id": template_id,
            "organization_id": "org_123",
            "issuer_profile_id": "ip-template",
        }

    monkeypatch.setattr(issuance, "_load_credential_template", fake_load_template)

    with pytest.raises(issuance.HTTPException) as exc_info:
        await issuance.create_issuance(
            issuance.IssuanceCreate(
                organization_id="org_123",
                credential_template_id="template-1",
                issuer_profile_id="ip-other",
            ),
            _build_request(session_org_id="org_123"),
        )

    assert exc_info.value.status_code == 422
    assert "cannot override the credential template issuer profile" in exc_info.value.detail


@pytest.mark.asyncio
async def test_create_issuance_rejects_claims_issuer_profile_override_for_template(monkeypatch: pytest.MonkeyPatch):
    async def fake_load_template(template_id, request):
        return {
            "id": template_id,
            "organization_id": "org_123",
            "issuer_profile_id": "ip-template",
        }

    monkeypatch.setattr(issuance, "_load_credential_template", fake_load_template)

    with pytest.raises(issuance.HTTPException) as exc_info:
        await issuance.create_issuance(
            issuance.IssuanceCreate(
                organization_id="org_123",
                credential_template_id="template-1",
                claims={"issuer_profile_id": "ip-other"},
            ),
            _build_request(session_org_id="org_123"),
        )

    assert exc_info.value.status_code == 422
    assert "claims.issuer_profile_id cannot override" in exc_info.value.detail


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
async def test_resolve_issuer_identity_requires_explicit_active_profile(monkeypatch: pytest.MonkeyPatch):
    """_resolve_issuer_identity should only return the explicitly selected active profile."""
    from fastapi import HTTPException as FastAPIHTTPException

    async def fake_resolve_issuer_context(**kwargs):
        assert kwargs["organization_id"] == "org_acme"
        assert kwargs["x_api_key"] == "secret"
        if kwargs["issuer_profile_id"] == "ip-1":
            raise FastAPIHTTPException(status_code=404, detail="not active")
        return JSONResponse({
            "ok": True,
            "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
            "signing_service_id": "svc-2",
            "signing_key_reference": "",
            "verification_method_id": "",
            "key_purpose": "vc_jwt_issuer",
            "service": {},
        })

    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "secret")
    monkeypatch.setattr(signing_keys, "internal_resolve_issuer_context", fake_resolve_issuer_context)

    request = _build_request(session_org_id="org_acme")
    assert await issuance._resolve_issuer_identity(request, "org_acme", None) is None
    assert await issuance._resolve_issuer_identity(request, "org_acme", "ip-1") is None

    identity = await issuance._resolve_issuer_identity(request, "org_acme", "ip-2")
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
    async def fake_resolve_issuer_context(**kwargs):
        assert kwargs["issuer_profile_id"] == "ip-mdoc"
        assert kwargs["credential_format"] == "mso_mdoc"
        assert kwargs["key_purpose"] == "mdoc_dsc"
        return JSONResponse({
            "ok": True,
            "issuer_did": "did:web:beta.elevenidllc.com:orgs:acme",
            "signing_service_id": "svc-mdoc",
            "signing_key_reference": "cred-dsc-acme-primary",
            "verification_method_id": "did:web:beta.elevenidllc.com:orgs:acme#cred-dsc-acme-primary",
            "key_purpose": "mdoc_dsc",
            "service": {"algorithm": "ES256"},
        })

    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "secret")
    monkeypatch.setattr(signing_keys, "internal_resolve_issuer_context", fake_resolve_issuer_context)

    request = _build_request(session_org_id="org_acme")
    identity = await issuance._resolve_issuer_identity(
        request,
        "org_acme",
        "ip-mdoc",
        credential_format="mso_mdoc",
    )

    assert identity["signing_service_id"] == "svc-mdoc"
    assert identity["signing_key_reference"] == "cred-dsc-acme-primary"
    assert identity["verification_method_id"] == "did:web:beta.elevenidllc.com:orgs:acme#cred-dsc-acme-primary"
    assert identity["key_purpose"] == "mdoc_dsc"


@pytest.mark.asyncio
async def test_resolve_issuer_identity_returns_none_when_no_active(monkeypatch: pytest.MonkeyPatch):
    """_resolve_issuer_identity should return None when the explicit profile is not active."""
    from fastapi import HTTPException as FastAPIHTTPException

    async def fake_resolve_issuer_context(**kwargs):
        raise FastAPIHTTPException(status_code=404, detail="not active")

    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "secret")
    monkeypatch.setattr(signing_keys, "internal_resolve_issuer_context", fake_resolve_issuer_context)

    request = _build_request(session_org_id="org_x")
    result = await issuance._resolve_issuer_identity(request, "org_x", "ip-1")

    assert result is None


@pytest.mark.asyncio
async def test_resolve_issuer_identity_returns_none_when_no_profiles(monkeypatch: pytest.MonkeyPatch):
    """_resolve_issuer_identity should return None when no profiles exist at all."""
    from fastapi import HTTPException as FastAPIHTTPException

    async def fake_resolve_issuer_context(**kwargs):
        raise FastAPIHTTPException(status_code=404, detail="no profiles")

    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "secret")
    monkeypatch.setattr(signing_keys, "internal_resolve_issuer_context", fake_resolve_issuer_context)

    request = _build_request(session_org_id="org_empty")
    result = await issuance._resolve_issuer_identity(request, "org_empty", "ip-1")

    assert result is None


@pytest.mark.asyncio
async def test_resolve_issuer_identity_preserves_signing_key_service_outage(monkeypatch: pytest.MonkeyPatch):
    """_resolve_issuer_identity should not hide resolver outages as an invalid profile."""
    from fastapi import HTTPException as FastAPIHTTPException

    async def fake_resolve_issuer_context(**kwargs):
        raise FastAPIHTTPException(status_code=503, detail="signing keys unavailable")

    monkeypatch.setenv("SIGNING_KEYS_INTERNAL_API_KEY", "secret")
    monkeypatch.setattr(signing_keys, "internal_resolve_issuer_context", fake_resolve_issuer_context)

    request = _build_request(session_org_id="org_x")
    with pytest.raises(FastAPIHTTPException) as exc_info:
        await issuance._resolve_issuer_identity(request, "org_x", "ip-1")

    assert exc_info.value.status_code == 503
