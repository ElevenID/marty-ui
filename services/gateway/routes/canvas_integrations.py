"""Canvas integration proxy routes."""

from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Request, Response

from gateway.proxy import get_registry, proxy_request


canvas_integration_router = APIRouter(prefix="/v1/integrations/canvas", tags=["Canvas Integrations"])


def _read_secret_value(name: str) -> str:
    direct = os.environ.get(name)
    if direct:
        return direct
    file_path = os.environ.get(f"{name}_FILE")
    if not file_path:
        return ""
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


_ISSUANCE_API_KEY = _read_secret_value("ISSUANCE_API_KEY")
_ISSUANCE_HEADERS: dict[str, str] | None = (
    {"X-API-Key": _ISSUANCE_API_KEY} if _ISSUANCE_API_KEY else None
)


@canvas_integration_router.get("/lti/jwks", summary="Get Marty public Canvas LTI keys")
async def get_canvas_lti_tool_jwks(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/lti/jwks")


@canvas_integration_router.get("/lti/config/{registration_token}", summary="Get revocable Canvas registration config")
async def get_public_canvas_lti_registration_config(registration_token: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/lti/config/{registration_token}",
    )


@canvas_integration_router.post("/platforms", summary="Create Canvas platform")
async def create_canvas_platform(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/platforms", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.get("/platforms", summary="List Canvas platforms")
async def list_canvas_platforms(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/platforms", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.get("/platforms/{platform_id}", summary="Get Canvas platform")
async def get_canvas_platform(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/platforms/{platform_id}", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.get(
    "/platforms/{platform_id}/registration-config",
    summary="Get portable Canvas LTI registration configuration",
)
async def get_canvas_lti_registration_config(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/platforms/{platform_id}/registration-config",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.get("/platforms/{platform_id}/readiness", summary="Check portable Canvas readiness")
async def get_canvas_platform_readiness(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/platforms/{platform_id}/readiness",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.put("/platforms/{platform_id}/lti-installation", summary="Configure Canvas LTI installation")
async def configure_canvas_lti_installation(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/platforms/{platform_id}/lti-installation",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post("/platforms/{platform_id}/oauth/start", summary="Start Canvas API OAuth connection")
async def start_canvas_oauth_connection(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/platforms/{platform_id}/oauth/start",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post(
    "/platforms/{platform_id}/oauth/authorizations",
    summary="Start capability-derived Canvas API OAuth authorization",
)
async def create_canvas_oauth_authorization(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/platforms/{platform_id}/oauth/authorizations",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.get("/oauth/callback", summary="Complete Canvas API OAuth connection")
async def complete_canvas_oauth_connection(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/oauth/callback")


@canvas_integration_router.delete("/platforms/{platform_id}/oauth", summary="Disconnect Canvas API OAuth connection")
async def disconnect_canvas_oauth_connection(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/platforms/{platform_id}/oauth",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.put("/platforms/{platform_id}", summary="Update Canvas platform")
async def update_canvas_platform(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/platforms/{platform_id}", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.delete("/platforms/{platform_id}", summary="Delete Canvas platform")
async def delete_canvas_platform(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/platforms/{platform_id}", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.post("/platforms/{platform_id}/sandbox-probe", summary="Probe Canvas platform metadata")
async def probe_canvas_platform_sandbox(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/platforms/{platform_id}/sandbox-probe",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post("/platforms/{platform_id}/jwks-refresh", summary="Refresh Canvas platform JWKS metadata")
async def refresh_canvas_platform_jwks(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/platforms/{platform_id}/jwks-refresh",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post("/platforms/{platform_id}/scope-discovery", summary="Discover Canvas courses and activities")
async def discover_canvas_scope(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/platforms/{platform_id}/scope-discovery",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.get(
    "/platforms/{platform_id}/catalog",
    summary="Discover Canvas courses and activities through connected OAuth",
)
async def get_canvas_catalog(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/platforms/{platform_id}/catalog",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post("/platforms/{platform_id}/program-bindings", summary="Create Canvas program binding")
async def create_canvas_program_binding(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/platforms/{platform_id}/program-bindings",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.get("/program-bindings", summary="List Canvas program bindings")
async def list_canvas_program_bindings(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/program-bindings", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.get("/program-bindings/{binding_id}", summary="Get Canvas program binding")
async def get_canvas_program_binding(binding_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/program-bindings/{binding_id}", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.put("/program-bindings/{binding_id}", summary="Update Canvas program binding")
async def update_canvas_program_binding(binding_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/program-bindings/{binding_id}", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.delete("/program-bindings/{binding_id}", summary="Delete Canvas program binding")
async def delete_canvas_program_binding(binding_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/program-bindings/{binding_id}", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.post("/program-bindings/{binding_id}/validate", summary="Validate Canvas binding readiness")
async def validate_canvas_program_binding(binding_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/program-bindings/{binding_id}/validate",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post("/program-bindings/{binding_id}/activate", summary="Activate ready Canvas binding")
async def activate_canvas_program_binding(binding_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/program-bindings/{binding_id}/activate",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post("/program-bindings/{binding_id}/deactivate", summary="Deactivate Canvas binding")
async def deactivate_canvas_program_binding(binding_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/program-bindings/{binding_id}/deactivate",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post("/canvas-credentials/validate", summary="Validate Canvas Credentials provider configuration")
async def validate_canvas_credentials_provider(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/integrations/canvas/canvas-credentials/validate",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post("/integration-secrets", summary="Create Canvas integration secret")
async def create_canvas_integration_secret(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/integrations/canvas/integration-secrets",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.get("/integration-secrets", summary="List Canvas integration secrets")
async def list_canvas_integration_secrets(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/integrations/canvas/integration-secrets",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.put("/integration-secrets/{secret_id}", summary="Update Canvas integration secret")
async def update_canvas_integration_secret(secret_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/integration-secrets/{secret_id}",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.delete("/integration-secrets/{secret_id}", summary="Delete Canvas integration secret")
async def delete_canvas_integration_secret(secret_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/integration-secrets/{secret_id}",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post("/evidence-events", summary="Process Canvas evidence event")
async def process_canvas_evidence_event(request: Request) -> Response:
    """Proxy signed Canvas evidence events to the issuance service."""

    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/evidence-events")


@canvas_integration_router.post("/ags/score-events", summary="Process Canvas AGS score as MIP evidence")
async def process_canvas_ags_score_event(request: Request) -> Response:
    """Proxy signed Canvas AGS score events to the issuance service."""

    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/ags/score-events")


@canvas_integration_router.post("/nrps/membership-events", summary="Process Canvas NRPS membership as MIP evidence")
async def process_canvas_nrps_membership_event(request: Request) -> Response:
    """Proxy signed Canvas NRPS membership events to the issuance service."""

    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/nrps/membership-events")


@canvas_integration_router.get(
    "/evidence-events/{canvas_account_id}/{provider_event_id}",
    summary="Get Canvas evidence event status",
)
async def get_canvas_evidence_event_status(canvas_account_id: str, provider_event_id: str, request: Request) -> Response:
    """Proxy Canvas evidence event receipt/status reads to issuance."""

    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/evidence-events/{canvas_account_id}/{provider_event_id}",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post("/applications/{application_id}/canvas-sync", summary="Enqueue Canvas evidence sync")
async def enqueue_canvas_application_sync(application_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/applications/{application_id}/canvas-sync",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post(
    "/applications/{application_id}/approve",
    summary="Approve a Canvas application for wallet claim",
)
async def approve_canvas_application(application_id: str, request: Request) -> Response:
    """Proxy the deliberately Canvas-only approval contract to issuance."""

    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/applications/{application_id}/approve",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.get("/canvas-sync-jobs", summary="List Canvas evidence sync jobs")
async def list_canvas_sync_jobs(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/canvas-sync-jobs", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.get("/canvas-sync-jobs/{job_id}", summary="Get Canvas evidence sync job")
async def get_canvas_sync_job(job_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/canvas-sync-jobs/{job_id}", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.post("/canvas-sync-jobs/{job_id}/retry", summary="Retry Canvas evidence sync job")
async def retry_canvas_sync_job(job_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/canvas-sync-jobs/{job_id}/retry", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.post(
    "/canvas-sync-jobs/{job_id}/resolve",
    summary="Acknowledge Canvas evidence sync dead letter",
)
async def resolve_canvas_sync_job(job_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/canvas-sync-jobs/{job_id}/resolve",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.get("/canvas-award-candidates", summary="List Canvas award candidates")
async def list_canvas_award_candidates(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/canvas-award-candidates", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.get("/evidence-policy-reviews", summary="List Canvas evidence correction reviews")
async def list_canvas_evidence_policy_reviews(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/evidence-policy-reviews", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.post(
    "/evidence-policy-reviews/{review_id}/resolve",
    summary="Resolve Canvas evidence correction review",
)
async def resolve_canvas_evidence_policy_review(review_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/evidence-policy-reviews/{review_id}/resolve",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post("/lti/platforms/{platform_id}/login", summary="Initiate Canvas LTI login")
async def initiate_canvas_lti_login(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/lti/platforms/{platform_id}/login")


@canvas_integration_router.post("/lti/platforms/{platform_id}/experience-login", summary="Initiate Canvas LTI experience login")
async def initiate_canvas_lti_experience_login(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/lti/platforms/{platform_id}/experience-login")


@canvas_integration_router.post("/lti/platforms/{platform_id}/launch", summary="Verify Canvas LTI launch")
async def verify_canvas_lti_launch(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/lti/platforms/{platform_id}/launch")


@canvas_integration_router.post("/lti/platforms/{platform_id}/experience", summary="Launch ElevenID from Canvas LTI")
async def launch_canvas_lti_experience(platform_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/lti/platforms/{platform_id}/experience")


@canvas_integration_router.post("/lti/experience-sessions/exchange", summary="Exchange one-time Canvas experience code")
async def exchange_canvas_lti_experience_code(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/lti/experience-sessions/exchange")


@canvas_integration_router.get("/lti/experience-sessions/current", summary="Get current Canvas LTI experience")
async def get_current_canvas_lti_experience(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/lti/experience-sessions/current")


@canvas_integration_router.post("/lti/experience-sessions/current/bootstrap", summary="Bootstrap current Canvas application")
async def bootstrap_current_canvas_lti_application(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/lti/experience-sessions/current/bootstrap")


@canvas_integration_router.post("/lti/experience-sessions/current/evidence-sync", summary="Enqueue current Canvas evidence sync")
async def sync_current_canvas_lti_evidence(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/lti/experience-sessions/current/evidence-sync")


@canvas_integration_router.get(
    "/lti/experience-sessions/current/evidence-status",
    summary="Get current Canvas evidence status",
)
async def get_current_canvas_lti_evidence_status(request: Request) -> Response:
    """Forward only the browser's short-lived Canvas experience bearer."""

    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        "/v1/integrations/canvas/lti/experience-sessions/current/evidence-status",
    )


@canvas_integration_router.post(
    "/lti/experience-sessions/current/deep-linking-response",
    summary="Create current Canvas Deep Linking response",
)
async def create_current_canvas_lti_deep_linking_response(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/lti/experience-sessions/current/deep-linking-response")


@canvas_integration_router.get("/lti/experience-sessions/{state}", summary="Get Canvas LTI experience session")
async def get_canvas_lti_experience_session(state: str, request: Request) -> Response:
    del state, request
    raise HTTPException(status_code=410, detail="State-addressed Canvas sessions are no longer supported")


@canvas_integration_router.post(
    "/lti/experience-sessions/{state}/bootstrap",
    summary="Bootstrap Canvas LTI application",
)
async def bootstrap_canvas_lti_application(state: str, request: Request) -> Response:
    del state, request
    raise HTTPException(status_code=410, detail="State-addressed Canvas sessions are no longer supported")


@canvas_integration_router.post(
    "/lti/experience-sessions/{state}/evidence-sync",
    summary="Synchronize portable Canvas LTI evidence",
)
async def sync_canvas_lti_evidence(state: str, request: Request) -> Response:
    del state, request
    raise HTTPException(status_code=410, detail="State-addressed Canvas sessions are no longer supported")


@canvas_integration_router.post(
    "/lti/experience-sessions/{state}/deep-linking-response",
    summary="Create Canvas LTI Deep Linking response",
)
async def create_canvas_lti_deep_linking_response(state: str, request: Request) -> Response:
    del state, request
    raise HTTPException(status_code=410, detail="State-addressed Canvas sessions are no longer supported")
