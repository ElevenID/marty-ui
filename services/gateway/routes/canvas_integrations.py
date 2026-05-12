"""Canvas integration proxy routes."""

from __future__ import annotations

import os

from fastapi import APIRouter, Request, Response

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


@canvas_integration_router.post("/connectors", summary="Create Canvas connector")
async def create_canvas_connector(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/connectors", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.get("/connectors", summary="List Canvas connectors")
async def list_canvas_connectors(request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/connectors", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.get("/connectors/{connector_id}", summary="Get Canvas connector")
async def get_canvas_connector(connector_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/connectors/{connector_id}", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.put("/connectors/{connector_id}", summary="Update Canvas connector")
async def update_canvas_connector(connector_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/connectors/{connector_id}", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.delete("/connectors/{connector_id}", summary="Delete Canvas connector")
async def delete_canvas_connector(connector_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/connectors/{connector_id}", inject_headers=_ISSUANCE_HEADERS)


@canvas_integration_router.post("/connectors/{connector_id}/sandbox-probe", summary="Probe Canvas sandbox metadata")
async def probe_canvas_connector_sandbox(connector_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/connectors/{connector_id}/sandbox-probe",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post("/connectors/{connector_id}/jwks-refresh", summary="Refresh Canvas JWKS metadata")
async def refresh_canvas_connector_jwks(connector_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/connectors/{connector_id}/jwks-refresh",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post("/connectors/{connector_id}/evidence-flow", summary="Plan Canvas evidence flow")
async def plan_canvas_evidence_flow(connector_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(
        request,
        service_url,
        f"/v1/integrations/canvas/connectors/{connector_id}/evidence-flow",
        inject_headers=_ISSUANCE_HEADERS,
    )


@canvas_integration_router.post("/evidence-events", summary="Process Canvas evidence event")
async def process_canvas_evidence_event(request: Request) -> Response:
    """Proxy signed Canvas evidence events to the issuance service."""

    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/evidence-events")


@canvas_integration_router.post("/credential-events", summary="Process Canvas credential event")
async def process_canvas_credential_event(request: Request) -> Response:
    """Proxy signed Canvas completion events to the issuance service."""

    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/integrations/canvas/credential-events")


@canvas_integration_router.post("/lti/login/{connector_id}", summary="Initiate Canvas LTI login")
async def initiate_canvas_lti_login(connector_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/lti/login/{connector_id}")


@canvas_integration_router.post("/lti/experience-login/{connector_id}", summary="Initiate Canvas LTI experience login")
async def initiate_canvas_lti_experience_login(connector_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/lti/experience-login/{connector_id}")


@canvas_integration_router.post("/lti/launch/{connector_id}", summary="Verify Canvas LTI launch")
async def verify_canvas_lti_launch(connector_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/lti/launch/{connector_id}")


@canvas_integration_router.post("/lti/experience/{connector_id}", summary="Launch ElevenID from Canvas LTI")
async def launch_canvas_lti_experience(connector_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/lti/experience/{connector_id}")


@canvas_integration_router.get("/lti/experience-sessions/{state}", summary="Get Canvas LTI experience session")
async def get_canvas_lti_experience_session(state: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/integrations/canvas/lti/experience-sessions/{state}")
