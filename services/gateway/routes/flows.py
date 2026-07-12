"""Flow definition, flow instance, verification flow, and SIOPv2 routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, Response

from gateway.models import (
    FlowDefinitionCreate,
    FlowDefinitionResponse,
    FlowInstanceCreate,
    FlowInstanceResponse,
    StartVerificationFlowRequest,
    VerificationRequestResponse,
    VerificationResultResponse,
)
from gateway.proxy import _resource_exists, get_registry, proxy_request
from gateway.routes.issuance import _ISSUANCE_HEADERS

flow_router = APIRouter(prefix="/v1/flows", tags=["Flows"])


async def _validate_flow_definition_refs(body: FlowDefinitionCreate, request: Request) -> None:
    """Validate that FK references in a FlowDefinitionCreate exist."""
    if body.credential_template_id:
        if not await _resource_exists("credential-templates", f"/v1/credential-templates/{body.credential_template_id}", request):
            raise HTTPException(status_code=404, detail=f"Credential template not found: {body.credential_template_id}")
    if body.application_template_id:
        if not await _resource_exists(
            "issuance",
            f"/v1/application-templates/{body.application_template_id}",
            request,
            inject_headers=_ISSUANCE_HEADERS,
        ):
            raise HTTPException(status_code=404, detail=f"Application template not found: {body.application_template_id}")
    if body.presentation_policy_id:
        if not await _resource_exists("presentation-policies", f"/v1/presentation-policies/{body.presentation_policy_id}", request):
            raise HTTPException(status_code=422, detail=f"Presentation policy not found: {body.presentation_policy_id}")
    if body.delivery_destination_profile_id:
        if not await _resource_exists("credential-templates", f"/v1/delivery-destinations/{body.delivery_destination_profile_id}", request):
            raise HTTPException(status_code=422, detail=f"Delivery destination not found: {body.delivery_destination_profile_id}")
    if body.trust_profile_id:
        if not await _resource_exists("trust-profiles", f"/v1/trust-profiles/{body.trust_profile_id}", request):
            raise HTTPException(status_code=422, detail=f"Trust profile not found: {body.trust_profile_id}")


# ── Flow Definitions ─────────────────────────────────────────────────

@flow_router.get("/capabilities", summary="Get Flow Capabilities")
async def get_flow_capabilities(request: Request) -> Response:
    """Return fixed sequences, extension points, and runtime blockers."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/capabilities")


@flow_router.post("/definitions", response_model=FlowDefinitionResponse, summary="Create Flow Definition")
async def create_flow_definition(body: FlowDefinitionCreate, request: Request) -> Response:
    """Create a new Flow Definition for orchestrating credential operations."""
    await _validate_flow_definition_refs(body, request)
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/definitions")


@flow_router.get("/definitions", response_model=list[FlowDefinitionResponse], summary="List Flow Definitions")
async def list_flow_definitions(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Flow Definitions for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/definitions")


@flow_router.get("/definitions/{flow_id}", response_model=FlowDefinitionResponse, summary="Get Flow Definition")
async def get_flow_definition(flow_id: str, request: Request) -> Response:
    """Get a Flow Definition by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/definitions/{flow_id}")


@flow_router.post("/definitions/{flow_id}/activate", response_model=FlowDefinitionResponse, summary="Activate Flow")
async def activate_flow_definition(flow_id: str, request: Request) -> Response:
    """Activate a Flow Definition."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/definitions/{flow_id}/activate")


@flow_router.post("/definitions/{flow_id}/validate", summary="Validate Flow")
async def validate_flow_definition(flow_id: str, request: Request) -> Response:
    """Return dependency and capability blockers for a draft flow."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/definitions/{flow_id}/validate")


@flow_router.post("/definitions/{flow_id}/test", summary="Test Flow")
async def test_flow_definition(flow_id: str, request: Request) -> Response:
    """Resolve a dry-run execution plan without external side effects."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/definitions/{flow_id}/test")


@flow_router.put("/definitions/{flow_id}", response_model=FlowDefinitionResponse, summary="Update Flow Definition")
async def update_flow_definition(flow_id: str, body: FlowDefinitionCreate, request: Request) -> Response:
    """Update a Flow Definition."""
    await _validate_flow_definition_refs(body, request)
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/definitions/{flow_id}")


@flow_router.delete("/definitions/{flow_id}", summary="Delete Flow Definition")
async def delete_flow_definition(flow_id: str, request: Request) -> Response:
    """Delete a Flow Definition."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/definitions/{flow_id}")


# ── Flow Instances ───────────────────────────────────────────────────

@flow_router.post("/instances", response_model=FlowInstanceResponse, summary="Start Flow Instance")
async def start_flow_instance(body: FlowInstanceCreate, request: Request) -> Response:
    """Start a new Flow Instance."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/instances")


@flow_router.get("/instances", response_model=list[FlowInstanceResponse], summary="List Flow Instances")
async def list_flow_instances(
    organization_id: str = Query(..., description="Organization ID"),
    flow_definition_id: str | None = Query(None, description="Filter by flow definition"),
    status: str | None = Query(None, description="Filter by status"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    request: Request = None,
) -> Response:
    """List Flow Instances for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/instances")


@flow_router.get("/instances/{instance_id}", response_model=FlowInstanceResponse, summary="Get Flow Instance")
async def get_flow_instance(instance_id: str, request: Request) -> Response:
    """Get a Flow Instance by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/instances/{instance_id}")


@flow_router.post("/instances/{instance_id}/advance", response_model=FlowInstanceResponse, summary="Advance Flow")
async def advance_flow_instance(instance_id: str, request: Request) -> Response:
    """Advance a Flow Instance to the next step."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/instances/{instance_id}/advance")


# ── Verification Flows ───────────────────────────────────────────────

@flow_router.post("/verify", response_model=VerificationRequestResponse, summary="Start Verification Flow")
async def start_verification_flow(body: StartVerificationFlowRequest, request: Request) -> Response:
    """
    Start a verification flow for async wallet interactions.

    Creates a flow instance with a QR code / request_uri for wallet scanning.
    For stateless verification, use POST /v1/presentation-policies/{id}/evaluate instead.
    """
    if body.presentation_policy_id:
        if not await _resource_exists("presentation-policies", f"/v1/presentation-policies/{body.presentation_policy_id}", request):
            raise HTTPException(status_code=422, detail=f"Presentation policy not found: {body.presentation_policy_id}")
    if body.trust_profile_id:
        if not await _resource_exists("trust-profiles", f"/v1/trust-profiles/{body.trust_profile_id}", request):
            raise HTTPException(status_code=422, detail=f"Trust profile not found: {body.trust_profile_id}")
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/verify")


@flow_router.get("/instances/{instance_id}/request", summary="Get Verification Request Object")
async def get_flow_verification_request(instance_id: str, request: Request) -> Response:
    """Get the OID4VP request object (for wallet to fetch via request_uri)."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/instances/{instance_id}/request")


@flow_router.get("/instances/{instance_id}/result", summary="Get Verification Result")
async def get_flow_instance_result(instance_id: str, request: Request) -> Response:
    """OID4VP-1FINAL §8.7 — Relying-party result polling endpoint for a flow instance."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/instances/{instance_id}/result")


@flow_router.post("/instances/{instance_id}/submit", response_model=VerificationResultResponse, summary="Submit Verification")
async def submit_flow_verification(instance_id: str, request: Request) -> Response:
    """Submit a VP token to complete a verification flow. Accepts JSON or form-encoded data."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/instances/{instance_id}/submit")


# ── SIOPv2 ───────────────────────────────────────────────────────────

@flow_router.post("/siop", summary="Start SIOPv2 Cross-Device Flow")
async def start_siop_flow_gateway(request: Request) -> Response:
    """SIOPv2 Draft 13 §9: Initiate a cross-device SIOPv2 authentication flow."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/siop")


@flow_router.post("/siop/submit", summary="Submit SIOPv2 ID Token")
async def submit_siop_id_token_gateway(request: Request) -> Response:
    """SIOPv2 Draft 13 §11: Validate a self-issued ID token from the wallet (wallet-facing, no auth)."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/siop/submit")
