"""Flow definition, flow instance, verification flow, and SIOPv2 routes."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import ValidationError

from gateway.models import (
    FlowDefinitionCreate,
    FlowDefinitionResponse,
    FlowDefinitionUpdate,
    FlowInstanceCreate,
    FlowInstanceResponse,
    StartVerificationFlowRequest,
    VerificationRequestResponse,
    VerificationResultResponse,
)
from gateway.proxy import (
    _resource_exists,
    _resource_org_id,
    get_registry,
    proxy_request,
)
from gateway.routes.issuance import _ISSUANCE_HEADERS

flow_router = APIRouter(prefix="/v1/flows", tags=["Flows"])


def _validated_flow_body(
    body: FlowDefinitionCreate | FlowDefinitionUpdate | FlowInstanceCreate,
    *,
    patch: bool = False,
) -> bytes:
    """Serialize only validated public Flow fields to the downstream service."""
    payload = body.model_dump(mode="json", exclude_unset=patch)
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()


def _require_selected_organization(request: Request, organization_id: str) -> None:
    """Bind body tenant selection to the gateway-authenticated organization."""
    state = getattr(request, "state", None)
    selected = str(getattr(state, "organization_id", "") or "").strip()
    if selected and selected != organization_id:
        raise HTTPException(
            status_code=403,
            detail="organization_id does not match the authorized organization context",
        )


def _sanitize_public_response(
    response: Response,
    model: type,
    *,
    many: bool = False,
) -> Response:
    """Project and validate successful service responses against one public model."""
    body = getattr(response, "body", None)
    if response.status_code >= 400 or response.status_code == 204 or body is None:
        return response
    if not body:
        return response
    try:
        raw = json.loads(bytes(body))

        def validate_item(item):
            if not isinstance(item, dict):
                raise ValueError("public response item is not an object")
            projected = {
                field: item[field] for field in model.model_fields if field in item
            }
            return model.model_validate(projected).model_dump(
                mode="json",
                exclude_none=True,
            )

        if many:
            if not isinstance(raw, list):
                raise ValueError("public response is not a list")
            public = [validate_item(item) for item in raw]
        else:
            public = validate_item(raw)
    except (TypeError, ValueError, UnicodeDecodeError, ValidationError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Flow service returned a response outside the public contract.",
        ) from exc

    return Response(
        content=json.dumps(public, separators=(",", ":")),
        status_code=response.status_code,
        headers={
            key: value
            for key, value in response.headers.items()
            if key.lower() not in {"content-length", "content-type"}
        },
        media_type="application/json",
    )


def _sanitize_verification_start_response(response: Response) -> Response:
    """Expose only the Marty-Protocol verification-start response."""
    if response.status_code >= 400 or response.status_code == 204 or not response.body:
        return response
    try:
        payload = json.loads(response.body)
        if not isinstance(payload, dict):
            raise ValueError("response is not an object")
        public_payload = {
            field: payload[field]
            for field in VerificationRequestResponse.model_fields
            if field in payload
        }
        validated = VerificationRequestResponse.model_validate(public_payload)
    except (TypeError, ValueError, UnicodeDecodeError, ValidationError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Flow service returned an invalid public verification response.",
        ) from exc

    return Response(
        content=validated.model_dump_json(),
        status_code=response.status_code,
        headers={
            key: value
            for key, value in response.headers.items()
            if key.lower() not in {"content-length", "content-type"}
        },
        media_type="application/json",
    )


async def _validate_flow_definition_refs(
    body: FlowDefinitionCreate | FlowDefinitionUpdate,
    request: Request,
) -> None:
    """Validate that FK references in a FlowDefinitionCreate exist."""
    if body.credential_template_id:
        if not await _resource_exists(
            "credential-templates",
            f"/v1/credential-templates/{body.credential_template_id}",
            request,
        ):
            raise HTTPException(
                status_code=404,
                detail=f"Credential template not found: {body.credential_template_id}",
            )
    if body.application_template_id:
        if not await _resource_exists(
            "issuance",
            f"/v1/application-templates/{body.application_template_id}",
            request,
            inject_headers=_ISSUANCE_HEADERS,
        ):
            raise HTTPException(
                status_code=404,
                detail=f"Application template not found: {body.application_template_id}",
            )
    if body.presentation_policy_id:
        if not await _resource_exists(
            "presentation-policies",
            f"/v1/presentation-policies/{body.presentation_policy_id}",
            request,
        ):
            raise HTTPException(
                status_code=422,
                detail=f"Presentation policy not found: {body.presentation_policy_id}",
            )
    if body.delivery_destination_profile_id:
        if not await _resource_exists(
            "credential-templates",
            f"/v1/delivery-destinations/{body.delivery_destination_profile_id}",
            request,
        ):
            raise HTTPException(
                status_code=422,
                detail=f"Delivery destination not found: {body.delivery_destination_profile_id}",
            )
    if body.trust_profile_id:
        if not await _resource_exists(
            "trust-profiles", f"/v1/trust-profiles/{body.trust_profile_id}", request
        ):
            raise HTTPException(
                status_code=422,
                detail=f"Trust profile not found: {body.trust_profile_id}",
            )


# ── Flow Definitions ─────────────────────────────────────────────────


@flow_router.get("/capabilities", summary="Get Flow Capabilities")
async def get_flow_capabilities(request: Request) -> Response:
    """Return fixed sequences, extension points, and runtime blockers."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/capabilities")


@flow_router.post(
    "/definitions",
    response_model=FlowDefinitionResponse,
    summary="Create Flow Definition",
)
async def create_flow_definition(
    body: FlowDefinitionCreate, request: Request
) -> Response:
    """Create a new Flow Definition for orchestrating credential operations."""
    _require_selected_organization(request, body.organization_id)
    await _validate_flow_definition_refs(body, request)
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    response = await proxy_request(
        request,
        service_url,
        "/v1/flows/definitions",
        body_override=_validated_flow_body(body),
    )
    return _sanitize_public_response(response, FlowDefinitionResponse)


@flow_router.get(
    "/definitions",
    response_model=list[FlowDefinitionResponse],
    summary="List Flow Definitions",
)
async def list_flow_definitions(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Flow Definitions for an organization."""
    _require_selected_organization(request, organization_id)
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    response = await proxy_request(request, service_url, "/v1/flows/definitions")
    return _sanitize_public_response(response, FlowDefinitionResponse, many=True)


@flow_router.get(
    "/definitions/{flow_id}",
    response_model=FlowDefinitionResponse,
    summary="Get Flow Definition",
)
async def get_flow_definition(flow_id: str, request: Request) -> Response:
    """Get a Flow Definition by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    response = await proxy_request(
        request, service_url, f"/v1/flows/definitions/{flow_id}"
    )
    return _sanitize_public_response(response, FlowDefinitionResponse)


@flow_router.post(
    "/definitions/{flow_id}/activate",
    response_model=FlowDefinitionResponse,
    summary="Activate Flow",
)
async def activate_flow_definition(flow_id: str, request: Request) -> Response:
    """Activate a Flow Definition."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    response = await proxy_request(
        request, service_url, f"/v1/flows/definitions/{flow_id}/activate"
    )
    return _sanitize_public_response(response, FlowDefinitionResponse)


@flow_router.post("/definitions/{flow_id}/validate", summary="Validate Flow")
async def validate_flow_definition(flow_id: str, request: Request) -> Response:
    """Return dependency and capability blockers for a draft flow."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(
        request, service_url, f"/v1/flows/definitions/{flow_id}/validate"
    )


@flow_router.post("/definitions/{flow_id}/test", summary="Test Flow")
async def test_flow_definition(flow_id: str, request: Request) -> Response:
    """Resolve a dry-run execution plan without external side effects."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(
        request, service_url, f"/v1/flows/definitions/{flow_id}/test"
    )


@flow_router.patch(
    "/definitions/{flow_id}",
    response_model=FlowDefinitionResponse,
    summary="Update Flow Definition",
)
async def update_flow_definition(
    flow_id: str, body: FlowDefinitionUpdate, request: Request
) -> Response:
    """Update a Flow Definition."""
    _require_selected_organization(request, body.organization_id)
    await _validate_flow_definition_refs(body, request)
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    response = await proxy_request(
        request,
        service_url,
        f"/v1/flows/definitions/{flow_id}",
        body_override=_validated_flow_body(body, patch=True),
    )
    return _sanitize_public_response(response, FlowDefinitionResponse)


@flow_router.delete("/definitions/{flow_id}", summary="Delete Flow Definition")
async def delete_flow_definition(flow_id: str, request: Request) -> Response:
    """Delete a Flow Definition."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/definitions/{flow_id}")


# ── Flow Instances ───────────────────────────────────────────────────


@flow_router.post(
    "/instances", response_model=FlowInstanceResponse, summary="Start Flow Instance"
)
async def start_flow_instance(body: FlowInstanceCreate, request: Request) -> Response:
    """Start a new Flow Instance."""
    _require_selected_organization(request, body.organization_id)
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    response = await proxy_request(
        request,
        service_url,
        "/v1/flows/instances",
        body_override=_validated_flow_body(body),
    )
    return _sanitize_public_response(response, FlowInstanceResponse)


@flow_router.get(
    "/instances",
    response_model=list[FlowInstanceResponse],
    summary="List Flow Instances",
)
async def list_flow_instances(
    organization_id: str = Query(..., description="Organization ID"),
    flow_definition_id: str | None = Query(
        None, description="Filter by flow definition"
    ),
    status: str | None = Query(None, description="Filter by status"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    request: Request = None,
) -> Response:
    """List Flow Instances for an organization."""
    _require_selected_organization(request, organization_id)
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    response = await proxy_request(request, service_url, "/v1/flows/instances")
    return _sanitize_public_response(response, FlowInstanceResponse, many=True)


@flow_router.get(
    "/instances/{instance_id}",
    response_model=FlowInstanceResponse,
    summary="Get Flow Instance",
)
async def get_flow_instance(instance_id: str, request: Request) -> Response:
    """Get a Flow Instance by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    response = await proxy_request(
        request, service_url, f"/v1/flows/instances/{instance_id}"
    )
    return _sanitize_public_response(response, FlowInstanceResponse)


@flow_router.post(
    "/instances/{instance_id}/advance",
    response_model=FlowInstanceResponse,
    summary="Advance Flow",
)
async def advance_flow_instance(instance_id: str, request: Request) -> Response:
    """Advance a Flow Instance to the next step."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    response = await proxy_request(
        request, service_url, f"/v1/flows/instances/{instance_id}/advance"
    )
    return _sanitize_public_response(response, FlowInstanceResponse)


@flow_router.post(
    "/instances/{instance_id}/cancel",
    response_model=FlowInstanceResponse,
    summary="Cancel Flow",
)
async def cancel_flow_instance(instance_id: str, request: Request) -> Response:
    """Cancel an unfinished Flow Instance."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    response = await proxy_request(
        request, service_url, f"/v1/flows/instances/{instance_id}/cancel"
    )
    return _sanitize_public_response(response, FlowInstanceResponse)


# ── Verification Flows ───────────────────────────────────────────────


@flow_router.post(
    "/verify",
    response_model=VerificationRequestResponse,
    summary="Start Verification Flow",
)
async def start_verification_flow(
    body: StartVerificationFlowRequest, request: Request
) -> Response:
    """
    Start a verification flow for async wallet interactions.

    Creates a flow instance with a QR code / request_uri for wallet scanning.
    For stateless verification, use POST /v1/presentation-policies/{id}/evaluate instead.
    """
    organization_id = str(body.organization_id or "").strip()
    issuer_did = str(body.issuer_did or "").strip()
    if not organization_id:
        raise HTTPException(
            status_code=422,
            detail="organization_id is required to start a signed verification flow.",
        )
    if not issuer_did:
        raise HTTPException(
            status_code=422,
            detail="issuer_did is required to start a signed verification flow.",
        )
    _require_selected_organization(request, organization_id)

    policy_organization_id: str | None = None
    if body.presentation_policy_id:
        policy_organization_id = await _resource_org_id(
            "presentation-policies",
            f"/v1/presentation-policies/{body.presentation_policy_id}",
            request,
        )
        if (
            not isinstance(policy_organization_id, str)
            or not policy_organization_id.strip()
        ):
            raise HTTPException(
                status_code=422,
                detail=f"Presentation policy not found: {body.presentation_policy_id}",
            )
        policy_organization_id = policy_organization_id.strip()
        if policy_organization_id != organization_id:
            raise HTTPException(
                status_code=403,
                detail="Presentation policy belongs to another organization.",
            )
    if body.trust_profile_id:
        trust_profile_organization_id = await _resource_org_id(
            "trust-profiles",
            f"/v1/trust-profiles/{body.trust_profile_id}",
            request,
        )
        if (
            not isinstance(trust_profile_organization_id, str)
            or not trust_profile_organization_id.strip()
        ):
            raise HTTPException(
                status_code=422,
                detail=f"Trust profile not found: {body.trust_profile_id}",
            )
        trust_profile_organization_id = trust_profile_organization_id.strip()
        if (
            policy_organization_id
            and trust_profile_organization_id != policy_organization_id
        ):
            raise HTTPException(
                status_code=422,
                detail="Trust profile and presentation policy must belong to the same organization",
            )
        if trust_profile_organization_id != organization_id:
            raise HTTPException(
                status_code=403,
                detail="Trust profile belongs to another organization.",
            )
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    response = await proxy_request(request, service_url, "/v1/flows/verify")
    return _sanitize_verification_start_response(response)


@flow_router.api_route(
    "/instances/{instance_id}/request",
    methods=["GET", "POST"],
    summary="Get Verification Request Object",
)
async def get_flow_verification_request(instance_id: str, request: Request) -> Response:
    """Get the OID4VP request object, including POST request_uri retrieval."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(
        request, service_url, f"/v1/flows/instances/{instance_id}/request"
    )


@flow_router.get(
    "/instances/{instance_id}/result",
    response_model=VerificationResultResponse,
    summary="Get Verification Result",
)
async def get_flow_instance_result(instance_id: str, request: Request) -> Response:
    """OID4VP-1FINAL §8.7 — Relying-party result polling endpoint for a flow instance."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    response = await proxy_request(
        request, service_url, f"/v1/flows/instances/{instance_id}/result"
    )
    return _sanitize_public_response(response, VerificationResultResponse)


@flow_router.post("/instances/{instance_id}/submit", summary="Submit Verification")
async def submit_flow_verification(instance_id: str, request: Request) -> Response:
    """Submit a VP token to complete a verification flow. Accepts JSON or form-encoded data."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(
        request, service_url, f"/v1/flows/instances/{instance_id}/submit"
    )


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
