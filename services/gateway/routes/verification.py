"""Presentation Policy routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, Response

from gateway.models import (
    EvaluateInlineRequest,
    EvaluatePresentationRequest,
    PolicyEvaluationResponse,
    PresentationPolicyCreate,
    PresentationPolicyResponse,
)
from gateway.proxy import _resource_exists, get_registry, proxy_request

presentation_policy_router = APIRouter(prefix="/v1/presentation-policies", tags=["Presentation Policies"])


@presentation_policy_router.post("", response_model=PresentationPolicyResponse, summary="Create Presentation Policy")
async def create_presentation_policy(body: PresentationPolicyCreate, request: Request) -> Response:
    """Create a new Presentation Policy defining what credentials to request."""
    for req in body.credential_requirements:
        if not await _resource_exists("credential-templates", f"/v1/credential-templates/{req.credential_template_id}", request):
            raise HTTPException(status_code=422, detail=f"Credential template not found: {req.credential_template_id}")
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, "/v1/presentation-policies")


@presentation_policy_router.get("", response_model=list[PresentationPolicyResponse], summary="List Presentation Policies")
async def list_presentation_policies(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Presentation Policies for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, "/v1/presentation-policies")


@presentation_policy_router.get("/{policy_id}", response_model=PresentationPolicyResponse, summary="Get Presentation Policy")
async def get_presentation_policy(policy_id: str, request: Request) -> Response:
    """Get a Presentation Policy by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, f"/v1/presentation-policies/{policy_id}")


@presentation_policy_router.post("/{policy_id}/activate", response_model=PresentationPolicyResponse, summary="Activate Presentation Policy")
async def activate_presentation_policy(policy_id: str, request: Request) -> Response:
    """Activate a Presentation Policy for use in verification."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, f"/v1/presentation-policies/{policy_id}/activate")


@presentation_policy_router.put("/{policy_id}", response_model=PresentationPolicyResponse, summary="Update Presentation Policy")
async def update_presentation_policy(policy_id: str, body: PresentationPolicyCreate, request: Request) -> Response:
    """Update a Presentation Policy."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, f"/v1/presentation-policies/{policy_id}")


@presentation_policy_router.delete("/{policy_id}", summary="Delete Presentation Policy")
async def delete_presentation_policy(policy_id: str, request: Request) -> Response:
    """Delete a Presentation Policy."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, f"/v1/presentation-policies/{policy_id}")


@presentation_policy_router.post("/{policy_id}/evaluate", response_model=PolicyEvaluationResponse, summary="Evaluate Presentation Against Policy")
async def evaluate_presentation_with_policy(policy_id: str, body: EvaluatePresentationRequest, request: Request) -> Response:
    """
    Evaluate a verifiable presentation against a saved policy.

    This is the primary endpoint for stateless verification. Submit a VP token
    along with a policy ID, and receive an immediate evaluation result.

    The policy defines what credentials and claims are required, and this endpoint
    executes that policy against the submitted presentation.
    """
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, f"/v1/presentation-policies/{policy_id}/evaluate")


@presentation_policy_router.post("/evaluate", response_model=PolicyEvaluationResponse, summary="Evaluate Presentation with Inline Policy")
async def evaluate_presentation_inline(body: EvaluateInlineRequest, request: Request) -> Response:
    """
    Evaluate a verifiable presentation with an inline (ad-hoc) policy.

    Use this for one-off verifications where you don't need a saved policy.
    Provide both the policy definition and the VP token in the request body.
    """
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, "/v1/presentation-policies/evaluate")
