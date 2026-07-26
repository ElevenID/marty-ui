"""Presentation Policy routes."""

from __future__ import annotations

import json
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Query, Request, Response

from gateway.models import (
    EvaluateInlineRequest,
    EvaluatePresentationRequest,
    PolicyEvaluationResponse,
    PresentationPolicyCreate,
    PresentationPolicyResponse,
)
from gateway.proxy import _forward_headers, get_http_client, get_registry, proxy_request

presentation_policy_router = APIRouter(
    prefix="/v1/presentation-policies", tags=["Presentation Policies"]
)


async def _load_credential_template(
    credential_template_id: str,
    request: Request,
) -> dict[str, Any]:
    registry = get_registry()
    client = get_http_client()
    url = (
        f"{registry.get_service_url('credential-templates')}"
        f"/v1/credential-templates/{credential_template_id}"
    )
    try:
        response = await client.get(
            url,
            timeout=10.0,
            headers=_forward_headers(request),
        )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail="Credential template service unavailable",
        ) from exc
    if response.status_code >= 400:
        raise HTTPException(
            status_code=422,
            detail=f"Credential template not found: {credential_template_id}",
        )
    try:
        template = response.json()
    except ValueError as exc:
        raise HTTPException(
            status_code=502,
            detail="Credential template service returned invalid JSON",
        ) from exc
    if not isinstance(template, dict):
        raise HTTPException(
            status_code=502,
            detail="Credential template service returned an invalid template",
        )
    return template


async def _authoritative_policy_body(
    body: PresentationPolicyCreate,
    request: Request,
) -> bytes:
    """Bind every policy requirement to its authoritative template format.

    The verifier must not guess SD-JWT for an mdoc template, and callers must
    not be allowed to select a format that differs from the referenced
    template. Preserve the original JSON shape while replacing that field with
    the credential-template service's canonical value.
    """
    try:
        payload = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=400, detail="Invalid JSON request body"
        ) from exc
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=400, detail="Request body must be a JSON object"
        )

    raw_requirements = payload.get("credential_requirements", [])
    if not isinstance(raw_requirements, list) or len(raw_requirements) != len(
        body.credential_requirements
    ):
        raise HTTPException(
            status_code=422,
            detail="credential_requirements does not match the validated request",
        )

    for raw_requirement, requirement in zip(
        raw_requirements,
        body.credential_requirements,
        strict=True,
    ):
        if not isinstance(raw_requirement, dict):
            raise HTTPException(
                status_code=422,
                detail="credential_requirements entries must be JSON objects",
            )
        template = await _load_credential_template(
            requirement.credential_template_id,
            request,
        )
        if template.get("organization_id") != body.organization_id:
            raise HTTPException(
                status_code=422,
                detail=(
                    "Credential template must belong to the presentation "
                    f"policy organization: {requirement.credential_template_id}"
                ),
            )
        credential_format = template.get("credential_payload_format")
        if not isinstance(credential_format, str) or not credential_format.strip():
            raise HTTPException(
                status_code=502,
                detail=(
                    "Credential template has no canonical credential payload "
                    f"format: {requirement.credential_template_id}"
                ),
            )
        raw_requirement["credential_payload_format"] = credential_format.strip()

    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()


@presentation_policy_router.post(
    "", response_model=PresentationPolicyResponse, summary="Create Presentation Policy"
)
async def create_presentation_policy(
    body: PresentationPolicyCreate, request: Request
) -> Response:
    """Create a new Presentation Policy defining what credentials to request."""
    body_override = await _authoritative_policy_body(body, request)
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(
        request,
        service_url,
        "/v1/presentation-policies",
        body_override=body_override,
    )


@presentation_policy_router.get(
    "",
    response_model=list[PresentationPolicyResponse],
    summary="List Presentation Policies",
)
async def list_presentation_policies(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Presentation Policies for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, "/v1/presentation-policies")


@presentation_policy_router.get(
    "/{policy_id}",
    response_model=PresentationPolicyResponse,
    summary="Get Presentation Policy",
)
async def get_presentation_policy(policy_id: str, request: Request) -> Response:
    """Get a Presentation Policy by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(
        request, service_url, f"/v1/presentation-policies/{policy_id}"
    )


@presentation_policy_router.post(
    "/{policy_id}/activate",
    response_model=PresentationPolicyResponse,
    summary="Activate Presentation Policy",
)
async def activate_presentation_policy(policy_id: str, request: Request) -> Response:
    """Activate a Presentation Policy for use in verification."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(
        request, service_url, f"/v1/presentation-policies/{policy_id}/activate"
    )


@presentation_policy_router.put(
    "/{policy_id}",
    response_model=PresentationPolicyResponse,
    summary="Update Presentation Policy",
)
async def update_presentation_policy(
    policy_id: str, body: PresentationPolicyCreate, request: Request
) -> Response:
    """Update a Presentation Policy."""
    body_override = await _authoritative_policy_body(body, request)
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(
        request,
        service_url,
        f"/v1/presentation-policies/{policy_id}",
        body_override=body_override,
    )


@presentation_policy_router.delete("/{policy_id}", summary="Delete Presentation Policy")
async def delete_presentation_policy(policy_id: str, request: Request) -> Response:
    """Delete a Presentation Policy."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(
        request, service_url, f"/v1/presentation-policies/{policy_id}"
    )


@presentation_policy_router.post(
    "/{policy_id}/evaluate",
    response_model=PolicyEvaluationResponse,
    summary="Evaluate Presentation Against Policy",
)
async def evaluate_presentation_with_policy(
    policy_id: str, body: EvaluatePresentationRequest, request: Request
) -> Response:
    """
    Evaluate a verifiable presentation against a saved policy.

    This is the primary endpoint for stateless verification. Submit a VP token
    along with a policy ID, and receive an immediate evaluation result.

    The policy defines what credentials and claims are required, and this endpoint
    executes that policy against the submitted presentation.
    """
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(
        request, service_url, f"/v1/presentation-policies/{policy_id}/evaluate"
    )


@presentation_policy_router.post(
    "/evaluate",
    response_model=PolicyEvaluationResponse,
    summary="Evaluate Presentation with Inline Policy",
)
async def evaluate_presentation_inline(
    body: EvaluateInlineRequest, request: Request
) -> Response:
    """
    Evaluate a verifiable presentation with an inline (ad-hoc) policy.

    Use this for one-off verifications where you don't need a saved policy.
    Provide both the policy definition and the VP token in the request body.
    """
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(
        request, service_url, "/v1/presentation-policies/evaluate"
    )
