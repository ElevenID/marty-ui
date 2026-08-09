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
    PresentationPolicyUpdate,
)
from gateway.proxy import (
    _forward_headers,
    _resource_org_id,
    get_http_client,
    get_registry,
    proxy_request,
)

presentation_policy_router = APIRouter(
    prefix="/v1/presentation-policies", tags=["Presentation Policies"]
)

_PUBLIC_PRESENTATION_POLICY_FIELDS = frozenset(PresentationPolicyResponse.model_fields)


def _sanitize_presentation_policy_response(response: Response) -> Response:
    """Enforce the public MIP resource shape on proxied policy responses."""
    if response.status_code >= 400 or response.status_code == 204 or not response.body:
        return response
    try:
        payload = json.loads(response.body)
    except (TypeError, ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=502,
            detail="Presentation policy service returned invalid JSON",
        ) from exc

    def sanitize(value: object) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise HTTPException(
                status_code=502,
                detail="Presentation policy service returned an invalid resource",
            )
        public = {
            key: entry
            for key, entry in value.items()
            if key in _PUBLIC_PRESENTATION_POLICY_FIELDS
        }
        try:
            validated = PresentationPolicyResponse.model_validate(public)
            sanitized = validated.model_dump(
                mode="json",
                exclude_none=True,
            )
            if not validated.holder_binding.required:
                sanitized["holder_binding"] = {"required": False}
            return sanitized
        except ValueError as exc:
            raise HTTPException(
                status_code=502,
                detail="Presentation policy service response violates the public contract",
            ) from exc

    if isinstance(payload, list):
        sanitized: object = [sanitize(item) for item in payload]
    else:
        sanitized = sanitize(payload)

    headers = {
        key: value
        for key, value in response.headers.items()
        if key.lower() not in {"content-length", "content-type"}
    }
    return Response(
        content=json.dumps(sanitized, separators=(",", ":")),
        status_code=response.status_code,
        headers=headers,
        media_type="application/json",
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


def _validated_policy_payload(
    body: PresentationPolicyCreate | PresentationPolicyUpdate,
    *,
    include_organization_id: bool = True,
) -> dict[str, Any]:
    """Serialize only public validated fields in their canonical wire shape."""
    payload = body.model_dump(mode="json", exclude_none=True, exclude_unset=True)
    if body.holder_binding is not None and not body.holder_binding.required:
        payload["holder_binding"] = {"required": False}
    if not include_organization_id:
        payload.pop("organization_id", None)
    return payload


async def _authoritative_policy_body(
    body: PresentationPolicyCreate | PresentationPolicyUpdate,
    request: Request,
    *,
    include_organization_id: bool = True,
) -> bytes:
    """Bind every policy requirement to its authoritative template format.

    The verifier must not guess SD-JWT for an mdoc template, and callers must
    not be allowed to select a format that differs from the referenced
    template. Re-serialize only the validated public model and replace each
    format with the credential-template service's canonical value.
    """
    payload = _validated_policy_payload(
        body,
        include_organization_id=include_organization_id,
    )
    organization_id = body.organization_id

    requirement_groups = [
        (
            payload.get("credential_requirements", []),
            body.credential_requirements or [],
        )
    ]
    raw_alternatives = payload.get("alternative_requirements", [])
    for raw_alternative, alternative in zip(
        raw_alternatives,
        body.alternative_requirements or [],
        strict=True,
    ):
        requirement_groups.append(
            (
                raw_alternative["credential_requirements"],
                alternative.credential_requirements,
            )
        )

    for raw_requirements, requirements in requirement_groups:
        for raw_requirement, requirement in zip(
            raw_requirements,
            requirements,
            strict=True,
        ):
            template = await _load_credential_template(
                requirement.credential_template_id,
                request,
            )
            if template.get("organization_id") != organization_id:
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
    response = await proxy_request(
        request,
        service_url,
        "/v1/presentation-policies",
        body_override=body_override,
    )
    return _sanitize_presentation_policy_response(response)


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
    response = await proxy_request(
        request,
        service_url,
        "/v1/presentation-policies",
    )
    return _sanitize_presentation_policy_response(response)


@presentation_policy_router.get(
    "/{policy_id}",
    response_model=PresentationPolicyResponse,
    summary="Get Presentation Policy",
)
async def get_presentation_policy(policy_id: str, request: Request) -> Response:
    """Get a Presentation Policy by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    response = await proxy_request(
        request, service_url, f"/v1/presentation-policies/{policy_id}"
    )
    return _sanitize_presentation_policy_response(response)


@presentation_policy_router.post(
    "/{policy_id}/activate",
    response_model=PresentationPolicyResponse,
    summary="Activate Presentation Policy",
)
async def activate_presentation_policy(policy_id: str, request: Request) -> Response:
    """Activate a Presentation Policy for use in verification."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    response = await proxy_request(
        request, service_url, f"/v1/presentation-policies/{policy_id}/activate"
    )
    return _sanitize_presentation_policy_response(response)


@presentation_policy_router.patch(
    "/{policy_id}",
    response_model=PresentationPolicyResponse,
    summary="Update Presentation Policy",
)
async def update_presentation_policy(
    policy_id: str, body: PresentationPolicyUpdate, request: Request
) -> Response:
    """Update a Presentation Policy."""
    owner_org = await _resource_org_id(
        "presentation-policies",
        f"/v1/presentation-policies/{policy_id}",
        request,
    )
    if owner_org is None or owner_org != body.organization_id:
        raise HTTPException(status_code=404, detail="Presentation Policy not found")
    body_override = await _authoritative_policy_body(
        body,
        request,
        include_organization_id=False,
    )
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    response = await proxy_request(
        request,
        service_url,
        f"/v1/presentation-policies/{policy_id}",
        body_override=body_override,
    )
    return _sanitize_presentation_policy_response(response)


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
