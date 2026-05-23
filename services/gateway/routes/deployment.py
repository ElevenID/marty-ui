"""Deployment Profile and Lane routes."""
from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query, Request, Response

from gateway.models import (
    DeploymentProfileCreate,
    DeploymentProfileResponse,
    DeploymentProfileUpdate,
    DeviceAssignment,
    LaneCreate,
    LaneResponse,
)
from gateway.proxy import _resource_exists, _resource_org_id, get_registry, proxy_request

deployment_profile_router = APIRouter(prefix="/v1/deployment-profiles", tags=["Deployment Profiles"])


@deployment_profile_router.post("", response_model=DeploymentProfileResponse, summary="Create Deployment Profile")
async def create_deployment_profile(body: DeploymentProfileCreate, request: Request) -> Response:
    """Create a new Deployment Profile for runtime configuration."""
    raw_body = await request.body()
    raw_data = json.loads(raw_body) if raw_body else {}
    trust_profile_id = raw_data.get("trust_profile_id") or body.trust_profile_id
    if not trust_profile_id:
        raise HTTPException(status_code=422, detail="trust_profile_id is required")
    if not await _resource_exists("trust-profiles", f"/v1/trust-profiles/{trust_profile_id}", request):
        raise HTTPException(status_code=422, detail=f"Trust profile not found: {trust_profile_id}")

    default_policy_id = (
        raw_data.get("default_policy_id")
        or raw_data.get("default_presentation_policy_id")
        or body.default_policy_id
        or body.default_presentation_policy_id
    )
    presentation_policy_ids = raw_data.get("presentation_policy_ids") or body.presentation_policy_ids
    if not presentation_policy_ids and default_policy_id:
        presentation_policy_ids = [default_policy_id]
    if not presentation_policy_ids:
        raise HTTPException(status_code=422, detail="presentation_policy_ids must contain at least one policy")
    if default_policy_id and default_policy_id not in presentation_policy_ids:
        raise HTTPException(status_code=422, detail="default_policy_id must be included in presentation_policy_ids")
    for policy_id in presentation_policy_ids:
        owner_org = await _resource_org_id("presentation-policies", f"/v1/presentation-policies/{policy_id}", request)
        if owner_org is None:
            raise HTTPException(status_code=422, detail=f"Presentation policy not found: {policy_id}")
        if owner_org != body.organization_id:
            raise HTTPException(status_code=403, detail="Access denied: presentation policy belongs to another organization")

    credential_template_ids = raw_data.get("credential_template_ids") or body.credential_template_ids
    for template_id in credential_template_ids:
        owner_org = await _resource_org_id("credential-templates", f"/v1/credential-templates/{template_id}", request)
        if owner_org is None:
            raise HTTPException(status_code=422, detail=f"Credential template not found: {template_id}")
        if owner_org != body.organization_id:
            raise HTTPException(status_code=403, detail="Access denied: credential template belongs to another organization")
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, "/v1/deployment-profiles", body_override=raw_body)


@deployment_profile_router.get("", response_model=list[DeploymentProfileResponse], summary="List Deployment Profiles")
async def list_deployment_profiles(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Deployment Profiles for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, "/v1/deployment-profiles")


@deployment_profile_router.get("/{profile_id}", response_model=DeploymentProfileResponse, summary="Get Deployment Profile")
async def get_deployment_profile(profile_id: str, request: Request) -> Response:
    """Get a Deployment Profile by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}")


@deployment_profile_router.post("/{profile_id}/activate", response_model=DeploymentProfileResponse, summary="Activate Deployment Profile")
async def activate_deployment_profile(profile_id: str, request: Request) -> Response:
    """Activate a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/activate")


@deployment_profile_router.put("/{profile_id}", response_model=DeploymentProfileResponse, summary="Update Deployment Profile")
async def update_deployment_profile(profile_id: str, body: DeploymentProfileUpdate, request: Request) -> Response:
    """Update a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}")


@deployment_profile_router.patch("/{profile_id}", response_model=DeploymentProfileResponse, summary="Patch Deployment Profile")
async def patch_deployment_profile(profile_id: str, body: DeploymentProfileUpdate, request: Request) -> Response:
    """Patch a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}")


@deployment_profile_router.delete("/{profile_id}", summary="Delete Deployment Profile")
async def delete_deployment_profile(profile_id: str, request: Request) -> Response:
    """Delete a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}")


@deployment_profile_router.post("/{profile_id}/generate-api-key", summary="Generate API Key")
async def generate_deployment_api_key(profile_id: str, request: Request) -> Response:
    """Generate a new API key for the Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/generate-api-key")


# ── Lanes (nested under Deployment Profiles) ─────────────────────────

@deployment_profile_router.post("/{profile_id}/lanes", response_model=LaneResponse, summary="Create Lane")
async def create_lane(profile_id: str, body: LaneCreate, request: Request) -> Response:
    """Create a Lane (logical device grouping) within a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes")


@deployment_profile_router.get("/{profile_id}/lanes", response_model=list[LaneResponse], summary="List Lanes")
async def list_lanes(profile_id: str, request: Request) -> Response:
    """List Lanes for a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes")


@deployment_profile_router.get("/{profile_id}/lanes/{lane_id}", response_model=LaneResponse, summary="Get Lane")
async def get_lane(profile_id: str, lane_id: str, request: Request) -> Response:
    """Get a Lane by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}")


@deployment_profile_router.put("/{profile_id}/lanes/{lane_id}", response_model=LaneResponse, summary="Update Lane")
async def update_lane(profile_id: str, lane_id: str, body: LaneCreate, request: Request) -> Response:
    """Update a Lane."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}")


@deployment_profile_router.delete("/{profile_id}/lanes/{lane_id}", summary="Delete Lane")
async def delete_lane(profile_id: str, lane_id: str, request: Request) -> Response:
    """Delete a Lane."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}")


@deployment_profile_router.post("/{profile_id}/lanes/{lane_id}/devices", summary="Assign Device to Lane")
async def assign_device_to_lane(profile_id: str, lane_id: str, body: DeviceAssignment, request: Request) -> Response:
    """Assign a device to a Lane."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}/devices")
