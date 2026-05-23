"""Revocation Profile and Cascade Revocation routes."""
from __future__ import annotations

from fastapi import APIRouter, Request, Response

from gateway.proxy import get_registry, proxy_request

revocation_profile_router = APIRouter(prefix="/v1/revocation-profiles", tags=["Revocation Profiles"])
cascade_revocation_router = APIRouter(prefix="/v1/cascade-revocations", tags=["Cascade Revocations"])
status_list_router = APIRouter(prefix="/v1/organizations", tags=["Status Lists"])


# ── Revocation Profiles ──────────────────────────────────────────────

@revocation_profile_router.post("", summary="Create Revocation Profile")
async def create_revocation_profile(request: Request) -> Response:
    """Create a new Revocation Profile for format-agnostic revocation configuration."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, "/v1/revocation-profiles")


@revocation_profile_router.get("", summary="List Revocation Profiles")
async def list_revocation_profiles(request: Request) -> Response:
    """List all Revocation Profiles."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, "/v1/revocation-profiles")


@revocation_profile_router.get("/{profile_id}", summary="Get Revocation Profile")
async def get_revocation_profile(profile_id: str, request: Request) -> Response:
    """Get a Revocation Profile by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/revocation-profiles/{profile_id}")


@revocation_profile_router.post("/{profile_id}/activate", summary="Activate Revocation Profile")
async def activate_revocation_profile(profile_id: str, request: Request) -> Response:
    """Activate a Revocation Profile for use in credential issuance."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/revocation-profiles/{profile_id}/activate")


@revocation_profile_router.delete("/{profile_id}", summary="Delete Revocation Profile")
async def delete_revocation_profile(profile_id: str, request: Request) -> Response:
    """Delete a Revocation Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/revocation-profiles/{profile_id}")


# Public Status Lists ---------------------------------------------------------

@status_list_router.get(
    "/{organization_id}/revocation-profiles/{profile_id}/status-lists/{mechanism}/{purpose}",
    summary="Get Status List Document",
)
async def get_status_list_document(
    organization_id: str,
    profile_id: str,
    mechanism: str,
    purpose: str,
    request: Request,
) -> Response:
    """Proxy public status-list VC documents for credentialStatus resolution."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(
        request,
        service_url,
        (
            f"/v1/organizations/{organization_id}"
            f"/revocation-profiles/{profile_id}"
            f"/status-lists/{mechanism}/{purpose}"
        ),
    )


# ── Cascade Revocations ─────────────────────────────────────────────

@cascade_revocation_router.post("", summary="Trigger Cascade Revocation")
async def create_cascade_revocation(request: Request) -> Response:
    """Trigger a cascade revocation operation."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, "/v1/cascade-revocations")


@cascade_revocation_router.get("", summary="List Cascade Revocations")
async def list_cascade_revocations(request: Request) -> Response:
    """List cascade revocation operations."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, "/v1/cascade-revocations")


@cascade_revocation_router.get("/{operation_id}", summary="Get Cascade Revocation")
async def get_cascade_revocation(operation_id: str, request: Request) -> Response:
    """Get a cascade revocation operation by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/cascade-revocations/{operation_id}")


@cascade_revocation_router.post("/{operation_id}/confirm", summary="Confirm Cascade Revocation")
async def confirm_cascade_revocation(operation_id: str, request: Request) -> Response:
    """Confirm a paused cascade revocation operation."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/cascade-revocations/{operation_id}/confirm")


@cascade_revocation_router.post("/{operation_id}/rollback", summary="Rollback Cascade Revocation")
async def rollback_cascade_revocation(operation_id: str, request: Request) -> Response:
    """Roll back a completed cascade revocation operation."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/cascade-revocations/{operation_id}/rollback")


@cascade_revocation_router.delete("/{operation_id}", summary="Cancel Cascade Revocation")
async def delete_cascade_revocation(operation_id: str, request: Request) -> Response:
    """Cancel a pending cascade revocation operation."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/cascade-revocations/{operation_id}")
