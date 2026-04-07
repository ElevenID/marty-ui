"""Device Registration routes."""
from __future__ import annotations

from fastapi import APIRouter, Query, Request, Response

from gateway.models import (
    DeviceRegistrationCreate,
    DeviceRegistrationResponse,
    DeviceRegistrationUpdate,
)
from gateway.proxy import get_registry, proxy_request

device_router = APIRouter(prefix="/v1/devices", tags=["Devices"])


@device_router.post("", response_model=DeviceRegistrationResponse, summary="Register Device")
async def register_device(body: DeviceRegistrationCreate, request: Request) -> Response:
    """Register or upsert a device for the current user."""
    registry = get_registry()
    service_url = registry.get_service_url("device-registration")
    return await proxy_request(request, service_url, "/v1/devices")


@device_router.get("", response_model=list[DeviceRegistrationResponse], summary="List Devices")
async def list_devices(
    organization_id: str | None = Query(None, description="Optional organization filter"),
    request: Request = None,
) -> Response:
    """List device registrations for the current user."""
    registry = get_registry()
    service_url = registry.get_service_url("device-registration")
    return await proxy_request(request, service_url, "/v1/devices")


@device_router.get("/{registration_id}", response_model=DeviceRegistrationResponse, summary="Get Device")
async def get_device(registration_id: str, request: Request) -> Response:
    """Get a device registration by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("device-registration")
    return await proxy_request(request, service_url, f"/v1/devices/{registration_id}")


@device_router.patch("/{registration_id}", response_model=DeviceRegistrationResponse, summary="Update Device")
async def update_device(registration_id: str, body: DeviceRegistrationUpdate, request: Request) -> Response:
    """Update a device registration."""
    registry = get_registry()
    service_url = registry.get_service_url("device-registration")
    return await proxy_request(request, service_url, f"/v1/devices/{registration_id}")


@device_router.delete("/{registration_id}", summary="Delete Device")
async def delete_device(registration_id: str, request: Request) -> Response:
    """Delete a device registration."""
    registry = get_registry()
    service_url = registry.get_service_url("device-registration")
    return await proxy_request(request, service_url, f"/v1/devices/{registration_id}")
