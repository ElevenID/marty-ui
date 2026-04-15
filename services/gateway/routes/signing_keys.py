"""Signing key compatibility routes for the console UI."""
from __future__ import annotations

import os

from fastapi import APIRouter, Body, HTTPException, Query, Request
from fastapi.responses import JSONResponse

signing_key_router = APIRouter(prefix="/v1/signing-keys", tags=["Signing Keys"])


def _resolve_org_id(request: Request, organization_id: str | None) -> str:
    resolved = organization_id or getattr(request.state, "session_organization_id", None)
    if not resolved:
        raise HTTPException(status_code=422, detail="organization_id is required")
    return resolved


def _domain_config(request: Request) -> dict:
    host = request.headers.get("host", "")
    public_domain = os.environ.get("PUBLIC_DOMAIN") or host.split(":")[0]
    issuer_base_url = os.environ.get("ISSUER_BASE_URL") or f"{request.url.scheme}://{host}"
    return {
        "public_domain": public_domain,
        "issuer_base_url": issuer_base_url,
        "key_source": os.environ.get("SIGNING_KEY_SOURCE", "hsm-compat"),
        "key_management_mode": "metadata-only",
    }


def _provider_metadata() -> dict:
    return {
        "provider": os.environ.get("HSM_PROVIDER", "unconfigured"),
        "status": "metadata_only",
        "managed_by": "Marty gateway compatibility layer",
        "supports_rotation": False,
        "supports_upload": False,
        "supports_delete": False,
    }


@signing_key_router.get("", summary="List Signing Keys")
async def list_signing_keys(
    request: Request,
    organization_id: str | None = Query(None, description="Optional organization scope"),
):
    """Return signing key compatibility metadata and domain configuration."""
    _resolve_org_id(request, organization_id)
    return JSONResponse(
        content={
            "keys": [],
            "provider_metadata": _provider_metadata(),
            "domain_config": _domain_config(request),
            "message": "Dedicated signing-key inventory is not configured in this deployment.",
        }
    )


@signing_key_router.get("/config", summary="Get Signing Key Management Config")
async def get_signing_key_config(
    request: Request,
    organization_id: str | None = Query(None, description="Optional organization scope"),
):
    """Return compatibility config while signing-key service is not separately deployed."""
    _resolve_org_id(request, organization_id)
    return JSONResponse(
        content={
            "hsm_enabled": False,
            "hsm_settings": {},
            "vault_enabled": False,
            "vault_settings": {},
            "provider_metadata": _provider_metadata(),
            "domain_config": _domain_config(request),
        }
    )


@signing_key_router.patch("/config", summary="Update Signing Key Management Config")
async def update_signing_key_config(
    request: Request,
    body: dict = Body(default_factory=dict),
    organization_id: str | None = Query(None, description="Optional organization scope"),
):
    """Accept config updates for UI compatibility and echo the requested settings."""
    _resolve_org_id(request, organization_id)
    return JSONResponse(
        content={
            **body,
            "provider_metadata": _provider_metadata(),
            "domain_config": _domain_config(request),
        }
    )
