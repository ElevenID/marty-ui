"""Credential Template, Wallet Registry, and Compliance Profile routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request, Response

from gateway.models import (
    ComplianceProfileCreate,
    ComplianceProfileResponse,
    ComplianceProfileUpdate,
    CredentialTemplateCreate,
    CredentialTemplateResponse,
)
from gateway.proxy import _resource_exists, _resource_org_id, get_registry, proxy_request

credential_template_router = APIRouter(prefix="/v1/credential-templates", tags=["Credential Templates"])
wallet_registry_router = APIRouter(prefix="/v1/wallet-registry", tags=["Wallet Registry"])
delivery_destination_router = APIRouter(prefix="/v1/delivery-destinations", tags=["Delivery Destinations"])
compliance_profile_router = APIRouter(prefix="/v1/compliance-profiles", tags=["Compliance Profiles"])


# ── Credential Templates ─────────────────────────────────────────────

@credential_template_router.post("", response_model=CredentialTemplateResponse, summary="Create Credential Template")
async def create_credential_template(body: CredentialTemplateCreate, request: Request) -> Response:
    """Create a new Credential Template (master issuance configuration).

    Credential Template is the complete definition for issuing credentials, combining:
    - Schema/claims definition
    - Compliance Profile reference (format, framework)
    - Optional Application Template reference (for application-based issuance)
    - Cryptographic configuration (keys, certs, DIDs)
    - Validity and revocation settings
    """
    if body.trust_profile_id:
        if not await _resource_exists("trust-profiles", f"/v1/trust-profiles/{body.trust_profile_id}", request):
            raise HTTPException(status_code=422, detail=f"Trust profile not found: {body.trust_profile_id}")
    compliance_path = f"/v1/compliance-profiles/{body.compliance_profile_id}"
    if not await _resource_exists("compliance-profiles", compliance_path, request):
        raise HTTPException(status_code=422, detail=f"Compliance profile not found: {body.compliance_profile_id}")
    owner_org = await _resource_org_id("compliance-profiles", compliance_path, request)
    if owner_org is not None and owner_org != body.organization_id:
        raise HTTPException(status_code=403, detail="Access denied: compliance profile belongs to another organization")
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(
        request,
        service_url,
        "/v1/credential-templates",
        body_override=body.model_dump_json(exclude_none=True).encode(),
    )


@credential_template_router.get("", response_model=list[CredentialTemplateResponse], summary="List Credential Templates")
async def list_credential_templates(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Credential Templates for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, "/v1/credential-templates")


@credential_template_router.get("/{template_id}", response_model=CredentialTemplateResponse, summary="Get Credential Template")
async def get_credential_template(template_id: str, request: Request) -> Response:
    """Get a Credential Template by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(
        request,
        service_url,
        f"/v1/credential-templates/{template_id}",
    )


@credential_template_router.get("/{template_id}/wallet-compatibility", summary="Get Wallet Compatibility")
async def get_credential_template_wallet_compatibility(template_id: str, request: Request) -> Response:
    """Resolve the protocol-derived wallet compatibility profile for a credential template."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}/wallet-compatibility")


@credential_template_router.patch("/{template_id}", response_model=CredentialTemplateResponse, summary="Update Draft Credential Template")
async def update_credential_template(template_id: str, request: Request) -> Response:
    """Partially update a draft Credential Template."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}")


@credential_template_router.delete("/{template_id}", summary="Delete Credential Template")
async def delete_credential_template(template_id: str, request: Request) -> Response:
    """Delete a Credential Template."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}")


@credential_template_router.post("/{template_id}/validate-artifacts", summary="Validate Cryptographic Artifacts")
async def validate_credential_template_artifacts(template_id: str, request: Request) -> Response:
    """Validate that all required cryptographic artifacts are properly configured.

    Checks:
    - Signing key availability
    - Certificate chain validity (for mDoc)
    - DID resolution (for DID-based credentials)
    - Compliance with selected Compliance Profile requirements
    """
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}/validate-artifacts")


@credential_template_router.post("/{template_id}/activate", response_model=CredentialTemplateResponse, summary="Activate Credential Template")
async def activate_credential_template(template_id: str, request: Request) -> Response:
    """Activate a Credential Template."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}/activate")


@credential_template_router.post("/{template_id}/new-version", response_model=CredentialTemplateResponse, summary="Create Credential Template Version")
async def create_credential_template_version(template_id: str, request: Request) -> Response:
    """Create a new draft version from an existing Credential Template."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}/new-version")


@credential_template_router.post("/{template_id}/deprecate", response_model=CredentialTemplateResponse, summary="Deprecate Credential Template")
async def deprecate_credential_template(template_id: str, request: Request) -> Response:
    """Deprecate an active Credential Template."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}/deprecate")


@credential_template_router.get("/{template_id}/application-template", summary="Get Linked Application Template")
async def get_credential_template_application_template(template_id: str, request: Request) -> Response:
    """Get the Application Template linked to this Credential Template (if any)."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}/application-template")


# ── Wallet Registry ──────────────────────────────────────────────────

@wallet_registry_router.get("", summary="List Wallet Registry")
async def list_wallet_registry(request: Request) -> Response:
    """List all wallets in the global registry."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, "/v1/wallet-registry")


@wallet_registry_router.get("/{wallet_id}", summary="Get Wallet")
async def get_wallet_registry_entry(wallet_id: str, request: Request) -> Response:
    """Get a wallet registry entry by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/wallet-registry/{wallet_id}")


@wallet_registry_router.get("/{wallet_id}/open-link", summary="Build Wallet Open Link")
async def build_wallet_registry_open_link(wallet_id: str, request: Request) -> Response:
    """Build a wallet-specific open link for a standard OID4VC inner URI."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/wallet-registry/{wallet_id}/open-link")


@wallet_registry_router.get("/resolve/profile", summary="Resolve Wallet Compatibility")
async def resolve_wallet_registry_profile(request: Request) -> Response:
    """Resolve a derived wallet compatibility profile with organization-specific overrides."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, "/v1/wallet-registry/resolve/profile")


@wallet_registry_router.post("", summary="Create Wallet Entry")
async def create_wallet_registry_entry(request: Request) -> Response:
    """Create a new wallet registry entry."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, "/v1/wallet-registry")


@wallet_registry_router.patch("/{wallet_id}", summary="Update Wallet Entry")
async def update_wallet_registry_entry(wallet_id: str, request: Request) -> Response:
    """Update a wallet registry entry."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/wallet-registry/{wallet_id}")


@wallet_registry_router.delete("/{wallet_id}", summary="Delete Wallet Entry")
async def delete_wallet_registry_entry(wallet_id: str, request: Request) -> Response:
    """Delete a wallet registry entry."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/wallet-registry/{wallet_id}")


# ── Compliance Profiles ──────────────────────────────────────────────

# -- Delivery Destinations -----------------------------------------------------

@delivery_destination_router.get("", summary="List Delivery Destinations")
async def list_delivery_destinations(request: Request) -> Response:
    """List system and organization delivery destinations."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, "/v1/delivery-destinations")


@delivery_destination_router.get("/{destination_id}", summary="Get Delivery Destination")
async def get_delivery_destination(destination_id: str, request: Request) -> Response:
    """Get a delivery destination by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/delivery-destinations/{destination_id}")


@delivery_destination_router.post("", summary="Create Delivery Destination")
async def create_delivery_destination(request: Request) -> Response:
    """Create an organization delivery destination."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, "/v1/delivery-destinations")


@delivery_destination_router.patch("/{destination_id}", summary="Update Delivery Destination")
async def update_delivery_destination(destination_id: str, request: Request) -> Response:
    """Update an organization delivery destination."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/delivery-destinations/{destination_id}")


@delivery_destination_router.delete("/{destination_id}", summary="Delete Delivery Destination")
async def delete_delivery_destination(destination_id: str, request: Request) -> Response:
    """Delete an organization delivery destination."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/delivery-destinations/{destination_id}")


@compliance_profile_router.post("", response_model=ComplianceProfileResponse, summary="Create Compliance Profile")
async def create_compliance_profile(body: ComplianceProfileCreate, request: Request) -> Response:
    """Create a new Compliance Profile defining regulatory rules."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, "/v1/compliance-profiles")


@compliance_profile_router.get("", response_model=list[ComplianceProfileResponse], summary="List Compliance Profiles")
async def list_compliance_profiles(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Compliance Profiles for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, "/v1/compliance-profiles")


@compliance_profile_router.get("/{profile_id}", response_model=ComplianceProfileResponse, summary="Get Compliance Profile")
async def get_compliance_profile(profile_id: str, request: Request) -> Response:
    """Get a Compliance Profile by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, f"/v1/compliance-profiles/{profile_id}")


@compliance_profile_router.post("/{profile_id}/activate", response_model=ComplianceProfileResponse, summary="Activate Compliance Profile")
async def activate_compliance_profile(profile_id: str, request: Request) -> Response:
    """Activate a Compliance Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, f"/v1/compliance-profiles/{profile_id}/activate")


@compliance_profile_router.patch("/{profile_id}", response_model=ComplianceProfileResponse, summary="Update Compliance Profile")
async def update_compliance_profile(profile_id: str, body: ComplianceProfileUpdate, request: Request) -> Response:
    """Update a Compliance Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, f"/v1/compliance-profiles/{profile_id}")


@compliance_profile_router.delete("/{profile_id}", summary="Delete Compliance Profile")
async def delete_compliance_profile(profile_id: str, request: Request) -> Response:
    """Delete a Compliance Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, f"/v1/compliance-profiles/{profile_id}")
