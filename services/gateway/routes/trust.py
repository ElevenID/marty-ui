"""Trust Profile, Issuer Entity, Trust Framework, Trust Registry, and API Key routes."""
from __future__ import annotations

from fastapi import APIRouter, Query, Request, Response

from gateway.models import (
    ApiKeyCreatedResponse,
    ApiKeyResponse,
    CreateApiKeyRequest,
    IssuerEntityCreate,
    IssuerEntityResponse,
    IssuerEntityUpdate,
    OrganizationTrustProfileCreate,
    OrganizationTrustProfileResponse,
    OrganizationTrustProfileUpdate,
    TrustedIssuerCreate,
    TrustedIssuerResponse,
    TrustedIssuerUpdate,
    TrustFrameworkResponse,
    TrustProfileCreate,
    TrustProfileResponse,
    TrustProfileUpdate,
    TrustRegistryEntryResponse,
    TrustRegistryStatusResponse,
    TrustRegistrySyncResponse,
)
from gateway.proxy import get_registry, proxy_request

trust_profile_router = APIRouter(prefix="/v1/trust-profiles", tags=["Trust Profiles"])
organization_trust_profile_router = APIRouter(prefix="/v1/organizations/{organization_id}/trust-profiles", tags=["Organization Trust Profiles"])
issuer_entity_router = APIRouter(prefix="/v1/issuer-entities", tags=["Issuer Entities"])
trust_framework_router = APIRouter(prefix="/v1/trust-frameworks", tags=["Trust Frameworks"])
api_key_router = APIRouter(prefix="/v1/api-keys", tags=["API Keys"])
trust_registry_router = APIRouter(prefix="/v1/trust-registry", tags=["Trust Registry"])


# ── Trust Profile ────────────────────────────────────────────────────

@trust_profile_router.post("", response_model=TrustProfileResponse, summary="Create Trust Profile")
async def create_trust_profile(body: TrustProfileCreate, request: Request) -> Response:
    """Create a new Trust Profile for configuring trust relationships."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/trust-profiles")


@trust_profile_router.get("", response_model=list[TrustProfileResponse], summary="List Trust Profiles")
async def list_trust_profiles(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Trust Profiles for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/trust-profiles")


@trust_profile_router.get("/{profile_id}", response_model=TrustProfileResponse, summary="Get Trust Profile")
async def get_trust_profile(profile_id: str, request: Request) -> Response:
    """Get a Trust Profile by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}")


@trust_profile_router.post("/{profile_id}/activate", response_model=TrustProfileResponse, summary="Activate Trust Profile")
async def activate_trust_profile(profile_id: str, request: Request) -> Response:
    """Activate a Trust Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}/activate")


@trust_profile_router.put("/{profile_id}", response_model=TrustProfileResponse, summary="Update Trust Profile")
async def update_trust_profile(profile_id: str, body: TrustProfileUpdate, request: Request) -> Response:
    """Update a Trust Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}")


@trust_profile_router.delete("/{profile_id}", summary="Delete Trust Profile")
async def delete_trust_profile(profile_id: str, request: Request) -> Response:
    """Delete a Trust Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}")


# ── Trusted Issuers (nested under Trust Profile) ─────────────────────

@trust_profile_router.post("/{profile_id}/issuers", response_model=TrustedIssuerResponse, summary="Add Trusted Issuer")
async def add_trusted_issuer(profile_id: str, body: TrustedIssuerCreate, request: Request) -> Response:
    """Add a Trusted Issuer to a Trust Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}/issuers")


@trust_profile_router.get("/{profile_id}/issuers", response_model=list[TrustedIssuerResponse], summary="List Trusted Issuers")
async def list_trusted_issuers(profile_id: str, request: Request) -> Response:
    """List Trusted Issuers for a Trust Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}/issuers")


@trust_profile_router.get("/{profile_id}/issuers/{issuer_id}", response_model=TrustedIssuerResponse, summary="Get Trusted Issuer")
async def get_trusted_issuer(profile_id: str, issuer_id: str, request: Request) -> Response:
    """Get a Trusted Issuer by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}/issuers/{issuer_id}")


@trust_profile_router.put("/{profile_id}/issuers/{issuer_id}", response_model=TrustedIssuerResponse, summary="Update Trusted Issuer")
async def update_trusted_issuer(profile_id: str, issuer_id: str, body: TrustedIssuerUpdate, request: Request) -> Response:
    """Update a Trusted Issuer."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}/issuers/{issuer_id}")


@trust_profile_router.delete("/{profile_id}/issuers/{issuer_id}", summary="Delete Trusted Issuer")
async def delete_trusted_issuer(profile_id: str, issuer_id: str, request: Request) -> Response:
    """Delete a Trusted Issuer from a Trust Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-profiles/{profile_id}/issuers/{issuer_id}")


# ── Organization Trust Profiles ──────────────────────────────────────

@organization_trust_profile_router.post("", response_model=OrganizationTrustProfileResponse, summary="Create Organization Trust Profile")
async def create_organization_trust_profile(
    organization_id: str,
    body: OrganizationTrustProfileCreate,
    request: Request,
) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/organizations/{organization_id}/trust-profiles")


@organization_trust_profile_router.get("", response_model=list[OrganizationTrustProfileResponse], summary="List Organization Trust Profiles")
async def list_organization_trust_profiles(organization_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/organizations/{organization_id}/trust-profiles")


@organization_trust_profile_router.get("/{profile_id}", response_model=OrganizationTrustProfileResponse, summary="Get Organization Trust Profile")
async def get_organization_trust_profile(organization_id: str, profile_id: str, request: Request) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/organizations/{organization_id}/trust-profiles/{profile_id}")


@organization_trust_profile_router.put("/{profile_id}", response_model=OrganizationTrustProfileResponse, summary="Update Organization Trust Profile")
async def update_organization_trust_profile(
    organization_id: str,
    profile_id: str,
    body: OrganizationTrustProfileUpdate,
    request: Request,
) -> Response:
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/organizations/{organization_id}/trust-profiles/{profile_id}")


# ── Issuer Entities ──────────────────────────────────────────────────

@issuer_entity_router.post("", response_model=IssuerEntityResponse, summary="Create Issuer Entity")
async def create_issuer_entity(body: IssuerEntityCreate, request: Request) -> Response:
    """Create a protocol-aligned issuer registry entry."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/issuer-entities")


@issuer_entity_router.get("", response_model=list[IssuerEntityResponse], summary="List Issuer Entities")
async def list_issuer_entities(
    organization_id: str | None = Query(None, description="Optional organization scope"),
    request: Request = None,
) -> Response:
    """List issuer registry entities, optionally scoped to an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/issuer-entities")


@issuer_entity_router.get("/{issuer_entity_id}", response_model=IssuerEntityResponse, summary="Get Issuer Entity")
async def get_issuer_entity(issuer_entity_id: str, request: Request) -> Response:
    """Get a single issuer registry entity."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/issuer-entities/{issuer_entity_id}")


@issuer_entity_router.put("/{issuer_entity_id}", response_model=IssuerEntityResponse, summary="Update Issuer Entity")
async def update_issuer_entity(issuer_entity_id: str, body: IssuerEntityUpdate, request: Request) -> Response:
    """Update an issuer registry entity."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/issuer-entities/{issuer_entity_id}")


@issuer_entity_router.delete("/{issuer_entity_id}", summary="Delete Issuer Entity")
async def delete_issuer_entity(issuer_entity_id: str, request: Request) -> Response:
    """Delete an issuer registry entity."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/issuer-entities/{issuer_entity_id}")


# ── Trust Frameworks ─────────────────────────────────────────────────

@trust_framework_router.get("", response_model=list[TrustFrameworkResponse], summary="List Trust Frameworks")
async def list_trust_frameworks(request: Request) -> Response:
    """List system-managed trust frameworks."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/trust-frameworks")


@trust_framework_router.get("/{framework_id}", response_model=TrustFrameworkResponse, summary="Get Trust Framework")
async def get_trust_framework(framework_id: str, request: Request) -> Response:
    """Get a trust framework by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-frameworks/{framework_id}")


# ── Trust Registry ───────────────────────────────────────────────────

@trust_registry_router.get("/sync", response_model=TrustRegistrySyncResponse, summary="Sync Trust Registry")
async def sync_trust_registry(request: Request) -> Response:
    """Delta-sync trust anchors for wallet offline verification."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/trust-registry/sync")


@trust_registry_router.get("/csca", response_model=list[TrustRegistryEntryResponse], summary="List CSCAs")
async def list_csca_entries(request: Request) -> Response:
    """List current CSCA trust anchors."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/trust-registry/csca")


@trust_registry_router.get("/dsc", response_model=list[TrustRegistryEntryResponse], summary="List DSCs")
async def list_dsc_entries(request: Request) -> Response:
    """List current DSC trust anchors."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/trust-registry/dsc")


@trust_registry_router.get("/csca/{country_code}", response_model=list[TrustRegistryEntryResponse], summary="List CSCAs By Country")
async def list_country_csca_entries(country_code: str, request: Request) -> Response:
    """List current CSCAs for a specific country."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, f"/v1/trust-registry/csca/{country_code}")


@trust_registry_router.get("/status", response_model=TrustRegistryStatusResponse, summary="Trust Registry Status")
async def get_trust_registry_status(request: Request) -> Response:
    """Get trust registry health and sequence metadata."""
    registry = get_registry()
    service_url = registry.get_service_url("trust-profiles")
    return await proxy_request(request, service_url, "/v1/trust-registry/status")


# ── API Keys ─────────────────────────────────────────────────────────

@api_key_router.get("", response_model=list[ApiKeyResponse], summary="List API Keys")
async def list_api_keys(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List API keys for an organization using the protocol top-level route."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{organization_id}/api-keys")


@api_key_router.post("", response_model=ApiKeyCreatedResponse, summary="Create API Key")
async def create_api_key(
    body: CreateApiKeyRequest,
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """Create an API key for an organization using the protocol top-level route."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{organization_id}/api-keys")


@api_key_router.delete("/{key_id}", summary="Delete API Key")
async def delete_api_key(
    key_id: str,
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """Delete or revoke an API key for an organization using the protocol top-level route."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{organization_id}/api-keys/{key_id}")
