"""
Wallet Compatibility Service

Manages wallet profiles and compatibility detection for OID4VCI/OID4VP.

Different wallets support different:
- Credential formats (jwt_vc_json, vc+sd-jwt, ldp_vc, etc.)
- Cryptographic algorithms (ES256, EdDSA, etc.)
- Transport methods (QR codes, deep links, NFC)
- Protocol quirks and extensions

This service helps adapt issuer/verifier behavior based on wallet capabilities.

Port: 8015
"""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "wallet-service"
SERVICE_PORT = int(os.environ.get("WALLET_SERVICE_PORT", "8015"))


# =============================================================================
# Domain Layer
# =============================================================================

class WalletVendor(str, Enum):
    """Known wallet vendors."""
    GENERIC = "generic"
    SPRIND_FUNKE = "sprind_funke"
    EUDI_WALLET = "eudi_wallet"
    MICROSOFT_AUTHENTICATOR = "microsoft_authenticator"
    GOOGLE_WALLET = "google_wallet"
    APPLE_WALLET = "apple_wallet"
    ARIES = "aries"
    TRINSIC = "trinsic"
    DOCK = "dock"
    SPHEREON = "sphereon"


class CredentialFormat(str, Enum):
    """Credential format identifiers."""
    JWT_VC_JSON = "jwt_vc_json"
    JWT_VC_JSON_LD = "jwt_vc_json-ld"
    VC_SD_JWT = "vc+sd-jwt"
    LDP_VC = "ldp_vc"
    MSO_MDOC = "mso_mdoc"


class CryptoAlgorithm(str, Enum):
    """Cryptographic algorithms."""
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"
    EDDSA = "EdDSA"
    RS256 = "RS256"


@dataclass
class WalletProfile:
    """
    Wallet profile defining capabilities and quirks.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    
    # Identification
    vendor: WalletVendor = WalletVendor.GENERIC
    wallet_name: str = ""
    version: str | None = None
    user_agent_pattern: str | None = None  # Regex to match User-Agent
    
    # Supported capabilities
    supported_formats: list[CredentialFormat] = field(default_factory=list)
    supported_algorithms: list[CryptoAlgorithm] = field(default_factory=list)
    supported_proof_types: list[str] = field(default_factory=list)
    
    # Transport preferences
    prefers_deep_links: bool = False
    supports_nfc: bool = False
    supports_ble: bool = False
    
    # Protocol quirks and workarounds
    quirks: dict[str, Any] = field(default_factory=dict)
    
    # Feature flags
    supports_batch_issuance: bool = False
    supports_deferred_issuance: bool = False
    supports_key_attestation: bool = False
    
    # Metadata
    is_active: bool = True
    notes: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# Pre-defined Wallet Profiles
# =============================================================================

def get_default_wallet_profiles() -> list[WalletProfile]:
    """
    Get default wallet profiles for known wallets.
    
    These serve as templates that can be customized per organization.
    """
    return [
        # Generic wallet - broadest compatibility
        WalletProfile(
            vendor=WalletVendor.GENERIC,
            wallet_name="Generic OID4VCI Wallet",
            supported_formats=[
                CredentialFormat.JWT_VC_JSON,
                CredentialFormat.VC_SD_JWT,
            ],
            supported_algorithms=[
                CryptoAlgorithm.ES256,
                CryptoAlgorithm.EDDSA,
            ],
            supported_proof_types=["jwt"],
            notes="Default profile for unknown wallets"
        ),
        
        # SPRIND Funke Wallet (German pilot)
        WalletProfile(
            vendor=WalletVendor.SPRIND_FUNKE,
            wallet_name="SPRIND Funke Wallet",
            supported_formats=[
                CredentialFormat.VC_SD_JWT,
                CredentialFormat.MSO_MDOC,
            ],
            supported_algorithms=[
                CryptoAlgorithm.ES256,
            ],
            supported_proof_types=["jwt"],
            supports_key_attestation=True,
            quirks={
                "requires_issuer_state": True,
                "expects_c_nonce_in_offer": False,
            },
            notes="German EUDI Wallet pilot implementation"
        ),
        
        # EUDI Wallet Reference Implementation
        WalletProfile(
            vendor=WalletVendor.EUDI_WALLET,
            wallet_name="EUDI Wallet Reference",
            supported_formats=[
                CredentialFormat.VC_SD_JWT,
                CredentialFormat.MSO_MDOC,
            ],
            supported_algorithms=[
                CryptoAlgorithm.ES256,
            ],
            supported_proof_types=["jwt"],
            supports_batch_issuance=True,
            supports_key_attestation=True,
            quirks={
                "strict_par_validation": True,
                "requires_dpop": False,
            },
            notes="EU Digital Identity Wallet ARF reference implementation"
        ),
        
        # Microsoft Authenticator
        WalletProfile(
            vendor=WalletVendor.MICROSOFT_AUTHENTICATOR,
            wallet_name="Microsoft Authenticator",
            supported_formats=[
                CredentialFormat.JWT_VC_JSON,
            ],
            supported_algorithms=[
                CryptoAlgorithm.ES256,
            ],
            supported_proof_types=["jwt"],
            prefers_deep_links=True,
            quirks={
                "custom_manifest_format": True,
                "requires_linked_domain": True,
            },
            notes="Microsoft Entra Verified ID"
        ),
        
        # Aries Framework wallets
        WalletProfile(
            vendor=WalletVendor.ARIES,
            wallet_name="Aries Framework Wallet",
            supported_formats=[
                CredentialFormat.JWT_VC_JSON_LD,
                CredentialFormat.LDP_VC,
            ],
            supported_algorithms=[
                CryptoAlgorithm.EDDSA,
                CryptoAlgorithm.ES256,
            ],
            supported_proof_types=["jwt", "ldp"],
            quirks={
                "prefers_json_ld": True,
            },
            notes="Hyperledger Aries-based wallets"
        ),
    ]


# =============================================================================
# Application Layer
# =============================================================================

class InMemoryWalletRepository:
    """In-memory repository for development."""
    
    def __init__(self):
        self._profiles: dict[str, WalletProfile] = {}
        # Pre-populate with defaults
        for profile in get_default_wallet_profiles():
            self._profiles[profile.id] = profile
    
    async def save(self, profile: WalletProfile) -> None:
        self._profiles[profile.id] = profile
    
    async def get_by_id(self, profile_id: str) -> WalletProfile | None:
        return self._profiles.get(profile_id)
    
    async def get_by_vendor(self, vendor: WalletVendor) -> WalletProfile | None:
        for profile in self._profiles.values():
            if profile.vendor == vendor:
                return profile
        return None
    
    async def list_by_organization(
        self,
        org_id: str,
        active_only: bool = True,
    ) -> list[WalletProfile]:
        profiles = [p for p in self._profiles.values() if p.organization_id == org_id or p.organization_id == ""]
        if active_only:
            profiles = [p for p in profiles if p.is_active]
        return profiles
    
    async def list_all(self) -> list[WalletProfile]:
        return list(self._profiles.values())
    
    async def delete(self, profile_id: str) -> None:
        self._profiles.pop(profile_id, None)


def detect_wallet_from_user_agent(user_agent: str) -> WalletVendor:
    """
    Detect wallet vendor from User-Agent string.
    
    This is a heuristic approach - wallets should ideally identify themselves
    via client metadata or attestation.
    """
    ua_lower = user_agent.lower()
    
    if "funke" in ua_lower or "sprind" in ua_lower:
        return WalletVendor.SPRIND_FUNKE
    elif "eudi" in ua_lower:
        return WalletVendor.EUDI_WALLET
    elif "microsoft authenticator" in ua_lower or "entra" in ua_lower:
        return WalletVendor.MICROSOFT_AUTHENTICATOR
    elif "aries" in ua_lower or "hyperledger" in ua_lower:
        return WalletVendor.ARIES
    elif "trinsic" in ua_lower:
        return WalletVendor.TRINSIC
    elif "sphereon" in ua_lower:
        return WalletVendor.SPHEREON
    
    return WalletVendor.GENERIC


def filter_formats_by_wallet(
    available_formats: list[str],
    wallet_profile: WalletProfile,
) -> list[str]:
    """
    Filter credential formats based on wallet capabilities.
    
    Returns the intersection of available formats and wallet-supported formats,
    ordered by wallet preference.
    """
    if not wallet_profile.supported_formats:
        # If wallet profile doesn't specify, assume all are supported
        return available_formats
    
    supported_format_values = [f.value for f in wallet_profile.supported_formats]
    filtered = [fmt for fmt in available_formats if fmt in supported_format_values]
    
    return filtered


# =============================================================================
# HTTP Adapter - Request/Response Models
# =============================================================================

class WalletProfileResponse(BaseModel):
    id: str
    organization_id: str
    vendor: str
    wallet_name: str
    version: str | None
    supported_formats: list[str]
    supported_algorithms: list[str]
    supported_proof_types: list[str]
    prefers_deep_links: bool
    supports_batch_issuance: bool
    supports_deferred_issuance: bool
    quirks: dict
    is_active: bool
    created_at: str
    updated_at: str


class CreateWalletProfileRequest(BaseModel):
    organization_id: str
    vendor: str = "generic"
    wallet_name: str
    version: str | None = None
    supported_formats: list[str] = []
    supported_algorithms: list[str] = []
    supported_proof_types: list[str] = ["jwt"]
    prefers_deep_links: bool = False
    supports_batch_issuance: bool = False
    supports_deferred_issuance: bool = False
    quirks: dict = {}


class DetectWalletRequest(BaseModel):
    user_agent: str
    client_metadata: dict | None = None


class DetectWalletResponse(BaseModel):
    detected_vendor: str
    profile_id: str | None
    supported_formats: list[str]
    recommended_format: str


class FilterFormatsRequest(BaseModel):
    available_formats: list[str]
    wallet_profile_id: str | None = None
    user_agent: str | None = None


class FilterFormatsResponse(BaseModel):
    filtered_formats: list[str]
    wallet_vendor: str
    reasoning: str


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/wallets", tags=["wallets"])

_repo: InMemoryWalletRepository | None = None


def get_repo() -> InMemoryWalletRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


@router.get("/profiles", response_model=list[WalletProfileResponse])
async def list_wallet_profiles(
    organization_id: str | None = Query(None),
    active_only: bool = Query(True),
    repo: InMemoryWalletRepository = Depends(get_repo),
) -> list[WalletProfileResponse]:
    """List wallet profiles."""
    if organization_id:
        profiles = await repo.list_by_organization(organization_id, active_only)
    else:
        profiles = await repo.list_all()
        if active_only:
            profiles = [p for p in profiles if p.is_active]
    
    return [_to_response(p) for p in profiles]


@router.get("/profiles/{profile_id}", response_model=WalletProfileResponse)
async def get_wallet_profile(
    profile_id: str,
    repo: InMemoryWalletRepository = Depends(get_repo),
) -> WalletProfileResponse:
    """Get a wallet profile by ID."""
    profile = await repo.get_by_id(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Wallet profile not found")
    return _to_response(profile)


@router.post("/profiles", response_model=WalletProfileResponse)
async def create_wallet_profile(
    request: CreateWalletProfileRequest,
    repo: InMemoryWalletRepository = Depends(get_repo),
) -> WalletProfileResponse:
    """Create a custom wallet profile."""
    profile = WalletProfile(
        organization_id=request.organization_id,
        vendor=WalletVendor(request.vendor),
        wallet_name=request.wallet_name,
        version=request.version,
        supported_formats=[CredentialFormat(f) for f in request.supported_formats],
        supported_algorithms=[CryptoAlgorithm(a) for a in request.supported_algorithms],
        supported_proof_types=request.supported_proof_types,
        prefers_deep_links=request.prefers_deep_links,
        supports_batch_issuance=request.supports_batch_issuance,
        supports_deferred_issuance=request.supports_deferred_issuance,
        quirks=request.quirks,
    )
    
    await repo.save(profile)
    logger.info(f"Created wallet profile: {profile.id} ({profile.wallet_name})")
    return _to_response(profile)


@router.post("/detect", response_model=DetectWalletResponse)
async def detect_wallet(
    request: DetectWalletRequest,
    repo: InMemoryWalletRepository = Depends(get_repo),
) -> DetectWalletResponse:
    """
    Detect wallet type from User-Agent or client metadata.
    Returns appropriate profile and supported formats.
    """
    vendor = detect_wallet_from_user_agent(request.user_agent)
    profile = await repo.get_by_vendor(vendor)
    
    if not profile:
        # Fall back to generic
        profile = await repo.get_by_vendor(WalletVendor.GENERIC)
    
    supported_formats = [f.value for f in profile.supported_formats] if profile else []
    recommended_format = supported_formats[0] if supported_formats else "jwt_vc_json"
    
    return DetectWalletResponse(
        detected_vendor=vendor.value,
        profile_id=profile.id if profile else None,
        supported_formats=supported_formats,
        recommended_format=recommended_format,
    )


@router.post("/filter-formats", response_model=FilterFormatsResponse)
async def filter_credential_formats(
    request: FilterFormatsRequest,
    repo: InMemoryWalletRepository = Depends(get_repo),
) -> FilterFormatsResponse:
    """
    Filter available credential formats based on wallet capabilities.
    Used during issuer metadata generation and credential offer creation.
    """
    profile = None
    
    if request.wallet_profile_id:
        profile = await repo.get_by_id(request.wallet_profile_id)
    elif request.user_agent:
        vendor = detect_wallet_from_user_agent(request.user_agent)
        profile = await repo.get_by_vendor(vendor)
    
    if not profile:
        profile = await repo.get_by_vendor(WalletVendor.GENERIC)
    
    filtered = filter_formats_by_wallet(request.available_formats, profile)
    
    reasoning = (
        f"Filtered {len(request.available_formats)} formats to {len(filtered)} "
        f"based on {profile.wallet_name} capabilities"
    )
    
    return FilterFormatsResponse(
        filtered_formats=filtered,
        wallet_vendor=profile.vendor.value,
        reasoning=reasoning,
    )


def _to_response(profile: WalletProfile) -> WalletProfileResponse:
    return WalletProfileResponse(
        id=profile.id,
        organization_id=profile.organization_id,
        vendor=profile.vendor.value,
        wallet_name=profile.wallet_name,
        version=profile.version,
        supported_formats=[f.value for f in profile.supported_formats],
        supported_algorithms=[a.value for a in profile.supported_algorithms],
        supported_proof_types=profile.supported_proof_types,
        prefers_deep_links=profile.prefers_deep_links,
        supports_batch_issuance=profile.supports_batch_issuance,
        supports_deferred_issuance=profile.supports_deferred_issuance,
        quirks=profile.quirks,
        is_active=profile.is_active,
        created_at=profile.created_at.isoformat(),
        updated_at=profile.updated_at.isoformat(),
    )


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo
    logger.info(f"Starting {SERVICE_NAME}...")
    _repo = InMemoryWalletRepository()
    logger.info(f"Loaded {len(await _repo.list_all())} default wallet profiles")
    yield
    logger.info(f"Shutting down {SERVICE_NAME}...")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Wallet Compatibility Service",
        description="Manages wallet profiles and compatibility detection for OID4VCI/OID4VP",
        version="1.0.0",
        lifespan=lifespan,
    )
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    app.include_router(router)
    
    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": SERVICE_NAME}
    
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("wallet.main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
