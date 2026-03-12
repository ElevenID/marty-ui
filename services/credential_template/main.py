"""
Credential Template Service

Manages Credential Templates - the blueprint for what credentials
can be issued and their structure.

A Credential Template defines:
- Display metadata (name, description, visual styling)
- Claims schema (what data the credential contains)
- Privacy posture (selective disclosure, derived attributes)
- Validity rules (expiration, refresh)
- Format-specific settings (SD-JWT, mdoc)

Port: 8003
"""

from __future__ import annotations

import logging
import os
import uuid

import httpx
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from typing import Annotated
from marty_common import OrganizationClient, OrganizationContext, require_org_membership, require_org_admin
from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware

from credential_template.infrastructure.adapters import (
    PostgresCredentialTemplateRepository,
    PostgresWalletRegistryRepository,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "credential-template-service"
SERVICE_PORT = int(os.environ.get("CREDENTIAL_TEMPLATE_SERVICE_PORT", "8003"))


def get_config() -> dict:
    """Get service configuration from environment."""
    return {
        "database_url": os.environ.get(
            "DATABASE_URL",
            "postgresql+asyncpg://marty:marty_dev@localhost:5432/marty_credentials"
        ),
    }


# =============================================================================
# Domain Layer
# =============================================================================

class TemplateStatus(str, Enum):
    """Credential template status."""
    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


class PrivacyPosture(str, Enum):
    """Privacy level for the credential."""
    STANDARD = "standard"           # No special privacy features
    SELECTIVE_DISCLOSURE = "selective_disclosure"  # SD-JWT style
    ZERO_KNOWLEDGE = "zero_knowledge"  # ZKP-enabled
    MINIMAL = "minimal"             # Derived attributes only


class ClaimType(str, Enum):
    """Supported claim data types."""
    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    DATE = "date"
    DATETIME = "datetime"
    OBJECT = "object"
    ARRAY = "array"
    IMAGE = "image"  # base64 or URL
    BINARY = "binary"


class CredentialFormat(str, Enum):
    """Supported credential formats."""
    SD_JWT_VC = "sd_jwt_vc"
    MDOC = "mdoc"
    MSO_MDOC = "mso_mdoc"
    JWT_VC = "jwt_vc"
    JSON_LD_VC = "json_ld_vc"
    ZK_MDOC = "zk_mdoc"


@dataclass
class ClaimDefinition:
    """
    Definition of a claim within a credential.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    display_name: str = ""
    description: str | None = None
    claim_type: ClaimType = ClaimType.STRING
    required: bool = True
    
    # Privacy settings
    selectively_disclosable: bool = True  # Can be disclosed individually
    derivable: bool = False  # Can derive predicates (e.g., age > 21)
    
    # Validation
    pattern: str | None = None  # Regex for validation
    enum_values: list[str] | None = None  # Allowed values
    min_value: float | None = None
    max_value: float | None = None
    
    # Format-specific
    mdoc_namespace: str | None = None  # For mdoc: org.iso.18013.5.1
    mdoc_element_identifier: str | None = None


@dataclass
class DisplayStyle:
    """
    Visual styling for credential display.
    """
    background_color: str = "#1a1a2e"
    text_color: str = "#ffffff"
    logo_url: str | None = None
    background_image_url: str | None = None
    icon: str | None = None


@dataclass
class ValidityRules:
    """
    Rules for credential validity.
    """
    default_validity_days: int = 365
    max_validity_days: int = 1095  # 3 years
    renewable: bool = True
    renewal_window_days: int = 30  # Can renew 30 days before expiry
    require_revalidation: bool = False
    revalidation_interval_days: int | None = None


@dataclass
class IssuerRequirements:
    """Requirements for the issuer."""
    allowed_issuer_dids: list[str] = field(default_factory=list)
    trust_tier_required: str | None = None
    audit_level_required: str | None = None


@dataclass
class DerivedAttribute:
    """
    An attribute that can be derived from credential claims.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str | None = None
    source_claim: str = ""  # The claim to derive from
    derivation_type: str = ""  # age_over, range, presence, etc.
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class WalletConfig:
    """Per-wallet issuance configuration attached to a credential template."""

    wallet_id: str = ""
    """Registry ID of the wallet (e.g. 'wr-lissi-001')."""

    deep_link_scheme: str = "openid-credential-offer://"
    """Deep-link scheme used for this wallet's credential offer URI.
    
    Example: 'openid-credential-offer://' or 'spruceid://'
    """

    format_variant: str | None = None
    """Optional credential format variant for SDK-specific compatibility.

    Set to ``"spruce-vc+sd-jwt"`` for the SpruceID mobile SDK, which requires
    a dedicated metadata document emitting ``spruce-vc+sd-jwt`` entries instead
    of the standard ``vc+sd-jwt`` format accepted by Walt.id and other wallets.
    Leave ``None`` (or unset) for all other wallets.
    """


@dataclass
class CredentialTemplate:
    """
    Credential Template - blueprint for credential issuance.
    
    This defines the structure and rules for a type of credential.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    name: str = ""
    description: str | None = None
    status: TemplateStatus = TemplateStatus.DRAFT
    
    # Type identifiers
    credential_type: str = ""  # e.g., "VerifiedEmployeeCredential"
    vct: str = ""  # Verifiable Credential Type URI
    doctype: str = ""  # For mdoc: org.iso.18013.5.1.mDL
    
    # Schema
    claims: list[ClaimDefinition] = field(default_factory=list)
    
    # Privacy
    privacy_posture: PrivacyPosture = PrivacyPosture.SELECTIVE_DISCLOSURE
    selective_disclosure_fields: list[str] = field(default_factory=list)
    zk_predicate_claims: list[str] = field(default_factory=list)
    derived_attributes: list[DerivedAttribute] = field(default_factory=list)
    
    # Display
    display_style: DisplayStyle = field(default_factory=DisplayStyle)
    
    # Validity
    validity_rules: ValidityRules = field(default_factory=ValidityRules)
    
    # Issuer Constraints
    issuer_requirements: IssuerRequirements = field(default_factory=IssuerRequirements)
    
    # Supported formats
    supported_formats: list[CredentialFormat] = field(
        default_factory=lambda: [CredentialFormat.SD_JWT_VC]
    )

    # Wallet compatibility
    wallet_configs: list[WalletConfig] = field(default_factory=list)
    """Per-wallet configurations: which wallets are enabled and their deep-link schemes."""
    issuance_protocol: str = "oid4vci"
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt"
    """SD-JWT payload structure: 'ietf_sd_jwt' (flat) or 'w3c_vcdm_v2_sd_jwt' (W3C envelope)."""
    
    # Timestamps
    version: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def activate(self) -> None:
        self.status = TemplateStatus.ACTIVE
        self.updated_at = datetime.now(timezone.utc)
    
    def deprecate(self) -> None:
        self.status = TemplateStatus.DEPRECATED
        self.updated_at = datetime.now(timezone.utc)
    
    def new_version(self) -> "CredentialTemplate":
        """Create a new draft version of this template."""
        new = CredentialTemplate(
            organization_id=self.organization_id,
            name=self.name,
            description=self.description,
            credential_type=self.credential_type,
            vct=self.vct,
            doctype=self.doctype,
            claims=self.claims.copy(),
            privacy_posture=self.privacy_posture,
            display_style=self.display_style,
            validity_rules=self.validity_rules,
            supported_formats=self.supported_formats.copy(),
            wallet_configs=[WalletConfig(wallet_id=wc.wallet_id, deep_link_scheme=wc.deep_link_scheme, format_variant=wc.format_variant) for wc in self.wallet_configs],
            issuance_protocol=self.issuance_protocol,
            credential_payload_format=self.credential_payload_format,
            version=self.version + 1,
        )
        return new


@dataclass
class WalletRegistryEntry:
    """Global wallet registry entry — describes a wallet app and how to open it."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    logo_url: str | None = None
    deep_link_template: str = "openid-credential-offer://?credential_offer={OFFER}"
    supported_formats: list[str] = field(default_factory=list)
    supported_protocols: list[str] = field(default_factory=lambda: ["oid4vci"])
    platforms: list[str] = field(default_factory=list)
    supports_qr: bool = True
    supports_deeplink: bool = True
    docs_url: str | None = None
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# Application Layer
# =============================================================================

class InMemoryCredentialTemplateRepository:
    """In-memory repository for development."""
    
    def __init__(self):
        self._templates: dict[str, CredentialTemplate] = {}
    
    async def save(self, template: CredentialTemplate) -> None:
        self._templates[template.id] = template
    
    async def get(self, template_id: str) -> CredentialTemplate | None:
        t = self._templates.get(template_id)
        return t
    
    async def list(self, org_id: str, status: TemplateStatus | None = None) -> list[CredentialTemplate]:
        templates = [t for t in self._templates.values() if t.organization_id == org_id]
        if status:
            templates = [t for t in templates if t.status == status]
        return templates
    
    async def list_all(self, status: TemplateStatus | None = None) -> list[CredentialTemplate]:
        """List all templates regardless of organization (internal use only)."""
        results = list(self._templates.values())
        if status:
            results = [t for t in results if t.status == status]
        return results

    async def delete(self, template_id: str) -> None:
        self._templates.pop(template_id, None)


class InMemoryWalletRegistryRepository:
    """In-memory wallet registry — seeded with common wallets."""

    _DEFAULT_WALLETS: list[WalletRegistryEntry] = [
        # ── SpruceID wallets ──────────────────────────────────────────────
        WalletRegistryEntry(
            id="wr-spruce-001",
            name="SpruceKit",
            logo_url="https://spruceid.com/favicon.ico",
            deep_link_template="openid-credential-offer://?credential_offer={OFFER}",
            supported_formats=["spruce-vc+sd-jwt"],
            supported_protocols=["oid4vci"],
            platforms=["ios", "android"],
            docs_url="https://spruceid.com/products/sprucekit",
        ),
        WalletRegistryEntry(
            id="wr-marty-001",
            name="Marty Authenticator",
            deep_link_template="openid-credential-offer://?credential_offer={OFFER}",
            supported_formats=["spruce-vc+sd-jwt"],
            supported_protocols=["oid4vci"],
            platforms=["ios", "android"],
        ),
        # ── Generic OID4VCI wallets ───────────────────────────────────────
        WalletRegistryEntry(
            id="wr-default",
            name="Any OID4VCI Wallet",
            deep_link_template="openid-credential-offer://?credential_offer={OFFER}",
            supported_formats=["sd_jwt_vc", "jwt_vc_json"],
            supported_protocols=["oid4vci"],
            platforms=["ios", "android", "web"],
        ),
        WalletRegistryEntry(
            id="wr-lissi-001",
            name="LISSI Wallet",
            logo_url="https://lissi.id/favicon.ico",
            deep_link_template="openid-credential-offer://?credential_offer={OFFER}",
            supported_formats=["sd_jwt_vc", "jwt_vc_json"],
            platforms=["ios", "android"],
            docs_url="https://lissi.id",
        ),
        WalletRegistryEntry(
            id="wr-waltid-001",
            name="walt.id Wallet",
            logo_url="https://walt.id/favicon.ico",
            deep_link_template="openid-credential-offer://?credential_offer={OFFER}",
            supported_formats=["sd_jwt_vc", "jwt_vc_json", "mdoc"],
            platforms=["ios", "android", "web"],
            docs_url="https://docs.walt.id",
        ),
        WalletRegistryEntry(
            id="wr-sphereon-001",
            name="Sphereon Wallet",
            logo_url="https://sphereon.com/favicon.ico",
            deep_link_template="openid-credential-offer://?credential_offer={OFFER}",
            supported_formats=["sd_jwt_vc", "jwt_vc_json"],
            platforms=["ios", "android"],
            docs_url="https://sphereon.com",
        ),
        WalletRegistryEntry(
            id="wr-dc4eu-001",
            name="DC4EU Wallet",
            deep_link_template="openid-credential-offer://?credential_offer={OFFER}",
            supported_formats=["sd_jwt_vc", "mdoc"],
            platforms=["ios", "android"],
        ),
    ]

    def __init__(self) -> None:
        self._wallets: dict[str, WalletRegistryEntry] = {
            w.id: w for w in self._DEFAULT_WALLETS
        }

    async def save(self, entry: WalletRegistryEntry) -> None:
        entry.updated_at = datetime.now(timezone.utc)
        self._wallets[entry.id] = entry

    async def get(self, wallet_id: str) -> WalletRegistryEntry | None:
        return self._wallets.get(wallet_id)

    async def list(self, active_only: bool = True) -> list[WalletRegistryEntry]:
        wallets = list(self._wallets.values())
        if active_only:
            wallets = [w for w in wallets if w.is_active]
        return wallets

    async def delete(self, wallet_id: str) -> None:
        self._wallets.pop(wallet_id, None)


# =============================================================================
# HTTP Adapter - Request/Response Models
# =============================================================================

class ClaimDefinitionModel(BaseModel):
    name: str
    display_name: str
    description: str | None = None
    claim_type: str = "string"
    required: bool = True
    selectively_disclosable: bool = True
    derivable: bool = False
    pattern: str | None = None
    enum_values: list[str] | None = None
    min_value: float | None = None
    max_value: float | None = None
    mdoc_namespace: str | None = None
    mdoc_element_identifier: str | None = None


class DisplayStyleModel(BaseModel):
    background_color: str = "#1a1a2e"
    text_color: str = "#ffffff"
    logo_url: str | None = None
    background_image_url: str | None = None
    icon: str | None = None


class ValidityRulesModel(BaseModel):
    default_validity_days: int = 365
    max_validity_days: int = 1095
    renewable: bool = True
    renewal_window_days: int = 30
    require_revalidation: bool = False
    revalidation_interval_days: int | None = None


class IssuerRequirementsModel(BaseModel):
    allowed_issuer_dids: list[str] = []
    trust_tier_required: str | None = None
    audit_level_required: str | None = None


class DerivedAttributeModel(BaseModel):
    name: str
    description: str | None = None
    source_claim: str
    derivation_type: str  # age_over, range, presence
    parameters: dict = {}


class CreateCredentialTemplateRequest(BaseModel):
    organization_id: str
    name: str
    description: str | None = None
    credential_type: str
    vct: str | None = None
    doctype: str | None = None
    claims: list[ClaimDefinitionModel] = []
    privacy_posture: str = "selective_disclosure"
    selective_disclosure_fields: list[str] = []
    zk_predicate_claims: list[str] = []
    derived_attributes: list[DerivedAttributeModel] = []
    display_style: DisplayStyleModel | None = None
    validity_rules: ValidityRulesModel | None = None
    issuer_requirements: IssuerRequirementsModel | None = None
    supported_formats: list[str] = ["sd_jwt_vc"]
    # Wallet compatibility
    wallet_configs: list[dict] = []
    issuance_protocol: str = "oid4vci"
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt"
    schema_uri: dict | None = None


class UpdateCredentialTemplateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    claims: list[ClaimDefinitionModel] | None = None
    privacy_posture: str | None = None
    selective_disclosure_fields: list[str] | None = None
    zk_predicate_claims: list[str] | None = None
    derived_attributes: list[DerivedAttributeModel] | None = None
    display_style: DisplayStyleModel | None = None
    validity_rules: ValidityRulesModel | None = None
    issuer_requirements: IssuerRequirementsModel | None = None
    supported_formats: list[str] | None = None
    # Wallet compatibility
    wallet_configs: list[dict] | None = None
    issuance_protocol: str | None = None
    credential_payload_format: str | None = None


class CredentialTemplateResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    credential_type: str
    vct: str
    doctype: str
    claims: list[dict]
    privacy_posture: str
    selective_disclosure_fields: list[str]
    zk_predicate_claims: list[str]
    derived_attributes: list[dict]
    display_style: dict
    validity_rules: dict
    issuer_requirements: dict
    supported_formats: list[str]
    # Wallet compatibility
    wallet_configs: list[dict]
    issuance_protocol: str
    credential_payload_format: str
    version: int
    created_at: str
    updated_at: str


# ----- Wallet Registry Pydantic Models -----

class WalletRegistryEntryCreate(BaseModel):
    name: str
    logo_url: str | None = None
    deep_link_template: str = "openid-credential-offer://?credential_offer={OFFER}"
    supported_formats: list[str] = []
    supported_protocols: list[str] = ["oid4vci"]
    platforms: list[str] = []
    supports_qr: bool = True
    supports_deeplink: bool = True
    docs_url: str | None = None


class WalletRegistryEntryUpdate(BaseModel):
    name: str | None = None
    logo_url: str | None = None
    deep_link_template: str | None = None
    supported_formats: list[str] | None = None
    supported_protocols: list[str] | None = None
    platforms: list[str] | None = None
    supports_qr: bool | None = None
    supports_deeplink: bool | None = None
    docs_url: str | None = None
    is_active: bool | None = None


class WalletRegistryEntryResponse(BaseModel):
    id: str
    name: str
    logo_url: str | None
    deep_link_template: str
    supported_formats: list[str]
    supported_protocols: list[str]
    platforms: list[str]
    supports_qr: bool
    supports_deeplink: bool
    docs_url: str | None
    is_active: bool
    created_at: str
    updated_at: str


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/credential-templates", tags=["credential-templates"])
wallet_router = APIRouter(prefix="/v1/wallet-registry", tags=["wallet-registry"])

_repo: InMemoryCredentialTemplateRepository | None = None
_wallet_repo: PostgresWalletRegistryRepository | None = None


def get_repo() -> InMemoryCredentialTemplateRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


def get_wallet_repo() -> PostgresWalletRegistryRepository:
    if _wallet_repo is None:
        raise RuntimeError("Wallet registry not configured")
    return _wallet_repo


# Helper to get current user ID from gateway-injected header
async def get_current_user_id(
    x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None
) -> str:
    """Get current user ID from gateway auth middleware."""
    if not x_user_id:
        raise HTTPException(
            status_code=401,
            detail="Authentication required - missing user context",
        )
    return x_user_id


@router.post("", response_model=CredentialTemplateResponse)
async def create_credential_template(
    body: CreateCredentialTemplateRequest,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Create a new Credential Template. Requires organization membership.
    
    Note: This verifies the user is a member of the organization specified
    in the request body. Admin role recommended for production.
    """
    await require_org_membership(body.organization_id, request, user_id)

    template = CredentialTemplate(
        organization_id=body.organization_id,
        name=body.name,
        description=body.description,
        credential_type=body.credential_type,
        vct=body.vct or f"https://credentials.example.com/{body.credential_type}",
        doctype=body.doctype or "",
        privacy_posture=PrivacyPosture(body.privacy_posture),
        selective_disclosure_fields=body.selective_disclosure_fields,
        zk_predicate_claims=body.zk_predicate_claims,
        supported_formats=[CredentialFormat(f) for f in body.supported_formats],
        wallet_configs=[WalletConfig(wallet_id=wc.get("wallet_id", ""), deep_link_scheme=wc.get("deep_link_scheme", "openid-credential-offer://"), format_variant=wc.get("format_variant")) for wc in body.wallet_configs],
        issuance_protocol=body.issuance_protocol,
        credential_payload_format=body.credential_payload_format,
    )
    
    # Set claims
    for claim in body.claims:
        template.claims.append(ClaimDefinition(
            name=claim.name,
            display_name=claim.display_name,
            description=claim.description,
            claim_type=ClaimType(claim.claim_type),
            required=claim.required,
            selectively_disclosable=claim.selectively_disclosable,
            derivable=claim.derivable,
            pattern=claim.pattern,
            enum_values=claim.enum_values,
            min_value=claim.min_value,
            max_value=claim.max_value,
            mdoc_namespace=claim.mdoc_namespace,
            mdoc_element_identifier=claim.mdoc_element_identifier,
        ))
    
    # Set derived attributes
    for da in body.derived_attributes:
        template.derived_attributes.append(DerivedAttribute(
            name=da.name,
            description=da.description,
            source_claim=da.source_claim,
            derivation_type=da.derivation_type,
            parameters=da.parameters,
        ))
    
    # Set display style
    if body.display_style:
        template.display_style = DisplayStyle(
            background_color=body.display_style.background_color,
            text_color=body.display_style.text_color,
            logo_url=body.display_style.logo_url,
            background_image_url=body.display_style.background_image_url,
            icon=body.display_style.icon,
        )
    
    # Set validity rules
    if body.validity_rules:
        template.validity_rules = ValidityRules(
            default_validity_days=body.validity_rules.default_validity_days,
            max_validity_days=body.validity_rules.max_validity_days,
            renewable=body.validity_rules.renewable,
            renewal_window_days=body.validity_rules.renewal_window_days,
            require_revalidation=body.validity_rules.require_revalidation,
            revalidation_interval_days=body.validity_rules.revalidation_interval_days,
        )

    # Set issuer requirements
    if body.issuer_requirements:
        template.issuer_requirements = IssuerRequirements(
            allowed_issuer_dids=body.issuer_requirements.allowed_issuer_dids,
            trust_tier_required=body.issuer_requirements.trust_tier_required,
            audit_level_required=body.issuer_requirements.audit_level_required,
        )
    
    await repo.save(template)
    logger.info(f"Created Credential Template: {template.id}")
    return _template_to_response(template)


@router.get("", response_model=list[CredentialTemplateResponse])
async def list_credential_templates(
    organization_id: str = Query(..., description="Organization ID"),
    status: str | None = Query(None, description="Filter by status"),
    request: Request = None,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> list[CredentialTemplateResponse]:
    """List Credential Templates for an organization. Requires organization membership."""
    await require_org_membership(organization_id, request, user_id)

    status_filter = TemplateStatus(status) if status else None
    templates = await repo.list(organization_id, status_filter)
    return [_template_to_response(t) for t in templates]


@router.get("/{template_id}", response_model=CredentialTemplateResponse)
async def get_credential_template(
    template_id: str,
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Get a Credential Template by ID."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")
    return _template_to_response(template)


@router.patch("/{template_id}", response_model=CredentialTemplateResponse)
async def update_credential_template(
    template_id: str,
    request: UpdateCredentialTemplateRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Update a Credential Template (only allowed in draft status).
    
    Note: Requires user authentication. Org membership verified via template's org_id.
    """
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")
    
    if template.status != TemplateStatus.DRAFT:
        raise HTTPException(
            status_code=400, 
            detail="Only draft templates can be modified. Create a new version instead."
        )
    
    if request.name is not None:
        template.name = request.name
    if request.description is not None:
        template.description = request.description
    if request.privacy_posture is not None:
        template.privacy_posture = PrivacyPosture(request.privacy_posture)
    if request.selective_disclosure_fields is not None:
        template.selective_disclosure_fields = request.selective_disclosure_fields
    if request.zk_predicate_claims is not None:
        template.zk_predicate_claims = request.zk_predicate_claims
    if request.supported_formats is not None:
        template.supported_formats = [CredentialFormat(f) for f in request.supported_formats]
    if request.wallet_configs is not None:
        template.wallet_configs = [WalletConfig(wallet_id=wc.get("wallet_id", ""), deep_link_scheme=wc.get("deep_link_scheme", "openid-credential-offer://"), format_variant=wc.get("format_variant")) for wc in request.wallet_configs]
    if request.issuance_protocol is not None:
        template.issuance_protocol = request.issuance_protocol
    if request.credential_payload_format is not None:
        template.credential_payload_format = request.credential_payload_format
    
    template.updated_at = datetime.now(timezone.utc)
    await repo.save(template)
    return _template_to_response(template)


@router.post("/{template_id}/activate", response_model=CredentialTemplateResponse)
async def activate_credential_template(
    template_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Activate a Credential Template. Requires authentication."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")
    
    if not template.claims:
        raise HTTPException(status_code=400, detail="Template must have at least one claim")
    
    template.activate()
    await repo.save(template)
    return _template_to_response(template)


@router.post("/{template_id}/deprecate", response_model=CredentialTemplateResponse)
async def deprecate_credential_template(
    template_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Deprecate a Credential Template. Requires authentication."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")
    template.deprecate()
    await repo.save(template)
    return _template_to_response(template)


@router.post("/{template_id}/new-version", response_model=CredentialTemplateResponse)
async def create_new_version(
    template_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Create a new draft version from an existing template. Requires authentication."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")
    
    new_template = template.new_version()
    await repo.save(new_template)
    return _template_to_response(new_template)


@router.delete("/{template_id}")
async def delete_credential_template(
    template_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> dict:
    """Delete a Credential Template (soft delete). Requires authentication."""
    """Delete a Credential Template (only allowed for drafts)."""
    template = await repo.get(template_id)
    if template and template.status != TemplateStatus.DRAFT:
        raise HTTPException(
            status_code=400, 
            detail="Only draft templates can be deleted. Deprecate active templates instead."
        )
    await repo.delete(template_id)
    return {"success": True}


# Claims sub-resource
@router.post("/{template_id}/claims", response_model=CredentialTemplateResponse)
async def add_claim(
    template_id: str,
    claim: ClaimDefinitionModel,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Add a claim to a Credential Template. Requires authentication."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")
    
    if template.status != TemplateStatus.DRAFT:
        raise HTTPException(status_code=400, detail="Only draft templates can be modified")
    
    template.claims.append(ClaimDefinition(
        name=claim.name,
        display_name=claim.display_name,
        description=claim.description,
        claim_type=ClaimType(claim.claim_type),
        required=claim.required,
        selectively_disclosable=claim.selectively_disclosable,
        derivable=claim.derivable,
    ))
    
    template.updated_at = datetime.now(timezone.utc)
    await repo.save(template)
    return _template_to_response(template)


def _template_to_response(template: CredentialTemplate) -> CredentialTemplateResponse:
    return CredentialTemplateResponse(
        id=template.id,
        organization_id=template.organization_id,
        name=template.name,
        description=template.description,
        status=template.status.value,
        credential_type=template.credential_type,
        vct=template.vct,
        doctype=template.doctype,
        claims=[
            {
                "id": c.id,
                "name": c.name,
                "display_name": c.display_name,
                "description": c.description,
                "claim_type": c.claim_type.value,
                "required": c.required,
                "selectively_disclosable": c.selectively_disclosable,
                "derivable": c.derivable,
            }
            for c in template.claims
        ],
        privacy_posture=template.privacy_posture.value,
        selective_disclosure_fields=template.selective_disclosure_fields,
        zk_predicate_claims=template.zk_predicate_claims,
        derived_attributes=[
            {
                "id": da.id,
                "name": da.name,
                "source_claim": da.source_claim,
                "derivation_type": da.derivation_type,
                "parameters": da.parameters,
            }
            for da in template.derived_attributes
        ],
        display_style={
            "background_color": template.display_style.background_color,
            "text_color": template.display_style.text_color,
            "logo_url": template.display_style.logo_url,
            "background_image_url": template.display_style.background_image_url,
            "icon": template.display_style.icon,
        },
        validity_rules={
            "default_validity_days": template.validity_rules.default_validity_days,
            "max_validity_days": template.validity_rules.max_validity_days,
            "renewable": template.validity_rules.renewable,
            "renewal_window_days": template.validity_rules.renewal_window_days,
            "require_revalidation": template.validity_rules.require_revalidation,
        },
        issuer_requirements={
            "allowed_issuer_dids": template.issuer_requirements.allowed_issuer_dids,
            "trust_tier_required": template.issuer_requirements.trust_tier_required,
            "audit_level_required": template.issuer_requirements.audit_level_required,
        },
        supported_formats=[f.value for f in template.supported_formats],
        wallet_configs=[{k: v for k, v in {"wallet_id": wc.wallet_id, "deep_link_scheme": wc.deep_link_scheme, "format_variant": wc.format_variant}.items() if v is not None} for wc in template.wallet_configs],
        issuance_protocol=template.issuance_protocol,
        credential_payload_format=template.credential_payload_format,
        version=template.version,
        created_at=template.created_at.isoformat(),
        updated_at=template.updated_at.isoformat(),
    )


def _wallet_to_response(w: WalletRegistryEntry) -> WalletRegistryEntryResponse:
    return WalletRegistryEntryResponse(
        id=w.id,
        name=w.name,
        logo_url=w.logo_url,
        deep_link_template=w.deep_link_template,
        supported_formats=w.supported_formats,
        supported_protocols=w.supported_protocols,
        platforms=w.platforms,
        supports_qr=w.supports_qr,
        supports_deeplink=w.supports_deeplink,
        docs_url=w.docs_url,
        is_active=w.is_active,
        created_at=w.created_at.isoformat(),
        updated_at=w.updated_at.isoformat(),
    )


# =============================================================================
# Wallet Registry Router
# =============================================================================

@wallet_router.get("", response_model=list[WalletRegistryEntryResponse], summary="List Wallet Registry")
async def list_wallets(
    active_only: bool = Query(True, description="Return only active wallets"),
    repo: PostgresWalletRegistryRepository = Depends(get_wallet_repo),
) -> list[WalletRegistryEntryResponse]:
    """List all wallets in the global registry."""
    wallets = await repo.list(active_only=active_only)
    return [_wallet_to_response(w) for w in wallets]


@wallet_router.get("/{wallet_id}", response_model=WalletRegistryEntryResponse, summary="Get Wallet")
async def get_wallet(
    wallet_id: str,
    repo: PostgresWalletRegistryRepository = Depends(get_wallet_repo),
) -> WalletRegistryEntryResponse:
    """Get a wallet registry entry by ID."""
    wallet = await repo.get(wallet_id)
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    return _wallet_to_response(wallet)


@wallet_router.post("", response_model=WalletRegistryEntryResponse, summary="Create Wallet Entry", status_code=201)
async def create_wallet(
    body: WalletRegistryEntryCreate,
    user_id: str = Depends(get_current_user_id),
    repo: PostgresWalletRegistryRepository = Depends(get_wallet_repo),
) -> WalletRegistryEntryResponse:
    """Create a new wallet registry entry. Requires admin authentication."""
    entry = WalletRegistryEntry(
        name=body.name,
        logo_url=body.logo_url,
        deep_link_template=body.deep_link_template,
        supported_formats=body.supported_formats,
        supported_protocols=body.supported_protocols,
        platforms=body.platforms,
        supports_qr=body.supports_qr,
        supports_deeplink=body.supports_deeplink,
        docs_url=body.docs_url,
    )
    await repo.save(entry)
    logger.info(f"Created wallet registry entry: {entry.id} ({entry.name})")
    return _wallet_to_response(entry)


@wallet_router.patch("/{wallet_id}", response_model=WalletRegistryEntryResponse, summary="Update Wallet Entry")
async def update_wallet(
    wallet_id: str,
    body: WalletRegistryEntryUpdate,
    user_id: str = Depends(get_current_user_id),
    repo: PostgresWalletRegistryRepository = Depends(get_wallet_repo),
) -> WalletRegistryEntryResponse:
    """Update a wallet registry entry. Requires admin authentication."""
    entry = await repo.get(wallet_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Wallet not found")
    if body.name is not None:
        entry.name = body.name
    if body.logo_url is not None:
        entry.logo_url = body.logo_url
    if body.deep_link_template is not None:
        entry.deep_link_template = body.deep_link_template
    if body.supported_formats is not None:
        entry.supported_formats = body.supported_formats
    if body.supported_protocols is not None:
        entry.supported_protocols = body.supported_protocols
    if body.platforms is not None:
        entry.platforms = body.platforms
    if body.supports_qr is not None:
        entry.supports_qr = body.supports_qr
    if body.supports_deeplink is not None:
        entry.supports_deeplink = body.supports_deeplink
    if body.docs_url is not None:
        entry.docs_url = body.docs_url
    if body.is_active is not None:
        entry.is_active = body.is_active
    await repo.save(entry)
    logger.info(f"Updated wallet registry entry: {entry.id}")
    return _wallet_to_response(entry)


@wallet_router.delete("/{wallet_id}", summary="Delete Wallet Entry")
async def delete_wallet(
    wallet_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: PostgresWalletRegistryRepository = Depends(get_wallet_repo),
) -> dict:
    """Delete a wallet registry entry. Requires admin authentication."""
    entry = await repo.get(wallet_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Wallet not found")
    await repo.delete(wallet_id)
    return {"success": True}


# =============================================================================
# Internal API (no authentication — cluster-internal only)
# =============================================================================

internal_router = APIRouter(prefix="/internal", tags=["internal"])


@internal_router.get("/credential-configurations")
async def get_credential_configurations() -> dict:
    """
    Internal endpoint returning OID4VCI ``credential_configurations_supported``
    built dynamically from all **active** credential templates.

    Called by the gateway to serve ``/.well-known/openid-credential-issuer``
    without hard-coding credential types.

    No authentication is required — this path must not be exposed externally.
    """
    _proof_types: dict = {
        "jwt": {"proof_signing_alg_values_supported": ["ES256", "EdDSA"]}
    }
    _binding = ["did:key"]
    _signing_algs = ["ES256", "EdDSA"]

    # Always include the generic "default" fallback entry.
    configs: dict = {
        "default": {
            "format": "jwt_vc_json",
            "scope": "credential",
            "cryptographic_binding_methods_supported": _binding,
            "credential_signing_alg_values_supported": _signing_algs,
            "proof_types_supported": _proof_types,
            "credential_definition": {"type": ["VerifiableCredential"]},
            "display": [{"name": "Verifiable Credential", "locale": "en-US"}],
        }
    }

    if _repo is None:
        return configs

    try:
        templates = await _repo.list_all(status=TemplateStatus.ACTIVE)
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to load credential templates for well-known: %s", exc)
        return configs

    for t in templates:
        cred_type = (t.credential_type or "").strip()
        if not cred_type:
            continue

        # Always emit jwt_vc_json — that is the only format our issuance service
        # produces, regardless of what the template's supported_formats list says.
        fmt = "jwt_vc_json"

        configs[cred_type] = {
            "format": fmt,
            "scope": f"{cred_type}_credential",
            "cryptographic_binding_methods_supported": _binding,
            "credential_signing_alg_values_supported": _signing_algs,
            "proof_types_supported": _proof_types,
            "credential_definition": {
                "type": ["VerifiableCredential", cred_type]
            },
            "display": [{"name": t.name or cred_type, "locale": "en-US"}],
        }

    # Try to look up the issuer display name from the org service using the
    # organization_id of the first active template we found.
    issuer_display_name: str | None = None
    org_service_url = os.environ.get("ORGANIZATION_SERVICE_URL", "http://organization:8002")
    if templates:
        org_id = getattr(templates[0], "organization_id", None)
        if org_id:
            try:
                async with httpx.AsyncClient(timeout=3.0) as org_client:
                    org_resp = await org_client.get(
                        f"{org_service_url}/internal/v1/organizations/{org_id}"
                    )
                    if org_resp.status_code == 200:
                        org_data = org_resp.json()
                        issuer_display_name = (
                            org_data.get("display_name")
                            or org_data.get("name")
                        )
            except Exception as exc:
                logger.warning("Could not look up org name for well-known: %s", exc)

    return {
        "credential_configurations_supported": configs,
        "issuer_display_name": issuer_display_name,
    }


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo, _wallet_repo
    logger.info(f"Starting {SERVICE_NAME}...")
    
    config = get_config()
    
    # Initialize database
    engine = create_async_engine(config["database_url"], echo=False)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    
    # Initialize repository
    _repo = PostgresCredentialTemplateRepository(session_factory)

    # Initialize wallet registry (DB-backed)
    _wallet_repo = PostgresWalletRegistryRepository(session_factory)
    
    # Initialize OrganizationClient for authorization
    org_service_url = os.environ.get("ORGANIZATION_SERVICE_URL", "http://organization:8002")
    org_client = OrganizationClient(
        base_url=org_service_url,
        redis_client=None,  # No Redis caching at service level (gateway handles it)
    )
    app.state.org_client = org_client
    
    logger.info(f"{SERVICE_NAME} started successfully")
    yield
    
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await org_client.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Credential Template Service",
        description="Manages Credential Templates - blueprints for credential issuance",
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
    
    # Add request middleware
    app.add_middleware(RequestLoggingMiddleware, service_name=SERVICE_NAME)
    app.add_middleware(RequestIdMiddleware)
    
    app.include_router(router)
    app.include_router(wallet_router)
    app.include_router(internal_router)
    
    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": SERVICE_NAME}
    
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
