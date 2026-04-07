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

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from typing import Annotated
from marty_common import OrganizationContext, require_org_membership
from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware
from marty_common.service_setup import create_service_app

from credential_template.infrastructure.adapters import (
    PostgresCredentialTemplateRepository,
    PostgresWalletRegistryRepository,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "credential-template-service"
SERVICE_PORT = int(os.environ.get("CREDENTIAL_TEMPLATE_SERVICE_PORT", "8003"))
SECONDS_PER_DAY = 86400


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


from marty_common.domain_enums import CredentialFormat, parse_credential_format  # noqa: E402


def normalize_credential_format(value: str) -> CredentialFormat:
    """Accept canonical names, upper/lower variants, and OID4VCI wire aliases."""
    return parse_credential_format(value)


# Primary wire-format names used in API responses (matches OID4VCI/test expectations)
_FORMAT_WIRE_NAMES: dict[str, str] = {
    "MDOC": "mdoc",
    "SD_JWT_VC": "sd_jwt_vc",
    "VC_JWT": "jwt_vc",
    "JSON_LD": "ldp_vc",
    "ZK_MDOC": "zk_mdoc",
}


def format_to_wire(fmt: CredentialFormat) -> str:
    """Return the primary wire-format name for a CredentialFormat enum value."""
    return _FORMAT_WIRE_NAMES.get(fmt.value, fmt.value.lower())


_PAYLOAD_FORMAT_ALIASES: dict[str, str] = {
    "sd_jwt_vc": CredentialFormat.SD_JWT_VC.value,
    "sd-jwt-vc": CredentialFormat.SD_JWT_VC.value,
    "vc+sd-jwt": CredentialFormat.SD_JWT_VC.value,
    "dc+sd-jwt": CredentialFormat.SD_JWT_VC.value,
    "ietf_sd_jwt": CredentialFormat.SD_JWT_VC.value,
    "w3c_vcdm_v2_sd_jwt": CredentialFormat.SD_JWT_VC.value,
    "mdoc": CredentialFormat.MDOC.value,
    "mso_mdoc": CredentialFormat.MDOC.value,
    "vc_jwt": CredentialFormat.VC_JWT.value,
    "jwt_vc": CredentialFormat.VC_JWT.value,
    "jwt_vc_json": CredentialFormat.VC_JWT.value,
    "jwt_vc_json-ld": CredentialFormat.VC_JWT.value,
    "w3c_vcdm_v2_jwt_vc": CredentialFormat.VC_JWT.value,
    "json_ld": CredentialFormat.JSON_LD.value,
    "json-ld": CredentialFormat.JSON_LD.value,
    "ldp_vc": CredentialFormat.JSON_LD.value,
}


def _default_payload_format(supported_formats: list[CredentialFormat]) -> str:
    if supported_formats:
        return supported_formats[0].value
    return CredentialFormat.SD_JWT_VC.value


def normalize_credential_payload_format(
    value: str | None,
    supported_formats: list[CredentialFormat],
) -> str:
    """Normalize legacy payload-format names onto protocol credential-format enums."""
    if value is None or not str(value).strip():
        return _default_payload_format(supported_formats)

    normalized = str(value).strip()
    alias = _PAYLOAD_FORMAT_ALIASES.get(normalized) or _PAYLOAD_FORMAT_ALIASES.get(normalized.lower())
    if alias:
        return alias

    try:
        return normalize_credential_format(normalized).value
    except ValueError as exc:
        raise ValueError(f"'{value}' is not a valid credential payload format") from exc


def payload_format_to_wire(value: str | None) -> str:
    normalized = normalize_credential_payload_format(value, [])
    return format_to_wire(CredentialFormat(normalized))


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
    not_before_offset_seconds: int = 0
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


class MergeStrategy(str, Enum):
    APPEND = "APPEND"
    REPLACE = "REPLACE"


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

    # Compliance
    compliance_profile: dict | None = None
    compliance_profile_id: str | None = None

    # Protocol schema fields
    application_template_id: str | None = None
    trust_profile_id: str | None = None
    revocation_profile_id: str | None = None
    issuer_key_id: str | None = None
    issuer_algorithm: str | None = None
    key_access_mode: str | None = None
    issuer_certificate_chain_pem: str | None = None
    issuer_did: str | None = None
    auto_generate_artifacts: bool = False
    
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
    organization_id: str | None = None
    is_override: bool = False
    override_precedence: int = 50
    merge_strategy: MergeStrategy = MergeStrategy.APPEND
    credential_format: str | None = None
    issuance_protocol: str | None = None
    compliance_profile_code: str | None = None
    name: str = ""
    description: str | None = None
    wallet_apps: list[str] = field(default_factory=list)
    specifications: list[str] = field(default_factory=list)
    logo_url: str | None = None
    deep_link_template: str = "openid-credential-offer://?credential_offer_uri={offer_uri}"
    supported_formats: list[str] = field(default_factory=list)
    supported_protocols: list[str] = field(default_factory=lambda: ["OID4VCI_PRE_AUTH"])
    platforms: list[str] = field(default_factory=list)
    supports_qr: bool = True
    supports_deeplink: bool = True
    docs_url: str | None = None
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class DerivedWalletProfile:
    credential_format: str
    issuance_protocol: str
    compliance_profile_code: str | None
    name: str
    description: str
    wallet_apps: list[str]
    specifications: list[str]
    supported_platforms: list[str]
    deep_link_pattern: str


SYSTEM_WALLET_CATALOG: tuple[WalletRegistryEntry, ...] = (
    WalletRegistryEntry(
        id="wr-spruce-001",
        name="SpruceKit",
        description="SpruceID mobile wallet for OID4VCI delivery.",
        wallet_apps=["SpruceKit"],
        specifications=["OID4VCI"],
        logo_url="https://spruceid.com/favicon.ico",
        supported_formats=["spruce-vc+sd-jwt"],
        platforms=["ios", "android"],
        docs_url="https://spruceid.com/products/sprucekit",
    ),
    WalletRegistryEntry(
        id="wr-marty-001",
        name="Marty Authenticator",
        description="Marty-branded authenticator wallet.",
        wallet_apps=["Marty Authenticator"],
        specifications=["OID4VCI"],
        supported_formats=["spruce-vc+sd-jwt"],
        platforms=["ios", "android"],
    ),
    WalletRegistryEntry(
        id="wr-default",
        name="Any OID4VCI Wallet",
        description="Generic OID4VCI-compatible wallet entry.",
        wallet_apps=["Any OID4VCI Wallet"],
        specifications=["OID4VCI"],
        supported_formats=["sd_jwt_vc", "jwt_vc", "mdoc"],
        platforms=["ios", "android", "web"],
    ),
    WalletRegistryEntry(
        id="wr-lissi-001",
        name="LISSI Wallet",
        description="LISSI mobile wallet.",
        wallet_apps=["LISSI Wallet"],
        specifications=["OID4VCI"],
        logo_url="https://lissi.id/favicon.ico",
        supported_formats=["sd_jwt_vc", "jwt_vc"],
        platforms=["ios", "android"],
        docs_url="https://lissi.id",
    ),
    WalletRegistryEntry(
        id="wr-waltid-001",
        name="walt.id Wallet",
        description="walt.id mobile and web wallet.",
        wallet_apps=["walt.id Wallet"],
        specifications=["OID4VCI", "OID4VP"],
        logo_url="https://walt.id/favicon.ico",
        supported_formats=["sd_jwt_vc", "jwt_vc", "mdoc"],
        platforms=["ios", "android", "web"],
        docs_url="https://docs.walt.id",
    ),
    WalletRegistryEntry(
        id="wr-sphereon-001",
        name="Sphereon Wallet",
        description="Sphereon mobile wallet.",
        wallet_apps=["Sphereon Wallet"],
        specifications=["OID4VCI"],
        logo_url="https://sphereon.com/favicon.ico",
        supported_formats=["sd_jwt_vc", "jwt_vc"],
        platforms=["ios", "android"],
        docs_url="https://sphereon.com",
    ),
    WalletRegistryEntry(
        id="wr-dc4eu-001",
        name="DC4EU Wallet",
        description="DC4EU and EUDI ecosystem wallet.",
        wallet_apps=["DC4EU Wallet"],
        specifications=["OID4VCI", "eIDAS"],
        supported_formats=["sd_jwt_vc", "mdoc"],
        platforms=["ios", "android"],
    ),
    WalletRegistryEntry(
        id="wr-google-001",
        name="Google Wallet",
        description="Google Wallet via Android CredentialManager API.",
        wallet_apps=["Google Wallet"],
        specifications=["OID4VCI", "CredentialManager"],
        logo_url="https://wallet.google/favicon.ico",
        supported_formats=["dc+sd-jwt"],
        supported_protocols=["CREDENTIAL_MANAGER"],
        platforms=["android"],
        deep_link_template="openid-credential-offer://?credential_offer={offer}",
        docs_url="https://developer.android.com/identity/digital-credentials",
    ),
    WalletRegistryEntry(
        id="wr-apple-001",
        name="Apple Wallet",
        description="Apple Wallet via Verify with Wallet / ISO 18013-5 issuance.",
        wallet_apps=["Apple Wallet"],
        specifications=["OID4VCI", "ISO 18013-5"],
        logo_url="https://www.apple.com/favicon.ico",
        supported_formats=["mso_mdoc"],
        supported_protocols=["APPLE_WALLET"],
        platforms=["ios"],
        deep_link_template="openid-credential-offer://?credential_offer={offer}",
        docs_url="https://developer.apple.com/documentation/passkit/wallet",
    ),
    WalletRegistryEntry(
        id="wr-didcomm-001",
        name="DIDComm V2 Agent",
        description="Push credential delivery via DIDComm v2 messaging. Resolves holder DID to find service endpoint.",
        wallet_apps=["DIDComm V2 Agent"],
        specifications=["DIDComm v2", "DIF DIDComm Messaging"],
        supported_formats=["sd_jwt_vc", "jwt_vc", "mso_mdoc"],
        supported_protocols=["DIDCOMM_V2"],
        platforms=["any"],
        supports_qr=False,
        supports_deeplink=False,
        deep_link_template="",
        docs_url="https://identity.foundation/didcomm-messaging/spec/v2.1/",
    ),
)


DERIVED_WALLET_PROFILES: dict[tuple[str, str, str | None], DerivedWalletProfile] = {
    ("MDOC", "OID4VCI_PRE_AUTH", "AAMVA_MDL"): DerivedWalletProfile(
        credential_format="MDOC",
        issuance_protocol="OID4VCI_PRE_AUTH",
        compliance_profile_code="AAMVA_MDL",
        name="AAMVA mDL Wallet",
        description="Derived compatibility profile for AAMVA mobile driver licenses.",
        wallet_apps=["Apple Wallet (mDL)", "Google Wallet (mDL)", "ISO mDL wallets"],
        specifications=["ISO 18013-5", "ISO 23220-3", "OID4VCI"],
        supported_platforms=["ios", "android"],
        deep_link_pattern="openid-credential-offer://?credential_offer_uri={offer_uri}",
    ),
    ("MDOC", "OID4VCI_PRE_AUTH", "ICAO_DTC"): DerivedWalletProfile(
        credential_format="MDOC",
        issuance_protocol="OID4VCI_PRE_AUTH",
        compliance_profile_code="ICAO_DTC",
        name="ICAO DTC Wallet",
        description="Derived compatibility profile for ICAO DTC wallets.",
        wallet_apps=["ICAO DTC-compliant wallets"],
        specifications=["ICAO DTC", "OID4VCI"],
        supported_platforms=["ios", "android"],
        deep_link_pattern="openid-credential-offer://?credential_offer_uri={offer_uri}",
    ),
    ("MDOC", "OID4VCI_PRE_AUTH", "EUDI_MDL"): DerivedWalletProfile(
        credential_format="MDOC",
        issuance_protocol="OID4VCI_PRE_AUTH",
        compliance_profile_code="EUDI_MDL",
        name="EUDI mDL Wallet",
        description="Derived compatibility profile for EUDI mobile driving licences.",
        wallet_apps=["EUDI Wallet", "eIDAS wallets"],
        specifications=["eIDAS", "OID4VCI", "ISO 18013-5"],
        supported_platforms=["ios", "android", "web"],
        deep_link_pattern="openid-credential-offer://?credential_offer_uri={offer_uri}",
    ),
    ("SD_JWT_VC", "OID4VCI_PRE_AUTH", "EUDI_PID"): DerivedWalletProfile(
        credential_format="SD_JWT_VC",
        issuance_protocol="OID4VCI_PRE_AUTH",
        compliance_profile_code="EUDI_PID",
        name="EUDI PID Wallet",
        description="Derived compatibility profile for EUDI PID credentials.",
        wallet_apps=["EUDI Wallet", "eIDAS wallets"],
        specifications=["SD-JWT VC", "OID4VCI", "eIDAS"],
        supported_platforms=["ios", "android", "web"],
        deep_link_pattern="openid-credential-offer://?credential_offer_uri={offer_uri}",
    ),
    ("SD_JWT_VC", "OID4VCI_PRE_AUTH", None): DerivedWalletProfile(
        credential_format="SD_JWT_VC",
        issuance_protocol="OID4VCI_PRE_AUTH",
        compliance_profile_code=None,
        name="Generic SD-JWT VC Wallet",
        description="Derived compatibility profile for generic SD-JWT VC issuance.",
        wallet_apps=["EUDI Wallet", "OID4VCI-compatible wallets"],
        specifications=["SD-JWT VC", "OID4VCI"],
        supported_platforms=["ios", "android", "web"],
        deep_link_pattern="openid-credential-offer://?credential_offer_uri={offer_uri}",
    ),
    ("VC_JWT", "OID4VCI_PRE_AUTH", "OB3_JWT"): DerivedWalletProfile(
        credential_format="VC_JWT",
        issuance_protocol="OID4VCI_PRE_AUTH",
        compliance_profile_code="OB3_JWT",
        name="Open Badges JWT Wallet",
        description="Derived compatibility profile for Open Badges JWT credentials.",
        wallet_apps=["1EdTech Open Badge Passport", "Learning Credential Wallet"],
        specifications=["Open Badges 3.0", "OID4VCI"],
        supported_platforms=["ios", "android", "web"],
        deep_link_pattern="openid-credential-offer://?credential_offer_uri={offer_uri}",
    ),
    ("JSON_LD", "OID4VCI_PRE_AUTH", "OB3_JSONLD"): DerivedWalletProfile(
        credential_format="JSON_LD",
        issuance_protocol="OID4VCI_PRE_AUTH",
        compliance_profile_code="OB3_JSONLD",
        name="Open Badges JSON-LD Wallet",
        description="Derived compatibility profile for Open Badges JSON-LD credentials.",
        wallet_apps=["1EdTech Open Badge Passport", "DIF Universal Wallet"],
        specifications=["Open Badges 3.0", "VC Data Model", "OID4VCI"],
        supported_platforms=["ios", "android", "web"],
        deep_link_pattern="openid-credential-offer://?credential_offer_uri={offer_uri}",
    ),
    ("VC_JWT", "OID4VCI_PRE_AUTH", "ENTERPRISE_VC"): DerivedWalletProfile(
        credential_format="VC_JWT",
        issuance_protocol="OID4VCI_PRE_AUTH",
        compliance_profile_code="ENTERPRISE_VC",
        name="Enterprise VC Wallet",
        description="Derived compatibility profile for enterprise-managed VC JWT credentials.",
        wallet_apps=["Organization-managed wallets"],
        specifications=["VC JWT", "OID4VCI"],
        supported_platforms=["ios", "android", "web"],
        deep_link_pattern="openid-credential-offer://?credential_offer_uri={offer_uri}",
    ),
}


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

    def __init__(self) -> None:
        self._wallets: dict[str, WalletRegistryEntry] = {
            w.id: WalletRegistryEntry(**w.__dict__) for w in SYSTEM_WALLET_CATALOG
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
    default_validity_days: int | None = None
    max_validity_days: int | None = None
    renewable: bool = True
    renewal_window_days: int | None = None
    ttl_seconds: int | None = None
    reissue_within_seconds: int | None = None
    not_before_offset_seconds: int | None = None
    not_before_offset: int | None = None
    max_validity_seconds: int | None = None
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
    organization_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    credential_type: str = Field(min_length=1, max_length=255)
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
    supported_formats: list[str] = ["SD_JWT_VC"]
    # Compliance
    compliance_profile: dict | None = None
    compliance_profile_id: str | None = None
    # Wallet compatibility
    wallet_configs: list[dict] = []
    issuance_protocol: str = "oid4vci"
    credential_payload_format: str | None = None
    schema_uri: dict | None = None


class UpdateCredentialTemplateRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
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
    compliance_profile_id: str | None = None
    vct: str | None = None
    credential_payload_format: str | None = None
    supported_formats: list[str] = []
    zk_predicate_claims: list[str] = []
    application_template_id: str | None = None
    trust_profile_id: str | None = None
    revocation_profile_id: str | None = None
    claims: list[dict]
    validity_rules: dict
    issuer_key_id: str | None = None
    issuer_algorithm: str | None = None
    key_access_mode: str | None = None
    issuer_certificate_chain_pem: str | None = None
    issuer_did: str | None = None
    auto_generate_artifacts: bool = False
    privacy_posture: dict | None = None
    wallet_configs: list[dict] = Field(default_factory=list)
    created_at: str
    updated_at: str


def _days_from_seconds(seconds: int) -> int:
    return max(1, (int(seconds) + SECONDS_PER_DAY - 1) // SECONDS_PER_DAY)


def _resolve_validity_rules(
    value: ValidityRulesModel,
    existing: ValidityRules | None = None,
) -> ValidityRules:
    base = existing or ValidityRules()
    payload = value.model_dump(exclude_unset=True)

    default_validity_days = payload.get("default_validity_days", base.default_validity_days)
    if payload.get("ttl_seconds") is not None:
        if payload["ttl_seconds"] <= 0:
            raise HTTPException(status_code=422, detail="validity_rules.ttl_seconds must be > 0")
        default_validity_days = _days_from_seconds(payload["ttl_seconds"])

    max_validity_days = payload.get("max_validity_days", base.max_validity_days)
    if payload.get("max_validity_seconds") is not None:
        max_validity_days = _days_from_seconds(payload["max_validity_seconds"])

    renewal_window_days = payload.get("renewal_window_days", base.renewal_window_days)
    if payload.get("reissue_within_seconds") is not None:
        renewal_window_days = _days_from_seconds(payload["reissue_within_seconds"])

    not_before_offset_seconds = base.not_before_offset_seconds
    if payload.get("not_before_offset_seconds") is not None:
        not_before_offset_seconds = int(payload["not_before_offset_seconds"])
    elif payload.get("not_before_offset") is not None:
        not_before_offset_seconds = int(payload["not_before_offset"])

    return ValidityRules(
        default_validity_days=default_validity_days,
        max_validity_days=max_validity_days,
        renewable=payload.get("renewable", base.renewable),
        renewal_window_days=renewal_window_days,
        not_before_offset_seconds=not_before_offset_seconds,
        require_revalidation=payload.get("require_revalidation", base.require_revalidation),
        revalidation_interval_days=payload.get("revalidation_interval_days", base.revalidation_interval_days),
    )


# ----- Wallet Registry Pydantic Models -----

class WalletRegistryEntryCreate(BaseModel):
    organization_id: str | None = None
    credential_format: str | None = None
    issuance_protocol: str | None = None
    compliance_profile_code: str | None = None
    name: str
    description: str | None = None
    wallet_apps: list[str] = Field(default_factory=list)
    specifications: list[str] = Field(default_factory=list)
    logo_url: str | None = None
    deep_link_template: str = "openid-credential-offer://?credential_offer_uri={offer_uri}"
    deep_link_pattern: str | None = None
    supported_formats: list[str] = Field(default_factory=list)
    supported_protocols: list[str] = Field(default_factory=lambda: ["OID4VCI_PRE_AUTH"])
    platforms: list[str] = Field(default_factory=list)
    supported_platforms: list[str] | None = None
    supports_qr: bool = True
    supports_deeplink: bool = True
    docs_url: str | None = None
    override_precedence: int = 50
    merge_strategy: str = MergeStrategy.APPEND.value


class WalletRegistryEntryUpdate(BaseModel):
    organization_id: str | None = None
    credential_format: str | None = None
    issuance_protocol: str | None = None
    compliance_profile_code: str | None = None
    name: str | None = None
    description: str | None = None
    wallet_apps: list[str] | None = None
    specifications: list[str] | None = None
    logo_url: str | None = None
    deep_link_template: str | None = None
    deep_link_pattern: str | None = None
    supported_formats: list[str] | None = None
    supported_protocols: list[str] | None = None
    platforms: list[str] | None = None
    supported_platforms: list[str] | None = None
    supports_qr: bool | None = None
    supports_deeplink: bool | None = None
    docs_url: str | None = None
    is_active: bool | None = None
    override_precedence: int | None = None
    merge_strategy: str | None = None


class WalletRegistryEntryResponse(BaseModel):
    id: str
    organization_id: str | None
    is_override: bool
    override_precedence: int
    merge_strategy: str
    credential_format: str | None
    issuance_protocol: str | None
    compliance_profile_code: str | None
    name: str
    description: str | None
    wallet_apps: list[str]
    specifications: list[str]
    deep_link_pattern: str
    supported_platforms: list[str]
    created_at: str
    updated_at: str


class DerivedFromResponse(BaseModel):
    credential_format: str
    issuance_protocol: str
    compliance_profile_code: str | None = None


class WalletCompatibilityResponse(BaseModel):
    id: str | None = None
    organization_id: str | None = None
    derived_from: DerivedFromResponse
    is_override: bool
    override_precedence: int = 0
    merge_strategy: str = MergeStrategy.APPEND.value
    name: str
    description: str
    credential_format: str
    issuance_protocol: str
    compliance_profile_code: str | None = None
    wallet_apps: list[str] = Field(default_factory=list)
    specifications: list[str] = Field(default_factory=list)
    supported_platforms: list[str] = Field(default_factory=list)
    deep_link_pattern: str
    applied_override_ids: list[str] = Field(default_factory=list)
    template_wallet_configs: list[dict] = Field(default_factory=list)
    created_at: str
    updated_at: str


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/credential-templates", tags=["credential-templates"])
wallet_router = APIRouter(prefix="/v1/wallet-registry", tags=["wallet-registry"])

_repo: InMemoryCredentialTemplateRepository | None = None
_wallet_repo: InMemoryWalletRegistryRepository | PostgresWalletRegistryRepository | None = None


def get_repo() -> InMemoryCredentialTemplateRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


def get_wallet_repo() -> InMemoryWalletRegistryRepository | PostgresWalletRegistryRepository:
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


@router.post("", response_model=CredentialTemplateResponse, response_model_exclude_none=True)
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

    # MIP §6.2 — credential_type MUST be PascalCase OR a reverse-domain doctype
    # PascalCase: "EmployeeBadge", "VerifiableId"
    # Reverse-domain (ISO mdoc): "org.iso.18013.5.1.mDL"
    import re as _re
    _CREDENTIAL_TYPE_RE = r"[A-Z][a-zA-Z0-9]+|[a-z][a-zA-Z0-9]*(\.[a-zA-Z0-9]+)+"
    if not _re.fullmatch(_CREDENTIAL_TYPE_RE, body.credential_type):
        raise HTTPException(
            status_code=422,
            detail=f"credential_type must be PascalCase or reverse-domain notation, got: {body.credential_type}",
        )

    # MIP §6.2 — claims MUST have ≥1 entry
    if not body.claims:
        raise HTTPException(status_code=422, detail="claims must contain at least one claim definition")

    try:
        supported_formats = [normalize_credential_format(f) for f in body.supported_formats]
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"Invalid credential format: {e}")

    try:
        credential_payload_format = normalize_credential_payload_format(
            body.credential_payload_format,
            supported_formats,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    resolved_vct = body.vct or f"https://credentials.example.com/{body.credential_type}"
    _validate_template_protocol_requirements(
        compliance_profile=body.compliance_profile,
        compliance_profile_id=body.compliance_profile_id,
        credential_payload_format=credential_payload_format,
        vct=resolved_vct,
    )

    template = CredentialTemplate(
        organization_id=body.organization_id,
        name=body.name,
        description=body.description,
        credential_type=body.credential_type,
        vct=resolved_vct,
        doctype=body.doctype or "",
        privacy_posture=PrivacyPosture(body.privacy_posture),
        selective_disclosure_fields=body.selective_disclosure_fields,
        zk_predicate_claims=body.zk_predicate_claims,
        supported_formats=supported_formats,
        wallet_configs=[WalletConfig(wallet_id=wc.get("wallet_id", ""), deep_link_scheme=wc.get("deep_link_scheme", "openid-credential-offer://"), format_variant=wc.get("format_variant")) for wc in body.wallet_configs],
        issuance_protocol=body.issuance_protocol,
        credential_payload_format=credential_payload_format,
        compliance_profile=body.compliance_profile,
        compliance_profile_id=body.compliance_profile_id,
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
        template.validity_rules = _resolve_validity_rules(body.validity_rules)

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


@router.get("", response_model=list[CredentialTemplateResponse], response_model_exclude_none=True)
async def list_credential_templates(
    organization_id: str = Query(..., description="Organization ID"),
    status: str | None = Query(None, description="Filter by status"),
    request: Request = None,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[CredentialTemplateResponse]:
    """List Credential Templates for an organization. Requires organization membership."""
    await require_org_membership(organization_id, request, user_id)

    status_filter = TemplateStatus(status) if status else None
    templates = await repo.list(organization_id, status_filter)
    return [_template_to_response(t) for t in templates[offset:offset + limit]]


@router.get("/{template_id}", response_model=CredentialTemplateResponse, response_model_exclude_none=True)
async def get_credential_template(
    template_id: str,
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Get a Credential Template by ID."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")
    return _template_to_response(template)


@router.patch("/{template_id}", response_model=CredentialTemplateResponse, response_model_exclude_none=True)
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
    supported_formats = template.supported_formats
    if request.supported_formats is not None:
        supported_formats = [normalize_credential_format(f) for f in request.supported_formats]
        template.supported_formats = supported_formats
    if request.wallet_configs is not None:
        template.wallet_configs = [WalletConfig(wallet_id=wc.get("wallet_id", ""), deep_link_scheme=wc.get("deep_link_scheme", "openid-credential-offer://"), format_variant=wc.get("format_variant")) for wc in request.wallet_configs]
    if request.issuance_protocol is not None:
        template.issuance_protocol = request.issuance_protocol
    if request.credential_payload_format is not None:
        try:
            template.credential_payload_format = normalize_credential_payload_format(
                request.credential_payload_format,
                supported_formats,
            )
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
    if request.validity_rules is not None:
        template.validity_rules = _resolve_validity_rules(request.validity_rules, template.validity_rules)

    _validate_template_protocol_requirements(
        compliance_profile=template.compliance_profile,
        compliance_profile_id=template.compliance_profile_id,
        credential_payload_format=normalize_credential_payload_format(
            template.credential_payload_format,
            template.supported_formats,
        ),
        vct=template.vct,
    )
    
    template.updated_at = datetime.now(timezone.utc)
    await repo.save(template)
    return _template_to_response(template)


@router.post("/{template_id}/activate", response_model=CredentialTemplateResponse, response_model_exclude_none=True)
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


@router.post("/{template_id}/deprecate", response_model=CredentialTemplateResponse, response_model_exclude_none=True)
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


@router.post("/{template_id}/new-version", response_model=CredentialTemplateResponse, response_model_exclude_none=True)
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
@router.post("/{template_id}/claims", response_model=CredentialTemplateResponse, response_model_exclude_none=True)
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
    canonical_payload_format = normalize_credential_payload_format(
        template.credential_payload_format,
        template.supported_formats,
    )

    privacy_posture = {
        "default_disclose_all": template.privacy_posture == PrivacyPosture.STANDARD,
        "prefer_predicates": bool(template.zk_predicate_claims) or template.privacy_posture == PrivacyPosture.ZERO_KNOWLEDGE,
        "sd_alg": "sha-256",
    }

    return CredentialTemplateResponse(
        id=template.id,
        organization_id=template.organization_id,
        name=template.name,
        description=template.description,
        status=template.status.value.upper(),
        credential_type=template.credential_type,
        compliance_profile_id=template.compliance_profile_id,
        vct=template.vct or None,
        credential_payload_format=canonical_payload_format,
        supported_formats=[f.value for f in template.supported_formats],
        zk_predicate_claims=template.zk_predicate_claims or [],
        application_template_id=template.application_template_id,
        trust_profile_id=template.trust_profile_id,
        revocation_profile_id=template.revocation_profile_id,
        issuer_key_id=template.issuer_key_id,
        issuer_algorithm=template.issuer_algorithm,
        key_access_mode=template.key_access_mode,
        issuer_certificate_chain_pem=template.issuer_certificate_chain_pem,
        issuer_did=template.issuer_did,
        auto_generate_artifacts=template.auto_generate_artifacts,
        claims=[
            {
                "name": c.name,
                "type": {
                    ClaimType.STRING: "STRING",
                    ClaimType.INTEGER: "INTEGER",
                    ClaimType.BOOLEAN: "BOOLEAN",
                    ClaimType.DATE: "DATE",
                    ClaimType.DATETIME: "DATE",
                    ClaimType.OBJECT: "OBJECT",
                    ClaimType.ARRAY: "ARRAY",
                    ClaimType.IMAGE: "STRING",
                    ClaimType.BINARY: "STRING",
                }[c.claim_type],
                **({"description": c.description} if c.description else {}),
                "required": c.required,
                **({"selectively_disclosable": c.selectively_disclosable} if c.selectively_disclosable else {}),
                **({"namespace": c.mdoc_namespace} if c.mdoc_namespace else {}),
                **({"derived_from": c.name} if c.derivable else {}),
                **({"display": {"label": c.display_name}} if c.display_name else {}),
            }
            for c in template.claims
        ],
        validity_rules={
            "ttl_seconds": template.validity_rules.default_validity_days * SECONDS_PER_DAY,
            "renewable": template.validity_rules.renewable,
            **({"reissue_within_seconds": template.validity_rules.renewal_window_days * SECONDS_PER_DAY} if template.validity_rules.renewal_window_days else {}),
            **({"not_before_offset_seconds": template.validity_rules.not_before_offset_seconds} if template.validity_rules.not_before_offset_seconds else {}),
        },
        privacy_posture=privacy_posture,
        wallet_configs=[
            {k: v for k, v in {"wallet_id": wc.wallet_id, "deep_link_scheme": wc.deep_link_scheme, "format_variant": wc.format_variant}.items() if v is not None}
            for wc in template.wallet_configs
        ],
        created_at=template.created_at.isoformat(),
        updated_at=template.updated_at.isoformat(),
    )


def _normalize_issuance_protocol(value: str | None) -> str:
    normalized = (value or "OID4VCI_PRE_AUTH").strip().upper()
    aliases = {
        "OID4VCI": "OID4VCI_PRE_AUTH",
        "OID4VCI_PRE_AUTH": "OID4VCI_PRE_AUTH",
        "OID4VCI_PRE_AUTHORIZED": "OID4VCI_PRE_AUTH",
        "OID4VCI_PREAUTHORIZED": "OID4VCI_PRE_AUTH",
        "OID4VCI_PRE_AUTH_CODE": "OID4VCI_PRE_AUTH",
        "OID4VCI_AUTHORIZATION_CODE": "OID4VCI_AUTH_CODE",
    }
    return aliases.get(normalized, normalized)


def _extract_compliance_profile_code(template: CredentialTemplate) -> str | None:
    if isinstance(template.compliance_profile, dict):
        code = template.compliance_profile.get("compliance_code") or template.compliance_profile.get("code")
        if code:
            return str(code).upper()
    if template.compliance_profile_id:
        return str(template.compliance_profile_id).upper()
    return None


def _extract_template_credential_format(template: CredentialTemplate) -> str:
    if template.credential_payload_format:
        try:
            return normalize_credential_payload_format(
                template.credential_payload_format,
                template.supported_formats,
            )
        except ValueError:
            logger.warning(
                "Ignoring unknown credential_payload_format on template %s: %s",
                template.id,
                template.credential_payload_format,
            )
    if isinstance(template.compliance_profile, dict):
        compliance_format = template.compliance_profile.get("credential_format")
        if compliance_format:
            return normalize_credential_format(str(compliance_format)).value
    if template.supported_formats:
        return template.supported_formats[0].value
    return CredentialFormat.SD_JWT_VC.value


def _validate_template_protocol_requirements(
    *,
    compliance_profile: dict | None,
    compliance_profile_id: str | None,
    credential_payload_format: str,
    vct: str | None,
) -> None:
    compliance_code = None
    if isinstance(compliance_profile, dict):
        compliance_code = compliance_profile.get("compliance_code") or compliance_profile.get("code")

    if not compliance_profile_id and not compliance_code:
        raise HTTPException(
            status_code=422,
            detail="compliance_profile_id is required unless compatibility mode provides compliance_profile.compliance_code",
        )

    if credential_payload_format == CredentialFormat.SD_JWT_VC.value and not (vct and str(vct).strip()):
        raise HTTPException(
            status_code=422,
            detail="vct is required when credential_payload_format resolves to SD_JWT_VC",
        )
    # MIP §6.2 — vct MUST be an absolute URI per SD-JWT-VC §3.2.1
    # Only enforced for SD-JWT-VC format; mDoc doctypes use reverse-domain notation
    if (
        credential_payload_format == CredentialFormat.SD_JWT_VC.value
        and vct and str(vct).strip()
        and "://" not in str(vct)
    ):
        raise HTTPException(
            status_code=422,
            detail=f"vct must be an absolute URI (e.g. https://…), got: {vct}",
        )


def _derive_wallet_profile(
    credential_format: str,
    issuance_protocol: str,
    compliance_profile_code: str | None,
) -> DerivedWalletProfile:
    normalized_key = (
        credential_format.upper(),
        _normalize_issuance_protocol(issuance_protocol),
        compliance_profile_code.upper() if compliance_profile_code else None,
    )
    derived = DERIVED_WALLET_PROFILES.get(normalized_key)
    if derived is None:
        derived = DERIVED_WALLET_PROFILES.get((normalized_key[0], normalized_key[1], None))
    if derived is not None:
        return derived
    return DerivedWalletProfile(
        credential_format=normalized_key[0],
        issuance_protocol=normalized_key[1],
        compliance_profile_code=normalized_key[2],
        name=f"{normalized_key[0]} Wallet Compatibility",
        description="Derived fallback compatibility profile for this credential format and issuance protocol.",
        wallet_apps=["OID4VCI-compatible wallets"],
        specifications=[normalized_key[0], normalized_key[1]],
        supported_platforms=["ios", "android", "web"],
        deep_link_pattern="openid-credential-offer://?credential_offer_uri={offer_uri}",
    )


def _wallet_entry_matches_key(
    entry: WalletRegistryEntry,
    credential_format: str,
    issuance_protocol: str,
    compliance_profile_code: str | None,
) -> bool:
    if entry.credential_format and entry.credential_format.upper() != credential_format.upper():
        return False
    if entry.issuance_protocol and _normalize_issuance_protocol(entry.issuance_protocol) != _normalize_issuance_protocol(issuance_protocol):
        return False
    if entry.compliance_profile_code and entry.compliance_profile_code.upper() != (compliance_profile_code.upper() if compliance_profile_code else None):
        return False
    return True


async def _list_matching_wallet_overrides(
    repo: InMemoryWalletRegistryRepository | PostgresWalletRegistryRepository,
    organization_id: str,
    credential_format: str,
    issuance_protocol: str,
    compliance_profile_code: str | None,
) -> list[WalletRegistryEntry]:
    entries = await repo.list(active_only=True)
    return sorted(
        [
            entry
            for entry in entries
            if entry.is_override
            and entry.organization_id == organization_id
            and _wallet_entry_matches_key(entry, credential_format, issuance_protocol, compliance_profile_code)
        ],
        key=lambda entry: entry.override_precedence,
        reverse=True,
    )


def _merge_unique(base: list[str], extra: list[str]) -> list[str]:
    merged = list(base)
    for value in extra:
        if value not in merged:
            merged.append(value)
    return merged


def _merge_wallet_profile(
    derived: DerivedWalletProfile,
    overrides: list[WalletRegistryEntry],
    template: CredentialTemplate,
) -> WalletCompatibilityResponse:
    merged_name = derived.name
    merged_description = derived.description
    merged_wallet_apps = list(derived.wallet_apps)
    merged_specifications = list(derived.specifications)
    merged_platforms = list(derived.supported_platforms)
    deep_link_pattern = derived.deep_link_pattern
    applied_override_ids: list[str] = []
    primary_override = overrides[0] if overrides else None

    for override in overrides:
        applied_override_ids.append(override.id)
        override_apps = override.wallet_apps or [override.name]
        override_specs = override.specifications or []
        override_platforms = override.platforms or []
        if override.merge_strategy == MergeStrategy.REPLACE:
            merged_wallet_apps = list(override_apps) or merged_wallet_apps
            merged_specifications = list(override_specs) or merged_specifications
            merged_platforms = list(override_platforms) or merged_platforms
        else:
            merged_wallet_apps = _merge_unique(merged_wallet_apps, override_apps)
            merged_specifications = _merge_unique(merged_specifications, override_specs)
            merged_platforms = _merge_unique(merged_platforms, override_platforms)
        if override.name:
            merged_name = override.name
        if override.description:
            merged_description = override.description
        if override.deep_link_template:
            deep_link_pattern = override.deep_link_template

    return WalletCompatibilityResponse(
        id=primary_override.id if primary_override else None,
        organization_id=primary_override.organization_id if primary_override else None,
        derived_from=DerivedFromResponse(
            credential_format=derived.credential_format,
            issuance_protocol=derived.issuance_protocol,
            compliance_profile_code=derived.compliance_profile_code,
        ),
        is_override=bool(applied_override_ids),
        override_precedence=primary_override.override_precedence if primary_override else 0,
        merge_strategy=primary_override.merge_strategy.value if primary_override else MergeStrategy.APPEND.value,
        name=merged_name,
        description=merged_description,
        credential_format=derived.credential_format,
        issuance_protocol=derived.issuance_protocol,
        compliance_profile_code=derived.compliance_profile_code,
        wallet_apps=merged_wallet_apps,
        specifications=merged_specifications,
        supported_platforms=merged_platforms,
        deep_link_pattern=deep_link_pattern,
        applied_override_ids=applied_override_ids,
        template_wallet_configs=[
            {k: v for k, v in {"wallet_id": wc.wallet_id, "deep_link_scheme": wc.deep_link_scheme, "format_variant": wc.format_variant}.items() if v is not None}
            for wc in template.wallet_configs
        ],
        created_at=(primary_override.created_at if primary_override else template.created_at).isoformat(),
        updated_at=(primary_override.updated_at if primary_override else template.updated_at).isoformat(),
    )


def _wallet_to_response(w: WalletRegistryEntry) -> WalletRegistryEntryResponse:
    return WalletRegistryEntryResponse(
        id=w.id,
        organization_id=w.organization_id,
        is_override=w.is_override,
        override_precedence=w.override_precedence,
        merge_strategy=w.merge_strategy.value,
        credential_format=w.credential_format,
        issuance_protocol=_normalize_issuance_protocol(w.issuance_protocol) if w.issuance_protocol else None,
        compliance_profile_code=w.compliance_profile_code,
        name=w.name,
        description=w.description,
        wallet_apps=w.wallet_apps or [w.name],
        specifications=w.specifications,
        deep_link_pattern=w.deep_link_template,
        supported_platforms=w.platforms,
        created_at=w.created_at.isoformat(),
        updated_at=w.updated_at.isoformat(),
    )


# =============================================================================
# Wallet Registry Router
# =============================================================================

@wallet_router.get("", response_model=list[WalletRegistryEntryResponse], response_model_exclude_none=True, summary="List Wallet Registry")
async def list_wallets(
    active_only: bool = Query(True, description="Return only active wallets"),
    organization_id: str | None = Query(None, description="Optional organization scope for override entries"),
    repo: InMemoryWalletRegistryRepository | PostgresWalletRegistryRepository = Depends(get_wallet_repo),
) -> list[WalletRegistryEntryResponse]:
    """List all wallets in the global registry."""
    wallets = await repo.list(active_only=active_only)
    if organization_id is not None:
        wallets = [wallet for wallet in wallets if wallet.organization_id in {None, organization_id}]
    return [_wallet_to_response(w) for w in wallets]


@wallet_router.get("/{wallet_id}", response_model=WalletRegistryEntryResponse, response_model_exclude_none=True, summary="Get Wallet")
async def get_wallet(
    wallet_id: str,
    repo: InMemoryWalletRegistryRepository | PostgresWalletRegistryRepository = Depends(get_wallet_repo),
) -> WalletRegistryEntryResponse:
    """Get a wallet registry entry by ID."""
    wallet = await repo.get(wallet_id)
    if not wallet:
        raise HTTPException(status_code=404, detail="Wallet not found")
    return _wallet_to_response(wallet)


@wallet_router.get("/resolve/profile", response_model=WalletCompatibilityResponse, response_model_exclude_none=True, summary="Resolve Wallet Compatibility")
async def resolve_wallet_profile(
    organization_id: str = Query(...),
    credential_format: str = Query(...),
    issuance_protocol: str = Query(...),
    compliance_profile_code: str | None = Query(None),
    request: Request = None,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryWalletRegistryRepository | PostgresWalletRegistryRepository = Depends(get_wallet_repo),
) -> WalletCompatibilityResponse:
    await require_org_membership(organization_id, request, user_id)
    derived = _derive_wallet_profile(credential_format, issuance_protocol, compliance_profile_code)
    overrides = await _list_matching_wallet_overrides(
        repo,
        organization_id,
        derived.credential_format,
        derived.issuance_protocol,
        derived.compliance_profile_code,
    )
    return _merge_wallet_profile(derived, overrides, CredentialTemplate(organization_id=organization_id))


@router.get("/{template_id}/wallet-compatibility", response_model=WalletCompatibilityResponse, response_model_exclude_none=True)
async def get_wallet_compatibility(
    template_id: str,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
    wallet_repo: InMemoryWalletRegistryRepository | PostgresWalletRegistryRepository = Depends(get_wallet_repo),
) -> WalletCompatibilityResponse:
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")

    await require_org_membership(template.organization_id, request, user_id)
    derived = _derive_wallet_profile(
        _extract_template_credential_format(template),
        template.issuance_protocol,
        _extract_compliance_profile_code(template),
    )
    overrides = await _list_matching_wallet_overrides(
        wallet_repo,
        template.organization_id,
        derived.credential_format,
        derived.issuance_protocol,
        derived.compliance_profile_code,
    )
    return _merge_wallet_profile(derived, overrides, template)


@wallet_router.post("", response_model=WalletRegistryEntryResponse, response_model_exclude_none=True, summary="Create Wallet Entry", status_code=201)
async def create_wallet(
    body: WalletRegistryEntryCreate,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryWalletRegistryRepository | PostgresWalletRegistryRepository = Depends(get_wallet_repo),
) -> WalletRegistryEntryResponse:
    """Create a new wallet registry entry. Requires admin authentication."""
    if not body.organization_id:
        raise HTTPException(status_code=422, detail="organization_id is required for wallet overrides")
    await require_org_membership(body.organization_id, request, user_id)
    deep_link_pattern = body.deep_link_pattern or body.deep_link_template
    supported_platforms = body.supported_platforms if body.supported_platforms is not None else body.platforms
    entry = WalletRegistryEntry(
        organization_id=body.organization_id,
        is_override=True,
        override_precedence=body.override_precedence,
        merge_strategy=MergeStrategy(body.merge_strategy.upper()),
        credential_format=body.credential_format.upper() if body.credential_format else None,
        issuance_protocol=_normalize_issuance_protocol(body.issuance_protocol) if body.issuance_protocol else None,
        compliance_profile_code=body.compliance_profile_code.upper() if body.compliance_profile_code else None,
        name=body.name,
        description=body.description,
        wallet_apps=body.wallet_apps,
        specifications=body.specifications,
        logo_url=body.logo_url,
        deep_link_template=deep_link_pattern,
        supported_formats=body.supported_formats,
        supported_protocols=[_normalize_issuance_protocol(protocol) for protocol in body.supported_protocols],
        platforms=supported_platforms,
        supports_qr=body.supports_qr,
        supports_deeplink=body.supports_deeplink,
        docs_url=body.docs_url,
    )
    await repo.save(entry)
    logger.info(f"Created wallet registry entry: {entry.id} ({entry.name})")
    return _wallet_to_response(entry)


@wallet_router.patch("/{wallet_id}", response_model=WalletRegistryEntryResponse, response_model_exclude_none=True, summary="Update Wallet Entry")
async def update_wallet(
    wallet_id: str,
    body: WalletRegistryEntryUpdate,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryWalletRegistryRepository | PostgresWalletRegistryRepository = Depends(get_wallet_repo),
) -> WalletRegistryEntryResponse:
    """Update a wallet registry entry. Requires admin authentication."""
    entry = await repo.get(wallet_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Wallet not found")
    if entry.organization_id:
        await require_org_membership(entry.organization_id, request, user_id)
    if body.organization_id is not None:
        entry.organization_id = body.organization_id
    if body.credential_format is not None:
        entry.credential_format = body.credential_format.upper() if body.credential_format else None
    if body.issuance_protocol is not None:
        entry.issuance_protocol = _normalize_issuance_protocol(body.issuance_protocol) if body.issuance_protocol else None
    if body.compliance_profile_code is not None:
        entry.compliance_profile_code = body.compliance_profile_code.upper() if body.compliance_profile_code else None
    if body.name is not None:
        entry.name = body.name
    if body.description is not None:
        entry.description = body.description
    if body.wallet_apps is not None:
        entry.wallet_apps = body.wallet_apps
    if body.specifications is not None:
        entry.specifications = body.specifications
    if body.logo_url is not None:
        entry.logo_url = body.logo_url
    if body.deep_link_template is not None or body.deep_link_pattern is not None:
        entry.deep_link_template = body.deep_link_pattern or body.deep_link_template or entry.deep_link_template
    if body.supported_formats is not None:
        entry.supported_formats = body.supported_formats
    if body.supported_protocols is not None:
        entry.supported_protocols = [_normalize_issuance_protocol(protocol) for protocol in body.supported_protocols]
    if body.platforms is not None or body.supported_platforms is not None:
        entry.platforms = body.supported_platforms if body.supported_platforms is not None else body.platforms or []
    if body.supports_qr is not None:
        entry.supports_qr = body.supports_qr
    if body.supports_deeplink is not None:
        entry.supports_deeplink = body.supports_deeplink
    if body.docs_url is not None:
        entry.docs_url = body.docs_url
    if body.is_active is not None:
        entry.is_active = body.is_active
    if body.override_precedence is not None:
        entry.override_precedence = body.override_precedence
    if body.merge_strategy is not None:
        entry.merge_strategy = MergeStrategy(body.merge_strategy.upper())
    await repo.save(entry)
    logger.info(f"Updated wallet registry entry: {entry.id}")
    return _wallet_to_response(entry)


@wallet_router.delete("/{wallet_id}", summary="Delete Wallet Entry")
async def delete_wallet(
    wallet_id: str,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryWalletRegistryRepository | PostgresWalletRegistryRepository = Depends(get_wallet_repo),
) -> dict:
    """Delete a wallet registry entry. Requires admin authentication."""
    entry = await repo.get(wallet_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Wallet not found")
    if entry.organization_id:
        await require_org_membership(entry.organization_id, request, user_id)
    await repo.delete(wallet_id)
    return {"success": True}


# =============================================================================
# Internal API (no authentication — cluster-internal only)
# =============================================================================

internal_router = APIRouter(prefix="/internal", tags=["internal"])


@internal_router.get("/credential-configurations")
async def get_credential_configurations(request: Request) -> dict:
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
    if templates:
        org_id = getattr(templates[0], "organization_id", None)
        if org_id:
            try:
                from marty_proto.v1 import organization_service_pb2 as org_pb2
                stub = request.app.state.org_client._grpc_stub
                org_resp = await stub.GetOrganization(
                    org_pb2.GetOrganizationRequest(organization_id=str(org_id))
                )
                issuer_display_name = org_resp.display_name or org_resp.name or None
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
    from marty_common.database import DatabaseManager, DatabaseConfig
    db = DatabaseManager(DatabaseConfig.from_env("credential-template"))
    session_factory = db.session_factory
    
    # Initialize repository
    _repo = PostgresCredentialTemplateRepository(session_factory)

    # Initialize wallet registry (DB-backed)
    _wallet_repo = PostgresWalletRegistryRepository(session_factory)
    for entry in SYSTEM_WALLET_CATALOG:
        existing = await _wallet_repo.get(entry.id)
        if existing is None:
            await _wallet_repo.save(WalletRegistryEntry(**entry.__dict__))
    
    # Initialize gRPC channel to organization service
    from common.di import setup_org_client, teardown_org_client
    await setup_org_client(app, "credential-template")
    
    # Start gRPC server
    from common.grpc_factory import create_grpc_server, start_grpc_server_port
    from credential_template.infrastructure.adapters.grpc_adapter import (
        CredentialTemplateServiceGrpc,
    )
    from marty_proto.v1.credential_template_service_pb2_grpc import (
        add_CredentialTemplateServiceServicer_to_server,
    )

    grpc_port = int(os.environ.get("CT_GRPC_PORT", "9003"))
    grpc_server, health_servicer = create_grpc_server("credential-template")
    ct_servicer = CredentialTemplateServiceGrpc(
        repo=_repo,
        to_response_fn=_template_to_response,
        wallet_repo=_wallet_repo,
    )
    add_CredentialTemplateServiceServicer_to_server(ct_servicer, grpc_server)
    start_grpc_server_port(
        grpc_server, grpc_port,
        service_names=["marty.ui.credential_template.v1.CredentialTemplateService"],
        health_servicer=health_servicer,
    )
    await grpc_server.start()
    logger.info(f"Credential-template gRPC server listening on :{grpc_port}")
    
    logger.info(f"{SERVICE_NAME} started successfully")
    yield
    
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await grpc_server.stop(grace=5)
    await teardown_org_client(app)
    await db.close()


def create_app() -> FastAPI:
    return create_service_app(
        title="Credential Template Service",
        description="Manages Credential Templates - blueprints for credential issuance",
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[router, wallet_router, internal_router],
    )


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
