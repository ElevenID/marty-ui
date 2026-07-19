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
import json
import os
import re
import uuid
import httpx
import copy

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator
from urllib.parse import parse_qs, quote, urlparse

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from typing import Annotated
from marty_common import OrganizationContext, require_org_membership
from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware
from marty_common.service_setup import create_service_app

from credential_template.infrastructure.adapters import (
    PostgresCredentialTemplateRepository,
    PostgresDeliveryDestinationRepository,
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


class IosSameDeviceMode(str, Enum):
    DIGITAL_CREDENTIALS = "digital_credentials"
    UNIVERSAL_LINK = "universal_link"
    NESTED_LINK = "nested_link"
    PROTOCOL_ONLY = "protocol_only"
    UNSUPPORTED = "unsupported"


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
    issuer_profile_id: str | None = None
    application_template_id: str | None = None
    trust_profile_id: str | None = None
    revocation_profile_id: str | None = None
    issuer_key_id: str | None = None
    issuer_algorithm: str | None = None
    key_access_mode: str | None = None
    remote_signing_config: dict[str, Any] | None = None
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
            selective_disclosure_fields=self.selective_disclosure_fields.copy(),
            zk_predicate_claims=self.zk_predicate_claims.copy(),
            derived_attributes=self.derived_attributes.copy(),
            display_style=self.display_style,
            validity_rules=self.validity_rules,
            issuer_requirements=self.issuer_requirements,
            supported_formats=self.supported_formats.copy(),
            compliance_profile=self.compliance_profile.copy() if isinstance(self.compliance_profile, dict) else self.compliance_profile,
            compliance_profile_id=self.compliance_profile_id,
            issuer_profile_id=self.issuer_profile_id,
            application_template_id=self.application_template_id,
            trust_profile_id=self.trust_profile_id,
            revocation_profile_id=self.revocation_profile_id,
            issuer_key_id=self.issuer_key_id,
            issuer_algorithm=self.issuer_algorithm,
            key_access_mode=self.key_access_mode,
            remote_signing_config=self.remote_signing_config.copy() if isinstance(self.remote_signing_config, dict) else self.remote_signing_config,
            issuer_certificate_chain_pem=self.issuer_certificate_chain_pem,
            issuer_did=self.issuer_did,
            auto_generate_artifacts=self.auto_generate_artifacts,
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
    routing_templates: dict[str, str] = field(default_factory=dict)
    install_urls: dict[str, str] = field(default_factory=dict)
    ios_scheme: str | None = None
    universal_link_template: str | None = None
    android_package: str | None = None
    supported_formats: list[str] = field(default_factory=list)
    supported_protocols: list[str] = field(default_factory=lambda: ["OID4VCI_PRE_AUTH"])
    platforms: list[str] = field(default_factory=list)
    supports_qr: bool = True
    supports_deeplink: bool = True
    supports_digital_credentials: bool = False
    supports_haip: bool = False
    docs_url: str | None = None
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DeliveryDestinationEntry:
    """Registry entry for places issued credentials can be delivered or published."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str | None = None
    is_system: bool = False
    name: str = ""
    description: str | None = None
    provider: str = "custom"
    mode: str = "holder_wallet"
    setup_actor: str = "learner"
    delivery_target: str = "wallet"
    wallet_profile_id: str | None = None
    credential_format: str | None = None
    issuance_protocol: str | None = None
    compliance_profile_code: str | None = None
    connector_type: str | None = None
    connector_id: str | None = None
    requires_consent: bool = False
    claim_projection_policy: dict[str, Any] = field(default_factory=dict)
    setup_requirements: list[str] = field(default_factory=list)
    capabilities: dict[str, bool] = field(default_factory=dict)
    docs_url: str | None = None
    is_enabled: bool = True
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
        routing_templates={
            "generic": "openid-credential-offer://?{credential_offer_param}={offer_encoded}",
            "ios": "openid-credential-offer://?{credential_offer_param}={offer_encoded}",
            "android": "intent://?{credential_offer_param}={offer_encoded}#Intent;scheme=openid-credential-offer;package=com.spruceid.mobilesdkexample;end",
        },
        install_urls={
            "ios": "https://apps.apple.com/search?term=SpruceKit",
            "android": "https://play.google.com/store/search?q=SpruceKit&c=apps",
        },
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
        routing_templates={
            "generic": "marty-authenticator://open?inner={inner_uri_encoded}",
            "ios": "marty-authenticator://open?inner={inner_uri_encoded}",
            "android": "marty-authenticator://open?inner={inner_uri_encoded}",
        },
        ios_scheme="marty-authenticator",
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
        description="walt.id community wallet retained for interoperability tracking.",
        wallet_apps=["walt.id Wallet"],
        specifications=["OID4VCI", "OID4VP"],
        logo_url="https://walt.id/favicon.ico",
        deep_link_template="openid-credential-offer://?{credential_offer_param}={offer_encoded}",
        routing_templates={
            "generic": "openid-credential-offer://?{credential_offer_param}={offer_encoded}",
            "web": "https://wallet.demo.walt.id/api/siop/initiateIssuance?{credential_offer_param}={offer_encoded}",
            "desktop": "https://wallet.demo.walt.id/api/siop/initiateIssuance?{credential_offer_param}={offer_encoded}",
        },
        supported_formats=["sd_jwt_vc", "jwt_vc", "mdoc"],
        platforms=["ios", "android", "web"],
        docs_url="https://docs.walt.id",
        is_active=False,
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
        routing_templates={
            "generic": "openid-credential-offer://?credential_offer={offer_encoded}",
            "android": "openid-credential-offer://?credential_offer={offer_encoded}",
        },
        android_package="com.google.android.gms",
        supports_digital_credentials=True,
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
        routing_templates={
            "generic": "openid-credential-offer://?credential_offer={offer_encoded}",
            "ios": "openid-credential-offer://?credential_offer={offer_encoded}",
        },
        supports_digital_credentials=True,
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


SYSTEM_DELIVERY_DESTINATION_CATALOG: tuple[DeliveryDestinationEntry, ...] = (
    DeliveryDestinationEntry(
        id="dd-elevenid-wallet",
        is_system=True,
        name="ElevenID Wallet",
        description="Add the credential to the holder's ElevenID-compatible wallet using OID4VCI.",
        provider="elevenid_wallet",
        mode="holder_wallet",
        setup_actor="learner",
        delivery_target="wallet",
        wallet_profile_id="wr-marty-001",
        issuance_protocol="OID4VCI_PRE_AUTH",
        requires_consent=False,
        claim_projection_policy={"mode": "full_credential_reference"},
        capabilities={
            "holder_wallet": True,
            "oid4vci": True,
            "post_issuance_publish": False,
        },
    ),
    DeliveryDestinationEntry(
        id="dd-oid4vci-compatible-wallet",
        is_system=True,
        name="Compatible Wallet",
        description="Open the standards-based credential offer in any compatible OID4VCI wallet.",
        provider="oid4vci_wallet",
        mode="holder_wallet",
        setup_actor="learner",
        delivery_target="wallet",
        wallet_profile_id="wr-default",
        issuance_protocol="OID4VCI_PRE_AUTH",
        requires_consent=False,
        claim_projection_policy={"mode": "full_credential_reference"},
        capabilities={
            "holder_wallet": True,
            "oid4vci": True,
            "post_issuance_publish": False,
        },
    ),
    DeliveryDestinationEntry(
        id="dd-canvas-credentials-institutional",
        is_system=True,
        name="Canvas Credentials",
        description=(
            "Publish a public Open Badge view to Canvas Credentials after canonical "
            "ElevenID issuance. Requires organization-managed Canvas Credentials setup."
        ),
        provider="canvas_credentials",
        mode="organization_mirror",
        setup_actor="org_admin",
        delivery_target="canvas_credentials",
        credential_format="VC_JWT",
        issuance_protocol="DIRECT",
        compliance_profile_code="OB3_JWT",
        connector_type="canvas_platform",
        requires_consent=True,
        claim_projection_policy={
            "mode": "public_badge",
            "allowed_claims": [
                "achievement",
                "result",
                "learning_context",
                "issuer",
                "credentialSubject",
                "credentialStatus",
                "provenance",
            ],
        },
        setup_requirements=[
            "Canvas Credentials issuer/API access configured by an organization admin",
            "Canvas Credentials API token referenced from an org-scoped secret or issuance secret layer",
            "Canvas Credentials badgeclass/entity ID mapped to the credential template, program binding, or delivery destination",
            "Canvas program binding enabled for Canvas mirror delivery",
        ],
        capabilities={
            "holder_wallet": False,
            "org_managed": True,
            "post_issuance_publish": True,
            "status_sync": True,
            "provenance": True,
            "badgr_api": True,
        },
        docs_url="https://developerdocs.instructure.com/services/credentials",
    ),
    DeliveryDestinationEntry(
        id="dd-canvas-credentials-backpack",
        is_system=True,
        name="Canvas Credentials Backpack",
        description="Let a learner connect a personal Canvas/Parchment backpack when OAuth setup is available.",
        provider="canvas_credentials_backpack",
        mode="learner_backpack",
        setup_actor="learner",
        delivery_target="external_api",
        connector_type="canvas_credentials_oauth",
        requires_consent=True,
        claim_projection_policy={"mode": "public_badge"},
        setup_requirements=[
            "Learner authorizes their own backpack account",
            "Organization enables backpack import as an allowed destination",
        ],
        capabilities={
            "holder_wallet": False,
            "learner_owned": True,
            "oauth_required": True,
            "post_issuance_publish": True,
        },
        docs_url="https://developerdocs.instructure.com/services/credentials",
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


class InMemoryDeliveryDestinationRepository:
    """In-memory delivery destination registry seeded with system destinations."""

    def __init__(self) -> None:
        self._destinations: dict[str, DeliveryDestinationEntry] = {
            entry.id: DeliveryDestinationEntry(**entry.__dict__)
            for entry in SYSTEM_DELIVERY_DESTINATION_CATALOG
        }

    async def save(self, entry: DeliveryDestinationEntry) -> None:
        entry.updated_at = datetime.now(timezone.utc)
        self._destinations[entry.id] = entry

    async def get(self, destination_id: str) -> DeliveryDestinationEntry | None:
        return self._destinations.get(destination_id)

    async def list(
        self,
        *,
        active_only: bool = True,
        organization_id: str | None = None,
        provider: str | None = None,
        mode: str | None = None,
    ) -> list[DeliveryDestinationEntry]:
        destinations = list(self._destinations.values())
        if active_only:
            destinations = [entry for entry in destinations if entry.is_enabled]
        if organization_id is not None:
            destinations = [
                entry for entry in destinations
                if entry.is_system or entry.organization_id == organization_id
            ]
        if provider:
            destinations = [entry for entry in destinations if entry.provider == provider]
        if mode:
            destinations = [entry for entry in destinations if entry.mode == mode]
        return sorted(destinations, key=lambda entry: (0 if entry.is_system else 1, entry.name.lower()))

    async def delete(self, destination_id: str) -> None:
        self._destinations.pop(destination_id, None)


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


class DerivedAttributeModel(BaseModel):
    name: str
    description: str | None = None
    source_claim: str
    derivation_type: str  # age_over, range, presence
    parameters: dict = {}


class CreateCredentialTemplateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
    supported_formats: list[str] = ["SD_JWT_VC"]
    application_template_id: str | None = None
    trust_profile_id: str | None = None
    revocation_profile_id: str | None = None
    # Compliance
    compliance_profile_id: str = Field(min_length=1, max_length=255)
    issuer_key_id: str | None = None
    issuer_algorithm: str | None = None
    signing_algorithm: str | None = None
    key_access_mode: str | None = None
    remote_signing_config: dict[str, Any] | None = None
    issuer_certificate_chain_pem: str | None = None
    issuer_did: str | None = None
    issuer_profile_id: str | None = None
    auto_generate_artifacts: bool = False
    credential_payload_format: str | None = None
    schema_uri: dict | None = None


class UpdateCredentialTemplateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    claims: list[ClaimDefinitionModel] | None = None
    privacy_posture: str | None = None
    selective_disclosure_fields: list[str] | None = None
    zk_predicate_claims: list[str] | None = None
    derived_attributes: list[DerivedAttributeModel] | None = None
    display_style: DisplayStyleModel | None = None
    validity_rules: ValidityRulesModel | None = None
    supported_formats: list[str] | None = None
    application_template_id: str | None = None
    trust_profile_id: str | None = None
    revocation_profile_id: str | None = None
    issuer_key_id: str | None = None
    issuer_algorithm: str | None = None
    signing_algorithm: str | None = None
    key_access_mode: str | None = None
    remote_signing_config: dict[str, Any] | None = None
    issuer_certificate_chain_pem: str | None = None
    issuer_did: str | None = None
    issuer_profile_id: str | None = None
    auto_generate_artifacts: bool | None = None
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
    issuer_profile_id: str | None = None
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
    issuer_certificate_chain_configured: bool = False
    artifacts_status: str = "missing"
    hasArtifacts: bool = False
    artifactsValidated: bool = False
    usedByFlowsCount: int = 0
    privacy_posture: dict | None = None
    wallet_configs_json: str | None = None  # JSON string of wallet configs for per-wallet offers
    created_at: str
    updated_at: str


def _days_from_seconds(seconds: int) -> int:
    return max(1, (int(seconds) + SECONDS_PER_DAY - 1) // SECONDS_PER_DAY)


def _resolve_auto_generate_artifacts(
    auto_generate_artifacts: bool | None,
) -> bool:
    """Resolve the canonical auto-generate flag."""
    return bool(auto_generate_artifacts)


def _artifact_material_count(template: CredentialTemplate) -> int:
    return sum(
        1
        for value in (
            template.issuer_key_id,
            template.issuer_certificate_chain_pem,
            template.remote_signing_config,
        )
        if value
    )


def _artifacts_status(template: CredentialTemplate) -> str:
    material_count = _artifact_material_count(template)
    if template.auto_generate_artifacts or material_count > 0:
        return "valid"
    if template.issuer_did:
        return "invalid"
    return "missing"


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
    routing_templates: dict[str, str] = Field(default_factory=dict)
    install_urls: dict[str, str] = Field(default_factory=dict)
    ios_scheme: str | None = None
    universal_link_template: str | None = None
    android_package: str | None = None
    supported_formats: list[str] = Field(default_factory=list)
    supported_protocols: list[str] = Field(default_factory=lambda: ["OID4VCI_PRE_AUTH"])
    platforms: list[str] = Field(default_factory=list)
    supported_platforms: list[str] | None = None
    supports_qr: bool = True
    supports_deeplink: bool = True
    supports_digital_credentials: bool = False
    supports_haip: bool = False
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
    routing_templates: dict[str, str] | None = None
    install_urls: dict[str, str] = Field(default_factory=dict)
    ios_scheme: str | None = None
    universal_link_template: str | None = None
    android_package: str | None = None
    supported_formats: list[str] | None = None
    supported_protocols: list[str] | None = None
    platforms: list[str] | None = None
    supported_platforms: list[str] | None = None
    supports_qr: bool | None = None
    supports_deeplink: bool | None = None
    supports_digital_credentials: bool | None = None
    supports_haip: bool | None = None
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
    logo_url: str | None = None
    deep_link_pattern: str
    routing_templates: dict[str, str] = Field(default_factory=dict)
    install_urls: dict[str, str] | None = None
    ios_scheme: str | None = None
    universal_link_template: str | None = None
    android_package: str | None = None
    supported_formats: list[str] = Field(default_factory=list)
    supported_protocols: list[str] = Field(default_factory=list)
    supported_platforms: list[str]
    supports_qr: bool = True
    supports_deeplink: bool = True
    supports_digital_credentials: bool = False
    supports_haip: bool = False
    ios_same_device_mode: str
    ios_same_device_single_wallet_only: bool = False
    oid4vci_profile: dict[str, str] | None = None
    docs_url: str | None = None
    capabilities: dict[str, bool] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class WalletOpenLinkResponse(BaseModel):
    wallet_id: str
    inner_uri: str
    open_uri: str
    platform: str | None = None
    transport: str = "wallet_deeplink"


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


class DeliveryDestinationCreate(BaseModel):
    organization_id: str
    id: str | None = None
    name: str
    description: str | None = None
    provider: str = "custom"
    mode: str = "holder_wallet"
    setup_actor: str = "learner"
    delivery_target: str = "wallet"
    wallet_profile_id: str | None = None
    credential_format: str | None = None
    issuance_protocol: str | None = None
    compliance_profile_code: str | None = None
    connector_type: str | None = None
    connector_id: str | None = None
    requires_consent: bool = False
    claim_projection_policy: dict[str, Any] = Field(default_factory=dict)
    setup_requirements: list[str] = Field(default_factory=list)
    capabilities: dict[str, bool] = Field(default_factory=dict)
    docs_url: str | None = None
    is_enabled: bool = True


class DeliveryDestinationUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    provider: str | None = None
    mode: str | None = None
    setup_actor: str | None = None
    delivery_target: str | None = None
    wallet_profile_id: str | None = None
    credential_format: str | None = None
    issuance_protocol: str | None = None
    compliance_profile_code: str | None = None
    connector_type: str | None = None
    connector_id: str | None = None
    requires_consent: bool | None = None
    claim_projection_policy: dict[str, Any] | None = None
    setup_requirements: list[str] | None = None
    capabilities: dict[str, bool] | None = None
    docs_url: str | None = None
    is_enabled: bool | None = None


class DeliveryDestinationResponse(BaseModel):
    id: str
    organization_id: str | None = None
    is_system: bool
    name: str
    description: str | None = None
    provider: str
    mode: str
    setup_actor: str
    delivery_target: str
    wallet_profile_id: str | None = None
    credential_format: str | None = None
    issuance_protocol: str | None = None
    compliance_profile_code: str | None = None
    connector_type: str | None = None
    connector_id: str | None = None
    requires_consent: bool
    claim_projection_policy: dict[str, Any] = Field(default_factory=dict)
    setup_requirements: list[str] = Field(default_factory=list)
    capabilities: dict[str, bool] = Field(default_factory=dict)
    docs_url: str | None = None
    is_enabled: bool
    created_at: str
    updated_at: str


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/credential-templates", tags=["credential-templates"])
wallet_router = APIRouter(prefix="/v1/wallet-registry", tags=["wallet-registry"])
delivery_destination_router = APIRouter(prefix="/v1/delivery-destinations", tags=["delivery-destinations"])

_repo: InMemoryCredentialTemplateRepository | None = None
_wallet_repo: InMemoryWalletRegistryRepository | PostgresWalletRegistryRepository | None = None
DeliveryDestinationRepository = InMemoryDeliveryDestinationRepository | PostgresDeliveryDestinationRepository
_delivery_destination_repo: DeliveryDestinationRepository | None = None


def get_repo() -> InMemoryCredentialTemplateRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


def get_wallet_repo() -> InMemoryWalletRegistryRepository | PostgresWalletRegistryRepository:
    if _wallet_repo is None:
        raise RuntimeError("Wallet registry not configured")
    return _wallet_repo


def get_delivery_destination_repo() -> DeliveryDestinationRepository:
    if _delivery_destination_repo is None:
        raise RuntimeError("Delivery destination registry not configured")
    return _delivery_destination_repo


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


def _read_secret_value(name: str) -> str:
    value = os.environ.get(name)
    if value:
        return value.strip()
    file_path = os.environ.get(f"{name}_FILE")
    if file_path:
        try:
            with open(file_path, encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError:
            logger.warning("Unable to read %s_FILE at %s", name, file_path, exc_info=True)
    return ""


def _key_purpose_for_credential_format(value: str | None) -> str:
    normalized = (value or "").strip().lower().replace("-", "_")
    if normalized in {"mso_mdoc", "mdoc", "zk_mdoc"}:
        return "mdoc_dsc"
    if normalized in {"vds_nc", "vdsnc"}:
        return "vdsnc_signing"
    return "vc_jwt_issuer"


def _first_non_empty(*values: Any) -> str | None:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def _compact_dict(value: dict[str, Any]) -> dict[str, Any]:
    return {
        key: entry
        for key, entry in value.items()
        if entry is not None and entry != ""
    }


def _canonical_issuer_fields(
    issuer_context: dict[str, Any],
    *,
    requested_algorithm: str | None = None,
) -> dict[str, Any]:
    profile = issuer_context.get("issuer_profile")
    if not isinstance(profile, dict):
        profile = {}
    service = issuer_context.get("service")
    if not isinstance(service, dict):
        service = {}

    signing_service_id = _first_non_empty(
        issuer_context.get("signing_service_id"),
        profile.get("signing_service_id"),
        service.get("id"),
    )
    signing_key_reference = _first_non_empty(
        issuer_context.get("signing_key_reference"),
        profile.get("signing_key_reference"),
        service.get("key_reference"),
    )
    verification_method_id = _first_non_empty(
        issuer_context.get("verification_method_id"),
        profile.get("verification_method_id"),
    )
    key_purpose = _first_non_empty(
        issuer_context.get("key_purpose"),
        profile.get("key_purpose"),
    )
    algorithm = _first_non_empty(
        requested_algorithm,
        issuer_context.get("algorithm"),
        profile.get("algorithm"),
        service.get("algorithm"),
    )

    return {
        "issuer_profile_id": _first_non_empty(
            issuer_context.get("issuer_profile_id"),
            profile.get("id"),
        ),
        "issuer_key_id": signing_key_reference or verification_method_id or signing_service_id,
        "issuer_algorithm": algorithm,
        "key_access_mode": "REMOTE_SIGNING",
        "remote_signing_config": _compact_dict({
            "provider": "managed-signing-service",
            "signing_service_id": signing_service_id,
            "signing_key_reference": signing_key_reference,
            "verification_method_id": verification_method_id,
            "key_purpose": key_purpose,
        }),
        "issuer_did": _first_non_empty(
            issuer_context.get("issuer_did"),
            profile.get("issuer_did"),
        ),
    }


async def _require_active_issuer_profile(
    request: Request,
    *,
    organization_id: str,
    issuer_profile_id: str | None,
    credential_format: str | None = None,
    algorithm: str | None = None,
) -> dict[str, Any]:
    if not issuer_profile_id or not str(issuer_profile_id).strip():
        raise HTTPException(
            status_code=422,
            detail="issuer_profile_id is required. Credential templates must use an active KMS-backed issuer profile.",
        )

    base_url = os.environ.get("SIGNING_KEYS_INTERNAL_URL", "http://gateway:8000/internal/signing-keys").rstrip("/")
    api_key = _read_secret_value("SIGNING_KEYS_INTERNAL_API_KEY") or _read_secret_value("ISSUANCE_API_KEY")
    headers = {"X-API-Key": api_key} if api_key else {}
    request_id = getattr(request.state, "request_id", None)
    if request_id:
        headers["X-Request-ID"] = request_id

    params = {
        "organization_id": organization_id,
        "issuer_profile_id": issuer_profile_id,
        "key_purpose": _key_purpose_for_credential_format(credential_format),
    }
    if credential_format:
        params["credential_format"] = credential_format
    if algorithm:
        params["algorithm"] = algorithm

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(f"{base_url}/issuer-context", params=params, headers=headers)
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to validate issuer profile through signing-keys service: {exc}",
        ) from exc

    if response.status_code == 404:
        raise HTTPException(
            status_code=422,
            detail="issuer_profile_id must reference an active issuer profile for this organization.",
        )
    if response.status_code == 409:
        raise HTTPException(status_code=422, detail=response.text)
    if response.status_code >= 400:
        raise HTTPException(
            status_code=503,
            detail=f"Signing-keys issuer profile validation failed with status {response.status_code}.",
        )

    payload = response.json()
    if not payload.get("ok") or not payload.get("signing_service_id") or not payload.get("issuer_did"):
        raise HTTPException(
            status_code=422,
            detail="issuer_profile_id did not resolve to a KMS-backed issuer profile.",
        )
    return payload


def _issuer_identifier_candidates(value: str | None) -> set[str]:
    identifier = str(value or "").strip()
    if not identifier:
        return set()
    candidates = {identifier}
    if "#" in identifier:
        candidates.add(identifier.split("#", 1)[0])
    return candidates


def _trust_profile_issuer_identifiers(profile: dict[str, Any]) -> set[str]:
    identifiers: set[str] = set()
    for issuer in profile.get("allowed_issuers") or []:
        if isinstance(issuer, str):
            identifiers.update(_issuer_identifier_candidates(issuer))
        elif isinstance(issuer, dict):
            identifiers.update(
                _issuer_identifier_candidates(issuer.get("issuer_did") or issuer.get("issuer_id"))
            )
    for source in profile.get("trust_sources") or []:
        if not isinstance(source, dict) or source.get("enabled") is False:
            continue
        identifiers.update(
            _issuer_identifier_candidates(source.get("issuer_did") or source.get("issuer_id"))
        )
    return identifiers


async def _require_trust_profile_accepts_issuer(
    *,
    trust_profile_id: str | None,
    issuer_did: str | None,
) -> None:
    if not trust_profile_id:
        return
    if not issuer_did:
        raise HTTPException(status_code=422, detail="The active issuer profile did not provide an issuer DID.")

    base_url = os.environ.get("TRUST_PROFILE_SERVICE_URL", "http://trust-profile:8004").rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.get(f"{base_url}/internal/v1/trust-profiles/{trust_profile_id}")
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to validate the Trust Profile: {exc}",
        ) from exc

    if response.status_code == 404:
        raise HTTPException(status_code=422, detail="trust_profile_id does not reference a Trust Profile.")
    if response.status_code >= 400:
        raise HTTPException(
            status_code=503,
            detail=f"Trust Profile validation failed with status {response.status_code}.",
        )

    profile = response.json()
    if str(profile.get("status") or "").strip().lower() != "active":
        raise HTTPException(status_code=422, detail="Credential Templates require an active Trust Profile.")

    trusted_identifiers = _trust_profile_issuer_identifiers(profile)
    if trusted_identifiers and _issuer_identifier_candidates(issuer_did).isdisjoint(trusted_identifiers):
        raise HTTPException(
            status_code=422,
            detail=(
                "The selected Trust Profile does not trust the selected issuer profile. "
                "Add the issuer DID to the Trust Profile before activation."
            ),
        )


async def _require_active_revocation_profile(
    *,
    organization_id: str,
    revocation_profile_id: str | None,
) -> None:
    if not revocation_profile_id or not str(revocation_profile_id).strip():
        raise HTTPException(
            status_code=422,
            detail="revocation_profile_id is required before a Credential Template can be activated.",
        )

    import grpc
    from marty_proto.v1 import revocation_profile_service_pb2 as rp_pb2
    from marty_proto.v1 import revocation_profile_service_pb2_grpc as rp_grpc

    target = os.environ.get("RP_GRPC_TARGET", "revocation-profile:9013")
    try:
        async with grpc.aio.insecure_channel(target) as channel:
            response = await rp_grpc.RevocationProfileServiceStub(channel).GetRevocationProfile(
                rp_pb2.GetRevocationProfileRequest(profile_id=revocation_profile_id),
                timeout=3.0,
            )
    except grpc.aio.AioRpcError as exc:
        if exc.code() == grpc.StatusCode.NOT_FOUND:
            raise HTTPException(
                status_code=422,
                detail="revocation_profile_id does not reference a Revocation Profile.",
            ) from exc
        raise HTTPException(
            status_code=503,
            detail=f"Unable to validate the Revocation Profile: {exc.details() or exc.code().name}.",
        ) from exc

    if response.organization_id != organization_id:
        raise HTTPException(
            status_code=422,
            detail="The selected Revocation Profile belongs to another organization.",
        )
    if str(response.status or "").strip().lower() != "active":
        raise HTTPException(
            status_code=422,
            detail="Credential Templates require an active Revocation Profile.",
        )


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

    issuer_context = await _require_active_issuer_profile(
        request,
        organization_id=body.organization_id,
        issuer_profile_id=body.issuer_profile_id,
        credential_format=format_to_wire(CredentialFormat(credential_payload_format)),
        algorithm=body.issuer_algorithm or body.signing_algorithm,
    )
    issuer_fields = _canonical_issuer_fields(
        issuer_context,
        requested_algorithm=body.issuer_algorithm or body.signing_algorithm,
    )

    resolved_vct = body.vct or f"https://credentials.example.com/{body.credential_type}"
    _validate_template_protocol_requirements(
        compliance_profile=None,
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
        application_template_id=body.application_template_id,
        trust_profile_id=body.trust_profile_id,
        revocation_profile_id=body.revocation_profile_id,
        privacy_posture=PrivacyPosture(body.privacy_posture),
        selective_disclosure_fields=body.selective_disclosure_fields,
        zk_predicate_claims=body.zk_predicate_claims,
        supported_formats=supported_formats,
        wallet_configs=[],
        issuance_protocol="oid4vci",
        credential_payload_format=credential_payload_format,
        compliance_profile=None,
        compliance_profile_id=body.compliance_profile_id,
        issuer_profile_id=issuer_fields["issuer_profile_id"],
        issuer_key_id=issuer_fields["issuer_key_id"],
        issuer_algorithm=issuer_fields["issuer_algorithm"],
        key_access_mode=issuer_fields["key_access_mode"],
        remote_signing_config=issuer_fields["remote_signing_config"],
        issuer_certificate_chain_pem=body.issuer_certificate_chain_pem,
        issuer_did=issuer_fields["issuer_did"],
        auto_generate_artifacts=_resolve_auto_generate_artifacts(
            body.auto_generate_artifacts,
        ),
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
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Update a Credential Template (only allowed in draft status).
    
    Note: Requires user authentication. Org membership verified via template's org_id.
    """
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")

    await require_org_membership(template.organization_id, fastapi_request, user_id)
    
    if template.status != TemplateStatus.DRAFT:
        raise HTTPException(
            status_code=400, 
            detail="Only draft templates can be modified. Create a new version instead."
        )

    candidate = copy.deepcopy(template)
    
    if request.name is not None:
        candidate.name = request.name
    if request.description is not None:
        candidate.description = request.description
    if request.privacy_posture is not None:
        candidate.privacy_posture = PrivacyPosture(request.privacy_posture)
    if request.selective_disclosure_fields is not None:
        candidate.selective_disclosure_fields = request.selective_disclosure_fields
    if request.zk_predicate_claims is not None:
        candidate.zk_predicate_claims = request.zk_predicate_claims
    if request.application_template_id is not None:
        candidate.application_template_id = request.application_template_id
    if request.trust_profile_id is not None:
        candidate.trust_profile_id = request.trust_profile_id
    if request.revocation_profile_id is not None:
        candidate.revocation_profile_id = request.revocation_profile_id
    if request.issuer_profile_id is not None:
        candidate.issuer_profile_id = request.issuer_profile_id
    if request.issuer_algorithm is not None or request.signing_algorithm is not None:
        candidate.issuer_algorithm = request.issuer_algorithm or request.signing_algorithm
    if request.issuer_certificate_chain_pem is not None:
        candidate.issuer_certificate_chain_pem = request.issuer_certificate_chain_pem
    if request.auto_generate_artifacts is not None:
        candidate.auto_generate_artifacts = _resolve_auto_generate_artifacts(
            request.auto_generate_artifacts,
        )
    supported_formats = candidate.supported_formats
    if request.supported_formats is not None:
        supported_formats = [normalize_credential_format(f) for f in request.supported_formats]
        candidate.supported_formats = supported_formats
    if request.credential_payload_format is not None:
        try:
            candidate.credential_payload_format = normalize_credential_payload_format(
                request.credential_payload_format,
                supported_formats,
            )
        except ValueError as e:
            raise HTTPException(status_code=422, detail=str(e))
    if request.validity_rules is not None:
        candidate.validity_rules = _resolve_validity_rules(request.validity_rules, candidate.validity_rules)

    _validate_template_protocol_requirements(
        compliance_profile=candidate.compliance_profile,
        compliance_profile_id=candidate.compliance_profile_id,
        credential_payload_format=normalize_credential_payload_format(
            candidate.credential_payload_format,
            candidate.supported_formats,
        ),
        vct=candidate.vct,
    )

    issuer_context = await _require_active_issuer_profile(
        fastapi_request,
        organization_id=candidate.organization_id,
        issuer_profile_id=candidate.issuer_profile_id,
        credential_format=payload_format_to_wire(candidate.credential_payload_format),
        algorithm=candidate.issuer_algorithm,
    )
    issuer_fields = _canonical_issuer_fields(
        issuer_context,
        requested_algorithm=candidate.issuer_algorithm,
    )
    candidate.issuer_profile_id = issuer_fields["issuer_profile_id"]
    candidate.issuer_key_id = issuer_fields["issuer_key_id"]
    candidate.issuer_algorithm = issuer_fields["issuer_algorithm"]
    candidate.key_access_mode = issuer_fields["key_access_mode"]
    candidate.remote_signing_config = issuer_fields["remote_signing_config"]
    candidate.issuer_did = issuer_fields["issuer_did"]
    
    candidate.updated_at = datetime.now(timezone.utc)
    await repo.save(candidate)
    return _template_to_response(candidate)


@router.post("/{template_id}/activate", response_model=CredentialTemplateResponse, response_model_exclude_none=True)
async def activate_credential_template(
    template_id: str,
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Activate a Credential Template. Requires authentication."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")

    await require_org_membership(template.organization_id, fastapi_request, user_id)
    
    if not template.claims:
        raise HTTPException(status_code=400, detail="Template must have at least one claim")

    _validate_template_protocol_requirements(
        compliance_profile=template.compliance_profile,
        compliance_profile_id=template.compliance_profile_id,
        credential_payload_format=_extract_template_credential_format(template),
        vct=template.vct,
    )

    await _require_active_revocation_profile(
        organization_id=template.organization_id,
        revocation_profile_id=template.revocation_profile_id,
    )

    issuer_context = await _require_active_issuer_profile(
        fastapi_request,
        organization_id=template.organization_id,
        issuer_profile_id=template.issuer_profile_id,
        credential_format=payload_format_to_wire(template.credential_payload_format),
        algorithm=template.issuer_algorithm,
    )
    issuer_fields = _canonical_issuer_fields(
        issuer_context,
        requested_algorithm=template.issuer_algorithm,
    )
    await _require_trust_profile_accepts_issuer(
        trust_profile_id=template.trust_profile_id,
        issuer_did=issuer_fields["issuer_did"],
    )

    template.issuer_profile_id = issuer_fields["issuer_profile_id"]
    template.issuer_key_id = issuer_fields["issuer_key_id"]
    template.issuer_algorithm = issuer_fields["issuer_algorithm"]
    template.key_access_mode = issuer_fields["key_access_mode"]
    template.remote_signing_config = issuer_fields["remote_signing_config"]
    template.issuer_did = issuer_fields["issuer_did"]
    
    template.activate()
    await repo.save(template)
    return _template_to_response(template)


@router.post("/{template_id}/deprecate", response_model=CredentialTemplateResponse, response_model_exclude_none=True)
async def deprecate_credential_template(
    template_id: str,
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Deprecate a Credential Template. Requires authentication."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")

    await require_org_membership(template.organization_id, fastapi_request, user_id)

    template.deprecate()
    await repo.save(template)
    return _template_to_response(template)


@router.post("/{template_id}/new-version", response_model=CredentialTemplateResponse, response_model_exclude_none=True)
async def create_new_version(
    template_id: str,
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Create a new draft version from an existing template. Requires authentication."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")

    await require_org_membership(template.organization_id, fastapi_request, user_id)
    
    new_template = template.new_version()
    await repo.save(new_template)
    return _template_to_response(new_template)


@router.delete("/{template_id}", status_code=204, response_class=Response)
async def delete_credential_template(
    template_id: str,
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> Response:
    """Delete a Credential Template (only allowed for drafts)."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")

    await require_org_membership(template.organization_id, fastapi_request, user_id)

    if template.status != TemplateStatus.DRAFT:
        raise HTTPException(
            status_code=409,
            detail="Only draft templates can be deleted. Deprecate active templates instead."
        )
    await repo.delete(template_id)
    return Response(status_code=204)


# Claims sub-resource
@router.post("/{template_id}/claims", response_model=CredentialTemplateResponse, response_model_exclude_none=True)
async def add_claim(
    template_id: str,
    claim: ClaimDefinitionModel,
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryCredentialTemplateRepository = Depends(get_repo),
) -> CredentialTemplateResponse:
    """Add a claim to a Credential Template. Requires authentication."""
    template = await repo.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Credential Template not found")

    await require_org_membership(template.organization_id, fastapi_request, user_id)
    
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
    artifacts_status = _artifacts_status(template)
    has_artifacts = artifacts_status != "missing"

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
        issuer_profile_id=template.issuer_profile_id,
        application_template_id=template.application_template_id,
        trust_profile_id=template.trust_profile_id,
        revocation_profile_id=template.revocation_profile_id,
        issuer_key_id=template.issuer_key_id,
        issuer_algorithm=template.issuer_algorithm,
        key_access_mode=template.key_access_mode,
        issuer_certificate_chain_pem=template.issuer_certificate_chain_pem,
        issuer_did=template.issuer_did,
        auto_generate_artifacts=template.auto_generate_artifacts,
        issuer_certificate_chain_configured=bool(template.issuer_certificate_chain_pem),
        artifacts_status=artifacts_status,
        hasArtifacts=has_artifacts,
        artifactsValidated=artifacts_status == "valid",
        usedByFlowsCount=0,
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
        wallet_configs_json=json.dumps([
            {
                "wallet_id": wc.wallet_id,
                "deep_link_scheme": wc.deep_link_scheme,
                "format_variant": wc.format_variant,
            }
            for wc in template.wallet_configs
        ]) if template.wallet_configs else None,
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
    if not compliance_profile_id:
        raise HTTPException(
            status_code=422,
            detail="compliance_profile_id is required",
        )

    if credential_payload_format == CredentialFormat.SD_JWT_VC.value and not (vct and str(vct).strip()):
        raise HTTPException(
            status_code=422,
            detail="vct is required when credential_payload_format resolves to SD_JWT_VC",
        )
    # MIP §6.2 — vct MUST be an absolute URI per SD-JWT-VC §3.2.1.
    # An absolute URI is identified by a scheme, not just an HTTP authority:
    # registered VCTs such as ``urn:eudi:pid:1`` are valid and are used by the
    # OID4VP Final interoperability suite.
    # Only enforced for SD-JWT-VC format; mDoc doctypes use reverse-domain notation.
    if (
        credential_payload_format == CredentialFormat.SD_JWT_VC.value
        and vct and str(vct).strip()
        and not urlparse(str(vct).strip()).scheme
    ):
        raise HTTPException(
            status_code=422,
            detail=f"vct must be an absolute URI (e.g. https://… or urn:…), got: {vct}",
        )
    if vct and urlparse(str(vct).strip()).hostname == "marty.example":
        raise HTTPException(
            status_code=422,
            detail="vct must use the configured public credential metadata origin; marty.example is forbidden",
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
    ios_same_device_mode = _derive_ios_same_device_mode(w)
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
        logo_url=w.logo_url,
        deep_link_pattern=w.deep_link_template,
        routing_templates=_wallet_routing_templates(w),
        install_urls=w.install_urls,
        ios_scheme=w.ios_scheme,
        universal_link_template=w.universal_link_template,
        android_package=w.android_package,
        supported_formats=w.supported_formats,
        supported_protocols=w.supported_protocols,
        supported_platforms=w.platforms,
        supports_qr=w.supports_qr,
        supports_deeplink=w.supports_deeplink,
        supports_digital_credentials=w.supports_digital_credentials,
        supports_haip=w.supports_haip,
        ios_same_device_mode=ios_same_device_mode.value,
        ios_same_device_single_wallet_only=ios_same_device_mode == IosSameDeviceMode.PROTOCOL_ONLY,
        oid4vci_profile=_wallet_oid4vci_profile(w),
        docs_url=w.docs_url,
        capabilities=_wallet_capabilities(w),
        created_at=w.created_at.isoformat(),
        updated_at=w.updated_at.isoformat(),
    )


_DELIVERY_PROVIDERS = {
    "elevenid_wallet",
    "oid4vci_wallet",
    "didcomm_v2",
    "canvas_credentials",
    "canvas_credentials_backpack",
    "open_badges_backpack",
    "custom",
    "physical_document_bureau",
}
_DELIVERY_MODES = {"holder_wallet", "learner_backpack", "organization_mirror", "direct_delivery", "physical_document"}
_DELIVERY_SETUP_ACTORS = {"learner", "org_admin", "system"}
_DELIVERY_TARGETS = {"wallet", "didcomm_v2", "canvas_credentials", "external_api", "webhook", "physical_document"}


def _normalize_optional_upper(value: str | None) -> str | None:
    return value.strip().upper() if isinstance(value, str) and value.strip() else None


def _validate_delivery_destination(entry: DeliveryDestinationEntry) -> None:
    if entry.provider not in _DELIVERY_PROVIDERS:
        raise HTTPException(status_code=422, detail=f"Unsupported delivery destination provider: {entry.provider}")
    if entry.mode not in _DELIVERY_MODES:
        raise HTTPException(status_code=422, detail=f"Unsupported delivery destination mode: {entry.mode}")
    if entry.setup_actor not in _DELIVERY_SETUP_ACTORS:
        raise HTTPException(status_code=422, detail=f"Unsupported delivery destination setup_actor: {entry.setup_actor}")
    if entry.delivery_target not in _DELIVERY_TARGETS:
        raise HTTPException(status_code=422, detail=f"Unsupported delivery target: {entry.delivery_target}")
    if entry.mode == "organization_mirror" and entry.setup_actor != "org_admin":
        raise HTTPException(status_code=422, detail="organization_mirror destinations must use setup_actor=org_admin")
    if not entry.is_system and not entry.organization_id:
        raise HTTPException(status_code=422, detail="organization_id is required for organization delivery destinations")


async def _require_destination_admin(organization_id: str, request: Request, user_id: str) -> OrganizationContext:
    context = await require_org_membership(organization_id, request, user_id)
    if (
        context.is_owner
        or context.has_org_console_access
        or context.has_permission("delivery_destinations", "write")
        or context.has_permission("integrations", "write")
    ):
        return context
    raise HTTPException(status_code=403, detail="Organization destination management requires org console access")


def _delivery_destination_to_response(entry: DeliveryDestinationEntry) -> DeliveryDestinationResponse:
    return DeliveryDestinationResponse(
        id=entry.id,
        organization_id=entry.organization_id,
        is_system=entry.is_system,
        name=entry.name,
        description=entry.description,
        provider=entry.provider,
        mode=entry.mode,
        setup_actor=entry.setup_actor,
        delivery_target=entry.delivery_target,
        wallet_profile_id=entry.wallet_profile_id,
        credential_format=entry.credential_format,
        issuance_protocol=entry.issuance_protocol,
        compliance_profile_code=entry.compliance_profile_code,
        connector_type=entry.connector_type,
        connector_id=entry.connector_id,
        requires_consent=entry.requires_consent,
        claim_projection_policy=entry.claim_projection_policy,
        setup_requirements=entry.setup_requirements,
        capabilities=entry.capabilities,
        docs_url=entry.docs_url,
        is_enabled=entry.is_enabled,
        created_at=entry.created_at.isoformat(),
        updated_at=entry.updated_at.isoformat(),
    )


def _wallet_oid4vci_profile(w: WalletRegistryEntry) -> dict[str, str] | None:
    formats = {str(fmt).strip().lower().replace("_", "-") for fmt in (w.supported_formats or [])}
    if "spruce-vc+sd-jwt" in formats:
        return {
            "format_variant": "spruce-vc+sd-jwt",
            "issuer_path": "spruce",
            "credential_configuration_suffix": "spruce-sd-jwt",
        }
    return None


def _wallet_capabilities(w: WalletRegistryEntry) -> dict[str, bool]:
    tokens = " ".join([*w.specifications, *w.supported_protocols]).lower()
    supports_oid4vci = "oid4vci" in tokens or "oid4vci_pre_auth" in tokens
    supports_oid4vp = "oid4vp" in tokens
    supports_dc_api = w.supports_digital_credentials or any(marker in tokens for marker in ("credentialmanager", "digital_credentials", "dc_api"))
    supports_haip = w.supports_haip or "haip" in tokens
    return {
        "oid4vci": supports_oid4vci,
        "oid4vp": supports_oid4vp,
        "digital_credentials": supports_dc_api,
        "haip": supports_haip,
        "same_device": w.supports_deeplink or supports_dc_api,
        "qr": w.supports_qr,
    }


_PROTOCOL_ONLY_WALLET_SCHEMES = {"openid-credential-offer", "openid4vp", "haip-vci", "haip-vp"}


def _wallet_has_explicit_ios_routing(w: WalletRegistryEntry) -> bool:
    templates = w.routing_templates or {}
    return bool(w.universal_link_template or w.ios_scheme or templates.get("ios"))


def _wallet_targets_ios_same_device(w: WalletRegistryEntry) -> bool:
    platforms = {str(platform).strip().lower() for platform in (w.platforms or []) if str(platform).strip()}
    if "ios" in platforms or "any" in platforms:
        return True
    if platforms:
        return _wallet_has_explicit_ios_routing(w)
    return bool(w.supports_digital_credentials or _wallet_has_explicit_ios_routing(w) or w.deep_link_template)


def _is_universal_link_template(template: str | None) -> bool:
    if not template:
        return False
    return urlparse(template).scheme.lower() in {"https", "http"}


def _is_protocol_only_wallet_template(template: str | None) -> bool:
    if not template:
        return False
    return urlparse(template).scheme.lower() in _PROTOCOL_ONLY_WALLET_SCHEMES


def _derive_ios_same_device_mode(w: WalletRegistryEntry) -> IosSameDeviceMode:
    if not _wallet_targets_ios_same_device(w):
        return IosSameDeviceMode.UNSUPPORTED
    if w.supports_digital_credentials:
        return IosSameDeviceMode.DIGITAL_CREDENTIALS

    route_template = _wallet_route_template_for_platform(w, "ios")
    if _is_universal_link_template(route_template):
        return IosSameDeviceMode.UNIVERSAL_LINK
    if _is_wallet_routing_template(route_template):
        return IosSameDeviceMode.NESTED_LINK
    if _is_protocol_only_wallet_template(route_template):
        return IosSameDeviceMode.PROTOCOL_ONLY
    return IosSameDeviceMode.UNSUPPORTED


def _wallet_routing_templates(w: WalletRegistryEntry) -> dict[str, str]:
    if not w.supports_deeplink:
        return {}
    templates = dict(w.routing_templates or {})
    if w.deep_link_template:
        templates.setdefault("generic", w.deep_link_template)
    if w.universal_link_template:
        templates.setdefault("web", w.universal_link_template)
        templates.setdefault("ios", w.universal_link_template)
    if w.ios_scheme:
        templates.setdefault("ios", f"{w.ios_scheme}://open?inner={{inner_uri_encoded}}")
    for platform in w.platforms:
        if platform in {"ios", "android", "web", "desktop"}:
            if w.deep_link_template:
                templates.setdefault(platform, w.deep_link_template)
    return templates


def _wallet_route_template_for_platform(w: WalletRegistryEntry, platform: str | None) -> str:
    templates = _wallet_routing_templates(w)
    normalized_platform = (platform or "").strip().lower()
    if normalized_platform == "desktop":
        normalized_platform = "web"
    exact_template = templates.get(normalized_platform) or ""
    if _is_wallet_routing_template(exact_template):
        return exact_template
    if exact_template:
        return exact_template

    generic_template = templates.get("generic") or templates.get("default") or w.deep_link_template or ""
    if _is_wallet_routing_template(generic_template):
        return generic_template
    if generic_template:
        return generic_template

    if normalized_platform:
        return ""

    fallback_templates = [
        templates.get("ios"),
        templates.get("android"),
        templates.get("web"),
        templates.get("desktop"),
        *templates.values(),
        w.deep_link_template,
    ]
    nested_fallback = next((template for template in fallback_templates if _is_wallet_routing_template(template or "")), "")
    return nested_fallback or exact_template or generic_template


def _is_wallet_routing_template(template: str | None) -> bool:
    if not template:
        return False
    scheme = urlparse(template).scheme.lower()
    if scheme in {"openid-credential-offer", "openid4vp", "haip-vci", "haip-vp"}:
        return False
    return re.search(
        r"\{(?:inner_uri|uri|offer_uri|offer|credential_offer_uri|request_uri)(?:_encoded)?\}",
        template,
    ) is not None


def _query_value(uri: str, keys: tuple[str, ...]) -> str:
    parsed = urlparse(uri)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key in keys:
        values = query.get(key)
        if values and values[0]:
            return values[0]
    return uri


def _credential_offer_parts(uri: str) -> tuple[str, str]:
    parsed = urlparse(uri)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key in ("credential_offer_uri", "credential_offer"):
        values = query.get(key)
        if values and values[0]:
            return key, values[0]
    return "credential_offer_uri", uri


def _validate_wallet_inner_uri(inner_uri: str) -> str:
    value = inner_uri.strip()
    if not value:
        raise HTTPException(status_code=400, detail="inner_uri is required")

    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    allowed_schemes = {"https", "openid-credential-offer", "openid4vp", "haip-vci", "haip-vp"}
    if os.environ.get("ENVIRONMENT", "production").lower() in {"development", "test"}:
        allowed_schemes.add("http")
    if scheme not in allowed_schemes:
        raise HTTPException(status_code=400, detail="inner_uri scheme is not allowed")
    if scheme in {"http", "https"} and not parsed.netloc:
        raise HTTPException(status_code=400, detail="inner_uri must include a host")
    return value


def _render_wallet_open_uri(template: str, inner_uri: str, wallet_id: str, platform: str | None) -> str:
    if not template:
        return inner_uri
    offer_param, offer_value = _credential_offer_parts(inner_uri)
    if offer_param == "credential_offer":
        template = re.sub(
            r"credential_offer_uri=(\{(?:offer_uri|offer|credential_offer_uri)(?:_encoded)?\})",
            r"credential_offer=\1",
            template,
        )
    request_uri = _query_value(inner_uri, ("request_uri",))
    replacements = {
        "inner_uri": inner_uri,
        "inner_uri_encoded": quote(inner_uri, safe=""),
        "uri": inner_uri,
        "uri_encoded": quote(inner_uri, safe=""),
        "offer_uri": offer_value,
        "offer_uri_encoded": quote(offer_value, safe=""),
        "offer": offer_value,
        "offer_encoded": quote(offer_value, safe=""),
        "credential_offer_param": offer_param,
        "credential_offer_uri": offer_value,
        "credential_offer_uri_encoded": quote(offer_value, safe=""),
        "request_uri": request_uri,
        "request_uri_encoded": quote(request_uri, safe=""),
        "wallet_id": wallet_id,
        "platform": platform or "",
    }

    def replace(match: re.Match[str]) -> str:
        return replacements.get(match.group(1), match.group(0))

    return re.sub(r"\{([a-zA-Z0-9_]+)\}", replace, template)


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


@wallet_router.get("/{wallet_id}/open-link", response_model=WalletOpenLinkResponse, summary="Build Wallet Open Link")
async def build_wallet_open_link(
    wallet_id: str,
    inner_uri: str = Query(..., description="Standard OID4VP/OID4VCI/HAIP inner URI"),
    platform: str | None = Query(None, description="Optional platform hint such as ios or android"),
    repo: InMemoryWalletRegistryRepository | PostgresWalletRegistryRepository = Depends(get_wallet_repo),
) -> WalletOpenLinkResponse:
    """Build a wallet-specific outer link while preserving the standard inner URI."""
    wallet = await repo.get(wallet_id)
    if not wallet or not wallet.is_active:
        raise HTTPException(status_code=404, detail="Wallet not found")
    if not wallet.supports_deeplink:
        raise HTTPException(status_code=400, detail="Wallet does not support deep links")

    validated_inner_uri = _validate_wallet_inner_uri(inner_uri)
    route_template = _wallet_route_template_for_platform(wallet, platform)
    open_uri = _render_wallet_open_uri(route_template, validated_inner_uri, wallet_id, platform)
    return WalletOpenLinkResponse(
        wallet_id=wallet_id,
        inner_uri=validated_inner_uri,
        open_uri=open_uri,
        platform=platform,
    )


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
        routing_templates=body.routing_templates,
        install_urls=body.install_urls,
        ios_scheme=body.ios_scheme,
        universal_link_template=body.universal_link_template,
        android_package=body.android_package,
        supported_formats=body.supported_formats,
        supported_protocols=[_normalize_issuance_protocol(protocol) for protocol in body.supported_protocols],
        platforms=supported_platforms,
        supports_qr=body.supports_qr,
        supports_deeplink=body.supports_deeplink,
        supports_digital_credentials=body.supports_digital_credentials,
        supports_haip=body.supports_haip,
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
    if body.routing_templates is not None:
        entry.routing_templates = body.routing_templates
    if body.install_urls is not None:
        entry.install_urls = body.install_urls
    if body.ios_scheme is not None:
        entry.ios_scheme = body.ios_scheme
    if body.universal_link_template is not None:
        entry.universal_link_template = body.universal_link_template
    if body.android_package is not None:
        entry.android_package = body.android_package
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
    if body.supports_digital_credentials is not None:
        entry.supports_digital_credentials = body.supports_digital_credentials
    if body.supports_haip is not None:
        entry.supports_haip = body.supports_haip
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

# =============================================================================
# Delivery Destination Registry Router
# =============================================================================

@delivery_destination_router.get(
    "",
    response_model=list[DeliveryDestinationResponse],
    response_model_exclude_none=True,
    summary="List Delivery Destinations",
)
async def list_delivery_destinations(
    active_only: bool = Query(True, description="Return only enabled destinations"),
    organization_id: str | None = Query(None, description="Optional organization scope"),
    provider: str | None = Query(None, description="Optional provider filter"),
    mode: str | None = Query(None, description="Optional destination mode filter"),
    request: Request = None,
    user_id: str = Depends(get_current_user_id),
    repo: DeliveryDestinationRepository = Depends(get_delivery_destination_repo),
) -> list[DeliveryDestinationResponse]:
    """List system and organization delivery destinations."""
    if organization_id:
        await require_org_membership(organization_id, request, user_id)
    entries = await repo.list(
        active_only=active_only,
        organization_id=organization_id,
        provider=provider,
        mode=mode,
    )
    return [_delivery_destination_to_response(entry) for entry in entries]


@delivery_destination_router.get(
    "/{destination_id}",
    response_model=DeliveryDestinationResponse,
    response_model_exclude_none=True,
    summary="Get Delivery Destination",
)
async def get_delivery_destination(
    destination_id: str,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: DeliveryDestinationRepository = Depends(get_delivery_destination_repo),
) -> DeliveryDestinationResponse:
    """Get a delivery destination by id."""
    entry = await repo.get(destination_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Delivery destination not found")
    if entry.organization_id:
        await require_org_membership(entry.organization_id, request, user_id)
    return _delivery_destination_to_response(entry)


@delivery_destination_router.post(
    "",
    response_model=DeliveryDestinationResponse,
    response_model_exclude_none=True,
    summary="Create Delivery Destination",
    status_code=201,
)
async def create_delivery_destination(
    body: DeliveryDestinationCreate,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: DeliveryDestinationRepository = Depends(get_delivery_destination_repo),
) -> DeliveryDestinationResponse:
    """Create an organization delivery destination. System destinations are read-only."""
    await _require_destination_admin(body.organization_id, request, user_id)
    entry = DeliveryDestinationEntry(
        id=body.id or str(uuid.uuid4()),
        organization_id=body.organization_id,
        is_system=False,
        name=body.name,
        description=body.description,
        provider=body.provider,
        mode=body.mode,
        setup_actor=body.setup_actor,
        delivery_target=body.delivery_target,
        wallet_profile_id=body.wallet_profile_id,
        credential_format=_normalize_optional_upper(body.credential_format),
        issuance_protocol=_normalize_issuance_protocol(body.issuance_protocol) if body.issuance_protocol else None,
        compliance_profile_code=_normalize_optional_upper(body.compliance_profile_code),
        connector_type=body.connector_type,
        connector_id=body.connector_id,
        requires_consent=body.requires_consent,
        claim_projection_policy=body.claim_projection_policy,
        setup_requirements=body.setup_requirements,
        capabilities=body.capabilities,
        docs_url=body.docs_url,
        is_enabled=body.is_enabled,
    )
    _validate_delivery_destination(entry)
    if await repo.get(entry.id):
        raise HTTPException(status_code=409, detail="Delivery destination already exists")
    await repo.save(entry)
    logger.info("Created delivery destination: %s (%s)", entry.id, entry.name)
    return _delivery_destination_to_response(entry)


@delivery_destination_router.patch(
    "/{destination_id}",
    response_model=DeliveryDestinationResponse,
    response_model_exclude_none=True,
    summary="Update Delivery Destination",
)
async def update_delivery_destination(
    destination_id: str,
    body: DeliveryDestinationUpdate,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: DeliveryDestinationRepository = Depends(get_delivery_destination_repo),
) -> DeliveryDestinationResponse:
    """Update an organization delivery destination. System destinations are read-only."""
    entry = await repo.get(destination_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Delivery destination not found")
    if entry.is_system:
        raise HTTPException(status_code=403, detail="System delivery destinations are read-only")
    await _require_destination_admin(entry.organization_id or "", request, user_id)

    for field_name in (
        "name",
        "description",
        "provider",
        "mode",
        "setup_actor",
        "delivery_target",
        "wallet_profile_id",
        "connector_type",
        "connector_id",
        "requires_consent",
        "claim_projection_policy",
        "setup_requirements",
        "capabilities",
        "docs_url",
        "is_enabled",
    ):
        value = getattr(body, field_name)
        if value is not None:
            setattr(entry, field_name, value)
    if body.credential_format is not None:
        entry.credential_format = _normalize_optional_upper(body.credential_format)
    if body.issuance_protocol is not None:
        entry.issuance_protocol = _normalize_issuance_protocol(body.issuance_protocol) if body.issuance_protocol else None
    if body.compliance_profile_code is not None:
        entry.compliance_profile_code = _normalize_optional_upper(body.compliance_profile_code)

    _validate_delivery_destination(entry)
    await repo.save(entry)
    logger.info("Updated delivery destination: %s", entry.id)
    return _delivery_destination_to_response(entry)


@delivery_destination_router.delete("/{destination_id}", summary="Delete Delivery Destination")
async def delete_delivery_destination(
    destination_id: str,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: DeliveryDestinationRepository = Depends(get_delivery_destination_repo),
) -> dict:
    """Delete an organization delivery destination. System destinations are read-only."""
    entry = await repo.get(destination_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Delivery destination not found")
    if entry.is_system:
        raise HTTPException(status_code=403, detail="System delivery destinations are read-only")
    await _require_destination_admin(entry.organization_id or "", request, user_id)
    await repo.delete(destination_id)
    return {"success": True}


internal_router = APIRouter(prefix="/internal", tags=["internal"])


def _has_kms_backed_issuer(template: Any) -> bool:
    issuer_profile_id = str(getattr(template, "issuer_profile_id", "") or "").strip()
    key_access_mode = str(getattr(template, "key_access_mode", "") or "").strip().upper()
    return bool(issuer_profile_id and key_access_mode == "REMOTE_SIGNING")


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

    configs: dict = {}

    if _repo is None:
        return {
            "credential_configurations_supported": configs,
            "issuer_display_name": None,
        }

    try:
        templates = await _repo.list_all(status=TemplateStatus.ACTIVE)
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to load credential templates for well-known: %s", exc)
        return {
            "credential_configurations_supported": configs,
            "issuer_display_name": None,
        }

    advertised_templates: list[CredentialTemplate] = []
    for t in templates:
        if not _has_kms_backed_issuer(t):
            logger.warning(
                "Skipping active credential template %s in issuer metadata because it lacks a KMS-backed issuer profile",
                getattr(t, "id", None) or getattr(t, "name", None) or "unknown",
            )
            continue
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
        advertised_templates.append(t)

    # Try to look up the issuer display name from the org service using the
    # organization_id of the first active template we can actually advertise.
    issuer_display_name: str | None = None
    if advertised_templates:
        org_id = getattr(advertised_templates[0], "organization_id", None)
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
    global _repo, _wallet_repo, _delivery_destination_repo
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

    _delivery_destination_repo = PostgresDeliveryDestinationRepository(session_factory)
    for entry in SYSTEM_DELIVERY_DESTINATION_CATALOG:
        existing = await _delivery_destination_repo.get(entry.id)
        if existing is None:
            await _delivery_destination_repo.save(DeliveryDestinationEntry(**entry.__dict__))
    
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
        routers=[router, wallet_router, delivery_destination_router, internal_router],
    )


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
