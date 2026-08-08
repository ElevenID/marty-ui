"""
Trust Profile Service

Manages Trust Profiles - the configuration of who is trusted and how
cryptographic validation happens.

A Trust Profile contains:
- Trust sources (registries, pinned roots, issuer allow/deny lists)
- Validation rules (chain building, allowed algorithms, key usage)
- Revocation policy (OCSP/CRL/status list, hard-fail vs soft-fail)
- Time policy (clock skew, freshness windows)
- Format support (mdoc/mDL, VC, SD-JWT)

Port: 8004
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import uuid
from copy import deepcopy
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated, Any, AsyncGenerator, Literal

import httpx
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from marty_common.dto import DeleteResponse
from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from sqlalchemy import text
from marty_common import ensure_membership_permission
from marty_common.org_authorization import get_organization_client
from marty_common.service_setup import create_service_app
from marty_common.system_ids import (
    MARTY_DEFAULT_ORG_ID,
    MARTY_DEFAULT_REVOCATION_PROFILE_ID,
    MARTY_LOGIN_TRUST_PROFILE_ID,
    MARTY_LOGIN_TRUSTED_ISSUER_ID,
    MARTY_MEMBER_MDOC_TEMPLATE_ID,
    MARTY_MEMBER_SD_JWT_TEMPLATE_ID,
    MARTY_TRUST_BUNDLE_SOURCE_ID,
)
from marty_common.system_urls import (
    resolve_marty_issuer_base_url,
    resolve_marty_issuer_did,
)
from trust_profile.infrastructure.adapters import PostgresTrustProfileRepository
from trust_profile.infrastructure.models import mapper_registry
from trust_profile.registry_sync import (
    RegistrySyncError,
    registry_tls_context,
    state_from_storage,
    synchronize_registry,
    validate_current_registry_entries,
    validate_registry_url_structure,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "trust-profile-service"
SERVICE_PORT = int(os.environ.get("TRUST_PROFILE_SERVICE_PORT", "8004"))


# =============================================================================
# Domain Layer
# =============================================================================


class TrustProfileStatus(str, Enum):
    """Trust profile status."""

    DRAFT = "draft"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class TrustProfileType(str, Enum):
    ICAO = "ICAO"
    AAMVA = "AAMVA"
    EUDI = "EUDI"
    CUSTOM = "CUSTOM"


class ComplianceStatus(str, Enum):
    COMPLIANT = "COMPLIANT"
    NEEDS_ATTENTION = "NEEDS_ATTENTION"
    SETUP_REQUIRED = "SETUP_REQUIRED"


class TrustSourceType(str, Enum):
    TRUST_LIST = "TRUST_LIST"
    PINNED_ISSUER = "PINNED_ISSUER"
    ROOT_CA = "ROOT_CA"
    PKD_URL = "PKD_URL"


class RevocationCheckMode(str, Enum):
    """Failure behavior when a revocation check is performed.
    Maps to marty-protocol enum: revocation-check-modes.json
    """

    HARD_FAIL = "HARD_FAIL"
    SOFT_FAIL = "SOFT_FAIL"
    SKIP = "SKIP"


from marty_common.domain_enums import CredentialFormat  # noqa: E402


class IssuerEntityType(str, Enum):
    ORGANIZATION = "ORGANIZATION"
    GOVERNMENT = "GOVERNMENT"
    DEVICE = "DEVICE"


class IssuerEntityComplianceStatus(str, Enum):
    ACCREDITED = "ACCREDITED"
    COMPLIANT = "COMPLIANT"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class TrustRelationshipStatus(str, Enum):
    TRUSTED = "TRUSTED"
    DENIED = "DENIED"
    UNDER_REVIEW = "UNDER_REVIEW"


class CascadeRevocationPolicy(str, Enum):
    AUTO_CASCADE = "AUTO_CASCADE"
    MANUAL = "MANUAL"
    NOTIFY_ONLY = "NOTIFY_ONLY"


class TrustAnchorType(str, Enum):
    CSCA = "CSCA"
    DSC = "DSC"


class TrustRegistryOperation(str, Enum):
    ADD = "ADD"
    REMOVE = "REMOVE"


class TrustRegistrySource(str, Enum):
    ICAO_PKD = "ICAO_PKD"
    AAMVA = "AAMVA"
    EUDI_LOTL = "EUDI_LOTL"
    MANUAL = "MANUAL"


@dataclass
class TrustSource:
    """
    A source of trust (registry, pinned root, etc.)
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    source_type: str = TrustSourceType.TRUST_LIST.value
    url: str | None = None
    certificate_pem: str | None = None
    issuer_did: str | None = None
    description: str | None = None
    pinned_certificates: list[str] = field(default_factory=list)
    refresh_interval_hours: int = 24
    enabled: bool = True
    registry_sync: dict[str, Any] | None = None
    registry_sync_token: str | None = None
    registry_sequence: int = 0
    registry_entries: dict[str, dict[str, Any]] = field(default_factory=dict)
    registry_last_synced_at: datetime | None = None


@dataclass
class ValidationRules:
    """
    Rules for cryptographic validation.
    """

    allowed_algorithms: list[str] = field(
        default_factory=lambda: ["ES256", "ES384", "EdDSA"]
    )
    min_key_size_rsa: int = 2048
    min_key_size_ec: int = 256
    require_key_usage: bool = True
    max_chain_depth: int = 5
    allow_self_signed: bool = False


@dataclass
class RevocationPolicy:
    """
    Policy for revocation checking.
    """

    check_mode: RevocationCheckMode = RevocationCheckMode.HARD_FAIL
    check_ocsp: bool = True
    check_crl: bool = True
    check_status_list: bool = True
    offline_grace_period_hours: int = 24
    cache_duration_hours: int = 1


@dataclass
class TimePolicy:
    """
    Time-related validation rules.
    """

    max_clock_skew_seconds: int = 300  # 5 minutes
    credential_freshness_hours: int | None = (
        None  # If set, credentials must be issued within this window
    )
    require_not_before: bool = True
    require_expiration: bool = True


@dataclass
class IssuerEntity:
    """Protocol-aligned issuer registry entity."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str | None = None
    issuer_id: str = ""
    issuer_type: IssuerEntityType = IssuerEntityType.ORGANIZATION
    display_name: str = ""
    description: str | None = None
    is_system_issuer: bool = False
    compliance_status: IssuerEntityComplianceStatus = (
        IssuerEntityComplianceStatus.COMPLIANT
    )
    accreditation_body: str | None = None
    accreditations: list[str] = field(default_factory=list)
    accreditation_date: datetime | None = None
    valid_from: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    valid_until: datetime | None = None
    trust_anchor_id: str | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None
    revoked_by: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TrustProfileIssuer:
    """Protocol-aligned join entity between TrustProfile and IssuerEntity."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    trust_profile_id: str = ""
    issuer_id: str = ""
    trust_level: int = 100
    relationship_status: TrustRelationshipStatus = TrustRelationshipStatus.TRUSTED
    cascade_revocation_policy: CascadeRevocationPolicy = (
        CascadeRevocationPolicy.NOTIFY_ONLY
    )
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TrustFramework:
    """System-managed trust framework definitions."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    code: str = "CUSTOM"
    display_name: str = "Custom"
    description: str | None = None
    pkd_endpoints: list[str] = field(default_factory=list)
    default_algorithms: list[str] = field(
        default_factory=lambda: ["ES256", "ES384", "EdDSA"]
    )
    default_formats: list[str] = field(
        default_factory=lambda: [CredentialFormat.MDOC.value]
    )
    validation_ruleset: dict[str, Any] = field(default_factory=dict)
    sync_config: dict[str, Any] = field(default_factory=dict)
    is_system: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class OrganizationTrustProfile:
    """Organization-specific overlay of a TrustFramework."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    framework_id: str = ""
    name: str = ""
    display_name: str | None = None
    description: str | None = None
    enabled: bool = True
    use_case_tags: list[str] = field(default_factory=list)
    compliance_status: ComplianceStatus = ComplianceStatus.SETUP_REQUIRED
    auto_generated: bool = False
    revocation_policy: dict[str, Any] | None = None
    time_policy: dict[str, Any] | None = None
    allowed_algorithms: list[str] | None = None
    allowed_formats: list[CredentialFormat] | None = None
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    jurisdiction_filter: list[str] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TrustRegistryEntry:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    anchor_type: TrustAnchorType = TrustAnchorType.CSCA
    operation: TrustRegistryOperation = TrustRegistryOperation.ADD
    country_code: str = "XX"
    certificate_pem: str | None = None
    subject_key_id: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    source: TrustRegistrySource = TrustRegistrySource.MANUAL
    framework_code: str | None = None
    sequence: int = 0
    is_current: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


SYSTEM_TRUST_FRAMEWORKS: tuple[TrustFramework, ...] = (
    TrustFramework(
        code="ICAO",
        display_name="ICAO PKD",
        description="ICAO trust framework for mdoc and travel credential validation.",
        pkd_endpoints=["https://pkddownload1.icao.int/PKDDownload/"],
        default_algorithms=["ES256", "ES384", "EdDSA"],
        default_formats=[CredentialFormat.MDOC.value],
        validation_ruleset={
            "require_document_signer": True,
            "require_country_signing_ca": True,
            "allow_self_signed": False,
        },
        sync_config={"mode": "PKD_DELTA", "refresh_interval_hours": 24},
        is_system=True,
    ),
    TrustFramework(
        code="AAMVA",
        display_name="AAMVA mDL",
        description="AAMVA trust framework for North American mobile driver licenses.",
        pkd_endpoints=[],
        default_algorithms=["ES256", "ES384"],
        default_formats=[CredentialFormat.MDOC.value],
        validation_ruleset={
            "require_crl_distribution_points": True,
            "require_issuer_alt_name": True,
            "allow_self_signed": False,
        },
        sync_config={"mode": "MANUAL", "refresh_interval_hours": 24},
        is_system=True,
    ),
    TrustFramework(
        code="EUDI",
        display_name="EUDI Wallet",
        description="EUDI wallet trust framework defaults for interoperable European credentials.",
        pkd_endpoints=[],
        default_algorithms=["ES256", "ES384", "EdDSA"],
        default_formats=[CredentialFormat.MDOC.value, CredentialFormat.SD_JWT_VC.value],
        validation_ruleset={
            "require_pid_metadata": True,
            "allow_self_signed": False,
        },
        sync_config={"mode": "MANUAL", "refresh_interval_hours": 24},
        is_system=True,
    ),
)


@dataclass
class TrustProfile:
    """
    Trust Profile - defines who is trusted and how validation happens.

    This is the core configuration object for trust management.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    name: str = ""
    description: str | None = None
    status: TrustProfileStatus = TrustProfileStatus.DRAFT
    profile_type: TrustProfileType = TrustProfileType.CUSTOM
    compliance_status: ComplianceStatus = ComplianceStatus.SETUP_REQUIRED

    # Trust configuration
    trust_sources: list[TrustSource] = field(default_factory=list)
    validation_rules: ValidationRules = field(default_factory=ValidationRules)
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    system_issuer_overrides: dict[str, dict[str, Any]] = field(default_factory=dict)
    compatible_compliance_codes: list[str] = field(default_factory=list)
    verification_policy_set_id: str | None = None
    auto_generated: bool = False

    # Revocation configuration
    revocation_policy: RevocationPolicy = field(
        default_factory=RevocationPolicy
    )  # DEPRECATED: use revocation_profile_id
    revocation_profile_id: str | None = None  # NEW: links to RevocationProfile

    time_policy: TimePolicy = field(default_factory=TimePolicy)

    # Supported formats
    supported_formats: list[CredentialFormat] = field(
        default_factory=lambda: [CredentialFormat.SD_JWT_VC, CredentialFormat.MDOC]
    )

    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def activate(self) -> None:
        self.status = TrustProfileStatus.ACTIVE
        self.updated_at = datetime.now(timezone.utc)

    def suspend(self) -> None:
        self.status = TrustProfileStatus.SUSPENDED
        self.updated_at = datetime.now(timezone.utc)


# =============================================================================
# Application Layer
# =============================================================================


class InMemoryTrustProfileRepository:
    """In-memory repository for development."""

    def __init__(self):
        self._profiles: dict[str, TrustProfile] = {}
        self._frameworks: dict[str, TrustFramework] = {}
        self._organization_trust_profiles: dict[str, OrganizationTrustProfile] = {}
        self._registry_entries: dict[str, TrustRegistryEntry] = {}
        self._issuer_entities: dict[str, IssuerEntity] = {}
        self._profile_issuers: dict[str, TrustProfileIssuer] = {}

    # Trust Framework operations
    async def save_framework(self, framework: TrustFramework) -> None:
        self._frameworks[framework.id] = framework

    async def get_framework(self, framework_id: str) -> TrustFramework | None:
        return self._frameworks.get(framework_id)

    async def get_framework_by_code(self, code: str) -> TrustFramework | None:
        return next(
            (
                framework
                for framework in self._frameworks.values()
                if framework.code == code
            ),
            None,
        )

    async def list_frameworks(self) -> list[TrustFramework]:
        return sorted(
            self._frameworks.values(),
            key=lambda framework: (not framework.is_system, framework.code),
        )

    # Organization Trust Profile operations
    async def save_organization_trust_profile(
        self, profile: OrganizationTrustProfile
    ) -> None:
        self._organization_trust_profiles[profile.id] = profile

    async def get_organization_trust_profile(
        self, profile_id: str
    ) -> OrganizationTrustProfile | None:
        return self._organization_trust_profiles.get(profile_id)

    async def list_organization_trust_profiles(
        self, organization_id: str
    ) -> list[OrganizationTrustProfile]:
        return sorted(
            [
                profile
                for profile in self._organization_trust_profiles.values()
                if profile.organization_id == organization_id
            ],
            key=lambda profile: (profile.created_at, profile.id),
        )

    async def delete_organization_trust_profile(self, profile_id: str) -> None:
        self._organization_trust_profiles.pop(profile_id, None)

    # Trust Registry operations
    async def save_registry_entry(self, entry: TrustRegistryEntry) -> None:
        self._registry_entries[entry.id] = entry

    async def list_registry_entries(
        self,
        anchor_type: str | None = None,
        country_code: str | None = None,
        current_only: bool = True,
        since_sequence: int | None = None,
    ) -> list[TrustRegistryEntry]:
        entries = list(self._registry_entries.values())
        if anchor_type is not None:
            entries = [
                entry for entry in entries if entry.anchor_type.value == anchor_type
            ]
        if country_code is not None:
            normalized = country_code.upper()
            entries = [entry for entry in entries if entry.country_code == normalized]
        if current_only:
            entries = [entry for entry in entries if entry.is_current]
        if since_sequence is not None:
            entries = [entry for entry in entries if entry.sequence > since_sequence]
        return sorted(
            entries, key=lambda entry: (entry.sequence, entry.country_code, entry.id)
        )

    async def get_registry_sequence(self) -> int:
        return max(
            (entry.sequence for entry in self._registry_entries.values()), default=0
        )

    async def get_registry_status(self) -> dict[str, int | None]:
        entries = list(self._registry_entries.values())
        current_entries = [entry for entry in entries if entry.is_current]
        return {
            "total_entries": len(entries),
            "current_entries": len(current_entries),
            "csca_entries": len(
                [
                    entry
                    for entry in current_entries
                    if entry.anchor_type == TrustAnchorType.CSCA
                ]
            ),
            "dsc_entries": len(
                [
                    entry
                    for entry in current_entries
                    if entry.anchor_type == TrustAnchorType.DSC
                ]
            ),
            "current_sequence": await self.get_registry_sequence(),
        }

    # Trust Profile operations
    async def save_profile(
        self,
        profile: TrustProfile,
        *,
        expected_updated_at: datetime | None = None,
    ) -> bool:
        current = self._profiles.get(profile.id)
        if expected_updated_at is not None and (
            current is None or current.updated_at != expected_updated_at
        ):
            return False
        self._profiles[profile.id] = profile
        return True

    async def get_profile(self, profile_id: str) -> TrustProfile | None:
        return self._profiles.get(profile_id)

    async def list_profiles(self, org_id: str) -> list[TrustProfile]:
        return [p for p in self._profiles.values() if p.organization_id == org_id]

    async def list_all_profiles(self) -> list[TrustProfile]:
        return sorted(self._profiles.values(), key=lambda profile: profile.id)

    async def delete_profile(self, profile_id: str) -> None:
        self._profiles.pop(profile_id, None)
        link_ids = [
            link.id
            for link in self._profile_issuers.values()
            if link.trust_profile_id == profile_id
        ]
        for link_id in link_ids:
            self._profile_issuers.pop(link_id, None)

    # Issuer entity operations
    async def save_issuer_entity(self, issuer_entity: IssuerEntity) -> None:
        self._issuer_entities[issuer_entity.id] = issuer_entity

    async def get_issuer_entity(self, issuer_entity_id: str) -> IssuerEntity | None:
        return self._issuer_entities.get(issuer_entity_id)

    async def find_issuer_entity_by_identifier(
        self,
        organization_id: str | None,
        issuer_id: str,
    ) -> IssuerEntity | None:
        return next(
            (
                issuer_entity
                for issuer_entity in self._issuer_entities.values()
                if issuer_entity.organization_id == organization_id
                and issuer_entity.issuer_id == issuer_id
            ),
            None,
        )

    async def list_issuer_entities(
        self, organization_id: str | None = None
    ) -> list[IssuerEntity]:
        entities = list(self._issuer_entities.values())
        if organization_id is not None:
            entities = [
                entity
                for entity in entities
                if entity.organization_id == organization_id
                or entity.is_system_issuer
                or entity.organization_id is None
            ]
        return sorted(
            entities, key=lambda entity: (entity.display_name.lower(), entity.id)
        )

    async def delete_issuer_entity(self, issuer_entity_id: str) -> None:
        self._issuer_entities.pop(issuer_entity_id, None)
        link_ids = [
            link.id
            for link in self._profile_issuers.values()
            if link.issuer_id == issuer_entity_id
        ]
        for link_id in link_ids:
            self._profile_issuers.pop(link_id, None)

    # Trust profile issuer operations
    async def save_profile_issuer(self, profile_issuer: TrustProfileIssuer) -> None:
        self._profile_issuers[profile_issuer.id] = profile_issuer

    async def get_profile_issuer(
        self, profile_issuer_id: str
    ) -> TrustProfileIssuer | None:
        return self._profile_issuers.get(profile_issuer_id)

    async def get_profile_issuer_by_pair(
        self, trust_profile_id: str, issuer_id: str
    ) -> TrustProfileIssuer | None:
        return next(
            (
                link
                for link in self._profile_issuers.values()
                if link.trust_profile_id == trust_profile_id
                and link.issuer_id == issuer_id
            ),
            None,
        )

    async def list_profile_issuers(
        self, trust_profile_id: str
    ) -> list[TrustProfileIssuer]:
        return sorted(
            [
                link
                for link in self._profile_issuers.values()
                if link.trust_profile_id == trust_profile_id
            ],
            key=lambda link: (link.created_at, link.id),
        )

    async def delete_profile_issuer(self, profile_issuer_id: str) -> None:
        self._profile_issuers.pop(profile_issuer_id, None)


# =============================================================================
# HTTP Adapter - Request/Response Models
# =============================================================================


class RegistrySyncConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol: Literal["MARTY_TRUST_REGISTRY_SYNC_V1"]
    refresh_interval_hours: int = Field(ge=1, le=720)


class TrustSourceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_type: Literal["TRUST_LIST", "PINNED_ISSUER", "ROOT_CA", "PKD_URL"]
    url: str | None = None
    certificate_pem: str | None = None
    issuer_did: str | None = None
    description: str | None = Field(default=None, max_length=256)
    registry_sync: RegistrySyncConfigModel | None = None

    @field_validator("source_type", mode="before")
    @classmethod
    def normalize_source_type(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_source_identity(self) -> "TrustSourceModel":
        selectors = [self.url, self.certificate_pem, self.issuer_did]
        if sum(value is not None for value in selectors) != 1:
            raise ValueError(
                "exactly one of url, certificate_pem, or issuer_did is required"
            )
        if self.url is not None:
            try:
                validate_registry_url_structure(self.url)
            except ValueError as exc:
                raise ValueError(str(exc)) from exc
        if self.registry_sync is not None:
            if self.url is None:
                raise ValueError("registry_sync requires a registry URL")
            if self.source_type not in {
                TrustSourceType.TRUST_LIST.value,
                TrustSourceType.PKD_URL.value,
            }:
                raise ValueError(
                    "registry_sync requires TRUST_LIST or PKD_URL source_type"
                )
        elif self.url is not None and self.source_type in {
            TrustSourceType.TRUST_LIST.value,
            TrustSourceType.PKD_URL.value,
        }:
            raise ValueError(
                "URL trust registries require an explicit supported registry_sync protocol"
            )
        if self.certificate_pem is not None and not self.certificate_pem.startswith(
            "-----BEGIN CERTIFICATE-----"
        ):
            raise ValueError("certificate_pem must contain a PEM certificate")
        if self.issuer_did is not None and not self.issuer_did.startswith("did:"):
            raise ValueError("issuer_did must be a DID")
        return self


def _validated_registry_sync_config(source: TrustSource) -> RegistrySyncConfigModel:
    try:
        return RegistrySyncConfigModel.model_validate(source.registry_sync)
    except ValidationError as exc:
        raise RegistrySyncError(
            "stored registry sync configuration is invalid"
        ) from exc


class ValidationRulesModel(BaseModel):
    allowed_algorithms: list[str] = Field(
        default_factory=lambda: ["ES256", "ES384", "EdDSA"]
    )
    min_key_size_rsa: int = 2048
    min_key_size_ec: int = 256
    require_key_usage: bool = True
    max_chain_depth: int = 5
    allow_self_signed: bool = False


class RevocationPolicyModel(BaseModel):
    check_mode: str = "HARD_FAIL"
    check_ocsp: bool = True
    check_crl: bool = True
    check_status_list: bool = True
    offline_grace_period_hours: int = 24
    cache_duration_hours: int = 1


class TimePolicyModel(BaseModel):
    max_clock_skew_seconds: int = 300
    credential_freshness_hours: int | None = None
    require_not_before: bool = True
    require_expiration: bool = True


class CreateTrustProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    profile_type: str = TrustProfileType.CUSTOM.value
    compliance_status: str = ComplianceStatus.SETUP_REQUIRED.value
    trust_sources: list[TrustSourceModel] = Field(default_factory=list)
    validation_rules: ValidationRulesModel | None = None
    allowed_algorithms: list[str] | None = None
    min_key_size_rsa: int | None = None
    min_key_size_ec: int | None = None
    require_key_usage: bool | None = None
    max_chain_depth: int | None = None
    allow_self_signed: bool | None = None
    revocation_policy: RevocationPolicyModel | None = (
        None  # DEPRECATED: use revocation_profile_id
    )
    revocation_profile_id: str | None = None  # NEW: links to RevocationProfile
    time_policy: TimePolicyModel | None = None
    supported_formats: list[str] = Field(default_factory=lambda: ["SD_JWT_VC", "MDOC"])
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    system_issuer_overrides: dict[str, dict[str, Any]] = Field(default_factory=dict)
    compatible_compliance_codes: list[str] = Field(default_factory=list)
    verification_policy_set_id: str | None = None
    auto_generated: bool = False


class UpdateTrustProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    profile_type: str | None = None
    compliance_status: str | None = None
    trust_sources: list[TrustSourceModel] | None = None
    validation_rules: ValidationRulesModel | None = None
    allowed_algorithms: list[str] | None = None
    min_key_size_rsa: int | None = None
    min_key_size_ec: int | None = None
    require_key_usage: bool | None = None
    max_chain_depth: int | None = None
    allow_self_signed: bool | None = None
    revocation_policy: RevocationPolicyModel | None = None  # DEPRECATED
    revocation_profile_id: str | None = None  # NEW
    time_policy: TimePolicyModel | None = None
    supported_formats: list[str] | None = None
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    system_issuer_overrides: dict[str, dict[str, Any]] | None = None
    compatible_compliance_codes: list[str] | None = None
    verification_policy_set_id: str | None = None
    auto_generated: bool | None = None


class TrustProfileResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    profile_type: str
    compliance_status: str
    trust_sources: list[dict]
    allowed_algorithms: list[str]
    revocation_policy: dict | None = None
    revocation_services: dict | None = None
    revocation_profile_id: str | None  # NEW
    time_policy: dict
    supported_formats: list[str]
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    system_issuer_overrides: dict[str, dict[str, Any]] = Field(default_factory=dict)
    compatible_compliance_codes: list[str] = Field(default_factory=list)
    verification_policy_set_id: str | None = None
    auto_generated: bool = False
    created_at: str
    updated_at: str


def _field_was_provided(model: BaseModel, field_name: str) -> bool:
    fields = getattr(model, "model_fields_set", None)
    if fields is not None:
        return field_name in fields

    legacy_fields = getattr(model, "__fields_set__", None)
    if legacy_fields is not None:
        return field_name in legacy_fields

    return False


def _normalize_accreditations(values: list[str]) -> list[str]:
    """Validate and normalize public accreditation identifiers."""
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("accreditation identifiers cannot be blank")
        if len(cleaned) > 128:
            raise ValueError("accreditation identifiers cannot exceed 128 characters")
        comparison_key = cleaned.casefold()
        if comparison_key in seen:
            raise ValueError(
                "accreditation identifiers must be unique case-insensitively"
            )
        seen.add(comparison_key)
        normalized.append(cleaned)
    return normalized


class CreateIssuerEntityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(max_length=255)
    issuer_id: str = Field(..., min_length=1, max_length=512)
    issuer_type: Literal["ORGANIZATION", "GOVERNMENT", "DEVICE"] = "ORGANIZATION"
    display_name: str = Field(..., min_length=1, max_length=256)
    description: str | None = Field(None, max_length=1024)
    compliance_status: Literal["ACCREDITED", "COMPLIANT", "SUSPENDED"] = "COMPLIANT"
    accreditation_body: str | None = Field(None, max_length=256)
    accreditations: list[str] = Field(default_factory=list, max_length=64)
    accreditation_date: str | None = Field(None, max_length=50)
    valid_from: str | None = Field(None, max_length=50)
    valid_until: str | None = Field(None, max_length=50)
    trust_anchor_id: str | None = Field(None, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("accreditations")
    @classmethod
    def validate_accreditations(cls, values: list[str]) -> list[str]:
        return _normalize_accreditations(values)

    @model_validator(mode="after")
    def reject_private_custody_metadata(self) -> CreateIssuerEntityRequest:
        _reject_private_custody_metadata(self.metadata)
        return self


class UpdateIssuerEntityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(max_length=255)
    display_name: str | None = Field(None, min_length=1, max_length=256)
    description: str | None = Field(None, max_length=1024)
    issuer_type: Literal["ORGANIZATION", "GOVERNMENT", "DEVICE"] | None = None
    compliance_status: (
        Literal["ACCREDITED", "COMPLIANT", "SUSPENDED", "REVOKED"] | None
    ) = None
    accreditation_body: str | None = Field(None, max_length=256)
    accreditations: list[str] | None = Field(None, max_length=64)
    accreditation_date: str | None = Field(None, max_length=50)
    valid_from: str | None = Field(None, max_length=50)
    valid_until: str | None = Field(None, max_length=50)
    trust_anchor_id: str | None = Field(None, max_length=255)
    metadata: dict[str, Any] | None = None
    revocation_reason: str | None = Field(None, max_length=512)

    @field_validator("accreditations")
    @classmethod
    def validate_accreditations(cls, values: list[str] | None) -> list[str] | None:
        return None if values is None else _normalize_accreditations(values)

    @model_validator(mode="after")
    def validate_update(self) -> UpdateIssuerEntityRequest:
        if not (self.model_fields_set - {"organization_id"}):
            raise ValueError("at least one issuer entity field is required")
        for field_name in (
            "display_name",
            "issuer_type",
            "compliance_status",
            "accreditations",
            "valid_from",
            "metadata",
        ):
            if (
                field_name in self.model_fields_set
                and getattr(self, field_name) is None
            ):
                raise ValueError(f"{field_name} cannot be null")
        if self.compliance_status == "REVOKED" and not self.revocation_reason:
            raise ValueError("revocation_reason is required when revoking an issuer")
        if self.revocation_reason is not None and self.compliance_status != "REVOKED":
            raise ValueError("revocation_reason is valid only for a revocation")
        _reject_private_custody_metadata(self.metadata)
        return self


class CreateTrustProfileIssuerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer_id: str = Field(
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    trust_level: int = Field(default=100, ge=0, le=100)
    relationship_status: Literal["TRUSTED", "DENIED", "UNDER_REVIEW"] = "TRUSTED"
    cascade_revocation_policy: Literal["AUTO_CASCADE", "MANUAL", "NOTIFY_ONLY"] = (
        "NOTIFY_ONLY"
    )
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_private_custody_metadata(self) -> CreateTrustProfileIssuerRequest:
        _reject_private_custody_metadata(self.metadata)
        return self


class UpdateTrustProfileIssuerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trust_level: int | None = Field(default=None, ge=0, le=100)
    relationship_status: Literal["TRUSTED", "DENIED", "UNDER_REVIEW"] | None = None
    cascade_revocation_policy: (
        Literal["AUTO_CASCADE", "MANUAL", "NOTIFY_ONLY"] | None
    ) = None
    metadata: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_update(self) -> UpdateTrustProfileIssuerRequest:
        if not self.model_fields_set:
            raise ValueError("at least one trust relationship field is required")
        if "metadata" in self.model_fields_set and self.metadata is None:
            raise ValueError("metadata cannot be null")
        _reject_private_custody_metadata(self.metadata)
        return self


TRUST_SOURCE_TYPE_ALIASES = {
    "registry": TrustSourceType.TRUST_LIST.value,
    "trust_list": TrustSourceType.TRUST_LIST.value,
    "allowlist": TrustSourceType.PINNED_ISSUER.value,
    "pinned_issuer": TrustSourceType.PINNED_ISSUER.value,
    "pinned_root": TrustSourceType.ROOT_CA.value,
    "root_ca": TrustSourceType.ROOT_CA.value,
    "pkd": TrustSourceType.PKD_URL.value,
    "pkd_url": TrustSourceType.PKD_URL.value,
}


def _normalize_trust_source_type(value: str) -> str:
    return TRUST_SOURCE_TYPE_ALIASES.get(value.lower(), value.upper())


def _build_validation_rules(
    request_validation_rules: ValidationRulesModel | None,
    allowed_algorithms: list[str] | None,
    min_key_size_rsa: int | None,
    min_key_size_ec: int | None,
    require_key_usage: bool | None,
    max_chain_depth: int | None,
    allow_self_signed: bool | None,
    current: ValidationRules | None = None,
) -> ValidationRules:
    base = current or ValidationRules()
    return ValidationRules(
        allowed_algorithms=(
            allowed_algorithms
            or (
                request_validation_rules.allowed_algorithms
                if request_validation_rules
                else None
            )
            or base.allowed_algorithms
        ),
        min_key_size_rsa=(
            min_key_size_rsa
            if min_key_size_rsa is not None
            else (
                request_validation_rules.min_key_size_rsa
                if request_validation_rules
                else base.min_key_size_rsa
            )
        ),
        min_key_size_ec=(
            min_key_size_ec
            if min_key_size_ec is not None
            else (
                request_validation_rules.min_key_size_ec
                if request_validation_rules
                else base.min_key_size_ec
            )
        ),
        require_key_usage=(
            require_key_usage
            if require_key_usage is not None
            else (
                request_validation_rules.require_key_usage
                if request_validation_rules
                else base.require_key_usage
            )
        ),
        max_chain_depth=(
            max_chain_depth
            if max_chain_depth is not None
            else (
                request_validation_rules.max_chain_depth
                if request_validation_rules
                else base.max_chain_depth
            )
        ),
        allow_self_signed=(
            allow_self_signed
            if allow_self_signed is not None
            else (
                request_validation_rules.allow_self_signed
                if request_validation_rules
                else base.allow_self_signed
            )
        ),
    )


def _build_trust_sources(trust_sources: list[TrustSourceModel]) -> list[TrustSource]:
    return [
        TrustSource(
            name=ts.description or ts.url or ts.issuer_did or "Trust Source",
            source_type=_normalize_trust_source_type(ts.source_type),
            url=ts.url,
            certificate_pem=ts.certificate_pem,
            issuer_did=ts.issuer_did,
            description=ts.description,
            refresh_interval_hours=(
                ts.registry_sync.refresh_interval_hours if ts.registry_sync else 24
            ),
            registry_sync=(
                ts.registry_sync.model_dump(mode="json") if ts.registry_sync else None
            ),
        )
        for ts in trust_sources
    ]


def _normalize_supported_formats(values: list[str]) -> list[CredentialFormat]:
    return [CredentialFormat(value.upper()) for value in values]


def _normalize_optional_formats(
    values: list[str] | None,
) -> list[CredentialFormat] | None:
    if values is None:
        return None
    return [CredentialFormat(value.upper()) for value in values]


def _parse_optional_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _validate_jurisdiction_filter(values: list[str] | None) -> None:
    if values is None:
        return
    for value in values:
        normalized = value.upper()
        parts = normalized.split("-")
        if len(parts) > 2 or len(parts[0]) != 2 or not parts[0].isalpha():
            raise HTTPException(
                status_code=422, detail=f"Invalid jurisdiction code: {value}"
            )
        if len(parts) == 2 and (not 1 <= len(parts[1]) <= 3 or not parts[1].isalnum()):
            raise HTTPException(
                status_code=422, detail=f"Invalid jurisdiction code: {value}"
            )


_PRIVATE_CUSTODY_METADATA_FIELDS = {
    "issuer_algorithm",
    "issuer_key_id",
    "issuer_profile_id",
    "key_access_mode",
    "key_binding",
    "key_management",
    "key_reference",
    "key_name",
    "key_version",
    "kms_arn",
    "kms_provider",
    "kms_region",
    "managed_key_id",
    "provider",
    "service_id",
    "signing_agent_auth",
    "signing_agent_url",
    "signing_key_reference",
    "signing_service_id",
    "transit_mount",
    "verification_method_id",
}

_PRIVATE_JWK_PARAMETERS = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}


def _find_private_custody_metadata(value: Any) -> str | None:
    if isinstance(value, dict):
        normalized_keys = {str(key).lower() for key in value}
        if "kty" in normalized_keys:
            private_parameters = normalized_keys & _PRIVATE_JWK_PARAMETERS
            if private_parameters:
                return f"private JWK parameter '{sorted(private_parameters)[0]}'"
        for key, nested_value in value.items():
            if str(key).lower() in _PRIVATE_CUSTODY_METADATA_FIELDS:
                return str(key)
            found = _find_private_custody_metadata(nested_value)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            found = _find_private_custody_metadata(item)
            if found is not None:
                return found
    return None


def _reject_private_custody_metadata(metadata: dict[str, Any] | None) -> None:
    field_name = _find_private_custody_metadata(metadata)
    if field_name is not None:
        raise ValueError(
            f"Public metadata cannot contain private custody selector or private key material '{field_name}'; "
            "signing is resolved from the issuer DID through an issuer profile"
        )


def _sanitize_private_custody_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        is_jwk = "kty" in {str(key).lower() for key in value}
        return {
            key: _sanitize_private_custody_metadata(nested_value)
            for key, nested_value in value.items()
            if str(key).lower() not in _PRIVATE_CUSTODY_METADATA_FIELDS
            and not (is_jwk and str(key).lower() in _PRIVATE_JWK_PARAMETERS)
        }
    if isinstance(value, list):
        return [_sanitize_private_custody_metadata(item) for item in value]
    return value


def _normalize_jurisdiction_filter(values: list[str] | None) -> list[str] | None:
    if values is None:
        return None
    _validate_jurisdiction_filter(values)
    return [value.upper() for value in values]


def _build_issuer_entity_from_request(
    request: CreateIssuerEntityRequest,
) -> IssuerEntity:
    return IssuerEntity(
        organization_id=request.organization_id,
        issuer_id=request.issuer_id,
        issuer_type=IssuerEntityType(request.issuer_type.upper()),
        display_name=request.display_name,
        description=request.description,
        is_system_issuer=False,
        compliance_status=IssuerEntityComplianceStatus(
            request.compliance_status.upper()
        ),
        accreditation_body=request.accreditation_body,
        accreditations=request.accreditations,
        accreditation_date=_parse_optional_datetime(request.accreditation_date),
        valid_from=_parse_optional_datetime(request.valid_from)
        or datetime.now(timezone.utc),
        valid_until=_parse_optional_datetime(request.valid_until),
        trust_anchor_id=request.trust_anchor_id,
        metadata=request.metadata,
    )


async def _get_issuer_entity_or_404(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository,
    issuer_entity_id: str,
) -> IssuerEntity:
    issuer_entity = await repo.get_issuer_entity(issuer_entity_id)
    if not issuer_entity:
        raise HTTPException(status_code=404, detail="Issuer Entity not found")
    return issuer_entity


async def _get_profile_issuer_or_404(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository,
    profile_issuer_id: str,
) -> TrustProfileIssuer:
    profile_issuer = await repo.get_profile_issuer(profile_issuer_id)
    if not profile_issuer:
        raise HTTPException(status_code=404, detail="Trust Profile Issuer not found")
    return profile_issuer


async def _ensure_unique_issuer_identifier(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository,
    organization_id: str | None,
    issuer_id: str,
    excluding_id: str | None = None,
) -> None:
    existing = await repo.find_issuer_entity_by_identifier(organization_id, issuer_id)
    if existing and existing.id != excluding_id:
        raise HTTPException(
            status_code=409, detail="Issuer identifier already exists in this scope"
        )


async def _get_organization_trust_profile_or_404(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository,
    profile_id: str,
) -> OrganizationTrustProfile:
    profile = await repo.get_organization_trust_profile(profile_id)
    if not profile:
        raise HTTPException(
            status_code=404, detail="Organization Trust Profile not found"
        )
    return profile


async def _materialize_trust_profile_issuer(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository,
    profile_issuer: TrustProfileIssuer,
) -> TrustProfileIssuerResponse:
    # Resolve the foreign key before returning it so a stale relationship never
    # masquerades as a valid public resource.
    await _get_issuer_entity_or_404(repo, profile_issuer.issuer_id)
    return TrustProfileIssuerResponse(
        id=profile_issuer.id,
        trust_profile_id=profile_issuer.trust_profile_id,
        issuer_id=profile_issuer.issuer_id,
        trust_level=profile_issuer.trust_level,
        relationship_status=profile_issuer.relationship_status.value,
        cascade_revocation_policy=profile_issuer.cascade_revocation_policy.value,
        metadata=profile_issuer.metadata or {},
        created_at=profile_issuer.created_at.isoformat(),
        updated_at=profile_issuer.updated_at.isoformat(),
    )


class TrustProfileIssuerResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    trust_profile_id: str = Field(
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    issuer_id: str = Field(
        pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    trust_level: int = Field(ge=0, le=100)
    relationship_status: Literal["TRUSTED", "DENIED", "UNDER_REVIEW"]
    cascade_revocation_policy: Literal["AUTO_CASCADE", "MANUAL", "NOTIFY_ONLY"]
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str | None = None

    @model_validator(mode="after")
    def reject_private_custody_metadata(self) -> TrustProfileIssuerResponse:
        _reject_private_custody_metadata(self.metadata)
        return self


class IssuerEntityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    organization_id: str | None = None
    issuer_id: str
    issuer_type: str
    display_name: str
    description: str | None = None
    is_system_issuer: bool
    compliance_status: str
    accreditation_body: str | None = None
    accreditations: list[str] = Field(max_length=64)
    accreditation_date: str | None = None
    valid_from: str
    valid_until: str | None = None
    trust_anchor_id: str | None = None
    revoked_at: str | None = None
    revocation_reason: str | None = None
    revoked_by: str | None = None
    metadata: dict[str, Any]
    created_at: str
    updated_at: str

    @model_validator(mode="after")
    def reject_private_custody_metadata(self) -> IssuerEntityResponse:
        _reject_private_custody_metadata(self.metadata)
        return self

    @field_validator("accreditations")
    @classmethod
    def validate_accreditations(cls, values: list[str]) -> list[str]:
        return _normalize_accreditations(values)


class TrustFrameworkResponse(BaseModel):
    id: str
    code: str
    display_name: str
    description: str | None = None
    pkd_endpoints: list[str] = Field(default_factory=list)
    default_algorithms: list[str] = Field(default_factory=list)
    default_formats: list[str] = Field(default_factory=list)
    validation_ruleset: dict[str, Any] = Field(default_factory=dict)
    sync_config: dict[str, Any] = Field(default_factory=dict)
    is_system: bool = True
    created_at: str
    updated_at: str


class TrustRegistryEntryResponse(BaseModel):
    entry_id: str
    anchor_type: str
    operation: str
    country_code: str
    certificate_pem: str | None = None
    subject_key_id: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    source: str


class TrustRegistrySyncResponse(BaseModel):
    sync_token: str
    sequence: int
    entries: list[TrustRegistryEntryResponse] = Field(default_factory=list)
    has_more: bool = False
    generated_at: str


class TrustRegistryStatusResponse(BaseModel):
    status: str
    current_sequence: int
    total_entries: int
    current_entries: int
    csca_entries: int
    dsc_entries: int
    generated_at: str


class TrustProfileRegistrySourceSyncResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(pattern=r"^https://")
    protocol: Literal["MARTY_TRUST_REGISTRY_SYNC_V1"]
    sequence: int = Field(ge=0)
    csca_entries: int = Field(ge=0)
    dsc_entries: int = Field(ge=0)
    synchronized_at: AwareDatetime

    @field_validator("url")
    @classmethod
    def validate_result_url(cls, value: str) -> str:
        try:
            return validate_registry_url_structure(value)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc


class TrustProfileRegistrySyncResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trust_profile_id: uuid.UUID
    sources: list[TrustProfileRegistrySourceSyncResponse] = Field(min_length=1)
    synchronized_at: AwareDatetime


class CreateOrganizationTrustProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework_id: str
    name: str
    display_name: str | None = None
    description: str | None = None
    enabled: bool = True
    use_case_tags: list[str] = Field(default_factory=list)
    compliance_status: str = ComplianceStatus.SETUP_REQUIRED.value
    auto_generated: bool = False
    revocation_policy: dict[str, Any] | None = None
    time_policy: dict[str, Any] | None = None
    allowed_algorithms: list[str] | None = None
    allowed_formats: list[str] | None = None
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    jurisdiction_filter: list[str] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_private_custody_metadata(self) -> CreateOrganizationTrustProfileRequest:
        _reject_private_custody_metadata(self.metadata)
        return self


class UpdateOrganizationTrustProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    display_name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    use_case_tags: list[str] | None = None
    compliance_status: str | None = None
    auto_generated: bool | None = None
    revocation_policy: dict[str, Any] | None = None
    time_policy: dict[str, Any] | None = None
    allowed_algorithms: list[str] | None = None
    allowed_formats: list[str] | None = None
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    jurisdiction_filter: list[str] | None = None
    metadata: dict[str, Any] | None = None

    @model_validator(mode="after")
    def reject_private_custody_metadata(self) -> UpdateOrganizationTrustProfileRequest:
        _reject_private_custody_metadata(self.metadata)
        return self


class OrganizationTrustProfileResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    organization_id: str
    framework_id: str
    name: str
    display_name: str | None = None
    description: str | None = None
    enabled: bool = True
    use_case_tags: list[str] = Field(default_factory=list)
    compliance_status: str
    auto_generated: bool = False
    revocation_policy: dict[str, Any] | None = None
    time_policy: dict[str, Any] | None = None
    allowed_algorithms: list[str] | None = None
    allowed_formats: list[str] | None = None
    allowed_issuers: list[str] | None = None
    denied_issuers: list[str] | None = None
    jurisdiction_filter: list[str] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str | None = None

    @model_validator(mode="after")
    def reject_private_custody_metadata(self) -> OrganizationTrustProfileResponse:
        _reject_private_custody_metadata(self.metadata)
        return self


class TrustDecisionIssuerResponse(BaseModel):
    """Minimal issuer relationship material consumed by verification services."""

    model_config = ConfigDict(extra="forbid")

    issuer_id: str = Field(..., min_length=1, max_length=512)
    trust_level: int = Field(ge=0, le=100)
    relationship_status: Literal["TRUSTED", "DENIED", "UNDER_REVIEW"]
    compliance_status: Literal["ACCREDITED", "COMPLIANT", "SUSPENDED", "REVOKED"]
    accreditation_body: str | None = None
    accreditations: list[str] = Field(default_factory=list, max_length=64)
    valid_from: str
    valid_until: str | None = None
    revoked_at: str | None = None


class InternalTrustProfileResponse(TrustProfileResponse):
    """Internal verification view with normalized issuer decisions."""

    model_config = ConfigDict(extra="forbid")

    issuer_relationships: list[TrustDecisionIssuerResponse] = Field(
        default_factory=list
    )


def _imported_registry_trust_sources(profile: TrustProfile) -> list[dict[str, Any]]:
    """Return fresh imported anchors or fail before a trust decision is made."""
    imported_sources: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    for source in profile.trust_sources:
        if not source.enabled:
            continue
        if source.registry_sync is None:
            if source.url and source.source_type in {
                TrustSourceType.TRUST_LIST.value,
                TrustSourceType.PKD_URL.value,
            }:
                raise HTTPException(
                    status_code=503,
                    detail="Trust Profile registry source has no supported sync protocol",
                )
            continue
        try:
            sync_config = _validated_registry_sync_config(source)
        except RegistrySyncError as exc:
            raise HTTPException(
                status_code=503,
                detail="Trust Profile registry configuration is invalid",
            ) from exc
        if source.registry_last_synced_at is None:
            raise HTTPException(
                status_code=503,
                detail="Trust Profile registry source has never synchronized",
            )
        stale_after = source.registry_last_synced_at + timedelta(
            hours=sync_config.refresh_interval_hours
        )
        if now >= stale_after:
            raise HTTPException(
                status_code=503,
                detail="Trust Profile registry source is stale",
            )
        try:
            stored_state = state_from_storage(
                sync_token=source.registry_sync_token,
                sequence=source.registry_sequence,
                entries=source.registry_entries,
                synchronized_at=source.registry_last_synced_at,
            )
            current_entries = validate_current_registry_entries(
                stored_state.entries,
                now=now,
            )
        except RegistrySyncError as exc:
            raise HTTPException(
                status_code=503,
                detail="Trust Profile registry state is invalid",
            ) from exc
        for imported in current_entries.values():
            anchor_type = imported.anchor_type
            certificate_pem = imported.certificate_pem
            imported_sources.append(
                {
                    "source_type": (
                        TrustSourceType.ROOT_CA.value
                        if anchor_type == "CSCA"
                        else TrustSourceType.PINNED_ISSUER.value
                    ),
                    "certificate_pem": certificate_pem,
                    "description": (
                        f"Imported {anchor_type} from {source.url or 'registry'}"
                    ),
                    "pinned_certificates": [],
                }
            )
    return imported_sources


async def _internal_profile_to_response(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository,
    profile: TrustProfile,
) -> InternalTrustProfileResponse:
    """Materialize normalized issuer relationships for a trust decision."""
    decisions: list[TrustDecisionIssuerResponse] = []
    for relationship in await repo.list_profile_issuers(profile.id):
        issuer = await repo.get_issuer_entity(relationship.issuer_id)
        if issuer is None:
            raise HTTPException(
                status_code=503,
                detail="Trust Profile contains an unresolved issuer relationship",
            )
        if issuer.organization_id != profile.organization_id and not (
            issuer.organization_id is None and issuer.is_system_issuer
        ):
            raise HTTPException(
                status_code=503,
                detail="Trust Profile contains a cross-organization issuer relationship",
            )
        decisions.append(
            TrustDecisionIssuerResponse(
                issuer_id=issuer.issuer_id,
                trust_level=relationship.trust_level,
                relationship_status=relationship.relationship_status.value,
                compliance_status=issuer.compliance_status.value,
                accreditation_body=issuer.accreditation_body,
                accreditations=list(issuer.accreditations),
                valid_from=issuer.valid_from.isoformat(),
                valid_until=(
                    issuer.valid_until.isoformat() if issuer.valid_until else None
                ),
                revoked_at=(
                    issuer.revoked_at.isoformat() if issuer.revoked_at else None
                ),
            )
        )

    public_response = _profile_to_response(profile)
    effective_sources = [
        *public_response.trust_sources,
        *_imported_registry_trust_sources(profile),
    ]
    return InternalTrustProfileResponse(
        **{
            **public_response.model_dump(),
            "trust_sources": effective_sources,
        },
        issuer_relationships=decisions,
    )


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/trust-profiles", tags=["trust-profiles"])
internal_router = APIRouter(
    prefix="/internal/v1/trust-profiles", tags=["internal-trust-profiles"]
)
resource_owner_router = APIRouter(
    prefix="/internal/v1/resource-owners",
    tags=["internal-resource-owners"],
)
organization_trust_profile_router = APIRouter(
    prefix="/v1/organizations/{organization_id}/trust-profiles",
    tags=["organization-trust-profiles"],
)
framework_router = APIRouter(prefix="/v1/trust-frameworks", tags=["trust-frameworks"])
registry_router = APIRouter(prefix="/v1/trust-registry", tags=["trust-registry"])
issuer_router = APIRouter(prefix="/v1/issuer-entities", tags=["issuer-entities"])

_repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository | None = None

MARTY_ORG_ID = os.environ.get("MARTY_ORG_ID", MARTY_DEFAULT_ORG_ID)
MARTY_TRUST_PROFILE_ID = MARTY_LOGIN_TRUST_PROFILE_ID
MARTY_TRUSTED_ISSUER_ID = MARTY_LOGIN_TRUSTED_ISSUER_ID
MARTY_ISSUER_ENTITY_ID = "60000000-0000-0000-0000-000000000012"
MARTY_REVOCATION_PROFILE_ID = MARTY_DEFAULT_REVOCATION_PROFILE_ID


def _marty_issuer_base_url() -> str:
    return resolve_marty_issuer_base_url()


def _marty_issuer_did() -> str:
    return resolve_marty_issuer_did()


def get_repo() -> InMemoryTrustProfileRepository | PostgresTrustProfileRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


def _read_internal_api_key() -> str:
    direct = os.environ.get("SIGNING_KEYS_INTERNAL_API_KEY")
    if direct:
        return direct
    file_path = os.environ.get("SIGNING_KEYS_INTERNAL_API_KEY_FILE")
    if not file_path:
        return ""
    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _verify_internal_api_key(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> str:
    expected = _read_internal_api_key()
    if not expected:
        raise HTTPException(
            status_code=503, detail="Internal API key is not configured"
        )
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid internal API key")
    return x_api_key


async def _seed_system_frameworks(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository,
) -> None:
    for framework in SYSTEM_TRUST_FRAMEWORKS:
        existing = await repo.get_framework_by_code(framework.code)
        if existing:
            continue
        await repo.save_framework(framework)


async def _bootstrap_marty_login_trust_profile(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository,
) -> None:
    """Ensure Marty org has a trust profile linked to the default revocation profile."""
    issuer_did = _marty_issuer_did()
    issuer_url = _marty_issuer_base_url()
    managed_trust_source = TrustSource(
        id=MARTY_TRUST_BUNDLE_SOURCE_ID,
        name="Marty Managed Issuer",
        source_type=TrustSourceType.PINNED_ISSUER.value,
        issuer_did=issuer_did,
        description="Marty managed issuer DID",
        enabled=True,
        refresh_interval_hours=24,
        pinned_certificates=[],
    )
    profile = await repo.get_profile(MARTY_TRUST_PROFILE_ID)

    if profile is None:
        profile = TrustProfile(
            id=MARTY_TRUST_PROFILE_ID,
            organization_id=MARTY_ORG_ID,
            name="Marty Credential Login Trust",
            description="Default trust profile for Marty credential-login preview flows.",
            status=TrustProfileStatus.ACTIVE,
            trust_sources=[managed_trust_source],
            validation_rules=ValidationRules(
                allowed_algorithms=["ES256", "EdDSA"],
                min_key_size_rsa=2048,
                min_key_size_ec=256,
                require_key_usage=True,
                max_chain_depth=5,
                allow_self_signed=False,
            ),
            revocation_policy=RevocationPolicy(
                check_mode=RevocationCheckMode.HARD_FAIL,
                check_ocsp=True,
                check_crl=True,
                check_status_list=True,
                offline_grace_period_hours=12,
                cache_duration_hours=24,
            ),
            revocation_profile_id=MARTY_REVOCATION_PROFILE_ID,
            time_policy=TimePolicy(
                max_clock_skew_seconds=300,
                credential_freshness_hours=24,
                require_not_before=True,
                require_expiration=True,
            ),
            supported_formats=[CredentialFormat.SD_JWT_VC, CredentialFormat.MDOC],
        )
        await repo.save_profile(profile)
    elif profile.organization_id == MARTY_ORG_ID:
        changed = False
        if profile.revocation_profile_id != MARTY_REVOCATION_PROFILE_ID:
            profile.revocation_profile_id = MARTY_REVOCATION_PROFILE_ID
            changed = True
        trust_sources = list(profile.trust_sources or [])
        matched_source = False
        for index, source in enumerate(trust_sources):
            if (
                source.id == managed_trust_source.id
                or source.name == managed_trust_source.name
            ):
                matched_source = True
                if (
                    source.issuer_did != issuer_did
                    or source.source_type != TrustSourceType.PINNED_ISSUER.value
                ):
                    trust_sources[index] = managed_trust_source
                    changed = True
                break
        if not matched_source:
            trust_sources.append(managed_trust_source)
            changed = True
        if changed:
            profile.trust_sources = trust_sources
            profile.updated_at = datetime.now(timezone.utc)
            await repo.save_profile(profile)

    issuer_entity = await repo.get_issuer_entity(MARTY_ISSUER_ENTITY_ID)
    if issuer_entity is None:
        issuer_entity = await repo.find_issuer_entity_by_identifier(
            MARTY_ORG_ID, issuer_did
        )
    if issuer_entity is None:
        issuer_entity = IssuerEntity(
            id=MARTY_ISSUER_ENTITY_ID,
            organization_id=MARTY_ORG_ID,
            issuer_id=issuer_did,
            display_name="Marty Managed Issuer",
            description="Default issuer for Marty credential-login bootstrap.",
            compliance_status=IssuerEntityComplianceStatus.COMPLIANT,
            metadata={"issuer_url": issuer_url, "verification_keys": []},
        )
    elif issuer_entity.organization_id == MARTY_ORG_ID:
        issuer_entity.issuer_id = issuer_did
        issuer_entity.display_name = "Marty Managed Issuer"
        issuer_entity.description = (
            "Default issuer for Marty credential-login bootstrap."
        )
        issuer_entity.metadata = {
            **(issuer_entity.metadata or {}),
            "issuer_url": issuer_url,
            "verification_keys": [],
        }
        issuer_entity.updated_at = datetime.now(timezone.utc)
    await repo.save_issuer_entity(issuer_entity)

    profile_issuer = await repo.get_profile_issuer(MARTY_TRUSTED_ISSUER_ID)
    if profile_issuer is None:
        profile_issuer = TrustProfileIssuer(
            id=MARTY_TRUSTED_ISSUER_ID,
            trust_profile_id=MARTY_TRUST_PROFILE_ID,
            issuer_id=issuer_entity.id,
        )
    elif profile_issuer.trust_profile_id == MARTY_TRUST_PROFILE_ID:
        profile_issuer.issuer_id = issuer_entity.id
        profile_issuer.updated_at = datetime.now(timezone.utc)
    profile_issuer.metadata = {
        "credential_template_ids": [
            MARTY_MEMBER_SD_JWT_TEMPLATE_ID,
            MARTY_MEMBER_MDOC_TEMPLATE_ID,
        ]
    }
    await repo.save_profile_issuer(profile_issuer)


def get_current_user_id(x_user_id: Annotated[str, Header()]) -> str:
    """Extract user ID from X-User-Id header (injected by gateway)."""
    return x_user_id


@organization_trust_profile_router.post(
    "",
    response_model=OrganizationTrustProfileResponse,
    response_model_exclude_none=True,
)
async def create_organization_trust_profile(
    organization_id: str,
    request: CreateOrganizationTrustProfileRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> OrganizationTrustProfileResponse:
    membership = await app.state.org_client.get_membership(user_id, organization_id)
    ensure_membership_permission(membership, "trust-profile", "create")

    framework = await repo.get_framework(request.framework_id)
    if not framework:
        raise HTTPException(status_code=422, detail="Trust Framework not found")

    profile = OrganizationTrustProfile(
        organization_id=organization_id,
        framework_id=request.framework_id,
        name=request.name,
        display_name=request.display_name,
        description=request.description,
        enabled=request.enabled,
        use_case_tags=request.use_case_tags,
        compliance_status=ComplianceStatus(request.compliance_status.upper()),
        auto_generated=request.auto_generated,
        revocation_policy=request.revocation_policy,
        time_policy=request.time_policy,
        allowed_algorithms=request.allowed_algorithms,
        allowed_formats=_normalize_optional_formats(request.allowed_formats),
        allowed_issuers=request.allowed_issuers,
        denied_issuers=request.denied_issuers,
        jurisdiction_filter=_normalize_jurisdiction_filter(request.jurisdiction_filter),
        metadata=request.metadata,
    )
    await repo.save_organization_trust_profile(profile)
    return _organization_trust_profile_to_response(profile)


@organization_trust_profile_router.get(
    "",
    response_model=list[OrganizationTrustProfileResponse],
    response_model_exclude_none=True,
)
async def list_organization_trust_profiles(
    organization_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> list[OrganizationTrustProfileResponse]:
    membership = await app.state.org_client.get_membership(user_id, organization_id)
    ensure_membership_permission(membership, "trust-profile", "view")
    profiles = await repo.list_organization_trust_profiles(organization_id)
    return [_organization_trust_profile_to_response(profile) for profile in profiles]


@organization_trust_profile_router.get(
    "/{profile_id}",
    response_model=OrganizationTrustProfileResponse,
    response_model_exclude_none=True,
)
async def get_organization_trust_profile(
    organization_id: str,
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> OrganizationTrustProfileResponse:
    profile = await _get_organization_trust_profile_or_404(repo, profile_id)
    if profile.organization_id != organization_id:
        raise HTTPException(
            status_code=404, detail="Organization Trust Profile not found"
        )
    membership = await app.state.org_client.get_membership(user_id, organization_id)
    ensure_membership_permission(membership, "trust-profile", "view")
    return _organization_trust_profile_to_response(profile)


@organization_trust_profile_router.put(
    "/{profile_id}",
    response_model=OrganizationTrustProfileResponse,
    response_model_exclude_none=True,
)
async def update_organization_trust_profile(
    organization_id: str,
    profile_id: str,
    request: UpdateOrganizationTrustProfileRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> OrganizationTrustProfileResponse:
    profile = await _get_organization_trust_profile_or_404(repo, profile_id)
    if profile.organization_id != organization_id:
        raise HTTPException(
            status_code=404, detail="Organization Trust Profile not found"
        )
    membership = await app.state.org_client.get_membership(user_id, organization_id)
    ensure_membership_permission(membership, "trust-profile", "edit")

    if request.name is not None:
        profile.name = request.name
    if request.display_name is not None:
        profile.display_name = request.display_name
    if request.description is not None:
        profile.description = request.description
    if request.enabled is not None:
        profile.enabled = request.enabled
    if request.use_case_tags is not None:
        profile.use_case_tags = request.use_case_tags
    if request.compliance_status is not None:
        profile.compliance_status = ComplianceStatus(request.compliance_status.upper())
    if request.auto_generated is not None:
        profile.auto_generated = request.auto_generated
    if request.revocation_policy is not None:
        profile.revocation_policy = request.revocation_policy
    if request.time_policy is not None:
        profile.time_policy = request.time_policy
    if request.allowed_algorithms is not None:
        profile.allowed_algorithms = request.allowed_algorithms
    if request.allowed_formats is not None:
        profile.allowed_formats = _normalize_optional_formats(request.allowed_formats)
    if request.allowed_issuers is not None:
        profile.allowed_issuers = request.allowed_issuers
    if request.denied_issuers is not None:
        profile.denied_issuers = request.denied_issuers
    if request.jurisdiction_filter is not None:
        profile.jurisdiction_filter = _normalize_jurisdiction_filter(
            request.jurisdiction_filter
        )
    if request.metadata is not None:
        profile.metadata = request.metadata

    profile.updated_at = datetime.now(timezone.utc)
    await repo.save_organization_trust_profile(profile)
    return _organization_trust_profile_to_response(profile)


# Trust Profile endpoints
@router.post("", response_model=TrustProfileResponse, response_model_exclude_none=True)
async def create_trust_profile(
    request: CreateTrustProfileRequest,
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> TrustProfileResponse:
    """Create a new Trust Profile."""
    org_client = await get_organization_client(fastapi_request)
    membership = await org_client.get_membership(user_id, request.organization_id)
    ensure_membership_permission(membership, "trust-profile", "create")

    allowed_issuers_was_provided = _field_was_provided(request, "allowed_issuers")

    profile = TrustProfile(
        organization_id=request.organization_id,
        name=request.name,
        description=request.description,
        profile_type=TrustProfileType(request.profile_type.upper()),
        compliance_status=ComplianceStatus(request.compliance_status.upper()),
        revocation_profile_id=request.revocation_profile_id,
        supported_formats=_normalize_supported_formats(request.supported_formats),
        allowed_issuers=request.allowed_issuers
        if allowed_issuers_was_provided
        else ([] if not request.trust_sources else None),
        denied_issuers=request.denied_issuers,
        system_issuer_overrides=request.system_issuer_overrides,
        compatible_compliance_codes=request.compatible_compliance_codes,
        verification_policy_set_id=request.verification_policy_set_id,
        auto_generated=request.auto_generated,
    )

    if not request.supported_formats:
        raise HTTPException(
            status_code=422, detail="supported_formats must contain at least one format"
        )

    # MIP §5.2 — allowed_algorithms must be non-empty and contain valid values
    _VALID_ALGORITHMS = {
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
        "EdDSA",
        "RS256",
        "RS384",
        "RS512",
        "BBS_BLS12381_SHA256",
        "BBS_BLS12381_SHAKE256",
    }
    algorithms = (
        request.allowed_algorithms
        or (
            request.validation_rules.allowed_algorithms
            if request.validation_rules
            else None
        )
        or ["ES256", "ES384", "EdDSA"]
    )
    if not algorithms:
        raise HTTPException(
            status_code=422,
            detail="allowed_algorithms must contain at least one algorithm",
        )
    invalid_algs = set(algorithms) - _VALID_ALGORITHMS
    if invalid_algs:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid algorithms: {', '.join(sorted(invalid_algs))}. Must be one of: {', '.join(sorted(_VALID_ALGORITHMS))}",
        )

    # Set trust sources
    profile.trust_sources = _build_trust_sources(request.trust_sources)

    # Set validation rules
    profile.validation_rules = _build_validation_rules(
        request.validation_rules,
        request.allowed_algorithms,
        request.min_key_size_rsa,
        request.min_key_size_ec,
        request.require_key_usage,
        request.max_chain_depth,
        request.allow_self_signed,
    )

    # Set revocation policy (DEPRECATED - prefer revocation_profile_id)
    if request.revocation_policy:
        profile.revocation_policy = RevocationPolicy(
            check_mode=RevocationCheckMode(request.revocation_policy.check_mode),
            check_ocsp=request.revocation_policy.check_ocsp,
            check_crl=request.revocation_policy.check_crl,
            check_status_list=request.revocation_policy.check_status_list,
            offline_grace_period_hours=request.revocation_policy.offline_grace_period_hours,
            cache_duration_hours=request.revocation_policy.cache_duration_hours,
        )

    # Set time policy
    if request.time_policy:
        profile.time_policy = TimePolicy(
            max_clock_skew_seconds=request.time_policy.max_clock_skew_seconds,
            credential_freshness_hours=request.time_policy.credential_freshness_hours,
            require_not_before=request.time_policy.require_not_before,
            require_expiration=request.time_policy.require_expiration,
        )

    await repo.save_profile(profile)
    logger.info(f"Created Trust Profile: {profile.id}")
    return _profile_to_response(profile)


@router.get(
    "", response_model=list[TrustProfileResponse], response_model_exclude_none=True
)
async def list_trust_profiles(
    organization_id: str = Query(..., description="Organization ID"),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
    request: Request = None,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[TrustProfileResponse]:
    """List Trust Profiles for an organization."""
    membership = await app.state.org_client.get_membership(user_id, organization_id)
    ensure_membership_permission(membership, "trust-profile", "view")
    profiles = await repo.list_profiles(organization_id)
    return [_profile_to_response(p) for p in profiles[offset : offset + limit]]


@router.get(
    "/{profile_id}",
    response_model=TrustProfileResponse,
    response_model_exclude_none=True,
)
async def get_trust_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> TrustProfileResponse:
    """Get a Trust Profile by ID."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    membership = await app.state.org_client.get_membership(
        user_id, profile.organization_id
    )
    ensure_membership_permission(membership, "trust-profile", "view")
    return _profile_to_response(profile)


@internal_router.get(
    "/{profile_id}",
    response_model=InternalTrustProfileResponse,
    response_model_exclude_none=True,
    include_in_schema=False,
)
async def internal_get_trust_profile(
    profile_id: str,
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> InternalTrustProfileResponse:
    """Read a Trust Profile for internal verifier/policy evaluation."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    return await _internal_profile_to_response(repo, profile)


def _registry_source_is_due(source: TrustSource, now: datetime) -> bool:
    sync_config = _validated_registry_sync_config(source)
    if source.registry_last_synced_at is None:
        return True
    refresh_seconds = sync_config.refresh_interval_hours * 60 * 60
    return now >= source.registry_last_synced_at + timedelta(
        seconds=refresh_seconds * 0.8
    )


async def _synchronize_profile_registry_sources(
    profile: TrustProfile,
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository,
    client: httpx.AsyncClient,
    *,
    synchronized_at: datetime,
    due_only: bool,
) -> list[TrustProfileRegistrySourceSyncResponse]:
    """Refresh selected sources and persist them with optimistic concurrency."""
    profile_version = profile.updated_at
    candidate = deepcopy(profile)
    configured = [
        source
        for source in candidate.trust_sources
        if source.enabled and source.registry_sync is not None
    ]
    selected = [
        source
        for source in configured
        if not due_only or _registry_source_is_due(source, synchronized_at)
    ]
    if not selected:
        return []

    source_results: list[TrustProfileRegistrySourceSyncResponse] = []
    for source in selected:
        if source.url is None:
            raise RegistrySyncError("registry source has no URL")
        sync_config = _validated_registry_sync_config(source)
        source.refresh_interval_hours = sync_config.refresh_interval_hours
        state = state_from_storage(
            sync_token=source.registry_sync_token,
            sequence=source.registry_sequence,
            entries=source.registry_entries,
            synchronized_at=source.registry_last_synced_at,
        )
        imported = await synchronize_registry(
            source.url,
            state,
            client=client,
            now=synchronized_at,
        )
        source.registry_sync_token = imported.state.sync_token
        source.registry_sequence = imported.state.sequence
        source.registry_entries = {
            entry_id: entry.to_storage()
            for entry_id, entry in imported.state.entries.items()
        }
        source.registry_last_synced_at = imported.state.synchronized_at
        csca_entries = sum(
            entry.anchor_type == "CSCA" for entry in imported.state.entries.values()
        )
        dsc_entries = sum(
            entry.anchor_type == "DSC" for entry in imported.state.entries.values()
        )
        source_results.append(
            TrustProfileRegistrySourceSyncResponse(
                url=source.url,
                protocol=sync_config.protocol,
                sequence=imported.state.sequence,
                csca_entries=csca_entries,
                dsc_entries=dsc_entries,
                synchronized_at=synchronized_at.isoformat(),
            )
        )

    candidate.updated_at = synchronized_at
    saved = await repo.save_profile(
        candidate,
        expected_updated_at=profile_version,
    )
    if not saved:
        raise HTTPException(
            status_code=409,
            detail="Trust Profile changed during registry synchronization; retry the operation",
        )
    return source_results


def _registry_sync_poll_seconds() -> int:
    raw = os.environ.get("TRUST_REGISTRY_SYNC_POLL_SECONDS", "300")
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Invalid TRUST_REGISTRY_SYNC_POLL_SECONDS; using 300")
        return 300
    return min(max(value, 60), 86_400)


async def _synchronize_due_registry_sources(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository,
) -> None:
    profiles = await repo.list_all_profiles()
    if not any(
        source.enabled and source.registry_sync is not None
        for profile in profiles
        for source in profile.trust_sources
    ):
        return

    synchronized_at = datetime.now(timezone.utc)
    timeout = httpx.Timeout(15.0, connect=5.0)
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=timeout,
        trust_env=False,
        verify=registry_tls_context(),
    ) as client:
        for profile in profiles:
            try:
                results = await _synchronize_profile_registry_sources(
                    profile,
                    repo,
                    client,
                    synchronized_at=synchronized_at,
                    due_only=True,
                )
                if results:
                    logger.info(
                        "Synchronized %d registry source(s) for Trust Profile %s",
                        len(results),
                        profile.id,
                    )
            except (RegistrySyncError, HTTPException) as exc:
                logger.warning(
                    "Scheduled registry synchronization failed for Trust Profile %s: %s",
                    profile.id,
                    exc,
                )


async def _registry_sync_loop(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository,
) -> None:
    while True:
        try:
            await _synchronize_due_registry_sources(repo)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Scheduled trust registry synchronization failed")
        await asyncio.sleep(_registry_sync_poll_seconds())


@router.post(
    "/{profile_id}/registry-sync",
    response_model=TrustProfileRegistrySyncResponse,
    response_model_exclude_none=True,
)
async def synchronize_trust_profile_registries(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> TrustProfileRegistrySyncResponse:
    """Atomically refresh all configured external registry feeds."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    membership = await app.state.org_client.get_membership(
        user_id, profile.organization_id
    )
    ensure_membership_permission(membership, "trust-profile", "edit")

    configured = [
        source
        for source in profile.trust_sources
        if source.enabled and source.registry_sync is not None
    ]
    if not configured:
        raise HTTPException(
            status_code=409,
            detail="Trust Profile has no external registry sync source",
        )

    synchronized_at = datetime.now(timezone.utc)
    timeout = httpx.Timeout(15.0, connect=5.0)
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            trust_env=False,
            verify=registry_tls_context(),
        ) as client:
            source_results = await _synchronize_profile_registry_sources(
                profile,
                repo,
                client,
                synchronized_at=synchronized_at,
                due_only=False,
            )
    except RegistrySyncError as exc:
        logger.warning("Trust registry synchronization rejected: %s", exc)
        raise HTTPException(
            status_code=502,
            detail="External trust registry synchronization failed",
        ) from exc

    return TrustProfileRegistrySyncResponse(
        trust_profile_id=profile.id,
        sources=source_results,
        synchronized_at=synchronized_at.isoformat(),
    )


@resource_owner_router.get(
    "/trust-profiles/{profile_id}",
    response_model=dict[str, str],
    dependencies=[Depends(_verify_internal_api_key)],
    include_in_schema=False,
)
async def get_trust_profile_owner(
    profile_id: str,
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> dict[str, str]:
    """Return only the tenant owner needed for gateway authorization."""

    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Resource not found")
    return {"organization_id": profile.organization_id}


@router.patch(
    "/{profile_id}",
    response_model=TrustProfileResponse,
    response_model_exclude_none=True,
)
async def update_trust_profile(
    profile_id: str,
    request: UpdateTrustProfileRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> TrustProfileResponse:
    """Update a Trust Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify admin access
    membership = await app.state.org_client.get_membership(
        user_id, profile.organization_id
    )
    ensure_membership_permission(membership, "trust-profile", "edit")

    allowed_issuers_was_provided = _field_was_provided(request, "allowed_issuers")

    if request.name is not None:
        profile.name = request.name
    if request.description is not None:
        profile.description = request.description
    if request.profile_type is not None:
        profile.profile_type = TrustProfileType(request.profile_type.upper())
    if request.compliance_status is not None:
        profile.compliance_status = ComplianceStatus(request.compliance_status.upper())
    if request.trust_sources is not None:
        profile.trust_sources = _build_trust_sources(request.trust_sources)
        if (
            not request.trust_sources
            and not allowed_issuers_was_provided
            and profile.allowed_issuers is None
        ):
            profile.allowed_issuers = []
    if (
        request.validation_rules is not None
        or request.allowed_algorithms is not None
        or request.min_key_size_rsa is not None
        or request.min_key_size_ec is not None
        or request.require_key_usage is not None
        or request.max_chain_depth is not None
        or request.allow_self_signed is not None
    ):
        profile.validation_rules = _build_validation_rules(
            request.validation_rules,
            request.allowed_algorithms,
            request.min_key_size_rsa,
            request.min_key_size_ec,
            request.require_key_usage,
            request.max_chain_depth,
            request.allow_self_signed,
            current=profile.validation_rules,
        )
    if request.revocation_profile_id is not None:
        profile.revocation_profile_id = request.revocation_profile_id
    if request.supported_formats is not None:
        if not request.supported_formats:
            raise HTTPException(
                status_code=422,
                detail="supported_formats must contain at least one format",
            )
        profile.supported_formats = _normalize_supported_formats(
            request.supported_formats
        )
    if allowed_issuers_was_provided:
        profile.allowed_issuers = request.allowed_issuers
    if request.denied_issuers is not None:
        profile.denied_issuers = request.denied_issuers
    if request.system_issuer_overrides is not None:
        profile.system_issuer_overrides = request.system_issuer_overrides
    if request.compatible_compliance_codes is not None:
        profile.compatible_compliance_codes = request.compatible_compliance_codes
    if request.verification_policy_set_id is not None:
        profile.verification_policy_set_id = request.verification_policy_set_id
    if request.auto_generated is not None:
        profile.auto_generated = request.auto_generated

    profile.updated_at = datetime.now(timezone.utc)
    await repo.save_profile(profile)
    return _profile_to_response(profile)


@router.post(
    "/{profile_id}/activate",
    response_model=TrustProfileResponse,
    response_model_exclude_none=True,
)
async def activate_trust_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> TrustProfileResponse:
    """Activate a Trust Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify admin access
    membership = await app.state.org_client.get_membership(
        user_id, profile.organization_id
    )
    ensure_membership_permission(membership, "trust-profile", "activate")
    try:
        _imported_registry_trust_sources(profile)
    except HTTPException as exc:
        raise HTTPException(status_code=409, detail=exc.detail) from exc
    profile.activate()
    await repo.save_profile(profile)
    return _profile_to_response(profile)


@router.post(
    "/{profile_id}/suspend",
    response_model=TrustProfileResponse,
    response_model_exclude_none=True,
)
async def suspend_trust_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> TrustProfileResponse:
    """Suspend a Trust Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify admin access
    membership = await app.state.org_client.get_membership(
        user_id, profile.organization_id
    )
    ensure_membership_permission(membership, "trust-profile", "suspend")
    profile.suspend()
    await repo.save_profile(profile)
    return _profile_to_response(profile)


@router.delete("/{profile_id}", response_model=DeleteResponse)
async def delete_trust_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> DeleteResponse:
    """Delete a Trust Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify admin access
    membership = await app.state.org_client.get_membership(
        user_id, profile.organization_id
    )
    ensure_membership_permission(membership, "trust-profile", "delete")

    # Cascade check: reject if profile still has trusted issuers
    issuers = await repo.list_profile_issuers(profile_id)
    if issuers:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete trust profile with {len(issuers)} trusted issuer(s). Remove all issuers first.",
        )

    await repo.delete_profile(profile_id)
    return DeleteResponse()


# Trusted Issuer endpoints (sub-resource)
@router.post(
    "/{profile_id}/issuers",
    response_model=TrustProfileIssuerResponse,
    response_model_exclude_none=True,
)
async def add_trusted_issuer(
    profile_id: str,
    request: CreateTrustProfileIssuerRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> TrustProfileIssuerResponse:
    """Link an existing IssuerEntity to a Trust Profile."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify admin access
    membership = await app.state.org_client.get_membership(
        user_id, profile.organization_id
    )
    ensure_membership_permission(membership, "trusted-issuer", "create")

    issuer_entity = await _get_issuer_entity_or_404(repo, request.issuer_id)
    if (
        issuer_entity.organization_id != profile.organization_id
        and issuer_entity.organization_id is not None
        and not issuer_entity.is_system_issuer
    ):
        raise HTTPException(status_code=404, detail="Issuer Entity not found")

    existing_link = await repo.get_profile_issuer_by_pair(profile_id, issuer_entity.id)
    if existing_link:
        raise HTTPException(
            status_code=409, detail="Issuer already linked to this trust profile"
        )

    profile_issuer = TrustProfileIssuer(
        trust_profile_id=profile_id,
        issuer_id=issuer_entity.id,
        trust_level=request.trust_level,
        relationship_status=TrustRelationshipStatus(request.relationship_status),
        cascade_revocation_policy=CascadeRevocationPolicy(
            request.cascade_revocation_policy
        ),
        metadata=request.metadata,
    )
    await repo.save_profile_issuer(profile_issuer)
    logger.info(
        "Added Trusted Issuer link: %s to profile %s", profile_issuer.id, profile_id
    )
    return await _materialize_trust_profile_issuer(repo, profile_issuer)


@router.get(
    "/{profile_id}/issuers",
    response_model=list[TrustProfileIssuerResponse],
    response_model_exclude_none=True,
)
async def list_trusted_issuers(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[TrustProfileIssuerResponse]:
    """List Trusted Issuers for a Trust Profile."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    membership = await app.state.org_client.get_membership(
        user_id, profile.organization_id
    )
    ensure_membership_permission(membership, "trusted-issuer", "view")
    profile_issuers = await repo.list_profile_issuers(profile_id)
    return [
        await _materialize_trust_profile_issuer(repo, profile_issuer)
        for profile_issuer in profile_issuers[offset : offset + limit]
    ]


@router.get(
    "/{profile_id}/issuers/{issuer_id}",
    response_model=TrustProfileIssuerResponse,
    response_model_exclude_none=True,
)
async def get_trusted_issuer(
    profile_id: str,
    issuer_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> TrustProfileIssuerResponse:
    """Get a Trusted Issuer by ID."""
    profile_issuer = await repo.get_profile_issuer(issuer_id)
    if not profile_issuer or profile_issuer.trust_profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Trusted Issuer not found")
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    membership = await app.state.org_client.get_membership(
        user_id, profile.organization_id
    )
    ensure_membership_permission(membership, "trusted-issuer", "view")
    return await _materialize_trust_profile_issuer(repo, profile_issuer)


@router.patch(
    "/{profile_id}/issuers/{issuer_id}",
    response_model=TrustProfileIssuerResponse,
    response_model_exclude_none=True,
)
async def update_trusted_issuer(
    profile_id: str,
    issuer_id: str,
    request: UpdateTrustProfileIssuerRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> TrustProfileIssuerResponse:
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    membership = await app.state.org_client.get_membership(
        user_id, profile.organization_id
    )
    ensure_membership_permission(membership, "trusted-issuer", "edit")

    profile_issuer = await repo.get_profile_issuer(issuer_id)
    if not profile_issuer or profile_issuer.trust_profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Trusted Issuer not found")
    if request.trust_level is not None:
        profile_issuer.trust_level = request.trust_level
    if request.relationship_status is not None:
        profile_issuer.relationship_status = TrustRelationshipStatus(
            request.relationship_status.upper()
        )
    if request.cascade_revocation_policy is not None:
        profile_issuer.cascade_revocation_policy = CascadeRevocationPolicy(
            request.cascade_revocation_policy.upper()
        )
    if _field_was_provided(request, "metadata"):
        profile_issuer.metadata = request.metadata or {}
    profile_issuer.updated_at = datetime.now(timezone.utc)
    await repo.save_profile_issuer(profile_issuer)
    return await _materialize_trust_profile_issuer(repo, profile_issuer)


@router.delete("/{profile_id}/issuers/{issuer_id}")
async def remove_trusted_issuer(
    profile_id: str,
    issuer_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> dict:
    """Remove a Trusted Issuer from a Trust Profile (requires admin)."""
    profile_issuer = await repo.get_profile_issuer(issuer_id)
    if not profile_issuer or profile_issuer.trust_profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Trusted Issuer not found")
    # Verify admin access
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    membership = await app.state.org_client.get_membership(
        user_id, profile.organization_id
    )
    ensure_membership_permission(membership, "trusted-issuer", "delete")
    await repo.delete_profile_issuer(issuer_id)
    return {"success": True}


@framework_router.get(
    "", response_model=list[TrustFrameworkResponse], response_model_exclude_none=True
)
async def list_trust_frameworks(
    _user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> list[TrustFrameworkResponse]:
    frameworks = await repo.list_frameworks()
    return [_framework_to_response(framework) for framework in frameworks]


@framework_router.get(
    "/{framework_id}",
    response_model=TrustFrameworkResponse,
    response_model_exclude_none=True,
)
async def get_trust_framework(
    framework_id: str,
    _user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> TrustFrameworkResponse:
    framework = await repo.get_framework(framework_id)
    if not framework:
        raise HTTPException(status_code=404, detail="Trust Framework not found")
    return _framework_to_response(framework)


def _parse_sync_token(since: str | None) -> int | None:
    if since is None:
        return None
    try:
        value = int(since)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid sync token") from exc
    if value < 0:
        raise HTTPException(status_code=400, detail="Invalid sync token")
    return value


@registry_router.get(
    "/sync", response_model=TrustRegistrySyncResponse, response_model_exclude_none=True
)
async def sync_trust_registry(
    since: str | None = Query(
        None, description="Opaque sync token from the previous response"
    ),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> TrustRegistrySyncResponse:
    since_sequence = _parse_sync_token(since)
    current_sequence = await repo.get_registry_sequence()
    entries = await repo.list_registry_entries(
        current_only=since_sequence is None,
        since_sequence=since_sequence,
    )
    return TrustRegistrySyncResponse(
        sync_token=str(current_sequence),
        sequence=current_sequence,
        entries=[_registry_entry_to_response(entry) for entry in entries],
        has_more=False,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


@registry_router.get(
    "/csca",
    response_model=list[TrustRegistryEntryResponse],
    response_model_exclude_none=True,
)
async def list_csca_entries(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> list[TrustRegistryEntryResponse]:
    entries = await repo.list_registry_entries(
        anchor_type=TrustAnchorType.CSCA.value, current_only=True
    )
    return [_registry_entry_to_response(entry) for entry in entries]


@registry_router.get(
    "/dsc",
    response_model=list[TrustRegistryEntryResponse],
    response_model_exclude_none=True,
)
async def list_dsc_entries(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> list[TrustRegistryEntryResponse]:
    entries = await repo.list_registry_entries(
        anchor_type=TrustAnchorType.DSC.value, current_only=True
    )
    return [_registry_entry_to_response(entry) for entry in entries]


@registry_router.get(
    "/csca/{country_code}",
    response_model=list[TrustRegistryEntryResponse],
    response_model_exclude_none=True,
)
async def list_country_csca_entries(
    country_code: str,
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> list[TrustRegistryEntryResponse]:
    entries = await repo.list_registry_entries(
        anchor_type=TrustAnchorType.CSCA.value,
        country_code=country_code,
        current_only=True,
    )
    return [_registry_entry_to_response(entry) for entry in entries]


@registry_router.get(
    "/status",
    response_model=TrustRegistryStatusResponse,
    response_model_exclude_none=True,
)
async def get_trust_registry_status(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> TrustRegistryStatusResponse:
    status = await repo.get_registry_status()
    return TrustRegistryStatusResponse(
        status="healthy",
        current_sequence=int(status["current_sequence"] or 0),
        total_entries=int(status["total_entries"] or 0),
        current_entries=int(status["current_entries"] or 0),
        csca_entries=int(status["csca_entries"] or 0),
        dsc_entries=int(status["dsc_entries"] or 0),
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


@issuer_router.post(
    "", response_model=IssuerEntityResponse, response_model_exclude_none=True
)
async def create_issuer_entity(
    request: CreateIssuerEntityRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> IssuerEntityResponse:
    membership = await app.state.org_client.get_membership(
        user_id, request.organization_id
    )
    ensure_membership_permission(membership, "trusted-issuer", "create")
    await _ensure_unique_issuer_identifier(
        repo, request.organization_id, request.issuer_id
    )
    issuer_entity = _build_issuer_entity_from_request(request)
    await repo.save_issuer_entity(issuer_entity)
    return _issuer_entity_to_response(issuer_entity)


@issuer_router.get(
    "", response_model=list[IssuerEntityResponse], response_model_exclude_none=True
)
async def list_issuer_entities(
    organization_id: str | None = Query(
        None, description="Organization scope; includes system issuers when set"
    ),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> list[IssuerEntityResponse]:
    if organization_id is not None:
        membership = await app.state.org_client.get_membership(user_id, organization_id)
        ensure_membership_permission(membership, "trusted-issuer", "view")
        issuer_entities = await repo.list_issuer_entities(organization_id)
    else:
        issuer_entities = [
            issuer_entity
            for issuer_entity in await repo.list_issuer_entities(None)
            if issuer_entity.is_system_issuer or issuer_entity.organization_id is None
        ]
    return [
        _issuer_entity_to_response(issuer_entity) for issuer_entity in issuer_entities
    ]


@issuer_router.get(
    "/{issuer_entity_id}",
    response_model=IssuerEntityResponse,
    response_model_exclude_none=True,
)
async def get_issuer_entity(
    issuer_entity_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> IssuerEntityResponse:
    issuer_entity = await _get_issuer_entity_or_404(repo, issuer_entity_id)
    if issuer_entity.organization_id is not None:
        membership = await app.state.org_client.get_membership(
            user_id, issuer_entity.organization_id
        )
        ensure_membership_permission(membership, "trusted-issuer", "view")
    return _issuer_entity_to_response(issuer_entity)


@issuer_router.patch(
    "/{issuer_entity_id}",
    response_model=IssuerEntityResponse,
    response_model_exclude_none=True,
)
async def update_issuer_entity(
    issuer_entity_id: str,
    request: UpdateIssuerEntityRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> IssuerEntityResponse:
    issuer_entity = await _get_issuer_entity_or_404(repo, issuer_entity_id)
    if issuer_entity.organization_id is None or issuer_entity.is_system_issuer:
        raise HTTPException(
            status_code=403,
            detail="Global and system issuers cannot be mutated through the public API",
        )
    if request.organization_id != issuer_entity.organization_id:
        raise HTTPException(status_code=404, detail="Issuer Entity not found")
    membership = await app.state.org_client.get_membership(
        user_id, issuer_entity.organization_id
    )
    ensure_membership_permission(membership, "trusted-issuer", "edit")
    if (
        issuer_entity.compliance_status == IssuerEntityComplianceStatus.REVOKED
        and request.compliance_status
        not in {None, IssuerEntityComplianceStatus.REVOKED.value}
    ):
        raise HTTPException(
            status_code=400,
            detail="Revoked issuer cannot be reinstated; create a new IssuerEntity instead",
        )
    if request.display_name is not None:
        issuer_entity.display_name = request.display_name
    if _field_was_provided(request, "description"):
        issuer_entity.description = request.description
    if request.issuer_type is not None:
        issuer_entity.issuer_type = IssuerEntityType(request.issuer_type.upper())
    if _field_was_provided(request, "accreditation_body"):
        issuer_entity.accreditation_body = request.accreditation_body
    if _field_was_provided(request, "accreditations"):
        issuer_entity.accreditations = list(request.accreditations or [])
    if _field_was_provided(request, "accreditation_date"):
        issuer_entity.accreditation_date = _parse_optional_datetime(
            request.accreditation_date
        )
    if request.valid_from is not None:
        issuer_entity.valid_from = (
            _parse_optional_datetime(request.valid_from) or issuer_entity.valid_from
        )
    if _field_was_provided(request, "valid_until"):
        issuer_entity.valid_until = _parse_optional_datetime(request.valid_until)
    if _field_was_provided(request, "trust_anchor_id"):
        issuer_entity.trust_anchor_id = request.trust_anchor_id
    if _field_was_provided(request, "metadata"):
        issuer_entity.metadata = request.metadata or {}
    if request.compliance_status is not None:
        next_status = IssuerEntityComplianceStatus(request.compliance_status.upper())
        issuer_entity.compliance_status = next_status
        if next_status == IssuerEntityComplianceStatus.REVOKED:
            issuer_entity.revoked_at = datetime.now(timezone.utc)
            issuer_entity.revocation_reason = request.revocation_reason
            issuer_entity.revoked_by = user_id
    issuer_entity.updated_at = datetime.now(timezone.utc)
    await repo.save_issuer_entity(issuer_entity)
    return _issuer_entity_to_response(issuer_entity)


@issuer_router.delete("/{issuer_entity_id}")
async def delete_issuer_entity(
    issuer_entity_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(
        get_repo
    ),
) -> dict[str, bool]:
    issuer_entity = await _get_issuer_entity_or_404(repo, issuer_entity_id)
    if issuer_entity.organization_id is None or issuer_entity.is_system_issuer:
        raise HTTPException(
            status_code=403,
            detail="Global and system issuers cannot be deleted through the public API",
        )
    membership = await app.state.org_client.get_membership(
        user_id, issuer_entity.organization_id
    )
    ensure_membership_permission(membership, "trusted-issuer", "delete")
    await repo.delete_issuer_entity(issuer_entity_id)
    return {"success": True}


# Response builders
def _profile_to_response(profile: TrustProfile) -> TrustProfileResponse:
    enabled_methods: list[str] = []
    if profile.revocation_policy.check_crl:
        enabled_methods.append("CRL")
    if profile.revocation_policy.check_ocsp:
        enabled_methods.append("OCSP")
    if profile.revocation_policy.check_status_list:
        enabled_methods.append("STATUS_LIST")

    max_credential_age_seconds = (
        profile.time_policy.credential_freshness_hours * 3600
        if profile.time_policy.credential_freshness_hours is not None
        else None
    )
    require_freshness = max_credential_age_seconds is not None

    return TrustProfileResponse(
        id=profile.id,
        organization_id=profile.organization_id,
        name=profile.name,
        description=profile.description,
        status=profile.status.value,
        profile_type=profile.profile_type.value,
        compliance_status=profile.compliance_status.value,
        trust_sources=[
            {
                "source_type": ts.source_type,
                "url": ts.url,
                "certificate_pem": ts.certificate_pem,
                "issuer_did": ts.issuer_did,
                "description": ts.description,
                "pinned_certificates": list(ts.pinned_certificates),
                **(
                    {"registry_sync": deepcopy(ts.registry_sync)}
                    if ts.registry_sync is not None
                    else {}
                ),
            }
            for ts in profile.trust_sources
        ],
        allowed_algorithms=profile.validation_rules.allowed_algorithms,
        revocation_policy={
            "check_mode": profile.revocation_policy.check_mode.value,
            "cache_ttl_seconds": profile.revocation_policy.cache_duration_hours * 3600,
        },
        revocation_services={
            "enabled_methods": enabled_methods,
            "auto_discover": False,
            "merge_discovered": False,
        },
        revocation_profile_id=profile.revocation_profile_id,
        time_policy={
            "clock_skew_seconds": profile.time_policy.max_clock_skew_seconds,
            "max_credential_age_seconds": max_credential_age_seconds,
            "require_freshness": require_freshness,
            "freshness_window_seconds": max_credential_age_seconds,
        },
        supported_formats=[f.value for f in profile.supported_formats],
        allowed_issuers=profile.allowed_issuers,
        denied_issuers=profile.denied_issuers,
        system_issuer_overrides=profile.system_issuer_overrides,
        compatible_compliance_codes=profile.compatible_compliance_codes,
        verification_policy_set_id=profile.verification_policy_set_id,
        auto_generated=profile.auto_generated,
        created_at=profile.created_at.isoformat(),
        updated_at=profile.updated_at.isoformat(),
    )


def _issuer_entity_to_response(issuer_entity: IssuerEntity) -> IssuerEntityResponse:
    return IssuerEntityResponse(
        id=issuer_entity.id,
        organization_id=issuer_entity.organization_id,
        issuer_id=issuer_entity.issuer_id,
        issuer_type=issuer_entity.issuer_type.value,
        display_name=issuer_entity.display_name,
        description=issuer_entity.description,
        is_system_issuer=issuer_entity.is_system_issuer,
        compliance_status=issuer_entity.compliance_status.value,
        accreditation_body=issuer_entity.accreditation_body,
        accreditations=list(issuer_entity.accreditations),
        accreditation_date=issuer_entity.accreditation_date.isoformat()
        if issuer_entity.accreditation_date
        else None,
        valid_from=issuer_entity.valid_from.isoformat(),
        valid_until=issuer_entity.valid_until.isoformat()
        if issuer_entity.valid_until
        else None,
        trust_anchor_id=issuer_entity.trust_anchor_id,
        revoked_at=issuer_entity.revoked_at.isoformat()
        if issuer_entity.revoked_at
        else None,
        revocation_reason=issuer_entity.revocation_reason,
        revoked_by=issuer_entity.revoked_by,
        metadata=issuer_entity.metadata,
        created_at=issuer_entity.created_at.isoformat(),
        updated_at=issuer_entity.updated_at.isoformat(),
    )


def _framework_to_response(framework: TrustFramework) -> TrustFrameworkResponse:
    return TrustFrameworkResponse(
        id=framework.id,
        code=framework.code,
        display_name=framework.display_name,
        description=framework.description,
        pkd_endpoints=framework.pkd_endpoints,
        default_algorithms=framework.default_algorithms,
        default_formats=framework.default_formats,
        validation_ruleset=framework.validation_ruleset,
        sync_config=framework.sync_config,
        is_system=framework.is_system,
        created_at=framework.created_at.isoformat(),
        updated_at=framework.updated_at.isoformat(),
    )


def _organization_trust_profile_to_response(
    profile: OrganizationTrustProfile,
) -> OrganizationTrustProfileResponse:
    return OrganizationTrustProfileResponse(
        id=profile.id,
        organization_id=profile.organization_id,
        framework_id=profile.framework_id,
        name=profile.name,
        display_name=profile.display_name,
        description=profile.description,
        enabled=profile.enabled,
        use_case_tags=profile.use_case_tags,
        compliance_status=profile.compliance_status.value,
        auto_generated=profile.auto_generated,
        revocation_policy=profile.revocation_policy,
        time_policy=profile.time_policy,
        allowed_algorithms=profile.allowed_algorithms,
        allowed_formats=[fmt.value for fmt in profile.allowed_formats]
        if profile.allowed_formats is not None
        else None,
        allowed_issuers=profile.allowed_issuers,
        denied_issuers=profile.denied_issuers,
        jurisdiction_filter=profile.jurisdiction_filter,
        metadata=_sanitize_private_custody_metadata(profile.metadata),
        created_at=profile.created_at.isoformat(),
        updated_at=profile.updated_at.isoformat(),
    )


def _registry_entry_to_response(
    entry: TrustRegistryEntry,
) -> TrustRegistryEntryResponse:
    return TrustRegistryEntryResponse(
        entry_id=entry.id,
        anchor_type=entry.anchor_type.value,
        operation=entry.operation.value,
        country_code=entry.country_code,
        certificate_pem=entry.certificate_pem,
        subject_key_id=entry.subject_key_id,
        not_before=entry.not_before.isoformat() if entry.not_before else None,
        not_after=entry.not_after.isoformat() if entry.not_after else None,
        source=entry.source.value,
    )


# =============================================================================
# Application Setup
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo
    logger.info(f"Starting {SERVICE_NAME}...")

    # Initialize database
    from marty_common.database import DatabaseManager, DatabaseConfig

    db = DatabaseManager(DatabaseConfig.from_env("trust-profile"))
    async with db.engine.begin() as conn:
        await conn.execute(text("CREATE SCHEMA IF NOT EXISTS trust_profile_service"))
        await conn.run_sync(mapper_registry.metadata.create_all)
    session_factory = db.session_factory

    # Initialize repository
    _repo = PostgresTrustProfileRepository(session_factory)
    await _seed_system_frameworks(_repo)
    await _bootstrap_marty_login_trust_profile(_repo)

    # Initialize gRPC channel to organization service
    from common.di import setup_org_client, teardown_org_client

    await setup_org_client(app, "trust-profile")
    registry_sync_task = asyncio.create_task(
        _registry_sync_loop(_repo), name="trust-registry-sync"
    )

    yield
    logger.info(f"Shutting down {SERVICE_NAME}...")
    registry_sync_task.cancel()
    with suppress(asyncio.CancelledError):
        await registry_sync_task
    await teardown_org_client(app)
    await db.close()


def create_app() -> FastAPI:
    return create_service_app(
        title="Trust Profile Service",
        description="Manages Trust Profiles - who is trusted and how validation happens",
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[
            router,
            internal_router,
            resource_owner_router,
            organization_trust_profile_router,
            framework_router,
            registry_router,
            issuer_router,
        ],
    )


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
