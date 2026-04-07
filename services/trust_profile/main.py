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

import logging
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from marty_common.dto import DeleteResponse
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from typing import Annotated

from marty_common import (
    OrganizationContext,
    require_org_membership,
)
from marty_common.org_authorization import get_organization_client
from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware
from marty_common.service_setup import create_service_app
from trust_profile.infrastructure.adapters import PostgresTrustProfileRepository
from trust_profile.infrastructure.models import mapper_registry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "trust-profile-service"
SERVICE_PORT = int(os.environ.get("TRUST_PROFILE_SERVICE_PORT", "8004"))


def get_config() -> dict:
    """Get service configuration from environment."""
    return {
        "database_url": os.environ.get(
            "DATABASE_URL",
        ),
    }


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


class IssuerStatus(str, Enum):
    """Trusted issuer status."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


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


@dataclass
class ValidationRules:
    """
    Rules for cryptographic validation.
    """
    allowed_algorithms: list[str] = field(default_factory=lambda: ["ES256", "ES384", "EdDSA"])
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
    credential_freshness_hours: int | None = None  # If set, credentials must be issued within this window
    require_not_before: bool = True
    require_expiration: bool = True


@dataclass
class TrustedIssuer:
    """
    A trusted issuer within a Trust Profile.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    trust_profile_id: str = ""
    name: str = ""
    description: str | None = None
    
    # Issuer identity
    issuer_did: str = ""
    issuer_url: str | None = None
    
    # Trust settings
    status: IssuerStatus = IssuerStatus.ACTIVE
    credential_template_ids: list[str] = field(default_factory=list)  # Which templates this issuer can issue
    
    # Verification keys (JWK format)
    verification_keys: list[dict[str, Any]] = field(default_factory=list)
    
    # Constraints
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


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
    compliance_status: IssuerEntityComplianceStatus = IssuerEntityComplianceStatus.COMPLIANT
    accreditation_body: str | None = None
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
    cascade_revocation_policy: CascadeRevocationPolicy = CascadeRevocationPolicy.NOTIFY_ONLY
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
    default_algorithms: list[str] = field(default_factory=lambda: ["ES256", "ES384", "EdDSA"])
    default_formats: list[str] = field(default_factory=lambda: [CredentialFormat.MDOC.value])
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
    revocation_policy: RevocationPolicy = field(default_factory=RevocationPolicy)  # DEPRECATED: use revocation_profile_id
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
        self._issuers: dict[str, TrustedIssuer] = {}

    # Trust Framework operations
    async def save_framework(self, framework: TrustFramework) -> None:
        self._frameworks[framework.id] = framework

    async def get_framework(self, framework_id: str) -> TrustFramework | None:
        return self._frameworks.get(framework_id)

    async def get_framework_by_code(self, code: str) -> TrustFramework | None:
        return next((framework for framework in self._frameworks.values() if framework.code == code), None)

    async def list_frameworks(self) -> list[TrustFramework]:
        return sorted(
            self._frameworks.values(),
            key=lambda framework: (not framework.is_system, framework.code),
        )

    # Organization Trust Profile operations
    async def save_organization_trust_profile(self, profile: OrganizationTrustProfile) -> None:
        self._organization_trust_profiles[profile.id] = profile

    async def get_organization_trust_profile(self, profile_id: str) -> OrganizationTrustProfile | None:
        return self._organization_trust_profiles.get(profile_id)

    async def list_organization_trust_profiles(self, organization_id: str) -> list[OrganizationTrustProfile]:
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
            entries = [entry for entry in entries if entry.anchor_type.value == anchor_type]
        if country_code is not None:
            normalized = country_code.upper()
            entries = [entry for entry in entries if entry.country_code == normalized]
        if current_only:
            entries = [entry for entry in entries if entry.is_current]
        if since_sequence is not None:
            entries = [entry for entry in entries if entry.sequence > since_sequence]
        return sorted(entries, key=lambda entry: (entry.sequence, entry.country_code, entry.id))

    async def get_registry_sequence(self) -> int:
        return max((entry.sequence for entry in self._registry_entries.values()), default=0)

    async def get_registry_status(self) -> dict[str, int | None]:
        entries = list(self._registry_entries.values())
        current_entries = [entry for entry in entries if entry.is_current]
        return {
            "total_entries": len(entries),
            "current_entries": len(current_entries),
            "csca_entries": len([entry for entry in current_entries if entry.anchor_type == TrustAnchorType.CSCA]),
            "dsc_entries": len([entry for entry in current_entries if entry.anchor_type == TrustAnchorType.DSC]),
            "current_sequence": await self.get_registry_sequence(),
        }
    
    # Trust Profile operations
    async def save_profile(self, profile: TrustProfile) -> None:
        self._profiles[profile.id] = profile
    
    async def get_profile(self, profile_id: str) -> TrustProfile | None:
        return self._profiles.get(profile_id)
    
    async def list_profiles(self, org_id: str) -> list[TrustProfile]:
        return [p for p in self._profiles.values() if p.organization_id == org_id]
    
    async def delete_profile(self, profile_id: str) -> None:
        self._profiles.pop(profile_id, None)
        link_ids = [link.id for link in self._profile_issuers.values() if link.trust_profile_id == profile_id]
        for link_id in link_ids:
            self._profile_issuers.pop(link_id, None)
        # Also delete associated issuers
        to_delete = [i.id for i in self._issuers.values() if i.trust_profile_id == profile_id]
        for issuer_id in to_delete:
            self._issuers.pop(issuer_id, None)

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
                if issuer_entity.organization_id == organization_id and issuer_entity.issuer_id == issuer_id
            ),
            None,
        )

    async def list_issuer_entities(self, organization_id: str | None = None) -> list[IssuerEntity]:
        entities = list(self._issuer_entities.values())
        if organization_id is not None:
            entities = [
                entity
                for entity in entities
                if entity.organization_id == organization_id or entity.is_system_issuer or entity.organization_id is None
            ]
        return sorted(entities, key=lambda entity: (entity.display_name.lower(), entity.id))

    async def delete_issuer_entity(self, issuer_entity_id: str) -> None:
        self._issuer_entities.pop(issuer_entity_id, None)
        link_ids = [link.id for link in self._profile_issuers.values() if link.issuer_id == issuer_entity_id]
        for link_id in link_ids:
            self._profile_issuers.pop(link_id, None)

    # Trust profile issuer operations
    async def save_profile_issuer(self, profile_issuer: TrustProfileIssuer) -> None:
        self._profile_issuers[profile_issuer.id] = profile_issuer

    async def get_profile_issuer(self, profile_issuer_id: str) -> TrustProfileIssuer | None:
        return self._profile_issuers.get(profile_issuer_id)

    async def get_profile_issuer_by_pair(self, trust_profile_id: str, issuer_id: str) -> TrustProfileIssuer | None:
        return next(
            (
                link
                for link in self._profile_issuers.values()
                if link.trust_profile_id == trust_profile_id and link.issuer_id == issuer_id
            ),
            None,
        )

    async def list_profile_issuers(self, trust_profile_id: str) -> list[TrustProfileIssuer]:
        return sorted(
            [link for link in self._profile_issuers.values() if link.trust_profile_id == trust_profile_id],
            key=lambda link: (link.created_at, link.id),
        )

    async def delete_profile_issuer(self, profile_issuer_id: str) -> None:
        self._profile_issuers.pop(profile_issuer_id, None)
    
    # Trusted Issuer operations
    async def save_issuer(self, issuer: TrustedIssuer) -> None:
        self._issuers[issuer.id] = issuer
    
    async def get_issuer(self, issuer_id: str) -> TrustedIssuer | None:
        return self._issuers.get(issuer_id)
    
    async def list_issuers(self, profile_id: str) -> list[TrustedIssuer]:
        return [i for i in self._issuers.values() if i.trust_profile_id == profile_id]
    
    async def delete_issuer(self, issuer_id: str) -> None:
        self._issuers.pop(issuer_id, None)


# =============================================================================
# HTTP Adapter - Request/Response Models
# =============================================================================

class TrustSourceModel(BaseModel):
    name: str = ""
    source_type: str = TrustSourceType.TRUST_LIST.value
    url: str | None = None
    certificate_pem: str | None = None
    issuer_did: str | None = None
    description: str | None = None
    pinned_certificates: list[str] = Field(default_factory=list)
    refresh_interval_hours: int = 24
    enabled: bool = True


class ValidationRulesModel(BaseModel):
    allowed_algorithms: list[str] = Field(default_factory=lambda: ["ES256", "ES384", "EdDSA"])
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
    revocation_policy: RevocationPolicyModel | None = None  # DEPRECATED: use revocation_profile_id
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


class CreateTrustedIssuerRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    issuer_did: str = Field(min_length=1, max_length=2048)
    issuer_url: str | None = None
    credential_template_ids: list[str] = Field(default_factory=list)
    verification_keys: list[dict] = Field(default_factory=list)
    valid_from: str | None = None
    valid_until: str | None = None


class UpdateTrustedIssuerRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    issuer_did: str | None = None
    issuer_url: str | None = None
    credential_template_ids: list[str] | None = None
    verification_keys: list[dict] | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    trust_level: int | None = None
    relationship_status: str | None = None
    cascade_revocation_policy: str | None = None


class CreateIssuerEntityRequest(BaseModel):
    organization_id: str | None = Field(None, max_length=255)
    issuer_id: str = Field(..., min_length=1, max_length=255)
    issuer_type: str = Field(IssuerEntityType.ORGANIZATION.value, max_length=50)
    display_name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    is_system_issuer: bool = False
    compliance_status: str = Field(IssuerEntityComplianceStatus.COMPLIANT.value, max_length=50)
    accreditation_body: str | None = Field(None, max_length=255)
    accreditation_date: str | None = Field(None, max_length=50)
    valid_from: str | None = Field(None, max_length=50)
    valid_until: str | None = Field(None, max_length=50)
    trust_anchor_id: str | None = Field(None, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)


class UpdateIssuerEntityRequest(BaseModel):
    display_name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    issuer_type: str | None = Field(None, max_length=50)
    is_system_issuer: bool | None = None
    compliance_status: str | None = Field(None, max_length=50)
    accreditation_body: str | None = Field(None, max_length=255)
    accreditation_date: str | None = Field(None, max_length=50)
    valid_from: str | None = Field(None, max_length=50)
    valid_until: str | None = Field(None, max_length=50)
    trust_anchor_id: str | None = Field(None, max_length=255)
    metadata: dict[str, Any] | None = None
    revocation_reason: str | None = Field(None, max_length=500)
    revoked_by: str | None = Field(None, max_length=255)


class CreateTrustProfileIssuerRequest(BaseModel):
    issuer_id: str
    trust_level: int = 100
    relationship_status: str = TrustRelationshipStatus.TRUSTED.value
    cascade_revocation_policy: str = CascadeRevocationPolicy.NOTIFY_ONLY.value
    metadata: dict[str, Any] = Field(default_factory=dict)


class UpdateTrustProfileIssuerRequest(BaseModel):
    trust_level: int | None = None
    relationship_status: str | None = None
    cascade_revocation_policy: str | None = None
    metadata: dict[str, Any] | None = None


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
            or (request_validation_rules.allowed_algorithms if request_validation_rules else None)
            or base.allowed_algorithms
        ),
        min_key_size_rsa=(
            min_key_size_rsa
            if min_key_size_rsa is not None
            else (request_validation_rules.min_key_size_rsa if request_validation_rules else base.min_key_size_rsa)
        ),
        min_key_size_ec=(
            min_key_size_ec
            if min_key_size_ec is not None
            else (request_validation_rules.min_key_size_ec if request_validation_rules else base.min_key_size_ec)
        ),
        require_key_usage=(
            require_key_usage
            if require_key_usage is not None
            else (request_validation_rules.require_key_usage if request_validation_rules else base.require_key_usage)
        ),
        max_chain_depth=(
            max_chain_depth
            if max_chain_depth is not None
            else (request_validation_rules.max_chain_depth if request_validation_rules else base.max_chain_depth)
        ),
        allow_self_signed=(
            allow_self_signed
            if allow_self_signed is not None
            else (request_validation_rules.allow_self_signed if request_validation_rules else base.allow_self_signed)
        ),
    )


def _build_trust_sources(trust_sources: list[TrustSourceModel]) -> list[TrustSource]:
    # MIP §5.2 — each TrustSource MUST specify exactly one of url, certificate_pem, issuer_did
    for ts in trust_sources:
        provided = sum(1 for v in (ts.url, ts.certificate_pem, ts.issuer_did) if v)
        if provided != 1:
            raise HTTPException(
                status_code=422,
                detail=f"TrustSource '{ts.name}' must specify exactly one of url, certificate_pem, or issuer_did (got {provided})",
            )
    return [
        TrustSource(
            name=ts.name,
            source_type=_normalize_trust_source_type(ts.source_type),
            url=ts.url,
            certificate_pem=ts.certificate_pem,
            issuer_did=ts.issuer_did,
            description=ts.description,
            pinned_certificates=ts.pinned_certificates,
            refresh_interval_hours=ts.refresh_interval_hours,
            enabled=ts.enabled,
        )
        for ts in trust_sources
    ]


def _normalize_supported_formats(values: list[str]) -> list[CredentialFormat]:
    return [CredentialFormat(value.upper()) for value in values]


def _normalize_optional_formats(values: list[str] | None) -> list[CredentialFormat] | None:
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
            raise HTTPException(status_code=422, detail=f"Invalid jurisdiction code: {value}")
        if len(parts) == 2 and (not 1 <= len(parts[1]) <= 3 or not parts[1].isalnum()):
            raise HTTPException(status_code=422, detail=f"Invalid jurisdiction code: {value}")


def _normalize_jurisdiction_filter(values: list[str] | None) -> list[str] | None:
    if values is None:
        return None
    _validate_jurisdiction_filter(values)
    return [value.upper() for value in values]


def _issuer_status_from_compliance(status: IssuerEntityComplianceStatus) -> IssuerStatus:
    if status == IssuerEntityComplianceStatus.REVOKED:
        return IssuerStatus.REVOKED
    if status == IssuerEntityComplianceStatus.SUSPENDED:
        return IssuerStatus.SUSPENDED
    return IssuerStatus.ACTIVE


def _build_legacy_metadata(name: str, issuer_url: str | None, credential_template_ids: list[str], verification_keys: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "legacy_name": name,
        "issuer_url": issuer_url,
        "credential_template_ids": credential_template_ids,
        "verification_keys": verification_keys,
    }


def _build_issuer_entity_from_request(request: CreateIssuerEntityRequest) -> IssuerEntity:
    return IssuerEntity(
        organization_id=request.organization_id,
        issuer_id=request.issuer_id,
        issuer_type=IssuerEntityType(request.issuer_type.upper()),
        display_name=request.display_name,
        description=request.description,
        is_system_issuer=request.is_system_issuer,
        compliance_status=IssuerEntityComplianceStatus(request.compliance_status.upper()),
        accreditation_body=request.accreditation_body,
        accreditation_date=_parse_optional_datetime(request.accreditation_date),
        valid_from=_parse_optional_datetime(request.valid_from) or datetime.now(timezone.utc),
        valid_until=_parse_optional_datetime(request.valid_until),
        trust_anchor_id=request.trust_anchor_id,
        metadata=request.metadata,
    )


def _validate_trust_level(trust_level: int) -> None:
    if trust_level < 0 or trust_level > 100:
        raise HTTPException(status_code=422, detail="trust_level must be between 0 and 100")


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
        raise HTTPException(status_code=409, detail="Issuer identifier already exists in this scope")


async def _get_organization_trust_profile_or_404(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository,
    profile_id: str,
) -> OrganizationTrustProfile:
    profile = await repo.get_organization_trust_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Organization Trust Profile not found")
    return profile


async def _materialize_trusted_issuer(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository,
    profile_issuer: TrustProfileIssuer,
) -> TrustedIssuerResponse:
    return TrustedIssuerResponse(
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


class TrustedIssuerResponse(BaseModel):
    id: str
    trust_profile_id: str
    issuer_id: str | None = None
    trust_level: int = 100
    relationship_status: str = TrustRelationshipStatus.TRUSTED.value
    cascade_revocation_policy: str = CascadeRevocationPolicy.NOTIFY_ONLY.value
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class IssuerEntityResponse(BaseModel):
    id: str
    organization_id: str | None = None
    issuer_id: str
    issuer_type: str
    display_name: str
    description: str | None = None
    is_system_issuer: bool = False
    compliance_status: str
    accreditation_body: str | None = None
    accreditation_date: str | None = None
    valid_from: str
    valid_until: str | None = None
    trust_anchor_id: str | None = None
    revoked_at: str | None = None
    revocation_reason: str | None = None
    revoked_by: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


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


class CreateOrganizationTrustProfileRequest(BaseModel):
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


class UpdateOrganizationTrustProfileRequest(BaseModel):
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


class OrganizationTrustProfileResponse(BaseModel):
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
    updated_at: str


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/trust-profiles", tags=["trust-profiles"])
organization_trust_profile_router = APIRouter(prefix="/v1/organizations/{organization_id}/trust-profiles", tags=["organization-trust-profiles"])
framework_router = APIRouter(prefix="/v1/trust-frameworks", tags=["trust-frameworks"])
registry_router = APIRouter(prefix="/v1/trust-registry", tags=["trust-registry"])
issuer_router = APIRouter(prefix="/v1/issuer-entities", tags=["issuer-entities"])

_repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository | None = None


def get_repo() -> InMemoryTrustProfileRepository | PostgresTrustProfileRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


async def _seed_system_frameworks(repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository) -> None:
    for framework in SYSTEM_TRUST_FRAMEWORKS:
        existing = await repo.get_framework_by_code(framework.code)
        if existing:
            continue
        await repo.save_framework(framework)


def get_current_user_id(x_user_id: Annotated[str, Header()]) -> str:
    """Extract user ID from X-User-Id header (injected by gateway)."""
    return x_user_id


@organization_trust_profile_router.post("", response_model=OrganizationTrustProfileResponse, response_model_exclude_none=True)
async def create_organization_trust_profile(
    organization_id: str,
    request: CreateOrganizationTrustProfileRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> OrganizationTrustProfileResponse:
    membership = await app.state.org_client.get_membership(user_id, organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")

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


@organization_trust_profile_router.get("", response_model=list[OrganizationTrustProfileResponse], response_model_exclude_none=True)
async def list_organization_trust_profiles(
    organization_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> list[OrganizationTrustProfileResponse]:
    await app.state.org_client.get_membership(user_id, organization_id)
    profiles = await repo.list_organization_trust_profiles(organization_id)
    return [_organization_trust_profile_to_response(profile) for profile in profiles]


@organization_trust_profile_router.get("/{profile_id}", response_model=OrganizationTrustProfileResponse, response_model_exclude_none=True)
async def get_organization_trust_profile(
    organization_id: str,
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> OrganizationTrustProfileResponse:
    profile = await _get_organization_trust_profile_or_404(repo, profile_id)
    if profile.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Organization Trust Profile not found")
    await app.state.org_client.get_membership(user_id, organization_id)
    return _organization_trust_profile_to_response(profile)


@organization_trust_profile_router.put("/{profile_id}", response_model=OrganizationTrustProfileResponse, response_model_exclude_none=True)
async def update_organization_trust_profile(
    organization_id: str,
    profile_id: str,
    request: UpdateOrganizationTrustProfileRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> OrganizationTrustProfileResponse:
    profile = await _get_organization_trust_profile_or_404(repo, profile_id)
    if profile.organization_id != organization_id:
        raise HTTPException(status_code=404, detail="Organization Trust Profile not found")
    membership = await app.state.org_client.get_membership(user_id, organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")

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
        profile.jurisdiction_filter = _normalize_jurisdiction_filter(request.jurisdiction_filter)
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
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> TrustProfileResponse:
    """Create a new Trust Profile."""
    # Verify org membership
    org_client = await get_organization_client(fastapi_request)
    membership = await org_client.get_membership(user_id, request.organization_id)
    if not membership or not membership.is_active():
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    
    profile = TrustProfile(
        organization_id=request.organization_id,
        name=request.name,
        description=request.description,
        profile_type=TrustProfileType(request.profile_type.upper()),
        compliance_status=ComplianceStatus(request.compliance_status.upper()),
        revocation_profile_id=request.revocation_profile_id,
        supported_formats=_normalize_supported_formats(request.supported_formats),
        allowed_issuers=request.allowed_issuers,
        denied_issuers=request.denied_issuers,
        system_issuer_overrides=request.system_issuer_overrides,
        compatible_compliance_codes=request.compatible_compliance_codes,
        verification_policy_set_id=request.verification_policy_set_id,
        auto_generated=request.auto_generated,
    )

    if not request.trust_sources:
        raise HTTPException(status_code=422, detail="trust_sources must contain at least one source")
    if not request.supported_formats:
        raise HTTPException(status_code=422, detail="supported_formats must contain at least one format")

    # MIP §5.2 — allowed_algorithms must be non-empty and contain valid values
    _VALID_ALGORITHMS = {
        "ES256", "ES384", "ES512", "PS256", "PS384", "PS512",
        "EdDSA", "RS256", "RS384", "RS512",
        "BBS_BLS12381_SHA256", "BBS_BLS12381_SHAKE256",
    }
    algorithms = (
        request.allowed_algorithms
        or (request.validation_rules.allowed_algorithms if request.validation_rules else None)
        or ["ES256", "ES384", "EdDSA"]
    )
    if not algorithms:
        raise HTTPException(status_code=422, detail="allowed_algorithms must contain at least one algorithm")
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


@router.get("", response_model=list[TrustProfileResponse], response_model_exclude_none=True)
async def list_trust_profiles(
    organization_id: str = Query(..., description="Organization ID"),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
    request: Request = None,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[TrustProfileResponse]:
    """List Trust Profiles for an organization."""
    # Verify org membership
    await app.state.org_client.get_membership(user_id, organization_id)
    profiles = await repo.list_profiles(organization_id)
    return [_profile_to_response(p) for p in profiles[offset:offset + limit]]


@router.get("/{profile_id}", response_model=TrustProfileResponse, response_model_exclude_none=True)
async def get_trust_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> TrustProfileResponse:
    """Get a Trust Profile by ID."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify org membership
    await app.state.org_client.get_membership(user_id, profile.organization_id)
    return _profile_to_response(profile)


@router.patch("/{profile_id}", response_model=TrustProfileResponse, response_model_exclude_none=True)
async def update_trust_profile(
    profile_id: str,
    request: UpdateTrustProfileRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> TrustProfileResponse:
    """Update a Trust Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if request.name is not None:
        profile.name = request.name
    if request.description is not None:
        profile.description = request.description
    if request.profile_type is not None:
        profile.profile_type = TrustProfileType(request.profile_type.upper())
    if request.compliance_status is not None:
        profile.compliance_status = ComplianceStatus(request.compliance_status.upper())
    if request.trust_sources is not None:
        if not request.trust_sources:
            raise HTTPException(status_code=422, detail="trust_sources must contain at least one source")
        profile.trust_sources = _build_trust_sources(request.trust_sources)
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
            raise HTTPException(status_code=422, detail="supported_formats must contain at least one format")
        profile.supported_formats = _normalize_supported_formats(request.supported_formats)
    if request.allowed_issuers is not None:
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


@router.post("/{profile_id}/activate", response_model=TrustProfileResponse, response_model_exclude_none=True)
async def activate_trust_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> TrustProfileResponse:
    """Activate a Trust Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    profile.activate()
    await repo.save_profile(profile)
    return _profile_to_response(profile)


@router.post("/{profile_id}/suspend", response_model=TrustProfileResponse, response_model_exclude_none=True)
async def suspend_trust_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> TrustProfileResponse:
    """Suspend a Trust Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    profile.suspend()
    await repo.save_profile(profile)
    return _profile_to_response(profile)


@router.delete("/{profile_id}", response_model=DeleteResponse)
async def delete_trust_profile(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> DeleteResponse:
    """Delete a Trust Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")

    # Cascade check: reject if profile still has trusted issuers
    issuers = await repo.list_issuers(profile_id)
    if issuers:
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete trust profile with {len(issuers)} trusted issuer(s). Remove all issuers first."
        )

    await repo.delete_profile(profile_id)
    return DeleteResponse()


# Trusted Issuer endpoints (sub-resource)
@router.post("/{profile_id}/issuers", response_model=TrustedIssuerResponse, response_model_exclude_none=True)
async def add_trusted_issuer(
    profile_id: str,
    request: CreateTrustedIssuerRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> TrustedIssuerResponse:
    """Add a Trusted Issuer to a Trust Profile (requires admin)."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")

    issuer_entity = await repo.find_issuer_entity_by_identifier(profile.organization_id, request.issuer_did)
    if issuer_entity is None:
        issuer_entity = IssuerEntity(
            organization_id=profile.organization_id,
            issuer_id=request.issuer_did,
            issuer_type=IssuerEntityType.ORGANIZATION,
            display_name=request.name,
            description=request.description,
            compliance_status=IssuerEntityComplianceStatus.COMPLIANT,
            valid_from=_parse_optional_datetime(request.valid_from) or datetime.now(timezone.utc),
            valid_until=_parse_optional_datetime(request.valid_until),
            metadata={"issuer_url": request.issuer_url},
        )
        await repo.save_issuer_entity(issuer_entity)

    existing_link = await repo.get_profile_issuer_by_pair(profile_id, issuer_entity.id)
    if existing_link:
        raise HTTPException(status_code=409, detail="Issuer already linked to this trust profile")

    profile_issuer = TrustProfileIssuer(
        trust_profile_id=profile_id,
        issuer_id=issuer_entity.id,
        trust_level=100,
        relationship_status=TrustRelationshipStatus.TRUSTED,
        cascade_revocation_policy=CascadeRevocationPolicy.NOTIFY_ONLY,
        metadata=_build_legacy_metadata(
            request.name,
            request.issuer_url,
            request.credential_template_ids,
            request.verification_keys,
        ),
    )
    await repo.save_profile_issuer(profile_issuer)
    logger.info("Added Trusted Issuer link: %s to profile %s", profile_issuer.id, profile_id)
    return await _materialize_trusted_issuer(repo, profile_issuer)


@router.get("/{profile_id}/issuers", response_model=list[TrustedIssuerResponse], response_model_exclude_none=True)
async def list_trusted_issuers(
    profile_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[TrustedIssuerResponse]:
    """List Trusted Issuers for a Trust Profile."""
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    # Verify org membership
    await app.state.org_client.get_membership(user_id, profile.organization_id)
    profile_issuers = await repo.list_profile_issuers(profile_id)
    return [await _materialize_trusted_issuer(repo, profile_issuer) for profile_issuer in profile_issuers[offset:offset + limit]]


@router.get("/{profile_id}/issuers/{issuer_id}", response_model=TrustedIssuerResponse, response_model_exclude_none=True)
async def get_trusted_issuer(
    profile_id: str,
    issuer_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> TrustedIssuerResponse:
    """Get a Trusted Issuer by ID."""
    profile_issuer = await repo.get_profile_issuer(issuer_id)
    if not profile_issuer or profile_issuer.trust_profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Trusted Issuer not found")
    # Verify org membership via profile
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    await app.state.org_client.get_membership(user_id, profile.organization_id)
    return await _materialize_trusted_issuer(repo, profile_issuer)


@router.put("/{profile_id}/issuers/{issuer_id}", response_model=TrustedIssuerResponse, response_model_exclude_none=True)
async def update_trusted_issuer(
    profile_id: str,
    issuer_id: str,
    request: UpdateTrustedIssuerRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> TrustedIssuerResponse:
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")

    profile_issuer = await repo.get_profile_issuer(issuer_id)
    if not profile_issuer or profile_issuer.trust_profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Trusted Issuer not found")
    issuer_entity = await _get_issuer_entity_or_404(repo, profile_issuer.issuer_id)

    if request.issuer_did is not None and request.issuer_did != issuer_entity.issuer_id:
        await _ensure_unique_issuer_identifier(repo, issuer_entity.organization_id, request.issuer_did, excluding_id=issuer_entity.id)
        issuer_entity.issuer_id = request.issuer_did
    if request.name is not None:
        issuer_entity.display_name = request.name
    if request.description is not None:
        issuer_entity.description = request.description
    if request.valid_from is not None:
        issuer_entity.valid_from = _parse_optional_datetime(request.valid_from) or issuer_entity.valid_from
    if request.valid_until is not None:
        issuer_entity.valid_until = _parse_optional_datetime(request.valid_until)
    issuer_entity.updated_at = datetime.now(timezone.utc)
    await repo.save_issuer_entity(issuer_entity)

    metadata = dict(profile_issuer.metadata)
    if request.name is not None:
        metadata["legacy_name"] = request.name
    if request.issuer_url is not None:
        metadata["issuer_url"] = request.issuer_url
    if request.credential_template_ids is not None:
        metadata["credential_template_ids"] = request.credential_template_ids
    if request.verification_keys is not None:
        metadata["verification_keys"] = request.verification_keys
    if request.trust_level is not None:
        _validate_trust_level(request.trust_level)
        profile_issuer.trust_level = request.trust_level
    if request.relationship_status is not None:
        profile_issuer.relationship_status = TrustRelationshipStatus(request.relationship_status.upper())
    if request.cascade_revocation_policy is not None:
        profile_issuer.cascade_revocation_policy = CascadeRevocationPolicy(request.cascade_revocation_policy.upper())
    profile_issuer.metadata = metadata
    profile_issuer.updated_at = datetime.now(timezone.utc)
    await repo.save_profile_issuer(profile_issuer)
    return await _materialize_trusted_issuer(repo, profile_issuer)


@router.delete("/{profile_id}/issuers/{issuer_id}")
async def remove_trusted_issuer(
    profile_id: str,
    issuer_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> dict:
    """Remove a Trusted Issuer from a Trust Profile (requires admin)."""
    profile_issuer = await repo.get_profile_issuer(issuer_id)
    if not profile_issuer or profile_issuer.trust_profile_id != profile_id:
        raise HTTPException(status_code=404, detail="Trusted Issuer not found")
    # Verify admin access
    profile = await repo.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Trust Profile not found")
    membership = await app.state.org_client.get_membership(user_id, profile.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    await repo.delete_profile_issuer(issuer_id)
    return {"success": True}


@framework_router.get("", response_model=list[TrustFrameworkResponse], response_model_exclude_none=True)
async def list_trust_frameworks(
    _user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> list[TrustFrameworkResponse]:
    frameworks = await repo.list_frameworks()
    return [_framework_to_response(framework) for framework in frameworks]


@framework_router.get("/{framework_id}", response_model=TrustFrameworkResponse, response_model_exclude_none=True)
async def get_trust_framework(
    framework_id: str,
    _user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
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


@registry_router.get("/sync", response_model=TrustRegistrySyncResponse, response_model_exclude_none=True)
async def sync_trust_registry(
    since: str | None = Query(None, description="Opaque sync token from the previous response"),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
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


@registry_router.get("/csca", response_model=list[TrustRegistryEntryResponse], response_model_exclude_none=True)
async def list_csca_entries(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> list[TrustRegistryEntryResponse]:
    entries = await repo.list_registry_entries(anchor_type=TrustAnchorType.CSCA.value, current_only=True)
    return [_registry_entry_to_response(entry) for entry in entries]


@registry_router.get("/dsc", response_model=list[TrustRegistryEntryResponse], response_model_exclude_none=True)
async def list_dsc_entries(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> list[TrustRegistryEntryResponse]:
    entries = await repo.list_registry_entries(anchor_type=TrustAnchorType.DSC.value, current_only=True)
    return [_registry_entry_to_response(entry) for entry in entries]


@registry_router.get("/csca/{country_code}", response_model=list[TrustRegistryEntryResponse], response_model_exclude_none=True)
async def list_country_csca_entries(
    country_code: str,
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> list[TrustRegistryEntryResponse]:
    entries = await repo.list_registry_entries(
        anchor_type=TrustAnchorType.CSCA.value,
        country_code=country_code,
        current_only=True,
    )
    return [_registry_entry_to_response(entry) for entry in entries]


@registry_router.get("/status", response_model=TrustRegistryStatusResponse, response_model_exclude_none=True)
async def get_trust_registry_status(
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
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


@issuer_router.post("", response_model=IssuerEntityResponse, response_model_exclude_none=True)
async def create_issuer_entity(
    request: CreateIssuerEntityRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> IssuerEntityResponse:
    if request.organization_id is None and not request.is_system_issuer:
        raise HTTPException(status_code=400, detail="organization_id is required for non-system issuers")
    if request.organization_id is not None:
        membership = await app.state.org_client.get_membership(user_id, request.organization_id)
        if not membership.has_role("admin", "owner"):
            raise HTTPException(status_code=403, detail="Admin access required")
    await _ensure_unique_issuer_identifier(repo, request.organization_id, request.issuer_id)
    issuer_entity = _build_issuer_entity_from_request(request)
    await repo.save_issuer_entity(issuer_entity)
    return _issuer_entity_to_response(issuer_entity)


@issuer_router.get("", response_model=list[IssuerEntityResponse], response_model_exclude_none=True)
async def list_issuer_entities(
    organization_id: str | None = Query(None, description="Organization scope; includes system issuers when set"),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> list[IssuerEntityResponse]:
    if organization_id is not None:
        await app.state.org_client.get_membership(user_id, organization_id)
        issuer_entities = await repo.list_issuer_entities(organization_id)
    else:
        issuer_entities = [
            issuer_entity
            for issuer_entity in await repo.list_issuer_entities(None)
            if issuer_entity.is_system_issuer or issuer_entity.organization_id is None
        ]
    return [_issuer_entity_to_response(issuer_entity) for issuer_entity in issuer_entities]


@issuer_router.get("/{issuer_entity_id}", response_model=IssuerEntityResponse, response_model_exclude_none=True)
async def get_issuer_entity(
    issuer_entity_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> IssuerEntityResponse:
    issuer_entity = await _get_issuer_entity_or_404(repo, issuer_entity_id)
    if issuer_entity.organization_id is not None:
        await app.state.org_client.get_membership(user_id, issuer_entity.organization_id)
    return _issuer_entity_to_response(issuer_entity)


@issuer_router.put("/{issuer_entity_id}", response_model=IssuerEntityResponse, response_model_exclude_none=True)
async def update_issuer_entity(
    issuer_entity_id: str,
    request: UpdateIssuerEntityRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> IssuerEntityResponse:
    issuer_entity = await _get_issuer_entity_or_404(repo, issuer_entity_id)
    if issuer_entity.organization_id is not None:
        membership = await app.state.org_client.get_membership(user_id, issuer_entity.organization_id)
        if not membership.has_role("admin", "owner"):
            raise HTTPException(status_code=403, detail="Admin access required")
    if issuer_entity.compliance_status == IssuerEntityComplianceStatus.REVOKED and request.compliance_status not in {None, IssuerEntityComplianceStatus.REVOKED.value}:
        raise HTTPException(status_code=400, detail="Revoked issuer cannot be reinstated; create a new IssuerEntity instead")
    if request.display_name is not None:
        issuer_entity.display_name = request.display_name
    if request.description is not None:
        issuer_entity.description = request.description
    if request.issuer_type is not None:
        issuer_entity.issuer_type = IssuerEntityType(request.issuer_type.upper())
    if request.is_system_issuer is not None:
        issuer_entity.is_system_issuer = request.is_system_issuer
    if request.accreditation_body is not None:
        issuer_entity.accreditation_body = request.accreditation_body
    if request.accreditation_date is not None:
        issuer_entity.accreditation_date = _parse_optional_datetime(request.accreditation_date)
    if request.valid_from is not None:
        issuer_entity.valid_from = _parse_optional_datetime(request.valid_from) or issuer_entity.valid_from
    if request.valid_until is not None:
        issuer_entity.valid_until = _parse_optional_datetime(request.valid_until)
    if request.trust_anchor_id is not None:
        issuer_entity.trust_anchor_id = request.trust_anchor_id
    if request.metadata is not None:
        issuer_entity.metadata = request.metadata
    if request.compliance_status is not None:
        next_status = IssuerEntityComplianceStatus(request.compliance_status.upper())
        issuer_entity.compliance_status = next_status
        if next_status == IssuerEntityComplianceStatus.REVOKED:
            issuer_entity.revoked_at = datetime.now(timezone.utc)
            issuer_entity.revocation_reason = request.revocation_reason
            issuer_entity.revoked_by = request.revoked_by or user_id
    issuer_entity.updated_at = datetime.now(timezone.utc)
    await repo.save_issuer_entity(issuer_entity)
    return _issuer_entity_to_response(issuer_entity)


@issuer_router.delete("/{issuer_entity_id}")
async def delete_issuer_entity(
    issuer_entity_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryTrustProfileRepository | PostgresTrustProfileRepository = Depends(get_repo),
) -> dict[str, bool]:
    issuer_entity = await _get_issuer_entity_or_404(repo, issuer_entity_id)
    if issuer_entity.organization_id is not None:
        membership = await app.state.org_client.get_membership(user_id, issuer_entity.organization_id)
        if not membership.has_role("admin", "owner"):
            raise HTTPException(status_code=403, detail="Admin access required")
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
        profile_type=profile.profile_type.value,
        compliance_status=profile.compliance_status.value,
        trust_sources=[
            {
                "source_type": ts.source_type,
                "url": ts.url,
                "certificate_pem": ts.certificate_pem,
                "issuer_did": ts.issuer_did,
                "description": ts.description,
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


def _issuer_to_response(issuer: TrustedIssuer) -> TrustedIssuerResponse:
    return TrustedIssuerResponse(
        id=issuer.id,
        trust_profile_id=issuer.trust_profile_id,
        issuer_id=None,
        trust_level=100,
        relationship_status=TrustRelationshipStatus.TRUSTED.value,
        cascade_revocation_policy=CascadeRevocationPolicy.NOTIFY_ONLY.value,
        metadata={},
        created_at=issuer.created_at.isoformat(),
        updated_at=issuer.updated_at.isoformat(),
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
        accreditation_date=issuer_entity.accreditation_date.isoformat() if issuer_entity.accreditation_date else None,
        valid_from=issuer_entity.valid_from.isoformat(),
        valid_until=issuer_entity.valid_until.isoformat() if issuer_entity.valid_until else None,
        trust_anchor_id=issuer_entity.trust_anchor_id,
        revoked_at=issuer_entity.revoked_at.isoformat() if issuer_entity.revoked_at else None,
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


def _organization_trust_profile_to_response(profile: OrganizationTrustProfile) -> OrganizationTrustProfileResponse:
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
        allowed_formats=[fmt.value for fmt in profile.allowed_formats] if profile.allowed_formats is not None else None,
        allowed_issuers=profile.allowed_issuers,
        denied_issuers=profile.denied_issuers,
        jurisdiction_filter=profile.jurisdiction_filter,
        metadata=profile.metadata,
        created_at=profile.created_at.isoformat(),
        updated_at=profile.updated_at.isoformat(),
    )


def _registry_entry_to_response(entry: TrustRegistryEntry) -> TrustRegistryEntryResponse:
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
    
    config = get_config()
    
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
    
    # Initialize gRPC channel to organization service
    from common.di import setup_org_client, teardown_org_client
    await setup_org_client(app, "trust-profile")
    
    yield
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await teardown_org_client(app)
    await db.close()


def create_app() -> FastAPI:
    return create_service_app(
        title="Trust Profile Service",
        description="Manages Trust Profiles - who is trusted and how validation happens",
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[router, organization_trust_profile_router, framework_router, registry_router, issuer_router],
    )


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
