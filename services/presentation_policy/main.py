"""
Presentation Policy Service

Manages Presentation Policies - what credentials are requested and how
they should be presented.

A Presentation Policy defines:
- Required credential templates (what credentials are needed)
- Requested claims (which specific claims to request)
- Constraints (predicates, ranges, presence checks)
- Display metadata (how to present the request to users)
- Alternative options (acceptable substitutes)

Stateless Verification:
- POST /v1/presentation-policies/{id}/evaluate - Evaluate VP against saved policy
- POST /v1/presentation-policies/evaluate - Evaluate VP with inline policy (ad-hoc)

Port: 8009
"""

from __future__ import annotations

import base64
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, AsyncGenerator
from urllib.parse import unquote

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from marty_common.dto import DeleteResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from typing import Annotated

from marty_common import (
    OrganizationContext,
    CedarEngine,
    ensure_membership_permission,
)
from marty_common.org_authorization import get_organization_client
from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware
from marty_common.service_setup import create_service_app
from marty_common.domain_enums import parse_credential_format

from presentation_policy.infrastructure.adapters import PostgresPresentationPolicyRepository

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "presentation-policy-service"
SERVICE_PORT = int(os.environ.get("PRESENTATION_POLICY_SERVICE_PORT", "8009"))


def get_config() -> dict[str, Any]:
    """Get database configuration from environment."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL environment variable is required")
    if not database_url.startswith("postgresql+asyncpg://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return {"database_url": database_url}


# =============================================================================
# Domain Layer
# =============================================================================

class PolicyStatus(str, Enum):
    """Presentation policy status."""
    DRAFT = "draft"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class ConstraintType(str, Enum):
    """Types of constraints on claims."""
    EQUALS = "equals"           # Exact value match
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    GREATER_OR_EQUAL = "greater_or_equal"
    LESS_OR_EQUAL = "less_or_equal"
    IN_SET = "in_set"           # Value in allowed set
    NOT_IN_SET = "not_in_set"
    PRESENCE = "presence"       # Claim exists
    REGEX = "regex"             # Pattern match
    AGE_OVER = "age_over"       # Derived: age >= N


class RequestPurpose(str, Enum):
    """Purpose categories for credential requests."""
    IDENTITY_VERIFICATION = "identity_verification"
    AGE_VERIFICATION = "age_verification"
    EMPLOYMENT_VERIFICATION = "employment_verification"
    ADDRESS_VERIFICATION = "address_verification"
    QUALIFICATION_VERIFICATION = "qualification_verification"
    AUTHORIZATION = "authorization"
    COMPLIANCE = "compliance"
    OTHER = "other"


@dataclass
class ClaimConstraint:
    """
    A constraint on a requested claim.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    claim_name: str = ""
    constraint_type: ConstraintType = ConstraintType.PRESENCE
    value: Any = None  # The value to compare against
    description: str | None = None


@dataclass
class RequestedClaim:
    """
    A claim requested in the presentation.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    claim_name: str = ""
    display_name: str = ""
    description: str | None = None
    required: bool = True
    
    # Privacy preferences
    selective_disclosure: bool = True  # Request SD if available
    accept_derived: bool = True  # Accept derived attributes (e.g., age_over_21)
    
    # ZK predicate specification
    predicate_spec: dict | None = None
    
    # Constraints
    constraints: list[ClaimConstraint] = field(default_factory=list)


@dataclass
class CredentialRequirement:
    """
    A credential requirement within the policy.
    
    Specifies a credential template and which claims to request from it.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    credential_template_id: str = ""  # Reference to Credential Template
    display_name: str = ""
    description: str | None = None
    required: bool = True
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt"  # Expected payload format for verification
    
    # What to request
    requested_claims: list[RequestedClaim] = field(default_factory=list)
    
    # Trust requirements
    trust_profile_id: str | None = None  # Optional: specific trust profile
    
    # Validity requirements
    max_age_seconds: int | None = None  # Credential must be newer than this
    require_fresh_issuance: bool = False


@dataclass
class AlternativeRequirement:
    """
    An alternative way to satisfy a credential requirement.
    
    e.g., Accept either a driver's license OR a passport for identity.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str | None = None
    credential_requirements: list[CredentialRequirement] = field(default_factory=list)
    
    # How many of the alternatives are needed
    min_satisfied: int = 1  # At least one must be satisfied


@dataclass
class DisplayMetadata:
    """
    Display information for the presentation request.
    """
    title: str = ""
    description: str = ""
    purpose: RequestPurpose = RequestPurpose.IDENTITY_VERIFICATION
    purpose_description: str | None = None  # Detailed explanation for user
    verifier_name: str = ""
    verifier_logo_url: str | None = None
    privacy_policy_url: str | None = None
    terms_of_service_url: str | None = None


@dataclass
class HolderBinding:
    required: bool = False
    binding_methods: list[str] = field(default_factory=list)
    nonce_required: bool = False


@dataclass
class FreshnessPolicy:
    max_age_seconds: int | None = None
    require_not_revoked: bool = False
    revocation_grace_seconds: int | None = None


@dataclass
class IssuerConstraints:
    min_trust_level: int | None = None
    required_compliance_statuses: list[str] = field(default_factory=list)
    required_accreditations: list[str] = field(default_factory=list)


@dataclass
class PresentationPolicy:
    """
    Presentation Policy - what credentials are requested.
    
    This defines what a verifier needs to see.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    name: str = ""
    description: str | None = None
    status: PolicyStatus = PolicyStatus.DRAFT
    
    # Display
    display_metadata: DisplayMetadata = field(default_factory=DisplayMetadata)
    
    # Requirements
    required_claims: list[RequestedClaim] = field(default_factory=list)
    accepted_credential_types: list[str] = field(default_factory=list)
    credential_requirements: list[CredentialRequirement] = field(default_factory=list)
    alternative_requirements: list[AlternativeRequirement] = field(default_factory=list)
    trust_profile_id: str | None = None
    holder_binding: HolderBinding = field(default_factory=HolderBinding)
    freshness: FreshnessPolicy | None = None
    issuer_constraints: IssuerConstraints | None = None
    credential_ranking_strategy: str = "FRESHEST_FIRST"
    credential_ranking_weights: dict[str, float] | None = None
    purpose: str | None = None
    
    # Compliance
    compliance_profile_id: str | None = None  # Reference to Compliance Profile
    
    # ZK predicate options
    prefer_predicates: bool = False
    fallback_policy: str | None = None  # e.g., "accept_raw", "require_predicate", "deny"
    supported_circuits: list[str] = field(default_factory=list)  # e.g., ["ligero_age_over_21"]
    
    # Timestamps
    version: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def activate(self) -> None:
        self.status = PolicyStatus.ACTIVE
        self.updated_at = datetime.now(timezone.utc)
    
    def suspend(self) -> None:
        self.status = PolicyStatus.SUSPENDED
        self.updated_at = datetime.now(timezone.utc)

    @property
    def protocol_required_claims(self) -> list[dict[str, Any]]:
        if self.required_claims:
            return [
                {
                    "claim_name": claim.claim_name,
                    "credential_type": self.accepted_credential_types[0] if self.accepted_credential_types else None,
                    "value_constraint": claim.constraints[0].value if claim.constraints else None,
                    "predicate_spec": claim.predicate_spec,
                }
                for claim in self.required_claims
            ]

        flattened: list[dict[str, Any]] = []
        for requirement in self.credential_requirements:
            for claim in requirement.requested_claims:
                flattened.append(
                    {
                        "claim_name": claim.claim_name,
                        "credential_type": requirement.credential_template_id,
                        "value_constraint": claim.constraints[0].value if claim.constraints else None,
                        "predicate_spec": claim.predicate_spec,
                    }
                )
        return flattened

    @property
    def effective_accepted_credential_types(self) -> list[str]:
        if self.accepted_credential_types:
            return self.accepted_credential_types
        return [req.credential_template_id for req in self.credential_requirements if req.credential_template_id]


# =============================================================================
# Application Layer
# =============================================================================

class TrustProfileCache:
    """
    In-memory cache for Trust Profiles.
    
    Caches Trust Profile data with TTL based on time_policy.freshness_window_seconds.
    Reduces load on trust-profiles service during verification.
    """
    
    def __init__(self, maxsize: int = 10_000):
        self._cache: dict[str, dict] = {}  # profile_id -> {data, expires_at}
        self._maxsize = maxsize
    
    def get(self, profile_id: str) -> dict | None:
        """Get cached Trust Profile if not expired."""
        entry = self._cache.get(profile_id)
        if not entry:
            return None
        
        if datetime.now(timezone.utc) > entry["expires_at"]:
            # Expired
            del self._cache[profile_id]
            return None
        
        return entry["data"]
    
    def set(self, profile_id: str, data: dict, ttl_seconds: int) -> None:
        """Cache Trust Profile with TTL."""
        if len(self._cache) >= self._maxsize:
            # Evict expired entries first, then oldest
            now = datetime.now(timezone.utc)
            expired = [k for k, v in self._cache.items() if now > v["expires_at"]]
            for k in expired:
                del self._cache[k]
            if len(self._cache) >= self._maxsize:
                oldest = min(self._cache, key=lambda k: self._cache[k]["expires_at"])
                del self._cache[oldest]
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        self._cache[profile_id] = {
            "data": data,
            "expires_at": expires_at,
        }
        logger.debug(f"Cached Trust Profile {profile_id} until {expires_at.isoformat()}")
    
    def clear(self) -> None:
        """Clear all cached profiles."""
        self._cache.clear()


class InMemoryPresentationPolicyRepository:
    """In-memory repository for development."""
    
    def __init__(self):
        self._policies: dict[str, PresentationPolicy] = {}
    
    async def save(self, policy: PresentationPolicy) -> None:
        self._policies[policy.id] = policy
    
    async def get(self, policy_id: str) -> PresentationPolicy | None:
        return self._policies.get(policy_id)
    
    async def list(self, org_id: str) -> list[PresentationPolicy]:
        return [p for p in self._policies.values() if p.organization_id == org_id]
    
    async def delete(self, policy_id: str) -> None:
        self._policies.pop(policy_id, None)


# =============================================================================
# HTTP Adapter - Request/Response Models
# =============================================================================

class ClaimConstraintModel(BaseModel):
    claim_name: str
    constraint_type: str = "presence"
    value: Any = None
    description: str | None = None


class RequestedClaimModel(BaseModel):
    claim_name: str
    display_name: str = ""
    description: str | None = None
    required: bool = True
    selective_disclosure: bool = True
    accept_derived: bool = True
    predicate_spec: dict | None = None
    constraints: list[ClaimConstraintModel] = Field(default_factory=list)


class ProtocolRequiredClaimModel(BaseModel):
    claim_name: str
    credential_type: str | None = None
    value_constraint: Any = None
    predicate_spec: dict | None = None


class CredentialRequirementModel(BaseModel):
    credential_template_id: str
    display_name: str = ""
    description: str | None = None
    required: bool = True
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt"
    requested_claims: list[RequestedClaimModel] = Field(default_factory=list)
    trust_profile_id: str | None = None
    max_age_seconds: int | None = None
    require_fresh_issuance: bool = False


class AlternativeRequirementModel(BaseModel):
    name: str
    description: str | None = None
    credential_requirements: list[CredentialRequirementModel] = Field(default_factory=list)
    min_satisfied: int = 1


class DisplayMetadataModel(BaseModel):
    title: str = ""
    description: str = ""
    purpose: str = "identity_verification"
    purpose_description: str | None = None
    verifier_name: str = ""
    verifier_logo_url: str | None = None
    privacy_policy_url: str | None = None
    terms_of_service_url: str | None = None


class CreatePresentationPolicyRequest(BaseModel):
    organization_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    purpose: str | None = Field(None, max_length=2000)
    display_metadata: DisplayMetadataModel | None = None
    required_claims: list[ProtocolRequiredClaimModel] = Field(default_factory=list)
    accepted_credential_types: list[str] = Field(default_factory=list)
    trust_profile_id: str | None = None
    holder_binding: dict[str, Any] | None = None
    freshness: dict[str, Any] | None = None
    issuer_constraints: dict[str, Any] | None = None
    credential_ranking_strategy: str = "FRESHEST_FIRST"
    credential_ranking_weights: dict[str, float] | None = None
    credential_requirements: list[CredentialRequirementModel] = Field(default_factory=list)
    alternative_requirements: list[AlternativeRequirementModel] = Field(default_factory=list)
    compliance_profile_id: str | None = None
    prefer_predicates: bool = False
    fallback_policy: str | None = None
    supported_circuits: list[str] = Field(default_factory=list)


class UpdatePresentationPolicyRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    purpose: str | None = Field(None, max_length=2000)
    display_metadata: DisplayMetadataModel | None = None
    required_claims: list[ProtocolRequiredClaimModel] | None = None
    accepted_credential_types: list[str] | None = None
    trust_profile_id: str | None = None
    holder_binding: dict[str, Any] | None = None
    freshness: dict[str, Any] | None = None
    issuer_constraints: dict[str, Any] | None = None
    credential_ranking_strategy: str | None = None
    credential_ranking_weights: dict[str, float] | None = None
    credential_requirements: list[CredentialRequirementModel] | None = None
    alternative_requirements: list[AlternativeRequirementModel] | None = None
    compliance_profile_id: str | None = None


class PresentationPolicyResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None = None
    purpose: str | None = None
    required_claims: list[dict] = Field(default_factory=list)
    accepted_credential_types: list[str] = Field(default_factory=list)
    credential_requirements: list[dict] | None = None
    trust_profile_id: str | None = None
    holder_binding: dict | None = None
    freshness: dict | None = None
    prefer_predicates: bool = False
    supported_circuits: list[str] = Field(default_factory=list)
    fallback_policy: str | None = None
    issuer_constraints: dict | None = None
    credential_ranking_strategy: str = "FRESHEST_FIRST"
    credential_ranking_weights: dict[str, float] | None = None
    created_at: str
    updated_at: str | None = None


# =============================================================================
# Constraint Evaluation
# =============================================================================

def _evaluate_constraint(constraint_type: str, value: Any, constraint: "ClaimConstraint") -> bool:
    """Evaluate a single claim constraint against a presented value."""
    import re as _re

    expected = constraint.value

    if constraint_type == ConstraintType.PRESENCE.value:
        return value is not None

    if value is None:
        # Remaining constraint types require an actual value
        return False

    if constraint_type == ConstraintType.EQUALS.value:
        return str(value) == str(expected)

    if constraint_type == ConstraintType.NOT_EQUALS.value:
        return str(value) != str(expected)

    if constraint_type == ConstraintType.IN_SET.value:
        allowed = expected if isinstance(expected, list) else [expected]
        return str(value) in [str(a) for a in allowed]

    if constraint_type == ConstraintType.NOT_IN_SET.value:
        allowed = expected if isinstance(expected, list) else [expected]
        return str(value) not in [str(a) for a in allowed]

    if constraint_type == ConstraintType.GREATER_THAN.value:
        try:
            return float(value) > float(expected)
        except (TypeError, ValueError):
            return False

    if constraint_type == ConstraintType.LESS_THAN.value:
        try:
            return float(value) < float(expected)
        except (TypeError, ValueError):
            return False

    if constraint_type == ConstraintType.GREATER_OR_EQUAL.value:
        try:
            return float(value) >= float(expected)
        except (TypeError, ValueError):
            return False

    if constraint_type == ConstraintType.LESS_OR_EQUAL.value:
        try:
            return float(value) <= float(expected)
        except (TypeError, ValueError):
            return False

    if constraint_type == ConstraintType.REGEX.value:
        try:
            return bool(_re.fullmatch(str(expected), str(value)))
        except _re.error:
            return False

    if constraint_type == ConstraintType.AGE_OVER.value:
        # value is expected to be an ISO-8601 date of birth string
        from datetime import date as _date, datetime as _dt
        try:
            min_age = int(expected)
            dob = _dt.fromisoformat(str(value)).date()
            today = _date.today()
            age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
            return age >= min_age
        except Exception:
            logger.warning("AGE_OVER constraint evaluation failed for value=%r, expected=%r", value, expected, exc_info=True)
            return False

    # Unknown constraint type — pass through
    logger.warning(f"Unknown constraint type '{constraint_type}'; treating as passing")
    return True


# =============================================================================
# Format Detection & Verification Utilities
# =============================================================================

_SD_JWT_FORMAT_ALIASES = {
    "sd-jwt",
    "sd_jwt",
    "sd-jwt-vc",
    "sd_jwt_vc",
    "dc+sd-jwt",
    "vc+sd-jwt",
    "spruce-vc+sd-jwt",
    "ietf_sd_jwt",
    "w3c_vcdm_v2_sd_jwt",
}


def _b64decode_unpadded(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode())


def _load_marty_rs_binding() -> Any | None:
    """Load whichever Python package path exposes the marty-rs functions."""
    try:
        from _marty_rs import _marty_rs as binding
        return binding
    except Exception:
        pass

    try:
        import _marty_rs as binding
        inner = getattr(binding, "_marty_rs", None)
        return inner or binding
    except Exception:
        return None


def _detected_format_to_canonical(credential_format: str) -> str:
    normalized = str(credential_format or "").strip().lower().replace("_", "-")
    sd_jwt_aliases = {value.replace("_", "-") for value in _SD_JWT_FORMAT_ALIASES}
    if normalized in sd_jwt_aliases:
        return "SD_JWT_VC"
    if normalized in {"w3c-vc", "jwt-vc", "vc-jwt", "jwt-vc-json"}:
        return "VC_JWT"
    if normalized in {"mdoc", "mso-mdoc"}:
        return "MDOC"
    if normalized in {"openbadge-v3", "open-badge-v3", "openbadge3"}:
        return "OPENBADGE_V3"
    if normalized in {"openbadge-v2", "open-badge-v2", "openbadge2"}:
        return "OPENBADGE_V2"
    return normalized.upper() or "UNKNOWN"


def _required_format_to_canonical(required_format: str | None) -> str | None:
    if not required_format:
        return None
    normalized = str(required_format).strip().lower()
    if not normalized:
        return None
    sd_jwt_aliases = {value.replace("_", "-") for value in _SD_JWT_FORMAT_ALIASES}
    if normalized in _SD_JWT_FORMAT_ALIASES or normalized.replace("_", "-") in sd_jwt_aliases:
        return "SD_JWT_VC"
    if normalized in {"openbadge-v3", "open-badge-v3", "openbadge3"}:
        return "OPENBADGE_V3"
    if normalized in {"openbadge-v2", "open-badge-v2", "openbadge2"}:
        return "OPENBADGE_V2"
    try:
        return parse_credential_format(required_format).value
    except ValueError:
        return normalized.upper()


def _credential_format_satisfies_requirement(detected_format: str, required_format: str | None) -> bool:
    expected = _required_format_to_canonical(required_format)
    if expected is None:
        return True
    actual = _detected_format_to_canonical(detected_format)
    return actual == expected


def _jwt_header_and_payload(jwt_part: str) -> tuple[dict[str, Any], dict[str, Any]]:
    segments = jwt_part.split(".")
    if len(segments) < 2:
        raise ValueError("Malformed JWT")
    header = json.loads(_b64decode_unpadded(segments[0]))
    payload = json.loads(_b64decode_unpadded(segments[1]))
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("Malformed JWT header or payload")
    return header, payload


def _did_web_resolution_path(did: str) -> str:
    if not did.startswith("did:web:"):
        raise ValueError(f"Unsupported issuer DID method for SD-JWT verification: {did}")

    did_parts = did[len("did:web:"):].split(":")
    if not did_parts or not did_parts[0]:
        raise ValueError(f"Malformed did:web issuer DID: {did}")

    path_parts = [unquote(part) for part in did_parts[1:] if part]
    if not path_parts:
        return "/.well-known/did.json"
    return "/" + "/".join(path_parts) + "/did.json"


def _did_web_external_url(did: str) -> str:
    did_parts = did[len("did:web:"):].split(":")
    domain = unquote(did_parts[0])
    return f"https://{domain}{_did_web_resolution_path(did)}"


def _did_resolution_candidate_urls(did: str) -> list[str]:
    path = _did_web_resolution_path(did)
    candidates: list[str] = []
    for base in (
        os.environ.get("DID_RESOLUTION_BASE_URL"),
        os.environ.get("PUBLIC_BASE_URL"),
        os.environ.get("ISSUER_BASE_URL"),
        os.environ.get("PUBLIC_API_URL"),
        "http://gateway:8000",
    ):
        if not base:
            continue
        url = f"{base.rstrip('/')}{path}"
        if url not in candidates:
            candidates.append(url)

    external_url = _did_web_external_url(did)
    if external_url not in candidates:
        candidates.append(external_url)
    return candidates


def _resolve_did_document(did: str) -> dict[str, Any]:
    import httpx

    errors: list[str] = []
    for url in _did_resolution_candidate_urls(did):
        try:
            response = httpx.get(url, headers={"Accept": "application/did+json, application/json"}, timeout=5.0)
            if response.status_code == 200:
                document = response.json()
                if isinstance(document, dict):
                    return document
                errors.append(f"{url}: DID document was not a JSON object")
                continue
            errors.append(f"{url}: HTTP {response.status_code}")
        except Exception as exc:
            errors.append(f"{url}: {exc}")

    suffix = "; ".join(errors[-3:]) if errors else "no resolution URLs configured"
    raise RuntimeError(f"DID resolution failed for {did}: {suffix}")


def _method_id_matches_kid(method_id: str, kid: str, issuer_did: str) -> bool:
    if not kid:
        return False
    if method_id == kid:
        return True
    if kid.startswith("#") and method_id == f"{issuer_did}{kid}":
        return True
    if "#" not in kid and method_id == f"{issuer_did}#{kid}":
        return True
    return False


def _select_public_jwk_from_did_document(
    did_document: dict[str, Any],
    issuer_did: str,
    kid: str | None,
) -> dict[str, Any]:
    methods = did_document.get("verificationMethod") if isinstance(did_document.get("verificationMethod"), list) else []
    method_by_id = {
        method.get("id"): method
        for method in methods
        if isinstance(method, dict) and isinstance(method.get("id"), str)
    }

    if kid:
        for method_id, method in method_by_id.items():
            if _method_id_matches_kid(method_id, kid, issuer_did) and isinstance(method.get("publicKeyJwk"), dict):
                return dict(method["publicKeyJwk"])

    assertion = did_document.get("assertionMethod") if isinstance(did_document.get("assertionMethod"), list) else []
    for entry in assertion:
        method = entry if isinstance(entry, dict) else method_by_id.get(entry)
        if isinstance(method, dict) and isinstance(method.get("publicKeyJwk"), dict):
            return dict(method["publicKeyJwk"])

    for method in methods:
        if isinstance(method, dict) and isinstance(method.get("publicKeyJwk"), dict):
            return dict(method["publicKeyJwk"])

    raise RuntimeError(f"DID resolution failed for {issuer_did}: no publicKeyJwk assertion method found")


def _public_jwk_to_pem(public_jwk: dict[str, Any]) -> str:
    try:
        from jwcrypto import jwk

        sanitized = {
            key: value
            for key, value in public_jwk.items()
            if key not in {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
        }
        return jwk.JWK(**sanitized).export_to_pem(private_key=False, password=None).decode()
    except Exception as exc:
        raise RuntimeError(f"DID resolution failed: issuer public key could not be converted to PEM ({exc})") from exc

def _detect_credential_format(vp_token: str) -> str:
    """
    Auto-detect credential format from VP token.
    
    Returns: "w3c-vc", "sd-jwt", "mdoc", "openbadge-v2", "openbadge-v3", or "unknown"
    """
    try:
        stripped = vp_token.strip()
        if stripped.startswith("{"):
            credential, _document_store = _extract_open_badge_payload(stripped, "credential")
            if isinstance(credential, dict):
                context = credential.get("@context", [])
                contexts = context if isinstance(context, list) else [context]
                type_value = credential.get("type", [])
                types = type_value if isinstance(type_value, list) else [type_value]
                if "https://w3id.org/openbadges/v2" in contexts:
                    return "openbadge-v2"
                if (
                    "OpenBadgeCredential" in types
                    or "AchievementCredential" in types
                    or "https://purl.imsglobal.org/spec/ob/v3p0/context.json" in contexts
                    or "https://w3id.org/openbadges/v3" in contexts
                ):
                    return "openbadge-v3"

        # Try JWT-based formats first
        if "." in vp_token and vp_token.count(".") >= 2:
            # Could be JWT, SD-JWT, W3C VC, or Open Badge
            parts = vp_token.split(".")
            
            # SD-JWT has ~-separated disclosures after the JWT
            if "~" in vp_token:
                return "sd-jwt"
            
            # Decode header to check type
            try:
                import base64
                header_data = base64.urlsafe_b64decode(parts[0] + "==")
                header = json.loads(header_data)
                
                # Check JWT type claim
                if header.get("typ") == "openBadgeCredential":
                    return "openbadge-v3"
                elif "badge" in str(header).lower():
                    return "openbadge-v2"
                elif header.get("typ") in ["JWT", "vc+jwt"]:
                    return "w3c-vc"
            except (ValueError, json.JSONDecodeError, Exception):
                pass
            
            # Default JWT to W3C VC
            return "w3c-vc"
        
        # mDoc is CBOR-encoded
        if vp_token.startswith("\\x"):
            return "mdoc"
        
    except Exception as e:
        logger.warning(f"Format detection error: {e}")
    
    return "unknown"


def _verify_credential_by_format(
    vp_token: str,
    credential_format: str,
    nonce: str | None,
    audience: str | None,
) -> dict[str, Any]:
    """
    Verify credential based on detected format.
    
    Returns verification result with:
    - verified: bool
    - claims: dict
    - issuer_did: str
    - error: str (if failed)
    """
    try:
        if credential_format == "w3c-vc":
            return _verify_w3c_vc(vp_token, nonce, audience)
        elif credential_format == "sd-jwt":
            return _verify_sd_jwt(vp_token, nonce, audience)
        elif credential_format == "mdoc":
            return _verify_mdoc(vp_token, nonce, audience)
        elif credential_format == "openbadge-v2":
            return _verify_open_badge_v2(vp_token)
        elif credential_format == "openbadge-v3":
            return _verify_open_badge_v3(vp_token)
        else:
            return {
                "verified": False,
                "error": f"Unsupported credential format: {credential_format}",
                "claims": {},
            }
    except Exception as e:
        logger.error(f"Verification error for {credential_format}: {e}")
        return {
            "verified": False,
            "error": str(e),
            "claims": {},
        }


def _verify_w3c_vc(vp_token: str, nonce: str | None, audience: str | None) -> dict:
    """Verify W3C Verifiable Credential via Rust OID4VP engine."""
    _marty_rs = _load_marty_rs_binding()
    if _marty_rs is None:
        logger.warning("_marty_rs not available — W3C VC verification disabled")
        return {
            "verified": False,
            "claims": {},
            "issuer_did": "unknown",
            "format": "w3c-vc",
            "error": "marty-rs bindings not installed",
        }

    try:
        import json as _json
        if hasattr(_marty_rs, "oid4vp_verify_vp_token"):
            result_json = _marty_rs.oid4vp_verify_vp_token(
                vp_token,
                nonce or "",
                audience or "",
            )
        elif hasattr(_marty_rs, "verify_vp_token_jwt"):
            result_json = _marty_rs.verify_vp_token_jwt(
                audience or "",
                audience or "",
                vp_token,
                nonce or "",
            )
        else:
            raise RuntimeError("marty-rs OID4VP verification function is not available")
        result = _json.loads(result_json)
        is_valid = result.get("valid", False)
        errors = result.get("errors", [])

        # Extract claims from the VP token payload
        claims = {}
        try:
            import base64 as _b64
            parts = vp_token.split(".")
            if len(parts) >= 2:
                padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                payload = _json.loads(_b64.urlsafe_b64decode(padded))
                claims = payload.get("credentialSubject", payload.get("vc", {}).get("credentialSubject", {}))
                issuer = payload.get("iss", payload.get("issuer", "unknown"))
            else:
                issuer = "unknown"
        except Exception:
            issuer = "unknown"

        return {
            "verified": is_valid,
            "claims": claims,
            "issuer_did": issuer,
            "format": "w3c-vc",
            "error": "; ".join(errors) if errors else None,
        }
    except Exception as e:
        logger.error("W3C VC Rust verification failed: %s", e)
        return {"verified": False, "claims": {}, "issuer_did": "unknown",
                "format": "w3c-vc", "error": str(e)}


def _verify_sd_jwt(vp_token: str, nonce: str | None, audience: str | None) -> dict:
    """
    Decode an SD-JWT VC and extract all Claims (base claims + disclosures).

    Format:  ``<JWT>~<disclosure_1>~<disclosure_2>~...[~<KB-JWT>]``

    Each disclosure is a base64url-encoded JSON array:
      ``[salt, claim_name, claim_value]``

    Note: This implementation does NOT cryptographically verify the JWT
    signature or validate the issuer trust chain.  That is the responsibility
    of the trust-profile service and the Rust marty-rs bridge.  In a
    production deployment, wrap this with
    ``marty_rs.SdJwtVerifier(issuer_public_key_pem).verify(vp_token)``
    before trusting the extracted claims.
    """
    try:
        # Split SD-JWT into JWT part and disclosures
        # The last segment may be a key-binding JWT (non-empty, starts with 'e')
        segments = vp_token.split("~")
        jwt_part = segments[0]
        disclosure_parts = [
            s for s in segments[1:]
            if s and "." not in s  # KB-JWT would contain dots
        ]

        # Decode JWT payload
        header, payload = _jwt_header_and_payload(jwt_part)

        # Collect base (non-selective) claims — exclude SD-JWT internals
        _SD_INTERNAL = {"_sd", "_sd_alg", "cnf", "..."}
        claims: dict = {
            k: v for k, v in payload.items()
            if k not in _SD_INTERNAL and not k.startswith("_")
        }

        # Decode each disclosure and merge  
        for disc in disclosure_parts:
            try:
                decoded = json.loads(_b64decode_unpadded(disc))
                if isinstance(decoded, list) and len(decoded) == 3:
                    _salt, claim_name, claim_value = decoded
                    claims[str(claim_name)] = claim_value
            except Exception as disc_exc:
                logger.debug(f"Skipping malformed disclosure: {disc_exc}")

        # Optional: validate nonce if the payload carries it
        if nonce and payload.get("nonce") and payload["nonce"] != nonce:
            return {
                "verified": False,
                "error": "Nonce mismatch",
                "claims": claims,
            }

        issuer = payload.get("iss") or payload.get("issuer", "unknown")
        subject = payload.get("sub") or payload.get("subject", "unknown")

        if not isinstance(issuer, str) or not issuer.startswith("did:"):
            return {
                "verified": False,
                "claims": claims,
                "issuer_did": str(issuer or "unknown"),
                "subject": subject,
                "format": "sd-jwt",
                "error": "DID resolution failed: SD-JWT issuer is not a DID",
            }

        marty_rs = _load_marty_rs_binding()
        if marty_rs is None or not hasattr(marty_rs, "verify_sd_jwt"):
            return {
                "verified": False,
                "claims": claims,
                "issuer_did": issuer,
                "subject": subject,
                "format": "sd-jwt",
                "error": "marty-rs SD-JWT verification bindings are not installed",
            }

        try:
            did_document = _resolve_did_document(issuer)
            public_jwk = _select_public_jwk_from_did_document(did_document, issuer, header.get("kid"))
            public_key_pem = _public_jwk_to_pem(public_jwk)
            result_json = marty_rs.verify_sd_jwt(
                vp_token,
                public_key_pem,
                header.get("alg") or None,
                nonce,
                audience,
            )
            rust_result = json.loads(result_json) if isinstance(result_json, str) and result_json.strip() else {}
            if isinstance(rust_result, dict) and rust_result.get("valid") is False:
                errors = rust_result.get("errors") or []
                error_message = "; ".join(str(error) for error in errors) or rust_result.get("error") or "SD-JWT verification failed"
                return {
                    "verified": False,
                    "claims": claims,
                    "issuer_did": issuer,
                    "subject": subject,
                    "format": "sd-jwt",
                    "error": error_message,
                }
            if isinstance(rust_result, dict):
                claims.update(
                    {
                        key: value
                        for key, value in rust_result.items()
                        if key not in _SD_INTERNAL and not str(key).startswith("_")
                    }
                )
        except Exception as exc:
            error_message = str(exc)
            if "DID resolution failed" not in error_message:
                error_message = f"SD-JWT verification failed: {error_message}"
            return {
                "verified": False,
                "claims": claims,
                "issuer_did": issuer,
                "subject": subject,
                "format": "sd-jwt",
                "error": error_message,
            }

        return {
            "verified": True,
            "claims": claims,
            "issuer_did": issuer,
            "subject": subject,
            "format": "sd-jwt",
            "error": None,
        }

    except Exception as exc:
        logger.error(f"SD-JWT decode error: {exc}")
        return {"verified": False, "error": str(exc), "claims": {}}


def _verify_mdoc(vp_token: str, nonce: str | None, audience: str | None) -> dict:
    """Verify mDoc/ISO 18013-5 credential via Rust mDoc verification."""
    try:
        import _marty_rs
    except ImportError:
        logger.warning("_marty_rs not available — mDoc verification disabled")
        return {
            "verified": False,
            "claims": {},
            "issuer_did": "unknown",
            "format": "mdoc",
            "error": "marty-rs bindings not installed",
        }

    try:
        import base64 as _b64

        # mDoc VP tokens are typically base64url-encoded CBOR DeviceResponse
        padded = vp_token + "=" * (4 - len(vp_token) % 4)
        cbor_bytes = _b64.urlsafe_b64decode(padded)

        # Extract claims via Rust
        claims = _marty_rs.verify_mdoc_cbor(cbor_bytes)
        if not isinstance(claims, dict):
            claims = {}

        # Attempt signature verification (no trusted certs = structural only)
        result = _marty_rs.verify_mdoc_signature(cbor_bytes, [])
        is_valid = result.signature_valid
        error = result.error

        return {
            "verified": is_valid,
            "claims": claims,
            "issuer_did": "mdoc-issuer",
            "format": "mdoc",
            "error": error,
        }
    except Exception as e:
        logger.error("mDoc Rust verification failed: %s", e)
        return {"verified": False, "claims": {}, "issuer_did": "unknown",
                "format": "mdoc", "error": str(e)}


def _b64url_json_decode(segment: str) -> dict[str, Any]:
    import base64 as _b64

    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(_b64.urlsafe_b64decode(padded.encode()).decode())


def _extract_open_badge_payload(vp_token: str, default_key: str) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Extract an Open Badge credential/assertion and offline document store."""
    token = vp_token.strip()
    document_store: dict[str, Any] = {}

    if token.startswith("{"):
        parsed = json.loads(token)
        if not isinstance(parsed, dict):
            return None, document_store
        document_store = parsed.get("document_store") or parsed.get("documentStore") or {}
        if not isinstance(document_store, dict):
            document_store = {}

        for key in (default_key, "credential", "assertion"):
            value = parsed.get(key)
            if isinstance(value, dict):
                return value, document_store

        vp = parsed.get("vp") if isinstance(parsed.get("vp"), dict) else parsed
        verifiable_credential = vp.get("verifiableCredential") if isinstance(vp, dict) else None
        if isinstance(verifiable_credential, list) and verifiable_credential:
            first = verifiable_credential[0]
            if isinstance(first, dict):
                return first, document_store
        if isinstance(verifiable_credential, dict):
            return verifiable_credential, document_store

        return parsed, document_store

    # JWT VC fallback: extract the embedded vc object when present. Signature
    # verification remains the responsibility of the JWT/W3C path; this branch
    # only enables claim normalization for OB JWT payloads that are explicitly
    # routed here by format detection.
    parts = token.split("~", 1)[0].split(".")
    if len(parts) >= 2:
        payload = _b64url_json_decode(parts[1])
        vc = payload.get("vc") if isinstance(payload, dict) else None
        if isinstance(vc, dict):
            if "issuer" not in vc and payload.get("iss"):
                vc["issuer"] = payload["iss"]
            if "id" not in vc and payload.get("jti"):
                vc["id"] = payload["jti"]
            return vc, document_store
        if isinstance(payload, dict):
            return payload, document_store

    return None, document_store


def _run_open_badge_verify(version: str, credential: dict[str, Any], document_store: dict[str, Any]) -> dict[str, Any]:
    try:
        from marty_verification_py import open_badge_ob2_verify, open_badge_ob3_verify
    except ImportError as exc:
        raise RuntimeError("marty_verification_py Open Badge bindings are not installed") from exc

    if version == "v2":
        request = {"assertion": credential, "document_store": document_store}
        result_json = open_badge_ob2_verify(json.dumps(request))
    else:
        request = {"credential": credential, "document_store": document_store}
        result_json = open_badge_ob3_verify(json.dumps(request))
    return json.loads(result_json)


def _claims_from_open_badge_result(result: dict[str, Any], credential: dict[str, Any]) -> dict[str, Any]:
    normalized = result.get("normalized") if isinstance(result, dict) else {}
    claims = normalized.copy() if isinstance(normalized, dict) else {}

    credential_subject = (
        claims.get("credential_subject")
        or claims.get("credentialSubject")
        or credential.get("credentialSubject")
        or credential.get("recipient")
    )
    if isinstance(credential_subject, dict):
        claims.setdefault("credential_subject", credential_subject)
        if credential_subject.get("id"):
            claims.setdefault("recipient", credential_subject["id"])

        for key, value in credential_subject.items():
            if key in {"achievement", "identifier", "type", "id"}:
                continue
            if isinstance(value, (str, int, float, bool)):
                claims.setdefault(key, value)

        achievement = credential_subject.get("achievement")
        if isinstance(achievement, dict):
            if achievement.get("name"):
                claims.setdefault("name", achievement["name"])
            if achievement.get("description"):
                claims.setdefault("description", achievement["description"])

    return claims


_REVOCATION_CHECK_KEYS = {
    "revocation_checked",
    "revocation_validated",
    "revocation_status_checked",
    "status_list_checked",
    "status_checked",
}

_NOT_REVOKED_KEYS = {
    "not_revoked",
    "is_not_revoked",
    "revocation_passed",
}

_REVOKED_KEYS = {
    "revoked",
    "is_revoked",
}


def _collect_bool_values(payload: Any, target_keys: set[str]) -> list[bool]:
    values: list[bool] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_lc = str(key).strip().lower()
            if key_lc in target_keys and isinstance(value, bool):
                values.append(value)
            values.extend(_collect_bool_values(value, target_keys))
    elif isinstance(payload, list):
        for item in payload:
            values.extend(_collect_bool_values(item, target_keys))
    return values


def _derive_revocation_state(verification_result: dict[str, Any]) -> tuple[bool | None, bool | None]:
    """Derive revocation evidence from verifier output in a format-agnostic way.

    Returns:
      - revocation_checked: whether status/revocation was actually checked
      - not_revoked: whether credential is confirmed not revoked
    """
    checked_values = _collect_bool_values(verification_result, _REVOCATION_CHECK_KEYS)
    not_revoked_values = _collect_bool_values(verification_result, _NOT_REVOKED_KEYS)
    revoked_values = _collect_bool_values(verification_result, _REVOKED_KEYS)

    revocation_checked: bool | None = None
    if checked_values:
        revocation_checked = any(checked_values)

    not_revoked: bool | None = None
    if any(revoked_values):
        not_revoked = False
    elif not_revoked_values:
        # Any explicit false should fail closed.
        not_revoked = all(not_revoked_values)

    # If revocation outcome is present, treat that as evidence a check occurred.
    if revocation_checked is None and (revoked_values or not_revoked_values):
        revocation_checked = True

    return revocation_checked, not_revoked


def _issuer_from_open_badge(credential: dict[str, Any], claims: dict[str, Any]) -> str:
    issuer = claims.get("issuer") or credential.get("issuer", "unknown")
    if isinstance(issuer, dict):
        return str(issuer.get("id") or issuer.get("url") or "unknown")
    return str(issuer or "unknown")


def _verify_open_badge(vp_token: str, version: str) -> dict:
    request_key = "assertion" if version == "v2" else "credential"
    credential, document_store = _extract_open_badge_payload(vp_token, request_key)
    if not credential:
        return {
            "verified": False,
            "claims": {},
            "issuer_did": "unknown",
            "format": f"openbadge-{version}",
            "error": "Open Badge credential payload could not be extracted",
        }

    try:
        result = _run_open_badge_verify(version, credential, document_store)
    except Exception as exc:
        logger.error("Open Badge %s verification failed: %s", version, exc)
        return {
            "verified": False,
            "claims": {},
            "issuer_did": "unknown",
            "format": f"openbadge-{version}",
            "error": str(exc),
        }

    claims = _claims_from_open_badge_result(result, credential)
    errors = result.get("errors") or []
    error_message = None if result.get("valid") else "; ".join(str(e) for e in errors) or result.get("error") or "Open Badge verification failed"
    revocation_checked, not_revoked = _derive_revocation_state(result)
    is_revoked = (not_revoked is False) if not_revoked is not None else None
    return {
        "verified": bool(result.get("valid")),
        "claims": claims,
        "issuer_did": _issuer_from_open_badge(credential, claims),
        "format": f"openbadge-{version}",
        "error": error_message,
        "revocation_checked": revocation_checked,
        "not_revoked": not_revoked,
        "is_revoked": is_revoked,
        "credential_results": result,
    }


def _verify_open_badge_v2(vp_token: str) -> dict:
    """Verify Open Badges v2 credential."""
    return _verify_open_badge(vp_token, "v2")


def _verify_open_badge_v3(vp_token: str) -> dict:
    """Verify Open Badges v3 credential."""
    return _verify_open_badge(vp_token, "v3")


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/presentation-policies", tags=["presentation-policies"])

_repo: InMemoryPresentationPolicyRepository | None = None
_trust_profile_cache: TrustProfileCache | None = None


def get_repo() -> InMemoryPresentationPolicyRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


def get_current_user_id(x_user_id: Annotated[str, Header()]) -> str:
    """Extract user ID from X-User-Id header (injected by gateway)."""
    return x_user_id


def get_trust_cache() -> TrustProfileCache:
    if _trust_profile_cache is None:
        raise RuntimeError("Service not configured")
    return _trust_profile_cache


def _trust_profile_service_url() -> str:
    """Return the internal Trust Profile service base URL."""
    return os.environ.get("TRUST_PROFILE_SERVICE_URL", "http://trust-profile:8004")


def _trust_profile_lookup_url(profile_id: str) -> str:
    """Return the service-to-service Trust Profile lookup URL."""
    return f"{_trust_profile_service_url()}/internal/v1/trust-profiles/{profile_id}"


def _build_credential_requirement(model: CredentialRequirementModel) -> CredentialRequirement:
    req = CredentialRequirement(
        credential_template_id=model.credential_template_id,
        display_name=model.display_name,
        description=model.description,
        required=model.required,
        credential_payload_format=model.credential_payload_format,
        trust_profile_id=model.trust_profile_id,
        max_age_seconds=model.max_age_seconds,
        require_fresh_issuance=model.require_fresh_issuance,
    )
    
    for claim in model.requested_claims:
        rc = RequestedClaim(
            claim_name=claim.claim_name,
            display_name=claim.display_name,
            description=claim.description,
            required=claim.required,
            selective_disclosure=claim.selective_disclosure,
            accept_derived=claim.accept_derived,
            predicate_spec=claim.predicate_spec,
        )
        for constraint in claim.constraints:
            rc.constraints.append(ClaimConstraint(
                claim_name=constraint.claim_name,
                constraint_type=ConstraintType(constraint.constraint_type),
                value=constraint.value,
                description=constraint.description,
            ))
        req.requested_claims.append(rc)
    
    return req


def _build_requested_claim_from_protocol(model: ProtocolRequiredClaimModel) -> RequestedClaim:
    requested_claim = RequestedClaim(
        claim_name=model.claim_name,
        display_name=model.claim_name.replace("_", " ").title(),
        predicate_spec=model.predicate_spec,
    )
    if model.value_constraint is not None:
        requested_claim.constraints.append(
            ClaimConstraint(
                claim_name=model.claim_name,
                constraint_type=ConstraintType.EQUALS,
                value=model.value_constraint,
            )
        )
    return requested_claim


def _build_protocol_requirement(request: CreatePresentationPolicyRequest) -> CredentialRequirement | None:
    if not request.required_claims:
        return None

    requirement = CredentialRequirement(
        credential_template_id=request.accepted_credential_types[0] if request.accepted_credential_types else "protocol-inline",
        display_name=request.name,
        description=request.description,
        trust_profile_id=request.trust_profile_id,
        max_age_seconds=(request.freshness or {}).get("max_age_seconds") if request.freshness else None,
    )
    requirement.requested_claims.extend(
        _build_requested_claim_from_protocol(claim)
        for claim in request.required_claims
    )
    return requirement


@router.post("", response_model=PresentationPolicyResponse, response_model_exclude_none=True)
async def create_presentation_policy(
    request: CreatePresentationPolicyRequest,
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryPresentationPolicyRepository = Depends(get_repo),
) -> PresentationPolicyResponse:
    """Create a new Presentation Policy."""
    org_client = await get_organization_client(fastapi_request)
    membership = await org_client.get_membership(user_id, request.organization_id)
    ensure_membership_permission(membership, "presentation-policy", "create")
    
    if not request.credential_requirements and not request.required_claims:
        raise HTTPException(status_code=400, detail="At least one required claim or credential requirement is required")
    # MIP §7.2 — each credential_requirement MUST have ≥1 requested_claims
    for i, cr in enumerate(request.credential_requirements):
        if not cr.requested_claims:
            raise HTTPException(
                status_code=422,
                detail=f"credential_requirements[{i}] must have at least one requested_claims entry",
            )
    if request.credential_ranking_strategy == "CUSTOM" and not request.credential_ranking_weights:
        raise HTTPException(status_code=400, detail="credential_ranking_weights are required when credential_ranking_strategy is CUSTOM")

    policy = PresentationPolicy(
        organization_id=request.organization_id,
        name=request.name,
        description=request.description,
        purpose=request.purpose,
        accepted_credential_types=request.accepted_credential_types,
        trust_profile_id=request.trust_profile_id,
        holder_binding=HolderBinding(**request.holder_binding) if request.holder_binding else HolderBinding(),
        freshness=FreshnessPolicy(**request.freshness) if request.freshness else None,
        issuer_constraints=IssuerConstraints(**request.issuer_constraints) if request.issuer_constraints else None,
        credential_ranking_strategy=request.credential_ranking_strategy,
        credential_ranking_weights=request.credential_ranking_weights,
        compliance_profile_id=request.compliance_profile_id,
        prefer_predicates=request.prefer_predicates,
        fallback_policy=request.fallback_policy,
        supported_circuits=request.supported_circuits,
    )
    
    # Set display metadata
    if request.display_metadata:
        policy.display_metadata = DisplayMetadata(
            title=request.display_metadata.title,
            description=request.display_metadata.description,
            purpose=RequestPurpose(request.display_metadata.purpose),
            purpose_description=request.display_metadata.purpose_description or request.purpose,
            verifier_name=request.display_metadata.verifier_name,
            verifier_logo_url=request.display_metadata.verifier_logo_url,
            privacy_policy_url=request.display_metadata.privacy_policy_url,
            terms_of_service_url=request.display_metadata.terms_of_service_url,
        )
    elif request.purpose:
        policy.display_metadata.purpose_description = request.purpose
    
    # Set credential requirements
    for req_model in request.credential_requirements:
        policy.credential_requirements.append(_build_credential_requirement(req_model))

    # Accept protocol-first required_claims and bridge into the legacy evaluator shape.
    if request.required_claims:
        policy.required_claims.extend(
            _build_requested_claim_from_protocol(claim)
            for claim in request.required_claims
        )
        if not policy.credential_requirements:
            synthetic_requirement = _build_protocol_requirement(request)
            if synthetic_requirement:
                policy.credential_requirements.append(synthetic_requirement)
    
    # Set alternative requirements
    for alt_model in request.alternative_requirements:
        alt = AlternativeRequirement(
            name=alt_model.name,
            description=alt_model.description,
            min_satisfied=alt_model.min_satisfied,
        )
        for req_model in alt_model.credential_requirements:
            alt.credential_requirements.append(_build_credential_requirement(req_model))
        policy.alternative_requirements.append(alt)
    
    await repo.save(policy)
    logger.info(f"Created Presentation Policy: {policy.id}")
    return _policy_to_response(policy)


@router.get("", response_model=list[PresentationPolicyResponse], response_model_exclude_none=True)
async def list_presentation_policies(
    organization_id: str = Query(..., description="Organization ID"),
    limit: int = Query(default=100, le=500, description="Max items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryPresentationPolicyRepository = Depends(get_repo),
) -> list[PresentationPolicyResponse]:
    """List Presentation Policies for an organization."""
    membership = await app.state.org_client.get_membership(user_id, organization_id)
    ensure_membership_permission(membership, "presentation-policy", "view")
    policies = await repo.list(organization_id)
    return [_policy_to_response(p) for p in policies[offset:offset + limit]]


@router.get("/{policy_id}", response_model=PresentationPolicyResponse, response_model_exclude_none=True)
async def get_presentation_policy(
    policy_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryPresentationPolicyRepository = Depends(get_repo),
) -> PresentationPolicyResponse:
    """Get a Presentation Policy by ID."""
    policy = await repo.get(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Presentation Policy not found")
    # Service-to-service callers (non-UUID user IDs like "auth-service", "flow")
    # are allowed to read policies without an org membership check.
    try:
        uuid.UUID(user_id)
        is_service_user = False
    except (ValueError, AttributeError):
        is_service_user = True
    if not is_service_user:
        membership = await app.state.org_client.get_membership(user_id, policy.organization_id)
        ensure_membership_permission(membership, "presentation-policy", "view")
    return _policy_to_response(policy)


@router.patch("/{policy_id}", response_model=PresentationPolicyResponse, response_model_exclude_none=True)
async def update_presentation_policy(
    policy_id: str,
    request: UpdatePresentationPolicyRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryPresentationPolicyRepository = Depends(get_repo),
) -> PresentationPolicyResponse:
    """Update a Presentation Policy (requires admin)."""
    policy = await repo.get(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Presentation Policy not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, policy.organization_id)
    ensure_membership_permission(membership, "presentation-policy", "edit")
    
    if policy.status != PolicyStatus.DRAFT:
        raise HTTPException(
            status_code=400,
            detail="Only draft policies can be modified. Create a new version instead."
        )
    
    if request.name is not None:
        policy.name = request.name
    if request.description is not None:
        policy.description = request.description
    if request.purpose is not None:
        policy.purpose = request.purpose
        policy.display_metadata.purpose_description = request.purpose
    if request.compliance_profile_id is not None:
        policy.compliance_profile_id = request.compliance_profile_id
    if request.accepted_credential_types is not None:
        policy.accepted_credential_types = request.accepted_credential_types
    if request.trust_profile_id is not None:
        policy.trust_profile_id = request.trust_profile_id
    if request.holder_binding is not None:
        policy.holder_binding = HolderBinding(**request.holder_binding)
    if request.freshness is not None:
        policy.freshness = FreshnessPolicy(**request.freshness)
    if request.issuer_constraints is not None:
        policy.issuer_constraints = IssuerConstraints(**request.issuer_constraints)
    if request.credential_ranking_strategy is not None:
        if request.credential_ranking_strategy == "CUSTOM" and not request.credential_ranking_weights:
            raise HTTPException(status_code=400, detail="credential_ranking_weights are required when credential_ranking_strategy is CUSTOM")
        policy.credential_ranking_strategy = request.credential_ranking_strategy
    if request.credential_ranking_weights is not None:
        policy.credential_ranking_weights = request.credential_ranking_weights
    if request.display_metadata is not None:
        policy.display_metadata = DisplayMetadata(
            title=request.display_metadata.title,
            description=request.display_metadata.description,
            purpose=RequestPurpose(request.display_metadata.purpose),
            purpose_description=request.display_metadata.purpose_description or policy.purpose,
            verifier_name=request.display_metadata.verifier_name,
            verifier_logo_url=request.display_metadata.verifier_logo_url,
            privacy_policy_url=request.display_metadata.privacy_policy_url,
            terms_of_service_url=request.display_metadata.terms_of_service_url,
        )
    if request.credential_requirements is not None:
        policy.credential_requirements = [_build_credential_requirement(req) for req in request.credential_requirements]
    if request.required_claims is not None:
        policy.required_claims = [_build_requested_claim_from_protocol(claim) for claim in request.required_claims]
        if request.required_claims and not policy.credential_requirements:
            synthetic_requirement = CredentialRequirement(
                credential_template_id=policy.effective_accepted_credential_types[0] if policy.effective_accepted_credential_types else "protocol-inline",
                display_name=policy.name,
                description=policy.description,
                trust_profile_id=policy.trust_profile_id,
                max_age_seconds=policy.freshness.max_age_seconds if policy.freshness else None,
                requested_claims=list(policy.required_claims),
            )
            policy.credential_requirements = [synthetic_requirement]
    if request.alternative_requirements is not None:
        policy.alternative_requirements = []
        for alt_model in request.alternative_requirements:
            alt = AlternativeRequirement(
                name=alt_model.name,
                description=alt_model.description,
                min_satisfied=alt_model.min_satisfied,
            )
            for req_model in alt_model.credential_requirements:
                alt.credential_requirements.append(_build_credential_requirement(req_model))
            policy.alternative_requirements.append(alt)
    
    policy.updated_at = datetime.now(timezone.utc)
    await repo.save(policy)
    return _policy_to_response(policy)


@router.post("/{policy_id}/activate", response_model=PresentationPolicyResponse, response_model_exclude_none=True)
async def activate_presentation_policy(
    policy_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryPresentationPolicyRepository = Depends(get_repo),
) -> PresentationPolicyResponse:
    """Activate a Presentation Policy (requires admin)."""
    policy = await repo.get(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Presentation Policy not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, policy.organization_id)
    ensure_membership_permission(membership, "presentation-policy", "activate")
    
    if not policy.credential_requirements and not policy.alternative_requirements:
        raise HTTPException(
            status_code=400,
            detail="Policy must have at least one credential requirement"
        )
    
    policy.activate()
    await repo.save(policy)
    return _policy_to_response(policy)


@router.post("/{policy_id}/suspend", response_model=PresentationPolicyResponse, response_model_exclude_none=True)
async def suspend_presentation_policy(
    policy_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryPresentationPolicyRepository = Depends(get_repo),
) -> PresentationPolicyResponse:
    """Suspend a Presentation Policy (requires admin)."""
    policy = await repo.get(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Presentation Policy not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, policy.organization_id)
    ensure_membership_permission(membership, "presentation-policy", "suspend")
    policy.suspend()
    await repo.save(policy)
    return _policy_to_response(policy)


@router.post("/{policy_id}/new-version", response_model=PresentationPolicyResponse, response_model_exclude_none=True)
async def create_new_version(
    policy_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryPresentationPolicyRepository = Depends(get_repo),
) -> PresentationPolicyResponse:
    """Create a new draft version from an existing policy (requires admin)."""
    policy = await repo.get(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Presentation Policy not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, policy.organization_id)
    ensure_membership_permission(membership, "presentation-policy", "version")
    
    new_policy = PresentationPolicy(
        organization_id=policy.organization_id,
        name=policy.name,
        description=policy.description,
        display_metadata=policy.display_metadata,
        credential_requirements=policy.credential_requirements.copy(),
        alternative_requirements=policy.alternative_requirements.copy(),
        compliance_profile_id=policy.compliance_profile_id,
        version=policy.version + 1,
    )
    
    await repo.save(new_policy)
    return _policy_to_response(new_policy)


@router.delete("/{policy_id}", response_model=DeleteResponse)
async def delete_presentation_policy(
    policy_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryPresentationPolicyRepository = Depends(get_repo),
) -> DeleteResponse:
    """Delete a Presentation Policy (only allowed for drafts, requires admin)."""
    policy = await repo.get(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Presentation Policy not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, policy.organization_id)
    ensure_membership_permission(membership, "presentation-policy", "delete")
    
    if policy.status != PolicyStatus.DRAFT:
        raise HTTPException(
            status_code=400,
            detail="Only draft policies can be deleted. Suspend or archive active policies."
        )

    # Cascade check: warn if any deployment profiles reference this policy
    # (defensive — policies should only be deleted in DRAFT state, but check anyway)

    await repo.delete(policy_id)
    return DeleteResponse()


# =============================================================================
# Policy Evaluation - Stateless Verification
# =============================================================================

class EvaluationResult(str, Enum):
    """Overall evaluation result."""
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"


class ClaimEvaluationResult(BaseModel):
    """Result of evaluating a single claim."""
    claim_name: str
    satisfied: bool
    presented_value: Any | None = None
    constraint_results: list[dict] = []
    error: str | None = None


class CredentialEvaluationResult(BaseModel):
    """Result of evaluating a single credential."""
    credential_template_id: str
    satisfied: bool
    issuer_did: str | None = None
    issuer_name: str | None = None
    claim_results: list[ClaimEvaluationResult] = []
    trust_check_passed: bool = True
    freshness_check_passed: bool = True
    signature_valid: bool = True
    errors: list[str] = []
    warnings: list[str] = []


class PolicyEvaluationResponse(BaseModel):
    """Response from evaluating a presentation against a policy."""
    result: str
    policy_id: str
    policy_name: str
    
    # Per-credential results
    credential_results: list[CredentialEvaluationResult]
    
    # Summary
    total_requirements: int
    satisfied_requirements: int
    required_satisfied: int
    required_total: int
    
    # Decision support
    decision: str  # "allow", "deny", "manual_review"
    decision_reason: str
    
    # Verified claims (aggregated from all credentials)
    verified_claims: dict[str, Any]
    
    # Audit
    evaluation_timestamp: str
    nonce: str | None = None


class EvaluatePresentationRequest(BaseModel):
    """Request to evaluate a verifiable presentation against a policy."""
    vp_token: str = Field(max_length=1_000_000)  # The VP token (JWT or JSON)
    trust_profile_id: str | None = Field(None, max_length=255)  # Override policy's trust profile
    nonce: str | None = Field(None, max_length=512)  # Expected nonce for replay protection
    audience: str | None = Field(None, max_length=512)  # Expected audience
    
    # Context for evaluation
    context: dict[str, Any] = {}


class EvaluateInlineRequest(BaseModel):
    """Request to evaluate with inline policy (ad-hoc verification)."""
    vp_token: str = Field(max_length=1_000_000)
    
    # Inline policy definition
    required_claims: list[dict] = []  # [{claim_name, constraints}]
    accepted_credential_types: list[str] = []
    trust_profile_id: str | None = Field(None, max_length=255)
    
    # Verification options
    nonce: str | None = Field(None, max_length=512)
    audience: str | None = Field(None, max_length=512)


@router.post("/{policy_id}/evaluate", response_model=PolicyEvaluationResponse, response_model_exclude_none=True)
async def evaluate_presentation(
    policy_id: str,
    request: EvaluatePresentationRequest,
    http_request: Request = None,
    repo: InMemoryPresentationPolicyRepository = Depends(get_repo),
) -> PolicyEvaluationResponse:
    """
    Evaluate a Verifiable Presentation against a Presentation Policy.
    
    This is the primary verification endpoint. It:
    1. Auto-detects credential format (W3C VC, SD-JWT, mDoc, Open Badges v2/v3)
    2. Validates the VP token structure and signature
    3. Checks issuer trust against the Trust Profile
    4. Verifies each credential meets the policy's requirements
    5. Evaluates claim constraints (predicates, presence, etc.)
    6. Returns a detailed result with verified claims
    
    Supported Formats:
    - W3C Verifiable Credentials (JWT format)
    - SD-JWT (Selective Disclosure JWT)
    - mDoc/ISO 18013-5
    - Open Badges v2 (JWT)
    - Open Badges v3 (JWT)
    
    Use this for stateless verification where you have the VP token.
    For async wallet flows (QR codes, request_uri), use Flow instances.
    """
    policy = await repo.get(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Presentation Policy not found")
    
    if policy.status != PolicyStatus.ACTIVE:
        raise HTTPException(
            status_code=400,
            detail=f"Policy is not active (status: {policy.status.value})"
        )
    
    # Auto-detect credential format
    credential_format = _detect_credential_format(request.vp_token)
    logger.info(f"Detected credential format: {credential_format}")
    
    # Verify credential based on format.
    #
    # MIP flow note:
    # - Some credential-login policies intentionally do NOT require holder
    #   binding (`holder_binding.required=false`, `nonce_required=false`).
    # - Passing nonce/audience unconditionally can force SD-JWT key-binding
    #   checks and reject otherwise valid issuer-signed credentials.
    #
    # Therefore only enforce nonce/audience at credential-verification time when
    # the policy requires holder binding (or explicitly requires nonce).
    verify_nonce = request.nonce if (policy.holder_binding.required or policy.holder_binding.nonce_required) else None
    verify_audience = request.audience if policy.holder_binding.required else None

    verification_result = _verify_credential_by_format(
        request.vp_token,
        credential_format,
        verify_nonce,
        verify_audience,
    )
    # 4. Check issuer trust using Trust Profile
    # 5. Evaluate claims against policy constraints
    # 6. Check freshness/expiry
    
    # Extract real claims from the verification result
    extracted_claims: dict[str, Any] = verification_result.get("claims", {})
    issuer_did: str = verification_result.get("issuer_did", "unknown")
    verification_ok: bool = verification_result.get("verified", False)
    revocation_checked, not_revoked = _derive_revocation_state(verification_result)

    if not verification_ok:
        verification_error = verification_result.get("error") or "Credential verification failed"
        credential_results = [
            CredentialEvaluationResult(
                credential_template_id=req.credential_template_id,
                satisfied=False,
                issuer_did=issuer_did,
                claim_results=[],
                signature_valid=False,
                errors=[str(verification_error)],
            )
            for req in policy.credential_requirements
        ]
        required_total = sum(1 for req in policy.credential_requirements if req.required)
        return PolicyEvaluationResponse(
            result=EvaluationResult.FAILED.value,
            policy_id=policy.id,
            policy_name=policy.name,
            credential_results=credential_results,
            total_requirements=len(policy.credential_requirements),
            satisfied_requirements=0,
            required_satisfied=0,
            required_total=required_total,
            decision="deny",
            decision_reason=f"Credential verification failed: {verification_error}",
            verified_claims={},
            evaluation_timestamp=datetime.now(timezone.utc).isoformat(),
            nonce=request.nonce,
        )

    # Validate issuer DID against the policy's Trust Profile (MIP §8.3).
    # Resolve trust_profile_id: per-requirement override takes precedence over policy-level.
    trust_profile_id = request.trust_profile_id or policy.trust_profile_id
    if not trust_profile_id:
        for req in policy.credential_requirements:
            if req.trust_profile_id:
                trust_profile_id = req.trust_profile_id
                break

    trust_check_passed = True
    trust_check_error: str | None = None
    if trust_profile_id and issuer_did and issuer_did != "unknown":
        try:
            trust_cache = get_trust_cache()
            trust_profile_data = trust_cache.get(trust_profile_id)
            if trust_profile_data is None:
                # Fetch from trust-profiles service via HTTP
                import httpx as _httpx
                resp = _httpx.get(
                    _trust_profile_lookup_url(trust_profile_id),
                    timeout=5.0,
                )
                if resp.status_code == 200:
                    trust_profile_data = resp.json()
                    ttl = int(trust_profile_data.get("time_policy", {}).get("freshness_window_seconds", 3600))
                    trust_cache.set(trust_profile_id, trust_profile_data, ttl)
                else:
                    trust_check_passed = False
                    trust_check_error = (
                        f"Trust Profile {trust_profile_id} could not be loaded "
                        f"(HTTP {resp.status_code})"
                    )
                    logger.warning(trust_check_error)

            if trust_profile_data:
                allowed_issuers: list[str] = trust_profile_data.get("allowed_issuers") or []
                denied_issuers: list[str] = trust_profile_data.get("denied_issuers") or []
                trust_sources: list[dict] = trust_profile_data.get("trust_sources") or []
                # Check denied list first (fail-closed)
                if denied_issuers and issuer_did in denied_issuers:
                    trust_check_passed = False
                    trust_check_error = f"Issuer {issuer_did} is explicitly denied by Trust Profile"
                elif allowed_issuers:
                    # If allowed list is specified, issuer MUST be in it
                    if issuer_did not in allowed_issuers:
                        trust_check_passed = False
                        trust_check_error = f"Issuer {issuer_did} is not in Trust Profile allowed_issuers"
                elif trust_sources:
                    # Check if issuer DID matches any trust source's issuer_did
                    source_dids = [
                        source.get("issuer_did") or ""
                        for source in trust_sources
                        if isinstance(source, dict)
                    ]
                    if source_dids and issuer_did not in source_dids:
                        trust_check_passed = False
                        trust_check_error = (
                            f"Issuer {issuer_did} does not match any trust source "
                            f"in Trust Profile {trust_profile_id}"
                        )
                    elif not source_dids:
                        logger.debug(
                            "Trust Profile %s has no trust_source issuer_dids — skipping issuer match",
                            trust_profile_id,
                        )
            elif trust_check_passed:
                trust_check_passed = False
                trust_check_error = f"Trust Profile {trust_profile_id} could not be loaded"
        except Exception as exc:
            trust_check_passed = False
            trust_check_error = f"Trust Profile validation failed for {issuer_did}: {exc}"
            logger.warning(trust_check_error)

    if not trust_check_passed:
        credential_results = [
            CredentialEvaluationResult(
                credential_template_id=req.credential_template_id,
                satisfied=False,
                issuer_did=issuer_did,
                claim_results=[],
                trust_check_passed=False,
                signature_valid=False,
                errors=[str(trust_check_error)],
            )
            for req in policy.credential_requirements
        ]
        required_total = sum(1 for req in policy.credential_requirements if req.required)
        return PolicyEvaluationResponse(
            result=EvaluationResult.FAILED.value,
            policy_id=policy.id,
            policy_name=policy.name,
            credential_results=credential_results,
            total_requirements=len(policy.credential_requirements),
            satisfied_requirements=0,
            required_satisfied=0,
            required_total=required_total,
            decision="deny",
            decision_reason=f"Credential verification failed: {trust_check_error}",
            verified_claims={},
            evaluation_timestamp=datetime.now(timezone.utc).isoformat(),
            nonce=request.nonce,
        )

    # Apply freshness/revocation requirements from MIP policy abstractions.
    # This must remain format-agnostic and not tied to a specific login flow.
    if policy.freshness and policy.freshness.require_not_revoked:
        if revocation_checked is not True:
            verification_error = "Revocation status was not checked by the verifier"
            credential_results = [
                CredentialEvaluationResult(
                    credential_template_id=req.credential_template_id,
                    satisfied=False,
                    issuer_did=issuer_did,
                    claim_results=[],
                    freshness_check_passed=False,
                    signature_valid=False,
                    errors=[verification_error],
                )
                for req in policy.credential_requirements
            ]
            required_total = sum(1 for req in policy.credential_requirements if req.required)
            return PolicyEvaluationResponse(
                result=EvaluationResult.FAILED.value,
                policy_id=policy.id,
                policy_name=policy.name,
                credential_results=credential_results,
                total_requirements=len(policy.credential_requirements),
                satisfied_requirements=0,
                required_satisfied=0,
                required_total=required_total,
                decision="deny",
                decision_reason=f"Credential verification failed: {verification_error}",
                verified_claims={},
                evaluation_timestamp=datetime.now(timezone.utc).isoformat(),
                nonce=request.nonce,
            )
        if not_revoked is not True:
            verification_error = "Credential is revoked"
            credential_results = [
                CredentialEvaluationResult(
                    credential_template_id=req.credential_template_id,
                    satisfied=False,
                    issuer_did=issuer_did,
                    claim_results=[],
                    freshness_check_passed=False,
                    signature_valid=False,
                    errors=[verification_error],
                )
                for req in policy.credential_requirements
            ]
            required_total = sum(1 for req in policy.credential_requirements if req.required)
            return PolicyEvaluationResponse(
                result=EvaluationResult.FAILED.value,
                policy_id=policy.id,
                policy_name=policy.name,
                credential_results=credential_results,
                total_requirements=len(policy.credential_requirements),
                satisfied_requirements=0,
                required_satisfied=0,
                required_total=required_total,
                decision="deny",
                decision_reason=f"Credential verification failed: {verification_error}",
                verified_claims={},
                evaluation_timestamp=datetime.now(timezone.utc).isoformat(),
                nonce=request.nonce,
            )

    credential_results = []
    verified_claims: dict[str, Any] = {}
    all_satisfied = True
    required_satisfied = 0
    required_total = 0
    
    for req in policy.credential_requirements:
        if req.required:
            required_total += 1
        
        claim_results = []
        req_satisfied = True
        req_errors: list[str] = []

        if not _credential_format_satisfies_requirement(credential_format, req.credential_payload_format):
            req_satisfied = False
            req_errors.append(
                "Credential format mismatch: "
                f"policy requires {req.credential_payload_format}, presentation is {credential_format}"
            )
        
        for claim in req.requested_claims:
            # Use real extracted value; fall back to None if not present
            presented_value = extracted_claims.get(claim.claim_name)
            claim_satisfied = presented_value is not None or not claim.required

            # Evaluate constraints against the presented value
            constraint_results = []
            for c in claim.constraints:
                try:
                    ct = c.constraint_type.value
                    passed = _evaluate_constraint(ct, presented_value, c)
                    constraint_results.append({"constraint": ct, "passed": passed})
                    if not passed:
                        claim_satisfied = False
                except Exception:
                    logger.warning("Constraint evaluation error for %s/%s", claim.claim_name, c.constraint_type.value, exc_info=True)
                    constraint_results.append({"constraint": c.constraint_type.value, "passed": False, "error": True})
                    claim_satisfied = False

            claim_results.append(ClaimEvaluationResult(
                claim_name=claim.claim_name,
                satisfied=claim_satisfied,
                presented_value=str(presented_value) if presented_value is not None else None,
                constraint_results=constraint_results,
            ))
            if claim.required and not claim_satisfied:
                req_satisfied = False
            
            if presented_value is not None:
                verified_claims[claim.claim_name] = presented_value
        
        credential_results.append(CredentialEvaluationResult(
            credential_template_id=req.credential_template_id,
            satisfied=req_satisfied,
            issuer_did=issuer_did,
            issuer_name=None,
            claim_results=claim_results,
            errors=req_errors,
        ))
        
        if req.required:
            if req_satisfied:
                required_satisfied += 1
            else:
                all_satisfied = False
    
    # Determine overall result
    if all_satisfied and required_satisfied == required_total:
        result = EvaluationResult.PASSED
        decision = "allow"
        decision_reason = "All required credentials and claims satisfied"
    elif required_satisfied > 0:
        result = EvaluationResult.PARTIAL
        decision = "manual_review"
        decision_reason = f"Partially satisfied: {required_satisfied}/{required_total} required"
        all_satisfied = False
    else:
        result = EvaluationResult.FAILED
        decision = "deny"
        decision_reason = "Required credentials not satisfied"
        all_satisfied = False
    
    # Cedar policy evaluation for credential verification trust rules
    cedar_engine = None
    if http_request and hasattr(http_request.app.state, "cedar_engine"):
        cedar_engine = http_request.app.state.cedar_engine
    
    if cedar_engine and decision == "allow":
        cedar_context = {
            "credential_format": _detected_format_to_canonical(credential_format),
            "compliance_code": verified_claims.get("_compliance_code", "CUSTOM"),
            "issuer_id": credential_results[0].issuer_did if credential_results else "",
            "issuer_trust_level": 75,
            "credential_age_seconds": 0,
            "is_revoked": not_revoked is False,
            "is_expired": False,
            "holder_binding_present": True,
            "algorithm": verified_claims.get("_algorithm", "ES256"),
        }
        cedar_entities = [
            {
                "uid": {"type": "MIP::User", "id": "verifier"},
                "attrs": {"email": "", "status": "ACTIVE"},
                "parents": [{"type": "MIP::Organization", "id": policy.organization_id}],
            },
            {
                "uid": {"type": "MIP::Organization", "id": policy.organization_id},
                "attrs": {},
                "parents": [],
            },
            {
                "uid": {"type": "MIP::Credential", "id": "presented-credential"},
                "attrs": {
                    "format": cedar_context["credential_format"],
                    "status": "ACTIVE",
                    "compliance_code": cedar_context["compliance_code"],
                    "issuer_id": cedar_context["issuer_id"],
                    "trust_level": cedar_context["issuer_trust_level"],
                },
                "parents": [{"type": "MIP::Organization", "id": policy.organization_id}],
            },
        ]
        cedar_decision = cedar_engine.is_authorized(
            principal='MIP::User::"verifier"',
            action='MIP::Action::"credentials:verify"',
            resource='MIP::Credential::"presented-credential"',
            context=cedar_context,
            entities=cedar_entities,
        )
        if not cedar_decision.allowed:
            decision = "deny"
            decision_reason = f"Cedar policy denied: {cedar_decision.reasons or cedar_decision.errors}"
            result = EvaluationResult.FAILED
            logger.warning(f"Cedar denied credential verification: {cedar_decision.errors}")
    
    return PolicyEvaluationResponse(
        result=result.value,
        policy_id=policy.id,
        policy_name=policy.name,
        credential_results=credential_results,
        total_requirements=len(policy.credential_requirements),
        satisfied_requirements=sum(1 for cr in credential_results if cr.satisfied),
        required_satisfied=required_satisfied,
        required_total=required_total,
        decision=decision,
        decision_reason=decision_reason,
        verified_claims=verified_claims,
        evaluation_timestamp=datetime.now(timezone.utc).isoformat(),
        nonce=request.nonce,
    )


@router.post("/evaluate", response_model=PolicyEvaluationResponse, response_model_exclude_none=True)
async def evaluate_presentation_inline(
    request: EvaluateInlineRequest,
) -> PolicyEvaluationResponse:
    """
    Evaluate a presentation with inline policy definition.
    
    Use this for ad-hoc verification where you don't have a saved policy.
    For production use, prefer saved policies for consistency and auditing.
    """
    # Build inline policy
    claim_results = []
    verified_claims: dict[str, Any] = {}
    
    for claim_def in request.required_claims:
        claim_name = claim_def.get("claim_name", "unknown")
        claim_results.append(ClaimEvaluationResult(
            claim_name=claim_name,
            satisfied=True,  # Simulated
            presented_value="[simulated]",
        ))
        verified_claims[claim_name] = "[simulated]"
    
    credential_results = [
        CredentialEvaluationResult(
            credential_template_id=ct,
            satisfied=True,
            issuer_did="did:example:issuer",
            claim_results=claim_results,
        )
        for ct in request.accepted_credential_types
    ] if request.accepted_credential_types else [
        CredentialEvaluationResult(
            credential_template_id="inline",
            satisfied=True,
            issuer_did="did:example:issuer",
            claim_results=claim_results,
        )
    ]
    
    return PolicyEvaluationResponse(
        result=EvaluationResult.PASSED.value,
        policy_id="inline",
        policy_name="Inline Policy",
        credential_results=credential_results,
        total_requirements=len(request.required_claims),
        satisfied_requirements=len(request.required_claims),
        required_satisfied=len(request.required_claims),
        required_total=len(request.required_claims),
        decision="allow",
        decision_reason="Inline evaluation passed (simulated)",
        verified_claims=verified_claims,
        evaluation_timestamp=datetime.now(timezone.utc).isoformat(),
        nonce=request.nonce,
    )


def _policy_to_response(policy: PresentationPolicy) -> PresentationPolicyResponse:
    return PresentationPolicyResponse(
        id=policy.id,
        organization_id=policy.organization_id,
        name=policy.name,
        description=policy.description,
        purpose=policy.purpose or policy.display_metadata.purpose_description,
        required_claims=policy.protocol_required_claims,
        accepted_credential_types=policy.effective_accepted_credential_types,
        credential_requirements=None,
        trust_profile_id=policy.trust_profile_id,
        holder_binding={
            "required": policy.holder_binding.required,
            "binding_methods": policy.holder_binding.binding_methods,
            "nonce_required": policy.holder_binding.nonce_required,
        },
        freshness={
            "max_age_seconds": policy.freshness.max_age_seconds,
            "require_not_revoked": policy.freshness.require_not_revoked,
            "revocation_grace_seconds": policy.freshness.revocation_grace_seconds,
        } if policy.freshness else None,
        prefer_predicates=policy.prefer_predicates,
        supported_circuits=policy.supported_circuits,
        fallback_policy=policy.fallback_policy,
        issuer_constraints={
            "min_trust_level": policy.issuer_constraints.min_trust_level,
            "required_compliance_statuses": policy.issuer_constraints.required_compliance_statuses,
            "required_accreditations": policy.issuer_constraints.required_accreditations,
        } if policy.issuer_constraints else None,
        credential_ranking_strategy=policy.credential_ranking_strategy,
        credential_ranking_weights=policy.credential_ranking_weights,
        created_at=policy.created_at.isoformat(),
        updated_at=policy.updated_at.isoformat(),
    )


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo, _trust_profile_cache
    logger.info(f"Starting {SERVICE_NAME}...")
    
    # Initialize PostgreSQL adapter
    config = get_config()
    from marty_common.database import DatabaseManager, DatabaseConfig
    db = DatabaseManager(DatabaseConfig.from_env("presentation-policy"))
    session_factory = db.session_factory
    _repo = PostgresPresentationPolicyRepository(session_factory)
    logger.info("PostgreSQL adapter initialized for presentation-policy service")
    
    # Initialize gRPC channel to organization service
    from common.di import setup_org_client, teardown_org_client
    await setup_org_client(app, "presentation-policy")
    
    _trust_profile_cache = TrustProfileCache()
    
    # Initialize Cedar engine for credential verification policies.
    # Some deployed images may carry an older marty_common package that does not
    # yet expose with_credential_verification(); gracefully fall back to defaults.
    if hasattr(CedarEngine, "with_credential_verification"):
        app.state.cedar_engine = CedarEngine.with_credential_verification()
        logger.info("Cedar engine initialized for credential verification")
    else:
        app.state.cedar_engine = CedarEngine.with_defaults()
        logger.warning(
            "CedarEngine.with_credential_verification unavailable; falling back to default Cedar policies"
        )
    
    # Start gRPC server
    from common.grpc_factory import create_grpc_server, start_grpc_server_port
    from presentation_policy.infrastructure.adapters.grpc_adapter import (
        PresentationPolicyServiceGrpc,
    )
    from marty_proto.v1.presentation_policy_service_pb2_grpc import (
        add_PresentationPolicyServiceServicer_to_server,
    )

    grpc_port = int(os.environ.get("PP_GRPC_PORT", "9009"))
    grpc_server, health_servicer = create_grpc_server("presentation-policy")
    servicer = PresentationPolicyServiceGrpc(
        repo=_repo,
        evaluate_fn=evaluate_presentation,
        to_response_fn=_policy_to_response,
    )
    add_PresentationPolicyServiceServicer_to_server(servicer, grpc_server)
    start_grpc_server_port(
        grpc_server, grpc_port,
        service_names=["marty.ui.presentation_policy.v1.PresentationPolicyService"],
        health_servicer=health_servicer,
    )
    await grpc_server.start()
    logger.info(f"Presentation-policy gRPC server listening on :{grpc_port}")
    
    yield
    
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await grpc_server.stop(grace=5)
    await teardown_org_client(app)
    await db.close()


def create_app() -> FastAPI:
    app = create_service_app(
        title="Presentation Policy Service",
        description="""Manages Presentation Policies - what credentials are requested for verification.

## Stateless Verification

For immediate policy evaluation without session state:

- `POST /v1/presentation-policies/{id}/evaluate` - Evaluate VP against a saved policy
- `POST /v1/presentation-policies/evaluate` - Evaluate VP with inline (ad-hoc) policy

## Policy Management

CRUD operations for Presentation Policies that define required credentials and claims.
        """,
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[router],
    )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        logger.warning("Validation error on %s %s: %s", request.method, request.url.path, exc.errors())
        return JSONResponse(status_code=400, content={"detail": exc.errors()})

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
