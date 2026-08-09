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
import hashlib
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, AsyncGenerator
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from marty_common.dto import DeleteResponse
from pydantic import BaseModel, ConfigDict, Field

from marty_common import (
    CedarEngine,
    ensure_membership_permission,
)
from marty_common.org_authorization import get_organization_client
from marty_common.service_setup import create_service_app
from marty_common.domain_enums import parse_credential_format

from common.did_resolution import resolve_did_document
from presentation_policy.infrastructure.adapters import (
    PostgresPresentationPolicyRepository,
)

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

    EQUALS = "equals"  # Exact value match
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    GREATER_OR_EQUAL = "greater_or_equal"
    LESS_OR_EQUAL = "less_or_equal"
    IN_SET = "in_set"  # Value in allowed set
    NOT_IN_SET = "not_in_set"
    PRESENCE = "presence"  # Claim exists
    REGEX = "regex"  # Pattern match
    AGE_OVER = "age_over"  # Derived: age >= N


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
    credential_payload_format: str = (
        "w3c_vcdm_v2_sd_jwt"  # Expected payload format for verification
    )

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
    proof_profiles: list[str] = field(default_factory=list)
    proof_freshness: dict[str, Any] = field(default_factory=dict)


def normalize_holder_binding(value: dict[str, Any] | None) -> HolderBinding:
    """Read legacy policies while emitting only the MIP canonical shape."""
    payload = dict(value or {})
    required = bool(payload.get("required", False))
    methods = [
        "SESSION_BINDING" if method == "NONCE" else method
        for method in payload.get("binding_methods", [])
        if method != "BIOMETRIC"
    ]
    if required and not methods:
        methods = ["DEVICE_KEY"]

    profiles = list(payload.get("proof_profiles") or [])
    if required and not profiles:
        profiles = ["OID4VP_VERIFIABLE_PRESENTATION"]

    proof_freshness = dict(payload.get("proof_freshness") or {})
    if required and not proof_freshness:
        proof_freshness = {
            "challenge_required": True,
            "audience_binding_required": True,
            "replay_detection_required": True,
        }

    return HolderBinding(
        required=required,
        binding_methods=methods,
        proof_profiles=profiles,
        proof_freshness=proof_freshness,
    )


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
    fallback_policy: str | None = (
        None  # e.g., "accept_raw", "require_predicate", "deny"
    )
    supported_circuits: list[str] = field(
        default_factory=list
    )  # e.g., ["ligero_age_over_21"]

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
                    "credential_type": self.accepted_credential_types[0]
                    if self.accepted_credential_types
                    else None,
                    "value_constraint": claim.constraints[0].value
                    if claim.constraints
                    else None,
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
                        "value_constraint": claim.constraints[0].value
                        if claim.constraints
                        else None,
                        "predicate_spec": claim.predicate_spec,
                    }
                )
        return flattened

    @property
    def effective_accepted_credential_types(self) -> list[str]:
        if self.accepted_credential_types:
            return self.accepted_credential_types
        return [
            req.credential_template_id
            for req in self.credential_requirements
            if req.credential_template_id
        ]


# =============================================================================
# Application Layer
# =============================================================================


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
    model_config = ConfigDict(extra="forbid")

    claim_name: str
    constraint_type: str = "presence"
    value: Any = None
    description: str | None = None


class RequestedClaimModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_name: str
    display_name: str = ""
    description: str | None = None
    required: bool = True
    selective_disclosure: bool = True
    accept_derived: bool = True
    predicate_spec: dict | None = None
    constraints: list[ClaimConstraintModel] = Field(default_factory=list)


class ProtocolRequiredClaimModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    claim_name: str
    credential_type: str | None = None
    value_constraint: Any = None
    predicate_spec: dict | None = None


class CredentialRequirementModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_template_id: str
    display_name: str = ""
    description: str | None = None
    required: bool = True
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt"
    requested_claims: list[RequestedClaimModel] = Field(min_length=1)
    trust_profile_id: str | None = None
    max_age_seconds: int | None = None
    require_fresh_issuance: bool = False


class AlternativeRequirementModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str | None = None
    credential_requirements: list[CredentialRequirementModel] = Field(min_length=1)
    min_satisfied: int = 1


class DisplayMetadataModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = ""
    description: str = ""
    purpose: str = "identity_verification"
    purpose_description: str | None = None
    verifier_name: str = ""
    verifier_logo_url: str | None = None
    privacy_policy_url: str | None = None
    terms_of_service_url: str | None = None


class CreatePresentationPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
    credential_requirements: list[CredentialRequirementModel] = Field(
        default_factory=list
    )
    alternative_requirements: list[AlternativeRequirementModel] = Field(
        default_factory=list
    )
    compliance_profile_id: str | None = None
    prefer_predicates: bool = False
    fallback_policy: str | None = None
    supported_circuits: list[str] = Field(default_factory=list)


class UpdatePresentationPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

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
    model_config = ConfigDict(extra="forbid")

    id: str
    organization_id: str
    name: str
    status: str
    description: str | None = None
    purpose: str | None = None
    required_claims: list[dict]
    accepted_credential_types: list[str]
    display_metadata: dict | None = None
    credential_requirements: list[dict] | None = None
    alternative_requirements: list[dict] | None = None
    compliance_profile_id: str | None = None
    trust_profile_id: str | None = None
    holder_binding: dict
    freshness: dict | None = None
    prefer_predicates: bool
    supported_circuits: list[str]
    fallback_policy: str | None = None
    issuer_constraints: dict | None = None
    credential_ranking_strategy: str
    credential_ranking_weights: dict[str, float] | None = None
    version: int
    created_at: str
    updated_at: str


# =============================================================================
# Constraint Evaluation
# =============================================================================


def _evaluate_constraint(
    constraint_type: str, value: Any, constraint: "ClaimConstraint"
) -> bool:
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
            age = (
                today.year
                - dob.year
                - ((today.month, today.day) < (dob.month, dob.day))
            )
            return age >= min_age
        except Exception:
            logger.warning(
                "AGE_OVER constraint evaluation failed for value=%r, expected=%r",
                value,
                expected,
                exc_info=True,
            )
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
    "ietf_sd_jwt",
    "w3c_vcdm_v2_sd_jwt",
}


def _b64decode_unpadded(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded.encode())


def _load_marty_rs_binding() -> Any | None:
    """Load the released marty-rs package, retaining legacy import compatibility."""
    try:
        from marty_rs import _marty_rs as binding

        return binding
    except Exception:
        pass

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
    if normalized in {"w3c-vcdm-di", "w3c-vcdm-v2-di", "data-integrity"}:
        return "W3C_VCDM_V2_DI"
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
    if normalized.replace("_", "-") in {
        "w3c-vcdm-di",
        "w3c-vcdm-v2-di",
        "data-integrity",
        "json-ld",
        "ldp-vc",
    }:
        return "W3C_VCDM_V2_DI"
    if (
        normalized in _SD_JWT_FORMAT_ALIASES
        or normalized.replace("_", "-") in sd_jwt_aliases
    ):
        return "SD_JWT_VC"
    if normalized in {"openbadge-v3", "open-badge-v3", "openbadge3"}:
        return "OPENBADGE_V3"
    if normalized in {"openbadge-v2", "open-badge-v2", "openbadge2"}:
        return "OPENBADGE_V2"
    if normalized in {
        "w3c_vcdm_v2_jwt_vc",
        "w3c-vcdm-v2-jwt-vc",
        "jwt_vc",
        "jwt-vc",
        "vc_jwt",
        "vc-jwt",
        "jwt_vc_json",
        "jwt-vc-json",
    }:
        return "VC_JWT"
    try:
        return parse_credential_format(required_format).value
    except ValueError:
        return normalized.upper()


def _credential_format_satisfies_requirement(
    detected_format: str, required_format: str | None
) -> bool:
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


def _first_present(*values: Any) -> Any:
    """Return the first non-empty value without coercing verification evidence."""
    for value in values:
        if value is not None and value != "":
            return value
    return None


def _jwt_verification_evidence(
    header: dict[str, Any],
    payload: dict[str, Any],
    credential: dict[str, Any] | None = None,
    *,
    holder_binding_verified: bool = False,
) -> dict[str, Any]:
    """Project facts authenticated by a successful JWT verification."""
    credential = credential or {}
    algorithm = header.get("alg")
    return {
        "algorithm": algorithm if isinstance(algorithm, str) and algorithm else None,
        "issued_at": _first_present(
            payload.get("iat"),
            payload.get("nbf"),
            credential.get("validFrom"),
            credential.get("issuanceDate"),
        ),
        "expires_at": _first_present(
            payload.get("exp"),
            credential.get("validUntil"),
            credential.get("expirationDate"),
        ),
        # The Rust VCDM/SD-JWT verifier checks time validity. An omitted expiry
        # is therefore an indefinite credential, not an invented future date.
        "validity_checked": True,
        "is_expired": False,
        "holder_binding_verified": holder_binding_verified,
    }


class _ResolvedDidDocument(dict[str, Any]):
    """DID document plus service-observed resolution provenance."""

    resolution_provenance: dict[str, str]


def _did_resolution_provenance(
    document: dict[str, Any],
) -> dict[str, str] | None:
    provenance = getattr(document, "resolution_provenance", None)
    if not isinstance(provenance, dict):
        return None
    required = ("did", "source", "retrieved_at", "content_sha256")
    if any(
        not isinstance(provenance.get(field), str) or not provenance[field]
        for field in required
    ):
        return None
    if provenance["did"] != document.get("id") or provenance["source"] not in {
        "embedded:did:jwk",
        "configured_internal_resolver",
        "allowlisted_public_did_web",
    }:
        return None
    try:
        retrieved_at = datetime.fromisoformat(
            provenance["retrieved_at"].replace("Z", "+00:00")
        )
    except ValueError:
        return None
    digest = provenance["content_sha256"].lower()
    if retrieved_at.tzinfo is None or len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        return None
    provenance = {**provenance, "content_sha256": digest}
    return {field: provenance[field] for field in required}


async def _resolve_did_document(did: str) -> dict[str, Any]:
    result = await resolve_did_document(did)
    document = _ResolvedDidDocument(result.document)
    result_provenance = getattr(result, "provenance", None)
    if isinstance(result_provenance, dict):
        document.resolution_provenance = {
            "did": did,
            **{
                key: value
                for key, value in result_provenance.items()
                if key in {"source", "retrieved_at", "content_sha256"}
                and isinstance(value, str)
                and value
            },
        }
    return document


async def _await_verification_result(value: Any) -> dict[str, Any]:
    """Await production verifiers while preserving simple injected test adapters."""
    if hasattr(value, "__await__"):
        value = await value
    if not isinstance(value, dict):
        raise TypeError("Credential verifier returned a non-object result")
    return value


def _document_identifier(document: dict[str, Any], name: str) -> str | None:
    value = document.get(name)
    if isinstance(value, str) and value.startswith("did:"):
        return value
    if isinstance(value, dict):
        identifier = value.get("id")
        if isinstance(identifier, str) and identifier.startswith("did:"):
            return identifier
    return None


def _absolute_did_method_id(value: str, controller: str) -> str:
    return f"{controller}{value}" if value.startswith("#") else value


def _resolved_public_method(
    did_document: dict[str, Any],
    controller: str,
    method_id: str,
    relationship: str,
) -> dict[str, Any]:
    if did_document.get("id") != controller:
        raise RuntimeError(
            "DID resolution failed: resolved document id does not match the proof controller"
        )

    methods = (
        did_document.get("verificationMethod")
        if isinstance(did_document.get("verificationMethod"), list)
        else []
    )
    method_by_id: dict[str, dict[str, Any]] = {}
    for method in methods:
        if not isinstance(method, dict) or not isinstance(method.get("id"), str):
            continue
        absolute_id = _absolute_did_method_id(method["id"], controller)
        if absolute_id in method_by_id:
            raise RuntimeError(
                "DID resolution failed: duplicate verification method id"
            )
        method_by_id[absolute_id] = method

    relationship_entries = did_document.get(relationship)
    if not isinstance(relationship_entries, list):
        raise RuntimeError(
            f"DID resolution failed: verification method is not authorized for {relationship}"
        )
    authorized: dict[str, dict[str, Any] | None] = {}
    for entry in relationship_entries:
        if isinstance(entry, str):
            authorized[_absolute_did_method_id(entry, controller)] = None
        elif isinstance(entry, dict) and isinstance(entry.get("id"), str):
            absolute_id = _absolute_did_method_id(entry["id"], controller)
            authorized[absolute_id] = entry

    if method_id not in authorized:
        raise RuntimeError(
            f"DID resolution failed: verification method is not authorized for {relationship}"
        )
    method = authorized[method_id] or method_by_id.get(method_id)
    if not isinstance(method, dict):
        raise RuntimeError(
            "DID resolution failed: proof verification method was not found"
        )
    if _absolute_did_method_id(str(method.get("id", "")), controller) != method_id:
        raise RuntimeError(
            "DID resolution failed: proof verification method id does not match"
        )
    if method.get("controller") != controller:
        raise RuntimeError(
            "DID resolution failed: verification method controller does not match"
        )
    public_jwk = method.get("publicKeyJwk")
    if not isinstance(public_jwk, dict) or not public_jwk.get("kty"):
        raise RuntimeError(
            "DID resolution failed: verification method has no publicKeyJwk"
        )
    prohibited = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}.intersection(public_jwk)
    if prohibited:
        raise RuntimeError(
            "DID resolution failed: verification method contains private key material"
        )
    return {
        "id": method_id,
        "controller": controller,
        "public_jwk": dict(public_jwk),
    }


async def _resolved_data_integrity_methods(
    document: dict[str, Any],
    resolution_provenance: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    """Resolve non-did:key proof methods through the product DID resolver.

    The proof selects a DID URL, never a key or custody backend. This function
    resolves that DID, requires the exact relationship and controller, and
    passes only public verification material to the Rust verifier.
    """

    document_types = document.get("type")
    normalized_types = (
        document_types if isinstance(document_types, list) else [document_types]
    )
    targets: list[tuple[dict[str, Any], str, str | None]] = []
    if "VerifiablePresentation" in normalized_types:
        targets.append(
            (document, "authentication", _document_identifier(document, "holder"))
        )
        credentials = document.get("verifiableCredential")
        if isinstance(credentials, list):
            for credential in credentials:
                if isinstance(credential, dict):
                    targets.append(
                        (
                            credential,
                            "assertionMethod",
                            _document_identifier(credential, "issuer"),
                        )
                    )
    else:
        targets.append(
            (document, "assertionMethod", _document_identifier(document, "issuer"))
        )

    resolved: dict[str, dict[str, Any]] = {}
    for target, relationship, expected_controller in targets:
        proof_value = target.get("proof")
        proofs = proof_value if isinstance(proof_value, list) else [proof_value]
        for proof in proofs:
            if not isinstance(proof, dict) or proof.get("type") != "DataIntegrityProof":
                continue
            method_id = proof.get("verificationMethod")
            if not isinstance(method_id, str) or "#" not in method_id:
                continue
            controller, fragment = method_id.split("#", 1)
            if (
                not controller.startswith("did:")
                or not fragment
                or controller.startswith("did:key:")
            ):
                continue
            if expected_controller is not None and expected_controller != controller:
                raise RuntimeError(
                    "DID resolution failed: proof controller does not match document signer"
                )
            did_document = await _resolve_did_document(controller)
            provenance = _did_resolution_provenance(did_document)
            if (
                provenance is not None
                and resolution_provenance is not None
                and provenance not in resolution_provenance
            ):
                resolution_provenance.append(provenance)
            method = _resolved_public_method(
                did_document,
                controller,
                method_id,
                relationship,
            )
            existing = resolved.get(method_id)
            if existing is not None and existing != method:
                raise RuntimeError(
                    "DID resolution failed: conflicting verification method material"
                )
            resolved[method_id] = method
    return list(resolved.values())


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
    methods = (
        did_document.get("verificationMethod")
        if isinstance(did_document.get("verificationMethod"), list)
        else []
    )
    method_by_id: dict[str, dict[str, Any]] = {}
    for method in methods:
        if not isinstance(method, dict) or not isinstance(method.get("id"), str):
            continue
        method_id = _absolute_did_method_id(method["id"], issuer_did)
        if method_id in method_by_id:
            raise RuntimeError(
                f"DID resolution failed for {issuer_did}: duplicate verification method id"
            )
        method_by_id[method_id] = method

    assertion = (
        did_document.get("assertionMethod")
        if isinstance(did_document.get("assertionMethod"), list)
        else []
    )
    authorized_ids: set[str] = set()
    for entry in assertion:
        value = entry.get("id") if isinstance(entry, dict) else entry
        if not isinstance(value, str):
            continue
        method_id = _absolute_did_method_id(value, issuer_did)
        if method_id not in method_by_id:
            raise RuntimeError(
                f"DID resolution failed for {issuer_did}: assertion method was not found"
            )
        authorized_ids.add(method_id)

    if kid:
        selected_ids = {
            method_id
            for method_id in authorized_ids
            if _method_id_matches_kid(method_id, kid, issuer_did)
        }
        if len(selected_ids) != 1:
            raise RuntimeError(
                f"DID resolution failed for {issuer_did}: kid does not select exactly one assertion method"
            )
    else:
        if len(authorized_ids) != 1:
            raise RuntimeError(
                f"DID resolution failed for {issuer_did}: kid is required when assertion methods are ambiguous"
            )
        selected_ids = authorized_ids

    selected = method_by_id[next(iter(selected_ids))].get("publicKeyJwk")
    if isinstance(selected, dict) and selected.get("kty"):
        prohibited = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}.intersection(
            selected
        )
        if prohibited:
            raise RuntimeError(
                f"DID resolution failed for {issuer_did}: assertion method contains private key material"
            )
        return dict(selected)

    raise RuntimeError(
        f"DID resolution failed for {issuer_did}: assertion method has no public JWK"
    )


def _public_jwk_to_pem(public_jwk: dict[str, Any]) -> str:
    try:
        from jwcrypto import jwk

        sanitized = {
            key: value
            for key, value in public_jwk.items()
            if key not in {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
        }
        return (
            jwk.JWK(**sanitized)
            .export_to_pem(private_key=False, password=None)
            .decode()
        )
    except Exception as exc:
        raise RuntimeError(
            f"DID resolution failed: issuer public key could not be converted to PEM ({exc})"
        ) from exc


def _detect_credential_format(vp_token: str | dict[str, Any]) -> str:
    """
    Auto-detect credential format from VP token.

    Returns: "w3c-vc", "sd-jwt", "mdoc", "openbadge-v2", "openbadge-v3", or "unknown"
    """
    try:
        if isinstance(vp_token, dict):
            proof = vp_token.get("proof")
            proofs = proof if isinstance(proof, list) else [proof]
            if any(
                isinstance(item, dict) and item.get("type") == "DataIntegrityProof"
                for item in proofs
            ):
                # This is routing, not acceptance. A structured document with
                # a Data Integrity proof must reach the released VCDM engine,
                # which validates its context, types, proof configuration,
                # signature, and current validity. Requiring an exact context
                # shape here can misclassify an otherwise verifiable document
                # as "unknown" before cryptographic verification; relaxing
                # candidate detection does not make an invalid document pass.
                return "w3c-vcdm-di"
            return "unknown"

        stripped = vp_token.strip()
        if stripped.startswith("{"):
            credential, _document_store = _extract_open_badge_payload(
                stripped, "credential"
            )
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
                    or "https://purl.imsglobal.org/spec/ob/v3p0/context.json"
                    in contexts
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
        mdoc_candidate = stripped
        for prefix in ("mso_mdoc:", "mdoc:"):
            if mdoc_candidate.startswith(prefix):
                mdoc_candidate = mdoc_candidate[len(prefix) :]
                break
        if mdoc_candidate and "." not in mdoc_candidate and "~" not in mdoc_candidate:
            try:
                import base64 as _b64

                mdoc_bytes = _b64.urlsafe_b64decode(
                    mdoc_candidate + "=" * (-len(mdoc_candidate) % 4)
                )
                marty_rs = _load_marty_rs_binding()
                if marty_rs is None:
                    raise RuntimeError("marty-rs verification binding is unavailable")
                marty_rs.parse_device_response(mdoc_bytes)
                return "mdoc"
            except Exception:
                pass

    except Exception as e:
        logger.warning(f"Format detection error: {e}")

    return "unknown"


async def _verify_credential_by_format(
    vp_token: str | dict[str, Any],
    credential_format: str,
    nonce: str | None,
    audience: str | None,
    issuer_public_jwk: dict[str, Any] | None = None,
    verification_context: dict[str, Any] | None = None,
    mdoc_root_certs_pem: list[str] | None = None,
    mdoc_pinned_issuer_certs_pem: list[str] | None = None,
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
        if credential_format == "w3c-vcdm-di":
            if not isinstance(vp_token, dict):
                raise ValueError("VCDM Data Integrity input must be a JSON object")
            return await _verify_vcdm_data_integrity(vp_token, nonce, audience)
        if not isinstance(vp_token, str):
            raise ValueError(
                f"Credential format {credential_format} requires a string serialization"
            )
        if credential_format == "w3c-vc":
            return await _verify_w3c_vc(
                vp_token,
                nonce,
                audience,
                issuer_public_jwk,
            )
        elif credential_format == "sd-jwt":
            return await _verify_sd_jwt(
                vp_token, nonce, audience, issuer_public_jwk
            )
        elif credential_format == "mdoc":
            return _verify_mdoc(
                vp_token,
                nonce,
                audience,
                verification_context or {},
                mdoc_root_certs_pem or [],
                mdoc_pinned_issuer_certs_pem or [],
            )
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


def _vcdm_issuer_and_claims(document: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Extract policy inputs only after the Rust verifier accepts the document."""
    types = document.get("type")
    normalized_types = types if isinstance(types, list) else [types]
    credentials: list[dict[str, Any]] = []
    if "VerifiablePresentation" in normalized_types:
        embedded = document.get("verifiableCredential")
        if isinstance(embedded, list):
            credentials = [item for item in embedded if isinstance(item, dict)]
    else:
        credentials = [document]

    claims: dict[str, Any] = {}
    issuer = "unknown"
    for credential in credentials:
        subject = credential.get("credentialSubject")
        subjects = subject if isinstance(subject, list) else [subject]
        for item in subjects:
            if isinstance(item, dict):
                claims.update(item)
        if issuer == "unknown":
            issuer_value = credential.get("issuer")
            if isinstance(issuer_value, str):
                issuer = issuer_value
            elif isinstance(issuer_value, dict) and isinstance(
                issuer_value.get("id"), str
            ):
                issuer = issuer_value["id"]
    return issuer, claims


async def _verify_vcdm_data_integrity(
    document: dict[str, Any],
    nonce: str | None,
    audience: str | None,
) -> dict[str, Any]:
    """Verify a VCDM v2 Data Integrity VC/VP with the released Rust engine."""
    binding = _load_marty_rs_binding()
    if binding is None or not hasattr(binding, "verify_vcdm_data_integrity"):
        return {
            "verified": False,
            "claims": {},
            "issuer_did": "unknown",
            "format": "w3c-vcdm-di",
            "error": "marty-rs VCDM Data Integrity binding is not installed",
        }

    did_resolution_provenance: list[dict[str, str]] = []
    try:
        request: dict[str, Any] = {"document": document}
        resolved_methods = await _resolved_data_integrity_methods(
            document,
            did_resolution_provenance,
        )
        if resolved_methods:
            request["resolved_verification_methods"] = resolved_methods
        types = document.get("type")
        normalized_types = types if isinstance(types, list) else [types]
        if "VerifiablePresentation" in normalized_types:
            request["expected_challenge"] = nonce
            request["expected_domain"] = audience
        result = json.loads(binding.verify_vcdm_data_integrity(json.dumps(request)))
        if not isinstance(result, dict):
            raise ValueError("VCDM verifier returned a non-object result")
    except Exception as exc:
        logger.error("VCDM Data Integrity verification failed: %s", exc)
        return {
            "verified": False,
            "claims": {},
            "issuer_did": "unknown",
            "format": "w3c-vcdm-di",
            "error": "VCDM Data Integrity verification failed",
            "verification_evidence": {
                "did_resolution": did_resolution_provenance,
            },
        }

    verified = result.get("valid") is True
    issuer, claims = _vcdm_issuer_and_claims(document) if verified else ("unknown", {})
    types = document.get("type")
    normalized_types = types if isinstance(types, list) else [types]
    is_presentation = "VerifiablePresentation" in normalized_types
    embedded = document.get("verifiableCredential") if is_presentation else None
    embedded_credentials = (
        [item for item in embedded if isinstance(item, dict)]
        if isinstance(embedded, list)
        else []
    )
    evidence_document = (
        embedded_credentials[0]
        if len(embedded_credentials) == 1
        else document
        if not is_presentation
        else {}
    )
    proof = evidence_document.get("proof")
    proofs = proof if isinstance(proof, list) else [proof]
    proof_algorithm = next(
        (
            item.get("cryptosuite") or item.get("type")
            for item in proofs
            if isinstance(item, dict)
            and isinstance(item.get("cryptosuite") or item.get("type"), str)
        ),
        None,
    )
    errors = result.get("errors")
    safe_error = None
    if not verified:
        count = len(errors) if isinstance(errors, list) else 1
        safe_error = (
            f"VCDM Data Integrity verification rejected the document ({count} error(s))"
        )
    return {
        "verified": verified,
        "claims": claims,
        "issuer_did": issuer,
        "format": "w3c-vcdm-di",
        "error": safe_error,
        "verification_evidence": {
            "kind": result.get("kind"),
            "verified_proofs": result.get("verified_proofs", 0),
            "verified_credentials": result.get("verified_credentials", 0),
            "credential_count": len(embedded_credentials) if is_presentation else 1,
            "algorithm": result.get("algorithm") or proof_algorithm,
            "issued_at": _first_present(
                evidence_document.get("validFrom"),
                evidence_document.get("issuanceDate"),
            ),
            "expires_at": _first_present(
                evidence_document.get("validUntil"),
                evidence_document.get("expirationDate"),
            ),
            "validity_checked": verified,
            "is_expired": False if verified else None,
            "holder_binding_verified": bool(
                verified
                and is_presentation
                and (nonce is not None or audience is not None)
            ),
            "did_resolution": did_resolution_provenance,
        },
    }


async def _verify_w3c_vc(
    vp_token: str,
    _nonce: str | None,
    _audience: str | None,
    issuer_public_jwk: dict[str, Any] | None = None,
) -> dict:
    """Verify a standalone VCDM v2 VC-JWT against issuer-profile DID material.

    The protected JWT header and payload are decoded only to select public
    verification material. Trust and acceptance come exclusively from the
    released Rust verifier. Signing remains behind the issuer profile and this
    path never accepts a KMS key coordinate or private JWK.
    """
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

    did_resolution_provenance: dict[str, str] | None = None
    try:
        if not hasattr(_marty_rs, "verify_vcdm_jwt"):
            raise RuntimeError(
                "marty-rs VCDM JWT verification function is not available"
            )

        header, payload = _jwt_header_and_payload(vp_token)
        issuer = payload.get("iss")
        if not isinstance(issuer, str) or not issuer:
            raise ValueError("VC-JWT payload does not contain an issuer")
        kid = header.get("kid") if isinstance(header.get("kid"), str) else None

        public_jwk = issuer_public_jwk
        if public_jwk is None and not issuer.startswith("did:key:"):
            did_document = await _resolve_did_document(issuer)
            did_resolution_provenance = _did_resolution_provenance(did_document)
            public_jwk = _select_public_jwk_from_did_document(
                did_document,
                issuer,
                kid,
            )

        request: dict[str, Any] = {"token": vp_token}
        if public_jwk is not None:
            request["issuer_public_jwk"] = public_jwk
        result = json.loads(_marty_rs.verify_vcdm_jwt(json.dumps(request)))
        if not isinstance(result, dict):
            raise ValueError("VCDM JWT verifier returned a non-object result")
        is_valid = result.get("valid") is True
        verified_payload = result.get("claims") if is_valid else None
        verified_vc = (
            verified_payload.get("vc")
            if isinstance(verified_payload, dict)
            and isinstance(verified_payload.get("vc"), dict)
            else {}
        )
        credential_id = None
        if isinstance(verified_payload, dict):
            jwt_id = verified_payload.get("jti")
            vc_id = verified_vc.get("id")
            for candidate in (jwt_id, vc_id):
                if isinstance(candidate, str) and candidate.strip():
                    credential_id = candidate.strip()
                    break
        claims = verified_vc.get("credentialSubject", {})
        if not isinstance(claims, (dict, list)):
            claims = {}
        verified_issuer = result.get("issuer") if is_valid else None
        errors = result.get("errors")
        error_count = len(errors) if isinstance(errors, list) else 1
        if not is_valid:
            categories = _vcdm_jwt_error_categories(errors)
            logger.warning(
                "VCDM JWT verification error categories=%s error_count=%d",
                ",".join(categories),
                error_count,
            )
        verification_evidence = (
            _jwt_verification_evidence(header, verified_payload, verified_vc)
            if is_valid and isinstance(verified_payload, dict)
            else {}
        )
        if did_resolution_provenance is not None:
            verification_evidence["did_resolution"] = did_resolution_provenance

        return {
            "verified": is_valid,
            "claims": claims,
            "issuer_did": verified_issuer
            if isinstance(verified_issuer, str)
            else "unknown",
            # This identifier comes only from the Rust-verified JWT payload.
            # It lets the policy engine query the authoritative issuer-managed
            # status record without trusting the caller or exposing KMS routing.
            "credential_id": credential_id,
            "format": "w3c-vc",
            "verification_evidence": verification_evidence,
            "error": (
                None
                if is_valid
                else f"VCDM JWT verification rejected the credential ({error_count} error(s))"
            ),
        }
    except Exception as e:
        logger.error("W3C VC Rust verification failed: %s", e)
        return {
            "verified": False,
            "claims": {},
            "issuer_did": "unknown",
            "format": "w3c-vc",
            "error": str(e),
            "verification_evidence": (
                {"did_resolution": did_resolution_provenance}
                if did_resolution_provenance is not None
                else {}
            ),
        }


def _vcdm_jwt_error_categories(errors: Any) -> list[str]:
    """Reduce Rust verifier details to stable, non-sensitive diagnostics.

    The full verifier errors can contain issuer DIDs or verification-method
    identifiers. Those values must not be copied into public conformance logs.
    Categories are intentionally coarse: they identify the failed contract
    layer without exposing credential or key material.
    """
    messages = errors if isinstance(errors, list) else []
    categories: set[str] = set()
    rules = (
        ("private-key-material", ("private key", "private parameter")),
        ("signature", ("signature",)),
        (
            "public-key-resolution",
            ("public jwk", "public key", "did:key", "resolve", "verification method"),
        ),
        ("issuer-binding", ("issuer", "controller", "`kid`", "key id")),
        ("context", ("context",)),
        ("credential-type", ("credential type", "verifiablecredential")),
        ("credential-subject", ("credentialsubject", "`sub`", "subject")),
        (
            "validity",
            ("expired", "not yet valid", "numericdate", "validfrom", "validuntil"),
        ),
        (
            "serialization",
            ("compact jws", "payload", "json", "jwt verification request"),
        ),
    )
    for message in messages:
        normalized = str(message).lower()
        category = next(
            (
                name
                for name, needles in rules
                if any(needle in normalized for needle in needles)
            ),
            "verifier",
        )
        categories.add(category)
    return sorted(categories or {"verifier"})


async def _verify_sd_jwt(
    vp_token: str,
    nonce: str | None,
    audience: str | None,
    issuer_public_jwk: dict[str, Any] | None = None,
) -> dict:
    """
    Decode an SD-JWT VC and extract all Claims (base claims + disclosures).

    Format:  ``<JWT>~<disclosure_1>~<disclosure_2>~...[~<KB-JWT>]``

    Each disclosure is a base64url-encoded JSON array:
      ``[salt, claim_name, claim_value]``

    Note: This implementation does NOT cryptographically verify the JWT
    signature or validate the issuer trust chain.  That is the responsibility
    of the trust-profile service and the Rust marty-rs bridge.  In a
    production deployment, wrap this with
    ``marty_rs.verify_sd_jwt(vp_token, issuer_public_jwk, audience, nonce)``
    before trusting the extracted claims.
    """
    try:
        # Split SD-JWT into JWT part and disclosures
        # The last segment may be a key-binding JWT (non-empty, starts with 'e')
        segments = vp_token.split("~")
        jwt_part = segments[0]
        disclosure_parts = [
            s
            for s in segments[1:]
            if s and "." not in s  # KB-JWT would contain dots
        ]

        # Decode JWT payload
        header, payload = _jwt_header_and_payload(jwt_part)

        # Collect base (non-selective) claims — exclude SD-JWT internals
        _SD_INTERNAL = {"_sd", "_sd_alg", "cnf", "..."}
        claims: dict = {
            k: v
            for k, v in payload.items()
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

        if not isinstance(issuer, str) or not issuer:
            return {
                "verified": False,
                "claims": claims,
                "issuer_did": str(issuer or "unknown"),
                "subject": subject,
                "format": "sd-jwt",
                "error": "SD-JWT issuer is missing",
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

        did_resolution_provenance: dict[str, str] | None = None
        try:
            if issuer_public_jwk is not None:
                # A non-DID issuer is accepted only with a JWK explicitly
                # pinned by the selected trust profile. The normal DID path
                # remains the default for every other issuer.
                public_jwk = issuer_public_jwk
            elif issuer.startswith("did:"):
                did_document = await _resolve_did_document(issuer)
                did_resolution_provenance = _did_resolution_provenance(did_document)
                public_jwk = _select_public_jwk_from_did_document(
                    did_document, issuer, header.get("kid")
                )
            else:
                return {
                    "verified": False,
                    "claims": claims,
                    "issuer_did": issuer,
                    "subject": subject,
                    "format": "sd-jwt",
                    "error": "SD-JWT issuer is not a DID and has no pinned trust-profile JWK",
                }
            result_json = marty_rs.verify_sd_jwt(
                vp_token,
                json.dumps(public_jwk, separators=(",", ":"), sort_keys=True),
                audience,
                nonce,
            )
            rust_result = (
                json.loads(result_json)
                if isinstance(result_json, str) and result_json.strip()
                else {}
            )
            if isinstance(rust_result, dict) and rust_result.get("valid") is False:
                errors = rust_result.get("errors") or []
                error_message = (
                    "; ".join(str(error) for error in errors)
                    or rust_result.get("error")
                    or "SD-JWT verification failed"
                )
                return {
                    "verified": False,
                    "claims": claims,
                    "issuer_did": issuer,
                    "subject": subject,
                    "format": "sd-jwt",
                    "error": error_message,
                    "verification_evidence": (
                        {"did_resolution": did_resolution_provenance}
                        if did_resolution_provenance is not None
                        else {}
                    ),
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
                "verification_evidence": (
                    {"did_resolution": did_resolution_provenance}
                    if did_resolution_provenance is not None
                    else {}
                ),
            }

        kb_jwt_present = any(segment and "." in segment for segment in segments[1:])
        verification_evidence = _jwt_verification_evidence(
            header,
            payload,
            holder_binding_verified=bool(
                kb_jwt_present and (nonce is not None or audience is not None)
            ),
        )
        if did_resolution_provenance is not None:
            verification_evidence["did_resolution"] = did_resolution_provenance
        return {
            "verified": True,
            "claims": claims,
            "issuer_did": issuer,
            "subject": subject,
            "format": "sd-jwt",
            "verification_evidence": verification_evidence,
            "error": None,
        }

    except Exception as exc:
        logger.error(f"SD-JWT decode error: {exc}")
        return {"verified": False, "error": str(exc), "claims": {}}


def _classify_mdoc_verification_error(error: object) -> str:
    """Return a stable, non-sensitive category for Rust mdoc failures."""
    if not isinstance(error, str) or not error:
        return "none"

    normalized = error.casefold()
    classifications = (
        ("detached payload", "detached-issuer-auth"),
        ("could not parse mso", "mso-parse-failed"),
        ("unable to parse mdoc deviceresponse", "device-response-parse-failed"),
        ("unable to parse session transcript", "session-transcript-parse-failed"),
        ("deviceresponse status is not ok", "device-response-status-invalid"),
        ("deviceresponse contains no documents", "device-response-documents-missing"),
        ("unsupported deviceresponse version", "device-response-version-unsupported"),
        ("device key jwk is missing coordinates", "device-key-coordinates-missing"),
        ("unsupported device_key type", "device-key-type-unsupported"),
        ("currently unsupported format", "device-auth-method-unsupported"),
        ("failed verifying device signature", "device-signature-invalid"),
        ("error verifying device signature", "device-signature-processing-error"),
        ("malformed signature", "device-signature-malformed"),
        ("algorithm in protected headers", "device-signature-algorithm-mismatch"),
        ("cryptographic error", "device-key-invalid"),
        ("cbor", "device-auth-cbor-error"),
    )
    for marker, category in classifications:
        if marker in normalized:
            return category
    return "unclassified"


def _verify_mdoc(
    vp_token: str,
    nonce: str | None,
    audience: str | None,
    verification_context: dict[str, Any],
    trusted_root_certs_pem: list[str],
    pinned_issuer_certs_pem: list[str],
) -> dict:
    """Verify mDoc/ISO 18013-5 credential via Rust mDoc verification."""
    marty_rs = _load_marty_rs_binding()
    if marty_rs is None:
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
        encoded = vp_token.strip()
        for prefix in ("mso_mdoc:", "mdoc:"):
            if encoded.startswith(prefix):
                encoded = encoded[len(prefix) :]
                break
        padded = encoded + "=" * (-len(encoded) % 4)
        cbor_bytes = _b64.urlsafe_b64decode(padded)

        transcript_b64url = verification_context.get("mdoc_session_transcript_b64url")
        if not isinstance(transcript_b64url, str) or not transcript_b64url:
            raise ValueError("Verifier-owned mdoc session transcript is required")
        session_transcript_cbor = _b64.urlsafe_b64decode(
            transcript_b64url + "=" * (-len(transcript_b64url) % 4)
        )
        context_client_id = verification_context.get("oid4vp_client_id")
        if (
            audience
            and isinstance(context_client_id, str)
            and context_client_id
            and context_client_id != audience
        ):
            raise ValueError("mdoc verifier audience does not match request state")
        if not trusted_root_certs_pem and not pinned_issuer_certs_pem:
            raise ValueError("No trusted mdoc issuer certificates are configured")

        result = marty_rs.verify_mdoc_presentation(
            cbor_bytes,
            session_transcript_cbor,
            trusted_root_certs_pem,
            pinned_issuer_certs_pem,
        )
        logger.info(
            "mDoc verification binding transcript_sha256=%s "
            "device_response_sha256=%s "
            "issuer_signature_valid=%s issuer_trusted=%s "
            "device_authentication_valid=%s",
            hashlib.sha256(session_transcript_cbor).hexdigest(),
            hashlib.sha256(cbor_bytes).hexdigest(),
            bool(result.issuer_signature_valid),
            bool(result.issuer_trusted),
            bool(result.device_authentication_valid),
        )
        is_valid = bool(
            result.issuer_signature_valid
            and result.issuer_trusted
            and result.device_authentication_valid
        )
        error = result.error
        logger.info(
            "mDoc verification outcome device_auth_error_kind=%s",
            _classify_mdoc_verification_error(error),
        )
        claims: dict[str, Any] = {}
        if is_valid:
            extracted = marty_rs.verify_mdoc_cbor(cbor_bytes)
            if isinstance(extracted, dict):
                claims = extracted

        return {
            "verified": is_valid,
            "claims": claims,
            "issuer_did": "unknown",
            "format": "mdoc",
            "error": error,
            "document_types": list(result.document_types),
            "issuer_signature_valid": bool(result.issuer_signature_valid),
            "issuer_trusted": bool(result.issuer_trusted),
            "device_authentication_valid": bool(result.device_authentication_valid),
            "verification_evidence": {
                # The current binding proves device authentication but does not
                # expose MSO signing-algorithm or validity-window evidence.
                "algorithm": None,
                "issued_at": None,
                "expires_at": None,
                "validity_checked": False,
                "is_expired": None,
                "holder_binding_verified": bool(
                    is_valid and result.device_authentication_valid
                ),
                "credential_count": len(result.document_types),
            },
        }
    except Exception as e:
        logger.error("mDoc Rust verification failed: %s", e)
        return {
            "verified": False,
            "claims": {},
            "issuer_did": "unknown",
            "format": "mdoc",
            "error": str(e),
        }


def _b64url_json_decode(segment: str) -> dict[str, Any]:
    import base64 as _b64

    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(_b64.urlsafe_b64decode(padded.encode()).decode())


def _extract_open_badge_payload(
    vp_token: str, default_key: str
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Extract an Open Badge credential/assertion and offline document store."""
    token = vp_token.strip()
    document_store: dict[str, Any] = {}

    if token.startswith("{"):
        parsed = json.loads(token)
        if not isinstance(parsed, dict):
            return None, document_store
        document_store = (
            parsed.get("document_store") or parsed.get("documentStore") or {}
        )
        if not isinstance(document_store, dict):
            document_store = {}

        for key in (default_key, "credential", "assertion"):
            value = parsed.get(key)
            if isinstance(value, dict):
                return value, document_store

        vp = parsed.get("vp") if isinstance(parsed.get("vp"), dict) else parsed
        verifiable_credential = (
            vp.get("verifiableCredential") if isinstance(vp, dict) else None
        )
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


def _run_open_badge_verify(
    version: str, credential: dict[str, Any], document_store: dict[str, Any]
) -> dict[str, Any]:
    try:
        from marty_verification_py import open_badge_ob2_verify, open_badge_ob3_verify
    except ImportError as exc:
        raise RuntimeError(
            "marty_verification_py Open Badge bindings are not installed"
        ) from exc

    if version == "v2":
        request = {"assertion": credential, "document_store": document_store}
        result_json = open_badge_ob2_verify(json.dumps(request))
    else:
        request = {"credential": credential, "document_store": document_store}
        result_json = open_badge_ob3_verify(json.dumps(request))
    return json.loads(result_json)


def _claims_from_open_badge_result(
    result: dict[str, Any], credential: dict[str, Any]
) -> dict[str, Any]:
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


def _derive_revocation_state(
    verification_result: dict[str, Any],
) -> tuple[bool | None, bool | None]:
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


def _normalize_issuer_url(value: str | None) -> str | None:
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None
    normalized = parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=parsed.netloc.lower(),
        query="",
        fragment="",
    )
    return normalized.geturl().rstrip("/")


def _issuer_domain(value: str | None) -> str | None:
    if not value:
        return None
    raw = value.strip()
    if not raw:
        return None

    if raw.lower().startswith("did:web:"):
        remainder = raw[len("did:web:") :]
        host = remainder.split(":", 1)[0].strip().lower()
        return host or None

    normalized_url = _normalize_issuer_url(raw)
    if normalized_url:
        parsed = urlparse(normalized_url)
        return parsed.hostname.lower() if parsed.hostname else None

    candidate = raw.rstrip("/").lower()
    if (
        candidate
        and "://" not in candidate
        and "/" not in candidate
        and ":" not in candidate
        and " " not in candidate
        and "." in candidate
    ):
        return candidate
    return None


def _issuer_identifier_candidates(value: str | None) -> set[str]:
    if not value:
        return set()
    raw = value.strip()
    if not raw or raw == "unknown":
        return set()

    candidates = {raw}
    if raw.endswith("/") and len(raw) > 1:
        candidates.add(raw.rstrip("/"))

    normalized_url = _normalize_issuer_url(raw)
    if normalized_url:
        candidates.add(normalized_url)

    domain = _issuer_domain(raw)
    if domain:
        candidates.add(domain)

    return candidates


def _matches_configured_issuer_identifiers(
    issuer_candidates: set[str],
    configured_values: list[str],
) -> bool:
    if not issuer_candidates or not configured_values:
        return False

    configured_candidates: set[str] = set()
    for value in configured_values:
        configured_candidates.update(_issuer_identifier_candidates(value))
    return not issuer_candidates.isdisjoint(configured_candidates)


def _sd_jwt_unverified_issuer(vp_token: str) -> str | None:
    """Read an SD-JWT issuer solely to select an already-pinned key.

    This does not establish trust: the returned value is matched exactly to a
    trust-profile override before signature verification runs.
    """
    try:
        _header, payload = _jwt_header_and_payload(vp_token.split("~", 1)[0])
    except Exception:
        return None
    issuer = payload.get("iss")
    return issuer if isinstance(issuer, str) and issuer else None


def _pinned_issuer_jwk(
    trust_profile_data: dict[str, Any] | None, issuer: str | None
) -> dict[str, Any] | None:
    if not trust_profile_data or not issuer:
        return None
    overrides = trust_profile_data.get("system_issuer_overrides") or {}
    if not isinstance(overrides, dict):
        return None
    issuer_candidates = _issuer_identifier_candidates(issuer)
    for identifier, override in overrides.items():
        if not isinstance(identifier, str) or not isinstance(override, dict):
            continue
        if issuer_candidates.isdisjoint(_issuer_identifier_candidates(identifier)):
            continue
        public_jwk = override.get("public_jwk")
        if isinstance(public_jwk, dict) and public_jwk.get("kty"):
            return public_jwk
    return None


def _mdoc_trust_certificates_pem(
    trust_profile_data: dict[str, Any] | None,
) -> tuple[list[str], list[str]]:
    """Separate mdoc PKIX roots from explicitly pinned issuer certificates."""
    if not trust_profile_data:
        return [], []
    roots: list[str] = []
    pinned_issuers: list[str] = []
    for source in trust_profile_data.get("trust_sources") or []:
        if not isinstance(source, dict) or source.get("enabled") is False:
            continue
        source_type = str(source.get("source_type") or "").upper()
        if source_type == "ROOT_CA":
            target = roots
        elif source_type == "PINNED_ISSUER":
            target = pinned_issuers
        else:
            continue
        candidates = [source.get("certificate_pem")]
        pinned = source.get("pinned_certificates")
        if isinstance(pinned, list):
            candidates.extend(pinned)
        for candidate in candidates:
            if (
                isinstance(candidate, str)
                and "-----BEGIN CERTIFICATE-----" in candidate
                and candidate not in target
            ):
                target.append(candidate)
    return roots, pinned_issuers


def _trust_source_issuer_candidates(source: dict[str, Any]) -> set[str]:
    candidates: set[str] = set()

    issuer_did = source.get("issuer_did")
    if isinstance(issuer_did, str):
        candidates.update(_issuer_identifier_candidates(issuer_did))

    source_type = str(source.get("source_type") or "").upper()
    source_url = source.get("url")
    if source_type == "PINNED_ISSUER" and isinstance(source_url, str):
        candidates.update(_issuer_identifier_candidates(source_url))

    return candidates


def _trust_decision_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _verification_datetime(value: object) -> datetime | None:
    """Parse verifier-authenticated NumericDate or ISO-8601 evidence."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    return _trust_decision_datetime(value)


def _credential_age_seconds(
    verification_evidence: dict[str, Any],
    *,
    now: datetime | None = None,
) -> int | None:
    issued_at = _verification_datetime(verification_evidence.get("issued_at"))
    if issued_at is None:
        return None
    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    age = int((current_time - issued_at).total_seconds())
    return age if age >= 0 else None


def _normalized_issuer_policy_evidence(
    trust_profile_data: dict[str, Any] | None,
    issuer_did: str,
) -> dict[str, Any] | None:
    """Return Cedar facts only from one exact normalized issuer relationship."""
    if not trust_profile_data:
        return None
    relationships = trust_profile_data.get("issuer_relationships")
    if not isinstance(relationships, list):
        return None
    matched = [
        relationship
        for relationship in relationships
        if isinstance(relationship, dict)
        and isinstance(relationship.get("issuer_id"), str)
        and _normalized_relationship_issuer_id(relationship["issuer_id"])
        == _normalized_relationship_issuer_id(issuer_did)
    ]
    if len(matched) != 1:
        return None
    relationship = matched[0]
    trust_level = relationship.get("trust_level")
    if (
        isinstance(trust_level, bool)
        or not isinstance(trust_level, int)
        or not 0 <= trust_level <= 100
    ):
        return None
    compliance_status = relationship.get("compliance_status")
    return {
        "issuer_trust_level": trust_level,
        "compliance_status": (
            compliance_status.upper()
            if isinstance(compliance_status, str) and compliance_status
            else None
        ),
    }


def _issuer_constraints_require_relationship(
    constraints: IssuerConstraints | None,
) -> bool:
    return bool(
        constraints
        and (
            constraints.min_trust_level is not None
            or constraints.required_compliance_statuses
            or constraints.required_accreditations
        )
    )


def _normalized_relationship_issuer_id(value: str) -> str:
    """Normalize a registry identifier without collapsing distinct DID paths."""
    raw = value.strip()
    if raw.lower().startswith("did:"):
        return raw
    return _normalize_issuer_url(raw) or raw


def _evaluate_normalized_issuer_relationship(
    *,
    issuer_did: str,
    relationships: list[object],
    constraints: IssuerConstraints | None,
    now: datetime | None = None,
) -> tuple[bool, str | None]:
    """Evaluate exactly one normalized TrustProfile-to-IssuerEntity link."""
    matched: list[dict[str, Any]] = []
    for relationship in relationships:
        if not isinstance(relationship, dict):
            return False, "Trust Profile contains invalid issuer relationship data"
        configured_issuer = relationship.get("issuer_id")
        if not isinstance(configured_issuer, str) or not configured_issuer.strip():
            return False, "Trust Profile contains invalid issuer relationship data"
        if _normalized_relationship_issuer_id(
            configured_issuer
        ) == _normalized_relationship_issuer_id(issuer_did):
            matched.append(relationship)

    if not matched:
        return False, f"Issuer {issuer_did} has no trusted issuer relationship"
    if len(matched) != 1:
        return False, f"Issuer {issuer_did} has ambiguous issuer relationships"

    relationship = matched[0]
    relationship_status = str(relationship.get("relationship_status") or "").upper()
    if relationship_status == "DENIED":
        return False, f"Issuer {issuer_did} is explicitly denied by Trust Profile"
    if relationship_status != "TRUSTED":
        return False, f"Issuer {issuer_did} relationship is not trusted"

    compliance_status = str(relationship.get("compliance_status") or "").upper()
    if compliance_status in {"SUSPENDED", "REVOKED"}:
        return False, f"Issuer {issuer_did} is {compliance_status.lower()}"
    if compliance_status not in {"ACCREDITED", "COMPLIANT"}:
        return False, f"Issuer {issuer_did} has invalid compliance status"
    if relationship.get("revoked_at"):
        return False, f"Issuer {issuer_did} is revoked"

    current_time = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    valid_from = _trust_decision_datetime(relationship.get("valid_from"))
    if valid_from is None:
        return False, f"Issuer {issuer_did} has invalid validity metadata"
    if current_time < valid_from:
        return False, f"Issuer {issuer_did} is not yet valid"
    valid_until_value = relationship.get("valid_until")
    if valid_until_value is not None:
        valid_until = _trust_decision_datetime(valid_until_value)
        if valid_until is None:
            return False, f"Issuer {issuer_did} has invalid validity metadata"
        if current_time >= valid_until:
            return False, f"Issuer {issuer_did} relationship is expired"

    trust_level = relationship.get("trust_level")
    if isinstance(trust_level, bool) or not isinstance(trust_level, int):
        return False, f"Issuer {issuer_did} has invalid trust level"
    if trust_level < 0 or trust_level > 100:
        return False, f"Issuer {issuer_did} has invalid trust level"

    if constraints:
        if (
            constraints.min_trust_level is not None
            and trust_level < constraints.min_trust_level
        ):
            return False, f"Issuer {issuer_did} does not meet minimum trust level"

        required_statuses = {
            str(status).upper() for status in constraints.required_compliance_statuses
        }
        if required_statuses and compliance_status not in required_statuses:
            return False, f"Issuer {issuer_did} does not meet compliance requirements"

        required_accreditations = {
            str(accreditation).strip().casefold()
            for accreditation in constraints.required_accreditations
            if str(accreditation).strip()
        }
        raw_accreditations = relationship.get("accreditations")
        if not isinstance(raw_accreditations, list) or any(
            not isinstance(accreditation, str) or not accreditation.strip()
            for accreditation in raw_accreditations
        ):
            return False, f"Issuer {issuer_did} has invalid accreditation evidence"
        held_accreditations = {
            accreditation.strip().casefold() for accreditation in raw_accreditations
        }
        if not required_accreditations.issubset(held_accreditations):
            return (
                False,
                f"Issuer {issuer_did} does not meet accreditation requirements",
            )

    return True, None


def _evaluate_issuer_trust(
    *,
    trust_profile_data: dict[str, Any],
    issuer_did: str,
    constraints: IssuerConstraints | None,
) -> tuple[bool, str | None]:
    """Evaluate normalized issuer relationships with legacy-source fallback."""
    if str(trust_profile_data.get("status") or "").lower() != "active":
        return False, "Trust Profile is not active"

    issuer_identifiers = _issuer_identifier_candidates(issuer_did)
    denied_issuers = trust_profile_data.get("denied_issuers") or []
    if denied_issuers and _matches_configured_issuer_identifiers(
        issuer_identifiers, denied_issuers
    ):
        return False, f"Issuer {issuer_did} is explicitly denied by Trust Profile"

    relationship_value = trust_profile_data.get("issuer_relationships")
    if relationship_value is not None and not isinstance(relationship_value, list):
        return False, "Trust Profile contains invalid issuer relationship data"
    relationships = relationship_value or []
    if relationships:
        return _evaluate_normalized_issuer_relationship(
            issuer_did=issuer_did,
            relationships=relationships,
            constraints=constraints,
        )
    if _issuer_constraints_require_relationship(constraints):
        return False, f"Issuer {issuer_did} has no trust-level relationship"

    allowed_issuers = trust_profile_data.get("allowed_issuers") or []
    if allowed_issuers:
        if _matches_configured_issuer_identifiers(issuer_identifiers, allowed_issuers):
            return True, None
        return False, f"Issuer {issuer_did} is not in Trust Profile allowed_issuers"

    trust_sources = trust_profile_data.get("trust_sources") or []
    source_identifiers: set[str] = set()
    for source in trust_sources:
        if isinstance(source, dict):
            source_identifiers.update(_trust_source_issuer_candidates(source))
    if source_identifiers and issuer_identifiers.isdisjoint(source_identifiers):
        return (
            False,
            f"Issuer {issuer_did} does not match any trust source issuer identifier",
        )

    return True, None


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
    error_message = (
        None
        if result.get("valid")
        else "; ".join(str(e) for e in errors)
        or result.get("error")
        or "Open Badge verification failed"
    )
    revocation_checked, not_revoked = _derive_revocation_state(result)
    is_revoked = (not_revoked is False) if not_revoked is not None else None
    algorithm: str | None = None
    stripped_token = vp_token.strip()
    if stripped_token.count(".") == 2 and not stripped_token.startswith("{"):
        try:
            jwt_header, _jwt_payload = _jwt_header_and_payload(stripped_token)
            header_algorithm = jwt_header.get("alg")
            if isinstance(header_algorithm, str) and header_algorithm:
                algorithm = header_algorithm
        except Exception:
            algorithm = None
    if algorithm is None:
        proof = credential.get("proof")
        proofs = proof if isinstance(proof, list) else [proof]
        algorithm = next(
            (
                item.get("cryptosuite") or item.get("type")
                for item in proofs
                if isinstance(item, dict)
                and isinstance(item.get("cryptosuite") or item.get("type"), str)
            ),
            None,
        )
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
        "verification_evidence": {
            "algorithm": algorithm,
            "issued_at": _first_present(
                credential.get("validFrom"),
                credential.get("issuanceDate"),
                credential.get("issuedOn"),
            ),
            "expires_at": _first_present(
                credential.get("validUntil"),
                credential.get("expirationDate"),
                credential.get("expires"),
            ),
            "validity_checked": bool(result.get("valid")),
            "is_expired": False if result.get("valid") else None,
            "holder_binding_verified": False,
            "credential_count": 1,
        },
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


def get_repo() -> InMemoryPresentationPolicyRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


def get_current_user_id(x_user_id: Annotated[str, Header()]) -> str:
    """Extract user ID from X-User-Id header (injected by gateway)."""
    return x_user_id


def _trust_profile_service_url() -> str:
    """Return the internal Trust Profile service base URL."""
    return os.environ.get("TRUST_PROFILE_SERVICE_URL", "http://trust-profile:8004")


def _trust_profile_lookup_url(profile_id: str) -> str:
    """Return the service-to-service Trust Profile lookup URL."""
    return f"{_trust_profile_service_url()}/internal/v1/trust-profiles/{profile_id}"


def _load_policy_trust_profile(
    profile_id: str,
    policy_organization_id: Any,
) -> dict[str, Any]:
    """Load one Trust Profile and enforce the saved policy tenant boundary.

    This validation belongs at the evaluator decision boundary because the
    evaluator is called by both REST and internal gRPC flows. Gateway-only
    validation is insufficient for service-to-service callers.
    """
    if (
        not isinstance(policy_organization_id, str)
        or not policy_organization_id.strip()
    ):
        raise HTTPException(
            status_code=503,
            detail="Presentation Policy has no unambiguous organization_id",
        )
    expected_organization_id = policy_organization_id.strip()

    # Trust relationship, lifecycle, and revocation changes are authorization
    # decisions. Read the current internal view for every evaluation rather
    # than accepting a stale process-local allow decision.
    import httpx as _httpx

    try:
        response = _httpx.get(_trust_profile_lookup_url(profile_id), timeout=5.0)
    except Exception as exc:
        logger.warning(
            "Could not load Trust Profile %s for tenant validation",
            profile_id,
            exc_info=True,
        )
        raise HTTPException(
            status_code=503,
            detail=f"Trust Profile {profile_id} could not be loaded",
        ) from exc
    if response.status_code == 404:
        raise HTTPException(
            status_code=422,
            detail=f"Trust Profile {profile_id} does not exist",
        )
    if response.status_code != 200:
        raise HTTPException(
            status_code=503,
            detail=f"Trust Profile {profile_id} could not be loaded",
        )
    try:
        trust_profile_data = response.json()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Trust Profile {profile_id} returned invalid data",
        ) from exc

    if not isinstance(trust_profile_data, dict):
        raise HTTPException(
            status_code=503,
            detail=f"Trust Profile {profile_id} returned invalid data",
        )
    profile_organization_id = trust_profile_data.get("organization_id")
    if (
        not isinstance(profile_organization_id, str)
        or not profile_organization_id.strip()
    ):
        raise HTTPException(
            status_code=503,
            detail=f"Trust Profile {profile_id} has no unambiguous organization_id",
        )
    if profile_organization_id.strip() != expected_organization_id:
        raise HTTPException(
            status_code=422,
            detail="Trust Profile and Presentation Policy must belong to the same organization",
        )

    return trust_profile_data


def _issuance_service_url() -> str:
    """Return the internal Issuance service base URL."""
    return os.environ.get("ISSUANCE_SERVICE_URL", "http://issuance:8005")


def _credential_status_lookup_url(credential_id: str) -> str:
    """Return the configured managed-issuer credential-status lookup URL.

    MIP freshness policies require revocation evidence but do not mandate a
    single transport. The default endpoint is Marty's issuance service, while
    MIP_CREDENTIAL_STATUS_URL_TEMPLATE lets deployments point the verifier at a
    different issuer-managed status resolver. The template may contain
    ``{credential_id}``; values are URL-escaped before interpolation.
    """
    escaped_id = quote(credential_id, safe="")
    template = os.environ.get("MIP_CREDENTIAL_STATUS_URL_TEMPLATE", "").strip()
    if template:
        return template.replace("{credential_id}", escaped_id)
    return f"{_issuance_service_url()}/v1/issuance/credentials/{escaped_id}/status"


def _split_configured_values(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _managed_issuer_identifier_candidates() -> set[str]:
    """Return issuer identifiers allowed to use issuer-managed status lookup.

    This is the MIP abstraction boundary: the verifier may use an issuer-state
    status endpoint only for issuers explicitly managed by this deployment (or
    derived from its self-host public issuer identity). It is intentionally not
    tied to a credential format or the OpenBadgeLogin policy.
    """
    candidates = {
        value
        for env_name in (
            "MIP_MANAGED_ISSUER_IDENTIFIERS",
            "MIP_MANAGED_ISSUER_DIDS",
            # Backwards-compatible deployment env names.
            "MARTY_ISSUER_DID",
            "CREDENTIAL_LOGIN_ISSUER_DID",
            "ISSUER_DID",
        )
        for value in _split_configured_values(os.environ.get(env_name))
    }
    org_slug = os.environ.get("MARTY_ORG_SLUG", "marty").strip() or "marty"
    public_domain = os.environ.get("PUBLIC_DOMAIN", "").strip()
    if public_domain:
        candidates.add(f"did:web:{public_domain}:orgs:{org_slug}")

    for env_name in ("PUBLIC_BASE_URL", "ISSUER_BASE_URL", "PUBLIC_API_URL"):
        base_url = os.environ.get(env_name, "").strip()
        if not base_url:
            continue
        parsed = urlparse(base_url)
        host = (parsed.hostname or parsed.netloc or parsed.path).strip()
        if host and host not in {"localhost", "127.0.0.1", "gateway", "marty-gateway"}:
            candidates.add(f"did:web:{host}:orgs:{org_slug}")

    return candidates


def _is_managed_issuer_identifier(issuer_did: str | None) -> bool:
    if not issuer_did:
        return False
    configured = list(_managed_issuer_identifier_candidates())
    return _matches_configured_issuer_identifiers(
        _issuer_identifier_candidates(issuer_did),
        configured,
    )


def _credential_status_identifier_candidates(
    claims: dict[str, Any],
    verification_result: dict[str, Any],
) -> list[str]:
    """Return stable credential identifiers usable with issuer-managed status.

    MIP credentials may expose IDs through different format-specific names.
    This keeps the status resolver format-neutral while avoiding claim values
    that are not intended to identify the issued credential.
    """
    candidates: list[str] = []

    def _append(value: Any) -> None:
        if isinstance(value, str):
            normalized = value.strip()
            if normalized and normalized not in candidates:
                candidates.append(normalized)

    for payload in (claims, verification_result):
        for key in (
            "credential_id",
            "credentialId",
            "credentialID",
            "jti",
        ):
            _append(payload.get(key))

        vc = payload.get("vc")
        if isinstance(vc, dict):
            _append(vc.get("id"))

        credential = payload.get("credential")
        if isinstance(credential, dict):
            _append(credential.get("id"))

    return candidates


def _status_indicates_not_revoked(status: str) -> bool:
    return status in {"active", "valid", "current", "good"}


def _get_issued_credential_status(credential_id: str) -> dict[str, Any] | None:
    """Fetch current issuer-managed status for a credential id."""
    import httpx as _httpx

    response = _httpx.get(
        _credential_status_lookup_url(credential_id),
        headers={"Accept": "application/json"},
        timeout=5.0,
    )
    if response.status_code == 404:
        return None
    response.raise_for_status()
    payload = response.json()
    return payload if isinstance(payload, dict) else None


def _lookup_managed_issuer_credential_status_revocation_state(
    *,
    issuer_did: str | None,
    credential_ids: list[str],
) -> tuple[bool | None, bool | None, str | None]:
    """Use issuer-managed status as revocation evidence when configured.

    Some MIP credential formats carry a stable credential identifier but no
    embedded StatusList/OCSP/CRL evidence in the presentation. For issuers
    managed by this deployment, an authoritative issuer-status endpoint is a
    valid revocation source. This resolver is deliberately format-agnostic:
    caller supplies candidate credential IDs extracted from the verified
    presentation, and this function tries the configured status endpoint.
    """
    if not credential_ids:
        return None, None, None

    configured_managed_issuer = _is_managed_issuer_identifier(issuer_did)
    issuer_candidates = _issuer_identifier_candidates(issuer_did)

    for credential_id in credential_ids:
        try:
            status_payload = _get_issued_credential_status(credential_id)
        except Exception as exc:
            logger.warning(
                "Credential status lookup failed for managed issuer %s credential=%s: %s",
                issuer_did,
                credential_id[:8] + "..." if len(credential_id) > 8 else credential_id,
                exc,
            )
            continue

        if not status_payload:
            logger.debug(
                "Credential status lookup found no managed issuer record for %s credential=%s",
                issuer_did,
                credential_id[:8] + "..." if len(credential_id) > 8 else credential_id,
            )
            continue

        status_issuer = status_payload.get("issuer_did")
        if status_issuer:
            if issuer_candidates.isdisjoint(
                _issuer_identifier_candidates(str(status_issuer))
            ):
                logger.warning(
                    "Credential status issuer mismatch for credential=%s presented=%s recorded=%s",
                    credential_id[:8] + "..."
                    if len(credential_id) > 8
                    else credential_id,
                    issuer_did,
                    status_issuer,
                )
                continue
        elif not configured_managed_issuer:
            logger.warning(
                "Credential status record omitted issuer identity for unconfigured issuer %s",
                issuer_did,
            )
            continue

        status = str(status_payload.get("status") or "").strip().lower()
        if not status:
            return True, False, "unknown"
        return True, _status_indicates_not_revoked(status), status

    logger.warning(
        "Credential status lookup found no managed issuer record for %s across %d candidate IDs",
        issuer_did,
        len(credential_ids),
    )
    return None, None, None


def _build_credential_requirement(
    model: CredentialRequirementModel,
) -> CredentialRequirement:
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
            rc.constraints.append(
                ClaimConstraint(
                    claim_name=constraint.claim_name,
                    constraint_type=ConstraintType(constraint.constraint_type),
                    value=constraint.value,
                    description=constraint.description,
                )
            )
        req.requested_claims.append(rc)

    return req


def _build_requested_claim_from_protocol(
    model: ProtocolRequiredClaimModel,
) -> RequestedClaim:
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


def _build_protocol_requirement(
    request: CreatePresentationPolicyRequest,
) -> CredentialRequirement | None:
    if not request.required_claims:
        return None

    requirement = CredentialRequirement(
        credential_template_id=request.accepted_credential_types[0]
        if request.accepted_credential_types
        else "protocol-inline",
        display_name=request.name,
        description=request.description,
        trust_profile_id=request.trust_profile_id,
        max_age_seconds=(request.freshness or {}).get("max_age_seconds")
        if request.freshness
        else None,
    )
    requirement.requested_claims.extend(
        _build_requested_claim_from_protocol(claim) for claim in request.required_claims
    )
    return requirement


@router.post(
    "", response_model=PresentationPolicyResponse, response_model_exclude_none=True
)
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

    if (
        not request.credential_requirements
        and not request.required_claims
        and not request.alternative_requirements
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "At least one required claim, credential requirement, or "
                "alternative requirement is required"
            ),
        )
    # MIP §7.2 — each credential_requirement MUST have ≥1 requested_claims
    for i, cr in enumerate(request.credential_requirements):
        if not cr.requested_claims:
            raise HTTPException(
                status_code=422,
                detail=f"credential_requirements[{i}] must have at least one requested_claims entry",
            )
    if (
        request.credential_ranking_strategy == "CUSTOM"
        and not request.credential_ranking_weights
    ):
        raise HTTPException(
            status_code=400,
            detail="credential_ranking_weights are required when credential_ranking_strategy is CUSTOM",
        )

    policy = PresentationPolicy(
        organization_id=request.organization_id,
        name=request.name,
        description=request.description,
        purpose=request.purpose,
        accepted_credential_types=request.accepted_credential_types,
        trust_profile_id=request.trust_profile_id,
        holder_binding=normalize_holder_binding(request.holder_binding),
        freshness=FreshnessPolicy(**request.freshness) if request.freshness else None,
        issuer_constraints=IssuerConstraints(**request.issuer_constraints)
        if request.issuer_constraints
        else None,
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
            purpose_description=request.display_metadata.purpose_description
            or request.purpose,
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


@router.get(
    "",
    response_model=list[PresentationPolicyResponse],
    response_model_exclude_none=True,
)
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
    return [_policy_to_response(p) for p in policies[offset : offset + limit]]


@router.get(
    "/{policy_id}",
    response_model=PresentationPolicyResponse,
    response_model_exclude_none=True,
)
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
        membership = await app.state.org_client.get_membership(
            user_id, policy.organization_id
        )
        ensure_membership_permission(membership, "presentation-policy", "view")
    return _policy_to_response(policy)


@router.patch(
    "/{policy_id}",
    response_model=PresentationPolicyResponse,
    response_model_exclude_none=True,
)
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
    membership = await app.state.org_client.get_membership(
        user_id, policy.organization_id
    )
    ensure_membership_permission(membership, "presentation-policy", "edit")

    if policy.status != PolicyStatus.DRAFT:
        raise HTTPException(
            status_code=400,
            detail="Only draft policies can be modified. Create a new version instead.",
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
        policy.holder_binding = normalize_holder_binding(request.holder_binding)
    if request.freshness is not None:
        policy.freshness = FreshnessPolicy(**request.freshness)
    if request.issuer_constraints is not None:
        policy.issuer_constraints = IssuerConstraints(**request.issuer_constraints)
    if request.credential_ranking_strategy is not None:
        if (
            request.credential_ranking_strategy == "CUSTOM"
            and not request.credential_ranking_weights
        ):
            raise HTTPException(
                status_code=400,
                detail="credential_ranking_weights are required when credential_ranking_strategy is CUSTOM",
            )
        policy.credential_ranking_strategy = request.credential_ranking_strategy
    if request.credential_ranking_weights is not None:
        policy.credential_ranking_weights = request.credential_ranking_weights
    if request.display_metadata is not None:
        policy.display_metadata = DisplayMetadata(
            title=request.display_metadata.title,
            description=request.display_metadata.description,
            purpose=RequestPurpose(request.display_metadata.purpose),
            purpose_description=request.display_metadata.purpose_description
            or policy.purpose,
            verifier_name=request.display_metadata.verifier_name,
            verifier_logo_url=request.display_metadata.verifier_logo_url,
            privacy_policy_url=request.display_metadata.privacy_policy_url,
            terms_of_service_url=request.display_metadata.terms_of_service_url,
        )
    if request.credential_requirements is not None:
        policy.credential_requirements = [
            _build_credential_requirement(req)
            for req in request.credential_requirements
        ]
    if request.required_claims is not None:
        policy.required_claims = [
            _build_requested_claim_from_protocol(claim)
            for claim in request.required_claims
        ]
        if request.required_claims and not policy.credential_requirements:
            synthetic_requirement = CredentialRequirement(
                credential_template_id=policy.effective_accepted_credential_types[0]
                if policy.effective_accepted_credential_types
                else "protocol-inline",
                display_name=policy.name,
                description=policy.description,
                trust_profile_id=policy.trust_profile_id,
                max_age_seconds=policy.freshness.max_age_seconds
                if policy.freshness
                else None,
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
                alt.credential_requirements.append(
                    _build_credential_requirement(req_model)
                )
            policy.alternative_requirements.append(alt)

    policy.updated_at = datetime.now(timezone.utc)
    await repo.save(policy)
    return _policy_to_response(policy)


@router.post(
    "/{policy_id}/activate",
    response_model=PresentationPolicyResponse,
    response_model_exclude_none=True,
)
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
    membership = await app.state.org_client.get_membership(
        user_id, policy.organization_id
    )
    ensure_membership_permission(membership, "presentation-policy", "activate")

    if not policy.credential_requirements and not policy.alternative_requirements:
        raise HTTPException(
            status_code=400,
            detail="Policy must have at least one credential requirement",
        )

    policy.activate()
    await repo.save(policy)
    return _policy_to_response(policy)


@router.post(
    "/{policy_id}/suspend",
    response_model=PresentationPolicyResponse,
    response_model_exclude_none=True,
)
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
    membership = await app.state.org_client.get_membership(
        user_id, policy.organization_id
    )
    ensure_membership_permission(membership, "presentation-policy", "suspend")
    policy.suspend()
    await repo.save(policy)
    return _policy_to_response(policy)


@router.post(
    "/{policy_id}/new-version",
    response_model=PresentationPolicyResponse,
    response_model_exclude_none=True,
)
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
    membership = await app.state.org_client.get_membership(
        user_id, policy.organization_id
    )
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
    membership = await app.state.org_client.get_membership(
        user_id, policy.organization_id
    )
    ensure_membership_permission(membership, "presentation-policy", "delete")

    if policy.status != PolicyStatus.DRAFT:
        raise HTTPException(
            status_code=400,
            detail="Only draft policies can be deleted. Suspend or archive active policies.",
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

    model_config = ConfigDict(extra="forbid")

    # JSON-LD Data Integrity documents remain structured JSON all the way to
    # the Rust verifier. String serializations continue to use the existing
    # JWT, SD-JWT and mdoc path.
    vp_token: str | dict[str, Any] = Field(max_length=1_000_000)
    trust_profile_id: str | None = Field(
        None, max_length=255
    )  # Override policy's trust profile
    nonce: str | None = Field(
        None, max_length=512
    )  # Expected nonce for replay protection
    audience: str | None = Field(None, max_length=512)  # Expected audience

    # Context for evaluation
    context: dict[str, Any] = Field(default_factory=dict)


class EvaluateInlineRequest(BaseModel):
    """Request to evaluate with inline policy (ad-hoc verification)."""

    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1, max_length=255)
    vp_token: str | dict[str, Any] = Field(max_length=1_000_000)
    credential_requirements: list[CredentialRequirementModel] = Field(
        min_length=1,
    )
    trust_profile_id: str | None = Field(None, max_length=255)
    compliance_profile_id: str | None = Field(None, max_length=255)

    # Verification options
    nonce: str | None = Field(None, max_length=512)
    audience: str | None = Field(None, max_length=512)
    context: dict[str, Any] = Field(default_factory=dict)


def _failed_policy_response(
    policy: PresentationPolicy,
    request: EvaluatePresentationRequest,
    error: str,
    *,
    signature_valid: bool = True,
    trust_check_passed: bool = True,
    freshness_check_passed: bool = True,
) -> PolicyEvaluationResponse:
    """Build a fail-closed response without releasing unverified claims."""
    credential_results = [
        CredentialEvaluationResult(
            credential_template_id=requirement.credential_template_id,
            satisfied=False,
            claim_results=[],
            signature_valid=signature_valid,
            trust_check_passed=trust_check_passed,
            freshness_check_passed=freshness_check_passed,
            errors=[error],
        )
        for requirement in policy.credential_requirements
    ]
    required_total = sum(
        1 for requirement in policy.credential_requirements if requirement.required
    )
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
        decision_reason=error,
        verified_claims={},
        evaluation_timestamp=datetime.now(timezone.utc).isoformat(),
        nonce=request.nonce,
    )


_API_KEY_VERIFICATION_SCOPES = frozenset(
    {"credentials:read", "flows:execute", "admin:full"}
)


def _authorize_gateway_api_key_evaluation(
    request: Request,
    *,
    user_id: str,
    organization_id: str,
) -> bool:
    """Authorize gateway-validated API keys without inventing a user membership.

    The gateway validates the raw key, binds it to one organization, applies
    its Cedar route permission, strips caller-supplied internal headers, and
    forwards the resulting context. A service must validate the complete
    forwarded context before treating the principal as an API key; a partial
    or inconsistent context fails closed instead of falling back to user RBAC.
    """
    api_key_id = request.headers.get("x-api-key-id", "").strip()
    if not api_key_id:
        return False

    forwarded_organization = request.headers.get("x-organization-id", "").strip()
    required_permission = request.headers.get("x-required-permission", "").strip()
    scopes = {
        scope.strip()
        for scope in request.headers.get("x-api-key-scopes", "").split(",")
        if scope.strip()
    }
    if (
        user_id != f"api_key:{api_key_id}"
        or forwarded_organization != organization_id
        or required_permission != "verification:execute"
        or not scopes.intersection(_API_KEY_VERIFICATION_SCOPES)
    ):
        raise HTTPException(
            status_code=403,
            detail="API key is not authorized to evaluate this presentation policy",
        )
    return True


@router.post(
    "/{policy_id}/evaluate",
    response_model=PolicyEvaluationResponse,
    response_model_exclude_none=True,
)
async def evaluate_presentation_http(
    policy_id: str,
    request: EvaluatePresentationRequest,
    http_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryPresentationPolicyRepository = Depends(get_repo),
) -> PolicyEvaluationResponse:
    """Authorize the public request before invoking the shared evaluator."""
    policy = await repo.get(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Presentation Policy not found")

    if not _authorize_gateway_api_key_evaluation(
        http_request,
        user_id=user_id,
        organization_id=policy.organization_id,
    ):
        org_client = await get_organization_client(http_request)
        membership = await org_client.get_membership(user_id, policy.organization_id)
        ensure_membership_permission(membership, "presentation-policy", "evaluate")
    return await evaluate_presentation(
        policy_id=policy_id,
        request=request,
        http_request=http_request,
        repo=repo,
    )


async def evaluate_presentation(
    policy_id: str,
    request: EvaluatePresentationRequest,
    http_request: Request = None,
    repo: InMemoryPresentationPolicyRepository = Depends(get_repo),
    cedar_engine: Any = None,
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
    - W3C Verifiable Credentials Data Model v2 Data Integrity
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
            detail=f"Policy is not active (status: {policy.status.value})",
        )

    # This endpoint accepts one presentation token and currently returns one
    # credential evidence record. It cannot safely prove N-of-M alternatives or
    # bind one authenticated credential to multiple credential requirements.
    if policy.alternative_requirements:
        return _failed_policy_response(
            policy,
            request,
            "Alternative credential requirements require descriptor-bound per-credential evidence",
        )
    if len(policy.credential_requirements) != 1:
        return _failed_policy_response(
            policy,
            request,
            "Exactly one credential requirement is supported per presentation token",
        )
    if not policy.credential_requirements[0].required:
        return _failed_policy_response(
            policy,
            request,
            "At least one required credential requirement is necessary for a decision",
        )

    # Auto-detect credential format
    credential_format = _detect_credential_format(request.vp_token)
    logger.info(f"Detected credential format: {credential_format}")

    # Verify credential based on format.
    #
    # MIP flow note:
    # - Some credential-login policies intentionally do NOT require holder
    #   binding (`holder_binding.required=false`).
    # - Passing nonce/audience unconditionally can force SD-JWT key-binding
    #   checks and reject otherwise valid issuer-signed credentials.
    #
    # A nonce is a freshness challenge, not holder binding by itself. It is
    # supplied only when the configured proof profile requires a signed challenge.
    proof_freshness = policy.holder_binding.proof_freshness
    # An OID4VP flow always represents a holder presentation.  Its signed
    # challenge cannot be disabled by a presentation-policy configuration
    # intended for credential-only verification.  The marker is written by
    # the flow service when it creates the request object and only strengthens
    # verification if a stateless caller supplies it.
    oid4vp_verifier_context = request.context.get("oid4vp_verifier_context") is True
    requires_bound_presentation = (
        policy.holder_binding.required
        or credential_format == "mdoc"
        or oid4vp_verifier_context
    )
    verify_nonce = (
        request.nonce
        if (
            requires_bound_presentation
            and proof_freshness.get("challenge_required", True)
        )
        else None
    )
    verify_audience = (
        request.audience
        if (
            requires_bound_presentation
            and proof_freshness.get("audience_binding_required", True)
        )
        else None
    )

    # Select an explicitly pinned public JWK before signature verification.
    # This supports authoritative non-DID issuers without weakening the normal
    # DID path: the key comes only from the policy's Trust Profile.
    trust_profile_id = request.trust_profile_id or policy.trust_profile_id
    if not trust_profile_id:
        for requirement in policy.credential_requirements:
            if requirement.trust_profile_id:
                trust_profile_id = requirement.trust_profile_id
                break
    trust_profile_data: dict[str, Any] | None = None
    if trust_profile_id:
        trust_profile_data = _load_policy_trust_profile(
            trust_profile_id,
            policy.organization_id,
        )

    pinned_issuer_jwk = _pinned_issuer_jwk(
        trust_profile_data,
        _sd_jwt_unverified_issuer(request.vp_token)
        if credential_format == "sd-jwt" and isinstance(request.vp_token, str)
        else None,
    )

    mdoc_root_certs_pem, mdoc_pinned_issuer_certs_pem = _mdoc_trust_certificates_pem(
        trust_profile_data
    )
    verification_result = await _await_verification_result(
        _verify_credential_by_format(
            request.vp_token,
            credential_format,
            verify_nonce,
            verify_audience,
            pinned_issuer_jwk,
            request.context,
            mdoc_root_certs_pem,
            mdoc_pinned_issuer_certs_pem,
        )
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
        verification_error = (
            verification_result.get("error") or "Credential verification failed"
        )
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
        required_total = sum(
            1 for req in policy.credential_requirements if req.required
        )
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

    verification_evidence = verification_result.get("verification_evidence")
    if not isinstance(verification_evidence, dict):
        verification_evidence = {}
    credential_count = verification_evidence.get("credential_count", 1)
    if (
        isinstance(credential_count, bool)
        or not isinstance(credential_count, int)
        or credential_count != 1
    ):
        return _failed_policy_response(
            policy,
            request,
            "Presentation must contain exactly one independently verified credential",
        )
    if (
        requires_bound_presentation
        and verification_evidence.get("holder_binding_verified") is not True
    ):
        return _failed_policy_response(
            policy,
            request,
            "Required holder binding was not verified",
            signature_valid=False,
        )

    requirement = policy.credential_requirements[0]
    freshness_limits = [
        value
        for value in (
            policy.freshness.max_age_seconds if policy.freshness else None,
            requirement.max_age_seconds,
        )
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
    ]
    requires_issuance_time = bool(
        freshness_limits or requirement.require_fresh_issuance
    )
    credential_age_seconds = _credential_age_seconds(verification_evidence)
    if requires_issuance_time and credential_age_seconds is None:
        return _failed_policy_response(
            policy,
            request,
            "Credential issuance-time evidence is unavailable or invalid",
            freshness_check_passed=False,
        )
    if freshness_limits and credential_age_seconds is not None:
        max_age_seconds = min(freshness_limits)
        if credential_age_seconds > max_age_seconds:
            return _failed_policy_response(
                policy,
                request,
                f"Credential exceeds maximum age of {max_age_seconds} seconds",
                freshness_check_passed=False,
            )

    # Validate issuer DID against the policy's Trust Profile (MIP §8.3).
    # Resolve trust_profile_id: per-requirement override takes precedence over policy-level.
    trust_check_passed = True
    trust_check_error: str | None = None
    if trust_profile_id and issuer_did and issuer_did != "unknown":
        try:
            if trust_profile_data is not None:
                trust_check_passed, trust_check_error = _evaluate_issuer_trust(
                    trust_profile_data=trust_profile_data,
                    issuer_did=issuer_did,
                    constraints=policy.issuer_constraints,
                )
            elif trust_check_passed:
                trust_check_passed = False
                trust_check_error = (
                    f"Trust Profile {trust_profile_id} could not be loaded"
                )
        except Exception as exc:
            trust_check_passed = False
            trust_check_error = (
                f"Trust Profile validation failed for {issuer_did}: {exc}"
            )
            logger.warning(trust_check_error)

    if not trust_check_passed:
        credential_results = [
            CredentialEvaluationResult(
                credential_template_id=req.credential_template_id,
                satisfied=False,
                issuer_did=issuer_did,
                claim_results=[],
                trust_check_passed=False,
                signature_valid=True,
                errors=[str(trust_check_error)],
            )
            for req in policy.credential_requirements
        ]
        required_total = sum(
            1 for req in policy.credential_requirements if req.required
        )
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

    if revocation_checked is not True:
        (
            status_revocation_checked,
            status_not_revoked,
            revocation_status,
        ) = _lookup_managed_issuer_credential_status_revocation_state(
            issuer_did=issuer_did,
            credential_ids=_credential_status_identifier_candidates(
                extracted_claims,
                verification_result,
            ),
        )
        if status_revocation_checked is not None:
            verification_result["revocation_checked"] = status_revocation_checked
            verification_result["not_revoked"] = status_not_revoked
            verification_result["revocation_status"] = revocation_status or "unknown"
            revocation_checked, not_revoked = _derive_revocation_state(
                verification_result
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
                    signature_valid=True,
                    errors=[verification_error],
                )
                for req in policy.credential_requirements
            ]
            required_total = sum(
                1 for req in policy.credential_requirements if req.required
            )
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
            normalized_lifecycle_status = (
                str(verification_result.get("revocation_status") or "").strip().lower()
            )
            verification_error = {
                "suspended": "Credential is suspended",
                "expired": "Credential is expired",
            }.get(normalized_lifecycle_status, "Credential is revoked")
            credential_results = [
                CredentialEvaluationResult(
                    credential_template_id=req.credential_template_id,
                    satisfied=False,
                    issuer_did=issuer_did,
                    claim_results=[],
                    freshness_check_passed=False,
                    signature_valid=True,
                    errors=[verification_error],
                )
                for req in policy.credential_requirements
            ]
            required_total = sum(
                1 for req in policy.credential_requirements if req.required
            )
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

        if not _credential_format_satisfies_requirement(
            credential_format, req.credential_payload_format
        ):
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
                    logger.warning(
                        "Constraint evaluation error for %s/%s",
                        claim.claim_name,
                        c.constraint_type.value,
                        exc_info=True,
                    )
                    constraint_results.append(
                        {
                            "constraint": c.constraint_type.value,
                            "passed": False,
                            "error": True,
                        }
                    )
                    claim_satisfied = False

            claim_results.append(
                ClaimEvaluationResult(
                    claim_name=claim.claim_name,
                    satisfied=claim_satisfied,
                    presented_value=str(presented_value)
                    if presented_value is not None
                    else None,
                    constraint_results=constraint_results,
                )
            )
            if claim.required and not claim_satisfied:
                req_satisfied = False

            if presented_value is not None:
                verified_claims[claim.claim_name] = presented_value

        credential_results.append(
            CredentialEvaluationResult(
                credential_template_id=req.credential_template_id,
                satisfied=req_satisfied,
                issuer_did=issuer_did,
                issuer_name=None,
                claim_results=claim_results,
                errors=req_errors,
            )
        )

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
        decision_reason = (
            f"Partially satisfied: {required_satisfied}/{required_total} required"
        )
        all_satisfied = False
    else:
        result = EvaluationResult.FAILED
        decision = "deny"
        decision_reason = "Required credentials not satisfied"
        all_satisfied = False

    # Cedar policy evaluation for credential verification trust rules. Keep
    # specific verifier/trust/freshness denials above, but never let omission
    # of the final authorization reducer turn a tentative allow into success.
    if (
        cedar_engine is None
        and http_request
        and hasattr(http_request.app.state, "cedar_engine")
    ):
        cedar_engine = http_request.app.state.cedar_engine
    if decision == "allow" and cedar_engine is None:
        return _failed_policy_response(
            policy,
            request,
            "Cedar credential-verification policy engine is unavailable",
        )

    if decision == "allow":
        issuer_policy_evidence = _normalized_issuer_policy_evidence(
            trust_profile_data,
            issuer_did,
        )
        algorithm = verification_evidence.get("algorithm")
        validity_checked = verification_evidence.get("validity_checked")
        is_expired = verification_evidence.get("is_expired")
        missing_evidence: list[str] = []
        if issuer_policy_evidence is None:
            missing_evidence.append("numeric issuer trust")
        if revocation_checked is not True or not_revoked is not True:
            missing_evidence.append("non-revocation")
        if validity_checked is not True or not isinstance(is_expired, bool):
            missing_evidence.append("credential validity")
        if credential_age_seconds is None:
            missing_evidence.append("credential issuance time")
        if not isinstance(algorithm, str) or not algorithm:
            missing_evidence.append("signature algorithm")
        if missing_evidence:
            return _failed_policy_response(
                policy,
                request,
                "Cedar policy evidence is incomplete: " + ", ".join(missing_evidence),
                trust_check_passed=issuer_policy_evidence is not None,
                freshness_check_passed=(
                    revocation_checked is True
                    and not_revoked is True
                    and validity_checked is True
                    and isinstance(is_expired, bool)
                    and credential_age_seconds is not None
                ),
            )

        compliance_code = verified_claims.get("_compliance_code")
        if not isinstance(compliance_code, str) or not compliance_code:
            compliance_code = "UNSPECIFIED"
        cedar_context = {
            "credential_format": _detected_format_to_canonical(credential_format),
            "compliance_code": compliance_code,
            "issuer_id": credential_results[0].issuer_did if credential_results else "",
            "issuer_trust_level": issuer_policy_evidence["issuer_trust_level"],
            "credential_age_seconds": credential_age_seconds,
            "is_revoked": False,
            "is_expired": is_expired,
            "holder_binding_present": (
                verification_evidence.get("holder_binding_verified") is True
            ),
            "algorithm": algorithm,
        }
        cedar_entities = [
            {
                "uid": {"type": "MIP::User", "id": "verifier"},
                "attrs": {"email": "", "status": "ACTIVE"},
                "parents": [
                    {"type": "MIP::Organization", "id": policy.organization_id}
                ],
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
                "parents": [
                    {"type": "MIP::Organization", "id": policy.organization_id}
                ],
            },
        ]
        try:
            cedar_decision = cedar_engine.is_authorized(
                principal='MIP::User::"verifier"',
                action='MIP::Action::"credentials:verify"',
                resource='MIP::Credential::"presented-credential"',
                context=cedar_context,
                entities=cedar_entities,
            )
        except Exception:
            logger.exception("Cedar credential-verification evaluation failed")
            return _failed_policy_response(
                policy,
                request,
                "Cedar policy evaluation failed",
            )
        if not cedar_decision.allowed:
            decision = "deny"
            decision_reason = f"Cedar policy denied: {cedar_decision.reasons or cedar_decision.errors}"
            result = EvaluationResult.FAILED
            logger.warning(
                f"Cedar denied credential verification: {cedar_decision.errors}"
            )

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


@router.post(
    "/evaluate",
    response_model=PolicyEvaluationResponse,
    response_model_exclude_none=True,
)
async def evaluate_presentation_inline(
    request: EvaluateInlineRequest,
    http_request: Request,
    user_id: str = Depends(get_current_user_id),
) -> PolicyEvaluationResponse:
    """
    Evaluate a presentation with inline policy definition.

    Use this for ad-hoc verification where you don't have a saved policy.
    For production use, prefer saved policies for consistency and auditing.
    """
    if not _authorize_gateway_api_key_evaluation(
        http_request,
        user_id=user_id,
        organization_id=request.organization_id,
    ):
        org_client = await get_organization_client(http_request)
        membership = await org_client.get_membership(
            user_id,
            request.organization_id,
        )
        ensure_membership_permission(membership, "presentation-policy", "evaluate")

    policy = PresentationPolicy(
        id=f"inline-{uuid.uuid4()}",
        organization_id=request.organization_id,
        name="Inline Policy",
        status=PolicyStatus.ACTIVE,
        trust_profile_id=request.trust_profile_id,
        compliance_profile_id=request.compliance_profile_id,
        credential_requirements=[
            _build_credential_requirement(requirement)
            for requirement in request.credential_requirements
        ],
    )
    inline_repo = InMemoryPresentationPolicyRepository()
    await inline_repo.save(policy)
    return await evaluate_presentation(
        policy_id=policy.id,
        request=EvaluatePresentationRequest(
            vp_token=request.vp_token,
            trust_profile_id=request.trust_profile_id,
            nonce=request.nonce,
            audience=request.audience,
            context=request.context,
        ),
        http_request=http_request,
        repo=inline_repo,
    )


def _claim_constraint_to_public(constraint: ClaimConstraint) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "claim_name": constraint.claim_name,
        "constraint_type": constraint.constraint_type.value,
        "value": constraint.value,
    }
    if constraint.description is not None:
        payload["description"] = constraint.description
    return payload


def _requested_claim_to_public(claim: RequestedClaim) -> dict[str, Any]:
    return {
        "claim_name": claim.claim_name,
        "display_name": claim.display_name,
        "description": claim.description,
        "required": claim.required,
        "selective_disclosure": claim.selective_disclosure,
        "accept_derived": claim.accept_derived,
        "predicate_spec": claim.predicate_spec,
        "constraints": [
            _claim_constraint_to_public(constraint) for constraint in claim.constraints
        ],
    }


def _credential_requirement_to_public(
    requirement: CredentialRequirement,
) -> dict[str, Any]:
    return {
        "credential_template_id": requirement.credential_template_id,
        "display_name": requirement.display_name,
        "description": requirement.description,
        "required": requirement.required,
        "credential_payload_format": requirement.credential_payload_format,
        "requested_claims": [
            _requested_claim_to_public(claim) for claim in requirement.requested_claims
        ],
        "trust_profile_id": requirement.trust_profile_id,
        "max_age_seconds": requirement.max_age_seconds,
        "require_fresh_issuance": requirement.require_fresh_issuance,
    }


def _alternative_requirement_to_public(
    alternative: AlternativeRequirement,
) -> dict[str, Any]:
    return {
        "name": alternative.name,
        "description": alternative.description,
        "credential_requirements": [
            _credential_requirement_to_public(requirement)
            for requirement in alternative.credential_requirements
        ],
        "min_satisfied": alternative.min_satisfied,
    }


def _holder_binding_to_public(binding: HolderBinding) -> dict[str, Any]:
    if not binding.required:
        return {"required": False}
    return {
        "required": True,
        "binding_methods": binding.binding_methods,
        "proof_profiles": binding.proof_profiles,
        "proof_freshness": binding.proof_freshness,
    }


def _policy_to_response(policy: PresentationPolicy) -> PresentationPolicyResponse:
    required_claims = [
        {key: value for key, value in claim.items() if value is not None}
        for claim in policy.protocol_required_claims
    ]
    display_metadata = {
        "title": policy.display_metadata.title,
        "description": policy.display_metadata.description,
        "purpose": policy.display_metadata.purpose.value,
        "purpose_description": policy.display_metadata.purpose_description,
        "verifier_name": policy.display_metadata.verifier_name,
        "verifier_logo_url": policy.display_metadata.verifier_logo_url,
        "privacy_policy_url": policy.display_metadata.privacy_policy_url,
        "terms_of_service_url": policy.display_metadata.terms_of_service_url,
    }
    return PresentationPolicyResponse(
        id=policy.id,
        organization_id=policy.organization_id,
        name=policy.name,
        status=policy.status.value
        if hasattr(policy.status, "value")
        else str(policy.status),
        description=policy.description,
        purpose=policy.purpose or policy.display_metadata.purpose_description,
        required_claims=required_claims,
        accepted_credential_types=policy.effective_accepted_credential_types,
        display_metadata=display_metadata,
        credential_requirements=[
            _credential_requirement_to_public(requirement)
            for requirement in policy.credential_requirements
        ],
        alternative_requirements=[
            _alternative_requirement_to_public(alternative)
            for alternative in policy.alternative_requirements
        ],
        compliance_profile_id=policy.compliance_profile_id,
        trust_profile_id=policy.trust_profile_id,
        holder_binding=_holder_binding_to_public(policy.holder_binding),
        freshness={
            key: value
            for key, value in {
                "max_age_seconds": policy.freshness.max_age_seconds,
                "require_not_revoked": policy.freshness.require_not_revoked,
                "revocation_grace_seconds": policy.freshness.revocation_grace_seconds,
            }.items()
            if value is not None
        }
        if policy.freshness
        else None,
        prefer_predicates=policy.prefer_predicates,
        supported_circuits=policy.supported_circuits,
        fallback_policy=(
            policy.fallback_policy.upper() if policy.fallback_policy else None
        ),
        issuer_constraints={
            "min_trust_level": policy.issuer_constraints.min_trust_level,
            "required_compliance_statuses": [
                status.upper()
                for status in policy.issuer_constraints.required_compliance_statuses
            ],
            "required_accreditations": policy.issuer_constraints.required_accreditations,
        }
        if policy.issuer_constraints
        else None,
        credential_ranking_strategy=policy.credential_ranking_strategy.upper(),
        credential_ranking_weights=policy.credential_ranking_weights,
        version=policy.version,
        created_at=policy.created_at.isoformat(),
        updated_at=policy.updated_at.isoformat(),
    )


# =============================================================================
# Application Setup
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo
    logger.info(f"Starting {SERVICE_NAME}...")

    # Initialize PostgreSQL adapter
    from marty_common.database import DatabaseManager, DatabaseConfig

    db = DatabaseManager(DatabaseConfig.from_env("presentation-policy"))
    session_factory = db.session_factory
    _repo = PostgresPresentationPolicyRepository(session_factory)
    logger.info("PostgreSQL adapter initialized for presentation-policy service")

    # Initialize gRPC channel to organization service
    from common.di import setup_org_client, teardown_org_client

    await setup_org_client(app, "presentation-policy")

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
        cedar_engine=app.state.cedar_engine,
    )
    add_PresentationPolicyServiceServicer_to_server(servicer, grpc_server)
    start_grpc_server_port(
        grpc_server,
        grpc_port,
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
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ):
        logger.warning(
            "Validation error on %s %s: %s",
            request.method,
            request.url.path,
            exc.errors(),
        )
        return JSONResponse(status_code=400, content={"detail": exc.errors()})

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500, content={"detail": "Internal server error"}
        )

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
