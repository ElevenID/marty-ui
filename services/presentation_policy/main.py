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

import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from typing import Annotated

from marty_common import (
    OrganizationClient,
    OrganizationContext,
    require_org_admin,
    require_org_membership,
)
from marty_common.org_authorization import get_organization_client
from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware

from presentation_policy.infrastructure.adapters import PostgresPresentationPolicyRepository

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "presentation-policy-service"
SERVICE_PORT = int(os.environ.get("PRESENTATION_POLICY_SERVICE_PORT", "8009"))


def get_config() -> dict[str, Any]:
    """Get database configuration from environment."""
    database_url = os.environ.get("DATABASE_URL", "postgresql://marty:marty_dev@postgres:5432/marty_credentials")
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
    credential_requirements: list[CredentialRequirement] = field(default_factory=list)
    alternative_requirements: list[AlternativeRequirement] = field(default_factory=list)
    
    # Compliance
    compliance_profile_id: str | None = None  # Reference to Compliance Profile
    
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


# =============================================================================
# Application Layer
# =============================================================================

class TrustProfileCache:
    """
    In-memory cache for Trust Profiles.
    
    Caches Trust Profile data with TTL based on time_policy.freshness_window_seconds.
    Reduces load on trust-profiles service during verification.
    """
    
    def __init__(self):
        self._cache: dict[str, dict] = {}  # profile_id -> {data, expires_at}
    
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
    display_name: str
    description: str | None = None
    required: bool = True
    selective_disclosure: bool = True
    accept_derived: bool = True
    constraints: list[ClaimConstraintModel] = []


class CredentialRequirementModel(BaseModel):
    credential_template_id: str
    display_name: str
    description: str | None = None
    required: bool = True
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt"
    requested_claims: list[RequestedClaimModel] = []
    trust_profile_id: str | None = None
    max_age_seconds: int | None = None
    require_fresh_issuance: bool = False


class AlternativeRequirementModel(BaseModel):
    name: str
    description: str | None = None
    credential_requirements: list[CredentialRequirementModel] = []
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
    organization_id: str
    name: str
    description: str | None = None
    display_metadata: DisplayMetadataModel | None = None
    credential_requirements: list[CredentialRequirementModel] = []
    alternative_requirements: list[AlternativeRequirementModel] = []
    compliance_profile_id: str | None = None


class UpdatePresentationPolicyRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    display_metadata: DisplayMetadataModel | None = None
    credential_requirements: list[CredentialRequirementModel] | None = None
    alternative_requirements: list[AlternativeRequirementModel] | None = None
    compliance_profile_id: str | None = None


class PresentationPolicyResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    display_metadata: dict
    credential_requirements: list[dict]
    alternative_requirements: list[dict]
    compliance_profile_id: str | None
    version: int
    created_at: str
    updated_at: str


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
            return False

    # Unknown constraint type — pass through
    logger.warning(f"Unknown constraint type '{constraint_type}'; treating as passing")
    return True


# =============================================================================
# Format Detection & Verification Utilities
# =============================================================================

def _detect_credential_format(vp_token: str) -> str:
    """
    Auto-detect credential format from VP token.
    
    Returns: "w3c-vc", "sd-jwt", "mdoc", "openbadge-v2", "openbadge-v3", or "unknown"
    """
    try:
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
            except:
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
    """Verify W3C Verifiable Credential."""
    # In production: call verification service or use marty_verification_py
    return {
        "verified": True,
        "claims": {"simulated": "w3c_vc_claims"},
        "issuer_did": "did:example:issuer",
        "format": "w3c-vc",
    }


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
    import base64 as _b64

    def _b64decode_unpadded(s: str) -> bytes:
        s = s.replace("-", "+").replace("_", "/")
        padding = 4 - len(s) % 4
        if padding != 4:
            s += "=" * padding
        return _b64.b64decode(s)

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
        jwt_segs = jwt_part.split(".")
        if len(jwt_segs) < 2:
            return {"verified": False, "error": "Malformed SD-JWT", "claims": {}}

        payload_bytes = _b64decode_unpadded(jwt_segs[1])
        payload: dict = json.loads(payload_bytes)

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

        return {
            "verified": True,  # structural verification only — crypto TODO
            "claims": claims,
            "issuer_did": issuer,
            "subject": subject,
            "format": "sd-jwt",
        }

    except Exception as exc:
        logger.error(f"SD-JWT decode error: {exc}")
        return {"verified": False, "error": str(exc), "claims": {}}


def _verify_mdoc(vp_token: str, nonce: str | None, audience: str | None) -> dict:
    """Verify mDoc/ISO 18013-5 credential."""
    # In production: call verification service or use _marty_rs
    return {
        "verified": True,
        "claims": {"simulated": "mdoc_claims"},
        "issuer_did": "did:example:issuer",
        "format": "mdoc",
    }


def _verify_open_badge_v2(vp_token: str) -> dict:
    """Verify Open Badges v2 credential."""
    # In production: use marty_verification_py.open_badge_ob2_verify
    return {
        "verified": True,
        "claims": {"simulated": "openbadge_v2_claims"},
        "issuer_did": "did:example:issuer",
        "format": "openbadge-v2",
    }


def _verify_open_badge_v3(vp_token: str) -> dict:
    """Verify Open Badges v3 credential."""
    # In production: use marty_verification_py.open_badge_ob3_verify
    return {
        "verified": True,
        "claims": {"simulated": "openbadge_v3_claims"},
        "issuer_did": "did:example:issuer",
        "format": "openbadge-v3",
    }


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


@router.post("", response_model=PresentationPolicyResponse)
async def create_presentation_policy(
    request: CreatePresentationPolicyRequest,
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryPresentationPolicyRepository = Depends(get_repo),
) -> PresentationPolicyResponse:
    """Create a new Presentation Policy."""
    # Verify org membership
    org_client = await get_organization_client(fastapi_request)
    membership = await org_client.get_membership(user_id, request.organization_id)
    if not membership or not membership.is_active():
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    
    policy = PresentationPolicy(
        organization_id=request.organization_id,
        name=request.name,
        description=request.description,
        compliance_profile_id=request.compliance_profile_id,
    )
    
    # Set display metadata
    if request.display_metadata:
        policy.display_metadata = DisplayMetadata(
            title=request.display_metadata.title,
            description=request.display_metadata.description,
            purpose=RequestPurpose(request.display_metadata.purpose),
            purpose_description=request.display_metadata.purpose_description,
            verifier_name=request.display_metadata.verifier_name,
            verifier_logo_url=request.display_metadata.verifier_logo_url,
            privacy_policy_url=request.display_metadata.privacy_policy_url,
            terms_of_service_url=request.display_metadata.terms_of_service_url,
        )
    
    # Set credential requirements
    for req_model in request.credential_requirements:
        policy.credential_requirements.append(_build_credential_requirement(req_model))
    
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


@router.get("", response_model=list[PresentationPolicyResponse])
async def list_presentation_policies(
    organization_id: str = Query(..., description="Organization ID"),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryPresentationPolicyRepository = Depends(get_repo),
) -> list[PresentationPolicyResponse]:
    """List Presentation Policies for an organization."""
    # Verify org membership
    await app.state.org_client.get_membership(user_id, organization_id)
    policies = await repo.list(organization_id)
    return [_policy_to_response(p) for p in policies]


@router.get("/{policy_id}", response_model=PresentationPolicyResponse)
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
        # Verify org membership for real users
        await app.state.org_client.get_membership(user_id, policy.organization_id)
    return _policy_to_response(policy)


@router.patch("/{policy_id}", response_model=PresentationPolicyResponse)
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
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if policy.status != PolicyStatus.DRAFT:
        raise HTTPException(
            status_code=400,
            detail="Only draft policies can be modified. Create a new version instead."
        )
    
    if request.name is not None:
        policy.name = request.name
    if request.description is not None:
        policy.description = request.description
    if request.compliance_profile_id is not None:
        policy.compliance_profile_id = request.compliance_profile_id
    
    policy.updated_at = datetime.now(timezone.utc)
    await repo.save(policy)
    return _policy_to_response(policy)


@router.post("/{policy_id}/activate", response_model=PresentationPolicyResponse)
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
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if not policy.credential_requirements and not policy.alternative_requirements:
        raise HTTPException(
            status_code=400,
            detail="Policy must have at least one credential requirement"
        )
    
    policy.activate()
    await repo.save(policy)
    return _policy_to_response(policy)


@router.post("/{policy_id}/suspend", response_model=PresentationPolicyResponse)
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
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    policy.suspend()
    await repo.save(policy)
    return _policy_to_response(policy)


@router.post("/{policy_id}/new-version", response_model=PresentationPolicyResponse)
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
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
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


@router.delete("/{policy_id}")
async def delete_presentation_policy(
    policy_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryPresentationPolicyRepository = Depends(get_repo),
) -> dict:
    """Delete a Presentation Policy (only allowed for drafts, requires admin)."""
    policy = await repo.get(policy_id)
    if not policy:
        raise HTTPException(status_code=404, detail="Presentation Policy not found")
    
    # Verify admin access
    membership = await app.state.org_client.get_membership(user_id, policy.organization_id)
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if policy.status != PolicyStatus.DRAFT:
        raise HTTPException(
            status_code=400,
            detail="Only draft policies can be deleted. Suspend or archive active policies."
        )
    await repo.delete(policy_id)
    return {"success": True}


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
    vp_token: str  # The VP token (JWT or JSON)
    trust_profile_id: str | None = None  # Override policy's trust profile
    nonce: str | None = None  # Expected nonce for replay protection
    audience: str | None = None  # Expected audience
    
    # Context for evaluation
    context: dict[str, Any] = {}


class EvaluateInlineRequest(BaseModel):
    """Request to evaluate with inline policy (ad-hoc verification)."""
    vp_token: str
    
    # Inline policy definition
    required_claims: list[dict] = []  # [{claim_name, constraints}]
    accepted_credential_types: list[str] = []
    trust_profile_id: str | None = None
    
    # Verification options
    nonce: str | None = None
    audience: str | None = None


@router.post("/{policy_id}/evaluate", response_model=PolicyEvaluationResponse)
async def evaluate_presentation(
    policy_id: str,
    request: EvaluatePresentationRequest,
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
    
    # Verify credential based on format
    verification_result = _verify_credential_by_format(
        request.vp_token, 
        credential_format,
        request.nonce,
        request.audience,
    )
    # 4. Check issuer trust using Trust Profile
    # 5. Evaluate claims against policy constraints
    # 6. Check freshness/expiry
    
    # Extract real claims from the verification result
    extracted_claims: dict[str, Any] = verification_result.get("claims", {})
    issuer_did: str = verification_result.get("issuer_did", "unknown")
    verification_ok: bool = verification_result.get("verified", False)

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
                    constraint_results.append({"constraint": c.constraint_type.value, "passed": False})
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


@router.post("/evaluate", response_model=PolicyEvaluationResponse)
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
        status=policy.status.value,
        display_metadata={
            "title": policy.display_metadata.title,
            "description": policy.display_metadata.description,
            "purpose": policy.display_metadata.purpose.value,
            "purpose_description": policy.display_metadata.purpose_description,
            "verifier_name": policy.display_metadata.verifier_name,
            "verifier_logo_url": policy.display_metadata.verifier_logo_url,
            "privacy_policy_url": policy.display_metadata.privacy_policy_url,
            "terms_of_service_url": policy.display_metadata.terms_of_service_url,
        },
        credential_requirements=[
            {
                "id": req.id,
                "credential_template_id": req.credential_template_id,
                "display_name": req.display_name,
                "required": req.required,
                "credential_payload_format": req.credential_payload_format,
                "requested_claims": [
                    {
                        "id": rc.id,
                        "claim_name": rc.claim_name,
                        "display_name": rc.display_name,
                        "required": rc.required,
                        "selective_disclosure": rc.selective_disclosure,
                        "constraints": [
                            {
                                "constraint_type": c.constraint_type.value,
                                "value": c.value,
                            }
                            for c in rc.constraints
                        ],
                    }
                    for rc in req.requested_claims
                ],
                "trust_profile_id": req.trust_profile_id,
                "max_age_seconds": req.max_age_seconds,
            }
            for req in policy.credential_requirements
        ],
        alternative_requirements=[
            {
                "id": alt.id,
                "name": alt.name,
                "min_satisfied": alt.min_satisfied,
                "credential_requirements": [
                    {
                        "id": req.id,
                        "credential_template_id": req.credential_template_id,
                        "display_name": req.display_name,
                    }
                    for req in alt.credential_requirements
                ],
            }
            for alt in policy.alternative_requirements
        ],
        compliance_profile_id=policy.compliance_profile_id,
        version=policy.version,
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
    engine = create_async_engine(
        config["database_url"],
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        echo=False
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    _repo = PostgresPresentationPolicyRepository(session_factory)
    logger.info("PostgreSQL adapter initialized for presentation-policy service")
    
    # Initialize OrganizationClient
    org_service_url = os.environ.get("ORGANIZATION_SERVICE_URL", "http://organization:8002")
    app.state.org_client = OrganizationClient(
        base_url=org_service_url,
        redis_client=None,
    )
    
    _trust_profile_cache = TrustProfileCache()
    yield
    
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await engine.dispose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Presentation Policy Service",
        description="""Manages Presentation Policies - what credentials are requested for verification.

## Stateless Verification

For immediate policy evaluation without session state:

- `POST /v1/presentation-policies/{id}/evaluate` - Evaluate VP against a saved policy
- `POST /v1/presentation-policies/evaluate` - Evaluate VP with inline (ad-hoc) policy

## Policy Management

CRUD operations for Presentation Policies that define required credentials and claims.
        """,
        version="1.0.0",
        lifespan=lifespan,
    )
    
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RequestIdMiddleware)
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
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
