"""
Marty API Gateway

Central API gateway that routes requests to microservices.
All services follow the Digital Identity model architecture.

Services:
- Auth (8001) - Authentication
- Organization (8002) - Organization management
- Credential Template (8003) - Credential blueprints
- Trust Profile (8004) - Trust configuration
- Issuance (8005) - Credential issuance
- Notification (8007) - Notifications
- Compliance Profile (8008) - Regulatory rules
- Presentation Policy (8009) - Verification policies + stateless evaluation
- Deployment Profile (8010) - Runtime configuration
- Flow (8011) - Orchestration + async verification flows

Port: 8000
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, List

import httpx
from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
import redis.asyncio as aioredis
from marty_common import OrganizationClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

SERVICE_NAME = "api-gateway"
SERVICE_PORT = int(os.environ.get("GATEWAY_PORT", "8000"))


# =============================================================================
# Service Registry
# =============================================================================

class ServiceRegistry:
    """Service registry for routing."""
    
    def __init__(self):
        self._services: dict[str, str] = {}
        self._load_services()
    
    def _load_services(self) -> None:
        """Load service URLs from environment or defaults."""
        self._services = {
            "auth": os.environ.get("AUTH_SERVICE_URL", "http://localhost:8001"),
            "organizations": os.environ.get("ORGANIZATION_SERVICE_URL", "http://localhost:8002"),
            "credential-templates": os.environ.get("CREDENTIAL_TEMPLATE_SERVICE_URL", "http://localhost:8003"),
            "trust-profiles": os.environ.get("TRUST_PROFILE_SERVICE_URL", "http://localhost:8004"),
            "issuance": os.environ.get("ISSUANCE_SERVICE_URL", "http://localhost:8005"),
            "applicant": os.environ.get("APPLICANT_SERVICE_URL", "http://localhost:8006"),
            "notifications": os.environ.get("NOTIFICATION_SERVICE_URL", "http://localhost:8007"),
            "compliance-profiles": os.environ.get("COMPLIANCE_PROFILE_SERVICE_URL", "http://localhost:8008"),
            "presentation-policies": os.environ.get("PRESENTATION_POLICY_SERVICE_URL", "http://localhost:8009"),
            "deployment-profiles": os.environ.get("DEPLOYMENT_PROFILE_SERVICE_URL", "http://localhost:8010"),
            "flows": os.environ.get("FLOW_SERVICE_URL", "http://localhost:8011"),
            "verification": os.environ.get("VERIFICATION_SERVICE_URL", "http://localhost:8012"),
            "revocation-profiles": os.environ.get("REVOCATION_PROFILE_SERVICE_URL", "http://localhost:8013"),
        }
    
    def get_service_url(self, service_name: str) -> str | None:
        return self._services.get(service_name)
    
    def get_all_services(self) -> dict[str, str]:
        return self._services.copy()


# =============================================================================
# Session Cache
# =============================================================================

class SessionCache:
    """Simple in-memory cache for session validation with TTL."""
    
    def __init__(self, ttl_seconds: int = 60):
        self._cache: dict[str, tuple[dict, float]] = {}
        self._ttl_seconds = ttl_seconds
    
    def get(self, session_id: str) -> dict | None:
        """Get cached session data if not expired."""
        if session_id not in self._cache:
            return None
        
        data, expires_at = self._cache[session_id]
        if time.time() > expires_at:
            del self._cache[session_id]
            return None
        
        return data
    
    def set(self, session_id: str, data: dict) -> None:
        """Set session data with TTL."""
        expires_at = time.time() + self._ttl_seconds
        self._cache[session_id] = (data, expires_at)
    
    def clear(self, session_id: str) -> None:
        """Clear cached session."""
        self._cache.pop(session_id, None)


# =============================================================================
# Auth Middleware
# =============================================================================

class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware that validates sessions and injects user context headers."""
    
    def __init__(self, app, registry: ServiceRegistry, session_cache: SessionCache):
        super().__init__(app)
        self.registry = registry
        self.session_cache = session_cache
        self._http_client: httpx.AsyncClient | None = None
    
    async def dispatch(self, request: Request, call_next):
        """Process request and inject user context headers."""
        import re as _re
        # Get route configuration
        route_config = get_route_config(request.url.path)
        
        # OID4VP wallet-facing endpoints must be public (wallet has no session cookie)
        _WALLET_PUBLIC = _re.compile(
            r"^/v1/flows/instances/[^/]+/(request|submit)$"
        )
        
        # Skip auth for unauthenticated routes or health checks
        if (
            not route_config
            or not route_config.get("requires_auth", False)
            or request.url.path == "/health"
            or request.url.path.startswith("/health/")
            or request.url.path.startswith("/.well-known/")
            or _WALLET_PUBLIC.match(request.url.path)
        ):
            return await call_next(request)
        
        # Extract session ID from cookie
        session_id = request.cookies.get("sessionId")
        if not session_id:
            logger.warning(f"No session cookie for authenticated route: {request.url.path}")
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required"},
            )
        
        # Check cache first
        user_data = self.session_cache.get(session_id)
        
        # Validate with auth service if not cached
        if not user_data:
            auth_url = self.registry.get_service_url("auth")
            if not auth_url:
                logger.error("Auth service URL not configured")
                return JSONResponse(
                    status_code=503,
                    content={"detail": "Auth service unavailable"},
                )
            
            # Validate session
            try:
                if not self._http_client:
                    self._http_client = httpx.AsyncClient()
                
                response = await self._http_client.post(
                    f"{auth_url}/internal/v1/auth/validate-session",
                    params={"session_id": session_id},
                    timeout=5.0,
                )
                
                if response.status_code != 200:
                    logger.warning(f"Session validation failed: {response.status_code}")
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "Invalid session"},
                    )
                
                validation_data = response.json()
                if not validation_data.get("valid"):
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "Invalid session"},
                    )
                
                user_data = validation_data.get("user", {})
                
                # Cache the result
                self.session_cache.set(session_id, user_data)
                
            except httpx.TimeoutException:
                logger.error("Auth service timeout during session validation")
                return JSONResponse(
                    status_code=504,
                    content={"detail": "Auth service timeout"},
                )
            except Exception as e:
                logger.error(f"Error validating session: {e}")
                return JSONResponse(
                    status_code=502,
                    content={"detail": "Auth service error"},
                )
        
        # Inject user context headers
        user_id = user_data.get("user_id")
        email = user_data.get("email")
        
        if not user_id:
            logger.error("No user_id in session data")
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid session data"},
            )
        
        # Add headers to request for downstream services
        request.state.user_id = user_id
        request.state.user_email = email
        request.state.user_domain = email.split("@")[1] if email and "@" in email else None
        
        # Proceed with request
        response = await call_next(request)
        return response


# =============================================================================
# Organization Authorization Middleware
# =============================================================================

class OrgAuthMiddleware(BaseHTTPMiddleware):
    """Middleware that verifies organization membership for org-scoped routes."""
    
    # Routes that should skip org membership checks
    ORG_ALLOWLIST_PATTERNS = [
        r"^/v1/organizations$",  # List all orgs (discovery)
        r"^/v1/organizations/mine$",  # Get my orgs
        r"^/v1/organizations/discover",  # Discover orgs
        r"^/v1/organizations/join/",  # Join flows
        r"^/v1/organizations/[^/]+/join$",  # Join specific org by ID (user may not be a member yet)
        r"^/v1/organizations/invitations/",  # Invitation flows
        r"^/health",
        r"^/.well-known/",
    ]
    
    def __init__(self, app):
        super().__init__(app)
        import re
        self._allowlist_patterns = [re.compile(p) for p in self.ORG_ALLOWLIST_PATTERNS]
    
    async def dispatch(self, request: Request, call_next):
        """Check org membership for org-scoped routes."""
        path = request.url.path
        
        # Skip if path matches allowlist
        import re
        if any(pattern.match(path) for pattern in self._allowlist_patterns):
            return await call_next(request)
        
        # Check if this is an org-scoped route: /v1/organizations/{org_id}/...
        org_id_match = re.match(r"^/v1/organizations/([a-f0-9\-]{36})/", path)
        if not org_id_match:
            # Not an org-scoped route, proceed
            return await call_next(request)
        
        org_id = org_id_match.group(1)
        
        # Get user_id from request state (injected by AuthMiddleware)
        user_id = getattr(request.state, "user_id", None)
        if not user_id:
            # User not authenticated - AuthMiddleware should have caught this
            # but just in case...
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required"},
            )
        
        # Get OrganizationClient from app state
        if not hasattr(request.app.state, "org_client"):
            logger.error("OrganizationClient not configured in app state")
            return JSONResponse(
                status_code=500,
                content={"detail": "Organization client not configured"},
            )
        
        org_client: OrganizationClient = request.app.state.org_client
        
        # Verify membership
        try:
            membership = await org_client.get_membership(user_id, org_id)
            
            if not membership:
                logger.warning(
                    f"User {user_id} attempted to access organization {org_id} "
                    f"without membership (path: {path})"
                )
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Not a member of this organization"},
                )
            
            if membership.status != "active":
                logger.warning(
                    f"User {user_id} attempted to access organization {org_id} "
                    f"with inactive membership (status: {membership.status}, path: {path})"
                )
                return JSONResponse(
                    status_code=403,
                    content={"detail": f"Organization membership is {membership.status}"},
                )
            
            # Inject org role header for downstream services
            request.state.org_role = membership.role.value
            
        except HTTPException as e:
            # OrganizationClient raises HTTPException for service errors
            logger.error(f"Error verifying membership: {e.detail}")
            return JSONResponse(
                status_code=e.status_code,
                content={"detail": e.detail},
            )
        except Exception as e:
            logger.error(f"Unexpected error in org auth middleware: {e}", exc_info=True)
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error"},
            )
        
        # Membership verified, proceed
        response = await call_next(request)
        return response


# =============================================================================
# Route Configuration
# =============================================================================

ROUTE_CONFIG = {
    # Auth routes (no auth required)
    "/v1/auth": {"service": "auth", "requires_auth": False},
    "/v1/organizations/invitations/validate": {"service": "auth", "requires_auth": False},
    "/v1/organizations/join/code/validate": {"service": "organizations", "requires_auth": False},
    
    # Organization routes
    "/v1/organizations": {"service": "organizations", "requires_auth": True},
    "/v1/me": {"service": "organizations", "requires_auth": True},
    
    # Digital Identity Model - Configuration Resources
    "/v1/credential-templates": {"service": "credential-templates", "requires_auth": True},
    "/v1/trust-profiles": {"service": "trust-profiles", "requires_auth": True},
    "/v1/compliance-profiles": {"service": "compliance-profiles", "requires_auth": True},
    "/v1/presentation-policies": {"service": "presentation-policies", "requires_auth": True},
    "/v1/deployment-profiles": {"service": "deployment-profiles", "requires_auth": True},
    "/v1/revocation-profiles": {"service": "revocation-profiles", "requires_auth": True},
    
    # Digital Identity Model - Operational Resources
    "/v1/applicants": {"service": "applicant", "requires_auth": True},
    # OID4VCI wallet-facing endpoints must be public (no auth token available on wallet)
    "/v1/issuance/token": {"service": "issuance", "requires_auth": False},
    "/v1/issuance/credential": {"service": "issuance", "requires_auth": False},
    "/v1/issuance": {"service": "issuance", "requires_auth": True},
    "/v1/application-templates": {"service": "issuance", "requires_auth": True},
    "/v1/applications": {"service": "issuance", "requires_auth": True},
    "/v1/flows": {"service": "flows", "requires_auth": True},
    
    # Verification & ZK Proof routes
    "/v1/verify": {"service": "verification", "requires_auth": True},
    "/v1/verify/zkp": {"service": "verification", "requires_auth": True},
    
    # Utility routes
    "/v1/notifications": {"service": "notifications", "requires_auth": True},
}


def get_route_config(path: str) -> dict[str, Any] | None:
    """Find matching route configuration for a path."""
    for prefix, config in sorted(ROUTE_CONFIG.items(), key=lambda x: -len(x[0])):
        if path.startswith(prefix):
            return config
    return None


# =============================================================================
# Base Classes for Models
# =============================================================================

class BaseResourceCreate(BaseModel):
    """Base class for creating organization-scoped resources."""
    organization_id: str
    name: str
    description: str | None = None


class BaseResourceResponse(BaseModel):
    """Base class for resource responses."""
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    created_at: str
    updated_at: str


# =============================================================================
# API Models - Trust Profile
# =============================================================================

class TrustSourceModel(BaseModel):
    name: str
    source_type: str = "registry"
    url: str | None = None
    enabled: bool = True


class ValidationRulesModel(BaseModel):
    allowed_algorithms: list[str] = ["ES256", "ES384", "EdDSA"]
    min_key_size_rsa: int = 2048
    allow_self_signed: bool = False


class TrustProfileCreate(BaseModel):
    organization_id: str
    name: str
    description: str | None = None
    trust_sources: list[TrustSourceModel] = []
    validation_rules: ValidationRulesModel | None = None
    supported_formats: list[str] = ["sd_jwt_vc", "mdoc"]


class TrustProfileResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    trust_sources: list[dict]
    validation_rules: dict
    revocation_policy: dict
    supported_formats: list[str]
    created_at: str
    updated_at: str


class TrustedIssuerCreate(BaseModel):
    name: str
    description: str | None = None
    issuer_did: str
    issuer_url: str | None = None
    credential_template_ids: list[str] = []


class TrustedIssuerResponse(BaseModel):
    id: str
    trust_profile_id: str
    name: str
    issuer_did: str
    status: str
    credential_template_ids: list[str]
    created_at: str


# =============================================================================
# API Models - Credential Template
# =============================================================================

class ClaimDefinitionModel(BaseModel):
    name: str
    display_name: str
    claim_type: str = "string"
    required: bool = True
    selectively_disclosable: bool = True


class TemplateValidityRules(BaseModel):
    ttl_days: int = 365
    expiration_mode: str = "hard"  # hard, soft
    reissue_window_days: int = 30


class TemplateIssuerRequirements(BaseModel):
    allowed_issuer_ids: list[str] = []  # References Trust Profile entries or specific DIDs
    signing_algorithm_constraints: list[str] | None = None


class CredentialTemplateCreate(BaseModel):
    """Create a Credential Template (complete issuance definition).
    
    Credential Template is the master configuration combining:
    - Schema/claims definition
    - Compliance Profile (embedded - format, framework rules)
    - Application Template reference (optional - for application-based flows)
    - Cryptographic configuration (keys, certs, DIDs)
    - Validity and revocation settings
    """
    organization_id: str
    name: str
    description: str | None = None
    
    # Schema & Claims
    credential_type: str
    vct: str  # Verifiable Credential Type identifier
    claims: list[ClaimDefinitionModel] = []
    privacy_posture: str = "selective_disclosure"
    supported_formats: list[str] = ["sd_jwt_vc"]
    
    # INVERTED RELATIONSHIP: Credential Template references Application Template
    application_template_id: str | None = None  # Optional - for application-based issuance
    
    # Embedded Compliance Profile
    compliance_profile: dict  # Embedded compliance rules (no longer a reference)
    trust_profile_id: str | None = None
    revocation_profile_id: str | None = None
    
    # Validity configuration
    validity_rules: TemplateValidityRules | None = None
    
    # Cryptographic configuration (moved from Application Template)
    issuer_key_id: str | None = None
    issuer_key_algorithm: str | None = None  # RS256, ES256, EdDSA, etc.
    key_access_mode: str = "key_vault"  # key_vault, hsm, local (dev only)
    issuer_certificate_chain_pem: str | None = None  # For mDoc/X.509-based credentials
    issuer_did: str | None = None  # For DID-based credentials
    auto_generate_artifacts: bool = True  # Auto-generate missing artifacts in non-production
    
    # Legacy field for backward compatibility during migration
    issuer_requirements: TemplateIssuerRequirements | None = None
    # ZK-specific fields
    zk_predicate_claims: list[str] = []
    schema_uri: dict | None = None
    # Payload format and wallet deep-link configuration
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt"  # ietf_sd_jwt | w3c_vcdm_v2_sd_jwt | w3c_vcdm_v2_jwt_vc
    wallet_configs: list[dict] = []  # [{"wallet_id": ..., "deep_link_scheme": ...}]


class CredentialTemplateResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    
    # Schema & Claims
    credential_type: str
    vct: str  # Verifiable Credential Type identifier
    claims: list[dict]
    privacy_posture: str
    supported_formats: list[str]
    
    # Profile references
    application_template_id: str | None
    compliance_profile: dict  # Embedded compliance rules
    trust_profile_id: str | None
    revocation_profile_id: str | None
    
    # Validity
    validity_rules: dict | None
    
    # Cryptographic status (don't expose raw PEM in responses)
    issuer_key_id: str | None
    issuer_key_algorithm: str | None
    key_access_mode: str
    issuer_certificate_chain_configured: bool  # Whether cert chain is set
    issuer_did: str | None
    artifacts_status: str  # "complete", "partial", "missing"
    
    # Legacy field
    issuer_requirements: dict | None
    # ZK-specific fields
    zk_predicate_claims: list[str] = []
    # Payload format and wallet deep-link configuration
    credential_payload_format: str = "w3c_vcdm_v2_sd_jwt"
    wallet_configs: list[dict] = []

    # Metadata
    version: int
    created_at: str
    updated_at: str


# =============================================================================
# API Models - Compliance Profile
# =============================================================================

class DataRetentionModel(BaseModel):
    retention_period: str = "session"
    retain_metadata_only: bool = False


class ComplianceProfileCreate(BaseModel):
    """Create a Compliance Profile for regulatory rules and format abstraction."""
    organization_id: str
    name: str
    description: str | None = None
    # Compliance code (e.g., ICAO_DTC, AAMVA_MDL, EUDI_PID, ENTERPRISE_VC)
    compliance_code: str | None = None
    # Credential format mapping
    credential_format: str = "sd_jwt_vc"  # sd_jwt_vc, mdoc, jwt_vc, json_ld
    # Regulatory frameworks
    frameworks: list[str] = []
    # Data retention policy
    data_retention: DataRetentionModel | None = None
    # Trust profile constraints (which trust profiles can use this)
    trust_profile_constraints: list[str] = []
    # Whether this is a system-provided profile
    system_profile: bool = False


class ComplianceProfileResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    compliance_code: str | None
    credential_format: str
    frameworks: list[str]
    data_retention: dict
    consent_requirement: dict
    audit_configuration: dict
    trust_profile_constraints: list[str]
    system_profile: bool
    created_at: str
    updated_at: str
    updated_at: str


# =============================================================================
# API Models - Presentation Policy
# =============================================================================

class RequestedClaimModel(BaseModel):
    claim_name: str
    display_name: str
    required: bool = True
    selective_disclosure: bool = True


class CredentialRequirementModel(BaseModel):
    credential_template_id: str
    display_name: str
    required: bool = True
    requested_claims: list[RequestedClaimModel] = []


class HolderBindingModel(BaseModel):
    """How to verify the presenter is the legitimate holder."""
    required: bool = True
    methods: list[str] = ["key_binding"]  # key_binding, biometric, pin


class IssuerConstraintsModel(BaseModel):
    """Constraints on accepted issuers."""
    allowed_issuers: list[str] = []  # DIDs or issuer identifiers
    trust_profile_id: str | None = None


class FreshnessConstraintsModel(BaseModel):
    """How fresh credentials must be."""
    max_age_seconds: int | None = None
    require_not_expired: bool = True
    require_not_revoked: bool = True


class PresentationPolicyCreate(BaseModel):
    """Create a Presentation Policy defining what credentials to request."""
    organization_id: str
    name: str
    description: str | None = None
    credential_requirements: list[CredentialRequirementModel] = []
    compliance_profile_id: str | None = None
    # Holder binding requirements
    holder_binding: HolderBindingModel | None = None
    # Issuer constraints
    issuer_constraints: IssuerConstraintsModel | None = None
    # Freshness requirements
    freshness_constraints: FreshnessConstraintsModel | None = None


class PresentationPolicyResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    credential_requirements: list[dict]
    compliance_profile_id: str | None
    holder_binding: dict | None
    issuer_constraints: dict | None
    freshness_constraints: dict | None
    version: int
    created_at: str
    updated_at: str


# =============================================================================
# API Models - Deployment Profile
# =============================================================================

class CallbacksModel(BaseModel):
    issuance_complete_url: str | None = None
    verification_complete_url: str | None = None


class FeatureFlagsModel(BaseModel):
    enable_selective_disclosure: bool = True
    enable_qr_code_generation: bool = True


class DeploymentProfileCreate(BaseModel):
    organization_id: str
    name: str
    description: str | None = None
    environment: str = "development"
    callbacks: CallbacksModel | None = None
    feature_flags: FeatureFlagsModel | None = None
    # Enabled flows (which flow definitions can use this profile)
    enabled_flow_ids: list[str] = []
    # Default presentation policy for verification
    default_policy_id: str | None = None
    # Network mode: online, offline, hybrid
    network_mode: str = "online"
    # UX configuration
    ux_config: dict | None = None  # language, signage_text, branding
    # Update channel for version pinning
    update_channel: str = "stable"  # stable, beta, dev


class DeploymentProfileResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    environment: str
    callbacks: dict
    feature_flags: dict
    enabled_flow_ids: list[str]
    default_policy_id: str | None
    network_mode: str
    ux_config: dict | None
    update_channel: str
    api_key_prefix: str | None
    created_at: str
    updated_at: str


# =============================================================================
# API Models - Flow
# =============================================================================

class FlowStepModel(BaseModel):
    name: str
    step_type: str = "user_input"
    config: dict = {}


class FlowDefinitionCreate(BaseModel):
    """Create a Flow Definition for orchestrating credential operations."""
    organization_id: str
    name: str
    description: str | None = None
    flow_type: str = "issuance"  # issuance, verification, presentation, renewal, revocation
    steps: list[FlowStepModel] = []
    # Configuration resources this flow uses
    trust_profile_id: str | None = None
    credential_template_id: str | None = None
    application_template_id: str | None = None  # Mutually exclusive with credential_template_id
    presentation_policy_id: str | None = None
    # Deployment profiles where this flow can run
    deployment_profile_ids: list[str] = []


class FlowDefinitionResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    flow_type: str
    steps: list[dict]
    trust_profile_id: str | None
    credential_template_id: str | None
    application_template_id: str | None
    presentation_policy_id: str | None
    deployment_profile_ids: list[str]
    version: int
    created_at: str
    updated_at: str


class FlowInstanceCreate(BaseModel):
    flow_definition_id: str
    subject_id: str | None = None
    initial_context: dict = {}


class FlowInstanceResponse(BaseModel):
    id: str
    flow_definition_id: str
    status: str
    current_step_id: str | None
    context: dict
    created_at: str
    updated_at: str


# =============================================================================
# API Models - Policy Evaluation
# =============================================================================

class EvaluatePresentationRequest(BaseModel):
    vp_token: str
    trust_profile_id: str | None = None
    nonce: str | None = None
    audience: str | None = None
    context: dict = {}


class ClaimEvaluationResult(BaseModel):
    claim_name: str
    satisfied: bool
    presented_value: Any | None = None
    error: str | None = None


class CredentialEvaluationResult(BaseModel):
    credential_template_id: str
    satisfied: bool
    issuer_did: str | None = None
    claim_results: list[ClaimEvaluationResult] = []
    errors: list[str] = []


class PolicyEvaluationResponse(BaseModel):
    result: str  # passed, failed, partial
    policy_id: str
    policy_name: str
    credential_results: list[CredentialEvaluationResult]
    decision: str  # allow, deny, manual_review
    decision_reason: str
    verified_claims: dict
    evaluation_timestamp: str


class EvaluateInlineRequest(BaseModel):
    """Request to evaluate a VP with an inline (ad-hoc) policy."""
    vp_token: str
    credential_requirements: list[CredentialRequirementModel] = []
    trust_profile_id: str | None = None
    compliance_profile_id: str | None = None
    nonce: str | None = None
    audience: str | None = None
    context: dict = {}


# =============================================================================
# API Models - Verification Flow (async wallet interaction)
# =============================================================================

class StartVerificationFlowRequest(BaseModel):
    presentation_policy_id: str
    trust_profile_id: str | None = None
    deployment_profile_id: str | None = None
    external_reference: str | None = None
    callback_url: str | None = None
    expiry_minutes: int = 15


class VerificationRequestResponse(BaseModel):
    instance_id: str
    request_uri: str
    qr_code_data: str
    presentation_policy_id: str
    nonce: str
    expires_at: str
    status: str


class SubmitVerificationRequest(BaseModel):
    vp_token: str
    presentation_submission: dict | None = None


class VerificationResultResponse(BaseModel):
    instance_id: str
    status: str
    result: str
    decision: str
    decision_reason: str
    verified_claims: dict
    evaluation_timestamp: str


# =============================================================================
# API Models - Organization
# =============================================================================

class OrganizationCreate(BaseModel):
    name: str
    display_name: str | None = None


class OrganizationResponse(BaseModel):
    id: str
    name: str
    display_name: str | None
    slug: str | None = None
    description: str | None = None
    org_type: str | None = None
    status: str | None = None
    contact_email: str | None = None
    contact_phone: str | None = None
    website: str | None = None
    join_mechanism: str | None = None
    requires_approval: bool | None = None
    is_discoverable: bool | None = None
    created_at: str
    updated_at: str


# =============================================================================
# API Models - Issuance
# =============================================================================

class IssuanceCreate(BaseModel):
    """Create an issuance request."""
    organization_id: str
    credential_template_id: str
    subject_did: str | None = None
    application_id: str | None = None
    claims: dict = {}


class IssuanceResponse(BaseModel):
    """Issuance response."""
    id: str
    organization_id: str
    credential_template_id: str
    subject_did: str | None
    application_id: str | None
    status: str
    credential_offer_uri: str | None
    issued_credential: dict | None = None
    created_at: str


# =============================================================================
# API Models - Application Template (How users apply for credentials)
# =============================================================================

from enum import Enum


class EvidenceType(str, Enum):
    """Types of evidence applicants can provide."""
    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"
    ID_CARD = "id_card"
    SELFIE = "selfie"
    LIVENESS_CHECK = "liveness_check"
    PROOF_OF_ADDRESS = "proof_of_address"
    EMAIL_VERIFICATION = "email_verification"
    PHONE_VERIFICATION = "phone_verification"
    BIOMETRIC_SCAN = "biometric_scan"
    DOCUMENT_SCAN = "document_scan"


class ApprovalStrategy(str, Enum):
    """How applications are approved."""
    AUTO = "auto"
    MANUAL = "manual"
    RULES_BASED = "rules_based"


class FormFieldModel(BaseModel):
    """Form field definition."""
    field_id: str
    field_type: str
    label: str
    required: bool = True
    options: list[str] = []
    validation_pattern: str | None = None


class ClaimCollectionModel(BaseModel):
    """Claim collection rule."""
    claim_name: str
    source: str  # form_field, evidence, derived
    source_field: str | None = None
    required: bool = True


class NotificationConfigModel(BaseModel):
    """Notification configuration."""
    send_confirmation: bool = True
    send_status_updates: bool = True
    email_template_id: str | None = None


class ApplicationUIConfigModel(BaseModel):
    """UI configuration for application."""
    theme: str = "default"
    logo_url: str | None = None
    instructions: str | None = None


class ApplicationTemplateCreate(BaseModel):
    """Create an Application Template (user-facing workflow definition).
    
    Application Template defines what users fill out to apply for credentials.
    This is a PURE USER-FACING entity with NO cryptographic concerns.
    It defines the application workflow, not the credential structure.
    """
    organization_id: str
    name: str
    description: str | None = None
    credential_template_id: str | None = None  # Added
    
    # Evidence collection requirements - list of string identifiers like ["drivers_license", "selfie"]
    evidence_requirements: Any = Field(
        default=[],
        description="List of evidence type strings required for this application"
    )
    
    # Form field definitions (what users fill out)
    form_fields: List[dict] = Field(default_factory=list)  # Simplified to dict only
    
    # Claim collection (how to gather claim values from applicant)
    claim_collection_rules: List[dict] = Field(default_factory=list)  # Simplified to dict only
    
    # Workflow configuration
    approval_strategy: str = "auto"  # Changed from enum to string
    application_validity_days: int = 30  # How long application remains valid
    auto_approval_rules: list[dict] = []  # Added to match backend
    
    # Notification settings
    notifications: NotificationConfigModel | None = None
    notification_config: dict = {}  # Added as alternative
    
    # UI/UX configuration
    ui_config: ApplicationUIConfigModel | dict | None = None  # Allow dict too


class ApplicationTemplateResponse(BaseModel):
    """Application Template response."""
    id: str
    organization_id: str
    name: str
    description: str | None
    credential_template_id: str | None  # Added
    status: str
    
    # Evidence collection
    evidence_requirements: list[str]
    
    # Form configuration
    form_fields: list[dict]
    
    # Claim collection
    claim_collection_rules: list[dict]
    
    # Workflow
    approval_strategy: str
    application_validity_days: int
    auto_approval_rules: list[dict] = []  # Added
    
    # Notifications
    notifications: dict | None = None
    notification_config: dict = {}  # Added as alternative
    
    # UI configuration
    ui_config: dict | None
    
    # Metadata
    created_at: str
    updated_at: str
    version: int | None = None  # Optional


# =============================================================================
# API Models - Application (Instances of Application Templates)
# =============================================================================

class ApplicationCreate(BaseModel):
    """Create an Application from an Application Template."""
    application_template_id: str
    applicant_data: dict = {}  # Form data from applicant


class EvidenceSubmission(BaseModel):
    """Submit evidence for an application."""
    evidence_type: str  # Changed from EvidenceType enum to string for flexibility
    evidence_data: dict = {}  # Changed from 'data' to 'evidence_data' to match backend


class ApplicationResponse(BaseModel):
    """Application response."""
    id: str
    organization_id: str
    application_template_id: str
    applicant_identifier: str  # Changed from subject_id
    form_data: dict  # Changed from status
    evidence_submissions: list[dict]  # Added
    status: str  # pending, under_review, approved, rejected
    review_notes: str | None
    reviewer_id: str | None = None  # Added
    submitted_at: str  # Added
    reviewed_at: str | None = None  # Added
    expires_at: str  # Added
    issuance_transaction_id: str | None = None  # Added
    created_at: str | None = None  # Optional for compatibility
    updated_at: str | None = None  # Optional for compatibility


# =============================================================================
# API Models - Audit Events (Immutable log)
# =============================================================================

class AuditEventResponse(BaseModel):
    """Audit event response."""
    id: str
    organization_id: str
    timestamp: str
    actor_id: str | None
    actor_type: str  # user, system, api_key
    action: str  # created, updated, deleted, activated, etc.
    resource_type: str  # trust_profile, credential_template, etc.
    resource_id: str
    resource_name: str | None
    changes: dict | None
    metadata: dict


# =============================================================================
# API Models - Lanes (Device groupings for Deployment Profiles)
# =============================================================================

class LaneCreate(BaseModel):
    """Create a Lane (logical device grouping) within a Deployment Profile."""
    name: str
    description: str | None = None
    location: str | None = None
    device_type: str = "kiosk"  # kiosk, mobile, gate, checkpoint


class LaneResponse(BaseModel):
    """Lane response."""
    id: str
    deployment_profile_id: str
    name: str
    description: str | None
    location: str | None
    device_type: str
    device_count: int
    status: str
    created_at: str
    updated_at: str


class DeviceAssignment(BaseModel):
    """Assign a device to a lane."""
    device_id: str
    device_name: str | None = None


# =============================================================================
# Proxy Implementation
# =============================================================================

_registry: ServiceRegistry | None = None
_http_client: httpx.AsyncClient | None = None


def get_registry() -> ServiceRegistry:
    if _registry is None:
        raise RuntimeError("Service not configured")
    return _registry


def get_http_client() -> httpx.AsyncClient:
    if _http_client is None:
        raise RuntimeError("Service not configured")
    return _http_client


async def proxy_request(
    request: Request,
    service_url: str,
    path: str,
    inject_params: dict | None = None,
    body_override: bytes | None = None,
) -> Response:
    """Proxy a request to a backend service.

    Args:
        request: The incoming FastAPI request.
        service_url: Base URL of the target micro-service.
        path: Path to append to the service URL.
        inject_params: Extra query parameters to merge into the forwarded URL.
            These are appended *in addition to* any query params already present
            on the incoming request, and they override duplicate keys.
    """
    client = get_http_client()
    
    # Build target URL
    url = f"{service_url}{path}"
    # Forward incoming query string, then overlay inject_params
    from urllib.parse import parse_qsl, urlencode
    qs_pairs = list(parse_qsl(request.url.query or ""))
    if inject_params:
        incoming_keys = {k for k, _ in qs_pairs}
        for k, v in inject_params.items():
            if k not in incoming_keys:
                qs_pairs.append((k, v))
    if qs_pairs:
        url = f"{url}?{urlencode(qs_pairs)}"
    
    # Get request body if present
    body = body_override if body_override is not None else await request.body()
    
    # Forward headers (excluding hop-by-hop headers)
    excluded_headers = {"host", "connection", "keep-alive", "transfer-encoding"}
    # Also strip content-length when body_override is provided (size may differ)
    if body_override is not None:
        excluded_headers.add("content-length")
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in excluded_headers
    }
    
    # Inject user context headers from middleware
    if hasattr(request.state, "user_id") and request.state.user_id:
        headers["X-User-Id"] = request.state.user_id
    
    if hasattr(request.state, "user_email") and request.state.user_email:
        headers["X-User-Email"] = request.state.user_email
    
    if hasattr(request.state, "user_domain") and request.state.user_domain:
        headers["X-User-Domain"] = request.state.user_domain
    
    try:
        response = await client.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body,
            timeout=30.0,
        )
        
        # Return proxied response
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers={
                k: v for k, v in response.headers.items()
                if k.lower() not in ("content-encoding", "transfer-encoding", "content-length")
            },
            media_type=response.headers.get("content-type"),
        )
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="Service unavailable")
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Service timeout")


# =============================================================================
# Documented API Routes
# =============================================================================

# Trust Profile routes
trust_profile_router = APIRouter(prefix="/v1/trust-profiles", tags=["Trust Profiles"])


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
async def update_trust_profile(profile_id: str, body: TrustProfileCreate, request: Request) -> Response:
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
async def update_trusted_issuer(profile_id: str, issuer_id: str, body: TrustedIssuerCreate, request: Request) -> Response:
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


# Revocation Profile routes
revocation_profile_router = APIRouter(prefix="/v1/revocation-profiles", tags=["Revocation Profiles"])


@revocation_profile_router.post("", summary="Create Revocation Profile")
async def create_revocation_profile(request: Request) -> Response:
    """Create a new Revocation Profile for format-agnostic revocation configuration."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, "/v1/revocation-profiles")


@revocation_profile_router.get("", summary="List Revocation Profiles")
async def list_revocation_profiles(request: Request) -> Response:
    """List all Revocation Profiles."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, "/v1/revocation-profiles")


@revocation_profile_router.get("/{profile_id}", summary="Get Revocation Profile")
async def get_revocation_profile(profile_id: str, request: Request) -> Response:
    """Get a Revocation Profile by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/revocation-profiles/{profile_id}")


@revocation_profile_router.post("/{profile_id}/activate", summary="Activate Revocation Profile")
async def activate_revocation_profile(profile_id: str, request: Request) -> Response:
    """Activate a Revocation Profile for use in credential issuance."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/revocation-profiles/{profile_id}/activate")


@revocation_profile_router.delete("/{profile_id}", summary="Delete Revocation Profile")
async def delete_revocation_profile(profile_id: str, request: Request) -> Response:
    """Delete a Revocation Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("revocation-profiles")
    return await proxy_request(request, service_url, f"/v1/revocation-profiles/{profile_id}")


# Credential Template routes
credential_template_router = APIRouter(prefix="/v1/credential-templates", tags=["Credential Templates"])


@credential_template_router.post("", response_model=CredentialTemplateResponse, summary="Create Credential Template")
async def create_credential_template(body: CredentialTemplateCreate, request: Request) -> Response:
    """Create a new Credential Template (master issuance configuration).
    
    Credential Template is the complete definition for issuing credentials, combining:
    - Schema/claims definition
    - Compliance Profile reference (format, framework)
    - Optional Application Template reference (for application-based issuance)
    - Cryptographic configuration (keys, certs, DIDs)
    - Validity and revocation settings
    """
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, "/v1/credential-templates", body_override=body.model_dump_json().encode())


@credential_template_router.get("", response_model=list[CredentialTemplateResponse], summary="List Credential Templates")
async def list_credential_templates(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Credential Templates for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, "/v1/credential-templates")


@credential_template_router.get("/{template_id}", response_model=CredentialTemplateResponse, summary="Get Credential Template")
async def get_credential_template(template_id: str, request: Request) -> Response:
    """Get a Credential Template by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}")


@credential_template_router.put("/{template_id}", response_model=CredentialTemplateResponse, summary="Update Credential Template")
async def update_credential_template(template_id: str, body: CredentialTemplateCreate, request: Request) -> Response:
    """Update a Credential Template."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}")


@credential_template_router.delete("/{template_id}", summary="Delete Credential Template")
async def delete_credential_template(template_id: str, request: Request) -> Response:
    """Delete a Credential Template."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}")


@credential_template_router.post("/{template_id}/validate-artifacts", summary="Validate Cryptographic Artifacts")
async def validate_credential_template_artifacts(template_id: str, request: Request) -> Response:
    """Validate that all required cryptographic artifacts are properly configured.
    
    Checks:
    - Signing key availability
    - Certificate chain validity (for mDoc)
    - DID resolution (for DID-based credentials)
    - Compliance with selected Compliance Profile requirements
    """
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}/validate-artifacts")


@credential_template_router.get("/{template_id}/application-template", summary="Get Linked Application Template")
async def get_credential_template_application_template(template_id: str, request: Request) -> Response:
    """Get the Application Template linked to this Credential Template (if any)."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/credential-templates/{template_id}/application-template")


# Wallet Registry routes (proxied to credential-template service)
wallet_registry_router = APIRouter(prefix="/v1/wallet-registry", tags=["Wallet Registry"])


@wallet_registry_router.get("", summary="List Wallet Registry")
async def list_wallet_registry(request: Request) -> Response:
    """List all wallets in the global registry."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, "/v1/wallet-registry")


@wallet_registry_router.get("/{wallet_id}", summary="Get Wallet")
async def get_wallet_registry_entry(wallet_id: str, request: Request) -> Response:
    """Get a wallet registry entry by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/wallet-registry/{wallet_id}")


@wallet_registry_router.post("", summary="Create Wallet Entry")
async def create_wallet_registry_entry(request: Request) -> Response:
    """Create a new wallet registry entry."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, "/v1/wallet-registry")


@wallet_registry_router.patch("/{wallet_id}", summary="Update Wallet Entry")
async def update_wallet_registry_entry(wallet_id: str, request: Request) -> Response:
    """Update a wallet registry entry."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/wallet-registry/{wallet_id}")


@wallet_registry_router.delete("/{wallet_id}", summary="Delete Wallet Entry")
async def delete_wallet_registry_entry(wallet_id: str, request: Request) -> Response:
    """Delete a wallet registry entry."""
    registry = get_registry()
    service_url = registry.get_service_url("credential-templates")
    return await proxy_request(request, service_url, f"/v1/wallet-registry/{wallet_id}")


# Compliance Profile routes
compliance_profile_router = APIRouter(prefix="/v1/compliance-profiles", tags=["Compliance Profiles"])


@compliance_profile_router.post("", response_model=ComplianceProfileResponse, summary="Create Compliance Profile")
async def create_compliance_profile(body: ComplianceProfileCreate, request: Request) -> Response:
    """Create a new Compliance Profile defining regulatory rules."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, "/v1/compliance-profiles")


@compliance_profile_router.get("", response_model=list[ComplianceProfileResponse], summary="List Compliance Profiles")
async def list_compliance_profiles(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Compliance Profiles for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, "/v1/compliance-profiles")


@compliance_profile_router.get("/{profile_id}", response_model=ComplianceProfileResponse, summary="Get Compliance Profile")
async def get_compliance_profile(profile_id: str, request: Request) -> Response:
    """Get a Compliance Profile by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, f"/v1/compliance-profiles/{profile_id}")


@compliance_profile_router.post("/{profile_id}/activate", response_model=ComplianceProfileResponse, summary="Activate Compliance Profile")
async def activate_compliance_profile(profile_id: str, request: Request) -> Response:
    """Activate a Compliance Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, f"/v1/compliance-profiles/{profile_id}/activate")


@compliance_profile_router.put("/{profile_id}", response_model=ComplianceProfileResponse, summary="Update Compliance Profile")
async def update_compliance_profile(profile_id: str, body: ComplianceProfileCreate, request: Request) -> Response:
    """Update a Compliance Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, f"/v1/compliance-profiles/{profile_id}")


@compliance_profile_router.delete("/{profile_id}", summary="Delete Compliance Profile")
async def delete_compliance_profile(profile_id: str, request: Request) -> Response:
    """Delete a Compliance Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("compliance-profiles")
    return await proxy_request(request, service_url, f"/v1/compliance-profiles/{profile_id}")


# Presentation Policy routes
presentation_policy_router = APIRouter(prefix="/v1/presentation-policies", tags=["Presentation Policies"])


@presentation_policy_router.post("", response_model=PresentationPolicyResponse, summary="Create Presentation Policy")
async def create_presentation_policy(body: PresentationPolicyCreate, request: Request) -> Response:
    """Create a new Presentation Policy defining what credentials to request."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, "/v1/presentation-policies")


@presentation_policy_router.get("", response_model=list[PresentationPolicyResponse], summary="List Presentation Policies")
async def list_presentation_policies(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Presentation Policies for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, "/v1/presentation-policies")


@presentation_policy_router.get("/{policy_id}", response_model=PresentationPolicyResponse, summary="Get Presentation Policy")
async def get_presentation_policy(policy_id: str, request: Request) -> Response:
    """Get a Presentation Policy by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, f"/v1/presentation-policies/{policy_id}")


@presentation_policy_router.post("/{policy_id}/activate", response_model=PresentationPolicyResponse, summary="Activate Presentation Policy")
async def activate_presentation_policy(policy_id: str, request: Request) -> Response:
    """Activate a Presentation Policy for use in verification."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, f"/v1/presentation-policies/{policy_id}/activate")


@presentation_policy_router.put("/{policy_id}", response_model=PresentationPolicyResponse, summary="Update Presentation Policy")
async def update_presentation_policy(policy_id: str, body: PresentationPolicyCreate, request: Request) -> Response:
    """Update a Presentation Policy."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, f"/v1/presentation-policies/{policy_id}")


@presentation_policy_router.delete("/{policy_id}", summary="Delete Presentation Policy")
async def delete_presentation_policy(policy_id: str, request: Request) -> Response:
    """Delete a Presentation Policy."""
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, f"/v1/presentation-policies/{policy_id}")


@presentation_policy_router.post("/{policy_id}/evaluate", response_model=PolicyEvaluationResponse, summary="Evaluate Presentation Against Policy")
async def evaluate_presentation_with_policy(policy_id: str, body: EvaluatePresentationRequest, request: Request) -> Response:
    """
    Evaluate a verifiable presentation against a saved policy.
    
    This is the primary endpoint for stateless verification. Submit a VP token
    along with a policy ID, and receive an immediate evaluation result.
    
    The policy defines what credentials and claims are required, and this endpoint
    executes that policy against the submitted presentation.
    """
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, f"/v1/presentation-policies/{policy_id}/evaluate")


@presentation_policy_router.post("/evaluate", response_model=PolicyEvaluationResponse, summary="Evaluate Presentation with Inline Policy")
async def evaluate_presentation_inline(body: EvaluateInlineRequest, request: Request) -> Response:
    """
    Evaluate a verifiable presentation with an inline (ad-hoc) policy.
    
    Use this for one-off verifications where you don't need a saved policy.
    Provide both the policy definition and the VP token in the request body.
    """
    registry = get_registry()
    service_url = registry.get_service_url("presentation-policies")
    return await proxy_request(request, service_url, "/v1/presentation-policies/evaluate")


# Deployment Profile routes
deployment_profile_router = APIRouter(prefix="/v1/deployment-profiles", tags=["Deployment Profiles"])


@deployment_profile_router.post("", response_model=DeploymentProfileResponse, summary="Create Deployment Profile")
async def create_deployment_profile(body: DeploymentProfileCreate, request: Request) -> Response:
    """Create a new Deployment Profile for runtime configuration."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, "/v1/deployment-profiles")


@deployment_profile_router.get("", response_model=list[DeploymentProfileResponse], summary="List Deployment Profiles")
async def list_deployment_profiles(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Deployment Profiles for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, "/v1/deployment-profiles")


@deployment_profile_router.get("/{profile_id}", response_model=DeploymentProfileResponse, summary="Get Deployment Profile")
async def get_deployment_profile(profile_id: str, request: Request) -> Response:
    """Get a Deployment Profile by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}")


@deployment_profile_router.post("/{profile_id}/activate", response_model=DeploymentProfileResponse, summary="Activate Deployment Profile")
async def activate_deployment_profile(profile_id: str, request: Request) -> Response:
    """Activate a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/activate")


@deployment_profile_router.put("/{profile_id}", response_model=DeploymentProfileResponse, summary="Update Deployment Profile")
async def update_deployment_profile(profile_id: str, body: DeploymentProfileCreate, request: Request) -> Response:
    """Update a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}")


@deployment_profile_router.delete("/{profile_id}", summary="Delete Deployment Profile")
async def delete_deployment_profile(profile_id: str, request: Request) -> Response:
    """Delete a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}")


@deployment_profile_router.post("/{profile_id}/generate-api-key", summary="Generate API Key")
async def generate_deployment_api_key(profile_id: str, request: Request) -> Response:
    """Generate a new API key for the Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/generate-api-key")


# Lanes (nested under Deployment Profiles)
@deployment_profile_router.post("/{profile_id}/lanes", response_model=LaneResponse, summary="Create Lane")
async def create_lane(profile_id: str, body: LaneCreate, request: Request) -> Response:
    """Create a Lane (logical device grouping) within a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes")


@deployment_profile_router.get("/{profile_id}/lanes", response_model=list[LaneResponse], summary="List Lanes")
async def list_lanes(profile_id: str, request: Request) -> Response:
    """List Lanes for a Deployment Profile."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes")


@deployment_profile_router.get("/{profile_id}/lanes/{lane_id}", response_model=LaneResponse, summary="Get Lane")
async def get_lane(profile_id: str, lane_id: str, request: Request) -> Response:
    """Get a Lane by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}")


@deployment_profile_router.put("/{profile_id}/lanes/{lane_id}", response_model=LaneResponse, summary="Update Lane")
async def update_lane(profile_id: str, lane_id: str, body: LaneCreate, request: Request) -> Response:
    """Update a Lane."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}")


@deployment_profile_router.delete("/{profile_id}/lanes/{lane_id}", summary="Delete Lane")
async def delete_lane(profile_id: str, lane_id: str, request: Request) -> Response:
    """Delete a Lane."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}")


@deployment_profile_router.post("/{profile_id}/lanes/{lane_id}/devices", summary="Assign Device to Lane")
async def assign_device_to_lane(profile_id: str, lane_id: str, body: DeviceAssignment, request: Request) -> Response:
    """Assign a device to a Lane."""
    registry = get_registry()
    service_url = registry.get_service_url("deployment-profiles")
    return await proxy_request(request, service_url, f"/v1/deployment-profiles/{profile_id}/lanes/{lane_id}/devices")


# Flow routes
flow_router = APIRouter(prefix="/v1/flows", tags=["Flows"])


@flow_router.post("/definitions", response_model=FlowDefinitionResponse, summary="Create Flow Definition")
async def create_flow_definition(body: FlowDefinitionCreate, request: Request) -> Response:
    """Create a new Flow Definition for orchestrating credential operations."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/definitions")


@flow_router.get("/definitions", response_model=list[FlowDefinitionResponse], summary="List Flow Definitions")
async def list_flow_definitions(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List all Flow Definitions for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/definitions")


@flow_router.get("/definitions/{flow_id}", response_model=FlowDefinitionResponse, summary="Get Flow Definition")
async def get_flow_definition(flow_id: str, request: Request) -> Response:
    """Get a Flow Definition by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/definitions/{flow_id}")


@flow_router.post("/definitions/{flow_id}/activate", response_model=FlowDefinitionResponse, summary="Activate Flow")
async def activate_flow_definition(flow_id: str, request: Request) -> Response:
    """Activate a Flow Definition."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/definitions/{flow_id}/activate")


@flow_router.put("/definitions/{flow_id}", response_model=FlowDefinitionResponse, summary="Update Flow Definition")
async def update_flow_definition(flow_id: str, body: FlowDefinitionCreate, request: Request) -> Response:
    """Update a Flow Definition."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/definitions/{flow_id}")


@flow_router.delete("/definitions/{flow_id}", summary="Delete Flow Definition")
async def delete_flow_definition(flow_id: str, request: Request) -> Response:
    """Delete a Flow Definition."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/definitions/{flow_id}")


@flow_router.post("/instances", response_model=FlowInstanceResponse, summary="Start Flow Instance")
async def start_flow_instance(body: FlowInstanceCreate, request: Request) -> Response:
    """Start a new Flow Instance."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/instances")


@flow_router.get("/instances", response_model=list[FlowInstanceResponse], summary="List Flow Instances")
async def list_flow_instances(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List Flow Instances for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/instances")


@flow_router.get("/instances/{instance_id}", response_model=FlowInstanceResponse, summary="Get Flow Instance")
async def get_flow_instance(instance_id: str, request: Request) -> Response:
    """Get a Flow Instance by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/instances/{instance_id}")


@flow_router.post("/instances/{instance_id}/advance", response_model=FlowInstanceResponse, summary="Advance Flow")
async def advance_flow_instance(instance_id: str, request: Request) -> Response:
    """Advance a Flow Instance to the next step."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/instances/{instance_id}/advance")


@flow_router.post("/verify", response_model=VerificationRequestResponse, summary="Start Verification Flow")
async def start_verification_flow(body: StartVerificationFlowRequest, request: Request) -> Response:
    """
    Start a verification flow for async wallet interactions.
    
    Creates a flow instance with a QR code / request_uri for wallet scanning.
    For stateless verification, use POST /v1/presentation-policies/{id}/evaluate instead.
    """
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, "/v1/flows/verify")


@flow_router.get("/instances/{instance_id}/request", summary="Get Verification Request Object")
async def get_flow_verification_request(instance_id: str, request: Request) -> Response:
    """Get the OID4VP request object (for wallet to fetch via request_uri)."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/instances/{instance_id}/request")


@flow_router.post("/instances/{instance_id}/submit", response_model=VerificationResultResponse, summary="Submit Verification")
async def submit_flow_verification(instance_id: str, request: Request) -> Response:
    """Submit a VP token to complete a verification flow. Accepts JSON or form-encoded data."""
    registry = get_registry()
    service_url = registry.get_service_url("flows")
    return await proxy_request(request, service_url, f"/v1/flows/instances/{instance_id}/submit")


# Issuance routes
issuance_router = APIRouter(prefix="/v1/issuance", tags=["Issuance"])


@issuance_router.post("", response_model=IssuanceResponse, summary="Create Issuance")
async def create_issuance(body: IssuanceCreate, request: Request) -> Response:
    """Initiate credential issuance for a subject (directly or via Application)."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/initiate")


@issuance_router.get("", response_model=list[IssuanceResponse], summary="List Issuances")
async def list_issuances(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List issuance records for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/transactions")


@issuance_router.get("/{issuance_id}", response_model=IssuanceResponse, summary="Get Issuance")
async def get_issuance(issuance_id: str, request: Request) -> Response:
    """Get an issuance record by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issuance/transactions/{issuance_id}")


@issuance_router.get("/offers/{tx_id}", summary="Get Credential Offer")
async def get_credential_offer(tx_id: str, request: Request) -> Response:
    """
    Get OID4VCI credential offer for wallet integration.
    
    This endpoint is called by wallets when resolving a credential_offer_uri.
    No authentication required as the pre-authorized code serves as the auth token.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/issuance/offers/{tx_id}")


@issuance_router.post("/token", summary="Exchange Token")
async def exchange_token(request: Request) -> Response:
    """
    OID4VCI Token Endpoint.
    
    Exchange pre-authorized code for access token. This is called by wallets
    during the credential issuance flow.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/token")


@issuance_router.post("/credential", summary="Issue Credential")
async def issue_credential(request: Request) -> Response:
    """
    OID4VCI Credential Endpoint.
    
    Issue a credential after successful token exchange. This is called by wallets
    to receive the actual credential.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/issuance/credential")


# Application Template routes (how users apply for credentials)
application_template_router = APIRouter(prefix="/v1/application-templates", tags=["Application Templates"])


@application_template_router.post("", response_model=ApplicationTemplateResponse, summary="Create Application Template")
async def create_application_template(body: ApplicationTemplateCreate, request: Request) -> Response:
    """Create an Application Template defining how users apply for credentials."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/application-templates")


@application_template_router.get("", response_model=list[ApplicationTemplateResponse], summary="List Application Templates")
async def list_application_templates(
    organization_id: str = Query(..., description="Organization ID"),
    request: Request = None,
) -> Response:
    """List Application Templates for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/application-templates")


@application_template_router.get("/{template_id}", response_model=ApplicationTemplateResponse, summary="Get Application Template")
async def get_application_template(template_id: str, request: Request) -> Response:
    """Get an Application Template by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}")


@application_template_router.put("/{template_id}", response_model=ApplicationTemplateResponse, summary="Update Application Template")
async def update_application_template(template_id: str, body: ApplicationTemplateCreate, request: Request) -> Response:
    """Update an Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}")


@application_template_router.delete("/{template_id}", summary="Delete Application Template")
async def delete_application_template(template_id: str, request: Request) -> Response:
    """Delete an Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}")


@application_template_router.post("/{template_id}/activate", response_model=ApplicationTemplateResponse, summary="Activate Application Template")
async def activate_application_template(template_id: str, request: Request) -> Response:
    """Activate an Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/application-templates/{template_id}/activate")


@application_template_router.post("/validate-artifacts", summary="Validate Issuer Artifacts")
async def validate_application_artifacts(request: Request) -> Response:
    """Validate issuer artifacts (keys, certificates, DIDs) for an Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/application-templates/validate-artifacts")


# Application routes (instances of Application Templates)
application_router = APIRouter(prefix="/v1/applications", tags=["Applications"])


@application_router.post("", response_model=ApplicationResponse, summary="Create Application")
async def create_application(body: ApplicationCreate, request: Request) -> Response:
    """Create an Application from an Application Template."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/applications")


@application_router.get("", response_model=list[ApplicationResponse], summary="List Applications")
async def list_applications(
    organization_id: str = Query(..., description="Organization ID"),
    status: str | None = Query(None, description="Filter by status"),
    request: Request = None,
) -> Response:
    """List Applications for an organization."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, "/v1/applications")


@application_router.get("/{application_id}", response_model=ApplicationResponse, summary="Get Application")
async def get_application(application_id: str, request: Request) -> Response:
    """Get an Application by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}")


@application_router.post("/{application_id}/submit-evidence", response_model=ApplicationResponse, summary="Submit Evidence")
async def submit_application_evidence(application_id: str, body: EvidenceSubmission, request: Request) -> Response:
    """Submit evidence for an Application."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/submit-evidence")


@application_router.post("/{application_id}/approve", response_model=ApplicationResponse, summary="Approve Application")
async def approve_application(application_id: str, request: Request) -> Response:
    """Approve an Application for credential issuance."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/approve")


@application_router.post("/{application_id}/reject", response_model=ApplicationResponse, summary="Reject Application")
async def reject_application(application_id: str, request: Request) -> Response:
    """Reject an Application."""
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/reject")


@application_router.post("/{application_id}/issuance-offer", summary="Generate Wallet Invite")
async def generate_issuance_offer(application_id: str, request: Request) -> Response:
    """Generate (or refresh) a wallet credential offer for an approved application.

    Returns offer_url, qr_payload, wallets deep-link list, email_payload, and expires_at.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/issuance-offer")


@application_router.get("/{application_id}/issuance-offer", summary="Get Wallet Invite (Applicant)")
async def get_issuance_offer(application_id: str, request: Request) -> Response:
    """Retrieve the current wallet credential offer for an application (applicant-facing).

    Returns 404 until an admin has generated the offer via POST.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/issuance-offer")


@application_router.get("/{application_id}/issuance-events", summary="List Issuance Events (Admin)")
async def get_application_issuance_events(application_id: str, request: Request) -> Response:
    """List all lifecycle events for an application (admin audit timeline).

    Returns events in chronological order covering the full issuance lifecycle:
    offer_generated, offer_viewed, offer_expired, credential_issued.
    """
    registry = get_registry()
    service_url = registry.get_service_url("issuance")
    return await proxy_request(request, service_url, f"/v1/applications/{application_id}/issuance-events")


# Notification routes
notification_router = APIRouter(prefix="/v1/notifications", tags=["Notifications"])


@notification_router.api_route("", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], summary="Notifications")
@notification_router.api_route("/{subpath:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], summary="Notifications")
async def proxy_notifications(request: Request, subpath: str = "") -> Response:
    """Proxy all notification routes to notification service."""
    registry = get_registry()
    service_url = registry.get_service_url("notifications")
    target_path = "/v1/notifications"
    if subpath:
        target_path = f"{target_path}/{subpath}"
    return await proxy_request(request, service_url, target_path)


# Applicant routes (applicant profiles)
applicant_router = APIRouter(prefix="/v1/applicants", tags=["Applicants"])


@applicant_router.post("", summary="Create Applicant")
async def create_applicant(request: Request) -> Response:
    """Create an applicant profile."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/applicants")


@applicant_router.get("/by-user/{user_id}", summary="Get Applicant by User ID")
async def get_applicant_by_user(user_id: str, request: Request) -> Response:
    """Get an applicant profile by user ID."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/by-user/{user_id}")


@applicant_router.get("/profiles/{applicant_id}", summary="Get Applicant")
async def get_applicant(applicant_id: str, request: Request) -> Response:
    """Get an applicant profile by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/profiles/{applicant_id}")


@applicant_router.patch("/profiles/{applicant_id}", summary="Update Applicant")
async def update_applicant(applicant_id: str, request: Request) -> Response:
    """Update an applicant profile."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/profiles/{applicant_id}")


@applicant_router.get("", summary="List Applicants")
async def list_applicants(
    organization_id: str = Query(None, description="Filter by organization"),
    request: Request = None,
) -> Response:
    """List applicant profiles."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/applicants")


@applicant_router.post("/applications", summary="Create Application")
async def create_applicant_application(request: Request) -> Response:
    """Create an application for a credential."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/applicants/applications")


@applicant_router.get("/org-applications", summary="List Organization Applications")
async def list_applicant_applications(request: Request) -> Response:
    """List applications for an organization queue."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, "/v1/applicants/org-applications")


@applicant_router.get("/applications/{application_id}", summary="Get Application")
async def get_applicant_application(application_id: str, request: Request) -> Response:
    """Get an application by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}")


@applicant_router.post("/applications/{application_id}/submit", summary="Submit Application")
async def submit_applicant_application(application_id: str, request: Request) -> Response:
    """Submit an application for review."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/submit")


@applicant_router.patch("/applications/{application_id}", summary="Update Application")
async def update_applicant_application(application_id: str, request: Request) -> Response:
    """Update application fields (admin)."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}")


@applicant_router.post("/applications/{application_id}/review", summary="Review Application")
async def review_applicant_application(application_id: str, request: Request) -> Response:
    """Review (approve/reject) an application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/review")


@applicant_router.post("/applications/{application_id}/issue", summary="Issue Application")
async def issue_applicant_application(application_id: str, request: Request) -> Response:
    """Issue a credential for an approved application."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/applications/{application_id}/issue")


@applicant_router.post("/profiles/{applicant_id}/biometrics", summary="Enroll Biometric")
async def enroll_applicant_biometric(applicant_id: str, request: Request) -> Response:
    """Enroll biometric data for an applicant."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/profiles/{applicant_id}/biometrics")


@applicant_router.get("/profiles/{applicant_id}/applications", summary="Get Applicant Applications")
async def get_applicant_applications(applicant_id: str, request: Request) -> Response:
    """Get applications for a specific applicant."""
    registry = get_registry()
    service_url = registry.get_service_url("applicant")
    return await proxy_request(request, service_url, f"/v1/applicants/profiles/{applicant_id}/applications")


# Organization routes
organization_router = APIRouter(prefix="/v1/organizations", tags=["Organizations"])


@organization_router.post("", response_model=OrganizationResponse, summary="Create Organization")
async def create_organization(body: OrganizationCreate, request: Request) -> Response:
    """Create a new Organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations")


@organization_router.get("", response_model=list[OrganizationResponse], summary="List Organizations")
async def list_organizations(request: Request) -> Response:
    """List Organizations."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations")


@organization_router.get("/discover", response_model=list[OrganizationResponse], summary="Discover Organizations")
async def discover_organizations(request: Request) -> Response:
    """Discover publicly available organizations."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations/discover")


@organization_router.get("/mine", response_model=list[dict], summary="My Organizations")
async def get_my_organizations(request: Request) -> Response:
    """Get organizations the current user belongs to with membership details."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations/mine")


@organization_router.get("/{org_id}", response_model=OrganizationResponse, summary="Get Organization")
async def get_organization(org_id: str, request: Request) -> Response:
    """Get an Organization by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}", inject_params={"organization_id": org_id})


@organization_router.put("/{org_id}", response_model=OrganizationResponse, summary="Update Organization")
async def update_organization(org_id: str, body: OrganizationCreate, request: Request) -> Response:
    """Update an Organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}", inject_params={"organization_id": org_id})


@organization_router.delete("/{org_id}", summary="Delete Organization")
async def delete_organization(org_id: str, request: Request) -> Response:
    """Delete an Organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}", inject_params={"organization_id": org_id})


# Join by Code
class JoinByCodeRequest(BaseModel):
    """Request to join an organization by code."""
    code: str = Field(description="8-character join code")


class JoinByCodeResponse(BaseModel):
    """Response after joining an organization."""
    organization: OrganizationResponse
    membership: dict = Field(description="Member information")


class ValidateJoinCodeResponse(BaseModel):
    """Response for join code validation."""
    valid: bool
    organization_id: str | None = None
    organization_name: str | None = None
    expired: bool = False
    message: str | None = None


class InvitationValidateResponse(BaseModel):
    """Response for invitation validation."""
    valid: bool
    organization_id: str | None = None
    organization_name: str | None = None
    role: str | None = None
    expired: bool = False
    message: str | None = None


class InvitationAcceptRequest(BaseModel):
    """Request to accept an invitation."""
    token: str


class InvitationAcceptResponse(BaseModel):
    """Response for invitation acceptance."""
    success: bool
    organization_id: str | None = None
    organization_name: str | None = None
    role: str | None = None
    message: str


@organization_router.post("/join/code", response_model=JoinByCodeResponse, summary="Join Organization by Code", status_code=201)
async def join_by_code(body: JoinByCodeRequest, request: Request) -> Response:
    """Join an organization using a join code."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations/join/code")


@organization_router.get("/join/code/validate", response_model=ValidateJoinCodeResponse, summary="Validate Join Code")
async def validate_join_code(request: Request) -> Response:
    """Validate join/invitation code without joining."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/organizations/join/code/validate")


@organization_router.post("/{org_id}/join", response_model=JoinByCodeResponse, summary="Join Organization", status_code=201)
async def join_organization(org_id: str, request: Request) -> Response:
    """Join/request to join an organization by ID (open join organizations)."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/join", inject_params={"organization_id": org_id})


@organization_router.get("/invitations/validate", response_model=InvitationValidateResponse, summary="Validate Invitation")
async def validate_organization_invitation(request: Request) -> Response:
    """Validate invitation token (public endpoint)."""
    registry = get_registry()
    service_url = registry.get_service_url("auth")
    return await proxy_request(request, service_url, "/api/onboarding/invitations/validate")


@organization_router.post("/invitations/accept", response_model=InvitationAcceptResponse, summary="Accept Invitation")
async def accept_organization_invitation(body: InvitationAcceptRequest, request: Request) -> Response:
    """Accept invitation and join organization."""
    registry = get_registry()
    service_url = registry.get_service_url("auth")
    return await proxy_request(request, service_url, "/api/onboarding/invitations/accept")


# Audit Events (nested under Organization)
@organization_router.get("/{org_id}/audit-events", response_model=list[AuditEventResponse], summary="List Audit Events")
async def list_audit_events(
    org_id: str,
    resource_type: str | None = Query(None, description="Filter by resource type"),
    action: str | None = Query(None, description="Filter by action"),
    start_date: str | None = Query(None, description="Filter from date (ISO 8601)"),
    end_date: str | None = Query(None, description="Filter to date (ISO 8601)"),
    limit: int = Query(100, description="Max results", le=1000),
    request: Request = None,
) -> Response:
    """List Audit Events for an organization (immutable log)."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/audit-events", inject_params={"organization_id": org_id})


@organization_router.get("/{org_id}/audit-events/{event_id}", response_model=AuditEventResponse, summary="Get Audit Event")
async def get_audit_event(org_id: str, event_id: str, request: Request) -> Response:
    """Get an Audit Event by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/audit-events/{event_id}", inject_params={"organization_id": org_id})


# RBAC: Permissions catalog
@organization_router.get("/{org_id}/permissions", summary="List Permissions")
async def list_permissions(org_id: str, request: Request) -> Response:
    """List the available permission catalog for this organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/permissions", inject_params={"organization_id": org_id})


# RBAC: Roles
@organization_router.get("/{org_id}/roles", summary="List Roles")
async def list_roles(org_id: str, request: Request) -> Response:
    """List roles in this organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/roles", inject_params={"organization_id": org_id})


@organization_router.post("/{org_id}/roles", summary="Create Role", status_code=201)
async def create_role(org_id: str, request: Request) -> Response:
    """Create a custom role in this organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/roles", inject_params={"organization_id": org_id})


@organization_router.get("/{org_id}/roles/{role_id}", summary="Get Role")
async def get_role(org_id: str, role_id: str, request: Request) -> Response:
    """Get a role by ID."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/roles/{role_id}", inject_params={"organization_id": org_id})


@organization_router.patch("/{org_id}/roles/{role_id}", summary="Update Role")
async def update_role(org_id: str, role_id: str, request: Request) -> Response:
    """Update a custom role."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/roles/{role_id}", inject_params={"organization_id": org_id})


@organization_router.delete("/{org_id}/roles/{role_id}", summary="Delete Role")
async def delete_role(org_id: str, role_id: str, request: Request) -> Response:
    """Delete a custom role."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/roles/{role_id}", inject_params={"organization_id": org_id})


# RBAC: Member role assignments
@organization_router.put("/{org_id}/members/{member_id}/roles", summary="Set Member Roles")
async def set_member_roles(org_id: str, member_id: str, request: Request) -> Response:
    """Replace all roles for a member."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/{member_id}/roles", inject_params={"organization_id": org_id})


@organization_router.post("/{org_id}/members/{member_id}/roles/{role_id}", summary="Add Role to Member")
async def add_member_role(org_id: str, member_id: str, role_id: str, request: Request) -> Response:
    """Add a role to a member."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/{member_id}/roles/{role_id}", inject_params={"organization_id": org_id})


@organization_router.delete("/{org_id}/members/{member_id}/roles/{role_id}", summary="Remove Role from Member")
async def remove_member_role(org_id: str, member_id: str, role_id: str, request: Request) -> Response:
    """Remove a role from a member."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/{member_id}/roles/{role_id}", inject_params={"organization_id": org_id})


# RBAC: Current user permissions
@organization_router.get("/{org_id}/members/me/permissions", summary="Get My Permissions")
async def get_my_permissions(org_id: str, request: Request) -> Response:
    """Get the current user's permissions in this organization."""
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, f"/v1/organizations/{org_id}/members/me/permissions", inject_params={"organization_id": org_id})


# =============================================================================
# Preferences Routes (Console Context)
# =============================================================================

# Pydantic models for preferences
class PreferencesResponse(BaseModel):
    """Console context preferences response."""
    last_view_mode: str = Field(description="Last selected view mode: 'applicant' or 'org_admin'")
    last_active_org_id: str | None = Field(description="Last active organization ID (null if none)")


class UpdatePreferencesRequest(BaseModel):
    """Request to update console context preferences (partial update)."""
    last_view_mode: str | None = Field(None, description="View mode to set: 'applicant' or 'org_admin'")
    last_active_org_id: str | None = Field(None, description="Organization ID to set as active (explicit null allowed)")


preferences_router = APIRouter(prefix="/v1/me", tags=["User Preferences"])


@preferences_router.get("/preferences", response_model=PreferencesResponse, summary="Get Console Context Preferences")
async def get_preferences(request: Request) -> Response:
    """
    Get current user's console context preferences.
    
    Returns existing preferences or defaults if none exist.
    """
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/me/preferences")


@preferences_router.put("/preferences", response_model=PreferencesResponse, summary="Update Console Context Preferences")
async def update_preferences(body: UpdatePreferencesRequest, request: Request) -> Response:
    """
    Update (upsert) current user's console context preferences.
    
    Partial update semantics:
    - Absent field: keep existing value
    - Field present as explicit null for last_active_org_id: set to null
    - Field present as null for last_view_mode: rejected with 400
    """
    registry = get_registry()
    service_url = registry.get_service_url("organizations")
    return await proxy_request(request, service_url, "/v1/me/preferences")


# =============================================================================
# Health and Status
# =============================================================================

_session_cache: SessionCache | None = None

def get_session_cache() -> SessionCache:
    if _session_cache is None:
        raise RuntimeError("Service not configured")
    return _session_cache


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _registry, _http_client, _session_cache
    logger.info(f"Starting {SERVICE_NAME}...")
    _registry = ServiceRegistry()
    _http_client = httpx.AsyncClient()
    _session_cache = SessionCache(ttl_seconds=60)
    
    # Initialize Redis for membership caching
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    redis_db = int(os.environ.get("REDIS_DB_GATEWAY", "2"))  # Use DB 2 for gateway
    logger.info(f"Connecting to Redis at {redis_url}/{redis_db}")
    redis_client = aioredis.from_url(
        f"{redis_url}/{redis_db}",
        encoding="utf-8",
        decode_responses=True
    )
    
    # Initialize OrganizationClient for membership verification
    org_service_url = _registry.get_service_url("organizations")
    org_client = OrganizationClient(
        base_url=org_service_url,
        redis_client=redis_client,
        cache_ttl=120,  # 2 minutes cache
    )
    app.state.org_client = org_client
    app.state.redis_client = redis_client
    
    logger.info(f"{SERVICE_NAME} started successfully")
    yield
    
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await org_client.close()
    await redis_client.aclose()
    await _http_client.aclose()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Marty API Gateway",
        description="""
## Digital Identity Management API

The Marty API provides a complete platform for digital identity credential management,
following the Digital Identity model architecture.

### Configuration Resources

- **Trust Profiles** - Define who is trusted and how validation happens
- **Revocation Profiles** - Format-agnostic revocation configuration
- **Credential Templates** - Blueprint for credential structure and claims
- **Compliance Profiles** - Regulatory and policy rules
- **Presentation Policies** - Define what credentials to request for verification
- **Deployment Profiles** - Runtime configuration for different environments (including Lanes)

### Operational Resources

- **Flows** - Orchestrate multi-step credential operations (issuance and verification)
- **Issuance** - Issue credentials to holders
- **Applications** - Manage Application Templates and Application instances
- **Audit Events** - Track actions within Organizations

### Verification

Verification is handled through two complementary approaches:

- **Stateless Evaluation**: Use `POST /v1/presentation-policies/{id}/evaluate` to immediately verify a VP token against a policy
- **Async Wallet Flows**: Use `POST /v1/flows/verify` to start a verification flow with QR code / request_uri for wallet interactions

### Getting Started

1. Create an Organization
2. Configure a Trust Profile (who you trust)
3. Create a Credential Template (what to issue)
4. Create an Application Template and instance Application
5. Issue credentials (via Application or direct issuance)
6. Create a Presentation Policy and use `/evaluate` or start a Flow to verify
        """,
        version="1.0.0",
        lifespan=lifespan,
    )
    
    # CORS configuration: Use specific origins when credentials are enabled
    # Cannot use wildcard "*" with credentials per CORS spec
    allowed_origins = os.environ.get(
        "CORS_ORIGINS",
        "http://localhost:3000,https://beta.elevenidllc.com,http://localhost:5173"
    ).split(",")
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[origin.strip() for origin in allowed_origins],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
    )
    
    # Add auth middleware for session validation and user context injection.
    # NOTE: create_app() runs at import time, before lifespan() initializes globals.
    # So we bootstrap defaults here and let lifespan() refresh them at startup.
    global _registry, _session_cache
    if _registry is None:
        _registry = ServiceRegistry()
    if _session_cache is None:
        _session_cache = SessionCache(ttl_seconds=60)

    registry = _registry
    session_cache = _session_cache

    # Add org auth middleware first, then auth middleware.
    # Starlette executes middleware in reverse registration order, so this makes
    # AuthMiddleware run before OrgAuthMiddleware and inject user context early.
    app.add_middleware(OrgAuthMiddleware)
    app.add_middleware(AuthMiddleware, registry=registry, session_cache=session_cache)
    
    # Include all routers
    app.include_router(trust_profile_router)
    app.include_router(revocation_profile_router)
    app.include_router(credential_template_router)
    app.include_router(wallet_registry_router)
    app.include_router(compliance_profile_router)
    app.include_router(presentation_policy_router)
    app.include_router(deployment_profile_router)
    app.include_router(flow_router)
    app.include_router(issuance_router)
    app.include_router(application_template_router)
    app.include_router(application_router)
    app.include_router(notification_router)
    app.include_router(applicant_router)
    app.include_router(organization_router)
    app.include_router(preferences_router)
    
    # Auth service proxy - forward all /v1/auth/* requests to auth service
    @app.api_route("/v1/auth/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    async def proxy_auth_requests(request: Request, path: str) -> Response:
        """Proxy auth requests to the auth service.
        
        This handles login/logout redirects and session management.
        """
        registry = get_registry()
        auth_url = registry.get_service_url("auth")
        if not auth_url:
            raise HTTPException(status_code=503, detail="Auth service unavailable")
        
        client = get_http_client()
        target_url = f"{auth_url}/v1/auth/{path}"
        
        # Forward query parameters
        if request.url.query:
            target_url += f"?{request.url.query}"
        
        # Get request body if present
        body = None
        if request.method in ["POST", "PUT", "PATCH"]:
            body = await request.body()
        
        # Forward headers (excluding hop-by-hop headers)
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in ("host", "connection", "keep-alive", "transfer-encoding")
        }
        
        try:
            # Forward request without following redirects (auth handles redirects)
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                follow_redirects=False,
                timeout=30.0,
            )
            
            # Return proxied response with all headers including Set-Cookie
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers={
                    k: v for k, v in response.headers.items()
                    if k.lower() not in ("content-encoding", "transfer-encoding")
                },
                media_type=response.headers.get("content-type"),
            )
        except httpx.ConnectError:
            logger.error(f"Auth service unavailable at {auth_url}")
            raise HTTPException(status_code=503, detail="Auth service unavailable")
        except httpx.TimeoutException:
            logger.error(f"Auth service timeout at {auth_url}")
            raise HTTPException(status_code=504, detail="Auth service timeout")
        except Exception as e:
            logger.error(f"Error proxying auth request: {e}")
            raise HTTPException(status_code=502, detail="Auth service error")
    
    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": SERVICE_NAME}

    async def _proxy_to_issuance_well_known(path: str) -> Response:
        """Proxy a well-known request to the issuance service.

        The issuance service is the source of truth for OID4VCI metadata.
        Keeping gateway endpoints as a proxy avoids drift and ensures that
        per-org discovery (OID4VCI v1 §12.2.2 insertion rule) works end-to-end.
        """
        registry = get_registry()
        issuance_url = registry.get_service_url("issuance")
        if not issuance_url:
            raise HTTPException(status_code=503, detail="Issuance service unavailable")

        client = get_http_client()
        try:
            upstream = await client.get(f"{issuance_url}{path}", timeout=10.0)
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="Issuance service timeout")
        except Exception as exc:
            logger.error("Error proxying well-known to issuance (%s): %s", path, exc)
            raise HTTPException(status_code=502, detail="Issuance service error")

        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type"),
            headers={
                k: v
                for k, v in upstream.headers.items()
                if k.lower() not in ("content-encoding", "transfer-encoding")
            },
        )

    # ---------------------------------------------------------------------
    # OID4VCI v1 per-org discovery (insertion rule paths)
    # ---------------------------------------------------------------------

    @app.get("/.well-known/openid-credential-issuer/org/{org_id}")
    async def get_org_issuer_metadata(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/openid-credential-issuer/org/{org_id}")

    @app.get("/.well-known/oauth-authorization-server/org/{org_id}")
    async def get_org_oauth_authorization_server_metadata(org_id: str) -> Response:
        return await _proxy_to_issuance_well_known(f"/.well-known/oauth-authorization-server/org/{org_id}")

    # ---------------------------------------------------------------------
    # OID4VCI spec §11.2.2 "/.well-known/openid-credential-issuer" appended
    # to the credential_issuer URL (RFC 8414-style discovery).
    # When credential_issuer = "https://host/org/{org_id}", wallets fetch:
    #   https://host/org/{org_id}/.well-known/openid-credential-issuer
    # These two routes satisfy that pattern.
    # ---------------------------------------------------------------------

    @app.get("/org/{org_id}/.well-known/openid-credential-issuer")
    async def get_org_issuer_metadata_oid4vci_style(org_id: str) -> Response:
        """OID4VCI §11.2.2 discovery: <credential_issuer>/.well-known/openid-credential-issuer"""
        return await _proxy_to_issuance_well_known(f"/.well-known/openid-credential-issuer/org/{org_id}")

    @app.get("/org/{org_id}/.well-known/oauth-authorization-server")
    async def get_org_oauth_metadata_oid4vci_style(org_id: str) -> Response:
        """OID4VCI §11.2.2 discovery: <credential_issuer>/.well-known/oauth-authorization-server"""
        return await _proxy_to_issuance_well_known(f"/.well-known/oauth-authorization-server/org/{org_id}")
    
    @app.get("/.well-known/openid-credential-issuer")
    async def get_issuer_metadata() -> Response:
        """OID4VCI Issuer Metadata — proxied to the issuance service (source of truth)."""
        return await _proxy_to_issuance_well_known("/.well-known/openid-credential-issuer")

    @app.get("/.well-known/oauth-authorization-server")
    async def get_oauth_authorization_server_metadata() -> Response:
        """OAuth Authorization Server Metadata — proxied to the issuance service (source of truth)."""
        return await _proxy_to_issuance_well_known("/.well-known/oauth-authorization-server")

    @app.get("/.well-known/openid-configuration")
    async def get_openid_configuration() -> dict:
        """OIDC Discovery metadata (compatibility endpoint used by some wallets)."""
        issuer_url = os.environ.get("ISSUER_BASE_URL", "http://localhost:8000")
        return {
            "issuer": issuer_url,
            "authorization_endpoint": f"{issuer_url}/v1/issuance/authorize",
            "token_endpoint": f"{issuer_url}/v1/issuance/token",
            "jwks_uri": f"{issuer_url}/.well-known/jwks.json",
            "response_types_supported": ["code", "token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["EdDSA", "ES256"],
            "grant_types_supported": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            ],
            "token_endpoint_auth_methods_supported": ["none"],
        }

    @app.get("/.well-known/jwks.json")
    async def get_jwks() -> dict:
        """Compatibility JWKS endpoint for clients that expect OIDC discovery links."""
        return {"keys": []}
    
    @app.get("/health/services")
    async def services_health() -> dict:
        """Check health of all backend services."""
        registry = get_registry()
        client = get_http_client()
        
        results = {}
        for service, url in registry.get_all_services().items():
            try:
                response = await client.get(f"{url}/health", timeout=5.0)
                results[service] = {
                    "status": "healthy" if response.status_code == 200 else "unhealthy",
                    "url": url,
                }
            except Exception as e:
                results[service] = {
                    "status": "unreachable",
                    "url": url,
                    "error": str(e),
                }
        
        return {"services": results}
    
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("gateway.main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
