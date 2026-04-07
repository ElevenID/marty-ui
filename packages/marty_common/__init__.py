"""
Marty Common Package

Shared utilities, value objects, and infrastructure for Marty microservices.
This package provides common functionality used across all services while
maintaining service autonomy for business logic.

Contents:
- value_objects: Shared domain value objects (UserId, OrganizationId, Email, etc.)
- errors: Standardized error types and API error responses
- database: Schema-aware database connection utilities
- middleware: Request ID injection, logging middleware
- dto: Common API response DTOs
- events: Domain event base classes and messaging utilities
- org_authorization: Organization-scoped authorization dependencies
- cedar_engine: Cedar policy evaluation engine
- cedar_entities: Cedar entity builders
- cedar_actions: Route-to-Cedar action mapping
- cedar_middleware: Cedar authorization middleware
"""

from .value_objects import UserId, OrganizationId, Email
from .errors import (
    MartyError,
    ValidationError,
    NotFoundError,
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    RateLimitError,
)
from .dto import ApiResponse, PaginatedResponse, ErrorResponse, DeleteResponse, CountResponse
from .org_authorization import (
    OrgRole,
    OrganizationMembership,
    OrganizationContext,
    OrganizationClient,
    require_org_membership,
    require_org_role,
)
from .cedar_engine import CedarEngine, AuthzDecision
from .cedar_entities import build_user_entities, build_apikey_entities, build_request_context
from .cedar_actions import resolve_action, resolve_action_and_resource, extract_org_id
from .cedar_middleware import CedarAuthMiddleware
from .billing_engine import BillingCedarEngine
from .billing_middleware import BillingAuthMiddleware
from .messages import (
    ClaimResultPayload,
    CredentialOfferPayload,
    CredentialProofPayload,
    CredentialRequestPayload,
    CredentialResponsePayload,
    MIPMessage,
    MessageSignature,
    MessageType,
    PresentationRequestPayload,
    PresentationResponsePayload,
    TokenRequestPayload,
    TokenResponsePayload,
    VerificationResultPayload,
)
from .middleware import RequestIdMiddleware, RequestLoggingMiddleware
from .service_setup import create_service_app
from .pairwise import compute_pairwise_id, generate_holder_secret
from .plans import PlanTier, PlanLimits, PLAN_LIMITS, PLAN_INFO, get_plan_limits, check_limit, check_feature
from .usage import UsageTracker

__all__ = [
    # Value Objects
    "UserId",
    "OrganizationId", 
    "Email",
    # Errors
    "MartyError",
    "ValidationError",
    "NotFoundError",
    "AuthenticationError",
    "AuthorizationError",
    "ConflictError",
    "RateLimitError",
    # DTOs
    "ApiResponse",
    "PaginatedResponse",
    "ErrorResponse",
    # Organization Authorization
    "OrgRole",
    "OrganizationMembership",
    "OrganizationContext",
    "OrganizationClient",
    "require_org_membership",
    "require_org_role",
    # Cedar Authorization
    "CedarEngine",
    "AuthzDecision",
    "CedarAuthMiddleware",
    "build_user_entities",
    "build_apikey_entities",
    "build_request_context",
    "resolve_action",
    "resolve_action_and_resource",
    "extract_org_id",
    # Billing Authorization
    "BillingCedarEngine",
    "BillingAuthMiddleware",
    # Message Layer
    "ClaimResultPayload",
    "CredentialOfferPayload",
    "CredentialProofPayload",
    "CredentialRequestPayload",
    "CredentialResponsePayload",
    "MIPMessage",
    "MessageSignature",
    "MessageType",
    "PresentationRequestPayload",
    "PresentationResponsePayload",
    "TokenRequestPayload",
    "TokenResponsePayload",
    "VerificationResultPayload",
    # Middleware
    "RequestIdMiddleware",
    "RequestLoggingMiddleware",
    # Service Setup
    "create_service_app",
    # Pairwise Subject Identifiers
    "compute_pairwise_id",
    "generate_holder_secret",
    # Plans & Usage
    "PlanTier",
    "PlanLimits",
    "PLAN_LIMITS",
    "PLAN_INFO",
    "get_plan_limits",
    "check_limit",
    "check_feature",
    "UsageTracker",
]
