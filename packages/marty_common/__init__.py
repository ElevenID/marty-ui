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
    OrganizationRoleSummary,
    OrganizationMembership,
    OrganizationContext,
    OrganizationClient,
    ensure_active_membership,
    ensure_membership_permission,
    require_org_membership,
    require_org_admin,
    require_org_owner,
    require_org_role,
    require_permission,
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
from .licensing import (
    LicenseClaims,
    LicenseValidationError,
    license_enforcement_enabled,
    validate_license_claims,
    validate_license_token,
    validate_runtime_license_from_env,
)
from .migration_profile import (
    MigrationProfileSettings,
    allow_experimental_data_fixes,
    include_beta_seed_data,
    include_demo_seed_data,
    include_experimental_seed_data,
    include_test_seed_data,
    is_persistent_profile,
    migration_profile,
    migration_profile_settings,
    normalize_migration_profile,
    skip_demo_migrations,
    use_explicit_demo_seed_pack,
)
from .system_ids import (
    MARTY_CREDENTIAL_LOGIN_FLOW_ID,
    MARTY_CREDENTIAL_LOGIN_FLOW_INSTANCE_ID,
    MARTY_DEFAULT_DEPLOYMENT_PROFILE_ID,
    MARTY_DEFAULT_ORG_ID,
    MARTY_DEFAULT_ORG_SLUG,
    MARTY_DEFAULT_REVOCATION_PROFILE_ID,
    MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_APPLICATION_TEMPLATE_ID,
    MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_TEMPLATE_ID,
    MARTY_LOGIN_TRUSTED_ISSUER_ID,
    MARTY_LOGIN_TRUST_PROFILE_ID,
    MARTY_OPEN_BADGE_LOGIN_POLICY_ID,
    MARTY_SYSTEM_APPLICATION_TEMPLATE_IDS,
    MARTY_SYSTEM_DEPLOYMENT_PROFILE_IDS,
    MARTY_SYSTEM_FLOW_IDS,
    MARTY_SYSTEM_ORG_IDS,
    MARTY_SYSTEM_POLICY_IDS,
    MARTY_SYSTEM_REVOCATION_PROFILE_IDS,
    MARTY_SYSTEM_TEMPLATE_IDS,
    MARTY_SYSTEM_TRUST_PROFILE_IDS,
    MARTY_SYSTEM_TRUST_SOURCE_IDS,
    MARTY_VERIFIED_MEMBER_BADGE_APPLICATION_TEMPLATE_ID,
    MARTY_VERIFIED_MEMBER_BADGE_TEMPLATE_ID,
    SYSTEM_ID_GROUPS,
    flatten_system_ids,
)

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
    "OrganizationRoleSummary",
    "OrganizationMembership",
    "OrganizationContext",
    "OrganizationClient",
    "ensure_active_membership",
    "ensure_membership_permission",
    "require_org_membership",
    "require_org_admin",
    "require_org_owner",
    "require_org_role",
    "require_permission",
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
    # Licensing
    "LicenseClaims",
    "LicenseValidationError",
    "license_enforcement_enabled",
    "validate_license_claims",
    "validate_license_token",
    "validate_runtime_license_from_env",
    # Migration profiles
    "MigrationProfileSettings",
    "allow_experimental_data_fixes",
    "include_beta_seed_data",
    "include_demo_seed_data",
    "include_experimental_seed_data",
    "include_test_seed_data",
    "is_persistent_profile",
    "migration_profile",
    "migration_profile_settings",
    "normalize_migration_profile",
    "skip_demo_migrations",
    "use_explicit_demo_seed_pack",
    # System IDs
    "MARTY_CREDENTIAL_LOGIN_FLOW_ID",
    "MARTY_CREDENTIAL_LOGIN_FLOW_INSTANCE_ID",
    "MARTY_DEFAULT_DEPLOYMENT_PROFILE_ID",
    "MARTY_DEFAULT_ORG_ID",
    "MARTY_DEFAULT_ORG_SLUG",
    "MARTY_DEFAULT_REVOCATION_PROFILE_ID",
    "MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_APPLICATION_TEMPLATE_ID",
    "MARTY_CANVAS_MIP_QUIZ_OPEN_BADGE_TEMPLATE_ID",
    "MARTY_LOGIN_TRUSTED_ISSUER_ID",
    "MARTY_LOGIN_TRUST_PROFILE_ID",
    "MARTY_OPEN_BADGE_LOGIN_POLICY_ID",
    "MARTY_SYSTEM_APPLICATION_TEMPLATE_IDS",
    "MARTY_SYSTEM_DEPLOYMENT_PROFILE_IDS",
    "MARTY_SYSTEM_FLOW_IDS",
    "MARTY_SYSTEM_ORG_IDS",
    "MARTY_SYSTEM_POLICY_IDS",
    "MARTY_SYSTEM_REVOCATION_PROFILE_IDS",
    "MARTY_SYSTEM_TEMPLATE_IDS",
    "MARTY_SYSTEM_TRUST_PROFILE_IDS",
    "MARTY_SYSTEM_TRUST_SOURCE_IDS",
    "MARTY_VERIFIED_MEMBER_BADGE_APPLICATION_TEMPLATE_ID",
    "MARTY_VERIFIED_MEMBER_BADGE_TEMPLATE_ID",
    "SYSTEM_ID_GROUPS",
    "flatten_system_ids",
]
