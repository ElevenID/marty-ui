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
from .dto import ApiResponse, PaginatedResponse, ErrorResponse
from .org_authorization import (
    OrgRole,
    OrganizationMembership,
    OrganizationContext,
    OrganizationClient,
    require_org_membership,
    require_org_role,
    require_org_admin,
    require_org_owner,
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
    "OrgRole",
    "OrganizationMembership",
    "OrganizationContext",
    "OrganizationClient",
    "require_org_membership",
    "require_org_role",
    "require_org_admin",
    "require_org_owner",
]
