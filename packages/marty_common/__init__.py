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
]
