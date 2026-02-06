"""
Standardized Error Types

Common error classes and API error response utilities for all Marty services.
Follows consistent error response format across the API.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ErrorSeverity(str, Enum):
    """Error severity levels."""
    
    LOW = "low"           # Minor issues, may be ignored
    MEDIUM = "medium"     # Should be addressed
    HIGH = "high"         # Requires attention
    CRITICAL = "critical" # Requires immediate attention


class RecoveryAction(str, Enum):
    """Suggested recovery actions for errors."""
    
    RETRY = "retry"                    # Client can retry the request
    RETRY_WITH_BACKOFF = "retry_with_backoff"  # Retry after delay
    CONTACT_SUPPORT = "contact_support"  # User should contact support
    FIX_INPUT = "fix_input"            # Fix request parameters
    REAUTHENTICATE = "reauthenticate"  # Re-login required
    UPGRADE_PLAN = "upgrade_plan"      # Subscription upgrade needed
    NONE = "none"                      # No recovery possible


@dataclass
class ErrorDetail:
    """Details about a specific error field or issue."""
    
    field: str | None = None
    message: str = ""
    code: str | None = None
    value: Any = None


@dataclass
class MartyError(Exception):
    """Base error class for all Marty services."""
    
    code: str
    message: str
    user_message: str | None = None
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    recovery_action: RecoveryAction = RecoveryAction.NONE
    details: list[ErrorDetail] = field(default_factory=list)
    http_status: int = 500
    
    def __post_init__(self) -> None:
        super().__init__(self.message)
        if self.user_message is None:
            self.user_message = self.message
    
    def to_dict(self) -> dict[str, Any]:
        """Convert error to API response dict."""
        return {
            "code": self.code,
            "message": self.message,
            "user_message": self.user_message,
            "severity": self.severity.value,
            "recovery_action": self.recovery_action.value,
            "details": [
                {
                    "field": d.field,
                    "message": d.message,
                    "code": d.code,
                }
                for d in self.details
            ] if self.details else [],
        }


@dataclass
class ValidationError(MartyError):
    """Validation error for invalid request data."""
    
    code: str = "VALIDATION_ERROR"
    message: str = "Validation failed"
    user_message: str = "Please check your input and try again"
    severity: ErrorSeverity = ErrorSeverity.LOW
    recovery_action: RecoveryAction = RecoveryAction.FIX_INPUT
    http_status: int = 422
    
    @classmethod
    def for_field(cls, field: str, message: str, value: Any = None) -> ValidationError:
        """Create validation error for a specific field."""
        return cls(
            message=f"Validation failed for field '{field}': {message}",
            user_message=message,
            details=[ErrorDetail(field=field, message=message, value=value)],
        )
    
    @classmethod
    def for_fields(cls, field_errors: dict[str, str]) -> ValidationError:
        """Create validation error for multiple fields."""
        details = [
            ErrorDetail(field=field, message=msg)
            for field, msg in field_errors.items()
        ]
        return cls(
            message=f"Validation failed for {len(field_errors)} field(s)",
            details=details,
        )


@dataclass
class NotFoundError(MartyError):
    """Resource not found error."""
    
    code: str = "NOT_FOUND"
    message: str = "Resource not found"
    user_message: str = "The requested resource was not found"
    severity: ErrorSeverity = ErrorSeverity.LOW
    recovery_action: RecoveryAction = RecoveryAction.NONE
    http_status: int = 404
    
    @classmethod
    def for_resource(cls, resource_type: str, resource_id: str) -> NotFoundError:
        """Create not found error for a specific resource."""
        return cls(
            message=f"{resource_type} with ID '{resource_id}' not found",
            user_message=f"The {resource_type.lower()} you requested was not found",
        )


@dataclass
class AuthenticationError(MartyError):
    """Authentication error."""
    
    code: str = "AUTHENTICATION_ERROR"
    message: str = "Authentication failed"
    user_message: str = "Please log in to continue"
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    recovery_action: RecoveryAction = RecoveryAction.REAUTHENTICATE
    http_status: int = 401
    
    @classmethod
    def invalid_credentials(cls) -> AuthenticationError:
        """Create error for invalid credentials."""
        return cls(
            code="INVALID_CREDENTIALS",
            message="Invalid credentials provided",
            user_message="The email or password you entered is incorrect",
        )
    
    @classmethod
    def session_expired(cls) -> AuthenticationError:
        """Create error for expired session."""
        return cls(
            code="SESSION_EXPIRED",
            message="Session has expired",
            user_message="Your session has expired. Please log in again.",
        )
    
    @classmethod
    def invalid_token(cls) -> AuthenticationError:
        """Create error for invalid token."""
        return cls(
            code="INVALID_TOKEN",
            message="Invalid or expired token",
            user_message="Your authentication token is invalid or has expired",
        )


@dataclass
class AuthorizationError(MartyError):
    """Authorization error."""
    
    code: str = "AUTHORIZATION_ERROR"
    message: str = "Access denied"
    user_message: str = "You don't have permission to perform this action"
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    recovery_action: RecoveryAction = RecoveryAction.NONE
    http_status: int = 403
    
    @classmethod
    def insufficient_permissions(cls, required_permission: str) -> AuthorizationError:
        """Create error for insufficient permissions."""
        return cls(
            code="INSUFFICIENT_PERMISSIONS",
            message=f"Missing required permission: {required_permission}",
            user_message="You don't have permission to perform this action",
        )
    
    @classmethod
    def not_organization_member(cls, org_id: str) -> AuthorizationError:
        """Create error for non-organization member."""
        return cls(
            code="NOT_ORGANIZATION_MEMBER",
            message=f"User is not a member of organization {org_id}",
            user_message="You are not a member of this organization",
        )


@dataclass
class ConflictError(MartyError):
    """Conflict error for duplicate resources or invalid state transitions."""
    
    code: str = "CONFLICT"
    message: str = "Resource conflict"
    user_message: str = "The operation conflicts with the current state"
    severity: ErrorSeverity = ErrorSeverity.LOW
    recovery_action: RecoveryAction = RecoveryAction.NONE
    http_status: int = 409
    
    @classmethod
    def duplicate_resource(cls, resource_type: str, identifier: str) -> ConflictError:
        """Create error for duplicate resource."""
        return cls(
            code="DUPLICATE_RESOURCE",
            message=f"{resource_type} with identifier '{identifier}' already exists",
            user_message=f"A {resource_type.lower()} with this identifier already exists",
        )
    
    @classmethod
    def invalid_state_transition(
        cls, resource_type: str, current_state: str, target_state: str
    ) -> ConflictError:
        """Create error for invalid state transition."""
        return cls(
            code="INVALID_STATE_TRANSITION",
            message=f"Cannot transition {resource_type} from '{current_state}' to '{target_state}'",
            user_message=f"This operation cannot be performed in the current state",
        )


@dataclass
class RateLimitError(MartyError):
    """Rate limit exceeded error."""
    
    code: str = "RATE_LIMIT_EXCEEDED"
    message: str = "Rate limit exceeded"
    user_message: str = "Too many requests. Please try again later."
    severity: ErrorSeverity = ErrorSeverity.LOW
    recovery_action: RecoveryAction = RecoveryAction.RETRY_WITH_BACKOFF
    http_status: int = 429
    retry_after: int = 60  # seconds
    
    def to_dict(self) -> dict[str, Any]:
        """Convert error to API response dict with retry info."""
        result = super().to_dict()
        result["retry_after"] = self.retry_after
        return result


@dataclass  
class ServiceUnavailableError(MartyError):
    """Service temporarily unavailable error."""
    
    code: str = "SERVICE_UNAVAILABLE"
    message: str = "Service temporarily unavailable"
    user_message: str = "The service is temporarily unavailable. Please try again later."
    severity: ErrorSeverity = ErrorSeverity.HIGH
    recovery_action: RecoveryAction = RecoveryAction.RETRY_WITH_BACKOFF
    http_status: int = 503


@dataclass
class InternalError(MartyError):
    """Internal server error."""
    
    code: str = "INTERNAL_ERROR"
    message: str = "An internal error occurred"
    user_message: str = "Something went wrong. Please try again or contact support."
    severity: ErrorSeverity = ErrorSeverity.HIGH
    recovery_action: RecoveryAction = RecoveryAction.CONTACT_SUPPORT
    http_status: int = 500
