"""
Auth Service Domain Events

Domain events emitted by the Auth service.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone

from marty_common.events import DomainEvent


@dataclass
class UserAuthenticatedEvent(DomainEvent):
    """Emitted when a user successfully authenticates."""
    
    source_service: str = "auth"
    user_id: str = ""
    email: str = ""
    organization_id: str | None = None
    authentication_method: str = "oidc"  # oidc, api_key, etc.
    ip_address: str | None = None


@dataclass
class UserLoggedOutEvent(DomainEvent):
    """Emitted when a user logs out."""
    
    source_service: str = "auth"
    user_id: str = ""
    session_id: str = ""
    logout_type: str = "user_initiated"  # user_initiated, session_expired, forced


@dataclass
class SessionCreatedEvent(DomainEvent):
    """Emitted when a new session is created."""
    
    source_service: str = "auth"
    session_id: str = ""
    user_id: str = ""
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SessionRevokedEvent(DomainEvent):
    """Emitted when a session is revoked."""
    
    source_service: str = "auth"
    session_id: str = ""
    user_id: str = ""
    revoked_by: str = ""  # user_id or "system"
    reason: str = ""
