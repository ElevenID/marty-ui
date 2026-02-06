"""
Auth Service Application Ports

Port interfaces that define the boundaries of the Auth service.
Inbound ports define what the service can do (use cases).
Outbound ports define what the service needs from external systems.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Protocol

from ..domain.entities import (
    AuthenticatedUser,
    OIDCUserInfo,
    PKCEState,
    Session,
)


# =============================================================================
# Inbound Ports (Use Case Interfaces)
# =============================================================================

@dataclass
class InitiateLoginCommand:
    """Command to initiate OIDC login flow."""
    redirect_uri: str | None = None


@dataclass
class InitiateLoginResult:
    """Result of initiating login."""
    authorization_url: str
    state: str


@dataclass
class HandleCallbackCommand:
    """Command to handle OIDC callback."""
    code: str
    state: str
    ip_address: str | None = None
    user_agent: str | None = None


@dataclass
class HandleCallbackResult:
    """Result of handling OIDC callback."""
    session: Session
    redirect_uri: str


@dataclass
class ValidateSessionQuery:
    """Query to validate a session."""
    session_id: str


@dataclass
class LogoutCommand:
    """Command to logout user."""
    session_id: str


@dataclass
class LogoutResult:
    """Result of logout."""
    success: bool
    sso_logout_url: str | None = None


class AuthenticatePort(Protocol):
    """Inbound port for authentication operations."""
    
    async def initiate_login(self, command: InitiateLoginCommand) -> InitiateLoginResult:
        """Initiate OIDC login flow."""
        ...
    
    async def initiate_registration(self, command: InitiateLoginCommand) -> InitiateLoginResult:
        """Initiate OIDC registration flow."""
        ...
    
    async def handle_callback(self, command: HandleCallbackCommand) -> HandleCallbackResult:
        """Handle OIDC callback after authentication."""
        ...
    
    async def logout(self, command: LogoutCommand) -> LogoutResult:
        """Logout user and revoke session."""
        ...


class SessionPort(Protocol):
    """Inbound port for session operations."""
    
    async def validate_session(self, query: ValidateSessionQuery) -> Session | None:
        """Validate a session and return user info if valid."""
        ...
    
    async def get_user(self, session_id: str) -> AuthenticatedUser | None:
        """Get authenticated user from session."""
        ...
    
    async def refresh_session(self, session_id: str) -> Session | None:
        """Refresh session expiry."""
        ...


# =============================================================================
# Outbound Ports (Infrastructure Dependencies)
# =============================================================================

class SessionRepositoryPort(ABC):
    """Outbound port for session storage."""
    
    @abstractmethod
    async def save(self, session: Session) -> None:
        """Save a session."""
        ...
    
    @abstractmethod
    async def get(self, session_id: str) -> Session | None:
        """Get a session by ID."""
        ...
    
    @abstractmethod
    async def delete(self, session_id: str) -> None:
        """Delete a session."""
        ...
    
    @abstractmethod
    async def get_by_user(self, user_id: str) -> list[Session]:
        """Get all sessions for a user."""
        ...
    
    @abstractmethod
    async def delete_all_for_user(self, user_id: str) -> int:
        """Delete all sessions for a user. Returns count deleted."""
        ...


class PKCEStateRepositoryPort(ABC):
    """Outbound port for PKCE state storage."""
    
    @abstractmethod
    async def save(self, pkce_state: PKCEState) -> None:
        """Save PKCE state."""
        ...
    
    @abstractmethod
    async def get_and_delete(self, state: str) -> PKCEState | None:
        """Get and atomically delete PKCE state (single-use pattern)."""
        ...


class OIDCProviderPort(ABC):
    """Outbound port for OIDC provider interactions."""
    
    @abstractmethod
    def get_authorization_url(
        self,
        state: str,
        code_challenge: str,
        redirect_uri: str | None = None,
    ) -> str:
        """Build authorization URL with PKCE."""
        ...
    
    @abstractmethod
    def get_registration_url(
        self,
        state: str,
        code_challenge: str,
        redirect_uri: str | None = None,
    ) -> str:
        """Build registration URL with PKCE."""
        ...
    
    @abstractmethod
    async def exchange_code(
        self,
        code: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        """Exchange authorization code for tokens."""
        ...
    
    @abstractmethod
    def parse_id_token(self, id_token: str) -> OIDCUserInfo:
        """Parse user claims from ID token (already validated via PKCE)."""
        ...
    
    @abstractmethod
    def get_logout_url(self, id_token: str | None = None) -> str:
        """Get OIDC logout URL for SSO logout."""
        ...


class UserProvisioningPort(ABC):
    """Outbound port for user provisioning (JIT)."""
    
    @abstractmethod
    async def provision_user(self, oidc_user: OIDCUserInfo) -> AuthenticatedUser:
        """Provision or update user from OIDC info (JIT provisioning)."""
        ...


class EventPublisherPort(ABC):
    """Outbound port for publishing domain events."""
    
    @abstractmethod
    async def publish(self, event: Any) -> None:
        """Publish a domain event."""
        ...
