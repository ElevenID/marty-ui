"""
Auth Service Domain Entities

Core domain entities for authentication and session management.
These are pure domain objects with no infrastructure dependencies.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class SessionStatus(str, Enum):
    """Session status values."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class UserType(str, Enum):
    """User type values."""
    APPLICANT = "applicant"
    VENDOR = "vendor"
    ADMINISTRATOR = "administrator"


@dataclass
class AuthenticatedUser:
    """
    Represents an authenticated user in the system.
    
    This is a domain entity that holds user identity information
    after successful authentication.
    """
    
    user_id: str
    email: str
    username: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    user_type: UserType = UserType.APPLICANT
    applicant_id: str | None = None
    roles: list[str] = field(default_factory=list)
    organization_id: str | None = None
    organization_name: str | None = None
    onboarding_completed: datetime | None = None
    
    @property
    def display_name(self) -> str:
        """Get user's display name."""
        if self.given_name and self.family_name:
            return f"{self.given_name} {self.family_name}"
        if self.given_name:
            return self.given_name
        if self.username:
            return self.username
        return self.email.split("@")[0]
    
    @property
    def is_admin(self) -> bool:
        """Check if user is an administrator."""
        return self.user_type == UserType.ADMINISTRATOR or "admin" in self.roles
    
    @property
    def is_org_admin(self) -> bool:
        """Check if user is an organization admin."""
        return "org_admin" in self.roles or self.is_admin
    
    def has_role(self, role: str) -> bool:
        """Check if user has a specific role."""
        return role in self.roles
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "user_id": self.user_id,
            "email": self.email,
            "username": self.username,
            "given_name": self.given_name,
            "family_name": self.family_name,
            "user_type": self.user_type.value,
            "applicant_id": self.applicant_id,
            "roles": self.roles,
            "organization_id": self.organization_id,
            "organization_name": self.organization_name,
            "onboarding_completed": self.onboarding_completed.isoformat() if self.onboarding_completed else None,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthenticatedUser:
        """Create from dictionary."""
        user_type = data.get("user_type", "applicant")
        if isinstance(user_type, str):
            user_type = UserType(user_type)
        
        onboarding = data.get("onboarding_completed")
        if isinstance(onboarding, str):
            onboarding = datetime.fromisoformat(onboarding)
        
        return cls(
            user_id=data["user_id"],
            email=data["email"],
            username=data.get("username"),
            given_name=data.get("given_name"),
            family_name=data.get("family_name"),
            user_type=user_type,
            applicant_id=data.get("applicant_id"),
            roles=data.get("roles", []),
            organization_id=data.get("organization_id"),
            organization_name=data.get("organization_name"),
            onboarding_completed=onboarding,
        )


@dataclass
class Session:
    """
    Represents a user session.
    
    Sessions are created after successful authentication and
    stored in Redis for fast lookup.
    """
    
    session_id: str
    user: AuthenticatedUser
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=24))
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: SessionStatus = SessionStatus.ACTIVE
    ip_address: str | None = None
    user_agent: str | None = None
    id_token: str | None = None  # For SSO logout
    refresh_token: str | None = None
    
    @classmethod
    def create(
        cls,
        user: AuthenticatedUser,
        ttl_seconds: int = 86400,
        ip_address: str | None = None,
        user_agent: str | None = None,
        id_token: str | None = None,
        refresh_token: str | None = None,
    ) -> Session:
        """Create a new session for a user."""
        now = datetime.now(timezone.utc)
        return cls(
            session_id=str(uuid.uuid4()),
            user=user,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            last_activity=now,
            status=SessionStatus.ACTIVE,
            ip_address=ip_address,
            user_agent=user_agent,
            id_token=id_token,
            refresh_token=refresh_token,
        )
    
    @property
    def is_valid(self) -> bool:
        """Check if session is still valid."""
        if self.status != SessionStatus.ACTIVE:
            return False
        return datetime.now(timezone.utc) < self.expires_at
    
    @property
    def remaining_ttl_seconds(self) -> int:
        """Get remaining TTL in seconds."""
        if not self.is_valid:
            return 0
        delta = self.expires_at - datetime.now(timezone.utc)
        return max(0, int(delta.total_seconds()))
    
    def touch(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)
    
    def revoke(self) -> None:
        """Revoke the session."""
        self.status = SessionStatus.REVOKED
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "session_id": self.session_id,
            "user": self.user.to_dict(),
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "status": self.status.value,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "id_token": self.id_token,
            "refresh_token": self.refresh_token,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Session:
        """Create from dictionary."""
        return cls(
            session_id=data["session_id"],
            user=AuthenticatedUser.from_dict(data["user"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            last_activity=datetime.fromisoformat(data["last_activity"]),
            status=SessionStatus(data["status"]),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
            id_token=data.get("id_token"),
            refresh_token=data.get("refresh_token"),
        )


@dataclass
class PKCEState:
    """
    PKCE state for OAuth authorization flow.
    
    Stores the code verifier and related state during
    the authorization code exchange.
    """
    
    state: str
    code_verifier: str
    redirect_uri: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=10))
    
    @property
    def is_valid(self) -> bool:
        """Check if PKCE state is still valid."""
        return datetime.now(timezone.utc) < self.expires_at
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "state": self.state,
            "code_verifier": self.code_verifier,
            "redirect_uri": self.redirect_uri,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PKCEState:
        """Create from dictionary."""
        return cls(
            state=data["state"],
            code_verifier=data["code_verifier"],
            redirect_uri=data["redirect_uri"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
        )


@dataclass
class OIDCUserInfo:
    """
    User information from OIDC provider.
    
    Represents claims received from the OIDC userinfo endpoint
    or decoded from the ID token.
    """
    
    sub: str  # Subject identifier (unique user ID from provider)
    email: str
    email_verified: bool = False
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    preferred_username: str | None = None
    picture: str | None = None
    locale: str | None = None
    
    # Custom claims
    organization_id: str | None = None
    roles: list[str] = field(default_factory=list)
    
    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> OIDCUserInfo:
        """Create from OIDC claims dictionary."""
        # Extract roles from various claim formats
        roles = []
        if "roles" in claims:
            roles = claims["roles"]
        elif "realm_access" in claims:
            roles = claims["realm_access"].get("roles", [])
        elif "resource_access" in claims:
            # Keycloak client roles
            for client_roles in claims["resource_access"].values():
                roles.extend(client_roles.get("roles", []))
        
        return cls(
            sub=claims.get("sub", ""),
            email=claims.get("email", ""),
            email_verified=claims.get("email_verified", False),
            name=claims.get("name"),
            given_name=claims.get("given_name"),
            family_name=claims.get("family_name"),
            preferred_username=claims.get("preferred_username"),
            picture=claims.get("picture"),
            locale=claims.get("locale"),
            organization_id=claims.get("organization_id"),
            roles=roles,
        )
