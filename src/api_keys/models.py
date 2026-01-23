"""
API Key Models

SQLAlchemy models for API key management.
Supports scoped access control for vendor organizations.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def generate_uuid() -> str:
    """Generate a UUID string for primary keys."""
    return str(uuid4())


def utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


def generate_api_key() -> str:
    """Generate a secure API key with prefix."""
    prefix = "mk_"
    key = secrets.token_urlsafe(32)
    return f"{prefix}{key}"


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for API keys."""


class APIKeyScope(str, Enum):
    """Available scopes for API keys."""
    
    # Credential operations
    READ_CREDENTIALS = "read:credentials"
    WRITE_CREDENTIALS = "write:credentials"
    
    # Trust registry operations
    READ_TRUST_REGISTRY = "read:trust_registry"
    WRITE_TRUST_REGISTRY = "write:trust_registry"
    
    # Revocation operations
    READ_REVOCATION = "read:revocation"
    WRITE_REVOCATION = "write:revocation"
    
    # Webhook management
    MANAGE_WEBHOOKS = "manage:webhooks"
    
    # Verification operations
    VERIFY_CREDENTIALS = "verify:credentials"


# Association table for API key scopes
api_key_scopes = Table(
    "api_key_scopes",
    Base.metadata,
    Column("api_key_id", String(36), ForeignKey("api_keys.id"), primary_key=True),
    Column("scope", String(50), primary_key=True),
)


class APIKey(Base):
    """API Key model for programmatic access."""
    
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )
    
    # Organization this key belongs to
    organization_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True,
    )
    
    # Human-readable name for the key
    name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    
    # The hashed API key (never store plain text)
    key_hash: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        unique=True,
    )
    
    # Prefix for display (e.g., "mk_abc123...")
    key_prefix: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )
    
    # Scopes as comma-separated string for simplicity
    # In production, use the association table
    scopes_str: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )
    
    # Metadata
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    
    created_by: Mapped[str] = mapped_column(
        String(255),
        nullable=True,
    )
    
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    # Status
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    
    revoked_by: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    
    # Usage tracking
    usage_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    @property
    def scopes(self) -> List[str]:
        """Get scopes as a list."""
        if not self.scopes_str:
            return []
        return [s.strip() for s in self.scopes_str.split(",") if s.strip()]
    
    @scopes.setter
    def scopes(self, value: List[str]) -> None:
        """Set scopes from a list."""
        self.scopes_str = ",".join(value) if value else ""

    def is_expired(self) -> bool:
        """Check if the key is expired."""
        if self.expires_at is None:
            return False
        # Handle both naive and aware datetimes
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            # Assume naive datetime is UTC
            expires = expires.replace(tzinfo=timezone.utc)
        return now > expires

    def is_valid(self) -> bool:
        """Check if the key is valid (active and not expired)."""
        return self.is_active and not self.is_expired()

    def has_scope(self, scope: str) -> bool:
        """Check if the key has a specific scope."""
        return scope in self.scopes

    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "name": self.name,
            "key_prefix": self.key_prefix,
            "scopes": self.scopes,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "created_by": self.created_by,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_active": self.is_active,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "usage_count": self.usage_count,
        }

    def __repr__(self) -> str:
        return f"<APIKey {self.id}: {self.name} ({self.key_prefix}...)>"
