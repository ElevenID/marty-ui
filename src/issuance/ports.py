"""Issuance storage ports (hexagonal architecture).

This module defines the storage interfaces (ports) for credential issuance,
following the hexagonal architecture pattern from MMF. The ports define
what storage capabilities are needed, while adapters implement the actual
storage mechanisms (Redis, database, etc.).

Note: Key management has been migrated to SpruceIDKeyManager.
Use get_key_manager() from marty_plugin.adapters.credentials.spruceid.

Usage:
    from issuance.ports import IIssuanceStorage
    from issuance.adapters import RedisIssuanceStorage
    
    # Dependency injection
    issuance_storage = RedisIssuanceStorage(cache_manager)
    
    service = IssuanceService(
        issuance_storage=issuance_storage,
    )
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from subscription.models import CredentialOffer, IssuanceSession


# =============================================================================
# Issuance Storage Data Types
# =============================================================================


@dataclass
class StoredSession:
    """Issuance session data for cache storage.
    
    Mirrors the IssuanceSession SQLAlchemy model but is cache-friendly.
    """
    
    id: str
    transaction_id: str
    organization_id: str
    credential_config_id: str
    applicant_id: str
    status: str
    credential_format: str
    pre_authorized_code: str | None = None
    application_id: str | None = None
    device_id: str | None = None
    credential_data: dict[str, Any] | None = None
    issued_credential: str | None = None
    expires_at: str | None = None
    accepted_at: str | None = None
    issued_at: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "id": self.id,
            "transaction_id": self.transaction_id,
            "organization_id": self.organization_id,
            "credential_config_id": self.credential_config_id,
            "applicant_id": self.applicant_id,
            "status": self.status,
            "credential_format": self.credential_format,
            "pre_authorized_code": self.pre_authorized_code,
            "application_id": self.application_id,
            "device_id": self.device_id,
            "credential_data": self.credential_data,
            "issued_credential": self.issued_credential,
            "expires_at": self.expires_at,
            "accepted_at": self.accepted_at,
            "issued_at": self.issued_at,
            "created_at": self.created_at,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StoredSession:
        """Create from dictionary."""
        return cls(
            id=data["id"],
            transaction_id=data["transaction_id"],
            organization_id=data["organization_id"],
            credential_config_id=data["credential_config_id"],
            applicant_id=data["applicant_id"],
            status=data["status"],
            credential_format=data["credential_format"],
            pre_authorized_code=data.get("pre_authorized_code"),
            application_id=data.get("application_id"),
            device_id=data.get("device_id"),
            credential_data=data.get("credential_data"),
            issued_credential=data.get("issued_credential"),
            expires_at=data.get("expires_at"),
            accepted_at=data.get("accepted_at"),
            issued_at=data.get("issued_at"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class StoredOffer:
    """Credential offer data for cache storage."""
    
    id: str
    issuance_session_id: str
    organization_id: str
    offer_uri: str
    offer_payload: dict[str, Any]
    is_active: bool = True
    expires_at: str | None = None
    accessed_at: str | None = None
    access_count: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "id": self.id,
            "issuance_session_id": self.issuance_session_id,
            "organization_id": self.organization_id,
            "offer_uri": self.offer_uri,
            "offer_payload": self.offer_payload,
            "is_active": self.is_active,
            "expires_at": self.expires_at,
            "accessed_at": self.accessed_at,
            "access_count": self.access_count,
            "created_at": self.created_at,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StoredOffer:
        """Create from dictionary."""
        return cls(
            id=data["id"],
            issuance_session_id=data["issuance_session_id"],
            organization_id=data["organization_id"],
            offer_uri=data["offer_uri"],
            offer_payload=data["offer_payload"],
            is_active=data.get("is_active", True),
            expires_at=data.get("expires_at"),
            accessed_at=data.get("accessed_at"),
            access_count=data.get("access_count", 0),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


# =============================================================================
# Storage Ports (Interfaces)
# =============================================================================


@runtime_checkable
class IIssuanceStorage(Protocol):
    """Port for issuance session and offer storage.
    
    This interface defines the storage operations needed for credential
    issuance, including sessions and offers. Adapters implement this
    using Redis, database, or other storage backends.
    
    Key format:
    - Sessions by transaction_id: "session:txn:{transaction_id}"
    - Sessions by id: "session:id:{session_id}"
    - Sessions by pre-auth code: "session:pac:{pre_authorized_code}"
    - Offers by id: "offer:id:{offer_id}"
    - Offers by session: "offer:session:{session_id}"
    """

    # Session operations
    
    async def store_session(
        self,
        session: StoredSession,
        ttl_seconds: int | None = None,
    ) -> None:
        """Store an issuance session.
        
        Args:
            session: The session data to store
            ttl_seconds: Optional TTL for the session
        """
        ...

    async def get_session_by_id(self, session_id: str) -> StoredSession | None:
        """Get a session by its ID.
        
        Args:
            session_id: The session ID
            
        Returns:
            The session if found, None otherwise
        """
        ...

    async def get_session_by_transaction_id(
        self, transaction_id: str
    ) -> StoredSession | None:
        """Get a session by its transaction ID.
        
        Args:
            transaction_id: The OID4VCI transaction ID
            
        Returns:
            The session if found, None otherwise
        """
        ...

    async def get_session_by_pre_auth_code(
        self, pre_authorized_code: str
    ) -> StoredSession | None:
        """Get a session by its pre-authorized code.
        
        Args:
            pre_authorized_code: The OID4VCI pre-authorized code
            
        Returns:
            The session if found, None otherwise
        """
        ...

    async def update_session(
        self,
        session: StoredSession,
        ttl_seconds: int | None = None,
    ) -> None:
        """Update an existing session.
        
        Args:
            session: The updated session data
            ttl_seconds: Optional new TTL
        """
        ...

    async def delete_session(self, session_id: str) -> bool:
        """Delete a session.
        
        Args:
            session_id: The session ID to delete
            
        Returns:
            True if deleted, False if not found
        """
        ...

    # Offer operations

    async def store_offer(
        self,
        offer: StoredOffer,
        ttl_seconds: int | None = None,
    ) -> None:
        """Store a credential offer.
        
        Args:
            offer: The offer data to store
            ttl_seconds: Optional TTL for the offer
        """
        ...

    async def get_offer_by_id(self, offer_id: str) -> StoredOffer | None:
        """Get an offer by its ID.
        
        Args:
            offer_id: The offer ID
            
        Returns:
            The offer if found, None otherwise
        """
        ...

    async def get_offers_by_session(self, session_id: str) -> list[StoredOffer]:
        """Get all offers for a session.
        
        Args:
            session_id: The issuance session ID
            
        Returns:
            List of offers for the session
        """
        ...

    async def update_offer(
        self,
        offer: StoredOffer,
        ttl_seconds: int | None = None,
    ) -> None:
        """Update an existing offer.
        
        Args:
            offer: The updated offer data
            ttl_seconds: Optional new TTL
        """
        ...

    async def delete_offer(self, offer_id: str) -> bool:
        """Delete an offer.
        
        Args:
            offer_id: The offer ID to delete
            
        Returns:
            True if deleted, False if not found
        """
        ...


# Note: IKeyStorage has been removed.
# Key management is now handled by SpruceIDKeyManager.
# Use get_key_manager() from marty_plugin.adapters.credentials.spruceid.


__all__ = [
    # Data classes
    "StoredSession",
    "StoredOffer",
    # Ports
    "IIssuanceStorage",
]
