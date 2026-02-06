"""
Domain Event Base Classes and Utilities

Provides the foundation for event-driven communication between services.
Uses the marty-microservices-framework messaging infrastructure.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Generic, TypeVar

T = TypeVar("T")


@dataclass
class DomainEvent:
    """
    Base class for all domain events.
    
    Domain events represent facts that have happened in the system.
    They are immutable and contain all the information needed to
    understand what happened.
    """
    
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str = field(default="")
    source_service: str = field(default="")
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    correlation_id: str | None = field(default=None)
    causation_id: str | None = field(default=None)
    version: str = field(default="1.0")
    
    def __post_init__(self) -> None:
        if not self.event_type:
            # Default event type from class name
            self.event_type = self._derive_event_type()
    
    def _derive_event_type(self) -> str:
        """Derive event type from class name."""
        # Convert CamelCase to dot.notation
        # e.g., CredentialTypeConfigured -> credential.type.configured
        name = self.__class__.__name__
        import re
        words = re.findall(r'[A-Z][a-z]*', name)
        return ".".join(w.lower() for w in words)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "source_service": self.source_service,
            "timestamp": self.timestamp.isoformat(),
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "version": self.version,
            "data": self._get_event_data(),
        }
    
    def _get_event_data(self) -> dict[str, Any]:
        """Get event-specific data. Override in subclasses."""
        # Get all fields except base event fields
        base_fields = {
            "event_id", "event_type", "source_service", 
            "timestamp", "correlation_id", "causation_id", "version"
        }
        return {
            k: v for k, v in self.__dict__.items() 
            if k not in base_fields
        }


# =============================================================================
# Auth Service Events
# =============================================================================

@dataclass
class UserAuthenticated(DomainEvent):
    """User successfully authenticated."""
    source_service: str = "auth"
    user_id: str = ""
    email: str = ""
    organization_id: str | None = None


@dataclass
class UserLoggedOut(DomainEvent):
    """User logged out."""
    source_service: str = "auth"
    user_id: str = ""
    session_id: str = ""


@dataclass
class SessionCreated(DomainEvent):
    """New session created."""
    source_service: str = "auth"
    session_id: str = ""
    user_id: str = ""
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# Organization Service Events
# =============================================================================

@dataclass
class OrganizationCreated(DomainEvent):
    """New organization created."""
    source_service: str = "organization"
    organization_id: str = ""
    name: str = ""
    owner_id: str = ""


@dataclass
class MemberAdded(DomainEvent):
    """Member added to organization."""
    source_service: str = "organization"
    organization_id: str = ""
    user_id: str = ""
    role: str = ""
    added_by: str = ""


@dataclass
class MemberRemoved(DomainEvent):
    """Member removed from organization."""
    source_service: str = "organization"
    organization_id: str = ""
    user_id: str = ""
    removed_by: str = ""


@dataclass
class ApiKeyCreated(DomainEvent):
    """API key created."""
    source_service: str = "organization"
    organization_id: str = ""
    api_key_id: str = ""
    name: str = ""
    scopes: list[str] = field(default_factory=list)
    created_by: str = ""


@dataclass
class ApiKeyRevoked(DomainEvent):
    """API key revoked."""
    source_service: str = "organization"
    organization_id: str = ""
    api_key_id: str = ""
    revoked_by: str = ""


# =============================================================================
# Credential Service Events
# =============================================================================

@dataclass
class CredentialTypeConfigured(DomainEvent):
    """Credential type configured for organization."""
    source_service: str = "credential"
    organization_id: str = ""
    credential_type_id: str = ""
    credential_type: str = ""
    configured_by: str = ""


@dataclass
class CredentialTypeDisabled(DomainEvent):
    """Credential type disabled for organization."""
    source_service: str = "credential"
    organization_id: str = ""
    credential_type_id: str = ""
    disabled_by: str = ""


# =============================================================================
# Trust Service Events
# =============================================================================

@dataclass
class TrustConfigured(DomainEvent):
    """Trust framework configured for organization."""
    source_service: str = "trust"
    organization_id: str = ""
    trust_framework: str = ""
    configured_by: str = ""


@dataclass
class IssuerKeyGenerated(DomainEvent):
    """Issuer signing key generated."""
    source_service: str = "trust"
    organization_id: str = ""
    key_id: str = ""
    algorithm: str = ""
    did: str = ""


# =============================================================================
# Issuance Service Events
# =============================================================================

@dataclass
class CredentialOfferCreated(DomainEvent):
    """Credential offer created."""
    source_service: str = "issuance"
    organization_id: str = ""
    transaction_id: str = ""
    credential_type: str = ""
    applicant_id: str = ""


@dataclass
class CredentialIssued(DomainEvent):
    """Credential issued to wallet."""
    source_service: str = "issuance"
    organization_id: str = ""
    transaction_id: str = ""
    credential_type: str = ""
    applicant_id: str = ""
    credential_id: str = ""


@dataclass
class CredentialIssuanceFailed(DomainEvent):
    """Credential issuance failed."""
    source_service: str = "issuance"
    organization_id: str = ""
    transaction_id: str = ""
    error_code: str = ""
    error_message: str = ""


# =============================================================================
# Applicant Service Events
# =============================================================================

@dataclass
class ApplicantCreated(DomainEvent):
    """New applicant created."""
    source_service: str = "applicant"
    organization_id: str = ""
    applicant_id: str = ""
    email: str = ""


@dataclass
class ApplicationSubmitted(DomainEvent):
    """Application submitted for processing."""
    source_service: str = "applicant"
    organization_id: str = ""
    applicant_id: str = ""
    application_id: str = ""
    application_type: str = ""


@dataclass
class ApplicantApproved(DomainEvent):
    """Applicant approved for credential issuance."""
    source_service: str = "applicant"
    organization_id: str = ""
    applicant_id: str = ""
    application_id: str = ""
    approved_by: str = ""


@dataclass
class ApplicantRejected(DomainEvent):
    """Applicant rejected."""
    source_service: str = "applicant"
    organization_id: str = ""
    applicant_id: str = ""
    application_id: str = ""
    rejected_by: str = ""
    reason: str = ""


# =============================================================================
# Event Publisher Interface
# =============================================================================

class EventPublisherPort(ABC):
    """Port interface for publishing domain events."""
    
    @abstractmethod
    async def publish(self, event: DomainEvent) -> None:
        """Publish a single event."""
        ...
    
    @abstractmethod
    async def publish_batch(self, events: list[DomainEvent]) -> None:
        """Publish multiple events."""
        ...


class EventSubscriberPort(ABC):
    """Port interface for subscribing to domain events."""
    
    @abstractmethod
    async def subscribe(
        self, 
        event_types: list[str], 
        handler: Callable[[DomainEvent], Any],
        consumer_group: str | None = None,
    ) -> str:
        """Subscribe to event types. Returns subscription ID."""
        ...
    
    @abstractmethod
    async def unsubscribe(self, subscription_id: str) -> None:
        """Unsubscribe from events."""
        ...
