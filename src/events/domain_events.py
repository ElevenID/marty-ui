"""Domain event definitions extending MMF Message semantics.

This module defines typed domain events for the event-driven architecture.
Events are published through MMF messaging infrastructure and consumed by
the Notification Hub for multi-channel delivery.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional
import uuid

# Import MMF messaging types when available
# from mmf.core.messaging import Message, MessagePriority, MessageHeaders


class DomainEventType(str, Enum):
    """Enumeration of all domain event types."""

    # Credential Lifecycle Events
    CREDENTIAL_ISSUED = "credential.issued"
    CREDENTIAL_REVOKED = "credential.revoked"
    CREDENTIAL_STATUS_CHANGED = "credential.status_changed"
    CREDENTIAL_EXPIRED = "credential.expired"
    CREDENTIAL_SUSPENDED = "credential.suspended"
    CREDENTIAL_REINSTATED = "credential.reinstated"

    # Trust Anchor Events
    DSC_REVOKED = "dsc.revoked"
    DSC_EXPIRED = "dsc.expired"
    DSC_ADDED = "dsc.added"
    CSCA_REVOKED = "csca.revoked"
    CSCA_EXPIRED = "csca.expired"
    CSCA_ADDED = "csca.added"
    TRUST_ANCHOR_CASCADE = "trust_anchor.cascade"
    CRL_UPDATED = "crl.updated"

    # Subscription & Billing Events
    SUBSCRIPTION_CREATED = "subscription.created"
    SUBSCRIPTION_CANCELLED = "subscription.cancelled"
    SUBSCRIPTION_RENEWED = "subscription.renewed"
    SUBSCRIPTION_UPGRADED = "subscription.upgraded"
    SUBSCRIPTION_DOWNGRADED = "subscription.downgraded"
    PAYMENT_CONFIRMED = "payment.confirmed"
    PAYMENT_FAILED = "payment.failed"
    PAYMENT_REFUNDED = "payment.refunded"
    INVOICE_GENERATED = "invoice.generated"
    USAGE_THRESHOLD_REACHED = "usage.threshold_reached"
    USAGE_LIMIT_EXCEEDED = "usage.limit_exceeded"

    # Trust Registry Events
    TRUST_REGISTRY_UPDATED = "trust_registry.updated"
    TRUST_REGISTRY_DELTA = "trust_registry.delta"

    # API Key Events
    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"
    API_KEY_ROTATED = "api_key.rotated"

    # Webhook Events
    WEBHOOK_REGISTERED = "webhook.registered"
    WEBHOOK_DEACTIVATED = "webhook.deactivated"
    WEBHOOK_DELIVERY_FAILED = "webhook.delivery_failed"


class MessagePriority(str, Enum):
    """Message priority levels (mirrors MMF MessagePriority)."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


@dataclass
class MessageHeaders:
    """Message headers for routing and tracing."""

    correlation_id: str
    content_type: str = "application/json"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    custom_headers: dict[str, Any] = field(default_factory=dict)


@dataclass
class DomainEvent:
    """Base domain event extending MMF Message semantics.

    All domain events inherit from this base class and can be converted
    to MMF Messages for publishing through the messaging infrastructure.

    Attributes:
        event_type: The type of domain event
        tenant_id: The organization/tenant this event belongs to
        aggregate_id: The ID of the aggregate (entity) this event relates to
        aggregate_type: The type name of the aggregate
        payload: Event-specific data
        occurred_at: When the event occurred
        event_id: Unique identifier for this event instance
        correlation_id: ID for correlating related events
        causation_id: ID of the event that caused this event
        actor_id: ID of the user/system that triggered the event
        actor_type: Type of actor (user, system, api_key)
    """

    event_type: DomainEventType
    tenant_id: str
    aggregate_id: str
    aggregate_type: str
    payload: dict[str, Any]
    occurred_at: datetime = field(default_factory=datetime.utcnow)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: Optional[str] = None
    causation_id: Optional[str] = None
    actor_id: Optional[str] = None
    actor_type: Optional[str] = None

    def to_message_dict(self, priority: MessagePriority = MessagePriority.NORMAL) -> dict[str, Any]:
        """Convert to dictionary suitable for MMF Message construction.

        Returns:
            Dictionary with id, body, headers, priority, routing_key
        """
        return {
            "id": self.event_id,
            "body": {
                "event_type": self.event_type.value,
                "tenant_id": self.tenant_id,
                "aggregate_id": self.aggregate_id,
                "aggregate_type": self.aggregate_type,
                "payload": self.payload,
                "occurred_at": self.occurred_at.isoformat(),
                "actor_id": self.actor_id,
                "actor_type": self.actor_type,
            },
            "headers": {
                "correlation_id": self.correlation_id or self.event_id,
                "content_type": "application/json",
                "timestamp": self.occurred_at.isoformat(),
                "causation_id": self.causation_id,
                "tenant_id": self.tenant_id,
                "event_type": self.event_type.value,
            },
            "priority": priority.value,
            "routing_key": f"{self.tenant_id}.{self.event_type.value}",
        }

    def with_correlation(self, correlation_id: str) -> "DomainEvent":
        """Create a copy with the specified correlation ID."""
        return DomainEvent(
            event_type=self.event_type,
            tenant_id=self.tenant_id,
            aggregate_id=self.aggregate_id,
            aggregate_type=self.aggregate_type,
            payload=self.payload,
            occurred_at=self.occurred_at,
            event_id=self.event_id,
            correlation_id=correlation_id,
            causation_id=self.causation_id,
            actor_id=self.actor_id,
            actor_type=self.actor_type,
        )

    def caused_by(self, causing_event: "DomainEvent") -> "DomainEvent":
        """Create a copy linked to a causing event."""
        return DomainEvent(
            event_type=self.event_type,
            tenant_id=self.tenant_id,
            aggregate_id=self.aggregate_id,
            aggregate_type=self.aggregate_type,
            payload=self.payload,
            occurred_at=self.occurred_at,
            event_id=self.event_id,
            correlation_id=causing_event.correlation_id or causing_event.event_id,
            causation_id=causing_event.event_id,
            actor_id=self.actor_id,
            actor_type=self.actor_type,
        )


# Typed Event Classes for better type safety and IDE support


@dataclass
class CredentialIssuedEvent(DomainEvent):
    """Event fired when a credential is issued."""

    def __init__(
        self,
        tenant_id: str,
        credential_id: str,
        credential_type: str,
        holder_did: str,
        issuer_did: str,
        claims: dict[str, Any],
        status_list_index: Optional[int] = None,
        **kwargs,
    ):
        super().__init__(
            event_type=DomainEventType.CREDENTIAL_ISSUED,
            tenant_id=tenant_id,
            aggregate_id=credential_id,
            aggregate_type="Credential",
            payload={
                "credential_type": credential_type,
                "holder_did": holder_did,
                "issuer_did": issuer_did,
                "claims": claims,
                "status_list_index": status_list_index,
            },
            **kwargs,
        )


@dataclass
class CredentialRevokedEvent(DomainEvent):
    """Event fired when a credential is revoked."""

    def __init__(
        self,
        tenant_id: str,
        credential_id: str,
        credential_type: str,
        reason: str,
        revoked_by: str,
        status_list_format: str,
        cascade_source: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(
            event_type=DomainEventType.CREDENTIAL_REVOKED,
            tenant_id=tenant_id,
            aggregate_id=credential_id,
            aggregate_type="Credential",
            payload={
                "credential_type": credential_type,
                "reason": reason,
                "revoked_by": revoked_by,
                "status_list_format": status_list_format,
                "cascade_source": cascade_source,
            },
            **kwargs,
        )


@dataclass
class DSCRevokedEvent(DomainEvent):
    """Event fired when a Document Signer Certificate is revoked."""

    def __init__(
        self,
        tenant_id: str,
        dsc_id: str,
        issuing_country: str,
        reason: str,
        cascade_policy: str,
        affected_credential_count: int,
        **kwargs,
    ):
        super().__init__(
            event_type=DomainEventType.DSC_REVOKED,
            tenant_id=tenant_id,
            aggregate_id=dsc_id,
            aggregate_type="DSC",
            payload={
                "issuing_country": issuing_country,
                "reason": reason,
                "cascade_policy": cascade_policy,
                "affected_credential_count": affected_credential_count,
            },
            **kwargs,
        )


@dataclass
class CSCARevokedEvent(DomainEvent):
    """Event fired when a Country Signing CA is revoked."""

    def __init__(
        self,
        tenant_id: str,
        csca_id: str,
        country_code: str,
        reason: str,
        cascade_policy: str,
        affected_dsc_count: int,
        affected_credential_count: int,
        **kwargs,
    ):
        super().__init__(
            event_type=DomainEventType.CSCA_REVOKED,
            tenant_id=tenant_id,
            aggregate_id=csca_id,
            aggregate_type="CSCA",
            payload={
                "country_code": country_code,
                "reason": reason,
                "cascade_policy": cascade_policy,
                "affected_dsc_count": affected_dsc_count,
                "affected_credential_count": affected_credential_count,
            },
            **kwargs,
        )


@dataclass
class TrustAnchorCascadeEvent(DomainEvent):
    """Event fired when trust anchor revocation triggers a cascade."""

    def __init__(
        self,
        tenant_id: str,
        source_id: str,
        source_type: str,
        cascade_policy: str,
        affected_credentials: list[str],
        action_required: bool,
        **kwargs,
    ):
        super().__init__(
            event_type=DomainEventType.TRUST_ANCHOR_CASCADE,
            tenant_id=tenant_id,
            aggregate_id=source_id,
            aggregate_type=source_type,
            payload={
                "cascade_policy": cascade_policy,
                "affected_credentials": affected_credentials,
                "affected_count": len(affected_credentials),
                "action_required": action_required,
            },
            **kwargs,
        )


@dataclass
class SubscriptionCreatedEvent(DomainEvent):
    """Event fired when a subscription is created."""

    def __init__(
        self,
        tenant_id: str,
        subscription_id: str,
        tier: str,
        billing_period: str,
        square_subscription_id: str,
        **kwargs,
    ):
        super().__init__(
            event_type=DomainEventType.SUBSCRIPTION_CREATED,
            tenant_id=tenant_id,
            aggregate_id=subscription_id,
            aggregate_type="Subscription",
            payload={
                "tier": tier,
                "billing_period": billing_period,
                "square_subscription_id": square_subscription_id,
            },
            **kwargs,
        )


@dataclass
class SubscriptionCancelledEvent(DomainEvent):
    """Event fired when a subscription is cancelled."""

    def __init__(
        self,
        tenant_id: str,
        subscription_id: str,
        reason: str,
        effective_date: datetime,
        **kwargs,
    ):
        super().__init__(
            event_type=DomainEventType.SUBSCRIPTION_CANCELLED,
            tenant_id=tenant_id,
            aggregate_id=subscription_id,
            aggregate_type="Subscription",
            payload={
                "reason": reason,
                "effective_date": effective_date.isoformat(),
            },
            **kwargs,
        )


@dataclass
class PaymentConfirmedEvent(DomainEvent):
    """Event fired when a payment is confirmed."""

    def __init__(
        self,
        tenant_id: str,
        payment_id: str,
        amount_cents: int,
        currency: str,
        square_payment_id: str,
        subscription_id: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(
            event_type=DomainEventType.PAYMENT_CONFIRMED,
            tenant_id=tenant_id,
            aggregate_id=payment_id,
            aggregate_type="Payment",
            payload={
                "amount_cents": amount_cents,
                "currency": currency,
                "square_payment_id": square_payment_id,
                "subscription_id": subscription_id,
            },
            **kwargs,
        )


@dataclass
class PaymentFailedEvent(DomainEvent):
    """Event fired when a payment fails."""

    def __init__(
        self,
        tenant_id: str,
        payment_id: str,
        amount_cents: int,
        currency: str,
        failure_reason: str,
        retry_count: int,
        next_retry_at: Optional[datetime] = None,
        **kwargs,
    ):
        super().__init__(
            event_type=DomainEventType.PAYMENT_FAILED,
            tenant_id=tenant_id,
            aggregate_id=payment_id,
            aggregate_type="Payment",
            payload={
                "amount_cents": amount_cents,
                "currency": currency,
                "failure_reason": failure_reason,
                "retry_count": retry_count,
                "next_retry_at": next_retry_at.isoformat() if next_retry_at else None,
            },
            **kwargs,
        )


@dataclass
class UsageThresholdReachedEvent(DomainEvent):
    """Event fired when usage reaches a threshold percentage."""

    def __init__(
        self,
        tenant_id: str,
        resource_type: str,
        threshold_percent: int,
        current_usage: int,
        limit: int,
        **kwargs,
    ):
        super().__init__(
            event_type=DomainEventType.USAGE_THRESHOLD_REACHED,
            tenant_id=tenant_id,
            aggregate_id=tenant_id,
            aggregate_type="Organization",
            payload={
                "resource_type": resource_type,
                "threshold_percent": threshold_percent,
                "current_usage": current_usage,
                "limit": limit,
                "remaining": limit - current_usage,
            },
            **kwargs,
        )


@dataclass
class TrustRegistryUpdatedEvent(DomainEvent):
    """Event fired when the trust registry is updated."""

    def __init__(
        self,
        tenant_id: str,
        registry_version: int,
        update_type: str,
        entries_added: int,
        entries_removed: int,
        entries_modified: int,
        **kwargs,
    ):
        super().__init__(
            event_type=DomainEventType.TRUST_REGISTRY_UPDATED,
            tenant_id=tenant_id,
            aggregate_id=f"registry-{registry_version}",
            aggregate_type="TrustRegistry",
            payload={
                "registry_version": registry_version,
                "update_type": update_type,
                "entries_added": entries_added,
                "entries_removed": entries_removed,
                "entries_modified": entries_modified,
                "total_changes": entries_added + entries_removed + entries_modified,
            },
            **kwargs,
        )


@dataclass
class TrustRegistryDeltaEvent(DomainEvent):
    """Event fired with delta changes for mobile wallet sync."""

    def __init__(
        self,
        tenant_id: str,
        from_version: int,
        to_version: int,
        delta_entries: list[dict[str, Any]],
        **kwargs,
    ):
        super().__init__(
            event_type=DomainEventType.TRUST_REGISTRY_DELTA,
            tenant_id=tenant_id,
            aggregate_id=f"delta-{from_version}-{to_version}",
            aggregate_type="TrustRegistry",
            payload={
                "from_version": from_version,
                "to_version": to_version,
                "delta_entries": delta_entries,
                "entry_count": len(delta_entries),
            },
            **kwargs,
        )
