"""
Billing Service Domain Events
"""

from dataclasses import dataclass

from marty_common.events import DomainEvent


@dataclass
class SubscriptionCreatedEvent(DomainEvent):
    """Emitted when a subscription is created."""
    source_service: str = "billing"
    organization_id: str = ""
    plan_tier: str = ""
    square_subscription_id: str = ""


@dataclass
class SubscriptionCanceledEvent(DomainEvent):
    """Emitted when a subscription is canceled."""
    source_service: str = "billing"
    organization_id: str = ""
    plan_tier: str = ""
    at_period_end: bool = True


@dataclass
class PlanChangedEvent(DomainEvent):
    """Emitted when an organization's plan tier changes."""
    source_service: str = "billing"
    organization_id: str = ""
    old_plan: str = ""
    new_plan: str = ""


@dataclass
class PaymentReceivedEvent(DomainEvent):
    """Emitted when a payment is successfully processed."""
    source_service: str = "billing"
    organization_id: str = ""
    amount_cents: int = 0
    currency: str = "USD"


@dataclass
class PaymentFailedEvent(DomainEvent):
    """Emitted when a payment fails."""
    source_service: str = "billing"
    organization_id: str = ""
    amount_cents: int = 0
    reason: str = ""
