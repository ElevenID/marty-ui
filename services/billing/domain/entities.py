"""
Billing Service Domain Entities
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class SubscriptionStatus(str, Enum):
    """Subscription lifecycle states."""
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    PENDING = "pending"


class InvoiceStatus(str, Enum):
    """Invoice payment states."""
    PAID = "paid"
    PENDING = "pending"
    FAILED = "failed"
    VOIDED = "voided"


@dataclass
class Customer:
    """Maps an organization to an external payment provider customer."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    square_customer_id: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "square_customer_id": self.square_customer_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class Subscription:
    """A plan subscription for an organization."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    customer_id: str = ""
    square_subscription_id: str = ""
    plan_tier: str = "free"
    status: SubscriptionStatus = SubscriptionStatus.PENDING
    current_period_start: datetime | None = None
    current_period_end: datetime | None = None
    cancel_at_period_end: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @staticmethod
    def create(
        organization_id: str,
        customer_id: str,
        plan_tier: str,
        square_subscription_id: str = "",
    ) -> Subscription:
        now = datetime.now(timezone.utc)
        return Subscription(
            organization_id=organization_id,
            customer_id=customer_id,
            plan_tier=plan_tier,
            square_subscription_id=square_subscription_id,
            status=SubscriptionStatus.ACTIVE,
            current_period_start=now,
            created_at=now,
            updated_at=now,
        )

    def cancel(self, at_period_end: bool = True) -> None:
        if at_period_end:
            self.cancel_at_period_end = True
        else:
            self.status = SubscriptionStatus.CANCELED
        self.updated_at = datetime.now(timezone.utc)

    def mark_past_due(self) -> None:
        self.status = SubscriptionStatus.PAST_DUE
        self.updated_at = datetime.now(timezone.utc)

    def activate(self) -> None:
        self.status = SubscriptionStatus.ACTIVE
        self.cancel_at_period_end = False
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "customer_id": self.customer_id,
            "square_subscription_id": self.square_subscription_id,
            "plan_tier": self.plan_tier,
            "status": self.status.value,
            "current_period_start": self.current_period_start.isoformat() if self.current_period_start else None,
            "current_period_end": self.current_period_end.isoformat() if self.current_period_end else None,
            "cancel_at_period_end": self.cancel_at_period_end,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class Invoice:
    """A billing invoice record."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    subscription_id: str = ""
    organization_id: str = ""
    square_invoice_id: str = ""
    amount_cents: int = 0
    currency: str = "USD"
    status: InvoiceStatus = InvoiceStatus.PENDING
    period_start: datetime | None = None
    period_end: datetime | None = None
    paid_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def mark_paid(self) -> None:
        self.status = InvoiceStatus.PAID
        self.paid_at = datetime.now(timezone.utc)

    def mark_failed(self) -> None:
        self.status = InvoiceStatus.FAILED

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "subscription_id": self.subscription_id,
            "organization_id": self.organization_id,
            "square_invoice_id": self.square_invoice_id,
            "amount_cents": self.amount_cents,
            "currency": self.currency,
            "status": self.status.value,
            "period_start": self.period_start.isoformat() if self.period_start else None,
            "period_end": self.period_end.isoformat() if self.period_end else None,
            "paid_at": self.paid_at.isoformat() if self.paid_at else None,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class PaymentMethod:
    """A stored payment method for an organization."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    square_card_id: str = ""
    card_brand: str = ""
    card_last4: str = ""
    is_default: bool = False
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "card_brand": self.card_brand,
            "card_last4": self.card_last4,
            "is_default": self.is_default,
            "created_at": self.created_at.isoformat(),
        }
