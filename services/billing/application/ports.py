"""
Billing Service Application Ports

Command objects and abstract repository interfaces following hexagonal
architecture. Implementations live in infrastructure/adapters/.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from ..domain.entities import Customer, Invoice, PaymentMethod, Subscription


# =============================================================================
# Commands
# =============================================================================

@dataclass
class CreateSubscriptionCommand:
    """Create a new subscription for an organization."""
    organization_id: str
    plan_tier: str
    payment_nonce: str  # Square Web Payments SDK tokenized card nonce


@dataclass
class ChangePlanCommand:
    """Upgrade or downgrade an existing subscription."""
    organization_id: str
    new_plan_tier: str


@dataclass
class CancelSubscriptionCommand:
    """Cancel a subscription."""
    organization_id: str
    at_period_end: bool = True


@dataclass
class AddPaymentMethodCommand:
    """Add a payment method (card) to an organization."""
    organization_id: str
    payment_nonce: str  # Square nonce from client SDK


# =============================================================================
# Repository Ports
# =============================================================================

class CustomerRepositoryPort(ABC):
    @abstractmethod
    async def save(self, customer: Customer) -> None: ...

    @abstractmethod
    async def get_by_org_id(self, organization_id: str) -> Customer | None: ...

    @abstractmethod
    async def get_by_id(self, customer_id: str) -> Customer | None: ...


class SubscriptionRepositoryPort(ABC):
    @abstractmethod
    async def save(self, subscription: Subscription) -> None: ...

    @abstractmethod
    async def get_by_org_id(self, organization_id: str) -> Subscription | None: ...

    @abstractmethod
    async def get_by_id(self, subscription_id: str) -> Subscription | None: ...

    @abstractmethod
    async def get_by_square_id(self, square_subscription_id: str) -> Subscription | None: ...


class InvoiceRepositoryPort(ABC):
    @abstractmethod
    async def save(self, invoice: Invoice) -> None: ...

    @abstractmethod
    async def list_by_org(
        self, organization_id: str, limit: int = 50, offset: int = 0
    ) -> list[Invoice]: ...

    @abstractmethod
    async def get_by_square_id(self, square_invoice_id: str) -> Invoice | None: ...


class PaymentMethodRepositoryPort(ABC):
    @abstractmethod
    async def save(self, method: PaymentMethod) -> None: ...

    @abstractmethod
    async def list_by_org(self, organization_id: str) -> list[PaymentMethod]: ...

    @abstractmethod
    async def delete(self, method_id: str) -> None: ...


# =============================================================================
# External Service Ports
# =============================================================================

class PaymentProviderPort(ABC):
    """Abstract interface to payment provider (Square)."""

    @abstractmethod
    async def create_customer(self, org_id: str, email: str) -> str:
        """Create customer in payment provider. Returns external customer ID."""
        ...

    @abstractmethod
    async def create_subscription(
        self, customer_id: str, plan_tier: str, card_nonce: str
    ) -> dict[str, Any]:
        """Create subscription. Returns provider subscription data."""
        ...

    @abstractmethod
    async def cancel_subscription(self, subscription_id: str) -> None:
        """Cancel a subscription in the payment provider."""
        ...

    @abstractmethod
    async def change_plan(
        self, subscription_id: str, new_plan_tier: str
    ) -> dict[str, Any]:
        """Change subscription plan. Returns updated subscription data."""
        ...

    @abstractmethod
    async def store_card(
        self, customer_id: str, card_nonce: str
    ) -> dict[str, Any]:
        """Store a card for a customer. Returns card data."""
        ...


class OrgServicePort(ABC):
    """Abstract interface to organization service internal API."""

    @abstractmethod
    async def update_plan(self, organization_id: str, plan_tier: str) -> None:
        """Update organization plan tier via internal API."""
        ...


class EventPublisherPort(ABC):
    """Abstract interface for publishing domain events."""

    @abstractmethod
    async def publish(self, event: Any) -> None: ...
