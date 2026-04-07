"""
Billing Service Use Cases
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from ..domain.entities import (
    Customer,
    Invoice,
    PaymentMethod,
    Subscription,
    SubscriptionStatus,
)
from ..domain.events import (
    PaymentFailedEvent,
    PaymentReceivedEvent,
    PlanChangedEvent,
    SubscriptionCanceledEvent,
    SubscriptionCreatedEvent,
)
from .ports import (
    AddPaymentMethodCommand,
    CancelSubscriptionCommand,
    ChangePlanCommand,
    CreateSubscriptionCommand,
    CustomerRepositoryPort,
    EventPublisherPort,
    InvoiceRepositoryPort,
    OrgServicePort,
    PaymentMethodRepositoryPort,
    PaymentProviderPort,
    SubscriptionRepositoryPort,
)

logger = logging.getLogger(__name__)


@dataclass
class BillingUseCase:
    """Core billing business logic."""

    customer_repo: CustomerRepositoryPort
    subscription_repo: SubscriptionRepositoryPort
    invoice_repo: InvoiceRepositoryPort
    payment_method_repo: PaymentMethodRepositoryPort
    payment_provider: PaymentProviderPort
    org_service: OrgServicePort
    event_publisher: EventPublisherPort

    async def create_subscription(
        self, command: CreateSubscriptionCommand
    ) -> Subscription:
        """Create a new subscription for an organization.

        1. Get or create Square customer
        2. Create subscription in Square
        3. Store locally
        4. Update org plan in org service
        5. Publish event
        """
        # Check for existing active subscription
        existing = await self.subscription_repo.get_by_org_id(command.organization_id)
        if existing and existing.status == SubscriptionStatus.ACTIVE:
            raise ValueError("Organization already has an active subscription")

        # Get or create customer
        customer = await self.customer_repo.get_by_org_id(command.organization_id)
        if not customer:
            # Resolve org contact email for the payment provider
            org_email = ""
            try:
                org_email = await self.org_service.get_contact_email(
                    command.organization_id
                )
            except Exception:
                logger.warning(
                    "Could not resolve contact email for org %s, "
                    "creating Square customer without email",
                    command.organization_id,
                )
            square_customer_id = await self.payment_provider.create_customer(
                org_id=command.organization_id,
                email=org_email,
            )
            customer = Customer(
                organization_id=command.organization_id,
                square_customer_id=square_customer_id,
            )
            await self.customer_repo.save(customer)

        # Create subscription in Square
        provider_data = await self.payment_provider.create_subscription(
            customer_id=customer.square_customer_id,
            plan_tier=command.plan_tier,
            card_nonce=command.payment_nonce,
        )

        # Store subscription
        subscription = Subscription.create(
            organization_id=command.organization_id,
            customer_id=customer.id,
            plan_tier=command.plan_tier,
            square_subscription_id=provider_data.get("subscription_id", ""),
        )
        await self.subscription_repo.save(subscription)

        # Update org plan via internal API
        await self.org_service.update_plan(command.organization_id, command.plan_tier)

        # Publish event
        await self.event_publisher.publish(
            SubscriptionCreatedEvent(
                organization_id=command.organization_id,
                plan_tier=command.plan_tier,
                square_subscription_id=subscription.square_subscription_id,
            )
        )

        logger.info(
            f"Subscription created: org={command.organization_id} plan={command.plan_tier}"
        )
        return subscription

    async def change_plan(self, command: ChangePlanCommand) -> Subscription:
        """Upgrade or downgrade a subscription."""
        subscription = await self.subscription_repo.get_by_org_id(
            command.organization_id
        )
        if not subscription:
            raise ValueError("No active subscription found")

        if subscription.status != SubscriptionStatus.ACTIVE:
            raise ValueError(f"Subscription is {subscription.status.value}, cannot change plan")

        old_plan = subscription.plan_tier

        # Update in Square
        await self.payment_provider.change_plan(
            subscription_id=subscription.square_subscription_id,
            new_plan_tier=command.new_plan_tier,
        )

        # Update local record
        subscription.plan_tier = command.new_plan_tier
        subscription.activate()
        await self.subscription_repo.save(subscription)

        # Update org plan
        await self.org_service.update_plan(
            command.organization_id, command.new_plan_tier
        )

        await self.event_publisher.publish(
            PlanChangedEvent(
                organization_id=command.organization_id,
                old_plan=old_plan,
                new_plan=command.new_plan_tier,
            )
        )

        logger.info(
            f"Plan changed: org={command.organization_id} {old_plan} → {command.new_plan_tier}"
        )
        return subscription

    async def cancel_subscription(
        self, command: CancelSubscriptionCommand
    ) -> Subscription:
        """Cancel a subscription."""
        subscription = await self.subscription_repo.get_by_org_id(
            command.organization_id
        )
        if not subscription:
            raise ValueError("No active subscription found")

        # Cancel in Square
        await self.payment_provider.cancel_subscription(
            subscription_id=subscription.square_subscription_id,
        )

        # Update local record
        subscription.cancel(at_period_end=command.at_period_end)
        await self.subscription_repo.save(subscription)

        await self.event_publisher.publish(
            SubscriptionCanceledEvent(
                organization_id=command.organization_id,
                plan_tier=subscription.plan_tier,
                at_period_end=command.at_period_end,
            )
        )

        logger.info(
            f"Subscription canceled: org={command.organization_id} "
            f"at_period_end={command.at_period_end}"
        )
        return subscription

    async def get_subscription(self, organization_id: str) -> Subscription | None:
        """Get the current subscription for an organization."""
        return await self.subscription_repo.get_by_org_id(organization_id)

    async def get_invoices(
        self, organization_id: str, limit: int = 50, offset: int = 0
    ) -> list[Invoice]:
        """Get invoices for an organization."""
        return await self.invoice_repo.list_by_org(
            organization_id, limit=limit, offset=offset
        )

    async def add_payment_method(
        self, command: AddPaymentMethodCommand
    ) -> PaymentMethod:
        """Add a payment method to an organization."""
        customer = await self.customer_repo.get_by_org_id(command.organization_id)
        if not customer:
            raise ValueError("No billing customer found — subscribe first")

        card_data = await self.payment_provider.store_card(
            customer_id=customer.square_customer_id,
            card_nonce=command.payment_nonce,
        )

        method = PaymentMethod(
            organization_id=command.organization_id,
            square_card_id=card_data.get("card_id", ""),
            card_brand=card_data.get("card_brand", ""),
            card_last4=card_data.get("last_4", ""),
            is_default=True,
        )
        await self.payment_method_repo.save(method)
        return method

    async def get_payment_methods(
        self, organization_id: str
    ) -> list[PaymentMethod]:
        """List payment methods for an organization."""
        return await self.payment_method_repo.list_by_org(organization_id)

    # ── Webhook Handling ─────────────────────────────────────────────

    async def handle_payment_succeeded(
        self, square_subscription_id: str, amount_cents: int, square_invoice_id: str
    ) -> None:
        """Handle successful payment webhook from Square."""
        subscription = await self.subscription_repo.get_by_square_id(
            square_subscription_id
        )
        if not subscription:
            logger.warning(
                f"Payment for unknown subscription: {square_subscription_id}"
            )
            return

        # Record invoice
        invoice = Invoice(
            subscription_id=subscription.id,
            organization_id=subscription.organization_id,
            square_invoice_id=square_invoice_id,
            amount_cents=amount_cents,
        )
        invoice.mark_paid()
        await self.invoice_repo.save(invoice)

        # Ensure subscription is active
        if subscription.status != SubscriptionStatus.ACTIVE:
            subscription.activate()
            await self.subscription_repo.save(subscription)
            await self.org_service.update_plan(
                subscription.organization_id, subscription.plan_tier
            )

        await self.event_publisher.publish(
            PaymentReceivedEvent(
                organization_id=subscription.organization_id,
                amount_cents=amount_cents,
            )
        )

    async def handle_payment_failed(
        self, square_subscription_id: str, amount_cents: int
    ) -> None:
        """Handle failed payment webhook from Square."""
        subscription = await self.subscription_repo.get_by_square_id(
            square_subscription_id
        )
        if not subscription:
            return

        subscription.mark_past_due()
        await self.subscription_repo.save(subscription)

        await self.event_publisher.publish(
            PaymentFailedEvent(
                organization_id=subscription.organization_id,
                amount_cents=amount_cents,
                reason="payment_failed",
            )
        )

    async def handle_subscription_canceled(
        self, square_subscription_id: str
    ) -> None:
        """Handle subscription cancellation webhook from Square."""
        subscription = await self.subscription_repo.get_by_square_id(
            square_subscription_id
        )
        if not subscription:
            return

        old_plan = subscription.plan_tier
        subscription.status = SubscriptionStatus.CANCELED
        await self.subscription_repo.save(subscription)

        # Downgrade to free
        await self.org_service.update_plan(subscription.organization_id, "free")

        await self.event_publisher.publish(
            PlanChangedEvent(
                organization_id=subscription.organization_id,
                old_plan=old_plan,
                new_plan="free",
            )
        )
