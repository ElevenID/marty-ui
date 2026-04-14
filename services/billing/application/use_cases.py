"""
Billing Service Use Cases
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
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

_HOSTED_PILOT_PLAN_ALIASES = {"starter", "hosted_pilot", "pilot"}


def _normalize_plan_tier(plan_tier: str) -> str:
    normalized = (plan_tier or "").strip().lower()
    if normalized in {"hosted_pilot", "pilot"}:
        return "starter"
    if normalized in {"self_hosted_production", "self-hosted-production"}:
        return "professional"
    return normalized


def _read_positive_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    return parsed if parsed > 0 else default


def _parse_datetime_value(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        return None

    normalized = value.strip()
    if not normalized:
        return None
    if len(normalized) == 10 and normalized[4] == "-" and normalized[7] == "-":
        normalized = f"{normalized}T00:00:00+00:00"
    normalized = normalized.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _provider_plan_expires_at(provider_data: dict[str, Any] | None) -> datetime | None:
    provider_data = provider_data or {}
    for key in ("current_period_end", "plan_expires_at", "charged_through_date", "cancel_at"):
        parsed = _parse_datetime_value(provider_data.get(key))
        if parsed is not None:
            return parsed
    return None


def _resolve_plan_expires_at(
    plan_tier: str,
    *,
    current_period_end: datetime | None = None,
    provider_data: dict[str, Any] | None = None,
    reference_at: datetime | None = None,
) -> datetime | None:
    explicit_expiry = _parse_datetime_value(current_period_end)
    if explicit_expiry is not None:
        return explicit_expiry

    provider_expiry = _provider_plan_expires_at(provider_data)
    if provider_expiry is not None:
        return provider_expiry

    normalized = _normalize_plan_tier(plan_tier)
    if normalized not in _HOSTED_PILOT_PLAN_ALIASES:
        return None

    duration_days = _read_positive_int_env(
        "HOSTED_PILOT_PLAN_DURATION_DAYS",
        _read_positive_int_env("HOSTED_PILOT_RETENTION_DAYS", 30),
    )
    base_time = reference_at or datetime.now(timezone.utc)
    return base_time + timedelta(days=duration_days)


def _build_plan_settings_patch(plan_tier: str) -> dict[str, Any]:
    normalized = _normalize_plan_tier(plan_tier)
    if normalized in _HOSTED_PILOT_PLAN_ALIASES:
        retention_days = _read_positive_int_env("HOSTED_PILOT_RETENTION_DAYS", 30)
        return {
            "pilot_retention_enabled": True,
            "pilot_retention_days": retention_days,
            "audit_retention_days": retention_days,
            "data_retention_mode": "hosted_pilot_rolling_purge",
        }

    return {
        "pilot_retention_enabled": False,
        "pilot_retention_days": None,
        "pilot_retention_last_purged_at": None,
        "audit_retention_days": None,
        "data_retention_mode": "standard",
    }


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

    async def _sync_org_plan_state(
        self,
        organization_id: str,
        plan_tier: str,
        *,
        current_period_end: datetime | None = None,
        provider_data: dict[str, Any] | None = None,
        reference_at: datetime | None = None,
    ) -> datetime | None:
        normalized_plan = _normalize_plan_tier(plan_tier)
        plan_expires_at = _resolve_plan_expires_at(
            normalized_plan,
            current_period_end=current_period_end,
            provider_data=provider_data,
            reference_at=reference_at,
        )
        await self.org_service.update_plan(
            organization_id,
            normalized_plan,
            plan_expires_at=plan_expires_at,
            settings_patch=_build_plan_settings_patch(normalized_plan),
        )
        return plan_expires_at

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
        subscription.current_period_end = _resolve_plan_expires_at(
            subscription.plan_tier,
            current_period_end=subscription.current_period_end,
            provider_data=provider_data,
            reference_at=subscription.current_period_start or subscription.created_at,
        )
        await self.subscription_repo.save(subscription)

        # Update org plan via internal API
        await self._sync_org_plan_state(
            command.organization_id,
            subscription.plan_tier,
            current_period_end=subscription.current_period_end,
            provider_data=provider_data,
            reference_at=subscription.current_period_start or subscription.created_at,
        )

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
        provider_data = await self.payment_provider.change_plan(
            subscription_id=subscription.square_subscription_id,
            new_plan_tier=command.new_plan_tier,
        )

        # Update local record
        subscription.plan_tier = command.new_plan_tier
        subscription.activate()
        provider_expiry = _provider_plan_expires_at(provider_data)
        if _normalize_plan_tier(subscription.plan_tier) not in _HOSTED_PILOT_PLAN_ALIASES and provider_expiry is None:
            subscription.current_period_end = None
        else:
            subscription.current_period_end = _resolve_plan_expires_at(
                subscription.plan_tier,
                current_period_end=subscription.current_period_end,
                provider_data=provider_data,
                reference_at=subscription.updated_at,
            )
        await self.subscription_repo.save(subscription)

        # Update org plan
        await self._sync_org_plan_state(
            command.organization_id,
            subscription.plan_tier,
            current_period_end=subscription.current_period_end,
            provider_data=provider_data,
            reference_at=subscription.updated_at,
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
        if command.at_period_end:
            subscription.current_period_end = _resolve_plan_expires_at(
                subscription.plan_tier,
                current_period_end=subscription.current_period_end,
                reference_at=subscription.updated_at,
            )
        await self.subscription_repo.save(subscription)

        if command.at_period_end:
            await self._sync_org_plan_state(
                command.organization_id,
                subscription.plan_tier,
                current_period_end=subscription.current_period_end,
                reference_at=subscription.updated_at,
            )
        else:
            await self._sync_org_plan_state(
                command.organization_id,
                "free",
                current_period_end=None,
                reference_at=subscription.updated_at,
            )

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
            subscription.current_period_end = _resolve_plan_expires_at(
                subscription.plan_tier,
                current_period_end=subscription.current_period_end,
                reference_at=subscription.updated_at,
            )
            await self.subscription_repo.save(subscription)
            await self._sync_org_plan_state(
                subscription.organization_id,
                subscription.plan_tier,
                current_period_end=subscription.current_period_end,
                reference_at=subscription.updated_at,
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
        await self._sync_org_plan_state(
            subscription.organization_id,
            "free",
            current_period_end=None,
            reference_at=subscription.updated_at,
        )

        await self.event_publisher.publish(
            PlanChangedEvent(
                organization_id=subscription.organization_id,
                old_plan=old_plan,
                new_plan="free",
            )
        )
