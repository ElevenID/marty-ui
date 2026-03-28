"""
PostgreSQL Repository Adapters for Billing Service
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ...application.ports import (
    CustomerRepositoryPort,
    InvoiceRepositoryPort,
    PaymentMethodRepositoryPort,
    SubscriptionRepositoryPort,
)
from ...domain.entities import (
    Customer,
    Invoice,
    InvoiceStatus,
    PaymentMethod,
    Subscription,
    SubscriptionStatus,
)
from ..models import (
    customers_table,
    invoices_table,
    payment_methods_table,
    subscriptions_table,
)

logger = logging.getLogger(__name__)


class PostgresCustomerRepository(CustomerRepositoryPort):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory

    async def save(self, customer: Customer) -> None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(customers_table.c.id).where(
                    customers_table.c.id == customer.id
                )
            )
            exists = result.scalar_one_or_none() is not None

            if exists:
                await session.execute(
                    customers_table.update()
                    .where(customers_table.c.id == customer.id)
                    .values(
                        square_customer_id=customer.square_customer_id,
                        updated_at=customer.updated_at,
                    )
                )
            else:
                await session.execute(
                    customers_table.insert().values(
                        id=customer.id,
                        organization_id=customer.organization_id,
                        square_customer_id=customer.square_customer_id,
                        created_at=customer.created_at,
                        updated_at=customer.updated_at,
                    )
                )
            await session.commit()

    async def get_by_org_id(self, organization_id: str) -> Customer | None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(customers_table).where(
                    customers_table.c.organization_id == organization_id
                )
            )
            row = result.first()
            return _row_to_customer(row) if row else None

    async def get_by_id(self, customer_id: str) -> Customer | None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(customers_table).where(customers_table.c.id == customer_id)
            )
            row = result.first()
            return _row_to_customer(row) if row else None


class PostgresSubscriptionRepository(SubscriptionRepositoryPort):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory

    async def save(self, subscription: Subscription) -> None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(subscriptions_table.c.id).where(
                    subscriptions_table.c.id == subscription.id
                )
            )
            exists = result.scalar_one_or_none() is not None

            values = dict(
                organization_id=subscription.organization_id,
                customer_id=subscription.customer_id,
                square_subscription_id=subscription.square_subscription_id,
                plan_tier=subscription.plan_tier,
                status=subscription.status.value,
                current_period_start=subscription.current_period_start,
                current_period_end=subscription.current_period_end,
                cancel_at_period_end=subscription.cancel_at_period_end,
                updated_at=subscription.updated_at,
            )

            if exists:
                await session.execute(
                    subscriptions_table.update()
                    .where(subscriptions_table.c.id == subscription.id)
                    .values(**values)
                )
            else:
                values["id"] = subscription.id
                values["created_at"] = subscription.created_at
                await session.execute(
                    subscriptions_table.insert().values(**values)
                )
            await session.commit()

    async def get_by_org_id(self, organization_id: str) -> Subscription | None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(subscriptions_table)
                .where(subscriptions_table.c.organization_id == organization_id)
                .order_by(subscriptions_table.c.created_at.desc())
                .limit(1)
            )
            row = result.first()
            return _row_to_subscription(row) if row else None

    async def get_by_id(self, subscription_id: str) -> Subscription | None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(subscriptions_table).where(
                    subscriptions_table.c.id == subscription_id
                )
            )
            row = result.first()
            return _row_to_subscription(row) if row else None

    async def get_by_square_id(
        self, square_subscription_id: str
    ) -> Subscription | None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(subscriptions_table).where(
                    subscriptions_table.c.square_subscription_id
                    == square_subscription_id
                )
            )
            row = result.first()
            return _row_to_subscription(row) if row else None


class PostgresInvoiceRepository(InvoiceRepositoryPort):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory

    async def save(self, invoice: Invoice) -> None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(invoices_table.c.id).where(
                    invoices_table.c.id == invoice.id
                )
            )
            exists = result.scalar_one_or_none() is not None

            if exists:
                await session.execute(
                    invoices_table.update()
                    .where(invoices_table.c.id == invoice.id)
                    .values(
                        status=invoice.status.value,
                        paid_at=invoice.paid_at,
                    )
                )
            else:
                await session.execute(
                    invoices_table.insert().values(
                        id=invoice.id,
                        subscription_id=invoice.subscription_id,
                        organization_id=invoice.organization_id,
                        square_invoice_id=invoice.square_invoice_id,
                        amount_cents=invoice.amount_cents,
                        currency=invoice.currency,
                        status=invoice.status.value,
                        period_start=invoice.period_start,
                        period_end=invoice.period_end,
                        paid_at=invoice.paid_at,
                        created_at=invoice.created_at,
                    )
                )
            await session.commit()

    async def list_by_org(
        self, organization_id: str, limit: int = 50, offset: int = 0
    ) -> list[Invoice]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(invoices_table)
                .where(invoices_table.c.organization_id == organization_id)
                .order_by(invoices_table.c.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            return [_row_to_invoice(row) for row in result.all()]

    async def get_by_square_id(self, square_invoice_id: str) -> Invoice | None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(invoices_table).where(
                    invoices_table.c.square_invoice_id == square_invoice_id
                )
            )
            row = result.first()
            return _row_to_invoice(row) if row else None


class PostgresPaymentMethodRepository(PaymentMethodRepositoryPort):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self.session_factory = session_factory

    async def save(self, method: PaymentMethod) -> None:
        async with self.session_factory() as session:
            # If this is default, unset others
            if method.is_default:
                await session.execute(
                    payment_methods_table.update()
                    .where(
                        payment_methods_table.c.organization_id
                        == method.organization_id
                    )
                    .values(is_default=False)
                )
            await session.execute(
                payment_methods_table.insert().values(
                    id=method.id,
                    organization_id=method.organization_id,
                    square_card_id=method.square_card_id,
                    card_brand=method.card_brand,
                    card_last4=method.card_last4,
                    is_default=method.is_default,
                    created_at=method.created_at,
                )
            )
            await session.commit()

    async def list_by_org(self, organization_id: str) -> list[PaymentMethod]:
        async with self.session_factory() as session:
            result = await session.execute(
                select(payment_methods_table)
                .where(
                    payment_methods_table.c.organization_id == organization_id
                )
                .order_by(payment_methods_table.c.created_at.desc())
            )
            return [_row_to_payment_method(row) for row in result.all()]

    async def delete(self, method_id: str) -> None:
        async with self.session_factory() as session:
            await session.execute(
                payment_methods_table.delete().where(
                    payment_methods_table.c.id == method_id
                )
            )
            await session.commit()


# =============================================================================
# Row Mappers
# =============================================================================


def _row_to_customer(row) -> Customer:
    return Customer(
        id=str(row.id),
        organization_id=row.organization_id,
        square_customer_id=row.square_customer_id,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _row_to_subscription(row) -> Subscription:
    return Subscription(
        id=str(row.id),
        organization_id=row.organization_id,
        customer_id=str(row.customer_id),
        square_subscription_id=row.square_subscription_id,
        plan_tier=row.plan_tier,
        status=SubscriptionStatus(row.status),
        current_period_start=row.current_period_start,
        current_period_end=row.current_period_end,
        cancel_at_period_end=row.cancel_at_period_end,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _row_to_invoice(row) -> Invoice:
    return Invoice(
        id=str(row.id),
        subscription_id=str(row.subscription_id),
        organization_id=row.organization_id,
        square_invoice_id=row.square_invoice_id,
        amount_cents=row.amount_cents,
        currency=row.currency,
        status=InvoiceStatus(row.status),
        period_start=row.period_start,
        period_end=row.period_end,
        paid_at=row.paid_at,
        created_at=row.created_at,
    )


def _row_to_payment_method(row) -> PaymentMethod:
    return PaymentMethod(
        id=str(row.id),
        organization_id=row.organization_id,
        square_card_id=row.square_card_id,
        card_brand=row.card_brand,
        card_last4=row.card_last4,
        is_default=row.is_default,
        created_at=row.created_at,
    )
