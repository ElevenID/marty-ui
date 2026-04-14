"""
Billing Service Unit Tests

Tests the domain entities, use case logic, HTTP adapter, and webhook
verification using mock ports (no DB, no Square, no network).
"""

from __future__ import annotations

import base64
from datetime import datetime
import hashlib
import hmac as hmac_mod
import json
from dataclasses import dataclass, field
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.billing.application.ports import (
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
from services.billing.application.use_cases import BillingUseCase
from services.billing.domain.entities import (
    Customer,
    Invoice,
    InvoiceStatus,
    PaymentMethod,
    Subscription,
    SubscriptionStatus,
)
from services.billing.infrastructure.adapters.http_adapter import (
    configure_billing_router,
    router,
)
from services.billing.infrastructure.adapters.webhook_adapter import (
    configure_webhook_router,
    webhook_router,
)


# ============================================================================
# In-Memory Fakes
# ============================================================================


class FakeCustomerRepo(CustomerRepositoryPort):
    def __init__(self) -> None:
        self._store: dict[str, Customer] = {}

    async def save(self, customer: Customer) -> None:
        self._store[customer.id] = customer

    async def get_by_org_id(self, organization_id: str) -> Customer | None:
        return next(
            (c for c in self._store.values() if c.organization_id == organization_id),
            None,
        )

    async def get_by_id(self, customer_id: str) -> Customer | None:
        return self._store.get(customer_id)


class FakeSubscriptionRepo(SubscriptionRepositoryPort):
    def __init__(self) -> None:
        self._store: dict[str, Subscription] = {}

    async def save(self, subscription: Subscription) -> None:
        self._store[subscription.id] = subscription

    async def get_by_org_id(self, organization_id: str) -> Subscription | None:
        return next(
            (s for s in self._store.values() if s.organization_id == organization_id),
            None,
        )

    async def get_by_id(self, subscription_id: str) -> Subscription | None:
        return self._store.get(subscription_id)

    async def get_by_square_id(self, square_subscription_id: str) -> Subscription | None:
        return next(
            (
                s
                for s in self._store.values()
                if s.square_subscription_id == square_subscription_id
            ),
            None,
        )


class FakeInvoiceRepo(InvoiceRepositoryPort):
    def __init__(self) -> None:
        self._store: list[Invoice] = []

    async def save(self, invoice: Invoice) -> None:
        self._store.append(invoice)

    async def list_by_org(
        self, organization_id: str, limit: int = 50, offset: int = 0
    ) -> list[Invoice]:
        matching = [i for i in self._store if i.organization_id == organization_id]
        return matching[offset : offset + limit]

    async def get_by_square_id(self, square_invoice_id: str) -> Invoice | None:
        return next(
            (i for i in self._store if i.square_invoice_id == square_invoice_id),
            None,
        )


class FakePaymentMethodRepo(PaymentMethodRepositoryPort):
    def __init__(self) -> None:
        self._store: dict[str, PaymentMethod] = {}

    async def save(self, method: PaymentMethod) -> None:
        self._store[method.id] = method

    async def list_by_org(self, organization_id: str) -> list[PaymentMethod]:
        return [m for m in self._store.values() if m.organization_id == organization_id]

    async def delete(self, method_id: str) -> None:
        self._store.pop(method_id, None)


class FakePaymentProvider(PaymentProviderPort):
    def __init__(self) -> None:
        self.created_customers: list[str] = []
        self.created_subscriptions: list[dict] = []
        self.canceled: list[str] = []
        self.plan_changes: list[dict] = []
        self.current_period_end = "2026-05-13T00:00:00+00:00"

    async def create_customer(self, org_id: str, email: str) -> str:
        cid = f"sq-cust-{org_id}"
        self.created_customers.append(cid)
        return cid

    async def create_subscription(
        self, customer_id: str, plan_tier: str, card_nonce: str
    ) -> dict:
        data = {
            "subscription_id": f"sq-sub-{customer_id}",
            "current_period_end": self.current_period_end,
        }
        self.created_subscriptions.append(data)
        return data

    async def cancel_subscription(self, subscription_id: str) -> None:
        self.canceled.append(subscription_id)

    async def change_plan(self, subscription_id: str, new_plan_tier: str) -> dict:
        data = {
            "subscription_id": subscription_id,
            "new_plan": new_plan_tier,
            "current_period_end": self.current_period_end,
        }
        self.plan_changes.append(data)
        return data

    async def store_card(self, customer_id: str, card_nonce: str) -> dict:
        return {"card_id": f"sq-card-{card_nonce}", "card_brand": "VISA", "last_4": "4242"}


class FakeOrgService(OrgServicePort):
    def __init__(self) -> None:
        self.updates: list[dict[str, object]] = []

    async def update_plan(
        self,
        organization_id: str,
        plan_tier: str,
        plan_expires_at: datetime | None = None,
        settings_patch: dict[str, object] | None = None,
    ) -> None:
        self.updates.append(
            {
                "organization_id": organization_id,
                "plan_tier": plan_tier,
                "plan_expires_at": plan_expires_at,
                "settings_patch": settings_patch,
            }
        )


class FakeEventPublisher(EventPublisherPort):
    def __init__(self) -> None:
        self.events: list = []

    async def publish(self, event) -> None:
        self.events.append(event)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture()
def repos():
    return {
        "customer": FakeCustomerRepo(),
        "subscription": FakeSubscriptionRepo(),
        "invoice": FakeInvoiceRepo(),
        "payment_method": FakePaymentMethodRepo(),
    }


@pytest.fixture()
def provider():
    return FakePaymentProvider()


@pytest.fixture()
def org_service():
    return FakeOrgService()


@pytest.fixture()
def publisher():
    return FakeEventPublisher()


@pytest.fixture()
def use_case(repos, provider, org_service, publisher):
    return BillingUseCase(
        customer_repo=repos["customer"],
        subscription_repo=repos["subscription"],
        invoice_repo=repos["invoice"],
        payment_method_repo=repos["payment_method"],
        payment_provider=provider,
        org_service=org_service,
        event_publisher=publisher,
    )


@pytest.fixture()
def http_client(use_case):
    app = FastAPI()
    configure_billing_router(use_case)
    app.include_router(router)
    return TestClient(app)


@pytest.fixture()
def webhook_client(use_case):
    app = FastAPI()
    configure_webhook_router(use_case)
    app.include_router(webhook_router)
    return TestClient(app)


# ============================================================================
# Domain Entity Tests
# ============================================================================


class TestSubscriptionEntity:
    def test_create_sets_active_status(self):
        sub = Subscription.create("org-1", "cust-1", "professional")
        assert sub.status == SubscriptionStatus.ACTIVE
        assert sub.organization_id == "org-1"
        assert sub.plan_tier == "professional"

    def test_cancel_at_period_end_sets_flag(self):
        sub = Subscription.create("org-1", "cust-1", "professional")
        sub.cancel(at_period_end=True)
        assert sub.cancel_at_period_end is True
        assert sub.status == SubscriptionStatus.ACTIVE

    def test_cancel_immediately_sets_canceled(self):
        sub = Subscription.create("org-1", "cust-1", "professional")
        sub.cancel(at_period_end=False)
        assert sub.status == SubscriptionStatus.CANCELED

    def test_mark_past_due(self):
        sub = Subscription.create("org-1", "cust-1", "starter")
        sub.mark_past_due()
        assert sub.status == SubscriptionStatus.PAST_DUE

    def test_activate_clears_cancel_flag(self):
        sub = Subscription.create("org-1", "cust-1", "starter")
        sub.cancel(at_period_end=True)
        sub.activate()
        assert sub.status == SubscriptionStatus.ACTIVE
        assert sub.cancel_at_period_end is False

    def test_to_dict_round_trips(self):
        sub = Subscription.create("org-1", "cust-1", "enterprise")
        d = sub.to_dict()
        assert d["organization_id"] == "org-1"
        assert d["status"] == "active"
        assert d["plan_tier"] == "enterprise"


class TestInvoiceEntity:
    def test_mark_paid_sets_status_and_timestamp(self):
        inv = Invoice(subscription_id="sub-1", amount_cents=1999)
        inv.mark_paid()
        assert inv.status == InvoiceStatus.PAID
        assert inv.paid_at is not None

    def test_mark_failed_sets_status(self):
        inv = Invoice(subscription_id="sub-1", amount_cents=1999)
        inv.mark_failed()
        assert inv.status == InvoiceStatus.FAILED


# ============================================================================
# Use Case Tests
# ============================================================================


class TestCreateSubscription:
    @pytest.mark.asyncio
    async def test_creates_customer_and_subscription(self, use_case, repos, provider, publisher):
        sub = await use_case.create_subscription(
            CreateSubscriptionCommand(
                organization_id="org-1",
                plan_tier="professional",
                payment_nonce="nonce-123",
            )
        )
        assert sub.status == SubscriptionStatus.ACTIVE
        assert sub.plan_tier == "professional"
        assert len(provider.created_customers) == 1
        assert len(publisher.events) == 1

        # Customer was stored
        cust = await repos["customer"].get_by_org_id("org-1")
        assert cust is not None

    @pytest.mark.asyncio
    async def test_reuses_existing_customer(self, use_case, repos, provider):
        # Pre-seed a customer
        existing = Customer(organization_id="org-1", square_customer_id="sq-existing")
        await repos["customer"].save(existing)

        sub = await use_case.create_subscription(
            CreateSubscriptionCommand(
                organization_id="org-1",
                plan_tier="starter",
                payment_nonce="nonce-x",
            )
        )
        assert sub.status == SubscriptionStatus.ACTIVE
        assert len(provider.created_customers) == 0  # no new customer created

    @pytest.mark.asyncio
    async def test_rejects_duplicate_active_subscription(self, use_case, repos):
        # Pre-seed an active subscription
        existing = Subscription.create("org-1", "cust-1", "starter")
        await repos["subscription"].save(existing)

        with pytest.raises(ValueError, match="already has an active subscription"):
            await use_case.create_subscription(
                CreateSubscriptionCommand(
                    organization_id="org-1",
                    plan_tier="professional",
                    payment_nonce="nonce-dup",
                )
            )

    @pytest.mark.asyncio
    async def test_updates_org_plan(self, use_case, org_service):
        await use_case.create_subscription(
            CreateSubscriptionCommand(
                organization_id="org-1",
                plan_tier="enterprise",
                payment_nonce="nonce-e",
            )
        )
        assert any(
            update["organization_id"] == "org-1"
            and update["plan_tier"] == "enterprise"
            and update["settings_patch"] == {
                "pilot_retention_enabled": False,
                "pilot_retention_days": None,
                "pilot_retention_last_purged_at": None,
                "audit_retention_days": None,
                "data_retention_mode": "standard",
            }
            for update in org_service.updates
        )

    @pytest.mark.asyncio
    async def test_starter_subscription_sets_hosted_pilot_metadata(self, use_case, org_service):
        await use_case.create_subscription(
            CreateSubscriptionCommand(
                organization_id="org-1",
                plan_tier="starter",
                payment_nonce="nonce-starter",
            )
        )

        assert any(
            update["organization_id"] == "org-1"
            and update["plan_tier"] == "starter"
            and update["plan_expires_at"] is not None
            and update["settings_patch"] == {
                "pilot_retention_enabled": True,
                "pilot_retention_days": 30,
                "audit_retention_days": 30,
                "data_retention_mode": "hosted_pilot_rolling_purge",
            }
            for update in org_service.updates
        )


class TestChangePlan:
    @pytest.mark.asyncio
    async def test_changes_active_subscription(self, use_case, repos, publisher):
        sub = Subscription.create("org-1", "cust-1", "starter", "sq-sub-1")
        await repos["subscription"].save(sub)

        result = await use_case.change_plan(
            ChangePlanCommand(organization_id="org-1", new_plan_tier="professional")
        )
        assert result.plan_tier == "professional"
        assert len(publisher.events) == 1

    @pytest.mark.asyncio
    async def test_rejects_when_no_subscription(self, use_case):
        with pytest.raises(ValueError, match="No active subscription found"):
            await use_case.change_plan(
                ChangePlanCommand(organization_id="org-none", new_plan_tier="starter")
            )

    @pytest.mark.asyncio
    async def test_rejects_when_not_active(self, use_case, repos):
        sub = Subscription.create("org-1", "cust-1", "starter", "sq-sub-1")
        sub.status = SubscriptionStatus.CANCELED
        await repos["subscription"].save(sub)

        with pytest.raises(ValueError, match="canceled, cannot change plan"):
            await use_case.change_plan(
                ChangePlanCommand(organization_id="org-1", new_plan_tier="professional")
            )

    @pytest.mark.asyncio
    async def test_change_plan_off_hosted_pilot_clears_stale_expiry(self, use_case, repos, provider, org_service):
        provider.current_period_end = None
        sub = Subscription.create("org-1", "cust-1", "starter", "sq-sub-1")
        sub.current_period_end = datetime.fromisoformat("2026-05-13T00:00:00+00:00")
        await repos["subscription"].save(sub)

        result = await use_case.change_plan(
            ChangePlanCommand(organization_id="org-1", new_plan_tier="professional")
        )

        assert result.current_period_end is None
        assert any(
            update["organization_id"] == "org-1"
            and update["plan_tier"] == "professional"
            and update["plan_expires_at"] is None
            and update["settings_patch"] == {
                "pilot_retention_enabled": False,
                "pilot_retention_days": None,
                "pilot_retention_last_purged_at": None,
                "audit_retention_days": None,
                "data_retention_mode": "standard",
            }
            for update in org_service.updates
        )


class TestCancelSubscription:
    @pytest.mark.asyncio
    async def test_cancels_at_period_end(self, use_case, repos, provider, publisher):
        sub = Subscription.create("org-1", "cust-1", "professional", "sq-sub-1")
        await repos["subscription"].save(sub)

        result = await use_case.cancel_subscription(
            CancelSubscriptionCommand(organization_id="org-1", at_period_end=True)
        )
        assert result.cancel_at_period_end is True
        assert len(provider.canceled) == 1
        assert len(publisher.events) == 1

    @pytest.mark.asyncio
    async def test_cancel_at_period_end_preserves_plan_with_expiry(self, use_case, repos, org_service):
        sub = Subscription.create("org-1", "cust-1", "starter", "sq-sub-1")
        await repos["subscription"].save(sub)

        result = await use_case.cancel_subscription(
            CancelSubscriptionCommand(organization_id="org-1", at_period_end=True)
        )

        assert result.current_period_end is not None
        assert any(
            update["organization_id"] == "org-1"
            and update["plan_tier"] == "starter"
            and update["plan_expires_at"] == result.current_period_end
            and update["settings_patch"] == {
                "pilot_retention_enabled": True,
                "pilot_retention_days": 30,
                "audit_retention_days": 30,
                "data_retention_mode": "hosted_pilot_rolling_purge",
            }
            for update in org_service.updates
        )

    @pytest.mark.asyncio
    async def test_rejects_when_no_subscription(self, use_case):
        with pytest.raises(ValueError, match="No active subscription found"):
            await use_case.cancel_subscription(
                CancelSubscriptionCommand(organization_id="org-none")
            )


class TestAddPaymentMethod:
    @pytest.mark.asyncio
    async def test_stores_card(self, use_case, repos):
        cust = Customer(organization_id="org-1", square_customer_id="sq-cust-1")
        await repos["customer"].save(cust)

        method = await use_case.add_payment_method(
            AddPaymentMethodCommand(organization_id="org-1", payment_nonce="nonce-card")
        )
        assert method.card_last4 == "4242"
        assert method.card_brand == "VISA"
        assert method.is_default is True

    @pytest.mark.asyncio
    async def test_rejects_when_no_customer(self, use_case):
        with pytest.raises(ValueError, match="No billing customer found"):
            await use_case.add_payment_method(
                AddPaymentMethodCommand(organization_id="org-none", payment_nonce="nonce")
            )


class TestWebhookHandlers:
    @pytest.mark.asyncio
    async def test_payment_succeeded_records_invoice(self, use_case, repos, publisher):
        sub = Subscription.create("org-1", "cust-1", "professional", "sq-sub-1")
        await repos["subscription"].save(sub)

        await use_case.handle_payment_succeeded("sq-sub-1", 2999, "sq-inv-1")

        invoices = await repos["invoice"].list_by_org("org-1")
        assert len(invoices) == 1
        assert invoices[0].amount_cents == 2999
        assert invoices[0].status == InvoiceStatus.PAID
        assert len(publisher.events) == 1

    @pytest.mark.asyncio
    async def test_payment_succeeded_reactivates_past_due(self, use_case, repos, org_service):
        sub = Subscription.create("org-1", "cust-1", "professional", "sq-sub-1")
        sub.mark_past_due()
        await repos["subscription"].save(sub)

        await use_case.handle_payment_succeeded("sq-sub-1", 2999, "sq-inv-2")

        stored = await repos["subscription"].get_by_org_id("org-1")
        assert stored.status == SubscriptionStatus.ACTIVE
        assert any(
            update["organization_id"] == "org-1"
            and update["plan_tier"] == "professional"
            for update in org_service.updates
        )

    @pytest.mark.asyncio
    async def test_payment_succeeded_unknown_sub_is_noop(self, use_case, repos):
        await use_case.handle_payment_succeeded("sq-unknown", 100, "inv-x")
        # No exception, no invoice saved
        assert len(repos["invoice"]._store) == 0

    @pytest.mark.asyncio
    async def test_payment_failed_marks_past_due(self, use_case, repos, publisher):
        sub = Subscription.create("org-1", "cust-1", "professional", "sq-sub-1")
        await repos["subscription"].save(sub)

        await use_case.handle_payment_failed("sq-sub-1", 2999)

        stored = await repos["subscription"].get_by_org_id("org-1")
        assert stored.status == SubscriptionStatus.PAST_DUE
        assert len(publisher.events) == 1

    @pytest.mark.asyncio
    async def test_subscription_canceled_downgrades_to_free(
        self, use_case, repos, org_service, publisher
    ):
        sub = Subscription.create("org-1", "cust-1", "enterprise", "sq-sub-1")
        await repos["subscription"].save(sub)

        await use_case.handle_subscription_canceled("sq-sub-1")

        stored = await repos["subscription"].get_by_org_id("org-1")
        assert stored.status == SubscriptionStatus.CANCELED
        assert any(
            update["organization_id"] == "org-1"
            and update["plan_tier"] == "free"
            and update["plan_expires_at"] is None
            and update["settings_patch"] == {
                "pilot_retention_enabled": False,
                "pilot_retention_days": None,
                "pilot_retention_last_purged_at": None,
                "audit_retention_days": None,
                "data_retention_mode": "standard",
            }
            for update in org_service.updates
        )
        assert len(publisher.events) == 1


# ============================================================================
# HTTP Adapter Tests
# ============================================================================


class TestHTTPSubscribe:
    def test_subscribe_returns_subscription(self, http_client):
        resp = http_client.post(
            "/v1/billing/subscribe",
            json={
                "organization_id": "org-1",
                "plan_tier": "starter",
                "payment_nonce": "nonce-1",
            },
            headers={"X-User-Id": "user-1"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["plan_tier"] == "starter"
        assert body["status"] == "active"

    def test_subscribe_rejects_invalid_tier(self, http_client):
        resp = http_client.post(
            "/v1/billing/subscribe",
            json={
                "organization_id": "org-1",
                "plan_tier": "free",
                "payment_nonce": "nonce-1",
            },
            headers={"X-User-Id": "user-1"},
        )
        assert resp.status_code == 400
        assert "Invalid plan tier" in resp.json()["detail"]

    def test_subscribe_requires_auth(self, http_client):
        resp = http_client.post(
            "/v1/billing/subscribe",
            json={
                "organization_id": "org-1",
                "plan_tier": "starter",
                "payment_nonce": "nonce-1",
            },
        )
        assert resp.status_code == 401


class TestHTTPChangePlan:
    def test_change_plan_success(self, http_client):
        # First create a subscription
        http_client.post(
            "/v1/billing/subscribe",
            json={
                "organization_id": "org-1",
                "plan_tier": "starter",
                "payment_nonce": "nonce-1",
            },
            headers={"X-User-Id": "user-1"},
        )
        resp = http_client.post(
            "/v1/billing/change-plan",
            json={"organization_id": "org-1", "new_plan_tier": "professional"},
            headers={"X-User-Id": "user-1"},
        )
        assert resp.status_code == 200
        assert resp.json()["plan_tier"] == "professional"

    def test_change_plan_no_subscription(self, http_client):
        resp = http_client.post(
            "/v1/billing/change-plan",
            json={"organization_id": "org-none", "new_plan_tier": "starter"},
            headers={"X-User-Id": "user-1"},
        )
        assert resp.status_code == 400


class TestHTTPCancel:
    def test_cancel_success(self, http_client):
        http_client.post(
            "/v1/billing/subscribe",
            json={
                "organization_id": "org-1",
                "plan_tier": "starter",
                "payment_nonce": "nonce-1",
            },
            headers={"X-User-Id": "user-1"},
        )
        resp = http_client.post(
            "/v1/billing/cancel",
            json={"organization_id": "org-1"},
            headers={"X-User-Id": "user-1"},
        )
        assert resp.status_code == 200


class TestHTTPGetSubscription:
    def test_returns_none_when_no_subscription(self, http_client):
        resp = http_client.get(
            "/v1/billing/subscription",
            params={"organization_id": "org-none"},
            headers={"X-User-Id": "user-1"},
        )
        assert resp.status_code == 200
        assert resp.json() is None

    def test_returns_subscription(self, http_client):
        http_client.post(
            "/v1/billing/subscribe",
            json={
                "organization_id": "org-1",
                "plan_tier": "enterprise",
                "payment_nonce": "nonce-1",
            },
            headers={"X-User-Id": "user-1"},
        )
        resp = http_client.get(
            "/v1/billing/subscription",
            params={"organization_id": "org-1"},
            headers={"X-User-Id": "user-1"},
        )
        assert resp.status_code == 200
        assert resp.json()["plan_tier"] == "enterprise"


class TestHTTPInvoices:
    def test_empty_invoices_list(self, http_client):
        resp = http_client.get(
            "/v1/billing/invoices",
            params={"organization_id": "org-1"},
            headers={"X-User-Id": "user-1"},
        )
        assert resp.status_code == 200
        assert resp.json() == []


class TestHTTPPaymentMethods:
    def test_add_payment_method_requires_customer(self, http_client):
        resp = http_client.post(
            "/v1/billing/payment-methods",
            json={"organization_id": "org-none", "payment_nonce": "nonce-pm"},
            headers={"X-User-Id": "user-1"},
        )
        assert resp.status_code == 400


# ============================================================================
# Webhook Adapter Tests
# ============================================================================

WEBHOOK_KEY = "test-webhook-secret"


def _sign_body(body: bytes, url: str) -> str:
    payload = url.encode("utf-8") + body
    sig = base64.b64encode(
        hmac_mod.new(WEBHOOK_KEY.encode("utf-8"), payload, hashlib.sha256).digest()
    ).decode("utf-8")
    return sig


class TestSquareWebhook:
    @patch.dict("os.environ", {"SQUARE_WEBHOOK_SIGNATURE_KEY": WEBHOOK_KEY})
    def test_valid_payment_event(self, webhook_client):
        event = {
            "type": "invoice.payment_made",
            "data": {
                "object": {
                    "invoice": {
                        "subscription_id": "sq-sub-1",
                        "id": "sq-inv-1",
                        "payment_requests": [
                            {"computed_amount_money": {"amount": 2999}}
                        ],
                    }
                }
            },
        }
        body = json.dumps(event).encode()
        url = "http://testserver/v1/billing/webhooks/square"
        sig = _sign_body(body, url)

        resp = webhook_client.post(
            "/v1/billing/webhooks/square",
            content=body,
            headers={
                "Content-Type": "application/json",
                "x-square-hmacsha256-signature": sig,
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @patch.dict("os.environ", {"SQUARE_WEBHOOK_SIGNATURE_KEY": WEBHOOK_KEY})
    def test_invalid_signature_rejected(self, webhook_client):
        event = {"type": "invoice.payment_made", "data": {}}
        body = json.dumps(event).encode()

        resp = webhook_client.post(
            "/v1/billing/webhooks/square",
            content=body,
            headers={
                "Content-Type": "application/json",
                "x-square-hmacsha256-signature": "bad-signature",
            },
        )
        assert resp.status_code == 403

    @patch.dict("os.environ", {"SQUARE_WEBHOOK_SIGNATURE_KEY": ""})
    def test_missing_key_rejects(self, webhook_client):
        event = {"type": "test.event", "data": {}}
        body = json.dumps(event).encode()

        resp = webhook_client.post(
            "/v1/billing/webhooks/square",
            content=body,
            headers={
                "Content-Type": "application/json",
                "x-square-hmacsha256-signature": "anything",
            },
        )
        assert resp.status_code == 403

    @patch.dict("os.environ", {"SQUARE_WEBHOOK_SIGNATURE_KEY": WEBHOOK_KEY})
    def test_unhandled_event_type_returns_ok(self, webhook_client):
        event = {"type": "unknown.event", "data": {"object": {}}}
        body = json.dumps(event).encode()
        url = "http://testserver/v1/billing/webhooks/square"
        sig = _sign_body(body, url)

        resp = webhook_client.post(
            "/v1/billing/webhooks/square",
            content=body,
            headers={
                "Content-Type": "application/json",
                "x-square-hmacsha256-signature": sig,
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @patch.dict("os.environ", {"SQUARE_WEBHOOK_SIGNATURE_KEY": WEBHOOK_KEY})
    def test_malformed_json_rejected(self, webhook_client):
        body = b"not-json"
        url = "http://testserver/v1/billing/webhooks/square"
        sig = _sign_body(body, url)

        resp = webhook_client.post(
            "/v1/billing/webhooks/square",
            content=body,
            headers={
                "Content-Type": "application/json",
                "x-square-hmacsha256-signature": sig,
            },
        )
        assert resp.status_code == 400
