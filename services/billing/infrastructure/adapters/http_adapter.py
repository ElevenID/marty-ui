"""
Billing Service HTTP Adapter (FastAPI)
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel

from ...application.ports import (
    AddPaymentMethodCommand,
    CancelSubscriptionCommand,
    ChangePlanCommand,
    CreateSubscriptionCommand,
)
from ...application.use_cases import BillingUseCase

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/billing", tags=["billing"])

_billing_use_case: BillingUseCase | None = None


def configure_billing_router(use_case: BillingUseCase) -> None:
    global _billing_use_case
    _billing_use_case = use_case


def get_use_case() -> BillingUseCase:
    if _billing_use_case is None:
        raise RuntimeError("Billing router not configured")
    return _billing_use_case


async def get_current_user_id(
    x_user_id: Annotated[str | None, Header(alias="X-User-Id")] = None
) -> str:
    if not x_user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    return x_user_id


async def get_org_id(
    x_org_id: Annotated[str | None, Header(alias="X-Organization-Id")] = None,
    organization_id: str | None = None,
) -> str:
    """Resolve org ID from header or query param."""
    org_id = x_org_id or organization_id
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization ID required")
    return org_id


# =============================================================================
# Request/Response Models
# =============================================================================

class SubscribeRequest(BaseModel):
    organization_id: str
    plan_tier: str  # starter | professional | enterprise
    payment_nonce: str


class ChangePlanRequest(BaseModel):
    organization_id: str
    new_plan_tier: str


class CancelRequest(BaseModel):
    organization_id: str
    at_period_end: bool = True


class AddPaymentMethodRequest(BaseModel):
    organization_id: str
    payment_nonce: str


class SubscriptionResponse(BaseModel):
    id: str
    organization_id: str
    plan_tier: str
    status: str
    current_period_start: str | None = None
    current_period_end: str | None = None
    cancel_at_period_end: bool = False
    created_at: str


class InvoiceResponse(BaseModel):
    id: str
    amount_cents: int
    currency: str
    status: str
    paid_at: str | None = None
    created_at: str


class PaymentMethodResponse(BaseModel):
    id: str
    card_brand: str
    card_last4: str
    is_default: bool
    created_at: str


# =============================================================================
# Endpoints
# =============================================================================

@router.post("/subscribe", response_model=SubscriptionResponse)
async def subscribe(
    body: SubscribeRequest,
    user_id: str = Depends(get_current_user_id),
    use_case: BillingUseCase = Depends(get_use_case),
) -> SubscriptionResponse:
    """Create a new subscription."""
    valid_tiers = {"starter", "professional", "enterprise"}
    if body.plan_tier not in valid_tiers:
        raise HTTPException(status_code=400, detail=f"Invalid plan tier: {body.plan_tier}")
    try:
        sub = await use_case.create_subscription(
            CreateSubscriptionCommand(
                organization_id=body.organization_id,
                plan_tier=body.plan_tier,
                payment_nonce=body.payment_nonce,
            )
        )
        return _sub_to_response(sub)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/change-plan", response_model=SubscriptionResponse)
async def change_plan(
    body: ChangePlanRequest,
    user_id: str = Depends(get_current_user_id),
    use_case: BillingUseCase = Depends(get_use_case),
) -> SubscriptionResponse:
    """Upgrade or downgrade subscription plan."""
    try:
        sub = await use_case.change_plan(
            ChangePlanCommand(
                organization_id=body.organization_id,
                new_plan_tier=body.new_plan_tier,
            )
        )
        return _sub_to_response(sub)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/cancel", response_model=SubscriptionResponse)
async def cancel(
    body: CancelRequest,
    user_id: str = Depends(get_current_user_id),
    use_case: BillingUseCase = Depends(get_use_case),
) -> SubscriptionResponse:
    """Cancel subscription."""
    try:
        sub = await use_case.cancel_subscription(
            CancelSubscriptionCommand(
                organization_id=body.organization_id,
                at_period_end=body.at_period_end,
            )
        )
        return _sub_to_response(sub)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/subscription", response_model=SubscriptionResponse | None)
async def get_subscription(
    organization_id: str = Query(...),
    user_id: str = Depends(get_current_user_id),
    use_case: BillingUseCase = Depends(get_use_case),
) -> SubscriptionResponse | None:
    """Get current subscription status."""
    sub = await use_case.get_subscription(organization_id)
    if not sub:
        return None
    return _sub_to_response(sub)


@router.get("/invoices", response_model=list[InvoiceResponse])
async def get_invoices(
    organization_id: str = Query(...),
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    user_id: str = Depends(get_current_user_id),
    use_case: BillingUseCase = Depends(get_use_case),
) -> list[InvoiceResponse]:
    """Get invoice history."""
    invoices = await use_case.get_invoices(organization_id, limit=limit, offset=offset)
    return [_invoice_to_response(inv) for inv in invoices]


@router.post("/payment-methods", response_model=PaymentMethodResponse)
async def add_payment_method(
    body: AddPaymentMethodRequest,
    user_id: str = Depends(get_current_user_id),
    use_case: BillingUseCase = Depends(get_use_case),
) -> PaymentMethodResponse:
    """Add a payment method."""
    try:
        method = await use_case.add_payment_method(
            AddPaymentMethodCommand(
                organization_id=body.organization_id,
                payment_nonce=body.payment_nonce,
            )
        )
        return _method_to_response(method)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/payment-methods", response_model=list[PaymentMethodResponse])
async def get_payment_methods(
    organization_id: str = Query(...),
    user_id: str = Depends(get_current_user_id),
    use_case: BillingUseCase = Depends(get_use_case),
) -> list[PaymentMethodResponse]:
    """List payment methods."""
    methods = await use_case.get_payment_methods(organization_id)
    return [_method_to_response(m) for m in methods]


# =============================================================================
# Response Helpers
# =============================================================================

def _sub_to_response(sub) -> SubscriptionResponse:
    return SubscriptionResponse(
        id=sub.id,
        organization_id=sub.organization_id,
        plan_tier=sub.plan_tier,
        status=sub.status.value,
        current_period_start=sub.current_period_start.isoformat() if sub.current_period_start else None,
        current_period_end=sub.current_period_end.isoformat() if sub.current_period_end else None,
        cancel_at_period_end=sub.cancel_at_period_end,
        created_at=sub.created_at.isoformat(),
    )


def _invoice_to_response(inv) -> InvoiceResponse:
    return InvoiceResponse(
        id=inv.id,
        amount_cents=inv.amount_cents,
        currency=inv.currency,
        status=inv.status.value,
        paid_at=inv.paid_at.isoformat() if inv.paid_at else None,
        created_at=inv.created_at.isoformat(),
    )


def _method_to_response(m) -> PaymentMethodResponse:
    return PaymentMethodResponse(
        id=m.id,
        card_brand=m.card_brand,
        card_last4=m.card_last4,
        is_default=m.is_default,
        created_at=m.created_at.isoformat(),
    )
