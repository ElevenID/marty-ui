"""
Square Webhook Receiver

Verifies HMAC-SHA256 signature and dispatches to billing use cases.
No auth middleware — webhook routes use signature verification instead.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os

from fastapi import APIRouter, HTTPException, Request

from ...application.use_cases import BillingUseCase

logger = logging.getLogger(__name__)

webhook_router = APIRouter(prefix="/v1/billing/webhooks", tags=["billing-webhooks"])

_billing_use_case: BillingUseCase | None = None


def configure_webhook_router(use_case: BillingUseCase) -> None:
    global _billing_use_case
    _billing_use_case = use_case


def _verify_square_signature(body: bytes, signature: str, url: str) -> bool:
    """Verify Square webhook HMAC-SHA256 signature."""
    webhook_key = os.environ.get("SQUARE_WEBHOOK_SIGNATURE_KEY", "")
    if not webhook_key:
        logger.error("SQUARE_WEBHOOK_SIGNATURE_KEY not set — rejecting webhook")
        return False

    # Square signature = Base64(HMAC-SHA256(webhook_key, url + body))
    import base64

    payload = url.encode("utf-8") + body
    expected = base64.b64encode(
        hmac.new(webhook_key.encode("utf-8"), payload, hashlib.sha256).digest()
    ).decode("utf-8")

    return hmac.compare_digest(expected, signature)


@webhook_router.post("/square")
async def square_webhook(request: Request) -> dict:
    """Receive and verify Square webhook events."""
    if _billing_use_case is None:
        raise HTTPException(status_code=500, detail="Billing not configured")

    body = await request.body()
    signature = request.headers.get("x-square-hmacsha256-signature", "")
    webhook_url = str(request.url)

    if not _verify_square_signature(body, signature, webhook_url):
        logger.warning("Square webhook signature verification failed")
        raise HTTPException(status_code=403, detail="Invalid signature")

    import json

    try:
        event = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    event_type = event.get("type", "")
    data = event.get("data", {}).get("object", {})

    logger.info(f"Square webhook: {event_type}")

    try:
        if event_type == "invoice.payment_made":
            subscription_id = data.get("invoice", {}).get("subscription_id", "")
            amount = data.get("invoice", {}).get("payment_requests", [{}])[0].get(
                "computed_amount_money", {}
            ).get("amount", 0)
            invoice_id = data.get("invoice", {}).get("id", "")
            await _billing_use_case.handle_payment_succeeded(
                square_subscription_id=subscription_id,
                amount_cents=amount,
                square_invoice_id=invoice_id,
            )

        elif event_type == "invoice.payment_failed":
            subscription_id = data.get("invoice", {}).get("subscription_id", "")
            amount = data.get("invoice", {}).get("payment_requests", [{}])[0].get(
                "computed_amount_money", {}
            ).get("amount", 0)
            await _billing_use_case.handle_payment_failed(
                square_subscription_id=subscription_id,
                amount_cents=amount,
            )

        elif event_type == "subscription.updated":
            sub_data = data.get("subscription", {})
            if sub_data.get("status") == "CANCELED":
                await _billing_use_case.handle_subscription_canceled(
                    square_subscription_id=sub_data.get("id", ""),
                )

        else:
            logger.debug(f"Unhandled Square webhook type: {event_type}")

    except Exception:
        logger.exception(f"Error handling Square webhook: {event_type}")
        # Return 200 to prevent Square from retrying — we logged the error
        return {"status": "error_logged"}

    return {"status": "ok"}
