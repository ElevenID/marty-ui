"""
Square Payment Provider Adapter

Implements PaymentProviderPort using the Square Subscriptions API.
Requires SQUARE_ACCESS_TOKEN and SQUARE_ENVIRONMENT env vars.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any

import httpx

from ...application.ports import PaymentProviderPort

logger = logging.getLogger(__name__)

# Square catalog IDs mapped to plan tiers.
# These must be created in Square Dashboard → Catalog → Subscription Plans.
# Set via environment variables or hardcode after catalog setup.
PLAN_CATALOG_MAP: dict[str, str] = {
    "starter": os.environ.get("SQUARE_PLAN_STARTER_ID", ""),
    "professional": os.environ.get("SQUARE_PLAN_PROFESSIONAL_ID", ""),
    "enterprise": os.environ.get("SQUARE_PLAN_ENTERPRISE_ID", ""),
}

SQUARE_BASE_URL = {
    "sandbox": "https://connect.squareupsandbox.com/v2",
    "production": "https://connect.squareup.com/v2",
}


class SquarePaymentProvider(PaymentProviderPort):
    """Square API adapter for subscriptions and payments."""

    def __init__(self) -> None:
        self._access_token = os.environ.get("SQUARE_ACCESS_TOKEN", "")
        env = os.environ.get("SQUARE_ENVIRONMENT", "sandbox")
        self._base_url = SQUARE_BASE_URL.get(env, SQUARE_BASE_URL["sandbox"])
        self._location_id = os.environ.get("SQUARE_LOCATION_ID", "")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
            "Square-Version": "2025-01-23",
        }

    async def create_customer(self, org_id: str, email: str) -> str:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/customers",
                headers=self._headers(),
                json={
                    "idempotency_key": str(uuid.uuid4()),
                    "reference_id": org_id,
                    "email_address": email or None,
                },
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json()
            customer_id = data["customer"]["id"]
            logger.info(f"Square customer created: {customer_id} for org {org_id}")
            return customer_id

    async def create_subscription(
        self, customer_id: str, plan_tier: str, card_nonce: str
    ) -> dict[str, Any]:
        plan_variation_id = PLAN_CATALOG_MAP.get(plan_tier)
        if not plan_variation_id:
            raise ValueError(f"No Square catalog plan for tier: {plan_tier}")

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/subscriptions",
                headers=self._headers(),
                json={
                    "idempotency_key": str(uuid.uuid4()),
                    "location_id": self._location_id,
                    "plan_variation_id": plan_variation_id,
                    "customer_id": customer_id,
                    "card_id": card_nonce,
                },
                timeout=15.0,
            )
            resp.raise_for_status()
            sub = resp.json()["subscription"]
            logger.info(f"Square subscription created: {sub['id']}")
            return {"subscription_id": sub["id"], "status": sub.get("status")}

    async def cancel_subscription(self, subscription_id: str) -> None:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/subscriptions/{subscription_id}/cancel",
                headers=self._headers(),
                timeout=15.0,
            )
            resp.raise_for_status()
            logger.info(f"Square subscription canceled: {subscription_id}")

    async def change_plan(
        self, subscription_id: str, new_plan_tier: str
    ) -> dict[str, Any]:
        plan_variation_id = PLAN_CATALOG_MAP.get(new_plan_tier)
        if not plan_variation_id:
            raise ValueError(f"No Square catalog plan for tier: {new_plan_tier}")

        async with httpx.AsyncClient() as client:
            # Square: swap plan by updating subscription
            resp = await client.put(
                f"{self._base_url}/subscriptions/{subscription_id}",
                headers=self._headers(),
                json={
                    "subscription": {
                        "plan_variation_id": plan_variation_id,
                    }
                },
                timeout=15.0,
            )
            resp.raise_for_status()
            sub = resp.json()["subscription"]
            logger.info(
                f"Square subscription plan changed: {subscription_id} → {new_plan_tier}"
            )
            return {"subscription_id": sub["id"], "status": sub.get("status")}

    async def store_card(
        self, customer_id: str, card_nonce: str
    ) -> dict[str, Any]:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/cards",
                headers=self._headers(),
                json={
                    "idempotency_key": str(uuid.uuid4()),
                    "source_id": card_nonce,
                    "card": {
                        "customer_id": customer_id,
                    },
                },
                timeout=15.0,
            )
            resp.raise_for_status()
            card = resp.json()["card"]
            return {
                "card_id": card["id"],
                "card_brand": card.get("card_brand", ""),
                "last_4": card.get("last_4", ""),
            }
