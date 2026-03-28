"""
Organization Service Client Adapter

Calls the org service internal API to update plan tier.
"""

from __future__ import annotations

import logging
import os

import httpx

from ...application.ports import OrgServicePort

logger = logging.getLogger(__name__)


class OrgServiceClient(OrgServicePort):
    """HTTP client for the organization service internal API."""

    def __init__(self) -> None:
        self._base_url = os.environ.get(
            "ORGANIZATION_SERVICE_URL", "http://localhost:8002"
        )

    async def update_plan(self, organization_id: str, plan_tier: str) -> None:
        url = f"{self._base_url}/internal/v1/organizations/{organization_id}/plan"
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                url,
                json={"plan_tier": plan_tier},
                timeout=10.0,
            )
            resp.raise_for_status()
            logger.info(
                f"Org plan updated via internal API: org={organization_id} plan={plan_tier}"
            )
