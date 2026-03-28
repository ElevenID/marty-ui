"""
Usage tracking for plan enforcement and billing analytics.

Uses Redis sorted sets with monthly keys for metered usage counters.
Tracks: verifications, issued_credentials, active_flows, api_calls.

Keys:
    usage:{org_id}:{YYYY-MM}:{metric}  — monthly counter (Integer)
    usage:{org_id}:active_flows         — current gauge (Integer, not monthly)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import redis.asyncio as aioredis

logger = logging.getLogger(__name__)


def _month_key() -> str:
    """Current month in YYYY-MM format."""
    return datetime.now(timezone.utc).strftime("%Y-%m")


class UsageTracker:
    """Redis-backed usage counter for organizations."""

    def __init__(self, redis_client: aioredis.Redis) -> None:
        self._redis = redis_client

    # ── Increment ────────────────────────────────────────────────────

    async def increment(self, org_id: str, metric: str, amount: int = 1) -> int:
        """Increment a monthly counter. Returns new value."""
        key = f"usage:{org_id}:{_month_key()}:{metric}"
        val = await self._redis.incrby(key, amount)
        # Auto-expire after 90 days (keep 3 months of history)
        await self._redis.expire(key, 90 * 86400)
        return val

    async def set_gauge(self, org_id: str, metric: str, value: int) -> None:
        """Set a gauge metric (e.g. active_flows — not monthly, just current)."""
        key = f"usage:{org_id}:{metric}"
        await self._redis.set(key, value)

    async def increment_gauge(self, org_id: str, metric: str, amount: int = 1) -> int:
        """Increment a gauge and return new value."""
        key = f"usage:{org_id}:{metric}"
        return await self._redis.incrby(key, amount)

    async def decrement_gauge(self, org_id: str, metric: str, amount: int = 1) -> int:
        """Decrement a gauge (floor at 0) and return new value."""
        key = f"usage:{org_id}:{metric}"
        val = await self._redis.decrby(key, amount)
        if val < 0:
            await self._redis.set(key, 0)
            return 0
        return val

    # ── Read ─────────────────────────────────────────────────────────

    async def get(self, org_id: str, metric: str, month: str | None = None) -> int:
        """Get current value for a metric. Uses current month if not specified."""
        if metric == "active_flows":
            key = f"usage:{org_id}:active_flows"
        else:
            key = f"usage:{org_id}:{month or _month_key()}:{metric}"
        val = await self._redis.get(key)
        return int(val) if val else 0

    async def get_all(self, org_id: str, month: str | None = None) -> dict[str, int]:
        """Get all usage metrics for an org in a given month."""
        m = month or _month_key()
        metrics = ["verifications", "issued_credentials", "api_calls"]
        result = {}
        for metric in metrics:
            result[metric] = await self.get(org_id, metric, m)
        result["active_flows"] = await self.get(org_id, "active_flows")
        return result

    async def get_history(self, org_id: str, metric: str, months: int = 6) -> dict[str, int]:
        """Get usage for the last N months."""
        now = datetime.now(timezone.utc)
        history = {}
        for i in range(months):
            month_offset = now.month - i
            year = now.year
            while month_offset <= 0:
                month_offset += 12
                year -= 1
            m = f"{year}-{month_offset:02d}"
            history[m] = await self.get(org_id, metric, m)
        return history
