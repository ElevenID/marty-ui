"""Dependency-light value types shared by flow persistence and delivery.

This module deliberately has no HTTP, metrics, or application-service imports so
database migrations and repository contract tests exercise the production
persistence adapter without needing the full service runtime.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class CallbackOutboxEvent:
    event_id: str
    flow_instance_id: str
    organization_id: str
    destination_url: str
    audience: str
    event_type: str
    payload: dict[str, Any]
    created_at: datetime
    next_attempt_at: datetime
    expires_at: datetime
    status: str = "pending"
    attempt_count: int = 0
    lease_token: str | None = None
    lease_expires_at: datetime | None = None
    delivered_at: datetime | None = None
    last_error_code: str | None = None


def new_lease_token() -> str:
    """Create an opaque token used to fence concurrent delivery workers."""

    return str(uuid.uuid4())
