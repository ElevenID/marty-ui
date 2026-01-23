"""In-memory notification store for API access."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4


_notifications: list[dict[str, Any]] = []


def record_notification(
    user_id: str,
    event_type: str,
    title: str,
    body: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Record a notification for a user."""
    notification = {
        "id": str(uuid4()),
        "user_id": user_id,
        "event_type": event_type,
        "title": title,
        "body": body,
        "data": data or {},
        "created_at": datetime.utcnow().isoformat(),
    }
    _notifications.append(notification)
    return notification


def list_notifications(user_id: str) -> list[dict[str, Any]]:
    """List notifications for a user."""
    return [n for n in _notifications if n.get("user_id") == user_id]


def clear_notifications(user_id: str | None = None) -> int:
    """Clear notifications for a user (or all if user_id is None)."""
    global _notifications
    if user_id is None:
        count = len(_notifications)
        _notifications = []
        return count
    remaining = [n for n in _notifications if n.get("user_id") != user_id]
    count = len(_notifications) - len(remaining)
    _notifications = remaining
    return count
