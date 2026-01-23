"""Notification API endpoints for retrieving stored notifications."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel

from .store import clear_notifications, list_notifications

router = APIRouter(prefix="/api/notifications", tags=["Notifications"])


class NotificationRecord(BaseModel):
    """Notification record response."""

    id: str
    user_id: str
    event_type: str
    title: str
    body: str
    data: dict[str, Any]
    created_at: str


class NotificationListResponse(BaseModel):
    """List notifications response."""

    notifications: list[NotificationRecord]
    count: int


class ClearNotificationsResponse(BaseModel):
    """Clear notifications response."""

    cleared: int
    message: str


def _resolve_user_id(user_id: str | None, x_user_id: str | None) -> str:
    resolved = user_id or x_user_id
    if not resolved:
        raise HTTPException(status_code=400, detail="User ID is required")
    return resolved


@router.get("", response_model=NotificationListResponse)
async def get_notifications(
    user_id: str | None = Query(None),
    x_user_id: str | None = Header(default=None, alias="X-User-ID"),
):
    """List notifications for a user."""
    resolved_user_id = _resolve_user_id(user_id, x_user_id)
    notifications = list_notifications(resolved_user_id)
    return NotificationListResponse(notifications=notifications, count=len(notifications))


@router.delete("", response_model=ClearNotificationsResponse)
async def delete_notifications(
    user_id: str | None = Query(None),
    x_user_id: str | None = Header(default=None, alias="X-User-ID"),
):
    """Clear notifications for a user."""
    resolved_user_id = _resolve_user_id(user_id, x_user_id)
    cleared = clear_notifications(resolved_user_id)
    return ClearNotificationsResponse(
        cleared=cleared,
        message=f"Cleared {cleared} notifications",
    )
