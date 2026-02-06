"""
Notification Service

Handles email and push notifications.

Ports:
- HTTP API on port 8007
- RabbitMQ event consumer
"""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "notification-service"
SERVICE_PORT = int(os.environ.get("NOTIFICATION_SERVICE_PORT", "8007"))


# =============================================================================
# Domain Layer
# =============================================================================

class NotificationType(str, Enum):
    """Notification type."""
    EMAIL = "email"
    PUSH = "push"
    SMS = "sms"
    WEBHOOK = "webhook"


class NotificationStatus(str, Enum):
    """Notification delivery status."""
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"


class NotificationPriority(str, Enum):
    """Notification priority."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


@dataclass
class Notification:
    """
    Notification entity.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str | None = None
    
    # Target
    recipient_id: str | None = None
    recipient_email: str | None = None
    recipient_phone: str | None = None
    
    # Content
    notification_type: NotificationType = NotificationType.EMAIL
    template_id: str | None = None
    subject: str = ""
    body: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    
    # Status
    status: NotificationStatus = NotificationStatus.PENDING
    priority: NotificationPriority = NotificationPriority.NORMAL
    
    # Delivery info
    attempts: int = 0
    last_attempt_at: datetime | None = None
    delivered_at: datetime | None = None
    error_message: str | None = None
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scheduled_at: datetime | None = None
    
    def mark_sent(self) -> None:
        self.status = NotificationStatus.SENT
        self.attempts += 1
        self.last_attempt_at = datetime.now(timezone.utc)
    
    def mark_delivered(self) -> None:
        self.status = NotificationStatus.DELIVERED
        self.delivered_at = datetime.now(timezone.utc)
    
    def mark_failed(self, error: str) -> None:
        self.status = NotificationStatus.FAILED
        self.error_message = error
        self.attempts += 1
        self.last_attempt_at = datetime.now(timezone.utc)


@dataclass
class NotificationTemplate:
    """
    Notification template.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str | None = None  # None = system template
    
    name: str = ""
    notification_type: NotificationType = NotificationType.EMAIL
    subject_template: str = ""
    body_template: str = ""
    
    # Metadata
    active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# Application Layer
# =============================================================================

class InMemoryNotificationRepository:
    """In-memory repository for development."""
    
    def __init__(self):
        self._notifications: dict[str, Notification] = {}
        self._templates: dict[str, NotificationTemplate] = {}
        
        # Add default templates
        self._add_default_templates()
    
    def _add_default_templates(self) -> None:
        templates = [
            NotificationTemplate(
                id="invitation",
                name="Member Invitation",
                subject_template="You've been invited to join {{organization_name}}",
                body_template="Hello,\n\nYou've been invited to join {{organization_name}} on Marty.\n\nClick here to accept: {{invitation_link}}",
            ),
            NotificationTemplate(
                id="approval",
                name="Application Approved",
                subject_template="Your application has been approved",
                body_template="Hello {{given_name}},\n\nYour application for {{credential_type}} has been approved.",
            ),
            NotificationTemplate(
                id="credential-ready",
                name="Credential Ready",
                subject_template="Your credential is ready to claim",
                body_template="Hello {{given_name}},\n\nYour {{credential_type}} credential is ready.\n\nClaim it here: {{claim_link}}",
            ),
        ]
        for t in templates:
            self._templates[t.id] = t
    
    async def save_notification(self, notification: Notification) -> None:
        self._notifications[notification.id] = notification
    
    async def get_notification(self, notif_id: str) -> Notification | None:
        return self._notifications.get(notif_id)
    
    async def list_notifications(
        self,
        org_id: str | None = None,
        recipient_id: str | None = None,
        status: NotificationStatus | None = None,
    ) -> list[Notification]:
        notifications = list(self._notifications.values())
        if org_id:
            notifications = [n for n in notifications if n.organization_id == org_id]
        if recipient_id:
            notifications = [n for n in notifications if n.recipient_id == recipient_id]
        if status:
            notifications = [n for n in notifications if n.status == status]
        return notifications
    
    async def get_template(self, template_id: str) -> NotificationTemplate | None:
        return self._templates.get(template_id)
    
    async def list_templates(self, org_id: str | None = None) -> list[NotificationTemplate]:
        templates = list(self._templates.values())
        if org_id:
            templates = [t for t in templates if t.organization_id == org_id or t.organization_id is None]
        return templates


# =============================================================================
# HTTP Adapter
# =============================================================================

router = APIRouter(prefix="/v1/notifications", tags=["notifications"])

_repo: InMemoryNotificationRepository | None = None


def get_repo() -> InMemoryNotificationRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


class SendNotificationRequest(BaseModel):
    organization_id: str | None = None
    recipient_id: str | None = None
    recipient_email: EmailStr | None = None
    notification_type: str = "email"
    template_id: str | None = None
    subject: str | None = None
    body: str | None = None
    data: dict[str, Any] = {}
    priority: str = "normal"


class NotificationResponse(BaseModel):
    id: str
    notification_type: str
    status: str
    recipient_email: str | None
    subject: str
    created_at: str
    delivered_at: str | None


class TemplateResponse(BaseModel):
    id: str
    name: str
    notification_type: str
    subject_template: str
    active: bool


@router.post("/send", response_model=NotificationResponse)
async def send_notification(
    request: SendNotificationRequest,
    repo: InMemoryNotificationRepository = Depends(get_repo),
) -> NotificationResponse:
    """Send a notification."""
    # Get template if specified
    subject = request.subject or ""
    body = request.body or ""
    
    if request.template_id:
        template = await repo.get_template(request.template_id)
        if template:
            subject = template.subject_template
            body = template.body_template
            # Simple template substitution
            for key, value in request.data.items():
                subject = subject.replace(f"{{{{{key}}}}}", str(value))
                body = body.replace(f"{{{{{key}}}}}", str(value))
    
    notification = Notification(
        organization_id=request.organization_id,
        recipient_id=request.recipient_id,
        recipient_email=request.recipient_email,
        notification_type=NotificationType(request.notification_type),
        template_id=request.template_id,
        subject=subject,
        body=body,
        data=request.data,
        priority=NotificationPriority(request.priority),
    )
    
    # Simulate sending (in real implementation, would queue for delivery)
    notification.mark_sent()
    notification.mark_delivered()  # Simulate success
    
    await repo.save_notification(notification)
    
    logger.info(f"Sent notification {notification.id} to {request.recipient_email}")
    return _to_response(notification)


@router.get("", response_model=list[NotificationResponse])
async def list_notifications(
    organization_id: str | None = None,
    recipient_id: str | None = None,
    status: str | None = None,
    repo: InMemoryNotificationRepository = Depends(get_repo),
) -> list[NotificationResponse]:
    """List notifications."""
    status_filter = NotificationStatus(status) if status else None
    notifications = await repo.list_notifications(organization_id, recipient_id, status_filter)
    return [_to_response(n) for n in notifications]


@router.get("/{notification_id}", response_model=NotificationResponse)
async def get_notification(
    notification_id: str,
    repo: InMemoryNotificationRepository = Depends(get_repo),
) -> NotificationResponse:
    """Get a notification."""
    notification = await repo.get_notification(notification_id)
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    return _to_response(notification)


@router.get("/templates", response_model=list[TemplateResponse])
async def list_templates(
    organization_id: str | None = None,
    repo: InMemoryNotificationRepository = Depends(get_repo),
) -> list[TemplateResponse]:
    """List notification templates."""
    templates = await repo.list_templates(organization_id)
    return [
        TemplateResponse(
            id=t.id,
            name=t.name,
            notification_type=t.notification_type.value,
            subject_template=t.subject_template,
            active=t.active,
        )
        for t in templates
    ]


def _to_response(notification: Notification) -> NotificationResponse:
    return NotificationResponse(
        id=notification.id,
        notification_type=notification.notification_type.value,
        status=notification.status.value,
        recipient_email=notification.recipient_email,
        subject=notification.subject,
        created_at=notification.created_at.isoformat(),
        delivered_at=notification.delivered_at.isoformat() if notification.delivered_at else None,
    )


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo
    logger.info(f"Starting {SERVICE_NAME}...")
    _repo = InMemoryNotificationRepository()
    yield
    logger.info(f"Shutting down {SERVICE_NAME}...")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Notification Service",
        description="Email and push notification service",
        version="1.0.0",
        lifespan=lifespan,
    )
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    app.include_router(router)
    
    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": SERVICE_NAME}
    
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("notification.main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
