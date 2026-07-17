"""
Notification Service

Handles user notifications plus protocol-facing subscription and webhook
delivery resources.

Ports:
- HTTP API on port 8007
- gRPC API on port 9007
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, AsyncGenerator
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from marty_common.dto import DeleteResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware
from marty_common.service_setup import create_service_app
from notification.infrastructure.adapters.postgres_adapter import PostgresNotificationRepository
from notification.infrastructure.models import mapper_registry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "notification-service"
SERVICE_PORT = int(os.environ.get("NOTIFICATION_SERVICE_PORT", "8007"))
WEBHOOK_CIRCUIT_BREAKER_THRESHOLD = int(os.environ.get("WEBHOOK_CIRCUIT_BREAKER_THRESHOLD", "5"))


# =============================================================================
# Domain Layer
# =============================================================================


class NotificationType(str, Enum):
    EMAIL = "email"
    PUSH = "push"
    SMS = "sms"
    WEBHOOK = "webhook"


class NotificationStatus(str, Enum):
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"


class NotificationPriority(str, Enum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ChannelType(str, Enum):
    FCM = "FCM"
    SSE = "SSE"
    WEBHOOK = "WEBHOOK"
    EMAIL = "EMAIL"
    SMS = "SMS"


class DeliveryChannel(str, Enum):
    WEBHOOK = "WEBHOOK"


STANDARD_EVENT_CHANNELS: dict[str, list[ChannelType]] = {
    "credential.offered": [ChannelType.FCM, ChannelType.SSE],
    "credential.issued": [ChannelType.FCM, ChannelType.SSE],
    "credential.revoked": [ChannelType.FCM, ChannelType.SSE, ChannelType.EMAIL],
    "verification.requested": [ChannelType.FCM, ChannelType.SSE],
    "application.received": [ChannelType.EMAIL],
    "application.approved": [ChannelType.FCM, ChannelType.SSE, ChannelType.EMAIL],
    "application.rejected": [ChannelType.FCM, ChannelType.SSE, ChannelType.EMAIL],
    "applicant.submitted": [ChannelType.EMAIL],
    "applicant.approved": [ChannelType.FCM, ChannelType.SSE, ChannelType.EMAIL],
    "applicant.rejected": [ChannelType.FCM, ChannelType.SSE, ChannelType.EMAIL],
    "applicant.status_changed": [ChannelType.FCM, ChannelType.SSE],
    "device.key_expiring": [ChannelType.FCM, ChannelType.SSE],
}


@dataclass
class NotificationTarget:
    organization_id: str | None = None
    user_id: str | None = None
    device_tokens: list[str] = field(default_factory=list)
    webhook_endpoints: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    channels: list[ChannelType] = field(default_factory=list)


@dataclass
class DeliveryResult:
    notification_id: str
    channel: ChannelType
    success: bool
    attempted_at: datetime
    delivered_at: datetime | None = None
    error_code: str | None = None
    should_retry: bool | None = None
    retry_after: int | None = None


@dataclass
class Notification:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str | None = None
    recipient_id: str | None = None
    recipient_email: str | None = None
    recipient_phone: str | None = None
    notification_type: NotificationType = NotificationType.EMAIL
    template_id: str | None = None
    subject: str = ""
    body: str = ""
    severity: str = "info"
    link: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    status: NotificationStatus = NotificationStatus.PENDING
    priority: NotificationPriority = NotificationPriority.NORMAL
    event_type: str = "custom"
    ttl_seconds: int = 86400
    collapse_key: str | None = None
    correlation_id: str | None = None
    target: NotificationTarget | None = None
    delivery_results: list[DeliveryResult] = field(default_factory=list)
    attempts: int = 0
    last_attempt_at: datetime | None = None
    delivered_at: datetime | None = None
    error_message: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scheduled_at: datetime | None = None
    read_at: datetime | None = None

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

    def mark_read(self) -> None:
        self.read_at = datetime.now(timezone.utc)

    @property
    def is_read(self) -> bool:
        return self.read_at is not None


@dataclass
class NotificationTemplate:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str | None = None
    name: str = ""
    notification_type: NotificationType = NotificationType.EMAIL
    subject_template: str = ""
    body_template: str = ""
    active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class RetryPolicy(BaseModel):
    max_attempts: int = 3
    initial_backoff_seconds: int = 1
    max_backoff_seconds: int = 30


@dataclass
class Subscription:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    name: str = ""
    description: str | None = None
    event_types: list[str] = field(default_factory=list)
    delivery_channel: DeliveryChannel = DeliveryChannel.WEBHOOK
    filter_config: dict[str, Any] = field(default_factory=dict)
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    delivery_target_id: str | None = None
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class WebhookEndpoint:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    name: str = ""
    url: str = ""
    secret: str = field(default_factory=lambda: secrets.token_hex(32))
    description: str | None = None
    event_types: list[str] = field(default_factory=list)
    enabled: bool = True
    failure_count: int = 0
    last_failure_at: datetime | None = None
    last_triggered_at: datetime | None = None
    circuit_breaker_open_until: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class WebhookDelivery:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    webhook_id: str = ""
    subscription_id: str | None = None
    event_id: str = ""
    event_type: str = ""
    success: bool = False
    response_status_code: int | None = None
    response_body: str | None = None
    error_message: str | None = None
    retry_count: int = 0
    response_time_ms: int | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# Repository
# =============================================================================


class InMemoryNotificationRepository:
    def __init__(self):
        self._notifications: dict[str, Notification] = {}
        self._templates: dict[str, NotificationTemplate] = {}
        self._subscriptions: dict[str, Subscription] = {}
        self._webhooks: dict[str, WebhookEndpoint] = {}
        self._webhook_deliveries: dict[str, WebhookDelivery] = {}
        self._add_default_templates()

    def _add_default_templates(self) -> None:
        for template in default_templates():
            self._templates[template.id] = template

    async def save_notification(self, notification: Notification) -> None:
        self._notifications[notification.id] = notification

    async def get_notification(self, notif_id: str) -> Notification | None:
        return self._notifications.get(notif_id)

    async def delete_notification(self, notif_id: str) -> bool:
        if notif_id in self._notifications:
            del self._notifications[notif_id]
            return True
        return False

    async def list_notifications(self, org_id: str | None = None, recipient_id: str | None = None, status: NotificationStatus | None = None) -> list[Notification]:
        notifications = list(self._notifications.values())
        if org_id:
            notifications = [n for n in notifications if n.organization_id == org_id]
        if recipient_id:
            notifications = [n for n in notifications if n.recipient_id == recipient_id]
        if status:
            notifications = [n for n in notifications if n.status == status]
        return sorted(notifications, key=lambda n: n.created_at, reverse=True)

    async def save_template(self, template: NotificationTemplate) -> None:
        self._templates[template.id] = template

    async def get_template(self, template_id: str) -> NotificationTemplate | None:
        return self._templates.get(template_id)

    async def list_templates(self, org_id: str | None = None) -> list[NotificationTemplate]:
        templates = list(self._templates.values())
        if org_id:
            templates = [t for t in templates if t.organization_id == org_id or t.organization_id is None]
        return sorted(templates, key=lambda t: t.name)

    async def save_subscription(self, subscription: Subscription) -> None:
        self._subscriptions[subscription.id] = subscription

    async def get_subscription(self, subscription_id: str) -> Subscription | None:
        return self._subscriptions.get(subscription_id)

    async def list_subscriptions(self, organization_id: str | None = None) -> list[Subscription]:
        subscriptions = list(self._subscriptions.values())
        if organization_id:
            subscriptions = [s for s in subscriptions if s.organization_id == organization_id]
        return sorted(subscriptions, key=lambda s: s.created_at, reverse=True)

    async def delete_subscription(self, subscription_id: str) -> bool:
        if subscription_id in self._subscriptions:
            del self._subscriptions[subscription_id]
            return True
        return False

    async def save_webhook(self, webhook: WebhookEndpoint) -> None:
        self._webhooks[webhook.id] = webhook

    async def get_webhook(self, webhook_id: str) -> WebhookEndpoint | None:
        return self._webhooks.get(webhook_id)

    async def list_webhooks(self, organization_id: str | None = None) -> list[WebhookEndpoint]:
        webhooks = list(self._webhooks.values())
        if organization_id:
            webhooks = [w for w in webhooks if w.organization_id == organization_id]
        return sorted(webhooks, key=lambda w: w.created_at, reverse=True)

    async def delete_webhook(self, webhook_id: str) -> bool:
        if webhook_id in self._webhooks:
            del self._webhooks[webhook_id]
            return True
        return False

    async def save_webhook_delivery(self, delivery: WebhookDelivery) -> None:
        self._webhook_deliveries[delivery.id] = delivery

    async def list_webhook_deliveries(self, webhook_id: str) -> list[WebhookDelivery]:
        deliveries = [d for d in self._webhook_deliveries.values() if d.webhook_id == webhook_id]
        return sorted(deliveries, key=lambda d: d.created_at, reverse=True)


# =============================================================================
# API Models
# =============================================================================


router = APIRouter(prefix="/v1/notifications", tags=["notifications"])
subscription_router = APIRouter(prefix="/v1/subscriptions", tags=["subscriptions"])
webhook_router = APIRouter(prefix="/v1/webhooks", tags=["webhooks"])
internal_router = APIRouter(prefix="/internal", tags=["internal-notifications"])

_repo: InMemoryNotificationRepository | PostgresNotificationRepository | None = None


def get_repo() -> InMemoryNotificationRepository | PostgresNotificationRepository:
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
    title: str | None = None
    message: str | None = None
    severity: str = "info"
    link: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    priority: str = "normal"
    event_type: str = "custom"
    ttl_seconds: int = 86400
    collapse_key: str | None = None
    correlation_id: str | None = None
    target: "NotificationTargetModel | None" = None


class NotificationTargetModel(BaseModel):
    organization_id: str | None = None
    user_id: str | None = None
    device_tokens: list[str] = Field(default_factory=list)
    webhook_endpoints: list[str] = Field(default_factory=list)
    email_addresses: list[EmailStr] = Field(default_factory=list)
    channels: list[str] = Field(default_factory=list)


class DeliveryResultResponse(BaseModel):
    notification_id: str
    channel: str
    success: bool
    attempted_at: str
    delivered_at: str | None = None
    error_code: str | None = None
    should_retry: bool | None = None
    retry_after: int | None = None


class NotificationResponse(BaseModel):
    id: str
    title: str
    body: str
    data: dict[str, Any] = Field(default_factory=dict)
    event_type: str
    priority: str
    target: NotificationTargetModel
    ttl_seconds: int
    collapse_key: str | None = None
    correlation_id: str | None = None
    created_at: str


class NotificationCountResponse(BaseModel):
    count: int


class MarkAllReadResponse(BaseModel):
    marked_read: int


class TemplateResponse(BaseModel):
    id: str
    name: str
    notification_type: str
    subject_template: str
    active: bool


class RetryPolicyModel(BaseModel):
    max_attempts: int = 3
    initial_backoff_seconds: int = 1
    max_backoff_seconds: int = 30


class CreateSubscriptionRequest(BaseModel):
    organization_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    event_types: list[str] = Field(default_factory=list)
    delivery_channel: str = DeliveryChannel.WEBHOOK.value
    filter: dict[str, Any] = Field(default_factory=dict)
    retry_policy: RetryPolicyModel = Field(default_factory=RetryPolicyModel)
    delivery_target_id: str | None = None
    enabled: bool = True


class UpdateSubscriptionRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    event_types: list[str] | None = None
    delivery_channel: str | None = None
    filter: dict[str, Any] | None = None
    retry_policy: RetryPolicyModel | None = None
    delivery_target_id: str | None = None
    enabled: bool | None = None


class SubscriptionResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None = None
    event_types: list[str] = Field(default_factory=list)
    delivery: dict[str, Any] = Field(default_factory=dict)
    filter: dict[str, Any] | None = None
    enabled: bool
    retry_policy: dict[str, Any] | None = None
    created_at: str
    updated_at: str


class CreateWebhookRequest(BaseModel):
    organization_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    url: str = Field(min_length=1, max_length=2048)
    description: str | None = Field(None, max_length=2000)
    event_types: list[str] = Field(default_factory=list)
    secret: str | None = None
    enabled: bool = True


class UpdateWebhookRequest(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    url: str | None = Field(None, min_length=1, max_length=2048)
    description: str | None = Field(None, max_length=2000)
    event_types: list[str] | None = None
    secret: str | None = None
    enabled: bool | None = None


class WebhookResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None = None
    endpoint_url: str
    events: list[str] = Field(default_factory=list)
    signing_secret: str | None = None
    signing_secret_masked: str | None = None
    enabled: bool
    api_version: str | None = None
    filter: dict[str, Any] | None = None
    delivery_config: dict[str, Any] | None = None
    status: str | None = None
    failure_count: int = 0
    last_triggered_at: str | None = None
    last_success_at: str | None = None
    created_at: str
    updated_at: str


class WebhookDeliveryResponse(BaseModel):
    id: str
    webhook_id: str
    subscription_id: str | None = None
    event_id: str
    event_type: str
    success: bool
    response_status_code: int | None = None
    response_body: str | None = None
    error_message: str | None = None
    retry_count: int
    response_time_ms: int | None = None
    created_at: str


class EventIngestRequest(BaseModel):
    event_id: str | None = None
    event_type: str
    aggregate_id: str
    aggregate_type: str
    organization_id: str
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: str | None = None


# =============================================================================
# Helpers
# =============================================================================


def default_templates() -> list[NotificationTemplate]:
    return [
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


def _match_event_patterns(patterns: list[str], event_type: str) -> bool:
    if not patterns:
        return False
    if "*" in patterns or event_type in patterns:
        return True
    event_category = event_type.split(".", 1)[0]
    return any(pattern.endswith(".*") and pattern[:-2] == event_category for pattern in patterns)


def _filter_matches(filter_config: dict[str, Any], payload: dict[str, Any]) -> bool:
    if not filter_config:
        return True
    aggregate_types = filter_config.get("aggregate_types") or []
    if aggregate_types and payload.get("aggregate_type") not in aggregate_types:
        return False
    required_keys = filter_config.get("required_data_keys") or []
    if required_keys and any(key not in payload.get("data", {}) for key in required_keys):
        return False
    return True


def _generate_signature(secret: str, payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _parse_priority(value: str | None) -> NotificationPriority:
    normalized = (value or NotificationPriority.NORMAL.value).strip().upper()
    if normalized == "URGENT":
        normalized = NotificationPriority.CRITICAL.value
    return NotificationPriority(normalized)


def _notification_target_to_model(target: NotificationTarget | None) -> NotificationTargetModel | None:
    if target is None:
        return None
    return NotificationTargetModel(
        organization_id=target.organization_id,
        user_id=target.user_id,
        device_tokens=target.device_tokens,
        webhook_endpoints=target.webhook_endpoints,
        email_addresses=target.email_addresses,
        channels=[channel.value for channel in target.channels],
    )


def _delivery_result_to_response(result: DeliveryResult) -> DeliveryResultResponse:
    return DeliveryResultResponse(
        notification_id=result.notification_id,
        channel=result.channel.value,
        success=result.success,
        attempted_at=result.attempted_at.isoformat(),
        delivered_at=result.delivered_at.isoformat() if result.delivered_at else None,
        error_code=result.error_code,
        should_retry=result.should_retry,
        retry_after=result.retry_after,
    )


def _default_channels_for_event(event_type: str) -> list[ChannelType]:
    return list(STANDARD_EVENT_CHANNELS.get(event_type, [ChannelType.EMAIL]))


def _notification_type_from_channels(channels: list[ChannelType]) -> NotificationType:
    if ChannelType.WEBHOOK in channels:
        return NotificationType.WEBHOOK
    if ChannelType.EMAIL in channels:
        return NotificationType.EMAIL
    if ChannelType.SMS in channels:
        return NotificationType.SMS
    return NotificationType.PUSH


def _legacy_target_from_request(request: SendNotificationRequest) -> NotificationTarget:
    channels: list[ChannelType] = _default_channels_for_event(request.event_type)
    notification_type = request.notification_type.strip().lower()
    if notification_type == NotificationType.WEBHOOK.value:
        channels = [ChannelType.WEBHOOK]
    elif notification_type == NotificationType.SMS.value:
        channels = [ChannelType.SMS]
    elif notification_type == NotificationType.PUSH.value:
        channels = [ChannelType.FCM]
    elif request.recipient_email:
        channels = [ChannelType.EMAIL]

    return NotificationTarget(
        organization_id=request.organization_id,
        user_id=request.recipient_id,
        email_addresses=[str(request.recipient_email)] if request.recipient_email else [],
        channels=channels,
    )


def _build_target(request: SendNotificationRequest) -> NotificationTarget:
    if request.target is None:
        return _legacy_target_from_request(request)
    channels = [ChannelType(channel.strip().upper()) for channel in request.target.channels] or _default_channels_for_event(request.event_type)
    return NotificationTarget(
        organization_id=request.target.organization_id or request.organization_id,
        user_id=request.target.user_id or request.recipient_id,
        device_tokens=request.target.device_tokens,
        webhook_endpoints=request.target.webhook_endpoints,
        email_addresses=[str(address) for address in request.target.email_addresses],
        channels=channels,
    )


def _validate_target(target: NotificationTarget, ttl_seconds: int) -> None:
    if ttl_seconds <= 0:
        raise HTTPException(status_code=422, detail="ttl_seconds must be greater than 0")
    if not target.channels:
        raise HTTPException(status_code=422, detail="target.channels must contain at least one channel")
    if not any(
        [
            target.organization_id,
            target.user_id,
            target.device_tokens,
            target.webhook_endpoints,
            target.email_addresses,
        ]
    ):
        raise HTTPException(
            status_code=422,
            detail="At least one of organization_id, user_id, device_tokens, webhook_endpoints, or email_addresses must be provided",
        )
    for endpoint in target.webhook_endpoints:
        if urlparse(endpoint).scheme.lower() != "https":
            raise HTTPException(status_code=422, detail="Webhook endpoints must use HTTPS")


async def _deliver_direct_webhook(notification: Notification, endpoint: str) -> DeliveryResult:
    """Deliver notification directly to a webhook endpoint with retry."""
    attempted_at = datetime.now(timezone.utc)
    payload = {
        "id": notification.id,
        "title": notification.subject,
        "body": notification.body,
        "data": notification.data,
        "event_type": notification.event_type,
        "priority": notification.priority.value,
        "correlation_id": notification.correlation_id,
        "created_at": notification.created_at.isoformat(),
    }
    headers = {
        "Content-Type": "application/json",
        "X-MIP-Notification-ID": notification.id,
        "X-MIP-Event-Type": notification.event_type,
    }
    secret = os.environ.get("NOTIFICATION_WEBHOOK_SECRET")
    if secret:
        headers["X-MIP-Signature"] = _generate_signature(secret, payload)

    max_attempts = int(os.environ.get("DIRECT_WEBHOOK_MAX_RETRIES", "3"))
    last_error: str | None = None
    for attempt in range(max_attempts):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(endpoint, json=payload, headers=headers)
            if 200 <= response.status_code < 300:
                return DeliveryResult(
                    notification_id=notification.id,
                    channel=ChannelType.WEBHOOK,
                    success=True,
                    attempted_at=attempted_at,
                    delivered_at=datetime.now(timezone.utc),
                )
            last_error = f"HTTP_{response.status_code}"
            if response.status_code < 500:
                break  # Non-retryable client error
        except httpx.HTTPError as exc:
            last_error = "WEBHOOK_DELIVERY_FAILED"
        # Exponential backoff before retry
        if attempt + 1 < max_attempts:
            import asyncio
            await asyncio.sleep(min(1 * (2 ** attempt), 30))

    return DeliveryResult(
        notification_id=notification.id,
        channel=ChannelType.WEBHOOK,
        success=False,
        attempted_at=attempted_at,
        error_code=last_error or "WEBHOOK_DELIVERY_FAILED",
        should_retry=False,
    )


async def _deliver_notification(notification: Notification) -> list[DeliveryResult]:
    target = notification.target
    if target is None:
        return []

    now = datetime.now(timezone.utc)
    results: list[DeliveryResult] = []
    for channel in target.channels:
        if channel == ChannelType.WEBHOOK:
            if not target.webhook_endpoints:
                results.append(
                    DeliveryResult(
                        notification_id=notification.id,
                        channel=channel,
                        success=False,
                        attempted_at=now,
                        error_code="NO_WEBHOOK_TARGETS",
                        should_retry=False,
                    )
                )
                continue
            for endpoint in target.webhook_endpoints:
                results.append(await _deliver_direct_webhook(notification, endpoint))
            continue

        if channel == ChannelType.EMAIL:
            success = bool(target.email_addresses)
            results.append(
                DeliveryResult(
                    notification_id=notification.id,
                    channel=channel,
                    success=success,
                    attempted_at=now,
                    delivered_at=now if success else None,
                    error_code=None if success else "NO_EMAIL_TARGETS",
                    should_retry=False if success else None,
                )
            )
            continue

        if channel in {ChannelType.FCM, ChannelType.SSE, ChannelType.SMS}:
            has_resolvable_target = bool(target.device_tokens or target.user_id or target.organization_id)
            results.append(
                DeliveryResult(
                    notification_id=notification.id,
                    channel=channel,
                    success=has_resolvable_target,
                    attempted_at=now,
                    delivered_at=now if has_resolvable_target else None,
                    error_code=None if has_resolvable_target else "NO_DEVICE_TARGETS",
                    should_retry=False if has_resolvable_target else None,
                )
            )
    return results


def _apply_delivery_results(notification: Notification, delivery_results: list[DeliveryResult]) -> None:
    notification.delivery_results = delivery_results
    notification.mark_sent()
    if any(result.success for result in delivery_results):
        notification.mark_delivered()
        notification.error_message = None
        return
    if delivery_results:
        notification.status = NotificationStatus.FAILED
        notification.error_message = next((result.error_code for result in delivery_results if result.error_code), None)


import ipaddress
import socket


def _validate_webhook_url(url: str) -> None:
    """Validate webhook URL is HTTPS and not targeting private/loopback networks (SSRF prevention)."""
    parsed = urlparse(url.strip())
    if parsed.scheme.lower() != "https":
        raise HTTPException(status_code=422, detail="Webhook URL must use HTTPS")
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=422, detail="Webhook URL must include a hostname")
    # Block localhost variants
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise HTTPException(status_code=422, detail="Webhook URL must not target localhost")
    # Resolve and check for private/reserved IPs
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        # hostname is a domain name — resolve it
        try:
            resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            addrs = [ipaddress.ip_address(r[4][0]) for r in resolved]
        except socket.gaierror:
            raise HTTPException(status_code=422, detail=f"Cannot resolve webhook hostname: {hostname}")
    else:
        addrs = [addr]
    for addr in addrs:
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
            raise HTTPException(
                status_code=422,
                detail="Webhook URL must not target private or reserved IP addresses",
            )


async def _deliver_to_webhook(
    payload: dict[str, Any],
    subscription: Subscription,
    webhook: WebhookEndpoint,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository,
) -> WebhookDelivery:
    retry_policy = subscription.retry_policy
    attempts_allowed = max(1, retry_policy.max_attempts)
    attempt_count = 0
    success = False
    error_message: str | None = None
    response_status_code: int | None = None
    response_body: str | None = None
    started_at = datetime.now(timezone.utc)

    # MIP §15.7: webhook URLs MUST be absolute HTTPS URIs
    if urlparse(webhook.url).scheme.lower() != "https":
        logger.warning("Webhook URL %s is not HTTPS — delivery blocked per MIP §15.7", webhook.url)
        return WebhookDelivery(
            id=str(uuid.uuid4()),
            webhook_endpoint_id=webhook.id,
            subscription_id=subscription.id,
            event_type=payload.get("type", ""),
            payload=payload,
            success=False,
            attempt_count=0,
            response_status_code=None,
            response_body=None,
            error_message="Webhook URL must use HTTPS",
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    async with httpx.AsyncClient(timeout=10.0) as client:
        for attempt in range(attempts_allowed):
            attempt_count = attempt + 1
            try:
                response = await client.post(
                    webhook.url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "X-MIP-Signature": _generate_signature(webhook.secret, payload),
                        "X-MIP-Event": payload["type"],
                        "X-MIP-Event-Id": payload["id"],
                        "X-MIP-Timestamp": payload["timestamp"],
                    },
                )
                response_status_code = response.status_code
                response_body = response.text[:1000]
                if 200 <= response.status_code < 300:
                    success = True
                    webhook.failure_count = 0
                    webhook.last_triggered_at = datetime.now(timezone.utc)
                    webhook.circuit_breaker_open_until = None
                    break
                error_message = f"HTTP {response.status_code}: {response.text[:200]}"
            except Exception as exc:  # pragma: no cover
                error_message = str(exc)

            if attempt + 1 < attempts_allowed:
                backoff = min(
                    retry_policy.initial_backoff_seconds * (2 ** attempt),
                    retry_policy.max_backoff_seconds,
                )
                await asyncio.sleep(backoff)

    if not success:
        webhook.failure_count += 1
        webhook.last_failure_at = datetime.now(timezone.utc)
        if webhook.failure_count >= WEBHOOK_CIRCUIT_BREAKER_THRESHOLD:
            webhook.circuit_breaker_open_until = datetime.now(timezone.utc) + timedelta(hours=1)

    webhook.updated_at = datetime.now(timezone.utc)
    await repo.save_webhook(webhook)

    delivery = WebhookDelivery(
        organization_id=subscription.organization_id,
        webhook_id=webhook.id,
        subscription_id=subscription.id,
        event_id=payload["id"],
        event_type=payload["type"],
        success=success,
        response_status_code=response_status_code,
        response_body=response_body,
        error_message=error_message if not success else None,
        retry_count=max(0, attempt_count - 1),
        response_time_ms=int((datetime.now(timezone.utc) - started_at).total_seconds() * 1000),
    )
    await repo.save_webhook_delivery(delivery)
    return delivery


async def _dispatch_event_to_subscriptions(
    event: EventIngestRequest,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository,
) -> dict[str, int]:
    subscriptions = await repo.list_subscriptions(event.organization_id)
    matching = [
        subscription
        for subscription in subscriptions
        if subscription.enabled
        and _match_event_patterns(subscription.event_types, event.event_type)
        and _filter_matches(
            subscription.filter_config,
            {
                "aggregate_id": event.aggregate_id,
                "aggregate_type": event.aggregate_type,
                "organization_id": event.organization_id,
                "data": event.data,
            },
        )
    ]

    payload = {
        "id": event.event_id or str(uuid.uuid4()),
        "type": event.event_type,
        "timestamp": event.timestamp or datetime.now(timezone.utc).isoformat(),
        "aggregate_id": event.aggregate_id,
        "aggregate_type": event.aggregate_type,
        "organization_id": event.organization_id,
        "data": event.data,
    }

    deliveries = 0
    failures = 0
    for subscription in matching:
        if subscription.delivery_channel != DeliveryChannel.WEBHOOK or not subscription.delivery_target_id:
            continue
        webhook = await repo.get_webhook(subscription.delivery_target_id)
        if not webhook or not webhook.enabled:
            continue
        if webhook.circuit_breaker_open_until and webhook.circuit_breaker_open_until > datetime.now(timezone.utc):
            failures += 1
            continue
        if webhook.event_types and not _match_event_patterns(webhook.event_types, event.event_type):
            continue
        delivery = await _deliver_to_webhook(payload, subscription, webhook, repo)
        deliveries += 1
        if not delivery.success:
            failures += 1

    return {"matched_subscriptions": len(matching), "deliveries": deliveries, "failures": failures}


def _to_response(notification: Notification) -> NotificationResponse:
    return NotificationResponse(
        id=notification.id,
        title=notification.subject,
        body=notification.body,
        data=notification.data,
        event_type=notification.event_type,
        priority=notification.priority.value,
        ttl_seconds=notification.ttl_seconds,
        collapse_key=notification.collapse_key,
        correlation_id=notification.correlation_id,
        target=_notification_target_to_model(notification.target) or NotificationTargetModel(channels=[]),
        created_at=notification.created_at.isoformat(),
    )


def _subscription_to_response(subscription: Subscription) -> SubscriptionResponse:
    return SubscriptionResponse(
        id=subscription.id,
        organization_id=subscription.organization_id,
        name=subscription.name,
        description=subscription.description,
        event_types=subscription.event_types,
        delivery={"channel": subscription.delivery_channel.value},
        filter=subscription.filter_config or None,
        retry_policy=subscription.retry_policy.model_dump() if subscription.retry_policy else None,
        enabled=subscription.enabled,
        created_at=subscription.created_at.isoformat(),
        updated_at=subscription.updated_at.isoformat(),
    )


def _webhook_to_response(webhook: WebhookEndpoint, include_secret: bool = False) -> WebhookResponse:
    return WebhookResponse(
        id=webhook.id,
        organization_id=webhook.organization_id,
        name=webhook.name,
        description=webhook.description,
        endpoint_url=webhook.url,
        events=webhook.event_types,
        signing_secret=webhook.secret if include_secret else None,
        signing_secret_masked=f"{webhook.secret[:4]}..." if webhook.secret else None,
        enabled=webhook.enabled,
        status="ACTIVE" if webhook.enabled else "DISABLED",
        failure_count=webhook.failure_count,
        last_triggered_at=webhook.last_triggered_at.isoformat() if webhook.last_triggered_at else None,
        last_success_at=None,
        created_at=webhook.created_at.isoformat(),
        updated_at=webhook.updated_at.isoformat(),
    )


def _delivery_to_response(delivery: WebhookDelivery) -> WebhookDeliveryResponse:
    return WebhookDeliveryResponse(
        id=delivery.id,
        webhook_id=delivery.webhook_id,
        subscription_id=delivery.subscription_id,
        event_id=delivery.event_id,
        event_type=delivery.event_type,
        success=delivery.success,
        response_status_code=delivery.response_status_code,
        response_body=delivery.response_body,
        error_message=delivery.error_message,
        retry_count=delivery.retry_count,
        response_time_ms=delivery.response_time_ms,
        created_at=delivery.created_at.isoformat(),
    )


# =============================================================================
# Routes
# =============================================================================


@router.post("/send", response_model=NotificationResponse, response_model_exclude_none=True)
async def send_notification(
    request: SendNotificationRequest,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> NotificationResponse:
    subject = request.title or request.subject or ""
    body = request.message or request.body or ""
    if request.template_id:
        template = await repo.get_template(request.template_id)
        if template:
            subject = template.subject_template
            body = template.body_template
            for key, value in request.data.items():
                subject = subject.replace(f"{{{{{key}}}}}", str(value))
                body = body.replace(f"{{{{{key}}}}}", str(value))

    target = _build_target(request)
    _validate_target(target, request.ttl_seconds)

    notification = Notification(
        organization_id=request.organization_id,
        recipient_id=request.recipient_id,
        recipient_email=request.recipient_email,
        notification_type=_notification_type_from_channels(target.channels),
        template_id=request.template_id,
        subject=subject,
        body=body,
        severity=request.severity,
        link=request.link,
        data=request.data,
        priority=_parse_priority(request.priority),
        event_type=request.event_type,
        ttl_seconds=request.ttl_seconds,
        collapse_key=request.collapse_key,
        correlation_id=request.correlation_id,
        target=target,
    )
    delivery_results = await _deliver_notification(notification)
    _apply_delivery_results(notification, delivery_results)
    await repo.save_notification(notification)
    logger.info("Sent notification %s to %s", notification.id, request.recipient_email)
    return _to_response(notification)


@router.get("", response_model=list[NotificationResponse], response_model_exclude_none=True)
async def list_notifications(
    organization_id: str | None = None,
    recipient_id: str | None = None,
    status: str | None = None,
    unread_only: bool = Query(False),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> list[NotificationResponse]:
    status_filter = NotificationStatus(status) if status else None
    notifications = await repo.list_notifications(organization_id, recipient_id, status_filter)
    if unread_only:
        notifications = [notification for notification in notifications if not notification.is_read]
    return [_to_response(notification) for notification in notifications[offset:offset + limit]]


@router.get("/unread/count", response_model=NotificationCountResponse, response_model_exclude_none=True)
@router.get("/unread-count", response_model=NotificationCountResponse, response_model_exclude_none=True)
async def get_unread_count(
    organization_id: str | None = None,
    recipient_id: str | None = None,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> NotificationCountResponse:
    effective_recipient_id = recipient_id or x_user_id
    if not effective_recipient_id:
        raise HTTPException(status_code=400, detail="recipient_id or X-User-Id is required")
    notifications = await repo.list_notifications(organization_id, effective_recipient_id)
    return NotificationCountResponse(count=sum(1 for notification in notifications if not notification.is_read))


@router.patch("/{notification_id}/read", response_model=NotificationResponse, response_model_exclude_none=True)
async def mark_as_read(
    notification_id: str,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> NotificationResponse:
    notification = await repo.get_notification(notification_id)
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    notification.mark_read()
    await repo.save_notification(notification)
    return _to_response(notification)


@router.delete("/{notification_id}/read", response_model=NotificationResponse, response_model_exclude_none=True)
async def mark_as_unread(
    notification_id: str,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> NotificationResponse:
    notification = await repo.get_notification(notification_id)
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    notification.read_at = None
    await repo.save_notification(notification)
    return _to_response(notification)


@router.post("/read-all", response_model=MarkAllReadResponse, response_model_exclude_none=True)
async def mark_all_as_read(
    organization_id: str | None = None,
    recipient_id: str | None = None,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> MarkAllReadResponse:
    effective_recipient_id = recipient_id or x_user_id
    if not effective_recipient_id:
        raise HTTPException(status_code=400, detail="recipient_id or X-User-Id is required")
    notifications = await repo.list_notifications(organization_id, effective_recipient_id)
    marked = 0
    for notification in notifications:
        if not notification.is_read:
            notification.mark_read()
            await repo.save_notification(notification)
            marked += 1
    return MarkAllReadResponse(marked_read=marked)


@router.delete("/{notification_id}", response_model=DeleteResponse)
async def delete_notification(
    notification_id: str,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> DeleteResponse:
    deleted = await repo.delete_notification(notification_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Notification not found")
    return DeleteResponse()


@router.get("/templates", response_model=list[TemplateResponse], response_model_exclude_none=True)
async def list_templates(
    organization_id: str | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> list[TemplateResponse]:
    templates = await repo.list_templates(organization_id)
    return [
        TemplateResponse(
            id=template.id,
            name=template.name,
            notification_type=template.notification_type.value,
            subject_template=template.subject_template,
            active=template.active,
        )
        for template in templates[offset:offset + limit]
    ]


@router.get("/{notification_id}", response_model=NotificationResponse, response_model_exclude_none=True)
async def get_notification(
    notification_id: str,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> NotificationResponse:
    notification = await repo.get_notification(notification_id)
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    return _to_response(notification)


@router.get("/{notification_id}/delivery-results", response_model=list[DeliveryResultResponse], response_model_exclude_none=True)
async def get_delivery_results(
    notification_id: str,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> list[DeliveryResultResponse]:
    notification = await repo.get_notification(notification_id)
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    results = notification.delivery_results[offset:offset + limit]
    return [_delivery_result_to_response(result) for result in results]


@subscription_router.post("", response_model=SubscriptionResponse, response_model_exclude_none=True)
async def create_subscription(
    body: CreateSubscriptionRequest,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> SubscriptionResponse:
    if body.delivery_channel != DeliveryChannel.WEBHOOK.value:
        raise HTTPException(status_code=422, detail="Only WEBHOOK delivery_channel is currently supported")
    if not body.event_types:
        raise HTTPException(status_code=422, detail="event_types must contain at least one event")
    if not body.delivery_target_id:
        raise HTTPException(status_code=422, detail="delivery_target_id is required for WEBHOOK subscriptions")
    webhook = await repo.get_webhook(body.delivery_target_id)
    if not webhook or webhook.organization_id != body.organization_id:
        raise HTTPException(status_code=422, detail="Referenced webhook endpoint not found")

    # MIP §15 — validate event_types against MIP-defined set
    _ALLOWED_EVENT_TYPES = set(STANDARD_EVENT_CHANNELS.keys())
    unknown = set(body.event_types) - _ALLOWED_EVENT_TYPES
    if unknown:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown event_types: {', '.join(sorted(unknown))}. Allowed: {', '.join(sorted(_ALLOWED_EVENT_TYPES))}",
        )
    subscription = Subscription(
        organization_id=body.organization_id,
        name=body.name,
        description=body.description,
        event_types=body.event_types,
        delivery_channel=DeliveryChannel(body.delivery_channel),
        filter_config=body.filter,
        retry_policy=RetryPolicy(**body.retry_policy.model_dump()),
        delivery_target_id=body.delivery_target_id,
        enabled=body.enabled,
    )
    await repo.save_subscription(subscription)
    return _subscription_to_response(subscription)


@subscription_router.get("", response_model=list[SubscriptionResponse], response_model_exclude_none=True)
async def list_subscriptions(
    organization_id: str = Query(...),
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> list[SubscriptionResponse]:
    subscriptions = await repo.list_subscriptions(organization_id)
    return [_subscription_to_response(subscription) for subscription in subscriptions]


@subscription_router.get("/{subscription_id}", response_model=SubscriptionResponse, response_model_exclude_none=True)
async def get_subscription(
    subscription_id: str,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> SubscriptionResponse:
    subscription = await repo.get_subscription(subscription_id)
    if not subscription:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return _subscription_to_response(subscription)


@subscription_router.put("/{subscription_id}", response_model=SubscriptionResponse, response_model_exclude_none=True)
async def update_subscription(
    subscription_id: str,
    body: UpdateSubscriptionRequest,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> SubscriptionResponse:
    subscription = await repo.get_subscription(subscription_id)
    if not subscription:
        raise HTTPException(status_code=404, detail="Subscription not found")
    if body.name is not None:
        subscription.name = body.name
    if body.description is not None:
        subscription.description = body.description
    if body.event_types is not None:
        if not body.event_types:
            raise HTTPException(status_code=422, detail="event_types must contain at least one event")
        subscription.event_types = body.event_types
    if body.delivery_channel is not None:
        if body.delivery_channel != DeliveryChannel.WEBHOOK.value:
            raise HTTPException(status_code=422, detail="Only WEBHOOK delivery_channel is currently supported")
        subscription.delivery_channel = DeliveryChannel(body.delivery_channel)
    if body.filter is not None:
        subscription.filter_config = body.filter
    if body.retry_policy is not None:
        subscription.retry_policy = RetryPolicy(**body.retry_policy.model_dump())
    if body.delivery_target_id is not None:
        webhook = await repo.get_webhook(body.delivery_target_id)
        if not webhook or webhook.organization_id != subscription.organization_id:
            raise HTTPException(status_code=422, detail="Referenced webhook endpoint not found")
        subscription.delivery_target_id = body.delivery_target_id
    if body.enabled is not None:
        subscription.enabled = body.enabled
    subscription.updated_at = datetime.now(timezone.utc)
    await repo.save_subscription(subscription)
    return _subscription_to_response(subscription)


@subscription_router.delete("/{subscription_id}", response_model=DeleteResponse)
async def delete_subscription(
    subscription_id: str,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> DeleteResponse:
    deleted = await repo.delete_subscription(subscription_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return DeleteResponse()


@webhook_router.post("", response_model=WebhookResponse, response_model_exclude_none=True)
async def create_webhook(
    body: CreateWebhookRequest,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> WebhookResponse:
    # MIP §15.7 — webhook URLs MUST be HTTPS; also block private/loopback (SSRF)
    _validate_webhook_url(body.url)
    webhook = WebhookEndpoint(
        organization_id=body.organization_id,
        name=body.name,
        url=body.url,
        secret=body.secret or secrets.token_hex(32),
        description=body.description,
        event_types=body.event_types,
        enabled=body.enabled,
    )
    await repo.save_webhook(webhook)
    return _webhook_to_response(webhook, include_secret=True)


@webhook_router.get("", response_model=list[WebhookResponse], response_model_exclude_none=True)
async def list_webhooks(
    organization_id: str = Query(...),
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> list[WebhookResponse]:
    webhooks = await repo.list_webhooks(organization_id)
    return [_webhook_to_response(webhook) for webhook in webhooks]


@webhook_router.get("/{webhook_id}", response_model=WebhookResponse, response_model_exclude_none=True)
async def get_webhook(
    webhook_id: str,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> WebhookResponse:
    webhook = await repo.get_webhook(webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return _webhook_to_response(webhook)


@webhook_router.put("/{webhook_id}", response_model=WebhookResponse, response_model_exclude_none=True)
async def update_webhook(
    webhook_id: str,
    body: UpdateWebhookRequest,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> WebhookResponse:
    webhook = await repo.get_webhook(webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    if body.name is not None:
        webhook.name = body.name
    if body.url is not None:
        _validate_webhook_url(body.url)
        webhook.url = body.url
    if body.description is not None:
        webhook.description = body.description
    if body.event_types is not None:
        webhook.event_types = body.event_types
    secret_rotated = False
    if body.secret is not None:
        webhook.secret = body.secret
        secret_rotated = True
    if body.enabled is not None:
        webhook.enabled = body.enabled
    webhook.updated_at = datetime.now(timezone.utc)
    await repo.save_webhook(webhook)
    # MIP: write-only secret — return it only on creation or rotation
    return _webhook_to_response(webhook, include_secret=secret_rotated)


@webhook_router.delete("/{webhook_id}", response_model=DeleteResponse)
async def delete_webhook(
    webhook_id: str,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> DeleteResponse:
    deleted = await repo.delete_webhook(webhook_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return DeleteResponse()


@webhook_router.get("/{webhook_id}/deliveries", response_model=list[WebhookDeliveryResponse], response_model_exclude_none=True)
async def list_webhook_deliveries(
    webhook_id: str,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> list[WebhookDeliveryResponse]:
    webhook = await repo.get_webhook(webhook_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    deliveries = await repo.list_webhook_deliveries(webhook_id)
    return [_delivery_to_response(delivery) for delivery in deliveries]


@internal_router.post("/events")
async def ingest_event(
    body: EventIngestRequest,
    repo: InMemoryNotificationRepository | PostgresNotificationRepository = Depends(get_repo),
) -> dict[str, int | str]:
    result = await _dispatch_event_to_subscriptions(body, repo)
    return {"status": "accepted", **result}


# =============================================================================
# Application Setup
# =============================================================================


async def _seed_default_templates(repo: InMemoryNotificationRepository | PostgresNotificationRepository) -> None:
    for template in default_templates():
        if await repo.get_template(template.id):
            continue
        await repo.save_template(template)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo
    logger.info("Starting %s...", SERVICE_NAME)
    engine = create_async_engine(
        os.environ.get("DATABASE_URL", "postgresql+asyncpg://marty:marty_dev@localhost:5432/marty_credentials"),
        future=True,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        pool_recycle=3600,
    )
    async with engine.begin() as conn:
        await conn.execute(text("CREATE SCHEMA IF NOT EXISTS notification_service"))
        await conn.run_sync(mapper_registry.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    _repo = PostgresNotificationRepository(session_factory)
    await _seed_default_templates(_repo)

    grpc_enabled = os.environ.get("NOTIF_GRPC_ENABLED", "true").lower() == "true"
    grpc_server = None
    if grpc_enabled:
        from common.grpc_factory import create_grpc_server, start_grpc_server_port
        from marty_proto.v1.notification_service_pb2_grpc import add_NotificationServiceServicer_to_server
        from notification.infrastructure.adapters.grpc_adapter import NotificationServiceGrpc

        grpc_port = int(os.environ.get("NOTIF_GRPC_PORT", "9007"))
        grpc_server, health_servicer = create_grpc_server("notification")
        notif_servicer = NotificationServiceGrpc(get_repo_fn=get_repo)
        add_NotificationServiceServicer_to_server(notif_servicer, grpc_server)
        start_grpc_server_port(
            grpc_server,
            grpc_port,
            service_names=["marty.ui.notification.v1.NotificationService"],
            health_servicer=health_servicer,
        )
        await grpc_server.start()
        logger.info("Notification gRPC server listening on :%s", grpc_port)

    yield

    logger.info("Shutting down %s...", SERVICE_NAME)
    if grpc_server:
        await grpc_server.stop(grace=5)
    await engine.dispose()


def create_app() -> FastAPI:
    return create_service_app(
        title="Notification Service",
        description="Notifications, subscriptions, and webhook delivery service",
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[router, subscription_router, webhook_router, internal_router],
    )


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
