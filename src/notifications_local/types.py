"""Type definitions for the Notification Hub."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class ChannelType(str, Enum):
    """Supported notification delivery channels."""

    FCM = "fcm"  # Firebase Cloud Messaging (mobile push)
    WEBHOOK = "webhook"  # HTTP webhooks to vendor systems
    EMAIL = "email"  # Email notifications
    SSE = "sse"  # Server-Sent Events (real-time dashboard)
    SMS = "sms"  # SMS notifications (future)


class DeliveryStatus(str, Enum):
    """Status of a notification delivery attempt."""

    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"
    EXPIRED = "expired"


class NotificationPriority(str, Enum):
    """Priority levels for notifications."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


@dataclass
class NotificationTarget:
    """Multi-principal identity target for notifications.

    Represents a target that can receive notifications through various
    channels. Supports tenant+user, API keys, and wallet DIDs.

    Attributes:
        tenant_id: The organization/tenant ID
        user_id: Optional user ID within the tenant
        channel: The delivery channel to use
        device_token: FCM token for push notifications
        webhook_url: URL for webhook delivery
        webhook_secret: Secret for HMAC signing webhooks
        email: Email address for email delivery
        api_key_id: API key ID for webhook authentication
        wallet_did: DID from mobile wallet (SpruceID)
        preferences: Channel-specific delivery preferences
    """

    tenant_id: str
    channel: ChannelType
    user_id: Optional[str] = None
    device_token: Optional[str] = None
    webhook_url: Optional[str] = None
    webhook_secret: Optional[str] = None
    email: Optional[str] = None
    api_key_id: Optional[str] = None
    wallet_did: Optional[str] = None
    preferences: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate that required fields are present for the channel."""
        if self.channel == ChannelType.FCM and not self.device_token:
            raise ValueError("FCM channel requires device_token")
        if self.channel == ChannelType.WEBHOOK and not self.webhook_url:
            raise ValueError("Webhook channel requires webhook_url")
        if self.channel == ChannelType.EMAIL and not self.email:
            raise ValueError("Email channel requires email address")


@dataclass
class NotificationPayload:
    """Payload for a notification to be delivered.

    Attributes:
        event_type: The domain event type that triggered this notification
        title: Human-readable notification title
        body: Notification body/message
        data: Structured data payload
        action_url: Optional URL for click action
        image_url: Optional image URL
        priority: Notification priority
        ttl_seconds: Time-to-live in seconds
        collapse_key: Key for collapsing similar notifications
        tenant_id: Tenant this notification belongs to
        correlation_id: ID for correlating with source event
    """

    event_type: str
    title: str
    body: str
    data: dict[str, Any] = field(default_factory=dict)
    action_url: Optional[str] = None
    image_url: Optional[str] = None
    priority: NotificationPriority = NotificationPriority.NORMAL
    ttl_seconds: int = 86400  # 24 hours default
    collapse_key: Optional[str] = None
    tenant_id: Optional[str] = None
    correlation_id: Optional[str] = None

    def to_fcm_message(self) -> dict[str, Any]:
        """Convert to FCM message format."""
        message = {
            "notification": {
                "title": self.title,
                "body": self.body,
            },
            "data": {
                "event_type": self.event_type,
                "correlation_id": self.correlation_id or "",
                **{k: str(v) for k, v in self.data.items()},
            },
            "android": {
                "priority": "high" if self.priority in (NotificationPriority.HIGH, NotificationPriority.URGENT) else "normal",
                "ttl": f"{self.ttl_seconds}s",
            },
            "apns": {
                "headers": {
                    "apns-priority": "10" if self.priority in (NotificationPriority.HIGH, NotificationPriority.URGENT) else "5",
                    "apns-expiration": str(int(datetime.utcnow().timestamp()) + self.ttl_seconds),
                },
            },
        }

        if self.image_url:
            message["notification"]["image"] = self.image_url

        if self.collapse_key:
            message["android"]["collapse_key"] = self.collapse_key
            message["apns"]["headers"]["apns-collapse-id"] = self.collapse_key

        return message

    def to_webhook_payload(self) -> dict[str, Any]:
        """Convert to webhook payload format."""
        return {
            "event_type": self.event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "tenant_id": self.tenant_id,
            "correlation_id": self.correlation_id,
            "data": {
                "title": self.title,
                "body": self.body,
                **self.data,
            },
        }

    def to_email_content(self) -> dict[str, Any]:
        """Convert to email content format."""
        return {
            "subject": self.title,
            "body_text": self.body,
            "body_html": f"<p>{self.body}</p>",
            "event_type": self.event_type,
            "data": self.data,
            "action_url": self.action_url,
        }

    def to_sse_event(self) -> dict[str, Any]:
        """Convert to Server-Sent Event format."""
        return {
            "event": self.event_type,
            "data": {
                "title": self.title,
                "body": self.body,
                "timestamp": datetime.utcnow().isoformat(),
                "correlation_id": self.correlation_id,
                **self.data,
            },
        }


@dataclass
class DeliveryResult:
    """Result of a notification delivery attempt.

    Attributes:
        target: The notification target
        status: Delivery status
        delivered_at: When the notification was delivered
        error: Error message if failed
        provider_response: Raw response from the delivery provider
        retry_count: Number of retry attempts made
        next_retry_at: When the next retry is scheduled
    """

    target: NotificationTarget
    status: DeliveryStatus
    delivered_at: Optional[datetime] = None
    error: Optional[str] = None
    provider_response: Optional[dict[str, Any]] = None
    retry_count: int = 0
    next_retry_at: Optional[datetime] = None

    @property
    def success(self) -> bool:
        """Check if delivery was successful."""
        return self.status == DeliveryStatus.DELIVERED


@dataclass
class BatchDeliveryResult:
    """Result of a batch notification delivery."""

    total: int
    delivered: int
    failed: int
    pending: int
    results: list[DeliveryResult] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        """Calculate delivery success rate."""
        if self.total == 0:
            return 0.0
        return self.delivered / self.total


@dataclass
class NotificationSubscription:
    """Subscription to specific event types for a target.

    Attributes:
        target_id: ID of the notification target
        event_types: List of event types to subscribe to
        channel: Preferred delivery channel
        filters: Optional filters for event matching
        created_at: When the subscription was created
        is_active: Whether the subscription is active
    """

    target_id: str
    event_types: list[str]
    channel: ChannelType
    filters: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    is_active: bool = True
