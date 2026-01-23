"""Central Notification Hub for multi-channel event delivery.

This module provides the main NotificationHub class that orchestrates
event consumption from MMF messaging and delivery through multiple
channels (FCM, Webhook, Email, SSE).
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional, Protocol

from .device_registry import DeviceRegistry
from .router import NotificationRouter, RouteAction, create_default_routing_rules
from .types import (
    BatchDeliveryResult,
    ChannelType,
    DeliveryResult,
    DeliveryStatus,
    NotificationPayload,
    NotificationPriority,
    NotificationTarget,
)

logger = logging.getLogger(__name__)


class INotificationAdapter(Protocol):
    """Protocol for notification delivery adapters.

    Each channel (FCM, Webhook, Email, SSE) implements this protocol
    to handle delivery for that specific channel.
    """

    async def send(
        self,
        target: NotificationTarget,
        payload: NotificationPayload,
    ) -> DeliveryResult:
        """Send a notification to a single target.

        Args:
            target: The notification target
            payload: The notification payload

        Returns:
            DeliveryResult indicating success/failure
        """
        ...

    async def send_batch(
        self,
        targets: list[NotificationTarget],
        payload: NotificationPayload,
    ) -> BatchDeliveryResult:
        """Send a notification to multiple targets.

        Args:
            targets: List of notification targets
            payload: The notification payload

        Returns:
            BatchDeliveryResult with per-target results
        """
        ...

    async def health_check(self) -> dict[str, Any]:
        """Check adapter health.

        Returns:
            Dictionary with health status and metrics
        """
        ...


class IMessageConsumer(Protocol):
    """Protocol matching MMF IMessageConsumer interface."""

    async def start(self) -> None:
        """Start consuming messages."""
        ...

    async def stop(self) -> None:
        """Stop consuming messages."""
        ...

    async def set_handler(self, handler: Any) -> None:
        """Set the message handler."""
        ...

    async def acknowledge(self, message_id: str) -> bool:
        """Acknowledge a message."""
        ...

    async def reject(self, message_id: str, requeue: bool = False) -> bool:
        """Reject a message."""
        ...


class IMessagingManager(Protocol):
    """Protocol matching MMF IMessagingManager interface."""

    async def create_consumer(self, config: Any) -> IMessageConsumer:
        """Create a message consumer."""
        ...


@dataclass
class HubMetrics:
    """Metrics for the Notification Hub."""

    events_received: int = 0
    notifications_sent: int = 0
    notifications_delivered: int = 0
    notifications_failed: int = 0
    by_channel: dict[str, dict[str, int]] = field(default_factory=dict)
    by_event_type: dict[str, int] = field(default_factory=dict)
    last_event_at: Optional[datetime] = None
    started_at: Optional[datetime] = None


@dataclass
class HubConfig:
    """Configuration for the Notification Hub."""

    # Queue configuration
    queue_name: str = "notification-hub"
    prefetch_count: int = 100

    # Delivery settings
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    batch_size: int = 100
    batch_timeout_seconds: float = 0.5

    # Channel settings
    enabled_channels: list[ChannelType] = field(
        default_factory=lambda: [
            ChannelType.FCM,
            ChannelType.WEBHOOK,
            ChannelType.EMAIL,
            ChannelType.SSE,
        ]
    )

    # Filtering
    event_type_filter: Optional[list[str]] = None
    tenant_filter: Optional[list[str]] = None


class NotificationHub:
    """Central hub for multi-channel notification delivery.

    The NotificationHub consumes domain events from the MMF messaging
    infrastructure and delivers notifications through multiple channels:
    - FCM: Push notifications to mobile apps (Marty Auth)
    - Webhook: HTTP callbacks to vendor systems
    - Email: Email notifications via SendGrid/SES
    - SSE: Real-time updates to web dashboards

    Example:
        # Create hub with adapters
        hub = NotificationHub(
            messaging_manager=mmf_manager,
            device_registry=registry,
            adapters={
                ChannelType.FCM: fcm_adapter,
                ChannelType.WEBHOOK: webhook_adapter,
                ChannelType.EMAIL: email_adapter,
                ChannelType.SSE: sse_adapter,
            },
            config=HubConfig(
                queue_name="notification-hub",
                prefetch_count=100,
            ),
        )

        # Start processing events
        await hub.start()

        # Later, stop gracefully
        await hub.stop()
    """

    def __init__(
        self,
        messaging_manager: Optional[IMessagingManager],
        device_registry: DeviceRegistry,
        adapters: dict[ChannelType, INotificationAdapter],
        config: Optional[HubConfig] = None,
        router: Optional[NotificationRouter] = None,
    ):
        """Initialize the Notification Hub.

        Args:
            messaging_manager: MMF messaging manager (optional for direct delivery)
            device_registry: Registry of notification targets
            adapters: Channel adapters for delivery
            config: Hub configuration
            router: Notification router (uses defaults if not provided)
        """
        self._messaging = messaging_manager
        self._registry = device_registry
        self._adapters = adapters
        self._config = config or HubConfig()
        self._router = router or NotificationRouter()
        self._consumer: Optional[IMessageConsumer] = None
        self._metrics = HubMetrics()
        self._running = False

        # Initialize default routing rules
        for rule in create_default_routing_rules():
            self._router.add_rule(rule)

    async def start(self) -> None:
        """Start the notification hub.

        Connects to MMF messaging and starts consuming events.
        """
        if self._running:
            logger.warning("NotificationHub already running")
            return

        self._running = True
        self._metrics.started_at = datetime.utcnow()

        if self._messaging:
            # Create consumer from MMF
            # Note: In production, this would use actual MMF ConsumerConfig
            self._consumer = await self._messaging.create_consumer(
                {
                    "queue_name": self._config.queue_name,
                    "prefetch_count": self._config.prefetch_count,
                }
            )
            await self._consumer.set_handler(self._handle_message)
            await self._consumer.start()

            logger.info(
                "NotificationHub started",
                extra={"queue": self._config.queue_name},
            )
        else:
            logger.info("NotificationHub started in direct delivery mode")

    async def stop(self) -> None:
        """Stop the notification hub.

        Gracefully shuts down message consumption and pending deliveries.
        """
        if not self._running:
            return

        self._running = False

        if self._consumer:
            await self._consumer.stop()
            self._consumer = None

        logger.info("NotificationHub stopped")

    async def deliver(
        self,
        event_type: str,
        tenant_id: str,
        payload: NotificationPayload,
        user_id: Optional[str] = None,
    ) -> BatchDeliveryResult:
        """Deliver a notification directly (without going through messaging).

        This method can be used for synchronous delivery or testing.

        Args:
            event_type: The event type
            tenant_id: The tenant to deliver to
            payload: The notification payload
            user_id: Optional specific user to deliver to

        Returns:
            BatchDeliveryResult with delivery results
        """
        # Get targets from registry
        targets_by_channel = await self._registry.get_targets_by_channel(
            tenant_id=tenant_id,
            event_type=event_type,
        )

        # Route to determine channels and priority
        matches = self._router.route(event_type, payload)

        # Get effective channels from routing
        effective_channels = set()
        effective_priority = payload.priority
        effective_payload = payload

        for match in matches:
            if match.action == RouteAction.SUPPRESS:
                # Event suppressed by routing rule
                logger.debug(f"Event {event_type} suppressed by rule {match.rule.id}")
                return BatchDeliveryResult(total=0, delivered=0, failed=0, pending=0)

            effective_channels.update(match.channels)

            if match.priority.value > effective_priority.value:
                effective_priority = match.priority

            if match.transformed_payload:
                effective_payload = match.transformed_payload

        # Deliver to each channel
        all_results: list[DeliveryResult] = []

        for channel in effective_channels:
            if channel not in self._config.enabled_channels:
                continue

            adapter = self._adapters.get(channel)
            if not adapter:
                logger.warning(f"No adapter for channel {channel.value}")
                continue

            targets = targets_by_channel.get(channel, [])
            if not targets:
                continue

            # Filter by user if specified
            if user_id:
                targets = [t for t in targets if t.user_id == user_id]

            if targets:
                effective_payload.priority = effective_priority
                result = await adapter.send_batch(targets, effective_payload)
                all_results.extend(result.results)

                # Update metrics
                self._update_channel_metrics(channel, result)

        # Aggregate results
        total = len(all_results)
        delivered = sum(1 for r in all_results if r.success)
        failed = total - delivered

        self._metrics.notifications_sent += total
        self._metrics.notifications_delivered += delivered
        self._metrics.notifications_failed += failed
        self._update_event_metrics(event_type)

        return BatchDeliveryResult(
            total=total,
            delivered=delivered,
            failed=failed,
            pending=0,
            results=all_results,
        )

    async def _handle_message(self, message: Any) -> None:
        """Handle an incoming message from MMF.

        Args:
            message: The MMF message object
        """
        try:
            self._metrics.events_received += 1
            self._metrics.last_event_at = datetime.utcnow()

            # Extract event data from message
            body = message.body if hasattr(message, "body") else message
            event_type = body.get("event_type")
            tenant_id = body.get("tenant_id")
            correlation_id = body.get("correlation_id") or (
                message.headers.get("correlation_id") if hasattr(message, "headers") else None
            )

            if not event_type or not tenant_id:
                logger.warning("Message missing event_type or tenant_id")
                if self._consumer:
                    await self._consumer.reject(message.id, requeue=False)
                return

            # Apply filters
            if self._config.event_type_filter:
                if not any(event_type.startswith(f) for f in self._config.event_type_filter):
                    if self._consumer:
                        await self._consumer.acknowledge(message.id)
                    return

            if self._config.tenant_filter:
                if tenant_id not in self._config.tenant_filter:
                    if self._consumer:
                        await self._consumer.acknowledge(message.id)
                    return

            # Create notification payload from event
            payload = self._create_payload_from_event(body, correlation_id)

            # Deliver notification
            result = await self.deliver(event_type, tenant_id, payload)

            logger.info(
                "Delivered notification",
                extra={
                    "event_type": event_type,
                    "tenant_id": tenant_id,
                    "delivered": result.delivered,
                    "failed": result.failed,
                },
            )

            # Acknowledge message
            if self._consumer:
                await self._consumer.acknowledge(message.id)

        except Exception as e:
            logger.exception("Error handling message")
            if self._consumer and hasattr(message, "id"):
                await self._consumer.reject(message.id, requeue=True)

    def _create_payload_from_event(
        self,
        event_data: dict[str, Any],
        correlation_id: Optional[str],
    ) -> NotificationPayload:
        """Create a notification payload from event data.

        Args:
            event_data: The event data dictionary
            correlation_id: Optional correlation ID

        Returns:
            NotificationPayload for delivery
        """
        event_type = event_data.get("event_type", "unknown")
        event_payload = event_data.get("payload", {})
        tenant_id = event_data.get("tenant_id")

        # Generate human-readable title and body
        title, body = self._format_notification(event_type, event_payload)

        return NotificationPayload(
            event_type=event_type,
            title=title,
            body=body,
            data=event_payload,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            priority=self._infer_priority(event_type),
        )

    def _format_notification(
        self,
        event_type: str,
        payload: dict[str, Any],
    ) -> tuple[str, str]:
        """Format event into human-readable notification.

        Args:
            event_type: The event type
            payload: The event payload

        Returns:
            Tuple of (title, body)
        """
        # Default formatting - can be customized with templates
        event_titles = {
            "credential.issued": "Credential Issued",
            "credential.revoked": "Credential Revoked",
            "credential.expired": "Credential Expired",
            "dsc.revoked": "Document Signer Certificate Revoked",
            "csca.revoked": "Country Signing CA Revoked",
            "trust_anchor.cascade": "Trust Anchor Cascade Alert",
            "subscription.created": "Subscription Created",
            "subscription.cancelled": "Subscription Cancelled",
            "payment.confirmed": "Payment Confirmed",
            "payment.failed": "Payment Failed",
            "usage.threshold_reached": "Usage Threshold Alert",
            "trust_registry.delta": "Trust Registry Updated",
        }

        title = event_titles.get(event_type, f"Event: {event_type}")

        # Generate body based on event type
        if event_type == "credential.revoked":
            reason = payload.get("reason", "No reason provided")
            body = f"A credential has been revoked. Reason: {reason}"

        elif event_type == "trust_anchor.cascade":
            count = payload.get("affected_count", 0)
            body = f"Trust anchor change affects {count} credentials. Action may be required."

        elif event_type == "payment.failed":
            reason = payload.get("failure_reason", "Unknown error")
            body = f"Payment failed: {reason}"

        elif event_type == "usage.threshold_reached":
            resource = payload.get("resource_type", "resource")
            percent = payload.get("threshold_percent", 0)
            body = f"{resource} usage has reached {percent}% of your limit."

        else:
            body = f"Event occurred: {event_type}"

        return title, body

    def _infer_priority(self, event_type: str) -> NotificationPriority:
        """Infer notification priority from event type.

        Args:
            event_type: The event type

        Returns:
            Inferred priority level
        """
        urgent_events = {
            "credential.revoked",
            "dsc.revoked",
            "csca.revoked",
            "trust_anchor.cascade",
        }
        high_events = {
            "payment.failed",
            "usage.threshold_reached",
            "usage.limit_exceeded",
        }

        if event_type in urgent_events:
            return NotificationPriority.URGENT
        elif event_type in high_events:
            return NotificationPriority.HIGH
        else:
            return NotificationPriority.NORMAL

    def _update_channel_metrics(
        self,
        channel: ChannelType,
        result: BatchDeliveryResult,
    ) -> None:
        """Update per-channel metrics.

        Args:
            channel: The channel type
            result: The batch delivery result
        """
        channel_name = channel.value
        if channel_name not in self._metrics.by_channel:
            self._metrics.by_channel[channel_name] = {
                "sent": 0,
                "delivered": 0,
                "failed": 0,
            }

        self._metrics.by_channel[channel_name]["sent"] += result.total
        self._metrics.by_channel[channel_name]["delivered"] += result.delivered
        self._metrics.by_channel[channel_name]["failed"] += result.failed

    def _update_event_metrics(self, event_type: str) -> None:
        """Update per-event-type metrics.

        Args:
            event_type: The event type
        """
        if event_type not in self._metrics.by_event_type:
            self._metrics.by_event_type[event_type] = 0
        self._metrics.by_event_type[event_type] += 1

    async def health_check(self) -> dict[str, Any]:
        """Check hub health and return status.

        Returns:
            Dictionary with health status and metrics
        """
        adapter_health = {}
        for channel, adapter in self._adapters.items():
            try:
                adapter_health[channel.value] = await adapter.health_check()
            except Exception as e:
                adapter_health[channel.value] = {"status": "error", "error": str(e)}

        return {
            "status": "healthy" if self._running else "stopped",
            "running": self._running,
            "metrics": {
                "events_received": self._metrics.events_received,
                "notifications_sent": self._metrics.notifications_sent,
                "notifications_delivered": self._metrics.notifications_delivered,
                "notifications_failed": self._metrics.notifications_failed,
                "by_channel": self._metrics.by_channel,
                "by_event_type": self._metrics.by_event_type,
            },
            "started_at": self._metrics.started_at.isoformat() if self._metrics.started_at else None,
            "last_event_at": self._metrics.last_event_at.isoformat() if self._metrics.last_event_at else None,
            "adapters": adapter_health,
        }

    @property
    def metrics(self) -> HubMetrics:
        """Get hub metrics."""
        return self._metrics

    @property
    def router(self) -> NotificationRouter:
        """Get the notification router."""
        return self._router
