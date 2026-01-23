"""Server-Sent Events (SSE) adapter for real-time dashboard notifications.

This adapter maintains persistent connections to web clients and
delivers notifications in real-time through Server-Sent Events.
"""

import asyncio
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator, Optional
from weakref import WeakSet

from ..types import (
    BatchDeliveryResult,
    DeliveryResult,
    DeliveryStatus,
    NotificationPayload,
    NotificationTarget,
)

logger = logging.getLogger(__name__)


@dataclass
class SSEConfig:
    """Configuration for SSE adapter.

    Attributes:
        heartbeat_interval: Seconds between heartbeat messages
        max_connections_per_tenant: Maximum connections per tenant
        max_total_connections: Maximum total connections
        message_timeout: Timeout for message delivery
        buffer_size: Size of message buffer per connection
    """

    heartbeat_interval: float = 30.0
    max_connections_per_tenant: int = 100
    max_total_connections: int = 10000
    message_timeout: float = 5.0
    buffer_size: int = 100


@dataclass
class SSEMetrics:
    """Metrics for SSE adapter."""

    connections_active: int = 0
    connections_total: int = 0
    messages_sent: int = 0
    messages_delivered: int = 0
    messages_failed: int = 0
    by_tenant: dict[str, int] = field(default_factory=dict)
    last_message_at: Optional[datetime] = None


@dataclass
class SSEConnection:
    """Represents an active SSE connection.

    Attributes:
        id: Unique connection identifier
        tenant_id: Tenant this connection belongs to
        user_id: User ID if authenticated
        queue: Message queue for this connection
        created_at: When the connection was established
        last_message_at: Last message sent on this connection
        subscriptions: Event types this connection is subscribed to
    """

    id: str
    tenant_id: str
    queue: asyncio.Queue
    user_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_message_at: Optional[datetime] = None
    subscriptions: list[str] = field(default_factory=list)

    def is_subscribed_to(self, event_type: str) -> bool:
        """Check if this connection is subscribed to an event type."""
        if not self.subscriptions:
            return True  # No filter = all events

        for sub in self.subscriptions:
            if sub == "*":
                return True
            if sub.endswith(".*") and event_type.startswith(sub[:-2]):
                return True
            if sub == event_type:
                return True

        return False


class SSEAdapter:
    """Server-Sent Events adapter for real-time notifications.

    This adapter manages SSE connections and delivers notifications
    to connected web clients in real-time.

    Example:
        adapter = SSEAdapter(SSEConfig(
            heartbeat_interval=30,
            max_connections_per_tenant=100,
        ))

        # In FastAPI route handler:
        @app.get("/events")
        async def sse_endpoint(request: Request):
            tenant_id = get_tenant_from_request(request)
            async def event_generator():
                async for event in adapter.subscribe(tenant_id):
                    yield event
            return EventSourceResponse(event_generator())

        # Sending notifications
        result = await adapter.send(
            target=NotificationTarget(
                tenant_id="org-123",
                channel=ChannelType.SSE,
            ),
            payload=NotificationPayload(
                event_type="credential.revoked",
                title="Credential Revoked",
                body="A credential has been revoked.",
            ),
        )
    """

    def __init__(self, config: Optional[SSEConfig] = None):
        """Initialize the SSE adapter.

        Args:
            config: SSE configuration
        """
        self._config = config or SSEConfig()
        self._metrics = SSEMetrics()
        self._connections: dict[str, SSEConnection] = {}
        self._by_tenant: dict[str, set[str]] = defaultdict(set)
        self._by_user: dict[str, set[str]] = defaultdict(set)
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self) -> None:
        """Start the SSE adapter and heartbeat task."""
        if self._running:
            return

        self._running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

        logger.info("SSE adapter started")

    async def stop(self) -> None:
        """Stop the SSE adapter."""
        self._running = False

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        # Close all connections
        for conn_id in list(self._connections.keys()):
            await self.disconnect(conn_id)

        logger.info("SSE adapter stopped")

    async def connect(
        self,
        tenant_id: str,
        user_id: Optional[str] = None,
        subscriptions: Optional[list[str]] = None,
    ) -> SSEConnection:
        """Create a new SSE connection.

        Args:
            tenant_id: Tenant ID for this connection
            user_id: Optional user ID
            subscriptions: Optional list of event types to subscribe to

        Returns:
            SSEConnection object

        Raises:
            ValueError: If connection limits exceeded
        """
        import uuid

        # Check limits
        if len(self._connections) >= self._config.max_total_connections:
            raise ValueError("Maximum total connections exceeded")

        tenant_connections = len(self._by_tenant.get(tenant_id, set()))
        if tenant_connections >= self._config.max_connections_per_tenant:
            raise ValueError(f"Maximum connections for tenant {tenant_id} exceeded")

        # Create connection
        conn_id = str(uuid.uuid4())
        connection = SSEConnection(
            id=conn_id,
            tenant_id=tenant_id,
            user_id=user_id,
            queue=asyncio.Queue(maxsize=self._config.buffer_size),
            subscriptions=subscriptions or [],
        )

        self._connections[conn_id] = connection
        self._by_tenant[tenant_id].add(conn_id)
        if user_id:
            self._by_user[user_id].add(conn_id)

        self._metrics.connections_active = len(self._connections)
        self._metrics.connections_total += 1

        if tenant_id not in self._metrics.by_tenant:
            self._metrics.by_tenant[tenant_id] = 0
        self._metrics.by_tenant[tenant_id] += 1

        logger.debug(
            "SSE connection created",
            extra={
                "connection_id": conn_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
            },
        )

        return connection

    async def disconnect(self, connection_id: str) -> None:
        """Close an SSE connection.

        Args:
            connection_id: ID of the connection to close
        """
        connection = self._connections.pop(connection_id, None)
        if not connection:
            return

        self._by_tenant[connection.tenant_id].discard(connection_id)
        if connection.user_id:
            self._by_user[connection.user_id].discard(connection_id)

        # Send close signal to queue
        try:
            connection.queue.put_nowait(None)
        except asyncio.QueueFull:
            pass

        self._metrics.connections_active = len(self._connections)

        logger.debug(
            "SSE connection closed",
            extra={"connection_id": connection_id},
        )

    async def subscribe(
        self,
        tenant_id: str,
        user_id: Optional[str] = None,
        subscriptions: Optional[list[str]] = None,
    ) -> AsyncIterator[str]:
        """Subscribe to SSE events.

        This is an async generator that yields SSE-formatted events.
        Use this in a FastAPI EventSourceResponse.

        Args:
            tenant_id: Tenant ID
            user_id: Optional user ID
            subscriptions: Optional event type filter

        Yields:
            SSE-formatted event strings
        """
        connection = await self.connect(tenant_id, user_id, subscriptions)

        try:
            while self._running:
                try:
                    message = await asyncio.wait_for(
                        connection.queue.get(),
                        timeout=self._config.heartbeat_interval,
                    )

                    if message is None:
                        # Connection closed
                        break

                    yield message

                except asyncio.TimeoutError:
                    # Send heartbeat
                    yield ": heartbeat\n\n"

        finally:
            await self.disconnect(connection.id)

    async def send(
        self,
        target: NotificationTarget,
        payload: NotificationPayload,
    ) -> DeliveryResult:
        """Send a notification to SSE connections.

        Args:
            target: The notification target
            payload: The notification payload

        Returns:
            DeliveryResult indicating success/failure
        """
        tenant_id = target.tenant_id
        connection_ids = self._by_tenant.get(tenant_id, set())

        if not connection_ids:
            return DeliveryResult(
                target=target,
                status=DeliveryStatus.DELIVERED,
                delivered_at=datetime.utcnow(),
                provider_response={"connections": 0},
            )

        # Format SSE event
        sse_data = payload.to_sse_event()
        event_str = self._format_sse_event(sse_data)

        # Send to all matching connections
        delivered = 0
        failed = 0

        for conn_id in list(connection_ids):
            connection = self._connections.get(conn_id)
            if not connection:
                continue

            # Check subscription filter
            if not connection.is_subscribed_to(payload.event_type):
                continue

            # Check user filter
            if target.user_id and connection.user_id != target.user_id:
                continue

            try:
                connection.queue.put_nowait(event_str)
                connection.last_message_at = datetime.utcnow()
                delivered += 1
            except asyncio.QueueFull:
                failed += 1
                logger.warning(f"SSE queue full for connection {conn_id}")

        self._metrics.messages_sent += 1
        self._metrics.messages_delivered += delivered
        self._metrics.messages_failed += failed
        self._metrics.last_message_at = datetime.utcnow()

        return DeliveryResult(
            target=target,
            status=DeliveryStatus.DELIVERED if delivered > 0 else DeliveryStatus.FAILED,
            delivered_at=datetime.utcnow(),
            provider_response={
                "connections": delivered,
                "failed": failed,
            },
        )

    async def send_batch(
        self,
        targets: list[NotificationTarget],
        payload: NotificationPayload,
    ) -> BatchDeliveryResult:
        """Send notification to multiple targets.

        For SSE, this sends to all connections matching the targets.

        Args:
            targets: List of notification targets
            payload: The notification payload

        Returns:
            BatchDeliveryResult with delivery results
        """
        if not targets:
            return BatchDeliveryResult(total=0, delivered=0, failed=0, pending=0)

        results = []
        delivered = 0
        failed = 0

        for target in targets:
            result = await self.send(target, payload)
            results.append(result)
            if result.success:
                delivered += 1
            else:
                failed += 1

        return BatchDeliveryResult(
            total=len(targets),
            delivered=delivered,
            failed=failed,
            pending=0,
            results=results,
        )

    async def broadcast(
        self,
        tenant_id: str,
        payload: NotificationPayload,
    ) -> int:
        """Broadcast a notification to all connections for a tenant.

        Args:
            tenant_id: Tenant to broadcast to
            payload: The notification payload

        Returns:
            Number of connections that received the message
        """
        target = NotificationTarget(
            tenant_id=tenant_id,
            channel=None,  # Not used for SSE
        )
        result = await self.send(target, payload)
        return result.provider_response.get("connections", 0) if result.provider_response else 0

    def _format_sse_event(self, data: dict[str, Any]) -> str:
        """Format data as an SSE event string.

        Args:
            data: Event data with 'event' and 'data' keys

        Returns:
            SSE-formatted string
        """
        lines = []

        if "event" in data:
            lines.append(f"event: {data['event']}")

        event_data = data.get("data", data)
        json_data = json.dumps(event_data)
        lines.append(f"data: {json_data}")

        lines.append("")  # Empty line to end event
        lines.append("")

        return "\n".join(lines)

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeat messages to all connections."""
        while self._running:
            await asyncio.sleep(self._config.heartbeat_interval)

            heartbeat = ": heartbeat\n\n"
            now = datetime.utcnow()

            for conn_id, connection in list(self._connections.items()):
                try:
                    connection.queue.put_nowait(heartbeat)
                except asyncio.QueueFull:
                    # Queue full, connection might be slow
                    pass

    async def health_check(self) -> dict[str, Any]:
        """Check adapter health.

        Returns:
            Dictionary with health status and metrics
        """
        return {
            "status": "healthy" if self._running else "stopped",
            "running": self._running,
            "config": {
                "heartbeat_interval": self._config.heartbeat_interval,
                "max_connections_per_tenant": self._config.max_connections_per_tenant,
                "max_total_connections": self._config.max_total_connections,
            },
            "metrics": {
                "connections_active": self._metrics.connections_active,
                "connections_total": self._metrics.connections_total,
                "messages_sent": self._metrics.messages_sent,
                "messages_delivered": self._metrics.messages_delivered,
                "messages_failed": self._metrics.messages_failed,
                "by_tenant": dict(self._metrics.by_tenant),
            },
            "last_message_at": (
                self._metrics.last_message_at.isoformat()
                if self._metrics.last_message_at
                else None
            ),
        }

    @property
    def metrics(self) -> SSEMetrics:
        """Get adapter metrics."""
        return self._metrics

    @property
    def active_connections(self) -> int:
        """Get number of active connections."""
        return len(self._connections)
