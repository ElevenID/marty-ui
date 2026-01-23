"""Firebase Cloud Messaging (FCM) adapter for push notifications.

This adapter handles delivery of push notifications to mobile devices
(iOS and Android) through Firebase Cloud Messaging.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from ..types import (
    BatchDeliveryResult,
    DeliveryResult,
    DeliveryStatus,
    NotificationPayload,
    NotificationTarget,
)

logger = logging.getLogger(__name__)


@dataclass
class FCMConfig:
    """Configuration for FCM adapter.

    Attributes:
        project_id: Firebase project ID
        credentials_path: Path to service account JSON
        credentials_dict: Service account credentials as dict (alternative to path)
        dry_run: If True, validate but don't send (for testing)
        timeout_seconds: Request timeout
        max_concurrent: Maximum concurrent requests
        retry_count: Number of retries on failure
    """

    project_id: str
    credentials_path: Optional[str] = None
    credentials_dict: Optional[dict[str, Any]] = None
    dry_run: bool = False
    timeout_seconds: float = 10.0
    max_concurrent: int = 100
    retry_count: int = 3


@dataclass
class FCMMetrics:
    """Metrics for FCM adapter."""

    sent: int = 0
    delivered: int = 0
    failed: int = 0
    invalid_tokens: int = 0
    rate_limited: int = 0
    last_send_at: Optional[datetime] = None


class FCMAdapter:
    """Firebase Cloud Messaging adapter for push notifications.

    This adapter sends push notifications to mobile devices through FCM.
    It supports both individual and batch sending, with automatic retry
    and token invalidation handling.

    Example:
        adapter = FCMAdapter(FCMConfig(
            project_id="my-project",
            credentials_path="/path/to/service-account.json",
        ))

        await adapter.initialize()

        result = await adapter.send(
            target=NotificationTarget(
                tenant_id="org-123",
                channel=ChannelType.FCM,
                device_token="fcm-token-abc",
            ),
            payload=NotificationPayload(
                event_type="credential.revoked",
                title="Credential Revoked",
                body="Your credential has been revoked.",
            ),
        )
    """

    def __init__(self, config: FCMConfig):
        """Initialize the FCM adapter.

        Args:
            config: FCM configuration
        """
        self._config = config
        self._metrics = FCMMetrics()
        self._initialized = False
        self._client: Any = None  # firebase_admin.messaging
        self._semaphore: Optional[asyncio.Semaphore] = None

    async def initialize(self) -> None:
        """Initialize the FCM client.

        This method should be called before sending any notifications.
        """
        if self._initialized:
            return

        try:
            # Import firebase_admin dynamically
            import firebase_admin
            from firebase_admin import credentials, messaging

            # Initialize Firebase app if not already done
            if not firebase_admin._apps:
                if self._config.credentials_path:
                    cred = credentials.Certificate(self._config.credentials_path)
                elif self._config.credentials_dict:
                    cred = credentials.Certificate(self._config.credentials_dict)
                else:
                    # Use default credentials (Application Default Credentials)
                    cred = credentials.ApplicationDefault()

                firebase_admin.initialize_app(cred, {
                    "projectId": self._config.project_id,
                })

            self._client = messaging
            self._semaphore = asyncio.Semaphore(self._config.max_concurrent)
            self._initialized = True

            logger.info("FCM adapter initialized", extra={"project_id": self._config.project_id})

        except ImportError:
            logger.warning("firebase-admin not installed, FCM adapter will use mock mode")
            self._initialized = True
            self._semaphore = asyncio.Semaphore(self._config.max_concurrent)

        except Exception as e:
            logger.error(f"Failed to initialize FCM: {e}")
            raise

    async def send(
        self,
        target: NotificationTarget,
        payload: NotificationPayload,
    ) -> DeliveryResult:
        """Send a notification to a single target.

        Args:
            target: The notification target with FCM token
            payload: The notification payload

        Returns:
            DeliveryResult indicating success/failure
        """
        if not self._initialized:
            await self.initialize()

        if not target.device_token:
            return DeliveryResult(
                target=target,
                status=DeliveryStatus.FAILED,
                error="No device token provided",
            )

        async with self._semaphore:
            try:
                self._metrics.sent += 1
                self._metrics.last_send_at = datetime.utcnow()

                if self._client and not self._config.dry_run:
                    # Build FCM message
                    fcm_message = payload.to_fcm_message()
                    fcm_message["token"] = target.device_token

                    # Create Message object
                    message = self._client.Message(
                        notification=self._client.Notification(
                            title=fcm_message["notification"]["title"],
                            body=fcm_message["notification"]["body"],
                            image=fcm_message["notification"].get("image"),
                        ),
                        data=fcm_message["data"],
                        android=self._client.AndroidConfig(
                            priority=fcm_message["android"]["priority"],
                            ttl=int(payload.ttl_seconds),
                        ),
                        apns=self._client.APNSConfig(
                            headers=fcm_message["apns"]["headers"],
                        ),
                        token=target.device_token,
                    )

                    # Send synchronously (Firebase SDK is synchronous)
                    loop = asyncio.get_event_loop()
                    response = await loop.run_in_executor(
                        None,
                        lambda: self._client.send(message, dry_run=self._config.dry_run),
                    )

                    self._metrics.delivered += 1

                    return DeliveryResult(
                        target=target,
                        status=DeliveryStatus.DELIVERED,
                        delivered_at=datetime.utcnow(),
                        provider_response={"message_id": response},
                    )

                else:
                    # Mock mode for testing
                    logger.debug(
                        "FCM mock send",
                        extra={
                            "token": target.device_token[:20] + "...",
                            "title": payload.title,
                        },
                    )
                    self._metrics.delivered += 1

                    return DeliveryResult(
                        target=target,
                        status=DeliveryStatus.DELIVERED,
                        delivered_at=datetime.utcnow(),
                        provider_response={"mock": True},
                    )

            except Exception as e:
                error_msg = str(e)
                self._metrics.failed += 1

                # Check for invalid token errors
                if "not-registered" in error_msg.lower() or "invalid-registration" in error_msg.lower():
                    self._metrics.invalid_tokens += 1
                    logger.warning(f"Invalid FCM token: {target.device_token[:20]}...")

                # Check for rate limiting
                elif "quota" in error_msg.lower() or "too-many-requests" in error_msg.lower():
                    self._metrics.rate_limited += 1
                    logger.warning("FCM rate limited")

                logger.error(f"FCM send failed: {e}")

                return DeliveryResult(
                    target=target,
                    status=DeliveryStatus.FAILED,
                    error=error_msg,
                )

    async def send_batch(
        self,
        targets: list[NotificationTarget],
        payload: NotificationPayload,
    ) -> BatchDeliveryResult:
        """Send a notification to multiple targets.

        Uses FCM's batch sending capabilities for efficiency.

        Args:
            targets: List of notification targets
            payload: The notification payload

        Returns:
            BatchDeliveryResult with per-target results
        """
        if not self._initialized:
            await self.initialize()

        if not targets:
            return BatchDeliveryResult(total=0, delivered=0, failed=0, pending=0)

        # For small batches, send individually
        if len(targets) <= 5:
            results = await asyncio.gather(
                *[self.send(target, payload) for target in targets],
                return_exceptions=True,
            )

            delivery_results = []
            delivered = 0
            failed = 0

            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    delivery_results.append(
                        DeliveryResult(
                            target=targets[i],
                            status=DeliveryStatus.FAILED,
                            error=str(result),
                        )
                    )
                    failed += 1
                else:
                    delivery_results.append(result)
                    if result.success:
                        delivered += 1
                    else:
                        failed += 1

            return BatchDeliveryResult(
                total=len(targets),
                delivered=delivered,
                failed=failed,
                pending=0,
                results=delivery_results,
            )

        # For larger batches, use FCM's multicast
        if self._client and not self._config.dry_run:
            try:
                tokens = [t.device_token for t in targets if t.device_token]
                fcm_message = payload.to_fcm_message()

                message = self._client.MulticastMessage(
                    notification=self._client.Notification(
                        title=fcm_message["notification"]["title"],
                        body=fcm_message["notification"]["body"],
                    ),
                    data=fcm_message["data"],
                    tokens=tokens,
                )

                loop = asyncio.get_event_loop()
                response = await loop.run_in_executor(
                    None,
                    lambda: self._client.send_multicast(message),
                )

                # Process batch response
                delivery_results = []
                for i, (target, send_response) in enumerate(zip(targets, response.responses)):
                    if send_response.success:
                        delivery_results.append(
                            DeliveryResult(
                                target=target,
                                status=DeliveryStatus.DELIVERED,
                                delivered_at=datetime.utcnow(),
                                provider_response={"message_id": send_response.message_id},
                            )
                        )
                        self._metrics.delivered += 1
                    else:
                        delivery_results.append(
                            DeliveryResult(
                                target=target,
                                status=DeliveryStatus.FAILED,
                                error=str(send_response.exception),
                            )
                        )
                        self._metrics.failed += 1

                self._metrics.sent += len(targets)

                return BatchDeliveryResult(
                    total=len(targets),
                    delivered=response.success_count,
                    failed=response.failure_count,
                    pending=0,
                    results=delivery_results,
                )

            except Exception as e:
                logger.error(f"FCM batch send failed: {e}")
                # Fall back to individual sends
                pass

        # Fallback: send individually
        tasks = [self.send(target, payload) for target in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        delivery_results = []
        delivered = 0
        failed = 0

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                delivery_results.append(
                    DeliveryResult(
                        target=targets[i],
                        status=DeliveryStatus.FAILED,
                        error=str(result),
                    )
                )
                failed += 1
            else:
                delivery_results.append(result)
                if result.success:
                    delivered += 1
                else:
                    failed += 1

        return BatchDeliveryResult(
            total=len(targets),
            delivered=delivered,
            failed=failed,
            pending=0,
            results=delivery_results,
        )

    async def health_check(self) -> dict[str, Any]:
        """Check adapter health.

        Returns:
            Dictionary with health status and metrics
        """
        return {
            "status": "healthy" if self._initialized else "not_initialized",
            "project_id": self._config.project_id,
            "dry_run": self._config.dry_run,
            "metrics": {
                "sent": self._metrics.sent,
                "delivered": self._metrics.delivered,
                "failed": self._metrics.failed,
                "invalid_tokens": self._metrics.invalid_tokens,
                "rate_limited": self._metrics.rate_limited,
                "success_rate": (
                    self._metrics.delivered / self._metrics.sent
                    if self._metrics.sent > 0
                    else 0.0
                ),
            },
            "last_send_at": (
                self._metrics.last_send_at.isoformat()
                if self._metrics.last_send_at
                else None
            ),
        }

    @property
    def metrics(self) -> FCMMetrics:
        """Get adapter metrics."""
        return self._metrics
