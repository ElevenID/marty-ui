"""Webhook adapter for HTTP callback notifications.

This adapter handles delivery of notifications to vendor webhook endpoints
with HMAC signature verification and retry logic.
"""

import asyncio
import hashlib
import hmac
import logging
import time
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
class WebhookConfig:
    """Configuration for webhook adapter.

    Attributes:
        timeout_seconds: Request timeout
        max_retries: Maximum retry attempts
        retry_delay_seconds: Initial retry delay
        retry_backoff_factor: Exponential backoff multiplier
        max_concurrent: Maximum concurrent requests
        user_agent: User-Agent header value
        signature_header: Header name for HMAC signature
        timestamp_header: Header name for request timestamp
        verify_ssl: Whether to verify SSL certificates
    """

    timeout_seconds: float = 30.0
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    retry_backoff_factor: float = 2.0
    max_concurrent: int = 50
    user_agent: str = "Marty-Webhook/1.0"
    signature_header: str = "X-Marty-Signature"
    timestamp_header: str = "X-Marty-Timestamp"
    verify_ssl: bool = True


@dataclass
class WebhookMetrics:
    """Metrics for webhook adapter."""

    sent: int = 0
    delivered: int = 0
    failed: int = 0
    retried: int = 0
    timed_out: int = 0
    last_send_at: Optional[datetime] = None
    by_status_code: dict[int, int] = field(default_factory=dict)


class WebhookAdapter:
    """Webhook adapter for HTTP callback notifications.

    This adapter sends notifications to registered webhook endpoints.
    It supports HMAC signature verification, automatic retries with
    exponential backoff, and concurrent delivery.

    Webhook Payload Format:
        {
            "event_type": "credential.revoked",
            "timestamp": "2025-12-15T10:30:00Z",
            "tenant_id": "org-123",
            "correlation_id": "evt-456",
            "data": {
                "title": "Credential Revoked",
                "body": "Your credential has been revoked.",
                ...
            }
        }

    Signature Verification:
        The adapter generates an HMAC-SHA256 signature using the webhook
        secret. Vendors should verify this signature to ensure authenticity.

        Signature format: sha256=<hex_digest>
        Signed data: <timestamp>.<payload_json>

    Example:
        adapter = WebhookAdapter(WebhookConfig(
            timeout_seconds=30,
            max_retries=3,
        ))

        result = await adapter.send(
            target=NotificationTarget(
                tenant_id="org-123",
                channel=ChannelType.WEBHOOK,
                webhook_url="https://vendor.example.com/webhooks",
                webhook_secret="secret-key",
            ),
            payload=NotificationPayload(
                event_type="credential.revoked",
                title="Credential Revoked",
                body="Your credential has been revoked.",
            ),
        )
    """

    def __init__(self, config: Optional[WebhookConfig] = None):
        """Initialize the webhook adapter.

        Args:
            config: Webhook configuration
        """
        self._config = config or WebhookConfig()
        self._metrics = WebhookMetrics()
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._session: Any = None  # aiohttp.ClientSession

    async def initialize(self) -> None:
        """Initialize the HTTP client session."""
        if self._session is not None:
            return

        try:
            import aiohttp

            connector = aiohttp.TCPConnector(
                limit=self._config.max_concurrent,
                ssl=self._config.verify_ssl,
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=self._config.timeout_seconds),
            )
            self._semaphore = asyncio.Semaphore(self._config.max_concurrent)

            logger.info("Webhook adapter initialized")

        except ImportError:
            logger.warning("aiohttp not installed, webhook adapter will use mock mode")
            self._semaphore = asyncio.Semaphore(self._config.max_concurrent)

    async def close(self) -> None:
        """Close the HTTP client session."""
        if self._session:
            await self._session.close()
            self._session = None

    async def send(
        self,
        target: NotificationTarget,
        payload: NotificationPayload,
    ) -> DeliveryResult:
        """Send a notification to a webhook endpoint.

        Args:
            target: The notification target with webhook URL
            payload: The notification payload

        Returns:
            DeliveryResult indicating success/failure
        """
        if self._semaphore is None:
            await self.initialize()

        if not target.webhook_url:
            return DeliveryResult(
                target=target,
                status=DeliveryStatus.FAILED,
                error="No webhook URL provided",
            )

        async with self._semaphore:
            return await self._send_with_retry(target, payload)

    async def _send_with_retry(
        self,
        target: NotificationTarget,
        payload: NotificationPayload,
    ) -> DeliveryResult:
        """Send with automatic retry on failure.

        Args:
            target: The notification target
            payload: The notification payload

        Returns:
            DeliveryResult from final attempt
        """
        last_error = None
        retry_delay = self._config.retry_delay_seconds

        for attempt in range(self._config.max_retries + 1):
            try:
                result = await self._do_send(target, payload)

                if result.success:
                    return result

                # Check if we should retry based on status code
                status_code = result.provider_response.get("status_code", 0) if result.provider_response else 0

                if status_code in (429, 500, 502, 503, 504):
                    # Retryable errors
                    last_error = result.error
                    self._metrics.retried += 1
                else:
                    # Non-retryable error
                    return result

            except asyncio.TimeoutError:
                last_error = "Request timed out"
                self._metrics.timed_out += 1
                self._metrics.retried += 1

            except Exception as e:
                last_error = str(e)
                self._metrics.retried += 1

            # Wait before retry (except on last attempt)
            if attempt < self._config.max_retries:
                await asyncio.sleep(retry_delay)
                retry_delay *= self._config.retry_backoff_factor

        # All retries exhausted
        self._metrics.failed += 1

        return DeliveryResult(
            target=target,
            status=DeliveryStatus.FAILED,
            error=f"Max retries exceeded: {last_error}",
            retry_count=self._config.max_retries,
        )

    async def _do_send(
        self,
        target: NotificationTarget,
        payload: NotificationPayload,
    ) -> DeliveryResult:
        """Perform the actual HTTP request.

        Args:
            target: The notification target
            payload: The notification payload

        Returns:
            DeliveryResult from this attempt
        """
        import json

        self._metrics.sent += 1
        self._metrics.last_send_at = datetime.utcnow()

        # Build webhook payload
        webhook_payload = payload.to_webhook_payload()
        payload_json = json.dumps(webhook_payload, separators=(",", ":"))

        # Generate timestamp and signature
        timestamp = str(int(time.time()))
        signature = self._generate_signature(
            timestamp,
            payload_json,
            target.webhook_secret or "",
        )

        headers = {
            "Content-Type": "application/json",
            "User-Agent": self._config.user_agent,
            self._config.timestamp_header: timestamp,
            self._config.signature_header: signature,
        }

        if self._session:
            try:
                async with self._session.post(
                    target.webhook_url,
                    data=payload_json,
                    headers=headers,
                ) as response:
                    status_code = response.status
                    self._update_status_metrics(status_code)

                    if 200 <= status_code < 300:
                        self._metrics.delivered += 1

                        return DeliveryResult(
                            target=target,
                            status=DeliveryStatus.DELIVERED,
                            delivered_at=datetime.utcnow(),
                            provider_response={
                                "status_code": status_code,
                                "response_text": await response.text(),
                            },
                        )
                    else:
                        return DeliveryResult(
                            target=target,
                            status=DeliveryStatus.FAILED,
                            error=f"HTTP {status_code}",
                            provider_response={
                                "status_code": status_code,
                                "response_text": await response.text(),
                            },
                        )

            except Exception as e:
                return DeliveryResult(
                    target=target,
                    status=DeliveryStatus.FAILED,
                    error=str(e),
                )

        else:
            # Mock mode for testing
            logger.debug(
                "Webhook mock send",
                extra={
                    "url": target.webhook_url,
                    "event_type": payload.event_type,
                },
            )
            self._metrics.delivered += 1

            return DeliveryResult(
                target=target,
                status=DeliveryStatus.DELIVERED,
                delivered_at=datetime.utcnow(),
                provider_response={"mock": True, "status_code": 200},
            )

    def _generate_signature(
        self,
        timestamp: str,
        payload: str,
        secret: str,
    ) -> str:
        """Generate HMAC-SHA256 signature for the payload.

        Args:
            timestamp: Request timestamp
            payload: JSON payload string
            secret: Webhook secret

        Returns:
            Signature in format: sha256=<hex_digest>
        """
        if not secret:
            return ""

        signed_payload = f"{timestamp}.{payload}"
        signature = hmac.new(
            secret.encode("utf-8"),
            signed_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return f"sha256={signature}"

    def _update_status_metrics(self, status_code: int) -> None:
        """Update metrics for status code.

        Args:
            status_code: HTTP status code
        """
        if status_code not in self._metrics.by_status_code:
            self._metrics.by_status_code[status_code] = 0
        self._metrics.by_status_code[status_code] += 1

    async def send_batch(
        self,
        targets: list[NotificationTarget],
        payload: NotificationPayload,
    ) -> BatchDeliveryResult:
        """Send a notification to multiple webhook endpoints.

        Args:
            targets: List of notification targets
            payload: The notification payload

        Returns:
            BatchDeliveryResult with per-target results
        """
        if not targets:
            return BatchDeliveryResult(total=0, delivered=0, failed=0, pending=0)

        # Send to all targets concurrently
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
            "status": "healthy" if self._session or self._semaphore else "not_initialized",
            "config": {
                "timeout_seconds": self._config.timeout_seconds,
                "max_retries": self._config.max_retries,
                "max_concurrent": self._config.max_concurrent,
            },
            "metrics": {
                "sent": self._metrics.sent,
                "delivered": self._metrics.delivered,
                "failed": self._metrics.failed,
                "retried": self._metrics.retried,
                "timed_out": self._metrics.timed_out,
                "success_rate": (
                    self._metrics.delivered / self._metrics.sent
                    if self._metrics.sent > 0
                    else 0.0
                ),
                "by_status_code": self._metrics.by_status_code,
            },
            "last_send_at": (
                self._metrics.last_send_at.isoformat()
                if self._metrics.last_send_at
                else None
            ),
        }

    @property
    def metrics(self) -> WebhookMetrics:
        """Get adapter metrics."""
        return self._metrics


def verify_webhook_signature(
    payload: str,
    signature: str,
    secret: str,
    timestamp: str,
    max_age_seconds: int = 300,
) -> bool:
    """Verify a webhook signature.

    This function can be used by webhook receivers to verify
    that a request came from Marty.

    Args:
        payload: The raw JSON payload string
        signature: The signature from X-Marty-Signature header
        secret: The webhook secret
        timestamp: The timestamp from X-Marty-Timestamp header
        max_age_seconds: Maximum age of the request in seconds

    Returns:
        True if signature is valid and request is not too old
    """
    # Check timestamp freshness
    try:
        request_time = int(timestamp)
        current_time = int(time.time())
        if abs(current_time - request_time) > max_age_seconds:
            return False
    except (ValueError, TypeError):
        return False

    # Verify signature
    if not signature.startswith("sha256="):
        return False

    expected_sig = signature[7:]  # Remove "sha256=" prefix

    signed_payload = f"{timestamp}.{payload}"
    computed_sig = hmac.new(
        secret.encode("utf-8"),
        signed_payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected_sig, computed_sig)
