"""Email adapter for email notifications.

This adapter handles delivery of email notifications through
email service providers like SendGrid or Amazon SES.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from ..types import (
    BatchDeliveryResult,
    DeliveryResult,
    DeliveryStatus,
    NotificationPayload,
    NotificationTarget,
)

logger = logging.getLogger(__name__)


class EmailProvider(str, Enum):
    """Supported email providers."""

    SENDGRID = "sendgrid"
    SES = "ses"
    SMTP = "smtp"
    MOCK = "mock"


@dataclass
class EmailConfig:
    """Configuration for email adapter.

    Attributes:
        provider: Email provider to use
        api_key: API key for SendGrid
        aws_region: AWS region for SES
        smtp_host: SMTP server host
        smtp_port: SMTP server port
        smtp_username: SMTP username
        smtp_password: SMTP password
        smtp_use_tls: Whether to use TLS
        from_email: Default from email address
        from_name: Default from name
        reply_to: Reply-to email address
        max_concurrent: Maximum concurrent requests
        template_dir: Directory containing email templates
    """

    provider: EmailProvider = EmailProvider.MOCK
    api_key: Optional[str] = None
    aws_region: Optional[str] = None
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True
    from_email: str = "noreply@marty.example.com"
    from_name: str = "Marty Notifications"
    reply_to: Optional[str] = None
    max_concurrent: int = 20
    template_dir: Optional[str] = None


@dataclass
class EmailMetrics:
    """Metrics for email adapter."""

    sent: int = 0
    delivered: int = 0
    failed: int = 0
    bounced: int = 0
    last_send_at: Optional[datetime] = None


@dataclass
class EmailMessage:
    """An email message to be sent."""

    to: str
    subject: str
    body_text: str
    body_html: Optional[str] = None
    from_email: Optional[str] = None
    from_name: Optional[str] = None
    reply_to: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)


class EmailAdapter:
    """Email adapter for email notifications.

    This adapter sends email notifications through various providers
    including SendGrid, Amazon SES, and SMTP.

    Example:
        adapter = EmailAdapter(EmailConfig(
            provider=EmailProvider.SENDGRID,
            api_key="SG.xxxxx",
            from_email="notifications@example.com",
        ))

        await adapter.initialize()

        result = await adapter.send(
            target=NotificationTarget(
                tenant_id="org-123",
                channel=ChannelType.EMAIL,
                email="user@example.com",
            ),
            payload=NotificationPayload(
                event_type="payment.failed",
                title="Payment Failed",
                body="Your payment could not be processed.",
            ),
        )
    """

    def __init__(self, config: Optional[EmailConfig] = None):
        """Initialize the email adapter.

        Args:
            config: Email configuration
        """
        self._config = config or EmailConfig()
        self._metrics = EmailMetrics()
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._client: Any = None

    async def initialize(self) -> None:
        """Initialize the email client."""
        if self._semaphore is not None:
            return

        self._semaphore = asyncio.Semaphore(self._config.max_concurrent)

        if self._config.provider == EmailProvider.SENDGRID:
            await self._init_sendgrid()
        elif self._config.provider == EmailProvider.SES:
            await self._init_ses()
        elif self._config.provider == EmailProvider.SMTP:
            await self._init_smtp()

        logger.info(f"Email adapter initialized with provider: {self._config.provider.value}")

    async def _init_sendgrid(self) -> None:
        """Initialize SendGrid client."""
        try:
            from sendgrid import SendGridAPIClient

            self._client = SendGridAPIClient(self._config.api_key)
        except ImportError:
            logger.warning("sendgrid not installed, falling back to mock mode")
            self._config.provider = EmailProvider.MOCK

    async def _init_ses(self) -> None:
        """Initialize AWS SES client."""
        try:
            import boto3

            self._client = boto3.client(
                "ses",
                region_name=self._config.aws_region,
            )
        except ImportError:
            logger.warning("boto3 not installed, falling back to mock mode")
            self._config.provider = EmailProvider.MOCK

    async def _init_smtp(self) -> None:
        """Initialize SMTP connection parameters."""
        # SMTP doesn't need persistent connection
        pass

    async def send(
        self,
        target: NotificationTarget,
        payload: NotificationPayload,
    ) -> DeliveryResult:
        """Send an email notification.

        Args:
            target: The notification target with email address
            payload: The notification payload

        Returns:
            DeliveryResult indicating success/failure
        """
        if self._semaphore is None:
            await self.initialize()

        if not target.email:
            return DeliveryResult(
                target=target,
                status=DeliveryStatus.FAILED,
                error="No email address provided",
            )

        async with self._semaphore:
            # Convert payload to email
            email_content = payload.to_email_content()

            message = EmailMessage(
                to=target.email,
                subject=email_content["subject"],
                body_text=email_content["body_text"],
                body_html=email_content.get("body_html"),
            )

            return await self._send_email(target, message)

    async def _send_email(
        self,
        target: NotificationTarget,
        message: EmailMessage,
    ) -> DeliveryResult:
        """Send an email through the configured provider.

        Args:
            target: The notification target
            message: The email message

        Returns:
            DeliveryResult from the send attempt
        """
        self._metrics.sent += 1
        self._metrics.last_send_at = datetime.utcnow()

        try:
            if self._config.provider == EmailProvider.SENDGRID:
                return await self._send_sendgrid(target, message)
            elif self._config.provider == EmailProvider.SES:
                return await self._send_ses(target, message)
            elif self._config.provider == EmailProvider.SMTP:
                return await self._send_smtp(target, message)
            else:
                return await self._send_mock(target, message)

        except Exception as e:
            self._metrics.failed += 1
            logger.error(f"Email send failed: {e}")

            return DeliveryResult(
                target=target,
                status=DeliveryStatus.FAILED,
                error=str(e),
            )

    async def _send_sendgrid(
        self,
        target: NotificationTarget,
        message: EmailMessage,
    ) -> DeliveryResult:
        """Send email via SendGrid.

        Args:
            target: The notification target
            message: The email message

        Returns:
            DeliveryResult from SendGrid
        """
        from sendgrid.helpers.mail import Content, Email, Mail, To

        mail = Mail(
            from_email=Email(
                message.from_email or self._config.from_email,
                message.from_name or self._config.from_name,
            ),
            to_emails=To(message.to),
            subject=message.subject,
            plain_text_content=Content("text/plain", message.body_text),
        )

        if message.body_html:
            mail.add_content(Content("text/html", message.body_html))

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._client.send(mail),
        )

        if response.status_code in (200, 201, 202):
            self._metrics.delivered += 1
            return DeliveryResult(
                target=target,
                status=DeliveryStatus.DELIVERED,
                delivered_at=datetime.utcnow(),
                provider_response={
                    "status_code": response.status_code,
                    "message_id": response.headers.get("X-Message-Id"),
                },
            )
        else:
            self._metrics.failed += 1
            return DeliveryResult(
                target=target,
                status=DeliveryStatus.FAILED,
                error=f"SendGrid returned {response.status_code}",
                provider_response={"status_code": response.status_code},
            )

    async def _send_ses(
        self,
        target: NotificationTarget,
        message: EmailMessage,
    ) -> DeliveryResult:
        """Send email via AWS SES.

        Args:
            target: The notification target
            message: The email message

        Returns:
            DeliveryResult from SES
        """
        body = {"Text": {"Data": message.body_text}}
        if message.body_html:
            body["Html"] = {"Data": message.body_html}

        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self._client.send_email(
                Source=f"{self._config.from_name} <{self._config.from_email}>",
                Destination={"ToAddresses": [message.to]},
                Message={
                    "Subject": {"Data": message.subject},
                    "Body": body,
                },
            ),
        )

        message_id = response.get("MessageId")
        if message_id:
            self._metrics.delivered += 1
            return DeliveryResult(
                target=target,
                status=DeliveryStatus.DELIVERED,
                delivered_at=datetime.utcnow(),
                provider_response={"message_id": message_id},
            )
        else:
            self._metrics.failed += 1
            return DeliveryResult(
                target=target,
                status=DeliveryStatus.FAILED,
                error="SES did not return message ID",
            )

    async def _send_smtp(
        self,
        target: NotificationTarget,
        message: EmailMessage,
    ) -> DeliveryResult:
        """Send email via SMTP.

        Args:
            target: The notification target
            message: The email message

        Returns:
            DeliveryResult from SMTP send
        """
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        msg = MIMEMultipart("alternative")
        msg["Subject"] = message.subject
        msg["From"] = f"{self._config.from_name} <{self._config.from_email}>"
        msg["To"] = message.to

        msg.attach(MIMEText(message.body_text, "plain"))
        if message.body_html:
            msg.attach(MIMEText(message.body_html, "html"))

        loop = asyncio.get_event_loop()

        def send_sync():
            with smtplib.SMTP(self._config.smtp_host, self._config.smtp_port) as server:
                if self._config.smtp_use_tls:
                    server.starttls()
                if self._config.smtp_username and self._config.smtp_password:
                    server.login(self._config.smtp_username, self._config.smtp_password)
                server.send_message(msg)

        await loop.run_in_executor(None, send_sync)

        self._metrics.delivered += 1
        return DeliveryResult(
            target=target,
            status=DeliveryStatus.DELIVERED,
            delivered_at=datetime.utcnow(),
            provider_response={"provider": "smtp"},
        )

    async def _send_mock(
        self,
        target: NotificationTarget,
        message: EmailMessage,
    ) -> DeliveryResult:
        """Mock email send for testing.

        Args:
            target: The notification target
            message: The email message

        Returns:
            Successful DeliveryResult
        """
        logger.debug(
            "Email mock send",
            extra={
                "to": message.to,
                "subject": message.subject,
            },
        )

        self._metrics.delivered += 1
        return DeliveryResult(
            target=target,
            status=DeliveryStatus.DELIVERED,
            delivered_at=datetime.utcnow(),
            provider_response={"mock": True},
        )

    async def send_batch(
        self,
        targets: list[NotificationTarget],
        payload: NotificationPayload,
    ) -> BatchDeliveryResult:
        """Send email to multiple recipients.

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
            "status": "healthy" if self._semaphore else "not_initialized",
            "provider": self._config.provider.value,
            "from_email": self._config.from_email,
            "metrics": {
                "sent": self._metrics.sent,
                "delivered": self._metrics.delivered,
                "failed": self._metrics.failed,
                "bounced": self._metrics.bounced,
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
    def metrics(self) -> EmailMetrics:
        """Get adapter metrics."""
        return self._metrics
