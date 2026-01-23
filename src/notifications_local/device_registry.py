"""Device registry for managing notification targets.

This module provides persistent storage and querying of device registrations
for push notifications, including FCM tokens, webhook endpoints, and email
addresses associated with tenant+user identities.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional, Protocol

from .types import ChannelType, NotificationTarget

logger = logging.getLogger(__name__)


class IDeviceRepository(Protocol):
    """Protocol for device storage backend."""

    async def save(self, registration: "DeviceRegistration") -> bool:
        """Save or update a device registration."""
        ...

    async def get(self, device_id: str) -> Optional["DeviceRegistration"]:
        """Get a device registration by ID."""
        ...

    async def delete(self, device_id: str) -> bool:
        """Delete a device registration."""
        ...

    async def find_by_tenant(
        self,
        tenant_id: str,
        channel: Optional[ChannelType] = None,
    ) -> list["DeviceRegistration"]:
        """Find all registrations for a tenant."""
        ...

    async def find_by_user(
        self,
        tenant_id: str,
        user_id: str,
        channel: Optional[ChannelType] = None,
    ) -> list["DeviceRegistration"]:
        """Find all registrations for a user."""
        ...

    async def find_by_event_type(
        self,
        tenant_id: str,
        event_type: str,
    ) -> list["DeviceRegistration"]:
        """Find registrations subscribed to an event type."""
        ...


@dataclass
class DeviceRegistration:
    """Registration of a device/endpoint for notifications.

    Attributes:
        id: Unique registration ID
        tenant_id: Organization/tenant ID
        user_id: User ID within the tenant
        channel: Notification channel type
        device_id: Device identifier (for FCM)
        platform: Device platform (ios/android)
        fcm_token: Firebase Cloud Messaging token
        webhook_url: Webhook endpoint URL
        webhook_secret: Secret for HMAC signing
        email: Email address
        wallet_did: DID from mobile wallet
        event_subscriptions: Event types this device is subscribed to
        preferences: Channel-specific preferences
        is_active: Whether this registration is active
        created_at: Registration creation time
        updated_at: Last update time
        last_used_at: Last successful delivery time
    """

    id: str
    tenant_id: str
    channel: ChannelType
    user_id: Optional[str] = None
    device_id: Optional[str] = None
    platform: Optional[str] = None
    fcm_token: Optional[str] = None
    webhook_url: Optional[str] = None
    webhook_secret: Optional[str] = None
    email: Optional[str] = None
    wallet_did: Optional[str] = None
    event_subscriptions: list[str] = field(default_factory=list)
    preferences: dict[str, Any] = field(default_factory=dict)
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    last_used_at: Optional[datetime] = None

    def to_target(self) -> NotificationTarget:
        """Convert to NotificationTarget for delivery."""
        return NotificationTarget(
            tenant_id=self.tenant_id,
            user_id=self.user_id,
            channel=self.channel,
            device_token=self.fcm_token,
            webhook_url=self.webhook_url,
            webhook_secret=self.webhook_secret,
            email=self.email,
            wallet_did=self.wallet_did,
            preferences=self.preferences,
        )

    def is_subscribed_to(self, event_type: str) -> bool:
        """Check if subscribed to a specific event type.

        Supports wildcard matching:
        - "*" matches all events
        - "credential.*" matches all credential events
        """
        if not self.event_subscriptions:
            return False

        for subscription in self.event_subscriptions:
            if subscription == "*":
                return True
            if subscription.endswith(".*"):
                prefix = subscription[:-2]
                if event_type.startswith(prefix):
                    return True
            if subscription == event_type:
                return True

        return False


class DeviceRegistry:
    """Registry for managing device registrations.

    Provides methods for registering, updating, and querying notification
    targets across all supported channels.

    Example:
        registry = DeviceRegistry(repository)

        # Register a mobile device
        await registry.register_device(
            tenant_id="org-123",
            user_id="user-456",
            channel=ChannelType.FCM,
            fcm_token="token-abc",
            platform="ios",
            event_subscriptions=["credential.revoked", "trust_anchor.*"],
        )

        # Get targets for an event
        targets = await registry.get_targets(
            tenant_id="org-123",
            event_type="credential.revoked",
        )
    """

    def __init__(self, repository: IDeviceRepository):
        """Initialize the registry.

        Args:
            repository: Storage backend for device registrations
        """
        self._repository = repository

    async def register_device(
        self,
        tenant_id: str,
        channel: ChannelType,
        user_id: Optional[str] = None,
        device_id: Optional[str] = None,
        platform: Optional[str] = None,
        fcm_token: Optional[str] = None,
        webhook_url: Optional[str] = None,
        webhook_secret: Optional[str] = None,
        email: Optional[str] = None,
        wallet_did: Optional[str] = None,
        event_subscriptions: Optional[list[str]] = None,
        preferences: Optional[dict[str, Any]] = None,
    ) -> DeviceRegistration:
        """Register a new device/endpoint for notifications.

        Args:
            tenant_id: Organization/tenant ID
            channel: Notification channel type
            user_id: Optional user ID
            device_id: Device identifier
            platform: Device platform
            fcm_token: FCM token for push
            webhook_url: Webhook endpoint URL
            webhook_secret: Secret for HMAC signing
            email: Email address
            wallet_did: Wallet DID
            event_subscriptions: Event types to subscribe to
            preferences: Channel-specific preferences

        Returns:
            The created DeviceRegistration
        """
        import uuid

        registration = DeviceRegistration(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            user_id=user_id,
            channel=channel,
            device_id=device_id,
            platform=platform,
            fcm_token=fcm_token,
            webhook_url=webhook_url,
            webhook_secret=webhook_secret,
            email=email,
            wallet_did=wallet_did,
            event_subscriptions=event_subscriptions or [],
            preferences=preferences or {},
        )

        await self._repository.save(registration)

        logger.info(
            "Registered device",
            extra={
                "registration_id": registration.id,
                "tenant_id": tenant_id,
                "channel": channel.value,
            },
        )

        return registration

    async def update_fcm_token(
        self,
        registration_id: str,
        new_token: str,
    ) -> bool:
        """Update the FCM token for a registration.

        This is called when the app receives a new token from Firebase.

        Args:
            registration_id: ID of the registration
            new_token: New FCM token

        Returns:
            True if updated successfully
        """
        registration = await self._repository.get(registration_id)
        if not registration:
            logger.warning(f"Registration not found: {registration_id}")
            return False

        registration.fcm_token = new_token
        registration.updated_at = datetime.utcnow()

        return await self._repository.save(registration)

    async def update_subscriptions(
        self,
        registration_id: str,
        event_subscriptions: list[str],
    ) -> bool:
        """Update event subscriptions for a registration.

        Args:
            registration_id: ID of the registration
            event_subscriptions: New list of event types to subscribe to

        Returns:
            True if updated successfully
        """
        registration = await self._repository.get(registration_id)
        if not registration:
            return False

        registration.event_subscriptions = event_subscriptions
        registration.updated_at = datetime.utcnow()

        return await self._repository.save(registration)

    async def deactivate(self, registration_id: str) -> bool:
        """Deactivate a device registration.

        Used when a device is unregistered or a webhook is disabled.

        Args:
            registration_id: ID of the registration

        Returns:
            True if deactivated successfully
        """
        registration = await self._repository.get(registration_id)
        if not registration:
            return False

        registration.is_active = False
        registration.updated_at = datetime.utcnow()

        return await self._repository.save(registration)

    async def delete(self, registration_id: str) -> bool:
        """Delete a device registration.

        Args:
            registration_id: ID of the registration

        Returns:
            True if deleted successfully
        """
        return await self._repository.delete(registration_id)

    async def get_targets(
        self,
        tenant_id: str,
        event_type: str,
        user_id: Optional[str] = None,
        channels: Optional[list[ChannelType]] = None,
    ) -> list[NotificationTarget]:
        """Get notification targets for an event.

        Args:
            tenant_id: Tenant to get targets for
            event_type: Event type to filter by subscriptions
            user_id: Optional user ID to filter by
            channels: Optional list of channels to filter by

        Returns:
            List of NotificationTargets matching the criteria
        """
        registrations = await self._repository.find_by_event_type(
            tenant_id=tenant_id,
            event_type=event_type,
        )

        targets = []
        for reg in registrations:
            # Skip inactive registrations
            if not reg.is_active:
                continue

            # Filter by user if specified
            if user_id and reg.user_id != user_id:
                continue

            # Filter by channel if specified
            if channels and reg.channel not in channels:
                continue

            # Check subscription
            if not reg.is_subscribed_to(event_type):
                continue

            targets.append(reg.to_target())

        return targets

    async def get_targets_by_channel(
        self,
        tenant_id: str,
        event_type: str,
    ) -> dict[ChannelType, list[NotificationTarget]]:
        """Get notification targets grouped by channel.

        Args:
            tenant_id: Tenant to get targets for
            event_type: Event type to filter by subscriptions

        Returns:
            Dictionary mapping channel types to lists of targets
        """
        targets = await self.get_targets(tenant_id, event_type)

        grouped: dict[ChannelType, list[NotificationTarget]] = {}
        for target in targets:
            if target.channel not in grouped:
                grouped[target.channel] = []
            grouped[target.channel].append(target)

        return grouped

    async def mark_used(self, registration_id: str) -> None:
        """Mark a registration as recently used.

        Called after successful delivery to track activity.

        Args:
            registration_id: ID of the registration
        """
        registration = await self._repository.get(registration_id)
        if registration:
            registration.last_used_at = datetime.utcnow()
            await self._repository.save(registration)


class InMemoryDeviceRepository:
    """In-memory implementation of IDeviceRepository for testing."""

    def __init__(self):
        self._registrations: dict[str, DeviceRegistration] = {}

    async def save(self, registration: DeviceRegistration) -> bool:
        self._registrations[registration.id] = registration
        return True

    async def get(self, device_id: str) -> Optional[DeviceRegistration]:
        return self._registrations.get(device_id)

    async def delete(self, device_id: str) -> bool:
        if device_id in self._registrations:
            del self._registrations[device_id]
            return True
        return False

    async def find_by_tenant(
        self,
        tenant_id: str,
        channel: Optional[ChannelType] = None,
    ) -> list[DeviceRegistration]:
        results = []
        for reg in self._registrations.values():
            if reg.tenant_id == tenant_id:
                if channel is None or reg.channel == channel:
                    results.append(reg)
        return results

    async def find_by_user(
        self,
        tenant_id: str,
        user_id: str,
        channel: Optional[ChannelType] = None,
    ) -> list[DeviceRegistration]:
        results = []
        for reg in self._registrations.values():
            if reg.tenant_id == tenant_id and reg.user_id == user_id:
                if channel is None or reg.channel == channel:
                    results.append(reg)
        return results

    async def find_by_event_type(
        self,
        tenant_id: str,
        event_type: str,
    ) -> list[DeviceRegistration]:
        results = []
        for reg in self._registrations.values():
            if reg.tenant_id == tenant_id and reg.is_subscribed_to(event_type):
                results.append(reg)
        return results
