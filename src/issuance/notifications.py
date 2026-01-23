"""Credential push notification integration.

Sends credentials directly to applicant's authenticator app after
application approval. Since the holder consented by applying,
credentials are auto-accepted - no manual offer acceptance needed.
"""

import logging
from datetime import datetime
from typing import Optional

from subscription.models import DeviceRegistration, IssuanceSession

logger = logging.getLogger(__name__)

# In-memory credential delivery queue for authenticators to poll
# Key: device_id, Value: list of pending credentials
_credential_delivery_queue: dict[str, list[dict]] = {}


class CredentialOfferNotifier:
    """Sends credentials directly to registered devices.

    For the application flow, credentials are auto-accepted since the
    holder already consented when submitting their application.
    """

    def __init__(self, notification_hub=None):
        """Initialize the notifier.

        Args:
            notification_hub: Optional NotificationHub instance for delivery.
                             If not provided, uses a stub implementation.
        """
        self._hub = notification_hub
        self._fcm_adapter = None

    async def notify_credential_ready(
        self,
        session: IssuanceSession,
        credential_uri: str,
    ) -> bool:
        """Push credential to the authenticator.

        For auto-accept flow, this pushes the actual credential
        for immediate storage in the wallet.

        Args:
            session: The issuance session with credential details
            credential_uri: URI for the credential

        Returns:
            True if notification was sent successfully
        """
        if not session.device_id:
            logger.info(
                f"No device_id for session {session.id}, skipping push notification"
            )
            return False

        # Determine if this is a direct credential push or an offer
        is_direct_push = credential_uri.startswith("credential://")
        
        if is_direct_push and session.issued_credential:
            # Direct credential push - auto-accept flow
            payload = {
                "type": "credential_issued",
                "title": "Credential Issued",
                "body": "Your credential has been added to your wallet",
                "data": {
                    "action": "store_credential",
                    "transaction_id": session.transaction_id,
                    "credential_config_id": session.credential_config_id,
                    "credential_format": session.credential_format,
                    "credential": session.issued_credential,
                    "auto_accepted": True,
                },
                "priority": "high",
                "ttl": 86400,
            }
        else:
            # Credential offer - manual accept flow
            payload = {
                "type": "credential_ready",
                "title": "Credential Ready",
                "body": "Your credential is ready to be added to your wallet",
                "data": {
                    "credential_offer_uri": credential_uri,
                    "transaction_id": session.transaction_id,
                    "credential_config_id": session.credential_config_id,
                    "action": "open_credential_offer",
                },
                "priority": "high",
                "ttl": 86400,
            }

        try:
            # Add to delivery queue for authenticator polling
            if session.device_id not in _credential_delivery_queue:
                _credential_delivery_queue[session.device_id] = []
            _credential_delivery_queue[session.device_id].append({
                **payload,
                "queued_at": datetime.utcnow().isoformat(),
                "session_id": session.id,
            })
            
            # If we have a hub, also push via FCM/SSE
            if self._hub:
                from notifications.types import (
                    NotificationPayload,
                    NotificationTarget,
                    NotificationPriority,
                    ChannelType,
                )

                target = NotificationTarget(
                    user_id=session.applicant_id,
                    device_token=session.device_id,
                    channel=ChannelType.FCM,
                )

                notification = NotificationPayload(
                    title=payload["title"],
                    body=payload["body"],
                    data=payload["data"],
                    priority=NotificationPriority.HIGH,
                )

                result = await self._hub.send_notification(target, notification)
                success = result.status.value == "delivered"
            else:
                # Stub implementation - log and rely on polling
                logger.info(
                    f"[PUSH] Credential queued for device {session.device_id}: "
                    f"type={payload['type']}, transaction_id={session.transaction_id}"
                )
                success = True

            if success:
                logger.info(
                    f"Sent credential notification for session {session.id} "
                    f"to device {session.device_id}"
                )
            return success

        except Exception as e:
            logger.error(
                f"Failed to send credential notification for session {session.id}: {e}"
            )
            return False

    async def notify_application_approved(
        self,
        applicant_id: str,
        application_id: str,
        organization_name: str,
        device_id: Optional[str] = None,
    ) -> bool:
        """Send push notification that application was approved.

        Args:
            applicant_id: The applicant's user ID
            application_id: The application ID
            organization_name: Name of the issuing organization
            device_id: Optional specific device to notify

        Returns:
            True if notification was sent successfully
        """
        payload = {
            "type": "application_approved",
            "title": "Application Approved!",
            "body": f"Your application with {organization_name} has been approved",
            "data": {
                "application_id": application_id,
                "organization_name": organization_name,
                "action": "view_application",
            },
            "priority": "high",
        }

        try:
            if device_id:
                if device_id not in _credential_delivery_queue:
                    _credential_delivery_queue[device_id] = []
                _credential_delivery_queue[device_id].append({
                    **payload,
                    "queued_at": datetime.utcnow().isoformat(),
                })

            if self._hub:
                from notifications.types import (
                    NotificationPayload,
                    NotificationTarget,
                    NotificationPriority,
                    ChannelType,
                )

                target = NotificationTarget(
                    user_id=applicant_id,
                    device_token=device_id,
                    channel=ChannelType.FCM if device_id else ChannelType.SSE,
                )

                notification = NotificationPayload(
                    title=payload["title"],
                    body=payload["body"],
                    data=payload["data"],
                    priority=NotificationPriority.HIGH,
                )

                result = await self._hub.send_notification(target, notification)
                success = result.status.value == "delivered"
            else:
                logger.info(
                    f"[PUSH] Application approved notification for application {application_id}"
                )
                success = True

            return success
        except Exception as e:
            logger.error(f"Failed to send application approved notification: {e}")
            return False

    async def notify_application_submitted(
        self,
        applicant_id: str,
        application_id: str,
        organization_name: str,
        credential_type: str,
        device_id: Optional[str] = None,
    ) -> bool:
        """Send notification that application was submitted.

        Args:
            applicant_id: The applicant's user ID
            application_id: The application ID
            organization_name: Name of the organization
            credential_type: Type of credential applied for
            device_id: Optional specific device to notify

        Returns:
            True if notification was sent successfully
        """
        payload = {
            "type": "application_submitted",
            "title": "Application Submitted",
            "body": f"Your {credential_type} application to {organization_name} has been submitted",
            "data": {
                "application_id": application_id,
                "organization_name": organization_name,
                "credential_type": credential_type,
                "action": "view_application",
            },
            "priority": "normal",
        }

        try:
            if device_id:
                if device_id not in _credential_delivery_queue:
                    _credential_delivery_queue[device_id] = []
                _credential_delivery_queue[device_id].append({
                    **payload,
                    "queued_at": datetime.utcnow().isoformat(),
                })

            if self._hub:
                from notifications.types import (
                    NotificationPayload,
                    NotificationTarget,
                    NotificationPriority,
                    ChannelType,
                )

                target = NotificationTarget(
                    user_id=applicant_id,
                    device_token=device_id,
                    channel=ChannelType.FCM if device_id else ChannelType.SSE,
                )

                notification = NotificationPayload(
                    title=payload["title"],
                    body=payload["body"],
                    data=payload["data"],
                    priority=NotificationPriority.NORMAL,
                )

                result = await self._hub.send_notification(target, notification)
                success = result.status.value == "delivered"
            else:
                logger.info(
                    f"[PUSH] Application submitted notification for application {application_id}"
                )
                success = True

            return success
        except Exception as e:
            logger.error(f"Failed to send application submitted notification: {e}")
            return False

    async def notify_application_rejected(
        self,
        applicant_id: str,
        application_id: str,
        organization_name: str,
        rejection_reason: Optional[str] = None,
        device_id: Optional[str] = None,
    ) -> bool:
        """Send notification that application was rejected.

        Args:
            applicant_id: The applicant's user ID
            application_id: The application ID
            organization_name: Name of the organization
            rejection_reason: Optional reason for rejection
            device_id: Optional specific device to notify

        Returns:
            True if notification was sent successfully
        """
        body = f"Your application with {organization_name} was not approved"
        if rejection_reason:
            body += f": {rejection_reason}"

        payload = {
            "type": "application_rejected",
            "title": "Application Not Approved",
            "body": body,
            "data": {
                "application_id": application_id,
                "organization_name": organization_name,
                "rejection_reason": rejection_reason,
                "action": "view_application",
            },
            "priority": "high",
        }

        try:
            if device_id:
                if device_id not in _credential_delivery_queue:
                    _credential_delivery_queue[device_id] = []
                _credential_delivery_queue[device_id].append({
                    **payload,
                    "queued_at": datetime.utcnow().isoformat(),
                })

            if self._hub:
                from notifications.types import (
                    NotificationPayload,
                    NotificationTarget,
                    NotificationPriority,
                    ChannelType,
                )

                target = NotificationTarget(
                    user_id=applicant_id,
                    device_token=device_id,
                    channel=ChannelType.FCM if device_id else ChannelType.SSE,
                )

                notification = NotificationPayload(
                    title=payload["title"],
                    body=payload["body"],
                    data=payload["data"],
                    priority=NotificationPriority.HIGH,
                )

                result = await self._hub.send_notification(target, notification)
                success = result.status.value == "delivered"
            else:
                logger.info(
                    f"[PUSH] Application rejected notification for application {application_id}"
                )
                success = True

            return success
        except Exception as e:
            logger.error(f"Failed to send application rejected notification: {e}")
            return False

    async def notify_application_under_review(
        self,
        applicant_id: str,
        application_id: str,
        organization_name: str,
        device_id: Optional[str] = None,
    ) -> bool:
        """Send notification that application is under review.

        Args:
            applicant_id: The applicant's user ID
            application_id: The application ID
            organization_name: Name of the organization
            device_id: Optional specific device to notify

        Returns:
            True if notification was sent successfully
        """
        payload = {
            "type": "application_under_review",
            "title": "Application Under Review",
            "body": f"{organization_name} is now reviewing your application",
            "data": {
                "application_id": application_id,
                "organization_name": organization_name,
                "action": "view_application",
            },
            "priority": "normal",
        }

        try:
            if device_id:
                if device_id not in _credential_delivery_queue:
                    _credential_delivery_queue[device_id] = []
                _credential_delivery_queue[device_id].append({
                    **payload,
                    "queued_at": datetime.utcnow().isoformat(),
                })

            if self._hub:
                from notifications.types import (
                    NotificationPayload,
                    NotificationTarget,
                    NotificationPriority,
                    ChannelType,
                )

                target = NotificationTarget(
                    user_id=applicant_id,
                    device_token=device_id,
                    channel=ChannelType.FCM if device_id else ChannelType.SSE,
                )

                notification = NotificationPayload(
                    title=payload["title"],
                    body=payload["body"],
                    data=payload["data"],
                    priority=NotificationPriority.NORMAL,
                )

                result = await self._hub.send_notification(target, notification)
                success = result.status.value == "delivered"
            else:
                logger.info(
                    f"[PUSH] Application under review notification for application {application_id}"
                )
                success = True

            return success
        except Exception as e:
            logger.error(f"Failed to send application under review notification: {e}")
            return False

    async def notify_application_revision_requested(
        self,
        applicant_id: str,
        application_id: str,
        organization_name: str,
        revision_notes: str,
        device_id: Optional[str] = None,
    ) -> bool:
        """Send notification that application needs revision.

        Args:
            applicant_id: The applicant's user ID
            application_id: The application ID
            organization_name: Name of the organization
            revision_notes: Notes explaining what needs to be revised
            device_id: Optional specific device to notify

        Returns:
            True if notification was sent successfully
        """
        payload = {
            "type": "application_needs_revision",
            "title": "Application Needs Revision",
            "body": f"{organization_name} has requested changes to your application",
            "data": {
                "application_id": application_id,
                "organization_name": organization_name,
                "revision_notes": revision_notes,
                "action": "edit_application",
            },
            "priority": "high",
        }

        try:
            if device_id:
                if device_id not in _credential_delivery_queue:
                    _credential_delivery_queue[device_id] = []
                _credential_delivery_queue[device_id].append({
                    **payload,
                    "queued_at": datetime.utcnow().isoformat(),
                })

            if self._hub:
                from notifications.types import (
                    NotificationPayload,
                    NotificationTarget,
                    NotificationPriority,
                    ChannelType,
                )

                target = NotificationTarget(
                    user_id=applicant_id,
                    device_token=device_id,
                    channel=ChannelType.FCM if device_id else ChannelType.SSE,
                )

                notification = NotificationPayload(
                    title=payload["title"],
                    body=payload["body"],
                    data=payload["data"],
                    priority=NotificationPriority.HIGH,
                )

                result = await self._hub.send_notification(target, notification)
                success = result.status.value == "delivered"
            else:
                logger.info(
                    f"[PUSH] Application revision requested notification for application {application_id}"
                )
                success = True

            return success
        except Exception as e:
            logger.error(f"Failed to send application revision requested notification: {e}")
            return False


# Singleton instance
_notifier: Optional[CredentialOfferNotifier] = None


def get_credential_offer_notifier() -> CredentialOfferNotifier:
    """Get the credential offer notifier singleton."""
    global _notifier
    if _notifier is None:
        _notifier = CredentialOfferNotifier()
    return _notifier


async def send_credential_offer_notification(
    session: IssuanceSession,
    credential_offer_uri: str,
) -> bool:
    """Convenience function to send credential offer notification.

    Args:
        session: The issuance session
        credential_offer_uri: The credential offer URI

    Returns:
        True if notification was sent successfully
    """
    notifier = get_credential_offer_notifier()
    return await notifier.notify_credential_ready(session, credential_offer_uri)


def get_pending_credentials(device_id: str) -> list[dict]:
    """Get pending credentials for a device.

    Authenticator apps can poll this to retrieve credentials
    that were auto-accepted on their behalf.

    Args:
        device_id: The device ID

    Returns:
        List of pending credentials
    """
    return _credential_delivery_queue.get(device_id, [])


def acknowledge_credential(device_id: str, session_id: str) -> bool:
    """Acknowledge receipt of a credential.

    After the authenticator stores the credential, it should
    acknowledge receipt to remove it from the queue.

    Args:
        device_id: The device ID
        session_id: The session ID to acknowledge

    Returns:
        True if acknowledged successfully
    """
    if device_id not in _credential_delivery_queue:
        return False

    queue = _credential_delivery_queue[device_id]
    original_len = len(queue)
    _credential_delivery_queue[device_id] = [
        c for c in queue if c.get("session_id") != session_id
    ]

    return len(_credential_delivery_queue[device_id]) < original_len
