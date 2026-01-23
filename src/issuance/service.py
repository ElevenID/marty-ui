"""Credential issuance service.

Business logic for creating credential offers and managing the
issuance lifecycle. Integrates with the applicant service for
approval-triggered issuance.

Uses hexagonal architecture with IIssuanceStorage port for persistent
storage via Redis. Key management is handled by SpruceIDKeyManager.
"""

from __future__ import annotations

import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Optional

from subscription.models import IssuanceStatus
from issuance.ports import (
    IIssuanceStorage,
    StoredOffer,
    StoredSession,
)

logger = logging.getLogger(__name__)


# Configuration
OFFER_EXPIRY_SECONDS = 300  # 5 minutes for real-time
DEFERRED_EXPIRY_SECONDS = 86400  # 24 hours for deferred
TRANSACTION_ID_LENGTH = 32


def _generate_transaction_id() -> str:
    """Generate a unique transaction ID."""
    return secrets.token_urlsafe(TRANSACTION_ID_LENGTH)


def _generate_pre_authorized_code() -> str:
    """Generate a pre-authorized code."""
    return secrets.token_urlsafe(32)


class IssuanceService:
    """Service for managing credential issuance.
    
    Uses injected storage port for persistence:
    - IIssuanceStorage: Sessions and offers
    
    Key management is handled by SpruceIDKeyManager via CredentialSigner.
    """

    def __init__(
        self,
        issuance_storage: IIssuanceStorage,
        issuer_url: str = "http://localhost:8000",
    ):
        """Initialize the issuance service.
        
        Args:
            issuance_storage: Storage port for sessions and offers
            issuer_url: Base URL for the credential issuer
        """
        self.issuer_url = issuer_url
        self._storage = issuance_storage

    async def create_offer_for_application(
        self,
        *,
        organization_id: str,
        application_id: str,
        credential_config_id: str,
        applicant_id: str,
        credential_data: dict,
        device_id: Optional[str] = None,
        credential_format: str = "vc+sd-jwt",
        auto_accept: bool = True,  # Auto-accept since holder already applied
    ) -> StoredSession:
        """Create a credential offer for an approved application.

        This is the main integration point called after an application
        is approved and ready for credential issuance.
        
        Since the holder already consented by submitting the application,
        the credential is automatically accepted and pushed to their
        authenticator - no additional user action required.

        Args:
            organization_id: The issuing organization ID
            application_id: The source application ID
            credential_config_id: The credential type configuration ID
            applicant_id: The recipient user ID
            credential_data: The claim values for the credential
            device_id: Optional target device for push notification
            credential_format: Credential format (vc+sd-jwt, jwt_vc_json, mso_mdoc)
            auto_accept: Auto-accept the offer (default True for application flow)

        Returns:
            The created StoredSession with transaction_id and offer_uri
        """
        session_id = str(uuid.uuid4())
        transaction_id = _generate_transaction_id()
        pre_authorized_code = _generate_pre_authorized_code()

        # For auto-accept (application flow), credential is generated immediately
        # and pushed to the authenticator - no user action needed
        expiry = datetime.now(timezone.utc) + timedelta(seconds=DEFERRED_EXPIRY_SECONDS)
        now = datetime.now(timezone.utc)

        # Create issuance session using StoredSession (cache-friendly dataclass)
        session = StoredSession(
            id=session_id,
            transaction_id=transaction_id,
            organization_id=organization_id,
            credential_config_id=credential_config_id,
            applicant_id=applicant_id,
            status=IssuanceStatus.PENDING.value,
            credential_format=credential_format,
            pre_authorized_code=pre_authorized_code,
            application_id=application_id,
            device_id=device_id,
            credential_data=credential_data,
            expires_at=expiry.isoformat(),
            created_at=now.isoformat(),
        )

        # Store in Redis via storage port
        await self._storage.store_session(session, ttl_seconds=DEFERRED_EXPIRY_SECONDS)

        # Build credential offer
        offer_payload = self._build_credential_offer(session)
        offer_uri = self._build_credential_offer_uri(session_id)

        # Create offer record using StoredOffer (cache-friendly dataclass)
        offer = StoredOffer(
            id=str(uuid.uuid4()),
            issuance_session_id=session_id,
            organization_id=organization_id,
            offer_uri=offer_uri,
            offer_payload=offer_payload,
            is_active=True,
            expires_at=expiry.isoformat(),
            created_at=now.isoformat(),
        )

        # Store offer in Redis
        await self._storage.store_offer(offer, ttl_seconds=OFFER_EXPIRY_SECONDS)

        logger.info(
            f"Created issuance session {session_id} for application {application_id}, "
            f"transaction_id={transaction_id}, auto_accept={auto_accept}"
        )

        # Generate the credential immediately
        session = await self._queue_credential_generation(session)

        if auto_accept:
            # Auto-accept: mark as accepted and issued, push credential to authenticator
            session.status = IssuanceStatus.ISSUED.value
            session.accepted_at = now.isoformat()
            session.issued_at = now.isoformat()
            
            # Update session in storage
            await self._storage.update_session(session)
            
            # Push the actual credential to the authenticator (not just an offer)
            if device_id:
                await self._push_credential_to_authenticator(session)
        else:
            # Manual accept: send offer notification, user must accept
            if device_id:
                await self._send_credential_ready_notification(session, offer_uri)

        return session

    async def get_session(self, transaction_id: str) -> Optional[StoredSession]:
        """Get issuance session by transaction ID."""
        return await self._storage.get_session_by_transaction_id(transaction_id)

    async def get_session_by_id(self, session_id: str) -> Optional[StoredSession]:
        """Get issuance session by session ID."""
        return await self._storage.get_session_by_id(session_id)

    async def get_session_by_pre_auth_code(
        self, pre_authorized_code: str
    ) -> Optional[StoredSession]:
        """Get issuance session by pre-authorized code."""
        return await self._storage.get_session_by_pre_auth_code(pre_authorized_code)

    async def update_session_status(
        self,
        transaction_id: str,
        status: IssuanceStatus,
        credential: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> Optional[StoredSession]:
        """Update issuance session status.

        Called by the credential generation worker when async processing completes.
        """
        session = await self._storage.get_session_by_transaction_id(transaction_id)
        if not session:
            return None

        now = datetime.now(timezone.utc)
        session.status = status.value

        if credential:
            session.issued_credential = credential
            session.issued_at = now.isoformat()

        # Note: error_message would need to be added to StoredSession if needed

        await self._storage.update_session(session)
        logger.info(f"Updated issuance session {transaction_id} to status {status}")

        return session

    def _build_credential_offer(self, session: StoredSession) -> dict:
        """Build OID4VCI credential offer payload."""
        return {
            "credential_issuer": self.issuer_url,
            "credential_configuration_ids": [session.credential_config_id],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": session.pre_authorized_code,
                    "tx_code": None,
                }
            },
        }

    def _build_credential_offer_uri(self, session_id: str) -> str:
        """Build credential offer URI for wallet."""
        from urllib.parse import urlencode

        offer_endpoint = f"{self.issuer_url}/api/issuance/offers/{session_id}"
        params = urlencode({"credential_offer_uri": offer_endpoint})
        return f"openid-credential-offer://?{params}"

    async def _queue_credential_generation(self, session: StoredSession) -> StoredSession:
        """Queue async credential generation.

        In production, this would:
        1. Send a message to a job queue (Celery, RQ, etc.)
        2. The worker would fetch the session, generate the credential,
           and call update_session_status

        For now, we perform immediate signing.
        
        Returns:
            Updated session with credential or error status
        """
        logger.info(f"Generating credential for session {session.id}")

        try:
            # Sign the credential
            from issuance.signing import get_credential_signer
            
            signer = get_credential_signer()
            credential = await signer.sign_credential(
                organization_id=session.organization_id,
                credential_config_id=session.credential_config_id,
                subject_id=session.applicant_id,
                claims=session.credential_data or {},
                credential_format=session.credential_format or "vc+sd-jwt",
            )
            
            now = datetime.now(timezone.utc)
            session.status = IssuanceStatus.READY.value
            session.issued_credential = credential
            session.issued_at = now.isoformat()
            
            # Update in storage
            await self._storage.update_session(session)
            
            logger.info(f"Credential generated for session {session.id}")
            
        except Exception as e:
            logger.error(f"Failed to generate credential for session {session.id}: {e}")
            session.status = IssuanceStatus.FAILED.value
            await self._storage.update_session(session)
        
        return session

    async def _push_credential_to_authenticator(
        self,
        session: StoredSession,
    ) -> bool:
        """Push the credential directly to the authenticator.

        For auto-accept flow: the holder already consented when they applied,
        so we push the credential directly to their wallet without requiring
        them to manually accept an offer.

        Args:
            session: The issuance session with the generated credential

        Returns:
            True if credential was pushed successfully
        """
        if not session.device_id:
            logger.info(
                f"No device_id for session {session.id}, skipping push"
            )
            return False

        if not session.issued_credential:
            logger.error(
                f"No credential to push for session {session.id}"
            )
            return False

        # Build push payload with the actual credential
        payload = {
            "type": "credential_issued",
            "title": "New Credential",
            "body": "A new credential has been added to your wallet",
            "data": {
                "action": "store_credential",
                "transaction_id": session.transaction_id,
                "credential_config_id": session.credential_config_id,
                "credential_format": session.credential_format,
                "credential": session.issued_credential,
                "credential_data": session.credential_data,
                "issued_at": session.issued_at,  # Already ISO string
            },
            "priority": "high",
        }

        try:
            # Push via FCM or SSE
            logger.info(
                f"[PUSH] Sending credential to device {session.device_id}: "
                f"transaction_id={session.transaction_id}"
            )
            
            # TODO: Integrate with actual push service (FCM/SSE)
            # For now, store in a pickup queue that the authenticator can poll
            from issuance.notifications import get_credential_offer_notifier
            
            notifier = get_credential_offer_notifier()
            # The notifier will handle the push delivery
            await notifier.notify_credential_ready(
                session, 
                f"credential://{session.transaction_id}"  # Direct credential URI
            )
            
            logger.info(
                f"Credential pushed to authenticator for session {session.id}"
            )
            
            # Emit SSE event for test observability
            await self._emit_credential_issued_event(session)
            
            return True
        except Exception as e:
            logger.error(
                f"Failed to push credential for session {session.id}: {e}"
            )
            return False

    async def _emit_credential_issued_event(self, session: StoredSession) -> None:
        """Emit SSE event for credential issuance (test observability)."""
        try:
            import sys
            from pathlib import Path
            from uuid import uuid4
            from datetime import datetime, timezone
            
            # Add main src directory to path for notifications module
            _main_src = Path(__file__).parent.parent.parent.parent / "src"
            if _main_src.exists() and str(_main_src) not in sys.path:
                sys.path.insert(0, str(_main_src))
            sys.path.insert(0, '/app')  # For Docker context
            
            from notifications.adapters.sse import SSEAdapter
            from notifications.types import NotificationPayload, NotificationTarget
            from notifications.api import get_sse_adapter
            
            try:
                sse_adapter = get_sse_adapter()
            except Exception:
                return
            
            payload = NotificationPayload(
                id=uuid4(),
                event_type="credential.issued",
                title="Credential Issued",
                body="A new credential has been issued",
                data={
                    "session_id": str(session.id),
                    "transaction_id": session.transaction_id,
                    "credential_config_id": session.credential_config_id,
                    "application_id": session.application_id,
                },
                created_at=datetime.now(timezone.utc),
                target=NotificationTarget(
                    user_id=session.applicant_id,
                    organization_id=UUID(session.organization_id) if session.organization_id else None,
                ) if session.applicant_id else None,
            )
            
            await sse_adapter.send(payload)
            logger.debug(f"SSE event emitted: credential.issued for session {session.id}")
            
        except Exception as e:
            logger.debug(f"Failed to emit credential.issued event: {e}")
    
    async def _send_credential_ready_notification(
        self,
        session: StoredSession,
        credential_offer_uri: str,
    ) -> bool:
        """Send push notification that credential offer is ready.

        For manual accept flow: notify user they have a pending offer.

        Args:
            session: The issuance session
            credential_offer_uri: The credential offer URI for wallet

        Returns:
            True if notification was sent
        """
        from issuance.notifications import send_credential_offer_notification

        try:
            return await send_credential_offer_notification(session, credential_offer_uri)
        except Exception as e:
            logger.error(
                f"Failed to send credential ready notification for session {session.id}: {e}"
            )
            return False


# Singleton instance
_issuance_service: Optional[IssuanceService] = None
_issuance_storage: Optional[IIssuanceStorage] = None


def get_issuance_storage() -> IIssuanceStorage:
    """Get or create the issuance storage singleton."""
    global _issuance_storage
    if _issuance_storage is None:
        from issuance.adapters import create_issuance_storage
        _issuance_storage = create_issuance_storage()
    return _issuance_storage


def get_issuance_service() -> IssuanceService:
    """Get the issuance service singleton.
    
    Uses Redis-backed storage via IIssuanceStorage port.
    """
    global _issuance_service
    if _issuance_service is None:
        storage = get_issuance_storage()
        _issuance_service = IssuanceService(issuance_storage=storage)
    return _issuance_service
