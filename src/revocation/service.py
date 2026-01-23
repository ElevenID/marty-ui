"""Revocation service for credentials and trust anchors.

This module provides the RevocationService for managing credential revocation
with configurable cascade policies for trust anchor revocation.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Protocol

logger = logging.getLogger(__name__)


class CascadePolicy(str, Enum):
    """Policy for cascading revocation from trust anchors to credentials.

    AUTO_CASCADE: Immediately revoke all credentials when trust anchor is revoked
    MANUAL: Require explicit admin action to revoke affected credentials
    NOTIFY_ONLY: Send notifications but don't automatically revoke
    """

    AUTO_CASCADE = "auto_cascade"
    MANUAL = "manual"
    NOTIFY_ONLY = "notify_only"


class StatusListFormat(str, Enum):
    """Status list format for credential revocation.

    TOKEN_STATUS_LIST: IETF Token Status List (for mDoc/CWT)
        - Uses CBOR encoding
        - Supports multiple status values (0-255)
        - Defined in draft-ietf-oauth-status-list-14

    BITSTRING_STATUS_LIST: W3C Bitstring Status List v1.0 (for SD-JWT VC)
        - Uses base64url encoded bitstring
        - Binary status (revoked/not revoked)
        - Defined in W3C Bitstring Status List v1.0
    """

    TOKEN_STATUS_LIST = "token_status_list"
    BITSTRING_STATUS_LIST = "bitstring_status_list"


class RevocationReason(str, Enum):
    """Standard revocation reasons."""

    UNSPECIFIED = "unspecified"
    KEY_COMPROMISE = "key_compromise"
    CA_COMPROMISE = "ca_compromise"
    AFFILIATION_CHANGED = "affiliation_changed"
    SUPERSEDED = "superseded"
    CESSATION_OF_OPERATION = "cessation_of_operation"
    PRIVILEGE_WITHDRAWN = "privilege_withdrawn"
    TRUST_ANCHOR_REVOKED = "trust_anchor_revoked"
    HOLDER_REQUEST = "holder_request"


@dataclass
class RevocationConfig:
    """Configuration for revocation service.

    Attributes:
        mdoc_format: Status list format for mDoc credentials
        sd_jwt_format: Status list format for SD-JWT VC credentials
        dsc_cascade_policy: Cascade policy for DSC revocation
        csca_cascade_policy: Cascade policy for CSCA revocation
        status_list_size: Size of status list (bits for bitstring, entries for token)
        auto_publish: Whether to automatically publish status list updates
        status_list_ttl_seconds: TTL for status list caching
    """

    mdoc_format: StatusListFormat = StatusListFormat.TOKEN_STATUS_LIST
    sd_jwt_format: StatusListFormat = StatusListFormat.BITSTRING_STATUS_LIST
    dsc_cascade_policy: CascadePolicy = CascadePolicy.NOTIFY_ONLY
    csca_cascade_policy: CascadePolicy = CascadePolicy.MANUAL
    status_list_size: int = 131072  # 16KB default (131072 bits / 8 = 16384 bytes)
    auto_publish: bool = True
    status_list_ttl_seconds: int = 300  # 5 minutes


@dataclass
class RevocationResult:
    """Result of a credential revocation operation.

    Attributes:
        success: Whether the revocation was successful
        credential_id: ID of the revoked credential
        status_list_index: Index in the status list
        format: Status list format used
        revoked_at: When the revocation occurred
        reason: Reason for revocation
        error: Error message if failed
    """

    success: bool
    credential_id: str
    status_list_index: Optional[int] = None
    format: Optional[StatusListFormat] = None
    revoked_at: Optional[datetime] = None
    reason: Optional[str] = None
    error: Optional[str] = None


@dataclass
class CascadeResult:
    """Result of a cascade revocation operation.

    Attributes:
        source_id: ID of the revoked trust anchor
        source_type: Type of trust anchor (DSC, CSCA)
        cascade_policy: Policy that was applied
        affected_count: Number of affected credentials
        revoked_credentials: List of revoked credential IDs
        notified_credentials: List of credentials for which notifications were sent
        pending_credentials: List of credentials pending manual action
        events_published: Number of domain events published
    """

    source_id: str
    source_type: str
    cascade_policy: CascadePolicy
    affected_count: int = 0
    revoked_credentials: list[str] = field(default_factory=list)
    notified_credentials: list[str] = field(default_factory=list)
    pending_credentials: list[str] = field(default_factory=list)
    events_published: int = 0


class ICredentialRepository(Protocol):
    """Protocol for credential storage."""

    async def get(self, credential_id: str) -> Optional[dict[str, Any]]:
        """Get a credential by ID."""
        ...

    async def update_status(
        self,
        credential_id: str,
        status: str,
        revoked_at: datetime,
        reason: str,
    ) -> bool:
        """Update credential status."""
        ...

    async def find_by_dsc(self, dsc_id: str) -> list[dict[str, Any]]:
        """Find all credentials issued by a DSC."""
        ...

    async def find_by_csca(self, csca_id: str) -> list[dict[str, Any]]:
        """Find all credentials issued under a CSCA."""
        ...


class IStatusListManager(Protocol):
    """Protocol for status list management."""

    async def set_status(
        self,
        tenant_id: str,
        index: int,
        status: int,
        format: StatusListFormat,
    ) -> bool:
        """Set status at a specific index."""
        ...

    async def get_status(
        self,
        tenant_id: str,
        index: int,
        format: StatusListFormat,
    ) -> int:
        """Get status at a specific index."""
        ...

    async def allocate_index(
        self,
        tenant_id: str,
        format: StatusListFormat,
    ) -> int:
        """Allocate a new index in the status list."""
        ...

    async def publish(
        self,
        tenant_id: str,
        format: StatusListFormat,
    ) -> str:
        """Publish the status list and return URL."""
        ...


class IEventPublisher(Protocol):
    """Protocol for domain event publishing."""

    async def publish(self, event: Any) -> bool:
        """Publish a domain event."""
        ...


class RevocationService:
    """Service for managing credential and trust anchor revocation.

    This service handles:
    - Individual credential revocation
    - Trust anchor (DSC/CSCA) revocation with cascade
    - Status list management (Token Status List and Bitstring)
    - Domain event publishing for notifications

    Example:
        config = RevocationConfig(
            dsc_cascade_policy=CascadePolicy.NOTIFY_ONLY,
            csca_cascade_policy=CascadePolicy.MANUAL,
        )

        service = RevocationService(
            config=config,
            credential_repo=credential_repository,
            status_list_manager=status_list_manager,
            event_publisher=domain_event_publisher,
        )

        # Revoke a single credential
        result = await service.revoke_credential(
            tenant_id="org-123",
            credential_id="cred-456",
            credential_type="mDoc",
            reason="holder_request",
            revoked_by="user-789",
        )

        # Revoke a DSC with cascade
        cascade_result = await service.revoke_dsc(
            tenant_id="org-123",
            dsc_id="dsc-abc",
            issuing_country="US",
            reason="key_compromise",
            revoked_by="admin-xyz",
        )
    """

    def __init__(
        self,
        config: RevocationConfig,
        credential_repo: ICredentialRepository,
        status_list_manager: IStatusListManager,
        event_publisher: Optional[IEventPublisher] = None,
    ):
        """Initialize the revocation service.

        Args:
            config: Revocation configuration
            credential_repo: Repository for credential storage
            status_list_manager: Manager for status lists
            event_publisher: Optional event publisher for notifications
        """
        self._config = config
        self._credential_repo = credential_repo
        self._status_list_manager = status_list_manager
        self._event_publisher = event_publisher

    async def revoke_credential(
        self,
        tenant_id: str,
        credential_id: str,
        credential_type: str,
        reason: str,
        revoked_by: str,
        cascade_source: Optional[str] = None,
    ) -> RevocationResult:
        """Revoke a single credential.

        Args:
            tenant_id: Organization/tenant ID
            credential_id: ID of the credential to revoke
            credential_type: Type of credential ("mDoc" or "sd_jwt_vc")
            reason: Reason for revocation
            revoked_by: ID of user/system performing revocation
            cascade_source: If revoked due to cascade, the source ID

        Returns:
            RevocationResult indicating success/failure
        """
        try:
            # Get credential
            credential = await self._credential_repo.get(credential_id)
            if not credential:
                return RevocationResult(
                    success=False,
                    credential_id=credential_id,
                    error="Credential not found",
                )

            # Determine format based on credential type
            format = (
                self._config.mdoc_format
                if credential_type.lower() == "mdoc"
                else self._config.sd_jwt_format
            )

            # Get or allocate status list index
            status_list_index = credential.get("status_list_index")
            if status_list_index is None:
                status_list_index = await self._status_list_manager.allocate_index(
                    tenant_id, format
                )

            # Set revoked status (1 = revoked for both formats)
            await self._status_list_manager.set_status(
                tenant_id=tenant_id,
                index=status_list_index,
                status=1,  # revoked
                format=format,
            )

            # Update credential in repository
            revoked_at = datetime.utcnow()
            await self._credential_repo.update_status(
                credential_id=credential_id,
                status="revoked",
                revoked_at=revoked_at,
                reason=reason,
            )

            # Publish status list if auto-publish enabled
            if self._config.auto_publish:
                await self._status_list_manager.publish(tenant_id, format)

            # Publish domain event
            if self._event_publisher:
                from ..events.domain_events import CredentialRevokedEvent

                event = CredentialRevokedEvent(
                    tenant_id=tenant_id,
                    credential_id=credential_id,
                    credential_type=credential_type,
                    reason=reason,
                    revoked_by=revoked_by,
                    status_list_format=format.value,
                    cascade_source=cascade_source,
                )
                await self._event_publisher.publish(event)

            logger.info(
                "Credential revoked",
                extra={
                    "credential_id": credential_id,
                    "tenant_id": tenant_id,
                    "format": format.value,
                    "reason": reason,
                },
            )

            return RevocationResult(
                success=True,
                credential_id=credential_id,
                status_list_index=status_list_index,
                format=format,
                revoked_at=revoked_at,
                reason=reason,
            )

        except Exception as e:
            logger.exception(f"Error revoking credential {credential_id}")
            return RevocationResult(
                success=False,
                credential_id=credential_id,
                error=str(e),
            )

    async def revoke_dsc(
        self,
        tenant_id: str,
        dsc_id: str,
        issuing_country: str,
        reason: str,
        revoked_by: str,
    ) -> CascadeResult:
        """Revoke a Document Signer Certificate with cascade.

        Args:
            tenant_id: Organization/tenant ID
            dsc_id: ID of the DSC to revoke
            issuing_country: ISO country code of the issuing authority
            reason: Reason for revocation
            revoked_by: ID of user/system performing revocation

        Returns:
            CascadeResult with details of the cascade operation
        """
        cascade_policy = self._config.dsc_cascade_policy

        # Find affected credentials
        affected_credentials = await self._credential_repo.find_by_dsc(dsc_id)

        result = CascadeResult(
            source_id=dsc_id,
            source_type="DSC",
            cascade_policy=cascade_policy,
            affected_count=len(affected_credentials),
        )

        # Publish DSC revocation event
        if self._event_publisher:
            from ..events.domain_events import DSCRevokedEvent

            event = DSCRevokedEvent(
                tenant_id=tenant_id,
                dsc_id=dsc_id,
                issuing_country=issuing_country,
                reason=reason,
                cascade_policy=cascade_policy.value,
                affected_credential_count=len(affected_credentials),
            )
            await self._event_publisher.publish(event)
            result.events_published += 1

        # Apply cascade policy
        if cascade_policy == CascadePolicy.AUTO_CASCADE:
            # Immediately revoke all affected credentials
            for cred in affected_credentials:
                revoke_result = await self.revoke_credential(
                    tenant_id=tenant_id,
                    credential_id=cred["id"],
                    credential_type=cred.get("type", "mDoc"),
                    reason=f"DSC revoked: {reason}",
                    revoked_by="system",
                    cascade_source=dsc_id,
                )
                if revoke_result.success:
                    result.revoked_credentials.append(cred["id"])

        elif cascade_policy == CascadePolicy.NOTIFY_ONLY:
            # Publish cascade notification event
            if self._event_publisher:
                from ..events.domain_events import TrustAnchorCascadeEvent

                cascade_event = TrustAnchorCascadeEvent(
                    tenant_id=tenant_id,
                    source_id=dsc_id,
                    source_type="DSC",
                    cascade_policy=cascade_policy.value,
                    affected_credentials=[c["id"] for c in affected_credentials],
                    action_required=True,
                )
                await self._event_publisher.publish(cascade_event)
                result.events_published += 1

            result.notified_credentials = [c["id"] for c in affected_credentials]

        elif cascade_policy == CascadePolicy.MANUAL:
            # Mark as pending manual action
            result.pending_credentials = [c["id"] for c in affected_credentials]

        logger.info(
            "DSC revoked with cascade",
            extra={
                "dsc_id": dsc_id,
                "cascade_policy": cascade_policy.value,
                "affected_count": result.affected_count,
                "revoked_count": len(result.revoked_credentials),
            },
        )

        return result

    async def revoke_csca(
        self,
        tenant_id: str,
        csca_id: str,
        country_code: str,
        reason: str,
        revoked_by: str,
    ) -> CascadeResult:
        """Revoke a Country Signing CA with cascade.

        CSCA revocation is more severe than DSC revocation and affects
        all DSCs and credentials under the CSCA.

        Args:
            tenant_id: Organization/tenant ID
            csca_id: ID of the CSCA to revoke
            country_code: ISO country code
            reason: Reason for revocation
            revoked_by: ID of user/system performing revocation

        Returns:
            CascadeResult with details of the cascade operation
        """
        cascade_policy = self._config.csca_cascade_policy

        # Find affected credentials (all under this CSCA)
        affected_credentials = await self._credential_repo.find_by_csca(csca_id)

        result = CascadeResult(
            source_id=csca_id,
            source_type="CSCA",
            cascade_policy=cascade_policy,
            affected_count=len(affected_credentials),
        )

        # Publish CSCA revocation event
        if self._event_publisher:
            from ..events.domain_events import CSCARevokedEvent

            event = CSCARevokedEvent(
                tenant_id=tenant_id,
                csca_id=csca_id,
                country_code=country_code,
                reason=reason,
                cascade_policy=cascade_policy.value,
                affected_dsc_count=0,  # Would need DSC lookup
                affected_credential_count=len(affected_credentials),
            )
            await self._event_publisher.publish(event)
            result.events_published += 1

        # CSCA cascade is typically manual due to severity
        if cascade_policy == CascadePolicy.AUTO_CASCADE:
            for cred in affected_credentials:
                revoke_result = await self.revoke_credential(
                    tenant_id=tenant_id,
                    credential_id=cred["id"],
                    credential_type=cred.get("type", "mDoc"),
                    reason=f"CSCA revoked: {reason}",
                    revoked_by="system",
                    cascade_source=csca_id,
                )
                if revoke_result.success:
                    result.revoked_credentials.append(cred["id"])

        elif cascade_policy == CascadePolicy.NOTIFY_ONLY:
            if self._event_publisher:
                from ..events.domain_events import TrustAnchorCascadeEvent

                cascade_event = TrustAnchorCascadeEvent(
                    tenant_id=tenant_id,
                    source_id=csca_id,
                    source_type="CSCA",
                    cascade_policy=cascade_policy.value,
                    affected_credentials=[c["id"] for c in affected_credentials],
                    action_required=True,
                )
                await self._event_publisher.publish(cascade_event)
                result.events_published += 1

            result.notified_credentials = [c["id"] for c in affected_credentials]

        else:  # MANUAL
            result.pending_credentials = [c["id"] for c in affected_credentials]

        logger.info(
            "CSCA revoked with cascade",
            extra={
                "csca_id": csca_id,
                "cascade_policy": cascade_policy.value,
                "affected_count": result.affected_count,
            },
        )

        return result

    async def check_credential_status(
        self,
        tenant_id: str,
        credential_id: str,
        credential_type: str,
    ) -> dict[str, Any]:
        """Check the revocation status of a credential.

        Args:
            tenant_id: Organization/tenant ID
            credential_id: ID of the credential
            credential_type: Type of credential

        Returns:
            Dictionary with status information
        """
        credential = await self._credential_repo.get(credential_id)
        if not credential:
            return {"found": False, "status": "unknown"}

        status_list_index = credential.get("status_list_index")
        if status_list_index is None:
            return {
                "found": True,
                "status": "active",
                "status_list_index": None,
            }

        format = (
            self._config.mdoc_format
            if credential_type.lower() == "mdoc"
            else self._config.sd_jwt_format
        )

        status = await self._status_list_manager.get_status(
            tenant_id=tenant_id,
            index=status_list_index,
            format=format,
        )

        return {
            "found": True,
            "status": "revoked" if status == 1 else "active",
            "status_list_index": status_list_index,
            "format": format.value,
        }

    async def reinstate_credential(
        self,
        tenant_id: str,
        credential_id: str,
        credential_type: str,
        reinstated_by: str,
    ) -> RevocationResult:
        """Reinstate a previously revoked credential.

        Note: This is only supported for certain revocation reasons
        and may not be allowed in all compliance scenarios.

        Args:
            tenant_id: Organization/tenant ID
            credential_id: ID of the credential
            credential_type: Type of credential
            reinstated_by: ID of user performing reinstatement

        Returns:
            RevocationResult indicating success/failure
        """
        try:
            credential = await self._credential_repo.get(credential_id)
            if not credential:
                return RevocationResult(
                    success=False,
                    credential_id=credential_id,
                    error="Credential not found",
                )

            status_list_index = credential.get("status_list_index")
            if status_list_index is None:
                return RevocationResult(
                    success=False,
                    credential_id=credential_id,
                    error="Credential has no status list entry",
                )

            format = (
                self._config.mdoc_format
                if credential_type.lower() == "mdoc"
                else self._config.sd_jwt_format
            )

            # Set status back to valid (0)
            await self._status_list_manager.set_status(
                tenant_id=tenant_id,
                index=status_list_index,
                status=0,  # valid
                format=format,
            )

            # Update credential in repository
            await self._credential_repo.update_status(
                credential_id=credential_id,
                status="active",
                revoked_at=None,
                reason=f"Reinstated by {reinstated_by}",
            )

            if self._config.auto_publish:
                await self._status_list_manager.publish(tenant_id, format)

            logger.info(
                "Credential reinstated",
                extra={
                    "credential_id": credential_id,
                    "tenant_id": tenant_id,
                    "reinstated_by": reinstated_by,
                },
            )

            return RevocationResult(
                success=True,
                credential_id=credential_id,
                status_list_index=status_list_index,
                format=format,
                reason="reinstated",
            )

        except Exception as e:
            logger.exception(f"Error reinstating credential {credential_id}")
            return RevocationResult(
                success=False,
                credential_id=credential_id,
                error=str(e),
            )

    @property
    def config(self) -> RevocationConfig:
        """Get the revocation configuration."""
        return self._config
