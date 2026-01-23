"""Status list manager for credential revocation.

This module provides management of status lists for credential revocation,
supporting both IETF Token Status List and W3C Bitstring Status List formats.
"""

import asyncio
import base64
import hashlib
import logging
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Protocol

from .service import StatusListFormat

logger = logging.getLogger(__name__)


class StatusListType(str, Enum):
    """Type of status list."""

    TOKEN = "token"  # IETF Token Status List
    BITSTRING = "bitstring"  # W3C Bitstring Status List


@dataclass
class StatusListEntry:
    """Entry in a status list.

    Attributes:
        index: Position in the status list
        status: Status value (0=valid, 1=revoked for bitstring; 0-255 for token)
        credential_id: ID of the credential at this index
        updated_at: When the status was last updated
    """

    index: int
    status: int
    credential_id: Optional[str] = None
    updated_at: Optional[datetime] = None


@dataclass
class StatusList:
    """A status list for revocation checking.

    Attributes:
        id: Unique status list identifier
        tenant_id: Organization/tenant ID
        format: Status list format
        size: Total size of the list
        bits_per_status: Bits per status entry (1 for bitstring, 8 for token)
        data: Raw status data
        version: Version number for updates
        published_at: When last published
        url: URL where the list is published
    """

    id: str
    tenant_id: str
    format: StatusListFormat
    size: int
    bits_per_status: int
    data: bytes
    version: int = 0
    published_at: Optional[datetime] = None
    url: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


class IStatusListRepository(Protocol):
    """Protocol for status list storage."""

    async def get(self, tenant_id: str, format: StatusListFormat) -> Optional[StatusList]:
        """Get a status list by tenant and format."""
        ...

    async def save(self, status_list: StatusList) -> bool:
        """Save or update a status list."""
        ...

    async def get_next_index(self, tenant_id: str, format: StatusListFormat) -> int:
        """Get the next available index."""
        ...

    async def record_allocation(
        self,
        tenant_id: str,
        format: StatusListFormat,
        index: int,
        credential_id: str,
    ) -> bool:
        """Record an index allocation."""
        ...


class StatusListManager:
    """Manager for credential status lists.

    Handles creation, updating, and publishing of status lists in both
    Token Status List (IETF) and Bitstring Status List (W3C) formats.

    Token Status List (for mDoc/CWT):
        - Uses 8 bits per status entry
        - Supports values 0-255
        - CBOR encoded for embedding in CWT
        - Compressed with DEFLATE

    Bitstring Status List (for SD-JWT VC):
        - Uses 1 bit per status entry
        - Binary revoked/not revoked
        - Base64url encoded
        - Compressed with GZIP

    Example:
        manager = StatusListManager(
            repository=status_list_repo,
            publisher=status_list_publisher,
            base_url="https://status.example.com",
        )

        # Allocate index for new credential
        index = await manager.allocate_index("org-123", StatusListFormat.TOKEN_STATUS_LIST)

        # Revoke a credential
        await manager.set_status("org-123", index, status=1, format=StatusListFormat.TOKEN_STATUS_LIST)

        # Publish updated list
        url = await manager.publish("org-123", StatusListFormat.TOKEN_STATUS_LIST)
    """

    def __init__(
        self,
        repository: IStatusListRepository,
        base_url: str = "https://status.example.com",
        default_size: int = 131072,  # 16KB worth of bits
    ):
        """Initialize the status list manager.

        Args:
            repository: Storage backend for status lists
            base_url: Base URL for published status lists
            default_size: Default size for new status lists
        """
        self._repository = repository
        self._base_url = base_url
        self._default_size = default_size
        self._locks: dict[str, asyncio.Lock] = {}

    def _get_lock(self, key: str) -> asyncio.Lock:
        """Get or create a lock for a key."""
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()
        return self._locks[key]

    async def get_or_create(
        self,
        tenant_id: str,
        format: StatusListFormat,
    ) -> StatusList:
        """Get an existing status list or create a new one.

        Args:
            tenant_id: Organization/tenant ID
            format: Status list format

        Returns:
            StatusList instance
        """
        lock_key = f"{tenant_id}:{format.value}"
        async with self._get_lock(lock_key):
            status_list = await self._repository.get(tenant_id, format)

            if status_list is None:
                status_list = self._create_empty_list(tenant_id, format)
                await self._repository.save(status_list)

            return status_list

    def _create_empty_list(
        self,
        tenant_id: str,
        format: StatusListFormat,
    ) -> StatusList:
        """Create an empty status list.

        Args:
            tenant_id: Organization/tenant ID
            format: Status list format

        Returns:
            New empty StatusList
        """
        import uuid

        if format == StatusListFormat.TOKEN_STATUS_LIST:
            # Token status list: 1 byte per entry
            size = self._default_size
            bits_per_status = 8
            data = bytes(size)  # All zeros = all valid
        else:
            # Bitstring: 1 bit per entry
            size = self._default_size
            bits_per_status = 1
            byte_size = (size + 7) // 8
            data = bytes(byte_size)  # All zeros = all valid

        return StatusList(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            format=format,
            size=size,
            bits_per_status=bits_per_status,
            data=data,
        )

    async def allocate_index(
        self,
        tenant_id: str,
        format: StatusListFormat,
    ) -> int:
        """Allocate a new index in the status list.

        Args:
            tenant_id: Organization/tenant ID
            format: Status list format

        Returns:
            Allocated index

        Raises:
            ValueError: If the status list is full
        """
        status_list = await self.get_or_create(tenant_id, format)

        next_index = await self._repository.get_next_index(tenant_id, format)

        if next_index >= status_list.size:
            raise ValueError(f"Status list full for tenant {tenant_id}")

        return next_index

    async def set_status(
        self,
        tenant_id: str,
        index: int,
        status: int,
        format: StatusListFormat,
    ) -> bool:
        """Set the status at a specific index.

        Args:
            tenant_id: Organization/tenant ID
            index: Index in the status list
            status: Status value (0=valid, 1=revoked, etc.)
            format: Status list format

        Returns:
            True if successful

        Raises:
            ValueError: If index is out of range or status is invalid
        """
        lock_key = f"{tenant_id}:{format.value}"
        async with self._get_lock(lock_key):
            status_list = await self.get_or_create(tenant_id, format)

            if index < 0 or index >= status_list.size:
                raise ValueError(f"Index {index} out of range [0, {status_list.size})")

            if format == StatusListFormat.TOKEN_STATUS_LIST:
                if status < 0 or status > 255:
                    raise ValueError(f"Status {status} out of range [0, 255] for token status list")
                # Direct byte update
                data = bytearray(status_list.data)
                data[index] = status
                status_list.data = bytes(data)
            else:
                if status not in (0, 1):
                    raise ValueError(f"Status {status} must be 0 or 1 for bitstring status list")
                # Bit update
                data = bytearray(status_list.data)
                byte_index = index // 8
                bit_index = index % 8
                if status:
                    data[byte_index] |= (1 << (7 - bit_index))
                else:
                    data[byte_index] &= ~(1 << (7 - bit_index))
                status_list.data = bytes(data)

            status_list.version += 1
            status_list.updated_at = datetime.utcnow()

            await self._repository.save(status_list)

            logger.debug(
                "Status updated",
                extra={
                    "tenant_id": tenant_id,
                    "index": index,
                    "status": status,
                    "format": format.value,
                },
            )

            return True

    async def get_status(
        self,
        tenant_id: str,
        index: int,
        format: StatusListFormat,
    ) -> int:
        """Get the status at a specific index.

        Args:
            tenant_id: Organization/tenant ID
            index: Index in the status list
            format: Status list format

        Returns:
            Status value at the index
        """
        status_list = await self.get_or_create(tenant_id, format)

        if index < 0 or index >= status_list.size:
            raise ValueError(f"Index {index} out of range [0, {status_list.size})")

        if format == StatusListFormat.TOKEN_STATUS_LIST:
            return status_list.data[index]
        else:
            byte_index = index // 8
            bit_index = index % 8
            return (status_list.data[byte_index] >> (7 - bit_index)) & 1

    async def publish(
        self,
        tenant_id: str,
        format: StatusListFormat,
    ) -> str:
        """Publish the status list and return its URL.

        Args:
            tenant_id: Organization/tenant ID
            format: Status list format

        Returns:
            URL where the status list is published
        """
        status_list = await self.get_or_create(tenant_id, format)

        # Compress the data
        if format == StatusListFormat.TOKEN_STATUS_LIST:
            compressed = self._compress_token_status_list(status_list.data)
            content_type = "application/cbor"
            extension = "cbor"
        else:
            compressed = self._compress_bitstring_status_list(status_list.data)
            content_type = "application/json"
            extension = "json"

        # Generate URL
        list_hash = hashlib.sha256(status_list.data).hexdigest()[:16]
        url = f"{self._base_url}/{tenant_id}/{format.value}/{list_hash}.{extension}"

        # Update status list
        status_list.published_at = datetime.utcnow()
        status_list.url = url
        await self._repository.save(status_list)

        logger.info(
            "Status list published",
            extra={
                "tenant_id": tenant_id,
                "format": format.value,
                "url": url,
                "version": status_list.version,
            },
        )

        return url

    def _compress_token_status_list(self, data: bytes) -> bytes:
        """Compress data for Token Status List (DEFLATE).

        Args:
            data: Raw status data

        Returns:
            Compressed data
        """
        return zlib.compress(data, level=9)

    def _compress_bitstring_status_list(self, data: bytes) -> str:
        """Compress and encode data for Bitstring Status List.

        Args:
            data: Raw bitstring data

        Returns:
            Base64url encoded GZIP compressed data
        """
        compressed = zlib.compress(data, level=9)
        return base64.urlsafe_b64encode(compressed).decode("ascii").rstrip("=")

    def encode_status_list_token(
        self,
        status_list: StatusList,
        issuer: str,
        subject: str,
    ) -> dict[str, Any]:
        """Encode a Token Status List for embedding in CWT/JWT.

        Creates the status list token structure per IETF draft.

        Args:
            status_list: The status list to encode
            issuer: Issuer identifier
            subject: Subject identifier (status list ID)

        Returns:
            Dictionary suitable for JWT/CWT encoding
        """
        compressed = self._compress_token_status_list(status_list.data)

        return {
            "iss": issuer,
            "sub": subject,
            "iat": int(datetime.utcnow().timestamp()),
            "status_list": {
                "bits": status_list.bits_per_status,
                "lst": base64.urlsafe_b64encode(compressed).decode("ascii").rstrip("="),
            },
        }

    def encode_bitstring_status_list(
        self,
        status_list: StatusList,
        issuer: str,
        status_purpose: str = "revocation",
    ) -> dict[str, Any]:
        """Encode a Bitstring Status List credential.

        Creates the BitstringStatusListCredential structure per W3C spec.

        Args:
            status_list: The status list to encode
            issuer: Issuer DID
            status_purpose: Purpose of the status list

        Returns:
            Dictionary for BitstringStatusListCredential
        """
        encoded_list = self._compress_bitstring_status_list(status_list.data)

        return {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
            ],
            "id": status_list.url or f"urn:uuid:{status_list.id}",
            "type": ["VerifiableCredential", "BitstringStatusListCredential"],
            "issuer": issuer,
            "validFrom": status_list.created_at.isoformat(),
            "credentialSubject": {
                "id": f"{status_list.url}#list",
                "type": "BitstringStatusList",
                "statusPurpose": status_purpose,
                "encodedList": encoded_list,
            },
        }


class InMemoryStatusListRepository:
    """In-memory implementation of IStatusListRepository for testing."""

    def __init__(self):
        self._lists: dict[str, StatusList] = {}
        self._next_indices: dict[str, int] = {}
        self._allocations: dict[str, list[tuple[int, str]]] = {}

    def _key(self, tenant_id: str, format: StatusListFormat) -> str:
        return f"{tenant_id}:{format.value}"

    async def get(self, tenant_id: str, format: StatusListFormat) -> Optional[StatusList]:
        return self._lists.get(self._key(tenant_id, format))

    async def save(self, status_list: StatusList) -> bool:
        key = self._key(status_list.tenant_id, status_list.format)
        self._lists[key] = status_list
        return True

    async def get_next_index(self, tenant_id: str, format: StatusListFormat) -> int:
        key = self._key(tenant_id, format)
        index = self._next_indices.get(key, 0)
        self._next_indices[key] = index + 1
        return index

    async def record_allocation(
        self,
        tenant_id: str,
        format: StatusListFormat,
        index: int,
        credential_id: str,
    ) -> bool:
        key = self._key(tenant_id, format)
        if key not in self._allocations:
            self._allocations[key] = []
        self._allocations[key].append((index, credential_id))
        return True
