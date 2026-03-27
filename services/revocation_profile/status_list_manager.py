"""Status List Manager

Manages Token Status Lists (IETF) and Bitstring Status Lists (W3C).
Originally migrated from the retired monolith revocation implementation.

Storage:
- Uses MMF framework ICacheManager for Redis persistence
- Falls back to InMemoryCache when Redis unavailable
"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, Optional, Protocol

if TYPE_CHECKING:
    from mmf.core.cache import ICacheManager

logger = logging.getLogger(__name__)


class StatusListFormat(str, Enum):
    """Status list format types."""
    TOKEN_STATUS_LIST = "token"  # IETF Token Status List
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
            # Get status list directly from repository to avoid double-locking
            status_list = await self._repository.get(tenant_id, format)
            
            if status_list is None:
                status_list = self._create_empty_list(tenant_id, format)
                await self._repository.save(status_list)

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
                "Status updated for tenant=%s index=%d status=%d format=%s",
                tenant_id, index, status, format.value
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
            "Status list published: tenant=%s format=%s url=%s version=%d",
            tenant_id, format.value, url, status_list.version
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


class StatusListRepository:
    """Redis-backed repository using MMF framework's ICacheManager.
    
    Uses MMF's cache infrastructure for persistent storage following the pattern
    from the retired monolith issuance Redis storage adapter.
    
    Key format: {tenant_id}:status_list:{format}
    """
    
    def __init__(self, cache_manager: "ICacheManager"):
        """Initialize repository with MMF cache manager.
        
        Args:
            cache_manager: MMF cache manager (RedisCacheManager or InMemoryCache)
        """
        self._cache = cache_manager
        self._next_index_suffix = ":next_index"
        self._allocations_suffix = ":allocations"
    
    def _make_key(self, tenant_id: str, format: StatusListFormat, suffix: str = "") -> str:
        """Create cache key with hash tags for cluster support."""
        return f"{{{tenant_id}}}:status_list:{format.value}{suffix}"
    
    async def get(self, tenant_id: str, format: StatusListFormat) -> Optional[StatusList]:
        """Get status list from cache."""
        key = self._make_key(tenant_id, format)
        data = await self._cache.get(key)
        if not data:
            return None
        
        # Deserialize
        status_dict = json.loads(data)
        return StatusList(
            id=status_dict["id"],
            tenant_id=status_dict["tenant_id"],
            format=StatusListFormat(status_dict["format"]),
            size=status_dict["size"],
            bits_per_status=status_dict["bits_per_status"],
            data=base64.b64decode(status_dict["data"]),
            version=status_dict.get("version", 0),
            published_at=datetime.fromisoformat(status_dict["published_at"]) if status_dict.get("published_at") else None,
            url=status_dict.get("url"),
            created_at=datetime.fromisoformat(status_dict["created_at"]),
            updated_at=datetime.fromisoformat(status_dict["updated_at"]),
        )
    
    async def save(self, status_list: StatusList) -> bool:
        """Save status list to cache."""
        key = self._make_key(status_list.tenant_id, status_list.format)
        
        # Serialize
        status_dict = {
            "id": status_list.id,
            "tenant_id": status_list.tenant_id,
            "format": status_list.format.value,
            "size": status_list.size,
            "bits_per_status": status_list.bits_per_status,
            "data": base64.b64encode(status_list.data).decode("ascii"),
            "version": status_list.version,
            "published_at": status_list.published_at.isoformat() if status_list.published_at else None,
            "url": status_list.url,
            "created_at": status_list.created_at.isoformat(),
            "updated_at": status_list.updated_at.isoformat(),
        }
        
        await self._cache.set(key, json.dumps(status_dict))
        logger.debug(f"Saved status list to cache: {key}")
        return True
    
    async def get_next_index(self, tenant_id: str, format: StatusListFormat) -> int:
        """Get and increment next available index atomically."""
        key = self._make_key(tenant_id, format, self._next_index_suffix)
        
        # Try to get current value
        data = await self._cache.get(key)
        if data:
            index = int(data)
        else:
            index = 0
        
        # Increment and store
        next_index = index + 1
        await self._cache.set(key, str(next_index))
        return index
    
    async def record_allocation(
        self,
        tenant_id: str,
        format: StatusListFormat,
        index: int,
        credential_id: str,
    ) -> bool:
        """Record an index allocation."""
        key = self._make_key(tenant_id, format, self._allocations_suffix)
        
        # Get existing allocations
        data = await self._cache.get(key)
        if data:
            try:
                allocations = json.loads(data)
            except json.JSONDecodeError:
                allocations = []
        else:
            allocations = []
        
        # Add new allocation
        allocation = {
            "index": index,
            "credential_id": credential_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        allocations.append(allocation)
        
        # Save back
        await self._cache.set(key, json.dumps(allocations))
        return True


# =============================================================================
# Simple Cache Adapters (for standalone service)
# =============================================================================


class CacheAdapter(Protocol):
    """Simple cache protocol matching MMF ICacheManager interface."""
    
    async def get(self, key: str) -> bytes | None:
        ...
    
    async def set(self, key: str, value: bytes, ttl: int | None = None) -> bool:
        ...


class RedisCacheAdapter:
    """Minimal Redis cache adapter for standalone service."""
    
    def __init__(self, redis_client, key_prefix: str = "marty"):
        self._redis = redis_client
        self._prefix = key_prefix
    
    def _make_key(self, key: str) -> str:
        return f"{self._prefix}:{key}"
    
    async def get(self, key: str) -> bytes | None:
        full_key = self._make_key(key)
        return await self._redis.get(full_key)
    
    async def set(self, key: str, value: bytes, ttl: int | None = None) -> bool:
        full_key = self._make_key(key)
        if ttl:
            await self._redis.setex(full_key, ttl, value)
        else:
            await self._redis.set(full_key, value)
        return True


def create_status_list_repository() -> IStatusListRepository:
    """Create a status list repository using Redis.
    
    Uses redis.asyncio with proper key prefixing.
    Follows MMF patterns but keeps dependencies minimal for standalone service.
    
    Raises:
        ImportError: If redis package is not installed
        Exception: If Redis connection fails
        
    Returns:
        Status list repository implementation
    """
    import redis.asyncio as redis_async
    
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    
    # Create Redis client (will raise exception if connection fails)
    redis_client = redis_async.from_url(redis_url, decode_responses=False)
    
    # Create cache manager wrapper
    cache_manager = RedisCacheAdapter(redis_client, key_prefix="marty:revocation")
    
    logger.info(f"Using Redis-backed StatusListRepository with URL: {redis_url}")
    return StatusListRepository(cache_manager)
