"""Redis adapters for issuance storage (hexagonal architecture).

This module implements the storage port IIssuanceStorage using Redis via
MMF's RedisCacheManager. This adapter provides persistent storage for
credential issuance sessions and offers.

Note: Key storage has been migrated to SpruceIDKeyManager. 
Use get_key_manager() from marty_plugin.adapters.credentials.spruceid.

Usage:
    from issuance.adapters import (
        RedisIssuanceStorage,
        create_issuance_storage,
    )
    
    # Using factory function (recommended)
    issuance_storage = create_issuance_storage()
    
    # Or with explicit cache manager
    cache_manager = RedisCacheManager(redis_client, prefix_config, metrics)
    issuance_storage = RedisIssuanceStorage(cache_manager)
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from issuance.ports import (
    IIssuanceStorage,
    StoredOffer,
    StoredSession,
)

if TYPE_CHECKING:
    from mmf.core.cache import ICacheManager

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================


class IssuanceStorageConfig:
    """Configuration for issuance storage."""
    
    # Default TTLs
    DEFAULT_SESSION_TTL = 86400  # 24 hours
    DEFAULT_OFFER_TTL = 300  # 5 minutes
    
    # Key prefixes within the namespace
    SESSION_ID_PREFIX = "session:id"
    SESSION_TXN_PREFIX = "session:txn"
    SESSION_PAC_PREFIX = "session:pac"
    OFFER_ID_PREFIX = "offer:id"
    OFFER_SESSION_PREFIX = "offer:session"


# =============================================================================
# Redis Issuance Storage Adapter
# =============================================================================


class RedisIssuanceStorage(IIssuanceStorage):
    """Redis adapter for issuance session and offer storage.
    
    Implements IIssuanceStorage using MMF's RedisCacheManager.
    Sessions are indexed by id, transaction_id, and pre_authorized_code
    for efficient lookup during the OID4VCI flow.
    
    Multi-Tenant Redis Key Patterns (with organization hash tags):
      - Session by ID:  {org-id}:session:id:{session_id}
      - Session by TXN: {org-id}:session:txn:{transaction_id}
      - Session by PAC: {org-id}:session:pac:{pre_auth_code}
      - Offer by ID:    {org-id}:offer:id:{offer_id}
      - Offers list:    {org-id}:offer:session:{session_id}
    
    Hash tags {...} ensure all issuance data for an organization hashes to the
    same Redis Cluster slot, enabling efficient multi-key operations.
    """

    def __init__(
        self,
        cache_manager: "ICacheManager",
        config: IssuanceStorageConfig | None = None,
    ):
        """Initialize Redis issuance storage.
        
        Args:
            cache_manager: MMF cache manager (e.g., RedisCacheManager)
            config: Storage configuration
        """
        self._cache = cache_manager
        self._config = config or IssuanceStorageConfig()
        self._logger = logging.getLogger(__name__)

    # =========================================================================
    # Session Operations
    # =========================================================================

    async def store_session(
        self,
        session: StoredSession,
        ttl_seconds: int | None = None,
    ) -> None:
        """Store an issuance session with multiple indexes."""
        ttl = ttl_seconds or self._config.DEFAULT_SESSION_TTL
        session_dict = session.to_dict()
        session_json = json.dumps(session_dict)
        
        # Multi-tenant key pattern with hash tags for Redis Cluster
        # Extract organization_id from session (should be present)
        org_id = session_dict.get("organization_id")
        if org_id:
            org_prefix = f"{{{org_id}}}"
        else:
            # Fallback for sessions without org_id (deprecated)
            org_prefix = ""
            logger.warning(
                f"Session {session.id} stored without organization_id. "
                "This breaks multi-tenant isolation."
            )
        
        # Store by session ID (primary)
        id_key = f"{org_prefix}:{self._config.SESSION_ID_PREFIX}:{session.id}" if org_prefix else f"{self._config.SESSION_ID_PREFIX}:{session.id}"
        await self._cache.set(id_key, session_json, ttl=ttl)
        
        # Index by transaction ID
        txn_key = f"{org_prefix}:{self._config.SESSION_TXN_PREFIX}:{session.transaction_id}" if org_prefix else f"{self._config.SESSION_TXN_PREFIX}:{session.transaction_id}"
        await self._cache.set(txn_key, session_json, ttl=ttl)
        
        # Index by pre-authorized code (if present)
        if session.pre_authorized_code:
            pac_key = f"{org_prefix}:{self._config.SESSION_PAC_PREFIX}:{session.pre_authorized_code}" if org_prefix else f"{self._config.SESSION_PAC_PREFIX}:{session.pre_authorized_code}"
            await self._cache.set(pac_key, session_json, ttl=ttl)
        
        self._logger.debug(
            f"Stored session {session.id}, txn={session.transaction_id}, org={org_id}"
        )

    async def get_session_by_id(self, session_id: str, organization_id: str | None = None) -> StoredSession | None:
        """Get a session by its ID.
        
        Args:
            session_id: Session identifier
            organization_id: Optional organization context for scoped lookup
        """
        # Try org-scoped key first if org_id provided
        if organization_id:
            key = f"{{{organization_id}}}:{self._config.SESSION_ID_PREFIX}:{session_id}"
            session = await self._get_session(key)
            if session:
                return session
        
        # Fall back to legacy key (no org prefix)
        key = f"{self._config.SESSION_ID_PREFIX}:{session_id}"
        return await self._get_session(key)

    async def get_session_by_transaction_id(
        self, transaction_id: str, organization_id: str | None = None
    ) -> StoredSession | None:
        """Get a session by its transaction ID.
        
        Args:
            transaction_id: Transaction identifier
            organization_id: Optional organization context for scoped lookup
        """
        # Try org-scoped key first if org_id provided
        if organization_id:
            key = f"{{{organization_id}}}:{self._config.SESSION_TXN_PREFIX}:{transaction_id}"
            session = await self._get_session(key)
            if session:
                return session
        
        # Fall back to legacy key (no org prefix)
        key = f"{self._config.SESSION_TXN_PREFIX}:{transaction_id}"
        return await self._get_session(key)

    async def get_session_by_pre_auth_code(
        self, pre_authorized_code: str, organization_id: str | None = None
    ) -> StoredSession | None:
        """Get a session by its pre-authorized code.
        
        Args:
            pre_authorized_code: Pre-authorization code
            organization_id: Optional organization context for scoped lookup
        """
        # Try org-scoped key first if org_id provided
        if organization_id:
            key = f"{{{organization_id}}}:{self._config.SESSION_PAC_PREFIX}:{pre_authorized_code}"
            session = await self._get_session(key)
            if session:
                return session
        
        # Fall back to legacy key (no org prefix)
        key = f"{self._config.SESSION_PAC_PREFIX}:{pre_authorized_code}"
        return await self._get_session(key)

    async def _get_session(self, key: str) -> StoredSession | None:
        """Internal helper to get a session by key."""
        data = await self._cache.get(key)
        if data is None:
            return None
        
        try:
            session_dict = json.loads(data)
            return StoredSession.from_dict(session_dict)
        except (json.JSONDecodeError, KeyError) as e:
            self._logger.warning(f"Failed to deserialize session from {key}: {e}")
            return None

    async def update_session(
        self,
        session: StoredSession,
        ttl_seconds: int | None = None,
    ) -> None:
        """Update an existing session (same as store with new data)."""
        await self.store_session(session, ttl_seconds)

    async def delete_session(self, session_id: str) -> bool:
        """Delete a session and all its indexes."""
        # First get the session to find all keys
        session = await self.get_session_by_id(session_id)
        if session is None:
            return False
        
        # Delete all indexes
        keys_to_delete = [
            f"{self._config.SESSION_ID_PREFIX}:{session.id}",
            f"{self._config.SESSION_TXN_PREFIX}:{session.transaction_id}",
        ]
        if session.pre_authorized_code:
            keys_to_delete.append(
                f"{self._config.SESSION_PAC_PREFIX}:{session.pre_authorized_code}"
            )
        
        for key in keys_to_delete:
            await self._cache.delete(key)
        
        self._logger.debug(f"Deleted session {session_id}")
        return True

    # =========================================================================
    # Offer Operations
    # =========================================================================

    async def store_offer(
        self,
        offer: StoredOffer,
        ttl_seconds: int | None = None,
    ) -> None:
        """Store a credential offer with indexes."""
        ttl = ttl_seconds or self._config.DEFAULT_OFFER_TTL
        offer_dict = offer.to_dict()
        offer_json = json.dumps(offer_dict)
        
        # Multi-tenant key pattern with hash tags
        org_id = offer_dict.get("organization_id")
        if org_id:
            org_prefix = f"{{{org_id}}}"
        else:
            org_prefix = ""
            logger.warning(
                f"Offer {offer.id} stored without organization_id. "
                "This breaks multi-tenant isolation."
            )
        
        # Store by offer ID
        id_key = f"{org_prefix}:{self._config.OFFER_ID_PREFIX}:{offer.id}" if org_prefix else f"{self._config.OFFER_ID_PREFIX}:{offer.id}"
        await self._cache.set(id_key, offer_json, ttl=ttl)
        
        # Add to session's offer list (using a set-like pattern)
        session_key = f"{org_prefix}:{self._config.OFFER_SESSION_PREFIX}:{offer.issuance_session_id}" if org_prefix else f"{self._config.OFFER_SESSION_PREFIX}:{offer.issuance_session_id}"
        existing_offers = await self._cache.get(session_key)
        
        if existing_offers:
            try:
                offer_ids = json.loads(existing_offers)
            except json.JSONDecodeError:
                offer_ids = []
        else:
            offer_ids = []
        
        if offer.id not in offer_ids:
            offer_ids.append(offer.id)
            await self._cache.set(session_key, json.dumps(offer_ids), ttl=ttl)
        
        self._logger.debug(
            f"Stored offer {offer.id} for session {offer.issuance_session_id}, org={org_id}"
        )

    async def get_offer_by_id(self, offer_id: str, organization_id: str | None = None) -> StoredOffer | None:
        """Get an offer by its ID.
        
        Args:
            offer_id: Offer identifier
            organization_id: Optional organization context for scoped lookup
        """
        # Try org-scoped key first if org_id provided
        if organization_id:
            key = f"{{{organization_id}}}:{self._config.OFFER_ID_PREFIX}:{offer_id}"
            data = await self._cache.get(key)
            if data:
                try:
                    offer_dict = json.loads(data)
                    return StoredOffer.from_dict(offer_dict)
                except (json.JSONDecodeError, KeyError) as e:
                    self._logger.warning(f"Failed to deserialize offer from {key}: {e}")
        
        # Fall back to legacy key (no org prefix)
        key = f"{self._config.OFFER_ID_PREFIX}:{offer_id}"
        data = await self._cache.get(key)
        
        if data is None:
            return None
        
        try:
            offer_dict = json.loads(data)
            return StoredOffer.from_dict(offer_dict)
        except (json.JSONDecodeError, KeyError) as e:
            self._logger.warning(f"Failed to deserialize offer from {key}: {e}")
            return None

    async def get_offers_by_session(self, session_id: str) -> list[StoredOffer]:
        """Get all offers for a session."""
        session_key = f"{self._config.OFFER_SESSION_PREFIX}:{session_id}"
        data = await self._cache.get(session_key)
        
        if data is None:
            return []
        
        try:
            offer_ids = json.loads(data)
        except json.JSONDecodeError:
            return []
        
        offers = []
        for offer_id in offer_ids:
            offer = await self.get_offer_by_id(offer_id)
            if offer:
                offers.append(offer)
        
        return offers

    async def update_offer(
        self,
        offer: StoredOffer,
        ttl_seconds: int | None = None,
    ) -> None:
        """Update an existing offer."""
        await self.store_offer(offer, ttl_seconds)

    async def delete_offer(self, offer_id: str) -> bool:
        """Delete an offer."""
        offer = await self.get_offer_by_id(offer_id)
        if offer is None:
            return False
        
        # Delete offer itself
        id_key = f"{self._config.OFFER_ID_PREFIX}:{offer_id}"
        await self._cache.delete(id_key)
        
        # Remove from session's offer list
        session_key = f"{self._config.OFFER_SESSION_PREFIX}:{offer.issuance_session_id}"
        existing_offers = await self._cache.get(session_key)
        
        if existing_offers:
            try:
                offer_ids = json.loads(existing_offers)
                if offer_id in offer_ids:
                    offer_ids.remove(offer_id)
                    await self._cache.set(session_key, json.dumps(offer_ids))
            except json.JSONDecodeError:
                pass
        
        self._logger.debug(f"Deleted offer {offer_id}")
        return True


# =============================================================================
# Factory Functions
# =============================================================================


def create_issuance_storage(
    redis_url: str | None = None,
    config: IssuanceStorageConfig | None = None,
) -> RedisIssuanceStorage:
    """Create a RedisIssuanceStorage instance.
    
    Args:
        redis_url: Redis connection URL (defaults to env var REDIS_URL)
        config: Storage configuration
        
    Returns:
        Configured RedisIssuanceStorage
    """
    import os
    import redis.asyncio as redis
    
    from mmf.adapters.cache import RedisCacheManager
    from mmf.core.cache import KeyPrefixConfig
    from mmf.framework.observability.cache_metrics import CacheMetrics
    
    redis_url = redis_url or os.environ.get("REDIS_URL", "redis://localhost:6379/0")
    redis_client = redis.from_url(redis_url, decode_responses=True)
    
    prefix_config = KeyPrefixConfig(
        app_prefix="marty",
        plugin_prefix="issuance",
        component_prefix="",
    )
    
    metrics = CacheMetrics(service_name="marty-ui")
    
    cache_manager = RedisCacheManager(
        redis_client=redis_client,
        prefix_config=prefix_config,
        metrics=metrics,
    )
    
    return RedisIssuanceStorage(
        cache_manager=cache_manager,
        config=config,
    )


__all__ = [
    # Adapters
    "RedisIssuanceStorage",
    # Config
    "IssuanceStorageConfig",
    # Factory functions
    "create_issuance_storage",
]
