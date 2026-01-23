"""
Auth Cache Service.

This module provides a unified cache interface for authentication state,
using the MMF cache infrastructure. It handles PKCE state, refresh tokens,
ID tokens, and session invalidation with consistent patterns and metrics.

Usage:
    # With PluginContext
    auth_cache = AuthCacheService.from_context(plugin_context)
    
    # Or with explicit cache manager
    cache_manager = RedisCacheManager(redis_client, prefix_config, metrics)
    auth_cache = AuthCacheService(cache_manager, config)
    
    # Store PKCE state
    await auth_cache.store_pkce_state(state, code_verifier, redirect_uri)
    
    # Consume PKCE state (single-use)
    state_data = await auth_cache.consume_pkce_state(state)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mmf.core.cache import ICacheManager
    from mmf.core.plugins import PluginContext

logger = logging.getLogger(__name__)


# =============================================================================
# Configuration
# =============================================================================


@dataclass
class AuthCacheConfig:
    """
    Configuration for auth caching.
    
    Defines TTLs for different types of auth state and feature flags.
    """
    
    # PKCE state TTL (typically 10 minutes for OAuth flow)
    pkce_state_ttl_seconds: int = 600
    
    # Session TTL (typically 30 minutes, refreshed on activity)
    session_ttl_seconds: int = 1800
    
    # Refresh token TTL (typically 7 days)
    refresh_token_ttl_seconds: int = 604800
    
    # ID token TTL (used for SSO logout, matches session)
    id_token_ttl_seconds: int = 1800
    
    # Enable detailed logging
    debug_logging: bool = False

    @classmethod
    def from_env(cls) -> AuthCacheConfig:
        """Create configuration from environment variables."""
        import os
        
        return cls(
            pkce_state_ttl_seconds=int(
                os.environ.get("AUTH_PKCE_STATE_TTL", "600")
            ),
            session_ttl_seconds=int(
                os.environ.get("SESSION_TTL_SECONDS", "1800")
            ),
            refresh_token_ttl_seconds=int(
                os.environ.get("AUTH_REFRESH_TOKEN_TTL", "604800")
            ),
            id_token_ttl_seconds=int(
                os.environ.get("AUTH_ID_TOKEN_TTL", "1800")
            ),
            debug_logging=os.environ.get("AUTH_DEBUG_LOGGING", "false").lower() == "true",
        )


# =============================================================================
# Auth Cache Service
# =============================================================================


@dataclass
class PKCEStateData:
    """PKCE state data stored during OAuth flow."""
    
    code_verifier: str
    redirect_uri: str
    created_at: str
    
    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary for storage."""
        return {
            "code_verifier": self.code_verifier,
            "redirect_uri": self.redirect_uri,
            "created_at": self.created_at,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PKCEStateData:
        """Create from dictionary."""
        return cls(
            code_verifier=data["code_verifier"],
            redirect_uri=data.get("redirect_uri", "/"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


class AuthCacheService:
    """
    Unified cache service for authentication state.
    
    Uses MMF cache patterns:
    - Write-through for session state (immediate write to cache)
    - Read-through with lazy loading for session validation
    - Ephemeral storage for PKCE state (auto-expire, single-use)
    
    Multi-Tenant Redis Key Patterns (with organization hash tags):
      - PKCE:         marty:{org-id}:pkce:{state}
      - Refresh:      marty:{org-id}:refresh:{session_id}
      - ID Token:     marty:{org-id}:id_token:{session_id}
      - Session:      marty:{org-id}:session:{session_id}
    
    Hash tags {...} ensure all auth data for an organization hashes to the same
    Redis Cluster slot, enabling efficient multi-key operations.
    
    This service is designed to work with MMF's PluginContext or
    as a standalone service with an injected ICacheManager.
    """

    # Cache key prefixes (within the namespace)
    PKCE_PREFIX = "pkce"
    REFRESH_TOKEN_PREFIX = "refresh"
    ID_TOKEN_PREFIX = "id_token"
    SESSION_PREFIX = "session"

    def __init__(
        self,
        cache_manager: "ICacheManager",
        config: AuthCacheConfig | None = None,
    ):
        """
        Initialize auth cache service.
        
        Args:
            cache_manager: ICacheManager implementation (e.g., RedisCacheManager)
            config: Auth cache configuration
        """
        self._cache = cache_manager
        self.config = config or AuthCacheConfig()
        self._logger = logging.getLogger(__name__)

    @classmethod
    def from_context(
        cls,
        context: "PluginContext",
        config: AuthCacheConfig | None = None,
    ) -> "AuthCacheService":
        """
        Create AuthCacheService from MMF PluginContext.
        
        Args:
            context: MMF PluginContext with cache manager
            config: Optional auth cache configuration
            
        Returns:
            Configured AuthCacheService instance
            
        Raises:
            ValueError: If context has no cache manager
        """
        if context.cache is None:
            raise ValueError(
                "PluginContext must have a cache manager. "
                "Use PluginContextBuilder.with_cache() to configure."
            )
        return cls(cache_manager=context.cache, config=config)

    # =========================================================================
    # PKCE State (Ephemeral, Single-Use)
    # =========================================================================

    async def store_pkce_state(
        self,
        state: str,
        code_verifier: str,
        redirect_uri: str,
        organization_id: str | None = None,
    ) -> None:
        """
        Store PKCE state for OAuth flow.
        
        The state is stored with a short TTL and should be consumed
        exactly once during the OAuth callback.
        
        Args:
            state: OAuth state parameter (used as key)
            code_verifier: PKCE code verifier
            redirect_uri: Original redirect URI to return to
            organization_id: Organization context for multi-tenant isolation (recommended)
        """
        # Multi-tenant key pattern with hash tags for Redis Cluster
        if organization_id:
            key = f"{{{organization_id}}}:{self.PKCE_PREFIX}:{state}"
        else:
            # Fallback for backwards compatibility (deprecated)
            key = f"{self.PKCE_PREFIX}:{state}"
            logger.warning(
                f"PKCE state stored without organization_id. "
                "This breaks multi-tenant isolation and is deprecated."
            )
        
        state_data = PKCEStateData(
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        
        await self._cache.set(
            key,
            state_data.to_dict(),
            ttl=self.config.pkce_state_ttl_seconds,
        )
        
        if self.config.debug_logging:
            self._logger.debug(f"Stored PKCE state: {state[:20]}... (org: {organization_id})")

    async def consume_pkce_state(
        self,
        state: str,
        organization_id: str | None = None,
    ) -> PKCEStateData | None:
        """
        Retrieve and delete PKCE state (single-use pattern).
        
        This atomically gets and deletes the state to prevent replay attacks.
        
        Args:
            state: OAuth state parameter
            organization_id: Organization context for scoped lookup
            
        Returns:
            PKCEStateData if found, None if not found or expired
        """
        # Try org-scoped key first, fall back to legacy key
        if organization_id:
            key = f"{{{organization_id}}}:{self.PKCE_PREFIX}:{state}"
        else:
            key = f"{self.PKCE_PREFIX}:{state}"
        
        data = await self._cache.get_and_delete(key)
        
        if data is None:
            self._logger.warning(f"PKCE state not found or expired: {state[:20]}... (org: {organization_id})")
            return None
        
        if self.config.debug_logging:
            self._logger.debug(f"Consumed PKCE state: {state[:20]}... (org: {organization_id})")
        
        # Handle both dict and string data (backwards compatibility)
        if isinstance(data, str):
            try:
                import ast
                data = ast.literal_eval(data)
            except (ValueError, SyntaxError):
                data = json.loads(data)
        
        return PKCEStateData.from_dict(data)

    async def pkce_state_exists(
        self,
        state: str,
        organization_id: str | None = None,
    ) -> bool:
        """
        Check if PKCE state exists (without consuming it).
        
        Args:
            state: OAuth state parameter
            organization_id: Organization context for scoped lookup
            
        Returns:
            True if state exists
        """
        # Try org-scoped key first, fall back to legacy key
        if organization_id:
            key = f"{{{organization_id}}}:{self.PKCE_PREFIX}:{state}"
        else:
            key = f"{self.PKCE_PREFIX}:{state}"
        return await self._cache.exists(key)

    # =========================================================================
    # Token Storage
    # =========================================================================

    async def store_refresh_token(
        self,
        session_id: str,
        refresh_token: str,
        ttl: int | None = None,
        organization_id: str | None = None,
    ) -> None:
        """
        Store refresh token for session.
        
        Args:
            session_id: Session identifier
            refresh_token: OAuth refresh token
            ttl: Optional TTL override
            organization_id: Organization context for multi-tenant isolation
        """
        # Multi-tenant key pattern with hash tags
        if organization_id:
            key = f"{{{organization_id}}}:{self.REFRESH_TOKEN_PREFIX}:{session_id}"
        else:
            key = f"{self.REFRESH_TOKEN_PREFIX}:{session_id}"
            logger.warning(
                f"Refresh token stored without organization_id for session {session_id[:20]}..."
            )
        
        await self._cache.set(
            key,
            refresh_token,
            ttl=ttl or self.config.refresh_token_ttl_seconds,
        )
        
        if self.config.debug_logging:
            self._logger.debug(f"Stored refresh token for session: {session_id[:20]}... (org: {organization_id})")

    async def get_refresh_token(
        self,
        session_id: str,
        organization_id: str | None = None,
    ) -> str | None:
        """
        Get refresh token for session.
        
        Args:
            session_id: Session identifier
            organization_id: Organization context for scoped lookup
            
        Returns:
            Refresh token or None if not found
        """
        # Try org-scoped key first, fall back to legacy key
        if organization_id:
            key = f"{{{organization_id}}}:{self.REFRESH_TOKEN_PREFIX}:{session_id}"
        else:
            key = f"{self.REFRESH_TOKEN_PREFIX}:{session_id}"
        return await self._cache.get(key)

    async def store_id_token(
        self,
        session_id: str,
        id_token: str,
        ttl: int | None = None,
        organization_id: str | None = None,
    ) -> None:
        """
        Store ID token for session (used for SSO logout).
        
        Args:
            session_id: Session identifier
            id_token: OIDC ID token
            ttl: Optional TTL override
            organization_id: Organization context for multi-tenant isolation
        """
        # Multi-tenant key pattern with hash tags
        if organization_id:
            key = f"{{{organization_id}}}:{self.ID_TOKEN_PREFIX}:{session_id}"
        else:
            key = f"{self.ID_TOKEN_PREFIX}:{session_id}"
            logger.warning(
                f"ID token stored without organization_id for session {session_id[:20]}..."
            )
        
        await self._cache.set(
            key,
            id_token,
            ttl=ttl or self.config.id_token_ttl_seconds,
        )
        
        if self.config.debug_logging:
            self._logger.debug(f"Stored ID token for session: {session_id[:20]}... (org: {organization_id})")

    async def get_id_token(
        self,
        session_id: str,
        organization_id: str | None = None,
    ) -> str | None:
        """
        Get ID token for session.
        
        Args:
            session_id: Session identifier
            organization_id: Organization context for scoped lookup
            
        Returns:
            ID token or None if not found
        """
        # Try org-scoped key first, fall back to legacy key
        if organization_id:
            key = f"{{{organization_id}}}:{self.ID_TOKEN_PREFIX}:{session_id}"
        else:
            key = f"{self.ID_TOKEN_PREFIX}:{session_id}"
        return await self._cache.get(key)

    # =========================================================================
    # Session Invalidation
    # =========================================================================

    async def invalidate_session_tokens(
        self,
        session_id: str,
        organization_id: str | None = None,
    ) -> None:
        """
        Remove all cached tokens for a session.
        
        Called during logout to ensure all session-related tokens are cleared.
        
        Args:
            session_id: Session identifier
            organization_id: Organization context for scoped deletion
        """
        # Delete both org-scoped and legacy keys for backwards compatibility
        if organization_id:
            refresh_key = f"{{{organization_id}}}:{self.REFRESH_TOKEN_PREFIX}:{session_id}"
            id_token_key = f"{{{organization_id}}}:{self.ID_TOKEN_PREFIX}:{session_id}"
        else:
            refresh_key = f"{self.REFRESH_TOKEN_PREFIX}:{session_id}"
            id_token_key = f"{self.ID_TOKEN_PREFIX}:{session_id}"
        
        await self._cache.delete(refresh_key)
        await self._cache.delete(id_token_key)
        
        self._logger.info(f"Invalidated tokens for session: {session_id[:20]}... (org: {organization_id})")

    # =========================================================================
    # Session State (Optional - for advanced use cases)
    # =========================================================================

    async def store_session_state(
        self,
        session_id: str,
        state: dict[str, Any],
        ttl: int | None = None,
    ) -> None:
        """
        Store arbitrary session state.
        
        Args:
            session_id: Session identifier
            state: Session state dictionary
            ttl: Optional TTL override
        """
        key = f"{self.SESSION_PREFIX}:{session_id}"
        await self._cache.set(
            key,
            state,
            ttl=ttl or self.config.session_ttl_seconds,
        )

    async def get_session_state(self, session_id: str) -> dict[str, Any] | None:
        """
        Get session state.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session state dictionary or None
        """
        key = f"{self.SESSION_PREFIX}:{session_id}"
        return await self._cache.get(key)

    async def extend_session(self, session_id: str, ttl: int | None = None) -> bool:
        """
        Extend session TTL.
        
        Args:
            session_id: Session identifier
            ttl: New TTL in seconds
            
        Returns:
            True if session existed and was extended
        """
        key = f"{self.SESSION_PREFIX}:{session_id}"
        return await self._cache.expire(key, ttl or self.config.session_ttl_seconds)


# =============================================================================
# Factory Functions
# =============================================================================


async def create_auth_cache_service(
    redis_url: str | None = None,
    key_prefix: str = "marty:auth",
    config: AuthCacheConfig | None = None,
) -> AuthCacheService:
    """
    Create an AuthCacheService with Redis backend.
    
    Convenience factory for creating a fully-configured service.
    
    Args:
        redis_url: Redis connection URL (defaults to env var)
        key_prefix: Key prefix for auth cache namespace
        config: Auth cache configuration
        
    Returns:
        Configured AuthCacheService
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
        plugin_prefix="auth",
        component_prefix="",
    )
    
    metrics = CacheMetrics(service_name="marty-ui")
    
    cache_manager = RedisCacheManager(
        redis_client=redis_client,
        prefix_config=prefix_config,
        metrics=metrics,
    )
    
    return AuthCacheService(
        cache_manager=cache_manager,
        config=config or AuthCacheConfig.from_env(),
    )


__all__ = [
    "AuthCacheConfig",
    "AuthCacheService",
    "PKCEStateData",
    "create_auth_cache_service",
]
