"""
Redis Session Repository Adapter

Implements SessionRepositoryPort and PKCEStateRepositoryPort
using Redis for session storage.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import redis.asyncio as redis

from ...application.ports import PKCEStateRepositoryPort, SessionRepositoryPort
from ...domain.entities import PKCEState, Session

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class RedisSessionRepository(SessionRepositoryPort):
    """
    Redis-based session repository.
    
    Stores sessions as JSON with automatic TTL-based expiration.
    Uses key prefix for namespace isolation.
    """
    
    def __init__(
        self,
        redis_client: redis.Redis,
        key_prefix: str = "marty:session:",
        user_sessions_prefix: str = "marty:user_sessions:",
    ):
        self.redis = redis_client
        self.key_prefix = key_prefix
        self.user_sessions_prefix = user_sessions_prefix
    
    def _session_key(self, session_id: str) -> str:
        """Get Redis key for a session."""
        return f"{self.key_prefix}{session_id}"
    
    def _user_sessions_key(self, user_id: str) -> str:
        """Get Redis key for user's session set."""
        return f"{self.user_sessions_prefix}{user_id}"
    
    async def save(self, session: Session) -> None:
        """Save a session with TTL."""
        key = self._session_key(session.session_id)
        ttl = session.remaining_ttl_seconds
        
        if ttl <= 0:
            # Session already expired, don't save
            return
        
        # Store session as JSON
        session_data = json.dumps(session.to_dict())
        await self.redis.setex(key, ttl, session_data)
        
        # Track session in user's session set
        user_key = self._user_sessions_key(session.user.user_id)
        await self.redis.sadd(user_key, session.session_id)
        # Set TTL on user sessions set (cleanup old entries)
        await self.redis.expire(user_key, ttl + 3600)  # Extra hour buffer
        
        logger.debug(f"Saved session {session.session_id[:8]}... with TTL {ttl}s")
    
    async def get(self, session_id: str) -> Session | None:
        """Get a session by ID."""
        key = self._session_key(session_id)
        data = await self.redis.get(key)
        
        if not data:
            return None
        
        try:
            session_dict = json.loads(data)
            return Session.from_dict(session_dict)
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to deserialize session {session_id}: {e}")
            return None
    
    async def delete(self, session_id: str) -> None:
        """Delete a session."""
        # Get session first to remove from user set
        session = await self.get(session_id)
        if session:
            user_key = self._user_sessions_key(session.user.user_id)
            await self.redis.srem(user_key, session_id)
        
        key = self._session_key(session_id)
        await self.redis.delete(key)
        logger.debug(f"Deleted session {session_id[:8]}...")
    
    async def get_by_user(self, user_id: str) -> list[Session]:
        """Get all sessions for a user."""
        user_key = self._user_sessions_key(user_id)
        session_ids = await self.redis.smembers(user_key)
        
        sessions = []
        invalid_ids = []
        
        for session_id in session_ids:
            session = await self.get(session_id)
            if session and session.is_valid:
                sessions.append(session)
            else:
                invalid_ids.append(session_id)
        
        # Clean up invalid session references
        if invalid_ids:
            await self.redis.srem(user_key, *invalid_ids)
        
        return sessions
    
    async def delete_all_for_user(self, user_id: str) -> int:
        """Delete all sessions for a user."""
        sessions = await self.get_by_user(user_id)
        
        for session in sessions:
            await self.delete(session.session_id)
        
        # Clean up user sessions set
        user_key = self._user_sessions_key(user_id)
        await self.redis.delete(user_key)
        
        return len(sessions)


class RedisPKCEStateRepository(PKCEStateRepositoryPort):
    """
    Redis-based PKCE state repository.
    
    Stores PKCE state with short TTL and supports atomic get-and-delete
    for single-use pattern.
    """
    
    def __init__(
        self,
        redis_client: redis.Redis,
        key_prefix: str = "marty:pkce:",
        ttl_seconds: int = 600,  # 10 minutes
    ):
        self.redis = redis_client
        self.key_prefix = key_prefix
        self.ttl_seconds = ttl_seconds
    
    def _key(self, state: str) -> str:
        """Get Redis key for PKCE state."""
        return f"{self.key_prefix}{state}"
    
    async def save(self, pkce_state: PKCEState) -> None:
        """Save PKCE state with TTL."""
        key = self._key(pkce_state.state)
        data = json.dumps(pkce_state.to_dict())
        await self.redis.setex(key, self.ttl_seconds, data)
        logger.debug(f"Saved PKCE state {pkce_state.state[:20]}...")
    
    async def get_and_delete(self, state: str) -> PKCEState | None:
        """
        Get and atomically delete PKCE state.
        
        Uses GETDEL for atomic operation (single-use pattern).
        """
        key = self._key(state)
        
        # GETDEL is atomic - prevents replay attacks
        data = await self.redis.getdel(key)
        
        if not data:
            return None
        
        try:
            state_dict = json.loads(data)
            return PKCEState.from_dict(state_dict)
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to deserialize PKCE state: {e}")
            return None
