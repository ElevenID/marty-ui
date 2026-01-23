"""
API Key Service

Business logic for API key management.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from .models import APIKey, Base, generate_api_key, generate_uuid

logger = logging.getLogger(__name__)


import os


def hash_api_key(key: str) -> str:
    """Hash an API key for storage."""
    return hashlib.sha256(key.encode()).hexdigest()


# Default database path - use /tmp for container compatibility
DEFAULT_DB_PATH = os.environ.get("API_KEYS_DB_PATH", "/tmp/api_keys.db")


class APIKeyService:
    """Service for managing API keys."""

    def __init__(self, database_url: str | None = None):
        """Initialize the API key service."""
        if database_url is None:
            database_url = f"sqlite:///{DEFAULT_DB_PATH}"
        self.engine = create_engine(database_url)
        Base.metadata.create_all(self.engine)
        logger.info("API Key service initialized")

    def _get_session(self) -> Session:
        """Get a new database session."""
        return Session(self.engine)

    def create_key(
        self,
        organization_id: str,
        name: str,
        scopes: List[str],
        created_by: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> tuple[APIKey, str]:
        """
        Create a new API key.
        
        Returns:
            Tuple of (APIKey model, plain text key)
            The plain text key is only returned on creation!
        """
        # Generate the key
        plain_key = generate_api_key()
        key_hash = hash_api_key(plain_key)
        key_prefix = plain_key[:12]  # "mk_" + first 9 chars

        # Create the model
        api_key = APIKey(
            id=generate_uuid(),
            organization_id=organization_id,
            name=name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            created_by=created_by,
            expires_at=expires_at,
        )
        api_key.scopes = scopes

        # Save to database
        with self._get_session() as session:
            session.add(api_key)
            session.commit()
            session.refresh(api_key)
            logger.info(f"Created API key {api_key.id} for org {organization_id}")
            return api_key, plain_key

    def get_key(self, key_id: str, organization_id: Optional[str] = None) -> Optional[APIKey]:
        """Get an API key by ID."""
        with self._get_session() as session:
            query = select(APIKey).where(APIKey.id == key_id)
            if organization_id:
                query = query.where(APIKey.organization_id == organization_id)
            result = session.execute(query).scalar_one_or_none()
            if result:
                session.expunge(result)
            return result

    def list_keys(self, organization_id: str, include_revoked: bool = False, include_expired: bool = False) -> List[APIKey]:
        """List all API keys for an organization."""
        with self._get_session() as session:
            query = select(APIKey).where(APIKey.organization_id == organization_id)
            if not include_revoked:
                query = query.where(APIKey.is_active.is_(True))
            query = query.order_by(APIKey.created_at.desc())
            results = session.execute(query).scalars().all()
            
            # Filter out expired keys unless include_expired is True
            if not include_expired:
                now = datetime.now(timezone.utc)
                results = [
                    r for r in results 
                    if r.expires_at is None or (
                        r.expires_at.replace(tzinfo=timezone.utc) if r.expires_at.tzinfo is None else r.expires_at
                    ) > now
                ]
            
            for r in results:
                session.expunge(r)
            return list(results)

    def validate_key(self, plain_key: str) -> Optional[APIKey]:
        """
        Validate an API key and return the associated APIKey if valid.
        Also updates last_used_at and usage_count.
        """
        key_hash = hash_api_key(plain_key)
        
        with self._get_session() as session:
            api_key = session.execute(
                select(APIKey).where(APIKey.key_hash == key_hash)
            ).scalar_one_or_none()

            if api_key is None:
                logger.warning("API key not found")
                return None

            if not api_key.is_valid():
                logger.warning(f"API key {api_key.id} is not valid (active={api_key.is_active}, expired={api_key.is_expired()})")
                return None

            # Update usage stats
            api_key.last_used_at = datetime.now(timezone.utc)
            api_key.usage_count += 1
            session.commit()
            session.refresh(api_key)
            session.expunge(api_key)
            
            logger.debug(f"API key {api_key.id} validated successfully")
            return api_key

    def revoke_key(
        self,
        key_id: str,
        organization_id: str,
        revoked_by: Optional[str] = None,
    ) -> bool:
        """Revoke an API key."""
        with self._get_session() as session:
            api_key = session.execute(
                select(APIKey).where(
                    APIKey.id == key_id,
                    APIKey.organization_id == organization_id,
                )
            ).scalar_one_or_none()

            if api_key is None:
                logger.warning(f"API key {key_id} not found")
                return False

            api_key.is_active = False
            api_key.revoked_at = datetime.now(timezone.utc)
            api_key.revoked_by = revoked_by
            session.commit()
            
            logger.info(f"API key {key_id} revoked by {revoked_by}")
            return True

    def delete_key(self, key_id: str, organization_id: str) -> bool:
        """Permanently delete an API key."""
        with self._get_session() as session:
            api_key = session.execute(
                select(APIKey).where(
                    APIKey.id == key_id,
                    APIKey.organization_id == organization_id,
                )
            ).scalar_one_or_none()

            if api_key is None:
                logger.warning(f"API key {key_id} not found")
                return False

            session.delete(api_key)
            session.commit()
            
            logger.info(f"API key {key_id} deleted")
            return True

    def update_key(
        self,
        key_id: str,
        organization_id: str,
        name: Optional[str] = None,
        scopes: Optional[List[str]] = None,
    ) -> Optional[APIKey]:
        """Update an API key's name or scopes."""
        with self._get_session() as session:
            api_key = session.execute(
                select(APIKey).where(
                    APIKey.id == key_id,
                    APIKey.organization_id == organization_id,
                )
            ).scalar_one_or_none()

            if api_key is None:
                return None

            if name is not None:
                api_key.name = name
            if scopes is not None:
                api_key.scopes = scopes

            session.commit()
            session.refresh(api_key)
            session.expunge(api_key)

            logger.info("API key %s updated", key_id)
            return api_key


# Global service instance
_api_key_service: Optional[APIKeyService] = None


def get_api_key_service() -> APIKeyService:
    """Get or create the API key service singleton."""
    global _api_key_service
    if _api_key_service is None:
        db_path = os.environ.get("API_KEYS_DB_PATH", "/tmp/api_keys.db")
        db_url = f"sqlite:///{db_path}"
        _api_key_service = APIKeyService(db_url)
    return _api_key_service
