"""
PostgreSQL Audit Repository Adapter

Implements audit logging for authentication events.
Stores audit logs and session history in PostgreSQL for compliance and analytics.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy import select, and_, desc
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ...infrastructure.models import mapper_registry, AuditLog, SessionHistory
from ...domain.entities import Session, AuthenticatedUser

logger = logging.getLogger(__name__)


class PostgresAuditRepository:
    """
    PostgreSQL-based audit repository.
    
    Logs authentication events and session history for compliance,
    security monitoring, and analytics. Does not affect active session
    management which remains in Redis.
    """
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory
    
    # =========================================================================
    # Audit Logging
    # =========================================================================
    
    async def log_authentication(
        self,
        user_id: str,
        email: str,
        organization_id: str | None,
        session_id: str | None,
        authentication_method: str,
        success: bool,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log a user authentication event."""
        async with self._session_factory() as session:
            audit_log = AuditLog(
                id=uuid4(),
                event_type="user_authenticated",
                user_id=user_id,
                email=email,
                organization_id=organization_id,
                session_id=session_id,
                authentication_method=authentication_method,
                success=success,
                ip_address=ip_address,
                user_agent=user_agent,
                event_metadata=metadata or {},
                created_at=datetime.now(timezone.utc),
            )
            
            session.add(audit_log)
            await session.commit()
            
            logger.debug(
                f"Logged authentication event: user={user_id[:8]}..., "
                f"success={success}, method={authentication_method}"
            )
    
    async def log_logout(
        self,
        user_id: str,
        session_id: str,
        organization_id: str | None,
        logout_type: str = "user_initiated",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Log a user logout event."""
        async with self._session_factory() as session:
            audit_log = AuditLog(
                id=uuid4(),
                event_type="logout",
                user_id=user_id,
                session_id=session_id,
                organization_id=organization_id,
                success=True,
                event_metadata={"logout_type": logout_type, **(metadata or {})},
                created_at=datetime.now(timezone.utc),
            )
            
            session.add(audit_log)
            await session.commit()
            
            logger.debug(f"Logged logout event: user={user_id[:8]}..., type={logout_type}")
    
    async def log_session_created(
        self,
        session_entity: Session,
    ) -> None:
        """Log session creation event."""
        async with self._session_factory() as session:
            audit_log = AuditLog(
                id=uuid4(),
                event_type="session_created",
                user_id=session_entity.user.user_id,
                email=session_entity.user.email,
                organization_id=session_entity.user.organization_id,
                session_id=session_entity.session_id,
                success=True,
                ip_address=session_entity.ip_address,
                user_agent=session_entity.user_agent,
                event_metadata={
                    "expires_at": session_entity.expires_at.isoformat(),
                    "user_type": session_entity.user.user_type.value,
                },
                created_at=datetime.now(timezone.utc),
            )
            
            session.add(audit_log)
            await session.commit()
            
            logger.debug(f"Logged session created: {session_entity.session_id[:8]}...")
    
    async def log_session_revoked(
        self,
        user_id: str,
        session_id: str,
        organization_id: str | None,
        revoked_by: str,
        reason: str,
    ) -> None:
        """Log session revocation event."""
        async with self._session_factory() as session:
            audit_log = AuditLog(
                id=uuid4(),
                event_type="session_revoked",
                user_id=user_id,
                session_id=session_id,
                organization_id=organization_id,
                success=True,
                event_metadata={
                    "revoked_by": revoked_by,
                    "reason": reason,
                },
                created_at=datetime.now(timezone.utc),
            )
            
            session.add(audit_log)
            await session.commit()
            
            logger.debug(f"Logged session revoked: {session_id[:8]}... by {revoked_by}")
    
    async def get_audit_logs(
        self,
        user_id: str | None = None,
        organization_id: str | None = None,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Query audit logs with filters.
        
        Args:
            user_id: Filter by user ID
            organization_id: Filter by organization ID
            event_type: Filter by event type
            limit: Maximum number of results
            
        Returns:
            List of audit log dictionaries
        """
        async with self._session_factory() as session:
            query = select(AuditLog)
            
            filters = []
            if user_id:
                filters.append(AuditLog.user_id == user_id)
            if organization_id:
                filters.append(AuditLog.organization_id == organization_id)
            if event_type:
                filters.append(AuditLog.event_type == event_type)
            
            if filters:
                query = query.where(and_(*filters))
            
            query = query.order_by(desc(AuditLog.created_at)).limit(limit)
            
            result = await session.execute(query)
            logs = result.scalars().all()
            
            return [
                {
                    "id": str(log.id),
                    "event_type": log.event_type,
                    "user_id": log.user_id,
                    "email": log.email,
                    "organization_id": log.organization_id,
                    "session_id": log.session_id,
                    "authentication_method": log.authentication_method,
                    "success": log.success,
                    "ip_address": str(log.ip_address) if log.ip_address else None,
                    "user_agent": log.user_agent,
                    "event_metadata": log.event_metadata,
                    "created_at": log.created_at.isoformat(),
                }
                for log in logs
            ]
    
    # =========================================================================
    # Session History
    # =========================================================================
    
    async def record_session_history(
        self,
        session_entity: Session,
    ) -> None:
        """
        Record session to history table.
        
        This can be called when a session is created (for initial record)
        or when it expires/is revoked (to update the record).
        """
        async with self._session_factory() as db_session:
            # Check if record already exists
            query = select(SessionHistory).where(
                SessionHistory.session_id == session_entity.session_id
            )
            result = await db_session.execute(query)
            existing = result.scalar_one_or_none()
            
            if existing:
                # Update existing record
                if session_entity.status.value == "expired":
                    existing.expired_at = datetime.now(timezone.utc)
                elif session_entity.status.value == "revoked":
                    existing.revoked_at = datetime.now(timezone.utc)
                    existing.revocation_reason = "revoked"
                
                existing.last_activity = session_entity.last_activity
            else:
                # Create new record
                history = SessionHistory(
                    id=uuid4(),
                    session_id=session_entity.session_id,
                    user_id=session_entity.user.user_id,
                    email=session_entity.user.email,
                    organization_id=session_entity.user.organization_id,
                    user_type=session_entity.user.user_type.value,
                    created_at=session_entity.created_at,
                    expires_at=session_entity.expires_at,
                    ip_address=session_entity.ip_address,
                    user_agent=session_entity.user_agent,
                    last_activity=session_entity.last_activity,
                )
                db_session.add(history)
            
            await db_session.commit()
            
            logger.debug(f"Recorded session history: {session_entity.session_id[:8]}...")
    
    async def update_session_history_on_revocation(
        self,
        session_id: str,
        reason: str,
    ) -> None:
        """Update session history when session is revoked."""
        async with self._session_factory() as db_session:
            query = select(SessionHistory).where(
                SessionHistory.session_id == session_id
            )
            result = await db_session.execute(query)
            history = result.scalar_one_or_none()
            
            if history:
                history.revoked_at = datetime.now(timezone.utc)
                history.revocation_reason = reason
                await db_session.commit()
                
                logger.debug(f"Updated session history on revocation: {session_id[:8]}...")
    
    async def get_session_history(
        self,
        user_id: str | None = None,
        organization_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Query session history with filters.
        
        Args:
            user_id: Filter by user ID
            organization_id: Filter by organization ID
            limit: Maximum number of results
            
        Returns:
            List of session history dictionaries
        """
        async with self._session_factory() as session:
            query = select(SessionHistory)
            
            filters = []
            if user_id:
                filters.append(SessionHistory.user_id == user_id)
            if organization_id:
                filters.append(SessionHistory.organization_id == organization_id)
            
            if filters:
                query = query.where(and_(*filters))
            
            query = query.order_by(desc(SessionHistory.created_at)).limit(limit)
            
            result = await session.execute(query)
            histories = result.scalars().all()
            
            return [
                {
                    "id": str(hist.id),
                    "session_id": hist.session_id,
                    "user_id": hist.user_id,
                    "email": hist.email,
                    "organization_id": hist.organization_id,
                    "user_type": hist.user_type,
                    "created_at": hist.created_at.isoformat(),
                    "expires_at": hist.expires_at.isoformat(),
                    "expired_at": hist.expired_at.isoformat() if hist.expired_at else None,
                    "revoked_at": hist.revoked_at.isoformat() if hist.revoked_at else None,
                    "revocation_reason": hist.revocation_reason,
                    "ip_address": str(hist.ip_address) if hist.ip_address else None,
                    "user_agent": hist.user_agent,
                    "last_activity": hist.last_activity.isoformat() if hist.last_activity else None,
                }
                for hist in histories
            ]
