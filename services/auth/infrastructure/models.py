"""
Auth Service Database Models

SQLAlchemy table definitions for auth audit logging and session history.
Redis remains the primary storage for active sessions and PKCE state.
PostgreSQL stores audit logs and session history for compliance and analytics.
"""

from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    Text,
    Index,
)
from sqlalchemy.dialects.postgresql import UUID, INET, JSONB
from sqlalchemy.orm import registry
import uuid
from datetime import datetime, timezone

# Create mapper registry
mapper_registry = registry()


@mapper_registry.mapped
class AuditLog:
    """
    Audit log for authentication events.
    
    Tracks all authentication-related activities for compliance,
    security monitoring, and forensics.
    """
    
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_user_id", "user_id"),
        Index("ix_audit_logs_organization_id", "organization_id"),
        Index("ix_audit_logs_event_type", "event_type"),
        Index("ix_audit_logs_created_at", "created_at"),
        Index("ix_audit_logs_success", "success"),
        Index("ix_audit_logs_composite_user_created", "user_id", "created_at"),
        {"schema": "auth_service"},
    )
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type = Column(String(50), nullable=False)  # user_authenticated, logout, session_created, session_revoked
    user_id = Column(String(255), nullable=False)
    email = Column(String(255))
    organization_id = Column(String(255))
    session_id = Column(String(255))
    authentication_method = Column(String(50))  # oidc, api_key, etc.
    success = Column(Boolean, default=True)
    ip_address = Column(INET)
    user_agent = Column(Text)
    event_metadata = Column(JSONB)  # Flexible storage for event-specific data (renamed from 'metadata' to avoid conflict)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


@mapper_registry.mapped
class SessionHistory:
    """
    Historical record of user sessions.
    
    Persists session metadata after expiration for analytics,
    compliance, and security monitoring.
    """
    
    __tablename__ = "session_history"
    __table_args__ = (
        Index("ix_session_history_session_id", "session_id", unique=True),
        Index("ix_session_history_user_id", "user_id"),
        Index("ix_session_history_organization_id", "organization_id"),
        Index("ix_session_history_created_at", "created_at"),
        Index("ix_session_history_expired_at", "expired_at"),
        Index("ix_session_history_composite_user_created", "user_id", "created_at"),
        {"schema": "auth_service"},
    )
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(String(255), nullable=False)
    user_id = Column(String(255), nullable=False)
    email = Column(String(255))
    organization_id = Column(String(255))
    user_type = Column(String(50))
    created_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    expired_at = Column(DateTime(timezone=True))  # Actual expiration time
    revoked_at = Column(DateTime(timezone=True))
    revocation_reason = Column(String(100))
    ip_address = Column(INET)
    user_agent = Column(Text)
    device_info = Column(JSONB)
    last_activity = Column(DateTime(timezone=True))
