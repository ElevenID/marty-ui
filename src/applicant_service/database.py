"""
Applicant Service Database Layer

Production-grade async database management for applicant vetting.
Supports both PostgreSQL (production) and SQLite (development/testing).
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, TypeVar
from uuid import UUID

from sqlalchemy import select, update, delete, and_, or_, func, desc
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .models import (
    Base,
    ApplicantRecord,
    ApplicationRecord,
    VettingCheckRecord,
    BiometricEnrollmentRecord,
    KYCSubmissionRecord,
    ApplicationAuditLog,
    ApplicationStatus,
    VettingCheckStatus,
    VettingCheckType,
    BiometricType,
    AuditEventType,
    ActorType,
    KYCVerificationStatus,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


def _normalize_id(value: UUID | str | None) -> str | None:
    if value is None:
        return None
    return str(value) if isinstance(value, UUID) else value


def _enum_value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


@dataclass(slots=True)
class ApplicantDatabaseConfig:
    """Configuration for applicant service database connection."""

    url: str
    echo: bool = False
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30

    @classmethod
    def from_env(cls) -> ApplicantDatabaseConfig:
        """Create configuration from environment variables."""
        db_url = os.environ.get(
            "APPLICANT_DB_URL",
            os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///data/applicants/applicants.db"),
        )
        
        # Convert postgres:// to postgresql+asyncpg://
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql+asyncpg://", 1)
        elif db_url.startswith("postgresql://") and "+asyncpg" not in db_url:
            db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
        
        return cls(
            url=db_url,
            echo=bool(os.environ.get("DB_ECHO", "false").lower() == "true"),
            pool_size=int(os.environ.get("DB_POOL_SIZE", "10")),
            max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "20")),
            pool_timeout=int(os.environ.get("DB_POOL_TIMEOUT", "30")),
        )

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ApplicantDatabaseConfig:
        """Create configuration from dictionary."""
        if "url" in raw:
            url = raw["url"]
        else:
            host = raw.get("host", "localhost")
            port = raw.get("port", 5432)
            name = raw.get("name", "marty_applicants")
            user = raw.get("user", "marty")
            password = raw.get("password", "marty")
            url = f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{name}"
        return cls(
            url=url,
            echo=bool(raw.get("echo", False)),
            pool_size=int(raw.get("pool_size", 10)),
            max_overflow=int(raw.get("max_overflow", 20)),
            pool_timeout=int(raw.get("pool_timeout", 30)),
        )


class ApplicantDatabaseManager:
    """
    Async database session manager for applicant service.
    
    Provides:
    - Connection pooling with configurable parameters
    - Transaction management via session_scope
    - Schema initialization
    """

    def __init__(self, config: ApplicantDatabaseConfig | None = None) -> None:
        self._config = config or ApplicantDatabaseConfig.from_env()
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None

    def create_engine(self) -> AsyncEngine:
        """Create or return cached async engine."""
        if self._engine is None:
            # Determine engine options based on driver
            connect_args = {}
            engine_kwargs: dict[str, Any] = {
                "echo": self._config.echo,
                "future": True,
            }
            
            # SQLite-specific settings
            if "sqlite" in self._config.url:
                # Ensure directory exists for SQLite
                if ":///" in self._config.url:
                    db_path = self._config.url.split(":///")[-1]
                    if db_path != ":memory:":
                        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
            else:
                # PostgreSQL pool settings
                engine_kwargs.update({
                    "pool_size": self._config.pool_size,
                    "max_overflow": self._config.max_overflow,
                    "pool_timeout": self._config.pool_timeout,
                })
            
            self._engine = create_async_engine(
                self._config.url,
                **engine_kwargs,
            )
        return self._engine

    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Create or return cached session factory."""
        if self._session_factory is None:
            engine = self.create_engine()
            self._session_factory = async_sessionmaker(
                engine,
                expire_on_commit=False,
                autoflush=False,
            )
        return self._session_factory

    async def create_all(self) -> None:
        """Create all database tables."""
        engine = self.create_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Applicant service database tables created")

    async def drop_all(self) -> None:
        """Drop all database tables. Use with caution!"""
        engine = self.create_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        logger.info("Applicant service database tables dropped")

    async def dispose(self) -> None:
        """Dispose of engine and close all connections."""
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None

    @asynccontextmanager
    async def session_scope(self) -> AsyncIterator[AsyncSession]:
        """
        Context manager for database sessions with automatic commit/rollback.
        
        Usage:
            async with db_manager.session_scope() as session:
                # perform database operations
                session.add(record)
        """
        session = self.session_factory()()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    async def run_within_transaction(
        self, handler: Callable[[AsyncSession], Awaitable[T]]
    ) -> T:
        """Run a function within a database transaction."""
        async with self.session_scope() as session:
            return await handler(session)


# Repository classes for each entity
class ApplicantRepository:
    """Repository for ApplicantRecord CRUD operations."""

    def __init__(self, db_manager: ApplicantDatabaseManager) -> None:
        self._db = db_manager

    async def create(self, applicant: ApplicantRecord) -> ApplicantRecord:
        """Create a new applicant record."""
        async with self._db.session_scope() as session:
            session.add(applicant)
            await session.flush()
            await session.refresh(applicant)
            return applicant

    async def get_by_id(self, applicant_id: UUID) -> ApplicantRecord | None:
        """Get applicant by ID."""
        applicant_id = _normalize_id(applicant_id)
        async with self._db.session_scope() as session:
            return await session.get(ApplicantRecord, applicant_id)

    async def get_by_user_id(self, user_id: str) -> ApplicantRecord | None:
        """Get applicant by user account ID."""
        async with self._db.session_scope() as session:
            result = await session.execute(
                select(ApplicantRecord).where(ApplicantRecord.account_id == user_id)
            )
            return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> ApplicantRecord | None:
        """Get applicant by email address."""
        async with self._db.session_scope() as session:
            result = await session.execute(
                select(ApplicantRecord).where(ApplicantRecord.email == email)
            )
            return result.scalar_one_or_none()

    async def update(
        self, applicant_id: UUID, updates: dict[str, Any]
    ) -> ApplicantRecord | None:
        """Update an applicant record."""
        applicant_id = _normalize_id(applicant_id)
        async with self._db.session_scope() as session:
            applicant = await session.get(ApplicantRecord, applicant_id)
            if applicant:
                for key, value in updates.items():
                    if hasattr(applicant, key):
                        setattr(applicant, key, value)
                applicant.updated_at = datetime.utcnow()
                await session.flush()
                await session.refresh(applicant)
            return applicant

    async def list_all(
        self,
        is_active: bool | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ApplicantRecord], int]:
        """List applicants with optional filters."""
        async with self._db.session_scope() as session:
            query = select(ApplicantRecord)
            count_query = select(func.count(ApplicantRecord.id))
            
            if is_active is not None:
                query = query.where(ApplicantRecord.active == is_active)
                count_query = count_query.where(ApplicantRecord.active == is_active)
            
            # Get total count
            count_result = await session.execute(count_query)
            total = count_result.scalar() or 0
            
            # Get paginated results
            query = query.order_by(desc(ApplicantRecord.created_at))
            query = query.offset(offset).limit(limit)
            result = await session.execute(query)
            
            return list(result.scalars().all()), total


class ApplicationRepository:
    """Repository for ApplicationRecord CRUD operations."""

    def __init__(self, db_manager: ApplicantDatabaseManager) -> None:
        self._db = db_manager

    async def create(self, application: ApplicationRecord) -> ApplicationRecord:
        """Create a new application."""
        async with self._db.session_scope() as session:
            session.add(application)
            await session.flush()
            await session.refresh(application)
            return application

    async def get_by_id(self, application_id: UUID) -> ApplicationRecord | None:
        """Get application by ID."""
        application_id = _normalize_id(application_id)
        async with self._db.session_scope() as session:
            return await session.get(ApplicationRecord, application_id)

    async def get_by_reference(self, reference_number: str) -> ApplicationRecord | None:
        """Get application by reference number."""
        async with self._db.session_scope() as session:
            result = await session.execute(
                select(ApplicationRecord).where(
                    ApplicationRecord.application_number == reference_number
                )
            )
            return result.scalar_one_or_none()

    async def get_for_applicant(
        self,
        applicant_id: UUID,
        status: ApplicationStatus | None = None,
    ) -> list[ApplicationRecord]:
        """Get all applications for an applicant."""
        applicant_id = _normalize_id(applicant_id)
        async with self._db.session_scope() as session:
            query = select(ApplicationRecord).where(
                ApplicationRecord.applicant_id == applicant_id
            )
            if status:
                query = query.where(ApplicationRecord.status == _enum_value(status))
            query = query.order_by(desc(ApplicationRecord.created_at))
            result = await session.execute(query)
            return list(result.scalars().all())

    async def update_status(
        self,
        application_id: UUID,
        new_status: ApplicationStatus,
        updated_by: str | None = None,
        rejection_reason: str | None = None,
    ) -> ApplicationRecord | None:
        """Update application status."""
        application_id = _normalize_id(application_id)
        async with self._db.session_scope() as session:
            application = await session.get(ApplicationRecord, application_id)
            if application:
                status_value = _enum_value(new_status)
                application.status = status_value
                application.status_changed_at = datetime.utcnow()
                application.status_changed_by = updated_by
                application.updated_at = datetime.utcnow()
                
                if status_value == ApplicationStatus.APPROVED.value:
                    application.approved_at = datetime.utcnow()
                    application.approved_by = updated_by
                elif status_value == ApplicationStatus.REJECTED.value:
                    application.rejected_at = datetime.utcnow()
                    application.rejected_by = updated_by
                    application.rejection_reason = rejection_reason
                    application.status_reason = rejection_reason
                elif status_value == ApplicationStatus.ISSUED.value:
                    application.issued_at = datetime.utcnow()
                
                await session.flush()
                await session.refresh(application)
            return application

    async def list_all(
        self,
        status: ApplicationStatus | None = None,
        document_type: str | None = None,
        organization_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ApplicationRecord], int]:
        """List applications with optional filters."""
        async with self._db.session_scope() as session:
            query = select(ApplicationRecord)
            count_query = select(func.count(ApplicationRecord.id))
            
            conditions = []
            if status:
                conditions.append(ApplicationRecord.status == _enum_value(status))
            if document_type:
                conditions.append(ApplicationRecord.document_type == document_type)
            if organization_id:
                conditions.append(ApplicationRecord.organization_id == organization_id)
            
            if conditions:
                query = query.where(and_(*conditions))
                count_query = count_query.where(and_(*conditions))
            
            count_result = await session.execute(count_query)
            total = count_result.scalar() or 0
            
            query = query.order_by(desc(ApplicationRecord.created_at))
            query = query.offset(offset).limit(limit)
            result = await session.execute(query)
            
            return list(result.scalars().all()), total

    async def get_pending_review(self, limit: int = 50) -> list[ApplicationRecord]:
        """Get applications pending review."""
        async with self._db.session_scope() as session:
            result = await session.execute(
                select(ApplicationRecord)
                .where(
                    ApplicationRecord.status.in_([
                        ApplicationStatus.SUBMITTED.value,
                        ApplicationStatus.PENDING_APPROVAL.value,
                    ])
                )
                .order_by(ApplicationRecord.submitted_at)
                .limit(limit)
            )
            return list(result.scalars().all())


class VettingCheckRepository:
    """Repository for VettingCheckRecord CRUD operations."""

    def __init__(self, db_manager: ApplicantDatabaseManager) -> None:
        self._db = db_manager

    async def create(self, check: VettingCheckRecord) -> VettingCheckRecord:
        """Create a new vetting check."""
        async with self._db.session_scope() as session:
            session.add(check)
            await session.flush()
            await session.refresh(check)
            return check

    async def create_many(self, checks: list[VettingCheckRecord]) -> list[VettingCheckRecord]:
        """Create multiple vetting checks."""
        async with self._db.session_scope() as session:
            session.add_all(checks)
            await session.flush()
            for check in checks:
                await session.refresh(check)
            return checks

    async def get_by_id(self, check_id: UUID) -> VettingCheckRecord | None:
        """Get vetting check by ID."""
        check_id = _normalize_id(check_id)
        async with self._db.session_scope() as session:
            return await session.get(VettingCheckRecord, check_id)

    async def get_for_application(
        self, application_id: UUID
    ) -> list[VettingCheckRecord]:
        """Get all vetting checks for an application."""
        application_id = _normalize_id(application_id)
        async with self._db.session_scope() as session:
            result = await session.execute(
                select(VettingCheckRecord)
                .where(VettingCheckRecord.application_id == application_id)
                .order_by(VettingCheckRecord.order)
            )
            return list(result.scalars().all())

    async def update_status(
        self,
        check_id: UUID,
        new_status: VettingCheckStatus,
        result: dict[str, Any] | None = None,
        notes: str | None = None,
        performed_by: str | None = None,
    ) -> VettingCheckRecord | None:
        """Update vetting check status."""
        check_id = _normalize_id(check_id)
        async with self._db.session_scope() as session:
            check = await session.get(VettingCheckRecord, check_id)
            if check:
                status_value = _enum_value(new_status)
                check.status = status_value
                check.updated_at = datetime.utcnow()
                
                if status_value == VettingCheckStatus.IN_PROGRESS.value:
                    check.started_at = datetime.utcnow()
                elif status_value in [
                    VettingCheckStatus.PASSED.value,
                    VettingCheckStatus.FAILED.value,
                    VettingCheckStatus.REQUIRES_MANUAL_REVIEW.value,
                ]:
                    check.completed_at = datetime.utcnow()
                
                if performed_by:
                    extra = check.extra_data or {}
                    extra["performed_by"] = performed_by
                    check.extra_data = extra

                if result is not None:
                    check.result = result
                if notes is not None:
                    check.notes = notes
                
                await session.flush()
                await session.refresh(check)
            return check

    async def get_pending_checks(
        self, check_type: VettingCheckType | None = None, limit: int = 50
    ) -> list[VettingCheckRecord]:
        """Get pending vetting checks."""
        async with self._db.session_scope() as session:
            query = select(VettingCheckRecord).where(
                VettingCheckRecord.status == VettingCheckStatus.PENDING.value
            )
            if check_type:
                query = query.where(
                    VettingCheckRecord.check_type == _enum_value(check_type)
                )
            query = query.order_by(VettingCheckRecord.created_at).limit(limit)
            result = await session.execute(query)
            return list(result.scalars().all())


class BiometricEnrollmentRepository:
    """Repository for BiometricEnrollmentRecord CRUD operations."""

    def __init__(self, db_manager: ApplicantDatabaseManager) -> None:
        self._db = db_manager

    async def create(
        self, enrollment: BiometricEnrollmentRecord
    ) -> BiometricEnrollmentRecord:
        """Create a new biometric enrollment."""
        async with self._db.session_scope() as session:
            session.add(enrollment)
            await session.flush()
            await session.refresh(enrollment)
            return enrollment

    async def get_by_id(self, enrollment_id: UUID) -> BiometricEnrollmentRecord | None:
        """Get biometric enrollment by ID."""
        enrollment_id = _normalize_id(enrollment_id)
        async with self._db.session_scope() as session:
            return await session.get(BiometricEnrollmentRecord, enrollment_id)

    async def get_for_applicant(
        self,
        applicant_id: UUID,
        biometric_type: BiometricType | None = None,
        is_active: bool = True,
    ) -> list[BiometricEnrollmentRecord]:
        """Get biometric enrollments for an applicant."""
        applicant_id = _normalize_id(applicant_id)
        async with self._db.session_scope() as session:
            query = select(BiometricEnrollmentRecord).where(
                and_(
                    BiometricEnrollmentRecord.applicant_id == applicant_id,
                    BiometricEnrollmentRecord.active == is_active,
                )
            )
            if biometric_type:
                query = query.where(
                    BiometricEnrollmentRecord.biometric_type == _enum_value(biometric_type)
                )
            query = query.order_by(desc(BiometricEnrollmentRecord.captured_at))
            result = await session.execute(query)
            return list(result.scalars().all())

    async def deactivate(self, enrollment_id: UUID) -> BiometricEnrollmentRecord | None:
        """Deactivate a biometric enrollment."""
        enrollment_id = _normalize_id(enrollment_id)
        async with self._db.session_scope() as session:
            enrollment = await session.get(BiometricEnrollmentRecord, enrollment_id)
            if enrollment:
                enrollment.active = False
                enrollment.updated_at = datetime.utcnow()
                await session.flush()
                await session.refresh(enrollment)
            return enrollment

    async def update_verification(
        self,
        enrollment_id: UUID,
        verified: bool,
        score: float | None = None,
    ) -> BiometricEnrollmentRecord | None:
        """Update biometric verification status."""
        enrollment_id = _normalize_id(enrollment_id)
        async with self._db.session_scope() as session:
            enrollment = await session.get(BiometricEnrollmentRecord, enrollment_id)
            if enrollment:
                enrollment.last_verification_result = verified
                enrollment.last_verified_at = datetime.utcnow()
                if score is not None:
                    extra = enrollment.extra_data or {}
                    extra["verification_score"] = score
                    enrollment.extra_data = extra
                enrollment.verification_attempts += 1
                enrollment.updated_at = datetime.utcnow()
                await session.flush()
                await session.refresh(enrollment)
            return enrollment


class KYCSubmissionRepository:
    """Repository for KYCSubmissionRecord CRUD operations."""

    def __init__(self, db_manager: ApplicantDatabaseManager) -> None:
        self._db = db_manager

    async def create(self, submission: KYCSubmissionRecord) -> KYCSubmissionRecord:
        """Create a new KYC submission."""
        async with self._db.session_scope() as session:
            session.add(submission)
            await session.flush()
            await session.refresh(submission)
            return submission

    async def get_by_id(self, submission_id: UUID) -> KYCSubmissionRecord | None:
        """Get KYC submission by ID."""
        submission_id = _normalize_id(submission_id)
        async with self._db.session_scope() as session:
            return await session.get(KYCSubmissionRecord, submission_id)

    async def get_for_application(
        self, application_id: UUID
    ) -> list[KYCSubmissionRecord]:
        """Get all KYC submissions for an application."""
        application_id = _normalize_id(application_id)
        async with self._db.session_scope() as session:
            result = await session.execute(
                select(KYCSubmissionRecord)
                .where(KYCSubmissionRecord.application_id == application_id)
                .order_by(desc(KYCSubmissionRecord.created_at))
            )
            return list(result.scalars().all())

    async def update_verification(
        self,
        submission_id: UUID,
        verified: bool,
        verified_by: str | None = None,
        notes: str | None = None,
    ) -> KYCSubmissionRecord | None:
        """Update KYC verification status."""
        submission_id = _normalize_id(submission_id)
        async with self._db.session_scope() as session:
            submission = await session.get(KYCSubmissionRecord, submission_id)
            if submission:
                now = datetime.utcnow()
                submission.status = (
                    KYCVerificationStatus.VERIFIED.value
                    if verified
                    else KYCVerificationStatus.REJECTED.value
                )
                if verified:
                    submission.verified_by = verified_by
                    submission.verified_at = now
                    if notes is not None:
                        submission.verification_notes = notes
                else:
                    submission.rejected_by = verified_by
                    submission.rejected_at = now
                    if notes is not None:
                        submission.rejection_reason = notes
                submission.updated_at = now
                await session.flush()
                await session.refresh(submission)
            return submission


class ApplicationAuditRepository:
    """Repository for ApplicationAuditLog operations."""

    def __init__(self, db_manager: ApplicantDatabaseManager) -> None:
        self._db = db_manager

    async def create(self, audit_log: ApplicationAuditLog) -> ApplicationAuditLog:
        """Create a new audit log entry."""
        async with self._db.session_scope() as session:
            session.add(audit_log)
            await session.flush()
            await session.refresh(audit_log)
            return audit_log

    async def log_event(
        self,
        application_id: UUID,
        event_type: AuditEventType,
        actor_id: str,
        actor_type: str | ActorType = ActorType.API.value,
        actor_role: str | None = None,
        event_description: str | None = None,
        details: dict[str, Any] | None = None,
        previous_status: str | None = None,
        new_status: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        session_id: str | None = None,
    ) -> ApplicationAuditLog:
        """Create an audit log entry with simplified interface."""
        from uuid import uuid4
        application_id = _normalize_id(application_id)

        audit_log = ApplicationAuditLog(
            id=str(uuid4()),
            application_id=application_id,
            event_type=_enum_value(event_type),
            event_description=event_description,
            actor_id=actor_id,
            actor_type=_enum_value(actor_type),
            actor_role=actor_role,
            previous_status=previous_status,
            new_status=new_status,
            changes=details or None,
            timestamp=datetime.utcnow(),
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            session_id=session_id,
        )
        return await self.create(audit_log)

    async def get_for_application(
        self, application_id: UUID, limit: int = 100
    ) -> list[ApplicationAuditLog]:
        """Get audit logs for an application."""
        application_id = _normalize_id(application_id)
        async with self._db.session_scope() as session:
            result = await session.execute(
                select(ApplicationAuditLog)
                .where(ApplicationAuditLog.application_id == application_id)
                .order_by(desc(ApplicationAuditLog.timestamp))
                .limit(limit)
            )
            return list(result.scalars().all())

    async def get_by_actor(
        self,
        actor_id: str,
        event_type: AuditEventType | None = None,
        limit: int = 100,
    ) -> list[ApplicationAuditLog]:
        """Get audit logs by actor."""
        async with self._db.session_scope() as session:
            query = select(ApplicationAuditLog).where(
                ApplicationAuditLog.actor_id == actor_id
            )
            if event_type:
                query = query.where(ApplicationAuditLog.event_type == event_type)
            query = query.order_by(desc(ApplicationAuditLog.timestamp)).limit(limit)
            result = await session.execute(query)
            return list(result.scalars().all())


# Global database manager instance (lazy initialization)
_db_manager: ApplicantDatabaseManager | None = None


def get_db_manager() -> ApplicantDatabaseManager:
    """Get or create the global database manager instance."""
    global _db_manager
    if _db_manager is None:
        _db_manager = ApplicantDatabaseManager()
    return _db_manager


async def init_database(config: ApplicantDatabaseConfig | None = None) -> ApplicantDatabaseManager:
    """Initialize the applicant database."""
    global _db_manager
    _db_manager = ApplicantDatabaseManager(config)
    await _db_manager.create_all()
    logger.info("Applicant service database initialized")
    return _db_manager


async def close_database() -> None:
    """Close the database connection."""
    global _db_manager
    if _db_manager:
        await _db_manager.dispose()
        _db_manager = None
    logger.info("Applicant service database closed")
