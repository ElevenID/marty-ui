"""
Data Retention Manager for Applicant Service

Implements configurable data retention policies following ICAO Annex 9 guidelines.
Handles soft-delete, archival, and hard-delete workflows for applicant data.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

import yaml
from sqlalchemy import select, update, and_

from .database import (
    ApplicantDatabaseManager,
    get_db_manager,
)
from .models import (
    ApplicantRecord,
    ApplicationRecord,
    VettingCheckRecord,
    BiometricEnrollmentRecord,
    KYCSubmissionRecord,
    ApplicationAuditLog,
    ApplicationStatus,
    AuditEventType,
)

logger = logging.getLogger(__name__)


class RetentionAction(str, Enum):
    """Actions that can be taken on expired data."""
    ARCHIVE = "archive"
    SOFT_DELETE = "soft_delete"
    HARD_DELETE = "hard_delete"
    ANONYMIZE = "anonymize"


@dataclass
class RetentionPolicy:
    """Configuration for a specific data retention policy."""
    name: str
    retention_days: int
    action: RetentionAction
    require_approval: bool = False
    approver_role: str | None = None
    archive_destination: str | None = None

    @classmethod
    def from_dict(cls, name: str, config: dict[str, Any]) -> RetentionPolicy:
        """Create policy from dictionary configuration."""
        retention = config
        if isinstance(retention, str):
            if retention == "indefinite":
                retention_days = -1
            else:
                # Parse format like "10_years", "5_years", etc.
                parts = retention.replace("_", " ").split()
                if len(parts) == 2 and parts[1].startswith("year"):
                    retention_days = int(parts[0]) * 365
                elif len(parts) == 2 and parts[1].startswith("day"):
                    retention_days = int(parts[0])
                else:
                    retention_days = 365 * 10  # Default 10 years
        else:
            retention_days = config.get("retention_days", 365 * 10)

        return cls(
            name=name,
            retention_days=retention_days,
            action=RetentionAction(config.get("action", "archive")),
            require_approval=config.get("require_approval", False),
            approver_role=config.get("approver_role"),
            archive_destination=config.get("archive_destination"),
        )


@dataclass
class RetentionConfig:
    """Complete retention configuration loaded from YAML."""
    application_policies: dict[str, RetentionPolicy] = field(default_factory=dict)
    biometric_policies: dict[str, RetentionPolicy] = field(default_factory=dict)
    kyc_policies: dict[str, RetentionPolicy] = field(default_factory=dict)
    audit_policies: dict[str, RetentionPolicy] = field(default_factory=dict)
    archive_enabled: bool = True
    archive_after_days: int = 365
    purge_enabled: bool = True
    purge_require_approval: bool = True
    purge_approver_role: str = "DATA_PROTECTION_OFFICER"

    @classmethod
    def from_yaml(cls, config_path: str | Path) -> RetentionConfig:
        """Load retention configuration from YAML file."""
        with open(config_path) as f:
            raw = yaml.safe_load(f)

        retention_section = raw.get("data_retention", {})

        config = cls()

        # Parse application record policies
        app_records = retention_section.get("application_records", {})
        for status, retention in app_records.items():
            if isinstance(retention, str) and retention == "indefinite":
                days = -1
            elif isinstance(retention, str):
                parts = retention.replace("_", " ").split()
                if len(parts) == 2 and parts[1].startswith("year"):
                    days = int(parts[0]) * 365
                else:
                    days = 365 * 10
            else:
                days = 365 * 10

            config.application_policies[status] = RetentionPolicy(
                name=f"application_{status}",
                retention_days=days,
                action=RetentionAction.ARCHIVE if days > 0 else RetentionAction.SOFT_DELETE,
            )

        # Parse biometric policies
        bio_records = retention_section.get("biometric_data", {})
        for data_type, retention in bio_records.items():
            if isinstance(retention, str):
                parts = retention.replace("_", " ").split()
                if len(parts) == 2 and parts[1].startswith("year"):
                    days = int(parts[0]) * 365
                else:
                    days = 365 * 5
            else:
                days = 365 * 5

            config.biometric_policies[data_type] = RetentionPolicy(
                name=f"biometric_{data_type}",
                retention_days=days,
                action=RetentionAction.HARD_DELETE,  # Biometric data should be hard deleted
            )

        # Parse KYC policies
        kyc_records = retention_section.get("kyc_documents", {})
        for doc_type, retention in kyc_records.items():
            if isinstance(retention, str):
                parts = retention.replace("_", " ").split()
                if len(parts) == 2 and parts[1].startswith("year"):
                    days = int(parts[0]) * 365
                else:
                    days = 365 * 5
            else:
                days = 365 * 5

            config.kyc_policies[doc_type] = RetentionPolicy(
                name=f"kyc_{doc_type}",
                retention_days=days,
                action=RetentionAction.ARCHIVE,
            )

        # Parse audit policies
        audit_records = retention_section.get("audit_logs", {})
        for log_type, retention in audit_records.items():
            if isinstance(retention, str):
                parts = retention.replace("_", " ").split()
                if len(parts) == 2 and parts[1].startswith("year"):
                    days = int(parts[0]) * 365
                else:
                    days = 365 * 7
            else:
                days = 365 * 7

            config.audit_policies[log_type] = RetentionPolicy(
                name=f"audit_{log_type}",
                retention_days=days,
                action=RetentionAction.HARD_DELETE,
            )

        # Parse archive settings
        archive = retention_section.get("archive", {})
        config.archive_enabled = archive.get("enabled", True)
        config.archive_after_days = archive.get("archive_after_days", 365)

        # Parse purge settings
        purge = retention_section.get("purge", {})
        config.purge_enabled = purge.get("enabled", True)
        config.purge_require_approval = purge.get("require_approval", True)
        config.purge_approver_role = purge.get("approver_role", "DATA_PROTECTION_OFFICER")

        return config

    @classmethod
    def default(cls) -> RetentionConfig:
        """Create default retention configuration."""
        return cls(
            application_policies={
                "active_application": RetentionPolicy("active", -1, RetentionAction.ARCHIVE),
                "approved_application": RetentionPolicy("approved", 365 * 10, RetentionAction.ARCHIVE),
                "rejected_application": RetentionPolicy("rejected", 365 * 5, RetentionAction.ARCHIVE),
                "withdrawn_application": RetentionPolicy("withdrawn", 365, RetentionAction.SOFT_DELETE),
            },
            biometric_policies={
                "template_data": RetentionPolicy("template", 365 * 10, RetentionAction.HARD_DELETE),
                "image_data": RetentionPolicy("image", 365 * 5, RetentionAction.HARD_DELETE),
                "verification_logs": RetentionPolicy("verification", 365 * 2, RetentionAction.HARD_DELETE),
            },
            kyc_policies={
                "identity_documents": RetentionPolicy("identity", 365 * 10, RetentionAction.ARCHIVE),
                "supporting_documents": RetentionPolicy("supporting", 365 * 5, RetentionAction.ARCHIVE),
            },
            audit_policies={
                "standard": RetentionPolicy("standard", 365 * 7, RetentionAction.ARCHIVE),
                "security_events": RetentionPolicy("security", 365 * 10, RetentionAction.ARCHIVE),
            },
        )


@dataclass
class RetentionResult:
    """Result of a retention operation."""
    action: RetentionAction
    record_type: str
    record_id: UUID
    success: bool
    message: str
    archived_to: str | None = None


class DataRetentionManager:
    """
    Manages data retention lifecycle for applicant service data.
    
    Responsibilities:
    - Track data age against retention policies
    - Archive data approaching retention limits
    - Soft-delete expired data
    - Hard-delete data past purge threshold
    - Generate retention reports
    - Enforce approval workflows for destructive operations
    """

    def __init__(
        self,
        db_manager: ApplicantDatabaseManager | None = None,
        config: RetentionConfig | None = None,
    ) -> None:
        self._db = db_manager or get_db_manager()
        self._config = config or RetentionConfig.default()
        self._pending_approvals: list[dict[str, Any]] = []

    def load_config(self, config_path: str | Path) -> None:
        """Load retention configuration from YAML file."""
        self._config = RetentionConfig.from_yaml(config_path)
        logger.info(f"Loaded retention configuration from {config_path}")

    async def check_retention_status(self) -> dict[str, Any]:
        """
        Check retention status for all data types.
        
        Returns summary of data approaching retention limits.
        """
        now = datetime.utcnow()
        status = {
            "checked_at": now.isoformat(),
            "applications": await self._check_application_retention(now),
            "biometrics": await self._check_biometric_retention(now),
            "kyc_documents": await self._check_kyc_retention(now),
            "audit_logs": await self._check_audit_retention(now),
        }
        return status

    async def _check_application_retention(self, now: datetime) -> dict[str, Any]:
        """Check application records against retention policies."""
        result = {
            "total": 0,
            "approaching_limit": 0,
            "past_limit": 0,
            "by_status": {},
        }

        async with self._db.session_scope() as session:
            # Check each status
            for status in ApplicationStatus:
                status_key = f"{status.value.lower()}_application"
                policy = self._config.application_policies.get(status_key)
                
                if not policy or policy.retention_days < 0:
                    continue  # Indefinite retention

                cutoff = now - timedelta(days=policy.retention_days)
                warning_cutoff = now - timedelta(days=policy.retention_days - 30)

                # Count records past limit
                past_limit_result = await session.execute(
                    select(ApplicationRecord)
                    .where(
                        and_(
                            ApplicationRecord.status == status,
                            ApplicationRecord.updated_at < cutoff,
                        )
                    )
                )
                past_limit = len(list(past_limit_result.scalars().all()))

                # Count records approaching limit (within 30 days)
                approaching_result = await session.execute(
                    select(ApplicationRecord)
                    .where(
                        and_(
                            ApplicationRecord.status == status,
                            ApplicationRecord.updated_at >= cutoff,
                            ApplicationRecord.updated_at < warning_cutoff,
                        )
                    )
                )
                approaching = len(list(approaching_result.scalars().all()))

                result["by_status"][status.value] = {
                    "past_limit": past_limit,
                    "approaching_limit": approaching,
                    "retention_days": policy.retention_days,
                }
                result["past_limit"] += past_limit
                result["approaching_limit"] += approaching

        return result

    async def _check_biometric_retention(self, now: datetime) -> dict[str, Any]:
        """Check biometric records against retention policies."""
        result = {"total": 0, "past_limit": 0}

        policy = self._config.biometric_policies.get("template_data")
        if not policy or policy.retention_days < 0:
            return result

        cutoff = now - timedelta(days=policy.retention_days)

        async with self._db.session_scope() as session:
            past_limit_result = await session.execute(
                select(BiometricEnrollmentRecord)
                .where(BiometricEnrollmentRecord.created_at < cutoff)
            )
            result["past_limit"] = len(list(past_limit_result.scalars().all()))

        return result

    async def _check_kyc_retention(self, now: datetime) -> dict[str, Any]:
        """Check KYC records against retention policies."""
        result = {"total": 0, "past_limit": 0}

        policy = self._config.kyc_policies.get("identity_documents")
        if not policy or policy.retention_days < 0:
            return result

        cutoff = now - timedelta(days=policy.retention_days)

        async with self._db.session_scope() as session:
            past_limit_result = await session.execute(
                select(KYCSubmissionRecord)
                .where(KYCSubmissionRecord.created_at < cutoff)
            )
            result["past_limit"] = len(list(past_limit_result.scalars().all()))

        return result

    async def _check_audit_retention(self, now: datetime) -> dict[str, Any]:
        """Check audit logs against retention policies."""
        result = {"total": 0, "past_limit": 0}

        policy = self._config.audit_policies.get("standard")
        if not policy or policy.retention_days < 0:
            return result

        cutoff = now - timedelta(days=policy.retention_days)

        async with self._db.session_scope() as session:
            past_limit_result = await session.execute(
                select(ApplicationAuditLog)
                .where(ApplicationAuditLog.timestamp < cutoff)
            )
            result["past_limit"] = len(list(past_limit_result.scalars().all()))

        return result

    async def archive_expired_data(
        self,
        dry_run: bool = True,
        actor_id: str = "system",
    ) -> list[RetentionResult]:
        """
        Archive data that has exceeded retention limits.
        
        Args:
            dry_run: If True, only report what would be archived
            actor_id: ID of actor performing the operation
            
        Returns:
            List of archive operation results
        """
        results: list[RetentionResult] = []
        now = datetime.utcnow()

        # Archive applications
        for status_key, policy in self._config.application_policies.items():
            if policy.retention_days < 0 or policy.action != RetentionAction.ARCHIVE:
                continue

            cutoff = now - timedelta(days=policy.retention_days)
            status_value = status_key.replace("_application", "").upper()

            try:
                status = ApplicationStatus(status_value)
            except ValueError:
                continue

            async with self._db.session_scope() as session:
                query = select(ApplicationRecord).where(
                    and_(
                        ApplicationRecord.status == status,
                        ApplicationRecord.updated_at < cutoff,
                    )
                )
                records = (await session.execute(query)).scalars().all()

                for record in records:
                    if dry_run:
                        results.append(RetentionResult(
                            action=RetentionAction.ARCHIVE,
                            record_type="ApplicationRecord",
                            record_id=record.id,
                            success=True,
                            message=f"Would archive application {record.reference_number}",
                        ))
                    else:
                        # In production, this would move data to archive storage
                        # For now, we mark it in metadata
                        record.metadata = record.metadata or {}
                        record.metadata["archived_at"] = now.isoformat()
                        record.metadata["archived_by"] = actor_id
                        
                        results.append(RetentionResult(
                            action=RetentionAction.ARCHIVE,
                            record_type="ApplicationRecord",
                            record_id=record.id,
                            success=True,
                            message=f"Archived application {record.reference_number}",
                        ))

        logger.info(f"Archive operation completed: {len(results)} records processed (dry_run={dry_run})")
        return results

    async def soft_delete_expired_data(
        self,
        dry_run: bool = True,
        actor_id: str = "system",
    ) -> list[RetentionResult]:
        """
        Soft-delete data that has exceeded retention limits.
        
        Soft-deleted data is marked as inactive but not removed from database.
        
        Args:
            dry_run: If True, only report what would be deleted
            actor_id: ID of actor performing the operation
            
        Returns:
            List of delete operation results
        """
        results: list[RetentionResult] = []
        now = datetime.utcnow()

        # Soft-delete applications with SOFT_DELETE policy
        for status_key, policy in self._config.application_policies.items():
            if policy.retention_days < 0 or policy.action != RetentionAction.SOFT_DELETE:
                continue

            cutoff = now - timedelta(days=policy.retention_days)
            status_value = status_key.replace("_application", "").upper()

            try:
                status = ApplicationStatus(status_value)
            except ValueError:
                continue

            async with self._db.session_scope() as session:
                query = select(ApplicationRecord).where(
                    and_(
                        ApplicationRecord.status == status,
                        ApplicationRecord.updated_at < cutoff,
                    )
                )
                records = (await session.execute(query)).scalars().all()

                for record in records:
                    if dry_run:
                        results.append(RetentionResult(
                            action=RetentionAction.SOFT_DELETE,
                            record_type="ApplicationRecord",
                            record_id=record.id,
                            success=True,
                            message=f"Would soft-delete application {record.reference_number}",
                        ))
                    else:
                        record.metadata = record.metadata or {}
                        record.metadata["soft_deleted_at"] = now.isoformat()
                        record.metadata["soft_deleted_by"] = actor_id
                        record.metadata["is_deleted"] = True
                        
                        results.append(RetentionResult(
                            action=RetentionAction.SOFT_DELETE,
                            record_type="ApplicationRecord",
                            record_id=record.id,
                            success=True,
                            message=f"Soft-deleted application {record.reference_number}",
                        ))

        logger.info(f"Soft-delete operation completed: {len(results)} records processed (dry_run={dry_run})")
        return results

    async def hard_delete_biometric_data(
        self,
        dry_run: bool = True,
        require_approval: bool = True,
        actor_id: str = "system",
        approver_id: str | None = None,
    ) -> list[RetentionResult]:
        """
        Permanently delete biometric data past retention period.
        
        This is a destructive operation and may require approval.
        
        Args:
            dry_run: If True, only report what would be deleted
            require_approval: If True, require approver_id
            actor_id: ID of actor performing the operation
            approver_id: ID of approver (required if require_approval=True)
            
        Returns:
            List of delete operation results
        """
        if require_approval and not approver_id:
            raise ValueError("Approver ID required for biometric data deletion")

        results: list[RetentionResult] = []
        now = datetime.utcnow()

        policy = self._config.biometric_policies.get("template_data")
        if not policy or policy.retention_days < 0:
            return results

        cutoff = now - timedelta(days=policy.retention_days)

        async with self._db.session_scope() as session:
            query = select(BiometricEnrollmentRecord).where(
                BiometricEnrollmentRecord.created_at < cutoff
            )
            records = (await session.execute(query)).scalars().all()

            for record in records:
                if dry_run:
                    results.append(RetentionResult(
                        action=RetentionAction.HARD_DELETE,
                        record_type="BiometricEnrollmentRecord",
                        record_id=record.id,
                        success=True,
                        message=f"Would hard-delete biometric enrollment {record.id}",
                    ))
                else:
                    await session.delete(record)
                    results.append(RetentionResult(
                        action=RetentionAction.HARD_DELETE,
                        record_type="BiometricEnrollmentRecord",
                        record_id=record.id,
                        success=True,
                        message=f"Hard-deleted biometric enrollment {record.id}",
                    ))

        logger.info(f"Hard-delete operation completed: {len(results)} records processed (dry_run={dry_run})")
        return results

    async def generate_retention_report(self) -> dict[str, Any]:
        """
        Generate a comprehensive retention report.
        
        Returns:
            Report with retention status, upcoming expirations, and recommendations
        """
        status = await self.check_retention_status()
        
        report = {
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "applications_past_limit": status["applications"]["past_limit"],
                "applications_approaching_limit": status["applications"]["approaching_limit"],
                "biometrics_past_limit": status["biometrics"]["past_limit"],
                "kyc_past_limit": status["kyc_documents"]["past_limit"],
                "audit_logs_past_limit": status["audit_logs"]["past_limit"],
            },
            "policies": {
                "application_policies": {
                    k: {"retention_days": v.retention_days, "action": v.action.value}
                    for k, v in self._config.application_policies.items()
                },
                "biometric_policies": {
                    k: {"retention_days": v.retention_days, "action": v.action.value}
                    for k, v in self._config.biometric_policies.items()
                },
            },
            "recommendations": [],
            "details": status,
        }

        # Add recommendations
        if status["applications"]["past_limit"] > 0:
            report["recommendations"].append({
                "priority": "high",
                "message": f"{status['applications']['past_limit']} applications have exceeded retention period",
                "action": "Run archive_expired_data to archive these records",
            })

        if status["biometrics"]["past_limit"] > 0:
            report["recommendations"].append({
                "priority": "critical",
                "message": f"{status['biometrics']['past_limit']} biometric records have exceeded retention period",
                "action": "Run hard_delete_biometric_data with DPO approval",
            })

        return report


# Global instance
_retention_manager: DataRetentionManager | None = None


def get_retention_manager() -> DataRetentionManager:
    """Get or create the global retention manager instance."""
    global _retention_manager
    if _retention_manager is None:
        _retention_manager = DataRetentionManager()
    return _retention_manager


async def init_retention_manager(config_path: str | Path | None = None) -> DataRetentionManager:
    """Initialize retention manager with optional configuration."""
    global _retention_manager
    _retention_manager = DataRetentionManager()
    
    if config_path and Path(config_path).exists():
        _retention_manager.load_config(config_path)
    
    return _retention_manager
