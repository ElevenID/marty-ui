"""
Applicant Service for Travel Document Issuance

This module provides the applicant vetting and authorization workflow for travel document issuance.
It follows NIST SP 800-63A Identity Assurance Level (IAL) requirements and ICAO Doc 9303 Annex 9
guidelines for background verification and data retention.

Key Features:
- Applicant registration with live facial biometric enrollment
- Multi-step application workflow with configurable vetting requirements
- KYC (Know Your Customer) document collection and verification
- Background check tracking and prerequisite enforcement
- Biometric collection at document issuance (fingerprint, iris)
- Multi-role approval workflow with RBAC integration
- Configurable data retention policies per ICAO Annex 9

Components:
- models.py: SQLAlchemy models for applicant, application, vetting, biometrics, KYC
- database.py: Database manager and repository implementations
- service.py: Business logic for application workflow
- api.py: FastAPI router with REST endpoints
"""

from .models import (
    ApplicationStatus,
    VettingCheckType,
    VettingCheckStatus,
    BiometricType,
    BiometricPurpose,
    KYCDocumentType,
    KYCFieldType,
    KYCVerificationStatus,
    AuditEventType,
    ActorType,
    ApplicantRecord,
    ApplicationRecord,
    VettingCheckRecord,
    BiometricEnrollmentRecord,
    KYCSubmissionRecord,
    ApplicationAuditLog,
)
from .database import (
    ApplicantDatabaseConfig,
    ApplicantDatabaseManager,
    init_database,
    close_database,
    get_db_manager,
)
from .service import (
    ApplicantService,
    ApplicationService,
    VettingService,
    ApprovalService,
    KYCService,
)
from .api import router

__all__ = [
    # Enums
    "ApplicationStatus",
    "VettingCheckType",
    "VettingCheckStatus",
    "BiometricType",
    "KYCFieldType",
    "AuditEventType",
    # Models
    "ApplicantRecord",
    "ApplicationRecord",
    "VettingCheckRecord",
    "BiometricEnrollmentRecord",
    "KYCSubmissionRecord",
    "ApplicationAuditLog",
    # Database
    "ApplicantDatabaseConfig",
    "ApplicantDatabaseManager",
    "init_database",
    "close_database",
    "get_db_manager",
    # Services
    "ApplicantService",
    "ApplicationService",
    "VettingService",
    "ApprovalService",
    "KYCService",
    # API
    "router",
]
