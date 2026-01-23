"""
SQLAlchemy Models for Applicant Service

Defines the data models for:
- Applicants: Identity-proofed individuals with biometric enrollment
- Applications: Document issuance requests linked to applicants
- Vetting Checks: Background verification tracking per ICAO Annex 9
- Biometric Enrollments: Facial (account creation) and additional biometrics (issuance)
- KYC Submissions: Know Your Customer document collection

Follows NIST SP 800-63A IAL requirements and ICAO Doc 9303 standards.
"""

from __future__ import annotations

from datetime import date, datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def generate_uuid() -> str:
    """Generate a UUID string for primary keys."""
    return str(uuid4())


def utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """SQLAlchemy declarative base for applicant service models."""
    pass


# ==================== Enums ====================

class ApplicationStatus(str, Enum):
    """Application lifecycle status following NIST 800-63A identity proofing workflow."""
    
    DRAFT = "draft"                           # Initial creation, incomplete
    SUBMITTED = "submitted"                   # Applicant submitted for review
    IDENTITY_PROOFING = "identity_proofing"   # IAL verification in progress
    PENDING_KYC = "pending_kyc"               # Awaiting KYC document submission
    KYC_REVIEW = "kyc_review"                 # KYC documents under review
    PENDING_VETTING = "pending_vetting"       # Awaiting background checks
    VETTING_IN_PROGRESS = "vetting_in_progress"  # Background checks in progress
    PENDING_BIOMETRICS = "pending_biometrics"    # Awaiting issuance biometrics
    PENDING_APPROVAL = "pending_approval"     # Awaiting supervisor approval
    NEEDS_REVISION = "needs_revision"         # Requires applicant to revise and resubmit
    APPROVED = "approved"                     # Ready for document issuance
    REJECTED = "rejected"                     # Application denied
    ISSUED = "issued"                         # Document issued
    EXPIRED = "expired"                       # Application expired before issuance
    CANCELLED = "cancelled"                   # Applicant cancelled


class VettingCheckType(str, Enum):
    """Types of vetting checks per ICAO Annex 9 requirements."""
    
    CRIMINAL_HISTORY = "criminal_history"
    EMPLOYMENT_VERIFICATION = "employment_verification"
    IDENTITY_VERIFICATION = "identity_verification"
    SECURITY_CLEARANCE = "security_clearance"
    AVIATION_EXPERIENCE = "aviation_experience"
    SANCTIONS_SCREENING = "sanctions_screening"
    WATCHLIST_CHECK = "watchlist_check"
    REFERENCE_CHECK = "reference_check"
    EDUCATION_VERIFICATION = "education_verification"
    ADDRESS_VERIFICATION = "address_verification"
    BIOMETRIC_ENROLLMENT = "biometric_enrollment"
    DOCUMENT_VERIFICATION = "document_verification"
    FINANCIAL_CHECK = "financial_check"


class VettingCheckStatus(str, Enum):
    """Status of individual vetting checks."""
    
    NOT_STARTED = "not_started"
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    PASSED = "passed"
    FAILED = "failed"
    REQUIRES_MANUAL_REVIEW = "requires_manual_review"
    COMPLETED_PASSED = "completed_passed"
    COMPLETED_FAILED = "completed_failed"
    COMPLETED_CONDITIONAL = "completed_conditional"
    EXPIRED = "expired"
    WAIVED = "waived"
    SKIPPED = "skipped"


class BiometricType(str, Enum):
    """Biometric modalities per ISO/IEC 19794 and ICAO Doc 9303."""
    
    FACIAL = "facial"           # ISO 19794-5, captured at account creation
    FINGERPRINT = "fingerprint"  # ISO 19794-4, captured at issuance
    IRIS = "iris"               # ISO 19794-6, captured at issuance
    SIGNATURE = "signature"     # ISO 19794-7


class BiometricPurpose(str, Enum):
    """Purpose of biometric collection."""
    
    ACCOUNT_ENROLLMENT = "account_enrollment"   # Primary identity at account creation
    ISSUANCE_ENROLLMENT = "issuance_enrollment"  # Additional biometrics for document
    VERIFICATION = "verification"               # Live check against enrollment
    RE_ENROLLMENT = "re_enrollment"             # Updated biometric after change


class KYCDocumentType(str, Enum):
    """Types of KYC identity documents."""
    
    PASSPORT = "passport"
    NATIONAL_ID = "national_id"
    DRIVERS_LICENSE = "drivers_license"
    BIRTH_CERTIFICATE = "birth_certificate"
    UTILITY_BILL = "utility_bill"
    BANK_STATEMENT = "bank_statement"
    TAX_DOCUMENT = "tax_document"
    EMPLOYMENT_LETTER = "employment_letter"
    RESIDENCE_PERMIT = "residence_permit"
    OTHER = "other"


class KYCFieldType(str, Enum):
    """Types of KYC data fields that can be submitted."""
    
    FULL_NAME = "full_name"
    DATE_OF_BIRTH = "date_of_birth"
    NATIONALITY = "nationality"
    PLACE_OF_BIRTH = "place_of_birth"
    CURRENT_ADDRESS = "current_address"
    PHONE_NUMBER = "phone_number"
    EMAIL = "email"
    GOVERNMENT_ID = "government_id"
    TAX_ID = "tax_id"
    EMPLOYMENT_STATUS = "employment_status"
    OCCUPATION = "occupation"
    EMPLOYER = "employer"
    INCOME_LEVEL = "income_level"
    SOURCE_OF_FUNDS = "source_of_funds"
    PHOTO = "photo"
    SIGNATURE = "signature"
    OTHER = "other"


class KYCVerificationStatus(str, Enum):
    """Status of KYC document verification."""
    
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    VERIFIED = "verified"
    REJECTED = "rejected"
    EXPIRED = "expired"


class AuditEventType(str, Enum):
    """Types of audit events for applications."""
    
    CREATED = "created"
    SUBMITTED = "submitted"
    STATUS_CHANGED = "status_changed"
    KYC_SUBMITTED = "kyc_submitted"
    KYC_VERIFIED = "kyc_verified"
    KYC_REJECTED = "kyc_rejected"
    VETTING_STARTED = "vetting_started"
    VETTING_CHECK_COMPLETED = "vetting_check_completed"
    VETTING_PASSED = "vetting_passed"
    VETTING_FAILED = "vetting_failed"
    BIOMETRIC_ENROLLED = "biometric_enrolled"
    BIOMETRIC_VERIFIED = "biometric_verified"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVISION_REQUESTED = "revision_requested"
    RESUBMITTED = "resubmitted"
    ISSUED = "issued"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    DATA_ACCESSED = "data_accessed"
    DATA_MODIFIED = "data_modified"


class ActorType(str, Enum):
    """Types of actors that can perform actions."""
    
    APPLICANT = "applicant"
    VETTING_OFFICER = "vetting_officer"
    BIOMETRIC_OPERATOR = "biometric_operator"
    SUPERVISOR = "supervisor"
    COMPLIANCE_OFFICER = "compliance_officer"
    ADMIN = "admin"
    SYSTEM = "system"
    API = "api"


# ==================== Models ====================

class ApplicantRecord(Base):
    """
    Applicant identity record - the vetted individual.
    
    Created during account registration with live facial biometric enrollment.
    Linked to multiple applications over time.
    """
    __tablename__ = "applicants"
    
    # Primary key
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    
    # Account linkage
    account_id: Mapped[str | None] = mapped_column(String(36), unique=True, nullable=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    phone: Mapped[str | None] = mapped_column(String(50), nullable=True)
    
    # Identity information (minimal per Annex 9)
    surname: Mapped[str] = mapped_column(String(255), nullable=False)
    given_names: Mapped[str] = mapped_column(String(255), nullable=False)
    date_of_birth: Mapped[date] = mapped_column(Date, nullable=False)
    nationality: Mapped[str] = mapped_column(String(3), nullable=False)  # ISO 3166-1 alpha-3
    gender: Mapped[str | None] = mapped_column(String(1), nullable=True)  # M, F, X
    
    # Address (for enrollment code delivery per NIST 800-63A)
    address_line1: Mapped[str | None] = mapped_column(String(255), nullable=True)
    address_line2: Mapped[str | None] = mapped_column(String(255), nullable=True)
    city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    state_province: Mapped[str | None] = mapped_column(String(100), nullable=True)
    postal_code: Mapped[str | None] = mapped_column(String(20), nullable=True)
    country: Mapped[str | None] = mapped_column(String(3), nullable=True)  # ISO 3166-1 alpha-3
    
    # Identity proofing level per NIST 800-63A
    identity_assurance_level: Mapped[int] = mapped_column(Integer, default=1)  # IAL1, IAL2, IAL3
    identity_proofing_completed: Mapped[bool] = mapped_column(Boolean, default=False)
    identity_proofing_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    identity_proofing_method: Mapped[str | None] = mapped_column(String(50), nullable=True)
    
    # Primary biometric (facial from account creation)
    primary_biometric_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    
    # Status
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    suspended: Mapped[bool] = mapped_column(Boolean, default=False)
    suspension_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    
    # Metadata
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    
    # Soft delete for retention
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    applications: Mapped[list["ApplicationRecord"]] = relationship(back_populates="applicant")
    biometric_enrollments: Mapped[list["BiometricEnrollmentRecord"]] = relationship(back_populates="applicant")
    kyc_submissions: Mapped[list["KYCSubmissionRecord"]] = relationship(back_populates="applicant")


class ApplicationRecord(Base):
    """
    Travel document application linked to a vetted applicant.
    
    Tracks the full lifecycle from submission through document issuance,
    including vetting, biometric collection, and approval workflow.
    """
    __tablename__ = "applications"
    
    # Primary key
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    
    # Application number (human-readable)
    application_number: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    
    # Applicant linkage
    applicant_id: Mapped[str] = mapped_column(String(36), ForeignKey("applicants.id"), nullable=False)
    
    # Document type requested
    document_type: Mapped[str] = mapped_column(String(50), nullable=False)  # eMRTD, DTC, mDL, etc.
    document_subtype: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Credential configuration linkage
    credential_configuration_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    credential_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    config_version: Mapped[int | None] = mapped_column(Integer, nullable=True)  # Track credential config version at submission
    
    # Application status
    status: Mapped[str] = mapped_column(String(50), default=ApplicationStatus.DRAFT.value)
    status_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    status_changed_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    
    # Revision tracking
    revision_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revision_requested_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    revision_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    revision_count: Mapped[int] = mapped_column(Integer, default=0)
    
    # Document details (populated from applicant + application-specific)
    holder_name: Mapped[str] = mapped_column(String(255), nullable=False)
    holder_given_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    holder_family_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    holder_dob: Mapped[date] = mapped_column(Date, nullable=False)
    nationality: Mapped[str] = mapped_column(String(3), nullable=False)
    issuing_country: Mapped[str] = mapped_column(String(3), nullable=False)
    
    # Requested validity
    requested_validity_years: Mapped[int] = mapped_column(Integer, default=10)
    
    # Vetting summary
    vetting_required: Mapped[bool] = mapped_column(Boolean, default=True)
    vetting_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    vetting_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    vetting_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    vetting_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Biometrics summary
    biometrics_required: Mapped[bool] = mapped_column(Boolean, default=True)
    biometrics_completed: Mapped[bool] = mapped_column(Boolean, default=False)
    biometrics_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Approval workflow
    approval_required: Mapped[bool] = mapped_column(Boolean, default=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    approval_level: Mapped[int] = mapped_column(Integer, default=0)  # Multi-level approval tracking
    
    # Rejection details
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejected_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Issuance linkage
    issued_document_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Expiration (applications have limited validity)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Configuration reference
    vetting_config_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    
    # Metadata
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Soft delete for retention
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    applicant: Mapped["ApplicantRecord"] = relationship(back_populates="applications")
    vetting_checks: Mapped[list["VettingCheckRecord"]] = relationship(back_populates="application")
    biometric_enrollments: Mapped[list["BiometricEnrollmentRecord"]] = relationship(back_populates="application")
    audit_logs: Mapped[list["ApplicationAuditLog"]] = relationship(back_populates="application")


class VettingCheckRecord(Base):
    """
    Individual vetting check for an application.
    
    Tracks background verification per ICAO Annex 9 requirements:
    - Criminal history
    - Employment verification
    - Identity verification
    - Security clearance
    - Aviation experience
    """
    __tablename__ = "vetting_checks"
    
    # Primary key
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    
    # Application linkage
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False)
    
    # Check details
    check_type: Mapped[str] = mapped_column(String(50), nullable=False)
    check_subtype: Mapped[str | None] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(50), default=VettingCheckStatus.NOT_STARTED.value)

    # Check configuration
    is_required: Mapped[bool] = mapped_column(Boolean, default=True)
    order: Mapped[int] = mapped_column(Integer, default=0)
    config: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    
    # External reference (for third-party vetting services)
    external_reference: Mapped[str | None] = mapped_column(String(100), nullable=True)
    external_provider: Mapped[str | None] = mapped_column(String(100), nullable=True)
    
    # Check authority
    check_authority: Mapped[str | None] = mapped_column(String(255), nullable=True)
    authority_reference: Mapped[str | None] = mapped_column(String(100), nullable=True)
    
    # Timing
    requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Validity period
    validity_period_days: Mapped[int] = mapped_column(Integer, default=365)
    
    # Results
    result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    result_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    result_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    
    # Findings (for audit, store minimal per Annex 9)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    has_adverse_findings: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Conditions (for conditional passes)
    conditions: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    conditions_met: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    
    # Waiver details
    waived: Mapped[bool] = mapped_column(Boolean, default=False)
    waived_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    waiver_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    waiver_approval: Mapped[str | None] = mapped_column(String(100), nullable=True)
    
    # Verification code for authenticity
    verification_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    
    # Annex 9 compliance
    annex9_compliant: Mapped[bool] = mapped_column(Boolean, default=False)
    
    # Metadata
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    
    # Relationships
    application: Mapped["ApplicationRecord"] = relationship(back_populates="vetting_checks")


class BiometricEnrollmentRecord(Base):
    """
    Biometric enrollment record.
    
    Types:
    - Facial: Captured at account creation (live webcam with liveness)
    - Fingerprint: Captured at document issuance
    - Iris: Captured at document issuance (optional)
    
    Follows ISO/IEC 19794 standards and ICAO Doc 9303 requirements.
    """
    __tablename__ = "biometric_enrollments"
    
    # Primary key
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    
    # Linkages
    applicant_id: Mapped[str] = mapped_column(String(36), ForeignKey("applicants.id"), nullable=False)
    application_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("applications.id"), nullable=True)
    
    # Biometric type
    biometric_type: Mapped[str] = mapped_column(String(20), nullable=False)
    biometric_subtype: Mapped[str | None] = mapped_column(String(50), nullable=True)  # e.g., right_index for fingerprint
    purpose: Mapped[str] = mapped_column(String(30), default=BiometricPurpose.ACCOUNT_ENROLLMENT.value)
    
    # Template data (encrypted at rest)
    template_format: Mapped[str] = mapped_column(String(50), nullable=False)  # ISO 19794-5, JPEG2000, etc.
    template_data: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)  # Actual template
    template_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)  # SHA-256 for verification
    
    # Image reference (store hash/pointer per Annex 9, not full image)
    image_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    image_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    
    # Quality assessment per ISO 19794
    quality_score: Mapped[float | None] = mapped_column(Float, nullable=True)  # 0.0 - 1.0
    quality_algorithm: Mapped[str | None] = mapped_column(String(50), nullable=True)
    quality_passed: Mapped[bool] = mapped_column(Boolean, default=False)
    quality_details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    
    # Liveness detection (for facial)
    liveness_check_performed: Mapped[bool] = mapped_column(Boolean, default=False)
    liveness_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    liveness_method: Mapped[str | None] = mapped_column(String(50), nullable=True)
    liveness_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    
    # Capture details
    capture_device: Mapped[str | None] = mapped_column(String(100), nullable=True)
    capture_method: Mapped[str | None] = mapped_column(String(50), nullable=True)  # webcam, scanner, etc.
    captured_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    capture_location: Mapped[str | None] = mapped_column(String(255), nullable=True)
    
    # Status
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    superseded_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    
    # Verification count
    verification_attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_verification_result: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    
    # Retention
    retention_period_days: Mapped[int] = mapped_column(Integer, default=3650)  # 10 years
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Metadata
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    
    # Soft delete for retention
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    applicant: Mapped["ApplicantRecord"] = relationship(back_populates="biometric_enrollments")
    application: Mapped["ApplicationRecord"] = relationship(back_populates="biometric_enrollments")


class KYCSubmissionRecord(Base):
    """
    KYC document submission for identity evidence.
    
    Follows NIST 800-63A identity evidence requirements:
    - SUPERIOR: Passport, national ID with photo and biometric
    - STRONG: Driver's license, government-issued ID
    - FAIR: Utility bill, bank statement
    """
    __tablename__ = "kyc_submissions"
    
    # Primary key
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    
    # Linkages
    applicant_id: Mapped[str] = mapped_column(String(36), ForeignKey("applicants.id"), nullable=False)
    application_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    
    # Document details
    document_type: Mapped[str] = mapped_column(String(50), nullable=False)
    document_subtype: Mapped[str | None] = mapped_column(String(50), nullable=True)
    document_number: Mapped[str | None] = mapped_column(String(100), nullable=True)
    
    # Evidence strength per NIST 800-63A
    evidence_strength: Mapped[str] = mapped_column(String(20), default="fair")  # superior, strong, fair, weak
    
    # Document issuer
    issuing_authority: Mapped[str | None] = mapped_column(String(255), nullable=True)
    issuing_country: Mapped[str | None] = mapped_column(String(3), nullable=True)
    issue_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    expiry_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    
    # Document storage (encrypted reference, not actual document per Annex 9)
    document_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    document_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    
    # Extracted data (minimal per Annex 9)
    extracted_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    
    # Verification status
    status: Mapped[str] = mapped_column(String(30), default=KYCVerificationStatus.PENDING.value)
    
    # Validation results
    format_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    authenticity_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    data_matches_profile: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    expiry_valid: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    
    # Verification details
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    verification_method: Mapped[str | None] = mapped_column(String(50), nullable=True)
    verification_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Rejection details
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejected_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Metadata
    extra_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    
    # Soft delete for retention
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Relationships
    applicant: Mapped["ApplicantRecord"] = relationship(back_populates="kyc_submissions")


class ApplicationAuditLog(Base):
    """
    Audit log for application lifecycle events.
    
    Provides full traceability for compliance and security per ICAO Annex 9
    access control and audit trail requirements.
    """
    __tablename__ = "application_audit_logs"
    
    # Primary key
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    
    # Application linkage
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id"), nullable=False)
    applicant_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    
    # Event details
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    event_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Actor information
    actor_id: Mapped[str] = mapped_column(String(100), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(30), nullable=False)
    actor_role: Mapped[str | None] = mapped_column(String(50), nullable=True)
    
    # State change
    previous_status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    new_status: Mapped[str | None] = mapped_column(String(50), nullable=True)
    
    # Change details
    changes: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    
    # Request context
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    
    # Timestamp
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    
    # Integrity
    log_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    previous_log_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    
    # Relationships
    application: Mapped["ApplicationRecord"] = relationship(back_populates="audit_logs")
