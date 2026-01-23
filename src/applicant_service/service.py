"""
Applicant Service - Business Logic Layer

Production-grade applicant vetting workflow with:
- NIST SP 800-63A Identity Assurance Level (IAL2/IAL3) compliance
- ICAO Annex 9 vetting requirements
- Configurable vetting checks per document type
- Biometric enrollment and verification
- Full audit trail
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import string
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from .database import (
    ApplicantDatabaseManager,
    ApplicantRepository,
    ApplicationRepository,
    VettingCheckRepository,
    BiometricEnrollmentRepository,
    KYCSubmissionRepository,
    ApplicationAuditRepository,
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
    VettingCheckStatus,
    VettingCheckType,
    BiometricType,
    BiometricPurpose,
    KYCFieldType,
    KYCVerificationStatus,
    AuditEventType,
)

logger = logging.getLogger(__name__)

# Utilities
def _enum_value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


# Default vetting requirements by document type
# This should be loaded from configuration in production
DEFAULT_VETTING_REQUIREMENTS: dict[str, list[dict[str, Any]]] = {
    "PASSPORT": [
        {
            "type": VettingCheckType.IDENTITY_VERIFICATION,
            "required": True,
            "order": 1,
            "config": {"min_documents": 2, "require_photo_id": True},
        },
        {
            "type": VettingCheckType.BIOMETRIC_ENROLLMENT,
            "required": True,
            "order": 2,
            "config": {"types": ["FACIAL", "FINGERPRINT"], "live_capture": True},
        },
        {
            "type": VettingCheckType.CRIMINAL_HISTORY,
            "required": True,
            "order": 3,
            "config": {"scope": "national", "lookback_years": 10},
        },
        {
            "type": VettingCheckType.DOCUMENT_VERIFICATION,
            "required": True,
            "order": 4,
            "config": {"verify_birth_certificate": True, "verify_citizenship": True},
        },
    ],
    "MDL": [
        {
            "type": VettingCheckType.IDENTITY_VERIFICATION,
            "required": True,
            "order": 1,
            "config": {"min_documents": 1, "require_photo_id": True},
        },
        {
            "type": VettingCheckType.BIOMETRIC_ENROLLMENT,
            "required": True,
            "order": 2,
            "config": {"types": ["FACIAL"], "live_capture": True},
        },
        {
            "type": VettingCheckType.DOCUMENT_VERIFICATION,
            "required": True,
            "order": 3,
            "config": {"verify_driver_license": True},
        },
    ],
    "TRAVEL_PERMIT": [
        {
            "type": VettingCheckType.IDENTITY_VERIFICATION,
            "required": True,
            "order": 1,
            "config": {"min_documents": 1, "require_photo_id": True},
        },
        {
            "type": VettingCheckType.BIOMETRIC_ENROLLMENT,
            "required": True,
            "order": 2,
            "config": {"types": ["FACIAL"], "live_capture": True},
        },
        {
            "type": VettingCheckType.DOCUMENT_VERIFICATION,
            "required": True,
            "order": 3,
            "config": {"verify_existing_passport": True},
        },
    ],
    "VISA": [
        {
            "type": VettingCheckType.IDENTITY_VERIFICATION,
            "required": True,
            "order": 1,
            "config": {"min_documents": 2, "require_photo_id": True},
        },
        {
            "type": VettingCheckType.BIOMETRIC_ENROLLMENT,
            "required": True,
            "order": 2,
            "config": {"types": ["FACIAL", "FINGERPRINT"], "live_capture": True},
        },
        {
            "type": VettingCheckType.CRIMINAL_HISTORY,
            "required": True,
            "order": 3,
            "config": {"scope": "international", "lookback_years": 10},
        },
        {
            "type": VettingCheckType.SECURITY_CLEARANCE,
            "required": True,
            "order": 4,
            "config": {"level": "basic"},
        },
        {
            "type": VettingCheckType.FINANCIAL_CHECK,
            "required": False,
            "order": 5,
            "config": {"verify_funds": True},
        },
    ],
    "DIPLOMATIC_CREDENTIAL": [
        {
            "type": VettingCheckType.IDENTITY_VERIFICATION,
            "required": True,
            "order": 1,
            "config": {"min_documents": 3, "require_photo_id": True},
        },
        {
            "type": VettingCheckType.BIOMETRIC_ENROLLMENT,
            "required": True,
            "order": 2,
            "config": {"types": ["FACIAL", "FINGERPRINT", "IRIS"], "live_capture": True},
        },
        {
            "type": VettingCheckType.CRIMINAL_HISTORY,
            "required": True,
            "order": 3,
            "config": {"scope": "international", "lookback_years": 20},
        },
        {
            "type": VettingCheckType.SECURITY_CLEARANCE,
            "required": True,
            "order": 4,
            "config": {"level": "secret"},
        },
        {
            "type": VettingCheckType.EMPLOYMENT_VERIFICATION,
            "required": True,
            "order": 5,
            "config": {"verify_government_employment": True},
        },
    ],
    "ACCESS_BADGE": [
        {
            "type": VettingCheckType.IDENTITY_VERIFICATION,
            "required": True,
            "order": 1,
            "config": {"min_documents": 1, "require_photo_id": True},
        },
        {
            "type": VettingCheckType.BIOMETRIC_ENROLLMENT,
            "required": True,
            "order": 2,
            "config": {"types": ["FACIAL"], "live_capture": True},
        },
    ],
    "NATIONAL_ID": [
        {
            "type": VettingCheckType.IDENTITY_VERIFICATION,
            "required": True,
            "order": 1,
            "config": {"min_documents": 2, "require_photo_id": True},
        },
        {
            "type": VettingCheckType.BIOMETRIC_ENROLLMENT,
            "required": True,
            "order": 2,
            "config": {"types": ["FACIAL"], "live_capture": True},
        },
        {
            "type": VettingCheckType.DOCUMENT_VERIFICATION,
            "required": True,
            "order": 3,
            "config": {"verify_birth_certificate": True},
        },
    ],
    "DTC": [
        {
            "type": VettingCheckType.IDENTITY_VERIFICATION,
            "required": True,
            "order": 1,
            "config": {"min_documents": 2, "require_photo_id": True},
        },
        {
            "type": VettingCheckType.BIOMETRIC_ENROLLMENT,
            "required": True,
            "order": 2,
            "config": {"types": ["FACIAL"], "live_capture": True},
        },
        {
            "type": VettingCheckType.DOCUMENT_VERIFICATION,
            "required": True,
            "order": 3,
            "config": {"verify_passport": True},
        },
    ],
    "OPEN_BADGE": [
        {
            "type": VettingCheckType.IDENTITY_VERIFICATION,
            "required": True,
            "order": 1,
            "config": {"min_documents": 1, "require_photo_id": False},
        },
    ],
}


def generate_reference_number() -> str:
    """Generate a unique application reference number."""
    timestamp = datetime.utcnow().strftime("%Y%m%d")
    random_part = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
    return f"APP-{timestamp}-{random_part}"


class ApplicantService:
    """
    Service for managing applicant records and account registration.
    
    Handles:
    - Applicant account creation with initial biometric enrollment
    - Applicant profile management
    - Contact information verification
    """

    def __init__(self, db_manager: ApplicantDatabaseManager | None = None) -> None:
        self._db = db_manager or get_db_manager()
        self._repo = ApplicantRepository(self._db)
        self._biometric_repo = BiometricEnrollmentRepository(self._db)
        self._audit_repo = ApplicationAuditRepository(self._db)

    async def create_applicant(
        self,
        user_id: str,
        given_name: str,
        family_name: str,
        email: str,
        date_of_birth: datetime,
        nationality: str,
        phone_number: str | None = None,
        address: dict[str, Any] | None = None,
        identity_documents: list[dict[str, Any]] | None = None,
        actor_id: str = "system",
        ip_address: str | None = None,
    ) -> ApplicantRecord:
        """
        Create a new applicant record during account registration.
        
        This is the first step in the applicant vetting process.
        Initial facial biometric should be captured separately via enroll_biometric.
        
        Args:
            user_id: User account ID from authentication system
            given_name: Applicant's given/first name
            family_name: Applicant's family/last name
            email: Email address (will be verified)
            date_of_birth: Date of birth
            nationality: ISO 3166-1 alpha-3 nationality code
            phone_number: Optional phone number
            address: Optional address as structured dict
            identity_documents: Optional list of identity documents
            actor_id: ID of actor performing the action
            ip_address: Request IP for audit
            
        Returns:
            Created ApplicantRecord
        """
        # Check for existing applicant
        existing = await self._repo.get_by_user_id(user_id)
        if existing:
            raise ValueError(f"Applicant already exists for user {user_id}")

        existing_email = await self._repo.get_by_email(email)
        if existing_email:
            raise ValueError(f"Applicant already exists with email {email}")

        address_data = address or {}
        dob_value = date_of_birth.date() if isinstance(date_of_birth, datetime) else date_of_birth

        applicant = ApplicantRecord(
            account_id=user_id,
            email=email,
            phone=phone_number,
            surname=family_name,
            given_names=given_name,
            date_of_birth=dob_value,
            nationality=nationality,
            address_line1=address_data.get("street_line1"),
            address_line2=address_data.get("street_line2"),
            city=address_data.get("city"),
            state_province=address_data.get("state_province"),
            postal_code=address_data.get("postal_code"),
            country=address_data.get("country"),
            extra_data={"identity_documents": identity_documents} if identity_documents else None,
        )

        created = await self._repo.create(applicant)
        logger.info(f"Created applicant record: {created.id} for user {user_id}")

        return created

    async def get_applicant(self, applicant_id: UUID) -> ApplicantRecord | None:
        """Get applicant by ID."""
        return await self._repo.get_by_id(applicant_id)

    async def get_applicant_by_user(self, user_id: str) -> ApplicantRecord | None:
        """Get applicant by user account ID."""
        return await self._repo.get_by_user_id(user_id)

    async def update_applicant(
        self,
        applicant_id: UUID,
        updates: dict[str, Any],
        actor_id: str = "system",
    ) -> ApplicantRecord | None:
        """Update applicant profile."""
        applicant = await self._repo.update(applicant_id, updates)
        if applicant:
            logger.info(f"Updated applicant {applicant_id}: {list(updates.keys())}")
        return applicant

    async def verify_email(self, applicant_id: UUID) -> ApplicantRecord | None:
        """Mark email as verified."""
        applicant = await self._repo.get_by_id(applicant_id)
        if not applicant:
            return None
        extra = applicant.extra_data or {}
        extra["email_verified"] = True
        return await self._repo.update(applicant_id, {"extra_data": extra})

    async def verify_phone(self, applicant_id: UUID) -> ApplicantRecord | None:
        """Mark phone as verified."""
        applicant = await self._repo.get_by_id(applicant_id)
        if not applicant:
            return None
        extra = applicant.extra_data or {}
        extra["phone_verified"] = True
        return await self._repo.update(applicant_id, {"extra_data": extra})

    async def enroll_biometric(
        self,
        applicant_id: UUID,
        biometric_type: BiometricType,
        template_data: bytes,
        image_data: bytes | None = None,
        capture_quality_score: float | None = None,
        capture_device_id: str | None = None,
        is_live_capture: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> BiometricEnrollmentRecord:
        """
        Enroll a biometric for an applicant.
        
        This supports:
        - Facial capture at account creation (live recording)
        - Additional biometrics (fingerprint, iris) during application
        
        Args:
            applicant_id: Applicant ID
            biometric_type: Type of biometric (FACIAL, FINGERPRINT, IRIS)
            template_data: ISO 19794 compliant biometric template
            image_data: Optional raw image data
            capture_quality_score: Quality score from capture device
            capture_device_id: ID of capture device
            is_live_capture: Whether captured live (vs uploaded)
            metadata: Additional capture metadata
            
        Returns:
            Created BiometricEnrollmentRecord
        """
        # Deactivate any existing biometric of same type
        existing = await self._biometric_repo.get_for_applicant(
            applicant_id, biometric_type, is_active=True
        )
        for old_enrollment in existing:
            await self._biometric_repo.deactivate(old_enrollment.id)

        now = datetime.utcnow()
        enrollment = BiometricEnrollmentRecord(
            id=str(uuid4()),
            applicant_id=str(applicant_id),
            biometric_type=_enum_value(biometric_type),
            purpose=BiometricPurpose.ACCOUNT_ENROLLMENT.value
            if is_live_capture
            else BiometricPurpose.ISSUANCE_ENROLLMENT.value,
            template_format="ISO_19794",
            template_data=template_data,
            quality_score=capture_quality_score,
            capture_device=capture_device_id,
            liveness_check_performed=is_live_capture,
            captured_at=now,
            active=True,
            extra_data={
                "metadata": metadata or {},
                "image_bytes_length": len(image_data) if image_data else 0,
            },
            created_at=now,
            updated_at=now,
        )

        created = await self._biometric_repo.create(enrollment)
        logger.info(
            f"Enrolled {biometric_type.value} biometric for applicant {applicant_id}"
        )
        return created

    async def verify_biometric(
        self,
        enrollment_id: UUID,
        verification_score: float,
        threshold: float = 0.8,
    ) -> BiometricEnrollmentRecord | None:
        """
        Verify a biometric enrollment against reference.
        
        Args:
            enrollment_id: Biometric enrollment ID
            verification_score: Score from biometric comparison
            threshold: Minimum score for verification pass
            
        Returns:
            Updated BiometricEnrollmentRecord
        """
        verified = verification_score >= threshold
        return await self._biometric_repo.update_verification(
            enrollment_id, verified, verification_score
        )

    async def get_applicant_biometrics(
        self,
        applicant_id: UUID,
        biometric_type: BiometricType | None = None,
    ) -> list[BiometricEnrollmentRecord]:
        """Get active biometric enrollments for an applicant."""
        return await self._biometric_repo.get_for_applicant(
            applicant_id, biometric_type, is_active=True
        )


class ApplicationService:
    """
    Service for managing travel document applications.
    
    Handles:
    - Application creation and submission
    - Vetting workflow orchestration
    - Status management and transitions
    - Approval workflows
    """

    def __init__(self, db_manager: ApplicantDatabaseManager | None = None) -> None:
        self._db = db_manager or get_db_manager()
        self._app_repo = ApplicationRepository(self._db)
        self._applicant_repo = ApplicantRepository(self._db)
        self._check_repo = VettingCheckRepository(self._db)
        self._kyc_repo = KYCSubmissionRepository(self._db)
        self._audit_repo = ApplicationAuditRepository(self._db)

    async def create_application(
        self,
        applicant_id: UUID,
        document_type: str,
        issuing_authority: str,
        credential_configuration_id: str | None = None,
        credential_type: str | None = None,
        organization_id: str | None = None,
        requested_validity_years: int = 10,
        travel_purpose: str | None = None,
        destination_countries: list[str] | None = None,
        expedited: bool = False,
        metadata: dict[str, Any] | None = None,
        actor_id: str = "system",
        ip_address: str | None = None,
    ) -> ApplicationRecord:
        """
        Create a new travel document application.
        
        Args:
            applicant_id: Applicant ID
            document_type: Type of document (PASSPORT, VISA, etc.)
            issuing_authority: Authority issuing the document
            requested_validity_years: Requested validity period
            travel_purpose: Purpose of travel (for visas)
            destination_countries: Destination countries (for visas)
            expedited: Whether expedited processing requested
            metadata: Additional application metadata
            actor_id: Actor creating the application
            ip_address: Request IP for audit
            
        Returns:
            Created ApplicationRecord in DRAFT status
        """
        # Verify applicant exists
        applicant = await self._applicant_repo.get_by_id(applicant_id)
        if not applicant:
            raise ValueError(f"Applicant not found: {applicant_id}")

        now = datetime.utcnow()
        reference = generate_reference_number()
        metadata_payload = metadata or {}
        extra_data = {
            "issuing_authority": issuing_authority,
            "travel_purpose": travel_purpose,
            "destination_countries": destination_countries or [],
            "is_expedited": expedited,
            "metadata": metadata_payload,
            "credential_configuration_id": credential_configuration_id,
            "credential_type": credential_type,
            "credential_display_name": metadata_payload.get("credential_display_name"),
            "vetting_config": self._get_vetting_config(document_type),
        }
        issuing_country = metadata_payload.get("issuing_country") or applicant.nationality or "USA"
        holder_given = applicant.given_names
        holder_family = applicant.surname
        holder_name = f"{holder_given} {holder_family}".strip()

        application = ApplicationRecord(
            application_number=reference,
            applicant_id=str(applicant.id),
            document_type=document_type,
            document_subtype=metadata_payload.get("document_subtype"),
            credential_configuration_id=credential_configuration_id,
            credential_type=credential_type,
            organization_id=organization_id,
            status=ApplicationStatus.DRAFT.value,
            holder_name=holder_name,
            holder_given_name=holder_given,
            holder_family_name=holder_family,
            holder_dob=applicant.date_of_birth,
            nationality=applicant.nationality,
            issuing_country=issuing_country,
            requested_validity_years=requested_validity_years,
            extra_data=extra_data,
            created_at=now,
            updated_at=now,
        )

        created = await self._app_repo.create(application)

        # Log creation
        await self._audit_repo.log_event(
            application_id=created.id,
            event_type=AuditEventType.CREATED,
            actor_id=actor_id,
            details={"document_type": document_type, "reference": reference},
            ip_address=ip_address,
        )

        logger.info(f"Created application {reference} for applicant {applicant_id}")
        return created

    def _get_vetting_config(self, document_type: str) -> dict[str, Any]:
        """Get vetting configuration for document type."""
        requirements = DEFAULT_VETTING_REQUIREMENTS.get(
            document_type, DEFAULT_VETTING_REQUIREMENTS["PASSPORT"]
        )
        return {
            "document_type": document_type,
            "requirements": [
                {
                    "type": r["type"].value if hasattr(r["type"], "value") else r["type"],
                    "required": r["required"],
                    "order": r["order"],
                    "config": r["config"],
                }
                for r in requirements
            ],
        }

    async def submit_application(
        self,
        application_id: UUID,
        actor_id: str = "system",
        ip_address: str | None = None,
    ) -> ApplicationRecord:
        """
        Submit an application for vetting.
        
        Transitions from DRAFT to SUBMITTED and creates vetting checks.
        
        Args:
            application_id: Application ID
            actor_id: Actor submitting
            ip_address: Request IP for audit
            
        Returns:
            Updated ApplicationRecord
        """
        application = await self._app_repo.get_by_id(application_id)
        if not application:
            raise ValueError(f"Application not found: {application_id}")

        if application.status != ApplicationStatus.DRAFT.value:
            raise ValueError(
                f"Cannot submit application in status {application.status}"
            )

        # Create vetting checks based on config
        await self._create_vetting_checks(application)

        # Update status
        now = datetime.utcnow()
        application = await self._app_repo.update_status(
            application_id, ApplicationStatus.SUBMITTED
        )
        if application:
            # Update submitted_at manually since update_status doesn't handle it
            async with self._db.session_scope() as session:
                app = await session.get(ApplicationRecord, str(application_id))
                if app:
                    app.submitted_at = now
                    await session.flush()
                    await session.refresh(app)
                    application = app

        # Log submission
        await self._audit_repo.log_event(
            application_id=application_id,
            event_type=AuditEventType.SUBMITTED,
            actor_id=actor_id,
            ip_address=ip_address,
        )

        logger.info(f"Submitted application {application.application_number}")
        return application

    async def _create_vetting_checks(self, application: ApplicationRecord) -> None:
        """Create vetting check records from configuration."""
        config = (application.extra_data or {}).get("vetting_config", {})
        requirements = config.get("requirements", [])

        now = datetime.utcnow()
        checks = []

        for req in requirements:
            check = VettingCheckRecord(
                id=str(uuid4()),
                application_id=application.id,
                check_type=_enum_value(req["type"]),
                status=VettingCheckStatus.PENDING.value,
                is_required=req.get("required", True),
                order=req.get("order", 0),
                config=req.get("config", {}),
                created_at=now,
                updated_at=now,
            )
            checks.append(check)

        if checks:
            await self._check_repo.create_many(checks)
            logger.info(
                f"Created {len(checks)} vetting checks for application {application.id}"
            )

    async def get_application(self, application_id: UUID) -> ApplicationRecord | None:
        """Get application by ID."""
        return await self._app_repo.get_by_id(application_id)

    async def get_application_by_reference(
        self, reference_number: str
    ) -> ApplicationRecord | None:
        """Get application by reference number."""
        return await self._app_repo.get_by_reference(reference_number)

    async def get_applicant_applications(
        self,
        applicant_id: UUID,
        status: ApplicationStatus | None = None,
    ) -> list[ApplicationRecord]:
        """Get all applications for an applicant."""
        return await self._app_repo.get_for_applicant(applicant_id, status)

    async def get_vetting_checks(
        self, application_id: UUID
    ) -> list[VettingCheckRecord]:
        """Get all vetting checks for an application."""
        return await self._check_repo.get_for_application(application_id)

    async def get_application_with_details(
        self, application_id: UUID
    ) -> dict[str, Any] | None:
        """Get application with all related records."""
        application = await self._app_repo.get_by_id(application_id)
        if not application:
            return None

        applicant = await self._applicant_repo.get_by_id(application.applicant_id)
        checks = await self._check_repo.get_for_application(application_id)
        kyc_submissions = await self._kyc_repo.get_for_application(application_id)
        audit_logs = await self._audit_repo.get_for_application(application_id, limit=20)

        return {
            "application": application,
            "applicant": applicant,
            "vetting_checks": checks,
            "kyc_submissions": kyc_submissions,
            "recent_audit_logs": audit_logs,
        }

    async def list_applications(
        self,
        status: ApplicationStatus | None = None,
        document_type: str | None = None,
        organization_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[ApplicationRecord], int]:
        """List applications with optional filters."""
        return await self._app_repo.list_all(status, document_type, organization_id, limit, offset)

    async def get_pending_applications(
        self, limit: int = 50
    ) -> list[ApplicationRecord]:
        """Get applications pending review."""
        return await self._app_repo.get_pending_review(limit)


class VettingService:
    """
    Service for managing vetting checks and workflow.
    
    Handles:
    - Check execution and status updates
    - Workflow progression
    - Manual review handling
    - Check result recording
    """

    def __init__(self, db_manager: ApplicantDatabaseManager | None = None) -> None:
        self._db = db_manager or get_db_manager()
        self._check_repo = VettingCheckRepository(self._db)
        self._app_repo = ApplicationRepository(self._db)
        self._audit_repo = ApplicationAuditRepository(self._db)

    async def start_check(
        self,
        check_id: UUID,
        actor_id: str = "system",
    ) -> VettingCheckRecord | None:
        """Mark a vetting check as in progress."""
        check = await self._check_repo.update_status(
            check_id, VettingCheckStatus.IN_PROGRESS
        )
        if check:
            await self._audit_repo.log_event(
                application_id=check.application_id,
                event_type=AuditEventType.VETTING_STARTED,
                actor_id=actor_id,
                details={"check_id": str(check_id), "check_type": _enum_value(check.check_type)},
            )
            await self._update_application_status(check.application_id)
        return check

    async def complete_check(
        self,
        check_id: UUID,
        passed: bool,
        result: dict[str, Any] | None = None,
        notes: str | None = None,
        performed_by: str | None = None,
    ) -> VettingCheckRecord | None:
        """
        Complete a vetting check with result.
        
        Args:
            check_id: Check ID
            passed: Whether the check passed
            result: Detailed check results
            notes: Optional notes
            performed_by: ID of person/system that performed check
            
        Returns:
            Updated VettingCheckRecord
        """
        status = VettingCheckStatus.PASSED if passed else VettingCheckStatus.FAILED
        check = await self._check_repo.update_status(
            check_id, status, result, notes, performed_by
        )

        if check:
            await self._audit_repo.log_event(
                application_id=check.application_id,
                event_type=AuditEventType.VETTING_CHECK_COMPLETED,
                actor_id=performed_by or "system",
                details={
                    "check_id": str(check_id),
                    "check_type": _enum_value(check.check_type),
                    "result": result,
                    "passed": passed,
                },
            )
            await self._update_application_status(check.application_id)

        return check

    async def request_manual_review(
        self,
        check_id: UUID,
        reason: str,
        actor_id: str = "system",
    ) -> VettingCheckRecord | None:
        """Flag a check for manual review."""
        check = await self._check_repo.update_status(
            check_id,
            VettingCheckStatus.REQUIRES_MANUAL_REVIEW,
            notes=reason,
        )

        if check:
            await self._audit_repo.log_event(
                application_id=check.application_id,
                event_type=AuditEventType.STATUS_CHANGED,
                actor_id=actor_id,
                details={
                    "check_id": str(check_id),
                    "check_type": _enum_value(check.check_type),
                    "reason": reason,
                },
            )

        return check

    async def _update_application_status(self, application_id: UUID) -> None:
        """Update application status based on check results."""
        checks = await self._check_repo.get_for_application(application_id)
        if not checks:
            return

        required_checks = [c for c in checks if c.is_required]
        
        # Check for any failures
        failed = [
            c for c in required_checks if c.status == VettingCheckStatus.FAILED.value
        ]
        if failed:
            await self._app_repo.update_status(
                application_id,
                ApplicationStatus.REJECTED,
                rejection_reason=f"Failed vetting check: {_enum_value(failed[0].check_type)}",
            )
            return

        # Check for manual review needed
        manual_review = [
            c
            for c in checks
            if c.status == VettingCheckStatus.REQUIRES_MANUAL_REVIEW.value
        ]
        if manual_review:
            # Status stays at current review stage
            return

        # Check if all required checks passed
        all_passed = all(
            c.status == VettingCheckStatus.PASSED.value for c in required_checks
        )
        if all_passed:
            await self._app_repo.update_status(
                application_id, ApplicationStatus.PENDING_APPROVAL
            )
            return

        # Check if any checks are in progress
        in_progress = [
            c for c in checks if c.status == VettingCheckStatus.IN_PROGRESS.value
        ]
        if in_progress:
            await self._app_repo.update_status(
                application_id, ApplicationStatus.VETTING_IN_PROGRESS
            )

    async def get_pending_checks(
        self,
        check_type: VettingCheckType | None = None,
        limit: int = 50,
    ) -> list[VettingCheckRecord]:
        """Get pending vetting checks for processing."""
        return await self._check_repo.get_pending_checks(check_type, limit)


class ApprovalService:
    """
    Service for managing application approvals.
    
    Handles:
    - Review and approval workflows
    - Multi-level approval chains
    - Final approval for document issuance
    """

    def __init__(self, db_manager: ApplicantDatabaseManager | None = None) -> None:
        self._db = db_manager or get_db_manager()
        self._app_repo = ApplicationRepository(self._db)
        self._check_repo = VettingCheckRepository(self._db)
        self._audit_repo = ApplicationAuditRepository(self._db)

    async def approve_application(
        self,
        application_id: UUID,
        approved_by: str,
        notes: str | None = None,
        ip_address: str | None = None,
    ) -> ApplicationRecord | None:
        """
        Approve an application for document issuance.
        
        Args:
            application_id: Application ID
            approved_by: ID of approving user
            notes: Optional approval notes
            ip_address: Request IP for audit
            
        Returns:
            Updated ApplicationRecord
        """
        application = await self._app_repo.get_by_id(application_id)
        if not application:
            raise ValueError(f"Application not found: {application_id}")

        if application.status != ApplicationStatus.PENDING_APPROVAL.value:
            raise ValueError(
                f"Cannot approve application in status {application.status}"
            )

        # Verify all required checks passed
        checks = await self._check_repo.get_for_application(application_id)
        required_checks = [c for c in checks if c.is_required]
        all_passed = all(
            c.status == VettingCheckStatus.PASSED.value for c in required_checks
        )
        if not all_passed:
            raise ValueError("Cannot approve: not all required checks passed")

        # Update status to approved
        application = await self._app_repo.update_status(
            application_id, ApplicationStatus.APPROVED, updated_by=approved_by
        )

        if application:
            await self._audit_repo.log_event(
                application_id=application_id,
                event_type=AuditEventType.APPROVED,
                actor_id=approved_by,
                details={"notes": notes} if notes else {},
                ip_address=ip_address,
            )
            logger.info(
                f"Approved application {application.application_number} by {approved_by}"
            )

        return application

    async def reject_application(
        self,
        application_id: UUID,
        rejected_by: str,
        reason: str,
        ip_address: str | None = None,
    ) -> ApplicationRecord | None:
        """
        Reject an application.
        
        Args:
            application_id: Application ID
            rejected_by: ID of rejecting user
            reason: Rejection reason
            ip_address: Request IP for audit
            
        Returns:
            Updated ApplicationRecord
        """
        application = await self._app_repo.get_by_id(application_id)
        if not application:
            raise ValueError(f"Application not found: {application_id}")

        if application.status in [
            ApplicationStatus.APPROVED.value,
            ApplicationStatus.ISSUED.value,
            ApplicationStatus.REJECTED.value,
        ]:
            raise ValueError(
                f"Cannot reject application in status {application.status}"
            )

        application = await self._app_repo.update_status(
            application_id,
            ApplicationStatus.REJECTED,
            updated_by=rejected_by,
            rejection_reason=reason,
        )

        if application:
            await self._audit_repo.log_event(
                application_id=application_id,
                event_type=AuditEventType.REJECTED,
                actor_id=rejected_by,
                details={"reason": reason},
                ip_address=ip_address,
            )
            logger.info(
                f"Rejected application {application.application_number}: {reason}"
            )

        return application

    async def request_revision(
        self,
        application_id: UUID,
        requested_by: str,
        notes: str,
        ip_address: str | None = None,
    ) -> ApplicationRecord | None:
        """
        Request revisions to an application.
        
        Sets status to NEEDS_REVISION and stores revision notes for the applicant.
        
        Args:
            application_id: Application ID
            requested_by: ID of user requesting revision
            notes: Revision notes/instructions
            ip_address: Request IP for audit
            
        Returns:
            Updated ApplicationRecord
        """
        application = await self._app_repo.get_by_id(application_id)
        if not application:
            raise ValueError(f"Application not found: {application_id}")

        if application.status in [
            ApplicationStatus.APPROVED.value,
            ApplicationStatus.ISSUED.value,
            ApplicationStatus.REJECTED.value,
        ]:
            raise ValueError(
                f"Cannot request revision for application in status {application.status}"
            )

        # Update application with revision info
        application.status = ApplicationStatus.NEEDS_REVISION.value
        application.status_changed_at = datetime.utcnow()
        application.status_changed_by = requested_by
        application.revision_requested_at = datetime.utcnow()
        application.revision_requested_by = requested_by
        application.revision_notes = notes
        application.revision_count += 1
        
        await self._app_repo.session.commit()
        await self._app_repo.session.refresh(application)

        await self._audit_repo.log_event(
            application_id=application_id,
            event_type=AuditEventType.REVISION_REQUESTED,
            actor_id=requested_by,
            details={"notes": notes, "revision_count": application.revision_count},
            ip_address=ip_address,
        )
        logger.info(
            f"Requested revision for application {application.application_number}: {notes}"
        )

        return application

    async def mark_issued(
        self,
        application_id: UUID,
        document_id: str,
        issued_by: str = "system",
    ) -> ApplicationRecord | None:
        """
        Mark application as issued after document creation.
        
        Args:
            application_id: Application ID
            document_id: ID of issued document
            issued_by: ID of issuing actor
            
        Returns:
            Updated ApplicationRecord
        """
        application = await self._app_repo.get_by_id(application_id)
        if not application:
            raise ValueError(f"Application not found: {application_id}")

        if application.status != ApplicationStatus.APPROVED.value:
            raise ValueError(
                f"Cannot issue for application in status {application.status}"
            )

        # Update to issued and store document ID in metadata
        async with self._db.session_scope() as session:
            app = await session.get(ApplicationRecord, str(application_id))
            if app:
                app.status = ApplicationStatus.ISSUED.value
                app.issued_at = datetime.utcnow()
                app.issued_document_id = document_id
                app.updated_at = datetime.utcnow()
                await session.flush()
                await session.refresh(app)
                application = app

        await self._audit_repo.log_event(
            application_id=application_id,
            event_type=AuditEventType.ISSUED,
            actor_id=issued_by,
            details={"document_id": document_id},
        )

        logger.info(
            f"Marked application {application.application_number} as issued: {document_id}"
        )
        return application

    async def get_approved_applications(
        self, limit: int = 50
    ) -> list[ApplicationRecord]:
        """Get applications approved and ready for issuance."""
        apps, _ = await self._app_repo.list_all(
            status=ApplicationStatus.APPROVED, limit=limit
        )
        return apps


class KYCService:
    """
    Service for managing KYC (Know Your Customer) submissions.
    
    Handles:
    - Document uploads and verification
    - Identity document management
    - Address verification documents
    """

    def __init__(self, db_manager: ApplicantDatabaseManager | None = None) -> None:
        self._db = db_manager or get_db_manager()
        self._kyc_repo = KYCSubmissionRepository(self._db)
        self._app_repo = ApplicationRepository(self._db)
        self._audit_repo = ApplicationAuditRepository(self._db)

    async def submit_kyc_document(
        self,
        application_id: UUID,
        field_type: KYCFieldType,
        field_value: str,
        document_data: bytes | None = None,
        document_type: str | None = None,
        document_number: str | None = None,
        issuing_country: str | None = None,
        issue_date: datetime | None = None,
        expiry_date: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> KYCSubmissionRecord:
        """
        Submit a KYC document for verification.
        
        Args:
            application_id: Application ID
            field_type: Type of KYC field
            field_value: Value for the field
            document_data: Optional document image/data
            document_type: Type of document (passport, driver_license, etc.)
            document_number: Document number
            issuing_country: Country that issued the document
            issue_date: Document issue date
            expiry_date: Document expiry date
            metadata: Additional metadata
            
        Returns:
            Created KYCSubmissionRecord
        """
        application = await self._app_repo.get_by_id(application_id)
        if not application:
            raise ValueError(f"Application not found: {application_id}")

        now = datetime.utcnow()
        issue_date_value = (
            issue_date.date() if isinstance(issue_date, datetime) else issue_date
        )
        expiry_date_value = (
            expiry_date.date() if isinstance(expiry_date, datetime) else expiry_date
        )
        document_type_value = document_type or field_type.value
        document_hash = (
            hashlib.sha256(document_data).hexdigest() if document_data else None
        )
        document_reference = None
        if metadata:
            document_reference = metadata.get("document_reference") or metadata.get(
                "document_storage_id"
            )

        extra_data = {
            "field_type": field_type.value,
            "field_value": field_value,
            "metadata": metadata or {},
            "document_bytes_length": len(document_data) if document_data else 0,
        }

        submission = KYCSubmissionRecord(
            id=str(uuid4()),
            applicant_id=str(application.applicant_id),
            application_id=str(application_id),
            document_type=document_type_value,
            document_number=document_number,
            issuing_country=issuing_country,
            issue_date=issue_date_value,
            expiry_date=expiry_date_value,
            document_reference=document_reference,
            document_hash=document_hash,
            status=KYCVerificationStatus.PENDING.value,
            extra_data=extra_data,
            created_at=now,
            updated_at=now,
        )

        created = await self._kyc_repo.create(submission)

        await self._audit_repo.log_event(
            application_id=application_id,
            event_type=AuditEventType.KYC_SUBMITTED,
            actor_id="applicant",
            details={
                "field_type": field_type.value,
                "document_type": document_type,
                "submission_id": str(created.id),
            },
        )

        logger.info(
            f"KYC submission {created.id} for application {application_id}"
        )
        return created

    async def verify_kyc_submission(
        self,
        submission_id: UUID,
        verified: bool,
        verified_by: str,
        notes: str | None = None,
    ) -> KYCSubmissionRecord | None:
        """Verify a KYC submission."""
        submission = await self._kyc_repo.update_verification(
            submission_id, verified, verified_by, notes
        )

        if submission:
            await self._audit_repo.log_event(
                application_id=submission.application_id,
                event_type=AuditEventType.KYC_VERIFIED if verified else AuditEventType.KYC_REJECTED,
                actor_id=verified_by,
                details={
                    "submission_id": str(submission_id),
                    "verified": verified,
                    "notes": notes,
                },
            )

        return submission

    async def get_kyc_submissions(
        self, application_id: UUID
    ) -> list[KYCSubmissionRecord]:
        """Get all KYC submissions for an application."""
        return await self._kyc_repo.get_for_application(application_id)
