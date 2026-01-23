"""
Applicant Service API - FastAPI Router

REST API endpoints for applicant vetting and application management.
Production-grade endpoints with full audit logging, validation, and compliance.
"""

from __future__ import annotations

import base64
import logging
from datetime import date, datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, UploadFile, File, Form, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, EmailStr, field_validator

from .database import init_database, get_db_manager
from .models import (
    ApplicationStatus,
    VettingCheckType,
    VettingCheckStatus,
    BiometricType,
    KYCFieldType,
    KYCVerificationStatus,
)
from .service import (
    ApplicantService,
    ApplicationService,
    VettingService,
    ApprovalService,
    KYCService,
)
from auth.router import get_current_user, AuthStatusResponse
from document_service.models import DocumentListResponse
from credentials.types import credential_to_application_type
from subscription.database import get_db_session as get_subscription_session
from subscription.models import CredentialTypeConfiguration
from sqlalchemy import select as sql_select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/applicants", tags=["Applicants"])

# Global service instances
_applicant_service: ApplicantService | None = None
_application_service: ApplicationService | None = None
_vetting_service: VettingService | None = None
_approval_service: ApprovalService | None = None
_kyc_service: KYCService | None = None


def get_applicant_service() -> ApplicantService:
    """Get or create the applicant service instance."""
    global _applicant_service
    if _applicant_service is None:
        _applicant_service = ApplicantService()
    return _applicant_service


def get_application_service() -> ApplicationService:
    """Get or create the application service instance."""
    global _application_service
    if _application_service is None:
        _application_service = ApplicationService()
    return _application_service


def get_vetting_service() -> VettingService:
    """Get or create the vetting service instance."""
    global _vetting_service
    if _vetting_service is None:
        _vetting_service = VettingService()
    return _vetting_service


def get_approval_service() -> ApprovalService:
    """Get or create the approval service instance."""
    global _approval_service
    if _approval_service is None:
        _approval_service = ApprovalService()
    return _approval_service


def get_kyc_service() -> KYCService:
    """Get or create the KYC service instance."""
    global _kyc_service
    if _kyc_service is None:
        _kyc_service = KYCService()
    return _kyc_service


async def _emit_sse_event(
    event_type: str,
    user_id: Optional[str] = None,
    organization_id: Optional[str] = None,
    data: Optional[dict] = None,
    title: Optional[str] = None,
    body: Optional[str] = None,
) -> None:
    """
    Emit an SSE event for test observability.
    
    Args:
        event_type: Event type (e.g., 'application.approved', 'credential.issued')
        user_id: Target user ID
        organization_id: Target organization ID
        data: Event data payload
        title: Event title
        body: Event body/description
    """
    try:
        import sys
        from pathlib import Path
        from uuid import uuid4
        from datetime import datetime, timezone
        
        # Add main src directory to path for notifications module
        _main_src = Path(__file__).parent.parent.parent.parent / "src"
        if _main_src.exists() and str(_main_src) not in sys.path:
            sys.path.insert(0, str(_main_src))
        sys.path.insert(0, '/app')  # For Docker context
        
        from notifications.adapters.sse import SSEAdapter
        from notifications.types import NotificationPayload, NotificationTarget
        from notifications.api import get_sse_adapter
        
        try:
            sse_adapter = get_sse_adapter()
        except Exception:
            # SSE not configured, skip
            return
        
        payload = NotificationPayload(
            id=uuid4(),
            event_type=event_type,
            title=title or event_type,
            body=body or "",
            data=data or {},
            created_at=datetime.now(timezone.utc),
            target=NotificationTarget(
                user_id=user_id,
                organization_id=UUID(organization_id) if organization_id else None,
            ) if (user_id or organization_id) else None,
        )
        
        await sse_adapter.send(payload)
        logger.debug(f"SSE event emitted: {event_type}")
        
    except Exception as e:
        logger.debug(f"Failed to emit SSE event {event_type}: {e}")


async def _trigger_credential_issuance(application) -> None:
    """
    Trigger credential issuance after an application is approved.
    
    Creates a credential offer for the applicant that can be picked up
    via OID4VCI protocol. Attempts to find the user's registered device
    for push notification delivery via SSE.
    """
    try:
        from issuance.service import get_issuance_service
        
        issuance_service = get_issuance_service()
        
        # Build credential data from application
        credential_data = {
            "given_name": application.applicant.given_name if application.applicant else None,
            "family_name": application.applicant.family_name if application.applicant else None,
            "application_number": application.application_number,
            "approved_at": application.approved_at.isoformat() if application.approved_at else None,
        }
        
        # Get the applicant's user_id
        user_id = application.applicant.user_id if application.applicant else str(application.applicant_id)
        organization_id = application.organization_id or "default"
        
        # Look up the user's registered device for push notifications
        device_id = await _get_user_device_id(organization_id, user_id)
        
        # Create credential offer
        session = await issuance_service.create_offer_for_application(
            organization_id=organization_id,
            application_id=str(application.id),
            credential_config_id=application.credential_type or "default_credential",
            applicant_id=user_id,
            credential_data=credential_data,
            device_id=device_id,
        )
        
        logger.info(
            f"Created credential offer for application {application.application_number}, "
            f"transaction_id={session.transaction_id}, device_id={device_id}"
        )
    except Exception as e:
        # Log but don't fail the approval - credential issuance can be retried
        logger.error(f"Failed to trigger credential issuance for application {application.id}: {e}")


async def _get_user_device_id(tenant_id: str, user_id: str) -> Optional[str]:
    """
    Get the user's active device ID for push notifications.
    
    Looks up the user's registered devices and returns the most recently
    active one. Returns None if no devices are registered.
    
    Args:
        tenant_id: The organization/tenant ID
        user_id: The user ID
        
    Returns:
        Device ID if found, None otherwise
    """
    try:
        from notifications_local import get_notification_hub
        
        hub = get_notification_hub()
        if not hub or not hub._registry:
            logger.debug(f"No notification hub available for device lookup")
            return None
        
        # Find user's registered devices
        registrations = await hub._registry._repository.find_by_user(
            tenant_id=tenant_id,
            user_id=user_id,
        )
        
        if not registrations:
            logger.debug(f"No devices registered for user {user_id}")
            return None
        
        # Get the most recently active device (prefer FCM devices)
        active_devices = [r for r in registrations if r.is_active]
        if not active_devices:
            return None
        
        # Sort by last_used_at (most recent first)
        active_devices.sort(
            key=lambda r: r.last_used_at or r.created_at,
            reverse=True,
        )
        
        device = active_devices[0]
        logger.debug(f"Found device for user {user_id}: {device.device_id}")
        return device.device_id
        
    except Exception as e:
        logger.warning(f"Failed to lookup device for user {user_id}: {e}")
        return None


@router.on_event("startup")
async def startup_event() -> None:
    """Initialize applicant database on API startup."""
    await init_database()
    logger.info("Applicant service initialized")


# ==================== Pydantic Models for API ====================

class AddressModel(BaseModel):
    """Address structure for API."""
    street_line1: str
    street_line2: str | None = None
    city: str
    state_province: str | None = None
    postal_code: str
    country: str = Field(..., min_length=3, max_length=3, description="ISO 3166-1 alpha-3")


class CreateApplicantRequest(BaseModel):
    """Request to create a new applicant."""
    user_id: str = Field(..., description="User account ID from auth system")
    given_name: str = Field(..., min_length=1, max_length=100)
    family_name: str = Field(..., min_length=1, max_length=100)
    email: EmailStr
    date_of_birth: datetime
    nationality: str = Field(..., min_length=3, max_length=3, description="ISO 3166-1 alpha-3")
    phone_number: str | None = None
    address: AddressModel | None = None


class UpdateApplicantRequest(BaseModel):
    """Request to update an applicant."""
    given_name: str | None = None
    family_name: str | None = None
    phone_number: str | None = None
    address: AddressModel | None = None


class ApplicantResponse(BaseModel):
    """Response containing an applicant."""
    id: UUID
    user_id: str
    given_name: str
    family_name: str
    full_name: str
    email: str
    phone_number: str | None
    date_of_birth: datetime
    nationality: str
    address: dict[str, Any]
    is_active: bool
    is_email_verified: bool
    is_phone_verified: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class BiometricEnrollRequest(BaseModel):
    """Request to enroll a biometric."""
    biometric_type: BiometricType
    template_data_base64: str = Field(..., description="Base64 encoded ISO 19794 template")
    image_data_base64: str | None = Field(None, description="Base64 encoded image data")
    capture_quality_score: float | None = Field(None, ge=0, le=1)
    capture_device_id: str | None = None
    is_live_capture: bool = True
    metadata: dict[str, Any] | None = None

    @field_validator("biometric_type", mode="before")
    @classmethod
    def normalize_biometric_type(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.lower()
        return value


class BiometricEnrollmentResponse(BaseModel):
    """Response containing a biometric enrollment."""
    id: UUID
    applicant_id: UUID
    biometric_type: BiometricType
    template_format: str
    capture_quality_score: float | None
    capture_device_id: str | None
    is_live_capture: bool
    captured_at: datetime
    is_verified: bool
    verification_score: float | None
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class CreateApplicationRequest(BaseModel):
    """Request to create a new application."""
    applicant_id: UUID
    credential_configuration_id: str = Field(..., description="Credential configuration ID")
    issuing_authority: str
    requested_validity_years: int = Field(10, ge=1, le=20)
    travel_purpose: str | None = Field(None, description="Purpose of travel (for visas)")
    destination_countries: list[str] | None = Field(None, description="Destination countries (ISO alpha-3)")
    is_expedited: bool = False
    metadata: dict[str, Any] | None = None


class ApplicationResponse(BaseModel):
    """Response containing an application."""
    id: UUID
    reference_number: str
    applicant_id: UUID
    document_type: str
    credential_configuration_id: str | None = None
    credential_type: str | None = None
    credential_display_name: str | None = None
    organization_id: str | None = None
    status: ApplicationStatus
    issuing_authority: str
    requested_validity_years: int
    travel_purpose: str | None
    destination_countries: list[str]
    is_expedited: bool
    submitted_at: datetime | None
    approved_at: datetime | None
    approved_by: str | None
    issued_at: datetime | None
    issued_document_id: str | None
    rejection_reason: str | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ApplicationListResponse(BaseModel):
    """Response containing list of applications."""
    applications: list[ApplicationResponse]
    total: int
    limit: int
    offset: int


class VettingCheckResponse(BaseModel):
    """Response containing a vetting check."""
    id: UUID
    application_id: UUID
    check_type: VettingCheckType
    status: VettingCheckStatus
    is_required: bool
    order: int
    result: dict[str, Any] | None
    notes: str | None
    started_at: datetime | None
    completed_at: datetime | None
    performed_by: str | None
    created_at: datetime

    class Config:
        from_attributes = True


class CompleteCheckRequest(BaseModel):
    """Request to complete a vetting check."""
    passed: bool
    result: dict[str, Any] | None = None
    notes: str | None = None
    performed_by: str | None = None


class ApproveApplicationRequest(BaseModel):
    """Request to approve an application."""
    approved_by: str
    notes: str | None = None


class RejectApplicationRequest(BaseModel):
    """Request to reject an application."""
    rejected_by: str
    reason: str


class KYCSubmissionRequest(BaseModel):
    """Request to submit KYC information."""
    field_type: KYCFieldType
    field_value: str
    document_data_base64: str | None = Field(None, description="Base64 encoded document image")
    document_type: str | None = None
    document_number: str | None = None
    issuing_country: str | None = Field(None, min_length=3, max_length=3)
    issue_date: datetime | None = None
    expiry_date: datetime | None = None
    metadata: dict[str, Any] | None = None


class KYCSubmissionResponse(BaseModel):
    """Response containing a KYC submission."""
    id: UUID
    application_id: UUID
    field_type: KYCFieldType
    field_value: str
    document_type: str | None
    document_number: str | None
    issuing_country: str | None
    issue_date: datetime | None
    expiry_date: datetime | None
    is_verified: bool
    verified_by: str | None
    verified_at: datetime | None
    submitted_at: datetime
    created_at: datetime

    class Config:
        from_attributes = True


class ApplicationDetailResponse(BaseModel):
    """Detailed application response with all related data."""
    application: ApplicationResponse
    applicant: ApplicantResponse | None
    vetting_checks: list[VettingCheckResponse]
    kyc_submissions: list[KYCSubmissionResponse]


class ApprovedApplicantResponse(BaseModel):
    """Response for approved applicants ready for document issuance."""
    application_id: UUID
    reference_number: str
    applicant_id: UUID
    applicant_name: str
    document_type: str
    credential_configuration_id: str | None = None
    credential_type: str | None = None
    credential_display_name: str | None = None
    approved_at: datetime
    approved_by: str | None


# ==================== Helper Functions ====================

def get_client_info(request: Request) -> tuple[str | None, str | None]:
    """Extract client info from request for audit."""
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    return ip_address, user_agent


def get_actor_id(request: Request) -> str:
    """Extract actor ID from request headers or return default."""
    # In production, this would come from JWT token or session
    return request.headers.get("X-Actor-ID", "api_user")


def _to_uuid(value: Any) -> UUID:
    if isinstance(value, UUID):
        return value
    return UUID(str(value))


def _date_to_datetime(value: date | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.combine(value, datetime.min.time(), tzinfo=timezone.utc)


def _build_address(applicant: Any) -> dict[str, Any]:
    return {
        "street_line1": getattr(applicant, "address_line1", None),
        "street_line2": getattr(applicant, "address_line2", None),
        "city": getattr(applicant, "city", None),
        "state_province": getattr(applicant, "state_province", None),
        "postal_code": getattr(applicant, "postal_code", None),
        "country": getattr(applicant, "country", None),
    }


def build_applicant_response(applicant: Any) -> ApplicantResponse:
    extra = applicant.extra_data or {}
    given_name = applicant.given_names
    family_name = applicant.surname
    full_name = f"{given_name} {family_name}".strip()

    return ApplicantResponse(
        id=_to_uuid(applicant.id),
        user_id=applicant.account_id or "",
        given_name=given_name,
        family_name=family_name,
        full_name=full_name,
        email=applicant.email,
        phone_number=applicant.phone,
        date_of_birth=_date_to_datetime(applicant.date_of_birth),
        nationality=applicant.nationality,
        address=_build_address(applicant),
        is_active=applicant.active,
        is_email_verified=bool(extra.get("email_verified", False)),
        is_phone_verified=bool(extra.get("phone_verified", False)),
        created_at=applicant.created_at,
        updated_at=applicant.updated_at,
    )


def build_application_response(application: Any) -> ApplicationResponse:
    extra = application.extra_data or {}
    status_value = application.status
    try:
        status = ApplicationStatus(status_value)
    except ValueError:
        status = ApplicationStatus.DRAFT

    return ApplicationResponse(
        id=_to_uuid(application.id),
        reference_number=application.application_number,
        applicant_id=_to_uuid(application.applicant_id),
        document_type=application.document_type,
        credential_configuration_id=application.credential_configuration_id,
        credential_type=application.credential_type,
        credential_display_name=extra.get("credential_display_name"),
        organization_id=application.organization_id,
        status=status,
        issuing_authority=extra.get("issuing_authority", ""),
        requested_validity_years=application.requested_validity_years,
        travel_purpose=extra.get("travel_purpose"),
        destination_countries=extra.get("destination_countries") or [],
        is_expedited=bool(extra.get("is_expedited", False)),
        submitted_at=application.submitted_at,
        approved_at=application.approved_at,
        approved_by=application.approved_by,
        issued_at=application.issued_at,
        issued_document_id=application.issued_document_id,
        rejection_reason=application.rejection_reason,
        created_at=application.created_at,
        updated_at=application.updated_at,
    )


def build_vetting_check_response(check: Any) -> VettingCheckResponse:
    extra = check.extra_data or {}
    try:
        check_type = VettingCheckType(check.check_type)
    except ValueError:
        check_type = VettingCheckType.IDENTITY_VERIFICATION
    try:
        status = VettingCheckStatus(check.status)
    except ValueError:
        status = VettingCheckStatus.NOT_STARTED

    return VettingCheckResponse(
        id=_to_uuid(check.id),
        application_id=_to_uuid(check.application_id),
        check_type=check_type,
        status=status,
        is_required=check.is_required,
        order=check.order,
        result=check.result,
        notes=check.notes,
        started_at=check.started_at,
        completed_at=check.completed_at,
        performed_by=extra.get("performed_by") or check.check_authority or check.external_provider,
        created_at=check.created_at,
    )


def build_biometric_response(enrollment: Any) -> BiometricEnrollmentResponse:
    extra = enrollment.extra_data or {}
    verification_score = extra.get("verification_score")
    try:
        biometric_type = BiometricType(enrollment.biometric_type)
    except ValueError:
        biometric_type = BiometricType.FACIAL

    return BiometricEnrollmentResponse(
        id=_to_uuid(enrollment.id),
        applicant_id=_to_uuid(enrollment.applicant_id),
        biometric_type=biometric_type,
        template_format=enrollment.template_format,
        capture_quality_score=enrollment.quality_score,
        capture_device_id=enrollment.capture_device,
        is_live_capture=bool(enrollment.liveness_check_performed),
        captured_at=enrollment.captured_at,
        is_verified=bool(enrollment.last_verification_result)
        if enrollment.last_verification_result is not None
        else False,
        verification_score=verification_score,
        is_active=enrollment.active,
        created_at=enrollment.created_at,
    )


def build_kyc_submission_response(submission: Any) -> KYCSubmissionResponse:
    extra = submission.extra_data or {}
    field_type_value = extra.get("field_type")
    try:
        field_type = KYCFieldType(field_type_value) if field_type_value else KYCFieldType.OTHER
    except ValueError:
        field_type = KYCFieldType.OTHER

    is_verified = submission.status == KYCVerificationStatus.VERIFIED.value

    return KYCSubmissionResponse(
        id=_to_uuid(submission.id),
        application_id=_to_uuid(submission.application_id),
        field_type=field_type,
        field_value=extra.get("field_value", ""),
        document_type=submission.document_type,
        document_number=submission.document_number,
        issuing_country=submission.issuing_country,
        issue_date=_date_to_datetime(submission.issue_date),
        expiry_date=_date_to_datetime(submission.expiry_date),
        is_verified=is_verified,
        verified_by=submission.verified_by,
        verified_at=submission.verified_at,
        submitted_at=submission.created_at,
        created_at=submission.created_at,
    )


# ==================== Applicant Endpoints ====================

@router.post("", response_model=ApplicantResponse, status_code=201)
async def create_applicant(
    req: CreateApplicantRequest,
    request: Request,
) -> ApplicantResponse:
    """
    Create a new applicant record.
    
    This is the first step in the applicant vetting process.
    After creation, the applicant should enroll their facial biometric.
    
    Args:
        req: Applicant creation request
        
    Returns:
        Created applicant record
        
    Raises:
        400: Applicant already exists
    """
    service = get_applicant_service()
    ip_address, _ = get_client_info(request)
    actor_id = get_actor_id(request)

    try:
        applicant = await service.create_applicant(
            user_id=req.user_id,
            given_name=req.given_name,
            family_name=req.family_name,
            email=req.email,
            date_of_birth=req.date_of_birth,
            nationality=req.nationality,
            phone_number=req.phone_number,
            address=req.address.model_dump() if req.address else None,
            actor_id=actor_id,
            ip_address=ip_address,
        )
        return build_applicant_response(applicant)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))




# ==================== Biometric Endpoints ====================

@router.post("/{applicant_id}/biometrics", response_model=BiometricEnrollmentResponse, status_code=201)
async def enroll_biometric(
    applicant_id: UUID,
    req: BiometricEnrollRequest,
    request: Request,
) -> BiometricEnrollmentResponse:
    """
    Enroll a biometric for an applicant.
    
    For account creation, facial biometric should be captured live.
    Additional biometrics (fingerprint, iris) are captured during application.
    
    Args:
        applicant_id: UUID of the applicant
        req: Biometric enrollment request
        
    Returns:
        Created biometric enrollment record
        
    Raises:
        404: Applicant not found
    """
    service = get_applicant_service()
    
    # Verify applicant exists
    applicant = await service.get_applicant(applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail=f"Applicant {applicant_id} not found")

    # Decode base64 data
    try:
        template_data = base64.b64decode(req.template_data_base64)
        image_data = base64.b64decode(req.image_data_base64) if req.image_data_base64 else None
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 encoding: {e}")

    enrollment = await service.enroll_biometric(
        applicant_id=applicant_id,
        biometric_type=req.biometric_type,
        template_data=template_data,
        image_data=image_data,
        capture_quality_score=req.capture_quality_score,
        capture_device_id=req.capture_device_id,
        is_live_capture=req.is_live_capture,
        metadata=req.metadata,
    )

    return build_biometric_response(enrollment)


@router.get("/{applicant_id}/biometrics", response_model=list[BiometricEnrollmentResponse])
async def get_applicant_biometrics(
    applicant_id: UUID,
    biometric_type: BiometricType | None = Query(None),
) -> list[BiometricEnrollmentResponse]:
    """
    Get biometric enrollments for an applicant.
    
    Args:
        applicant_id: UUID of the applicant
        biometric_type: Optional filter by type
        
    Returns:
        List of active biometric enrollments
    """
    service = get_applicant_service()
    enrollments = await service.get_applicant_biometrics(applicant_id, biometric_type)
    return [build_biometric_response(e) for e in enrollments]


# ==================== Application Endpoints ====================

@router.post("/applications", response_model=ApplicationResponse, status_code=201)
async def create_application(
    req: CreateApplicationRequest,
    request: Request,
    subscription_db: AsyncSession = Depends(get_subscription_session),
) -> ApplicationResponse:
    """
    Create a new travel document application.
    
    The application starts in DRAFT status. Use submit endpoint to begin vetting.
    
    Args:
        req: Application creation request
        
    Returns:
        Created application in DRAFT status
        
    Raises:
        400: Invalid request or applicant not found
    """
    service = get_application_service()
    ip_address, _ = get_client_info(request)
    actor_id = get_actor_id(request)

    try:
        if not req.credential_configuration_id:
            raise HTTPException(status_code=400, detail="Credential configuration is required")

        config_result = await subscription_db.execute(
            sql_select(CredentialTypeConfiguration).where(
                CredentialTypeConfiguration.id == req.credential_configuration_id,
                CredentialTypeConfiguration.is_active == True,
            )
        )
        config = config_result.scalar_one_or_none()
        if not config:
            raise HTTPException(status_code=404, detail="Credential configuration not found")

        document_type = credential_to_application_type(config.credential_type)
        metadata = req.metadata or {}
        metadata.update(
            {
                "credential_configuration_id": config.id,
                "credential_type": config.credential_type.value,
                "credential_display_name": config.display_name,
            }
        )

        application = await service.create_application(
            applicant_id=req.applicant_id,
            document_type=document_type,
            credential_configuration_id=config.id,
            credential_type=config.credential_type.value,
            organization_id=config.organization_id,
            issuing_authority=req.issuing_authority,
            requested_validity_years=req.requested_validity_years,
            travel_purpose=req.travel_purpose,
            destination_countries=req.destination_countries,
            expedited=req.is_expedited,
            metadata=metadata,
            actor_id=actor_id,
            ip_address=ip_address,
        )
        return build_application_response(application)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/applications/{application_id}/submit", response_model=ApplicationResponse)
async def submit_application(
    application_id: UUID,
    request: Request,
) -> ApplicationResponse:
    """
    Submit an application for vetting.
    
    Transitions from DRAFT to SUBMITTED and creates vetting checks.
    
    Args:
        application_id: UUID of the application
        
    Returns:
        Updated application in SUBMITTED status
        
    Raises:
        400: Invalid state transition
        404: Application not found
    """
    service = get_application_service()
    ip_address, _ = get_client_info(request)
    actor_id = get_actor_id(request)

    try:
        application = await service.submit_application(
            application_id=application_id,
            actor_id=actor_id,
            ip_address=ip_address,
        )
        return build_application_response(application)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/applications", response_model=ApplicationListResponse)
async def list_applications(
    status: ApplicationStatus | None = Query(None, description="Filter by status"),
    document_type: str | None = Query(None, description="Filter by document type"),
    organization_id: str | None = Query(None, description="Filter by organization ID"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> ApplicationListResponse:
    """
    List applications with optional filters.
    
    Args:
        status: Filter by application status
        document_type: Filter by document type
        organization_id: Filter by organization ID (for vendor views)
        limit: Maximum results
        offset: Pagination offset
        
    Returns:
        List of applications with pagination info
    """
    service = get_application_service()
    applications, total = await service.list_applications(
        status=status,
        document_type=document_type,
        organization_id=organization_id,
        limit=limit,
        offset=offset,
    )
    
    return ApplicationListResponse(
        applications=[build_application_response(a) for a in applications],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/applications/by-reference/{reference_number}", response_model=ApplicationResponse)
async def get_application_by_reference(reference_number: str) -> ApplicationResponse:
    """
    Get application by reference number.

    Args:
        reference_number: Application reference number (e.g., APP-20250101-ABC123)

    Returns:
        Application record

    Raises:
        404: Application not found
    """
    service = get_application_service()
    application = await service.get_application_by_reference(reference_number)

    if not application:
        raise HTTPException(status_code=404, detail=f"Application {reference_number} not found")

    return build_application_response(application)


@router.get("/applications/approved", response_model=list[ApprovedApplicantResponse])
async def get_approved_applications(
    limit: int = Query(50, ge=1, le=200),
) -> list[ApprovedApplicantResponse]:
    """
    Get approved applications ready for document issuance.

    These applications have passed all vetting and are ready
    to have travel documents issued.

    Args:
        limit: Maximum results

    Returns:
        List of approved applications with applicant info
    """
    approval_service = get_approval_service()
    applicant_service = get_applicant_service()

    applications = await approval_service.get_approved_applications(limit)

    result = []
    for app in applications:
        applicant = await applicant_service.get_applicant(app.applicant_id)
        if applicant:
            extra = app.extra_data or {}
            result.append(
                ApprovedApplicantResponse(
                    application_id=_to_uuid(app.id),
                    reference_number=app.application_number,
                    applicant_id=_to_uuid(app.applicant_id),
                    applicant_name=f"{applicant.given_names} {applicant.surname}".strip(),
                    document_type=app.document_type,
                    credential_configuration_id=app.credential_configuration_id,
                    credential_type=app.credential_type,
                    credential_display_name=extra.get("credential_display_name"),
                    approved_at=app.approved_at,
                    approved_by=app.approved_by,
                )
            )

    return result


@router.get("/applications/{application_id}", response_model=ApplicationDetailResponse)
async def get_application(application_id: UUID) -> ApplicationDetailResponse:
    """
    Get detailed application information.

    Includes applicant, vetting checks, and KYC submissions.

    Args:
        application_id: UUID of the application

    Returns:
        Detailed application information

    Raises:
        404: Application not found
    """
    service = get_application_service()
    details = await service.get_application_with_details(application_id)

    if not details:
        raise HTTPException(status_code=404, detail=f"Application {application_id} not found")

    return ApplicationDetailResponse(
        application=build_application_response(details["application"]),
        applicant=build_applicant_response(details["applicant"]) if details["applicant"] else None,
        vetting_checks=[build_vetting_check_response(c) for c in details["vetting_checks"]],
        kyc_submissions=[build_kyc_submission_response(s) for s in details["kyc_submissions"]],
    )


@router.get("/{applicant_id}/applications", response_model=list[ApplicationResponse])
async def get_applicant_applications(
    applicant_id: UUID,
    status: ApplicationStatus | None = Query(None),
) -> list[ApplicationResponse]:
    """
    Get all applications for an applicant.
    
    Args:
        applicant_id: UUID of the applicant
        status: Optional status filter
        
    Returns:
        List of applications for the applicant
    """
    service = get_application_service()
    applications = await service.get_applicant_applications(applicant_id, status)
    return [build_application_response(a) for a in applications]


@router.get("/me/documents", response_model=DocumentListResponse)
async def get_my_documents(
    current_user: AuthStatusResponse = Depends(get_current_user),
) -> DocumentListResponse:
    """
    Get issued documents for the authenticated applicant.
    """
    if not current_user.authenticated or not current_user.user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    applicant_id = current_user.user.applicant_id
    if not applicant_id:
        applicant = await get_applicant_service().get_applicant_by_user(
            current_user.user.user_id
        )
        if not applicant:
            raise HTTPException(status_code=404, detail="Applicant profile not found")
        applicant_id = applicant.id

    from integration import get_applicant_document_integration

    integration = get_applicant_document_integration()
    documents = await integration.get_documents_for_applicant(applicant_id)

    return DocumentListResponse(
        documents=documents,
        total=len(documents),
        limit=len(documents),
        offset=0,
    )


# ==================== Vetting Check Endpoints ====================

@router.get("/applications/{application_id}/checks", response_model=list[VettingCheckResponse])
async def get_vetting_checks(application_id: UUID) -> list[VettingCheckResponse]:
    """
    Get all vetting checks for an application.
    
    Args:
        application_id: UUID of the application
        
    Returns:
        List of vetting checks in order
    """
    service = get_application_service()
    checks = await service.get_vetting_checks(application_id)
    return [build_vetting_check_response(c) for c in checks]


@router.post("/checks/{check_id}/start", response_model=VettingCheckResponse)
async def start_vetting_check(
    check_id: UUID,
    request: Request,
) -> VettingCheckResponse:
    """
    Start a vetting check.
    
    Args:
        check_id: UUID of the check
        
    Returns:
        Updated check in IN_PROGRESS status
    """
    service = get_vetting_service()
    actor_id = get_actor_id(request)
    
    check = await service.start_check(check_id, actor_id)
    if not check:
        raise HTTPException(status_code=404, detail=f"Check {check_id} not found")
    
    return build_vetting_check_response(check)


@router.post("/checks/{check_id}/complete", response_model=VettingCheckResponse)
async def complete_vetting_check(
    check_id: UUID,
    req: CompleteCheckRequest,
) -> VettingCheckResponse:
    """
    Complete a vetting check with result.
    
    Args:
        check_id: UUID of the check
        req: Completion request with pass/fail and details
        
    Returns:
        Updated check with result
    """
    service = get_vetting_service()
    
    check = await service.complete_check(
        check_id=check_id,
        passed=req.passed,
        result=req.result,
        notes=req.notes,
        performed_by=req.performed_by,
    )
    
    if not check:
        raise HTTPException(status_code=404, detail=f"Check {check_id} not found")
    
    # Emit SSE event for test observability
    if check.application:
        user_id = check.application.applicant.user_id if check.application.applicant else str(check.application.applicant_id)
        await _emit_sse_event(
            event_type="check.completed",
            user_id=user_id,
            organization_id=str(check.application.organization_id) if check.application.organization_id else None,
            data={
                "check_id": str(check.id),
                "application_id": str(check.application_id),
                "check_type": check.check_type.value if hasattr(check.check_type, 'value') else str(check.check_type),
                "passed": check.passed,
                "result": check.result,
            },
            title="Check Completed",
            body=f"Check {check.check_type.value if hasattr(check.check_type, 'value') else check.check_type} {'passed' if check.passed else 'failed'}",
        )
    
    return build_vetting_check_response(check)


@router.post("/checks/{check_id}/manual-review", response_model=VettingCheckResponse)
async def request_manual_review(
    check_id: UUID,
    reason: str = Query(..., description="Reason for manual review"),
    request: Request = None,
) -> VettingCheckResponse:
    """
    Flag a check for manual review.
    
    Args:
        check_id: UUID of the check
        reason: Reason for manual review
        
    Returns:
        Updated check in REQUIRES_MANUAL_REVIEW status
    """
    service = get_vetting_service()
    actor_id = get_actor_id(request) if request else "system"
    
    check = await service.request_manual_review(check_id, reason, actor_id)
    if not check:
        raise HTTPException(status_code=404, detail=f"Check {check_id} not found")
    
    return build_vetting_check_response(check)


@router.get("/checks/pending", response_model=list[VettingCheckResponse])
async def get_pending_checks(
    check_type: VettingCheckType | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
) -> list[VettingCheckResponse]:
    """
    Get pending vetting checks for processing.
    
    Args:
        check_type: Filter by check type
        limit: Maximum results
        
    Returns:
        List of pending checks
    """
    service = get_vetting_service()
    checks = await service.get_pending_checks(check_type, limit)
    return [build_vetting_check_response(c) for c in checks]


# ==================== KYC Endpoints ====================

@router.post("/applications/{application_id}/kyc", response_model=KYCSubmissionResponse, status_code=201)
async def submit_kyc(
    application_id: UUID,
    req: KYCSubmissionRequest,
    request: Request,
) -> KYCSubmissionResponse:
    """
    Submit KYC information for an application.
    
    Args:
        application_id: UUID of the application
        req: KYC submission request
        
    Returns:
        Created KYC submission
    """
    service = get_kyc_service()
    
    # Decode document data if provided
    document_data = None
    if req.document_data_base64:
        try:
            document_data = base64.b64decode(req.document_data_base64)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid base64 encoding: {e}")

    submission = await service.submit_kyc_document(
        application_id=application_id,
        field_type=req.field_type,
        field_value=req.field_value,
        document_data=document_data,
        document_type=req.document_type,
        document_number=req.document_number,
        issuing_country=req.issuing_country,
        issue_date=req.issue_date,
        expiry_date=req.expiry_date,
        metadata=req.metadata,
    )

    return build_kyc_submission_response(submission)


@router.get("/applications/{application_id}/kyc", response_model=list[KYCSubmissionResponse])
async def get_kyc_submissions(application_id: UUID) -> list[KYCSubmissionResponse]:
    """
    Get all KYC submissions for an application.
    
    Args:
        application_id: UUID of the application
        
    Returns:
        List of KYC submissions
    """
    service = get_kyc_service()
    submissions = await service.get_kyc_submissions(application_id)
    return [build_kyc_submission_response(s) for s in submissions]


@router.post("/kyc/{submission_id}/verify", response_model=KYCSubmissionResponse)
async def verify_kyc_submission(
    submission_id: UUID,
    verified: bool = Query(...),
    verified_by: str = Query(...),
    notes: str | None = Query(None),
) -> KYCSubmissionResponse:
    """
    Verify or reject a KYC submission.
    
    Args:
        submission_id: UUID of the KYC submission
        verified: Whether the submission is verified
        verified_by: ID of verifying user
        notes: Optional verification notes
        
    Returns:
        Updated KYC submission
    """
    service = get_kyc_service()
    
    submission = await service.verify_kyc_submission(
        submission_id=submission_id,
        verified=verified,
        verified_by=verified_by,
        notes=notes,
    )
    
    if not submission:
        raise HTTPException(status_code=404, detail=f"KYC submission {submission_id} not found")
    
    return build_kyc_submission_response(submission)


# ==================== Approval Endpoints ====================

@router.post("/applications/{application_id}/approve", response_model=ApplicationResponse)
async def approve_application(
    application_id: UUID,
    req: ApproveApplicationRequest,
    request: Request,
) -> ApplicationResponse:
    """
    Approve an application for document issuance.
    
    Requires all mandatory vetting checks to have passed.
    After approval, automatically creates a credential offer for the applicant.
    
    Args:
        application_id: UUID of the application
        req: Approval request
        
    Returns:
        Updated application in APPROVED status
        
    Raises:
        400: Cannot approve (checks not passed or invalid state)
    """
    service = get_approval_service()
    ip_address, _ = get_client_info(request)

    try:
        application = await service.approve_application(
            application_id=application_id,
            approved_by=req.approved_by,
            notes=req.notes,
            ip_address=ip_address,
        )
        
        # Emit SSE event for test observability
        user_id = application.applicant.user_id if application.applicant else str(application.applicant_id)
        await _emit_sse_event(
            event_type="application.approved",
            user_id=user_id,
            organization_id=str(application.organization_id) if application.organization_id else None,
            data={
                "application_id": str(application.id),
                "application_number": application.application_number,
                "status": application.status.value if hasattr(application.status, 'value') else str(application.status),
            },
            title="Application Approved",
            body=f"Application {application.application_number} has been approved",
        )
        
        # Trigger credential issuance after approval
        await _trigger_credential_issuance(application)
        
        return build_application_response(application)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/applications/{application_id}/reject", response_model=ApplicationResponse)
async def reject_application(
    application_id: UUID,
    req: RejectApplicationRequest,
    request: Request,
) -> ApplicationResponse:
    """
    Reject an application.
    
    Args:
        application_id: UUID of the application
        req: Rejection request
        
    Returns:
        Updated application in REJECTED status
        
    Raises:
        400: Invalid state transition
    """
    service = get_approval_service()
    ip_address, _ = get_client_info(request)

    try:
        application = await service.reject_application(
            application_id=application_id,
            rejected_by=req.rejected_by,
            reason=req.reason,
            ip_address=ip_address,
        )
        return build_application_response(application)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/applications/{application_id}/request-revision", response_model=ApplicationResponse)
async def request_revision(
    application_id: UUID,
    req: RejectApplicationRequest,  # Reuse RejectApplicationRequest for now (has reason field)
    request: Request,
) -> ApplicationResponse:
    """
    Request revisions to an application.
    
    Sets application to NEEDS_REVISION status and stores notes for the applicant.
    Applicant can then edit and resubmit the application.
    
    Args:
        application_id: UUID of the application
        req: Revision request with notes
        
    Returns:
        Updated application in NEEDS_REVISION status
        
    Raises:
        400: Invalid state transition
    """
    service = get_approval_service()
    ip_address, _ = get_client_info(request)

    try:
        application = await service.request_revision(
            application_id=application_id,
            requested_by=req.rejected_by,  # Field name is misleading but works
            notes=req.reason,
            ip_address=ip_address,
        )
        
        # Emit SSE event
        user_id = application.applicant.user_id if application.applicant else str(application.applicant_id)
        await _emit_sse_event(
            event_type="application.revision_requested",
            user_id=user_id,
            organization_id=str(application.organization_id) if application.organization_id else None,
            data={
                "application_id": str(application.id),
                "application_number": application.application_number,
                "notes": req.reason,
            },
            title="Application Revision Requested",
            body=f"Application {application.application_number} requires revisions",
        )
        
        return build_application_response(application)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/applications/{application_id}/mark-issued", response_model=ApplicationResponse)
async def mark_application_issued(
    application_id: UUID,
    document_id: str = Query(..., description="ID of the issued document"),
    request: Request = None,
) -> ApplicationResponse:
    """
    Mark an application as issued after document creation.
    
    Called by document service after successful issuance.
    
    Args:
        application_id: UUID of the application
        document_id: ID of the issued document
        
    Returns:
        Updated application in ISSUED status
        
    Raises:
        400: Application not approved
    """
    service = get_approval_service()
    actor_id = get_actor_id(request) if request else "system"

    try:
        application = await service.mark_issued(
            application_id=application_id,
            document_id=document_id,
            issued_by=actor_id,
        )
        return build_application_response(application)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ==================== Document Type Configuration ====================

@router.get("/document-types", response_model=list[dict[str, Any]])
async def get_document_types() -> list[dict[str, Any]]:
    """
    Get supported document types with their vetting requirements.
    
    Returns:
        List of document types and their configurations
    """
    from .service import DEFAULT_VETTING_REQUIREMENTS
    
    return [
        {
            "document_type": doc_type,
            "requirements": [
                {
                    "check_type": req["type"].value,
                    "required": req["required"],
                    "order": req["order"],
                }
                for req in requirements
            ],
        }
        for doc_type, requirements in DEFAULT_VETTING_REQUIREMENTS.items()
    ]


# ==================== Applicant Lookup Endpoints ====================

@router.get("/{applicant_id}", response_model=ApplicantResponse)
async def get_applicant(applicant_id: UUID) -> ApplicantResponse:
    """
    Get an applicant by ID.
    
    Args:
        applicant_id: UUID of the applicant
        
    Returns:
        Applicant record
        
    Raises:
        404: Applicant not found
    """
    service = get_applicant_service()
    applicant = await service.get_applicant(applicant_id)
    
    if not applicant:
        raise HTTPException(status_code=404, detail=f"Applicant {applicant_id} not found")
    
    return build_applicant_response(applicant)


@router.get("/by-user/{user_id}", response_model=ApplicantResponse)
async def get_applicant_by_user(user_id: str) -> ApplicantResponse:
    """
    Get an applicant by user account ID.
    
    Args:
        user_id: User account ID
        
    Returns:
        Applicant record
        
    Raises:
        404: Applicant not found
    """
    service = get_applicant_service()
    applicant = await service.get_applicant_by_user(user_id)
    
    if not applicant:
        raise HTTPException(status_code=404, detail=f"No applicant found for user {user_id}")
    
    return build_applicant_response(applicant)


@router.patch("/{applicant_id}", response_model=ApplicantResponse)
async def update_applicant(
    applicant_id: UUID,
    req: UpdateApplicantRequest,
    request: Request,
) -> ApplicantResponse:
    """
    Update an applicant's profile.
    
    Args:
        applicant_id: UUID of the applicant
        req: Update request
        
    Returns:
        Updated applicant record
        
    Raises:
        404: Applicant not found
    """
    service = get_applicant_service()
    actor_id = get_actor_id(request)

    updates: dict[str, Any] = {}
    if req.given_name:
        updates["given_names"] = req.given_name
    if req.family_name:
        updates["surname"] = req.family_name
    if req.phone_number:
        updates["phone"] = req.phone_number
    if req.address:
        address = req.address.model_dump()
        updates.update(
            {
                "address_line1": address.get("street_line1"),
                "address_line2": address.get("street_line2"),
                "city": address.get("city"),
                "state_province": address.get("state_province"),
                "postal_code": address.get("postal_code"),
                "country": address.get("country"),
            }
        )

    applicant = await service.update_applicant(applicant_id, updates, actor_id)
    
    if not applicant:
        raise HTTPException(status_code=404, detail=f"Applicant {applicant_id} not found")
    
    return build_applicant_response(applicant)
