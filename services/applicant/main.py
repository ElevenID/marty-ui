"""
Applicant Service

Manages applicants and their vetting/verification status.

Ports:
- HTTP API on port 8006
"""

from __future__ import annotations

import logging
import os
import json
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, AsyncGenerator

import httpx
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

try:
    from common.events import EventPublisher, DomainEvent, EventType, get_event_publisher
except ImportError:
    # Fallback if common module not available
    EventPublisher = None
    DomainEvent = None
    EventType = None
    get_event_publisher = lambda: None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "applicant-service"
SERVICE_PORT = int(os.environ.get("APPLICANT_SERVICE_PORT", "8006"))
ISSUANCE_SERVICE_URL = os.environ.get("ISSUANCE_SERVICE_URL", "http://gateway:8000")


def _generate_reference_number() -> str:
    """Generate a stable human-readable application reference number."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    suffix = uuid.uuid4().hex[:6].upper()
    return f"APP-{stamp}-{suffix}"


# =============================================================================
# Domain Layer
# =============================================================================

class ApplicantStatus(str, Enum):
    """Applicant vetting status."""
    PENDING = "pending"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED = "revoked"


class VettingLevel(str, Enum):
    """Vetting assurance level."""
    BASIC = "basic"
    STANDARD = "standard"
    ENHANCED = "enhanced"


class ApplicationStatus(str, Enum):
    """Credential application lifecycle status."""
    DRAFT = "draft"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    NEEDS_INFO = "needs_info"
    APPROVED = "approved"
    ISSUED = "issued"
    REJECTED = "rejected"


class VettingCheckStatus(str, Enum):
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


class VettingCheckType(str, Enum):
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
    CUSTOM = "custom"


@dataclass
class Applicant:
    """
    Applicant aggregate.
    
    Represents a person requesting credentials.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    
    # Identity
    email: str = ""
    given_name: str | None = None
    family_name: str | None = None
    phone: str | None = None
    
    # External identity
    oidc_subject: str | None = None
    
    # Vetting status
    status: ApplicantStatus = ApplicantStatus.PENDING
    vetting_level: VettingLevel = VettingLevel.BASIC
    
    # Vetting data
    vetting_data: dict[str, Any] = field(default_factory=dict)
    verification_results: list[dict[str, Any]] = field(default_factory=list)
    
    # Notes and decisions
    reviewer_notes: str | None = None
    rejection_reason: str | None = None
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reviewed_at: datetime | None = None
    last_login: datetime | None = None
    
    @property
    def display_name(self) -> str:
        if self.given_name and self.family_name:
            return f"{self.given_name} {self.family_name}"
        return self.email.split("@")[0]
    
    def start_review(self) -> None:
        self.status = ApplicantStatus.IN_REVIEW
        self.updated_at = datetime.now(timezone.utc)
    
    def approve(self, reviewer_notes: str | None = None) -> None:
        self.status = ApplicantStatus.APPROVED
        self.reviewer_notes = reviewer_notes
        self.reviewed_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
    
    def reject(self, reason: str) -> None:
        self.status = ApplicantStatus.REJECTED
        self.rejection_reason = reason
        self.reviewed_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
    
    def revoke(self, reason: str) -> None:
        self.status = ApplicantStatus.REVOKED
        self.rejection_reason = reason
        self.updated_at = datetime.now(timezone.utc)


@dataclass
class ApplicantApplication:
    """Credential application submitted by an applicant."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    applicant_id: str = ""
    organization_id: str = ""
    reference_number: str | None = None
    credential_configuration_id: str = ""
    issuing_authority: str | None = None
    requested_validity_years: int | None = None
    status: ApplicationStatus = ApplicationStatus.DRAFT
    metadata: dict[str, Any] = field(default_factory=dict)
    # Snapshot of vetting checks required for this application (from template at creation time).
    # Each entry: { check_type, custom_name, is_required, order, config, external_provider, webhook_url }
    required_checks: list[dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    submitted_at: datetime | None = None
    reviewed_at: datetime | None = None
    issued_at: datetime | None = None
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ApplicantBiometric:
    """Biometric enrollment record for an applicant."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    applicant_id: str = ""
    biometric_type: str = "FACIAL"
    template_data_base64: str = ""
    image_data_base64: str | None = None
    is_live_capture: bool = True
    capture_device_id: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class VettingCheck:
    """A single vetting/verification check for an application."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    application_id: str = ""
    check_type: VettingCheckType = VettingCheckType.IDENTITY_VERIFICATION
    custom_name: str | None = None
    is_required: bool = True
    order: int = 0
    status: VettingCheckStatus = VettingCheckStatus.NOT_STARTED
    config: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)
    notes: str | None = None
    performed_by: str | None = None
    external_provider: str | None = None
    webhook_url: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    completed_at: datetime | None = None


@dataclass
class ReviewerLock:
    """Soft lock placed when a reviewer opens an application."""
    application_id: str = ""
    reviewer_id: str = ""
    reviewer_name: str = ""
    lock_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    acquired_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# Application Layer
# =============================================================================

class InMemoryApplicantRepository:
    """File-backed repository that persists data across container restarts."""
    
    def __init__(self):
        self._applicants: dict[str, Applicant] = {}
        self._applications: dict[str, ApplicantApplication] = {}
        self._biometrics: dict[str, list[ApplicantBiometric]] = {}
        self._checks: dict[str, list[VettingCheck]] = {}   # keyed by application_id
        self._all_checks: dict[str, VettingCheck] = {}     # keyed by check_id
        self._locks: dict[str, ReviewerLock] = {}           # keyed by application_id
        data_file = os.environ.get("APPLICANT_DATA_FILE", "/app/data/applicant_store.json")
        self._data_file = Path(data_file)
        self._data_file.parent.mkdir(parents=True, exist_ok=True)
        self._load()

    def _dt_to_str(self, value: datetime | None) -> str | None:
        return value.isoformat() if value else None

    def _str_to_dt(self, value: str | None) -> datetime | None:
        if not value:
            return None
        return datetime.fromisoformat(value)

    def _serialize_applicant(self, applicant: Applicant) -> dict[str, Any]:
        return {
            "id": applicant.id,
            "organization_id": applicant.organization_id,
            "email": applicant.email,
            "given_name": applicant.given_name,
            "family_name": applicant.family_name,
            "phone": applicant.phone,
            "oidc_subject": applicant.oidc_subject,
            "status": applicant.status.value,
            "vetting_level": applicant.vetting_level.value,
            "vetting_data": applicant.vetting_data,
            "verification_results": applicant.verification_results,
            "reviewer_notes": applicant.reviewer_notes,
            "rejection_reason": applicant.rejection_reason,
            "created_at": self._dt_to_str(applicant.created_at),
            "updated_at": self._dt_to_str(applicant.updated_at),
            "reviewed_at": self._dt_to_str(applicant.reviewed_at),
            "last_login": self._dt_to_str(applicant.last_login),
        }

    def _deserialize_applicant(self, payload: dict[str, Any]) -> Applicant:
        return Applicant(
            id=payload.get("id", str(uuid.uuid4())),
            organization_id=payload.get("organization_id", ""),
            email=payload.get("email", ""),
            given_name=payload.get("given_name"),
            family_name=payload.get("family_name"),
            phone=payload.get("phone"),
            oidc_subject=payload.get("oidc_subject"),
            status=ApplicantStatus(payload.get("status", ApplicantStatus.PENDING.value)),
            vetting_level=VettingLevel(payload.get("vetting_level", VettingLevel.BASIC.value)),
            vetting_data=payload.get("vetting_data", {}),
            verification_results=payload.get("verification_results", []),
            reviewer_notes=payload.get("reviewer_notes"),
            rejection_reason=payload.get("rejection_reason"),
            created_at=self._str_to_dt(payload.get("created_at")) or datetime.now(timezone.utc),
            updated_at=self._str_to_dt(payload.get("updated_at")) or datetime.now(timezone.utc),
            reviewed_at=self._str_to_dt(payload.get("reviewed_at")),
            last_login=self._str_to_dt(payload.get("last_login")),
        )

    def _serialize_application(self, application: ApplicantApplication) -> dict[str, Any]:
        return {
            "id": application.id,
            "applicant_id": application.applicant_id,
            "organization_id": application.organization_id,
            "reference_number": application.reference_number,
            "credential_configuration_id": application.credential_configuration_id,
            "issuing_authority": application.issuing_authority,
            "requested_validity_years": application.requested_validity_years,
            "status": application.status.value,
            "metadata": application.metadata,
            "required_checks": application.required_checks,
            "created_at": self._dt_to_str(application.created_at),
            "submitted_at": self._dt_to_str(application.submitted_at),
            "reviewed_at": self._dt_to_str(application.reviewed_at),
            "issued_at": self._dt_to_str(application.issued_at),
            "updated_at": self._dt_to_str(application.updated_at),
        }

    def _deserialize_application(self, payload: dict[str, Any]) -> ApplicantApplication:
        return ApplicantApplication(
            id=payload.get("id", str(uuid.uuid4())),
            applicant_id=payload.get("applicant_id", ""),
            organization_id=payload.get("organization_id", ""),
            reference_number=payload.get("reference_number"),
            credential_configuration_id=payload.get("credential_configuration_id", ""),
            issuing_authority=payload.get("issuing_authority"),
            requested_validity_years=payload.get("requested_validity_years"),
            status=ApplicationStatus(payload.get("status", ApplicationStatus.DRAFT.value)),
            metadata=payload.get("metadata", {}),
            required_checks=payload.get("required_checks", []),
            created_at=self._str_to_dt(payload.get("created_at")) or datetime.now(timezone.utc),
            submitted_at=self._str_to_dt(payload.get("submitted_at")),
            reviewed_at=self._str_to_dt(payload.get("reviewed_at")),
            issued_at=self._str_to_dt(payload.get("issued_at")),
            updated_at=self._str_to_dt(payload.get("updated_at")) or datetime.now(timezone.utc),
        )

    def _serialize_biometric(self, biometric: ApplicantBiometric) -> dict[str, Any]:
        return {
            "id": biometric.id,
            "applicant_id": biometric.applicant_id,
            "biometric_type": biometric.biometric_type,
            "template_data_base64": biometric.template_data_base64,
            "image_data_base64": biometric.image_data_base64,
            "is_live_capture": biometric.is_live_capture,
            "capture_device_id": biometric.capture_device_id,
            "created_at": self._dt_to_str(biometric.created_at),
        }

    def _deserialize_biometric(self, payload: dict[str, Any]) -> ApplicantBiometric:
        return ApplicantBiometric(
            id=payload.get("id", str(uuid.uuid4())),
            applicant_id=payload.get("applicant_id", ""),
            biometric_type=payload.get("biometric_type", "FACIAL"),
            template_data_base64=payload.get("template_data_base64", ""),
            image_data_base64=payload.get("image_data_base64"),
            is_live_capture=payload.get("is_live_capture", True),
            capture_device_id=payload.get("capture_device_id"),
            created_at=self._str_to_dt(payload.get("created_at")) or datetime.now(timezone.utc),
        )

    def _serialize_check(self, check: VettingCheck) -> dict[str, Any]:
        return {
            "id": check.id,
            "application_id": check.application_id,
            "check_type": check.check_type.value,
            "custom_name": check.custom_name,
            "is_required": check.is_required,
            "order": check.order,
            "status": check.status.value,
            "config": check.config,
            "result": check.result,
            "notes": check.notes,
            "performed_by": check.performed_by,
            "external_provider": check.external_provider,
            "webhook_url": check.webhook_url,
            "created_at": self._dt_to_str(check.created_at),
            "updated_at": self._dt_to_str(check.updated_at),
            "started_at": self._dt_to_str(check.started_at),
            "completed_at": self._dt_to_str(check.completed_at),
        }

    def _deserialize_check(self, payload: dict[str, Any]) -> VettingCheck:
        return VettingCheck(
            id=payload.get("id", str(uuid.uuid4())),
            application_id=payload.get("application_id", ""),
            check_type=VettingCheckType(payload.get("check_type", VettingCheckType.IDENTITY_VERIFICATION.value)),
            custom_name=payload.get("custom_name"),
            is_required=payload.get("is_required", True),
            order=payload.get("order", 0),
            status=VettingCheckStatus(payload.get("status", VettingCheckStatus.NOT_STARTED.value)),
            config=payload.get("config", {}),
            result=payload.get("result", {}),
            notes=payload.get("notes"),
            performed_by=payload.get("performed_by"),
            external_provider=payload.get("external_provider"),
            webhook_url=payload.get("webhook_url"),
            created_at=self._str_to_dt(payload.get("created_at")) or datetime.now(timezone.utc),
            updated_at=self._str_to_dt(payload.get("updated_at")) or datetime.now(timezone.utc),
            started_at=self._str_to_dt(payload.get("started_at")),
            completed_at=self._str_to_dt(payload.get("completed_at")),
        )

    def _load(self) -> None:
        if not self._data_file.exists():
            return
        try:
            payload = json.loads(self._data_file.read_text(encoding="utf-8"))
            self._applicants = {
                row["id"]: self._deserialize_applicant(row)
                for row in payload.get("applicants", [])
            }
            self._applications = {
                row["id"]: self._deserialize_application(row)
                for row in payload.get("applications", [])
            }
            biometrics_rows = payload.get("biometrics", {})
            self._biometrics = {
                applicant_id: [self._deserialize_biometric(row) for row in rows]
                for applicant_id, rows in biometrics_rows.items()
            }
            checks_rows = payload.get("checks", [])
            for row in checks_rows:
                check = self._deserialize_check(row)
                self._all_checks[check.id] = check
                self._checks.setdefault(check.application_id, []).append(check)
            logger.info("Loaded applicant repository state from %s", self._data_file)
        except Exception as exc:
            logger.error("Failed loading applicant persistence file %s: %s", self._data_file, exc)

    def _flush(self) -> None:
        payload = {
            "applicants": [self._serialize_applicant(a) for a in self._applicants.values()],
            "applications": [self._serialize_application(a) for a in self._applications.values()],
            "biometrics": {
                applicant_id: [self._serialize_biometric(b) for b in rows]
                for applicant_id, rows in self._biometrics.items()
            },
            "checks": [self._serialize_check(c) for c in self._all_checks.values()],
        }
        temp_file = self._data_file.with_suffix(".tmp")
        temp_file.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
        temp_file.replace(self._data_file)
    
    async def save(self, applicant: Applicant) -> None:
        self._applicants[applicant.id] = applicant
        self._flush()
    
    async def get_by_id(self, applicant_id: str) -> Applicant | None:
        return self._applicants.get(applicant_id)
    
    async def get_by_email(self, email: str, org_id: str) -> Applicant | None:
        for a in self._applicants.values():
            if a.email == email and a.organization_id == org_id:
                return a
        return None

    async def get_by_user_id(self, user_id: str) -> Applicant | None:
        for a in self._applicants.values():
            if a.oidc_subject == user_id:
                return a
        return None
    
    async def list_by_organization(
        self,
        org_id: str,
        status: ApplicantStatus | None = None,
    ) -> list[Applicant]:
        applicants = [a for a in self._applicants.values() if a.organization_id == org_id]
        if status:
            applicants = [a for a in applicants if a.status == status]
        return applicants
    
    async def delete(self, applicant_id: str) -> None:
        self._applicants.pop(applicant_id, None)
        self._flush()

    async def save_application(self, application: ApplicantApplication) -> None:
        self._applications[application.id] = application
        self._flush()

    async def get_application(self, application_id: str) -> ApplicantApplication | None:
        return self._applications.get(application_id)

    async def list_applications_for_applicant(self, applicant_id: str) -> list[ApplicantApplication]:
        return [a for a in self._applications.values() if a.applicant_id == applicant_id]

    async def list_applications_for_organization(
        self,
        organization_id: str,
        status: ApplicationStatus | None = None,
    ) -> list[ApplicantApplication]:
        applications = [a for a in self._applications.values() if a.organization_id == organization_id]
        if status:
            applications = [a for a in applications if a.status == status]
        return applications

    async def save_biometric(self, biometric: ApplicantBiometric) -> None:
        self._biometrics.setdefault(biometric.applicant_id, []).append(biometric)
        self._flush()

    async def list_biometrics(self, applicant_id: str) -> list[ApplicantBiometric]:
        return self._biometrics.get(applicant_id, [])

    # --- Vetting Checks ---

    async def save_check(self, check: VettingCheck) -> None:
        self._all_checks[check.id] = check
        app_checks = self._checks.setdefault(check.application_id, [])
        existing_ids = {c.id for c in app_checks}
        if check.id not in existing_ids:
            app_checks.append(check)
        else:
            for i, c in enumerate(app_checks):
                if c.id == check.id:
                    app_checks[i] = check
                    break
        self._flush()

    async def list_checks_for_application(self, application_id: str) -> list[VettingCheck]:
        return sorted(self._checks.get(application_id, []), key=lambda c: c.order)

    async def get_check(self, check_id: str) -> VettingCheck | None:
        return self._all_checks.get(check_id)

    async def list_pending_checks(self, check_type: str | None = None) -> list[VettingCheck]:
        pending_statuses = {
            VettingCheckStatus.NOT_STARTED,
            VettingCheckStatus.PENDING,
            VettingCheckStatus.IN_PROGRESS,
            VettingCheckStatus.REQUIRES_MANUAL_REVIEW,
        }
        checks = [c for c in self._all_checks.values() if c.status in pending_statuses]
        if check_type:
            checks = [c for c in checks if c.check_type.value == check_type]
        return checks

    # --- Reviewer Locks ---

    LOCK_TTL_SECONDS = 300  # 5 minutes

    def _lock_expired(self, lock: ReviewerLock) -> bool:
        return datetime.now(timezone.utc) > lock.expires_at

    async def acquire_lock(self, application_id: str, reviewer_id: str, reviewer_name: str) -> tuple[bool, ReviewerLock | None]:
        """Returns (acquired, existing_lock_if_blocked)."""
        existing = self._locks.get(application_id)
        if existing and not self._lock_expired(existing):
            if existing.reviewer_id == reviewer_id:
                # Refresh own lock
                existing.expires_at = datetime.now(timezone.utc) + timedelta(seconds=self.LOCK_TTL_SECONDS)
                return True, existing
            return False, existing
        lock = ReviewerLock(
            application_id=application_id,
            reviewer_id=reviewer_id,
            reviewer_name=reviewer_name,
            acquired_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.LOCK_TTL_SECONDS),
        )
        self._locks[application_id] = lock
        return True, lock

    async def release_lock(self, application_id: str, reviewer_id: str) -> bool:
        existing = self._locks.get(application_id)
        if existing and (existing.reviewer_id == reviewer_id or self._lock_expired(existing)):
            self._locks.pop(application_id, None)
            return True
        return False

    async def get_lock(self, application_id: str) -> ReviewerLock | None:
        lock = self._locks.get(application_id)
        if lock and self._lock_expired(lock):
            self._locks.pop(application_id, None)
            return None
        return lock


# =============================================================================
# HTTP Adapter
# =============================================================================

router = APIRouter(prefix="/v1/applicants", tags=["applicants"])

_repo: InMemoryApplicantRepository | None = None


def get_repo() -> InMemoryApplicantRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


class CreateApplicantRequest(BaseModel):
    organization_id: str
    user_id: str | None = None
    email: EmailStr
    given_name: str | None = None
    family_name: str | None = None
    phone: str | None = None
    vetting_level: str = "basic"


class UpdateApplicantRequest(BaseModel):
    given_name: str | None = None
    family_name: str | None = None
    phone: str | None = None
    vetting_data: dict[str, Any] | None = None


class ReviewRequest(BaseModel):
    decision: str  # "approve" or "reject"
    notes: str | None = None
    reason: str | None = None


class ApplicantResponse(BaseModel):
    id: str
    organization_id: str
    email: str
    given_name: str | None
    family_name: str | None
    phone: str | None
    status: str
    vetting_level: str
    created_at: str
    reviewed_at: str | None


class CreateApplicationRequest(BaseModel):
    applicant_id: str
    credential_configuration_id: str
    issuing_authority: str | None = None
    requested_validity_years: int | None = None
    metadata: dict[str, Any] = {}
    # Required checks snapshot from the application template (if known at creation time).
    # Each entry: { check_type, custom_name, is_required, order, config, external_provider, webhook_url }
    required_checks: list[dict[str, Any]] = []


class ApplicationResponse(BaseModel):
    id: str
    applicant_id: str
    organization_id: str | None = None
    reference_number: str | None = None
    credential_configuration_id: str
    status: str
    created_at: str
    submitted_at: str | None = None
    reviewed_at: str | None = None
    issued_at: str | None = None
    updated_at: str
    credential_display_name: str | None = None


class EnrollBiometricRequest(BaseModel):
    biometric_type: str = "FACIAL"
    template_data_base64: str
    image_data_base64: str | None = None
    is_live_capture: bool = True
    capture_device_id: str | None = None


class ApplicationReviewRequest(BaseModel):
    decision: str  # "approve" or "reject"
    notes: str | None = None
    reason: str | None = None


class BiometricResponse(BaseModel):
    id: str
    applicant_id: str
    biometric_type: str
    is_live_capture: bool
    capture_device_id: str | None = None
    created_at: str


class VettingCheckResponse(BaseModel):
    id: str
    application_id: str
    check_type: str
    custom_name: str | None = None
    is_required: bool
    order: int
    status: str
    config: dict[str, Any] = {}
    result: dict[str, Any] = {}
    notes: str | None = None
    performed_by: str | None = None
    external_provider: str | None = None
    webhook_url: str | None = None
    created_at: str
    updated_at: str
    started_at: str | None = None
    completed_at: str | None = None


class CompleteCheckRequest(BaseModel):
    passed: bool
    notes: str | None = None
    performed_by: str | None = None
    result: dict[str, Any] = {}


class RequestInfoRequest(BaseModel):
    missing_items: list[str] = []
    message: str = ""
    deadline: str | None = None


class AcquireLockRequest(BaseModel):
    reviewer_id: str
    reviewer_name: str


class LockResponse(BaseModel):
    locked: bool
    lock_id: str | None = None
    reviewer_id: str | None = None
    reviewer_name: str | None = None
    acquired_at: str | None = None
    expires_at: str | None = None


class EnrichedApplicationResponse(BaseModel):
    id: str
    applicant_id: str
    organization_id: str | None = None
    reference_number: str | None = None
    credential_configuration_id: str
    status: str
    created_at: str
    submitted_at: str | None = None
    reviewed_at: str | None = None
    issued_at: str | None = None
    updated_at: str
    credential_display_name: str | None = None
    metadata: dict[str, Any] = {}
    # Enriched applicant info
    applicant_email: str | None = None
    applicant_given_name: str | None = None
    applicant_family_name: str | None = None
    applicant_phone: str | None = None
    applicant_status: str | None = None
    applicant_vetting_level: str | None = None
    verification_results: list[dict[str, Any]] = []


@router.post("", response_model=ApplicantResponse)
async def create_applicant(
    request: CreateApplicantRequest,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicantResponse:
    """Create a new applicant."""
    # Check for existing
    existing = await repo.get_by_email(request.email, request.organization_id)
    if existing:
        raise HTTPException(status_code=409, detail="Applicant already exists")
    
    applicant = Applicant(
        organization_id=request.organization_id,
        email=request.email,
        given_name=request.given_name,
        family_name=request.family_name,
        phone=request.phone,
        oidc_subject=request.user_id,
        vetting_level=VettingLevel(request.vetting_level),
    )
    await repo.save(applicant)
    return _to_response(applicant)


@router.get("/by-user/{user_id}", response_model=ApplicantResponse)
async def get_applicant_by_user(
    user_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicantResponse:
    """Get an applicant profile by authenticated user id."""
    applicant = await repo.get_by_user_id(user_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")
    return _to_response(applicant)


@router.get("", response_model=list[ApplicantResponse])
async def list_applicants(
    organization_id: str = Query(...),
    status: str | None = None,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> list[ApplicantResponse]:
    """List applicants for an organization."""
    status_filter = ApplicantStatus(status) if status else None
    applicants = await repo.list_by_organization(organization_id, status_filter)
    return [_to_response(a) for a in applicants]


@router.get("/profiles/{applicant_id}", response_model=ApplicantResponse)
async def get_applicant(
    applicant_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicantResponse:
    """Get an applicant by ID."""
    applicant = await repo.get_by_id(applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")
    return _to_response(applicant)


@router.post("/profiles/{applicant_id}/biometrics", response_model=BiometricResponse)
async def enroll_biometric(
    applicant_id: str,
    request: EnrollBiometricRequest,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> BiometricResponse:
    """Enroll a biometric for an applicant."""
    applicant = await repo.get_by_id(applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")

    biometric = ApplicantBiometric(
        applicant_id=applicant_id,
        biometric_type=request.biometric_type,
        template_data_base64=request.template_data_base64,
        image_data_base64=request.image_data_base64,
        is_live_capture=request.is_live_capture,
        capture_device_id=request.capture_device_id,
    )
    await repo.save_biometric(biometric)
    return _biometric_to_response(biometric)


@router.get("/profiles/{applicant_id}/biometrics", response_model=list[BiometricResponse])
async def list_biometrics(
    applicant_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> list[BiometricResponse]:
    """List biometrics for an applicant."""
    applicant = await repo.get_by_id(applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")
    biometrics = await repo.list_biometrics(applicant_id)
    return [_biometric_to_response(b) for b in biometrics]


@router.post("/applications", response_model=ApplicationResponse)
async def create_application(
    request: CreateApplicationRequest,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    """Create an application for a credential configuration."""
    applicant = await repo.get_by_id(request.applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")

    application = ApplicantApplication(
        applicant_id=request.applicant_id,
        organization_id=applicant.organization_id,
        reference_number=_generate_reference_number(),
        credential_configuration_id=request.credential_configuration_id,
        issuing_authority=request.issuing_authority,
        requested_validity_years=request.requested_validity_years,
        metadata=request.metadata or {},
        required_checks=request.required_checks or [],
    )
    await repo.save_application(application)
    return _application_to_response(application)


@router.get("/profiles/{applicant_id}/applications", response_model=list[ApplicationResponse])
async def list_applications_for_applicant(
    applicant_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> list[ApplicationResponse]:
    """List applications for an applicant profile."""
    applications = await repo.list_applications_for_applicant(applicant_id)
    applications.sort(key=lambda a: a.created_at, reverse=True)
    return [_application_to_response(a) for a in applications]


@router.get("/org-applications", response_model=list[ApplicationResponse])
async def list_applications_for_organization(
    organization_id: str = Query(...),
    status: str | None = Query(None),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> list[ApplicationResponse]:
    """List applications for an organization (used by org console)."""
    status_filter = ApplicationStatus(status) if status else None
    applications = await repo.list_applications_for_organization(organization_id, status_filter)
    applications.sort(key=lambda a: a.created_at, reverse=True)
    return [_application_to_response(a) for a in applications]


@router.post("/applications/{application_id}/submit", response_model=ApplicationResponse)
async def submit_application(
    application_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    """Submit an existing application into review."""
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")

    if application.status == ApplicationStatus.SUBMITTED:
        if not application.reference_number:
            application.reference_number = _generate_reference_number()
            application.updated_at = datetime.now(timezone.utc)
            await repo.save_application(application)
        return _application_to_response(application)

    submittable = {ApplicationStatus.DRAFT, ApplicationStatus.NEEDS_INFO}
    if application.status not in submittable:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot submit application in {application.status.value} status",
        )

    is_first_submission = application.status == ApplicationStatus.DRAFT

    application.status = ApplicationStatus.SUBMITTED
    if not application.reference_number:
        application.reference_number = _generate_reference_number()
    application.submitted_at = datetime.now(timezone.utc)
    application.updated_at = datetime.now(timezone.utc)
    await repo.save_application(application)

    # Create vetting checks on first submission.
    # Uses required_checks from the application (snapshotted from the template at creation),
    # falling back to a minimal identity verification check when none are defined.
    if is_first_submission:
        existing_checks = await repo.list_checks_for_application(application_id)
        if not existing_checks:
            check_specs = application.required_checks or [
                {"check_type": VettingCheckType.IDENTITY_VERIFICATION.value, "is_required": True, "order": 1}
            ]
            now = datetime.now(timezone.utc)
            for spec in check_specs:
                check_type_val = spec.get("check_type", VettingCheckType.IDENTITY_VERIFICATION.value)
                try:
                    check_type = VettingCheckType(check_type_val)
                except ValueError:
                    check_type = VettingCheckType.CUSTOM
                check = VettingCheck(
                    application_id=application_id,
                    check_type=check_type,
                    custom_name=spec.get("custom_name"),
                    is_required=spec.get("is_required", True),
                    order=spec.get("order", 0),
                    config=spec.get("config", {}),
                    external_provider=spec.get("external_provider"),
                    webhook_url=spec.get("webhook_url"),
                    created_at=now,
                    updated_at=now,
                )
                await repo.save_check(check)

    return _application_to_response(application)


@router.post("/applications/{application_id}/review", response_model=ApplicationResponse)
async def review_application(
    application_id: str,
    request: ApplicationReviewRequest,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    """Approve or reject an application in org console."""
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")

    if application.status not in {ApplicationStatus.SUBMITTED, ApplicationStatus.UNDER_REVIEW, ApplicationStatus.NEEDS_INFO}:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot review application in {application.status.value} status",
        )
    decision = request.decision.lower().strip()
    if decision == "approve":
        application.status = ApplicationStatus.APPROVED
        application.reviewed_at = datetime.now(timezone.utc)
        if request.notes:
            application.metadata["review_notes"] = request.notes
    elif decision == "reject":
        if not request.reason:
            raise HTTPException(status_code=400, detail="Rejection reason required")
        application.status = ApplicationStatus.REJECTED
        application.reviewed_at = datetime.now(timezone.utc)
        application.metadata["rejection_reason"] = request.reason
        if request.notes:
            application.metadata["review_notes"] = request.notes
    else:
        raise HTTPException(status_code=400, detail="Invalid decision")

    application.updated_at = datetime.now(timezone.utc)
    await repo.save_application(application)
    return _application_to_response(application)


@router.post("/applications/{application_id}/issue", response_model=ApplicationResponse)
async def issue_application(
    application_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    """Issue a credential for an approved application."""
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")

    if application.status == ApplicationStatus.ISSUED:
        return _application_to_response(application)

    if application.status != ApplicationStatus.APPROVED:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot issue application in {application.status.value} status",
        )

    applicant = await repo.get_by_id(application.applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")

    claims = {
        **application.metadata,
        "applicant_id": applicant.id,
        "email": applicant.email,
        "given_name": applicant.given_name,
        "family_name": applicant.family_name,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{ISSUANCE_SERVICE_URL}/v1/issuance/initiate",
                json={
                    "organization_id": application.organization_id,
                    "credential_template_id": application.credential_configuration_id,
                    "applicant_id": applicant.id,
                    "claims": claims,
                },
            )
            response.raise_for_status()
            issuance = response.json()
    except httpx.HTTPStatusError as e:
        logger.warning(
            "Issuance initiation failed for %s (status=%s). Falling back to local issuance marker.",
            application_id,
            e.response.status_code,
        )
        issuance = {
            "id": f"local-{uuid.uuid4().hex[:12]}",
            "credential_offer_uri": None,
            "fallback": True,
        }
    except Exception as e:
        logger.warning("Issuance service unavailable for %s. Using local fallback marker.", application_id)
        issuance = {
            "id": f"local-{uuid.uuid4().hex[:12]}",
            "credential_offer_uri": None,
            "fallback": True,
        }

    application.status = ApplicationStatus.ISSUED
    application.issued_at = datetime.now(timezone.utc)
    application.updated_at = datetime.now(timezone.utc)
    application.metadata["issuance_transaction_id"] = issuance.get("id")
    application.metadata["credential_offer_uri"] = issuance.get("credential_offer_uri")
    if issuance.get("fallback"):
        application.metadata["issuance_fallback"] = True
    await repo.save_application(application)
    return _application_to_response(application)


@router.patch("/applications/{application_id}", response_model=ApplicationResponse)
async def update_application(
    application_id: str,
    organization_id: str | None = Query(None),
    reference_number: str | None = Query(None),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    """Update application fields (administrative endpoint)."""
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")

    if organization_id:
        application.organization_id = organization_id
    if reference_number:
        application.reference_number = reference_number
    
    application.updated_at = datetime.now(timezone.utc)
    await repo.save_application(application)
    return _application_to_response(application)


@router.get("/applications/{application_id}", response_model=EnrichedApplicationResponse)
async def get_application(
    application_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> EnrichedApplicationResponse:
    """Get a single application with enriched applicant data."""
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    applicant = await repo.get_by_id(application.applicant_id)
    return _enriched_application_to_response(application, applicant)


# --- Vetting Checks Endpoints ---

@router.get("/applications/{application_id}/checks", response_model=list[VettingCheckResponse])
async def list_checks(
    application_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> list[VettingCheckResponse]:
    """List vetting checks for an application."""
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    checks = await repo.list_checks_for_application(application_id)
    return [_check_to_response(c) for c in checks]


@router.post("/checks/{check_id}/start", response_model=VettingCheckResponse)
async def start_check(
    check_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> VettingCheckResponse:
    """Mark a vetting check as in progress."""
    check = await repo.get_check(check_id)
    if not check:
        raise HTTPException(status_code=404, detail="Check not found")
    check.status = VettingCheckStatus.IN_PROGRESS
    check.started_at = datetime.now(timezone.utc)
    check.updated_at = datetime.now(timezone.utc)
    await repo.save_check(check)
    return _check_to_response(check)


@router.post("/checks/{check_id}/complete", response_model=VettingCheckResponse)
async def complete_check(
    check_id: str,
    request: CompleteCheckRequest,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> VettingCheckResponse:
    """Complete a vetting check with pass/fail outcome."""
    check = await repo.get_check(check_id)
    if not check:
        raise HTTPException(status_code=404, detail="Check not found")
    check.status = VettingCheckStatus.COMPLETED_PASSED if request.passed else VettingCheckStatus.COMPLETED_FAILED
    check.notes = request.notes
    check.performed_by = request.performed_by
    check.result = request.result
    check.completed_at = datetime.now(timezone.utc)
    check.updated_at = datetime.now(timezone.utc)
    await repo.save_check(check)
    return _check_to_response(check)


@router.get("/checks/pending", response_model=list[VettingCheckResponse])
async def get_pending_checks(
    check_type: str | None = Query(None),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> list[VettingCheckResponse]:
    """Get all pending vetting checks (optionally filtered by type)."""
    checks = await repo.list_pending_checks(check_type)
    return [_check_to_response(c) for c in checks]


# --- Request Info Endpoint ---

@router.post("/applications/{application_id}/request-info", response_model=ApplicationResponse)
async def request_info(
    application_id: str,
    request: RequestInfoRequest,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    """Request additional information from the applicant."""
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")

    reviewable_statuses = {
        ApplicationStatus.SUBMITTED,
        ApplicationStatus.UNDER_REVIEW,
        ApplicationStatus.NEEDS_INFO,
    }
    if application.status not in reviewable_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot request info for application in {application.status.value} status",
        )

    application.status = ApplicationStatus.NEEDS_INFO
    info_requests = application.metadata.get("info_requests", [])
    info_requests.append({
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "missing_items": request.missing_items,
        "message": request.message,
        "deadline": request.deadline,
    })
    application.metadata["info_requests"] = info_requests
    application.updated_at = datetime.now(timezone.utc)
    await repo.save_application(application)
    return _application_to_response(application)


# --- Reviewer Lock Endpoints ---

@router.post("/applications/{application_id}/lock", response_model=LockResponse)
async def acquire_lock(
    application_id: str,
    request: AcquireLockRequest,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> LockResponse:
    """Acquire a soft reviewer lock on an application."""
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    acquired, lock = await repo.acquire_lock(application_id, request.reviewer_id, request.reviewer_name)
    if not acquired and lock:
        return LockResponse(
            locked=False,
            lock_id=lock.lock_id,
            reviewer_id=lock.reviewer_id,
            reviewer_name=lock.reviewer_name,
            acquired_at=lock.acquired_at.isoformat(),
            expires_at=lock.expires_at.isoformat(),
        )
    return LockResponse(
        locked=True,
        lock_id=lock.lock_id if lock else None,
        reviewer_id=request.reviewer_id,
        reviewer_name=request.reviewer_name,
        acquired_at=lock.acquired_at.isoformat() if lock else None,
        expires_at=lock.expires_at.isoformat() if lock else None,
    )


@router.delete("/applications/{application_id}/lock")
async def release_lock(
    application_id: str,
    reviewer_id: str = Query(...),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> dict[str, bool]:
    """Release the reviewer lock on an application."""
    released = await repo.release_lock(application_id, reviewer_id)
    return {"released": released}


@router.get("/applications/{application_id}/lock", response_model=LockResponse)
async def get_lock_status(
    application_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> LockResponse:
    """Get the current lock status for an application."""
    lock = await repo.get_lock(application_id)
    if not lock:
        return LockResponse(locked=False)
    return LockResponse(
        locked=True,
        lock_id=lock.lock_id,
        reviewer_id=lock.reviewer_id,
        reviewer_name=lock.reviewer_name,
        acquired_at=lock.acquired_at.isoformat(),
        expires_at=lock.expires_at.isoformat(),
    )


@router.patch("/profiles/{applicant_id}", response_model=ApplicantResponse)
async def update_applicant(
    applicant_id: str,
    request: UpdateApplicantRequest,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicantResponse:
    """Update an applicant."""
    applicant = await repo.get_by_id(applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")
    
    if request.given_name is not None:
        applicant.given_name = request.given_name
    if request.family_name is not None:
        applicant.family_name = request.family_name
    if request.phone is not None:
        applicant.phone = request.phone
    if request.vetting_data is not None:
        applicant.vetting_data.update(request.vetting_data)
    
    applicant.updated_at = datetime.now(timezone.utc)
    await repo.save(applicant)
    return _to_response(applicant)


@router.post("/profiles/{applicant_id}/review", response_model=ApplicantResponse)
async def review_applicant(
    applicant_id: str,
    request: ReviewRequest,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicantResponse:
    """Review an applicant (approve/reject)."""
    applicant = await repo.get_by_id(applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")
    
    if request.decision == "approve":
        applicant.approve(request.notes)
        
        # Publish APPLICATION_APPROVED event
        if EventPublisher and get_event_publisher():
            try:
                event = DomainEvent(
                    event_type=EventType.APPLICATION_APPROVED,
                    aggregate_id=applicant.id,
                    aggregate_type="applicant",
                    organization_id=applicant.organization_id,
                    data={
                        "applicant_id": applicant.id,
                        "email": applicant.email,
                        "given_name": applicant.given_name,
                        "family_name": applicant.family_name,
                        "status": applicant.status.value,
                        "vetting_level": applicant.vetting_level.value,
                        "reviewer_notes": request.notes,
                    }
                )
                publisher = get_event_publisher()
                await publisher.publish(event)
                logger.info(f"Published APPLICATION_APPROVED event for applicant {applicant.id}")
            except Exception as e:
                logger.error(f"Failed to publish event: {e}")
                # Don't fail the approval if event publishing fails
        
    elif request.decision == "reject":
        if not request.reason:
            raise HTTPException(status_code=400, detail="Rejection reason required")
        applicant.reject(request.reason)
    else:
        raise HTTPException(status_code=400, detail="Invalid decision")
    
    await repo.save(applicant)
    return _to_response(applicant)


@router.post("/profiles/{applicant_id}/revoke")
async def revoke_applicant(
    applicant_id: str,
    reason: str = Query(...),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> dict[str, bool]:
    """Revoke an applicant's status."""
    applicant = await repo.get_by_id(applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")
    applicant.revoke(reason)
    await repo.save(applicant)
    return {"success": True}


def _to_response(applicant: Applicant) -> ApplicantResponse:
    return ApplicantResponse(
        id=applicant.id,
        organization_id=applicant.organization_id,
        email=applicant.email,
        given_name=applicant.given_name,
        family_name=applicant.family_name,
        phone=applicant.phone,
        status=applicant.status.value,
        vetting_level=applicant.vetting_level.value,
        created_at=applicant.created_at.isoformat(),
        reviewed_at=applicant.reviewed_at.isoformat() if applicant.reviewed_at else None,
    )


def _application_to_response(application: ApplicantApplication) -> ApplicationResponse:
    return ApplicationResponse(
        id=application.id,
        applicant_id=application.applicant_id,
        organization_id=application.organization_id or None,
        reference_number=application.reference_number,
        credential_configuration_id=application.credential_configuration_id,
        status=application.status.value,
        created_at=application.created_at.isoformat(),
        submitted_at=application.submitted_at.isoformat() if application.submitted_at else None,
        reviewed_at=application.reviewed_at.isoformat() if application.reviewed_at else None,
        issued_at=application.issued_at.isoformat() if application.issued_at else None,
        updated_at=application.updated_at.isoformat(),
        credential_display_name=application.metadata.get("credential_display_name"),
    )


def _biometric_to_response(biometric: ApplicantBiometric) -> BiometricResponse:
    return BiometricResponse(
        id=biometric.id,
        applicant_id=biometric.applicant_id,
        biometric_type=biometric.biometric_type,
        is_live_capture=biometric.is_live_capture,
        capture_device_id=biometric.capture_device_id,
        created_at=biometric.created_at.isoformat(),
    )


def _check_to_response(check: VettingCheck) -> VettingCheckResponse:
    return VettingCheckResponse(
        id=check.id,
        application_id=check.application_id,
        check_type=check.check_type.value,
        custom_name=check.custom_name,
        is_required=check.is_required,
        order=check.order,
        status=check.status.value,
        config=check.config,
        result=check.result,
        notes=check.notes,
        performed_by=check.performed_by,
        external_provider=check.external_provider,
        webhook_url=check.webhook_url,
        created_at=check.created_at.isoformat(),
        updated_at=check.updated_at.isoformat(),
        started_at=check.started_at.isoformat() if check.started_at else None,
        completed_at=check.completed_at.isoformat() if check.completed_at else None,
    )


def _enriched_application_to_response(
    application: ApplicantApplication,
    applicant: Applicant | None,
) -> EnrichedApplicationResponse:
    return EnrichedApplicationResponse(
        id=application.id,
        applicant_id=application.applicant_id,
        organization_id=application.organization_id or None,
        reference_number=application.reference_number,
        credential_configuration_id=application.credential_configuration_id,
        status=application.status.value,
        created_at=application.created_at.isoformat(),
        submitted_at=application.submitted_at.isoformat() if application.submitted_at else None,
        reviewed_at=application.reviewed_at.isoformat() if application.reviewed_at else None,
        issued_at=application.issued_at.isoformat() if application.issued_at else None,
        updated_at=application.updated_at.isoformat(),
        credential_display_name=application.metadata.get("credential_display_name"),
        metadata=application.metadata,
        applicant_email=applicant.email if applicant else None,
        applicant_given_name=applicant.given_name if applicant else None,
        applicant_family_name=applicant.family_name if applicant else None,
        applicant_phone=applicant.phone if applicant else None,
        applicant_status=applicant.status.value if applicant else None,
        applicant_vetting_level=applicant.vetting_level.value if applicant else None,
        verification_results=applicant.verification_results if applicant else [],
    )


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo
    logger.info(f"Starting {SERVICE_NAME}...")
    _repo = InMemoryApplicantRepository()
    yield
    logger.info(f"Shutting down {SERVICE_NAME}...")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Applicant Service",
        description="Applicant vetting and management service",
        version="1.0.0",
        lifespan=lifespan,
    )
    
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    app.include_router(router)
    
    @app.get("/health")
    async def health_check() -> dict:
        return {"status": "healthy", "service": SERVICE_NAME}
    
    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("applicant.main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
