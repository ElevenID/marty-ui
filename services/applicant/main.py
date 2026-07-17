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
import re
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, AsyncGenerator

import httpx
from fastapi import APIRouter, Body, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from marty_common.service_setup import create_service_app

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from common.events import EventPublisher, DomainEvent, EventType, get_event_publisher
except ImportError:
    logger.info("common.events not available; event publishing disabled")
    # Fallback if common module not available
    EventPublisher = None
    DomainEvent = None
    EventType = None
    get_event_publisher = lambda: None

SERVICE_NAME = "applicant-service"
SERVICE_PORT = int(os.environ.get("APPLICANT_SERVICE_PORT", "8006"))
# Internal issuance orchestration is delegated to flow-service.
ISSUANCE_SERVICE_URL = os.environ.get("ISSUANCE_SERVICE_URL", "http://issuance:8005")
FLOW_SERVICE_URL = os.environ.get("FLOW_SERVICE_URL", "http://flow:8011")


def _service_secret(name: str) -> str:
    value = os.environ.get(name, "")
    if value:
        return value
    path = os.environ.get(f"{name}_FILE", "")
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _identity_headers(
    x_user_id: str | None,
    x_user_email: str | None = None,
    x_organization_id: str | None = None,
    x_org_permissions: str | None = None,
) -> tuple[str, str, set[str]]:
    user_id = str(x_user_id or "").strip()
    if not user_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    organization_id = str(x_organization_id or "").strip()
    permissions = {
        value.strip()
        for value in str(x_org_permissions or "").split(",")
        if value.strip()
    }
    return user_id, organization_id, permissions


async def _load_application_template(template_id: str) -> dict[str, Any]:
    headers: dict[str, str] = {}
    api_key = _service_secret("ISSUANCE_API_KEY")
    if api_key:
        headers["X-API-Key"] = api_key
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.get(
            f"{ISSUANCE_SERVICE_URL}/v1/application-templates/{template_id}",
            headers=headers,
        )
    if response.status_code == 404:
        raise HTTPException(status_code=422, detail="Application Template not found")
    if response.status_code >= 400:
        raise HTTPException(status_code=503, detail="Application Template service unavailable")
    body = response.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=503, detail="Application Template response is malformed")
    return body


def _field_error(field: str, code: str, message: str) -> dict[str, str]:
    return {"field": field, "code": code, "message": message}


def _validate_form_data(form_data: dict[str, Any], fields: list[dict[str, Any]]) -> None:
    errors: list[dict[str, str]] = []
    allowed_fields: set[str] = set()
    for definition in fields:
        if not isinstance(definition, dict):
            continue
        name = str(definition.get("field_id") or "").strip()
        if not name:
            continue
        allowed_fields.add(name)
        value = form_data.get(name)
        if definition.get("required") and value in (None, "", []):
            errors.append(_field_error(name, "REQUIRED", "This field is required."))
            continue
        if value in (None, ""):
            continue

        field_type = str(definition.get("field_type") or "TEXT").strip().lower()
        if field_type == "date":
            try:
                if re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(value)) is None:
                    raise ValueError
                datetime.strptime(str(value), "%Y-%m-%d")
            except ValueError:
                errors.append(_field_error(name, "INVALID_DATE", "Use an ISO date in YYYY-MM-DD format."))
        elif field_type in {"datetime", "datetime-local"}:
            if _parse_iso_datetime(str(value)) is None:
                errors.append(_field_error(name, "INVALID_DATETIME", "Use a valid ISO 8601 date-time."))
        elif field_type in {"integer", "int"}:
            if isinstance(value, bool) or not isinstance(value, int):
                errors.append(_field_error(name, "INVALID_INTEGER", "Enter a whole number."))
        elif field_type in {"number", "float", "decimal"}:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                errors.append(_field_error(name, "INVALID_NUMBER", "Enter a number."))
        elif field_type in {"boolean", "bool"} and not isinstance(value, bool):
            errors.append(_field_error(name, "INVALID_BOOLEAN", "Choose true or false."))

        allowed = definition.get("options")
        if isinstance(allowed, list) and allowed:
            normalized_allowed = [
                item.get("value") if isinstance(item, dict) else item
                for item in allowed
            ]
            if value not in normalized_allowed:
                errors.append(_field_error(name, "INVALID_CHOICE", "Choose one of the allowed values."))
        pattern = definition.get("validation_pattern")
        if pattern and isinstance(value, str):
            try:
                if re.fullmatch(str(pattern), value) is None:
                    errors.append(_field_error(name, "PATTERN_MISMATCH", "Value does not match the required format."))
            except re.error:
                errors.append(_field_error(name, "INVALID_FIELD_CONFIGURATION", "Field validation pattern is invalid."))
        minimum = definition.get("minimum")
        maximum = definition.get("maximum")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if isinstance(minimum, (int, float)) and value < minimum:
                errors.append(_field_error(name, "BELOW_MINIMUM", f"Value must be at least {minimum}."))
            if isinstance(maximum, (int, float)) and value > maximum:
                errors.append(_field_error(name, "ABOVE_MAXIMUM", f"Value must be at most {maximum}."))

    for name in sorted(set(form_data) - allowed_fields):
        errors.append(_field_error(name, "UNKNOWN_FIELD", "This field is not defined by the Application Template."))

    if errors:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "FIELD_VALIDATION_FAILED",
                "message": "Application data failed validation.",
                "field_errors": errors,
            },
        )


def _generate_reference_number() -> str:
    """Generate a stable human-readable application reference number."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    suffix = uuid.uuid4().hex[:6].upper()
    return f"APP-{stamp}-{suffix}"


async def _initiate_issuance_via_flow(
    *,
    application: "ApplicantApplication",
    applicant: "Applicant",
    claims: dict[str, Any],
) -> dict[str, Any] | None:
    """Trigger OID4VCI issuance via flow-service webhook orchestration.

    Returns an issuance-shaped payload when a matching flow produced an offer.
    Raises HTTPException when no eligible flow/offer exists.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    event_payload = {
        "event_type": "application.approved",
        "aggregate_id": application.id,
        "aggregate_type": "application",
        "organization_id": application.organization_id,
        "timestamp": timestamp,
        "data": {
            "applicant_id": applicant.id,
            "application_id": application.id,
            "credential_template_id": application.credential_template_id,
            "email": applicant.email,
            "given_name": applicant.given_name,
            "family_name": applicant.family_name,
            "vetting_level": applicant.vetting_level.value,
            "application_status": application.status.value.lower(),
            "application_approved_at": application.reviewed_at.isoformat() if application.reviewed_at else timestamp,
            "triggered_by_event": "application.manual_issue",
            "claims": claims,
        },
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{FLOW_SERVICE_URL}/v1/flows/webhooks/application-approved",
            json=event_payload,
        )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=f"Flow service issuance trigger failed with status {response.status_code}",
        )

    body = response.json() if response.content else {}
    offers = body.get("offers") if isinstance(body, dict) else None
    if not isinstance(offers, list) or not offers:
        raise HTTPException(
            status_code=409,
            detail=(
                "No active issuance flow produced an offer for this application. "
                "Configure and activate an OID4VCI flow for the credential template."
            ),
        )

    selected_offer = next(
        (
            offer
            for offer in offers
            if isinstance(offer, dict)
            and (offer.get("credential_offer_uri") or offer.get("credential_offer_uris"))
        ),
        None,
    )
    if not selected_offer:
        raise HTTPException(
            status_code=502,
            detail="Flow orchestration completed without a credential offer URI",
        )

    return {
        "id": selected_offer.get("credential_offer_transaction_id") or selected_offer.get("flow_instance_id"),
        "flow_instance_id": selected_offer.get("flow_instance_id"),
        "flow_definition_id": selected_offer.get("flow_definition_id"),
        "credential_offer_uri": selected_offer.get("credential_offer_uri"),
        "credential_offer_uris": selected_offer.get("credential_offer_uris") or {},
        "credential_offer_labels": selected_offer.get("credential_offer_labels") or {},
        "pre_auth_code": selected_offer.get("pre_authorized_code"),
        "expires_at": selected_offer.get("expires_at"),
        "status": selected_offer.get("issuance_status") or "pending",
        "source": "flow",
    }


# =============================================================================
# Domain Layer
# =============================================================================

class ApplicantStatus(str, Enum):
    """Applicant vetting status."""
    DRAFT = "DRAFT"
    SUBMITTED = "SUBMITTED"
    UNDER_REVIEW = "UNDER_REVIEW"
    PENDING_INFORMATION = "PENDING_INFORMATION"
    APPROVED = "APPROVED"
    OFFERED = "OFFERED"
    REJECTED = "REJECTED"
    WITHDRAWN = "WITHDRAWN"
    CREDENTIALED = "CREDENTIALED"
    SUSPENDED = "SUSPENDED"


class VettingLevel(str, Enum):
    """Vetting assurance level."""
    BASIC = "basic"
    STANDARD = "standard"
    ENHANCED = "enhanced"


class ApplicationStatus(str, Enum):
    """Credential application lifecycle status."""
    DRAFT = "DRAFT"
    SUBMITTED = "SUBMITTED"
    UNDER_REVIEW = "UNDER_REVIEW"
    PENDING_INFORMATION = "PENDING_INFORMATION"
    APPROVED = "APPROVED"
    OFFERED = "OFFERED"
    REJECTED = "REJECTED"
    WITHDRAWN = "WITHDRAWN"
    CREDENTIALED = "CREDENTIALED"
    SUSPENDED = "SUSPENDED"


class ClaimState(str, Enum):
    NOT_READY = "NOT_READY"
    BLOCKED = "BLOCKED"
    OFFER_READY = "OFFER_READY"
    CLAIMED = "CLAIMED"
    EXPIRED = "EXPIRED"


LEGACY_APPLICANT_STATUS_MAP = {
    "pending": ApplicantStatus.SUBMITTED,
    "in_review": ApplicantStatus.UNDER_REVIEW,
    "approved": ApplicantStatus.APPROVED,
    "rejected": ApplicantStatus.REJECTED,
    "revoked": ApplicantStatus.SUSPENDED,
    "draft": ApplicantStatus.DRAFT,
    "submitted": ApplicantStatus.SUBMITTED,
    "under_review": ApplicantStatus.UNDER_REVIEW,
    "needs_info": ApplicantStatus.PENDING_INFORMATION,
    "offered": ApplicantStatus.OFFERED,
    "issued": ApplicantStatus.CREDENTIALED,
}

LEGACY_APPLICATION_STATUS_MAP = {
    "draft": ApplicationStatus.DRAFT,
    "submitted": ApplicationStatus.SUBMITTED,
    "under_review": ApplicationStatus.UNDER_REVIEW,
    "needs_info": ApplicationStatus.PENDING_INFORMATION,
    "approved": ApplicationStatus.APPROVED,
    "offered": ApplicationStatus.OFFERED,
    "issued": ApplicationStatus.CREDENTIALED,
    "rejected": ApplicationStatus.REJECTED,
    "revoked": ApplicationStatus.SUSPENDED,
}

APPLICANT_ALLOWED_TRANSITIONS: dict[ApplicantStatus, set[ApplicantStatus]] = {
    ApplicantStatus.DRAFT: {ApplicantStatus.SUBMITTED, ApplicantStatus.WITHDRAWN},
    ApplicantStatus.SUBMITTED: {ApplicantStatus.UNDER_REVIEW, ApplicantStatus.PENDING_INFORMATION, ApplicantStatus.WITHDRAWN, ApplicantStatus.SUSPENDED},
    ApplicantStatus.UNDER_REVIEW: {ApplicantStatus.APPROVED, ApplicantStatus.REJECTED, ApplicantStatus.PENDING_INFORMATION, ApplicantStatus.SUSPENDED},
    ApplicantStatus.PENDING_INFORMATION: {ApplicantStatus.SUBMITTED, ApplicantStatus.UNDER_REVIEW, ApplicantStatus.WITHDRAWN, ApplicantStatus.SUSPENDED},
    ApplicantStatus.APPROVED: {ApplicantStatus.OFFERED, ApplicantStatus.CREDENTIALED, ApplicantStatus.SUSPENDED},
    ApplicantStatus.OFFERED: {ApplicantStatus.CREDENTIALED, ApplicantStatus.SUSPENDED},
    ApplicantStatus.REJECTED: set(),
    ApplicantStatus.WITHDRAWN: set(),
    ApplicantStatus.CREDENTIALED: set(),
    ApplicantStatus.SUSPENDED: set(),
}

APPLICATION_ALLOWED_TRANSITIONS: dict[ApplicationStatus, set[ApplicationStatus]] = {
    ApplicationStatus.DRAFT: {ApplicationStatus.SUBMITTED, ApplicationStatus.WITHDRAWN},
    ApplicationStatus.SUBMITTED: {ApplicationStatus.UNDER_REVIEW, ApplicationStatus.APPROVED, ApplicationStatus.REJECTED, ApplicationStatus.PENDING_INFORMATION, ApplicationStatus.WITHDRAWN, ApplicationStatus.SUSPENDED},
    ApplicationStatus.UNDER_REVIEW: {ApplicationStatus.APPROVED, ApplicationStatus.REJECTED, ApplicationStatus.PENDING_INFORMATION, ApplicationStatus.SUSPENDED},
    ApplicationStatus.PENDING_INFORMATION: {ApplicationStatus.SUBMITTED, ApplicationStatus.UNDER_REVIEW, ApplicationStatus.WITHDRAWN, ApplicationStatus.SUSPENDED},
    ApplicationStatus.APPROVED: {ApplicationStatus.OFFERED, ApplicationStatus.CREDENTIALED, ApplicationStatus.SUSPENDED},
    ApplicationStatus.OFFERED: {ApplicationStatus.CREDENTIALED, ApplicationStatus.SUSPENDED},
    ApplicationStatus.REJECTED: set(),
    ApplicationStatus.WITHDRAWN: set(),
    ApplicationStatus.CREDENTIALED: set(),
    ApplicationStatus.SUSPENDED: set(),
}


def _parse_applicant_status(value: str | ApplicantStatus | None) -> ApplicantStatus:
    if value is None:
        return ApplicantStatus.DRAFT
    if isinstance(value, ApplicantStatus):
        return value
    if value in ApplicantStatus._value2member_map_:
        return ApplicantStatus(value)
    mapped = LEGACY_APPLICANT_STATUS_MAP.get(value.lower())
    if mapped:
        return mapped
    return ApplicantStatus(value.upper())


def _parse_application_status(value: str | ApplicationStatus | None) -> ApplicationStatus:
    if value is None:
        return ApplicationStatus.DRAFT
    if isinstance(value, ApplicationStatus):
        return value
    if value in ApplicationStatus._value2member_map_:
        return ApplicationStatus(value)
    mapped = LEGACY_APPLICATION_STATUS_MAP.get(value.lower())
    if mapped:
        return mapped
    return ApplicationStatus(value.upper())


def _transition_status(current: Enum, target: Enum, allowed: dict[Enum, set[Enum]], entity_name: str) -> Enum:
    if current == target:
        return target
    if target not in allowed.get(current, set()):
        raise HTTPException(status_code=400, detail=f"Invalid {entity_name} status transition: {current.value} -> {target.value}")
    return target


def _set_applicant_status(applicant: "Applicant", status: ApplicantStatus) -> None:
    applicant.status = _transition_status(applicant.status, status, APPLICANT_ALLOWED_TRANSITIONS, "applicant")
    applicant.updated_at = datetime.now(timezone.utc)


def _set_application_status(application: "ApplicantApplication", status: ApplicationStatus) -> None:
    application.status = _transition_status(application.status, status, APPLICATION_ALLOWED_TRANSITIONS, "application")
    application.updated_at = datetime.now(timezone.utc)


def _force_application_status(application: "ApplicantApplication", status: ApplicationStatus) -> None:
    application.status = status
    application.updated_at = datetime.now(timezone.utc)


def _force_applicant_status(applicant: "Applicant", status: ApplicantStatus) -> None:
    applicant.status = status
    applicant.updated_at = datetime.now(timezone.utc)


def _parse_iso_datetime(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _build_credential_claims(
    application: "ApplicantApplication",
    applicant: "Applicant",
    template: dict[str, Any],
) -> dict[str, Any]:
    """Map applicant form fields to credential claims using the active template."""
    claims: dict[str, Any] = {}
    for field in template.get("form_fields") or []:
        if not isinstance(field, dict):
            continue
        field_id = str(field.get("field_id") or "").strip()
        claim_name = str(field.get("claim_mapping") or field_id).strip()
        if field_id and claim_name and field_id in application.form_data:
            claims[claim_name] = application.form_data[field_id]

    now = datetime.now(timezone.utc)
    validity_days = int(template.get("application_validity_days") or 30)
    system_values = {
        "applicant.user_id": applicant.user_id,
        "applicant.email": applicant.email,
        "applicant.given_name": applicant.given_name,
        "applicant.family_name": applicant.family_name,
        "application.id": application.id,
        "application.reference_number": application.reference_number,
        "application.organization_id": application.organization_id,
        "current.date": now.date().isoformat(),
        "current.datetime": now.isoformat(),
        "validity.expiry_date": (now + timedelta(days=validity_days)).date().isoformat(),
        "template.name": template.get("name"),
        "template.description": template.get("description"),
    }

    for rule in template.get("claim_collection_rules") or []:
        if not isinstance(rule, dict):
            continue
        source_config = rule.get("source_config")
        if not isinstance(source_config, dict):
            continue
        claim_name = str(rule.get("claim_name") or "").strip()
        source = str(rule.get("source") or "")
        field_id = str(source_config.get("field_id") or "").strip()
        if source == "FORM_FIELD" and field_id and claim_name and field_id in application.form_data:
            claims[claim_name] = application.form_data[field_id]
        elif source == "SYSTEM" and claim_name:
            system_field = str(source_config.get("system_field") or "").strip()
            value = source_config.get("value") if system_field == "constant" else system_values.get(system_field)
            if value is not None:
                claims[claim_name] = value

    return claims


def _advance_applicant_to_offered(applicant: "Applicant") -> None:
    if applicant.status == ApplicantStatus.CREDENTIALED:
        return
    if applicant.status == ApplicantStatus.DRAFT:
        _set_applicant_status(applicant, ApplicantStatus.SUBMITTED)
    if applicant.status == ApplicantStatus.SUBMITTED:
        _set_applicant_status(applicant, ApplicantStatus.UNDER_REVIEW)
    if applicant.status in {ApplicantStatus.UNDER_REVIEW, ApplicantStatus.PENDING_INFORMATION}:
        _set_applicant_status(applicant, ApplicantStatus.APPROVED)
    if applicant.status == ApplicantStatus.APPROVED:
        _set_applicant_status(applicant, ApplicantStatus.OFFERED)


def _advance_applicant_to_credentialed(applicant: "Applicant") -> None:
    if applicant.status == ApplicantStatus.CREDENTIALED:
        return
    _advance_applicant_to_offered(applicant)
    if applicant.status == ApplicantStatus.OFFERED:
        _set_applicant_status(applicant, ApplicantStatus.CREDENTIALED)


async def _get_issuance_transaction_context(transaction_id: str | None) -> dict[str, Any] | None:
    if not transaction_id or transaction_id.startswith("local-"):
        return None
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(f"{ISSUANCE_SERVICE_URL}/v1/issuance/transactions/{transaction_id}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    except Exception as exc:
        logger.debug("Unable to sync issuance transaction %s: %s", transaction_id, exc)
        return None


async def _sync_application_issuance_state(
    application: "ApplicantApplication",
    repo: "InMemoryApplicantRepository",
    *,
    save: bool = True,
) -> bool:
    """Reconcile application status with the real OID4VCI transaction state."""
    changed = False
    offer_expires_at = _parse_iso_datetime(application.system_data.get("offer_expires_at"))
    if (
        application.claim_state == ClaimState.OFFER_READY
        and offer_expires_at
        and offer_expires_at <= datetime.now(timezone.utc)
    ):
        application.claim_state = ClaimState.EXPIRED
        application.claim_blocker = {
            "code": "OFFER_EXPIRED",
            "owner": "APPLICANT",
            "message": "This credential offer has expired. Request a new offer.",
        }
        changed = True

    transaction_id = application.system_data.get("issuance_transaction_id")
    tx = await _get_issuance_transaction_context(transaction_id)
    if not tx:
        if changed and save:
            await repo.save_application(application)
        return changed

    status = str(tx.get("status") or "").lower()

    if status == "issued":
        issued_at = _parse_iso_datetime(tx.get("issued_at")) or datetime.now(timezone.utc)
        if application.status != ApplicationStatus.CREDENTIALED:
            try:
                _set_application_status(application, ApplicationStatus.CREDENTIALED)
            except HTTPException:
                _force_application_status(application, ApplicationStatus.CREDENTIALED)
            changed = True
        if application.issued_at != issued_at:
            application.issued_at = issued_at
            application.updated_at = datetime.now(timezone.utc)
            changed = True
        if application.system_data.get("issuance_status") != status:
            application.system_data["issuance_status"] = status
        if application.claim_state != ClaimState.CLAIMED:
            application.claim_state = ClaimState.CLAIMED
            application.claim_blocker = None
            changed = True

        applicant = await repo.get_by_id(application.applicant_id)
        if applicant and applicant.status != ApplicantStatus.CREDENTIALED:
            try:
                _advance_applicant_to_credentialed(applicant)
            except HTTPException:
                _force_applicant_status(applicant, ApplicantStatus.CREDENTIALED)
            if save:
                await repo.save(applicant)
    elif status in {"pending", "authorized"}:
        if application.system_data.get("issuance_status") != status:
            application.system_data["issuance_status"] = status
            changed = True
        if application.status == ApplicationStatus.CREDENTIALED:
            # Older builds marked a generated offer as CREDENTIALED. If the
            # wallet has not completed issuance yet, repair that optimistic state.
            _force_application_status(application, ApplicationStatus.OFFERED)
            application.issued_at = None
            changed = True

    if changed and save:
        await repo.save_application(application)
    return changed


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
    flow_id: str = ""
    
    # Identity
    email: str = ""
    given_name: str | None = None
    family_name: str | None = None
    phone: str | None = None
    
    # External identity
    oidc_subject: str | None = None
    user_id: str | None = None
    external_id: str | None = None
    
    # Protocol schema fields
    credential_template_id: str | None = None
    reviewer_id: str | None = None
    reviewer_lock_expires_at: datetime | None = None
    submitted_at: datetime | None = None
    approved_at: datetime | None = None
    credentialed_at: datetime | None = None
    rejection_code: str | None = None
    application_data: dict[str, Any] | None = None
    vetting_checks: list[dict[str, Any]] | None = None
    issued_credential_id: str | None = None
    metadata: dict[str, Any] | None = None
    
    # Vetting status
    status: ApplicantStatus = ApplicantStatus.DRAFT
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
        _set_applicant_status(self, ApplicantStatus.UNDER_REVIEW)
    
    def approve(self, reviewer_notes: str | None = None) -> None:
        _set_applicant_status(self, ApplicantStatus.APPROVED)
        self.reviewer_notes = reviewer_notes
        self.reviewed_at = datetime.now(timezone.utc)
    
    def reject(self, reason: str) -> None:
        _set_applicant_status(self, ApplicantStatus.REJECTED)
        self.rejection_reason = reason
        self.reviewed_at = datetime.now(timezone.utc)
    
    def revoke(self, reason: str) -> None:
        _set_applicant_status(self, ApplicantStatus.SUSPENDED)
        self.rejection_reason = reason


@dataclass
class ApplicantApplication:
    """Credential application submitted by an applicant."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    applicant_id: str = ""
    organization_id: str = ""
    reference_number: str | None = None
    application_template_id: str = ""
    credential_template_id: str = ""
    status: ApplicationStatus = ApplicationStatus.DRAFT
    form_data: dict[str, Any] = field(default_factory=dict)
    integration_context: dict[str, Any] = field(default_factory=dict)
    system_data: dict[str, Any] = field(default_factory=dict)
    required_checks: list[dict[str, Any]] = field(default_factory=list)
    claim_state: ClaimState = ClaimState.NOT_READY
    claim_blocker: dict[str, Any] | None = None
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
            "flow_id": applicant.flow_id,
            "email": applicant.email,
            "given_name": applicant.given_name,
            "family_name": applicant.family_name,
            "phone": applicant.phone,
            "oidc_subject": applicant.oidc_subject,
            "user_id": applicant.user_id,
            "external_id": applicant.external_id,
            "credential_template_id": applicant.credential_template_id,
            "status": applicant.status.value,
            "vetting_level": applicant.vetting_level.value,
            "vetting_data": applicant.vetting_data,
            "verification_results": applicant.verification_results,
            "reviewer_id": applicant.reviewer_id,
            "reviewer_notes": applicant.reviewer_notes,
            "rejection_reason": applicant.rejection_reason,
            "rejection_code": applicant.rejection_code,
            "application_data": applicant.application_data,
            "vetting_checks": applicant.vetting_checks,
            "issued_credential_id": applicant.issued_credential_id,
            "metadata": applicant.metadata,
            "created_at": self._dt_to_str(applicant.created_at),
            "updated_at": self._dt_to_str(applicant.updated_at),
            "reviewed_at": self._dt_to_str(applicant.reviewed_at),
            "submitted_at": self._dt_to_str(applicant.submitted_at),
            "approved_at": self._dt_to_str(applicant.approved_at),
            "credentialed_at": self._dt_to_str(applicant.credentialed_at),
            "reviewer_lock_expires_at": self._dt_to_str(applicant.reviewer_lock_expires_at),
            "last_login": self._dt_to_str(applicant.last_login),
        }

    def _deserialize_applicant(self, payload: dict[str, Any]) -> Applicant:
        return Applicant(
            id=payload.get("id", str(uuid.uuid4())),
            organization_id=payload.get("organization_id", ""),
            flow_id=payload.get("flow_id", ""),
            email=payload.get("email", ""),
            given_name=payload.get("given_name"),
            family_name=payload.get("family_name"),
            phone=payload.get("phone"),
            oidc_subject=payload.get("oidc_subject"),
            user_id=payload.get("user_id"),
            external_id=payload.get("external_id"),
            credential_template_id=payload.get("credential_template_id"),
            status=_parse_applicant_status(payload.get("status", ApplicantStatus.DRAFT.value)),
            vetting_level=VettingLevel(payload.get("vetting_level", VettingLevel.BASIC.value)),
            vetting_data=payload.get("vetting_data", {}),
            verification_results=payload.get("verification_results", []),
            reviewer_id=payload.get("reviewer_id"),
            reviewer_notes=payload.get("reviewer_notes"),
            rejection_reason=payload.get("rejection_reason"),
            rejection_code=payload.get("rejection_code"),
            application_data=payload.get("application_data"),
            vetting_checks=payload.get("vetting_checks"),
            issued_credential_id=payload.get("issued_credential_id"),
            metadata=payload.get("metadata"),
            created_at=self._str_to_dt(payload.get("created_at")) or datetime.now(timezone.utc),
            updated_at=self._str_to_dt(payload.get("updated_at")) or datetime.now(timezone.utc),
            reviewed_at=self._str_to_dt(payload.get("reviewed_at")),
            submitted_at=self._str_to_dt(payload.get("submitted_at")),
            approved_at=self._str_to_dt(payload.get("approved_at")),
            credentialed_at=self._str_to_dt(payload.get("credentialed_at")),
            reviewer_lock_expires_at=self._str_to_dt(payload.get("reviewer_lock_expires_at")),
            last_login=self._str_to_dt(payload.get("last_login")),
        )

    def _serialize_application(self, application: ApplicantApplication) -> dict[str, Any]:
        return {
            "id": application.id,
            "applicant_id": application.applicant_id,
            "organization_id": application.organization_id,
            "reference_number": application.reference_number,
            "application_template_id": application.application_template_id,
            "credential_template_id": application.credential_template_id,
            "status": application.status.value,
            "form_data": application.form_data,
            "integration_context": application.integration_context,
            "system_data": application.system_data,
            "required_checks": application.required_checks,
            "claim_state": application.claim_state.value,
            "claim_blocker": application.claim_blocker,
            "created_at": self._dt_to_str(application.created_at),
            "submitted_at": self._dt_to_str(application.submitted_at),
            "reviewed_at": self._dt_to_str(application.reviewed_at),
            "issued_at": self._dt_to_str(application.issued_at),
            "updated_at": self._dt_to_str(application.updated_at),
        }

    def _deserialize_application(self, payload: dict[str, Any]) -> ApplicantApplication:
        if "credential_configuration_id" in payload or "metadata" in payload:
            raise RuntimeError(
                "Legacy applicant store detected. Run the MIP 0.3 applicant-store migration before startup."
            )
        return ApplicantApplication(
            id=payload.get("id", str(uuid.uuid4())),
            applicant_id=payload.get("applicant_id", ""),
            organization_id=payload.get("organization_id", ""),
            reference_number=payload.get("reference_number"),
            application_template_id=payload.get("application_template_id", ""),
            credential_template_id=payload.get("credential_template_id", ""),
            status=_parse_application_status(payload.get("status", ApplicationStatus.DRAFT.value)),
            form_data=payload.get("form_data", {}),
            integration_context=payload.get("integration_context", {}),
            system_data=payload.get("system_data", {}),
            required_checks=payload.get("required_checks", []),
            claim_state=ClaimState(payload.get("claim_state", ClaimState.NOT_READY.value)),
            claim_blocker=payload.get("claim_blocker"),
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

    async def get_by_user_id(self, user_id: str, organization_id: str | None = None) -> Applicant | None:
        for a in self._applicants.values():
            if (
                (a.oidc_subject == user_id or a.user_id == user_id)
                and (organization_id is None or a.organization_id == organization_id)
            ):
                return a
        return None

    async def list_by_user_id(self, user_id: str) -> list[Applicant]:
        return [
            applicant
            for applicant in self._applicants.values()
            if applicant.oidc_subject == user_id or applicant.user_id == user_id
        ]
    
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

_repo: InMemoryApplicantRepository | None = None


def get_repo() -> InMemoryApplicantRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


class CreateApplicantRequest(BaseModel):
    organization_id: str = Field(min_length=1, max_length=255)
    user_id: str | None = None
    email: EmailStr
    given_name: str | None = Field(None, max_length=255)
    family_name: str | None = Field(None, max_length=255)
    phone: str | None = Field(None, max_length=50)
    vetting_level: str = "basic"


class UpdateApplicantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr | None = None
    given_name: str | None = Field(None, max_length=255)
    family_name: str | None = Field(None, max_length=255)
    phone: str | None = Field(None, max_length=50)
    vetting_data: dict[str, Any] | None = None


class ReviewRequest(BaseModel):
    decision: str  # "approve" or "reject"
    notes: str | None = None
    reason: str | None = None


class ApplicantResponse(BaseModel):
    id: str
    organization_id: str
    flow_id: str
    credential_template_id: str | None = None
    user_id: str | None = None
    external_id: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    email: str | None = None
    phone: str | None = None
    status: str
    reviewer_id: str | None = None
    reviewer_lock_expires_at: str | None = None
    submitted_at: str | None = None
    reviewed_at: str | None = None
    approved_at: str | None = None
    credentialed_at: str | None = None
    rejection_reason: str | None = None
    rejection_code: str | None = None
    application_data: dict[str, Any] | None = None
    vetting_checks: list[dict[str, Any]] | None = None
    issued_credential_id: str | None = None
    metadata: dict[str, Any] | None = None
    created_at: str
    updated_at: str | None = None


class CreateApplicationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1, max_length=255)
    application_template_id: str = Field(min_length=1, max_length=255)
    form_data: dict[str, Any] = Field(default_factory=dict)
    integration_context: dict[str, Any] = Field(default_factory=dict)


class ApplicationResponse(BaseModel):
    id: str
    applicant_id: str
    organization_id: str | None = None
    reference_number: str | None = None
    application_template_id: str
    credential_template_id: str
    form_data: dict[str, Any] = Field(default_factory=dict)
    integration_context: dict[str, Any] = Field(default_factory=dict)
    status: str
    claim_state: str
    claim_blocker: dict[str, Any] | None = None
    created_at: str
    submitted_at: str | None = None
    reviewed_at: str | None = None
    issued_at: str | None = None
    updated_at: str
    credential_display_name: str | None = None
    credential_offer_uri: str | None = None
    offer_expires_at: str | None = None
    # Per-wallet offer URIs keyed by wallet_id (e.g. {"marty": "openid-credential-offer://..."}).
    # Populated when the credential template has wallet_configs and the issuance
    # service is running with multi-wallet support.
    credential_offer_uris: dict[str, str] = Field(default_factory=dict)
    # Display labels for each wallet tab, sourced from the credential template's
    # wallet_configs display_name field (e.g. {"wr-marty-001": "SpruceKit"}).
    credential_offer_labels: dict[str, str] = Field(default_factory=dict)


class EnrollBiometricRequest(BaseModel):
    biometric_type: str = Field(
        "FACIAL",
        pattern=r"^(FACIAL|FINGERPRINT|IRIS|VOICE|SIGNATURE)$",
    )
    template_data_base64: str = Field(
        ..., min_length=10, max_length=10 * 1024 * 1024
    )
    image_data_base64: str | None = Field(
        None, max_length=50 * 1024 * 1024
    )
    is_live_capture: bool = True
    capture_device_id: str | None = Field(None, max_length=255)


class ApplicationReviewRequest(BaseModel):
    decision: str  # "approve" or "reject"
    notes: str | None = None
    reason: str | None = None


class SupersedeApplicationRequest(BaseModel):
    reason: str | None = None
    replacement_application_id: str | None = None
    replacement_credential_template_id: str | None = None
    source: str | None = None


class ApplicationIssueRequest(BaseModel):
    """Learner delivery preferences captured when generating an issuance offer."""

    model_config = ConfigDict(extra="forbid")

    delivery_destination_ids: list[str] = Field(default_factory=list)
    canvas_credentials_consent: bool = False


class BiometricResponse(BaseModel):
    id: str
    applicant_id: str
    organization_id: str | None = None
    modality: str
    template_hash: str | None = None
    hash_algorithm: str | None = None
    provider: str | None = None
    capture_device: str | None = None
    quality_score: float | None = None
    liveness_verified: bool | None = None
    status: str | None = None
    revoked_at: str | None = None
    revocation_reason: str | None = None
    created_at: str


class VettingCheckResponse(BaseModel):
    id: str
    applicant_id: str | None = None
    organization_id: str | None = None
    check_type: str
    provider: str | None = None
    provider_reference_id: str | None = None
    status: str
    score: float | None = None
    threshold: float | None = None
    failure_reason: str | None = None
    evidence_refs: list[str] | None = None
    performed_by: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    expires_at: str | None = None
    raw_result: dict[str, Any] | None = None
    created_at: str
    updated_at: str | None = None


class CompleteCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passed: bool
    notes: str | None = None
    performed_by: str | None = None
    result: dict[str, Any] = Field(default_factory=dict)


class RequestInfoRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    missing_items: list[str] = Field(default_factory=list)
    message: str = ""
    deadline: str | None = None


class AcquireLockRequest(BaseModel):
    """Unreachable legacy adapter model; canonical locks derive identity from headers."""

    reviewer_id: str
    reviewer_name: str


class LockResponse(BaseModel):
    id: str | None = None
    applicant_id: str | None = None
    organization_id: str | None = None
    holder_user_id: str | None = None
    ttl_seconds: int | None = None
    expires_at: str | None = None
    released_at: str | None = None
    status: str | None = None
    created_at: str | None = None


class EnrichedApplicationResponse(BaseModel):
    id: str
    applicant_id: str
    organization_id: str | None = None
    reference_number: str | None = None
    application_template_id: str
    credential_template_id: str
    form_data: dict[str, Any] = Field(default_factory=dict)
    integration_context: dict[str, Any] = Field(default_factory=dict)
    status: str
    claim_state: str
    claim_blocker: dict[str, Any] | None = None
    created_at: str
    submitted_at: str | None = None
    reviewed_at: str | None = None
    issued_at: str | None = None
    updated_at: str
    credential_display_name: str | None = None
    # Enriched applicant info
    applicant_email: str | None = None
    applicant_given_name: str | None = None
    applicant_family_name: str | None = None
    applicant_phone: str | None = None
    applicant_status: str | None = None
    applicant_vetting_level: str | None = None
    verification_results: list[dict[str, Any]] = Field(default_factory=list)


async def create_applicant(
    request: CreateApplicantRequest,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicantResponse:
    """Create a new applicant."""
    # Check for existing
    existing = await repo.get_by_email(request.email, request.organization_id)
    if existing:
        updated = False
        if request.user_id and existing.oidc_subject != request.user_id:
            existing.oidc_subject = request.user_id
            existing.user_id = request.user_id
            updated = True
        if request.given_name and existing.given_name != request.given_name:
            existing.given_name = request.given_name
            updated = True
        if request.family_name and existing.family_name != request.family_name:
            existing.family_name = request.family_name
            updated = True
        if request.phone and existing.phone != request.phone:
            existing.phone = request.phone
            updated = True
        if updated:
            existing.updated_at = datetime.now(timezone.utc)
            await repo.save(existing)
        return _to_response(existing)
    
    applicant = Applicant(
        organization_id=request.organization_id,
        email=request.email,
        given_name=request.given_name,
        family_name=request.family_name,
        phone=request.phone,
        oidc_subject=request.user_id,
        user_id=request.user_id,
        vetting_level=VettingLevel(request.vetting_level),
    )
    await repo.save(applicant)
    return _to_response(applicant)


async def get_applicant_by_user(
    user_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicantResponse:
    """Get an applicant profile by authenticated user id."""
    applicant = await repo.get_by_user_id(user_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")
    return _to_response(applicant)


async def list_applicants(
    organization_id: str = Query(...),
    status: str | None = None,
    limit: int = Query(default=100, le=500, description="Max items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> list[ApplicantResponse]:
    """List applicants for an organization."""
    status_filter = _parse_applicant_status(status) if status else None
    applicants = await repo.list_by_organization(organization_id, status_filter)
    return [_to_response(a) for a in applicants[offset:offset + limit]]


async def get_applicant(
    applicant_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicantResponse:
    """Get an applicant by ID."""
    applicant = await repo.get_by_id(applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")
    return _to_response(applicant)


async def enroll_biometric(
    applicant_id: str,
    request: EnrollBiometricRequest,
    repo: InMemoryApplicantRepository = Depends(get_repo),
    x_organization_id: str = Header(alias="X-Organization-Id"),
) -> BiometricResponse:
    """Enroll a biometric for an applicant."""
    applicant = await repo.get_by_id(applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")
    if applicant.organization_id and applicant.organization_id != x_organization_id:
        raise HTTPException(status_code=403, detail="Not authorized for this applicant")

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


async def list_biometrics(
    applicant_id: str,
    limit: int = Query(default=100, le=500, description="Max items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> list[BiometricResponse]:
    """List biometrics for an applicant."""
    applicant = await repo.get_by_id(applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")
    biometrics = await repo.list_biometrics(applicant_id)
    return [_biometric_to_response(b) for b in biometrics[offset:offset + limit]]


async def create_application(
    request: CreateApplicationRequest,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-ID"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    """Create a holder-owned application from an active Application Template."""
    user_id, _, _ = _identity_headers(x_user_id)
    template = await _load_application_template(request.application_template_id)
    template_org_id = str(template.get("organization_id") or "")
    if template_org_id != request.organization_id:
        raise HTTPException(status_code=422, detail="Application Template belongs to another organization")
    if str(template.get("status") or "").strip().upper() != "ACTIVE":
        raise HTTPException(status_code=422, detail="Application Template must be active")
    credential_template_id = str(template.get("credential_template_id") or "").strip()
    if not credential_template_id:
        raise HTTPException(status_code=422, detail="Application Template has no Credential Template")

    form_fields = template.get("form_fields") if isinstance(template.get("form_fields"), list) else []
    _validate_form_data(request.form_data, form_fields)

    applicant_organization_id = str(x_organization_id or "").strip()
    if not applicant_organization_id:
        raise HTTPException(status_code=422, detail="Authenticated applicant organization context is required")
    applicant = await repo.get_by_user_id(user_id, applicant_organization_id)
    if not applicant:
        raise HTTPException(status_code=409, detail="Create your applicant profile before applying")

    # Prevent duplicate active applications for the same credential type
    existing = await repo.list_applications_for_applicant(applicant.id)
    _active_statuses = {
        ApplicationStatus.DRAFT, ApplicationStatus.SUBMITTED,
        ApplicationStatus.UNDER_REVIEW, ApplicationStatus.PENDING_INFORMATION,
        ApplicationStatus.APPROVED, ApplicationStatus.OFFERED,
        ApplicationStatus.CREDENTIALED,
    }
    duplicate = next(
        (a for a in existing
         if a.credential_template_id == credential_template_id
         and a.status in _active_statuses),
        None,
    )
    if duplicate:
        raise HTTPException(
            status_code=409,
            detail=f"An active application for this credential already exists (ref {duplicate.reference_number})",
        )

    application = ApplicantApplication(
        applicant_id=applicant.id,
        organization_id=request.organization_id,
        reference_number=_generate_reference_number(),
        application_template_id=request.application_template_id,
        credential_template_id=credential_template_id,
        form_data=request.form_data,
        integration_context=request.integration_context,
        system_data={
            "credential_display_name": template.get("name"),
            "approval_strategy": template.get("approval_strategy"),
            "application_validity_days": template.get("application_validity_days"),
        },
        required_checks=[
            check
            for check in (template.get("required_checks") or [])
            if isinstance(check, dict)
        ],
    )
    await repo.save_application(application)
    return _application_to_response(application)


async def list_applications_for_applicant(
    applicant_id: str,
    limit: int = Query(default=100, le=500, description="Max items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> list[ApplicationResponse]:
    """List applications for an applicant profile."""
    applications = await repo.list_applications_for_applicant(applicant_id)
    for application in applications:
        await _sync_application_issuance_state(application, repo)
    applications.sort(key=lambda a: a.created_at, reverse=True)
    return [_application_to_response(a) for a in applications[offset:offset + limit]]


async def list_applications_for_organization(
    organization_id: str = Query(...),
    status: str | None = Query(None),
    limit: int = Query(default=100, le=500, description="Max items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> list[ApplicationResponse]:
    """List applications for an organization (used by org console)."""
    status_filter = _parse_application_status(status) if status else None
    applications = await repo.list_applications_for_organization(organization_id, status_filter)
    for application in applications:
        await _sync_application_issuance_state(application, repo)
    applications.sort(key=lambda a: a.created_at, reverse=True)
    return [_application_to_response(a) for a in applications[offset:offset + limit]]


async def submit_application(
    application_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    """Submit an existing application into review."""
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    await _sync_application_issuance_state(application, repo)

    applicant = await repo.get_by_id(application.applicant_id)

    if application.status == ApplicationStatus.SUBMITTED:
        if not application.reference_number:
            application.reference_number = _generate_reference_number()
            application.updated_at = datetime.now(timezone.utc)
            await repo.save_application(application)
        return _application_to_response(application)

    submittable = {ApplicationStatus.DRAFT, ApplicationStatus.PENDING_INFORMATION}
    if application.status not in submittable:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot submit application in {application.status.value} status",
        )

    is_first_submission = application.status == ApplicationStatus.DRAFT
    template = await _load_application_template(application.application_template_id)
    form_fields = template.get("form_fields") if isinstance(template.get("form_fields"), list) else []
    _validate_form_data(application.form_data, form_fields)
    auto_approve = str(application.system_data.get("approval_strategy") or "").upper() in {
        "AUTO",
        "AUTO_APPROVE",
    }

    _set_application_status(application, ApplicationStatus.SUBMITTED)
    if not application.reference_number:
        application.reference_number = _generate_reference_number()
    application.submitted_at = datetime.now(timezone.utc)

    applicant = await repo.get_by_id(application.applicant_id)
    if applicant and applicant.status in {ApplicantStatus.DRAFT, ApplicantStatus.PENDING_INFORMATION}:
        _set_applicant_status(applicant, ApplicantStatus.SUBMITTED)
        await repo.save(applicant)

    # Auto-approve: skip the vetting queue entirely when the template opts out
    # of manual review.  We resolve this BEFORE creating vetting checks so no
    # orphaned NOT_STARTED checks accumulate for auto-issued credentials.
    if auto_approve:
        _set_application_status(application, ApplicationStatus.APPROVED)
        application.reviewed_at = datetime.now(timezone.utc)
        await repo.save_application(application)
        return _application_to_response(application)

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


async def auto_issue_application(
    application_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    """Atomically submit, approve, and issue a credential for an auto-approve application.

    Intended for MemberCredential and other templates where ``approval_required``
    is False.  The caller must have already created the application and included
    ``auto_approve: true`` in the metadata.  This endpoint combines the three
    separate calls (submit / review / issue) into one round-trip so there is no
    window for partial state.
    """
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    await _sync_application_issuance_state(application, repo)

    if str(application.system_data.get("approval_strategy") or "").upper() not in {"AUTO", "AUTO_APPROVE"}:
        raise HTTPException(
            status_code=400,
            detail="Application Template does not allow automatic approval",
        )

    now = datetime.now(timezone.utc)

    # Move through SUBMITTED → APPROVED in one atomic save, skipping vetting.
    if application.status in {ApplicationStatus.DRAFT, ApplicationStatus.PENDING_INFORMATION}:
        _set_application_status(application, ApplicationStatus.SUBMITTED)
        if not application.reference_number:
            application.reference_number = _generate_reference_number()
        application.submitted_at = now

    if application.status == ApplicationStatus.SUBMITTED:
        _set_application_status(application, ApplicationStatus.APPROVED)
        application.reviewed_at = now

    if application.status not in (ApplicationStatus.APPROVED, ApplicationStatus.OFFERED):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot auto-issue application in {application.status.value} status",
        )

    await repo.save_application(application)

    # Delegate to the issuance service.
    applicant = await repo.get_by_id(application.applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")

    template = await _load_application_template(application.application_template_id)
    claims = _build_credential_claims(application, applicant, template)

    try:
        issuance = await _initiate_issuance_via_flow(
            application=application,
            applicant=applicant,
            claims=claims,
        )
    except HTTPException as exc:
        if exc.status_code == 409:
            application.claim_state = ClaimState.BLOCKED
            application.claim_blocker = {
                "code": "NO_ACTIVE_ISSUANCE_FLOW",
                "owner": "ISSUER",
                "message": "The issuer is still preparing this credential.",
            }
            application.updated_at = datetime.now(timezone.utc)
            await repo.save_application(application)
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "NO_ACTIVE_ISSUANCE_FLOW",
                    "message": "No active issuance flow is available for this application.",
                    "claim_state": application.claim_state.value,
                    "claim_blocker": application.claim_blocker,
                },
            ) from exc
        raise

    has_offer = bool(issuance.get("credential_offer_uri") or issuance.get("credential_offer_uris"))
    if has_offer:
        if application.status == ApplicationStatus.APPROVED:
            _set_application_status(application, ApplicationStatus.OFFERED)
        application.issued_at = None
    application.system_data["issuance_transaction_id"] = issuance.get("id")
    application.system_data["credential_offer_uri"] = issuance.get("credential_offer_uri")
    application.system_data["offer_expires_at"] = issuance.get("expires_at")
    application.system_data["credential_offer_uris"] = issuance.get("credential_offer_uris") or {}
    application.system_data["credential_offer_labels"] = issuance.get("credential_offer_labels") or {}
    application.system_data["offer_generated_at"] = datetime.now(timezone.utc).isoformat()
    application.system_data["issuance_status"] = issuance.get("status") or "pending"
    application.claim_state = ClaimState.OFFER_READY
    application.claim_blocker = None
    if issuance.get("flow_instance_id"):
        application.system_data["flow_instance_id"] = issuance.get("flow_instance_id")
    if issuance.get("flow_definition_id"):
        application.system_data["flow_definition_id"] = issuance.get("flow_definition_id")
    if issuance.get("source"):
        application.system_data["issuance_source"] = issuance.get("source")
    application.updated_at = datetime.now(timezone.utc)
    await repo.save_application(application)

    # A generated QR/offer is not a credential yet. The status becomes
    # CREDENTIALED only after the issuance transaction reaches "issued".
    if has_offer:
        _advance_applicant_to_offered(applicant)
    await repo.save(applicant)
    return _application_to_response(application)


async def review_application(
    application_id: str,
    request: ApplicationReviewRequest,
    http_request: Request = None,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    """Approve or reject an application in org console."""
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")

    if application.status not in {ApplicationStatus.SUBMITTED, ApplicationStatus.UNDER_REVIEW, ApplicationStatus.PENDING_INFORMATION}:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot review application in {application.status.value} status",
        )
    decision = request.decision.lower().strip()
    
    # Cedar policy evaluation for approval decisions
    if decision == "approve" and http_request and hasattr(http_request.app.state, "cedar_engine"):
        cedar_engine = http_request.app.state.cedar_engine
        meta = {**application.form_data, **application.integration_context}
        cedar_context = {
            "risk_score": int(meta.get("risk_score", 0)),
            "document_verification_passed": bool(meta.get("document_verification_passed", True)),
            "biometric_match_score": int(meta.get("biometric_match_score", 100)),
            "evidence_count": int(meta.get("evidence_count", 1)),
            "applicant_country": str(meta.get("applicant_country", "US")),
        }
        org_id = str(meta.get("organization_id", application.applicant_id))
        cedar_entities = [
            {
                "uid": {"type": "MIP::User", "id": "reviewer"},
                "attrs": {"email": "", "status": "ACTIVE"},
                "parents": [{"type": "MIP::Organization", "id": org_id}],
            },
            {
                "uid": {"type": "MIP::Organization", "id": org_id},
                "attrs": {},
                "parents": [],
            },
            {
                "uid": {"type": "MIP::Application", "id": application_id},
                "attrs": {
                    "risk_score": cedar_context["risk_score"],
                    "status": application.status.value,
                },
                "parents": [{"type": "MIP::Organization", "id": org_id}],
            },
        ]
        cedar_decision = cedar_engine.is_authorized(
            principal='MIP::User::"reviewer"',
            action='MIP::Action::"applications:approve"',
            resource=f'MIP::Application::"{application_id}"',
            context=cedar_context,
            entities=cedar_entities,
        )
        if not cedar_decision.allowed:
            raise HTTPException(
                status_code=403,
                detail=f"Approval denied by policy: {cedar_decision.reasons or cedar_decision.errors}",
            )
    
    if decision == "approve":
        _set_application_status(application, ApplicationStatus.APPROVED)
        application.reviewed_at = datetime.now(timezone.utc)
        if request.notes:
            application.system_data["review_notes"] = request.notes
        applicant = await repo.get_by_id(application.applicant_id)
        if applicant and applicant.status != ApplicantStatus.APPROVED:
            _set_applicant_status(applicant, ApplicantStatus.APPROVED)
            await repo.save(applicant)
    elif decision == "reject":
        if not request.reason:
            raise HTTPException(status_code=400, detail="Rejection reason required")
        _set_application_status(application, ApplicationStatus.REJECTED)
        application.reviewed_at = datetime.now(timezone.utc)
        application.system_data["rejection_reason"] = request.reason
        if request.notes:
            application.system_data["review_notes"] = request.notes
        applicant = await repo.get_by_id(application.applicant_id)
        if applicant:
            _set_applicant_status(applicant, ApplicantStatus.REJECTED)
            await repo.save(applicant)
    else:
        raise HTTPException(status_code=400, detail="Invalid decision")

    await repo.save_application(application)
    return _application_to_response(application)


async def supersede_application(
    application_id: str,
    request: SupersedeApplicationRequest,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    """Retire an active application so a replacement request can be created."""
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    await _sync_application_issuance_state(application, repo)

    if application.status in {ApplicationStatus.CREDENTIALED}:
        raise HTTPException(
            status_code=400,
            detail="Issued applications cannot be superseded from the applicant flow",
        )

    if application.status not in {
        ApplicationStatus.REJECTED,
        ApplicationStatus.WITHDRAWN,
        ApplicationStatus.SUSPENDED,
    }:
        # Superseding is an explicit replacement decision, so use a terminal
        # inactive state even when the normal user journey has already advanced
        # beyond states that allow withdrawal through ordinary transitions.
        _force_application_status(application, ApplicationStatus.WITHDRAWN)

    now = datetime.now(timezone.utc)
    application.system_data = {
        **(application.system_data or {}),
        "superseded": True,
        "superseded_at": now.isoformat(),
        "superseded_reason": request.reason or "superseded_by_reapplication",
        "superseded_source": request.source or "applicant_reapplication",
    }
    if request.replacement_application_id:
        application.system_data["superseded_by_application_id"] = request.replacement_application_id
    if request.replacement_credential_template_id:
        application.system_data["superseded_by_credential_template_id"] = request.replacement_credential_template_id
    await repo.save_application(application)
    return _application_to_response(application)


async def issue_application(
    application_id: str,
    request: ApplicationIssueRequest | None = Body(default=None),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    """Issue a credential for an approved application."""
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    await _sync_application_issuance_state(application, repo)

    # Always re-initiate: offers expire, and we need a fresh URL each time the admin requests one.
    # Also allow CREDENTIALED so an already-issued credential can be re-offered (re-issuance).
    REISSUABLE_STATUSES = (ApplicationStatus.APPROVED, ApplicationStatus.OFFERED, ApplicationStatus.CREDENTIALED)
    if application.status not in REISSUABLE_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot issue application in {application.status.value} status",
        )

    # For already-credentialed applications, roll back to OFFERED so the
    # issuance flow can generate a fresh wallet invite without a transition error.
    if application.status == ApplicationStatus.CREDENTIALED:
        _force_application_status(application, ApplicationStatus.OFFERED)
        application.issued_at = None

    applicant = await repo.get_by_id(application.applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")

    if request is not None:
        application.system_data["delivery_preferences"] = {
            "delivery_destination_ids": list(dict.fromkeys(request.delivery_destination_ids or [])),
            "canvas_credentials_consent": bool(request.canvas_credentials_consent),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

    template = await _load_application_template(application.application_template_id)
    claims = _build_credential_claims(application, applicant, template)

    try:
        issuance = await _initiate_issuance_via_flow(
            application=application,
            applicant=applicant,
            claims=claims,
        )
    except HTTPException as exc:
        if exc.status_code == 409:
            application.claim_state = ClaimState.BLOCKED
            application.claim_blocker = {
                "code": "NO_ACTIVE_ISSUANCE_FLOW",
                "owner": "ISSUER",
                "message": "The issuer is still preparing this credential.",
            }
            application.updated_at = datetime.now(timezone.utc)
            await repo.save_application(application)
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "NO_ACTIVE_ISSUANCE_FLOW",
                    "message": "No active issuance flow is available for this application.",
                    "claim_state": application.claim_state.value,
                    "claim_blocker": application.claim_blocker,
                },
            ) from exc
        raise

    has_offer = bool(issuance.get("credential_offer_uri") or issuance.get("credential_offer_uris"))
    if has_offer:
        if application.status == ApplicationStatus.APPROVED:
            _set_application_status(application, ApplicationStatus.OFFERED)
        application.issued_at = None
    application.system_data["issuance_transaction_id"] = issuance.get("id")
    application.system_data["credential_offer_uri"] = issuance.get("credential_offer_uri")
    application.system_data["offer_expires_at"] = issuance.get("expires_at")
    application.system_data["credential_offer_uris"] = issuance.get("credential_offer_uris") or {}
    application.system_data["credential_offer_labels"] = issuance.get("credential_offer_labels") or {}
    application.system_data["offer_generated_at"] = datetime.now(timezone.utc).isoformat()
    application.system_data["issuance_status"] = issuance.get("status") or "pending"
    application.claim_state = ClaimState.OFFER_READY
    application.claim_blocker = None
    if issuance.get("flow_instance_id"):
        application.system_data["flow_instance_id"] = issuance.get("flow_instance_id")
    if issuance.get("flow_definition_id"):
        application.system_data["flow_definition_id"] = issuance.get("flow_definition_id")
    if issuance.get("source"):
        application.system_data["issuance_source"] = issuance.get("source")
    application.updated_at = datetime.now(timezone.utc)
    await repo.save_application(application)

    # A generated QR/offer is not a credential yet. The status becomes
    # CREDENTIALED only after the issuance transaction reaches "issued".
    if has_offer:
        _advance_applicant_to_offered(applicant)
    await repo.save(applicant)
    return _application_to_response(application)


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


async def get_application(
    application_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> EnrichedApplicationResponse:
    """Get a single application with enriched applicant data."""
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    await _sync_application_issuance_state(application, repo)
    applicant = await repo.get_by_id(application.applicant_id)
    return _enriched_application_to_response(application, applicant)


# --- Vetting Checks Endpoints ---

async def list_checks(
    application_id: str,
    limit: int = Query(default=100, le=500, description="Max items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> list[VettingCheckResponse]:
    """List vetting checks for an application."""
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    checks = await repo.list_checks_for_application(application_id)
    return [_check_to_response(c) for c in checks[offset:offset + limit]]


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


async def get_pending_checks(
    check_type: str | None = Query(None),
    limit: int = Query(default=100, le=500, description="Max items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> list[VettingCheckResponse]:
    """Get all pending vetting checks (optionally filtered by type)."""
    checks = await repo.list_pending_checks(check_type)
    return [_check_to_response(c) for c in checks[offset:offset + limit]]


# --- Request Info Endpoint ---

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
        ApplicationStatus.PENDING_INFORMATION,
    }
    if application.status not in reviewable_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot request info for application in {application.status.value} status",
        )

    _set_application_status(application, ApplicationStatus.PENDING_INFORMATION)
    info_requests = application.system_data.get("info_requests", [])
    info_requests.append({
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "missing_items": request.missing_items,
        "message": request.message,
        "deadline": request.deadline,
    })
    application.system_data["info_requests"] = info_requests
    await repo.save_application(application)
    applicant = await repo.get_by_id(application.applicant_id)
    if applicant:
        _set_applicant_status(applicant, ApplicantStatus.PENDING_INFORMATION)
        await repo.save(applicant)
    return _application_to_response(application)


# --- Reviewer Lock Endpoints ---

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
            id=lock.lock_id,
            holder_user_id=lock.reviewer_id,
            expires_at=lock.expires_at.isoformat(),
            status="HELD",
            created_at=lock.acquired_at.isoformat(),
        )
    return LockResponse(
        id=lock.lock_id if lock else None,
        holder_user_id=request.reviewer_id,
        expires_at=lock.expires_at.isoformat() if lock else None,
        status="ACQUIRED",
        created_at=lock.acquired_at.isoformat() if lock else None,
    )


async def release_lock(
    application_id: str,
    reviewer_id: str = Query(...),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> dict[str, bool]:
    """Release the reviewer lock on an application."""
    released = await repo.release_lock(application_id, reviewer_id)
    return {"released": released}


async def get_lock_status(
    application_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> LockResponse:
    """Get the current lock status for an application."""
    lock = await repo.get_lock(application_id)
    if not lock:
        return LockResponse(status="RELEASED")
    return LockResponse(
        id=lock.lock_id,
        holder_user_id=lock.reviewer_id,
        expires_at=lock.expires_at.isoformat(),
        status="HELD",
        created_at=lock.acquired_at.isoformat(),
    )


async def update_applicant(
    applicant_id: str,
    request: UpdateApplicantRequest,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicantResponse:
    """Update an applicant."""
    applicant = await repo.get_by_id(applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")
    
    if request.email is not None:
        applicant.email = request.email
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


async def review_applicant(
    applicant_id: str,
    request: ReviewRequest,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicantResponse:
    """Review an applicant (approve/reject)."""
    applicant = await repo.get_by_id(applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")

    if applicant.status == ApplicantStatus.DRAFT:
        _set_applicant_status(applicant, ApplicantStatus.SUBMITTED)
    if applicant.status in {ApplicantStatus.SUBMITTED, ApplicantStatus.PENDING_INFORMATION}:
        _set_applicant_status(applicant, ApplicantStatus.UNDER_REVIEW)
    
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
        flow_id=applicant.flow_id,
        credential_template_id=applicant.credential_template_id,
        user_id=applicant.user_id,
        external_id=applicant.external_id,
        given_name=applicant.given_name,
        family_name=applicant.family_name,
        email=applicant.email or None,
        phone=applicant.phone,
        status=applicant.status.value,
        reviewer_id=applicant.reviewer_id,
        reviewer_lock_expires_at=applicant.reviewer_lock_expires_at.isoformat() if applicant.reviewer_lock_expires_at else None,
        submitted_at=applicant.submitted_at.isoformat() if applicant.submitted_at else None,
        reviewed_at=applicant.reviewed_at.isoformat() if applicant.reviewed_at else None,
        approved_at=applicant.approved_at.isoformat() if applicant.approved_at else None,
        credentialed_at=applicant.credentialed_at.isoformat() if applicant.credentialed_at else None,
        rejection_reason=applicant.rejection_reason,
        rejection_code=applicant.rejection_code,
        application_data=applicant.application_data,
        vetting_checks=applicant.vetting_checks,
        issued_credential_id=applicant.issued_credential_id,
        metadata=applicant.metadata,
        created_at=applicant.created_at.isoformat(),
        updated_at=applicant.updated_at.isoformat() if applicant.updated_at else None,
    )


def _application_to_response(application: ApplicantApplication) -> ApplicationResponse:
    return ApplicationResponse(
        id=application.id,
        applicant_id=application.applicant_id,
        organization_id=application.organization_id or None,
        reference_number=application.reference_number,
        application_template_id=application.application_template_id,
        credential_template_id=application.credential_template_id,
        form_data=application.form_data,
        integration_context=application.integration_context,
        status=application.status.value,
        claim_state=application.claim_state.value,
        claim_blocker=application.claim_blocker,
        created_at=application.created_at.isoformat(),
        submitted_at=application.submitted_at.isoformat() if application.submitted_at else None,
        reviewed_at=application.reviewed_at.isoformat() if application.reviewed_at else None,
        issued_at=application.issued_at.isoformat() if application.issued_at else None,
        updated_at=application.updated_at.isoformat(),
        credential_display_name=application.system_data.get("credential_display_name"),
        credential_offer_uri=application.system_data.get("credential_offer_uri"),
        offer_expires_at=application.system_data.get("offer_expires_at"),
        credential_offer_uris=application.system_data.get("credential_offer_uris") or {},
        credential_offer_labels=application.system_data.get("credential_offer_labels") or {},
    )


def _biometric_to_response(biometric: ApplicantBiometric) -> BiometricResponse:
    return BiometricResponse(
        id=biometric.id,
        applicant_id=biometric.applicant_id,
        modality=biometric.biometric_type,
        liveness_verified=biometric.is_live_capture,
        capture_device=biometric.capture_device_id,
        created_at=biometric.created_at.isoformat(),
    )


def _check_to_response(check: VettingCheck) -> VettingCheckResponse:
    return VettingCheckResponse(
        id=check.id,
        check_type=check.check_type.value,
        provider=check.external_provider,
        status=check.status.value,
        performed_by=check.performed_by,
        started_at=check.started_at.isoformat() if check.started_at else None,
        completed_at=check.completed_at.isoformat() if check.completed_at else None,
        created_at=check.created_at.isoformat(),
        updated_at=check.updated_at.isoformat(),
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
        application_template_id=application.application_template_id,
        credential_template_id=application.credential_template_id,
        form_data=application.form_data,
        integration_context=application.integration_context,
        status=application.status.value,
        claim_state=application.claim_state.value,
        claim_blocker=application.claim_blocker,
        created_at=application.created_at.isoformat(),
        submitted_at=application.submitted_at.isoformat() if application.submitted_at else None,
        reviewed_at=application.reviewed_at.isoformat() if application.reviewed_at else None,
        issued_at=application.issued_at.isoformat() if application.issued_at else None,
        updated_at=application.updated_at.isoformat(),
        credential_display_name=application.system_data.get("credential_display_name"),
        applicant_email=applicant.email if applicant else None,
        applicant_given_name=applicant.given_name if applicant else None,
        applicant_family_name=applicant.family_name if applicant else None,
        applicant_phone=applicant.phone if applicant else None,
        applicant_status=applicant.status.value if applicant else None,
        applicant_vetting_level=applicant.vetting_level.value if applicant else None,
        verification_results=applicant.verification_results if applicant else [],
    )


# =============================================================================
# MIP 0.3 HTTP Adapter
# =============================================================================

canonical_router = APIRouter(tags=["applicants"])


class ApproveApplicationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    notes: str | None = Field(None, max_length=4000)


class RejectApplicationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=2000)
    notes: str | None = Field(None, max_length=4000)


class WithdrawApplicationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(None, max_length=2000)


async def _self_application(
    application_id: str,
    user_id: str,
    repo: InMemoryApplicantRepository,
) -> tuple[ApplicantApplication, Applicant]:
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    applicant = await repo.get_by_id(application.applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant profile not found")
    if applicant.user_id != user_id and applicant.oidc_subject != user_id:
        logger.warning(
            "Applicant authorization denied user=%s application=%s org=%s",
            user_id,
            application_id,
            application.organization_id,
        )
        raise HTTPException(status_code=403, detail="Not authorized for this application")
    return application, applicant


async def _organization_application(
    organization_id: str,
    application_id: str,
    required_permission: str,
    x_user_id: str | None,
    x_organization_id: str | None,
    x_org_permissions: str | None,
    repo: InMemoryApplicantRepository,
) -> ApplicantApplication:
    user_id, header_org_id, permissions = _identity_headers(
        x_user_id,
        x_organization_id=x_organization_id,
        x_org_permissions=x_org_permissions,
    )
    application = await repo.get_application(application_id)
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    if application.organization_id != organization_id or header_org_id != organization_id:
        logger.warning(
            "Cross-organization applicant access denied user=%s application=%s requested_org=%s actual_org=%s",
            user_id,
            application_id,
            organization_id,
            application.organization_id,
        )
        raise HTTPException(status_code=403, detail="Not authorized for this organization")
    if required_permission not in permissions:
        logger.warning(
            "Applicant permission denied user=%s application=%s org=%s permission=%s",
            user_id,
            application_id,
            organization_id,
            required_permission,
        )
        raise HTTPException(status_code=403, detail="Action not authorized")
    return application


async def _require_reviewer_lock(
    application_id: str,
    user_id: str,
    repo: InMemoryApplicantRepository,
) -> ReviewerLock:
    lock = await repo.get_lock(application_id)
    if not lock or lock.reviewer_id != user_id:
        raise HTTPException(status_code=409, detail="An active reviewer lock held by the caller is required")
    return lock


@canonical_router.get("/v1/me/applicant-profile", response_model=ApplicantResponse, response_model_exclude_none=True)
async def get_my_profile(
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-ID"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicantResponse:
    user_id, _, _ = _identity_headers(x_user_id)
    organization_id = str(x_organization_id or "").strip()
    if not organization_id:
        raise HTTPException(status_code=422, detail="Authenticated organization context is required")
    applicant = await repo.get_by_user_id(user_id, organization_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant profile not found")
    return _to_response(applicant)


@canonical_router.patch("/v1/me/applicant-profile", response_model=ApplicantResponse, response_model_exclude_none=True)
async def upsert_my_profile(
    body: UpdateApplicantRequest,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_user_email: str | None = Header(default=None, alias="X-User-Email"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-ID"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicantResponse:
    user_id, _, _ = _identity_headers(x_user_id, x_user_email)
    organization_id = str(x_organization_id or "").strip()
    if not organization_id:
        raise HTTPException(status_code=422, detail="Authenticated organization context is required")
    applicant = await repo.get_by_user_id(user_id, organization_id)
    if not applicant and (body.email or x_user_email):
        applicant = await repo.get_by_email(str(body.email or x_user_email), organization_id)
        if applicant:
            applicant.user_id = user_id
            applicant.oidc_subject = user_id
    if not applicant:
        email = str(body.email or x_user_email or "").strip()
        if not email:
            raise HTTPException(status_code=422, detail="email is required when creating a profile")
        applicant = Applicant(
            organization_id=organization_id,
            user_id=user_id,
            oidc_subject=user_id,
            email=email,
        )
    if body.email is not None:
        applicant.email = str(body.email)
    if body.given_name is not None:
        applicant.given_name = body.given_name
    if body.family_name is not None:
        applicant.family_name = body.family_name
    if body.phone is not None:
        applicant.phone = body.phone
    if body.vetting_data is not None:
        applicant.vetting_data = body.vetting_data
    applicant.updated_at = datetime.now(timezone.utc)
    await repo.save(applicant)
    return _to_response(applicant)


@canonical_router.post("/v1/me/applicant-profile/biometrics", response_model=BiometricResponse, response_model_exclude_none=True)
async def enroll_my_profile_biometric(
    body: EnrollBiometricRequest,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-ID"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> BiometricResponse:
    user_id, _, _ = _identity_headers(x_user_id)
    organization_id = str(x_organization_id or "").strip()
    if not organization_id:
        raise HTTPException(status_code=422, detail="Authenticated organization context is required")
    applicant = await repo.get_by_user_id(user_id, organization_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant profile not found")
    biometric = ApplicantBiometric(
        applicant_id=applicant.id,
        biometric_type=body.biometric_type,
        template_data_base64=body.template_data_base64,
        image_data_base64=body.image_data_base64,
        is_live_capture=body.is_live_capture,
        capture_device_id=body.capture_device_id,
    )
    await repo.save_biometric(biometric)
    return _biometric_to_response(biometric)


@canonical_router.get("/v1/me/applications")
async def get_my_applications(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> dict[str, Any]:
    user_id, _, _ = _identity_headers(x_user_id)
    profiles = await repo.list_by_user_id(user_id)
    applications: list[ApplicantApplication] = []
    for profile in profiles:
        applications.extend(await repo.list_applications_for_applicant(profile.id))
    for application in applications:
        await _sync_application_issuance_state(application, repo)
    applications.sort(key=lambda item: item.updated_at, reverse=True)
    return {
        "items": [_application_to_response(item).model_dump(exclude_none=True) for item in applications[offset:offset + limit]],
        "total": len(applications),
        "limit": limit,
        "offset": offset,
    }


@canonical_router.get("/v1/issued-credentials/mine")
async def get_my_issued_credentials(
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> dict[str, Any]:
    user_id, _, _ = _identity_headers(x_user_id)
    profiles = await repo.list_by_user_id(user_id)
    records: list[dict[str, Any]] = []
    headers: dict[str, str] = {}
    api_key = _service_secret("ISSUANCE_API_KEY")
    if api_key:
        headers["X-API-Key"] = api_key
    async with httpx.AsyncClient(timeout=5.0) as client:
        for profile in profiles:
            response = await client.get(
                f"{ISSUANCE_SERVICE_URL}/v1/issued-credentials",
                params={
                    "organization_id": profile.organization_id,
                    "subject_id": profile.id,
                    "limit": 500,
                },
                headers=headers,
            )
            if response.status_code >= 500:
                raise HTTPException(status_code=503, detail="Credential inventory is temporarily unavailable")
            if response.status_code >= 400:
                continue
            payload = response.json()
            items = payload if isinstance(payload, list) else payload.get("items", payload.get("credentials", []))
            for item in items if isinstance(items, list) else []:
                if not isinstance(item, dict) or str(item.get("subject_id") or "") != profile.id:
                    continue
                records.append({
                    "id": item.get("id"),
                    "organization_id": item.get("organization_id"),
                    "application_id": item.get("application_id"),
                    "credential_template_id": item.get("credential_template_id"),
                    "credential_display_name": item.get("credential_display_name") or item.get("display_name"),
                    "credential_format": item.get("credential_format"),
                    "issuer_did": item.get("issuer_did"),
                    "issuer_name": item.get("issuer_name"),
                    "status": item.get("status"),
                    "issued_at": item.get("issued_at"),
                    "valid_until": item.get("valid_until"),
                    "image_url": item.get("image_url"),
                })
    if status:
        records = [item for item in records if str(item.get("status") or "").lower() == status.lower()]
    records.sort(key=lambda item: str(item.get("issued_at") or ""), reverse=True)
    return {"items": records[offset:offset + limit], "total": len(records), "limit": limit, "offset": offset}


@canonical_router.post("/v1/me/applications", response_model=ApplicationResponse, response_model_exclude_none=True)
async def post_my_application(
    body: CreateApplicationRequest,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-ID"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    return await create_application(
        body,
        x_user_id=x_user_id,
        x_organization_id=x_organization_id,
        repo=repo,
    )


@canonical_router.get("/v1/me/applications/{application_id}", response_model=EnrichedApplicationResponse, response_model_exclude_none=True)
async def get_my_application_detail(
    application_id: str,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> EnrichedApplicationResponse:
    user_id, _, _ = _identity_headers(x_user_id)
    application, applicant = await _self_application(application_id, user_id, repo)
    await _sync_application_issuance_state(application, repo)
    return _enriched_application_to_response(application, applicant)


@canonical_router.post("/v1/me/applications/{application_id}/submit", response_model=ApplicationResponse, response_model_exclude_none=True)
async def post_my_application_submit(
    application_id: str,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    user_id, _, _ = _identity_headers(x_user_id)
    application, _ = await _self_application(application_id, user_id, repo)
    return await submit_application(application.id, repo=repo)


@canonical_router.post("/v1/me/applications/{application_id}/withdraw", response_model=ApplicationResponse, response_model_exclude_none=True)
async def post_my_application_withdraw(
    application_id: str,
    body: WithdrawApplicationRequest | None = Body(default=None),
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    user_id, _, _ = _identity_headers(x_user_id)
    application, _ = await _self_application(application_id, user_id, repo)
    _set_application_status(application, ApplicationStatus.WITHDRAWN)
    application.system_data["withdrawal_reason"] = body.reason if body else None
    await repo.save_application(application)
    return _application_to_response(application)


@canonical_router.post("/v1/me/applications/{application_id}/claim", response_model=ApplicationResponse, response_model_exclude_none=True)
async def post_my_application_claim(
    application_id: str,
    body: ApplicationIssueRequest | None = Body(default=None),
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    user_id, _, _ = _identity_headers(x_user_id)
    application, _ = await _self_application(application_id, user_id, repo)
    return await issue_application(application.id, request=body, repo=repo)


@canonical_router.get("/v1/organizations/{organization_id}/applicants")
async def get_organization_applicant_queue(
    organization_id: str,
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
    x_org_permissions: str | None = Header(default=None, alias="X-Org-Permissions"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> dict[str, Any]:
    _, header_org_id, permissions = _identity_headers(
        x_user_id,
        x_organization_id=x_organization_id,
        x_org_permissions=x_org_permissions,
    )
    if header_org_id != organization_id or "application:review" not in permissions:
        raise HTTPException(status_code=403, detail="Action not authorized")
    status_filter = _parse_application_status(status) if status else None
    applications = await repo.list_applications_for_organization(organization_id, status_filter)
    applications.sort(key=lambda item: item.updated_at, reverse=True)
    return {
        "items": [_application_to_response(item).model_dump(exclude_none=True) for item in applications[offset:offset + limit]],
        "total": len(applications),
        "limit": limit,
        "offset": offset,
    }


async def _review_context(
    organization_id: str,
    application_id: str,
    permission: str,
    x_user_id: str | None,
    x_user_email: str | None,
    x_organization_id: str | None,
    x_org_permissions: str | None,
    repo: InMemoryApplicantRepository,
) -> tuple[ApplicantApplication, str, str]:
    application = await _organization_application(
        organization_id,
        application_id,
        permission,
        x_user_id,
        x_organization_id,
        x_org_permissions,
        repo,
    )
    user_id, _, _ = _identity_headers(x_user_id)
    return application, user_id, str(x_user_email or user_id)


@canonical_router.get("/v1/organizations/{organization_id}/applicants/{application_id}", response_model=EnrichedApplicationResponse, response_model_exclude_none=True)
async def get_organization_applicant_detail(
    organization_id: str,
    application_id: str,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
    x_org_permissions: str | None = Header(default=None, alias="X-Org-Permissions"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> EnrichedApplicationResponse:
    application = await _organization_application(
        organization_id, application_id, "application:review",
        x_user_id, x_organization_id, x_org_permissions, repo,
    )
    applicant = await repo.get_by_id(application.applicant_id)
    return _enriched_application_to_response(application, applicant)


@canonical_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/lock", response_model=LockResponse, response_model_exclude_none=True)
async def post_organization_applicant_lock(
    organization_id: str,
    application_id: str,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_user_email: str | None = Header(default=None, alias="X-User-Email"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
    x_org_permissions: str | None = Header(default=None, alias="X-Org-Permissions"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> LockResponse:
    _, user_id, reviewer_name = await _review_context(
        organization_id, application_id, "application:review", x_user_id,
        x_user_email, x_organization_id, x_org_permissions, repo,
    )
    acquired, lock = await repo.acquire_lock(application_id, user_id, reviewer_name)
    if not acquired:
        raise HTTPException(status_code=409, detail="APPLICANT_LOCKED")
    logger.info("Reviewer lock acquired user=%s application=%s org=%s", user_id, application_id, organization_id)
    return LockResponse(
        id=lock.lock_id if lock else None,
        applicant_id=application_id,
        organization_id=organization_id,
        holder_user_id=user_id,
        expires_at=lock.expires_at.isoformat() if lock else None,
        status="ACTIVE",
        created_at=lock.acquired_at.isoformat() if lock else None,
    )


@canonical_router.get("/v1/organizations/{organization_id}/applicants/{application_id}/lock", response_model=LockResponse, response_model_exclude_none=True)
async def get_organization_applicant_lock_status(
    organization_id: str,
    application_id: str,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
    x_org_permissions: str | None = Header(default=None, alias="X-Org-Permissions"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> LockResponse:
    await _organization_application(
        organization_id, application_id, "application:review",
        x_user_id, x_organization_id, x_org_permissions, repo,
    )
    lock = await repo.get_lock(application_id)
    return LockResponse(
        id=lock.lock_id if lock else None,
        applicant_id=application_id,
        organization_id=organization_id,
        holder_user_id=lock.reviewer_id if lock else None,
        expires_at=lock.expires_at.isoformat() if lock else None,
        status="ACTIVE" if lock else "AVAILABLE",
        created_at=lock.acquired_at.isoformat() if lock else None,
    )


@canonical_router.delete("/v1/organizations/{organization_id}/applicants/{application_id}/lock")
async def delete_organization_applicant_lock(
    organization_id: str,
    application_id: str,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
    x_org_permissions: str | None = Header(default=None, alias="X-Org-Permissions"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> dict[str, bool]:
    _, user_id, _ = await _review_context(
        organization_id, application_id, "application:review", x_user_id,
        None, x_organization_id, x_org_permissions, repo,
    )
    released = await repo.release_lock(application_id, user_id)
    if not released:
        raise HTTPException(status_code=403, detail="Only the lock holder may release this lock")
    return {"released": True}


async def _canonical_review_decision(
    organization_id: str,
    application_id: str,
    decision: str,
    notes: str | None,
    reason: str | None,
    http_request: Request,
    x_user_id: str | None,
    x_organization_id: str | None,
    x_org_permissions: str | None,
    repo: InMemoryApplicantRepository,
) -> ApplicationResponse:
    application = await _organization_application(
        organization_id, application_id, f"application:{decision}",
        x_user_id, x_organization_id, x_org_permissions, repo,
    )
    user_id, _, _ = _identity_headers(x_user_id)
    await _require_reviewer_lock(application_id, user_id, repo)
    response = await review_application(
        application.id,
        ApplicationReviewRequest(decision=decision, notes=notes, reason=reason),
        http_request=http_request,
        repo=repo,
    )
    logger.info("Application decision user=%s application=%s org=%s decision=%s", user_id, application_id, organization_id, decision)
    return response


@canonical_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/approve", response_model=ApplicationResponse, response_model_exclude_none=True)
async def post_organization_applicant_approve(
    organization_id: str,
    application_id: str,
    body: ApproveApplicationRequest,
    http_request: Request,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
    x_org_permissions: str | None = Header(default=None, alias="X-Org-Permissions"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    return await _canonical_review_decision(
        organization_id, application_id, "approve", body.notes, None,
        http_request, x_user_id, x_organization_id, x_org_permissions, repo,
    )


@canonical_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/reject", response_model=ApplicationResponse, response_model_exclude_none=True)
async def post_organization_applicant_reject(
    organization_id: str,
    application_id: str,
    body: RejectApplicationRequest,
    http_request: Request,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
    x_org_permissions: str | None = Header(default=None, alias="X-Org-Permissions"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    return await _canonical_review_decision(
        organization_id, application_id, "reject", body.notes, body.reason,
        http_request, x_user_id, x_organization_id, x_org_permissions, repo,
    )


@canonical_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/request-information", response_model=ApplicationResponse, response_model_exclude_none=True)
async def post_organization_applicant_request_information(
    organization_id: str,
    application_id: str,
    body: RequestInfoRequest,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
    x_org_permissions: str | None = Header(default=None, alias="X-Org-Permissions"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    application = await _organization_application(
        organization_id, application_id, "application:review",
        x_user_id, x_organization_id, x_org_permissions, repo,
    )
    user_id, _, _ = _identity_headers(x_user_id)
    await _require_reviewer_lock(application_id, user_id, repo)
    return await request_info(application.id, body, repo=repo)


@canonical_router.get("/v1/organizations/{organization_id}/applicants/{application_id}/checks", response_model=list[VettingCheckResponse], response_model_exclude_none=True)
async def get_organization_applicant_checks(
    organization_id: str,
    application_id: str,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
    x_org_permissions: str | None = Header(default=None, alias="X-Org-Permissions"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> list[VettingCheckResponse]:
    await _organization_application(
        organization_id, application_id, "application:review",
        x_user_id, x_organization_id, x_org_permissions, repo,
    )
    return await list_checks(application_id, repo=repo)


async def _canonical_check_action(
    organization_id: str,
    application_id: str,
    check_id: str,
    body: CompleteCheckRequest | None,
    x_user_id: str | None,
    x_organization_id: str | None,
    x_org_permissions: str | None,
    repo: InMemoryApplicantRepository,
) -> VettingCheckResponse:
    await _organization_application(
        organization_id, application_id, "application:review",
        x_user_id, x_organization_id, x_org_permissions, repo,
    )
    user_id, _, _ = _identity_headers(x_user_id)
    await _require_reviewer_lock(application_id, user_id, repo)
    check = await repo.get_check(check_id)
    if not check or check.application_id != application_id:
        raise HTTPException(status_code=404, detail="Vetting check not found")
    if body is None:
        return await start_check(check_id, repo=repo)
    body.performed_by = user_id
    return await complete_check(check_id, body, repo=repo)


@canonical_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/checks/{check_id}/start", response_model=VettingCheckResponse, response_model_exclude_none=True)
async def post_organization_applicant_check_start(
    organization_id: str,
    application_id: str,
    check_id: str,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
    x_org_permissions: str | None = Header(default=None, alias="X-Org-Permissions"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> VettingCheckResponse:
    return await _canonical_check_action(
        organization_id, application_id, check_id, None,
        x_user_id, x_organization_id, x_org_permissions, repo,
    )


@canonical_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/checks/{check_id}/complete", response_model=VettingCheckResponse, response_model_exclude_none=True)
async def post_organization_applicant_check_complete(
    organization_id: str,
    application_id: str,
    check_id: str,
    body: CompleteCheckRequest,
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
    x_org_permissions: str | None = Header(default=None, alias="X-Org-Permissions"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> VettingCheckResponse:
    return await _canonical_check_action(
        organization_id, application_id, check_id, body,
        x_user_id, x_organization_id, x_org_permissions, repo,
    )


@canonical_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/issue", response_model=ApplicationResponse, response_model_exclude_none=True)
async def post_organization_applicant_issue(
    organization_id: str,
    application_id: str,
    body: ApplicationIssueRequest | None = Body(default=None),
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
    x_org_permissions: str | None = Header(default=None, alias="X-Org-Permissions"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    application = await _organization_application(
        organization_id, application_id, "issuance:initiate",
        x_user_id, x_organization_id, x_org_permissions, repo,
    )
    return await issue_application(application.id, request=body, repo=repo)


@canonical_router.post("/v1/organizations/{organization_id}/applicants/{application_id}/withdraw", response_model=ApplicationResponse, response_model_exclude_none=True)
async def post_organization_applicant_withdraw(
    organization_id: str,
    application_id: str,
    body: WithdrawApplicationRequest | None = Body(default=None),
    x_user_id: str | None = Header(default=None, alias="X-User-Id"),
    x_organization_id: str | None = Header(default=None, alias="X-Organization-Id"),
    x_org_permissions: str | None = Header(default=None, alias="X-Org-Permissions"),
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicationResponse:
    application = await _organization_application(
        organization_id, application_id, "application:review",
        x_user_id, x_organization_id, x_org_permissions, repo,
    )
    _force_application_status(application, ApplicationStatus.WITHDRAWN)
    application.system_data["withdrawal_reason"] = body.reason if body else None
    await repo.save_application(application)
    return _application_to_response(application)


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo
    logger.info(f"Starting {SERVICE_NAME}...")
    _repo = InMemoryApplicantRepository()
    
    # Initialize Cedar engine for approval policies
    from marty_common import CedarEngine
    app.state.cedar_engine = CedarEngine.with_defaults()
    logger.info("Cedar engine initialized for approval policies")
    
    yield
    logger.info(f"Shutting down {SERVICE_NAME}...")


def create_app() -> FastAPI:
    return create_service_app(
        title="Applicant Service",
        description="Applicant vetting and management service",
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[canonical_router],
    )


app = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
