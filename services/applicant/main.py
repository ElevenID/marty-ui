"""
Applicant Service

Manages applicants and their vetting/verification status.

Ports:
- HTTP API on port 8006
"""

from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "applicant-service"
SERVICE_PORT = int(os.environ.get("APPLICANT_SERVICE_PORT", "8006"))


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


# =============================================================================
# Application Layer
# =============================================================================

class InMemoryApplicantRepository:
    """In-memory repository for development."""
    
    def __init__(self):
        self._applicants: dict[str, Applicant] = {}
    
    async def save(self, applicant: Applicant) -> None:
        self._applicants[applicant.id] = applicant
    
    async def get_by_id(self, applicant_id: str) -> Applicant | None:
        return self._applicants.get(applicant_id)
    
    async def get_by_email(self, email: str, org_id: str) -> Applicant | None:
        for a in self._applicants.values():
            if a.email == email and a.organization_id == org_id:
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
        vetting_level=VettingLevel(request.vetting_level),
    )
    await repo.save(applicant)
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


@router.get("/{applicant_id}", response_model=ApplicantResponse)
async def get_applicant(
    applicant_id: str,
    repo: InMemoryApplicantRepository = Depends(get_repo),
) -> ApplicantResponse:
    """Get an applicant by ID."""
    applicant = await repo.get_by_id(applicant_id)
    if not applicant:
        raise HTTPException(status_code=404, detail="Applicant not found")
    return _to_response(applicant)


@router.patch("/{applicant_id}", response_model=ApplicantResponse)
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


@router.post("/{applicant_id}/review", response_model=ApplicantResponse)
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
    elif request.decision == "reject":
        if not request.reason:
            raise HTTPException(status_code=400, detail="Rejection reason required")
        applicant.reject(request.reason)
    else:
        raise HTTPException(status_code=400, detail="Invalid decision")
    
    await repo.save(applicant)
    return _to_response(applicant)


@router.post("/{applicant_id}/revoke")
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
