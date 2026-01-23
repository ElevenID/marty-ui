"""
Data models for Travel Document Service

Defines document types per ICAO specifications:
- eMRTD (ePassport) - ICAO Doc 9303
- DTC (Digital Travel Credential) - ICAO DTC Specification
- mDL (Mobile Driving License) - ISO/IEC 18013-5
- National ID
- Visa
- Residence Permit
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator


class DocumentType(str, Enum):
    """Travel document types supported by the system."""
    
    EMRTD = "eMRTD"  # Electronic Machine Readable Travel Document (ePassport)
    DTC = "DTC"  # Digital Travel Credential
    MDL = "mDL"  # Mobile Driving License
    NATIONAL_ID = "National ID"
    VISA = "Visa"
    RESIDENCE_PERMIT = "Residence Permit"


class DocumentStatus(str, Enum):
    """Document lifecycle status."""
    
    DRAFT = "draft"  # Created but not yet issued
    ACTIVE = "active"  # Issued and valid
    SUSPENDED = "suspended"  # Temporarily invalid
    REVOKED = "revoked"  # Permanently invalid
    EXPIRED = "expired"  # Past expiration date


class AuditEventType(str, Enum):
    """Types of audit events for documents."""
    
    CREATED = "created"
    ISSUED = "issued"
    VIEWED = "viewed"
    VERIFIED = "verified"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    REINSTATED = "reinstated"
    EXPIRED = "expired"
    UPDATED = "updated"
    DELETED = "deleted"


class ActorType(str, Enum):
    """Types of actors that can perform actions on documents."""
    
    SYSTEM = "system"
    OPERATOR = "operator"
    API = "api"
    AUTOMATED = "automated"


class TravelDocument(BaseModel):
    """
    Travel Document model representing an issued credential.
    
    Follows ICAO Doc 9303 and ISO/IEC 18013-5 specifications.
    """
    
    id: UUID = Field(default_factory=uuid4)
    document_type: DocumentType
    document_number: str = Field(..., min_length=1, max_length=100)
    
    # Holder information
    holder_name: str = Field(..., min_length=1, max_length=255)
    holder_given_name: str | None = None
    holder_family_name: str | None = None
    holder_dob: date
    nationality: str = Field(..., min_length=3, max_length=3)  # ISO 3166-1 alpha-3
    
    # Document validity
    issued_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    status: DocumentStatus = DocumentStatus.ACTIVE
    
    # Issuer information
    issuer_id: str = Field(..., min_length=1, max_length=100)
    issuing_authority: str | None = None
    issuing_country: str = Field(..., min_length=3, max_length=3)  # ISO 3166-1 alpha-3
    
    # Cryptographic binding
    signer_cert_id: UUID | None = None  # Reference to DSC key
    signature: bytes | None = None
    signed_data: bytes | None = None
    
    # Additional metadata
    metadata: dict[str, Any] = Field(default_factory=dict)
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    @validator("nationality", "issuing_country")
    @classmethod
    def validate_country_code(cls, v: str) -> str:
        """Validate ISO 3166-1 alpha-3 country code format."""
        if not v.isalpha() or len(v) != 3:
            raise ValueError("Country code must be 3 letters (ISO 3166-1 alpha-3)")
        return v.upper()
    
    @validator("expires_at")
    @classmethod
    def validate_expiry(cls, v: datetime, values: dict) -> datetime:
        """Ensure expiry is after issue date."""
        issued_at = values.get("issued_at", datetime.utcnow())
        if v <= issued_at:
            raise ValueError("Expiration date must be after issue date")
        return v
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            date: lambda v: v.isoformat(),
            bytes: lambda v: v.hex() if v else None,
            UUID: str,
        }


class DocumentAuditLog(BaseModel):
    """
    Audit log entry for document lifecycle events.
    
    Provides full traceability for compliance and security.
    """
    
    id: UUID = Field(default_factory=uuid4)
    document_id: UUID
    event_type: AuditEventType
    
    # Actor information
    actor_id: str = Field(..., min_length=1, max_length=100)
    actor_type: ActorType
    
    # Event details
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    details: dict[str, Any] = Field(default_factory=dict)
    
    # Request context
    ip_address: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: str,
        }


# ==================== Request Models ====================

class IssueDocumentRequest(BaseModel):
    """Request to issue a new travel document."""
    
    document_type: DocumentType
    document_number: str = Field(..., min_length=1, max_length=100)
    
    # Holder information
    holder_name: str
    holder_given_name: str | None = None
    holder_family_name: str | None = None
    holder_dob: date
    nationality: str = Field(..., min_length=3, max_length=3)
    
    # Document validity
    validity_years: int = Field(default=10, ge=1, le=20)
    
    # Issuer information
    issuer_id: str = "marty_trust_services"
    issuing_authority: str | None = None
    issuing_country: str = Field(default="USA", min_length=3, max_length=3)
    
    # Signing key (optional - will use default if not provided)
    signer_cert_id: UUID | None = None
    
    # Additional metadata
    metadata: dict[str, Any] = Field(default_factory=dict)


class UpdateDocumentRequest(BaseModel):
    """Request to update a travel document."""
    
    status: DocumentStatus | None = None
    metadata: dict[str, Any] | None = None
    reason: str | None = None  # Required for status changes


class DocumentSearchRequest(BaseModel):
    """Request to search for documents."""
    
    document_type: DocumentType | None = None
    status: DocumentStatus | None = None
    holder_name: str | None = None
    nationality: str | None = None
    issuing_country: str | None = None
    issued_after: datetime | None = None
    issued_before: datetime | None = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


# ==================== Response Models ====================

class DocumentResponse(BaseModel):
    """Response containing a single document."""
    
    document: TravelDocument
    
    class Config:
        json_encoders = TravelDocument.Config.json_encoders


class DocumentListResponse(BaseModel):
    """Response containing a list of documents."""
    
    documents: list[TravelDocument]
    total: int
    limit: int
    offset: int
    
    class Config:
        json_encoders = TravelDocument.Config.json_encoders


class AuditLogResponse(BaseModel):
    """Response containing audit log entries."""
    
    entries: list[DocumentAuditLog]
    total: int
    document_id: UUID | None = None
    
    class Config:
        json_encoders = DocumentAuditLog.Config.json_encoders


class DocumentStatsResponse(BaseModel):
    """Response containing document statistics."""
    
    total_documents: int
    by_type: dict[str, int]
    by_status: dict[str, int]
    by_country: dict[str, int]
    issued_today: int
    issued_this_week: int
    issued_this_month: int
    expiring_soon: int  # Within 30 days
