"""
Document Service API - FastAPI Router

REST API endpoints for travel document management with full audit logging.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from .database import init_document_db
from .models import (
    ActorType,
    AuditLogResponse,
    DocumentListResponse,
    DocumentResponse,
    DocumentStatsResponse,
    DocumentStatus,
    DocumentType,
    IssueDocumentRequest,
    UpdateDocumentRequest,
)
from .service import DocumentService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/documents", tags=["Documents"])

# Global service instance
_document_service: DocumentService | None = None


def get_document_service() -> DocumentService:
    """Get or create the document service instance."""
    global _document_service
    if _document_service is None:
        _document_service = DocumentService()
    return _document_service


@router.on_event("startup")
async def startup_event() -> None:
    """Initialize document database on API startup."""
    await init_document_db()
    logger.info("Document service initialized")


# ==================== Document Endpoints ====================

@router.get("/types", response_model=list[dict[str, str]])
async def get_document_types() -> list[dict[str, str]]:
    """
    Get all supported document types.
    
    Returns:
        List of document types with their descriptions.
    """
    return [
        {"value": dt.value, "label": dt.value, "description": _get_type_description(dt)}
        for dt in DocumentType
    ]


@router.get("/stats", response_model=DocumentStatsResponse)
async def get_document_stats() -> DocumentStatsResponse:
    """
    Get document statistics.
    
    Returns:
        Statistics about documents in the system.
    """
    service = get_document_service()
    return await service.get_stats()


@router.get("", response_model=DocumentListResponse)
async def list_documents(
    document_type: DocumentType | None = Query(None, description="Filter by document type"),
    status: DocumentStatus | None = Query(None, description="Filter by status"),
    nationality: str | None = Query(None, description="Filter by holder nationality (ISO 3166-1 alpha-3)"),
    issuing_country: str | None = Query(None, description="Filter by issuing country (ISO 3166-1 alpha-3)"),
    limit: int = Query(50, ge=1, le=200, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Results offset for pagination"),
) -> DocumentListResponse:
    """
    List all documents with optional filters.
    
    Args:
        document_type: Filter by document type
        status: Filter by document status
        nationality: Filter by holder nationality
        issuing_country: Filter by issuing country
        limit: Maximum number of results
        offset: Pagination offset
        
    Returns:
        List of documents with pagination info.
    """
    service = get_document_service()
    return await service.list_documents(
        document_type=document_type,
        status=status,
        nationality=nationality,
        issuing_country=issuing_country,
        limit=limit,
        offset=offset,
    )


# ==================== Applicant Integration Endpoints ====================

@router.get("/approved-applicants")
async def get_approved_applicants(
    limit: int = Query(50, ge=1, le=200, description="Maximum number of results"),
) -> list[dict]:
    """
    Get approved applicants ready for document issuance.

    Returns applications that have passed vetting and are ready
    for travel document issuance.

    Args:
        limit: Maximum number of results

    Returns:
        List of approved applications with applicant details
    """
    try:
        from integration import get_applicant_document_integration
        integration = get_applicant_document_integration()
        return await integration.get_approved_applications_for_issuance(limit)
    except ImportError:
        logger.warning("Applicant integration not available")
        return []


@router.post("/issue-from-application", status_code=201)
async def issue_from_application(
    application_id: str = Query(..., description="UUID of the approved application"),
    document_number: str = Query(..., description="Document number to assign"),
    request: Request = None,
) -> dict:
    """
    Issue a document from an approved application.

    This endpoint issues a travel document using holder information
    from a vetted and approved application. The applicant must have:
    - Completed all required vetting checks
    - Application in APPROVED status
    - Biometrics enrolled

    Args:
        application_id: UUID of the approved application
        document_number: Document number to assign

    Returns:
        Issued document details

    Raises:
        400: Application not approved or validation failed
        404: Application not found
    """
    try:
        from uuid import UUID as UUIDType
        from integration import get_applicant_document_integration, IssueFromApplicationRequest

        integration = get_applicant_document_integration()

        client_host = request.client.host if request and request.client else None
        actor_id = request.headers.get("X-Actor-ID", "api_user") if request else "api_user"

        issue_request = IssueFromApplicationRequest(
            application_id=UUIDType(application_id),
            document_number=document_number,
        )

        result = await integration.issue_document_from_application(
            request=issue_request,
            actor_id=actor_id,
            ip_address=client_host,
        )

        return result

    except ImportError:
        raise HTTPException(status_code=501, detail="Applicant integration not available")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/verify-biometrics")
async def verify_biometrics_at_issuance(
    application_id: str = Query(..., description="UUID of the application"),
    biometric_type: str = Query("FACIAL", description="Type of biometric"),
    request: Request = None,
) -> dict:
    """
    Verify applicant biometrics at document issuance time.

    Compares newly captured biometric data against the enrolled template
    to ensure the person collecting the document matches the applicant.

    Args:
        application_id: UUID of the application
        biometric_type: Type of biometric (FACIAL, FINGERPRINT, IRIS)

    Returns:
        Verification result with match status and score
    """
    try:
        from uuid import UUID as UUIDType
        from integration import get_applicant_document_integration

        integration = get_applicant_document_integration()

        # In production, biometric data would come from request body
        # For now, use mock data for the demo
        mock_biometric_data = b"mock_biometric_template"

        match_result, score = await integration.verify_biometrics_at_issuance(
            application_id=UUIDType(application_id),
            captured_biometric_data=mock_biometric_data,
            biometric_type=biometric_type,
        )

        return {
            "application_id": application_id,
            "biometric_type": biometric_type,
            "match": match_result,
            "score": score,
            "threshold": 0.8,
        }

    except ImportError:
        raise HTTPException(status_code=501, detail="Applicant integration not available")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{document_id}", response_model=DocumentResponse)
async def get_document(
    document_id: str,
    request: Request,
) -> DocumentResponse:
    """
    Get a document by ID.
    
    Args:
        document_id: UUID of the document
        
    Returns:
        The requested document.
        
    Raises:
        404: Document not found
    """
    service = get_document_service()
    
    # Get client info for audit
    client_host = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    document = await service.get_document(
        document_id=document_id,
        actor_id="api_user",
        actor_type=ActorType.API,
    )
    
    if not document:
        raise HTTPException(status_code=404, detail=f"Document {document_id} not found")
    
    return DocumentResponse(document=document)


@router.post("", response_model=DocumentResponse, status_code=201)
async def issue_document(
    request_body: IssueDocumentRequest,
    request: Request,
) -> DocumentResponse:
    """
    Issue a new travel document.
    
    Args:
        request_body: Document issuance request
        
    Returns:
        Newly issued document.
        
    Raises:
        400: Invalid request or duplicate document number
    """
    service = get_document_service()
    
    # Get client info for audit
    client_host = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    try:
        document = await service.issue_document(
            request=request_body,
            actor_id="api_user",
            actor_type=ActorType.OPERATOR,
            ip_address=client_host,
            user_agent=user_agent,
        )
        return DocumentResponse(document=document)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"Error issuing document: {e}")
        raise HTTPException(status_code=500, detail=f"Error issuing document: {e!s}")


@router.patch("/{document_id}/status", response_model=DocumentResponse)
async def update_document_status(
    document_id: str,
    request_body: UpdateDocumentRequest,
    request: Request,
) -> DocumentResponse:
    """
    Update a document's status.
    
    Args:
        document_id: UUID of the document
        request_body: Status update request
        
    Returns:
        Updated document.
        
    Raises:
        400: Invalid request
        404: Document not found
    """
    if not request_body.status:
        raise HTTPException(status_code=400, detail="Status is required")
    
    if not request_body.reason:
        raise HTTPException(status_code=400, detail="Reason is required for status changes")
    
    service = get_document_service()
    
    # Get client info for audit
    client_host = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    document = await service.update_document_status(
        document_id=document_id,
        new_status=request_body.status,
        reason=request_body.reason,
        actor_id="api_user",
        actor_type=ActorType.OPERATOR,
        ip_address=client_host,
        user_agent=user_agent,
    )
    
    if not document:
        raise HTTPException(status_code=404, detail=f"Document {document_id} not found")
    
    return DocumentResponse(document=document)


@router.delete("/{document_id}", status_code=204, response_class=Response)
async def delete_document(
    document_id: str,
    reason: str = Query(..., description="Reason for deletion"),
    request: Request = None,
):
    """
    Delete a document.
    
    Args:
        document_id: UUID of the document
        reason: Reason for deletion (required for audit)
        
    Raises:
        404: Document not found
    """
    service = get_document_service()
    
    # Get client info for audit
    client_host = request.client.host if request and request.client else None
    user_agent = request.headers.get("user-agent") if request else None
    
    success = await service.delete_document(
        document_id=document_id,
        reason=reason,
        actor_id="api_user",
        actor_type=ActorType.OPERATOR,
        ip_address=client_host,
        user_agent=user_agent,
    )
    
    if not success:
        raise HTTPException(status_code=404, detail=f"Document {document_id} not found")


# ==================== Audit Log Endpoints ====================

@router.get("/{document_id}/audit", response_model=AuditLogResponse)
async def get_document_audit_log(
    document_id: str,
    limit: int = Query(100, ge=1, le=500, description="Maximum number of results"),
    offset: int = Query(0, ge=0, description="Results offset for pagination"),
) -> AuditLogResponse:
    """
    Get audit log entries for a document.
    
    Args:
        document_id: UUID of the document
        limit: Maximum number of results
        offset: Pagination offset
        
    Returns:
        Audit log entries for the document.
    """
    service = get_document_service()
    entries, total = await service.get_document_audit_log(
        document_id=document_id,
        limit=limit,
        offset=offset,
    )
    
    return AuditLogResponse(
        entries=entries,
        total=total,
        document_id=UUID(document_id),
    )


# ==================== Helper Functions ====================

def _get_type_description(doc_type: DocumentType) -> str:
    """Get a description for a document type."""
    descriptions = {
        DocumentType.EMRTD: "Electronic Machine Readable Travel Document (ePassport) per ICAO Doc 9303",
        DocumentType.DTC: "Digital Travel Credential per ICAO DTC Specification",
        DocumentType.MDL: "Mobile Driving License per ISO/IEC 18013-5",
        DocumentType.NATIONAL_ID: "National Identity Document",
        DocumentType.VISA: "Travel Visa Document",
        DocumentType.RESIDENCE_PERMIT: "Residence Permit Document",
    }
    return descriptions.get(doc_type, "")
