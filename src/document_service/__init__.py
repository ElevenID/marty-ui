"""
Document Service Package

Provides travel document issuance and management with full audit logging.
Supports eMRTD (ePassport), DTC, mDL, National ID, Visa, and Residence Permit.
"""

from .models import (
    DocumentType,
    DocumentStatus,
    TravelDocument,
    DocumentAuditLog,
    IssueDocumentRequest,
    DocumentResponse,
    DocumentListResponse,
    AuditLogResponse,
)
from .database import init_document_db, get_db_connection
from .service import DocumentService
from .api import router as document_router

__all__ = [
    "DocumentType",
    "DocumentStatus",
    "TravelDocument",
    "DocumentAuditLog",
    "IssueDocumentRequest",
    "DocumentResponse",
    "DocumentListResponse",
    "AuditLogResponse",
    "init_document_db",
    "get_db_connection",
    "DocumentService",
    "document_router",
]
