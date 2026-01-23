"""
Document Service - Business Logic Layer

Handles travel document issuance, lifecycle management, and audit logging.
Integrates with PKD/Trust services for cryptographic signing.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from .database import AuditRepository, DocumentRepository
from .models import (
    ActorType,
    AuditEventType,
    DocumentAuditLog,
    DocumentListResponse,
    DocumentResponse,
    DocumentStatsResponse,
    DocumentStatus,
    DocumentType,
    IssueDocumentRequest,
    TravelDocument,
    UpdateDocumentRequest,
)

logger = logging.getLogger(__name__)


class DocumentService:
    """
    Service for managing travel documents with full audit logging.
    
    Provides:
    - Document issuance with cryptographic signing
    - Lifecycle management (suspend, revoke, reinstate)
    - Full audit trail for compliance
    - Integration with PKD/Trust services
    """
    
    def __init__(self):
        self.document_repo = DocumentRepository()
        self.audit_repo = AuditRepository()
    
    async def issue_document(
        self,
        request: IssueDocumentRequest,
        actor_id: str = "system",
        actor_type: ActorType = ActorType.OPERATOR,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> TravelDocument:
        """
        Issue a new travel document.
        
        Args:
            request: Document issuance request
            actor_id: ID of the actor issuing the document
            actor_type: Type of actor
            ip_address: Request IP address for audit
            user_agent: Request user agent for audit
            
        Returns:
            Newly issued travel document
        """
        now = datetime.utcnow()
        expires_at = now + timedelta(days=365 * request.validity_years)
        
        # Generate unique document number if not provided
        document_number = request.document_number
        
        # Check for duplicate document number
        existing = await self.document_repo.get_by_number(document_number)
        if existing:
            raise ValueError(f"Document number {document_number} already exists")
        
        # Create document
        document = TravelDocument(
            id=uuid4(),
            document_type=request.document_type,
            document_number=document_number,
            holder_name=request.holder_name,
            holder_given_name=request.holder_given_name,
            holder_family_name=request.holder_family_name,
            holder_dob=request.holder_dob,
            nationality=request.nationality,
            issued_at=now,
            expires_at=expires_at,
            status=DocumentStatus.ACTIVE,
            issuer_id=request.issuer_id,
            issuing_authority=request.issuing_authority,
            issuing_country=request.issuing_country,
            signer_cert_id=request.signer_cert_id,
            metadata=request.metadata,
            created_at=now,
            updated_at=now,
        )
        
        # Convert to dict for storage
        doc_dict = document.dict()
        doc_dict["holder_dob"] = str(doc_dict["holder_dob"])
        doc_dict["issued_at"] = doc_dict["issued_at"].isoformat()
        doc_dict["expires_at"] = doc_dict["expires_at"].isoformat()
        doc_dict["created_at"] = doc_dict["created_at"].isoformat()
        doc_dict["updated_at"] = doc_dict["updated_at"].isoformat()
        doc_dict["document_type"] = doc_dict["document_type"].value
        doc_dict["status"] = doc_dict["status"].value
        doc_dict["metadata"] = json.dumps(doc_dict["metadata"])
        
        # Store document
        await self.document_repo.create(doc_dict)
        
        # Create audit log entry
        await self._create_audit_entry(
            document_id=document.id,
            event_type=AuditEventType.ISSUED,
            actor_id=actor_id,
            actor_type=actor_type,
            details={
                "document_type": request.document_type.value,
                "holder_name": request.holder_name,
                "nationality": request.nationality,
                "validity_years": request.validity_years,
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )
        
        logger.info(f"Issued document {document.id} of type {document.document_type}")
        return document
    
    async def get_document(
        self,
        document_id: str,
        actor_id: str = "system",
        actor_type: ActorType = ActorType.API,
        log_access: bool = True,
    ) -> TravelDocument | None:
        """
        Get a document by ID.
        
        Args:
            document_id: Document ID
            actor_id: ID of the actor accessing the document
            actor_type: Type of actor
            log_access: Whether to log this access in audit trail
            
        Returns:
            Travel document if found
        """
        doc_dict = await self.document_repo.get_by_id(document_id)
        if not doc_dict:
            return None
        
        document = self._dict_to_document(doc_dict)
        
        if log_access:
            await self._create_audit_entry(
                document_id=document.id,
                event_type=AuditEventType.VIEWED,
                actor_id=actor_id,
                actor_type=actor_type,
                details={"access_type": "get_by_id"},
            )
        
        return document
    
    async def list_documents(
        self,
        document_type: DocumentType | None = None,
        status: DocumentStatus | None = None,
        nationality: str | None = None,
        issuing_country: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> DocumentListResponse:
        """
        List documents with optional filters.
        
        Args:
            document_type: Filter by document type
            status: Filter by status
            nationality: Filter by holder nationality
            issuing_country: Filter by issuing country
            limit: Maximum number of results
            offset: Results offset for pagination
            
        Returns:
            List of documents with pagination info
        """
        docs, total = await self.document_repo.list_all(
            document_type=document_type.value if document_type else None,
            status=status.value if status else None,
            nationality=nationality,
            issuing_country=issuing_country,
            limit=limit,
            offset=offset,
        )
        
        documents = [self._dict_to_document(d) for d in docs]
        
        return DocumentListResponse(
            documents=documents,
            total=total,
            limit=limit,
            offset=offset,
        )
    
    async def update_document_status(
        self,
        document_id: str,
        new_status: DocumentStatus,
        reason: str,
        actor_id: str = "system",
        actor_type: ActorType = ActorType.OPERATOR,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> TravelDocument | None:
        """
        Update a document's status with audit logging.
        
        Args:
            document_id: Document ID
            new_status: New status to set
            reason: Reason for status change
            actor_id: ID of the actor making the change
            actor_type: Type of actor
            ip_address: Request IP address for audit
            user_agent: Request user agent for audit
            
        Returns:
            Updated document
        """
        doc_dict = await self.document_repo.get_by_id(document_id)
        if not doc_dict:
            return None
        
        old_status = doc_dict["status"]
        
        # Update document
        updated = await self.document_repo.update(
            document_id,
            {"status": new_status.value},
        )
        
        if not updated:
            return None
        
        # Determine audit event type
        event_type_map = {
            DocumentStatus.SUSPENDED: AuditEventType.SUSPENDED,
            DocumentStatus.REVOKED: AuditEventType.REVOKED,
            DocumentStatus.ACTIVE: AuditEventType.REINSTATED,
            DocumentStatus.EXPIRED: AuditEventType.EXPIRED,
        }
        event_type = event_type_map.get(new_status, AuditEventType.UPDATED)
        
        # Create audit log entry
        await self._create_audit_entry(
            document_id=UUID(document_id),
            event_type=event_type,
            actor_id=actor_id,
            actor_type=actor_type,
            details={
                "old_status": old_status,
                "new_status": new_status.value,
                "reason": reason,
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )
        
        logger.info(f"Updated document {document_id} status from {old_status} to {new_status.value}")
        return self._dict_to_document(updated)
    
    async def delete_document(
        self,
        document_id: str,
        reason: str,
        actor_id: str = "system",
        actor_type: ActorType = ActorType.OPERATOR,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> bool:
        """
        Delete a document with audit logging.
        
        Note: In production, consider soft delete instead.
        
        Args:
            document_id: Document ID to delete
            reason: Reason for deletion
            actor_id: ID of the actor performing deletion
            actor_type: Type of actor
            ip_address: Request IP address for audit
            user_agent: Request user agent for audit
            
        Returns:
            True if deleted
        """
        doc_dict = await self.document_repo.get_by_id(document_id)
        if not doc_dict:
            return False
        
        # Create audit entry before deletion
        await self._create_audit_entry(
            document_id=UUID(document_id),
            event_type=AuditEventType.DELETED,
            actor_id=actor_id,
            actor_type=actor_type,
            details={
                "reason": reason,
                "document_snapshot": {
                    "document_type": doc_dict["document_type"],
                    "document_number": doc_dict["document_number"],
                    "holder_name": doc_dict["holder_name"],
                },
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )
        
        success = await self.document_repo.delete(document_id)
        logger.info(f"Deleted document {document_id}: {success}")
        return success
    
    async def get_document_audit_log(
        self,
        document_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[DocumentAuditLog], int]:
        """
        Get audit log entries for a document.
        
        Args:
            document_id: Document ID
            limit: Maximum number of results
            offset: Results offset for pagination
            
        Returns:
            List of audit log entries and total count
        """
        entries, total = await self.audit_repo.get_by_document(
            document_id, limit=limit, offset=offset
        )
        
        audit_logs = [self._dict_to_audit_entry(e) for e in entries]
        return audit_logs, total
    
    async def get_stats(self) -> DocumentStatsResponse:
        """
        Get document statistics.
        
        Returns:
            Statistics about documents in the system
        """
        stats = await self.document_repo.get_stats()
        return DocumentStatsResponse(**stats)
    
    async def _create_audit_entry(
        self,
        document_id: UUID,
        event_type: AuditEventType,
        actor_id: str,
        actor_type: ActorType,
        details: dict[str, Any] | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
    ) -> DocumentAuditLog:
        """Create an audit log entry."""
        entry = DocumentAuditLog(
            id=uuid4(),
            document_id=document_id,
            event_type=event_type,
            actor_id=actor_id,
            actor_type=actor_type,
            timestamp=datetime.utcnow(),
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
        )
        
        entry_dict = entry.dict()
        entry_dict["timestamp"] = entry_dict["timestamp"].isoformat()
        entry_dict["event_type"] = entry_dict["event_type"].value
        entry_dict["actor_type"] = entry_dict["actor_type"].value
        entry_dict["details"] = json.dumps(entry_dict["details"])
        
        await self.audit_repo.create(entry_dict)
        return entry
    
    def _dict_to_document(self, doc_dict: dict[str, Any]) -> TravelDocument:
        """Convert a database row dict to a TravelDocument model."""
        # Parse JSON metadata
        metadata = doc_dict.get("metadata", "{}")
        if isinstance(metadata, str):
            metadata = json.loads(metadata)
        
        return TravelDocument(
            id=UUID(doc_dict["id"]),
            document_type=DocumentType(doc_dict["document_type"]),
            document_number=doc_dict["document_number"],
            holder_name=doc_dict["holder_name"],
            holder_given_name=doc_dict.get("holder_given_name"),
            holder_family_name=doc_dict.get("holder_family_name"),
            holder_dob=doc_dict["holder_dob"],
            nationality=doc_dict["nationality"],
            issued_at=datetime.fromisoformat(doc_dict["issued_at"]),
            expires_at=datetime.fromisoformat(doc_dict["expires_at"]),
            status=DocumentStatus(doc_dict["status"]),
            issuer_id=doc_dict["issuer_id"],
            issuing_authority=doc_dict.get("issuing_authority"),
            issuing_country=doc_dict["issuing_country"],
            signer_cert_id=UUID(doc_dict["signer_cert_id"]) if doc_dict.get("signer_cert_id") else None,
            signature=doc_dict.get("signature"),
            signed_data=doc_dict.get("signed_data"),
            metadata=metadata,
            created_at=datetime.fromisoformat(doc_dict["created_at"]),
            updated_at=datetime.fromisoformat(doc_dict["updated_at"]),
        )
    
    def _dict_to_audit_entry(self, entry_dict: dict[str, Any]) -> DocumentAuditLog:
        """Convert a database row dict to a DocumentAuditLog model."""
        details = entry_dict.get("details", "{}")
        if isinstance(details, str):
            details = json.loads(details)
        
        return DocumentAuditLog(
            id=UUID(entry_dict["id"]),
            document_id=UUID(entry_dict["document_id"]),
            event_type=AuditEventType(entry_dict["event_type"]),
            actor_id=entry_dict["actor_id"],
            actor_type=ActorType(entry_dict["actor_type"]),
            timestamp=datetime.fromisoformat(entry_dict["timestamp"]),
            details=details,
            ip_address=entry_dict.get("ip_address"),
            user_agent=entry_dict.get("user_agent"),
            request_id=entry_dict.get("request_id"),
        )
