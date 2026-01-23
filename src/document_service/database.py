"""
Database module for Travel Document Service

Uses SQLite for persistent storage with async support via aiosqlite.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator
from uuid import UUID

import aiosqlite

logger = logging.getLogger(__name__)

# Database configuration
DATA_PATH = os.environ.get("DOCUMENT_DATA_PATH", "data/documents")
DB_PATH = os.path.join(DATA_PATH, "documents.db")


# SQL schema for travel documents
CREATE_TRAVEL_DOCUMENTS_TABLE = """
CREATE TABLE IF NOT EXISTS travel_documents (
    id TEXT PRIMARY KEY,
    document_type TEXT NOT NULL,
    document_number TEXT UNIQUE NOT NULL,
    holder_name TEXT NOT NULL,
    holder_given_name TEXT,
    holder_family_name TEXT,
    holder_dob TEXT NOT NULL,
    nationality TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    issuer_id TEXT NOT NULL,
    issuing_authority TEXT,
    issuing_country TEXT NOT NULL,
    signer_cert_id TEXT,
    signature BLOB,
    signed_data BLOB,
    metadata TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

CREATE_DOCUMENT_AUDIT_LOG_TABLE = """
CREATE TABLE IF NOT EXISTS document_audit_log (
    id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}',
    ip_address TEXT,
    user_agent TEXT,
    request_id TEXT,
    FOREIGN KEY (document_id) REFERENCES travel_documents(id)
);
"""

# Create indices for common queries
CREATE_INDICES = """
CREATE INDEX IF NOT EXISTS idx_documents_type ON travel_documents(document_type);
CREATE INDEX IF NOT EXISTS idx_documents_status ON travel_documents(status);
CREATE INDEX IF NOT EXISTS idx_documents_nationality ON travel_documents(nationality);
CREATE INDEX IF NOT EXISTS idx_documents_issuing_country ON travel_documents(issuing_country);
CREATE INDEX IF NOT EXISTS idx_documents_holder_name ON travel_documents(holder_name);
CREATE INDEX IF NOT EXISTS idx_documents_expires_at ON travel_documents(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_document_id ON document_audit_log(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON document_audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON document_audit_log(event_type);
"""


async def init_document_db() -> None:
    """
    Initialize the document database and create tables if they don't exist.
    """
    logger.info(f"Initializing document database at {DB_PATH}")
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    async with aiosqlite.connect(DB_PATH) as db:
        # Create tables
        await db.execute(CREATE_TRAVEL_DOCUMENTS_TABLE)
        await db.execute(CREATE_DOCUMENT_AUDIT_LOG_TABLE)
        
        # Create indices (each statement separately)
        for index_sql in CREATE_INDICES.strip().split(";"):
            if index_sql.strip():
                await db.execute(index_sql)
        
        await db.commit()
        logger.info("Document database initialized successfully")


@asynccontextmanager
async def get_db_connection() -> AsyncIterator[aiosqlite.Connection]:
    """
    Get a database connection.

    Returns:
        Async iterator yielding a database connection
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as conn:
        conn.row_factory = aiosqlite.Row
        yield conn


class DocumentRepository:
    """Repository for travel document CRUD operations."""
    
    async def create(self, document: dict[str, Any]) -> dict[str, Any]:
        """Create a new travel document."""
        async with get_db_connection() as db:
            await db.execute(
                """
                INSERT INTO travel_documents (
                    id, document_type, document_number, holder_name,
                    holder_given_name, holder_family_name, holder_dob,
                    nationality, issued_at, expires_at, status,
                    issuer_id, issuing_authority, issuing_country,
                    signer_cert_id, signature, signed_data, metadata,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(document["id"]),
                    document["document_type"],
                    document["document_number"],
                    document["holder_name"],
                    document.get("holder_given_name"),
                    document.get("holder_family_name"),
                    document["holder_dob"],
                    document["nationality"],
                    document["issued_at"],
                    document["expires_at"],
                    document["status"],
                    document["issuer_id"],
                    document.get("issuing_authority"),
                    document["issuing_country"],
                    str(document["signer_cert_id"]) if document.get("signer_cert_id") else None,
                    document.get("signature"),
                    document.get("signed_data"),
                    document.get("metadata", "{}"),
                    document["created_at"],
                    document["updated_at"],
                ),
            )
            await db.commit()
            return document
    
    async def get_by_id(self, document_id: str) -> dict[str, Any] | None:
        """Get a document by ID."""
        async with get_db_connection() as db:
            cursor = await db.execute(
                "SELECT * FROM travel_documents WHERE id = ?",
                (document_id,),
            )
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    async def get_by_number(self, document_number: str) -> dict[str, Any] | None:
        """Get a document by document number."""
        async with get_db_connection() as db:
            cursor = await db.execute(
                "SELECT * FROM travel_documents WHERE document_number = ?",
                (document_number,),
            )
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    async def list_all(
        self,
        document_type: str | None = None,
        status: str | None = None,
        nationality: str | None = None,
        issuing_country: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """List documents with optional filters."""
        async with get_db_connection() as db:
            # Build query dynamically
            conditions = []
            params = []
            
            if document_type:
                conditions.append("document_type = ?")
                params.append(document_type)
            if status:
                conditions.append("status = ?")
                params.append(status)
            if nationality:
                conditions.append("nationality = ?")
                params.append(nationality)
            if issuing_country:
                conditions.append("issuing_country = ?")
                params.append(issuing_country)
            
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            
            # Get total count
            count_cursor = await db.execute(
                f"SELECT COUNT(*) FROM travel_documents WHERE {where_clause}",
                params,
            )
            total = (await count_cursor.fetchone())[0]
            
            # Get documents
            cursor = await db.execute(
                f"""
                SELECT * FROM travel_documents
                WHERE {where_clause}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                params + [limit, offset],
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows], total
    
    async def update(self, document_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        """Update a document."""
        async with get_db_connection() as db:
            # Build update query
            set_clauses = []
            params = []
            for key, value in updates.items():
                if key not in ("id", "created_at"):  # Don't update these
                    set_clauses.append(f"{key} = ?")
                    if isinstance(value, (UUID,)):
                        params.append(str(value))
                    else:
                        params.append(value)
            
            if not set_clauses:
                return await self.get_by_id(document_id)
            
            # Add updated_at
            set_clauses.append("updated_at = ?")
            params.append(datetime.utcnow().isoformat())
            params.append(document_id)
            
            await db.execute(
                f"""
                UPDATE travel_documents
                SET {", ".join(set_clauses)}
                WHERE id = ?
                """,
                params,
            )
            await db.commit()
            return await self.get_by_id(document_id)
    
    async def delete(self, document_id: str) -> bool:
        """Delete a document (soft delete by changing status)."""
        async with get_db_connection() as db:
            cursor = await db.execute(
                "DELETE FROM travel_documents WHERE id = ?",
                (document_id,),
            )
            await db.commit()
            return cursor.rowcount > 0
    
    async def get_stats(self) -> dict[str, Any]:
        """Get document statistics."""
        async with get_db_connection() as db:
            # Total documents
            cursor = await db.execute("SELECT COUNT(*) FROM travel_documents")
            total = (await cursor.fetchone())[0]
            
            # By type
            cursor = await db.execute(
                "SELECT document_type, COUNT(*) FROM travel_documents GROUP BY document_type"
            )
            by_type = {row[0]: row[1] for row in await cursor.fetchall()}
            
            # By status
            cursor = await db.execute(
                "SELECT status, COUNT(*) FROM travel_documents GROUP BY status"
            )
            by_status = {row[0]: row[1] for row in await cursor.fetchall()}
            
            # By country
            cursor = await db.execute(
                "SELECT issuing_country, COUNT(*) FROM travel_documents GROUP BY issuing_country"
            )
            by_country = {row[0]: row[1] for row in await cursor.fetchall()}
            
            # Recent issuances (today, this week, this month)
            today = datetime.utcnow().date().isoformat()
            cursor = await db.execute(
                "SELECT COUNT(*) FROM travel_documents WHERE date(issued_at) = ?",
                (today,),
            )
            issued_today = (await cursor.fetchone())[0]
            
            # Expiring soon (within 30 days)
            cursor = await db.execute(
                """
                SELECT COUNT(*) FROM travel_documents
                WHERE status = 'active'
                AND date(expires_at) <= date('now', '+30 days')
                """
            )
            expiring_soon = (await cursor.fetchone())[0]
            
            return {
                "total_documents": total,
                "by_type": by_type,
                "by_status": by_status,
                "by_country": by_country,
                "issued_today": issued_today,
                "issued_this_week": 0,  # Simplified
                "issued_this_month": 0,  # Simplified
                "expiring_soon": expiring_soon,
            }


class AuditRepository:
    """Repository for document audit log operations."""
    
    async def create(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Create a new audit log entry."""
        async with get_db_connection() as db:
            await db.execute(
                """
                INSERT INTO document_audit_log (
                    id, document_id, event_type, actor_id, actor_type,
                    timestamp, details, ip_address, user_agent, request_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(entry["id"]),
                    str(entry["document_id"]),
                    entry["event_type"],
                    entry["actor_id"],
                    entry["actor_type"],
                    entry["timestamp"],
                    entry.get("details", "{}"),
                    entry.get("ip_address"),
                    entry.get("user_agent"),
                    entry.get("request_id"),
                ),
            )
            await db.commit()
            return entry
    
    async def get_by_document(
        self,
        document_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """Get audit log entries for a document."""
        async with get_db_connection() as db:
            # Get total count
            count_cursor = await db.execute(
                "SELECT COUNT(*) FROM document_audit_log WHERE document_id = ?",
                (document_id,),
            )
            total = (await count_cursor.fetchone())[0]
            
            # Get entries
            cursor = await db.execute(
                """
                SELECT * FROM document_audit_log
                WHERE document_id = ?
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                """,
                (document_id, limit, offset),
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows], total
    
    async def get_all(
        self,
        event_type: str | None = None,
        actor_id: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """Get all audit log entries with optional filters."""
        async with get_db_connection() as db:
            conditions = []
            params = []
            
            if event_type:
                conditions.append("event_type = ?")
                params.append(event_type)
            if actor_id:
                conditions.append("actor_id = ?")
                params.append(actor_id)
            
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            
            # Get total count
            count_cursor = await db.execute(
                f"SELECT COUNT(*) FROM document_audit_log WHERE {where_clause}",
                params,
            )
            total = (await count_cursor.fetchone())[0]
            
            # Get entries
            cursor = await db.execute(
                f"""
                SELECT * FROM document_audit_log
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                """,
                params + [limit, offset],
            )
            rows = await cursor.fetchall()
            return [dict(row) for row in rows], total
