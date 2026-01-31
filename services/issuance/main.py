"""
Issuance Service

Handles OID4VCI credential issuance flows.

Ports:
- HTTP API on port 8005
"""

from __future__ import annotations

import logging
import os
import secrets
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "issuance-service"
SERVICE_PORT = int(os.environ.get("ISSUANCE_SERVICE_PORT", "8005"))


# =============================================================================
# Domain Layer
# =============================================================================

class IssuanceStatus(str, Enum):
    """Issuance transaction status."""
    PENDING = "pending"
    AUTHORIZED = "authorized"
    ISSUED = "issued"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class IssuanceTransaction:
    """
    Issuance transaction aggregate.
    
    Tracks the state of a credential issuance request.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    credential_template_id: str = ""
    applicant_id: str | None = None  # Optional now
    subject_did: str | None = None   # Direct issuance subject
    
    # Transaction state
    status: IssuanceStatus = IssuanceStatus.PENDING
    
    # OID4VCI tokens
    pre_auth_code: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    access_token: str | None = None
    c_nonce: str | None = None
    
    # Credential data
    claims: dict[str, Any] = field(default_factory=dict)
    
    # Timing
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=30))
    issued_at: datetime | None = None
    
    def authorize(self) -> str:
        """Generate access token for credential request."""
        self.access_token = secrets.token_urlsafe(32)
        self.c_nonce = secrets.token_urlsafe(16)
        self.status = IssuanceStatus.AUTHORIZED
        return self.access_token
    
    def complete(self) -> None:
        """Mark issuance as complete."""
        self.status = IssuanceStatus.ISSUED
        self.issued_at = datetime.now(timezone.utc)
    
    def fail(self, reason: str) -> None:
        """Mark issuance as failed."""
        self.status = IssuanceStatus.FAILED
    
    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at


@dataclass
class IssuedCredential:
    """
    Record of an issued credential.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    transaction_id: str = ""
    organization_id: str = ""
    credential_template_id: str = ""
    applicant_id: str | None = None
    subject_did: str | None = None
    
    # Credential data
    credential_jwt: str = ""
    credential_hash: str = ""
    
    # Revocation
    revoked: bool = False
    revoked_at: datetime | None = None
    revocation_reason: str | None = None
    
    # Timestamps
    issued_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None


# =============================================================================
# Application Layer
# =============================================================================

class InMemoryIssuanceRepository:
    """In-memory repository for development."""
    
    def __init__(self):
        self._transactions: dict[str, IssuanceTransaction] = {}
        self._credentials: dict[str, IssuedCredential] = {}
    
    async def save_transaction(self, tx: IssuanceTransaction) -> None:
        self._transactions[tx.id] = tx
    
    async def get_transaction(self, tx_id: str) -> IssuanceTransaction | None:
        return self._transactions.get(tx_id)
    
    async def get_by_pre_auth_code(self, code: str) -> IssuanceTransaction | None:
        for tx in self._transactions.values():
            if tx.pre_auth_code == code:
                return tx
        return None
    
    async def list_transactions(self, org_id: str) -> list[IssuanceTransaction]:
        return [tx for tx in self._transactions.values() if tx.organization_id == org_id]
    
    async def save_credential(self, cred: IssuedCredential) -> None:
        self._credentials[cred.id] = cred
    
    async def list_credentials(self, applicant_id: str) -> list[IssuedCredential]:
        return [c for c in self._credentials.values() if c.applicant_id == applicant_id]


# =============================================================================
# HTTP Adapter
# =============================================================================

router = APIRouter(prefix="/v1/issuance", tags=["issuance"])

_repo: InMemoryIssuanceRepository | None = None


def get_repo() -> InMemoryIssuanceRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


class InitiateIssuanceRequest(BaseModel):
    organization_id: str
    credential_template_id: str
    applicant_id: str | None = None
    subject_did: str | None = None
    claims: dict[str, Any] = {}


class IssuanceResponse(BaseModel):
    id: str
    status: str
    credential_offer_uri: str
    pre_auth_code: str
    expires_at: str


class TokenRequest(BaseModel):
    grant_type: str = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
    pre_authorized_code: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    c_nonce: str


class CredentialRequest(BaseModel):
    format: str = "jwt_vc_json"
    proof: dict[str, Any] | None = None


class CredentialResponse(BaseModel):
    credential: str
    format: str


@router.post("/initiate", response_model=IssuanceResponse)
async def initiate_issuance(
    request: InitiateIssuanceRequest,
    repo: InMemoryIssuanceRepository = Depends(get_repo),
) -> IssuanceResponse:
    """Initiate a credential issuance transaction."""
    tx = IssuanceTransaction(
        organization_id=request.organization_id,
        credential_template_id=request.credential_template_id,
        applicant_id=request.applicant_id,
        subject_did=request.subject_did,
        claims=request.claims,
    )
    await repo.save_transaction(tx)
    
    # Build credential offer URI
    offer_uri = f"openid-credential-offer://?credential_offer_uri=https://api.marty.dev/v1/issuance/offers/{tx.id}"
    
    return IssuanceResponse(
        id=tx.id,
        status=tx.status.value,
        credential_offer_uri=offer_uri,
        pre_auth_code=tx.pre_auth_code,
        expires_at=tx.expires_at.isoformat(),
    )


@router.post("/token", response_model=TokenResponse)
async def exchange_token(
    request: TokenRequest,
    repo: InMemoryIssuanceRepository = Depends(get_repo),
) -> TokenResponse:
    """Exchange pre-authorized code for access token (OID4VCI)."""
    tx = await repo.get_by_pre_auth_code(request.pre_authorized_code)
    
    if not tx:
        raise HTTPException(status_code=400, detail="Invalid pre-authorized code")
    
    if tx.is_expired:
        raise HTTPException(status_code=400, detail="Transaction expired")
    
    if tx.status != IssuanceStatus.PENDING:
        raise HTTPException(status_code=400, detail="Invalid transaction state")
    
    access_token = tx.authorize()
    await repo.save_transaction(tx)
    
    return TokenResponse(
        access_token=access_token,
        expires_in=1800,
        c_nonce=tx.c_nonce,
    )


@router.get("/transactions", response_model=list[dict])
async def list_transactions(
    organization_id: str = Query(...),
    repo: InMemoryIssuanceRepository = Depends(get_repo),
) -> list[dict]:
    """List issuance transactions for an organization."""
    transactions = await repo.list_transactions(organization_id)
    return [
        {
            "id": tx.id,
            "credential_template_id": tx.credential_template_id,
            "applicant_id": tx.applicant_id,
            "subject_did": tx.subject_did,
            "status": tx.status.value,
            "created_at": tx.created_at.isoformat(),
        }
        for tx in transactions
    ]


@router.get("/transactions/{tx_id}")
async def get_transaction(
    tx_id: str,
    repo: InMemoryIssuanceRepository = Depends(get_repo),
) -> dict:
    """Get a specific issuance transaction."""
    tx = await repo.get_transaction(tx_id)
    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")
    return {
        "id": tx.id,
        "organization_id": tx.organization_id,
        "credential_template_id": tx.credential_template_id,
        "applicant_id": tx.applicant_id,
        "subject_did": tx.subject_did,
        "status": tx.status.value,
        "created_at": tx.created_at.isoformat(),
        "expires_at": tx.expires_at.isoformat(),
        "issued_at": tx.issued_at.isoformat() if tx.issued_at else None,
    }


# =============================================================================
# Application Templates (for credential applications)
# =============================================================================

# In-memory template storage for development
_templates: dict[str, dict] = {}


@router.get("/templates")
async def list_application_templates(
    organization_id: str = Query(...),
) -> dict:
    """
    List application templates for an organization.
    
    Application templates define the structure of credential applications.
    """
    org_templates = [
        t for t in _templates.values() 
        if t.get("organization_id") == organization_id
    ]
    return {"templates": org_templates}


@router.post("/templates")
async def create_application_template(
    template: dict,
) -> dict:
    """Create a new application template."""
    import uuid
    from datetime import datetime, timezone
    
    template_id = str(uuid.uuid4())
    template["id"] = template_id
    template["created_at"] = datetime.now(timezone.utc).isoformat()
    template["updated_at"] = template["created_at"]
    
    _templates[template_id] = template
    logger.info(f"Created application template: {template_id}")
    
    return template


@router.get("/templates/{template_id}")
async def get_application_template(
    template_id: str,
) -> dict:
    """Get a specific application template."""
    template = _templates.get(template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    return template


@router.put("/templates/{template_id}")
async def update_application_template(
    template_id: str,
    template: dict,
) -> dict:
    """Update an application template."""
    from datetime import datetime, timezone
    
    if template_id not in _templates:
        raise HTTPException(status_code=404, detail="Template not found")
    
    template["id"] = template_id
    template["updated_at"] = datetime.now(timezone.utc).isoformat()
    _templates[template_id] = template
    
    logger.info(f"Updated application template: {template_id}")
    return template


@router.delete("/templates/{template_id}")
async def delete_application_template(
    template_id: str,
) -> dict:
    """Delete an application template."""
    if template_id not in _templates:
        raise HTTPException(status_code=404, detail="Template not found")
    
    del _templates[template_id]
    logger.info(f"Deleted application template: {template_id}")
    
    return {"success": True}


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo
    logger.info(f"Starting {SERVICE_NAME}...")
    _repo = InMemoryIssuanceRepository()
    yield
    logger.info(f"Shutting down {SERVICE_NAME}...")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Issuance Service",
        description="OID4VCI credential issuance service",
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
    uvicorn.run("issuance.main:app", host="0.0.0.0", port=SERVICE_PORT, reload=True)
