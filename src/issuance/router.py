"""Credential issuance API router.

Provides OID4VCI-compliant endpoints for credential issuance,
including support for deferred (async) credential generation
with transaction_id polling.
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Header, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from auth.router import get_current_user, require_org_admin, AuthStatusResponse
from subscription.models import (
    CredentialOffer,
    IssuanceSession,
    IssuanceStatus,
)

router = APIRouter(prefix="/api/issuance", tags=["issuance"])


# ==================== Configuration ====================

# Default offer expiry (5 minutes for real-time, 24 hours for deferred)
OFFER_EXPIRY_SECONDS = 300
DEFERRED_EXPIRY_SECONDS = 86400
TRANSACTION_ID_LENGTH = 32


# ==================== Pydantic Schemas ====================


class CreateOfferRequest(BaseModel):
    """Request to create a credential offer."""

    organization_id: Optional[str] = Field(None, description="Target organization ID (required for platform admins)")
    credential_config_id: str = Field(..., description="Credential type configuration ID")
    applicant_id: str = Field(..., description="Recipient user ID")
    application_id: Optional[str] = Field(None, description="Source application ID (if from application flow)")
    credential_data: dict = Field(..., description="Claim values for the credential")
    device_id: Optional[str] = Field(None, description="Target device for push notification")
    credential_format: str = Field(default="vc+sd-jwt", description="Credential format")
    deferred: bool = Field(default=False, description="Use deferred issuance (async generation)")


class CredentialOfferResponse(BaseModel):
    """Credential offer response."""

    transaction_id: str
    credential_offer_uri: str
    pre_authorized_code: Optional[str] = None
    expires_at: datetime
    status: IssuanceStatus
    qr_code_data: Optional[str] = None

    class Config:
        from_attributes = True


class IssuanceSessionResponse(BaseModel):
    """Issuance session status response."""

    transaction_id: str
    status: IssuanceStatus
    credential_format: str
    expires_at: datetime
    accepted_at: Optional[datetime] = None
    issued_at: Optional[datetime] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    # Only included when status is READY or ISSUED
    credential: Optional[str] = None
    c_nonce: Optional[str] = None
    c_nonce_expires_in: Optional[int] = None

    class Config:
        from_attributes = True


class TokenRequest(BaseModel):
    """OID4VCI token request (pre-authorized code flow)."""

    grant_type: str = Field(..., description="Must be 'urn:ietf:params:oauth:grant-type:pre-authorized_code'")
    pre_authorized_code: str = Field(..., alias="pre-authorized_code")
    tx_code: Optional[str] = Field(None, description="Transaction code (PIN) if required")


class TokenResponse(BaseModel):
    """OID4VCI token response."""

    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 300
    c_nonce: Optional[str] = None
    c_nonce_expires_in: Optional[int] = None


class CredentialRequest(BaseModel):
    """OID4VCI credential request."""

    format: str = Field(..., description="Credential format (vc+sd-jwt, jwt_vc_json, mso_mdoc)")
    credential_identifier: Optional[str] = Field(None, description="Credential configuration ID")
    proof: Optional[dict] = Field(None, description="Proof of possession")


class CredentialResponse(BaseModel):
    """OID4VCI credential response."""

    format: str
    credential: Optional[str] = None
    transaction_id: Optional[str] = None  # For deferred issuance
    c_nonce: Optional[str] = None
    c_nonce_expires_in: Optional[int] = None


class DeferredCredentialRequest(BaseModel):
    """OID4VCI deferred credential request."""

    transaction_id: str


# ==================== In-Memory Storage (for now) ====================

# TODO: Replace with proper database session
_issuance_sessions: dict[str, IssuanceSession] = {}
_credential_offers: dict[str, CredentialOffer] = {}
_access_tokens: dict[str, str] = {}  # token_hash -> session_id


# ==================== Helper Functions ====================


def _generate_transaction_id() -> str:
    """Generate a unique transaction ID."""
    return secrets.token_urlsafe(TRANSACTION_ID_LENGTH)


def _generate_pre_authorized_code() -> str:
    """Generate a pre-authorized code."""
    return secrets.token_urlsafe(32)


def _generate_c_nonce() -> str:
    """Generate a challenge nonce."""
    return secrets.token_urlsafe(16)


def _generate_access_token() -> str:
    """Generate an access token."""
    return secrets.token_urlsafe(32)


def _hash_token(token: str) -> str:
    """Hash a token for storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def _build_credential_offer(
    session: IssuanceSession,
    issuer_url: str,
) -> dict:
    """Build OID4VCI credential offer payload.

    Args:
        session: The issuance session
        issuer_url: Base URL of the issuer

    Returns:
        Credential offer JSON payload
    """
    return {
        "credential_issuer": issuer_url,
        "credential_configuration_ids": [session.credential_config_id],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": session.pre_authorized_code,
                "tx_code": None,  # No PIN required for now
            }
        },
    }


def _build_credential_offer_uri(
    offer_id: str,
    issuer_url: str,
) -> str:
    """Build credential offer URI for wallet.

    Args:
        offer_id: The offer ID
        issuer_url: Base URL of the issuer

    Returns:
        openid-credential-offer:// URI
    """
    offer_endpoint = f"{issuer_url}/api/issuance/offers/{offer_id}"
    params = urlencode({"credential_offer_uri": offer_endpoint})
    return f"openid-credential-offer://?{params}"


async def _create_credential_async(session: IssuanceSession) -> None:
    """Create credential asynchronously (placeholder).

    In production, this would be a background task that:
    1. Fetches the issuer signing key
    2. Builds the credential claims
    3. Signs the credential
    4. Updates the session with the result

    Args:
        session: The issuance session
    """
    # TODO: Implement actual credential creation
    # For now, simulate async processing
    session.status = IssuanceStatus.READY
    session.issued_credential = "eyJ...placeholder..."  # Placeholder
    session.issued_at = datetime.utcnow()


# ==================== API Endpoints ====================


@router.post("/offers", response_model=CredentialOfferResponse)
async def create_credential_offer(
    request: CreateOfferRequest,
    current_user: AuthStatusResponse = Depends(require_org_admin),
    issuer_url: str = Header(default="http://localhost:8000", alias="X-Issuer-URL"),
):
    """Create a credential offer for an applicant.

    Creates an OID4VCI credential offer that can be scanned by a wallet
    or pushed to a registered device. Supports both immediate and
    deferred issuance.
    """
    user = current_user.user
    roles = user.roles or []
    is_platform_admin = "platform_admin" in roles or "admin" in roles or "administrator" in roles
    
    # Platform admins can specify organization via request body
    # Org members use their own organization
    org_id = user.organization_id
    if is_platform_admin and request.organization_id:
        org_id = request.organization_id
    
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization context required",
        )

    # Create issuance session
    session_id = str(uuid.uuid4())
    transaction_id = _generate_transaction_id()
    pre_authorized_code = _generate_pre_authorized_code()

    expiry = (
        datetime.utcnow() + timedelta(seconds=DEFERRED_EXPIRY_SECONDS)
        if request.deferred
        else datetime.utcnow() + timedelta(seconds=OFFER_EXPIRY_SECONDS)
    )

    session = IssuanceSession()
    session.id = session_id
    session.transaction_id = transaction_id
    session.organization_id = org_id
    session.application_id = request.application_id
    session.credential_config_id = request.credential_config_id
    session.applicant_id = request.applicant_id
    session.device_id = request.device_id
    session.status = IssuanceStatus.DEFERRED if request.deferred else IssuanceStatus.PENDING
    session.pre_authorized_code = pre_authorized_code
    session.credential_format = request.credential_format
    session.credential_data = request.credential_data
    session.expires_at = expiry
    session.created_at = datetime.utcnow()

    _issuance_sessions[transaction_id] = session

    # Build credential offer
    offer_payload = _build_credential_offer(session, issuer_url)
    offer_uri = _build_credential_offer_uri(session_id, issuer_url)

    # Create offer record
    offer = CredentialOffer()
    offer.id = str(uuid.uuid4())
    offer.issuance_session_id = session_id
    offer.offer_uri = offer_uri
    offer.offer_payload = offer_payload
    offer.is_active = True
    offer.access_count = 0  # Initialize for in-memory usage
    offer.expires_at = expiry
    offer.created_at = datetime.utcnow()

    _credential_offers[offer.id] = offer

    # If deferred, start async credential creation
    if request.deferred:
        # In production, this would queue a background task
        await _create_credential_async(session)

    return CredentialOfferResponse(
        transaction_id=transaction_id,
        credential_offer_uri=offer_uri,
        pre_authorized_code=pre_authorized_code,
        expires_at=expiry,
        status=session.status,
        qr_code_data=None,  # TODO: Generate QR code
    )


@router.get("/offers/{offer_id}")
async def get_credential_offer(offer_id: str):
    """Get credential offer payload (for wallet retrieval).

    This endpoint is called by the wallet when it dereferences
    the credential_offer_uri from a QR code or push notification.
    """
    offer = _credential_offers.get(offer_id)
    if not offer:
        # Try looking up by session ID or transaction_id
        for o in _credential_offers.values():
            if o.issuance_session_id == offer_id:
                offer = o
                break
        
        # Also try by transaction_id from session
        # Sessions are keyed by transaction_id
        if not offer and offer_id in _issuance_sessions:
            session = _issuance_sessions[offer_id]
            for o in _credential_offers.values():
                if o.issuance_session_id == session.id:
                    offer = o
                    break

    if not offer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential offer not found",
        )

    if not offer.is_active:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Credential offer has been consumed",
        )

    if datetime.utcnow() > offer.expires_at:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Credential offer has expired",
        )

    # Track access
    offer.access_count += 1
    offer.accessed_at = datetime.utcnow()

    return JSONResponse(content=offer.offer_payload)


@router.get("/sessions/{transaction_id}", response_model=IssuanceSessionResponse)
async def get_issuance_session(
    transaction_id: str,
    current_user: AuthStatusResponse = Depends(get_current_user),
):
    """Get issuance session status by transaction_id.

    Used by wallets to poll for deferred credential readiness,
    or by admins to check issuance status.
    """
    if not current_user.authenticated or not current_user.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    
    user = current_user.user
    session = _issuance_sessions.get(transaction_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Issuance session not found",
        )

    # Check authorization
    roles = user.roles or []
    is_platform_admin = "platform_admin" in roles or "admin" in roles or "administrator" in roles
    is_org_admin = user.organization_id == session.organization_id and (
        "org_admin" in roles or "owner" in roles or "admin" in roles or "vendor" in roles
    )
    is_applicant = user.user_id == session.applicant_id

    if not is_platform_admin and not is_org_admin and not is_applicant:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this issuance session",
        )

    # Build response
    response = IssuanceSessionResponse(
        transaction_id=session.transaction_id,
        status=session.status,
        credential_format=session.credential_format,
        expires_at=session.expires_at,
        accepted_at=session.accepted_at,
        issued_at=session.issued_at,
        error_code=session.error_code,
        error_message=session.error_message,
    )

    # Include credential if ready and requester is the applicant
    if session.status in [IssuanceStatus.READY, IssuanceStatus.ISSUED] and is_applicant:
        response.credential = session.issued_credential
        if session.c_nonce and session.c_nonce_expires_at:
            response.c_nonce = session.c_nonce
            response.c_nonce_expires_in = int(
                (session.c_nonce_expires_at - datetime.utcnow()).total_seconds()
            )

    return response


@router.post("/token", response_model=TokenResponse)
async def token_endpoint(
    grant_type: str = Form(..., alias="grant_type"),
    pre_authorized_code: str = Form(..., alias="pre-authorized_code"),
    tx_code: Optional[str] = Form(None),
):
    """OID4VCI token endpoint (pre-authorized code flow).

    Exchanges a pre-authorized code for an access token that
    can be used to retrieve the credential.
    """
    if grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported grant type",
        )

    # Find session by pre-authorized code
    session = None
    for s in _issuance_sessions.values():
        if s.pre_authorized_code == pre_authorized_code:
            session = s
            break

    if not session:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid pre-authorized code",
        )

    if session.is_expired:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pre-authorized code has expired",
        )

    # Generate access token
    access_token = _generate_access_token()
    token_hash = _hash_token(access_token)
    _access_tokens[token_hash] = session.transaction_id

    # Update session
    session.access_token_hash = token_hash
    session.accepted_at = datetime.utcnow()
    if session.status == IssuanceStatus.PENDING:
        session.status = IssuanceStatus.ACCEPTED

    # Generate c_nonce for proof of possession
    c_nonce = _generate_c_nonce()
    session.c_nonce = c_nonce
    session.c_nonce_expires_at = datetime.utcnow() + timedelta(minutes=5)

    return TokenResponse(
        access_token=access_token,
        token_type="Bearer",
        expires_in=300,
        c_nonce=c_nonce,
        c_nonce_expires_in=300,
    )


@router.post("/credential", response_model=CredentialResponse)
async def credential_endpoint(
    request: CredentialRequest,
    authorization: str = Header(...),
):
    """OID4VCI credential endpoint.

    Returns the credential after validating the access token
    and optional proof of possession.
    """
    # Validate authorization header
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header",
        )

    access_token = authorization[7:]
    token_hash = _hash_token(access_token)
    transaction_id = _access_tokens.get(token_hash)

    if not transaction_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
        )

    session = _issuance_sessions.get(transaction_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Issuance session not found",
        )

    # Check if deferred
    if session.status == IssuanceStatus.DEFERRED:
        # Return transaction_id for polling
        return CredentialResponse(
            format=request.format,
            transaction_id=session.transaction_id,
        )

    # Check if credential is ready
    if session.status not in [IssuanceStatus.READY, IssuanceStatus.ACCEPTED]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Credential not ready. Status: {session.status}",
        )

    # Validate proof of possession if provided
    if request.proof:
        # TODO: Validate JWT proof against c_nonce
        pass

    # Generate new c_nonce for potential retry
    new_c_nonce = _generate_c_nonce()
    session.c_nonce = new_c_nonce
    session.c_nonce_expires_at = datetime.utcnow() + timedelta(minutes=5)

    # If credential not yet generated, create it now
    if not session.issued_credential:
        await _create_credential_async(session)

    # Update session status
    session.status = IssuanceStatus.ISSUED
    session.issued_at = datetime.utcnow()

    return CredentialResponse(
        format=session.credential_format,
        credential=session.issued_credential,
        c_nonce=new_c_nonce,
        c_nonce_expires_in=300,
    )


@router.post("/deferred", response_model=CredentialResponse)
async def deferred_credential_endpoint(
    request: DeferredCredentialRequest,
    authorization: str = Header(...),
):
    """OID4VCI deferred credential endpoint.

    Polls for credential readiness using the transaction_id
    returned from the credential endpoint.
    """
    # Validate authorization header
    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header",
        )

    access_token = authorization[7:]
    token_hash = _hash_token(access_token)
    stored_transaction_id = _access_tokens.get(token_hash)

    if not stored_transaction_id or stored_transaction_id != request.transaction_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token or transaction_id mismatch",
        )

    session = _issuance_sessions.get(request.transaction_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Issuance session not found",
        )

    # Check if still deferred
    if session.status == IssuanceStatus.DEFERRED:
        # Increment retry count
        session.retry_count += 1
        session.last_retry_at = datetime.utcnow()

        # Check if expired
        if session.is_expired:
            session.status = IssuanceStatus.EXPIRED
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Deferred credential request has expired",
            )

        # Return pending response (HTTP 202)
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "transaction_id": session.transaction_id,
                "retry_after": 5,  # Suggest retry after 5 seconds
            },
        )

    # Check if ready
    if session.status == IssuanceStatus.READY:
        session.status = IssuanceStatus.ISSUED
        session.issued_at = datetime.utcnow()

        return CredentialResponse(
            format=session.credential_format,
            credential=session.issued_credential,
        )

    # Check for errors
    if session.status == IssuanceStatus.FAILED:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=session.error_message or "Credential generation failed",
        )

    # Already issued
    if session.status == IssuanceStatus.ISSUED:
        return CredentialResponse(
            format=session.credential_format,
            credential=session.issued_credential,
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Unexpected session status: {session.status}",
    )


@router.get("/pending", response_model=list[IssuanceSessionResponse])
async def list_pending_offers(
    current_user: AuthStatusResponse = Depends(get_current_user),
):
    """List pending credential offers for the current user.

    Returns all active/pending issuance sessions for the
    authenticated user's wallet to claim.
    """
    if not current_user.authenticated or not current_user.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    
    user_id = current_user.user.user_id

    pending = []
    for session in _issuance_sessions.values():
        if session.applicant_id == user_id and session.status in [
            IssuanceStatus.PENDING,
            IssuanceStatus.ACCEPTED,
            IssuanceStatus.READY,
        ]:
            if not session.is_expired:
                pending.append(
                    IssuanceSessionResponse(
                        transaction_id=session.transaction_id,
                        status=session.status,
                        credential_format=session.credential_format,
                        expires_at=session.expires_at,
                        accepted_at=session.accepted_at,
                        issued_at=session.issued_at,
                    )
                )

    return pending


# ==================== Issuer Metadata ====================


@router.get("/.well-known/openid-credential-issuer/{org_id}")
async def get_issuer_metadata(org_id: str):
    """Get OID4VCI issuer metadata for an organization.

    Returns the OpenID4VCI issuer configuration including
    supported credential types and endpoints.
    """
    # TODO: Build from CredentialTypeConfiguration records
    # For now, return a placeholder
    base_url = f"http://localhost:8000"

    return {
        "credential_issuer": f"{base_url}/api/issuance/{org_id}",
        "authorization_servers": [base_url],
        "credential_endpoint": f"{base_url}/api/issuance/credential",
        "deferred_credential_endpoint": f"{base_url}/api/issuance/deferred",
        "token_endpoint": f"{base_url}/api/issuance/token",
        "credential_configurations_supported": {
            # TODO: Populate from org's credential configs
        },
        "display": [
            {
                "name": "Organization Issuer",
                "locale": "en",
            }
        ],
    }


# ==================== Credential Revocation ====================


class RevokeCredentialRequest(BaseModel):
    """Request to revoke a credential."""
    reason: str = Field(..., description="Revocation reason")
    revoked_by: str = Field(..., description="ID of user revoking the credential")


class RevocationEntry(BaseModel):
    """A revocation list entry."""
    credential_id: str
    transaction_id: str
    revoked_at: datetime
    reason: str
    revoked_by: str


class RevocationListResponse(BaseModel):
    """Response containing revocation list."""
    organization_id: str
    entries: list[RevocationEntry]
    last_updated: datetime


# In-memory revocation list (TODO: move to database)
_revocation_lists: dict[str, list[RevocationEntry]] = {}


@router.post(
    "/sessions/{transaction_id}/revoke",
    response_model=dict,
    summary="Revoke issued credential",
)
async def revoke_credential(
    transaction_id: str,
    request: RevokeCredentialRequest,
    current_user: AuthStatusResponse = Depends(require_org_admin),
) -> dict:
    """
    Revoke a previously issued credential.

    The credential will be added to the organization's revocation list
    and marked as revoked in the issuance session.

    Args:
        transaction_id: The transaction ID of the credential to revoke
        request: Revocation details

    Returns:
        Confirmation of revocation
    """
    session = _issuance_sessions.get(transaction_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Issuance session not found",
        )

    # Verify org access
    user_org = current_user.user.organization_id if current_user.user else None
    if user_org and session.organization_id != user_org:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to revoke this credential",
        )

    # Check if already revoked
    if session.status == IssuanceStatus.REVOKED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Credential is already revoked",
        )

    # Check if credential was issued
    if session.status not in [IssuanceStatus.ISSUED, IssuanceStatus.READY]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot revoke credential in status {session.status.value}",
        )

    # Mark session as revoked
    session.status = IssuanceStatus.REVOKED
    session.updated_at = datetime.utcnow()

    # Add to revocation list
    entry = RevocationEntry(
        credential_id=session.credential_id or session.id,
        transaction_id=transaction_id,
        revoked_at=datetime.utcnow(),
        reason=request.reason,
        revoked_by=request.revoked_by,
    )

    org_id = session.organization_id
    if org_id not in _revocation_lists:
        _revocation_lists[org_id] = []
    _revocation_lists[org_id].append(entry)

    logger.info(
        f"Revoked credential {transaction_id} for org {org_id}: {request.reason}"
    )

    return {
        "status": "revoked",
        "transaction_id": transaction_id,
        "revoked_at": entry.revoked_at.isoformat(),
    }


@router.get(
    "/revocations/{org_id}",
    response_model=RevocationListResponse,
    summary="Get organization revocation list",
)
async def get_revocation_list(org_id: str) -> RevocationListResponse:
    """
    Get the revocation list for an organization.

    This endpoint is public to allow verifiers to check credential status.
    In production, this should be a status list (bitstring) per SD-JWT-VC spec.

    Args:
        org_id: Organization ID

    Returns:
        List of revoked credentials
    """
    entries = _revocation_lists.get(org_id, [])
    
    return RevocationListResponse(
        organization_id=org_id,
        entries=entries,
        last_updated=datetime.utcnow(),
    )


@router.get(
    "/status/{transaction_id}",
    response_model=dict,
    summary="Check credential status",
)
async def check_credential_status(transaction_id: str) -> dict:
    """
    Check the status of a credential by transaction ID.

    This is a simplified status endpoint. In production, implement
    Token Status List (draft-ietf-oauth-status-list) for scalable
    status checking.

    Args:
        transaction_id: The transaction ID of the credential

    Returns:
        Credential status information
    """
    session = _issuance_sessions.get(transaction_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential not found",
        )

    is_revoked = session.status == IssuanceStatus.REVOKED
    
    return {
        "transaction_id": transaction_id,
        "status": session.status.value,
        "is_valid": not is_revoked and session.status in [IssuanceStatus.ISSUED, IssuanceStatus.READY],
        "is_revoked": is_revoked,
        "issued_at": session.issued_at.isoformat() if session.issued_at else None,
        "expires_at": session.expires_at.isoformat() if session.expires_at else None,
    }


# ==================== Authenticator Credential Pickup ====================


@router.get(
    "/pickup/{device_id}",
    response_model=list,
    summary="Get pending credentials for device",
)
async def get_pending_credentials_for_device(device_id: str) -> list:
    """
    Get credentials pending delivery to a device.

    For auto-accept flow: authenticators poll this endpoint to retrieve
    credentials that have been issued for applications they submitted.
    Since the holder already consented when applying, these credentials
    are automatically accepted.

    Args:
        device_id: The device ID

    Returns:
        List of pending credentials to store
    """
    from issuance.notifications import get_pending_credentials

    pending = get_pending_credentials(device_id)
    return pending


@router.post(
    "/pickup/{device_id}/acknowledge",
    response_model=dict,
    summary="Acknowledge credential receipt",
)
async def acknowledge_credential_receipt(
    device_id: str,
    session_id: str,
) -> dict:
    """
    Acknowledge that a credential has been stored.

    After the authenticator successfully stores the credential,
    it should call this to remove it from the pending queue.

    Args:
        device_id: The device ID
        session_id: The issuance session ID

    Returns:
        Confirmation
    """
    from issuance.notifications import acknowledge_credential

    success = acknowledge_credential(device_id, session_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential not found in pending queue",
        )

    return {
        "acknowledged": True,
        "device_id": device_id,
        "session_id": session_id,
    }


# Note: Test key management endpoints have been removed.
# Keys are now managed internally via SpruceIDKeyManager.
# Use get_key_manager() from marty_plugin.adapters.credentials.spruceid
