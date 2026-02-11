"""Credential issuance API router.

Provides OID4VCI-compliant endpoints for credential issuance,
including support for deferred (async) credential generation
with transaction_id polling.
"""

import hashlib
import io
import os
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional, AsyncGenerator
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Header, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy import select, and_, or_, func
import qrcode
import qrcode.image.svg

from auth.router import get_current_user, require_org_admin, AuthStatusResponse
from subscription.models import (
    CredentialOffer,
    IssuanceSession,
    IssuanceStatus,
    OfferAccessLog,
    AuditEventType,
)

router = APIRouter(prefix="/api/issuance", tags=["issuance"])


# ==================== Database Configuration ====================

# Database engine and session maker
_engine = None
_async_session_maker = None


def get_db_config() -> dict:
    """Get database configuration from environment."""
    database_url = os.environ.get("DATABASE_URL", "postgresql://marty:marty_dev@postgres:5432/marty_credentials")
    if not database_url.startswith("postgresql+asyncpg://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return {"database_url": database_url}


def init_db():
    """Initialize database engine and session maker."""
    global _engine, _async_session_maker
    if _engine is None:
        config = get_db_config()
        _engine = create_async_engine(
            config["database_url"],
            echo=False,
            pool_pre_ping=True,
        )
        _async_session_maker = async_sessionmaker(
            _engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session."""
    if _async_session_maker is None:
        init_db()
    
    async with _async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


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
    applicant_id: Optional[str] = Field(None, description="Recipient user ID (legacy)")
    subject_did: Optional[str] = Field(None, description="Subject DID (for direct issuance)")
    application_id: Optional[str] = Field(None, description="Source application ID (if from application flow)")
    credential_data: dict = Field(..., description="Claim values for the credential")
    device_id: Optional[str] = Field(None, description="Target device for push notification")
    credential_format: str = Field(default="vc+sd-jwt", description="Credential format")
    deferred: bool = Field(default=False, description="Use deferred issuance (async generation)")
    deployment_profile_id: Optional[str] = Field(None, description="Deployment profile ID for QR branding")


class CredentialOfferResponse(BaseModel):
    """Credential offer response."""

    transaction_id: str
    credential_offer_uri: str  # Deep link format: openid-credential-offer://...
    offer_endpoint: Optional[str] = Field(None, description="HTTP endpoint for offer retrieval")
    deep_link_uri: Optional[str] = Field(None, description="Deep link for mobile wallets (same as credential_offer_uri)")
    pre_authorized_code: Optional[str] = None
    expires_at: datetime
    status: IssuanceStatus
    qr_code_data: Optional[str] = None
    branding: Optional[dict] = Field(None, description="QR code branding configuration from deployment profile")

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


class RetryPolicyResponse(BaseModel):
    """Retry policy information for expired offers."""
    
    can_retry: bool = Field(..., description="Whether retry is allowed")
    attempt_number: int = Field(..., description="Current attempt number")
    max_retries: int = Field(..., description="Maximum retries allowed")
    cooldown_minutes: int = Field(..., description="Minutes to wait between retries")
    next_retry_at: Optional[datetime] = Field(None, description="Earliest time for next retry")
    reason: Optional[str] = Field(None, description="Reason if retry not allowed")


class RegenerateOfferRequest(BaseModel):
    """Request to regenerate an expired credential offer."""
    
    force: bool = Field(default=False, description="Force regeneration ignoring cooldown (admin only)")


class OfferListItemResponse(BaseModel):
    """Individual offer item in list response."""
    
    offer_id: str
    session_id: str
    transaction_id: str
    organization_id: str
    credential_config_id: str
    applicant_id: Optional[str] = None
    application_id: Optional[str] = None
    subject_did: Optional[str] = None
    
    # Status
    status: IssuanceStatus
    is_active: bool
    is_expired: bool
    
    # Offer details
    credential_offer_uri: str
    offer_endpoint: Optional[str] = None
    deep_link_uri: Optional[str] = None
    qr_code_data: Optional[str] = None
    
    # Access tracking
    access_count: int = 0
    accessed_at: Optional[datetime] = None
    
    # Timing
    created_at: datetime
    expires_at: datetime
    issued_at: Optional[datetime] = None
    
    # Metadata
    attempt_number: int = 1
    credential_format: str = "vc+sd-jwt"
    
    class Config:
        from_attributes = True


class OfferListResponse(BaseModel):
    """Paginated list of credential offers."""
    
    offers: list[OfferListItemResponse]
    total: int
    page: int = 1
    page_size: int = 50
    has_more: bool = False


# ==================== Analytics Endpoints ====================


class SupportedFormatsResponse(BaseModel):
    """Supported credential formats response."""
    formats: list[str] = Field(..., description="List of supported credential format identifiers")


@router.get("/formats/supported", response_model=SupportedFormatsResponse)
async def get_supported_formats_endpoint():
    """Get list of credential formats supported by this issuer.
    
    Returns all credential formats that wallets can request during
    the credential issuance flow. These formats will be negotiated
    during the token exchange based on wallet capabilities.
    """
    return SupportedFormatsResponse(formats=_get_supported_formats())


# Pydantic models for analytics


class AnalyticsSummaryResponse(BaseModel):
    """Analytics summary for credential offers."""
    
    total_offers: int
    active_offers: int
    total_scans: int
    unique_wallets: int
    success_rate: float
    avg_scans_per_offer: float
    top_wallet_types: list[dict]
    recent_activity: list[dict]


class ScanLogResponse(BaseModel):
    """Individual scan log entry."""
    
    id: str
    offer_id: str
    session_id: str
    transaction_id: Optional[str] = None
    access_type: str
    wallet_type: Optional[str] = None
    wallet_version: Optional[str] = None
    outcome: str
    error_code: Optional[str] = None
    ip_address: Optional[str] = None
    accessed_at: datetime
    
    class Config:
        from_attributes = True


class ScanListResponse(BaseModel):
    """Paginated list of scan logs."""
    
    scans: list[ScanLogResponse]
    total: int
    page: int = 1
    page_size: int = 50
    has_more: bool = False


# ==================== Helper Functions ====================

# Note: In-memory storage removed - now using PostgreSQL via AsyncSession
# All session/offer operations now use database queries


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


def _generate_qr_code(data: str, format: str = "png") -> bytes:
    """Generate QR code image from data.
    
    Args:
        data: The data to encode in the QR code
        format: Output format - "png" or "svg"
    
    Returns:
        QR code image as bytes
    """
    qr = qrcode.QRCode(
        version=None,  # Auto-size
        error_correction=qrcode.constants.ERROR_CORRECT_H,  # High error correction for mobile scanning
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    if format == "svg":
        # SVG format
        factory = qrcode.image.svg.SvgPathImage
        img = qr.make_image(image_factory=factory)
        buffer = io.BytesIO()
        img.save(buffer)
        return buffer.getvalue()
    else:
        # PNG format (default)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()


def _generate_qr_data_uri(qr_bytes: bytes, format: str = "png") -> str:
    """Convert QR code bytes to data URI.
    
    Args:
        qr_bytes: QR code image bytes
        format: Image format
    
    Returns:
        Data URI string (e.g., "data:image/png;base64,...")
    """
    import base64
    b64_data = base64.b64encode(qr_bytes).decode()
    mime_type = f"image/{format}"
    return f"data:{mime_type};base64,{b64_data}"


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


def _detect_wallet_from_user_agent(user_agent: str) -> tuple[str, str]:
    """Detect wallet type and version from user agent string.
    
    Args:
        user_agent: HTTP User-Agent header value
    
    Returns:
        Tuple of (wallet_type, wallet_version)
    """
    if not user_agent:
        return ("unknown", "")
    
    ua_lower = user_agent.lower()
    
    # Check for known wallet patterns
    wallet_patterns = [
        ("microsoft authenticator", "microsoft_authenticator"),
        ("spruce", "spruce_wallet"),
        ("walt.id", "waltid_wallet"),
        ("trinsic", "trinsic_wallet"),
        ("esatus", "esatus_wallet"),
        ("lissi", "lissi_wallet"),
        ("sphereon", "sphereon_wallet"),
        ("paradym", "paradym_wallet"),
        ("mattr", "mattr_wallet"),
        ("verimi", "verimi_wallet"),
    ]
    
    for pattern, wallet_type in wallet_patterns:
        if pattern in ua_lower:
            # Try to extract version
            version = ""
            if "/" in user_agent:
                parts = user_agent.split("/")
                for i, part in enumerate(parts):
                    if pattern in part.lower() and i + 1 < len(parts):
                        version = parts[i + 1].split()[0] if parts[i + 1] else ""
                        break
            return (wallet_type, version)
    
    # Check for mobile platforms
    if "android" in ua_lower:
        return ("android_wallet", "")
    elif "iphone" in ua_lower or "ipad" in ua_lower:
        return ("ios_wallet", "")
    
    return ("unknown", "")


async def _log_offer_access(
    db: AsyncSession,
    offer: CredentialOffer,
    session: IssuanceSession,
    access_type: str,
    user_agent: Optional[str],
    ip_address: Optional[str],
    outcome: str,
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> None:
    """Log an access to a credential offer.
    
    Args:
        db: Database session
        offer: The credential offer
        session: The issuance session
        access_type: Type of access (qr_view, offer_retrieval, token_exchange, etc.)
        user_agent: Client user agent string
        ip_address: Client IP address
        outcome: success, expired, error, unauthorized
        error_code: Optional error code
        error_message: Optional error message
        metadata: Additional context
    """
    wallet_type, wallet_version = _detect_wallet_from_user_agent(user_agent or "")
    
    log_entry = OfferAccessLog()
    log_entry.id = str(uuid.uuid4())
    log_entry.offer_id = offer.id
    log_entry.session_id = session.id
    log_entry.access_type = access_type
    log_entry.user_agent = user_agent
    log_entry.ip_address = ip_address
    log_entry.wallet_type = wallet_type if wallet_type != "unknown" else None
    log_entry.wallet_version = wallet_version if wallet_version else None
    log_entry.outcome = outcome
    log_entry.error_code = error_code
    log_entry.error_message = error_message
    log_entry.access_metadata = metadata  # Renamed from metadata to access_metadata
    log_entry.accessed_at = datetime.utcnow()
    
    db.add(log_entry)
    try:
        await db.commit()
    except Exception:
        # Don't fail the request if logging fails
        await db.rollback()


async def _create_credential_async(session: IssuanceSession, credential_format: Optional[str] = None) -> None:
    """Create credential asynchronously (placeholder).

    In production, this would be a background task that:
    1. Fetches the issuer signing key
    2. Builds the credential claims
    3. Signs the credential
    4. Updates the session with the result

    Args:
        session: The issuance session
        credential_format: Optional format override (for format negotiation)
    """
    # Use provided format or session default
    format_to_use = credential_format or session.credential_format
    
    # TODO: Implement actual credential creation with format_to_use
    # For now, simulate async processing
    session.status = IssuanceStatus.READY
    session.issued_credential = "eyJ...placeholder..."  # Placeholder
    session.credential_format = format_to_use  # Update session with negotiated format
    session.issued_at = datetime.utcnow()


def _get_supported_formats() -> list[str]:
    """Get list of credential formats supported by this issuer.
    
    Returns:
        List of supported format identifiers
    """
    return [
        "vc+sd-jwt",      # SD-JWT Verifiable Credential (selective disclosure)
        "jwt_vc_json",    # JWT VC (W3C Verifiable Credentials in JWT format)
        "mso_mdoc",       # ISO/IEC 18013-5 mobile driving license format
    ]


def _negotiate_credential_format(
    requested_format: str,
    session_format: str,
) -> tuple[str, bool]:
    """Negotiate credential format between wallet request and issuer capabilities.
    
    Args:
        requested_format: Format requested by the wallet
        session_format: Format stored in the issuance session
        
    Returns:
        Tuple of (negotiated_format, format_changed)
        
    Raises:
        HTTPException: If requested format is unsupported
    """
    supported_formats = _get_supported_formats()
    
    # Check if requested format is supported
    if requested_format in supported_formats:
        # Requested format is supported
        format_changed = requested_format != session_format
        return requested_format, format_changed
    
    # Requested format not supported - check if session format is valid
    if session_format in supported_formats:
        # Use session format as fallback
        return session_format, False
    
    # Neither format is supported (shouldn't happen in production)
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "error": "unsupported_credential_format",
            "error_description": f"Format '{requested_format}' is not supported",
            "supported_formats": supported_formats,
        },
    )


async def _fetch_deployment_profile_branding(
    deployment_profile_id: str,
) -> dict | None:
    """Fetch QR branding configuration from deployment profile service.
    
    Args:
        deployment_profile_id: The deployment profile ID
        
    Returns:
        Branding configuration dict or None if not found/unavailable
    """
    try:
        import httpx
        deployment_service_url = os.environ.get("DEPLOYMENT_PROFILE_SERVICE_URL", "http://deployment-profile-service:8014")
        
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(
                f"{deployment_service_url}/v1/deployment-profiles/{deployment_profile_id}"
            )
            
            if response.status_code == 200:
                profile = response.json()
                # Extract QR-specific branding fields
                branding = profile.get("branding", {})
                return {
                    "qr_size": branding.get("qr_size", 256),
                    "qr_foreground_color": branding.get("qr_foreground_color", "#000000"),
                    "qr_background_color": branding.get("qr_background_color", "#FFFFFF"),
                    "qr_logo_url": branding.get("qr_logo_url"),
                    "qr_logo_size_percent": branding.get("qr_logo_size_percent", 20),
                    "qr_border_color": branding.get("qr_border_color"),
                    "qr_border_width": branding.get("qr_border_width", 2),
                    "qr_error_correction": branding.get("qr_error_correction", "H"),
                    "qr_show_instructions": branding.get("qr_show_instructions", True),
                    "qr_custom_instruction_text": branding.get("qr_custom_instruction_text"),
                    "primary_color": branding.get("primary_color", "#1a1a2e"),
                    "secondary_color": branding.get("secondary_color", "#4a4a6a"),
                    "organization_name": branding.get("organization_name", ""),
                }
            return None
    except Exception as e:
        # Don't fail offer creation if branding fetch fails
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to fetch deployment profile branding: {e}")
        return None


async def _check_retry_policy(
    session: IssuanceSession,
    offer: CredentialOffer,
    max_retries: int = 3,
    cooldown_minutes: int = 5,
) -> RetryPolicyResponse:
    """Check if offer can be regenerated based on retry policy.
    
    Args:
        session: The issuance session
        offer: The current credential offer
        max_retries: Maximum number of retry attempts allowed
        cooldown_minutes: Minimum minutes between retry attempts
    
    Returns:
        RetryPolicyResponse with retry eligibility information
    """
    # Get attempt number from offer metadata (default to 1 for legacy offers)
    attempt_number = 1
    if hasattr(offer, 'metadata') and isinstance(offer.metadata, dict):
        attempt_number = offer.metadata.get('attempt_number', 1)
    
    # Check if max retries exceeded
    if attempt_number >= max_retries:
        return RetryPolicyResponse(
            can_retry=False,
            attempt_number=attempt_number,
            max_retries=max_retries,
            cooldown_minutes=cooldown_minutes,
            reason=f"Maximum retry attempts ({max_retries}) exceeded"
        )
    
    # Check cooldown period
    if cooldown_minutes > 0:
        last_attempt_time = offer.created_at
        cooldown_end = last_attempt_time + timedelta(minutes=cooldown_minutes)
        now = datetime.utcnow()
        
        if now < cooldown_end:
            return RetryPolicyResponse(
                can_retry=False,
                attempt_number=attempt_number,
                max_retries=max_retries,
                cooldown_minutes=cooldown_minutes,
                next_retry_at=cooldown_end,
                reason=f"Cooldown period active. Try again after {cooldown_end.isoformat()}"
            )
    
    # Retry allowed
    return RetryPolicyResponse(
        can_retry=True,
        attempt_number=attempt_number,
        max_retries=max_retries,
        cooldown_minutes=cooldown_minutes,
        next_retry_at=None,
        reason=None
    )


# ==================== API Endpoints ====================


@router.post("/offers", response_model=CredentialOfferResponse)
async def create_credential_offer(
    request: CreateOfferRequest,
    current_user: AuthStatusResponse = Depends(require_org_admin),
    issuer_url: str = Header(default="http://localhost:8000", alias="X-Issuer-URL"),
    user_agent: str = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """Create a credential offer for an applicant.

    Creates an OID4VCI credential offer that can be scanned by a wallet
    or pushed to a registered device. Supports both immediate and
    deferred issuance.
    
    Automatically adapts credential format to wallet capabilities if
    User-Agent header is provided.
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
    
    # Detect wallet and adapt credential format if User-Agent provided
    credential_format = request.credential_format
    if user_agent:
        try:
            import httpx
            import logging
            logger = logging.getLogger(__name__)
            
            wallet_service_url = os.environ.get("WALLET_SERVICE_URL", "http://wallet-service:8015")
            async with httpx.AsyncClient(timeout=2.0) as client:
                response = await client.post(
                    f"{wallet_service_url}/v1/wallets/detect",
                    json={"user_agent": user_agent}
                )
                if response.status_code == 200:
                    wallet_info = response.json()
                    supported_formats = wallet_info.get("supported_formats", [])
                    
                    # Adapt format if current format not supported
                    if supported_formats and credential_format not in supported_formats:
                        # Use recommended format from wallet
                        recommended = wallet_info.get("recommended_format")
                        if recommended and recommended in supported_formats:
                            credential_format = recommended
                            logger.info(
                                f"Adapted credential format from {request.credential_format} "
                                f"to {credential_format} for wallet {wallet_info.get('detected_vendor')}"
                            )
        except Exception as e:
            # Don't fail offer creation if wallet detection fails
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to detect wallet capabilities: {e}")

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
    session.applicant_id = request.applicant_id or request.subject_did or "unknown"
    session.subject_did = request.subject_did
    session.device_id = request.device_id
    session.status = IssuanceStatus.DEFERRED if request.deferred else IssuanceStatus.PENDING
    session.pre_authorized_code = pre_authorized_code
    session.credential_format = credential_format  # Use adapted format
    session.credential_data = request.credential_data
    session.expires_at = expiry
    session.created_at = datetime.utcnow()

    # Save session to database
    db.add(session)
    await db.flush()  # Flush to get ID generated

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
    offer.access_count = 0
    offer.expires_at = expiry
    offer.created_at = datetime.utcnow()

    # Save offer to database
    db.add(offer)
    await db.commit()

    # Generate QR code data URI
    qr_bytes = _generate_qr_code(offer_uri, format="png")
    qr_data_uri = _generate_qr_data_uri(qr_bytes, format="png")
    
    # Update offer with QR code data
    offer.qr_code_data = qr_data_uri
    await db.commit()

    # Fetch deployment profile branding if specified
    branding = None
    if request.deployment_profile_id:
        branding = await _fetch_deployment_profile_branding(request.deployment_profile_id)

    # If deferred, start async credential creation
    if request.deferred:
        # In production, this would queue a background task
        await _create_credential_async(session)

    # Log audit event for offer creation
    try:
        from audit import log_audit_event
        await log_audit_event(
            db=db,
            event_type=AuditEventType.CREDENTIAL_OFFER_CREATED,
            user_id=user.user_id,
            user_email=user.email,
            organization_id=org_id,
            target_user_id=request.applicant_id or request.subject_did,
            target_user_email=None,  # Could be looked up if needed
            details={
                "transaction_id": transaction_id,
                "offer_id": offer.id,
                "credential_config_id": request.credential_config_id,
                "credential_format": credential_format,
                "deferred": request.deferred,
                "application_id": request.application_id,
            },
        )
    except Exception as e:
        # Don't fail offer creation if audit logging fails
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to log audit event for offer creation: {e}")

    # Extract HTTP endpoint from deep link for reference
    from urllib.parse import parse_qs, urlparse
    parsed = urlparse(offer_uri)
    offer_endpoint = None
    if parsed.scheme == 'openid-credential-offer':
        params = parse_qs(parsed.query)
        if 'credential_offer_uri' in params:
            offer_endpoint = params['credential_offer_uri'][0]
    
    return CredentialOfferResponse(
        transaction_id=transaction_id,
        credential_offer_uri=offer_uri,
        offer_endpoint=offer_endpoint,
        deep_link_uri=offer_uri,  # Explicit deep link field
        pre_authorized_code=pre_authorized_code,
        expires_at=expiry,
        status=session.status,
        qr_code_data=qr_data_uri,
        branding=branding,
    )


@router.get("/offers/{offer_id}")
async def get_credential_offer(
    offer_id: str,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
    x_forwarded_for: Optional[str] = Header(None, alias="X-Forwarded-For"),
    x_real_ip: Optional[str] = Header(None, alias="X-Real-IP"),
    db: AsyncSession = Depends(get_db),
):
    """Get credential offer payload (for wallet retrieval).

    This endpoint is called by the wallet when it dereferences
    the credential_offer_uri from a QR code or push notification.
    
    Logs every access for analytics and security monitoring.
    """
    # Determine client IP
    ip_address = x_real_ip or x_forwarded_for or None
    if ip_address and "," in ip_address:
        # Take first IP from X-Forwarded-For chain
        ip_address = ip_address.split(",")[0].strip()
    
    # Query offer from database
    result = await db.execute(
        select(CredentialOffer).where(
            or_(
                CredentialOffer.id == offer_id,
                CredentialOffer.issuance_session_id == offer_id
            )
        )
    )
    offer = result.scalar_one_or_none()
    
    if not offer:
        # Log failed access
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential offer not found",
        )
    
    # Get associated session
    result = await db.execute(
        select(IssuanceSession).where(IssuanceSession.id == offer.issuance_session_id)
    )
    session = result.scalar_one_or_none()
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Issuance session not found",
        )
    
    # Check if offer is active
    if not offer.is_active:
        await _log_offer_access(
            db=db,
            offer=offer,
            session=session,
            access_type="offer_retrieval",
            user_agent=user_agent,
            ip_address=ip_address,
            outcome="error",
            error_code="offer_consumed",
            error_message="Credential offer has been consumed",
        )
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Credential offer has been consumed",
        )
    
    # Check if offer is expired
    if datetime.utcnow() > offer.expires_at:
        await _log_offer_access(
            db=db,
            offer=offer,
            session=session,
            access_type="offer_retrieval",
            user_agent=user_agent,
            ip_address=ip_address,
            outcome="expired",
            error_code="offer_expired",
            error_message="Credential offer has expired",
        )
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Credential offer has expired",
        )
    
    # Track access
    offer.access_count += 1
    offer.accessed_at = datetime.utcnow()
    
    # Log successful access
    await _log_offer_access(
        db=db,
        offer=offer,
        session=session,
        access_type="offer_retrieval",
        user_agent=user_agent,
        ip_address=ip_address,
        outcome="success",
    )
    
    # Log audit event for offer access
    try:
        from audit import log_audit_event
        await log_audit_event(
            db=db,
            event_type=AuditEventType.CREDENTIAL_OFFER_ACCESSED,
            user_id="wallet_client",  # Wallet client, not a user
            user_email="system",
            organization_id=session.organization_id,
            target_user_id=session.applicant_id,
            target_user_email=None,
            details={
                "transaction_id": session.transaction_id,
                "offer_id": offer.id,
                "wallet_type": _detect_wallet_from_user_agent(user_agent or "")[0],
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except Exception as e:
        # Don't fail offer retrieval if audit logging fails
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to log audit event for offer access: {e}")
    
    await db.commit()

    return JSONResponse(content=offer.offer_payload)


@router.get("/offers/{offer_id}/qr")
async def get_qr_code(
    offer_id: str,
    format: str = "png",
    db: AsyncSession = Depends(get_db),
):
    """Get QR code image for a credential offer.
    
    Args:
        offer_id: The credential offer ID
        format: Image format - "png" (default) or "svg"
    
    Returns:
        QR code image as PNG or SVG
    """
    # Query the offer from database
    result = await db.execute(
        select(CredentialOffer).where(
            or_(
                CredentialOffer.id == offer_id,
                CredentialOffer.issuance_session_id == offer_id
            )
        )
    )
    offer = result.scalar_one_or_none()
    
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
        # Get session for retry policy check
        result = await db.execute(
            select(IssuanceSession).where(IssuanceSession.id == offer.issuance_session_id)
        )
        session = result.scalar_one_or_none()
        
        # Include retry policy info in error response
        if session:
            retry_policy = await _check_retry_policy(session, offer, max_retries=3, cooldown_minutes=5)
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="Credential offer has expired",
                headers={
                    "X-Retry-Policy": retry_policy.model_dump_json(),
                    "X-Can-Retry": str(retry_policy.can_retry).lower(),
                }
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="Credential offer has expired",
            )

    # Generate QR code
    qr_bytes = _generate_qr_code(offer.offer_uri, format=format)
    
    # Return as image
    media_type = f"image/{format}" if format in ["png", "svg"] else "image/png"
    return Response(
        content=qr_bytes,
        media_type=media_type,
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        }
    )


@router.post("/offers/{offer_id}/regenerate", response_model=CredentialOfferResponse)
async def regenerate_credential_offer(
    offer_id: str,
    request: RegenerateOfferRequest,
    current_user: AuthStatusResponse = Depends(require_org_admin),
    issuer_url: str = Header(default="http://localhost:8000", alias="X-Issuer-URL"),
    db: AsyncSession = Depends(get_db),
):
    """Regenerate an expired credential offer with retry policy enforcement.
    
    This endpoint allows regenerating expired QR codes while enforcing:
    - Maximum retry attempts (configurable per flow)
    - Cooldown period between retries
    - Attempt number tracking
    
    Args:
        offer_id: The expired offer ID or session ID
        request: Regeneration request with optional force flag
        current_user: Authenticated user (org admin required)
        issuer_url: Issuer base URL from header
        db: Database session
    
    Returns:
        New credential offer with fresh QR code
    
    Raises:
        404: Offer/session not found
        403: Not authorized
        400: Retry policy violation (max attempts exceeded, cooldown active)
        409: Offer still active (not expired)
    """
    user = current_user.user
    roles = user.roles or []
    is_platform_admin = "platform_admin" in roles or "admin" in roles or "administrator" in roles
    
    # Look up existing offer
    result = await db.execute(
        select(CredentialOffer).where(
            or_(
                CredentialOffer.id == offer_id,
                CredentialOffer.issuance_session_id == offer_id
            )
        )
    )
    old_offer = result.scalar_one_or_none()
    
    if not old_offer:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Credential offer not found",
        )
    
    # Get associated session
    result = await db.execute(
        select(IssuanceSession).where(IssuanceSession.id == old_offer.issuance_session_id)
    )
    session = result.scalar_one_or_none()
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Issuance session not found",
        )
    
    # Check authorization
    if not is_platform_admin and session.organization_id != user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to regenerate this offer",
        )
    
    # Check if offer is actually expired
    if old_offer.is_active and datetime.utcnow() <= old_offer.expires_at:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Offer is still active and has not expired",
        )
    
    # Check retry policy (unless force is specified and user is admin)
    if not (request.force and is_platform_admin):
        # Default retry policy - could be fetched from flow definition
        max_retries = 3
        cooldown_minutes = 5
        
        retry_policy = await _check_retry_policy(session, old_offer, max_retries, cooldown_minutes)
        
        if not retry_policy.can_retry:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=retry_policy.reason,
                headers={
                    "X-Retry-Policy": retry_policy.model_dump_json(),
                }
            )
    
    # Deactivate old offer
    old_offer.is_active = False
    await db.flush()
    
    # Get new attempt number
    new_attempt = 1
    if hasattr(old_offer, 'metadata') and isinstance(old_offer.metadata, dict):
        new_attempt = old_offer.metadata.get('attempt_number', 1) + 1
    else:
        new_attempt = 2  # This is a retry, so at least attempt 2
    
    # Generate new offer
    new_offer_id = str(uuid.uuid4())
    new_pre_auth_code = _generate_pre_authorized_code()
    new_expiry = datetime.utcnow() + timedelta(seconds=OFFER_EXPIRY_SECONDS)
    
    # Update session
    session.pre_authorized_code = new_pre_auth_code
    session.expires_at = new_expiry
    
    # Build new offer
    offer_payload = _build_credential_offer(session, issuer_url)
    offer_uri = _build_credential_offer_uri(session.id, issuer_url)
    
    # Create new offer record
    new_offer = CredentialOffer()
    new_offer.id = new_offer_id
    new_offer.issuance_session_id = session.id
    new_offer.offer_uri = offer_uri
    new_offer.offer_payload = offer_payload
    new_offer.is_active = True
    new_offer.access_count = 0
    new_offer.expires_at = new_expiry
    new_offer.created_at = datetime.utcnow()
    new_offer.metadata = {'attempt_number': new_attempt}
    
    # Generate new QR code
    qr_bytes = _generate_qr_code(offer_uri, format="png")
    qr_data_uri = _generate_qr_data_uri(qr_bytes, format="png")
    new_offer.qr_code_data = qr_data_uri
    
    # Save to database
    db.add(new_offer)
    await db.commit()
    
    # Log audit event for offer regeneration
    try:
        from audit import log_audit_event
        await log_audit_event(
            db=db,
            event_type=AuditEventType.CREDENTIAL_OFFER_REGENERATED,
            user_id=user.user_id,
            user_email=user.email,
            organization_id=session.organization_id,
            target_user_id=session.applicant_id,
            target_user_email=None,
            details={
                "transaction_id": session.transaction_id,
                "old_offer_id": old_offer.id,
                "new_offer_id": new_offer.id,
                "attempt_number": new_attempt,
                "forced": request.force,
            },
        )
    except Exception as e:
        # Don't fail offer regeneration if audit logging fails
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to log audit event for offer regeneration: {e}")
    
    # Fetch branding if session has deployment_profile_id in context
    branding = None
    # Note: In production, deployment_profile_id would be stored in session context
    # For now, branding would need to be passed through or retrieved from organization settings
    
    # Extract HTTP endpoint from deep link for reference
    from urllib.parse import parse_qs, urlparse
    parsed = urlparse(offer_uri)
    offer_endpoint = None
    if parsed.scheme == 'openid-credential-offer':
        params = parse_qs(parsed.query)
        if 'credential_offer_uri' in params:
            offer_endpoint = params['credential_offer_uri'][0]
    
    return CredentialOfferResponse(
        transaction_id=session.transaction_id,
        credential_offer_uri=offer_uri,
        offer_endpoint=offer_endpoint,
        deep_link_uri=offer_uri,  # Explicit deep link field
        pre_authorized_code=new_pre_auth_code,
        expires_at=new_expiry,
        status=session.status,
        qr_code_data=qr_data_uri,
        branding=branding,
    )


@router.get("/offers", response_model=OfferListResponse)
async def list_credential_offers(
    organization_id: Optional[str] = None,
    status: Optional[str] = None,
    is_active: Optional[bool] = None,
    page: int = 1,
    page_size: int = 50,
    current_user: AuthStatusResponse = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List credential offers with filters and pagination.
    
    Vendor portal endpoint to display all offers for an organization,
    with filtering by status, active state, and pagination.
    
    Args:
        organization_id: Filter by organization (optional, defaults to user's org)
        status: Filter by session status (pending, ready, issued, expired, error)
        is_active: Filter by active/inactive offers
        page: Page number (1-indexed)
        page_size: Items per page (max 100)
        current_user: Authenticated user
        db: Database session
    
    Returns:
        Paginated list of offers with session and access details
    
    Raises:
        401: Not authenticated
        403: Not authorized to view organization's offers
    """
    if not current_user.authenticated or not current_user.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    
    user = current_user.user
    roles = user.roles or []
    is_platform_admin = "platform_admin" in roles or "admin" in roles or "administrator" in roles
    
    # Determine target organization
    target_org_id = organization_id if organization_id else user.organization_id
    
    # Check authorization
    if not is_platform_admin and target_org_id != user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view offers for this organization",
        )
    
    # Validate pagination
    if page < 1:
        page = 1
    if page_size < 1 or page_size > 100:
        page_size = 50
    
    # Build query
    query = (
        select(CredentialOffer, IssuanceSession)
        .join(IssuanceSession, CredentialOffer.issuance_session_id == IssuanceSession.id)
        .where(IssuanceSession.organization_id == target_org_id)
    )
    
    # Apply filters
    if status:
        try:
            status_enum = IssuanceStatus(status)
            query = query.where(IssuanceSession.status == status_enum)
        except ValueError:
            pass  # Ignore invalid status values
    
    if is_active is not None:
        query = query.where(CredentialOffer.is_active == is_active)
    
    # Order by created_at descending (newest first)
    query = query.order_by(CredentialOffer.created_at.desc())
    
    # Get total count
    count_query = select(func.count()).select_from(
        select(CredentialOffer.id)
        .join(IssuanceSession, CredentialOffer.issuance_session_id == IssuanceSession.id)
        .where(IssuanceSession.organization_id == target_org_id)
        .subquery()
    )
    if status:
        try:
            status_enum = IssuanceStatus(status)
            count_query = count_query.where(IssuanceSession.status == status_enum)
        except ValueError:
            pass
    if is_active is not None:
        count_query = count_query.where(CredentialOffer.is_active == is_active)
    
    total_result = await db.execute(count_query)
    total = total_result.scalar()
    
    # Apply pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    
    # Execute query
    result = await db.execute(query)
    rows = result.all()
    
    # Build response items
    offers = []
    for offer, session in rows:
        # Determine if expired
        is_expired = datetime.utcnow() > offer.expires_at
        
        # Extract HTTP endpoint from deep link
        from urllib.parse import parse_qs, urlparse
        offer_endpoint = None
        deep_link_uri = offer.offer_uri
        if offer.offer_uri.startswith('openid-credential-offer://'):
            parsed = urlparse(offer.offer_uri)
            params = parse_qs(parsed.query)
            if 'credential_offer_uri' in params:
                offer_endpoint = params['credential_offer_uri'][0]
        
        # Extract attempt number from metadata
        attempt_number = 1
        if hasattr(offer, 'metadata') and isinstance(offer.metadata, dict):
            attempt_number = offer.metadata.get('attempt_number', 1)
        
        offers.append(OfferListItemResponse(
            offer_id=offer.id,
            session_id=session.id,
            transaction_id=session.transaction_id,
            organization_id=session.organization_id,
            credential_config_id=session.credential_config_id,
            applicant_id=session.applicant_id,
            application_id=session.application_id,
            subject_did=session.subject_did,
            status=session.status,
            is_active=offer.is_active,
            is_expired=is_expired,
            credential_offer_uri=offer.offer_uri,
            offer_endpoint=offer_endpoint,
            deep_link_uri=deep_link_uri,
            qr_code_data=offer.qr_code_data,
            access_count=offer.access_count,
            accessed_at=offer.accessed_at,
            created_at=offer.created_at,
            expires_at=offer.expires_at,
            issued_at=session.issued_at,
            attempt_number=attempt_number,
            credential_format=session.credential_format,
        ))
    
    # Determine if there are more pages
    has_more = (offset + len(offers)) < total
    
    return OfferListResponse(
        offers=offers,
        total=total,
        page=page,
        page_size=page_size,
        has_more=has_more,
    )


@router.get("/analytics/summary", response_model=AnalyticsSummaryResponse)
async def get_analytics_summary(
    organization_id: Optional[str] = None,
    days: int = 30,
    current_user: AuthStatusResponse = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get analytics summary for credential offers.
    
    Provides high-level metrics including:
    - Total and active offer counts
    - Scan statistics
    - Success rates
    - Wallet type distribution
    - Recent activity
    
    Args:
        organization_id: Filter by organization (defaults to user's org)
        days: Number of days to include in summary (default 30)
        current_user: Authenticated user
        db: Database session
    
    Returns:
        Analytics summary with key metrics
    """
    if not current_user.authenticated or not current_user.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    
    user = current_user.user
    roles = user.roles or []
    is_platform_admin = "platform_admin" in roles or "admin" in roles or "administrator" in roles
    
    # Determine target organization
    target_org_id = organization_id if organization_id else user.organization_id
    
    # Check authorization
    if not is_platform_admin and target_org_id != user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view analytics for this organization",
        )
    
    # Calculate date range
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    # Get total offers
    total_result = await db.execute(
        select(func.count(CredentialOffer.id))
        .join(IssuanceSession, CredentialOffer.issuance_session_id == IssuanceSession.id)
        .where(
            and_(
                IssuanceSession.organization_id == target_org_id,
                CredentialOffer.created_at >= cutoff_date
            )
        )
    )
    total_offers = total_result.scalar() or 0
    
    # Get active offers
    active_result = await db.execute(
        select(func.count(CredentialOffer.id))
        .join(IssuanceSession, CredentialOffer.issuance_session_id == IssuanceSession.id)
        .where(
            and_(
                IssuanceSession.organization_id == target_org_id,
                CredentialOffer.is_active == True,
                CredentialOffer.expires_at > datetime.utcnow()
            )
        )
    )
    active_offers = active_result.scalar() or 0
    
    # Get total scans
    scans_result = await db.execute(
        select(func.count(OfferAccessLog.id))
        .join(IssuanceSession, OfferAccessLog.session_id == IssuanceSession.id)
        .where(
            and_(
                IssuanceSession.organization_id == target_org_id,
                OfferAccessLog.accessed_at >= cutoff_date
            )
        )
    )
    total_scans = scans_result.scalar() or 0
    
    # Get unique wallet types
    wallets_result = await db.execute(
        select(func.count(func.distinct(OfferAccessLog.wallet_type)))
        .join(IssuanceSession, OfferAccessLog.session_id == IssuanceSession.id)
        .where(
            and_(
                IssuanceSession.organization_id == target_org_id,
                OfferAccessLog.accessed_at >= cutoff_date,
                OfferAccessLog.wallet_type != None
            )
        )
    )
    unique_wallets = wallets_result.scalar() or 0
    
    # Calculate success rate
    success_result = await db.execute(
        select(func.count(OfferAccessLog.id))
        .join(IssuanceSession, OfferAccessLog.session_id == IssuanceSession.id)
        .where(
            and_(
                IssuanceSession.organization_id == target_org_id,
                OfferAccessLog.accessed_at >= cutoff_date,
                OfferAccessLog.outcome == "success"
            )
        )
    )
    successful_scans = success_result.scalar() or 0
    success_rate = (successful_scans / total_scans * 100) if total_scans > 0 else 0.0
    
    # Average scans per offer
    avg_scans = (total_scans / total_offers) if total_offers > 0 else 0.0
    
    # Top wallet types
    wallet_types_result = await db.execute(
        select(
            OfferAccessLog.wallet_type,
            func.count(OfferAccessLog.id).label('count')
        )
        .join(IssuanceSession, OfferAccessLog.session_id == IssuanceSession.id)
        .where(
            and_(
                IssuanceSession.organization_id == target_org_id,
                OfferAccessLog.accessed_at >= cutoff_date,
                OfferAccessLog.wallet_type != None
            )
        )
        .group_by(OfferAccessLog.wallet_type)
        .order_by(func.count(OfferAccessLog.id).desc())
        .limit(5)
    )
    top_wallet_types = [
        {"wallet_type": row[0], "count": row[1]}
        for row in wallet_types_result.all()
    ]
    
    # Recent activity (last 10 scans)
    recent_result = await db.execute(
        select(OfferAccessLog)
        .join(IssuanceSession, OfferAccessLog.session_id == IssuanceSession.id)
        .where(IssuanceSession.organization_id == target_org_id)
        .order_by(OfferAccessLog.accessed_at.desc())
        .limit(10)
    )
    recent_scans = recent_result.scalars().all()
    recent_activity = [
        {
            "access_type": scan.access_type,
            "wallet_type": scan.wallet_type,
            "outcome": scan.outcome,
            "accessed_at": scan.accessed_at.isoformat(),
        }
        for scan in recent_scans
    ]
    
    return AnalyticsSummaryResponse(
        total_offers=total_offers,
        active_offers=active_offers,
        total_scans=total_scans,
        unique_wallets=unique_wallets,
        success_rate=round(success_rate, 2),
        avg_scans_per_offer=round(avg_scans, 2),
        top_wallet_types=top_wallet_types,
        recent_activity=recent_activity,
    )


@router.get("/analytics/scans", response_model=ScanListResponse)
async def list_scan_logs(
    organization_id: Optional[str] = None,
    offer_id: Optional[str] = None,
    access_type: Optional[str] = None,
    outcome: Optional[str] = None,
    wallet_type: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
    current_user: AuthStatusResponse = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List scan logs with filtering and pagination.
    
    Provides detailed access logs for debugging and analytics.
    
    Args:
        organization_id: Filter by organization
        offer_id: Filter by specific offer
        access_type: Filter by access type (qr_view, offer_retrieval, etc.)
        outcome: Filter by outcome (success, error, expired)
        wallet_type: Filter by wallet type
        page: Page number (1-indexed)
        page_size: Items per page (max 100)
        current_user: Authenticated user
        db: Database session
    
    Returns:
        Paginated list of scan logs
    """
    if not current_user.authenticated or not current_user.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    
    user = current_user.user
    roles = user.roles or []
    is_platform_admin = "platform_admin" in roles or "admin" in roles or "administrator" in roles
    
    # Determine target organization
    target_org_id = organization_id if organization_id else user.organization_id
    
    # Check authorization
    if not is_platform_admin and target_org_id != user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view scan logs for this organization",
        )
    
    # Validate pagination
    if page < 1:
        page = 1
    if page_size < 1 or page_size > 100:
        page_size = 50
    
    # Build query
    query = (
        select(OfferAccessLog, IssuanceSession.transaction_id)
        .join(IssuanceSession, OfferAccessLog.session_id == IssuanceSession.id)
        .where(IssuanceSession.organization_id == target_org_id)
    )
    
    # Apply filters
    if offer_id:
        query = query.where(OfferAccessLog.offer_id == offer_id)
    if access_type:
        query = query.where(OfferAccessLog.access_type == access_type)
    if outcome:
        query = query.where(OfferAccessLog.outcome == outcome)
    if wallet_type:
        query = query.where(OfferAccessLog.wallet_type == wallet_type)
    
    # Order by accessed_at descending (newest first)
    query = query.order_by(OfferAccessLog.accessed_at.desc())
    
    # Get total count
    count_query = select(func.count()).select_from(
        select(OfferAccessLog.id)
        .join(IssuanceSession, OfferAccessLog.session_id == IssuanceSession.id)
        .where(IssuanceSession.organization_id == target_org_id)
        .subquery()
    )
    if offer_id:
        count_query = count_query.where(OfferAccessLog.offer_id == offer_id)
    if access_type:
        count_query = count_query.where(OfferAccessLog.access_type == access_type)
    if outcome:
        count_query = count_query.where(OfferAccessLog.outcome == outcome)
    if wallet_type:
        count_query = count_query.where(OfferAccessLog.wallet_type == wallet_type)
    
    total_result = await db.execute(count_query)
    total = total_result.scalar() or 0
    
    # Apply pagination
    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    
    # Execute query
    result = await db.execute(query)
    rows = result.all()
    
    # Build response
    scans = []
    for log, transaction_id in rows:
        scans.append(ScanLogResponse(
            id=log.id,
            offer_id=log.offer_id,
            session_id=log.session_id,
            transaction_id=transaction_id,
            access_type=log.access_type,
            wallet_type=log.wallet_type,
            wallet_version=log.wallet_version,
            outcome=log.outcome,
            error_code=log.error_code,
            ip_address=log.ip_address,
            accessed_at=log.accessed_at,
        ))
    
    # Determine if there are more pages
    has_more = (offset + len(scans)) < total
    
    return ScanListResponse(
        scans=scans,
        total=total,
        page=page,
        page_size=page_size,
        has_more=has_more,
    )


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
    and optional proof of possession. Supports format negotiation
    where the wallet can request a specific credential format.
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

    # Format negotiation: check if wallet's requested format is supported
    negotiated_format, format_changed = _negotiate_credential_format(
        requested_format=request.format,
        session_format=session.credential_format,
    )
    
    # Log audit event for format negotiation if format changed
    if format_changed:
        try:
            from audit import log_audit_event
            await log_audit_event(
                db=None,  # We don't have db dependency in this old code, would need db session
                event_type=AuditEventType.CREDENTIAL_FORMAT_NEGOTIATED,
                user_id="wallet_client",
                user_email="system",
                organization_id=session.organization_id,
                target_user_id=session.applicant_id,
                target_user_email=None,
                details={
                    "transaction_id": session.transaction_id,
                    "original_format": session.credential_format,
                    "negotiated_format": negotiated_format,
                    "requested_format": request.format,
                },
            )
        except Exception as e:
            # Don't fail credential issuance if audit logging fails
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Failed to log audit event for format negotiation: {e}")
    
    # If format changed and credential already generated, regenerate it
    if format_changed and session.issued_credential:
        import logging
        logger = logging.getLogger(__name__)
        logger.info(
            f"Regenerating credential in format {negotiated_format} "
            f"(was {session.credential_format}) for transaction {transaction_id}"
        )
        # Clear existing credential to force regeneration
        session.issued_credential = None

    # Generate new c_nonce for potential retry
    new_c_nonce = _generate_c_nonce()
    session.c_nonce = new_c_nonce
    session.c_nonce_expires_at = datetime.utcnow() + timedelta(minutes=5)

    # If credential not yet generated, create it now with negotiated format
    if not session.issued_credential:
        await _create_credential_async(session, credential_format=negotiated_format)

    # Update session status
    session.status = IssuanceStatus.ISSUED
    session.issued_at = datetime.utcnow()

    # Log audit event for credential issuance
    try:
        from audit import log_audit_event
        # Note: In production, we'd need proper db session here
        # For now, this demonstrates the audit logging integration
        # await log_audit_event(
        #     db=db,  # Would need db session
        #     event_type=AuditEventType.CREDENTIAL_ISSUED,
        #     user_id="wallet_client",
        #     user_email="system",
        #     organization_id=session.organization_id,
        #     target_user_id=session.applicant_id,
        #     target_user_email=None,
        #     details={
        #         "transaction_id": session.transaction_id,
        #         "credential_format": negotiated_format,
        #         "format_negotiated": format_changed,
        #     },
        # )
        pass  # Placeholder until db session is available
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to log audit event for credential issuance: {e}")

    return CredentialResponse(
        format=negotiated_format,  # Return negotiated format
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
    supported credential types, formats, and endpoints.
    """
    # TODO: Build from CredentialTypeConfiguration records
    # For now, return a placeholder
    base_url = f"http://localhost:8000"
    supported_formats = _get_supported_formats()

    return {
        "credential_issuer": f"{base_url}/api/issuance/{org_id}",
        "authorization_servers": [base_url],
        "credential_endpoint": f"{base_url}/api/issuance/credential",
        "deferred_credential_endpoint": f"{base_url}/api/issuance/deferred",
        "token_endpoint": f"{base_url}/api/issuance/token",
        "credential_configurations_supported": {
            # Generic configuration showing supported formats
            "default": {
                "format": supported_formats,
                "cryptographic_binding_methods_supported": ["jwk", "did"],
                "credential_signing_alg_values_supported": ["ES256", "EdDSA"],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["ES256", "EdDSA"]
                    }
                },
                "display": [
                    {
                        "name": "Verifiable Credential",
                        "locale": "en",
                    }
                ],
            }
            # TODO: Add specific configurations per credential type from database
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
# Use get_key_manager() from marty_credentials.adapters.credentials.spruceid
