"""Device and Push Challenge API Router.

Provides endpoints for device registration and push challenge management.

Endpoints:
- POST /api/devices/register - Register a device for push notifications
- GET /api/devices/{device_id} - Get device info
- DELETE /api/devices/{device_id} - Unregister device
- POST /api/push/challenges - Create a push challenge
- GET /api/push/challenges/pending - Get pending challenges for device
- POST /api/push/challenges/{challenge_id}/respond - Respond to challenge
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Header, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from subscription.models import (
    DeviceRegistration,
    PushChallenge,
    PushChallengeStatus,
)
from subscription.database import get_db_session

# SSE (Server-Sent Events) service imports for real-time notifications
try:
    import sys
    from pathlib import Path
    # Add main src directory to path for full notifications module
    _main_src = Path(__file__).parent.parent.parent.parent / "src"
    if _main_src.exists():
        sys.path.insert(0, str(_main_src))
    sys.path.insert(0, '/app')  # For Docker context
    from notifications.adapters.sse import SSEAdapter
    SSE_SERVICE_AVAILABLE = True
except ImportError:
    SSE_SERVICE_AVAILABLE = False

logger = logging.getLogger(__name__)

router = APIRouter(tags=["devices"])


# =============================================================================
# Request/Response Models
# =============================================================================


class RegisterDeviceRequest(BaseModel):
    """Request to register a device."""
    
    device_id: str = Field(..., min_length=1, max_length=255, description="Unique device identifier")
    fcm_token: str | None = Field(None, max_length=512, description="Firebase Cloud Messaging token")
    platform: str = Field(..., pattern="^(ios|android|web)$", description="Device platform")
    app_version: str | None = Field(None, max_length=50)
    os_version: str | None = Field(None, max_length=50)
    device_model: str | None = Field(None, max_length=100)
    public_key: str | None = Field(None, description="Base64-encoded DER public key for challenge signing")
    organization_id: str | None = Field(None, description="Organization ID for org-scoped push notifications")


class DeviceInfo(BaseModel):
    """Device information response."""
    
    device_id: str
    user_id: str
    platform: str
    app_version: str | None
    is_active: bool
    has_public_key: bool
    key_id: str | None
    last_seen_at: str | None
    created_at: str


class RegisterDeviceResponse(BaseModel):
    """Response after registering device."""
    
    success: bool
    device_id: str
    registration_id: str | None = None  # Internal ID for the registration
    organization_id: str | None = None  # Organization extracted from device_id if present
    message: str


class CreateChallengeRequest(BaseModel):
    """Request to create a push challenge."""
    
    device_id: str = Field(..., min_length=1, description="Target device ID")
    title: str = Field(..., min_length=1, max_length=255, description="Challenge title")
    question: str = Field(..., min_length=1, description="Challenge question/prompt")
    nonce: str | None = Field(None, description="Custom nonce (auto-generated if not provided)")
    ttl_seconds: int = Field(120, ge=30, le=3600, description="Time to live in seconds")
    credential_id: str | None = Field(None, description="Optional associated credential ID")
    data: dict | None = Field(None, description="Optional additional data for the challenge")


class ChallengeInfo(BaseModel):
    """Challenge information."""
    
    challenge_id: str
    device_id: str
    title: str
    question: str
    nonce: str
    credential_id: str | None
    data: dict | None = None
    status: str
    expires_at: str
    created_at: str


class CreateChallengeResponse(BaseModel):
    """Response after creating challenge."""
    
    challenge_id: str
    device_id: str
    nonce: str
    expires_at: str


class PendingChallengesResponse(BaseModel):
    """Response with pending challenges."""
    
    challenges: list[ChallengeInfo]


class RespondChallengeRequest(BaseModel):
    """Request to respond to a challenge."""
    
    # Accept either 'accept'/'reject' string or boolean
    response: str | None = Field(None, description="Response: 'accept' or 'reject'")
    accept: bool | None = Field(None, description="Whether to accept or reject (alternative to response)")
    signature: str | None = Field(None, description="Base64-encoded signature over nonce")
    
    @property
    def is_accepted(self) -> bool:
        """Get whether the response is acceptance."""
        if self.response is not None:
            return self.response.lower() == 'accept'
        return bool(self.accept)


class RespondChallengeResponse(BaseModel):
    """Response after responding to challenge."""
    
    success: bool
    challenge_id: str
    status: str
    response: str  # 'accept' or 'reject'
    message: str


# =============================================================================
# Helper Functions
# =============================================================================


def compute_key_id(public_key_base64: str) -> str:
    """Compute key ID from public key (first 16 chars of SHA-256 hex)."""
    key_bytes = base64.b64decode(public_key_base64)
    hash_hex = hashlib.sha256(key_bytes).hexdigest()
    return hash_hex[:16]


def _challenge_to_info(challenge: PushChallenge) -> ChallengeInfo:
    """Convert database model to response model."""
    return ChallengeInfo(
        challenge_id=challenge.id,
        device_id=challenge.device_id,
        title=challenge.title,
        question=challenge.question,
        nonce=challenge.nonce,
        credential_id=challenge.credential_id,
        data=challenge.data,
        status=challenge.status.value,
        expires_at=challenge.expires_at.isoformat(),
        created_at=challenge.created_at.isoformat() if challenge.created_at else "",
    )


# =============================================================================
# Device Endpoints
# =============================================================================


@router.post("/api/devices/register", response_model=RegisterDeviceResponse, status_code=201)
async def register_device(
    body: RegisterDeviceRequest,
    x_user_id: str = Header(..., alias="X-User-ID", description="User ID from auth"),
    db: AsyncSession = Depends(get_db_session),
):
    """Register a device for push notifications."""
    # Check if device already exists
    result = await db.execute(
        select(DeviceRegistration).where(DeviceRegistration.device_id == body.device_id)
    )
    existing = result.scalar_one_or_none()
    
    key_id = None
    if body.public_key:
        key_id = compute_key_id(body.public_key)
    
    if existing:
        # Update existing registration
        existing.user_id = x_user_id
        existing.fcm_token = body.fcm_token
        existing.platform = body.platform
        existing.app_version = body.app_version
        existing.os_version = body.os_version
        existing.device_model = body.device_model
        existing.public_key = body.public_key
        existing.key_id = key_id
        existing.is_active = True
        existing.last_seen_at = datetime.utcnow()
        existing.updated_at = datetime.utcnow()
        
        # Handle organization_id - explicit param takes precedence over device_id prefix
        org_id = body.organization_id
        if not org_id and ":" in body.device_id:
            org_id = body.device_id.split(":")[0]
        existing.organization_id = org_id
        
        await db.commit()
        
        logger.info(f"Updated device registration: device={body.device_id}, user={x_user_id}, org={org_id}")
        return RegisterDeviceResponse(
            success=True,
            device_id=body.device_id,
            registration_id=existing.id,
            organization_id=org_id,
            message="Device registration updated",
        )
    
    # Create new registration
    # Handle organization_id - explicit param takes precedence over device_id prefix
    org_id = body.organization_id
    if not org_id and ":" in body.device_id:
        org_id = body.device_id.split(":")[0]
    
    registration_id = str(uuid4())
    registration = DeviceRegistration(
        id=registration_id,
        device_id=body.device_id,
        user_id=x_user_id,
        organization_id=org_id,
        fcm_token=body.fcm_token,
        platform=body.platform,
        app_version=body.app_version,
        os_version=body.os_version,
        device_model=body.device_model,
        public_key=body.public_key,
        key_id=key_id,
        is_active=True,
        last_seen_at=datetime.utcnow(),
    )
    
    db.add(registration)
    await db.commit()
    
    logger.info(f"Registered new device: device={body.device_id}, user={x_user_id}, org={org_id}")
    return RegisterDeviceResponse(
        success=True,
        device_id=body.device_id,
        registration_id=registration_id,
        organization_id=org_id,
        message="Device registered successfully",
    )


class DeviceListResponse(BaseModel):
    """List of devices response."""
    
    devices: list[DeviceInfo]
    total: int


@router.get("/api/devices", response_model=DeviceListResponse)
async def list_devices(
    organization_id: str | None = None,
    x_user_id: str = Header(..., alias="X-User-ID"),
    db: AsyncSession = Depends(get_db_session),
):
    """List all devices for the authenticated user."""
    # Build query for user's devices
    query = select(DeviceRegistration).where(
        and_(
            DeviceRegistration.user_id == x_user_id,
            DeviceRegistration.is_active == True,
        )
    )
    
    # Optional organization filter (devices with org:device ID format)
    if organization_id:
        query = query.where(DeviceRegistration.device_id.like(f"{organization_id}:%"))
    
    result = await db.execute(query)
    devices = result.scalars().all()
    
    device_list = [
        DeviceInfo(
            device_id=d.device_id,
            user_id=d.user_id,
            platform=d.platform,
            app_version=d.app_version,
            is_active=d.is_active,
            has_public_key=bool(d.public_key),
            key_id=d.key_id,
            last_seen_at=d.last_seen_at.isoformat() if d.last_seen_at else None,
            created_at=d.created_at.isoformat() if d.created_at else "",
        )
        for d in devices
    ]
    
    return DeviceListResponse(devices=device_list, total=len(device_list))


@router.get("/api/devices/{device_id}", response_model=DeviceInfo)
async def get_device(
    device_id: str,
    x_user_id: str = Header(..., alias="X-User-ID"),
    db: AsyncSession = Depends(get_db_session),
):
    """Get device information."""
    result = await db.execute(
        select(DeviceRegistration).where(DeviceRegistration.device_id == device_id)
    )
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Check ownership (allow own devices only)
    if device.user_id != x_user_id:
        raise HTTPException(status_code=403, detail="Not authorized to view this device")
    
    return DeviceInfo(
        device_id=device.device_id,
        user_id=device.user_id,
        platform=device.platform,
        app_version=device.app_version,
        is_active=device.is_active,
        has_public_key=bool(device.public_key),
        key_id=device.key_id,
        last_seen_at=device.last_seen_at.isoformat() if device.last_seen_at else None,
        created_at=device.created_at.isoformat() if device.created_at else "",
    )


@router.delete("/api/devices/{device_id}", status_code=204)
async def unregister_device(
    device_id: str,
    x_user_id: str = Header(..., alias="X-User-ID"),
    db: AsyncSession = Depends(get_db_session),
):
    """Unregister a device (soft delete)."""
    result = await db.execute(
        select(DeviceRegistration).where(DeviceRegistration.device_id == device_id)
    )
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Check ownership
    if device.user_id != x_user_id:
        raise HTTPException(status_code=403, detail="Not authorized to unregister this device")
    
    device.is_active = False
    device.updated_at = datetime.utcnow()
    
    await db.commit()
    
    logger.info(f"Unregistered device: device={device_id}, user={x_user_id}")


# =============================================================================
# Push Challenge Endpoints
# =============================================================================


@router.post("/api/push/challenges", response_model=CreateChallengeResponse, status_code=201)
async def create_challenge(
    body: CreateChallengeRequest,
    db: AsyncSession = Depends(get_db_session),
):
    """Create a push challenge for a device."""
    # Verify device exists and is active
    result = await db.execute(
        select(DeviceRegistration).where(
            DeviceRegistration.device_id == body.device_id,
            DeviceRegistration.is_active == True,
        )
    )
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found or inactive")
    
    # Generate nonce if not provided
    nonce = body.nonce or secrets.token_urlsafe(32)
    
    # Calculate expiry
    expires_at = datetime.utcnow() + timedelta(seconds=body.ttl_seconds)
    
    # Create challenge
    challenge = PushChallenge(
        id=str(uuid4()),
        device_id=body.device_id,
        title=body.title,
        question=body.question,
        nonce=nonce,
        credential_id=body.credential_id,
        data=body.data,
        status=PushChallengeStatus.PENDING,
        expires_at=expires_at,
    )
    
    db.add(challenge)
    await db.commit()
    
    logger.info(f"Created push challenge: id={challenge.id}, device={body.device_id}")
    
    return CreateChallengeResponse(
        challenge_id=challenge.id,
        device_id=body.device_id,
        nonce=nonce,
        expires_at=expires_at.isoformat(),
    )


@router.get("/api/push/challenges/pending", response_model=PendingChallengesResponse)
async def get_pending_challenges(
    device_id: str,
    x_user_id: str = Header(..., alias="X-User-ID"),
    db: AsyncSession = Depends(get_db_session),
):
    """Get pending challenges for a device."""
    # Verify device ownership
    result = await db.execute(
        select(DeviceRegistration).where(DeviceRegistration.device_id == device_id)
    )
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    if device.user_id != x_user_id:
        raise HTTPException(status_code=403, detail="Not authorized to view challenges for this device")
    
    # Get pending, non-expired challenges
    now = datetime.utcnow()
    result = await db.execute(
        select(PushChallenge).where(
            PushChallenge.device_id == device_id,
            PushChallenge.status == PushChallengeStatus.PENDING,
            PushChallenge.expires_at > now,
        ).order_by(PushChallenge.created_at.desc())
    )
    challenges = result.scalars().all()
    
    return PendingChallengesResponse(
        challenges=[_challenge_to_info(c) for c in challenges]
    )


@router.post("/api/push/challenges/{challenge_id}/respond", response_model=RespondChallengeResponse)
async def respond_to_challenge(
    challenge_id: str,
    body: RespondChallengeRequest,
    x_user_id: str = Header(..., alias="X-User-ID"),
    db: AsyncSession = Depends(get_db_session),
):
    """Respond to a push challenge."""
    # Get challenge
    result = await db.execute(
        select(PushChallenge).where(PushChallenge.id == challenge_id)
    )
    challenge = result.scalar_one_or_none()
    
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    # Verify not expired
    if challenge.is_expired:
        challenge.status = PushChallengeStatus.EXPIRED
        await db.commit()
        raise HTTPException(status_code=410, detail="Challenge has expired")
    
    # Verify already responded
    if challenge.status != PushChallengeStatus.PENDING:
        raise HTTPException(status_code=409, detail="Challenge already responded to")
    
    # Verify device ownership
    result = await db.execute(
        select(DeviceRegistration).where(DeviceRegistration.device_id == challenge.device_id)
    )
    device = result.scalar_one_or_none()
    
    if not device or device.user_id != x_user_id:
        raise HTTPException(status_code=403, detail="Not authorized to respond to this challenge")
    
    # Update challenge
    is_accepted = body.is_accepted
    response_str = "accept" if is_accepted else "reject"
    if is_accepted:
        challenge.status = PushChallengeStatus.ACCEPTED
        challenge.response_signature = body.signature
    else:
        challenge.status = PushChallengeStatus.REJECTED
    
    challenge.responded_at = datetime.utcnow()
    
    await db.commit()
    
    logger.info(f"Challenge responded: id={challenge_id}, status={challenge.status.value}")
    
    return RespondChallengeResponse(
        success=True,
        challenge_id=challenge_id,
        status=challenge.status.value,
        response=response_str,
        message=f"Challenge {challenge.status.value}",
    )


@router.delete("/api/push/challenges", status_code=204)
async def clear_challenges(
    device_id: str,
    x_user_id: str = Header(..., alias="X-User-ID"),
    db: AsyncSession = Depends(get_db_session),
):
    """Clear all pending challenges for a device (for testing)."""
    # Verify device ownership
    result = await db.execute(
        select(DeviceRegistration).where(DeviceRegistration.device_id == device_id)
    )
    device = result.scalar_one_or_none()
    
    if device and device.user_id != x_user_id:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Mark all pending challenges as expired
    result = await db.execute(
        select(PushChallenge).where(
            PushChallenge.device_id == device_id,
            PushChallenge.status == PushChallengeStatus.PENDING,
        )
    )
    challenges = result.scalars().all()
    
    for challenge in challenges:
        challenge.status = PushChallengeStatus.EXPIRED
    
    await db.commit()
    
    logger.info(f"Cleared {len(challenges)} challenges for device {device_id}")


# =============================================================================
# QR-Based Device Registration (Mobile Wallet -> Web UI)
# =============================================================================

# In-memory store for pending QR registrations (tokens with TTL)
# In production, use Redis or database
_pending_qr_registrations: dict[str, dict] = {}

# Secret key for HMAC signing (in production, use env var)
_QR_SECRET_KEY = os.environ.get("QR_REGISTRATION_SECRET", "dev-qr-secret-key-change-me")
QR_TOKEN_TTL_SECONDS = 300  # 5 minutes


class QRRegistrationRequest(BaseModel):
    """Request to generate a QR code for device registration."""
    
    user_id: str = Field(..., description="User ID requesting registration")


class QRRegistrationData(BaseModel):
    """QR code data for mobile wallet to scan."""
    
    organization_id: str
    api_url: str
    temp_token: str
    user_id: str
    expires_at: str
    qr_url: str  # marty://push-register URL for easy parsing


class QRRegistrationResponse(BaseModel):
    """Response with QR code data."""
    
    success: bool
    qr_data: QRRegistrationData | None = None
    message: str


class QRCallbackRequest(BaseModel):
    """Callback from mobile wallet after scanning QR."""
    
    temp_token: str = Field(..., description="Temporary token from QR code")
    device_id: str = Field(..., description="Mobile device ID")
    fcm_token: str | None = Field(None, description="FCM token for push")
    platform: str = Field("mobile", description="Device platform")
    public_key: str | None = Field(None, description="Device public key")


class QRCallbackResponse(BaseModel):
    """Response to QR callback."""
    
    success: bool
    device_id: str | None = None
    registration_id: str | None = None
    organization_id: str | None = None
    message: str


def _generate_qr_token(user_id: str, org_id: str, expires_at: float) -> str:
    """Generate HMAC-signed token for QR registration."""
    payload = f"{user_id}:{org_id}:{int(expires_at)}"
    signature = hmac.new(
        _QR_SECRET_KEY.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()[:16]
    
    # Combine payload and signature
    token_data = f"{payload}:{signature}"
    return base64.urlsafe_b64encode(token_data.encode()).decode()


def _verify_qr_token(token: str) -> dict | None:
    """Verify HMAC-signed token and return payload if valid."""
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        parts = decoded.split(":")
        if len(parts) != 4:
            return None
        
        user_id, org_id, expires_str, signature = parts
        expires_at = int(expires_str)
        
        # Check expiration
        if time.time() > expires_at:
            logger.warning(f"QR token expired: user={user_id}")
            return None
        
        # Verify signature
        payload = f"{user_id}:{org_id}:{expires_str}"
        expected_sig = hmac.new(
            _QR_SECRET_KEY.encode(),
            payload.encode(),
            hashlib.sha256
        ).hexdigest()[:16]
        
        if not hmac.compare_digest(signature, expected_sig):
            logger.warning(f"QR token signature mismatch: user={user_id}")
            return None
        
        return {
            "user_id": user_id,
            "organization_id": org_id,
            "expires_at": expires_at,
        }
    except Exception as e:
        logger.error(f"QR token verification failed: {e}")
        return None


@router.post("/api/devices/register-qr", response_model=QRRegistrationResponse)
async def generate_qr_registration(
    body: QRRegistrationRequest,
    request: Request,
    x_organization_id: str = Header("default_org", alias="X-Organization-ID"),
):
    """Generate QR code data for mobile wallet to scan and register device.
    
    The QR contains a marty://push-register URL that the mobile wallet can scan.
    After registration, the web UI is notified via SSE.
    """
    # Get API URL from request
    api_url = str(request.base_url).rstrip("/")
    
    # Generate expiration time
    expires_at = time.time() + QR_TOKEN_TTL_SECONDS
    expires_iso = datetime.utcfromtimestamp(expires_at).isoformat() + "Z"
    
    # Generate signed token
    temp_token = _generate_qr_token(body.user_id, x_organization_id, expires_at)
    
    # Store pending registration for SSE notification
    registration_key = temp_token[:32]  # Use first 32 chars as key
    _pending_qr_registrations[registration_key] = {
        "user_id": body.user_id,
        "organization_id": x_organization_id,
        "expires_at": expires_at,
        "completed": False,
        "device_id": None,
    }
    
    # Build marty://push-register URL
    qr_url = (
        f"marty://push-register"
        f"?org={x_organization_id}"
        f"&api={api_url}"
        f"&token={temp_token}"
        f"&user={body.user_id}"
    )
    
    qr_data = QRRegistrationData(
        organization_id=x_organization_id,
        api_url=api_url,
        temp_token=temp_token,
        user_id=body.user_id,
        expires_at=expires_iso,
        qr_url=qr_url,
    )
    
    logger.info(f"Generated QR registration for user={body.user_id}, org={x_organization_id}")
    
    return QRRegistrationResponse(
        success=True,
        qr_data=qr_data,
        message="QR code generated. Scan with mobile wallet to register device.",
    )


@router.post("/api/devices/qr-callback", response_model=QRCallbackResponse)
async def qr_registration_callback(
    body: QRCallbackRequest,
    db: AsyncSession = Depends(get_db_session),
):
    """Callback from mobile wallet after scanning QR code.
    
    This verifies the temp token, registers the device, and notifies
    the web UI via SSE that registration is complete.
    """
    # Verify the token
    token_data = _verify_qr_token(body.temp_token)
    if not token_data:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    
    user_id = token_data["user_id"]
    org_id = token_data["organization_id"]
    
    # Check if device already exists
    result = await db.execute(
        select(DeviceRegistration).where(DeviceRegistration.device_id == body.device_id)
    )
    existing = result.scalar_one_or_none()
    
    key_id = None
    if body.public_key:
        key_id = compute_key_id(body.public_key)
    
    if existing:
        # Update existing registration
        existing.user_id = user_id
        existing.fcm_token = body.fcm_token
        existing.platform = body.platform
        existing.public_key = body.public_key
        existing.key_id = key_id
        existing.is_active = True
        existing.organization_id = org_id
        existing.last_seen_at = datetime.utcnow()
        existing.updated_at = datetime.utcnow()
        
        await db.commit()
        registration_id = existing.id
        logger.info(f"QR callback: Updated device={body.device_id}, user={user_id}, org={org_id}")
    else:
        # Create new registration
        registration_id = str(uuid4())
        registration = DeviceRegistration(
            id=registration_id,
            device_id=body.device_id,
            user_id=user_id,
            organization_id=org_id,
            fcm_token=body.fcm_token,
            platform=body.platform,
            public_key=body.public_key,
            key_id=key_id,
            is_active=True,
            last_seen_at=datetime.utcnow(),
        )
        
        db.add(registration)
        await db.commit()
        logger.info(f"QR callback: Created device={body.device_id}, user={user_id}, org={org_id}")
    
    # Update pending registration and trigger SSE notification
    registration_key = body.temp_token[:32]
    if registration_key in _pending_qr_registrations:
        _pending_qr_registrations[registration_key]["completed"] = True
        _pending_qr_registrations[registration_key]["device_id"] = body.device_id
        _pending_qr_registrations[registration_key]["registration_id"] = registration_id
    
    # Try to send SSE notification
    try:
        if SSE_SERVICE_AVAILABLE:
            from notifications.adapters.sse import SSEAdapter
            sse_adapter = SSEAdapter()
            await sse_adapter.push_event(
                user_id=user_id,
                event_type="device_registered",
                data={
                    "device_id": body.device_id,
                    "registration_id": registration_id,
                    "organization_id": org_id,
                    "platform": body.platform,
                    "registered_at": datetime.utcnow().isoformat(),
                },
            )
            logger.info(f"SSE notification sent for device registration: user={user_id}")
    except Exception as e:
        logger.warning(f"Failed to send SSE notification: {e}")
    
    return QRCallbackResponse(
        success=True,
        device_id=body.device_id,
        registration_id=registration_id,
        organization_id=org_id,
        message="Device registered via QR code",
    )


@router.get("/api/devices/qr-status/{token_prefix}")
async def check_qr_registration_status(token_prefix: str):
    """Check if a QR registration has been completed.
    
    Used by web UI to poll for registration completion as a fallback
    when SSE is not available.
    
    Args:
        token_prefix: First 32 characters of the temp_token
    """
    if token_prefix not in _pending_qr_registrations:
        raise HTTPException(status_code=404, detail="Registration not found")
    
    pending = _pending_qr_registrations[token_prefix]
    
    # Check expiration
    if time.time() > pending["expires_at"]:
        del _pending_qr_registrations[token_prefix]
        raise HTTPException(status_code=410, detail="Registration expired")
    
    if pending["completed"]:
        # Clean up after returning status
        result = {
            "completed": True,
            "device_id": pending["device_id"],
            "registration_id": pending.get("registration_id"),
            "organization_id": pending["organization_id"],
        }
        del _pending_qr_registrations[token_prefix]
        return result
    
    return {
        "completed": False,
        "expires_at": datetime.utcfromtimestamp(pending["expires_at"]).isoformat() + "Z",
    }
