"""
OID4VC API Service

This FastAPI service provides REST APIs for OID4VCI credential issuance
and OID4VP credential verification, using the hexagonal architecture adapters.
"""

import json
import logging
import os
from datetime import datetime
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from oid4vc.store import (
    record_presentation_request,
    mark_presentation_submitted,
    get_presentation_request,
    list_presentation_requests,
    clear_presentation_requests,
)

# Enhanced features imports
try:
    from age_verification import AgeVerificationEngine
    from offline_verification import OfflineQREngine
    from policy_engine import PolicyBasedDisclosureEngine
    ENHANCED_FEATURES_AVAILABLE = True
except ImportError:
    ENHANCED_FEATURES_AVAILABLE = False
    logger.warning("Enhanced features not available")

# Import adapters - these will be lazily initialized
_key_manager = None
_issuer = None
_wallet = None
_verifier = None

# Enhanced engines
_age_verification_engine = None
_offline_qr_engine = None
_policy_engine = None

# Public Document service imports (for verifying apps)
try:
    from document_service.api import router as document_router
    from document_service.database import init_document_db
    DOCUMENT_SERVICE_AVAILABLE = True
except ImportError:
    DOCUMENT_SERVICE_AVAILABLE = False

# Applicant service deprecated - removed
APPLICANT_SERVICE_AVAILABLE = False

# Auth service imports
try:
    from auth.router import router as auth_router
    AUTH_SERVICE_AVAILABLE = True
except ImportError as e:
    AUTH_SERVICE_AVAILABLE = False
    logging.warning(f"Auth service not available: {e}")

# Onboarding service imports
try:
    from auth.onboarding import router as onboarding_router
    ONBOARDING_SERVICE_AVAILABLE = True
except ImportError as e:
    ONBOARDING_SERVICE_AVAILABLE = False
    logging.warning(f"Onboarding service not available: {e}")

# Audit service imports
try:
    from audit import router as audit_router
    AUDIT_SERVICE_AVAILABLE = True
except ImportError as e:
    AUDIT_SERVICE_AVAILABLE = False
    logging.warning(f"Audit service not available: {e}")

# Role escalation service imports
try:
    from roles import router as roles_router
    ROLES_SERVICE_AVAILABLE = True
except ImportError as e:
    ROLES_SERVICE_AVAILABLE = False
    logging.warning(f"Roles service not available: {e}")

# Notification preferences service imports
try:
    from notifications_service import router as notification_prefs_router
    NOTIFICATION_PREFS_AVAILABLE = True
except ImportError as e:
    NOTIFICATION_PREFS_AVAILABLE = False
    logging.warning(f"Notification preferences service not available: {e}")

# Admin impersonation service imports
try:
    from admin_impersonation import router as admin_impersonation_router
    ADMIN_IMPERSONATION_AVAILABLE = True
except ImportError as e:
    ADMIN_IMPERSONATION_AVAILABLE = False
    logging.warning(f"Admin impersonation service not available: {e}")

# Credential configuration service imports
try:
    from credentials.router import router as credentials_router
    CREDENTIALS_SERVICE_AVAILABLE = True
except ImportError as e:
    CREDENTIALS_SERVICE_AVAILABLE = False
    logging.warning(f"Credentials service not available: {e}")

# Trust configuration service imports
try:
    from trust.router import router as trust_router
    TRUST_SERVICE_AVAILABLE = True
except ImportError as e:
    TRUST_SERVICE_AVAILABLE = False
    logging.warning(f"Trust configuration service not available: {e}")

# Issuance service imports
try:
    from issuance.router import router as issuance_router
    ISSUANCE_SERVICE_AVAILABLE = True
except ImportError as e:
    ISSUANCE_SERVICE_AVAILABLE = False
    logging.warning(f"Issuance service not available: {e}")

# Devices service imports
try:
    from devices import router as devices_router
    DEVICES_SERVICE_AVAILABLE = True
except ImportError as e:
    DEVICES_SERVICE_AVAILABLE = False
    logging.warning(f"Devices service not available: {e}")

# Open Badges service imports
try:
    from open_badges.router import router as open_badges_router
    OPEN_BADGES_AVAILABLE = True
except ImportError as e:
    OPEN_BADGES_AVAILABLE = False
    logging.warning(f"Open Badges service not available: {e}")

# Status List service imports
try:
    from status_list.infrastructure.persistence.database import (
        init_status_list_db,
        get_session_factory as get_status_list_session_factory,
    )
    from status_list.infrastructure.security import SymmetricEncryption
    from status_list.infrastructure.adapters.issuer_key_registry import IssuerKeyRegistry
    from status_list.infrastructure.adapters.lazy_signing_adapter import LazySigningAdapter
    from status_list.infrastructure.adapters.rest_adapter import create_status_list_router
    from status_list.application.services.status_list_service import StatusListService
    from status_list.application.services.credential_status_service import CredentialStatusService
    from status_list.application.services.status_list_credential_service import StatusListCredentialService
    from status_list.infrastructure.persistence.repository import (
        StatusListRepository,
        StatusEntryRepository,
    )
    from open_badges.status_integration import configure_credential_status_service
    STATUS_LIST_AVAILABLE = True
except ImportError as e:
    STATUS_LIST_AVAILABLE = False
    logging.warning(f"Status List service not available: {e}")

# Notifications API imports (local notification storage/retrieval)
try:
    from notifications_local.api import router as notifications_router
    NOTIFICATIONS_API_AVAILABLE = True
except ImportError as e:
    NOTIFICATIONS_API_AVAILABLE = False
    logging.warning(f"Notifications API not available: {e}")
# ZK Verification service imports
try:
    from marty_credentials.infrastructure.adapters.zk_verification_adapter import create_zk_verification_router
    from marty_credentials.adapters.services.verification_service import VerificationService
    ZK_VERIFICATION_AVAILABLE = True
except ImportError as e:
    ZK_VERIFICATION_AVAILABLE = False
    logging.warning(f"ZK Verification service not available: {e}")



# SSE (Server-Sent Events) service imports for real-time push notifications
try:
    import sys
    from pathlib import Path
    # Add main src directory to path for full notifications module (native or Docker)
    _main_src = Path(__file__).parent.parent.parent / "src"
    if _main_src.exists():
        sys.path.insert(0, str(_main_src))
    sys.path.insert(0, '/app')  # For Docker context
    # Import from main notifications module (not the simplified marty-ui version)
    from notifications.api import sse_router, push_router, configure_sse_adapter
    from notifications.adapters.sse import SSEAdapter
    SSE_SERVICE_AVAILABLE = True
    logging.info("SSE service loaded successfully")
except ImportError as e:
    SSE_SERVICE_AVAILABLE = False
    logging.warning(f"SSE service not available: {e}")

# Error handling imports (path already set above)
try:
    from marty_common.errors import register_exception_handlers
    ERROR_HANDLERS_AVAILABLE = True
except ImportError as e:
    ERROR_HANDLERS_AVAILABLE = False
    logging.warning(f"Global error handlers not available: {e}")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="Marty Trust Services API",
    description="Travel document issuance and credential management services",
    version="1.0.0",
)

# Register global exception handlers for unified error responses
if ERROR_HANDLERS_AVAILABLE:
    register_exception_handlers(app)
    logger.info("Global exception handlers registered")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include document service router
if DOCUMENT_SERVICE_AVAILABLE:
    app.include_router(document_router)
    logger.info("Document service router registered")

# Include applicant service router
if APPLICANT_SERVICE_AVAILABLE:
    app.include_router(applicant_router)
    logger.info("Applicant service router registered")

# Client error reporting service
try:
    from client_errors import router as client_errors_router
    app.include_router(client_errors_router, tags=["Client Errors"])
    logger.info("Client errors router registered")
except ImportError as e:
    logging.warning(f"Client errors service not available: {e}")

# Include auth service router
if AUTH_SERVICE_AVAILABLE:
    app.include_router(auth_router, tags=["Authentication"])
    logger.info("Auth service router registered")

# Include onboarding service router
if ONBOARDING_SERVICE_AVAILABLE:
    app.include_router(onboarding_router, tags=["Onboarding"])
    logger.info("Onboarding service router registered")

# Include audit service router
if AUDIT_SERVICE_AVAILABLE:
    app.include_router(audit_router, tags=["Audit"])
    logger.info("Audit service router registered")

# Include roles service router
if ROLES_SERVICE_AVAILABLE:
    app.include_router(roles_router, tags=["Roles"])
    logger.info("Roles service router registered")

# Include notification preferences router
if NOTIFICATION_PREFS_AVAILABLE:
    app.include_router(notification_prefs_router, tags=["Notifications"])
    logger.info("Notification preferences router registered")

# Include admin impersonation router
if ADMIN_IMPERSONATION_AVAILABLE:
    app.include_router(admin_impersonation_router, tags=["Admin"])
    logger.info("Admin impersonation router registered")

# API Keys service
try:
    from api_keys.api import router as api_keys_router
    app.include_router(api_keys_router, tags=["API Keys"])
    logger.info("API Keys service router registered")
except ImportError as e:
    logging.warning(f"API Keys service not available: {e}")

# Credential configuration service
if CREDENTIALS_SERVICE_AVAILABLE:
    app.include_router(credentials_router, tags=["Credential Configuration"])
    logger.info("Credentials service router registered")

# Trust configuration service
if TRUST_SERVICE_AVAILABLE:
    app.include_router(trust_router, tags=["Trust Configuration"])
    logger.info("Trust configuration service router registered")

# Issuance service (OID4VCI)
if ISSUANCE_SERVICE_AVAILABLE:
    app.include_router(issuance_router, tags=["Credential Issuance"])
    logger.info("Issuance service router registered")

# Devices and push challenges service
if DEVICES_SERVICE_AVAILABLE:
    app.include_router(devices_router, tags=["Devices"])
    logger.info("Devices service router registered")

# Open Badges endpoints
if OPEN_BADGES_AVAILABLE:
    app.include_router(open_badges_router, tags=["Open Badges"])
    logger.info("Open Badges router registered")

# Notifications API endpoints
if NOTIFICATIONS_API_AVAILABLE:
    app.include_router(notifications_router, tags=["Notifications"])
    logger.info("Notifications API router registered")

# SSE (Server-Sent Events) endpoints for real-time push challenge delivery
if SSE_SERVICE_AVAILABLE:
    app.include_router(sse_router, tags=["SSE Events"])
    app.include_router(push_router, tags=["Push Notifications"])
    logger.info("SSE and Push notification routers registered")


# =============================================================================
# Startup Events - Database Initialization
# =============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize databases on application startup."""
    # Initialize subscription database (for devices, push challenges, credentials config)
    try:
        from subscription.database import init_database as init_subscription_db
        await init_subscription_db()
        logger.info("Subscription database initialized")
    except Exception as e:
        logger.error(f"Failed to initialize subscription database: {e}")
    
    # Initialize applicant database (for applicant management)
    if APPLICANT_SERVICE_AVAILABLE:
        try:
            from applicant_service.database import init_database as init_applicant_db
            await init_applicant_db()
            logger.info("Applicant database initialized")
        except Exception as e:
            logger.error(f"Failed to initialize applicant database: {e}")
    
    # Initialize SSE adapter for real-time push notifications
    if SSE_SERVICE_AVAILABLE:
        try:
            notification_adapter = os.getenv("NOTIFICATION_ADAPTER", "default")
            if notification_adapter == "sse":
                sse_adapter = SSEAdapter(
                    heartbeat_interval=30,
                    max_connections_per_user=5,
                )
                await sse_adapter.start()
                configure_sse_adapter(sse_adapter)
                logger.info("SSE adapter initialized for real-time push notifications")
            else:
                logger.info(f"SSE adapter not started (NOTIFICATION_ADAPTER={notification_adapter})")
        except Exception as e:
            logger.error(f"Failed to initialize SSE adapter: {e}")
    
    # Initialize Status List service (fail-fast pattern)
    if STATUS_LIST_AVAILABLE:
        try:
            # Initialize database tables
            await init_status_list_db()
            logger.info("Status list database tables created")
            
            # Create encryption service for key protection
            encryption_service = SymmetricEncryption.from_env("STATUS_LIST_MASTER_KEY")
            logger.info("Status list encryption service initialized")
            
            # Create session factory for repositories
            status_session_factory = get_status_list_session_factory()
            
            # Create issuer key registry with factory pattern
            def create_key_registry() -> IssuerKeyRegistry:
                return IssuerKeyRegistry(status_session_factory, encryption_service)
            
            # Create lazy signing adapter (keys loaded on-demand)
            signing_adapter = LazySigningAdapter(
                key_registry_factory=create_key_registry,
                default_proof_type="DataIntegrityProof",
                default_cryptosuite="eddsa-rdfc-2022",
            )
            logger.info("Lazy signing adapter created (keys load on-demand)")
            
            # Create repositories
            status_list_repo = StatusListRepository(status_session_factory)
            status_entry_repo = StatusEntryRepository(status_session_factory)
            
            # Initialize application services
            # Note: event_publisher=None is supported - events are optional per status_list_service.py
            status_list_service = StatusListService(
                status_list_repository=status_list_repo,
                status_entry_repository=status_entry_repo,
                event_publisher=None,  # Events optional - observability only
            )
            
            base_url = os.getenv("STATUS_LIST_BASE_URL", "http://localhost:8000")
            credential_status_service = CredentialStatusService(
                status_list_service=status_list_service,
                base_url=base_url,
            )

            
            status_list_credential_service = StatusListCredentialService(
                status_list_repository=status_list_repo,
                signing_service=signing_adapter,
                base_url=base_url,
            )
            
            # Create and mount REST router
            status_list_router = create_status_list_router(
                status_list_service=status_list_service,
                credential_status_service=credential_status_service,
                status_list_credential_service=status_list_credential_service,
            )
            app.include_router(status_list_router, tags=["Status Lists"])
            logger.info("Status list REST endpoints registered")
            
            # Configure global service for Open Badges integration
            configure_credential_status_service(credential_status_service)
            logger.info("Status list service configured for Open Badges")
            
        except Exception as e:
            logger.error(f"Failed to initialize status list service: {e}")
            # Fail fast - status list is critical infrastructure
            raise

    # Initialize ZK Verification service
    if ZK_VERIFICATION_AVAILABLE:
        try:
            # Re-use the status list session factory if available, or applicant DB
            from applicant_service.database import get_session_factory as get_applicant_session_factory
            from sqlalchemy.orm import scoped_session
            
            session_factory = get_applicant_session_factory()
            scoped_db_session = scoped_session(session_factory)
            
            # Initialize service with scoped session for thread safety
            zk_service = VerificationService(db_session=scoped_db_session) # type: ignore
            
            zk_router = create_zk_verification_router(zk_service)
            app.include_router(zk_router)
            logger.info("ZK Verification router registered")
        except Exception as e:
            logger.error(f"Failed to initialize ZK verification service: {e}")


def _get_adapters():
    """Lazy initialization of adapters."""
    global _key_manager, _issuer, _wallet, _verifier
    if _key_manager is None:
        # Import from marty_credentials adapters (credential vendor implementations)
        from marty_credentials.adapters.credentials import (
            get_issuer,
            get_key_manager,
            get_verifier,
            get_wallet,
        )
        _key_manager = get_key_manager()
        _issuer = get_issuer()
        _wallet = get_wallet()
        _verifier = get_verifier()
    return _key_manager, _issuer, _wallet, _verifier

def _get_enhanced_engines():
    """Lazy initialization of enhanced engines."""
    global _age_verification_engine, _offline_qr_engine, _policy_engine
    if ENHANCED_FEATURES_AVAILABLE:
        if _age_verification_engine is None:
            _age_verification_engine = AgeVerificationEngine()
        if _offline_qr_engine is None:
            _offline_qr_engine = OfflineQREngine()
        if _policy_engine is None:
            _policy_engine = PolicyBasedDisclosureEngine()
    return _age_verification_engine, _offline_qr_engine, _policy_engine


# Default issuer key
_issuer_key = None


def _get_issuer_key():
    """Get or create the issuer key."""
    global _issuer_key
    if _issuer_key is None:
        from mmf.core.credentials import KeyAlgorithm
        key_manager, _, _, _ = _get_adapters()
        
        # Try to load existing key
        _issuer_key = key_manager.get_key("issuer_default")
        if _issuer_key is None:
            # Generate new key
            _issuer_key = key_manager.generate_key(KeyAlgorithm.ES256)
            key_manager.store_key("issuer_default", _issuer_key)
            logger.info(f"Generated new issuer key: {_issuer_key.did}")
    return _issuer_key


# ==================== Pydantic Models ====================

class SubjectData(BaseModel):
    """Subject data for credential issuance."""
    given_name: str = "Jane"
    family_name: str = "Doe"
    birth_date: str = "1990-01-01"
    document_number: str | None = None
    issuing_country: str = "XX"
    issuing_authority: str = "Demo Issuer"
    expiry_date: str | None = None


class IssueCredentialRequest(BaseModel):
    """Request to issue a credential."""
    credential_type: str = Field(default="UniversityDegreeCredential", description="Type of credential")
    subject_data: SubjectData = Field(default_factory=SubjectData)
    subject_id: str | None = Field(default=None, description="Subject DID")
    issuer_id: str = Field(default="demo_issuer", description="Issuer identifier")
    expiration_days: int | None = Field(default=365, description="Credential validity in days")


class CredentialOfferRequest(BaseModel):
    """Request to create a credential offer."""
    credential_types: list[str] = Field(default=["UniversityDegreeCredential"])
    pre_authorized: bool = True
    user_pin_required: bool = False
    wallet_format: str = Field(default="standard", description="standard or microsoft")


class VerifyCredentialRequest(BaseModel):
    """Request to verify a credential."""
    credential_jwt: str = Field(..., description="JWT credential to verify")
    expected_issuer: str | None = None


class PresentCredentialsRequest(BaseModel):
    """Request to create a presentation."""
    credential_ids: list[str] = Field(..., description="IDs of credentials to present")
    audience: str = Field(..., description="Verifier identifier")
    nonce: str | None = None


class VerifyPresentationRequest(BaseModel):
    """Request to verify a presentation."""
    presentation_jwt: str = Field(..., description="JWT presentation to verify")
    expected_audience: str = Field(..., description="Expected verifier")
    expected_nonce: str | None = None
    request_id: str | None = None


class CreatePresentationRequest(BaseModel):
    """Request to create a presentation request."""
    requested_credentials: list[str] = Field(default=["VerifiableCredential"])
    verifier_id: str | None = Field(default=None)


class GenerateKeyRequest(BaseModel):
    """Request to generate a new key."""
    algorithm: str = Field(default="ES256", description="ES256 or EdDSA")
    key_id: str | None = Field(default=None, description="Optional key identifier")


# ==================== API Endpoints ====================

@app.get("/", include_in_schema=False)
async def root():
    """Redirect root to Swagger UI."""
    return RedirectResponse(url="/docs")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "oid4vc-api", "version": "1.0.0"}


@app.get("/api/issuer/metadata")
async def get_issuer_metadata():
    """Get OID4VCI issuer metadata for discovery."""
    _, issuer, _, _ = _get_adapters()
    
    issuer_url = os.getenv("ISSUER_URL", "http://localhost:8000")
    issuer_name = os.getenv("ISSUER_NAME", "Demo Credential Issuer")
    
    supported_credentials = [
        {"id": "UniversityDegreeCredential", "name": "University Degree", "format": "jwt_vc_json"},
        {"id": "DriverLicenseCredential", "name": "Driver License", "format": "jwt_vc_json"},
        {"id": "EmployeeCredential", "name": "Employee Badge", "format": "jwt_vc_json"},
    ]
    
    metadata = issuer.generate_issuer_metadata(
        issuer_url=issuer_url,
        issuer_name=issuer_name,
        supported_credentials=supported_credentials,
    )
    
    return json.loads(metadata)


@app.post("/api/issuer/issue")
async def issue_credential(request: IssueCredentialRequest):
    """Issue a new verifiable credential."""
    from mmf.core.credentials import CredentialSubject
    
    _, issuer, _, _ = _get_adapters()
    issuer_key = _get_issuer_key()
    
    # Build claims from subject data
    claims = {
        "name": f"{request.subject_data.given_name} {request.subject_data.family_name}",
        "given_name": request.subject_data.given_name,
        "family_name": request.subject_data.family_name,
        "birth_date": request.subject_data.birth_date,
        "issuing_authority": request.subject_data.issuing_authority,
        "issuing_country": request.subject_data.issuing_country,
    }
    
    if request.subject_data.document_number:
        claims["document_number"] = request.subject_data.document_number
    if request.subject_data.expiry_date:
        claims["expiry_date"] = request.subject_data.expiry_date
    
    subject = CredentialSubject(
        id=request.subject_id,
        claims=claims,
    )
    
    expiration_seconds = None
    if request.expiration_days:
        expiration_seconds = request.expiration_days * 24 * 60 * 60
    
    try:
        credential = issuer.create_credential(
            issuer_key=issuer_key,
            credential_type=request.credential_type,
            subject=subject,
            expiration_seconds=expiration_seconds,
        )
        
        return {
            "success": True,
            "credential_id": credential.id,
            "credential_jwt": credential.jwt,
            "issuer": credential.issuer,
            "types": credential.types,
            "issuance_date": credential.issuance_date.isoformat(),
            "expiration_date": credential.expiration_date.isoformat() if credential.expiration_date else None,
            "claims": claims,
        }
    except Exception as e:
        logger.error(f"Failed to issue credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/issuer/offer")
async def create_credential_offer(request: CredentialOfferRequest):
    """Create a credential offer for OID4VCI."""
    _, issuer, _, _ = _get_adapters()
    
    issuer_url = os.getenv("ISSUER_URL", "http://localhost:8000")
    
    try:
        offer = issuer.create_offer(
            issuer_url=issuer_url,
            credential_types=request.credential_types,
            pre_authorized=request.pre_authorized,
            user_pin_required=request.user_pin_required,
            wallet_format=request.wallet_format,
        )
        
        return {
            "success": True,
            "offer_id": offer.offer_id,
            "offer_uri": offer.offer_uri,
            "credential_types": offer.credential_types,
            "pre_authorized_code": offer.pre_authorized_code,
            "user_pin_required": offer.user_pin_required,
            "offer_json": json.loads(offer.offer_json) if offer.offer_json else None,
        }
    except Exception as e:
        logger.error(f"Failed to create offer: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/verifier/verify")
async def verify_credential(request: VerifyCredentialRequest):
    """Verify a verifiable credential JWT."""
    _, _, _, verifier = _get_adapters()
    
    try:
        result = verifier.verify_credential(
            credential_jwt=request.credential_jwt,
            expected_issuer=request.expected_issuer,
        )
        
        return {
            "valid": result.valid,
            "claims": result.claims,
            "issuer": result.issuer,
            "error": result.error,
        }
    except Exception as e:
        logger.error(f"Failed to verify credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/verifier/verify-presentation")
async def verify_presentation(request: VerifyPresentationRequest):
    """Verify a verifiable presentation JWT."""
    _, _, _, verifier = _get_adapters()
    
    try:
        result = verifier.verify_presentation(
            presentation_jwt=request.presentation_jwt,
            expected_audience=request.expected_audience,
            expected_nonce=request.expected_nonce,
        )

        if request.request_id and result.valid:
            mark_presentation_submitted(request.request_id, {"vp_jwt": request.presentation_jwt})
        
        return {
            "valid": result.valid,
            "claims": result.claims,
            "holder": result.issuer,
            "error": result.error,
        }
    except Exception as e:
        logger.error(f"Failed to verify presentation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/verifier/request")
async def create_presentation_request(request: CreatePresentationRequest):
    """Create a presentation request for OID4VP."""
    _, _, _, verifier = _get_adapters()
    
    verifier_id = request.verifier_id or os.getenv("VERIFIER_ID", "demo_verifier")
    
    try:
        presentation_request = verifier.create_presentation_request(
            verifier_id=verifier_id,
            requested_credentials=request.requested_credentials or ["VerifiableCredential"],
        )

        record_presentation_request(
            request_id=presentation_request.request_id,
            verifier=presentation_request.verifier,
            requested_credentials=presentation_request.requested_credentials,
            nonce=presentation_request.nonce,
            audience=presentation_request.audience,
            request_uri=getattr(presentation_request, "request_uri", None),
        )
        
        return {
            "request_id": presentation_request.request_id,
            "verifier": presentation_request.verifier,
            "requested_credentials": presentation_request.requested_credentials,
            "nonce": presentation_request.nonce,
            "audience": presentation_request.audience,
            "request_uri": getattr(presentation_request, "request_uri", None),
        }
    except Exception as e:
        logger.error(f"Failed to create presentation request: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/verifier/requests")
async def list_presentation_requests_api():
    """List presentation requests (in-memory)."""
    requests = list_presentation_requests()
    return {"count": len(requests), "requests": requests}


@app.get("/api/verifier/requests/{request_id}/status")
async def get_presentation_request_status(request_id: str):
    """Get presentation request status."""
    record = get_presentation_request(request_id)
    if not record:
        raise HTTPException(status_code=404, detail="Presentation request not found")
    return {
        "status": record.get("status"),
        "presentation": record.get("presentation"),
    }


@app.delete("/api/verifier/requests")
async def clear_presentation_requests_api():
    """Clear presentation requests (in-memory)."""
    cleared = clear_presentation_requests()
    return {"cleared": cleared, "message": f"Cleared {cleared} presentation requests"}


@app.post("/api/wallet/store")
async def store_credential(credential_jwt: str):
    """Store a credential in the wallet."""
    from mmf.core.credentials import CredentialData, CredentialSubject
    
    _, _, wallet, verifier = _get_adapters()
    
    # First verify the credential
    result = verifier.verify_credential(credential_jwt=credential_jwt)
    if not result.valid:
        raise HTTPException(status_code=400, detail=f"Invalid credential: {result.error}")
    
    # Create credential data from verified claims
    credential = CredentialData(
        id=f"urn:uuid:{uuid4()}",
        types=["VerifiableCredential"],
        issuer=result.issuer or "unknown",
        subject=CredentialSubject(claims=result.claims),
        issuance_date=datetime.utcnow(),
        jwt=credential_jwt,
    )
    
    storage_id = wallet.store_credential(credential)
    
    return {
        "success": True,
        "credential_id": storage_id,
        "issuer": result.issuer,
        "claims": result.claims,
    }


@app.get("/api/wallet/credentials")
async def list_credentials(credential_type: str | None = None):
    """List credentials in the wallet."""
    _, _, wallet, _ = _get_adapters()
    
    credentials = wallet.list_credentials(credential_type)
    
    return {
        "credentials": [
            {
                "id": c.id,
                "types": c.types,
                "issuer": c.issuer,
                "issuance_date": c.issuance_date.isoformat(),
                "expiration_date": c.expiration_date.isoformat() if c.expiration_date else None,
            }
            for c in credentials
        ],
        "count": len(credentials),
    }


@app.post("/api/wallet/present")
async def create_presentation(request: PresentCredentialsRequest):
    """Create a verifiable presentation."""
    from mmf.core.credentials import KeyAlgorithm
    
    key_manager, _, wallet, _ = _get_adapters()
    
    # Get or create holder key
    holder_key = key_manager.get_key("holder_default")
    if holder_key is None:
        holder_key = key_manager.generate_key(KeyAlgorithm.ES256)
        key_manager.store_key("holder_default", holder_key)
    
    # Get credentials to present
    credentials = []
    for cred_id in request.credential_ids:
        cred = wallet.get_credential(cred_id)
        if cred:
            credentials.append(cred)
    
    if not credentials:
        raise HTTPException(status_code=404, detail="No matching credentials found")
    
    try:
        presentation_jwt = wallet.create_presentation(
            holder_key=holder_key,
            credentials=credentials,
            audience=request.audience,
            nonce=request.nonce,
        )
        
        return {
            "success": True,
            "presentation_jwt": presentation_jwt,
            "holder": holder_key.did,
            "credentials_count": len(credentials),
        }
    except Exception as e:
        logger.error(f"Failed to create presentation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/keys/generate")
async def generate_key(request: GenerateKeyRequest):
    """Generate a new cryptographic key."""
    from mmf.core.credentials import KeyAlgorithm
    
    key_manager, _, _, _ = _get_adapters()
    
    alg = KeyAlgorithm.ES256 if request.algorithm == "ES256" else KeyAlgorithm.EDDSA
    
    try:
        key_pair = key_manager.generate_key(alg)
        
        key_id = request.key_id or f"key_{uuid4().hex[:8]}"
        key_manager.store_key(key_id, key_pair)
        
        return {
            "success": True,
            "key_id": key_id,
            "did": key_pair.did,
            "algorithm": key_pair.algorithm.value,
            "created_at": key_pair.created_at.isoformat(),
        }
    except Exception as e:
        logger.error(f"Failed to generate key: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/keys")
async def list_keys():
    """List all stored keys."""
    key_manager, _, _, _ = _get_adapters()
    
    key_ids = key_manager.list_keys()
    keys = []
    
    for key_id in key_ids:
        key = key_manager.get_key(key_id)
        if key:
            keys.append({
                "key_id": key_id,
                "did": key.did,
                "algorithm": key.algorithm.value,
                "created_at": key.created_at.isoformat(),
            })
    
    return {"keys": keys, "count": len(keys)}


# ==================== Admin & Enhanced Features Endpoints ====================

@app.get("/api/admin/stats")
async def get_admin_stats():
    """Get system statistics."""
    try:
        _, issuer, wallet, verifier = _get_adapters()
        # We can't easily count issued credentials without persistence query
        # But we can count wallet credentials
        wallet_creds = len(wallet.list_credentials()) if wallet else 0
    except Exception:
        # Adapters not available, return mock data
        wallet_creds = 0
    
    return {
        "passport": 12, # Mock
        "mdl": wallet_creds,
        "mdoc": 8, # Mock
        "verifications": 120 # Mock
    }

@app.get("/api/admin/csca")
async def list_csca_certificates():
    """List CSCA certificates."""
    # Mock implementation
    return {
        "certificates": [
            {
                "id": "csca_001",
                "subject": "C=US, O=Marty, CN=Marty Root CA",
                "expiry_date": "2030-12-31",
                "status": "active"
            }
        ]
    }

@app.post("/api/admin/csca")
async def create_csca_certificate(data: dict[str, Any]):
    """Create a new CSCA certificate."""
    # Mock implementation
    return {
        "success": True,
        "certificate_id": f"csca_{uuid4().hex[:8]}",
        "status": "created"
    }

@app.get("/api/admin/pkd")
async def list_pkd_certificates():
    """List PKD certificates."""
    # Mock implementation
    return {
        "certificates": []
    }

@app.post("/api/admin/pkd")
async def upload_pkd_certificate(data: dict[str, Any]):
    """Upload a PKD certificate."""
    # Mock implementation
    return {
        "success": True,
        "certificate_id": f"pkd_{uuid4().hex[:8]}",
        "status": "uploaded"
    }

@app.get("/api/admin/metrics")
async def get_metrics():
    """Get system metrics."""
    # Mock implementation
    return {
        "cpu_usage": 45,
        "memory_usage": 60,
        "request_rate": 125,
        "transaction_volume": [
            { "name": '00:00', "issuance": 4, "verification": 2 },
            { "name": '04:00', "issuance": 3, "verification": 1 },
            { "name": '08:00', "issuance": 15, "verification": 8 },
            { "name": '12:00', "issuance": 45, "verification": 23 },
            { "name": '16:00', "issuance": 38, "verification": 30 },
            { "name": '20:00', "issuance": 12, "verification": 15 },
            { "name": '23:59', "issuance": 5, "verification": 4 },
        ]
    }

@app.post("/api/passport/process")
async def process_passport(data: dict[str, Any]):
    """Process a passport issuance request."""
    # Mock implementation
    return {
        "success": True,
        "passport_number": data.get("passport_number") or f"P{uuid4().int % 100000000}",
        "status": "issued",
        "expiry_date": "2035-01-01"
    }

@app.post("/api/passport/inspect")
async def inspect_passport(data: dict[str, Any]):
    """Inspect a passport."""
    # Mock implementation
    return {
        "valid": True,
        "details": {
            "passport_number": data.get("passport_number"),
            "holder": "John Doe",
            "nationality": "UTO",
            "expiry": "2030-12-31"
        }
    }

# ==================== Enhanced Verifier Endpoints ====================

@app.post("/api/verifier/age-verification/request")
async def create_age_verification_request(data: dict[str, Any]):
    """Create an age verification request."""
    age_engine, _, _ = _get_enhanced_engines()
    if not age_engine:
        raise HTTPException(status_code=501, detail="Enhanced features not available")
    
    try:
        request = age_engine.create_age_verification_request(
            use_case=data.get("use_case"),
            verifier_id=data.get("verifier_id"),
            purpose=data.get("purpose")
        )
        return {"success": True, "verification_request": request}
    except Exception as e:
        logger.error(f"Failed to create age verification request: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/verifier/age-verification/verify")
async def verify_age(data: dict[str, Any]):
    """Verify age proof."""
    age_engine, _, _ = _get_enhanced_engines()
    if not age_engine:
        raise HTTPException(status_code=501, detail="Enhanced features not available")
    
    # Mock verification for now as we don't have full ZK proof support in adapters yet
    # In a real implementation, we would verify the ZK proof here
    return {
        "success": True,
        "verified": True,
        "age_verified": True,
        "details": {
            "timestamp": datetime.utcnow().isoformat(),
            "method": "zk_proof"
        }
    }

@app.post("/api/verifier/offline-qr/create")
async def create_offline_qr(data: dict[str, Any]):
    """Create an offline verification QR code."""
    _, qr_engine, _ = _get_enhanced_engines()
    if not qr_engine:
        raise HTTPException(status_code=501, detail="Enhanced features not available")
    
    try:
        qr_data = qr_engine.create_offline_qr(
            mdl_data=data.get("mdl_data", {}),
            verification_requirements=data.get("requirements"),
            expires_in_minutes=data.get("expires_in_minutes", 30)
        )
        return {"success": True, "qr_data": qr_data}
    except Exception as e:
        logger.error(f"Failed to create offline QR: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/verifier/offline-qr/verify")
async def verify_offline_qr(data: dict[str, Any]):
    """Verify an offline QR code."""
    _, qr_engine, _ = _get_enhanced_engines()
    if not qr_engine:
        raise HTTPException(status_code=501, detail="Enhanced features not available")
    
    try:
        result = qr_engine.verify_offline_qr(
            qr_data=data.get("qr_data"),
            verifier_context=data.get("context")
        )
        return {"success": True, "result": result}
    except Exception as e:
        logger.error(f"Failed to verify offline QR: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/verifier/policy/evaluate")
async def evaluate_policy(data: dict[str, Any]):
    """Evaluate a disclosure policy."""
    _, _, policy_engine = _get_enhanced_engines()
    if not policy_engine:
        raise HTTPException(status_code=501, detail="Enhanced features not available")
    
    # Mock evaluation
    return {
        "success": True,
        "allowed": True,
        "policy_evaluation": {
            "policy_id": data.get("policy_id"),
            "result": "compliant",
            "timestamp": datetime.utcnow().isoformat()
        }
    }

@app.get("/api/verifier/policy/summary")
async def get_policy_summary():
    """Get policy engine summary."""
    _, _, policy_engine = _get_enhanced_engines()
    if not policy_engine:
        raise HTTPException(status_code=501, detail="Enhanced features not available")
    
    # Mock summary
    return {
        "active_policies": 5,
        "policy_types": ["age_verification", "identity_proofing", "employment"],
        "last_update": datetime.utcnow().isoformat()
    }

@app.get("/api/verifier/certificates/dashboard")
async def get_certificate_dashboard():
    """Get certificate management dashboard data."""
    # Mock data for now, or aggregate from key manager
    return {
        "active_certificates": 12,
        "expiring_soon": 2,
        "revoked": 1,
        "trust_anchors": 5,
        "last_update": datetime.utcnow().isoformat()
    }

@app.post("/api/verifier/certificates/{cert_id}/renew")
async def renew_certificate(cert_id: str):
    """Renew a certificate."""
    # Mock renewal
    return {
        "success": True,
        "renewal_successful": True,
        "new_expiry": (datetime.utcnow().replace(year=datetime.utcnow().year + 1)).isoformat()
    }

# ==================== OID4VCI Protocol Endpoints ====================

@app.post("/api/issuer/token")
async def issuer_token(grant_type: str = "urn:ietf:params:oauth:grant-type:pre-authorized_code", pre_authorized_code: str | None = None):
    """OID4VCI Token Endpoint."""
    # Mock token issuance
    return {
        "access_token": "mock_access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "c_nonce": str(uuid4())
    }

@app.post("/api/issuer/credential")
async def issuer_credential(request: dict[str, Any]):
    """OID4VCI Credential Endpoint."""
    from mmf.core.credentials import CredentialSubject
    
    _, issuer, _, _ = _get_adapters()
    issuer_key = _get_issuer_key()
    
    # Extract requested type
    # request = {"format": "...", "credential_definition": {"type": [...]}, "proof": ...}
    cred_def = request.get("credential_definition", {})
    types = cred_def.get("type", [])
    credential_type = types[-1] if types else "VerifiableCredential"
    
    # Mock subject data for OID4VCI flow (since we don't have a real user session here)
    # In a real flow, the access token would be bound to a user session
    subject = CredentialSubject(
        id=f"did:key:{uuid4().hex}", # Should come from proof
        claims={
            "given_name": "Jane",
            "family_name": "Doe",
            "birth_date": "1990-01-01",
            "degree": "Bachelor of Science",
            "university": "Demo University"
        }
    )
    
    try:
        credential = issuer.create_credential(
            issuer_key=issuer_key,
            credential_type=credential_type,
            subject=subject,
            expiration_seconds=365 * 24 * 60 * 60,
        )
        
        return {
            "credential": credential.jwt,
            "format": "jwt_vc_json",
            "c_nonce": str(uuid4()),
            "c_nonce_expires_in": 86400
        }
    except Exception as e:
        logger.error(f"Failed to issue credential via OID4VCI: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# OID4VCI Issuer Metadata Endpoint
# =============================================================================

@app.get("/.well-known/openid-credential-issuer")
async def get_issuer_metadata(user_agent: str = Header(None)):
    """OID4VCI Issuer Metadata Endpoint.
    
    Returns metadata about the credential issuer per OID4VCI specification.
    Includes credential configurations derived from active credential templates.
    Adapts to wallet capabilities if User-Agent is provided.
    """
    # Get base URL from environment
    base_url = os.getenv("PUBLIC_BASE_URL", "http://localhost:8000")
    
    # Detect wallet capabilities if User-Agent is provided
    wallet_vendor = "generic"
    supported_formats = None
    
    if user_agent:
        try:
            import httpx
            wallet_service_url = os.getenv("WALLET_SERVICE_URL", "http://wallet-service:8015")
            async with httpx.AsyncClient(timeout=2.0) as client:
                response = await client.post(
                    f"{wallet_service_url}/v1/wallets/detect",
                    json={"user_agent": user_agent}
                )
                if response.status_code == 200:
                    wallet_info = response.json()
                    wallet_vendor = wallet_info.get("detected_vendor", "generic")
                    supported_formats = wallet_info.get("supported_formats", [])
                    logger.info(f"Detected wallet: {wallet_vendor}, formats: {supported_formats}")
        except Exception as e:
            logger.warning(f"Failed to detect wallet from User-Agent: {e}")
    
    # Query active credential templates if credential service is available
    credential_configurations = {}
    
    if CREDENTIALS_SERVICE_AVAILABLE:
        try:
            # Import credential models to query active templates
            from subscription.models import CredentialTypeConfiguration
            from sqlalchemy import create_engine
            from sqlalchemy.orm import sessionmaker
            
            # Create database session
            db_url = os.getenv("DATABASE_URL", "postgresql://marty:marty_dev@postgres:5432/marty_credentials")
            engine = create_engine(db_url)
            SessionLocal = sessionmaker(bind=engine)
            db = SessionLocal()
            
            try:
                # Query active credential templates
                active_templates = db.query(CredentialTypeConfiguration).filter(
                    CredentialTypeConfiguration.is_active == True
                ).all()
                
                # Build credential configurations from templates
                for template in active_templates:
                    config_id = template.id
                    
                    # Parse supported formats from template
                    all_formats = template.formats or ["vc+sd-jwt", "jwt_vc_json"]
                    
                    # Filter formats by wallet capabilities
                    if supported_formats:
                        formats = [f for f in all_formats if f in supported_formats or f.replace("_", "+") in supported_formats]
                        if not formats:
                            # If wallet doesn't support any formats, skip this template
                            logger.info(f"Skipping template {template.name} - no format match for wallet {wallet_vendor}")
                            continue
                    else:
                        formats = all_formats
                    
                    # Build format-specific configurations
                    format_config = {}
                    if "vc+sd-jwt" in formats or "vc_sd_jwt" in formats:
                        format_config["format"] = "vc+sd-jwt"
                        format_config["scope"] = template.name.lower().replace(" ", "_")
                        format_config["cryptographic_binding_methods_supported"] = ["did:key", "did:web", "did:jwk"]
                        format_config["credential_signing_alg_values_supported"] = ["ES256", "ES384", "EdDSA"]
                        format_config["proof_types_supported"] = ["jwt"]
                        
                        # Add display metadata
                        format_config["display"] = [{
                            "name": template.display_name or template.name,
                            "locale": "en-US",
                            "logo": {
                                "uri": template.logo_url if hasattr(template, 'logo_url') and template.logo_url else f"{base_url}/assets/credential-logo.png",
                            },
                            "background_color": template.background_color if hasattr(template, 'background_color') and template.background_color else "#0066CC",
                            "text_color": template.text_color if hasattr(template, 'text_color') and template.text_color else "#FFFFFF",
                        }]
                        
                        # Add credential definition
                        vct = template.credential_type or template.name.replace(" ", "")
                        format_config["vct"] = vct
                    
                    elif "jwt_vc_json" in formats or "vc_jwt" in formats:
                        format_config["format"] = "jwt_vc_json"
                        format_config["scope"] = template.name.lower().replace(" ", "_")
                        format_config["cryptographic_binding_methods_supported"] = ["did:key", "did:web", "did:jwk"]
                        format_config["credential_signing_alg_values_supported"] = ["ES256", "ES384", "EdDSA"]
                        format_config["proof_types_supported"] = ["jwt"]
                        
                        # Add display metadata
                        format_config["display"] = [{
                            "name": template.display_name or template.name,
                            "locale": "en-US",
                        }]
                        
                        # Add credential definition with types
                        types = ["VerifiableCredential"]
                        if template.credential_type:
                            types.append(template.credential_type)
                        
                        format_config["credential_definition"] = {
                            "type": types,
                        }
                    
                    credential_configurations[config_id] = format_config
                
            finally:
                db.close()
        except Exception as e:
            logger.warning(f"Failed to load credential templates for issuer metadata: {e}")
            # Fall back to default configuration
            pass
    
    # If no templates loaded, provide default configuration
    if not credential_configurations:
        credential_configurations = {
            "default_credential": {
                "format": "vc+sd-jwt",
                "scope": "credential",
                "cryptographic_binding_methods_supported": ["did:key", "did:web"],
                "credential_signing_alg_values_supported": ["ES256", "EdDSA"],
                "proof_types_supported": ["jwt"],
                "display": [{
                    "name": "Verifiable Credential",
                    "locale": "en-US",
                }],
                "vct": "VerifiableCredential",
            }
        }
    
    # Build full issuer metadata
    metadata = {
        "credential_issuer": base_url,
        "credential_endpoint": f"{base_url}/api/issuance/credential",
        "token_endpoint": f"{base_url}/api/issuance/token",
        "deferred_credential_endpoint": f"{base_url}/api/issuance/deferred",
        "credential_configurations_supported": credential_configurations,
        "display": [{
            "name": "Marty Credential Issuer",
            "locale": "en-US",
            "logo": {
                "uri": f"{base_url}/assets/logo.png",
            },
        }],
    }
    
    # Add wallet compatibility metadata for debugging
    if user_agent and supported_formats:
        metadata["_wallet_detected"] = wallet_vendor
        metadata["_formats_filtered"] = len(all_formats if 'all_formats' in locals() else []) > len(credential_configurations)
    
    return metadata


# Run with: uvicorn oid4vc_api:app --reload
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
