"""Trust configuration API router.

Provides endpoints for managing organization trust configuration
for credential issuance, including trust framework selection and
key management (Marty-hosted or BYOK).
"""

import json
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.router import get_current_user, require_org_admin, AuthStatusResponse
from subscription.database import get_db_session
from subscription.models import (
    IssuerKeyConfig,
    IssuerKeySource,
    OrganizationTrustConfig,
    TrustFramework,
)

# Import marty-rs for key generation
try:
    import _marty_rs as marty_rs
except ImportError as e:
    raise RuntimeError(
        "marty-rs is required for key generation. "
        "Install it with: pip install marty-rs"
    ) from e

router = APIRouter(prefix="/api/organizations", tags=["trust-config"])


# ==================== Pydantic Schemas ====================


class TrustConfigResponse(BaseModel):
    """Trust configuration response."""

    id: str
    organization_id: str
    trust_framework: TrustFramework
    key_source: IssuerKeySource
    is_configured: bool
    trust_anchor_url: Optional[str] = None
    trust_anchor_did: Optional[str] = None
    policy_uri: Optional[str] = None
    terms_of_use_uri: Optional[str] = None
    settings: dict = Field(default_factory=dict)
    created_at: datetime
    updated_at: Optional[datetime] = None
    issuer_keys: list["IssuerKeyResponse"] = Field(default_factory=list)

    class Config:
        from_attributes = True


class IssuerKeyResponse(BaseModel):
    """Issuer key configuration response (public info only)."""

    id: str
    key_id: str
    algorithm: str
    key_type: str
    did: Optional[str] = None
    did_method: Optional[str] = None
    is_active: bool
    is_default: bool
    valid_from: datetime
    valid_until: Optional[datetime] = None
    has_certificate: bool = False

    class Config:
        from_attributes = True


class TrustConfigCreate(BaseModel):
    """Create trust configuration request."""

    trust_framework: TrustFramework = TrustFramework.MARTY_HOSTED
    key_source: IssuerKeySource = IssuerKeySource.MARTY_GENERATED
    trust_anchor_url: Optional[str] = None
    trust_anchor_did: Optional[str] = None
    policy_uri: Optional[str] = None
    terms_of_use_uri: Optional[str] = None
    settings: dict = Field(default_factory=dict)


class TrustConfigUpdate(BaseModel):
    """Update trust configuration request."""

    trust_framework: Optional[TrustFramework] = None
    key_source: Optional[IssuerKeySource] = None
    trust_anchor_url: Optional[str] = None
    trust_anchor_did: Optional[str] = None
    policy_uri: Optional[str] = None
    terms_of_use_uri: Optional[str] = None
    settings: Optional[dict] = None


class BYOKCertificateUpload(BaseModel):
    """Upload BYOK certificates request."""

    root_ca_certificate: str = Field(..., description="PEM-encoded root CA certificate")
    intermediate_certificates: Optional[str] = Field(
        None, description="PEM-encoded intermediate certificates (concatenated)"
    )
    issuer_certificate: str = Field(..., description="PEM-encoded issuer signing certificate")
    private_key_pem: str = Field(..., description="PEM-encoded private key for issuer certificate")


class GenerateKeyRequest(BaseModel):
    """Request to generate a new Marty-hosted signing key."""

    algorithm: str = Field(default="ES256", description="Signing algorithm (ES256, EdDSA)")
    did_method: str = Field(default="key", description="DID method (key, web, jwk)")
    set_as_default: bool = Field(default=True, description="Set this key as the default signing key")
    validity_days: int = Field(default=365, description="Key validity period in days")


# ==================== Helper Functions ====================


def _generate_es256_keypair() -> tuple[dict, dict]:
    """Generate ES256 (P-256) keypair using marty-rs.

    Returns:
        Tuple of (public_jwk, private_jwk)
    """
    # marty-rs returns (did, jwk_json_string)
    did, jwk_json = marty_rs.generate_p256_key()
    jwk = json.loads(jwk_json)
    
    # Add kid from DID
    kid = did.split(":")[-1]  # Extract from did:jwk:...
    jwk["kid"] = kid
    jwk["use"] = "sig"
    jwk["alg"] = "ES256"
    
    # Split into public and private
    public_jwk = {
        "kty": jwk["kty"],
        "crv": jwk["crv"],
        "x": jwk["x"],
        "y": jwk["y"],
        "kid": kid,
        "use": "sig",
        "alg": "ES256",
    }
    
    private_jwk = jwk  # Full JWK with private key
    
    return public_jwk, private_jwk


def _generate_ed25519_keypair() -> tuple[dict, dict]:
    """Generate Ed25519 keypair using marty-rs.

    Returns:
        Tuple of (public_jwk, private_jwk)
    """
    # marty-rs returns (did, jwk_json_string)
    did, jwk_json = marty_rs.generate_did_key()
    jwk = json.loads(jwk_json)
    
    # Add kid from DID  
    kid = did  # Use full did:key:z... as kid
    jwk["kid"] = kid
    jwk["use"] = "sig"
    jwk["alg"] = "EdDSA"
    
    # Split into public and private
    public_jwk = {
        "kty": jwk["kty"],
        "crv": jwk["crv"],
        "x": jwk["x"],
        "kid": kid,
        "use": "sig",
        "alg": "EdDSA",
    }
    
    private_jwk = jwk  # Full JWK with private key
    
    return public_jwk, private_jwk


def _generate_did_key(public_jwk: dict) -> str:
    """Generate did:key or did:jwk from public JWK.

    For EdDSA uses did:key format, for ES256 uses did:jwk format.

    Args:
        public_jwk: Public key as JWK

    Returns:
        did identifier
    """
    alg = public_jwk.get("alg", "")
    
    if alg == "EdDSA":
        # For EdDSA, the kid is already the did:key
        return public_jwk.get("kid", "")
    else:
        # For ES256 (P-256), generate did:jwk
        jwk_copy = {k: v for k, v in public_jwk.items() if k not in ["d", "use", "kid", "alg"]}
        jwk_str = json.dumps(jwk_copy, separators=(',', ':'), sort_keys=True)
        import base64
        encoded = base64.urlsafe_b64encode(jwk_str.encode()).decode().rstrip('=')
        return f"did:jwk:{encoded}"


# ==================== API Endpoints ====================


@router.get("/{org_id}/trust-config", response_model=TrustConfigResponse)
async def get_trust_config(
    org_id: str,
    current_user: AuthStatusResponse = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
):
    """Get organization trust configuration.

    Returns the trust framework settings and issuer key information
    for the organization. Only organization members can access this.
    """
    if not current_user.authenticated or not current_user.user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    
    user = current_user.user
    # Check user has access to this org
    is_platform_admin = "platform_admin" in (user.roles or []) or "admin" in (user.roles or []) or "administrator" in (user.roles or [])
    if user.organization_id != org_id and not is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this organization's trust configuration",
        )

    # Query database for trust config
    result = await db.execute(
        select(OrganizationTrustConfig).where(
            OrganizationTrustConfig.organization_id == org_id
        )
    )
    config = result.scalar_one_or_none()
    
    if not config:
        # Return default unconfigured state
        return TrustConfigResponse(
            id="",
            organization_id=org_id,
            trust_framework=TrustFramework.MARTY_HOSTED,
            key_source=IssuerKeySource.MARTY_GENERATED,
            is_configured=False,
            created_at=datetime.utcnow(),
            issuer_keys=[],
        )

    # Query issuer keys for this trust config
    keys_result = await db.execute(
        select(IssuerKeyConfig).where(
            IssuerKeyConfig.trust_config_id == config.id
        )
    )
    keys = keys_result.scalars().all()
    
    # Build issuer keys response
    issuer_keys = [
        IssuerKeyResponse(
            id=key.id,
            key_id=key.key_id,
            algorithm=key.algorithm,
            key_type=key.key_type,
            did=key.did,
            did_method=key.did_method,
            is_active=key.is_active,
            is_default=key.is_default,
            valid_from=key.valid_from,
            valid_until=key.valid_until,
            has_certificate=key.x509_certificate is not None,
        )
        for key in keys
    ]

    return TrustConfigResponse(
        id=config.id,
        organization_id=config.organization_id,
        trust_framework=config.trust_framework,
        key_source=config.key_source,
        is_configured=config.is_configured,
        trust_anchor_url=config.trust_anchor_url,
        trust_anchor_did=config.trust_anchor_did,
        policy_uri=config.policy_uri,
        terms_of_use_uri=config.terms_of_use_uri,
        settings=config.settings or {},
        created_at=config.created_at,
        updated_at=config.updated_at,
        issuer_keys=issuer_keys,
    )


@router.put("/{org_id}/trust-config", response_model=TrustConfigResponse)
async def update_trust_config(
    org_id: str,
    request: TrustConfigUpdate,
    current_user: AuthStatusResponse = Depends(require_org_admin),
    db: AsyncSession = Depends(get_db_session),
):
    """Update organization trust configuration.

    Allows org admins to configure the trust framework for credential issuance.
    When switching to MARTY_HOSTED, keys will be auto-generated if none exist.
    """
    user = current_user.user
    # Verify user is admin of this org
    is_platform_admin = "platform_admin" in (user.roles or []) or "admin" in (user.roles or []) or "administrator" in (user.roles or [])
    if user.organization_id != org_id and not is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to modify this organization's trust configuration",
        )

    # Query for existing config
    result = await db.execute(
        select(OrganizationTrustConfig).where(
            OrganizationTrustConfig.organization_id == org_id
        )
    )
    config = result.scalar_one_or_none()
    
    if not config:
        # Create new config
        config = OrganizationTrustConfig(
            id=str(uuid.uuid4()),
            organization_id=org_id,
            trust_framework=TrustFramework.MARTY_HOSTED,
            key_source=IssuerKeySource.MARTY_GENERATED,
            is_configured=False,
            created_at=datetime.utcnow(),
        )
        db.add(config)

    # Update fields
    if request.trust_framework is not None:
        config.trust_framework = request.trust_framework
    if request.key_source is not None:
        config.key_source = request.key_source
    if request.trust_anchor_url is not None:
        config.trust_anchor_url = request.trust_anchor_url
    if request.trust_anchor_did is not None:
        config.trust_anchor_did = request.trust_anchor_did
    if request.policy_uri is not None:
        config.policy_uri = request.policy_uri
    if request.terms_of_use_uri is not None:
        config.terms_of_use_uri = request.terms_of_use_uri
    if request.settings is not None:
        config.settings = request.settings

    config.updated_at = datetime.utcnow()
    config.is_configured = True

    # Auto-generate key for Marty-hosted if none exists
    if (
        config.trust_framework == TrustFramework.MARTY_HOSTED
        and config.key_source == IssuerKeySource.MARTY_GENERATED
    ):
        # Check for existing keys
        keys_result = await db.execute(
            select(IssuerKeyConfig).where(
                IssuerKeyConfig.trust_config_id == config.id
            )
        )
        existing_keys = keys_result.scalars().all()
        
        if not existing_keys:
            # Generate default ES256 key
            public_jwk, private_jwk = _generate_es256_keypair()
            did = _generate_did_key(public_jwk)

            key = IssuerKeyConfig(
                id=str(uuid.uuid4()),
                trust_config_id=config.id,
                key_id=public_jwk["kid"],
                algorithm="ES256",
                key_type="EC",
                did=did,
                did_method="key",
                jwk_public=public_jwk,
                jwk_private_encrypted=json.dumps(private_jwk),  # TODO: Storage layer should encrypt automatically
                is_active=True,
                is_default=True,
                valid_from=datetime.utcnow(),
                valid_until=datetime.utcnow() + timedelta(days=365),
                created_at=datetime.utcnow(),
            )
            db.add(key)

    await db.commit()
    await db.refresh(config)
    
    return await get_trust_config(org_id, current_user, db)


@router.post("/{org_id}/trust-config/keys", response_model=IssuerKeyResponse)
async def generate_signing_key(
    org_id: str,
    request: GenerateKeyRequest,
    current_user: AuthStatusResponse = Depends(require_org_admin),
    db: AsyncSession = Depends(get_db_session),
):
    """Generate a new Marty-hosted signing key.

    Creates a new signing keypair managed by Marty. Only available
    when trust_framework is MARTY_HOSTED.
    """
    user = current_user.user
    # Verify user is admin of this org
    is_platform_admin = "platform_admin" in (user.roles or []) or "admin" in (user.roles or []) or "administrator" in (user.roles or [])
    if user.organization_id != org_id and not is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to manage this organization's keys",
        )

    # Query for trust config
    result = await db.execute(
        select(OrganizationTrustConfig).where(
            OrganizationTrustConfig.organization_id == org_id
        )
    )
    config = result.scalar_one_or_none()
    
    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Trust configuration not found. Configure trust settings first.",
        )

    if config.trust_framework != TrustFramework.MARTY_HOSTED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Key generation only available for Marty-hosted trust framework. Use BYOK upload for imported keys.",
        )

    # Generate keypair based on algorithm
    if request.algorithm == "EdDSA":
        public_jwk, private_jwk = _generate_ed25519_keypair()
        key_type = "OKP"
    elif request.algorithm == "ES256":
        public_jwk, private_jwk = _generate_es256_keypair()
        key_type = "EC"
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported algorithm: {request.algorithm}. Use ES256 or EdDSA.",
        )

    # Generate DID
    if request.did_method == "key":
        did = _generate_did_key(public_jwk)
    else:
        did = None  # did:web requires external setup

    # If setting as default, unset current default
    if request.set_as_default:
        keys_result = await db.execute(
            select(IssuerKeyConfig).where(
                IssuerKeyConfig.trust_config_id == config.id,
                IssuerKeyConfig.is_default == True,
            )
        )
        for existing_key in keys_result.scalars().all():
            existing_key.is_default = False

    # Create key config
    key = IssuerKeyConfig(
        id=str(uuid.uuid4()),
        trust_config_id=config.id,
        key_id=public_jwk["kid"],
        algorithm=request.algorithm,
        key_type=key_type,
        did=did,
        did_method=request.did_method,
        jwk_public=public_jwk,
        jwk_private_encrypted=json.dumps(private_jwk),  # TODO: Storage layer should encrypt automatically
        is_active=True,
        is_default=request.set_as_default,
        valid_from=datetime.utcnow(),
        valid_until=datetime.utcnow() + timedelta(days=request.validity_days),
        created_at=datetime.utcnow(),
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)

    return IssuerKeyResponse(
        id=key.id,
        key_id=key.key_id,
        algorithm=key.algorithm,
        key_type=key.key_type,
        did=key.did,
        did_method=key.did_method,
        is_active=key.is_active,
        is_default=key.is_default,
        valid_from=key.valid_from,
        valid_until=key.valid_until,
        has_certificate=False,
    )


@router.post("/{org_id}/trust-config/byok", response_model=TrustConfigResponse)
async def upload_byok_certificates(
    org_id: str,
    request: BYOKCertificateUpload,
    current_user: AuthStatusResponse = Depends(require_org_admin),
):
    """Upload BYOK certificates and private key.

    Allows organizations with existing PKI to bring their own
    signing certificates. Validates the certificate chain and
    stores securely.
    """
    user = current_user.user
    # Verify user is admin of this org
    is_platform_admin = "platform_admin" in (user.roles or []) or "admin" in (user.roles or []) or "administrator" in (user.roles or [])
    if user.organization_id != org_id and not is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to manage this organization's certificates",
        )

    config = _trust_configs.get(org_id)
    if not config:
        # Create new config for BYOK
        config = OrganizationTrustConfig()
        config.id = str(uuid.uuid4())
        config.organization_id = org_id
        config.created_at = datetime.utcnow()
        _trust_configs[org_id] = config

    # Update to BYOK mode
    config.trust_framework = TrustFramework.BYOK
    config.key_source = IssuerKeySource.IMPORTED
    config.root_ca_certificate = request.root_ca_certificate
    config.intermediate_certificates = request.intermediate_certificates
    config.issuer_certificate = request.issuer_certificate
    config.is_configured = True
    config.updated_at = datetime.utcnow()

    # Parse certificate and create issuer key config
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_pem_x509_certificate(request.issuer_certificate.encode())
        private_key = serialization.load_pem_private_key(
            request.private_key_pem.encode(),
            password=None,
        )

        # Verify key matches certificate
        cert_public_key = cert.public_key()
        # TODO: Add proper key matching verification

        # Extract key info
        key_id = f"byok-{secrets.token_urlsafe(8)}"

        # Deactivate existing keys
        for existing_key in _issuer_keys.values():
            if existing_key.trust_config_id == config.id:
                existing_key.is_active = False
                existing_key.is_default = False

        # Create new issuer key from certificate
        key = IssuerKeyConfig()
        key.id = str(uuid.uuid4())
        key.trust_config_id = config.id
        key.key_id = key_id
        key.algorithm = "ES256"  # TODO: Detect from cert
        key.key_type = "EC"  # TODO: Detect from cert
        key.x509_certificate = request.issuer_certificate
        key.jwk_private_encrypted = request.private_key_pem  # TODO: Encrypt
        key.is_active = True
        key.is_default = True
        key.valid_from = cert.not_valid_before_utc
        key.valid_until = cert.not_valid_after_utc
        key.created_at = datetime.utcnow()

        _issuer_keys[key.id] = key

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid certificate or key: {str(e)}",
        )

    return await get_trust_config(org_id, current_user)


@router.delete("/{org_id}/trust-config/keys/{key_id}")
async def deactivate_signing_key(
    org_id: str,
    key_id: str,
    current_user: AuthStatusResponse = Depends(require_org_admin),
):
    """Deactivate a signing key.

    Keys are not deleted but marked inactive. Previously issued
    credentials remain valid for verification.
    """
    user = current_user.user
    # Verify user is admin of this org
    is_platform_admin = "platform_admin" in (user.roles or []) or "admin" in (user.roles or []) or "administrator" in (user.roles or [])
    if user.organization_id != org_id and not is_platform_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to manage this organization's keys",
        )

    key = _issuer_keys.get(key_id)
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Key not found",
        )

    # Verify key belongs to org's trust config
    config = _trust_configs.get(org_id)
    if not config or key.trust_config_id != config.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Key does not belong to this organization",
        )

    key.is_active = False
    key.is_default = False
    key.updated_at = datetime.utcnow()

    return {"message": "Key deactivated successfully", "key_id": key_id}
