"""Open Badges API endpoints."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from subscription.database import get_db_session
from subscription.models import CredentialType, CredentialTypeConfiguration

# Status integration for credential revocation/suspension support (optional)
_STATUS_INTEGRATION_AVAILABLE = False
try:
    from open_badges.status_integration import (
        inject_credential_status,
        is_credential_status_enabled,
    )
    _STATUS_INTEGRATION_AVAILABLE = True
except ImportError:
    # Status list module not available, credential status features disabled
    def inject_credential_status(credential, *args, **kwargs):
        return credential
    def is_credential_status_enabled():
        return False

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/open-badges", tags=["Open Badges"])

_MARTY_RS_AVAILABLE = False
try:
    import _marty_rs as marty_rs  # type: ignore
    _MARTY_RS_AVAILABLE = True
except Exception:
    marty_rs = None

_CRYPTO_BRIDGE_AVAILABLE = False
try:
    from marty_plugin.common.crypto_bridge import (
        open_badge_ob2_issue as _open_badge_ob2_issue,
        open_badge_ob2_verify as _open_badge_ob2_verify,
        open_badge_ob3_issue as _open_badge_ob3_issue,
        open_badge_ob3_verify as _open_badge_ob3_verify,
    )
    _CRYPTO_BRIDGE_AVAILABLE = True
except Exception:
    _open_badge_ob2_issue = None
    _open_badge_ob2_verify = None
    _open_badge_ob3_issue = None
    _open_badge_ob3_verify = None


class IssueOpenBadgeRequest(BaseModel):
    """Request to issue an Open Badge credential."""

    credential_configuration_id: str = Field(..., description="Credential configuration ID")
    version: Literal["v2", "v3"] = Field("v2", description="Open Badges version")
    issuer_name: str = Field("Marty Issuer", description="Issuer display name")
    recipient_identity: str = Field("user@example.org", description="Recipient identity")
    recipient_name: str | None = Field(None, description="Recipient display name")
    badge_name: str = Field("Marty Open Badge", description="Badge name")
    badge_description: str = Field(
        "Issued by Marty",
        description="Badge description",
    )
    include_document_store: bool = Field(
        True,
        description="Include verification document_store in response",
    )
    include_revocation_status: bool = Field(
        True,
        description="Include revocation status in credential (V3 only)",
    )
    include_suspension_status: bool = Field(
        True,
        description="Include suspension status in credential (V3 only)",
    )


class IssueOpenBadgeResponse(BaseModel):
    """Response with issued Open Badge credential."""

    success: bool
    issued: bool
    version: str
    credential: dict[str, Any]
    document_store: dict[str, Any] | None = None
    warnings: list[str] = Field(default_factory=list)
    message: str | None = None


class VerifyOpenBadgeRequest(BaseModel):
    """Request to verify an Open Badge credential."""

    version: Literal["v2", "v3"] = Field("v2", description="Open Badges version")
    credential: dict[str, Any] = Field(..., description="Credential or assertion JSON")
    document_store: dict[str, Any] | None = Field(
        None,
        description="Document store for verification",
    )
    recipient_identity: str | None = Field(None, description="Expected recipient identity")


class VerifyOpenBadgeResponse(BaseModel):
    """Response with Open Badge verification result."""

    success: bool
    valid: bool
    version: str
    errors: list[str] = Field(default_factory=list)
    error_codes: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    normalized: dict[str, Any] | None = None
    message: str | None = None


def _public_jwk(jwk: dict[str, Any]) -> dict[str, Any]:
    """Strip private key material from a JWK."""
    return {key: value for key, value in jwk.items() if key not in {"d"}}


def _iso_timestamp() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _build_ob2_issue_request(
    body: IssueOpenBadgeRequest, issuer_key: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    issuer_did = issuer_key["did"]
    verification_method = f"{issuer_did}#key-1"
    badge_id = f"urn:uuid:{uuid4()}"
    assertion_id = f"urn:uuid:{uuid4()}"

    issuer = {"id": issuer_did, "type": "Issuer", "name": body.issuer_name}
    badge = {
        "id": badge_id,
        "type": "BadgeClass",
        "name": body.badge_name,
        "description": body.badge_description,
        "issuer": issuer,
    }
    recipient = {
        "identity": body.recipient_identity,
        "type": "email",
        "hashed": False,
    }
    if body.recipient_name:
        recipient["name"] = body.recipient_name

    assertion = {
        "@context": "https://w3id.org/openbadges/v2",
        "id": assertion_id,
        "type": "Assertion",
        "badge": badge,
        "issuedOn": _iso_timestamp(),
        "recipient": recipient,
    }

    request = {
        "assertion": assertion,
        "signing": {
            "jwk": issuer_key["jwk"],
            "creator": verification_method,
            "verification_type": "signed",
        },
    }

    store = {
        verification_method: {
            "id": verification_method,
            "publicKeyJwk": _public_jwk(issuer_key["jwk"]),
        },
        issuer_did: issuer,
        badge_id: badge,
    }

    return request, store


def _build_ob3_issue_request(
    body: IssueOpenBadgeRequest, issuer_key: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    issuer_did = issuer_key["did"]
    verification_method = f"{issuer_did}#key-1"
    credential_id = f"urn:uuid:{uuid4()}"
    achievement_id = f"urn:uuid:{uuid4()}"

    credential = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://purl.imsglobal.org/spec/ob/v3p0/context.json",
        ],
        "id": credential_id,
        "type": [
            "OpenBadgeCredential",
            "AchievementCredential",
            "VerifiableCredential",
        ],
        "issuer": {"id": issuer_did, "name": body.issuer_name},
        "issuanceDate": _iso_timestamp(),
        "credentialSubject": {
            "id": body.recipient_identity,
            "type": "AchievementSubject",
            "name": body.recipient_name or body.recipient_identity,
            "achievement": {
                "id": achievement_id,
                "type": "Achievement",
                "name": body.badge_name,
                "description": body.badge_description,
            },
            "recipient": {"identity": body.recipient_identity, "type": "email"},
        },
    }

    request = {
        "credential": credential,
        "signing": {
            "jwk": issuer_key["jwk"],
            "verification_method": verification_method,
            "verification_method_type": "JsonWebKey2020",
            "controller": issuer_did,
            "proof_purpose": "assertionMethod",
        },
    }

    store = {
        verification_method: {
            "id": verification_method,
            "type": "JsonWebKey2020",
            "controller": issuer_did,
            "publicKeyJwk": _public_jwk(issuer_key["jwk"]),
        }
    }

    return request, store


def _context_contains(value: dict[str, Any], needle: str) -> bool:
    context = value.get("@context") or value.get("context")
    if isinstance(context, str):
        return needle in context
    if isinstance(context, list):
        return any(isinstance(item, str) and needle in item for item in context)
    return False


async def _get_open_badge_config(
    config_id: str,
    db: AsyncSession,
) -> CredentialTypeConfiguration:
    result = await db.execute(
        select(CredentialTypeConfiguration).where(
            CredentialTypeConfiguration.id == config_id,
            CredentialTypeConfiguration.is_active == True,
        )
    )
    config = result.scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail="Credential configuration not found")
    if config.credential_type != CredentialType.OPEN_BADGE:
        raise HTTPException(status_code=400, detail="Credential configuration is not an Open Badge")
    if not config.issuer_jwk or not config.issuer_did:
        raise HTTPException(status_code=400, detail="Credential configuration missing issuer key")
    return config


@router.post("/issue", response_model=IssueOpenBadgeResponse)
async def issue_open_badge(
    body: IssueOpenBadgeRequest,
    db: AsyncSession = Depends(get_db_session),
):
    """Issue an Open Badge (OB2 or OB3)."""
    config = await _get_open_badge_config(body.credential_configuration_id, db)

    issuer_key = {
        "did": config.issuer_did,
        "jwk": config.issuer_jwk,
    }
    warnings: list[str] = []

    if body.version == "v3":
        request, store = _build_ob3_issue_request(body, issuer_key)
        default_version = "3.0"
        issue_fn = (
            getattr(marty_rs, "open_badge_ob3_issue", None)
            if _MARTY_RS_AVAILABLE
            else _open_badge_ob3_issue
        )
        
        # Inject credential status for V3 credentials (revocation/suspension support)
        credential_id = request["credential"]["id"]
        issuer_did = issuer_key["did"]
        request["credential"], status_warnings = await inject_credential_status(
            credential=request["credential"],
            credential_id=credential_id,
            issuer_id=issuer_did,
            include_revocation=body.include_revocation_status,
            include_suspension=body.include_suspension_status,
        )
        warnings.extend(status_warnings)
    else:
        request, store = _build_ob2_issue_request(body, issuer_key)
        default_version = "2.0"
        issue_fn = (
            getattr(marty_rs, "open_badge_ob2_issue", None)
            if _MARTY_RS_AVAILABLE
            else _open_badge_ob2_issue
        )

    if issue_fn is not None:
        try:
            result_json = issue_fn(json.dumps(request))
            result = json.loads(result_json)
            credential = result.get("credential") or {}
            issued = bool(result.get("issued", False))
            version = str(result.get("version", default_version))
            warnings = list(result.get("warnings", []))
        except Exception as exc:
            logger.error(f"Failed to issue Open Badge: {exc}")
            raise HTTPException(status_code=500, detail=f"Open Badge issuance failed: {exc}")
    else:
        warnings.append("Open Badge signing unavailable; issued unsigned credential")
        credential = request.get("credential") or request.get("assertion") or {}
        issued = True
        version = default_version

    document_store = store if body.include_document_store else None

    return IssueOpenBadgeResponse(
        success=True,
        issued=issued,
        version=version,
        credential=credential,
        document_store=document_store,
        warnings=warnings,
        message="Open Badge issued",
    )


@router.post("/verify", response_model=VerifyOpenBadgeResponse)
async def verify_open_badge(body: VerifyOpenBadgeRequest):
    """Verify an Open Badge (OB2 or OB3)."""
    warnings: list[str] = []

    if body.version == "v3":
        request = {"credential": body.credential, "document_store": body.document_store}
        verify_fn = (
            getattr(marty_rs, "open_badge_ob3_verify", None)
            if _MARTY_RS_AVAILABLE
            else _open_badge_ob3_verify
        )
        default_version = "3.0"
    else:
        request = {
            "assertion": body.credential,
            "document_store": body.document_store,
            "recipient_identity": body.recipient_identity,
        }
        verify_fn = (
            getattr(marty_rs, "open_badge_ob2_verify", None)
            if _MARTY_RS_AVAILABLE
            else _open_badge_ob2_verify
        )
        default_version = "2.0"

    if verify_fn is not None:
        try:
            result_json = verify_fn(json.dumps(request))
            result = json.loads(result_json)
            return VerifyOpenBadgeResponse(
                success=True,
                valid=bool(result.get("valid", False)),
                version=str(result.get("version", default_version)),
                errors=list(result.get("errors", [])),
                error_codes=list(result.get("error_codes", [])),
                warnings=list(result.get("warnings", [])),
                normalized=result.get("normalized"),
                message="Open Badge verification completed",
            )
        except Exception as exc:
            logger.error(f"Failed to verify Open Badge: {exc}")
            raise HTTPException(status_code=500, detail=f"Open Badge verification failed: {exc}")

    warnings.append("Open Badge verification unavailable; performed minimal checks")
    credential = body.credential
    if body.version == "v3":
        valid = _context_contains(credential, "openbadges/v3") or _context_contains(
            credential, "ob/v3p0/context.json"
        )
        types = credential.get("type", [])
        if isinstance(types, str):
            types = [types]
        valid = bool(valid and ("OpenBadgeCredential" in types or "AchievementCredential" in types))
    else:
        valid = _context_contains(credential, "openbadges/v2") and credential.get("type") == "Assertion"
        valid = bool(valid and credential.get("badge"))

    return VerifyOpenBadgeResponse(
        success=True,
        valid=valid,
        version=default_version,
        warnings=warnings,
        normalized=None,
        message="Open Badge verification completed (minimal checks)",
    )
