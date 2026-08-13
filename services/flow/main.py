"""
Flow Service

Manages Flows - the orchestration of credential operations.

A Flow defines:
- Flow type (issuance, verification, presentation)
- Steps and transitions
- State machine for the credential journey
- Integration points (callbacks, webhooks)
- Timeout and expiry settings

Verification Flows:
- POST /v1/flows/verify - Start async verification (returns request_uri + QR code)
- GET /v1/flows/instances/{id}/request - OID4VP request object for wallet
- POST /v1/flows/instances/{id}/submit - Submit VP token to complete flow

Port: 8011
"""

from __future__ import annotations

import asyncio
import base64
import copy
import hmac
import hashlib
import json
import logging
import os
import re
import urllib.parse
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, AsyncGenerator, Literal

import httpx
from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from jwcrypto import jwk
from jwcrypto import jwt as jwcrypto_jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from typing import Annotated

from marty_common import (
    ClaimResultPayload,
    CredentialOfferPayload,
    ensure_membership_permission,
    MIPMessage,
    MessageType,
    PresentationRequestPayload,
    VerificationResultPayload,
)
from marty_common.org_authorization import get_organization_client
from marty_common.service_setup import create_service_app
from common.grpc_factory import create_grpc_channel
from common.native_backend import NativeOperationError
from common.oid4vp_native import (
    build_oid4vp_presentation_request,
    credential_requirement_input,
    initialize_native_oid4vp_backend,
    parse_policy_requirements,
    wallet_registry_format_names,
)
from common.webhook_signatures import is_valid_event_secret, payload_digest
from flow.callback_outbox import (
    CallbackOutboxEvent,
    deliver_due_callback_events,
    new_callback_event,
    new_lease_token,
    require_registered_callback_destination,
    run_callback_dispatcher,
)
from flow.infrastructure.adapters import PostgresFlowRepository
from flow.native import (
    NativeFlowOperationError,
    evaluate_transition as evaluate_native_flow_transition,
    initialize_native_flow_backend,
    is_terminal_status as is_native_terminal_status,
    select_next_step as select_native_next_step,
    validate_graph as validate_native_flow_graph,
)
from protocol_version import MIP_VERSION
from common.application_event_auth import (
    AUDIENCE as APPLICATION_EVENT_AUDIENCE,
    PRODUCER as APPLICATION_EVENT_PRODUCER,
    ApplicationEventAuthError,
    ApplicationEventEvidence,
    authenticate_application_event,
    consume_application_event_replay,
    validate_application_event_configuration,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "flow-service"
SERVICE_PORT = int(os.environ.get("FLOW_SERVICE_PORT", "8011"))
ISSUANCE_SERVICE_URL = os.environ.get("ISSUANCE_SERVICE_URL", "http://issuance:8005")
ISSUANCE_GRPC_TARGET = os.environ.get("ISSUANCE_GRPC_TARGET", "issuance:9005")

# OID4VP Request Objects are signed through an issuer DID. The gateway resolves
# its active profile and the flow service never receives KMS coordinates.
_OID4VP_DID_WEB_PATH = "oid4vp"
_SD_JWT_PRESENTATION_ALGS = {
    "sd-jwt_alg_values": ["ES256", "EdDSA"],
    "kb-jwt_alg_values": ["ES256", "EdDSA"],
}
_DC_API_PROTOCOL = "openid4vp-v1-signed"
_SIOP_ID_TOKEN_ALGS = ("ES256", "EdDSA")
_SIOP_JWK_SUBJECT_PREFIX = "urn:ietf:params:oauth:jwk-thumbprint"
_SIOP_CLOCK_SKEW_SECONDS = 60
_DC_API_JWT_RESPONSE_MODE = "dc_api.jwt"
_HAIP_JWE_ALG = "ECDH-ES"
_HAIP_JWE_ENC = "A256GCM"
_HAIP_JWE_ENC_VALUES = ["A128GCM", _HAIP_JWE_ENC]
_SUPPORTED_HAIP_JWE_ALGS = {_HAIP_JWE_ALG}
_SUPPORTED_HAIP_JWE_ENCS = set(_HAIP_JWE_ENC_VALUES)


def _origin_for_base_url(base_url: str) -> str:
    """Normalize a verifier base URL to its origin."""
    parsed = urllib.parse.urlparse(base_url)
    if not parsed.scheme or not parsed.netloc:
        raise RuntimeError(f"PUBLIC_BASE_URL must include scheme and host: {base_url}")
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def _expected_origins_for_dc_api(base_url: str) -> list[str]:
    """Return allowed verifier origins for OpenID4VP over the DC API."""
    configured_origins = os.environ.get("VERIFIER_EXPECTED_ORIGINS", "")
    if configured_origins.strip():
        origins = [
            value.strip().rstrip("/")
            for value in configured_origins.split(",")
            if value.strip()
        ]
        if origins:
            return origins
    return [_origin_for_base_url(base_url)]


def _verification_audience_for_origin(origin: str) -> str:
    """Return the OpenID4VP audience value for DC API responses."""
    return f"origin:{origin.rstrip('/')}"


def _read_secret_value(name: str) -> str:
    value = os.environ.get(name)
    if value:
        return value.strip()
    file_path = os.environ.get(f"{name}_FILE")
    if file_path:
        try:
            return Path(file_path).read_text(encoding="utf-8").strip()
        except OSError:
            logger.warning(
                "Unable to read %s_FILE at %s", name, file_path, exc_info=True
            )
    return ""


def _configured_oid4vp_issuer_did() -> str:
    """Return the deployment's public verifier DID, never a key selector."""
    configured = (
        os.environ.get("OID4VP_ISSUER_DID") or os.environ.get("MARTY_ISSUER_DID") or ""
    ).strip()
    if configured:
        return configured
    public_base_url = os.environ.get("PUBLIC_BASE_URL", "https://beta.elevenidllc.com")
    parsed = urllib.parse.urlparse(public_base_url)
    authority = parsed.netloc.strip().replace(":", "%3A")
    org_slug = (os.environ.get("MARTY_ORG_SLUG") or "marty").strip() or "marty"
    if not authority:
        return ""
    return f"did:web:{authority}:orgs:{org_slug}"


async def _oid4vp_issuer_identity(
    organization_id: str,
    issuer_did: str | None = None,
) -> dict[str, Any]:
    """Resolve a public verifier DID to one org-owned signing identity."""
    resolved_did = (issuer_did or _configured_oid4vp_issuer_did()).strip()
    if not resolved_did.startswith("did:"):
        raise HTTPException(
            status_code=422,
            detail=(
                "issuer_did is required to start a signed verification flow; "
                "configure OID4VP_ISSUER_DID for service-managed defaults."
            ),
        )
    base_url = os.environ.get(
        "SIGNING_KEYS_INTERNAL_URL",
        "http://gateway:8000/internal/signing-keys",
    ).rstrip("/")
    api_key = _read_secret_value("SIGNING_KEYS_INTERNAL_API_KEY") or _read_secret_value(
        "ISSUANCE_API_KEY"
    )
    if not api_key:
        raise HTTPException(
            status_code=503, detail="Issuer DID signing API is not configured"
        )
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                f"{base_url}/resolve-issuer-did",
                params={
                    "organization_id": organization_id,
                    "issuer_did": resolved_did,
                    "key_purpose": "oid4vp_request_signing",
                    # This is the operation's internal wire capability, not a
                    # caller-selected credential profile.  Supplying it makes
                    # DID resolution use the complete organization + DID +
                    # purpose + format + algorithm tuple and excludes stale,
                    # incomplete profile records.
                    "credential_format": "oauth-authz-req+jwt",
                    "algorithm": "ES256",
                },
                headers={"X-API-Key": api_key},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503, detail="Issuer-profile identity service is unavailable"
        ) from exc
    if response.status_code in {404, 409, 422}:
        try:
            detail = response.json().get("detail")
        except Exception:  # noqa: BLE001
            detail = None
        raise HTTPException(
            status_code=response.status_code,
            detail=detail or "OID4VP issuer DID could not be resolved",
        )
    if response.status_code >= 400:
        raise HTTPException(
            status_code=503, detail="OID4VP issuer DID resolver is unavailable"
        )
    resolved = response.json()
    if resolved.get("organization_id") != organization_id:
        raise HTTPException(
            status_code=409,
            detail="Issuer DID resolver returned an identity outside the requested organization.",
        )
    identity = {
        "organization_id": resolved.get("organization_id"),
        "issuer_did": resolved.get("issuer_did"),
        "verification_method_id": resolved.get("verification_method_id"),
        "public_jwk": resolved.get("public_jwk"),
        "did_document": resolved.get("did_document"),
        "key_purpose": resolved.get("key_purpose"),
        "algorithm": resolved.get("algorithm"),
    }
    public_jwk = identity.get("public_jwk")
    identity_issuer_did = str(identity.get("issuer_did") or "")
    if (
        identity.get("key_purpose") != "oid4vp_request_signing"
        or identity.get("algorithm") != "ES256"
        or not identity_issuer_did.startswith("did:")
        or not str(identity.get("verification_method_id") or "").startswith(
            f"{identity_issuer_did}#"
        )
        or not isinstance(public_jwk, dict)
        or public_jwk.get("kty") != "EC"
        or public_jwk.get("crv") != "P-256"
        or any(secret in public_jwk for secret in ("d", "p", "q", "k"))
    ):
        raise HTTPException(
            status_code=503,
            detail="OID4VP issuer DID returned an invalid signing identity",
        )
    if identity_issuer_did != resolved_did:
        raise HTTPException(
            status_code=409,
            detail="Issuer DID resolver returned a different public identity",
        )
    return identity


async def _sign_request_object_with_issuer_did(
    *,
    organization_id: str,
    identity: dict[str, Any],
    protected_header: dict[str, Any],
    claims: dict[str, Any],
) -> str:
    """Create compact JWS through the tenant-scoped issuer DID resolver."""
    protected = _base64url_encode(
        json.dumps(protected_header, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
    )
    payload = _base64url_encode(
        json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signing_input = f"{protected}.{payload}".encode("ascii")
    base_url = os.environ.get(
        "SIGNING_KEYS_INTERNAL_URL",
        "http://gateway:8000/internal/signing-keys",
    ).rstrip("/")
    api_key = _read_secret_value("SIGNING_KEYS_INTERNAL_API_KEY") or _read_secret_value(
        "ISSUANCE_API_KEY"
    )
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{base_url}/issuer-dids/sign",
                params={"organization_id": organization_id},
                headers={"X-API-Key": api_key},
                json={
                    "issuer_did": identity["issuer_did"],
                    "credential_format": "oauth-authz-req+jwt",
                    "key_purpose": "oid4vp_request_signing",
                    "payload_b64": _base64url_encode(signing_input),
                    "algorithm": "ES256",
                },
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503, detail="Issuer DID signing service is unavailable"
        ) from exc
    if response.status_code >= 400:
        raise HTTPException(status_code=503, detail="Issuer DID request signing failed")
    signed = response.json()
    if (
        signed.get("issuer_did") != identity.get("issuer_did")
        or signed.get("verification_method_id")
        != identity.get("verification_method_id")
        or signed.get("algorithm") != "ES256"
    ):
        raise HTTPException(
            status_code=503,
            detail="Issuer DID signer returned a mismatched identity",
        )
    signature = signed.get("signature_raw_b64") or (
        signed.get("signature_b64")
        if signed.get("signature_encoding") == "raw_ieee_p1363"
        else None
    )
    if not isinstance(signature, str) or not signature:
        raise HTTPException(
            status_code=503,
            detail="Issuer DID signer did not return an ES256 JWS signature",
        )
    return f"{protected}.{payload}.{signature}"


VERIFIER_CLIENT_ID = os.environ.get(
    "VERIFIER_CLIENT_ID", ""
)  # Will be set based on PUBLIC_BASE_URL

# Replay state is committed by the repository with the terminal decision.
_NONCE_TTL_SECONDS = int(os.environ.get("NONCE_TTL_SECONDS", "3600"))
_nonce_redis: Any = None  # Set during lifespan when Redis is available.


def get_config() -> dict[str, Any]:
    """Get database configuration from environment."""
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL environment variable is required")
    if not database_url.startswith("postgresql+asyncpg://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return {"database_url": database_url}


# =============================================================================
# Domain Layer
# =============================================================================


class FlowType(str, Enum):
    """Types of flows."""

    OID4VCI_PRE_AUTHORIZED = "oid4vci_pre_authorized"
    OID4VCI_AUTHORIZATION_CODE = "oid4vci_authorization_code"
    MDL_ISSUANCE = "mdl_issuance"
    OID4VP_PRESENTATION = "oid4vp_presentation"
    MDL_PRESENTATION = "mdl_presentation"
    SIOPV2 = "siopv2"
    APPLICATION_APPROVAL_ISSUANCE = "application_approval_issuance"
    CREDENTIAL_RENEWAL = "credential_renewal"
    CREDENTIAL_REVOCATION = "credential_revocation"
    PHYSICAL_DOCUMENT_ISSUANCE = "physical_document_issuance"
    COMBINED = "combined"
    CUSTOM = "custom"


class FlowStatus(str, Enum):
    """Flow definition status."""

    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    ARCHIVED = "ARCHIVED"


FLOW_TYPE_ALIASES: dict[str, FlowType] = {
    "issuance": FlowType.OID4VCI_PRE_AUTHORIZED,
    "issuance_oid4vci": FlowType.OID4VCI_PRE_AUTHORIZED,
    "verification": FlowType.OID4VP_PRESENTATION,
    "verification_oid4vp": FlowType.OID4VP_PRESENTATION,
    "presentation": FlowType.OID4VP_PRESENTATION,
    "renewal": FlowType.CREDENTIAL_RENEWAL,
    "revocation": FlowType.CREDENTIAL_REVOCATION,
    "siop_v2": FlowType.SIOPV2,
}

FLOW_STATUS_ALIASES: dict[str, FlowStatus] = {
    "draft": FlowStatus.DRAFT,
    "active": FlowStatus.ACTIVE,
    "suspended": FlowStatus.PAUSED,
    "paused": FlowStatus.PAUSED,
    "archived": FlowStatus.ARCHIVED,
}

FLOW_CATEGORY_BY_TYPE: dict[FlowType, str] = {
    FlowType.OID4VCI_PRE_AUTHORIZED: "ISSUANCE",
    FlowType.OID4VCI_AUTHORIZATION_CODE: "ISSUANCE",
    FlowType.MDL_ISSUANCE: "ISSUANCE",
    FlowType.APPLICATION_APPROVAL_ISSUANCE: "ISSUANCE",
    FlowType.OID4VP_PRESENTATION: "VERIFICATION",
    FlowType.MDL_PRESENTATION: "VERIFICATION",
    FlowType.SIOPV2: "VERIFICATION",
    FlowType.CREDENTIAL_RENEWAL: "RENEWAL",
    FlowType.CREDENTIAL_REVOCATION: "REVOCATION",
    FlowType.PHYSICAL_DOCUMENT_ISSUANCE: "ISSUANCE",
    FlowType.COMBINED: "COMBINED",
}

FLOW_STEP_SEQUENCES: dict[FlowType, list[str]] = {
    FlowType.OID4VCI_PRE_AUTHORIZED: [
        "create_offer",
        "token_exchange",
        "credential_request",
        "issue_credential",
    ],
    FlowType.OID4VCI_AUTHORIZATION_CODE: [
        "create_offer",
        "authorization",
        "token_exchange",
        "credential_request",
        "issue_credential",
    ],
    FlowType.MDL_ISSUANCE: [
        "application_submit",
        "validate_evidence",
        "approval_decision",
        "issue_mdl",
        "deliver_credential",
    ],
    FlowType.OID4VP_PRESENTATION: [
        "create_request",
        "wallet_selection",
        "presentation_submission",
        "verify_presentation",
    ],
    FlowType.MDL_PRESENTATION: [
        "device_engagement",
        "session_establishment",
        "request_items",
        "response_items",
        "session_termination",
    ],
    FlowType.APPLICATION_APPROVAL_ISSUANCE: [
        "accept_application",
        "validate_evidence",
        "approval_decision",
        "issue_credential",
        "deliver_credential",
    ],
    FlowType.CREDENTIAL_RENEWAL: [
        "validate_existing",
        "create_offer",
        "token_exchange",
        "credential_request",
        "issue_renewed_credential",
        "revoke_old_credential",
    ],
    FlowType.CREDENTIAL_REVOCATION: [
        "validate_revocation_request",
        "update_status_list",
        "notify_holder",
    ],
    FlowType.PHYSICAL_DOCUMENT_ISSUANCE: [
        "accept_application",
        "validate_evidence",
        "approval_decision",
        "generate_data_groups",
        "sign_sod",
        "submit_to_personalization",
        "track_production",
        "quality_verify",
        "activate_credential",
    ],
    FlowType.COMBINED: [
        "accept_application",
        "approval_decision",
        "issue_credential",
        "create_request",
        "presentation_submission",
        "verify_presentation",
    ],
    FlowType.SIOPV2: ["create_request", "authentication_submission", "verify_id_token"],
}


def _parse_flow_type(value: FlowType | str) -> FlowType:
    if isinstance(value, FlowType):
        return value
    normalized = str(value).strip()
    alias = FLOW_TYPE_ALIASES.get(normalized.lower())
    if alias:
        return alias
    return FlowType(normalized)


def _parse_flow_status(value: FlowStatus | str) -> FlowStatus:
    if isinstance(value, FlowStatus):
        return value
    normalized = str(value).strip()
    alias = FLOW_STATUS_ALIASES.get(normalized.lower())
    if alias:
        return alias
    return FlowStatus(normalized.upper())


STANDARD_FLOW_TYPES = frozenset(
    flow_type for flow_type in FlowType if flow_type != FlowType.CUSTOM
)

FLOW_REQUIRED_REFERENCES: dict[FlowType, tuple[str, ...]] = {
    FlowType.OID4VCI_PRE_AUTHORIZED: ("credential_template_id",),
    FlowType.OID4VCI_AUTHORIZATION_CODE: ("credential_template_id",),
    FlowType.MDL_ISSUANCE: ("credential_template_id",),
    FlowType.OID4VP_PRESENTATION: ("presentation_policy_id",),
    FlowType.MDL_PRESENTATION: ("presentation_policy_id",),
    FlowType.SIOPV2: ("presentation_policy_id",),
    FlowType.APPLICATION_APPROVAL_ISSUANCE: ("application_template_id",),
    FlowType.CREDENTIAL_RENEWAL: ("credential_template_id",),
    FlowType.CREDENTIAL_REVOCATION: ("credential_template_id",),
    FlowType.PHYSICAL_DOCUMENT_ISSUANCE: (
        "credential_template_id",
        "application_template_id",
        "delivery_destination_profile_id",
    ),
    FlowType.COMBINED: ("credential_template_id", "presentation_policy_id"),
    FlowType.CUSTOM: ("extension",),
}

FLOW_EXTENSIBLE_STEPS: dict[FlowType, tuple[str, ...]] = {
    FlowType.MDL_ISSUANCE: ("approval_decision", "deliver_credential"),
    FlowType.APPLICATION_APPROVAL_ISSUANCE: ("approval_decision", "deliver_credential"),
    FlowType.PHYSICAL_DOCUMENT_ISSUANCE: (
        "approval_decision",
        "submit_to_personalization",
        "quality_verify",
    ),
}


def _normalize_deployment_profile_ids(
    deployment_profile_ids: list[str] | None,
    deployment_profile_id: str | None = None,
) -> list[str]:
    normalized_ids: list[str] = []
    for candidate in [*(deployment_profile_ids or []), deployment_profile_id]:
        if candidate and candidate not in normalized_ids:
            normalized_ids.append(candidate)
    return normalized_ids


def _step_type_for_sequence_name(step_name: str) -> StepType:
    if step_name in {"approval_decision", "accept_application"}:
        return StepType.APPROVAL
    if step_name.startswith("validate"):
        return StepType.VALIDATION
    if step_name.startswith("verify"):
        return StepType.VERIFICATION
    if step_name.startswith("issue") or step_name in {
        "create_offer",
        "deliver_credential",
    }:
        return StepType.ISSUANCE
    if step_name in {
        "token_exchange",
        "presentation_submission",
        "authentication_submission",
        "session_establishment",
        "response_items",
    }:
        return StepType.CALLBACK
    if step_name in {
        "wallet_selection",
        "device_engagement",
        "request_items",
        "authorization",
        "create_request",
    }:
        return StepType.USER_INPUT
    if step_name in {
        "notify_holder",
        "revoke_old_credential",
        "update_status_list",
        "session_termination",
    }:
        return StepType.END
    return StepType.WAIT


def _titleize_step_name(step_name: str) -> str:
    return step_name.replace("_", " ").title()


def _build_default_steps(
    flow_type: FlowType,
) -> tuple[list[FlowStep], list[FlowTransition], str | None]:
    sequence = FLOW_STEP_SEQUENCES.get(flow_type, [])
    if not sequence:
        return [], [], None

    steps = [
        FlowStep(
            name=_titleize_step_name(step_name),
            description=f"Protocol-defined step: {step_name}",
            step_type=_step_type_for_sequence_name(step_name),
            config={"protocol_step": step_name},
        )
        for step_name in sequence
    ]
    transitions = [
        FlowTransition(
            from_step_id=steps[index].id,
            to_step_id=steps[index + 1].id,
            condition=TransitionCondition.SUCCESS,
        )
        for index in range(len(steps) - 1)
    ]
    return steps, transitions, steps[0].id if steps else None


def _validate_flow_request(
    request: "CreateFlowDefinitionRequest", flow_type: FlowType
) -> None:
    if (
        request.credential_template_id
        and request.application_template_id
        and flow_type != FlowType.PHYSICAL_DOCUMENT_ISSUANCE
    ):
        raise HTTPException(
            status_code=400,
            detail="credential_template_id and application_template_id are mutually exclusive",
        )

    for reference_name in FLOW_REQUIRED_REFERENCES[flow_type]:
        if not getattr(request, reference_name, None):
            raise HTTPException(
                status_code=400,
                detail=f"{reference_name} is required for {flow_type.value}",
            )

    if (
        flow_type == FlowType.APPLICATION_APPROVAL_ISSUANCE
        and not request.application_template_id
    ):
        raise HTTPException(
            status_code=400,
            detail="application_template_id is required for application_approval_issuance",
        )
    if (
        flow_type == FlowType.APPLICATION_APPROVAL_ISSUANCE
        and request.credential_template_id
    ):
        raise HTTPException(
            status_code=400,
            detail="application_approval_issuance MUST NOT have credential_template_id",
        )

    # MIP §9.7 — COMBINED requires both credential_template_id AND presentation_policy_id
    if flow_type == FlowType.COMBINED:
        if not request.credential_template_id:
            raise HTTPException(
                status_code=400,
                detail="credential_template_id is required for combined flow_type",
            )
        if not request.presentation_policy_id:
            raise HTTPException(
                status_code=400,
                detail="presentation_policy_id is required for combined flow_type",
            )

    if flow_type == FlowType.CUSTOM and request.extension is None:
        raise HTTPException(
            status_code=400, detail="extension is required for custom flow_type"
        )
    if flow_type != FlowType.CUSTOM and request.extension is not None:
        raise HTTPException(
            status_code=400, detail="extension is only permitted for custom flow_type"
        )

    extensible_steps = FLOW_EXTENSIBLE_STEPS.get(flow_type, ())
    if flow_type != FlowType.CUSTOM:
        for hook_name in request.hooks:
            _, step_name = hook_name.split("_", 1)
            if step_name not in extensible_steps:
                raise HTTPException(
                    status_code=400,
                    detail=f"{hook_name} does not target an extensible step for {flow_type.value}",
                )


def _replace_flow_definition_content(
    flow: "FlowDefinition",
    request: "CreateFlowDefinitionRequest",
    flow_type: FlowType,
) -> None:
    """Apply a full flow-definition payload to a new or existing flow."""
    deployment_profile_ids = _normalize_deployment_profile_ids(
        request.deployment_profile_ids
    )

    flow.organization_id = request.organization_id
    flow.name = request.name
    flow.description = request.description
    flow.flow_type = flow_type
    flow.extension = (
        request.extension.model_dump(mode="json") if request.extension else None
    )
    flow.start_step_id = None
    flow.preconditions = []
    flow.approval_strategy = request.approval_strategy
    flow.hooks = {
        name: [hook.model_dump(mode="json", exclude_none=True) for hook in hooks]
        for name, hooks in request.hooks.items()
    }
    flow.trigger = request.trigger.model_dump(mode="json") if request.trigger else None
    flow.credential_template_id = request.credential_template_id
    flow.application_template_id = request.application_template_id
    flow.presentation_policy_id = request.presentation_policy_id
    flow.delivery_destination_profile_id = request.delivery_destination_profile_id
    flow.deployment_profile_id = (
        deployment_profile_ids[0] if deployment_profile_ids else None
    )
    flow.deployment_profile_ids = deployment_profile_ids
    flow.trust_profile_id = request.trust_profile_id
    flow.steps = []
    flow.transitions = []

    if flow_type != FlowType.CUSTOM:
        default_steps, default_transitions, default_start_step_id = (
            _build_default_steps(flow_type)
        )
        flow.steps.extend(default_steps)
        flow.transitions.extend(default_transitions)
        flow.start_step_id = default_start_step_id
        return

    extension = request.extension
    assert extension is not None
    internal_step_ids: dict[str, str] = {}
    for step_model in extension.steps:
        action_name = step_model.action.rsplit(":", 1)[-1].rsplit(".", 1)[-1]
        step = FlowStep(
            name=_titleize_step_name(step_model.step_id),
            description=step_model.description,
            step_type=_step_type_for_sequence_name(action_name),
            config={
                **step_model.config,
                "extension_step_id": step_model.step_id,
                "extension_action": step_model.action,
            },
            timeout_seconds=step_model.timeout_seconds,
        )
        internal_step_ids[step_model.step_id] = step.id
        flow.steps.append(step)

    outcome_conditions = {
        "SUCCESS": TransitionCondition.SUCCESS,
        "FAILURE": TransitionCondition.FAILURE,
        "APPROVED": TransitionCondition.APPROVAL_GRANTED,
        "REJECTED": TransitionCondition.APPROVAL_DENIED,
        "TIMEOUT": TransitionCondition.TIMEOUT,
        "CUSTOM": TransitionCondition.CONDITION_MET,
    }
    for transition_model in extension.transitions:
        flow.transitions.append(
            FlowTransition(
                from_step_id=internal_step_ids[transition_model.from_step_id],
                to_step_id=internal_step_ids[transition_model.to_step_id],
                condition=outcome_conditions[transition_model.outcome],
                condition_expression=(
                    json.dumps(transition_model.condition, sort_keys=True)
                    if transition_model.condition
                    else None
                ),
            )
        )
    flow.start_step_id = internal_step_ids[extension.entry_step_id]


def _is_reference_not_found(exc: Exception) -> bool:
    code_fn = getattr(exc, "code", None)
    code = code_fn() if callable(code_fn) else None
    if getattr(code, "name", "") == "NOT_FOUND":
        return True
    return "not found" in str(exc).lower()


def _require_reference_org(
    kind: str, reference_id: str, actual_org: str, expected_org: str
) -> None:
    if actual_org and actual_org != expected_org:
        raise HTTPException(
            status_code=400,
            detail=f"{kind} {reference_id} belongs to organization {actual_org}, not {expected_org}",
        )


def _require_reference_active(
    kind: str, reference_id: str, status: str, require_active: bool
) -> None:
    if require_active and str(status or "").lower() != "active":
        raise HTTPException(
            status_code=400,
            detail=f"{kind} {reference_id} must be active before activating a flow",
        )


_TEMPLATE_SIGNING_FORMATS = {
    "sd_jwt_vc": "dc+sd-jwt",
    "ietf_sd_jwt": "dc+sd-jwt",
    "w3c_vcdm_v2_sd_jwt": "dc+sd-jwt",
    "vc+sd-jwt": "dc+sd-jwt",
    "jwt_vc": "jwt_vc_json",
    "vc_jwt": "jwt_vc_json",
    "w3c_vcdm_v2_jwt_vc": "jwt_vc_json",
    "json_ld": "ldp_vc",
    "json-ld": "ldp_vc",
    "mdoc": "mso_mdoc",
}


def _template_signing_format(template: Any) -> str:
    value = str(getattr(template, "credential_payload_format", "") or "").strip()
    normalized = value.lower()
    return _TEMPLATE_SIGNING_FORMATS.get(normalized, normalized)


def _template_key_purpose(credential_format: str) -> str:
    if credential_format in {"mso_mdoc", "zk_mdoc"}:
        return "mdoc_dsc"
    if credential_format in {"vds_nc", "vdsnc"}:
        return "vdsnc_signing"
    return "vc_jwt_issuer"


async def _validate_template_issuer_identity(
    *,
    organization_id: str,
    template_id: str,
    template: Any,
) -> None:
    """Resolve a template's public DID to an organization-owned signing identity.

    Credential templates deliberately do not expose issuer-profile IDs, service
    IDs, or key references. The flow service validates the public DID and
    credential capability through the internal organization-scoped resolver.
    """
    issuer_did = str(getattr(template, "issuer_did", "") or "").strip()
    if not issuer_did.startswith("did:"):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Credential template {template_id} must provide issuer_did before "
                "it can be bound to a flow"
            ),
        )
    credential_format = _template_signing_format(template)
    if not credential_format:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Credential template {template_id} must provide a credential format "
                "before it can be bound to a flow"
            ),
        )
    key_purpose = _template_key_purpose(credential_format)
    issuer_algorithm = str(getattr(template, "issuer_algorithm", "") or "").strip()
    params = {
        "organization_id": organization_id,
        "issuer_did": issuer_did,
        "credential_format": credential_format,
        "key_purpose": key_purpose,
    }
    if issuer_algorithm:
        params["algorithm"] = issuer_algorithm

    base_url = os.environ.get(
        "SIGNING_KEYS_INTERNAL_URL",
        "http://gateway:8000/internal/signing-keys",
    ).rstrip("/")
    api_key = _read_secret_value("SIGNING_KEYS_INTERNAL_API_KEY") or _read_secret_value(
        "ISSUANCE_API_KEY"
    )
    if not api_key:
        raise HTTPException(
            status_code=503,
            detail="Issuer DID resolver is not configured",
        )
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                f"{base_url}/resolve-issuer-did",
                params=params,
                headers={"X-API-Key": api_key},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503,
            detail="Issuer DID resolver is unavailable",
        ) from exc
    if response.status_code in {404, 409, 422}:
        try:
            detail = response.json().get("detail")
        except Exception:  # noqa: BLE001
            detail = None
        raise HTTPException(
            status_code=response.status_code,
            detail=detail
            or (
                f"Credential template {template_id} issuer DID could not be "
                "resolved to one active organization-owned signing identity"
            ),
        )
    if response.status_code >= 400:
        raise HTTPException(
            status_code=503,
            detail="Issuer DID resolver is unavailable",
        )

    resolved = response.json()
    verification_method_id = str(resolved.get("verification_method_id") or "")
    public_jwk = resolved.get("public_jwk")
    if (
        resolved.get("ok") is not True
        or resolved.get("organization_id") != organization_id
        or resolved.get("issuer_did") != issuer_did
        or resolved.get("key_purpose") != key_purpose
        or (issuer_algorithm and resolved.get("algorithm") != issuer_algorithm)
        or not str(resolved.get("algorithm") or "")
        or not verification_method_id.startswith(f"{issuer_did}#")
        or not isinstance(public_jwk, dict)
        or any(secret in public_jwk for secret in ("d", "p", "q", "k"))
    ):
        raise HTTPException(
            status_code=503,
            detail=(
                f"Credential template {template_id} issuer DID resolver returned "
                "an invalid public signing identity"
            ),
        )


async def _get_credential_template_reference(template_id: str):
    from marty_proto.v1 import credential_template_service_pb2 as ct_pb2
    from marty_proto.v1 import credential_template_service_pb2_grpc as ct_grpc

    channel = getattr(app.state, "ct_grpc_channel", None)
    if channel is None:
        raise HTTPException(
            status_code=503,
            detail="Credential template service is not configured for flow validation",
        )
    try:
        stub = ct_grpc.CredentialTemplateServiceStub(channel)
        resp = await stub.GetTemplate(
            ct_pb2.GetTemplateRequest(template_id=template_id)
        )
    except Exception as exc:
        status_code = 404 if _is_reference_not_found(exc) else 502
        raise HTTPException(
            status_code=status_code,
            detail=f"Credential template {template_id} could not be resolved: {exc}",
        ) from exc
    if not getattr(resp, "id", ""):
        raise HTTPException(
            status_code=404, detail=f"Credential template {template_id} not found"
        )
    return resp


async def _get_presentation_policy_reference(policy_id: str):
    from marty_proto.v1 import presentation_policy_service_pb2 as pp_pb2
    from marty_proto.v1 import presentation_policy_service_pb2_grpc as pp_grpc

    channel = getattr(app.state, "pp_grpc_channel", None)
    if channel is None:
        raise HTTPException(
            status_code=503,
            detail="Presentation policy service is not configured for flow validation",
        )
    try:
        stub = pp_grpc.PresentationPolicyServiceStub(channel)
        resp = await stub.GetPolicy(pp_pb2.GetPolicyRequest(policy_id=policy_id))
    except Exception as exc:
        status_code = 404 if _is_reference_not_found(exc) else 502
        raise HTTPException(
            status_code=status_code,
            detail=f"Presentation policy {policy_id} could not be resolved: {exc}",
        ) from exc
    if not getattr(resp, "id", ""):
        raise HTTPException(
            status_code=404, detail=f"Presentation policy {policy_id} not found"
        )
    return resp


async def _validate_credential_layer_references(
    *,
    organization_id: str,
    credential_template_id: str | None = None,
    presentation_policy_id: str | None = None,
    require_active: bool = False,
) -> None:
    """Validate dynamic flow references against credential-layer services."""
    template_cache: dict[str, Any] = {}

    async def _validate_template(template_id: str) -> None:
        if template_id in template_cache:
            template = template_cache[template_id]
        else:
            template = await _get_credential_template_reference(template_id)
            template_cache[template_id] = template
        _require_reference_org(
            "Credential template",
            template_id,
            getattr(template, "organization_id", ""),
            organization_id,
        )
        _require_reference_active(
            "Credential template",
            template_id,
            getattr(template, "status", ""),
            require_active,
        )
        await _validate_template_issuer_identity(
            organization_id=organization_id,
            template_id=template_id,
            template=template,
        )

    if credential_template_id:
        await _validate_template(credential_template_id)

    if presentation_policy_id:
        policy = await _get_presentation_policy_reference(presentation_policy_id)
        _require_reference_org(
            "Presentation policy",
            presentation_policy_id,
            getattr(policy, "organization_id", ""),
            organization_id,
        )
        _require_reference_active(
            "Presentation policy",
            presentation_policy_id,
            getattr(policy, "status", ""),
            require_active,
        )

        requirements_json = getattr(policy, "credential_requirements_json", "") or "[]"
        try:
            requirements = json.loads(requirements_json)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Presentation policy {presentation_policy_id} has invalid credential requirements JSON",
            ) from exc
        if isinstance(requirements, list):
            for requirement in requirements:
                if isinstance(requirement, dict) and requirement.get(
                    "credential_template_id"
                ):
                    await _validate_template(str(requirement["credential_template_id"]))


class StepType(str, Enum):
    """Types of steps in a flow."""

    START = "start"
    USER_INPUT = "user_input"
    DATA_COLLECTION = "data_collection"
    VERIFICATION = "verification"
    VALIDATION = "validation"
    APPROVAL = "approval"
    ISSUANCE = "issuance"
    CALLBACK = "callback"
    WAIT = "wait"
    DECISION = "decision"
    END = "end"


class TransitionCondition(str, Enum):
    """Conditions for step transitions."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    USER_CANCEL = "user_cancel"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    CONDITION_MET = "condition_met"
    ALWAYS = "always"
    QR_SCANNED = "qr_scanned"  # Wallet scanned QR code
    TOKEN_EXCHANGED = "token_exchanged"  # Pre-auth code exchanged for token
    CREDENTIAL_ISSUED = "credential_issued"  # Credential successfully issued


@dataclass
class FlowStep:
    """
    A step in a flow.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str | None = None
    step_type: StepType = StepType.USER_INPUT

    # Step configuration
    config: dict[str, Any] = field(default_factory=dict)
    approval_strategy: str | None = None

    # Timing
    timeout_seconds: int | None = None

    # For decision steps
    conditions: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class FlowTransition:
    """
    A transition between steps.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    from_step_id: str = ""
    to_step_id: str = ""
    condition: TransitionCondition = TransitionCondition.SUCCESS
    condition_expression: str | None = None  # For complex conditions


@dataclass
class FlowDefinition:
    """
    Flow Definition - the blueprint for a flow.

    This defines the steps and transitions for a credential operation.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = ""
    name: str = ""
    description: str | None = None
    status: FlowStatus = FlowStatus.DRAFT
    flow_type: FlowType = FlowType.OID4VCI_PRE_AUTHORIZED
    extension: dict[str, Any] | None = None

    # Steps and transitions
    steps: list[FlowStep] = field(default_factory=list)
    transitions: list[FlowTransition] = field(default_factory=list)
    start_step_id: str | None = None

    # Legacy runtime state retained only until the clean-break data migration.
    preconditions: list[str] = field(default_factory=list)

    # Linked configurations (by ID)
    credential_template_id: str | None = None
    application_template_id: str | None = None
    presentation_policy_id: str | None = None
    delivery_destination_profile_id: str | None = None
    deployment_profile_id: str | None = None
    deployment_profile_ids: list[str] = field(default_factory=list)
    trust_profile_id: str | None = None
    approval_strategy: str = "AUTO"
    hooks: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    trigger: dict[str, Any] | None = None

    # Flow-level settings
    default_timeout_seconds: int = (
        600  # MIP §9.9.4: 10-minute default for AWAITING_WALLET
    )
    max_retries: int = 3
    retry_cooldown_minutes: int = 5  # Minimum time between retry attempts
    enable_resume: bool = True  # Can resume from where left off

    # Timestamps
    version: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def activate(self) -> None:
        self.status = FlowStatus.ACTIVE
        self.updated_at = datetime.now(timezone.utc)

    def suspend(self) -> None:
        self.status = FlowStatus.PAUSED
        self.updated_at = datetime.now(timezone.utc)

    @property
    def flow_category(self) -> str:
        if self.flow_type == FlowType.CUSTOM and self.extension:
            extended_type = _parse_flow_type(
                self.extension.get("extends_flow_type", "")
            )
            return FLOW_CATEGORY_BY_TYPE[extended_type]
        return FLOW_CATEGORY_BY_TYPE[self.flow_type]


def _effective_flow_type(flow: FlowDefinition) -> FlowType:
    """Return the standard behavior extended by a custom flow."""
    if flow.flow_type == FlowType.CUSTOM and flow.extension:
        return _parse_flow_type(flow.extension["extends_flow_type"])
    return flow.flow_type


def _native_flow_graph(flow: FlowDefinition) -> dict[str, Any]:
    """Map persisted flow DTOs to the canonical Rust graph contract."""
    if not flow.start_step_id:
        raise NativeFlowOperationError(
            "FLOW.INVALID_GRAPH: flow definition has no start step"
        )
    return {
        "entry_step_id": flow.start_step_id,
        "steps": [{"step_id": step.id} for step in flow.steps],
        "transitions": [
            {
                "from_step_id": transition.from_step_id,
                "to_step_id": transition.to_step_id,
                "outcome": transition.condition.value,
            }
            for transition in flow.transitions
        ],
    }


# =============================================================================
# Default Flow Step Templates
# =============================================================================


def create_default_oid4vci_steps() -> tuple[list[FlowStep], list[FlowTransition], str]:
    """
    Create default steps for OID4VCI issuance flow.

    Flow: Preconditions Check → Create Offer → QR Generated → Wallet Scanned → Token Exchange → Credential Issued

    Returns:
        tuple: (steps, transitions, start_step_id)
    """
    # Create steps
    start_step = FlowStep(
        name="Check Preconditions",
        description="Check application approval, identity verification, and other preconditions",
        step_type=StepType.APPROVAL,
        config={
            "required_preconditions": [],  # To be configured: application_approved, identity_verified, etc.
            "auto_advance": True,
        },
        timeout_seconds=300,  # 5 minutes
    )

    create_offer_step = FlowStep(
        name="Create Credential Offer",
        description="Generate OID4VCI credential offer with pre-authorized code",
        step_type=StepType.ISSUANCE,
        config={
            "transport_method": "qr_code",  # qr_code, deep_link, or api_only
            "offer_validity_minutes": 15,
            "generate_qr": True,
        },
        timeout_seconds=60,
    )

    qr_generated_step = FlowStep(
        name="QR Code Generated",
        description="QR code displayed, waiting for wallet to scan",
        step_type=StepType.WAIT,
        config={
            "wait_for_event": "qr_scanned",
            "show_deep_link": True,
        },
        timeout_seconds=900,  # 15 minutes
    )

    token_exchange_step = FlowStep(
        name="Token Exchange",
        description="Wallet exchanges pre-authorized code for access token",
        step_type=StepType.CALLBACK,
        config={
            "endpoint": "/api/issuance/token",
            "auto_advance": True,
        },
        timeout_seconds=60,
    )

    credential_request_step = FlowStep(
        name="Issue Credential",
        description="Wallet requests and receives credential",
        step_type=StepType.ISSUANCE,
        config={
            "endpoint": "/api/issuance/credential",
            "format": "vc_jwt",  # Can be overridden by wallet request
            "auto_advance": True,
        },
        timeout_seconds=60,
    )

    end_step = FlowStep(
        name="Issuance Complete",
        description="Credential successfully issued to wallet",
        step_type=StepType.END,
        config={
            "emit_event": "credential_issued",
        },
    )

    steps = [
        start_step,
        create_offer_step,
        qr_generated_step,
        token_exchange_step,
        credential_request_step,
        end_step,
    ]

    # Create transitions
    transitions = [
        FlowTransition(
            from_step_id=start_step.id,
            to_step_id=create_offer_step.id,
            condition=TransitionCondition.SUCCESS,
        ),
        FlowTransition(
            from_step_id=create_offer_step.id,
            to_step_id=qr_generated_step.id,
            condition=TransitionCondition.SUCCESS,
        ),
        FlowTransition(
            from_step_id=qr_generated_step.id,
            to_step_id=token_exchange_step.id,
            condition=TransitionCondition.QR_SCANNED,
        ),
        FlowTransition(
            from_step_id=qr_generated_step.id,
            to_step_id=end_step.id,
            condition=TransitionCondition.TIMEOUT,
        ),
        FlowTransition(
            from_step_id=token_exchange_step.id,
            to_step_id=credential_request_step.id,
            condition=TransitionCondition.TOKEN_EXCHANGED,
        ),
        FlowTransition(
            from_step_id=credential_request_step.id,
            to_step_id=end_step.id,
            condition=TransitionCondition.CREDENTIAL_ISSUED,
        ),
    ]

    return steps, transitions, start_step.id


# =============================================================================
# Flow Instance (Runtime)
# =============================================================================


class FlowInstanceStatus(str, Enum):
    """Status of a running flow instance."""

    CREATED = "created"
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    AWAITING_WALLET = "awaiting_wallet"
    AWAITING_APPROVAL = "awaiting_approval"
    AWAITING_EVIDENCE = "awaiting_evidence"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


def _parse_flow_instance_status(value: FlowInstanceStatus | str) -> FlowInstanceStatus:
    if isinstance(value, FlowInstanceStatus):
        return value
    return FlowInstanceStatus(str(value).strip().lower())


@dataclass
class FlowInstance:
    """
    A running instance of a flow.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    flow_definition_id: str = ""
    organization_id: str = ""

    # Current state
    status: FlowInstanceStatus = FlowInstanceStatus.CREATED
    current_step_id: str | None = None

    # Context data (accumulated through the flow)
    context: dict[str, Any] = field(default_factory=dict)

    # History
    step_history: list[dict[str, Any]] = field(default_factory=list)
    state_history: list[dict[str, Any]] = field(default_factory=list)

    # Subject (who this flow is for)
    subject_id: str | None = None
    subject_type: str = "applicant"  # applicant, holder, etc.

    # External references
    external_reference: str | None = None
    application_flow_key_hash: str | None = None

    # Timing
    started_at: datetime | None = None
    completed_at: datetime | None = None
    expires_at: datetime | None = None

    # Result
    result: dict[str, Any] | None = None
    error: str | None = None

    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def transition_to(
        self,
        new_status: FlowInstanceStatus,
        *,
        actor: str | None = None,
        event: str | None = None,
    ) -> None:
        """Atomically transition to a new status with guard.

        Raises ValueError if the transition is not valid per MIP §9.
        """
        decision = evaluate_native_flow_transition(
            self.status.value,
            new_status.value,
            actor=actor,
            event=event,
        )
        if decision["no_op"]:
            return
        prior = FlowInstanceStatus(decision["prior_state"])
        decided_status = FlowInstanceStatus(decision["new_state"])
        now = datetime.now(timezone.utc)
        self.state_history.append(
            {
                "prior_state": prior.value,
                "new_state": decided_status.value,
                "timestamp": now.isoformat(),
                "actor": decision["actor"],
                "event": decision["event"],
            }
        )
        self.status = decided_status
        self.updated_at = now
        if decision["terminal"]:
            self.completed_at = now


class ArtifactStatus(str, Enum):
    """Status of flow instance artifacts (like QR codes)."""

    ACTIVE = "active"
    SCANNED = "scanned"
    EXPIRED = "expired"
    REVOKED = "revoked"


@dataclass
class FlowInstanceArtifact:
    """
    Runtime artifacts produced by a Flow Instance.

    For OID4VCI flows, this stores credential offer URIs, QR payload, and scan status.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    flow_instance_id: str = ""
    issuance_transaction_id: str | None = None

    # OID4VCI-specific fields
    credential_offer_uri: str | None = None
    credential_offer_uris: dict[str, str] = field(default_factory=dict)
    credential_offer_labels: dict[str, str] = field(default_factory=dict)
    qr_payload: str | None = None  # Base64-encoded QR image data URI
    pre_authorized_code: str | None = None
    issuance_status: str | None = None

    # Timing
    expires_at: datetime | None = None
    scanned_at: datetime | None = None

    # Status and metadata
    status: ArtifactStatus = ArtifactStatus.ACTIVE
    state: str | None = None  # OAuth state parameter
    wallet_metadata: dict[str, Any] = field(
        default_factory=dict
    )  # User-Agent, wallet type, etc.

    # Attempt tracking (for retry policy)
    attempt_number: int = 1

    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ApplicationEventPlanReceipt:
    """Durable, minimized snapshot of flows selected by one authenticated event."""

    event_id_sha256: str
    payload_sha256: str
    organization_id: str
    application_id: str
    flow_plan: list[dict[str, str]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# Application Layer
# =============================================================================


class InMemoryFlowRepository:
    """In-memory repository for development."""

    def __init__(self):
        self._definitions: dict[str, FlowDefinition] = {}
        self._instances: dict[str, FlowInstance] = {}
        self._artifacts: dict[str, FlowInstanceArtifact] = {}
        self._finalization_lock = asyncio.Lock()
        self._consumed_nonce_digests: dict[str, datetime] = {}
        self._finalized_instance_ids: set[str] = set()
        self._callback_events: dict[str, CallbackOutboxEvent] = {}
        self._terminal_instance_snapshots: dict[str, FlowInstance] = {}
        self._application_flow_instances: dict[tuple[str, str], str] = {}
        self._application_event_receipts: dict[str, ApplicationEventPlanReceipt] = {}
        self._application_event_plan_lock = asyncio.Lock()
        self._artifact_locks: dict[str, asyncio.Lock] = {}

    # Flow Definition operations
    async def save_definition(self, flow: FlowDefinition) -> None:
        self._definitions[flow.id] = flow

    async def get_definition(self, flow_id: str) -> FlowDefinition | None:
        return self._definitions.get(flow_id)

    async def list_definitions(self, org_id: str) -> list[FlowDefinition]:
        return [f for f in self._definitions.values() if f.organization_id == org_id]

    async def delete_definition(self, flow_id: str) -> None:
        self._definitions.pop(flow_id, None)

    # Flow Instance operations
    async def save_instance(self, instance: FlowInstance) -> None:
        async with self._finalization_lock:
            terminal_snapshot = self._terminal_instance_snapshots.get(instance.id)
            if terminal_snapshot is not None:
                # Keep the development repository's historical shared-object
                # behavior while restoring the immutable committed decision if
                # a stale handler mutates that object before calling save.
                instance.__dict__.update(copy.deepcopy(terminal_snapshot.__dict__))
                self._instances[instance.id] = instance
                return
            self._instances[instance.id] = instance
            if is_native_terminal_status(instance.status.value):
                self._terminal_instance_snapshots[instance.id] = copy.deepcopy(instance)

    async def reserve_application_event_plan(
        self,
        receipt: ApplicationEventPlanReceipt,
        planned_instances: list[tuple[FlowInstance, dict[str, str]]],
    ) -> tuple[ApplicationEventPlanReceipt, bool]:
        async with self._application_event_plan_lock:
            existing_receipt = self._application_event_receipts.get(
                receipt.event_id_sha256
            )
            if existing_receipt is not None:
                if (
                    existing_receipt.payload_sha256 != receipt.payload_sha256
                    or existing_receipt.organization_id != receipt.organization_id
                    or existing_receipt.application_id != receipt.application_id
                ):
                    raise ApplicationOfferConflictError(
                        "application event identity was already bound to another payload"
                    )
                return existing_receipt, False

            staged_instances: list[tuple[tuple[str, str], FlowInstance]] = []
            final_plan: list[dict[str, str]] = []
            for candidate, plan_entry in planned_instances:
                logical_key = (
                    candidate.organization_id,
                    candidate.application_flow_key_hash or "",
                )
                existing_id = self._application_flow_instances.get(logical_key)
                selected = self._instances.get(existing_id) if existing_id else None
                if selected is None:
                    selected = candidate
                    staged_instances.append((logical_key, selected))
                if (
                    selected.context.get("_marty_application_offer_semantics_hash_v1")
                    != plan_entry["offer_semantics_hash"]
                ):
                    raise ApplicationOfferConflictError(
                        "application and flow were already bound to different issuance claims"
                    )
                final_plan.append({**plan_entry, "instance_id": selected.id})

            for logical_key, instance in staged_instances:
                self._instances[instance.id] = instance
                self._application_flow_instances[logical_key] = instance.id
            receipt.flow_plan = final_plan
            self._application_event_receipts[receipt.event_id_sha256] = receipt
            return receipt, True

    async def get_instance(self, instance_id: str) -> FlowInstance | None:
        return self._instances.get(instance_id)

    async def finalize_verification(
        self,
        instance: FlowInstance,
        *,
        nonce_digest: str,
        replay_expires_at: datetime,
        expected_status: FlowInstanceStatus,
        callback_event: CallbackOutboxEvent | None = None,
    ) -> bool:
        """Development repository equivalent of the database transaction."""
        async with self._finalization_lock:
            now = datetime.now(timezone.utc)
            self._consumed_nonce_digests = {
                digest: expiry
                for digest, expiry in self._consumed_nonce_digests.items()
                if expiry > now
            }
            stored_instance = self._instances.get(instance.id)
            if (
                nonce_digest in self._consumed_nonce_digests
                or instance.id in self._finalized_instance_ids
                or stored_instance is None
                or stored_instance.status is not expected_status
                or (
                    stored_instance.expires_at is not None
                    and now > stored_instance.expires_at
                )
                or expected_status
                not in {
                    FlowInstanceStatus.AWAITING_WALLET,
                    FlowInstanceStatus.IN_PROGRESS,
                }
            ):
                return False
            self._consumed_nonce_digests[nonce_digest] = replay_expires_at
            self._finalized_instance_ids.add(instance.id)
            stored_instance.__dict__.update(copy.deepcopy(instance.__dict__))
            self._terminal_instance_snapshots[instance.id] = copy.deepcopy(
                stored_instance
            )
            self._instances[instance.id] = stored_instance
            if callback_event is not None:
                self._callback_events[callback_event.event_id] = copy.deepcopy(
                    callback_event
                )
            return True

    async def claim_due_callback_events(
        self,
        *,
        now: datetime,
        lease_expires_at: datetime,
        limit: int,
    ) -> list[CallbackOutboxEvent]:
        async with self._finalization_lock:
            for event_id, event in tuple(self._callback_events.items()):
                if event.expires_at <= now and event.status in {
                    "pending",
                    "retry",
                    "delivering",
                    "dead_letter",
                }:
                    self._callback_events[event_id] = replace(
                        event,
                        status="expired",
                        destination_url="",
                        payload={},
                        lease_token=None,
                        lease_expires_at=None,
                        last_error_code="retention_expired",
                    )
            due = sorted(
                (
                    event
                    for event in self._callback_events.values()
                    if event.expires_at > now
                    and (
                        (
                            event.status in {"pending", "retry"}
                            and event.next_attempt_at <= now
                        )
                        or (
                            event.status == "delivering"
                            and event.lease_expires_at is not None
                            and event.lease_expires_at <= now
                        )
                    )
                ),
                key=lambda item: item.created_at,
            )[:limit]
            claimed: list[CallbackOutboxEvent] = []
            for event in due:
                claimed_event = replace(
                    event,
                    status="delivering",
                    attempt_count=event.attempt_count + 1,
                    lease_token=new_lease_token(),
                    lease_expires_at=lease_expires_at,
                )
                self._callback_events[event.event_id] = claimed_event
                claimed.append(copy.deepcopy(claimed_event))
            return claimed

    async def mark_callback_delivered(
        self,
        event_id: str,
        *,
        lease_token: str,
        delivered_at: datetime,
    ) -> bool:
        async with self._finalization_lock:
            event = self._callback_events.get(event_id)
            if (
                event is None
                or event.status != "delivering"
                or event.lease_token != lease_token
            ):
                return False
            self._callback_events[event_id] = replace(
                event,
                status="delivered",
                destination_url="",
                payload={},
                lease_token=None,
                lease_expires_at=None,
                delivered_at=delivered_at,
                last_error_code=None,
            )
            return True

    async def mark_callback_failed(
        self,
        event_id: str,
        *,
        lease_token: str,
        failed_at: datetime,
        next_attempt_at: datetime,
        terminal: bool,
        error_code: str,
    ) -> bool:
        del failed_at
        async with self._finalization_lock:
            event = self._callback_events.get(event_id)
            if (
                event is None
                or event.status != "delivering"
                or event.lease_token != lease_token
            ):
                return False
            self._callback_events[event_id] = replace(
                event,
                status="dead_letter" if terminal else "retry",
                next_attempt_at=next_attempt_at,
                lease_token=None,
                lease_expires_at=None,
                last_error_code=error_code,
            )
            return True

    async def list_instances(
        self,
        org_id: str,
        flow_definition_id: str | None = None,
        status: FlowInstanceStatus | None = None,
    ) -> list[FlowInstance]:
        instances = [i for i in self._instances.values() if i.organization_id == org_id]
        if flow_definition_id:
            instances = [
                i for i in instances if i.flow_definition_id == flow_definition_id
            ]
        if status:
            instances = [i for i in instances if i.status == status]
        return instances

    # Flow Instance Artifact operations
    async def save_artifact(
        self, artifact: FlowInstanceArtifact
    ) -> FlowInstanceArtifact:
        lock = self._artifact_locks.setdefault(
            artifact.flow_instance_id, asyncio.Lock()
        )
        async with lock:
            existing = next(
                (
                    item
                    for item in self._artifacts.values()
                    if item.id == artifact.id
                    or (
                        artifact.issuance_transaction_id is not None
                        and item.issuance_transaction_id
                        == artifact.issuance_transaction_id
                    )
                ),
                None,
            )
            if existing is not None:
                if existing.flow_instance_id != artifact.flow_instance_id:
                    raise ValueError(
                        "issuance transaction is already bound to another flow instance"
                    )
                persisted_id = existing.id
                persisted_flow_instance_id = existing.flow_instance_id
                existing.__dict__.update(artifact.__dict__)
                existing.id = persisted_id
                existing.flow_instance_id = persisted_flow_instance_id
                return existing
            self._artifacts[artifact.id] = artifact
            return artifact

    async def get_artifact(self, artifact_id: str) -> FlowInstanceArtifact | None:
        return self._artifacts.get(artifact_id)

    async def list_artifacts(self, flow_instance_id: str) -> list[FlowInstanceArtifact]:
        return [
            a
            for a in self._artifacts.values()
            if a.flow_instance_id == flow_instance_id
        ]

    async def get_artifact_by_code(
        self, pre_authorized_code: str
    ) -> FlowInstanceArtifact | None:
        """Find artifact by pre-authorized code (for OID4VCI flows)."""
        for artifact in self._artifacts.values():
            if artifact.pre_authorized_code == pre_authorized_code:
                return artifact
        return None


# =============================================================================
# HTTP Adapter - Request/Response Models
# =============================================================================


class FlowExtensionStepModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$", max_length=128)
    action: str = Field(pattern=r"^[a-z][a-z0-9_.:-]*$", max_length=160)
    description: str | None = Field(None, max_length=512)
    config: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int | None = Field(None, ge=1, le=86400)


class FlowExtensionTransitionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    from_step_id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$", max_length=128)
    to_step_id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$", max_length=128)
    outcome: Literal["SUCCESS", "FAILURE", "APPROVED", "REJECTED", "TIMEOUT", "CUSTOM"]
    condition: dict[str, Any] | None = None


class FlowExtensionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    extension_uri: str = Field(max_length=2048)
    extension_version: str = Field(min_length=1, max_length=64)
    extends_flow_type: FlowType
    entry_step_id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$", max_length=128)
    steps: list[FlowExtensionStepModel] = Field(min_length=1)
    transitions: list[FlowExtensionTransitionModel] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_graph(self) -> "FlowExtensionModel":
        if self.extends_flow_type == FlowType.CUSTOM:
            raise ValueError("extends_flow_type must identify a standard FlowType")
        if ":" not in self.extension_uri:
            raise ValueError("extension_uri must be an absolute URI")

        outcome_map = {
            "SUCCESS": "success",
            "FAILURE": "failure",
            "APPROVED": "approval_granted",
            "REJECTED": "approval_denied",
            "TIMEOUT": "timeout",
            "CUSTOM": "condition_met",
        }
        graph = {
            "entry_step_id": self.entry_step_id,
            "steps": [{"step_id": step.step_id} for step in self.steps],
            "transitions": [
                {
                    "from_step_id": transition.from_step_id,
                    "to_step_id": transition.to_step_id,
                    "outcome": outcome_map[transition.outcome],
                }
                for transition in self.transitions
            ],
        }
        try:
            validate_native_flow_graph(graph)
        except NativeFlowOperationError as error:
            raise ValueError(str(error)) from error
        return self


class FlowHookModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hook_type: Literal["WEBHOOK", "EXTERNAL_API", "SCRIPT"]
    url: str | None = Field(None, max_length=2048)
    config: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_hook(self) -> "FlowHookModel":
        if self.hook_type in {"WEBHOOK", "EXTERNAL_API"} and not self.url:
            raise ValueError(f"url is required for {self.hook_type} hooks")
        if self.url and ":" not in self.url:
            raise ValueError("hook url must be an absolute URI")
        return self


class FlowTriggerModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trigger_type: Literal["API_CALL", "WEBHOOK", "SCHEDULE", "APPLICATION_SUBMITTED"]
    config: dict[str, Any] = Field(default_factory=dict)


class CreateFlowDefinitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(max_length=255)
    name: str = Field(max_length=255)
    description: str | None = Field(None, max_length=2000)
    flow_type: FlowType
    approval_strategy: Literal["AUTO", "MANUAL", "RULES_BASED", "EXTERNAL"] = "AUTO"
    hooks: dict[str, list[FlowHookModel]] = Field(default_factory=dict)
    trigger: FlowTriggerModel | None = None
    extension: FlowExtensionModel | None = None
    credential_template_id: str | None = Field(None, max_length=255)
    application_template_id: str | None = Field(None, max_length=255)
    presentation_policy_id: str | None = Field(None, max_length=255)
    delivery_destination_profile_id: str | None = Field(None, max_length=128)
    deployment_profile_ids: list[str] = Field(default_factory=list)
    trust_profile_id: str | None = Field(None, max_length=255)

    @field_validator("hooks")
    @classmethod
    def validate_hook_names(
        cls, hooks: dict[str, list[FlowHookModel]]
    ) -> dict[str, list[FlowHookModel]]:
        for hook_name in hooks:
            if not hook_name.startswith(("pre_", "post_")):
                raise ValueError(
                    "hook names must use pre_{step_name} or post_{step_name}"
                )
            step_name = hook_name.split("_", 1)[1]
            if (
                not step_name
                or not step_name[0].isalpha()
                or not step_name.replace("_", "").isalnum()
            ):
                raise ValueError(f"invalid hook name: {hook_name}")
        return hooks

    @model_validator(mode="after")
    def validate_extension_contract(self) -> "CreateFlowDefinitionRequest":
        if self.flow_type == FlowType.CUSTOM and self.extension is None:
            raise ValueError("extension is required for custom flow_type")
        if self.flow_type != FlowType.CUSTOM and self.extension is not None:
            raise ValueError("extension is only permitted for custom flow_type")
        return self


class UpdateFlowDefinitionRequest(BaseModel):
    """Partial public Flow update bound to the immutable owning organization."""

    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1, max_length=255)
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=2000)
    flow_type: FlowType | None = None
    approval_strategy: Literal["AUTO", "MANUAL", "RULES_BASED", "EXTERNAL"] | None = (
        None
    )
    hooks: dict[str, list[FlowHookModel]] | None = None
    trigger: FlowTriggerModel | None = None
    extension: FlowExtensionModel | None = None
    credential_template_id: str | None = Field(None, max_length=255)
    application_template_id: str | None = Field(None, max_length=255)
    presentation_policy_id: str | None = Field(None, max_length=255)
    delivery_destination_profile_id: str | None = Field(None, max_length=128)
    deployment_profile_ids: list[str] | None = None
    trust_profile_id: str | None = Field(None, max_length=255)

    @model_validator(mode="after")
    def require_a_change(self) -> "UpdateFlowDefinitionRequest":
        if self.model_fields_set <= {"organization_id"}:
            raise ValueError("at least one mutable Flow field is required")
        return self


PublicFlowInstanceStatus = Literal[
    "PENDING",
    "IN_PROGRESS",
    "AWAITING_APPROVAL",
    "AWAITING_WALLET",
    "AWAITING_EVIDENCE",
    "COMPLETED",
    "FAILED",
    "EXPIRED",
    "CANCELLED",
]


class FlowDefinitionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    organization_id: str
    name: str
    description: str | None = None
    flow_type: FlowType
    flow_category: Literal[
        "ISSUANCE", "VERIFICATION", "RENEWAL", "REVOCATION", "COMBINED"
    ]
    resolved_steps: list[str]
    extension: dict[str, Any] | None = None
    trust_profile_id: str | None = None
    credential_template_id: str | None = None
    application_template_id: str | None = None
    presentation_policy_id: str | None = None
    delivery_destination_profile_id: str | None = None
    deployment_profile_ids: list[str] = Field(default_factory=list)
    approval_strategy: Literal["AUTO", "MANUAL", "RULES_BASED", "EXTERNAL"]
    hooks: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    trigger: dict[str, Any] | None = None
    version: int
    status: FlowStatus
    created_at: str
    updated_at: str


class StartFlowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(min_length=1, max_length=255)
    flow_definition_id: str = Field(min_length=1, max_length=255)
    subject_id: str | None = Field(None, max_length=255)
    subject_type: str = Field("applicant", max_length=50)
    external_reference: str | None = Field(None, max_length=500)
    initial_context: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_private_context(self) -> "StartFlowRequest":
        forbidden_path = _private_flow_context_path(self.initial_context)
        if forbidden_path:
            raise ValueError(
                f"initial_context.{forbidden_path} is private service state and cannot be supplied"
            )
        return self


class FlowInstanceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    flow_id: str | None
    flow_type: FlowType | None
    organization_id: str
    status: PublicFlowInstanceStatus
    current_step: str | None = None
    current_step_index: int | None = None
    context_data: dict
    step_results: dict[str, dict[str, Any]]
    issued_credential_id: str | None = None
    started_at: str | None
    completed_at: str | None
    expires_at: str | None
    error_code: str | None = None
    metadata: dict[str, Any]
    state_history: list[dict[str, Any]]
    created_at: str
    updated_at: str


class VerificationResultResponse(BaseModel):
    """Public result from polling or completing a verification flow."""

    model_config = ConfigDict(extra="forbid")

    instance_id: str
    status: PublicFlowInstanceStatus
    result: str | None = None  # passed, failed, partial
    decision: str | None = None  # allow, deny, manual_review
    decision_reason: str | None = None
    verified_claims: dict
    evaluation_timestamp: str | None = None


class AdvanceFlowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_result: str = Field("success", max_length=50)  # success, failure, etc.
    data: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def reject_private_context(self) -> "AdvanceFlowRequest":
        forbidden_path = _private_flow_context_path(self.data)
        if forbidden_path:
            raise ValueError(
                f"data.{forbidden_path} is private service state and cannot be supplied"
            )
        return self


class FlowInstanceArtifactResponse(BaseModel):
    id: str
    flow_instance_id: str
    credential_offer_uri: str | None
    qr_payload: str | None
    pre_authorized_code: str | None
    expires_at: str | None
    scanned_at: str | None
    status: str
    state: str | None
    wallet_metadata: dict
    attempt_number: int
    created_at: str
    updated_at: str


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/flows", tags=["flows"])
did_router = APIRouter(tags=["oid4vp-did"])

_repo: InMemoryFlowRepository | None = None


def get_repo() -> InMemoryFlowRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


def get_current_user_id(x_user_id: Annotated[str, Header()]) -> str:
    """Extract user ID from X-User-Id header (injected by gateway)."""
    return x_user_id


# =============================================================================
# Helper Functions
# =============================================================================


async def check_preconditions(
    preconditions: list[str],
    context: dict[str, Any],
) -> tuple[bool, list[str]]:
    """
    Check if all preconditions are met for flow advancement.

    Args:
        preconditions: List of precondition IDs to check
        context: Flow instance context with state information

    Returns:
        tuple: (all_met, unmet_preconditions)
    """
    if not preconditions:
        return True, []

    unmet = []
    evidence = context.get(_PRECONDITION_EVIDENCE_KEY)
    if not isinstance(evidence, dict):
        evidence = {}

    for precondition in preconditions:
        met = False

        if precondition == "application_approved":
            approval = evidence.get("application_approved")
            met = (
                isinstance(approval, dict)
                and approval.get("producer") == APPLICATION_EVENT_PRODUCER
                and approval.get("audience") == APPLICATION_EVENT_AUDIENCE
                and bool(
                    re.fullmatch(
                        r"[0-9a-f]{64}", str(approval.get("event_id_sha256") or "")
                    )
                )
                and bool(
                    re.fullmatch(
                        r"[0-9a-f]{64}", str(approval.get("payload_sha256") or "")
                    )
                )
                and bool(str(approval.get("authenticated_at") or "").strip())
            )

        elif precondition == "identity_verified":
            # No authoritative setter/evidence schema exists yet.
            met = False

        elif precondition == "manual_admin_approval":
            met = False

        elif precondition == "external_verification":
            met = False

        else:
            # An unknown required control cannot be safely assumed satisfied.
            logger.warning(f"Unknown precondition: {precondition}")
            met = False

        if not met:
            unmet.append(precondition)

    all_met = len(unmet) == 0
    return all_met, unmet


def _is_application_approved_issuance_trigger(flow_def: FlowDefinition) -> bool:
    """Identify flows whose trigger grants application-approval authority."""
    if (
        flow_def.flow_type != FlowType.CUSTOM
        or not flow_def.extension
        or _effective_flow_type(flow_def) != FlowType.OID4VCI_PRE_AUTHORIZED
    ):
        return False
    trigger = flow_def.trigger if isinstance(flow_def.trigger, dict) else {}
    trigger_config = (
        trigger.get("config") if isinstance(trigger.get("config"), dict) else {}
    )
    return (
        str(trigger.get("trigger_type") or "").upper() == "WEBHOOK"
        and str(trigger_config.get("event_type") or "").upper()
        == "APPLICATION_APPROVED"
    )


def _required_issuance_preconditions(flow_def: FlowDefinition) -> list[str]:
    """Collect every required control that must precede offer creation."""
    required = list(flow_def.preconditions or [])
    # The trigger is part of the server-owned flow contract. An administrator
    # must not be able to accidentally author an APPLICATION_APPROVED issuance
    # flow whose direct-start path bypasses authenticated approval evidence.
    if _is_application_approved_issuance_trigger(flow_def):
        required.append("application_approved")
    for step in flow_def.steps:
        if step.step_type != StepType.APPROVAL or not isinstance(step.config, dict):
            continue
        configured = step.config.get("required_preconditions", [])
        if isinstance(configured, list):
            required.extend(str(value) for value in configured if str(value).strip())
        elif configured:
            required.append("invalid_required_preconditions_configuration")
    return list(dict.fromkeys(required))


async def _assert_issuance_preconditions(
    instance: FlowInstance,
    flow_def: FlowDefinition,
) -> None:
    """Fail closed before any OID4VCI offer or pre-authorized code exists."""
    required = _required_issuance_preconditions(flow_def)
    met, unmet = await check_preconditions(required, instance.context)
    if not met:
        raise HTTPException(
            status_code=409,
            detail={
                "error": "ISSUANCE_PRECONDITIONS_NOT_MET",
                "unmet_preconditions": unmet,
            },
        )


def _protocol_status_for_instance(status: FlowInstanceStatus) -> str:
    mapping = {
        FlowInstanceStatus.CREATED: "PENDING",
        FlowInstanceStatus.PENDING: "PENDING",
        FlowInstanceStatus.IN_PROGRESS: "IN_PROGRESS",
        FlowInstanceStatus.AWAITING_WALLET: "AWAITING_WALLET",
        FlowInstanceStatus.AWAITING_APPROVAL: "AWAITING_APPROVAL",
        FlowInstanceStatus.AWAITING_EVIDENCE: "AWAITING_EVIDENCE",
        FlowInstanceStatus.COMPLETED: "COMPLETED",
        FlowInstanceStatus.FAILED: "FAILED",
        FlowInstanceStatus.CANCELLED: "CANCELLED",
        FlowInstanceStatus.EXPIRED: "EXPIRED",
    }
    return mapping.get(status, status.value.upper())


_PRIVATE_FLOW_CONTEXT_KEYS = frozenset(
    {
        "issuer_profile_id",
        "issuer_key_id",
        "issuer_algorithm",
        "key_access_mode",
        "verification_method_id",
        "signing_service_id",
        "signing_key_reference",
        "key_reference",
        "kms_provider",
        "provider",
        "key_name",
        "key_version",
        "transit_mount",
        "pre_auth_code",
        "pre_authorized_code",
        "pre-authorized_code",
        "access_token",
        "refresh_token",
        "client_secret",
        "private_key",
        "private_key_jwk",
        "session_token",
        "api_key",
    }
)
_PRIVATE_FLOW_CONTEXT_PREFIX = "_marty_"
_PRECONDITION_EVIDENCE_KEY = "_marty_precondition_evidence_v1"


def _private_flow_context_path(value: Any, prefix: str = "") -> str | None:
    """Return the first public-context path containing private service state."""
    if isinstance(value, dict):
        for key, entry in value.items():
            key_text = str(key)
            path = f"{prefix}.{key_text}" if prefix else key_text
            if (
                key_text.casefold() in _PRIVATE_FLOW_CONTEXT_KEYS
                or key_text.casefold().startswith(_PRIVATE_FLOW_CONTEXT_PREFIX)
            ):
                return path
            nested = _private_flow_context_path(entry, path)
            if nested:
                return nested
    elif isinstance(value, list):
        for index, entry in enumerate(value):
            path = f"{prefix}[{index}]" if prefix else f"[{index}]"
            nested = _private_flow_context_path(entry, path)
            if nested:
                return nested
    return None


def _public_flow_value(value: Any) -> Any:
    """Recursively project persisted execution state onto the public contract."""
    if isinstance(value, dict):
        return {
            str(key): _public_flow_value(entry)
            for key, entry in value.items()
            if str(key).casefold() not in _PRIVATE_FLOW_CONTEXT_KEYS
            and not str(key).casefold().startswith(_PRIVATE_FLOW_CONTEXT_PREFIX)
        }
    if isinstance(value, list):
        return [_public_flow_value(entry) for entry in value]
    return value


def _response_flow_type(instance: FlowInstance) -> str | None:
    protocol_flow_type = instance.context.get("protocol_flow_type")
    if protocol_flow_type:
        return str(protocol_flow_type)

    runtime_flow_type = str(instance.context.get("flow_type") or "").strip().lower()
    special_cases = {
        "verification": FlowType.OID4VP_PRESENTATION.value,
        "siop_v2": FlowType.SIOPV2.value,
        "siopv2": FlowType.SIOPV2.value,
    }
    return special_cases.get(runtime_flow_type)


def _protocol_step_name(
    flow_def: FlowDefinition | None, step_id: str | None
) -> str | None:
    if not flow_def or not step_id:
        return None
    step = next(
        (candidate for candidate in flow_def.steps if candidate.id == step_id), None
    )
    if not step:
        return None
    protocol_step = (
        step.config.get("protocol_step") if isinstance(step.config, dict) else None
    )
    if protocol_step:
        return str(protocol_step)
    if step.name:
        return step.name.strip().lower().replace(" ", "_")
    return step.id


def _protocol_step_index(
    flow_def: FlowDefinition | None, step_id: str | None
) -> int | None:
    if not flow_def or not step_id:
        return None
    for index, step in enumerate(flow_def.steps):
        if step.id == step_id:
            return index
    return None


def _sync_protocol_context(
    instance: FlowInstance, flow_def: FlowDefinition | None = None
) -> None:
    step_results = instance.context.setdefault("step_results", {})
    if not isinstance(step_results, dict):
        instance.context["step_results"] = {}

    if flow_def is None:
        return

    instance.context["protocol_flow_type"] = flow_def.flow_type.value
    current_step_name = _protocol_step_name(flow_def, instance.current_step_id)
    if current_step_name is not None:
        instance.context["current_step_name"] = current_step_name

    current_step_index = _protocol_step_index(flow_def, instance.current_step_id)
    if current_step_index is not None:
        instance.context["current_step_index"] = current_step_index


def _definition_to_response(flow: FlowDefinition) -> FlowDefinitionResponse:
    """Convert FlowDefinition to response model."""
    if flow.flow_type == FlowType.CUSTOM and flow.extension:
        resolved_steps = [step["step_id"] for step in flow.extension.get("steps", [])]
    else:
        resolved_steps = FLOW_STEP_SEQUENCES.get(flow.flow_type, [])

    return FlowDefinitionResponse(
        id=flow.id,
        organization_id=flow.organization_id,
        name=flow.name,
        description=flow.description,
        status=flow.status.value,
        flow_type=flow.flow_type.value,
        flow_category=flow.flow_category,
        resolved_steps=resolved_steps,
        extension=flow.extension,
        trust_profile_id=flow.trust_profile_id,
        credential_template_id=flow.credential_template_id,
        application_template_id=flow.application_template_id,
        presentation_policy_id=flow.presentation_policy_id,
        delivery_destination_profile_id=flow.delivery_destination_profile_id,
        deployment_profile_ids=flow.deployment_profile_ids,
        approval_strategy=flow.approval_strategy,
        hooks=flow.hooks,
        trigger=flow.trigger,
        version=flow.version,
        created_at=flow.created_at.isoformat(),
        updated_at=flow.updated_at.isoformat(),
    )


def _merged_flow_definition_request(
    flow: FlowDefinition,
    request: UpdateFlowDefinitionRequest,
) -> CreateFlowDefinitionRequest:
    """Validate a partial public patch as one complete Flow definition."""
    current: dict[str, Any] = {
        "organization_id": flow.organization_id,
        "name": flow.name,
        "description": flow.description,
        "flow_type": flow.flow_type.value,
        "approval_strategy": flow.approval_strategy,
        "hooks": flow.hooks,
        "trigger": flow.trigger,
        "extension": flow.extension,
        "credential_template_id": flow.credential_template_id,
        "application_template_id": flow.application_template_id,
        "presentation_policy_id": flow.presentation_policy_id,
        "delivery_destination_profile_id": flow.delivery_destination_profile_id,
        "deployment_profile_ids": flow.deployment_profile_ids,
        "trust_profile_id": flow.trust_profile_id,
    }
    patch = request.model_dump(mode="json", exclude_unset=True)
    patch.pop("organization_id", None)
    return CreateFlowDefinitionRequest.model_validate({**current, **patch})


def _instance_to_response(instance: FlowInstance) -> FlowInstanceResponse:
    """Convert FlowInstance to response model."""
    flow_type = _response_flow_type(instance)
    protocol_status = _protocol_status_for_instance(instance.status)
    flow_definition_reference = instance.context.get(
        "flow_definition_reference", instance.flow_definition_id
    )
    metadata = _public_flow_value(
        {
            "runtime_status": instance.status.value,
            "flow_definition_reference": flow_definition_reference,
            "subject_type": instance.subject_type,
            **({"subject_id": instance.subject_id} if instance.subject_id else {}),
            **(
                {"external_reference": instance.external_reference}
                if instance.external_reference
                else {}
            ),
        }
    )
    public_context = _public_flow_value(instance.context)
    public_step_results = public_context.get("step_results", {})
    if not isinstance(public_step_results, dict):
        public_step_results = {}
    return FlowInstanceResponse(
        id=instance.id,
        flow_id=None
        if instance.flow_definition_id.startswith("__")
        else instance.flow_definition_id,
        flow_type=flow_type,
        organization_id=instance.organization_id,
        status=protocol_status,
        current_step=instance.context.get("current_step_name"),
        current_step_index=instance.context.get("current_step_index"),
        context_data=public_context,
        step_results=public_step_results,
        issued_credential_id=public_context.get("issued_credential_id"),
        started_at=instance.started_at.isoformat() if instance.started_at else None,
        completed_at=instance.completed_at.isoformat()
        if instance.completed_at
        else None,
        expires_at=instance.expires_at.isoformat() if instance.expires_at else None,
        error_code=public_context.get("error_code"),
        metadata=metadata,
        state_history=_public_flow_value(instance.state_history),
        created_at=instance.created_at.isoformat(),
        updated_at=instance.updated_at.isoformat(),
    )


def _verification_result_to_response(
    instance: FlowInstance,
) -> VerificationResultResponse:
    """Return one strict result shape for polling and completed submissions."""
    raw_result = instance.result if isinstance(instance.result, dict) else {}
    verified_claims = _public_flow_value(raw_result.get("verified_claims", {}))
    if not isinstance(verified_claims, dict):
        verified_claims = {}
    return VerificationResultResponse(
        instance_id=instance.id,
        status=_protocol_status_for_instance(instance.status),
        result=raw_result.get("evaluation_result"),
        decision=raw_result.get("decision"),
        decision_reason=raw_result.get("decision_reason") or instance.error,
        verified_claims=verified_claims,
        evaluation_timestamp=(
            instance.completed_at.isoformat() if instance.completed_at else None
        ),
    )


def _artifact_to_response(
    artifact: FlowInstanceArtifact,
) -> FlowInstanceArtifactResponse:
    """Convert FlowInstanceArtifact to response model."""
    return FlowInstanceArtifactResponse(
        id=artifact.id,
        flow_instance_id=artifact.flow_instance_id,
        credential_offer_uri=artifact.credential_offer_uri,
        qr_payload=artifact.qr_payload,
        pre_authorized_code=artifact.pre_authorized_code,
        expires_at=artifact.expires_at.isoformat() if artifact.expires_at else None,
        scanned_at=artifact.scanned_at.isoformat() if artifact.scanned_at else None,
        status=artifact.status.value,
        state=artifact.state,
        wallet_metadata=artifact.wallet_metadata,
        attempt_number=artifact.attempt_number,
        created_at=artifact.created_at.isoformat(),
        updated_at=artifact.updated_at.isoformat(),
    )


def _record_mip_message(
    instance: FlowInstance, label: str, message: MIPMessage
) -> None:
    """Record the latest typed MIP message plus bounded history on the instance."""
    serialized = message.to_dict()
    message_log = instance.context.setdefault("mip_messages", {})
    message_log[label] = serialized

    history = instance.context.setdefault("mip_message_history", [])
    if not any(
        entry.get("label") == label
        and entry.get("envelope", {}).get("message_id") == serialized["message_id"]
        for entry in history
    ):
        history.append({"label": label, "envelope": serialized})
        if len(history) > 25:
            del history[:-25]


async def _initiate_credential_layer_issuance(
    instance: FlowInstance,
    flow_def: FlowDefinition,
) -> dict[str, Any]:
    """Initiate an OID4VCI offer through the credential-layer issuance service.

    Dynamic flows are orchestration only; credential protocol state lives in the
    issuance service. Use gRPC first and retain an HTTP fallback so local/dev
    stacks can still run when protobuf stubs lag the service image.
    """
    claims = instance.context.get("claims") or {}
    if not isinstance(claims, dict):
        claims = {}

    logger.info(
        "[flow] _initiate_credential_layer_issuance instance=%s template=%s claims_keys=%s",
        instance.id,
        flow_def.credential_template_id,
        list(claims.keys()),
    )

    application_id = str(instance.context.get("application_id") or "").strip()
    idempotency_key = (
        f"application-flow-offer-v1:{instance.application_flow_key_hash}"
        if instance.application_flow_key_hash and application_id
        else ""
    )
    if not flow_def.credential_template_id:
        raise HTTPException(status_code=500, detail="credential template is required")
    template = await _get_credential_template_reference(flow_def.credential_template_id)
    issuer_did = str(getattr(template, "issuer_did", "") or "").strip()
    if not issuer_did.startswith("did:"):
        raise HTTPException(
            status_code=502,
            detail="credential template did not return a valid issuer DID",
        )
    claims_json = json.dumps(
        claims,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )

    try:
        from marty_proto.v1 import issuance_service_pb2 as iss_pb2
        from marty_proto.v1 import issuance_service_pb2_grpc as iss_grpc

        channel = getattr(app.state, "issuance_grpc_channel", None)
        if channel is None:
            channel = create_grpc_channel(
                ISSUANCE_GRPC_TARGET,
                service_name="flow",
            )
            close_channel = True
        else:
            close_channel = False

        try:
            stub = iss_grpc.IssuanceServiceStub(channel)
            resp = await stub.InitiateIssuance(
                iss_pb2.InitiateIssuanceRequest(
                    organization_id=instance.organization_id,
                    credential_template_id=flow_def.credential_template_id or "",
                    applicant_id=instance.subject_id or "",
                    subject_did=str(instance.context.get("subject_did") or ""),
                    holder_did=str(instance.context.get("holder_did") or ""),
                    application_id=application_id,
                    issuer_did=issuer_did,
                    delivery_mode="wallet_only",
                    idempotency_key=idempotency_key,
                    claims_json=claims_json,
                ),
                timeout=10.0,
            )
        finally:
            if close_channel:
                await channel.close()

        return {
            "id": resp.id,
            "organization_id": resp.organization_id,
            "credential_template_id": resp.credential_template_id,
            "status": resp.status,
            "credential_offer_uri": resp.credential_offer_uri,
            "credential_offer_uris": dict(resp.credential_offer_uris),
            "credential_offer_labels": dict(resp.credential_offer_labels),
            "pre_auth_code": resp.pre_auth_code,
            "expires_at": resp.expires_at,
        }
    except ImportError:
        logger.warning("Issuance gRPC stubs unavailable, falling back to HTTP")
    except Exception as grpc_err:
        logger.warning(
            "Credential-layer InitiateIssuance failed over gRPC (status=%s), falling back to HTTP: %s",
            getattr(grpc_err, "code", lambda: "N/A")(),
            grpc_err,
        )

    issuance_api_key = _read_secret_value("ISSUANCE_API_KEY")
    if not issuance_api_key:
        raise HTTPException(
            status_code=503,
            detail="credential issuance HTTP fallback is not authenticated",
        )
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{ISSUANCE_SERVICE_URL}/v1/issuance/initiate",
            headers={
                "X-API-Key": issuance_api_key,
                **({"Idempotency-Key": idempotency_key} if idempotency_key else {}),
            },
            json={
                "organization_id": instance.organization_id,
                "credential_template_id": flow_def.credential_template_id,
                "application_id": application_id,
                "applicant_id": instance.subject_id,
                "subject_did": instance.context.get("subject_did"),
                "holder_did": instance.context.get("holder_did"),
                "issuer_did": issuer_did,
                "delivery_mode": "wallet_only",
                "claims": claims,
            },
        )
        response.raise_for_status()
        return response.json()


async def _build_wallet_offers_from_template(
    template_id: str,
    org_id: str,
    pre_auth_code: str,
) -> tuple[dict[str, str], dict[str, str]]:
    """
    Build per-wallet credential offer URIs and labels from a credential template.

    Fallback when issuance service doesn't populate credential_offer_uris.
    This handles missing per-wallet offers for wallets like SpruceID.

    Args:
        template_id: Credential template ID
        org_id: Organization ID
        pre_auth_code: Pre-authorized code for the offer

    Returns:
        Tuple of (credential_offer_uris dict, credential_offer_labels dict)
    """
    from urllib.parse import quote

    credential_offer_uris: dict[str, str] = {}
    credential_offer_labels: dict[str, str] = {}

    try:
        # Fetch credential template via gRPC
        from marty_proto.v1 import credential_template_service_pb2 as ct_pb2
        from marty_proto.v1 import credential_template_service_pb2_grpc as ct_grpc
        ct_grpc_target = os.environ.get("CT_GRPC_TARGET", "credential-template:9003")
        async with create_grpc_channel(
            ct_grpc_target,
            service_name="flow",
        ) as channel:
            ct_stub = ct_grpc.CredentialTemplateServiceStub(channel)
            tmpl_resp = await ct_stub.GetTemplate(
                ct_pb2.GetTemplateRequest(template_id=template_id)
            )

            if not tmpl_resp.id:
                logger.warning(
                    f"Template {template_id} not found for wallet offer generation"
                )
                return {}, {}

            # Parse wallet configs
            wallet_configs_json = tmpl_resp.wallet_configs_json
            if not wallet_configs_json:
                logger.warning(f"Template {template_id} has no wallet configs")
                return {}, {}

            wallet_configs = (
                json.loads(wallet_configs_json)
                if isinstance(wallet_configs_json, str)
                else wallet_configs_json
            )
            logger.info(
                f"Building wallet offers from {len(wallet_configs)} wallet configs"
            )

            # Build per-wallet offers
            from issuance.infrastructure.api.application_routes import (
                org_issuer_url,
            )
            from issuance.application.rust_integration import (
                oid4vci_create_credential_offer,
            )

            credential_type = tmpl_resp.credential_type or "default"

            for wc in wallet_configs:
                wallet_id = wc.get("wallet_id", "")
                scheme = wc.get("deep_link_scheme", "openid-credential-offer://")
                fmt_variant = wc.get("format_variant")
                display_name = wc.get("display_name", "")

                if not wallet_id:
                    continue

                # Select credential_configuration_id based on format variant
                if fmt_variant == "mso_mdoc":
                    config_id = f"{credential_type}#mdoc"
                    issuer_url = org_issuer_url(org_id)
                else:
                    config_id = f"{credential_type}#sd-jwt"
                    issuer_url = org_issuer_url(org_id)

                try:
                    # Create wallet-specific offer
                    offer_json = oid4vci_create_credential_offer(
                        issuer_url=issuer_url,
                        credential_types=[config_id],
                        pre_authorized_code=pre_auth_code,
                        user_pin_required=False,
                    )

                    # Encode and build offer URI
                    sep = "&" if "?" in scheme else "?"
                    credential_offer_uris[wallet_id] = (
                        f"{scheme}{sep}credential_offer={quote(offer_json)}"
                    )
                    if display_name:
                        credential_offer_labels[wallet_id] = display_name

                    logger.info(f"Built offer for wallet {wallet_id} ({fmt_variant})")

                except Exception as e:
                    logger.warning(f"Failed to build offer for wallet {wallet_id}: {e}")
                    continue

    except ImportError as e:
        logger.warning(f"Could not import template service stubs: {e}")
    except Exception as e:
        logger.warning(f"Failed to build wallet offers from template: {e}")

    return credential_offer_uris, credential_offer_labels


async def _create_oid4vci_artifact(
    instance: FlowInstance,
    flow_def: FlowDefinition,
    repo: InMemoryFlowRepository,
    attempt_number: int = 1,
) -> FlowInstanceArtifact | None:
    """
    Create OID4VCI credential offer artifact for a flow instance.

    Generates pre-authorized code and credential offer URI.
    Returns None if flow is not OID4VCI type.

    Args:
        instance: The flow instance
        flow_def: The flow definition with retry policy
        repo: The repository
        attempt_number: The attempt number for retry tracking (default: 1)
    """
    if _effective_flow_type(flow_def) != FlowType.OID4VCI_PRE_AUTHORIZED:
        return None

    await _assert_issuance_preconditions(instance, flow_def)

    existing_artifacts = await repo.list_artifacts(instance.id)
    if instance.application_flow_key_hash and existing_artifacts:
        artifact = existing_artifacts[0]
        instance.context["oid4vci_artifact_id"] = artifact.id
        instance.context["credential_offer_transaction_id"] = (
            artifact.issuance_transaction_id
        )
        instance.context["offer_id"] = artifact.issuance_transaction_id
        instance.context["credential_offer_uri"] = artifact.credential_offer_uri
        instance.context["credential_offer_uris"] = artifact.credential_offer_uris
        instance.context["credential_offer_labels"] = artifact.credential_offer_labels
        instance.context["issuance_status"] = artifact.issuance_status
        if artifact.pre_authorized_code:
            instance.context["pre_auth_code"] = artifact.pre_authorized_code
        await repo.save_instance(instance)
        return artifact

    issuance = await _initiate_credential_layer_issuance(instance, flow_def)
    pre_auth_code = issuance.get("pre_auth_code") or None
    state = issuance.get("id") or str(uuid.uuid4())
    credential_offer_uri = issuance.get("credential_offer_uri")
    credential_offer_uris = issuance.get("credential_offer_uris") or {}
    credential_offer_labels = issuance.get("credential_offer_labels") or {}

    # Log the condition values for debugging
    logger.info(
        f"OID4VCI artifact conditions: credential_offer_uris={credential_offer_uris}, "
        f"template_id={flow_def.credential_template_id}, pre_auth_code={bool(pre_auth_code)}"
    )

    # FALLBACK: If issuance service didn't populate per-wallet offers,
    # fetch the template and build them locally (issue #SpruceID-parsing).
    # This handles cases where the issuance service has empty wallet_configs.
    if not credential_offer_uris and flow_def.credential_template_id and pre_auth_code:
        logger.warning(
            "Issuance service returned empty credential_offer_uris; "
            "building wallet-specific offers from credential template..."
        )
        (
            credential_offer_uris,
            credential_offer_labels,
        ) = await _build_wallet_offers_from_template(
            flow_def.credential_template_id,
            instance.organization_id,
            pre_auth_code,
        )

    if not credential_offer_uri:
        if isinstance(credential_offer_uris, dict):
            credential_offer_uri = next(
                (uri for uri in credential_offer_uris.values() if uri), None
            )
    if not credential_offer_uri:
        raise HTTPException(
            status_code=502,
            detail="Issuance service did not return a credential offer URI",
        )

    issuer_url = os.environ.get("PUBLIC_BASE_URL", "http://localhost:8000")
    expires_at = None
    if issuance.get("expires_at"):
        try:
            expires_at = datetime.fromisoformat(
                str(issuance["expires_at"]).replace("Z", "+00:00")
            )
        except ValueError:
            logger.warning(
                "Invalid issuance expires_at value: %s", issuance.get("expires_at")
            )
    if expires_at is None:
        from datetime import timedelta

        expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

    artifact = FlowInstanceArtifact(
        flow_instance_id=instance.id,
        issuance_transaction_id=issuance.get("id"),
        credential_offer_uri=credential_offer_uri,
        credential_offer_uris=credential_offer_uris or {},
        credential_offer_labels=credential_offer_labels or {},
        pre_authorized_code=pre_auth_code,
        issuance_status=issuance.get("status"),
        state=state,
        expires_at=expires_at,
        status=ArtifactStatus.ACTIVE,
        attempt_number=attempt_number,
    )

    artifact = await repo.save_artifact(artifact)

    # Store artifact ID and offer details in instance context
    instance.context["oid4vci_artifact_id"] = artifact.id
    instance.context["credential_offer_transaction_id"] = (
        artifact.issuance_transaction_id
    )
    instance.context["offer_id"] = artifact.issuance_transaction_id
    instance.context["credential_offer_uri"] = artifact.credential_offer_uri
    instance.context["credential_offer_uris"] = artifact.credential_offer_uris
    instance.context["credential_offer_labels"] = artifact.credential_offer_labels
    instance.context["issuance_status"] = artifact.issuance_status
    if pre_auth_code:
        instance.context["pre_auth_code"] = pre_auth_code

    credential_offer_message = MIPMessage(
        message_type=MessageType.CREDENTIAL_OFFER,
        correlation_id=instance.id,
        sender_id=issuer_url,
        payload=CredentialOfferPayload(
            credential_issuer=issuer_url,
            credential_configuration_ids=[flow_def.credential_template_id]
            if flow_def.credential_template_id
            else [],
            grants={
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": pre_auth_code,
                }
            },
            mip_flow_instance_id=instance.id,
        ),
    )
    _record_mip_message(instance, "credential_offer", credential_offer_message)
    await repo.save_instance(instance)

    logger.info(
        "Created credential-layer OID4VCI artifact for instance %s: artifact=%s transaction=%s",
        instance.id,
        artifact.id,
        issuance.get("id"),
    )

    return artifact


# =============================================================================
# API Endpoints
# =============================================================================


def _flow_capabilities() -> dict[str, Any]:
    physical_signing = bool(os.environ.get("ICAO_DOCUMENT_SIGNER_URL", "").strip()) or (
        os.environ.get("PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED", "").lower() == "true"
    )
    encrypted_artifacts = bool(
        os.environ.get("PHYSICAL_DOCUMENT_ARTIFACT_KEY", "").strip()
    )
    personalization_bureau = bool(
        os.environ.get("PERSONALIZATION_BUREAU_URL", "").strip()
    )
    physical_blockers: list[str] = []
    if not physical_signing:
        physical_blockers.append(
            "Configure ICAO_DOCUMENT_SIGNER_URL for eMRTD SOD signing."
        )
    if not encrypted_artifacts:
        physical_blockers.append(
            "Configure PHYSICAL_DOCUMENT_ARTIFACT_KEY for encrypted sensitive artifacts."
        )
    if not personalization_bureau:
        physical_blockers.append(
            "Configure PERSONALIZATION_BUREAU_URL for document production handoff."
        )

    return {
        "protocol_version": MIP_VERSION,
        "flow_types": [flow_type.value for flow_type in FlowType],
        "standard_flow_types": [flow_type.value for flow_type in STANDARD_FLOW_TYPES],
        "sequences": {
            flow_type.value: sequence
            for flow_type, sequence in FLOW_STEP_SEQUENCES.items()
        },
        "required_references": {
            flow_type.value: list(references)
            for flow_type, references in FLOW_REQUIRED_REFERENCES.items()
        },
        "extensible_steps": {
            flow_type.value: list(steps)
            for flow_type, steps in FLOW_EXTENSIBLE_STEPS.items()
        },
        "triggers": ["API_CALL", "WEBHOOK", "SCHEDULE", "APPLICATION_SUBMITTED"],
        "physical_document_issuance": {
            "supported": not physical_blockers,
            "blockers": physical_blockers,
        },
    }


async def _physical_document_request(
    method: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    headers = {}
    issuance_api_key = os.environ.get("ISSUANCE_API_KEY", "").strip()
    if issuance_api_key:
        headers["X-API-Key"] = issuance_api_key
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.request(
            method,
            f"{ISSUANCE_SERVICE_URL}{path}",
            json=payload,
            headers=headers,
        )
    if response.status_code >= 400:
        try:
            detail = response.json().get("detail", response.text)
        except (ValueError, AttributeError):
            detail = response.text
        raise HTTPException(status_code=response.status_code, detail=detail)
    return response.json()


async def _initialize_physical_document_job(
    instance: FlowInstance,
    flow: FlowDefinition,
) -> None:
    physical_document = instance.context.pop("physical_document", None)
    if not isinstance(physical_document, dict):
        raise HTTPException(
            status_code=422,
            detail="initial_context.physical_document is required for physical document issuance",
        )
    required_fields = ("country_code", "applicant", "mrz", "data_groups")
    missing = [
        field_name
        for field_name in required_fields
        if not physical_document.get(field_name)
    ]
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"physical_document is missing required fields: {', '.join(missing)}",
        )
    job = await _physical_document_request(
        "POST",
        "/v1/passport/applications",
        payload={
            "organization_id": flow.organization_id,
            "flow_execution_id": instance.id,
            "application_template_id": flow.application_template_id,
            "credential_template_id": flow.credential_template_id,
            "delivery_destination_profile_id": flow.delivery_destination_profile_id,
            "document_type": physical_document.get("document_type", "TD3"),
            "country_code": physical_document["country_code"],
            "applicant": physical_document["applicant"],
            "mrz": physical_document["mrz"],
            "data_groups": physical_document["data_groups"],
        },
    )
    instance.context["physical_document_job"] = job
    instance.context["application_id"] = job["application_id"]


async def _execute_physical_document_step(
    instance: FlowInstance,
    step_name: str | None,
    step_data: dict[str, Any],
) -> None:
    job = instance.context.get("physical_document_job")
    if not isinstance(job, dict) or not job.get("application_id"):
        raise HTTPException(
            status_code=409, detail="Physical document job is not initialized"
        )
    application_id = job["application_id"]
    operation: tuple[str, str, dict[str, Any] | None] | None = None
    if step_name == "generate_data_groups":
        operation = (
            "POST",
            f"/v1/passport/applications/{application_id}/generate-data-groups",
            None,
        )
    elif step_name == "sign_sod":
        operation = (
            "POST",
            f"/v1/passport/applications/{application_id}/generate-sod",
            None,
        )
    elif step_name == "submit_to_personalization":
        operation = (
            "POST",
            f"/v1/passport/applications/{application_id}/submit-personalization",
            None,
        )
    elif step_name == "track_production":
        operation = (
            "GET",
            f"/v1/passport/applications/{application_id}/production-status",
            None,
        )
    elif step_name == "quality_verify":
        operation = (
            "POST",
            f"/v1/passport/applications/{application_id}/quality-verify",
            {
                "passed": bool(step_data.get("passed")),
                "failure_codes": step_data.get("failure_codes", []),
            },
        )
    elif step_name == "activate_credential":
        operation = (
            "POST",
            f"/v1/passport/applications/{application_id}/activate",
            None,
        )

    if operation:
        method, path, payload = operation
        updated_job = await _physical_document_request(method, path, payload=payload)
        instance.context["physical_document_job"] = updated_job


async def _validate_flow_definition(flow: FlowDefinition) -> dict[str, Any]:
    errors: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    dependencies: list[dict[str, str]] = []

    for reference_name in FLOW_REQUIRED_REFERENCES[flow.flow_type]:
        reference_value = getattr(flow, reference_name, None)
        if not reference_value:
            errors.append(
                {
                    "code": "MISSING_REFERENCE",
                    "field": reference_name,
                    "message": f"{reference_name} is required for {flow.flow_type.value}.",
                }
            )
        elif reference_name != "extension":
            dependencies.append(
                {"type": reference_name.removesuffix("_id"), "id": str(reference_value)}
            )

    if not flow.steps:
        errors.append(
            {
                "code": "EMPTY_FLOW",
                "field": "flow_type",
                "message": "The flow resolves to no executable steps.",
            }
        )

    physical_capability = _flow_capabilities()["physical_document_issuance"]
    if flow.flow_type == FlowType.PHYSICAL_DOCUMENT_ISSUANCE:
        for blocker in physical_capability["blockers"]:
            errors.append(
                {
                    "code": "CAPABILITY_UNAVAILABLE",
                    "field": "flow_type",
                    "message": blocker,
                }
            )

    try:
        await _validate_credential_layer_references(
            organization_id=flow.organization_id,
            credential_template_id=flow.credential_template_id,
            presentation_policy_id=flow.presentation_policy_id,
            require_active=True,
        )
    except HTTPException as exc:
        errors.append(
            {
                "code": "DEPENDENCY_INVALID",
                "field": "dependencies",
                "message": str(exc.detail),
            }
        )

    if not flow.deployment_profile_ids:
        warnings.append(
            {
                "code": "NO_DEPLOYMENT_TARGET",
                "field": "deployment_profile_ids",
                "message": "No deployment target is selected; activation is allowed, but the flow cannot be deployed.",
            }
        )

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "resolved_dependencies": dependencies,
        "resolved_steps": (
            [
                step.get("step_id", "")
                for step in (flow.extension or {}).get("steps", [])
            ]
            if flow.flow_type == FlowType.CUSTOM
            else FLOW_STEP_SEQUENCES.get(flow.flow_type, [])
        ),
    }


@router.get("/capabilities")
async def get_flow_capabilities() -> dict[str, Any]:
    """Describe the MIP flow contract and runtime capability blockers."""
    return _flow_capabilities()


@router.post(
    "/definitions",
    response_model=FlowDefinitionResponse,
    response_model_exclude_none=True,
)
async def create_flow_definition(
    request: CreateFlowDefinitionRequest,
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowDefinitionResponse:
    """Create a new Flow Definition."""
    org_client = await get_organization_client(fastapi_request)
    membership = await org_client.get_membership(user_id, request.organization_id)
    ensure_membership_permission(membership, "flow-definition", "create")

    flow_type = _parse_flow_type(request.flow_type)
    _validate_flow_request(request, flow_type)
    await _validate_credential_layer_references(
        organization_id=request.organization_id,
        credential_template_id=request.credential_template_id,
        presentation_policy_id=request.presentation_policy_id,
        require_active=False,
    )
    flow = FlowDefinition(
        organization_id=request.organization_id,
    )
    _replace_flow_definition_content(flow, request, flow_type)

    # Auto-activate enabled flow definition on creation

    await repo.save_definition(flow)
    logger.info(f"Created Flow Definition: {flow.id}")
    return _definition_to_response(flow)


@router.get(
    "/definitions",
    response_model=list[FlowDefinitionResponse],
    response_model_exclude_none=True,
)
async def list_flow_definitions(
    organization_id: str = Query(..., description="Organization ID"),
    limit: int = Query(default=100, le=500, description="Max items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> list[FlowDefinitionResponse]:
    """List Flow Definitions for an organization."""
    membership = await app.state.org_client.get_membership(user_id, organization_id)
    ensure_membership_permission(membership, "flow-definition", "view")
    flows = await repo.list_definitions(organization_id)
    return [_definition_to_response(f) for f in flows[offset : offset + limit]]


@router.get(
    "/definitions/{flow_id}",
    response_model=FlowDefinitionResponse,
    response_model_exclude_none=True,
)
async def get_flow_definition(
    flow_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowDefinitionResponse:
    """Get a Flow Definition by ID."""
    flow = await repo.get_definition(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow Definition not found")
    membership = await app.state.org_client.get_membership(
        user_id, flow.organization_id
    )
    ensure_membership_permission(membership, "flow-definition", "view")
    return _definition_to_response(flow)


@router.patch(
    "/definitions/{flow_id}",
    response_model=FlowDefinitionResponse,
    response_model_exclude_none=True,
)
async def update_flow_definition(
    flow_id: str,
    request: UpdateFlowDefinitionRequest,
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowDefinitionResponse:
    """Patch a Flow Definition and validate the complete merged definition."""
    flow = await repo.get_definition(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow Definition not found")
    if flow.status == FlowStatus.ARCHIVED:
        raise HTTPException(
            status_code=400, detail="Archived flow definitions cannot be updated"
        )

    org_client = await get_organization_client(fastapi_request)
    membership = await org_client.get_membership(user_id, flow.organization_id)
    ensure_membership_permission(membership, "flow-definition", "edit")

    if request.organization_id != flow.organization_id:
        raise HTTPException(
            status_code=400,
            detail="organization_id cannot be changed for an existing flow definition",
        )

    merged_request = _merged_flow_definition_request(flow, request)
    flow_type = _parse_flow_type(merged_request.flow_type)
    _validate_flow_request(merged_request, flow_type)
    await _validate_credential_layer_references(
        organization_id=merged_request.organization_id,
        credential_template_id=merged_request.credential_template_id,
        presentation_policy_id=merged_request.presentation_policy_id,
        require_active=False,
    )

    flow.version += 1
    _replace_flow_definition_content(flow, merged_request, flow_type)
    flow.status = FlowStatus.DRAFT
    flow.updated_at = datetime.now(timezone.utc)

    await repo.save_definition(flow)
    return _definition_to_response(flow)


@router.post("/definitions/{flow_id}/validate")
async def validate_flow_definition(
    flow_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> dict[str, Any]:
    """Validate a draft and return actionable dependency and capability results."""
    flow = await repo.get_definition(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow Definition not found")
    membership = await app.state.org_client.get_membership(
        user_id, flow.organization_id
    )
    ensure_membership_permission(membership, "flow-definition", "view")
    return await _validate_flow_definition(flow)


@router.post("/definitions/{flow_id}/test")
async def test_flow_definition(
    flow_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> dict[str, Any]:
    """Resolve a draft execution plan without invoking external side effects."""
    flow = await repo.get_definition(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow Definition not found")
    membership = await app.state.org_client.get_membership(
        user_id, flow.organization_id
    )
    ensure_membership_permission(membership, "flow-definition", "view")
    validation = await _validate_flow_definition(flow)
    return {
        **validation,
        "mode": "DRY_RUN",
        "would_execute": validation["resolved_steps"] if validation["valid"] else [],
        "side_effects_executed": False,
    }


@router.post(
    "/definitions/{flow_id}/activate",
    response_model=FlowDefinitionResponse,
    response_model_exclude_none=True,
)
async def activate_flow_definition(
    flow_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowDefinitionResponse:
    """Activate a Flow Definition (requires admin)."""
    flow = await repo.get_definition(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow Definition not found")

    # Verify admin access
    membership = await app.state.org_client.get_membership(
        user_id, flow.organization_id
    )
    ensure_membership_permission(membership, "flow-definition", "activate")

    validation = await _validate_flow_definition(flow)
    if not validation["valid"]:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Flow validation failed; resolve all blockers before activation.",
                **validation,
            },
        )

    flow.activate()
    await repo.save_definition(flow)
    return _definition_to_response(flow)


@router.delete("/definitions/{flow_id}")
async def delete_flow_definition(
    flow_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> dict:
    """Delete a Flow Definition (only drafts, requires admin)."""
    flow = await repo.get_definition(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow Definition not found")

    # Verify admin access
    membership = await app.state.org_client.get_membership(
        user_id, flow.organization_id
    )
    ensure_membership_permission(membership, "flow-definition", "delete")

    if flow.status != FlowStatus.DRAFT:
        raise HTTPException(status_code=400, detail="Only draft flows can be deleted")
    await repo.delete_definition(flow_id)
    return {"success": True}


# Flow Instance endpoints
@router.post(
    "/instances", response_model=FlowInstanceResponse, response_model_exclude_none=True
)
async def start_flow(
    request: StartFlowRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceResponse:
    """Start a new Flow Instance."""
    flow_def = await repo.get_definition(request.flow_definition_id)
    if not flow_def:
        raise HTTPException(status_code=404, detail="Flow Definition not found")

    if request.organization_id != flow_def.organization_id:
        # Bind the public request to its selected tenant without confirming a
        # guessed cross-tenant Flow identifier exists.
        raise HTTPException(status_code=404, detail="Flow Definition not found")

    membership = await app.state.org_client.get_membership(
        user_id, flow_def.organization_id
    )
    ensure_membership_permission(membership, "flow-instance", "start")

    if flow_def.status != FlowStatus.ACTIVE:
        raise HTTPException(status_code=400, detail="Flow Definition is not active")

    instance = FlowInstance(
        flow_definition_id=request.flow_definition_id,
        organization_id=flow_def.organization_id,
        status=FlowInstanceStatus.IN_PROGRESS
        if flow_def.start_step_id
        else FlowInstanceStatus.PENDING,
        current_step_id=flow_def.start_step_id,
        context=dict(request.initial_context),
        subject_id=request.subject_id,
        subject_type=request.subject_type,
        external_reference=request.external_reference,
        started_at=datetime.now(timezone.utc),
    )
    if _effective_flow_type(flow_def) == FlowType.PHYSICAL_DOCUMENT_ISSUANCE:
        await _initialize_physical_document_job(instance, flow_def)
    _sync_protocol_context(instance, flow_def)

    if _effective_flow_type(flow_def) == FlowType.OID4VCI_PRE_AUTHORIZED:
        await _assert_issuance_preconditions(instance, flow_def)

    # Set expiry
    from datetime import timedelta

    instance.expires_at = instance.started_at + timedelta(
        seconds=flow_def.default_timeout_seconds
    )

    # Record initial state transition in state_history (MIP §9.9.4)
    instance.state_history.append(
        {
            "prior_state": None,
            "new_state": instance.status.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": user_id,
            "event": "flow_instance_created",
        }
    )

    # Record first step
    if flow_def.start_step_id:
        instance.step_history.append(
            {
                "step_id": flow_def.start_step_id,
                "entered_at": datetime.now(timezone.utc).isoformat(),
                "status": "entered",
            }
        )

    await repo.save_instance(instance)

    # Create OID4VCI artifact if this is an OID4VCI flow
    if _effective_flow_type(flow_def) == FlowType.OID4VCI_PRE_AUTHORIZED:
        artifact = await _create_oid4vci_artifact(instance, flow_def, repo)
        if artifact:
            logger.info(f"Created OID4VCI artifact: {artifact.id}")

    logger.info(f"Started Flow Instance: {instance.id}")
    return _instance_to_response(instance)


@router.get(
    "/instances",
    response_model=list[FlowInstanceResponse],
    response_model_exclude_none=True,
)
async def list_flow_instances(
    organization_id: str = Query(..., description="Organization ID"),
    flow_definition_id: str | None = Query(
        None, description="Filter by flow definition"
    ),
    status: str | None = Query(None, description="Filter by status"),
    limit: int = Query(default=100, le=500, description="Max items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> list[FlowInstanceResponse]:
    """List Flow Instances."""
    membership = await app.state.org_client.get_membership(user_id, organization_id)
    ensure_membership_permission(membership, "flow-instance", "view")
    status_filter = _parse_flow_instance_status(status) if status else None
    instances = await repo.list_instances(
        organization_id, flow_definition_id, status_filter
    )
    return [_instance_to_response(i) for i in instances[offset : offset + limit]]


@router.get(
    "/instances/{instance_id}",
    response_model=FlowInstanceResponse,
    response_model_exclude_none=True,
)
async def get_flow_instance(
    instance_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceResponse:
    """Get a Flow Instance by ID."""
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")
    membership = await app.state.org_client.get_membership(
        user_id, instance.organization_id
    )
    ensure_membership_permission(membership, "flow-instance", "view")
    return _instance_to_response(instance)


@router.get(
    "/instances/{instance_id}/result",
    response_model=VerificationResultResponse,
    response_model_exclude_none=True,
)
async def get_flow_instance_result(
    instance_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> VerificationResultResponse:
    """OID4VP-1FINAL §8.7 — Relying-party result polling endpoint.

    Returns the current verification state and any verified claims for the
    given flow instance. Before submission the state is ``awaiting_wallet``; after a
    successful VP submission it is ``completed``.
    """
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")
    membership = await app.state.org_client.get_membership(
        user_id, instance.organization_id
    )
    ensure_membership_permission(membership, "flow-instance", "view")
    return _verification_result_to_response(instance)


@router.post(
    "/instances/{instance_id}/advance",
    response_model=FlowInstanceResponse,
    response_model_exclude_none=True,
)
async def advance_flow(
    instance_id: str,
    request: AdvanceFlowRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceResponse:
    """Advance a Flow Instance to the next step."""
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")

    membership = await app.state.org_client.get_membership(
        user_id, instance.organization_id
    )
    ensure_membership_permission(membership, "flow-instance", "advance")

    if instance.status not in [
        FlowInstanceStatus.IN_PROGRESS,
        FlowInstanceStatus.AWAITING_WALLET,
    ]:
        raise HTTPException(
            status_code=400, detail=f"Cannot advance flow in {instance.status} status"
        )

    flow_def = await repo.get_definition(instance.flow_definition_id)
    if not flow_def:
        raise HTTPException(status_code=404, detail="Flow Definition not found")

    # Check preconditions if this is the first step (precondition check step)
    current_step = next(
        (s for s in flow_def.steps if s.id == instance.current_step_id), None
    )
    if current_step and current_step.step_type == StepType.APPROVAL:
        # Check if this is the precondition check step
        required_preconditions = flow_def.preconditions or current_step.config.get(
            "required_preconditions", []
        )
        if required_preconditions:
            preconditions_met, unmet = await check_preconditions(
                required_preconditions, instance.context
            )
            if not preconditions_met:
                raise HTTPException(
                    status_code=400, detail=f"Preconditions not met: {', '.join(unmet)}"
                )
            # Store that preconditions were checked
            instance.context["preconditions_checked"] = True
            instance.context["preconditions_met_at"] = datetime.now(
                timezone.utc
            ).isoformat()

    current_step_name = _protocol_step_name(flow_def, instance.current_step_id)
    if (
        _effective_flow_type(flow_def) == FlowType.PHYSICAL_DOCUMENT_ISSUANCE
        and request.step_result == TransitionCondition.SUCCESS.value
    ):
        await _execute_physical_document_step(instance, current_step_name, request.data)

    if instance.status == FlowInstanceStatus.AWAITING_WALLET:
        instance.transition_to(
            FlowInstanceStatus.IN_PROGRESS,
            actor=user_id,
            event="wallet_step_response_received",
        )

    # Let the canonical Rust graph select the sole next step.
    current_step_id = instance.current_step_id
    condition = TransitionCondition(request.step_result)
    if current_step_id is None:
        raise HTTPException(status_code=400, detail="Flow has no current step")
    try:
        next_step_id = select_native_next_step(
            _native_flow_graph(flow_def), current_step_id, condition.value
        )
    except NativeFlowOperationError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    # Update context with request data
    instance.context.update(request.data)

    # Record step completion
    if instance.step_history:
        completed_at = datetime.now(timezone.utc).isoformat()
        instance.step_history[-1]["completed_at"] = completed_at
        instance.step_history[-1]["result"] = request.step_result
        if current_step_name is not None:
            instance.context.setdefault("step_results", {})[current_step_name] = {
                "result": request.step_result,
                "completed_at": completed_at,
            }

    if next_step_id:
        # Move to next step
        instance.current_step_id = next_step_id
        _sync_protocol_context(instance, flow_def)
        instance.step_history.append(
            {
                "step_id": next_step_id,
                "entered_at": datetime.now(timezone.utc).isoformat(),
                "status": "entered",
            }
        )

        # Check if this is an end step
        next_step = next((s for s in flow_def.steps if s.id == next_step_id), None)
        if next_step and next_step.step_type == StepType.END:
            instance.transition_to(FlowInstanceStatus.COMPLETED, actor=user_id)
            instance.result = instance.context
    else:
        # No valid transition, flow ends
        if request.step_result == "failure":
            instance.transition_to(FlowInstanceStatus.FAILED, actor=user_id)
            instance.error = "Step failed with no recovery transition"
        else:
            instance.transition_to(FlowInstanceStatus.COMPLETED, actor=user_id)

    instance.updated_at = datetime.now(timezone.utc)
    await repo.save_instance(instance)
    return _instance_to_response(instance)


@router.post(
    "/instances/{instance_id}/cancel",
    response_model=FlowInstanceResponse,
    response_model_exclude_none=True,
)
async def cancel_flow(
    instance_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceResponse:
    """Cancel a Flow Instance."""
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")

    membership = await app.state.org_client.get_membership(
        user_id, instance.organization_id
    )
    ensure_membership_permission(membership, "flow-instance", "cancel")

    if is_native_terminal_status(instance.status.value):
        raise HTTPException(status_code=400, detail="Flow already ended")

    try:
        instance.transition_to(FlowInstanceStatus.CANCELLED)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    await repo.save_instance(instance)
    return _instance_to_response(instance)


# =============================================================================
# Flow Instance Artifact Endpoints
# =============================================================================


@router.get(
    "/instances/{instance_id}/artifacts",
    response_model=list[FlowInstanceArtifactResponse],
    response_model_exclude_none=True,
)
async def list_flow_instance_artifacts(
    instance_id: str,
    limit: int = Query(default=100, le=500, description="Max items to return"),
    offset: int = Query(default=0, ge=0, description="Number of items to skip"),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> list[FlowInstanceArtifactResponse]:
    """Get all artifacts (QR codes, offers, etc.) for a flow instance."""
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")

    membership = await app.state.org_client.get_membership(
        user_id, instance.organization_id
    )
    ensure_membership_permission(membership, "flow-instance", "view")

    artifacts = await repo.list_artifacts(instance_id)
    return [_artifact_to_response(a) for a in artifacts[offset : offset + limit]]


@router.get(
    "/instances/{instance_id}/artifacts/{artifact_id}",
    response_model=FlowInstanceArtifactResponse,
    response_model_exclude_none=True,
)
async def get_flow_instance_artifact(
    instance_id: str,
    artifact_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceArtifactResponse:
    """Get a specific artifact by ID."""
    artifact = await repo.get_artifact(artifact_id)
    if not artifact or artifact.flow_instance_id != instance_id:
        raise HTTPException(status_code=404, detail="Artifact not found")

    # Verify org membership via instance
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")
    membership = await app.state.org_client.get_membership(
        user_id, instance.organization_id
    )
    ensure_membership_permission(membership, "flow-instance", "view")

    return _artifact_to_response(artifact)


@router.post(
    "/instances/{instance_id}/generate-qr",
    response_model=FlowInstanceArtifactResponse,
    response_model_exclude_none=True,
)
async def generate_qr_code(
    instance_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceArtifactResponse:
    """Manually generate a new QR code / credential offer for an OID4VCI flow instance."""
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")

    membership = await app.state.org_client.get_membership(
        user_id, instance.organization_id
    )
    ensure_membership_permission(membership, "flow-instance", "advance")

    flow_def = await repo.get_definition(instance.flow_definition_id)
    if not flow_def:
        raise HTTPException(status_code=404, detail="Flow Definition not found")

    if _effective_flow_type(flow_def) != FlowType.OID4VCI_PRE_AUTHORIZED:
        raise HTTPException(
            status_code=400, detail="Flow is not an OID4VCI issuance flow"
        )

    # Check retry policy (will be fully implemented in step 12)
    existing_artifacts = await repo.list_artifacts(instance_id)
    # For now, allow re-generation (retry policy will be enforced later)

    # Expire old artifacts
    for artifact in existing_artifacts:
        if artifact.status == ArtifactStatus.ACTIVE:
            artifact.status = ArtifactStatus.EXPIRED
            artifact.updated_at = datetime.now(timezone.utc)
            await repo.save_artifact(artifact)

    # Create new artifact
    artifact = await _create_oid4vci_artifact(instance, flow_def, repo)
    if not artifact:
        raise HTTPException(status_code=500, detail="Failed to create OID4VCI artifact")

    logger.info(
        f"Manually generated QR code for instance {instance_id}: artifact {artifact.id}"
    )
    return _artifact_to_response(artifact)


# =============================================================================
# Verification Flow Endpoints (for async wallet interactions)
# =============================================================================


class VerificationRequestResponse(BaseModel):
    """Response when creating a verification request through a flow."""

    instance_id: str
    flow_definition_id: str
    request_uri: str
    qr_code_data: str
    presentation_policy_id: str
    nonce: str
    expires_at: str
    status: str


class StartVerificationFlowRequest(BaseModel):
    """Request to start a verification flow (async wallet interaction).

    For OID4VP: presentation_policy_id is required.
    For SIOPv2: set response_type='id_token'; presentation_policy_id is not needed.
    """

    model_config = ConfigDict(extra="forbid")

    # Optional so SIOPv2 flows (response_type=id_token) don't require a policy.
    presentation_policy_id: str | None = None
    organization_id: str = Field(min_length=1, max_length=255)
    issuer_did: str = Field(
        pattern=r"^did:",
        max_length=2048,
        description=(
            "Public verifier DID. Signed transports resolve it to the managed "
            "Request Object signing profile; URL-query uses it only for "
            "organization-scoped verifier authorization."
        ),
    )
    # SIOPv2 Draft 13 §9: response_type=id_token selects SIOPv2 authentication.
    response_type: Literal["vp_token", "id_token"] = "vp_token"
    trust_profile_id: str | None = None
    deployment_profile_id: str | None = None
    external_reference: str | None = None
    callback_url: str | None = Field(None, max_length=2048)
    oid4vp_profile: Literal["standard", "haip"] = "standard"
    request_transport: Literal["request_uri", "request_object", "url_query"] = (
        "request_uri"
    )
    request_uri_method: Literal["get", "post"] = "get"
    expiry_minutes: int = Field(default=15, ge=1, le=1440)

    @model_validator(mode="after")
    def validate_oid4vp_transport(self) -> "StartVerificationFlowRequest":
        """Keep signed and unsigned transports distinct and fail closed."""
        if self.response_type == "vp_token" and not self.presentation_policy_id:
            raise ValueError(
                "presentation_policy_id is required for OID4VP vp_token flows"
            )
        if (
            self.request_transport in {"request_object", "url_query"}
            and self.request_uri_method != "get"
        ):
            raise ValueError(
                f"{self.request_transport} transport cannot use request_uri_method; "
                "use request_uri transport"
            )
        if self.request_transport == "url_query" and self.response_type == "id_token":
            raise ValueError(
                "url_query transport is supported only for OID4VP vp_token flows"
            )
        if self.request_transport == "url_query" and self.oid4vp_profile == "haip":
            raise ValueError(
                "url_query transport is unsigned and cannot be used for HAIP"
            )
        return self

    @field_validator("callback_url")
    @classmethod
    def validate_callback_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        from urllib.parse import urlparse

        parsed = urlparse(v)
        _env = os.environ.get("ENVIRONMENT", "production").lower()
        allowed_schemes = {"https"}
        if _env in ("development", "test"):
            allowed_schemes.add("http")
        if parsed.scheme not in allowed_schemes:
            raise ValueError(
                f"callback_url must use scheme: {', '.join(sorted(allowed_schemes))}"
            )
        if not parsed.netloc:
            raise ValueError("callback_url must have a valid host")
        # Block internal/metadata IPs
        hostname = parsed.hostname or ""
        _blocked = (
            "169.254.",
            "10.",
            "172.16.",
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "192.168.",
            "127.",
            "0.",
        )
        if any(hostname.startswith(prefix) for prefix in _blocked):
            raise ValueError("callback_url must not target private/internal networks")
        if hostname in ("localhost", "metadata.internal", "[::1]"):
            if _env not in ("development", "test"):
                raise ValueError("callback_url must not target localhost in production")
        return v


class StartSiopFlowRequest(BaseModel):
    """Request to start a cross-device SIOPv2 flow."""

    organization_id: str | None = None
    expiry_minutes: int = 15


def _require_registered_callback(
    organization_id: str,
    callback_url: str | None,
) -> None:
    if not callback_url:
        return
    try:
        require_registered_callback_destination(organization_id, callback_url)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=503,
            detail="Verification callback destination policy is unavailable",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


class SiopSubmitRequest(BaseModel):
    """Body for validating a self-issued ID token."""

    id_token: str = Field(min_length=1, max_length=16384)
    instance_id: str = Field(min_length=1, max_length=255)


class SubmitVerificationRequest(BaseModel):
    """Request to submit a VP token to a verification flow."""

    vp_token: str
    presentation_submission: dict | None = None


class DigitalCredentialSubmissionRequest(BaseModel):
    """Browser-mediated DC API response payload."""

    protocol: str | None = Field(None, max_length=128)
    origin: str | None = Field(None, max_length=512)
    data: dict[str, Any] = Field(default_factory=dict)


def _oid4vp_client_identity(
    base_url: str,
    response_uri: str,
    *,
    signing_identity: dict[str, Any],
    lissi_compat: bool = False,
) -> tuple[str, list[str] | None, str]:
    """Resolve one verifier identity for both the outer URI and signed JAR."""
    verifier_did = _derive_verifier_did(signing_identity, base_url)
    request_x5c: list[str] | None = None
    client_id_prefix = (
        os.environ.get(
            "OID4VP_CLIENT_ID_PREFIX",
            "decentralized_identifier",
        )
        .strip()
        .lower()
    )

    if lissi_compat:
        client_identifier = verifier_did
    elif client_id_prefix == "redirect_uri":
        client_identifier = response_uri
    elif client_id_prefix == "decentralized_identifier":
        client_identifier = f"decentralized_identifier:{verifier_did}"
    elif client_id_prefix == "x509_hash":
        client_identifier, request_x5c = _x509_hash_client_id_and_header(
            signing_identity["public_jwk"]
        )
    else:
        raise HTTPException(
            status_code=500,
            detail=(
                "OID4VP_CLIENT_ID_PREFIX must be decentralized_identifier, "
                "redirect_uri, or x509_hash"
            ),
        )
    return client_identifier, request_x5c, verifier_did


@router.post(
    "/verify",
    response_model=VerificationRequestResponse,
    response_model_exclude_none=True,
)
async def start_verification_flow(
    request: StartVerificationFlowRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> VerificationRequestResponse:
    """
    Start a verification flow for async wallet interactions.

    - OID4VP (default): requires presentation_policy_id; response_type=vp_token
    - SIOPv2: set response_type=id_token; presentation_policy_id is not needed.

    For stateless verification (when you already have the VP token),
    use POST /v1/presentation-policies/{id}/evaluate instead.
    """
    import secrets
    from datetime import timedelta

    # OID4VP Final requires a fresh, high-entropy nonce. Thirty-two random
    # bytes also clears the official runner's conservative entropy heuristic.
    nonce = secrets.token_urlsafe(32)

    # SIOPv2 path: no presentation policy needed — just authentication with an ID token.
    if request.response_type == "id_token":
        organization_id = str(request.organization_id or "").strip()
        if not organization_id:
            raise HTTPException(
                status_code=422,
                detail="organization_id is required to start a signed verification flow.",
            )
        if not str(request.issuer_did or "").strip():
            raise HTTPException(
                status_code=422,
                detail="issuer_did is required to start a signed verification flow.",
            )
        _require_registered_callback(organization_id, request.callback_url)
        signing_identity = await _oid4vp_issuer_identity(
            organization_id,
            request.issuer_did,
        )
        flow_definition_id = str(uuid.uuid4())
        instance = FlowInstance(
            flow_definition_id=flow_definition_id,
            organization_id=organization_id,
            status=FlowInstanceStatus.AWAITING_WALLET,
            context={
                "flow_definition_reference": "__siop_v2__",
                "nonce": nonce,
                "flow_type": "siop_v2",
                "protocol_flow_type": FlowType.SIOPV2.value,
                "current_step_name": "create_request",
                "current_step_index": 0,
                "step_results": {},
                "response_type": "id_token",
                "callback_url": request.callback_url,
                "oid4vp_issuer_did": signing_identity["issuer_did"],
                "oid4vp_signing_identity": signing_identity,
            },
            external_reference=request.external_reference,
            started_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc)
            + timedelta(minutes=request.expiry_minutes),
        )
        base_url = os.environ.get("PUBLIC_BASE_URL", "http://marty-gateway:8000")
        client_id = os.environ.get("VERIFIER_CLIENT_ID", f"{base_url}/verifier")
        request_uri = f"{base_url}/v1/flows/instances/{instance.id}/request"
        auth_request = f"openid://authorize?request_uri={request_uri}"
        instance.context["siop_client_id"] = client_id
        instance.context["request_uri"] = request_uri
        instance.context["auth_request"] = auth_request
        await repo.save_instance(instance)
        logger.info(f"Started SIOPv2 auth flow: {instance.id}")
        return VerificationRequestResponse(
            instance_id=instance.id,
            flow_definition_id=instance.flow_definition_id,
            request_uri=auth_request,
            qr_code_data=auth_request,
            presentation_policy_id="",
            nonce=nonce,
            expires_at=instance.expires_at.isoformat() if instance.expires_at else "",
            status=instance.status.value,
        )

    # OID4VP path: presentation_policy_id required.
    if not request.presentation_policy_id:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": "presentation_policy_id is required for OID4VP flows",
            },
        )
    if (
        request.oid4vp_profile == "haip"
        and os.environ.get("OID4VP_HAIP_ENABLED") != "1"
    ):
        raise HTTPException(
            status_code=409,
            detail="HAIP verifier support is not enabled for this deployment",
        )

    # Resolve the real organization_id from the presentation policy so that the
    # instance carries a valid org and the membership check in get_flow_instance
    # (and other endpoints) enforces actual authorization.
    organization_id = "__unknown__"
    try:
        from marty_proto.v1 import presentation_policy_service_pb2 as pp_pb2
        from marty_proto.v1 import presentation_policy_service_pb2_grpc as pp_grpc

        pp_stub = pp_grpc.PresentationPolicyServiceStub(app.state.pp_grpc_channel)
        pp_resp = await pp_stub.GetPolicy(
            pp_pb2.GetPolicyRequest(policy_id=request.presentation_policy_id)
        )
        if pp_resp.id:
            organization_id = pp_resp.organization_id
        else:
            raise Exception("Policy not found")
    except Exception as exc:
        logger.warning(
            f"Could not resolve organization for policy {request.presentation_policy_id}: {exc}"
        )
        raise HTTPException(
            status_code=404,
            detail=f"Presentation policy not found or service unavailable: {request.presentation_policy_id}",
        )

    requested_organization_id = str(request.organization_id or "").strip()
    if not requested_organization_id:
        raise HTTPException(
            status_code=422,
            detail="organization_id is required to start a verification flow.",
        )
    if requested_organization_id != organization_id:
        raise HTTPException(
            status_code=403,
            detail="Presentation policy belongs to another organization.",
        )
    _require_registered_callback(organization_id, request.callback_url)
    if not str(request.issuer_did or "").strip():
        raise HTTPException(
            status_code=422,
            detail="issuer_did is required to start a verification flow.",
        )

    # Verify that the requesting user is actually a member of the policy's org
    # before creating the instance. Service-to-service callers (non-UUID user IDs
    # like "auth-service") bypass this check so the credential-login flow works.
    try:
        import uuid as _uuid

        _uuid.UUID(user_id)
        is_service_user = False
    except (ValueError, AttributeError):
        is_service_user = True
    if not is_service_user:
        membership = await app.state.org_client.get_membership(user_id, organization_id)
        ensure_membership_permission(membership, "verification", "execute")

    # Create a verification flow instance directly
    signing_identity = await _oid4vp_issuer_identity(
        organization_id,
        request.issuer_did,
    )
    flow_definition_id = str(uuid.uuid4())
    instance = FlowInstance(
        flow_definition_id=flow_definition_id,
        organization_id=organization_id,
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={
            "flow_definition_reference": "__verification__",
            "presentation_policy_id": request.presentation_policy_id,
            "trust_profile_id": request.trust_profile_id,
            "deployment_profile_id": request.deployment_profile_id,
            "callback_url": request.callback_url,
            "nonce": nonce,
            "flow_type": "verification",
            "oid4vp_profile": request.oid4vp_profile,
            "oid4vp_issuer_did": signing_identity["issuer_did"],
            "oid4vp_signing_identity": signing_identity,
            "request_transport": request.request_transport,
            "request_uri_method": request.request_uri_method,
            "protocol_flow_type": FlowType.OID4VP_PRESENTATION.value,
            "current_step_name": "create_request",
            "current_step_index": 0,
            "step_results": {},
        },
        external_reference=request.external_reference,
        started_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc)
        + timedelta(minutes=request.expiry_minutes),
    )

    # Generate request URI and QR code data
    # Use gateway URL for Docker networking (Walt.ID wallet needs to access this)
    base_url = os.environ.get("PUBLIC_BASE_URL", "http://marty-gateway:8000")
    # Signed transports use the DID-resolved profile identity. Native
    # URL-query has no Request Object and derives its redirect-URI client
    # identifier from the callback endpoint instead.
    request_uri = f"{base_url}/v1/flows/instances/{instance.id}/request"
    response_uri = f"{base_url}/v1/flows/instances/{instance.id}/submit"
    if request.request_transport == "url_query":
        client_identifier = f"redirect_uri:{response_uri}"
    else:
        client_identifier, _, _ = _oid4vp_client_identity(
            base_url,
            response_uri,
            signing_identity=signing_identity,
        )
    instance.context["request_uri"] = request_uri
    instance.context["oid4vp_client_id"] = client_identifier
    await repo.save_instance(instance)

    if request.request_transport == "request_object":
        # Preserve signed by-value functionality under its canonical name.
        # The compact JAR remains opaque and profile-signed; no claim is
        # reconstructed into the outer authorization request.
        signed_response = await get_verification_request_object(instance.id, repo)
        signed_request = signed_response.body.decode("utf-8")
        auth_request = "openid4vp://authorize?" + urllib.parse.urlencode(
            [("client_id", client_identifier), ("request", signed_request)],
            quote_via=urllib.parse.quote,
            safe="",
        )
        max_length = int(
            os.environ.get(
                "OID4VP_REQUEST_OBJECT_MAX_LENGTH",
                os.environ.get("OID4VP_URL_QUERY_MAX_LENGTH", "8192"),
            )
        )
        if max_length < 1024:
            raise HTTPException(
                status_code=500,
                detail="OID4VP_REQUEST_OBJECT_MAX_LENGTH must be at least 1024",
            )
        if len(auth_request) > max_length:
            raise HTTPException(
                status_code=422,
                detail=(
                    "Signed OID4VP request exceeds the configured by-value limit; "
                    "use request_uri transport"
                ),
            )
    elif request.request_transport == "url_query":
        auth_request = await _unsigned_oid4vp_url_query(
            instance,
            base_url=base_url,
            response_uri=response_uri,
            repo=repo,
        )
    else:
        authorization_parameters = [
            ("client_id", client_identifier),
            ("request_uri", request_uri),
        ]
        if request.request_uri_method == "post":
            authorization_parameters.append(("request_uri_method", "post"))
        auth_request = "openid4vp://authorize?" + urllib.parse.urlencode(
            authorization_parameters,
            quote_via=urllib.parse.quote,
            safe="",
        )

    qr_code_data = auth_request
    instance.context["auth_request"] = auth_request
    instance.context["qr_code_data"] = qr_code_data
    await repo.save_instance(instance)
    logger.info(f"Started verification flow: {instance.id}")

    return VerificationRequestResponse(
        instance_id=instance.id,
        flow_definition_id=instance.flow_definition_id,
        request_uri=auth_request,
        qr_code_data=qr_code_data,
        presentation_policy_id=request.presentation_policy_id,
        nonce=nonce,
        expires_at=instance.expires_at.isoformat() if instance.expires_at else "",
        status=instance.status.value,
    )


async def _build_presentation_request_artifacts(
    presentation_policy_id: str,
) -> dict[str, Any]:
    """Fetch application records and delegate all OID4VP construction to Rust."""
    if not presentation_policy_id:
        raise NativeOperationError("OID4VP requests require a presentation policy")

    from marty_proto.v1 import credential_template_service_pb2 as ct_pb2
    from marty_proto.v1 import credential_template_service_pb2_grpc as ct_grpc
    from marty_proto.v1 import presentation_policy_service_pb2 as pp_pb2
    from marty_proto.v1 import presentation_policy_service_pb2_grpc as pp_grpc

    pp_stub = pp_grpc.PresentationPolicyServiceStub(app.state.pp_grpc_channel)
    policy = await pp_stub.GetPolicy(
        pp_pb2.GetPolicyRequest(policy_id=presentation_policy_id)
    )
    if not policy.id:
        raise NativeOperationError(
            f"Presentation policy {presentation_policy_id} was not found"
        )
    requirements = parse_policy_requirements(
        presentation_policy_id, policy.credential_requirements_json
    )

    ct_stub = ct_grpc.CredentialTemplateServiceStub(app.state.ct_grpc_channel)
    native_requirements: list[dict[str, Any]] = []
    for requirement in requirements:
        template_id = str(
            requirement.get("credential_template_id", "") or ""
        ).strip()
        if not template_id:
            raise NativeOperationError(
                f"Presentation policy {presentation_policy_id} has a requirement "
                "without a template"
            )
        template = await ct_stub.GetTemplate(
            ct_pb2.GetTemplateRequest(template_id=template_id)
        )
        if not template.id:
            raise NativeOperationError(
                f"Credential template {template_id} was not found"
            )
        native_requirements.append(
            credential_requirement_input(requirement, template)
        )

    return build_oid4vp_presentation_request(
        {
            "id": str(uuid.uuid4()),
            "requirements": native_requirements,
            "wallet_formats": wallet_registry_format_names(),
        }
    )


async def _build_presentation_definition(
    presentation_policy_id: str,
) -> dict[str, Any]:
    """Compatibility adapter returning Rust's Presentation Exchange artifact."""
    artifacts = await _build_presentation_request_artifacts(presentation_policy_id)
    return artifacts["presentation_definition"]


async def _oid4vp_credential_query(
    instance: FlowInstance,
    *,
    lissi_compat: bool = False,
) -> dict[str, Any]:
    """Return one of the equivalent credential queries constructed by Rust."""
    artifacts = await _build_presentation_request_artifacts(
        instance.context.get("presentation_policy_id", "")
    )
    if lissi_compat:
        return {"presentation_definition": artifacts["presentation_definition"]}
    return {"dcql_query": artifacts["dcql_query"]}

async def _unsigned_oid4vp_url_query(
    instance: FlowInstance,
    *,
    base_url: str,
    response_uri: str,
    repo: InMemoryFlowRepository,
) -> str:
    """Build the native OID4VP URL-query authorization request.

    This transport has no Request Object and therefore performs no signing.
    The redirect-URI client identifier is derived by the product and every
    structured authorization parameter is encoded as JSON exactly once.
    """
    client_identifier = f"redirect_uri:{response_uri}"
    parameters: dict[str, Any] = {
        "response_type": "vp_token",
        "client_id": client_identifier,
        "nonce": instance.context.get("nonce"),
        "response_mode": "direct_post",
        "response_uri": response_uri,
        "state": instance.id,
        "client_metadata": _oid4vp_client_metadata(base_url),
    }
    parameters.update(await _oid4vp_credential_query(instance))

    instance.context["oid4vp_client_id"] = client_identifier
    instance.context["oid4vp_response_uri"] = response_uri
    instance.context["oid4vp_response_encryption_jwk"] = None
    instance.context["oid4vp_expected_state"] = instance.id
    instance.context["verification_audience"] = client_identifier
    instance.context["oid4vp_verifier_context"] = True

    presentation_request_message = MIPMessage(
        message_type=MessageType.PRESENTATION_REQUEST,
        correlation_id=instance.id,
        sender_id=client_identifier,
        nonce=parameters["nonce"],
        payload=PresentationRequestPayload(
            client_id=client_identifier,
            response_type="vp_token",
            nonce=parameters["nonce"],
            presentation_definition=parameters.get("presentation_definition"),
            dcql_query=parameters.get("dcql_query"),
            mip_flow_instance_id=instance.id,
            mip_policy_id=instance.context.get("presentation_policy_id"),
            response_mode="direct_post",
            response_uri=response_uri,
        ),
    )
    _record_mip_message(instance, "presentation_request", presentation_request_message)
    await repo.save_instance(instance)

    query_parameters: list[tuple[str, str]] = []
    for name, value in parameters.items():
        if value is None:
            continue
        if isinstance(value, (dict, list)):
            encoded_value = json.dumps(
                value,
                separators=(",", ":"),
                sort_keys=True,
            )
        else:
            encoded_value = str(value)
        query_parameters.append((name, encoded_value))

    authorization_request = "openid4vp://authorize?" + urllib.parse.urlencode(
        query_parameters,
        quote_via=urllib.parse.quote,
        safe="",
    )
    max_length = int(os.environ.get("OID4VP_URL_QUERY_MAX_LENGTH", "8192"))
    if max_length < 1024:
        raise HTTPException(
            status_code=500,
            detail="OID4VP_URL_QUERY_MAX_LENGTH must be at least 1024",
        )
    if len(authorization_request) > max_length:
        raise HTTPException(
            status_code=422,
            detail=(
                "OID4VP authorization parameters exceed the configured URL-query "
                "limit; use request_uri transport"
            ),
        )
    return authorization_request


@router.api_route("/instances/{instance_id}/request", methods=["GET", "POST"])
async def get_verification_request_object(
    instance_id: str,
    repo: InMemoryFlowRepository = Depends(get_repo),
    transport: Annotated[str, Query()] = "request_uri",
    compat: Annotated[str | None, Query()] = None,
    request: Request = None,
) -> Response:
    """
    Get the verification request object (for wallet to fetch via request_uri).

    Per OID4VP spec, this MUST return a signed JWT Request Object,
    not plain JSON. The JWT is signed by the verifier's private key.

    For SIOPv2 instances (flow_type=siop_v2), returns a SIOPv2 auth request
    with response_type=id_token and scope=openid per SIOPv2 Draft 13 §9.

    Content-Type: application/oauth-authz-req+jwt
    """
    if transport not in {"request_uri", "dc_api"}:
        raise HTTPException(
            status_code=400, detail="transport must be either 'request_uri' or 'dc_api'"
        )

    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow instance not found")

    if instance.status not in [
        FlowInstanceStatus.AWAITING_WALLET,
        FlowInstanceStatus.IN_PROGRESS,
    ]:
        raise HTTPException(
            status_code=400, detail="Request already processed or invalid state"
        )

    if instance.expires_at and datetime.now(timezone.utc) > instance.expires_at:
        instance.transition_to(FlowInstanceStatus.EXPIRED, event="request_expired")
        await repo.save_instance(instance)
        raise HTTPException(status_code=410, detail="Verification request has expired")

    if instance.context.get("request_transport") == "url_query":
        raise HTTPException(
            status_code=400,
            detail="url_query transport has no signed Request Object endpoint",
        )

    # Resolve the active identity on every fetch so a revoked or rotated issuer
    # profile cannot continue signing from stale flow state.
    signing_identity = await _oid4vp_issuer_identity(
        instance.organization_id,
        instance.context.get("oid4vp_issuer_did"),
    )
    # Build base URL for response_uri (where wallet posts the VP)
    base_url = os.environ.get("PUBLIC_BASE_URL", "http://marty-gateway:8000")
    flow_type = instance.context.get("flow_type", "verification")
    configured_client_id = os.environ.get("VERIFIER_CLIENT_ID", f"{base_url}/verifier")
    client_id = (
        instance.context.get("siop_client_id") or configured_client_id
        if flow_type == "siop_v2"
        else configured_client_id
    )
    compat_profile = (compat or "").strip().lower()
    request_x5c: list[str] | None = None

    if flow_type == "siop_v2":
        # SIOPv2 Draft 13 §9: authentication request for a self-issued OP.
        # response_type MUST be id_token; scope MUST include openid.
        siop_submit_uri = f"{base_url}/v1/flows/siop/submit"
        request_payload = {
            "response_type": "id_token",
            "scope": "openid",
            "client_id": client_id,
            "redirect_uri": siop_submit_uri,
            "nonce": instance.context.get("nonce"),
            "state": instance_id,
            "iss": client_id,
            "aud": "https://self-issued.me/v2",
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(instance.expires_at.timestamp())
            if instance.expires_at
            else int(datetime.now(timezone.utc).timestamp() + 900),
            # SIOPv2 §6.1: advertise subject syntax types we accept
            "subject_syntax_types_supported": [
                "urn:ietf:params:oauth:jwk-thumbprint",
            ],
        }
    else:
        # Mark every request produced by this endpoint as an OID4VP verifier
        # transaction.  Presentation policies may also be used for credential-
        # only checks that intentionally have no holder proof; the downstream
        # verifier needs this trusted flow-owned context to distinguish those
        # calls from an OID4VP presentation, where SD-JWT key binding is
        # mandatory regardless of an operator's policy setting.
        instance.context["oid4vp_verifier_context"] = True
        response_uri = f"{base_url}/v1/flows/instances/{instance_id}/submit"
        # OID4VP 1.0 Final §5.10: identify the verifier with a DID-based
        # client identifier. SpruceID Kit rejects did:key/did:jwk for request
        # object verification, so the default verifier DID is path-scoped did:web.
        # The response_uri is where the wallet POSTs the VP token (the submit endpoint).
        lissi_compat = compat_profile == "lissi"
        client_identifier, request_x5c, verifier_did = _oid4vp_client_identity(
            base_url,
            response_uri,
            signing_identity=signing_identity,
            lissi_compat=lissi_compat,
        )
        outer_client_identifier = instance.context.get("oid4vp_client_id")
        if lissi_compat:
            compatible_outer_identifiers = {
                verifier_did,
                f"decentralized_identifier:{verifier_did}",
            }
            if outer_client_identifier not in compatible_outer_identifiers:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "LISSI compatibility requires a DID verifier identity; "
                        "start a standard DID-based OID4VP flow"
                    ),
                )
        elif (
            isinstance(outer_client_identifier, str)
            and outer_client_identifier
            and outer_client_identifier != client_identifier
        ):
            raise HTTPException(
                status_code=409,
                detail="OID4VP verifier identity changed after this flow was created",
            )
        if (
            isinstance(outer_client_identifier, str)
            and outer_client_identifier
            and not lissi_compat
        ):
            client_identifier = outer_client_identifier
        # Build OID4VP Request Object payload
        # This will be signed as a JWT per OID4VP spec section 5
        request_payload = {
            # Standard OAuth 2.0 parameters
            "response_type": "vp_token",
            "client_id": client_identifier,
            "nonce": instance.context.get("nonce"),
            # JWT claims
            "iss": client_identifier,
            "aud": "https://self-issued.me/v2",  # Audience (standard for OID4VP)
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(instance.expires_at.timestamp())
            if instance.expires_at
            else int((datetime.now(timezone.utc).timestamp() + 900)),
        }

        if instance.context.get("request_uri_method") == "post":
            if request is None or request.method != "POST":
                raise HTTPException(
                    status_code=405, detail="this request_uri requires HTTP POST"
                )
            form = await request.form()
            wallet_nonce = form.get("wallet_nonce")
            if not isinstance(wallet_nonce, str) or not wallet_nonce:
                raise HTTPException(
                    status_code=400,
                    detail="wallet_nonce is required for POST request_uri retrieval",
                )
            request_payload["wallet_nonce"] = wallet_nonce

        if lissi_compat:
            request_payload["client_id_scheme"] = "did"
        else:
            request_payload["client_metadata"] = _oid4vp_client_metadata(base_url)

        response_encryption_jwk: dict[str, str] | None = None
        if transport == "dc_api":
            expected_origins = _expected_origins_for_dc_api(base_url)
            if not lissi_compat:
                response_encryption_jwk = await _haip_response_encryption_key(instance)
                request_payload["client_metadata"] = _oid4vp_client_metadata(
                    base_url,
                    include_encrypted_response=True,
                    response_encryption_jwk=response_encryption_jwk,
                )
            request_payload["response_mode"] = _DC_API_JWT_RESPONSE_MODE
            request_payload["expected_origins"] = expected_origins
            instance.context["dc_api_expected_origins"] = expected_origins
            instance.context["dc_api_protocol"] = _DC_API_PROTOCOL
            instance.context["dc_api_response_mode"] = _DC_API_JWT_RESPONSE_MODE
            instance.context["dc_api_jwe_alg"] = _HAIP_JWE_ALG
            instance.context["dc_api_jwe_enc"] = _HAIP_JWE_ENC
        else:
            haip = instance.context.get("oid4vp_profile") == "haip"
            if haip:
                if lissi_compat:
                    raise HTTPException(
                        status_code=400,
                        detail="HAIP is incompatible with the lissi compatibility profile",
                    )
                response_encryption_jwk = await _haip_response_encryption_key(instance)
                request_payload["client_metadata"] = _oid4vp_client_metadata(
                    base_url,
                    include_encrypted_response=True,
                    response_encryption_jwk=response_encryption_jwk,
                )
                request_payload["response_mode"] = "direct_post.jwt"
                instance.context["haip_response_mode"] = "direct_post.jwt"
                instance.context["haip_jwe_alg"] = _HAIP_JWE_ALG
                instance.context["haip_jwe_enc"] = _HAIP_JWE_ENC
            else:
                request_payload["response_mode"] = "direct_post"
            request_payload["response_uri"] = response_uri
            request_payload["state"] = instance_id
            # Bind the callback to this exact request.  Keep the expected
            # value in the flow rather than inferring it from the callback
            # path: a direct-post response can be delivered through a proxy
            # or by a wallet that reorders its form fields.
            instance.context["oid4vp_expected_state"] = instance_id
            instance.context["verification_audience"] = client_identifier

        instance.context["oid4vp_client_id"] = client_identifier
        instance.context["oid4vp_response_uri"] = request_payload.get("response_uri")
        instance.context["oid4vp_response_encryption_jwk"] = response_encryption_jwk

        request_payload.update(
            await _oid4vp_credential_query(
                instance,
                lissi_compat=lissi_compat,
            )
        )

        presentation_request_message = MIPMessage(
            message_type=MessageType.PRESENTATION_REQUEST,
            correlation_id=instance.id,
            sender_id=client_identifier,
            nonce=request_payload.get("nonce"),
            payload=PresentationRequestPayload(
                client_id=client_identifier,
                response_type=request_payload["response_type"],
                nonce=request_payload["nonce"],
                presentation_definition=request_payload.get("presentation_definition"),
                dcql_query=request_payload.get("dcql_query"),
                mip_flow_instance_id=instance.id,
                mip_policy_id=instance.context.get("presentation_policy_id"),
                response_mode=request_payload.get("response_mode"),
                response_uri=request_payload.get("response_uri"),
            ),
        )
        _record_mip_message(
            instance, "presentation_request", presentation_request_message
        )
        await repo.save_instance(instance)

    jwt_headers = {
        "typ": "oauth-authz-req+jwt",
        "alg": "ES256",
        "kid": signing_identity["verification_method_id"],
    }
    if flow_type != "siop_v2":
        if request_x5c:
            jwt_headers.pop("kid", None)
            jwt_headers["x5c"] = request_x5c

    # Sign the Request Object through the issuer DID. The flow service has only
    # the DID and public key; it never receives KMS coordinates or private key
    # material.
    try:
        signed_request_jwt = await _sign_request_object_with_issuer_did(
            organization_id=instance.organization_id,
            identity=signing_identity,
            protected_header=jwt_headers,
            claims=request_payload,
        )

        logger.info(f"Generated signed Request Object JWT for instance {instance_id}")

        # Return the JWT with proper content type per OID4VP spec
        return Response(
            content=signed_request_jwt,
            media_type="application/oauth-authz-req+jwt",
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to sign Request Object: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate request object")


@did_router.get(f"/{_OID4VP_DID_WEB_PATH}/did.json", include_in_schema=False)
async def get_oid4vp_did_web_document(request: Request) -> JSONResponse:
    """Serve a compatibility alias for the issuer profile's public DID document."""
    organization_id = os.environ.get(
        "MARTY_ORG_ID",
        "00000000-0000-0000-0000-000000000001",
    )
    signing_identity = await _oid4vp_issuer_identity(organization_id)
    return JSONResponse(
        content=_oid4vp_did_web_document(signing_identity),
        media_type="application/did+json",
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Access-Control-Allow-Origin": "*",
        },
    )


def _base58_encode(data: bytes) -> str:
    """Base58btc encode (Bitcoin alphabet)."""
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(data, "big")
    result = []
    while num > 0:
        num, remainder = divmod(num, 58)
        result.append(ALPHABET[remainder])
    for byte in data:
        if byte == 0:
            result.append(ALPHABET[0])
        else:
            break
    return "".join(reversed(result))


def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(data: str) -> bytes:
    """Base64url decode with optional padding omitted."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def _cbor_length(major_type: int, length: int) -> bytes:
    """Encode a canonical definite-length CBOR header."""
    if length < 24:
        return bytes([(major_type << 5) | length])
    if length <= 0xFF:
        return bytes([(major_type << 5) | 24, length])
    if length <= 0xFFFF:
        return bytes([(major_type << 5) | 25]) + length.to_bytes(2, "big")
    if length <= 0xFFFFFFFF:
        return bytes([(major_type << 5) | 26]) + length.to_bytes(4, "big")
    return bytes([(major_type << 5) | 27]) + length.to_bytes(8, "big")


def _cbor_encode_handover_value(value: Any) -> bytes:
    """Encode only the types used by ISO OpenID4VP HandoverInfo."""
    if value is None:
        return b"\xf6"
    if isinstance(value, bytes):
        return _cbor_length(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return _cbor_length(3, len(encoded)) + encoded
    if isinstance(value, list):
        return _cbor_length(4, len(value)) + b"".join(
            _cbor_encode_handover_value(item) for item in value
        )
    raise TypeError(f"Unsupported OpenID4VP handover CBOR type: {type(value).__name__}")


def _openid4vp_response_key_thumbprint(
    response_encryption_jwk: dict[str, Any] | None,
) -> bytes | None:
    """Return the raw RFC 7638 thumbprint used by OpenID4VP HandoverInfo."""
    if response_encryption_jwk is None:
        return None
    if response_encryption_jwk.get("kty") != "EC":
        raise ValueError("OpenID4VP response-encryption JWK must be an EC key")
    required = ("crv", "kty", "x", "y")
    if any(not isinstance(response_encryption_jwk.get(name), str) for name in required):
        raise ValueError("OpenID4VP response-encryption JWK is incomplete")
    canonical = json.dumps(
        {name: response_encryption_jwk[name] for name in required},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).digest()


def _build_openid4vp_mdoc_session_transcript(
    *,
    client_id: str,
    nonce: str,
    response_uri: str,
    response_encryption_jwk: dict[str, Any] | None,
) -> bytes:
    """Build ISO 18013-7 OpenID4VP SessionTranscript from verifier-owned state."""
    if not client_id or not nonce or not response_uri:
        raise ValueError(
            "OpenID4VP mdoc handover requires client_id, nonce, and response_uri"
        )
    handover_info = [
        client_id,
        nonce,
        _openid4vp_response_key_thumbprint(response_encryption_jwk),
        response_uri,
    ]
    handover_digest = hashlib.sha256(
        _cbor_encode_handover_value(handover_info)
    ).digest()
    return _cbor_encode_handover_value(
        [None, None, ["OpenID4VPHandover", handover_digest]]
    )


def _openid4vp_mdoc_binding_digests(
    *,
    session_transcript: bytes,
    client_id: str,
    nonce: str,
    response_uri: str,
    response_encryption_jwk: dict[str, Any] | None,
    presentation: str,
) -> dict[str, str]:
    """Return non-reversible diagnostics for an mdoc request binding.

    Official interoperability runs can compare these digests with values
    exported by an unmodified external runner without logging the request
    nonce, verifier identity, callback URL, response key, or transcript.
    """
    response_key_thumbprint = _openid4vp_response_key_thumbprint(
        response_encryption_jwk
    )
    return {
        "transcript_sha256": hashlib.sha256(session_transcript).hexdigest(),
        "client_id_sha256": hashlib.sha256(client_id.encode("utf-8")).hexdigest(),
        "nonce_sha256": hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
        "response_uri_sha256": hashlib.sha256(response_uri.encode("utf-8")).hexdigest(),
        "response_key_thumbprint_sha256": (
            hashlib.sha256(response_key_thumbprint).hexdigest()
            if response_key_thumbprint is not None
            else "none"
        ),
        "presentation_sha256": hashlib.sha256(presentation.encode("utf-8")).hexdigest(),
    }


def _verifier_x509_certificates() -> list[x509.Certificate]:
    """Load the verifier leaf certificate and any issuer chain certificates.

    ``x509_hash`` is derived from the leaf, while a HAIP request object must
    include the complete leaf-to-trust-anchor chain in its ``x5c`` header.
    PEM bundles are accepted in the natural order: leaf first, then issuers.
    """
    certificate_pem = os.environ.get("VERIFIER_X509_CERT_PEM")
    certificate_file = os.environ.get("VERIFIER_X509_CERT_FILE")
    if certificate_pem:
        data = certificate_pem.encode("utf-8")
    elif certificate_file and os.path.isfile(certificate_file):
        data = Path(certificate_file).read_bytes()
    else:
        raise RuntimeError(
            "VERIFIER_X509_CERT_PEM or VERIFIER_X509_CERT_FILE is required for x509_hash"
        )
    pem_certificates = re.findall(
        rb"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----",
        data,
    )
    if not pem_certificates:
        raise RuntimeError("VERIFIER_X509_CERT_* contains no PEM certificate")
    return [
        x509.load_pem_x509_certificate(certificate) for certificate in pem_certificates
    ]


def _verifier_x509_certificate() -> x509.Certificate:
    """Return the leaf certificate used for the x509_hash client identifier."""
    return _verifier_x509_certificates()[0]


def _ec_public_key_from_jwk(public_jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    if public_jwk.get("kty") != "EC" or public_jwk.get("crv") != "P-256":
        raise RuntimeError("OID4VP issuer profile must publish a P-256 public JWK")
    try:
        x = int.from_bytes(_base64url_decode(str(public_jwk["x"])), "big")
        y = int.from_bytes(_base64url_decode(str(public_jwk["y"])), "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(
            "OID4VP issuer profile contains an invalid P-256 public JWK"
        ) from exc


def _x509_hash_client_id_and_header(
    public_jwk: dict[str, Any],
) -> tuple[str, list[str]]:
    """Return the OID4VP x509_hash identifier and JOSE ``x5c`` certificate."""
    certificates = _verifier_x509_certificates()
    certificate = certificates[0]
    der = certificate.public_bytes(serialization.Encoding.DER)
    certificate_hash = hashes.Hash(hashes.SHA256())
    certificate_hash.update(der)
    digest = _base64url_encode(certificate_hash.finalize())

    certificate_public = certificate.public_key()
    profile_public = _ec_public_key_from_jwk(public_jwk)
    if not isinstance(certificate_public, ec.EllipticCurvePublicKey) or (
        certificate_public.public_numbers() != profile_public.public_numbers()
    ):
        raise RuntimeError(
            "VERIFIER_X509_CERT_* public key must match the issuer profile signing identity"
        )
    # x5c carries the leaf and intermediates.  A verifier's configured trust
    # anchor is deliberately omitted: HAIP validators reject trust anchors in
    # the JOSE header and obtain them from their configured trust store.
    x5c_certificates = certificates
    if len(certificates) > 1 and certificates[-1].issuer == certificates[-1].subject:
        x5c_certificates = certificates[:-1]
    return f"x509_hash:{digest}", [
        base64.b64encode(item.public_bytes(serialization.Encoding.DER)).decode("ascii")
        for item in x5c_certificates
    ]


def _verifier_public_jwk(signing_identity: dict[str, Any]) -> dict[str, str]:
    """Return the issuer profile's sanitized public verifier JWK."""
    public_jwk = signing_identity.get("public_jwk")
    if not isinstance(public_jwk, dict):
        raise RuntimeError("OID4VP issuer profile has no public JWK")
    return {
        key: str(value)
        for key, value in public_jwk.items()
        if key in {"kty", "crv", "x", "y", "kid", "alg", "use"}
    }


def _new_haip_response_encryption_key() -> tuple[dict[str, str], dict[str, str]]:
    """Create a fresh P-256 response-encryption key for one verification flow."""
    private = jwk.JWK.generate(kty="EC", crv="P-256", kid=f"oid4vp-haip-{uuid.uuid4()}")
    private_data = json.loads(private.export_private())
    public_data = json.loads(private.export_public())
    public_data.update({"alg": _HAIP_JWE_ALG, "use": "enc"})
    private_data.update({"alg": _HAIP_JWE_ALG, "use": "enc"})
    return public_data, private_data


async def _wrap_flow_private_jwk(
    instance: FlowInstance,
    private_jwk: dict[str, Any],
) -> str:
    base_url = os.environ.get(
        "SIGNING_KEYS_INTERNAL_URL",
        "http://gateway:8000/internal/signing-keys",
    ).rstrip("/")
    api_key = _read_secret_value("SIGNING_KEYS_INTERNAL_API_KEY") or _read_secret_value(
        "ISSUANCE_API_KEY"
    )
    encoded = _base64url_encode(
        json.dumps(private_jwk, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{base_url}/flow-key-envelopes/wrap",
                params={"organization_id": instance.organization_id},
                headers={"X-API-Key": api_key},
                json={"flow_instance_id": instance.id, "plaintext_b64": encoded},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503, detail="KMS flow-key wrapping service is unavailable"
        ) from exc
    if response.status_code >= 400:
        raise HTTPException(status_code=503, detail="KMS flow-key wrapping failed")
    ciphertext = response.json().get("ciphertext")
    if not isinstance(ciphertext, str) or not ciphertext.startswith("vault:"):
        raise HTTPException(
            status_code=503, detail="KMS returned an invalid flow-key envelope"
        )
    return ciphertext


async def _unwrap_flow_private_jwk(instance: FlowInstance) -> dict[str, Any]:
    ciphertext = instance.context.get("haip_response_encryption_key_envelope")
    if not isinstance(ciphertext, str) or not ciphertext.startswith("vault:"):
        raise HTTPException(
            status_code=400, detail="Encrypted response was not requested for this flow"
        )
    base_url = os.environ.get(
        "SIGNING_KEYS_INTERNAL_URL",
        "http://gateway:8000/internal/signing-keys",
    ).rstrip("/")
    api_key = _read_secret_value("SIGNING_KEYS_INTERNAL_API_KEY") or _read_secret_value(
        "ISSUANCE_API_KEY"
    )
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{base_url}/flow-key-envelopes/unwrap",
                params={"organization_id": instance.organization_id},
                headers={"X-API-Key": api_key},
                json={"flow_instance_id": instance.id, "ciphertext": ciphertext},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=503, detail="KMS flow-key unwrapping service is unavailable"
        ) from exc
    if response.status_code >= 400:
        raise HTTPException(
            status_code=400, detail="KMS flow-key envelope could not be unwrapped"
        )
    try:
        encoded = str(response.json()["plaintext_b64"])
        private_jwk = json.loads(_base64url_decode(encoded))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=503, detail="KMS returned invalid flow-key material"
        ) from exc
    if not isinstance(private_jwk, dict) or not private_jwk.get("d"):
        raise HTTPException(
            status_code=503, detail="KMS returned invalid flow-key material"
        )
    return private_jwk


async def _haip_response_encryption_key(instance: FlowInstance) -> dict[str, str]:
    """Return the public half of a per-flow HAIP response key.

    The private half is persisted only as a KMS ciphertext envelope, while a
    new key is generated for every separate flow.
    """
    envelope = instance.context.get("haip_response_encryption_key_envelope")
    public = instance.context.get("haip_response_encryption_public_jwk")
    if (
        isinstance(envelope, str)
        and envelope.startswith("vault:")
        and isinstance(public, dict)
    ):
        return public
    public, private = _new_haip_response_encryption_key()
    envelope = await _wrap_flow_private_jwk(instance, private)
    instance.context["haip_response_encryption_public_jwk"] = public
    instance.context["haip_response_encryption_key_envelope"] = envelope
    return public


def _derive_verifier_did(
    signing_identity: dict[str, Any],
    base_url: str | None = None,
) -> str:
    """Derive the verifier DID used as the OID4VP client identifier.

    Defaults to did:web because SpruceID Kit currently rejects did:key and
    did:jwk request object verification methods. VERIFIER_DID_METHOD can still
    select did:key or did:jwk for other wallet profiles.
    """
    did_method = os.environ.get("VERIFIER_DID_METHOD", "did:web").strip().lower()
    if did_method in {"web", "did:web"}:
        return str(signing_identity["issuer_did"])
    if did_method in {"jwk", "did:jwk"}:
        return _derive_verifier_did_jwk(signing_identity)
    if did_method in {"key", "did:key"}:
        return _derive_verifier_did_key(signing_identity)
    raise RuntimeError(f"Unsupported VERIFIER_DID_METHOD: {did_method}")


def _derive_verifier_did_jwk(signing_identity: dict[str, Any]) -> str:
    """Derive a did:jwk from the verifier's P-256 public signing key."""
    public_jwk = _verifier_public_jwk(signing_identity)
    public_jwk.pop("kid", None)
    jwk_json = json.dumps(public_jwk, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return f"did:jwk:{_base64url_encode(jwk_json)}"


def _derive_verifier_did_key(signing_identity: dict[str, Any]) -> str:
    """Derive a did:key from the verifier's P-256 (secp256r1) signing key.

    Uses multicodec code 0x1200 (varint: b'\\x80\\x24') for secp256r1-pub,
    encoded as base58btc multibase (prefix 'z').
    """
    public_key = _ec_public_key_from_jwk(_verifier_public_jwk(signing_identity))
    compressed_pub = public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )
    # varint(0x1200) = b'\x80\x24' (secp256r1-pub multicodec prefix)
    multicodec_bytes = b"\x80\x24" + compressed_pub
    return f"did:key:z{_base58_encode(multicodec_bytes)}"


def _oid4vp_did_web_document(signing_identity: dict[str, Any]) -> dict[str, Any]:
    """Return the DID document published for the selected issuer profile."""
    document = signing_identity.get("did_document")
    if not isinstance(document, dict) or document.get("id") != signing_identity.get(
        "issuer_did"
    ):
        raise RuntimeError("OID4VP issuer profile has no matching DID document")
    return document


def _oid4vp_client_metadata(
    base_url: str,
    *,
    include_encrypted_response: bool = False,
    response_encryption_jwk: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Verifier metadata advertised to wallets in OID4VP request objects."""
    metadata: dict[str, Any] = {
        "vp_formats_supported": {
            "jwt_vp": {"alg_values_supported": ["ES256", "EdDSA"]},
            "ldp_vp": {"proof_type_values_supported": ["Ed25519Signature2020"]},
            "jwt_vc_json": {"alg_values_supported": ["ES256", "EdDSA"]},
            "vc+sd-jwt": dict(_SD_JWT_PRESENTATION_ALGS),
            "dc+sd-jwt": dict(_SD_JWT_PRESENTATION_ALGS),
            "mso_mdoc": {"alg_values_supported": ["ES256"]},
        },
    }
    # The OID4VP Final runner treats branding fields as unknown client
    # metadata. Keep them for normal wallet UX, but omit them in the strict
    # conformance deployment rather than introducing runner-only exceptions.
    if os.environ.get("OID4VP_STRICT_CLIENT_METADATA") != "1":
        metadata.update(
            {
                "client_name": os.environ.get("VERIFIER_DISPLAY_NAME", "ElevenID LLC"),
                "logo_uri": os.environ.get(
                    "VERIFIER_LOGO_URI", f"{base_url}/favicon.svg"
                ),
            }
        )
    if include_encrypted_response:
        if response_encryption_jwk is None:
            raise RuntimeError(
                "Encrypted OID4VP responses require a per-flow public key"
            )
        metadata.update(
            {
                # HAIP defines this set in client metadata.  Do not emit the
                # legacy authorization_encrypted_response_* names alongside
                # it: strict wallets treat those as unexpected parameters.
                "encrypted_response_enc_values_supported": _HAIP_JWE_ENC_VALUES,
                "jwks": {"keys": [response_encryption_jwk]},
            }
        )
    return metadata


def _select_vp_token_for_evaluation(vp_token: str) -> str:
    """Extract the actual credential token from OID4VP descriptor wrappers.

    Some wallets submit ``vp_token`` as a JSON object keyed by input descriptor,
    for example ``{"descriptor-id": ["<sd-jwt>"]}``.  The policy evaluator
    expects the credential token itself, so unwrap the first token-like string.
    """
    raw = vp_token.strip()
    if not raw or raw[0] not in "[{":
        return vp_token

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return vp_token

    # OID4VP DCQL sends a JSON object keyed by credential-query id. This
    # evaluator currently supports one requested credential, so accept only
    # the exact one-query/one-presentation transport shape. The value remains
    # untrusted and is fully parsed and authenticated by the policy service.
    if isinstance(parsed, dict) and len(parsed) == 1:
        presentations = next(iter(parsed.values()))
        if (
            isinstance(presentations, list)
            and len(presentations) == 1
            and isinstance(presentations[0], str)
            and presentations[0].strip()
        ):
            return presentations[0]

    def _looks_token_like(value: str) -> bool:
        candidate = value.strip()
        return (
            "~" in candidate
            or candidate.count(".") >= 2
            or candidate.startswith(("mso_mdoc:", "mdoc:", "oob:"))
        )

    def _walk(value: Any) -> str | None:
        if isinstance(value, str):
            return value if _looks_token_like(value) else None
        if isinstance(value, list):
            for item in value:
                found = _walk(item)
                if found:
                    return found
        if isinstance(value, dict):
            for item in value.values():
                found = _walk(item)
                if found:
                    return found
        return None

    return _walk(parsed) or vp_token


def _parse_presentation_submission(
    presentation_submission: str | dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Normalize presentation_submission from form or JSON bodies."""
    if presentation_submission is None:
        return None
    if isinstance(presentation_submission, dict):
        return presentation_submission
    if isinstance(presentation_submission, str):
        try:
            return json.loads(presentation_submission)
        except json.JSONDecodeError:
            raise HTTPException(
                status_code=400, detail="presentation_submission must be valid JSON"
            )
    raise HTTPException(
        status_code=400, detail="presentation_submission must be a JSON object"
    )


def _decode_compact_jose_header(compact_token: str) -> dict[str, Any]:
    parts = compact_token.split(".")
    if len(parts) != 5:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": "DigitalCredential.data.response must be a compact JWE",
            },
        )
    try:
        header = json.loads(_base64url_decode(parts[0]))
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": f"Malformed dc_api.jwt JWE header: {exc}",
            },
        ) from exc
    if not isinstance(header, dict):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": "dc_api.jwt JWE header must be a JSON object",
            },
        )
    return header


def _parse_decrypted_dc_api_response(payload_bytes: bytes) -> dict[str, Any]:
    try:
        payload_text = payload_bytes.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": f"Decrypted dc_api.jwt response must be UTF-8 JSON or JWT: {exc}",
            },
        ) from exc

    try:
        if payload_text.startswith("{"):
            response_payload = json.loads(payload_text)
        elif len(payload_text.split(".")) >= 3:
            jwt_parts = payload_text.split(".")
            response_payload = json.loads(_base64url_decode(jwt_parts[1]))
        else:
            raise ValueError("payload is neither JSON nor JWT")
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": f"Decrypted dc_api.jwt response payload is invalid: {exc}",
            },
        ) from exc

    if not isinstance(response_payload, dict):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": "Decrypted dc_api.jwt response payload must be a JSON object",
            },
        )
    return response_payload


def _decrypt_jwt_response(
    encrypted_response: Any,
    private_jwk: dict[str, str],
    *,
    field_name: str,
) -> dict[str, Any]:
    _validate_encrypted_response_header(encrypted_response, field_name=field_name)

    try:
        from jwcrypto import jwe as jwcrypto_jwe
        from jwcrypto import jwk as jwcrypto_jwk
    except ImportError as exc:
        logger.error(
            "jwcrypto is required for HAIP dc_api.jwt decryption", exc_info=True
        )
        raise HTTPException(
            status_code=500,
            detail={
                "error": "server_error",
                "error_description": "HAIP dc_api.jwt decryption dependency is not installed",
            },
        ) from exc

    try:
        key = jwcrypto_jwk.JWK.from_json(json.dumps(private_jwk))
        token = jwcrypto_jwe.JWE()
        token.deserialize(encrypted_response, key=key)
    except Exception as exc:
        logger.info("Failed to decrypt %s response", field_name, exc_info=True)
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": f"Failed to decrypt {field_name} response: {exc}",
            },
        ) from exc

    return _parse_decrypted_dc_api_response(token.payload)


def _validate_encrypted_response_header(
    encrypted_response: Any,
    *,
    field_name: str,
) -> dict[str, Any]:
    """Reject malformed or unsupported JWE input before requesting KMS unwrap."""
    if not isinstance(encrypted_response, str) or not encrypted_response.strip():
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": f"{field_name} must be a non-empty compact JWE string",
            },
        )

    header = _decode_compact_jose_header(encrypted_response)
    alg = header.get("alg")
    enc = header.get("enc")
    if alg not in _SUPPORTED_HAIP_JWE_ALGS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": f"Unsupported {field_name} JWE alg: {alg}",
            },
        )
    if enc not in _SUPPORTED_HAIP_JWE_ENCS:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": f"Unsupported {field_name} JWE enc: {enc}",
            },
        )

    return header


def _decrypt_dc_api_jwt_response(
    encrypted_response: Any,
    private_jwk: dict[str, Any],
) -> dict[str, Any]:
    return _decrypt_jwt_response(
        encrypted_response,
        private_jwk,
        field_name="dc_api.jwt",
    )


def _verification_submission_digest(
    *,
    vp_token: str,
    presentation_submission: str | dict[str, Any] | None,
    state: str | None,
) -> str:
    canonical = json.dumps(
        {
            "vp_token": vp_token,
            "presentation_submission": presentation_submission,
            "state": state,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _terminal_verification_response(
    instance: FlowInstance,
) -> VerificationResultResponse:
    result = instance.result or {}
    return VerificationResultResponse(
        instance_id=instance.id,
        status=_protocol_status_for_instance(instance.status),
        result=str(result.get("evaluation_result") or "failed"),
        decision=str(result.get("decision") or "deny"),
        decision_reason=str(result.get("decision_reason") or ""),
        verified_claims=result.get("verified_claims")
        if isinstance(result.get("verified_claims"), dict)
        else {},
        evaluation_timestamp=(instance.completed_at or instance.updated_at).isoformat(),
    )


def _raise_verification_replay_conflict() -> None:
    raise HTTPException(
        status_code=409,
        detail={
            "error": "verification_replay_conflict",
            "error_description": (
                "A different response already finalized this verification transaction"
            ),
        },
    )


async def _submit_verification_response_internal(
    instance_id: str,
    vp_token: str,
    presentation_submission: str | dict[str, Any] | None,
    state: str | None,
    repo: InMemoryFlowRepository,
    verification_audience: str | None = None,
) -> VerificationResultResponse:
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow instance not found")

    submission_digest = _verification_submission_digest(
        vp_token=vp_token,
        presentation_submission=presentation_submission,
        state=state,
    )
    if instance.status in {
        FlowInstanceStatus.COMPLETED,
        FlowInstanceStatus.FAILED,
    }:
        prior_digest = (instance.result or {}).get("submission_digest")
        if isinstance(prior_digest, str) and hmac.compare_digest(
            prior_digest, submission_digest
        ):
            return _terminal_verification_response(instance)
        _raise_verification_replay_conflict()

    if instance.expires_at and datetime.now(timezone.utc) > instance.expires_at:
        instance.transition_to(FlowInstanceStatus.EXPIRED, event="submission_expired")
        await repo.save_instance(instance)
        raise HTTPException(status_code=410, detail="Verification request has expired")

    if instance.status not in [
        FlowInstanceStatus.AWAITING_WALLET,
        FlowInstanceStatus.IN_PROGRESS,
    ]:
        raise HTTPException(
            status_code=400, detail="Submission not accepted in current state"
        )
    expected_status = instance.status
    # Repository adapters return detached objects in production. Use the same
    # semantics in the development repository so concurrent handlers never
    # mutate shared state before the compare-and-swap commit.
    instance = copy.deepcopy(instance)

    # Every request object emitted by this verifier contains a state value.
    # Require the corresponding callback parameter before accepting a
    # direct-post response, including a state carried inside a HAIP encrypted
    # response.  Older internal callers that never generated an OID4VP request
    # have no ``oid4vp_expected_state`` marker and retain their existing API
    # contract.
    expected_state = instance.context.get("oid4vp_expected_state")
    if expected_state is not None and state != expected_state:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": "OID4VP response state does not match the verification request",
            },
        )

    effective_audience = verification_audience or instance.context.get(
        "verification_audience", ""
    )
    if effective_audience:
        instance.context["verification_audience"] = effective_audience

    parsed_submission = _parse_presentation_submission(presentation_submission)

    # OID4VP 1.0 Final §8: validate presentation_submission structure (PE v2)
    if parsed_submission is not None:
        if (
            not isinstance(parsed_submission, dict)
            or "id" not in parsed_submission
            or "definition_id" not in parsed_submission
            or "descriptor_map" not in parsed_submission
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid presentation_submission: missing required fields (id, definition_id, descriptor_map)",
            )

    # OID4VP 1.0 Final §8.6: verify nonce in VP token matches expected nonce
    raw_vp_token = vp_token
    vp_token = _select_vp_token_for_evaluation(vp_token)
    if vp_token != raw_vp_token:
        logger.info("Unwrapped OID4VP descriptor-map vp_token for policy evaluation")

    # The flow service owns OID4VP transport and replay state. It deliberately
    # does not decode unverified JWT/CBOR claims or implement a partial
    # algorithm allowlist. The presentation-policy service is the sole
    # cryptographic verifier for SD-JWT, JWT VC, Data Integrity and mdoc, and
    # receives the exact nonce and audience from this flow below.
    expected_nonce = instance.context.get("nonce")

    # -----------------------------------------------------------------------
    # Real policy evaluation — call the presentation-policy service via gRPC
    # -----------------------------------------------------------------------
    policy_id = instance.context.get("presentation_policy_id")

    verified_claims: dict = {}
    credential_results: list[dict[str, Any]] = []
    evaluation_result = "passed"
    evaluation_decision = "allow"
    decision_reason = "All policy requirements satisfied"

    if policy_id:
        try:
            import json as _json
            from marty_proto.v1 import presentation_policy_service_pb2 as pp_pb2
            from marty_proto.v1 import presentation_policy_service_pb2_grpc as pp_grpc

            pp_stub = pp_grpc.PresentationPolicyServiceStub(app.state.pp_grpc_channel)
            evaluation_context: dict[str, Any] = {}
            if instance.context.get("oid4vp_verifier_context") is True:
                evaluation_context["oid4vp_verifier_context"] = True
                # The flow repository atomically consumes the verifier nonce
                # when this transaction is finalized and rejects a distinct
                # concurrent or subsequent response. The policy service may
                # therefore pass this trusted gRPC fact to the Rust replay gate.
                evaluation_context["replay_check_verified"] = True
            mdoc_client_id = instance.context.get("oid4vp_client_id")
            mdoc_nonce = instance.context.get("nonce")
            mdoc_response_uri = instance.context.get("oid4vp_response_uri")
            if all(
                isinstance(value, str) and value
                for value in (mdoc_client_id, mdoc_nonce, mdoc_response_uri)
            ):
                response_encryption_jwk = instance.context.get(
                    "oid4vp_response_encryption_jwk"
                )
                mdoc_session_transcript = _build_openid4vp_mdoc_session_transcript(
                    client_id=mdoc_client_id,
                    nonce=mdoc_nonce,
                    response_uri=mdoc_response_uri,
                    response_encryption_jwk=response_encryption_jwk,
                )
                evaluation_context.update(
                    {
                        "mdoc_session_transcript_b64url": _base64url_encode(
                            mdoc_session_transcript
                        ),
                        "oid4vp_client_id": mdoc_client_id,
                        "oid4vp_response_uri": mdoc_response_uri,
                    }
                )
                binding_digests = _openid4vp_mdoc_binding_digests(
                    session_transcript=mdoc_session_transcript,
                    client_id=mdoc_client_id,
                    nonce=mdoc_nonce,
                    response_uri=mdoc_response_uri,
                    response_encryption_jwk=response_encryption_jwk,
                    presentation=vp_token,
                )
                logger.info(
                    "OID4VP mdoc binding "
                    "flow_instance_sha256=%s transcript_sha256=%s "
                    "client_id_sha256=%s nonce_sha256=%s "
                    "response_uri_sha256=%s response_key_thumbprint_sha256=%s "
                    "presentation_sha256=%s",
                    hashlib.sha256(instance_id.encode("utf-8")).hexdigest(),
                    binding_digests["transcript_sha256"],
                    binding_digests["client_id_sha256"],
                    binding_digests["nonce_sha256"],
                    binding_digests["response_uri_sha256"],
                    binding_digests["response_key_thumbprint_sha256"],
                    binding_digests["presentation_sha256"],
                )
            eval_resp = await pp_stub.EvaluatePresentation(
                pp_pb2.EvaluatePresentationRequest(
                    policy_id=policy_id,
                    vp_token=vp_token,
                    nonce=instance.context.get("nonce", ""),
                    audience=effective_audience,
                    trust_profile_id=instance.context.get("trust_profile_id") or "",
                    context_json=_json.dumps(
                        evaluation_context,
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                )
            )
            if eval_resp.result:
                evaluation_result = eval_resp.result
                evaluation_decision = eval_resp.decision
                decision_reason = eval_resp.decision_reason
                try:
                    decoded_credential_results = (
                        _json.loads(eval_resp.credential_results_json)
                        if eval_resp.credential_results_json
                        else []
                    )
                except (TypeError, ValueError):
                    logger.warning(
                        "Presentation-policy service returned malformed credential evidence"
                    )
                    decoded_credential_results = []
                credential_results = (
                    [
                        item
                        for item in decoded_credential_results
                        if isinstance(item, dict)
                    ]
                    if isinstance(decoded_credential_results, list)
                    else []
                )
                verified_claims = (
                    _json.loads(eval_resp.verified_claims_json)
                    if eval_resp.verified_claims_json
                    else {}
                )
                logger.info(
                    "Policy evaluation for %s: result=%s decision=%s reason=%s",
                    instance_id,
                    evaluation_result,
                    evaluation_decision,
                    decision_reason or "<none>",
                )
            else:
                logger.error(
                    "Policy evaluation returned no decision for %s; denying",
                    instance_id,
                )
                evaluation_result = "failed"
                evaluation_decision = "deny"
                decision_reason = "Policy service returned no verification decision"
                verified_claims = {}
        except Exception as exc:
            # MIP §5.7.3: trust evaluation MUST be executed — failing open is prohibited.
            logger.error(
                f"Policy service unreachable ({exc}); verification FAILED per MIP §5.7.3"
            )
            evaluation_result = "failed"
            evaluation_decision = "deny"
            decision_reason = f"Policy service unavailable: {exc}"
            verified_claims = {}
    else:
        logger.error(
            "Verification flow %s has no presentation policy; denying",
            instance_id,
        )
        evaluation_result = "failed"
        evaluation_decision = "deny"
        decision_reason = "A presentation policy is required for verification"
        verified_claims = {}

    cryptographic_response_authenticated = bool(credential_results) and all(
        credential_result.get("signature_valid") is True
        for credential_result in credential_results
    )
    if not cryptographic_response_authenticated:
        # An unauthenticated or structurally incomplete response cannot claim
        # the transaction. The wallet may retry with a valid presentation.
        return VerificationResultResponse(
            instance_id=instance.id,
            status=_protocol_status_for_instance(expected_status),
            result="failed",
            decision="deny",
            decision_reason=decision_reason,
            verified_claims={},
            evaluation_timestamp=datetime.now(timezone.utc).isoformat(),
        )

    if not isinstance(expected_nonce, str) or not expected_nonce:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": "Verification transaction has no live nonce",
            },
        )

    final_allowed = evaluation_result == "passed" and evaluation_decision == "allow"
    if not final_allowed:
        verified_claims = {}
    instance.context.pop("vp_token", None)
    instance.context.pop("vp_token_raw", None)
    instance.context.pop("presentation_submission", None)
    instance.context["vp_token_sha256"] = hashlib.sha256(
        vp_token.encode("utf-8")
    ).hexdigest()
    if raw_vp_token != vp_token:
        instance.context["vp_transport_sha256"] = hashlib.sha256(
            raw_vp_token.encode("utf-8")
        ).hexdigest()
    if parsed_submission is not None:
        instance.context["presentation_submission_sha256"] = hashlib.sha256(
            json.dumps(
                parsed_submission,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
    if state:
        instance.context["state"] = state
    if instance.status == FlowInstanceStatus.AWAITING_WALLET:
        instance.transition_to(
            FlowInstanceStatus.IN_PROGRESS,
            event="wallet_submission_received",
        )
    instance.transition_to(
        FlowInstanceStatus.COMPLETED if final_allowed else FlowInstanceStatus.FAILED,
        event="verification_completed" if final_allowed else "verification_failed",
    )
    instance.result = {
        "evaluation_result": evaluation_result,
        "decision": evaluation_decision,
        "decision_reason": decision_reason,
        "verified_claims": verified_claims,
        "submission_digest": submission_digest,
    }

    verification_result_message = MIPMessage(
        message_type=MessageType.VERIFICATION_RESULT,
        correlation_id=instance.id,
        sender_id=os.environ.get("VERIFIER_CLIENT_ID")
        or os.environ.get("PUBLIC_BASE_URL", "http://marty-gateway:8000"),
        nonce=instance.context.get("nonce"),
        payload=VerificationResultPayload(
            flow_instance_id=instance.id,
            policy_id=policy_id or "",
            overall_result=evaluation_result.upper(),
            claim_results=[
                ClaimResultPayload(
                    claim_name=str(claim_name),
                    required=False,
                    present=claim_value is not None,
                    satisfies_predicate=claim_value is not None,
                    result="PASS" if claim_value is not None else "SKIPPED",
                )
                for claim_name, claim_value in verified_claims.items()
            ],
            trust_chain_valid=evaluation_result == "passed",
            revocation_checked=bool(policy_id),
            revocation_status="VALID" if evaluation_result == "passed" else "UNKNOWN",
            evaluated_at=datetime.now(timezone.utc),
            verifier_nonce=instance.context.get("nonce", ""),
        ),
    )
    _record_mip_message(instance, "verification_result", verification_result_message)
    instance.updated_at = datetime.now(timezone.utc)

    replay_expires_at = instance.expires_at
    if replay_expires_at is None or replay_expires_at <= instance.completed_at:
        replay_expires_at = instance.completed_at + timedelta(
            seconds=_NONCE_TTL_SECONDS
        )
    callback_event: CallbackOutboxEvent | None = None
    webhook_secret = ""
    callback_url = instance.context.get("callback_url")
    if isinstance(callback_url, str) and callback_url:
        webhook_secret = _read_secret_value("FLOW_WEBHOOK_SECRET")
        if not is_valid_event_secret(webhook_secret):
            raise HTTPException(
                status_code=503,
                detail="Verification callback authentication is unavailable",
            )
        evidence_digest = payload_digest({"credential_results": credential_results})
        callback_payload = {
            "flow_instance_id": instance.id,
            "result": evaluation_result,
            "decision": evaluation_decision,
            "decision_reason": decision_reason,
            "verified_claims": verified_claims,
            "presentation_policy_id": policy_id,
            "completed_at": instance.completed_at.isoformat(),
            "evidence_digest": evidence_digest,
        }
        callback_payload["decision_digest"] = payload_digest(callback_payload)
        try:
            callback_event = new_callback_event(
                flow_instance_id=instance.id,
                organization_id=instance.organization_id,
                destination_url=callback_url,
                payload=callback_payload,
                created_at=instance.completed_at,
            )
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(
                status_code=503,
                detail="Verification callback destination is not authorized",
            ) from exc
    committed = await repo.finalize_verification(
        instance,
        nonce_digest=hashlib.sha256(expected_nonce.encode("utf-8")).hexdigest(),
        replay_expires_at=replay_expires_at,
        expected_status=expected_status,
        callback_event=callback_event,
    )
    if not committed:
        current = await repo.get_instance(instance.id)
        prior_digest = (
            (current.result or {}).get("submission_digest") if current else None
        )
        if (
            current is not None
            and current.status
            in {FlowInstanceStatus.COMPLETED, FlowInstanceStatus.FAILED}
            and isinstance(prior_digest, str)
            and hmac.compare_digest(prior_digest, submission_digest)
        ):
            return _terminal_verification_response(current)
        _raise_verification_replay_conflict()
    logger.info(
        "Completed verification flow: %s result=%s decision=%s reason=%s",
        instance_id,
        evaluation_result,
        evaluation_decision,
        decision_reason or "<none>",
    )

    if callback_event is not None:
        try:
            await deliver_due_callback_events(
                repo,
                webhook_secret=webhook_secret,
                limit=1,
            )
        except Exception:
            # The callback was committed transactionally and the background
            # dispatcher will reclaim it after this request or process fails.
            logger.exception(
                "Immediate callback delivery failed for flow %s; event remains durable",
                instance.id,
            )

    return VerificationResultResponse(
        instance_id=instance.id,
        status=_protocol_status_for_instance(instance.status),
        result=evaluation_result,
        decision=evaluation_decision,
        decision_reason=decision_reason,
        verified_claims=verified_claims,
        evaluation_timestamp=datetime.now(timezone.utc).isoformat(),
    )


async def submit_verification_response(
    instance_id: str,
    vp_token: str | None = Form(None),
    presentation_submission: str = Form(None),
    state: str = Form(None),
    repo: InMemoryFlowRepository = Depends(get_repo),
    response: str | None = Form(None),
) -> VerificationResultResponse:
    """
    Submit a VP token to complete a verification flow.

    This is called by the wallet (via direct_post) or by the relying party
    after receiving the VP token from the wallet.

    Accepts form-encoded ``vp_token`` direct-post responses and encrypted
    ``response`` values for HAIP ``direct_post.jwt`` responses.
    """
    encrypted_response = response if isinstance(response, str) else None
    if bool(vp_token) == bool(encrypted_response):
        raise HTTPException(
            status_code=400, detail="exactly one of vp_token or response is required"
        )
    if encrypted_response:
        instance = await repo.get_instance(instance_id)
        if not instance:
            raise HTTPException(status_code=404, detail="Flow instance not found")
        _validate_encrypted_response_header(
            encrypted_response,
            field_name="direct_post.jwt response",
        )
        private_jwk = await _unwrap_flow_private_jwk(instance)
        decrypted = _decrypt_jwt_response(
            encrypted_response,
            private_jwk,
            field_name="direct_post.jwt response",
        )
        vp_value = decrypted.get("vp_token")
        if vp_value is None:
            raise HTTPException(
                status_code=400,
                detail="decrypted direct_post.jwt response has no vp_token",
            )
        vp_token = vp_value if isinstance(vp_value, str) else json.dumps(vp_value)
        presentation_submission = decrypted.get(
            "presentation_submission", presentation_submission
        )
        state = decrypted.get("state", state)
    return await _submit_verification_response_internal(
        instance_id=instance_id,
        vp_token=vp_token or "",
        presentation_submission=presentation_submission,
        state=state,
        repo=repo,
    )


@router.post("/instances/{instance_id}/submit", response_model=None)
async def submit_oid4vp_direct_post_response(
    instance_id: str,
    vp_token: str | None = Form(None),
    presentation_submission: str = Form(None),
    state: str = Form(None),
    repo: InMemoryFlowRepository = Depends(get_repo),
    response: str | None = Form(None),
) -> JSONResponse:
    """Process a wallet direct-post and return the OID4VP response envelope.

    Flow state and the detailed verification decision remain available through
    the result endpoint. OID4VP §8.2 permits an empty JSON object here; it
    prevents internal decision data from becoming a wallet callback contract.
    """
    result = await submit_verification_response(
        instance_id,
        vp_token,
        presentation_submission,
        state,
        repo,
        response,
    )
    if result.decision != "allow" or result.result != "passed":
        # A wallet needs an HTTP failure for a rejected VP. The detailed
        # decision remains at the authenticated result endpoint, rather than
        # being exposed in the protocol callback response.
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_presentation",
                "error_description": "presentation verification failed",
            },
        )

    # HAIP 1.0 §5.1 requires a successful direct_post.jwt response to give the
    # wallet a URI to which it can return control.  Standard OID4VP direct-post
    # deliberately retains the empty object defined by §8.2, so do not turn a
    # wallet callback into an application-result contract outside HAIP.
    instance = await repo.get_instance(instance_id)
    if instance and instance.context.get("oid4vp_profile") == "haip":
        base_url = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
        if not base_url.startswith("https://"):
            logger.error("HAIP flow %s has no public HTTPS base URL", instance_id)
            raise HTTPException(
                status_code=500, detail="HAIP redirect URI is not configured"
            )
        return JSONResponse(
            content={"redirect_uri": f"{base_url}/v1/flows/instances/{instance.id}"}
        )
    return JSONResponse(content={})


@router.post(
    "/instances/{instance_id}/submit/dc-api",
    response_model=VerificationResultResponse,
    response_model_exclude_none=True,
)
async def submit_digital_credential_response(
    instance_id: str,
    credential: DigitalCredentialSubmissionRequest,
    request: Request = None,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> VerificationResultResponse:
    """Submit a browser-mediated Digital Credentials API response."""
    protocol = credential.protocol or _DC_API_PROTOCOL
    if protocol != _DC_API_PROTOCOL:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported Digital Credentials protocol: {protocol}",
        )

    response_data = credential.data or {}
    if not isinstance(response_data, dict):
        raise HTTPException(
            status_code=400, detail="DigitalCredential.data must be an object"
        )

    response_mode = None
    if "response" in response_data:
        _validate_encrypted_response_header(
            response_data["response"],
            field_name="dc_api.jwt",
        )
        instance = await repo.get_instance(instance_id)
        if not instance:
            raise HTTPException(status_code=404, detail="Flow instance not found")
        private_jwk = await _unwrap_flow_private_jwk(instance)
        response_data = _decrypt_dc_api_jwt_response(
            response_data["response"],
            private_jwk,
        )
        response_mode = _DC_API_JWT_RESPONSE_MODE

    if response_data.get("error"):
        raise HTTPException(
            status_code=400,
            detail={
                "error": response_data["error"],
                "error_description": "Wallet returned an OpenID4VP error",
            },
        )

    vp_token_value = response_data.get("vp_token")
    if vp_token_value is None:
        raise HTTPException(
            status_code=400, detail="DigitalCredential.data.vp_token is required"
        )

    vp_token = (
        vp_token_value
        if isinstance(vp_token_value, str)
        else json.dumps(vp_token_value)
    )
    presentation_submission = response_data.get("presentation_submission")

    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow instance not found")

    origin = (
        credential.origin or (request.headers.get("origin") if request else "") or ""
    ).rstrip("/")
    expected_origins = [
        str(value).rstrip("/")
        for value in instance.context.get("dc_api_expected_origins", [])
        if value
    ]
    if not origin:
        if len(expected_origins) == 1:
            origin = expected_origins[0]
        else:
            raise HTTPException(
                status_code=400,
                detail="Verifier origin is required for dc_api submissions",
            )

    if expected_origins and origin not in expected_origins:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_request",
                "error_description": "Origin does not match expected_origins",
            },
        )

    instance.context["dc_api_last_origin"] = origin
    if response_mode:
        instance.context["dc_api_last_response_mode"] = response_mode
    await repo.save_instance(instance)

    return await _submit_verification_response_internal(
        instance_id=instance_id,
        vp_token=vp_token,
        presentation_submission=presentation_submission,
        state=None,
        repo=repo,
        verification_audience=_verification_audience_for_origin(origin),
    )


# =============================================================================
# Webhook Endpoints (Event-Driven Flow Triggering)
# =============================================================================


class ApplicationApprovedWebhook(BaseModel):
    """Webhook payload for application approved event."""

    model_config = ConfigDict(extra="forbid")

    event_type: Literal["application.approved"]
    aggregate_id: str = Field(min_length=1, max_length=255)
    aggregate_type: Literal["application"]
    organization_id: str = Field(min_length=1, max_length=255)
    data: dict[str, Any]
    timestamp: str = Field(min_length=1, max_length=64)


@router.post("/siop")
async def start_siop_flow(
    request: StartSiopFlowRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> dict:
    """SIOPv2 Draft 13 §9: Initiate a cross-device SIOPv2 authentication flow.

    Returns an openid:// URI (for QR code presentation) that a wallet can
    scan to authenticate with a self-issued ID token.
    """
    import secrets
    from datetime import timedelta

    nonce = secrets.token_urlsafe(32)
    flow_definition_id = str(uuid.uuid4())
    instance = FlowInstance(
        flow_definition_id=flow_definition_id,
        organization_id=request.organization_id or "__unknown__",
        status=FlowInstanceStatus.AWAITING_WALLET,
        context={
            "flow_definition_reference": "__siop_v2__",
            "nonce": nonce,
            "flow_type": "siop_v2",
            "protocol_flow_type": FlowType.SIOPV2.value,
            "current_step_name": "create_request",
            "current_step_index": 0,
            "step_results": {},
            "response_type": "id_token",
        },
        started_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc)
        + timedelta(minutes=request.expiry_minutes),
    )
    base_url = os.environ.get("PUBLIC_BASE_URL", "http://marty-gateway:8000")
    client_id = os.environ.get("VERIFIER_CLIENT_ID", f"{base_url}/verifier")
    redirect_uri = f"{base_url}/v1/flows/siop/submit"
    # SIOPv2 §9: the request_uri parameter allows the wallet to fetch a signed
    # request object; the openid:// scheme triggers wallet deep link handling.
    request_uri = f"{base_url}/v1/flows/instances/{instance.id}/request"
    siop_uri = (
        f"openid://authorize"
        f"?response_type=id_token"
        f"&scope=openid"
        f"&client_id={urllib.parse.quote(client_id)}"
        f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
        f"&nonce={nonce}"
        f"&state={instance.id}"
        f"&request_uri={urllib.parse.quote(request_uri)}"
    )
    instance.context["request_uri"] = request_uri
    instance.context["siop_uri"] = siop_uri
    instance.context["siop_client_id"] = client_id
    await repo.save_instance(instance)
    logger.info(f"Started SIOPv2 cross-device flow: {instance.id}")
    return {
        "instance_id": instance.id,
        "request_uri": siop_uri,
        "siop_uri": siop_uri,
        "nonce": nonce,
        "expires_at": instance.expires_at.isoformat() if instance.expires_at else "",
    }


def _siop_error(description: str, *, error: str = "invalid_id_token") -> HTTPException:
    return HTTPException(
        status_code=400,
        detail={"error": error, "error_description": description},
    )


def _decode_siop_jwt_object(segment: str, label: str) -> dict[str, Any]:
    if not segment or not re.fullmatch(r"[A-Za-z0-9_-]+", segment):
        raise ValueError(f"Invalid {label} encoding")
    padded = segment + "=" * (-len(segment) % 4)
    decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    value = json.loads(decoded)
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _verify_siop_jwk_id_token(id_token: str) -> tuple[dict[str, Any], str]:
    """Verify a draft-13 JWK-thumbprint SIOPv2 ID token.

    DID subject syntax is deliberately not accepted until the verifier has a
    governed DID resolver that can select the header ``kid`` from the resolved
    authentication methods.
    """
    parts = id_token.split(".")
    if len(parts) != 3 or not parts[2]:
        raise _siop_error("ID token must be a signed compact JWS")

    try:
        header = _decode_siop_jwt_object(parts[0], "JOSE header")
        unverified_claims = _decode_siop_jwt_object(parts[1], "JWT claims")
    except (ValueError, json.JSONDecodeError) as exc:
        raise _siop_error(f"Malformed ID token: {exc}") from exc

    alg = header.get("alg")
    if alg not in _SIOP_ID_TOKEN_ALGS:
        raise _siop_error("ID token signing algorithm is not supported")

    subject = unverified_claims.get("sub")
    if not isinstance(subject, str) or not subject.startswith(
        f"{_SIOP_JWK_SUBJECT_PREFIX}:"
    ):
        raise _siop_error(
            "Only JWK-thumbprint SIOPv2 subjects are currently supported",
            error="subject_syntax_types_not_supported",
        )

    sub_jwk = unverified_claims.get("sub_jwk")
    if not isinstance(sub_jwk, dict):
        raise _siop_error("JWK-thumbprint subject requires a sub_jwk public key")
    private_members = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
    if private_members.intersection(sub_jwk):
        raise _siop_error("sub_jwk must contain public key material only")

    expected_key_shape = {
        "ES256": ("EC", "P-256"),
        "EdDSA": ("OKP", "Ed25519"),
    }[alg]
    if (sub_jwk.get("kty"), sub_jwk.get("crv")) != expected_key_shape:
        raise _siop_error("sub_jwk key type does not match the signing algorithm")
    if sub_jwk.get("alg") not in (None, alg):
        raise _siop_error("sub_jwk algorithm does not match the JOSE header")
    if sub_jwk.get("use") not in (None, "sig"):
        raise _siop_error("sub_jwk is not authorized for signatures")
    key_ops = sub_jwk.get("key_ops")
    if key_ops is not None and (
        not isinstance(key_ops, list) or "verify" not in key_ops
    ):
        raise _siop_error("sub_jwk is not authorized for verification")

    try:
        verification_key = jwk.JWK.from_json(json.dumps(sub_jwk))
        verified_token = jwcrypto_jwt.JWT(
            jwt=id_token,
            key=verification_key,
            algs=[alg],
            check_claims={},
        )
        claims = json.loads(verified_token.claims)
    except Exception as exc:
        logger.info(
            "SIOPv2 ID token signature validation failed: %s", type(exc).__name__
        )
        raise _siop_error("ID token signature validation failed") from exc

    if not isinstance(claims, dict):
        raise _siop_error("ID token claims must be a JSON object")

    thumbprint = verification_key.thumbprint()
    expected_subject = f"{_SIOP_JWK_SUBJECT_PREFIX}:sha-256:{thumbprint}"
    if not hmac.compare_digest(subject, expected_subject):
        raise _siop_error("sub is not bound to the sub_jwk thumbprint")

    return claims, alg


def _terminal_siop_response(instance: FlowInstance) -> dict[str, Any]:
    result = instance.result or {}
    return {
        "status": "verified",
        "sub": result.get("subject"),
        "nonce": instance.context.get("nonce"),
        "subject_syntax_type": result.get("subject_syntax_type")
        or _SIOP_JWK_SUBJECT_PREFIX,
    }


@router.post("/siop/submit")
async def submit_siop_id_token(
    body: SiopSubmitRequest,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> dict:
    """Validate a cross-device SIOPv2 draft-13 self-issued ID token."""
    instance = await repo.get_instance(body.instance_id)
    if not instance:
        raise _siop_error("Flow instance not found", error="invalid_request")
    submission_digest = hashlib.sha256(
        json.dumps(
            {"id_token": body.id_token},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    if instance.status in {
        FlowInstanceStatus.COMPLETED,
        FlowInstanceStatus.FAILED,
    }:
        prior_digest = (instance.result or {}).get("submission_digest")
        if isinstance(prior_digest, str) and hmac.compare_digest(
            prior_digest, submission_digest
        ):
            return _terminal_siop_response(instance)
        _raise_verification_replay_conflict()
    if instance.context.get("flow_type") != "siop_v2":
        raise _siop_error(
            "Flow instance is not a SIOPv2 transaction", error="invalid_request"
        )
    if instance.expires_at and datetime.now(timezone.utc) > instance.expires_at:
        instance.transition_to(FlowInstanceStatus.EXPIRED, event="siop_submission_expired")
        await repo.save_instance(instance)
        raise HTTPException(status_code=410, detail="SIOPv2 transaction has expired")
    if instance.status not in {
        FlowInstanceStatus.AWAITING_WALLET,
        FlowInstanceStatus.IN_PROGRESS,
    }:
        raise _siop_error(
            "SIOPv2 response is not accepted in the current state",
            error="invalid_request",
        )
    expected_status = instance.status
    instance = copy.deepcopy(instance)

    expected_nonce = instance.context.get("nonce")
    expected_audience = instance.context.get("siop_client_id")
    if not isinstance(expected_nonce, str) or not expected_nonce:
        raise _siop_error(
            "SIOPv2 transaction has no verifier nonce", error="invalid_request"
        )
    if not isinstance(expected_audience, str) or not expected_audience:
        raise _siop_error(
            "SIOPv2 transaction has no verifier audience", error="invalid_request"
        )

    claims, alg = _verify_siop_jwk_id_token(body.id_token)
    subject = claims.get("sub")
    issuer = claims.get("iss")
    nonce = claims.get("nonce")

    if not isinstance(issuer, str) or not isinstance(subject, str) or issuer != subject:
        raise _siop_error("Self-issued ID token requires iss to equal sub")

    audience = claims.get("aud")
    audience_matches = audience == expected_audience or (
        isinstance(audience, list) and expected_audience in audience
    )
    if not audience_matches:
        raise _siop_error("ID token audience does not match the SIOPv2 request")
    if not isinstance(nonce, str) or not hmac.compare_digest(nonce, expected_nonce):
        raise _siop_error("ID token nonce does not match the SIOPv2 request")

    now = int(datetime.now(timezone.utc).timestamp())
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, (int, float))
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, (int, float))
    ):
        raise _siop_error("ID token requires numeric iat and exp claims")
    if issued_at > now + _SIOP_CLOCK_SKEW_SECONDS:
        raise _siop_error("ID token iat is in the future")
    if expires_at <= now - _SIOP_CLOCK_SKEW_SECONDS:
        raise _siop_error("ID token has expired")
    if issued_at >= expires_at:
        raise _siop_error("ID token validity window is invalid")
    if instance.started_at:
        earliest_iat = int(instance.started_at.timestamp()) - _SIOP_CLOCK_SKEW_SECONDS
        if issued_at < earliest_iat:
            raise _siop_error("ID token predates the SIOPv2 transaction")

    if instance.status == FlowInstanceStatus.AWAITING_WALLET:
        instance.transition_to(
            FlowInstanceStatus.IN_PROGRESS,
            event="siop_submission_received",
        )
    instance.transition_to(
        FlowInstanceStatus.COMPLETED,
        event="siop_verification_completed",
    )
    instance.subject_id = subject
    instance.completed_at = datetime.now(timezone.utc)
    instance.updated_at = instance.completed_at
    instance.result = {
        "evaluation_result": "passed",
        "decision": "allow",
        "subject": subject,
        "subject_syntax_type": _SIOP_JWK_SUBJECT_PREFIX,
        "signing_algorithm": alg,
        "claims_trust": "self_attested",
        "submission_digest": submission_digest,
    }
    replay_expires_at = instance.expires_at
    if replay_expires_at is None or replay_expires_at <= instance.completed_at:
        replay_expires_at = instance.completed_at + timedelta(
            seconds=_NONCE_TTL_SECONDS
        )
    committed = await repo.finalize_verification(
        instance,
        nonce_digest=hashlib.sha256(expected_nonce.encode("utf-8")).hexdigest(),
        replay_expires_at=replay_expires_at,
        expected_status=expected_status,
    )
    if not committed:
        current = await repo.get_instance(instance.id)
        prior_digest = (
            (current.result or {}).get("submission_digest") if current else None
        )
        if (
            current is not None
            and current.status is FlowInstanceStatus.COMPLETED
            and isinstance(prior_digest, str)
            and hmac.compare_digest(prior_digest, submission_digest)
        ):
            return _terminal_siop_response(current)
        _raise_verification_replay_conflict()

    subject_digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()
    logger.info(
        "SIOPv2 ID token validated for subject_sha256=%s instance=%s",
        subject_digest,
        instance.id,
    )
    return {
        "status": "verified",
        "sub": subject,
        "nonce": nonce,
        "subject_syntax_type": _SIOP_JWK_SUBJECT_PREFIX,
    }


async def _authenticate_application_approved_event(
    event: ApplicationApprovedWebhook | dict[str, Any],
    metadata: dict[str, str],
) -> ApplicationEventEvidence:
    """Verify an approval event before its durable execution plan is reserved."""
    payload = (
        event.model_dump(mode="json")
        if isinstance(event, ApplicationApprovedWebhook)
        else dict(event)
    )
    return await authenticate_application_event(
        payload,
        metadata,
        replay_store=_nonce_redis,
        consume_replay=False,
    )


class ApplicationOfferConflictError(RuntimeError):
    """One application/flow identity was reused with different offer semantics."""


@router.post("/webhooks/application-approved")
async def receive_application_approved(
    event: ApplicationApprovedWebhook,
    request: Request,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> dict:
    """Authenticate the Applicant workload before invoking issuance logic."""
    try:
        evidence = await _authenticate_application_approved_event(
            event,
            dict(request.headers),
        )
        return await handle_application_approved(
            event=event,
            repo=repo,
            auth_evidence=evidence,
            enforce_replay=True,
        )
    except ApplicationEventAuthError as exc:
        status_code = 401
        if exc.code == "replayed_event":
            status_code = 409
        elif exc.code in {"configuration_error", "replay_store_unavailable"}:
            status_code = 503
        raise HTTPException(
            status_code=status_code,
            detail={"error": exc.code, "message": str(exc)},
        ) from exc
    except ApplicationOfferConflictError as exc:
        raise HTTPException(
            status_code=409,
            detail={"error": "APPLICATION_OFFER_CONFLICT", "message": str(exc)},
        ) from exc


async def handle_application_approved(
    event: ApplicationApprovedWebhook,
    repo: InMemoryFlowRepository,
    auth_evidence: ApplicationEventEvidence,
    enforce_replay: bool = False,
) -> dict:
    """
    Handle APPLICATION_APPROVED event from applicant service.

    Starts active custom issuance flows that explicitly bind this webhook event.
    """
    logger.info(
        f"Received APPLICATION_APPROVED event for applicant {event.aggregate_id} "
        f"in org {event.organization_id}"
    )

    applicant_id = event.data.get("applicant_id")
    if not applicant_id:
        logger.warning("No applicant_id in event data")
        return {"success": False, "error": "Missing applicant_id"}

    requested_template_id = (
        str(event.data.get("credential_template_id") or "").strip() or None
    )
    triggered_by_event = str(event.data.get("triggered_by_event") or "").strip()

    # Find active OID4VCI flows explicitly configured for application-approved
    # issuance. If the caller provides credential_template_id, only matching
    # flows are eligible so manual issuance can target the correct template
    # pipeline.
    all_flows = await repo.list_definitions(event.organization_id)

    def handles_application_approved(flow: FlowDefinition) -> bool:
        return (
            flow.status == FlowStatus.ACTIVE
            and _is_application_approved_issuance_trigger(flow)
        )

    matching_flows = sorted(
        (
            flow
            for flow in all_flows
            if handles_application_approved(flow)
            and (
                not requested_template_id
                or str(flow.credential_template_id or "").strip()
                == requested_template_id
            )
        ),
        key=lambda flow: flow.id,
    )

    raw_event_claims = event.data.get("claims")
    if raw_event_claims is not None and not isinstance(raw_event_claims, dict):
        raise ApplicationOfferConflictError("application claims must be a JSON object")
    event_claims = dict(raw_event_claims or {})
    logger.info("[auto-trigger] event claim keys=%s", list(event_claims.keys()))

    def logical_key(flow_def: FlowDefinition) -> str:
        material = json.dumps(
            [event.organization_id, event.aggregate_id, flow_def.id],
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(
            f"marty:application-flow-offer:v1:{material}".encode()
        ).hexdigest()

    def semantics_hash(flow_def: FlowDefinition) -> str:
        def enum_value(value: Any) -> Any:
            return value.value if isinstance(value, Enum) else value

        semantics = json.dumps(
            {
                "application_id": event.aggregate_id,
                "organization_id": flow_def.organization_id,
                "flow_definition_id": flow_def.id,
                "flow_definition_name": flow_def.name,
                "flow_definition_description": flow_def.description,
                "flow_definition_version": flow_def.version,
                "flow_status": enum_value(flow_def.status),
                "flow_type": enum_value(flow_def.flow_type),
                "flow_extension": flow_def.extension or {},
                "steps": [
                    {
                        "id": step.id,
                        "name": step.name,
                        "description": step.description,
                        "step_type": enum_value(step.step_type),
                        "config": step.config,
                        "approval_strategy": step.approval_strategy,
                        "timeout_seconds": step.timeout_seconds,
                        "conditions": step.conditions,
                    }
                    for step in flow_def.steps
                ],
                "transitions": [
                    {
                        "id": transition.id,
                        "from_step_id": transition.from_step_id,
                        "to_step_id": transition.to_step_id,
                        "condition": enum_value(transition.condition),
                        "condition_expression": transition.condition_expression,
                    }
                    for transition in flow_def.transitions
                ],
                "start_step_id": flow_def.start_step_id,
                "preconditions": flow_def.preconditions,
                "credential_template_id": flow_def.credential_template_id,
                "application_template_id": flow_def.application_template_id,
                "presentation_policy_id": flow_def.presentation_policy_id,
                "delivery_destination_profile_id": (
                    flow_def.delivery_destination_profile_id
                ),
                "deployment_profile_id": flow_def.deployment_profile_id,
                "deployment_profile_ids": flow_def.deployment_profile_ids,
                "trust_profile_id": flow_def.trust_profile_id,
                "approval_strategy": flow_def.approval_strategy,
                "hooks": flow_def.hooks,
                "trigger": flow_def.trigger,
                "default_timeout_seconds": flow_def.default_timeout_seconds,
                "max_retries": flow_def.max_retries,
                "retry_cooldown_minutes": flow_def.retry_cooldown_minutes,
                "enable_resume": flow_def.enable_resume,
                "applicant_id": applicant_id,
                "claims": event_claims,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return hashlib.sha256(
            f"marty:application-offer-semantics:v1:{semantics}".encode()
        ).hexdigest()

    from datetime import timedelta

    planned_instances: list[tuple[FlowInstance, dict[str, str]]] = []
    for flow_def in matching_flows:
        application_flow_key_hash = logical_key(flow_def)
        offer_semantics_hash = semantics_hash(flow_def)
        initial_context = {
            "applicant_id": applicant_id,
            "application_id": event.aggregate_id or "",
            "application_status": "approved",
            "application_approved_at": event.timestamp,
            "applicant_email": event.data.get("email"),
            "applicant_given_name": event.data.get("given_name"),
            "applicant_family_name": event.data.get("family_name"),
            "vetting_level": event.data.get("vetting_level"),
            "triggered_by_event": triggered_by_event or "application.approved",
            "claims": event_claims,
            _PRECONDITION_EVIDENCE_KEY: {
                "application_approved": auth_evidence.as_dict(),
            },
            "_marty_application_offer_semantics_hash_v1": offer_semantics_hash,
        }
        instance = FlowInstance(
            flow_definition_id=flow_def.id,
            organization_id=flow_def.organization_id,
            status=FlowInstanceStatus.IN_PROGRESS,
            current_step_id=flow_def.start_step_id,
            context=initial_context,
            subject_id=applicant_id,
            subject_type="applicant",
            external_reference=f"application-flow:{application_flow_key_hash}",
            application_flow_key_hash=application_flow_key_hash,
            started_at=datetime.now(timezone.utc),
        )
        _sync_protocol_context(instance, flow_def)
        instance.expires_at = instance.started_at + timedelta(
            seconds=flow_def.default_timeout_seconds
        )
        if flow_def.start_step_id:
            instance.step_history.append(
                {
                    "step_id": flow_def.start_step_id,
                    "entered_at": datetime.now(timezone.utc).isoformat(),
                    "status": "entered",
                }
            )
        planned_instances.append(
            (
                instance,
                {
                    "flow_definition_id": flow_def.id,
                    "application_flow_key_hash": application_flow_key_hash,
                    "offer_semantics_hash": offer_semantics_hash,
                    "flow_definition_version": str(flow_def.version),
                },
            )
        )

    receipt, _receipt_created = await repo.reserve_application_event_plan(
        ApplicationEventPlanReceipt(
            event_id_sha256=auth_evidence.event_id_sha256,
            payload_sha256=auth_evidence.payload_sha256,
            organization_id=event.organization_id,
            application_id=event.aggregate_id,
        ),
        planned_instances,
    )

    if enforce_replay:
        was_new = await consume_application_event_replay(
            auth_evidence,
            replay_store=_nonce_redis,
        )
        if not was_new and not receipt.flow_plan:
            raise ApplicationEventAuthError(
                "replayed_event",
                "application event was already consumed",
                evidence=auth_evidence,
            )

    if not receipt.flow_plan:
        detail = (
            "No active custom OID4VCI extension handling APPLICATION_APPROVED "
            f"matched org {event.organization_id}"
        )
        if requested_template_id:
            detail = f"{detail} and credential template {requested_template_id}"
        logger.info(detail)
        return {
            "success": triggered_by_event != "application.manual_issue",
            "flows_triggered": 0,
            "reason": detail,
        }

    flow_by_id = {flow.id: flow for flow in all_flows}
    triggered_instances: list[str] = []
    offers: list[dict[str, Any]] = []
    failed_flow_ids: list[str] = []
    for plan_entry in receipt.flow_plan:
        flow_def = flow_by_id.get(plan_entry["flow_definition_id"])
        if (
            flow_def is None
            or semantics_hash(flow_def) != plan_entry["offer_semantics_hash"]
        ):
            raise ApplicationOfferConflictError(
                "the durably selected application flow is unavailable or has changed"
            )
        instance = await repo.get_instance(plan_entry["instance_id"])
        if instance is None:
            raise RuntimeError(
                "durable application event plan references a missing instance"
            )
        try:
            artifact = None
            if _effective_flow_type(flow_def) == FlowType.OID4VCI_PRE_AUTHORIZED:
                artifact = await _create_oid4vci_artifact(instance, flow_def, repo)
                if artifact:
                    logger.info("Created OID4VCI artifact: %s", artifact.id)

            triggered_instances.append(instance.id)
            if artifact:
                offers.append(
                    {
                        "flow_definition_id": flow_def.id,
                        "flow_definition_name": flow_def.name,
                        "flow_instance_id": instance.id,
                        "artifact_id": artifact.id,
                        "credential_offer_transaction_id": instance.context.get(
                            "credential_offer_transaction_id"
                        ),
                        "credential_offer_uri": artifact.credential_offer_uri,
                        "credential_offer_uris": instance.context.get(
                            "credential_offer_uris"
                        )
                        or {},
                        "credential_offer_labels": instance.context.get(
                            "credential_offer_labels"
                        )
                        or {},
                        "pre_authorized_code": artifact.pre_authorized_code,
                        "expires_at": artifact.expires_at.isoformat()
                        if artifact.expires_at
                        else None,
                        "issuance_status": instance.context.get("issuance_status")
                        or "pending",
                    }
                )
            logger.info(
                "Auto-triggered flow %s (%s) for applicant %s: instance %s",
                flow_def.id,
                flow_def.name,
                applicant_id,
                instance.id,
            )
        except ApplicationOfferConflictError:
            raise
        except Exception as exc:
            failed_flow_ids.append(flow_def.id)
            logger.error(
                "Failed to trigger flow %s for applicant %s: %s",
                flow_def.id,
                applicant_id,
                exc,
            )

    return {
        "success": not failed_flow_ids,
        "flows_triggered": len(triggered_instances),
        "instance_ids": triggered_instances,
        "offers": offers,
        **({"failed_flow_ids": failed_flow_ids} if failed_flow_ids else {}),
    }


# =============================================================================
# Application Setup
# =============================================================================


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo, _nonce_redis
    logger.info(f"Starting {SERVICE_NAME}...")
    native_diagnostics = initialize_native_flow_backend()
    app.state.native_backend_diagnostics = native_diagnostics
    logger.info(
        "Native backend ready: backend=%s version=%s capabilities=%s",
        native_diagnostics["backend"],
        native_diagnostics["version"],
        ",".join(native_diagnostics["capabilities"]),
    )
    oid4vp_diagnostics = initialize_native_oid4vp_backend()
    app.state.oid4vp_native_backend_diagnostics = oid4vp_diagnostics
    logger.info(
        "Native OID4VP builder ready: backend=%s version=%s capabilities=%s",
        oid4vp_diagnostics["backend"],
        oid4vp_diagnostics["version"],
        ",".join(oid4vp_diagnostics["capabilities"]),
    )
    callback_secret = _read_secret_value("FLOW_WEBHOOK_SECRET")
    if (
        not is_valid_event_secret(callback_secret)
        and os.environ.get("ENVIRONMENT", "production").lower() == "production"
    ):
        raise RuntimeError(
            "FLOW_WEBHOOK_SECRET must contain at least 32 bytes in production"
        )
    validate_application_event_configuration()

    # Initialize Redis for nonce replay prevention (shared across replicas)
    import redis.asyncio as aioredis

    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
    redis_db = int(os.environ.get("REDIS_DB_FLOW", "3"))
    try:
        _nonce_redis = aioredis.from_url(
            f"{redis_url}/{redis_db}", encoding="utf-8", decode_responses=True
        )
        await _nonce_redis.ping()
        logger.info("Flow nonce store: Redis at %s/%s", redis_url, redis_db)
    except Exception as exc:
        logger.warning("Redis unavailable (%s) — using process-local nonce store", exc)
        _nonce_redis = None

    # Initialize PostgreSQL adapter
    config = get_config()
    engine = create_async_engine(
        config["database_url"],
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        echo=False,
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    _repo = PostgresFlowRepository(session_factory)
    logger.info("PostgreSQL adapter initialized for flow service")

    callback_stop = asyncio.Event()
    callback_task: asyncio.Task[None] | None = None
    if is_valid_event_secret(callback_secret):
        callback_task = asyncio.create_task(
            run_callback_dispatcher(
                _repo,
                secret_provider=lambda: _read_secret_value("FLOW_WEBHOOK_SECRET"),
                stop_event=callback_stop,
            ),
            name="verification-callback-dispatcher",
        )
    else:
        logger.warning(
            "Verification callback dispatcher is disabled without a 32-byte secret"
        )

    # Initialize gRPC channel to organization service
    from common.di import setup_org_client, teardown_org_client

    await setup_org_client(app, "flow")

    # gRPC channels to downstream services
    from common.grpc_factory import (
        create_grpc_server,
        start_grpc_server_port,
    )

    pp_grpc_target = os.environ.get("PP_GRPC_TARGET", "presentation-policy:9009")
    pp_grpc_channel = create_grpc_channel(
        pp_grpc_target,
        service_name="flow",
        require_workload_identity=True,
    )
    app.state.pp_grpc_channel = pp_grpc_channel

    ct_grpc_target = os.environ.get("CT_GRPC_TARGET", "credential-template:9003")
    ct_grpc_channel = create_grpc_channel(ct_grpc_target, service_name="flow")
    app.state.ct_grpc_channel = ct_grpc_channel

    issuance_grpc_channel = create_grpc_channel(
        ISSUANCE_GRPC_TARGET, service_name="flow"
    )
    app.state.issuance_grpc_channel = issuance_grpc_channel

    # Start gRPC server
    from flow.infrastructure.adapters.grpc_adapter import FlowServiceGrpc
    from marty_proto.v1.flow_service_pb2_grpc import (
        add_FlowServiceServicer_to_server,
    )

    grpc_port = int(os.environ.get("FLOW_GRPC_PORT", "9011"))
    grpc_server, health_servicer = create_grpc_server("flow")
    flow_servicer = FlowServiceGrpc(
        start_verification_fn=start_verification_flow,
        application_approved_fn=handle_application_approved,
        authenticate_application_approved_fn=_authenticate_application_approved_event,
        get_repo_fn=get_repo,
    )
    add_FlowServiceServicer_to_server(flow_servicer, grpc_server)
    start_grpc_server_port(
        grpc_server,
        grpc_port,
        service_names=["marty.ui.flow.v1.FlowService"],
        health_servicer=health_servicer,
    )
    await grpc_server.start()
    logger.info(f"Flow gRPC server listening on :{grpc_port}")

    yield

    logger.info(f"Shutting down {SERVICE_NAME}...")
    if callback_task is not None:
        callback_stop.set()
        await callback_task
    await grpc_server.stop(grace=5)
    await pp_grpc_channel.close()
    await ct_grpc_channel.close()
    await issuance_grpc_channel.close()
    await teardown_org_client(app)
    await engine.dispose()


def create_app() -> FastAPI:
    app = create_service_app(
        title="Flow Service",
        description="""Manages Flows - orchestration of credential operations.

## Verification Flows

For async wallet-based verification (QR codes, deep links):

- `POST /v1/flows/verify` - Start verification flow, returns request_uri and QR code
- `GET /v1/flows/instances/{id}/request` - OID4VP request object (wallet fetches this)
- `POST /v1/flows/instances/{id}/submit` - Submit VP token to complete verification

## Flow Definitions

For orchestrating multi-step credential journeys (issuance, renewal, revocation).
        """,
        service_name=SERVICE_NAME,
        lifespan=lifespan,
        routers=[router, did_router],
    )

    @app.get("/health/native-backend")
    async def native_backend_health() -> dict[str, Any]:
        diagnostics = getattr(app.state, "native_backend_diagnostics", None)
        if not isinstance(diagnostics, dict) or diagnostics.get("available") is not True:
            raise HTTPException(status_code=503, detail="Native backend is unavailable")
        return {"status": "ready", **diagnostics}

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # OID4VP §6.4 / RFC 9126 §2.2: missing or malformed request parameters
        # must return HTTP 400 with error=invalid_request, not FastAPI's default 422.
        errors = exc.errors()
        missing = [e["loc"][-1] for e in errors if e.get("type") == "missing"]
        description = (
            f"Missing required parameter(s): {', '.join(str(m) for m in missing)}"
            if missing
            else str(errors)
        )
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_request",
                "error_description": description,
            },
        )

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
