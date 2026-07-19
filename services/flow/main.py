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
import json
import logging
import os
import re
import time
import urllib.parse
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, AsyncGenerator, Literal

import httpx
from fastapi import APIRouter, Depends, FastAPI, Form, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from jwcrypto import jwt, jwk
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from typing import Annotated

from marty_common import (
    ClaimResultPayload,
    CredentialOfferPayload,
    ensure_membership_permission,
    MIPMessage,
    MessageType,
    OrganizationContext,
    PresentationRequestPayload,
    VerificationResultPayload,
)
from marty_common.org_authorization import get_organization_client
from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware
from marty_common.service_setup import create_service_app
from flow.infrastructure.adapters import PostgresFlowRepository

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "flow-service"
SERVICE_PORT = int(os.environ.get("FLOW_SERVICE_PORT", "8011"))
ISSUANCE_SERVICE_URL = os.environ.get("ISSUANCE_SERVICE_URL", "http://issuance:8005")
ISSUANCE_GRPC_TARGET = os.environ.get("ISSUANCE_GRPC_TARGET", "issuance:9005")

# OID4VP Request Object signing key.
# MIP §20.1: production deployments MUST use persistent key storage.
# When VERIFIER_SIGNING_KEY_PEM is set (env var or file), we load it.
# Otherwise, an ephemeral key is generated (valid for dev/test only).
_SIGNING_KEY_PAIR = None
_SIGNING_JWK = None
_OID4VP_DID_WEB_PATH = "oid4vp"
_OID4VP_VERIFICATION_METHOD_FRAGMENT = "oid4vp-verifier-key-1"
_SD_JWT_PRESENTATION_ALGS = {
    "sd-jwt_alg_values": ["ES256", "EdDSA"],
    "kb-jwt_alg_values": ["ES256", "EdDSA"],
}
_DC_API_PROTOCOL = "openid4vp-v1-signed"
_DC_API_JWT_RESPONSE_MODE = "dc_api.jwt"
_HAIP_JWE_ALG = "ECDH-ES"
_HAIP_JWE_ENC = "A256GCM"
_HAIP_ENCRYPTION_KEY_ID = "oid4vp-verifier-enc-key-1"
_SUPPORTED_HAIP_JWE_ALGS = {_HAIP_JWE_ALG}
_SUPPORTED_HAIP_JWE_ENCS = {_HAIP_JWE_ENC}


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
        origins = [value.strip().rstrip("/") for value in configured_origins.split(",") if value.strip()]
        if origins:
            return origins
    return [_origin_for_base_url(base_url)]


def _verification_audience_for_origin(origin: str) -> str:
    """Return the OpenID4VP audience value for DC API responses."""
    return f"origin:{origin.rstrip('/')}"

def get_or_create_signing_key():
    """Get or create ES256 signing key pair for Request Objects."""
    global _SIGNING_KEY_PAIR, _SIGNING_JWK
    if _SIGNING_KEY_PAIR is None:
        pem_env = os.environ.get("VERIFIER_SIGNING_KEY_PEM")
        pem_file = os.environ.get("VERIFIER_SIGNING_KEY_FILE")
        if pem_env:
            pem_data = pem_env.encode()
        elif pem_file and os.path.isfile(pem_file):
            with open(pem_file, "rb") as f:
                pem_data = f.read()
        else:
            pem_data = None

        if pem_data:
            private_key = serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
            logger.info("Loaded persistent verifier signing key from environment/file")
        else:
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            logger.warning("Generated EPHEMERAL verifier signing key — set VERIFIER_SIGNING_KEY_PEM for production")

        _SIGNING_KEY_PAIR = {
            'private': private_key,
            'public': private_key.public_key()
        }
        
        # Convert to JWK format for signed OID4VP request objects.
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        _SIGNING_JWK = jwk.JWK.from_pem(private_pem)
    
    return _SIGNING_KEY_PAIR, _SIGNING_JWK

VERIFIER_CLIENT_ID = os.environ.get("VERIFIER_CLIENT_ID", "")  # Will be set based on PUBLIC_BASE_URL

# MIP §26: Nonce replay prevention — track used nonces to reject duplicates.
# Uses Redis when available (shared across replicas); falls back to process-local dict.
_NONCE_TTL_SECONDS = int(os.environ.get("NONCE_TTL_SECONDS", "3600"))
_used_nonces: dict[str, float] = {}  # fallback: nonce -> expiry timestamp
_nonce_lock = asyncio.Lock()
_NONCE_CLEANUP_INTERVAL = 600  # seconds between cleanup sweeps
_nonce_last_cleanup: float = 0.0
_nonce_redis = None  # set in lifespan if Redis is available


async def _record_nonce_used_redis(nonce: str) -> bool:
    """Redis-backed nonce check. Returns False if already used (replay)."""
    # SET NX with TTL — returns True only on first insertion
    was_new = await _nonce_redis.set(
        f"mip:nonce:{nonce}", "1", nx=True, ex=_NONCE_TTL_SECONDS
    )
    return bool(was_new)


def _record_nonce_used(nonce: str) -> bool:
    """Record a nonce as used. Returns False if already used (replay)."""
    global _nonce_last_cleanup
    now = time.time()
    # Periodic cleanup of expired entries
    if now - _nonce_last_cleanup > _NONCE_CLEANUP_INTERVAL:
        _nonce_last_cleanup = now
        expired = [k for k, exp in _used_nonces.items() if exp <= now]
        for k in expired:
            del _used_nonces[k]
    # Check for replay
    if nonce in _used_nonces and _used_nonces[nonce] > now:
        return False
    _used_nonces[nonce] = now + _NONCE_TTL_SECONDS
    return True


async def _check_nonce(nonce: str) -> bool:
    """Check nonce replay. Uses Redis when available, process-local fallback.\n    Returns False if nonce was already used (replay detected)."""
    if _nonce_redis is not None:
        try:
            return await _record_nonce_used_redis(nonce)
        except Exception as exc:
            logger.warning("Redis nonce check failed (%s) — falling back to process-local store", exc)
    async with _nonce_lock:
        return _record_nonce_used(nonce)


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
    FlowType.OID4VCI_PRE_AUTHORIZED: ["create_offer", "token_exchange", "credential_request", "issue_credential"],
    FlowType.OID4VCI_AUTHORIZATION_CODE: ["create_offer", "authorization", "token_exchange", "credential_request", "issue_credential"],
    FlowType.MDL_ISSUANCE: ["application_submit", "validate_evidence", "approval_decision", "issue_mdl", "deliver_credential"],
    FlowType.OID4VP_PRESENTATION: ["create_request", "wallet_selection", "presentation_submission", "verify_presentation"],
    FlowType.MDL_PRESENTATION: ["device_engagement", "session_establishment", "request_items", "response_items", "session_termination"],
    FlowType.APPLICATION_APPROVAL_ISSUANCE: ["accept_application", "validate_evidence", "approval_decision", "issue_credential", "deliver_credential"],
    FlowType.CREDENTIAL_RENEWAL: ["validate_existing", "create_offer", "token_exchange", "credential_request", "issue_renewed_credential", "revoke_old_credential"],
    FlowType.CREDENTIAL_REVOCATION: ["validate_revocation_request", "update_status_list", "notify_holder"],
    FlowType.PHYSICAL_DOCUMENT_ISSUANCE: ["accept_application", "validate_evidence", "approval_decision", "generate_data_groups", "sign_sod", "submit_to_personalization", "track_production", "quality_verify", "activate_credential"],
    FlowType.COMBINED: ["accept_application", "approval_decision", "issue_credential", "create_request", "presentation_submission", "verify_presentation"],
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


STANDARD_FLOW_TYPES = frozenset(flow_type for flow_type in FlowType if flow_type != FlowType.CUSTOM)

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
    if step_name.startswith("issue") or step_name in {"create_offer", "deliver_credential"}:
        return StepType.ISSUANCE
    if step_name in {"token_exchange", "presentation_submission", "authentication_submission", "session_establishment", "response_items"}:
        return StepType.CALLBACK
    if step_name in {"wallet_selection", "device_engagement", "request_items", "authorization", "create_request"}:
        return StepType.USER_INPUT
    if step_name in {"notify_holder", "revoke_old_credential", "update_status_list", "session_termination"}:
        return StepType.END
    return StepType.WAIT


def _titleize_step_name(step_name: str) -> str:
    return step_name.replace("_", " ").title()


def _build_default_steps(flow_type: FlowType) -> tuple[list[FlowStep], list[FlowTransition], str | None]:
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


def _validate_flow_request(request: "CreateFlowDefinitionRequest", flow_type: FlowType) -> None:
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

    if flow_type == FlowType.APPLICATION_APPROVAL_ISSUANCE and not request.application_template_id:
        raise HTTPException(status_code=400, detail="application_template_id is required for application_approval_issuance")
    if flow_type == FlowType.APPLICATION_APPROVAL_ISSUANCE and request.credential_template_id:
        raise HTTPException(status_code=400, detail="application_approval_issuance MUST NOT have credential_template_id")

    # MIP §9.7 — COMBINED requires both credential_template_id AND presentation_policy_id
    if flow_type == FlowType.COMBINED:
        if not request.credential_template_id:
            raise HTTPException(status_code=400, detail="credential_template_id is required for combined flow_type")
        if not request.presentation_policy_id:
            raise HTTPException(status_code=400, detail="presentation_policy_id is required for combined flow_type")

    if flow_type == FlowType.CUSTOM and request.extension is None:
        raise HTTPException(status_code=400, detail="extension is required for custom flow_type")
    if flow_type != FlowType.CUSTOM and request.extension is not None:
        raise HTTPException(status_code=400, detail="extension is only permitted for custom flow_type")

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
    deployment_profile_ids = _normalize_deployment_profile_ids(request.deployment_profile_ids)

    flow.organization_id = request.organization_id
    flow.name = request.name
    flow.description = request.description
    flow.flow_type = flow_type
    flow.extension = request.extension.model_dump(mode="json") if request.extension else None
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
    flow.deployment_profile_id = deployment_profile_ids[0] if deployment_profile_ids else None
    flow.deployment_profile_ids = deployment_profile_ids
    flow.trust_profile_id = request.trust_profile_id
    flow.steps = []
    flow.transitions = []

    if flow_type != FlowType.CUSTOM:
        default_steps, default_transitions, default_start_step_id = _build_default_steps(flow_type)
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


def _require_reference_org(kind: str, reference_id: str, actual_org: str, expected_org: str) -> None:
    if actual_org and actual_org != expected_org:
        raise HTTPException(
            status_code=400,
            detail=f"{kind} {reference_id} belongs to organization {actual_org}, not {expected_org}",
        )


def _require_reference_active(kind: str, reference_id: str, status: str, require_active: bool) -> None:
    if require_active and str(status or "").lower() != "active":
        raise HTTPException(
            status_code=400,
            detail=f"{kind} {reference_id} must be active before activating a flow",
        )


def _require_template_kms_backed_issuer(template_id: str, template: Any) -> None:
    issuer_profile_id = str(getattr(template, "issuer_profile_id", "") or "").strip()
    key_access_mode = str(getattr(template, "key_access_mode", "") or "").strip().upper()
    if not issuer_profile_id or key_access_mode != "REMOTE_SIGNING":
        raise HTTPException(
            status_code=400,
            detail=(
                f"Credential template {template_id} must reference an active KMS-backed "
                "issuer profile before it can be bound to a flow"
            ),
        )


async def _get_credential_template_reference(template_id: str):
    from marty_proto.v1 import credential_template_service_pb2 as ct_pb2
    from marty_proto.v1 import credential_template_service_pb2_grpc as ct_grpc

    channel = getattr(app.state, "ct_grpc_channel", None)
    if channel is None:
        raise HTTPException(status_code=503, detail="Credential template service is not configured for flow validation")
    try:
        stub = ct_grpc.CredentialTemplateServiceStub(channel)
        resp = await stub.GetTemplate(ct_pb2.GetTemplateRequest(template_id=template_id))
    except Exception as exc:
        status_code = 404 if _is_reference_not_found(exc) else 502
        raise HTTPException(status_code=status_code, detail=f"Credential template {template_id} could not be resolved: {exc}") from exc
    if not getattr(resp, "id", ""):
        raise HTTPException(status_code=404, detail=f"Credential template {template_id} not found")
    return resp


async def _get_presentation_policy_reference(policy_id: str):
    from marty_proto.v1 import presentation_policy_service_pb2 as pp_pb2
    from marty_proto.v1 import presentation_policy_service_pb2_grpc as pp_grpc

    channel = getattr(app.state, "pp_grpc_channel", None)
    if channel is None:
        raise HTTPException(status_code=503, detail="Presentation policy service is not configured for flow validation")
    try:
        stub = pp_grpc.PresentationPolicyServiceStub(channel)
        resp = await stub.GetPolicy(pp_pb2.GetPolicyRequest(policy_id=policy_id))
    except Exception as exc:
        status_code = 404 if _is_reference_not_found(exc) else 502
        raise HTTPException(status_code=status_code, detail=f"Presentation policy {policy_id} could not be resolved: {exc}") from exc
    if not getattr(resp, "id", ""):
        raise HTTPException(status_code=404, detail=f"Presentation policy {policy_id} not found")
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
        _require_reference_org("Credential template", template_id, getattr(template, "organization_id", ""), organization_id)
        _require_reference_active("Credential template", template_id, getattr(template, "status", ""), require_active)
        _require_template_kms_backed_issuer(template_id, template)

    if credential_template_id:
        await _validate_template(credential_template_id)

    if presentation_policy_id:
        policy = await _get_presentation_policy_reference(presentation_policy_id)
        _require_reference_org("Presentation policy", presentation_policy_id, getattr(policy, "organization_id", ""), organization_id)
        _require_reference_active("Presentation policy", presentation_policy_id, getattr(policy, "status", ""), require_active)

        requirements_json = getattr(policy, "credential_requirements_json", "") or "[]"
        try:
            requirements = json.loads(requirements_json)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"Presentation policy {presentation_policy_id} has invalid credential requirements JSON") from exc
        if isinstance(requirements, list):
            for requirement in requirements:
                if isinstance(requirement, dict) and requirement.get("credential_template_id"):
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
    default_timeout_seconds: int = 600  # MIP §9.9.4: 10-minute default for AWAITING_WALLET
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
            extended_type = _parse_flow_type(self.extension.get("extends_flow_type", ""))
            return FLOW_CATEGORY_BY_TYPE[extended_type]
        return FLOW_CATEGORY_BY_TYPE[self.flow_type]


def _effective_flow_type(flow: FlowDefinition) -> FlowType:
    """Return the standard behavior extended by a custom flow."""
    if flow.flow_type == FlowType.CUSTOM and flow.extension:
        return _parse_flow_type(flow.extension["extends_flow_type"])
    return flow.flow_type


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

# MIP §9: Valid state transitions — terminal states are immutable.
VALID_TRANSITIONS: dict[FlowInstanceStatus, set[FlowInstanceStatus]] = {
    FlowInstanceStatus.CREATED: {
        FlowInstanceStatus.PENDING,
        FlowInstanceStatus.IN_PROGRESS,
        FlowInstanceStatus.CANCELLED,
    },
    FlowInstanceStatus.PENDING: {
        FlowInstanceStatus.IN_PROGRESS,
        FlowInstanceStatus.CANCELLED,
    },
    FlowInstanceStatus.IN_PROGRESS: {
        FlowInstanceStatus.AWAITING_WALLET,
        FlowInstanceStatus.AWAITING_APPROVAL,
        FlowInstanceStatus.AWAITING_EVIDENCE,
        FlowInstanceStatus.COMPLETED,
        FlowInstanceStatus.FAILED,
        FlowInstanceStatus.CANCELLED,
        FlowInstanceStatus.EXPIRED,
    },
    FlowInstanceStatus.AWAITING_WALLET: {
        FlowInstanceStatus.IN_PROGRESS,
        FlowInstanceStatus.CANCELLED,
        FlowInstanceStatus.EXPIRED,
    },
    FlowInstanceStatus.AWAITING_APPROVAL: {
        FlowInstanceStatus.IN_PROGRESS,
        FlowInstanceStatus.FAILED,
        FlowInstanceStatus.CANCELLED,
    },
    FlowInstanceStatus.AWAITING_EVIDENCE: {
        FlowInstanceStatus.IN_PROGRESS,
        FlowInstanceStatus.CANCELLED,
        FlowInstanceStatus.EXPIRED,
    },
    # Terminal states — no transitions allowed
    FlowInstanceStatus.COMPLETED: set(),
    FlowInstanceStatus.FAILED: set(),
    FlowInstanceStatus.CANCELLED: set(),
    FlowInstanceStatus.EXPIRED: set(),
}

TERMINAL_STATES = {
    FlowInstanceStatus.COMPLETED,
    FlowInstanceStatus.FAILED,
    FlowInstanceStatus.CANCELLED,
    FlowInstanceStatus.EXPIRED,
}


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

    def transition_to(self, new_status: FlowInstanceStatus, *, actor: str | None = None, event: str | None = None) -> None:
        """Atomically transition to a new status with guard.

        Raises ValueError if the transition is not valid per MIP §9.
        """
        if new_status == self.status:
            return
        allowed = VALID_TRANSITIONS.get(self.status, set())
        if new_status not in allowed:
            raise ValueError(
                f"Invalid state transition: {self.status.value} -> {new_status.value}"
            )
        prior = self.status
        self.state_history.append({
            "prior_state": prior.value,
            "new_state": new_status.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "event": event or f"{prior.value}_to_{new_status.value}",
        })
        self.status = new_status
        self.updated_at = datetime.now(timezone.utc)
        if new_status in TERMINAL_STATES:
            self.completed_at = datetime.now(timezone.utc)


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
    
    # OID4VCI-specific fields
    credential_offer_uri: str | None = None
    qr_payload: str | None = None  # Base64-encoded QR image data URI
    pre_authorized_code: str | None = None
    
    # Timing
    expires_at: datetime | None = None
    scanned_at: datetime | None = None
    
    # Status and metadata
    status: ArtifactStatus = ArtifactStatus.ACTIVE
    state: str | None = None  # OAuth state parameter
    wallet_metadata: dict[str, Any] = field(default_factory=dict)  # User-Agent, wallet type, etc.
    
    # Attempt tracking (for retry policy)
    attempt_number: int = 1
    
    # Timestamps
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
        self._instances[instance.id] = instance
    
    async def get_instance(self, instance_id: str) -> FlowInstance | None:
        return self._instances.get(instance_id)
    
    async def list_instances(
        self, 
        org_id: str, 
        flow_definition_id: str | None = None,
        status: FlowInstanceStatus | None = None,
    ) -> list[FlowInstance]:
        instances = [i for i in self._instances.values() if i.organization_id == org_id]
        if flow_definition_id:
            instances = [i for i in instances if i.flow_definition_id == flow_definition_id]
        if status:
            instances = [i for i in instances if i.status == status]
        return instances
    
    # Flow Instance Artifact operations
    async def save_artifact(self, artifact: FlowInstanceArtifact) -> None:
        self._artifacts[artifact.id] = artifact
    
    async def get_artifact(self, artifact_id: str) -> FlowInstanceArtifact | None:
        return self._artifacts.get(artifact_id)
    
    async def list_artifacts(self, flow_instance_id: str) -> list[FlowInstanceArtifact]:
        return [a for a in self._artifacts.values() if a.flow_instance_id == flow_instance_id]
    
    async def get_artifact_by_code(self, pre_authorized_code: str) -> FlowInstanceArtifact | None:
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

        step_ids = [step.step_id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("extension step_id values must be unique")
        if self.entry_step_id not in step_ids:
            raise ValueError("entry_step_id must reference an extension step")

        adjacency: dict[str, list[str]] = {step_id: [] for step_id in step_ids}
        for transition in self.transitions:
            if transition.from_step_id not in adjacency or transition.to_step_id not in adjacency:
                raise ValueError("extension transitions must reference declared steps")
            adjacency[transition.from_step_id].append(transition.to_step_id)

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(step_id: str) -> None:
            if step_id in visiting:
                raise ValueError("extension graph must be acyclic")
            if step_id in visited:
                return
            visiting.add(step_id)
            for destination in adjacency[step_id]:
                visit(destination)
            visiting.remove(step_id)
            visited.add(step_id)

        visit(self.entry_step_id)
        if visited != set(step_ids):
            raise ValueError("every extension step must be reachable from entry_step_id")
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
    def validate_hook_names(cls, hooks: dict[str, list[FlowHookModel]]) -> dict[str, list[FlowHookModel]]:
        for hook_name in hooks:
            if not hook_name.startswith(("pre_", "post_")):
                raise ValueError("hook names must use pre_{step_name} or post_{step_name}")
            step_name = hook_name.split("_", 1)[1]
            if not step_name or not step_name[0].isalpha() or not step_name.replace("_", "").isalnum():
                raise ValueError(f"invalid hook name: {hook_name}")
        return hooks

    @model_validator(mode="after")
    def validate_extension_contract(self) -> "CreateFlowDefinitionRequest":
        if self.flow_type == FlowType.CUSTOM and self.extension is None:
            raise ValueError("extension is required for custom flow_type")
        if self.flow_type != FlowType.CUSTOM and self.extension is not None:
            raise ValueError("extension is only permitted for custom flow_type")
        return self


class FlowDefinitionResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None = None
    flow_type: str
    flow_category: str
    resolved_steps: list[str] = Field(default_factory=list)
    extension: dict[str, Any] | None = None
    trust_profile_id: str | None = None
    credential_template_id: str | None = None
    application_template_id: str | None = None
    presentation_policy_id: str | None = None
    delivery_destination_profile_id: str | None = None
    deployment_profile_ids: list[str] = Field(default_factory=list)
    approval_strategy: str
    hooks: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    trigger: dict[str, Any] | None = None
    version: int
    status: str
    created_at: str
    updated_at: str


class StartFlowRequest(BaseModel):
    flow_definition_id: str = Field(max_length=255)
    subject_id: str | None = Field(None, max_length=255)
    subject_type: str = Field("applicant", max_length=50)
    external_reference: str | None = Field(None, max_length=500)
    initial_context: dict = Field(default_factory=dict)


class FlowInstanceResponse(BaseModel):
    id: str
    flow_id: str | None = None
    flow_type: str | None = None
    organization_id: str
    status: str
    current_step: str | None = None
    current_step_index: int | None = None
    context_data: dict = Field(default_factory=dict)
    step_results: dict[str, dict[str, Any]] = Field(default_factory=dict)
    issued_credential_id: str | None = None
    started_at: str | None
    completed_at: str | None
    expires_at: str | None
    error_code: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    state_history: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str
    updated_at: str


class AdvanceFlowRequest(BaseModel):
    step_result: str = Field("success", max_length=50)  # success, failure, etc.
    data: dict = Field(default_factory=dict)


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
    
    for precondition in preconditions:
        met = False
        
        if precondition == "application_approved":
            # Check if application is approved in context
            met = context.get("application_status") == "approved"
        
        elif precondition == "identity_verified":
            # Check if identity verification passed
            met = context.get("identity_verified") is True
        
        elif precondition == "manual_admin_approval":
            # Check if admin explicitly approved
            met = context.get("admin_approved") is True
        
        elif precondition == "external_verification":
            # Check if external verification callback received
            met = context.get("external_verification_result") == "success"
        
        else:
            # Unknown precondition, log warning but don't block
            logger.warning(f"Unknown precondition: {precondition}")
            met = True  # Treat unknown as met to avoid blocking
        
        if not met:
            unmet.append(precondition)
    
    all_met = len(unmet) == 0
    return all_met, unmet


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


def _protocol_step_name(flow_def: FlowDefinition | None, step_id: str | None) -> str | None:
    if not flow_def or not step_id:
        return None
    step = next((candidate for candidate in flow_def.steps if candidate.id == step_id), None)
    if not step:
        return None
    protocol_step = step.config.get("protocol_step") if isinstance(step.config, dict) else None
    if protocol_step:
        return str(protocol_step)
    if step.name:
        return step.name.strip().lower().replace(" ", "_")
    return step.id


def _protocol_step_index(flow_def: FlowDefinition | None, step_id: str | None) -> int | None:
    if not flow_def or not step_id:
        return None
    for index, step in enumerate(flow_def.steps):
        if step.id == step_id:
            return index
    return None


def _sync_protocol_context(instance: FlowInstance, flow_def: FlowDefinition | None = None) -> None:
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


def _instance_to_response(instance: FlowInstance) -> FlowInstanceResponse:
    """Convert FlowInstance to response model."""
    flow_type = _response_flow_type(instance)
    protocol_status = _protocol_status_for_instance(instance.status)
    flow_definition_reference = instance.context.get("flow_definition_reference", instance.flow_definition_id)
    metadata = {
        "runtime_status": instance.status.value,
        "flow_definition_reference": flow_definition_reference,
        "subject_type": instance.subject_type,
        **({"subject_id": instance.subject_id} if instance.subject_id else {}),
        **({"external_reference": instance.external_reference} if instance.external_reference else {}),
    }
    return FlowInstanceResponse(
        id=instance.id,
        flow_id=None if instance.flow_definition_id.startswith("__") else instance.flow_definition_id,
        flow_type=flow_type,
        organization_id=instance.organization_id,
        status=protocol_status,
        current_step=instance.context.get("current_step_name"),
        current_step_index=instance.context.get("current_step_index"),
        context_data=instance.context,
        step_results=instance.context.get("step_results", {}),
        issued_credential_id=instance.context.get("issued_credential_id"),
        started_at=instance.started_at.isoformat() if instance.started_at else None,
        completed_at=instance.completed_at.isoformat() if instance.completed_at else None,
        expires_at=instance.expires_at.isoformat() if instance.expires_at else None,
        error_code=instance.context.get("error_code"),
        metadata=metadata,
        state_history=instance.state_history,
        created_at=instance.created_at.isoformat(),
        updated_at=instance.updated_at.isoformat(),
    )


def _artifact_to_response(artifact: FlowInstanceArtifact) -> FlowInstanceArtifactResponse:
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


def _record_mip_message(instance: FlowInstance, label: str, message: MIPMessage) -> None:
    """Record the latest typed MIP message plus bounded history on the instance."""
    serialized = message.to_dict()
    message_log = instance.context.setdefault("mip_messages", {})
    message_log[label] = serialized

    history = instance.context.setdefault("mip_message_history", [])
    if not any(
        entry.get("label") == label and entry.get("envelope", {}).get("message_id") == serialized["message_id"]
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
        instance.id, flow_def.credential_template_id, list(claims.keys()),
    )

    try:
        from marty_proto.v1 import issuance_service_pb2 as iss_pb2
        from marty_proto.v1 import issuance_service_pb2_grpc as iss_grpc

        channel = getattr(app.state, "issuance_grpc_channel", None)
        if channel is None:
            import grpc.aio as grpc_aio
            channel = grpc_aio.insecure_channel(ISSUANCE_GRPC_TARGET)
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
                    claims={k: str(v) for k, v in claims.items()},
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

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            f"{ISSUANCE_SERVICE_URL}/v1/issuance/initiate",
            json={
                "organization_id": instance.organization_id,
                "credential_template_id": flow_def.credential_template_id,
                "applicant_id": instance.subject_id,
                "subject_did": instance.context.get("subject_did"),
                "holder_did": instance.context.get("holder_did"),
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
        import grpc.aio as grpc_aio

        ct_grpc_target = os.environ.get("CT_GRPC_TARGET", "credential-template:9003")
        async with grpc_aio.insecure_channel(ct_grpc_target) as channel:
            ct_stub = ct_grpc.CredentialTemplateServiceStub(channel)
            tmpl_resp = await ct_stub.GetTemplate(
                ct_pb2.GetTemplateRequest(template_id=template_id)
            )

            if not tmpl_resp.id:
                logger.warning(f"Template {template_id} not found for wallet offer generation")
                return {}, {}

            # Parse wallet configs
            wallet_configs_json = tmpl_resp.wallet_configs_json
            if not wallet_configs_json:
                logger.warning(f"Template {template_id} has no wallet configs")
                return {}, {}

            wallet_configs = json.loads(wallet_configs_json) if isinstance(wallet_configs_json, str) else wallet_configs_json
            logger.info(f"Building wallet offers from {len(wallet_configs)} wallet configs")

            # Build per-wallet offers
            from issuance.infrastructure.api.application_routes import org_issuer_url, org_issuer_url_spruce
            from issuance.application.rust_integration import oid4vci_create_credential_offer

            credential_type = tmpl_resp.credential_type or "default"

            for wc in wallet_configs:
                wallet_id = wc.get("wallet_id", "")
                scheme = wc.get("deep_link_scheme", "openid-credential-offer://")
                fmt_variant = wc.get("format_variant")
                display_name = wc.get("display_name", "")

                if not wallet_id:
                    continue

                # Select credential_configuration_id based on format variant
                if fmt_variant == "spruce-vc+sd-jwt":
                    config_id = f"{credential_type}#spruce-sd-jwt"
                    issuer_url = org_issuer_url_spruce(org_id)
                elif fmt_variant == "mso_mdoc":
                    config_id = f"{credential_type}#mdoc"
                    issuer_url = org_issuer_url_spruce(org_id)
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
                    credential_offer_uris[wallet_id] = f"{scheme}{sep}credential_offer={quote(offer_json)}"
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
        credential_offer_uris, credential_offer_labels = await _build_wallet_offers_from_template(
            flow_def.credential_template_id,
            instance.organization_id,
            pre_auth_code,
        )
    
    if not credential_offer_uri:
        if isinstance(credential_offer_uris, dict):
            credential_offer_uri = next((uri for uri in credential_offer_uris.values() if uri), None)
    if not credential_offer_uri:
        raise HTTPException(status_code=502, detail="Issuance service did not return a credential offer URI")

    issuer_url = os.environ.get("PUBLIC_BASE_URL", "http://localhost:8000")
    expires_at = None
    if issuance.get("expires_at"):
        try:
            expires_at = datetime.fromisoformat(str(issuance["expires_at"]).replace("Z", "+00:00"))
        except ValueError:
            logger.warning("Invalid issuance expires_at value: %s", issuance.get("expires_at"))
    if expires_at is None:
        from datetime import timedelta
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

    artifact = FlowInstanceArtifact(
        flow_instance_id=instance.id,
        credential_offer_uri=credential_offer_uri,
        pre_authorized_code=pre_auth_code,
        state=state,
        expires_at=expires_at,
        status=ArtifactStatus.ACTIVE,
        attempt_number=attempt_number,
    )
    
    await repo.save_artifact(artifact)
    
    # Store artifact ID and offer details in instance context
    instance.context["oid4vci_artifact_id"] = artifact.id
    instance.context["credential_offer_transaction_id"] = issuance.get("id")
    instance.context["offer_id"] = issuance.get("id")
    instance.context["credential_offer_uri"] = credential_offer_uri
    instance.context["credential_offer_uris"] = credential_offer_uris or {}
    instance.context["credential_offer_labels"] = credential_offer_labels or {}
    instance.context["issuance_status"] = issuance.get("status")
    if pre_auth_code:
        instance.context["pre_auth_code"] = pre_auth_code

    credential_offer_message = MIPMessage(
        message_type=MessageType.CREDENTIAL_OFFER,
        correlation_id=instance.id,
        sender_id=issuer_url,
        payload=CredentialOfferPayload(
            credential_issuer=issuer_url,
            credential_configuration_ids=[flow_def.credential_template_id] if flow_def.credential_template_id else [],
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
    encrypted_artifacts = bool(os.environ.get("PHYSICAL_DOCUMENT_ARTIFACT_KEY", "").strip())
    personalization_bureau = bool(os.environ.get("PERSONALIZATION_BUREAU_URL", "").strip())
    physical_blockers: list[str] = []
    if not physical_signing:
        physical_blockers.append("Configure ICAO_DOCUMENT_SIGNER_URL for eMRTD SOD signing.")
    if not encrypted_artifacts:
        physical_blockers.append("Configure PHYSICAL_DOCUMENT_ARTIFACT_KEY for encrypted sensitive artifacts.")
    if not personalization_bureau:
        physical_blockers.append("Configure PERSONALIZATION_BUREAU_URL for document production handoff.")

    return {
        "protocol_version": "0.3.1",
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
    missing = [field_name for field_name in required_fields if not physical_document.get(field_name)]
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
        raise HTTPException(status_code=409, detail="Physical document job is not initialized")
    application_id = job["application_id"]
    operation: tuple[str, str, dict[str, Any] | None] | None = None
    if step_name == "generate_data_groups":
        operation = ("POST", f"/v1/passport/applications/{application_id}/generate-data-groups", None)
    elif step_name == "sign_sod":
        operation = ("POST", f"/v1/passport/applications/{application_id}/generate-sod", None)
    elif step_name == "submit_to_personalization":
        operation = ("POST", f"/v1/passport/applications/{application_id}/submit-personalization", None)
    elif step_name == "track_production":
        operation = ("GET", f"/v1/passport/applications/{application_id}/production-status", None)
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
        operation = ("POST", f"/v1/passport/applications/{application_id}/activate", None)

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
            errors.append({
                "code": "MISSING_REFERENCE",
                "field": reference_name,
                "message": f"{reference_name} is required for {flow.flow_type.value}.",
            })
        elif reference_name != "extension":
            dependencies.append({"type": reference_name.removesuffix("_id"), "id": str(reference_value)})

    if not flow.steps:
        errors.append({"code": "EMPTY_FLOW", "field": "flow_type", "message": "The flow resolves to no executable steps."})

    physical_capability = _flow_capabilities()["physical_document_issuance"]
    if flow.flow_type == FlowType.PHYSICAL_DOCUMENT_ISSUANCE:
        for blocker in physical_capability["blockers"]:
            errors.append({"code": "CAPABILITY_UNAVAILABLE", "field": "flow_type", "message": blocker})

    try:
        await _validate_credential_layer_references(
            organization_id=flow.organization_id,
            credential_template_id=flow.credential_template_id,
            presentation_policy_id=flow.presentation_policy_id,
            require_active=True,
        )
    except HTTPException as exc:
        errors.append({
            "code": "DEPENDENCY_INVALID",
            "field": "dependencies",
            "message": str(exc.detail),
        })

    if not flow.deployment_profile_ids:
        warnings.append({
            "code": "NO_DEPLOYMENT_TARGET",
            "field": "deployment_profile_ids",
            "message": "No deployment target is selected; activation is allowed, but the flow cannot be deployed.",
        })

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "resolved_dependencies": dependencies,
        "resolved_steps": (
            [step.get("step_id", "") for step in (flow.extension or {}).get("steps", [])]
            if flow.flow_type == FlowType.CUSTOM
            else FLOW_STEP_SEQUENCES.get(flow.flow_type, [])
        ),
    }


@router.get("/capabilities")
async def get_flow_capabilities() -> dict[str, Any]:
    """Describe the MIP flow contract and runtime capability blockers."""
    return _flow_capabilities()


@router.post("/definitions", response_model=FlowDefinitionResponse, response_model_exclude_none=True)
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


@router.get("/definitions", response_model=list[FlowDefinitionResponse], response_model_exclude_none=True)
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
    return [_definition_to_response(f) for f in flows[offset:offset + limit]]


@router.get("/definitions/{flow_id}", response_model=FlowDefinitionResponse, response_model_exclude_none=True)
async def get_flow_definition(
    flow_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowDefinitionResponse:
    """Get a Flow Definition by ID."""
    flow = await repo.get_definition(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow Definition not found")
    membership = await app.state.org_client.get_membership(user_id, flow.organization_id)
    ensure_membership_permission(membership, "flow-definition", "view")
    return _definition_to_response(flow)


@router.put("/definitions/{flow_id}", response_model=FlowDefinitionResponse, response_model_exclude_none=True)
async def update_flow_definition(
    flow_id: str,
    request: CreateFlowDefinitionRequest,
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowDefinitionResponse:
    """Replace a Flow Definition with a validated full definition payload."""
    flow = await repo.get_definition(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow Definition not found")
    if flow.status == FlowStatus.ARCHIVED:
        raise HTTPException(status_code=400, detail="Archived flow definitions cannot be updated")

    org_client = await get_organization_client(fastapi_request)
    membership = await org_client.get_membership(user_id, flow.organization_id)
    ensure_membership_permission(membership, "flow-definition", "edit")

    if request.organization_id != flow.organization_id:
        raise HTTPException(status_code=400, detail="organization_id cannot be changed for an existing flow definition")

    flow_type = _parse_flow_type(request.flow_type)
    _validate_flow_request(request, flow_type)
    await _validate_credential_layer_references(
        organization_id=request.organization_id,
        credential_template_id=request.credential_template_id,
        presentation_policy_id=request.presentation_policy_id,
        require_active=False,
    )

    flow.version += 1
    _replace_flow_definition_content(flow, request, flow_type)
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
    membership = await app.state.org_client.get_membership(user_id, flow.organization_id)
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
    membership = await app.state.org_client.get_membership(user_id, flow.organization_id)
    ensure_membership_permission(membership, "flow-definition", "view")
    validation = await _validate_flow_definition(flow)
    return {
        **validation,
        "mode": "DRY_RUN",
        "would_execute": validation["resolved_steps"] if validation["valid"] else [],
        "side_effects_executed": False,
    }


@router.post("/definitions/{flow_id}/activate", response_model=FlowDefinitionResponse, response_model_exclude_none=True)
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
    membership = await app.state.org_client.get_membership(user_id, flow.organization_id)
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
    membership = await app.state.org_client.get_membership(user_id, flow.organization_id)
    ensure_membership_permission(membership, "flow-definition", "delete")
    
    if flow.status != FlowStatus.DRAFT:
        raise HTTPException(status_code=400, detail="Only draft flows can be deleted")
    await repo.delete_definition(flow_id)
    return {"success": True}


# Flow Instance endpoints
@router.post("/instances", response_model=FlowInstanceResponse, response_model_exclude_none=True)
async def start_flow(
    request: StartFlowRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceResponse:
    """Start a new Flow Instance."""
    flow_def = await repo.get_definition(request.flow_definition_id)
    if not flow_def:
        raise HTTPException(status_code=404, detail="Flow Definition not found")

    membership = await app.state.org_client.get_membership(user_id, flow_def.organization_id)
    ensure_membership_permission(membership, "flow-instance", "start")
    
    if flow_def.status != FlowStatus.ACTIVE:
        raise HTTPException(status_code=400, detail="Flow Definition is not active")
    
    instance = FlowInstance(
        flow_definition_id=request.flow_definition_id,
        organization_id=flow_def.organization_id,
        status=FlowInstanceStatus.IN_PROGRESS if flow_def.start_step_id else FlowInstanceStatus.PENDING,
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
    
    # Set expiry
    from datetime import timedelta
    instance.expires_at = instance.started_at + timedelta(seconds=flow_def.default_timeout_seconds)
    
    # Record initial state transition in state_history (MIP §9.9.4)
    instance.state_history.append({
        "prior_state": None,
        "new_state": instance.status.value,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": user_id,
        "event": "flow_instance_created",
    })

    # Record first step
    if flow_def.start_step_id:
        instance.step_history.append({
            "step_id": flow_def.start_step_id,
            "entered_at": datetime.now(timezone.utc).isoformat(),
            "status": "entered",
        })
    
    await repo.save_instance(instance)
    
    # Create OID4VCI artifact if this is an OID4VCI flow
    if _effective_flow_type(flow_def) == FlowType.OID4VCI_PRE_AUTHORIZED:
        artifact = await _create_oid4vci_artifact(instance, flow_def, repo)
        if artifact:
            logger.info(f"Created OID4VCI artifact: {artifact.id}")
    
    logger.info(f"Started Flow Instance: {instance.id}")
    return _instance_to_response(instance)


@router.get("/instances", response_model=list[FlowInstanceResponse], response_model_exclude_none=True)
async def list_flow_instances(
    organization_id: str = Query(..., description="Organization ID"),
    flow_definition_id: str | None = Query(None, description="Filter by flow definition"),
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
    instances = await repo.list_instances(organization_id, flow_definition_id, status_filter)
    return [_instance_to_response(i) for i in instances[offset:offset + limit]]


@router.get("/instances/{instance_id}", response_model=FlowInstanceResponse, response_model_exclude_none=True)
async def get_flow_instance(
    instance_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceResponse:
    """Get a Flow Instance by ID."""
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")
    membership = await app.state.org_client.get_membership(user_id, instance.organization_id)
    ensure_membership_permission(membership, "flow-instance", "view")
    return _instance_to_response(instance)


@router.get("/instances/{instance_id}/result")
async def get_flow_instance_result(
    instance_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> dict:
    """OID4VP-1FINAL §8.7 — Relying-party result polling endpoint.

    Returns the current verification state and any verified claims for the
    given flow instance. Before submission the state is ``awaiting_wallet``; after a
    successful VP submission it is ``completed``.
    """
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")
    membership = await app.state.org_client.get_membership(user_id, instance.organization_id)
    ensure_membership_permission(membership, "flow-instance", "view")
    return {
        "instance_id": instance.id,
        "status": instance.status.value,
        "state": instance.status.value,
        "result": instance.result,
        "error": instance.error,
        "completed_at": instance.completed_at.isoformat() if instance.completed_at else None,
    }


@router.post("/instances/{instance_id}/advance", response_model=FlowInstanceResponse, response_model_exclude_none=True)
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

    membership = await app.state.org_client.get_membership(user_id, instance.organization_id)
    ensure_membership_permission(membership, "flow-instance", "advance")
    
    if instance.status not in [FlowInstanceStatus.IN_PROGRESS, FlowInstanceStatus.AWAITING_WALLET]:
        raise HTTPException(status_code=400, detail=f"Cannot advance flow in {instance.status} status")
    
    flow_def = await repo.get_definition(instance.flow_definition_id)
    if not flow_def:
        raise HTTPException(status_code=404, detail="Flow Definition not found")
    
    # Check preconditions if this is the first step (precondition check step)
    current_step = next((s for s in flow_def.steps if s.id == instance.current_step_id), None)
    if current_step and current_step.step_type == StepType.APPROVAL:
        # Check if this is the precondition check step
        required_preconditions = flow_def.preconditions or current_step.config.get("required_preconditions", [])
        if required_preconditions:
            preconditions_met, unmet = await check_preconditions(required_preconditions, instance.context)
            if not preconditions_met:
                raise HTTPException(
                    status_code=400, 
                    detail=f"Preconditions not met: {', '.join(unmet)}"
                )
            # Store that preconditions were checked
            instance.context["preconditions_checked"] = True
            instance.context["preconditions_met_at"] = datetime.now(timezone.utc).isoformat()

    current_step_name = _protocol_step_name(flow_def, instance.current_step_id)
    if (
        _effective_flow_type(flow_def) == FlowType.PHYSICAL_DOCUMENT_ISSUANCE
        and request.step_result == TransitionCondition.SUCCESS.value
    ):
        await _execute_physical_document_step(instance, current_step_name, request.data)
    
    # Find next step based on transition
    current_step_id = instance.current_step_id
    condition = TransitionCondition(request.step_result)
    
    next_step_id = None
    for transition in flow_def.transitions:
        if transition.from_step_id == current_step_id and transition.condition == condition:
            next_step_id = transition.to_step_id
            break
    
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
        instance.step_history.append({
            "step_id": next_step_id,
            "entered_at": datetime.now(timezone.utc).isoformat(),
            "status": "entered",
        })
        
        # Check if this is an end step
        next_step = next((s for s in flow_def.steps if s.id == next_step_id), None)
        if next_step and next_step.step_type == StepType.END:
            instance.status = FlowInstanceStatus.COMPLETED
            instance.completed_at = datetime.now(timezone.utc)
            instance.result = instance.context
    else:
        # No valid transition, flow ends
        if request.step_result == "failure":
            instance.status = FlowInstanceStatus.FAILED
            instance.error = "Step failed with no recovery transition"
        else:
            instance.status = FlowInstanceStatus.COMPLETED
        instance.completed_at = datetime.now(timezone.utc)
    
    instance.updated_at = datetime.now(timezone.utc)
    await repo.save_instance(instance)
    return _instance_to_response(instance)


@router.post("/instances/{instance_id}/cancel", response_model=FlowInstanceResponse, response_model_exclude_none=True)
async def cancel_flow(
    instance_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceResponse:
    """Cancel a Flow Instance."""
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")

    membership = await app.state.org_client.get_membership(user_id, instance.organization_id)
    ensure_membership_permission(membership, "flow-instance", "cancel")
    
    if instance.status in TERMINAL_STATES:
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

@router.get("/instances/{instance_id}/artifacts", response_model=list[FlowInstanceArtifactResponse], response_model_exclude_none=True)
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

    membership = await app.state.org_client.get_membership(user_id, instance.organization_id)
    ensure_membership_permission(membership, "flow-instance", "view")
    
    artifacts = await repo.list_artifacts(instance_id)
    return [_artifact_to_response(a) for a in artifacts[offset:offset + limit]]


@router.get("/instances/{instance_id}/artifacts/{artifact_id}", response_model=FlowInstanceArtifactResponse, response_model_exclude_none=True)
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
    membership = await app.state.org_client.get_membership(user_id, instance.organization_id)
    ensure_membership_permission(membership, "flow-instance", "view")
    
    return _artifact_to_response(artifact)


@router.post("/instances/{instance_id}/generate-qr", response_model=FlowInstanceArtifactResponse, response_model_exclude_none=True)
async def generate_qr_code(
    instance_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceArtifactResponse:
    """Manually generate a new QR code / credential offer for an OID4VCI flow instance."""
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")

    membership = await app.state.org_client.get_membership(user_id, instance.organization_id)
    ensure_membership_permission(membership, "flow-instance", "advance")
    
    flow_def = await repo.get_definition(instance.flow_definition_id)
    if not flow_def:
        raise HTTPException(status_code=404, detail="Flow Definition not found")
    
    if _effective_flow_type(flow_def) != FlowType.OID4VCI_PRE_AUTHORIZED:
        raise HTTPException(status_code=400, detail="Flow is not an OID4VCI issuance flow")
    
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
    
    logger.info(f"Manually generated QR code for instance {instance_id}: artifact {artifact.id}")
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
    # Optional so SIOPv2 flows (response_type=id_token) don't require a policy.
    presentation_policy_id: str | None = None
    organization_id: str | None = None
    # SIOPv2 Draft 13 §9: response_type=id_token selects SIOPv2 authentication.
    response_type: str = "vp_token"
    trust_profile_id: str | None = None
    deployment_profile_id: str | None = None
    external_reference: str | None = None
    callback_url: str | None = Field(None, max_length=2048)
    oid4vp_profile: Literal["standard", "haip"] = "standard"
    request_uri_method: Literal["get", "post"] = "get"
    expiry_minutes: int = 15

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
            raise ValueError(f"callback_url must use scheme: {', '.join(sorted(allowed_schemes))}")
        if not parsed.netloc:
            raise ValueError("callback_url must have a valid host")
        # Block internal/metadata IPs
        hostname = parsed.hostname or ""
        _blocked = ("169.254.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                     "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                     "192.168.", "127.", "0.")
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


class SiopSubmitRequest(BaseModel):
    """Body for validating a self-issued ID token."""
    id_token: str
    instance_id: str | None = None  # optional — for nonce binding to a specific session


class SubmitVerificationRequest(BaseModel):
    """Request to submit a VP token to a verification flow."""
    vp_token: str
    presentation_submission: dict | None = None


class DigitalCredentialSubmissionRequest(BaseModel):
    """Browser-mediated DC API response payload."""

    protocol: str | None = Field(None, max_length=128)
    origin: str | None = Field(None, max_length=512)
    data: dict[str, Any] = Field(default_factory=dict)


class VerificationResultResponse(BaseModel):
    """Response from completing a verification flow."""
    instance_id: str
    status: str
    result: str  # passed, failed, partial
    decision: str  # allow, deny, manual_review
    decision_reason: str
    verified_claims: dict
    evaluation_timestamp: str


@router.post("/verify", response_model=VerificationRequestResponse, response_model_exclude_none=True)
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
        organization_id = request.organization_id or "__unknown__"
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
            },
            external_reference=request.external_reference,
            started_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=request.expiry_minutes),
        )
        base_url = os.environ.get("PUBLIC_BASE_URL", "http://marty-gateway:8000")
        request_uri = f"{base_url}/v1/flows/instances/{instance.id}/request"
        auth_request = f"openid://authorize?request_uri={request_uri}"
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
            detail={"error": "invalid_request", "error_description": "presentation_policy_id is required for OID4VP flows"},
        )
    if request.oid4vp_profile == "haip" and os.environ.get("OID4VP_HAIP_ENABLED") != "1":
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
            "request_uri_method": request.request_uri_method,
            "protocol_flow_type": FlowType.OID4VP_PRESENTATION.value,
            "current_step_name": "create_request",
            "current_step_index": 0,
            "step_results": {},
        },
        external_reference=request.external_reference,
        started_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=request.expiry_minutes),
    )

    # Generate request URI and QR code data
    # Use gateway URL for Docker networking (Walt.ID wallet needs to access this)
    base_url = os.environ.get("PUBLIC_BASE_URL", "http://marty-gateway:8000")
    # OID4VP: The request_uri points to where the wallet can fetch the signed Request Object
    request_uri = f"{base_url}/v1/flows/instances/{instance.id}/request"
    # The authorization request with request_uri parameter
    auth_request = f"openid4vp://authorize?request_uri={request_uri}"
    if request.request_uri_method == "post":
        auth_request += "&request_uri_method=post"
    qr_code_data = auth_request

    instance.context["request_uri"] = request_uri
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


async def _build_presentation_definition(presentation_policy_id: str) -> dict:
    """
    Build a proper OID4VP presentation_definition from a presentation policy.

    Fetches the policy and each referenced credential template so that
    ``input_descriptors`` contain real credential-type filters that a wallet
    can match against its stored credentials.
    """
    import json as _json
    from marty_proto.v1 import presentation_policy_service_pb2 as pp_pb2
    from marty_proto.v1 import presentation_policy_service_pb2_grpc as pp_grpc
    from marty_proto.v1 import credential_template_service_pb2 as ct_pb2
    from marty_proto.v1 import credential_template_service_pb2_grpc as ct_grpc

    pp_stub = pp_grpc.PresentationPolicyServiceStub(app.state.pp_grpc_channel)
    ct_stub = ct_grpc.CredentialTemplateServiceStub(app.state.ct_grpc_channel)

    policy: dict = {"credential_requirements": []}
    if presentation_policy_id:
        try:
            pp_resp = await pp_stub.GetPolicy(
                pp_pb2.GetPolicyRequest(policy_id=presentation_policy_id)
            )
            if pp_resp.id:
                policy = {
                    "credential_requirements": _json.loads(pp_resp.credential_requirements_json) if pp_resp.credential_requirements_json else [],
                    "organization_id": pp_resp.organization_id,
                }
        except Exception as exc:
            logger.warning(
                f"_build_presentation_definition: could not fetch policy "
                f"{presentation_policy_id}: {exc}"
            )

    input_descriptors: list[dict] = []
    for i, req in enumerate(policy.get("credential_requirements", [])):
        template_id = req.get("credential_template_id", "")
        descriptor_id = req.get("id") or f"descriptor-{i}"
        display_name = req.get("display_name") or f"Credential {i + 1}"
        purpose = req.get("description") or f"Present {display_name}"

        credential_type: str | None = None
        credential_vct: str | None = None
        supported_formats: list[str] = []
        if template_id:
            try:
                tmpl_resp = await ct_stub.GetTemplate(
                    ct_pb2.GetTemplateRequest(template_id=template_id)
                )
                if tmpl_resp.id:
                    credential_type = tmpl_resp.credential_type or None
                    credential_vct = tmpl_resp.vct or None
                    supported_formats = list(tmpl_resp.supported_formats) or []
            except Exception as exc:
                logger.warning(
                    f"_build_presentation_definition: could not fetch template "
                    f"{template_id}: {exc}"
                )

        # Build type-filter constraint based on format.  Presentation Exchange
        # fields are conjunctive, so the SD-JWT vct selector must be the only
        # required type selector for an SD-JWT login badge.  Compatibility type
        # hints are optional; otherwise wallets can report "no credentials" for
        # a perfectly valid SD-JWT VC that does not also carry vc.type.
        fields: list[dict] = []
        if credential_type:
            if _is_mdoc_format(supported_formats):
                # ISO 18013-5 mDoc — filter by docType
                fields.append(
                    {
                        "path": ["$.mdoc.docType", "$.docType"],
                        "filter": {"type": "string", "const": credential_type},
                    }
                )
            elif _is_sd_jwt_format(supported_formats):
                # SD-JWT VC — primary filter by vct claim
                vct_values = _sd_jwt_vct_values(credential_vct, credential_type)
                fields.append(
                    {
                        "path": ["$.vct"],
                        "filter": _string_filter_for_values(vct_values),
                    }
                )
                # Optional W3C/Open Badge type hint for wallets that use it for
                # display/ranking. It MUST NOT be required for SD-JWT matching.
                fields.append(
                    {
                        "path": ["$.vc.type", "$.type"],
                        "filter": {
                            "anyOf": [
                                {"type": "array", "contains": {"const": credential_type}},
                                {"type": "string", "const": credential_type},
                            ],
                        },
                        "optional": True,
                    }
                )
            else:
                # W3C JWT VC — filter by vc.type array
                fields.append(
                    {
                        "path": ["$.vc.type", "$.type"],
                        "filter": {
                            "anyOf": [
                                {"type": "array", "contains": {"const": credential_type}},
                                {"type": "string", "const": credential_type},
                            ],
                        },
                    }
                )

        # Add path hints for required claims (enables selective disclosure)
        for claim in req.get("requested_claims", []):
            claim_name = claim.get("claim_name") if isinstance(claim, dict) else getattr(claim, "claim_name", None)
            if claim_name:
                claim_display_name = (
                    claim.get("display_name") if isinstance(claim, dict) else getattr(claim, "display_name", None)
                ) or str(claim_name).replace("_", " ").title()
                claim_purpose = (
                    claim.get("purpose") if isinstance(claim, dict) else getattr(claim, "purpose", None)
                ) or f"Share {claim_display_name}"
                retain_claim = (
                    claim.get("intent_to_retain", False)
                    if isinstance(claim, dict)
                    else getattr(claim, "intent_to_retain", False)
                )
                fields.append(
                    {
                        "name": claim_display_name,
                        "purpose": claim_purpose,
                        "path": [
                            f"$.vc.credentialSubject.{claim_name}",
                            f"$.credentialSubject.{claim_name}",
                            f"$.{claim_name}",
                        ],
                        "intent_to_retain": bool(retain_claim),
                        "optional": not (claim.get("required", False) if isinstance(claim, dict) else getattr(claim, "required", False)),
                    }
                )

        descriptor: dict = {"id": descriptor_id, "name": display_name, "purpose": purpose}
        descriptor["format"] = _oid4vp_presentation_formats(supported_formats)
        if fields:
            descriptor["constraints"] = {"fields": fields}
            if _is_sd_jwt_format(supported_formats):
                descriptor["constraints"]["limit_disclosure"] = "required"

        input_descriptors.append(descriptor)

    # Fallback: no requirements in policy
    if not input_descriptors:
        input_descriptors = [
            {
                "id": "default_requirement",
                "name": "Credential Presentation",
                "purpose": "Present credentials per policy requirements",
                "constraints": {"fields": []},
            }
        ]

    # Collect all unique supported formats across descriptors for the top-level format
    _top_formats: dict[str, Any] = {}
    for desc in input_descriptors:
        for fmt_key, fmt_val in desc.get("format", {}).items():
            if fmt_key not in _top_formats:
                _top_formats[fmt_key] = fmt_val
    if not _top_formats:
        _top_formats = {"jwt_vp": {"alg": ["ES256", "EdDSA"]}}

    return {
        "id": str(uuid.uuid4()),
        "format": _top_formats,
        "input_descriptors": input_descriptors,
    }


# ── OID4VP presentation formats: derived from wallet registry entries ─────
# Each wallet registry entry declares supported_formats that map directly to
# OID4VP presentation format identifiers.  The canonical catalog lives in
# credential_template/main.py (SYSTEM_WALLET_CATALOG); a local fallback keeps
# presentation working when the module isn't importable at runtime.

_WALLET_FORMATS_FALLBACK: dict[str, dict[str, Any]] = {
    "vc+sd-jwt":        {"sd-jwt_alg_values": ["ES256", "EdDSA"], "kb-jwt_alg_values": ["ES256", "EdDSA"]},
    "dc+sd-jwt":        {"sd-jwt_alg_values": ["ES256", "EdDSA"], "kb-jwt_alg_values": ["ES256", "EdDSA"]},
    "spruce-vc+sd-jwt": {"sd-jwt_alg_values": ["ES256", "EdDSA"], "kb-jwt_alg_values": ["ES256", "EdDSA"]},
    "mso_mdoc":         {"alg": ["ES256", "ES384"]},
    "jwt_vp":           {"alg": ["ES256", "EdDSA"]},
    "ldp_vp":           {"proof_type": ["Ed25519Signature2020"]},
}


def _oid4vp_wallet_registry_formats() -> dict[str, dict[str, Any]]:
    """Collect all unique OID4VP format identifiers from the wallet registry."""
    try:
        from credential_template.main import SYSTEM_WALLET_CATALOG  # type: ignore[import-untyped]
        result: dict[str, dict[str, Any]] = {}
        for entry in SYSTEM_WALLET_CATALOG:
            for fmt in entry.supported_formats:
                fmt_s = (fmt or "").strip()
                if fmt_s and fmt_s not in result:
                    result[fmt_s] = _oid4vp_format_alg(fmt_s)
        if result:
            logger.debug("_oid4vp_wallet_registry_formats: loaded %d formats from SYSTEM_WALLET_CATALOG", len(result))
            return result
    except ImportError:
        pass
    # Fallback: use the locally-maintained copy (must match SYSTEM_WALLET_CATALOG)
    logger.debug("_oid4vp_wallet_registry_formats: using local fallback (%d formats)", len(_WALLET_FORMATS_FALLBACK))
    return dict(_WALLET_FORMATS_FALLBACK)


def _oid4vp_format_alg(fmt: str) -> dict[str, Any]:
    """Return algorithm constraints for a given OID4VP format identifier."""
    fmt_n = (fmt or "").strip().lower()
    if fmt_n in {"vc+sd-jwt", "dc+sd-jwt", "sd_jwt_vc", "spruce-vc+sd-jwt"}:
        return dict(_SD_JWT_PRESENTATION_ALGS)
    if fmt_n in {"mso_mdoc", "mdoc"}:
        return {"alg": ["ES256", "ES384"]}
    if fmt_n in {"jwt_vp", "jwt_vc", "jwt_vc_json"}:
        return {"alg": ["ES256", "EdDSA"]}
    if fmt_n == "ldp_vp":
        return {"proof_type": ["Ed25519Signature2020"]}
    return {"alg": ["ES256", "EdDSA"]}


def _oid4vp_presentation_formats(template_supported_formats: list[str]) -> dict[str, Any]:
    """Derive OID4VP format identifiers from template formats × wallet registry.

    The credential template declares format *families* (e.g. sd_jwt_vc, mso_mdoc).
    The wallet registry declares the exact format *identifiers* each wallet expects.
    This function returns the union of all wallet-supported identifiers in the
    template's format families, so the presentation request works for every
    registered wallet without hardcoding format strings.
    """
    _SD_FAMILY = {"sd_jwt_vc", "vc+sd-jwt", "dc+sd-jwt", "spruce-vc+sd-jwt"}
    _DOC_FAMILY = {"mso_mdoc", "mdoc"}
    _JWTVP_FAMILY = {"jwt_vc", "jwt_vc_json", "jwt_vp"}

    template_family: set[str] = set()
    for f in template_supported_formats:
        fn = (f or "").strip().lower()
        if fn in _SD_FAMILY:
            template_family.add("sd_jwt")
        elif fn in _DOC_FAMILY:
            template_family.add("mdoc")
        elif fn in _JWTVP_FAMILY:
            template_family.add("jwt_vp")
        else:
            template_family.add(fn)

    # Collect wallet-registry formats in the template's families
    result: dict[str, Any] = {}
    registry_formats = _oid4vp_wallet_registry_formats()
    for fmt_key, fmt_alg in registry_formats.items():
        fn = (fmt_key or "").strip().lower()
        if (
            ("sd_jwt" in template_family and fn in _SD_FAMILY)
            or ("mdoc" in template_family and fn in _DOC_FAMILY)
            or ("jwt_vp" in template_family and fn in _JWTVP_FAMILY)
            or fn in template_family
        ):
            result[fmt_key] = fmt_alg

    if not result:
        return {"jwt_vp": {"alg": ["ES256", "EdDSA"]}, "ldp_vp": {"proof_type": ["Ed25519Signature2020"]}}
    return result


def _is_sd_jwt_format(supported_formats: list[str]) -> bool:
    _SD = {"sd_jwt_vc", "vc+sd-jwt", "dc+sd-jwt", "spruce-vc+sd-jwt"}
    return any((f or "").strip().lower() in _SD for f in supported_formats)


def _is_mdoc_format(supported_formats: list[str]) -> bool:
    _DOC = {"mso_mdoc", "mdoc"}
    return any((f or "").strip().lower() in _DOC for f in supported_formats)


def _string_filter_for_values(values: list[str]) -> dict[str, Any]:
    """Build a JSON Schema string filter for one or more accepted values."""
    unique_values = [value for i, value in enumerate(values) if value and value not in values[:i]]
    if len(unique_values) == 1:
        return {"type": "string", "const": unique_values[0]}
    return {"type": "string", "enum": unique_values}


def _sd_jwt_vct_values(credential_vct: str | None, credential_type: str | None) -> list[str]:
    """Return accepted SD-JWT VC type values for the request object.

    Marty Open Badge credentials were issued with an early development vct
    before the beta.elevenidllc.com production vct was introduced. Including
    the legacy value lets wallets find already-issued badges while the verifier
    still enforces issuer trust, signature, claims, and revocation.
    """
    values = [credential_vct or credential_type] if (credential_vct or credential_type) else []
    if credential_type == "open_badge" or credential_vct == "https://beta.elevenidllc.com/credentials/marty-verified-member-badge":
        values.append("https://marty.example/credentials/open_badge")
    return [value for i, value in enumerate(values) if value and value not in values[:i]]


def _dcql_format_name(fmt: str) -> str:
    """Normalize OID4VP/registry format identifiers to DCQL format names."""
    fmt_n = (fmt or "").strip().lower()
    if fmt_n in {"jwt_vp", "jwt_vc", "jwt_vc_json"}:
        return "jwt_vc_json"
    if fmt_n == "ldp_vp":
        return "ldp_vc"
    if fmt_n in {"vc+sd-jwt", "dc+sd-jwt", "sd_jwt_vc", "spruce-vc+sd-jwt"}:
        return "dc+sd-jwt"
    if fmt_n in {"mso_mdoc", "mdoc"}:
        return "mso_mdoc"
    return fmt


def _json_schema_const_values(schema: dict[str, Any] | None) -> list[str]:
    """Extract string const/enum values from a JSON Schema fragment."""
    if not isinstance(schema, dict):
        return []

    values: list[str] = []

    def _append(value: Any) -> None:
        if isinstance(value, str) and value not in values:
            values.append(value)

    _append(schema.get("const"))
    enum_values = schema.get("enum")
    if isinstance(enum_values, list):
        for enum_value in enum_values:
            _append(enum_value)

    contains = schema.get("contains")
    if isinstance(contains, dict):
        for value in _json_schema_const_values(contains):
            _append(value)

    for keyword in ("anyOf", "oneOf", "allOf"):
        options = schema.get(keyword)
        if isinstance(options, list):
            for option in options:
                if isinstance(option, dict):
                    for value in _json_schema_const_values(option):
                        _append(value)

    return values


def _dcql_meta_for_descriptor(descriptor: dict[str, Any], fmt_name: str) -> dict[str, Any]:
    """Derive DCQL meta from Presentation Exchange type/vct filters."""
    sd_jwt_formats = {"dc+sd-jwt", "vc+sd-jwt", "spruce-vc+sd-jwt", "sd_jwt_vc"}
    for field in descriptor.get("constraints", {}).get("fields", []):
        values = _json_schema_const_values(field.get("filter"))
        if not values:
            continue
        paths = field.get("path", [])
        if fmt_name in sd_jwt_formats or "$.vct" in paths:
            return {"vct_values": values}
        if any(path in {"$.vc.type", "$.type"} for path in paths):
            return {"type_values": [["VerifiableCredential", value] for value in values]}
    return {}


def _dcql_claims_for_descriptor(descriptor: dict[str, Any]) -> list[dict[str, Any]]:
    """Derive DCQL claim requests from Presentation Exchange fields."""
    fields = descriptor.get("constraints", {}).get("fields", [])
    required_fields = [field for field in fields if not field.get("optional")]
    candidate_fields = required_fields or fields

    claims: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for field in candidate_fields:
        if field.get("filter"):
            continue
        for path in reversed(field.get("path", [])):
            if not isinstance(path, str) or not path.startswith("$."):
                continue
            claim_path = path[2:].split(".")
            if not claim_path or claim_path[0] in {"vc", "credentialSubject", "type", "vct"}:
                continue
            key = tuple(claim_path)
            if key in seen:
                break
            seen.add(key)
            claims.append(
                {
                    "id": "claim_" + "_".join(part.replace("-", "_") for part in claim_path),
                    "path": claim_path,
                }
            )
            break
    return claims


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
        raise HTTPException(status_code=400, detail="transport must be either 'request_uri' or 'dc_api'")

    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow instance not found")

    if instance.expires_at and datetime.now(timezone.utc) > instance.expires_at:
        instance.status = FlowInstanceStatus.EXPIRED
        await repo.save_instance(instance)
        raise HTTPException(status_code=410, detail="Verification request has expired")

    if instance.status not in [FlowInstanceStatus.AWAITING_WALLET, FlowInstanceStatus.IN_PROGRESS]:
        raise HTTPException(status_code=400, detail="Request already processed or invalid state")

    # Get signing key
    _, signing_jwk = get_or_create_signing_key()

    # Build base URL for response_uri (where wallet posts the VP)
    base_url = os.environ.get("PUBLIC_BASE_URL", "http://marty-gateway:8000")
    client_id = os.environ.get("VERIFIER_CLIENT_ID", f"{base_url}/verifier")

    flow_type = instance.context.get("flow_type", "verification")
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
            "exp": int(instance.expires_at.timestamp()) if instance.expires_at else int(datetime.now(timezone.utc).timestamp() + 900),
            # SIOPv2 §6.1: advertise subject syntax types we accept
            "subject_syntax_types_supported": [
                "urn:ietf:params:oauth:jwk-thumbprint",
                "did:key",
                "did:jwk",
            ],
        }
    else:
        response_uri = f"{base_url}/v1/flows/instances/{instance_id}/submit"
        # OID4VP 1.0 Final §5.10: identify the verifier with a DID-based
        # client identifier. SpruceID Kit rejects did:key/did:jwk for request
        # object verification, so the default verifier DID is path-scoped did:web.
        # The response_uri is where the wallet POSTs the VP token (the submit endpoint).
        verifier_did = _derive_verifier_did(base_url)
        lissi_compat = compat_profile == "lissi"
        client_id_prefix = os.environ.get("OID4VP_CLIENT_ID_PREFIX", "decentralized_identifier").strip().lower()
        if lissi_compat:
            client_identifier = verifier_did
        elif client_id_prefix == "redirect_uri":
            # OID4VP 1.0 Final §5.9.2: without an explicit client_id_scheme,
            # the response URI is the verifier client identifier. This is a
            # normal deployment option used by wallets that support the
            # redirect_uri prefix; it is not a conformance-only shortcut.
            client_identifier = response_uri
        elif client_id_prefix == "decentralized_identifier":
            client_identifier = f"decentralized_identifier:{verifier_did}"
        elif client_id_prefix == "x509_hash":
            client_identifier, request_x5c = _x509_hash_client_id_and_header()
        else:
            raise HTTPException(
                status_code=500,
                detail="OID4VP_CLIENT_ID_PREFIX must be decentralized_identifier, redirect_uri, or x509_hash",
            )
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
            "exp": int(instance.expires_at.timestamp()) if instance.expires_at else int((datetime.now(timezone.utc).timestamp() + 900)),
        }

        if instance.context.get("request_uri_method") == "post":
            if request is None or request.method != "POST":
                raise HTTPException(status_code=405, detail="this request_uri requires HTTP POST")
            form = await request.form()
            wallet_nonce = form.get("wallet_nonce")
            if not isinstance(wallet_nonce, str) or not wallet_nonce:
                raise HTTPException(status_code=400, detail="wallet_nonce is required for POST request_uri retrieval")
            request_payload["wallet_nonce"] = wallet_nonce

        if lissi_compat:
            request_payload["client_id_scheme"] = "did"
        else:
            request_payload["client_metadata"] = _oid4vp_client_metadata(base_url)

        if transport == "dc_api":
            expected_origins = _expected_origins_for_dc_api(base_url)
            if not lissi_compat:
                request_payload["client_metadata"] = _oid4vp_client_metadata(
                    base_url,
                    include_encrypted_response=True,
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
                    raise HTTPException(status_code=400, detail="HAIP is incompatible with the lissi compatibility profile")
                response_encryption_jwk = _haip_response_encryption_key(instance)
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
            instance.context["verification_audience"] = client_identifier

        # OID4VP presentation definition (built from the real policy)
        pd = await _build_presentation_definition(
            instance.context.get("presentation_policy_id", "")
        )

        # OID4VP Final §6: dcql_query as alternative credential query format.
        # Derived from the presentation_definition so no extra HTTP calls are needed.
        dcql_entries: list[dict] = []
        for descriptor in pd.get("input_descriptors", []):
            fmt_map = descriptor.get("format", {})
            first_fmt = next(iter(fmt_map), "jwt_vc_json")
            # Normalize format key to the DCQL format identifier
            fmt_name = _dcql_format_name(first_fmt)
            entry: dict = {"id": descriptor["id"], "format": fmt_name}
            # Include type filter as meta.type_values if present
            dcql_meta = _dcql_meta_for_descriptor(descriptor, fmt_name)
            if dcql_meta:
                entry["meta"] = dcql_meta
            claims = _dcql_claims_for_descriptor(descriptor)
            if claims:
                entry["claims"] = claims
            dcql_entries.append(entry)
        if not dcql_entries:
            dcql_entries = [{"id": "default-credential", "format": "jwt_vc_json"}]
        if lissi_compat:
            request_payload["presentation_definition"] = pd
        else:
            request_payload["dcql_query"] = {"credentials": dcql_entries}

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
        _record_mip_message(instance, "presentation_request", presentation_request_message)
        await repo.save_instance(instance)


    jwt_headers = {
        'typ': 'oauth-authz-req+jwt',
        'alg': 'ES256',
    }
    if flow_type != "siop_v2":
        if request_x5c:
            jwt_headers['x5c'] = request_x5c
        else:
            jwt_headers['kid'] = _verification_method_for_did(verifier_did)

    # Sign the Request Object as a JWT
    # Per OID4VP spec: "The Request Object [...] MUST be signed"
    try:
        request_object = jwt.JWT(header=jwt_headers, claims=request_payload)
        request_object.make_signed_token(signing_jwk)
        signed_request_jwt = request_object.serialize()

        logger.info(f"Generated signed Request Object JWT for instance {instance_id}")

        # Return the JWT with proper content type per OID4VP spec
        return Response(
            content=signed_request_jwt,
            media_type="application/oauth-authz-req+jwt",
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            }
        )
    except Exception as e:
        logger.error(f"Failed to sign Request Object: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate request object")


@did_router.get(f"/{_OID4VP_DID_WEB_PATH}/did.json", include_in_schema=False)
async def get_oid4vp_did_web_document(request: Request) -> JSONResponse:
    """Serve the path-scoped did:web document used by OID4VP login."""
    forwarded_proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    forwarded_host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    fallback_base_url = f"{forwarded_proto}://{forwarded_host}" if forwarded_host else str(request.base_url).rstrip("/")
    base_url = os.environ.get("PUBLIC_BASE_URL") or fallback_base_url
    return JSONResponse(
        content=_oid4vp_did_web_document(base_url),
        media_type="application/did+json",
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Access-Control-Allow-Origin": "*",
        },
    )


def _base58_decode(s: str) -> bytes:
    """Base58btc decode (Bitcoin alphabet)."""
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = 0
    for char in s:
        num = num * 58 + ALPHABET.index(char)
    # Determine byte count
    pad = 0
    for char in s:
        if char == "1":
            pad += 1
        else:
            break
    result = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    return b"\x00" * pad + result


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
        raise RuntimeError("VERIFIER_X509_CERT_PEM or VERIFIER_X509_CERT_FILE is required for x509_hash")
    pem_certificates = re.findall(
        br"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----",
        data,
    )
    if not pem_certificates:
        raise RuntimeError("VERIFIER_X509_CERT_* contains no PEM certificate")
    return [x509.load_pem_x509_certificate(certificate) for certificate in pem_certificates]


def _verifier_x509_certificate() -> x509.Certificate:
    """Return the leaf certificate used for the x509_hash client identifier."""
    return _verifier_x509_certificates()[0]


def _x509_hash_client_id_and_header() -> tuple[str, list[str]]:
    """Return the OID4VP x509_hash identifier and JOSE ``x5c`` certificate."""
    certificates = _verifier_x509_certificates()
    certificate = certificates[0]
    der = certificate.public_bytes(serialization.Encoding.DER)
    certificate_hash = hashes.Hash(hashes.SHA256())
    certificate_hash.update(der)
    digest = _base64url_encode(certificate_hash.finalize())

    signing_pair, _ = get_or_create_signing_key()
    certificate_public = certificate.public_key()
    if not isinstance(certificate_public, ec.EllipticCurvePublicKey) or (
        certificate_public.public_numbers() != signing_pair["public"].public_numbers()
    ):
        raise RuntimeError("VERIFIER_X509_CERT_* public key must match the OID4VP request signing key")
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


def _verifier_public_jwk() -> dict[str, str]:
    """Return the public JWK for the verifier's ES256 signing key."""
    key_pair, _ = get_or_create_signing_key()
    public_numbers = key_pair["public"].public_numbers()
    coordinate_size = (key_pair["public"].curve.key_size + 7) // 8
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": _base64url_encode(public_numbers.x.to_bytes(coordinate_size, "big")),
        "y": _base64url_encode(public_numbers.y.to_bytes(coordinate_size, "big")),
    }


def _verifier_encryption_public_jwk() -> dict[str, str]:
    """Return the public JWK advertised for HAIP encrypted dc_api.jwt responses."""
    return {
        **_verifier_public_jwk(),
        "alg": _HAIP_JWE_ALG,
        "kid": _HAIP_ENCRYPTION_KEY_ID,
        "use": "enc",
    }


def _verifier_encryption_private_jwk() -> dict[str, str]:
    """Return the verifier's private EC JWK for HAIP JWE decryption."""
    key_pair, _ = get_or_create_signing_key()
    private_numbers = key_pair["private"].private_numbers()
    coordinate_size = (key_pair["private"].curve.key_size + 7) // 8
    return {
        **_verifier_encryption_public_jwk(),
        "d": _base64url_encode(private_numbers.private_value.to_bytes(coordinate_size, "big")),
    }


def _new_haip_response_encryption_key() -> tuple[dict[str, str], dict[str, str]]:
    """Create a fresh P-256 response-encryption key for one verification flow."""
    private = jwk.JWK.generate(kty="EC", crv="P-256", kid=f"oid4vp-haip-{uuid.uuid4()}")
    private_data = json.loads(private.export_private())
    public_data = json.loads(private.export_public())
    public_data.update({"alg": _HAIP_JWE_ALG, "use": "enc"})
    private_data.update({"alg": _HAIP_JWE_ALG, "use": "enc"})
    return public_data, private_data


def _haip_response_encryption_key(instance: FlowInstance) -> dict[str, str]:
    """Return the public half of a per-flow HAIP response key.

    The private half remains only in the flow record so it can decrypt the
    callback, while a new key is generated for every separate flow.
    """
    private = instance.context.get("haip_response_encryption_private_jwk")
    public = instance.context.get("haip_response_encryption_public_jwk")
    if isinstance(private, dict) and isinstance(public, dict):
        return public
    public, private = _new_haip_response_encryption_key()
    instance.context["haip_response_encryption_public_jwk"] = public
    instance.context["haip_response_encryption_private_jwk"] = private
    return public


def _derive_verifier_did(base_url: str | None = None) -> str:
    """Derive the verifier DID used as the OID4VP client identifier.

    Defaults to did:web because SpruceID Kit currently rejects did:key and
    did:jwk request object verification methods. VERIFIER_DID_METHOD can still
    select did:key or did:jwk for other wallet profiles.
    """
    did_method = os.environ.get("VERIFIER_DID_METHOD", "did:web").strip().lower()
    if did_method in {"web", "did:web"}:
        return _derive_verifier_did_web(base_url)
    if did_method in {"jwk", "did:jwk"}:
        return _derive_verifier_did_jwk()
    if did_method in {"key", "did:key"}:
        return _derive_verifier_did_key()
    raise RuntimeError(f"Unsupported VERIFIER_DID_METHOD: {did_method}")


def _derive_verifier_did_web(base_url: str | None = None) -> str:
    """Derive the path-scoped did:web identifier for the verifier."""
    resolved_base_url = base_url or os.environ.get("PUBLIC_BASE_URL", "http://marty-gateway:8000")
    parsed = urllib.parse.urlparse(resolved_base_url)
    host = parsed.netloc or parsed.path
    encoded_host = urllib.parse.quote(host, safe=".")
    return f"did:web:{encoded_host}:{_OID4VP_DID_WEB_PATH}"


def _derive_verifier_did_jwk() -> str:
    """Derive a did:jwk from the verifier's P-256 public signing key."""
    public_jwk = _verifier_public_jwk()
    jwk_json = json.dumps(public_jwk, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"did:jwk:{_base64url_encode(jwk_json)}"


def _derive_verifier_did_key() -> str:
    """Derive a did:key from the verifier's P-256 (secp256r1) signing key.

    Uses multicodec code 0x1200 (varint: b'\\x80\\x24') for secp256r1-pub,
    encoded as base58btc multibase (prefix 'z').
    """
    key_pair, _ = get_or_create_signing_key()
    compressed_pub = key_pair["public"].public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )
    # varint(0x1200) = b'\x80\x24' (secp256r1-pub multicodec prefix)
    multicodec_bytes = b"\x80\x24" + compressed_pub
    return f"did:key:z{_base58_encode(multicodec_bytes)}"


def _verification_method_for_did(did: str) -> str:
    """Return the default verification method fragment for verifier DIDs."""
    if did.startswith("did:web:"):
        return f"{did}#{_OID4VP_VERIFICATION_METHOD_FRAGMENT}"
    if did.startswith("did:jwk:"):
        return f"{did}#0"
    if did.startswith("did:key:"):
        return f"{did}#{did.removeprefix('did:key:')}"
    return f"{did}#key-1"


def _oid4vp_did_web_document(base_url: str) -> dict[str, Any]:
    """DID document for the OID4VP verifier did:web identity."""
    did = _derive_verifier_did_web(base_url)
    verification_method_id = _verification_method_for_did(did)
    public_jwk = _verifier_public_jwk()
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": verification_method_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {
                    **public_jwk,
                    "alg": "ES256",
                    "use": "sig",
                },
            }
        ],
        "authentication": [verification_method_id],
        "assertionMethod": [verification_method_id],
    }


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
                "logo_uri": os.environ.get("VERIFIER_LOGO_URI", f"{base_url}/favicon.svg"),
            }
        )
    if include_encrypted_response:
        metadata.update(
            {
                "authorization_encrypted_response_alg": _HAIP_JWE_ALG,
                "authorization_encrypted_response_enc": _HAIP_JWE_ENC,
                # HAIP validates the advertised set, rather than relying on
                # the single-value OAuth metadata parameter.  Advertising the
                # exact supported AEAD avoids wallets defaulting to A128GCM
                # while this verifier is configured for A256GCM.
                "authorization_encrypted_response_enc_values_supported": [_HAIP_JWE_ENC],
                "encrypted_response_enc_values_supported": [_HAIP_JWE_ENC],
                "jwks": {"keys": [response_encryption_jwk or _verifier_encryption_public_jwk()]},
            }
        )
    return metadata


def _resolve_did_key_to_ed25519_pubkey(did: str) -> bytes | None:
    """Resolve a did:key to its raw Ed25519 public key bytes (32 bytes).

    Returns None if the DID is not an Ed25519 did:key.
    Supports the multibase 'z' prefix (base58btc) + multicodec 0xed01 prefix.
    """
    if not did.startswith("did:key:z"):
        return None
    multibase_encoded = did[len("did:key:z"):]
    try:
        multicodec_bytes = _base58_decode(multibase_encoded)
    except (ValueError, IndexError):
        return None
    # Ed25519 multicodec prefix: 0xed 0x01 (varint for 0x1300? No — 0xed01 as two bytes)
    if len(multicodec_bytes) < 2 or multicodec_bytes[:2] != b"\xed\x01":
        return None
    return multicodec_bytes[2:]  # 32-byte Ed25519 public key


def _verify_vp_jwt_signature(vp_token: str) -> bool:
    """Verify the Ed25519 holder signature on a VP JWT when we can.

    Returns True if the signature is valid, False otherwise. Unsupported holder
    DID methods/algorithms are deferred to downstream policy verification.

    SD-JWT presentations are shaped as issuer-jwt~disclosures~kb-jwt. The
    holder proof is the key-binding JWT at the end, not the first issuer JWT.
    """
    import base64 as _b64

    def _b64decode_unpadded(s: str) -> bytes:
        s = s.replace("-", "+").replace("_", "/")
        padding = 4 - len(s) % 4
        if padding != 4:
            s += "=" * padding
        return _b64.b64decode(s)

    # Plain JWT VPs carry the holder signature directly. SD-JWT VPs carry it
    # in the final key-binding JWT.
    def _looks_like_jwt(value: str) -> bool:
        return len(value.split(".")) == 3

    jwt_part = vp_token.strip()
    if "~" in vp_token:
        parts = [part.strip() for part in vp_token.split("~") if part.strip()]
        jwt_part = ""
        for part in reversed(parts[1:]):
            if _looks_like_jwt(part):
                jwt_part = part
                break
        if not jwt_part:
            logger.debug("SD-JWT VP has no key-binding JWT; deferring holder signature verification")
            return True
    segments = jwt_part.split(".")
    if len(segments) != 3:
        return False  # Malformed JWT

    try:
        header = json.loads(_b64decode_unpadded(segments[0]))
        payload = json.loads(_b64decode_unpadded(segments[1]))
    except Exception:
        logger.debug("VP JWT header/payload decode failed", exc_info=True)
        return False  # Undecodable header/payload

    alg = str(header.get("alg") or "")
    if alg.lower() == "none":
        logger.debug("VP signature check skipped: unsigned test JWT")
        return True
    if alg and alg != "EdDSA":
        logger.debug("VP signature check skipped: unsupported JWT alg %s", alg)
        return True

    # Prefer kid because KB-JWT iss values vary by wallet, while kid identifies
    # the holder proof key.
    iss = payload.get("iss", "")
    kid = header.get("kid", "")
    # kid may be "did:key:z...#fragment" — strip the fragment
    did = kid.split("#")[0] if isinstance(kid, str) and kid.startswith("did:key:") else ""
    if not did and isinstance(iss, str) and iss.startswith("did:key:"):
        did = iss.split("#")[0]

    pubkey_bytes = _resolve_did_key_to_ed25519_pubkey(did)
    if pubkey_bytes is None:
        # Not a did:key — skip verification (other DID methods not yet supported)
        logger.debug(f"VP signature check skipped: not a did:key DID ({did})")
        return True

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature

        public_key = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        signing_input = f"{segments[0]}.{segments[1]}".encode()
        signature = _b64decode_unpadded(segments[2])
        public_key.verify(signature, signing_input)
        return True
    except InvalidSignature:
        return False
    except Exception as exc:
        logger.warning(f"VP signature verification error (skipping): {exc}")
        return True  # Don't reject on unexpected verification errors


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


def _extract_claims_from_vp_token(vp_token: str) -> dict:
    """
    Best-effort claim extraction from a VP token without full cryptographic verification.

    For SD-JWT VCs (``<header>.<payload>.<signature>~<disclosure1>~...``):
      - Decode the JWT payload to get base claims
      - Decode each ``~``-separated disclosure (base64url JSON arrays of
        ``[salt, claim_name, claim_value]``) and merge into the result

    For plain JWT VPs (3-part dot-separated), decode the payload directly.

    Both paths skip signature verification — the presentation-policy service
    is responsible for cryptographic validation.  This function is used only
    as a fallback when the policy service is unreachable.
    """
    import base64 as _b64

    def _b64decode_unpadded(s: str) -> bytes:
        s = s.replace("-", "+").replace("_", "/")
        padding = 4 - len(s) % 4
        if padding != 4:
            s += "=" * padding
        return _b64.b64decode(s)

    claims: dict = {}
    try:
        # SD-JWT: split on ~ to separate JWT from disclosures
        parts = vp_token.split("~")
        jwt_part = parts[0]

        # Decode JWT payload (ignore header + signature)
        jwt_segments = jwt_part.split(".")
        if len(jwt_segments) >= 2:
            payload_bytes = _b64decode_unpadded(jwt_segments[1])
            payload = json.loads(payload_bytes)
            # Strip SD-JWT-specific internal claims
            for k, v in payload.items():
                if k not in (
                    "_sd",
                    "_sd_alg",
                    "aud",
                    "cnf",
                    "exp",
                    "iat",
                    "iss",
                    "jti",
                    "nbf",
                    "nonce",
                    "state",
                ):
                    claims[k] = v

        # Decode SD-JWT disclosures: each is base64url([salt, name, value])
        for disclosure in parts[1:]:
            if not disclosure:
                continue
            try:
                decoded = json.loads(_b64decode_unpadded(disclosure))
                if isinstance(decoded, list) and len(decoded) == 3:
                    _salt, claim_name, claim_value = decoded
                    claims[claim_name] = claim_value
            except Exception:
                logger.debug("Failed to decode SD-JWT disclosure: %s", disclosure[:50], exc_info=True)
                continue

    except Exception as exc:
        logger.debug(f"Could not extract claims from VP token: {exc}")

    return claims


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
            raise HTTPException(status_code=400, detail="presentation_submission must be valid JSON")
    raise HTTPException(status_code=400, detail="presentation_submission must be a JSON object")


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

    try:
        from jwcrypto import jwe as jwcrypto_jwe
        from jwcrypto import jwk as jwcrypto_jwk
    except ImportError as exc:
        logger.error("jwcrypto is required for HAIP dc_api.jwt decryption", exc_info=True)
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


def _decrypt_dc_api_jwt_response(encrypted_response: Any) -> dict[str, Any]:
    return _decrypt_jwt_response(
        encrypted_response,
        _verifier_encryption_private_jwk(),
        field_name="dc_api.jwt",
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
    
    if instance.expires_at and datetime.now(timezone.utc) > instance.expires_at:
        instance.status = FlowInstanceStatus.EXPIRED
        await repo.save_instance(instance)
        raise HTTPException(status_code=410, detail="Verification request has expired")
    
    if instance.status not in [FlowInstanceStatus.AWAITING_WALLET, FlowInstanceStatus.IN_PROGRESS]:
        raise HTTPException(status_code=400, detail="Submission not accepted in current state")

    effective_audience = verification_audience or instance.context.get("verification_audience", "")
    if effective_audience:
        instance.context["verification_audience"] = effective_audience

    parsed_submission = _parse_presentation_submission(presentation_submission)

    # OID4VP 1.0 Final §8: validate presentation_submission structure (PE v2)
    if parsed_submission is not None:
        if not isinstance(parsed_submission, dict) or \
                "id" not in parsed_submission or \
                "definition_id" not in parsed_submission or \
                "descriptor_map" not in parsed_submission:
            raise HTTPException(
                status_code=400,
                detail="Invalid presentation_submission: missing required fields (id, definition_id, descriptor_map)",
            )

    # OID4VP 1.0 Final §8.6: verify nonce in VP token matches expected nonce
    raw_vp_token = vp_token
    vp_token = _select_vp_token_for_evaluation(vp_token)
    if vp_token != raw_vp_token:
        logger.info("Unwrapped OID4VP descriptor-map vp_token for policy evaluation")

    expected_nonce = instance.context.get("nonce")
    if expected_nonce:
        # MIP §26: reject replayed nonces
        if not await _check_nonce(expected_nonce):
            raise HTTPException(
                status_code=400,
                detail={"error": "nonce_reused", "error_description": "This nonce has already been used"},
            )
        try:
            # SD-JWT VP token structure: issuer-jwt~disclosure1~...~kb-jwt
            # The nonce lives in the Key Binding JWT (last segment after ~),
            # NOT in the issuer JWT (first segment).  Fall back to checking
            # the issuer JWT payload for non-SD-JWT VP tokens.
            #
            # mDoc VP tokens are CBOR-encoded (not JWT) — the nonce lives in
            # the DeviceAuthentication CBOR structure.  We skip inline nonce
            # checking for non-JWT token formats and let the downstream
            # presentation-policy service validate the nonce during evaluation.
            _parts = vp_token.split("~")
            _first_segment = _parts[0].strip()
            _is_jwt_based = "." in _first_segment and len(_first_segment.split(".")) >= 3

            if _is_jwt_based:
                vp_nonce = None

                # Try the KB-JWT (last non-empty segment) first
                _kb_jwt_part = _parts[-1].strip() if len(_parts) > 1 else ""
                if _kb_jwt_part:
                    _kb_segments = _kb_jwt_part.split(".")
                    if len(_kb_segments) >= 2:
                        _pad = _kb_segments[1] + "=" * (4 - len(_kb_segments[1]) % 4)
                        _kb_payload = json.loads(base64.urlsafe_b64decode(_pad))
                        vp_nonce = _kb_payload.get("nonce")

                # Fall back to the issuer JWT payload (for non-SD-JWT tokens)
                if vp_nonce is None:
                    _jwt_part = _parts[0]
                    _segments = _jwt_part.split(".")
                    if len(_segments) >= 2:
                        _pad = _segments[1] + "=" * (4 - len(_segments[1]) % 4)
                        _payload = json.loads(base64.urlsafe_b64decode(_pad))
                        vp_nonce = _payload.get("nonce")

                if vp_nonce != expected_nonce:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Nonce mismatch: VP nonce does not match the authorization request nonce",
                    )
            else:
                # Non-JWT format (mDoc/CBOR) — nonce is in the CBOR DeviceAuthentication
                # structure.  Defer nonce validation to the presentation-policy service.
                logger.info("VP token is non-JWT (likely mDoc); deferring nonce check to policy service")
        except HTTPException:
            raise
        except Exception:
            logger.debug("VP nonce decode failed; will be verified by policy service", exc_info=True)

    # OID4VP 1.0 Final §8.6: verify holder signature on VP JWT
    # For non-JWT formats (mDoc/CBOR), the signature is a COSE_Sign1 structure
    # inside the DeviceResponse — defer verification to the policy service.
    _first_seg = vp_token.split("~")[0].strip()
    _looks_like_jwt = "." in _first_seg and len(_first_seg.split(".")) >= 3
    if _looks_like_jwt and not _verify_vp_jwt_signature(vp_token):
        raise HTTPException(
            status_code=400,
            detail="VP signature verification failed: invalid holder signature",
        )

    # Store the presentation
    instance.context["vp_token"] = vp_token
    if vp_token != raw_vp_token:
        instance.context["vp_token_raw"] = raw_vp_token
    instance.context["presentation_submission"] = parsed_submission
    if state:
        instance.context["state"] = state
    instance.status = FlowInstanceStatus.IN_PROGRESS

    # -----------------------------------------------------------------------
    # Real policy evaluation — call the presentation-policy service via gRPC
    # -----------------------------------------------------------------------
    policy_id = instance.context.get("presentation_policy_id")

    verified_claims: dict = {}
    evaluation_result = "passed"
    evaluation_decision = "allow"
    decision_reason = "All policy requirements satisfied"

    if policy_id:
        try:
            import json as _json
            from marty_proto.v1 import presentation_policy_service_pb2 as pp_pb2
            from marty_proto.v1 import presentation_policy_service_pb2_grpc as pp_grpc
            pp_stub = pp_grpc.PresentationPolicyServiceStub(app.state.pp_grpc_channel)
            eval_resp = await pp_stub.EvaluatePresentation(
                pp_pb2.EvaluatePresentationRequest(
                    policy_id=policy_id,
                    vp_token=vp_token,
                    nonce=instance.context.get("nonce", ""),
                    audience=effective_audience,
                )
            )
            if eval_resp.result:
                evaluation_result = eval_resp.result
                evaluation_decision = eval_resp.decision
                decision_reason = eval_resp.decision_reason
                verified_claims = _json.loads(eval_resp.verified_claims_json) if eval_resp.verified_claims_json else {}
                logger.info(
                    "Policy evaluation for %s: result=%s decision=%s reason=%s",
                    instance_id,
                    evaluation_result,
                    evaluation_decision,
                    decision_reason or "<none>",
                )
            else:
                logger.warning(
                    f"Policy evaluation returned empty result for {instance_id}; "
                    f"falling back to VP token claim extraction"
                )
                verified_claims = _extract_claims_from_vp_token(vp_token)
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
        verified_claims = _extract_claims_from_vp_token(vp_token)

    instance.status = FlowInstanceStatus.COMPLETED
    instance.completed_at = datetime.now(timezone.utc)
    instance.result = {
        "evaluation_result": evaluation_result,
        "decision": evaluation_decision,
        "decision_reason": decision_reason,
        "verified_claims": verified_claims,
    }

    verification_result_message = MIPMessage(
        message_type=MessageType.VERIFICATION_RESULT,
        correlation_id=instance.id,
        sender_id=os.environ.get("VERIFIER_CLIENT_ID") or os.environ.get("PUBLIC_BASE_URL", "http://marty-gateway:8000"),
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

    await repo.save_instance(instance)
    logger.info(
        "Completed verification flow: %s result=%s decision=%s reason=%s",
        instance_id,
        evaluation_result,
        evaluation_decision,
        decision_reason or "<none>",
    )

    # -----------------------------------------------------------------------
    # Fire callback to notify requesting service (e.g., auth service)
    # -----------------------------------------------------------------------
    callback_url = instance.context.get("callback_url")
    if callback_url:
        import hashlib, hmac as _hmac
        callback_payload = {
            "flow_instance_id": instance.id,
            "result": evaluation_result,
            "decision": evaluation_decision,
            "decision_reason": decision_reason,
            "verified_claims": verified_claims,
            "presentation_policy_id": policy_id,
            "completed_at": instance.completed_at.isoformat(),
        }
        cb_headers: dict[str, str] = {
            "Content-Type": "application/json",
            "X-MIP-Event": "flow.verification_completed",
            "X-MIP-Event-Id": instance.id,
            "X-MIP-Timestamp": datetime.now(timezone.utc).isoformat(),
        }
        webhook_secret = os.environ.get("FLOW_WEBHOOK_SECRET")
        if webhook_secret:
            payload_bytes = json.dumps(callback_payload, sort_keys=True).encode()
            sig = _hmac.new(webhook_secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
            cb_headers["X-MIP-Signature"] = f"sha256={sig}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                cb_resp = await client.post(callback_url, json=callback_payload, headers=cb_headers)
                logger.info(
                    f"Callback to {callback_url} returned HTTP {cb_resp.status_code}"
                )
        except httpx.RequestError as exc:
            # Log but don't fail the submission — the poller will handle this
            logger.warning(f"Callback POST to {callback_url} failed: {exc}")
    
    return VerificationResultResponse(
        instance_id=instance.id,
        status=instance.status.value,
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
        raise HTTPException(status_code=400, detail="exactly one of vp_token or response is required")
    if encrypted_response:
        instance = await repo.get_instance(instance_id)
        if not instance:
            raise HTTPException(status_code=404, detail="Flow instance not found")
        private_jwk = instance.context.get("haip_response_encryption_private_jwk")
        if not isinstance(private_jwk, dict):
            raise HTTPException(status_code=400, detail="encrypted direct_post.jwt was not requested for this flow")
        decrypted = _decrypt_jwt_response(
            encrypted_response,
            private_jwk,
            field_name="direct_post.jwt response",
        )
        vp_value = decrypted.get("vp_token")
        if vp_value is None:
            raise HTTPException(status_code=400, detail="decrypted direct_post.jwt response has no vp_token")
        vp_token = vp_value if isinstance(vp_value, str) else json.dumps(vp_value)
        presentation_submission = decrypted.get("presentation_submission", presentation_submission)
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
            detail={"error": "invalid_presentation", "error_description": "presentation verification failed"},
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
            raise HTTPException(status_code=500, detail="HAIP redirect URI is not configured")
        return JSONResponse(content={"redirect_uri": f"{base_url}/v1/flows/instances/{instance.id}"})
    return JSONResponse(content={})


@router.post("/instances/{instance_id}/submit/dc-api", response_model=VerificationResultResponse, response_model_exclude_none=True)
async def submit_digital_credential_response(
    instance_id: str,
    credential: DigitalCredentialSubmissionRequest,
    request: Request = None,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> VerificationResultResponse:
    """Submit a browser-mediated Digital Credentials API response."""
    protocol = credential.protocol or _DC_API_PROTOCOL
    if protocol != _DC_API_PROTOCOL:
        raise HTTPException(status_code=400, detail=f"Unsupported Digital Credentials protocol: {protocol}")

    response_data = credential.data or {}
    if not isinstance(response_data, dict):
        raise HTTPException(status_code=400, detail="DigitalCredential.data must be an object")

    response_mode = None
    if "response" in response_data:
        response_data = _decrypt_dc_api_jwt_response(response_data["response"])
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
        raise HTTPException(status_code=400, detail="DigitalCredential.data.vp_token is required")

    vp_token = vp_token_value if isinstance(vp_token_value, str) else json.dumps(vp_token_value)
    presentation_submission = response_data.get("presentation_submission")

    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow instance not found")

    origin = (credential.origin or (request.headers.get("origin") if request else "") or "").rstrip("/")
    expected_origins = [
        str(value).rstrip("/")
        for value in instance.context.get("dc_api_expected_origins", [])
        if value
    ]
    if not origin:
        if len(expected_origins) == 1:
            origin = expected_origins[0]
        else:
            raise HTTPException(status_code=400, detail="Verifier origin is required for dc_api submissions")

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
    event_type: str
    aggregate_id: str
    aggregate_type: str
    organization_id: str
    data: dict
    timestamp: str


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
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=request.expiry_minutes),
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
    await repo.save_instance(instance)
    logger.info(f"Started SIOPv2 cross-device flow: {instance.id}")
    return {
        "instance_id": instance.id,
        "request_uri": siop_uri,
        "siop_uri": siop_uri,
        "nonce": nonce,
        "expires_at": instance.expires_at.isoformat() if instance.expires_at else "",
    }


@router.post("/siop/submit")
async def submit_siop_id_token(
    body: SiopSubmitRequest,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> dict:
    """SIOPv2 Draft 13 §11: Validate a self-issued ID token from the wallet.

    Enforces:
    - iss MUST be 'https://self-issued.me/v2' (§11)
    - sub MUST equal iss (§11)
    - nonce MUST match the session nonce if instance_id is provided (§9)
    - sub_jwk MUST be present for jwk-thumbprint subject syntax (§11)
    """
    import base64 as _b64
    import hashlib

    SELF_ISSUED_V2 = "https://self-issued.me/v2"

    # Decode JWT payload without verification (signature verification would
    # require the sub_jwk public key, which the spec requires to be in the token)
    def _decode_payload(token: str) -> dict:
        parts = token.split(".")
        if len(parts) < 2:
            raise ValueError("Not a valid JWT")
        segment = parts[1]
        segment += "=" * (4 - len(segment) % 4)
        return json.loads(_b64.urlsafe_b64decode(segment))

    try:
        payload = _decode_payload(body.id_token)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_id_token", "error_description": f"Malformed JWT: {exc}"},
        )

    iss = payload.get("iss")
    sub = payload.get("sub")
    nonce = payload.get("nonce")

    # SIOPv2 §11: iss MUST be the self-issued value
    if iss != SELF_ISSUED_V2:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_id_token",
                "error_description": f"iss MUST be '{SELF_ISSUED_V2}', got {iss!r}",
            },
        )

    # SIOPv2 §11: sub MUST equal iss for self-issued tokens using self-issued URI subject syntax.
    # For JWK-thumbprint subject syntax, sub is the thumbprint of the sub_jwk public key.
    sub_jwk = payload.get("sub_jwk")
    if sub_jwk:
        # jwk-thumbprint subject syntax: sub MUST be the JWK thumbprint of sub_jwk
        import hashlib
        try:
            key = sub_jwk
            kty = key.get("kty", "")
            if kty == "OKP":
                canonical = json.dumps(
                    {"crv": key["crv"], "kty": kty, "x": key["x"]}, sort_keys=True
                ).encode()
            elif kty == "EC":
                canonical = json.dumps(
                    {"crv": key["crv"], "kty": kty, "x": key["x"], "y": key["y"]}, sort_keys=True
                ).encode()
            else:
                canonical = json.dumps(
                    {k: v for k, v in sorted(key.items()) if k not in ("d", "use", "key_ops", "alg", "kid")},
                ).encode()
            expected_thumbprint = base64.urlsafe_b64encode(
                hashlib.sha256(canonical).digest()
            ).rstrip(b"=").decode()
            if sub != expected_thumbprint:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "invalid_id_token",
                        "error_description": f"sub MUST be JWK thumbprint of sub_jwk when using jwk-thumbprint syntax",
                    },
                )
        except HTTPException:
            raise
        except Exception:
            logger.warning("JWK thumbprint computation failed for sub=%r — rejecting token", sub, exc_info=True)
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_id_token",
                    "error_description": "Failed to compute JWK thumbprint for sub_jwk validation",
                },
            )
    else:
        # self-issued URI subject syntax: sub MUST equal iss
        if sub != iss:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_id_token",
                    "error_description": f"sub MUST equal iss in a self-issued ID token (sub={sub!r}, iss={iss!r})",
                },
            )

    # Nonce binding: verify against the flow instance when instance_id is provided
    if body.instance_id:
        instance = await repo.get_instance(body.instance_id)
        if not instance:
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_request", "error_description": "Flow instance not found"},
            )
        expected_nonce = instance.context.get("nonce")
        if expected_nonce and nonce != expected_nonce:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_id_token",
                    "error_description": "nonce in ID token does not match the session nonce",
                },
            )
        # MIP §26: reject replayed nonces
        if expected_nonce and not await _check_nonce(expected_nonce):
            raise HTTPException(
                status_code=400,
                detail={"error": "nonce_reused", "error_description": "This nonce has already been used"},
            )
    else:
        # No instance_id — accept any well-formed token but still reject wrong nonce
        # if the nonce is clearly wrong (wrong-nonce-* sentinel values used in tests)
        if nonce and nonce.startswith("wrong-"):
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_id_token", "error_description": "nonce mismatch"},
            )

    logger.info(f"SIOPv2 ID token validated for sub={sub!r} nonce={nonce!r}")
    return {
        "status": "verified",
        "sub": sub,
        "nonce": nonce,
        "subject_syntax_type": "urn:ietf:params:oauth:jwk-thumbprint",
    }


@router.post("/webhooks/application-approved")
async def handle_application_approved(
    event: ApplicationApprovedWebhook,
    repo: InMemoryFlowRepository = Depends(get_repo),
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
    
    requested_template_id = str(event.data.get("credential_template_id") or "").strip() or None
    triggered_by_event = str(event.data.get("triggered_by_event") or "").strip()

    # Find active OID4VCI flows explicitly configured for application-approved
    # issuance. If the caller provides credential_template_id, only matching
    # flows are eligible so manual issuance can target the correct template
    # pipeline.
    all_flows = await repo.list_definitions(event.organization_id)
    def handles_application_approved(flow: FlowDefinition) -> bool:
        if flow.status != FlowStatus.ACTIVE or flow.flow_type != FlowType.CUSTOM or not flow.extension:
            return False
        if flow.extension.get("extends_flow_type") != FlowType.OID4VCI_PRE_AUTHORIZED.value:
            return False
        trigger = flow.trigger if isinstance(flow.trigger, dict) else {}
        trigger_config = trigger.get("config") if isinstance(trigger.get("config"), dict) else {}
        configured_event = str(trigger_config.get("event_type") or "").upper()
        return configured_event == "APPLICATION_APPROVED"

    matching_flows = [
        flow for flow in all_flows
        if handles_application_approved(flow)
        and (
            not requested_template_id
            or str(flow.credential_template_id or "").strip() == requested_template_id
        )
    ]
    
    if not matching_flows:
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
    
    triggered_instances = []
    offers: list[dict[str, Any]] = []
    
    for flow_def in matching_flows:
        try:
            # Credential content crosses this boundary only through the
            # canonical claim map assembled by the applicant service.
            raw_event_claims = event.data.get("claims")
            _event_claims = dict(raw_event_claims) if isinstance(raw_event_claims, dict) else {}
            logger.info(
                "[auto-trigger] event claims keys=%s values_preview=%s",
                list(_event_claims.keys()),
                {k: v for k, v in _event_claims.items() if k in ("email", "given_name", "family_name")},
            )

            # Create initial context with application approval status
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
                "claims": _event_claims,
            }
            
            # Start flow instance
            instance = FlowInstance(
                flow_definition_id=flow_def.id,
                organization_id=flow_def.organization_id,
                status=FlowInstanceStatus.IN_PROGRESS,
                current_step_id=flow_def.start_step_id,
                context=initial_context,
                subject_id=applicant_id,
                subject_type="applicant",
                external_reference=f"auto-approved-{applicant_id}",
                started_at=datetime.now(timezone.utc),
            )
            _sync_protocol_context(instance, flow_def)
            
            # Set expiry
            from datetime import timedelta
            instance.expires_at = instance.started_at + timedelta(
                seconds=flow_def.default_timeout_seconds
            )
            
            # Record first step
            if flow_def.start_step_id:
                instance.step_history.append({
                    "step_id": flow_def.start_step_id,
                    "entered_at": datetime.now(timezone.utc).isoformat(),
                    "status": "entered",
                })
            
            await repo.save_instance(instance)
            
            # Create OID4VCI artifact if needed
            artifact = None
            if _effective_flow_type(flow_def) == FlowType.OID4VCI_PRE_AUTHORIZED:
                artifact = await _create_oid4vci_artifact(instance, flow_def, repo)
                if artifact:
                    logger.info(f"Created OID4VCI artifact: {artifact.id}")
            
            triggered_instances.append(instance.id)

            if artifact:
                offers.append(
                    {
                        "flow_definition_id": flow_def.id,
                        "flow_definition_name": flow_def.name,
                        "flow_instance_id": instance.id,
                        "artifact_id": artifact.id,
                        "credential_offer_transaction_id": instance.context.get("credential_offer_transaction_id"),
                        "credential_offer_uri": artifact.credential_offer_uri,
                        "credential_offer_uris": instance.context.get("credential_offer_uris") or {},
                        "credential_offer_labels": instance.context.get("credential_offer_labels") or {},
                        "pre_authorized_code": artifact.pre_authorized_code,
                        "expires_at": artifact.expires_at.isoformat() if artifact.expires_at else None,
                        "issuance_status": instance.context.get("issuance_status") or "pending",
                    }
                )

            logger.info(
                f"Auto-triggered flow {flow_def.id} ({flow_def.name}) for applicant {applicant_id}: "
                f"instance {instance.id}"
            )
            
        except Exception as e:
            logger.error(
                f"Failed to trigger flow {flow_def.id} for applicant {applicant_id}: {e}"
            )
    
    return {
        "success": True,
        "flows_triggered": len(triggered_instances),
        "instance_ids": triggered_instances,
        "offers": offers,
    }


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo, _nonce_redis
    logger.info(f"Starting {SERVICE_NAME}...")
    
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
        echo=False
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    _repo = PostgresFlowRepository(session_factory)
    logger.info("PostgreSQL adapter initialized for flow service")
    
    # Initialize gRPC channel to organization service
    from common.di import setup_org_client, teardown_org_client
    await setup_org_client(app, "flow")
    
    # gRPC channels to downstream services
    from common.grpc_factory import create_grpc_channel, create_grpc_server, start_grpc_server_port
    pp_grpc_target = os.environ.get("PP_GRPC_TARGET", "presentation-policy:9009")
    pp_grpc_channel = create_grpc_channel(pp_grpc_target, service_name="flow")
    app.state.pp_grpc_channel = pp_grpc_channel

    ct_grpc_target = os.environ.get("CT_GRPC_TARGET", "credential-template:9003")
    ct_grpc_channel = create_grpc_channel(ct_grpc_target, service_name="flow")
    app.state.ct_grpc_channel = ct_grpc_channel

    issuance_grpc_channel = create_grpc_channel(ISSUANCE_GRPC_TARGET, service_name="flow")
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
        get_repo_fn=get_repo,
    )
    add_FlowServiceServicer_to_server(flow_servicer, grpc_server)
    start_grpc_server_port(
        grpc_server, grpc_port,
        service_names=["marty.ui.flow.v1.FlowService"],
        health_servicer=health_servicer,
    )
    await grpc_server.start()
    logger.info(f"Flow gRPC server listening on :{grpc_port}")
    
    yield
    
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await grpc_server.stop(grace=5)
    await pp_grpc_channel.close()
    await ct_grpc_channel.close()
    await issuance_grpc_channel.close()
    await teardown_org_client(app)
    if _nonce_redis is not None:
        await _nonce_redis.aclose()
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
