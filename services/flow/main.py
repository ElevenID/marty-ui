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

import json
import logging
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator

from fastapi import APIRouter, Depends, FastAPI, Form, HTTPException, Query
from fastapi.responses import Response
from jose import jwt, jwk
from jose.constants import ALGORITHMS
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from flow.infrastructure.adapters import PostgresFlowRepository

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SERVICE_NAME = "flow-service"
SERVICE_PORT = int(os.environ.get("FLOW_SERVICE_PORT", "8011"))

# OID4VP Request Object signing key (in production, use proper key management)
# For testing, we generate an ephemeral ES256 key. In production, use stored keys with rotation
_SIGNING_KEY_PAIR = None
_SIGNING_JWK = None

def get_or_create_signing_key():
    """Get or create ES256 signing key pair for Request Objects."""
    global _SIGNING_KEY_PAIR, _SIGNING_JWK
    if _SIGNING_KEY_PAIR is None:
        # Generate ES256 key pair
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        _SIGNING_KEY_PAIR = {
            'private': private_key,
            'public': private_key.public_key()
        }
        
        # Convert to JWK format for jose library
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        _SIGNING_JWK = jwk.construct(private_pem, algorithm='ES256')
    
    return _SIGNING_KEY_PAIR, _SIGNING_JWK

VERIFIER_CLIENT_ID = os.environ.get("VERIFIER_CLIENT_ID", "")  # Will be set based on PUBLIC_BASE_URL


def get_config() -> dict[str, Any]:
    """Get database configuration from environment."""
    database_url = os.environ.get("DATABASE_URL", "postgresql://marty:marty_dev@postgres:5432/marty_credentials")
    if not database_url.startswith("postgresql+asyncpg://"):
        database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return {"database_url": database_url}


# =============================================================================
# Domain Layer
# =============================================================================

class FlowType(str, Enum):
    """Types of flows."""
    ISSUANCE = "issuance"
    VERIFICATION = "verification"
    PRESENTATION = "presentation"
    RENEWAL = "renewal"
    REVOCATION = "revocation"


class FlowStatus(str, Enum):
    """Flow definition status."""
    DRAFT = "draft"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class StepType(str, Enum):
    """Types of steps in a flow."""
    START = "start"
    USER_INPUT = "user_input"
    VERIFICATION = "verification"
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
    flow_type: FlowType = FlowType.ISSUANCE
    
    # Steps and transitions
    steps: list[FlowStep] = field(default_factory=list)
    transitions: list[FlowTransition] = field(default_factory=list)
    start_step_id: str | None = None
    
    # Linked configurations (by ID)
    credential_template_id: str | None = None
    presentation_policy_id: str | None = None
    deployment_profile_id: str | None = None
    
    # Flow-level settings
    default_timeout_seconds: int = 3600  # 1 hour
    max_retries: int = 3
    enable_resume: bool = True  # Can resume from where left off
    
    # Timestamps
    version: int = 1
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def activate(self) -> None:
        self.status = FlowStatus.ACTIVE
        self.updated_at = datetime.now(timezone.utc)
    
    def suspend(self) -> None:
        self.status = FlowStatus.SUSPENDED
        self.updated_at = datetime.now(timezone.utc)


# =============================================================================
# Flow Instance (Runtime)
# =============================================================================

class FlowInstanceStatus(str, Enum):
    """Status of a running flow instance."""
    CREATED = "created"
    IN_PROGRESS = "in_progress"
    WAITING = "waiting"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


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


# =============================================================================
# Application Layer
# =============================================================================

class InMemoryFlowRepository:
    """In-memory repository for development."""
    
    def __init__(self):
        self._definitions: dict[str, FlowDefinition] = {}
        self._instances: dict[str, FlowInstance] = {}
    
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


# =============================================================================
# HTTP Adapter - Request/Response Models
# =============================================================================

class FlowStepModel(BaseModel):
    name: str
    description: str | None = None
    step_type: str = "user_input"
    config: dict = {}
    timeout_seconds: int | None = None
    conditions: list[dict] = []


class FlowTransitionModel(BaseModel):
    from_step_id: str
    to_step_id: str
    condition: str = "success"
    condition_expression: str | None = None


class CreateFlowDefinitionRequest(BaseModel):
    organization_id: str
    name: str
    description: str | None = None
    flow_type: str = "issuance"
    steps: list[FlowStepModel] = []
    transitions: list[FlowTransitionModel] = []
    start_step_id: str | None = None
    credential_template_id: str | None = None
    presentation_policy_id: str | None = None
    deployment_profile_id: str | None = None
    default_timeout_seconds: int = 3600
    max_retries: int = 3
    enable_resume: bool = True


class FlowDefinitionResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None
    status: str
    flow_type: str
    steps: list[dict]
    transitions: list[dict]
    start_step_id: str | None
    credential_template_id: str | None
    presentation_policy_id: str | None
    deployment_profile_id: str | None
    default_timeout_seconds: int
    version: int
    created_at: str
    updated_at: str


class StartFlowRequest(BaseModel):
    flow_definition_id: str
    subject_id: str | None = None
    subject_type: str = "applicant"
    external_reference: str | None = None
    initial_context: dict = {}


class FlowInstanceResponse(BaseModel):
    id: str
    flow_definition_id: str
    organization_id: str
    status: str
    current_step_id: str | None
    context: dict
    step_history: list[dict]
    subject_id: str | None
    external_reference: str | None
    started_at: str | None
    completed_at: str | None
    expires_at: str | None
    result: dict | None
    error: str | None
    created_at: str
    updated_at: str


class AdvanceFlowRequest(BaseModel):
    step_result: str = "success"  # success, failure, etc.
    data: dict = {}


# =============================================================================
# HTTP Adapter - Router
# =============================================================================

router = APIRouter(prefix="/v1/flows", tags=["flows"])

_repo: InMemoryFlowRepository | None = None


def get_repo() -> InMemoryFlowRepository:
    if _repo is None:
        raise RuntimeError("Service not configured")
    return _repo


# Flow Definition endpoints
@router.post("/definitions", response_model=FlowDefinitionResponse)
async def create_flow_definition(
    request: CreateFlowDefinitionRequest,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowDefinitionResponse:
    """Create a new Flow Definition."""
    flow = FlowDefinition(
        organization_id=request.organization_id,
        name=request.name,
        description=request.description,
        flow_type=FlowType(request.flow_type),
        start_step_id=request.start_step_id,
        credential_template_id=request.credential_template_id,
        presentation_policy_id=request.presentation_policy_id,
        deployment_profile_id=request.deployment_profile_id,
        default_timeout_seconds=request.default_timeout_seconds,
        max_retries=request.max_retries,
        enable_resume=request.enable_resume,
    )
    
    # Add steps
    step_id_map: dict[str, str] = {}  # Old ID -> New ID mapping
    for i, step_model in enumerate(request.steps):
        step = FlowStep(
            name=step_model.name,
            description=step_model.description,
            step_type=StepType(step_model.step_type),
            config=step_model.config,
            timeout_seconds=step_model.timeout_seconds,
            conditions=step_model.conditions,
        )
        # If start_step_id references this step by index, map it
        if request.start_step_id == str(i):
            flow.start_step_id = step.id
        step_id_map[str(i)] = step.id
        flow.steps.append(step)
    
    # Add transitions (map step IDs)
    for trans_model in request.transitions:
        from_id = step_id_map.get(trans_model.from_step_id, trans_model.from_step_id)
        to_id = step_id_map.get(trans_model.to_step_id, trans_model.to_step_id)
        transition = FlowTransition(
            from_step_id=from_id,
            to_step_id=to_id,
            condition=TransitionCondition(trans_model.condition),
            condition_expression=trans_model.condition_expression,
        )
        flow.transitions.append(transition)
    
    # Set start step if not set
    if not flow.start_step_id and flow.steps:
        flow.start_step_id = flow.steps[0].id
    
    await repo.save_definition(flow)
    logger.info(f"Created Flow Definition: {flow.id}")
    return _definition_to_response(flow)


@router.get("/definitions", response_model=list[FlowDefinitionResponse])
async def list_flow_definitions(
    organization_id: str = Query(..., description="Organization ID"),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> list[FlowDefinitionResponse]:
    """List Flow Definitions for an organization."""
    flows = await repo.list_definitions(organization_id)
    return [_definition_to_response(f) for f in flows]


@router.get("/definitions/{flow_id}", response_model=FlowDefinitionResponse)
async def get_flow_definition(
    flow_id: str,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowDefinitionResponse:
    """Get a Flow Definition by ID."""
    flow = await repo.get_definition(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow Definition not found")
    return _definition_to_response(flow)


@router.post("/definitions/{flow_id}/activate", response_model=FlowDefinitionResponse)
async def activate_flow_definition(
    flow_id: str,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowDefinitionResponse:
    """Activate a Flow Definition."""
    flow = await repo.get_definition(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow Definition not found")
    
    if not flow.steps:
        raise HTTPException(status_code=400, detail="Flow must have at least one step")
    
    flow.activate()
    await repo.save_definition(flow)
    return _definition_to_response(flow)


@router.delete("/definitions/{flow_id}")
async def delete_flow_definition(
    flow_id: str,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> dict:
    """Delete a Flow Definition (only drafts)."""
    flow = await repo.get_definition(flow_id)
    if flow and flow.status != FlowStatus.DRAFT:
        raise HTTPException(status_code=400, detail="Only draft flows can be deleted")
    await repo.delete_definition(flow_id)
    return {"success": True}


# Flow Instance endpoints
@router.post("/instances", response_model=FlowInstanceResponse)
async def start_flow(
    request: StartFlowRequest,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceResponse:
    """Start a new Flow Instance."""
    flow_def = await repo.get_definition(request.flow_definition_id)
    if not flow_def:
        raise HTTPException(status_code=404, detail="Flow Definition not found")
    
    if flow_def.status != FlowStatus.ACTIVE:
        raise HTTPException(status_code=400, detail="Flow Definition is not active")
    
    instance = FlowInstance(
        flow_definition_id=request.flow_definition_id,
        organization_id=flow_def.organization_id,
        status=FlowInstanceStatus.IN_PROGRESS,
        current_step_id=flow_def.start_step_id,
        context=request.initial_context,
        subject_id=request.subject_id,
        subject_type=request.subject_type,
        external_reference=request.external_reference,
        started_at=datetime.now(timezone.utc),
    )
    
    # Set expiry
    from datetime import timedelta
    instance.expires_at = instance.started_at + timedelta(seconds=flow_def.default_timeout_seconds)
    
    # Record first step
    if flow_def.start_step_id:
        instance.step_history.append({
            "step_id": flow_def.start_step_id,
            "entered_at": datetime.now(timezone.utc).isoformat(),
            "status": "entered",
        })
    
    await repo.save_instance(instance)
    logger.info(f"Started Flow Instance: {instance.id}")
    return _instance_to_response(instance)


@router.get("/instances", response_model=list[FlowInstanceResponse])
async def list_flow_instances(
    organization_id: str = Query(..., description="Organization ID"),
    flow_definition_id: str | None = Query(None, description="Filter by flow definition"),
    status: str | None = Query(None, description="Filter by status"),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> list[FlowInstanceResponse]:
    """List Flow Instances."""
    status_filter = FlowInstanceStatus(status) if status else None
    instances = await repo.list_instances(organization_id, flow_definition_id, status_filter)
    return [_instance_to_response(i) for i in instances]


@router.get("/instances/{instance_id}", response_model=FlowInstanceResponse)
async def get_flow_instance(
    instance_id: str,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceResponse:
    """Get a Flow Instance by ID."""
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")
    return _instance_to_response(instance)


@router.post("/instances/{instance_id}/advance", response_model=FlowInstanceResponse)
async def advance_flow(
    instance_id: str,
    request: AdvanceFlowRequest,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceResponse:
    """Advance a Flow Instance to the next step."""
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")
    
    if instance.status not in [FlowInstanceStatus.IN_PROGRESS, FlowInstanceStatus.WAITING]:
        raise HTTPException(status_code=400, detail=f"Cannot advance flow in {instance.status} status")
    
    flow_def = await repo.get_definition(instance.flow_definition_id)
    if not flow_def:
        raise HTTPException(status_code=404, detail="Flow Definition not found")
    
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
        instance.step_history[-1]["completed_at"] = datetime.now(timezone.utc).isoformat()
        instance.step_history[-1]["result"] = request.step_result
    
    if next_step_id:
        # Move to next step
        instance.current_step_id = next_step_id
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


@router.post("/instances/{instance_id}/cancel", response_model=FlowInstanceResponse)
async def cancel_flow(
    instance_id: str,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceResponse:
    """Cancel a Flow Instance."""
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")
    
    if instance.status in [FlowInstanceStatus.COMPLETED, FlowInstanceStatus.CANCELLED]:
        raise HTTPException(status_code=400, detail="Flow already ended")
    
    instance.status = FlowInstanceStatus.CANCELLED
    instance.completed_at = datetime.now(timezone.utc)
    instance.updated_at = datetime.now(timezone.utc)
    
    await repo.save_instance(instance)
    return _instance_to_response(instance)


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
    """Request to start a verification flow (async wallet interaction)."""
    presentation_policy_id: str
    trust_profile_id: str | None = None
    deployment_profile_id: str | None = None
    external_reference: str | None = None
    callback_url: str | None = None
    expiry_minutes: int = 15


class SubmitVerificationRequest(BaseModel):
    """Request to submit a VP token to a verification flow."""
    vp_token: str
    presentation_submission: dict | None = None


class VerificationResultResponse(BaseModel):
    """Response from completing a verification flow."""
    instance_id: str
    status: str
    result: str  # passed, failed, partial
    decision: str  # allow, deny, manual_review
    decision_reason: str
    verified_claims: dict
    evaluation_timestamp: str


@router.post("/verify", response_model=VerificationRequestResponse)
async def start_verification_flow(
    request: StartVerificationFlowRequest,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> VerificationRequestResponse:
    """
    Start a verification flow for async wallet interactions.
    
    This creates a flow instance configured for verification, generates
    a request_uri and QR code data for the wallet to scan.
    
    For stateless verification (when you already have the VP token),
    use POST /v1/presentation-policies/{id}/evaluate instead.
    """
    import secrets
    from datetime import timedelta
    
    nonce = secrets.token_urlsafe(16)
    
    # Create a verification flow instance directly
    instance = FlowInstance(
        flow_definition_id="__verification__",  # Special marker for ad-hoc verification
        organization_id="default",  # Would come from auth context in production
        status=FlowInstanceStatus.WAITING,
        context={
            "presentation_policy_id": request.presentation_policy_id,
            "trust_profile_id": request.trust_profile_id,
            "deployment_profile_id": request.deployment_profile_id,
            "callback_url": request.callback_url,
            "nonce": nonce,
            "flow_type": "verification",
        },
        external_reference=request.external_reference,
        started_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=request.expiry_minutes),
    )
    
    # Generate request URI and QR code data
    # Use gateway URL for Docker networking (Walt.ID wallet needs to access this)
    base_url = os.environ.get("PUBLIC_BASE_URL", "http://gateway:8000")
    # OID4VP: The request_uri points to where the wallet can fetch the signed Request Object
    request_uri = f"{base_url}/v1/flows/instances/{instance.id}/request"
    # The authorization request with request_uri parameter
    auth_request = f"openid4vp://authorize?request_uri={request_uri}"
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


@router.get("/instances/{instance_id}/request")
async def get_verification_request_object(
    instance_id: str,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> Response:
    """
    Get the verification request object (for wallet to fetch via request_uri).
    
    Per OID4VP spec, this MUST return a signed JWT Request Object,
    not plain JSON. The JWT is signed by the verifier's private key.
    
    Content-Type: application/oauth-authz-req+jwt
    """
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow instance not found")
    
    if instance.expires_at and datetime.now(timezone.utc) > instance.expires_at:
        instance.status = FlowInstanceStatus.EXPIRED
        await repo.save_instance(instance)
        raise HTTPException(status_code=410, detail="Verification request has expired")
    
    if instance.status not in [FlowInstanceStatus.WAITING, FlowInstanceStatus.IN_PROGRESS]:
        raise HTTPException(status_code=400, detail="Request already processed or invalid state")
    
    # Get signing key
    _, signing_jwk = get_or_create_signing_key()
    
    # Build base URL for response_uri (where wallet posts the VP)
    base_url = os.environ.get("PUBLIC_BASE_URL", "http://gateway:8000")
    client_id = os.environ.get("VERIFIER_CLIENT_ID", f"{base_url}/verifier")
    response_uri = f"{base_url}/v1/flows/instances/{instance_id}/submit"
    
    # Build OID4VP Request Object payload
    # This will be signed as a JWT per OID4VP spec section 5
    request_payload = {
        # Standard OAuth 2.0 parameters
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "client_id": client_id,
        "response_uri": response_uri,
        "nonce": instance.context.get("nonce"),
        "state": instance_id,
        
        # JWT claims
        "iss": client_id,  # Issuer (the verifier)
        "aud": "https://self-issued.me/v2",  # Audience (standard for OID4VP)
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "exp": int(instance.expires_at.timestamp()) if instance.expires_at else int((datetime.now(timezone.utc).timestamp() + 900)),
        
        # OID4VP presentation definition
        "presentation_definition": {
            "id": str(uuid.uuid4()),
            "format": {
                "jwt_vp": {"alg": ["ES256", "EdDSA"]},
                "ldp_vp": {"proof_type": ["Ed25519Signature2020"]},
            },
            "input_descriptors": [
                {
                    "id": "policy_requirement",
                    "name": "Presentation Policy Requirement",
                    "purpose": "Verify credentials per presentation policy",
                    "constraints": {
                        "fields": [
                            {
                                "path": ["$.presentation_policy_id"],
                                "filter": {
                                    "type": "string",
                                    "const": instance.context.get("presentation_policy_id")
                                }
                            }
                        ]
                    }
                }
            ],
        },
    }
    
    # Sign the Request Object as a JWT
    # Per OID4VP spec: "The Request Object [...] MUST be signed"
    try:
        signed_request_jwt = jwt.encode(
            request_payload,
            signing_jwk.to_dict(),
            algorithm='ES256',
            headers={
                'typ': 'oauth-authz-req+jwt',
                'alg': 'ES256',
            }
        )
        
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


@router.post("/instances/{instance_id}/submit", response_model=VerificationResultResponse)
async def submit_verification_response(
    instance_id: str,
    vp_token: str = Form(...),
    presentation_submission: str = Form(None),
    state: str = Form(None),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> VerificationResultResponse:
    """
    Submit a VP token to complete a verification flow.
    
    This is called by the wallet (via direct_post) or by the relying party
    after receiving the VP token from the wallet.
    
    Accepts form-encoded data per OID4VP spec (application/x-www-form-urlencoded).
    """
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow instance not found")
    
    if instance.expires_at and datetime.now(timezone.utc) > instance.expires_at:
        instance.status = FlowInstanceStatus.EXPIRED
        await repo.save_instance(instance)
        raise HTTPException(status_code=410, detail="Verification request has expired")
    
    if instance.status not in [FlowInstanceStatus.WAITING, FlowInstanceStatus.IN_PROGRESS]:
        raise HTTPException(status_code=400, detail="Submission not accepted in current state")
    
    # Parse presentation_submission if it's JSON string
    parsed_submission = None
    if presentation_submission:
        try:
            parsed_submission = json.loads(presentation_submission)
        except json.JSONDecodeError:
            parsed_submission = presentation_submission
    
    # Store the presentation
    instance.context["vp_token"] = vp_token
    instance.context["presentation_submission"] = parsed_submission
    if state:
        instance.context["state"] = state
    instance.status = FlowInstanceStatus.IN_PROGRESS
    
    # In a real implementation, this would:
    # 1. Decode and validate the VP token
    # 2. Fetch the presentation policy
    # 3. Call the policy evaluation logic
    # 4. Return the result
    
    # Simulated evaluation
    verified_claims = {
        "given_name": "Jane",
        "family_name": "Doe",
        "age_over_21": True,
    }
    
    instance.status = FlowInstanceStatus.COMPLETED
    instance.completed_at = datetime.now(timezone.utc)
    instance.result = {
        "evaluation_result": "passed",
        "decision": "allow",
        "decision_reason": "All policy requirements satisfied",
        "verified_claims": verified_claims,
    }
    instance.updated_at = datetime.now(timezone.utc)
    
    await repo.save_instance(instance)
    logger.info(f"Completed verification flow: {instance_id} with result: passed")
    
    # Trigger callback if configured
    callback_url = instance.context.get("callback_url")
    if callback_url:
        logger.info(f"Would POST result to callback: {callback_url}")
    
    return VerificationResultResponse(
        instance_id=instance.id,
        status=instance.status.value,
        result="passed",
        decision="allow",
        decision_reason="All policy requirements satisfied",
        verified_claims=verified_claims,
        evaluation_timestamp=datetime.now(timezone.utc).isoformat(),
    )


def _definition_to_response(flow: FlowDefinition) -> FlowDefinitionResponse:
    return FlowDefinitionResponse(
        id=flow.id,
        organization_id=flow.organization_id,
        name=flow.name,
        description=flow.description,
        status=flow.status.value,
        flow_type=flow.flow_type.value,
        steps=[
            {
                "id": s.id,
                "name": s.name,
                "description": s.description,
                "step_type": s.step_type.value,
                "config": s.config,
                "timeout_seconds": s.timeout_seconds,
            }
            for s in flow.steps
        ],
        transitions=[
            {
                "id": t.id,
                "from_step_id": t.from_step_id,
                "to_step_id": t.to_step_id,
                "condition": t.condition.value,
            }
            for t in flow.transitions
        ],
        start_step_id=flow.start_step_id,
        credential_template_id=flow.credential_template_id,
        presentation_policy_id=flow.presentation_policy_id,
        deployment_profile_id=flow.deployment_profile_id,
        default_timeout_seconds=flow.default_timeout_seconds,
        version=flow.version,
        created_at=flow.created_at.isoformat(),
        updated_at=flow.updated_at.isoformat(),
    )


def _instance_to_response(instance: FlowInstance) -> FlowInstanceResponse:
    return FlowInstanceResponse(
        id=instance.id,
        flow_definition_id=instance.flow_definition_id,
        organization_id=instance.organization_id,
        status=instance.status.value,
        current_step_id=instance.current_step_id,
        context=instance.context,
        step_history=instance.step_history,
        subject_id=instance.subject_id,
        external_reference=instance.external_reference,
        started_at=instance.started_at.isoformat() if instance.started_at else None,
        completed_at=instance.completed_at.isoformat() if instance.completed_at else None,
        expires_at=instance.expires_at.isoformat() if instance.expires_at else None,
        result=instance.result,
        error=instance.error,
        created_at=instance.created_at.isoformat(),
        updated_at=instance.updated_at.isoformat(),
    )


# =============================================================================
# Application Setup
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    global _repo
    logger.info(f"Starting {SERVICE_NAME}...")
    
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
    
    yield
    
    logger.info(f"Shutting down {SERVICE_NAME}...")
    await engine.dispose()


def create_app() -> FastAPI:
    app = FastAPI(
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
    uvicorn.run(app, host="0.0.0.0", port=SERVICE_PORT, reload=False)
