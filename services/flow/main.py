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

import httpx
from fastapi import APIRouter, Depends, FastAPI, Form, Header, HTTPException, Query, Request
from fastapi.responses import Response
from jose import jwt, jwk
from jose.constants import ALGORITHMS
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from typing import Annotated

from marty_common import (
    OrganizationClient,
    OrganizationContext,
    require_org_admin,
    require_org_membership,
)
from marty_common.org_authorization import get_organization_client
from marty_common.middleware import RequestIdMiddleware, RequestLoggingMiddleware
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
    ISSUANCE_OID4VCI = "issuance_oid4vci"  # OID4VCI credential issuance with QR codes
    VERIFICATION = "verification"
    VERIFICATION_OID4VP = "verification_oid4vp"  # OID4VP credential verification
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
    
    # Preconditions for automatic flow advancement
    preconditions: list[str] = field(default_factory=list)
    
    # Linked configurations (by ID)
    credential_template_id: str | None = None
    presentation_policy_id: str | None = None
    deployment_profile_id: str | None = None
    
    # Flow-level settings
    default_timeout_seconds: int = 3600  # 1 hour
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
        self.status = FlowStatus.SUSPENDED
        self.updated_at = datetime.now(timezone.utc)


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
    preconditions: list[str] = []
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
    preconditions: list[str]
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


def _definition_to_response(flow: FlowDefinition) -> FlowDefinitionResponse:
    """Convert FlowDefinition to response model."""
    return FlowDefinitionResponse(
        id=flow.id,
        organization_id=flow.organization_id,
        name=flow.name,
        description=flow.description,
        status=flow.status.value,
        flow_type=flow.flow_type.value,
        steps=[{
            "id": s.id,
            "name": s.name,
            "description": s.description,
            "step_type": s.step_type.value,
            "config": s.config,
            "timeout_seconds": s.timeout_seconds,
            "conditions": s.conditions,
        } for s in flow.steps],
        transitions=[{
            "id": t.id,
            "from_step_id": t.from_step_id,
            "to_step_id": t.to_step_id,
            "condition": t.condition.value,
            "condition_expression": t.condition_expression,
        } for t in flow.transitions],
        start_step_id=flow.start_step_id,
        preconditions=flow.preconditions,
        credential_template_id=flow.credential_template_id,
        presentation_policy_id=flow.presentation_policy_id,
        deployment_profile_id=flow.deployment_profile_id,
        default_timeout_seconds=flow.default_timeout_seconds,
        version=flow.version,
        created_at=flow.created_at.isoformat(),
        updated_at=flow.updated_at.isoformat(),
    )


def _instance_to_response(instance: FlowInstance) -> FlowInstanceResponse:
    """Convert FlowInstance to response model."""
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
    if flow_def.flow_type != FlowType.ISSUANCE_OID4VCI:
        return None
    
    # Generate pre-authorized code
    import secrets
    pre_auth_code = secrets.token_urlsafe(32)
    state = secrets.token_urlsafe(16)
    
    # Get issuer URL from environment
    issuer_url = os.environ.get("PUBLIC_BASE_URL", "http://localhost:8000")
    
    # Build credential offer URI
    # Format: openid-credential-offer://?credential_offer_uri=<url>
    offer_id = str(uuid.uuid4())
    credential_offer_uri = f"{issuer_url}/api/issuance/offers/{offer_id}"
    
    # Create artifact
    from datetime import timedelta
    artifact = FlowInstanceArtifact(
        flow_instance_id=instance.id,
        credential_offer_uri=credential_offer_uri,
        pre_authorized_code=pre_auth_code,
        state=state,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),  # Default 15 min expiry
        status=ArtifactStatus.ACTIVE,
        attempt_number=attempt_number,
    )
    
    await repo.save_artifact(artifact)
    
    # Store artifact ID and offer details in instance context
    instance.context["oid4vci_artifact_id"] = artifact.id
    instance.context["offer_id"] = offer_id
    instance.context["credential_offer_uri"] = credential_offer_uri
    await repo.save_instance(instance)
    
    logger.info(f"Created OID4VCI artifact for instance {instance.id}: {artifact.id}")
    
    return artifact


# =============================================================================
# API Endpoints
# =============================================================================
@router.post("/definitions", response_model=FlowDefinitionResponse)
async def create_flow_definition(
    request: CreateFlowDefinitionRequest,
    fastapi_request: Request,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowDefinitionResponse:
    """Create a new Flow Definition."""
    # Verify org membership
    org_client = await get_organization_client(fastapi_request)
    membership = await org_client.get_membership(user_id, request.organization_id)
    if not membership or not membership.is_active():
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    
    flow = FlowDefinition(
        organization_id=request.organization_id,
        name=request.name,
        description=request.description,
        flow_type=FlowType(request.flow_type),
        start_step_id=request.start_step_id,
        preconditions=request.preconditions,
        credential_template_id=request.credential_template_id,
        presentation_policy_id=request.presentation_policy_id,
        deployment_profile_id=request.deployment_profile_id,
        default_timeout_seconds=request.default_timeout_seconds,
        max_retries=request.max_retries,
        retry_cooldown_minutes=getattr(request, 'retry_cooldown_minutes', 5),
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
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> list[FlowDefinitionResponse]:
    """List Flow Definitions for an organization."""
    # Verify org membership
    await app.state.org_client.get_membership(user_id, organization_id)
    flows = await repo.list_definitions(organization_id)
    return [_definition_to_response(f) for f in flows]


@router.get("/definitions/{flow_id}", response_model=FlowDefinitionResponse)
async def get_flow_definition(
    flow_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowDefinitionResponse:
    """Get a Flow Definition by ID."""
    flow = await repo.get_definition(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow Definition not found")
    # Verify org membership
    await app.state.org_client.get_membership(user_id, flow.organization_id)
    return _definition_to_response(flow)


@router.post("/definitions/{flow_id}/activate", response_model=FlowDefinitionResponse)
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
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if not flow.steps:
        raise HTTPException(status_code=400, detail="Flow must have at least one step")
    
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
    if not membership.has_role("admin", "owner"):
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if flow.status != FlowStatus.DRAFT:
        raise HTTPException(status_code=400, detail="Only draft flows can be deleted")
    await repo.delete_definition(flow_id)
    return {"success": True}


# Flow Instance endpoints
@router.post("/instances", response_model=FlowInstanceResponse)
async def start_flow(
    request: StartFlowRequest,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceResponse:
    """Start a new Flow Instance."""
    flow_def = await repo.get_definition(request.flow_definition_id)
    if not flow_def:
        raise HTTPException(status_code=404, detail="Flow Definition not found")
    
    # Verify org membership
    await app.state.org_client.get_membership(user_id, flow_def.organization_id)
    
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
    
    # Create OID4VCI artifact if this is an OID4VCI flow
    if flow_def.flow_type == FlowType.ISSUANCE_OID4VCI:
        artifact = await _create_oid4vci_artifact(instance, flow_def, repo)
        if artifact:
            logger.info(f"Created OID4VCI artifact: {artifact.id}")
    
    logger.info(f"Started Flow Instance: {instance.id}")
    return _instance_to_response(instance)


@router.get("/instances", response_model=list[FlowInstanceResponse])
async def list_flow_instances(
    organization_id: str = Query(..., description="Organization ID"),
    flow_definition_id: str | None = Query(None, description="Filter by flow definition"),
    status: str | None = Query(None, description="Filter by status"),
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> list[FlowInstanceResponse]:
    """List Flow Instances."""
    # Verify org membership
    await app.state.org_client.get_membership(user_id, organization_id)
    status_filter = FlowInstanceStatus(status) if status else None
    instances = await repo.list_instances(organization_id, flow_definition_id, status_filter)
    return [_instance_to_response(i) for i in instances]


@router.get("/instances/{instance_id}", response_model=FlowInstanceResponse)
async def get_flow_instance(
    instance_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceResponse:
    """Get a Flow Instance by ID."""
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")
    # Verify org membership
    await app.state.org_client.get_membership(user_id, instance.organization_id)
    return _instance_to_response(instance)


@router.post("/instances/{instance_id}/advance", response_model=FlowInstanceResponse)
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
    
    # Verify org membership
    await app.state.org_client.get_membership(user_id, instance.organization_id)
    
    if instance.status not in [FlowInstanceStatus.IN_PROGRESS, FlowInstanceStatus.WAITING]:
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
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceResponse:
    """Cancel a Flow Instance."""
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")
    
    # Verify org membership
    await app.state.org_client.get_membership(user_id, instance.organization_id)
    
    if instance.status in [FlowInstanceStatus.COMPLETED, FlowInstanceStatus.CANCELLED]:
        raise HTTPException(status_code=400, detail="Flow already ended")
    
    instance.status = FlowInstanceStatus.CANCELLED
    instance.completed_at = datetime.now(timezone.utc)
    instance.updated_at = datetime.now(timezone.utc)
    
    await repo.save_instance(instance)
    return _instance_to_response(instance)


# =============================================================================
# Flow Instance Artifact Endpoints
# =============================================================================

@router.get("/instances/{instance_id}/artifacts", response_model=list[FlowInstanceArtifactResponse])
async def list_flow_instance_artifacts(
    instance_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> list[FlowInstanceArtifactResponse]:
    """Get all artifacts (QR codes, offers, etc.) for a flow instance."""
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")
    
    # Verify org membership
    await app.state.org_client.get_membership(user_id, instance.organization_id)
    
    artifacts = await repo.list_artifacts(instance_id)
    return [_artifact_to_response(a) for a in artifacts]


@router.get("/instances/{instance_id}/artifacts/{artifact_id}", response_model=FlowInstanceArtifactResponse)
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
    await app.state.org_client.get_membership(user_id, instance.organization_id)
    
    return _artifact_to_response(artifact)


@router.post("/instances/{instance_id}/generate-qr", response_model=FlowInstanceArtifactResponse)
async def generate_qr_code(
    instance_id: str,
    user_id: str = Depends(get_current_user_id),
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> FlowInstanceArtifactResponse:
    """Manually generate a new QR code / credential offer for an OID4VCI flow instance."""
    instance = await repo.get_instance(instance_id)
    if not instance:
        raise HTTPException(status_code=404, detail="Flow Instance not found")
    
    # Verify org membership
    await app.state.org_client.get_membership(user_id, instance.organization_id)
    
    flow_def = await repo.get_definition(instance.flow_definition_id)
    if not flow_def:
        raise HTTPException(status_code=404, detail="Flow Definition not found")
    
    if flow_def.flow_type != FlowType.ISSUANCE_OID4VCI:
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
    user_id: str = Depends(get_current_user_id),
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

    # Resolve the real organization_id from the presentation policy so that the
    # instance carries a valid org and the membership check in get_flow_instance
    # (and other endpoints) enforces actual authorization.
    presentation_policy_service_url = os.environ.get(
        "PRESENTATION_POLICY_SERVICE_URL", "http://presentation-policy:8009"
    )
    organization_id = "__unknown__"
    try:
        policy_url = f"{presentation_policy_service_url}/v1/presentation-policies/{request.presentation_policy_id}"
        async with httpx.AsyncClient(timeout=5.0) as client:
            policy_resp = await client.get(policy_url, headers={"x-user-id": user_id})
            policy_resp.raise_for_status()
            organization_id = policy_resp.json().get("organization_id", "__unknown__")
    except Exception as exc:
        logger.warning(
            f"Could not resolve organization for policy {request.presentation_policy_id}: {exc}"
        )
        raise HTTPException(
            status_code=404,
            detail=f"Presentation policy not found or service unavailable: {request.presentation_policy_id}",
        )

    # Verify that the requesting user is actually a member of the policy's org
    # before creating the instance.
    await app.state.org_client.get_membership(user_id, organization_id)

    # Create a verification flow instance directly
    instance = FlowInstance(
        flow_definition_id="__verification__",  # Special marker for ad-hoc verification
        organization_id=organization_id,
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
    base_url = os.environ.get("PUBLIC_BASE_URL", "http://marty-gateway:8000")
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


async def _build_presentation_definition(presentation_policy_id: str) -> dict:
    """
    Build a proper OID4VP presentation_definition from a presentation policy.

    Fetches the policy and each referenced credential template so that
    ``input_descriptors`` contain real credential-type filters that a wallet
    can match against its stored credentials.
    """
    presentation_policy_service_url = os.environ.get(
        "PRESENTATION_POLICY_SERVICE_URL", "http://presentation-policy:8009"
    )
    credential_template_service_url = os.environ.get(
        "CREDENTIAL_TEMPLATE_SERVICE_URL", "http://credential-template:8003"
    )

    policy: dict = {"credential_requirements": []}
    if presentation_policy_id:
        try:
            async with httpx.AsyncClient(timeout=5.0) as _http:
                resp = await _http.get(
                    f"{presentation_policy_service_url}/v1/presentation-policies/{presentation_policy_id}"
                )
                resp.raise_for_status()
                policy = resp.json()
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
        supported_formats: list[str] = []
        if template_id:
            try:
                async with httpx.AsyncClient(timeout=5.0) as _http:
                    tmpl_resp = await _http.get(
                        f"{credential_template_service_url}/v1/credential-templates/{template_id}"
                    )
                    if tmpl_resp.status_code == 200:
                        tmpl = tmpl_resp.json()
                        credential_type = tmpl.get("credential_type")
                        supported_formats = tmpl.get("supported_formats") or []
            except Exception as exc:
                logger.warning(
                    f"_build_presentation_definition: could not fetch template "
                    f"{template_id}: {exc}"
                )

        # Build type-filter constraint based on format
        fields: list[dict] = []
        if credential_type:
            if "mdoc" in supported_formats:
                # ISO 18013-5 mDoc — filter by docType
                fields.append(
                    {
                        "path": ["$.mdoc.docType", "$.docType"],
                        "filter": {"type": "string", "const": credential_type},
                    }
                )
            elif "sd_jwt_vc" in supported_formats:
                # SD-JWT VC — filter by vct claim
                fields.append(
                    {
                        "path": ["$.vct"],
                        "filter": {"type": "string", "const": credential_type},
                    }
                )
            else:
                # W3C JWT VC — filter by vc.type array
                fields.append(
                    {
                        "path": ["$.vc.type", "$.type"],
                        "filter": {
                            "type": "array",
                            "contains": {"const": credential_type},
                        },
                    }
                )

        # Add path hints for required claims (enables selective disclosure)
        for claim in req.get("requested_claims", []):
            claim_name = claim.get("claim_name") if isinstance(claim, dict) else getattr(claim, "claim_name", None)
            if claim_name:
                fields.append(
                    {
                        "path": [
                            f"$.vc.credentialSubject.{claim_name}",
                            f"$.credentialSubject.{claim_name}",
                            f"$.{claim_name}",
                        ],
                        "intent_to_retain": True,
                        "optional": not (claim.get("required", False) if isinstance(claim, dict) else getattr(claim, "required", False)),
                    }
                )

        descriptor: dict = {"id": descriptor_id, "name": display_name, "purpose": purpose}
        if "mdoc" in supported_formats:
            descriptor["format"] = {"mso_mdoc": {"alg": ["ES256", "ES384"]}}
        elif "sd_jwt_vc" in supported_formats:
            descriptor["format"] = {"vc+sd-jwt": {"alg": ["ES256", "EdDSA"]}}
        else:
            descriptor["format"] = {
                "jwt_vp": {"alg": ["ES256", "EdDSA"]},
                "ldp_vp": {"proof_type": ["Ed25519Signature2020"]},
            }
        if fields:
            descriptor["constraints"] = {"fields": fields}

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

    return {
        "id": str(uuid.uuid4()),
        "format": {
            "jwt_vp": {"alg": ["ES256", "EdDSA"]},
            "ldp_vp": {"proof_type": ["Ed25519Signature2020"]},
            "mso_mdoc": {"alg": ["ES256"]},
        },
        "input_descriptors": input_descriptors,
    }


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
    base_url = os.environ.get("PUBLIC_BASE_URL", "http://marty-gateway:8000")
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
        
        # OID4VP presentation definition (built from the real policy)
        "presentation_definition": await _build_presentation_definition(
            instance.context.get("presentation_policy_id", "")
        ),
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


@router.post("/webhooks/application-approved")
async def handle_application_approved(
    event: ApplicationApprovedWebhook,
    repo: InMemoryFlowRepository = Depends(get_repo),
) -> dict:
    """
    Handle APPLICATION_APPROVED event from applicant service.
    
    Automatically starts OID4VCI flows that have 'application_approved' 
    as a precondition.
    """
    logger.info(
        f"Received APPLICATION_APPROVED event for applicant {event.aggregate_id} "
        f"in org {event.organization_id}"
    )
    
    applicant_id = event.data.get("applicant_id")
    if not applicant_id:
        logger.warning("No applicant_id in event data")
        return {"success": False, "error": "Missing applicant_id"}
    
    # Find all active OID4VCI flows with application_approved precondition
    all_flows = await repo.list_definitions(event.organization_id)
    matching_flows = [
        f for f in all_flows
        if f.status == FlowStatus.ACTIVE
        and f.flow_type == FlowType.ISSUANCE_OID4VCI
        and "application_approved" in f.preconditions
    ]
    
    if not matching_flows:
        logger.info(
            f"No active OID4VCI flows with application_approved precondition "
            f"found for org {event.organization_id}"
        )
        return {"success": True, "flows_triggered": 0}
    
    triggered_instances = []
    
    for flow_def in matching_flows:
        try:
            # Create initial context with application approval status
            initial_context = {
                "applicant_id": applicant_id,
                "application_status": "approved",
                "application_approved_at": event.timestamp,
                "applicant_email": event.data.get("email"),
                "applicant_given_name": event.data.get("given_name"),
                "applicant_family_name": event.data.get("family_name"),
                "vetting_level": event.data.get("vetting_level"),
                "triggered_by_event": "application.approved",
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
            if flow_def.flow_type == FlowType.ISSUANCE_OID4VCI:
                artifact = await _create_oid4vci_artifact(instance, flow_def, repo)
                if artifact:
                    logger.info(f"Created OID4VCI artifact: {artifact.id}")
            
            triggered_instances.append(instance.id)
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
    }


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
    
    # Initialize OrganizationClient (no Redis at service level - gateway handles caching)
    org_service_url = os.environ.get("ORGANIZATION_SERVICE_URL", "http://organization:8002")
    app.state.org_client = OrganizationClient(
        base_url=org_service_url,
        redis_client=None,
    )
    
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
    
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RequestIdMiddleware)
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
