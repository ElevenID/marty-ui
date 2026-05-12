"""
Flow Service gRPC Adapter (Inbound)

Implements the full FlowService gRPC servicer — flow definitions, instances,
artifacts, OID4VP verification, webhook events, and real-time streaming.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import grpc

from marty_proto.v1 import flow_service_pb2, flow_service_pb2_grpc

logger = logging.getLogger(__name__)


def _normalize_grpc_callback_url(value: str | None) -> str | None:
    """Validate callback URLs accepted through the internal gRPC API.

    Public HTTP callers are held to the stricter Pydantic model in
    ``flow.main``. gRPC calls are service-to-service, so the auth service must
    be able to use Docker-internal HTTP callbacks such as ``http://auth:8001``.
    """
    if not value:
        return None
    if len(value) > 2048:
        raise ValueError("callback_url must be 2048 characters or fewer")

    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("callback_url must be an absolute URL")

    if parsed.scheme == "https":
        return value

    if parsed.scheme == "http":
        hostname = parsed.hostname or ""
        try:
            ipaddress.ip_address(hostname)
            is_ip_address = True
        except ValueError:
            is_ip_address = False

        if hostname and "." not in hostname and hostname not in {"localhost", "0"} and not is_ip_address:
            return value

    raise ValueError("callback_url must be https or an internal service URL")


# ---------------------------------------------------------------------------
# Protobuf helpers
# ---------------------------------------------------------------------------


def _definition_to_pb(flow: Any) -> flow_service_pb2.FlowDefinitionResponse:
    """Map domain FlowDefinition → protobuf."""
    steps = [
        flow_service_pb2.FlowStep(
            step_id=s.id,
            name=s.name,
            step_type=s.step_type.value,
            config={k: str(v) for k, v in (s.config or {}).items()},
        )
        for s in flow.steps
    ]
    transitions = [
        flow_service_pb2.FlowTransition(
            from_step_id=t.from_step_id,
            to_step_id=t.to_step_id,
            condition=t.condition.value,
        )
        for t in flow.transitions
    ]
    return flow_service_pb2.FlowDefinitionResponse(
        id=flow.id,
        organization_id=flow.organization_id,
        name=flow.name,
        description=flow.description or "",
        status=flow.status.value,
        flow_type=flow.flow_type.value,
        steps=steps,
        transitions=transitions,
        start_step_id=flow.start_step_id or "",
        preconditions=flow.preconditions or [],
        credential_template_id=flow.credential_template_id or "",
        presentation_policy_id=flow.presentation_policy_id or "",
        deployment_profile_id=flow.deployment_profile_id or "",
        default_timeout_seconds=flow.default_timeout_seconds,
        version=flow.version,
        created_at=flow.created_at.isoformat(),
        updated_at=flow.updated_at.isoformat(),
    )


def _instance_to_pb(inst: Any) -> flow_service_pb2.FlowInstanceResponse:
    """Map domain FlowInstance → protobuf."""
    from flow.main import _protocol_status_for_instance, _response_flow_type

    ctx = {k: str(v) for k, v in (inst.context or {}).items()}
    protocol_status = _protocol_status_for_instance(inst.status)
    return flow_service_pb2.FlowInstanceResponse(
        id=inst.id,
        flow_definition_id=inst.flow_definition_id,
        organization_id=inst.organization_id,
        status=protocol_status,
        current_step_id=inst.current_step_id or "",
        context=ctx,
        subject_id=inst.subject_id or "",
        external_reference=inst.external_reference or "",
        started_at=inst.started_at.isoformat() if inst.started_at else "",
        completed_at=inst.completed_at.isoformat() if inst.completed_at else "",
        expires_at=inst.expires_at.isoformat() if inst.expires_at else "",
        result=json.dumps(inst.result) if inst.result else "",
        error=inst.error or "",
        created_at=inst.created_at.isoformat(),
        updated_at=inst.updated_at.isoformat(),
        flow_id="" if inst.flow_definition_id.startswith("__") else inst.flow_definition_id,
        protocol_status=protocol_status,
        flow_type=_response_flow_type(inst) or "",
        current_step=str((inst.context or {}).get("current_step_name") or ""),
        current_step_index=int((inst.context or {}).get("current_step_index") or 0),
        issued_credential_id=str((inst.context or {}).get("issued_credential_id") or ""),
        error_code=str((inst.context or {}).get("error_code") or ""),
    )


def _artifact_to_pb(art: Any) -> flow_service_pb2.FlowArtifact:
    """Map domain FlowInstanceArtifact → protobuf."""
    return flow_service_pb2.FlowArtifact(
        id=art.id,
        flow_instance_id=art.flow_instance_id,
        credential_offer_uri=art.credential_offer_uri or "",
        qr_payload=art.qr_payload or "",
        pre_authorized_code=art.pre_authorized_code or "",
        expires_at=art.expires_at.isoformat() if art.expires_at else "",
        scanned_at=art.scanned_at.isoformat() if art.scanned_at else "",
        status=art.status.value,
        state=art.state or "",
        attempt_number=art.attempt_number,
        created_at=art.created_at.isoformat(),
        updated_at=art.updated_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# Servicer
# ---------------------------------------------------------------------------


class FlowServiceGrpc(flow_service_pb2_grpc.FlowServiceServicer):
    """gRPC inbound adapter for the flow service."""

    def __init__(
        self,
        start_verification_fn: Any,
        application_approved_fn: Any,
        get_repo_fn: Any,
    ) -> None:
        """
        Parameters
        ----------
        start_verification_fn:
            ``start_verification_flow`` coroutine from main.py.
        application_approved_fn:
            ``handle_application_approved`` coroutine from main.py.
        get_repo_fn:
            ``get_repo`` callable that returns the repo instance.
        """
        self._start_verification = start_verification_fn
        self._application_approved = application_approved_fn
        self._get_repo = get_repo_fn
        # Active streaming subscribers: subscriber_id → asyncio.Queue
        self._stream_queues: dict[str, asyncio.Queue] = {}

    # ------------------------------------------------------------------ #
    # Flow Definitions
    # ------------------------------------------------------------------ #

    async def CreateFlowDefinition(self, request, context):
        from flow.main import (
            FlowDefinition,
            FlowStep,
            FlowTransition,
            FlowType,
            StepType,
            TransitionCondition,
        )

        repo = self._get_repo()

        flow = FlowDefinition(
            organization_id=request.organization_id,
            name=request.name,
            description=request.description or None,
            flow_type=FlowType(request.flow_type) if request.flow_type else FlowType.OID4VCI_PRE_AUTHORIZED,
            start_step_id=request.start_step_id or "",
            preconditions=list(request.preconditions),
            credential_template_id=request.credential_template_id or None,
            presentation_policy_id=request.presentation_policy_id or None,
            deployment_profile_id=request.deployment_profile_id or None,
            default_timeout_seconds=request.default_timeout_seconds or 3600,
            max_retries=request.max_retries or 3,
            enable_resume=request.enable_resume,
        )

        step_id_map: dict[str, str] = {}
        for i, s in enumerate(request.steps):
            step = FlowStep(
                name=s.name,
                step_type=StepType(s.step_type) if s.step_type else StepType.USER_INPUT,
                config=dict(s.config),
            )
            if request.start_step_id == str(i):
                flow.start_step_id = step.id
            step_id_map[str(i)] = step.id
            flow.steps.append(step)

        for t in request.transitions:
            from_id = step_id_map.get(t.from_step_id, t.from_step_id)
            to_id = step_id_map.get(t.to_step_id, t.to_step_id)
            flow.transitions.append(FlowTransition(
                from_step_id=from_id,
                to_step_id=to_id,
                condition=TransitionCondition(t.condition) if t.condition else TransitionCondition.SUCCESS,
            ))

        if not flow.start_step_id and flow.steps:
            flow.start_step_id = flow.steps[0].id

        flow.activate()
        await repo.save_definition(flow)
        logger.info("gRPC CreateFlowDefinition: %s", flow.id)
        return _definition_to_pb(flow)

    async def GetFlowDefinition(self, request, context):
        repo = self._get_repo()
        flow = await repo.get_definition(request.flow_id)
        if not flow:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Flow definition {request.flow_id} not found")
            return flow_service_pb2.FlowDefinitionResponse()
        return _definition_to_pb(flow)

    async def ListFlowDefinitions(self, request, context):
        repo = self._get_repo()
        flows = await repo.list_definitions(request.organization_id)
        return flow_service_pb2.ListFlowDefinitionsResponse(
            definitions=[_definition_to_pb(f) for f in flows],
        )

    async def ActivateFlowDefinition(self, request, context):
        repo = self._get_repo()
        flow = await repo.get_definition(request.flow_id)
        if not flow:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Flow definition {request.flow_id} not found")
            return flow_service_pb2.FlowDefinitionResponse()

        if not flow.steps:
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details("Flow must have at least one step")
            return flow_service_pb2.FlowDefinitionResponse()

        flow.activate()
        await repo.save_definition(flow)
        logger.info("gRPC ActivateFlowDefinition: %s", flow.id)
        return _definition_to_pb(flow)

    async def DeleteFlowDefinition(self, request, context):
        from flow.main import FlowStatus

        repo = self._get_repo()
        flow = await repo.get_definition(request.flow_id)
        if not flow:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Flow definition {request.flow_id} not found")
            return flow_service_pb2.DeleteFlowDefinitionResponse(success=False)

        if flow.status != FlowStatus.DRAFT:
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details("Only draft flows can be deleted")
            return flow_service_pb2.DeleteFlowDefinitionResponse(success=False)

        await repo.delete_definition(request.flow_id)
        logger.info("gRPC DeleteFlowDefinition: %s", request.flow_id)
        return flow_service_pb2.DeleteFlowDefinitionResponse(success=True)

    # ------------------------------------------------------------------ #
    # Flow Instances
    # ------------------------------------------------------------------ #

    async def StartFlowInstance(self, request, context):
        from flow.main import FlowInstance, FlowInstanceStatus, FlowStatus, FlowType

        repo = self._get_repo()
        flow_def = await repo.get_definition(request.flow_definition_id)
        if not flow_def:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Flow definition not found")
            return flow_service_pb2.FlowInstanceResponse()

        if flow_def.status != FlowStatus.ACTIVE:
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details("Flow definition is not active")
            return flow_service_pb2.FlowInstanceResponse()

        now = datetime.now(timezone.utc)
        instance = FlowInstance(
            flow_definition_id=request.flow_definition_id,
            organization_id=flow_def.organization_id,
            status=FlowInstanceStatus.PENDING,
            current_step_id=flow_def.start_step_id,
            context=dict(request.initial_context),
            subject_id=request.subject_id or None,
            subject_type=request.subject_type or None,
            external_reference=request.external_reference or None,
            started_at=now,
            expires_at=now + timedelta(seconds=flow_def.default_timeout_seconds),
        )

        if flow_def.start_step_id:
            instance.step_history.append({
                "step_id": flow_def.start_step_id,
                "entered_at": now.isoformat(),
                "status": "entered",
            })

        await repo.save_instance(instance)

        # Auto-create OID4VCI artifact if applicable
        if flow_def.flow_type == FlowType.OID4VCI_PRE_AUTHORIZED:
            from flow.main import _create_oid4vci_artifact
            await _create_oid4vci_artifact(instance, flow_def, repo)

        logger.info("gRPC StartFlowInstance: %s", instance.id)
        await self._emit_flow_event("started", instance)
        return _instance_to_pb(instance)

    async def GetFlowInstance(self, request, context):
        repo = self._get_repo()
        instance = await repo.get_instance(request.instance_id)
        if not instance:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"Flow instance {request.instance_id} not found")
            return flow_service_pb2.FlowInstanceResponse()
        return _instance_to_pb(instance)

    async def ListFlowInstances(self, request, context):
        from flow.main import _parse_flow_instance_status

        repo = self._get_repo()
        status_filter = _parse_flow_instance_status(request.status) if request.status else None
        instances = await repo.list_instances(
            request.organization_id,
            request.flow_definition_id or None,
            status_filter,
        )
        return flow_service_pb2.ListFlowInstancesResponse(
            instances=[_instance_to_pb(i) for i in instances],
            total=len(instances),
        )

    async def AdvanceFlowInstance(self, request, context):
        from flow.main import FlowInstanceStatus, StepType, TransitionCondition

        repo = self._get_repo()
        instance = await repo.get_instance(request.instance_id)
        if not instance:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Flow instance not found")
            return flow_service_pb2.FlowInstanceResponse()

        if instance.status not in (FlowInstanceStatus.IN_PROGRESS, FlowInstanceStatus.WAITING):
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details(f"Cannot advance flow in {instance.status.value} status")
            return flow_service_pb2.FlowInstanceResponse()

        flow_def = await repo.get_definition(instance.flow_definition_id)
        if not flow_def:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Flow definition not found")
            return flow_service_pb2.FlowInstanceResponse()

        condition = TransitionCondition(request.step_result) if request.step_result else TransitionCondition.SUCCESS
        next_step_id = None
        for t in flow_def.transitions:
            if t.from_step_id == instance.current_step_id and t.condition == condition:
                next_step_id = t.to_step_id
                break

        instance.context.update(dict(request.data))

        if instance.step_history:
            instance.step_history[-1]["completed_at"] = datetime.now(timezone.utc).isoformat()
            instance.step_history[-1]["result"] = request.step_result

        now = datetime.now(timezone.utc)
        if next_step_id:
            instance.current_step_id = next_step_id
            instance.step_history.append({
                "step_id": next_step_id,
                "entered_at": now.isoformat(),
                "status": "entered",
            })
            next_step = next((s for s in flow_def.steps if s.id == next_step_id), None)
            if next_step and next_step.step_type == StepType.END:
                instance.status = FlowInstanceStatus.COMPLETED
                instance.completed_at = now
                instance.result = instance.context
        else:
            if request.step_result == "failure":
                instance.status = FlowInstanceStatus.FAILED
                instance.error = "Step failed with no recovery transition"
            else:
                instance.status = FlowInstanceStatus.COMPLETED
            instance.completed_at = now

        instance.updated_at = now
        await repo.save_instance(instance)
        logger.info("gRPC AdvanceFlowInstance: %s → %s", instance.id, instance.status.value)
        event_type = "completed" if instance.status.value in ("completed", "failed") else "advanced"
        await self._emit_flow_event(event_type, instance)
        return _instance_to_pb(instance)

    async def CancelFlowInstance(self, request, context):
        from flow.main import FlowInstanceStatus

        repo = self._get_repo()
        instance = await repo.get_instance(request.instance_id)
        if not instance:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Flow instance not found")
            return flow_service_pb2.FlowInstanceResponse()

        if instance.status in (FlowInstanceStatus.COMPLETED, FlowInstanceStatus.CANCELLED):
            context.set_code(grpc.StatusCode.FAILED_PRECONDITION)
            context.set_details("Flow already ended")
            return flow_service_pb2.FlowInstanceResponse()

        now = datetime.now(timezone.utc)
        instance.status = FlowInstanceStatus.CANCELLED
        instance.completed_at = now
        instance.updated_at = now
        await repo.save_instance(instance)
        logger.info("gRPC CancelFlowInstance: %s", instance.id)
        await self._emit_flow_event("cancelled", instance)
        return _instance_to_pb(instance)

    async def GetFlowResult(self, request, context):
        from flow.main import _protocol_status_for_instance

        repo = self._get_repo()
        instance = await repo.get_instance(request.instance_id)
        if not instance:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Flow instance not found")
            return flow_service_pb2.FlowResultResponse()

        result = instance.result or {}
        verified_claims = {k: str(v) for k, v in result.items()} if isinstance(result, dict) else {}

        return flow_service_pb2.FlowResultResponse(
            instance_id=instance.id,
            status=_protocol_status_for_instance(instance.status),
            result=json.dumps(result) if result else "",
            decision=result.get("decision", "") if isinstance(result, dict) else "",
            decision_reason=result.get("decision_reason", "") if isinstance(result, dict) else "",
            verified_claims=verified_claims,
            evaluation_timestamp=instance.completed_at.isoformat() if instance.completed_at else "",
        )

    async def ListFlowArtifacts(self, request, context):
        repo = self._get_repo()
        instance = await repo.get_instance(request.instance_id)
        if not instance:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details("Flow instance not found")
            return flow_service_pb2.ListFlowArtifactsResponse()

        artifacts = await repo.list_artifacts(request.instance_id)
        return flow_service_pb2.ListFlowArtifactsResponse(
            artifacts=[_artifact_to_pb(a) for a in artifacts],
        )

    # ------------------------------------------------------------------ #
    # Verification (OID4VP)
    # ------------------------------------------------------------------ #

    async def StartVerification(self, request, context):
        from flow.main import StartVerificationFlowRequest

        try:
            callback_url = _normalize_grpc_callback_url(request.callback_url or None)
            req = StartVerificationFlowRequest(
                presentation_policy_id=request.presentation_policy_id or None,
                organization_id=request.organization_id or None,
                response_type=request.response_type or "vp_token",
                trust_profile_id=request.trust_profile_id or None,
                deployment_profile_id=request.deployment_profile_id or None,
                external_reference=request.external_reference or None,
                callback_url=None,
                expiry_minutes=request.expiry_minutes or 15,
            )
            # Public HTTP verification still rejects internal HTTP callbacks.
            # The gRPC surface is internal, so assign after model validation.
            req.callback_url = callback_url

            result = await self._start_verification(
                request=req,
                user_id=request.user_id or "grpc-service",
                repo=self._get_repo(),
            )
        except Exception as exc:
            code = grpc.StatusCode.INTERNAL
            detail = str(exc)
            if "not found" in detail.lower() or "404" in detail:
                code = grpc.StatusCode.NOT_FOUND
            elif "invalid_request" in detail.lower() or "400" in detail:
                code = grpc.StatusCode.INVALID_ARGUMENT
            elif isinstance(exc, ValueError) or "validation error" in detail.lower():
                code = grpc.StatusCode.INVALID_ARGUMENT
            context.set_code(code)
            context.set_details(detail)
            return flow_service_pb2.VerificationRequestResponse()

        return flow_service_pb2.VerificationRequestResponse(
            instance_id=result.instance_id,
            flow_definition_id=result.flow_definition_id,
            request_uri=result.request_uri,
            qr_code_data=result.qr_code_data,
            presentation_policy_id=result.presentation_policy_id or "",
            nonce=result.nonce,
            expires_at=result.expires_at,
            status=result.status,
        )

    # ------------------------------------------------------------------ #
    # Webhook
    # ------------------------------------------------------------------ #

    async def ApplicationApproved(self, request, context):
        from flow.main import ApplicationApprovedWebhook

        webhook = ApplicationApprovedWebhook(
            event_type=request.event_type,
            aggregate_id=request.aggregate_id,
            aggregate_type=request.aggregate_type,
            organization_id=request.organization_id,
            data=dict(request.data),
            timestamp=request.timestamp,
        )

        try:
            result = await self._application_approved(
                event=webhook,
                repo=self._get_repo(),
            )
        except Exception as exc:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return flow_service_pb2.ApplicationApprovedResponse()

        return flow_service_pb2.ApplicationApprovedResponse(
            success=result.get("success", False),
            flows_triggered=result.get("flows_triggered", 0),
        )

    # ------------------------------------------------------------------ #
    # Streaming
    # ------------------------------------------------------------------ #

    async def _emit_flow_event(
        self,
        event_type: str,
        instance: Any,
        artifact: Any = None,
    ) -> None:
        """Push a flow event to all active stream subscribers."""
        from flow.main import _protocol_status_for_instance

        event = flow_service_pb2.FlowInstanceEvent(
            event_type=event_type,
            instance_id=instance.id,
            definition_id=instance.flow_definition_id,
            current_step_id=instance.current_step_id or "",
            status=_protocol_status_for_instance(instance.status),
            artifact=_artifact_to_pb(artifact) if artifact else None,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        stale: list[str] = []
        for sub_id, q in self._stream_queues.items():
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("Dropping flow event for slow subscriber %s", sub_id)
            except Exception:
                logger.warning("Failed to enqueue flow event for subscriber %s — marking stale", sub_id, exc_info=True)
                stale.append(sub_id)
        for sid in stale:
            self._stream_queues.pop(sid, None)

    async def StreamFlowUpdates(self, request, context):
        """Server-streaming: push flow instance events to the caller."""
        import uuid

        sub_id = str(uuid.uuid4())
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self._stream_queues[sub_id] = q
        logger.info("StreamFlowUpdates: subscriber %s connected", sub_id)

        try:
            while not context.cancelled():
                try:
                    event = await asyncio.wait_for(q.get(), timeout=30.0)
                    # Apply filters
                    if request.instance_id and event.instance_id != request.instance_id:
                        continue
                    yield event
                except asyncio.TimeoutError:
                    continue
        finally:
            self._stream_queues.pop(sub_id, None)
            logger.info("StreamFlowUpdates: subscriber %s disconnected", sub_id)

    # ------------------------------------------------------------------ #
    # Health
    # ------------------------------------------------------------------ #

    async def HealthCheck(self, request, context):
        return flow_service_pb2.HealthCheckResponse(status="serving")
