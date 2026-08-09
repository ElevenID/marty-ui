"""
PostgreSQL adapter for flow repository.
"""

import logging
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import delete, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

if TYPE_CHECKING:
    from flow.main import (
        FlowDefinition,
        FlowInstance,
        FlowInstanceArtifact,
        FlowInstanceStatus,
    )

from flow.infrastructure.models import (
    flow_callback_outbox,
    flow_definitions,
    flow_instances,
    flow_nonce_consumptions,
)
from flow.callback_outbox import CallbackOutboxEvent, new_lease_token

logger = logging.getLogger(__name__)


class _FinalizationConflict(Exception):
    pass


_TERMINAL_FLOW_STATUSES = ("completed", "failed", "cancelled", "expired")


def _serialize_preconditions_payload(flow: "FlowDefinition") -> list[str]:
    return list(flow.preconditions)


def _deserialize_preconditions_payload(
    payload: list[str] | dict | None,
) -> tuple[list[str], dict]:
    if isinstance(payload, dict):
        return payload.get("items", []) or [], payload.get("protocol", {}) or {}
    return payload or [], {}


def _coerce_step_type(value):
    from flow.main import StepType

    normalized = str(value or StepType.USER_INPUT.value).strip().lower()
    try:
        return StepType(normalized)
    except ValueError:
        logger.warning(
            "Unknown flow step_type '%s'; defaulting to '%s'",
            value,
            StepType.USER_INPUT.value,
        )
        return StepType.USER_INPUT


def _coerce_transition_condition(value):
    from flow.main import TransitionCondition

    normalized = str(value or TransitionCondition.SUCCESS.value).strip().lower()
    try:
        return TransitionCondition(normalized)
    except ValueError:
        logger.warning(
            "Unknown flow transition condition '%s'; defaulting to '%s'",
            value,
            TransitionCondition.SUCCESS.value,
        )
        return TransitionCondition.SUCCESS


class PostgresFlowRepository:
    """PostgreSQL implementation of flow repository."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory
        # Artifacts are kept in-memory until a dedicated table is added.
        self._artifacts: dict[str, "FlowInstanceArtifact"] = {}

    # ========== Flow Instance Artifact Operations (in-memory) ==========

    async def save_artifact(self, artifact: "FlowInstanceArtifact") -> None:
        self._artifacts[artifact.id] = artifact

    async def get_artifact(self, artifact_id: str) -> "FlowInstanceArtifact | None":
        return self._artifacts.get(artifact_id)

    async def list_artifacts(
        self, flow_instance_id: str
    ) -> list["FlowInstanceArtifact"]:
        return [
            a
            for a in self._artifacts.values()
            if a.flow_instance_id == flow_instance_id
        ]

    async def get_artifact_by_code(
        self, pre_authorized_code: str
    ) -> "FlowInstanceArtifact | None":
        for a in self._artifacts.values():
            if a.pre_authorized_code == pre_authorized_code:
                return a
        return None

    # ========== Flow Definition Operations ==========

    async def save_definition(self, flow: "FlowDefinition") -> None:
        """Save or update a flow definition."""
        async with self._session_factory() as session:
            preconditions_data = _serialize_preconditions_payload(flow)
            # Serialize steps
            steps_data = [
                {
                    "id": step.id,
                    "name": step.name,
                    "description": step.description,
                    "step_type": step.step_type,
                    "config": step.config,
                    "timeout_seconds": step.timeout_seconds,
                    "conditions": step.conditions,
                    "approval_strategy": step.approval_strategy,
                }
                for step in flow.steps
            ]

            # Serialize transitions
            transitions_data = [
                {
                    "id": trans.id,
                    "from_step_id": trans.from_step_id,
                    "to_step_id": trans.to_step_id,
                    "condition": trans.condition,
                    "condition_expression": trans.condition_expression,
                }
                for trans in flow.transitions
            ]

            # Check if exists
            result = await session.execute(
                select(flow_definitions.c.id).where(flow_definitions.c.id == flow.id)
            )
            exists = result.scalar_one_or_none()

            if exists:
                # Update
                await session.execute(
                    flow_definitions.update()
                    .where(flow_definitions.c.id == flow.id)
                    .values(
                        organization_id=flow.organization_id,
                        name=flow.name,
                        description=flow.description,
                        status=flow.status,
                        flow_type=flow.flow_type,
                        steps=steps_data,
                        transitions=transitions_data,
                        start_step_id=flow.start_step_id,
                        credential_template_id=flow.credential_template_id,
                        application_template_id=flow.application_template_id,
                        presentation_policy_id=flow.presentation_policy_id,
                        delivery_destination_profile_id=flow.delivery_destination_profile_id,
                        deployment_profile_id=flow.deployment_profile_id,
                        deployment_profile_ids=flow.deployment_profile_ids,
                        trust_profile_id=flow.trust_profile_id,
                        approval_strategy=flow.approval_strategy,
                        hooks=flow.hooks,
                        trigger=flow.trigger,
                        extension=flow.extension,
                        preconditions=preconditions_data,
                        default_timeout_seconds=flow.default_timeout_seconds,
                        max_retries=flow.max_retries,
                        enable_resume=flow.enable_resume,
                        version=flow.version,
                        updated_at=flow.updated_at,
                    )
                )
            else:
                # Insert
                await session.execute(
                    flow_definitions.insert().values(
                        id=flow.id,
                        organization_id=flow.organization_id,
                        name=flow.name,
                        description=flow.description,
                        status=flow.status,
                        flow_type=flow.flow_type,
                        steps=steps_data,
                        transitions=transitions_data,
                        start_step_id=flow.start_step_id,
                        credential_template_id=flow.credential_template_id,
                        application_template_id=flow.application_template_id,
                        presentation_policy_id=flow.presentation_policy_id,
                        delivery_destination_profile_id=flow.delivery_destination_profile_id,
                        deployment_profile_id=flow.deployment_profile_id,
                        deployment_profile_ids=flow.deployment_profile_ids,
                        trust_profile_id=flow.trust_profile_id,
                        approval_strategy=flow.approval_strategy,
                        hooks=flow.hooks,
                        trigger=flow.trigger,
                        extension=flow.extension,
                        preconditions=preconditions_data,
                        default_timeout_seconds=flow.default_timeout_seconds,
                        max_retries=flow.max_retries,
                        enable_resume=flow.enable_resume,
                        version=flow.version,
                        created_at=flow.created_at,
                        updated_at=flow.updated_at,
                    )
                )

            await session.commit()

    async def get_definition(self, flow_id: str) -> "FlowDefinition | None":
        """Get a flow definition by ID."""
        from flow.main import (
            FlowDefinition,
            FlowStep,
            FlowTransition,
            _parse_flow_status,
            _parse_flow_type,
        )

        async with self._session_factory() as session:
            result = await session.execute(
                select(flow_definitions).where(flow_definitions.c.id == flow_id)
            )
            row = result.first()

            if not row:
                return None

            preconditions, protocol_metadata = _deserialize_preconditions_payload(
                getattr(row, "preconditions", None)
            )

            steps_payload = row.steps if isinstance(row.steps, list) else []
            transitions_payload = (
                row.transitions if isinstance(row.transitions, list) else []
            )

            # Deserialize steps
            steps = [
                FlowStep(
                    id=step_data.get("id", ""),
                    name=step_data.get("name", ""),
                    description=step_data.get("description"),
                    step_type=_coerce_step_type(step_data.get("step_type")),
                    config=step_data.get("config", {}),
                    timeout_seconds=step_data.get("timeout_seconds"),
                    conditions=step_data.get("conditions", []),
                    approval_strategy=step_data.get("approval_strategy"),
                )
                for step_data in steps_payload
                if isinstance(step_data, dict)
            ]

            # Deserialize transitions
            transitions = [
                FlowTransition(
                    id=trans_data.get("id", ""),
                    from_step_id=trans_data.get("from_step_id", ""),
                    to_step_id=trans_data.get("to_step_id", ""),
                    condition=_coerce_transition_condition(trans_data.get("condition")),
                    condition_expression=trans_data.get("condition_expression"),
                )
                for trans_data in transitions_payload
                if isinstance(trans_data, dict)
            ]

            return FlowDefinition(
                id=row.id,
                organization_id=row.organization_id,
                name=row.name,
                description=row.description,
                status=_parse_flow_status(row.status),
                flow_type=_parse_flow_type(row.flow_type),
                steps=steps,
                transitions=transitions,
                start_step_id=row.start_step_id,
                preconditions=preconditions,
                credential_template_id=row.credential_template_id,
                application_template_id=row.application_template_id
                or protocol_metadata.get("application_template_id"),
                presentation_policy_id=row.presentation_policy_id,
                delivery_destination_profile_id=row.delivery_destination_profile_id,
                deployment_profile_id=row.deployment_profile_id,
                deployment_profile_ids=row.deployment_profile_ids
                or protocol_metadata.get("deployment_profile_ids")
                or ([row.deployment_profile_id] if row.deployment_profile_id else []),
                trust_profile_id=row.trust_profile_id
                or protocol_metadata.get("trust_profile_id"),
                approval_strategy=row.approval_strategy
                or protocol_metadata.get("approval_strategy", "AUTO"),
                hooks=row.hooks or protocol_metadata.get("hooks") or {},
                trigger=row.trigger or protocol_metadata.get("trigger"),
                extension=row.extension,
                default_timeout_seconds=row.default_timeout_seconds,
                max_retries=row.max_retries,
                enable_resume=row.enable_resume,
                version=row.version,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )

    async def list_definitions(self, org_id: str) -> list["FlowDefinition"]:
        """List all flow definitions for an organization."""
        from flow.main import (
            FlowDefinition,
            FlowStep,
            FlowTransition,
            _parse_flow_status,
            _parse_flow_type,
        )

        async with self._session_factory() as session:
            result = await session.execute(
                select(flow_definitions)
                .where(flow_definitions.c.organization_id == org_id)
                .order_by(flow_definitions.c.created_at.desc())
            )
            rows = result.all()

            definitions = []
            for row in rows:
                preconditions, protocol_metadata = _deserialize_preconditions_payload(
                    getattr(row, "preconditions", None)
                )
                steps_payload = row.steps if isinstance(row.steps, list) else []
                transitions_payload = (
                    row.transitions if isinstance(row.transitions, list) else []
                )
                # Deserialize steps
                steps = [
                    FlowStep(
                        id=step_data.get("id", ""),
                        name=step_data.get("name", ""),
                        description=step_data.get("description"),
                        step_type=_coerce_step_type(step_data.get("step_type")),
                        config=step_data.get("config", {}),
                        timeout_seconds=step_data.get("timeout_seconds"),
                        conditions=step_data.get("conditions", []),
                        approval_strategy=step_data.get("approval_strategy"),
                    )
                    for step_data in steps_payload
                    if isinstance(step_data, dict)
                ]

                # Deserialize transitions
                transitions = [
                    FlowTransition(
                        id=trans_data.get("id", ""),
                        from_step_id=trans_data.get("from_step_id", ""),
                        to_step_id=trans_data.get("to_step_id", ""),
                        condition=_coerce_transition_condition(
                            trans_data.get("condition")
                        ),
                        condition_expression=trans_data.get("condition_expression"),
                    )
                    for trans_data in transitions_payload
                    if isinstance(trans_data, dict)
                ]

                definitions.append(
                    FlowDefinition(
                        id=row.id,
                        organization_id=row.organization_id,
                        name=row.name,
                        description=row.description,
                        status=_parse_flow_status(row.status),
                        flow_type=_parse_flow_type(row.flow_type),
                        steps=steps,
                        transitions=transitions,
                        start_step_id=row.start_step_id,
                        preconditions=preconditions,
                        credential_template_id=row.credential_template_id,
                        application_template_id=row.application_template_id
                        or protocol_metadata.get("application_template_id"),
                        presentation_policy_id=row.presentation_policy_id,
                        delivery_destination_profile_id=row.delivery_destination_profile_id,
                        deployment_profile_id=row.deployment_profile_id,
                        deployment_profile_ids=row.deployment_profile_ids
                        or protocol_metadata.get("deployment_profile_ids")
                        or (
                            [row.deployment_profile_id]
                            if row.deployment_profile_id
                            else []
                        ),
                        trust_profile_id=row.trust_profile_id
                        or protocol_metadata.get("trust_profile_id"),
                        approval_strategy=row.approval_strategy
                        or protocol_metadata.get("approval_strategy", "AUTO"),
                        hooks=row.hooks or protocol_metadata.get("hooks") or {},
                        trigger=row.trigger or protocol_metadata.get("trigger"),
                        extension=row.extension,
                        default_timeout_seconds=row.default_timeout_seconds,
                        max_retries=row.max_retries,
                        enable_resume=row.enable_resume,
                        version=row.version,
                        created_at=row.created_at,
                        updated_at=row.updated_at,
                    )
                )

            return definitions

    async def delete_definition(self, flow_id: str) -> None:
        """Delete a flow definition."""
        async with self._session_factory() as session:
            await session.execute(
                delete(flow_definitions).where(flow_definitions.c.id == flow_id)
            )
            await session.commit()

    # ========== Flow Instance Operations ==========

    async def save_instance(self, instance: "FlowInstance") -> None:
        """Save or update a flow instance."""
        async with self._session_factory() as session:
            # Check if exists
            result = await session.execute(
                select(flow_instances.c.id).where(flow_instances.c.id == instance.id)
            )
            exists = result.scalar_one_or_none()

            if exists:
                # Update
                await session.execute(
                    flow_instances.update()
                    .where(
                        flow_instances.c.id == instance.id,
                        # Terminal decisions are immutable. In particular, a
                        # stale request/expiry handler must not overwrite a
                        # verification result committed after it read the row.
                        flow_instances.c.status.not_in(_TERMINAL_FLOW_STATUSES),
                    )
                    .values(
                        flow_definition_id=instance.flow_definition_id,
                        organization_id=instance.organization_id,
                        status=instance.status,
                        current_step_id=instance.current_step_id,
                        context=instance.context,
                        step_history=instance.step_history,
                        subject_id=instance.subject_id,
                        subject_type=instance.subject_type,
                        external_reference=instance.external_reference,
                        started_at=instance.started_at,
                        completed_at=instance.completed_at,
                        expires_at=instance.expires_at,
                        result=instance.result,
                        error=instance.error,
                        updated_at=instance.updated_at,
                    )
                )
            else:
                # Insert
                await session.execute(
                    flow_instances.insert().values(
                        id=instance.id,
                        flow_definition_id=instance.flow_definition_id,
                        organization_id=instance.organization_id,
                        status=instance.status,
                        current_step_id=instance.current_step_id,
                        context=instance.context,
                        step_history=instance.step_history,
                        subject_id=instance.subject_id,
                        subject_type=instance.subject_type,
                        external_reference=instance.external_reference,
                        started_at=instance.started_at,
                        completed_at=instance.completed_at,
                        expires_at=instance.expires_at,
                        result=instance.result,
                        error=instance.error,
                        created_at=instance.created_at,
                        updated_at=instance.updated_at,
                    )
                )

            await session.commit()

    async def finalize_verification(
        self,
        instance: "FlowInstance",
        *,
        nonce_digest: str,
        replay_expires_at,
        expected_status: "FlowInstanceStatus",
        callback_event: CallbackOutboxEvent | None = None,
    ) -> bool:
        """Atomically consume replay state and commit one terminal decision."""
        try:
            async with self._session_factory() as session:
                async with session.begin():
                    # Indexed opportunistic cleanup is part of the same
                    # transaction and uses database time so application clock
                    # skew cannot retire a live replay record early.
                    await session.execute(
                        delete(flow_nonce_consumptions).where(
                            flow_nonce_consumptions.c.expires_at
                            <= func.clock_timestamp()
                        )
                    )
                    replay_result = await session.execute(
                        pg_insert(flow_nonce_consumptions)
                        .values(
                            nonce_digest=nonce_digest,
                            flow_instance_id=instance.id,
                            consumed_at=func.clock_timestamp(),
                            expires_at=replay_expires_at,
                        )
                        .on_conflict_do_nothing()
                        .returning(flow_nonce_consumptions.c.nonce_digest)
                    )
                    if replay_result.scalar_one_or_none() is None:
                        raise _FinalizationConflict

                    update_result = await session.execute(
                        flow_instances.update()
                        .where(
                            flow_instances.c.id == instance.id,
                            flow_instances.c.status == expected_status.value,
                            # Expiry is part of the compare-and-swap boundary,
                            # not just an application-layer preflight check.
                            # PostgreSQL time is authoritative at commit.
                            or_(
                                flow_instances.c.expires_at.is_(None),
                                flow_instances.c.expires_at
                                >= func.clock_timestamp(),
                            ),
                        )
                        .values(
                            flow_definition_id=instance.flow_definition_id,
                            organization_id=instance.organization_id,
                            status=instance.status,
                            current_step_id=instance.current_step_id,
                            context=instance.context,
                            step_history=instance.step_history,
                            subject_id=instance.subject_id,
                            subject_type=instance.subject_type,
                            external_reference=instance.external_reference,
                            started_at=instance.started_at,
                            completed_at=instance.completed_at,
                            expires_at=instance.expires_at,
                            result=instance.result,
                            error=instance.error,
                            updated_at=instance.updated_at,
                        )
                    )
                    if update_result.rowcount != 1:
                        raise _FinalizationConflict
                    if callback_event is not None:
                        await session.execute(
                            flow_callback_outbox.insert().values(
                                event_id=callback_event.event_id,
                                flow_instance_id=callback_event.flow_instance_id,
                                organization_id=callback_event.organization_id,
                                destination_url=callback_event.destination_url,
                                audience=callback_event.audience,
                                event_type=callback_event.event_type,
                                payload=callback_event.payload,
                                status="pending",
                                attempt_count=0,
                                next_attempt_at=callback_event.next_attempt_at,
                                created_at=callback_event.created_at,
                                expires_at=callback_event.expires_at,
                            )
                        )
        except _FinalizationConflict:
            return False
        return True

    async def claim_due_callback_events(
        self,
        *,
        now: datetime,
        lease_expires_at: datetime,
        limit: int,
    ) -> list[CallbackOutboxEvent]:
        """Lease due callbacks across replicas using row locks."""
        claimed: list[CallbackOutboxEvent] = []
        async with self._session_factory() as session:
            async with session.begin():
                await session.execute(
                    flow_callback_outbox.update()
                    .where(
                        flow_callback_outbox.c.expires_at <= now,
                        flow_callback_outbox.c.status.in_(
                            ("pending", "retry", "delivering", "dead_letter")
                        ),
                    )
                    .values(
                        status="expired",
                        destination_url="",
                        payload={},
                        lease_token=None,
                        lease_expires_at=None,
                        last_error_code="retention_expired",
                    )
                )
                result = await session.execute(
                    select(flow_callback_outbox)
                    .where(
                        flow_callback_outbox.c.expires_at > now,
                        or_(
                            (
                                flow_callback_outbox.c.status.in_(("pending", "retry"))
                                & (flow_callback_outbox.c.next_attempt_at <= now)
                            ),
                            (
                                (flow_callback_outbox.c.status == "delivering")
                                & (flow_callback_outbox.c.lease_expires_at <= now)
                            ),
                        ),
                    )
                    .order_by(flow_callback_outbox.c.created_at)
                    .limit(limit)
                    .with_for_update(skip_locked=True)
                )
                for row in result.mappings().all():
                    lease_token = new_lease_token()
                    attempt_count = int(row["attempt_count"]) + 1
                    await session.execute(
                        flow_callback_outbox.update()
                        .where(flow_callback_outbox.c.event_id == row["event_id"])
                        .values(
                            status="delivering",
                            attempt_count=attempt_count,
                            lease_token=lease_token,
                            lease_expires_at=lease_expires_at,
                        )
                    )
                    claimed.append(
                        CallbackOutboxEvent(
                            event_id=row["event_id"],
                            flow_instance_id=row["flow_instance_id"],
                            organization_id=row["organization_id"],
                            destination_url=row["destination_url"],
                            audience=row["audience"],
                            event_type=row["event_type"],
                            payload=row["payload"],
                            created_at=row["created_at"],
                            next_attempt_at=row["next_attempt_at"],
                            expires_at=row["expires_at"],
                            status="delivering",
                            attempt_count=attempt_count,
                            lease_token=lease_token,
                            lease_expires_at=lease_expires_at,
                            delivered_at=row["delivered_at"],
                            last_error_code=row["last_error_code"],
                        )
                    )
        return claimed

    async def mark_callback_delivered(
        self,
        event_id: str,
        *,
        lease_token: str,
        delivered_at: datetime,
    ) -> bool:
        """Acknowledge a leased event and immediately scrub sensitive fields."""
        async with self._session_factory() as session:
            result = await session.execute(
                flow_callback_outbox.update()
                .where(
                    flow_callback_outbox.c.event_id == event_id,
                    flow_callback_outbox.c.status == "delivering",
                    flow_callback_outbox.c.lease_token == lease_token,
                )
                .values(
                    status="delivered",
                    destination_url="",
                    payload={},
                    delivered_at=delivered_at,
                    lease_token=None,
                    lease_expires_at=None,
                    last_error_code=None,
                )
            )
            await session.commit()
        return result.rowcount == 1

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
        """Release a lease for retry or move an exhausted event to dead letter."""
        del failed_at
        async with self._session_factory() as session:
            result = await session.execute(
                flow_callback_outbox.update()
                .where(
                    flow_callback_outbox.c.event_id == event_id,
                    flow_callback_outbox.c.status == "delivering",
                    flow_callback_outbox.c.lease_token == lease_token,
                )
                .values(
                    status="dead_letter" if terminal else "retry",
                    next_attempt_at=next_attempt_at,
                    lease_token=None,
                    lease_expires_at=None,
                    last_error_code=error_code,
                )
            )
            await session.commit()
        return result.rowcount == 1

    async def get_instance(self, instance_id: str) -> "FlowInstance | None":
        """Get a flow instance by ID."""
        from flow.main import FlowInstance, FlowInstanceStatus

        async with self._session_factory() as session:
            result = await session.execute(
                select(flow_instances).where(flow_instances.c.id == instance_id)
            )
            row = result.first()

            if not row:
                return None

            return FlowInstance(
                id=row.id,
                flow_definition_id=row.flow_definition_id,
                organization_id=row.organization_id,
                status=FlowInstanceStatus(row.status),
                current_step_id=row.current_step_id,
                context=row.context,
                step_history=row.step_history,
                subject_id=row.subject_id,
                subject_type=row.subject_type,
                external_reference=row.external_reference,
                started_at=row.started_at,
                completed_at=row.completed_at,
                expires_at=row.expires_at,
                result=row.result,
                error=row.error,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )

    async def list_instances(
        self,
        org_id: str,
        flow_definition_id: str | None = None,
        status: "FlowInstanceStatus | None" = None,
    ) -> list["FlowInstance"]:
        """List flow instances with optional filters."""
        from flow.main import FlowInstance, FlowInstanceStatus

        async with self._session_factory() as session:
            query = select(flow_instances).where(
                flow_instances.c.organization_id == org_id
            )

            if flow_definition_id:
                query = query.where(
                    flow_instances.c.flow_definition_id == flow_definition_id
                )

            if status:
                query = query.where(flow_instances.c.status == status)

            query = query.order_by(flow_instances.c.created_at.desc())

            result = await session.execute(query)
            rows = result.all()

            instances = []
            for row in rows:
                instances.append(
                    FlowInstance(
                        id=row.id,
                        flow_definition_id=row.flow_definition_id,
                        organization_id=row.organization_id,
                        status=FlowInstanceStatus(row.status),
                        current_step_id=row.current_step_id,
                        context=row.context,
                        step_history=row.step_history,
                        subject_id=row.subject_id,
                        subject_type=row.subject_type,
                        external_reference=row.external_reference,
                        started_at=row.started_at,
                        completed_at=row.completed_at,
                        expires_at=row.expires_at,
                        result=row.result,
                        error=row.error,
                        created_at=row.created_at,
                        updated_at=row.updated_at,
                    )
                )

            return instances
