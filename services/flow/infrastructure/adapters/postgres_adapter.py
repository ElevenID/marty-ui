"""
PostgreSQL adapter for flow repository.
"""
from typing import TYPE_CHECKING

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

if TYPE_CHECKING:
    from flow.main import FlowDefinition, FlowInstance, FlowStatus, FlowType, FlowInstanceStatus

from flow.infrastructure.models import flow_definitions, flow_instances


class PostgresFlowRepository:
    """PostgreSQL implementation of flow repository."""
    
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]):
        self._session_factory = session_factory
    
    # ========== Flow Definition Operations ==========
    
    async def save_definition(self, flow: "FlowDefinition") -> None:
        """Save or update a flow definition."""
        async with self._session_factory() as session:
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
                        presentation_policy_id=flow.presentation_policy_id,
                        deployment_profile_id=flow.deployment_profile_id,
                        preconditions=flow.preconditions,
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
                        presentation_policy_id=flow.presentation_policy_id,
                        deployment_profile_id=flow.deployment_profile_id,
                        preconditions=flow.preconditions,
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
        from flow.main import FlowDefinition, FlowStatus, FlowType, FlowStep, FlowTransition, StepType, TransitionCondition
        
        async with self._session_factory() as session:
            result = await session.execute(
                select(flow_definitions).where(flow_definitions.c.id == flow_id)
            )
            row = result.first()
            
            if not row:
                return None
            
            # Deserialize steps
            steps = [
                FlowStep(
                    id=step_data.get("id", ""),
                    name=step_data.get("name", ""),
                    description=step_data.get("description"),
                    step_type=StepType(step_data.get("step_type", "user_input")),
                    config=step_data.get("config", {}),
                    timeout_seconds=step_data.get("timeout_seconds"),
                    conditions=step_data.get("conditions", []),
                )
                for step_data in row.steps
            ]
            
            # Deserialize transitions
            transitions = [
                FlowTransition(
                    id=trans_data.get("id", ""),
                    from_step_id=trans_data.get("from_step_id", ""),
                    to_step_id=trans_data.get("to_step_id", ""),
                    condition=TransitionCondition(trans_data.get("condition", "success")),
                    condition_expression=trans_data.get("condition_expression"),
                )
                for trans_data in row.transitions
            ]
            
            return FlowDefinition(
                id=row.id,
                organization_id=row.organization_id,
                name=row.name,
                description=row.description,
                status=FlowStatus(row.status),
                flow_type=FlowType(row.flow_type),
                steps=steps,
                transitions=transitions,
                start_step_id=row.start_step_id,
                preconditions=getattr(row, 'preconditions', None) or [],
                credential_template_id=row.credential_template_id,
                presentation_policy_id=row.presentation_policy_id,
                deployment_profile_id=row.deployment_profile_id,
                default_timeout_seconds=row.default_timeout_seconds,
                max_retries=row.max_retries,
                enable_resume=row.enable_resume,
                version=row.version,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )
    
    async def list_definitions(self, org_id: str) -> list["FlowDefinition"]:
        """List all flow definitions for an organization."""
        from flow.main import FlowDefinition, FlowStatus, FlowType, FlowStep, FlowTransition, StepType, TransitionCondition
        
        async with self._session_factory() as session:
            result = await session.execute(
                select(flow_definitions)
                .where(flow_definitions.c.organization_id == org_id)
                .order_by(flow_definitions.c.created_at.desc())
            )
            rows = result.all()
            
            definitions = []
            for row in rows:
                # Deserialize steps
                steps = [
                    FlowStep(
                        id=step_data.get("id", ""),
                        name=step_data.get("name", ""),
                        description=step_data.get("description"),
                        step_type=StepType(step_data.get("step_type", "user_input")),
                        config=step_data.get("config", {}),
                        timeout_seconds=step_data.get("timeout_seconds"),
                        conditions=step_data.get("conditions", []),
                    )
                    for step_data in row.steps
                ]
                
                # Deserialize transitions
                transitions = [
                    FlowTransition(
                        id=trans_data.get("id", ""),
                        from_step_id=trans_data.get("from_step_id", ""),
                        to_step_id=trans_data.get("to_step_id", ""),
                        condition=TransitionCondition(trans_data.get("condition", "success")),
                        condition_expression=trans_data.get("condition_expression"),
                    )
                    for trans_data in row.transitions
                ]
                
                definitions.append(
                    FlowDefinition(
                        id=row.id,
                        organization_id=row.organization_id,
                        name=row.name,
                        description=row.description,
                        status=FlowStatus(row.status),
                        flow_type=FlowType(row.flow_type),
                        steps=steps,
                        transitions=transitions,
                        start_step_id=row.start_step_id,
                        preconditions=getattr(row, 'preconditions', None) or [],
                        credential_template_id=row.credential_template_id,
                        presentation_policy_id=row.presentation_policy_id,
                        deployment_profile_id=row.deployment_profile_id,
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
                    .where(flow_instances.c.id == instance.id)
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
            query = select(flow_instances).where(flow_instances.c.organization_id == org_id)
            
            if flow_definition_id:
                query = query.where(flow_instances.c.flow_definition_id == flow_definition_id)
            
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
