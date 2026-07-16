"""Audit event publisher for organization domain events."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ...application.ports import AuditEventRepositoryPort, EventPublisherPort
from ...domain.entities import AuditEvent
from ...domain.events import (
    ApiKeyCreatedEvent,
    ApiKeyRevokedEvent,
    MemberAddedEvent,
    MemberInvitedEvent,
    MemberRemovedEvent,
    OrganizationCreatedEvent,
    OrganizationUpdatedEvent,
    RoleAssignedEvent,
    RoleCreatedEvent,
    RoleDeletedEvent,
    RoleRemovedFromMemberEvent,
    RoleUpdatedEvent,
)


class AuditEventPublisher(EventPublisherPort):
    """Persist organization audit events, then delegate live event fan-out."""

    def __init__(
        self,
        audit_repo: AuditEventRepositoryPort,
        delegate: EventPublisherPort | None = None,
    ) -> None:
        self.audit_repo = audit_repo
        self.delegate = delegate

    async def publish(self, event: Any) -> None:
        audit_event = self._to_audit_event(event)
        if audit_event is not None:
            await self.audit_repo.save(audit_event)

        if self.delegate is not None:
            await self.delegate.publish(event)

    def _to_audit_event(self, event: Any) -> AuditEvent | None:
        organization_id = str(getattr(event, "organization_id", "") or "")
        if not organization_id:
            return None

        event_type = getattr(event, "event_type", "") or type(event).__name__
        timestamp = getattr(event, "timestamp", None) or datetime.now(timezone.utc)
        metadata = self._event_metadata(event)

        if isinstance(event, OrganizationCreatedEvent):
            return AuditEvent(
                organization_id=organization_id,
                event_type=event_type,
                action="organization.created",
                category="settings",
                resource_type="organization",
                resource_id=event.organization_id,
                resource_name=event.name,
                actor_id=event.owner_user_id,
                actor_type="user",
                message=f"Organization {event.name} created",
                metadata=metadata,
                timestamp=timestamp,
            )

        if isinstance(event, OrganizationUpdatedEvent):
            return AuditEvent(
                organization_id=organization_id,
                event_type=event_type,
                action="organization.updated",
                category="settings",
                resource_type="organization",
                resource_id=event.organization_id,
                actor_type="system",
                message="Organization settings updated",
                changes={"updated_fields": event.updated_fields},
                metadata=metadata,
                timestamp=timestamp,
            )

        if isinstance(event, MemberInvitedEvent):
            return AuditEvent(
                organization_id=organization_id,
                event_type=event_type,
                action="team.member.invited",
                category="team",
                resource_type="member",
                resource_id=event.member_id,
                resource_name=event.email,
                actor_id=event.invited_by,
                actor_type="user",
                message=f"Member invitation sent to {event.email}",
                metadata=metadata,
                timestamp=timestamp,
            )

        if isinstance(event, MemberAddedEvent):
            return AuditEvent(
                organization_id=organization_id,
                event_type=event_type,
                action="team.member.added",
                category="team",
                resource_type="member",
                resource_id=event.member_id,
                resource_name=event.user_id,
                actor_id=event.user_id,
                actor_type="user",
                message="Member added to organization",
                metadata=metadata,
                timestamp=timestamp,
            )

        if isinstance(event, MemberRemovedEvent):
            return AuditEvent(
                organization_id=organization_id,
                event_type=event_type,
                action="team.member.removed",
                category="team",
                resource_type="member",
                resource_id=event.member_id,
                resource_name=event.user_id,
                actor_id=event.user_id,
                actor_type="user",
                severity="warning",
                message="Member removed from organization",
                metadata=metadata,
                timestamp=timestamp,
            )

        if isinstance(event, ApiKeyCreatedEvent):
            return AuditEvent(
                organization_id=organization_id,
                event_type=event_type,
                action="api_key.created",
                category="settings",
                resource_type="api_key",
                resource_id=event.api_key_id,
                resource_name=event.name,
                actor_id=event.created_by,
                actor_type="user",
                message=f"API key {event.name} created",
                metadata=metadata,
                timestamp=timestamp,
            )

        if isinstance(event, ApiKeyRevokedEvent):
            return AuditEvent(
                organization_id=organization_id,
                event_type=event_type,
                action="api_key.revoked",
                category="settings",
                resource_type="api_key",
                resource_id=event.api_key_id,
                actor_id=event.revoked_by,
                actor_type="user",
                severity="warning",
                message="API key revoked",
                metadata=metadata,
                timestamp=timestamp,
            )

        if isinstance(event, RoleCreatedEvent):
            return self._role_event(
                event,
                action="team.role.created",
                actor_id=event.created_by,
                message=f"Role {event.role_name} created",
            )

        if isinstance(event, RoleUpdatedEvent):
            return self._role_event(
                event,
                action="team.role.updated",
                actor_id=event.updated_by,
                message=f"Role {event.role_name} updated",
            )

        if isinstance(event, RoleDeletedEvent):
            return self._role_event(
                event,
                action="team.role.deleted",
                actor_id=event.deleted_by,
                message=f"Role {event.role_name} deleted",
                severity="warning",
            )

        if isinstance(event, RoleAssignedEvent):
            return self._role_event(
                event,
                action="team.role.assigned",
                actor_id=event.assigned_by,
                message=f"Role {event.role_name} assigned",
                resource_id=event.member_id,
            )

        if isinstance(event, RoleRemovedFromMemberEvent):
            return self._role_event(
                event,
                action="team.role.removed",
                actor_id=event.removed_by,
                message=f"Role {event.role_name} removed",
                resource_id=event.member_id,
                severity="warning",
            )

        return AuditEvent(
            organization_id=organization_id,
            event_type=event_type,
            action=event_type,
            category="settings",
            resource_type="organization",
            resource_id=organization_id,
            actor_type="system",
            message=event_type,
            metadata=metadata,
            timestamp=timestamp,
        )

    def _role_event(
        self,
        event: Any,
        *,
        action: str,
        actor_id: str,
        message: str,
        resource_id: str | None = None,
        severity: str = "info",
    ) -> AuditEvent:
        return AuditEvent(
            organization_id=event.organization_id,
            event_type=getattr(event, "event_type", "") or type(event).__name__,
            action=action,
            category="team",
            resource_type="role",
            resource_id=resource_id or event.role_id,
            resource_name=event.role_name,
            actor_id=actor_id,
            actor_type="user" if actor_id else "system",
            severity=severity,
            message=message,
            metadata=self._event_metadata(event),
            timestamp=getattr(event, "timestamp", None) or datetime.now(timezone.utc),
        )

    @staticmethod
    def _event_metadata(event: Any) -> dict[str, Any]:
        event_dict = event.to_dict() if hasattr(event, "to_dict") else {}
        metadata = {
            "source_service": getattr(event, "source_service", "organization"),
            "source_event_id": getattr(event, "event_id", None),
            "source_event_type": getattr(event, "event_type", type(event).__name__),
        }
        data = event_dict.get("data")
        if isinstance(data, dict):
            metadata["event_data"] = data
        return metadata
