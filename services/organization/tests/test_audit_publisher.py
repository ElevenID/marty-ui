from __future__ import annotations

from typing import Any

from services.organization.domain.entities import AuditEvent
from services.organization.domain.events import ApiKeyCreatedEvent, OrganizationCreatedEvent
from services.organization.infrastructure.adapters.audit_publisher import AuditEventPublisher


class FakeAuditRepo:
    def __init__(self) -> None:
        self.saved: list[AuditEvent] = []

    async def save(self, event: AuditEvent) -> None:
        self.saved.append(event)

    async def get(self, organization_id: str, event_id: str) -> AuditEvent | None:
        return None

    async def list(self, query: Any) -> tuple[list[AuditEvent], int]:
        return [], 0


class FakeDelegate:
    def __init__(self) -> None:
        self.published: list[Any] = []

    async def publish(self, event: Any) -> None:
        self.published.append(event)


async def test_audit_publisher_records_api_key_events_and_delegates() -> None:
    repo = FakeAuditRepo()
    delegate = FakeDelegate()
    publisher = AuditEventPublisher(repo, delegate)
    event = ApiKeyCreatedEvent(
        organization_id="22222222-2222-2222-2222-222222222222",
        api_key_id="key-1",
        name="Console key",
        created_by="user-1",
    )

    await publisher.publish(event)

    assert len(repo.saved) == 1
    audit_event = repo.saved[0]
    assert audit_event.organization_id == event.organization_id
    assert audit_event.action == "api_key.created"
    assert audit_event.category == "settings"
    assert audit_event.resource_type == "api_key"
    assert audit_event.resource_id == "key-1"
    assert audit_event.actor_id == "user-1"
    assert audit_event.metadata["source_event_id"] == event.event_id
    assert delegate.published == [event]


async def test_audit_publisher_records_organization_created_actor() -> None:
    repo = FakeAuditRepo()
    publisher = AuditEventPublisher(repo)
    event = OrganizationCreatedEvent(
        organization_id="22222222-2222-2222-2222-222222222222",
        name="Marty",
        owner_user_id="owner-1",
    )

    await publisher.publish(event)

    audit_event = repo.saved[0]
    assert audit_event.action == "organization.created"
    assert audit_event.resource_name == "Marty"
    assert audit_event.actor_id == "owner-1"
