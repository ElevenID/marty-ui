from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.organization.application.ports import AuditEventQuery
from services.organization.domain.entities import AuditEvent
from services.organization.infrastructure.adapters.audit_adapter import (
    configure_audit_router,
    router,
)
from services.organization.infrastructure.adapters.postgres_adapter import (
    PostgresAuditEventRepository,
)


class FakeAuditRepo:
    def __init__(self) -> None:
        self.events = [
            AuditEvent(
                id="11111111-1111-1111-1111-111111111111",
                organization_id="22222222-2222-2222-2222-222222222222",
                event_type="api.key.created.event",
                action="api_key.created",
                category="settings",
                resource_type="api_key",
                resource_id="key-1",
                resource_name="Console key",
                actor_id="user-1",
                actor_type="user",
                message="API key Console key created",
                metadata={"ip_address": "127.0.0.1"},
            )
        ]
        self.last_query: AuditEventQuery | None = None

    async def save(self, event: AuditEvent) -> None:
        self.events.append(event)

    async def get(self, organization_id: str, event_id: str) -> AuditEvent | None:
        return next(
            (
                event
                for event in self.events
                if event.organization_id == organization_id and event.id == event_id
            ),
            None,
        )

    async def list(self, query: AuditEventQuery) -> tuple[list[AuditEvent], int]:
        self.last_query = query
        return self.events, len(self.events)


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_audit_routes_report_unavailable_when_storage_is_not_configured() -> None:
    configure_audit_router(None)
    client = _client()

    for path in (
        "/v1/organizations/audit/events?organization_id=org-1",
        "/v1/organizations/audit/events/export?organization_id=org-1",
        "/v1/organizations/audit/events/event-1?organization_id=org-1",
    ):
        response = client.get(path)

        assert response.status_code == 501
        assert response.json()["detail"]["error"] == "audit_log_unavailable"
        assert response.json()["detail"]["message_id"]


def test_audit_list_returns_persisted_events_with_filters() -> None:
    repo = FakeAuditRepo()
    configure_audit_router(repo)
    client = _client()

    try:
        response = client.get(
            "/v1/organizations/audit/events",
            params={
                "organization_id": "22222222-2222-2222-2222-222222222222",
                "limit": 25,
                "offset": 50,
                "resource_type": "api_key",
                "resource_id": "key-1",
                "action": "api_key.created",
                "actor": "user-1",
                "severity": "info",
                "ip_address": "127.0.0.1",
            },
        )
    finally:
        configure_audit_router(None)

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["page"] == 3
    assert payload["per_page"] == 25
    assert payload["events"][0]["action"] == "api_key.created"
    assert payload["events"][0]["resource_type"] == "api_key"
    assert payload["events"][0]["metadata"]["ip_address"] == "127.0.0.1"
    assert repo.last_query is not None
    assert repo.last_query.resource_id == "key-1"
    assert repo.last_query.actor == "user-1"


def test_audit_repository_resource_type_filter_does_not_impersonate_category() -> None:
    query = AuditEventQuery(
        organization_id="22222222-2222-2222-2222-222222222222",
        resource_type="api_key",
    )

    conditions = PostgresAuditEventRepository._conditions_for_query(query)
    condition_text = "\n".join(str(condition) for condition in conditions)

    assert "audit_events.resource_type" in condition_text
    assert "audit_events.category" not in condition_text


def test_audit_list_rejects_invalid_date_filters() -> None:
    configure_audit_router(FakeAuditRepo())
    client = _client()

    try:
        response = client.get(
            "/v1/organizations/audit/events",
            params={
                "organization_id": "22222222-2222-2222-2222-222222222222",
                "start_date": "not-a-date",
            },
        )
    finally:
        configure_audit_router(None)

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_audit_filter"
    assert response.json()["detail"]["message_id"]


def test_audit_list_applies_explicit_time_range() -> None:
    repo = FakeAuditRepo()
    configure_audit_router(repo)
    client = _client()

    try:
        response = client.get(
            "/v1/organizations/audit/events",
            params={
                "organization_id": "22222222-2222-2222-2222-222222222222",
                "time_range": "24h",
            },
        )
    finally:
        configure_audit_router(None)

    assert response.status_code == 200
    assert repo.last_query is not None
    assert repo.last_query.start_date is not None


def test_audit_list_rejects_invalid_time_range() -> None:
    configure_audit_router(FakeAuditRepo())
    client = _client()

    try:
        response = client.get(
            "/v1/organizations/audit/events",
            params={
                "organization_id": "22222222-2222-2222-2222-222222222222",
                "time_range": "recently",
            },
        )
    finally:
        configure_audit_router(None)

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "invalid_audit_filter"


def test_audit_detail_is_scoped_to_organization() -> None:
    repo = FakeAuditRepo()
    configure_audit_router(repo)
    client = _client()

    try:
        response = client.get(
            "/v1/organizations/audit/events/11111111-1111-1111-1111-111111111111",
            params={"organization_id": "22222222-2222-2222-2222-222222222222"},
        )
        missing = client.get(
            "/v1/organizations/audit/events/11111111-1111-1111-1111-111111111111",
            params={"organization_id": "33333333-3333-3333-3333-333333333333"},
        )
    finally:
        configure_audit_router(None)

    assert response.status_code == 200
    assert response.json()["id"] == "11111111-1111-1111-1111-111111111111"
    assert missing.status_code == 404
    assert missing.json()["detail"]["error"] == "audit_event_not_found"


def test_audit_export_returns_truthful_content() -> None:
    repo = FakeAuditRepo()
    configure_audit_router(repo)
    client = _client()

    try:
        response = client.get(
            "/v1/organizations/audit/events/export",
            params={
                "organization_id": "22222222-2222-2222-2222-222222222222",
                "format": "csv",
            },
        )
    finally:
        configure_audit_router(None)

    assert response.status_code == 200
    payload = response.json()
    assert payload["format"] == "csv"
    assert payload["filename"].endswith(".csv")
    assert "api_key.created" in payload["content"]
