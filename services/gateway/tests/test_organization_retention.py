from __future__ import annotations

from typing import Any

import pytest

from gateway.routes import organizations as organization_routes


@pytest.mark.asyncio
async def test_run_hosted_pilot_purge_persists_last_purged_at(monkeypatch):
    calls: list[dict[str, Any]] = []

    async def fake_request(
        service_name: str,
        path: str,
        *,
        method: str = "GET",
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        client=None,
        registry=None,
    ):
        calls.append(
            {
                "service_name": service_name,
                "path": path,
                "method": method,
                "params": params,
                "json_body": json_body,
            }
        )
        if service_name == "organizations" and path == "/v1/organizations/org-1/lifecycle":
            return {
                "created_at": "2026-04-01T00:00:00+00:00",
                "audit_retention_days": 30,
                "pilot_retention": {
                    "enabled": True,
                    "window_days": 30,
                    "last_purged_at": None,
                },
            }, None
        if service_name == "issuance" and path == "/v1/issuance/organizations/org-1/retention":
            return {
                "cutoff_at": "2026-03-14T00:00:00+00:00",
                "next_expiry_at": "2026-04-14T00:00:00+00:00",
                "oldest_retained_record_at": "2026-03-15T00:00:00+00:00",
                "eligible_for_purge": {"total": 4},
                "tracked_scope": ["applications"],
            }, None
        if service_name == "issuance" and path == "/v1/issuance/organizations/org-1/retention/purge":
            return {
                "organization_id": "org-1",
                "retention_days": 30,
                "cutoff_at": "2026-03-14T00:00:00+00:00",
                "purged_at": "2026-04-13T12:00:00+00:00",
                "purged_records": {"total": 4},
                "tracked_scope": ["applications"],
            }, None
        if service_name == "organizations" and path == "/internal/v1/organizations/org-1/settings":
            return {"ok": True}, None
        raise AssertionError(f"Unexpected request: {service_name} {path}")

    monkeypatch.setattr(organization_routes, "_request_service_json_with_headers", fake_request)

    payload, error_response = await organization_routes.run_hosted_pilot_purge("org-1")

    assert error_response is None
    assert payload["purged_at"] == "2026-04-13T12:00:00+00:00"
    sync_call = next(
        call for call in calls if call["path"] == "/internal/v1/organizations/org-1/settings"
    )
    assert sync_call["json_body"] == {
        "settings_patch": {
            "pilot_retention_last_purged_at": "2026-04-13T12:00:00+00:00",
        },
    }


@pytest.mark.asyncio
async def test_auto_purge_sweep_only_purges_due_hosted_pilot_orgs(monkeypatch):
    calls: list[dict[str, Any]] = []

    async def fake_request(
        service_name: str,
        path: str,
        *,
        method: str = "GET",
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        client=None,
        registry=None,
    ):
        calls.append(
            {
                "service_name": service_name,
                "path": path,
                "method": method,
                "params": params,
                "json_body": json_body,
            }
        )

        if service_name == "organizations" and path == "/v1/organizations":
            return [
                {"id": "org-1"},
                {"id": "org-2"},
                {"id": "org-3"},
            ], None

        if service_name == "organizations" and path == "/internal/v1/organizations/org-1/lifecycle":
            return {
                "created_at": "2026-04-01T00:00:00+00:00",
                "audit_retention_days": 30,
                "pilot_retention": {"enabled": True, "window_days": 30},
            }, None

        if service_name == "organizations" and path == "/internal/v1/organizations/org-2/lifecycle":
            return {
                "created_at": "2026-04-01T00:00:00+00:00",
                "audit_retention_days": 90,
                "pilot_retention": None,
            }, None

        if service_name == "organizations" and path == "/internal/v1/organizations/org-3/lifecycle":
            return {
                "created_at": "2026-04-01T00:00:00+00:00",
                "audit_retention_days": 30,
                "pilot_retention": {"enabled": True, "window_days": 30},
            }, None

        if service_name == "issuance" and path == "/v1/issuance/organizations/org-1/retention":
            return {
                "cutoff_at": "2026-03-14T00:00:00+00:00",
                "next_expiry_at": "2026-04-13T00:00:00+00:00",
                "oldest_retained_record_at": "2026-03-15T00:00:00+00:00",
                "eligible_for_purge": {"total": 2},
                "tracked_scope": ["applications"],
            }, None

        if service_name == "issuance" and path == "/v1/issuance/organizations/org-3/retention":
            return {
                "cutoff_at": "2026-03-14T00:00:00+00:00",
                "next_expiry_at": "2099-04-20T00:00:00+00:00",
                "oldest_retained_record_at": "2026-04-12T00:00:00+00:00",
                "eligible_for_purge": {"total": 0},
                "tracked_scope": ["applications"],
            }, None

        if service_name == "issuance" and path == "/v1/issuance/organizations/org-1/retention/purge":
            return {
                "organization_id": "org-1",
                "retention_days": 30,
                "cutoff_at": "2026-03-14T00:00:00+00:00",
                "purged_at": "2026-04-13T12:00:00+00:00",
                "purged_records": {"total": 2},
                "tracked_scope": ["applications"],
            }, None

        if service_name == "organizations" and path == "/internal/v1/organizations/org-1/settings":
            return {"ok": True}, None

        raise AssertionError(f"Unexpected request: {service_name} {path}")

    monkeypatch.setattr(organization_routes, "_request_service_json_with_headers", fake_request)

    stats = await organization_routes.run_hosted_pilot_auto_purge_sweep(batch_size=50)

    assert stats == {
        "organizations_scanned": 3,
        "hosted_pilot_orgs": 2,
        "purge_requests": 1,
        "purged_records": 2,
    }
    purge_paths = [
        call["path"]
        for call in calls
        if call["service_name"] == "issuance" and call["path"].endswith("/retention/purge")
    ]
    assert purge_paths == ["/v1/issuance/organizations/org-1/retention/purge"]
