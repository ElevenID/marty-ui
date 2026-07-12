"""MIP 0.3 application lifecycle and authorization regressions."""

from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

try:
    from applicant.main import (
        Applicant,
        ApplicantStatus,
        ApplicationStatus,
        InMemoryApplicantRepository,
        create_app,
        get_repo,
    )
    import applicant.main as service
except ModuleNotFoundError:
    from services.applicant.main import (
        Applicant,
        ApplicantStatus,
        ApplicationStatus,
        InMemoryApplicantRepository,
        create_app,
        get_repo,
    )
    import services.applicant.main as service


def run(coro):
    return asyncio.run(coro)


@pytest.fixture()
def repo(tmp_path):
    with patch.dict(os.environ, {"APPLICANT_DATA_FILE": str(tmp_path / "store.json")}):
        yield InMemoryApplicantRepository()


@pytest.fixture()
def template(monkeypatch):
    value = {
        "id": "application-template-1",
        "organization_id": "org-1",
        "credential_template_id": "credential-template-1",
        "name": "Member Credential Application",
        "status": "ACTIVE",
        "approval_strategy": "MANUAL",
        "form_fields": [
            {"name": "given_name", "type": "string", "required": True},
            {"name": "birth_date", "type": "date", "required": True},
        ],
        "required_checks": [
            {"check_type": "identity_verification", "is_required": True, "order": 1},
        ],
    }

    async def load(_template_id):
        return dict(value)

    monkeypatch.setattr(service, "_load_application_template", load)
    return value


@pytest.fixture()
def client(repo, template):
    app = create_app()
    app.dependency_overrides[get_repo] = lambda: repo
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def seeded(repo, client):
    applicant = Applicant(
        id="applicant-1",
        organization_id="org-1",
        user_id="user-1",
        oidc_subject="user-1",
        email="holder@example.test",
        given_name="Ada",
        family_name="Lovelace",
        status=ApplicantStatus.APPROVED,
    )
    run(repo.save(applicant))
    return applicant


def self_headers(user_id="user-1"):
    return {"X-User-Id": user_id, "X-User-Email": f"{user_id}@example.test"}


def reviewer_headers(org_id="org-1", permissions="application:review,application:approve,application:reject"):
    return {
        "X-User-Id": "reviewer-1",
        "X-User-Email": "reviewer@example.test",
        "X-Organization-Id": org_id,
        "X-Org-Permissions": permissions,
    }


def create_application(client, **overrides):
    payload = {
        "organization_id": "org-1",
        "application_template_id": "application-template-1",
        "form_data": {"given_name": "Ada", "birth_date": "1815-12-10"},
        "integration_context": {},
    }
    payload.update(overrides)
    return client.post("/v1/me/applications", headers=self_headers(), json=payload)


def test_removed_routes_and_fields_are_rejected(client, seeded):
    assert client.post("/v1/applicants/applications", json={}).status_code == 404
    response = create_application(client, applicant_id="spoofed-applicant")
    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "extra_forbidden"


def test_creation_derives_template_and_owner(client, seeded):
    response = create_application(client)
    assert response.status_code == 200
    body = response.json()
    assert body["applicant_id"] == "applicant-1"
    assert body["credential_template_id"] == "credential-template-1"
    assert body["application_template_id"] == "application-template-1"
    assert "metadata" not in body
    assert "credential_configuration_id" not in body


def test_invalid_iso_date_returns_structured_field_error(client, seeded):
    response = create_application(
        client,
        form_data={"given_name": "Ada", "birth_date": "12/10/1815"},
    )
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["error"] == "FIELD_VALIDATION_FAILED"
    assert detail["field_errors"] == [{
        "field": "birth_date",
        "code": "INVALID_DATE",
        "message": "Use an ISO date in YYYY-MM-DD format.",
    }]


def test_self_service_is_owner_scoped(client, seeded):
    application_id = create_application(client).json()["id"]
    response = client.get(
        f"/v1/me/applications/{application_id}",
        headers=self_headers("other-user"),
    )
    assert response.status_code == 403


def test_review_requires_actual_org_permission_and_callers_lock(client, seeded):
    application_id = create_application(client).json()["id"]
    submitted = client.post(f"/v1/me/applications/{application_id}/submit", headers=self_headers())
    assert submitted.status_code == 200, submitted.text

    wrong_org = client.get(
        f"/v1/organizations/org-2/applicants/{application_id}",
        headers=reviewer_headers("org-2"),
    )
    assert wrong_org.status_code == 403

    no_lock = client.post(
        f"/v1/organizations/org-1/applicants/{application_id}/approve",
        headers=reviewer_headers(),
        json={"notes": "verified"},
    )
    assert no_lock.status_code == 409

    lock = client.post(
        f"/v1/organizations/org-1/applicants/{application_id}/lock",
        headers=reviewer_headers(),
        json={"reviewer_id": "spoofed"},
    )
    assert lock.status_code == 200
    assert lock.json()["holder_user_id"] == "reviewer-1"

    approved = client.post(
        f"/v1/organizations/org-1/applicants/{application_id}/approve",
        headers=reviewer_headers(),
        json={"notes": "verified"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == ApplicationStatus.APPROVED.value


def test_claim_blocked_state_is_persisted(client, repo, seeded, monkeypatch):
    application_id = create_application(client).json()["id"]
    application = run(repo.get_application(application_id))
    application.status = ApplicationStatus.APPROVED
    run(repo.save_application(application))

    async def unavailable(**_kwargs):
        raise HTTPException(status_code=409, detail="No active flow")

    monkeypatch.setattr(service, "_initiate_issuance_via_flow", unavailable)
    response = client.post(
        f"/v1/me/applications/{application_id}/claim",
        headers=self_headers(),
        json={},
    )
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "NO_ACTIVE_ISSUANCE_FLOW"

    saved = run(repo.get_application(application_id))
    assert saved.status == ApplicationStatus.APPROVED
    assert saved.claim_state.value == "BLOCKED"
    assert saved.claim_blocker["owner"] == "ISSUER"


def test_claim_offer_ready_uses_only_form_claims(client, repo, seeded, monkeypatch):
    application_id = create_application(client).json()["id"]
    application = run(repo.get_application(application_id))
    application.status = ApplicationStatus.APPROVED
    run(repo.save_application(application))
    captured = {}

    async def issue(**kwargs):
        captured.update(kwargs["claims"])
        return {
            "id": "transaction-1",
            "status": "pending",
            "credential_offer_uri": "openid-credential-offer://offer-1",
            "expires_at": "2099-01-01T00:00:00Z",
        }

    monkeypatch.setattr(service, "_initiate_issuance_via_flow", issue)
    response = client.post(
        f"/v1/me/applications/{application_id}/claim",
        headers=self_headers(),
        json={},
    )
    assert response.status_code == 200
    assert response.json()["claim_state"] == "OFFER_READY"
    assert captured["birth_date"] == "1815-12-10"
    assert "integration_context" not in captured
    assert "approval_strategy" not in captured
