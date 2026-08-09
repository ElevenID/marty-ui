"""Current public application-evidence boundary regressions."""

from __future__ import annotations

import asyncio
import base64
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

try:
    from applicant.main import (
        Applicant,
        ApplicantStatus,
        InMemoryApplicantRepository,
        create_app,
        get_repo,
    )
    import applicant.main as service
except ModuleNotFoundError:
    from services.applicant.main import (
        Applicant,
        ApplicantStatus,
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
def templates(monkeypatch):
    def template(template_id: str, organization_id: str) -> dict:
        return {
            "id": template_id,
            "organization_id": organization_id,
            "credential_template_id": f"credential-{organization_id}",
            "name": "Identity application",
            "status": "ACTIVE",
            "approval_strategy": "MANUAL",
            "form_fields": [
                {"field_id": "name", "label": "Name", "field_type": "TEXT", "required": True},
            ],
            "evidence_requirements": [
                {
                    "evidence_id": "government_id_front",
                    "evidence_type": "DOCUMENT_SCAN",
                    "description": "Government ID front",
                    "required": True,
                    "accepted_formats": ["image/png"],
                    "max_file_size_bytes": 4096,
                },
            ],
            "required_checks": [
                {"check_type": "document_verification", "is_required": True, "order": 1},
            ],
        }

    values = {
        "template-org-1": template("template-org-1", "org-1"),
        "template-org-2": template("template-org-2", "org-2"),
    }

    async def load(template_id):
        return dict(values[template_id])

    monkeypatch.setattr(service, "_load_application_template", load)
    return values


@pytest.fixture()
def client(repo, templates):
    app = create_app()
    app.dependency_overrides[get_repo] = lambda: repo
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def principals(repo):
    for org_id, user_id in (("org-1", "user-1"), ("org-2", "user-2")):
        run(repo.save(Applicant(
            id=f"applicant-{org_id}",
            organization_id=org_id,
            user_id=user_id,
            oidc_subject=user_id,
            email=f"{user_id}@example.test",
            status=ApplicantStatus.APPROVED,
        )))


def self_headers(org_id="org-1", user_id="user-1"):
    return {
        "X-User-Id": user_id,
        "X-User-Email": f"{user_id}@example.test",
        "X-Organization-ID": org_id,
    }


def reviewer_headers(org_id="org-1"):
    return {
        "X-User-Id": f"reviewer-{org_id}",
        "X-User-Email": f"reviewer-{org_id}@example.test",
        "X-Organization-Id": org_id,
        "X-Org-Permissions": "application:review,application:approve",
    }


def create_application(client, org_id="org-1", user_id="user-1") -> str:
    response = client.post(
        "/v1/me/applications",
        headers=self_headers(org_id, user_id),
        json={
            "organization_id": org_id,
            "application_template_id": f"template-{org_id}",
            "form_data": {"name": user_id},
            "integration_context": {},
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def evidence_payload(content=b"verified government identity document", **overrides):
    payload = {
        "evidence_requirement_id": "government_id_front",
        "media_type": "image/png",
        "filename": "government-id-front.png",
        "content_base64": base64.b64encode(content).decode("ascii"),
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }
    payload.update(overrides)
    return payload


def upload_evidence(client, application_id: str, org_id="org-1", user_id="user-1"):
    response = client.post(
        f"/v1/me/applications/{application_id}/evidence",
        headers=self_headers(org_id, user_id),
        json=evidence_payload(),
    )
    assert response.status_code == 200, response.text
    return response


def test_required_evidence_uses_current_self_and_reviewer_paths(client, principals):
    application_id = create_application(client)

    missing = client.post(
        f"/v1/me/applications/{application_id}/submit",
        headers=self_headers(),
    )
    assert missing.status_code == 422
    assert missing.json()["detail"]["error"] == "EVIDENCE_VALIDATION_FAILED"

    uploaded = upload_evidence(client, application_id)
    evidence = uploaded.json()
    evidence_id = evidence["id"]
    assert evidence["organization_id"] == "org-1"
    assert evidence["application_id"] == application_id
    assert evidence["status"] == "ACTIVE"
    assert evidence["content_url"].startswith("/v1/me/applications/")
    assert {
        "storage_key", "storage_path", "bucket", "service_id", "provider_id", "kms_id",
    }.isdisjoint(evidence)

    download = client.get(evidence["content_url"], headers=self_headers())
    assert download.status_code == 200
    assert download.content == b"verified government identity document"
    assert download.headers["cache-control"] == "private, no-store"

    reviewer = client.get(
        f"/v1/organizations/org-1/applicants/{application_id}/evidence",
        headers=reviewer_headers(),
    )
    assert reviewer.status_code == 200
    assert reviewer.json()[0]["id"] == evidence_id
    assert reviewer.json()[0]["content_url"].startswith("/v1/organizations/org-1/applicants/")

    foreign_reviewer = client.get(
        f"/v1/organizations/org-2/applicants/{application_id}/evidence",
        headers=reviewer_headers("org-2"),
    )
    assert foreign_reviewer.status_code == 404
    foreign_applicant = client.get(
        f"/v1/me/applications/{application_id}/evidence/{evidence_id}",
        headers=self_headers("org-2", "user-2"),
    )
    assert foreign_applicant.status_code == 404

    submitted = client.post(
        f"/v1/me/applications/{application_id}/submit",
        headers=self_headers(),
    )
    assert submitted.status_code == 200, submitted.text
    assert submitted.json()["status"] == "SUBMITTED"
    assert client.delete(
        f"/v1/me/applications/{application_id}/evidence/{evidence_id}",
        headers=self_headers(),
    ).status_code == 409


def test_upload_rejects_malformed_stale_and_unconfigured_evidence(
    client, repo, principals
):
    application_id = create_application(client)
    path = f"/v1/me/applications/{application_id}/evidence"

    malformed = client.post(
        path,
        headers=self_headers(),
        json=evidence_payload(content_base64="%%%"),
    )
    assert malformed.status_code == 422

    wrong_format = client.post(
        path,
        headers=self_headers(),
        json=evidence_payload(media_type="text/plain", filename="identity.txt"),
    )
    assert wrong_format.status_code == 422

    traversal = client.post(
        path,
        headers=self_headers(),
        json=evidence_payload(filename="../identity.png"),
    )
    assert traversal.status_code == 422

    unknown = client.post(
        path,
        headers=self_headers(),
        json=evidence_payload(evidence_requirement_id="another-application-evidence"),
    )
    assert unknown.status_code == 422

    application = run(repo.get_application(application_id))
    application.evidence_requirements[0]["freshness"] = {
        "max_age_seconds": 60,
    }
    run(repo.save_application(application))
    stale = client.post(
        f"/v1/me/applications/{application_id}/evidence",
        headers=self_headers(),
        json=evidence_payload(
            captured_at=(datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        ),
    )
    assert stale.status_code == 422
    assert stale.json()["detail"] == "Evidence is stale"


def test_delete_and_revoke_fail_closed(client, principals):
    application_id = create_application(client)
    evidence_id = upload_evidence(client, application_id).json()["id"]

    deleted = client.delete(
        f"/v1/me/applications/{application_id}/evidence/{evidence_id}",
        headers=self_headers(),
    )
    assert deleted.status_code == 200
    assert deleted.json() == {"deleted": True}
    assert client.get(
        f"/v1/me/applications/{application_id}/evidence/{evidence_id}/content",
        headers=self_headers(),
    ).status_code == 404
    assert client.post(
        f"/v1/me/applications/{application_id}/submit",
        headers=self_headers(),
    ).status_code == 422

    active_id = upload_evidence(client, application_id).json()["id"]
    assert client.post(
        f"/v1/me/applications/{application_id}/submit",
        headers=self_headers(),
    ).status_code == 200
    revoked = client.post(
        f"/v1/organizations/org-1/applicants/{application_id}/evidence/{active_id}/revoke",
        headers=reviewer_headers(),
        json={"reason": "Document authenticity could not be confirmed"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "REVOKED"
    assert client.get(
        revoked.json()["content_url"],
        headers=reviewer_headers(),
    ).status_code == 410

    lock = client.post(
        f"/v1/organizations/org-1/applicants/{application_id}/lock",
        headers=reviewer_headers(),
        json={},
    )
    assert lock.status_code == 200
    approval = client.post(
        f"/v1/organizations/org-1/applicants/{application_id}/approve",
        headers=reviewer_headers(),
        json={"notes": "reviewed"},
    )
    assert approval.status_code == 422
    assert approval.json()["detail"]["error"] == "EVIDENCE_VALIDATION_FAILED"


def test_vetting_check_rejects_foreign_evidence_reference(client, principals):
    app_one = create_application(client)
    evidence_one = upload_evidence(client, app_one).json()["id"]
    app_two = create_application(client, "org-2", "user-2")
    evidence_two = upload_evidence(client, app_two, "org-2", "user-2").json()["id"]

    for app_id, headers in ((app_one, self_headers()), (app_two, self_headers("org-2", "user-2"))):
        assert client.post(f"/v1/me/applications/{app_id}/submit", headers=headers).status_code == 200

    checks = client.get(
        f"/v1/organizations/org-1/applicants/{app_one}/checks",
        headers=reviewer_headers(),
    ).json()
    check_id = checks[0]["id"]
    assert client.post(
        f"/v1/organizations/org-1/applicants/{app_one}/lock",
        headers=reviewer_headers(),
        json={},
    ).status_code == 200

    foreign = client.post(
        f"/v1/organizations/org-1/applicants/{app_one}/checks/{check_id}/complete",
        headers=reviewer_headers(),
        json={"passed": True, "evidence_submission_ids": [evidence_two]},
    )
    assert foreign.status_code == 404

    own = client.post(
        f"/v1/organizations/org-1/applicants/{app_one}/checks/{check_id}/complete",
        headers=reviewer_headers(),
        json={"passed": True, "evidence_submission_ids": [evidence_one]},
    )
    assert own.status_code == 200, own.text
    assert own.json()["evidence_refs"] == [evidence_one]

    substituted = client.get(
        f"/v1/organizations/org-1/applicants/{app_one}/evidence/{evidence_two}",
        headers=reviewer_headers(),
    )
    assert substituted.status_code == 404
