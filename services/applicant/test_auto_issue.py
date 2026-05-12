"""
Tests for the auto-approve / auto-issue workflow.

Covers:
  - submit with auto_approve=True → immediately reaches APPROVED (no vetting checks created)
  - submit without auto_approve → reaches SUBMITTED with vetting checks
  - POST /applications/{id}/auto-issue → atomically reaches ISSUED (issuance mocked)
  - POST /applications/{id}/auto-issue rejected when auto_approve not set
"""

from __future__ import annotations

import asyncio
import os
import uuid
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Ensure the store won't read/write production data during tests.
os.environ.setdefault("APPLICANT_DATA_FILE", "/tmp/_test_applicant_store.json")

# Use a relative import so the test runs both from the services/ root and
# from the repo root: `pytest services/applicant/test_auto_issue.py`.
try:
    from applicant.main import (  # when cwd == services/
        ApplicationStatus, ApplicantStatus, Applicant,
        InMemoryApplicantRepository, create_app, get_repo,
    )
    import applicant.main as _svc
except ModuleNotFoundError:
    from services.applicant.main import (  # when cwd == repo root
        ApplicationStatus, ApplicantStatus, Applicant,
        InMemoryApplicantRepository, create_app, get_repo,
    )
    import services.applicant.main as _svc  # type: ignore[no-redef]



def _run(coro):
    """Run a coroutine synchronously (helper for fixtures)."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def repo(tmp_path):
    """In-memory repo backed by a per-test temp file."""
    store = str(tmp_path / "store.json")
    with patch.dict(os.environ, {"APPLICANT_DATA_FILE": store}):
        yield InMemoryApplicantRepository()


@pytest.fixture()
def client(repo):
    """TestClient with the repo dependency override applied."""
    application = create_app()
    application.dependency_overrides[get_repo] = lambda: repo
    return TestClient(application, raise_server_exceptions=True)


@pytest.fixture()
def seeded(repo, client):
    """Seed a minimal applicant; return (repo, client, applicant)."""
    applicant = Applicant(
        id=str(uuid.uuid4()),
        organization_id="org-1",
        email="test@example.com",
        given_name="Test",
        family_name="User",
        status=ApplicantStatus.APPROVED,
    )
    _run(repo.save(applicant))
    return repo, client, applicant


def _make_app_payload(applicant_id: str, *, auto_approve: bool = False) -> dict:
    meta: dict = {
        "credential_type": "MemberCredential",
        "credential_display_name": "Member Login Credential",
        "email": "test@example.com",
        "given_name": "Test",
        "family_name": "User",
        "member_id": "user-123",
        "organization_id": "org-1",
        "role": "applicant",
    }
    if auto_approve:
        meta["auto_approve"] = True
    return {
        "applicant_id": applicant_id,
        "credential_configuration_id": "50000000-0000-0000-0000-000000000010",
        "issuing_authority": "Marty Trust Services",
        "requested_validity_years": 1,
        "metadata": meta,
    }


def _fake_issuance_post(captured: dict | None = None):
    """Return an async function that stubs httpx.AsyncClient.post."""
    offer_id = f"local-{uuid.uuid4().hex[:12]}"

    async def _post(self_, url, *, json=None, **_kw):
        if captured is not None:
            captured.update((json or {}).get("claims", {}))
        resp = MagicMock()
        resp.raise_for_status = lambda: None
        resp.json.return_value = {
            "id": offer_id,
            "credential_offer_uri": f"openid-credential-offer://?id={offer_id}",
            "credential_offer_uris": {"marty": f"marty://offer/{offer_id}"},
            "expires_at": "2026-03-08T00:00:00Z",
        }
        return resp

    return patch.object(_svc.httpx.AsyncClient, "post", new=_post)


# ---------------------------------------------------------------------------
# Tests: submit with auto_approve=True
# ---------------------------------------------------------------------------

class TestSubmitAutoApprove:
    def test_reaches_approved_status(self, seeded):
        repo, client, applicant = seeded
        app_id = client.post("/v1/applicants/applications",
                             json=_make_app_payload(applicant.id, auto_approve=True)).json()["id"]

        resp = client.post(f"/v1/applicants/applications/{app_id}/submit")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == ApplicationStatus.APPROVED.value
        assert body["reviewed_at"] is not None

    def test_creates_no_vetting_checks(self, seeded):
        repo, client, applicant = seeded
        app_id = client.post("/v1/applicants/applications",
                             json=_make_app_payload(applicant.id, auto_approve=True)).json()["id"]
        client.post(f"/v1/applicants/applications/{app_id}/submit")

        checks = _run(repo.list_checks_for_application(app_id))
        assert checks == [], f"Expected no checks, found {len(checks)}"

    def test_second_submit_rejected(self, seeded):
        """Submitting an already-approved application is a 400."""
        repo, client, applicant = seeded
        app_id = client.post("/v1/applicants/applications",
                             json=_make_app_payload(applicant.id, auto_approve=True)).json()["id"]
        client.post(f"/v1/applicants/applications/{app_id}/submit")
        resp = client.post(f"/v1/applicants/applications/{app_id}/submit")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Tests: submit without auto_approve
# ---------------------------------------------------------------------------

class TestSubmitNormal:
    def test_reaches_submitted_status(self, seeded):
        repo, client, applicant = seeded
        app_id = client.post("/v1/applicants/applications",
                             json=_make_app_payload(applicant.id)).json()["id"]
        resp = client.post(f"/v1/applicants/applications/{app_id}/submit")
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == ApplicationStatus.SUBMITTED.value

    def test_creates_vetting_checks(self, seeded):
        repo, client, applicant = seeded
        app_id = client.post("/v1/applicants/applications",
                             json=_make_app_payload(applicant.id)).json()["id"]
        client.post(f"/v1/applicants/applications/{app_id}/submit")
        checks = _run(repo.list_checks_for_application(app_id))
        assert len(checks) >= 1, "Expected at least one vetting check"


# ---------------------------------------------------------------------------
# Tests: POST …/auto-issue
# ---------------------------------------------------------------------------

class TestAutoIssueEndpoint:
    def test_full_flow_reaches_issued(self, seeded):
        repo, client, applicant = seeded
        app_id = client.post("/v1/applicants/applications",
                             json=_make_app_payload(applicant.id, auto_approve=True)).json()["id"]
        with _fake_issuance_post():
            resp = client.post(f"/v1/applicants/applications/{app_id}/auto-issue")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == ApplicationStatus.OFFERED.value
        assert body["credential_offer_uri"] is not None

    def test_works_from_draft_without_prior_submit(self, seeded):
        """auto-issue should transition DRAFT→SUBMITTED→APPROVED→ISSUED atomically."""
        repo, client, applicant = seeded
        app_id = client.post("/v1/applicants/applications",
                             json=_make_app_payload(applicant.id, auto_approve=True)).json()["id"]
        with _fake_issuance_post():
            resp = client.post(f"/v1/applicants/applications/{app_id}/auto-issue")
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == ApplicationStatus.OFFERED.value

    def test_rejected_without_flag(self, seeded):
        repo, client, applicant = seeded
        app_id = client.post("/v1/applicants/applications",
                             json=_make_app_payload(applicant.id)).json()["id"]
        resp = client.post(f"/v1/applicants/applications/{app_id}/auto-issue")
        assert resp.status_code == 400
        assert "auto_approve" in resp.json()["detail"]

    def test_404_for_unknown_application(self, client):
        resp = client.post(f"/v1/applicants/applications/{uuid.uuid4()}/auto-issue")
        assert resp.status_code == 404

    def test_auto_approve_stripped_from_claims(self, seeded):
        """auto_approve must NOT appear in claims sent to the issuance service."""
        repo, client, applicant = seeded
        app_id = client.post("/v1/applicants/applications",
                             json=_make_app_payload(applicant.id, auto_approve=True)).json()["id"]
        captured: dict = {}
        with _fake_issuance_post(captured=captured):
            resp = client.post(f"/v1/applicants/applications/{app_id}/auto-issue")
        assert resp.status_code == 200, resp.text
        assert "auto_approve" not in captured, f"auto_approve leaked: {captured}"

    def test_internal_fields_stripped_from_claims(self, seeded):
        """Internal metadata must never appear in VC claims."""
        repo, client, applicant = seeded
        app_id = client.post("/v1/applicants/applications",
                             json=_make_app_payload(applicant.id, auto_approve=True)).json()["id"]
        captured: dict = {}
        with _fake_issuance_post(captured=captured):
            client.post(f"/v1/applicants/applications/{app_id}/auto-issue")
        internal = {"credential_display_name", "credential_type", "auto_approve",
                    "review_notes", "rejection_reason", "info_requests"}
        leaked = internal & captured.keys()
        assert not leaked, f"Internal fields leaked into VC claims: {leaked}"
