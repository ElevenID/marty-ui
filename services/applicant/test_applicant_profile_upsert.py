from __future__ import annotations

import asyncio
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("APPLICANT_DATA_FILE", "/tmp/_test_applicant_profile_store.json")

try:
    from applicant.main import Applicant, InMemoryApplicantRepository, create_app, get_repo
except ModuleNotFoundError:
    from services.applicant.main import Applicant, InMemoryApplicantRepository, create_app, get_repo


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture()
def repo(tmp_path):
    store = str(tmp_path / "store.json")
    with patch.dict(os.environ, {"APPLICANT_DATA_FILE": store}):
        yield InMemoryApplicantRepository()


@pytest.fixture()
def client(repo):
    application = create_app()
    application.dependency_overrides[get_repo] = lambda: repo
    return TestClient(application, raise_server_exceptions=True)


def test_self_profile_upsert_returns_existing_and_links_login_subject(repo, client):
    applicant = Applicant(
        id="app-existing-1",
        organization_id="org-1",
        email="alice@example.com",
        given_name="Alice",
        family_name="Old",
    )
    _run(repo.save(applicant))

    response = client.patch(
        "/v1/me/applicant-profile",
        headers={
            "X-User-Id": "user-123",
            "X-User-Email": "alice@example.com",
            "X-Organization-ID": "org-1",
        },
        json={
            "email": "alice@example.com",
            "given_name": "Alice",
            "family_name": "Smith",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "app-existing-1"
    assert body["user_id"] == "user-123"
    assert body["family_name"] == "Smith"

    refreshed = _run(repo.get_by_id("app-existing-1"))
    assert refreshed is not None
    assert refreshed.oidc_subject == "user-123"
    assert refreshed.user_id == "user-123"
    assert refreshed.family_name == "Smith"


def test_self_profile_get_derives_organization_from_authenticated_context(repo, client):
    applicant = Applicant(
        id="app-existing-2",
        user_id="user-456",
        organization_id="org-2",
        email="bob@example.com",
    )
    _run(repo.save(applicant))

    response = client.get(
        "/v1/me/applicant-profile",
        headers={"X-User-Id": "user-456", "X-Organization-ID": "org-2"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == "app-existing-2"


def test_self_profile_patch_rejects_identity_fields(repo, client):
    response = client.patch(
        "/v1/me/applicant-profile",
        headers={
            "X-User-Id": "user-789",
            "X-User-Email": "eve@example.com",
            "X-Organization-ID": "org-3",
        },
        json={"organization_id": "org-other", "email": "eve@example.com"},
    )

    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "extra_forbidden"
