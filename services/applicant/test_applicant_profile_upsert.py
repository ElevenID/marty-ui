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
    return asyncio.get_event_loop().run_until_complete(coro)


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


def test_create_applicant_returns_existing_and_links_login_subject(repo, client):
    applicant = Applicant(
        id="app-existing-1",
        organization_id="org-1",
        email="alice@example.com",
        given_name="Alice",
        family_name="Old",
    )
    _run(repo.save(applicant))

    response = client.post(
        "/v1/applicants",
        json={
            "organization_id": "org-1",
            "user_id": "user-123",
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