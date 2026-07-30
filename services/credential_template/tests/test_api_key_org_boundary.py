from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from services.credential_template import main as credential_template


def _client() -> tuple[TestClient, AsyncMock]:
    app = FastAPI()
    app.include_router(credential_template.router)
    credential_template._repo = (
        credential_template.InMemoryCredentialTemplateRepository()
    )
    get_membership = AsyncMock()
    app.state.org_client = SimpleNamespace(get_membership=get_membership)
    return TestClient(app), get_membership


def _api_key_headers(organization_id: str) -> dict[str, str]:
    return {
        "X-User-Id": "api_key:key-b",
        "X-Organization-ID": organization_id,
        "X-Api-Key-Id": "key-b",
        "X-Required-Permission": "credential-template:view",
    }


def test_bound_api_key_lists_its_organization_without_human_membership() -> None:
    client, get_membership = _client()

    response = client.get(
        "/v1/credential-templates",
        params={"organization_id": "org-b"},
        headers=_api_key_headers("org-b"),
    )

    assert response.status_code == 200
    assert response.json() == []
    get_membership.assert_not_awaited()


def test_bound_api_key_cannot_select_another_organization() -> None:
    client, get_membership = _client()

    response = client.get(
        "/v1/credential-templates",
        params={"organization_id": "org-a"},
        headers=_api_key_headers("org-b"),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "API key does not have access to this organization"
    )
    get_membership.assert_not_awaited()
