from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from marty_common.org_authorization import OrganizationMembership

from services.revocation_profile import main as revocation_profile


FIXTURE = Path(__file__).parents[3] / "tests" / "fixtures" / "revocation_profile_http_vectors.json"


def _membership() -> OrganizationMembership:
    return OrganizationMembership(
        user_id="user-1",
        organization_id="org-1",
        status="active",
        permissions={
            "revocation-profile:view",
            "revocation-profile:create",
            "revocation-profile:delete",
            "revocation-profile:activate",
        },
    )


def _client(authorization: str) -> TestClient:
    repo = revocation_profile.InMemoryRevocationProfileRepository()
    app = FastAPI()
    app.include_router(revocation_profile.router)
    revocation_profile._repo = repo
    get_membership = AsyncMock(return_value=_membership() if authorization == "allow" else None)
    org_client = SimpleNamespace(get_membership=get_membership)
    app.state.org_client = org_client
    revocation_profile.app.state.org_client = org_client
    return TestClient(app)


def _normalize_dynamic_fields(body: object) -> object:
    if not isinstance(body, dict):
        return body
    profile_id = body.get("id")
    if not isinstance(profile_id, str):
        return body

    def replace(value: object) -> object:
        if isinstance(value, str):
            return value.replace(profile_id, "{profile_id}")
        if isinstance(value, list):
            return [replace(item) for item in value]
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        return value

    return replace(body)


def _assert_subset(actual: object, expected: object) -> None:
    if isinstance(expected, dict):
        assert isinstance(actual, dict)
        for key, value in expected.items():
            assert key in actual
            _assert_subset(actual[key], value)
    else:
        assert actual == expected


def test_python_adapter_matches_shared_revocation_http_vectors() -> None:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert fixture["version"] == 1

    for vector in fixture["cases"]:
        client = _client(vector["authorization"])
        response = client.request(
            vector["method"],
            vector["path"],
            headers=vector.get("headers"),
            json=vector.get("body"),
        )
        assert response.status_code == vector["expected_status"], vector["id"]
        if "expected_body_subset" not in vector:
            continue
        body = _normalize_dynamic_fields(response.json())
        _assert_subset(body, vector["expected_body_subset"])
        for field in vector.get("expected_absent_fields", []):
            assert field not in body, f"{vector['id']}: unexpected field {field}"
