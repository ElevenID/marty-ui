"""A lost Gateway response must never turn a beta setup retry into a second write."""

from __future__ import annotations

import pytest

from scripts.passport_beta_reference_intents import (
    DurableReferenceRequests, ReferenceIntentError,
)


ORG = "00000000-0000-0000-0000-000000000019"
ID = "d0000000-0000-4000-8000-000000000001"
BODY = {"organization_id": ORG, "name": "Beta passport credential"}


def adapter(tmp_path, request):
    return DurableReferenceRequests(
        request, tmp_path.resolve(), source_commit="a" * 40,
        gateway_container_id="b" * 64, organization_id=ORG,
    )


def test_lost_create_response_reconciles_the_exact_row_without_reposting(tmp_path):
    rows = []
    posts = []

    def request(method, path, body, headers):
        if method == "GET":
            return 200, list(rows)
        posts.append((path, body))
        rows.append({**body, "id": ID, "status": "DRAFT"})
        raise OSError("lost response")

    gateway = adapter(tmp_path, request)
    with pytest.raises(OSError):
        gateway("POST", "/v1/credential-templates", BODY, {})
    status, result = gateway("POST", "/v1/credential-templates", BODY, {})
    assert status == 200 and result["id"] == ID
    assert len(posts) == 1


def test_unresolved_create_attempt_fails_closed_without_reposting(tmp_path):
    posts = []

    def request(method, path, body, headers):
        if method == "GET":
            return 200, []
        posts.append(path)
        raise OSError("lost response")

    gateway = adapter(tmp_path, request)
    with pytest.raises(OSError):
        gateway("POST", "/v1/credential-templates", BODY, {})
    with pytest.raises(ReferenceIntentError, match="no unique row"):
        gateway("POST", "/v1/credential-templates", BODY, {})
    assert posts == ["/v1/credential-templates"]


def test_reconciliation_finds_a_named_row_on_the_second_bounded_page(tmp_path):
    rows = [{"id": f"other-{index}", "organization_id": ORG,
             "name": f"Other {index}"} for index in range(10)]
    posts = []

    def request(method, path, body, headers):
        if method == "GET":
            offset = int(path.split("offset=")[1])
            return 200, rows[offset:offset + 10]
        posts.append(path)
        rows.append({**body, "id": ID, "status": "DRAFT"})
        raise OSError("lost response")

    gateway = adapter(tmp_path, request)
    with pytest.raises(OSError):
        gateway("POST", "/v1/credential-templates", BODY, {})
    _, result = gateway("POST", "/v1/credential-templates", BODY, {})
    assert result["id"] == ID
    assert posts == ["/v1/credential-templates"]


def test_fresh_create_cannot_skip_the_activation_route(tmp_path):
    rows = []

    def request(method, path, body, headers):
        if method == "GET":
            return 200, list(rows)
        rows.append({**body, "id": ID, "status": "ACTIVE"})
        return 200, rows[0]

    gateway = adapter(tmp_path, request)
    with pytest.raises(ReferenceIntentError, match="not draft"):
        gateway("POST", "/v1/credential-templates", BODY, {})
    with pytest.raises(ReferenceIntentError, match="no activation intent"):
        gateway("POST", "/v1/credential-templates", BODY, {})


def test_activation_lost_response_resumes_only_after_active_readback(tmp_path):
    status = "DRAFT"
    posts = []

    def request(method, path, body, headers):
        nonlocal status
        if method == "GET":
            return 200, {**BODY, "id": ID, "status": status}
        posts.append(path)
        status = "ACTIVE"
        raise OSError("lost response")

    gateway = adapter(tmp_path, request)
    path = f"/v1/credential-templates/{ID}/activate"
    with pytest.raises(OSError):
        gateway("POST", path, None, {})
    response_code, result = gateway("POST", path, None, {})
    assert response_code == 200 and result["status"] == "ACTIVE"
    assert posts == [path]


def test_intent_rejects_changed_body_and_preexisting_unowned_name(tmp_path):
    rows = [{**BODY, "id": ID, "status": "DRAFT"}]

    def request(method, path, body, headers):
        assert method == "GET"
        return 200, rows

    gateway = adapter(tmp_path, request)
    with pytest.raises(ReferenceIntentError, match="Unowned"):
        gateway("POST", "/v1/credential-templates", BODY, {})
    rows.clear()

    def lost_request(method, path, body, headers):
        if method == "GET":
            return 200, []
        raise OSError("lost response")

    gateway = adapter(tmp_path, lost_request)
    with pytest.raises(OSError):
        gateway("POST", "/v1/credential-templates", BODY, {})
    with pytest.raises(ReferenceIntentError, match="intent changed"):
        gateway("POST", "/v1/credential-templates", {**BODY, "name": "Other"}, {})
