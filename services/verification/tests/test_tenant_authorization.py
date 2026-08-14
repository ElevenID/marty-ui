"""Marty-owned adversarial tests for standalone Verification tenancy."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from services.verification import main as verification


class _Membership:
    def __init__(self, *permissions: str, status: str = "active") -> None:
        self.permissions = set(permissions)
        self.status = status

    def is_active(self) -> bool:
        return self.status == "active"

    def has_permission(self, resource: str, action: str | None = None) -> bool:
        key = resource if action is None else f"{resource}:{action}"
        return key in self.permissions


def _policy(organization_id: str = "org-a", status: str = "active") -> SimpleNamespace:
    return SimpleNamespace(
        id="policy-a",
        organization_id=organization_id,
        status=status,
    )


def _build_client(
    membership: AsyncMock,
) -> tuple[TestClient, verification.SessionStore]:
    store = verification.SessionStore()
    app = FastAPI()
    app.state.enforce_verification_management_authorization = True
    app.state.org_client = SimpleNamespace(get_membership=membership)
    app.include_router(verification.router)
    app.include_router(verification.zkp_router)
    verification._store = store
    return TestClient(app), store


def test_production_app_factory_enables_management_authorization() -> None:
    assert verification.app.state.enforce_verification_management_authorization is True


def test_management_start_requires_an_authenticated_principal(monkeypatch) -> None:
    membership = AsyncMock(return_value=_Membership("verification:execute"))
    client, store = _build_client(membership)
    policy_lookup = AsyncMock(return_value=_policy())
    monkeypatch.setattr(
        verification, "_get_presentation_policy_reference", policy_lookup
    )
    monkeypatch.setattr(
        verification,
        "_resolve_policy_template_references",
        AsyncMock(return_value=[]),
    )

    response = client.post(
        "/v1/verify",
        json={"organization_id": "org-a", "presentation_policy_id": "policy-a"},
    )

    assert response.status_code == 401
    assert store._fallback == {}
    membership.assert_not_awaited()
    policy_lookup.assert_not_awaited()


def test_user_start_is_membership_and_policy_owner_bound(monkeypatch) -> None:
    membership = AsyncMock(return_value=_Membership("verification:execute"))
    client, store = _build_client(membership)
    policy_lookup = AsyncMock(return_value=_policy())
    monkeypatch.setattr(
        verification, "_get_presentation_policy_reference", policy_lookup
    )
    template_lookup = AsyncMock(return_value=[])
    monkeypatch.setattr(
        verification,
        "_resolve_policy_template_references",
        template_lookup,
    )

    response = client.post(
        "/v1/verify",
        headers={"x-user-id": "user-a", "x-organization-id": "org-a"},
        json={"organization_id": "org-a", "presentation_policy_id": "policy-a"},
    )

    assert response.status_code == 200
    [stored] = store._fallback.values()
    assert stored.organization_id == "org-a"
    assert stored.presentation_policy_id == "policy-a"
    membership.assert_awaited_once_with("user-a", "org-a")
    policy_lookup.assert_awaited_once_with("policy-a")
    template_lookup.assert_awaited_once_with(
        "policy-a",
        policy_lookup.return_value,
        organization_id="org-a",
    )


def test_start_rejects_gateway_and_body_organization_mismatch() -> None:
    membership = AsyncMock(return_value=_Membership("verification:execute"))
    client, store = _build_client(membership)

    response = client.post(
        "/v1/verify",
        headers={"x-user-id": "user-a", "x-organization-id": "org-b"},
        json={"organization_id": "org-a", "presentation_policy_id": "policy-a"},
    )

    assert response.status_code == 403
    assert store._fallback == {}
    membership.assert_not_awaited()


def test_start_hides_a_foreign_policy_and_never_persists(monkeypatch) -> None:
    membership = AsyncMock(return_value=_Membership("verification:execute"))
    client, store = _build_client(membership)
    monkeypatch.setattr(
        verification,
        "_get_presentation_policy_reference",
        AsyncMock(return_value=_policy("org-b")),
    )

    response = client.post(
        "/v1/verify",
        headers={"x-user-id": "user-a"},
        json={"organization_id": "org-a", "presentation_policy_id": "policy-a"},
    )

    assert response.status_code == 404
    assert store._fallback == {}


def test_start_rejects_an_inactive_policy_before_persistence(monkeypatch) -> None:
    membership = AsyncMock(return_value=_Membership("verification:execute"))
    client, store = _build_client(membership)
    monkeypatch.setattr(
        verification,
        "_get_presentation_policy_reference",
        AsyncMock(return_value=_policy(status="retired")),
    )
    template_lookup = AsyncMock()
    monkeypatch.setattr(
        verification,
        "_resolve_policy_template_references",
        template_lookup,
    )

    response = client.post(
        "/v1/verify",
        headers={"x-user-id": "user-a"},
        json={"organization_id": "org-a", "presentation_policy_id": "policy-a"},
    )

    assert response.status_code == 409
    assert store._fallback == {}
    template_lookup.assert_not_awaited()


def test_standalone_start_rejects_inert_profile_overrides() -> None:
    membership = AsyncMock(return_value=_Membership("verification:execute"))
    client, store = _build_client(membership)

    response = client.post(
        "/v1/verify",
        headers={"x-user-id": "user-a"},
        json={
            "organization_id": "org-a",
            "presentation_policy_id": "policy-a",
            "trust_profile_id": "trust-from-another-tenant",
        },
    )

    assert response.status_code == 400
    assert "Flow verification endpoint" in response.json()["detail"]
    assert store._fallback == {}


def test_complete_api_key_context_is_exactly_tenant_and_scope_bound(
    monkeypatch,
) -> None:
    membership = AsyncMock()
    client, store = _build_client(membership)
    monkeypatch.setattr(
        verification,
        "_get_presentation_policy_reference",
        AsyncMock(return_value=_policy()),
    )
    monkeypatch.setattr(
        verification,
        "_resolve_policy_template_references",
        AsyncMock(return_value=[]),
    )
    headers = {
        "x-user-id": "api_key:key-a",
        "x-api-key-id": "key-a",
        "x-api-key-scopes": "flows:execute",
        "x-organization-id": "org-a",
        "x-required-permission": "verification:execute",
    }

    accepted = client.post(
        "/v1/verify",
        headers=headers,
        json={"organization_id": "org-a", "presentation_policy_id": "policy-a"},
    )
    denied = client.post(
        "/v1/verify",
        headers={**headers, "x-api-key-scopes": "credentials:issue"},
        json={"organization_id": "org-a", "presentation_policy_id": "policy-a"},
    )

    assert accepted.status_code == 200
    assert denied.status_code == 403
    assert len(store._fallback) == 1
    membership.assert_not_awaited()


@pytest.mark.parametrize(
    ("header_overrides", "removed_header"),
    [
        ({"x-user-id": "api_key:key-b"}, None),
        ({"x-organization-id": "org-b"}, None),
        ({"x-required-permission": "credentials:read"}, None),
        ({}, "x-api-key-id"),
        ({}, "x-api-key-scopes"),
    ],
)
def test_partial_or_inconsistent_api_key_context_fails_closed(
    monkeypatch,
    header_overrides: dict[str, str],
    removed_header: str | None,
) -> None:
    membership = AsyncMock()
    client, store = _build_client(membership)
    policy_lookup = AsyncMock(return_value=_policy())
    monkeypatch.setattr(
        verification,
        "_get_presentation_policy_reference",
        policy_lookup,
    )
    headers = {
        "x-user-id": "api_key:key-a",
        "x-api-key-id": "key-a",
        "x-api-key-scopes": "flows:execute",
        "x-organization-id": "org-a",
        "x-required-permission": "verification:execute",
        **header_overrides,
    }
    if removed_header:
        headers.pop(removed_header)

    response = client.post(
        "/v1/verify",
        headers=headers,
        json={"organization_id": "org-a", "presentation_policy_id": "policy-a"},
    )

    assert response.status_code == 403
    assert store._fallback == {}
    membership.assert_not_awaited()
    policy_lookup.assert_not_awaited()


def test_cross_tenant_session_reads_and_lists_are_denied() -> None:
    async def membership_for_user(_user_id: str, organization_id: str):
        if organization_id == "org-a":
            return _Membership("verification:execute")
        return None

    membership = AsyncMock(side_effect=membership_for_user)
    client, store = _build_client(membership)
    foreign = verification.VerificationSession(
        organization_id="org-b",
        presentation_policy_id="policy-b",
    )
    store.save(foreign)

    session_response = client.get(
        f"/v1/verify/{foreign.session_id}",
        headers={"x-user-id": "user-a"},
    )
    list_response = client.get(
        "/v1/verify/sessions?organization_id=org-b",
        headers={"x-user-id": "user-a"},
    )
    inspection_response = client.get(
        f"/v1/verify/{foreign.session_id}/inspection",
        headers={"x-user-id": "user-a"},
    )

    assert session_response.status_code == 403
    assert list_response.status_code == 403
    assert inspection_response.status_code == 403


def test_wallet_request_path_remains_a_public_capability(monkeypatch) -> None:
    membership = AsyncMock()
    client, store = _build_client(membership)
    session = verification.VerificationSession(
        organization_id="org-a",
        presentation_policy_id="policy-a",
    )
    store.save(session)
    monkeypatch.setattr(
        verification,
        "_build_presentation_request_artifacts",
        AsyncMock(return_value={"dcql_query": {"credentials": []}}),
    )

    response = client.get(f"/v1/verify/{session.session_id}/request")

    assert response.status_code == 200
    assert response.json()["nonce"] == session.nonce
    membership.assert_not_awaited()


def test_stateless_evaluation_authorizes_the_policys_real_tenant(monkeypatch) -> None:
    membership = AsyncMock(return_value=None)
    client, _store = _build_client(membership)
    monkeypatch.setattr(
        verification,
        "_get_presentation_policy_reference",
        AsyncMock(return_value=_policy("org-b")),
    )
    evaluate = AsyncMock(return_value={"result": "passed"})
    monkeypatch.setattr(verification, "_evaluate_via_grpc", evaluate)

    response = client.post(
        "/v1/verify/evaluate",
        headers={"x-user-id": "user-a"},
        json={"presentation_policy_id": "policy-a", "vp_token": "vp"},
    )

    assert response.status_code == 403
    membership.assert_awaited_once_with("user-a", "org-b")
    evaluate.assert_not_awaited()


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        (
            "/v1/verify/evaluate",
            {"presentation_policy_id": "policy-a", "vp_token": "vp"},
        ),
        (
            "/v1/verify/zkp",
            {"presentation_policy_id": "policy-a", "proof": "proof"},
        ),
    ],
)
def test_stateless_evaluation_rejects_legacy_foreign_template_references(
    monkeypatch,
    path: str,
    payload: dict[str, str],
) -> None:
    membership = AsyncMock(return_value=_Membership("verification:execute"))
    client, _store = _build_client(membership)
    policy = _policy()
    monkeypatch.setattr(
        verification,
        "_get_presentation_policy_reference",
        AsyncMock(return_value=policy),
    )
    template_lookup = AsyncMock(
        side_effect=HTTPException(
            status_code=404,
            detail="Credential template not found",
        )
    )
    monkeypatch.setattr(
        verification,
        "_resolve_policy_template_references",
        template_lookup,
    )
    evaluate = AsyncMock(return_value={"result": "passed"})
    monkeypatch.setattr(verification, "_evaluate_via_grpc", evaluate)

    response = client.post(path, headers={"x-user-id": "user-a"}, json=payload)

    assert response.status_code == 404
    membership.assert_awaited_once_with("user-a", "org-a")
    template_lookup.assert_awaited_once_with(
        "policy-a",
        policy,
        organization_id="org-a",
    )
    evaluate.assert_not_awaited()


@pytest.mark.asyncio
async def test_nested_foreign_template_reference_is_rejected(monkeypatch) -> None:
    from marty_proto.v1 import credential_template_service_pb2_grpc

    class _ChannelContext:
        async def __aenter__(self):
            return object()

        async def __aexit__(self, *_args):
            return None

    stub = SimpleNamespace(
        GetTemplate=AsyncMock(
            return_value=SimpleNamespace(
                id="template-b",
                organization_id="org-b",
                status="active",
            )
        )
    )
    monkeypatch.setattr(
        verification,
        "create_grpc_channel",
        lambda *_args, **_kwargs: _ChannelContext(),
    )
    monkeypatch.setattr(
        credential_template_service_pb2_grpc,
        "CredentialTemplateServiceStub",
        lambda _channel: stub,
    )
    policy = SimpleNamespace(
        credential_requirements_json=(
            '[{"credential_template_id":"template-b","required":true}]'
        )
    )

    with pytest.raises(HTTPException) as exc_info:
        await verification._resolve_policy_template_references(
            "policy-a",
            policy,
            organization_id="org-a",
        )

    assert exc_info.value.status_code == 404


@pytest.mark.asyncio
async def test_inactive_nested_template_reference_is_rejected(monkeypatch) -> None:
    from marty_proto.v1 import credential_template_service_pb2_grpc

    class _ChannelContext:
        async def __aenter__(self):
            return object()

        async def __aexit__(self, *_args):
            return None

    stub = SimpleNamespace(
        GetTemplate=AsyncMock(
            return_value=SimpleNamespace(
                id="template-a",
                organization_id="org-a",
                status="retired",
            )
        )
    )
    monkeypatch.setattr(
        verification,
        "create_grpc_channel",
        lambda *_args, **_kwargs: _ChannelContext(),
    )
    monkeypatch.setattr(
        credential_template_service_pb2_grpc,
        "CredentialTemplateServiceStub",
        lambda _channel: stub,
    )
    policy = SimpleNamespace(
        credential_requirements_json=(
            '[{"credential_template_id":"template-a","required":true}]'
        )
    )

    with pytest.raises(HTTPException) as exc_info:
        await verification._resolve_policy_template_references(
            "policy-a",
            policy,
            organization_id="org-a",
        )

    assert exc_info.value.status_code == 409


@pytest.mark.asyncio
async def test_submission_revalidates_nested_references_before_claim(
    monkeypatch,
) -> None:
    store = verification.SessionStore()
    session = verification.VerificationSession(
        organization_id="org-a",
        presentation_policy_id="policy-a",
    )
    store.save(session)
    policy = _policy()
    policy_lookup = AsyncMock(return_value=policy)
    template_lookup = AsyncMock(
        side_effect=HTTPException(
            status_code=404,
            detail="Credential template not found",
        )
    )
    claim_submission = AsyncMock()
    monkeypatch.setattr(
        verification,
        "_require_session_policy_reference",
        policy_lookup,
    )
    monkeypatch.setattr(
        verification,
        "_resolve_policy_template_references",
        template_lookup,
    )
    monkeypatch.setattr(store, "claim_submission", claim_submission)

    with pytest.raises(HTTPException) as exc_info:
        await verification.process_session_submission(
            store,
            session.session_id,
            "vp-token",
            validate_references=True,
        )

    assert exc_info.value.status_code == 404
    policy_lookup.assert_awaited_once()
    [validated_session] = policy_lookup.await_args.args
    assert validated_session.session_id == session.session_id
    assert validated_session.organization_id == "org-a"
    template_lookup.assert_awaited_once_with(
        "policy-a",
        policy,
        organization_id="org-a",
    )
    claim_submission.assert_not_awaited()
