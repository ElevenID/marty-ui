"""Flow gateway dependency-routing tests."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import Response

from gateway.routes import flows
from gateway.models import (
    FlowDefinitionUpdate,
    FlowInstanceCreate,
    FlowInstanceResponse,
    StartVerificationFlowRequest,
)


def test_gateway_preserves_did_haip_and_post_request_uri_options() -> None:
    request = StartVerificationFlowRequest(
        presentation_policy_id="policy-1",
        organization_id="org-1",
        issuer_did="did:web:verifier.example",
        oid4vp_profile="haip",
        request_uri_method="post",
    )
    assert request.model_dump()["issuer_did"] == "did:web:verifier.example"
    assert request.model_dump()["oid4vp_profile"] == "haip"
    assert request.model_dump()["request_uri_method"] == "post"


def test_gateway_preserves_native_url_query_transport() -> None:
    request = StartVerificationFlowRequest(
        presentation_policy_id="policy-1",
        organization_id="org-1",
        issuer_did="did:web:verifier.example",
        request_transport="url_query",
    )
    assert request.model_dump()["request_transport"] == "url_query"

    with pytest.raises(ValueError, match="url_query transport"):
        StartVerificationFlowRequest(
            presentation_policy_id="policy-1",
            organization_id="org-1",
            issuer_did="did:web:verifier.example",
            request_transport="url_query",
            request_uri_method="post",
        )

    with pytest.raises(ValueError, match="only for OID4VP"):
        StartVerificationFlowRequest(
            presentation_policy_id="policy-1",
            organization_id="org-1",
            issuer_did="did:web:verifier.example",
            response_type="id_token",
            request_transport="url_query",
        )

    with pytest.raises(ValueError, match="cannot be used for HAIP"):
        StartVerificationFlowRequest(
            presentation_policy_id="policy-1",
            organization_id="org-1",
            issuer_did="did:web:verifier.example",
            oid4vp_profile="haip",
            request_transport="url_query",
        )


def test_gateway_preserves_signed_request_object_transport() -> None:
    request = StartVerificationFlowRequest(
        presentation_policy_id="policy-1",
        organization_id="org-1",
        issuer_did="did:web:verifier.example",
        request_transport="request_object",
    )
    assert request.model_dump()["request_transport"] == "request_object"

    with pytest.raises(ValueError, match="request_object transport"):
        StartVerificationFlowRequest(
            presentation_policy_id="policy-1",
            organization_id="org-1",
            issuer_did="did:web:verifier.example",
            request_transport="request_object",
            request_uri_method="post",
        )


@pytest.mark.parametrize(
    "direct_kms_field",
    ("signing_service_id", "signing_key_reference", "issuer_key_id"),
)
def test_verification_flow_rejects_direct_kms_routing(direct_kms_field: str) -> None:
    with pytest.raises(ValueError, match=direct_kms_field):
        StartVerificationFlowRequest.model_validate(
            {
                "presentation_policy_id": "policy-1",
                "organization_id": "org-1",
                "issuer_did": "did:web:verifier.example",
                direct_kms_field: "must-not-cross-runtime-boundary",
            }
        )


def test_verification_flow_requires_oid4vp_policy_and_bounded_expiry() -> None:
    with pytest.raises(ValueError, match="presentation_policy_id"):
        StartVerificationFlowRequest(
            organization_id="org-1",
            issuer_did="did:web:verifier.example",
        )

    for expiry_minutes in (0, 1441):
        with pytest.raises(ValueError, match="expiry_minutes"):
            StartVerificationFlowRequest(
                presentation_policy_id="policy-1",
                organization_id="org-1",
                issuer_did="did:web:verifier.example",
                expiry_minutes=expiry_minutes,
            )


def test_verification_flow_rejects_unknown_response_type() -> None:
    with pytest.raises(ValueError, match="response_type"):
        StartVerificationFlowRequest.model_validate(
            {
                "presentation_policy_id": "policy-1",
                "organization_id": "org-1",
                "issuer_did": "did:web:verifier.example",
                "response_type": "vp_token id_token",
            }
        )


def test_flow_start_rejects_nested_private_service_state() -> None:
    with pytest.raises(ValueError, match="pre_auth_code"):
        FlowInstanceCreate(
            organization_id="org-1",
            flow_definition_id="flow-1",
            initial_context={"wallet": {"pre_auth_code": "must-not-enter"}},
        )


def test_flow_instance_response_rejects_nested_private_service_state() -> None:
    response = Response(
        content=flows.json.dumps(
            {
                "id": "instance-1",
                "flow_id": "flow-1",
                "flow_type": "oid4vci_pre_authorized",
                "organization_id": "org-1",
                "status": "IN_PROGRESS",
                "context_data": {"wallet": {"pre_auth_code": "must-not-leak"}},
                "step_results": {},
                "metadata": {},
                "state_history": [],
                "created_at": "2026-07-31T00:00:00Z",
                "updated_at": "2026-07-31T00:00:00Z",
            }
        ),
        media_type="application/json",
    )

    with pytest.raises(flows.HTTPException) as exc_info:
        flows._sanitize_public_response(response, FlowInstanceResponse)

    assert exc_info.value.status_code == 502


def test_flow_patch_serializes_only_validated_public_fields() -> None:
    body = FlowDefinitionUpdate(
        organization_id="org-1",
        name="Updated flow",
    )

    assert flows.json.loads(flows._validated_flow_body(body, patch=True)) == {
        "name": "Updated flow",
        "organization_id": "org-1",
    }


def test_flow_definition_update_is_patch_only() -> None:
    route = next(
        route
        for route in flows.flow_router.routes
        if getattr(route, "path", "") == "/v1/flows/definitions/{flow_id}"
        and "PATCH" in getattr(route, "methods", set())
    )
    assert route.methods == {"PATCH"}


@pytest.mark.asyncio
async def test_public_gateway_rejects_application_approval_workload_events() -> None:
    route = next(
        route
        for route in flows.flow_router.routes
        if getattr(route, "path", "")
        == "/v1/flows/webhooks/application-approved"
    )

    assert route.methods == {"POST"}
    assert route.include_in_schema is False

    with pytest.raises(flows.HTTPException) as exc_info:
        await route.endpoint()

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == {
        "error": "application_event_auth_required",
        "message": "Application approval events require internal workload authentication.",
    }


@pytest.mark.asyncio
async def test_flow_start_rejects_selected_organization_mismatch_before_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy = AsyncMock()
    monkeypatch.setattr(flows, "proxy_request", proxy)
    request = SimpleNamespace(state=SimpleNamespace(organization_id="org-2"))
    body = FlowInstanceCreate(
        organization_id="org-1",
        flow_definition_id="flow-1",
    )

    with pytest.raises(flows.HTTPException) as exc_info:
        await flows.start_flow_instance(body, request)

    assert exc_info.value.status_code == 403
    proxy.assert_not_awaited()


@pytest.mark.asyncio
async def test_flow_definition_resolves_application_template_from_issuance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resource_exists = AsyncMock(return_value=True)
    monkeypatch.setattr(flows, "_resource_exists", resource_exists)
    body = SimpleNamespace(
        credential_template_id=None,
        application_template_id="application-template-1",
        presentation_policy_id=None,
        delivery_destination_profile_id=None,
        trust_profile_id=None,
    )
    request = SimpleNamespace()

    await flows._validate_flow_definition_refs(body, request)

    resource_exists.assert_awaited_once_with(
        "issuance",
        "/v1/application-templates/application-template-1",
        request,
        inject_headers=flows._ISSUANCE_HEADERS,
    )


@pytest.mark.asyncio
async def test_cancel_flow_instance_proxies_canonical_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = SimpleNamespace()
    proxy = AsyncMock(return_value=SimpleNamespace(status_code=200))
    registry = SimpleNamespace(get_service_url=lambda service: "http://flow:8011")
    monkeypatch.setattr(flows, "get_registry", lambda: registry)
    monkeypatch.setattr(flows, "proxy_request", proxy)

    response = await flows.cancel_flow_instance("instance-1", request)

    assert response.status_code == 200
    proxy.assert_awaited_once_with(
        request,
        "http://flow:8011",
        "/v1/flows/instances/instance-1/cancel",
    )


@pytest.mark.asyncio
async def test_start_verification_requires_policy_and_trust_profile_in_same_org(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = SimpleNamespace()
    body = StartVerificationFlowRequest(
        presentation_policy_id="policy-1",
        trust_profile_id="trust-1",
        organization_id="org-policy",
        issuer_did="did:web:verifier.example",
    )
    resource_org_id = AsyncMock(side_effect=["org-policy", "org-trust"])
    proxy = AsyncMock()
    monkeypatch.setattr(flows, "_resource_org_id", resource_org_id)
    monkeypatch.setattr(flows, "proxy_request", proxy)

    with pytest.raises(flows.HTTPException) as exc_info:
        await flows.start_verification_flow(body, request)

    assert exc_info.value.status_code == 422
    assert "same organization" in exc_info.value.detail
    proxy.assert_not_awaited()


@pytest.mark.asyncio
async def test_start_verification_proxies_same_org_policy_and_trust_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = SimpleNamespace()
    body = StartVerificationFlowRequest(
        presentation_policy_id="policy-1",
        trust_profile_id="trust-1",
        organization_id="org-1",
        issuer_did="did:web:verifier.example",
    )
    resource_org_id = AsyncMock(side_effect=["org-1", "org-1"])
    internal_response = {
        "instance_id": "instance-1",
        "flow_definition_id": "internal-definition",
        "request_uri": "openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test",
        "qr_code_data": "openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test",
        "presentation_policy_id": "policy-1",
        "nonce": "a-high-entropy-nonce-value",
        "expires_at": "2026-07-30T20:00:00Z",
        "status": "AWAITING_WALLET",
    }
    proxy = AsyncMock(
        return_value=Response(
            content=flows.json.dumps(internal_response),
            media_type="application/json",
        )
    )
    registry = SimpleNamespace(get_service_url=lambda service: "http://flow:8011")
    monkeypatch.setattr(flows, "_resource_org_id", resource_org_id)
    monkeypatch.setattr(flows, "get_registry", lambda: registry)
    monkeypatch.setattr(flows, "proxy_request", proxy)

    response = await flows.start_verification_flow(body, request)

    assert flows.json.loads(response.body) == {
        key: value
        for key, value in internal_response.items()
        if key != "flow_definition_id"
    }
    assert resource_org_id.await_args_list[0].args[:2] == (
        "presentation-policies",
        "/v1/presentation-policies/policy-1",
    )
    assert resource_org_id.await_args_list[1].args[:2] == (
        "trust-profiles",
        "/v1/trust-profiles/trust-1",
    )
    proxy.assert_awaited_once_with(request, "http://flow:8011", "/v1/flows/verify")


def test_verification_start_response_fails_closed_on_missing_public_field() -> None:
    response = Response(
        content=flows.json.dumps(
            {
                "instance_id": "instance-1",
                "flow_definition_id": "internal-definition",
            }
        ),
        media_type="application/json",
    )
    with pytest.raises(flows.HTTPException) as exc_info:
        flows._sanitize_verification_start_response(response)
    assert exc_info.value.status_code == 502


@pytest.mark.asyncio
async def test_start_verification_fails_closed_when_trust_profile_org_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = SimpleNamespace()
    body = StartVerificationFlowRequest(
        presentation_policy_id="policy-1",
        trust_profile_id="trust-1",
        organization_id="org-1",
        issuer_did="did:web:verifier.example",
    )
    monkeypatch.setattr(
        flows,
        "_resource_org_id",
        AsyncMock(side_effect=["org-1", None]),
    )

    with pytest.raises(flows.HTTPException) as exc_info:
        await flows.start_verification_flow(body, request)

    assert exc_info.value.status_code == 422
    assert exc_info.value.detail == "Trust profile not found: trust-1"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("resolved_orgs", "expected_detail"),
    [
        ([{"organization_id": "org-1"}], "Presentation policy not found: policy-1"),
        (["org-1", ["org-1"]], "Trust profile not found: trust-1"),
        (["   "], "Presentation policy not found: policy-1"),
    ],
)
async def test_start_verification_rejects_ambiguous_resource_organization_fields(
    monkeypatch: pytest.MonkeyPatch,
    resolved_orgs: list,
    expected_detail: str,
) -> None:
    request = SimpleNamespace()
    body = StartVerificationFlowRequest(
        presentation_policy_id="policy-1",
        trust_profile_id="trust-1",
        organization_id="org-1",
        issuer_did="did:web:verifier.example",
    )
    monkeypatch.setattr(
        flows,
        "_resource_org_id",
        AsyncMock(side_effect=resolved_orgs),
    )

    with pytest.raises(flows.HTTPException) as exc_info:
        await flows.start_verification_flow(body, request)

    assert exc_info.value.status_code == 422
    assert exc_info.value.detail == expected_detail
