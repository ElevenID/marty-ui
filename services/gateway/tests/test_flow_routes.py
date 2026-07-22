"""Flow gateway dependency-routing tests."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from gateway.routes import flows
from gateway.models import StartVerificationFlowRequest


def test_gateway_preserves_profile_haip_and_post_request_uri_options() -> None:
    request = StartVerificationFlowRequest(
        presentation_policy_id="policy-1",
        issuer_profile_id="issuer-profile-1",
        issuer_did="did:web:verifier.example",
        oid4vp_profile="haip",
        request_uri_method="post",
    )
    assert request.model_dump()["issuer_profile_id"] == "issuer-profile-1"
    assert request.model_dump()["issuer_did"] == "did:web:verifier.example"
    assert request.model_dump()["oid4vp_profile"] == "haip"
    assert request.model_dump()["request_uri_method"] == "post"


@pytest.mark.parametrize(
    "direct_kms_field",
    ("signing_service_id", "signing_key_reference", "issuer_key_id"),
)
def test_verification_flow_rejects_direct_kms_routing(direct_kms_field: str) -> None:
    with pytest.raises(ValueError, match=direct_kms_field):
        StartVerificationFlowRequest.model_validate(
            {
                "presentation_policy_id": "policy-1",
                "issuer_profile_id": "issuer-profile-1",
                "issuer_did": "did:web:verifier.example",
                direct_kms_field: "must-not-cross-runtime-boundary",
            }
        )


@pytest.mark.asyncio
async def test_flow_definition_resolves_application_template_from_issuance(monkeypatch: pytest.MonkeyPatch) -> None:
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
async def test_cancel_flow_instance_proxies_canonical_route(monkeypatch: pytest.MonkeyPatch) -> None:
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
    )
    resource_org_id = AsyncMock(side_effect=["org-1", "org-1"])
    expected_response = SimpleNamespace(status_code=200)
    proxy = AsyncMock(return_value=expected_response)
    registry = SimpleNamespace(get_service_url=lambda service: "http://flow:8011")
    monkeypatch.setattr(flows, "_resource_org_id", resource_org_id)
    monkeypatch.setattr(flows, "get_registry", lambda: registry)
    monkeypatch.setattr(flows, "proxy_request", proxy)

    response = await flows.start_verification_flow(body, request)

    assert response is expected_response
    assert resource_org_id.await_args_list[0].args[:2] == (
        "presentation-policies",
        "/v1/presentation-policies/policy-1",
    )
    assert resource_org_id.await_args_list[1].args[:2] == (
        "trust-profiles",
        "/v1/trust-profiles/trust-1",
    )
    proxy.assert_awaited_once_with(request, "http://flow:8011", "/v1/flows/verify")


@pytest.mark.asyncio
async def test_start_verification_fails_closed_when_trust_profile_org_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = SimpleNamespace()
    body = StartVerificationFlowRequest(
        presentation_policy_id="policy-1",
        trust_profile_id="trust-1",
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
