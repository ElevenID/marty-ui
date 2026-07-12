"""Flow gateway dependency-routing tests."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from gateway.routes import flows


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
