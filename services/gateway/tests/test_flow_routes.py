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
