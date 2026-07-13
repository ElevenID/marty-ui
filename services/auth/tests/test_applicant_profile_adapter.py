from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from auth.domain.entities import AuthenticatedUser, UserType
from auth.infrastructure.adapters.applicant_profile_adapter import ApplicantProfileProvisioningAdapter
from auth.infrastructure.adapters.keycloak_admin_adapter import KeycloakAdminAdapter


@pytest.mark.asyncio
async def test_credential_login_profile_upsert_sends_authenticated_organization_context():
    user = AuthenticatedUser(
        user_id="user-1",
        email="holder@example.com",
        username="holder@example.com",
        given_name="Holder",
        family_name="Example",
        user_type=UserType.APPLICANT,
        roles=["applicant"],
        organization_id="org-1",
    )
    response = httpx.Response(
        200,
        json={"id": "applicant-1"},
        request=httpx.Request("PATCH", "http://applicant/v1/me/applicant-profile"),
    )
    client = AsyncMock()
    client.patch.return_value = response
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None

    with patch(
        "auth.infrastructure.adapters.applicant_profile_adapter.httpx.AsyncClient",
        return_value=client,
    ):
        applicant_id = await ApplicantProfileProvisioningAdapter(
            service_url="http://applicant",
        ).ensure_applicant_profile(user)

    assert applicant_id == "applicant-1"
    _, kwargs = client.patch.call_args
    assert kwargs["headers"] == {
        "X-User-Id": "user-1",
        "X-User-Email": "holder@example.com",
        "X-Organization-ID": "org-1",
    }


@pytest.mark.asyncio
async def test_keycloak_token_exchange_is_not_probed_when_disabled(monkeypatch):
    monkeypatch.delenv("KEYCLOAK_TOKEN_EXCHANGE_ENABLED", raising=False)
    adapter = KeycloakAdminAdapter(
        admin_url="http://keycloak",
        realm="marty",
        client_id="marty-api",
        client_secret="secret",
    )

    with patch(
        "auth.infrastructure.adapters.keycloak_admin_adapter.httpx.AsyncClient",
    ) as client:
        tokens = await adapter.exchange_token_for_user("kc-user-1")

    assert tokens is None
    client.assert_not_called()
