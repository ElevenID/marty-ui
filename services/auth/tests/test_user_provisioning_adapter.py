from __future__ import annotations

from datetime import date, datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import grpc
import pytest

from auth.domain.entities import OIDCUserInfo
from auth.infrastructure.applicant_record_model import ApplicantRecord
from auth.infrastructure.adapters.user_provisioning_adapter import (
    InMemoryUserProvisioningAdapter,
    JITUserProvisioningAdapter,
    MARTY_ORG_ID,
    UNKNOWN_DATE_OF_BIRTH,
    UNKNOWN_NATIONALITY,
)


class _FakeRpcError(grpc.RpcError):
    def __init__(self, code: grpc.StatusCode, details: str = "") -> None:
        self._code = code
        self._details = details

    def code(self):
        return self._code

    def details(self):
        return self._details


@pytest.mark.asyncio
async def test_resolve_marty_organization_context_returns_membership_and_org_name():
    adapter = JITUserProvisioningAdapter(session_factory=AsyncMock())
    adapter._org_stub = SimpleNamespace(
        GetMember=AsyncMock(
            return_value=SimpleNamespace(
                organization_id=MARTY_ORG_ID,
                roles=[SimpleNamespace(name="applicant"), SimpleNamespace(name="admin")],
                has_org_console_access=True,
            )
        ),
        GetOrganization=AsyncMock(
            return_value=SimpleNamespace(
                display_name="Marty Default Org",
                name="marty",
            )
        ),
    )

    org_id, org_name, member_roles, has_org_console_access, context_unavailable = await adapter._resolve_marty_organization_context("user-123")

    assert org_id == MARTY_ORG_ID
    assert org_name == "Marty Default Org"
    assert member_roles == ["applicant", "admin"]
    assert has_org_console_access is True
    assert context_unavailable is False


@pytest.mark.asyncio
async def test_resolve_marty_organization_context_returns_none_when_membership_missing():
    adapter = JITUserProvisioningAdapter(session_factory=AsyncMock())
    adapter._org_stub = SimpleNamespace(
        GetMember=AsyncMock(side_effect=_FakeRpcError(grpc.StatusCode.NOT_FOUND, "missing")),
        GetOrganization=AsyncMock(),
    )

    org_id, org_name, member_roles, has_org_console_access, context_unavailable = await adapter._resolve_marty_organization_context("user-123")

    assert org_id is None
    assert org_name is None
    assert member_roles == []
    assert has_org_console_access is False
    assert context_unavailable is False
    adapter._org_stub.GetOrganization.assert_not_awaited()


def test_build_new_applicant_record_maps_oidc_user_into_modern_applicant_shape():
    adapter = JITUserProvisioningAdapter(session_factory=AsyncMock())
    oidc_user = OIDCUserInfo(
        sub="auth0|user-123",
        email="marty@example.com",
        name="Marty McFly",
    )

    applicant = adapter._build_new_applicant_record(oidc_user)

    assert applicant.account_id == "auth0|user-123"
    assert applicant.email == "marty@example.com"
    assert applicant.given_names == "Marty"
    assert applicant.surname == "McFly"
    assert applicant.date_of_birth == UNKNOWN_DATE_OF_BIRTH
    assert applicant.nationality == UNKNOWN_NATIONALITY
    assert applicant.extra_data["provisioned_via"] == "jit"
    assert applicant.extra_data["oidc_claims_incomplete"] is False
    assert applicant.extra_data["last_login_at"]


def test_update_applicant_record_preserves_existing_names_when_claims_are_missing():
    adapter = JITUserProvisioningAdapter(session_factory=AsyncMock())
    applicant = ApplicantRecord(
        id="app-1",
        account_id="old-sub",
        email="old@example.com",
        surname="McFly",
        given_names="Marty",
        date_of_birth=date(1985, 10, 26),
        nationality="USA",
        identity_proofing_completed=True,
        identity_proofing_date=datetime(2026, 1, 1, tzinfo=timezone.utc),
        extra_data={"foo": "bar"},
    )

    adapter._update_applicant_record_from_oidc(
        applicant,
        OIDCUserInfo(
            sub="new-sub",
            email="new@example.com",
            given_name=None,
            family_name=None,
        ),
    )

    assert applicant.account_id == "new-sub"
    assert applicant.email == "new@example.com"
    assert applicant.given_names == "Marty"
    assert applicant.surname == "McFly"
    assert applicant.extra_data["foo"] == "bar"
    assert applicant.extra_data["provisioned_via"] == "jit"
    assert applicant.extra_data["oidc_claims_incomplete"] is True


def test_to_authenticated_name_parts_hides_unknown_placeholders():
    given_name, family_name = JITUserProvisioningAdapter._to_authenticated_name_parts(
        ApplicantRecord(
            id="app-2",
            account_id="sub-2",
            email="unknown@example.com",
            surname="Unknown",
            given_names="Unknown",
            date_of_birth=date(1900, 1, 1),
            nationality="UNK",
        )
    )

    assert given_name is None
    assert family_name is None


@pytest.mark.asyncio
async def test_in_memory_provisioning_enriches_session_with_marty_org_context():
    adapter = InMemoryUserProvisioningAdapter()
    adapter._org_stub = SimpleNamespace(
        AddMember=AsyncMock(),
        GetMember=AsyncMock(
            return_value=SimpleNamespace(
                organization_id=MARTY_ORG_ID,
                roles=[SimpleNamespace(name="admin")],
                has_org_console_access=True,
            )
        ),
        GetOrganization=AsyncMock(
            return_value=SimpleNamespace(
                display_name="Marty Identity Platform",
                name="Marty",
            )
        ),
    )

    user = await adapter.provision_user(
        OIDCUserInfo(
            sub="user-123",
            email="marty@example.com",
            preferred_username="marty@example.com",
            given_name="Marty",
            family_name="McFly",
            organization={
                MARTY_ORG_ID: {"name": "Marty Identity Platform"},
            },
            roles=["administrator"],
        )
    )

    assert user.organization_id == MARTY_ORG_ID
    assert user.organization_name == "Marty Identity Platform"
    assert user.default_organization_id == MARTY_ORG_ID
    assert user.default_organization_name == "Marty Identity Platform"
    assert user.organizations == [
        {
            "id": MARTY_ORG_ID,
            "name": "marty",
            "display_name": "Marty Identity Platform",
            "membership": {
                "roles": [{"name": "admin", "display_name": "admin"}],
                "status": "active",
                "permissions": [],
                "has_org_console_access": True,
                "is_owner": False,
            },
        }
    ]
    assert user.organization_context_unavailable is False
    assert user.organization == {
        MARTY_ORG_ID: {"name": "Marty Identity Platform"},
    }
    assert "admin" in user.roles
    assert user.user_type.value == "administrator"
