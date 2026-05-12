from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from auth.domain.entities import AuthenticatedUser, OIDCUserInfo, UserType
from auth.infrastructure.adapters.credential_login_enricher import build_credential_login_user
from auth.infrastructure.adapters.user_provisioning_adapter import MARTY_ORG_ID


@pytest.mark.asyncio
async def test_build_credential_login_user_falls_back_to_credential_claims_without_provisioning():
    user = await build_credential_login_user(
        {
            "email": "alice@example.com",
            "given_name": "Alice",
            "family_name": "Smith",
            "role": "vendor",
            "organization_id": "org-123",
            "organization_name": "Acme",
            "member_id": "member-123",
        }
    )

    assert user.email == "alice@example.com"
    assert user.organization_id == "org-123"
    assert user.organization_name == "Acme"
    assert user.applicant_id == "member-123"
    assert user.user_type == UserType.VENDOR


@pytest.mark.asyncio
async def test_build_credential_login_user_uses_provisioned_org_context_when_available():
    provisioned_user = AuthenticatedUser(
        user_id="prov-user-1",
        email="alice@example.com",
        username="alice@example.com",
        given_name="Alice",
        family_name="Smith",
        user_type=UserType.APPLICANT,
        applicant_id="prov-app-1",
        roles=["applicant", "admin"],
        organization_id=MARTY_ORG_ID,
        organization_name="Marty Identity Platform",
        organization={
            MARTY_ORG_ID: {"name": "Marty Identity Platform"},
        },
    )
    user_provisioning = AsyncMock()
    user_provisioning.provision_user = AsyncMock(return_value=provisioned_user)

    user = await build_credential_login_user(
        {
            "email": "alice@example.com",
            "given_name": "Alice",
            "family_name": "Smith",
            "role": "applicant",
            "member_id": "member-123",
        },
        user_provisioning=user_provisioning,
    )

    assert user.user_id == "prov-user-1"
    assert user.organization_id == MARTY_ORG_ID
    assert user.organization_name == "Marty Identity Platform"
    assert user.organization == {
        MARTY_ORG_ID: {"name": "Marty Identity Platform"},
    }
    assert user.applicant_id == "member-123"
    assert user.roles == ["applicant", "admin"]


@pytest.mark.asyncio
async def test_build_credential_login_user_prefers_keycloak_context_for_roles_and_orgs():
    keycloak_user = OIDCUserInfo(
        sub="kc-user-1",
        email="alice@example.com",
        preferred_username="alice",
        given_name="Alice",
        family_name="Smith",
        organization={
            "org-1": {"name": "Acme"},
            "org-2": {"name": "Beta"},
        },
        organization_id="org-1",
        organization_name="Acme",
        roles=["administrator", "manage-users"],
    )

    user = await build_credential_login_user(
        {
            "email": "alice@example.com",
            "preferred_username": "badge-alice",
            "member_id": "member-123",
            "role": "applicant",
        },
        keycloak_user=keycloak_user,
    )

    assert user.email == "alice@example.com"
    assert user.username == "badge-alice"
    assert user.user_type == UserType.ADMINISTRATOR
    assert user.organization == {
        "org-1": {"name": "Acme"},
        "org-2": {"name": "Beta"},
    }
    assert user.organization_id == "org-1"
    assert user.roles == ["administrator", "manage-users", "applicant"]
    assert user.applicant_id == "member-123"


@pytest.mark.asyncio
async def test_build_credential_login_user_extracts_did_from_credential_subject():
    """MIP S5 - DID subject from credentialSubject.id is extracted and stored."""
    did = "did:web:beta.elevenidllc.com:orgs:marty"
    user = await build_credential_login_user(
        {
            "email": "alice@example.com",
            "given_name": "Alice",
            "family_name": "Smith",
            "role": "applicant",
            "credentialSubject": {
                "id": did,
                "email": "alice@example.com",
            },
        }
    )
    assert user.did_subject == did
    assert user.email == "alice@example.com"


@pytest.mark.asyncio
async def test_build_credential_login_user_extracts_did_from_sub_claim_fallback():
    """MIP S5 - Falls back to sub claim when credentialSubject is absent."""
    did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    user = await build_credential_login_user(
        {
            "email": "bob@example.com",
            "sub": did,
            "role": "vendor",
        }
    )
    assert user.did_subject == did


@pytest.mark.asyncio
async def test_build_credential_login_user_no_did_when_absent():
    """MIP S5 - did_subject is None when no DID is present in claims."""
    user = await build_credential_login_user(
        {
            "email": "carol@example.com",
            "given_name": "Carol",
            "role": "applicant",
        }
    )
    assert user.did_subject is None


@pytest.mark.asyncio
async def test_build_credential_login_user_did_persists_through_provisioning():
    """MIP S5 - DID survives the provisioning path."""
    did = "did:web:example.com:users:alice"
    provisioned_user = AuthenticatedUser(
        user_id="prov-user-2",
        email="alice@example.com",
        username="alice@example.com",
        given_name="Alice",
        family_name="Smith",
        user_type=UserType.APPLICANT,
        roles=["applicant"],
        organization_id=MARTY_ORG_ID,
        organization_name="Marty Identity Platform",
        organization={MARTY_ORG_ID: {"name": "Marty Identity Platform"}},
    )
    user_provisioning = AsyncMock()
    user_provisioning.provision_user = AsyncMock(return_value=provisioned_user)

    user = await build_credential_login_user(
        {
            "email": "alice@example.com",
            "credentialSubject": {"id": did},
            "role": "applicant",
        },
        user_provisioning=user_provisioning,
    )
    assert user.did_subject == did