from __future__ import annotations

import hashlib
import logging
import uuid

from ...application.ports import UserProvisioningPort
from ...domain.entities import AuthenticatedUser, OIDCUserInfo, UserType

logger = logging.getLogger(__name__)

_USER_TYPE_PRIORITY = {
    UserType.APPLICANT: 0,
    UserType.VENDOR: 1,
    UserType.ADMINISTRATOR: 2,
}


def _extract_did_subject(claims: dict[str, object]) -> str | None:
    """Extract DID subject from W3C Verifiable Credential claims (MIP §5).

    Checks credentialSubject.id for a did: prefix. Falls back to checking
    top-level 'sub' claim if it looks like a DID.
    """
    # Primary: credentialSubject.id from VC data model
    credential_subject = claims.get("credentialSubject")
    if isinstance(credential_subject, dict):
        subject_id = credential_subject.get("id")
        if isinstance(subject_id, str) and subject_id.startswith("did:"):
            return subject_id
    # Fallback: sub claim if it's a DID
    sub = claims.get("sub")
    if isinstance(sub, str) and sub.startswith("did:"):
        return sub
    return None


def _derive_user_id(email: str, claims: dict[str, object]) -> str:
    subject = claims.get("sub") or claims.get("subject")
    if isinstance(subject, str) and subject:
        return subject

    return str(uuid.UUID(bytes=hashlib.sha256(email.lower().encode()).digest()[:16]))


def _merge_roles(*role_sets: list[str]) -> list[str]:
    merged_roles: list[str] = []
    for roles in role_sets:
        for role in roles:
            if role and role not in merged_roles:
                merged_roles.append(role)
    return merged_roles


def _user_type_from_role(role: str) -> UserType:
    if role in {"admin", "administrator"}:
        return UserType.ADMINISTRATOR
    if role == "vendor":
        return UserType.VENDOR
    return UserType.APPLICANT


def _user_type_from_roles(roles: list[str]) -> UserType:
    if any(role in {"admin", "administrator"} for role in roles):
        return UserType.ADMINISTRATOR
    if "vendor" in roles:
        return UserType.VENDOR
    return UserType.APPLICANT


def _prefer_user_type(*user_types: UserType) -> UserType:
    return max(user_types, key=lambda user_type: _USER_TYPE_PRIORITY[user_type])


def _build_fallback_oidc_user(claims: dict[str, object], email: str, role: str, user_id: str) -> OIDCUserInfo:
    organization = claims.get("organization")

    return OIDCUserInfo(
        sub=user_id,
        email=email,
        email_verified=bool(claims.get("email_verified", True)),
        name=claims.get("name") if isinstance(claims.get("name"), str) else None,
        given_name=claims.get("given_name") if isinstance(claims.get("given_name"), str) else None,
        family_name=claims.get("family_name") if isinstance(claims.get("family_name"), str) else None,
        preferred_username=(
            claims.get("preferred_username")
            if isinstance(claims.get("preferred_username"), str)
            else email
        ),
        picture=claims.get("picture") if isinstance(claims.get("picture"), str) else None,
        locale=claims.get("locale") if isinstance(claims.get("locale"), str) else None,
        organization_id=(
            claims.get("organization_id")
            if isinstance(claims.get("organization_id"), str)
            else None
        ),
        organization_name=(
            claims.get("organization_name")
            if isinstance(claims.get("organization_name"), str)
            else None
        ),
        organization=organization if isinstance(organization, dict) else None,
        roles=[role],
    )


def _authenticated_user_from_oidc_user(
    oidc_user: OIDCUserInfo,
    applicant_id: str | None = None,
    did_subject: str | None = None,
) -> AuthenticatedUser:
    return AuthenticatedUser(
        user_id=oidc_user.sub,
        email=oidc_user.email,
        username=oidc_user.preferred_username,
        given_name=oidc_user.given_name,
        family_name=oidc_user.family_name,
        user_type=_user_type_from_roles(oidc_user.roles),
        applicant_id=applicant_id,
        roles=list(oidc_user.roles),
        organization_id=oidc_user.organization_id,
        organization_name=oidc_user.organization_name,
        organization=oidc_user.organization,
        picture=oidc_user.picture,
        did_subject=did_subject,
    )


def _build_fallback_user(claims: dict[str, object], email: str, role: str, user_id: str) -> AuthenticatedUser:
    member_id = claims.get("member_id")
    fallback_oidc_user = _build_fallback_oidc_user(claims, email, role, user_id)
    return _authenticated_user_from_oidc_user(
        fallback_oidc_user,
        applicant_id=member_id if isinstance(member_id, str) else None,
    )


async def build_credential_login_user(
    claims: dict[str, object],
    user_provisioning: UserProvisioningPort | None = None,
    keycloak_user: OIDCUserInfo | None = None,
) -> AuthenticatedUser:
    email = claims.get("email")
    if not isinstance(email, str) or not email:
        raise ValueError("Credential missing email claim")

    role = claims.get("role") if isinstance(claims.get("role"), str) else "applicant"
    user_id = _derive_user_id(email, claims)
    did_subject = _extract_did_subject(claims)  # MIP §5 — DID identity from credential
    fallback_oidc_user = _build_fallback_oidc_user(claims, email, role, user_id)
    fallback_user = _build_fallback_user(claims, email, role, user_id)
    identity_seed = keycloak_user or fallback_oidc_user

    if user_provisioning is None:
        base_user = _authenticated_user_from_oidc_user(
            identity_seed,
            applicant_id=fallback_user.applicant_id,
            did_subject=did_subject,
        )
        merged_roles = _merge_roles(base_user.roles, fallback_user.roles)
        return AuthenticatedUser(
            user_id=base_user.user_id or fallback_user.user_id,
            email=fallback_user.email or base_user.email,
            username=fallback_user.username or base_user.username,
            given_name=base_user.given_name or fallback_user.given_name,
            family_name=base_user.family_name or fallback_user.family_name,
            user_type=_prefer_user_type(base_user.user_type, _user_type_from_roles(merged_roles)),
            applicant_id=fallback_user.applicant_id or base_user.applicant_id,
            roles=merged_roles,
            organization_id=base_user.organization_id or fallback_user.organization_id,
            organization_name=base_user.organization_name or fallback_user.organization_name,
            organization=base_user.organization or fallback_user.organization,
            picture=base_user.picture or fallback_user.picture,
            did_subject=base_user.did_subject or did_subject,
        )

    try:
        provisioned_user = await user_provisioning.provision_user(identity_seed)
    except Exception as exc:
        logger.warning(
            "Credential login provisioning failed for %s, falling back to credential claims: %s",
            email,
            exc,
        )
        provisioned_user = _authenticated_user_from_oidc_user(
            identity_seed,
            applicant_id=fallback_user.applicant_id,
            did_subject=did_subject,
        )

    merged_roles = _merge_roles(provisioned_user.roles, fallback_user.roles)
    merged_user_type = _prefer_user_type(
        provisioned_user.user_type,
        _user_type_from_roles(merged_roles),
    )

    return AuthenticatedUser(
        user_id=provisioned_user.user_id or fallback_user.user_id,
        email=fallback_user.email or provisioned_user.email,
        username=fallback_user.username or provisioned_user.username,
        given_name=provisioned_user.given_name or fallback_user.given_name,
        family_name=provisioned_user.family_name or fallback_user.family_name,
        user_type=merged_user_type,
        applicant_id=fallback_user.applicant_id or provisioned_user.applicant_id,
        roles=merged_roles,
        organization_id=provisioned_user.organization_id or fallback_user.organization_id,
        organization_name=provisioned_user.organization_name or fallback_user.organization_name,
        organization=provisioned_user.organization or fallback_user.organization,
        onboarding_completed=provisioned_user.onboarding_completed,
        picture=provisioned_user.picture or fallback_user.picture,
        impersonation=provisioned_user.impersonation,
        did_subject=did_subject or provisioned_user.did_subject,
    )