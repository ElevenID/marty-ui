from __future__ import annotations

import pytest
from pydantic import ValidationError

from gateway.models import (
    ComplianceProfileCreate,
    CredentialTemplateCreate,
    DeploymentProfileCreate,
    DeploymentProfileUpdate,
)
from gateway.routes.deployment import deployment_profile_router
from gateway.routes.credentials import compliance_profile_router


@pytest.mark.parametrize(
    ("model", "payload", "removed_field"),
    [
        (
            ComplianceProfileCreate,
            {"organization_id": "org-1", "name": "Compliance"},
            "default_verification_rules",
        ),
        (
            CredentialTemplateCreate,
            {
                "organization_id": "org-1",
                "name": "Member badge",
                "credential_type": "MemberCredential",
                "vct": "https://beta.elevenidllc.com/credentials/member",
                "compliance_profile_id": "10000000-0000-0000-0000-000000000001",
            },
            "issuer_requirements",
        ),
        (
            CredentialTemplateCreate,
            {
                "organization_id": "org-1",
                "name": "Member badge",
                "credential_type": "MemberCredential",
                "vct": "https://beta.elevenidllc.com/credentials/member",
                "compliance_profile_id": "10000000-0000-0000-0000-000000000001",
            },
            "artifacts_auto_generate",
        ),
        (
            CredentialTemplateCreate,
            {
                "organization_id": "org-1",
                "name": "Member badge",
                "credential_type": "MemberCredential",
                "vct": "https://beta.elevenidllc.com/credentials/member",
                "compliance_profile_id": "10000000-0000-0000-0000-000000000001",
            },
            "wallet_configs",
        ),
        (
            DeploymentProfileCreate,
            {"organization_id": "org-1", "name": "Runtime"},
            "default_presentation_policy_id",
        ),
        (
            DeploymentProfileCreate,
            {"organization_id": "org-1", "name": "Runtime"},
            "ux_config",
        ),
        (DeploymentProfileUpdate, {}, "default_presentation_policy_id"),
        (DeploymentProfileUpdate, {}, "ux_config"),
    ],
)
def test_gateway_rejects_removed_request_fields(model, payload, removed_field) -> None:
    with pytest.raises(ValidationError, match=removed_field):
        model.model_validate({**payload, removed_field: {}})


def test_deployment_profile_put_route_is_removed() -> None:
    profile_methods = {
        method
        for route in deployment_profile_router.routes
        if route.path == "/v1/deployment-profiles/{profile_id}"
        for method in (route.methods or set())
    }

    assert "PUT" not in profile_methods
    assert "PATCH" in profile_methods


def test_compliance_profile_put_route_is_removed() -> None:
    profile_methods = {
        method
        for route in compliance_profile_router.routes
        if route.path == "/v1/compliance-profiles/{profile_id}"
        for method in (route.methods or set())
    }

    assert "PUT" not in profile_methods
    assert "PATCH" in profile_methods


def test_credential_template_requires_compliance_profile_reference() -> None:
    payload = {
        "organization_id": "org-1",
        "name": "Member badge",
        "credential_type": "MemberCredential",
        "vct": "https://beta.elevenidllc.com/credentials/member",
    }

    with pytest.raises(ValidationError, match="compliance_profile_id"):
        CredentialTemplateCreate.model_validate(payload)
    with pytest.raises(ValidationError, match="compliance_profile"):
        CredentialTemplateCreate.model_validate({
            **payload,
            "compliance_profile_id": "10000000-0000-0000-0000-000000000001",
            "compliance_profile": {"compliance_code": "CUSTOM"},
        })
