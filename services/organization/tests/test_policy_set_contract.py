from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from organization.application.policy_set_use_cases import PolicySetUseCase
from organization.domain.policy_set import PolicySet, PolicySetStatus, PolicySetType
from organization.infrastructure.adapters.policy_set_http_adapter import (
    POLICY_SET_TEMPLATES,
    CreatePolicySetRequest,
    _policy_set_response,
)


def test_policy_set_is_created_as_draft() -> None:
    policy_set = PolicySet.create(
        organization_id="org-1",
        name="Approval",
        cedar_policies="[]",
        policy_type=PolicySetType.APPROVAL_RULES,
    )

    assert policy_set.status == PolicySetStatus.DRAFT
    assert policy_set.cedar_schema_version == "MIP/1.0"


def test_create_request_requires_structured_cedar_policies() -> None:
    with pytest.raises(ValidationError):
        CreatePolicySetRequest(
            name="Legacy text",
            policy_type="CUSTOM",
            cedar_policies="permit(principal, action, resource);",
        )


def test_response_preserves_structured_policy_text() -> None:
    policies = POLICY_SET_TEMPLATES[0]["cedar_policies"]
    policy_set = PolicySet.create(
        organization_id="org-1",
        name="Approval",
        cedar_policies=json.dumps(policies),
        policy_type=PolicySetType.APPROVAL_RULES,
    )

    response = _policy_set_response(policy_set)

    assert response.cedar_policies == policies
    assert response.status == "DRAFT"


def test_templates_are_protocol_shaped() -> None:
    assert {template["policy_type"] for template in POLICY_SET_TEMPLATES} == {
        "ACCESS_CONTROL",
        "CREDENTIAL_VERIFICATION",
        "APPROVAL_RULES",
    }
    for template in POLICY_SET_TEMPLATES:
        request = CreatePolicySetRequest(
            name=template["name"],
            description=template["description"],
            policy_type=template["policy_type"],
            cedar_policies=template["cedar_policies"],
        )
        assert request.cedar_policies


def test_policy_validation_rejects_effect_mismatch() -> None:
    use_case = PolicySetUseCase(repo=None, cedar_engine=None)

    errors = use_case.validate_policies([{
        "policy_id": "mismatch",
        "effect": "forbid",
        "cedar_text": "permit(principal, action, resource);",
        "enabled": True,
    }])

    assert errors == ["Policy mismatch effect does not match its Cedar statement"]
