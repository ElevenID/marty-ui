"""MIP 0.3 Application Template gateway contract tests."""

import pytest
from pydantic import ValidationError

from gateway.models import ApplicationTemplateCreate, ApplicationTemplatePatch


def _payload() -> dict:
    return {
        "organization_id": "org-1",
        "name": "Membership application",
        "credential_template_id": "credential-template-1",
        "form_fields": [
            {
                "field_id": "member_email",
                "label": "Member email",
                "field_type": "EMAIL",
                "required": True,
                "claim_mapping": "email",
            }
        ],
    }


def test_create_accepts_canonical_fields_and_is_draft_implicit() -> None:
    request = ApplicationTemplateCreate(**_payload())

    assert request.approval_strategy == "MANUAL"
    assert request.form_fields[0].field_id == "member_email"
    assert "status" not in request.model_dump()


@pytest.mark.parametrize(
    "field",
    [
        {"name": "email", "label": "Email", "type": "text", "required": True},
        {"field_id": "email", "label": "Email", "field_type": "text", "required": True},
        {"field_id": "email", "label": "Email", "field_type": "TEXT", "required": True, "pattern": ".+"},
        {"field_id": "email", "label": "Email", "field_type": "SELECT", "required": True, "enum": ["a"]},
    ],
)
def test_create_rejects_legacy_field_aliases(field: dict) -> None:
    payload = _payload()
    payload["form_fields"] = [field]

    with pytest.raises(ValidationError):
        ApplicationTemplateCreate(**payload)


def test_create_rejects_client_status_and_opaque_approval_rules() -> None:
    with pytest.raises(ValidationError):
        ApplicationTemplateCreate(**_payload(), status="ACTIVE")
    with pytest.raises(ValidationError):
        ApplicationTemplateCreate(**_payload(), auto_approval_rules=[])


def test_patch_contains_only_mutable_draft_fields() -> None:
    patch = ApplicationTemplatePatch(name="Updated", application_validity_days=90)

    assert patch.model_dump(exclude_unset=True) == {
        "name": "Updated",
        "application_validity_days": 90,
    }
    with pytest.raises(ValidationError):
        ApplicationTemplatePatch(status="ACTIVE")
