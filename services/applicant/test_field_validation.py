from __future__ import annotations

import pytest
from fastapi import HTTPException

try:
    from applicant.main import _validate_form_data
except ModuleNotFoundError:
    from services.applicant.main import _validate_form_data


FIELDS = [
    {"field_id": "name", "label": "Name", "field_type": "TEXT", "required": True, "validation_pattern": "[A-Z][a-z]+"},
    {"field_id": "birth_date", "label": "Birth date", "field_type": "DATE", "required": True},
    {"field_id": "appointment", "label": "Appointment", "field_type": "DATETIME", "required": False},
    {"field_id": "tier", "label": "Tier", "field_type": "SELECT", "required": True, "options": ["standard", "premium"]},
    {"field_id": "visits", "label": "Visits", "field_type": "INTEGER", "required": True, "minimum": 1, "maximum": 10},
    {"field_id": "score", "label": "Score", "field_type": "NUMBER", "required": True, "minimum": 0.5, "maximum": 99.5},
    {"field_id": "consent", "label": "Consent", "field_type": "BOOLEAN", "required": True},
]


def valid_form() -> dict:
    return {
        "name": "Ada",
        "birth_date": "1815-12-10",
        "appointment": "2026-07-12T15:30:00Z",
        "tier": "premium",
        "visits": 3,
        "score": 98.5,
        "consent": True,
    }


def field_errors(form_data: dict, fields: list[dict] = FIELDS) -> list[dict]:
    with pytest.raises(HTTPException) as exc:
        _validate_form_data(form_data, fields)
    assert exc.value.status_code == 422
    assert exc.value.detail["error"] == "FIELD_VALIDATION_FAILED"
    return exc.value.detail["field_errors"]


def test_accepts_all_canonical_field_types() -> None:
    _validate_form_data(valid_form(), FIELDS)


def test_empty_options_do_not_restrict_non_select_fields() -> None:
    _validate_form_data(
        {"email": "ada@example.test"},
        [{"field_id": "email", "label": "Email", "field_type": "EMAIL", "required": True, "options": []}],
    )


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("birth_date", "1815-1-1", "INVALID_DATE"),
        ("birth_date", "1815-02-31", "INVALID_DATE"),
        ("appointment", "not-a-date", "INVALID_DATETIME"),
        ("tier", "vip", "INVALID_CHOICE"),
        ("visits", 3.5, "INVALID_INTEGER"),
        ("visits", 0, "BELOW_MINIMUM"),
        ("visits", 11, "ABOVE_MAXIMUM"),
        ("score", "98.5", "INVALID_NUMBER"),
        ("consent", "true", "INVALID_BOOLEAN"),
        ("name", "ada", "PATTERN_MISMATCH"),
    ],
)
def test_rejects_invalid_canonical_values(field: str, value, code: str) -> None:
    form = valid_form()
    form[field] = value
    assert any(error["field"] == field and error["code"] == code for error in field_errors(form))


def test_rejects_missing_and_unknown_fields() -> None:
    form = valid_form()
    del form["name"]
    form["reviewer_notes"] = "not applicant input"

    errors = field_errors(form)

    assert any(error["field"] == "name" and error["code"] == "REQUIRED" for error in errors)
    assert any(error["field"] == "reviewer_notes" and error["code"] == "UNKNOWN_FIELD" for error in errors)


def test_invalid_template_pattern_fails_closed() -> None:
    fields = [{"field_id": "name", "label": "Name", "field_type": "TEXT", "required": True, "validation_pattern": "["}]
    errors = field_errors({"name": "Ada"}, fields)
    assert errors == [{
        "field": "name",
        "code": "INVALID_FIELD_CONFIGURATION",
        "message": "Field validation pattern is invalid.",
    }]
