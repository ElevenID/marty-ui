"""Native field coverage and adversarial public template write schema cases."""

import copy
import json
import re
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
WRITES = json.loads(
    (ROOT / "contracts/credential-template-write-schemas.json").read_bytes()
)
WRITES["runtime__credential_template_validity_input"] = json.loads(
    (ROOT / "contracts/credential-template-validity-input.json").read_bytes()
)
FIXTURES = json.loads(
    (ROOT / "contracts/credential-template-write-behavior.json").read_bytes()
)


def validator(component):
    schema = {
        "$ref": "#/components/schemas/runtime__credential_template_" + component,
        "components": {"schemas": WRITES},
    }
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def test_every_native_and_gateway_public_root_field_is_described():
    native = (ROOT / "rust/services/credential-template/src/http_service.rs").read_text(
        encoding="utf-8"
    )
    for struct, component in [
        ("CreateTemplateRequest", "create_request"),
        ("UpdateTemplateRequest", "update_request"),
    ]:
        body = re.search(
            r"struct " + struct + r" \{(.*?)\n\}", native, re.DOTALL
        ).group(1)
        fields = set(re.findall(r"^    (\w+):", body, re.MULTILINE))
        if "_schema_uri" in fields:
            fields.remove("_schema_uri")
            fields.add("schema_uri")
        assert fields == set(
            WRITES["runtime__credential_template_" + component]["properties"]
        )
    gateway = (
        ROOT / "rust/services/gateway/src/credential_template_contract.rs"
    ).read_text(encoding="utf-8")
    body = re.search(r"const CREATE_FIELDS:.*?= &\[(.*?)\];", gateway, re.DOTALL).group(
        1
    )
    assert set(re.findall(r'"(\w+)"', body)) == set(
        WRITES["runtime__credential_template_create_request"]["properties"]
    )


@pytest.mark.parametrize(
    "case", FIXTURES["valid_create"], ids=lambda case: case["name"]
)
def test_public_create_fixtures(case):
    validator("create_request").validate(case["public"])


@pytest.mark.parametrize(
    "case", FIXTURES["valid_update"], ids=lambda case: case["name"]
)
def test_public_update_fixtures(case):
    validator("update_request").validate(case["public"])


@pytest.mark.parametrize("case", FIXTURES["invalid"], ids=lambda case: case["name"])
def test_rejected_native_or_gateway_fixture_is_not_advertised(case):
    with pytest.raises(jsonschema.ValidationError):
        validator(
            "create_request" if case["method"] == "POST" else "update_request"
        ).validate(case["public"])


@pytest.mark.parametrize(
    "field",
    [
        "key_reference",
        "signing_service_id",
        "signing_key_reference",
        "issuer_profile_id",
        "private_key",
        "privatekeyjwk",
        "access_token",
        "auth_token",
        "api_key",
        "client_secret",
    ],
)
def test_private_parameter_names_are_rejected_recursively_case_insensitively(field):
    value = copy.deepcopy(FIXTURES["valid_create"][1]["public"])
    value["derived_attributes"][0]["parameters"] = {
        "nested": [{"deeper": {field.upper(): "secret"}}]
    }
    with pytest.raises(jsonschema.ValidationError):
        validator("create_request").validate(value)


def test_patch_claims_null_is_not_a_clear_and_immutable_selectors_are_absent():
    properties = WRITES["runtime__credential_template_update_request"]["properties"]
    assert (
        not {
            "organization_id",
            "credential_type",
            "compliance_profile_id",
            "vct",
            "doctype",
            "schema_uri",
        }
        & properties.keys()
    )
    for value in [{"claims": None}, {"claims": []}]:
        with pytest.raises(jsonschema.ValidationError):
            validator("update_request").validate(value)
    validator("update_request").validate(
        {"description": None, "revocation_profile_id": ""}
    )
