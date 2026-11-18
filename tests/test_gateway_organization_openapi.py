"""Adversarial checks for the actual-export organization schema validator."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest
from jsonschema.exceptions import ValidationError

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "organization_export", ROOT / "scripts/check_gateway_organization_openapi.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def fixture():
    # A validator fixture only. The actual generated component is checked by
    # running this validator against the compiled executable/image export.
    organization = json.loads(
        (ROOT / "contracts/gateway-public-openapi-schemas.json").read_bytes()
    )["schemas"]["schemas__organization"]
    membership = organization["properties"]["membership"]["oneOf"][0]
    membership["required"].remove("joined_at")
    membership["properties"]["roles"]["items"]["required"].remove("display_name")
    operation = {
        "x-marty-response-schema-documented": True,
        "responses": {"200": {"content": {"application/json": {"schema": {
            "type": "array", "items": {"$ref": "#/components/schemas/schemas__organization"}
        }}}}},
    }
    document = {
        "components": {"schemas": {"schemas__organization": organization}},
        "paths": {path: {"get": copy.deepcopy(operation)} for path in MODULE.COLLECTIONS},
    }
    behavior = json.loads((ROOT / "contracts/gateway-organization-behavior.json").read_bytes())
    return document, behavior


def test_accepts_native_projector_readbacks_and_empty_collections():
    document, behavior = fixture()
    assert MODULE.validate(document, behavior) == {
        "organization_collections": 3, "readback_cases": 4
    }


@pytest.mark.parametrize("mutation", ["unmarked", "envelope", "private_fields", "missing_fields", "required_optional"])
def test_rejects_misleading_or_incompatible_organization_exports(mutation):
    document, behavior = fixture()
    operation = document["paths"][MODULE.COLLECTIONS[1]]["get"]
    organization = document["components"]["schemas"]["schemas__organization"]
    if mutation == "unmarked":
        operation["x-marty-response-schema-documented"] = False
    elif mutation == "envelope":
        operation["responses"]["200"]["content"]["application/json"]["schema"] = {"type": "object"}
    elif mutation == "private_fields":
        organization["additionalProperties"] = True
    elif mutation == "missing_fields":
        organization["required"] = ["id"]
    else:
        organization["properties"]["membership"]["oneOf"][0]["required"].append("joined_at")
    with pytest.raises((ValueError, ValidationError)):
        MODULE.validate(document, behavior)
