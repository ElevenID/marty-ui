import json
from pathlib import Path
import re
import sys

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from generate_public_openapi_schemas import bundle_schemas  # noqa: E402


def test_recursive_schema_references_are_relocated_into_components():
    sources = {
        "schemas/example.json": {
            "$id": "https://example/schema",
            "$ref": "#/$defs/value",
            "$defs": {"value": {"$ref": "../enums/example.json"}},
        },
        "enums/example.json": {"enum": ["one", "two"]},
    }
    bundled = bundle_schemas(["schemas/example.json"], sources.__getitem__, "a" * 40)
    example = bundled["schemas"]["schemas__example"]
    assert "$id" not in example
    assert example["$ref"] == "#/components/schemas/schemas__example/$defs/value"
    assert example["$defs"]["value"]["$ref"] == "#/components/schemas/enums__example"


@pytest.mark.parametrize(
    "reference",
    ["https://other.example/schema.json", "../../secret.json", "#unknown-anchor"],
)
def test_external_or_outside_protocol_references_fail(reference):
    with pytest.raises(ValueError):
        bundle_schemas(
            ["schemas/example.json"], lambda _: {"$ref": reference}, "a" * 40
        )


def test_generated_create_schema_rejects_private_custody_and_preserves_constraints():
    bundle = json.loads(
        (ROOT / "contracts/gateway-public-openapi-schemas.json").read_text()
    )
    schema = {
        "$ref": "#/components/schemas/schemas__organization_create_request",
        "components": {"schemas": bundle["schemas"]},
    }
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate({"name": "acme", "display_name": "Acme"})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(
            {"name": "acme", "display_name": "Acme", "kms_provider": "private"}
        )
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({"name": "", "display_name": "Acme"})


def test_operation_schema_paths_exist_in_the_real_route_contract():
    routes = {
        r["path"]
        for r in json.loads((ROOT / "contracts/gateway-routes.json").read_text())[
            "routes"
        ]
    }
    source = (ROOT / "rust/services/gateway/src/openapi.rs").read_text()
    for path in re.findall(r'"(/v1/[^" ]+)"', source):
        assert path in routes, path
