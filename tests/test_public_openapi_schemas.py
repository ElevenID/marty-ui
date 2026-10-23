from copy import deepcopy
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


def test_identity_capability_extension_is_strict_and_contains_no_custody_fields():
    schema = json.loads(
        (ROOT / "contracts/issuer-identity-capabilities-response.json").read_text()
    )
    validator = jsonschema.Draft202012Validator(schema)
    value = {
        "organization_id": "org-a",
        "basis": "configuration",
        "managed_issuer_did_prefix": "did:web:issuer.example:orgs:",
        "creation_options": [
            {
                "key_purpose": "vc_jwt_issuer",
                "credential_format": "SD_JWT_VC",
                "algorithm": "ES256",
            }
        ],
    }
    validator.validate(value)
    validator.validate(
        {**value, "managed_issuer_did_prefix": None, "creation_options": []}
    )
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({**value, "service_id": "private"})
    value["creation_options"][0]["key_reference"] = "private"
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(value)


def test_template_issuer_options_extensions_enforce_nested_public_boundaries():
    request = jsonschema.Draft202012Validator(json.loads(
        (ROOT / "contracts/template-issuer-options-request.json").read_text()
    ))
    scope = {"organization_id": "org-a", "compliance_profile_id": "profile-a"}
    request.validate(scope)
    request.validate({**scope, "supported_formats": ["SD_JWT_VC", "MDOC"]})
    for forbidden in ["algorithm", "signing_service_id", "key_reference", "issuer_profile_id"]:
        with pytest.raises(jsonschema.ValidationError):
            request.validate({**scope, forbidden: "private"})
    response = jsonschema.Draft202012Validator(json.loads(
        (ROOT / "contracts/template-issuer-options-response.json").read_text()
    ))
    value = {
        **scope, "credential_payload_format": "SD_JWT_VC", "supported_formats": ["SD_JWT_VC"],
        "issuance_protocol": "OID4VCI_PRE_AUTH",
        "requirements": {"vct": True, "doctype": False, "revocation_profile": True, "x509_certificate": False},
        "identities": [{"issuer_did": "did:example:issuer", "bindings": [{
            "credential_format": "SD_JWT_VC", "key_purpose": "vc_jwt_issuer", "algorithm": "ES256"
        }]}],
        "rejected_issuers": [{"issuer_did": "did:example:ambiguous", "reason": "ambiguous_identity"}],
    }
    response.validate(value)
    response.validate({**value, "identities": [], "rejected_issuers": []})
    for path, key, invalid in [
        ([], "key_reference", "private"),
        (["identities", 0], "signing_service_id", "private"),
        (["identities", 0, "bindings", 0], "key_reference", "private"),
        (["identities", 0, "bindings", 0], "public_jwk", {"d": "private"}),
        (["requirements"], "doctype", "false"),
        (["rejected_issuers", 0], "reason", "private-key-error"),
    ]:
        mutated = deepcopy(value)
        cursor = mutated
        for segment in path:
            cursor = cursor[segment]
        cursor[key] = invalid
        with pytest.raises(jsonschema.ValidationError):
            response.validate(mutated)


def test_inspection_component_example_and_recursive_public_document_boundaries():
    name = "runtime__issuer_identity_inspection"
    component = json.loads(
        (ROOT / "contracts/issuer-identity-inspection-response.json").read_text()
    )
    schema = {
        "$ref": f"#/components/schemas/{name}",
        "components": {"schemas": {name: component}},
    }
    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    )
    value = json.loads(
        (ROOT / "contracts/issuer-identity-inspection-example.json").read_text()
    )
    validator.validate(value)
    for path, field, invalid in [
        ([], "issuer_profile_id", "private"),
        (
            ["registry", "document", "verificationMethod", 0, "publicKeyJwk"],
            "d",
            "private",
        ),
        (["public_resolution", "document"], "service_id", "private"),
        (["managed_signer", "public_jwk"], "key_reference", "private"),
        (["registry", "verification_methods", 0], "assertion_authorized", "true"),
        (["public_resolution"], "checked_at", "not-a-timestamp"),
    ]:
        mutated = deepcopy(value)
        target = mutated
        for segment in path:
            target = target[segment]
        target[field] = invalid
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(mutated)
