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
    # Production operation bindings only; Rust tests also contain deliberately
    # absent legacy paths that must not become advertised operations.
    source = (ROOT / "rust/services/gateway/src/openapi.rs").read_text().split("#[cfg(test)]", 1)[0]
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


def test_native_compliance_schemas_match_http_bound_examples_and_reject_nested_drift():
    schemas = json.loads((ROOT / "contracts/compliance-profile-http-schemas.json").read_text())
    examples = json.loads((ROOT / "contracts/compliance-profile-http-examples.json").read_text())
    for value, key in ((examples["create"], "create_request"), (examples["response"], "response")):
        jsonschema.Draft202012Validator(schemas["runtime__compliance_profile_" + key]).validate(value)
    patch = jsonschema.Draft202012Validator(schemas["runtime__compliance_profile_update_request"])
    for value in ({"name": "Renamed"}, {"description": ""}, {"discoverable": False}, {"age_verification": None}):
        patch.validate(value)
    response = jsonschema.Draft202012Validator(schemas["runtime__compliance_profile_response"])
    for value in ({"status": "ACTIVE"}, {"organization_id": "foreign"}, {"issuer_artifact_requirements": {"kms_key_id": "private"}}, {"trust_profile_constraints": {"required_formats": [9]}}):
        with pytest.raises(jsonschema.ValidationError):
            patch.validate(value)
    for field in ("frameworks", "data_retention", "consent_requirement", "audit_configuration", "data_minimization_rules", "jurisdictional_constraints", "age_verification"):
        value = deepcopy(examples["response"])
        value[field] = {}
        with pytest.raises(jsonschema.ValidationError):
            response.validate(value)
    value = deepcopy(examples["response"])
    value["api_surface"][0]["standard_ref"] = {"private_key": "secret"}
    with pytest.raises(jsonschema.ValidationError):
        response.validate(value)


def test_derived_wallet_schema_matches_owner_example_and_rejects_nested_drift():
    schema = json.loads((ROOT / "contracts/wallet-compatibility-response.json").read_text())
    value = json.loads((ROOT / "contracts/wallet-compatibility-example.json").read_text())
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    validator.validate(value)
    override = {
        **value, "id": "override-1", "organization_id": "org-1", "is_override": True,
        "override_precedence": 85, "merge_strategy": "REPLACE", "applied_override_ids": ["override-1"],
        "template_wallet_configs": [{"wallet_id": "wallet-1", "deep_link_scheme": "campus://", "format_variant": "dc+sd-jwt"}],
    }
    validator.validate(override)
    for path, field, invalid in [
        ([], "verified", True),
        ([], "wallet_apps", [17]),
        ([], "merge_strategy", "MERGE"),
        ([], "organization_id", None),
        ([], "updated_at", "not-a-time"),
        (["derived_from"], "key_reference", "private"),
        (["template_wallet_configs", 0], "signing_service_id", "private"),
        (["template_wallet_configs", 0], "deep_link_scheme", None),
    ]:
        mutated = deepcopy(override)
        target = mutated
        for segment in path:
            target = target[segment]
        target[field] = invalid
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(mutated)


def test_notification_http_schemas_match_native_examples_and_embedded_target_boundaries():
    schemas = json.loads((ROOT / "contracts/notification-http-schemas.json").read_text())
    examples = json.loads((ROOT / "contracts/notification-http-examples.json").read_text())
    for key, schema in [("send", "runtime__notification_send_request"), ("response", "runtime__notification_response")]:
        validator = jsonschema.Draft202012Validator(schemas[schema], format_checker=jsonschema.FormatChecker())
        validator.validate(examples[key])
        for path, field, invalid in [
            ([], "kms_key_id", "private"), (["target"], "unknown", True),
            (["target"], "device_tokens", [17]),
        ]:
            value = deepcopy(examples[key])
            cursor = value
            for segment in path:
                cursor = cursor[segment]
            cursor[field] = invalid
            with pytest.raises(jsonschema.ValidationError):
                validator.validate(value)
    response = jsonschema.Draft202012Validator(schemas["runtime__notification_response"])
    for field, invalid in [("read", "false"), ("status", "VERIFIED"), ("target", {"channels": ["UNKNOWN"]})]:
        with pytest.raises(jsonschema.ValidationError):
            response.validate({**examples["response"], field: invalid})
    request = jsonschema.Draft202012Validator(schemas["runtime__notification_send_request"])
    request.validate({"organization_id": "org-a", "target": {"channels": ["sse"]}})
    delivery = jsonschema.Draft202012Validator(schemas["runtime__notification_delivery_result"])
    delivery.validate({"notification_id": "notification-1", "channel": "SSE", "success": False, "attempted_at": examples["response"]["created_at"], "should_retry": True})
    with pytest.raises(jsonschema.ValidationError):
        delivery.validate({"notification_id": "notification-1", "channel": "SSE", "success": "true"})


def test_protocol_support_catalog_is_strict_and_bound_to_real_api_and_ui_routes():
    schema = json.loads(
        (ROOT / "contracts/protocol-support-catalog-schema.json").read_text()
    )
    catalog = json.loads(
        (ROOT / "contracts/protocol-support-catalog.json").read_text()
    )
    jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    ).validate(catalog)
    assert catalog["protocol_revision"] == json.loads(
        (ROOT / "contracts/gateway-public-openapi-schemas.json").read_text()
    )["protocol_revision"]
    routes = {
        route["path"]
        for route in json.loads(
            (ROOT / "contracts/gateway-routes.json").read_text()
        )["routes"]
    }
    console = (ROOT / "ui/src/apps/console/ConsoleRoutes.jsx").read_text()
    ids = set()
    for entity in catalog["entities"]:
        assert entity["id"] not in ids
        ids.add(entity["id"])
        assert set(entity["api_paths"]) <= routes
        for ui_path in entity["ui_paths"]:
            if ui_path.startswith("/console/org/"):
                expected = f'path="{ui_path.removeprefix("/console/org/")}"'
            elif ui_path.startswith("/console/applicant/"):
                expected = f'path="{ui_path.removeprefix("/console/applicant/")}"'
            else:
                expected = f'path="{ui_path}"'
            assert expected in console, (entity["id"], ui_path)
    assert ids == {
        "applicant",
        "application-template",
        "authorization-decision-receipt",
        "compliance-profile",
        "credential-template",
        "delivery-destination-profile",
        "deployment-profile",
        "device-registration",
        "didcomm-delivery",
        "flow-definition",
        "flow-execution",
        "issued-credential",
        "issuer-entity",
        "issuer-identity",
        "key-attestation-policy",
        "machine-authentication-policy",
        "machine-identity",
        "notification",
        "notification-target",
        "organization",
        "organization-trust-profile",
        "policy-set",
        "presentation-policy",
        "revocation-profile",
        "scim",
        "subscription",
        "trust-framework",
        "trust-profile",
        "trust-profile-issuer",
        "trust-registry",
        "verification-decision-result",
        "wallet-profile",
        "wallet-registry",
    }
    assert {
        "machine-identity",
        "machine-authentication-policy",
        "authorization-decision-receipt",
    } == {
        entity["id"]
        for entity in catalog["entities"]
        if entity["support_level"] == "unsupported"
    }


def test_protocol_support_schema_rejects_false_unsupported_and_extra_claims():
    schema = json.loads(
        (ROOT / "contracts/protocol-support-catalog-schema.json").read_text()
    )
    catalog = json.loads(
        (ROOT / "contracts/protocol-support-catalog.json").read_text()
    )
    validator = jsonschema.Draft202012Validator(schema)
    machine = next(
        entity for entity in catalog["entities"] if entity["id"] == "machine-identity"
    )
    for field, value in [
        ("api_paths", ["/v1/machine-identities"]),
        ("ui_paths", ["/console/org/machines"]),
        ("schema_refs", ["#/components/schemas/schemas__machine_identity"]),
        ("owner_service", "machines"),
    ]:
        mutated = deepcopy(catalog)
        target = next(
            entity
            for entity in mutated["entities"]
            if entity["id"] == machine["id"]
        )
        target[field] = value
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(mutated)
    mutated = deepcopy(catalog)
    mutated["entities"][0]["release_ready"] = True
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(mutated)


def test_ai_consumer_page_uses_gateway_discovery_instead_of_unverified_cli_claims():
    page = (ROOT / "ui/src/components/pages/AiCapabilityPage.jsx").read_text()
    docs = (ROOT / "ui/src/components/ApiDocumentation.jsx").read_text()
    assert '/v1/protocol-support' in page
    assert '/openapi.json' in page
    assert 'href="/v1/protocol-support"' in docs
    assert 'href="/openapi.json"' in docs
    assert 'href="/redoc"' in docs
    assert 'localhost:8000/docs' not in docs
    for unverified_claim in (
        '@elevenid/marty-cli',
        'marty verify start',
        'marty creds issue',
        'All commands support',
        'primary interface for AI agents',
    ):
        assert unverified_claim not in page


def test_native_template_validity_extension_covers_days_and_input_aliases():
    properties = json.loads((ROOT / "contracts/credential-template-readback-properties.json").read_text())
    schema = properties["validity_rules"]
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate({"default_validity_days": 2, "max_validity_days": 1095,
                        "renewal_window_days": 0, "renewable": True,
                        "not_before_offset_seconds": -900, "require_revalidation": False,
                        "revalidation_interval_days": None})
    validator.validate({"ttl_seconds": 86401, "default_validity_days": 9})
    for invalid in [{"ttl_seconds": 0}, {"ttl_seconds": 1.5},
                    {"not_before_offset_seconds": 2147483648}, {"private_key": "secret"}]:
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(invalid)
    assert "override" in schema["description"]
    assert "whole-day" in schema["description"]
