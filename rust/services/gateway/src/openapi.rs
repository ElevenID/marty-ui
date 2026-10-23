//! Public protocol components from the reviewed pin, with operation metadata
//! reconciled against the gateway's public handlers. No private custody fields.
use mmf_platform::HttpMethod;
use serde_json::{json, Value};
use std::sync::LazyLock;

static BUNDLE: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "../../../../contracts/gateway-public-openapi-schemas.json"
    ))
    .expect("generated public protocol schemas")
});

pub fn schemas() -> Value {
    let mut schemas = BUNDLE["schemas"].clone();
    schemas["runtime__issuer_identity_capabilities"] = serde_json::from_str(include_str!(
        "../../../../contracts/issuer-identity-capabilities-response.json"
    ))
    .expect("public identity capabilities schema");
    schemas["runtime__template_issuer_options_request"] = serde_json::from_str(include_str!(
        "../../../../contracts/template-issuer-options-request.json"
    ))
    .expect("template issuer options request schema");
    schemas["runtime__template_issuer_options_response"] = serde_json::from_str(include_str!(
        "../../../../contracts/template-issuer-options-response.json"
    ))
    .expect("template issuer options response schema");
    schemas
}
pub fn protocol_revision() -> &'static str {
    BUNDLE["protocol_revision"].as_str().expect("protocol pin")
}

fn schema(name: &str) -> Value {
    let key = format!("schemas__{}", name.replace('-', "_"));
    assert!(
        BUNDLE["schemas"].get(&key).is_some(),
        "unknown public protocol schema: {name}"
    );
    json!({"$ref":format!("#/components/schemas/{key}")})
}

pub fn describe_operation(operation: &mut Value, method: HttpMethod, path: &str, status: u16) {
    use HttpMethod::{Get, Patch, Post};
    if method == Post && path == "/v1/credential-templates/issuer-options" {
        operation["summary"] = json!("Discover compatible, unambiguous template issuer DIDs");
        operation["description"] = json!("Requires credential-template:create in the selected organization. Validates an active compliance profile and every declared credential format; no algorithm or private binding selector is accepted. Template creation repeats these checks.");
        operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/runtime__template_issuer_options_request"}}}});
        for (status, description) in [
            (401, "Authentication required."),
            (403, "Organization or permission is not authorized."),
            (409, "Issuer inventory is ambiguous."),
            (
                422,
                "Invalid, inactive or incompatible template dependencies.",
            ),
            (502, "A dependency returned an invalid binding."),
            (
                503,
                "A required dependency is unavailable; no cached or default choices are returned.",
            ),
        ] {
            operation["responses"][status.to_string()] = json!({"description":description});
        }
        operation["responses"]["200"]["content"] = json!({"application/json":{"schema":{"$ref":"#/components/schemas/runtime__template_issuer_options_response"}}});
        operation["x-marty-request-schema-documented"] = json!(true);
        operation["x-marty-response-schema-documented"] = json!(true);
        return;
    }
    if method == Get && path == "/v1/signing-keys/issuer-identities/capabilities" {
        operation["summary"] = json!("Discover organization issuer identity creation options");
        operation["parameters"] = json!([query_parameter(
            "organization_id",
            "Organization authorized by the gateway; no provider or key selector is accepted."
        )]);
        operation["responses"]["200"]["content"] = json!({"application/json":{"schema":{"$ref":"#/components/schemas/runtime__issuer_identity_capabilities"}}});
        operation["responses"]["401"] = json!({"description":"Authentication required."});
        operation["responses"]["400"] =
            json!({"description":"Malformed or unsupported query parameters."});
        operation["responses"]["403"] = json!({"description":"Organization membership and signing-key:view permission required."});
        operation["responses"]["422"] =
            json!({"description":"Organization scope is blank or invalid."});
        operation["responses"]["503"] = json!({"description":"Issuer capability discovery is unavailable; do not assume a default set."});
        operation["x-marty-request-schema-documented"] = json!(true);
        operation["x-marty-response-schema-documented"] = json!(true);
        return;
    }
    if method == Post
        && matches!(
            path,
            "/v1/vc-api/credentials/issue"
                | "/v1/vc-api/credentials/verify"
                | "/v1/vc-api/presentations/verify"
        )
    {
        describe_vc_api(operation, path, status);
        return;
    }
    if method == Get
        && matches!(
            path,
            "/v1/credential-templates"
                | "/v1/trust-profiles"
                | "/v1/presentation-policies"
                | "/v1/compliance-profiles"
        )
    {
        operation["parameters"] = json!([query_parameter(
            "organization_id",
            "Authorized organization whose resources are listed."
        )]);
    }
    let request = match (method, path) {
        (Post, "/v1/organizations") => Some("organization-create-request"),
        (Patch, "/v1/organizations/{org_id}") => Some("organization-update-request"),
        (Post, "/v1/issuer-entities") => Some("issuer-entity-create-request"),
        (Patch, "/v1/issuer-entities/{issuer_entity_id}") => Some("issuer-entity-update-request"),
        (Post, "/v1/signing-keys/issuer-identities") => Some("issuer-identity-create-request"),
        (Post, "/v1/presentation-policies") => Some("presentation-policy-create-request"),
        (Patch, "/v1/presentation-policies/{policy_id}") => {
            Some("presentation-policy-update-request")
        }
        (Post, "/v1/flows/definitions") => Some("flow-create-request"),
        (Patch, "/v1/flows/definitions/{flow_id}") => Some("flow-update-request"),
        _ => None,
    };
    let response = match (method, path) {
        (Get, "/v1/organizations/{org_id}")
        | (Post, "/v1/organizations")
        | (Patch, "/v1/organizations/{org_id}") => Some("organization"),
        (Get, "/v1/issuer-entities/{issuer_entity_id}")
        | (Post, "/v1/issuer-entities")
        | (Patch, "/v1/issuer-entities/{issuer_entity_id}") => Some("issuer-entity"),
        (Get, "/v1/signing-keys/issuer-identities") => Some("issuer-identity-list-response"),
        (Post, "/v1/signing-keys/issuer-identities") => Some("issuer-identity-create-response"),
        (Get, "/v1/trust-profiles/{profile_id}") => Some("trust-profile"),
        (Get, "/v1/credential-templates/{template_id}") => Some("credential-template"),
        (Get, "/v1/presentation-policies/{policy_id}")
        | (Post, "/v1/presentation-policies")
        | (Patch, "/v1/presentation-policies/{policy_id}") => Some("presentation-policy"),
        (Get, "/v1/flows/definitions/{flow_id}")
        | (Post, "/v1/flows/definitions")
        | (Patch, "/v1/flows/definitions/{flow_id}") => Some("flow"),
        _ => None,
    };
    if let Some(name) = request {
        operation["requestBody"] =
            json!({"required":true,"content":{"application/json":{"schema":schema(name)}}});
    }
    if let Some(name) = response {
        operation["responses"][status.to_string()]["content"] =
            json!({"application/json":{"schema":schema(name)}});
    }
    // Coverage is explicit while remaining service-owned shapes are reconciled.
    operation["x-marty-request-schema-documented"] = json!(request.is_some());
    operation["x-marty-response-schema-documented"] = json!(response.is_some());
}

fn query_parameter(name: &str, description: &str) -> Value {
    json!({"name":name,"in":"query","required":true,"description":description,"schema":{"type":"string","minLength":1}})
}

fn describe_vc_api(operation: &mut Value, path: &str, status: u16) {
    let issue = path.ends_with("/issue");
    let field = if issue {
        "credential"
    } else if path.contains("/presentations/") {
        "verifiablePresentation"
    } else {
        "verifiableCredential"
    };
    let mut parameters = vec![query_parameter(
        "organization_id",
        "Must match the authenticated organization scope.",
    )];
    if issue {
        parameters.push(query_parameter(
            "credential_template_id",
            "Authorized active template defining credential claims, compliance and lifecycle.",
        ));
        let mut did = query_parameter("issuer_did", "Public DID selected for issuance. Marty resolves managed custody internally; the credential issuer must match this DID.");
        did["schema"]["pattern"] = json!("^did:");
        parameters.push(did);
    } else {
        parameters.push(query_parameter(
            "presentation_policy_id",
            "Authorized presentation policy governing credential verification.",
        ));
    }
    operation["parameters"] = json!(parameters);
    let mut properties = serde_json::Map::new();
    properties.insert(
        field.into(),
        if issue {
            json!({"type":"object","description":"Unsigned credential document matching the selected template and issuer DID."})
        } else {
            json!({"oneOf":[{"type":"string","minLength":1},{"type":"object"}],"description":"Signed token, native Data Integrity document, or supported VCDM envelope. Signature and policy checks determine acceptance."})
        },
    );
    if !issue {
        properties.insert("options".into(), json!({"type":"object","properties":{"challenge":{"type":"string"},"domain":{"type":"string"}}}));
    }
    operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"type":"object","required":[field],"properties":properties}}}});
    let success = if issue {
        json!({"type":"object","required":["verifiableCredential"],"properties":{"verifiableCredential":{"type":"object","description":"Issued native Data Integrity credential."}}})
    } else {
        json!({"type":"object","required":["verified","results","problemDetails"],"properties":{"verified":{"const":true},"results":{"type":"object"},"problemDetails":{"type":"array"}}})
    };
    operation["responses"][status.to_string()]["content"] =
        json!({"application/json":{"schema":success}});
    operation["responses"]["401"] = json!({"description":"Authentication is required."});
    operation["responses"]["403"] = json!({"description":"The caller is not authorized for the selected organization or resource."});
    operation["responses"]["413"] =
        json!({"description":"Request body exceeds the configured limit."});
    operation["responses"]["422"] = if issue {
        json!({"description":"Invalid input, issuer mismatch, or incompatible template/identity."})
    } else {
        // The handler also forwards upstream error bodies. Do not constrain
        // every error to the adapter's own rejection response.
        json!({"description":"Invalid input or verification/policy rejection. Upstream service errors are forwarded. A rejected verification is not a successful verified result.","content":{"application/json":{"examples":{"verificationRejected":{"value":{"verified":false,"errors":["verification_failed"]}},"invalidInput":{"value":{"detail":"verifiableCredential is required"}}}}}})
    };
    operation["responses"]["502"] =
        json!({"description":"A required upstream service returned unavailable or invalid data."});
    operation["x-marty-request-schema-documented"] = json!(true);
    operation["x-marty-response-schema-documented"] = json!(true);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn schema_bundle_refs_are_self_contained_and_pin_is_exact() {
        let document = json!({"components":{"schemas":schemas()}});
        fn check(value: &Value, document: &Value) {
            match value {
                Value::Object(object) => {
                    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                        let pointer = reference.strip_prefix('#').expect("local schema ref");
                        assert!(
                            document.pointer(pointer).is_some(),
                            "unresolved ref: {reference}"
                        );
                    }
                    for child in object.values() {
                        check(child, document);
                    }
                }
                Value::Array(values) => {
                    for child in values {
                        check(child, document);
                    }
                }
                _ => {}
            }
        }
        check(&document, &document);
        assert_eq!(protocol_revision().len(), 40);
    }

    #[test]
    fn vc_api_operations_publish_runtime_scope_fields_and_rejection_status() {
        let document = crate::contract::GatewayContract::load()
            .expect("gateway contract")
            .openapi_document("test");
        for (path, field, selection) in [
            (
                "/v1/vc-api/credentials/issue",
                "credential",
                "credential_template_id",
            ),
            (
                "/v1/vc-api/credentials/verify",
                "verifiableCredential",
                "presentation_policy_id",
            ),
            (
                "/v1/vc-api/presentations/verify",
                "verifiablePresentation",
                "presentation_policy_id",
            ),
        ] {
            let operation = &document["paths"][path]["post"];
            let parameters = operation["parameters"]
                .as_array()
                .expect("query parameters");
            for name in ["organization_id", selection] {
                assert!(
                    parameters.iter().any(|parameter| {
                        parameter["name"] == name
                            && parameter["in"] == "query"
                            && parameter["required"] == true
                    }),
                    "missing scope/selection for {path}"
                );
            }
            let request = &operation["requestBody"]["content"]["application/json"]["schema"];
            assert_eq!(request["required"], json!([field]));
            assert!(request["properties"][field].is_object());
            assert!(operation["responses"]["403"].is_object());
            assert!(operation["responses"]["422"].is_object());
            assert_eq!(operation["security"][1], json!({"apiKeyAuth": []}));
            if field == "credential" {
                let did = parameters
                    .iter()
                    .find(|parameter| parameter["name"] == "issuer_did")
                    .expect("public issuer DID");
                assert_eq!(did["schema"]["pattern"], "^did:");
                assert_eq!(
                    operation["responses"]["200"]["content"]["application/json"]["schema"]
                        ["properties"]["verifiableCredential"]["type"],
                    "object"
                );
            } else {
                assert_eq!(
                    operation["responses"]["200"]["content"]["application/json"]["schema"]
                        ["properties"]["verified"]["const"],
                    true
                );
                assert_eq!(
                    operation["responses"]["422"]["content"]["application/json"]["examples"]
                        ["verificationRejected"]["value"]["verified"],
                    false
                );
            }
        }
    }
}
