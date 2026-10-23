//! Public schemas generated from the reviewed protocol pin, never inferred
//! from service internals or populated with private custody fields.
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
    BUNDLE["schemas"].clone()
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
}
