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
    schemas["runtime__issuer_identity_inspection"] = serde_json::from_str(include_str!(
        "../../../../contracts/issuer-identity-inspection-response.json"
    ))
    .expect("public identity inspection schema");
    schemas["runtime__wallet_compatibility"] = serde_json::from_str(include_str!(
        "../../../../contracts/wallet-compatibility-response.json"
    ))
    .expect("native derived wallet compatibility schema");
    let compliance: Value = serde_json::from_str(include_str!(
        "../../../../contracts/compliance-profile-http-schemas.json"
    ))
    .expect("native compliance HTTP schemas");
    schemas
        .as_object_mut()
        .expect("schemas")
        .extend(compliance.as_object().expect("compliance schemas").clone());
    let notification: Value = serde_json::from_str(include_str!(
        "../../../../contracts/notification-http-schemas.json"
    ))
    .expect("native notification HTTP schemas");
    schemas.as_object_mut().expect("schemas").extend(
        notification
            .as_object()
            .expect("notification schemas")
            .clone(),
    );
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
    if path.starts_with("/v1/notifications") && path != "/v1/notifications/events/push" {
        describe_notification(operation, method, path, status);
        return;
    }
    if method == Get
        && matches!(
            path,
            "/v1/credential-templates/{template_id}/wallet-compatibility"
                | "/v1/wallet-registry/resolve/profile"
        )
    {
        let template = path.ends_with("/wallet-compatibility");
        operation["summary"] = json!("Read derived wallet requirements and applied overrides");
        operation["description"] = json!(if template {
            "Requires credential-template:view in the owning template's organization. Resolves only the primary credential format, issuance protocol and compliance key, plus matching registry overrides. Additional declared formats are not covered by this response. Physical documents have no wallet profile. Configuration only: wallet applications, platforms and specifications are not independently verified interoperability or delivery evidence."
        } else {
            "Requires wallet:view in the selected organization. Derives configuration from the supplied tuple plus matching organization registry overrides; it does not load or validate a credential template. Unknown tuples may return generic fallback requirements. Physical documents have no wallet profile. Registry entries and derived wallet names do not prove interoperability or successful delivery."
        });
        if !template {
            let mut parameters: Vec<Value> =
                ["organization_id", "credential_format", "issuance_protocol"]
                    .map(|name| {
                        query_parameter(
                            name,
                            "Derivation input in the selected authorized organization.",
                        )
                    })
                    .into();
            let mut code = query_parameter(
                "compliance_profile_code",
                "Optional compliance derivation key; not a template ID.",
            );
            code["required"] = json!(false);
            parameters.push(code);
            operation["parameters"] = json!(parameters);
        }
        for (code, description) in [
            (400, "Malformed or missing query parameters."),
            (401, "Authentication required."),
            (
                403,
                "Selected organization membership and route permission required.",
            ),
            (404, "Credential template or resource owner not found."),
            (
                422,
                "Invalid template configuration or physical document; no wallet profile applies.",
            ),
            (502, "Required upstream returned an invalid response."),
            (
                503,
                "Template, registry or authorization dependency unavailable.",
            ),
        ] {
            operation["responses"][code.to_string()] = json!({"description":description});
        }
        operation["responses"]["200"]["content"] = json!({"application/json":{"schema":{"$ref":"#/components/schemas/runtime__wallet_compatibility"},"example":serde_json::from_str::<Value>(include_str!("../../../../contracts/wallet-compatibility-example.json")).expect("wallet example")}});
        operation["x-marty-protocol-support"] = json!("derived");
        operation["x-marty-protocol-schema"] = schema("wallet-profile");
        operation["x-marty-request-schema-documented"] = json!(true);
        operation["x-marty-response-schema-documented"] = json!(true);
        return;
    }
    if matches!(
        path,
        "/v1/compliance-profiles"
            | "/v1/compliance-profiles/{profile_id}"
            | "/v1/compliance-profiles/{profile_id}/activate"
            | "/v1/compliance-profiles/{profile_id}/suspend"
            | "/v1/compliance-profiles/system/discoverable"
    ) {
        describe_compliance(operation, method, path, status);
        return;
    }
    if method == Get && path == "/v1/signing-keys/issuer-identities/inspection" {
        operation["summary"] = json!("Inspect DID publication and managed signer matching");
        operation["description"] = json!("Requires signing-key:view in the selected organization. Read-only current registry, managed signer and public HTTPS observations, including assertion authorization. Public resolution uses the deployment authority and no internal fallback. Assertion readiness does not qualify credential issuance, certificate trust or interoperability.");
        operation["parameters"] = json!(["organization_id", "issuer_did", "key_purpose", "credential_format", "algorithm"].map(|name| query_parameter(name, "Exact public identity tuple in the authorized organization; no private custody selector.")));
        for (code, description) in [
            (400, "Missing, malformed or unsupported query fields."),
            (401, "Authentication required."),
            (
                403,
                "Organization membership and signing-key:view permission required.",
            ),
            (404, "No active identity matches this public tuple."),
            (409, "Identity tuple is ambiguous."),
            (422, "Invalid public identity tuple."),
            (502, "Stored DID document is malformed."),
            (503, "Identity registry or document storage is unavailable."),
        ] {
            operation["responses"][code.to_string()] = json!({"description":description});
        }
        operation["responses"]["200"]["content"] = json!({"application/json":{"schema":{"$ref":"#/components/schemas/runtime__issuer_identity_inspection"}}});
        operation["x-marty-request-schema-documented"] = json!(true);
        operation["x-marty-response-schema-documented"] = json!(true);
        return;
    }
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

fn describe_compliance(operation: &mut Value, method: HttpMethod, path: &str, status: u16) {
    use HttpMethod::{Delete, Get, Patch, Post};
    let collection = path == "/v1/compliance-profiles";
    let catalog = path == "/v1/compliance-profiles/system/discoverable";
    let action = match method {
        Get => "view",
        Post if path.ends_with("/activate") => "activate",
        Post if path.ends_with("/suspend") => "suspend",
        Post => "create",
        Patch => "edit",
        Delete => "delete",
        _ => return,
    };
    operation["description"] = json!(format!("Requires compliance-profile:{action} in the resource's organization. System presets are migration-owned and immutable. Public metadata is a partial projection of the protocol entity; internal privacy enforcement sections are not returned."));
    operation["x-marty-protocol-schema-ref"] = schema("compliance-profile");
    operation["x-marty-protocol-support"] = json!("partial");
    operation["x-marty-request-schema-documented"] = json!(true);
    operation["x-marty-response-schema-documented"] = json!(true);
    if method == Get && (collection || catalog) {
        operation["parameters"] = json!([query_parameter("organization_id", "Selected authorized organization; even the shared catalog requires this view grant at the gateway.")]);
        if catalog {
            operation["parameters"][0]["required"] = json!(false);
        }
        if collection {
            operation["parameters"].as_array_mut().expect("parameters").extend([
                json!({"name":"limit","in":"query","schema":{"type":"integer","minimum":1,"maximum":500,"default":100}}),
                json!({"name":"offset","in":"query","schema":{"type":"integer","minimum":0,"default":0}}),
            ]);
        }
    }
    if (method == Post && collection) || method == Patch {
        let request = if method == Patch {
            "runtime__compliance_profile_update_request"
        } else {
            "runtime__compliance_profile_create_request"
        };
        operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{request}")}}}});
    }
    let response = if method == Delete {
        json!({"type":"object","additionalProperties":false,"required":["success"],"properties":{"success":{"const":true}}})
    } else if method == Get && (collection || catalog) {
        json!({"type":"array","items":{"$ref":"#/components/schemas/runtime__compliance_profile_response"}})
    } else {
        json!({"$ref":"#/components/schemas/runtime__compliance_profile_response"})
    };
    operation["responses"][status.to_string()]["content"] =
        json!({"application/json":{"schema":response}});
    for (code, description) in [
        (
            400,
            "Profile constraints or query values are invalid; no partial mutation is saved.",
        ),
        (401, "Authentication required."),
        (
            403,
            "Organization or action is not authorized, or a system preset cannot be mutated.",
        ),
        (404, "Profile not found."),
        (409, "The native owner reports a resource conflict."),
        (
            422,
            "JSON fields or enum values do not match the native request DTO.",
        ),
        (
            500,
            "The native profile storage is unavailable; backend details are not returned.",
        ),
        (502, "The native organization dependency is unavailable."),
        (
            503,
            "The gateway cannot reach or authorize a required service.",
        ),
    ] {
        operation["responses"][code.to_string()] = json!({"description":description});
    }
    if method == Post && !collection {
        operation["description"] = json!(format!("{} The operation has no request body; the native owner changes only status and updated_at.",operation["description"].as_str().expect("description")));
    }
}

fn describe_notification(operation: &mut Value, method: HttpMethod, path: &str, status: u16) {
    use HttpMethod::{Delete, Post};
    let send = method == Post && path == "/v1/notifications/send";
    let collection = path == "/v1/notifications";
    let count = matches!(
        path,
        "/v1/notifications/unread/count" | "/v1/notifications/unread-count"
    );
    let read_all = path == "/v1/notifications/read-all";
    let templates = path == "/v1/notifications/templates";
    let deliveries = path.ends_with("/delivery-results");
    operation["summary"] = json!(if send {
        "Send a notification with an embedded target"
    } else {
        "Read or update organization-scoped notifications"
    });
    operation["description"] = json!(if send {
        "Requires notification:send in the request organization. NotificationTarget is embedded, not a standalone saved profile. An explicit target organization must match the request organization. Channel and destination configuration determine delivery; acceptance does not prove delivery. Protected credential material and unknown root/target fields are rejected."
    } else {
        "Requires notification:view. An organization query selector is required even for stored IDs. Lists are arrays without total counts. List recipient filtering is explicit; unread count and mark-all-read default to the trusted authenticated user when recipient_id is omitted. Alert-rule and preference operations do not exist."
    });
    if send {
        operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/runtime__notification_send_request"}}}});
    } else {
        let mut parameters = operation["parameters"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        parameters.push(query_parameter(
            "organization_id",
            "Selected organization authorized by the gateway and native owner.",
        ));
        if collection || count || read_all {
            let mut recipient = query_parameter("recipient_id", "Recipient filter. Count and mark-all-read use the trusted authenticated user if omitted.");
            recipient["required"] = json!(false);
            parameters.push(recipient);
        }
        if collection || templates || deliveries {
            for (name, default) in [("limit", 100), ("offset", 0)] {
                parameters.push(json!({"name":name,"in":"query","required":false,"description":"Array pagination; limits above 500 are clamped. No total count is returned.","schema":{"type":"integer","minimum":0,"default":default}}));
            }
        }
        if collection {
            parameters.push(json!({"name":"unread_only","in":"query","required":false,"schema":{"type":"boolean","default":false}}));
            parameters.push(json!({"name":"status","in":"query","required":false,"description":"Case-insensitive pending, sent, delivered or failed state filter.","schema":{"type":"string"}}));
        }
        operation["parameters"] = json!(parameters);
    }
    let response_ref = json!({"$ref":"#/components/schemas/runtime__notification_response"});
    let response = if collection {
        json!({"type":"array","items":response_ref})
    } else if deliveries {
        json!({"type":"array","items":{"$ref":"#/components/schemas/runtime__notification_delivery_result"}})
    } else if count || read_all {
        let field = if count { "count" } else { "marked_read" };
        json!({"type":"object","additionalProperties":false,"required":[field],"properties":{field:{"type":"integer","minimum":0}}})
    } else if templates {
        json!({"type":"array","items":{"type":"object","additionalProperties":false,"required":["id","name","notification_type","subject_template","active"],"properties":{"id":{"type":"string"},"name":{"type":"string"},"notification_type":{"type":"string"},"subject_template":{"type":"string"},"active":{"type":"boolean"}}}})
    } else if method == Delete && !path.ends_with("/read") {
        json!({"type":"object","additionalProperties":false,"required":["success"],"properties":{"success":{"type":"boolean"}}})
    } else {
        response_ref
    };
    operation["responses"][status.to_string()]["content"] =
        json!({"application/json":{"schema":response}});
    for (code, description) in [
        (400, "Required organization query or recipient selector is missing or malformed."),
        (401, "Authentication required."), (403, "Organization membership or route permission is not authorized."),
        (404, "Notification does not exist in the selected organization."),
        (422, "Invalid request fields, target organization, channel, destination, TTL or protected credential payload."),
        (502, "Upstream returned an invalid response."), (503, "Notification or authorization dependency is unavailable."),
    ] {
        operation["responses"][code.to_string()] = json!({"description":description});
    }
    operation["x-marty-protocol-support"] = json!("partial");
    operation["x-marty-protocol-schemas"] = json!([
        schema("notification-payload"),
        schema("notification-target"),
        schema("notification-delivery-result")
    ]);
    operation["x-marty-request-schema-documented"] = json!(true);
    operation["x-marty-response-schema-documented"] = json!(true);
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
    #[test]
    fn notification_operations_document_real_scope_arrays_embedded_targets_and_delivery_evidence() {
        let document = crate::contract::GatewayContract::load()
            .unwrap()
            .openapi_document("test");
        for (path, method) in [
            ("/v1/notifications", "get"),
            ("/v1/notifications/send", "post"),
            ("/v1/notifications/unread/count", "get"),
            ("/v1/notifications/read-all", "post"),
            ("/v1/notifications/{notification_id}/read", "patch"),
            ("/v1/notifications/{notification_id}/read", "delete"),
            (
                "/v1/notifications/{notification_id}/delivery-results",
                "get",
            ),
        ] {
            let operation = &document["paths"][path][method];
            assert_eq!(operation["x-marty-protocol-support"], "partial");
            assert_eq!(operation["x-marty-request-schema-documented"], true);
            assert_eq!(operation["x-marty-response-schema-documented"], true);
            assert!(operation["responses"]["403"].is_object());
            if path != "/v1/notifications/send" {
                assert!(operation["parameters"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|parameter| parameter["name"] == "organization_id"
                        && parameter["required"] == true));
            }
        }
        let send = &document["paths"]["/v1/notifications/send"]["post"];
        assert_eq!(
            send["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/runtime__notification_send_request"
        );
        assert_eq!(
            document["paths"]["/v1/notifications"]["get"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["type"],
            "array"
        );
        assert_eq!(
            document["paths"]["/v1/notifications/unread/count"]["get"]["responses"]["200"]
                ["content"]["application/json"]["schema"]["properties"]["count"]["type"],
            "integer"
        );
        assert_eq!(
            document["paths"]["/v1/notifications/read-all"]["post"]["responses"]["200"]["content"]
                ["application/json"]["schema"]["properties"]["marked_read"]["type"],
            "integer"
        );
        assert!(document["components"]["schemas"]["schemas__notification_target"].is_object());
        assert_eq!(
            document["components"]["schemas"]["runtime__notification_response"]["properties"]
                ["read"]["type"],
            "boolean"
        );
        assert!(document["paths"]
            .get("/v1/notifications/{subpath:path}")
            .is_none());
        assert!(document["paths"]
            .get("/v1/notifications/preferences")
            .is_none());
    }

    #[test]
    fn wallet_requirements_document_native_projection_and_derived_scope() {
        let document = crate::contract::GatewayContract::load()
            .unwrap()
            .openapi_document("test");
        for path in [
            "/v1/credential-templates/{template_id}/wallet-compatibility",
            "/v1/wallet-registry/resolve/profile",
        ] {
            let operation = &document["paths"][path]["get"];
            assert_eq!(operation["x-marty-protocol-support"], "derived");
            assert_eq!(
                operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
                "#/components/schemas/runtime__wallet_compatibility"
            );
            assert!(operation.get("requestBody").is_none());
            assert!(operation["responses"]["403"].is_object());
            assert!(operation["responses"]["422"].is_object());
        }
        let parameters = document["paths"]["/v1/wallet-registry/resolve/profile"]["get"]
            ["parameters"]
            .as_array()
            .unwrap();
        for name in ["organization_id", "credential_format", "issuance_protocol"] {
            assert!(parameters
                .iter()
                .any(|parameter| parameter["name"] == name && parameter["required"] == true));
        }
        assert!(parameters
            .iter()
            .any(|parameter| parameter["name"] == "compliance_profile_code"
                && parameter["required"] == false));
        let response = &document["components"]["schemas"]["runtime__wallet_compatibility"];
        assert_eq!(response["additionalProperties"], false);
        assert_eq!(
            response["properties"]["derived_from"]["additionalProperties"],
            false
        );
        assert_eq!(
            response["properties"]["template_wallet_configs"]["items"]["additionalProperties"],
            false
        );
        assert!(response["properties"].get("verified").is_none());
    }

    #[test]
    fn compliance_http_operations_use_actual_owner_schemas_and_explicit_partial_support() {
        let document = crate::contract::GatewayContract::load()
            .unwrap()
            .openapi_document("test");
        for (path, methods) in [
            ("/v1/compliance-profiles", vec!["get", "post"]),
            (
                "/v1/compliance-profiles/{profile_id}",
                vec!["get", "patch", "delete"],
            ),
            (
                "/v1/compliance-profiles/{profile_id}/activate",
                vec!["post"],
            ),
            ("/v1/compliance-profiles/{profile_id}/suspend", vec!["post"]),
            ("/v1/compliance-profiles/system/discoverable", vec!["get"]),
        ] {
            for method in methods {
                let operation = &document["paths"][path][method];
                assert_eq!(operation["x-marty-protocol-support"], "partial");
                assert_eq!(operation["x-marty-response-schema-documented"], true);
                assert!(operation["security"][0].is_object());
                assert!(operation["responses"]["403"].is_object());
                assert!(operation["responses"]["422"].is_object());
            }
        }
        assert_eq!(
            document["paths"]["/v1/compliance-profiles"]["post"]["requestBody"]["content"]
                ["application/json"]["schema"]["$ref"],
            "#/components/schemas/runtime__compliance_profile_create_request"
        );
        assert_eq!(
            document["paths"]["/v1/compliance-profiles/{profile_id}"]["patch"]["requestBody"]
                ["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/runtime__compliance_profile_update_request"
        );
        let response = &document["components"]["schemas"]["runtime__compliance_profile_response"];
        assert_eq!(response["additionalProperties"], false);
        assert!(response["properties"].get("data_retention").is_none());
        assert_eq!(
            response["properties"]["api_surface"]["items"]["additionalProperties"],
            false
        );
    }
}
