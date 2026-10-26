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
    // The native owner and gateway omit absent optional membership fields.
    // Keep the protocol pin intact while reconciling this public readback.
    let membership = &mut schemas["schemas__organization"]["properties"]["membership"]["oneOf"][0];
    membership["required"]
        .as_array_mut()
        .expect("membership required fields")
        .retain(|name| name != "joined_at");
    membership["properties"]["roles"]["items"]["required"]
        .as_array_mut()
        .expect("role required fields")
        .retain(|name| name != "display_name");
    schemas["schemas__organization"]["x-marty-runtime-extension"] = json!(
        "Native organization readback omits absent membership joined_at and role display_name."
    );
    let readback: Value = serde_json::from_str(include_str!(
        "../../../../contracts/credential-template-readback-properties.json"
    ))
    .expect("native template readback schema");
    schemas["schemas__credential_template"]["properties"]
        .as_object_mut()
        .expect("template properties")
        .extend(readback.as_object().expect("readback properties").clone());
    schemas["schemas__credential_template"]["x-marty-runtime-extension"] = json!(
        "Native persisted configuration readback; extends the pinned protocol response. schema_uri writes are unsupported."
    );
    schemas["runtime__credential_template_validity_input"] = serde_json::from_str(include_str!(
        "../../../../contracts/credential-template-validity-input.json"
    ))
    .expect("native template validity input schema");
    let template_writes: Value = serde_json::from_str(include_str!(
        "../../../../contracts/credential-template-write-schemas.json"
    ))
    .expect("native template write schemas");
    schemas.as_object_mut().expect("schemas").extend(
        template_writes
            .as_object()
            .expect("template write schemas")
            .clone(),
    );
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
    schemas["runtime__protocol_support_catalog"] = serde_json::from_str(include_str!(
        "../../../../contracts/protocol-support-catalog-schema.json"
    ))
    .expect("protocol support catalog schema");
    let trust: Value = serde_json::from_str(include_str!(
        "../../../../contracts/trust-profile-readback-schemas.json"
    ))
    .expect("native trust readback schemas");
    schemas
        .as_object_mut()
        .expect("schemas")
        .extend(trust.as_object().expect("trust schemas").clone());
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
    let api_keys: Value = serde_json::from_str(include_str!(
        "../../../../contracts/api-key-http-schemas.json"
    ))
    .expect("native API-key HTTP schemas");
    schemas
        .as_object_mut()
        .expect("schemas")
        .extend(api_keys.as_object().expect("API-key schemas").clone());
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
    if path == "/v1/api-keys" || path == "/v1/api-keys/{key_id}" {
        describe_api_keys(operation, method, status);
        return;
    }
    if method == Get && path == "/v1/protocol-support" {
        operation["summary"] = json!("Discover product support for protocol abstractions");
        operation["description"] = json!(
            "Public gateway-owned catalog of product consumer surfaces. Implemented, derived, partial and unsupported are distinct; qualification state and limitations prevent route presence or protocol vocabulary from being presented as end-to-end support."
        );
        operation["responses"][status.to_string()]["content"] = json!({
            "application/json": {
                "schema": {"$ref":"#/components/schemas/runtime__protocol_support_catalog"},
                "example": serde_json::from_str::<Value>(include_str!("../../../../contracts/protocol-support-catalog.json")).expect("support catalog example")
            }
        });
        operation["x-marty-protocol-support"] = json!("implemented");
        operation["x-marty-request-schema-documented"] = json!(true);
        operation["x-marty-response-schema-documented"] = json!(true);
        return;
    }
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
        operation["description"] = json!(
            "Requires signing-key:view in the selected organization. Read-only current registry, managed signer and public HTTPS observations, including assertion authorization. Public resolution uses the deployment authority and no internal fallback. Assertion readiness does not qualify credential issuance, certificate trust or interoperability."
        );
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
        operation["description"] = json!(
            "Requires credential-template:create in the selected organization. Validates an active compliance profile and every declared credential format; no algorithm or private binding selector is accepted. Template creation repeats these checks."
        );
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
    if (method == Post && path == "/v1/credential-templates")
        || (method == Patch && path == "/v1/credential-templates/{template_id}")
    {
        let component = if method == Post { "create" } else { "update" };
        operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{
            "$ref":format!("#/components/schemas/runtime__credential_template_{component}_request")
        }}}});
        operation["description"] = json!(
            "Requires the existing tenant-scoped template write permission. Creation requires a public issuer DID, nonempty claims and a live compatible compliance/issuer binding; custody selectors are not public inputs. PATCH applies only to drafts, with null optional fields generally preserving stored values. Schema validation describes write DTOs, not authorization, readiness or successful issuance; native format/protocol, cross-claim and provider checks still apply."
        );
        operation["x-marty-request-schema-documented"] = json!(true);
        operation["x-marty-validity-rules-schema-documented"] = json!(true);
    }
    let template_response = (matches!(method, Get | Post) && path == "/v1/credential-templates")
        || (matches!(method, Get | Patch) && path == "/v1/credential-templates/{template_id}")
        || (method == Post && matches!(path, "/v1/credential-templates/{template_id}/activate"));
    if template_response && (200..300).contains(&status) {
        let response_schema = if method == Get && path == "/v1/credential-templates" {
            json!({"type":"array","items":schema("credential-template")})
        } else {
            schema("credential-template")
        };
        operation["responses"][status.to_string()]["content"] =
            json!({"application/json":{"schema":response_schema}});
        operation["x-marty-response-schema-documented"] = json!(true);
    }
    if method == Get
        && matches!(
            path,
            "/v1/organizations" | "/v1/organizations/discover" | "/v1/organizations/mine"
        )
    {
        describe_organization_collection(operation, path, status);
    }
    describe_trust_readback(operation, method, path, status);
}

fn describe_organization_collection(operation: &mut Value, path: &str, status: u16) {
    operation["responses"][status.to_string()]["content"] = json!({
        "application/json":{"schema":{"type":"array","items":schema("organization")}}
    });
    operation["x-marty-response-schema-documented"] = json!(true);
    operation["description"] = json!(match path {
        "/v1/organizations/mine" => "Organizations with memberships for the authenticated user. Returns an array without a total count. This route does not accept pagination or bootstrap an unauthenticated operator.",
        "/v1/organizations/discover" => "Active discoverable organizations, with optional discovery filters. Returns an array without a total count. Requires gateway authentication; this is not anonymous tenant bootstrap.",
        _ => "Organization collection exposed through the authenticated gateway. Returns an array without a total count. Discovery filters apply only to /v1/organizations/discover; this route uses limit and offset only."
    });
    if path == "/v1/organizations/mine" {
        return;
    }
    let mut parameters = vec![];
    for (name, default, description) in [
        ("limit", 100, "Requested page size; the native owner clamps values above 1000 to 1000. Zero is accepted."),
        ("offset", 0, "Number of organizations to skip."),
    ] {
        parameters.push(json!({
            "name":name,"in":"query","required":false,"description":description,
            "schema":{"type":"integer","minimum":0,"maximum":u32::MAX,"default":default}
        }));
    }
    if path == "/v1/organizations/discover" {
        let mut search = query_parameter("search", "Match organization name or display name.");
        search["required"] = json!(false);
        parameters.push(search);
        for name in ["org_type", "join_mechanism"] {
            parameters.push(json!({
                "name":name,"in":"query","required":false,
                "description": if name == "org_type" {
                    "Organization type, trimmed and case-insensitive. Canonical values are shown as examples; vendor aliases enterprise and nonprofit aliases individual. Unknown values are rejected."
                } else {
                    "Join mechanism, trimmed and case-insensitive. Supported canonical values are shown as examples. Unknown values are rejected."
                },
                "schema":{"type":"string","examples": BUNDLE["schemas"]["schemas__organization"]["properties"][name]["enum"]}
            }));
        }
    }
    operation["parameters"] = json!(parameters);
}

fn describe_trust_readback(operation: &mut Value, method: HttpMethod, path: &str, status: u16) {
    use HttpMethod::{Delete, Get, Patch, Post};
    let collection = path == "/v1/trust-profiles";
    let member = path == "/v1/trust-profiles/{profile_id}";
    let lifecycle = path == "/v1/trust-profiles/{profile_id}/activate";
    if !((collection && matches!(method, Get | Post))
        || (member && matches!(method, Get | Patch | Delete))
        || (lifecycle && method == Post))
    {
        return;
    }
    operation["description"] = json!("Native public trust-profile readback for an authorized organization. Optional fields are omitted, not returned as null. Public trust configuration does not prove issuer interoperability or successful verification. Private custody metadata fails closed; native authorization, trust and state validation remain authoritative.");
    operation["x-marty-protocol-schema-ref"] = schema("trust-profile");
    operation["x-marty-protocol-support"] = json!("partial");
    let response = if method == Delete {
        json!({"type":"object","additionalProperties":false,"required":["success"],"properties":{"success":{"const":true}}})
    } else if collection && method == Get {
        json!({"type":"array","items":{"$ref":"#/components/schemas/runtime__trust_profile_response"}})
    } else {
        json!({"$ref":"#/components/schemas/runtime__trust_profile_response"})
    };
    operation["responses"][status.to_string()]["content"] =
        json!({"application/json":{"schema":response}});
    operation["x-marty-response-schema-documented"] = json!(true);
    if method != Patch && !(collection && method == Post) {
        operation["x-marty-request-schema-documented"] = json!(true);
    }
    if collection && method == Get {
        operation["parameters"] = json!([
            query_parameter("organization_id", "Required authorized organization whose trust profiles are listed."),
            {"name":"limit","in":"query","required":false,"schema":{"type":"integer","minimum":0,"maximum":u64::MAX,"default":100},"description":"Unsigned 64-bit deployment page size. Zero is accepted; values above 500 are clamped to 500 by the native owner. Returns an array without a total count."},
            {"name":"offset","in":"query","required":false,"schema":{"type":"integer","minimum":0,"maximum":u64::MAX,"default":0},"description":"Number of organization profiles to skip."}
        ]);
    }
    if lifecycle {
        operation["description"] = json!(format!(
            "{} This lifecycle operation has no request body.",
            operation["description"].as_str().expect("description")
        ));
    }
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
    operation["description"] = json!(format!(
        "Requires compliance-profile:{action} in the resource's organization. System presets are migration-owned and immutable. Public metadata is a partial projection of the protocol entity; internal privacy enforcement sections are not returned."
    ));
    operation["x-marty-protocol-schema-ref"] = schema("compliance-profile");
    operation["x-marty-protocol-support"] = json!("partial");
    operation["x-marty-request-schema-documented"] = json!(true);
    operation["x-marty-response-schema-documented"] = json!(true);
    if method == Get && (collection || catalog) {
        operation["parameters"] = json!([query_parameter(
            "organization_id",
            "Selected authorized organization; even the shared catalog requires this view grant at the gateway."
        )]);
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
        operation["description"] = json!(format!(
            "{} The operation has no request body; the native owner changes only status and updated_at.",
            operation["description"].as_str().expect("description")
        ));
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
            let mut recipient = query_parameter(
                "recipient_id",
                "Recipient filter. Count and mark-all-read use the trusted authenticated user if omitted.",
            );
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
        (
            400,
            "Required organization query or recipient selector is missing or malformed.",
        ),
        (401, "Authentication required."),
        (
            403,
            "Organization membership or route permission is not authorized.",
        ),
        (
            404,
            "Notification does not exist in the selected organization.",
        ),
        (
            422,
            "Invalid request fields, target organization, channel, destination, TTL or protected credential payload.",
        ),
        (502, "Upstream returned an invalid response."),
        (
            503,
            "Notification or authorization dependency is unavailable.",
        ),
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

fn describe_api_keys(operation: &mut Value, method: HttpMethod, status: u16) {
    operation["summary"] = json!("Manage organization-bound machine API keys");
    operation["description"] = json!(
        "Requires the corresponding api-key:view, api-key:create or api-key:revoke permission. An organization-bound admin:full API key can manage keys within its own organization; ordinary credential scopes cannot. This API does not bootstrap an unauthenticated operator or accept OAuth access tokens. The secret key is returned only by creation."
    );
    if !operation["parameters"].is_array() {
        operation["parameters"] = json!([]);
    }
    let mut organization = query_parameter(
        "organization_id",
        "Authorized organization. May be omitted only when the authenticated identity already provides organization context.",
    );
    organization["required"] = json!(false);
    operation["parameters"]
        .as_array_mut()
        .unwrap()
        .push(organization);
    let response = match method {
        HttpMethod::Post => {
            operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":"#/components/schemas/runtime__api_key_create_request"}}}});
            json!({"$ref":"#/components/schemas/runtime__api_key_response"})
        }
        HttpMethod::Get => {
            operation["parameters"].as_array_mut().unwrap().extend([
                json!({"name":"limit","in":"query","schema":{"type":"integer","minimum":0,"maximum":500,"default":100}}),
                json!({"name":"offset","in":"query","schema":{"type":"integer","minimum":0,"default":0}}),
            ]);
            json!({"type":"array","items":{"$ref":"#/components/schemas/runtime__api_key_response"}})
        }
        HttpMethod::Delete => {
            json!({"type":"object","required":["success"],"properties":{"success":{"const":true}}})
        }
        _ => return,
    };
    operation["responses"][status.to_string()]["content"] =
        json!({"application/json":{"schema":response}});
    for (code, description) in [
        (
            400,
            "Invalid key scope, expiry or pagination, or malformed query.",
        ),
        (
            401,
            "Authentication required or API key invalid, expired or revoked.",
        ),
        (
            403,
            "Organization mismatch or required API-key management permission missing.",
        ),
        (404, "Organization or key not found."),
        (
            422,
            "JSON payload cannot be deserialized into the key creation request.",
        ),
        (503, "A required backend is unavailable."),
    ] {
        operation["responses"][code.to_string()] = json!({"description":description});
    }
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
        let mut did = query_parameter(
            "issuer_did",
            "Public DID selected for issuance. Marty resolves managed custody internally; the credential issuer must match this DID.",
        );
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
    #[test]
    fn api_key_operations_document_scoped_management_and_one_time_secret() {
        let document = crate::contract::GatewayContract::load()
            .unwrap()
            .openapi_document("test");
        let paths = &document["paths"];
        let create = &paths["/v1/api-keys"]["post"];
        assert_eq!(
            create["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/runtime__api_key_create_request"
        );
        assert_eq!(
            create["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/runtime__api_key_response"
        );
        assert_eq!(
            paths["/v1/api-keys"]["get"]["responses"]["200"]["content"]["application/json"]
                ["schema"]["type"],
            "array"
        );
        let revoke = &paths["/v1/api-keys/{key_id}"]["delete"];
        assert_eq!(revoke["parameters"][0]["name"], "key_id");
        assert_eq!(revoke["parameters"][1]["name"], "organization_id");
        assert_eq!(revoke["parameters"][1]["required"], false);
        assert_eq!(
            revoke["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
                ["success"]["const"],
            true
        );
        let schemas = &document["components"]["schemas"];
        assert_eq!(
            schemas["runtime__api_key_create_request"]["additionalProperties"],
            false
        );
        assert!(schemas["runtime__api_key_create_request"]["properties"]
            .get("organization_id")
            .is_none());
        assert_eq!(
            schemas["runtime__api_key_response"]["properties"]["key"]["readOnly"],
            true
        );
    }
    use super::*;
    #[test]
    fn organization_collections_document_native_arrays_and_query_boundaries() {
        let document = crate::contract::GatewayContract::load()
            .unwrap()
            .openapi_document("test");
        for path in [
            "/v1/organizations",
            "/v1/organizations/discover",
            "/v1/organizations/mine",
        ] {
            assert_eq!(
                crate::organization_contract::response_shape("GET", path),
                Some(true)
            );
            let operation = &document["paths"][path]["get"];
            assert_eq!(operation["x-marty-response-schema-documented"], true);
            assert!(operation.get("requestBody").is_none());
            assert_eq!(
                operation["responses"]["200"]["content"]["application/json"]["schema"],
                json!({"type":"array","items":{"$ref":"#/components/schemas/schemas__organization"}})
            );
            if path.ends_with("/mine") {
                assert!(operation.get("parameters").is_none());
            } else {
                let parameters = operation["parameters"].as_array().unwrap();
                assert_eq!(
                    parameters[0]["schema"],
                    json!({"type":"integer","minimum":0,"maximum":u32::MAX,"default":100})
                );
                assert_eq!(parameters[1]["schema"]["default"], 0);
                assert!(parameters
                    .iter()
                    .all(|parameter| parameter["required"] == false));
                assert_eq!(
                    parameters.len(),
                    if path.ends_with("/discover") { 5 } else { 2 }
                );
                if path.ends_with("/discover") {
                    assert_eq!(
                        parameters[3]["schema"]["examples"],
                        schemas()["schemas__organization"]["properties"]["org_type"]["enum"]
                    );
                    assert_eq!(
                        parameters[4]["schema"]["examples"],
                        schemas()["schemas__organization"]["properties"]["join_mechanism"]["enum"]
                    );
                }
            }
        }
        let schema = schemas();
        let membership = &schema["schemas__organization"]["properties"]["membership"]["oneOf"][0];
        assert_eq!(membership["additionalProperties"], false);
        assert!(!membership["required"]
            .as_array()
            .unwrap()
            .contains(&json!("joined_at")));
        assert_eq!(
            membership["properties"]["roles"]["items"]["required"],
            json!(["id", "name"])
        );
        // The immutable protocol bundle remains unchanged by runtime reconciliation.
        assert!(
            BUNDLE["schemas"]["schemas__organization"]["properties"]["membership"]["oneOf"][0]
                ["required"]
                .as_array()
                .unwrap()
                .contains(&json!("joined_at"))
        );
    }

    #[test]
    fn template_readback_schema_covers_native_response_operations() {
        let schemas = schemas();
        assert!(schemas["schemas__credential_template"]["properties"]["display_style"].is_object());
        assert!(schemas["schemas__credential_template"]["x-marty-runtime-extension"].is_string());
        for (method, path) in [
            (HttpMethod::Get, "/v1/credential-templates"),
            (HttpMethod::Post, "/v1/credential-templates"),
            (HttpMethod::Get, "/v1/credential-templates/{template_id}"),
            (HttpMethod::Patch, "/v1/credential-templates/{template_id}"),
            (
                HttpMethod::Post,
                "/v1/credential-templates/{template_id}/activate",
            ),
        ] {
            let mut operation = json!({});
            describe_operation(&mut operation, method, path, 200);
            assert_eq!(operation["x-marty-response-schema-documented"], true);
            if (method == HttpMethod::Post && path == "/v1/credential-templates")
                || method == HttpMethod::Patch
            {
                assert_eq!(operation["x-marty-request-schema-documented"], true);
                assert_eq!(operation["x-marty-validity-rules-schema-documented"], true);
                let reference = operation["requestBody"]["content"]["application/json"]["schema"]
                    ["$ref"]
                    .as_str()
                    .unwrap();
                let name = reference.strip_prefix("#/components/schemas/").unwrap();
                assert_eq!(
                    schemas[name]["properties"]["validity_rules"]["anyOf"][0]["$ref"],
                    "#/components/schemas/runtime__credential_template_validity_input"
                );
            }
        }
    }
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
    #[test]
    fn trust_readback_operations_use_native_components() {
        assert!(schemas()["runtime__trust_profile_response"].is_object());
        for (method, path) in [
            (HttpMethod::Get, "/v1/trust-profiles"),
            (HttpMethod::Post, "/v1/trust-profiles"),
            (HttpMethod::Get, "/v1/trust-profiles/{profile_id}"),
            (HttpMethod::Patch, "/v1/trust-profiles/{profile_id}"),
            (HttpMethod::Post, "/v1/trust-profiles/{profile_id}/activate"),
        ] {
            let mut op = json!({});
            describe_operation(&mut op, method, path, 200);
            assert_eq!(op["x-marty-response-schema-documented"], true);
            let response = &op["responses"]["200"]["content"]["application/json"]["schema"];
            let target = if method == HttpMethod::Get && path == "/v1/trust-profiles" {
                &response["items"]
            } else {
                response
            };
            assert_eq!(
                target["$ref"],
                "#/components/schemas/runtime__trust_profile_response"
            );
        }
    }
}
