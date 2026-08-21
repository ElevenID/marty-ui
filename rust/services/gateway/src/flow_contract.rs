use std::collections::BTreeSet;

use regex::Regex;
use serde_json::{json, Map, Value};

#[derive(Debug)]
pub struct FlowContractError;

#[derive(Clone, Copy)]
pub enum FlowResponseKind {
    Definition,
    Instance,
    VerificationResult,
}

const FLOW_TYPES: &[&str] = &[
    "oid4vci_pre_authorized",
    "oid4vci_authorization_code",
    "mdl_issuance",
    "oid4vp_presentation",
    "mdl_presentation",
    "siopv2",
    "application_approval_issuance",
    "credential_renewal",
    "credential_revocation",
    "physical_document_issuance",
    "combined",
    "custom",
];
const PRIVATE_CONTEXT_KEYS: &[&str] = &[
    "issuer_profile_id",
    "issuer_key_id",
    "issuer_algorithm",
    "key_access_mode",
    "verification_method_id",
    "signing_service_id",
    "signing_key_reference",
    "key_reference",
    "kms_provider",
    "provider",
    "key_name",
    "key_version",
    "transit_mount",
    "pre_auth_code",
    "pre_authorized_code",
    "pre-authorized-code",
    "access_token",
    "refresh_token",
    "client_secret",
    "private_key",
    "private_key_jwk",
    "session_token",
    "api_key",
];

pub fn canonicalize_definition(body: &[u8], update: bool) -> Result<Value, FlowContractError> {
    const FIELDS: &[&str] = &[
        "organization_id",
        "name",
        "description",
        "flow_type",
        "approval_strategy",
        "hooks",
        "trigger",
        "extension",
        "trust_profile_id",
        "credential_template_id",
        "application_template_id",
        "presentation_policy_id",
        "delivery_destination_profile_id",
        "deployment_profile_ids",
    ];
    let mut value = parse_object(body, FIELDS)?;
    required_string(&value, "organization_id", 1, 255)?;
    if update {
        if value.len() == 1 {
            return Err(FlowContractError);
        }
        if value.contains_key("name") && !value["name"].is_null() {
            required_string(&value, "name", 1, 255)?;
        }
    } else {
        required_string(&value, "name", 1, 255)?;
        required_enum(&value, "flow_type", FLOW_TYPES)?;
        value.entry("description").or_insert(Value::Null);
        value.entry("approval_strategy").or_insert(json!("AUTO"));
        value.entry("hooks").or_insert_with(|| json!({}));
        value.entry("trigger").or_insert(Value::Null);
        value.entry("extension").or_insert(Value::Null);
        for field in [
            "trust_profile_id",
            "credential_template_id",
            "application_template_id",
            "presentation_policy_id",
            "delivery_destination_profile_id",
        ] {
            value.entry(field).or_insert(Value::Null);
        }
        value
            .entry("deployment_profile_ids")
            .or_insert_with(|| json!([]));
    }
    optional_string(&value, "description", 2000)?;
    optional_enum(&value, "flow_type", FLOW_TYPES)?;
    optional_enum(
        &value,
        "approval_strategy",
        &["AUTO", "MANUAL", "RULES_BASED", "EXTERNAL"],
    )?;
    for field in [
        "trust_profile_id",
        "credential_template_id",
        "application_template_id",
        "presentation_policy_id",
        "delivery_destination_profile_id",
    ] {
        optional_string(&value, field, usize::MAX)?;
    }
    if let Some(hooks) = value.get_mut("hooks").filter(|entry| !entry.is_null()) {
        canonical_hooks(hooks)?;
    }
    if let Some(trigger) = value.get_mut("trigger").filter(|entry| !entry.is_null()) {
        *trigger = canonical_trigger(trigger.take())?;
    }
    if let Some(extension) = value.get_mut("extension").filter(|entry| !entry.is_null()) {
        *extension = canonical_extension(extension.take())?;
    }
    validate_string_array(value.get("deployment_profile_ids"), true)?;
    let flow_type = value.get("flow_type").and_then(Value::as_str);
    let has_extension = value.get("extension").is_some_and(|entry| !entry.is_null());
    if !update && ((flow_type == Some("custom")) != has_extension) {
        return Err(FlowContractError);
    }
    Ok(Value::Object(value))
}

pub fn canonicalize_instance(body: &[u8]) -> Result<Value, FlowContractError> {
    let mut value = parse_object(
        body,
        &[
            "organization_id",
            "flow_definition_id",
            "subject_id",
            "subject_type",
            "external_reference",
            "initial_context",
        ],
    )?;
    required_string(&value, "organization_id", 1, 255)?;
    required_string(&value, "flow_definition_id", 1, 255)?;
    value.entry("subject_id").or_insert(Value::Null);
    value.entry("subject_type").or_insert(json!("applicant"));
    value.entry("external_reference").or_insert(Value::Null);
    value.entry("initial_context").or_insert_with(|| json!({}));
    optional_string(&value, "subject_id", usize::MAX)?;
    required_string(&value, "subject_type", 0, usize::MAX)?;
    optional_string(&value, "external_reference", usize::MAX)?;
    let context = value
        .get("initial_context")
        .filter(|entry| entry.is_object())
        .ok_or(FlowContractError)?;
    if contains_private_context(context) {
        return Err(FlowContractError);
    }
    Ok(Value::Object(value))
}

pub fn definition_references(value: &Value) -> Vec<(&'static str, String)> {
    [
        ("credential_template_id", "credential-templates"),
        ("application_template_id", "application-templates"),
        ("presentation_policy_id", "presentation-policies"),
        ("delivery_destination_profile_id", "delivery-destinations"),
        ("trust_profile_id", "trust-profiles"),
    ]
    .into_iter()
    .filter_map(|(field, kind)| {
        value
            .get(field)
            .and_then(Value::as_str)
            .map(|id| (kind, id.to_owned()))
    })
    .collect()
}

pub fn project_response(value: Value, kind: FlowResponseKind) -> Result<Value, FlowContractError> {
    if let Value::Array(items) = value {
        return items
            .into_iter()
            .map(|item| project_one(item, kind))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    project_one(value, kind)
}

pub fn response_route(method: &str, path: &str) -> Option<FlowResponseKind> {
    if path == "/v1/flows/definitions" && matches!(method, "GET" | "POST") {
        return Some(FlowResponseKind::Definition);
    }
    if let Some(tail) = path.strip_prefix("/v1/flows/definitions/") {
        let segments = tail.split('/').collect::<Vec<_>>();
        if (segments.len() == 1 && matches!(method, "GET" | "PATCH"))
            || (segments.len() == 2 && segments[1] == "activate" && method == "POST")
        {
            return Some(FlowResponseKind::Definition);
        }
    }
    if path == "/v1/flows/instances" && matches!(method, "GET" | "POST") {
        return Some(FlowResponseKind::Instance);
    }
    if let Some(tail) = path.strip_prefix("/v1/flows/instances/") {
        let segments = tail.split('/').collect::<Vec<_>>();
        if (segments.len() == 1 && method == "GET")
            || (segments.len() == 2
                && matches!(segments[1], "advance" | "cancel")
                && method == "POST")
        {
            return Some(FlowResponseKind::Instance);
        }
        if segments.len() == 2 && segments[1] == "result" && method == "GET" {
            return Some(FlowResponseKind::VerificationResult);
        }
    }
    None
}

fn project_one(value: Value, kind: FlowResponseKind) -> Result<Value, FlowContractError> {
    match kind {
        FlowResponseKind::Definition => project_definition(value),
        FlowResponseKind::Instance => project_instance(value),
        FlowResponseKind::VerificationResult => project_verification_result(value),
    }
}

fn project_definition(value: Value) -> Result<Value, FlowContractError> {
    const FIELDS: &[&str] = &[
        "id",
        "organization_id",
        "name",
        "description",
        "status",
        "flow_type",
        "flow_category",
        "resolved_steps",
        "extension",
        "trust_profile_id",
        "credential_template_id",
        "application_template_id",
        "presentation_policy_id",
        "delivery_destination_profile_id",
        "approval_strategy",
        "hooks",
        "trigger",
        "deployment_profile_ids",
        "version",
        "created_at",
        "updated_at",
    ];
    let mut value = strict_object(value, FIELDS)?;
    for field in ["id", "organization_id", "name", "created_at", "updated_at"] {
        required_string(&value, field, 0, usize::MAX)?;
    }
    required_enum(&value, "status", &["DRAFT", "ACTIVE", "PAUSED", "ARCHIVED"])?;
    required_enum(&value, "flow_type", FLOW_TYPES)?;
    required_enum(
        &value,
        "flow_category",
        &[
            "ISSUANCE",
            "VERIFICATION",
            "RENEWAL",
            "REVOCATION",
            "COMBINED",
        ],
    )?;
    required_enum(
        &value,
        "approval_strategy",
        &["AUTO", "MANUAL", "RULES_BASED", "EXTERNAL"],
    )?;
    validate_string_array(value.get("resolved_steps"), false)?;
    validate_string_array(value.get("deployment_profile_ids"), true)?;
    if let Some(extension) = value.get("extension").filter(|entry| !entry.is_null()) {
        if !extension.is_object() {
            return Err(FlowContractError);
        }
    }
    if let Some(trigger) = value.get("trigger").filter(|entry| !entry.is_null()) {
        if !trigger.is_object() {
            return Err(FlowContractError);
        }
    }
    let hooks = value
        .get("hooks")
        .filter(|entry| entry.is_object())
        .unwrap_or(&Value::Null);
    if !hooks.is_null()
        && hooks.as_object().is_some_and(|hooks| {
            hooks.values().any(|entries| {
                entries
                    .as_array()
                    .is_none_or(|entries| entries.iter().any(|entry| !entry.is_object()))
            })
        })
    {
        return Err(FlowContractError);
    }
    if !value.get("version").is_some_and(Value::is_i64) {
        return Err(FlowContractError);
    }
    value.entry("hooks").or_insert_with(|| json!({}));
    value
        .entry("deployment_profile_ids")
        .or_insert_with(|| json!([]));
    omit_nulls(&mut value);
    Ok(Value::Object(value))
}

fn project_instance(value: Value) -> Result<Value, FlowContractError> {
    const FIELDS: &[&str] = &[
        "id",
        "flow_id",
        "flow_type",
        "organization_id",
        "status",
        "current_step",
        "current_step_index",
        "context_data",
        "step_results",
        "issued_credential_id",
        "started_at",
        "completed_at",
        "expires_at",
        "error_code",
        "metadata",
        "state_history",
        "created_at",
        "updated_at",
    ];
    let mut value = strict_object(value, FIELDS)?;
    for field in ["id", "organization_id", "created_at", "updated_at"] {
        required_string(&value, field, 0, usize::MAX)?;
    }
    optional_enum(&value, "flow_type", FLOW_TYPES)?;
    required_enum(
        &value,
        "status",
        &[
            "PENDING",
            "IN_PROGRESS",
            "AWAITING_APPROVAL",
            "AWAITING_WALLET",
            "AWAITING_EVIDENCE",
            "COMPLETED",
            "FAILED",
            "EXPIRED",
            "CANCELLED",
        ],
    )?;
    for field in ["flow_id", "flow_type"] {
        let Some(entry) = value.get(field) else {
            return Err(FlowContractError);
        };
        if !entry.is_null() && !entry.is_string() {
            return Err(FlowContractError);
        }
    }
    for field in ["context_data", "step_results", "metadata"] {
        let entry = value
            .get(field)
            .filter(|entry| entry.is_object())
            .ok_or(FlowContractError)?;
        if contains_private_context(entry) {
            return Err(FlowContractError);
        }
    }
    if value["step_results"]
        .as_object()
        .is_some_and(|results| results.values().any(|result| !result.is_object()))
    {
        return Err(FlowContractError);
    }
    let history = value
        .get("state_history")
        .and_then(Value::as_array)
        .ok_or(FlowContractError)?;
    if history.iter().any(|entry| !entry.is_object()) {
        return Err(FlowContractError);
    }
    if contains_private_context(&Value::Array(history.clone())) {
        return Err(FlowContractError);
    }
    omit_nulls(&mut value);
    Ok(Value::Object(value))
}

fn project_verification_result(value: Value) -> Result<Value, FlowContractError> {
    const FIELDS: &[&str] = &[
        "instance_id",
        "status",
        "result",
        "decision",
        "decision_reason",
        "verified_claims",
        "credential_results",
        "error_codes",
        "warnings",
        "evaluation_timestamp",
    ];
    let mut value = strict_object(value, FIELDS)?;
    required_string(&value, "instance_id", 0, usize::MAX)?;
    required_enum(
        &value,
        "status",
        &[
            "PENDING",
            "IN_PROGRESS",
            "AWAITING_APPROVAL",
            "AWAITING_WALLET",
            "AWAITING_EVIDENCE",
            "COMPLETED",
            "FAILED",
            "EXPIRED",
            "CANCELLED",
        ],
    )?;
    if !value.get("verified_claims").is_some_and(Value::is_object) {
        return Err(FlowContractError);
    }
    value
        .entry("credential_results")
        .or_insert_with(|| json!([]));
    value.entry("error_codes").or_insert_with(|| json!([]));
    value.entry("warnings").or_insert_with(|| json!([]));
    let results = value["credential_results"]
        .as_array_mut()
        .ok_or(FlowContractError)?;
    for result in results {
        *result = project_credential_result(result.take())?;
    }
    validate_string_array(value.get("error_codes"), true)?;
    validate_string_array(value.get("warnings"), true)?;
    omit_nulls(&mut value);
    Ok(Value::Object(value))
}

fn project_credential_result(value: Value) -> Result<Value, FlowContractError> {
    let mut value = strict_object(
        value,
        &[
            "credential_template_id",
            "satisfied",
            "issuer_did",
            "claim_results",
            "trust_check_passed",
            "freshness_check_passed",
            "signature_valid",
            "revocation_checked",
            "not_revoked",
            "revocation_status",
            "error_codes",
            "errors",
            "warnings",
        ],
    )?;
    required_string(&value, "credential_template_id", 0, usize::MAX)?;
    required_bool(&value, "satisfied")?;
    optional_string(&value, "issuer_did", usize::MAX)?;
    optional_string(&value, "revocation_status", usize::MAX)?;
    value.entry("claim_results").or_insert_with(|| json!([]));
    value.entry("trust_check_passed").or_insert(json!(true));
    value.entry("freshness_check_passed").or_insert(json!(true));
    value.entry("signature_valid").or_insert(json!(true));
    for field in [
        "trust_check_passed",
        "freshness_check_passed",
        "signature_valid",
    ] {
        required_bool(&value, field)?;
    }
    for field in ["revocation_checked", "not_revoked"] {
        if value
            .get(field)
            .is_some_and(|entry| !entry.is_null() && !entry.is_boolean())
        {
            return Err(FlowContractError);
        }
    }
    for field in ["error_codes", "errors", "warnings"] {
        value.entry(field).or_insert_with(|| json!([]));
        validate_string_array(value.get(field), true)?;
    }
    let claims = value["claim_results"]
        .as_array_mut()
        .ok_or(FlowContractError)?;
    for claim in claims {
        *claim = project_claim_result(claim.take())?;
    }
    omit_nulls(&mut value);
    Ok(Value::Object(value))
}

fn project_claim_result(value: Value) -> Result<Value, FlowContractError> {
    let mut value = strict_object(
        value,
        &["claim_name", "satisfied", "presented_value", "error"],
    )?;
    required_string(&value, "claim_name", 0, usize::MAX)?;
    required_bool(&value, "satisfied")?;
    optional_string(&value, "error", usize::MAX)?;
    omit_nulls(&mut value);
    Ok(Value::Object(value))
}

fn canonical_hooks(value: &mut Value) -> Result<(), FlowContractError> {
    let hooks = value.as_object_mut().ok_or(FlowContractError)?;
    for entries in hooks.values_mut() {
        let entries = entries.as_array_mut().ok_or(FlowContractError)?;
        for entry in entries {
            let mut hook = object(entry.take(), &["hook_type", "url", "config"])?;
            required_enum(&hook, "hook_type", &["WEBHOOK", "EXTERNAL_API", "SCRIPT"])?;
            optional_string(&hook, "url", usize::MAX)?;
            hook.entry("config").or_insert_with(|| json!({}));
            if !hook["config"].is_object() {
                return Err(FlowContractError);
            }
            *entry = Value::Object(hook);
        }
    }
    Ok(())
}

fn canonical_trigger(value: Value) -> Result<Value, FlowContractError> {
    let mut value = object(value, &["trigger_type", "config"])?;
    required_enum(
        &value,
        "trigger_type",
        &["API_CALL", "WEBHOOK", "SCHEDULE", "APPLICATION_SUBMITTED"],
    )?;
    value.entry("config").or_insert_with(|| json!({}));
    if !value["config"].is_object() {
        return Err(FlowContractError);
    }
    Ok(Value::Object(value))
}

fn canonical_extension(value: Value) -> Result<Value, FlowContractError> {
    let mut value = object(
        value,
        &[
            "extension_uri",
            "extension_version",
            "extends_flow_type",
            "entry_step_id",
            "steps",
            "transitions",
            "config",
        ],
    )?;
    for field in [
        "extension_uri",
        "extension_version",
        "extends_flow_type",
        "entry_step_id",
    ] {
        required_string(&value, field, 0, usize::MAX)?;
    }
    let steps = value
        .get_mut("steps")
        .and_then(Value::as_array_mut)
        .filter(|steps| !steps.is_empty())
        .ok_or(FlowContractError)?;
    let step_pattern = Regex::new(r"^[a-z][a-z0-9_-]*$").expect("step regex");
    let action_pattern = Regex::new(r"^[a-z][a-z0-9_.:-]*$").expect("action regex");
    for step in steps {
        let mut item = object(
            step.take(),
            &[
                "step_id",
                "action",
                "description",
                "config",
                "timeout_seconds",
            ],
        )?;
        let step_id = required_string(&item, "step_id", 0, 128)?;
        let action = required_string(&item, "action", 0, 160)?;
        if !step_pattern.is_match(step_id) || !action_pattern.is_match(action) {
            return Err(FlowContractError);
        }
        optional_string(&item, "description", 512)?;
        item.entry("config").or_insert_with(|| json!({}));
        if let Some(timeout) = item.get("timeout_seconds").filter(|entry| !entry.is_null()) {
            if timeout
                .as_u64()
                .is_none_or(|timeout| !(1..=86_400).contains(&timeout))
            {
                return Err(FlowContractError);
            }
        }
        *step = Value::Object(item);
    }
    value.entry("transitions").or_insert_with(|| json!([]));
    value.entry("config").or_insert_with(|| json!({}));
    let transitions = value["transitions"]
        .as_array_mut()
        .ok_or(FlowContractError)?;
    for transition in transitions {
        let item = object(
            transition.take(),
            &["from_step_id", "to_step_id", "outcome", "condition"],
        )?;
        required_string(&item, "from_step_id", 0, usize::MAX)?;
        required_string(&item, "to_step_id", 0, usize::MAX)?;
        required_enum(
            &item,
            "outcome",
            &[
                "SUCCESS", "FAILURE", "APPROVED", "REJECTED", "TIMEOUT", "CUSTOM",
            ],
        )?;
        if item
            .get("condition")
            .is_some_and(|condition| !condition.is_null() && !condition.is_object())
        {
            return Err(FlowContractError);
        }
        *transition = Value::Object(item);
    }
    if !value["config"].is_object() {
        return Err(FlowContractError);
    }
    Ok(Value::Object(value))
}

fn contains_private_context(value: &Value) -> bool {
    match value {
        Value::Object(entries) => entries.iter().any(|(key, value)| {
            PRIVATE_CONTEXT_KEYS.contains(&key.to_lowercase().as_str())
                || contains_private_context(value)
        }),
        Value::Array(entries) => entries.iter().any(contains_private_context),
        _ => false,
    }
}

fn parse_object(body: &[u8], allowed: &[&str]) -> Result<Map<String, Value>, FlowContractError> {
    object(
        serde_json::from_slice(body).map_err(|_| FlowContractError)?,
        allowed,
    )
}

fn object(value: Value, allowed: &[&str]) -> Result<Map<String, Value>, FlowContractError> {
    let value = value.as_object().cloned().ok_or(FlowContractError)?;
    if value.keys().any(|field| !allowed.contains(&field.as_str())) {
        return Err(FlowContractError);
    }
    Ok(value)
}

fn strict_object(value: Value, allowed: &[&str]) -> Result<Map<String, Value>, FlowContractError> {
    let value = value.as_object().ok_or(FlowContractError)?;
    Ok(value
        .iter()
        .filter(|(field, _)| allowed.contains(&field.as_str()))
        .map(|(field, value)| (field.clone(), value.clone()))
        .collect())
}

fn required_string<'a>(
    value: &'a Map<String, Value>,
    field: &str,
    min: usize,
    max: usize,
) -> Result<&'a str, FlowContractError> {
    let entry = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(FlowContractError)?;
    let len = entry.chars().count();
    if len < min || len > max {
        return Err(FlowContractError);
    }
    Ok(entry)
}

fn optional_string(
    value: &Map<String, Value>,
    field: &str,
    max: usize,
) -> Result<(), FlowContractError> {
    if let Some(entry) = value.get(field).filter(|entry| !entry.is_null()) {
        if entry
            .as_str()
            .is_none_or(|entry| entry.chars().count() > max)
        {
            return Err(FlowContractError);
        }
    }
    Ok(())
}

fn required_bool(value: &Map<String, Value>, field: &str) -> Result<(), FlowContractError> {
    value
        .get(field)
        .filter(|entry| entry.is_boolean())
        .map(|_| ())
        .ok_or(FlowContractError)
}

fn required_enum(
    value: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
) -> Result<(), FlowContractError> {
    if value
        .get(field)
        .and_then(Value::as_str)
        .is_none_or(|entry| !allowed.contains(&entry))
    {
        return Err(FlowContractError);
    }
    Ok(())
}

fn optional_enum(
    value: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
) -> Result<(), FlowContractError> {
    if let Some(entry) = value.get(field).filter(|entry| !entry.is_null()) {
        if entry.as_str().is_none_or(|entry| !allowed.contains(&entry)) {
            return Err(FlowContractError);
        }
    }
    Ok(())
}

fn validate_string_array(
    value: Option<&Value>,
    allow_missing: bool,
) -> Result<(), FlowContractError> {
    let Some(value) = value else {
        return if allow_missing {
            Ok(())
        } else {
            Err(FlowContractError)
        };
    };
    if value.is_null() && allow_missing {
        return Ok(());
    }
    if value
        .as_array()
        .is_none_or(|items| items.iter().any(|item| !item.is_string()))
    {
        return Err(FlowContractError);
    }
    Ok(())
}

fn omit_nulls(value: &mut Map<String, Value>) {
    let fields = value
        .iter()
        .filter(|(_, entry)| entry.is_null())
        .map(|(field, _)| field.clone())
        .collect::<BTreeSet<_>>();
    for field in fields {
        value.remove(&field);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        definition_create_input: Value,
        expected_definition_create: Value,
        definition_update_input: Value,
        expected_definition_update: Value,
        instance_create_input: Value,
        expected_instance_create: Value,
        invalid_instance: Value,
        internal_definition: Value,
        expected_definition: Value,
        internal_instance: Value,
        expected_instance: Value,
        internal_verification_result: Value,
        expected_verification_result: Value,
    }

    #[test]
    fn language_neutral_flow_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-flow-behavior.json"
        ))
        .expect("flow contract");
        assert_eq!(contract.schema_version, 1);
        assert_eq!(
            canonicalize_definition(
                &serde_json::to_vec(&contract.definition_create_input).expect("fixture"),
                false
            )
            .expect("create"),
            contract.expected_definition_create
        );
        assert_eq!(
            canonicalize_definition(
                &serde_json::to_vec(&contract.definition_update_input).expect("fixture"),
                true
            )
            .expect("update"),
            contract.expected_definition_update
        );
        assert_eq!(
            canonicalize_instance(
                &serde_json::to_vec(&contract.instance_create_input).expect("fixture")
            )
            .expect("instance"),
            contract.expected_instance_create
        );
        assert!(canonicalize_instance(
            &serde_json::to_vec(&contract.invalid_instance).expect("fixture")
        )
        .is_err());
        assert_eq!(
            project_response(contract.internal_definition, FlowResponseKind::Definition)
                .expect("definition"),
            contract.expected_definition
        );
        assert_eq!(
            project_response(contract.internal_instance, FlowResponseKind::Instance)
                .expect("instance"),
            contract.expected_instance
        );
        assert_eq!(
            project_response(
                contract.internal_verification_result,
                FlowResponseKind::VerificationResult,
            )
            .expect("verification result"),
            contract.expected_verification_result
        );
    }
}
