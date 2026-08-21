use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

#[derive(Debug)]
pub struct TrustContractError;

#[derive(Clone, Copy)]
pub enum ResponseKind {
    TrustProfile,
    RegistrySync,
    IssuerEntity,
    TrustProfileIssuer,
}

const ISSUER_CREATE_FIELDS: &[&str] = &[
    "organization_id",
    "issuer_id",
    "issuer_type",
    "display_name",
    "description",
    "compliance_status",
    "accreditation_body",
    "accreditations",
    "accreditation_date",
    "valid_from",
    "valid_until",
    "trust_anchor_id",
    "metadata",
];
const TRUST_PROFILE_FIELDS: &[&str] = &[
    "organization_id",
    "name",
    "description",
    "profile_type",
    "compliance_status",
    "trust_sources",
    "validation_rules",
    "allowed_algorithms",
    "min_key_size_rsa",
    "min_key_size_ec",
    "require_key_usage",
    "max_chain_depth",
    "allow_self_signed",
    "revocation_policy",
    "revocation_profile_id",
    "time_policy",
    "supported_formats",
    "allowed_issuers",
    "denied_issuers",
    "system_issuer_overrides",
    "compatible_compliance_codes",
    "verification_policy_set_id",
    "auto_generated",
];
const TRUST_PROFILE_UPDATE_FIELDS: &[&str] = &[
    "name",
    "description",
    "profile_type",
    "compliance_status",
    "trust_sources",
    "validation_rules",
    "allowed_algorithms",
    "min_key_size_rsa",
    "min_key_size_ec",
    "require_key_usage",
    "max_chain_depth",
    "allow_self_signed",
    "revocation_policy",
    "revocation_profile_id",
    "time_policy",
    "supported_formats",
    "allowed_issuers",
    "denied_issuers",
    "system_issuer_overrides",
    "compatible_compliance_codes",
    "verification_policy_set_id",
    "auto_generated",
];
const ISSUER_UPDATE_FIELDS: &[&str] = &[
    "organization_id",
    "display_name",
    "description",
    "issuer_type",
    "compliance_status",
    "accreditation_body",
    "accreditations",
    "accreditation_date",
    "valid_from",
    "valid_until",
    "trust_anchor_id",
    "metadata",
    "revocation_reason",
];
const RELATIONSHIP_FIELDS: &[&str] = &[
    "issuer_id",
    "trust_level",
    "relationship_status",
    "cascade_revocation_policy",
    "metadata",
];
const RELATIONSHIP_UPDATE_FIELDS: &[&str] = &[
    "trust_level",
    "relationship_status",
    "cascade_revocation_policy",
    "metadata",
];
const PRIVATE_CUSTODY_FIELDS: &[&str] = &[
    "issuer_algorithm",
    "issuer_profile_id",
    "issuer_key_id",
    "key_access_mode",
    "key_binding",
    "key_management",
    "key_name",
    "key_reference",
    "key_version",
    "kms_arn",
    "kms_provider",
    "kms_region",
    "managed_key_id",
    "provider",
    "service_id",
    "signing_agent_auth",
    "signing_agent_url",
    "signing_key_reference",
    "signing_service_id",
    "transit_mount",
    "verification_method_id",
];
const PRIVATE_JWK_FIELDS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

pub fn canonicalize_request(
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Option<Vec<u8>>, TrustContractError> {
    let operation = request_operation(method, path);
    let Some(operation) = operation else {
        return Ok(None);
    };
    let value = serde_json::from_slice::<Value>(body).map_err(|_| TrustContractError)?;
    let canonical = match operation {
        RequestOperation::TrustProfileCreate => canonicalize_trust_profile(value, false)?,
        RequestOperation::TrustProfileUpdate => canonicalize_trust_profile(value, true)?,
        RequestOperation::IssuerCreate => canonicalize_issuer_create(value)?,
        RequestOperation::IssuerUpdate => canonicalize_issuer_update(value)?,
        RequestOperation::RelationshipCreate => canonicalize_relationship_create(value)?,
        RequestOperation::RelationshipUpdate => canonicalize_relationship_update(value)?,
    };
    serde_json::to_vec(&canonical)
        .map(Some)
        .map_err(|_| TrustContractError)
}

pub fn response_shape(method: &str, path: &str) -> Option<(ResponseKind, bool)> {
    if path == "/v1/trust-profiles" {
        return match method {
            "GET" => Some((ResponseKind::TrustProfile, true)),
            "POST" => Some((ResponseKind::TrustProfile, false)),
            _ => None,
        };
    }
    if registry_sync(path) && method == "POST" {
        return Some((ResponseKind::RegistrySync, false));
    }
    if direct_child(path, "/v1/trust-profiles/") && matches!(method, "GET" | "PATCH") {
        return Some((ResponseKind::TrustProfile, false));
    }
    if activation(path) && method == "POST" {
        return Some((ResponseKind::TrustProfile, false));
    }
    if path == "/v1/issuer-entities" {
        return match method {
            "GET" => Some((ResponseKind::IssuerEntity, true)),
            "POST" => Some((ResponseKind::IssuerEntity, false)),
            _ => None,
        };
    }
    if direct_child(path, "/v1/issuer-entities/") && matches!(method, "GET" | "PATCH") {
        return Some((ResponseKind::IssuerEntity, false));
    }
    if relationship_collection(path) {
        return match method {
            "GET" => Some((ResponseKind::TrustProfileIssuer, true)),
            "POST" => Some((ResponseKind::TrustProfileIssuer, false)),
            _ => None,
        };
    }
    if relationship_member(path) && matches!(method, "GET" | "PATCH") {
        return Some((ResponseKind::TrustProfileIssuer, false));
    }
    None
}

pub fn project_response(
    value: Value,
    kind: ResponseKind,
    many: bool,
) -> Result<Value, TrustContractError> {
    if many {
        return value
            .as_array()
            .ok_or(TrustContractError)?
            .iter()
            .cloned()
            .map(|item| project_one(item, kind))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    project_one(value, kind)
}

#[derive(Clone, Copy)]
enum RequestOperation {
    TrustProfileCreate,
    TrustProfileUpdate,
    IssuerCreate,
    IssuerUpdate,
    RelationshipCreate,
    RelationshipUpdate,
}

fn request_operation(method: &str, path: &str) -> Option<RequestOperation> {
    if method == "POST" && path == "/v1/trust-profiles" {
        Some(RequestOperation::TrustProfileCreate)
    } else if method == "PATCH" && direct_child(path, "/v1/trust-profiles/") {
        Some(RequestOperation::TrustProfileUpdate)
    } else if method == "POST" && path == "/v1/issuer-entities" {
        Some(RequestOperation::IssuerCreate)
    } else if method == "PATCH" && direct_child(path, "/v1/issuer-entities/") {
        Some(RequestOperation::IssuerUpdate)
    } else if method == "POST" && relationship_collection(path) {
        Some(RequestOperation::RelationshipCreate)
    } else if method == "PATCH" && relationship_member(path) {
        Some(RequestOperation::RelationshipUpdate)
    } else {
        None
    }
}

fn direct_child(path: &str, prefix: &str) -> bool {
    path.strip_prefix(prefix)
        .is_some_and(|tail| !tail.is_empty() && !tail.contains('/'))
}

fn relationship_collection(path: &str) -> bool {
    let Some(tail) = path.strip_prefix("/v1/trust-profiles/") else {
        return false;
    };
    let segments = tail.split('/').collect::<Vec<_>>();
    segments.len() == 2 && !segments[0].is_empty() && segments[1] == "issuers"
}

fn relationship_member(path: &str) -> bool {
    let Some(tail) = path.strip_prefix("/v1/trust-profiles/") else {
        return false;
    };
    let segments = tail.split('/').collect::<Vec<_>>();
    segments.len() == 3
        && !segments[0].is_empty()
        && segments[1] == "issuers"
        && !segments[2].is_empty()
}

fn activation(path: &str) -> bool {
    path.strip_prefix("/v1/trust-profiles/")
        .is_some_and(|tail| {
            let segments = tail.split('/').collect::<Vec<_>>();
            segments.len() == 2 && !segments[0].is_empty() && segments[1] == "activate"
        })
}

fn registry_sync(path: &str) -> bool {
    path.strip_prefix("/v1/trust-profiles/")
        .is_some_and(|tail| {
            let segments = tail.split('/').collect::<Vec<_>>();
            segments.len() == 2 && !segments[0].is_empty() && segments[1] == "registry-sync"
        })
}

fn object(value: Value, allowed: &[&str]) -> Result<Map<String, Value>, TrustContractError> {
    let value = value.as_object().cloned().ok_or(TrustContractError)?;
    if value.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(TrustContractError);
    }
    Ok(value)
}

fn canonicalize_issuer_create(value: Value) -> Result<Value, TrustContractError> {
    let mut value = object(value, ISSUER_CREATE_FIELDS)?;
    required_string(&value, "organization_id", 0, usize::MAX)?;
    required_string(&value, "issuer_id", 1, 512)?;
    required_string(&value, "display_name", 1, 256)?;
    value.entry("issuer_type").or_insert(json!("ORGANIZATION"));
    value.entry("description").or_insert(Value::Null);
    value
        .entry("compliance_status")
        .or_insert(json!("COMPLIANT"));
    value.entry("accreditation_body").or_insert(Value::Null);
    value.entry("accreditations").or_insert_with(|| json!([]));
    value.entry("accreditation_date").or_insert(Value::Null);
    value.entry("valid_from").or_insert(Value::Null);
    value.entry("valid_until").or_insert(Value::Null);
    value.entry("trust_anchor_id").or_insert(Value::Null);
    value.entry("metadata").or_insert_with(|| json!({}));
    validate_enum(
        &value,
        "issuer_type",
        &["ORGANIZATION", "GOVERNMENT", "DEVICE"],
        false,
    )?;
    validate_enum(
        &value,
        "compliance_status",
        &["ACCREDITED", "COMPLIANT", "SUSPENDED"],
        false,
    )?;
    optional_string(&value, "description", 1024, true)?;
    optional_string(&value, "accreditation_body", 256, true)?;
    for field in [
        "accreditation_date",
        "valid_from",
        "valid_until",
        "trust_anchor_id",
    ] {
        optional_string(&value, field, usize::MAX, true)?;
    }
    normalize_accreditations(&mut value, "accreditations", false)?;
    validate_metadata(value.get("metadata"), false)?;
    Ok(Value::Object(value))
}

fn canonicalize_trust_profile(value: Value, update: bool) -> Result<Value, TrustContractError> {
    let mut value = object(
        value,
        if update {
            TRUST_PROFILE_UPDATE_FIELDS
        } else {
            TRUST_PROFILE_FIELDS
        },
    )?;
    if !update {
        required_string(&value, "organization_id", 1, 255)?;
        required_string(&value, "name", 1, 255)?;
        value.entry("description").or_insert(Value::Null);
        value.entry("profile_type").or_insert(json!("CUSTOM"));
        value
            .entry("compliance_status")
            .or_insert(json!("SETUP_REQUIRED"));
        value.entry("trust_sources").or_insert_with(|| json!([]));
        value.entry("validation_rules").or_insert(Value::Null);
        for field in [
            "allowed_algorithms",
            "min_key_size_rsa",
            "min_key_size_ec",
            "require_key_usage",
            "max_chain_depth",
            "allow_self_signed",
            "revocation_policy",
            "revocation_profile_id",
            "time_policy",
            "allowed_issuers",
            "denied_issuers",
            "verification_policy_set_id",
        ] {
            value.entry(field).or_insert(Value::Null);
        }
        value
            .entry("supported_formats")
            .or_insert_with(|| json!(["SD_JWT_VC", "MDOC"]));
        value
            .entry("system_issuer_overrides")
            .or_insert_with(|| json!({}));
        value
            .entry("compatible_compliance_codes")
            .or_insert_with(|| json!([]));
        value.entry("auto_generated").or_insert(json!(false));
    }
    validate_trust_profile_fields(&mut value, update)?;
    Ok(Value::Object(value))
}

fn validate_trust_profile_fields(
    value: &mut Map<String, Value>,
    update: bool,
) -> Result<(), TrustContractError> {
    for (field, maximum) in [
        ("name", 255),
        ("description", 2000),
        ("profile_type", 50),
        ("compliance_status", 50),
        ("revocation_profile_id", usize::MAX),
        ("verification_policy_set_id", usize::MAX),
    ] {
        if field == "name" && value.contains_key(field) && !value[field].is_null() {
            required_string(value, field, 1, maximum)?;
        } else {
            optional_string(value, field, maximum, true)?;
        }
    }
    if let Some(sources) = value.get_mut("trust_sources") {
        if !sources.is_null() {
            let sources = sources.as_array_mut().ok_or(TrustContractError)?;
            for source in sources {
                *source = canonicalize_trust_source(source.take())?;
            }
        } else if !update {
            return Err(TrustContractError);
        }
    }
    if let Some(rules) = value.get_mut("validation_rules") {
        if !rules.is_null() {
            *rules = canonicalize_validation_rules(rules.take())?;
        }
    }
    if let Some(policy) = value.get_mut("revocation_policy") {
        if !policy.is_null() {
            let mut policy = object(policy.take(), &["check_mode"])?;
            policy.entry("check_mode").or_insert(json!("HARD_FAIL"));
            validate_enum(
                &policy,
                "check_mode",
                &["HARD_FAIL", "SOFT_FAIL", "SKIP"],
                false,
            )?;
            value.insert("revocation_policy".into(), Value::Object(policy));
        }
    }
    if let Some(policy) = value.get_mut("time_policy") {
        if !policy.is_null() {
            *policy = canonicalize_time_policy(policy.take())?;
        }
    }
    for field in [
        "allowed_algorithms",
        "supported_formats",
        "allowed_issuers",
        "denied_issuers",
        "compatible_compliance_codes",
    ] {
        validate_string_array(value.get(field), true)?;
    }
    for field in ["min_key_size_rsa", "min_key_size_ec", "max_chain_depth"] {
        validate_integer(value.get(field), true)?;
    }
    for field in ["require_key_usage", "allow_self_signed", "auto_generated"] {
        validate_boolean(value.get(field), true)?;
    }
    if let Some(overrides) = value.get("system_issuer_overrides") {
        if !overrides.is_null() {
            let overrides = overrides.as_object().ok_or(TrustContractError)?;
            if overrides.values().any(|value| !value.is_object()) {
                return Err(TrustContractError);
            }
        }
    }
    Ok(())
}

fn canonicalize_trust_source(value: Value) -> Result<Value, TrustContractError> {
    let mut value = object(
        value,
        &[
            "source_type",
            "url",
            "certificate_pem",
            "issuer_did",
            "description",
            "registry_sync",
        ],
    )?;
    let source_type = required_string(&value, "source_type", 0, usize::MAX)?.to_uppercase();
    if !["TRUST_LIST", "PINNED_ISSUER", "ROOT_CA", "PKD_URL"].contains(&source_type.as_str()) {
        return Err(TrustContractError);
    }
    value.insert("source_type".into(), Value::String(source_type.clone()));
    for field in [
        "url",
        "certificate_pem",
        "issuer_did",
        "description",
        "registry_sync",
    ] {
        value.entry(field).or_insert(Value::Null);
    }
    optional_string(&value, "description", 256, true)?;
    let selectors = ["url", "certificate_pem", "issuer_did"]
        .iter()
        .filter(|field| value.get(**field).is_some_and(|entry| !entry.is_null()))
        .count();
    if selectors != 1 {
        return Err(TrustContractError);
    }
    if let Some(url) = value.get("url").and_then(Value::as_str) {
        validate_registry_url(url)?;
    } else if value.get("url").is_some_and(|url| !url.is_null()) {
        return Err(TrustContractError);
    }
    if let Some(certificate) = value.get("certificate_pem").and_then(Value::as_str) {
        if !certificate.starts_with("-----BEGIN CERTIFICATE-----") {
            return Err(TrustContractError);
        }
    } else if value
        .get("certificate_pem")
        .is_some_and(|certificate| !certificate.is_null())
    {
        return Err(TrustContractError);
    }
    if let Some(did) = value.get("issuer_did").and_then(Value::as_str) {
        if !did.starts_with("did:") {
            return Err(TrustContractError);
        }
    } else if value.get("issuer_did").is_some_and(|did| !did.is_null()) {
        return Err(TrustContractError);
    }
    let registry_kind = matches!(source_type.as_str(), "TRUST_LIST" | "PKD_URL");
    let has_url = value.get("url").is_some_and(|url| !url.is_null());
    match value.get_mut("registry_sync") {
        Some(sync) if !sync.is_null() => {
            if !registry_kind || !has_url {
                return Err(TrustContractError);
            }
            let config = object(sync.take(), &["protocol", "refresh_interval_hours"])?;
            required_enum(&config, "protocol", &["MARTY_TRUST_REGISTRY_SYNC_V1"])?;
            let interval = config
                .get("refresh_interval_hours")
                .and_then(Value::as_u64)
                .ok_or(TrustContractError)?;
            if !(1..=720).contains(&interval) {
                return Err(TrustContractError);
            }
            *sync = Value::Object(config);
        }
        _ if registry_kind && has_url => return Err(TrustContractError),
        _ => {}
    }
    Ok(Value::Object(value))
}

fn canonicalize_validation_rules(value: Value) -> Result<Value, TrustContractError> {
    let mut value = object(
        value,
        &[
            "allowed_algorithms",
            "min_key_size_rsa",
            "min_key_size_ec",
            "require_key_usage",
            "max_chain_depth",
            "allow_self_signed",
        ],
    )?;
    value
        .entry("allowed_algorithms")
        .or_insert_with(|| json!(["ES256", "ES384", "EdDSA"]));
    value.entry("min_key_size_rsa").or_insert(json!(2048));
    value.entry("min_key_size_ec").or_insert(json!(256));
    value.entry("require_key_usage").or_insert(json!(true));
    value.entry("max_chain_depth").or_insert(json!(5));
    value.entry("allow_self_signed").or_insert(json!(false));
    validate_string_array(value.get("allowed_algorithms"), false)?;
    for field in ["min_key_size_rsa", "min_key_size_ec", "max_chain_depth"] {
        validate_integer(value.get(field), false)?;
    }
    for field in ["require_key_usage", "allow_self_signed"] {
        validate_boolean(value.get(field), false)?;
    }
    Ok(Value::Object(value))
}

fn canonicalize_time_policy(value: Value) -> Result<Value, TrustContractError> {
    let mut value = object(
        value,
        &[
            "clock_skew_seconds",
            "require_freshness",
            "freshness_window_seconds",
        ],
    )?;
    value.entry("clock_skew_seconds").or_insert(json!(300));
    value.entry("require_freshness").or_insert(json!(false));
    value
        .entry("freshness_window_seconds")
        .or_insert(Value::Null);
    let skew = value
        .get("clock_skew_seconds")
        .and_then(Value::as_u64)
        .ok_or(TrustContractError)?;
    if skew > 86_400 {
        return Err(TrustContractError);
    }
    validate_boolean(value.get("require_freshness"), false)?;
    let window = value.get("freshness_window_seconds");
    if window.is_some_and(|window| !window.is_null()) {
        let window = window.and_then(Value::as_u64).ok_or(TrustContractError)?;
        if window == 0 || window % 3600 != 0 {
            return Err(TrustContractError);
        }
    }
    if value.get("require_freshness") == Some(&Value::Bool(true))
        && value
            .get("freshness_window_seconds")
            .is_none_or(Value::is_null)
    {
        return Err(TrustContractError);
    }
    Ok(Value::Object(value))
}

fn canonicalize_issuer_update(value: Value) -> Result<Value, TrustContractError> {
    let mut value = object(value, ISSUER_UPDATE_FIELDS)?;
    required_string(&value, "organization_id", 0, usize::MAX)?;
    if value.len() == 1 {
        return Err(TrustContractError);
    }
    if value.contains_key("display_name") {
        required_string(&value, "display_name", 1, 256)?;
    }
    optional_string(&value, "description", 1024, true)?;
    optional_string(&value, "accreditation_body", 256, true)?;
    for field in [
        "accreditation_date",
        "valid_until",
        "trust_anchor_id",
        "revocation_reason",
    ] {
        optional_string(
            &value,
            field,
            if field == "revocation_reason" {
                512
            } else {
                usize::MAX
            },
            true,
        )?;
    }
    if value.contains_key("valid_from") {
        required_string(&value, "valid_from", 0, usize::MAX)?;
    }
    validate_enum(
        &value,
        "issuer_type",
        &["ORGANIZATION", "GOVERNMENT", "DEVICE"],
        true,
    )?;
    validate_enum(
        &value,
        "compliance_status",
        &["ACCREDITED", "COMPLIANT", "SUSPENDED", "REVOKED"],
        true,
    )?;
    if value.contains_key("accreditations") {
        normalize_accreditations(&mut value, "accreditations", false)?;
    }
    if value.contains_key("metadata") {
        validate_metadata(value.get("metadata"), false)?;
    }
    let status = value.get("compliance_status").and_then(Value::as_str);
    let reason = value
        .get("revocation_reason")
        .and_then(Value::as_str)
        .filter(|reason| !reason.is_empty());
    if status == Some("REVOKED") && reason.is_none() {
        return Err(TrustContractError);
    }
    if value
        .get("revocation_reason")
        .is_some_and(|reason| !reason.is_null())
        && status != Some("REVOKED")
    {
        return Err(TrustContractError);
    }
    Ok(Value::Object(value))
}

fn canonicalize_relationship_create(value: Value) -> Result<Value, TrustContractError> {
    let mut value = object(value, RELATIONSHIP_FIELDS)?;
    let issuer_id = required_string(&value, "issuer_id", 0, usize::MAX)?;
    if !uuid_shape(issuer_id) {
        return Err(TrustContractError);
    }
    value.entry("trust_level").or_insert(json!(100));
    value
        .entry("relationship_status")
        .or_insert(json!("TRUSTED"));
    value
        .entry("cascade_revocation_policy")
        .or_insert(json!("NOTIFY_ONLY"));
    value.entry("metadata").or_insert_with(|| json!({}));
    validate_trust_level(value.get("trust_level"), false)?;
    validate_relationship_enums(&value, false)?;
    validate_metadata(value.get("metadata"), false)?;
    Ok(Value::Object(value))
}

fn canonicalize_relationship_update(value: Value) -> Result<Value, TrustContractError> {
    let value = object(value, RELATIONSHIP_UPDATE_FIELDS)?;
    if value.is_empty() {
        return Err(TrustContractError);
    }
    validate_trust_level(value.get("trust_level"), true)?;
    validate_relationship_enums(&value, true)?;
    if value.contains_key("metadata") {
        validate_metadata(value.get("metadata"), false)?;
    }
    Ok(Value::Object(value))
}

fn project_one(value: Value, kind: ResponseKind) -> Result<Value, TrustContractError> {
    match kind {
        ResponseKind::TrustProfile => project_trust_profile(value),
        ResponseKind::RegistrySync => project_registry_sync(value),
        ResponseKind::IssuerEntity => project_issuer(value),
        ResponseKind::TrustProfileIssuer => project_relationship(value),
    }
}

fn project_issuer(value: Value) -> Result<Value, TrustContractError> {
    const FIELDS: &[&str] = &[
        "id",
        "organization_id",
        "issuer_id",
        "issuer_type",
        "display_name",
        "description",
        "is_system_issuer",
        "compliance_status",
        "accreditation_body",
        "accreditations",
        "accreditation_date",
        "valid_from",
        "valid_until",
        "trust_anchor_id",
        "revoked_at",
        "revocation_reason",
        "revoked_by",
        "metadata",
        "created_at",
        "updated_at",
    ];
    let mut value = object(value, FIELDS)?;
    for field in [
        "id",
        "issuer_id",
        "issuer_type",
        "display_name",
        "compliance_status",
        "valid_from",
        "created_at",
        "updated_at",
    ] {
        required_string(&value, field, 0, usize::MAX)?;
    }
    if !value.get("is_system_issuer").is_some_and(Value::is_boolean) {
        return Err(TrustContractError);
    }
    for field in [
        "organization_id",
        "description",
        "accreditation_body",
        "accreditation_date",
        "valid_until",
        "trust_anchor_id",
        "revoked_at",
        "revocation_reason",
        "revoked_by",
    ] {
        optional_string(&value, field, usize::MAX, true)?;
        if value.get(field).is_some_and(Value::is_null) {
            value.remove(field);
        }
    }
    normalize_accreditations(&mut value, "accreditations", false)?;
    validate_metadata(value.get("metadata"), false)?;
    Ok(Value::Object(value))
}

fn project_trust_profile(value: Value) -> Result<Value, TrustContractError> {
    const FIELDS: &[&str] = &[
        "id",
        "organization_id",
        "name",
        "description",
        "status",
        "profile_type",
        "compliance_status",
        "trust_sources",
        "allowed_algorithms",
        "revocation_policy",
        "revocation_services",
        "revocation_profile_id",
        "time_policy",
        "supported_formats",
        "allowed_issuers",
        "denied_issuers",
        "system_issuer_overrides",
        "compatible_compliance_codes",
        "verification_policy_set_id",
        "auto_generated",
        "created_at",
        "updated_at",
    ];
    let mut value = object(value, FIELDS)?;
    for field in [
        "id",
        "organization_id",
        "name",
        "profile_type",
        "compliance_status",
        "created_at",
    ] {
        required_string(&value, field, 0, usize::MAX)?;
    }
    required_enum(
        &value,
        "status",
        &["draft", "active", "suspended", "archived"],
    )?;
    for field in ["trust_sources", "allowed_algorithms", "supported_formats"] {
        if !value.get(field).is_some_and(Value::is_array) {
            return Err(TrustContractError);
        }
    }
    for field in [
        "description",
        "revocation_profile_id",
        "verification_policy_set_id",
        "updated_at",
    ] {
        optional_string(&value, field, usize::MAX, true)?;
    }
    for field in [
        "revocation_policy",
        "revocation_services",
        "time_policy",
        "system_issuer_overrides",
    ] {
        if let Some(entry) = value.get(field) {
            if !entry.is_null() && !entry.is_object() {
                return Err(TrustContractError);
            }
        }
    }
    for field in [
        "allowed_issuers",
        "denied_issuers",
        "compatible_compliance_codes",
    ] {
        validate_string_array(value.get(field), true)?;
    }
    validate_boolean(value.get("auto_generated"), true)?;
    value
        .entry("system_issuer_overrides")
        .or_insert_with(|| json!({}));
    value
        .entry("compatible_compliance_codes")
        .or_insert_with(|| json!([]));
    value.entry("auto_generated").or_insert(json!(false));
    for field in [
        "description",
        "revocation_policy",
        "revocation_services",
        "revocation_profile_id",
        "time_policy",
        "allowed_issuers",
        "denied_issuers",
        "verification_policy_set_id",
        "updated_at",
    ] {
        if value.get(field).is_some_and(Value::is_null) {
            value.remove(field);
        }
    }
    Ok(Value::Object(value))
}

fn project_registry_sync(value: Value) -> Result<Value, TrustContractError> {
    let mut value = object(value, &["trust_profile_id", "sources", "synchronized_at"])?;
    let profile_id =
        uuid::Uuid::parse_str(required_string(&value, "trust_profile_id", 0, usize::MAX)?)
            .map_err(|_| TrustContractError)?;
    value.insert("trust_profile_id".into(), json!(profile_id));
    required_timestamp(&value, "synchronized_at")?;
    let sources = value
        .get_mut("sources")
        .and_then(Value::as_array_mut)
        .filter(|sources| !sources.is_empty())
        .ok_or(TrustContractError)?;
    for source in sources {
        let mut entry = object(
            source.take(),
            &[
                "url",
                "protocol",
                "sequence",
                "csca_entries",
                "dsc_entries",
                "synchronized_at",
            ],
        )?;
        let url = required_string(&entry, "url", 0, usize::MAX)?;
        validate_registry_url(url)?;
        required_enum(&entry, "protocol", &["MARTY_TRUST_REGISTRY_SYNC_V1"])?;
        for field in ["sequence", "csca_entries", "dsc_entries"] {
            validate_nonnegative_integer(entry.get(field), false)?;
        }
        required_timestamp(&entry, "synchronized_at")?;
        *source = Value::Object(std::mem::take(&mut entry));
    }
    Ok(Value::Object(value))
}

fn project_relationship(value: Value) -> Result<Value, TrustContractError> {
    const FIELDS: &[&str] = &[
        "id",
        "trust_profile_id",
        "issuer_id",
        "trust_level",
        "relationship_status",
        "cascade_revocation_policy",
        "metadata",
        "created_at",
        "updated_at",
    ];
    let mut value = object(value, FIELDS)?;
    for field in ["id", "trust_profile_id", "issuer_id"] {
        let id = required_string(&value, field, 0, usize::MAX)?;
        if !uuid_shape(id) {
            return Err(TrustContractError);
        }
    }
    required_string(&value, "created_at", 0, usize::MAX)?;
    validate_trust_level(value.get("trust_level"), false)?;
    validate_relationship_enums(&value, false)?;
    if !value.contains_key("metadata") {
        value.insert("metadata".into(), json!({}));
    }
    validate_metadata(value.get("metadata"), false)?;
    optional_string(&value, "updated_at", usize::MAX, true)?;
    if value.get("updated_at").is_some_and(Value::is_null) {
        value.remove("updated_at");
    }
    Ok(Value::Object(value))
}

fn required_string<'a>(
    value: &'a Map<String, Value>,
    field: &str,
    minimum: usize,
    maximum: usize,
) -> Result<&'a str, TrustContractError> {
    let value = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(TrustContractError)?;
    let length = value.chars().count();
    if length < minimum || length > maximum {
        return Err(TrustContractError);
    }
    Ok(value)
}

fn optional_string(
    value: &Map<String, Value>,
    field: &str,
    maximum: usize,
    allow_null: bool,
) -> Result<(), TrustContractError> {
    let Some(value) = value.get(field) else {
        return Ok(());
    };
    if allow_null && value.is_null() {
        return Ok(());
    }
    if value
        .as_str()
        .is_none_or(|value| value.chars().count() > maximum)
    {
        return Err(TrustContractError);
    }
    Ok(())
}

fn validate_enum(
    value: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
    allow_null: bool,
) -> Result<(), TrustContractError> {
    let Some(value) = value.get(field) else {
        return Ok(());
    };
    if allow_null && value.is_null() {
        return Ok(());
    }
    if value.as_str().is_none_or(|value| !allowed.contains(&value)) {
        return Err(TrustContractError);
    }
    Ok(())
}

fn required_enum(
    value: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
) -> Result<(), TrustContractError> {
    let entry = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(TrustContractError)?;
    if !allowed.contains(&entry) {
        return Err(TrustContractError);
    }
    Ok(())
}

fn validate_string_array(
    value: Option<&Value>,
    allow_null: bool,
) -> Result<(), TrustContractError> {
    let Some(value) = value else {
        return Ok(());
    };
    if allow_null && value.is_null() {
        return Ok(());
    }
    if value
        .as_array()
        .is_none_or(|values| values.iter().any(|value| !value.is_string()))
    {
        return Err(TrustContractError);
    }
    Ok(())
}

fn validate_nonnegative_integer(
    value: Option<&Value>,
    allow_null: bool,
) -> Result<(), TrustContractError> {
    let Some(value) = value else {
        return if allow_null {
            Ok(())
        } else {
            Err(TrustContractError)
        };
    };
    if allow_null && value.is_null() {
        return Ok(());
    }
    value.as_u64().map(|_| ()).ok_or(TrustContractError)
}

fn validate_integer(value: Option<&Value>, allow_null: bool) -> Result<(), TrustContractError> {
    let Some(value) = value else {
        return if allow_null {
            Ok(())
        } else {
            Err(TrustContractError)
        };
    };
    if allow_null && value.is_null() {
        return Ok(());
    }
    value.as_i64().map(|_| ()).ok_or(TrustContractError)
}

fn validate_boolean(value: Option<&Value>, allow_null: bool) -> Result<(), TrustContractError> {
    let Some(value) = value else {
        return Ok(());
    };
    if allow_null && value.is_null() {
        return Ok(());
    }
    value.as_bool().map(|_| ()).ok_or(TrustContractError)
}

fn validate_registry_url(value: &str) -> Result<(), TrustContractError> {
    let url = url::Url::parse(value).map_err(|_| TrustContractError)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some_and(|port| port != 443)
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(TrustContractError);
    }
    Ok(())
}

fn required_timestamp(value: &Map<String, Value>, field: &str) -> Result<(), TrustContractError> {
    let value = required_string(value, field, 1, usize::MAX)?;
    let offset = regex::Regex::new(r"[+-][0-9]{2}:[0-9]{2}$").expect("timestamp offset regex");
    if !value.contains('T') || (!value.ends_with('Z') && !offset.is_match(value)) {
        return Err(TrustContractError);
    }
    Ok(())
}

fn validate_relationship_enums(
    value: &Map<String, Value>,
    allow_null: bool,
) -> Result<(), TrustContractError> {
    validate_enum(
        value,
        "relationship_status",
        &["TRUSTED", "DENIED", "UNDER_REVIEW"],
        allow_null,
    )?;
    validate_enum(
        value,
        "cascade_revocation_policy",
        &["AUTO_CASCADE", "MANUAL", "NOTIFY_ONLY"],
        allow_null,
    )
}

fn validate_trust_level(value: Option<&Value>, allow_null: bool) -> Result<(), TrustContractError> {
    let Some(value) = value else {
        return Ok(());
    };
    if allow_null && value.is_null() {
        return Ok(());
    }
    if value.as_u64().is_none_or(|value| value > 100) {
        return Err(TrustContractError);
    }
    Ok(())
}

fn normalize_accreditations(
    value: &mut Map<String, Value>,
    field: &str,
    allow_null: bool,
) -> Result<(), TrustContractError> {
    let Some(entries) = value.get_mut(field) else {
        return Err(TrustContractError);
    };
    if allow_null && entries.is_null() {
        return Ok(());
    }
    let entries = entries.as_array_mut().ok_or(TrustContractError)?;
    if entries.len() > 64 {
        return Err(TrustContractError);
    }
    let mut seen = BTreeSet::new();
    for entry in entries {
        let cleaned = entry.as_str().ok_or(TrustContractError)?.trim().to_owned();
        if cleaned.is_empty() || cleaned.chars().count() > 128 {
            return Err(TrustContractError);
        }
        if !seen.insert(cleaned.to_lowercase()) {
            return Err(TrustContractError);
        }
        *entry = Value::String(cleaned);
    }
    Ok(())
}

fn validate_metadata(value: Option<&Value>, allow_null: bool) -> Result<(), TrustContractError> {
    let Some(value) = value else {
        return Err(TrustContractError);
    };
    if allow_null && value.is_null() {
        return Ok(());
    }
    if !value.is_object() || contains_private_metadata(value) {
        return Err(TrustContractError);
    }
    Ok(())
}

fn contains_private_metadata(value: &Value) -> bool {
    match value {
        Value::Object(value) => {
            let keys = value
                .keys()
                .map(|key| key.to_lowercase())
                .collect::<BTreeSet<_>>();
            (keys.contains("kty") && PRIVATE_JWK_FIELDS.iter().any(|key| keys.contains(*key)))
                || keys
                    .iter()
                    .any(|key| PRIVATE_CUSTODY_FIELDS.contains(&key.as_str()))
                || value.values().any(contains_private_metadata)
        }
        Value::Array(value) => value.iter().any(contains_private_metadata),
        _ => false,
    }
}

fn uuid_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, value)| {
            matches!(index, 8 | 13 | 18 | 23).then_some(b'-') == Some(*value)
                || (!matches!(index, 8 | 13 | 18 | 23) && value.is_ascii_hexdigit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        request_cases: Vec<RequestCase>,
        invalid_requests: Vec<RequestCase>,
        response_cases: Vec<ResponseCase>,
        private_metadata_response: ResponseCase,
    }
    #[derive(Deserialize)]
    struct RequestCase {
        name: String,
        method: String,
        path: String,
        input: Value,
        #[serde(default)]
        expected: Value,
    }
    #[derive(Deserialize)]
    struct ResponseCase {
        name: String,
        kind: String,
        many: bool,
        input: Value,
        #[serde(default)]
        expected: Value,
    }

    #[test]
    fn language_neutral_trust_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-trust-behavior.json"
        ))
        .expect("trust contract");
        assert_eq!(contract.schema_version, 1);
        for case in contract.request_cases {
            let canonical = canonicalize_request(
                &case.method,
                &case.path,
                &serde_json::to_vec(&case.input).expect("fixture"),
            )
            .unwrap_or_else(|_| panic!("{}", case.name))
            .expect("canonical request");
            assert_eq!(
                serde_json::from_slice::<Value>(&canonical).expect("JSON"),
                case.expected,
                "{}",
                case.name
            );
        }
        for case in contract.invalid_requests {
            assert!(
                canonicalize_request(
                    &case.method,
                    &case.path,
                    &serde_json::to_vec(&case.input).expect("fixture")
                )
                .is_err(),
                "{}",
                case.name
            );
        }
        for case in contract.response_cases {
            let kind = response_kind(&case.kind);
            assert_eq!(
                project_response(case.input, kind, case.many)
                    .unwrap_or_else(|_| panic!("{}", case.name)),
                case.expected,
                "{}",
                case.name
            );
        }
        let private = contract.private_metadata_response;
        assert!(
            project_response(private.input, response_kind(&private.kind), private.many).is_err()
        );
    }

    fn response_kind(value: &str) -> ResponseKind {
        match value {
            "trust_profile" => ResponseKind::TrustProfile,
            "registry_sync" => ResponseKind::RegistrySync,
            "issuer_entity" => ResponseKind::IssuerEntity,
            "trust_profile_issuer" => ResponseKind::TrustProfileIssuer,
            _ => panic!("unknown response kind"),
        }
    }
}
