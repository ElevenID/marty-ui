use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, fs, path::Path};
use thiserror::Error;

const INTERNAL_KEYS: &[&str] = &[
    "credential_offer_uri",
    "credential_offer_uris",
    "credential_offer_labels",
    "offer_expires_at",
    "offer_generated_at",
    "issuance_transaction_id",
    "issuance_status",
    "issuance_source",
    "flow_instance_id",
    "flow_definition_id",
    "credential_display_name",
    "credential_type",
    "review_notes",
    "rejection_reason",
    "info_requests",
    "delivery_preferences",
    "auto_approve",
];
const INTEGRATION_KEYS: &[&str] = &[
    "canvas_lti",
    "canvas_context",
    "learner_identity",
    "delivery_mode",
    "delivery",
];

pub fn migrate_payload(
    payload: &mut Value,
    template_map: &BTreeMap<String, String>,
) -> Result<bool, MigrationError> {
    let Some(root) = payload.as_object_mut() else {
        return Err(MigrationError::MalformedStore);
    };
    let Some(applications) = root.get("applications").and_then(Value::as_array) else {
        return Ok(false);
    };
    if applications.is_empty() {
        return Ok(false);
    }
    if applications
        .iter()
        .all(|row| row.get("credential_template_id").is_some() && row.get("metadata").is_none())
    {
        return Ok(false);
    }

    let mut migrated = Vec::with_capacity(applications.len());
    let mut unresolved = Vec::new();
    for row in applications {
        let Some(row) = row.as_object() else {
            unresolved.push("unknown".to_owned());
            continue;
        };
        let credential_template_id = text(row, "credential_template_id")
            .or_else(|| text(row, "credential_configuration_id"))
            .unwrap_or_default();
        let application_template_id = text(row, "application_template_id")
            .or_else(|| template_map.get(&credential_template_id).cloned())
            .unwrap_or_default();
        if credential_template_id.is_empty() || application_template_id.is_empty() {
            unresolved.push(text(row, "id").unwrap_or_else(|| "unknown".into()));
            continue;
        }

        let mut form_data = object(row.get("form_data"));
        let mut integration_context = object(row.get("integration_context"));
        let mut system_data = object(row.get("system_data"));
        for (key, value) in object(row.get("metadata")) {
            if INTERNAL_KEYS.contains(&key.as_str()) {
                system_data.insert(key, value);
            } else if INTEGRATION_KEYS.contains(&key.as_str()) {
                integration_context.insert(key, value);
            } else {
                form_data.insert(key, value);
            }
        }
        let auto_approve = system_data
            .remove("auto_approve")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        system_data
            .entry("approval_strategy")
            .or_insert_with(|| Value::String(if auto_approve { "AUTO" } else { "MANUAL" }.into()));
        let status = text(row, "status")
            .unwrap_or_else(|| "DRAFT".into())
            .to_ascii_uppercase();
        let offer_ready = non_empty(&system_data, "credential_offer_uri")
            || non_empty(&system_data, "credential_offer_uris");
        let claim_state = if matches!(status.as_str(), "CREDENTIALED" | "ISSUED") {
            "CLAIMED"
        } else if offer_ready {
            "OFFER_READY"
        } else {
            "NOT_READY"
        };
        migrated.push(json!({
            "id": row.get("id").cloned().unwrap_or(Value::Null),
            "applicant_id": row.get("applicant_id").cloned().unwrap_or(Value::Null),
            "organization_id": row.get("organization_id").cloned().unwrap_or(Value::Null),
            "reference_number": row.get("reference_number").cloned().unwrap_or(Value::Null),
            "application_template_id": application_template_id,
            "credential_template_id": credential_template_id,
            "status": status,
            "form_data": form_data,
            "integration_context": integration_context,
            "system_data": system_data,
            "required_checks": row.get("required_checks").cloned().unwrap_or_else(|| json!([])),
            "claim_state": claim_state,
            "claim_blocker": Value::Null,
            "created_at": row.get("created_at").cloned().unwrap_or(Value::Null),
            "submitted_at": row.get("submitted_at").cloned().unwrap_or(Value::Null),
            "reviewed_at": row.get("reviewed_at").cloned().unwrap_or(Value::Null),
            "issued_at": row.get("issued_at").cloned().unwrap_or(Value::Null),
            "updated_at": row.get("updated_at").cloned().unwrap_or(Value::Null)
        }));
    }
    if !unresolved.is_empty() {
        return Err(MigrationError::UnresolvedTemplates(unresolved));
    }
    root.insert("applications".into(), Value::Array(migrated));
    root.insert("schema_version".into(), Value::String("MIP/0.3.0".into()));
    Ok(true)
}

pub fn migrate_file(
    path: &Path,
    template_map: &BTreeMap<String, String>,
) -> Result<bool, MigrationError> {
    if !path.exists() {
        return Ok(false);
    }
    let original = fs::read(path)?;
    let mut payload: Value = serde_json::from_slice(&original)?;
    if !migrate_payload(&mut payload, template_map)? {
        return Ok(false);
    }
    let backup = path.with_extension(format!(
        "{}.mip-0.2.bak",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
    ));
    if !backup.exists() {
        fs::write(&backup, &original)?;
    }
    let temporary = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
    ));
    fs::write(&temporary, serde_json::to_vec(&payload)?)?;
    fs::rename(temporary, path)?;
    Ok(true)
}

fn text(row: &Map<String, Value>, key: &str) -> Option<String> {
    row.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}
fn object(value: Option<&Value>) -> Map<String, Value> {
    value
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}
fn non_empty(values: &Map<String, Value>, key: &str) -> bool {
    values.get(key).is_some_and(|value| match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
        Value::Number(_) => true,
    })
}

#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("applicant store must be a JSON object")]
    MalformedStore,
    #[error("Applicant migration cannot resolve Application Templates for: {0:?}")]
    UnresolvedTemplates(Vec<String>),
    #[error("applicant store I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("applicant store JSON is malformed: {0}")]
    Json(#[from] serde_json::Error),
}
