use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

#[derive(Debug)]
pub struct OrganizationCompositionError;

pub fn runtime_status(
    templates: &Value,
    policies: &Value,
    deployments: &Value,
    flows: &Value,
) -> Value {
    let templates = payload_items(templates, &["templates", "credential_templates"]);
    let policies = payload_items(policies, &["policies", "presentation_policies"]);
    let deployments = payload_items(deployments, &["profiles", "deployment_profiles"]);
    let flows = payload_items(flows, &["flows", "definitions", "flow_definitions"]);
    let active_templates = active(&templates);
    let active_policies = active(&policies);
    let active_deployments = active(&deployments);
    let active_flows = active(&flows);
    let did_backed = active_templates
        .iter()
        .filter(|item| {
            item.get("issuer_did")
                .and_then(Value::as_str)
                .is_some_and(|did| did.starts_with("did:"))
        })
        .count();
    let issuer_active = did_backed > 0;
    let deployment_active = !active_deployments.is_empty();
    let policy_reachable = !active_policies.is_empty();
    let issuance_flow_active = active_flows.iter().any(|item| {
        item.get("credential_template_id")
            .is_some_and(|entry| !entry.is_null())
    });
    json!({
        "can_issue": issuer_active && deployment_active && issuance_flow_active,
        "can_verify": policy_reachable && deployment_active,
        "issuer_keys_valid": issuer_active,
        "issuer_active": issuer_active,
        "deployment_active": deployment_active,
        "policy_reachable": policy_reachable,
        "last_issuance_timestamp": null,
        "last_verification_timestamp": null,
        "artifact_counts": {
            "active_credential_templates": active_templates.len(),
            "did_backed_credential_templates": did_backed,
            "active_presentation_policies": active_policies.len(),
            "active_deployment_profiles": active_deployments.len(),
            "active_flows": active_flows.len(),
        }
    })
}

pub fn applicant_stats(payload: &Value) -> Value {
    let items = payload_items(payload, &["items"]);
    let statuses = items.iter().map(status).collect::<Vec<_>>();
    json!({
        "pending": statuses.iter().filter(|status| matches!(status.as_str(), "submitted" | "under_review" | "pending_information" | "pending")).count(),
        "approved": statuses.iter().filter(|status| status.as_str() == "approved").count(),
        "issuable": statuses.iter().filter(|status| matches!(status.as_str(), "approved" | "offered")).count(),
        "total": items.len(),
    })
}

pub fn retention_window_days(lifecycle: &Value) -> u64 {
    let candidate = lifecycle
        .get("pilot_retention")
        .and_then(Value::as_object)
        .and_then(|pilot| pilot.get("window_days"))
        .or_else(|| lifecycle.get("audit_retention_days"));
    let parsed = candidate.and_then(integer_like).unwrap_or(30);
    if parsed > 0 {
        parsed as u64
    } else {
        30
    }
}

pub fn pilot_retention_enabled(lifecycle: &Value) -> bool {
    lifecycle
        .get("pilot_retention")
        .and_then(Value::as_object)
        .and_then(|pilot| pilot.get("enabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub fn compose_lifecycle(
    lifecycle: Value,
    retention_summary: Option<&Value>,
) -> Result<Value, OrganizationCompositionError> {
    let mut lifecycle = lifecycle
        .as_object()
        .cloned()
        .ok_or(OrganizationCompositionError)?;
    if pilot_retention_enabled(&Value::Object(lifecycle.clone())) {
        let summary = retention_summary
            .and_then(Value::as_object)
            .ok_or(OrganizationCompositionError)?;
        let mut pilot = lifecycle
            .get("pilot_retention")
            .and_then(Value::as_object)
            .cloned()
            .ok_or(OrganizationCompositionError)?;
        for field in [
            "cutoff_at",
            "next_expiry_at",
            "oldest_retained_record_at",
            "eligible_for_purge",
            "tracked_scope",
        ] {
            pilot.insert(
                field.into(),
                summary.get(field).cloned().unwrap_or_else(|| {
                    if matches!(field, "eligible_for_purge") {
                        json!({})
                    } else if field == "tracked_scope" {
                        json!([])
                    } else {
                        Value::Null
                    }
                }),
            );
        }
        lifecycle.insert("pilot_retention".into(), Value::Object(pilot));
    }
    project_lifecycle(Value::Object(lifecycle))
}

pub fn purge_due(lifecycle: &Value, now: DateTime<Utc>) -> bool {
    if !pilot_retention_enabled(lifecycle) {
        return false;
    }
    let pilot = &lifecycle["pilot_retention"];
    let eligible = pilot
        .get("eligible_for_purge")
        .and_then(|counts| counts.get("total"))
        .and_then(integer_like)
        .unwrap_or(0);
    if eligible > 0 {
        return true;
    }
    pilot
        .get("next_expiry_at")
        .and_then(Value::as_str)
        .and_then(parse_timestamp)
        .is_some_and(|expiry| expiry <= now)
}

pub fn integration_info(org_id: &str, base_url: &str) -> Value {
    let base_url = if base_url.trim_end_matches('/').ends_with("/v1") {
        base_url.trim_end_matches('/').to_owned()
    } else {
        format!("{}/v1", base_url.trim_end_matches('/'))
    };
    json!({
        "org_id": org_id,
        "base_url": base_url,
        "example_request": format!(
            "curl -sS -X POST \"{base_url}/flows/instances\" \\\n  -H \"Content-Type: application/json\" \\\n  -H \"X-API-Key: <api-key>\" \\\n  -H \"X-Organization-ID: {org_id}\" \\\n  -d '{{\"flow_definition_id\":\"<flow-definition-id>\",\"subject_id\":\"<subject-id>\",\"initial_context\":{{}}}}'"
        )
    })
}

pub fn purge_metadata_patch(purge: &Value) -> Option<Value> {
    purge
        .get("purged_at")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(|purged_at| json!({"settings_patch":{"pilot_retention_last_purged_at":purged_at}}))
}

pub fn purged_total(purge: &Value) -> u64 {
    purge
        .get("purged_records")
        .and_then(|counts| counts.get("total"))
        .and_then(integer_like)
        .filter(|total| *total > 0)
        .map_or(0, |total| total as u64)
}

pub fn project_purge(value: Value) -> Result<Value, OrganizationCompositionError> {
    let object = value.as_object().ok_or(OrganizationCompositionError)?;
    let public = select(
        object,
        &[
            "organization_id",
            "retention_days",
            "cutoff_at",
            "purged_at",
            "purged_records",
            "next_expiry_at",
            "oldest_retained_record_at",
            "tracked_scope",
        ],
    );
    let parsed: PurgeResponse =
        serde_json::from_value(Value::Object(public)).map_err(|_| OrganizationCompositionError)?;
    serde_json::to_value(parsed).map_err(|_| OrganizationCompositionError)
}

fn project_lifecycle(value: Value) -> Result<Value, OrganizationCompositionError> {
    let object = value.as_object().ok_or(OrganizationCompositionError)?;
    let public = select(
        object,
        &[
            "created_at",
            "compliance_profiles",
            "data_retention_mode",
            "audit_retention_days",
            "pilot_retention",
        ],
    );
    let parsed: LifecycleResponse =
        serde_json::from_value(Value::Object(public)).map_err(|_| OrganizationCompositionError)?;
    serde_json::to_value(parsed).map_err(|_| OrganizationCompositionError)
}

fn payload_items(payload: &Value, keys: &[&str]) -> Vec<Map<String, Value>> {
    let entries = payload.as_array().or_else(|| {
        payload
            .as_object()
            .and_then(|object| keys.iter().find_map(|key| object.get(*key)?.as_array()))
    });
    entries
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .cloned()
        .collect()
}

fn active(items: &[Map<String, Value>]) -> Vec<&Map<String, Value>> {
    items
        .iter()
        .filter(|item| matches!(status(item).as_str(), "" | "active" | "enabled" | "ready"))
        .collect()
}

fn status(item: &Map<String, Value>) -> String {
    item.get("status")
        .or_else(|| item.get("state"))
        .and_then(|value| match value {
            Value::String(value) => Some(value.clone()),
            Value::Null => None,
            other => Some(other.to_string()),
        })
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn integer_like(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| value.as_str()?.parse().ok())
}

fn parse_timestamp(value: &str) -> Option<DateTime<Utc>> {
    let normalized = if value.len() == 10 && value.as_bytes().get(4) == Some(&b'-') {
        format!("{value}T00:00:00+00:00")
    } else {
        value.to_owned()
    };
    DateTime::parse_from_rfc3339(&normalized)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn select(object: &Map<String, Value>, fields: &[&str]) -> Map<String, Value> {
    object
        .iter()
        .filter(|(key, _)| fields.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

#[derive(Default, Deserialize, Serialize)]
struct Counts {
    #[serde(default)]
    issuance_transactions: i64,
    #[serde(default)]
    applications: i64,
    #[serde(default)]
    authorization_sessions: i64,
    #[serde(default)]
    issuance_events: i64,
    #[serde(default)]
    issued_credentials: i64,
    #[serde(default)]
    total: i64,
}

#[derive(Deserialize, Serialize)]
struct PilotRetention {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "thirty")]
    window_days: i64,
    #[serde(default)]
    scope_summary: Option<String>,
    #[serde(default)]
    scope_items: Vec<String>,
    #[serde(default)]
    access_behavior: Option<String>,
    #[serde(default)]
    last_purged_at: Option<String>,
    #[serde(default)]
    cutoff_at: Option<String>,
    #[serde(default)]
    next_expiry_at: Option<String>,
    #[serde(default)]
    oldest_retained_record_at: Option<String>,
    #[serde(default)]
    eligible_for_purge: Counts,
    #[serde(default)]
    tracked_scope: Vec<String>,
}

const fn thirty() -> i64 {
    30
}
const fn ninety() -> i64 {
    90
}
fn standard() -> String {
    "standard".into()
}

#[derive(Deserialize, Serialize)]
struct LifecycleResponse {
    created_at: String,
    #[serde(default)]
    compliance_profiles: Vec<String>,
    #[serde(default = "standard")]
    data_retention_mode: String,
    #[serde(default = "ninety")]
    audit_retention_days: i64,
    #[serde(default)]
    pilot_retention: Option<PilotRetention>,
}

#[derive(Deserialize, Serialize)]
struct PurgeResponse {
    organization_id: String,
    retention_days: i64,
    cutoff_at: String,
    purged_at: String,
    purged_records: Counts,
    #[serde(default)]
    next_expiry_at: Option<String>,
    #[serde(default)]
    oldest_retained_record_at: Option<String>,
    #[serde(default)]
    tracked_scope: Vec<String>,
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct RuntimeInputs {
        templates: Value,
        policies: Value,
        deployments: Value,
        flows: Value,
    }
    #[derive(Deserialize)]
    struct Contract {
        schema_version: u32,
        runtime_inputs: RuntimeInputs,
        expected_runtime: Value,
        applicants: Value,
        expected_applicant_stats: Value,
        lifecycle: Value,
        retention_summary: Value,
        expected_lifecycle: Value,
        expected_integration_info: Value,
        sweep_now: String,
        due_lifecycle: Value,
        future_lifecycle: Value,
    }

    #[test]
    fn language_neutral_organization_composition_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-organization-composition-behavior.json"
        ))
        .expect("composition contract");
        assert_eq!(contract.schema_version, 1);
        assert_eq!(
            runtime_status(
                &contract.runtime_inputs.templates,
                &contract.runtime_inputs.policies,
                &contract.runtime_inputs.deployments,
                &contract.runtime_inputs.flows
            ),
            contract.expected_runtime
        );
        assert_eq!(
            applicant_stats(&contract.applicants),
            contract.expected_applicant_stats
        );
        assert_eq!(
            compose_lifecycle(contract.lifecycle, Some(&contract.retention_summary)).unwrap(),
            contract.expected_lifecycle
        );
        assert_eq!(
            integration_info("org-1", "https://beta.elevenidllc.com"),
            contract.expected_integration_info
        );
        let now = parse_timestamp(&contract.sweep_now).unwrap();
        assert!(purge_due(&contract.due_lifecycle, now));
        assert!(!purge_due(&contract.future_lifecycle, now));
    }
}
