use chrono::{TimeZone, Utc};
use marty_flow::{
    create_definition_record, parse_request, update_definition_record, CreateFlowDefinitionRequest,
    DefinitionStatus, UpdateFlowDefinitionRequest,
};
use serde_json::{json, Value};

fn api_contract() -> Value {
    serde_json::from_str(include_str!("../../../../contracts/flow-api-behavior.json"))
        .expect("API contract")
}

#[test]
fn standard_definition_creation_preserves_defaults_and_protocol_graph() {
    let payload = api_contract()["valid_requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| {
            case["kind"] == "create_definition"
                && case["payload"]["flow_type"] == "oid4vp_presentation"
        })
        .unwrap()["payload"]
        .clone();
    let request: CreateFlowDefinitionRequest = parse_request(payload).unwrap();
    let now = Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap();
    let record = create_definition_record(request, now).unwrap();
    assert_eq!(record.status, DefinitionStatus::Draft);
    assert_eq!(record.version, 1);
    assert_eq!(record.default_timeout_seconds, 600);
    assert_eq!(record.max_retries, 3);
    assert_eq!(record.retry_cooldown_minutes, 5);
    assert!(record.enable_resume);
    assert_eq!(record.steps.len(), 4);
    assert_eq!(record.transitions.len(), 3);
    assert_eq!(
        record
            .kernel()
            .unwrap()
            .steps
            .into_iter()
            .map(|step| step.protocol_step)
            .collect::<Vec<_>>(),
        [
            "create_request",
            "wallet_selection",
            "presentation_submission",
            "verify_presentation"
        ]
    );
}

#[test]
fn custom_graph_and_patch_semantics_preserve_behavior() {
    let payload = api_contract()["valid_requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| {
            case["kind"] == "create_definition" && case["payload"]["flow_type"] == "custom"
        })
        .unwrap()["payload"]
        .clone();
    let request: CreateFlowDefinitionRequest = parse_request(payload).unwrap();
    let created_at = Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap();
    let mut record = create_definition_record(request, created_at).unwrap();
    record.description = Some("remove me".into());
    assert_eq!(
        record
            .kernel()
            .unwrap()
            .steps
            .into_iter()
            .map(|step| step.protocol_step)
            .collect::<Vec<_>>(),
        ["collect", "verify"]
    );
    assert_eq!(
        record.extension.as_ref().unwrap()["entry_step_id"],
        "collect"
    );

    let patch: UpdateFlowDefinitionRequest = parse_request(json!({
        "organization_id": "org-1",
        "description": null,
        "deployment_profile_ids": ["deployment-1", "deployment-1"]
    }))
    .unwrap();
    let updated_at = Utc.with_ymd_and_hms(2026, 8, 20, 12, 5, 0).unwrap();
    let updated = update_definition_record(&record, patch, updated_at).unwrap();
    assert_eq!(updated.id, record.id);
    assert_eq!(updated.created_at, record.created_at);
    assert_eq!(updated.updated_at, updated_at);
    assert_eq!(updated.version, 2);
    assert_eq!(updated.status, DefinitionStatus::Draft);
    assert_eq!(updated.description, None);
    assert_eq!(updated.deployment_profile_ids, ["deployment-1"]);
    assert_eq!(
        updated.deployment_profile_id.as_deref(),
        Some("deployment-1")
    );
    assert_eq!(updated.kernel().unwrap().steps.len(), 2);
}

#[test]
fn patch_cannot_change_the_tenant() {
    let request: CreateFlowDefinitionRequest = parse_request(json!({
        "organization_id": "org-1",
        "name": "Issuance",
        "flow_type": "oid4vci_pre_authorized",
        "credential_template_id": "template-1"
    }))
    .unwrap();
    let now = Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap();
    let record = create_definition_record(request, now).unwrap();
    let patch: UpdateFlowDefinitionRequest = parse_request(json!({
        "organization_id": "org-2",
        "name": "Moved"
    }))
    .unwrap();
    assert!(update_definition_record(&record, patch, now).is_err());
}
