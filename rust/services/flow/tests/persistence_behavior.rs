use std::collections::{BTreeMap, BTreeSet};

use chrono::{TimeZone, Utc};
use marty_flow::{
    ApprovalStrategy, ArtifactStatus, DefinitionStatus, FlowArtifactRecord, FlowDefinitionRecord,
    FlowInstanceRecord, FlowRecordError, FlowType,
};
use marty_verification::flow::FlowInstanceStatus;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    definition_fields: Vec<String>,
    instance_fields: Vec<String>,
    artifact_fields: Vec<String>,
    state_history_storage: String,
    unknown_enum_behavior: String,
    malformed_json_behavior: String,
    terminal_update_behavior: String,
}

fn contract() -> Contract {
    serde_json::from_str(include_str!(
        "../../../../contracts/flow-persistence-behavior.json"
    ))
    .expect("valid persistence contract")
}

fn timestamp() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 20, 12, 34, 56)
        .single()
        .expect("timestamp")
}

fn definition() -> FlowDefinitionRecord {
    FlowDefinitionRecord {
        id: "flow-1".into(),
        organization_id: "org-1".into(),
        name: "Issue".into(),
        description: Some("Issue a credential".into()),
        status: DefinitionStatus::Active,
        flow_type: FlowType::Oid4vciPreAuthorized,
        steps: vec![
            json!({"id":"step-1","name":"create_offer","description":"Offer","step_type":"issuance","config":{"protocol_step":"create_offer"},"timeout_seconds":60,"conditions":[],"approval_strategy":null}),
            json!({"id":"step-2","name":"token_exchange","description":null,"step_type":"callback","config":{"protocol_step":"token_exchange"},"timeout_seconds":60,"conditions":[],"approval_strategy":null}),
        ],
        transitions: vec![
            json!({"id":"transition-1","from_step_id":"step-1","to_step_id":"step-2","condition":"success","condition_expression":null}),
        ],
        start_step_id: Some("step-1".into()),
        credential_template_id: Some("template-1".into()),
        application_template_id: None,
        presentation_policy_id: None,
        delivery_destination_profile_id: None,
        deployment_profile_id: Some("deployment-1".into()),
        deployment_profile_ids: vec!["deployment-1".into(), "deployment-2".into()],
        trust_profile_id: Some("trust-1".into()),
        approval_strategy: ApprovalStrategy::Auto,
        hooks: BTreeMap::from([(
            "on_complete".into(),
            vec![json!({"hook_type":"WEBHOOK","url":"https://callback.example/flow","config":{}})],
        )]),
        trigger: Some(json!({"trigger_type":"API_CALL","config":{}})),
        extension: None,
        preconditions: vec!["approved".into()],
        default_timeout_seconds: 600,
        max_retries: 3,
        retry_cooldown_minutes: 5,
        enable_resume: true,
        version: 7,
        created_at: timestamp(),
        updated_at: timestamp(),
    }
}

fn instance() -> FlowInstanceRecord {
    FlowInstanceRecord {
        id: "instance-1".into(),
        flow_definition_id: "flow-1".into(),
        organization_id: "org-1".into(),
        status: FlowInstanceStatus::InProgress,
        current_step_id: Some("step-1".into()),
        context: json!({"current_step_name":"create_offer","current_step_index":0}),
        step_history: vec![json!({"step_id":"step-0","result":"passed"})],
        state_history: vec![
            json!({"prior_state":"pending","new_state":"in_progress","timestamp":"2026-08-20T12:34:56Z","actor":"user-1","event":"advance"}),
        ],
        subject_id: Some("applicant-1".into()),
        subject_type: "applicant".into(),
        external_reference: Some("external-1".into()),
        application_flow_key_hash: Some("a".repeat(64)),
        started_at: Some(timestamp()),
        completed_at: None,
        expires_at: Some(timestamp()),
        result: None,
        error: None,
        created_at: timestamp(),
        updated_at: timestamp(),
    }
}

fn artifact() -> FlowArtifactRecord {
    FlowArtifactRecord {
        id: "artifact-1".into(),
        flow_instance_id: "instance-1".into(),
        issuance_transaction_id: Some("issuance-1".into()),
        credential_offer_uri: Some("openid-credential-offer://offer".into()),
        credential_offer_uris: BTreeMap::from([("en".into(), "offer-en".into())]),
        credential_offer_labels: BTreeMap::from([("en".into(), "English".into())]),
        pre_authorized_code: Some("secret-code".into()),
        issuance_status: Some("offer_created".into()),
        qr_payload: Some("data:image/png;base64,AA==".into()),
        expires_at: Some(timestamp()),
        scanned_at: None,
        status: ArtifactStatus::Active,
        state: Some("oauth-state".into()),
        wallet_metadata: json!({"wallet":"example"}),
        attempt_number: 2,
        created_at: timestamp(),
        updated_at: timestamp(),
    }
}

fn keys(value: Value) -> BTreeSet<String> {
    value
        .as_object()
        .expect("record object")
        .keys()
        .cloned()
        .collect()
}

#[test]
fn records_preserve_every_frozen_field() {
    let contract = contract();
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.state_history_storage, "dedicated_json_column");
    assert_eq!(contract.unknown_enum_behavior, "fail_closed");
    assert_eq!(contract.malformed_json_behavior, "fail_closed");
    assert_eq!(contract.terminal_update_behavior, "immutable");
    assert_eq!(
        keys(serde_json::to_value(definition()).expect("definition")),
        contract.definition_fields.into_iter().collect()
    );
    assert_eq!(
        keys(serde_json::to_value(instance()).expect("instance")),
        contract.instance_fields.into_iter().collect()
    );
    assert_eq!(
        keys(serde_json::to_value(artifact()).expect("artifact")),
        contract.artifact_fields.into_iter().collect()
    );
}

#[test]
fn lossless_records_feed_protocol_kernels_and_public_projections() {
    let definition = definition();
    let kernel = definition.kernel().expect("definition kernel");
    assert_eq!(kernel.id, definition.id);
    assert_eq!(kernel.steps[0].protocol_step, "create_offer");
    let projected = definition.projection().expect("definition projection");
    assert_eq!(projected.deployment_profile_ids.len(), 2);
    assert_eq!(projected.trust_profile_id.as_deref(), Some("trust-1"));

    let instance = instance();
    let kernel = instance.kernel().expect("instance kernel");
    assert_eq!(kernel.state_history.len(), 1);
    assert_eq!(kernel.state_history[0].timestamp_ms, 1_787_229_296_000);
    let projected = instance.projection().expect("instance projection");
    assert_eq!(projected.state_history, instance.state_history);

    let artifact = artifact();
    let projected = artifact.projection().expect("artifact projection");
    assert_eq!(projected.status, "active");
    assert_eq!(projected.attempt_number, 2);
}

#[test]
fn malformed_persisted_state_fails_closed() {
    let mut definition = definition();
    definition.transitions[0]["condition"] = json!("unknown");
    assert!(matches!(
        definition.kernel(),
        Err(FlowRecordError::InvalidStoredState(_))
    ));

    let mut instance = instance();
    instance.context = json!([]);
    assert_eq!(
        instance.kernel(),
        Err(FlowRecordError::InvalidStoredState(
            "instance.context".into()
        ))
    );

    let mut artifact = artifact();
    artifact.wallet_metadata = json!([]);
    assert!(matches!(
        artifact.projection(),
        Err(FlowRecordError::Projection(_))
    ));
}
