use chrono::{TimeZone, Utc};
use marty_flow::{
    advance_instance_record, create_definition_record, parse_request, start_instance_record,
    start_instance_record_with_trusted_context, AdvanceFlowRequest, CreateFlowDefinitionRequest,
    DefinitionStatus, StartFlowRequest,
};
use marty_verification::flow::FlowInstanceStatus;
use serde::Deserialize;
use serde_json::{json, Map};

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    start_definition_status: String,
    start_tenant_behavior: String,
    initial_status_with_entry_step: String,
    initial_state_history: InitialHistory,
    expiry_source: String,
    protocol_context_fields: Vec<String>,
    public_context_private_keys: String,
    advance_statuses: Vec<String>,
    next_step_selection: String,
    awaiting_wallet_event: String,
    terminal_without_transition: TerminalBehavior,
    application_approved_precondition: String,
    unknown_precondition: String,
    failure_behavior: String,
}

#[derive(Deserialize)]
struct InitialHistory {
    prior_state: Option<String>,
    event: String,
}

#[derive(Deserialize)]
struct TerminalBehavior {
    success: String,
    failure: String,
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap()
}

fn active_oid4vp() -> marty_flow::FlowDefinitionRecord {
    let request: CreateFlowDefinitionRequest = parse_request(json!({
        "organization_id": "org-1",
        "name": "Presentation",
        "flow_type": "oid4vp_presentation",
        "presentation_policy_id": "policy-1"
    }))
    .unwrap();
    let mut definition = create_definition_record(request, now()).unwrap();
    definition.status = DefinitionStatus::Active;
    definition
}

fn start_request() -> StartFlowRequest {
    parse_request(json!({
        "organization_id": "org-1",
        "flow_definition_id": "placeholder",
        "subject_id": "subject-1",
        "initial_context": {"application": {"id": "application-1"}}
    }))
    .unwrap()
}

#[test]
fn language_neutral_instance_contract_drives_start_and_advance() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/flow-instance-execution-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.start_definition_status, "active_only");
    assert_eq!(contract.start_tenant_behavior, "exact_match_or_not_found");
    assert_eq!(contract.initial_status_with_entry_step, "in_progress");
    assert_eq!(contract.initial_state_history.prior_state, None);
    assert_eq!(
        contract.initial_state_history.event,
        "flow_instance_created"
    );
    assert_eq!(contract.expiry_source, "definition.default_timeout_seconds");
    assert_eq!(contract.protocol_context_fields.len(), 4);
    assert_eq!(contract.public_context_private_keys, "reject_recursively");
    assert_eq!(
        contract.advance_statuses,
        ["in_progress", "awaiting_wallet"]
    );
    assert_eq!(
        contract.next_step_selection,
        "marty_verification.select_next_step"
    );
    assert_eq!(
        contract.awaiting_wallet_event,
        "wallet_step_response_received"
    );
    assert_eq!(contract.terminal_without_transition.success, "completed");
    assert_eq!(contract.terminal_without_transition.failure, "failed");
    assert_eq!(
        contract.application_approved_precondition,
        "authenticated_server_evidence_only"
    );
    assert_eq!(contract.unknown_precondition, "fail_closed");
    assert_eq!(contract.failure_behavior, "fail_closed");

    let definition = active_oid4vp();
    let mut request = start_request();
    request.flow_definition_id.clone_from(&definition.id);
    let mut instance = start_instance_record(&definition, request, "user-1", now()).unwrap();
    assert_eq!(instance.status, FlowInstanceStatus::InProgress);
    assert_eq!(
        instance.expires_at.unwrap().timestamp() - now().timestamp(),
        600
    );
    assert!(instance.state_history[0]["prior_state"].is_null());
    for field in contract.protocol_context_fields {
        assert!(instance.context.get(&field).is_some(), "missing {field}");
    }

    for expected_step in [
        "wallet_selection",
        "presentation_submission",
        "verify_presentation",
    ] {
        let request: AdvanceFlowRequest = parse_request(json!({"step_result": "success"})).unwrap();
        instance =
            advance_instance_record(&definition, &instance, request, "user-1", now()).unwrap();
        assert_eq!(instance.context["current_step_name"], expected_step);
    }
    let request: AdvanceFlowRequest = parse_request(json!({"step_result": "success"})).unwrap();
    instance = advance_instance_record(&definition, &instance, request, "user-1", now()).unwrap();
    assert_eq!(instance.status, FlowInstanceStatus::Completed);
    assert!(instance.completed_at.is_some());
}

#[test]
fn inactive_cross_tenant_private_and_failure_paths_are_closed() {
    let mut definition = active_oid4vp();
    let mut request = start_request();
    request.flow_definition_id.clone_from(&definition.id);
    definition.status = DefinitionStatus::Draft;
    assert!(start_instance_record(&definition, request.clone(), "user-1", now()).is_err());

    definition.status = DefinitionStatus::Active;
    request.organization_id = "org-2".into();
    assert!(start_instance_record(&definition, request, "user-1", now()).is_err());
    assert!(parse_request::<StartFlowRequest>(json!({
        "organization_id": "org-1",
        "flow_definition_id": definition.id,
        "initial_context": {"nested": {"access_token": "secret"}}
    }))
    .is_err());

    let mut request = start_request();
    request.flow_definition_id.clone_from(&definition.id);
    let instance = start_instance_record(&definition, request, "user-1", now()).unwrap();
    let failure: AdvanceFlowRequest = parse_request(json!({"step_result": "failure"})).unwrap();
    let failed = advance_instance_record(&definition, &instance, failure, "user-1", now()).unwrap();
    assert_eq!(failed.status, FlowInstanceStatus::Failed);
    assert_eq!(
        failed.error.as_deref(),
        Some("Step failed with no recovery transition")
    );
}

#[test]
fn application_approval_requires_trusted_evidence() {
    let request: CreateFlowDefinitionRequest = parse_request(json!({
        "organization_id": "org-1",
        "name": "Approved issuance",
        "flow_type": "custom",
        "trigger": {"trigger_type": "WEBHOOK", "config": {"event_type": "APPLICATION_APPROVED"}},
        "extension": {
            "extension_uri": "urn:marty:flow:approved",
            "extension_version": "1",
            "extends_flow_type": "oid4vci_pre_authorized",
            "entry_step_id": "issue",
            "steps": [{"step_id": "issue", "action": "issuance.issue"}]
        }
    }))
    .unwrap();
    let mut definition = create_definition_record(request, now()).unwrap();
    definition.status = DefinitionStatus::Active;
    let mut start = start_request();
    start.flow_definition_id.clone_from(&definition.id);
    assert!(start_instance_record(&definition, start.clone(), "user-1", now()).is_err());

    let digest = "a".repeat(64);
    let trusted = Map::from_iter([(
        "_marty_precondition_evidence_v1".into(),
        json!({"application_approved": {
            "producer": "marty-applicant-service",
            "audience": "marty-flow-application-approved",
            "event_id_sha256": digest,
            "payload_sha256": "b".repeat(64),
            "authenticated_at": now().to_rfc3339()
        }}),
    )]);
    let instance = start_instance_record_with_trusted_context(
        &definition,
        start,
        "marty-applicant-service",
        now(),
        trusted,
    )
    .unwrap();
    assert_eq!(instance.status, FlowInstanceStatus::InProgress);
    assert!(instance.context["_marty_precondition_evidence_v1"].is_object());
}
