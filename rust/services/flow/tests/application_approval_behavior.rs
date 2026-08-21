use chrono::{TimeZone, Utc};
use marty_flow::{
    application_flow_logical_key, create_definition_record, parse_request,
    prepare_application_event_plan, ApplicationApprovedWebhook, CreateFlowDefinitionRequest,
    DefinitionStatus,
};
use mmf_security::{
    ApplicationEventEvidence, APPLICATION_EVENT_AUDIENCE, APPLICATION_EVENT_PRODUCER,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    event_type: String,
    aggregate_type: String,
    authentication_owner: String,
    authentication_order: Vec<String>,
    eligible_definition: String,
    definition_order: String,
    template_filter: String,
    claims: String,
    manual_issue_requires_attempt_id: bool,
    attempt_id: String,
    logical_key_v1: KeyVector,
    logical_key_v2: KeyVector,
    semantics: String,
    reserved_instance: ReservedInstance,
    same_event_same_payload: String,
    same_event_different_payload: String,
    same_logical_flow_different_semantics: String,
    python_fallback: String,
}

#[derive(Deserialize)]
struct KeyVector {
    fields: Vec<String>,
    issuance_attempt_id: Option<String>,
    expected: String,
}

#[derive(Deserialize)]
struct ReservedInstance {
    status: String,
    subject_type: String,
    external_reference_prefix: String,
    raw_event_id_retained: bool,
}

fn now() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_786_291_200, 0).unwrap()
}

fn evidence() -> ApplicationEventEvidence {
    ApplicationEventEvidence {
        producer: APPLICATION_EVENT_PRODUCER.into(),
        audience: APPLICATION_EVENT_AUDIENCE.into(),
        event_id_sha256: "a".repeat(64),
        payload_sha256: "b".repeat(64),
        authenticated_at: now().to_rfc3339(),
    }
}

fn event() -> ApplicationApprovedWebhook {
    parse_request(json!({
        "event_type": "application.approved",
        "aggregate_id": "application-1",
        "aggregate_type": "application",
        "organization_id": "org-1",
        "data": {
            "applicant_id": "applicant-1",
            "email": "ada@example.com",
            "claims": {"given_name": "Ada", "roles": ["member"]}
        },
        "timestamp": "2026-08-09T12:00:00+00:00"
    }))
    .unwrap()
}

fn definition(id: &str, template: &str) -> marty_flow::FlowDefinitionRecord {
    let request: CreateFlowDefinitionRequest = parse_request(json!({
        "organization_id": "org-1",
        "name": format!("Approved issuance {id}"),
        "flow_type": "custom",
        "credential_template_id": template,
        "trigger": {"trigger_type": "WEBHOOK", "config": {"event_type": "APPLICATION_APPROVED"}},
        "extension": {
            "extension_uri": format!("urn:marty:flow:{id}"),
            "extension_version": "1",
            "extends_flow_type": "oid4vci_pre_authorized",
            "entry_step_id": "issue",
            "steps": [{"step_id": "issue", "action": "issuance.issue"}]
        }
    }))
    .unwrap();
    let mut definition = create_definition_record(request, now()).unwrap();
    definition.id = id.into();
    definition.status = DefinitionStatus::Active;
    definition
}

fn contract() -> Contract {
    serde_json::from_str(include_str!(
        "../../../../contracts/flow-application-approved-behavior.json"
    ))
    .unwrap()
}

#[test]
fn language_neutral_contract_and_logical_keys_are_stable() {
    let contract = contract();
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.event_type, "application.approved");
    assert_eq!(contract.aggregate_type, "application");
    assert_eq!(
        contract.authentication_owner,
        "mmf-security.application_event"
    );
    assert_eq!(contract.authentication_order.len(), 4);
    assert_eq!(
        contract.eligible_definition,
        "active_oid4vci_pre_authorized_with_application_approved_webhook_trigger"
    );
    assert_eq!(contract.definition_order, "flow_id_ascending");
    assert_eq!(contract.template_filter, "exact_when_present");
    assert_eq!(contract.claims, "object_only");
    assert!(contract.manual_issue_requires_attempt_id);
    assert_eq!(contract.attempt_id, "canonical_lowercase_uuid");
    assert_eq!(contract.logical_key_v1.fields.len(), 3);
    assert_eq!(contract.logical_key_v2.fields.len(), 4);
    assert_eq!(
        contract.semantics,
        "canonical_complete_definition_applicant_and_claims_snapshot"
    );
    assert_eq!(contract.reserved_instance.status, "in_progress");
    assert_eq!(contract.reserved_instance.subject_type, "applicant");
    assert_eq!(
        contract.reserved_instance.external_reference_prefix,
        "application-flow:"
    );
    assert!(!contract.reserved_instance.raw_event_id_retained);
    assert_eq!(contract.same_event_same_payload, "recover_reserved_plan");
    assert_eq!(contract.same_event_different_payload, "conflict");
    assert_eq!(contract.same_logical_flow_different_semantics, "conflict");
    assert_eq!(contract.python_fallback, "forbidden");

    assert_eq!(
        application_flow_logical_key("org-1", "application-1", None, "flow-1").unwrap(),
        contract.logical_key_v1.expected
    );
    assert_eq!(
        application_flow_logical_key(
            "org-1",
            "application-1",
            contract.logical_key_v2.issuance_attempt_id.as_deref(),
            "flow-1"
        )
        .unwrap(),
        contract.logical_key_v2.expected
    );
}

#[test]
fn plan_filters_orders_and_minimizes_authenticated_events() {
    let definitions = vec![
        definition("flow-z", "template-2"),
        definition("flow-b", "template-1"),
        definition("flow-a", "template-1"),
    ];
    let mut event = event();
    event.data.insert(
        "credential_template_id".into(),
        Value::String("template-1".into()),
    );
    let plan = prepare_application_event_plan(&event, &evidence(), &definitions, now()).unwrap();
    assert_eq!(plan.planned_flows.len(), 2);
    assert_eq!(plan.planned_flows[0].instance.flow_definition_id, "flow-a");
    assert_eq!(plan.planned_flows[1].instance.flow_definition_id, "flow-b");
    for planned in plan.planned_flows {
        let instance = planned.instance;
        assert_eq!(instance.subject_id.as_deref(), Some("applicant-1"));
        assert_eq!(instance.subject_type, "applicant");
        assert!(instance
            .external_reference
            .as_deref()
            .unwrap()
            .starts_with("application-flow:"));
        assert_eq!(
            instance.context["_marty_precondition_evidence_v1"]["application_approved"]
                ["event_id_sha256"],
            "a".repeat(64)
        );
        assert!(!instance.context.to_string().contains("f4593698"));
        assert!(planned.plan_entry["offer_semantics_hash"].len() == 64);
    }
}

#[test]
fn manual_attempt_claim_and_semantics_failures_are_closed() {
    let definitions = vec![definition("flow-1", "template-1")];
    let mut manual = event();
    manual.data.insert(
        "triggered_by_event".into(),
        Value::String("application.manual_issue".into()),
    );
    assert!(prepare_application_event_plan(&manual, &evidence(), &definitions, now()).is_err());
    manual.data.insert(
        "issuance_attempt_id".into(),
        Value::String("11111111-1111-4111-8111-111111111111".into()),
    );
    let plan = prepare_application_event_plan(&manual, &evidence(), &definitions, now()).unwrap();
    assert!(plan.manual_issue);
    assert_eq!(
        plan.planned_flows[0].instance.application_flow_key_hash,
        Some(contract().logical_key_v2.expected)
    );
    assert!(plan.planned_flows[0]
        .instance
        .context
        .get("_marty_application_offer_semantics_hash_v2")
        .is_some());

    let mut invalid_claims = event();
    invalid_claims
        .data
        .insert("claims".into(), Value::Array(Vec::new()));
    assert!(
        prepare_application_event_plan(&invalid_claims, &evidence(), &definitions, now()).is_err()
    );
    let empty: Vec<marty_flow::FlowDefinitionRecord> = Vec::new();
    let no_match = prepare_application_event_plan(&event(), &evidence(), &empty, now()).unwrap();
    assert!(no_match.planned_flows.is_empty());
}

#[test]
fn changed_claims_change_semantics_without_changing_v1_logical_identity() {
    let definitions = vec![definition("flow-1", "template-1")];
    let first = prepare_application_event_plan(&event(), &evidence(), &definitions, now()).unwrap();
    let mut changed = event();
    changed.data.insert(
        "claims".into(),
        Value::Object(Map::from_iter([("given_name".into(), json!("Grace"))])),
    );
    let second =
        prepare_application_event_plan(&changed, &evidence(), &definitions, now()).unwrap();
    assert_eq!(
        first.planned_flows[0].instance.application_flow_key_hash,
        second.planned_flows[0].instance.application_flow_key_hash
    );
    assert_ne!(
        first.planned_flows[0].plan_entry["offer_semantics_hash"],
        second.planned_flows[0].plan_entry["offer_semantics_hash"]
    );
}
