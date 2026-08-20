use std::collections::BTreeMap;

use marty_flow::*;
use marty_verification::flow::{evaluate_transition, FlowInstanceStatus, FlowTransitionRequest};
use mmf_messaging::InMemoryDeliveryStore;
use mmf_push::{verify_event_signature, WebhookDestinationRegistry};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    http_routes: Vec<[String; 2]>,
    grpc_methods: Vec<String>,
    flow_types: BTreeMap<String, FlowTypeCase>,
    status_projection: BTreeMap<String, String>,
    transition_cases: Vec<TransitionCase>,
    private_context: PrivateContextCase,
    verification_finalization: Value,
    application_offer_idempotency: Value,
    callback_outbox: CallbackOutboxCase,
}

#[derive(Deserialize)]
struct FlowTypeCase {
    category: Option<FlowCategory>,
    required: Vec<String>,
    steps: Vec<String>,
}

#[derive(Deserialize)]
struct TransitionCase {
    current: FlowInstanceStatus,
    target: FlowInstanceStatus,
    allowed: bool,
    terminal: Option<bool>,
}

#[derive(Deserialize)]
struct PrivateContextCase {
    prefix: String,
    keys: Vec<String>,
}

#[derive(Deserialize)]
struct CallbackOutboxCase {
    event_type: String,
    audience: String,
    default_retention_seconds: u64,
    default_max_attempts: u32,
    default_lease_seconds: u64,
    default_poll_milliseconds: u64,
    retry_base_seconds: u64,
    retry_cap_seconds: u64,
}

fn contract() -> Contract {
    serde_json::from_str(include_str!(
        "../../../../contracts/flow-service-behavior.json"
    ))
    .expect("valid Flow behavior contract")
}

#[test]
fn complete_transport_surface_is_frozen() {
    let contract = contract();
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.http_routes.len(), 26);
    assert_eq!(contract.grpc_methods.len(), 16);
    assert_eq!(
        contract.http_routes,
        HTTP_ROUTES
            .iter()
            .map(|(method, path)| [(*method).to_owned(), (*path).to_owned()])
            .collect::<Vec<_>>()
    );
    assert_eq!(
        contract.grpc_methods,
        GRPC_METHODS
            .iter()
            .map(|method| (*method).to_owned())
            .collect::<Vec<_>>()
    );
}

#[test]
fn all_flow_types_references_and_sequences_match_the_behavior_contract() {
    let contract = contract();
    assert_eq!(contract.flow_types.len(), 12);
    for (name, case) in contract.flow_types {
        let flow_type: FlowType =
            serde_json::from_value(Value::String(name)).expect("known flow type");
        assert_eq!(flow_type.category(), case.category);
        assert_eq!(
            flow_type.required_references(),
            case.required.iter().map(String::as_str).collect::<Vec<_>>()
        );
        assert_eq!(
            flow_type.sequence(),
            case.steps.iter().map(String::as_str).collect::<Vec<_>>()
        );
    }
    assert_eq!(FlowType::all().count(), 12);
}

#[test]
fn lifecycle_and_public_status_delegate_to_the_canonical_core() {
    let contract = contract();
    for (status, expected) in contract.status_projection {
        let status: FlowInstanceStatus =
            serde_json::from_value(Value::String(status)).expect("known status");
        assert_eq!(public_status(status), expected);
    }
    for case in contract.transition_cases {
        let result = evaluate_transition(FlowTransitionRequest {
            current: case.current,
            target: case.target,
            actor: None,
            event: None,
        });
        assert_eq!(result.is_ok(), case.allowed);
        if let (Ok(decision), Some(terminal)) = (result, case.terminal) {
            assert_eq!(decision.terminal, terminal);
        }
    }
}

#[test]
fn private_context_is_rejected_and_recursively_removed_from_public_results() {
    let contract = contract();
    assert_eq!(contract.private_context.prefix, "_marty_");
    for key in contract.private_context.keys {
        let input = json!({"public": {key.clone(): "secret"}});
        assert!(reject_private_context(&input).is_err(), "key {key}");
        assert_eq!(public_context(&input), json!({"public": {}}));
    }
    let prefixed = json!({"items": [{"_marty_private": "secret", "ok": true}]});
    assert!(reject_private_context(&prefixed).is_err());
    assert_eq!(public_context(&prefixed), json!({"items": [{"ok": true}]}));
}

#[test]
fn built_in_definitions_require_references_and_use_the_core_graph_validator() {
    let missing = FlowDefinition::built_in(
        "org-1",
        "Issue",
        FlowType::Oid4vciPreAuthorized,
        BTreeMap::new(),
    );
    assert!(missing.is_err());
    let definition = FlowDefinition::built_in(
        "org-1",
        "Issue",
        FlowType::Oid4vciPreAuthorized,
        BTreeMap::from([("credential_template_id".into(), "template-1".into())]),
    )
    .expect("valid built-in flow");
    definition.validate_graph().expect("valid core graph");
    assert_eq!(
        definition
            .steps
            .iter()
            .map(|step| step.protocol_step.as_str())
            .collect::<Vec<_>>(),
        FlowType::Oid4vciPreAuthorized.sequence()
    );
}

#[test]
fn callback_defaults_and_atomicity_obligations_are_explicit() {
    let contract = contract();
    let callback = contract.callback_outbox;
    assert_eq!(callback.event_type, CALLBACK_EVENT_TYPE);
    assert_eq!(callback.audience, CALLBACK_AUDIENCE);
    assert_eq!(
        callback.default_retention_seconds,
        CALLBACK_RETENTION_SECONDS
    );
    assert_eq!(callback.default_max_attempts, CALLBACK_MAX_ATTEMPTS);
    assert_eq!(callback.default_lease_seconds, CALLBACK_LEASE_SECONDS);
    assert_eq!(
        callback.default_poll_milliseconds,
        CALLBACK_POLL_MILLISECONDS
    );
    assert_eq!(callback.retry_base_seconds, CALLBACK_RETRY_BASE_SECONDS);
    assert_eq!(callback.retry_cap_seconds, CALLBACK_RETRY_CAP_SECONDS);
    assert_eq!(callback_retry_delay_seconds(1), 1);
    assert_eq!(callback_retry_delay_seconds(7), 60);
    assert_eq!(callback_retry_delay_seconds(u32::MAX), 60);
    assert_eq!(
        contract.verification_finalization["atomic_writes"],
        json!(["nonce_consumption", "terminal_instance", "callback_outbox"])
    );
    assert_eq!(
        contract.application_offer_idempotency["different_payload"],
        "conflict"
    );
}

#[test]
fn callback_delivery_composes_shared_registry_signature_and_fenced_outbox() {
    let destinations =
        WebhookDestinationRegistry::parse("org-1|https://callbacks.example/flows/__MARTY_TOKEN__")
            .unwrap();
    let event = CallbackEvent::new(
        "abcdefghijklmnop",
        "org-1",
        "https://callbacks.example/flows/abcdefghijklmnop",
        json!({"instance_id": "abcdefghijklmnop", "decision": "allow"}),
        1_000,
        &destinations,
    )
    .unwrap();
    let headers = event
        .delivery_headers(
            "shared-secret-at-least-32-bytes-long",
            "2026-08-08T16:00:00+00:00",
            1,
        )
        .unwrap();
    assert!(verify_event_signature(
        &headers["X-MIP-Signature"],
        "shared-secret-at-least-32-bytes-long",
        CALLBACK_AUDIENCE,
        CALLBACK_EVENT_TYPE,
        "abcdefghijklmnop",
        "2026-08-08T16:00:00+00:00",
        &event.payload,
    ));

    let mut outbox = InMemoryDeliveryStore::default();
    outbox
        .enqueue(event.into_outbox_message(), 1)
        .expect("enqueue once");
    let claimed = outbox.claim_due(1_000, 30_000, 1, None).unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].attempt_count, 1);
    assert_eq!(claimed[0].message.max_retries, 9);
    assert_eq!(
        claimed[0].message.reply_to.as_deref(),
        Some("https://callbacks.example/flows/abcdefghijklmnop")
    );
    assert!(CallbackEvent::new(
        "abcdefghijklmnop",
        "org-2",
        "https://callbacks.example/flows/abcdefghijklmnop",
        json!({}),
        1_000,
        &destinations,
    )
    .is_err());
}
