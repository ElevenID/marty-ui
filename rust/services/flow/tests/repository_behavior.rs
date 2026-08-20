use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};

use marty_flow::*;
use marty_verification::flow::FlowInstanceStatus;
use mmf_push::WebhookDestinationRegistry;
use serde_json::json;

fn instance(id: &str, status: FlowInstanceStatus) -> FlowInstance {
    FlowInstance {
        id: id.into(),
        flow_definition_id: "definition-1".into(),
        organization_id: "org-1".into(),
        status,
        current_step_id: Some("verify".into()),
        application_flow_key_hash: None,
        context: json!({}),
        state_history: Vec::new(),
        expires_at_ms: Some(10_000),
        completed_at_ms: None,
    }
}

fn callback(id: &str) -> mmf_messaging::Message {
    let destinations =
        WebhookDestinationRegistry::parse("org-1|https://callbacks.example/flows/__MARTY_TOKEN__")
            .unwrap();
    CallbackEvent::new(
        id,
        "org-1",
        format!("https://callbacks.example/flows/{id}"),
        json!({"instance_id": id, "decision": "allow"}),
        1_000,
        &destinations,
    )
    .unwrap()
    .into_outbox_message()
}

#[test]
fn terminal_result_nonce_and_callback_commit_once_under_concurrency() {
    let repository = Arc::new(InMemoryFlowRepository::default());
    repository
        .save_instance(instance(
            "abcdefghijklmnop",
            FlowInstanceStatus::AwaitingWallet,
        ))
        .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let handles = ["allow", "deny"].map(|decision| {
        let repository = Arc::clone(&repository);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            let mut terminal = instance("abcdefghijklmnop", FlowInstanceStatus::Completed);
            terminal.context = json!({"decision": decision});
            terminal.completed_at_ms = Some(2_000);
            barrier.wait();
            repository
                .finalize_verification(
                    terminal,
                    &"a".repeat(64),
                    10_000,
                    FlowInstanceStatus::AwaitingWallet,
                    Some(callback("abcdefghijklmnop")),
                    2_000,
                )
                .unwrap()
        })
    });
    barrier.wait();
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results.into_iter().filter(|accepted| *accepted).count(), 1);
    assert!(repository.callback("abcdefghijklmnop").unwrap().is_some());
    let terminal = repository.instance("abcdefghijklmnop").unwrap().unwrap();
    assert_eq!(terminal.status, FlowInstanceStatus::Completed);

    let mut stale = instance("abcdefghijklmnop", FlowInstanceStatus::InProgress);
    stale.context = json!({"decision": "stale"});
    repository.save_instance(stale).unwrap();
    assert_eq!(
        repository.instance("abcdefghijklmnop").unwrap().unwrap(),
        terminal
    );
}

#[test]
fn finalization_rejects_replay_expiry_and_mismatched_callback_identity() {
    let repository = InMemoryFlowRepository::default();
    repository
        .save_instance(instance(
            "abcdefghijklmnop",
            FlowInstanceStatus::AwaitingWallet,
        ))
        .unwrap();
    assert!(repository
        .finalize_verification(
            instance("abcdefghijklmnop", FlowInstanceStatus::Completed),
            "invalid",
            10_000,
            FlowInstanceStatus::AwaitingWallet,
            None,
            2_000,
        )
        .is_err());
    let mut wrong_callback = callback("qrstuvwxyzabcdef");
    wrong_callback.metadata.tenant_id = Some("org-1".into());
    assert!(repository
        .finalize_verification(
            instance("abcdefghijklmnop", FlowInstanceStatus::Completed),
            &"b".repeat(64),
            10_000,
            FlowInstanceStatus::AwaitingWallet,
            Some(wrong_callback),
            2_000,
        )
        .is_err());

    let expired = InMemoryFlowRepository::default();
    let mut candidate = instance("abcdefghijklmnop", FlowInstanceStatus::AwaitingWallet);
    candidate.expires_at_ms = Some(1_999);
    expired.save_instance(candidate).unwrap();
    assert!(!expired
        .finalize_verification(
            instance("abcdefghijklmnop", FlowInstanceStatus::Completed),
            &"c".repeat(64),
            10_000,
            FlowInstanceStatus::AwaitingWallet,
            None,
            2_000,
        )
        .unwrap());
}

fn planned_instance(id: &str, semantics: &str) -> PlannedApplicationFlow {
    let mut candidate = instance(id, FlowInstanceStatus::InProgress);
    candidate.application_flow_key_hash = Some("d".repeat(64));
    candidate.context = json!({"_marty_application_offer_semantics_hash_v1": semantics});
    PlannedApplicationFlow {
        instance: candidate,
        plan_entry: BTreeMap::from([
            ("flow_id".into(), "definition-1".into()),
            ("offer_semantics_hash".into(), semantics.into()),
        ]),
    }
}

fn receipt(event: char, payload: char) -> ApplicationEventReceipt {
    ApplicationEventReceipt {
        event_id_sha256: event.to_string().repeat(64),
        payload_sha256: payload.to_string().repeat(64),
        organization_id: "org-1".into(),
        application_id: "application-1".into(),
        flow_plan: Vec::new(),
        created_at_ms: 1_000,
        updated_at_ms: 1_000,
    }
}

#[test]
fn application_offer_plan_is_durable_idempotent_and_conflict_safe() {
    let repository = InMemoryFlowRepository::default();
    let (first, created) = repository
        .reserve_application_event_plan(
            receipt('a', 'b'),
            vec![planned_instance("instance-first", &"c".repeat(64))],
        )
        .unwrap();
    assert!(created);
    assert_eq!(first.flow_plan[0]["instance_id"], "instance-first");

    let (replay, created) = repository
        .reserve_application_event_plan(
            receipt('a', 'b'),
            vec![planned_instance("instance-ignored", &"c".repeat(64))],
        )
        .unwrap();
    assert!(!created);
    assert_eq!(replay, first);
    assert!(repository
        .reserve_application_event_plan(
            receipt('a', 'd'),
            vec![planned_instance("instance-conflict", &"c".repeat(64))],
        )
        .is_err());

    let (second_event, created) = repository
        .reserve_application_event_plan(
            receipt('e', 'f'),
            vec![planned_instance("instance-second", &"c".repeat(64))],
        )
        .unwrap();
    assert!(created);
    assert_eq!(second_event.flow_plan[0]["instance_id"], "instance-first");
    assert!(repository
        .reserve_application_event_plan(
            receipt('f', 'a'),
            vec![planned_instance("instance-new", &"e".repeat(64))],
        )
        .is_err());
}

#[test]
fn issuance_artifacts_are_idempotent_by_transaction_and_tenant_safe() {
    let repository = InMemoryFlowRepository::default();
    let first = FlowArtifact {
        id: "artifact-1".into(),
        flow_instance_id: "flow-1".into(),
        issuance_transaction_id: Some("transaction-1".into()),
        payload: json!({"status": "created"}),
        expires_at_ms: Some(10_000),
        attempt_number: 1,
    };
    repository.save_artifact(first).unwrap();
    let replay = repository
        .save_artifact(FlowArtifact {
            id: "artifact-2".into(),
            flow_instance_id: "flow-1".into(),
            issuance_transaction_id: Some("transaction-1".into()),
            payload: json!({"status": "ready"}),
            expires_at_ms: Some(10_000),
            attempt_number: 2,
        })
        .unwrap();
    assert_eq!(replay.id, "artifact-1");
    assert_eq!(replay.payload, json!({"status": "ready"}));
    assert!(repository
        .save_artifact(FlowArtifact {
            id: "artifact-3".into(),
            flow_instance_id: "flow-2".into(),
            issuance_transaction_id: Some("transaction-1".into()),
            payload: json!({}),
            expires_at_ms: None,
            attempt_number: 1,
        })
        .is_err());
}
