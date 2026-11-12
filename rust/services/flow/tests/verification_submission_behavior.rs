#[path = "support/presentation_snapshot.rs"]
mod presentation_snapshot;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use marty_flow::{
    decrypt_verification_response, prepare_verification_submission, FlowInstanceRecord,
    FlowKeyEnvelopeProvider, FlowProviderError, FlowProviderRegistry,
    FlowVerificationSubmissionError, PreparedVerificationSubmission, PresentationEvaluationRequest,
    PresentationEvaluationResult, PresentationPolicyProvider, PresentationPolicyReference,
    VerificationSubmissionInput, VerificationSubmissionOptions, CALLBACK_MAX_ATTEMPTS,
    CALLBACK_RETENTION_SECONDS,
};
#[path = "support/haip_remote_fixture.rs"]
mod haip_remote_fixture;
use marty_verification::flow::FlowInstanceStatus;
use mmf_push::WebhookDestinationRegistry;
use serde_json::{json, Value};

#[derive(Clone)]
struct Policies {
    response: Result<PresentationEvaluationResult, FlowProviderError>,
    seen: Arc<Mutex<Vec<PresentationEvaluationRequest>>>,
}

#[async_trait]
impl PresentationPolicyProvider for Policies {
    async fn get_policy(
        &self,
        policy_id: &str,
    ) -> Result<PresentationPolicyReference, FlowProviderError> {
        Ok(PresentationPolicyReference {
            prerequisite_evidence_profile: None,
            credential_authority: None,
            policy_revision: presentation_snapshot::revision(policy_id),
            id: policy_id.into(),
            organization_id: "org-1".into(),
            status: "active".into(),
            credential_requirements: vec![json!({"credential_type": "MemberCredential"})],
        })
    }

    async fn evaluate(
        &self,
        request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        self.seen.lock().unwrap().push(request.clone());
        self.response.clone()
    }
}

struct RemoteEnvelopes;

#[async_trait]
impl FlowKeyEnvelopeProvider for RemoteEnvelopes {
    async fn decrypt_haip_response(
        &self,
        organization_id: &str,
        flow_instance_id: &str,
        version: &str,
        jwe: &str,
    ) -> Result<Vec<u8>, FlowProviderError> {
        assert_eq!(organization_id, "org-1");
        assert_eq!(flow_instance_id, "abcdefghijklmnop");
        assert_eq!(version, haip_remote_fixture::VERSION);
        assert!(jwe.contains('.'));
        Ok(br#"{"vp_token":"remote-fixture"}"#.to_vec())
    }
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap()
}

fn instance(callback: bool) -> FlowInstanceRecord {
    let mut context = json!({
        "flow_type": "verification",
        "nonce": "nonce-with-at-least-32-bytes-1234567890",
        "oid4vp_expected_state": "state-1",
        "oid4vp_verifier_context": true,
        "oid4vp_client_id": "did:web:verifier.example",
        "presentation_policy_id": "policy-1",
        "_marty_verification_principal_id": "user-1",
        "verification_audience": "did:web:verifier.example",
        "trust_profile_id": "trust-1",
        "vp_token": "must-be-removed",
        "presentation_submission": {"must": "be-removed"}
    });
    if callback {
        context["callback_url"] = json!("https://callbacks.example/flows/abcdefghijklmnop");
    }
    let mut instance = FlowInstanceRecord {
        id: "abcdefghijklmnop".into(),
        flow_definition_id: "definition-1".into(),
        organization_id: "org-1".into(),
        status: FlowInstanceStatus::AwaitingWallet,
        current_step_id: None,
        context,
        step_history: Vec::new(),
        state_history: Vec::new(),
        subject_id: None,
        subject_type: "holder".into(),
        external_reference: None,
        application_flow_key_hash: None,
        started_at: Some(now()),
        completed_at: None,
        expires_at: Some(now() + Duration::minutes(15)),
        result: None,
        error: None,
        created_at: now(),
        updated_at: now(),
    };
    presentation_snapshot::freeze_default(&mut instance);
    presentation_snapshot::emit_query(
        &mut instance,
        "dcql_query",
        json!({"credentials": [{"id": "member", "format": "dc+sd-jwt"}]}),
    );
    instance
}

fn with_emitted_query(
    mut instance: FlowInstanceRecord,
    field: &str,
    query: Value,
) -> FlowInstanceRecord {
    presentation_snapshot::emit_query(&mut instance, field, query);
    instance
}

#[tokio::test]
async fn mdoc_binding_diagnostic_retains_only_existing_audit_hashes() {
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let output = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(output.clone());
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let mut original = instance(false);
    let response_uri = "https://verifier.example/private-fixture-response";
    original.context["oid4vp_response_uri"] = json!(response_uri);
    let original_id = original.id.clone();
    let nonce = original.context["nonce"].as_str().unwrap().to_owned();
    let client_id = original.context["oid4vp_client_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let presentation = "private-fixture-presentation";
    let (ports, _) = providers(Ok(allowed()));
    let _ = prepare_verification_submission(
        &ports,
        original,
        input(presentation),
        &options(None),
        now(),
    )
    .await
    .unwrap();
    let captured = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    let events = captured
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|event| {
            event["fields"]["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("OID4VP mdoc binding "))
        })
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1);
    let message = events[0]["fields"]["message"].as_str().unwrap();
    for private in [
        original_id.as_str(),
        nonce.as_str(),
        client_id.as_str(),
        response_uri,
        presentation,
    ] {
        assert!(!message.contains(private));
    }
    assert!(message.contains("response_key_thumbprint_sha256=none"));
    println!("PINNED_MDOC_AUDIT_EVENT={}", events[0]);
}

#[tokio::test]
async fn managed_owner_snapshot_reaches_policy_and_changed_authority_requires_restart() {
    let authority = presentation_snapshot::authority("org-1");
    let mut managed = instance(false);
    managed.context[presentation_snapshot::SNAPSHOT_KEY]["credential_authority"] = json!(authority);
    let mut evaluation = allowed();
    evaluation.evaluation_timestamp = Some(now().to_rfc3339());
    let (ports, seen) = providers(Ok(evaluation));
    let mut wallet = input("header.payload.signature");
    wallet.presentation_submission = None;
    prepare_verification_submission(
        &ports,
        managed.clone(),
        wallet.clone(),
        &options(None),
        now(),
    )
    .await
    .unwrap();
    assert_eq!(
        seen.lock().unwrap()[0]
            .oid4vp_transport
            .as_ref()
            .unwrap()
            .credential_authority,
        Some(authority)
    );
    let (changed, _) = providers(Err(FlowProviderError::CredentialAuthorityChanged));
    assert!(matches!(
        prepare_verification_submission(&changed, managed, wallet, &options(None), now()).await,
        Err(FlowVerificationSubmissionError::RestartRequired)
    ));
}

fn allowed() -> PresentationEvaluationResult {
    PresentationEvaluationResult {
        evaluation_timestamp: None,
        policy_revision: presentation_snapshot::revision("policy-1"),
        authentication_diagnostic: None,
        result: "passed".into(),
        decision: "allow".into(),
        decision_reason: Some("requirements satisfied".into()),
        verified_claims: [("given_name".into(), json!("Avery"))].into(),
        credential_results: vec![json!({
            "signature_valid": true,
            "revocation_checked": true,
            "not_revoked": true,
            "trust_check_passed": true,
            "warnings": ["credential-warning"]
        })],
        error_codes: vec!["policy-code".into()],
        warnings: vec!["policy-warning".into()],
    }
}

fn providers(
    response: Result<PresentationEvaluationResult, FlowProviderError>,
) -> (
    FlowProviderRegistry,
    Arc<Mutex<Vec<PresentationEvaluationRequest>>>,
) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    (
        FlowProviderRegistry {
            presentation_policy: Some(Arc::new(Policies {
                response,
                seen: Arc::clone(&seen),
            })),
            ..Default::default()
        },
        seen,
    )
}

fn options(secret: Option<&str>) -> VerificationSubmissionOptions {
    VerificationSubmissionOptions {
        callback_destinations: WebhookDestinationRegistry::parse(
            "org-1|https://callbacks.example/flows/__MARTY_TOKEN__",
        )
        .unwrap(),
        callback_secret: secret.map(str::to_owned),
        verifier_sender_id: "did:web:verifier.example".into(),
        nonce_ttl_seconds: 900,
        callback_retention_seconds: CALLBACK_RETENTION_SECONDS,
        callback_max_attempts: CALLBACK_MAX_ATTEMPTS,
    }
}

fn input(token: &str) -> VerificationSubmissionInput {
    VerificationSubmissionInput {
        vp_token: token.into(),
        presentation_submission: None,
        state: Some("state-1".into()),
        audience_override: None,
    }
}

async fn receipt_preparation(allow: bool) -> marty_flow::PreparedVerificationFinalization {
    let mut evaluation = allowed();
    evaluation.evaluation_timestamp = Some((now() + Duration::seconds(2)).to_rfc3339());
    if !allow {
        evaluation.result = "failed".into();
        evaluation.decision = "deny".into();
        evaluation.decision_reason = Some("requirements not satisfied".into());
    }
    let (ports, _) = providers(Ok(evaluation));
    match prepare_verification_submission(
        &ports,
        instance(true),
        input("header.payload.signature"),
        &options(Some("0123456789abcdef0123456789abcdef")),
        now(),
    )
    .await
    .unwrap()
    {
        PreparedVerificationSubmission::Final(prepared) => *prepared,
        other => panic!("expected terminal preparation: {other:?}"),
    }
}

#[tokio::test]
async fn receipt_records_separate_owner_and_consumption_clocks_only_after_commit() {
    use marty_oid4vp_contract::{
        digest_domain_json, FLOW_REQUEST_BINDING_DIGEST_DOMAIN, VERIFICATION_RECEIPT,
    };
    let prepared = receipt_preparation(true).await;
    assert!(prepared
        .instance
        .result
        .as_ref()
        .unwrap()
        .get(VERIFICATION_RECEIPT)
        .is_none());
    assert!(prepared
        .callback
        .as_ref()
        .unwrap()
        .payload
        .get(VERIFICATION_RECEIPT)
        .is_none());
    let repository = marty_flow::InMemoryFlowRepository::default();
    repository
        .save_instance(prepared.expected_instance.kernel().unwrap())
        .unwrap();
    let consumed_at = now() + Duration::seconds(8);
    let committed = repository
        .finalize_verification_with_receipt(
            &prepared,
            u64::try_from(consumed_at.timestamp_millis()).unwrap(),
        )
        .unwrap()
        .unwrap();
    let receipt = committed.receipt();
    assert_eq!(
        receipt.policy_evaluated_at_epoch_micros,
        (now() + Duration::seconds(2)).timestamp_micros()
    );
    assert_eq!(
        receipt.nonce_consumed_at_epoch_micros,
        consumed_at.timestamp_micros()
    );
    assert_eq!(
        receipt.request_binding_digest,
        digest_domain_json(
            FLOW_REQUEST_BINDING_DIGEST_DOMAIN,
            &prepared.expected_instance
        )
        .unwrap()
    );
    assert_ne!(
        receipt.request_binding_digest,
        digest_domain_json(FLOW_REQUEST_BINDING_DIGEST_DOMAIN, &prepared.instance).unwrap()
    );
    let serialized = serde_json::to_value(receipt).unwrap();
    assert_eq!(
        committed.instance().result.as_ref().unwrap()[VERIFICATION_RECEIPT],
        serialized
    );
    let callback = repository.callback(&prepared.instance.id).unwrap().unwrap();
    assert_eq!(callback.payload[VERIFICATION_RECEIPT], serialized);
    receipt.validate_callback(&callback.payload).unwrap();
    let projected = committed.instance().verification_projection().unwrap();
    assert_eq!(projected.verification_receipt.as_ref(), Some(receipt));
    assert_eq!(
        projected.evaluation_timestamp.as_deref(),
        Some("2026-08-20T12:00:02.000000Z")
    );
    let wire = serde_json::to_string(receipt).unwrap();
    for secret in [
        "header.payload.signature",
        "nonce-with-at-least-32-bytes",
        "Avery",
        "user-1",
        "must-be-removed",
    ] {
        assert!(!wire.contains(secret), "receipt leaked {secret}");
    }
}

#[tokio::test]
async fn receipt_recovery_preserves_the_original_record_after_retention_expiry() {
    let prepared = receipt_preparation(true).await;
    let repository = marty_flow::InMemoryFlowRepository::default();
    repository
        .save_instance(prepared.expected_instance.kernel().unwrap())
        .unwrap();
    let committed = repository
        .finalize_verification_with_receipt(
            &prepared,
            u64::try_from((now() + Duration::seconds(8)).timestamp_millis()).unwrap(),
        )
        .unwrap()
        .unwrap();
    let receipt = committed.receipt().clone();
    assert!(repository
        .finalize_verification_with_receipt(
            &prepared,
            u64::try_from((now() + Duration::hours(1)).timestamp_millis()).unwrap(),
        )
        .unwrap()
        .is_none());
    let (ports, seen) = providers(Err(FlowProviderError::PolicyRevisionMismatch));
    let recovered = prepare_verification_submission(
        &ports,
        committed.instance().clone(),
        input("header.payload.signature"),
        &options(None),
        now() + Duration::hours(1),
    )
    .await
    .unwrap();
    let PreparedVerificationSubmission::SameTerminal(recovered) = recovered else {
        panic!("expected persisted recovery")
    };
    assert_eq!(recovered.verification_receipt, Some(receipt));
    assert!(seen.lock().unwrap().is_empty());
    assert!(matches!(
        prepare_verification_submission(
            &ports,
            committed.instance().clone(),
            input("different.signed.token"),
            &options(None),
            now() + Duration::hours(1),
        )
        .await
        .unwrap(),
        PreparedVerificationSubmission::ReplayConflict
    ));
}

#[tokio::test]
async fn receipt_race_commits_one_result_and_a_denial_receipt_cannot_change_its_decision() {
    let allowed = receipt_preparation(true).await;
    let denied = receipt_preparation(false).await;
    let repository = Arc::new(marty_flow::InMemoryFlowRepository::default());
    repository
        .save_instance(allowed.expected_instance.kernel().unwrap())
        .unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let handles = [allowed, denied].map(|prepared| {
        let repository = Arc::clone(&repository);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            repository
                .finalize_verification_with_receipt(
                    &prepared,
                    u64::try_from((now() + Duration::seconds(8)).timestamp_millis()).unwrap(),
                )
                .unwrap()
        })
    });
    barrier.wait();
    let outcomes = handles.map(|handle| handle.join().unwrap());
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_some()).count(),
        1
    );
    let committed = outcomes.into_iter().flatten().next().unwrap();
    let callback = repository
        .callback(&committed.instance().id)
        .unwrap()
        .unwrap();
    committed
        .receipt()
        .validate_callback(&callback.payload)
        .unwrap();
    assert_eq!(
        callback.payload["decision"],
        committed.instance().result.as_ref().unwrap()["decision"]
    );
    assert_eq!(
        repository
            .instance(&committed.instance().id)
            .unwrap()
            .unwrap()
            .result,
        committed.instance().result
    );

    let denial = receipt_preparation(false).await;
    let denial_repository = marty_flow::InMemoryFlowRepository::default();
    denial_repository
        .save_instance(denial.expected_instance.kernel().unwrap())
        .unwrap();
    let committed = denial_repository
        .finalize_verification_with_receipt(
            &denial,
            u64::try_from((now() + Duration::seconds(8)).timestamp_millis()).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(committed.instance().status, FlowInstanceStatus::Failed);
    assert_eq!(
        committed.instance().result.as_ref().unwrap()["decision"],
        "deny"
    );
}

#[tokio::test]
async fn prepared_receipt_rejects_every_mutated_binding_before_any_write() {
    let prepared = receipt_preparation(true).await;
    let repository = marty_flow::InMemoryFlowRepository::default();
    repository
        .save_instance(prepared.expected_instance.kernel().unwrap())
        .unwrap();
    let consumed_ms = u64::try_from((now() + Duration::seconds(8)).timestamp_millis()).unwrap();
    for mutation in 0..11 {
        let mut changed = prepared.clone();
        match mutation {
            0 => {
                changed.expected_instance.context["verification_audience"] =
                    json!("different-audience")
            }
            1 => changed.expected_instance.updated_at += Duration::microseconds(1),
            2 => changed.instance.result.as_mut().unwrap()["decision"] = json!("deny"),
            3 => changed.instance.organization_id = "other-org".into(),
            4 => changed.nonce_digest = "b".repeat(64),
            5 => changed.submission_digest = "c".repeat(64),
            6 => changed.replay_expires_at_ms += 1_000,
            7 => {
                changed.callback.as_mut().unwrap().payload["verified_claims"] =
                    json!({"given_name":"replacement"})
            }
            8 => {
                changed.callback.as_mut().unwrap().reply_to =
                    Some("https://other.example/callback".into())
            }
            9 => {
                changed.instance.result.as_mut().unwrap()["evaluation_timestamp"] =
                    json!("2026-08-20T12:00:03.000000Z")
            }
            _ => {
                changed.expected_instance.context[presentation_snapshot::SNAPSHOT_KEY]
                    ["dcql_query"]["credentials"][0]["id"] = json!("other-query")
            }
        }
        assert!(
            repository
                .finalize_verification_with_receipt(&changed, consumed_ms)
                .is_err(),
            "mutation {mutation}"
        );
        assert!(repository
            .callback(&prepared.instance.id)
            .unwrap()
            .is_none());
        assert_eq!(
            repository.instance(&prepared.instance.id).unwrap(),
            Some(prepared.expected_instance.kernel().unwrap())
        );
    }
    assert!(repository
        .finalize_verification_with_receipt(&prepared, consumed_ms)
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn changed_row_or_expired_session_does_not_consume_receipt_authority() {
    let prepared = receipt_preparation(true).await;
    let repository = marty_flow::InMemoryFlowRepository::default();
    let expected = prepared.expected_instance.kernel().unwrap();
    let mut changed = expected.clone();
    changed.context["extra_request_state"] = json!("changed");
    repository.save_instance(changed.clone()).unwrap();
    assert!(repository
        .finalize_verification_with_receipt(
            &prepared,
            u64::try_from((now() + Duration::seconds(8)).timestamp_millis()).unwrap(),
        )
        .unwrap()
        .is_none());
    assert!(repository
        .callback(&prepared.instance.id)
        .unwrap()
        .is_none());
    assert_eq!(
        repository.instance(&prepared.instance.id).unwrap(),
        Some(changed)
    );
    repository.save_instance(expected.clone()).unwrap();
    assert!(repository
        .finalize_verification_with_receipt(
            &prepared,
            u64::try_from((now() + Duration::minutes(15)).timestamp_millis()).unwrap(),
        )
        .unwrap()
        .is_none());
    assert!(repository
        .callback(&prepared.instance.id)
        .unwrap()
        .is_none());
    // A rejected clock observation is not persisted as a receipt or nonce.
    assert!(repository
        .finalize_verification_with_receipt(
            &prepared,
            u64::try_from((now() + Duration::seconds(1)).timestamp_millis()).unwrap(),
        )
        .is_err());
    assert!(repository
        .finalize_verification_with_receipt(
            &prepared,
            u64::try_from((now() + Duration::seconds(8)).timestamp_millis()).unwrap(),
        )
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn receipt_readback_rejects_digest_consistent_scope_and_result_substitution() {
    use marty_oid4vp_contract::{FlowVerificationReceiptV1, VERIFICATION_RECEIPT};
    let prepared = receipt_preparation(true).await;
    let repository = marty_flow::InMemoryFlowRepository::default();
    repository
        .save_instance(prepared.expected_instance.kernel().unwrap())
        .unwrap();
    let committed = repository
        .finalize_verification_with_receipt(
            &prepared,
            u64::try_from((now() + Duration::seconds(8)).timestamp_millis()).unwrap(),
        )
        .unwrap()
        .unwrap();
    for mutation in 0..5 {
        let mut changed = committed.instance().clone();
        if mutation < 2 {
            let mut receipt: FlowVerificationReceiptV1 = serde_json::from_value(
                changed.result.as_ref().unwrap()[VERIFICATION_RECEIPT].clone(),
            )
            .unwrap();
            if mutation == 0 {
                receipt.organization_id = "other-org".into();
            } else {
                receipt.flow_instance_id = "other-instance".into();
            }
            receipt.receipt_digest = receipt.recompute_digest().unwrap();
            changed.result.as_mut().unwrap()[VERIFICATION_RECEIPT] = json!(receipt);
        } else if mutation == 2 {
            changed.result.as_mut().unwrap()["decision"] = json!("deny");
        } else if mutation == 3 {
            changed.context["nonce"] = json!("other-nonce");
        } else {
            changed.result.as_mut().unwrap()["evaluation_timestamp"] =
                json!("2026-08-20T12:00:08.000000Z");
        }
        assert!(
            changed.verification_projection().is_err(),
            "mutation {mutation}"
        );
    }
}

#[tokio::test]
async fn managed_receipt_requires_real_owner_time_and_legacy_results_keep_omission() {
    let (ports, _) = providers(Ok(allowed()));
    let mut managed = instance(false);
    managed.context[presentation_snapshot::SNAPSHOT_KEY]["credential_authority"] =
        json!(presentation_snapshot::authority("org-1"));
    assert!(matches!(
        prepare_verification_submission(
            &ports,
            managed,
            input("header.payload.signature"),
            &options(None),
            now(),
        )
        .await,
        Err(FlowVerificationSubmissionError::InvalidContext(
            "policy_evaluation_timestamp"
        ))
    ));
    let legacy = prepare_verification_submission(
        &ports,
        instance(false),
        input("header.payload.signature"),
        &options(None),
        now(),
    )
    .await
    .unwrap();
    let PreparedVerificationSubmission::Final(legacy) = legacy else {
        panic!("expected legacy preparation")
    };
    assert!(legacy
        .instance
        .verification_projection()
        .unwrap()
        .verification_receipt
        .is_none());
    for timestamp in [
        "",
        "not-a-time",
        "1970-01-01T00:00:00Z",
        "2026-08-20T12:00:02.000000001Z",
    ] {
        let mut evaluation = allowed();
        evaluation.evaluation_timestamp = Some(timestamp.into());
        let (ports, _) = providers(Ok(evaluation));
        assert!(
            matches!(
                prepare_verification_submission(
                    &ports,
                    instance(false),
                    input("header.payload.signature"),
                    &options(None),
                    now(),
                )
                .await,
                Err(FlowVerificationSubmissionError::InvalidClock)
            ),
            "timestamp {timestamp}"
        );
    }
}

#[tokio::test]
async fn legacy_finalization_cannot_sign_or_store_a_caller_supplied_receipt() {
    use marty_oid4vp_contract::VERIFICATION_RECEIPT;
    let prepared = receipt_preparation(true).await;
    let source = marty_flow::InMemoryFlowRepository::default();
    source
        .save_instance(prepared.expected_instance.kernel().unwrap())
        .unwrap();
    let now_ms = u64::try_from((now() + Duration::seconds(8)).timestamp_millis()).unwrap();
    let committed = source
        .finalize_verification_with_receipt(&prepared, now_ms)
        .unwrap()
        .unwrap();
    for attach_to_callback in [false, true] {
        let repository = marty_flow::InMemoryFlowRepository::default();
        let expected = prepared.expected_instance.kernel().unwrap();
        repository.save_instance(expected.clone()).unwrap();
        let mut terminal = prepared.instance.kernel().unwrap();
        let mut callback = prepared.callback.clone().unwrap();
        if attach_to_callback {
            callback.payload[VERIFICATION_RECEIPT] = json!(committed.receipt());
        } else {
            terminal.result.as_mut().unwrap()[VERIFICATION_RECEIPT] = json!(committed.receipt());
        }
        assert!(matches!(
            repository.finalize_verification(
                terminal,
                &prepared.nonce_digest,
                prepared.replay_expires_at_ms,
                &expected,
                Some(callback),
                now_ms,
            ),
            Err(marty_flow::RepositoryError::InvalidVerificationReceipt)
        ));
        assert_eq!(repository.instance(&expected.id).unwrap(), Some(expected));
        assert!(repository
            .callback(&prepared.instance.id)
            .unwrap()
            .is_none());
        assert!(repository
            .finalize_verification_with_receipt(&prepared, now_ms)
            .unwrap()
            .is_some());
    }
}

#[tokio::test]
async fn generic_writers_cannot_store_even_a_digest_consistent_receipt() {
    use marty_flow::{
        ApplicationEventReceipt, InMemoryFlowRepository, PlannedApplicationFlow,
        PlannedApplicationFlowRecord, PostgresFlowRepository, RepositoryError,
    };
    use marty_oid4vp_contract::VERIFICATION_RECEIPT;

    let prepared = receipt_preparation(true).await;
    let source = InMemoryFlowRepository::default();
    source
        .save_instance(prepared.expected_instance.kernel().unwrap())
        .unwrap();
    let now_ms = u64::try_from((now() + Duration::seconds(8)).timestamp_millis()).unwrap();
    let committed = source
        .finalize_verification_with_receipt(&prepared, now_ms)
        .unwrap()
        .unwrap();
    let receipt = serde_json::to_value(committed.receipt()).unwrap();
    let event = ApplicationEventReceipt {
        event_id_sha256: "a".repeat(64),
        payload_sha256: "b".repeat(64),
        organization_id: "org-1".into(),
        application_id: "application-1".into(),
        flow_plan: vec![],
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
    };
    // A lazy disconnected pool proves these writes reject caller receipts
    // before issuing SQL, even when the supplied receipt is internally valid.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://localhost:1/flow_test")
        .unwrap();
    let postgres = PostgresFlowRepository::new(pool);
    for attach_to_context in [false, true] {
        let mut candidate = committed.instance().clone();
        if attach_to_context {
            candidate.result = None;
            candidate.context[VERIFICATION_RECEIPT] = receipt.clone();
        }
        let kernel = candidate.kernel().unwrap();
        let memory = InMemoryFlowRepository::default();
        assert!(matches!(
            memory.save_instance(kernel.clone()),
            Err(RepositoryError::InvalidVerificationReceipt)
        ));
        assert!(matches!(
            memory.reserve_application_event_plan(
                event.clone(),
                vec![PlannedApplicationFlow {
                    instance: kernel,
                    plan_entry: Default::default(),
                }],
            ),
            Err(RepositoryError::InvalidVerificationReceipt)
        ));
        assert!(memory.instance(&candidate.id).unwrap().is_none());
        assert!(matches!(
            postgres.save_instance(&candidate).await,
            Err(RepositoryError::InvalidVerificationReceipt)
        ));
        assert!(matches!(
            postgres.save_started_instance(&candidate, None).await,
            Err(RepositoryError::InvalidVerificationReceipt)
        ));
        assert!(matches!(
            postgres
                .compare_and_swap_instance(
                    &candidate,
                    prepared.expected_instance.status,
                    prepared.expected_instance.updated_at,
                )
                .await,
            Err(RepositoryError::InvalidVerificationReceipt)
        ));
        assert!(matches!(
            postgres
                .reserve_application_event_plan(
                    event.clone(),
                    &[PlannedApplicationFlowRecord {
                        instance: candidate,
                        plan_entry: Default::default(),
                    }],
                )
                .await,
            Err(RepositoryError::InvalidVerificationReceipt)
        ));
    }
    // The original owner-created record remains recoverable without any
    // generic write or a second nonce consumption.
    assert_eq!(
        committed
            .instance()
            .verification_projection()
            .unwrap()
            .verification_receipt
            .as_ref(),
        Some(committed.receipt())
    );
}

#[tokio::test]
async fn legacy_or_changed_request_authority_fails_before_policy_evaluation() {
    let (ports, seen) = providers(Ok(allowed()));
    let mut legacy = instance(false);
    legacy
        .context
        .as_object_mut()
        .unwrap()
        .remove(presentation_snapshot::SNAPSHOT_KEY);
    assert!(matches!(
        prepare_verification_submission(
            &ports,
            legacy,
            input("header.payload.signature"),
            &options(None),
            now()
        )
        .await,
        Err(FlowVerificationSubmissionError::RestartRequired)
    ));
    for mutation in 0..5 {
        let mut altered = instance(false);
        match mutation {
            0 => altered.organization_id = "other-org".into(),
            1 => altered.id = "other-instance".into(),
            2 => altered.context["presentation_policy_id"] = json!("other-policy"),
            3 => {
                altered.context["mip_messages"]["presentation_request"]["payload"]["dcql_query"] =
                    json!({"credentials": [{"id": "other"}]})
            }
            _ => {
                altered
                    .context
                    .as_object_mut()
                    .unwrap()
                    .remove("mip_messages");
            }
        }
        assert!(
            matches!(
                prepare_verification_submission(
                    &ports,
                    altered,
                    input("header.payload.signature"),
                    &options(None),
                    now()
                )
                .await,
                Err(FlowVerificationSubmissionError::InvalidContext(_))
            ),
            "mutation {mutation}"
        );
    }
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn evaluator_revision_must_match_before_nonce_or_callback_finalization_is_prepared() {
    for mutation in 0..4 {
        let mut evaluated = allowed();
        match mutation {
            0 => evaluated.policy_revision.version += 1,
            1 => evaluated.policy_revision.content_digest = format!("sha256:{}", "b".repeat(64)),
            2 => evaluated.policy_revision.id = "other-policy".into(),
            _ => evaluated.policy_revision.content_digest.clear(),
        }
        let (ports, seen) = providers(Ok(evaluated));
        assert!(
            matches!(
                prepare_verification_submission(
                    &ports,
                    instance(true),
                    input("header.payload.signature"),
                    &options(Some("0123456789abcdef0123456789abcdef")),
                    now()
                )
                .await,
                Err(FlowVerificationSubmissionError::PolicyRevisionMismatch)
            ),
            "mutation {mutation}"
        );
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].expected_policy_revision,
            presentation_snapshot::revision("policy-1")
        );
    }
}

#[tokio::test]
async fn producer_stale_revision_rejection_requires_restart_without_finalization() {
    let (ports, seen) = providers(Err(FlowProviderError::PolicyRevisionMismatch));
    assert!(matches!(
        prepare_verification_submission(
            &ports,
            instance(true),
            input("header.payload.signature"),
            &options(Some("0123456789abcdef0123456789abcdef")),
            now()
        )
        .await,
        Err(FlowVerificationSubmissionError::PolicyRevisionMismatch)
    ));
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn callback_decision_digest_binds_the_validated_policy_revision() {
    let mut digests = Vec::new();
    for version in [1, 2] {
        let mut current = instance(true);
        let mut evaluated = allowed();
        evaluated.policy_revision.version = version;
        evaluated.policy_revision.content_digest =
            format!("sha256:{}", version.to_string().repeat(64));
        current.context[presentation_snapshot::SNAPSHOT_KEY]["policy_revision"] =
            json!(evaluated.policy_revision);
        let revision = evaluated.policy_revision.clone();
        let (ports, _) = providers(Ok(evaluated));
        let PreparedVerificationSubmission::Final(prepared) = prepare_verification_submission(
            &ports,
            current,
            input("header.payload.signature"),
            &options(Some("0123456789abcdef0123456789abcdef")),
            now(),
        )
        .await
        .unwrap() else {
            panic!("validated callback expected")
        };
        let mut payload = prepared.callback.unwrap().payload;
        assert_eq!(payload["policy_revision"], json!(revision));
        let digest = payload
            .as_object_mut()
            .unwrap()
            .remove("decision_digest")
            .unwrap();
        assert_eq!(digest, json!(mmf_push::payload_digest(&payload).unwrap()));
        assert!(!payload.to_string().contains("dcql_query"));
        assert!(!payload
            .to_string()
            .contains(presentation_snapshot::SNAPSHOT_KEY));
        digests.push(digest);
    }
    assert_ne!(digests[0], digests[1]);
}

#[tokio::test]
async fn emitted_query_and_submission_structure_reach_policy_without_new_verdict() {
    let query = json!({"id": "definition-1", "input_descriptors": [{"id": "member", "format": {"dc+sd-jwt": {}}}]});
    let instance = with_emitted_query(instance(false), "presentation_definition", query.clone());
    let mut wallet = input("header.payload.signature");
    let submission = json!({
        "id": "submission-1", "definition_id": "definition-1",
        "descriptor_map": [{"id": "member", "format": "dc+sd-jwt", "path": "$"}]
    });
    wallet.presentation_submission = Some(submission.clone());
    let (providers, seen) = providers(Ok(allowed()));
    let PreparedVerificationSubmission::Final(finalization) =
        prepare_verification_submission(&providers, instance, wallet, &options(None), now())
            .await
            .unwrap()
    else {
        panic!("existing allow result expected")
    };
    assert_eq!(
        finalization.instance.result.as_ref().unwrap()["decision"],
        "allow"
    );
    let requests = seen.lock().unwrap();
    let transport = requests[0].oid4vp_transport.as_ref().unwrap();
    assert_eq!(
        transport.query_kind,
        marty_oid4vp_contract::QueryKind::PresentationExchange
    );
    assert_eq!(transport.query_document, query);
    assert_eq!(transport.presentation_submission, Some(submission));
    assert!(transport.compatible_presentation_submission().is_ok());
    assert_eq!(transport.vp_token_raw, "header.payload.signature");
    assert_eq!(transport.verifier_client_id, "did:web:verifier.example");
    assert_eq!(
        transport.request_nonce,
        "nonce-with-at-least-32-bytes-1234567890"
    );
    transport.validate_transport().unwrap();
    assert_eq!(requests[0].presentation, "header.payload.signature");
    assert_eq!(
        requests[0].expected_policy_revision,
        presentation_snapshot::revision("policy-1")
    );
    assert_eq!(
        finalization.instance.result.as_ref().unwrap()["policy_revision"],
        json!(requests[0].expected_policy_revision)
    );
}

#[tokio::test]
async fn dcql_query_transport_does_not_require_presentation_submission() {
    let query = json!({"credentials": [{"id": "member", "format": "dc+sd-jwt"}]});
    let instance = with_emitted_query(instance(false), "dcql_query", query.clone());
    let raw_tokens = json!({"member": ["header.payload.signature"]}).to_string();
    let mut wallet = input(&raw_tokens);
    wallet.presentation_submission = None;
    let (providers, seen) = providers(Ok(allowed()));
    assert!(matches!(
        prepare_verification_submission(&providers, instance, wallet, &options(None), now()).await,
        Ok(PreparedVerificationSubmission::Final(_))
    ));
    let requests = seen.lock().unwrap();
    let transport = requests[0].oid4vp_transport.as_ref().unwrap();
    assert_eq!(transport.query_kind, marty_oid4vp_contract::QueryKind::Dcql);
    assert_eq!(transport.query_document, query);
    assert!(transport.presentation_submission.is_none());
    assert_eq!(transport.vp_token_raw, raw_tokens);
    assert_eq!(requests[0].presentation, "header.payload.signature");
}

#[tokio::test]
async fn complete_response_is_forwarded_and_unknown_queries_fail_before_evaluation() {
    let raw = json!({"member":["first.payload.signature","second.payload.signature"]}).to_string();
    let mut denied = allowed();
    denied.result = "failed".into();
    denied.decision = "deny".into();
    let (ports, seen) = providers(Ok(denied));
    assert!(matches!(
        prepare_verification_submission(
            &ports,
            instance(false),
            input(&raw),
            &options(None),
            now()
        )
        .await,
        Ok(PreparedVerificationSubmission::Final(_))
    ));
    {
        let requests = seen.lock().unwrap();
        assert_eq!(requests[0].presentation, raw);
        assert_eq!(
            requests[0].oid4vp_transport.as_ref().unwrap().vp_token_raw,
            raw
        );
    }
    let unknown =
        json!({"member":["first.payload.signature"],"unrequested":["second.payload.signature"]})
            .to_string();
    let result = prepare_verification_submission(
        &ports,
        instance(false),
        input(&unknown),
        &options(None),
        now(),
    )
    .await;
    assert!(matches!(
        result,
        Err(FlowVerificationSubmissionError::InvalidPresentationSubmission)
    ));
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn dc_api_preserves_legacy_empty_audience_while_carrying_emitted_client_id() {
    let mut instance = with_emitted_query(
        instance(false),
        "dcql_query",
        json!({"credentials": [{"id": "member", "format": "dc+sd-jwt"}]}),
    );
    instance
        .context
        .as_object_mut()
        .unwrap()
        .remove("verification_audience");
    let (providers, seen) = providers(Ok(allowed()));
    assert!(matches!(
        prepare_verification_submission(
            &providers,
            instance,
            input("header.payload.signature"),
            &options(None),
            now(),
        )
        .await,
        Ok(PreparedVerificationSubmission::Final(_))
    ));
    let requests = seen.lock().unwrap();
    assert_eq!(requests[0].audience, "");
    assert_eq!(
        requests[0]
            .oid4vp_transport
            .as_ref()
            .unwrap()
            .verifier_client_id,
        "did:web:verifier.example"
    );
}

#[tokio::test]
async fn oversized_submission_cannot_drop_frozen_query_binding() {
    let instance = with_emitted_query(
        instance(false),
        "dcql_query",
        json!({"credentials": [{"id": "member", "format": "dc+sd-jwt"}]}),
    );
    let mut wallet = input("header.payload.signature");
    wallet.presentation_submission = Some(json!({
        "id": "submission-1", "definition_id": "definition-1", "descriptor_map": [],
        "legacy_extension": "x".repeat(marty_oid4vp_contract::MAX_WALLET_SUBMISSION_BYTES)
    }));
    let (providers, seen) = providers(Ok(allowed()));
    assert!(matches!(
        prepare_verification_submission(&providers, instance, wallet, &options(None), now()).await,
        Err(FlowVerificationSubmissionError::InvalidPresentationSubmission)
    ));
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn malformed_recorded_query_cannot_be_promoted_to_transport_metadata() {
    let mut stored = with_emitted_query(instance(false), "dcql_query", json!({"credentials": []}));
    stored.context["mip_messages"]["presentation_request"]["payload"]["client_id"] =
        json!("attacker-client");
    let (providers, seen) = providers(Ok(allowed()));
    assert!(matches!(
        prepare_verification_submission(
            &providers,
            stored,
            input("header.payload.signature"),
            &options(None),
            now()
        )
        .await,
        Err(FlowVerificationSubmissionError::InvalidContext(
            "presentation_request_binding"
        ))
    ));
    assert!(seen.lock().unwrap().is_empty());

    // A contradictory persisted request fails before evaluation.
    let mut ambiguous = with_emitted_query(
        instance(false),
        "dcql_query",
        json!({"credentials": [{"id": "member", "format": "dc+sd-jwt"}]}),
    );
    ambiguous.context["mip_messages"]["presentation_request"]["payload"]
        ["presentation_definition"] = json!({"id": "definition-1", "input_descriptors": []});
    assert!(matches!(
        prepare_verification_submission(
            &providers,
            ambiguous,
            input("header.payload.signature"),
            &options(None),
            now(),
        )
        .await,
        Err(FlowVerificationSubmissionError::InvalidContext(
            "presentation_request_query"
        ))
    ));
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn language_neutral_allow_contract_scrubs_evidence_and_builds_atomic_outputs() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/flow-verification-submission-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["cryptographic_authority"],
        "presentation_policy_provider_only"
    );
    assert_eq!(
        contract["finalization"],
        "nonce_terminal_record_and_callback_atomic_compare_and_set"
    );

    let (providers, seen) = providers(Ok(allowed()));
    let raw = json!({"member": ["header.payload.signature"]}).to_string();
    let PreparedVerificationSubmission::Final(finalization) = prepare_verification_submission(
        &providers,
        instance(true),
        input(&raw),
        &options(Some("callback-secret-with-at-least-32-bytes")),
        now(),
    )
    .await
    .unwrap() else {
        panic!("terminal allow expected")
    };

    assert_eq!(
        finalization.expected_instance.status,
        FlowInstanceStatus::AwaitingWallet
    );
    assert_eq!(finalization.expected_instance, instance(true));
    assert_eq!(finalization.instance.status, FlowInstanceStatus::Completed);
    assert_eq!(
        finalization.instance.result.as_ref().unwrap()["decision"],
        "allow"
    );
    assert_eq!(
        finalization.instance.result.as_ref().unwrap()["verified_claims"]["given_name"],
        "Avery"
    );
    assert_eq!(
        finalization.instance.result.as_ref().unwrap()["error_codes"],
        json!(["policy-code"])
    );
    assert_eq!(
        finalization.instance.result.as_ref().unwrap()["warnings"],
        json!(["credential-warning", "policy-warning"])
    );
    assert!(finalization.instance.context.get("vp_token").is_none());
    assert!(finalization
        .instance
        .context
        .get("presentation_submission")
        .is_none());
    assert!(finalization.instance.context["vp_token_sha256"].is_string());
    assert!(finalization.instance.context["vp_transport_sha256"].is_string());
    assert!(finalization.instance.context["mip_messages"]["verification_result"].is_object());
    assert_eq!(finalization.nonce_digest.len(), 64);
    assert!(finalization.callback.is_some());

    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].presentation, "header.payload.signature");
    assert_eq!(requests[0].principal_id, "user-1");
    assert_eq!(requests[0].nonce, "nonce-with-at-least-32-bytes-1234567890");
    assert_eq!(requests[0].audience, "did:web:verifier.example");
    assert_eq!(requests[0].context["replay_check_verified"], true);
}

#[tokio::test]
async fn authenticated_deny_is_terminal_and_clears_claims() {
    let mut denied = allowed();
    denied.result = "failed".into();
    denied.decision = "deny".into();
    let (providers, _) = providers(Ok(denied));
    let PreparedVerificationSubmission::Final(finalization) = prepare_verification_submission(
        &providers,
        instance(false),
        input("header.payload.signature"),
        &options(None),
        now(),
    )
    .await
    .unwrap() else {
        panic!("terminal deny expected")
    };
    assert_eq!(finalization.instance.status, FlowInstanceStatus::Failed);
    assert_eq!(
        finalization.instance.result.as_ref().unwrap()["verified_claims"],
        json!({})
    );
}

#[tokio::test]
async fn unavailable_or_unauthenticated_verifier_is_retryable_without_terminal_outputs() {
    let (unavailable, _) = providers(Err(FlowProviderError::Unavailable {
        provider: "presentation_policy",
    }));
    let retry = prepare_verification_submission(
        &unavailable,
        instance(false),
        input("header.payload.signature"),
        &options(None),
        now(),
    )
    .await
    .unwrap();
    assert!(matches!(
        retry,
        PreparedVerificationSubmission::Retryable(_)
    ));

    let mut unauthenticated = allowed();
    unauthenticated.credential_results = Vec::new();
    let (providers, _) = providers(Ok(unauthenticated));
    let retry = prepare_verification_submission(
        &providers,
        instance(false),
        input("header.payload.signature"),
        &options(None),
        now(),
    )
    .await
    .unwrap();
    assert!(matches!(
        retry,
        PreparedVerificationSubmission::Retryable(_)
    ));
}

#[tokio::test]
async fn state_submission_callback_and_expiry_boundaries_fail_closed() {
    let (providers, _) = providers(Ok(allowed()));
    let mut missing_principal = instance(false);
    missing_principal
        .context
        .as_object_mut()
        .unwrap()
        .remove("_marty_verification_principal_id");
    assert!(matches!(
        prepare_verification_submission(
            &providers,
            missing_principal,
            input("header.payload.signature"),
            &options(None),
            now(),
        )
        .await,
        Err(FlowVerificationSubmissionError::InvalidContext(
            "_marty_verification_principal_id"
        ))
    ));
    let mut wrong_state = input("header.payload.signature");
    wrong_state.state = Some("wrong".into());
    assert!(matches!(
        prepare_verification_submission(
            &providers,
            instance(false),
            wrong_state,
            &options(None),
            now()
        )
        .await,
        Err(FlowVerificationSubmissionError::StateMismatch)
    ));

    let mut malformed = input("header.payload.signature");
    malformed.presentation_submission = Some(json!({
        "id": "submission-1",
        "definition_id": "definition-1",
        "descriptor_map": {}
    }));
    assert!(matches!(
        prepare_verification_submission(
            &providers,
            instance(false),
            malformed,
            &options(None),
            now()
        )
        .await,
        Err(FlowVerificationSubmissionError::InvalidPresentationSubmission)
    ));

    assert!(matches!(
        prepare_verification_submission(
            &providers,
            instance(true),
            input("header.payload.signature"),
            &options(Some("short")),
            now()
        )
        .await,
        Err(FlowVerificationSubmissionError::CallbackUnavailable)
    ));

    let mut expired = instance(false);
    expired.expires_at = Some(now());
    let PreparedVerificationSubmission::Expired(expired) = prepare_verification_submission(
        &providers,
        expired,
        input("header.payload.signature"),
        &options(None),
        now(),
    )
    .await
    .unwrap() else {
        panic!("exclusive expiry boundary expected")
    };
    assert_eq!(expired.status, FlowInstanceStatus::Expired);
    assert_eq!(expired.error.as_deref(), Some("submission_expired"));
}

#[tokio::test]
async fn terminal_replay_accepts_only_the_same_canonical_submission_digest() {
    let (providers, _) = providers(Ok(allowed()));
    let original = input("header.payload.signature");
    let PreparedVerificationSubmission::Final(finalization) = prepare_verification_submission(
        &providers,
        instance(false),
        original.clone(),
        &options(None),
        now(),
    )
    .await
    .unwrap() else {
        panic!("terminal result expected")
    };

    let same = prepare_verification_submission(
        &providers,
        finalization.instance.clone(),
        original,
        &options(None),
        now(),
    )
    .await
    .unwrap();
    assert!(matches!(
        same,
        PreparedVerificationSubmission::SameTerminal(_)
    ));

    let different = prepare_verification_submission(
        &providers,
        finalization.instance,
        input("different.payload.signature"),
        &options(None),
        now(),
    )
    .await
    .unwrap();
    assert!(matches!(
        different,
        PreparedVerificationSubmission::ReplayConflict
    ));
}

#[tokio::test]
async fn legacy_envelope_and_malformed_jwe_fail_closed() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../contracts/flow-haip-response-vector.json"
    ))
    .unwrap();
    let mut candidate = instance(false);
    candidate.context["haip_response_encryption_key_envelope"] = json!("vault:haip-key");
    let providers = FlowProviderRegistry {
        flow_key_envelope: Some(Arc::new(RemoteEnvelopes)),
        ..Default::default()
    };
    assert!(matches!(
        decrypt_verification_response(
            &providers,
            &candidate,
            vector["compact_jwe"].as_str().unwrap(),
        )
        .await,
        Err(FlowVerificationSubmissionError::InvalidEncryptedResponse)
    ));
    assert!(matches!(
        decrypt_verification_response(&providers, &candidate, "not-a-jwe").await,
        Err(FlowVerificationSubmissionError::InvalidEncryptedResponse)
    ));
}

#[tokio::test]
async fn remote_haip_response_uses_scoped_version_without_private_key_unwrap() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../contracts/flow-haip-response-vector.json"
    ))
    .unwrap();
    let mut candidate = instance(false);
    let remote = haip_remote_fixture::key(&candidate.organization_id, &candidate.id);
    candidate.context["haip_response_encryption_key_reference"] = json!(remote.key_reference);
    candidate.context["haip_response_encryption_public_jwk"] = remote.public_jwk;
    let providers = FlowProviderRegistry {
        flow_key_envelope: Some(Arc::new(RemoteEnvelopes)),
        ..Default::default()
    };
    let plaintext = decrypt_verification_response(
        &providers,
        &candidate,
        vector["compact_jwe"].as_str().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(plaintext, json!({"vp_token":"remote-fixture"}));
    candidate.context["haip_response_encryption_key_reference"] = json!(format!(
        "didcomm/haip/keys/other/abcdefghijklmnop/versions/{}",
        haip_remote_fixture::VERSION
    ));
    assert!(matches!(
        decrypt_verification_response(
            &providers,
            &candidate,
            vector["compact_jwe"].as_str().unwrap()
        )
        .await,
        Err(FlowVerificationSubmissionError::InvalidEncryptedResponse)
    ));
}

fn rejected_mdoc_evaluation(token: &str) -> PresentationEvaluationResult {
    use marty_oid4vp_contract::{
        BoundAuthenticationDiagnosticV1, CertificateTrustFailure, MdocAuthenticationDiagnosticV1,
        MdocDiagnosticFormat,
    };
    let mut value = allowed();
    value.result = "failed".into();
    value.decision = "deny".into();
    value.decision_reason = Some("Certificate trust was rejected".into());
    value.verified_claims.clear();
    value.credential_results =
        vec![json!({"signature_valid":false,"error_codes":["SignatureInvalid"]})];
    let session = instance(false);
    value.authentication_diagnostic = Some(
        BoundAuthenticationDiagnosticV1::bind(
            "policy-1",
            session.context["nonce"].as_str().unwrap(),
            token,
            1,
            MdocAuthenticationDiagnosticV1 {
                format: MdocDiagnosticFormat::MsoMdoc,
                document_count: 1,
                document_type: "org.iso.18013.5.1.mDL".into(),
                issuer_signature_valid: true,
                certificate_trust_passed: false,
                device_authentication_valid: true,
                certificate_trust_failures: vec![CertificateTrustFailure::CertificateChainRejected],
                issuer_certificate_sha256: "1".repeat(64),
            },
        )
        .unwrap(),
    );
    value
}

#[tokio::test]
async fn rejected_mdoc_attempt_remains_retryable_and_idempotent_then_clears_on_recovery() {
    let token = "wallet-mdoc";
    let original = instance(false);
    let (policies, _) = providers(Ok(rejected_mdoc_evaluation(token)));
    let PreparedVerificationSubmission::RetryableSnapshot(snapshot) =
        prepare_verification_submission(
            &policies,
            original.clone(),
            input(token),
            &options(None),
            now(),
        )
        .await
        .unwrap()
    else {
        panic!("durable retryable rejection expected")
    };
    assert_eq!(snapshot.instance.status, original.status);
    assert_eq!(snapshot.instance.completed_at, original.completed_at);
    assert_eq!(
        snapshot.instance.context["nonce"],
        original.context["nonce"]
    );
    assert_eq!(snapshot.response.decision.as_deref(), Some("deny"));
    assert_eq!(snapshot.response.verified_claims, json!({}));
    let attempt = snapshot.response.last_presentation_attempt.clone().unwrap();
    assert_eq!(
        snapshot
            .instance
            .projection()
            .unwrap()
            .last_presentation_attempt,
        Some(attempt.clone())
    );
    // Only the server-owned result bound to the current session is projected.
    for mutation in 0..3 {
        let mut changed = snapshot.instance.clone();
        match mutation {
            0 => changed.context["nonce"] = json!("different-request-nonce"),
            1 => changed.context["presentation_policy_id"] = json!("other-policy"),
            _ => changed.id = "other-instance".into(),
        }
        assert!(changed
            .projection()
            .unwrap()
            .last_presentation_attempt
            .is_none());
    }
    let mut forged = original.clone();
    forged.context["last_presentation_attempt"] = serde_json::to_value(&attempt).unwrap();
    assert!(forged
        .projection()
        .unwrap()
        .last_presentation_attempt
        .is_none());
    let history = snapshot.instance.state_history.len();
    let PreparedVerificationSubmission::RetryableSnapshot(repeated) =
        prepare_verification_submission(
            &policies,
            snapshot.instance.clone(),
            input(token),
            &options(None),
            now() + Duration::seconds(1),
        )
        .await
        .unwrap()
    else {
        panic!("duplicate rejection still needs active-snapshot CAS")
    };
    assert_eq!(repeated.response.last_presentation_attempt, Some(attempt));
    assert_eq!(repeated.instance.state_history.len(), history);
    let (recovery, _) = providers(Ok(allowed()));
    let PreparedVerificationSubmission::Final(recovered) = prepare_verification_submission(
        &recovery,
        snapshot.instance.clone(),
        input("new-wallet-token"),
        &options(None),
        now() + Duration::seconds(2),
    )
    .await
    .unwrap() else {
        panic!("normal authenticated recovery must complete")
    };
    assert_eq!(recovered.instance.status, FlowInstanceStatus::Completed);
    assert!(recovered
        .instance
        .projection()
        .unwrap()
        .last_presentation_attempt
        .is_none());
    assert!(recovered
        .instance
        .verification_projection()
        .unwrap()
        .last_presentation_attempt
        .is_none());
    assert!(recovered.instance.state_history.len() > history);
    assert_eq!(
        recovered.instance.state_history[history - 1],
        snapshot.instance.state_history[history - 1]
    );
}

#[tokio::test]
async fn rejected_mdoc_wrong_binding_and_generic_auth_failure_cannot_inherit_fingerprint() {
    let token = "wallet-mdoc";
    let mut bad = rejected_mdoc_evaluation(token);
    bad.authentication_diagnostic.as_mut().unwrap().nonce_sha256 = "f".repeat(64);
    let (policies, _) = providers(Ok(bad));
    let PreparedVerificationSubmission::Retryable(response) = prepare_verification_submission(
        &policies,
        instance(false),
        input(token),
        &options(None),
        now(),
    )
    .await
    .unwrap() else {
        panic!("wrong-bound diagnostic must not be persisted")
    };
    assert!(response.last_presentation_attempt.is_none());
    let (policies, _) = providers(Ok(rejected_mdoc_evaluation(token)));
    let PreparedVerificationSubmission::RetryableSnapshot(snapshot) =
        prepare_verification_submission(
            &policies,
            instance(false),
            input(token),
            &options(None),
            now(),
        )
        .await
        .unwrap()
    else {
        panic!("rejected snapshot expected")
    };
    let mut generic = allowed();
    generic.credential_results = Vec::new();
    let (policies, _) = providers(Ok(generic));
    let PreparedVerificationSubmission::RetryableSnapshot(cleared) =
        prepare_verification_submission(
            &policies,
            snapshot.instance,
            input("bad-signature-token"),
            &options(None),
            now() + Duration::seconds(1),
        )
        .await
        .unwrap()
    else {
        panic!("new generic rejection must clear stale fingerprint")
    };
    assert!(cleared.response.last_presentation_attempt.is_none());
    assert!(cleared
        .instance
        .projection()
        .unwrap()
        .last_presentation_attempt
        .is_none());
    assert_eq!(cleared.instance.status, FlowInstanceStatus::AwaitingWallet);
}

fn decline_instance(mode: &str) -> FlowInstanceRecord {
    let mut current = instance(false);
    current.context["oid4vp_expected_state"] = json!(current.id);
    current.context["oid4vp_response_uri"] = json!("https://verifier.example/submit");
    let message = &mut current.context["mip_messages"]["presentation_request"];
    message["correlation_id"] = json!(current.id);
    message["payload"]["mip_flow_instance_id"] = json!(current.id);
    message["payload"]["response_type"] = json!("vp_token");
    message["payload"]["response_mode"] = json!(mode);
    message["payload"]["response_uri"] = json!("https://verifier.example/submit");
    current
}

#[test]
fn wallet_access_denied_cancels_only_fresh_bound_pending_verification() {
    for mode in ["direct_post", "direct_post.jwt"] {
        let current = decline_instance(mode);
        let declined = marty_flow::prepare_verification_decline(
            current,
            Some("abcdefghijklmnop"),
            false,
            now(),
        )
        .unwrap();
        assert_eq!(declined.status, FlowInstanceStatus::Cancelled);
        assert_eq!(declined.error.as_deref(), Some("access_denied"));
        assert_eq!(declined.completed_at, Some(now()));
        assert!(declined.result.is_none());
        assert!(declined.subject_id.is_none());
        assert_eq!(
            declined.state_history.last().unwrap()["event"],
            "wallet_access_denied"
        );
        assert!(marty_flow::prepare_verification_decline(
            declined,
            Some("abcdefghijklmnop"),
            false,
            now()
        )
        .is_err());
    }
}

#[test]
fn encrypted_decline_requires_the_emitted_encrypted_mode() {
    assert!(marty_flow::prepare_verification_decline(
        decline_instance("direct_post.jwt"),
        Some("abcdefghijklmnop"),
        true,
        now()
    )
    .is_ok());
    assert!(matches!(
        marty_flow::prepare_verification_decline(
            decline_instance("direct_post"),
            Some("abcdefghijklmnop"),
            true,
            now()
        ),
        Err(FlowVerificationSubmissionError::ResponseModeMismatch)
    ));
    let mut current = decline_instance("direct_post");
    current.status = FlowInstanceStatus::InProgress;
    assert!(marty_flow::prepare_verification_decline(
        current,
        Some("abcdefghijklmnop"),
        false,
        now()
    )
    .is_ok());
    let mut current = decline_instance("direct_post");
    current.expires_at = None;
    assert!(marty_flow::prepare_verification_decline(
        current,
        Some("abcdefghijklmnop"),
        false,
        now()
    )
    .is_err());
}

#[test]
fn wallet_decline_rejects_invalid_state_expiry_terminal_and_other_modes() {
    for state in [None, Some(""), Some("other-flow-state")] {
        assert!(matches!(
            marty_flow::prepare_verification_decline(
                decline_instance("direct_post"),
                state,
                false,
                now()
            ),
            Err(FlowVerificationSubmissionError::StateMismatch)
        ));
    }
    for mode in ["dc_api", "dc_api.jwt", "query", ""] {
        assert!(matches!(
            marty_flow::prepare_verification_decline(
                decline_instance(mode),
                Some("abcdefghijklmnop"),
                false,
                now()
            ),
            Err(FlowVerificationSubmissionError::ResponseModeMismatch)
        ));
    }
    for status in [
        FlowInstanceStatus::Created,
        FlowInstanceStatus::Pending,
        FlowInstanceStatus::AwaitingApproval,
        FlowInstanceStatus::Completed,
        FlowInstanceStatus::Failed,
        FlowInstanceStatus::Expired,
        FlowInstanceStatus::Cancelled,
    ] {
        let mut current = decline_instance("direct_post");
        current.status = status;
        assert!(matches!(
            marty_flow::prepare_verification_decline(
                current,
                Some("abcdefghijklmnop"),
                false,
                now()
            ),
            Err(FlowVerificationSubmissionError::InvalidState)
        ));
    }
    let mut current = decline_instance("direct_post");
    current.expires_at = Some(now());
    assert!(marty_flow::prepare_verification_decline(
        current,
        Some("abcdefghijklmnop"),
        false,
        now()
    )
    .is_err());
    let mut current = decline_instance("direct_post");
    current.context["mip_messages"]["presentation_request"]["payload"]["mip_flow_instance_id"] =
        json!("other-instance");
    assert!(marty_flow::prepare_verification_decline(
        current,
        Some("abcdefghijklmnop"),
        false,
        now()
    )
    .is_err());
}

#[test]
fn wallet_decline_refuses_drifted_emitted_state_and_prior_finalization_markers() {
    let mut current = decline_instance("direct_post");
    current.context["oid4vp_expected_state"] = json!("drifted-state");
    assert!(matches!(
        marty_flow::prepare_verification_decline(current, Some("drifted-state"), false, now()),
        Err(FlowVerificationSubmissionError::StateMismatch)
    ));
    for result in [
        json!({"evaluation_result":"passed", "decision":"allow"}),
        json!({"submission_digest":"old-attempt"}),
        json!({"verification_receipt":{}}),
    ] {
        let mut current = decline_instance("direct_post");
        current.result = Some(result);
        assert!(matches!(
            marty_flow::prepare_verification_decline(
                current,
                Some("abcdefghijklmnop"),
                false,
                now()
            ),
            Err(FlowVerificationSubmissionError::InvalidState)
        ));
    }
    let mut current = decline_instance("direct_post");
    current.completed_at = Some(now());
    assert!(marty_flow::prepare_verification_decline(
        current,
        Some("abcdefghijklmnop"),
        false,
        now()
    )
    .is_err());
    let mut current = decline_instance("direct_post");
    current.subject_id = Some("existing-subject".into());
    assert!(marty_flow::prepare_verification_decline(
        current,
        Some("abcdefghijklmnop"),
        false,
        now()
    )
    .is_err());
}
