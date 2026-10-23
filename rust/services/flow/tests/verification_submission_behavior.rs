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
    FlowInstanceRecord {
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
    }
}

fn with_emitted_query(
    mut instance: FlowInstanceRecord,
    field: &str,
    query: Value,
) -> FlowInstanceRecord {
    let mut payload = json!({
        "nonce": "nonce-with-at-least-32-bytes-1234567890",
        "client_id": "did:web:verifier.example"
    });
    payload[field] = query;
    instance.context["mip_messages"]["presentation_request"] = json!({"payload": payload});
    instance
}

fn allowed() -> PresentationEvaluationResult {
    PresentationEvaluationResult {
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
        presentation_submission: Some(json!({
            "id": "submission-1",
            "definition_id": "definition-1",
            "descriptor_map": []
        })),
        state: Some("state-1".into()),
        audience_override: None,
    }
}

#[tokio::test]
async fn emitted_query_and_submission_structure_reach_policy_without_new_verdict() {
    let query = json!({"id": "definition-1", "input_descriptors": [{"id": "member"}]});
    let instance = with_emitted_query(instance(false), "presentation_definition", query.clone());
    let mut wallet = input("header.payload.signature");
    let submission = json!({
        "id": "submission-1", "definition_id": "definition-1",
        "descriptor_map": [{"id": "member", "format": "jwt_vp", "path": "$"}],
        "legacy_extension": true
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
    assert!(transport.compatible_presentation_submission().is_err());
    assert_eq!(transport.vp_token_raw, "header.payload.signature");
    assert_eq!(transport.verifier_client_id, "did:web:verifier.example");
    assert_eq!(
        transport.request_nonce,
        "nonce-with-at-least-32-bytes-1234567890"
    );
    transport.validate_transport().unwrap();
    assert_eq!(requests[0].presentation, "header.payload.signature");
}

#[tokio::test]
async fn dcql_query_transport_does_not_require_presentation_submission() {
    let query = json!({"credentials": [{"id": "member"}]});
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
async fn dc_api_preserves_legacy_empty_audience_while_carrying_emitted_client_id() {
    let mut instance = with_emitted_query(
        instance(false),
        "dcql_query",
        json!({"credentials": [{"id": "member"}]}),
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
async fn oversized_legacy_submission_keeps_existing_verdict_without_transport_claim() {
    let instance = with_emitted_query(
        instance(false),
        "dcql_query",
        json!({"credentials": [{"id": "member"}]}),
    );
    let mut wallet = input("header.payload.signature");
    wallet.presentation_submission = Some(json!({
        "id": "submission-1", "definition_id": "definition-1", "descriptor_map": [],
        "legacy_extension": "x".repeat(marty_oid4vp_contract::MAX_WALLET_SUBMISSION_BYTES)
    }));
    let (providers, seen) = providers(Ok(allowed()));
    let PreparedVerificationSubmission::Final(finalization) =
        prepare_verification_submission(&providers, instance, wallet, &options(None), now())
            .await
            .unwrap()
    else {
        panic!("legacy result must remain available")
    };
    assert_eq!(
        finalization.instance.result.as_ref().unwrap()["decision"],
        "allow"
    );
    assert!(seen.lock().unwrap()[0].oid4vp_transport.is_none());
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

    // Unlike an absent historical request, a contradictory persisted request
    // is a producer-state error and now fails before legacy evaluation.
    let mut ambiguous = with_emitted_query(
        instance(false),
        "dcql_query",
        json!({"credentials": [{"id": "member"}]}),
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
    let raw = json!({"member_query": ["header.payload.signature"]}).to_string();
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
        finalization.expected_status,
        FlowInstanceStatus::AwaitingWallet
    );
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
