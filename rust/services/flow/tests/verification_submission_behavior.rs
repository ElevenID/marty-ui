use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use marty_flow::{
    decrypt_verification_response, prepare_verification_submission, FlowInstanceRecord,
    FlowKeyEnvelope, FlowKeyEnvelopeProvider, FlowKeyEnvelopeRequest, FlowProviderError,
    FlowProviderRegistry, FlowVerificationSubmissionError, PreparedVerificationSubmission,
    PresentationEvaluationRequest, PresentationEvaluationResult, PresentationPolicyProvider,
    PresentationPolicyReference, VerificationSubmissionInput, VerificationSubmissionOptions,
    CALLBACK_MAX_ATTEMPTS, CALLBACK_RETENTION_SECONDS,
};
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

struct Envelopes(String);

#[async_trait]
impl FlowKeyEnvelopeProvider for Envelopes {
    async fn wrap(
        &self,
        _request: &FlowKeyEnvelopeRequest,
    ) -> Result<FlowKeyEnvelope, FlowProviderError> {
        unreachable!("submission only unwraps response keys")
    }

    async fn unwrap(&self, envelope: &FlowKeyEnvelope) -> Result<String, FlowProviderError> {
        assert_eq!(envelope.organization_id, "org-1");
        assert_eq!(envelope.flow_instance_id, "abcdefghijklmnop");
        assert_eq!(envelope.purpose, "oid4vp_response_decryption");
        assert_eq!(envelope.envelope, "vault:haip-key");
        Ok(self.0.clone())
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
async fn native_haip_interoperability_vector_decrypts_and_malformed_jwe_fails_closed() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../contracts/flow-haip-response-vector.json"
    ))
    .unwrap();
    let mut candidate = instance(false);
    candidate.context["haip_response_encryption_key_envelope"] = json!("vault:haip-key");
    let providers = FlowProviderRegistry {
        flow_key_envelope: Some(Arc::new(Envelopes(vector["private_jwk"].to_string()))),
        ..Default::default()
    };
    let plaintext = decrypt_verification_response(
        &providers,
        &candidate,
        vector["compact_jwe"].as_str().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(plaintext, json!({"vp_token": "fixture"}));
    assert!(matches!(
        decrypt_verification_response(&providers, &candidate, "not-a-jwe").await,
        Err(FlowVerificationSubmissionError::InvalidEncryptedResponse)
    ));
}
