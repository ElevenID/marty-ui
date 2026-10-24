use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, TimeZone, Utc};
use marty_flow::{
    prepare_siop_submission, FlowInstanceRecord, FlowSiopSubmissionError, PreparedSiopSubmission,
    SiopSubmissionOptions,
};
use marty_key_material_policy::contains_private_key;
use marty_verification::flow::FlowInstanceStatus;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap()
}

fn instance() -> FlowInstanceRecord {
    FlowInstanceRecord {
        id: "siop-instance-1".into(),
        flow_definition_id: "__siop_v2__".into(),
        organization_id: "org-1".into(),
        status: FlowInstanceStatus::AwaitingWallet,
        current_step_id: None,
        context: json!({
            "flow_type": "siop_v2",
            "nonce": "nonce-with-at-least-32-bytes-1234567890",
            "siop_client_id": "https://verifier.example/verifier"
        }),
        step_history: Vec::new(),
        state_history: Vec::new(),
        subject_id: None,
        subject_type: "holder".into(),
        external_reference: None,
        application_flow_key_hash: None,
        started_at: Some(now() - Duration::seconds(30)),
        completed_at: None,
        expires_at: Some(now() + Duration::minutes(15)),
        result: None,
        error: None,
        created_at: now() - Duration::seconds(30),
        updated_at: now() - Duration::seconds(30),
    }
}

#[derive(Deserialize)]
struct SignedVectors {
    schema_version: u8,
    es256_subject: String,
    eddsa_subject: String,
    tokens: BTreeMap<String, String>,
}

fn public_vector(case: &str) -> (String, String) {
    let vectors: SignedVectors =
        serde_json::from_str(include_str!("fixtures/siop_public_tokens.json")).unwrap();
    assert_eq!(vectors.schema_version, 1);
    let subject = if case == "eddsa_default" {
        vectors.eddsa_subject
    } else {
        vectors.es256_subject
    };
    (vectors.tokens[case].clone(), subject)
}

#[test]
fn signed_public_vectors_contain_no_private_key_material() {
    let vectors: SignedVectors =
        serde_json::from_str(include_str!("fixtures/siop_public_tokens.json")).unwrap();
    assert_eq!(vectors.schema_version, 1);
    assert_eq!(vectors.tokens.len(), 12);
    for (case, token) in vectors.tokens {
        let segments: Vec<_> = token.split('.').collect();
        assert_eq!(segments.len(), 3, "{case}");
        for segment in &segments[..2] {
            let decoded = URL_SAFE_NO_PAD.decode(segment).unwrap();
            let value: Value = serde_json::from_slice(&decoded).unwrap();
            assert!(!contains_private_key(&value), "{case}");
        }
    }
}

#[test]
fn language_neutral_siop_contract_completes_and_preserves_only_safe_result_state() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/flow-siop-submission-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract["schema_version"], 1);
    assert_eq!(
        contract["cryptographic_authority"],
        "marty_oid4vci_siop_jwk_thumbprint_verifier"
    );
    assert_eq!(contract["clock_skew_seconds"], 60);
    assert_eq!(contract["signing_algorithms"], json!(["ES256", "EdDSA"]));

    let (token, subject) = public_vector("audience_array");
    let PreparedSiopSubmission::Final(prepared) =
        prepare_siop_submission(instance(), &token, &SiopSubmissionOptions::default(), now())
            .unwrap()
    else {
        panic!("terminal SIOP result expected")
    };
    assert_eq!(prepared.response.status, "verified");
    assert_eq!(prepared.response.sub, subject);
    assert_eq!(
        prepared.finalization.instance.status,
        FlowInstanceStatus::Completed
    );
    assert_eq!(
        prepared.finalization.instance.subject_id.as_deref(),
        Some(subject.as_str())
    );
    assert_eq!(
        prepared.finalization.instance.result.as_ref().unwrap()["claims_trust"],
        "self_attested"
    );
    assert_eq!(
        prepared.finalization.instance.result.as_ref().unwrap()["signing_algorithm"],
        "ES256"
    );
    assert!(!prepared
        .finalization
        .instance
        .context
        .to_string()
        .contains(&token));
    assert_eq!(prepared.finalization.nonce_digest.len(), 64);
    assert!(prepared.finalization.callback.is_none());
    assert_eq!(
        prepared.finalization.expected_status,
        FlowInstanceStatus::AwaitingWallet
    );
    assert_eq!(prepared.finalization.instance.state_history.len(), 2);

    let (ed_token, ed_subject) = public_vector("eddsa_default");
    let PreparedSiopSubmission::Final(ed_prepared) = prepare_siop_submission(
        instance(),
        &ed_token,
        &SiopSubmissionOptions::default(),
        now(),
    )
    .unwrap() else {
        panic!("EdDSA terminal SIOP result expected")
    };
    assert_eq!(ed_prepared.response.sub, ed_subject);
    assert_eq!(
        ed_prepared.finalization.instance.result.as_ref().unwrap()["signing_algorithm"],
        "EdDSA"
    );
}

#[test]
fn issuer_audience_nonce_and_native_signature_validation_fail_closed() {
    let (issuer_mismatch, _) = public_vector("issuer_mismatch");
    assert!(matches!(
        prepare_siop_submission(
            instance(),
            &issuer_mismatch,
            &SiopSubmissionOptions::default(),
            now()
        ),
        Err(FlowSiopSubmissionError::IssuerSubjectMismatch)
    ));

    let (audience_mismatch, _) = public_vector("audience_mismatch");
    assert!(matches!(
        prepare_siop_submission(
            instance(),
            &audience_mismatch,
            &SiopSubmissionOptions::default(),
            now()
        ),
        Err(FlowSiopSubmissionError::AudienceMismatch)
    ));

    let (nonce_mismatch, _) = public_vector("nonce_mismatch");
    assert!(matches!(
        prepare_siop_submission(
            instance(),
            &nonce_mismatch,
            &SiopSubmissionOptions::default(),
            now()
        ),
        Err(FlowSiopSubmissionError::NonceMismatch)
    ));

    assert!(matches!(
        prepare_siop_submission(
            instance(),
            "not-a-token",
            &SiopSubmissionOptions::default(),
            now()
        ),
        Err(FlowSiopSubmissionError::InvalidIdToken(_))
    ));

    let (mut tampered, _) = public_vector("default");
    tampered.push('x');
    assert!(matches!(
        prepare_siop_submission(
            instance(),
            &tampered,
            &SiopSubmissionOptions::default(),
            now()
        ),
        Err(FlowSiopSubmissionError::InvalidIdToken(_))
    ));
}

#[test]
fn numeric_validity_and_transaction_time_boundaries_fail_closed() {
    for (case, expected) in [
        ("iat_future_61", "FLOW.SIOP_IAT_IN_FUTURE"),
        ("exp_past_60", "FLOW.SIOP_TOKEN_EXPIRED"),
        ("iat_exp_future_5m", "FLOW.SIOP_IAT_IN_FUTURE"),
        ("iat_before_tx_2m", "FLOW.SIOP_TOKEN_PREDATES_TRANSACTION"),
        ("iat_bool", "FLOW.SIOP_INVALID_TIME_CLAIMS"),
    ] {
        let (token, _) = public_vector(case);
        let error =
            prepare_siop_submission(instance(), &token, &SiopSubmissionOptions::default(), now())
                .unwrap_err();
        assert!(error.to_string().starts_with(expected), "{error}");
    }

    let (invalid_window, _) = public_vector("invalid_window");
    assert!(matches!(
        prepare_siop_submission(
            instance(),
            &invalid_window,
            &SiopSubmissionOptions::default(),
            now()
        ),
        Err(FlowSiopSubmissionError::InvalidValidityWindow)
    ));
}

#[test]
fn expiry_flow_binding_and_terminal_replay_are_deterministic() {
    let (token, _) = public_vector("default");
    let mut wrong_flow = instance();
    wrong_flow.context["flow_type"] = json!("verification");
    assert!(matches!(
        prepare_siop_submission(wrong_flow, &token, &SiopSubmissionOptions::default(), now()),
        Err(FlowSiopSubmissionError::InvalidTransaction)
    ));

    let mut expired = instance();
    expired.expires_at = Some(now());
    let PreparedSiopSubmission::Expired(expired) =
        prepare_siop_submission(expired, &token, &SiopSubmissionOptions::default(), now()).unwrap()
    else {
        panic!("exclusive expiry expected")
    };
    assert_eq!(expired.status, FlowInstanceStatus::Expired);
    assert_eq!(expired.error.as_deref(), Some("siop_submission_expired"));

    let PreparedSiopSubmission::Final(prepared) =
        prepare_siop_submission(instance(), &token, &SiopSubmissionOptions::default(), now())
            .unwrap()
    else {
        panic!("terminal result expected")
    };
    let same = prepare_siop_submission(
        prepared.finalization.instance.clone(),
        &token,
        &SiopSubmissionOptions::default(),
        now(),
    )
    .unwrap();
    assert!(matches!(same, PreparedSiopSubmission::SameTerminal(_)));

    let (different, _) = public_vector("nonce_mismatch");
    let replay = prepare_siop_submission(
        prepared.finalization.instance,
        &different,
        &SiopSubmissionOptions::default(),
        now(),
    )
    .unwrap();
    assert!(matches!(replay, PreparedSiopSubmission::ReplayConflict));
}
