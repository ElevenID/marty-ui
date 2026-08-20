use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, TimeZone, Utc};
use ed25519_dalek::SigningKey;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use marty_flow::{
    prepare_siop_submission, FlowInstanceRecord, FlowSiopSubmissionError, PreparedSiopSubmission,
    SiopSubmissionOptions,
};
use marty_oid4vci::siop::JWK_THUMBPRINT_SUBJECT_PREFIX;
use marty_verification::flow::FlowInstanceStatus;
use p256::{elliptic_curve::sec1::ToEncodedPoint, pkcs8::EncodePrivateKey, SecretKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

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

fn signed_token(overrides: Value) -> (String, String) {
    let secret = SecretKey::from_slice(&[7_u8; 32]).unwrap();
    let public = secret.public_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(public.x().unwrap());
    let y = URL_SAFE_NO_PAD.encode(public.y().unwrap());
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let thumbprint = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
    let subject = format!("{JWK_THUMBPRINT_SUBJECT_PREFIX}:sha-256:{thumbprint}");
    let mut claims = json!({
        "iss": subject,
        "sub": subject,
        "sub_jwk": {"kty":"EC", "crv":"P-256", "alg":"ES256", "x":x, "y":y},
        "aud": "https://verifier.example/verifier",
        "nonce": "nonce-with-at-least-32-bytes-1234567890",
        "iat": now().timestamp(),
        "exp": (now() + Duration::minutes(5)).timestamp()
    });
    for (name, value) in overrides.as_object().unwrap() {
        claims[name] = value.clone();
    }
    let der = secret.to_pkcs8_der().unwrap();
    let token = encode(
        &Header::new(Algorithm::ES256),
        &claims,
        &EncodingKey::from_ec_der(der.as_bytes()),
    )
    .unwrap();
    (token, subject)
}

fn signed_ed25519_token() -> (String, String) {
    let secret = SigningKey::from_bytes(&[9_u8; 32]);
    let x = URL_SAFE_NO_PAD.encode(secret.verifying_key().as_bytes());
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    let thumbprint = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
    let subject = format!("{JWK_THUMBPRINT_SUBJECT_PREFIX}:sha-256:{thumbprint}");
    let claims = json!({
        "iss": subject,
        "sub": subject,
        "sub_jwk": {"kty":"OKP", "crv":"Ed25519", "alg":"EdDSA", "x":x},
        "aud": "https://verifier.example/verifier",
        "nonce": "nonce-with-at-least-32-bytes-1234567890",
        "iat": now().timestamp(),
        "exp": (now() + Duration::minutes(5)).timestamp()
    });
    let der = secret.to_pkcs8_der().unwrap();
    let token = encode(
        &Header::new(Algorithm::EdDSA),
        &claims,
        &EncodingKey::from_ed_der(der.as_bytes()),
    )
    .unwrap();
    (token, subject)
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

    let (token, subject) = signed_token(json!({
        "aud": ["another-client", "https://verifier.example/verifier"]
    }));
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

    let (ed_token, ed_subject) = signed_ed25519_token();
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
    let (issuer_mismatch, _) = signed_token(json!({"iss": "different"}));
    assert!(matches!(
        prepare_siop_submission(
            instance(),
            &issuer_mismatch,
            &SiopSubmissionOptions::default(),
            now()
        ),
        Err(FlowSiopSubmissionError::IssuerSubjectMismatch)
    ));

    let (audience_mismatch, _) = signed_token(json!({"aud": "different"}));
    assert!(matches!(
        prepare_siop_submission(
            instance(),
            &audience_mismatch,
            &SiopSubmissionOptions::default(),
            now()
        ),
        Err(FlowSiopSubmissionError::AudienceMismatch)
    ));

    let (nonce_mismatch, _) = signed_token(json!({"nonce": "different"}));
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

    let (mut tampered, _) = signed_token(json!({}));
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
    for (overrides, expected) in [
        (
            json!({"iat": (now() + Duration::seconds(61)).timestamp()}),
            "FLOW.SIOP_IAT_IN_FUTURE",
        ),
        (
            json!({"exp": (now() - Duration::seconds(60)).timestamp()}),
            "FLOW.SIOP_TOKEN_EXPIRED",
        ),
        (
            json!({"iat": (now() + Duration::minutes(5)).timestamp(), "exp": (now() + Duration::minutes(5)).timestamp()}),
            "FLOW.SIOP_IAT_IN_FUTURE",
        ),
        (
            json!({"iat": (now() - Duration::minutes(2)).timestamp()}),
            "FLOW.SIOP_TOKEN_PREDATES_TRANSACTION",
        ),
        (json!({"iat": true}), "FLOW.SIOP_INVALID_TIME_CLAIMS"),
    ] {
        let (token, _) = signed_token(overrides);
        let error =
            prepare_siop_submission(instance(), &token, &SiopSubmissionOptions::default(), now())
                .unwrap_err();
        assert!(error.to_string().starts_with(expected), "{error}");
    }

    let (invalid_window, _) = signed_token(json!({
        "iat": now().timestamp(),
        "exp": now().timestamp()
    }));
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
    let (token, _) = signed_token(json!({}));
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

    let (different, _) = signed_token(json!({"nonce": "different"}));
    let replay = prepare_siop_submission(
        prepared.finalization.instance,
        &different,
        &SiopSubmissionOptions::default(),
        now(),
    )
    .unwrap();
    assert!(matches!(replay, PreparedSiopSubmission::ReplayConflict));
}
