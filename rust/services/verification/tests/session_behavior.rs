use chrono::{Duration, TimeZone, Utc};
use marty_verification_service::{
    sha256_text, MemorySessionStore, SessionStatus, SessionStore, StartVerificationRequest,
    SubmissionOutcome, VerificationSession,
};
use serde_json::{json, Value};

fn request() -> StartVerificationRequest {
    StartVerificationRequest {
        organization_id: "org-1".into(),
        presentation_policy_id: Some("policy-1".into()),
        response_type: "vp_token".into(),
        trust_profile_id: None,
        deployment_profile_id: Some("deploy-1".into()),
        external_reference: Some("case-123".into()),
        callback_url: None,
        expiry_minutes: 15,
        purpose: "Age verification".into(),
    }
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 21, 12, 0, 0).unwrap()
}

#[test]
fn language_neutral_contract_covers_the_released_surface() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/verification-service-behavior.json"
    ))
    .unwrap();
    assert_eq!(contract["service"], "verification");
    assert_eq!(contract["routes"].as_array().unwrap().len(), 8);
    assert_eq!(
        contract["submission_outcomes"],
        json!([
            "claimed",
            "committed",
            "duplicate",
            "busy",
            "conflict",
            "expired",
            "missing"
        ])
    );
    assert!(contract["invariants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| value.as_str().unwrap().contains("raw presentation tokens")));
}

#[test]
fn protocol_projection_exposes_only_the_stable_shape() {
    let session = VerificationSession::new(&request(), now()).unwrap();
    let body = session.protocol_value();
    let object = body.as_object().unwrap();
    let allowed = [
        "id",
        "flow_id",
        "flow_instance_id",
        "presentation_policy_id",
        "deployment_profile_id",
        "verifier_nonce",
        "holder_id",
        "status",
        "result",
        "expires_at",
        "created_at",
        "completed_at",
        "updated_at",
        "error",
    ];
    assert!(object.keys().all(|key| allowed.contains(&key.as_str())));
    assert_eq!(body["status"], "PENDING");
    assert_eq!(body["presentation_policy_id"], "policy-1");
    for prohibited in [
        "session_id",
        "organization_id",
        "evaluation_principal_id",
        "response_type",
        "nonce",
        "external_reference",
        "purpose",
        "verified_claims",
        "credential_results",
    ] {
        assert!(body.get(prohibited).is_none(), "{prohibited}");
    }
}

#[tokio::test]
async fn terminal_records_are_minimized_before_persistence() {
    let store = MemorySessionStore::new();
    let mut session = VerificationSession::new(&request(), now()).unwrap();
    session.status = SessionStatus::Completed;
    session.result = Some("passed".into());
    session.decision = Some("allow".into());
    session.completed_at = Some(now());
    session.updated_at = now();
    session.vp_token = Some("raw-vp-token".into());
    session.verified_claims = [
        ("email".into(), json!("alice@example.com")),
        ("given_name".into(), json!("Alice")),
    ]
    .into_iter()
    .collect();
    session.credential_results = vec![json!({
        "credential_template_id": "template-1",
        "satisfied": true,
        "revocation_checked": true,
        "claim_results": [{
            "claim_name": "email",
            "satisfied": true,
            "presented_value": "alice@example.com"
        }]
    })];
    session.inspection_performed = true;
    let inspection = json!({"document_number":"SECRET-123","result":"verified"}).to_string();
    session.inspection_result = inspection.clone();
    store.save(session.clone()).await.unwrap();

    let stored = store.get(&session.session_id).await.unwrap().unwrap();
    let encoded = serde_json::to_string(&stored).unwrap();
    assert_eq!(stored.vp_token_sha256, Some(sha256_text("raw-vp-token")));
    assert!(stored.vp_token.is_none());
    assert_eq!(
        stored.verified_claims,
        [
            ("email".into(), json!(true)),
            ("given_name".into(), json!(true))
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(stored.inspection_result, "verified");
    assert_eq!(
        stored.inspection_result_sha256,
        Some(sha256_text(&inspection))
    );
    for secret in [
        "alice@example.com",
        "SECRET-123",
        "presented_value",
        "raw-vp-token",
    ] {
        assert!(!encoded.contains(secret), "{secret}");
    }
}

#[tokio::test]
async fn expiry_uses_the_supplied_shared_clock() {
    let store = MemorySessionStore::new();
    let mut session = VerificationSession::new(&request(), now()).unwrap();
    session.evaluation_principal_id = "user-1".into();
    let id = session.session_id.clone();
    store.save(session).await.unwrap();
    let expired = store
        .get_at(&id, now() + Duration::minutes(16))
        .await
        .unwrap();
    assert_eq!(expired.status, SessionStatus::Expired);
    assert_eq!(
        expired.error.as_deref(),
        Some("Session expired before presentation was submitted")
    );
    assert!(expired.evaluation_principal_id.is_empty());
}

#[tokio::test]
async fn one_digest_owns_the_session_and_duplicate_reuses_terminal_state() {
    let store = MemorySessionStore::new();
    let session = VerificationSession::new(&request(), now()).unwrap();
    let id = session.session_id.clone();
    store.save(session).await.unwrap();
    let digest_a = sha256_text("presentation-a");
    let digest_b = sha256_text("presentation-b");

    let (first, competing) = tokio::join!(
        store.claim_at(&id, &digest_a, now()),
        store.claim_at(&id, &digest_b, now())
    );
    assert_eq!(
        [first.outcome, competing.outcome]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        [SubmissionOutcome::Claimed, SubmissionOutcome::Conflict]
            .into_iter()
            .collect()
    );
    let claimed = if first.outcome == SubmissionOutcome::Claimed {
        first
    } else {
        competing
    };
    let claimed_digest = claimed
        .session
        .as_ref()
        .unwrap()
        .vp_token_sha256
        .clone()
        .unwrap();
    let busy = store.claim_at(&id, &claimed_digest, now()).await;
    assert_eq!(busy.outcome, SubmissionOutcome::Busy);

    let reclaimed = store
        .claim_at(&id, &claimed_digest, now() + Duration::seconds(31))
        .await;
    assert_eq!(reclaimed.outcome, SubmissionOutcome::Claimed);
    assert_ne!(reclaimed.token, claimed.token);
    let mut terminal = reclaimed.session.clone().unwrap();
    terminal.status = SessionStatus::Completed;
    terminal.result = Some("passed".into());
    terminal.decision = Some("allow".into());
    terminal.completed_at = Some(now() + Duration::seconds(32));
    terminal.updated_at = terminal.completed_at.unwrap();
    terminal
        .verified_claims
        .insert("email".into(), json!("alice@example.com"));

    let stale = store
        .finalize_at(
            &id,
            &claimed_digest,
            claimed.token.as_deref().unwrap(),
            terminal.clone(),
        )
        .await
        .unwrap();
    assert_eq!(stale.outcome, SubmissionOutcome::Busy);
    let committed = store
        .finalize_at(
            &id,
            &claimed_digest,
            reclaimed.token.as_deref().unwrap(),
            terminal,
        )
        .await
        .unwrap();
    assert_eq!(committed.outcome, SubmissionOutcome::Committed);
    assert_eq!(
        committed.session.as_ref().unwrap().verified_claims["email"],
        true
    );
    let duplicate = store.claim_submission(&id, &claimed_digest).await.unwrap();
    assert_eq!(duplicate.outcome, SubmissionOutcome::Duplicate);
    assert_eq!(
        duplicate.session.unwrap().completed_at,
        committed.session.unwrap().completed_at
    );
}
