use std::sync::Arc;

use chrono::{TimeZone as _, Utc};
use marty_auth::{
    build_canvas_lti_user, credential_callback_session_id, failure_payload,
    verify_credential_callback, CallbackClaim, CredentialCallbackHeaders, CredentialCallbackPolicy,
    CredentialLoginPoll, CredentialLoginStateStore, CredentialStateError,
    CredentialVerifiedPayload, PendingCredentialLogin, AUTH_CALLBACK_AUDIENCE,
};
use mmf_data::MemoryCache;
use mmf_push::{canonical_event_bytes, payload_digest, sign_event, verify_event_signature};
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/auth-login-state-behavior.json"
    )))
    .expect("auth login-state fixture")
}

fn webhook_helper_reference() -> Value {
    let reference: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/auth-webhook-helper-ascii-reference.json"
    )))
    .expect("captured Python ASCII webhook helper contract");
    assert_eq!(
        reference["schema"],
        "marty.auth-webhook-helper-ascii-reference/v1"
    );
    reference
}

fn verify_reference_event(signature: &str, secret: &str, event: &Value) -> bool {
    verify_event_signature(
        signature,
        secret,
        event["audience"].as_str().unwrap(),
        event["event"].as_str().unwrap(),
        event["event_id"].as_str().unwrap(),
        event["timestamp"].as_str().unwrap(),
        &event["payload"],
    )
}

#[test]
fn callback_signature_matches_retired_python_ascii_contract() {
    let reference = webhook_helper_reference();
    let case = &reference["signed_event"];
    let event = &case["event"];
    let secret = case["secret"].as_str().unwrap();
    assert_eq!(event["audience"], AUTH_CALLBACK_AUDIENCE);
    let canonical = canonical_event_bytes(
        event["audience"].as_str().unwrap(),
        event["event"].as_str().unwrap(),
        event["event_id"].as_str().unwrap(),
        event["timestamp"].as_str().unwrap(),
        &event["payload"],
    )
    .unwrap();
    assert_eq!(
        canonical,
        case["canonical_event_utf8"].as_str().unwrap().as_bytes()
    );
    let signature = sign_event(
        secret,
        event["audience"].as_str().unwrap(),
        event["event"].as_str().unwrap(),
        event["event_id"].as_str().unwrap(),
        event["timestamp"].as_str().unwrap(),
        &event["payload"],
    )
    .unwrap();
    assert_eq!(signature, case["signature"].as_str().unwrap());
    assert_eq!(case["valid"], true);
    assert!(verify_reference_event(&signature, secret, event));
    let tampered = case["tampered"].as_array().unwrap();
    assert_eq!(tampered.len(), 2);
    for (mutation, field) in tampered.iter().zip(["event_id", "audience"]) {
        assert_eq!(mutation["field"], field);
        assert_eq!(mutation["valid"], false);
        let mut changed = event.clone();
        changed[field] = mutation["value"].clone();
        assert_ne!(changed[field], event[field]);
        assert!(!verify_reference_event(&signature, secret, &changed));
    }
}

#[test]
fn callback_signature_preserves_retired_python_weak_secret_rejection() {
    let reference = webhook_helper_reference();
    let case = &reference["weak_event"];
    let event = &case["event"];
    let secret = case["secret"].as_str().unwrap();
    let error = sign_event(
        secret,
        event["audience"].as_str().unwrap(),
        event["event"].as_str().unwrap(),
        event["event_id"].as_str().unwrap(),
        event["timestamp"].as_str().unwrap(),
        &event["payload"],
    )
    .expect_err("the Python reference rejects weak signing secrets");
    // Match the original test's diagnostic substring, not Python exception
    // identity or native error wrapping. All cryptography stays in mmf-push.
    let detail = case["sign_error_contains"].as_str().unwrap();
    assert_eq!(detail, "at least 32 bytes");
    assert!(case["sign_error"].as_str().unwrap().contains(detail));
    assert!(error.to_string().contains(detail));
    assert_eq!(case["valid"], false);
    assert!(!verify_reference_event(
        case["signature"].as_str().unwrap(),
        secret,
        event,
    ));
}

fn policy() -> CredentialCallbackPolicy {
    CredentialCallbackPolicy {
        secret: "test-flow-webhook-secret-at-least-32-bytes".into(),
        expected_policy_id: "policy-1".into(),
        expected_organization_id: "org-1".into(),
        maximum_timestamp_skew_seconds: 300,
        pending_ttl_seconds: 900,
        completion_ttl_seconds: 300,
        claim_lease_seconds: 30,
    }
}

fn pending(nonce: &str) -> PendingCredentialLogin {
    PendingCredentialLogin {
        nonce: nonce.into(),
        flow_instance_id: "flow-1".into(),
        presentation_policy_id: "policy-1".into(),
        organization_id: "org-1".into(),
        status: "pending".into(),
        revocation_checked: false,
    }
}

fn test_nonce() -> String {
    format!("test-{}", uuid::Uuid::new_v4())
}

fn payload() -> CredentialVerifiedPayload {
    let mut payload = CredentialVerifiedPayload {
        flow_instance_id: "flow-1".into(),
        result: "passed".into(),
        decision: "allow".into(),
        decision_reason: String::new(),
        verified_claims: serde_json::from_value(json!({"email": "alice@example.com"})).unwrap(),
        presentation_policy_id: "policy-1".into(),
        completed_at: "2026-08-20T12:00:00Z".into(),
        evidence_digest: "a".repeat(64),
        decision_digest: String::new(),
    };
    let mut basis = serde_json::to_value(&payload).unwrap();
    basis.as_object_mut().unwrap().remove("decision_digest");
    payload.decision_digest = payload_digest(&basis).unwrap();
    payload
}

#[test]
fn canvas_failure_and_session_id_kernels_match_shared_vectors() {
    let fixture = fixture();
    for case in fixture["session_id_vectors"].as_array().unwrap() {
        assert_eq!(
            credential_callback_session_id(
                case["secret"].as_str().unwrap(),
                case["flow_instance_id"].as_str().unwrap(),
                case["nonce"].as_str().unwrap(),
            )
            .to_string(),
            case["expected"].as_str().unwrap()
        );
    }
    for case in fixture["canvas_cases"].as_array().unwrap() {
        let user = build_canvas_lti_user(&case["session"]).expect("Canvas user");
        let expected = &case["expected"];
        assert_eq!(user.user_id, expected["user_id"]);
        assert_eq!(user.email, expected["email"]);
        assert_eq!(user.username.as_deref(), expected["username"].as_str());
        assert_eq!(user.given_name.as_deref(), expected["given_name"].as_str());
        assert_eq!(
            user.family_name.as_deref(),
            expected["family_name"].as_str()
        );
        assert_eq!(serde_json::to_value(user.roles).unwrap(), expected["roles"]);
        assert_eq!(
            user.organization_id.as_deref(),
            expected["organization_id"].as_str()
        );
    }
    for case in fixture["failure_cases"].as_array().unwrap() {
        let failure = failure_payload(case["reason"].as_str().unwrap());
        assert_eq!(failure.reason_code.as_deref(), case["reason_code"].as_str());
        assert!(failure
            .message
            .as_deref()
            .unwrap()
            .contains(case["message_contains"].as_str().unwrap()));
        assert_eq!(failure.detail.is_some(), case["detail"].as_bool().unwrap());
    }
}

#[test]
fn callback_authentication_is_digest_event_signature_and_time_bound() {
    let payload = payload();
    let now = Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap();
    let timestamp = now.to_rfc3339();
    let payload_value = serde_json::to_value(&payload).unwrap();
    let headers = CredentialCallbackHeaders {
        event: "flow.verification_completed".into(),
        audience: AUTH_CALLBACK_AUDIENCE.into(),
        event_id: payload.flow_instance_id.clone(),
        timestamp: timestamp.clone(),
        signature: sign_event(
            &policy().secret,
            AUTH_CALLBACK_AUDIENCE,
            "flow.verification_completed",
            &payload.flow_instance_id,
            &timestamp,
            &payload_value,
        )
        .unwrap(),
    };
    verify_credential_callback(&payload, &headers, &policy().secret, now, 300)
        .expect("fresh callback");
    let expired = now + chrono::Duration::seconds(301);
    assert!(matches!(
        verify_credential_callback(&payload, &headers, &policy().secret, expired, 300),
        Err(CredentialStateError::InvalidCallback(_))
    ));
    let mut tampered = payload;
    tampered
        .verified_claims
        .insert("email".into(), json!("mallory@example.com"));
    assert!(verify_credential_callback(&tampered, &headers, &policy().secret, now, 300).is_err());
}

#[tokio::test]
async fn callback_claim_completion_poll_and_finalize_are_single_use() {
    let store = CredentialLoginStateStore::new(Arc::new(MemoryCache::default()), policy()).unwrap();
    let nonce = test_nonce();
    store.save_pending(&pending(&nonce), 1_000).await.unwrap();
    assert_eq!(
        store.poll(&nonce, 1_000).await.unwrap(),
        CredentialLoginPoll::Pending
    );
    assert!(matches!(
        store
            .claim_callback(&nonce, &payload(), 1_000)
            .await
            .unwrap(),
        CallbackClaim::Claimed(_)
    ));
    assert_eq!(
        store.claim_callback(&nonce, &payload(), 1_000).await,
        Err(CredentialStateError::AlreadyClaimed)
    );
    store
        .complete(&nonce, "flow-1", "session-1", true, "valid", 1_000)
        .await
        .unwrap();
    assert_eq!(
        store
            .claim_callback(&nonce, &payload(), 1_000)
            .await
            .unwrap(),
        CallbackClaim::AlreadyProcessed
    );
    assert!(matches!(
        store.poll(&nonce, 1_000).await.unwrap(),
        CredentialLoginPoll::Completed {
            revocation_checked: true,
            ..
        }
    ));
    let completion = store.finalize(&nonce, 1_000).await.unwrap().unwrap();
    assert_eq!(completion.session_id.as_deref(), Some("session-1"));
    assert!(store.finalize(&nonce, 1_000).await.unwrap().is_none());
}

#[tokio::test]
async fn mismatched_callbacks_fail_before_acquiring_the_lease() {
    let store = CredentialLoginStateStore::new(Arc::new(MemoryCache::default()), policy()).unwrap();
    let nonce = test_nonce();
    store.save_pending(&pending(&nonce), 1_000).await.unwrap();
    let mut wrong = payload();
    wrong.presentation_policy_id = "policy-2".into();
    assert_eq!(
        store.claim_callback(&nonce, &wrong, 1_000).await,
        Err(CredentialStateError::Mismatch)
    );
    assert!(matches!(
        store
            .claim_callback(&nonce, &payload(), 1_000)
            .await
            .unwrap(),
        CallbackClaim::Claimed(_)
    ));
}
