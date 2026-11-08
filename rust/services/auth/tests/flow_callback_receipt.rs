//! Independent Auth verification of Flow's optional durable receipt projection.
//! The shared serializer owns wire production; Auth still owns callback HMAC,
//! policy/session correspondence and the tenant-scoped login claim.
use std::sync::Arc;

use chrono::{Duration, TimeZone, Utc};
use marty_auth::{
    verify_credential_callback, CallbackClaim, CredentialCallbackHeaders, CredentialCallbackPolicy,
    CredentialLoginStateStore, CredentialStateError, CredentialVerifiedPayload,
    PendingCredentialLogin,
};
use marty_oid4vp_contract::{
    build_verification_callback_payload, digest_domain_json, flow_callback_payload_digest,
    flow_result_digest, FlowVerificationReceiptContractVersion, FlowVerificationReceiptV1,
    FrozenPolicyIdentity, FLOW_REQUEST_BINDING_DIGEST_DOMAIN, VERIFICATION_RECEIPT,
};
use mmf_data::MemoryCache;
use mmf_push::{payload_digest, sign_event};
use serde_json::{json, Value};

const SECRET: &str = "test-flow-webhook-secret-at-least-32-bytes";

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 10).unwrap()
}

fn policy_revision() -> FrozenPolicyIdentity {
    FrozenPolicyIdentity {
        id: "policy-1".into(),
        version: 3,
        content_digest: format!("sha256:{}", "a".repeat(64)),
    }
}

fn produced_callback() -> Value {
    let mut result = json!({
        "policy_revision": policy_revision(),
        "evaluation_result": "passed",
        "decision": "allow",
        "decision_reason": "requirements satisfied",
        "verified_claims": {"email": "member@example.com"},
        "credential_results": [{"signature_valid": true, "satisfied": true}],
        "evaluation_timestamp": (now() - Duration::seconds(10)).to_rfc3339(),
        "submission_digest": "b".repeat(64),
        "warnings": [],
        "error_codes": [],
    });
    let completed_at = Some((now() - Duration::seconds(8)).to_rfc3339());
    let basis = build_verification_callback_payload(
        "flow-1",
        "policy-1",
        completed_at.clone(),
        result.as_object().unwrap(),
        payload_digest,
    )
    .unwrap();
    let mut receipt = FlowVerificationReceiptV1 {
        contract: FlowVerificationReceiptContractVersion::V1,
        organization_id: "org-1".into(),
        flow_instance_id: "flow-1".into(),
        policy: policy_revision(),
        request_binding_digest: digest_domain_json(
            FLOW_REQUEST_BINDING_DIGEST_DOMAIN,
            &json!({"flow_instance_id": "flow-1", "original_context": {"nonce": "private-nonce"}}),
        )
        .unwrap(),
        submission_digest: "b".repeat(64),
        nonce_digest: "c".repeat(64),
        result_digest: flow_result_digest(&result).unwrap(),
        callback_payload_digest: flow_callback_payload_digest(&basis).unwrap(),
        policy_evaluated_at_epoch_micros: (now() - Duration::seconds(10)).timestamp_micros(),
        nonce_consumed_at_epoch_micros: (now() - Duration::seconds(7)).timestamp_micros() + 123,
        nonce_retention_expires_at_epoch_micros: (now() + Duration::minutes(15)).timestamp_micros(),
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = receipt.recompute_digest().unwrap();
    result[VERIFICATION_RECEIPT] = serde_json::to_value(receipt).unwrap();
    build_verification_callback_payload(
        "flow-1",
        "policy-1",
        completed_at,
        result.as_object().unwrap(),
        payload_digest,
    )
    .unwrap()
}

fn headers(value: &Value) -> CredentialCallbackHeaders {
    let timestamp = now().to_rfc3339();
    CredentialCallbackHeaders {
        event: "flow.verification_completed".into(),
        audience: "marty-auth-service".into(),
        event_id: "flow-1".into(),
        signature: sign_event(
            SECRET,
            "marty-auth-service",
            "flow.verification_completed",
            "flow-1",
            &timestamp,
            value,
        )
        .unwrap(),
        timestamp,
    }
}

fn refresh_decision_digest(value: &mut Value) {
    value.as_object_mut().unwrap().remove("decision_digest");
    value["decision_digest"] = json!(payload_digest(value).unwrap());
}

fn refresh_receipt_digest(value: &mut Value) {
    let mut receipt: FlowVerificationReceiptV1 =
        serde_json::from_value(value[VERIFICATION_RECEIPT].clone()).unwrap();
    receipt.receipt_digest = receipt.recompute_digest().unwrap();
    value[VERIFICATION_RECEIPT] = serde_json::to_value(receipt).unwrap();
}

#[test]
fn receipt_bearing_flow_callback_roundtrips_through_independent_auth_dto() {
    let wire = produced_callback();
    let payload: CredentialVerifiedPayload = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(&payload).unwrap(), wire);
    let receipt = payload.verification_receipt.as_ref().unwrap();
    assert_eq!(receipt.organization_id, "org-1");
    assert_ne!(
        receipt.policy_evaluated_at_epoch_micros,
        receipt.nonce_consumed_at_epoch_micros,
    );
    verify_credential_callback(&payload, &headers(&wire), SECRET, now(), 300).unwrap();
}

#[test]
fn receipt_omission_or_digest_consistent_tampering_cannot_reuse_callback_hmac() {
    let original = produced_callback();
    let signed = headers(&original);
    for mutation in 0..7 {
        let mut changed = original.clone();
        match mutation {
            0 => {
                changed
                    .as_object_mut()
                    .unwrap()
                    .remove(VERIFICATION_RECEIPT);
            }
            1 => changed[VERIFICATION_RECEIPT]["organization_id"] = json!("org-2"),
            2 => {
                changed[VERIFICATION_RECEIPT]["request_binding_digest"] =
                    json!(format!("sha256:{}", "d".repeat(64)))
            }
            3 => {
                changed[VERIFICATION_RECEIPT]["result_digest"] =
                    json!(format!("sha256:{}", "d".repeat(64)))
            }
            4 => changed[VERIFICATION_RECEIPT]["submission_digest"] = json!("d".repeat(64)),
            5 => changed[VERIFICATION_RECEIPT]["nonce_digest"] = json!("d".repeat(64)),
            _ => {
                let consumed = changed[VERIFICATION_RECEIPT]["nonce_consumed_at_epoch_micros"]
                    .as_i64()
                    .unwrap();
                changed[VERIFICATION_RECEIPT]["nonce_consumed_at_epoch_micros"] =
                    json!(consumed + 1);
            }
        }
        if mutation != 0 {
            refresh_receipt_digest(&mut changed);
        }
        refresh_decision_digest(&mut changed);
        let payload = serde_json::from_value(changed).unwrap();
        assert!(
            verify_credential_callback(&payload, &signed, SECRET, now(), 300).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn even_a_signed_callback_must_match_the_receipts_instance_policy_and_decision() {
    let original = produced_callback();
    for mutation in 0..6 {
        let mut changed = original.clone();
        match mutation {
            0 => changed[VERIFICATION_RECEIPT]["flow_instance_id"] = json!("flow-2"),
            1 => changed[VERIFICATION_RECEIPT]["policy"]["id"] = json!("policy-2"),
            2 => changed[VERIFICATION_RECEIPT]["policy"]["version"] = json!(4),
            3 => changed["verified_claims"]["email"] = json!("other@example.com"),
            4 => changed["decision"] = json!("deny"),
            _ => changed["evidence_digest"] = json!("e".repeat(64)),
        }
        refresh_receipt_digest(&mut changed);
        refresh_decision_digest(&mut changed);
        let signed_changed = headers(&changed);
        let payload = serde_json::from_value(changed).unwrap();
        assert!(
            verify_credential_callback(&payload, &signed_changed, SECRET, now(), 300).is_err(),
            "mutation {mutation}"
        );
    }
}

fn callback_policy() -> CredentialCallbackPolicy {
    CredentialCallbackPolicy {
        secret: SECRET.into(),
        expected_policy_id: "policy-1".into(),
        expected_organization_id: "org-1".into(),
        maximum_timestamp_skew_seconds: 300,
        pending_ttl_seconds: 900,
        completion_ttl_seconds: 300,
        claim_lease_seconds: 30,
    }
}

#[tokio::test]
async fn receipt_tenant_mismatch_fails_before_new_or_completed_callback_claims() {
    let store = CredentialLoginStateStore::new(Arc::new(MemoryCache::default()), callback_policy())
        .unwrap();
    let nonce = "login-nonce-1";
    let now_ms = u64::try_from(now().timestamp_millis()).unwrap();
    store
        .save_pending(
            &PendingCredentialLogin {
                nonce: nonce.into(),
                flow_instance_id: "flow-1".into(),
                presentation_policy_id: "policy-1".into(),
                organization_id: "org-1".into(),
                status: "pending".into(),
                revocation_checked: false,
            },
            now_ms,
        )
        .await
        .unwrap();
    let correct_wire = produced_callback();
    let correct: CredentialVerifiedPayload = serde_json::from_value(correct_wire.clone()).unwrap();
    let mut wrong_wire = correct_wire.clone();
    wrong_wire[VERIFICATION_RECEIPT]["organization_id"] = json!("org-2");
    refresh_receipt_digest(&mut wrong_wire);
    refresh_decision_digest(&mut wrong_wire);
    let wrong_headers = headers(&wrong_wire);
    let wrong: CredentialVerifiedPayload = serde_json::from_value(wrong_wire).unwrap();
    // A valid callback signature cannot supply the consumer's tenant scope.
    verify_credential_callback(&wrong, &wrong_headers, SECRET, now(), 300).unwrap();
    assert_eq!(
        store.verify_callback(&wrong, &wrong_headers, now()),
        Err(CredentialStateError::Mismatch)
    );
    assert_eq!(
        store.claim_callback(nonce, &wrong, now_ms).await,
        Err(CredentialStateError::Mismatch)
    );

    store
        .verify_callback(&correct, &headers(&correct_wire), now())
        .unwrap();
    assert!(matches!(
        store.claim_callback(nonce, &correct, now_ms).await.unwrap(),
        CallbackClaim::Claimed(_)
    ));
    store
        .complete(nonce, "flow-1", "session-1", true, "valid", now_ms)
        .await
        .unwrap();
    assert_eq!(
        store.claim_callback(nonce, &wrong, now_ms).await,
        Err(CredentialStateError::Mismatch)
    );
    assert_eq!(
        store.claim_callback(nonce, &correct, now_ms).await.unwrap(),
        CallbackClaim::AlreadyProcessed
    );
}
