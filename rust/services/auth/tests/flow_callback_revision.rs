//! Flow's shared production callback builder and Auth's independent callback
//! authentication, without introducing a dependency between service crates.
use chrono::{TimeZone, Utc};
use marty_auth::{
    verify_credential_callback, CredentialCallbackHeaders, CredentialVerifiedPayload,
};
use marty_oid4vp_contract::{build_verification_callback_payload, FrozenPolicyIdentity};
use mmf_push::{canonical_event_bytes, payload_digest, sign_event};
use serde_json::{json, Value};

const SECRET: &str = "test-flow-webhook-secret-at-least-32-bytes";

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap()
}

fn policy_revision() -> FrozenPolicyIdentity {
    FrozenPolicyIdentity {
        id: "policy-1".into(),
        version: 1,
        content_digest: format!("sha256:{}", "a".repeat(64)),
    }
}

fn flow_callback() -> Value {
    let terminal_result = json!({
        "evaluation_result": "passed",
        "decision": "allow",
        "decision_reason": "requirements satisfied",
        "verified_claims": {"email": "member@example.com"},
        "credential_results": [{"signature_valid": true}],
        "policy_revision": policy_revision(),
    });
    build_verification_callback_payload(
        "flow-1",
        "policy-1",
        Some(now().to_rfc3339()),
        terminal_result.as_object().unwrap(),
        payload_digest,
    )
    .unwrap()
}

fn sign(value: &Value) -> CredentialCallbackHeaders {
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

#[test]
fn serialized_flow_callback_is_accepted_and_revision_tampering_is_rejected() {
    let produced = flow_callback();
    let payload: CredentialVerifiedPayload =
        serde_json::from_slice(&serde_json::to_vec(&produced).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(&payload).unwrap(), produced);
    assert_eq!(payload.policy_revision, Some(policy_revision()));
    let headers = sign(&produced);
    verify_credential_callback(&payload, &headers, SECRET, now(), 300).unwrap();
    for mutation in 0..3 {
        let mut changed = produced.clone();
        match mutation {
            0 => changed["policy_revision"]["version"] = json!(2),
            1 => {
                changed["policy_revision"]["content_digest"] =
                    json!(format!("sha256:{}", "b".repeat(64)))
            }
            _ => changed["decision_digest"] = json!("0".repeat(64)),
        }
        let changed_payload = serde_json::from_value(changed.clone()).unwrap();
        assert!(
            verify_credential_callback(&changed_payload, &headers, SECRET, now(), 300).is_err()
        );
        // Recomputing the ordinary digest still cannot replace the signed
        // policy identity without authenticating the changed callback.
        refresh_decision_digest(&mut changed);
        if mutation != 2 {
            let changed_payload = serde_json::from_value(changed).unwrap();
            assert!(
                verify_credential_callback(&changed_payload, &headers, SECRET, now(), 300).is_err()
            );
        }
    }
    for mutation in 0..3 {
        let mut invalid = produced.clone();
        match mutation {
            0 => invalid["policy_revision"]["id"] = json!("other-policy"),
            1 => invalid["policy_revision"]["version"] = json!(0),
            _ => invalid["policy_revision"]["content_digest"] = json!("malformed"),
        }
        refresh_decision_digest(&mut invalid);
        let signed_invalid = sign(&invalid);
        let payload = serde_json::from_value(invalid).unwrap();
        assert!(verify_credential_callback(&payload, &signed_invalid, SECRET, now(), 300).is_err());
    }
}

#[test]
fn queued_legacy_callback_without_revision_preserves_its_canonical_signature() {
    let mut legacy = flow_callback();
    legacy.as_object_mut().unwrap().remove("policy_revision");
    refresh_decision_digest(&mut legacy);
    let headers = sign(&legacy);
    // Frozen pre-revision wire bytes: retaining a queued callback must preserve
    // its canonical event, evidence/decision digests and HMAC exactly.
    let expected = concat!(
        r#"{"audience":"marty-auth-service","event":"flow.verification_completed","event_id":"flow-1","payload":{"completed_at":"2026-08-20T12:00:00+00:00","decision":"allow","decision_digest":"#,
        r#""a3d56771192221d2882130a019b9d237bb3823f762a89431fa29b30d94008450","decision_reason":"requirements satisfied","evidence_digest":"#,
        r#""351f0ffdabeedb31aee1547edf5af54de8bd68d6042ecc2d4da7da4364a04a09","flow_instance_id":"flow-1","presentation_policy_id":"policy-1","result":"passed","verified_claims":{"email":"member@example.com"}},"timestamp":"2026-08-20T12:00:00+00:00"}"#,
    );
    assert_eq!(
        canonical_event_bytes(
            &headers.audience,
            &headers.event,
            &headers.event_id,
            &headers.timestamp,
            &legacy,
        )
        .unwrap(),
        expected.as_bytes(),
    );
    assert_eq!(
        headers.signature,
        "sha256=fcf88650504ceed3473ba0239095d61b33bdb95d4aa20d952e594e965a0035a2",
    );
    let payload: CredentialVerifiedPayload = serde_json::from_value(legacy.clone()).unwrap();
    assert!(payload.policy_revision.is_none());
    assert_eq!(serde_json::to_value(&payload).unwrap(), legacy);
    verify_credential_callback(&payload, &headers, SECRET, now(), 300).unwrap();
}
