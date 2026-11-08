//! Actual Flow callback production and Auth callback authentication, with a
//! synthetic policy port isolating this transport contract from wallet crypto.
use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use marty_auth::{
    verify_credential_callback, CredentialCallbackHeaders, CredentialVerifiedPayload,
};
use marty_flow::{
    prepare_verification_submission, FlowInstanceRecord, FlowProviderError, FlowProviderRegistry,
    PreparedVerificationSubmission, PresentationEvaluationRequest, PresentationEvaluationResult,
    PresentationPolicyProvider, PresentationPolicyReference, VerificationSubmissionInput,
    VerificationSubmissionOptions, CALLBACK_MAX_ATTEMPTS, CALLBACK_RETENTION_SECONDS,
};
use mmf_push::{payload_digest, sign_event, WebhookDestinationRegistry};
use serde_json::{json, Value};

#[path = "../../flow/tests/support/presentation_snapshot.rs"]
mod presentation_snapshot;

const SECRET: &str = "test-flow-webhook-secret-at-least-32-bytes";

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 20, 12, 0, 0).unwrap()
}

struct Policy;

#[async_trait]
impl PresentationPolicyProvider for Policy {
    async fn get_policy(&self, _: &str) -> Result<PresentationPolicyReference, FlowProviderError> {
        unreachable!("submission uses the frozen policy")
    }

    async fn evaluate(
        &self,
        request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        assert_eq!(
            request.expected_policy_revision,
            presentation_snapshot::revision("policy-1")
        );
        Ok(PresentationEvaluationResult {
            policy_revision: request.expected_policy_revision.clone(),
            result: "passed".into(),
            decision: "allow".into(),
            decision_reason: Some("requirements satisfied".into()),
            verified_claims: BTreeMap::from([("email".into(), json!("member@example.com"))]),
            credential_results: vec![json!({"signature_valid": true})],
            authentication_diagnostic: None,
            error_codes: Vec::new(),
            warnings: Vec::new(),
        })
    }
}

async fn flow_callback() -> Value {
    let mut instance = FlowInstanceRecord {
        id: "flow-1".into(),
        flow_definition_id: "__verification__".into(),
        organization_id: "org-1".into(),
        status: serde_json::from_value(json!("awaiting_wallet")).unwrap(),
        current_step_id: None,
        context: json!({
            "flow_type": "verification",
            "nonce": "owned-callback-nonce-with-32-bytes-1234567890",
            "presentation_policy_id": "policy-1",
            "_marty_verification_principal_id": "member-1",
            "oid4vp_verifier_context": true,
            "oid4vp_client_id": "did:web:verifier.example",
            "verification_audience": "did:web:verifier.example",
            "callback_url": "https://callbacks.example/result"
        }),
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
        json!({"credentials": [{"id": "member"}]}),
    );
    let PreparedVerificationSubmission::Final(prepared) = prepare_verification_submission(
        &FlowProviderRegistry {
            presentation_policy: Some(Arc::new(Policy)),
            ..Default::default()
        },
        instance,
        VerificationSubmissionInput {
            vp_token: "header.payload.signature".into(),
            presentation_submission: None,
            state: None,
            audience_override: None,
        },
        &VerificationSubmissionOptions {
            callback_destinations: WebhookDestinationRegistry::parse(
                "org-1|https://callbacks.example/result",
            )
            .unwrap(),
            callback_secret: Some(SECRET.into()),
            verifier_sender_id: "did:web:verifier.example".into(),
            nonce_ttl_seconds: 900,
            callback_retention_seconds: CALLBACK_RETENTION_SECONDS,
            callback_max_attempts: CALLBACK_MAX_ATTEMPTS,
        },
        now(),
    )
    .await
    .unwrap() else {
        panic!("Flow callback must be prepared")
    };
    prepared.callback.unwrap().payload
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

#[tokio::test]
async fn serialized_flow_callback_is_accepted_and_revision_tampering_is_rejected() {
    let produced = flow_callback().await;
    let payload: CredentialVerifiedPayload =
        serde_json::from_slice(&serde_json::to_vec(&produced).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(&payload).unwrap(), produced);
    assert_eq!(
        payload.policy_revision,
        Some(presentation_snapshot::revision("policy-1"))
    );
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

#[tokio::test]
async fn queued_legacy_callback_without_revision_preserves_its_canonical_signature() {
    let mut legacy = flow_callback().await;
    legacy.as_object_mut().unwrap().remove("policy_revision");
    refresh_decision_digest(&mut legacy);
    let headers = sign(&legacy);
    let payload: CredentialVerifiedPayload = serde_json::from_value(legacy.clone()).unwrap();
    assert!(payload.policy_revision.is_none());
    assert_eq!(serde_json::to_value(&payload).unwrap(), legacy);
    verify_credential_callback(&payload, &headers, SECRET, now(), 300).unwrap();
}
