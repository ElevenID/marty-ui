//! Repository receipt fixtures use the real submission preparation and frozen
//! request shapes. Policy is a scoped mock here: these tests qualify persistence
//! and concurrency, not credential cryptography or canonical OID4VP evidence.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use marty_flow::{
    prepare_verification_submission, FlowInstanceRecord, FlowProviderError, FlowProviderRegistry,
    FlowVerificationSubmissionError, PreparedVerificationFinalization,
    PreparedVerificationSubmission, PresentationEvaluationRequest, PresentationEvaluationResult,
    PresentationPolicyProvider, PresentationPolicyReference, VerificationSubmissionInput,
    VerificationSubmissionOptions, CALLBACK_MAX_ATTEMPTS, CALLBACK_RETENTION_SECONDS,
};
use marty_verification::flow::FlowInstanceStatus;
use mmf_push::WebhookDestinationRegistry;
use serde_json::json;

use super::presentation_snapshot;

struct ReceiptPolicies {
    evaluated_at: Option<DateTime<Utc>>,
}

#[async_trait]
impl PresentationPolicyProvider for ReceiptPolicies {
    async fn get_policy(
        &self,
        policy_id: &str,
    ) -> Result<PresentationPolicyReference, FlowProviderError> {
        Ok(PresentationPolicyReference {
            id: policy_id.into(),
            organization_id: "org-1".into(),
            status: "active".into(),
            policy_revision: presentation_snapshot::revision(policy_id),
            prerequisite_evidence_profile: None,
            credential_authority: None,
            credential_requirements: vec![json!({"credential_type": "MemberCredential"})],
        })
    }

    async fn evaluate(
        &self,
        request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        assert_eq!(request.organization_id, "org-1");
        assert_eq!(request.policy_id, "policy-1");
        assert_eq!(request.principal_id, "receipt-principal-1");
        assert_eq!(request.audience, "did:web:receipt-verifier.example");
        assert!(request.oid4vp_transport.is_some());
        Ok(PresentationEvaluationResult {
            evaluation_timestamp: self.evaluated_at.map(|value| value.to_rfc3339()),
            policy_revision: request.expected_policy_revision.clone(),
            result: "passed".into(),
            decision: "allow".into(),
            decision_reason: Some("requirements satisfied".into()),
            verified_claims: [("member".into(), json!(true))].into(),
            credential_results: vec![json!({
                "credential_template_id": "member-template-1",
                "signature_valid": true,
                "revocation_checked": true,
                "not_revoked": true,
                "trust_check_passed": true,
                "warnings": []
            })],
            authentication_diagnostic: None,
            error_codes: Vec::new(),
            warnings: Vec::new(),
        })
    }
}

pub fn instance(
    id: &str,
    now: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
) -> FlowInstanceRecord {
    let mut instance = FlowInstanceRecord {
        id: id.into(),
        flow_definition_id: "__verification__".into(),
        organization_id: "org-1".into(),
        status: FlowInstanceStatus::AwaitingWallet,
        current_step_id: None,
        context: json!({
            "flow_type": "verification",
            "nonce": format!("receipt-verification-nonce-at-least-32-bytes-{id}"),
            "oid4vp_expected_state": "receipt-state-1",
            "oid4vp_verifier_context": true,
            "oid4vp_client_id": "did:web:receipt-verifier.example",
            "presentation_policy_id": "policy-1",
            "_marty_verification_principal_id": "receipt-principal-1",
            "verification_audience": "did:web:receipt-verifier.example",
            "trust_profile_id": "trust-1",
            "callback_url": format!("https://callbacks.example/flows/{id}")
        }),
        step_history: Vec::new(),
        state_history: Vec::new(),
        subject_id: None,
        subject_type: "holder".into(),
        external_reference: None,
        application_flow_key_hash: None,
        started_at: Some(now),
        completed_at: None,
        expires_at: Some(expires_at.unwrap_or(now + Duration::minutes(15))),
        result: None,
        error: None,
        created_at: now,
        updated_at: now,
    };
    presentation_snapshot::freeze_default(&mut instance);
    presentation_snapshot::emit_query(
        &mut instance,
        "dcql_query",
        json!({"credentials": [{
            "id": "member", "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:receipt:member"]}
        }]}),
    );
    instance
}

pub fn input(token: &str) -> VerificationSubmissionInput {
    VerificationSubmissionInput {
        vp_token: json!({"member": [token]}).to_string(),
        presentation_submission: None,
        state: Some("receipt-state-1".into()),
        audience_override: None,
    }
}

pub async fn prepare(
    instance: FlowInstanceRecord,
    evaluated_at: Option<DateTime<Utc>>,
    token: &str,
    now: DateTime<Utc>,
) -> Result<PreparedVerificationSubmission, FlowVerificationSubmissionError> {
    prepare_verification_submission(
        &FlowProviderRegistry {
            presentation_policy: Some(Arc::new(ReceiptPolicies { evaluated_at })),
            ..Default::default()
        },
        instance,
        input(token),
        &VerificationSubmissionOptions {
            callback_destinations: WebhookDestinationRegistry::parse(
                "org-1|https://callbacks.example/flows/__MARTY_TOKEN__",
            )
            .unwrap(),
            callback_secret: Some("0123456789abcdef0123456789abcdef".into()),
            verifier_sender_id: "did:web:receipt-verifier.example".into(),
            nonce_ttl_seconds: 900,
            callback_retention_seconds: CALLBACK_RETENTION_SECONDS,
            callback_max_attempts: CALLBACK_MAX_ATTEMPTS,
        },
        now,
    )
    .await
}

pub async fn finalization(
    instance: FlowInstanceRecord,
    evaluated_at: Option<DateTime<Utc>>,
    token: &str,
    now: DateTime<Utc>,
) -> Result<PreparedVerificationFinalization, FlowVerificationSubmissionError> {
    match prepare(instance, evaluated_at, token, now).await? {
        PreparedVerificationSubmission::Final(prepared) => Ok(*prepared),
        other => panic!("receipt fixture must prepare a terminal result: {other:?}"),
    }
}
