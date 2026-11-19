//! Delegated Decision Receipt v1 serialization and JWS signing boundary.
//!
//! The receipt is signed evidence of one evaluation, not a bearer permit and
//! not permission to execute a domain side effect. The signer must be backed by
//! the deployment's existing managed signing-key/KMS service. This module does
//! not create keys, implement JOSE verification, or own merchant idempotency.

use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::{domain::valid_uri, DelegationUseEvaluation, Principal};

pub const DELEGATED_DECISION_RECEIPT_PROFILE: &str = "urn:marty:delegated-decision-receipt:v1";
pub const DELEGATED_EVALUATION_PROFILE: &str = "urn:marty:delegated-evaluation:v1";
pub const DELEGATED_DECISION_JWS_PURPOSE: &str = "urn:marty:delegated-decision:jws-v1";
pub const DELEGATED_DECISION_JWS_TYP: &str = "mip-delegated-decision+jws";
const MAX_RECEIPT_LIFETIME_SECONDS: i64 = 600;
const MAX_COMPACT_RECEIPT_BYTES: usize = 100_000;

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedGrantReferenceV1 {
    pub id: Uuid,
    pub revision: u64,
    pub terms_digest: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedOperationV1 {
    pub action: String,
    pub resource_id: String,
    pub audience: String,
    pub request_profile: String,
    pub request_digest: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedStatusEvidenceV1 {
    pub issuer: Principal,
    pub grant: DelegatedGrantReferenceV1,
    pub state: &'static str,
    pub checked_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedEvaluationV1 {
    pub profile: &'static str,
    pub organization_id: Uuid,
    pub grant: DelegatedGrantReferenceV1,
    pub actor: Principal,
    pub subject: Principal,
    pub binding: crate::Binding,
    pub operation: DelegatedOperationV1,
    pub approval_evidence_ref: String,
    pub authority_evidence_ref: String,
    pub proof_evidence_ref: String,
    pub challenge: String,
    pub proof_verified_at: DateTime<Utc>,
    pub proof_valid_until: DateTime<Utc>,
    pub status: DelegatedStatusEvidenceV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_evidence: Option<DelegatedDomainEvidenceV1>,
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedDomainEvidenceV1 {
    pub evaluator: Principal,
    pub profile: String,
    pub document_digest: String,
    pub grant: DelegatedGrantReferenceV1,
    pub operation: DelegatedOperationV1,
    pub decision: &'static str,
    pub checked_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedDecisionPolicyV1 {
    pub id: String,
    pub version_digest: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedDecisionReceiptPayloadV1 {
    pub profile: &'static str,
    pub id: Uuid,
    pub issuer: Principal,
    pub decision: &'static str,
    pub evaluation: DelegatedEvaluationV1,
    pub policy: DelegatedDecisionPolicyV1,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct DelegatedReceiptSigningKey {
    pub issuer: Principal,
    pub purpose: String,
    pub key_id: String,
    pub algorithm: String,
}

#[derive(Clone, Debug)]
pub struct DelegatedReceiptSigningRequest {
    pub organization_id: Uuid,
    pub key: DelegatedReceiptSigningKey,
    /// Exact JWS signing input: BASE64URL(protected).BASE64URL(payload).
    pub signing_input: Vec<u8>,
}

/// Resolve a tenant-authorized receipt key once, then sign using that exact
/// key identity. Private key material never leaves the managed signing service.
#[async_trait]
pub trait DelegatedDecisionReceiptSigner: Send + Sync {
    async fn resolve_key(
        &self,
        organization_id: Uuid,
        issuer: &Principal,
        purpose: &'static str,
    ) -> Result<DelegatedReceiptSigningKey, DelegatedReceiptSigningError>;

    async fn sign(
        &self,
        request: DelegatedReceiptSigningRequest,
    ) -> Result<Vec<u8>, DelegatedReceiptSigningError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("delegated receipt signing is unavailable")]
pub struct DelegatedReceiptSigningError;

/// Signed receipt returned only after the configured signer has returned a
/// signature bound to the requested tenant, issuer and protocol purpose.
#[derive(Clone, Debug)]
pub struct IssuedDelegatedDecisionReceipt {
    payload: DelegatedDecisionReceiptPayloadV1,
    compact_jws: String,
}

impl IssuedDelegatedDecisionReceipt {
    pub fn payload(&self) -> &DelegatedDecisionReceiptPayloadV1 {
        &self.payload
    }

    pub fn compact_jws(&self) -> &str {
        &self.compact_jws
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DelegatedDecisionReceiptError {
    #[error("delegated evaluation is no longer valid")]
    Expired,
    #[error("delegated evaluation cannot be represented as a v1 receipt")]
    InvalidEvaluation,
    #[error("delegated receipt signer is unavailable or returned an invalid signature")]
    SigningFailed,
    #[error("delegated receipt exceeds its size limit")]
    TooLarge,
}

#[derive(Clone)]
pub struct DelegatedDecisionReceiptIssuer {
    signer: Arc<dyn DelegatedDecisionReceiptSigner>,
    issuer: Principal,
    maximum_lifetime: Duration,
}

impl DelegatedDecisionReceiptIssuer {
    pub fn new(
        signer: Arc<dyn DelegatedDecisionReceiptSigner>,
        issuer: Principal,
        maximum_lifetime_seconds: i64,
    ) -> Result<Self, DelegatedDecisionReceiptError> {
        if !(1..=MAX_RECEIPT_LIFETIME_SECONDS).contains(&maximum_lifetime_seconds)
            || issuer.id.is_empty()
            || issuer.id.len() > 1024
            || !valid_uri(Some(&issuer.id))
        {
            return Err(DelegatedDecisionReceiptError::InvalidEvaluation);
        }
        Ok(Self {
            signer,
            issuer,
            maximum_lifetime: Duration::seconds(maximum_lifetime_seconds),
        })
    }

    /// Sign one successful, nonserializable evaluation. A receipt's expiry is
    /// capped by every verified evidence deadline retained in the evaluation.
    /// Receipt issuance does not consume a Flow nonce or commit a domain action;
    /// those remain separate final-use and consuming-domain obligations.
    pub async fn issue(
        &self,
        evaluation: &DelegationUseEvaluation,
        now: DateTime<Utc>,
    ) -> Result<IssuedDelegatedDecisionReceipt, DelegatedDecisionReceiptError> {
        if now < evaluation.evaluated_at()
            || now >= evaluation.valid_until()
            || now >= evaluation.receipt_status_valid_until()
            || now >= evaluation.receipt_proof_valid_until()
            || evaluation.receipt_status_checked_at() > evaluation.evaluated_at()
            || evaluation.receipt_proof_verified_at() > evaluation.evaluated_at()
            || evaluation.receipt_proof_challenge().len() < 22
            || evaluation.receipt_proof_challenge().len() > 128
            || !evaluation.receipt_proof_challenge().is_ascii()
        {
            return Err(DelegatedDecisionReceiptError::Expired);
        }
        let expires_at = evaluation
            .valid_until()
            .min(evaluation.receipt_status_valid_until())
            .min(evaluation.receipt_proof_valid_until())
            .min(
                now.checked_add_signed(self.maximum_lifetime)
                    .ok_or(DelegatedDecisionReceiptError::InvalidEvaluation)?,
            );
        if expires_at <= now {
            return Err(DelegatedDecisionReceiptError::Expired);
        }
        let grant = DelegatedGrantReferenceV1 {
            id: evaluation.grant_id(),
            revision: evaluation.grant_revision(),
            terms_digest: evaluation.terms_digest().to_owned(),
        };
        let payload = DelegatedDecisionReceiptPayloadV1 {
            profile: DELEGATED_DECISION_RECEIPT_PROFILE,
            id: Uuid::new_v4(),
            issuer: self.issuer.clone(),
            decision: "PERMIT",
            evaluation: DelegatedEvaluationV1 {
                profile: DELEGATED_EVALUATION_PROFILE,
                organization_id: evaluation.organization_id(),
                grant: grant.clone(),
                actor: evaluation.actor().clone(),
                subject: evaluation.receipt_subject().clone(),
                binding: evaluation.receipt_binding().clone(),
                operation: DelegatedOperationV1 {
                    action: evaluation.action().to_owned(),
                    resource_id: evaluation.resource().to_owned(),
                    audience: evaluation.audience().to_owned(),
                    request_profile: evaluation.operation_profile().to_owned(),
                    request_digest: evaluation.operation_digest().to_owned(),
                },
                approval_evidence_ref: evaluation.receipt_approval_evidence_ref().to_owned(),
                authority_evidence_ref: evaluation.receipt_authority_evidence_ref().to_owned(),
                proof_evidence_ref: evaluation.receipt_proof_evidence_ref().to_owned(),
                challenge: evaluation.receipt_proof_challenge().to_owned(),
                proof_verified_at: evaluation.receipt_proof_verified_at(),
                proof_valid_until: evaluation.receipt_proof_valid_until(),
                status: DelegatedStatusEvidenceV1 {
                    issuer: evaluation.receipt_authority_issuer().clone(),
                    grant: grant.clone(),
                    state: "ACTIVE",
                    checked_at: evaluation.receipt_status_checked_at(),
                    valid_until: evaluation.receipt_status_valid_until(),
                    evidence_ref: evaluation.receipt_status_evidence_ref().to_owned(),
                },
                domain_evidence: evaluation.receipt_domain_evidence().map(|evidence| {
                    DelegatedDomainEvidenceV1 {
                        evaluator: evidence.evaluator.clone(),
                        profile: evidence.profile.clone(),
                        document_digest: evidence.document_digest.clone(),
                        grant: grant.clone(),
                        operation: DelegatedOperationV1 {
                            action: evaluation.action().to_owned(),
                            resource_id: evaluation.resource().to_owned(),
                            audience: evaluation.audience().to_owned(),
                            request_profile: evaluation.operation_profile().to_owned(),
                            request_digest: evaluation.operation_digest().to_owned(),
                        },
                        decision: "PERMIT",
                        checked_at: evidence.checked_at,
                        valid_until: evidence.valid_until,
                        evidence_ref: evidence.evidence_ref.clone(),
                    }
                }),
                evaluated_at: evaluation.evaluated_at(),
            },
            policy: DelegatedDecisionPolicyV1 {
                id: evaluation.policy_id().to_owned(),
                version_digest: evaluation.policy_digest().to_owned(),
            },
            issued_at: now,
            expires_at,
        };
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|_| DelegatedDecisionReceiptError::InvalidEvaluation)?;
        let key = self
            .signer
            .resolve_key(
                evaluation.organization_id(),
                &self.issuer,
                DELEGATED_DECISION_JWS_PURPOSE,
            )
            .await
            .map_err(|_| DelegatedDecisionReceiptError::SigningFailed)?;
        if key.issuer != self.issuer
            || key.purpose != DELEGATED_DECISION_JWS_PURPOSE
            || !valid_key_id(&key.key_id)
            || !matches!(key.algorithm.as_str(), "ES256" | "EdDSA")
        {
            return Err(DelegatedDecisionReceiptError::SigningFailed);
        }
        let header = ProtectedHeader {
            alg: key.algorithm.clone(),
            kid: key.key_id.clone(),
            typ: DELEGATED_DECISION_JWS_TYP,
        };
        let header_bytes = serde_json::to_vec(&header)
            .map_err(|_| DelegatedDecisionReceiptError::SigningFailed)?;
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header_bytes),
            URL_SAFE_NO_PAD.encode(&payload_bytes)
        );
        let signature = self
            .signer
            .sign(DelegatedReceiptSigningRequest {
                organization_id: evaluation.organization_id(),
                key,
                signing_input: signing_input.as_bytes().to_vec(),
            })
            .await
            .map_err(|_| DelegatedDecisionReceiptError::SigningFailed)?;
        if signature.len() != 64 {
            return Err(DelegatedDecisionReceiptError::SigningFailed);
        }
        let compact_jws = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));
        if compact_jws.len() > MAX_COMPACT_RECEIPT_BYTES {
            return Err(DelegatedDecisionReceiptError::TooLarge);
        }
        Ok(IssuedDelegatedDecisionReceipt {
            payload,
            compact_jws,
        })
    }
}

#[derive(Serialize)]
struct ProtectedHeader {
    alg: String,
    kid: String,
    typ: &'static str,
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.is_ascii()
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        authorization::{
            CedarDecision, CedarEvaluation, CedarEvaluationError, CedarEvaluationRequest,
            ConstraintVerificationError, DelegateProofError, DelegateProofVerifier,
            DelegationCedarEvaluator, DelegationUseAuthorizer, ExternalConstraintVerifier,
            VerifiedConstraintEvidence, VerifiedDelegateProof,
        },
        test_support::pending_grant,
        ApprovalEvidence, ConsentEvidenceVerifier, ConsentVerificationError,
        ConsentVerificationRequest, DelegationAuthorityService, DelegationClock,
        InMemoryDelegationGrantRepository, VerifiedConsent,
    };
    use chrono::Duration;
    use std::sync::Mutex;

    struct FixedConsent;
    #[async_trait]
    impl ConsentEvidenceVerifier for FixedConsent {
        async fn verify_approval(
            &self,
            request: ConsentVerificationRequest<'_>,
        ) -> Result<VerifiedConsent, ConsentVerificationError> {
            Ok(VerifiedConsent {
                valid_until: request.grant.terms.valid_until,
            })
        }
    }

    struct Proof;
    #[async_trait]
    impl DelegateProofVerifier for Proof {
        async fn verify(
            &self,
            grant: &crate::DelegationGrant,
            request: &crate::DelegationUseRequest,
            now: DateTime<Utc>,
        ) -> Result<VerifiedDelegateProof, DelegateProofError> {
            Ok(VerifiedDelegateProof {
                evidence_ref: format!("urn:marty:oid4vp-proof:{}", request.challenge_id),
                challenge: request.challenge_id.simple().to_string(),
                verified_at: now,
                valid_until: grant.terms.valid_until,
            })
        }
    }

    struct Constraint;
    #[async_trait]
    impl ExternalConstraintVerifier for Constraint {
        async fn verify(
            &self,
            grant: &crate::DelegationGrant,
            _request: &crate::DelegationUseRequest,
            _now: DateTime<Utc>,
        ) -> Result<VerifiedConstraintEvidence, ConstraintVerificationError> {
            Ok(VerifiedConstraintEvidence {
                valid_until: grant.terms.valid_until,
                checked_at: _now,
                evidence_ref: "urn:example:constraint-evidence:receipt-test".into(),
                context: serde_json::json!({"verified":true}),
                evidence_digest: format!("sha256:{}", "c".repeat(64)),
            })
        }
    }

    struct Policy;
    #[async_trait]
    impl DelegationCedarEvaluator for Policy {
        async fn evaluate(
            &self,
            _request: CedarEvaluationRequest,
            now: DateTime<Utc>,
        ) -> Result<CedarEvaluation, CedarEvaluationError> {
            Ok(CedarEvaluation {
                decision: CedarDecision::Permit,
                policy_id: "urn:example:policy:commerce".into(),
                policy_revision: 3,
                policy_digest: format!("sha256:{}", "d".repeat(64)),
                evaluated_at: now,
                valid_until: now + Duration::seconds(20),
            })
        }
    }

    struct Signer {
        calls: Mutex<Vec<DelegatedReceiptSigningRequest>>,
        key_id: String,
    }
    #[async_trait]
    impl DelegatedDecisionReceiptSigner for Signer {
        async fn resolve_key(
            &self,
            _organization_id: Uuid,
            issuer: &Principal,
            purpose: &'static str,
        ) -> Result<DelegatedReceiptSigningKey, DelegatedReceiptSigningError> {
            Ok(DelegatedReceiptSigningKey {
                issuer: issuer.clone(),
                purpose: purpose.to_owned(),
                key_id: self.key_id.clone(),
                algorithm: "EdDSA".into(),
            })
        }
        async fn sign(
            &self,
            request: DelegatedReceiptSigningRequest,
        ) -> Result<Vec<u8>, DelegatedReceiptSigningError> {
            self.calls.lock().unwrap().push(request);
            Ok(vec![7; 64])
        }
    }

    #[tokio::test]
    async fn receipt_uses_protocol_payload_and_signs_exact_compact_jws_input() {
        let template = pending_grant();
        let now = template.created_at + Duration::seconds(1);
        let clock = Arc::new(TestClock(Mutex::new(now)));
        let lifecycle = Arc::new(
            DelegationAuthorityService::with_clock(
                Arc::new(InMemoryDelegationGrantRepository::default()),
                Arc::new(FixedConsent),
                template.authority.clone(),
                clock.clone(),
            )
            .unwrap(),
        );
        let pending = lifecycle
            .propose(template.organization_id, template.terms)
            .await
            .unwrap();
        clock.set(now + Duration::seconds(1));
        let active = lifecycle
            .approve(
                pending.organization_id,
                pending.id,
                pending.revision,
                &pending.terms.grantor,
                ApprovalEvidence {
                    profile: "urn:example:approval:v1".into(),
                    evidence_ref: "urn:example:consent:1".into(),
                    authority_evidence_ref: "urn:example:authority:1".into(),
                },
            )
            .await
            .unwrap();
        let proof = Arc::new(Proof);
        let evaluator = DelegationUseAuthorizer::with_clock(
            lifecycle,
            proof,
            Arc::new(Constraint),
            Arc::new(Policy),
            Arc::new(TestClock(Mutex::new(now + Duration::seconds(1)))),
        );
        let request = crate::DelegationUseRequest {
            organization_id: active.organization_id,
            grant_id: active.id,
            expected_revision: active.revision,
            challenge_id: Uuid::new_v4(),
            actor: active.terms.delegate.clone(),
            action: active.terms.actions[0].clone(),
            audience: active.terms.audiences[0].clone(),
            resource: active.terms.resources[0].clone(),
            operation_profile: active.terms.constraints.profile.clone().unwrap(),
            operation_digest: format!("sha256:{}", "c".repeat(64)),
            proof: vec![1, 2, 3],
        };
        let evaluation = evaluator.evaluate(&request).await.unwrap();
        let issuer = Principal {
            principal_type: crate::PrincipalType::Organization,
            id: "https://issuer.example".into(),
        };
        let signer = Arc::new(Signer {
            calls: Mutex::new(Vec::new()),
            key_id: "https://issuer.example/keys/delegated-receipt-1".into(),
        });
        let receipt_issuer =
            DelegatedDecisionReceiptIssuer::new(signer.clone(), issuer.clone(), 30).unwrap();
        let issued_at = evaluation.evaluated_at();
        let receipt = receipt_issuer.issue(&evaluation, issued_at).await.unwrap();
        assert_eq!(
            receipt.payload().profile,
            DELEGATED_DECISION_RECEIPT_PROFILE
        );
        assert_eq!(receipt.payload().decision, "PERMIT");
        assert_eq!(receipt.payload().issuer.id, issuer.id);
        assert_eq!(receipt.payload().evaluation.grant.id, active.id);
        assert_eq!(
            receipt.payload().evaluation.operation.request_digest,
            request.operation_digest
        );
        assert_eq!(receipt.payload().evaluation.status.state, "ACTIVE");
        let domain_evidence = receipt
            .payload()
            .evaluation
            .domain_evidence
            .as_ref()
            .unwrap();
        assert_eq!(
            domain_evidence.profile,
            active.terms.constraints.profile.clone().unwrap()
        );
        assert_eq!(
            domain_evidence.document_digest,
            active.terms.constraints.document_digest.clone().unwrap()
        );
        assert_eq!(
            domain_evidence.evaluator,
            active.terms.constraints.evaluator.clone().unwrap()
        );
        assert_eq!(
            domain_evidence.operation.request_digest,
            request.operation_digest
        );
        assert_eq!(domain_evidence.decision, "PERMIT");
        assert!(receipt.payload().expires_at <= domain_evidence.valid_until);
        assert!(receipt.payload().expires_at <= evaluation.valid_until());
        let parts: Vec<_> = receipt.compact_jws().split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(URL_SAFE_NO_PAD.decode(parts[2]).unwrap(), vec![7; 64]);
        let calls = signer.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].key.key_id,
            "https://issuer.example/keys/delegated-receipt-1"
        );
        assert_eq!(calls[0].key.purpose, DELEGATED_DECISION_JWS_PURPOSE);
        assert!(String::from_utf8(calls[0].signing_input.clone())
            .unwrap()
            .contains('.'));
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["typ"], DELEGATED_DECISION_JWS_TYP);
        assert_eq!(header["alg"], "EdDSA");
        let payload: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            payload["evaluation"]["challenge"],
            request.challenge_id.simple().to_string()
        );
        assert_eq!(
            payload["evaluation"]["subject"]["id"],
            active.terms.subject.id
        );
    }

    struct TestClock(Mutex<DateTime<Utc>>);
    impl TestClock {
        fn set(&self, now: DateTime<Utc>) {
            *self.0.lock().unwrap() = now;
        }
    }
    impl DelegationClock for TestClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }
}
