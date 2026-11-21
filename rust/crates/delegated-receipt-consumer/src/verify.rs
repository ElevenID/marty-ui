use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    model::{valid_binding, valid_grant, valid_operation, valid_principal},
    strict, Binding, Decision, DomainEvidenceClaims, EvidenceReferences, EvidenceTimes,
    FreshnessPolicy, GrantReference, Operation, PinnedReceiptKey, Policy, Principal,
    ReceiptContext, ReceiptExpectation, ReceiptVerificationError as Error, Result, StatusState,
    EVALUATION_PROFILE, MAX_COMPACT_RECEIPT_BYTES, RECEIPT_JWS_TYPE, RECEIPT_PROFILE,
    RECEIPT_REFERENCE_PREFIX,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    kid: String,
    typ: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    profile: String,
    #[serde(deserialize_with = "strict::deserialize_uuid")]
    id: Uuid,
    issuer: Principal,
    decision: Decision,
    evaluation: Evaluation,
    policy: Policy,
    #[serde(deserialize_with = "strict::deserialize_time")]
    issued_at: DateTime<Utc>,
    #[serde(deserialize_with = "strict::deserialize_time")]
    expires_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Evaluation {
    profile: String,
    #[serde(deserialize_with = "strict::deserialize_uuid")]
    organization_id: Uuid,
    grant: GrantReference,
    actor: Principal,
    subject: Principal,
    binding: Binding,
    operation: Operation,
    approval_evidence_ref: String,
    authority_evidence_ref: String,
    proof_evidence_ref: String,
    challenge: String,
    #[serde(deserialize_with = "strict::deserialize_time")]
    proof_verified_at: DateTime<Utc>,
    #[serde(deserialize_with = "strict::deserialize_time")]
    proof_valid_until: DateTime<Utc>,
    status: Status,
    domain_evidence: Option<Domain>,
    #[serde(deserialize_with = "strict::deserialize_time")]
    evaluated_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Status {
    issuer: Principal,
    grant: GrantReference,
    state: StatusState,
    #[serde(deserialize_with = "strict::deserialize_time")]
    checked_at: DateTime<Utc>,
    #[serde(deserialize_with = "strict::deserialize_time")]
    valid_until: DateTime<Utc>,
    evidence_ref: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Domain {
    evaluator: Principal,
    profile: String,
    document_digest: String,
    grant: GrantReference,
    operation: Operation,
    decision: Decision,
    #[serde(deserialize_with = "strict::deserialize_time")]
    checked_at: DateTime<Utc>,
    #[serde(deserialize_with = "strict::deserialize_time")]
    valid_until: DateTime<Utc>,
    evidence_ref: String,
}

#[derive(Clone)]
struct Evidence {
    receipt_id: Uuid,
    receipt_ref: String,
    receipt_digest: String,
    decision: Decision,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    evaluated_at: DateTime<Utc>,
    recorded_at: DateTime<Utc>,
    verified_at: DateTime<Utc>,
    context: ReceiptContext,
    references: EvidenceReferences,
    evidence_times: EvidenceTimes,
    policy: Policy,
    domain_evidence: Option<DomainEvidenceClaims>,
}

/// Signature and exact context verified within the supplied freshness window.
/// This remains EVIDENCE_ONLY; it neither consumes replay state nor authorizes
/// a business side effect. Its original expiry never changes.
///
/// ```compile_fail
/// use marty_delegated_receipt_consumer::FreshReceiptEvidence;
/// let forged: FreshReceiptEvidence = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone)]
pub struct FreshReceiptEvidence(Evidence, DateTime<Utc>);

impl FreshReceiptEvidence {
    /// Exclusive bound from original receipt expiry and the caller's evidence
    /// age policy. Computing it never refreshes an issuer assertion.
    pub fn fresh_until(&self) -> DateTime<Utc> {
        self.1
    }
}

/// An authenticated original decision, including a DENY or expired receipt.
/// This type intentionally provides no conversion to FreshReceiptEvidence.
///
/// ```compile_fail
/// use marty_delegated_receipt_consumer::HistoricalReceiptEvidence;
/// let forged: HistoricalReceiptEvidence = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone)]
pub struct HistoricalReceiptEvidence(Evidence);

macro_rules! evidence_accessors {
    ($name:ident) => {
        impl $name {
            pub fn receipt_id(&self) -> Uuid {
                self.0.receipt_id
            }
            pub fn receipt_ref(&self) -> &str {
                &self.0.receipt_ref
            }
            pub fn receipt_digest(&self) -> &str {
                &self.0.receipt_digest
            }
            pub fn decision(&self) -> Decision {
                self.0.decision
            }
            pub fn issued_at(&self) -> DateTime<Utc> {
                self.0.issued_at
            }
            pub fn expires_at(&self) -> DateTime<Utc> {
                self.0.expires_at
            }
            pub fn evaluated_at(&self) -> DateTime<Utc> {
                self.0.evaluated_at
            }
            pub fn recorded_at(&self) -> DateTime<Utc> {
                self.0.recorded_at
            }
            pub fn verified_at(&self) -> DateTime<Utc> {
                self.0.verified_at
            }
            pub fn context(&self) -> &ReceiptContext {
                &self.0.context
            }
            pub fn evidence_references(&self) -> &EvidenceReferences {
                &self.0.references
            }
            pub fn evidence_times(&self) -> &EvidenceTimes {
                &self.0.evidence_times
            }
            pub fn policy(&self) -> &Policy {
                &self.0.policy
            }
            pub fn domain_evidence(&self) -> Option<&DomainEvidenceClaims> {
                self.0.domain_evidence.as_ref()
            }
            pub fn semantics(&self) -> &'static str {
                "EVIDENCE_ONLY"
            }
        }
        impl std::fmt::Debug for $name {
            fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.debug_struct(stringify!($name))
                    .field("decision", &self.0.decision)
                    .field("issued_at", &self.0.issued_at)
                    .field("expires_at", &self.0.expires_at)
                    .finish_non_exhaustive()
            }
        }
    };
}
evidence_accessors!(FreshReceiptEvidence);
evidence_accessors!(HistoricalReceiptEvidence);

/// Verify a PERMIT receipt as fresh identity/authority evidence at an explicit
/// instant. A signed DENY is rejected after authenticity and correspondence
/// checks; inspect it through verify_historical when historical evidence is needed.
pub fn verify_fresh(
    compact: &[u8],
    key: &PinnedReceiptKey,
    expected: &ReceiptExpectation,
    now: DateTime<Utc>,
    freshness: FreshnessPolicy,
) -> Result<FreshReceiptEvidence> {
    let payload = verify(compact, key, expected, now)?;
    if now >= payload.expires_at {
        return Err(Error::Expired);
    }
    let evaluation = &payload.evaluation;
    if payload.expires_at.signed_duration_since(payload.issued_at) > freshness.maximum_lifetime {
        return Err(Error::Stale);
    }
    let mut fresh_until = payload.expires_at;
    for at in [
        payload.issued_at,
        evaluation.evaluated_at,
        evaluation.proof_verified_at,
        evaluation.status.checked_at,
    ]
    .into_iter()
    .chain(
        evaluation
            .domain_evidence
            .as_ref()
            .map(|domain| domain.checked_at),
    ) {
        let deadline = at
            .checked_add_signed(freshness.maximum_evidence_age)
            .ok_or(Error::InvalidTimeline)?;
        fresh_until = fresh_until.min(deadline);
    }
    if now >= fresh_until {
        return Err(Error::Stale);
    }
    if payload.decision != Decision::Permit {
        return Err(Error::DecisionDenied);
    }
    Ok(FreshReceiptEvidence(
        evidence(payload, expected, now),
        fresh_until,
    ))
}

/// Verify the original signature, context and retained digest without renewing
/// the original time window. Expired receipts and signed denials remain history.
/// The caller must independently authenticate access to any recovered result.
pub fn verify_historical(
    compact: &[u8],
    key: &PinnedReceiptKey,
    expected: &ReceiptExpectation,
    observed_at: DateTime<Utc>,
) -> Result<HistoricalReceiptEvidence> {
    Ok(HistoricalReceiptEvidence(evidence(
        verify(compact, key, expected, observed_at)?,
        expected,
        observed_at,
    )))
}

fn verify(
    compact: &[u8],
    key: &PinnedReceiptKey,
    expected: &ReceiptExpectation,
    observed_at: DateTime<Utc>,
) -> Result<Payload> {
    if compact.len() > MAX_COMPACT_RECEIPT_BYTES {
        return Err(Error::TooLarge);
    }
    if compact.is_empty() || !compact.is_ascii() {
        return Err(Error::InvalidWire);
    }
    if !strict::instant(observed_at) {
        return Err(Error::InvalidExpectation);
    }
    let text = std::str::from_utf8(compact).map_err(|_| Error::InvalidWire)?;
    let mut pieces = text.split('.');
    let protected = pieces.next().ok_or(Error::InvalidWire)?;
    let encoded_payload = pieces.next().ok_or(Error::InvalidWire)?;
    let encoded_signature = pieces.next().ok_or(Error::InvalidWire)?;
    if pieces.next().is_some() {
        return Err(Error::InvalidWire);
    }
    let header: Header =
        serde_json::from_value(strict::read(&strict::segment(protected, 1024)?, 1024)?)
            .map_err(|_| Error::InvalidWire)?;
    if header.typ != RECEIPT_JWS_TYPE {
        return Err(Error::InvalidWire);
    }
    if header.alg != key.algorithm.as_str() || header.kid != key.key_id {
        return Err(Error::KeyMismatch);
    }
    let signature = strict::segment(encoded_signature, 64)?;
    let signing_input_end = protected.len() + 1 + encoded_payload.len();
    let payload_bytes = strict::segment(encoded_payload, 75_000)?;
    key.verify(&compact[..signing_input_end], &signature)?;
    let payload: Payload = serde_json::from_value(strict::read(&payload_bytes, 75_000)?)
        .map_err(|_| Error::InvalidWire)?;
    validate(&payload)?;
    if payload.issuer != key.issuer || payload.evaluation.organization_id != key.organization_id {
        return Err(Error::KeyMismatch);
    }
    match_context(&payload, expected)?;
    let retention = &expected.retention;
    if retention.receipt_ref != format!("{RECEIPT_REFERENCE_PREFIX}{}", payload.id)
        || retention.receipt_digest != format!("sha256:{:x}", Sha256::digest(compact))
        || retention.decision != payload.decision
        || retention.authorization_expires_at != payload.expires_at
        || retention.recorded_at < payload.issued_at
        || retention.recorded_at >= payload.expires_at
    {
        return Err(Error::RetentionMismatch);
    }
    if observed_at < payload.issued_at || observed_at < retention.recorded_at {
        return Err(Error::NotYetIssued);
    }
    Ok(payload)
}

fn validate(payload: &Payload) -> Result<()> {
    let e = &payload.evaluation;
    if payload.profile != RECEIPT_PROFILE
        || e.profile != EVALUATION_PROFILE
        || !valid_principal(&payload.issuer)
        || !valid_principal(&e.actor)
        || !valid_principal(&e.subject)
        || !valid_grant(&e.grant)
        || !valid_binding(&e.binding)
        || !valid_operation(&e.operation)
        || !strict::challenge(&e.challenge)
        || [
            &e.approval_evidence_ref,
            &e.authority_evidence_ref,
            &e.proof_evidence_ref,
            &e.status.evidence_ref,
            &payload.policy.id,
        ]
        .into_iter()
        .any(|value| !strict::uri(value))
        || !strict::digest(&payload.policy.version_digest)
        || !valid_principal(&e.status.issuer)
        || !valid_grant(&e.status.grant)
        || e.status.grant != e.grant
        || e.status.state != StatusState::Active
    {
        return Err(Error::InvalidWire);
    }
    if e.proof_verified_at > e.evaluated_at
        || e.status.checked_at > e.evaluated_at
        || e.evaluated_at > payload.issued_at
        || payload.expires_at <= payload.issued_at
        || payload.expires_at > e.proof_valid_until
        || payload.expires_at > e.status.valid_until
        || payload.expires_at.signed_duration_since(payload.issued_at) > Duration::seconds(600)
    {
        return Err(Error::InvalidTimeline);
    }
    if let Some(domain) = &e.domain_evidence {
        if !valid_principal(&domain.evaluator)
            || !strict::uri(&domain.profile)
            || !strict::digest(&domain.document_digest)
            || !strict::uri(&domain.evidence_ref)
            || domain.grant != e.grant
            || domain.operation != e.operation
            || domain.decision != Decision::Permit
        {
            return Err(Error::InvalidWire);
        }
        if domain.checked_at > e.evaluated_at || payload.expires_at > domain.valid_until {
            return Err(Error::InvalidTimeline);
        }
    }
    Ok(())
}

fn match_context(payload: &Payload, expected: &ReceiptExpectation) -> Result<()> {
    let e = &payload.evaluation;
    let c = &expected.context;
    if e.organization_id != c.organization_id
        || e.grant != c.grant
        || e.actor != c.actor
        || e.subject != c.subject
        || e.binding != c.binding
        || e.operation != c.operation
        || e.challenge != c.challenge
        || e.status.issuer != c.status_issuer
        || e.status.state != c.status_state
        || payload.policy.id != c.policy.id
        || c.policy
            .version_digest
            .as_deref()
            .is_some_and(|pin| pin != payload.policy.version_digest)
        || e.proof_verified_at < c.context_created_at
        || e.evaluated_at < c.context_created_at
        || payload.expires_at > c.context_expires_at
    {
        return Err(Error::ContextMismatch);
    }
    for (pin, actual) in [
        (&expected.pins.approval, &e.approval_evidence_ref),
        (&expected.pins.authority, &e.authority_evidence_ref),
        (&expected.pins.proof, &e.proof_evidence_ref),
        (&expected.pins.status, &e.status.evidence_ref),
    ] {
        if pin.as_ref().is_some_and(|pin| pin != actual) {
            return Err(Error::ContextMismatch);
        }
    }
    match (&c.domain_evidence, &e.domain_evidence) {
        (None, None) => {}
        (Some(expected), Some(actual))
            if expected.evaluator == actual.evaluator
                && expected.profile == actual.profile
                && expected.document_digest == actual.document_digest
                && expected
                    .evidence_ref
                    .as_ref()
                    .is_none_or(|pin| pin == &actual.evidence_ref) => {}
        _ => return Err(Error::ContextMismatch),
    }
    Ok(())
}

fn evidence(
    payload: Payload,
    expected: &ReceiptExpectation,
    verified_at: DateTime<Utc>,
) -> Evidence {
    let e = payload.evaluation;
    Evidence {
        receipt_id: payload.id,
        receipt_ref: expected.retention.receipt_ref.clone(),
        receipt_digest: expected.retention.receipt_digest.clone(),
        decision: payload.decision,
        issued_at: payload.issued_at,
        expires_at: payload.expires_at,
        evaluated_at: e.evaluated_at,
        recorded_at: expected.retention.recorded_at,
        verified_at,
        context: expected.context.clone(),
        references: EvidenceReferences {
            approval: e.approval_evidence_ref,
            authority: e.authority_evidence_ref,
            proof: e.proof_evidence_ref,
            status: e.status.evidence_ref,
        },
        evidence_times: EvidenceTimes {
            proof_verified_at: e.proof_verified_at,
            proof_valid_until: e.proof_valid_until,
            status_checked_at: e.status.checked_at,
            status_valid_until: e.status.valid_until,
        },
        policy: payload.policy,
        domain_evidence: e.domain_evidence.map(|d| DomainEvidenceClaims {
            evaluator: d.evaluator,
            profile: d.profile,
            document_digest: d.document_digest,
            decision: d.decision,
            checked_at: d.checked_at,
            valid_until: d.valid_until,
            evidence_ref: d.evidence_ref,
        }),
    }
}
