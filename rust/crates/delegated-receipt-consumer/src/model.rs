use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{strict, ReceiptVerificationError as Error, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    Es256,
    EdDsa,
}
impl Algorithm {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::EdDsa => "EdDSA",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrincipalType {
    User,
    Organization,
    ServiceAccount,
    MachineIdentity,
    External,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    #[serde(rename = "type")]
    pub principal_type: PrincipalType,
    pub id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Permit,
    Deny,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StatusState {
    Pending,
    Active,
    Suspended,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GrantReference {
    #[serde(deserialize_with = "strict::deserialize_uuid")]
    pub id: Uuid,
    pub revision: u64,
    pub terms_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub action: String,
    pub resource_id: String,
    pub audience: String,
    pub request_profile: String,
    pub request_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "method",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum Binding {
    Key {
        key_thumbprint: String,
    },
    Session {
        session_ref: String,
        establishment_evidence_ref: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub id: String,
    pub version_digest: String,
}

/// The selected policy ID is independent of the receipt. A version pin is
/// optional because a qualified current policy owner may select the revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyExpectation {
    pub id: String,
    pub version_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainEvidenceContext {
    pub evaluator: Principal,
    pub profile: String,
    pub document_digest: String,
    /// Only set when this reference was obtained independently.
    pub evidence_ref: Option<String>,
}

/// Independently known immutable operation and challenge context. This type
/// deliberately has no parser that derives expectations from a receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptContext {
    pub organization_id: Uuid,
    pub grant: GrantReference,
    pub actor: Principal,
    pub subject: Principal,
    pub binding: Binding,
    pub operation: Operation,
    pub challenge: String,
    pub status_issuer: Principal,
    pub status_state: StatusState,
    pub policy: PolicyExpectation,
    pub domain_evidence: Option<DomainEvidenceContext>,
    pub context_created_at: DateTime<Utc>,
    pub context_expires_at: DateTime<Utc>,
}

/// Metadata obtained from an independently authenticated FINAL_USE result.
/// Parsing an unauthenticated response does not establish this provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedReceiptBinding {
    pub receipt_ref: String,
    pub receipt_digest: String,
    pub decision: Decision,
    pub recorded_at: DateTime<Utc>,
    pub authorization_expires_at: DateTime<Utc>,
}

/// Optional exact pins for references known outside the submitted receipt.
/// Unpinned references remain signed issuer assertions, never independent
/// proof that the referenced material was fetched or currently authenticated.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EvidenceReferencePins {
    pub approval: Option<String>,
    pub authority: Option<String>,
    pub proof: Option<String>,
    pub status: Option<String>,
}

#[derive(Clone)]
pub struct ReceiptExpectation {
    pub(crate) context: ReceiptContext,
    pub(crate) retention: RetainedReceiptBinding,
    pub(crate) pins: EvidenceReferencePins,
}
impl std::fmt::Debug for ReceiptExpectation {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("ReceiptExpectation { <independent context> }")
    }
}
impl ReceiptExpectation {
    pub fn new(context: ReceiptContext, retention: RetainedReceiptBinding) -> Result<Self> {
        let reference_id = retention
            .receipt_ref
            .strip_prefix(crate::RECEIPT_REFERENCE_PREFIX)
            .and_then(strict::canonical_uuid);
        if context.organization_id.is_nil()
            || !valid_grant(&context.grant)
            || !valid_principal(&context.actor)
            || !valid_principal(&context.subject)
            || !valid_principal(&context.status_issuer)
            || context.status_state != StatusState::Active
            || !valid_binding(&context.binding)
            || !valid_operation(&context.operation)
            || !strict::challenge(&context.challenge)
            || !strict::uri(&context.policy.id)
            || context
                .policy
                .version_digest
                .as_deref()
                .is_some_and(|v| !strict::digest(v))
            || context.domain_evidence.as_ref().is_some_and(|domain| {
                !valid_principal(&domain.evaluator)
                    || !strict::uri(&domain.profile)
                    || !strict::digest(&domain.document_digest)
                    || domain
                        .evidence_ref
                        .as_deref()
                        .is_some_and(|v| !strict::uri(v))
            })
            || !strict::instant(context.context_created_at)
            || !strict::instant(context.context_expires_at)
            || context.context_created_at >= context.context_expires_at
            || reference_id.is_none()
            || !strict::digest(&retention.receipt_digest)
            || !strict::instant(retention.recorded_at)
            || !strict::instant(retention.authorization_expires_at)
            || retention.recorded_at < context.context_created_at
            || retention.recorded_at >= retention.authorization_expires_at
            || retention.authorization_expires_at > context.context_expires_at
        {
            return Err(Error::InvalidExpectation);
        }
        Ok(Self {
            context,
            retention,
            pins: EvidenceReferencePins::default(),
        })
    }

    pub fn with_evidence_reference_pins(mut self, pins: EvidenceReferencePins) -> Result<Self> {
        if [&pins.approval, &pins.authority, &pins.proof, &pins.status]
            .into_iter()
            .flatten()
            .any(|value| !strict::uri(value))
        {
            return Err(Error::InvalidExpectation);
        }
        self.pins = pins;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FreshnessPolicy {
    pub(crate) maximum_lifetime: Duration,
    pub(crate) maximum_evidence_age: Duration,
}
impl FreshnessPolicy {
    pub fn new(maximum_lifetime_seconds: u16, maximum_evidence_age_seconds: u16) -> Result<Self> {
        if !(1..=600).contains(&maximum_lifetime_seconds)
            || !(1..=600).contains(&maximum_evidence_age_seconds)
        {
            return Err(Error::InvalidExpectation);
        }
        Ok(Self {
            maximum_lifetime: Duration::seconds(i64::from(maximum_lifetime_seconds)),
            maximum_evidence_age: Duration::seconds(i64::from(maximum_evidence_age_seconds)),
        })
    }
}

/// Signed opaque references. Their contents and present availability were not
/// independently resolved by this offline verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceReferences {
    pub approval: String,
    pub authority: String,
    pub proof: String,
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceTimes {
    pub proof_verified_at: DateTime<Utc>,
    pub proof_valid_until: DateTime<Utc>,
    pub status_checked_at: DateTime<Utc>,
    pub status_valid_until: DateTime<Utc>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainEvidenceClaims {
    pub evaluator: Principal,
    pub profile: String,
    pub document_digest: String,
    pub decision: Decision,
    pub checked_at: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub evidence_ref: String,
}

pub(crate) fn valid_principal(value: &Principal) -> bool {
    strict::uri(&value.id)
}
pub(crate) fn valid_grant(value: &GrantReference) -> bool {
    !value.id.is_nil()
        && (1..=9_007_199_254_740_991).contains(&value.revision)
        && strict::digest(&value.terms_digest)
}
pub(crate) fn valid_operation(value: &Operation) -> bool {
    [
        &value.action,
        &value.resource_id,
        &value.audience,
        &value.request_profile,
    ]
    .into_iter()
    .all(|value| strict::uri(value))
        && strict::digest(&value.request_digest)
}
pub(crate) fn valid_binding(value: &Binding) -> bool {
    match value {
        Binding::Key { key_thumbprint } => strict::digest(key_thumbprint),
        Binding::Session {
            session_ref,
            establishment_evidence_ref,
        } => strict::uri(session_ref) && strict::uri(establishment_evidence_ref),
    }
}
