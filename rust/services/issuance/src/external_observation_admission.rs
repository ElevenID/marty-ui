// SPDX-License-Identifier: AGPL-3.0-only
//! Provider-neutral admission planning; NOT an HTTP endpoint or a trust verifier.
//!
//! The adapter must authenticate through Common Gateway, load current authority
//! from core-owned storage and commit the plan under its complete authority fence.
//! A registered producer attests to an observation; that is not a VERIFIED fact,
//! an approval, a signing grant, or a credential. No provider I/O occurs here.

use std::collections::{BTreeMap, BTreeSet};

pub const SUBMIT_SCOPE: &str = "evidence:submit";
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_AGE_MS: u64 = 900_000;
const MAX_SKEW_MS: u64 = 30_000;

#[derive(Clone, PartialEq)]
pub enum Scalar {
    Null,
    Boolean(bool),
    Number(f64),
    Text(String),
}

/// Decoded from a strictly validated wire envelope. No tenant, provider,
/// subject, scope, verification, policy or issuer fields are caller-selectable.
#[derive(Clone, PartialEq)]
pub struct Observation {
    pub binding_id: String,
    pub binding_revision: u64,
    pub observation_id: String,
    pub sequence: u64,
    pub observed_at_ms: u64,
    pub effective_at_ms: u64,
    pub claims: BTreeMap<String, Scalar>,
}

/// Construct only from successful Gateway API-key authentication, never JSON
/// body fields, forwarded untrusted headers, or caller-supplied scope claims.
pub struct AuthenticatedApiKey {
    pub id: String,
    pub organization_id: String,
    pub revision: u64,
    pub active: bool,
    pub expires_at_ms: u64,
    pub scopes: BTreeSet<String>,
}

/// Core-owned administrator-approved delegation. Key rotation requires an
/// explicit new delegation; an organization match alone is insufficient.
pub struct ProducerGrant {
    pub organization_id: String,
    pub source_id: String,
    pub api_key_id: String,
    pub revision: u64,
    pub active: bool,
    pub expires_at_ms: u64,
    pub bindings: BTreeSet<String>,
}

#[derive(Clone, Copy)]
pub enum ClaimKind {
    Boolean,
    Number { minimum: f64, maximum: f64 },
    Text { max_bytes: usize },
}

#[derive(Clone, Copy)]
pub struct ClaimRule {
    pub kind: ClaimKind,
    pub required: bool,
    pub nullable: bool,
}

/// This immutable binding is loaded from core storage. Changes to source,
/// resource scope, subject, claim rules or freshness must bump its revision.
pub struct EvidenceBinding {
    pub id: String,
    pub revision: u64,
    pub active: bool,
    pub organization_id: String,
    pub source_id: String,
    pub provider: String,
    pub application_id: String,
    pub subject_id: String,
    pub fact_type: String,
    pub resource_scope: BTreeMap<String, String>,
    pub claims: BTreeMap<String, ClaimRule>,
    pub max_age_ms: u64,
    pub max_clock_skew_ms: u64,
}

pub struct ApplicationSnapshot {
    pub id: String,
    pub organization_id: String,
    pub subject_id: String,
    pub revision: u64,
    /// Canonical application expiry, checked against the journal transaction's database clock.
    pub expires_at_ms: u64,
    /// Set by the lifecycle owner. Issued/rejected/withdrawn applications are
    /// not eligible until a separate correction workflow is explicitly wired.
    pub accepts_observations: bool,
}

/// Core receipt, never a client-supplied replay hint. Keep the full normalized
/// envelope for equality, or use a separately reviewed canonical digest adapter.
pub struct StoredReceipt {
    pub id: String,
    pub organization_id: String,
    pub source_id: String,
    pub api_key_id: String,
    pub observation: Observation,
}

pub enum ReplaySnapshot<'a> {
    Missing { current_sequence: u64 },
    Existing(&'a StoredReceipt),
}

/// Every field must be rechecked in the SAME transaction as receipt/event/head
/// insertion. A mismatch is a retryable conflict, never permission to proceed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityFence {
    pub api_key_revision: u64,
    pub grant_revision: u64,
    pub binding_revision: u64,
    pub application_revision: u64,
    pub previous_sequence: u64,
    /// Recheck active/expiry at commit as well as revisions: expiry needs no write.
    pub authorization_expires_at_ms: u64,
    pub observation_expires_at_ms: u64,
}

/// An unsigned insertion plan. Does not create a canonical EvidenceFact or
/// evaluate Cedar. Those remain separate core policy decisions after admission.
pub struct InsertPlan {
    pub organization_id: String,
    pub source_id: String,
    pub api_key_id: String,
    pub provider: String,
    pub application_id: String,
    pub subject_id: String,
    pub fact_type: String,
    pub resource_scope: BTreeMap<String, String>,
    pub received_at_ms: u64,
    pub observation: Observation,
    pub fence: AuthorityFence,
}

pub enum Admission {
    Insert(Box<InsertPlan>),
    Replay { receipt_id: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Denial {
    InvalidRequest,
    InvalidAuthority,
    AuthenticationRequired,
    ScopeMissing,
    NotAuthorized,
    BindingChanged,
    ApplicationClosed,
    InvalidClaims,
    StaleObservation,
    FutureObservation,
    ReplayConflict,
    OutOfOrder,
}

pub(crate) fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}

pub(crate) fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
}

pub(crate) fn text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn positive(value: u64) -> bool {
    (1..=MAX_SAFE_INTEGER).contains(&value)
}

fn claim_name(value: &str) -> bool {
    label(value)
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "verified"
                | "verification"
                | "policy_allowed"
                | "approved"
                | "organization_id"
                | "subject_id"
                | "application_id"
                | "provider"
                | "fact_type"
                | "scope"
                | "issuer_key"
                | "signing_key"
                | "private_key"
                | "token"
                | "access_token"
                | "refresh_token"
                | "client_secret"
                | "password"
        )
}

pub(crate) fn valid_rules(rules: &BTreeMap<String, ClaimRule>) -> bool {
    !rules.is_empty()
        && rules.len() <= 32
        && rules.iter().all(|(name, rule)| {
            claim_name(name)
                && match rule.kind {
                    ClaimKind::Boolean => true,
                    ClaimKind::Number { minimum, maximum } => {
                        minimum.is_finite() && maximum.is_finite() && minimum <= maximum
                    }
                    ClaimKind::Text { max_bytes } => (1..=512).contains(&max_bytes),
                }
        })
}

fn valid_claims(input: &Observation, binding: &EvidenceBinding) -> bool {
    if input.claims.is_empty() || input.claims.len() > 32 {
        return false;
    }
    if binding
        .claims
        .iter()
        .any(|(name, rule)| rule.required && !input.claims.contains_key(name))
    {
        return false;
    }
    input.claims.iter().all(|(name, value)| {
        let Some(rule) = binding.claims.get(name) else {
            return false;
        };
        match (value, &rule.kind) {
            (Scalar::Null, _) => rule.nullable,
            (Scalar::Boolean(_), ClaimKind::Boolean) => true,
            (Scalar::Number(value), ClaimKind::Number { minimum, maximum }) => {
                value.is_finite() && value >= minimum && value <= maximum
            }
            (Scalar::Text(value), ClaimKind::Text { max_bytes }) => text(value, *max_bytes),
            _ => false,
        }
    })
}

/// Plan one submission. The persistence adapter owns serializable snapshot
/// reads, replay lookup and atomic compare-and-insert; this function does no I/O.
/// `idempotency_key` must equal observation_id, so two names cannot describe one
/// logical attempt. Stable retries do not refresh observed_at or advance heads.
#[allow(clippy::too_many_arguments)]
pub fn plan_admission(
    principal: &AuthenticatedApiKey,
    grant: &ProducerGrant,
    binding: &EvidenceBinding,
    application: &ApplicationSnapshot,
    input: &Observation,
    idempotency_key: &str,
    replay: ReplaySnapshot<'_>,
    now_ms: u64,
) -> Result<Admission, Denial> {
    if !positive(now_ms)
        || !id(&input.binding_id)
        || !id(&input.observation_id)
        || idempotency_key != input.observation_id
        || !positive(input.binding_revision)
        || !positive(input.sequence)
        || !positive(input.observed_at_ms)
        || !positive(input.effective_at_ms)
        || input.effective_at_ms > input.observed_at_ms
    {
        return Err(Denial::InvalidRequest);
    }
    if !principal.active || principal.expires_at_ms <= now_ms {
        return Err(Denial::AuthenticationRequired);
    }
    // Do not silently equate integration write, approval or wildcard grants with
    // this proposed purpose-specific permission. Provisioning is a later gate.
    if !principal.scopes.contains(SUBMIT_SCOPE) {
        return Err(Denial::ScopeMissing);
    }
    if !grant.active
        || grant.expires_at_ms <= now_ms
        || !binding.active
        || principal.organization_id != grant.organization_id
        || principal.id != grant.api_key_id
        || binding.organization_id != grant.organization_id
        || binding.source_id != grant.source_id
        || !grant.bindings.contains(&binding.id)
        || input.binding_id != binding.id
        || application.id != binding.application_id
        || application.organization_id != binding.organization_id
        || application.subject_id != binding.subject_id
    {
        return Err(Denial::NotAuthorized);
    }
    if input.binding_revision != binding.revision {
        return Err(Denial::BindingChanged);
    }
    if !id(&principal.id)
        || !id(&principal.organization_id)
        || !id(&grant.source_id)
        || !id(&binding.id)
        || !id(&binding.application_id)
        || !text(&binding.subject_id, 1024)
        || !label(&binding.provider)
        || !label(&binding.fact_type)
        || !positive(principal.revision)
        || !positive(grant.revision)
        || !positive(binding.revision)
        || !positive(application.revision)
        || !positive(application.expires_at_ms)
        || !positive(principal.expires_at_ms)
        || !positive(grant.expires_at_ms)
        || !(1..=MAX_AGE_MS).contains(&binding.max_age_ms)
        || binding.max_clock_skew_ms > MAX_SKEW_MS
        || !valid_rules(&binding.claims)
        || binding.resource_scope.is_empty()
        || binding.resource_scope.len() > 16
        || binding
            .resource_scope
            .iter()
            .any(|(key, value)| !label(key) || !text(value, 512))
    {
        return Err(Denial::InvalidAuthority);
    }
    if !valid_claims(input, binding) {
        return Err(Denial::InvalidClaims);
    }
    let current_sequence = match replay {
        ReplaySnapshot::Existing(receipt) => {
            if !id(&receipt.id)
                || receipt.organization_id != principal.organization_id
                || receipt.source_id != grant.source_id
                || receipt.api_key_id != principal.id
                || receipt.observation != *input
            {
                return Err(Denial::ReplayConflict);
            }
            // Return the ORIGINAL receipt after current authorization checks.
            // No new fact, freshness, policy evaluation or application mutation.
            return Ok(Admission::Replay {
                receipt_id: receipt.id.clone(),
            });
        }
        ReplaySnapshot::Missing { current_sequence } => current_sequence,
    };
    if current_sequence > MAX_SAFE_INTEGER {
        return Err(Denial::InvalidAuthority);
    }
    if !application.accepts_observations || application.expires_at_ms <= now_ms {
        return Err(Denial::ApplicationClosed);
    }
    if input.observed_at_ms > now_ms.saturating_add(binding.max_clock_skew_ms) {
        return Err(Denial::FutureObservation);
    }
    let observation_expires_at_ms = input.observed_at_ms.saturating_add(binding.max_age_ms);
    if observation_expires_at_ms <= now_ms {
        return Err(Denial::StaleObservation);
    }
    if input.sequence <= current_sequence {
        return Err(Denial::OutOfOrder);
    }
    Ok(Admission::Insert(Box::new(InsertPlan {
        organization_id: principal.organization_id.clone(),
        source_id: grant.source_id.clone(),
        api_key_id: principal.id.clone(),
        provider: binding.provider.clone(),
        application_id: binding.application_id.clone(),
        subject_id: binding.subject_id.clone(),
        fact_type: binding.fact_type.clone(),
        resource_scope: binding.resource_scope.clone(),
        received_at_ms: now_ms,
        observation: input.clone(),
        fence: AuthorityFence {
            api_key_revision: principal.revision,
            grant_revision: grant.revision,
            binding_revision: binding.revision,
            application_revision: application.revision,
            previous_sequence: current_sequence,
            authorization_expires_at_ms: principal.expires_at_ms.min(grant.expires_at_ms),
            observation_expires_at_ms,
        },
    })))
}

#[cfg(test)]
#[path = "external_observation_admission_tests.rs"]
mod tests;
