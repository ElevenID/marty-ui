//! Independent, offline verification of delegated decision receipt evidence.
//!
//! Trust, expected request context, retained-result metadata, and time are
//! supplied independently by the caller. No identifier is fetched and no key
//! is selected from receipt-controlled metadata. Successful verification says
//! nothing about current revocation, business permission, execution, or replay
//! consumption. Historical evidence cannot be promoted to fresh evidence.

mod key;
mod model;
mod strict;
mod verify;

pub use key::PinnedReceiptKey;
pub use model::{
    Algorithm, Binding, Decision, DomainEvidenceClaims, DomainEvidenceContext,
    EvidenceReferencePins, EvidenceReferences, EvidenceTimes, FreshnessPolicy, GrantReference,
    Operation, Policy, PolicyExpectation, Principal, PrincipalType, ReceiptContext,
    ReceiptExpectation, RetainedReceiptBinding, StatusState,
};
pub use verify::{
    verify_fresh, verify_historical, FreshReceiptEvidence, HistoricalReceiptEvidence,
};

pub const RECEIPT_PROFILE: &str = "urn:marty:delegated-decision-receipt:v1";
pub const EVALUATION_PROFILE: &str = "urn:marty:delegated-evaluation:v1";
pub const RECEIPT_JWS_TYPE: &str = "mip-delegated-decision+jws";
pub const RECEIPT_REFERENCE_PREFIX: &str = "urn:marty:delegated-receipt:";
pub const MAX_COMPACT_RECEIPT_BYTES: usize = 100_000;

/// Stable diagnostics never embed submitted receipts, identities, or evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReceiptVerificationError {
    #[error("receipt exceeds its size limit")]
    TooLarge,
    #[error("receipt encoding or schema is invalid")]
    InvalidWire,
    #[error("receipt trust configuration is invalid")]
    InvalidTrust,
    #[error("independent receipt expectation is invalid")]
    InvalidExpectation,
    #[error("receipt signing identity does not match the selected trust")]
    KeyMismatch,
    #[error("receipt signature is invalid")]
    InvalidSignature,
    #[error("receipt context does not match the independent expectation")]
    ContextMismatch,
    #[error("receipt does not match the retained result")]
    RetentionMismatch,
    #[error("receipt evidence timeline is inconsistent")]
    InvalidTimeline,
    #[error("receipt was issued after the supplied observation time")]
    NotYetIssued,
    #[error("receipt evidence has expired")]
    Expired,
    #[error("receipt evidence exceeds the selected freshness policy")]
    Stale,
    #[error("receipt contains a signed denial")]
    DecisionDenied,
}

pub(crate) type Result<T> = std::result::Result<T, ReceiptVerificationError>;
