//! Explicit mTLS transport for the opt-in public delegated-use host.
//!
//! Commands are prepared and retained before I/O. Recovery uses that independent
//! command identity, never a digest copied from a server response. Network
//! failures, pending results, and missing results do not prove that a command
//! did no work; the client never automatically retries or creates another ID.
//!
//! Request and receipt artifacts remain unverified bytes. The caller supplies
//! independent signing trust and verifies the complete request before submitting
//! a proof. Receipt verification belongs to `marty-delegated-receipt-consumer`.
//! Neither transport success nor a signed receipt grants business permission.

mod model;
mod strict;
mod transport;

pub use model::{
    CallerVerifiedRequest, CommandResponse, CommandResult, FinalizedUse, GrantReference, Operation,
    PreparedFinalize, PreparedStart, ProofSubmission, ReceiptArtifact, StartedUse,
    UnverifiedRequestArtifact,
};
pub use transport::{ClientConfig, DelegatedUseClient, MtlsConfig};

pub const COMMAND_PROFILE: &str = "urn:marty:delegation-command:v1";
pub const COMMAND_RESPONSE_PROFILE: &str = "urn:marty:delegation-command-response:v1";
pub const REQUEST_LINK_RELATION: &str = "urn:marty:delegated-use:request";
pub const EVIDENCE_SEMANTICS: &str = "EVIDENCE_ONLY";
pub const MAX_REQUEST_ARTIFACT_BYTES: usize = 65_536;
pub const MAX_COMPACT_RECEIPT_BYTES: usize = 100_000;
pub const MAX_PROOF_BYTES: usize = 262_144;
pub const MAX_FORM_BYTES: usize = 786_432;

/// Diagnostics are intentionally closed and never include upstream bodies,
/// URLs, command content, proofs, signed artifacts, or TLS signer diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClientError {
    #[error("delegated-use client configuration is invalid")]
    InvalidConfiguration,
    #[error("delegated-use command input is invalid")]
    InvalidCommand,
    #[error("delegated-use response schema or headers are invalid")]
    InvalidResponse,
    #[error("delegated-use response does not match the original command")]
    CorrelationMismatch,
    #[error("delegated-use wallet destination does not match the configured host and challenge")]
    InvalidDestination,
    #[error("delegated-use request or response exceeds its size limit")]
    TooLarge,
    #[error("delegated-use transport failed; the command outcome may be indeterminate")]
    Transport,
    #[error("delegated-use endpoint returned HTTP {0}; no automatic retry is performed")]
    Http(u16),
}

pub type Result<T> = std::result::Result<T, ClientError>;
