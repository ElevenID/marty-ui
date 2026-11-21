//! Organization-owned identity inventory and administration.
//!
//! Administrative ACTIVE state is not authentication or delegated authority.
//! Managed entries start PROVISIONED. A separately enabled, exact-context
//! challenge can establish administrator-approved control of the current key
//! and ACTIVE eligibility. It does not establish external host or issuer trust,
//! issue operational machine credentials, or change existing DelegationGrants.
//!
//! Human administration requires a current active Organization membership and
//! the corresponding `agent-identity:*` permission. Consulted organization,
//! membership, role and permission rows remain locked until the transaction
//! commits; forwarded API keys cannot use this application boundary. Identity,
//! key, revision history and the Organization audit event commit together.
//!
//! Suspension is one-way in this candidate: there is no resume operation.
//! Enrollment only accepts a managed PROVISIONED record. A suspended record can
//! be inspected, have permitted metadata or
//! its inventory key changed, and then be revoked or retired; it cannot pass
//! current-use lookup. Revocation/retirement clear the current key projection
//! while preserving the historical key and immutable revision evidence.
//!
//! Registered public keys use the existing principal-runtime-binding verifier
//! for the pinned Ed25519/P-256 JWK profile. Source provenance remains an
//! operator declaration; enrollment records a separate KEY_CONTROL_VERIFIED
//! fact without qualifying external authentication or authority. Current lookup
//! returns a timestamped inventory match,
//! with no cache lifetime or authentication authority: every actual use still
//! requires independent live issuer/subject/runtime proof, MAP validation and
//! current delegation checks by the consuming authenticated adapter.
mod domain;
mod enrollment;
mod enrollment_store;
mod service;
mod wire;

pub use domain::*;
pub use enrollment::*;
pub use service::AgentDirectoryService;
pub use wire::decode_agent_request;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AgentDirectoryError {
    #[error("ORGANIZATION.AGENT_INVALID_REQUEST")]
    InvalidRequest,
    #[error("ORGANIZATION.AGENT_ACCESS_DENIED")]
    AccessDenied,
    #[error("ORGANIZATION.AGENT_NOT_FOUND")]
    NotFound,
    #[error("ORGANIZATION.AGENT_REVISION_OR_IDENTITY_CONFLICT")]
    Conflict,
    #[error("ORGANIZATION.AGENT_INVALID_TRANSITION")]
    InvalidTransition,
    #[error("ORGANIZATION.AGENT_DIRECTORY_UNAVAILABLE")]
    Unavailable,
    #[error("ORGANIZATION.AGENT_DIRECTORY_CORRUPT_DATA")]
    CorruptData,
}

fn database_error(error: sqlx::Error) -> AgentDirectoryError {
    if error
        .as_database_error()
        .and_then(|error| error.code())
        .as_deref()
        == Some("23505")
    {
        AgentDirectoryError::Conflict
    } else {
        AgentDirectoryError::Unavailable
    }
}
