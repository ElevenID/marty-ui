//! Compatibility boundary for the retired Credentials verification image.
//!
//! This module adapts the released HTTP and persistence contracts to canonical
//! Core and MMF behavior. It must not contain an independent verification,
//! governance, cryptographic, DID, policy, or framework implementation.

pub mod application;
pub mod decision;
pub mod dto;
pub mod evidence;
pub mod governance;
pub mod http;
pub mod migration;
pub mod native;
pub mod persistence;
pub mod resolver;
pub mod session;

pub use application::CredentialsCompatibilityService;
pub use decision::{
    build_canonical_decision, AdapterFacts, CredentialStatus, DecisionBuildError, Presented,
};
pub use dto::{
    ClaimResult, CreateSessionRequest, PresentationDefinition, PresentationPayload,
    RequestValidationError, SessionDurationSeconds, SessionResponse, SubmitPresentationRequest,
    VerificationResult, VerifyDirectRequest, VerifyVdsNcRequest,
};
pub use evidence::{EvidenceFailureReason, PersistedEvidence, PersistedEvidenceError};
pub use governance::{
    GovernanceEngine, GovernanceError, GovernancePurpose, GovernanceSnapshot, PolicyAuthority,
    TrustAuthority,
};
pub use http::{router, CompatibilityError, CompatibilityState, CompatibilityUseCases};
pub use migration::{migrate_session_schema, validate_session_schema, SessionMigrationError};
pub use native::{CredentialVerificationKernel, NativeCredentialVerificationKernel};
pub use persistence::{PostgresSessionRepository, SessionPersistenceError, SessionRepository};
pub use resolver::{
    IssuerKeyRequest, IssuerKeyResolver, IssuerResolutionError, OrganizationIssuerKeyResolver,
    ResolvedIssuerKey,
};
pub use session::{
    ClaimState, ProcessingLease, ProcessingToken, SessionDraft, SessionRecord, SessionStatus,
    Sha256Digest, SubmissionClaim, TerminalDecision, VerificationMethod, VerifierNonce,
};
