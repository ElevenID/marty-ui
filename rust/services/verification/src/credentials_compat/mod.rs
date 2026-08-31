//! Compatibility boundary for the retired Credentials verification image.
//!
//! This module adapts the released HTTP and persistence contracts to canonical
//! Core and MMF behavior. It must not contain an independent verification,
//! governance, cryptographic, DID, policy, or framework implementation.

pub mod dto;
pub mod governance;
pub mod http;

pub use dto::{
    ClaimResult, CreateSessionRequest, PresentationDefinition, PresentationPayload,
    RequestValidationError, SessionDurationSeconds, SessionResponse, SubmitPresentationRequest,
    VerificationResult, VerifyDirectRequest, VerifyVdsNcRequest,
};
pub use governance::{
    GovernanceEngine, GovernanceError, GovernancePurpose, GovernanceSnapshot, PolicyAuthority,
    TrustAuthority,
};
pub use http::{router, CompatibilityError, CompatibilityState, CompatibilityUseCases};
