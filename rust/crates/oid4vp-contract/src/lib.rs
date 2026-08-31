//! Versioned, language-neutral contracts for the canonical OID4VP trust boundary.
//!
//! These types deliberately do not perform credential or presentation verification.
//! They separate untrusted wallet input, server-owned frozen authority, and the
//! privacy-minimized projection emitted by a verifier. Arbitrary JSON never
//! becomes [`AuthenticatedOid4vpEvidenceV1`]; promotion belongs to the future
//! canonical Flow and presentation-policy producer adapter.

mod digest;
mod types;
mod validation;

pub use digest::*;
pub use types::*;
pub use validation::Oid4vpContractError;
