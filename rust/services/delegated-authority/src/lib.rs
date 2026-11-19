//! Marty Delegated Authority v1 lifecycle and operation evaluation.
//!
//! Owns authoritative grant state, consent-evidence admission and ephemeral
//! operation evaluation with Marty OID4VP and MMF Cedar adapters. A successful
//! evaluation is not a bearer permit or an operation commit. Authenticated
//! runtime composition, final-use replay/revision enforcement, signed receipts
//! and public Gateway hosting remain separate qualification milestones.
pub mod authorization;
pub mod consent;
pub mod consent_postgres;
pub mod domain;
pub mod oid4vp;
pub mod postgres;
pub mod repository;
pub mod service;
#[cfg(test)]
pub mod test_support;
pub mod wire;
pub use authorization::*;
pub use consent::*;
pub use consent_postgres::*;
pub use domain::*;
pub use oid4vp::*;
pub use postgres::PgDelegationGrantRepository;
pub use repository::*;
pub use service::*;
pub use wire::{decode_grant_snapshot, GrantWireError};
