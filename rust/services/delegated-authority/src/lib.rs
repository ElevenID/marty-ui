//! Marty Delegated Authority v1 lifecycle and operation evaluation.
//!
//! Owns authoritative grant state, consent-evidence admission and ephemeral
//! operation evaluation with Marty OID4VP and MMF Cedar adapters. A successful
//! evaluation is not a bearer permit or an operation commit. Authenticated
//! runtime composition, final-use replay/revision enforcement, signed receipts
//! and public Gateway hosting remain separate qualification milestones.
pub mod approval;
pub mod approval_host_config;
pub mod approval_http;
pub mod approval_postgres;
pub mod authorization;
pub mod challenge;
pub mod commands;
pub mod consent;
pub mod consent_postgres;
pub mod domain;
pub mod oid4vp;
pub mod organization_authority;
pub mod postgres;
pub mod receipt;
pub mod repository;
pub mod service;
#[cfg(test)]
pub mod test_support;
pub mod wire;
pub use approval::*;
pub use approval_postgres::*;
pub use authorization::*;
pub use challenge::*;
pub use commands::*;
pub use consent::*;
pub use consent_postgres::*;
pub use domain::*;
pub use oid4vp::*;
pub use organization_authority::*;
pub use postgres::PgDelegationGrantRepository;
pub use receipt::*;
pub use repository::*;
pub use service::*;
pub use wire::{decode_grant_snapshot, GrantWireError};
