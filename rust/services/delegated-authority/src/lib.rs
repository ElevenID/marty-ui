//! Marty Delegated Authority v1 grant lifecycle.
//! This crate owns authoritative grant state and consent-evidence admission.
//! Domain-operation evaluation, Cedar integration, public Gateway routes,
//! and production signing are separate qualification milestones.
pub mod authorization;
pub mod consent;
pub mod consent_postgres;
pub mod domain;
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
pub use postgres::PgDelegationGrantRepository;
pub use repository::*;
pub use service::*;
pub use wire::{decode_grant_snapshot, GrantWireError};
