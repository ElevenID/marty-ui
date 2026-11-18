//! Marty Delegated Authority v1 grant lifecycle.
//! This crate owns authoritative grant state and consent-evidence admission.
//! Domain-operation evaluation, Cedar integration, public Gateway routes,
//! and production signing are separate qualification milestones.
pub mod domain;
pub mod repository;
pub mod service;
#[cfg(test)]
pub mod test_support;
pub use domain::*;
pub use repository::*;
pub use service::*;
