//! Canonical credential-template service behavior.

#![forbid(unsafe_code)]

mod domain;
pub mod migration;
pub mod persistence;
pub mod postgres;

pub use domain::*;
pub use persistence::*;
pub use postgres::{CredentialTemplateRepositoryError, PostgresCredentialTemplateStore};
