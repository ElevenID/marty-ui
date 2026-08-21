//! Canonical credential-template service behavior.

#![forbid(unsafe_code)]

pub mod application;
pub mod catalog;
mod domain;
pub mod migration;
pub mod persistence;
pub mod postgres;
pub mod surface;

pub use domain::*;
pub use persistence::*;
pub use postgres::{CredentialTemplateRepositoryError, PostgresCredentialTemplateStore};
