//! Canonical credential-template service behavior.

#![forbid(unsafe_code)]

pub mod application;
pub mod catalog;
pub mod config;
pub mod control_plane;
mod domain;
pub mod grpc_service;
pub mod http_service;
pub mod migration;
pub mod persistence;
pub mod postgres;
pub mod registry_application;
pub mod runtime;
pub mod surface;
pub mod wallet;

pub mod credential_template_proto {
    tonic::include_proto!("marty.ui.credential_template.v1");
}

pub mod organization_proto {
    tonic::include_proto!("marty.ui.organization.v1");
}

pub mod revocation_profile_proto {
    tonic::include_proto!("marty.ui.revocation_profile.v1");
}

pub use domain::*;
pub use persistence::*;
pub use postgres::{CredentialTemplateRepositoryError, PostgresCredentialTemplateStore};
