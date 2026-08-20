//! Marty credential flow orchestration.
//!
//! Protocol and cryptographic decisions come from `marty-core`; generic
//! workflow, outbox, retry, and delivery behavior comes from MMF. This crate
//! owns only Marty Flow domain composition and service adapters.

#![forbid(unsafe_code)]

mod api;
mod callback;
mod config;
mod connections;
mod contract;
mod definition_mutation;
mod domain;
mod grpc_providers;
mod grpc_security;
mod http_providers;
mod http_read;
mod instance_execution;
mod instance_side_effects;
mod migration;
mod postgres;
mod projection;
mod providers;
mod records;
mod reference_validation;
mod repository;
mod runtime;

pub mod credential_template_proto {
    tonic::include_proto!("marty.ui.credential_template.v1");
}
pub mod flow_proto {
    tonic::include_proto!("marty.ui.flow.v1");
}
pub mod issuance_proto {
    tonic::include_proto!("marty.ui.issuance.v1");
}
pub mod organization_proto {
    tonic::include_proto!("marty.ui.organization.v1");
}
pub mod presentation_policy_proto {
    tonic::include_proto!("marty.ui.presentation_policy.v1");
}

pub use api::*;
pub use callback::*;
pub use config::*;
pub use connections::*;
pub use contract::*;
pub use definition_mutation::*;
pub use domain::*;
pub use grpc_providers::*;
pub use grpc_security::*;
pub use http_providers::*;
pub use http_read::*;
pub use instance_execution::*;
pub use instance_side_effects::*;
pub use migration::*;
pub use postgres::*;
pub use projection::*;
pub use providers::*;
pub use records::*;
pub use reference_validation::*;
pub use repository::*;
pub use runtime::*;
