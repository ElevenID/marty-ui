//! Marty credential flow orchestration.
//!
//! Protocol and cryptographic decisions come from `marty-core`; generic
//! workflow, outbox, retry, and delivery behavior comes from MMF. This crate
//! owns only Marty Flow domain composition and service adapters.

#![forbid(unsafe_code)]

mod api;
mod callback;
mod contract;
mod domain;
mod grpc_providers;
mod postgres;
mod providers;
mod repository;

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
pub use contract::*;
pub use domain::*;
pub use grpc_providers::*;
pub use postgres::*;
pub use providers::*;
pub use repository::*;
