//! Standalone verification orchestration.
//!
//! OID4VP/DCQL construction and credential verification remain canonical in
//! `marty-flow` and `marty-core`; MMF owns shared security and runtime policy.
//! This crate owns only the standalone session API and its atomic lifecycle.

#![forbid(unsafe_code)]

pub mod config;
pub mod credentials_compat;
pub mod domain;
pub mod grpc;
pub mod http;
pub mod providers;
pub mod runtime;
pub mod service;
pub mod store;

pub mod verification_proto {
    tonic::include_proto!("marty.ui.verification.v1");
}

pub use config::*;
pub use domain::*;
pub use grpc::*;
pub use providers::*;
pub use runtime::*;
pub use service::*;
pub use store::*;
