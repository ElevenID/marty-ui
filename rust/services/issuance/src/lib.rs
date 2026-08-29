//! Native issuance service boundary.
//!
//! This crate is intentionally not packaged or deployed while migration status
//! is `cutover-in-progress`. The Python service remains the parity oracle until
//! every frozen HTTP, gRPC, worker, configuration, and migration gate passes.

#![forbid(unsafe_code)]

pub mod config;
pub mod contract;
pub mod http;
pub mod runtime;
pub mod signing_policy;
pub mod tenant_discovery;
pub mod tenant_postgres;
pub mod transport;

pub use config::*;
pub use contract::*;
pub use runtime::*;
