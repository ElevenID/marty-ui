//! Native issuance service boundary.
//!
//! While migration status is `cutover-in-progress`, this crate is packaged only
//! as the beta `issuance-native` sidecar and receives the exact paths enumerated
//! by the coverage contract. The Python service remains the production runtime
//! and parity oracle until every frozen HTTP, gRPC, worker, configuration, and
//! migration gate passes.

#![forbid(unsafe_code)]

pub mod canvas_issuance_guard;
pub mod canvas_lti_launch;
pub mod canvas_lti_login;
pub mod canvas_lti_postgres;
pub mod client_auth;
pub mod config;
pub mod contract;
pub mod credential;
pub mod credential_builder;
pub mod credential_issuer;
pub mod credential_lifecycle;
pub mod credential_postgres;
pub mod dpop;
pub mod ephemeral_postgres;
pub mod http;
pub mod management_security;
pub mod proof_nonce;
pub mod runtime;
pub mod signing_policy;
pub mod tenant_discovery;
pub mod tenant_postgres;
pub mod token_exchange;
pub mod token_postgres;
pub mod token_rate_limit;
pub mod transaction_postgres;
pub mod transaction_reads;
pub mod transport;

pub use config::*;
pub use contract::*;
pub use runtime::*;
