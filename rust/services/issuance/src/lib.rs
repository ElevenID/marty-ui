//! Native issuance service boundary.
//!
//! While migration status is `cutover-in-progress`, this crate is packaged only
//! as the beta `issuance-native` sidecar and receives the exact paths enumerated
//! by the coverage contract. The Python service remains the production runtime
//! and parity oracle until every frozen HTTP, gRPC, worker, configuration, and
//! migration gate passes.

#![forbid(unsafe_code)]

pub mod canvas_award_candidate;
pub mod canvas_award_candidate_approval;
pub mod canvas_award_candidate_approval_postgres;
pub mod canvas_award_candidate_postgres;
pub mod canvas_award_candidate_service;
pub mod canvas_issuance_guard;
pub mod canvas_lti_bootstrap;
pub mod canvas_lti_deep_linking;
pub mod canvas_lti_deep_linking_postgres;
pub mod canvas_lti_evidence;
pub mod canvas_lti_evidence_postgres;
pub mod canvas_lti_experience;
pub mod canvas_lti_launch;
pub mod canvas_lti_login;
pub mod canvas_lti_postgres;
pub mod canvas_lti_sync_enqueue;
pub mod canvas_lti_tool_signing;
pub mod canvas_management;
pub mod canvas_oauth;
pub mod canvas_oauth_http;
pub mod canvas_oauth_postgres;
pub mod client_auth;
pub mod config;
pub mod contract;
pub mod credential;
pub mod credential_builder;
pub mod credential_issuer;
pub mod credential_lifecycle;
pub mod credential_management;
pub mod credential_management_events;
pub mod credential_management_grpc;
pub mod credential_management_http;
pub mod credential_management_postgres;
pub mod credential_postgres;
pub mod dpop;
pub mod ephemeral_postgres;
pub mod http;
pub mod initiation;
pub mod initiation_dependencies;
pub mod initiation_didcomm;
pub mod initiation_didcomm_http;
pub mod initiation_http;
pub mod initiation_response;
pub mod integration_secret;
pub mod management_security;
mod network_policy;
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

pub mod issuance_proto {
    tonic::include_proto!("marty.ui.issuance.v1");
}

pub mod organization_proto {
    tonic::include_proto!("marty.ui.organization.v1");
}

pub mod credential_template_proto {
    tonic::include_proto!("marty.ui.credential_template.v1");
}

pub mod revocation_profile_proto {
    tonic::include_proto!("marty.ui.revocation_profile.v1");
}
