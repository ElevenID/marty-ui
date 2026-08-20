#![forbid(unsafe_code)]

pub mod authorization;
pub mod config;
pub mod contract;
pub mod credential_metadata;
pub mod credential_template_contract;
pub mod deployment_contract;
pub mod did_web;
pub mod didcomm_contract;
pub mod discovery;
pub mod flow_contract;
pub mod issuance_create;
pub mod issuance_lifecycle_contract;
pub mod middleware;
pub mod organization_composition;
pub mod organization_contract;
pub mod presentation_policy_contract;
pub mod providers;
pub mod registry;
pub mod response_projection;
pub mod runtime;
pub mod signing_compat;
pub mod transport;
pub mod trust_contract;
pub mod vc_api;
pub mod verification_flow_contract;

pub mod auth_proto {
    tonic::include_proto!("marty.ui.auth.v1");
}

pub mod organization_proto {
    tonic::include_proto!("marty.ui.organization.v1");
}

pub mod event_stream_proto {
    tonic::include_proto!("marty.ui.event_stream.v1");
}
