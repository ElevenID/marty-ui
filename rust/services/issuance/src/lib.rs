//! Native issuance service boundary.
//!
//! While migration status is `cutover-in-progress`, this crate is packaged only
//! as the beta `issuance-native` sidecar and receives the exact paths enumerated
//! by the coverage contract. The Python service remains the production runtime
//! and parity oracle until every frozen HTTP, gRPC, worker, configuration, and
//! migration gate passes.

#![forbid(unsafe_code)]

pub mod lossless_json;
pub mod lossless_json_tree;
mod lossless_json_write;
pub mod owned_json_value;
mod python_datetime;
mod python_format;
mod python_json_diagnostic;
pub mod python_text;
mod python_value;

pub mod canvas_award_candidate;
pub mod canvas_award_candidate_approval;
pub mod canvas_award_candidate_approval_postgres;
pub mod canvas_award_candidate_postgres;
pub mod canvas_award_candidate_service;
pub mod canvas_binding_domain;
pub mod canvas_catalog;
mod canvas_content_decoder;
pub mod canvas_credentials_delivery_config;
mod canvas_credentials_protocol;
pub mod canvas_credentials_publication;
pub mod canvas_credentials_status;
pub mod canvas_credentials_transport;
mod canvas_credentials_urls;
pub mod canvas_credentials_validation;
pub mod canvas_event_status;
pub mod canvas_event_status_postgres;
pub mod canvas_issuance_guard;
pub mod canvas_legacy_ingest;
pub mod canvas_legacy_ingest_postgres;
pub mod canvas_lifecycle_delivery;
pub mod canvas_lti_bootstrap;
pub mod canvas_lti_deep_linking;
pub mod canvas_lti_deep_linking_postgres;
pub mod canvas_lti_evidence;
pub mod canvas_lti_evidence_postgres;
pub mod canvas_lti_experience;
pub mod canvas_lti_launch;
pub mod canvas_lti_login;
pub mod canvas_lti_postgres;
pub mod canvas_lti_probe;
pub mod canvas_lti_sync_enqueue;
pub mod canvas_lti_tool_signing;
pub mod canvas_management;
pub mod canvas_management_domain;
pub mod canvas_management_http;
pub mod canvas_management_postgres;
pub mod canvas_management_service;
pub mod canvas_mirror_automation;
pub mod canvas_mirror_domain;
pub mod canvas_mirror_http;
pub mod canvas_mirror_postgres;
pub mod canvas_mirror_provider;
pub mod canvas_mirror_repository;
pub mod canvas_mirror_service;
pub mod canvas_network_timeout;
pub mod canvas_oauth;
pub mod canvas_oauth_http;
pub mod canvas_oauth_postgres;
mod canvas_operation_http;
pub mod canvas_operations;
pub mod canvas_operator_secret;
pub mod canvas_provider_http;
pub mod canvas_readiness;
pub mod canvas_readiness_runtime;
mod canvas_response_text;
mod signing_error_detail;
mod signing_http_response;
pub use signing_http_response::SigningResponseFailure;
pub mod application_template_catalog;
pub mod application_template_domain;
pub mod application_template_http;
pub mod application_template_postgres;
pub mod application_template_service;
pub mod canvas_review_resolution;
pub mod canvas_sync_lease;
pub mod canvas_sync_processor;
pub mod canvas_sync_processor_postgres;
pub mod canvas_sync_provider_http;
pub mod canvas_sync_worker;
pub mod canvas_sync_worker_lifecycle;
pub mod canvas_sync_worker_postgres;
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
pub mod credential_renewal;
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
pub mod internal_application_approval;
mod internal_application_diagnostics;
#[cfg(feature = "feature-regression-observer")]
pub use internal_application_diagnostics::observe_internal_application_diagnostics;
pub mod internal_application_domain;
pub mod internal_application_evidence;
pub mod internal_application_http;
pub mod internal_application_offer;
pub mod internal_application_postgres;
pub mod internal_application_reconciliation;
pub mod internal_application_service;
pub mod internal_external_evidence;
pub mod issued_credential_http;
pub mod issued_credential_postgres;
pub mod issued_credential_records;
mod management_http;
pub mod management_security;
pub mod migration;
mod network_policy;
pub mod oid4vci_authorization;
pub mod oid4vci_authorization_postgres;
pub mod oid4vci_management;
pub mod oid4vci_management_http;
pub mod oid4vci_management_postgres;
pub mod passport_bureau;
pub mod passport_artifact;
pub mod passport_repository;
pub mod passport_signer;
pub mod proof_nonce;
pub mod resource_owner;
pub mod resource_owner_postgres;
pub mod retention;
pub mod retention_http;
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
