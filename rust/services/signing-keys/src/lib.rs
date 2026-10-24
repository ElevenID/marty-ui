pub mod bootstrap;
pub mod bootstrap_engine;
pub mod bootstrap_runtime;
pub mod bootstrap_simulation;
pub mod certificate_csr;
pub mod certificate_issuance;
pub mod compat;
pub mod config;
pub mod csca_lifecycle;
pub mod documents;
pub mod domain;
pub mod dsc_issuance_store;
pub mod flow_envelope;
pub mod http;
mod identity_capabilities;
pub mod integration_secret_envelope;
pub mod kms;
pub mod managed_holder_http;
pub mod managed_holder_key;
pub mod passport_artifact_envelope;
pub mod passport_callback_hmac;
mod private_material;
pub mod profiles;
pub mod registry;
pub mod validation;
pub mod vc_api_holder_proof;

#[cfg(test)]
extern crate self as marty_signing_keys;

#[cfg(test)]
#[path = "../tests/support/disposable_backends.rs"]
mod disposable_backends;

#[cfg(test)]
mod managed_key_create_mock_contract;
#[cfg(test)]
mod public_config_resolve_mock_contract;
#[cfg(test)]
mod service_rotation_mock_contract;
