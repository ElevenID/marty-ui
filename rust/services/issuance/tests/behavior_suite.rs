//! Independent behavior contracts share a test binary, not fixtures or state.
//! Child-process checks keep child-scoped configuration; database and executable
//! smoke harnesses retain separate binaries.

#[path = "canvas_management_contract.rs"]
mod canvas_management_contract;

#[path = "canvas_sync_worker_behavior.rs"]
mod canvas_sync_worker_behavior;

#[path = "canvas_sync_worker_configuration_oracle.rs"]
mod canvas_sync_worker_configuration_oracle;

#[path = "canvas_worker_result_oracle.rs"]
mod canvas_worker_result_oracle;

#[path = "proof_nonce_behavior.rs"]
mod proof_nonce_behavior;

#[path = "canvas_lti_tool_signing_behavior.rs"]
mod canvas_lti_tool_signing_behavior;
