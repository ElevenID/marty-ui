//! Independent behavior contracts share a test binary, not fixtures or state.
//! Child-process checks keep child-scoped configuration; database and executable
//! smoke harnesses retain separate binaries.

#[path = "proof_nonce_behavior.rs"]
mod proof_nonce_behavior;

#[path = "issued_credential_adapter_behavior.rs"]
mod issued_credential_adapter_behavior;

#[path = "migration_contract.rs"]
mod migration_contract;
