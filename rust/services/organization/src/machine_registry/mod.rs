//! Organization-owned full machine registration and deployment MAP selection.
//!
//! This is distinct from the SERVICE_ACCOUNT agent directory. A current entry
//! is an accountable source of identity/key/configuration facts, not proof that
//! a workload controls its key, holds trusted credentials, or has authority.
//! No public router or default-enabled host installs these APIs.

mod domain;
mod owner;
mod source;

pub use domain::{
    MachineRegistryDocuments, MachineRegistryError, MachineRegistryLifecycle,
    MachineRegistryRecord, MachineRegistrySelection, MachineRegistryUseScope,
};
pub use owner::MachineRegistryService;
pub(crate) use source::validate_schema;
pub use source::{
    HistoricalMachineRegistryObservation, MachineRegistryObservation, PgMachineRegistrySource,
};

pub const MACHINE_REGISTRY_MIGRATION: &str = "rust_organization_machine_registry_0005";
pub const MACHINE_REGISTRY_SOURCE_PROFILE: &str = "urn:marty:machine-registry-observation:v1";
pub const MACHINE_REGISTRY_SOURCE_REF_PREFIX: &str = "urn:marty:machine-registry:sha256:";

pub(crate) fn database_error(error: sqlx::Error) -> MachineRegistryError {
    if error.as_database_error().and_then(|e| e.code()).as_deref() == Some("23505") {
        MachineRegistryError::Conflict
    } else {
        MachineRegistryError::Unavailable
    }
}
