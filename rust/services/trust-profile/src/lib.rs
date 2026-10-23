pub mod application;
pub mod catalog;
pub mod config;
pub mod control_plane;
pub mod domain;
pub mod http_service;
pub mod issuer_keys;
pub mod migration;
pub mod persistence;
pub mod policy;
pub mod postgres;
pub mod registry_scheduler;
pub mod registry_sync;
pub mod repository;
pub mod runtime;
pub mod surface;

pub mod organization_proto {
    tonic::include_proto!("marty.ui.organization.v1");
}

pub use application::{
    Change, CreateProfileInput, IssuerEntityPatch, OrganizationProfilePatch, ProfilePatch,
    RelationshipPatch, TrustAuthorizationError, TrustProfileApplication,
    TrustProfileApplicationError, TrustProfileControlPlane,
};
pub use catalog::{
    bootstrap_system_catalog, system_frameworks, MartyBootstrapConfig, TrustCatalogError,
};
pub use config::{RuntimeEnvironment, TrustProfileConfigError, TrustProfileServiceConfig};
pub use control_plane::NativeTrustProfileControlPlane;
pub use domain::{
    CascadeRevocationPolicy, ComplianceStatus, IssuerEntity, IssuerEntityComplianceStatus,
    IssuerEntityType, OrganizationTrustProfile, RegistryImportSource, RegistryImportType,
    RegistryImportedIssuer, RegistryOperation, RegistrySource, RevocationCheckMode,
    RevocationPolicy, TimePolicy, TrustAnchorType, TrustFramework, TrustProfile,
    TrustProfileIssuer, TrustProfileStatus, TrustProfileType, TrustPurpose, TrustRegistryEntry,
    TrustRelationshipStatus, TrustSource, TrustSourceType, TrustedAssertionFormat, ValidationRules,
};
pub use http_service::{
    trust_profile_router, TrustProfileHttpState, TrustRegistrySyncError, TrustRegistrySynchronizer,
};
pub use issuer_keys::{
    IssuerKeyResolution, IssuerKeyResolutionError, IssuerKeyResolver, NativeIssuerKeyResolver,
};
pub use migration::{run_migrations, TrustProfileMigrationError, TrustProfileMigrationSummary};
pub use persistence::{TrustProfileRecord, TrustProfileRecordError, TRUST_PROFILE_MIGRATION};
pub use policy::{
    allowed_issuers_after_request, normalize_accreditations, normalize_jurisdictions,
    reject_private_custody_metadata, require_issuer_status_transition,
    sanitize_private_custody_metadata, TrustDomainError,
};
pub use postgres::PostgresTrustProfileRepository;
pub use registry_scheduler::{ScheduledRegistrySyncReport, TrustRegistryScheduler};
pub use registry_sync::NativeTrustRegistrySynchronizer;
pub use repository::{
    MemoryTrustProfileRepository, RegistryStatus, TrustProfileRepository,
    TrustProfileRepositoryError,
};
pub use runtime::{TrustProfileDependency, TrustProfileRuntime};
pub use surface::{HttpOperation, TRUST_PROFILE_HTTP_OPERATIONS};
