pub mod application;
pub mod catalog;
pub mod domain;
pub mod migration;
pub mod persistence;
pub mod policy;
pub mod postgres;
pub mod repository;

pub use application::{
    Change, CreateProfileInput, IssuerEntityPatch, OrganizationProfilePatch, ProfilePatch,
    RelationshipPatch, TrustAuthorizationError, TrustProfileApplication,
    TrustProfileApplicationError, TrustProfileControlPlane,
};
pub use catalog::{
    bootstrap_system_catalog, system_frameworks, MartyBootstrapConfig, TrustCatalogError,
};
pub use domain::{
    CascadeRevocationPolicy, ComplianceStatus, IssuerEntity, IssuerEntityComplianceStatus,
    IssuerEntityType, OrganizationTrustProfile, RegistryImportSource, RegistryImportType,
    RegistryImportedIssuer, RegistryOperation, RegistrySource, RevocationCheckMode,
    RevocationPolicy, TimePolicy, TrustAnchorType, TrustFramework, TrustProfile,
    TrustProfileIssuer, TrustProfileStatus, TrustProfileType, TrustRegistryEntry,
    TrustRelationshipStatus, TrustSource, TrustSourceType, ValidationRules,
};
pub use migration::{run_migrations, TrustProfileMigrationError, TrustProfileMigrationSummary};
pub use persistence::{TrustProfileRecord, TrustProfileRecordError, TRUST_PROFILE_MIGRATION};
pub use policy::{
    allowed_issuers_after_request, normalize_accreditations, normalize_jurisdictions,
    reject_private_custody_metadata, require_issuer_status_transition,
    sanitize_private_custody_metadata, TrustDomainError,
};
pub use postgres::PostgresTrustProfileRepository;
pub use repository::{
    MemoryTrustProfileRepository, RegistryStatus, TrustProfileRepository,
    TrustProfileRepositoryError,
};

pub const HTTP_OPERATIONS: [(&str, &str); 32] = [
    ("POST", "/v1/organizations/{organization_id}/trust-profiles"),
    ("GET", "/v1/organizations/{organization_id}/trust-profiles"),
    (
        "GET",
        "/v1/organizations/{organization_id}/trust-profiles/{profile_id}",
    ),
    (
        "PUT",
        "/v1/organizations/{organization_id}/trust-profiles/{profile_id}",
    ),
    ("POST", "/v1/trust-profiles"),
    ("GET", "/v1/trust-profiles"),
    ("GET", "/v1/trust-profiles/{profile_id}"),
    ("PATCH", "/v1/trust-profiles/{profile_id}"),
    ("POST", "/v1/trust-profiles/{profile_id}/activate"),
    ("POST", "/v1/trust-profiles/{profile_id}/suspend"),
    ("DELETE", "/v1/trust-profiles/{profile_id}"),
    ("POST", "/v1/trust-profiles/{profile_id}/registry-sync"),
    ("POST", "/v1/trust-profiles/{profile_id}/issuers"),
    ("GET", "/v1/trust-profiles/{profile_id}/issuers"),
    ("GET", "/v1/trust-profiles/{profile_id}/issuers/{issuer_id}"),
    (
        "PATCH",
        "/v1/trust-profiles/{profile_id}/issuers/{issuer_id}",
    ),
    (
        "DELETE",
        "/v1/trust-profiles/{profile_id}/issuers/{issuer_id}",
    ),
    ("GET", "/internal/v1/trust-profiles/{profile_id}"),
    (
        "GET",
        "/internal/v1/resource-owners/trust-profiles/{profile_id}",
    ),
    (
        "GET",
        "/internal/v1/resource-owners/issuer-entities/{issuer_entity_id}",
    ),
    ("GET", "/v1/trust-frameworks"),
    ("GET", "/v1/trust-frameworks/{framework_id}"),
    ("GET", "/v1/trust-registry/sync"),
    ("GET", "/v1/trust-registry/csca"),
    ("GET", "/v1/trust-registry/dsc"),
    ("GET", "/v1/trust-registry/csca/{country_code}"),
    ("GET", "/v1/trust-registry/status"),
    ("POST", "/v1/issuer-entities"),
    ("GET", "/v1/issuer-entities"),
    ("GET", "/v1/issuer-entities/{issuer_entity_id}"),
    ("PATCH", "/v1/issuer-entities/{issuer_entity_id}"),
    ("DELETE", "/v1/issuer-entities/{issuer_entity_id}"),
];
