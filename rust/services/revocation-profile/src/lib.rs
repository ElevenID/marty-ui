pub mod authorization;
pub mod config;
pub mod domain;
pub mod grpc;
pub mod http;
pub mod migration;
pub mod operations;
pub mod postgres;
pub mod postgres_operations;
pub mod redis_status;
pub mod repository;
pub mod runtime;
pub mod service;
pub mod status;

pub mod proto {
    tonic::include_proto!("marty.ui.revocation_profile.v1");
}

pub mod organization_proto {
    tonic::include_proto!("marty.ui.organization.v1");
}

pub use authorization::OrganizationAuthorization;
pub use config::{migration_only_from_env, Config, MigrationConfig};
pub use domain::*;
pub use grpc::RevocationProfileGrpc;
pub use http::{Authorization, AuthorizationError, InternalServiceAuth, RevocationProfileHttp};
pub use migration::{migrate_and_seed, DEFAULT_ORGANIZATION_ID, DEFAULT_REVOCATION_PROFILE_ID};
pub use operations::*;
pub use postgres::PgProfileRepository;
pub use postgres_operations::PgRevocationOperationRepository;
pub use redis_status::RedisStatusRepository;
pub use repository::{InMemoryProfileRepository, ProfileRepository};
pub use runtime::{operational_router, BackendReadiness, NativeDiagnostics, OperationalState};
pub use service::{RevocationProfileService, ServiceError};
pub use status::{InMemoryStatusRepository, StatusListFormat, StatusRepository};
