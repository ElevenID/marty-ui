pub mod domain;
pub mod grpc;
pub mod http;
pub mod postgres;
pub mod redis_status;
pub mod repository;
pub mod service;
pub mod status;

pub mod proto {
    tonic::include_proto!("marty.ui.revocation_profile.v1");
}

pub use domain::*;
pub use grpc::RevocationProfileGrpc;
pub use http::{Authorization, AuthorizationError, InternalServiceAuth, RevocationProfileHttp};
pub use postgres::PgProfileRepository;
pub use redis_status::RedisStatusRepository;
pub use repository::{InMemoryProfileRepository, ProfileRepository};
pub use service::{RevocationProfileService, ServiceError};
pub use status::{InMemoryStatusRepository, StatusListFormat, StatusRepository};
