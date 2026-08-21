#![forbid(unsafe_code)]

pub mod application;
pub mod cache_repository;
pub mod canvas;
pub mod canvas_transport;
pub mod credential_callback;
pub mod credential_http;
pub mod credential_login;
pub mod credential_page;
pub mod credential_state;
pub mod domain;
pub mod grpc_service;
pub mod http_kernel;
pub mod http_service;
pub mod keycloak;
pub mod migration;
pub mod oidc;
pub mod postgres;
pub mod provisioning;
pub mod service_transports;
pub mod wallet;

pub use application::*;
pub use cache_repository::*;
pub use canvas::*;
pub use canvas_transport::*;
pub use credential_callback::*;
pub use credential_http::*;
pub use credential_login::*;
pub use credential_page::*;
pub use credential_state::*;
pub use domain::{
    generate_pkce_pair, pkce_s256_challenge, AuthenticatedUser, ImpersonationContext, OidcUserInfo,
    OidcValidatedIdentity, PkcePair, PkceState, Session, SessionSpec, SessionStatus, UserType,
};
pub use grpc_service::*;
pub use http_kernel::*;
pub use http_service::*;
pub use keycloak::*;
pub use migration::*;
pub use oidc::*;
pub use postgres::*;
pub use provisioning::*;
pub use service_transports::*;
pub use wallet::*;

pub mod auth_proto {
    tonic::include_proto!("marty.ui.auth.v1");
}

pub mod flow_proto {
    tonic::include_proto!("marty.ui.flow.v1");
}

pub mod organization_proto {
    tonic::include_proto!("marty.ui.organization.v1");
}
