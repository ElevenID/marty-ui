#![forbid(unsafe_code)]

pub mod domain;

pub use domain::{
    generate_pkce_pair, pkce_s256_challenge, AuthenticatedUser, ImpersonationContext, OidcUserInfo,
    PkcePair, PkceState, Session, SessionSpec, SessionStatus, UserType,
};
