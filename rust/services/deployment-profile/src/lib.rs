//! Deployment runtime profiles, lanes, and device assignment.
//!
//! Generic lifecycle and authorization come from MMF. This crate is the one
//! Rust owner of the deployment-profile domain and its Gateway DTO contract.

#![forbid(unsafe_code)]

pub mod config;
pub mod domain;
pub mod gateway_contract;
pub mod http;
pub mod migration;
pub mod provider;
pub mod repository;
pub mod runtime;
pub mod service;

pub use config::*;
pub use domain::*;
pub use http::*;
pub use migration::*;
pub use provider::*;
pub use repository::*;
pub use runtime::*;
pub use service::*;
