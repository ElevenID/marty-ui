pub mod delivery;
pub mod domain;
pub mod grpc;
pub mod http;
pub mod migration;
pub mod outbox;
pub mod payload_security;
pub mod postgres;
pub mod repository;
pub mod service;
pub mod webhook;

pub mod proto {
    tonic::include_proto!("marty.ui.notification.v1");
}
