//! Marty Delegated Authority v1 lifecycle and operation evaluation.
//!
//! Owns authoritative grant state, consent-evidence admission and ephemeral
//! operation evaluation with Marty OID4VP and MMF Cedar adapters. A successful
//! evaluation is not a bearer permit or an operation commit. Default-off human
//! approval and lifecycle-command hosts compose behind the Gateway. Delegated-use
//! composition includes retained commands, an explicit authenticated internal
//! router, machine credential/audit gates and signed receipts. Public hosting
//! and authoritative source deployment remain separate qualification milestones.
pub mod approval;
pub mod approval_host_config;
pub mod approval_http;
pub mod approval_postgres;
pub mod authorization;
pub mod challenge;
pub mod command_host_config;
pub mod command_http;
pub mod command_postgres;
mod command_role_boundary;
pub mod commands;
pub mod consent;
pub mod consent_postgres;
pub mod delegation_policy_source;
pub mod domain;
pub mod machine_auth;
pub mod machine_cedar;
pub mod machine_credentials;
pub mod machine_evidence;
pub mod machine_policy_source;
pub mod oid4vp;
pub mod organization_authority;
pub mod organization_machine_state;
pub mod organization_use_access;
pub mod postgres;
pub mod receipt;
pub mod receipt_signing;
pub mod repository;
pub mod service;
#[cfg(test)]
pub mod test_support;
pub mod wire;
pub use approval::*;
pub use approval_postgres::*;
pub use authorization::*;
pub use challenge::*;
pub use commands::*;
pub use consent::*;
pub use consent_postgres::*;
pub use delegation_policy_source::OrganizationDelegationCedarPolicySource;
pub use domain::*;
pub use oid4vp::*;
pub use organization_authority::*;
pub use organization_use_access::OrganizationDelegationUseCommandAuthorizer;
pub use postgres::PgDelegationGrantRepository;
pub use receipt::*;
pub use receipt_signing::*;
pub use repository::*;
pub use service::*;
pub use wire::{decode_grant_snapshot, GrantWireError};

pub mod use_commands;
pub mod use_http;
pub mod use_ingress;
pub mod use_mtls;
pub mod use_postgres;
pub use use_commands::*;
pub use use_ingress::*;
pub use use_postgres::{delegated_use_receipt_ref, PgDelegationUseRepository};
