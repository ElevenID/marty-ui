use std::collections::{BTreeMap, BTreeSet};

use marty_crypto::certificate::get_certificate_info;
use mmf_platform::GrpcServerTlsMaterial;
use mmf_security::{
    constant_time_secret_eq, WorkloadAuthorizationDecision, WorkloadIdentityPolicy,
};
use thiserror::Error;
use tonic::{
    transport::server::{TcpConnectInfo, TlsConnectInfo},
    Request, Status,
};

use crate::FlowServiceConfig;

pub const START_VERIFICATION_METHOD: &str = "/marty.ui.flow.v1.FlowService/StartVerification";
pub const APPLICATION_APPROVED_METHOD: &str = "/marty.ui.flow.v1.FlowService/ApplicationApproved";
pub const AUTH_WORKLOAD_IDENTITY: &str = "spiffe://marty.internal/service/auth";
pub const APPLICANT_WORKLOAD_IDENTITY: &str = "spiffe://marty.internal/service/applicant";

#[derive(Debug, Error)]
pub enum FlowGrpcSecurityError {
    #[error("FLOW.GRPC_SECURITY_CONFIGURATION: {0}")]
    Configuration(String),
    #[error("FLOW.GRPC_TLS_CONFIGURATION: {0}")]
    Tls(#[from] mmf_platform::PlatformError),
    #[error("FLOW.GRPC_WORKLOAD_POLICY: {0}")]
    Policy(#[from] mmf_security::SecurityError),
}

pub struct FlowGrpcSecurity {
    service_token: Vec<u8>,
    workload_policy: WorkloadIdentityPolicy,
    server_tls: GrpcServerTlsMaterial,
}

impl FlowGrpcSecurity {
    pub fn from_config(config: &FlowServiceConfig) -> Result<Self, FlowGrpcSecurityError> {
        let service_token = config
            .service_token
            .as_deref()
            .ok_or_else(|| FlowGrpcSecurityError::Configuration("service token is missing".into()))?
            .as_bytes()
            .to_vec();
        let files = config.workload_server_tls.as_ref().ok_or_else(|| {
            FlowGrpcSecurityError::Configuration("workload server TLS is missing".into())
        })?;
        let server_tls = GrpcServerTlsMaterial::from_pem_files(
            &files.ca_certificate,
            &files.certificate,
            &files.private_key,
        )?;
        let workload_policy = WorkloadIdentityPolicy::new(BTreeMap::from([
            (
                START_VERIFICATION_METHOD.into(),
                BTreeSet::from([AUTH_WORKLOAD_IDENTITY.into()]),
            ),
            (
                APPLICATION_APPROVED_METHOD.into(),
                BTreeSet::from([APPLICANT_WORKLOAD_IDENTITY.into()]),
            ),
        ]))?;
        Ok(Self {
            service_token,
            workload_policy,
            server_tls,
        })
    }

    #[must_use]
    pub fn server_tls_config(&self) -> tonic::transport::ServerTlsConfig {
        self.server_tls.server_tls_config()
    }

    pub fn authenticate_service<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let candidate = request
            .metadata()
            .get("x-service-token")
            .and_then(|value| value.to_str().ok())
            .map(str::as_bytes)
            .unwrap_or_default();
        if constant_time_secret_eq(&self.service_token, candidate) {
            Ok(())
        } else {
            Err(Status::unauthenticated("service authentication failed"))
        }
    }

    pub fn authorize_workload<T>(&self, request: &Request<T>, method: &str) -> Result<(), Status> {
        self.authenticate_service(request)?;
        let identities = peer_uri_sans(request);
        self.authorize_evidence(method, identities.iter().map(String::as_str))
    }

    fn authorize_evidence<'a>(
        &self,
        method: &str,
        identities: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), Status> {
        match self.workload_policy.authorize(method, identities) {
            WorkloadAuthorizationDecision::Allow => Ok(()),
            WorkloadAuthorizationDecision::Unauthenticated => Err(Status::unauthenticated(
                "a mutually authenticated workload identity is required",
            )),
            WorkloadAuthorizationDecision::Forbidden => Err(Status::permission_denied(
                "the authenticated workload is not authorized for this RPC",
            )),
        }
    }
}

fn peer_uri_sans<T>(request: &Request<T>) -> BTreeSet<String> {
    let Some(certificates) = request
        .extensions()
        .get::<TlsConnectInfo<TcpConnectInfo>>()
        .and_then(TlsConnectInfo::peer_certs)
    else {
        return BTreeSet::new();
    };
    certificates
        .iter()
        .filter_map(|certificate| get_certificate_info(certificate.as_ref()).ok())
        .flat_map(|certificate| certificate.subject_alt_names)
        .filter_map(|name| name.strip_prefix("URI:").map(str::to_owned))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn security() -> FlowGrpcSecurity {
        FlowGrpcSecurity {
            service_token: b"0123456789abcdef0123456789abcdef".to_vec(),
            workload_policy: WorkloadIdentityPolicy::new(BTreeMap::from([
                (
                    START_VERIFICATION_METHOD.into(),
                    BTreeSet::from([AUTH_WORKLOAD_IDENTITY.into()]),
                ),
                (
                    APPLICATION_APPROVED_METHOD.into(),
                    BTreeSet::from([APPLICANT_WORKLOAD_IDENTITY.into()]),
                ),
            ]))
            .unwrap(),
            server_tls: GrpcServerTlsMaterial::new(
                b"-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----".to_vec(),
                b"-----BEGIN CERTIFICATE-----\nserver\n-----END CERTIFICATE-----".to_vec(),
                b"-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----".to_vec(),
            )
            .unwrap(),
        }
    }

    #[test]
    fn sensitive_methods_require_the_exact_workload_identity() {
        let security = security();
        assert!(security
            .authorize_evidence(START_VERIFICATION_METHOD, [AUTH_WORKLOAD_IDENTITY])
            .is_ok());
        assert_eq!(
            security
                .authorize_evidence(START_VERIFICATION_METHOD, [])
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            security
                .authorize_evidence(START_VERIFICATION_METHOD, [APPLICANT_WORKLOAD_IDENTITY])
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert!(security
            .authorize_evidence(APPLICATION_APPROVED_METHOD, [APPLICANT_WORKLOAD_IDENTITY])
            .is_ok());
    }

    #[test]
    fn service_token_cannot_replace_certificate_identity() {
        let security = security();
        let mut valid = Request::new(());
        valid.metadata_mut().insert(
            "x-service-token",
            "0123456789abcdef0123456789abcdef".parse().unwrap(),
        );
        assert!(security.authenticate_service(&valid).is_ok());
        assert_eq!(
            security
                .authorize_workload(&valid, START_VERIFICATION_METHOD)
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );

        let mut invalid = Request::new(());
        invalid
            .metadata_mut()
            .insert("x-service-token", "wrong".parse().unwrap());
        assert_eq!(
            security.authenticate_service(&invalid).unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
    }
}
