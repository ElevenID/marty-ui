use std::collections::{BTreeMap, BTreeSet};

use marty_service_runtime::workload::peer_uri_sans;
use mmf_platform::KeylessGrpcTlsAcceptor;
use mmf_security::{constant_time_secret_eq, WorkloadIdentityPolicy};
use thiserror::Error;
use tonic::{Request, Status};

use crate::{FlowServiceConfig, WorkloadServerTlsFiles};

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
    service_token: Option<Vec<u8>>,
    workload_policy: WorkloadIdentityPolicy,
    server_tls: Option<WorkloadServerTlsFiles>,
}

impl FlowGrpcSecurity {
    pub fn from_config(config: &FlowServiceConfig) -> Result<Self, FlowGrpcSecurityError> {
        let service_token = config
            .service_token
            .as_deref()
            .map(|value| value.as_bytes().to_vec());
        if config.environment.is_deployed() && service_token.is_none() {
            return Err(FlowGrpcSecurityError::Configuration(
                "service token is missing".into(),
            ));
        }
        let server_tls = config.workload_server_tls.clone();
        if config.environment.is_deployed() && server_tls.is_none() {
            return Err(FlowGrpcSecurityError::Configuration(
                "workload server TLS is missing".into(),
            ));
        }
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

    pub async fn server_tls_acceptor(
        &self,
    ) -> Result<Option<KeylessGrpcTlsAcceptor>, FlowGrpcSecurityError> {
        let Some(files) = &self.server_tls else {
            return Ok(None);
        };
        let acceptor = files
            .identity
            .grpc_acceptor(
                &files.ca_certificate,
                64,
                std::time::Duration::from_secs(15),
            )
            .await?;
        Ok(Some(acceptor))
    }

    pub fn authenticate_service<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let Some(expected) = self.service_token.as_deref() else {
            return Ok(());
        };
        let candidate = request
            .metadata()
            .get("x-service-token")
            .and_then(|value| value.to_str().ok())
            .map(str::as_bytes)
            .unwrap_or_default();
        if constant_time_secret_eq(expected, candidate) {
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
        marty_service_runtime::workload::authorize_evidence(
            &self.workload_policy,
            method,
            identities,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn security() -> FlowGrpcSecurity {
        FlowGrpcSecurity {
            service_token: Some(b"0123456789abcdef0123456789abcdef".to_vec()),
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
            server_tls: None,
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

    #[test]
    fn development_can_bind_plaintext_but_sensitive_methods_still_require_mtls() {
        let config = FlowServiceConfig::from_values([
            ("ENVIRONMENT".into(), "development".into()),
            ("DATABASE_URL".into(), "postgresql://db/flow".into()),
            ("REDIS_URL".into(), "redis://redis".into()),
        ])
        .unwrap();
        let security = FlowGrpcSecurity::from_config(&config).unwrap();
        assert!(security.server_tls.is_none());
        assert!(security.authenticate_service(&Request::new(())).is_ok());
        assert_eq!(
            security
                .authorize_workload(&Request::new(()), START_VERIFICATION_METHOD)
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }
}
