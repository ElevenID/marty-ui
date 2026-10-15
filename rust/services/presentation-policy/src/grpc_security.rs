use std::collections::{BTreeMap, BTreeSet};

use marty_crypto::certificate::get_certificate_info;
use mmf_platform::{KeylessGrpcTlsAcceptor, OpenBaoTlsIdentityFiles};
use mmf_security::{WorkloadAuthorizationDecision, WorkloadIdentityPolicy};
use thiserror::Error;
use tonic::{
    transport::server::{TcpConnectInfo, TlsConnectInfo},
    Request, Status,
};

use crate::{PresentationPolicyServiceConfig, WorkloadServerTlsFiles};

pub const GET_POLICY_METHOD: &str =
    "/marty.ui.presentation_policy.v1.PresentationPolicyService/GetPolicy";
pub const EVALUATE_PRESENTATION_METHOD: &str =
    "/marty.ui.presentation_policy.v1.PresentationPolicyService/EvaluatePresentation";
pub const FLOW_WORKLOAD_IDENTITY: &str = "spiffe://marty.internal/service/flow";
pub const VERIFICATION_WORKLOAD_IDENTITY: &str = "spiffe://marty.internal/service/verification";

#[derive(Debug, Error)]
pub enum PresentationGrpcSecurityError {
    #[error("PRESENTATION_POLICY.GRPC_SECURITY_CONFIGURATION: {0}")]
    Configuration(String),
    #[error("PRESENTATION_POLICY.GRPC_TLS_CONFIGURATION: {0}")]
    Tls(#[from] mmf_platform::PlatformError),
    #[error("PRESENTATION_POLICY.GRPC_WORKLOAD_POLICY: {0}")]
    Policy(#[from] mmf_security::SecurityError),
}

pub struct PresentationGrpcSecurity {
    workload_policy: WorkloadIdentityPolicy,
    server_tls: Option<WorkloadServerTlsFiles>,
}

impl PresentationGrpcSecurity {
    pub fn from_config(
        config: &PresentationPolicyServiceConfig,
    ) -> Result<Self, PresentationGrpcSecurityError> {
        let server_tls = config.workload_server_tls.clone();
        if config.environment.is_deployed() && server_tls.is_none() {
            return Err(PresentationGrpcSecurityError::Configuration(
                "workload server TLS is missing".into(),
            ));
        }
        let allowed = BTreeSet::from([
            FLOW_WORKLOAD_IDENTITY.into(),
            VERIFICATION_WORKLOAD_IDENTITY.into(),
        ]);
        let workload_policy = WorkloadIdentityPolicy::new(BTreeMap::from([
            (GET_POLICY_METHOD.into(), allowed.clone()),
            (EVALUATE_PRESENTATION_METHOD.into(), allowed),
        ]))?;
        Ok(Self {
            workload_policy,
            server_tls,
        })
    }

    pub async fn server_tls_acceptor(
        &self,
    ) -> Result<Option<KeylessGrpcTlsAcceptor>, PresentationGrpcSecurityError> {
        let Some(files) = &self.server_tls else {
            return Ok(None);
        };
        let acceptor = OpenBaoTlsIdentityFiles {
            certificate_chain_file: files.certificate.clone(),
            kms_ca_cert_file: files.kms_ca_certificate.clone(),
            kms_endpoint: files.kms_endpoint.clone(),
            kms_token_file: files.kms_token_file.clone(),
            kms_key_name: files.kms_key_name.clone(),
            kms_key_version: files.kms_key_version,
            request_timeout: std::time::Duration::from_secs(10),
            max_concurrent_signs: 64,
        }
        .grpc_acceptor(
            &files.ca_certificate,
            64,
            std::time::Duration::from_secs(15),
        )
        .await?;
        Ok(Some(acceptor))
    }

    pub fn authorize<T>(&self, request: &Request<T>, method: &str) -> Result<(), Status> {
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

    fn security() -> PresentationGrpcSecurity {
        PresentationGrpcSecurity {
            workload_policy: WorkloadIdentityPolicy::new(BTreeMap::from([
                (
                    GET_POLICY_METHOD.into(),
                    BTreeSet::from([
                        FLOW_WORKLOAD_IDENTITY.into(),
                        VERIFICATION_WORKLOAD_IDENTITY.into(),
                    ]),
                ),
                (
                    EVALUATE_PRESENTATION_METHOD.into(),
                    BTreeSet::from([
                        FLOW_WORKLOAD_IDENTITY.into(),
                        VERIFICATION_WORKLOAD_IDENTITY.into(),
                    ]),
                ),
            ]))
            .unwrap(),
            server_tls: None,
        }
    }

    #[test]
    fn sensitive_methods_require_exact_workload_identity() {
        let security = security();
        assert!(security
            .authorize_evidence(GET_POLICY_METHOD, [FLOW_WORKLOAD_IDENTITY])
            .is_ok());
        assert!(security
            .authorize_evidence(
                EVALUATE_PRESENTATION_METHOD,
                [VERIFICATION_WORKLOAD_IDENTITY]
            )
            .is_ok());
        assert_eq!(
            security
                .authorize_evidence(GET_POLICY_METHOD, [])
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            security
                .authorize_evidence(GET_POLICY_METHOD, ["spiffe://marty.internal/service/auth"])
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
    }
}
