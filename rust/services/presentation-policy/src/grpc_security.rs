use std::collections::{BTreeMap, BTreeSet};

use marty_crypto::certificate::get_certificate_info;
use mmf_platform::KeylessGrpcTlsAcceptor;
use mmf_security::WorkloadIdentityPolicy;
use thiserror::Error;
use tonic::{Request, Status};

use crate::{PresentationPolicyServiceConfig, WorkloadServerTlsFiles};

pub const GET_POLICY_METHOD: &str =
    "/marty.ui.presentation_policy.v1.PresentationPolicyService/GetPolicy";
pub const EVALUATE_PRESENTATION_METHOD: &str =
    "/marty.ui.presentation_policy.v1.PresentationPolicyService/EvaluatePresentation";
pub const FLOW_WORKLOAD_IDENTITY: &str = "spiffe://marty.internal/service/flow";
pub const VERIFICATION_WORKLOAD_IDENTITY: &str = "spiffe://marty.internal/service/verification";
pub const DELEGATED_USE_WORKLOAD_IDENTITY: &str = "spiffe://marty.internal/service/delegated-use";

fn workload_policy() -> Result<WorkloadIdentityPolicy, mmf_security::SecurityError> {
    let evaluators = BTreeSet::from([
        FLOW_WORKLOAD_IDENTITY.into(),
        VERIFICATION_WORKLOAD_IDENTITY.into(),
    ]);
    let mut readers = evaluators.clone();
    // The delegated-use host reads the selected policy revision for its own
    // machine/delegation evaluation; it cannot call presentation evaluation.
    readers.insert(DELEGATED_USE_WORKLOAD_IDENTITY.into());
    WorkloadIdentityPolicy::new(BTreeMap::from([
        (GET_POLICY_METHOD.into(), readers),
        (EVALUATE_PRESENTATION_METHOD.into(), evaluators),
    ]))
}

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
        Ok(Self {
            workload_policy: workload_policy()?,
            server_tls,
        })
    }

    pub async fn server_tls_acceptor(
        &self,
    ) -> Result<Option<KeylessGrpcTlsAcceptor>, PresentationGrpcSecurityError> {
        Ok(marty_service_runtime::workload_server_acceptor(
            self.server_tls.as_ref(),
            64,
            std::time::Duration::from_secs(15),
        )
        .await?)
    }

    pub fn authorize<T>(&self, request: &Request<T>, method: &str) -> Result<(), Status> {
        // Only the authenticated leaf represents the caller. A CA certificate
        // may carry its own URI SAN, which is neither caller authority nor an
        // additional identity of the leaf.
        let identities = request.peer_certs().map_or_else(BTreeSet::new, |chain| {
            leaf_uri_sans(chain.iter().map(|certificate| certificate.as_ref()))
        });
        self.authorize_evidence(method, identities.iter().map(String::as_str))
    }

    fn authorize_evidence<'a>(
        &self,
        method: &str,
        identities: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), Status> {
        let identities = identities.into_iter().collect::<BTreeSet<_>>();
        if identities.len() > 1 {
            return Err(Status::permission_denied(
                "exactly one authenticated workload identity is required",
            ));
        }
        marty_service_runtime::workload::authorize_evidence(
            &self.workload_policy,
            method,
            identities,
        )
    }
}

fn leaf_uri_sans<'a>(chain: impl IntoIterator<Item = &'a [u8]>) -> BTreeSet<String> {
    chain
        .into_iter()
        .next()
        .and_then(|leaf| get_certificate_info(leaf).ok())
        .into_iter()
        .flat_map(|certificate| certificate.subject_alt_names)
        .filter_map(|name| name.strip_prefix("URI:").map(str::to_owned))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn security() -> PresentationGrpcSecurity {
        let config = PresentationPolicyServiceConfig::from_values([
            ("ENVIRONMENT".into(), "test".into()),
            (
                "DATABASE_URL".into(),
                "postgres://localhost/presentation_policy_security_test".into(),
            ),
        ])
        .unwrap();
        PresentationGrpcSecurity::from_config(&config).unwrap()
    }

    #[test]
    fn sensitive_methods_require_exact_workload_identity() {
        let security = security();
        for identity in [FLOW_WORKLOAD_IDENTITY, VERIFICATION_WORKLOAD_IDENTITY] {
            for method in [GET_POLICY_METHOD, EVALUATE_PRESENTATION_METHOD] {
                assert!(security.authorize_evidence(method, [identity]).is_ok());
            }
        }
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

    #[test]
    fn delegated_use_can_read_policy_but_cannot_evaluate_or_call_unknown_methods() {
        let security = security();
        assert!(security
            .authorize_evidence(GET_POLICY_METHOD, [DELEGATED_USE_WORKLOAD_IDENTITY])
            .is_ok());
        for method in [
            EVALUATE_PRESENTATION_METHOD,
            "/marty.ui.presentation_policy.v1.PresentationPolicyService/CreatePolicy",
            "/marty.ui.presentation_policy.v1.PresentationPolicyService/Unknown",
        ] {
            assert_eq!(
                security
                    .authorize_evidence(method, [DELEGATED_USE_WORKLOAD_IDENTITY])
                    .unwrap_err()
                    .code(),
                tonic::Code::PermissionDenied
            );
        }
    }

    #[test]
    fn delegated_use_read_rejects_absent_ambiguous_or_spoofed_workload_identity() {
        let security = security();
        assert_eq!(
            security
                .authorize_evidence(GET_POLICY_METHOD, [])
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        for identities in [
            vec![DELEGATED_USE_WORKLOAD_IDENTITY, FLOW_WORKLOAD_IDENTITY],
            vec![
                DELEGATED_USE_WORKLOAD_IDENTITY,
                "spiffe://marty.internal/service/untrusted",
            ],
            vec!["spiffe://marty.internal/service/delegated-use-admin"],
        ] {
            assert_eq!(
                security
                    .authorize_evidence(GET_POLICY_METHOD, identities)
                    .unwrap_err()
                    .code(),
                tonic::Code::PermissionDenied
            );
        }
        let mut request = Request::new(());
        request.metadata_mut().insert(
            "x-workload-identity",
            DELEGATED_USE_WORKLOAD_IDENTITY.parse().unwrap(),
        );
        assert_eq!(
            security
                .authorize(&request, GET_POLICY_METHOD)
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
    }

    #[test]
    fn a_ca_uri_does_not_add_evaluation_authority_to_the_authenticated_leaf() {
        // Public parsing fixtures only; their private keys are not retained.
        let leaf = marty_crypto::certificate::load_certificate_pem(include_str!(
            "../tests/fixtures/workload_identity_leaf.pem"
        ))
        .unwrap();
        let ca = marty_crypto::certificate::load_certificate_pem(include_str!(
            "../tests/fixtures/workload_identity_ca.pem"
        ))
        .unwrap();
        let identities = leaf_uri_sans([leaf.as_slice(), ca.as_slice()]);
        assert_eq!(
            identities,
            BTreeSet::from([DELEGATED_USE_WORKLOAD_IDENTITY.to_owned()])
        );
        let security = security();
        assert!(security
            .authorize_evidence(GET_POLICY_METHOD, identities.iter().map(String::as_str))
            .is_ok());
        assert_eq!(
            security
                .authorize_evidence(
                    EVALUATE_PRESENTATION_METHOD,
                    identities.iter().map(String::as_str)
                )
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        for identities in [
            leaf_uri_sans([b"invalid certificate".as_slice(), ca.as_slice()]),
            leaf_uri_sans([b"".as_slice(), ca.as_slice()]),
            leaf_uri_sans(std::iter::empty()),
        ] {
            assert!(identities.is_empty());
            assert_eq!(
                security
                    .authorize_evidence(GET_POLICY_METHOD, identities.iter().map(String::as_str))
                    .unwrap_err()
                    .code(),
                tonic::Code::Unauthenticated
            );
        }
    }
}
