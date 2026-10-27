//! Shared Tonic boundary for Marty workload identity policy.
use marty_crypto::certificate::get_certificate_info;
use mmf_security::{WorkloadAuthorizationDecision, WorkloadIdentityPolicy};
use std::collections::BTreeSet;
use tonic::{
    transport::server::{TcpConnectInfo, TlsConnectInfo},
    Request, Status,
};

/// Read identities only from the TLS transport, never caller metadata.
pub fn peer_uri_sans<T>(request: &Request<T>) -> BTreeSet<String> {
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

pub fn authorize_evidence<'a>(
    policy: &WorkloadIdentityPolicy,
    method: &str,
    identities: impl IntoIterator<Item = &'a str>,
) -> Result<(), Status> {
    match policy.authorize(method, identities) {
        WorkloadAuthorizationDecision::Allow => Ok(()),
        WorkloadAuthorizationDecision::Unauthenticated => Err(Status::unauthenticated(
            "a mutually authenticated workload identity is required",
        )),
        WorkloadAuthorizationDecision::Forbidden => Err(Status::permission_denied(
            "the authenticated workload is not authorized for this RPC",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    #[test]
    fn missing_transport_cannot_be_replaced_by_caller_metadata() {
        let mut request = Request::new(());
        request.metadata_mut().insert(
            "x-workload-identity",
            "spiffe://marty.internal/service/auth".parse().unwrap(),
        );
        assert!(peer_uri_sans(&request).is_empty());
    }
    #[test]
    fn exact_method_and_identity_policy_preserve_statuses() {
        let policy = WorkloadIdentityPolicy::new(BTreeMap::from([(
            "/test.Service/Call".into(),
            BTreeSet::from(["spiffe://marty.internal/service/auth".into()]),
        )]))
        .unwrap();
        assert_eq!(
            authorize_evidence(&policy, "/test.Service/Call", [])
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        assert!(authorize_evidence(
            &policy,
            "/test.Service/Call",
            ["spiffe://marty.internal/service/auth"]
        )
        .is_ok());
        for (method, identity) in [
            (
                "/test.Service/Other",
                "spiffe://marty.internal/service/auth",
            ),
            (
                "/test.Service/Call",
                "spiffe://marty.internal/service/other",
            ),
        ] {
            assert_eq!(
                authorize_evidence(&policy, method, [identity])
                    .unwrap_err()
                    .code(),
                tonic::Code::PermissionDenied
            );
        }
    }
}
