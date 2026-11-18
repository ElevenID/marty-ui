use std::collections::BTreeMap;

use marty_flow::{
    APPLICANT_WORKLOAD_IDENTITY, APPLICATION_APPROVED_METHOD, AUTH_WORKLOAD_IDENTITY,
    START_VERIFICATION_METHOD,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    service_token_header: String,
    service_token_comparison: String,
    identity_source: String,
    bearer_identity_allowed: bool,
    sensitive_methods: BTreeMap<String, Vec<String>>,
    missing_service_token_status: String,
    missing_certificate_identity_status: String,
    wrong_certificate_identity_status: String,
    server_transport: String,
    client_certificate_required: bool,
    failure_behavior: String,
}

#[test]
fn flow_grpc_security_matches_language_neutral_contract() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/flow-grpc-security-behavior.json"
    ))
    .expect("gRPC security contract");
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.service_token_header, "x-service-token");
    assert_eq!(contract.service_token_comparison, "constant_time");
    assert_eq!(contract.identity_source, "mutual_tls_certificate_uri_san");
    assert!(!contract.bearer_identity_allowed);
    assert_eq!(
        contract.sensitive_methods,
        BTreeMap::from([
            (
                START_VERIFICATION_METHOD.into(),
                vec![AUTH_WORKLOAD_IDENTITY.into()],
            ),
            (
                APPLICATION_APPROVED_METHOD.into(),
                vec![APPLICANT_WORKLOAD_IDENTITY.into()],
            ),
        ])
    );
    assert_eq!(contract.missing_service_token_status, "unauthenticated");
    assert_eq!(
        contract.missing_certificate_identity_status,
        "unauthenticated"
    );
    assert_eq!(
        contract.wrong_certificate_identity_status,
        "permission_denied"
    );
    assert_eq!(contract.server_transport, "mutual_tls");
    assert!(contract.client_certificate_required);
    assert_eq!(contract.failure_behavior, "fail_closed");
}
