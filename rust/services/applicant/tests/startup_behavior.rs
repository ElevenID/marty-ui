use marty_applicant::{reject_unused_workload_tls, select_issuance_service_url};

#[test]
fn unused_workload_tls_settings_fail_closed() {
    assert!(reject_unused_workload_tls(["APPLICANT_SERVICE_PORT".into()]).is_ok());
    for name in [
        "GRPC_WORKLOAD_TLS_CLIENT_KEY",
        "GRPC_WORKLOAD_TLS_CLIENT_CERT",
    ] {
        assert!(reject_unused_workload_tls([name.into()]).is_err());
    }
}

#[test]
fn issuance_http_owner_prefers_native_and_preserves_legacy_production() {
    assert_eq!(
        select_issuance_service_url(
            Some("http://issuance-native:8005".into()),
            Some("http://issuance:8005".into()),
        ),
        "http://issuance-native:8005"
    );
    assert_eq!(
        select_issuance_service_url(None, Some("http://issuance:8005".into())),
        "http://issuance:8005"
    );
    assert_eq!(
        select_issuance_service_url(Some("  ".into()), Some("http://issuance:8005".into()),),
        "http://issuance:8005"
    );
}
