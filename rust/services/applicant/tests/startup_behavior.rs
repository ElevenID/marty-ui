use marty_applicant::select_issuance_service_url;

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
