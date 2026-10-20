use marty_presentation_policy::PresentationPolicyServiceConfig;

#[test]
fn issuer_resolution_requires_explicit_deployment_routes() {
    let base = [(
        "DATABASE_URL".to_owned(),
        "postgres://localhost/test".to_owned(),
    )];
    let config = PresentationPolicyServiceConfig::from_values(base.clone()).unwrap();
    assert!(config.did_resolution_base_urls.is_empty());
    assert!(config.did_web_allowed_hosts.is_empty());
    for route in [
        "http://user:password@gateway:8000",
        "http://gateway:8000/?credential=secret",
        "file:///tmp/did.json",
    ] {
        let values = base
            .clone()
            .into_iter()
            .chain([("DID_RESOLUTION_BASE_URL".into(), route.into())]);
        assert!(PresentationPolicyServiceConfig::from_values(values).is_err());
    }
    let values = base.into_iter().chain([
        (
            "DID_RESOLUTION_BASE_URL".into(),
            "http://gateway:8000".into(),
        ),
        ("DID_WEB_ALLOWED_HOSTS".into(), "issuer.example".into()),
    ]);
    let config = PresentationPolicyServiceConfig::from_values(values).unwrap();
    assert_eq!(config.did_resolution_base_urls, ["http://gateway:8000"]);
    assert_eq!(config.did_web_allowed_hosts, ["issuer.example"]);
}
