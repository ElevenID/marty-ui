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

#[test]
fn signing_registry_configuration_is_optional_but_rejects_invalid_credentials_and_routes() {
    let base = [(
        "DATABASE_URL".to_owned(),
        "postgres://localhost/test".to_owned(),
    )];
    let config = PresentationPolicyServiceConfig::from_values(base.clone()).unwrap();
    assert!(config.signing_registry_api_key.is_none());
    for (name, value) in [
        ("SIGNING_KEYS_INTERNAL_API_KEY", "short"),
        (
            "SIGNING_KEYS_SERVICE_URL",
            "https://user:password@registry.example",
        ),
        (
            "SIGNING_KEYS_SERVICE_URL",
            "https://registry.example?credential=secret",
        ),
    ] {
        assert!(PresentationPolicyServiceConfig::from_values(
            base.clone()
                .into_iter()
                .chain([(name.into(), value.into())])
        )
        .is_err());
    }
    let config = PresentationPolicyServiceConfig::from_values(base.into_iter().chain([
        (
            "SIGNING_KEYS_SERVICE_URL".into(),
            "http://signing-registry:8017".into(),
        ),
        ("SIGNING_KEYS_INTERNAL_API_KEY".into(), "a".repeat(32)),
    ]))
    .unwrap();
    assert_eq!(config.signing_registry_url, "http://signing-registry:8017");
    assert!(config.signing_registry_api_key.is_some());
}

#[test]
fn signing_registry_secret_files_load_without_global_environment_mutation() {
    let path = std::env::temp_dir().join(format!("marty-registry-secret-{}", uuid::Uuid::new_v4()));
    let base = [(
        "DATABASE_URL".to_owned(),
        "postgres://localhost/test".to_owned(),
    )];
    std::fs::write(&path, "test-registry-credential\n").unwrap();
    let file = (
        "SIGNING_KEYS_INTERNAL_API_KEY_FILE".to_owned(),
        path.to_string_lossy().into_owned(),
    );
    let config = PresentationPolicyServiceConfig::from_values(
        base.clone().into_iter().chain([file.clone()]),
    )
    .unwrap();
    assert_eq!(
        config.signing_registry_api_key.as_deref(),
        Some("test-registry-credential")
    );
    std::fs::write(&path, "\n").unwrap();
    assert!(PresentationPolicyServiceConfig::from_values(
        base.clone().into_iter().chain([file.clone()])
    )
    .is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(PresentationPolicyServiceConfig::from_values(
        base.clone().into_iter().chain([file.clone()])
    )
    .is_err());
    let config = PresentationPolicyServiceConfig::from_values(base.into_iter().chain([
        file,
        (
            "SIGNING_KEYS_INTERNAL_API_KEY".into(),
            "explicit-registry-credential".into(),
        ),
    ]))
    .unwrap();
    assert_eq!(
        config.signing_registry_api_key.as_deref(),
        Some("explicit-registry-credential")
    );
}
