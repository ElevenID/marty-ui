use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;

fn values() -> BTreeMap<String, String> {
    let mut values = BTreeMap::from([
        (ENABLED.into(), "true".into()),
        (
            "DELEGATED_USE_ORGANIZATION_ID".into(),
            "11111111-1111-4111-8111-111111111111".into(),
        ),
        (
            "DELEGATED_USE_DEPLOYMENT_PROFILE_ID".into(),
            "22222222-2222-4222-8222-222222222222".into(),
        ),
        (
            "DELEGATED_USE_DELEGATION_POLICY_ID".into(),
            "33333333-3333-4333-8333-333333333333".into(),
        ),
        (
            "DELEGATED_USE_APPROVAL_PROFILE".into(),
            "urn:marty:approval:organization:v1".into(),
        ),
        ("DELEGATED_USE_APPROVAL_VERSION".into(), "1.0.0".into()),
        (
            "DELEGATED_USE_APPROVAL_ARTIFACT_DIGEST".into(),
            format!("sha256:{}", "a".repeat(64)),
        ),
        (
            "DELEGATED_USE_STATUS_REF".into(),
            "https://issuer.example.invalid/delegations/status".into(),
        ),
        (
            "DELEGATED_USE_FLOW_DEFINITION_ID".into(),
            "selected-verification".into(),
        ),
        ("DELEGATED_USE_FLOW_DEFINITION_VERSION".into(), "1".into()),
        (
            "DELEGATED_USE_PUBLIC_BASE_URL".into(),
            "https://verifier.example.invalid".into(),
        ),
        (
            "DELEGATED_USE_VERIFIER_DID".into(),
            "did:web:verifier.example.invalid".into(),
        ),
        (
            "DELEGATED_USE_VERIFIER_DISPLAY_NAME".into(),
            "Internal verifier".into(),
        ),
        (
            "DELEGATED_USE_CREDENTIAL_TEMPLATE_GRPC_TARGET".into(),
            "https://template.example.invalid:9005".into(),
        ),
        (
            "DELEGATED_USE_PRESENTATION_POLICY_GRPC_TARGET".into(),
            "https://policy.example.invalid:9006".into(),
        ),
        (
            "DELEGATED_USE_ISSUANCE_NATIVE_URL".into(),
            "https://issuance.example.invalid".into(),
        ),
        (
            "DELEGATED_USE_CREDENTIAL_TEMPLATE_URL".into(),
            "https://template.example.invalid".into(),
        ),
        (
            "DELEGATED_USE_TRUST_PROFILE_URL".into(),
            "https://trust.example.invalid".into(),
        ),
        (
            "DELEGATED_USE_DEPLOYMENT_PROFILE_URL".into(),
            "https://deployment.example.invalid".into(),
        ),
        (
            "DELEGATED_USE_REQUEST_SIGNING_ORIGIN".into(),
            "https://signing.example.invalid".into(),
        ),
        (
            "DELEGATED_USE_REQUEST_GRANT_OPENBAO_ORIGIN".into(),
            "https://bao.example.invalid".into(),
        ),
        (
            "DELEGATED_USE_REQUEST_MINT_TOKEN_FILE".into(),
            "/fixture/request-mint.token".into(),
        ),
        (
            "DELEGATED_USE_RECEIPT_SIGNING_ORIGIN".into(),
            "https://signing.example.invalid".into(),
        ),
        (
            "DELEGATED_USE_RECEIPT_GRANT_OPENBAO_ORIGIN".into(),
            "https://bao.example.invalid".into(),
        ),
        (
            "DELEGATED_USE_RECEIPT_MINT_TOKEN_FILE".into(),
            "/fixture/receipt-mint.token".into(),
        ),
        (
            "DELEGATED_USE_RECEIPT_ISSUER_DID".into(),
            "did:web:receipt.example.invalid".into(),
        ),
        ("DELEGATED_USE_RECEIPT_ALGORITHM".into(), "EdDSA".into()),
        (
            "DELEGATED_USE_RECEIPT_KEY_ID".into(),
            "did:web:receipt.example.invalid#receipt-only".into(),
        ),
        (
            "DELEGATED_USE_RECEIPT_KEY_REFERENCE".into(),
            "receipt-only-key".into(),
        ),
        (
            "DELEGATED_USE_WORKLOAD_TLS_CA_CERT_FILE".into(),
            "/fixture/peer-ca.pem".into(),
        ),
        (
            "DELEGATED_USE_CLIENT_CA_FILES".into(),
            r#"["/fixture/client-ca.der"]"#.into(),
        ),
        (
            "DELEGATED_USE_WORKLOAD_BINDINGS".into(),
            json!([{
                "workload_uri":"spiffe://internal.example.invalid/machine/one",
                "leaf_sha256":format!("sha256:{}", "b".repeat(64)),
                "principal_id":"urn:marty:machine:one"
            }])
            .to_string(),
        ),
    ]);
    for (index, name) in DATABASE_NAMES.iter().enumerate() {
        values.insert((*name).into(), format!("postgresql://role_{index}:never-log-database-password@127.0.0.1:5432/qualification"));
    }
    for (index, name) in CREDENTIAL_NAMES.iter().enumerate() {
        values.insert(
            (*name).into(),
            format!("never-log-credential-{index}-{}", "x".repeat(32)),
        );
    }
    for prefix in ["DELEGATED_USE_TLS", "DELEGATED_USE_WORKLOAD_TLS"] {
        for (suffix, value) in [
            ("CERT_FILE", "/fixture/chain.pem"),
            ("KMS_PROVIDER", "openbao-transit"),
            ("KMS_ADDR", "https://bao.example.invalid"),
            ("KMS_CA_CERT_FILE", "/fixture/bao-ca.pem"),
            ("KMS_TOKEN_FILE", "/fixture/tls.token"),
            ("KMS_KEY_NAME", "delegated-use-tls"),
            ("KMS_KEY_VERSION", "1"),
        ] {
            values.insert(format!("{prefix}_{suffix}"), value.into());
        }
    }
    let key = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
    values.insert(
        "DELEGATED_USE_RECEIPT_PUBLIC_JWK".into(),
        json!({
            "kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())
        })
        .to_string(),
    );
    values
}
fn parse(values: BTreeMap<String, String>) -> Result<DelegatedUseHostConfig, HostConfigError> {
    DelegatedUseHostConfig::parse(values, |path, maximum| {
        assert_eq!(path, Path::new("/fixture/client-ca.der"));
        assert_eq!(maximum, 65_536);
        // Configuration validates bounded CA bytes; the listener independently
        // parses actual certificates before binding. No TLS fixture is implied.
        Ok(vec![0x30, 1, 0])
    })
}

#[test]
fn disabled_exits_before_any_file_or_secret_resolution() {
    for enabled in [None, Some("false"), Some("TRUE"), Some(" true"), Some("1")] {
        let mut values = values();
        values.remove(ENABLED);
        if let Some(enabled) = enabled {
            values.insert(ENABLED.into(), enabled.into());
        }
        values.insert(
            format!("{}_FILE", DATABASE_NAMES[0]),
            "/must-not-read-secret".into(),
        );
        values.insert("DELEGATED_USE_FALLBACK_HTTP".into(), "true".into());
        let result =
            DelegatedUseHostConfig::parse(values, |_, _| panic!("disabled host read a file"));
        assert_eq!(
            result.unwrap_err(),
            if matches!(enabled, None | Some("false")) {
                HostConfigError::Disabled
            } else {
                HostConfigError::Invalid(ENABLED)
            }
        );
    }
}

#[test]
fn accepts_each_supported_role_pool_limit() {
    for maximum in 1..=4 {
        let mut input = values();
        input.insert(
            "DELEGATED_USE_POOL_MAX_CONNECTIONS".into(),
            maximum.to_string(),
        );
        assert_eq!(parse(input).unwrap().pool_max_connections, maximum);
    }
}

#[test]
fn optional_health_listener_is_loopback_only_and_separate_from_mutual_tls() {
    for raw in ["127.0.0.1:8022", "[::1]:8022"] {
        let mut input = values();
        input.insert("DELEGATED_USE_HEALTH_ADDR".into(), raw.into());
        assert_eq!(
            parse(input).unwrap().health_addr,
            Some(raw.parse().unwrap())
        );
    }
    for raw in [
        "",
        " 127.0.0.1:8022",
        "127.0.0.1:8022\n",
        "127.0.0.1:0",
        "127.0.0.1:8021",
        "[::1]:8021",
        "0.0.0.0:8022",
        "[::]:8022",
        "192.0.2.1:8022",
        "[2001:db8::1]:8022",
        "health:8022",
    ] {
        let mut input = values();
        input.insert("DELEGATED_USE_HEALTH_ADDR".into(), raw.into());
        assert_eq!(
            parse(input).unwrap_err(),
            HostConfigError::Invalid("DELEGATED_USE_HEALTH_ADDR")
        );
    }
    let mut input = values();
    input.insert("DELEGATED_USE_LISTEN_ADDR".into(), "0.0.0.0:8022".into());
    input.insert("DELEGATED_USE_HEALTH_ADDR".into(), "127.0.0.1:8022".into());
    assert_eq!(
        parse(input).unwrap_err(),
        HostConfigError::Invalid("DELEGATED_USE_HEALTH_ADDR")
    );
}

#[test]
fn valid_configuration_uses_selected_profiles_and_redacts_credentials() {
    let input = values();
    let config = parse(input.clone()).unwrap();
    assert_eq!(config.listen_addr.to_string(), "127.0.0.1:8021");
    assert_eq!(config.health_addr, None);
    assert_eq!(config.pool_max_connections, 4);
    assert!(!config.public_caller_enabled);
    assert_eq!(
        config.flow_start.definition.organization_id,
        config.organization_id.to_string()
    );
    assert_eq!(
        config.flow_start.options.request_object,
        config.request_options
    );
    assert_eq!(config.flow_start.public_base_url, config.public_base_url);
    assert!(!config.flow_start.allow_http_loopback);
    assert!(!config.flow_start.options.haip_enabled);
    assert!(config.request_options.strict_client_metadata);
    assert_eq!(
        config.receipt_signing.issuer.principal_type,
        PrincipalType::Organization
    );
    let debug = format!(
        "{config:?} {:?} {:?} {:?}",
        config.database_urls, config.request_signing, config.receipt_signing
    );
    for name in DATABASE_NAMES.into_iter().chain(CREDENTIAL_NAMES) {
        assert!(!debug.contains(input.get(name).unwrap()));
    }
    assert!(!debug.contains("never-log"));
    assert!(!debug.contains("tls.token"));
}

#[test]
fn public_caller_routes_require_explicit_selection_and_canonical_origin() {
    for enabled in [None, Some("false"), Some("true")] {
        let mut input = values();
        if let Some(enabled) = enabled {
            input.insert("DELEGATED_USE_PUBLIC_CALLER_ENABLED".into(), enabled.into());
        }
        assert_eq!(
            parse(input).unwrap().public_caller_enabled,
            enabled == Some("true")
        );
    }
    for enabled in ["TRUE", "1", " true", "", "false "] {
        let mut input = values();
        input.insert("DELEGATED_USE_PUBLIC_CALLER_ENABLED".into(), enabled.into());
        assert_eq!(
            parse(input).unwrap_err(),
            HostConfigError::Invalid("DELEGATED_USE_PUBLIC_CALLER_ENABLED")
        );
    }
    for origin in [
        "https://verifier.example.invalid/prefix",
        "https://verifier.example.invalid/",
        "https://verifier.example.invalid:443",
        "https://VERIFIER.example.invalid",
        "https://verifier.example.invalid?caller=true",
        "https://user@verifier.example.invalid",
        "https://verifier.example.invalid#request",
        "http://verifier.example.invalid",
    ] {
        let mut input = values();
        input.insert("DELEGATED_USE_PUBLIC_CALLER_ENABLED".into(), "true".into());
        input.insert("DELEGATED_USE_PUBLIC_BASE_URL".into(), origin.into());
        assert_eq!(
            parse(input).unwrap_err(),
            HostConfigError::Invalid("DELEGATED_USE_PUBLIC_BASE_URL")
        );
    }
}

#[test]
fn unknown_duplicate_and_unsupported_mode_configuration_is_rejected() {
    for name in [
        "DELEGATED_USE_FALLBACK_HTTP",
        "DELEGATED_USE_ALLOW_ATTESTATION",
        "DELEGATED_USE_PUBLIC_ENABLED",
        "DELEGATED_USE_SERVICE_T0KEN",
    ] {
        let mut input = values();
        input.insert(name.into(), "true".into());
        assert_eq!(parse(input).unwrap_err(), HostConfigError::UnknownField);
    }
    let mut input: Vec<_> = values().into_iter().collect();
    input.push((
        "DELEGATED_USE_ORGANIZATION_ID".into(),
        Uuid::new_v4().to_string(),
    ));
    assert_eq!(
        DelegatedUseHostConfig::parse(input, |_, _| panic!("duplicate input read a file"))
            .unwrap_err(),
        HostConfigError::UnknownField
    );
}

#[test]
fn secrets_are_bounded_and_file_conflicts_do_not_read() {
    let mut input = values();
    input.insert(
        format!("{}_FILE", DATABASE_NAMES[0]),
        "/fixture/database.secret".into(),
    );
    assert_eq!(
        DelegatedUseHostConfig::parse(input, |_, _| panic!("conflicting secret read")).unwrap_err(),
        HostConfigError::File(DATABASE_NAMES[0])
    );
    for name in [DATABASE_NAMES[0], CREDENTIAL_NAMES[0]] {
        let mut input = values();
        input.insert(name.into(), "x".repeat(MAX_SECRET_BYTES + 1));
        assert_eq!(
            parse(input).unwrap_err(),
            HostConfigError::Invalid("configuration value size")
        );
    }
    let mut input = values();
    let original = input.remove(DATABASE_NAMES[0]).unwrap();
    input.insert(
        format!("{}_FILE", DATABASE_NAMES[0]),
        "/fixture/database.secret".into(),
    );
    let config = DelegatedUseHostConfig::parse(input, |path, maximum| {
        if path == Path::new("/fixture/database.secret") {
            assert_eq!(maximum, MAX_SECRET_BYTES + 2);
            Ok(format!("{original}\r\n").into_bytes())
        } else {
            Ok(vec![0x30, 1, 0])
        }
    })
    .unwrap();
    assert_eq!(config.database_urls.use_writer, original);
}

#[test]
fn scope_endpoints_and_lifetimes_are_closed_and_bounded() {
    for (name, value) in [
        (
            "DELEGATED_USE_ORGANIZATION_ID",
            "00000000-0000-0000-0000-000000000000",
        ),
        (
            "DELEGATED_USE_DEPLOYMENT_PROFILE_ID",
            "22222222-2222-4222-8222-22222222222A",
        ),
        ("DELEGATED_USE_DELEGATION_POLICY_ID", "../foreign"),
        ("DELEGATED_USE_POOL_MAX_CONNECTIONS", "0"),
        ("DELEGATED_USE_POOL_MAX_CONNECTIONS", "5"),
        ("DELEGATED_USE_LISTEN_ADDR", "127.0.0.1:0"),
        ("DELEGATED_USE_PUBLIC_BASE_URL", "http://127.0.0.1:8021"),
        (
            "DELEGATED_USE_PUBLIC_BASE_URL",
            "https://verifier.example.invalid/",
        ),
        (
            "DELEGATED_USE_STATUS_REF",
            "https://user:never-log@issuer.example.invalid/status",
        ),
        (
            "DELEGATED_USE_REQUEST_SIGNING_ORIGIN",
            "https://signing.example.invalid/alternate",
        ),
        (
            "DELEGATED_USE_PRESENTATION_POLICY_GRPC_TARGET",
            "http://localhost:9006",
        ),
        (
            "DELEGATED_USE_VERIFIER_DID",
            "did:web:verifier.example.invalid#key",
        ),
        ("DELEGATED_USE_VERIFIER_DID", "did:unsupported:verifier"),
        ("DELEGATED_USE_FLOW_DEFINITION_ID", "../verification"),
        ("DELEGATED_USE_FLOW_DEFINITION_VERSION", "01"),
        ("DELEGATED_USE_CHALLENGE_LIFETIME_SECONDS", "601"),
        ("DELEGATED_USE_RECEIPT_LIFETIME_SECONDS", "31"),
        ("DELEGATED_USE_AUTHORITY_VALIDITY_SECONDS", "16"),
        ("DELEGATED_USE_REQUEST_MINT_TOKEN_FILE", "relative.token"),
    ] {
        let mut input = values();
        input.insert(name.into(), value.into());
        assert!(parse(input).is_err(), "accepted {name}");
    }
    let mut input = values();
    input.insert(
        DATABASE_NAMES[0].into(),
        "postgresql://role:never-log@localhost/db?options=-c%20role%3Downer".into(),
    );
    let error = parse(input).unwrap_err();
    assert_eq!(error, HostConfigError::Invalid(DATABASE_NAMES[0]));
    assert!(!error.to_string().contains("never-log"));
}

#[test]
fn dedicated_credential_and_public_receipt_key_pins_cannot_be_replaced() {
    for (left, right) in [
        (DATABASE_NAMES[0], DATABASE_NAMES[1]),
        (CREDENTIAL_NAMES[0], CREDENTIAL_NAMES[3]),
        (CREDENTIAL_NAMES[2], CREDENTIAL_NAMES[3]),
    ] {
        let mut input = values();
        input.insert(right.into(), input[left].clone());
        assert!(parse(input).is_err());
    }
    let mut input = values();
    input.insert(
        CREDENTIAL_NAMES[5].into(),
        input[CREDENTIAL_NAMES[3]].clone(),
    );
    assert!(
        parse(input.clone()).is_ok(),
        "same Signing Keys origin uses its existing issuer credential"
    );
    input.insert(
        "DELEGATED_USE_RECEIPT_SIGNING_ORIGIN".into(),
        "https://another-signer.example.invalid".into(),
    );
    assert!(
        parse(input).is_err(),
        "a transport credential cannot cross configured origins"
    );
    let mut input = values();
    input.insert(
        "DELEGATED_USE_RECEIPT_MINT_TOKEN_FILE".into(),
        input["DELEGATED_USE_REQUEST_MINT_TOKEN_FILE"].clone(),
    );
    assert!(parse(input).is_err());
    for jwk in [
        r#"{"kty":"OKP","kty":"OKP","crv":"Ed25519","x":"value"}"#,
        r#"{"kty":"OKP","crv":"Ed25519","x":"value","d":"never-log-private"}"#,
        r#"{"kty":"OKP","crv":"Ed25519","x":"value","y":null}"#,
    ] {
        let mut input = values();
        input.insert("DELEGATED_USE_RECEIPT_PUBLIC_JWK".into(), jwk.into());
        assert!(parse(input).is_err());
    }
    let mut input = values();
    input.insert(
        "DELEGATED_USE_RECEIPT_KEY_ID".into(),
        "did:web:another.example.invalid#key".into(),
    );
    assert!(parse(input).is_err());
}

#[test]
fn workload_binding_json_refuses_ambiguity_and_identity_overrides() {
    let original = values()["DELEGATED_USE_WORKLOAD_BINDINGS"].clone();
    let mut binding: Value = serde_json::from_str(&original).unwrap();
    let duplicate = json!([binding[0].clone(), binding[0].clone()]).to_string();
    binding[0]["organization_id"] = json!(Uuid::new_v4());
    for document in [
        "[]".into(),
        duplicate,
        binding.to_string(),
        original.replace("spiffe://", "https://"),
        original.replace(
            "\"principal_id\":",
            "\"principal_id\":\"urn:attacker\",\"principal_id\":",
        ),
    ] {
        let mut input = values();
        input.insert("DELEGATED_USE_WORKLOAD_BINDINGS".into(), document);
        assert!(parse(input).is_err());
    }
}

#[test]
fn peer_ca_set_is_explicit_bounded_and_not_duplicated() {
    for document in [
        "[]".to_owned(),
        r#"["relative.der"]"#.into(),
        r#"["/fixture/client-ca.der","/fixture/client-ca.der"]"#.into(),
        json!(vec!["/fixture/client-ca.der"; 17]).to_string(),
    ] {
        let mut input = values();
        input.insert("DELEGATED_USE_CLIENT_CA_FILES".into(), document);
        assert!(parse(input).is_err());
    }
    for bytes in [vec![], vec![1; 65_537]] {
        assert!(DelegatedUseHostConfig::parse(values(), |_, _| Ok(bytes.clone())).is_err());
    }
    let mut input = values();
    input.insert(
        "DELEGATED_USE_CLIENT_CA_FILES".into(),
        r#"["/fixture/ca-one.der","/fixture/ca-two.der"]"#.into(),
    );
    assert!(DelegatedUseHostConfig::parse(input, |_, _| Ok(vec![1, 2, 3])).is_err());
}

#[test]
fn remote_tls_rejects_local_keys_mixed_providers_and_relative_files() {
    for prefix in ["DELEGATED_USE_TLS", "DELEGATED_USE_WORKLOAD_TLS"] {
        for (suffix, value) in [
            ("KEY_FILE", "/never/local.key"),
            ("PRIVATE_KEY", "never-log-private"),
            ("KMS_REGION", "us-east-1"),
            ("CERT_FILE", "relative.pem"),
            ("KMS_ADDR", "http://localhost:8200"),
        ] {
            let mut input = values();
            input.insert(format!("{prefix}_{suffix}"), value.into());
            assert_eq!(parse(input).unwrap_err(), HostConfigError::Invalid(prefix));
        }
    }
}

#[test]
fn bounded_file_reader_refuses_directories_and_oversized_data() {
    let directory = std::env::temp_dir().join(format!("delegated-use-config-{}", Uuid::new_v4()));
    fs::create_dir(&directory).unwrap();
    let path = directory.join("fixture.secret");
    fs::write(&path, b"bounded\n").unwrap();
    assert_eq!(bounded_file(&path, 8).unwrap(), b"bounded\n");
    assert!(bounded_file(&path, 7).is_err());
    assert!(bounded_file(&directory, 8).is_err());
    assert!(bounded_file(&directory.join("missing"), 8).is_err());
    fs::remove_dir_all(directory).unwrap();
}
