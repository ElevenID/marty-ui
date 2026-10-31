use std::collections::BTreeMap;

use super::*;

const ARN: &str = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012";

fn aws() -> BTreeMap<String, String> {
    [
        ("TEST_TLS_CERT", "public-chain.pem"),
        ("TEST_TLS_KMS_PROVIDER", "aws-kms"),
        ("TEST_TLS_KMS_REGION", "us-east-1"),
        ("TEST_TLS_KMS_KEY_ARN", ARN),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect()
}

fn openbao() -> BTreeMap<String, String> {
    [
        ("TEST_TLS_CERT", "public-chain.pem"),
        ("TEST_TLS_KMS_ADDR", "https://bao:8200"),
        ("TEST_TLS_KMS_CA_CERT", "bao-ca.pem"),
        ("TEST_TLS_KMS_TOKEN_FILE", "scoped-token"),
        ("TEST_TLS_KMS_KEY_NAME", "service-tls"),
        ("TEST_TLS_KMS_KEY_VERSION", "2"),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect()
}

fn parse(values: &BTreeMap<String, String>) -> Result<Option<RemoteTlsIdentityFiles>, String> {
    RemoteTlsIdentityFiles::from_values(
        |name| values.get(name).map(String::as_str),
        TlsIdentityNames::new("TEST_TLS"),
        Duration::from_secs(10),
        64,
    )
}

#[test]
fn aws_identity_requires_only_public_certificate_and_exact_workload_key() {
    let RemoteTlsIdentityFiles::AwsKms(files) = parse(&aws()).unwrap().unwrap() else {
        panic!("AWS provider must be selected");
    };
    assert_eq!(
        files.certificate_chain_file,
        PathBuf::from("public-chain.pem")
    );
    assert_eq!(files.key_arn, ARN);
    assert_eq!(files.kms.region, "us-east-1");
    assert_eq!(files.kms.authentication, AwsAuth::IamRole);
    assert!(files.kms.endpoint.is_none());
    assert_eq!(files.kms.request_timeout, Duration::from_secs(10));
    assert_eq!(files.max_concurrent_signs, 64);
}

#[test]
fn omitted_provider_preserves_exact_openbao_identity() {
    let RemoteTlsIdentityFiles::OpenBao(files) = parse(&openbao()).unwrap().unwrap() else {
        panic!("existing configuration must select OpenBao");
    };
    assert_eq!(files.kms_endpoint, "https://bao:8200");
    assert_eq!(files.kms_ca_cert_file, PathBuf::from("bao-ca.pem"));
    assert_eq!(files.kms_token_file, PathBuf::from("scoped-token"));
    assert_eq!(files.kms_key_name, "service-tls");
    assert_eq!(files.kms_key_version, 2);
}

#[test]
fn mixed_partial_unknown_and_private_identities_never_select_another_provider() {
    for field in [
        "TEST_TLS_KMS_ADDR",
        "TEST_TLS_KMS_CA_CERT",
        "TEST_TLS_KMS_TOKEN_FILE",
        "TEST_TLS_KMS_KEY_NAME",
        "TEST_TLS_KMS_KEY_VERSION",
    ] {
        let mut values = aws();
        values.insert(field.into(), "leftover-openbao-value".into());
        assert!(parse(&values).is_err(), "{field}");
    }
    for field in ["TEST_TLS_KMS_REGION", "TEST_TLS_KMS_KEY_ARN"] {
        let mut values = openbao();
        values.insert(field.into(), "leftover-aws-value".into());
        assert!(parse(&values).is_err(), "{field}");
    }
    for field in [
        "TEST_TLS_CERT",
        "TEST_TLS_KMS_REGION",
        "TEST_TLS_KMS_KEY_ARN",
    ] {
        let mut values = aws();
        values.remove(field);
        assert!(parse(&values).is_err(), "{field}");
    }
    for field in [
        "TEST_TLS_KEY",
        "TEST_TLS_KEY_FILE",
        "TEST_TLS_PRIVATE_KEY_FILE",
    ] {
        let mut values = aws();
        values.insert(field.into(), String::new());
        assert!(parse(&values).is_err(), "{field}");
    }
    for provider in ["unknown", "", "  "] {
        let mut values = aws();
        values.insert("TEST_TLS_KMS_PROVIDER".into(), provider.into());
        assert!(parse(&values).is_err());
        let selector_only = BTreeMap::from([("TEST_TLS_KMS_PROVIDER".into(), provider.into())]);
        assert!(parse(&selector_only).is_err());
    }
    assert!(parse(&BTreeMap::new()).unwrap().is_none());
}

#[test]
fn existing_file_suffixes_and_runtime_timeouts_are_preserved_for_both_providers() {
    for mut values in [aws(), openbao()] {
        let cert = values.remove("TEST_TLS_CERT").unwrap();
        values.insert("TEST_TLS_CERT_FILE".into(), cert);
        if let Some(ca) = values.remove("TEST_TLS_KMS_CA_CERT") {
            values.insert("TEST_TLS_KMS_CA_CERT_FILE".into(), ca);
        }
        let identity = RemoteTlsIdentityFiles::from_values(
            |name| values.get(name).map(String::as_str),
            TlsIdentityNames::files("TEST_TLS"),
            Duration::from_secs(5),
            32,
        )
        .unwrap()
        .unwrap()
        .with_request_timeout(Duration::from_secs(3));
        match identity {
            RemoteTlsIdentityFiles::OpenBao(files) => {
                assert_eq!(
                    files.certificate_chain_file,
                    PathBuf::from("public-chain.pem")
                );
                assert_eq!(files.kms_ca_cert_file, PathBuf::from("bao-ca.pem"));
                assert_eq!(files.request_timeout, Duration::from_secs(3));
                assert_eq!(files.max_concurrent_signs, 32);
            }
            RemoteTlsIdentityFiles::AwsKms(files) => {
                assert_eq!(
                    files.certificate_chain_file,
                    PathBuf::from("public-chain.pem")
                );
                assert_eq!(files.kms.request_timeout, Duration::from_secs(3));
                assert_eq!(files.max_concurrent_signs, 32);
            }
        }
        values.insert("TEST_TLS_CERT_FILE".into(), "line1\nline2".into());
        assert!(RemoteTlsIdentityFiles::from_values(
            |name| values.get(name).map(String::as_str),
            TlsIdentityNames::files("TEST_TLS"),
            Duration::from_secs(5),
            32,
        )
        .is_err());
    }
}

#[test]
fn aliases_region_mismatch_and_insecure_openbao_origins_are_rejected() {
    for key in [
        "alias/tls",
        "arn:aws:kms:us-east-1:123456789012:alias/tls",
        "arn:aws:kms:us-west-2:123456789012:key/12345678",
    ] {
        let mut values = aws();
        values.insert("TEST_TLS_KMS_KEY_ARN".into(), key.into());
        assert!(parse(&values).is_err(), "{key}");
    }
    for endpoint in [
        "http://bao:8200",
        "https://user:secret@bao:8200",
        "https://bao:8200/path",
    ] {
        let mut values = openbao();
        values.insert("TEST_TLS_KMS_ADDR".into(), endpoint.into());
        assert!(parse(&values).is_err(), "{endpoint}");
    }
    let mut values = openbao();
    values.insert("TEST_TLS_KMS_KEY_VERSION".into(), "0".into());
    assert!(parse(&values).is_err());
}

#[test]
fn workload_peer_ca_is_required_independently_of_private_key_provider() {
    let mut values = aws();
    let parse = |values: &BTreeMap<String, String>| {
        WorkloadTlsFiles::from_values(
            |name| values.get(name).map(String::as_str),
            TlsIdentityNames::new("TEST_TLS"),
            "PUBLIC_PEER_CA",
            true,
            Duration::from_secs(10),
            64,
        )
    };
    assert!(parse(&values).is_err());
    values.insert("PUBLIC_PEER_CA".into(), "peer-ca.pem".into());
    let files = parse(&values).unwrap().unwrap();
    assert_eq!(files.ca_certificate, PathBuf::from("peer-ca.pem"));
    assert_eq!(files.identity.provider(), "aws-kms");
    assert!(parse(&BTreeMap::new()).is_err());
}

#[tokio::test]
async fn unavailable_public_certificate_never_falls_back_to_plaintext_or_other_provider() {
    for mut values in [aws(), openbao()] {
        values.insert(
            "TEST_TLS_CERT".into(),
            "/nonexistent/public-chain.pem".into(),
        );
        assert!(parse(&values).unwrap().unwrap().connect().await.is_err());
    }
}
