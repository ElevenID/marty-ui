//! Shared internal gRPC channels. Client identity keys remain in the selected KMS.

use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use mmf_platform::{
    GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial, GrpcTransportSecurity, GrpcTrustMode,
    KeylessGrpcTransportOptions,
};
use tonic::transport::Channel;

use crate::config::normalize_grpc_target;

pub(crate) async fn channel(target: &str, timeout: Duration) -> Result<Channel, String> {
    let values = std::env::vars().collect::<BTreeMap<_, _>>();
    channel_with_values(target, timeout, &values).await
}

pub(crate) async fn credential_template_channel(
    target: &str,
    timeout: Duration,
) -> Result<Channel, String> {
    let values = std::env::vars().collect::<BTreeMap<_, _>>();
    credential_template_channel_with_values(target, timeout, &values).await
}

async fn credential_template_channel_with_values(
    target: &str,
    timeout: Duration,
    values: &BTreeMap<String, String>,
) -> Result<Channel, String> {
    let deployed = values.get("ENVIRONMENT").is_some_and(|environment| {
        matches!(
            environment.to_ascii_lowercase().as_str(),
            "beta" | "production" | "prod"
        )
    });
    if deployed {
        if !target.starts_with("https://") {
            return Err("credential-template gRPC requires an explicit HTTPS target".into());
        }
        if ["GRPC_TLS_CA_CERT", "GRPC_CA_CERT"].iter().all(|name| {
            values
                .get(*name)
                .is_none_or(|value| value.trim().is_empty())
        }) {
            return Err("credential-template gRPC requires a public CA".into());
        }
    }
    channel_with_values(target, timeout, values).await
}

async fn channel_with_values(
    target: &str,
    timeout: Duration,
    values: &BTreeMap<String, String>,
) -> Result<Channel, String> {
    let target = normalize_grpc_target(target).ok_or("invalid gRPC target")?;
    let value = |name: &str| {
        values
            .get(name)
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    if values.contains_key("GRPC_TLS_CLIENT_KEY") {
        return Err("gRPC client private-key files are not supported".into());
    }
    let ca = value("GRPC_TLS_CA_CERT").or_else(|| value("GRPC_CA_CERT"));
    if ca.is_some() && !target.starts_with("https://") {
        return Err("gRPC CA requires an explicit HTTPS target".into());
    }
    let identity = marty_service_runtime::RemoteTlsIdentityFiles::from_values(
        |name| values.get(name).map(String::as_str),
        marty_service_runtime::TlsIdentityNames::new("GRPC_TLS_CLIENT"),
        timeout.min(Duration::from_secs(30)),
        64,
    )
    .map_err(|_| "gRPC client TLS requires a public certificate, CA and remote KMS identity")?;
    if let Some(identity) = identity {
        let ca =
            ca.ok_or("gRPC client TLS requires a public certificate, CA and remote KMS identity")?;
        return identity
            .grpc_channel(
                &target,
                &PathBuf::from(ca),
                KeylessGrpcTransportOptions {
                    connect_timeout: timeout,
                    request_timeout: timeout,
                    ..KeylessGrpcTransportOptions::default()
                },
            )
            .await
            .map_err(|_| "gRPC remote TLS identity is invalid or unavailable".into());
    }
    let (target, security, trust, material) = if let Some(ca) = ca {
        (
            target,
            GrpcTransportSecurity::ServerTls,
            GrpcTrustMode::CustomCa,
            GrpcTlsMaterial::from_ca_pem_file(Some(PathBuf::from(ca).as_path()))
                .map_err(|_| "unable to read gRPC CA certificate")?,
        )
    } else {
        let environment = value("ENVIRONMENT").unwrap_or("development");
        let development = matches!(
            environment.to_ascii_lowercase().as_str(),
            "development" | "dev" | "local" | "test"
        );
        let insecure_allowed =
            value("GRPC_INSECURE_ALLOWED").is_some_and(|value| value.eq_ignore_ascii_case("true"));
        if !development && !insecure_allowed {
            return Err("gRPC CA is required outside development".into());
        }
        (
            target,
            GrpcTransportSecurity::Plaintext,
            GrpcTrustMode::NativeRoots,
            GrpcTlsMaterial::default(),
        )
    };
    GrpcChannelFactory::new(
        GrpcChannelConfig {
            target,
            security,
            trust,
            connect_timeout_ms: timeout.as_millis() as u64,
            request_timeout_ms: timeout.as_millis() as u64,
            ..GrpcChannelConfig::default()
        },
        material,
    )
    .and_then(|factory| factory.connect_lazy())
    .map_err(|_| "gRPC channel configuration is invalid".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn configured_aws_identity_cannot_fall_back_to_server_only_tls() {
        let ca = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../signing-keys/tests/fixtures/public_certificates/root-ca.pem");
        let mut values = BTreeMap::from([
            ("GRPC_TLS_CA_CERT".into(), ca.to_string_lossy().into_owned()),
            (
                "GRPC_TLS_CLIENT_CERT".into(),
                "/nonexistent/issuance-public-cert.pem".into(),
            ),
            ("GRPC_TLS_CLIENT_KMS_PROVIDER".into(), "aws-kms".into()),
            ("GRPC_TLS_CLIENT_KMS_REGION".into(), "us-east-1".into()),
            (
                "GRPC_TLS_CLIENT_KMS_KEY_ARN".into(),
                "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
                    .into(),
            ),
        ]);
        assert_eq!(
            channel_with_values("https://issuer:9000", Duration::from_secs(1), &values)
                .await
                .unwrap_err(),
            "gRPC remote TLS identity is invalid or unavailable"
        );
        values.insert("GRPC_TLS_CLIENT_KMS_TOKEN_FILE".into(), "old-token".into());
        assert_eq!(
            channel_with_values("https://issuer:9000", Duration::from_secs(1), &values)
                .await
                .unwrap_err(),
            "gRPC client TLS requires a public certificate, CA and remote KMS identity"
        );
    }

    #[tokio::test]
    async fn public_ca_and_private_key_file_configuration_fail_closed() {
        let timeout = Duration::from_secs(1);
        let mut values = BTreeMap::new();
        values.insert("GRPC_TLS_CA_CERT".into(), "missing-grpc-ca.pem".into());
        assert_eq!(
            channel_with_values("issuer:9000", timeout, &values)
                .await
                .unwrap_err(),
            "gRPC CA requires an explicit HTTPS target"
        );
        assert_eq!(
            channel_with_values("https://issuer:9000", timeout, &values)
                .await
                .unwrap_err(),
            "unable to read gRPC CA certificate"
        );
        values.insert("GRPC_TLS_CLIENT_KEY".into(), "client-key.pem".into());
        assert_eq!(
            channel_with_values("issuer:9000", timeout, &values)
                .await
                .unwrap_err(),
            "gRPC client private-key files are not supported"
        );
        assert!(
            channel_with_values("issuer:9000", timeout, &BTreeMap::new())
                .await
                .is_ok()
        );
        assert!(
            channel_with_values("bad host:9000", timeout, &BTreeMap::new())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn deployed_credential_template_cannot_use_plaintext_or_untrusted_tls() {
        let timeout = Duration::from_secs(1);
        let mut values = BTreeMap::from([
            ("ENVIRONMENT".into(), "beta".into()),
            ("GRPC_INSECURE_ALLOWED".into(), "true".into()),
        ]);
        assert_eq!(
            credential_template_channel_with_values("credential-template:9003", timeout, &values)
                .await
                .unwrap_err(),
            "credential-template gRPC requires an explicit HTTPS target"
        );
        assert_eq!(
            credential_template_channel_with_values(
                "https://credential-template:9003",
                timeout,
                &values
            )
            .await
            .unwrap_err(),
            "credential-template gRPC requires a public CA"
        );
        values.insert("GRPC_TLS_CA_CERT".into(), "missing-ca.pem".into());
        assert_eq!(
            credential_template_channel_with_values(
                "https://credential-template:9003",
                timeout,
                &values
            )
            .await
            .unwrap_err(),
            "unable to read gRPC CA certificate"
        );
    }
}
