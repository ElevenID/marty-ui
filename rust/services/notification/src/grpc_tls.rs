use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use marty_service_runtime::{RemoteTlsIdentityFiles, TlsIdentityNames};
use mmf_platform::{KeylessGrpcTlsAcceptor, PlatformError};

/// Public TLS files and a pinned, non-exportable remote signing key.
/// Notification's service-token interceptor remains active in both modes.
pub struct NotificationGrpcTlsSettings {
    identity: RemoteTlsIdentityFiles,
    client_ca_file: Option<PathBuf>,
}

impl NotificationGrpcTlsSettings {
    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
        development: bool,
    ) -> Result<Option<Self>, String> {
        let values = values.into_iter().collect::<BTreeMap<_, _>>();
        if values.contains_key("GRPC_TLS_KEY") {
            return Err("GRPC_TLS_KEY private-key files are not supported".into());
        }
        let value = |name: &str| {
            values
                .get(name)
                .map(String::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        };
        let identity = RemoteTlsIdentityFiles::from_values(
            |name| values.get(name).map(String::as_str),
            TlsIdentityNames::new("GRPC_TLS"),
            Duration::from_secs(10),
            64,
        )?;
        let require_client = match value("GRPC_TLS_REQUIRE_CLIENT_AUTH")
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            None | Some("false" | "0" | "no") => false,
            Some("true" | "1" | "yes") => true,
            Some(_) => return Err("GRPC_TLS_REQUIRE_CLIENT_AUTH is invalid".into()),
        };
        let client_ca = value("GRPC_TLS_CA_CERT").map(PathBuf::from);
        if identity.is_none() && development && !require_client && client_ca.is_none() {
            return Ok(None);
        }
        let identity = identity
            .ok_or("gRPC TLS requires a public certificate and complete remote KMS identity")?;
        if require_client && client_ca.is_none() {
            return Err("GRPC_TLS_CA_CERT is required for client authentication".into());
        }
        Ok(Some(Self {
            identity,
            client_ca_file: require_client.then_some(client_ca).flatten(),
        }))
    }

    pub async fn acceptor(&self) -> Result<KeylessGrpcTlsAcceptor, PlatformError> {
        match &self.client_ca_file {
            Some(ca) => {
                self.identity
                    .grpc_acceptor(ca, 64, Duration::from_secs(15))
                    .await
            }
            None => {
                self.identity
                    .grpc_acceptor_without_client_auth(64, Duration::from_secs(15))
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_server_keeps_client_auth_requirement_and_rejects_mixed_provider() {
        let mut values = vec![
            ("GRPC_TLS_CERT".into(), "public.pem".into()),
            ("GRPC_TLS_KMS_PROVIDER".into(), "aws-kms".into()),
            ("GRPC_TLS_KMS_REGION".into(), "us-east-1".into()),
            (
                "GRPC_TLS_KMS_KEY_ARN".into(),
                "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
                    .into(),
            ),
            ("GRPC_TLS_REQUIRE_CLIENT_AUTH".into(), "true".into()),
        ];
        assert!(NotificationGrpcTlsSettings::from_values(values.clone(), false).is_err());
        values.push(("GRPC_TLS_CA_CERT".into(), "client-ca.pem".into()));
        let tls = NotificationGrpcTlsSettings::from_values(values.clone(), false)
            .unwrap()
            .unwrap();
        assert_eq!(tls.identity.provider(), "aws-kms");
        assert_eq!(tls.client_ca_file, Some(PathBuf::from("client-ca.pem")));
        values.push(("GRPC_TLS_KMS_TOKEN_FILE".into(), "old-token".into()));
        assert!(NotificationGrpcTlsSettings::from_values(values, false).is_err());
    }

    fn configured() -> Vec<(String, String)> {
        [
            ("GRPC_TLS_CERT", "server.pem"),
            ("GRPC_TLS_KMS_ADDR", "https://bao:8200"),
            ("GRPC_TLS_KMS_CA_CERT", "bao-ca.pem"),
            ("GRPC_TLS_KMS_TOKEN_FILE", "token"),
            ("GRPC_TLS_KMS_KEY_NAME", "notification-server"),
            ("GRPC_TLS_KMS_KEY_VERSION", "1"),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .collect()
    }

    #[test]
    fn keyless_modes_keep_client_auth_policy_and_reject_private_key_files() {
        assert!(NotificationGrpcTlsSettings::from_values(Vec::new(), true)
            .unwrap()
            .is_none());
        assert!(
            NotificationGrpcTlsSettings::from_values(configured(), false)
                .unwrap()
                .unwrap()
                .client_ca_file
                .is_none()
        );
        let mut mtls = configured();
        mtls.push(("GRPC_TLS_REQUIRE_CLIENT_AUTH".into(), "true".into()));
        assert!(NotificationGrpcTlsSettings::from_values(mtls.clone(), false).is_err());
        mtls.push(("GRPC_TLS_CA_CERT".into(), "client-ca.pem".into()));
        assert!(NotificationGrpcTlsSettings::from_values(mtls, false)
            .unwrap()
            .unwrap()
            .client_ca_file
            .is_some());
        let mut retired = configured();
        retired.push(("GRPC_TLS_KEY".into(), "server-key.pem".into()));
        assert!(NotificationGrpcTlsSettings::from_values(retired, false).is_err());
        assert!(NotificationGrpcTlsSettings::from_values(Vec::new(), false).is_err());
    }
}
