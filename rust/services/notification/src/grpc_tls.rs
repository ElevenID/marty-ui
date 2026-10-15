use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use mmf_platform::{KeylessGrpcTlsAcceptor, OpenBaoTlsIdentityFiles, PlatformError};

/// Public TLS files and a versioned, non-exportable OpenBao signing key.
/// Notification's service-token interceptor remains active in both modes.
pub struct NotificationGrpcTlsSettings {
    identity: OpenBaoTlsIdentityFiles,
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
        let names = [
            "GRPC_TLS_CERT",
            "GRPC_TLS_KMS_ADDR",
            "GRPC_TLS_KMS_CA_CERT",
            "GRPC_TLS_KMS_TOKEN_FILE",
            "GRPC_TLS_KMS_KEY_NAME",
            "GRPC_TLS_KMS_KEY_VERSION",
        ];
        let value = |name: &str| {
            values
                .get(name)
                .map(String::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        };
        let configured = names.iter().filter(|name| value(name).is_some()).count();
        let require_client = match value("GRPC_TLS_REQUIRE_CLIENT_AUTH")
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            None | Some("false" | "0" | "no") => false,
            Some("true" | "1" | "yes") => true,
            Some(_) => return Err("GRPC_TLS_REQUIRE_CLIENT_AUTH is invalid".into()),
        };
        let client_ca = value("GRPC_TLS_CA_CERT").map(PathBuf::from);
        if configured == 0 && development && !require_client && client_ca.is_none() {
            return Ok(None);
        }
        if configured != names.len() {
            return Err(
                "gRPC TLS requires a public certificate and complete remote KMS identity".into(),
            );
        }
        if require_client && client_ca.is_none() {
            return Err("GRPC_TLS_CA_CERT is required for client authentication".into());
        }
        let version = value(names[5])
            .unwrap_or_default()
            .parse::<u32>()
            .ok()
            .filter(|version| *version > 0)
            .ok_or("GRPC_TLS_KMS_KEY_VERSION is invalid")?;
        Ok(Some(Self {
            identity: OpenBaoTlsIdentityFiles {
                certificate_chain_file: PathBuf::from(value(names[0]).unwrap_or_default()),
                kms_endpoint: value(names[1]).unwrap_or_default().into(),
                kms_ca_cert_file: PathBuf::from(value(names[2]).unwrap_or_default()),
                kms_token_file: PathBuf::from(value(names[3]).unwrap_or_default()),
                kms_key_name: value(names[4]).unwrap_or_default().into(),
                kms_key_version: version,
                request_timeout: Duration::from_secs(10),
                max_concurrent_signs: 64,
            },
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
