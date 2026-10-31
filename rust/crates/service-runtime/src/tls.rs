//! Provider selection for the existing MMF keyless TLS identities.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use mmf_aws_kms::{validate_key_arn, AwsAuth, AwsKmsConfig};
use mmf_platform::{
    AwsKmsTlsIdentityFiles, KeylessGrpcTlsAcceptor, KeylessGrpcTransportOptions,
    KeylessTlsIdentity, OpenBaoTlsIdentityFiles, PlatformError,
};
use tonic::transport::Channel;

/// A closed choice of existing remote signers. There is no local-key variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteTlsIdentityFiles {
    OpenBao(OpenBaoTlsIdentityFiles),
    AwsKms(AwsKmsTlsIdentityFiles),
}

/// Public peer trust stays separate from the selected private-key provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkloadTlsFiles {
    pub ca_certificate: PathBuf,
    pub identity: RemoteTlsIdentityFiles,
}

/// Preserve each existing TLS prefix's certificate-file spelling.
pub struct TlsIdentityNames {
    pub prefix: String,
    pub certificate: String,
    pub kms_ca_certificate: String,
    pub private_key: String,
}

impl TlsIdentityNames {
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.into(),
            certificate: format!("{prefix}_CERT"),
            kms_ca_certificate: format!("{prefix}_KMS_CA_CERT"),
            private_key: format!("{prefix}_KEY"),
        }
    }

    pub fn files(prefix: &str) -> Self {
        Self {
            certificate: format!("{prefix}_CERT_FILE"),
            kms_ca_certificate: format!("{prefix}_KMS_CA_CERT_FILE"),
            private_key: format!("{prefix}_KEY_FILE"),
            ..Self::new(prefix)
        }
    }
}

impl RemoteTlsIdentityFiles {
    /// Parse one identity only. Callers retain deployment requirements and peer
    /// CA policy; configured but incomplete identities always fail closed.
    pub fn from_values<'a>(
        get: impl Fn(&str) -> Option<&'a str>,
        names: TlsIdentityNames,
        request_timeout: Duration,
        max_concurrent_signs: usize,
    ) -> Result<Option<Self>, String> {
        let prefix = &names.prefix;
        let private_names = [
            names.private_key.clone(),
            format!("{prefix}_KEY"),
            format!("{prefix}_KEY_FILE"),
            format!("{prefix}_PRIVATE_KEY"),
            format!("{prefix}_PRIVATE_KEY_FILE"),
        ];
        if private_names.iter().any(|name| get(name).is_some()) {
            return Err(format!("{prefix} private-key files are retired"));
        }
        let value = |name: &str| get(name).map(str::trim).filter(|value| !value.is_empty());
        let provider_name = format!("{prefix}_KMS_PROVIDER");
        if get(&provider_name).is_some() && value(&provider_name).is_none() {
            return Err(format!(
                "{provider_name} must be openbao-transit or aws-kms"
            ));
        }
        let endpoint_name = format!("{prefix}_KMS_ADDR");
        let token_name = format!("{prefix}_KMS_TOKEN_FILE");
        let key_name = format!("{prefix}_KMS_KEY_NAME");
        let version_name = format!("{prefix}_KMS_KEY_VERSION");
        let region_name = format!("{prefix}_KMS_REGION");
        let arn_name = format!("{prefix}_KMS_KEY_ARN");
        let openbao_names = [
            &endpoint_name,
            &names.kms_ca_certificate,
            &token_name,
            &key_name,
            &version_name,
        ];
        let aws_names = [&region_name, &arn_name];
        for name in [&names.certificate, &provider_name]
            .into_iter()
            .chain(openbao_names.iter().copied())
            .chain(aws_names.iter().copied())
        {
            if get(name).is_some_and(|value| value.contains(['\r', '\n'])) {
                return Err(format!("{name} must be a single-line value"));
            }
        }
        let configured = value(&names.certificate).is_some()
            || value(&provider_name).is_some()
            || openbao_names
                .iter()
                .chain(aws_names.iter())
                .any(|name| value(name).is_some());
        if !configured {
            return Ok(None);
        }
        if request_timeout.is_zero()
            || request_timeout > Duration::from_secs(30)
            || !(1..=512).contains(&max_concurrent_signs)
        {
            return Err(format!("{prefix} remote TLS limits are invalid"));
        }
        let required = |name: &str| value(name).ok_or_else(|| format!("{name} is required"));
        let certificate_chain_file = PathBuf::from(required(&names.certificate)?);
        match value(&provider_name).unwrap_or("openbao-transit") {
            "openbao-transit" => {
                if aws_names.iter().any(|name| value(name).is_some()) {
                    return Err(format!(
                        "{prefix} cannot mix OpenBao and AWS TLS identity settings"
                    ));
                }
                let endpoint = required(&endpoint_name)?;
                let parsed =
                    url::Url::parse(endpoint).map_err(|_| format!("{endpoint_name} is invalid"))?;
                if parsed.scheme() != "https"
                    || parsed.host_str().is_none()
                    || !parsed.username().is_empty()
                    || parsed.password().is_some()
                    || parsed.path() != "/"
                    || parsed.query().is_some()
                    || parsed.fragment().is_some()
                {
                    return Err(format!(
                        "{endpoint_name} must be an uncredentialed HTTPS origin"
                    ));
                }
                let kms_key_version = required(&version_name)?
                    .parse::<u32>()
                    .ok()
                    .filter(|version| *version > 0)
                    .ok_or_else(|| format!("{version_name} must be positive"))?;
                Ok(Some(Self::OpenBao(OpenBaoTlsIdentityFiles {
                    certificate_chain_file,
                    kms_endpoint: endpoint.into(),
                    kms_ca_cert_file: required(&names.kms_ca_certificate)?.into(),
                    kms_token_file: required(&token_name)?.into(),
                    kms_key_name: required(&key_name)?.into(),
                    kms_key_version,
                    request_timeout,
                    max_concurrent_signs,
                })))
            }
            "aws-kms" => {
                if openbao_names.iter().any(|name| value(name).is_some()) {
                    return Err(format!(
                        "{prefix} cannot mix AWS and OpenBao TLS identity settings"
                    ));
                }
                let region = required(&region_name)?;
                let key_arn = required(&arn_name)?;
                validate_key_arn(key_arn, region).map_err(|_| {
                    format!("{arn_name} must be an immutable key ARN in {region_name}")
                })?;
                Ok(Some(Self::AwsKms(AwsKmsTlsIdentityFiles {
                    certificate_chain_file,
                    kms: AwsKmsConfig {
                        region: region.into(),
                        authentication: AwsAuth::IamRole,
                        endpoint: None,
                        request_timeout,
                    },
                    key_arn: key_arn.into(),
                    max_concurrent_signs,
                })))
            }
            _ => Err(format!(
                "{provider_name} must be openbao-transit or aws-kms"
            )),
        }
    }

    pub fn provider(&self) -> &'static str {
        match self {
            Self::OpenBao(_) => "openbao-transit",
            Self::AwsKms(_) => "aws-kms",
        }
    }

    /// Preserve a caller's existing dependency budget at transport activation.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        match &mut self {
            Self::OpenBao(files) => files.request_timeout = timeout,
            Self::AwsKms(files) => files.kms.request_timeout = timeout,
        }
        self
    }

    pub async fn connect(&self) -> Result<KeylessTlsIdentity, PlatformError> {
        match self {
            Self::OpenBao(files) => files.connect().await,
            Self::AwsKms(files) => files.connect().await,
        }
    }

    pub async fn grpc_channel(
        &self,
        target: &str,
        ca: &Path,
        options: KeylessGrpcTransportOptions,
    ) -> Result<Channel, PlatformError> {
        match self {
            Self::OpenBao(files) => files.grpc_channel(target, ca, options).await,
            Self::AwsKms(files) => files.grpc_channel(target, ca, options).await,
        }
    }

    pub async fn grpc_channel_connected(
        &self,
        target: &str,
        ca: &Path,
        options: KeylessGrpcTransportOptions,
    ) -> Result<Channel, PlatformError> {
        match self {
            Self::OpenBao(files) => files.grpc_channel_connected(target, ca, options).await,
            Self::AwsKms(files) => files.grpc_channel_connected(target, ca, options).await,
        }
    }

    pub async fn grpc_acceptor(
        &self,
        ca: &Path,
        max_handshakes: usize,
        timeout: Duration,
    ) -> Result<KeylessGrpcTlsAcceptor, PlatformError> {
        match self {
            Self::OpenBao(files) => files.grpc_acceptor(ca, max_handshakes, timeout).await,
            Self::AwsKms(files) => files.grpc_acceptor(ca, max_handshakes, timeout).await,
        }
    }

    pub async fn grpc_acceptor_without_client_auth(
        &self,
        max_handshakes: usize,
        timeout: Duration,
    ) -> Result<KeylessGrpcTlsAcceptor, PlatformError> {
        match self {
            Self::OpenBao(files) => {
                files
                    .grpc_acceptor_without_client_auth(max_handshakes, timeout)
                    .await
            }
            Self::AwsKms(files) => {
                files
                    .grpc_acceptor_without_client_auth(max_handshakes, timeout)
                    .await
            }
        }
    }

    /// Existing server-only policy; per-RPC service authorization stays active.
    pub async fn acceptor(&self) -> Result<KeylessGrpcTlsAcceptor, PlatformError> {
        self.grpc_acceptor_without_client_auth(64, Duration::from_secs(15))
            .await
    }
}

impl From<OpenBaoTlsIdentityFiles> for RemoteTlsIdentityFiles {
    fn from(files: OpenBaoTlsIdentityFiles) -> Self {
        Self::OpenBao(files)
    }
}

impl WorkloadTlsFiles {
    pub fn from_values<'a>(
        get: impl Fn(&str) -> Option<&'a str>,
        names: TlsIdentityNames,
        ca_name: &str,
        required: bool,
        request_timeout: Duration,
        max_concurrent_signs: usize,
    ) -> Result<Option<Self>, String> {
        let identity = RemoteTlsIdentityFiles::from_values(
            &get,
            names,
            request_timeout,
            max_concurrent_signs,
        )?;
        let Some(identity) = identity else {
            return if required {
                Err("workload TLS requires a remote identity".into())
            } else {
                Ok(None)
            };
        };
        let ca_certificate = get(ca_name)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("{ca_name} is required for workload TLS"))?
            .into();
        Ok(Some(Self {
            ca_certificate,
            identity,
        }))
    }
}

#[cfg(test)]
mod tests;
