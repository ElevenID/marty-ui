//! Shared remote TLS identity bootstrapping for Rust HTTPS edges.

use std::{env, error::Error, path::PathBuf, time::Duration};

use mmf_platform::{keyless_https_server_config, OpenBaoTlsIdentityFiles};

pub fn required(name: &str) -> Result<String, Box<dyn Error>> {
    let value = env::var(name)?;
    if value.trim().is_empty() || value.contains(['\r', '\n']) {
        return Err(format!("{name} must be a nonempty single-line value").into());
    }
    Ok(value)
}

pub async fn keyless_tls_config(
    prefix: &str,
) -> Result<axum_server::tls_rustls::RustlsConfig, Box<dyn Error>> {
    let key_version: u32 = required(&format!("{prefix}_TLS_KMS_KEY_VERSION"))?.parse()?;
    if key_version == 0 {
        return Err("remote TLS key version must be positive".into());
    }
    let identity = OpenBaoTlsIdentityFiles {
        certificate_chain_file: PathBuf::from(required(&format!("{prefix}_TLS_CERT_FILE"))?),
        kms_ca_cert_file: PathBuf::from(required(&format!("{prefix}_TLS_KMS_CA_CERT_FILE"))?),
        kms_endpoint: required(&format!("{prefix}_TLS_KMS_ADDR"))?,
        kms_token_file: PathBuf::from(required(&format!("{prefix}_TLS_KMS_TOKEN_FILE"))?),
        kms_key_name: required(&format!("{prefix}_TLS_KMS_KEY_NAME"))?,
        kms_key_version: key_version,
        request_timeout: Duration::from_secs(5),
        max_concurrent_signs: 32,
    }
    .connect()
    .await?;
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        keyless_https_server_config(&identity)?,
    ))
}
