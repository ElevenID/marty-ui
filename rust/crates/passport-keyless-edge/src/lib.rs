//! Shared remote TLS identity bootstrapping for Rust HTTPS edges.

use http::HeaderName;
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

pub fn hop_by_hop(name: &HeaderName, connection: &str) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    ) || connection
        .split(',')
        .any(|item| item.trim().eq_ignore_ascii_case(name.as_str()))
}

pub fn caller_forwarding_header(name: &HeaderName) -> bool {
    name.as_str() == "forwarded"
        || name.as_str() == "x-real-ip"
        || name.as_str().starts_with("x-forwarded-")
}

#[cfg(test)]
mod header_tests {
    use super::*;

    #[test]
    fn connection_tokens_are_case_insensitive_and_do_not_strip_end_to_end_headers() {
        assert!(hop_by_hop(
            &HeaderName::from_static("x-private-hop"),
            "keep-alive, X-PRIVATE-HOP"
        ));
        for name in [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
        ] {
            assert!(hop_by_hop(&HeaderName::from_static(name), ""));
        }
        for name in ["authorization", "content-type", "set-cookie"] {
            assert!(!hop_by_hop(&HeaderName::from_static(name), "keep-alive"));
        }
    }

    #[test]
    fn caller_forwarding_identity_is_filtered_without_matching_unrelated_names() {
        for name in [
            "forwarded",
            "x-real-ip",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
        ] {
            assert!(caller_forwarding_header(&HeaderName::from_static(name)));
        }
        for name in ["forwarded-extra", "x-request-id", "host"] {
            assert!(!caller_forwarding_header(&HeaderName::from_static(name)));
        }
    }
}
