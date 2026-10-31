//! Shared remote TLS identity bootstrapping for Rust HTTPS edges.

use http::HeaderName;
use std::{collections::BTreeMap, env, error::Error, time::Duration};

use marty_service_runtime::{RemoteTlsIdentityFiles, TlsIdentityNames};
use mmf_platform::keyless_https_server_config;

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
    let values = env::vars().collect::<BTreeMap<_, _>>();
    let identity = RemoteTlsIdentityFiles::from_values(
        |name| values.get(name).map(String::as_str),
        TlsIdentityNames::files(&format!("{prefix}_TLS")),
        Duration::from_secs(5),
        32,
    )?
    .ok_or("HTTPS edge requires a remote TLS identity")?
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
