//! Shared internal gRPC channel policy for issuance dependencies.

use std::{fs, time::Duration};

use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

use crate::config::normalize_grpc_target;

pub(crate) fn endpoint(target: &str, timeout: Duration) -> Result<Endpoint, String> {
    let ca_path = std::env::var("GRPC_TLS_CA_CERT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("GRPC_CA_CERT")
                .ok()
                .filter(|value| !value.trim().is_empty())
        });
    let client_cert = std::env::var("GRPC_TLS_CLIENT_CERT")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let client_key = std::env::var("GRPC_TLS_CLIENT_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty());
    if client_cert.is_some() != client_key.is_some() {
        return Err("gRPC client certificate and key must be configured together".into());
    }
    if ca_path.is_none() {
        let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "development".into());
        let development = matches!(
            environment.to_ascii_lowercase().as_str(),
            "development" | "dev" | "local" | "test"
        );
        let insecure_allowed = std::env::var("GRPC_INSECURE_ALLOWED")
            .is_ok_and(|value| value.eq_ignore_ascii_case("true"));
        if !development && !insecure_allowed {
            return Err(
                "gRPC CA is required outside development unless GRPC_INSECURE_ALLOWED is explicit"
                    .into(),
            );
        }
    }
    endpoint_with_tls_paths(
        target,
        timeout,
        ca_path.as_deref(),
        client_cert.as_deref(),
        client_key.as_deref(),
    )
}

fn endpoint_with_tls_paths(
    target: &str,
    timeout: Duration,
    ca_path: Option<&str>,
    client_cert: Option<&str>,
    client_key: Option<&str>,
) -> Result<Endpoint, String> {
    if client_cert.is_some() != client_key.is_some() {
        return Err("gRPC client certificate and key must be configured together".into());
    }
    if ca_path.is_none() && client_cert.is_some() {
        return Err("gRPC client identity requires a CA certificate".into());
    }
    let target = normalize_grpc_target(target).ok_or("invalid gRPC target")?;
    let mut target = target;
    let mut endpoint = if let Some(path) = ca_path {
        if target.starts_with("http://") {
            target = target.replacen("http://", "https://", 1);
        }
        let parsed = url::Url::parse(&target).map_err(|_| "invalid gRPC TLS target")?;
        if parsed.scheme() != "https" {
            return Err("gRPC CA requires an HTTPS target".into());
        }
        let host = parsed.host_str().ok_or("gRPC TLS target has no host")?;
        let pem = fs::read(path.trim()).map_err(|_| "unable to read gRPC CA certificate")?;
        let mut tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(pem))
            .domain_name(host);
        if let (Some(cert), Some(key)) = (client_cert, client_key) {
            let cert =
                fs::read(cert.trim()).map_err(|_| "unable to read gRPC client certificate")?;
            let key = fs::read(key.trim()).map_err(|_| "unable to read gRPC client key")?;
            tls = tls.identity(Identity::from_pem(cert, key));
        }
        Endpoint::from_shared(target.clone())
            .map_err(|_| "invalid gRPC TLS target")?
            .tls_config(tls)
            .map_err(|_| "invalid gRPC CA certificate")?
    } else {
        Endpoint::from_shared(target).map_err(|_| "invalid gRPC target")?
    };
    endpoint = endpoint.connect_timeout(timeout).timeout(timeout);
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_ca_requires_a_readable_file_and_secure_target() {
        let timeout = Duration::from_secs(1);
        assert_eq!(
            endpoint_with_tls_paths(
                "issuer:9000",
                timeout,
                Some("missing-grpc-ca.pem"),
                None,
                None
            )
            .unwrap_err(),
            "unable to read gRPC CA certificate"
        );
        assert_eq!(
            endpoint_with_tls_paths(
                "ftp://issuer:9000",
                timeout,
                Some("missing-grpc-ca.pem"),
                None,
                None
            )
            .unwrap_err(),
            "gRPC CA requires an HTTPS target"
        );
        assert_eq!(
            endpoint_with_tls_paths("issuer:9000", timeout, None, Some("cert.pem"), None)
                .unwrap_err(),
            "gRPC client certificate and key must be configured together"
        );
        assert!(endpoint_with_tls_paths("issuer:9000", timeout, None, None, None).is_ok());
    }
}
