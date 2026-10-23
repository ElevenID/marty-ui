//! One HTTPS transport policy for OpenBao requests in native Marty services.

use std::{fs::File, io::Read, path::Path, time::Duration};

use reqwest::{Certificate, Client, Url};

const MAX_CA_CERT_BYTES: u64 = 64 * 1024;

/// Validated OpenBao origin and a client that cannot follow redirects or use HTTP.
#[derive(Clone)]
pub struct OpenBaoHttp {
    origin: String,
    client: Client,
}

impl OpenBaoHttp {
    /// Trust `ca_file` alone when a private OpenBao CA is supplied; otherwise
    /// use the platform trust store for a publicly issued OpenBao certificate.
    pub fn connect(
        origin: &str,
        ca_file: Option<&Path>,
        timeout: Duration,
    ) -> Result<Self, String> {
        Self::build(origin, ca_file, timeout, false)
    }

    /// A long download may continue while data arrives; each read and the
    /// connection remain bounded. All HTTPS, CA, redirect and proxy rules apply.
    pub fn connect_with_read_timeout(
        origin: &str,
        ca_file: Option<&Path>,
        timeout: Duration,
    ) -> Result<Self, String> {
        Self::build(origin, ca_file, timeout, true)
    }

    fn build(
        origin: &str,
        ca_file: Option<&Path>,
        timeout: Duration,
        idle: bool,
    ) -> Result<Self, String> {
        let url = Url::parse(origin).map_err(|_| "OpenBao origin is invalid")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
            || origin.ends_with('/')
            || timeout.is_zero()
        {
            return Err("OpenBao requires an HTTPS origin without credentials or path".into());
        }
        let mut builder = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none());
        builder = if idle {
            builder.connect_timeout(timeout).read_timeout(timeout)
        } else {
            builder.timeout(timeout)
        };
        if let Some(path) = ca_file {
            let mut pem = Vec::new();
            File::open(path)
                .map_err(|_| "OpenBao CA certificate is unreadable")?
                .take(MAX_CA_CERT_BYTES + 1)
                .read_to_end(&mut pem)
                .map_err(|_| "OpenBao CA certificate is unreadable")?;
            if pem.is_empty()
                || pem.len() as u64 > MAX_CA_CERT_BYTES
                || pem.windows(11).any(|bytes| bytes == b"PRIVATE KEY")
            {
                return Err(
                    "OpenBao CA file is empty, oversized, or contains private material".into(),
                );
            }
            let certificate =
                Certificate::from_pem(&pem).map_err(|_| "OpenBao CA certificate is invalid")?;
            builder = builder.tls_certs_only([certificate]);
        }
        let client = builder
            .build()
            .map_err(|_| "OpenBao HTTPS client is unavailable")?;
        Ok(Self {
            origin: origin.into(),
            client,
        })
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn client(&self) -> &Client {
        &self.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openbao_transport_rejects_insecure_or_ambiguous_origins() {
        for origin in [
            "http://openbao:8200",
            "https://user@openbao:8200",
            "https://openbao:8200/v1/transit",
            "https://openbao:8200?x=1",
            "https://openbao:8200/",
        ] {
            assert!(OpenBaoHttp::connect(origin, None, Duration::from_secs(5)).is_err());
            assert!(
                OpenBaoHttp::connect_with_read_timeout(origin, None, Duration::from_secs(5))
                    .is_err()
            );
        }
        assert!(OpenBaoHttp::connect("https://openbao:8200", None, Duration::ZERO).is_err());
        assert!(OpenBaoHttp::connect_with_read_timeout(
            "https://openbao:8200",
            None,
            Duration::ZERO
        )
        .is_err());
        assert!(OpenBaoHttp::connect("https://openbao:8200", None, Duration::from_secs(5)).is_ok());
    }
}
