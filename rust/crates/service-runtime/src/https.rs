//! Optional direct HTTPS listeners backed exclusively by remote TLS signers.

use std::{io, net::SocketAddr, time::Duration};

use axum::Router;
use axum_server::{tls_rustls::RustlsConfig, Handle};
use tokio::sync::watch;

use crate::{RemoteTlsIdentityFiles, TlsIdentityNames};

/// Shared opt-in owner listener configuration. An incomplete TLS identity or
/// listener is an error in every environment; there is no plaintext fallback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedAuthorityHttpsConfig {
    pub address: SocketAddr,
    pub identity: RemoteTlsIdentityFiles,
}

impl ManagedAuthorityHttpsConfig {
    pub fn from_values<'a>(get: impl Fn(&str) -> Option<&'a str>) -> Result<Option<Self>, String> {
        const ADDRESS: &str = "MANAGED_AUTHORITY_HTTPS_ADDR";
        for suffix in [
            "CERT_FILE",
            "KMS_PROVIDER",
            "KMS_ADDR",
            "KMS_CA_CERT_FILE",
            "KMS_TOKEN_FILE",
            "KMS_KEY_NAME",
            "KMS_KEY_VERSION",
            "KMS_REGION",
            "KMS_KEY_ARN",
        ] {
            let name = format!("MANAGED_AUTHORITY_TLS_{suffix}");
            if get(&name).is_some_and(|value| value.trim().is_empty()) {
                return Err(format!("{name} cannot be empty"));
            }
        }
        let identity = RemoteTlsIdentityFiles::from_values(
            &get,
            TlsIdentityNames::files("MANAGED_AUTHORITY_TLS"),
            Duration::from_secs(10),
            64,
        )?;
        let address = get(ADDRESS)
            .map(|value| {
                if value.trim() != value || value.contains(['\r', '\n']) {
                    return Err(format!("{ADDRESS} must be a socket address"));
                }
                let address: SocketAddr = value
                    .parse()
                    .map_err(|_| format!("{ADDRESS} must be a socket address"))?;
                if address.port() == 0 {
                    return Err(format!("{ADDRESS} must use a nonzero port"));
                }
                Ok(address)
            })
            .transpose()?;
        match (address, identity) {
            (None, None) => Ok(None),
            (Some(address), Some(identity)) => Ok(Some(Self { address, identity })),
            _ => Err(
                "managed authority HTTPS requires both a listener and a remote TLS identity".into(),
            ),
        }
    }
}

/// TLS construction and socket binding finish before the service becomes ready.
pub struct BoundKeylessHttpsServer {
    listener: std::net::TcpListener,
    tls: RustlsConfig,
    router: Router,
}

impl BoundKeylessHttpsServer {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn bind(
        config: &ManagedAuthorityHttpsConfig,
        router: Router,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let identity = config.identity.connect().await?;
        let tls = RustlsConfig::from_config(mmf_platform::keyless_https_server_config(&identity)?);
        let listener = std::net::TcpListener::bind(config.address)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            tls,
            router,
        })
    }

    pub async fn serve(self, mut shutdown: watch::Receiver<bool>) -> io::Result<()> {
        let handle = Handle::new();
        let server = axum_server::from_tcp_rustls(self.listener, self.tls)?
            .handle(handle.clone())
            .serve(self.router.into_make_service());
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => result,
            () = crate::wait_for_shutdown(&mut shutdown) => {
                handle.graceful_shutdown(Some(Duration::from_secs(15)));
                server.await
            }
        }
    }
}

pub async fn serve_optional(
    server: Option<BoundKeylessHttpsServer>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    match server {
        Some(server) => server.serve(shutdown).await,
        None => {
            crate::wait_for_shutdown(&mut shutdown).await;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn listener_never_accepts_partial_identity_or_private_key_configuration() {
        let parse = |values: &BTreeMap<&str, &str>| {
            ManagedAuthorityHttpsConfig::from_values(|name| values.get(name).copied())
        };
        assert!(parse(&BTreeMap::new()).unwrap().is_none());
        for values in [
            BTreeMap::from([("MANAGED_AUTHORITY_HTTPS_ADDR", "127.0.0.1:8443")]),
            BTreeMap::from([("MANAGED_AUTHORITY_TLS_CERT_FILE", "public.pem")]),
            BTreeMap::from([("MANAGED_AUTHORITY_TLS_KEY_FILE", "private.pem")]),
            BTreeMap::from([("MANAGED_AUTHORITY_HTTPS_ADDR", "")]),
            BTreeMap::from([("MANAGED_AUTHORITY_TLS_CERT_FILE", "")]),
            BTreeMap::from([("MANAGED_AUTHORITY_TLS_KMS_ADDR", " ")]),
        ] {
            assert!(parse(&values).is_err());
        }
        let values = BTreeMap::from([
            ("MANAGED_AUTHORITY_HTTPS_ADDR", "127.0.0.1:8443"),
            ("MANAGED_AUTHORITY_TLS_CERT_FILE", "public.pem"),
            ("MANAGED_AUTHORITY_TLS_KMS_PROVIDER", "openbao-transit"),
            ("MANAGED_AUTHORITY_TLS_KMS_ADDR", "https://kms.example"),
            ("MANAGED_AUTHORITY_TLS_KMS_CA_CERT_FILE", "kms-ca.pem"),
            ("MANAGED_AUTHORITY_TLS_KMS_TOKEN_FILE", "scoped-token"),
            ("MANAGED_AUTHORITY_TLS_KMS_KEY_NAME", "owner-tls"),
            ("MANAGED_AUTHORITY_TLS_KMS_KEY_VERSION", "1"),
        ]);
        assert_eq!(parse(&values).unwrap().unwrap().address.port(), 8443);
        for address in ["127.0.0.1:0", " http://owner:8443", "127.0.0.1:8443\n"] {
            let mut invalid = values.clone();
            invalid.insert("MANAGED_AUTHORITY_HTTPS_ADDR", address);
            assert!(parse(&invalid).is_err());
        }
    }
}
