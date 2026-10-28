//! Shared process and keyless transport mechanics. Service policy stays at callers.

#[cfg(feature = "workload-identity")]
pub mod workload;

use mmf_platform::{KeylessGrpcTlsAcceptor, OpenBaoTlsIdentityFiles, PlatformError};
use std::{io, path::PathBuf, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_stream::{wrappers::TcpListenerStream, Stream, StreamExt};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcServerTls {
    pub certificate: PathBuf,
    pub kms_endpoint: String,
    pub kms_ca_certificate: PathBuf,
    pub kms_token_file: PathBuf,
    pub kms_key_name: String,
    pub kms_key_version: u32,
}

impl GrpcServerTls {
    /// Server-only TLS; callers retain service-token or per-RPC authorization.
    /// Workload mTLS uses a different MMF API and must not use this adapter.
    pub async fn acceptor(&self) -> Result<KeylessGrpcTlsAcceptor, PlatformError> {
        OpenBaoTlsIdentityFiles {
            certificate_chain_file: self.certificate.clone(),
            kms_ca_cert_file: self.kms_ca_certificate.clone(),
            kms_endpoint: self.kms_endpoint.clone(),
            kms_token_file: self.kms_token_file.clone(),
            kms_key_name: self.kms_key_name.clone(),
            kms_key_version: self.kms_key_version,
            request_timeout: Duration::from_secs(10),
            max_concurrent_signs: 64,
        }
        .grpc_acceptor_without_client_auth(64, Duration::from_secs(15))
        .await
    }
}

/// Preserve sequential acceptance, MMF handshake bounds and listener errors.
pub fn keyless_incoming(
    listener: TcpListener,
    acceptor: KeylessGrpcTlsAcceptor,
) -> impl Stream<Item = io::Result<TlsStream<TcpStream>>> {
    TcpListenerStream::new(listener).then(move |connection| {
        let acceptor = acceptor.clone();
        async move {
            match connection {
                Ok(stream) => acceptor.accept(stream).await,
                Err(error) => Err(error),
            }
        }
    })
}

// Keep the existing service-facing API while MMF owns the common mechanics.
pub use mmf_runtime::{shutdown_signal, shutdown_signal_best_effort, wait_for_shutdown};

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::watch;

    #[tokio::test]
    async fn shutdown_waits_through_false_then_exits_on_true() {
        let (tx, mut rx) = watch::channel(false);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), wait_for_shutdown(&mut rx))
                .await
                .is_err()
        );
        tx.send(false).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), wait_for_shutdown(&mut rx))
                .await
                .is_err()
        );
        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), wait_for_shutdown(&mut rx))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_exits_if_sender_is_already_closed() {
        let (tx, mut rx) = watch::channel(false);
        drop(tx);
        tokio::time::timeout(Duration::from_secs(1), wait_for_shutdown(&mut rx))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn absent_public_identity_fails_without_plaintext_fallback() {
        let files = GrpcServerTls {
            certificate: PathBuf::from("/nonexistent/marty-public-chain.pem"),
            kms_endpoint: "https://127.0.0.1:1".into(),
            kms_ca_certificate: PathBuf::from("/nonexistent/marty-ca.pem"),
            kms_token_file: PathBuf::from("/nonexistent/marty-token"),
            kms_key_name: "server-key".into(),
            kms_key_version: 1,
        };
        assert!(files.acceptor().await.is_err());
    }
}
