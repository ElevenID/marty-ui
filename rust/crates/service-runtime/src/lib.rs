//! Shared process and keyless transport mechanics. Service policy stays at callers.

#[cfg(feature = "workload-identity")]
pub mod workload;

#[cfg(feature = "forwarded-principal")]
pub mod forwarded_principal;

pub mod config;
mod crypto_provider;
pub mod grpc_request;
#[cfg(feature = "https")]
pub mod https;
mod secret_kms;
pub mod startup;
mod tls;
pub use crypto_provider::install_tls_crypto_provider;
pub use secret_kms::{SecretKmsNames, SecretKmsSelection};
pub use tls::RemoteTlsIdentityFiles as GrpcServerTls;
pub use tls::{
    workload_server_acceptor, RemoteTlsIdentityFiles, TlsConfigError, TlsConfigErrorKind,
    TlsIdentityNames, WorkloadTlsFiles,
};

use mmf_platform::KeylessGrpcTlsAcceptor;
use std::io;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_stream::{wrappers::TcpListenerStream, Stream, StreamExt};

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
    use mmf_platform::OpenBaoTlsIdentityFiles;
    use std::{path::PathBuf, time::Duration};
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
        let files = GrpcServerTls::OpenBao(OpenBaoTlsIdentityFiles {
            certificate_chain_file: PathBuf::from("/nonexistent/marty-public-chain.pem"),
            kms_endpoint: "https://127.0.0.1:1".into(),
            kms_ca_cert_file: PathBuf::from("/nonexistent/marty-ca.pem"),
            kms_token_file: PathBuf::from("/nonexistent/marty-token"),
            kms_key_name: "server-key".into(),
            kms_key_version: 1,
            request_timeout: Duration::from_secs(10),
            max_concurrent_signs: 64,
        });
        assert!(files.acceptor().await.is_err());
    }
}
