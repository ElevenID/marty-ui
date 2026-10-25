//! Shared process and keyless transport mechanics. Service policy stays at callers.

use mmf_platform::{KeylessGrpcTlsAcceptor, OpenBaoTlsIdentityFiles, PlatformError};
use std::{io, path::PathBuf, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
};
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

/// A closed sender also ends graceful shutdown, matching existing service loops.
pub async fn wait_for_shutdown(shutdown: &mut watch::Receiver<bool>) {
    while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
}

/// Match services that fail startup if installing a signal handler fails.
pub async fn shutdown_signal() {
    signal(false).await;
}

/// Match services whose existing policy returns on signal installation errors.
pub async fn shutdown_signal_best_effort() {
    signal(true).await;
}

async fn signal(best_effort: bool) {
    let ctrl_c = async {
        let result = tokio::signal::ctrl_c().await;
        if !best_effort {
            result.expect("failed to install Ctrl+C handler");
        }
    };
    #[cfg(unix)]
    let terminate = async {
        let result = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        if best_effort {
            if let Ok(mut signal) = result {
                signal.recv().await;
            }
        } else {
            result
                .expect("failed to install SIGTERM handler")
                .recv()
                .await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = terminate => {} }
}

#[cfg(test)]
mod tests {
    use super::*;

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
