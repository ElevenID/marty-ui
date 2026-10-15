//! Disposable HTTPS peer for tests of external KMS transport policy.

use axum::Router;
use tempfile::NamedTempFile;
use tokio::task::JoinHandle;

pub struct TestHttpsServer {
    pub endpoint: String,
    pub ca_file: NamedTempFile,
    task: JoinHandle<()>,
}

impl TestHttpsServer {
    pub async fn start(app: Router) -> Self {
        Self::start_with(|_| app).await
    }

    pub async fn start_with(build: impl FnOnce(&str) -> Router) -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let ca_file = NamedTempFile::new().unwrap();
        std::fs::write(ca_file.path(), certified.cert.pem()).unwrap();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            certified.cert.pem().into_bytes(),
            certified.signing_key.serialize_pem().into_bytes(),
        )
        .await
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("https://{}", listener.local_addr().unwrap());
        let app = build(&endpoint);
        let task = tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .unwrap()
                .serve(app.into_make_service())
                .await
                .unwrap();
        });
        Self {
            endpoint,
            ca_file,
            task,
        }
    }
}

impl Drop for TestHttpsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
