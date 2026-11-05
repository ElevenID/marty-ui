use std::{process::Command, sync::Arc};
use tokio_rustls::rustls;

/// A fresh process prevents another TLS test from installing a provider and
/// hiding the startup failure that affected the released Kubernetes workloads.
#[test]
fn explicit_provider_precedes_tls_configuration() {
    const CHILD: &str = "MARTY_TLS_PROVIDER_REGRESSION_CHILD";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "explicit_provider_precedes_tls_configuration"])
            .env(CHILD, "1")
            .output()
            .expect("run isolated TLS startup regression");
        assert!(
            output.status.success(),
            "TLS startup regression failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    // Both references must compile: this test deliberately retains both
    // providers instead of making the failure disappear through feature flags.
    let _ = rustls::crypto::ring::default_provider();
    let _ = rustls::crypto::aws_lc_rs::default_provider();
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());
    assert!(std::panic::catch_unwind(|| {
        let _ = rustls::ClientConfig::builder();
    })
    .is_err());
    assert!(rustls::crypto::CryptoProvider::get_default().is_none());

    marty_service_runtime::install_tls_crypto_provider();
    let selected = rustls::crypto::CryptoProvider::get_default()
        .expect("explicit process provider")
        .clone();
    marty_service_runtime::install_tls_crypto_provider();
    assert!(Arc::ptr_eq(
        &selected,
        rustls::crypto::CryptoProvider::get_default().expect("provider retained")
    ));

    let _client = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let _server = rustls::ServerConfig::builder().with_no_client_auth();
}
