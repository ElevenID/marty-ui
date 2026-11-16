/// Select the process-wide rustls provider before constructing any TLS client
/// or server, including Redis clients and migration-only startup paths.
///
/// The released binaries link dependencies that enable both ring and AWS-LC;
/// rustls cannot choose a default from that feature combination. Match the
/// existing signing service's AWS-LC choice, while preserving a provider that
/// an embedding process has already installed.
pub fn install_tls_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
}
