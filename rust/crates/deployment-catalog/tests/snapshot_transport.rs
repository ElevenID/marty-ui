//! Real TLS regression: healthy long streams progress; stalled reads time out.
use marty_openbao_http::OpenBaoHttp;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{path::Path, process::Command, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn server(cert: &Path, key: &Path, pause: Duration) -> (String, tokio::task::JoinHandle<()>) {
    let cert = CertificateDer::from_pem_file(cert).unwrap();
    let key = PrivateKeyDer::from_pem_file(key).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!(
        "https://127.0.0.1:{}",
        listener.local_addr().unwrap().port()
    );
    let handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(tcp)
            .await
            .unwrap();
        let mut bytes = [0u8; 1024];
        let _ = stream.read(&mut bytes).await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        for _ in 0..6 {
            if stream.write_all(b"x").await.is_err() || stream.flush().await.is_err() {
                break;
            }
            tokio::time::sleep(pause).await;
        }
    });
    (endpoint, handle)
}

#[tokio::test]
async fn snapshot_transport_preserves_idle_progress_without_a_total_deadline() {
    let temp = tempfile::tempdir().unwrap();
    let cert = temp.path().join("cert.pem");
    let key = temp.path().join("key.pem");
    let config = temp.path().join("openssl.cnf");
    std::fs::write(&config, "[req]\ndistinguished_name=dn\n[dn]\n").unwrap();
    let output = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
        ])
        .arg("-config")
        .arg(&config)
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let timeout = Duration::from_millis(500);
    // Six reads span longer than the idle allowance while each makes progress.
    let (endpoint, server) = server(&cert, &key, Duration::from_millis(150)).await;
    let client = OpenBaoHttp::connect_with_read_timeout(&endpoint, Some(&cert), timeout).unwrap();
    let started = std::time::Instant::now();
    let response = client.client().get(&endpoint).send().await.unwrap();
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"xxxxxx");
    assert!(started.elapsed() > timeout);
    server.await.unwrap();
    // The existing service constructor retains its total-deadline behavior.
    let (endpoint, server) = self::server(&cert, &key, Duration::from_millis(150)).await;
    let client = OpenBaoHttp::connect(&endpoint, Some(&cert), timeout).unwrap();
    assert!(client
        .client()
        .get(&endpoint)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .is_err());
    server.await.unwrap();
    // A stream that stops progressing still fails promptly.
    let (endpoint, server) = self::server(&cert, &key, Duration::from_millis(750)).await;
    let client = OpenBaoHttp::connect_with_read_timeout(&endpoint, Some(&cert), timeout).unwrap();
    assert!(client
        .client()
        .get(&endpoint)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .is_err());
    server.await.unwrap();
}
