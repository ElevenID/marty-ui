use super::*;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{collections::BTreeMap, process::Command, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn certificate(root: &Path, name: &str, dns: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let cert = root.join(format!("{name}.pem"));
    let key = root.join(format!("{name}.key"));
    let config = root.join("openssl.cnf");
    std::fs::write(&config, "[req]\ndistinguished_name=dn\n[dn]\n").unwrap();
    let output = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            &format!("subjectAltName=DNS:{dns}"),
            "-addext",
            "basicConstraints=critical,CA:FALSE",
        ])
        .arg("-config")
        .arg(config)
        .arg("-keyout")
        .arg(&key)
        .arg("-out")
        .arg(&cert)
        .output()
        .unwrap();
    assert!(output.status.success());
    (cert, key)
}
async fn serve(
    cert: &Path,
    key: &Path,
    response: Vec<u8>,
    delay: Duration,
) -> (TrustInfo, tokio::task::JoinHandle<()>) {
    serve_observed(
        cert,
        key,
        response,
        delay,
        Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    )
    .await
}
async fn serve_observed(
    cert: &Path,
    key: &Path,
    response: Vec<u8>,
    delay: Duration,
    requests: Arc<std::sync::atomic::AtomicUsize>,
) -> (TrustInfo, tokio::task::JoinHandle<()>) {
    let der = CertificateDer::from_pem_file(cert).unwrap();
    let fingerprint = format!("{:x}", Sha256::digest(&der));
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![der], PrivateKeyDer::from_pem_file(key).unwrap())
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        if let Ok(mut stream) = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(tcp)
            .await
        {
            let mut request = [0; 4096];
            if stream.read(&mut request).await.is_ok_and(|count| count > 0) {
                requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            tokio::time::sleep(delay).await;
            let _ = stream.write_all(&response).await;
            let _ = stream.shutdown().await;
        }
    });
    (
        TrustInfo {
            schema: "test",
            installation_id: "test".into(),
            origin,
            ca_certificate_pem: std::fs::read_to_string(cert).unwrap(),
            ca_der_sha256: fingerprint.clone(),
            certificate_der_sha256: fingerprint,
            ca_expires_at: 0,
            certificate_expires_at: 0,
            recorded_token_expires_at: 0,
            evidence_sha256: BTreeMap::new(),
            recorded_startup_containers: 0,
            runtime_observed: false,
            host_trust_observed: false,
            host_trust_modified: false,
            installation_ready: false,
            pending: vec![],
        },
        handle,
    )
}

#[tokio::test]
async fn wrong_leaf_is_rejected_before_an_authenticated_request_is_sent() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let root = tempfile::tempdir().unwrap();
    let (cert, key) = certificate(root.path(), "localhost", "localhost");
    let requests = Arc::new(AtomicUsize::new(0));
    let (mut trust, task) = serve_observed(
        &cert,
        &key,
        response(b"{}"),
        Duration::ZERO,
        requests.clone(),
    )
    .await;
    // The CA and hostname remain trusted. The recorded leaf alone is wrong.
    trust.certificate_der_sha256 = "0".repeat(64);
    assert!(client(&trust)
        .unwrap()
        .get(format!("{}/v1/signing-keys/config", trust.origin))
        .header("X-API-Key", "mk_test_never_transmit_to_wrong_leaf")
        .send()
        .await
        .is_err());
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn bound_transport_accepts_a_recorded_leaf_from_the_second_ca_in_a_bundle() {
    let root = tempfile::tempdir().unwrap();
    let (first, _) = certificate(root.path(), "previous-ca", "previous.invalid");
    let (cert, key) = certificate(root.path(), "localhost", "localhost");
    let (mut trust, task) = serve(&cert, &key, response(b"{}"), Duration::ZERO).await;
    trust.ca_certificate_pem = format!(
        "{}\n{}",
        std::fs::read_to_string(first).unwrap(),
        trust.ca_certificate_pem
    );
    let observed = get(&client(&trust).unwrap(), &trust, "/health").await;
    assert!(observed.tls_verified && observed.document.is_some());
    task.abort();
}
fn response(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}
#[tokio::test]
async fn real_tls_accepts_bound_leaf_and_refuses_wrong_leaf_ca_or_hostname() {
    let root = tempfile::tempdir().unwrap();
    let (cert, key) = certificate(root.path(), "localhost", "localhost");
    let (foreign, foreign_key) = certificate(root.path(), "foreign", "foreign.invalid");
    for case in 0..4 {
        let (c, k) = if case == 3 {
            (&foreign, &foreign_key)
        } else {
            (&cert, &key)
        };
        let (mut trust, task) =
            serve(c, k, response(b"{\"status\":\"healthy\"}"), Duration::ZERO).await;
        if case == 1 {
            trust.certificate_der_sha256 = "0".repeat(64);
        }
        if case == 2 {
            trust.ca_certificate_pem = std::fs::read_to_string(&foreign).unwrap();
        }
        let observed = get(&client(&trust).unwrap(), &trust, "/health").await;
        assert_eq!(observed.tls_verified, case == 0);
        assert_eq!(observed.document.is_some(), case == 0);
        task.abort();
    }
}
#[tokio::test]
async fn redirects_invalid_json_and_oversize_are_not_successful_checks() {
    let root = tempfile::tempdir().unwrap();
    let (cert, key) = certificate(root.path(), "localhost", "localhost");
    let mut chunked =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n10001\r\n"
            .to_vec();
    chunked.extend(vec![b'x'; 65537]);
    chunked.extend_from_slice(b"\r\n0\r\n\r\n");
    for bytes in [b"HTTP/1.1 302 Found\r\nLocation: https://foreign.invalid/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
        response(b"not-json-secret"),response(&vec![b'x';MAX_BODY+1]),chunked] {
        let (trust, task) = serve(&cert,&key,bytes,Duration::ZERO).await;
        let observed = get(&client(&trust).unwrap(), &trust, "/health").await;
        assert!(observed.tls_verified);
        assert!(observed.document.is_none());
        task.abort();
    }
}
#[tokio::test]
async fn stalled_https_is_bounded() {
    let root = tempfile::tempdir().unwrap();
    let (cert, key) = certificate(root.path(), "localhost", "localhost");
    let (trust, task) = serve(&cert, &key, response(b"{}"), Duration::from_secs(20)).await;
    let started = Instant::now();
    assert!(get(&client(&trust).unwrap(), &trust, "/health")
        .await
        .document
        .is_none());
    assert!(started.elapsed() < Duration::from_secs(8));
    task.abort();
}

#[tokio::test]
async fn proxy_and_ambient_ca_environment_do_not_override_bound_transport() {
    const CHILD: &str = "MARTY_VALIDATION_PROXY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "installer_validation::transport_tests::proxy_and_ambient_ca_environment_do_not_override_bound_transport"])
            .env(CHILD,"1").env("HTTPS_PROXY","http://127.0.0.1:1")
            .env("ALL_PROXY","http://127.0.0.1:1").env("SSL_CERT_FILE","/missing/ambient-ca.pem")
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (cert, key) = certificate(root.path(), "localhost", "localhost");
    let (trust, task) = serve(&cert, &key, response(b"{}"), Duration::ZERO).await;
    assert!(get(&client(&trust).unwrap(), &trust, "/health")
        .await
        .document
        .is_some());
    task.abort();
}
