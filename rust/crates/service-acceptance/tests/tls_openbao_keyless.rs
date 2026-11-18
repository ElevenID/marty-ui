//! Opt-in proof that Rustls' signing boundary can use a non-exportable OpenBao
//! Transit key. Server TLS and mTLS handshakes use no private-key PEM;
//! production service integration follows.

use std::{
    fmt,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine};
use rustls::{
    pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer},
    server::WebPkiClientVerifier,
    sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey},
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection,
    SignatureAlgorithm, SignatureScheme, StreamOwned,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

struct OpenBaoTlsKey {
    client: reqwest::blocking::Client,
    endpoint: String,
    token: String,
    key_name: String,
    version: u32,
    public_spki_der: Vec<u8>,
}

impl fmt::Debug for OpenBaoTlsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenBaoTlsKey")
            .field("key_name", &self.key_name)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl SigningKey for OpenBaoTlsKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| Box::new(self.clone_for_handshake()) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(
            self.public_spki_der.as_slice(),
        ))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl OpenBaoTlsKey {
    fn clone_for_handshake(&self) -> Self {
        Self {
            client: self.client.clone(),
            endpoint: self.endpoint.clone(),
            token: self.token.clone(),
            key_name: self.key_name.clone(),
            version: self.version,
            public_spki_der: self.public_spki_der.clone(),
        }
    }

    fn remote_sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let input = STANDARD.encode(Sha256::digest(message));
        let url = format!("{}/v1/transit/sign/{}", self.endpoint, self.key_name);
        let response: Value = self
            .client
            .post(url)
            .header("X-Vault-Token", &self.token)
            .json(&json!({
                "input": input,
                "prehashed": true,
                "hash_algorithm": "sha2-256",
                "marshaling_algorithm": "asn1",
                "key_version": self.version
            }))
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(reqwest::blocking::Response::json)
            .map_err(|_| rustls::Error::General("remote TLS signing unavailable".into()))?;
        let signature = response
            .pointer("/data/signature")
            .and_then(Value::as_str)
            .and_then(|value| value.strip_prefix(&format!("vault:v{}:", self.version)))
            .ok_or_else(|| {
                rustls::Error::General("remote TLS signature version mismatch".into())
            })?;
        STANDARD
            .decode(signature)
            .map_err(|_| rustls::Error::General("remote TLS signature is invalid".into()))
    }
}

impl Signer for OpenBaoTlsKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::task::block_in_place(|| self.remote_sign(message))
        } else {
            self.remote_sign(message)
        }
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

fn guarded_openbao() -> (String, String, reqwest::blocking::Client) {
    let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let parsed = url::Url::parse(&endpoint).expect("disposable OpenBao URL syntax");
    assert!(
        matches!(parsed.scheme(), "http" | "https") && parsed.host_str() == Some("127.0.0.1"),
        "TLS signer proof requires a loopback disposable OpenBao instance"
    );
    let token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable OpenBao token");
    let nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE")
        .expect("disposable OpenBao marker nonce");
    assert!(nonce.len() >= 16, "disposable marker nonce is too short");
    let mut builder = reqwest::blocking::Client::builder().timeout(Duration::from_secs(5));
    if parsed.scheme() == "https" {
        let ca_file = std::env::var("MARTY_TEST_OPENBAO_CA_CERT_FILE")
            .expect("disposable OpenBao public CA file");
        let ca_pem = std::fs::read(ca_file).expect("public OpenBao CA certificate");
        builder = builder.add_root_certificate(
            reqwest::Certificate::from_pem(&ca_pem).expect("public OpenBao CA certificate PEM"),
        );
    }
    let client = builder.build().unwrap();
    let marker: Value = client
        .get(format!(
            "{endpoint}/v1/secret/data/marty-test-disposable-guard"
        ))
        .header("X-Vault-Token", &token)
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(
        marker.pointer("/data/data/nonce").and_then(Value::as_str),
        Some(nonce.as_str()),
        "OpenBao is not the marked disposable instance"
    );
    (endpoint.trim_end_matches('/').into(), token, client)
}

fn provision_key(
    endpoint: &str,
    token: &str,
    client: &reqwest::blocking::Client,
    key_name: &str,
) -> Vec<u8> {
    let created = client
        .post(format!("{endpoint}/v1/transit/keys/{key_name}"))
        .header("X-Vault-Token", token)
        .json(&json!({
            "type": "ecdsa-p256",
            "exportable": false,
            "allow_plaintext_backup": false
        }))
        .send()
        .unwrap();
    assert!(created.status().is_success(), "Transit key creation failed");
    let metadata: Value = client
        .get(format!("{endpoint}/v1/transit/keys/{key_name}"))
        .header("X-Vault-Token", token)
        .send()
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(metadata["data"]["type"], "ecdsa-p256");
    assert_eq!(metadata["data"]["exportable"], false);
    assert_eq!(metadata["data"]["allow_plaintext_backup"], false);
    let public_pem = metadata["data"]["keys"]["1"]["public_key"]
        .as_str()
        .expect("Transit public key PEM");
    let base64_body: String = public_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD.decode(base64_body).expect("public SPKI DER")
}

fn pem_certificate_der(pem: &str) -> Vec<u8> {
    assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
    assert!(pem.contains("-----END CERTIFICATE-----"));
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD.decode(body).expect("public certificate DER")
}

fn post_json(
    client: &reqwest::blocking::Client,
    endpoint: &str,
    token: &str,
    path: &str,
    body: Value,
) -> Value {
    client
        .post(format!("{endpoint}/v1/{path}"))
        .header("X-Vault-Token", token)
        .json(&body)
        .send()
        .expect("disposable OpenBao request")
        .error_for_status()
        .expect("disposable OpenBao operation")
        .json()
        .unwrap_or(Value::Null)
}

fn issue_tls_certificate(signer: &OpenBaoTlsKey) -> (Vec<u8>, Vec<u8>, String) {
    let mount = format!("pki-tls-proof-{}", uuid::Uuid::new_v4().simple());
    post_json(
        &signer.client,
        &signer.endpoint,
        &signer.token,
        &format!("sys/mounts/{mount}"),
        json!({"type": "pki"}),
    );
    let ca = post_json(
        &signer.client,
        &signer.endpoint,
        &signer.token,
        &format!("{mount}/root/generate/internal"),
        json!({
            "common_name": "Marty Disposable TLS CA",
            "ttl": "48h",
            "key_type": "ec",
            "key_bits": 256
        }),
    );
    assert!(ca.pointer("/data/private_key").is_none());
    let ca_pem = ca["data"]["certificate"]
        .as_str()
        .expect("public CA certificate");
    post_json(
        &signer.client,
        &signer.endpoint,
        &signer.token,
        &format!("{mount}/roles/tls-proof"),
        json!({
            "allow_any_name": true,
            "allow_localhost": true,
            "server_flag": true,
            "client_flag": true,
            "key_type": "ec",
            "key_bits": 256,
            "max_ttl": "24h",
            "use_csr_common_name": false
        }),
    );
    let leaf_der = issue_leaf_certificate(signer, &mount, "localhost");
    (leaf_der, pem_certificate_der(ca_pem), mount)
}

fn issue_leaf_certificate(signer: &OpenBaoTlsKey, mount: &str, common_name: &str) -> Vec<u8> {
    let csr = post_json(
        &signer.client,
        &signer.endpoint,
        &signer.token,
        &format!("transit/keys/{}/csr", signer.key_name),
        json!({"version": signer.version}),
    );
    let csr_pem = csr["data"]["csr"].as_str().expect("Transit-signed CSR");
    let issued = post_json(
        &signer.client,
        &signer.endpoint,
        &signer.token,
        &format!("{mount}/sign/tls-proof"),
        json!({"csr": csr_pem, "common_name": common_name, "ttl": "1h"}),
    );
    assert!(issued.pointer("/data/private_key").is_none());
    let leaf_pem = issued["data"]["certificate"]
        .as_str()
        .expect("public TLS certificate");
    pem_certificate_der(leaf_pem)
}

fn complete_tls_handshake(
    signer: Arc<dyn SigningKey>,
    leaf_der: Vec<u8>,
    ca_der: Vec<u8>,
    require_client_auth: bool,
    client_identity: Option<(Arc<dyn SigningKey>, Vec<u8>)>,
    server_name: &str,
    expect_success: bool,
) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certified = CertifiedKey::new(vec![CertificateDer::from(leaf_der)], signer);
    certified
        .keys_match()
        .expect("certificate must match remote KMS key");
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_der))
        .expect("public CA certificate");
    let server_resolver = Arc::new(SingleCertAndKey::from(certified));
    let server_config = if require_client_auth {
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots.clone()))
            .build()
            .expect("public client CA verifier");
        ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(server_resolver)
    } else {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(server_resolver)
    };
    let client_builder = ClientConfig::builder().with_root_certificates(roots);
    let client_config = if let Some((client_signer, client_leaf_der)) = client_identity {
        let client_certified =
            CertifiedKey::new(vec![CertificateDer::from(client_leaf_der)], client_signer);
        client_certified
            .keys_match()
            .expect("client certificate must match remote KMS key");
        client_builder.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(client_certified)))
    } else {
        client_builder.with_no_client_auth()
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let connection = ServerConnection::new(Arc::new(server_config)).unwrap();
        let mut tls = StreamOwned::new(connection, stream);
        tls.write_all(b"remote-key TLS").and_then(|()| tls.flush())
    });
    let stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let server_name = ServerName::try_from(server_name).unwrap().to_owned();
    let connection = ClientConnection::new(Arc::new(client_config), server_name).unwrap();
    let mut tls = StreamOwned::new(connection, stream);
    let mut received = [0_u8; 14];
    let client_result = tls.read_exact(&mut received);
    let server_result = server.join().unwrap();
    if expect_success {
        client_result.expect("TLS client validates the remote-key certificate");
        server_result.expect("remote KMS signs the TLS handshake");
        assert_eq!(&received, b"remote-key TLS");
    } else {
        assert!(client_result.is_err(), "TLS client must fail closed");
        assert!(server_result.is_err(), "TLS server must fail closed");
    }
}

async fn complete_tonic_grpc_mtls(
    server_signer: OpenBaoTlsKey,
    client_signer: OpenBaoTlsKey,
    server_leaf_der: Vec<u8>,
    client_leaf_der: Vec<u8>,
    ca_der: Vec<u8>,
) {
    let server_identity =
        mmf_platform::KeylessTlsIdentity::new(vec![server_leaf_der], Arc::new(server_signer))
            .expect("keyless gRPC server identity");
    let client_identity =
        mmf_platform::KeylessTlsIdentity::new(vec![client_leaf_der], Arc::new(client_signer))
            .expect("keyless gRPC client identity");
    let acceptor = mmf_platform::KeylessGrpcTlsAcceptor::new(
        &server_identity,
        vec![ca_der.clone()],
        2,
        Duration::from_secs(5),
    )
    .expect("keyless gRPC acceptor");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sender, incoming) = tokio::sync::mpsc::channel(2);
    let accept_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            if let Ok(encrypted) = acceptor.accept(stream).await {
                if sender
                    .send(Ok::<_, std::io::Error>(encrypted))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    });
    let (_, health_service) = tonic_health::server::health_reporter();
    let server_task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(health_service)
            .serve_with_incoming(tokio_stream::wrappers::ReceiverStream::new(incoming))
            .await
    });
    let factory = mmf_platform::KeylessGrpcChannelFactory::new(
        &format!("https://127.0.0.1:{port}"),
        "localhost",
        &client_identity,
        vec![ca_der.clone()],
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .expect("keyless gRPC channel configuration");
    let channel = factory.connect().await.expect("keyless gRPC connection");
    let mut client = tonic_health::pb::health_client::HealthClient::new(channel);
    let response = client
        .check(tonic::Request::new(tonic_health::pb::HealthCheckRequest {
            service: String::new(),
        }))
        .await
        .expect("authenticated keyless gRPC health response")
        .into_inner();
    assert_eq!(response.status, 1);
    let wrong_host = mmf_platform::KeylessGrpcChannelFactory::new(
        &format!("https://127.0.0.1:{port}"),
        "wrong.example",
        &client_identity,
        vec![ca_der.clone()],
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .expect("wrong-host channel configuration");
    assert!(wrong_host.connect().await.is_err());
    let ca_pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        STANDARD.encode(&ca_der)
    );
    let public_client = |port| {
        mmf_platform::GrpcChannelFactory::new(
            mmf_platform::GrpcChannelConfig {
                target: format!("https://127.0.0.1:{port}"),
                security: mmf_platform::GrpcTransportSecurity::ServerTls,
                trust: mmf_platform::GrpcTrustMode::CustomCa,
                server_name: Some("localhost".into()),
                ..mmf_platform::GrpcChannelConfig::default()
            },
            mmf_platform::GrpcTlsMaterial {
                ca_certificate_pem: Some(ca_pem.as_bytes().to_vec()),
            },
        )
        .expect("public-CA gRPC client configuration")
    };
    if let Ok(channel) = public_client(port).connect().await {
        let result = tonic_health::pb::health_client::HealthClient::new(channel)
            .check(tonic::Request::new(tonic_health::pb::HealthCheckRequest {
                service: String::new(),
            }))
            .await;
        assert!(
            result.is_err(),
            "mTLS listener must reject a request without a client certificate"
        );
    }
    accept_task.abort();
    server_task.abort();

    let server_only = mmf_platform::KeylessGrpcTlsAcceptor::without_client_auth(
        &server_identity,
        2,
        Duration::from_secs(5),
    )
    .expect("keyless server-only gRPC acceptor");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_only_port = listener.local_addr().unwrap().port();
    let (sender, incoming) = tokio::sync::mpsc::channel(2);
    let accept_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            if let Ok(encrypted) = server_only.accept(stream).await {
                if sender
                    .send(Ok::<_, std::io::Error>(encrypted))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    });
    let (_, health_service) = tonic_health::server::health_reporter();
    let server_task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(health_service)
            .serve_with_incoming(tokio_stream::wrappers::ReceiverStream::new(incoming))
            .await
    });
    let channel = public_client(server_only_port)
        .connect()
        .await
        .expect("public-CA client connects without a private key");
    let response = tonic_health::pb::health_client::HealthClient::new(channel)
        .check(tonic::Request::new(tonic_health::pb::HealthCheckRequest {
            service: String::new(),
        }))
        .await
        .expect("server-only keyless gRPC health response");
    assert_eq!(response.into_inner().status, 1);
    accept_task.abort();
    server_task.abort();
}

#[test]
#[ignore = "requires an independently marked disposable OpenBao instance"]
fn rustls_signer_uses_non_exportable_openbao_key_and_fails_closed() {
    let (endpoint, token, client) = guarded_openbao();
    let key_name = format!("tls-proof-{}", uuid::Uuid::new_v4().simple());
    let public_spki_der = provision_key(&endpoint, &token, &client, &key_name);
    let signer = OpenBaoTlsKey {
        client,
        endpoint,
        token,
        key_name,
        version: 1,
        public_spki_der,
    };
    assert!(signer.choose_scheme(&[SignatureScheme::ED25519]).is_none());
    let selected = signer
        .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
        .expect("matching TLS signature scheme");
    let handshake_message = b"disposable rustls handshake signing bytes";
    let signature = selected.sign(handshake_message).expect("Transit signature");
    assert!(marty_crypto::ecdsa::verify_p256_sha256(
        &signer.public_spki_der,
        handshake_message,
        &signature
    )
    .unwrap());
    assert!(!marty_crypto::ecdsa::verify_p256_sha256(
        &signer.public_spki_der,
        b"changed handshake signing bytes",
        &signature
    )
    .unwrap());
    let mut unavailable = signer.clone_for_handshake();
    unavailable.endpoint = "http://127.0.0.1:1".into();
    assert!(unavailable.sign(handshake_message).is_err());
    let (leaf_der, ca_der, ca_mount) = issue_tls_certificate(&signer);
    if signer.endpoint.starts_with("https://") {
        let bao_ca_pem = std::fs::read_to_string(
            std::env::var("MARTY_TEST_OPENBAO_CA_CERT_FILE")
                .expect("disposable OpenBao public CA file"),
        )
        .unwrap();
        let token_directory = tempfile::tempdir().unwrap();
        let token_file = token_directory.path().join("scoped-tls-token");
        std::fs::write(&token_file, &signer.token).unwrap();
        let production = mmf_platform::OpenBaoTlsSigner::new(
            &signer.endpoint,
            &pem_certificate_der(&bao_ca_pem),
            &signer.key_name,
            1,
            token_file.clone(),
            Duration::from_secs(5),
            2,
        )
        .expect("production OpenBao TLS signer loads non-exportable metadata");
        let signature = production
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .unwrap()
            .sign(handshake_message)
            .expect("production TLS signer uses the pinned Transit key");
        assert!(marty_crypto::ecdsa::verify_p256_sha256(
            &signer.public_spki_der,
            handshake_message,
            &signature
        )
        .unwrap());
        complete_tls_handshake(
            Arc::new(production.clone()),
            leaf_der.clone(),
            ca_der.clone(),
            false,
            None,
            "localhost",
            true,
        );
        std::fs::write(&token_file, "denied-disposable-token").unwrap();
        complete_tls_handshake(
            Arc::new(production.clone()),
            leaf_der.clone(),
            ca_der.clone(),
            false,
            None,
            "localhost",
            false,
        );
        std::fs::remove_file(token_file).unwrap();
        complete_tls_handshake(
            Arc::new(production),
            leaf_der.clone(),
            ca_der.clone(),
            false,
            None,
            "localhost",
            false,
        );
    }
    let wrong_key_name = format!("tls-wrong-key-{}", uuid::Uuid::new_v4().simple());
    let wrong_spki = provision_key(
        &signer.endpoint,
        &signer.token,
        &signer.client,
        &wrong_key_name,
    );
    let mut mismatched = signer.clone_for_handshake();
    mismatched.key_name = wrong_key_name;
    mismatched.public_spki_der = wrong_spki;
    let wrong_certified = CertifiedKey::new(
        vec![CertificateDer::from(leaf_der.clone())],
        Arc::new(mismatched),
    );
    assert!(wrong_certified.keys_match().is_err());
    complete_tls_handshake(
        Arc::new(signer.clone_for_handshake()),
        leaf_der.clone(),
        ca_der.clone(),
        false,
        None,
        "localhost",
        true,
    );
    complete_tls_handshake(
        Arc::new(unavailable),
        leaf_der.clone(),
        ca_der.clone(),
        false,
        None,
        "localhost",
        false,
    );
    complete_tls_handshake(
        Arc::new(signer.clone_for_handshake()),
        leaf_der.clone(),
        ca_der.clone(),
        false,
        None,
        "wrong.example",
        false,
    );
    let client_key_name = format!("tls-client-{}", uuid::Uuid::new_v4().simple());
    let client_spki = provision_key(
        &signer.endpoint,
        &signer.token,
        &signer.client,
        &client_key_name,
    );
    let mut client_signer = signer.clone_for_handshake();
    client_signer.key_name = client_key_name;
    client_signer.public_spki_der = client_spki;
    let client_leaf_der = issue_leaf_certificate(&client_signer, &ca_mount, "marty-client");
    complete_tls_handshake(
        Arc::new(signer.clone_for_handshake()),
        leaf_der.clone(),
        ca_der.clone(),
        true,
        Some((
            Arc::new(client_signer.clone_for_handshake()),
            client_leaf_der.clone(),
        )),
        "localhost",
        true,
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(complete_tonic_grpc_mtls(
        signer.clone_for_handshake(),
        client_signer,
        leaf_der.clone(),
        client_leaf_der,
        ca_der.clone(),
    ));
    complete_tls_handshake(
        Arc::new(signer),
        leaf_der,
        ca_der,
        true,
        None,
        "localhost",
        false,
    );
}
