//! A disposable HTTPS peer whose TLS key remains in OpenBao Transit.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum_server::tls_rustls::RustlsConfig;
use base64::{engine::general_purpose::STANDARD, Engine};
use rustls::{
    pki_types::CertificateDer,
    sign::{CertifiedKey, SigningKey, SingleCertAndKey},
    ServerConfig, SignatureScheme,
};
use serde_json::{json, Value};

use super::issuance_named_peers::{canvas_openbao_client, peer_router, PeerState};

pub(super) struct RemoteTlsPeer {
    pub(super) port: u16,
    pub(super) ca_file: PathBuf,
    pub(super) certificate_file: PathBuf,
    pub(super) token_file: PathBuf,
    pub(super) key_name: String,
    handle: axum_server::Handle<std::net::SocketAddr>,
    task: tokio::task::JoinHandle<()>,
}

fn certificate_der(pem: &str) -> Vec<u8> {
    assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
    assert!(pem.contains("-----END CERTIFICATE-----"));
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD.decode(body).expect("public certificate DER")
}

async fn post(client: &reqwest::Client, url: String, token: &str, body: Value) -> Value {
    client
        .post(url)
        .header("X-Vault-Token", token)
        .json(&body)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap_or(Value::Null)
}

impl RemoteTlsPeer {
    pub(super) async fn start(state: PeerState, directory: &Path) -> Self {
        assert_eq!(
            tokio::runtime::Handle::current().runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread,
            "disposable OpenBao TLS signer requires a multi-thread Tokio runtime"
        );
        let endpoint = std::env::var("MARTY_CANVAS_OPENBAO_URL").unwrap();
        let root = std::env::var("MARTY_CANVAS_OPENBAO_ROOT_TOKEN").unwrap();
        let bao_ca = PathBuf::from(std::env::var("MARTY_CANVAS_OPENBAO_CA_CERT_FILE").unwrap());
        let client = canvas_openbao_client(&bao_ca);
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let key = format!("canvas_grpc_tls_{nonce}");
        let pki = format!("canvas-grpc-pki-{nonce}");
        let policy = format!("canvas-grpc-tls-{nonce}");

        post(
            &client,
            format!("{endpoint}/v1/transit/keys/{key}"),
            &root,
            json!({"type":"ecdsa-p256","exportable":false,"allow_plaintext_backup":false}),
        )
        .await;
        let metadata: Value = client
            .get(format!("{endpoint}/v1/transit/keys/{key}"))
            .header("X-Vault-Token", &root)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(metadata["data"]["type"], "ecdsa-p256");
        assert_eq!(metadata["data"]["exportable"], false);
        assert_eq!(metadata["data"]["allow_plaintext_backup"], false);
        assert_eq!(metadata["data"]["latest_version"], 1);

        post(
            &client,
            format!("{endpoint}/v1/sys/mounts/{pki}"),
            &root,
            json!({"type":"pki"}),
        )
        .await;
        let ca = post(&client, format!("{endpoint}/v1/{pki}/root/generate/internal"), &root,
            json!({"common_name":"Canvas Disposable gRPC CA","ttl":"24h","key_type":"ec","key_bits":256})).await;
        assert!(ca.pointer("/data/private_key").is_none());
        let ca_pem = ca["data"]["certificate"].as_str().unwrap();
        assert!(!ca_pem.contains("PRIVATE KEY"));
        let ca_file = directory.join(format!("canvas-grpc-ca-{nonce}.pem"));
        std::fs::write(&ca_file, ca_pem).unwrap();
        post(
            &client,
            format!("{endpoint}/v1/{pki}/roles/canvas-grpc"),
            &root,
            json!({"allow_any_name":true,"allow_localhost":true,"allow_ip_sans":true,
                   "server_flag":true,"client_flag":true,"key_type":"ec","key_bits":256,
                   "max_ttl":"1h","use_csr_common_name":false}),
        )
        .await;
        let csr = post(
            &client,
            format!("{endpoint}/v1/transit/keys/{key}/csr"),
            &root,
            json!({"version":1}),
        )
        .await;
        let issued = post(
            &client,
            format!("{endpoint}/v1/{pki}/sign/canvas-grpc"),
            &root,
            json!({"csr":csr["data"]["csr"],"common_name":"localhost",
                   "ip_sans":"127.0.0.1","ttl":"1h"}),
        )
        .await;
        assert!(issued.pointer("/data/private_key").is_none());
        assert!(!issued["data"]["certificate"]
            .as_str()
            .unwrap()
            .contains("PRIVATE KEY"));
        let certificate_file = directory.join(format!("canvas-grpc-cert-{nonce}.pem"));
        std::fs::write(
            &certificate_file,
            issued["data"]["certificate"].as_str().unwrap(),
        )
        .unwrap();
        let leaf_der = certificate_der(issued["data"]["certificate"].as_str().unwrap());

        client
            .put(format!("{endpoint}/v1/sys/policies/acl/{policy}"))
            .header("X-Vault-Token", &root)
            .json(&json!({"policy":format!(
                "path \"transit/keys/{key}\" {{ capabilities = [\"read\"] }}\n\
                 path \"transit/sign/{key}\" {{ capabilities = [\"update\"] }}") }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let issued_token = post(
            &client,
            format!("{endpoint}/v1/auth/token/create"),
            &root,
            json!({"policies":[policy],"no_default_policy":true,"ttl":"1h"}),
        )
        .await;
        let token_file = directory.join(format!("canvas-grpc-token-{nonce}"));
        std::fs::write(
            &token_file,
            issued_token["auth"]["client_token"].as_str().unwrap(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let signer = mmf_platform::OpenBaoTlsSigner::connect(
            endpoint,
            certificate_der(&std::fs::read_to_string(&bao_ca).unwrap()),
            key.clone(),
            1,
            token_file.clone(),
            Duration::from_secs(5),
            16,
        )
        .await
        .unwrap();
        let proof = signer
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .expect("disposable TLS key supports P-256")
            .sign(b"canvas-disposable-tls-remote-signing-proof")
            .expect("disposable TLS key signs through scoped OpenBao");
        assert!(!proof.is_empty(), "disposable TLS signature is empty");
        let certified = CertifiedKey::new(vec![CertificateDer::from(leaf_der)], Arc::new(signer));
        certified
            .keys_match()
            .expect("remote TLS key matches public certificate");
        let mut config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = axum_server::Handle::new();
        let shutdown = handle.clone();
        let router = peer_router(state);
        let tls = RustlsConfig::from_config(Arc::new(config));
        let task = tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .unwrap()
                .handle(shutdown)
                .serve(router.into_make_service())
                .await
                .unwrap();
        });
        let probe = reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("disposable TLS peer CA"),
            )
            .no_proxy()
            .https_only(true)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let mut last_error = None;
        for _ in 0..20 {
            match probe
                .get(format!("https://127.0.0.1:{port}/health"))
                .send()
                .await
            {
                Ok(_) => {
                    last_error = None;
                    break;
                }
                Err(error) => {
                    last_error = Some(error);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        assert!(
            last_error.is_none(),
            "disposable TLS peer handshake failed: {last_error:?}"
        );
        Self {
            port,
            ca_file,
            certificate_file,
            token_file,
            key_name: key,
            handle,
            task,
        }
    }

    pub(super) async fn close(self) {
        self.handle.graceful_shutdown(Some(Duration::from_secs(5)));
        tokio::time::timeout(Duration::from_secs(10), self.task)
            .await
            .unwrap()
            .unwrap();
    }
}
