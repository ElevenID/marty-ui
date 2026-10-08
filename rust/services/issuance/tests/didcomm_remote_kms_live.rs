//! Opt-in proof against a disposable OpenBao with the DIDComm plugin mounted.
//! The sender secret is generated and retained only inside OpenBao. The holder
//! key exists only in this test process to exercise independent decryption.

use std::{io::Write, path::PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_didcomm::DidDocument;
#[path = "support/didcomm_test_fixtures.rs"]
mod didcomm_test_fixtures;
use marty_issuance_service::{
    didcomm_remote_kms::{DidcommKeyReference, RemoteDidcommKms},
    initiation_didcomm::NativeDidcommEnvelope,
};
use rand::random;
use reqwest::Client;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

#[tokio::test]
#[ignore = "requires disposable MARTY_TEST_OPENBAO_URL and MARTY_TEST_OPENBAO_TOKEN with the didcomm plugin mounted"]
async fn issuer_authcrypt_uses_scoped_openbao_key_and_holder_decrypts_after_rotation() {
    let base = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let root_token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable root token");
    let client = Client::builder().no_proxy().build().unwrap();
    let tenant = format!("org_{}", uuid::Uuid::new_v4().simple());
    let name = "issuer";
    let sender_did = "did:web:issuer.example";
    let sender_kid = format!("{sender_did}#key-1");
    let create: Value = client
        .post(format!("{base}/v1/didcomm/keys/{tenant}/{name}"))
        .header("X-Vault-Token", &root_token)
        .json(&json!({"sender_did":sender_did,"sender_key_id":sender_kid}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let version = create["data"]["version"].as_str().unwrap();
    let sender_public = create["data"]["public_key"].as_str().unwrap();
    let reference = format!("didcomm/keys/{tenant}/{name}/versions/{version}");
    DidcommKeyReference::parse(&reference).unwrap();

    // A policy token has only public-version read and exact-version pack.
    let policy_name = format!("didcomm-test-{}", uuid::Uuid::new_v4().simple());
    let policy = format!(
        "path \"didcomm/keys/{tenant}/{name}/versions/{version}\" {{ capabilities = [\"read\"] }}\n\
         path \"didcomm/pack/{tenant}/{name}/{version}\" {{ capabilities = [\"update\"] }}"
    );
    client
        .put(format!("{base}/v1/sys/policies/acl/{policy_name}"))
        .header("X-Vault-Token", &root_token)
        .json(&json!({"policy":policy}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    let issued: Value = client
        .post(format!("{base}/v1/auth/token/create"))
        .header("X-Vault-Token", &root_token)
        .json(&json!({"policies":[policy_name],"no_default_policy":true,"ttl":"10m"}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let scoped_token = issued["auth"]["client_token"].as_str().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let token_file = temp.path().join("openbao-token");
    let mut file = std::fs::File::create(&token_file).unwrap();
    writeln!(file, "{scoped_token}").unwrap();
    drop(file);
    let denied = client
        .post(format!("{base}/v1/didcomm/keys/{tenant}/forbidden"))
        .header("X-Vault-Token", scoped_token)
        .json(&json!({"sender_did":sender_did,"sender_key_id":sender_kid}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status().as_u16(), 403);

    let sender_document: DidDocument = serde_json::from_value(json!({
        "id": sender_did,
        "verificationMethod": [
            {"id":sender_kid,"type":"JsonWebKey2020","controller":sender_did,
             "publicKeyJwk":{"kty":"OKP","crv":"X25519","x":sender_public}},
            {"id":format!("{sender_did}#signing-1"),"type":"JsonWebKey2020",
             "controller":sender_did,"publicKeyJwk":{"kty":"OKP","crv":"Ed25519",
             "x":URL_SAFE_NO_PAD.encode([1_u8;32])}}
        ],
        "keyAgreement":[sender_kid],
        "assertionMethod":[format!("{sender_did}#signing-1")]
    }))
    .unwrap();
    let holder_secret: [u8; 32] = random();
    let holder_public = x25519(holder_secret, X25519_BASEPOINT_BYTES);
    let holder_did = "did:example:holder";
    let holder_document: DidDocument = serde_json::from_value(json!({
        "id": holder_did,
        "verificationMethod":[{"id":format!("{holder_did}#key-1"),
            "type":"JsonWebKey2020","controller":holder_did,
            "publicKeyJwk":{"kty":"OKP","crv":"X25519",
                "x":URL_SAFE_NO_PAD.encode(holder_public)}}],
        "keyAgreement":[format!("{holder_did}#key-1")]
    }))
    .unwrap();
    let resolver_url = serve_sender_document_once(&sender_document).await;
    let policy_path = temp.path().join("didcomm-encryption-policy.json");
    std::fs::write(
        &policy_path,
        json!({"version":1,"issuers":{(sender_did):
            {"mode":"authcrypt","sender_key_ref":reference}}})
        .to_string(),
    )
    .unwrap();
    let kms = RemoteDidcommKms::new(&base, PathBuf::from(&token_file)).unwrap();
    let envelope = NativeDidcommEnvelope::new(
        None,
        Some(&resolver_url),
        Some(policy_path.to_str().unwrap()),
    )
    .with_remote_kms(kms);
    let prepared = envelope
        .prepare_encryption(&tenant, sender_did, holder_document.clone())
        .await
        .unwrap();

    let rotated: Value = client
        .post(format!("{base}/v1/didcomm/keys/{tenant}/{name}/rotate"))
        .header("X-Vault-Token", &root_token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(rotated["data"]["version"], version);
    let rotated_version = rotated["data"]["version"].as_str().unwrap();
    let denied_rotated_read = client
        .get(format!(
            "{base}/v1/didcomm/keys/{tenant}/{name}/versions/{rotated_version}"
        ))
        .header("X-Vault-Token", scoped_token)
        .send()
        .await
        .unwrap();
    assert_eq!(denied_rotated_read.status().as_u16(), 403);
    let denied_rotated_pack = client
        .post(format!(
            "{base}/v1/didcomm/pack/{tenant}/{name}/{rotated_version}"
        ))
        .header("X-Vault-Token", scoped_token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied_rotated_pack.status().as_u16(), 403);
    std::fs::write(
        &policy_path,
        json!({"version":1,"issuers":{(sender_did):{"mode":"anoncrypt"}}}).to_string(),
    )
    .unwrap();
    let plaintext = json!({"id":"live-1","type":"https://didcomm.org/basicmessage/2.0/message",
        "from":sender_did,"to":[holder_did],"body":{"live":true}})
    .to_string();
    let encrypted = envelope
        .encrypt_prepared(&plaintext, &prepared)
        .await
        .unwrap();
    let decrypted = didcomm_test_fixtures::holder_decrypt_authcrypt(
        &encrypted,
        &holder_secret,
        &holder_document,
        &sender_document,
    );
    assert_eq!(decrypted.plaintext, plaintext);
    assert_eq!(decrypted.sender_kid, sender_kid);
    assert_eq!(decrypted.recipient_kid, format!("{holder_did}#key-1"));
}

async fn serve_sender_document_once(document: &DidDocument) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let body = serde_json::to_string(document).unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 8_192);
            request.push(stream.read_u8().await.unwrap());
        }
        assert!(request.starts_with(b"GET /.well-known/did.json "));
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/did+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    format!("http://{address}")
}
