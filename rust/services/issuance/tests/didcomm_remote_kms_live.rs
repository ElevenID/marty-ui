//! Opt-in end-to-end authcrypt proof using the canonical registry, HTTPS
//! Signing Keys hop, one-use remote grants and the real OpenBao plugin.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_didcomm::DidDocument;
use marty_issuance_service::{
    didcomm_kms::RegisteredDidcommKms, initiation_didcomm::NativeDidcommEnvelope,
};
use marty_openbao_http::OpenBaoHttp;
use marty_signing_grant::{
    didcomm::{DidcommPackPhase, DidcommPackRequest, RemoteRecipientPublic, PACK_ROUTE},
    HEADER_NAME,
};
use rand::random;
use serde_json::json;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

#[allow(dead_code)]
#[path = "support/registered_didcomm_sender.rs"]
mod registered_didcomm_sender;
use registered_didcomm_sender::{policy, write, RegisteredSenderFixture, SenderInputs};

#[path = "support/didcomm_test_fixtures.rs"]
mod didcomm_test_fixtures;
#[allow(dead_code)]
#[path = "../../signing-keys/tests/support/disposable_backends.rs"]
mod disposable_backends;

struct EnvGuard(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl EnvGuard {
    fn set(values: &[(&'static str, &str)]) -> Self {
        Self(
            values
                .iter()
                .map(|(key, value)| {
                    let old = std::env::var_os(key);
                    std::env::set_var(key, value);
                    (*key, old)
                })
                .collect(),
        )
    }
}
impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, value) in self.0.drain(..) {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires disposable HTTPS MARTY_TEST_OPENBAO_URL/TOKEN with didcomm plugin and guarded MARTY_TEST_REDIS_URL"]
async fn issuer_authcrypt_uses_scoped_openbao_key_and_holder_decrypts_after_rotation() {
    let redis_url = disposable_backends::disposable_redis_url().await;
    let base = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let parsed = reqwest::Url::parse(&base).unwrap();
    assert_eq!(parsed.scheme(), "https");
    assert!(matches!(
        parsed.host_str(),
        Some("localhost" | "127.0.0.1" | "::1")
    ));
    let root_token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable root token");
    let kms_ca =
        PathBuf::from(std::env::var("MARTY_TEST_OPENBAO_CA_CERT_FILE").expect("public OpenBao CA"));
    let _environment = EnvGuard::set(&[
        ("BAO_ADDR", &base),
        ("BAO_CACERT", kms_ca.to_str().unwrap()),
    ]);
    let client = OpenBaoHttp::connect(&base, Some(&kms_ca), Duration::from_secs(10))
        .unwrap()
        .client()
        .clone();
    let tenant = format!("org_{}", uuid::Uuid::new_v4().simple());
    let slug = format!("live-{}", uuid::Uuid::new_v4().simple());
    let sender_did = format!("did:web:issuer.example:orgs:{slug}");
    let issuer_api_key = "test-distinct-issuer-api-authority";
    let temp = tempfile::tempdir().unwrap();
    let fixture = RegisteredSenderFixture::create(SenderInputs {
        client: &client,
        base: &base,
        root_token: &root_token,
        kms_ca: &kms_ca,
        redis_url: &redis_url,
        directory: temp.path(),
        tenant: &tenant,
        sender_did: &sender_did,
        issuer_api_key,
        integration_secret_api_key: None,
    })
    .await;
    let registry = fixture.registry.clone();
    let name = fixture.name.clone();
    let sender_kid = fixture.sender_kid.clone();
    let version = fixture.version.clone();
    let scoped_token = fixture.scoped_token.clone();
    let policy_name = fixture.policy_name.clone();
    let extension_policy = fixture.extension_policy.clone();
    let recording = fixture.recording.clone();
    let kms = fixture.kms.clone();
    let url = fixture.url.clone();
    let https = fixture.https.clone();
    let publication = fixture.publication.clone();
    let publication_url = fixture.publication_url.clone();
    let sender_document = fixture.sender_document.clone();
    let wrong_ca =
        include_bytes!("../../signing-keys/tests/fixtures/public_certificates/root-ca.pem");
    let wrong_trust = RegisteredDidcommKms::new(
        url.clone(),
        Some(wrong_ca),
        issuer_api_key,
        Arc::new(recording.clone()),
    )
    .unwrap();
    assert!(wrong_trust.resolve(&tenant, &sender_did).await.is_err());
    let prepared_binding = kms.resolve(&tenant, &sender_did).await.unwrap();
    let holder_secret: [u8; 32] = random();
    let holder_public = x25519(holder_secret, X25519_BASEPOINT_BYTES);
    let holder_did = "did:example:holder";
    let holder_kid = format!("{holder_did}#key-1");
    let holder_document: DidDocument = serde_json::from_value(json!({"id":holder_did,
        "verificationMethod":[{"id":holder_kid,"type":"JsonWebKey2020","controller":holder_did,"publicKeyJwk":{"kty":"OKP","crv":"X25519","x":URL_SAFE_NO_PAD.encode(holder_public)}}],
        "keyAgreement":[holder_kid]})).unwrap();
    let resolver_url =
        serve_sender_document_once(&sender_document, format!("/orgs/{slug}/did.json")).await;
    let policy_path = temp.path().join("didcomm-encryption-policy.json");
    std::fs::write(
        &policy_path,
        json!({"version":1,"issuers":{(&sender_did):{"mode":"authcrypt"}}}).to_string(),
    )
    .unwrap();
    let envelope = NativeDidcommEnvelope::new(
        None,
        Some(&resolver_url),
        Some(policy_path.to_str().unwrap()),
    )
    .with_registered_kms(kms.clone());
    let prepared = envelope
        .prepare_encryption(
            &tenant,
            "transaction-live",
            &sender_did,
            holder_document.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        recording.issued.lock().unwrap().len(),
        1,
        "preflight performs one real private-key operation with its own grant"
    );

    // A provider rotation and an unrelated default change cannot silently rebind
    // the already prepared operation to another sender key version/service.
    let rotated = write(
        &client,
        &base,
        &root_token,
        &format!("didcomm/keys/{tenant}/{name}/rotate"),
        json!({}),
    )
    .await;
    assert_ne!(rotated["data"]["version"], version);
    let rotated_version = rotated["data"]["version"].as_str().unwrap();
    for path in [
        format!("didcomm/keys/{tenant}/{name}/versions/{rotated_version}"),
        format!("didcomm/keys/{tenant}/forbidden"),
    ] {
        let denied = client
            .get(format!("{base}/v1/{path}"))
            .header("X-Vault-Token", &scoped_token)
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status().as_u16(), 403);
    }
    let denied_pack = client
        .post(format!(
            "{base}/v1/didcomm/pack/{tenant}/{name}/{rotated_version}"
        ))
        .header("X-Vault-Token", &scoped_token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied_pack.status().as_u16(), 403);
    assert_eq!(
        client
            .post(format!("{base}/v1/didcomm/keys/{tenant}/forbidden"))
            .header("X-Vault-Token", &scoped_token)
            .json(&json!({"sender_did":sender_did,"sender_key_id":sender_kid}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403,
        "the selected extension token cannot create sender keys"
    );
    let mut next = registry.load(&tenant).await.unwrap();
    next["services"].as_array_mut().unwrap().push(json!({"id":"aws-default","service_type":"aws-kms","auth_mode":"iam_role","region":"us-east-1",
        "key_reference":"arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012","algorithms":["ES256"]}));
    next["default_service_id"] = json!("aws-default");
    registry.save(&tenant, &next).await.unwrap();
    assert_eq!(
        kms.resolve(&tenant, &sender_did).await.unwrap(),
        prepared_binding
    );
    let mut forged = next.clone();
    forged["services"][0]["endpoint"] = json!("https://other.example");
    assert!(registry.save(&tenant, &forged).await.is_err());

    std::fs::write(
        &policy_path,
        json!({"version":1,"issuers":{(&sender_did):{"mode":"anoncrypt"}}}).to_string(),
    )
    .unwrap();
    let plaintext = json!({"id":"live-1","type":"https://didcomm.org/basicmessage/2.0/message","from":sender_did,"to":[holder_did],"body":{"live":true}}).to_string();
    policy(
        &client,
        &base,
        &root_token,
        &policy_name,
        "path \"*\" { capabilities = [\"deny\"] }",
    )
    .await;
    assert!(
        envelope
            .encrypt_prepared(&plaintext, &prepared)
            .await
            .is_err(),
        "provider denial must not downgrade prepared authcrypt"
    );
    policy(&client, &base, &root_token, &policy_name, &extension_policy).await;
    let encrypted = envelope
        .encrypt_prepared(&plaintext, &prepared)
        .await
        .unwrap();
    let grants = recording.issued.lock().unwrap().clone();
    assert_eq!(grants.len(), 2);
    assert_eq!(
        (grants[0].0.as_str(), grants[1].0.as_str()),
        ("preflight", "delivery")
    );
    assert_ne!(grants[0].1, grants[1].1);
    let decrypted = didcomm_test_fixtures::holder_decrypt_authcrypt(
        &encrypted,
        &holder_secret,
        &holder_document,
        &sender_document,
    );
    assert_eq!(decrypted.plaintext, plaintext);
    assert_eq!(decrypted.sender_kid, sender_kid);
    assert_eq!(decrypted.recipient_kid, holder_kid);

    let request = DidcommPackRequest {
        organization_id: tenant.clone(),
        issuer_did: sender_did.clone(),
        operation_id: "replay-test".into(),
        phase: DidcommPackPhase::Delivery,
        binding: prepared_binding,
        recipient_did: holder_did.into(),
        recipients: vec![RemoteRecipientPublic::new(holder_kid, &holder_public)],
        plaintext: plaintext.clone(),
    };
    let payload = request.bound_payload().unwrap();
    let header = recording
        .inner
        .mint(&request.grant_binding(&payload))
        .await
        .unwrap()
        .to_header_value()
        .unwrap();
    let pack_url = url.join(PACK_ROUTE).unwrap();
    let mut tampered = request.clone();
    tampered.plaintext.push('!');
    assert_eq!(
        https
            .post(pack_url.clone())
            .header("X-API-Key", issuer_api_key)
            .header(HEADER_NAME, &header)
            .json(&tampered)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        https
            .post(pack_url.clone())
            .header("X-API-Key", "wrong-api-key")
            .header(HEADER_NAME, &header)
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    assert!(https
        .post(pack_url.clone())
        .header("X-API-Key", issuer_api_key)
        .header(HEADER_NAME, &header)
        .json(&request)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    assert_eq!(
        https
            .post(pack_url)
            .header("X-API-Key", issuer_api_key)
            .header(HEADER_NAME, &header)
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let mut disabled = publication;
    disabled["enabled"] = json!(false);
    assert!(https
        .put(publication_url)
        .json(&disabled)
        .send()
        .await
        .unwrap()
        .status()
        .is_success());
    assert_eq!(
        kms.resolve(&tenant, &sender_did).await.err(),
        Some(marty_issuance_service::initiation_didcomm::NativeDidcommError::CapabilityUnavailable)
    );
    assert_eq!(
        envelope.encrypt_prepared(&plaintext, &prepared).await.err(),
        Some(marty_issuance_service::initiation_didcomm::NativeDidcommError::CapabilityUnavailable)
    );
}

async fn serve_sender_document_once(document: &DidDocument, path: String) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let body = serde_json::to_string(document).unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 8192);
            request.push(stream.read_u8().await.unwrap());
        }
        assert!(request.starts_with(format!("GET {path} ").as_bytes()));
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/did+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    });
    format!("http://{address}")
}
