//! Opt-in real OpenBao exercise for the Gateway VC-API holder-proof bridge.
//! Transit alone creates, signs with, and deletes each ephemeral private key.

use marty_signing_keys::vc_api_holder_proof::{HolderProofRequest, OpenBaoHolderProofProvider};
use reqwest::{Client, Url};
use serde_json::{json, Value};

#[tokio::test]
#[ignore = "requires disposable loopback MARTY_TEST_OPENBAO_URL and MARTY_TEST_OPENBAO_TOKEN"]
async fn holder_proof_is_verified_and_ephemeral_key_is_deleted() {
    let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("disposable OpenBao token");
    let scoped_token =
        std::env::var("MARTY_TEST_OPENBAO_SCOPED_TOKEN").unwrap_or_else(|_| token.clone());
    let parsed = Url::parse(&endpoint).expect("OpenBao URL");
    assert_eq!(parsed.scheme(), "http");
    assert!(matches!(
        parsed.host_str(),
        Some("127.0.0.1" | "localhost" | "::1")
    ));
    std::env::set_var("BAO_ADDR", &endpoint);
    std::env::set_var("BAO_TOKEN", &scoped_token);
    let client = Client::new();
    // The disposable bootstrap mounts Transit. This test runs with a scoped
    // workload token, which must not have sys/mounts privileges.

    let provider = OpenBaoHolderProofProvider::new(
        endpoint.clone(),
        scoped_token.clone(),
        "https://issuer.example".into(),
    )
    .expect("provider config");
    let tenant = format!("proof-{}", uuid::Uuid::new_v4().simple());
    let issuer_url = format!("https://issuer.example/org/{tenant}");
    let nonce = format!("nonce-{}", uuid::Uuid::new_v4().simple());
    let result = provider
        .issue(HolderProofRequest {
            organization_id: tenant,
            issuer_url: issuer_url.clone(),
            nonce: nonce.clone(),
        })
        .await
        .expect("proof signed by Transit");
    let verified =
        marty_oid4vci::proof::verify_jwt_proof(&result.proof_jwt, &issuer_url, Some(&nonce), 300)
            .expect("actual proof signature, audience and nonce");
    assert!(verified.holder_id.starts_with("did:key:z"));
    assert!(marty_oid4vci::proof::verify_jwt_proof(
        &result.proof_jwt,
        &issuer_url,
        Some("wrong-nonce"),
        300,
    )
    .is_err());

    // Exercise the deployed environment lookup, internal authentication, and
    // HTTP response with the same scoped OpenBao token used above.
    std::env::set_var("ISSUER_BASE_URL", "https://issuer.example");
    std::env::set_var("MARTY_RELEASE_VERSION", "development");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind signing-keys HTTP listener");
    let signing_url = format!(
        "http://{}/internal/vc-api/holder-proof",
        listener.local_addr().expect("HTTP listener address")
    );
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            marty_signing_keys::http::router_with_internal_api_key("test-internal-key".into()),
        )
        .await
        .expect("serve signing-keys route");
    });
    let request_body = json!({
        "organization_id":"http-org",
        "issuer_url":"https://issuer.example/org/http-org",
        "nonce":"http-nonce",
    });
    let denied = client
        .post(&signing_url)
        .json(&request_body)
        .send()
        .await
        .expect("unauthorized proof request");
    assert_eq!(denied.status(), reqwest::StatusCode::UNAUTHORIZED);
    let issued = client
        .post(&signing_url)
        .header("x-api-key", "test-internal-key")
        .json(&request_body)
        .send()
        .await
        .expect("authorized proof request");
    assert_eq!(issued.status(), reqwest::StatusCode::OK);
    let issued: Value = issued.json().await.expect("HTTP proof response");
    marty_oid4vci::proof::verify_jwt_proof(
        issued["proof_jwt"].as_str().expect("proof JWT"),
        "https://issuer.example/org/http-org",
        Some("http-nonce"),
        300,
    )
    .expect("verify HTTP proof");
    let rejected = client
        .post(&signing_url)
        .header("x-api-key", "test-internal-key")
        .json(&json!({
            "organization_id":"http-org",
            "issuer_url":"https://foreign.example/org/http-org",
            "nonce":"http-nonce",
        }))
        .send()
        .await
        .expect("out-of-scope proof request");
    assert_eq!(rejected.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    server.abort();

    let stale_name = format!(
        "vcapi-holder-{}-deadbeef-{}",
        chrono::Utc::now().timestamp() - 7200,
        uuid::Uuid::new_v4().simple()
    );
    let stale_url = format!("{endpoint}/v1/transit/keys/{stale_name}");
    let stale_created = client
        .post(&stale_url)
        .header("X-Vault-Token", &token)
        .json(&json!({"type":"ed25519","exportable":false,"allow_plaintext_backup":false}))
        .send()
        .await
        .expect("create orphaned key");
    assert!(stale_created.status().is_success());
    assert_eq!(provider.reap_stale_keys().await.expect("reap orphan"), 1);
    assert_eq!(
        client
            .get(&stale_url)
            .header("X-Vault-Token", &token)
            .send()
            .await
            .expect("read orphan after reap")
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );

    let listed = client
        .get(format!("{endpoint}/v1/transit/keys?list=true"))
        .header("X-Vault-Token", &token)
        .send()
        .await
        .expect("read key list");
    let status = listed.status();
    let listed: Value = listed.json().await.expect("key list JSON");
    let names = listed.pointer("/data/keys").and_then(Value::as_array);
    assert!(status.is_success() || status.as_u16() == 404);
    let mut names = names.into_iter().flatten();
    assert!(names.all(|name| !name
        .as_str()
        .unwrap_or_default()
        .starts_with("vcapi-holder-")));
}
