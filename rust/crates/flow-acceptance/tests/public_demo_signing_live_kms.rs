//! Actual Flow HTTP client -> Signing Keys admission -> scoped remote Transit.
//! Runs only on independently marked, controller-owned disposable backends.
use std::io::Write;

use axum::{body::Body, http::Request, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_flow::{HttpSigningProvider, SigningIdentityProvider, SigningRequest};
use marty_signing_grant::{
    minter::GrantMinter, replay::RedisGrantReplayStore, verifier::GrantVerifier, GrantBinding,
    SigningOrigin, HEADER_NAME,
};
use marty_signing_keys::{
    documents::DocumentStore, http::router_with_all_keys_and_grants, profiles::ProfileStore,
    registry::RegistryStore,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/public_demo_canonical.rs"]
mod canonical_example;
#[path = "../../../services/signing-keys/tests/support/disposable_backends.rs"]
mod disposable_backends;

const INTERNAL: &str = "demo-acceptance-internal-credential";
const ISSUER_SIGN: &str = "demo-acceptance-issuer-sign-credential";
const ROUTE: &str = "/internal/compat/issuer-dids/sign";

fn secret_file(variable: &str) -> tempfile::NamedTempFile {
    let value = std::env::var(variable).expect("controller scoped fixture capability");
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(value.as_bytes()).unwrap();
    file
}

async fn submit(app: &Router, body: &Value, grant: Option<&str>, key: &str) -> u16 {
    let mut request = Request::post(ROUTE)
        .header("content-type", "application/json")
        .header("x-api-key", key);
    if let Some(value) = grant {
        request = request.header(HEADER_NAME, value);
    }
    app.clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn grant(minter: &GrantMinter, request: &SigningRequest) -> String {
    let payload = URL_SAFE_NO_PAD.decode(&request.payload_b64url).unwrap();
    minter
        .mint(&GrantBinding {
            origin: SigningOrigin::FlowDemoHolder,
            operation_id: &request.operation_id,
            organization_id: &request.organization_id,
            route: ROUTE,
            service_id: None,
            issuer_did: Some(&request.issuer_did),
            key_reference: Some(&request.signing_key_reference),
            key_purpose: &request.key_purpose,
            algorithm: &request.algorithm,
            payload: &payload,
        })
        .await
        .unwrap()
        .to_header_value()
        .unwrap()
}

fn body(request: &SigningRequest) -> Value {
    json!({"organization_id":request.organization_id, "issuer_did":request.issuer_did,
        "key_reference":request.signing_key_reference, "credential_format":request.credential_format,
        "key_purpose":request.key_purpose, "algorithm":request.algorithm,
        "payload_b64":request.payload_b64url})
}

#[tokio::test]
#[ignore = "requires controller-owned TLS OpenBao/Redis and distinct scoped grant/custody tokens"]
async fn flow_demo_holder_http_admission_uses_remote_custody_and_one_use_grants() {
    let redis_url = disposable_backends::disposable_redis_url().await;
    let _ = disposable_backends::disposable_openbao_envelope().await;
    let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").unwrap();
    let org = Uuid::new_v4().to_string();
    let did = "did:web:demo.example:orgs:marty-demo-holder";
    let registry = RegistryStore::connect(&redis_url)
        .await
        .unwrap()
        .with_managed_openbao(Some(endpoint.clone()));
    let profiles = ProfileStore::from_connection(registry.connection());
    let verify_file = secret_file("MARTY_TEST_GRANT_VERIFY_TOKEN");
    let mint_file = secret_file("MARTY_TEST_GRANT_MINT_TOKEN");
    let verifier = GrantVerifier::for_managed_openbao(
        &endpoint,
        verify_file.path().into(),
        RedisGrantReplayStore::new(registry.connection()),
    )
    .unwrap();
    let app = router_with_all_keys_and_grants(
        INTERNAL.into(),
        None,
        Some(ISSUER_SIGN.into()),
        None,
        None,
        None,
        false,
        Some(registry.clone()),
        Some(DocumentStore::from_connection(registry.connection())),
        None,
        Some(profiles),
        None,
        Some("demo.example".into()),
        Some(verifier),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_app = app.clone();
    let server = tokio::spawn(async move { axum::serve(listener, server_app).await.unwrap() });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let created = client
        .post(format!(
            "http://{address}/v1/signing-keys/issuer-identities"
        ))
        .query(&[("organization_id", org.as_str())])
        .header("x-api-key", INTERNAL)
        .json(
            &json!({"issuer_did":did,"key_purpose":"demo_holder_binding",
            "credential_format":"SD_JWT_VC","algorithm":"ES256"}),
        )
        .send()
        .await
        .unwrap();
    let status = created.status();
    let created: Value = created.json().await.unwrap();
    assert!(
        status.is_success(),
        "governed identity creation {status}: {created}"
    );
    let minter = GrantMinter::for_managed_openbao(
        &endpoint,
        SigningOrigin::FlowDemoHolder,
        mint_file.path().into(),
    )
    .unwrap();
    let provider =
        HttpSigningProvider::new(&format!("http://{address}/internal"), INTERNAL, ISSUER_SIGN)
            .unwrap()
            .with_demo_holder_grant_minter(minter.clone());
    let resolved = client
        .post(format!(
            "http://{address}/internal/compat/resolve-issuer-did"
        ))
        .header("x-api-key", INTERNAL)
        .json(
            &json!({"organization_id":org,"issuer_did":did,"key_purpose":"demo_holder_binding",
            "credential_format":"dc+sd-jwt","algorithm":"ES256"}),
        )
        .send()
        .await
        .unwrap();
    let status = resolved.status();
    let resolved: Value = resolved.json().await.unwrap();
    assert!(
        status.is_success(),
        "governed identity resolution {status}: {resolved}"
    );
    let identity = provider
        .resolve(&org, did, "demo_holder_binding", "dc+sd-jwt", Some("ES256"))
        .await
        .expect("actual governed demo profile resolution");
    assert!(identity.signing_key_reference.starts_with("demo-holder-"));
    let request = SigningRequest {
        operation_id: Uuid::new_v4().to_string(),
        organization_id: org.clone(),
        issuer_did: did.into(),
        verification_method_id: identity.verification_method_id.clone(),
        signing_key_reference: identity.signing_key_reference.clone(),
        key_purpose: "demo_holder_binding".into(),
        credential_format: "dc+sd-jwt".into(),
        algorithm: "ES256".into(),
        payload_b64url: URL_SAFE_NO_PAD.encode(b"holder.proof.bound-input"),
    };
    let signed = provider
        .sign(&request)
        .await
        .expect("Flow HTTP -> authorized remote signing");
    signed.validate_binding(&request).unwrap();
    let signature = URL_SAFE_NO_PAD
        .decode(&signed.signature_raw_b64url)
        .unwrap();
    assert!(
        marty_oid4vci::jose::verify_detached_signature_with_public_jwk(
            b"holder.proof.bound-input",
            &signature,
            &json!(identity.public_jwk).to_string(),
            "ES256"
        )
        .unwrap()
    );
    // Single-use is enforced per grant nonce. Flow's example lease reconciles
    // operations before it asks this provider to mint a fresh grant.
    let mut next = request.clone();
    next.operation_id = Uuid::new_v4().to_string();
    let header = grant(&minter, &next).await;
    let original = body(&next);
    assert_eq!(submit(&app, &original, None, ISSUER_SIGN).await, 401);
    assert_eq!(submit(&app, &original, Some(&header), INTERNAL).await, 401);
    for (field, value) in [
        ("organization_id", "foreign-tenant"),
        ("issuer_did", "did:web:other.example:holder"),
        ("key_reference", "demo-holder-foreign"),
        ("key_purpose", "oid4vp_request_signing"),
        ("algorithm", "ES384"),
        ("payload_b64", "YWx0ZXJlZA"),
    ] {
        let mut altered = original.clone();
        altered[field] = json!(value);
        assert_eq!(
            submit(&app, &altered, Some(&header), ISSUER_SIGN).await,
            401,
            "{field}"
        );
    }
    // Failed binding/authentication attempts must not consume the valid grant.
    assert_eq!(
        submit(&app, &original, Some(&header), ISSUER_SIGN).await,
        200
    );
    assert_eq!(
        submit(&app, &original, Some(&header), ISSUER_SIGN).await,
        401
    );
    next.operation_id = Uuid::new_v4().to_string();
    let race_header = grant(&minter, &next).await;
    let race_body = body(&next);
    let (left, right) = tokio::join!(
        submit(&app, &race_body, Some(&race_header), ISSUER_SIGN),
        submit(&app, &race_body, Some(&race_header), ISSUER_SIGN)
    );
    assert!(matches!((left, right), (200, 401) | (401, 200)));
    // Even a correctly MAC-bound foreign tenant cannot select this tenant's key/profile.
    next.operation_id = Uuid::new_v4().to_string();
    next.organization_id = "foreign-tenant".into();
    let foreign_header = grant(&minter, &next).await;
    let status = submit(&app, &body(&next), Some(&foreign_header), ISSUER_SIGN).await;
    assert!(
        matches!(status, 400 | 404 | 409 | 422),
        "foreign profile status={status}"
    );
    next.organization_id = org.clone();
    next.operation_id = Uuid::new_v4().to_string();
    let format_header = grant(&minter, &next).await;
    let mut wrong_format = body(&next);
    wrong_format["credential_format"] = json!("mso_mdoc");
    let status = submit(&app, &wrong_format, Some(&format_header), ISSUER_SIGN).await;
    assert!(
        matches!(status, 400 | 404 | 409 | 422),
        "wrong format status={status}"
    );
    let wallet_file = secret_file("MARTY_TEST_FLOW_WALLET_MINT_TOKEN");
    let wallet_minter = GrantMinter::for_managed_openbao(
        &endpoint,
        SigningOrigin::FlowWalletRequest,
        wallet_file.path().into(),
    )
    .unwrap();
    let no_demo =
        HttpSigningProvider::new(&format!("http://{address}/internal"), INTERNAL, ISSUER_SIGN)
            .unwrap()
            .with_grant_minter(wallet_minter.clone());
    assert!(no_demo.sign(&next).await.is_err(), "no authority fallback");
    canonical_example::run(
        &format!("http://{address}"),
        &org,
        provider.with_grant_minter(wallet_minter),
        &identity,
        &endpoint,
    )
    .await;
    server.abort();
    let _ = server.await;
}
