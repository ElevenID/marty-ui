//! Wire contracts for the explicitly selected native owner transport. The
//! disposable joined gate separately exercises real HTTPS and remote custody.
use super::*;
use crate::credential_issuer::{validate_native_context, HttpIssuerContextResolver};
use axum::{
    extract::State,
    http::{HeaderMap, Uri},
    routing::post,
    Json, Router,
};
use marty_signing_grant::{payload_digest, GrantEnvelope};
use marty_signing_grant_test_support::ContractGrantMinter;
use std::sync::Mutex;

const API_KEY: &str = "native-owner-transport-contract-key";
const ISSUER: &str = "did:web:machine-issuer.example.test";

#[test]
fn native_owner_constructors_reject_ambiguous_or_insecure_origins() {
    for raw in [
        "http://owner.example",
        "https://user:password@owner.example",
        "https://owner.example/internal/compat",
        "https://owner.example/?tenant=other",
        "https://owner.example/#other",
    ] {
        let origin: Url = raw.parse().unwrap();
        assert!(HttpIssuerContextResolver::new_for_native_owner(
            origin.clone(),
            Some(API_KEY),
            Duration::from_secs(1)
        )
        .is_err());
        assert!(HttpCredentialBuilder::new_for_native_owner_with_grant(
            origin,
            Some(API_KEY),
            Duration::from_secs(1),
            ContractGrantMinter(SigningOrigin::IssuanceCredential)
        )
        .is_err());
    }
    let origin: Url = "https://owner.example:8443/".parse().unwrap();
    assert!(HttpIssuerContextResolver::new_for_native_owner(
        origin.clone(),
        Some(API_KEY),
        Duration::from_secs(1)
    )
    .is_ok());
    assert!(HttpCredentialBuilder::new_for_native_owner_with_grant(
        origin,
        Some(API_KEY),
        Duration::from_secs(1),
        ContractGrantMinter(SigningOrigin::IssuanceCredential)
    )
    .is_ok());
}

#[test]
fn native_resolution_posts_the_exact_owner_selection_and_preserves_legacy_query_shape() {
    let resolver = HttpIssuerContextResolver::new_for_native_owner(
        "https://owner.example:8443".parse().unwrap(),
        Some(API_KEY),
        Duration::from_secs(1),
    )
    .unwrap();
    let request = resolver
        .context_request(
            "org-selected",
            ISSUER,
            Some("org_managed"),
            "jwt_vc_json",
            "vc_jwt_issuer",
            "ES256",
        )
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(request.method(), reqwest::Method::POST);
    assert_eq!(
        request.url().as_str(),
        "https://owner.example:8443/internal/compat/resolve-issuer-did"
    );
    assert_eq!(request.headers()["x-api-key"], API_KEY);
    let body: Value = serde_json::from_slice(request.body().unwrap().as_bytes().unwrap()).unwrap();
    assert_eq!(
        body,
        json!({"organization_id":"org-selected","issuer_did":ISSUER,
        "credential_format":"jwt_vc_json","key_purpose":"vc_jwt_issuer","algorithm":"ES256"})
    );
    let legacy = HttpIssuerContextResolver::new(
        "https://gateway.example/internal/signing-keys"
            .parse()
            .unwrap(),
        Some(API_KEY),
        Duration::from_secs(1),
    )
    .unwrap();
    let request = legacy
        .context_request(
            "org-selected",
            ISSUER,
            Some("org_managed"),
            "jwt_vc_json",
            "vc_jwt_issuer",
            "ES256",
        )
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(request.method(), reqwest::Method::GET);
    assert_eq!(
        request.url().path(),
        "/internal/signing-keys/resolve-issuer-did"
    );
    let query: std::collections::BTreeMap<_, _> =
        request.url().query_pairs().into_owned().collect();
    assert_eq!(query["organization_id"], "org-selected");
    assert_eq!(query["issuer_did"], ISSUER);
    assert_eq!(query["issuer_mode"], "org_managed");
    assert!(request.body().is_none());
}

#[test]
fn native_resolution_rejects_cross_organization_and_issuer_mode_contexts() {
    let selected = json!({"organization_id":"org-selected",
        "issuer_profile":{"organization_id":"org-selected","issuer_mode":"org_managed"}});
    validate_native_context(&selected, "org-selected", Some("org_managed")).unwrap();
    for foreign in [
        json!({"organization_id":"org-other","issuer_profile":{"organization_id":"org-selected","issuer_mode":"org_managed"}}),
        json!({"organization_id":"org-selected","issuer_profile":{"organization_id":"org-other","issuer_mode":"org_managed"}}),
        json!({"organization_id":"org-selected","issuer_profile":{"organization_id":"org-selected","issuer_mode":"elevenid_managed"}}),
        json!({"organization_id":"org-selected"}),
    ] {
        assert!(validate_native_context(&foreign, "org-selected", Some("org_managed")).is_err());
    }
}

type Capture = Arc<Mutex<Option<(Uri, HeaderMap, Value)>>>;
async fn capture_sign(
    State(capture): State<Capture>,
    uri: Uri,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    *capture.lock().unwrap() = Some((uri, headers, body));
    Json(json!({"ok":true,"issuer_did":ISSUER,"algorithm":"ES256",
        "verification_method_id":format!("{ISSUER}#machine-key"),
        "signature_raw_b64":URL_SAFE_NO_PAD.encode([0x11;64])}))
}

#[tokio::test]
async fn native_signing_keeps_exact_organization_key_payload_and_owner_route_grant_binding() {
    for native_owner in [false, true] {
        let captured: Capture = Default::default();
        let router = Router::new()
            .fallback(post(capture_sign))
            .with_state(captured.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let base = if native_owner {
            "/internal/compat"
        } else {
            "/internal/signing-keys"
        };
        // Only this private wire test selects plain loopback. The public native
        // constructor rejects it and the joined qualification supplies HTTPS.
        let mut signer = HttpDidSigner::new(
            format!("http://{address}{base}").parse().unwrap(),
            Some(API_KEY),
            Duration::from_secs(1),
        )
        .unwrap()
        .with_grant_minter(
            SigningOrigin::IssuanceCredential,
            ContractGrantMinter(SigningOrigin::IssuanceCredential),
        );
        signer.native_owner = native_owner;
        let request = SignRequest {
            organization_id: "org-selected".into(),
            operation_id: "urn:uuid:managed-machine".into(),
            issuer_did: ISSUER.into(),
            credential_format: "jwt_vc_json".into(),
            key_purpose: "vc_jwt_issuer".into(),
            payload: b"exact.header-and-payload".to_vec(),
            algorithm: "ES256".into(),
            verification_method_id: format!("{ISSUER}#machine-key"),
            expected_public_jwk: None,
            signing_key_reference: "dedicated-machine-key".into(),
        };
        signer.sign_did(request.clone()).await.unwrap();
        let (uri, headers, body) = captured.lock().unwrap().take().unwrap();
        assert_eq!(uri.path(), format!("{base}/issuer-dids/sign"));
        assert_eq!(headers["x-api-key"], API_KEY);
        if native_owner {
            assert!(uri.query().is_none());
            assert_eq!(body["organization_id"], "org-selected");
        } else {
            assert_eq!(uri.query(), Some("organization_id=org-selected"));
            assert!(body.get("organization_id").is_none());
        }
        let grant =
            GrantEnvelope::from_header_value(headers[HEADER_NAME].to_str().unwrap()).unwrap();
        assert_eq!(grant.claims.origin, SigningOrigin::IssuanceCredential);
        assert_eq!(grant.claims.operation_id, request.operation_id);
        assert_eq!(grant.claims.algorithm, request.algorithm);
        assert_eq!(grant.claims.organization_id, request.organization_id);
        assert_eq!(grant.claims.route, "/internal/compat/issuer-dids/sign");
        assert_eq!(
            grant.claims.key_reference.as_deref(),
            Some("dedicated-machine-key")
        );
        assert_eq!(grant.claims.key_purpose, "vc_jwt_issuer");
        assert_eq!(grant.claims.issuer_did.as_deref(), Some(ISSUER));
        assert_eq!(
            grant.claims.payload_sha256_b64,
            payload_digest(&request.payload)
        );
        assert_eq!(body["key_reference"], "dedicated-machine-key");
        assert_eq!(
            body["payload_b64"],
            URL_SAFE_NO_PAD.encode(&request.payload)
        );
        assert_eq!(body["issuer_did"], ISSUER);
        assert_eq!(body["algorithm"], request.algorithm);
        assert_eq!(
            body["verification_method_id"],
            request.verification_method_id
        );
        assert_eq!(body["credential_format"], request.credential_format);
        server.abort();
    }
}
