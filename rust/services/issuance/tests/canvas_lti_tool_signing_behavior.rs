use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_issuance_service::canvas_lti_tool_signing::{
    CanvasLtiSigningKind, CanvasLtiToolIdentityResolver, CanvasLtiToolJwtSigner,
    CanvasLtiToolSignatureProvider, CanvasLtiToolSigningError, HttpCanvasLtiToolSignatureProvider,
    IssuerDidCanvasLtiToolJwtSigner,
};
use marty_issuance_service::{
    http::router_with_canvas_lti_tool_signer, transport::TransportPolicy, IssuanceRuntime,
    IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use marty_signing_grant::{minter::GrantMinter, SigningOrigin, HEADER_NAME};
use serde_json::{json, Value};

#[tokio::test]
async fn http_canvas_signer_mints_only_its_bound_remote_grant() {
    use axum::{http::HeaderMap, routing::post, Json, Router};
    use base64::engine::general_purpose::STANDARD;

    let app = Router::new()
        .route(
            "/v1/transit/hmac/marty-sign-grant-issuance-canvas-v1/sha2-256",
            post(|headers: HeaderMap| async move {
                assert_eq!(headers["x-vault-token"], "canvas-mint-token");
                Json(json!({"data": {"hmac": format!("vault:v1:{}", STANDARD.encode([7_u8; 32]))}}))
            }),
        )
        .route(
            "/internal/issuer-dids/sign",
            post(|headers: HeaderMap, Json(body): Json<Value>| async move {
                let grant = marty_signing_grant::GrantEnvelope::from_header_value(
                    headers[HEADER_NAME].to_str().unwrap(),
                )
                .unwrap();
                assert_eq!(grant.claims.origin, SigningOrigin::IssuanceCanvas);
                assert_eq!(grant.claims.operation_id, "deep-link:session-1:nonce-1");
                assert_eq!(
                    grant.claims.key_reference.as_deref(),
                    Some("transit/keys/canvas-1")
                );
                assert_eq!(grant.claims.key_purpose, "lti_tool_signing");
                assert_eq!(grant.claims.algorithm, "RS256");
                assert_eq!(
                    grant.claims.payload_sha256_b64,
                    marty_signing_grant::payload_digest(b"exact-jwt-signing-input")
                );
                assert!(body.get("signing_key_reference").is_none());
                Json(json!({
                    "ok": true,
                    "issuer_did": body["issuer_did"],
                    "algorithm": body["algorithm"],
                    "verification_method_id": "did:web:issuer.example:canvas#key-1",
                    "signature_raw_b64": URL_SAFE_NO_PAD.encode([1_u8, 2, 3]),
                }))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut token_file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut token_file, b"canvas-mint-token\n").unwrap();
    let previous = std::env::var_os("BAO_ADDR");
    std::env::set_var("BAO_ADDR", &endpoint);
    let minter = GrantMinter::for_managed_openbao(
        &endpoint,
        SigningOrigin::IssuanceCanvas,
        token_file.path().to_path_buf(),
    )
    .unwrap();
    match previous {
        Some(value) => std::env::set_var("BAO_ADDR", value),
        None => std::env::remove_var("BAO_ADDR"),
    }
    let provider = HttpCanvasLtiToolSignatureProvider::new_with_grant(
        format!("{endpoint}/internal").parse().unwrap(),
        Some("issuer-sign-key"),
        std::time::Duration::from_secs(2),
        minter,
    )
    .unwrap();
    assert_eq!(
        provider
            .sign(
                "org-a",
                "did:web:issuer.example:canvas",
                "did:web:issuer.example:canvas#key-1",
                "transit/keys/canvas-1",
                "deep-link:session-1:nonce-1",
                b"exact-jwt-signing-input",
            )
            .await
            .unwrap(),
        URL_SAFE_NO_PAD.encode([1_u8, 2, 3])
    );
    server.abort();
}
use tower::ServiceExt;

#[derive(Default)]
struct Resolver {
    response: Mutex<Value>,
    requests: Mutex<Vec<(String, String)>>,
}

#[async_trait]
impl CanvasLtiToolIdentityResolver for Resolver {
    async fn resolve(
        &self,
        organization_id: &str,
        issuer_did: &str,
    ) -> Result<Value, CanvasLtiToolSigningError> {
        self.requests
            .lock()
            .unwrap()
            .push((organization_id.to_owned(), issuer_did.to_owned()));
        Ok(self.response.lock().unwrap().clone())
    }
}

type SignatureRequest = (String, String, String, String, String, Vec<u8>);

#[derive(Default)]
struct Signatures {
    requests: Mutex<Vec<SignatureRequest>>,
    response: Mutex<Option<String>>,
}

#[async_trait]
impl CanvasLtiToolSignatureProvider for Signatures {
    async fn sign(
        &self,
        organization_id: &str,
        issuer_did: &str,
        verification_method_id: &str,
        signing_key_reference: &str,
        operation_id: &str,
        payload: &[u8],
    ) -> Result<String, CanvasLtiToolSigningError> {
        self.requests.lock().unwrap().push((
            organization_id.to_owned(),
            issuer_did.to_owned(),
            verification_method_id.to_owned(),
            signing_key_reference.to_owned(),
            operation_id.to_owned(),
            payload.to_vec(),
        ));
        Ok(self
            .response
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "c2ln==".to_owned()))
    }
}

fn identity(issuer_did: &str, kid: &str) -> Value {
    json!({
        "ok": true,
        "issuer_did": issuer_did,
        "signing_key_reference": "transit/keys/canvas-tool-1",
        "verification_method_id": kid,
        "public_jwk": {
            "kid": kid,
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": "public-modulus",
            "e": "AQAB",
        },
    })
}

fn signer(resolver: Arc<Resolver>, signatures: Arc<Signatures>) -> IssuerDidCanvasLtiToolJwtSigner {
    IssuerDidCanvasLtiToolJwtSigner::new(
        "system-tools",
        "did:web:issuer.example:canvas",
        true,
        resolver,
        signatures,
    )
}

fn signer_app(signer: Arc<dyn CanvasLtiToolJwtSigner>) -> axum::Router {
    let config = IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>())
        .expect("configuration");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    router_with_canvas_lti_tool_signer(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example.test", "Issuer"),
        TransportPolicy::new(Vec::new()),
        signer,
    )
}

async fn response_json(response: axum::response::Response) -> Value {
    let body = axum::body::to_bytes(response.into_body(), 128 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn signer_uses_only_the_organization_did_and_exact_rs256_method() {
    let issuer_did = "did:web:issuer.example:canvas";
    let kid = format!("{issuer_did}#lti-tool-rs256");
    let resolver = Arc::new(Resolver {
        response: Mutex::new(identity(issuer_did, &kid)),
        ..Resolver::default()
    });
    let signatures = Arc::new(Signatures::default());
    let token = signer(resolver.clone(), signatures.clone())
        .sign_jwt(
            &json!({
                "title": "Crème brûlée",
                "aud": "https://canvas.example.edu",
            }),
            CanvasLtiSigningKind::DeepLink,
            "synthetic-session:nonce",
        )
        .await
        .unwrap();

    let parts = token.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[2], "c2ln");
    assert_eq!(
        String::from_utf8(URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap(),
        format!(r#"{{"alg":"RS256","kid":"{kid}","typ":"JWT"}}"#)
    );
    assert_eq!(
        String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap(),
        r#"{"aud":"https://canvas.example.edu","title":"Cr\u00e8me br\u00fbl\u00e9e"}"#
    );
    assert_eq!(
        resolver.requests.lock().unwrap().as_slice(),
        [("system-tools".to_owned(), issuer_did.to_owned())]
    );
    let requests = signatures.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(&requests[0].0, "system-tools");
    assert_eq!(&requests[0].1, issuer_did);
    assert_eq!(&requests[0].2, &kid);
    assert_eq!(&requests[0].3, "transit/keys/canvas-tool-1");
    assert_eq!(&requests[0].4, "deep-link:synthetic-session:nonce");
    assert_eq!(
        requests[0].5,
        format!("{}.{}", parts[0], parts[1]).as_bytes()
    );
}

#[tokio::test]
async fn signer_fails_closed_for_configuration_and_resolver_key_drift() {
    let resolver = Arc::new(Resolver::default());
    let signatures = Arc::new(Signatures::default());
    for (organization, did, configured, expected) in [
        (
            "",
            "did:web:issuer.example:canvas",
            true,
            CanvasLtiToolSigningError::ConfigurationIncomplete,
        ),
        (
            "org",
            "",
            true,
            CanvasLtiToolSigningError::ConfigurationIncomplete,
        ),
        (
            "  ",
            "  ",
            true,
            CanvasLtiToolSigningError::ConfigurationIncomplete,
        ),
        (
            "org",
            "did:web:issuer.example:canvas",
            false,
            CanvasLtiToolSigningError::ConfigurationIncomplete,
        ),
        (
            "org",
            "not-a-did",
            true,
            CanvasLtiToolSigningError::IssuerIdentityNotDid,
        ),
    ] {
        let incomplete = IssuerDidCanvasLtiToolJwtSigner::new(
            organization,
            did,
            configured,
            resolver.clone(),
            signatures.clone(),
        );
        assert_eq!(
            incomplete
                .sign_jwt(
                    &json!({}),
                    CanvasLtiSigningKind::DeepLink,
                    "synthetic-session:nonce"
                )
                .await
                .unwrap_err(),
            expected
        );
        assert_eq!(incomplete.public_jwks().await.unwrap_err(), expected);
        assert!(resolver.requests.lock().unwrap().is_empty());
        assert!(signatures.requests.lock().unwrap().is_empty());
    }

    assert_eq!(
        signer(resolver.clone(), signatures.clone())
            .sign_jwt(&json!({}), CanvasLtiSigningKind::DeepLink, "")
            .await
            .unwrap_err(),
        CanvasLtiToolSigningError::InvalidSigningOperation
    );
    assert!(resolver.requests.lock().unwrap().is_empty());

    let issuer_did = "did:web:issuer.example:canvas";
    *resolver.response.lock().unwrap() = identity(issuer_did, "did:web:other.example#key-1");
    assert_eq!(
        signer(resolver.clone(), signatures.clone())
            .sign_jwt(
                &json!({}),
                CanvasLtiSigningKind::DeepLink,
                "synthetic-session:nonce"
            )
            .await
            .unwrap_err(),
        CanvasLtiToolSigningError::InvalidVerificationMethod
    );

    let kid = format!("{issuer_did}#private");
    let mut private = identity(issuer_did, &kid);
    private["public_jwk"]["d"] = Value::String("private".to_owned());
    *resolver.response.lock().unwrap() = private;
    assert_eq!(
        signer(resolver, signatures)
            .public_jwks()
            .await
            .unwrap_err(),
        CanvasLtiToolSigningError::PrivateKeyMaterial
    );
}

#[tokio::test]
async fn signer_rejects_incomplete_rsa_keys_and_malformed_signature_encoding() {
    let issuer_did = "did:web:issuer.example:canvas";
    let kid = format!("{issuer_did}#lti-tool-rs256");
    let resolver = Arc::new(Resolver {
        response: Mutex::new(identity(issuer_did, &kid)),
        ..Resolver::default()
    });
    let signatures = Arc::new(Signatures {
        response: Mutex::new(Some("not+base64".to_owned())),
        ..Signatures::default()
    });
    assert_eq!(
        signer(resolver.clone(), signatures)
            .sign_jwt(
                &json!({}),
                CanvasLtiSigningKind::DeepLink,
                "synthetic-session:nonce"
            )
            .await
            .unwrap_err(),
        CanvasLtiToolSigningError::InvalidSignatureEncoding
    );

    let mut incomplete = identity(issuer_did, &kid);
    incomplete["public_jwk"]["n"] = Value::String(String::new());
    *resolver.response.lock().unwrap() = incomplete;
    assert_eq!(
        signer(resolver, Arc::new(Signatures::default()))
            .public_jwks()
            .await
            .unwrap_err(),
        CanvasLtiToolSigningError::InvalidVerificationMethod
    );
}

#[tokio::test]
async fn jwks_publishes_active_then_sorted_public_assertion_methods_only() {
    let issuer_did = "did:web:issuer.example:canvas";
    let active = format!("{issuer_did}#active");
    let older_a = format!("{issuer_did}#a-retiring");
    let older_z = format!("{issuer_did}#z-retiring");
    let mut resolution = identity(issuer_did, &active);
    resolution["did_document"] = json!({
        "verificationMethod": [
            {"id": older_z, "publicKeyJwk": {"kty": "RSA", "n": "z", "e": "AQAB"}},
            {"id": older_a, "publicKeyJwk": {"kty": "RSA", "n": "a", "e": "AQAB"}},
            {"id": format!("{issuer_did}#not-asserted"), "publicKeyJwk": {"kty": "RSA", "n": "x", "e": "AQAB"}},
            {"id": "did:web:other.example#cross-did", "publicKeyJwk": {"kty": "RSA", "n": "x", "e": "AQAB"}},
            {"id": format!("{issuer_did}#private"), "publicKeyJwk": {"kty": "RSA", "n": "x", "e": "AQAB", "d": "private"}},
        ],
        "assertionMethod": [active, older_z, older_a, format!("{issuer_did}#private"), "did:web:other.example#cross-did"],
    });
    let resolver = Arc::new(Resolver {
        response: Mutex::new(resolution),
        ..Resolver::default()
    });
    let document = signer(resolver, Arc::new(Signatures::default()))
        .public_jwks()
        .await
        .unwrap();
    let keys = document["keys"].as_array().unwrap();
    assert_eq!(
        keys.iter()
            .map(|key| key["kid"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [active.as_str(), older_a.as_str(), older_z.as_str()]
    );
    assert!(keys.iter().all(|key| {
        key["kty"] == "RSA"
            && !["d", "p", "q", "dp", "dq", "qi", "oth"]
                .iter()
                .any(|name| key.get(name).is_some())
    }));
}

#[tokio::test]
async fn jwks_preserves_embedded_and_relative_assertion_methods_without_leaking_metadata() {
    let issuer_did = "did:web:issuer.example:canvas";
    let active = format!("{issuer_did}#active");
    let inline = format!("{issuer_did}#inline-retiring");
    let relative = format!("{issuer_did}#relative-retiring");
    let mut resolution = identity(issuer_did, &active);
    resolution["public_jwk"]["provider_reference"] = Value::String("secret-route".to_owned());
    resolution["did_document"] = json!({
        "verificationMethod": [
            {
                "id": "#relative-retiring",
                "publicKeyJwk": {
                    "kty": "RSA",
                    "n": "relative",
                    "e": "AQAB",
                    "retired_at": "2026-08-29T00:00:00Z",
                    "provider_reference": "must-not-be-public",
                },
            },
            {
                "id": "#missing-modulus",
                "publicKeyJwk": {"kty": "RSA", "e": "AQAB"},
            },
            {
                "id": "#encryption-only",
                "publicKeyJwk": {"kty": "RSA", "use": "enc", "n": "enc", "e": "AQAB"},
            },
        ],
        "assertionMethod": [
            "#relative-retiring",
            "#missing-modulus",
            "#encryption-only",
            {
                "id": "#inline-retiring",
                "publicKeyJwk": {"kty": "RSA", "n": "inline", "e": "AQAB"},
            },
        ],
    });
    let resolver = Arc::new(Resolver {
        response: Mutex::new(resolution),
        ..Resolver::default()
    });
    let document = signer(resolver, Arc::new(Signatures::default()))
        .public_jwks()
        .await
        .unwrap();
    let keys = document["keys"].as_array().unwrap();
    assert_eq!(
        keys.iter()
            .map(|key| key["kid"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [active.as_str(), inline.as_str(), relative.as_str()]
    );
    assert!(keys
        .iter()
        .all(|key| key.get("provider_reference").is_none()));
    assert_eq!(keys[2]["retired_at"], "2026-08-29T00:00:00Z");
}

#[tokio::test]
async fn jwks_http_route_returns_only_public_did_assertion_methods() {
    let issuer_did = "did:web:issuer.example:canvas";
    let kid = format!("{issuer_did}#lti-tool-rs256");
    let resolver = Arc::new(Resolver {
        response: Mutex::new(identity(issuer_did, &kid)),
        ..Resolver::default()
    });
    let response = signer_app(Arc::new(signer(resolver, Arc::new(Signatures::default()))))
        .oneshot(
            Request::get("/v1/integrations/canvas/lti/jwks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let document = response_json(response).await;
    assert_eq!(document["keys"][0]["kid"], kid);
    assert!(document["keys"][0].get("d").is_none());
}

#[tokio::test]
async fn jwks_http_route_preserves_the_sanitized_signing_outage_boundary() {
    let response = signer_app(Arc::new(IssuerDidCanvasLtiToolJwtSigner::new(
        "",
        "",
        false,
        Arc::new(Resolver::default()),
        Arc::new(Signatures::default()),
    )))
    .oneshot(
        Request::get("/v1/integrations/canvas/lti/jwks")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), 503);
    assert_eq!(
        response_json(response).await,
        json!({"detail": "Canvas LTI tool signing is temporarily unavailable"})
    );
}
