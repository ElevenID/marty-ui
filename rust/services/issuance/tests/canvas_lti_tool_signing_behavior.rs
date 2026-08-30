use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_issuance_service::canvas_lti_tool_signing::{
    CanvasLtiToolIdentityResolver, CanvasLtiToolJwtSigner, CanvasLtiToolSignatureProvider,
    CanvasLtiToolSigningError, IssuerDidCanvasLtiToolJwtSigner,
};
use marty_issuance_service::{
    http::router_with_canvas_lti_tool_signer, transport::TransportPolicy, IssuanceRuntime,
    IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::{json, Value};
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

type SignatureRequest = (String, String, String, Vec<u8>);

#[derive(Default)]
struct Signatures {
    requests: Mutex<Vec<SignatureRequest>>,
}

#[async_trait]
impl CanvasLtiToolSignatureProvider for Signatures {
    async fn sign(
        &self,
        organization_id: &str,
        issuer_did: &str,
        verification_method_id: &str,
        payload: &[u8],
    ) -> Result<String, CanvasLtiToolSigningError> {
        self.requests.lock().unwrap().push((
            organization_id.to_owned(),
            issuer_did.to_owned(),
            verification_method_id.to_owned(),
            payload.to_vec(),
        ));
        Ok("c2ln==".to_owned())
    }
}

fn identity(issuer_did: &str, kid: &str) -> Value {
    json!({
        "ok": true,
        "issuer_did": issuer_did,
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
        .sign_jwt(&json!({
            "title": "Crème brûlée",
            "aud": "https://canvas.example.edu",
        }))
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
    assert_eq!(
        requests[0].3,
        format!("{}.{}", parts[0], parts[1]).as_bytes()
    );
}

#[tokio::test]
async fn signer_fails_closed_for_configuration_and_resolver_key_drift() {
    let resolver = Arc::new(Resolver::default());
    let signatures = Arc::new(Signatures::default());
    let incomplete = IssuerDidCanvasLtiToolJwtSigner::new(
        "",
        "did:web:issuer.example:canvas",
        true,
        resolver.clone(),
        signatures.clone(),
    );
    assert_eq!(
        incomplete.sign_jwt(&json!({})).await.unwrap_err(),
        CanvasLtiToolSigningError::ConfigurationIncomplete
    );

    let issuer_did = "did:web:issuer.example:canvas";
    *resolver.response.lock().unwrap() = identity(issuer_did, "did:web:other.example#key-1");
    assert_eq!(
        signer(resolver.clone(), signatures.clone())
            .sign_jwt(&json!({}))
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
