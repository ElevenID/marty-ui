use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use marty_auth::{
    KeycloakOidcProvider, OidcAuthorizationRequest, OidcCodeExchange, OidcConfig, OidcHttpClient,
    OidcLogoutRequest, OidcProvider, PortError,
};
use p256::{elliptic_curve::sec1::ToEncodedPoint as _, pkcs8::EncodePrivateKey as _, SecretKey};
use serde_json::{json, Value};
use url::Url;

#[derive(Default)]
struct FakeHttp {
    discovery: Mutex<Option<Value>>,
    jwks: Mutex<VecDeque<Value>>,
    post_response: Mutex<Option<Value>>,
    get_urls: Mutex<Vec<String>>,
    posted_form: Mutex<Vec<(String, String)>>,
}

#[async_trait]
impl OidcHttpClient for FakeHttp {
    async fn get_json_object(
        &self,
        url: &str,
        _max_bytes: usize,
        _document_name: &str,
    ) -> Result<Value, PortError> {
        self.get_urls.lock().expect("GET lock").push(url.to_owned());
        if url.ends_with("/.well-known/openid-configuration") {
            return self
                .discovery
                .lock()
                .expect("discovery lock")
                .clone()
                .ok_or_else(|| PortError::new("missing_fixture", "missing discovery"));
        }
        self.jwks
            .lock()
            .expect("JWKS lock")
            .pop_front()
            .ok_or_else(|| PortError::new("missing_fixture", "missing JWKS"))
    }

    async fn post_form_json_object(
        &self,
        _url: &str,
        form: &[(String, String)],
        _max_bytes: usize,
        _document_name: &str,
    ) -> Result<Value, PortError> {
        *self.posted_form.lock().expect("form lock") = form.to_vec();
        self.post_response
            .lock()
            .expect("post lock")
            .clone()
            .ok_or_else(|| PortError::new("missing_fixture", "missing POST response"))
    }
}

fn config() -> OidcConfig {
    OidcConfig {
        issuer_url: "http://keycloak:8080/realms/marty/".to_owned(),
        external_issuer_url: "https://identity.example/realms/marty/".to_owned(),
        client_id: "marty-ui".to_owned(),
        client_secret: Some("secret".to_owned()),
        redirect_uri: "https://ui.example/v1/auth/callback".to_owned(),
        scopes: vec![
            "openid".to_owned(),
            "email".to_owned(),
            "profile".to_owned(),
        ],
        allowed_algorithms: vec!["ES256".to_owned()],
        leeway_seconds: 30,
        jwks_cache_seconds: 300,
    }
}

fn provider(http: Arc<FakeHttp>) -> KeycloakOidcProvider {
    KeycloakOidcProvider::new(config(), http).expect("valid provider")
}

fn signed_token() -> (String, Value) {
    let secret = SecretKey::from_slice(&[7_u8; 32]).expect("valid deterministic test key");
    let public = secret.public_key().to_encoded_point(false);
    let kid = "provider-key-1";
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "key_ops": ["verify"],
        "kid": kid,
        "x": URL_SAFE_NO_PAD.encode(public.x().expect("x coordinate")),
        "y": URL_SAFE_NO_PAD.encode(public.y().expect("y coordinate"))
    });
    let now = Utc::now().timestamp();
    let claims = json!({
        "iss": "https://identity.example/realms/marty",
        "sub": "user-1",
        "email": "alice@example.com",
        "aud": "marty-ui",
        "exp": now + 300,
        "iat": now - 10,
        "nonce": "nonce-1"
    });
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_owned());
    let der = secret.to_pkcs8_der().expect("PKCS#8 key");
    let token =
        encode(&header, &claims, &EncodingKey::from_ec_der(der.as_bytes())).expect("signed token");
    (token, json!({"keys": [jwk]}))
}

#[test]
fn authorization_registration_and_logout_urls_preserve_keycloak_contract() {
    let provider = provider(Arc::new(FakeHttp::default()));
    let login = provider
        .authorization_url(&OidcAuthorizationRequest {
            state: "state-1".to_owned(),
            code_challenge: "challenge".to_owned(),
            nonce: "nonce-1".to_owned(),
            redirect_uri: None,
            registration: false,
        })
        .expect("login URL");
    let login = Url::parse(&login).expect("parse login URL");
    let query = login
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(login.path(), "/realms/marty/protocol/openid-connect/auth");
    assert_eq!(
        query.get("scope").map(AsRef::as_ref),
        Some("openid email profile")
    );
    assert_eq!(
        query.get("prompt").map(AsRef::as_ref),
        Some("consent login")
    );
    assert_eq!(
        query.get("code_challenge_method").map(AsRef::as_ref),
        Some("S256")
    );

    let registration = provider
        .authorization_url(&OidcAuthorizationRequest {
            state: "state-1".to_owned(),
            code_challenge: "challenge".to_owned(),
            nonce: "nonce-1".to_owned(),
            redirect_uri: None,
            registration: true,
        })
        .expect("registration URL");
    let registration = Url::parse(&registration).expect("parse registration URL");
    assert_eq!(
        registration.path(),
        "/realms/marty/protocol/openid-connect/registrations"
    );
    assert!(!registration.query_pairs().any(|(name, _)| name == "prompt"));

    let logout = provider
        .logout_url(&OidcLogoutRequest {
            id_token: Some("id-token".to_owned()),
            post_logout_redirect_uri: "https://ui.example/".to_owned(),
        })
        .expect("logout URL")
        .expect("logout URL present");
    let logout = Url::parse(&logout).expect("parse logout URL");
    assert_eq!(
        logout.path(),
        "/realms/marty/protocol/openid-connect/logout"
    );
    assert!(logout
        .query_pairs()
        .any(|(name, value)| name == "id_token_hint" && value == "id-token"));
}

#[tokio::test]
async fn validation_uses_canonical_kernel_and_refreshes_once_for_rotated_keys() {
    let http = Arc::new(FakeHttp::default());
    *http.discovery.lock().expect("discovery lock") = Some(json!({
        "issuer": "https://identity.example/realms/marty",
        "jwks_uri": "https://identity.example/realms/marty/protocol/openid-connect/certs"
    }));
    let (token, jwks) = signed_token();
    http.jwks
        .lock()
        .expect("JWKS lock")
        .extend([json!({"keys": []}), jwks]);
    let identity = provider(http.clone())
        .validate_tokens(&token, "opaque-access-token", "nonce-1")
        .await
        .expect("valid identity after key rotation");
    assert_eq!(identity.user_info.sub, "user-1");
    assert_eq!(identity.id_token_claims["email"], "alice@example.com");
    assert_eq!(identity.access_token_claims, json!({}));
    let urls = http.get_urls.lock().expect("GET lock");
    assert_eq!(
        urls.iter()
            .filter(|url| url.ends_with("/.well-known/openid-configuration"))
            .count(),
        2
    );
    assert_eq!(
        urls.iter()
            .filter(|url| url.ends_with("/protocol/openid-connect/certs"))
            .count(),
        2
    );
    assert!(urls
        .iter()
        .filter(|url| url.ends_with("/protocol/openid-connect/certs"))
        .all(|url| url.starts_with("http://keycloak:8080/")));
}

#[tokio::test]
async fn untrusted_discovery_and_jwks_origins_fail_before_key_fetch() {
    let http = Arc::new(FakeHttp::default());
    *http.discovery.lock().expect("discovery lock") = Some(json!({
        "issuer": "https://identity.example/realms/marty",
        "jwks_uri": "https://attacker.example/keys"
    }));
    let (token, _) = signed_token();
    let error = provider(http.clone())
        .validate_tokens(&token, "opaque", "nonce-1")
        .await
        .expect_err("untrusted JWKS origin must fail");
    assert_eq!(error.code, "untrusted_oidc_jwks_uri");
    assert_eq!(http.get_urls.lock().expect("GET lock").len(), 1);
}

#[tokio::test]
async fn token_exchange_preserves_pkce_redirect_and_client_auth_fields() {
    let http = Arc::new(FakeHttp::default());
    *http.post_response.lock().expect("post lock") = Some(json!({
        "access_token": "access-token",
        "id_token": "id-token",
        "refresh_token": "refresh-token"
    }));
    let tokens = provider(http.clone())
        .exchange_code(&OidcCodeExchange {
            code: "code-1".to_owned(),
            code_verifier: "verifier".to_owned(),
            redirect_uri: Some("https://beta.example/v1/auth/callback".to_owned()),
        })
        .await
        .expect("token exchange");
    assert_eq!(tokens.access_token, "access-token");
    let form = http
        .posted_form
        .lock()
        .expect("form lock")
        .iter()
        .cloned()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(
        form.get("grant_type").map(String::as_str),
        Some("authorization_code")
    );
    assert_eq!(
        form.get("redirect_uri").map(String::as_str),
        Some("https://beta.example/v1/auth/callback")
    );
    assert_eq!(
        form.get("client_secret").map(String::as_str),
        Some("secret")
    );
}

#[test]
fn invalid_configuration_fails_closed() {
    let mut invalid = config();
    invalid.allowed_algorithms.clear();
    let error = KeycloakOidcProvider::new(invalid, Arc::new(FakeHttp::default()))
        .err()
        .expect("empty algorithm list must fail");
    assert_eq!(error.code, "invalid_oidc_configuration");
}
