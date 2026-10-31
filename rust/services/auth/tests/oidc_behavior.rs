use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use marty_auth::{
    KeycloakOidcProvider, OidcAuthorizationRequest, OidcCodeExchange, OidcConfig, OidcHttpClient,
    OidcLogoutRequest, OidcProvider, OidcProviderMode, PortError,
};
use serde_json::{json, Value};
use url::Url;

#[derive(Default)]
struct FakeHttp {
    discovery: Mutex<Option<Value>>,
    jwks: Mutex<VecDeque<Value>>,
    post_response: Mutex<Option<Value>>,
    get_urls: Mutex<Vec<String>>,
    posted_form: Mutex<Vec<(String, String)>>,
    post_urls: Mutex<Vec<String>>,
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
        url: &str,
        form: &[(String, String)],
        _max_bytes: usize,
        _document_name: &str,
    ) -> Result<Value, PortError> {
        *self.posted_form.lock().expect("form lock") = form.to_vec();
        self.post_urls
            .lock()
            .expect("POST lock")
            .push(url.to_owned());
        self.post_response
            .lock()
            .expect("post lock")
            .clone()
            .ok_or_else(|| PortError::new("missing_fixture", "missing POST response"))
    }
}

fn config() -> OidcConfig {
    OidcConfig {
        provider_mode: OidcProviderMode::Keycloak,
        trusted_endpoint_origins: Vec::new(),
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
    let fixture: Value = serde_json::from_str(include_str!("fixtures/oidc_public_id_token.json"))
        .expect("public OIDC ID token fixture");
    let token = fixture["id_token"]
        .as_str()
        .expect("signed public ID token")
        .to_owned();
    (token, fixture["jwks"].clone())
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
    assert_eq!(query.get("max_age").map(AsRef::as_ref), Some("0"));
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
    assert!(!registration
        .query_pairs()
        .any(|(name, _)| name == "max_age"));

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

fn external_config() -> OidcConfig {
    let mut config = config();
    config.provider_mode = OidcProviderMode::External;
    config.issuer_url = "https://identity.example/realms/marty".into();
    config.external_issuer_url.clone_from(&config.issuer_url);
    config
}

fn external_fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/external_oidc_public_id_tokens.json"))
        .expect("public external OIDC fixture")
}

fn external_http() -> Arc<FakeHttp> {
    let http = Arc::new(FakeHttp::default());
    *http.discovery.lock().unwrap() = Some(json!({
        "issuer": "https://identity.example/realms/marty",
        "authorization_endpoint": "https://identity.example/oauth2/authorize",
        "token_endpoint": "https://identity.example/oauth2/token",
        "jwks_uri": "https://identity.example/public/keys",
        "response_types_supported": ["code"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"]
    }));
    http.jwks
        .lock()
        .unwrap()
        .push_back(external_fixture()["jwks"].clone());
    *http.post_response.lock().unwrap() = Some(json!({"access_token": "access", "id_token": "id"}));
    http
}

fn authorization_request(registration: bool) -> OidcAuthorizationRequest {
    OidcAuthorizationRequest {
        state: "state-1".into(),
        code_challenge: "challenge".into(),
        nonce: "nonce-1".into(),
        redirect_uri: None,
        registration,
    }
}

fn exchange_request() -> OidcCodeExchange {
    OidcCodeExchange {
        code: "one-time-code".into(),
        code_verifier: "verifier".into(),
        redirect_uri: Some("https://ui.example/v1/auth/callback".into()),
    }
}

#[tokio::test]
async fn external_discovery_drives_existing_code_flow_without_keycloak_urls() {
    let http = external_http();
    let provider = KeycloakOidcProvider::new(external_config(), http.clone()).unwrap();
    assert_eq!(
        provider
            .authorization_url(&authorization_request(false))
            .unwrap_err()
            .code,
        "oidc_metadata_unavailable"
    );
    provider.health_check().await.unwrap();
    let login = Url::parse(
        &provider
            .authorization_url(&authorization_request(false))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(login.path(), "/oauth2/authorize");
    let query = login
        .query_pairs()
        .collect::<std::collections::HashMap<_, _>>();
    for (name, value) in [
        ("response_type", "code"),
        ("client_id", "marty-ui"),
        ("state", "state-1"),
        ("nonce", "nonce-1"),
        ("code_challenge", "challenge"),
        ("code_challenge_method", "S256"),
    ] {
        assert_eq!(query.get(name).map(AsRef::as_ref), Some(value));
    }
    provider.exchange_code(&exchange_request()).await.unwrap();
    assert_eq!(
        *http.post_urls.lock().unwrap(),
        ["https://identity.example/oauth2/token"]
    );
    let form = http
        .posted_form
        .lock()
        .unwrap()
        .iter()
        .cloned()
        .collect::<std::collections::HashMap<_, _>>();
    assert_eq!(form["client_secret"], "secret");
    assert_eq!(form["code_verifier"], "verifier");
    assert_eq!(form["redirect_uri"], "https://ui.example/v1/auth/callback");
    assert!(http
        .get_urls
        .lock()
        .unwrap()
        .iter()
        .all(|url| !url.contains("protocol/openid-connect")));
}

#[tokio::test]
async fn external_registration_and_logout_require_explicit_provider_metadata() {
    let http = external_http();
    // This is dynamic client registration, never an end-user signup URL.
    http.discovery.lock().unwrap().as_mut().unwrap()["registration_endpoint"] =
        json!("https://identity.example/clients/register");
    let provider = KeycloakOidcProvider::new(external_config(), http.clone()).unwrap();
    provider.health_check().await.unwrap();
    assert_eq!(
        provider
            .authorization_url(&authorization_request(true))
            .unwrap_err()
            .code,
        "oidc_registration_unsupported"
    );
    let logout = OidcLogoutRequest {
        id_token: Some("private-id-token".into()),
        post_logout_redirect_uri: "https://ui.example/".into(),
    };
    assert_eq!(provider.logout_url(&logout).unwrap(), None);

    {
        let mut discovery = http.discovery.lock().unwrap();
        let discovery = discovery.as_mut().unwrap();
        discovery["prompt_values_supported"] = json!(["login", "consent", "create"]);
        discovery["end_session_endpoint"] = json!("https://identity.example/session/end");
    }
    http.jwks
        .lock()
        .unwrap()
        .push_back(external_fixture()["jwks"].clone());
    provider.health_check().await.unwrap();
    let signup = Url::parse(
        &provider
            .authorization_url(&authorization_request(true))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(signup.path(), "/oauth2/authorize");
    assert!(signup
        .query_pairs()
        .any(|(name, value)| name == "prompt" && value == "create"));
    assert!(!signup.query_pairs().any(|(name, _)| name == "max_age"));
    let logout = Url::parse(&provider.logout_url(&logout).unwrap().unwrap()).unwrap();
    assert_eq!(logout.path(), "/session/end");
    assert!(logout
        .query_pairs()
        .any(|(name, value)| name == "id_token_hint" && value == "private-id-token"));
}

#[tokio::test]
async fn external_untrusted_metadata_never_receives_code_or_client_secret() {
    for field in [
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "end_session_endpoint",
    ] {
        for url in [
            "https://attacker.example/collect",
            "http://identity.example/collect",
            "https://user:password@identity.example/collect",
            "https://identity.example/collect#fragment",
            "https://identity.example/collect?client_id=other",
        ] {
            let http = external_http();
            http.discovery.lock().unwrap().as_mut().unwrap()[field] = json!(url);
            let provider = KeycloakOidcProvider::new(external_config(), http.clone()).unwrap();
            assert!(
                provider.exchange_code(&exchange_request()).await.is_err(),
                "{field}: {url}"
            );
            assert!(http.post_urls.lock().unwrap().is_empty());
            assert!(http.posted_form.lock().unwrap().is_empty());
            assert_eq!(http.get_urls.lock().unwrap().len(), 1);
            assert!(provider
                .authorization_url(&authorization_request(false))
                .is_err());
        }
    }
}

#[tokio::test]
async fn external_explicit_endpoint_origins_are_bounded_and_preserve_exact_issuer() {
    let http = external_http();
    {
        let mut discovery = http.discovery.lock().unwrap();
        let discovery = discovery.as_mut().unwrap();
        discovery["authorization_endpoint"] = json!("https://login.example/authorize");
        discovery["token_endpoint"] = json!("https://login.example/token");
        discovery["jwks_uri"] = json!("https://keys.example/jwks");
    }
    let mut config = external_config();
    config.trusted_endpoint_origins = vec![
        "https://login.example/".into(),
        "https://keys.example".into(),
    ];
    let provider = KeycloakOidcProvider::new(config, http.clone()).unwrap();
    provider.exchange_code(&exchange_request()).await.unwrap();
    assert_eq!(
        *http.post_urls.lock().unwrap(),
        ["https://login.example/token"]
    );
    let fixture = external_fixture();
    let identity = provider
        .validate_tokens(
            fixture["tokens"]["verified"].as_str().unwrap(),
            "opaque-access-token",
            "nonce-1",
        )
        .await
        .unwrap();
    assert_eq!(
        identity.id_token_claims["iss"],
        "https://identity.example/realms/marty"
    );
    assert_eq!(identity.user_info.sub, "user-1");

    let http = external_http();
    let mut config = external_config();
    config.issuer_url.push('/');
    config.external_issuer_url.push('/');
    let provider = KeycloakOidcProvider::new(config, http.clone()).unwrap();
    assert_eq!(
        provider
            .exchange_code(&exchange_request())
            .await
            .unwrap_err()
            .code,
        "oidc_discovery_issuer_mismatch"
    );
    assert!(http.post_urls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn external_unsupported_client_authentication_fails_before_post() {
    for methods in [
        None,
        Some(json!(["client_secret_basic"])),
        Some(json!(["private_key_jwt"])),
        Some(json!(["none"])),
        Some(json!([])),
        Some(json!("client_secret_post")),
    ] {
        let http = external_http();
        {
            let mut discovery = http.discovery.lock().unwrap();
            let discovery = discovery.as_mut().unwrap();
            if let Some(methods) = methods {
                discovery["token_endpoint_auth_methods_supported"] = methods;
            } else {
                discovery
                    .as_object_mut()
                    .unwrap()
                    .remove("token_endpoint_auth_methods_supported");
            }
        }
        let provider = KeycloakOidcProvider::new(external_config(), http.clone()).unwrap();
        assert!(provider.exchange_code(&exchange_request()).await.is_err());
        assert!(http.post_urls.lock().unwrap().is_empty());
        assert_eq!(http.get_urls.lock().unwrap().len(), 1);
    }
    let http = external_http();
    http.discovery.lock().unwrap().as_mut().unwrap()["token_endpoint_auth_methods_supported"] =
        json!(["none"]);
    let mut config = external_config();
    config.client_secret = None;
    let provider = KeycloakOidcProvider::new(config, http.clone()).unwrap();
    provider.exchange_code(&exchange_request()).await.unwrap();
    assert!(!http
        .posted_form
        .lock()
        .unwrap()
        .iter()
        .any(|(name, _)| name == "client_secret"));
}

#[tokio::test]
async fn external_verified_identity_gate_runs_after_signature_nonce_and_issuer_validation() {
    let fixture = external_fixture();
    let http = external_http();
    let provider = KeycloakOidcProvider::new(external_config(), http).unwrap();
    let verified = fixture["tokens"]["verified"].as_str().unwrap();
    let identity = provider
        .validate_tokens(verified, "access", "nonce-1")
        .await
        .unwrap();
    assert!(identity.user_info.email_verified);
    assert_eq!(identity.user_info.email, "alice@example.com");
    for case in [
        "unverified",
        "missing_verification",
        "string_verification",
        "missing_email",
        "blank_email",
        "blank_subject",
    ] {
        let token = fixture["tokens"][case].as_str().unwrap();
        assert_eq!(
            provider
                .validate_tokens(token, "access", "nonce-1")
                .await
                .unwrap_err()
                .code,
            "oidc_verified_email_required",
            "{case}"
        );
    }
    assert_eq!(
        provider
            .validate_tokens(verified, "access", "wrong-nonce")
            .await
            .unwrap_err()
            .code,
        "oidc_token_validation_failed"
    );
    let mut tampered = verified.to_owned();
    let signature = tampered.rfind('.').unwrap() + 1;
    tampered.replace_range(
        signature..signature + 1,
        if &verified[signature..signature + 1] == "A" {
            "B"
        } else {
            "A"
        },
    );
    assert_eq!(
        provider
            .validate_tokens(&tampered, "access", "nonce-1")
            .await
            .unwrap_err()
            .code,
        "oidc_token_validation_failed"
    );
}

#[test]
fn external_configuration_rejects_ambiguous_or_unbounded_endpoint_authority() {
    for origin in [
        "http://identity.example",
        "https://*.example",
        "https://identity.example/path",
        "https://identity.example?query=value",
        "https://identity.example#fragment",
        "https://user@identity.example",
    ] {
        let mut config = external_config();
        config.trusted_endpoint_origins = vec![origin.into()];
        assert!(config.validate().is_err(), "{origin}");
    }
    let mut duplicate = external_config();
    duplicate.trusted_endpoint_origins = vec![
        "https://login.example".into(),
        "https://login.example/".into(),
    ];
    assert!(duplicate.validate().is_err());
    let mut excessive = external_config();
    excessive.trusted_endpoint_origins = (0..9)
        .map(|index| format!("https://login{index}.example"))
        .collect();
    assert!(excessive.validate().is_err());
    let mut split_issuer = external_config();
    split_issuer.issuer_url = "https://internal.example/issuer".into();
    assert!(split_issuer.validate().is_err());
    let mut legacy = config();
    legacy.trusted_endpoint_origins = vec!["https://login.example".into()];
    assert!(legacy.validate().is_err());
}
