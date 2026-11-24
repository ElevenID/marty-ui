use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use marty_auth::{
    oidc_config_from_values, KeycloakOidcProvider, OidcHttpClient, OidcProvider, PortError,
    SupabaseNativeConfig,
};
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING},
};
use serde_json::{json, Value};

const ISSUER: &str = "https://project.example.invalid/auth/v1";
const CLIENT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SUBJECT: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

struct Documents(Value);

#[async_trait]
impl OidcHttpClient for Documents {
    async fn get_json_object(
        &self,
        url: &str,
        _limit: usize,
        _name: &str,
    ) -> Result<Value, PortError> {
        if url == format!("{ISSUER}/.well-known/openid-configuration") {
            return Ok(
                json!({"issuer":ISSUER, "authorization_endpoint":format!("{ISSUER}/oauth/authorize"),
                "token_endpoint":format!("{ISSUER}/oauth/token"), "jwks_uri":format!("{ISSUER}/.well-known/jwks.json"),
                "token_endpoint_auth_methods_supported":["none"], "response_types_supported":["code"],
                "code_challenge_methods_supported":["S256"], "id_token_signing_alg_values_supported":["ES256"]}),
            );
        }
        assert_eq!(url, format!("{ISSUER}/.well-known/jwks.json"));
        Ok(self.0.clone())
    }
    async fn post_form_json_object(
        &self,
        _url: &str,
        _form: &[(String, String)],
        _limit: usize,
        _name: &str,
    ) -> Result<Value, PortError> {
        panic!("Signature qualification must not exchange real authorization codes")
    }
}

fn sign(key: &EcdsaKeyPair, claims: &Value) -> String {
    let header =
        URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"ephemeral-fixture","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let input = format!("{header}.{payload}");
    let signature = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
}

#[tokio::test]
async fn real_asymmetric_verifier_composes_native_proof_without_promoting_oauth_claims() {
    let random = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &random)
        .unwrap();
    let public = key.public_key().as_ref();
    let documents = Documents(
        json!({"keys":[{"kty":"EC", "crv":"P-256", "alg":"ES256", "use":"sig", "kid":"ephemeral-fixture",
        "x":URL_SAFE_NO_PAD.encode(&public[1..33]), "y":URL_SAFE_NO_PAD.encode(&public[33..65])}]}),
    );
    let config = oidc_config_from_values([
        ("OIDC_PROVIDER_MODE".into(), "external".into()),
        ("OIDC_ISSUER_URL".into(), ISSUER.into()),
        ("OIDC_CLIENT_ID".into(), CLIENT.into()),
        (
            "OIDC_REDIRECT_URI".into(),
            "https://app.example.invalid/v1/auth/callback".into(),
        ),
        ("OIDC_TOKEN_ENDPOINT_AUTH_METHOD".into(), "none".into()),
        ("OIDC_ALLOWED_ALGORITHMS".into(), "ES256".into()),
    ])
    .unwrap();
    let provider = KeycloakOidcProvider::new(config, Arc::new(documents))
        .unwrap()
        .with_native_authentication(Some(SupabaseNativeConfig {
            authorization_origin: "https://authorization.example.invalid".into(),
            publishable_key: "sb_publishable_SYNTHETIC_public_0123456789".into(),
        }))
        .unwrap();
    let now = Utc::now().timestamp();
    let id_claims = json!({"iss":ISSUER, "aud":CLIENT, "sub":SUBJECT, "iat":now, "exp":now+3600,
        "nonce":"request-nonce", "email":"fixture@example.invalid", "email_verified":true, "auth_time":now});
    let id_token = sign(&key, &id_claims);
    let identity = provider
        .validate_tokens(&id_token, "synthetic-access", "request-nonce")
        .await
        .unwrap();
    let native = json!({"iss":ISSUER,"aud":"authenticated","sub":SUBJECT,"email":"fixture@example.invalid", "iat":now,"exp":now+3600,"aal":"aal2",
        "session_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc", "amr":[{"method":"password","timestamp":now-2},{"method":"mfa/totp","timestamp":now-1}]});
    let token = sign(&key, &native);
    let evidence = provider
        .validate_native_authentication(&token, &identity, now - 3, now)
        .await
        .unwrap();
    assert_eq!(evidence.password_authenticated_at, now - 2);
    assert_eq!(identity.id_token_claims, id_claims);
    assert!(identity.id_token_claims.get("aal").is_none());
    assert!(provider
        .validate_tokens(&id_token, "synthetic-access", "wrong-nonce")
        .await
        .is_err());
    for (field, value) in [
        ("aud", json!(CLIENT)),
        ("iss", json!("https://attacker.invalid/auth/v1")),
        ("aal", json!("aal1")),
        ("sub", json!("dddddddd-dddd-4ddd-8ddd-dddddddddddd")),
        (
            "amr",
            json!([{"method":"password","timestamp":now-20},{"method":"totp","timestamp":now-1}]),
        ),
    ] {
        let mut invalid = native.clone();
        invalid[field] = value;
        assert!(
            provider
                .validate_native_authentication(&sign(&key, &invalid), &identity, now - 3, now)
                .await
                .is_err(),
            "accepted signed invalid {field}"
        );
    }
    let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
    let mut signature = URL_SAFE_NO_PAD.decode(&parts[2]).unwrap();
    signature[0] ^= 1;
    parts[2] = URL_SAFE_NO_PAD.encode(signature);
    assert!(provider
        .validate_native_authentication(&parts.join("."), &identity, now - 3, now)
        .await
        .is_err());
}
