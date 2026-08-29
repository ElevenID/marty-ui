use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use marty_oid4vci::jose::verify_compact_jwt_with_public_jwk;
use p256::PublicKey;
use serde_json::{Map, Value};

use crate::token_exchange::{
    ClientAuthenticationRequest, Oid4vciClientAuthenticator, TokenExchangeError,
};

pub const JWT_BEARER_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const CLOCK_SKEW_SECONDS: i64 = 60;
const MAX_ASSERTION_LIFETIME_SECONDS: i64 = 300;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredOid4vciClient {
    pub organization_id: String,
    pub client_id: String,
    pub jwks: Value,
    pub token_endpoint_auth_method: String,
    pub active: bool,
}

#[async_trait]
pub trait RegisteredClientRepository: Send + Sync {
    async fn client(
        &self,
        organization_id: &str,
        client_id: &str,
    ) -> Result<Option<RegisteredOid4vciClient>, TokenExchangeError>;

    async fn claim_assertion(
        &self,
        organization_id: &str,
        client_id: &str,
        jti: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, TokenExchangeError>;
}

#[derive(Clone)]
pub struct RegisteredClientAuthenticator {
    repository: Arc<dyn RegisteredClientRepository>,
}

impl std::fmt::Debug for RegisteredClientAuthenticator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegisteredClientAuthenticator")
            .finish_non_exhaustive()
    }
}

impl RegisteredClientAuthenticator {
    #[must_use]
    pub fn new(repository: Arc<dyn RegisteredClientRepository>) -> Self {
        Self { repository }
    }
}

#[async_trait]
impl Oid4vciClientAuthenticator for RegisteredClientAuthenticator {
    async fn authenticate(
        &self,
        request: ClientAuthenticationRequest<'_>,
    ) -> Result<(), TokenExchangeError> {
        let supplied = request
            .client_assertion_type
            .is_some_and(|value| !value.is_empty())
            || request
                .client_assertion
                .is_some_and(|value| !value.is_empty());
        let (Some(organization_id), Some(expected_client_id)) =
            (request.organization_id, request.expected_client_id)
        else {
            return if supplied {
                Err(TokenExchangeError::InvalidClient)
            } else {
                Ok(())
            };
        };
        let registered = self
            .repository
            .client(organization_id, expected_client_id)
            .await?;
        let Some(registered) = registered else {
            return if request.registration_required || supplied {
                Err(TokenExchangeError::InvalidClient)
            } else {
                Ok(())
            };
        };
        if !registered.active
            || registered.token_endpoint_auth_method != "private_key_jwt"
            || request
                .client_id
                .is_some_and(|client_id| client_id != registered.client_id)
            || request.client_assertion_type != Some(JWT_BEARER_ASSERTION_TYPE)
        {
            return Err(TokenExchangeError::InvalidClient);
        }
        let assertion = request
            .client_assertion
            .filter(|assertion| !assertion.is_empty())
            .ok_or(TokenExchangeError::InvalidClient)?;
        let verified = verify_assertion(
            assertion,
            &registered.client_id,
            &registered.jwks,
            &request.allowed_audiences,
            Utc::now(),
        )?;
        if !self
            .repository
            .claim_assertion(
                organization_id,
                &registered.client_id,
                &verified.jti,
                verified.expires_at,
            )
            .await?
        {
            return Err(TokenExchangeError::InvalidClient);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedAssertion {
    jti: String,
    expires_at: DateTime<Utc>,
}

fn verify_assertion(
    assertion: &str,
    client_id: &str,
    jwks: &Value,
    allowed_audiences: &[String],
    now: DateTime<Utc>,
) -> Result<VerifiedAssertion, TokenExchangeError> {
    let keys = normalized_keys(jwks)?;
    let mut candidates = Vec::new();
    for key in keys {
        let key_json = serde_json::to_string(key).map_err(|_| TokenExchangeError::InvalidClient)?;
        let Ok(verified) = verify_compact_jwt_with_public_jwk(assertion, &key_json, "ES256") else {
            continue;
        };
        if verified.header.get("kid") == key.get("kid") {
            candidates.push((verified.header, verified.claims));
        }
    }
    let [(header, claims)] = candidates.as_slice() else {
        return Err(TokenExchangeError::InvalidClient);
    };
    if header.get("jwk").is_some()
        || header.get("jku").is_some()
        || header.get("x5u").is_some()
        || header.get("crit").is_some_and(json_truthy)
        || header.get("b64") == Some(&Value::Bool(false))
        || !matches!(
            header.get("typ").and_then(Value::as_str),
            None | Some("JWT")
        )
    {
        return Err(TokenExchangeError::InvalidClient);
    }
    if claims.get("iss").and_then(Value::as_str) != Some(client_id)
        || claims.get("sub").and_then(Value::as_str) != Some(client_id)
        || !audience_matches(claims.get("aud"), allowed_audiences)
    {
        return Err(TokenExchangeError::InvalidClient);
    }
    let issued_at = numeric_date(claims, "iat", true)?.ok_or(TokenExchangeError::InvalidClient)?;
    let expires_at = numeric_date(claims, "exp", true)?.ok_or(TokenExchangeError::InvalidClient)?;
    let not_before = numeric_date(claims, "nbf", false)?;
    let now_seconds = now.timestamp();
    if issued_at > now_seconds + CLOCK_SKEW_SECONDS
        || issued_at < now_seconds - MAX_ASSERTION_LIFETIME_SECONDS - CLOCK_SKEW_SECONDS
        || expires_at <= now_seconds - CLOCK_SKEW_SECONDS
        || expires_at <= issued_at
        || expires_at > issued_at + MAX_ASSERTION_LIFETIME_SECONDS
        || not_before.is_some_and(|value| value > now_seconds + CLOCK_SKEW_SECONDS)
    {
        return Err(TokenExchangeError::InvalidClient);
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty() && value.len() <= 256)
        .ok_or(TokenExchangeError::InvalidClient)?;
    Ok(VerifiedAssertion {
        jti: jti.to_owned(),
        expires_at: DateTime::from_timestamp(expires_at, 0)
            .ok_or(TokenExchangeError::InvalidClient)?,
    })
}

fn normalized_keys(jwks: &Value) -> Result<&[Value], TokenExchangeError> {
    let object = jwks.as_object().ok_or(TokenExchangeError::InvalidClient)?;
    if object.len() != 1 {
        return Err(TokenExchangeError::InvalidClient);
    }
    let keys = object
        .get("keys")
        .and_then(Value::as_array)
        .filter(|keys| !keys.is_empty())
        .ok_or(TokenExchangeError::InvalidClient)?;
    let mut key_ids = BTreeSet::new();
    for key in keys {
        let object = key.as_object().ok_or(TokenExchangeError::InvalidClient)?;
        validate_key(object)?;
        let kid = object
            .get("kid")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty() && value.len() <= 256)
            .ok_or(TokenExchangeError::InvalidClient)?;
        if !key_ids.insert(kid) {
            return Err(TokenExchangeError::InvalidClient);
        }
    }
    Ok(keys)
}

fn validate_key(key: &Map<String, Value>) -> Result<(), TokenExchangeError> {
    const ALLOWED: [&str; 8] = ["alg", "crv", "key_ops", "kid", "kty", "use", "x", "y"];
    const PRIVATE: [&str; 9] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "key"];
    if key.keys().any(|field| !ALLOWED.contains(&field.as_str()))
        || PRIVATE.iter().any(|field| key.contains_key(*field))
        || key.get("kty").and_then(Value::as_str) != Some("EC")
        || key.get("crv").and_then(Value::as_str) != Some("P-256")
        || !matches!(key.get("alg").and_then(Value::as_str), None | Some("ES256"))
        || !matches!(key.get("use").and_then(Value::as_str), None | Some("sig"))
        || !key.get("x").is_some_and(Value::is_string)
        || !key.get("y").is_some_and(Value::is_string)
    {
        return Err(TokenExchangeError::InvalidClient);
    }
    if let Some(operations) = key.get("key_ops") {
        let Some(operations) = operations.as_array() else {
            return Err(TokenExchangeError::InvalidClient);
        };
        if operations.is_empty()
            || operations
                .iter()
                .any(|operation| operation.as_str() != Some("verify"))
        {
            return Err(TokenExchangeError::InvalidClient);
        }
    }
    let x = public_coordinate(key, "x")?;
    let y = public_coordinate(key, "y")?;
    let mut encoded_point = Vec::with_capacity(65);
    encoded_point.push(4);
    encoded_point.extend_from_slice(&x);
    encoded_point.extend_from_slice(&y);
    PublicKey::from_sec1_bytes(&encoded_point).map_err(|_| TokenExchangeError::InvalidClient)?;
    Ok(())
}

fn public_coordinate(key: &Map<String, Value>, name: &str) -> Result<[u8; 32], TokenExchangeError> {
    let encoded = key
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(TokenExchangeError::InvalidClient)?;
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| TokenExchangeError::InvalidClient)?
        .try_into()
        .map_err(|_| TokenExchangeError::InvalidClient)
}

fn numeric_date(
    claims: &Value,
    name: &str,
    required: bool,
) -> Result<Option<i64>, TokenExchangeError> {
    match claims.get(name) {
        None | Some(Value::Null) if !required => Ok(None),
        Some(Value::Number(value)) => value
            .as_i64()
            .or_else(|| value.as_f64().map(|value| value.trunc() as i64))
            .map(Some)
            .ok_or(TokenExchangeError::InvalidClient),
        _ => Err(TokenExchangeError::InvalidClient),
    }
}

fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn audience_matches(value: Option<&Value>, expected: &[String]) -> bool {
    let expected = expected
        .iter()
        .map(|value| value.trim_end_matches('/'))
        .collect::<BTreeSet<_>>();
    match value {
        Some(Value::String(value)) => expected.contains(value.trim_end_matches('/')),
        Some(Value::Array(values)) if !values.is_empty() => {
            values.iter().all(Value::is_string)
                && values.iter().any(|value| {
                    expected.contains(value.as_str().unwrap_or_default().trim_end_matches('/'))
                })
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use chrono::{Duration, Utc};
    use jsonwebtoken::{encode, jwk::Jwk, Algorithm, EncodingKey, Header};
    use p256::{elliptic_curve::sec1::ToEncodedPoint, pkcs8::EncodePrivateKey, SecretKey};

    use super::{audience_matches, json_truthy, normalized_keys, numeric_date, verify_assertion};
    use serde_json::json;

    #[test]
    fn audience_and_numeric_date_policy_fail_closed() {
        assert!(audience_matches(
            Some(&json!(["https://other.example", "https://issuer.example/"])),
            &["https://issuer.example".to_owned()]
        ));
        assert!(!audience_matches(
            Some(&json!([])),
            &["https://issuer.example".to_owned()]
        ));
        assert!(numeric_date(&json!({"exp": true}), "exp", true).is_err());
        assert!(numeric_date(&json!({}), "exp", true).is_err());
        assert_eq!(
            numeric_date(&json!({"exp": 12.75}), "exp", true),
            Ok(Some(12))
        );
        assert!(!json_truthy(&json!([])));
        assert!(json_truthy(&json!(["unsupported"])));
    }

    #[test]
    fn registered_client_assertions_use_only_the_registered_public_key() {
        let secret = SecretKey::from_slice(&[7_u8; 32]).expect("P-256 private key");
        let public = secret.public_key().to_encoded_point(false);
        let jwk = json!({"keys": [{
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "use": "sig",
            "kid": "wallet-key-1",
            "x": URL_SAFE_NO_PAD.encode(public.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(public.y().unwrap())
        }]});
        let now = Utc::now();
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("wallet-key-1".to_owned());
        let assertion = encode(
            &header,
            &json!({
                "iss": "wallet-client",
                "sub": "wallet-client",
                "aud": "https://issuer.example/token",
                "iat": now.timestamp(),
                "nbf": now.timestamp(),
                "exp": (now + Duration::seconds(60)).timestamp(),
                "jti": "assertion-1"
            }),
            &EncodingKey::from_ec_der(secret.to_pkcs8_der().unwrap().as_bytes()),
        )
        .expect("signed assertion");

        let verified = verify_assertion(
            &assertion,
            "wallet-client",
            &jwk,
            &["https://issuer.example/token".to_owned()],
            now,
        )
        .expect("verified registered client");
        assert_eq!(verified.jti, "assertion-1");
        assert!(verify_assertion(
            &assertion,
            "wallet-client",
            &jwk,
            &["https://other.example/token".to_owned()],
            now
        )
        .is_err());

        let attacker = SecretKey::from_slice(&[8_u8; 32]).expect("attacker P-256 key");
        let attacker_assertion = encode(
            &header,
            &json!({
                "iss": "wallet-client",
                "sub": "wallet-client",
                "aud": "https://issuer.example/token",
                "iat": now.timestamp(),
                "exp": (now + Duration::seconds(60)).timestamp(),
                "jti": "assertion-attacker"
            }),
            &EncodingKey::from_ec_der(attacker.to_pkcs8_der().unwrap().as_bytes()),
        )
        .expect("attacker assertion");
        assert!(verify_assertion(
            &attacker_assertion,
            "wallet-client",
            &jwk,
            &["https://issuer.example/token".to_owned()],
            now
        )
        .is_err());

        let mut embedded_header = header;
        embedded_header.jwk = Some(
            serde_json::from_value::<Jwk>(jwk["keys"][0].clone()).expect("embedded public JWK"),
        );
        let embedded_assertion = encode(
            &embedded_header,
            &json!({
                "iss": "wallet-client",
                "sub": "wallet-client",
                "aud": "https://issuer.example/token",
                "iat": now.timestamp(),
                "exp": (now + Duration::seconds(60)).timestamp(),
                "jti": "assertion-embedded"
            }),
            &EncodingKey::from_ec_der(secret.to_pkcs8_der().unwrap().as_bytes()),
        )
        .expect("embedded-key assertion");
        assert!(verify_assertion(
            &embedded_assertion,
            "wallet-client",
            &jwk,
            &["https://issuer.example/token".to_owned()],
            now
        )
        .is_err());

        let mut private_jwks = jwk.clone();
        private_jwks["keys"][0]["d"] = json!("private-material");
        assert!(normalized_keys(&private_jwks).is_err());
        let mut duplicate_jwks = jwk.clone();
        duplicate_jwks["keys"] = json!([jwk["keys"][0].clone(), jwk["keys"][0].clone()]);
        assert!(normalized_keys(&duplicate_jwks).is_err());
        let mut malformed_jwks = jwk.clone();
        malformed_jwks["keys"][0]["x"] = json!("AA");
        assert!(normalized_keys(&malformed_jwks).is_err());
        let mut duplicate_verify_operation = jwk;
        duplicate_verify_operation["keys"][0]["key_ops"] = json!(["verify", "verify"]);
        assert!(normalized_keys(&duplicate_verify_operation).is_ok());
    }
}
