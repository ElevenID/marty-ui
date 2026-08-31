use std::sync::Arc;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use marty_didcomm::{DidDocument, DidResolver, VerificationMethod};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::{Map, Value};
use thiserror::Error;

use super::GovernanceSnapshot;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerKeyRequest<'a> {
    pub issuer_did: &'a str,
    pub verification_method_id: Option<&'a str>,
    pub credential_format: Option<&'a str>,
    pub key_purpose: Option<&'a str>,
    pub algorithm: Option<&'a str>,
}

#[derive(Clone, PartialEq)]
pub struct ResolvedIssuerKey {
    public_jwk: Value,
    verification_method_id: String,
}

impl std::fmt::Debug for ResolvedIssuerKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResolvedIssuerKey([VALIDATED PUBLIC KEY])")
    }
}

impl ResolvedIssuerKey {
    #[must_use]
    pub fn public_jwk(&self) -> &Value {
        &self.public_jwk
    }

    #[must_use]
    pub fn verification_method_id(&self) -> &str {
        &self.verification_method_id
    }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum IssuerResolutionError {
    #[error("issuer is not trusted by the governed profile")]
    Untrusted,
    #[error("organization-scoped issuer resolution is unavailable")]
    Unavailable,
    #[error("organization-scoped issuer resolution returned unusable provenance")]
    Invalid,
    #[error("issuer DID did not resolve to a usable public JWK")]
    UnusablePublicKey,
}

#[async_trait]
pub trait IssuerKeyResolver: Send + Sync {
    async fn resolve(
        &self,
        governance: &GovernanceSnapshot,
        request: IssuerKeyRequest<'_>,
    ) -> Result<ResolvedIssuerKey, IssuerResolutionError>;
}

#[derive(Clone)]
pub struct OrganizationIssuerKeyResolver {
    client: Client,
    base_url: String,
    api_key: String,
    public_resolver: Arc<DidResolver>,
}

impl std::fmt::Debug for OrganizationIssuerKeyResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OrganizationIssuerKeyResolver")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .finish()
    }
}

impl OrganizationIssuerKeyResolver {
    pub fn new(
        base_url: String,
        api_key: String,
        timeout: std::time::Duration,
        did_web_allowed_hosts: impl IntoIterator<Item = String>,
    ) -> Result<Self, IssuerResolutionError> {
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| IssuerResolutionError::Unavailable)?;
        Ok(Self {
            client,
            base_url,
            api_key,
            public_resolver: Arc::new(
                DidResolver::new().allow_did_web_hosts(did_web_allowed_hosts),
            ),
        })
    }
}

#[derive(Deserialize)]
struct ResolverResponse {
    ok: bool,
    organization_id: String,
    issuer_did: String,
    verification_method_id: String,
    public_jwk: Option<Value>,
    did_document: Value,
    verification_method: Value,
    resolver: Value,
}

#[async_trait]
impl IssuerKeyResolver for OrganizationIssuerKeyResolver {
    async fn resolve(
        &self,
        governance: &GovernanceSnapshot,
        request: IssuerKeyRequest<'_>,
    ) -> Result<ResolvedIssuerKey, IssuerResolutionError> {
        if !governance
            .trust_profile()
            .trusted_issuers()
            .iter()
            .any(|issuer| issuer == request.issuer_did)
        {
            return Err(IssuerResolutionError::Untrusted);
        }
        let mut query = vec![
            ("organization_id", governance.organization_id()),
            ("issuer_did", request.issuer_did),
        ];
        if let Some(method) = request.verification_method_id {
            query.push(("verification_method_id", method));
        }
        if let Some(algorithm) = request.algorithm {
            query.push(("algorithm", algorithm));
        }
        if let Some(credential_format) = request.credential_format {
            query.push(("credential_format", credential_format));
        }
        if let Some(key_purpose) = request.key_purpose {
            query.push(("key_purpose", key_purpose));
        }
        let response = self
            .client
            .get(format!("{}/resolve-issuer-did", self.base_url))
            .header("X-API-Key", &self.api_key)
            .query(&query)
            .send()
            .await;
        let organization_result = match response {
            Ok(response) if response.status() == StatusCode::OK => response
                .json::<ResolverResponse>()
                .await
                .map_err(|_| IssuerResolutionError::Invalid)
                .and_then(|response| validate_response(governance, &request, response)),
            Ok(_) | Err(_) => Err(IssuerResolutionError::Unavailable),
        };
        match organization_result {
            Ok(key) => Ok(key),
            Err(error) if !governance.trust_profile().allow_public_did_fallback() => Err(error),
            Err(_) => resolve_public(&self.public_resolver, &request).await,
        }
    }
}

async fn resolve_public(
    resolver: &DidResolver,
    request: &IssuerKeyRequest<'_>,
) -> Result<ResolvedIssuerKey, IssuerResolutionError> {
    let resolution = resolver
        .resolve_with_metadata(request.issuer_did)
        .await
        .map_err(|_| IssuerResolutionError::Unavailable)?;
    select_public_key(&resolution.document, request)
}

fn select_public_key(
    document: &DidDocument,
    request: &IssuerKeyRequest<'_>,
) -> Result<ResolvedIssuerKey, IssuerResolutionError> {
    if document.id != request.issuer_did {
        return Err(IssuerResolutionError::Invalid);
    }
    let authorized = document
        .assertion_method
        .iter()
        .filter_map(|entry| match entry {
            Value::String(value) => normalize_method_id(&document.id, value),
            Value::Object(value) => normalize_method_id(&document.id, string(value, "id")),
            _ => None,
        })
        .collect::<Vec<_>>();
    let requested = request
        .verification_method_id
        .map(|value| normalize_method_id(&document.id, value))
        .transpose_or_invalid()?;
    let candidates = document
        .verification_method
        .iter()
        .filter_map(|method| public_method_jwk(document, method, &authorized, request.algorithm))
        .filter(|(method_id, _)| requested.as_ref().is_none_or(|value| value == method_id))
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Err(IssuerResolutionError::UnusablePublicKey);
    }
    if candidates.len() != 1 {
        return Err(IssuerResolutionError::Invalid);
    }
    let (verification_method_id, public_jwk) =
        candidates.into_iter().next().expect("length checked");
    Ok(ResolvedIssuerKey {
        public_jwk,
        verification_method_id,
    })
}

fn public_method_jwk(
    document: &DidDocument,
    method: &VerificationMethod,
    authorized: &[String],
    algorithm: Option<&str>,
) -> Option<(String, Value)> {
    let method_id = normalize_method_id(&document.id, &method.id)?;
    if method.controller != document.id || !authorized.contains(&method_id) {
        return None;
    }
    let mut jwk = serde_json::to_value(method.public_key_jwk.as_ref()?).ok()?;
    let object = jwk.as_object_mut()?;
    object.retain(|_, value| !value.is_null());
    repair_compressed_p256_jwk(object)?;
    object.insert("kid".into(), Value::String(method_id.clone()));
    valid_public_jwk(&jwk, &method_id, algorithm).then_some((method_id, jwk))
}

/// The pinned native resolver preserves a compressed SEC1 P-256 point in `x`.
/// Normalize it into a standards-shaped public JWK before verification.
fn repair_compressed_p256_jwk(jwk: &mut Map<String, Value>) -> Option<()> {
    if string(jwk, "kty") != "EC" || string(jwk, "crv") != "P-256" || !string(jwk, "y").is_empty() {
        return Some(());
    }
    let compressed = URL_SAFE_NO_PAD.decode(string(jwk, "x")).ok()?;
    let key = p256::PublicKey::from_sec1_bytes(&compressed).ok()?;
    let point = key.to_encoded_point(false);
    jwk.insert(
        "x".into(),
        Value::String(URL_SAFE_NO_PAD.encode(point.x()?)),
    );
    jwk.insert(
        "y".into(),
        Value::String(URL_SAFE_NO_PAD.encode(point.y()?)),
    );
    Some(())
}

fn validate_response(
    governance: &GovernanceSnapshot,
    request: &IssuerKeyRequest<'_>,
    response: ResolverResponse,
) -> Result<ResolvedIssuerKey, IssuerResolutionError> {
    let method_id = normalize_method_id(request.issuer_did, &response.verification_method_id)
        .ok_or(IssuerResolutionError::Invalid)?;
    let requested_method = request
        .verification_method_id
        .map(|value| normalize_method_id(request.issuer_did, value))
        .transpose_or_invalid()?;
    if !response.ok
        || response.organization_id != governance.organization_id()
        || response.issuer_did != request.issuer_did
        || !method_id.starts_with(&format!("{}#", request.issuer_did))
        || requested_method
            .as_deref()
            .is_some_and(|requested| requested != method_id)
        || !valid_did_document(&response.did_document, request.issuer_did, &method_id)
        || !valid_method(
            &response.verification_method,
            request.issuer_did,
            &method_id,
        )
        || !valid_resolver_provenance(&response.resolver)
    {
        return Err(IssuerResolutionError::Invalid);
    }
    let public_jwk = response
        .public_jwk
        .ok_or(IssuerResolutionError::UnusablePublicKey)?;
    if !valid_public_jwk(&public_jwk, &method_id, request.algorithm) {
        return Err(IssuerResolutionError::UnusablePublicKey);
    }
    Ok(ResolvedIssuerKey {
        public_jwk,
        verification_method_id: method_id,
    })
}

trait TransposeInvalid<T> {
    fn transpose_or_invalid(self) -> Result<Option<T>, IssuerResolutionError>;
}

impl<T> TransposeInvalid<T> for Option<Option<T>> {
    fn transpose_or_invalid(self) -> Result<Option<T>, IssuerResolutionError> {
        self.map(|value| value.ok_or(IssuerResolutionError::Invalid))
            .transpose()
    }
}

fn normalize_method_id(issuer_did: &str, method_id: &str) -> Option<String> {
    let method_id = method_id.trim();
    if method_id.is_empty() {
        None
    } else if method_id.starts_with('#') {
        Some(format!("{issuer_did}{method_id}"))
    } else if method_id.starts_with("did:") || method_id.contains('#') {
        Some(method_id.into())
    } else {
        Some(format!("{issuer_did}#{method_id}"))
    }
}

fn valid_public_jwk(jwk: &Value, method_id: &str, algorithm: Option<&str>) -> bool {
    let Some(jwk) = jwk.as_object() else {
        return false;
    };
    if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
        .iter()
        .any(|field| jwk.contains_key(*field))
        || normalize_method_id(
            method_id.split('#').next().unwrap_or_default(),
            string(jwk, "kid"),
        )
        .as_deref()
            != Some(method_id)
    {
        return false;
    }
    let structural = match string(jwk, "kty") {
        "EC" => nonempty(jwk, &["crv", "x", "y"]),
        "OKP" => nonempty(jwk, &["crv", "x"]),
        "RSA" => nonempty(jwk, &["n", "e"]),
        _ => false,
    };
    structural
        && algorithm.is_none_or(|expected| {
            jwk.get("alg")
                .and_then(Value::as_str)
                .is_none_or(|actual| actual == expected)
                && algorithm_compatible(jwk, expected)
        })
}

fn algorithm_compatible(jwk: &Map<String, Value>, algorithm: &str) -> bool {
    match algorithm {
        "ES256" => string(jwk, "kty") == "EC" && string(jwk, "crv") == "P-256",
        "ES384" => string(jwk, "kty") == "EC" && string(jwk, "crv") == "P-384",
        "ES512" => string(jwk, "kty") == "EC" && string(jwk, "crv") == "P-521",
        "EdDSA" => string(jwk, "kty") == "OKP" && matches!(string(jwk, "crv"), "Ed25519" | "Ed448"),
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => string(jwk, "kty") == "RSA",
        _ => false,
    }
}

fn valid_did_document(document: &Value, issuer_did: &str, method_id: &str) -> bool {
    let Some(document) = document.as_object() else {
        return false;
    };
    if string(document, "id") != issuer_did {
        return false;
    }
    let methods = document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|method| valid_method(method, issuer_did, method_id))
        .count();
    methods == 1
        && relationship_ids(document, issuer_did, "assertionMethod")
            .iter()
            .any(|value| value == method_id)
}

fn valid_method(method: &Value, issuer_did: &str, method_id: &str) -> bool {
    method.as_object().is_some_and(|method| {
        normalize_method_id(issuer_did, string(method, "id")).as_deref() == Some(method_id)
            && string(method, "controller") == issuer_did
    })
}

fn relationship_ids(document: &Map<String, Value>, issuer_did: &str, name: &str) -> Vec<String> {
    document
        .get(name)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| match entry {
            Value::String(value) => normalize_method_id(issuer_did, value),
            Value::Object(value) => normalize_method_id(issuer_did, string(value, "id")),
            _ => None,
        })
        .collect()
}

fn valid_resolver_provenance(resolver: &Value) -> bool {
    resolver.as_object().is_some_and(|resolver| {
        string(resolver, "type") == "organization_issuer_profile"
            && resolver.get("public_fallback_used") == Some(&Value::Bool(false))
    })
}

fn nonempty(object: &Map<String, Value>, fields: &[&str]) -> bool {
    fields.iter().all(|field| !string(object, field).is_empty())
}

fn string<'a>(object: &'a Map<String, Value>, name: &str) -> &'a str {
    object.get(name).and_then(Value::as_str).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials_compat::{GovernanceEngine, GovernancePurpose};

    fn governance() -> GovernanceSnapshot {
        let fixture: Value =
            serde_json::from_str(marty_verification::governance::behavior_fixture_json()).unwrap();
        GovernanceEngine::new(&fixture["governance"].to_string())
            .unwrap()
            .authorize("purpose-scoped-test-key", GovernancePurpose::Direct)
            .unwrap()
    }

    fn valid_response() -> ResolverResponse {
        let method = "did:web:issuer.example#key-1";
        ResolverResponse {
            ok: true,
            organization_id: "123e4567-e89b-42d3-a456-426614174000".into(),
            issuer_did: "did:web:issuer.example".into(),
            verification_method_id: method.into(),
            public_jwk: Some(serde_json::json!({
                "kty":"EC","crv":"P-256","x":"x","y":"y","kid":method,"alg":"ES256"
            })),
            did_document: serde_json::json!({
                "id":"did:web:issuer.example",
                "verificationMethod":[{"id":method,"controller":"did:web:issuer.example"}],
                "assertionMethod":[method]
            }),
            verification_method: serde_json::json!({
                "id":method,"controller":"did:web:issuer.example"
            }),
            resolver: serde_json::json!({
                "type":"organization_issuer_profile","public_fallback_used":false
            }),
        }
    }

    #[test]
    fn resolver_response_is_bound_to_governance_issuer_method_and_public_key() {
        let governance = governance();
        let request = IssuerKeyRequest {
            issuer_did: "did:web:issuer.example",
            verification_method_id: Some("#key-1"),
            credential_format: Some("vds_nc"),
            key_purpose: Some("vdsnc_signing"),
            algorithm: Some("ES256"),
        };
        let key = validate_response(&governance, &request, valid_response()).unwrap();
        assert_eq!(
            format!("{key:?}"),
            "ResolvedIssuerKey([VALIDATED PUBLIC KEY])"
        );

        for mutate in [
            |response: &mut ResolverResponse| response.organization_id = "other".into(),
            |response: &mut ResolverResponse| response.issuer_did = "did:web:other".into(),
            |response: &mut ResolverResponse| {
                response.resolver["public_fallback_used"] = Value::Bool(true)
            },
        ] {
            let mut response = valid_response();
            mutate(&mut response);
            assert_eq!(
                validate_response(&governance, &request, response),
                Err(IssuerResolutionError::Invalid)
            );
        }

        for public_jwk in [
            None,
            Some(serde_json::json!({
                "kty":"EC","crv":"P-256","x":"x","y":"y",
                "kid":"did:web:issuer.example#key-1","alg":"ES256","d":"secret"
            })),
        ] {
            let mut response = valid_response();
            response.public_jwk = public_jwk;
            assert_eq!(
                validate_response(&governance, &request, response),
                Err(IssuerResolutionError::UnusablePublicKey)
            );
        }
    }

    #[test]
    fn method_ids_match_the_frozen_bare_fragment_and_absolute_normalization() {
        let issuer = "did:web:issuer.example";
        for (input, expected) in [
            ("key-1", "did:web:issuer.example#key-1"),
            ("#key-1", "did:web:issuer.example#key-1"),
            (
                "did:web:issuer.example#key-1",
                "did:web:issuer.example#key-1",
            ),
        ] {
            assert_eq!(
                normalize_method_id(issuer, input).as_deref(),
                Some(expected)
            );
        }
    }

    #[tokio::test]
    async fn native_public_resolution_selects_only_an_authorized_unambiguous_key() {
        let public_jwk = serde_json::json!({
            "kty":"OKP","crv":"Ed25519",
            "x":"11qYAYdk9Jf1h8R9VhL1Q5gFg2z9T_hnP9g7nC3K7rQ",
            "alg":"EdDSA"
        });
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&public_jwk).unwrap());
        let did = format!("did:jwk:{encoded}");
        let resolver = DidResolver::new();
        let mut document = resolver.resolve(&did).await.unwrap();
        let request = IssuerKeyRequest {
            issuer_did: &did,
            verification_method_id: None,
            credential_format: None,
            key_purpose: None,
            algorithm: Some("EdDSA"),
        };

        let selected = select_public_key(&document, &request).unwrap();
        assert_eq!(selected.public_jwk()["kid"], format!("{did}#0"));
        assert!(selected.public_jwk().get("d").is_none());

        let mut second = document.verification_method[0].clone();
        second.id = format!("{did}#1");
        document
            .assertion_method
            .push(Value::String(second.id.clone()));
        document.verification_method.push(second);
        assert_eq!(
            select_public_key(&document, &request),
            Err(IssuerResolutionError::Invalid)
        );
        let explicit = IssuerKeyRequest {
            verification_method_id: Some("#0"),
            ..request
        };
        assert!(select_public_key(&document, &explicit).is_ok());
    }

    #[test]
    fn compressed_p256_output_is_normalized_to_a_complete_public_jwk() {
        let secret = p256::SecretKey::from_slice(&[7_u8; 32]).unwrap();
        let compressed = secret.public_key().to_encoded_point(true);
        let mut jwk = serde_json::json!({
            "kty":"EC",
            "crv":"P-256",
            "x":URL_SAFE_NO_PAD.encode(compressed.as_bytes())
        })
        .as_object()
        .unwrap()
        .clone();

        repair_compressed_p256_jwk(&mut jwk).unwrap();

        assert_eq!(URL_SAFE_NO_PAD.decode(string(&jwk, "x")).unwrap().len(), 32);
        assert_eq!(URL_SAFE_NO_PAD.decode(string(&jwk, "y")).unwrap().len(), 32);
        assert!(!jwk.contains_key("d"));
    }
}
