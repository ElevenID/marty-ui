use std::collections::BTreeSet;

use async_trait::async_trait;
use marty_didcomm::{DidDocument, DidResolver, DidcommError, VerificationMethod};
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::reject_private_custody_metadata;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerKeyResolution {
    pub verification_keys: Vec<Value>,
    pub source: String,
    pub retrieved_at: String,
    pub content_sha256: String,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum IssuerKeyResolutionError {
    #[error("TRUST_PROFILE.ISSUER_DID_INVALID")]
    Invalid,
    #[error("TRUST_PROFILE.ISSUER_DID_RESOLUTION_UNAVAILABLE")]
    Unavailable,
}

#[async_trait]
pub trait IssuerKeyResolver: Send + Sync {
    async fn resolve(&self, did: &str) -> Result<IssuerKeyResolution, IssuerKeyResolutionError>;
}

pub struct NativeIssuerKeyResolver {
    resolver: DidResolver,
}

impl std::fmt::Debug for NativeIssuerKeyResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeIssuerKeyResolver")
            .finish_non_exhaustive()
    }
}

impl NativeIssuerKeyResolver {
    #[must_use]
    pub fn new(
        internal_base_urls: impl IntoIterator<Item = String>,
        allowed_hosts: impl IntoIterator<Item = String>,
    ) -> Self {
        let resolver = DidResolver::new()
            .with_did_web_internal_base_urls(internal_base_urls)
            .allow_did_web_hosts(allowed_hosts);
        Self { resolver }
    }
}

#[async_trait]
impl IssuerKeyResolver for NativeIssuerKeyResolver {
    async fn resolve(&self, did: &str) -> Result<IssuerKeyResolution, IssuerKeyResolutionError> {
        let resolution = self
            .resolver
            .resolve_with_metadata(did)
            .await
            .map_err(classify_resolution_error)?;
        let verification_keys = assertion_verification_keys(&resolution.document)?;
        Ok(IssuerKeyResolution {
            verification_keys,
            source: resolution.source,
            retrieved_at: resolution.retrieved_at,
            content_sha256: resolution.content_sha256,
        })
    }
}

pub(crate) fn pin_resolution(
    metadata: &mut Value,
    resolution: IssuerKeyResolution,
) -> Result<(), IssuerKeyResolutionError> {
    let object = metadata
        .as_object_mut()
        .ok_or(IssuerKeyResolutionError::Invalid)?;
    object.insert(
        "verification_keys".into(),
        Value::Array(resolution.verification_keys),
    );
    object.insert(
        "verification_key_resolution".into(),
        json!({
            "source": resolution.source,
            "retrieved_at": resolution.retrieved_at,
            "content_sha256": resolution.content_sha256,
        }),
    );
    Ok(())
}

fn assertion_verification_keys(
    document: &DidDocument,
) -> Result<Vec<Value>, IssuerKeyResolutionError> {
    if document.id.trim().is_empty() {
        return Err(IssuerKeyResolutionError::Invalid);
    }
    let mut authorized_ids = BTreeSet::new();
    let mut inline_methods = Vec::new();
    for relationship in &document.assertion_method {
        if let Some(reference) = relationship.as_str() {
            let id = canonical_method_id(&document.id, reference)
                .ok_or(IssuerKeyResolutionError::Invalid)?;
            authorized_ids.insert(id);
        } else {
            let method = serde_json::from_value::<VerificationMethod>(relationship.clone())
                .map_err(|_| IssuerKeyResolutionError::Invalid)?;
            inline_methods.push(method);
        }
    }

    let mut keys = Vec::new();
    for method in document
        .verification_method
        .iter()
        .filter(|method| {
            canonical_method_id(&document.id, &method.id)
                .is_some_and(|id| authorized_ids.contains(&id))
        })
        .chain(inline_methods.iter())
    {
        let Some(key) = public_assertion_jwk(&document.id, method)? else {
            continue;
        };
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    if keys.is_empty() || keys.len() > 32 {
        return Err(IssuerKeyResolutionError::Invalid);
    }
    Ok(keys)
}

fn public_assertion_jwk(
    did: &str,
    method: &VerificationMethod,
) -> Result<Option<Value>, IssuerKeyResolutionError> {
    if method.controller != did || canonical_method_id(did, &method.id).is_none() {
        return Err(IssuerKeyResolutionError::Invalid);
    }
    let Some(jwk) = &method.public_key_jwk else {
        return Ok(None);
    };
    let mut key = serde_json::to_value(jwk).map_err(|_| IssuerKeyResolutionError::Invalid)?;
    let object = key
        .as_object_mut()
        .ok_or(IssuerKeyResolutionError::Invalid)?;
    object.retain(|_, value| !value.is_null());
    valid_public_jwk(object)?;
    Ok(Some(key))
}

fn valid_public_jwk(key: &Map<String, Value>) -> Result<(), IssuerKeyResolutionError> {
    if key
        .get("kty")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
        || reject_private_custody_metadata(&Value::Object(key.clone())).is_err()
    {
        return Err(IssuerKeyResolutionError::Invalid);
    }
    Ok(())
}

fn canonical_method_id(did: &str, method_id: &str) -> Option<String> {
    if let Some(fragment) = method_id
        .strip_prefix('#')
        .filter(|value| !value.is_empty())
    {
        return Some(format!("{did}#{fragment}"));
    }
    method_id
        .strip_prefix(did)
        .filter(|suffix| suffix.starts_with('#') && suffix.len() > 1)
        .map(|_| method_id.to_owned())
}

fn classify_resolution_error(error: DidcommError) -> IssuerKeyResolutionError {
    match error {
        DidcommError::InvalidDid(_)
        | DidcommError::UnsupportedMethod { .. }
        | DidcommError::Json(_) => IssuerKeyResolutionError::Invalid,
        _ => IssuerKeyResolutionError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use axum::{routing::get, Json, Router};
    use marty_didcomm::{types::Jwk, DidDocument, VerificationMethod};
    use serde_json::json;

    use super::*;

    fn document() -> DidDocument {
        let did = "did:web:issuer.example:orgs:acme";
        DidDocument {
            id: did.into(),
            assertion_method: vec![json!(format!("{did}#issuer-key"))],
            authentication: vec![json!(format!("{did}#login-key"))],
            verification_method: vec![
                VerificationMethod {
                    id: format!("{did}#issuer-key"),
                    r#type: "JsonWebKey".into(),
                    controller: did.into(),
                    public_key_jwk: Some(Jwk {
                        kty: "EC".into(),
                        crv: Some("P-256".into()),
                        x: Some("x".into()),
                        y: Some("y".into()),
                        d: None,
                        kid: Some("issuer-key".into()),
                        additional_properties: Map::new(),
                    }),
                    public_key_multibase: None,
                    public_key_base58: None,
                    additional_properties: Map::new(),
                },
                VerificationMethod {
                    id: format!("{did}#login-key"),
                    r#type: "JsonWebKey".into(),
                    controller: did.into(),
                    public_key_jwk: Some(Jwk {
                        kty: "EC".into(),
                        crv: Some("P-256".into()),
                        x: Some("other-x".into()),
                        y: Some("other-y".into()),
                        d: None,
                        kid: Some("login-key".into()),
                        additional_properties: Map::new(),
                    }),
                    public_key_multibase: None,
                    public_key_base58: None,
                    additional_properties: Map::new(),
                },
            ],
            context: Value::Null,
            key_agreement: vec![],
            service: vec![],
            additional_properties: Map::new(),
        }
    }

    #[test]
    fn pins_only_assertion_authorized_public_jwks() {
        let keys = assertion_verification_keys(&document()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kid"], "issuer-key");
        assert!(keys[0].get("d").is_none());
    }

    #[test]
    fn rejects_private_or_unusable_assertion_methods() {
        let mut private = document();
        private.verification_method[0]
            .public_key_jwk
            .as_mut()
            .unwrap()
            .d = Some("private".into());
        assert_eq!(
            assertion_verification_keys(&private),
            Err(IssuerKeyResolutionError::Invalid)
        );

        let mut authentication_only = document();
        authentication_only.assertion_method.clear();
        assert_eq!(
            assertion_verification_keys(&authentication_only),
            Err(IssuerKeyResolutionError::Invalid)
        );
    }

    #[tokio::test]
    async fn native_resolver_uses_the_configured_internal_did_web_route() {
        let document = serde_json::to_value(document()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let application = Router::new().route(
            "/orgs/acme/did.json",
            get(move || {
                let document = document.clone();
                async move { Json(document) }
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, application).await.unwrap();
        });
        let resolver = NativeIssuerKeyResolver::new(
            [format!("http://{address}")],
            std::iter::empty::<String>(),
        );

        let resolved = resolver
            .resolve("did:web:issuer.example:orgs:acme")
            .await
            .unwrap();

        assert_eq!(resolved.source, "configured_internal_resolver");
        assert_eq!(resolved.verification_keys.len(), 1);
        assert_eq!(resolved.verification_keys[0]["kid"], "issuer-key");
        assert_eq!(resolved.content_sha256.len(), 64);
        server.abort();
    }
}
