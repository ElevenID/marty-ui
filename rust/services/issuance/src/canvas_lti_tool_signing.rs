use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::{
    canvas_award_candidate::python_canonical_json,
    credential_builder::{HttpDidSigner, SignRequest},
    credential_issuer::HttpIssuerContextResolver,
};

const CREDENTIAL_FORMAT: &str = "lti_tool_jwt";
const KEY_PURPOSE: &str = "lti_tool_signing";
const ALGORITHM: &str = "RS256";
const PRIVATE_RSA_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CanvasLtiToolSigningError {
    #[error("Production Canvas LTI signing requires SIGNING_KEYS_INTERNAL_URL/API key and CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID/ISSUER_DID")]
    ConfigurationIncomplete,
    #[error("Canvas LTI issuer identity must be a DID")]
    IssuerIdentityNotDid,
    #[error("Canvas LTI issuer DID resolution failed: {0}")]
    ResolutionFailed(String),
    #[error("Canvas LTI issuer DID could not be resolved")]
    IssuerDidUnresolved,
    #[error("Canvas LTI DID resolver output must not contain private key material")]
    PrivateKeyMaterial,
    #[error("Canvas LTI issuer DID did not resolve to a public RS256 verification method")]
    InvalidVerificationMethod,
    #[error("Canvas LTI DID-mediated signing failed: {0}")]
    SigningFailed(String),
    #[error("Canvas LTI DID-mediated signer returned no signature")]
    MissingSignature,
    #[error("Canvas LTI DID-mediated signer returned invalid signature encoding")]
    InvalidSignatureEncoding,
}

#[async_trait]
pub trait CanvasLtiToolJwtSigner: Send + Sync {
    async fn sign_jwt(&self, payload: &Value) -> Result<String, CanvasLtiToolSigningError>;
    async fn public_jwks(&self) -> Result<Value, CanvasLtiToolSigningError>;
}

#[async_trait]
pub trait CanvasLtiToolIdentityResolver: Send + Sync {
    async fn resolve(
        &self,
        organization_id: &str,
        issuer_did: &str,
    ) -> Result<Value, CanvasLtiToolSigningError>;
}

#[async_trait]
pub trait CanvasLtiToolSignatureProvider: Send + Sync {
    async fn sign(
        &self,
        organization_id: &str,
        issuer_did: &str,
        verification_method_id: &str,
        payload: &[u8],
    ) -> Result<String, CanvasLtiToolSigningError>;
}

#[derive(Clone)]
pub struct IssuerDidCanvasLtiToolJwtSigner {
    organization_id: String,
    issuer_did: String,
    signing_api_key_configured: bool,
    resolver: Arc<dyn CanvasLtiToolIdentityResolver>,
    signatures: Arc<dyn CanvasLtiToolSignatureProvider>,
}

impl std::fmt::Debug for IssuerDidCanvasLtiToolJwtSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuerDidCanvasLtiToolJwtSigner")
            .field("organization_id", &self.organization_id)
            .field("issuer_did", &self.issuer_did)
            .field(
                "signing_api_key_configured",
                &self.signing_api_key_configured,
            )
            .finish_non_exhaustive()
    }
}

impl IssuerDidCanvasLtiToolJwtSigner {
    #[must_use]
    pub fn new(
        organization_id: impl Into<String>,
        issuer_did: impl Into<String>,
        signing_api_key_configured: bool,
        resolver: Arc<dyn CanvasLtiToolIdentityResolver>,
        signatures: Arc<dyn CanvasLtiToolSignatureProvider>,
    ) -> Self {
        Self {
            organization_id: organization_id.into().trim().to_owned(),
            issuer_did: issuer_did.into().trim().to_owned(),
            signing_api_key_configured,
            resolver,
            signatures,
        }
    }

    fn configuration(&self) -> Result<(&str, &str), CanvasLtiToolSigningError> {
        if self.organization_id.is_empty()
            || self.issuer_did.is_empty()
            || !self.signing_api_key_configured
        {
            return Err(CanvasLtiToolSigningError::ConfigurationIncomplete);
        }
        if !self.issuer_did.starts_with("did:") {
            return Err(CanvasLtiToolSigningError::IssuerIdentityNotDid);
        }
        Ok((&self.organization_id, &self.issuer_did))
    }

    async fn resolved_identity(
        &self,
    ) -> Result<(String, Map<String, Value>, Value), CanvasLtiToolSigningError> {
        let (organization_id, issuer_did) = self.configuration()?;
        let resolution = self.resolver.resolve(organization_id, issuer_did).await?;
        if resolution.get("issuer_did").and_then(Value::as_str) != Some(issuer_did) {
            return Err(CanvasLtiToolSigningError::IssuerDidUnresolved);
        }
        let verification_method_id = resolution
            .get("verification_method_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned();
        let public_jwk = resolution
            .get("public_jwk")
            .and_then(Value::as_object)
            .cloned()
            .ok_or(CanvasLtiToolSigningError::InvalidVerificationMethod)?;
        if contains_private_material(&public_jwk) {
            return Err(CanvasLtiToolSigningError::PrivateKeyMaterial);
        }
        if !verification_method_id.starts_with(&format!("{issuer_did}#"))
            || public_jwk.get("kid").and_then(Value::as_str)
                != Some(verification_method_id.as_str())
            || !valid_public_rsa_jwk(&public_jwk)
        {
            return Err(CanvasLtiToolSigningError::InvalidVerificationMethod);
        }
        Ok((verification_method_id, public_jwk, resolution))
    }
}

#[async_trait]
impl CanvasLtiToolJwtSigner for IssuerDidCanvasLtiToolJwtSigner {
    async fn sign_jwt(&self, payload: &Value) -> Result<String, CanvasLtiToolSigningError> {
        let (organization_id, issuer_did) = self.configuration()?;
        let (verification_method_id, _, _) = self.resolved_identity().await?;
        let header = json!({
            "alg": ALGORITHM,
            "typ": "JWT",
            "kid": verification_method_id,
        });
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(python_canonical_json(&header)),
            URL_SAFE_NO_PAD.encode(python_canonical_json(payload)),
        );
        let signature = self
            .signatures
            .sign(
                organization_id,
                issuer_did,
                &verification_method_id,
                signing_input.as_bytes(),
            )
            .await?;
        let signature = signature.trim().trim_end_matches('=');
        if signature.is_empty() {
            return Err(CanvasLtiToolSigningError::MissingSignature);
        }
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| CanvasLtiToolSigningError::InvalidSignatureEncoding)?;
        if signature.is_empty() {
            return Err(CanvasLtiToolSigningError::MissingSignature);
        }
        let signature = URL_SAFE_NO_PAD.encode(signature);
        Ok(format!("{signing_input}.{signature}"))
    }

    async fn public_jwks(&self) -> Result<Value, CanvasLtiToolSigningError> {
        let (_, issuer_did) = self.configuration()?;
        let (active_id, active_jwk, resolution) = self.resolved_identity().await?;
        let active_jwk = normalized_public_rsa_jwk(&active_jwk, &active_id)
            .ok_or(CanvasLtiToolSigningError::InvalidVerificationMethod)?;
        let mut keys = BTreeMap::from([(active_id.clone(), Value::Object(active_jwk))]);
        let did_document = resolution.get("did_document").and_then(Value::as_object);
        let assertion_methods = did_document
            .and_then(|document| document.get("assertionMethod"))
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let assertion_ids = assertion_methods
            .iter()
            .filter_map(|method| assertion_method_id(issuer_did, method))
            .collect::<std::collections::BTreeSet<_>>();
        let verification_methods = did_document
            .and_then(|document| document.get("verificationMethod"))
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for method in verification_methods
            .iter()
            .chain(assertion_methods.iter())
            .filter_map(Value::as_object)
        {
            let Some(method_id) = method
                .get("id")
                .and_then(Value::as_str)
                .and_then(|method_id| normalize_method_id(issuer_did, method_id))
            else {
                continue;
            };
            let Some(public_jwk) = method.get("publicKeyJwk").and_then(Value::as_object) else {
                continue;
            };
            if !assertion_ids.contains(&method_id)
                || !method_id.starts_with(&format!("{issuer_did}#"))
            {
                continue;
            }
            let Some(public_jwk) = normalized_public_rsa_jwk(public_jwk, &method_id) else {
                continue;
            };
            keys.entry(method_id).or_insert(Value::Object(public_jwk));
        }
        let mut ordered = Vec::with_capacity(keys.len());
        if let Some(active) = keys.remove(&active_id) {
            ordered.push(active);
        }
        ordered.extend(keys.into_values());
        Ok(json!({"keys": ordered}))
    }
}

fn assertion_method_id(issuer_did: &str, value: &Value) -> Option<String> {
    value
        .as_str()
        .or_else(|| value.as_object()?.get("id")?.as_str())
        .and_then(|method_id| normalize_method_id(issuer_did, method_id))
}

fn normalize_method_id(issuer_did: &str, method_id: &str) -> Option<String> {
    let method_id = method_id.trim();
    if method_id.is_empty() {
        None
    } else if method_id.starts_with('#') {
        Some(format!("{issuer_did}{method_id}"))
    } else if method_id.starts_with("did:") {
        Some(method_id.to_owned())
    } else {
        Some(format!("{issuer_did}#{method_id}"))
    }
}

fn contains_private_material(jwk: &Map<String, Value>) -> bool {
    PRIVATE_RSA_MEMBERS
        .iter()
        .any(|name| jwk.contains_key(*name))
}

fn valid_public_rsa_jwk(jwk: &Map<String, Value>) -> bool {
    !contains_private_material(jwk)
        && jwk.get("kty").and_then(Value::as_str) == Some("RSA")
        && valid_rsa_algorithm(jwk.get("alg"))
        && valid_rsa_use(jwk.get("use"))
        && non_empty_string(jwk, "n")
        && non_empty_string(jwk, "e")
}

fn non_empty_string(jwk: &Map<String, Value>, member: &str) -> bool {
    jwk.get(member)
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
}

fn normalized_public_rsa_jwk(
    jwk: &Map<String, Value>,
    method_id: &str,
) -> Option<Map<String, Value>> {
    if !valid_public_rsa_jwk(jwk) {
        return None;
    }
    let mut normalized = Map::new();
    normalized.insert("alg".to_owned(), Value::String(ALGORITHM.to_owned()));
    normalized.insert("e".to_owned(), jwk.get("e")?.clone());
    normalized.insert("kid".to_owned(), Value::String(method_id.to_owned()));
    normalized.insert("kty".to_owned(), Value::String("RSA".to_owned()));
    normalized.insert("n".to_owned(), jwk.get("n")?.clone());
    normalized.insert("use".to_owned(), Value::String("sig".to_owned()));
    if let Some(retired_at) = jwk
        .get("retired_at")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        normalized.insert(
            "retired_at".to_owned(),
            Value::String(retired_at.to_owned()),
        );
    }
    Some(normalized)
}

fn valid_rsa_algorithm(value: Option<&Value>) -> bool {
    matches!(value, None | Some(Value::Null)) || value.and_then(Value::as_str) == Some(ALGORITHM)
}

fn valid_rsa_use(value: Option<&Value>) -> bool {
    matches!(value, None | Some(Value::Null)) || value.and_then(Value::as_str) == Some("sig")
}

#[derive(Clone)]
pub struct HttpCanvasLtiToolIdentityResolver {
    resolver: HttpIssuerContextResolver,
}

impl HttpCanvasLtiToolIdentityResolver {
    pub fn new(
        base_url: url::Url,
        api_key: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, CanvasLtiToolSigningError> {
        Ok(Self {
            resolver: HttpIssuerContextResolver::new(base_url, api_key, timeout)
                .map_err(|cause| CanvasLtiToolSigningError::ResolutionFailed(cause.to_string()))?,
        })
    }
}

#[async_trait]
impl CanvasLtiToolIdentityResolver for HttpCanvasLtiToolIdentityResolver {
    async fn resolve(
        &self,
        organization_id: &str,
        issuer_did: &str,
    ) -> Result<Value, CanvasLtiToolSigningError> {
        self.resolver
            .resolve_raw(
                organization_id,
                issuer_did,
                None,
                CREDENTIAL_FORMAT,
                KEY_PURPOSE,
                ALGORITHM,
            )
            .await
            .map_err(|cause| CanvasLtiToolSigningError::ResolutionFailed(cause.to_string()))
    }
}

#[derive(Clone)]
pub struct HttpCanvasLtiToolSignatureProvider {
    signer: HttpDidSigner,
}

impl HttpCanvasLtiToolSignatureProvider {
    pub fn new(
        base_url: url::Url,
        api_key: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, CanvasLtiToolSigningError> {
        Ok(Self {
            signer: HttpDidSigner::new(base_url, api_key, timeout)
                .map_err(|cause| CanvasLtiToolSigningError::SigningFailed(cause.to_string()))?,
        })
    }
}

#[async_trait]
impl CanvasLtiToolSignatureProvider for HttpCanvasLtiToolSignatureProvider {
    async fn sign(
        &self,
        organization_id: &str,
        issuer_did: &str,
        verification_method_id: &str,
        payload: &[u8],
    ) -> Result<String, CanvasLtiToolSigningError> {
        self.signer
            .sign_did(SignRequest {
                organization_id: organization_id.to_owned(),
                issuer_did: issuer_did.to_owned(),
                credential_format: CREDENTIAL_FORMAT.to_owned(),
                key_purpose: KEY_PURPOSE.to_owned(),
                payload: payload.to_vec(),
                algorithm: ALGORITHM.to_owned(),
                verification_method_id: verification_method_id.to_owned(),
            })
            .await
            .map(|response| response.signature_b64)
            .map_err(|cause| CanvasLtiToolSigningError::SigningFailed(cause.to_string()))
    }
}
