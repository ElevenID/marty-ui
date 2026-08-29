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
const PRIVATE_RSA_MEMBERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "oth"];

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
            || public_jwk.get("kty").and_then(Value::as_str) != Some("RSA")
            || !valid_rsa_algorithm(public_jwk.get("alg"))
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
        Ok(format!("{signing_input}.{signature}"))
    }

    async fn public_jwks(&self) -> Result<Value, CanvasLtiToolSigningError> {
        let (_, issuer_did) = self.configuration()?;
        let (active_id, mut active_jwk, resolution) = self.resolved_identity().await?;
        active_jwk.insert("kid".to_owned(), Value::String(active_id.clone()));
        active_jwk.insert("alg".to_owned(), Value::String(ALGORITHM.to_owned()));
        active_jwk.insert("use".to_owned(), Value::String("sig".to_owned()));
        let mut keys = BTreeMap::from([(active_id.clone(), Value::Object(active_jwk))]);
        let did_document = resolution.get("did_document").and_then(Value::as_object);
        let assertion_ids = did_document
            .and_then(|document| document.get("assertionMethod"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(assertion_method_id)
            .collect::<std::collections::BTreeSet<_>>();
        for method in did_document
            .and_then(|document| document.get("verificationMethod"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_object)
        {
            let method_id = method
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .trim();
            let Some(mut public_jwk) = method
                .get("publicKeyJwk")
                .and_then(Value::as_object)
                .cloned()
            else {
                continue;
            };
            if !assertion_ids.contains(method_id)
                || !method_id.starts_with(&format!("{issuer_did}#"))
                || contains_private_material(&public_jwk)
                || public_jwk.get("kty").and_then(Value::as_str) != Some("RSA")
                || !valid_rsa_algorithm(public_jwk.get("alg"))
            {
                continue;
            }
            public_jwk.insert("kid".to_owned(), Value::String(method_id.to_owned()));
            public_jwk.insert("alg".to_owned(), Value::String(ALGORITHM.to_owned()));
            public_jwk.insert("use".to_owned(), Value::String("sig".to_owned()));
            keys.entry(method_id.to_owned())
                .or_insert(Value::Object(public_jwk));
        }
        let mut ordered = Vec::with_capacity(keys.len());
        if let Some(active) = keys.remove(&active_id) {
            ordered.push(active);
        }
        ordered.extend(keys.into_values());
        Ok(json!({"keys": ordered}))
    }
}

fn assertion_method_id(value: &Value) -> Option<String> {
    value
        .as_str()
        .or_else(|| value.as_object()?.get("id")?.as_str())
        .map(str::to_owned)
}

fn contains_private_material(jwk: &Map<String, Value>) -> bool {
    PRIVATE_RSA_MEMBERS
        .iter()
        .any(|name| jwk.contains_key(*name))
}

fn valid_rsa_algorithm(value: Option<&Value>) -> bool {
    matches!(value, None | Some(Value::Null)) || value.and_then(Value::as_str) == Some(ALGORITHM)
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
