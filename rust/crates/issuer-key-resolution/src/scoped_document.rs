//! Resolve the exact public DID document already published in an authorized
//! organization's signing registry. The DID's authority is an identifier here;
//! requests only contact the deployment-configured signing service.

use std::{collections::BTreeSet, time::Duration};

use async_trait::async_trait;
use chrono::Utc;
use marty_didcomm::{DidDocument, VerificationMethod};
use reqwest::{header::HeaderValue, redirect::Policy, Client, StatusCode, Url};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    assertion_verification_keys, canonical_method_id, custody, policy::validate_source_controls,
    IssuerKeyResolution, IssuerKeyResolutionError,
};

const MAX_DOCUMENT_BYTES: usize = 1_048_576;

#[async_trait]
pub trait ScopedIssuerKeyResolver: Send + Sync {
    /// `None` means the authenticated owner explicitly reported no scoped
    /// document. Invalid documents and unavailable owners are errors, not misses.
    async fn resolve(
        &self,
        organization_id: &str,
        issuer_did: &str,
    ) -> Result<Option<IssuerKeyResolution>, IssuerKeyResolutionError>;
}

pub struct HttpScopedIssuerKeyResolver {
    client: Client,
    base_url: Url,
    credential: HeaderValue,
}

impl std::fmt::Debug for HttpScopedIssuerKeyResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpScopedIssuerKeyResolver")
            .finish_non_exhaustive()
    }
}

impl HttpScopedIssuerKeyResolver {
    pub fn new(
        base_url: &str,
        internal_api_key: &str,
        timeout: Duration,
    ) -> Result<Self, IssuerKeyResolutionError> {
        let base_url = Url::parse(base_url).map_err(|_| IssuerKeyResolutionError::Invalid)?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.path() != "/"
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || internal_api_key.trim().is_empty()
            || timeout.is_zero()
        {
            return Err(IssuerKeyResolutionError::Invalid);
        }
        let mut credential = HeaderValue::from_str(internal_api_key)
            .map_err(|_| IssuerKeyResolutionError::Invalid)?;
        credential.set_sensitive(true);
        let client = Client::builder()
            .timeout(timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|_| IssuerKeyResolutionError::Unavailable)?;
        Ok(Self {
            client,
            base_url,
            credential,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentResponse {
    found: bool,
    document: Value,
}

#[async_trait]
impl ScopedIssuerKeyResolver for HttpScopedIssuerKeyResolver {
    async fn resolve(
        &self,
        organization_id: &str,
        issuer_did: &str,
    ) -> Result<Option<IssuerKeyResolution>, IssuerKeyResolutionError> {
        validate_source_controls(issuer_did, Some(organization_id), &[])?;
        if organization_id.len() > 255
            || issuer_did.len() > 2048
            || organization_id
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && byte != b'-' && byte != b'_')
        {
            return Err(IssuerKeyResolutionError::Invalid);
        }
        let mut endpoint = self.base_url.clone();
        endpoint
            .path_segments_mut()
            .map_err(|_| IssuerKeyResolutionError::Invalid)?
            .pop_if_empty()
            .extend(["internal", "documents", organization_id, "did", "load"]);
        let mut response = self
            .client
            .post(endpoint)
            .header("x-api-key", self.credential.clone())
            .json(&json!({"did_id": issuer_did}))
            .send()
            .await
            .map_err(|_| IssuerKeyResolutionError::Unavailable)?;
        if response.status().is_server_error() {
            return Err(IssuerKeyResolutionError::Unavailable);
        }
        if response.status() != StatusCode::OK {
            return Err(IssuerKeyResolutionError::Invalid);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| IssuerKeyResolutionError::Unavailable)?
        {
            if bytes.len().saturating_add(chunk.len()) > MAX_DOCUMENT_BYTES {
                return Err(IssuerKeyResolutionError::Invalid);
            }
            bytes.extend_from_slice(&chunk);
        }
        let response: DocumentResponse =
            serde_json::from_slice(&bytes).map_err(|_| IssuerKeyResolutionError::Invalid)?;
        if !response.found {
            // The owner synthesizes an empty document for a missing key. It is
            // not publication evidence and must never supply verification keys.
            return Ok(None);
        }
        if response.document.get("id").and_then(Value::as_str) != Some(issuer_did)
            || marty_key_material_policy::contains_private_key(&response.document)
            || custody::find_private_custody_metadata(&response.document).is_some()
        {
            return Err(IssuerKeyResolutionError::Invalid);
        }
        let document: DidDocument = serde_json::from_value(response.document.clone())
            .map_err(|_| IssuerKeyResolutionError::Invalid)?;
        let mut method_ids = BTreeSet::new();
        for method in &document.verification_method {
            if !method_ids.insert(validate_method(issuer_did, method)?) {
                return Err(IssuerKeyResolutionError::Invalid);
            }
        }
        for relationship in document.assertion_methods() {
            if !relationship.is_string() {
                let method: VerificationMethod = serde_json::from_value(relationship.clone())
                    .map_err(|_| IssuerKeyResolutionError::Invalid)?;
                validate_method(issuer_did, &method)?;
            }
        }
        let verification_keys = assertion_verification_keys(&document)?;
        let mut key_ids = BTreeSet::new();
        for key in &verification_keys {
            let present = |name| {
                key.get(name)
                    .and_then(Value::as_str)
                    .is_some_and(|v| !v.is_empty())
            };
            let valid_material = match key.get("kty").and_then(Value::as_str) {
                Some("EC") => present("crv") && present("x") && present("y"),
                Some("OKP") => present("crv") && present("x"),
                Some("RSA") => present("n") && present("e"),
                _ => false,
            };
            if !valid_material || !key_ids.insert(key.get("kid").and_then(Value::as_str)) {
                return Err(IssuerKeyResolutionError::Invalid);
            }
        }
        let encoded = serde_json::to_vec(&response.document)
            .map_err(|_| IssuerKeyResolutionError::Invalid)?;
        Ok(Some(IssuerKeyResolution {
            verification_keys,
            source: "organization_published_did_document".into(),
            retrieved_at: Utc::now().to_rfc3339(),
            content_sha256: format!("{:x}", Sha256::digest(encoded)),
        }))
    }
}

fn validate_method(
    issuer_did: &str,
    method: &VerificationMethod,
) -> Result<String, IssuerKeyResolutionError> {
    let id =
        canonical_method_id(issuer_did, &method.id).ok_or(IssuerKeyResolutionError::Invalid)?;
    let material_count = usize::from(method.public_key_jwk.is_some())
        + usize::from(method.public_key_multibase.is_some())
        + usize::from(method.public_key_base58.is_some());
    if method.controller != issuer_did || method.r#type.trim().is_empty() || material_count != 1 {
        return Err(IssuerKeyResolutionError::Invalid);
    }
    Ok(id)
}

#[cfg(test)]
mod tests;
