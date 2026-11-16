//! DID operations use the registered Signing Keys owner over its existing HTTPS listener.

use crate::{
    initiation_didcomm::NativeDidcommError,
    integration_secret_kms::{internal_kms_environment, internal_kms_https_client},
};
use marty_signing_grant::{
    didcomm::{
        DidcommOperationBinding, DidcommPackRequest, DidcommResolveRequest, MAX_JWE_BYTES,
        PACK_ROUTE, RESOLVE_ROUTE,
    },
    minter::GrantMinting,
    HEADER_NAME,
};
use reqwest::{Client, StatusCode, Url};
use serde::{de::DeserializeOwned, Deserialize};
use std::sync::Arc;

#[derive(Clone)]
pub struct RegisteredDidcommKms {
    client: Client,
    base_url: Url,
    api_key: String,
    grants: Arc<dyn GrantMinting>,
}

impl RegisteredDidcommKms {
    pub fn from_environment(
        api_key: &str,
        grants: Arc<dyn GrantMinting>,
    ) -> Result<Self, NativeDidcommError> {
        let (base_url, ca_pem) =
            internal_kms_environment().map_err(|_| NativeDidcommError::TlsUnavailable)?;
        Self::new(base_url, ca_pem.as_deref(), api_key, grants)
    }

    pub fn new(
        base_url: Url,
        ca_pem: Option<&[u8]>,
        api_key: &str,
        grants: Arc<dyn GrantMinting>,
    ) -> Result<Self, NativeDidcommError> {
        if api_key.trim().is_empty() {
            return Err(NativeDidcommError::SenderAuthenticationUnavailable);
        }
        let client = internal_kms_https_client(&base_url, ca_pem)
            .map_err(|_| NativeDidcommError::TlsUnavailable)?;
        Ok(Self {
            client,
            base_url,
            api_key: api_key.into(),
            grants,
        })
    }

    fn endpoint(&self, path: &'static str) -> Url {
        let mut url = self.base_url.clone();
        url.set_path(path);
        url
    }

    pub async fn resolve(
        &self,
        organization_id: &str,
        issuer_did: &str,
    ) -> Result<DidcommOperationBinding, NativeDidcommError> {
        let request = DidcommResolveRequest {
            organization_id: organization_id.into(),
            issuer_did: issuer_did.into(),
        };
        let response = self
            .client
            .post(self.endpoint(RESOLVE_ROUTE))
            .header("X-API-Key", &self.api_key)
            .json(&request)
            .send()
            .await
            .map_err(|_| NativeDidcommError::SenderAuthenticationUnavailable)?;
        let binding: DidcommOperationBinding = response_json(response, 8192).await?;
        binding
            .validate(organization_id, issuer_did)
            .map_err(|_| NativeDidcommError::SenderAuthenticationUnavailable)?;
        Ok(binding)
    }

    pub async fn pack(&self, request: &DidcommPackRequest) -> Result<String, NativeDidcommError> {
        // Repeat resolution for final delivery; a registry rebind cannot silently
        // replace the custody selected by the preflight stage.
        let current = self
            .resolve(&request.organization_id, &request.issuer_did)
            .await?;
        if current != request.binding {
            return Err(NativeDidcommError::SenderAuthenticationUnavailable);
        }
        let payload = request
            .bound_payload()
            .map_err(|_| NativeDidcommError::SenderAuthenticationUnavailable)?;
        let grant = self
            .grants
            .mint(&request.grant_binding(&payload))
            .await
            .and_then(|grant| grant.to_header_value())
            .map_err(|_| NativeDidcommError::SenderAuthenticationUnavailable)?;
        let response = self
            .client
            .post(self.endpoint(PACK_ROUTE))
            .header("X-API-Key", &self.api_key)
            .header(HEADER_NAME, grant)
            .json(request)
            .send()
            .await
            .map_err(|_| NativeDidcommError::SenderAuthenticationUnavailable)?;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Packed {
            jwe: String,
        }
        let response: Packed = response_json(response, MAX_JWE_BYTES + 1024).await?;
        if response.jwe.is_empty() || response.jwe.len() > MAX_JWE_BYTES {
            return Err(NativeDidcommError::PackUnavailable);
        }
        Ok(response.jwe)
    }
}

async fn response_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<T, NativeDidcommError> {
    let status = response.status();
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| NativeDidcommError::SenderAuthenticationUnavailable)?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(NativeDidcommError::SenderAuthenticationUnavailable);
        }
        body.extend_from_slice(&chunk);
    }
    if status == StatusCode::UNPROCESSABLE_ENTITY {
        let value: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| NativeDidcommError::SenderAuthenticationUnavailable)?;
        if value["code"] == "capability_unavailable" && value["capability"] == "didcomm_authcrypt" {
            return Err(NativeDidcommError::CapabilityUnavailable);
        }
    }
    if !status.is_success() {
        return Err(NativeDidcommError::SenderAuthenticationUnavailable);
    }
    serde_json::from_slice(&body).map_err(|_| NativeDidcommError::SenderAuthenticationUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn didcomm_uses_existing_https_listener_admission() {
        let grants = Arc::new(crate::signing_grant_config::ContractGrantMinter(
            marty_signing_grant::SigningOrigin::IssuanceCredential,
        ));
        for url in [
            "http://signing-keys:8000/internal",
            "https://user:secret@signing-keys/internal",
            "https://signing-keys/other",
            "https://signing-keys/internal?redirect=other",
        ] {
            assert!(RegisteredDidcommKms::new(
                Url::parse(url).unwrap(),
                None,
                "issuer-key",
                grants.clone()
            )
            .is_err());
        }
        assert!(RegisteredDidcommKms::new(
            Url::parse("https://signing-keys:8443/internal").unwrap(),
            None,
            "issuer-key",
            grants
        )
        .is_ok());
    }
}
