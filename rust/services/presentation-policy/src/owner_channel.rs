//! Authenticated acquisition from the two configured managed credential owners.
//!
//! A response digest binds data; it does not identify its sender. Only this
//! fixed-origin, operator-CA-only HTTPS client constructs owner responses.

use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use chrono::Utc;
use marty_oid4vp_contract::{
    managed_status::{ManagedCredentialStatusObservationV1, ManagedCredentialStatusRequestV1},
    trust_authority::{
        CredentialAuthoritySnapshotRequestV1, CredentialAuthoritySnapshotV1,
        CredentialTrustEvaluationRequestV1, CredentialTrustEvaluationResponseV1,
    },
    MAX_FROZEN_REQUEST_BYTES,
};
use serde::{de::DeserializeOwned, Serialize};
use url::Url;
use uuid::Uuid;

use crate::{PresentationPolicyConfigError, PresentationVerificationError};

const MAX_OBSERVATION_BYTES: usize = 64 * 1024;
const TRUST_URL: &str = "PREREQUISITE_TRUST_OWNER_URL";
const ISSUANCE_URL: &str = "PREREQUISITE_ISSUANCE_OWNER_URL";
const CA_FILE: &str = "PREREQUISITE_OWNER_CA_CERT";

/// Dedicated owner endpoints. General control-plane URLs never supply these
/// defaults. Origins may use private DNS and an explicit HTTPS port.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedOwnerChannelConfig {
    pub trust_profile_url: String,
    pub issuance_url: String,
    pub ca_certificate: PathBuf,
}

impl ManagedOwnerChannelConfig {
    pub(crate) fn from_values(
        values: &BTreeMap<String, String>,
    ) -> Result<Option<Self>, PresentationPolicyConfigError> {
        let names = [TRUST_URL, ISSUANCE_URL, CA_FILE];
        if names.iter().all(|name| !values.contains_key(*name)) {
            return Ok(None);
        }
        let required = |name| {
            values
                .get(name)
                .map(String::as_str)
                .filter(|value| !value.trim().is_empty() && !value.contains(['\r', '\n']))
                .ok_or(PresentationPolicyConfigError::Invalid { name })
        };
        let trust = owner_origin(required(TRUST_URL)?)
            .map_err(|_| PresentationPolicyConfigError::Invalid { name: TRUST_URL })?;
        let issuance = owner_origin(required(ISSUANCE_URL)?)
            .map_err(|_| PresentationPolicyConfigError::Invalid { name: ISSUANCE_URL })?;
        Ok(Some(Self {
            trust_profile_url: trust.to_string(),
            issuance_url: issuance.to_string(),
            ca_certificate: required(CA_FILE)?.into(),
        }))
    }
}

/// An owner-authenticated acquisition, not a policy allow or issuance grant.
/// Its DTO can be inspected or projected, but cannot recreate the provenance.
///
/// ```compile_fail
/// use marty_presentation_policy::AuthenticatedOwnerResponse;
/// use marty_oid4vp_contract::trust_authority::CredentialTrustEvaluationResponseV1;
/// let _: AuthenticatedOwnerResponse<CredentialTrustEvaluationResponseV1> =
///     serde_json::from_str("{}").unwrap();
/// ```
///
/// ```compile_fail
/// use marty_presentation_policy::AuthenticatedOwnerResponse;
/// use marty_oid4vp_contract::trust_authority::CredentialTrustEvaluationResponseV1;
/// fn forge(dto: CredentialTrustEvaluationResponseV1)
///     -> AuthenticatedOwnerResponse<CredentialTrustEvaluationResponseV1> {
///     dto.into()
/// }
/// ```
#[derive(Clone, PartialEq)]
pub struct AuthenticatedOwnerResponse<T> {
    response: T,
    owner: Owner,
    origin: String,
}

impl<T> std::fmt::Debug for AuthenticatedOwnerResponse<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // In particular, never print the private managed credential identifier.
        f.debug_struct("AuthenticatedOwnerResponse")
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

impl<T> AuthenticatedOwnerResponse<T> {
    pub fn response(&self) -> &T {
        &self.response
    }

    pub fn into_response(self) -> T {
        self.response
    }

    pub(crate) fn is_owner(&self, owner: Owner) -> bool {
        self.owner == owner
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Owner {
    TrustProfile,
    Issuance,
}

#[derive(Clone)]
pub(crate) struct ManagedOwnerChannels {
    trust: Url,
    issuance: Url,
    http: reqwest::Client,
}

impl ManagedOwnerChannels {
    pub(crate) fn new(
        config: &ManagedOwnerChannelConfig,
        timeout: Duration,
    ) -> Result<Self, PresentationVerificationError> {
        let trust = owner_origin(&config.trust_profile_url)?;
        let issuance = owner_origin(&config.issuance_url)?;
        if timeout.is_zero() || timeout > Duration::from_secs(300) {
            return Err(unavailable());
        }
        let pem = std::fs::read(&config.ca_certificate).map_err(|_| unavailable())?;
        let certificates =
            reqwest::Certificate::from_pem_bundle(&pem).map_err(|_| unavailable())?;
        if certificates.is_empty() {
            return Err(unavailable());
        }
        // The pinned generic MMF HTTP client merges roots and permits proxies.
        // This authority boundary deliberately has a narrower trust policy.
        let http = reqwest::Client::builder()
            .tls_backend_rustls()
            .tls_certs_only(certificates)
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(timeout)
            .timeout(timeout)
            .build()
            .map_err(|_| unavailable())?;
        Ok(Self {
            trust,
            issuance,
            http,
        })
    }

    async fn post<T: Serialize, R: DeserializeOwned>(
        &self,
        owner: Owner,
        path: &str,
        headers: BTreeMap<String, String>,
        request: &T,
        maximum_bytes: usize,
    ) -> Result<R, PresentationVerificationError> {
        let mut url = match owner {
            Owner::TrustProfile => self.trust.clone(),
            Owner::Issuance => self.issuance.clone(),
        };
        // Paths are built only by the three methods below, from UUIDs or fixed
        // literals. No credential field or remote response can select an origin.
        url.set_path(path);
        let body = serde_json::to_vec(request).map_err(|_| unavailable())?;
        if body.len() > MAX_FROZEN_REQUEST_BYTES {
            return Err(unavailable());
        }
        let mut builder = self
            .http
            .post(url)
            .header("accept", "application/json")
            .header("content-type", "application/json")
            .body(body);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let mut response = builder.send().await.map_err(|_| unavailable())?;
        if response.status() == reqwest::StatusCode::CONFLICT && owner == Owner::TrustProfile {
            return Err(PresentationVerificationError::CredentialAuthorityChanged);
        }
        if response.status() != reqwest::StatusCode::OK
            || !response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| {
                    value
                        .split(';')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .eq_ignore_ascii_case("application/json")
                })
            || response
                .content_length()
                .is_some_and(|size| size > maximum_bytes as u64)
        {
            return Err(unavailable());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| unavailable())? {
            if body.len().saturating_add(chunk.len()) > maximum_bytes {
                return Err(unavailable());
            }
            body.extend_from_slice(&chunk);
        }
        // Deserialize directly: duplicate fields and unknown fields in the
        // strict owner contracts must fail, rather than be normalized away.
        serde_json::from_slice(&body).map_err(|_| unavailable())
    }

    fn acquired<T>(&self, owner: Owner, response: T) -> AuthenticatedOwnerResponse<T> {
        let origin = match owner {
            Owner::TrustProfile => &self.trust,
            Owner::Issuance => &self.issuance,
        };
        AuthenticatedOwnerResponse {
            response,
            owner,
            origin: origin.to_string(),
        }
    }

    pub(crate) async fn freeze(
        &self,
        organization_id: Uuid,
        profile_id: Uuid,
        token: &str,
    ) -> Result<
        AuthenticatedOwnerResponse<CredentialAuthoritySnapshotV1>,
        PresentationVerificationError,
    > {
        let response: CredentialAuthoritySnapshotV1 = self
            .post(
                Owner::TrustProfile,
                &format!("/internal/v1/trust-profiles/{profile_id}/credential-authority-snapshot"),
                token_header(token)?,
                &CredentialAuthoritySnapshotRequestV1 {
                    organization_id: organization_id.to_string(),
                },
                MAX_FROZEN_REQUEST_BYTES,
            )
            .await?;
        response.validate().map_err(|_| unavailable())?;
        if response.organization_id != organization_id.to_string()
            || response.profile.id != profile_id.to_string()
        {
            return Err(unavailable());
        }
        Ok(self.acquired(Owner::TrustProfile, response))
    }

    pub(crate) async fn evaluate(
        &self,
        request: &CredentialTrustEvaluationRequestV1,
        token: &str,
    ) -> Result<
        AuthenticatedOwnerResponse<CredentialTrustEvaluationResponseV1>,
        PresentationVerificationError,
    > {
        request.validate().map_err(|_| unavailable())?;
        let profile_id =
            Uuid::parse_str(&request.expected_profile.id).map_err(|_| unavailable())?;
        let response: CredentialTrustEvaluationResponseV1 = self
            .post(
                Owner::TrustProfile,
                &format!("/internal/v1/trust-profiles/{profile_id}/credential-trust-evaluations"),
                token_header(token)?,
                request,
                MAX_OBSERVATION_BYTES,
            )
            .await?;
        response
            .validate_for_request(request, Utc::now().timestamp())
            .map_err(|_| unavailable())?;
        Ok(self.acquired(Owner::TrustProfile, response))
    }

    pub(crate) async fn observe(
        &self,
        request: &ManagedCredentialStatusRequestV1,
        api_key: &str,
    ) -> Result<
        AuthenticatedOwnerResponse<ManagedCredentialStatusObservationV1>,
        PresentationVerificationError,
    > {
        request.validate().map_err(|_| unavailable())?;
        if api_key.trim().is_empty() {
            return Err(unavailable());
        }
        let response: ManagedCredentialStatusObservationV1 = self
            .post(
                Owner::Issuance,
                "/internal/issuance/sd-jwt-status/observe",
                BTreeMap::from([
                    ("x-api-key".into(), api_key.into()),
                    ("x-organization-id".into(), request.organization_id.clone()),
                ]),
                request,
                MAX_OBSERVATION_BYTES,
            )
            .await?;
        response
            .validate_for_request(request, Utc::now().timestamp())
            .map_err(|_| unavailable())?;
        Ok(self.acquired(Owner::Issuance, response))
    }
}

fn token_header(token: &str) -> Result<BTreeMap<String, String>, PresentationVerificationError> {
    if token.trim().is_empty() {
        return Err(unavailable());
    }
    Ok(BTreeMap::from([("x-service-token".into(), token.into())]))
}

fn owner_origin(value: &str) -> Result<Url, PresentationVerificationError> {
    let url = Url::parse(value).map_err(|_| unavailable())?;
    if value.trim() != value
        || value.contains(['\r', '\n', '\\'])
        || url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port_or_known_default() == Some(0)
    {
        return Err(unavailable());
    }
    Ok(url)
}

fn unavailable() -> PresentationVerificationError {
    PresentationVerificationError::Unavailable
}

#[cfg(test)]
pub(crate) fn test_owner_response<T>(owner: Owner, response: T) -> AuthenticatedOwnerResponse<T> {
    AuthenticatedOwnerResponse {
        response,
        owner,
        origin: "https://unit-test-owner.example/".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_origins_are_explicit_https_authorities() {
        for value in [
            "https://trust-profile:8443",
            "https://issuer.example",
            "https://127.0.0.1:8444/",
        ] {
            assert!(owner_origin(value).is_ok(), "{value}");
        }
        for value in [
            "http://trust-profile:8443",
            "https://user@issuer.example",
            "https://issuer.example/path",
            "https://issuer.example?redirect=http://other",
            "https://issuer.example#fragment",
            "https://issuer.example:0",
            " https://issuer.example",
            "https://issuer.example\\other",
            "https://issuer.example\n",
        ] {
            assert!(owner_origin(value).is_err(), "{value}");
        }
    }

    #[test]
    fn every_partial_or_blank_owner_configuration_is_rejected() {
        assert!(ManagedOwnerChannelConfig::from_values(&BTreeMap::new())
            .unwrap()
            .is_none());
        let all = BTreeMap::from([
            (TRUST_URL.into(), "https://trust-profile:8443".into()),
            (ISSUANCE_URL.into(), "https://issuance-native:8444".into()),
            (CA_FILE.into(), "owner-ca.pem".into()),
        ]);
        assert!(ManagedOwnerChannelConfig::from_values(&all)
            .unwrap()
            .is_some());
        for name in [TRUST_URL, ISSUANCE_URL, CA_FILE] {
            let mut partial = all.clone();
            partial.remove(name);
            assert!(ManagedOwnerChannelConfig::from_values(&partial).is_err());
            partial.insert(name.into(), String::new());
            assert!(ManagedOwnerChannelConfig::from_values(&partial).is_err());
        }
    }

    #[test]
    fn provenance_debug_does_not_expose_response_data() {
        let response = test_owner_response(Owner::Issuance, "private-credential-id");
        assert!(!format!("{response:?}").contains("private-credential-id"));
        assert!(response.is_owner(Owner::Issuance));
        assert!(!response.is_owner(Owner::TrustProfile));
    }
}
