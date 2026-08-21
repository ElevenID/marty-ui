use std::{collections::BTreeSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use tonic::{
    metadata::AsciiMetadataValue,
    transport::{Channel, Endpoint},
    Code, Request,
};

use crate::{
    application::{ControlPlaneError, CredentialTemplateControlPlane, IssuerIdentity},
    organization_proto::{
        organization_service_client::OrganizationServiceClient, GetMemberRequest,
        GetOrganizationRequest, MemberResponse,
    },
    revocation_profile_proto::{
        revocation_profile_service_client::RevocationProfileServiceClient,
        GetRevocationProfileRequest,
    },
};

const SERVICE_TOKEN_HEADER: &str = "x-service-token";

#[derive(Clone)]
pub struct NativeCredentialTemplateControlPlane {
    organizations: OrganizationServiceClient<Channel>,
    revocation_profiles: RevocationProfileServiceClient<Channel>,
    http: Client,
    service_token: Option<AsciiMetadataValue>,
    signing_keys_internal_url: Arc<str>,
    signing_keys_internal_api_key: Option<Arc<str>>,
    trust_profile_service_url: Arc<str>,
    timeout: Duration,
}

impl std::fmt::Debug for NativeCredentialTemplateControlPlane {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeCredentialTemplateControlPlane")
            .field("service_token_configured", &self.service_token.is_some())
            .field("signing_keys_internal_url", &self.signing_keys_internal_url)
            .field("trust_profile_service_url", &self.trust_profile_service_url)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl NativeCredentialTemplateControlPlane {
    pub fn connect_lazy(
        organization_target: &str,
        revocation_target: &str,
        service_token: Option<&str>,
        signing_keys_internal_url: impl Into<Arc<str>>,
        signing_keys_internal_api_key: Option<&str>,
        trust_profile_service_url: impl Into<Arc<str>>,
        timeout: Duration,
    ) -> Result<Self, ControlPlaneError> {
        if timeout.is_zero() {
            return Err(unavailable("dependency timeout must be positive"));
        }
        let organizations = OrganizationServiceClient::new(channel(organization_target, timeout)?);
        let revocation_profiles =
            RevocationProfileServiceClient::new(channel(revocation_target, timeout)?);
        let service_token = service_token
            .map(str::parse)
            .transpose()
            .map_err(|_| unavailable("service token is not valid ASCII metadata"))?;
        let http = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| unavailable(error.to_string()))?;
        Ok(Self {
            organizations,
            revocation_profiles,
            http,
            service_token,
            signing_keys_internal_url: signing_keys_internal_url.into(),
            signing_keys_internal_api_key: signing_keys_internal_api_key.map(Arc::<str>::from),
            trust_profile_service_url: trust_profile_service_url.into(),
            timeout,
        })
    }

    fn grpc_request<T>(&self, body: T) -> Request<T> {
        let mut request = Request::new(body);
        request.set_timeout(self.timeout);
        if let Some(token) = &self.service_token {
            request
                .metadata_mut()
                .insert(SERVICE_TOKEN_HEADER, token.clone());
        }
        request
    }

    async fn membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<MemberResponse, ControlPlaneError> {
        if user_id.trim().is_empty() || organization_id.trim().is_empty() {
            return Err(ControlPlaneError::MembershipRequired);
        }
        let request = self.grpc_request(GetMemberRequest {
            organization_id: organization_id.to_owned(),
            user_id: user_id.to_owned(),
        });
        let mut client = self.organizations.clone();
        let response = match client.get_member(request).await {
            Ok(response) => response.into_inner(),
            Err(status)
                if matches!(
                    status.code(),
                    Code::NotFound | Code::InvalidArgument | Code::Unknown
                ) =>
            {
                return Err(ControlPlaneError::MembershipRequired)
            }
            Err(status) => return Err(grpc_unavailable("organization membership", status)),
        };
        authorize_active_membership(&response, user_id, organization_id)?;
        Ok(response)
    }

    async fn resolve_issuer(
        &self,
        organization_id: &str,
        requested_issuer_did: Option<&str>,
        credential_format: &str,
    ) -> Result<IssuerIdentity, ControlPlaneError> {
        let issuer_did = requested_issuer_did.unwrap_or_default().trim();
        if !issuer_did.starts_with("did:") {
            return Err(ControlPlaneError::InvalidIssuer(
                "issuer_did must be a DID string".into(),
            ));
        }
        let key_purpose = key_purpose(credential_format);
        let mut endpoint = url::Url::parse(&format!(
            "{}/resolve-issuer-did",
            self.signing_keys_internal_url
        ))
        .map_err(|error| unavailable(format!("invalid signing-keys endpoint: {error}")))?;
        endpoint.query_pairs_mut().extend_pairs([
            ("organization_id", organization_id),
            ("issuer_did", issuer_did),
            ("key_purpose", key_purpose),
            ("credential_format", credential_format),
        ]);
        let mut request = self.http.get(endpoint);
        if let Some(api_key) = &self.signing_keys_internal_api_key {
            request = request.header("x-api-key", api_key.as_ref());
        }
        let response = request
            .send()
            .await
            .map_err(|error| unavailable(format!("signing-keys issuer resolution: {error}")))?;
        match response.status() {
            StatusCode::NOT_FOUND | StatusCode::UNPROCESSABLE_ENTITY | StatusCode::CONFLICT => {
                return Err(ControlPlaneError::InvalidIssuer(
                    "issuer DID does not resolve to exactly one active organization-owned signing identity"
                        .into(),
                ))
            }
            status if !status.is_success() => {
                return Err(unavailable(format!(
                    "signing-keys issuer resolution returned {status}"
                )))
            }
            _ => {}
        }
        let payload: Value = response
            .json()
            .await
            .map_err(|error| unavailable(format!("invalid signing-keys response: {error}")))?;
        issuer_identity(&payload, organization_id, issuer_did, key_purpose)
    }

    async fn trust_profile(&self, profile_id: &str) -> Result<Value, ControlPlaneError> {
        let mut request = self.http.get(format!(
            "{}/internal/v1/trust-profiles/{profile_id}",
            self.trust_profile_service_url
        ));
        if let Some(token) = &self.service_token {
            request = request.header(SERVICE_TOKEN_HEADER, token.as_encoded_bytes());
        }
        let response = request
            .send()
            .await
            .map_err(|error| unavailable(format!("trust-profile validation: {error}")))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(ControlPlaneError::TrustProfileRejected(
                "trust_profile_id does not reference a Trust Profile".into(),
            ));
        }
        if !response.status().is_success() {
            return Err(unavailable(format!(
                "trust-profile validation returned {}",
                response.status()
            )));
        }
        response
            .json()
            .await
            .map_err(|error| unavailable(format!("invalid trust-profile response: {error}")))
    }
}

#[async_trait]
impl CredentialTemplateControlPlane for NativeCredentialTemplateControlPlane {
    async fn require_membership(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<(), ControlPlaneError> {
        self.membership(user_id, organization_id).await.map(drop)
    }

    async fn require_wallet_admin(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<(), ControlPlaneError> {
        let member = self.membership(user_id, organization_id).await?;
        if member.is_owner
            || member.has_org_console_access
            || member.permissions.iter().any(|item| item == "wallet:write")
        {
            Ok(())
        } else {
            Err(ControlPlaneError::WalletAdminRequired)
        }
    }

    async fn require_destination_admin(
        &self,
        user_id: &str,
        organization_id: &str,
    ) -> Result<(), ControlPlaneError> {
        let member = self.membership(user_id, organization_id).await?;
        if member.is_owner
            || member.has_org_console_access
            || member.permissions.iter().any(|item| {
                matches!(
                    item.as_str(),
                    "delivery_destinations:write" | "integrations:write"
                )
            })
        {
            Ok(())
        } else {
            Err(ControlPlaneError::DestinationAdminRequired)
        }
    }

    async fn organization_display_name(
        &self,
        organization_id: &str,
    ) -> Result<Option<String>, ControlPlaneError> {
        let request = self.grpc_request(GetOrganizationRequest {
            organization_id: organization_id.to_owned(),
        });
        let mut client = self.organizations.clone();
        let response = match client.get_organization(request).await {
            Ok(response) => response.into_inner(),
            Err(status) if status.code() == Code::NotFound => return Ok(None),
            Err(status) => return Err(grpc_unavailable("organization lookup", status)),
        };
        if response.id != organization_id {
            return Err(unavailable("organization response identity mismatch"));
        }
        Ok(non_empty(&response.display_name)
            .or_else(|| non_empty(&response.name))
            .map(str::to_owned))
    }

    async fn resolve_active_issuer(
        &self,
        organization_id: &str,
        requested_issuer_did: Option<&str>,
        credential_format: &str,
    ) -> Result<IssuerIdentity, ControlPlaneError> {
        self.resolve_issuer(organization_id, requested_issuer_did, credential_format)
            .await
    }

    async fn require_active_revocation_profile(
        &self,
        organization_id: &str,
        revocation_profile_id: Option<&str>,
    ) -> Result<(), ControlPlaneError> {
        let Some(profile_id) = revocation_profile_id.and_then(non_empty) else {
            return Err(ControlPlaneError::InvalidRevocationProfile(
                "revocation_profile_id is required before activation".into(),
            ));
        };
        let request = self.grpc_request(GetRevocationProfileRequest {
            profile_id: profile_id.to_owned(),
        });
        let mut client = self.revocation_profiles.clone();
        let profile = match client.get_revocation_profile(request).await {
            Ok(response) => response.into_inner(),
            Err(status) if status.code() == Code::NotFound => {
                return Err(ControlPlaneError::InvalidRevocationProfile(
                    "revocation_profile_id does not reference a Revocation Profile".into(),
                ))
            }
            Err(status) => return Err(grpc_unavailable("revocation-profile validation", status)),
        };
        if profile.id != profile_id
            || profile.organization_id != organization_id
            || !profile.status.eq_ignore_ascii_case("active")
        {
            return Err(ControlPlaneError::InvalidRevocationProfile(
                "revocation profile must be active and owned by the template organization".into(),
            ));
        }
        Ok(())
    }

    async fn require_trust_profile_accepts_issuer(
        &self,
        trust_profile_id: Option<&str>,
        issuer_did: &str,
    ) -> Result<(), ControlPlaneError> {
        let Some(profile_id) = trust_profile_id.and_then(non_empty) else {
            return Ok(());
        };
        if issuer_did.trim().is_empty() {
            return Err(ControlPlaneError::TrustProfileRejected(
                "active issuer profile did not provide an issuer DID".into(),
            ));
        }
        let profile = self.trust_profile(profile_id).await?;
        if profile
            .get("status")
            .and_then(Value::as_str)
            .is_none_or(|status| !status.eq_ignore_ascii_case("active"))
        {
            return Err(ControlPlaneError::TrustProfileRejected(
                "credential templates require an active Trust Profile".into(),
            ));
        }
        let trusted = trust_profile_issuer_identifiers(&profile);
        if !trusted.is_empty() && issuer_candidates(issuer_did).is_disjoint(&trusted) {
            return Err(ControlPlaneError::TrustProfileRejected(
                "selected Trust Profile does not trust the selected issuer DID".into(),
            ));
        }
        Ok(())
    }
}

fn channel(target: &str, timeout: Duration) -> Result<Channel, ControlPlaneError> {
    Endpoint::from_shared(target.to_owned())
        .map_err(|error| unavailable(format!("invalid gRPC target: {error}")))
        .map(|endpoint| {
            endpoint
                .connect_timeout(timeout)
                .timeout(timeout)
                .connect_lazy()
        })
}

fn authorize_active_membership(
    member: &MemberResponse,
    user_id: &str,
    organization_id: &str,
) -> Result<(), ControlPlaneError> {
    if member.user_id == user_id
        && member.organization_id == organization_id
        && member.status.eq_ignore_ascii_case("active")
    {
        Ok(())
    } else {
        Err(ControlPlaneError::MembershipRequired)
    }
}

fn issuer_identity(
    payload: &Value,
    organization_id: &str,
    issuer_did: &str,
    key_purpose: &str,
) -> Result<IssuerIdentity, ControlPlaneError> {
    let algorithm = payload
        .get("algorithm")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let verification_method = payload
        .get("verification_method_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let public_jwk = payload.get("public_jwk").and_then(Value::as_object);
    let valid_public_jwk = public_jwk.is_some_and(|jwk| {
        !jwk.is_empty()
            && ["d", "p", "q", "k"]
                .iter()
                .all(|secret| !jwk.contains_key(*secret))
    });
    if payload.get("ok").and_then(Value::as_bool) != Some(true)
        || payload.get("organization_id").and_then(Value::as_str) != Some(organization_id)
        || payload.get("issuer_did").and_then(Value::as_str) != Some(issuer_did)
        || payload.get("key_purpose").and_then(Value::as_str) != Some(key_purpose)
        || algorithm.is_empty()
        || !verification_method.starts_with(&format!("{issuer_did}#"))
        || !valid_public_jwk
    {
        return Err(ControlPlaneError::InvalidIssuer(
            "issuer DID did not resolve to a complete organization-owned public signing identity"
                .into(),
        ));
    }
    Ok(IssuerIdentity {
        issuer_did: issuer_did.to_owned(),
        issuer_algorithm: algorithm.to_owned(),
    })
}

fn key_purpose(credential_format: &str) -> &'static str {
    match credential_format
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .as_str()
    {
        "mso_mdoc" | "mdoc" | "zk_mdoc" => "mdoc_dsc",
        "vds_nc" | "vdsnc" => "vdsnc_signing",
        _ => "vc_jwt_issuer",
    }
}

fn trust_profile_issuer_identifiers(profile: &Value) -> BTreeSet<String> {
    let mut identifiers = BTreeSet::new();
    collect_identifiers(profile.get("allowed_issuers"), false, &mut identifiers);
    collect_identifiers(profile.get("trust_sources"), true, &mut identifiers);
    identifiers
}

fn collect_identifiers(
    values: Option<&Value>,
    honor_enabled: bool,
    identifiers: &mut BTreeSet<String>,
) {
    let Some(values) = values.and_then(Value::as_array) else {
        return;
    };
    for value in values {
        if let Some(identifier) = value.as_str() {
            identifiers.extend(issuer_candidates(identifier));
            continue;
        }
        let Some(value) = value.as_object() else {
            continue;
        };
        if honor_enabled && value.get("enabled").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        if let Some(identifier) = value
            .get("issuer_did")
            .or_else(|| value.get("issuer_id"))
            .and_then(Value::as_str)
        {
            identifiers.extend(issuer_candidates(identifier));
        }
    }
}

fn issuer_candidates(identifier: &str) -> BTreeSet<String> {
    let identifier = identifier.trim();
    if identifier.is_empty() {
        return BTreeSet::new();
    }
    let mut candidates = BTreeSet::from([identifier.to_owned()]);
    if let Some((did, _)) = identifier.split_once('#') {
        candidates.insert(did.to_owned());
    }
    candidates
}

fn non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn grpc_unavailable(operation: &str, status: tonic::Status) -> ControlPlaneError {
    unavailable(format!(
        "{operation} failed with gRPC status {}",
        status.code()
    ))
}

fn unavailable(message: impl Into<String>) -> ControlPlaneError {
    ControlPlaneError::Unavailable(message.into())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn fixture() -> Value {
        serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../contracts/credential-template-control-plane-behavior.json"
        )))
        .expect("valid control-plane behavior fixture")
    }

    fn member() -> MemberResponse {
        MemberResponse {
            organization_id: "org-1".into(),
            user_id: "user-1".into(),
            status: "active".into(),
            ..Default::default()
        }
    }

    #[test]
    fn membership_identity_and_active_status_are_all_required() {
        assert!(authorize_active_membership(&member(), "user-1", "org-1").is_ok());
        assert!(authorize_active_membership(&member(), "user-2", "org-1").is_err());
        let mut suspended = member();
        suspended.status = "suspended".into();
        assert!(authorize_active_membership(&suspended, "user-1", "org-1").is_err());
    }

    #[test]
    fn signing_identity_rejects_mismatches_and_private_jwk_material() {
        let valid = fixture()["signing_identity"].clone();
        assert_eq!(
            issuer_identity(&valid, "org-1", "did:web:issuer.example", "vc_jwt_issuer")
                .unwrap()
                .issuer_algorithm,
            "ES256"
        );
        let mut private = valid;
        private["public_jwk"]["d"] = json!("secret");
        assert!(
            issuer_identity(&private, "org-1", "did:web:issuer.example", "vc_jwt_issuer").is_err()
        );
    }

    #[test]
    fn trust_identifiers_normalize_verification_methods_and_ignore_disabled_sources() {
        let fixture = fixture();
        let identifiers = trust_profile_issuer_identifiers(&fixture["trust_profile"]);
        for expected in fixture["expected_trusted_identifiers"].as_array().unwrap() {
            assert!(identifiers.contains(expected.as_str().unwrap()));
        }
        for forbidden in fixture["forbidden_trusted_identifiers"].as_array().unwrap() {
            assert!(!identifiers.contains(forbidden.as_str().unwrap()));
        }
        for case in fixture["key_purpose_cases"].as_array().unwrap() {
            assert_eq!(
                key_purpose(case["credential_format"].as_str().unwrap()),
                case["expected"].as_str().unwrap()
            );
        }
    }
}
