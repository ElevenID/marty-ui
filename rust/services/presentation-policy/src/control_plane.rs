use std::{collections::BTreeSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{Client, StatusCode};
use serde_json::{Map, Value};
use tonic::{
    metadata::AsciiMetadataValue,
    transport::{Channel, Endpoint},
    Code, Request,
};
use url::Url;
use uuid::Uuid;

use crate::{
    organization_proto::{
        organization_service_client::OrganizationServiceClient, GetMemberRequest, MemberResponse,
    },
    CredentialStatusEvidence, CredentialStatusResolver, IssuerTrustEvidence, PolicyAuthorization,
    PresentationTrustResolver, PresentationVerificationError, ResolvedTrustProfile,
};

const SERVICE_TOKEN_HEADER: &str = "x-service-token";

#[derive(Clone)]
pub struct NativePresentationControlPlane {
    organizations: OrganizationServiceClient<Channel>,
    http: Client,
    service_token: Option<AsciiMetadataValue>,
    service_token_header: Option<Arc<str>>,
    trust_profile_url: Arc<str>,
    status_url_template: Arc<str>,
    issuance_api_key: Option<Arc<str>>,
    managed_issuers: Arc<BTreeSet<String>>,
    timeout: Duration,
}

impl std::fmt::Debug for NativePresentationControlPlane {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativePresentationControlPlane")
            .field("trust_profile_url", &self.trust_profile_url)
            .field("status_url_template", &self.status_url_template)
            .field("managed_issuer_count", &self.managed_issuers.len())
            .field("service_token_configured", &self.service_token.is_some())
            .field(
                "issuance_api_key_configured",
                &self.issuance_api_key.is_some(),
            )
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl NativePresentationControlPlane {
    #[allow(clippy::too_many_arguments)]
    pub fn connect_lazy(
        organization_target: &str,
        trust_profile_url: &str,
        status_url_template: &str,
        service_token: Option<&str>,
        issuance_api_key: Option<&str>,
        managed_issuers: impl IntoIterator<Item = String>,
        timeout: Duration,
    ) -> Result<Self, PresentationVerificationError> {
        if timeout.is_zero() {
            return Err(failed("dependency timeout must be positive"));
        }
        let organizations = OrganizationServiceClient::new(channel(organization_target, timeout)?);
        let service_token_metadata = service_token
            .map(str::parse)
            .transpose()
            .map_err(|_| failed("service token is not valid ASCII metadata"))?;
        let trust_profile_url = service_url(trust_profile_url, "trust-profile")?;
        validate_status_template(status_url_template)?;
        let http = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| failed(&format!("HTTP client configuration failed: {error}")))?;
        Ok(Self {
            organizations,
            http,
            service_token: service_token_metadata,
            service_token_header: service_token.map(Arc::<str>::from),
            trust_profile_url: Arc::from(trust_profile_url),
            status_url_template: Arc::from(status_url_template),
            issuance_api_key: issuance_api_key.map(Arc::<str>::from),
            managed_issuers: Arc::new(
                managed_issuers
                    .into_iter()
                    .flat_map(|issuer| issuer_candidates(&issuer))
                    .collect(),
            ),
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
        principal_id: &str,
        organization_id: Uuid,
    ) -> Result<MemberResponse, String> {
        let request = self.grpc_request(GetMemberRequest {
            organization_id: organization_id.to_string(),
            user_id: principal_id.to_owned(),
        });
        let mut client = self.organizations.clone();
        let member = match client.get_member(request).await {
            Ok(response) => response.into_inner(),
            Err(status)
                if matches!(
                    status.code(),
                    Code::NotFound | Code::InvalidArgument | Code::Unknown
                ) =>
            {
                return Err("membership required".into())
            }
            Err(_) => return Err("organization membership service unavailable".into()),
        };
        if member.user_id != principal_id
            || member.organization_id != organization_id.to_string()
            || !member.status.eq_ignore_ascii_case("active")
        {
            return Err("membership response did not match the request".into());
        }
        Ok(member)
    }

    fn http_request(&self, url: impl reqwest::IntoUrl) -> reqwest::RequestBuilder {
        let mut request = self.http.get(url);
        if let Some(token) = &self.service_token_header {
            request = request.header(SERVICE_TOKEN_HEADER, token.as_ref());
        }
        request
    }
}

#[async_trait]
impl PolicyAuthorization for NativePresentationControlPlane {
    async fn require(
        &self,
        principal_id: &str,
        organization_id: Uuid,
        action: &'static str,
    ) -> Result<(), String> {
        let member = self.membership(principal_id, organization_id).await?;
        let permission = match action {
            "view" | "evaluate" => "presentation-policy:view",
            "create" => "presentation-policy:create",
            "edit" | "activate" | "suspend" | "version" => "presentation-policy:edit",
            "delete" => "presentation-policy:delete",
            _ => return Err("unsupported presentation-policy action".into()),
        };
        if member.is_owner
            || member.has_org_console_access
            || member.permissions.iter().any(|value| value == permission)
        {
            Ok(())
        } else {
            Err("presentation-policy permission required".into())
        }
    }
}

#[async_trait]
impl PresentationTrustResolver for NativePresentationControlPlane {
    async fn load_profile(
        &self,
        profile_id: Uuid,
        organization_id: Uuid,
    ) -> Result<ResolvedTrustProfile, PresentationVerificationError> {
        let response = self
            .http_request(format!(
                "{}/internal/v1/trust-profiles/{profile_id}",
                self.trust_profile_url
            ))
            .send()
            .await
            .map_err(|_| PresentationVerificationError::Unavailable)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Err(failed("Trust Profile does not exist"));
        }
        if !response.status().is_success() {
            return Err(PresentationVerificationError::Unavailable);
        }
        let mut document = response
            .json::<Value>()
            .await
            .map_err(|_| PresentationVerificationError::Unavailable)?;
        let object = document
            .as_object_mut()
            .ok_or(PresentationVerificationError::Unavailable)?;
        let returned_id = uuid_field(object, "id")?;
        let returned_organization = uuid_field(object, "organization_id")?;
        if returned_id != profile_id || returned_organization != organization_id {
            return Err(failed("Trust Profile identity or organization mismatch"));
        }
        project_verification_methods(object)?;
        Ok(ResolvedTrustProfile {
            id: returned_id,
            organization_id: returned_organization,
            document,
        })
    }

    async fn evaluate_issuer(
        &self,
        profile: &ResolvedTrustProfile,
        issuer_id: &str,
    ) -> Result<IssuerTrustEvidence, PresentationVerificationError> {
        Ok(evaluate_issuer_document(
            &profile.document,
            issuer_id,
            Utc::now(),
        ))
    }
}

#[async_trait]
impl CredentialStatusResolver for NativePresentationControlPlane {
    async fn resolve(
        &self,
        organization_id: Uuid,
        issuer_id: &str,
        credential_ids: &[String],
    ) -> Result<CredentialStatusEvidence, PresentationVerificationError> {
        let presented_issuer_candidates = issuer_candidates(issuer_id);
        if presented_issuer_candidates.is_disjoint(&self.managed_issuers) {
            return Ok(CredentialStatusEvidence::default());
        }
        for credential_id in credential_ids {
            let encoded: String =
                url::form_urlencoded::byte_serialize(credential_id.as_bytes()).collect();
            let endpoint = self
                .status_url_template
                .replace("{credential_id}", &encoded);
            let mut request = self.http.get(endpoint).header("accept", "application/json");
            if let Some(api_key) = &self.issuance_api_key {
                request = request
                    .header("x-api-key", api_key.as_ref())
                    .header("x-organization-id", organization_id.to_string());
            }
            let response = request
                .send()
                .await
                .map_err(|_| PresentationVerificationError::Unavailable)?;
            if response.status() == StatusCode::NOT_FOUND {
                continue;
            }
            if !response.status().is_success() {
                return Err(PresentationVerificationError::Unavailable);
            }
            let payload = response
                .json::<Value>()
                .await
                .map_err(|_| PresentationVerificationError::Unavailable)?;
            let object = payload
                .as_object()
                .ok_or(PresentationVerificationError::Unavailable)?;
            if let Some(recorded_issuer) = object.get("issuer_did").and_then(Value::as_str) {
                if issuer_candidates(recorded_issuer).is_disjoint(&presented_issuer_candidates) {
                    continue;
                }
            }
            let status = object
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .trim()
                .to_ascii_lowercase();
            return Ok(CredentialStatusEvidence {
                checked_at_epoch_seconds: u64::try_from(Utc::now().timestamp()).ok(),
                not_revoked: Some(matches!(
                    status.as_str(),
                    "active" | "valid" | "current" | "good"
                )),
                credential_status: Some(status),
                warnings: Vec::new(),
            });
        }
        Ok(CredentialStatusEvidence::default())
    }
}

fn evaluate_issuer_document(
    document: &Value,
    issuer_id: &str,
    now: DateTime<Utc>,
) -> IssuerTrustEvidence {
    let Some(profile) = document.as_object() else {
        return denied("Trust Profile returned invalid data");
    };
    if profile
        .get("status")
        .and_then(Value::as_str)
        .is_none_or(|status| !status.eq_ignore_ascii_case("active"))
    {
        return denied("Trust Profile is not active");
    }
    let candidates = issuer_candidates(issuer_id);
    if !configured_identifiers(profile.get("denied_issuers")).is_disjoint(&candidates) {
        return denied("Issuer is explicitly denied by Trust Profile");
    }
    let relationships = match profile.get("issuer_relationships") {
        None => return evaluate_legacy_trust(profile, &candidates),
        Some(Value::Array(relationships)) => relationships,
        Some(_) => return denied("Trust Profile contains invalid issuer relationship data"),
    };
    if relationships.is_empty() {
        return evaluate_legacy_trust(profile, &candidates);
    }
    let matches = relationships
        .iter()
        .filter_map(Value::as_object)
        .filter(|relationship| {
            relationship
                .get("issuer_id")
                .and_then(Value::as_str)
                .is_some_and(|value| normalize_issuer(value) == normalize_issuer(issuer_id))
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return denied(if matches.is_empty() {
            "Issuer has no trusted issuer relationship"
        } else {
            "Issuer has ambiguous issuer relationships"
        });
    }
    evaluate_relationship(matches[0], now)
}

fn evaluate_relationship(
    relationship: &Map<String, Value>,
    now: DateTime<Utc>,
) -> IssuerTrustEvidence {
    if relationship
        .get("relationship_status")
        .and_then(Value::as_str)
        != Some("TRUSTED")
    {
        return denied("Issuer relationship is not trusted");
    }
    let compliance = relationship
        .get("compliance_status")
        .and_then(Value::as_str)
        .map(str::to_ascii_uppercase);
    if !matches!(compliance.as_deref(), Some("ACCREDITED" | "COMPLIANT")) {
        return denied("Issuer compliance status is not current");
    }
    if relationship
        .get("revoked_at")
        .is_some_and(|value| !value.is_null())
    {
        return denied("Issuer is revoked");
    }
    let Some(valid_from) = relationship.get("valid_from").and_then(parse_datetime) else {
        return denied("Issuer has invalid validity metadata");
    };
    if now < valid_from {
        return denied("Issuer is not yet valid");
    }
    if let Some(value) = relationship
        .get("valid_until")
        .filter(|value| !value.is_null())
    {
        let Some(valid_until) = parse_datetime(value) else {
            return denied("Issuer has invalid validity metadata");
        };
        if now >= valid_until {
            return denied("Issuer relationship is expired");
        }
    }
    let Some(trust_level) = relationship
        .get("trust_level")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value <= 100)
    else {
        return denied("Issuer has invalid trust level");
    };
    let Some(accreditations) = string_list(relationship.get("accreditations")) else {
        return denied("Issuer has invalid accreditation evidence");
    };
    IssuerTrustEvidence {
        verified: true,
        failure_reason: None,
        trust_level: Some(trust_level),
        compliance_statuses: compliance.into_iter().collect(),
        accreditations,
    }
}

fn evaluate_legacy_trust(
    profile: &Map<String, Value>,
    candidates: &BTreeSet<String>,
) -> IssuerTrustEvidence {
    let allowed = configured_identifiers(profile.get("allowed_issuers"));
    if !allowed.is_empty() {
        return if allowed.is_disjoint(candidates) {
            denied("Issuer is not in Trust Profile allowed_issuers")
        } else {
            trusted_without_relationship()
        };
    }
    let sources = profile
        .get("trust_sources")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .flat_map(|source| {
            [source.get("issuer_did"), source.get("url")]
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .flat_map(issuer_candidates)
        })
        .collect::<BTreeSet<_>>();
    if !sources.is_empty() && sources.is_disjoint(candidates) {
        denied("Issuer does not match a Trust Profile source")
    } else {
        trusted_without_relationship()
    }
}

fn project_verification_methods(
    profile: &mut Map<String, Value>,
) -> Result<(), PresentationVerificationError> {
    let mut methods = Vec::new();
    for relationship in profile
        .get("issuer_relationships")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let relationship = relationship
            .as_object()
            .ok_or_else(|| failed("Trust Profile contains invalid issuer relationship data"))?;
        if relationship
            .get("relationship_status")
            .and_then(Value::as_str)
            != Some("TRUSTED")
        {
            continue;
        }
        let controller = relationship
            .get("issuer_id")
            .and_then(Value::as_str)
            .ok_or_else(|| failed("Trust Profile issuer relationship omitted issuer_id"))?;
        for key in relationship
            .get("verification_keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let key = key
                .as_object()
                .filter(|key| is_public_jwk(key))
                .ok_or_else(|| failed("Trust Profile contains invalid public verification key"))?;
            let id = key
                .get("kid")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| failed("Trust Profile verification key omitted kid"))?;
            methods.push(serde_json::json!({
                "id": id,
                "controller": controller,
                "public_jwk": key,
            }));
        }
    }
    profile.insert(
        "resolved_verification_methods".into(),
        Value::Array(methods),
    );
    Ok(())
}

fn is_public_jwk(key: &Map<String, Value>) -> bool {
    key.get("kty")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
        && ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
            .iter()
            .all(|parameter| !key.contains_key(*parameter))
}

fn uuid_field(
    value: &Map<String, Value>,
    name: &str,
) -> Result<Uuid, PresentationVerificationError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| failed(&format!("Trust Profile {name} is invalid")))
}

fn configured_identifiers(value: Option<&Value>) -> BTreeSet<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .flat_map(issuer_candidates)
        .collect()
}

fn issuer_candidates(value: &str) -> BTreeSet<String> {
    let raw = value.trim();
    if raw.is_empty() || raw == "unknown" {
        return BTreeSet::new();
    }
    let mut output = BTreeSet::from([raw.to_owned(), raw.trim_end_matches('/').to_owned()]);
    if let Ok(url) = Url::parse(raw) {
        if matches!(url.scheme(), "http" | "https") {
            let mut normalized = url;
            normalized.set_query(None);
            normalized.set_fragment(None);
            output.insert(
                normalized
                    .as_str()
                    .trim_end_matches('/')
                    .to_ascii_lowercase(),
            );
            if let Some(host) = normalized.host_str() {
                output.insert(host.to_ascii_lowercase());
            }
        }
    } else if let Some(host) = raw
        .strip_prefix("did:web:")
        .and_then(|value| value.split(':').next())
    {
        output.insert(host.to_ascii_lowercase());
    }
    output
}

fn normalize_issuer(value: &str) -> String {
    let raw = value.trim();
    if raw.to_ascii_lowercase().starts_with("did:") {
        raw.to_owned()
    } else if let Ok(mut url) = Url::parse(raw) {
        if matches!(url.scheme(), "http" | "https") {
            url.set_query(None);
            url.set_fragment(None);
            url.as_str().trim_end_matches('/').to_ascii_lowercase()
        } else {
            raw.to_owned()
        }
    } else {
        raw.trim_end_matches('/').to_owned()
    }
}

fn string_list(value: Option<&Value>) -> Option<Vec<String>> {
    value.and_then(Value::as_array).and_then(|values| {
        values
            .iter()
            .map(Value::as_str)
            .map(|value| {
                value
                    .filter(|value| !value.trim().is_empty())
                    .map(str::to_owned)
            })
            .collect::<Option<Vec<_>>>()
    })
}

fn parse_datetime(value: &Value) -> Option<DateTime<Utc>> {
    value
        .as_str()
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

fn denied(reason: &str) -> IssuerTrustEvidence {
    IssuerTrustEvidence {
        verified: false,
        failure_reason: Some(reason.into()),
        ..Default::default()
    }
}

fn trusted_without_relationship() -> IssuerTrustEvidence {
    IssuerTrustEvidence {
        verified: true,
        ..Default::default()
    }
}

fn service_url(value: &str, name: &str) -> Result<String, PresentationVerificationError> {
    let parsed = Url::parse(value).map_err(|_| failed(&format!("invalid {name} URL")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(failed(&format!("invalid {name} URL")));
    }
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

fn validate_status_template(value: &str) -> Result<(), PresentationVerificationError> {
    if !value.contains("{credential_id}") {
        return Err(failed(
            "credential status URL template requires {credential_id}",
        ));
    }
    service_url(
        &value.replace("{credential_id}", "test"),
        "credential status",
    )
    .map(drop)
}

fn channel(target: &str, timeout: Duration) -> Result<Channel, PresentationVerificationError> {
    Endpoint::from_shared(target.to_owned())
        .map_err(|_| failed("invalid organization gRPC target"))
        .map(|endpoint| {
            endpoint
                .connect_timeout(timeout)
                .timeout(timeout)
                .connect_lazy()
        })
}

fn failed(detail: &str) -> PresentationVerificationError {
    PresentationVerificationError::Failed(detail.into())
}
