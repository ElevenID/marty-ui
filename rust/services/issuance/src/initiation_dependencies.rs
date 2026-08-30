use std::{collections::BTreeSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use reqwest::{redirect::Policy, Client, StatusCode};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};
use sqlx::{PgPool, Row};
use tonic::{
    metadata::AsciiMetadataValue,
    transport::{Channel, Endpoint},
    Code, Request,
};

use crate::{
    client_auth::RegisteredClientRepository,
    credential_template_proto::{
        credential_template_service_client::CredentialTemplateServiceClient, GetTemplateRequest,
        TemplateResponse,
    },
    initiation::{
        InitiationApplicationClaimsResolver, InitiationClientRepository, InitiationDependencyError,
        InitiationOrganizationValidator, InitiationRegisteredClient,
        InitiationRelatedResourceValidator, InitiationRevocationProfileValidator,
        InitiationTemplate, InitiationTemplateResolver, OrganizationValidation,
    },
    organization_proto::{
        organization_service_client::OrganizationServiceClient, GetOrganizationRequest,
    },
    revocation_profile_proto::{
        revocation_profile_service_client::RevocationProfileServiceClient,
        GetRevocationProfileRequest,
    },
    token_postgres::PostgresTokenExchangeRepository,
};

const SERVICE_TOKEN_HEADER: &str = "x-service-token";
const DEFAULT_VALIDITY_DAYS: i64 = 365;
const DEFAULT_RENEWAL_WINDOW_DAYS: i64 = 30;

/// Shared clients for the initiation control-plane reads. Clones are cheap and
/// keep the three dependency ports on the same channel/authentication policy.
#[derive(Clone)]
pub struct NativeInitiationControlPlane {
    organizations: OrganizationServiceClient<Channel>,
    templates: CredentialTemplateServiceClient<Channel>,
    revocation_profiles: RevocationProfileServiceClient<Channel>,
    http: Client,
    credential_template_http_url: Arc<str>,
    service_token: Option<AsciiMetadataValue>,
    timeout: Duration,
}

impl std::fmt::Debug for NativeInitiationControlPlane {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeInitiationControlPlane")
            .field(
                "credential_template_http_url",
                &self.credential_template_http_url,
            )
            .field("service_token_configured", &self.service_token.is_some())
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl NativeInitiationControlPlane {
    pub fn connect_lazy(
        organization_target: &str,
        credential_template_target: &str,
        revocation_profile_target: &str,
        credential_template_http_url: impl Into<Arc<str>>,
        service_token: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, InitiationDependencyError> {
        if timeout.is_zero() {
            return Err(InitiationDependencyError::Invalid(
                "dependency timeout must be positive".to_owned(),
            ));
        }
        let service_token = service_token.map(str::parse).transpose().map_err(|_| {
            InitiationDependencyError::Invalid(
                "service token is not valid ASCII metadata".to_owned(),
            )
        })?;
        let http = Client::builder()
            .timeout(timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|_| InitiationDependencyError::Unavailable)?;
        Ok(Self {
            organizations: OrganizationServiceClient::new(channel(organization_target, timeout)?),
            templates: CredentialTemplateServiceClient::new(channel(
                credential_template_target,
                timeout,
            )?),
            revocation_profiles: RevocationProfileServiceClient::new(channel(
                revocation_profile_target,
                timeout,
            )?),
            http,
            credential_template_http_url: credential_template_http_url.into(),
            service_token,
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

    async fn resolve_template_http(
        &self,
        template_id: &str,
    ) -> Result<InitiationTemplate, InitiationDependencyError> {
        let base = self.credential_template_http_url.trim_end_matches('/');
        if base.is_empty() {
            return Err(InitiationDependencyError::Unavailable);
        }
        let encoded: String =
            url::form_urlencoded::byte_serialize(template_id.as_bytes()).collect();
        let mut request = self
            .http
            .get(format!("{base}/v1/credential-templates/{encoded}"));
        if let Some(token) = &self.service_token {
            request = request.header(SERVICE_TOKEN_HEADER, token.as_encoded_bytes());
        }
        let response = request.send().await.map_err(request_error)?;
        match response.status() {
            StatusCode::NOT_FOUND => return Err(InitiationDependencyError::NotFound),
            status if status.is_client_error() => {
                let status = status.as_u16();
                let detail = response.text().await.unwrap_or_default();
                return Err(InitiationDependencyError::HttpClient { status, detail });
            }
            status if !status.is_success() => return Err(InitiationDependencyError::Unavailable),
            _ => {}
        }
        let value: Value = response
            .json()
            .await
            .map_err(|_| InitiationDependencyError::Unavailable)?;
        template_from_json(template_id, &value)
    }
}

#[async_trait]
impl InitiationOrganizationValidator for NativeInitiationControlPlane {
    async fn validate(&self, organization_id: &str) -> OrganizationValidation {
        let mut client = self.organizations.clone();
        match client
            .get_organization(self.grpc_request(GetOrganizationRequest {
                organization_id: organization_id.to_owned(),
            }))
            .await
        {
            Ok(response) if response.get_ref().id == organization_id => {
                OrganizationValidation::Found
            }
            Ok(_) => OrganizationValidation::NotFound,
            Err(status) if status.code() == Code::NotFound => OrganizationValidation::NotFound,
            Err(_) => OrganizationValidation::Unavailable,
        }
    }
}

#[async_trait]
impl InitiationTemplateResolver for NativeInitiationControlPlane {
    async fn resolve(
        &self,
        template_id: &str,
    ) -> Result<InitiationTemplate, InitiationDependencyError> {
        let mut client = self.templates.clone();
        match client
            .get_template(self.grpc_request(GetTemplateRequest {
                template_id: template_id.to_owned(),
            }))
            .await
        {
            Ok(response) if response.get_ref().id.is_empty() => {
                Err(InitiationDependencyError::NotFound)
            }
            Ok(response) => match template_from_grpc(template_id, response.into_inner()) {
                Ok(template) => Ok(template),
                Err(_) => self.resolve_template_http(template_id).await,
            },
            Err(_) => self.resolve_template_http(template_id).await,
        }
    }
}

#[async_trait]
impl InitiationRevocationProfileValidator for NativeInitiationControlPlane {
    async fn validate_active(
        &self,
        organization_id: &str,
        profile_id: Option<&str>,
    ) -> Result<(), InitiationDependencyError> {
        let profile_id = profile_id
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                InitiationDependencyError::Invalid(
                    "credential template must reference an active revocation profile".into(),
                )
            })?;
        let mut client = self.revocation_profiles.clone();
        let profile = client
            .get_revocation_profile(self.grpc_request(GetRevocationProfileRequest {
                profile_id: profile_id.to_owned(),
            }))
            .await
            .map_err(grpc_dependency_error)?
            .into_inner();
        if profile.id != profile_id {
            return Err(InitiationDependencyError::Invalid(
                "revocation profile identity mismatch".into(),
            ));
        }
        if profile.organization_id != organization_id {
            return Err(InitiationDependencyError::Invalid(
                "revocation profile belongs to another organization".into(),
            ));
        }
        if !profile.status.trim().eq_ignore_ascii_case("active") {
            return Err(InitiationDependencyError::Invalid(
                "credential template must reference an active revocation profile".into(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl InitiationClientRepository for PostgresTokenExchangeRepository {
    async fn get(
        &self,
        organization_id: &str,
        client_id: &str,
    ) -> Result<Option<InitiationRegisteredClient>, InitiationDependencyError> {
        RegisteredClientRepository::client(self, organization_id, client_id)
            .await
            .map(|client| {
                client.map(|client| InitiationRegisteredClient {
                    client_id: client.client_id,
                    active: client.active,
                    token_endpoint_auth_method: client.token_endpoint_auth_method,
                })
            })
            .map_err(|_| InitiationDependencyError::Unavailable)
    }
}

#[derive(Clone, Debug)]
pub struct PostgresInitiationApplicationClaimsResolver {
    pool: PgPool,
}

impl PostgresInitiationApplicationClaimsResolver {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl InitiationApplicationClaimsResolver for PostgresInitiationApplicationClaimsResolver {
    async fn resolve(&self, application_id: &str) -> Result<Option<Map<String, Value>>, ()> {
        let row = sqlx::query("SELECT form_data FROM issuance_service.applications WHERE id = $1")
            .bind(application_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| ())?;
        let Some(row) = row else {
            return Ok(None);
        };
        let value: Value = row.try_get("form_data").map_err(|_| ())?;
        match value {
            Value::Object(claims) => Ok(Some(claims)),
            _ => Err(()),
        }
    }
}

#[derive(Clone)]
pub struct HttpInitiationRelatedResourceValidator {
    allowed_urls: Arc<BTreeSet<String>>,
    client: Client,
    max_bytes: usize,
}

impl std::fmt::Debug for HttpInitiationRelatedResourceValidator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpInitiationRelatedResourceValidator")
            .field("allowed_url_count", &self.allowed_urls.len())
            .field("max_bytes", &self.max_bytes)
            .finish_non_exhaustive()
    }
}

impl HttpInitiationRelatedResourceValidator {
    pub fn new(
        allowed_urls: impl IntoIterator<Item = String>,
        max_bytes: usize,
        timeout: Duration,
    ) -> Result<Self, InitiationDependencyError> {
        if max_bytes == 0 || timeout.is_zero() {
            return Err(InitiationDependencyError::Invalid(
                "related-resource validation is misconfigured".into(),
            ));
        }
        let allowed_urls = allowed_urls
            .into_iter()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect();
        let client = Client::builder()
            .timeout(timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|_| InitiationDependencyError::Unavailable)?;
        Ok(Self {
            allowed_urls: Arc::new(allowed_urls),
            client,
            max_bytes,
        })
    }

    async fn fetch(&self, resource_id: &str) -> Result<Vec<u8>, InitiationDependencyError> {
        let mut response = self.client.get(resource_id).send().await.map_err(|_| {
            InitiationDependencyError::Invalid("related_resource_unavailable".into())
        })?;
        if response.status() != StatusCode::OK
            || response
                .content_length()
                .is_some_and(|length| length > self.max_bytes as u64)
        {
            return Err(InitiationDependencyError::Invalid(
                "related_resource_unavailable".into(),
            ));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| {
            InitiationDependencyError::Invalid("related_resource_unavailable".into())
        })? {
            if body.len().saturating_add(chunk.len()) > self.max_bytes {
                return Err(InitiationDependencyError::Invalid(
                    "related_resource_unavailable".into(),
                ));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

#[async_trait]
impl InitiationRelatedResourceValidator for HttpInitiationRelatedResourceValidator {
    async fn validate(&self, credential: &Value) -> Result<(), InitiationDependencyError> {
        let Some(resources) = credential.get("relatedResource") else {
            return Ok(());
        };
        if self.allowed_urls.is_empty() {
            return Err(InitiationDependencyError::Invalid(
                "related_resource_validation_not_configured".into(),
            ));
        }
        let resources: Vec<&Value> = match resources {
            Value::Array(values) => values.iter().collect(),
            value => vec![value],
        };
        for resource in resources {
            let object = resource.as_object().ok_or_else(|| {
                InitiationDependencyError::Invalid("invalid_related_resource".into())
            })?;
            let resource_id = object.get("id").and_then(Value::as_str).ok_or_else(|| {
                InitiationDependencyError::Invalid("invalid_related_resource".into())
            })?;
            let is_https = url::Url::parse(resource_id)
                .ok()
                .is_some_and(|url| url.scheme() == "https");
            if !is_https || !self.allowed_urls.contains(resource_id) {
                return Err(InitiationDependencyError::Invalid(
                    "related_resource_not_allowlisted".into(),
                ));
            }
            let content = self.fetch(resource_id).await?;
            verify_sri(object.get("digestSRI").and_then(Value::as_str), &content)?;
        }
        Ok(())
    }
}

fn template_from_grpc(
    requested_id: &str,
    template: TemplateResponse,
) -> Result<InitiationTemplate, InitiationDependencyError> {
    if template.id != requested_id {
        return Err(InitiationDependencyError::Invalid(
            "credential template identity mismatch".into(),
        ));
    }
    let wallet_configs = if template.wallet_configs_json.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str::<Vec<Value>>(&template.wallet_configs_json).map_err(|_| {
            InitiationDependencyError::Invalid("invalid template wallet configuration".into())
        })?
    };
    let validity = template.validity_rules.unwrap_or_default();
    Ok(InitiationTemplate {
        credential_type: non_empty_or(template.credential_type, "org.iso.18013.5.1.mDL"),
        vct: non_empty(template.vct),
        zk_predicate_claims: template.zk_predicate_claims,
        selective_disclosure_claims: template.selective_disclosure_fields,
        credential_payload_format: non_empty_or(
            template.credential_payload_format,
            "w3c_vcdm_v2_sd_jwt",
        ),
        revocation_profile_id: non_empty(template.revocation_profile_id),
        issuer_did: non_empty(template.issuer_did),
        issuer_algorithm: non_empty(template.issuer_algorithm),
        wallet_configs,
        validity_days: positive_or(
            i64::from(validity.default_validity_days),
            DEFAULT_VALIDITY_DAYS,
        ),
        renewable: validity.renewable,
        renewal_window_days: positive_or(
            i64::from(validity.renewal_window_days),
            DEFAULT_RENEWAL_WINDOW_DAYS,
        ),
    })
}

fn template_from_json(
    requested_id: &str,
    value: &Value,
) -> Result<InitiationTemplate, InitiationDependencyError> {
    let object = value
        .as_object()
        .ok_or_else(|| InitiationDependencyError::Invalid("invalid template response".into()))?;
    if object.get("id").and_then(Value::as_str) != Some(requested_id) {
        return Err(InitiationDependencyError::Invalid(
            "credential template identity mismatch".into(),
        ));
    }
    let validity = object.get("validity_rules").and_then(Value::as_object);
    let validity_days = positive_or(
        json_i64(validity, "default_validity_days"),
        seconds_as_days(json_i64(validity, "ttl_seconds"), DEFAULT_VALIDITY_DAYS),
    );
    let renewal_window_days = positive_or(
        json_i64(validity, "renewal_window_days"),
        seconds_as_days(
            json_i64(validity, "reissue_within_seconds"),
            DEFAULT_RENEWAL_WINDOW_DAYS,
        ),
    );
    Ok(InitiationTemplate {
        credential_type: json_string(object, "credential_type")
            .unwrap_or_else(|| "org.iso.18013.5.1.mDL".into()),
        vct: json_optional_string(object, "vct"),
        zk_predicate_claims: json_strings(object, "zk_predicate_claims")?,
        selective_disclosure_claims: json_strings(object, "selective_disclosure_fields")?,
        credential_payload_format: json_string(object, "credential_payload_format")
            .unwrap_or_else(|| "w3c_vcdm_v2_sd_jwt".into()),
        revocation_profile_id: json_optional_string(object, "revocation_profile_id"),
        issuer_did: json_optional_string(object, "issuer_did"),
        issuer_algorithm: json_optional_string(object, "issuer_algorithm"),
        wallet_configs: object
            .get("wallet_configs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        validity_days,
        renewable: validity
            .and_then(|value| value.get("renewable"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        renewal_window_days,
    })
}

fn verify_sri(value: Option<&str>, content: &[u8]) -> Result<(), InitiationDependencyError> {
    let value = value
        .ok_or_else(|| InitiationDependencyError::Invalid("invalid_related_resource".into()))?;
    let (algorithm, encoded) = value
        .split_once('-')
        .ok_or_else(|| InitiationDependencyError::Invalid("invalid_related_resource".into()))?;
    let expected = STANDARD
        .decode(encoded)
        .map_err(|_| InitiationDependencyError::Invalid("invalid_related_resource".into()))?;
    let actual = match algorithm {
        "sha256" => Sha256::digest(content).to_vec(),
        "sha384" => Sha384::digest(content).to_vec(),
        "sha512" => Sha512::digest(content).to_vec(),
        _ => {
            return Err(InitiationDependencyError::Invalid(
                "invalid_related_resource".into(),
            ))
        }
    };
    if expected == actual {
        Ok(())
    } else {
        Err(InitiationDependencyError::Invalid(
            "related_resource_digest_mismatch".into(),
        ))
    }
}

fn channel(target: &str, timeout: Duration) -> Result<Channel, InitiationDependencyError> {
    let target = grpc_endpoint_target(target)?;
    Endpoint::from_shared(target)
        .map_err(|_| InitiationDependencyError::Invalid("invalid gRPC target".into()))
        .map(|endpoint| {
            endpoint
                .connect_timeout(timeout)
                .timeout(timeout)
                .connect_lazy()
        })
}

fn grpc_endpoint_target(target: &str) -> Result<String, InitiationDependencyError> {
    if target.is_empty() || target.chars().any(char::is_whitespace) {
        return Err(InitiationDependencyError::Invalid(
            "invalid gRPC target".into(),
        ));
    }
    Ok(if target.contains("://") {
        target.to_owned()
    } else {
        format!("http://{target}")
    })
}

fn grpc_dependency_error(status: tonic::Status) -> InitiationDependencyError {
    match status.code() {
        Code::NotFound => InitiationDependencyError::NotFound,
        Code::DeadlineExceeded => InitiationDependencyError::Timeout,
        _ => InitiationDependencyError::Unavailable,
    }
}

fn request_error(error: reqwest::Error) -> InitiationDependencyError {
    if error.is_timeout() {
        InitiationDependencyError::Timeout
    } else {
        InitiationDependencyError::Unavailable
    }
}

fn non_empty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

fn non_empty_or(value: String, fallback: &str) -> String {
    non_empty(value).unwrap_or_else(|| fallback.to_owned())
}

fn positive_or(value: i64, fallback: i64) -> i64 {
    if value > 0 {
        value
    } else {
        fallback
    }
}

fn seconds_as_days(value: i64, fallback: i64) -> i64 {
    if value > 0 {
        (value / 86_400).max(1)
    } else {
        fallback
    }
}

fn json_i64(object: Option<&Map<String, Value>>, name: &str) -> i64 {
    object
        .and_then(|value| value.get(name))
        .and_then(Value::as_i64)
        .unwrap_or_default()
}

fn json_string(object: &Map<String, Value>, name: &str) -> Option<String> {
    object
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn json_optional_string(object: &Map<String, Value>, name: &str) -> Option<String> {
    json_string(object, name)
}

fn json_strings(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Vec<String>, InitiationDependencyError> {
    let Some(value) = object.get(name) else {
        return Ok(Vec::new());
    };
    serde_json::from_value(value.clone())
        .map_err(|_| InitiationDependencyError::Invalid(format!("invalid template {name}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::HeaderMap, response::Json, routing::get, Router};
    use serde_json::json;

    const TEST_SERVICE_TOKEN: &str = "0123456789abcdef0123456789abcdef";

    #[tokio::test]
    async fn grpc_targets_preserve_legacy_host_port_configuration() {
        assert_eq!(
            grpc_endpoint_target("organization:9002").unwrap(),
            "http://organization:9002"
        );
        assert_eq!(
            grpc_endpoint_target("https://organization.example:9002").unwrap(),
            "https://organization.example:9002"
        );
        channel("organization:9002", Duration::from_secs(1)).unwrap();

        for invalid in ["", " organization:9002", "organization:9002 ", "org name:9002"] {
            assert_eq!(
                grpc_endpoint_target(invalid),
                Err(InitiationDependencyError::Invalid(
                    "invalid gRPC target".into()
                ))
            );
        }
    }

    async fn template_fallback(headers: HeaderMap) -> Json<Value> {
        assert_eq!(
            headers
                .get(SERVICE_TOKEN_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(TEST_SERVICE_TOKEN)
        );
        Json(json!({
            "id": "template-1",
            "credential_type": "EmployeeCredential",
            "vct": "https://credentials.example/employee",
            "issuer_did": "did:web:issuer.example",
            "issuer_algorithm": "ES256",
            "revocation_profile_id": "profile-1",
            "selective_disclosure_fields": ["employee_id"],
            "wallet_configs": [{"wallet_id": "wallet-1"}],
            "validity_rules": {
                "ttl_seconds": 172800,
                "reissue_within_seconds": 86400,
                "renewable": true
            }
        }))
    }

    async fn template_conflict() -> (StatusCode, &'static str) {
        (
            StatusCode::CONFLICT,
            "template is not readable in its current state",
        )
    }

    #[tokio::test]
    async fn unavailable_grpc_template_uses_authenticated_http_fallback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/v1/credential-templates/template-1",
            get(template_fallback),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let dependencies = NativeInitiationControlPlane::connect_lazy(
            "http://127.0.0.1:1",
            "http://127.0.0.1:1",
            "http://127.0.0.1:1",
            format!("http://{address}"),
            Some(TEST_SERVICE_TOKEN),
            Duration::from_secs(2),
        )
        .unwrap();

        let template = dependencies.resolve("template-1").await.unwrap();
        server.abort();

        assert_eq!(template.credential_type, "EmployeeCredential");
        assert_eq!(
            template.vct.as_deref(),
            Some("https://credentials.example/employee")
        );
        assert_eq!(template.selective_disclosure_claims, ["employee_id"]);
        assert_eq!(template.wallet_configs, [json!({"wallet_id": "wallet-1"})]);
        assert_eq!(template.validity_days, 2);
        assert_eq!(template.renewal_window_days, 1);
        assert!(template.renewable);
    }

    #[tokio::test]
    async fn http_template_client_status_and_detail_are_preserved() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new().route(
            "/v1/credential-templates/template-1",
            get(template_conflict),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let dependencies = NativeInitiationControlPlane::connect_lazy(
            "http://127.0.0.1:1",
            "http://127.0.0.1:1",
            "http://127.0.0.1:1",
            format!("http://{address}"),
            None,
            Duration::from_secs(2),
        )
        .unwrap();

        let error = dependencies.resolve_template_http("template-1").await;
        server.abort();

        assert_eq!(
            error,
            Err(InitiationDependencyError::HttpClient {
                status: 409,
                detail: "template is not readable in its current state".into(),
            })
        );
    }

    #[test]
    fn http_template_preserves_legacy_validity_fallbacks() {
        let template = template_from_json(
            "template-1",
            &json!({
                "id": "template-1",
                "credential_type": "EmployeeCredential",
                "issuer_did": "did:web:issuer.example",
                "issuer_algorithm": "ES256",
                "revocation_profile_id": "profile-1",
                "validity_rules": {
                    "ttl_seconds": 172800,
                    "reissue_within_seconds": 86400,
                    "renewable": true
                }
            }),
        )
        .unwrap();
        assert_eq!(template.validity_days, 2);
        assert_eq!(template.renewal_window_days, 1);
        assert!(template.renewable);
    }

    #[test]
    fn sri_accepts_sha_variants_and_rejects_mismatch() {
        let content = b"official context bytes";
        for (name, digest) in [
            ("sha256", Sha256::digest(content).to_vec()),
            ("sha384", Sha384::digest(content).to_vec()),
            ("sha512", Sha512::digest(content).to_vec()),
        ] {
            let sri = format!("{name}-{}", STANDARD.encode(digest));
            verify_sri(Some(&sri), content).unwrap();
        }
        assert_eq!(
            verify_sri(Some("sha256-d3Jvbmc="), content),
            Err(InitiationDependencyError::Invalid(
                "related_resource_digest_mismatch".into()
            ))
        );
    }

    #[tokio::test]
    async fn related_resources_require_configuration_before_network_access() {
        let validator = HttpInitiationRelatedResourceValidator::new(
            Vec::new(),
            2_000_000,
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!(
            validator
                .validate(&json!({
                    "relatedResource": {
                        "id": "https://www.w3.org/ns/credentials/v2",
                        "digestSRI": "sha256-ZXhhbXBsZQ=="
                    }
                }))
                .await,
            Err(InitiationDependencyError::Invalid(
                "related_resource_validation_not_configured".into()
            ))
        );
    }
}
