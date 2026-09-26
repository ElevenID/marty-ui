use crate::certificate_csr::{self, CsrSubject};
use crate::compat::{
    CompatibilityError, IssuerContextRequest, IssuerDidSignRequest, ProfileIdentityRequest,
    ProfileWriteRequest, ResolveIssuerDidRequest, ServiceSignRequest, SigningCompatibilityService,
};
use crate::csca_lifecycle::{
    self, CscaCertificateDataResponse, CscaCertificateView, CscaLifecycleDocument,
    CscaLifecycleError, CscaLifecycleStore, CscaOutboxEvent, ExpiringCscaCertificatesRequest,
    ImportCscaCertificateRequest, ListCscaCertificatesQuery, ListCscaOutboxQuery,
    RenewCscaCertificateRequest, RevokeCscaCertificateRequest,
};
use crate::documents::{
    self, CertificateAlertsRequest, CertificateAlertsResponse, DeleteJwkResponse,
    DidVerificationRelationship, DocumentStore, InspectCertificateRequest,
    InspectCertificateResponse, LoadDidRequest, LoadDidResponse, PublishDidRequest,
    PublishDidResponse, PublishJwkRequest, PublishJwkResponse, StoredCertificate, UpdateJwkRequest,
    UpdateJwkResponse,
};
use crate::domain::{key_purposes, service_capabilities};
use crate::flow_envelope::{
    FlowEnvelopeError, OpenBaoEnvelopeProvider, UnwrapRequest, WrapRequest,
};
use crate::kms::{self, ProviderRequest, SignRequest};
use crate::passport_artifact_envelope::{
    self, ArtifactEnvelopeError, DecryptChunkRequest, EncryptChunkRequest,
};
use crate::profiles::{
    self, CustodyFormatRequest, CustodyFormatResponse, DuplicateProfileRequest,
    DuplicateProfileResponse, FindProfilesRequest, NormalizeProfileRequest, ProfileStore,
    ValidateBindingRequest,
};
use crate::registry::{
    self, BindProfileRequest, NormalizeRegistryRequest, NormalizeRegistryResponse,
    NormalizeServiceRequest, NormalizeServiceResponse, RegistryStore, ResolveRequest,
    ResolveResponse, SaveRegistryRequest,
};
use crate::validation::{self, ValidationRequest};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tower_http::trace::TraceLayer;

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

#[derive(Debug, Serialize)]
struct ServiceStatus {
    service_name: &'static str,
    phase: &'static str,
    migrated_capabilities: [&'static str; 11],
    pending_capabilities: [&'static str; 2],
}

#[derive(Clone)]
struct AppState {
    internal_api_key: Arc<str>,
    registry_store: Option<RegistryStore>,
    document_store: Option<DocumentStore>,
    csca_lifecycle_store: Option<CscaLifecycleStore>,
    profile_store: Option<ProfileStore>,
    flow_envelopes: Option<OpenBaoEnvelopeProvider>,
    compatibility: Option<SigningCompatibilityService>,
    public_domain: Option<String>,
}

pub fn router() -> Router {
    router_with_internal_api_key("dev-signing-keys-internal-api-key".to_string())
}

pub fn router_with_internal_api_key(internal_api_key: String) -> Router {
    router_with_dependencies(internal_api_key, None, None, None, None, None, None)
}

pub fn router_with_dependencies(
    internal_api_key: String,
    registry_store: Option<RegistryStore>,
    document_store: Option<DocumentStore>,
    csca_lifecycle_store: Option<CscaLifecycleStore>,
    profile_store: Option<ProfileStore>,
    flow_envelopes: Option<OpenBaoEnvelopeProvider>,
    public_domain: Option<String>,
) -> Router {
    let compatibility = match (&registry_store, &document_store, &profile_store) {
        (Some(registry), Some(documents), Some(profiles)) => {
            Some(SigningCompatibilityService::new(
                registry.clone(),
                documents.clone(),
                profiles.clone(),
                public_domain.clone(),
            ))
        }
        _ => None,
    };
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/startup", get(startup))
        .route("/openapi.json", get(openapi))
        .route("/docs", get(docs))
        .route("/redoc", get(redoc))
        .route("/v1/signing-keys/service-status", get(service_status))
        .route("/v1/signing-keys", get(list_public_signing_keys))
        .route("/v1/signing-keys/jwks", get(public_organization_jwks))
        .route(
            "/v1/signing-keys/did-document",
            get(public_organization_did_document),
        )
        .route(
            "/v1/signing-keys/config",
            get(public_config).patch(save_public_config),
        )
        .route(
            "/v1/signing-keys/config/validate",
            post(validate_public_service),
        )
        .route(
            "/v1/signing-keys/config/certificate-expiry-alerts",
            get(public_certificate_expiry_alerts),
        )
        .route(
            "/v1/signing-keys/issuer-identities",
            get(list_public_issuer_identities)
                .post(create_public_issuer_identity)
                .patch(rebind_public_issuer_identity)
                .delete(delete_public_issuer_identity),
        )
        .route(
            "/v1/signing-keys/issuer-identities/resolve",
            post(resolve_public_issuer_identity),
        )
        .route(
            "/v1/signing-keys/issuer-identities/certificate",
            axum::routing::put(store_public_issuer_certificate),
        )
        .route(
            "/v1/signing-keys/issuer-identities/csca-certificate",
            axum::routing::put(enroll_public_csca_certificate),
        )
        .route(
            "/v1/signing-keys/issuer-identities/certificate-csr",
            axum::routing::put(generate_public_issuer_csr),
        )
        .route(
            "/v1/signing-keys/services/{service_id}/certificate",
            get(get_public_service_certificate).put(store_public_service_certificate),
        )
        .route(
            "/v1/signing-keys/services/{service_id}/certificate-csr",
            post(generate_public_service_csr),
        )
        .route(
            "/v1/signing-keys/services/{service_id}/mdoc-x5c",
            get(public_service_mdoc_x5c),
        )
        .route(
            "/v1/signing-keys/services/{service_id}/verify-current",
            get(verify_public_service_key),
        )
        .route(
            "/v1/signing-keys/services/{service_id}/publish-jwks",
            post(publish_public_service_jwks),
        )
        .route(
            "/v1/signing-keys/services/{service_id}/publish-did-vm",
            post(publish_public_service_did_vm),
        )
        .route("/v1/signing-keys/config/purposes", get(purposes))
        .route(
            "/v1/signing-keys/config/service-capabilities",
            get(capabilities),
        )
        .route("/internal/kms/sign", post(kms_sign))
        .route("/internal/kms/public-key", post(kms_public_key))
        .route("/internal/kms/verify", post(kms_verify))
        .route("/internal/flow-key-envelopes/wrap", post(wrap_flow_key))
        .route("/internal/flow-key-envelopes/unwrap", post(unwrap_flow_key))
        .route("/internal/compat/issuer-context", post(issuer_context))
        .route(
            "/internal/compat/resolve-issuer-did",
            post(resolve_issuer_did),
        )
        .route(
            "/internal/compat/issuer-profiles/{profile_id}/identity",
            post(profile_identity),
        )
        .route(
            "/internal/compat/issuer-profiles/{profile_id}/public-identity",
            post(profile_public_identity),
        )
        .route(
            "/internal/compat/services/{service_id}/sign",
            post(service_sign),
        )
        .route("/internal/compat/issuer-dids/sign", post(issuer_did_sign))
        .route(
            "/internal/compat/issuer-profiles",
            post(create_compatibility_profile),
        )
        .route(
            "/internal/compat/issuer-profiles/{profile_id}",
            axum::routing::patch(update_compatibility_profile),
        )
        .route(
            "/internal/compat/issuer-profiles/{profile_id}/certificate",
            axum::routing::put(attach_compatibility_certificate),
        )
        .route("/internal/config/validate", post(validate_service))
        .route("/internal/registry/catalog", get(registry_catalog))
        .route(
            "/internal/registry/normalize-service",
            post(normalize_registry_service),
        )
        .route("/internal/registry/normalize", post(normalize_registry))
        .route("/internal/registry/resolve", post(resolve_registry))
        .route(
            "/internal/registry/{organization_id}/bind-profile",
            post(bind_registry_profile),
        )
        .route(
            "/internal/registry/{organization_id}",
            get(load_registry).put(save_registry),
        )
        .route(
            "/internal/documents/certificate/inspect",
            post(inspect_certificate),
        )
        .route(
            "/internal/documents/certificate-alerts",
            post(certificate_alerts),
        )
        .route(
            "/internal/documents/{organization_id}/certificates",
            get(certificate_overrides),
        )
        .route(
            "/internal/documents/{organization_id}/certificates/{service_id}",
            axum::routing::put(store_certificate),
        )
        .route(
            "/internal/documents/{organization_id}/csca-certificates",
            get(list_csca_certificates),
        )
        .route(
            "/internal/documents/{organization_id}/csca-trust-anchors",
            get(active_csca_trust_anchors),
        )
        .route(
            "/internal/documents/{organization_id}/passport-artifacts/encrypt",
            post(encrypt_passport_artifact_chunk),
        )
        .route(
            "/internal/documents/{organization_id}/passport-artifacts/decrypt",
            post(decrypt_passport_artifact_chunk),
        )
        .route(
            "/internal/documents/{organization_id}/csca-certificates/expiring",
            post(expiring_csca_certificates),
        )
        .route(
            "/internal/documents/{organization_id}/csca-certificates/{certificate_id}",
            get(get_csca_certificate).put(import_csca_certificate),
        )
        .route(
            "/internal/documents/{organization_id}/csca-certificates/{certificate_id}/data",
            get(get_csca_certificate_data),
        )
        .route(
            "/internal/documents/{organization_id}/csca-certificates/{certificate_id}/revoke",
            post(revoke_csca_certificate),
        )
        .route(
            "/internal/documents/{organization_id}/csca-certificates/{certificate_id}/renew",
            post(renew_csca_certificate),
        )
        .route(
            "/internal/documents/{organization_id}/csca-outbox",
            get(list_csca_outbox),
        )
        .route(
            "/internal/documents/{organization_id}/csca-outbox/{event_id}/acknowledge",
            post(acknowledge_csca_outbox),
        )
        .route("/internal/documents/{organization_id}/jwks", get(load_jwks))
        .route(
            "/internal/documents/{organization_id}/jwks/{service_id}",
            axum::routing::put(publish_jwk)
                .patch(update_jwk)
                .delete(delete_jwk),
        )
        .route(
            "/internal/documents/{organization_id}/did/load",
            post(load_did),
        )
        .route(
            "/internal/documents/{organization_id}/did/{service_id}",
            axum::routing::put(publish_did),
        )
        .route("/internal/documents/did-web/{slug}", get(resolve_did_slug))
        .route(
            "/internal/profiles/{organization_id}/normalize",
            post(normalize_profile),
        )
        .route(
            "/internal/profiles/{organization_id}/validate-binding",
            post(validate_profile_binding),
        )
        .route(
            "/internal/profiles/{organization_id}/custody-format",
            post(resolve_profile_custody_format),
        )
        .route(
            "/internal/profiles/{organization_id}/find",
            post(find_profiles),
        )
        .route(
            "/internal/profiles/{organization_id}/find-duplicate",
            post(find_duplicate_profile),
        )
        .route("/internal/profiles/{organization_id}", get(list_profiles))
        .route(
            "/internal/profiles/{organization_id}/{profile_id}",
            get(get_profile).put(put_profile).delete(delete_profile),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(AppState {
            internal_api_key: Arc::from(internal_api_key),
            registry_store,
            document_store,
            csca_lifecycle_store,
            profile_store,
            flow_envelopes,
            compatibility,
            public_domain,
        })
}

#[derive(Debug, Deserialize)]
struct OrganizationScope {
    organization_id: String,
}

#[derive(Debug, Deserialize)]
struct IssuerIdentityQuery {
    organization_id: String,
    #[serde(default)]
    key_purpose: Option<String>,
    #[serde(default)]
    credential_format: Option<String>,
    #[serde(default)]
    algorithm: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerIdentityRequest {
    #[serde(default)]
    organization_id: Option<String>,
    issuer_did: String,
    key_purpose: String,
    credential_format: String,
    algorithm: String,
    #[serde(default)]
    key_attestation_policy: Option<Value>,
    #[serde(default)]
    cert_pem: Option<String>,
    #[serde(default)]
    cert_chain_pem: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CscaCertificateEnrollment {
    #[serde(default)]
    organization_id: Option<String>,
    issuer_did: String,
    credential_format: String,
    algorithm: String,
    certificate_id: String,
    cert_pem: String,
    #[serde(default)]
    cert_chain_pem: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PassportCsrRequest {
    #[serde(default)]
    organization_id: Option<String>,
    issuer_did: String,
    key_purpose: String,
    credential_format: String,
    algorithm: String,
    country: String,
    organization: String,
    common_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceCertificateRequest {
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    cert_pem: String,
    #[serde(default)]
    cert_chain_pem: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceCsrRequest {
    #[serde(default)]
    organization_id: Option<String>,
    country: String,
    organization: String,
    common_name: String,
}

#[derive(Debug, Deserialize)]
struct CertificateExpiryAlertQuery {
    organization_id: String,
    #[serde(default = "default_certificate_alert_days")]
    days_until_expiry: i64,
}

fn default_certificate_alert_days() -> i64 {
    30
}

impl PassportCsrRequest {
    fn identity(&self) -> IssuerIdentityRequest {
        IssuerIdentityRequest {
            organization_id: self.organization_id.clone(),
            issuer_did: self.issuer_did.clone(),
            key_purpose: self.key_purpose.clone(),
            credential_format: self.credential_format.clone(),
            algorithm: self.algorithm.clone(),
            key_attestation_policy: None,
            cert_pem: None,
            cert_chain_pem: None,
        }
    }
}

impl CscaCertificateEnrollment {
    fn identity(&self) -> IssuerIdentityRequest {
        IssuerIdentityRequest {
            organization_id: self.organization_id.clone(),
            issuer_did: self.issuer_did.clone(),
            key_purpose: "csca".into(),
            credential_format: self.credential_format.clone(),
            algorithm: self.algorithm.clone(),
            key_attestation_policy: None,
            cert_pem: None,
            cert_chain_pem: None,
        }
    }
}

#[derive(Debug)]
struct PublicSigningError {
    status: StatusCode,
    detail: String,
}

async fn list_public_signing_keys(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
) -> Response {
    let Some(registry_store) = state.registry_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        );
    };
    let registry = match registry_store.load(&scope.organization_id).await {
        Ok(registry) => registry,
        Err(error) => return public_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()),
    };
    let profiles = if let Some(profile_store) = state.profile_store.as_ref() {
        match profile_store
            .find(&scope.organization_id, FindProfilesRequest::default())
            .await
        {
            Ok(profiles) => profiles,
            Err(error) => return public_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()),
        }
    } else {
        Vec::new()
    };
    let keys = public_signing_key_inventory(&registry, &profiles);
    let key_count = keys.len();
    Json(json!({
        "keys": keys,
        "provider_metadata": {
            "provider": "configured-services",
            "status": "configured",
            "managed_by": "Marty signing service",
            "key_count": key_count,
        },
        "domain_config": {"public_domain": state.public_domain},
        "message": Value::Null,
    }))
    .into_response()
}

fn public_signing_key_inventory(registry: &Value, profiles: &[Value]) -> Vec<Value> {
    let services = registry
        .get("services")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let services_by_id = services
        .iter()
        .filter_map(|service| {
            service
                .get("id")
                .and_then(Value::as_str)
                .map(|id| (id.to_owned(), service))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut keys = std::collections::BTreeMap::<String, Value>::new();

    for profile in profiles {
        let Some(reference) = profile
            .get("signing_key_reference")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        let service_id = profile
            .get("signing_service_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let service = services_by_id.get(service_id).copied();
        let key = format!("{service_id}\0{reference}");
        keys.entry(key).or_insert_with(|| {
            json!({
                "id": reference,
                "provider_key_name": reference,
                "name": profile.get("name").and_then(Value::as_str).filter(|value| !value.is_empty()).unwrap_or(reference),
                "algorithm": profile.get("algorithm").and_then(Value::as_str).unwrap_or_default(),
                "status": profile.get("status").and_then(Value::as_str).unwrap_or("active"),
                "created_at": profile.get("created_at").cloned().unwrap_or(Value::Null),
                "expiry_date": Value::Null,
                "service_id": service_id,
                "provider": service.and_then(|value| value.get("provider")).cloned().unwrap_or(Value::Null),
                "key_purpose": profile.get("key_purpose").cloned().unwrap_or(Value::Null),
            })
        });
    }

    for service in &services {
        let service_id = service
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut references = service
            .get("key_aliases")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if let Some(reference) = service.get("key_reference").and_then(Value::as_str) {
            references.push(reference.to_owned());
        }
        for reference in references {
            let reference = reference.trim();
            if reference.is_empty() {
                continue;
            }
            let key = format!("{service_id}\0{reference}");
            keys.entry(key).or_insert_with(|| {
                json!({
                    "id": reference,
                    "provider_key_name": reference,
                    "name": reference,
                    "algorithm": service.get("algorithms").and_then(Value::as_array).and_then(|values| values.first()).cloned().unwrap_or(Value::Null),
                    "status": "active",
                    "created_at": Value::Null,
                    "expiry_date": Value::Null,
                    "service_id": service_id,
                    "provider": service.get("provider").cloned().unwrap_or(Value::Null),
                    "key_purpose": Value::Null,
                })
            });
        }
    }

    keys.into_values().collect()
}

impl IntoResponse for PublicSigningError {
    fn into_response(self) -> Response {
        public_error(self.status, &self.detail)
    }
}

async fn public_config(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
) -> Response {
    let Some(store) = state.registry_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        );
    };
    match store.load(&scope.organization_id).await {
        Ok(registry) => Json(public_config_document(&state, registry)).into_response(),
        Err(error) => public_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()),
    }
}

fn public_jwk_projection(key: &Value) -> Result<Value, documents::DocumentError> {
    let sanitized = documents::sanitize_public_jwk(key, None)?;
    const PUBLIC_JWK_FIELDS: &[&str] = &[
        "kty",
        "crv",
        "x",
        "y",
        "n",
        "e",
        "kid",
        "use",
        "alg",
        "key_ops",
        "x5c",
        "x5t",
        "x5t#S256",
        "service_id",
        "name",
        "status",
    ];
    let fields = sanitized
        .as_object()
        .expect("sanitized JWK is an object")
        .iter()
        .filter(|(name, _)| PUBLIC_JWK_FIELDS.contains(&name.as_str()))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    Ok(Value::Object(fields))
}

fn public_jwks_document(
    document: Value,
    organization_id: &str,
) -> Result<Value, PublicSigningError> {
    let keys = document
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| public_failure(StatusCode::BAD_GATEWAY, "Stored JWKS is malformed."))?;
    let sanitized = keys
        .iter()
        .map(public_jwk_projection)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| public_failure(StatusCode::BAD_GATEWAY, "Stored JWKS is malformed."))?;
    Ok(json!({
        "keys": sanitized,
        "organization_id": organization_id,
        "updated_at": document.get("updated_at"),
    }))
}

async fn public_organization_jwks(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
) -> Response {
    if let Err(error) = validate_service_scope(&scope.organization_id, None) {
        return error.into_response();
    }
    let Some(store) = state.document_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing document storage is unavailable.",
        );
    };
    let document = match store.jwks(&scope.organization_id).await {
        Ok(document) => document,
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing document storage is unavailable.",
            )
        }
    };
    match public_jwks_document(document, &scope.organization_id) {
        Ok(document) => Json(document).into_response(),
        Err(error) => error.into_response(),
    }
}

fn public_did_document(document: Value) -> Result<Value, PublicSigningError> {
    fn scrub(value: &Value) -> Result<Value, documents::DocumentError> {
        match value {
            Value::Object(fields) => {
                const CUSTODY_FIELDS: &[&str] = &[
                    "d",
                    "p",
                    "q",
                    "dp",
                    "dq",
                    "qi",
                    "oth",
                    "k",
                    "rsa_d",
                    "privateKeyJwk",
                    "privateKeyMultibase",
                    "privateKeyBase58",
                    "private_key",
                    "key_reference",
                    "auth_reference",
                    "auth_token",
                    "access_token",
                    "api_key",
                    "secret",
                    "secret_key",
                    "seed",
                ];
                let mut public = serde_json::Map::new();
                for (name, nested) in fields {
                    if CUSTODY_FIELDS.contains(&name.as_str()) {
                        continue;
                    }
                    public.insert(
                        name.clone(),
                        if name == "publicKeyJwk" {
                            public_jwk_projection(nested)?
                        } else {
                            scrub(nested)?
                        },
                    );
                }
                Ok(Value::Object(public))
            }
            Value::Array(values) => values
                .iter()
                .map(scrub)
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            other => Ok(other.clone()),
        }
    }
    if document
        .get("id")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(public_failure(
            StatusCode::BAD_GATEWAY,
            "Stored DID document is malformed.",
        ));
    }
    scrub(&document)
        .map_err(|_| public_failure(StatusCode::BAD_GATEWAY, "Stored DID document is malformed."))
}

async fn public_organization_did_document(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
) -> Response {
    if let Err(error) = validate_service_scope(&scope.organization_id, None) {
        return error.into_response();
    }
    let Some(domain) = state
        .public_domain
        .as_deref()
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
    else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Public DID authority is unavailable.",
        );
    };
    let Some(store) = state.document_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing document storage is unavailable.",
        );
    };
    let fallback_did = format!("did:web:{domain}:orgs:{}", scope.organization_id);
    let loaded = match store
        .load_did(
            &scope.organization_id,
            LoadDidRequest {
                did_id: None,
                fallback_did: Some(fallback_did),
            },
        )
        .await
    {
        Ok(loaded) => loaded,
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing document storage is unavailable.",
            )
        }
    };
    match public_did_document(loaded.document) {
        Ok(document) => Json(document).into_response(),
        Err(error) => error.into_response(),
    }
}

fn services_with_certificate_overrides(registry: &Value, overrides: &Value) -> Vec<Value> {
    let certificates = documents::normalize_certificate_overrides(overrides);
    registry
        .get("services")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|service| service.is_object())
        .map(|service| {
            let mut service = service.clone();
            if let Some(attachment) = service
                .get("id")
                .and_then(Value::as_str)
                .and_then(|id| certificates.get(id))
            {
                for field in ["cert_pem", "cert_chain_pem", "cert_expires_at"] {
                    if let Some(value) = attachment.get(field) {
                        service[field] = value.clone();
                    }
                }
            }
            service
        })
        .collect()
}

async fn public_certificate_expiry_alerts(
    State(state): State<AppState>,
    Query(query): Query<CertificateExpiryAlertQuery>,
) -> Response {
    if let Err(error) = validate_service_scope(&query.organization_id, None) {
        return error.into_response();
    }
    if !(0..=36_500).contains(&query.days_until_expiry) {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "days_until_expiry must be between 0 and 36500.",
        );
    }
    let Some(registry_store) = state.registry_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        );
    };
    let Some(document_store) = state.document_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Certificate storage is unavailable.",
        );
    };
    let registry = match registry_store.load(&query.organization_id).await {
        Ok(registry) => registry,
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing registry is unavailable.",
            )
        }
    };
    let overrides = match document_store
        .certificate_overrides(&query.organization_id)
        .await
    {
        Ok(overrides) => overrides,
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Certificate storage is unavailable.",
            )
        }
    };
    match documents::certificate_alerts(CertificateAlertsRequest {
        services: services_with_certificate_overrides(&registry, &overrides),
        days_until_expiry: query.days_until_expiry,
        now: None,
    }) {
        Ok(alerts) => Json(alerts).into_response(),
        Err(error) => document_error(error).into_response(),
    }
}

async fn save_public_config(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    Json(mut body): Json<Value>,
) -> Response {
    let Some(store) = state.registry_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        );
    };
    let existing = match store.load(&scope.organization_id).await {
        Ok(registry) => registry,
        Err(error) => return public_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()),
    };
    preserve_unchanged_auth_references(&mut body, &existing);
    match store.save(&scope.organization_id, &body).await {
        Ok(registry) => Json(public_config_document(&state, registry)).into_response(),
        Err(error) => public_error(StatusCode::UNPROCESSABLE_ENTITY, &error.to_string()),
    }
}

async fn validate_public_service(Json(request): Json<ValidationRequest>) -> Response {
    Json(validation::validate(request).await).into_response()
}

async fn list_public_issuer_identities(
    State(state): State<AppState>,
    Query(query): Query<IssuerIdentityQuery>,
) -> Response {
    let Some(store) = state.profile_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity storage is unavailable.",
        );
    };
    let request = FindProfilesRequest {
        active_only: true,
        key_purpose: cleaned(query.key_purpose),
        credential_format: cleaned(query.credential_format).map(|value| value.to_ascii_uppercase()),
        algorithm: cleaned(query.algorithm).map(|value| canonical_algorithm(&value)),
        require_signing_service: true,
        require_signing_key_reference: true,
        require_public_identity: true,
        ..FindProfilesRequest::default()
    };
    match store.find(&query.organization_id, request).await {
        Ok(profiles) => match projected_identities(profiles) {
            Ok(identities) => Json(json!({"identities": identities})).into_response(),
            Err(error) => error.into_response(),
        },
        Err(error) => public_error(StatusCode::UNPROCESSABLE_ENTITY, &error.to_string()),
    }
}

fn public_issuer_jwk(candidate: &Value) -> Result<Value, PublicSigningError> {
    let mut public = public_jwk_projection(candidate).map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer DID resolution returned no usable public key.",
        )
    })?;
    let Some(fields) = public.as_object_mut() else {
        return Err(public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer DID resolution returned no usable public key.",
        ));
    };
    for field in ["kid", "service_id", "name", "status"] {
        fields.remove(field);
    }
    Ok(public)
}

async fn resolve_public_issuer_identity(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    Json(input): Json<IssuerIdentityRequest>,
) -> Response {
    if let Err(error) = validate_identity_scope(&scope.organization_id, &input) {
        return error.into_response();
    }
    if let Err(error) = validate_identity_operation_fields(&input, false, false) {
        return error.into_response();
    }
    let profile = match one_matching_profile(&state, &scope.organization_id, &input).await {
        Ok(profile) => profile,
        Err(error) => return error.into_response(),
    };
    let Some(compatibility) = state.compatibility.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity service is unavailable.",
        );
    };
    let resolved = match compatibility
        .resolve_issuer_did(&ResolveIssuerDidRequest {
            organization_id: scope.organization_id,
            issuer_did: input.issuer_did,
            verification_method_id: None,
            credential_format: Some(input.credential_format),
            key_purpose: Some(input.key_purpose),
            algorithm: Some(canonical_algorithm(&input.algorithm)),
        })
        .await
    {
        Ok(resolved) => resolved,
        Err(error) => return error.into_response(),
    };
    if !same_managed_identity(&profile, &resolved) {
        return public_error(
            StatusCode::CONFLICT,
            "Resolved issuer identity does not match its active managed profile.",
        );
    }
    let Some(jwk) = resolved.get("public_jwk") else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer DID resolution returned no usable public key.",
        );
    };
    let public_jwk = match public_issuer_jwk(jwk) {
        Ok(jwk) => jwk,
        Err(error) => return error.into_response(),
    };
    Json(json!({"identity": identity_projection(&profile), "public_jwk": public_jwk}))
        .into_response()
}

async fn create_public_issuer_identity(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    Json(input): Json<IssuerIdentityRequest>,
) -> Response {
    if let Err(error) = validate_identity_scope(&scope.organization_id, &input) {
        return error.into_response();
    }
    if let Err(error) = validate_identity_operation_fields(&input, true, false) {
        return error.into_response();
    }
    if !local_managed_did(state.public_domain.as_deref(), &input.issuer_did) {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "New managed identities require a local path-scoped did:web issuer.",
        );
    }
    let Some(store) = state.profile_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity storage is unavailable.",
        );
    };
    let selector = identity_selector_with_publication(&input, false);
    let existing = match store.find(&scope.organization_id, selector).await {
        Ok(existing) => existing,
        Err(error) => return public_error(StatusCode::UNPROCESSABLE_ENTITY, &error.to_string()),
    };
    if existing.len() > 1 {
        return public_error(
            StatusCode::CONFLICT,
            "Issuer DID resolution is ambiguous for the requested identity tuple.",
        );
    }
    let Some(compatibility) = state.compatibility.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity service is unavailable.",
        );
    };
    if let Some(profile) = existing.first() {
        return match compatibility
            .create_profile(&ProfileWriteRequest {
                organization_id: scope.organization_id.clone(),
                body: profile.clone(),
            })
            .await
        {
            Ok(repaired) => repaired
                .get("profile")
                .map(|profile| {
                    Json(json!({"identity": identity_projection(profile), "created": false}))
                        .into_response()
                })
                .unwrap_or_else(|| {
                    public_error(
                        StatusCode::BAD_GATEWAY,
                        "Issuer identity repair returned an invalid response.",
                    )
                }),
            Err(error) => error.into_response(),
        };
    }
    let key_reference = managed_key_reference(&scope.organization_id, &input);
    let body = json!({
        "name": input.issuer_did,
        "issuer_did": input.issuer_did,
        "key_purpose": input.key_purpose,
        "credential_format": input.credential_format.to_ascii_uppercase(),
        "algorithm": canonical_algorithm(&input.algorithm),
        "key_attestation_policy": input.key_attestation_policy,
        "status": "active"
    });
    match compatibility
        .create_provider_neutral_profile(
            &ProfileWriteRequest {
                organization_id: scope.organization_id,
                body,
            },
            &key_reference,
        )
        .await
    {
        Ok(created) => {
            let Some(profile) = created.get("profile") else {
                return public_error(
                    StatusCode::BAD_GATEWAY,
                    "Issuer identity provisioning returned an invalid response.",
                );
            };
            Json(json!({
                "identity": identity_projection(profile),
                "created": created.get("created").and_then(Value::as_bool).unwrap_or(true)
            }))
            .into_response()
        }
        Err(error) => error.into_response(),
    }
}

async fn rebind_public_issuer_identity(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    Json(input): Json<IssuerIdentityRequest>,
) -> Response {
    if let Err(error) = validate_identity_scope(&scope.organization_id, &input) {
        return error.into_response();
    }
    if let Err(error) = validate_identity_operation_fields(&input, false, false) {
        return error.into_response();
    }
    if !local_managed_did(state.public_domain.as_deref(), &input.issuer_did) {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Signing-provider changes require a local path-scoped did:web issuer.",
        );
    }
    let profile = match one_matching_profile(&state, &scope.organization_id, &input).await {
        Ok(profile) => profile,
        Err(error) => return error.into_response(),
    };
    let Some(profile_id) = profile.get("id").and_then(Value::as_str) else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity storage is malformed.",
        );
    };
    let Some(compatibility) = state.compatibility.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity service is unavailable.",
        );
    };
    let key_reference = managed_key_reference(&scope.organization_id, &input);
    match compatibility
        .rebind_profile_to_default(&scope.organization_id, profile_id, &key_reference)
        .await
    {
        Ok(result) => {
            let Some(profile) = result.get("profile") else {
                return public_error(
                    StatusCode::BAD_GATEWAY,
                    "Issuer identity rebinding returned an invalid response.",
                );
            };
            Json(json!({
                "identity": identity_projection(profile),
                "changed": result.get("changed").and_then(Value::as_bool).unwrap_or(false)
            }))
            .into_response()
        }
        Err(error) => error.into_response(),
    }
}

async fn store_public_issuer_certificate(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    Json(input): Json<IssuerIdentityRequest>,
) -> Response {
    if let Err(error) = validate_identity_scope(&scope.organization_id, &input) {
        return error.into_response();
    }
    if let Err(error) = validate_identity_operation_fields(&input, false, true) {
        return error.into_response();
    }
    let profile = match one_matching_profile(&state, &scope.organization_id, &input).await {
        Ok(profile) => profile,
        Err(error) => return error.into_response(),
    };
    let Some(profile_id) = profile.get("id").and_then(Value::as_str) else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity storage is malformed.",
        );
    };
    let Some(compatibility) = state.compatibility.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity service is unavailable.",
        );
    };
    match compatibility
        .attach_profile_certificate(
            profile_id,
            &ProfileWriteRequest {
                organization_id: scope.organization_id,
                body: json!({
                    "cert_pem": input.cert_pem,
                    "cert_chain_pem": input.cert_chain_pem,
                }),
            },
        )
        .await
    {
        Ok(_) => Json(identity_projection(&profile)).into_response(),
        Err(error) => error.into_response(),
    }
}

fn managed_csca_import(
    input: &CscaCertificateEnrollment,
    profile: &Value,
    resolved: &Value,
    provider_public_jwk: &Value,
) -> Result<ImportCscaCertificateRequest, PublicSigningError> {
    if !same_managed_identity(profile, resolved)
        || profile.get("key_purpose").and_then(Value::as_str) != Some("csca")
    {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Resolved CSCA identity does not match its active managed profile.",
        ));
    }
    let key_reference = profile
        .get("signing_key_reference")
        .and_then(Value::as_str)
        .filter(|reference| !reference.trim().is_empty())
        .ok_or_else(|| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Managed CSCA key reference is unavailable.",
            )
        })?;
    let expected_public_jwk = resolved
        .get("public_jwk")
        .filter(|jwk| jwk.is_object())
        .cloned()
        .ok_or_else(|| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Managed CSCA public key is unavailable.",
            )
        })?;
    if !documents::same_public_jwk(&expected_public_jwk, provider_public_jwk) {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Published CSCA identity does not match its current managed KMS key.",
        ));
    }
    Ok(ImportCscaCertificateRequest {
        cert_pem: input.cert_pem.clone(),
        cert_chain_pem: input.cert_chain_pem.clone(),
        key_reference: key_reference.to_owned(),
        expected_public_jwk,
        metadata: json!({"issuer_did": input.issuer_did}),
    })
}

fn same_managed_identity(profile: &Value, resolved: &Value) -> bool {
    ["id", "signing_service_id", "signing_key_reference"]
        .iter()
        .all(|field| {
            profile
                .get(*field)
                .and_then(Value::as_str)
                .is_some_and(|value| {
                    !value.trim().is_empty()
                        && resolved
                            .pointer(&format!("/issuer_profile/{field}"))
                            .and_then(Value::as_str)
                            == Some(value)
                })
        })
}

async fn generate_public_issuer_csr(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    Json(input): Json<PassportCsrRequest>,
) -> Response {
    if !matches!(input.key_purpose.as_str(), "csca" | "x509_doc_signer") {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Passport CSR purpose is unsupported.",
        );
    }
    let identity = input.identity();
    if let Err(error) = validate_identity_scope(&scope.organization_id, &identity) {
        return error.into_response();
    }
    let profile = match one_matching_profile(&state, &scope.organization_id, &identity).await {
        Ok(profile) => profile,
        Err(error) => return error.into_response(),
    };
    let Some(compatibility) = state.compatibility.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity service is unavailable.",
        );
    };
    let algorithm = canonical_algorithm(&input.algorithm);
    let resolved = match compatibility
        .resolve_issuer_did(&ResolveIssuerDidRequest {
            organization_id: scope.organization_id.clone(),
            issuer_did: input.issuer_did.clone(),
            verification_method_id: None,
            credential_format: Some(input.credential_format.clone()),
            key_purpose: Some(input.key_purpose.clone()),
            algorithm: Some(algorithm.clone()),
        })
        .await
    {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if !same_managed_identity(&profile, &resolved) {
        return public_error(
            StatusCode::CONFLICT,
            "Resolved issuer identity does not match its active managed profile.",
        );
    }
    let current_jwk = match compatibility
        .provider_public_key_for_profile(&scope.organization_id, &profile)
        .await
    {
        Ok(jwk) => jwk,
        Err(error) => return error.into_response(),
    };
    if !resolved
        .get("public_jwk")
        .is_some_and(|jwk| documents::same_public_jwk(jwk, &current_jwk))
    {
        return public_error(
            StatusCode::CONFLICT,
            "Published issuer identity does not match its current managed KMS key.",
        );
    }
    let subject = CsrSubject {
        country: &input.country,
        organization: &input.organization,
        common_name: &input.common_name,
    };
    let csr = match certificate_csr::prepare(&current_jwk, &algorithm, &subject) {
        Ok(csr) => csr,
        Err(error) => return public_error(StatusCode::UNPROCESSABLE_ENTITY, &error.to_string()),
    };
    let signed = match compatibility
        .sign_with_issuer_did(&IssuerDidSignRequest {
            organization_id: scope.organization_id,
            issuer_did: input.issuer_did.clone(),
            credential_format: input.credential_format,
            key_purpose: input.key_purpose,
            algorithm,
            payload_b64: Some(URL_SAFE_NO_PAD.encode(csr.signing_bytes())),
            payload_hex: None,
        })
        .await
    {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if signed.get("signature_encoding").and_then(Value::as_str) != Some("der") {
        return public_error(
            StatusCode::BAD_GATEWAY,
            "Managed issuer returned an incompatible CSR signature.",
        );
    }
    let signature = signed
        .get("signature_b64")
        .and_then(Value::as_str)
        .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok());
    let Some(signature) = signature else {
        return public_error(
            StatusCode::BAD_GATEWAY,
            "Managed issuer returned an invalid CSR signature.",
        );
    };
    let csr_pem = match csr.finish(&signature) {
        Ok(pem) => pem,
        Err(_) => {
            return public_error(
                StatusCode::BAD_GATEWAY,
                "Managed issuer CSR signature did not verify.",
            )
        }
    };
    Json(json!({
        "csr_pem": csr_pem,
        "issuer_did": input.issuer_did,
        "subject": {"country": input.country, "organization": input.organization, "common_name": input.common_name}
    })).into_response()
}

fn validate_service_scope(
    organization_id: &str,
    requested_organization_id: Option<&str>,
) -> Result<(), PublicSigningError> {
    if organization_id.trim().is_empty() {
        return Err(public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "An organization context is required.",
        ));
    }
    if requested_organization_id.is_some_and(|requested| requested.trim() != organization_id) {
        return Err(public_failure(
            StatusCode::FORBIDDEN,
            "organization_id does not match the authorized organization context.",
        ));
    }
    Ok(())
}

async fn registered_certificate_service(
    state: &AppState,
    organization_id: &str,
    service_id: &str,
) -> Result<Value, PublicSigningError> {
    let store = state.registry_store.as_ref().ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        )
    })?;
    let registry = store.load(organization_id).await.map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        )
    })?;
    let service = registry
        .get("services")
        .and_then(Value::as_array)
        .and_then(|services| {
            services
                .iter()
                .find(|service| service.get("id").and_then(Value::as_str) == Some(service_id))
        })
        .cloned()
        .ok_or_else(|| {
            public_failure(
                StatusCode::NOT_FOUND,
                &format!("Service '{service_id}' not found."),
            )
        })?;
    if service_id == "managed-openbao-transit" {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Managed signing keys require an issuer-scoped certificate identity.",
        ));
    }
    Ok(service)
}

fn service_certificate_projection(service: &Value, certificate: &Value) -> Value {
    json!({
        "id": service.get("id"),
        "name": service.get("name"),
        "service_type": service.get("service_type"),
        "provider": service.get("provider"),
        "status": service.get("status"),
        "cert_pem": certificate.get("cert_pem"),
        "cert_chain_pem": certificate.get("cert_chain_pem"),
        "cert_expires_at": certificate.get("cert_expires_at"),
    })
}

fn service_certificate_key_config(service: &Value) -> Result<Value, PublicSigningError> {
    let mut config = service.clone();
    let reference = service
        .get("key_reference")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|reference| !reference.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            let aliases = service.get("key_aliases")?.as_array()?;
            if aliases.len() == 1 {
                aliases[0]
                    .as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            } else {
                None
            }
        })
        .ok_or_else(|| {
            public_failure(
                StatusCode::CONFLICT,
                "A service certificate requires one configured KMS signing key.",
            )
        })?;
    config["key_reference"] = json!(reference);
    Ok(config)
}

async fn current_service_public_jwk(service: &Value) -> Result<(Value, Value), PublicSigningError> {
    let config = service_certificate_key_config(service)?;
    let response = kms::public_key(ProviderRequest {
        service_config: config.clone(),
    })
    .await
    .map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "The service KMS public key is unavailable.",
        )
    })?;
    let public_jwk = documents::sanitize_public_jwk(&response, None).map_err(|_| {
        public_failure(
            StatusCode::BAD_GATEWAY,
            "The service KMS returned an invalid public key.",
        )
    })?;
    Ok((config, public_jwk))
}

async fn verify_public_service_key(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
) -> Response {
    if let Err(error) = validate_service_scope(&scope.organization_id, None) {
        return error.into_response();
    }
    let service =
        match registered_certificate_service(&state, &scope.organization_id, &service_id).await {
            Ok(service) => service,
            Err(error) => return error.into_response(),
        };
    let public_jwk = match current_service_public_jwk(&service).await {
        Ok((_, jwk)) => jwk,
        Err(error) => return error.into_response(),
    };
    Json(verify_service_key_result(
        &service_id,
        &service,
        &public_jwk,
        chrono::Utc::now().to_rfc3339(),
    ))
    .into_response()
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicServiceJwksPublicationRequest {}

async fn checked_stored_service_certificate(
    documents: &DocumentStore,
    organization_id: &str,
    service_id: &str,
    service: &Value,
    public_jwk: &Value,
) -> Result<Option<Value>, PublicSigningError> {
    let overrides = documents
        .certificate_overrides(organization_id)
        .await
        .map_err(|_| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Certificate storage is unavailable.",
            )
        })?;
    let certificate = selected_service_certificate(service, &overrides, service_id).cloned();
    if let Some(certificate) = certificate.as_ref() {
        checked_service_x5c(certificate, public_jwk, service_id)?;
    }
    Ok(certificate)
}

fn public_publication_error(error: documents::DocumentError) -> Response {
    match error {
        documents::DocumentError::Invalid(detail) => {
            public_error(StatusCode::UNPROCESSABLE_ENTITY, &detail)
        }
        documents::DocumentError::Conflict(detail) => public_error(StatusCode::CONFLICT, &detail),
        documents::DocumentError::NotFound(detail) => public_error(StatusCode::NOT_FOUND, &detail),
        documents::DocumentError::Storage(_) => public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing document storage is unavailable.",
        ),
        documents::DocumentError::Corrupt(_) => public_error(
            StatusCode::BAD_GATEWAY,
            "Stored signing document is malformed.",
        ),
    }
}

async fn publish_public_service_jwks(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
    _body: Option<Json<PublicServiceJwksPublicationRequest>>,
) -> Response {
    if let Err(error) = validate_service_scope(&scope.organization_id, None) {
        return error.into_response();
    }
    let service =
        match registered_certificate_service(&state, &scope.organization_id, &service_id).await {
            Ok(service) => service,
            Err(error) => return error.into_response(),
        };
    let Some(documents) = state.document_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing document storage is unavailable.",
        );
    };
    let (config, public_jwk) = match current_service_public_jwk(&service).await {
        Ok(material) => material,
        Err(error) => return error.into_response(),
    };
    let certificate = match checked_stored_service_certificate(
        documents,
        &scope.organization_id,
        &service_id,
        &service,
        &public_jwk,
    )
    .await
    {
        Ok(certificate) => certificate,
        Err(error) => return error.into_response(),
    };
    let publication = match documents
        .publish_jwk(
            &scope.organization_id,
            &service_id,
            PublishJwkRequest {
                jwk: public_jwk,
                key_reference: config["key_reference"].as_str().map(str::to_owned),
                cert_pem: certificate
                    .as_ref()
                    .and_then(|value| value.get("cert_pem"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                cert_chain_pem: certificate
                    .as_ref()
                    .and_then(|value| value.get("cert_chain_pem"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            },
        )
        .await
    {
        Ok(publication) => publication,
        Err(error) => return public_publication_error(error),
    };
    if let Err(error) = mark_service_publication_discovered(
        &state,
        &scope.organization_id,
        &service_id,
        &[("last_jwk_fetch_ok", json!(true))],
    )
    .await
    {
        return error.into_response();
    }
    let public = match public_jwk_projection(&publication.jwk) {
        Ok(public) => public,
        Err(_) => return public_error(StatusCode::BAD_GATEWAY, "Published JWK is malformed."),
    };
    Json(json!({
        "ok": true,
        "service_id": service_id,
        "message": "Public key published to organization JWKS document",
        "jwk": public,
        "jwks_document": {
            "organization_id": scope.organization_id,
            "key_count": publication.key_count,
        },
        "published_at": chrono::Utc::now().to_rfc3339(),
    }))
    .into_response()
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicServiceDidPublicationRequest {
    #[serde(default)]
    did_id: Option<String>,
    #[serde(default)]
    org_slug: Option<String>,
    #[serde(default)]
    fragment: Option<String>,
}

async fn publish_public_service_did_vm(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
    body: Option<Json<PublicServiceDidPublicationRequest>>,
) -> Response {
    if let Err(error) = validate_service_scope(&scope.organization_id, None) {
        return error.into_response();
    }
    let body = body.map(|Json(body)| body).unwrap_or_default();
    let service =
        match registered_certificate_service(&state, &scope.organization_id, &service_id).await {
            Ok(service) => service,
            Err(error) => return error.into_response(),
        };
    let Some(documents) = state.document_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing document storage is unavailable.",
        );
    };
    let Some(public_domain) = state
        .public_domain
        .as_deref()
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
    else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Public DID authority is unavailable.",
        );
    };
    let (config, public_jwk) = match current_service_public_jwk(&service).await {
        Ok(material) => material,
        Err(error) => return error.into_response(),
    };
    let certificate = match checked_stored_service_certificate(
        documents,
        &scope.organization_id,
        &service_id,
        &service,
        &public_jwk,
    )
    .await
    {
        Ok(certificate) => certificate,
        Err(error) => return error.into_response(),
    };
    let org_slug = body.org_slug.or_else(|| {
        body.did_id
            .is_none()
            .then(|| scope.organization_id.to_lowercase())
    });
    let publication = match documents
        .publish_did(
            &scope.organization_id,
            &service_id,
            PublishDidRequest {
                jwk: public_jwk,
                public_domain: public_domain.to_owned(),
                did_id: body.did_id,
                org_slug,
                fragment: body.fragment,
                key_reference: config["key_reference"].as_str().map(str::to_owned),
                cert_pem: certificate
                    .as_ref()
                    .and_then(|value| value.get("cert_pem"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                cert_chain_pem: certificate
                    .as_ref()
                    .and_then(|value| value.get("cert_chain_pem"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                relationship: DidVerificationRelationship::AssertionMethod,
            },
        )
        .await
    {
        Ok(publication) => publication,
        Err(error) => return public_publication_error(error),
    };
    let public_document = match public_did_document(publication.document) {
        Ok(document) => document,
        Err(error) => return error.into_response(),
    };
    let method_id = publication.verification_method["id"].as_str();
    let Some(method) = public_document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .and_then(|methods| {
            methods
                .iter()
                .find(|method| method.get("id").and_then(Value::as_str) == method_id)
        })
        .cloned()
    else {
        return public_error(
            StatusCode::BAD_GATEWAY,
            "Published DID method is malformed.",
        );
    };
    let has_x5c = method
        .get("x5c")
        .and_then(Value::as_array)
        .is_some_and(|chain| !chain.is_empty());
    if let Err(error) = mark_service_publication_discovered(
        &state,
        &scope.organization_id,
        &service_id,
        &[
            ("did_verification_method_publish", json!(true)),
            ("last_did_publish_ok", json!(true)),
            ("has_x5c", json!(has_x5c)),
        ],
    )
    .await
    {
        return error.into_response();
    }
    Json(json!({
        "ok": true,
        "service_id": service_id,
        "message": "Verification method published to organization DID document",
        "verification_method": method,
        "did_document": {
            "id": public_document.get("id"),
            "verification_method_count": publication.verification_method_count,
        },
        "published_at": chrono::Utc::now().to_rfc3339(),
    }))
    .into_response()
}

async fn mark_service_publication_discovered(
    state: &AppState,
    organization_id: &str,
    service_id: &str,
    publication_capabilities: &[(&str, Value)],
) -> Result<(), PublicSigningError> {
    let store = state.registry_store.as_ref().ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        )
    })?;
    let mut registry = store.load(organization_id).await.map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        )
    })?;
    let service = registry
        .get_mut("services")
        .and_then(Value::as_array_mut)
        .and_then(|services| {
            services
                .iter_mut()
                .find(|service| service.get("id").and_then(Value::as_str) == Some(service_id))
        })
        .ok_or_else(|| public_failure(StatusCode::NOT_FOUND, "Signing service is unavailable."))?;
    let provider = service["provider"].clone();
    let capabilities = service
        .as_object_mut()
        .expect("registered service is an object")
        .entry("discovered_capabilities")
        .or_insert_with(|| json!({}));
    let capabilities = capabilities
        .as_object_mut()
        .expect("normalized discovered capabilities are an object");
    capabilities.insert("public_key_export".into(), json!(true));
    capabilities.insert("provider".into(), provider);
    for (name, value) in publication_capabilities {
        capabilities.insert((*name).into(), value.clone());
    }
    service["updated_at"] = json!(chrono::Utc::now().to_rfc3339());
    store.save(organization_id, &registry).await.map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        )
    })?;
    Ok(())
}

fn verify_service_key_result(
    service_id: &str,
    service: &Value,
    public_jwk: &Value,
    verified_at: String,
) -> Value {
    let key_present = public_jwk.as_object().is_some_and(|jwk| !jwk.is_empty());
    let required_fields: &[&str] = match public_jwk.get("kty").and_then(Value::as_str) {
        Some("EC") => &["crv", "x", "y"],
        Some("RSA") => &["n", "e"],
        Some("OKP") => &["crv", "x"],
        _ => &[],
    };
    let required_fields_present = !required_fields.is_empty()
        && required_fields.iter().all(|field| {
            public_jwk
                .get(*field)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
        });
    let compatible_algorithms: &[&str] = match (
        public_jwk.get("kty").and_then(Value::as_str),
        public_jwk.get("crv").and_then(Value::as_str),
    ) {
        (Some("EC"), Some("P-256")) => &["ES256"],
        (Some("EC"), Some("P-384")) => &["ES384"],
        (Some("EC"), Some("P-521")) => &["ES512"],
        (Some("RSA"), _) => &["RS256", "PS256"],
        (Some("OKP"), Some("Ed25519")) => &["EdDSA"],
        _ => &[],
    };
    let advertised = service.get("algorithms").and_then(Value::as_array);
    let declared = public_jwk.get("alg").and_then(Value::as_str);
    let algorithm_supported = compatible_algorithms.iter().any(|algorithm| {
        advertised.is_some_and(|algorithms| {
            algorithms
                .iter()
                .any(|candidate| candidate.as_str() == Some(*algorithm))
        }) && declared.is_none_or(|value| value == *algorithm)
    });
    json!({
        "service_id": service_id,
        "key_valid": key_present && required_fields_present && algorithm_supported,
        "checks": {
            "key_present": key_present,
            "required_fields_present": required_fields_present,
            "algorithm_supported": algorithm_supported,
        },
        "verified_at": verified_at,
    })
}

async fn get_public_service_certificate(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
) -> Response {
    if let Err(error) = validate_service_scope(&scope.organization_id, None) {
        return error.into_response();
    }
    let service =
        match registered_certificate_service(&state, &scope.organization_id, &service_id).await {
            Ok(service) => service,
            Err(error) => return error.into_response(),
        };
    let Some(store) = state.document_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Certificate storage is unavailable.",
        );
    };
    let overrides = match store.certificate_overrides(&scope.organization_id).await {
        Ok(overrides) => overrides,
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Certificate storage is unavailable.",
            )
        }
    };
    let certificate = selected_service_certificate(&service, &overrides, &service_id);
    let Some(certificate) = certificate else {
        return public_error(
            StatusCode::NOT_FOUND,
            &format!("No certificate stored for service '{service_id}'."),
        );
    };
    Json(json!({
        "service_id": service_id,
        "cert_pem": certificate.get("cert_pem"),
        "cert_chain_pem": certificate.get("cert_chain_pem").cloned().unwrap_or_else(|| json!("")),
        "cert_expires_at": certificate.get("cert_expires_at"),
    }))
    .into_response()
}

fn selected_service_certificate<'a>(
    service: &'a Value,
    overrides: &'a Value,
    service_id: &str,
) -> Option<&'a Value> {
    let certificate = overrides
        .get("services")
        .and_then(|services| services.get(service_id))
        .filter(|attachment| attachment.get("cert_pem").and_then(Value::as_str).is_some())
        .unwrap_or(service);
    certificate
        .get("cert_pem")
        .and_then(Value::as_str)
        .filter(|pem| !pem.is_empty())
        .map(|_| certificate)
}

async fn public_service_mdoc_x5c(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
) -> Response {
    if let Err(error) = validate_service_scope(&scope.organization_id, None) {
        return error.into_response();
    }
    let service =
        match registered_certificate_service(&state, &scope.organization_id, &service_id).await {
            Ok(service) => service,
            Err(error) => return error.into_response(),
        };
    let Some(store) = state.document_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Certificate storage is unavailable.",
        );
    };
    let overrides = match store.certificate_overrides(&scope.organization_id).await {
        Ok(overrides) => overrides,
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Certificate storage is unavailable.",
            )
        }
    };
    let Some(certificate) = selected_service_certificate(&service, &overrides, &service_id) else {
        return public_error(
            StatusCode::NOT_FOUND,
            &format!("No certificate chain stored for service '{service_id}'."),
        );
    };
    let public_jwk = match current_service_public_jwk(&service).await {
        Ok((_, jwk)) => jwk,
        Err(error) => return error.into_response(),
    };
    match checked_service_x5c(certificate, &public_jwk, &service_id) {
        Ok(response) => Json(response).into_response(),
        Err(error) => error.into_response(),
    }
}

fn checked_service_x5c(
    certificate: &Value,
    public_jwk: &Value,
    service_id: &str,
) -> Result<Value, PublicSigningError> {
    let inspected = documents::inspect_certificate(&InspectCertificateRequest {
        cert_pem: certificate["cert_pem"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        cert_chain_pem: certificate
            .get("cert_chain_pem")
            .and_then(Value::as_str)
            .map(str::to_owned),
        expected_public_jwk: Some(public_jwk.clone()),
    })
    .map_err(|_| {
        public_failure(
            StatusCode::BAD_GATEWAY,
            "Stored service certificate is malformed.",
        )
    })?;
    if inspected.public_key_matches != Some(true) {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Stored service certificate does not match its current KMS key.",
        ));
    }
    if inspected.x5c.is_empty() {
        return Err(public_failure(
            StatusCode::NOT_FOUND,
            &format!("No certificate chain stored for service '{service_id}'."),
        ));
    }
    let chain_length = inspected.x5c.len();
    Ok(json!({
        "service_id": service_id,
        "x5c": inspected.x5c,
        "mdoc_cose_header_hints": {"x5chain": true, "x5c_length": chain_length},
    }))
}

async fn store_public_service_certificate(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
    Json(input): Json<ServiceCertificateRequest>,
) -> Response {
    if let Err(error) =
        validate_service_scope(&scope.organization_id, input.organization_id.as_deref())
    {
        return error.into_response();
    }
    if input.cert_pem.trim().is_empty() {
        return public_error(StatusCode::BAD_REQUEST, "cert_pem is required.");
    }
    let service =
        match registered_certificate_service(&state, &scope.organization_id, &service_id).await {
            Ok(service) => service,
            Err(error) => return error.into_response(),
        };
    let public_jwk = match current_service_public_jwk(&service).await {
        Ok((_, jwk)) => jwk,
        Err(error) => return error.into_response(),
    };
    let Some(store) = state.document_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Certificate storage is unavailable.",
        );
    };
    let attachment = match store
        .store_certificate(
            &scope.organization_id,
            &service_id,
            InspectCertificateRequest {
                cert_pem: input.cert_pem,
                cert_chain_pem: input.cert_chain_pem,
                expected_public_jwk: Some(public_jwk),
            },
        )
        .await
    {
        Ok(attachment) => attachment,
        Err(error) => return document_error(error).into_response(),
    };
    let certificate = json!({
        "cert_pem": attachment.cert_pem,
        "cert_chain_pem": attachment.cert_chain_pem,
        "cert_expires_at": attachment.cert_expires_at,
    });
    let display_pem = attachment.cert_pem.chars().take(100).collect::<String>();
    Json(json!({
        "ok": true,
        "service_id": service_id,
        "cert_pem": if attachment.cert_pem.chars().count() > 100 { format!("{display_pem}...") } else { display_pem },
        "cert_expires_at": attachment.cert_expires_at,
        "stored_at": attachment.updated_at,
        "service": service_certificate_projection(&service, &certificate),
    }))
    .into_response()
}

async fn generate_public_service_csr(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
    Json(input): Json<ServiceCsrRequest>,
) -> Response {
    if let Err(error) =
        validate_service_scope(&scope.organization_id, input.organization_id.as_deref())
    {
        return error.into_response();
    }
    let service =
        match registered_certificate_service(&state, &scope.organization_id, &service_id).await {
            Ok(service) => service,
            Err(error) => return error.into_response(),
        };
    let (mut service_config, public_jwk) = match current_service_public_jwk(&service).await {
        Ok(result) => result,
        Err(error) => return error.into_response(),
    };
    let algorithm = match public_jwk.get("crv").and_then(Value::as_str) {
        Some("P-256") => "ES256",
        Some("P-384") => "ES384",
        Some("P-521") => "ES512",
        _ => {
            return public_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "The service KMS key cannot sign an X.509 CSR.",
            )
        }
    };
    let csr = match certificate_csr::prepare(
        &public_jwk,
        algorithm,
        &CsrSubject {
            country: &input.country,
            organization: &input.organization,
            common_name: &input.common_name,
        },
    ) {
        Ok(csr) => csr,
        Err(error) => return public_error(StatusCode::UNPROCESSABLE_ENTITY, &error.to_string()),
    };
    service_config["algorithm"] = json!(algorithm);
    let signed = match kms::sign(SignRequest {
        service_config,
        payload_b64: URL_SAFE_NO_PAD.encode(csr.signing_bytes()),
    })
    .await
    {
        Ok(signed) => signed,
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "The service KMS could not sign the CSR.",
            )
        }
    };
    if signed.signature_encoding != "der" {
        return public_error(
            StatusCode::BAD_GATEWAY,
            "The service KMS returned an incompatible CSR signature.",
        );
    }
    let signature = match URL_SAFE_NO_PAD.decode(signed.signature_b64) {
        Ok(signature) => signature,
        Err(_) => {
            return public_error(
                StatusCode::BAD_GATEWAY,
                "The service KMS returned an invalid CSR signature.",
            )
        }
    };
    let csr_pem = match csr.finish(&signature) {
        Ok(pem) => pem,
        Err(_) => {
            return public_error(
                StatusCode::BAD_GATEWAY,
                "The service KMS CSR signature did not verify.",
            )
        }
    };
    Json(json!({
        "ok": true,
        "service_id": service_id,
        "csr_pem": csr_pem,
        "generated_at": chrono::Utc::now().to_rfc3339(),
    }))
    .into_response()
}

async fn enroll_public_csca_certificate(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    Json(input): Json<CscaCertificateEnrollment>,
) -> Response {
    let identity = input.identity();
    if let Err(error) = validate_identity_scope(&scope.organization_id, &identity) {
        return error.into_response();
    }
    if state.csca_lifecycle_store.is_none() {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "CSCA lifecycle storage is unavailable.",
        );
    }
    let profile = match one_matching_profile(&state, &scope.organization_id, &identity).await {
        Ok(profile) => profile,
        Err(error) => return error.into_response(),
    };
    let Some(compatibility) = state.compatibility.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity service is unavailable.",
        );
    };
    let resolved = match compatibility
        .resolve_issuer_did(&ResolveIssuerDidRequest {
            organization_id: scope.organization_id.clone(),
            issuer_did: input.issuer_did.clone(),
            verification_method_id: None,
            credential_format: Some(input.credential_format.clone()),
            key_purpose: Some("csca".into()),
            algorithm: Some(canonical_algorithm(&input.algorithm)),
        })
        .await
    {
        Ok(resolved) => resolved,
        Err(error) => return error.into_response(),
    };
    let provider_public_jwk = match compatibility
        .provider_public_key_for_profile(&scope.organization_id, &profile)
        .await
    {
        Ok(jwk) => jwk,
        Err(error) => return error.into_response(),
    };
    let request = match managed_csca_import(&input, &profile, &resolved, &provider_public_jwk) {
        Ok(request) => request,
        Err(error) => return error.into_response(),
    };
    let now = chrono::Utc::now();
    let mut document = match load_csca_lifecycle(&state, &scope.organization_id, now).await {
        Ok(document) => document,
        Err(error) => return error.into_response(),
    };
    let view = match document.import(&input.certificate_id, request, now) {
        Ok(view) => view,
        Err(error) => return csca_lifecycle_error(error).into_response(),
    };
    if let Err(error) = save_csca_lifecycle(&state, &document).await {
        return error.into_response();
    }
    Json(json!({
        "certificate_id": view.certificate.certificate_id,
        "subject": view.certificate.subject,
        "not_after": view.certificate.not_after,
        "status": view.status,
    }))
    .into_response()
}

async fn delete_public_issuer_identity(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    Json(input): Json<IssuerIdentityRequest>,
) -> Response {
    if let Err(error) = validate_identity_scope(&scope.organization_id, &input) {
        return error.into_response();
    }
    if let Err(error) = validate_identity_operation_fields(&input, false, false) {
        return error.into_response();
    }
    let profile = match one_matching_profile(&state, &scope.organization_id, &input).await {
        Ok(profile) => profile,
        Err(error) => return error.into_response(),
    };
    let Some(profile_id) = profile.get("id").and_then(Value::as_str) else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity storage is malformed.",
        );
    };
    let Some(store) = state.profile_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity storage is unavailable.",
        );
    };
    match store.delete(&scope.organization_id, profile_id).await {
        Ok(()) => Json(json!({"deleted": identity_projection(&profile)})).into_response(),
        Err(error) => public_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()),
    }
}

fn public_config_document(state: &AppState, registry: Value) -> Value {
    let services = registry
        .get("services")
        .and_then(Value::as_array)
        .map(|services| {
            services
                .iter()
                .map(public_service_config)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "hsm_enabled": !services.is_empty(),
        "hsm_settings": {},
        "vault_enabled": false,
        "vault_settings": {},
        "provider_metadata": {"provider": "openbao", "status": "configured", "managed_by": "Marty service stack"},
        "domain_config": {"public_domain": state.public_domain},
        "supports_native_key_management": true,
        "registration_mode": "managed-or-external",
        "default_service_id": registry.get("default_service_id").cloned().unwrap_or(Value::Null),
        "format_defaults": registry.get("format_defaults").cloned().unwrap_or_else(|| json!({})),
        "type_defaults": registry.get("type_defaults").cloned().unwrap_or_else(|| json!({})),
        "services": services,
        "key_reference_purposes": registry.get("key_reference_purposes").cloned().unwrap_or_else(|| json!({})),
        "service_type_catalog": registry::service_catalog(),
    })
}

fn public_service_config(service: &Value) -> Value {
    let mut public = service.clone();
    if let Some(fields) = public.as_object_mut() {
        let configured = fields
            .get("auth_reference")
            .and_then(Value::as_str)
            .is_some_and(|reference| !reference.is_empty());
        fields.insert("auth_reference".into(), json!(""));
        fields.insert("auth_configured".into(), json!(configured));
    }
    public
}

// The console sends the complete visible service list for default/removal changes.
// Preserve a hidden credential only when its service and connection binding are
// unchanged. An explicit null clears it; changing the endpoint or auth mode
// must never silently forward the old credential to another destination.
fn preserve_unchanged_auth_references(request: &mut Value, existing: &Value) {
    const BINDING: [&str; 8] = [
        "provider",
        "service_type",
        "protocol",
        "endpoint",
        "region",
        "auth_mode",
        "mount",
        "namespace",
    ];
    let Some(requested) = request.get_mut("services").and_then(Value::as_array_mut) else {
        return;
    };
    let Some(stored) = existing.get("services").and_then(Value::as_array) else {
        return;
    };
    for service in requested {
        let Some(id) = service.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(previous) = stored
            .iter()
            .find(|candidate| candidate.get("id").and_then(Value::as_str) == Some(id))
        else {
            continue;
        };
        let Some(fields) = service.as_object_mut() else {
            continue;
        };
        if fields.get("auth_reference").is_some_and(|value| {
            value.is_null() || value.as_str().is_some_and(|text| !text.is_empty())
        }) {
            continue;
        }
        if BINDING
            .iter()
            .any(|field| fields.get(*field) != previous.get(*field))
        {
            continue;
        }
        if let Some(reference) = previous.get("auth_reference") {
            fields.insert("auth_reference".into(), reference.clone());
        }
    }
}

fn identity_selector(input: &IssuerIdentityRequest) -> FindProfilesRequest {
    identity_selector_with_publication(input, true)
}

fn identity_selector_with_publication(
    input: &IssuerIdentityRequest,
    require_public_identity: bool,
) -> FindProfilesRequest {
    FindProfilesRequest {
        active_only: true,
        issuer_did: Some(input.issuer_did.trim().to_owned()),
        key_purpose: Some(input.key_purpose.trim().to_owned()),
        credential_format: Some(input.credential_format.trim().to_ascii_uppercase()),
        algorithm: Some(canonical_algorithm(&input.algorithm)),
        require_signing_service: true,
        require_signing_key_reference: true,
        require_public_identity,
        ..FindProfilesRequest::default()
    }
}

async fn one_matching_profile(
    state: &AppState,
    organization_id: &str,
    input: &IssuerIdentityRequest,
) -> Result<Value, PublicSigningError> {
    let Some(store) = state.profile_store.as_ref() else {
        return Err(public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity storage is unavailable.",
        ));
    };
    match store.find(organization_id, identity_selector(input)).await {
        Ok(matches) if matches.len() == 1 => Ok(matches.into_iter().next().expect("one match")),
        Ok(matches) if matches.is_empty() => Err(public_failure(
            StatusCode::NOT_FOUND,
            "No active issuer identity matches the requested tuple.",
        )),
        Ok(_) => Err(public_failure(
            StatusCode::CONFLICT,
            "Issuer DID resolution is ambiguous for the requested identity tuple.",
        )),
        Err(error) => Err(public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            &error.to_string(),
        )),
    }
}

fn projected_identities(profiles: Vec<Value>) -> Result<Vec<Value>, PublicSigningError> {
    let identities = profiles.iter().map(identity_projection).collect::<Vec<_>>();
    let mut unique = std::collections::BTreeSet::new();
    for identity in &identities {
        let tuple = serde_json::to_string(identity).unwrap_or_default();
        if !unique.insert(tuple) {
            return Err(public_failure(
                StatusCode::CONFLICT,
                "Issuer DID resolution is ambiguous for the requested identity tuple.",
            ));
        }
    }
    Ok(identities)
}

fn identity_projection(profile: &Value) -> Value {
    json!({
        "issuer_did": profile.get("issuer_did").cloned().unwrap_or(Value::Null),
        "key_purpose": profile.get("key_purpose").cloned().unwrap_or_else(|| Value::String("vc_jwt_issuer".into())),
        "credential_format": profile.get("credential_format").cloned().unwrap_or(Value::Null),
        "algorithm": profile.get("algorithm").and_then(Value::as_str).map(canonical_algorithm).unwrap_or_else(|| "ES256".into()),
        "status": "active"
    })
}

fn validate_identity_scope(
    organization_id: &str,
    input: &IssuerIdentityRequest,
) -> Result<(), PublicSigningError> {
    if input
        .organization_id
        .as_deref()
        .is_some_and(|requested| requested.trim() != organization_id)
    {
        return Err(public_failure(
            StatusCode::FORBIDDEN,
            "organization_id does not match the authorized organization context.",
        ));
    }
    if organization_id.trim().is_empty()
        || input.issuer_did.trim().is_empty()
        || input.key_purpose.trim().is_empty()
        || input.credential_format.trim().is_empty()
        || input.algorithm.trim().is_empty()
    {
        return Err(public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "A complete issuer identity tuple is required.",
        ));
    }
    Ok(())
}

fn local_managed_did(public_domain: Option<&str>, issuer_did: &str) -> bool {
    public_domain
        .map(str::trim)
        .filter(|domain| !domain.is_empty())
        .is_some_and(|domain| issuer_did.starts_with(&format!("did:web:{domain}:orgs:")))
}

fn validate_identity_operation_fields(
    input: &IssuerIdentityRequest,
    allow_attestation_policy: bool,
    allow_certificate: bool,
) -> Result<(), PublicSigningError> {
    if !allow_attestation_policy && input.key_attestation_policy.is_some() {
        return Err(public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "key_attestation_policy is not valid for this issuer identity operation.",
        ));
    }
    if !allow_certificate && (input.cert_pem.is_some() || input.cert_chain_pem.is_some()) {
        return Err(public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Certificate fields are not valid for this issuer identity operation.",
        ));
    }
    Ok(())
}

fn managed_key_reference(organization_id: &str, input: &IssuerIdentityRequest) -> String {
    let tuple = format!(
        "{organization_id}|{}|{}|{}|{}",
        input.issuer_did, input.key_purpose, input.credential_format, input.algorithm
    );
    let token = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, tuple.as_bytes())
        .simple()
        .to_string();
    let prefix = match input.key_purpose.as_str() {
        "oid4vp_request_signing" => "oid4vp-verifier-",
        "lti_tool_signing" => "lti-tool-",
        "mdoc_dsc" | "x509_doc_signer" | "vdsnc_signing" | "csca" => "cred-dsc-",
        _ => "cred-issuer-",
    };
    format!(
        "{prefix}{}-{}",
        &token[..20],
        input.algorithm.to_ascii_lowercase()
    )
}

fn cleaned(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn canonical_algorithm(value: &str) -> String {
    if value.trim().eq_ignore_ascii_case("eddsa") {
        "EdDSA".into()
    } else {
        value.trim().to_ascii_uppercase()
    }
}

fn public_error(status: StatusCode, detail: &str) -> Response {
    (status, Json(json!({"detail": detail}))).into_response()
}

fn public_failure(status: StatusCode, detail: &str) -> PublicSigningError {
    PublicSigningError {
        status,
        detail: detail.into(),
    }
}

async fn issuer_context(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IssuerContextRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(&state, &headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service.issuer_context(&request).await.map(Json)
}

async fn resolve_issuer_did(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ResolveIssuerDidRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(&state, &headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service.resolve_issuer_did(&request).await.map(Json)
}

async fn profile_identity(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ProfileIdentityRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    profile_identity_response(&state, &headers, &request, &profile_id, false).await
}

async fn profile_public_identity(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ProfileIdentityRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    profile_identity_response(&state, &headers, &request, &profile_id, true).await
}

async fn profile_identity_response(
    state: &AppState,
    headers: &HeaderMap,
    request: &ProfileIdentityRequest,
    profile_id: &str,
    public_projection: bool,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(state, headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service
        .profile_identity(&request.organization_id, profile_id, public_projection)
        .await
        .map(Json)
}

async fn service_sign(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ServiceSignRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(&state, &headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service
        .sign_with_service(&service_id, &request)
        .await
        .map(Json)
}

async fn issuer_did_sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IssuerDidSignRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(&state, &headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service.sign_with_issuer_did(&request).await.map(Json)
}

async fn create_compatibility_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProfileWriteRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(&state, &headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service.create_profile(&request).await.map(Json)
}

async fn update_compatibility_profile(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ProfileWriteRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(&state, &headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service
        .update_profile(&profile_id, &request)
        .await
        .map(Json)
}

async fn attach_compatibility_certificate(
    State(state): State<AppState>,
    Path(profile_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ProfileWriteRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    authorize_internal(&state, &headers).map_err(|_| CompatibilityError::Unauthorized)?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    service
        .attach_profile_certificate(&profile_id, &request)
        .await
        .map(Json)
}

async fn wrap_flow_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<WrapRequest>,
) -> Result<Json<serde_json::Value>, FlowEnvelopeError> {
    authorize_internal(&state, &headers).map_err(|_| FlowEnvelopeError::Unauthorized)?;
    let provider = state
        .flow_envelopes
        .as_ref()
        .ok_or(FlowEnvelopeError::Unavailable)?;
    provider.wrap(request).await.map(Json)
}

async fn unwrap_flow_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UnwrapRequest>,
) -> Result<Json<serde_json::Value>, FlowEnvelopeError> {
    authorize_internal(&state, &headers).map_err(|_| FlowEnvelopeError::Unauthorized)?;
    let provider = state
        .flow_envelopes
        .as_ref()
        .ok_or(FlowEnvelopeError::Unavailable)?;
    provider.unwrap(request).await.map(Json)
}

async fn encrypt_passport_artifact_chunk(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<EncryptChunkRequest>,
) -> Result<Json<Value>, ArtifactEnvelopeError> {
    authorize_internal(&state, &headers).map_err(|_| ArtifactEnvelopeError::Unauthorized)?;
    let provider = state
        .flow_envelopes
        .as_ref()
        .ok_or(ArtifactEnvelopeError::Unavailable)?;
    passport_artifact_envelope::encrypt_chunk(provider, &organization_id, request)
        .await
        .map(Json)
}

async fn decrypt_passport_artifact_chunk(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<DecryptChunkRequest>,
) -> Result<Json<Value>, ArtifactEnvelopeError> {
    authorize_internal(&state, &headers).map_err(|_| ArtifactEnvelopeError::Unauthorized)?;
    let provider = state
        .flow_envelopes
        .as_ref()
        .ok_or(ArtifactEnvelopeError::Unavailable)?;
    passport_artifact_envelope::decrypt_chunk(provider, &organization_id, request)
        .await
        .map(Json)
}

async fn kms_sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SignRequest>,
) -> Result<Json<kms::SignResponse>, kms::KmsError> {
    authorize_internal(&state, &headers)?;
    Ok(Json(kms::sign(request).await?))
}

async fn kms_public_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProviderRequest>,
) -> Result<Json<serde_json::Value>, kms::KmsError> {
    authorize_internal(&state, &headers)?;
    Ok(Json(kms::public_key(request).await?))
}

async fn kms_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProviderRequest>,
) -> Result<Json<kms::CapabilityResult>, kms::KmsError> {
    authorize_internal(&state, &headers)?;
    Ok(Json(kms::verify(request).await?))
}

async fn validate_service(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ValidationRequest>,
) -> Result<Json<validation::ValidationResult>, kms::KmsError> {
    authorize_internal(&state, &headers)?;
    Ok(Json(validation::validate(request).await))
}

type RegistryHttpError = (StatusCode, Json<serde_json::Value>);

async fn registry_catalog(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, RegistryHttpError> {
    authorize_registry(&state, &headers)?;
    Ok(Json(
        serde_json::json!({"service_types": registry::service_catalog()}),
    ))
}

async fn normalize_registry_service(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NormalizeServiceRequest>,
) -> Result<Json<NormalizeServiceResponse>, RegistryHttpError> {
    authorize_registry(&state, &headers)?;
    registry::normalize_service(request)
        .map(Json)
        .map_err(registry_error)
}

async fn normalize_registry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<NormalizeRegistryRequest>,
) -> Result<Json<NormalizeRegistryResponse>, RegistryHttpError> {
    authorize_registry(&state, &headers)?;
    registry::normalize_registry(request)
        .map(Json)
        .map_err(registry_error)
}

async fn resolve_registry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ResolveRequest>,
) -> Result<Json<ResolveResponse>, RegistryHttpError> {
    authorize_registry(&state, &headers)?;
    registry::resolve(request).map(Json).map_err(registry_error)
}

async fn load_registry(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, RegistryHttpError> {
    authorize_registry(&state, &headers)?;
    let store = state
        .registry_store
        .as_ref()
        .ok_or_else(registry_unavailable)?;
    store
        .load(&organization_id)
        .await
        .map(Json)
        .map_err(registry_error)
}

async fn save_registry(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<SaveRegistryRequest>,
) -> Result<Json<serde_json::Value>, RegistryHttpError> {
    authorize_registry(&state, &headers)?;
    let store = state
        .registry_store
        .as_ref()
        .ok_or_else(registry_unavailable)?;
    store
        .save(&organization_id, &request.registry)
        .await
        .map(Json)
        .map_err(registry_error)
}

async fn bind_registry_profile(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<BindProfileRequest>,
) -> Result<Json<serde_json::Value>, RegistryHttpError> {
    authorize_registry(&state, &headers)?;
    let store = state
        .registry_store
        .as_ref()
        .ok_or_else(registry_unavailable)?;
    store
        .bind_profile(&organization_id, &request.profile)
        .await
        .map(Json)
        .map_err(registry_error)
}

fn authorize_registry(state: &AppState, headers: &HeaderMap) -> Result<(), RegistryHttpError> {
    authorize_internal(state, headers).map_err(|error| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"detail": error.to_string()})),
        )
    })
}

fn registry_error(error: registry::RegistryError) -> RegistryHttpError {
    let status = match error {
        registry::RegistryError::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
        registry::RegistryError::Storage(_) => StatusCode::SERVICE_UNAVAILABLE,
        registry::RegistryError::Corrupt(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(serde_json::json!({"detail": error.to_string()})),
    )
}

fn registry_unavailable() -> RegistryHttpError {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"detail": "signing registry storage is unavailable"})),
    )
}

type DocumentHttpError = (StatusCode, Json<serde_json::Value>);

async fn inspect_certificate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<InspectCertificateRequest>,
) -> Result<Json<InspectCertificateResponse>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    documents::inspect_certificate(&request)
        .map(Json)
        .map_err(document_error)
}

async fn certificate_alerts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CertificateAlertsRequest>,
) -> Result<Json<CertificateAlertsResponse>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    documents::certificate_alerts(request)
        .map(Json)
        .map_err(document_error)
}

async fn certificate_overrides(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .certificate_overrides(&organization_id)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn store_certificate(
    State(state): State<AppState>,
    Path((organization_id, service_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<InspectCertificateRequest>,
) -> Result<Json<StoredCertificate>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .store_certificate(&organization_id, &service_id, request)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn list_csca_certificates(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    Query(query): Query<ListCscaCertificatesQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<CscaCertificateView>>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    let now = chrono::Utc::now();
    let document = load_csca_lifecycle(&state, &organization_id, now).await?;
    document
        .list(&query, now)
        .map(Json)
        .map_err(csca_lifecycle_error)
}

async fn active_csca_trust_anchors(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Vec<CscaCertificateDataResponse>>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    let now = chrono::Utc::now();
    load_csca_lifecycle(&state, &organization_id, now)
        .await?
        .active_certificate_data(now)
        .map(Json)
        .map_err(csca_lifecycle_error)
}

async fn import_csca_certificate(
    State(state): State<AppState>,
    Path((organization_id, certificate_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<ImportCscaCertificateRequest>,
) -> Result<Json<CscaCertificateView>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    let now = chrono::Utc::now();
    let mut document = load_csca_lifecycle(&state, &organization_id, now).await?;
    let view = document
        .import(&certificate_id, request, now)
        .map_err(csca_lifecycle_error)?;
    save_csca_lifecycle(&state, &document).await?;
    Ok(Json(view))
}

async fn get_csca_certificate(
    State(state): State<AppState>,
    Path((organization_id, certificate_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<CscaCertificateView>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    let now = chrono::Utc::now();
    let document = load_csca_lifecycle(&state, &organization_id, now).await?;
    document
        .get(&certificate_id, now)
        .map(Json)
        .map_err(csca_lifecycle_error)
}

async fn get_csca_certificate_data(
    State(state): State<AppState>,
    Path((organization_id, certificate_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<CscaCertificateDataResponse>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    let now = chrono::Utc::now();
    let document = load_csca_lifecycle(&state, &organization_id, now).await?;
    let certificate_data = document
        .certificate_data(&certificate_id, now)
        .map_err(csca_lifecycle_error)?
        .to_string();
    Ok(Json(CscaCertificateDataResponse {
        certificate_id,
        certificate_data,
        status: csca_lifecycle::CscaCertificateStatus::Valid,
    }))
}

async fn revoke_csca_certificate(
    State(state): State<AppState>,
    Path((organization_id, certificate_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<RevokeCscaCertificateRequest>,
) -> Result<Json<CscaCertificateView>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    let now = chrono::Utc::now();
    let mut document = load_csca_lifecycle(&state, &organization_id, now).await?;
    let prior_revision = document.revision;
    let view = document
        .revoke(&certificate_id, &request.reason, now)
        .map_err(csca_lifecycle_error)?;
    if document.revision != prior_revision {
        save_csca_lifecycle(&state, &document).await?;
    }
    Ok(Json(view))
}

async fn renew_csca_certificate(
    State(state): State<AppState>,
    Path((organization_id, certificate_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<RenewCscaCertificateRequest>,
) -> Result<Json<CscaCertificateView>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    let now = chrono::Utc::now();
    let mut document = load_csca_lifecycle(&state, &organization_id, now).await?;
    let replacement_id = request.replacement_certificate_id.clone();
    let reuse_key = request.reuse_key;
    let view = document
        .renew(
            &certificate_id,
            &replacement_id,
            request.into_import(),
            reuse_key,
            now,
        )
        .map_err(csca_lifecycle_error)?;
    save_csca_lifecycle(&state, &document).await?;
    Ok(Json(view))
}

async fn expiring_csca_certificates(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ExpiringCscaCertificatesRequest>,
) -> Result<Json<Vec<CscaCertificateView>>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    let now = chrono::Utc::now();
    let document = load_csca_lifecycle(&state, &organization_id, now).await?;
    document
        .expiring(request.days_threshold, now)
        .map(Json)
        .map_err(csca_lifecycle_error)
}

async fn list_csca_outbox(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    Query(query): Query<ListCscaOutboxQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<CscaOutboxEvent>>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    let document = load_csca_lifecycle(&state, &organization_id, chrono::Utc::now()).await?;
    document
        .pending_outbox(&query)
        .map(Json)
        .map_err(csca_lifecycle_error)
}

async fn acknowledge_csca_outbox(
    State(state): State<AppState>,
    Path((organization_id, event_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<CscaOutboxEvent>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    let now = chrono::Utc::now();
    let mut document = load_csca_lifecycle(&state, &organization_id, now).await?;
    let prior_revision = document.revision;
    let event = document
        .acknowledge_outbox(&event_id, now)
        .map_err(csca_lifecycle_error)?;
    if document.revision != prior_revision {
        save_csca_lifecycle(&state, &document).await?;
    }
    Ok(Json(event))
}

async fn load_jwks(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .jwks(&organization_id)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn publish_jwk(
    State(state): State<AppState>,
    Path((organization_id, service_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<PublishJwkRequest>,
) -> Result<Json<PublishJwkResponse>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .publish_jwk(&organization_id, &service_id, request)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn update_jwk(
    State(state): State<AppState>,
    Path((organization_id, key_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<UpdateJwkRequest>,
) -> Result<Json<UpdateJwkResponse>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .update_jwk(&organization_id, &key_id, request)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn delete_jwk(
    State(state): State<AppState>,
    Path((organization_id, key_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<DeleteJwkResponse>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .delete_jwk(&organization_id, &key_id)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn load_did(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<LoadDidRequest>,
) -> Result<Json<LoadDidResponse>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .load_did(&organization_id, request)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn publish_did(
    State(state): State<AppState>,
    Path((organization_id, service_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<PublishDidRequest>,
) -> Result<Json<PublishDidResponse>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    document_store(&state)?
        .publish_did(&organization_id, &service_id, request)
        .await
        .map(Json)
        .map_err(document_error)
}

async fn resolve_did_slug(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, DocumentHttpError> {
    authorize_documents(&state, &headers)?;
    let organization_id = document_store(&state)?
        .resolve_slug(&slug)
        .await
        .map_err(document_error)?;
    Ok(Json(
        serde_json::json!({"organization_id": organization_id}),
    ))
}

fn document_store(state: &AppState) -> Result<&DocumentStore, DocumentHttpError> {
    state.document_store.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"detail": "signing document storage is unavailable"})),
        )
    })
}

fn csca_lifecycle_store(state: &AppState) -> Result<&CscaLifecycleStore, DocumentHttpError> {
    state.csca_lifecycle_store.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"detail": "CSCA lifecycle storage is unavailable"})),
        )
    })
}

async fn load_csca_lifecycle(
    state: &AppState,
    organization_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<CscaLifecycleDocument, DocumentHttpError> {
    csca_lifecycle_store(state)?
        .load(organization_id, now)
        .await
        .map_err(csca_lifecycle_error)
}

async fn save_csca_lifecycle(
    state: &AppState,
    document: &CscaLifecycleDocument,
) -> Result<(), DocumentHttpError> {
    csca_lifecycle_store(state)?
        .save(document)
        .await
        .map_err(csca_lifecycle_error)
}

fn authorize_documents(state: &AppState, headers: &HeaderMap) -> Result<(), DocumentHttpError> {
    authorize_internal(state, headers).map_err(|error| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"detail": error.to_string()})),
        )
    })
}

fn document_error(error: documents::DocumentError) -> DocumentHttpError {
    let status = match &error {
        documents::DocumentError::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
        documents::DocumentError::Conflict(_) => StatusCode::CONFLICT,
        documents::DocumentError::NotFound(_) => StatusCode::NOT_FOUND,
        documents::DocumentError::Storage(_) => StatusCode::SERVICE_UNAVAILABLE,
        documents::DocumentError::Corrupt(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(serde_json::json!({"detail": error.to_string()})),
    )
}

fn csca_lifecycle_error(error: CscaLifecycleError) -> DocumentHttpError {
    let status = match &error {
        CscaLifecycleError::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
        CscaLifecycleError::Conflict(_) | CscaLifecycleError::ConcurrentModification => {
            StatusCode::CONFLICT
        }
        CscaLifecycleError::NotFound(_) | CscaLifecycleError::OutboxEventNotFound(_) => {
            StatusCode::NOT_FOUND
        }
        CscaLifecycleError::Revoked(_) | CscaLifecycleError::Expired(_) => StatusCode::GONE,
        CscaLifecycleError::NotYetValid(_) => StatusCode::TOO_EARLY,
        CscaLifecycleError::Storage(_) => StatusCode::SERVICE_UNAVAILABLE,
        CscaLifecycleError::Corrupt(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(serde_json::json!({"detail": error.to_string()})),
    )
}

type ProfileHttpError = (StatusCode, Json<serde_json::Value>);

async fn normalize_profile(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<NormalizeProfileRequest>,
) -> Result<Json<serde_json::Value>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profiles::normalize_profile(&organization_id, request)
        .map(|profile| Json(serde_json::json!({"profile": profile})))
        .map_err(profile_error)
}

async fn validate_profile_binding(
    State(state): State<AppState>,
    Path(_organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ValidateBindingRequest>,
) -> Result<Json<serde_json::Value>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profiles::validate_binding(&request).map_err(profile_error)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn resolve_profile_custody_format(
    State(state): State<AppState>,
    Path(_organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CustodyFormatRequest>,
) -> Result<Json<CustodyFormatResponse>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profiles::custody_format(&request)
        .map(Json)
        .map_err(profile_error)
}

async fn list_profiles(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profile_store(&state)?
        .list(&organization_id)
        .await
        .map(Json)
        .map_err(profile_error)
}

async fn get_profile(
    State(state): State<AppState>,
    Path((organization_id, profile_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profile_store(&state)?
        .get(&organization_id, &profile_id)
        .await
        .map(|profile| Json(serde_json::json!({"profile": profile})))
        .map_err(profile_error)
}

async fn put_profile(
    State(state): State<AppState>,
    Path((organization_id, profile_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(profile): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profile_store(&state)?
        .put(&organization_id, &profile_id, profile)
        .await
        .map(|profile| Json(serde_json::json!({"profile": profile})))
        .map_err(profile_error)
}

async fn delete_profile(
    State(state): State<AppState>,
    Path((organization_id, profile_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profile_store(&state)?
        .delete(&organization_id, &profile_id)
        .await
        .map_err(profile_error)?;
    Ok(Json(serde_json::json!({"deleted": profile_id})))
}

async fn find_profiles(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<FindProfilesRequest>,
) -> Result<Json<serde_json::Value>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profile_store(&state)?
        .find(&organization_id, request)
        .await
        .map(|profiles| Json(serde_json::json!({"profiles": profiles})))
        .map_err(profile_error)
}

async fn find_duplicate_profile(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<DuplicateProfileRequest>,
) -> Result<Json<DuplicateProfileResponse>, ProfileHttpError> {
    authorize_profiles(&state, &headers)?;
    profile_store(&state)?
        .find_duplicate(&organization_id, request)
        .await
        .map(Json)
        .map_err(profile_error)
}

fn profile_store(state: &AppState) -> Result<&ProfileStore, ProfileHttpError> {
    state.profile_store.as_ref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"detail": "issuer profile storage is unavailable"})),
        )
    })
}

fn authorize_profiles(state: &AppState, headers: &HeaderMap) -> Result<(), ProfileHttpError> {
    authorize_internal(state, headers).map_err(|error| {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"detail": error.to_string()})),
        )
    })
}

fn profile_error(error: profiles::ProfileError) -> ProfileHttpError {
    let status = match &error {
        profiles::ProfileError::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
        profiles::ProfileError::Conflict(_) => StatusCode::CONFLICT,
        profiles::ProfileError::NotFound(_) => StatusCode::NOT_FOUND,
        profiles::ProfileError::Storage(_) => StatusCode::SERVICE_UNAVAILABLE,
        profiles::ProfileError::Corrupt(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(serde_json::json!({"detail": error.to_string()})),
    )
}

fn authorize_internal(state: &AppState, headers: &HeaderMap) -> Result<(), kms::KmsError> {
    let candidate = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let expected = state.internal_api_key.as_bytes();
    let supplied = candidate.as_bytes();
    if expected.len() != supplied.len() || expected.ct_eq(supplied).unwrap_u8() != 1 {
        return Err(kms::KmsError::Unauthorized);
    }
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        service: "signing-keys-service",
    })
}

async fn ready() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ready",
        service: "signing-keys-service",
    })
}

async fn startup() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "started",
        service: "signing-keys-service",
    })
}

async fn service_status() -> Json<ServiceStatus> {
    Json(ServiceStatus {
        service_name: "signing-keys-service",
        phase: "provider-validation",
        migrated_capabilities: [
            "service-bootstrap",
            "health-surface",
            "integration-test-target",
            "kms-adapter-integration",
            "provider-key-normalization",
            "service-registration-validation",
            "registry-normalization-resolution",
            "registry-persistence",
            "certificate-document-persistence",
            "jwks-did-publication-persistence",
            "issuer-profile-policy-selection-persistence",
        ],
        pending_capabilities: ["audit-event-storage", "compliance-summary-computation"],
    })
}

async fn purposes() -> Json<serde_json::Value> {
    Json(serde_json::json!({"purposes": key_purposes()}))
}

async fn capabilities() -> Json<serde_json::Value> {
    Json(serde_json::json!({"service_capabilities": service_capabilities()}))
}

async fn openapi() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "openapi": "3.1.0",
        "info": {"title": "Signing Keys Service", "version": "1.0.0"},
        "paths": {
            "/health": {"get": {"summary": "Health Check", "responses": {"200": {"description": "Successful Response"}}}},
            "/v1/signing-keys": {"get": {"summary": "List Signing Keys", "responses": {"200": {"description": "Provider-neutral signing-key inventory"}}}},
            "/v1/signing-keys/issuer-identities": {
                "get": {"summary": "List Public Issuer Identities", "responses": {"200": {"description": "DID-first issuer identity inventory without custody coordinates"}}},
                "post": {"summary": "Create Public Issuer Identity", "responses": {"200": {"description": "Provider-neutral issuer identity provisioning"}}},
                "patch": {"summary": "Move Issuer Identity to Default Signing Service", "responses": {"200": {"description": "Replacement public key is published before active custody changes"}}},
                "delete": {"summary": "Retire Public Issuer Identity", "responses": {"200": {"description": "Issuer identity retired"}}}
            },
            "/v1/signing-keys/issuer-identities/resolve": {
                "post": {"summary": "Resolve Public Issuer Identity", "responses": {"200": {"description": "Exact active tuple and public JWK without custody coordinates"}}}
            },
            "/v1/signing-keys/issuer-identities/csca-certificate": {
                "put": {"summary": "Enroll Public CSCA Certificate for Managed Issuer Identity", "responses": {"200": {"description": "Tenant-scoped public trust anchor enrolled without exposing key coordinates"}}}
            },
            "/v1/signing-keys/issuer-identities/certificate-csr": {
                "put": {"summary": "Generate KMS-backed Certificate Request for Passport Issuer Identity", "responses": {"200": {"description": "Public PKCS#10 request signed in managed custody"}}}
            },
            "/v1/signing-keys/services/{service_id}/certificate": {
                "get": {"summary": "Read Registered Service Certificate", "responses": {"200": {"description": "Public certificate and chain"}}},
                "put": {"summary": "Store Registered Service Certificate", "responses": {"200": {"description": "Certificate checked against current KMS public key"}}}
            },
            "/v1/signing-keys/services/{service_id}/certificate-csr": {
                "post": {"summary": "Generate Registered Service CSR", "responses": {"200": {"description": "PKCS#10 request signed by the configured KMS key"}}}
            },
            "/v1/signing-keys/services/{service_id}/mdoc-x5c": {
                "get": {"summary": "Read Registered Service mDoc Certificate Chain", "responses": {"200": {"description": "Public X.509 chain bound to the current KMS key"}}}
            },
            "/v1/signing-keys/services/{service_id}/verify-current": {
                "get": {"summary": "Verify Current Registered Service Public Key", "responses": {"200": {"description": "KMS public-key verification checks"}}}
            },
            "/v1/signing-keys/services/{service_id}/publish-jwks": {
                "post": {"summary": "Publish Registered Service Public Key to Organization JWKS", "responses": {"200": {"description": "Current KMS public key published without custody coordinates"}}}
            },
            "/v1/signing-keys/services/{service_id}/publish-did-vm": {
                "post": {"summary": "Publish Registered Service DID Verification Method", "responses": {"200": {"description": "Current KMS public key published as a public assertion method"}}}
            },
            "/v1/signing-keys/config/certificate-expiry-alerts": {
                "get": {"summary": "Registered Service Certificate Expiry Alerts", "responses": {"200": {"description": "Tenant-scoped alerts using stored certificate overrides"}}}
            },
            "/v1/signing-keys/jwks": {
                "get": {"summary": "Organization Public JWKS", "responses": {"200": {"description": "Public JWKs without KMS custody coordinates"}}}
            },
            "/v1/signing-keys/did-document": {
                "get": {"summary": "Organization Public DID Document", "responses": {"200": {"description": "DID document with public verification material only"}}}
            },
            "/v1/signing-keys/service-status": {"get": {"summary": "Signing Keys Service Extraction Status", "responses": {"200": {"description": "Successful Response"}}}},
            "/v1/signing-keys/config/purposes": {"get": {"summary": "List Available Key Purposes", "responses": {"200": {"description": "Successful Response"}}}},
            "/v1/signing-keys/config/service-capabilities": {"get": {"summary": "List Provider Capability Metadata", "responses": {"200": {"description": "Successful Response"}}}}
        }
    }))
}

async fn docs() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html><head><title>Signing Keys Service - Swagger UI</title></head><body><div id="swagger-ui"></div><script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:'/openapi.json',dom_id:'#swagger-ui'})</script></body></html>"#,
    )
}

async fn redoc() -> Html<&'static str> {
    Html(
        r#"<!doctype html><html><head><title>Signing Keys Service - ReDoc</title></head><body><redoc spec-url="/openapi.json"></redoc><script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script></body></html>"#,
    )
}

#[cfg(test)]
mod public_contract_tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    fn identity(purpose: &str, algorithm: &str) -> IssuerIdentityRequest {
        IssuerIdentityRequest {
            organization_id: Some("org-a".into()),
            issuer_did: "did:web:beta.example:orgs:acme".into(),
            key_purpose: purpose.into(),
            credential_format: "SD_JWT_VC".into(),
            algorithm: algorithm.into(),
            key_attestation_policy: None,
            cert_pem: None,
            cert_chain_pem: None,
        }
    }

    #[test]
    fn public_csca_enrollment_derives_custody_from_matching_managed_identity() {
        let input: CscaCertificateEnrollment = serde_json::from_value(json!({
            "organization_id": "org-a",
            "issuer_did": "did:web:beta.example:orgs:acme",
            "credential_format": "MDOC",
            "algorithm": "ES256",
            "certificate_id": "csca-a",
            "cert_pem": "public-certificate",
            "cert_chain_pem": ""
        }))
        .unwrap();
        assert_eq!(input.identity().key_purpose, "csca");
        let profile = json!({
            "id": "profile-a", "key_purpose": "csca",
            "signing_service_id": "managed-openbao-transit",
            "signing_key_reference": "managed-kms-csca-a"
        });
        let resolved = json!({
            "issuer_profile": {"id": "profile-a", "signing_service_id": "managed-openbao-transit", "signing_key_reference": "managed-kms-csca-a"},
            "public_jwk": {"kty": "EC", "crv": "P-256", "x": "public-x", "y": "public-y"}
        });
        let request =
            managed_csca_import(&input, &profile, &resolved, &resolved["public_jwk"]).unwrap();
        assert_eq!(request.key_reference, "managed-kms-csca-a");
        assert_eq!(request.expected_public_jwk, resolved["public_jwk"]);
        assert_eq!(request.metadata, json!({"issuer_did": input.issuer_did}));
        assert!(serde_json::from_value::<CscaCertificateEnrollment>(json!({
            "issuer_did": input.issuer_did, "credential_format": "MDOC",
            "algorithm": "ES256", "certificate_id": "csca-a",
            "cert_pem": "public-certificate", "key_reference": "attacker-key"
        }))
        .is_err());
        assert!(managed_csca_import(
            &input,
            &profile,
            &json!({"issuer_profile": {"id": "profile-b"}, "public_jwk": resolved["public_jwk"]}),
            &resolved["public_jwk"]
        )
        .is_err());
        assert!(managed_csca_import(
            &input,
            &profile,
            &json!({
                "issuer_profile": {"id": "profile-a", "signing_service_id": "managed-openbao-transit", "signing_key_reference": "stale-kms-csca"},
                "public_jwk": resolved["public_jwk"]
            }),
            &resolved["public_jwk"]
        )
        .is_err());
        assert!(managed_csca_import(
            &input,
            &profile,
            &resolved,
            &json!({"kty": "EC", "crv": "P-256", "x": "rotated-x", "y": "rotated-y"})
        )
        .is_err());
    }

    #[test]
    fn passport_csr_request_accepts_only_public_issuer_identity_fields() {
        let behavior: Value = serde_json::from_str(include_str!(
            "../../../../contracts/passport-certificate-csr-behavior.json"
        ))
        .unwrap();
        let route = behavior["public_route"]["path"].as_str().unwrap();
        assert_eq!(route, "/v1/signing-keys/issuer-identities/certificate-csr");
        let request = json!({
            "organization_id": "org-a", "issuer_did": "did:web:beta.example:orgs:acme",
            "key_purpose": "csca", "credential_format": "MDOC", "algorithm": "ES256",
            "country": "US", "organization": "ElevenID Beta", "common_name": "Pilot CSCA"
        });
        let parsed: PassportCsrRequest = serde_json::from_value(request.clone()).unwrap();
        assert_eq!(parsed.identity().key_purpose, "csca");
        let mut with_key = request;
        with_key["key_reference"] = json!("attacker-key");
        assert!(serde_json::from_value::<PassportCsrRequest>(with_key).is_err());
    }

    #[tokio::test]
    async fn public_csr_route_rejects_caller_custody_before_managed_lookup() {
        let valid = json!({
            "organization_id": "org-a", "issuer_did": "did:web:beta.example:orgs:acme",
            "key_purpose": "csca", "credential_format": "MDOC", "algorithm": "ES256",
            "country": "US", "organization": "ElevenID Beta", "common_name": "Pilot CSCA"
        });
        let request = |body: Value| {
            Request::builder()
                .method("PUT")
                .uri("/v1/signing-keys/issuer-identities/certificate-csr?organization_id=org-a")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let response = router_with_internal_api_key("test-only".into())
            .oneshot(request(valid.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let mut forbidden = valid;
        forbidden["key_reference"] = json!("caller-selected-key");
        let response = router_with_internal_api_key("test-only".into())
            .oneshot(request(forbidden))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn service_certificate_contract_rejects_caller_custody_coordinates() {
        let behavior: Value = serde_json::from_str(include_str!(
            "../../../../contracts/signing-service-certificate-behavior.json"
        ))
        .unwrap();
        assert_eq!(behavior["routes"].as_array().unwrap().len(), 3);
        let upload = json!({"cert_pem": "public certificate", "cert_chain_pem": "public chain"});
        assert!(serde_json::from_value::<ServiceCertificateRequest>(upload.clone()).is_ok());
        for field in ["key_reference", "private_key", "expected_public_jwk"] {
            let mut forged = upload.clone();
            forged[field] = json!("attacker-selected-key");
            assert!(serde_json::from_value::<ServiceCertificateRequest>(forged).is_err());
        }
        let csr = json!({
            "country": "US", "organization": "ElevenID Beta", "common_name": "Signing Service"
        });
        assert!(serde_json::from_value::<ServiceCsrRequest>(csr.clone()).is_ok());
        let mut forged = csr;
        forged["key_reference"] = json!("attacker-selected-key");
        assert!(serde_json::from_value::<ServiceCsrRequest>(forged).is_err());
        assert!(validate_service_scope("org-a", Some("org-b")).is_err());
    }

    #[test]
    fn service_certificate_projection_never_leaks_kms_coordinates() {
        let service = json!({
            "id": "service-a", "name": "Signer", "service_type": "openbao-transit",
            "key_reference": "secret-key-name", "auth_reference": "secret-token",
            "endpoint": "https://private-kms.example", "private_key": "forbidden"
        });
        let certificate = json!({
            "cert_pem": "public certificate", "cert_chain_pem": "public chain",
            "cert_expires_at": "2030-01-01T00:00:00Z"
        });
        let projection = service_certificate_projection(&service, &certificate);
        let serialized = projection.to_string();
        for forbidden in [
            "secret-key-name",
            "secret-token",
            "private-kms",
            "forbidden",
        ] {
            assert!(!serialized.contains(forbidden));
        }
        assert_eq!(projection["cert_pem"], "public certificate");
    }

    #[test]
    fn service_certificate_uses_one_registered_key_without_caller_selection() {
        let fixed =
            json!({"key_reference": "service-primary", "key_aliases": ["service-secondary"]});
        assert_eq!(
            service_certificate_key_config(&fixed).unwrap()["key_reference"],
            "service-primary"
        );
        let one_alias = json!({"key_reference": "", "key_aliases": ["service-only"]});
        assert_eq!(
            service_certificate_key_config(&one_alias).unwrap()["key_reference"],
            "service-only"
        );
        let ambiguous = json!({"key_reference": "", "key_aliases": ["service-a", "service-b"]});
        assert!(service_certificate_key_config(&ambiguous).is_err());
    }

    #[test]
    fn mdoc_x5c_prefers_override_and_requires_current_kms_public_key() {
        let behavior: Value = serde_json::from_str(include_str!(
            "../../../../contracts/signing-mdoc-x5c-behavior.json"
        ))
        .unwrap();
        assert_eq!(
            behavior["path"],
            "/v1/signing-keys/services/{service_id}/mdoc-x5c"
        );
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/document_vectors.json")).unwrap();
        let cert = &fixture["certificate"];
        let service = json!({"id": "service-a", "cert_pem": "stale-inline-cert"});
        let overrides = json!({"services": {"service-a": {"cert_pem": cert["cert_pem"]}}});
        let selected = selected_service_certificate(&service, &overrides, "service-a").unwrap();
        assert_eq!(selected["cert_pem"], cert["cert_pem"]);
        let result = checked_service_x5c(selected, &cert["expected_jwk"], "service-a").unwrap();
        assert_eq!(result["x5c"][0], cert["expected_x5c"]);
        assert_eq!(
            result["mdoc_cose_header_hints"],
            json!({"x5chain": true, "x5c_length": 1})
        );
        assert!(result.get("key_reference").is_none());
        let mut wrong_key = cert["expected_jwk"].clone();
        wrong_key["x"] = json!("different-public-key");
        assert_eq!(
            checked_service_x5c(selected, &wrong_key, "service-a")
                .unwrap_err()
                .status,
            StatusCode::CONFLICT
        );
        assert_eq!(
            checked_service_x5c(
                &json!({"cert_pem": "not-a-cert"}),
                &cert["expected_jwk"],
                "service-a"
            )
            .unwrap_err()
            .status,
            StatusCode::BAD_GATEWAY
        );
        assert!(selected_service_certificate(
            &json!({"id": "service-a"}),
            &json!({"services": {}}),
            "service-a"
        )
        .is_none());
    }

    #[test]
    fn verify_current_preserves_checks_and_accepts_supported_kms_key_types() {
        let behavior: Value = serde_json::from_str(include_str!(
            "../../../../contracts/signing-service-verify-current-behavior.json"
        ))
        .unwrap();
        assert_eq!(
            behavior["path"],
            "/v1/signing-keys/services/{service_id}/verify-current"
        );
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/document_vectors.json")).unwrap();
        let p256 = &fixture["certificate"]["expected_jwk"];
        let result = verify_service_key_result(
            "service-a",
            &json!({"algorithms": ["ES256"]}),
            p256,
            "2026-09-26T00:00:00Z".into(),
        );
        assert_eq!(result["key_valid"], true);
        assert_eq!(
            result["checks"],
            json!({
                "key_present": true,
                "required_fields_present": true,
                "algorithm_supported": true,
            })
        );
        assert_eq!(result["verified_at"], "2026-09-26T00:00:00Z");
        assert!(result.get("key_reference").is_none());
        assert!(result.get("public_jwk").is_none());
        let wrong_policy = verify_service_key_result(
            "service-a",
            &json!({"algorithms": ["ES384"]}),
            p256,
            String::new(),
        );
        assert_eq!(wrong_policy["checks"]["algorithm_supported"], false);
        assert_eq!(wrong_policy["key_valid"], false);
        let missing_coordinate = verify_service_key_result(
            "service-a",
            &json!({"algorithms": ["ES256"]}),
            &json!({"kty": "EC", "crv": "P-256", "x": p256["x"]}),
            String::new(),
        );
        assert_eq!(
            missing_coordinate["checks"]["required_fields_present"],
            false
        );
        assert_eq!(missing_coordinate["key_valid"], false);
        for (key, algorithm) in [
            (
                json!({"kty": "EC", "crv": "P-384", "x": "x", "y": "y"}),
                "ES384",
            ),
            (
                json!({"kty": "EC", "crv": "P-521", "x": "x", "y": "y"}),
                "ES512",
            ),
            (
                json!({"kty": "RSA", "n": "n", "e": "AQAB", "alg": "PS256"}),
                "PS256",
            ),
            (json!({"kty": "OKP", "crv": "Ed25519", "x": "x"}), "EdDSA"),
        ] {
            assert_eq!(
                verify_service_key_result(
                    "service-a",
                    &json!({"algorithms": [algorithm]}),
                    &key,
                    String::new(),
                )["key_valid"],
                true
            );
        }
    }

    #[tokio::test]
    async fn public_jwks_publication_rejects_caller_key_selection_before_kms_use() {
        let behavior: Value = serde_json::from_str(include_str!(
            "../../../../contracts/signing-service-publish-jwks-behavior.json"
        ))
        .unwrap();
        assert_eq!(
            behavior["path"],
            "/v1/signing-keys/services/{service_id}/publish-jwks"
        );
        assert!(serde_json::from_value::<PublicServiceJwksPublicationRequest>(json!({})).is_ok());
        assert!(
            serde_json::from_value::<PublicServiceJwksPublicationRequest>(
                json!({"key_reference": "caller-selected"})
            )
            .is_err()
        );
        let forbidden = Request::builder()
            .method("POST")
            .uri("/v1/signing-keys/services/service-a/publish-jwks?organization_id=org-a")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"key_reference":"caller-selected"}"#))
            .unwrap();
        let response = router_with_internal_api_key("test-only".into())
            .oneshot(forbidden)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let empty = Request::builder()
            .method("POST")
            .uri("/v1/signing-keys/services/service-a/publish-jwks?organization_id=org-a")
            .body(Body::empty())
            .unwrap();
        let response = router_with_internal_api_key("test-only".into())
            .oneshot(empty)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn public_did_publication_accepts_only_identity_fields_before_kms_use() {
        let behavior: Value = serde_json::from_str(include_str!(
            "../../../../contracts/signing-service-publish-did-vm-behavior.json"
        ))
        .unwrap();
        assert_eq!(
            behavior["path"],
            "/v1/signing-keys/services/{service_id}/publish-did-vm"
        );
        let accepted: PublicServiceDidPublicationRequest = serde_json::from_value(json!({
            "did_id": "did:web:issuer.example:orgs:acme",
            "org_slug": "acme",
            "fragment": "service-a-vm"
        }))
        .unwrap();
        assert_eq!(accepted.org_slug.as_deref(), Some("acme"));
        assert!(
            serde_json::from_value::<PublicServiceDidPublicationRequest>(
                json!({"key_reference": "caller-selected"})
            )
            .is_err()
        );
        let forbidden = Request::builder()
            .method("POST")
            .uri("/v1/signing-keys/services/service-a/publish-did-vm?organization_id=org-a")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"key_reference":"caller-selected"}"#))
            .unwrap();
        let response = router_with_internal_api_key("test-only".into())
            .oneshot(forbidden)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn certificate_alerts_overlay_service_certificates_without_profile_leakage() {
        let behavior: Value = serde_json::from_str(include_str!(
            "../../../../contracts/signing-certificate-alerts-behavior.json"
        ))
        .unwrap();
        assert_eq!(
            behavior["path"],
            "/v1/signing-keys/config/certificate-expiry-alerts"
        );
        assert_eq!(behavior["query"]["days_until_expiry_default"], 30);
        let registry = json!({"services": [
            {"id": "service-a", "name": "Signer", "cert_expires_at": "2035-01-01T00:00:00Z"},
            {"id": "service-b", "name": "Other", "cert_expires_at": "2034-01-01T00:00:00Z"}
        ]});
        let overrides = json!({
            "services": {"service-a": {"cert_pem": "public-a", "cert_expires_at": "2026-10-01T00:00:00Z", "key_reference": "must-not-leak"}},
            "profiles": {"profile-a": {"cert_expires_at": "2026-09-27T00:00:00Z"}}
        });
        let services = services_with_certificate_overrides(&registry, &overrides);
        assert_eq!(services.len(), 2);
        assert_eq!(services[0]["cert_expires_at"], "2026-10-01T00:00:00Z");
        assert_eq!(services[1]["cert_expires_at"], "2034-01-01T00:00:00Z");
        assert!(services[0].get("key_reference").is_none());
        let alerts = documents::certificate_alerts(CertificateAlertsRequest {
            services,
            days_until_expiry: 30,
            now: Some("2026-09-26T00:00:00Z".into()),
        })
        .unwrap();
        assert_eq!(alerts.alerts.len(), 1);
        assert_eq!(alerts.alerts[0].service_id.as_deref(), Some("service-a"));
    }

    #[test]
    fn public_jwks_preserves_verification_fields_but_never_returns_custody_fields() {
        let behavior: Value = serde_json::from_str(include_str!(
            "../../../../contracts/signing-public-jwks-behavior.json"
        ))
        .unwrap();
        assert_eq!(behavior["path"], "/v1/signing-keys/jwks");
        let document = json!({
            "organization_id": "untrusted-stored-org", "updated_at": "2026-09-26T00:00:00Z",
            "auth_reference": "secret-top-level-token",
            "keys": [{
                "kty": "EC", "crv": "P-256", "x": "public-x", "y": "public-y", "kid": "public-id",
                "x5c": ["public-cert"], "service_id": "service-a", "status": "active",
                "d": "private-scalar", "key_reference": "internal-key-name",
                "auth_reference": "secret-token", "private_key": "forbidden"
            }]
        });
        let projected = public_jwks_document(document, "org-a").unwrap();
        assert_eq!(projected["keys"][0]["kid"], "public-id");
        assert_eq!(projected["organization_id"], "org-a");
        assert_eq!(projected["keys"][0]["x5c"][0], "public-cert");
        assert!(projected.get("auth_reference").is_none());
        for field in behavior["forbidden_fields"].as_array().unwrap() {
            assert!(projected["keys"][0].get(field.as_str().unwrap()).is_none());
        }
        assert!(public_jwks_document(json!({"keys": [{}]}), "org-a").is_err());
    }

    #[test]
    fn public_issuer_resolution_contract_rejects_selectors_and_scrubs_public_jwk() {
        let behavior: Value = serde_json::from_str(include_str!(
            "../../../../contracts/signing-public-issuer-resolution-behavior.json"
        ))
        .unwrap();
        assert_eq!(
            behavior["path"],
            "/v1/signing-keys/issuer-identities/resolve"
        );
        let request = json!({
            "organization_id": "org-a", "issuer_did": "did:web:beta.example:orgs:org-a",
            "key_purpose": "csca", "credential_format": "ICAO_EMRTD", "algorithm": "ES256"
        });
        assert!(serde_json::from_value::<IssuerIdentityRequest>(request.clone()).is_ok());
        for field in behavior["forbidden_request_fields"].as_array().unwrap() {
            let mut forbidden = request.clone();
            forbidden[field.as_str().unwrap()] = json!("caller-selected");
            assert!(serde_json::from_value::<IssuerIdentityRequest>(forbidden).is_err());
        }
        let jwk = json!({
            "kty": "EC", "crv": "P-256", "x": "public-x", "y": "public-y",
            "kid": "internal-key-name", "d": "private-scalar", "key_reference": "internal-key-name",
            "auth_reference": "secret-token"
        });
        let public = public_issuer_jwk(&jwk).unwrap();
        assert_eq!(public["x"], "public-x");
        for field in behavior["forbidden_public_jwk_fields"].as_array().unwrap() {
            assert!(public.get(field.as_str().unwrap()).is_none());
        }
        assert!(public_issuer_jwk(&json!({"d": "private-only"})).is_err());
    }

    #[tokio::test]
    async fn public_issuer_resolve_route_rejects_caller_custody_before_lookup() {
        let request = |body: Value| {
            Request::builder()
                .method("POST")
                .uri("/v1/signing-keys/issuer-identities/resolve?organization_id=org-a")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let valid = json!({
            "organization_id": "org-a", "issuer_did": "did:web:beta.example:orgs:org-a",
            "key_purpose": "csca", "credential_format": "ICAO_EMRTD", "algorithm": "ES256"
        });
        let router = router_with_internal_api_key("test-only".into());
        let unavailable = router
            .clone()
            .oneshot(request(valid.clone()))
            .await
            .unwrap();
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        let mut forged = valid;
        forged["key_reference"] = json!("attacker-selected");
        let rejected = router.oneshot(request(forged)).await.unwrap();
        assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn public_did_preserves_relationships_and_services_without_custody_fields() {
        let behavior: Value = serde_json::from_str(include_str!(
            "../../../../contracts/signing-public-did-document-behavior.json"
        ))
        .unwrap();
        assert_eq!(behavior["path"], "/v1/signing-keys/did-document");
        let document = json!({
            "id": "did:web:beta.example:orgs:org-a", "controller": "did:web:beta.example:orgs:org-a",
            "verificationMethod": [{
                "id": "did:web:beta.example:orgs:org-a#key-1", "type": "JsonWebKey2020",
                "publicKeyJwk": {"kty": "EC", "crv": "P-256", "x": "public-x", "y": "public-y", "d": "private-scalar", "key_reference": "secret-key-name"},
                "privateKeyJwk": {"d": "private-scalar"}
            }],
            "assertionMethod": ["did:web:beta.example:orgs:org-a#key-1"],
            "service": [{"id": "#endpoint", "serviceEndpoint": "https://example.org", "auth_reference": "secret-token"}],
            "key_reference": "secret-key-name"
        });
        let projected = public_did_document(document).unwrap();
        assert_eq!(
            projected["verificationMethod"][0]["publicKeyJwk"]["x"],
            "public-x"
        );
        assert_eq!(
            projected["assertionMethod"][0],
            "did:web:beta.example:orgs:org-a#key-1"
        );
        assert_eq!(
            projected["service"][0]["serviceEndpoint"],
            "https://example.org"
        );
        for forbidden in ["private-scalar", "secret-key-name", "secret-token"] {
            assert!(!projected.to_string().contains(forbidden));
        }
        assert!(public_did_document(json!({"id": "did:web:beta.example", "verificationMethod": [{"publicKeyJwk": {"d": "private"}}]})).is_err());
    }

    #[tokio::test]
    async fn service_certificate_routes_reject_custody_fields_before_storage() {
        let request = |method: &str, path: &str, body: Value| {
            Request::builder()
                .method(method)
                .uri(format!(
                    "/v1/signing-keys/services/service-a/{path}?organization_id=org-a"
                ))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let router = router_with_internal_api_key("test-only".into());
        let response = router
            .clone()
            .oneshot(request("PUT", "certificate", json!({"cert_pem": "public"})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let response = router
            .clone()
            .oneshot(request("PUT", "certificate", json!({})))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = router
            .clone()
            .oneshot(request(
                "PUT",
                "certificate",
                json!({"cert_pem": "public", "key_reference": "forged"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let response = router
            .clone()
            .oneshot(request(
                "POST",
                "certificate-csr",
                json!({
                    "country": "US", "organization": "Test", "common_name": "Test"
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let response = router
            .oneshot(request("POST", "certificate-csr", json!({
                "country": "US", "organization": "Test", "common_name": "Test", "private_key": "forged"
            })))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn public_certificate_alert_route_validates_threshold_before_storage() {
        let router = router_with_internal_api_key("test-only".into());
        let request = |threshold: &str| {
            Request::builder()
                .uri(format!(
                    "/v1/signing-keys/config/certificate-expiry-alerts?organization_id=org-a&days_until_expiry={threshold}"
                ))
                .body(Body::empty())
                .unwrap()
        };
        let response = router.clone().oneshot(request("-1")).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let response = router.oneshot(request("30")).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn public_projection_never_exposes_private_profile_or_kms_coordinates() {
        let projection = identity_projection(&json!({
            "id": "private-profile-id",
            "issuer_did": "did:web:beta.example:orgs:acme",
            "signing_service_id": "private-service-id",
            "signing_key_reference": "private-key-reference",
            "key_purpose": "vc_jwt_issuer",
            "credential_format": "SD_JWT_VC",
            "algorithm": "ES256",
        }));
        assert_eq!(projection["status"], "active");
        for private in ["id", "signing_service_id", "signing_key_reference"] {
            assert!(projection.get(private).is_none());
        }
    }

    #[test]
    fn managed_key_names_preserve_purpose_isolation_and_algorithm_canonicalization() {
        let issuer = managed_key_reference("org-a", &identity("vc_jwt_issuer", "ES256"));
        let verifier = managed_key_reference("org-a", &identity("oid4vp_request_signing", "ES256"));
        let csca = managed_key_reference("org-a", &identity("csca", "ES256"));
        let dsc = managed_key_reference("org-a", &identity("mdoc_dsc", "ES256"));
        let csca_contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/csca-capability-behavior.json"
        ))
        .unwrap();
        assert!(issuer.starts_with("cred-issuer-"));
        assert!(issuer.ends_with("-es256"));
        assert!(verifier.starts_with("oid4vp-verifier-"));
        assert!(csca.starts_with(
            csca_contract["supported_rust_surface"]["signing_keys"]["managed_key_reference_prefix"]
                .as_str()
                .unwrap()
        ));
        assert_ne!(csca, dsc);
        assert_ne!(issuer, verifier);
        assert_eq!(canonical_algorithm("eddsa"), "EdDSA");
    }

    #[test]
    fn managed_identity_scope_requires_the_local_path_scoped_did() {
        assert!(local_managed_did(
            Some("beta.example"),
            "did:web:beta.example:orgs:acme"
        ));
        assert!(!local_managed_did(
            Some("beta.example"),
            "did:web:attacker.example:orgs:acme"
        ));
        assert!(validate_identity_scope("org-a", &identity("vc_jwt_issuer", "ES256")).is_ok());
        assert!(validate_identity_scope("org-b", &identity("vc_jwt_issuer", "ES256")).is_err());
    }

    #[test]
    fn public_identity_requests_reject_private_custody_selectors() {
        for private in [
            "issuer_profile_id",
            "signing_service_id",
            "signing_key_reference",
        ] {
            let mut request = json!({
                "organization_id": "org-a",
                "issuer_did": "did:web:beta.example:orgs:acme",
                "key_purpose": "vc_jwt_issuer",
                "credential_format": "SD_JWT_VC",
                "algorithm": "ES256"
            });
            request[private] = json!("must-not-cross");
            assert!(serde_json::from_value::<IssuerIdentityRequest>(request).is_err());
        }
    }

    #[test]
    fn public_config_preserves_provider_routing_defaults_for_lossless_updates() {
        let state = AppState {
            internal_api_key: Arc::from("test-key"),
            registry_store: None,
            document_store: None,
            csca_lifecycle_store: None,
            profile_store: None,
            flow_envelopes: None,
            compatibility: None,
            public_domain: Some("beta.example".into()),
        };
        let projected = public_config_document(
            &state,
            json!({
                "services": [],
                "default_service_id": "provider-a",
                "format_defaults": {"dc+sd-jwt": "provider-b"},
                "type_defaults": {"vc_jwt_issuer": "provider-c"},
                "key_reference_purposes": {}
            }),
        );
        assert_eq!(projected["format_defaults"]["dc+sd-jwt"], "provider-b");
        assert_eq!(projected["type_defaults"]["vc_jwt_issuer"], "provider-c");
    }

    #[test]
    fn public_config_redacts_credentials_without_hiding_service_metadata() {
        let state = AppState {
            internal_api_key: Arc::from("test-key"),
            registry_store: None,
            document_store: None,
            csca_lifecycle_store: None,
            profile_store: None,
            flow_envelopes: None,
            compatibility: None,
            public_domain: None,
        };
        let projected = public_config_document(
            &state,
            json!({"services": [{
                "id": "provider-a",
                "endpoint": "https://kms.example.test",
                "key_reference": "issuer-key",
                "auth_reference": "sensitive-test-token"
            }]}),
        );
        assert_eq!(projected["services"][0]["id"], "provider-a");
        assert_eq!(projected["services"][0]["key_reference"], "issuer-key");
        assert_eq!(projected["services"][0]["auth_reference"], "");
        assert_eq!(projected["services"][0]["auth_configured"], true);
        assert!(!projected.to_string().contains("sensitive-test-token"));
    }

    #[test]
    fn redacted_config_round_trip_preserves_only_unchanged_credential_binding() {
        let existing = json!({"services": [{
            "id": "provider-a",
            "provider": "openbao",
            "service_type": "openbao-transit",
            "endpoint": "https://kms.example.test",
            "region": "",
            "auth_mode": "token",
            "mount": "transit",
            "namespace": "",
            "auth_reference": "sensitive-test-token"
        }]});
        let mut unchanged = json!({"services": [{
            "id": "provider-a",
            "provider": "openbao",
            "service_type": "openbao-transit",
            "endpoint": "https://kms.example.test",
            "region": "",
            "auth_mode": "token",
            "mount": "transit",
            "namespace": "",
            "auth_reference": ""
        }]});
        preserve_unchanged_auth_references(&mut unchanged, &existing);
        assert_eq!(
            unchanged["services"][0]["auth_reference"],
            "sensitive-test-token"
        );

        let mut rebound = unchanged.clone();
        rebound["services"][0]["endpoint"] = json!("https://other.example.test");
        rebound["services"][0]["auth_reference"] = json!("");
        preserve_unchanged_auth_references(&mut rebound, &existing);
        assert_eq!(rebound["services"][0]["auth_reference"], "");

        let mut cleared = unchanged;
        cleared["services"][0]["auth_reference"] = Value::Null;
        preserve_unchanged_auth_references(&mut cleared, &existing);
        assert!(cleared["services"][0]["auth_reference"].is_null());
    }

    #[test]
    fn public_inventory_combines_profile_and_service_key_references_without_custody_data() {
        let registry = json!({
            "services": [{
                "id": "svc-openbao",
                "provider": "openbao",
                "algorithms": ["ES256"],
                "key_reference": "configured-key",
                "auth_reference": "private-token-reference"
            }]
        });
        let profiles = vec![json!({
            "id": "private-profile-id",
            "name": "Issuer identity",
            "signing_service_id": "svc-openbao",
            "signing_key_reference": "issuer-key",
            "key_purpose": "vc_jwt_issuer",
            "algorithm": "ES256",
            "status": "active"
        })];
        let inventory = public_signing_key_inventory(&registry, &profiles);
        assert_eq!(inventory.len(), 2);
        assert!(inventory.iter().any(|key| key["id"] == "issuer-key"));
        assert!(inventory.iter().any(|key| key["id"] == "configured-key"));
        let serialized = serde_json::to_string(&inventory).expect("inventory JSON");
        assert!(!serialized.contains("private-profile-id"));
        assert!(!serialized.contains("private-token-reference"));
    }
}
