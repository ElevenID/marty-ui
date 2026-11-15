use crate::certificate_csr::{self, CsrSubject};
mod certificate_operations;
mod didcomm_operations;
mod identity_inspection;
use didcomm_operations::*;
mod mdoc_crl_operations;
use crate::certificate_issuance::{self, VerifiedDscSubject};
use crate::compat::{
    CompatibilityError, IssuerContextRequest, IssuerDidSignRequest, ProfileIdentityRequest,
    ProfileWriteRequest, ResolveIssuerDidRequest, ServiceSignRequest, SignAuthorization,
    SigningCompatibilityService,
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
    PublishDidResponse, PublishJwkRequest, PublishJwkResponse, RegisterHolderKeyRequest,
    StoredCertificate, UpdateJwkRequest, UpdateJwkResponse,
};
use crate::domain::{key_purposes, service_capabilities};
use crate::dsc_issuance_store::{
    BeginDscIssuance, CommitDscIssuance, DscClaim, DscIssuanceSnapshot, DscIssuanceStore,
    DscIssuanceStoreError,
};
use crate::flow_envelope::{
    CreateHaipKeyRequest, DecryptHaipResponseRequest, FlowEnvelopeError, OpenBaoEnvelopeProvider,
    ResolveHaipKeyRequest,
};
use crate::integration_secret_envelope::{
    self, DecryptRequest as DecryptIntegrationSecretRequest,
    EncryptRequest as EncryptIntegrationSecretRequest, IntegrationSecretEnvelopeError,
    IntegrationSecretProvider,
};
use crate::kms::{self, ProviderRequest, SignRequest};
use crate::passport_artifact_envelope::{
    self, ArtifactEnvelopeError, DecryptChunkRequest, EncryptChunkRequest,
};
use crate::passport_callback_hmac::{self, CallbackKmsError};
use crate::profiles::{
    self, CustodyFormatRequest, CustodyFormatResponse, DuplicateProfileRequest,
    DuplicateProfileResponse, FindProfilesRequest, NormalizeProfileRequest, ProfileStore,
    ValidateBindingRequest,
};
use crate::registry::{
    self, BindProfileRequest, NormalizeRegistryRequest, NormalizeRegistryResponse,
    NormalizeServiceRequest, NormalizeServiceResponse, RegistryStore, ResolveRequest,
    ResolveResponse, RotationLease, SaveRegistryRequest,
};
use crate::validation::{self, ValidationRequest};
use crate::vc_api_holder_proof::{
    HolderProofError, HolderProofRequest, HolderProofResponse, OpenBaoHolderProofProvider,
};
use axum::{
    extract::{Path, Query, State},
    http::{
        header::{CACHE_CONTROL, ETAG, IF_MATCH},
        HeaderMap, StatusCode,
    },
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use certificate_operations::*;
use marty_crypto::{ecdsa, jwk::PublicJwk};
use marty_signing_grant::{
    ceremony::{IssuerCsrIntent, ServiceCsrIntent},
    replay::ConsumedGrant,
    verifier::{GrantAuthorizationError, GrantVerifier},
    GrantBinding, GrantEnvelope, SigningOrigin, HEADER_NAME,
};
use mdoc_crl_operations::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::task::JoinSet;
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
    service_sign_gateway_key: Option<Arc<str>>,
    issuer_sign_key: Option<Arc<str>>,
    integration_secret_key: Option<Arc<str>>,
    dsc_issue_gateway_key: Option<Arc<str>>,
    csca_issue_gateway_key: Option<Arc<str>>,
    beta_csca_issuance_enabled: bool,
    mdoc_certificates: Arc<crate::mdoc_certificate::MdocCertificateOptions>,
    registry_store: Option<RegistryStore>,
    document_store: Option<DocumentStore>,
    csca_lifecycle_store: Option<CscaLifecycleStore>,
    profile_store: Option<ProfileStore>,
    dsc_issuance_store: Option<DscIssuanceStore>,
    flow_envelopes: Option<OpenBaoEnvelopeProvider>,
    integration_secret_envelopes: Option<IntegrationSecretProvider>,
    compatibility: Option<SigningCompatibilityService>,
    grant_verifier: Option<GrantVerifier>,
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
    router_with_dependencies_and_sign_key(
        internal_api_key,
        None,
        registry_store,
        document_store,
        csca_lifecycle_store,
        profile_store,
        flow_envelopes,
        public_domain,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn router_with_dependencies_and_sign_key(
    internal_api_key: String,
    service_sign_gateway_key: Option<String>,
    registry_store: Option<RegistryStore>,
    document_store: Option<DocumentStore>,
    csca_lifecycle_store: Option<CscaLifecycleStore>,
    profile_store: Option<ProfileStore>,
    flow_envelopes: Option<OpenBaoEnvelopeProvider>,
    public_domain: Option<String>,
) -> Router {
    router_with_all_keys(
        internal_api_key,
        service_sign_gateway_key,
        None,
        None,
        None,
        None,
        false,
        registry_store,
        document_store,
        csca_lifecycle_store,
        profile_store,
        flow_envelopes,
        public_domain,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn router_with_dependencies_and_dsc_key(
    internal_api_key: String,
    dsc_issue_gateway_key: Option<String>,
    registry_store: Option<RegistryStore>,
    document_store: Option<DocumentStore>,
    csca_lifecycle_store: Option<CscaLifecycleStore>,
    profile_store: Option<ProfileStore>,
    flow_envelopes: Option<OpenBaoEnvelopeProvider>,
    public_domain: Option<String>,
) -> Router {
    router_with_dependencies_and_ceremony_keys(
        internal_api_key,
        dsc_issue_gateway_key,
        None,
        false,
        registry_store,
        document_store,
        csca_lifecycle_store,
        profile_store,
        flow_envelopes,
        public_domain,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn router_with_dependencies_and_ceremony_keys(
    internal_api_key: String,
    dsc_issue_gateway_key: Option<String>,
    csca_issue_gateway_key: Option<String>,
    beta_csca_issuance_enabled: bool,
    registry_store: Option<RegistryStore>,
    document_store: Option<DocumentStore>,
    csca_lifecycle_store: Option<CscaLifecycleStore>,
    profile_store: Option<ProfileStore>,
    flow_envelopes: Option<OpenBaoEnvelopeProvider>,
    public_domain: Option<String>,
) -> Router {
    router_with_all_keys(
        internal_api_key,
        None,
        None,
        None,
        dsc_issue_gateway_key,
        csca_issue_gateway_key,
        beta_csca_issuance_enabled,
        registry_store,
        document_store,
        csca_lifecycle_store,
        profile_store,
        flow_envelopes,
        public_domain,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn router_with_all_keys(
    internal_api_key: String,
    service_sign_gateway_key: Option<String>,
    issuer_sign_key: Option<String>,
    integration_secret_key: Option<String>,
    dsc_issue_gateway_key: Option<String>,
    csca_issue_gateway_key: Option<String>,
    beta_csca_issuance_enabled: bool,
    registry_store: Option<RegistryStore>,
    document_store: Option<DocumentStore>,
    csca_lifecycle_store: Option<CscaLifecycleStore>,
    profile_store: Option<ProfileStore>,
    flow_envelopes: Option<OpenBaoEnvelopeProvider>,
    public_domain: Option<String>,
) -> Router {
    router_with_all_keys_and_grants(
        internal_api_key,
        service_sign_gateway_key,
        issuer_sign_key,
        integration_secret_key,
        dsc_issue_gateway_key,
        csca_issue_gateway_key,
        beta_csca_issuance_enabled,
        registry_store,
        document_store,
        csca_lifecycle_store,
        profile_store,
        flow_envelopes,
        public_domain,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn router_with_all_keys_and_grants(
    internal_api_key: String,
    service_sign_gateway_key: Option<String>,
    issuer_sign_key: Option<String>,
    integration_secret_key: Option<String>,
    dsc_issue_gateway_key: Option<String>,
    csca_issue_gateway_key: Option<String>,
    beta_csca_issuance_enabled: bool,
    registry_store: Option<RegistryStore>,
    document_store: Option<DocumentStore>,
    csca_lifecycle_store: Option<CscaLifecycleStore>,
    profile_store: Option<ProfileStore>,
    flow_envelopes: Option<OpenBaoEnvelopeProvider>,
    public_domain: Option<String>,
    grant_verifier: Option<GrantVerifier>,
) -> Router {
    router_with_all_keys_grants_and_mdoc(
        internal_api_key,
        service_sign_gateway_key,
        issuer_sign_key,
        integration_secret_key,
        dsc_issue_gateway_key,
        csca_issue_gateway_key,
        beta_csca_issuance_enabled,
        registry_store,
        document_store,
        csca_lifecycle_store,
        profile_store,
        flow_envelopes,
        public_domain,
        grant_verifier,
        Default::default(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn router_with_all_keys_grants_and_mdoc(
    internal_api_key: String,
    service_sign_gateway_key: Option<String>,
    issuer_sign_key: Option<String>,
    integration_secret_key: Option<String>,
    dsc_issue_gateway_key: Option<String>,
    csca_issue_gateway_key: Option<String>,
    beta_csca_issuance_enabled: bool,
    registry_store: Option<RegistryStore>,
    document_store: Option<DocumentStore>,
    csca_lifecycle_store: Option<CscaLifecycleStore>,
    profile_store: Option<ProfileStore>,
    flow_envelopes: Option<OpenBaoEnvelopeProvider>,
    public_domain: Option<String>,
    grant_verifier: Option<GrantVerifier>,
    mdoc_certificates: crate::mdoc_certificate::MdocCertificateOptions,
) -> Router {
    let integration_secret_envelopes = flow_envelopes
        .clone()
        .map(IntegrationSecretProvider::OpenBao);
    router_with_runtime_kms(
        internal_api_key,
        service_sign_gateway_key,
        issuer_sign_key,
        integration_secret_key,
        dsc_issue_gateway_key,
        csca_issue_gateway_key,
        beta_csca_issuance_enabled,
        registry_store,
        document_store,
        csca_lifecycle_store,
        profile_store,
        RuntimeKmsProviders {
            flow_envelopes,
            integration_secret_envelopes,
        },
        public_domain,
        grant_verifier,
        mdoc_certificates,
    )
}

/// Platform-owned providers, independent of tenant signing registrations.
/// Keeping the extension separate prevents AWS from impersonating Transit.
pub struct RuntimeKmsProviders {
    pub flow_envelopes: Option<OpenBaoEnvelopeProvider>,
    pub integration_secret_envelopes: Option<IntegrationSecretProvider>,
}

#[allow(clippy::too_many_arguments)]
pub fn router_with_runtime_kms(
    internal_api_key: String,
    service_sign_gateway_key: Option<String>,
    issuer_sign_key: Option<String>,
    integration_secret_key: Option<String>,
    dsc_issue_gateway_key: Option<String>,
    csca_issue_gateway_key: Option<String>,
    beta_csca_issuance_enabled: bool,
    registry_store: Option<RegistryStore>,
    document_store: Option<DocumentStore>,
    csca_lifecycle_store: Option<CscaLifecycleStore>,
    profile_store: Option<ProfileStore>,
    kms_providers: RuntimeKmsProviders,
    public_domain: Option<String>,
    grant_verifier: Option<GrantVerifier>,
    mdoc_certificates: crate::mdoc_certificate::MdocCertificateOptions,
) -> Router {
    let dsc_issuance_store = profile_store.as_ref().map(ProfileStore::dsc_issuance_store);
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
        .route(
            marty_signing_grant::didcomm::RESOLVE_ROUTE,
            post(resolve_registered_didcomm),
        )
        .route(
            marty_signing_grant::didcomm::PACK_ROUTE,
            post(pack_registered_didcomm),
        )
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/startup", get(startup))
        .route("/openapi.json", get(openapi))
        .route("/docs", get(docs))
        .route("/redoc", get(redoc))
        .route("/v1/signing-keys/service-status", get(service_status))
        .route(
            "/v1/signing-keys/mdoc-crls/{organization_id}/{file}",
            get(public_mdoc_crl),
        )
        .route(
            "/v1/signing-keys/mdoc-crls/{certificate_id}",
            post(publish_mdoc_crl),
        )
        .route(
            "/v1/signing-keys",
            get(list_public_signing_keys).post(create_public_signing_key),
        )
        .route("/v1/signing-keys/jwks", get(public_organization_jwks))
        .route(
            "/v1/signing-keys/compliance/keys-summary",
            get(public_compliance_keys_summary),
        )
        .route(
            "/v1/signing-keys/holder-keys",
            get(list_public_holder_keys).post(register_public_holder_key),
        )
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
            "/v1/signing-keys/config/validate-current",
            post(validate_current_issuer_service),
        )
        .route(
            "/v1/signing-keys/config/resolve",
            post(resolve_public_config),
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
            "/v1/signing-keys/issuer-identities/capabilities",
            get(public_identity_capabilities),
        )
        .route(
            "/v1/signing-keys/issuer-identities/resolve",
            post(resolve_public_issuer_identity),
        )
        .route(
            "/v1/signing-keys/issuer-identities/inspection",
            get(identity_inspection::inspect),
        )
        .route(
            "/v1/signing-keys/issuer-identities/didcomm-key-agreement",
            axum::routing::put(publish_public_issuer_didcomm_key_agreement),
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
            "/v1/signing-keys/issuer-identities/dsc-certificate",
            post(issue_public_dsc_certificate),
        )
        .route(
            "/v1/signing-keys/issuer-identities/csca-self-signed-certificate",
            post(issue_public_csca_self_signed_certificate),
        )
        .route(
            "/v1/signing-keys/issuer-identities/mdoc-iaca-self-signed-certificate",
            post(issue_public_mdoc_iaca_certificate),
        )
        .route(
            "/v1/signing-keys/issuer-identities/mdoc-dsc-certificate",
            post(issue_public_mdoc_dsc_certificate),
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
            "/v1/signing-keys/services/{service_id}/sign",
            post(sign_public_service_payload),
        )
        .route(
            "/v1/signing-keys/services/{service_id}/rotate",
            post(rotate_public_service_key),
        )
        .route(
            "/v1/signing-keys/services/vdsnc/register",
            post(register_public_vdsnc_service),
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
            "/v1/signing-keys/services/{service_id}/audit-log",
            get(public_service_audit_log),
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
        .route(
            "/v1/signing-keys/{key_id}",
            get(get_public_signing_key)
                .patch(update_public_signing_key)
                .delete(delete_public_signing_key),
        )
        .route("/internal/kms/public-key", post(kms_public_key))
        .route("/internal/kms/verify", post(kms_verify))
        .route("/internal/vc-api/holder-proof", post(vc_api_holder_proof))
        .route(
            "/internal/haip-response-keys/create",
            post(create_haip_response_key),
        )
        .route(
            "/internal/haip-response-keys/resolve",
            post(resolve_haip_response_key),
        )
        .route(
            "/internal/haip-response-keys/decrypt",
            post(decrypt_haip_response),
        )
        .route(
            "/internal/integration-secrets/encrypt",
            post(encrypt_integration_secret),
        )
        .route(
            "/internal/integration-secrets/decrypt",
            post(decrypt_integration_secret),
        )
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
            "/internal/registry/{organization_id}/services/{service_id}/rotation-reconcile",
            get(registry_rotation_reconcile_status).post(reconcile_registry_rotation),
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
            "/internal/documents/{organization_id}/passport-callbacks/verify",
            post(verify_passport_callback),
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
            service_sign_gateway_key: service_sign_gateway_key.map(Arc::from),
            issuer_sign_key: issuer_sign_key.map(Arc::from),
            integration_secret_key: integration_secret_key.map(Arc::from),
            dsc_issue_gateway_key: dsc_issue_gateway_key.map(Arc::from),
            csca_issue_gateway_key: csca_issue_gateway_key.map(Arc::from),
            beta_csca_issuance_enabled,
            mdoc_certificates: Arc::new(mdoc_certificates),
            registry_store,
            document_store,
            csca_lifecycle_store,
            profile_store,
            dsc_issuance_store,
            flow_envelopes: kms_providers.flow_envelopes,
            integration_secret_envelopes: kms_providers.integration_secret_envelopes,
            compatibility,
            grant_verifier,
            public_domain,
        })
}

#[derive(Debug, Deserialize)]
struct OrganizationScope {
    organization_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerCapabilitiesQuery {
    organization_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicManagedKeyCreateRequest {
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    key_name: Option<String>,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    key_purpose: Option<String>,
    #[serde(default)]
    service_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HolderKeysScope {
    organization_id: String,
    #[serde(default)]
    device_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuditLogScope {
    organization_id: String,
    #[serde(default)]
    limit: Option<String>,
    #[serde(default)]
    offset: Option<String>,
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
struct DidcommKeyAgreementRequest {
    service_id: String,
    key_reference: String,
    #[serde(default = "didcomm_enabled_by_default")]
    enabled: bool,
    organization_id: String,
    issuer_did: String,
    key_purpose: String,
    credential_format: String,
    algorithm: String,
    public_jwk: Value,
}

fn didcomm_enabled_by_default() -> bool {
    true
}

impl DidcommKeyAgreementRequest {
    fn identity(&self) -> IssuerIdentityRequest {
        IssuerIdentityRequest {
            organization_id: Some(self.organization_id.clone()),
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
struct DscCertificateIssueRequest {
    #[serde(skip)]
    mdoc_metadata: Option<marty_signing_grant::certificate_profile::MdocCertificateMetadata>,
    #[serde(default)]
    organization_id: Option<String>,
    dsc_issuer_did: String,
    csca_issuer_did: String,
    csca_certificate_id: String,
    credential_format: String,
    country: String,
    organization: String,
    common_name: String,
    validity_days: u8,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CscaSelfSignedIssueRequest {
    #[serde(skip)]
    mdoc_metadata: Option<marty_signing_grant::certificate_profile::MdocCertificateMetadata>,
    #[serde(default)]
    organization_id: Option<String>,
    issuer_did: String,
    certificate_id: String,
    credential_format: String,
    country: String,
    organization: String,
    common_name: String,
    validity_days: u16,
}

/// Public mdoc ceremonies select their family server-side. No caller TBS or publication metadata.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MdocIacaIssueRequest {
    #[serde(default)]
    organization_id: Option<String>,
    issuer_did: String,
    certificate_id: String,
    country: String,
    organization: String,
    common_name: String,
    validity_days: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MdocDscIssueRequest {
    #[serde(default)]
    organization_id: Option<String>,
    dsc_issuer_did: String,
    iaca_issuer_did: String,
    iaca_certificate_id: String,
    country: String,
    organization: String,
    common_name: String,
    validity_days: u8,
    idempotency_key: String,
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
struct PublicServiceSignRequest {
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    payload_b64: Option<String>,
    #[serde(default)]
    payload_hex: Option<String>,
    #[serde(default)]
    algorithm: Option<String>,
    #[serde(default)]
    key_reference: Option<String>,
    #[serde(default)]
    key_purpose: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicServiceRotationRequest {
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    overlap_days: Option<i64>,
    #[serde(default)]
    activate_at: Option<String>,
    #[serde(default)]
    publish_updates: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationReconcileRequest {
    operation_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicVdsncRegistrationRequest {
    #[serde(default)]
    organization_id: Option<String>,
    country_code: String,
    authority_name: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    generation: Option<i64>,
    #[serde(default)]
    key_reference: Option<String>,
    #[serde(default)]
    service_type: Option<String>,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    mount: Option<String>,
    #[serde(default)]
    namespace: Option<String>,
    #[serde(default)]
    auth_mode: Option<String>,
    #[serde(default)]
    auth_reference: Option<String>,
    #[serde(default)]
    algorithms: Option<Vec<String>>,
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

fn passport_csr_identity(input: &IssuerCsrIntent) -> IssuerIdentityRequest {
    IssuerIdentityRequest {
        organization_id: input.organization_id.clone(),
        issuer_did: input.issuer_did.clone(),
        key_purpose: input.key_purpose.clone(),
        credential_format: input.credential_format.clone(),
        algorithm: input.algorithm.clone(),
        key_attestation_policy: None,
        cert_pem: None,
        cert_chain_pem: None,
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
    let keys = match load_public_signing_key_inventory(&state, &scope.organization_id).await {
        Ok(keys) => keys,
        Err(error) => return error.into_response(),
    };
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

async fn load_public_signing_key_inventory(
    state: &AppState,
    organization_id: &str,
) -> Result<Vec<Value>, PublicSigningError> {
    validate_service_scope(organization_id, None)?;
    let Some(registry_store) = state.registry_store.as_ref() else {
        return Err(public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        ));
    };
    let registry = registry_store.load(organization_id).await.map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        )
    })?;
    let profiles = if let Some(profile_store) = state.profile_store.as_ref() {
        match profile_store
            .find(organization_id, FindProfilesRequest::default())
            .await
        {
            Ok(profiles) => profiles,
            Err(_) => {
                return Err(public_failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Issuer identity storage is unavailable.",
                ))
            }
        }
    } else {
        Vec::new()
    };
    let mut keys = public_signing_key_inventory(&registry, &profiles);
    enrich_managed_signing_key_inventory(&registry, &mut keys).await;
    keys.sort_by(|left, right| {
        left.get("id")
            .and_then(Value::as_str)
            .cmp(&right.get("id").and_then(Value::as_str))
    });
    Ok(keys)
}

fn queue_managed_key_inventory(
    tasks: &mut JoinSet<Option<(String, Value)>>,
    service: &Value,
    reference: String,
) {
    let mut config = service.clone();
    config["key_reference"] = json!(reference);
    tasks.spawn(async move {
        kms::read_managed_openbao(ProviderRequest {
            service_config: config,
        })
        .await
        .ok()
        .map(|public| (reference, public))
    });
}

fn verified_managed_references(service: &Value) -> std::collections::BTreeSet<String> {
    let mut references = service
        .get("key_aliases")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|reference| !reference.is_empty())
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
    if let Some(reference) = service.get("key_reference").and_then(Value::as_str) {
        if !reference.is_empty() {
            references.insert(reference.to_owned());
        }
    }
    references
}

async fn enrich_managed_signing_key_inventory(registry: &Value, keys: &mut Vec<Value>) {
    const MANAGED_ID: &str = "managed-openbao-transit";
    let Some(service) = registry
        .get("services")
        .and_then(Value::as_array)
        .and_then(|services| {
            services
                .iter()
                .find(|service| service.get("id").and_then(Value::as_str) == Some(MANAGED_ID))
        })
    else {
        return;
    };
    let Some(bindings) = registry
        .get("key_reference_purposes")
        .and_then(|bindings| bindings.get(MANAGED_ID))
        .and_then(Value::as_object)
    else {
        return;
    };
    // The managed service projection contains only live, tenant-owned keys.
    // Persisted bindings can outlive a retired issuer profile or refer to a
    // foreign namespace, so they are metadata rather than discovery input.
    let mut references = verified_managed_references(service).into_iter();
    let mut tasks = JoinSet::new();
    for _ in 0..8 {
        if let Some(reference) = references.next() {
            queue_managed_key_inventory(&mut tasks, service, reference);
        }
    }
    while let Some(result) = tasks.join_next().await {
        if let Some(reference) = references.next() {
            queue_managed_key_inventory(&mut tasks, service, reference);
        }
        if let Ok(Some((reference, public))) = result {
            let Some(public_jwk) = public.get("public_jwk") else {
                continue;
            };
            let Ok(public_jwk) = public_jwk_projection(public_jwk) else {
                continue;
            };
            let Some(algorithm) = compatible_public_key_algorithms(&public_jwk).first() else {
                continue;
            };
            if let Some(existing) = keys.iter_mut().find(|key| {
                key.get("service_id").and_then(Value::as_str) == Some(MANAGED_ID)
                    && key.get("provider_key_name").and_then(Value::as_str) == Some(&reference)
            }) {
                existing["public_jwk"] = public_jwk;
                existing["algorithm"] = json!(algorithm);
                existing["latest_version"] =
                    public.get("latest_version").cloned().unwrap_or(Value::Null);
            } else {
                let purpose = bindings
                    .get(&reference)
                    .and_then(Value::as_array)
                    .and_then(|purposes| purposes.first())
                    .cloned()
                    .unwrap_or(Value::Null);
                keys.push(json!({
                    "id": reference,
                    "provider_key_name": reference,
                    "name": reference,
                    "algorithm": algorithm,
                    "status": public.get("status").cloned().unwrap_or(json!("invalid")),
                    "created_at": public.get("created_at").cloned().unwrap_or(Value::Null),
                    "expiry_date": null,
                    "key_type": "hsm",
                    "provider": "openbao",
                    "service_id": MANAGED_ID,
                    "key_purpose": purpose,
                    "latest_version": public.get("latest_version").cloned().unwrap_or(Value::Null),
                    "public_jwk": public_jwk,
                }));
            }
        }
    }
}

async fn get_public_signing_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
) -> Response {
    let keys = match load_public_signing_key_inventory(&state, &scope.organization_id).await {
        Ok(keys) => keys,
        Err(error) => return error.into_response(),
    };
    match keys.into_iter().find(|key| {
        key.get("id").and_then(Value::as_str) == Some(&key_id)
            || key.get("provider_key_name").and_then(Value::as_str) == Some(&key_id)
    }) {
        Some(key) => Json(key).into_response(),
        None => public_error(
            StatusCode::NOT_FOUND,
            &format!("Signing key '{key_id}' not found."),
        ),
    }
}

fn public_jwk_metadata_patch(body: &Value) -> Result<Value, &'static str> {
    let valid_text = |text: &str| {
        !text.trim().is_empty() && text.len() <= 200 && !text.chars().any(char::is_control)
    };
    let Some(fields) = body.as_object() else {
        return Err("Signing key metadata update must be an object.");
    };
    let mut updates = serde_json::Map::new();
    for (field, value) in fields {
        match field.as_str() {
            "name" | "status" if value.as_str().is_some_and(valid_text) => {
                updates.insert(field.clone(), value.clone());
            }
            "aliases" | "key_aliases"
                if value.as_array().is_some_and(|values| {
                    values.len() <= 100
                        && values
                            .iter()
                            .all(|value| value.as_str().is_some_and(valid_text))
                }) =>
            {
                updates.insert(field.clone(), value.clone());
            }
            "name" | "status" | "aliases" | "key_aliases" => {
                return Err("Signing key metadata field has an invalid value.")
            }
            _ => return Err("Only name, status, aliases, and key_aliases may be updated."),
        }
    }
    Ok(Value::Object(updates))
}

async fn update_public_signing_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
    Json(body): Json<Value>,
) -> Response {
    if let Err(error) = validate_service_scope(&scope.organization_id, None) {
        return error.into_response();
    }
    let updates = match public_jwk_metadata_patch(&body) {
        Ok(updates) => updates,
        Err(message) => return public_error(StatusCode::UNPROCESSABLE_ENTITY, message),
    };
    let Some(store) = state.document_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing document storage is unavailable.",
        );
    };
    match store
        .update_jwk(
            &scope.organization_id,
            &key_id,
            UpdateJwkRequest { updates },
        )
        .await
    {
        Ok(updated) => {
            Json(json!({"ok": true, "key_id": key_id, "updated": updated.updated})).into_response()
        }
        Err(error) => public_publication_error(error),
    }
}

async fn delete_public_signing_key(
    State(state): State<AppState>,
    Path(key_id): Path<String>,
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
    match store.delete_jwk(&scope.organization_id, &key_id).await {
        Ok(deleted) => {
            Json(json!({"ok": true, "key_id": key_id, "removed": deleted.removed})).into_response()
        }
        Err(error) => public_publication_error(error),
    }
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
                    "algorithm": service.get("key_algorithms").and_then(|algorithms| algorithms.get(reference)).cloned().or_else(|| service.get("algorithms").and_then(Value::as_array).and_then(|values| values.first()).cloned()).unwrap_or(Value::Null),
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

fn managed_key_name(
    organization_id: &str,
    requested_name: &str,
    key_purpose: &str,
    algorithm: &str,
) -> Result<String, &'static str> {
    let requested_name = requested_name.trim();
    if requested_name.is_empty()
        || requested_name.len() > 256
        || requested_name.chars().any(char::is_control)
    {
        return Err(
            "name is required, must contain no control characters, and must be at most 256 bytes.",
        );
    }
    let mut stem = String::new();
    for character in requested_name.to_ascii_lowercase().chars() {
        if character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-' {
            stem.push(character);
        } else if !stem.ends_with('-') {
            stem.push('-');
        }
    }
    let stem = stem.trim_matches('-');
    let stem = if stem.is_empty() { "key" } else { stem };
    let expected_prefix = crate::domain::managed_key_prefix_for_purpose(key_purpose)
        .ok_or("Unsupported key_purpose.")?;
    let stem = crate::domain::MANAGED_KEY_PREFIXES
        .iter()
        .find_map(|prefix| stem.strip_prefix(prefix))
        .unwrap_or(stem)
        .trim_matches('-');
    let stem = if stem.is_empty() { "key" } else { stem };
    let algorithm_suffix = format!("-{}", algorithm.to_ascii_lowercase());
    let stem = stem
        .strip_suffix(&algorithm_suffix)
        .unwrap_or(stem)
        .trim_matches('-');
    let stem = if stem.is_empty() { "key" } else { stem };
    let tenant = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, organization_id.as_bytes())
        .simple()
        .to_string();
    let available = 96 - expected_prefix.len() - tenant.len() - 1 - algorithm_suffix.len();
    let stem = if stem.len() > available {
        // Keep the released 96-byte reference limit without conflating two
        // accepted names whose distinguishing bytes fall beyond that limit.
        let digest = Sha256::digest(stem.as_bytes())[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let prefix = stem[..available - digest.len() - 1].trim_matches('-');
        format!("{prefix}-{digest}")
    } else {
        stem.to_owned()
    };
    Ok(format!(
        "{expected_prefix}{tenant}-{stem}{algorithm_suffix}"
    ))
}

async fn create_public_signing_key(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    Json(input): Json<PublicManagedKeyCreateRequest>,
) -> Response {
    if let Err(error) =
        validate_service_scope(&scope.organization_id, input.organization_id.as_deref())
    {
        return error.into_response();
    }
    let requested_name = input
        .name
        .as_deref()
        .or(input.key_name.as_deref())
        .unwrap_or_default();
    let algorithm = input.algorithm.as_deref().unwrap_or("ES256");
    if !matches!(algorithm, "ES256" | "ES384" | "RS256" | "EdDSA") {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unsupported signing algorithm.",
        );
    }
    let key_purpose = input.key_purpose.as_deref().unwrap_or("vc_jwt_issuer");
    let Some(purpose) = key_purposes()
        .into_iter()
        .find(|purpose| purpose.id == key_purpose)
    else {
        return public_error(StatusCode::UNPROCESSABLE_ENTITY, "Unsupported key_purpose.");
    };
    if !purpose.allowed_algorithms.contains(&algorithm) {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "The requested algorithm is not allowed for key_purpose.",
        );
    }
    let key_reference = match managed_key_name(
        &scope.organization_id,
        requested_name,
        key_purpose,
        algorithm,
    ) {
        Ok(reference) => reference,
        Err(message) => return public_error(StatusCode::UNPROCESSABLE_ENTITY, message),
    };
    let Some(store) = state.registry_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        );
    };
    let registry = match store.load(&scope.organization_id).await {
        Ok(registry) => registry,
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing registry is unavailable.",
            )
        }
    };
    let service_id = input
        .service_id
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| registry.get("default_service_id").and_then(Value::as_str));
    let Some(service_id) = service_id else {
        return public_error(
            StatusCode::BAD_REQUEST,
            "No signing service is configured for this organization.",
        );
    };
    if service_id != "managed-openbao-transit" {
        return public_error(
            StatusCode::BAD_REQUEST,
            "Managed key creation is supported only for the managed OpenBao Transit service.",
        );
    }
    let Some(mut service) = registry
        .get("services")
        .and_then(Value::as_array)
        .and_then(|services| {
            services
                .iter()
                .find(|service| service.get("id").and_then(Value::as_str) == Some(service_id))
        })
        .cloned()
    else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Managed OpenBao Transit is unavailable.",
        );
    };
    service["key_reference"] = json!(key_reference);
    service["algorithm"] = json!(algorithm);
    let created = match kms::read_managed_openbao(ProviderRequest {
        service_config: service.clone(),
    })
    .await
    {
        Ok(existing) => existing,
        Err(error) => {
            let missing = match kms::missing_managed_openbao_key(&service, &error).await {
                Ok(missing) => missing,
                Err(_) => {
                    return public_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Managed KMS key inventory is unavailable.",
                    )
                }
            };
            if !missing {
                return public_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Managed KMS key inventory is unavailable.",
                );
            }
            let Some(profile_store) = state.profile_store.as_ref() else {
                return public_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Issuer profile storage is unavailable.",
                );
            };
            let profile_document = match profile_store.list(&scope.organization_id).await {
                Ok(document) => document,
                Err(_) => {
                    return public_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Issuer profile storage is unavailable.",
                    )
                }
            };
            if profiles::managed_reference_has_history(&registry, &profile_document, &key_reference)
            {
                return public_error(
                    StatusCode::CONFLICT,
                    "Previously bound managed KMS key is unavailable; restore its original material or use a distinct key name.",
                );
            }
            match kms::create_managed_openbao(ProviderRequest {
                service_config: service,
            })
            .await
            {
                Ok(created) => created,
                Err(_) => {
                    return public_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Managed KMS key creation failed.",
                    )
                }
            }
        }
    };
    let Some(public_jwk) = created.get("public_jwk") else {
        return public_error(
            StatusCode::BAD_GATEWAY,
            "Managed KMS did not return a public key.",
        );
    };
    if !compatible_public_key_algorithms(public_jwk).contains(&algorithm)
        || created.get("status").and_then(Value::as_str) != Some("active")
    {
        return public_error(
            StatusCode::CONFLICT,
            "The existing KMS key is incompatible with the requested algorithm or signing state.",
        );
    }
    let public_jwk = match public_jwk_projection(public_jwk) {
        Ok(public_jwk) => public_jwk,
        Err(_) => {
            return public_error(
                StatusCode::BAD_GATEWAY,
                "Managed KMS returned an invalid public key.",
            )
        }
    };
    if store
        .bind_key_purpose(
            &scope.organization_id,
            service_id,
            &key_reference,
            key_purpose,
        )
        .await
        .is_err()
    {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing key purpose binding could not be saved.",
        );
    }
    let key = json!({
        "id": key_reference,
        "name": requested_name.trim(),
        "algorithm": algorithm,
        "status": "active",
        "expiry_date": null,
        "created_at": created.get("created_at").cloned().unwrap_or(Value::Null),
        "key_type": "hsm",
        "provider": "openbao",
        "provider_key_name": key_reference,
        "latest_version": created.get("latest_version").cloned().unwrap_or(Value::Null),
        "public_jwk": public_jwk,
        "service_id": service_id,
        "key_purpose": key_purpose,
    });
    Json(json!({
        "ok": true, "service_id": service_id,
        "provider_key_name": key_reference,
        "key": key,
        "created_at": chrono::Utc::now().to_rfc3339(),
    }))
    .into_response()
}

// These strong revision tags are CAS tokens. Intermediary compression must not
// turn them into weak validators that cannot be used with If-Match.
fn public_config_revision_headers(revision: String) -> [(axum::http::HeaderName, String); 2] {
    [
        (ETAG, revision),
        (CACHE_CONTROL, "no-store, no-transform".to_owned()),
    ]
}

fn public_config_revision_response(
    state: &AppState,
    registry: Value,
    revision: String,
) -> Response {
    // Preserve the same opaque revision in JSON for clients whose shared
    // transport exposes decoded bodies rather than response headers.
    let mut document = public_config_document(state, registry);
    document["config_revision"] = json!(revision);
    (public_config_revision_headers(revision), Json(document)).into_response()
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
    match store.load_with_revision(&scope.organization_id).await {
        Ok((registry, revision)) => public_config_revision_response(&state, registry, revision),
        Err(error) => public_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()),
    }
}

fn public_jwk_projection(key: &Value) -> Result<Value, documents::DocumentError> {
    documents::public_jwk_projection(key)
}

async fn list_public_holder_keys(
    State(state): State<AppState>,
    Query(scope): Query<HolderKeysScope>,
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
    match store
        .holder_keys(&scope.organization_id, scope.device_id.as_deref())
        .await
    {
        Ok(keys) => Json(keys).into_response(),
        Err(error) => public_publication_error(error),
    }
}

async fn register_public_holder_key(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    Json(request): Json<RegisterHolderKeyRequest>,
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
    match store
        .register_holder_key(&scope.organization_id, request)
        .await
    {
        Ok(registered) => Json(registered).into_response(),
        Err(error) => public_publication_error(error),
    }
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
                    "password",
                    "credentials",
                    "credential_reference",
                    "signing_service_id",
                    "signing_key_reference",
                    "issuer_profile_id",
                    "kms_provider",
                    "kms_arn",
                    "kms_region",
                    "provider_config",
                    "service_id",
                    "client_secret",
                    "key_binding",
                ];
                let mut public = serde_json::Map::new();
                for (name, nested) in fields {
                    if CUSTODY_FIELDS
                        .iter()
                        .any(|field| field.eq_ignore_ascii_case(name))
                    {
                        continue;
                    }
                    public.insert(
                        name.clone(),
                        if name == "publicKeyJwk" {
                            let mut jwk = public_jwk_projection(nested)?;
                            if let Some(fields) = jwk.as_object_mut() {
                                for field in ["service_id", "name", "status"] {
                                    fields.remove(field);
                                }
                            }
                            jwk
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

fn strong_config_if_match(headers: &HeaderMap) -> Result<Option<String>, ()> {
    let mut values = headers.get_all(IF_MATCH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    let token = value
        .strip_prefix("\"r-")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(())?;
    if uuid::Uuid::parse_str(token).is_err() {
        return Err(());
    }
    Ok(Some(value.to_owned()))
}

async fn save_public_config(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    if !body.is_object() {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Signing configuration must be an object.",
        );
    }
    let expected_revision = match strong_config_if_match(&headers) {
        Ok(revision) => revision,
        Err(()) => {
            return public_error(
                StatusCode::BAD_REQUEST,
                "If-Match must be one strong registry revision.",
            )
        }
    };
    let Some(store) = state.registry_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        );
    };
    let lease = match store.acquire_rotation_lease(&scope.organization_id).await {
        Ok(Some(lease)) => lease,
        Ok(None) | Err(registry::RegistryError::Conflict) => {
            return public_error(
                StatusCode::CONFLICT,
                "Signing registry update is already in progress.",
            )
        }
        Err(error) => return public_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()),
    };
    let saved = async {
        let snapshot = store
            .load_with_revision_snapshot(&scope.organization_id)
            .await?;
        let existing = &snapshot.registry;
        if expected_revision
            .as_deref()
            .is_some_and(|expected| expected != snapshot.etag.as_str())
        {
            return Err(registry::RegistryError::PreconditionFailed);
        }
        preserve_unchanged_auth_references(&mut body, existing);
        if let Some(config) = body.as_object_mut() {
            let bindings = config
                .entry("key_reference_purposes")
                .or_insert_with(|| json!({}));
            if !bindings.is_object() {
                *bindings = json!({});
            }
            bindings["managed-openbao-transit"] = existing
                .pointer("/key_reference_purposes/managed-openbao-transit")
                .cloned()
                .unwrap_or_else(|| json!({}));
        }
        let (normalized, new_revision) = if expected_revision.is_some() {
            store
                .save_requested_if_unchanged_with_rotation_lease(
                    &scope.organization_id,
                    &body,
                    &snapshot,
                    &lease,
                )
                .await?
        } else {
            store
                .save_requested_with_rotation_lease_and_revision(
                    &scope.organization_id,
                    &body,
                    existing,
                    &lease,
                )
                .await?
        };
        Ok((
            store
                .with_managed_service(&scope.organization_id, normalized)
                .await,
            new_revision,
        ))
    }
    .await;
    let _ = lease.release().await;
    match saved {
        Ok((registry, revision)) => public_config_revision_response(&state, registry, revision),
        Err(registry::RegistryError::PreconditionFailed) => public_error(
            StatusCode::PRECONDITION_FAILED,
            "Signing registry changed since the supplied revision.",
        ),
        Err(registry::RegistryError::Conflict) => public_error(
            StatusCode::CONFLICT,
            "Signing registry update is already in progress.",
        ),
        Err(registry::RegistryError::Invalid(detail)) => {
            public_error(StatusCode::UNPROCESSABLE_ENTITY, &detail)
        }
        Err(error @ registry::RegistryError::SecretCapabilityUnavailable) => {
            registry_error(error).into_response()
        }
        Err(error) => public_error(StatusCode::SERVICE_UNAVAILABLE, &error.to_string()),
    }
}

async fn validate_public_service(Json(request): Json<ValidationRequest>) -> Response {
    Json(validation::validate(request).await).into_response()
}

// This probe uses the stored service credential. It never accepts a payload,
// returns a signature, or enters the gateway signing-grant path.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentIssuerServiceValidationRequest {
    #[serde(default)]
    organization_id: Option<String>,
    issuer_did: String,
    credential_format: String,
}

fn current_issuer_service_readiness(checks: &[validation::ValidationCheck]) -> bool {
    let passed = |name: &str| {
        checks
            .iter()
            .any(|check| check.name == name && check.status == "pass")
    };
    // Adapter verification for the supported vault-transit protocol reads the
    // existing key but intentionally does not sign or emit a Signer capability
    // check. The caller performs the actual fixed-challenge sign and verifies
    // it against that provider key after these read-only checks pass.
    passed("Key exists")
        // A sign-only token can receive 403 from lookup-self while key read and
        // signing succeed. Treat that lookup as diagnostic only.
        && !checks.iter().any(|check| check.status == "fail" && check.name != "Provider auth")
}

fn verify_current_issuer_signature(public: &Value, payload: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = PublicJwk::from_json(&public.to_string()) else {
        return false;
    };
    if key.kty != "EC" || key.crv.as_deref() != Some("P-256") {
        return false;
    }
    let (Some(x), Some(y)) = (key.x.as_deref(), key.y.as_deref()) else {
        return false;
    };
    let (Ok(x), Ok(y)) = (URL_SAFE_NO_PAD.decode(x), URL_SAFE_NO_PAD.decode(y)) else {
        return false;
    };
    if x.len() != 32 || y.len() != 32 {
        return false;
    }
    let mut point = vec![4];
    point.extend(x);
    point.extend(y);
    ecdsa::verify_p256_sha256(&point, payload, signature).ok() == Some(true)
}

async fn current_issuer_signature_verified(service: &Value) -> bool {
    // Read the existing provider key for this registry service/key_reference,
    // not the issuer profile's published JWK. Verify a fixed server-owned
    // challenge; neither the challenge selector nor signature is returned.
    const CHALLENGE: &[u8] = b"marty-current-issuer-service-readiness-v1";
    let Ok(public) = kms::public_key_existing(ProviderRequest {
        service_config: service.clone(),
    })
    .await
    else {
        return false;
    };
    let Ok(signed) = kms::sign(SignRequest {
        service_config: service.clone(),
        payload_b64: URL_SAFE_NO_PAD.encode(CHALLENGE),
    })
    .await
    else {
        return false;
    };
    if signed.signature_encoding != "der" {
        return false;
    }
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signed.signature_b64) else {
        return false;
    };
    verify_current_issuer_signature(&public, CHALLENGE, &signature)
}

fn current_issuer_profiles<'a>(
    document: &'a Value,
    issuer_did: &str,
    credential_format: &str,
) -> Vec<&'a Value> {
    document
        .get("profiles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|profile| {
            profile.get("status").and_then(Value::as_str) == Some("active")
                && profile.get("issuer_did").and_then(Value::as_str) == Some(issuer_did)
                && profile.get("credential_format").and_then(Value::as_str)
                    == Some(credential_format)
                && profile.get("key_purpose").and_then(Value::as_str) == Some("vc_jwt_issuer")
                && profile.get("algorithm").and_then(Value::as_str) == Some("ES256")
        })
        .collect()
}

fn supported_current_issuer_service(service: &Value) -> bool {
    service.get("service_type").and_then(Value::as_str) == Some("openbao-transit")
        && matches!(
            service.get("auth_mode").and_then(Value::as_str),
            Some("token" | "service_token")
        )
}

#[cfg(test)]
mod current_issuer_validation_tests;

async fn validate_current_issuer_service(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    headers: HeaderMap,
    input: Result<
        Json<CurrentIssuerServiceValidationRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> Response {
    if !authorize_service_sign(&state, &headers) {
        return public_error(
            StatusCode::UNAUTHORIZED,
            "Signing service authentication required.",
        );
    }
    let Json(input) = match input {
        Ok(input) => input,
        Err(_) => {
            return public_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid issuer validation request.",
            )
        }
    };
    if let Err(error) =
        validate_service_scope(&scope.organization_id, input.organization_id.as_deref())
    {
        return error.into_response();
    }
    if input.issuer_did.trim().is_empty()
        || !matches!(input.credential_format.as_str(), "VC_JWT" | "SD_JWT_VC")
    {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "A supported issuer tuple is required.",
        );
    }
    let Some(profiles) = state.profile_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity storage is unavailable.",
        );
    };
    let document = match profiles.list(&scope.organization_id).await {
        Ok(document) => document,
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Issuer identity storage is unavailable.",
            )
        }
    };
    let matches = current_issuer_profiles(&document, &input.issuer_did, &input.credential_format);
    let [profile] = matches.as_slice() else {
        return public_error(
            StatusCode::CONFLICT,
            "Exactly one active issuer binding is required.",
        );
    };
    let (Some(service_id), Some(key_reference)) = (
        profile.get("signing_service_id").and_then(Value::as_str),
        profile.get("signing_key_reference").and_then(Value::as_str),
    ) else {
        return public_error(
            StatusCode::CONFLICT,
            "Issuer signing binding is incomplete.",
        );
    };
    if let Err(error) = authorize_public_service_reference(
        &state,
        &scope.organization_id,
        service_id,
        key_reference,
        Some("vc_jwt_issuer"),
        Some("ES256"),
    )
    .await
    {
        return error.into_response();
    }
    let (registry, mut service) =
        match registered_service_with_registry(&state, &scope.organization_id, service_id).await {
            Ok(pair) => pair,
            Err(error) => return error.into_response(),
        };
    if !supported_current_issuer_service(&service) {
        return public_error(
            StatusCode::CONFLICT,
            "Issuer service is not supported by this probe.",
        );
    }
    let Some(service_fields) = service.as_object() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is malformed.",
        );
    };
    if let Err(error) = crate::compat::authorize_current_issuer_binding(
        &registry,
        service_fields,
        profile,
        &scope.organization_id,
        service_id,
        key_reference,
    ) {
        return error.into_response();
    }
    service["key_reference"] = json!(key_reference);
    let Some(service_config) = service.as_object().cloned() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is malformed.",
        );
    };
    let result = validation::validate(ValidationRequest {
        service_config,
        live_probe: true,
    })
    .await;
    let signature_verified = current_issuer_service_readiness(&result.checks)
        && current_issuer_signature_verified(&service).await;
    let ready = signature_verified;
    let key_read = result
        .checks
        .iter()
        .any(|check| check.name == "Key exists" && check.status == "pass");
    // Report capability only after the actual provider signature verifies.
    // The read-only vault-transit adapter does not emit a capability label.
    let signer_capable = signature_verified;
    let auth_lookup = result
        .checks
        .iter()
        .find(|check| check.name == "Provider auth")
        .map(|check| check.status.as_str())
        .unwrap_or("unavailable");
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "ok": ready, "organization_id": scope.organization_id,
            "issuer_did": input.issuer_did, "credential_format": input.credential_format,
            "service_id": service_id, "key_reference": key_reference,
            "key_purpose": "vc_jwt_issuer", "algorithm": "ES256",
            "key_read": key_read, "signer_capable": signer_capable,
        "signature_verified": signature_verified,
            "auth_lookup": auth_lookup,
        })),
    )
        .into_response()
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
        Err(profiles::ProfileError::Storage(_)) => public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity storage is unavailable.",
        ),
        Err(profiles::ProfileError::Corrupt(_)) => public_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Issuer identity storage is malformed.",
        ),
        Err(_) => public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Issuer identity filters are invalid.",
        ),
    }
}

async fn public_identity_capabilities(
    State(state): State<AppState>,
    Query(scope): Query<IssuerCapabilitiesQuery>,
) -> Response {
    if scope.organization_id.trim().is_empty() {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "organization_id is required.",
        );
    }
    let Some(store) = state.registry_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer capabilities are unavailable.",
        );
    };
    match store.load(&scope.organization_id).await {
        Ok(registry) => (
            [("cache-control", "no-store")],
            Json(crate::identity_capabilities::project(
                &scope.organization_id,
                &registry,
                state.public_domain.as_deref(),
            )),
        )
            .into_response(),
        Err(_) => public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer capabilities are unavailable.",
        ),
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

fn managed_key_binding_sha256(organization_id: &str, profile: &Value) -> Option<String> {
    let service_id = profile.get("signing_service_id")?.as_str()?;
    let key_reference = profile.get("signing_key_reference")?.as_str()?;
    let mut digest = Sha256::new();
    for value in [
        "marty-managed-key-binding-v1",
        organization_id,
        service_id,
        key_reference,
    ] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    Some(hex::encode(digest.finalize()))
}

struct CurrentManagedIssuerIdentity {
    resolved: Value,
    current_jwk: Value,
}

/// Resolve before reading the current provider key, refusing a stale profile
/// before polling the provider future. Callers keep tuple admission, algorithm
/// rules, authority and all signing/grant operations outside this read-only step.
async fn resolve_current_managed_issuer_identity(
    profile: &Value,
    resolution: impl std::future::Future<Output = Result<Value, CompatibilityError>>,
    provider_key: impl std::future::Future<Output = Result<Value, CompatibilityError>>,
) -> Result<CurrentManagedIssuerIdentity, Response> {
    let resolved = resolution.await.map_err(IntoResponse::into_response)?;
    if !same_managed_identity(profile, &resolved) {
        return Err(public_error(
            StatusCode::CONFLICT,
            "Resolved issuer identity does not match its active managed profile.",
        ));
    }
    let current_jwk = provider_key.await.map_err(IntoResponse::into_response)?;
    if !same_current_managed_key(&resolved, &current_jwk) {
        return Err(public_error(
            StatusCode::CONFLICT,
            "Published issuer identity does not match its current managed KMS key.",
        ));
    }
    Ok(CurrentManagedIssuerIdentity {
        resolved,
        current_jwk,
    })
}

#[cfg(test)]
mod current_managed_issuer_tests;

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
    let request = ResolveIssuerDidRequest {
        organization_id: scope.organization_id.clone(),
        issuer_did: input.issuer_did,
        verification_method_id: None,
        credential_format: Some(input.credential_format),
        key_purpose: Some(input.key_purpose),
        algorithm: Some(canonical_algorithm(&input.algorithm)),
    };
    let CurrentManagedIssuerIdentity { resolved, .. } =
        match resolve_current_managed_issuer_identity(
            &profile,
            compatibility.resolve_issuer_did(&request),
            compatibility.provider_public_key_for_profile(&scope.organization_id, &profile),
        )
        .await
        {
            Ok(identity) => identity,
            Err(error) => return error,
        };
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
    let Some(managed_key_binding_sha256) =
        managed_key_binding_sha256(&scope.organization_id, &profile)
    else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Managed issuer identity has no custody binding.",
        );
    };
    Json(json!({
        "identity": identity_projection(&profile),
        "public_jwk": public_jwk,
        "managed_key_binding_sha256": managed_key_binding_sha256,
    }))
    .into_response()
}

fn valid_didcomm_publication(
    publication: &PublishDidResponse,
    issuer_did: &str,
    method_id: &str,
    public_jwk: &Value,
) -> bool {
    let method = &publication.verification_method;
    let document = &publication.document;
    method.get("id").and_then(Value::as_str) == Some(method_id)
        && method.get("type").and_then(Value::as_str) == Some("JsonWebKey2020")
        && method.get("controller").and_then(Value::as_str) == Some(issuer_did)
        && method.get("publicKeyJwk") == Some(public_jwk)
        && document.get("id").and_then(Value::as_str) == Some(issuer_did)
        && document
            .get("verificationMethod")
            .and_then(Value::as_array)
            .is_some_and(|methods| methods.contains(method))
        && document
            .get("keyAgreement")
            .and_then(Value::as_array)
            .is_some_and(|methods| methods.contains(&json!(method_id)))
}

async fn create_public_issuer_identity(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    headers: HeaderMap,
    Json(input): Json<IssuerIdentityRequest>,
) -> Response {
    let expected_registry_revision = match strong_config_if_match(&headers) {
        Ok(revision) => revision,
        Err(()) => {
            return public_error(
                StatusCode::BAD_REQUEST,
                "If-Match must be one strong registry revision.",
            )
        }
    };
    if let Err(error) = validate_identity_scope(&scope.organization_id, &input) {
        return error.into_response();
    }
    if let Err(error) = validate_identity_operation_fields(&input, true, false) {
        return error.into_response();
    }
    if !crate::identity_capabilities::supports_tuple(
        &input.key_purpose,
        &input.credential_format,
        &canonical_algorithm(&input.algorithm),
    ) {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Issuer purpose, credential format and algorithm are incompatible.",
        );
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
                expected_registry_revision: expected_registry_revision.clone(),
            })
            .await
        {
            Ok(repaired) => repaired
                .get("profile")
                .map(|profile| {
                    Json(
                        json!({"identity": identity_projection(profile), "created": false,
                        "config_revision": repaired.get("config_revision")}),
                    )
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
                expected_registry_revision,
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
                "created": created.get("created").and_then(Value::as_bool).unwrap_or(true),
                "config_revision": created.get("config_revision")
            }))
            .into_response()
        }
        Err(error) => error.into_response(),
    }
}

async fn rebind_public_issuer_identity(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    headers: HeaderMap,
    Json(input): Json<IssuerIdentityRequest>,
) -> Response {
    let expected_registry_revision = match strong_config_if_match(&headers) {
        Ok(revision) => revision,
        Err(()) => {
            return public_error(
                StatusCode::BAD_REQUEST,
                "If-Match must be one strong registry revision.",
            )
        }
    };
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
        .rebind_profile_to_default(
            &scope.organization_id,
            profile_id,
            &key_reference,
            expected_registry_revision.as_deref(),
        )
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
                "changed": result.get("changed").and_then(Value::as_bool).unwrap_or(false),
                "config_revision": result.get("config_revision")
            }))
            .into_response()
        }
        Err(error) => error.into_response(),
    }
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

async fn registered_service_with_registry(
    state: &AppState,
    organization_id: &str,
    service_id: &str,
) -> Result<(Value, Value), PublicSigningError> {
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
    Ok((registry, service))
}

async fn registered_service(
    state: &AppState,
    organization_id: &str,
    service_id: &str,
) -> Result<Value, PublicSigningError> {
    registered_service_with_registry(state, organization_id, service_id)
        .await
        .map(|(_, service)| service)
}

fn service_supports_issuer_value(service: &Value, field: &str, requested: &str) -> bool {
    if field == "credential_formats"
        && !crate::domain::explicit_format_allowed(service.get(field), requested)
    {
        return false;
    }
    service
        .get(field)
        .and_then(Value::as_array)
        .is_none_or(|values| {
            values.is_empty() || values.iter().any(|value| value.as_str() == Some(requested))
        })
}

async fn validated_issuer_service(
    state: &AppState,
    organization_id: &str,
    profile: &Value,
    credential_format: &str,
    key_purpose: &str,
    algorithm: &str,
) -> Result<(), PublicSigningError> {
    let service_id = profile
        .get("signing_service_id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .ok_or_else(|| {
            public_failure(
                StatusCode::NOT_FOUND,
                "No active issuer identity matches the requested tuple.",
            )
        })?;
    let (registry, mut service) =
        registered_service_with_registry(state, organization_id, service_id)
            .await
            .map_err(|error| {
                if error.status == StatusCode::NOT_FOUND {
                    public_failure(
                        StatusCode::NOT_FOUND,
                        "No active issuer identity matches the requested tuple.",
                    )
                } else {
                    error
                }
            })?;
    let wire_format = profiles::custody_format(&CustodyFormatRequest {
        credential_format: credential_format.to_owned(),
        key_purpose: key_purpose.to_owned(),
    })
    .map_err(|error| public_failure(StatusCode::UNPROCESSABLE_ENTITY, &error.to_string()))?
    .wire_format;
    if !service_supports_issuer_value(&service, "credential_formats", &wire_format)
        || !service_supports_issuer_value(&service, "key_purposes", key_purpose)
        || !service_supports_issuer_value(&service, "algorithms", algorithm)
    {
        return Err(public_failure(
            StatusCode::NOT_FOUND,
            "No active issuer identity matches the requested tuple.",
        ));
    }
    let key_reference = profile
        .get("signing_key_reference")
        .and_then(Value::as_str)
        .filter(|reference| !reference.trim().is_empty())
        .ok_or_else(|| {
            public_failure(
                StatusCode::NOT_FOUND,
                "No active issuer identity matches the requested tuple.",
            )
        })?;
    service["key_reference"] = json!(key_reference);
    profiles::validate_binding(&ValidateBindingRequest {
        profile: profile.clone(),
        service,
        registry,
    })
    .map_err(|_| {
        public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Issuer signing service binding is incompatible.",
        )
    })
}

async fn registered_certificate_service(
    state: &AppState,
    organization_id: &str,
    service_id: &str,
) -> Result<Value, PublicSigningError> {
    let service = registered_service(state, organization_id, service_id).await?;
    if service_id == "managed-openbao-transit" {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Managed signing keys require an issuer-scoped certificate identity.",
        ));
    }
    Ok(service)
}

async fn sign_public_service_payload(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
    headers: HeaderMap,
    input: Result<Json<PublicServiceSignRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !authorize_service_sign(&state, &headers) {
        return public_error(
            StatusCode::UNAUTHORIZED,
            "Signing service authentication required.",
        );
    }
    let Json(input) = match input {
        Ok(input) => input,
        Err(error) => {
            return public_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("Invalid signing request: {error}"),
            );
        }
    };
    if let Err(error) =
        validate_service_scope(&scope.organization_id, input.organization_id.as_deref())
    {
        return error.into_response();
    }
    let Some(header) = headers
        .get(HEADER_NAME)
        .and_then(|value| value.to_str().ok())
    else {
        return public_error(StatusCode::UNAUTHORIZED, "Signing grant required.");
    };
    let Ok(envelope) = GrantEnvelope::from_header_value(header) else {
        return public_error(StatusCode::UNAUTHORIZED, "Signing grant is invalid.");
    };
    let Some(service) = state.compatibility.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing service is unavailable.",
        );
    };
    if let Some(reference) = input
        .key_reference
        .as_deref()
        .map(str::trim)
        .filter(|reference| !reference.is_empty())
    {
        if let Err(error) = authorize_public_service_reference(
            &state,
            &scope.organization_id,
            &service_id,
            reference,
            input.key_purpose.as_deref(),
            input.algorithm.as_deref(),
        )
        .await
        {
            return error.into_response();
        }
    }
    let (Some(key_reference), Some(key_purpose), Some(algorithm)) = (
        input.key_reference.as_deref(),
        input.key_purpose.as_deref(),
        input.algorithm.as_deref(),
    ) else {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "A bound signing key, purpose, and algorithm are required.",
        );
    };
    let payload = match crate::compat::signing_payload(
        input.payload_b64.as_deref(),
        input.payload_hex.as_deref(),
    ) {
        Ok(payload) => payload,
        Err(_) => {
            return public_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "A valid signing payload is required.",
            )
        }
    };
    let route = format!("/v1/signing-keys/services/{service_id}/sign");
    let binding = GrantBinding {
        origin: SigningOrigin::GatewayService,
        operation_id: &envelope.claims.operation_id,
        organization_id: &scope.organization_id,
        route: &route,
        service_id: Some(&service_id),
        issuer_did: None,
        key_reference: Some(key_reference),
        key_purpose,
        algorithm,
        payload: &payload,
    };
    let consumed = match consume_bound_signing_grant(&state, header, &binding).await {
        Ok(consumed) => consumed,
        Err(GrantAuthorizationError::Denied) => {
            return public_error(StatusCode::UNAUTHORIZED, "Signing grant is denied.")
        }
        Err(GrantAuthorizationError::Unavailable) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing grant verifier is unavailable.",
            )
        }
    };
    let request = ServiceSignRequest {
        organization_id: scope.organization_id,
        payload_b64: input.payload_b64,
        payload_hex: input.payload_hex,
        algorithm: input.algorithm,
        key_reference: input.key_reference,
        key_purpose: input.key_purpose,
    };
    let authorization = SignAuthorization::grant(consumed, route, None);
    match service
        .sign_with_service(&service_id, &request, authorization)
        .await
    {
        Ok(signed) => Json(signed).into_response(),
        Err(error) => error.into_response(),
    }
}

fn vdsnc_registration_fields(
    organization_id: &str,
    input: &PublicVdsncRegistrationRequest,
) -> Result<(String, String, String, i64, String), &'static str> {
    let country = input.country_code.trim().to_ascii_uppercase();
    if !(2..=3).contains(&country.len()) || !country.bytes().all(|byte| byte.is_ascii_alphabetic())
    {
        return Err("country_code must contain two or three ASCII letters.");
    }
    let authority = input.authority_name.trim();
    if authority.is_empty() || authority.len() > 200 || authority.chars().any(char::is_control) {
        return Err("authority_name must be a nonempty name of at most 200 bytes.");
    }
    let role = input
        .role
        .as_deref()
        .unwrap_or("dsc")
        .trim()
        .to_ascii_lowercase();
    if role.is_empty()
        || role.len() > 32
        || !role
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err("role must be an ASCII identifier of at most 32 bytes.");
    }
    let generation = input.generation.filter(|value| *value != 0).unwrap_or(1);
    if !(1..=1_000_000).contains(&generation) {
        return Err("generation must be between 1 and 1000000.");
    }
    let reference = input
        .key_reference
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            let tenant =
                uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, organization_id.as_bytes()).simple();
            format!("cred:vdsnc:{tenant}:{country}:{role}:{generation}")
        });
    if reference.len() > 512 || reference.chars().any(char::is_control) {
        return Err("key_reference must be an opaque KMS reference of at most 512 bytes.");
    }
    Ok((country, authority.to_owned(), role, generation, reference))
}

async fn register_public_vdsnc_service(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    Json(input): Json<PublicVdsncRegistrationRequest>,
) -> Response {
    if let Err(error) =
        validate_service_scope(&scope.organization_id, input.organization_id.as_deref())
    {
        return error.into_response();
    }
    let (country, authority, role, generation, key_reference) =
        match vdsnc_registration_fields(&scope.organization_id, &input) {
            Ok(fields) => fields,
            Err(message) => return public_error(StatusCode::UNPROCESSABLE_ENTITY, message),
        };
    let Some(store) = state.registry_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        );
    };
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let service_id = format!(
        "svc-vdsnc-{}-{}",
        country.to_ascii_lowercase(),
        &suffix[..8]
    );
    let service = json!({
        "id": service_id,
        "name": format!("VDS-NC {country} {authority}"),
        "service_type": input.service_type.as_deref().unwrap_or("custom-transit-compatible"),
        "provider": input.provider.as_deref().unwrap_or("custom"),
        "endpoint": input.endpoint.as_deref().unwrap_or(""),
        "mount": input.mount.as_deref().unwrap_or("transit"),
        "namespace": input.namespace.as_deref().unwrap_or(""),
        "auth_mode": input.auth_mode.as_deref().unwrap_or("token"),
        "auth_reference": input.auth_reference.as_deref().unwrap_or(""),
        "key_reference": key_reference,
        "algorithms": input.algorithms.as_deref().unwrap_or(&["ES256".to_owned()]),
        "key_purposes": ["vdsnc_signing"],
        "credential_formats": ["mso_mdoc", "vds_nc"],
        "country_code": country,
        "authority_name": authority,
        "discovered_capabilities": {
            "vdsnc_namespaced_key_reference": key_reference,
            "vdsnc_role": role,
            "vdsnc_generation": generation
        }
    });
    let normalized = match registry::normalize_service(NormalizeServiceRequest { service }) {
        Ok(NormalizeServiceResponse {
            service: Some(service),
        }) => service,
        _ => {
            return public_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "VDS-NC signing service configuration is invalid.",
            )
        }
    };
    if normalized.get("auth_mode").and_then(Value::as_str) == Some("service_token") {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "VDS-NC registration requires tenant-provided KMS credentials.",
        );
    }
    let lease = match store.acquire_rotation_lease(&scope.organization_id).await {
        Ok(Some(lease)) => lease,
        Ok(None) => {
            return public_error(
                StatusCode::CONFLICT,
                "Signing registry is being updated. Retry VDS-NC registration.",
            )
        }
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing registry is unavailable.",
            )
        }
    };
    let mut registry = match store.load(&scope.organization_id).await {
        Ok(registry) => registry,
        Err(_) => {
            let _ = lease.release().await;
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing registry is unavailable.",
            );
        }
    };
    let Some(services) = registry.get_mut("services").and_then(Value::as_array_mut) else {
        let _ = lease.release().await;
        return public_error(StatusCode::BAD_GATEWAY, "Signing registry is malformed.");
    };
    services.push(normalized);
    if registry
        .get("default_service_id")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        registry["default_service_id"] = json!(service_id);
    }
    let saved = store
        .save_with_rotation_lease(&scope.organization_id, &registry, &lease)
        .await;
    let _ = lease.release().await;
    let saved = match saved {
        Ok(saved) => saved,
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing registry could not be saved.",
            )
        }
    };
    let Some(registered) = saved
        .get("services")
        .and_then(Value::as_array)
        .and_then(|services| {
            services
                .iter()
                .find(|service| service.get("id").and_then(Value::as_str) == Some(&service_id))
        })
    else {
        return public_error(
            StatusCode::BAD_GATEWAY,
            "Signing registry did not retain the service.",
        );
    };
    Json(json!({
        "ok": true,
        "service": public_service_config(registered),
        "registered_at": chrono::Utc::now().to_rfc3339(),
    }))
    .into_response()
}

async fn rotate_public_service_key(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
    body: Option<Json<PublicServiceRotationRequest>>,
) -> Response {
    let body = body.map(|Json(body)| body).unwrap_or_default();
    if let Err(error) =
        validate_service_scope(&scope.organization_id, body.organization_id.as_deref())
    {
        return error.into_response();
    }
    let overlap_days = body.overlap_days.filter(|days| *days != 0).unwrap_or(7);
    if !(0..=3650).contains(&overlap_days) {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "overlap_days must be between 0 and 3650.",
        );
    }
    if let Some(activate_at) = body.activate_at.as_deref() {
        let parsed = match chrono::DateTime::parse_from_rfc3339(activate_at) {
            Ok(parsed) => parsed,
            Err(_) => {
                return public_error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "activate_at must be an RFC 3339 timestamp.",
                )
            }
        };
        if parsed > chrono::Utc::now() {
            return public_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Future activation is not supported by immediate KMS rotation.",
            );
        }
    }
    let Some(store) = state.registry_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        );
    };
    let lease = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        store.acquire_rotation_lease(&scope.organization_id),
    )
    .await
    {
        Ok(Ok(Some(lease))) => lease,
        Ok(Ok(None)) => {
            return public_error(
                StatusCode::CONFLICT,
                "Signing service rotation is already in progress.",
            )
        }
        _ => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing registry is unavailable.",
            )
        }
    };
    macro_rules! finish_with_lease {
        ($response:expr) => {{
            let response = $response;
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), lease.release()).await;
            return response;
        }};
    }
    let registry_timeout = std::time::Duration::from_secs(15);
    let registry =
        match tokio::time::timeout(registry_timeout, store.load(&scope.organization_id)).await {
            Ok(Ok(registry)) => registry,
            _ => {
                finish_with_lease!(public_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Signing registry is unavailable.",
                ))
            }
        };
    let Some(service) = registry
        .get("services")
        .and_then(Value::as_array)
        .and_then(|services| {
            services
                .iter()
                .find(|service| service.get("id").and_then(Value::as_str) == Some(&service_id))
        })
        .cloned()
    else {
        finish_with_lease!(public_error(
            StatusCode::NOT_FOUND,
            "Signing service not found."
        ));
    };
    if service_id == "managed-openbao-transit"
        || service.get("managed").and_then(Value::as_bool) == Some(true)
        || service.get("read_only").and_then(Value::as_bool) == Some(true)
    {
        finish_with_lease!(public_error(
            StatusCode::FORBIDDEN,
            "Managed or read-only signing services cannot be rotated through this route.",
        ));
    }
    let now = chrono::Utc::now();
    let rotated_at = now.to_rfc3339();
    let rotation_state = service
        .get("rotation_state")
        .filter(|state| state.is_object())
        .cloned()
        .unwrap_or_else(|| json!({}));
    let unrotated = |error: &str, state: Value| {
        let mut state = state;
        state["provider_rotation"] = json!({"ok": false, "error": error});
        Json(json!({
            "ok": false,
            "service_id": service_id,
            "rotation_state": state,
            "publication": {"jwks": false, "did": false},
            "rotated_at": null,
            "note": "Provider rotation did not complete; no rotation state was stored."
        }))
        .into_response()
    };
    if !matches!(
        service.get("service_type").and_then(Value::as_str),
        Some("openbao-transit" | "hashicorp-vault-transit" | "custom-transit-compatible")
    ) {
        finish_with_lease!(unrotated(
            "No provider rotation adapter available.",
            rotation_state
        ));
    }
    let key_reference = service
        .get("key_reference")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|reference| !reference.is_empty());
    let Some(key_reference) = key_reference else {
        finish_with_lease!(unrotated(
            "key_reference is required for rotation.",
            rotation_state
        ));
    };
    match store
        .rotation_marker(&scope.organization_id, &service)
        .await
    {
        Ok(Some(_)) => {
            finish_with_lease!(public_error(
                StatusCode::CONFLICT,
                "KMS rotation requires reconciliation before another attempt.",
            ))
        }
        Ok(None) => {}
        Err(_) => {
            finish_with_lease!(public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing registry is unavailable.",
            ))
        }
    }
    if rotation_state
        .get("reconcile_required")
        .is_some_and(|value| !value.is_null())
    {
        finish_with_lease!(public_error(
            StatusCode::CONFLICT,
            "KMS rotation requires reconciliation before another attempt.",
        ));
    }
    let global_fence = match store.acquire_global_rotation_fence(&lease).await {
        Ok(Some(fence)) => fence,
        Ok(None) => finish_with_lease!(public_error(
            StatusCode::CONFLICT,
            "Another signing service rotation is in progress.",
        )),
        Err(_) => finish_with_lease!(public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing rotation ownership check is unavailable.",
        )),
    };
    let ownership = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        store.ensure_exclusive_rotation_identity(&scope.organization_id, &service, &global_fence),
    )
    .await;
    if !matches!(ownership, Ok(Ok(()))) {
        let _ = global_fence.release().await;
        finish_with_lease!(public_error(
            if matches!(ownership, Ok(Err(registry::RegistryError::Conflict))) {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            "The KMS key is not exclusively bound to this tenant for rotation.",
        ));
    }
    if !renew_rotation_fences(&lease, &global_fence).await {
        let _ = global_fence.release().await;
        finish_with_lease!(public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing rotation ownership check expired before KMS use.",
        ));
    }
    let publish_updates = body.publish_updates.unwrap_or(true);
    let activate_at = body.activate_at.unwrap_or_else(|| rotated_at.clone());
    let task_store = store.clone();
    let task_organization_id = scope.organization_id.clone();
    let task_service_id = service_id.clone();
    let key_reference = key_reference.to_owned();
    let completed = tokio::spawn(async move {
        rotate_and_record_public_service(
            task_store,
            lease,
            global_fence,
            task_organization_id,
            task_service_id,
            registry,
            service,
            rotation_state,
            key_reference,
            now,
            rotated_at,
            overlap_days,
            activate_at,
            publish_updates,
        )
        .await
    })
    .await;
    let (rotation_state, rotated_at) = match completed {
        Ok(Ok(completed)) => completed,
        Ok(Err(response)) => return response,
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "KMS rotation outcome is uncertain; reconcile before retrying.",
            )
        }
    };
    let mut publication = json!({"jwks": false, "did": false});
    if publish_updates {
        publication["jwks"] = json!(publish_public_service_jwks(
            State(state.clone()),
            Path(service_id.clone()),
            Query(OrganizationScope {
                organization_id: scope.organization_id.clone()
            }),
            None,
        )
        .await
        .status()
        .is_success());
        publication["did"] = json!(publish_public_service_did_vm(
            State(state),
            Path(service_id.clone()),
            Query(OrganizationScope {
                organization_id: scope.organization_id
            }),
            None,
        )
        .await
        .status()
        .is_success());
    }
    Json(json!({
        "ok": true,
        "service_id": service_id,
        "rotation_state": rotation_state,
        "publication": publication,
        "rotated_at": rotated_at,
        "note": "Provider rotation completed; publication may require renewed certificate material."
    }))
    .into_response()
}

fn registered_service_mut<'a>(registry: &'a mut Value, service_id: &str) -> Option<&'a mut Value> {
    registry
        .get_mut("services")
        .and_then(Value::as_array_mut)
        .and_then(|services| {
            services
                .iter_mut()
                .find(|service| service.get("id").and_then(Value::as_str) == Some(service_id))
        })
}

async fn renew_rotation_fences(tenant: &RotationLease, global: &RotationLease) -> bool {
    matches!(tenant.renew().await, Ok(true)) && matches!(global.renew().await, Ok(true))
}

async fn registry_rotation_reconcile_status(
    State(state): State<AppState>,
    Path((organization_id, service_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if authorize_internal(&state, &headers).is_err() {
        return public_error(
            StatusCode::UNAUTHORIZED,
            "Invalid internal signing API key.",
        );
    }
    let Some(store) = state.registry_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        );
    };
    let indexed = match store
        .rotation_markers_for_service(&organization_id, &service_id)
        .await
    {
        Ok(indexed) => indexed,
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Rotation marker is unavailable.",
            )
        }
    };
    if let Some(marker) = indexed.first() {
        let operations = indexed
            .iter()
            .map(|marker| {
                json!({
                    "operation_id": marker["operation_id"],
                    "service_id": marker["service_id"],
                    "started_at": marker["started_at"],
                    "baseline_version": marker["baseline_version"],
                })
            })
            .collect::<Vec<_>>();
        return Json(json!({
            "reconcile_required": true,
            "operation_id": marker["operation_id"],
            "service_id": marker["service_id"],
            "started_at": marker["started_at"],
            "baseline_version": marker["baseline_version"],
            "operations": operations,
            "note": "Restore the original registered KMS identity before reconciliation if the service was rebound."
        })).into_response();
    }
    let registry = match store.load(&organization_id).await {
        Ok(registry) => registry,
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing registry is unavailable.",
            )
        }
    };
    let Some(service) = registry
        .get("services")
        .and_then(Value::as_array)
        .and_then(|services| services.iter().find(|service| service["id"] == service_id))
    else {
        return public_error(StatusCode::NOT_FOUND, "Signing service not found.");
    };
    match store.rotation_marker(&organization_id, service).await {
        Ok(Some(marker)) => Json(json!({
            "reconcile_required": true,
            "operation_id": marker["operation_id"],
            "service_id": marker["service_id"],
            "started_at": marker["started_at"],
            "baseline_version": marker["baseline_version"],
        }))
        .into_response(),
        Ok(None) => Json(json!({"reconcile_required": false})).into_response(),
        Err(_) => public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Rotation marker is unavailable.",
        ),
    }
}

async fn reconcile_registry_rotation(
    State(state): State<AppState>,
    Path((organization_id, service_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(request): Json<RotationReconcileRequest>,
) -> Response {
    if authorize_internal(&state, &headers).is_err() {
        return public_error(
            StatusCode::UNAUTHORIZED,
            "Invalid internal signing API key.",
        );
    }
    let Some(store) = state.registry_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        );
    };
    let lease = match store.acquire_rotation_lease(&organization_id).await {
        Ok(Some(lease)) => lease,
        Ok(None) | Err(registry::RegistryError::Conflict) => {
            return public_error(
                StatusCode::CONFLICT,
                "Signing registry update is already in progress.",
            )
        }
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing registry is unavailable.",
            )
        }
    };
    let outcome = async {
        let mut registry = store.load(&organization_id).await.map_err(|_| {
            public_error(StatusCode::SERVICE_UNAVAILABLE, "Signing registry is unavailable.")
        })?;
        let service = registry
            .get("services")
            .and_then(Value::as_array)
            .and_then(|services| services.iter().find(|service| service["id"] == service_id))
            .cloned()
            .ok_or_else(|| public_error(StatusCode::NOT_FOUND, "Signing service not found."))?;
        let indexed = store
            .rotation_markers_for_service(&organization_id, &service_id)
            .await
            .map_err(|_| public_error(StatusCode::SERVICE_UNAVAILABLE, "Rotation marker is unavailable."))?;
        let marker = store
            .rotation_marker(&organization_id, &service)
            .await
            .map_err(|_| public_error(StatusCode::SERVICE_UNAVAILABLE, "Rotation marker is unavailable."))?
            .ok_or_else(|| {
                if !indexed.is_empty() {
                    public_error(StatusCode::CONFLICT, "Restore the original registered KMS identity before reconciliation.")
                } else {
                    public_error(StatusCode::NOT_FOUND, "No unresolved rotation exists for this KMS key.")
                }
            })?;
        if marker["operation_id"] != request.operation_id || marker["service_id"] != service_id {
            return Err(public_error(StatusCode::CONFLICT, "Rotation operation or service does not match the unresolved KMS key."));
        }
        let baseline = marker["baseline_version"].as_u64().ok_or_else(|| {
            public_error(StatusCode::CONFLICT, "Rotation baseline is unavailable; keep the KMS key blocked.")
        })?;
        let started_at = marker["started_at"]
            .as_str()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .ok_or_else(|| public_error(StatusCode::CONFLICT, "Rotation timestamp is invalid; keep the KMS key blocked."))?;
        if chrono::Utc::now().signed_duration_since(started_at).num_seconds() < 30 {
            return Err(public_error(StatusCode::CONFLICT, "Wait for the uncertain KMS request to settle before reconciliation."));
        }
        let first = kms::openbao_latest_version(ProviderRequest { service_config: service.clone() })
            .await
            .map_err(|_| public_error(StatusCode::SERVICE_UNAVAILABLE, "KMS key version is unavailable; keep the key blocked."))?;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let second = kms::openbao_latest_version(ProviderRequest { service_config: service.clone() })
            .await
            .map_err(|_| public_error(StatusCode::SERVICE_UNAVAILABLE, "KMS key version is unavailable; keep the key blocked."))?;
        if first != second || Some(second) != baseline.checked_add(1) {
            return Err(public_error(StatusCode::CONFLICT, "KMS version does not prove exactly one completed rotation; keep the key blocked and review OpenBao audit evidence."));
        }
        if service["rotation_state"]["provider_rotation"]["operation_id"]
            == request.operation_id
        {
            store
                .clear_rotation_marker(&organization_id, &service, &marker, &lease)
                .await
                .map_err(|_| public_error(StatusCode::SERVICE_UNAVAILABLE, "Rotation marker could not be cleared; keep the key blocked."))?;
            return Ok(Json(json!({
                "ok": true,
                "service_id": service_id,
                "operation_id": request.operation_id,
                "rotation_state": service["rotation_state"],
                "republication_required": true,
                "note": "Verify the current KMS public key, replace stale certificate material, and revalidate JWKS/DID publication."
            })).into_response());
        }
        let overlap_days = marker["overlap_days"].as_i64().ok_or_else(|| {
            public_error(StatusCode::CONFLICT, "Rotation overlap is unavailable; keep the key blocked.")
        })?;
        let mut rotation_state = marker["prior_rotation_state"].clone();
        if !rotation_state.is_object() {
            return Err(public_error(StatusCode::CONFLICT, "Prior rotation state is malformed; keep the key blocked."));
        }
        let previous = json!({
            "key_reference": marker["key_reference"],
            "retire_after": (started_at.with_timezone(&chrono::Utc) + chrono::Duration::days(overlap_days)).to_rfc3339(),
            "recorded_at": marker["started_at"],
        });
        if let Some(versions) = rotation_state.get_mut("previous_versions").and_then(Value::as_array_mut) {
            versions.push(previous);
        } else {
            rotation_state["previous_versions"] = json!([previous]);
        }
        rotation_state["last_rotated_at"] = marker["started_at"].clone();
        rotation_state["activate_at"] = marker["activate_at"].clone();
        rotation_state["overlap_days"] = json!(overlap_days);
        rotation_state["provider_rotation"] = json!({"ok": true, "version": second, "operation_id": request.operation_id, "reconciled": true});
        let recorded = registered_service_mut(&mut registry, &service_id)
            .ok_or_else(|| public_error(StatusCode::NOT_FOUND, "Signing service not found."))?;
        recorded["rotation_state"] = rotation_state.clone();
        recorded["rotation_policy"]["overlap_days"] = json!(overlap_days);
        recorded["rotation_policy"]["auto_publish"] = marker["publish_updates"].clone();
        recorded["updated_at"] = json!(chrono::Utc::now().to_rfc3339());
        store.save_with_rotation_lease(&organization_id, &registry, &lease).await
            .map_err(|_| public_error(StatusCode::SERVICE_UNAVAILABLE, "Reconciled rotation could not be saved; keep the key blocked."))?;
        store.clear_rotation_marker(&organization_id, &service, &marker, &lease).await
            .map_err(|_| public_error(StatusCode::SERVICE_UNAVAILABLE, "Rotation marker could not be cleared; keep the key blocked."))?;
        Ok(Json(json!({
            "ok": true,
            "service_id": service_id,
            "operation_id": request.operation_id,
            "rotation_state": rotation_state,
            "republication_required": true,
            "note": "Verify the current KMS public key, replace stale certificate material, and revalidate JWKS/DID publication."
        })).into_response())
    }.await;
    let _ = lease.release().await;
    outcome.unwrap_or_else(|response| response)
}

#[allow(clippy::too_many_arguments)]
async fn rotate_and_record_public_service(
    store: RegistryStore,
    lease: RotationLease,
    global_fence: RotationLease,
    organization_id: String,
    service_id: String,
    mut registry: Value,
    service: Value,
    mut rotation_state: Value,
    key_reference: String,
    now: chrono::DateTime<chrono::Utc>,
    rotated_at: String,
    overlap_days: i64,
    activate_at: String,
    publish_updates: bool,
) -> Result<(Value, String), Response> {
    let registry_timeout = std::time::Duration::from_secs(15);
    let outcome = async {
        let prior_state = rotation_state.clone();
        let baseline_version = match kms::openbao_latest_version(ProviderRequest {
            service_config: service.clone(),
        })
        .await
        {
            Ok(version) => version,
            Err(error) => {
                if matches!(
                    error,
                    kms::KmsError::InvalidConfig(_)
                        | kms::KmsError::UnsupportedProvider(_)
                        | kms::KmsError::ProviderStatus {
                            status: StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN,
                            ..
                        }
                ) {
                    let mut reported_state = prior_state.clone();
                    reported_state["provider_rotation"] = json!({
                        "ok": false,
                        "error": "Transit provider rotation failed."
                    });
                    return Err(Json(json!({
                        "ok": false, "service_id": service_id,
                        "rotation_state": reported_state,
                        "publication": {"jwks": false, "did": false},
                        "rotated_at": null,
                        "note": "Provider rotation did not complete; no rotation state was stored."
                    }))
                    .into_response());
                }
                return Err(public_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "KMS key version could not be read; KMS was not called for rotation.",
                ))
            }
        };
        let marker = json!({
            "operation_id": uuid::Uuid::new_v4().to_string(),
            "started_at": rotated_at,
            "key_reference": key_reference,
            "service_id": service_id,
            "baseline_version": baseline_version,
            "prior_rotation_state": prior_state,
            "overlap_days": overlap_days,
            "activate_at": activate_at,
            "publish_updates": publish_updates,
        });
        rotation_state["reconcile_required"] = marker.clone();
        let recorded = registered_service_mut(&mut registry, &service_id).ok_or_else(|| {
            public_error(StatusCode::BAD_GATEWAY, "Signing registry is malformed.")
        })?;
        recorded["rotation_state"] = rotation_state.clone();
        if !matches!(
            tokio::time::timeout(
                registry_timeout,
                store.save_pending_rotation_with_marker(
                    &organization_id,
                    &service,
                    &registry,
                    &marker,
                    &lease,
                )
            )
            .await,
            Ok(Ok(_))
        ) {
            return Err(public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Pending rotation storage is uncertain; KMS was not called. Check reconciliation status before retrying.",
            ));
        }
        if !renew_rotation_fences(&lease, &global_fence).await {
            return Err(public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Rotation ownership expired before the KMS request; reconcile before retrying.",
            ));
        }
        let provider_rotation = match kms::rotate_openbao(ProviderRequest {
            service_config: service.clone(),
        })
        .await
        {
            Ok(result) => result,
            Err(error) => {
                let definitely_unrotated = matches!(
                    error,
                    kms::KmsError::InvalidConfig(_)
                        | kms::KmsError::UnsupportedProvider(_)
                        | kms::KmsError::ProviderStatus {
                            status: StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN,
                            ..
                        }
                );
                if definitely_unrotated {
                    if !renew_rotation_fences(&lease, &global_fence).await {
                        return Err(public_error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Rotation ownership expired; reconcile before retrying.",
                        ));
                    }
                    if let Some(recorded) = registered_service_mut(&mut registry, &service_id) {
                        recorded["rotation_state"] = prior_state.clone();
                    }
                    if matches!(
                        tokio::time::timeout(
                            registry_timeout,
                            store.save_with_rotation_lease(&organization_id, &registry, &lease)
                        )
                        .await,
                        Ok(Ok(_))
                    ) {
                        if store
                            .clear_rotation_marker(&organization_id, &service, &marker, &lease)
                            .await
                            .is_err()
                        {
                            return Err(public_error(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "KMS rotation marker could not be cleared; reconcile before retrying.",
                            ));
                        }
                        let mut reported_state = prior_state.clone();
                        reported_state["provider_rotation"] = json!({
                            "ok": false,
                            "error": "Transit provider rotation failed."
                        });
                        return Err(Json(json!({
                            "ok": false, "service_id": service_id,
                            "rotation_state": reported_state,
                            "publication": {"jwks": false, "did": false},
                            "rotated_at": null,
                            "note": "Provider rotation did not complete; no rotation state was stored."
                        }))
                        .into_response());
                    }
                }
                return Err(public_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "KMS rotation outcome requires reconciliation before retrying.",
                ));
            }
        };
        if provider_rotation
            .get("version")
            .and_then(Value::as_u64)
            != baseline_version.checked_add(1)
        {
            return Err(public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "KMS rotation version is uncertain; reconcile before retrying.",
            ));
        }
        if !renew_rotation_fences(&lease, &global_fence).await {
            return Err(public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Rotation ownership expired after the KMS request; reconcile before retrying.",
            ));
        }
        rotation_state = prior_state;
        let previous_version = json!({
            "key_reference": key_reference,
            "retire_after": (now + chrono::Duration::days(overlap_days)).to_rfc3339(),
            "recorded_at": rotated_at,
        });
        if let Some(previous) = rotation_state
            .get_mut("previous_versions")
            .and_then(Value::as_array_mut)
        {
            previous.push(previous_version);
        } else {
            rotation_state["previous_versions"] = json!([previous_version]);
        }
        rotation_state["last_rotated_at"] = json!(rotated_at);
        rotation_state["activate_at"] = json!(activate_at);
        rotation_state["overlap_days"] = json!(overlap_days);
        rotation_state["provider_rotation"] = provider_rotation;
        rotation_state["provider_rotation"]["operation_id"] = marker["operation_id"].clone();
        let recorded = registered_service_mut(&mut registry, &service_id).ok_or_else(|| {
            public_error(StatusCode::BAD_GATEWAY, "Signing registry is malformed.")
        })?;
        recorded["rotation_state"] = rotation_state.clone();
        recorded["rotation_policy"]["overlap_days"] = json!(overlap_days);
        recorded["rotation_policy"]["auto_publish"] = json!(publish_updates);
        recorded["updated_at"] = json!(rotated_at);
        if !matches!(
            tokio::time::timeout(
                registry_timeout,
                store.save_with_rotation_lease(&organization_id, &registry, &lease)
            )
            .await,
            Ok(Ok(_))
        ) {
            return Err(public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "The KMS key rotated, but its registry state could not be stored; reconcile before retrying.",
            ));
        }
        if store
            .clear_rotation_marker(&organization_id, &service, &marker, &lease)
            .await
            .is_err()
        {
            return Err(public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "KMS rotation marker could not be cleared; reconcile before retrying.",
            ));
        }
        Ok((rotation_state, rotated_at))
    }
    .await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), global_fence.release()).await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), lease.release()).await;
    outcome
}

async fn authorize_public_service_reference(
    state: &AppState,
    organization_id: &str,
    service_id: &str,
    reference: &str,
    key_purpose: Option<&str>,
    algorithm: Option<&str>,
) -> Result<(), PublicSigningError> {
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
        .ok_or_else(|| {
            public_failure(
                StatusCode::NOT_FOUND,
                &format!("Service '{service_id}' not found."),
            )
        })?;
    let is_default = service.get("key_reference").and_then(Value::as_str) == Some(reference);
    let is_alias = service
        .get("key_aliases")
        .and_then(Value::as_array)
        .is_some_and(|aliases| {
            aliases
                .iter()
                .any(|alias| alias.as_str() == Some(reference))
        });
    let bound_purposes = registry
        .get("key_reference_purposes")
        .and_then(|bindings| bindings.get(service_id))
        .and_then(|bindings| bindings.get(reference))
        .and_then(Value::as_array);
    let is_bound = bound_purposes.is_some_and(|purposes| !purposes.is_empty());
    let managed = service_id == "managed-openbao-transit";
    let selected_algorithm = algorithm.or_else(|| {
        service
            .get("algorithms")
            .and_then(Value::as_array)
            .and_then(|algorithms| algorithms.first())
            .and_then(Value::as_str)
    });
    if managed
        && managed_alias_allowed(
            service,
            organization_id,
            reference,
            bound_purposes,
            key_purpose,
            selected_algorithm,
        )
    {
        return Ok(());
    }
    if !managed && (is_default || is_alias || is_bound) {
        return Ok(());
    }
    let profiles = state.profile_store.as_ref().ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity storage is unavailable.",
        )
    })?;
    let document = profiles.list(organization_id).await.map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity storage is unavailable.",
        )
    })?;
    let active_profile_bound = document
        .get("profiles")
        .and_then(Value::as_array)
        .is_some_and(|profiles| {
            profiles.iter().any(|profile| {
                profile.get("status").and_then(Value::as_str) == Some("active")
                    && profile.get("signing_service_id").and_then(Value::as_str) == Some(service_id)
                    && profile.get("signing_key_reference").and_then(Value::as_str)
                        == Some(reference)
                    && (!managed
                        || registry::managed_profile_key_belongs_to_tenant(
                            organization_id,
                            profile,
                            reference,
                        ))
                    && key_purpose.is_none_or(|purpose| {
                        profile.get("key_purpose").and_then(Value::as_str) == Some(purpose)
                    })
                    && selected_algorithm.is_none_or(|algorithm| {
                        profile.get("algorithm").and_then(Value::as_str) == Some(algorithm)
                    })
            })
        });
    if active_profile_bound {
        Ok(())
    } else {
        Err(public_failure(
            StatusCode::CONFLICT,
            "Requested signing key is not registered for this service.",
        ))
    }
}

fn is_tenant_managed_create_reference(organization_id: &str, reference: &str) -> bool {
    registry::tenant_managed_key_name(organization_id, reference)
}

fn managed_alias_allowed(
    service: &Value,
    organization_id: &str,
    reference: &str,
    bound_purposes: Option<&Vec<Value>>,
    key_purpose: Option<&str>,
    algorithm: Option<&str>,
) -> bool {
    let is_alias = service
        .get("key_aliases")
        .and_then(Value::as_array)
        .is_some_and(|aliases| {
            aliases
                .iter()
                .any(|alias| alias.as_str() == Some(reference))
        });
    let is_bound = bound_purposes.is_some_and(|purposes| !purposes.is_empty());
    let purpose_matches = key_purpose.is_none_or(|purpose| {
        registry::managed_key_purposes(reference).contains(&purpose)
            && bound_purposes.is_some_and(|purposes| {
                purposes.iter().any(|bound| bound.as_str() == Some(purpose))
            })
    });
    let algorithm_matches = algorithm.is_some_and(|algorithm| {
        service
            .get("key_algorithms")
            .and_then(|algorithms| algorithms.get(reference))
            .and_then(Value::as_str)
            == Some(algorithm)
    });
    is_alias
        && is_bound
        && is_tenant_managed_create_reference(organization_id, reference)
        && purpose_matches
        && algorithm_matches
}

fn unavailable_observability_response(error: &str, message: &str, extra: Value) -> Response {
    let mut body = json!({
        "error": error,
        "error_description": message,
        "message_id": uuid::Uuid::new_v4().to_string(),
    });
    if let Some(fields) = extra.as_object() {
        for (name, value) in fields {
            body[name] = value.clone();
        }
    }
    let mut response = (StatusCode::NOT_IMPLEMENTED, Json(body)).into_response();
    response.headers_mut().insert(
        "x-mip-version",
        "0.5.0"
            .parse()
            .expect("static MIP version is a valid header"),
    );
    response
}

async fn public_compliance_keys_summary(
    State(_state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
) -> Response {
    if let Err(error) = validate_service_scope(&scope.organization_id, None) {
        return error.into_response();
    }
    unavailable_observability_response(
        "key_compliance_summary_unavailable",
        "Key compliance summary metrics are not available from a live backing data source.",
        json!({"organization_id": scope.organization_id}),
    )
}

async fn public_service_audit_log(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Query(scope): Query<AuditLogScope>,
) -> Response {
    if let Err(error) = validate_service_scope(&scope.organization_id, None) {
        return error.into_response();
    }
    if scope.limit.as_deref().is_some_and(|value| {
        !value
            .parse::<usize>()
            .is_ok_and(|limit| (1..=1000).contains(&limit))
    }) {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "limit must be between 1 and 1000",
        );
    }
    if scope
        .offset
        .as_deref()
        .is_some_and(|value| value.parse::<usize>().is_err())
    {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "offset must be nonnegative",
        );
    }
    if let Err(error) = registered_service(&state, &scope.organization_id, &service_id).await {
        return error.into_response();
    }
    unavailable_observability_response(
        "key_audit_log_unavailable",
        &format!("Key audit log storage is not available for service '{service_id}'."),
        json!({"organization_id": scope.organization_id, "service_id": service_id}),
    )
}

fn compatible_public_key_algorithms(public_jwk: &Value) -> &'static [&'static str] {
    match (
        public_jwk.get("kty").and_then(Value::as_str),
        public_jwk.get("crv").and_then(Value::as_str),
    ) {
        (Some("EC"), Some("P-256")) => &["ES256"],
        (Some("EC"), Some("P-384")) => &["ES384"],
        (Some("EC"), Some("P-521")) => &["ES512"],
        (Some("RSA"), _) => &["RS256", "PS256"],
        (Some("OKP"), Some("Ed25519")) => &["EdDSA"],
        _ => &[],
    }
}

async fn resolve_public_config(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    body: Option<Json<Value>>,
) -> Response {
    if let Err(error) = validate_service_scope(&scope.organization_id, None) {
        return error.into_response();
    }
    let Some(store) = state.registry_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        );
    };
    let registry = match store.load(&scope.organization_id).await {
        Ok(registry) => registry,
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing registry is unavailable.",
            )
        }
    };
    let body = body.map(|Json(body)| body).unwrap_or_else(|| json!({}));
    let field = |name: &str| body.get(name).and_then(Value::as_str).map(str::to_owned);
    let credential_format = field("credential_format");
    let key_purpose = field("key_purpose");
    let algorithm = field("algorithm");
    let selected = registry::resolve(ResolveRequest {
        registry: registry.clone(),
        service: None,
        keys: Vec::new(),
        credential_format: nonempty(&credential_format),
        key_purpose: nonempty(&key_purpose),
        algorithm: nonempty(&algorithm),
    });
    let Some(service) = selected.ok().and_then(|selection| selection.service) else {
        return public_error(
            StatusCode::NOT_FOUND,
            "No registered signing service matches the requested format, purpose, and algorithm.",
        );
    };
    let profiles = if let Some(profiles) = state.profile_store.as_ref() {
        match profiles
            .find(
                &scope.organization_id,
                FindProfilesRequest {
                    active_only: true,
                    ..FindProfilesRequest::default()
                },
            )
            .await
        {
            Ok(profiles) => profiles,
            Err(_) => {
                return public_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Issuer identity storage is unavailable.",
                )
            }
        }
    } else {
        Vec::new()
    };
    let (keys, discovery_failed) = resolution_keys(
        &registry,
        &service,
        &profiles,
        nonempty(&key_purpose).as_deref(),
        nonempty(&algorithm).as_deref(),
    )
    .await;
    let compatible_references = keys
        .iter()
        .filter_map(|key| key.get("id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>();
    let resolved = match registry::resolve(ResolveRequest {
        registry,
        service: Some(service),
        keys,
        credential_format: nonempty(&credential_format),
        key_purpose: nonempty(&key_purpose),
        algorithm: nonempty(&algorithm),
    }) {
        Ok(resolved) => resolved,
        Err(_) => {
            return public_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Signing service resolution failed.",
            )
        }
    };
    let Some(mut service) = resolved.service else {
        return public_error(
            StatusCode::NOT_FOUND,
            "No registered signing service matches the requested format, purpose, and algorithm.",
        );
    };
    if (nonempty(&key_purpose).is_some() || nonempty(&algorithm).is_some())
        && (resolved.key_reference.is_none()
            || (nonempty(&algorithm).is_some()
                && !resolved
                    .key_reference
                    .as_deref()
                    .is_some_and(|reference| compatible_references.contains(reference))))
    {
        return public_error(
            if discovery_failed {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::NOT_FOUND
            },
            if discovery_failed {
                "The signing KMS key inventory is unavailable."
            } else {
                "No key reference is bound to the requested purpose and algorithm."
            },
        );
    }
    if let Some(reference) = resolved.key_reference.as_deref() {
        service["key_reference"] = json!(reference);
    }
    let mdoc_hints = if needs_mdoc_hints(
        nonempty(&credential_format).as_deref(),
        nonempty(&key_purpose).as_deref(),
    ) {
        match resolved_mdoc_hints(&state, &scope.organization_id, &service).await {
            Ok(hints) => hints,
            Err(error) => return error.into_response(),
        }
    } else {
        Value::Null
    };
    Json(json!({
        "service": public_service_config(&service),
        "resolved_by": {"credential_format": credential_format, "key_purpose": key_purpose, "algorithm": algorithm},
        "mdoc_signing_hints": mdoc_hints,
    })).into_response()
}

fn nonempty(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn needs_mdoc_hints(format: Option<&str>, purpose: Option<&str>) -> bool {
    if purpose == Some("mdoc_iaca") {
        return false;
    }
    matches!(format, Some("mso_mdoc" | "zk_mdoc"))
        || matches!(purpose, Some("mdoc_dsc" | "vdsnc_signing" | "csca"))
}

fn resolution_references(
    registry: &Value,
    service: &Value,
    profiles: &[Value],
) -> std::collections::BTreeSet<String> {
    let mut references = std::collections::BTreeSet::new();
    let Some(service_id) = service.get("id").and_then(Value::as_str) else {
        return references;
    };
    if let Some(reference) = service
        .get("key_reference")
        .and_then(Value::as_str)
        .filter(|reference| !reference.is_empty())
    {
        references.insert(reference.to_owned());
    }
    for reference in service
        .get("key_aliases")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !reference.is_empty() {
            references.insert(reference.to_owned());
        }
    }
    if service_id == registry::MANAGED_OPENBAO_SERVICE_ID {
        return references;
    }
    if let Some(bound) = registry
        .get("key_reference_purposes")
        .and_then(|all| all.get(service_id))
        .and_then(Value::as_object)
    {
        references.extend(
            bound
                .keys()
                .filter(|reference| !reference.is_empty())
                .cloned(),
        );
    }
    for profile in profiles {
        if profile.get("signing_service_id").and_then(Value::as_str) == Some(service_id) {
            if let Some(reference) = profile
                .get("signing_key_reference")
                .and_then(Value::as_str)
                .filter(|reference| !reference.is_empty())
            {
                references.insert(reference.to_owned());
            }
        }
    }
    references
}

fn queue_key_discovery(
    tasks: &mut JoinSet<Result<Option<Value>, ()>>,
    service: &Value,
    reference: String,
    requested_algorithm: &str,
) {
    let mut config = service.clone();
    config["key_reference"] = json!(reference);
    let algorithm = requested_algorithm.to_owned();
    tasks.spawn(async move {
        match kms::public_key_existing(ProviderRequest {
            service_config: config,
        })
        .await
        {
            Ok(response) => {
                let compatible = discovered_key_matches_algorithm(&response, &algorithm)?;
                Ok(compatible.then(|| json!({"id": reference, "algorithm": algorithm})))
            }
            Err(kms::KmsError::ProviderStatus {
                status: StatusCode::NOT_FOUND,
                ..
            }) => Ok(None),
            Err(_) => Err(()),
        }
    });
}

fn discovered_key_matches_algorithm(response: &Value, algorithm: &str) -> Result<bool, ()> {
    let jwk = documents::sanitize_public_jwk(response, None).map_err(|_| ())?;
    if !compatible_public_key_algorithms(&jwk).contains(&algorithm) {
        return Ok(false);
    }
    for field in ["alg", "use"] {
        if let Some(declared) = jwk.get(field) {
            let value = declared.as_str().ok_or(())?;
            if (field == "alg" && value != algorithm) || (field == "use" && value != "sig") {
                return Ok(false);
            }
        }
    }
    match response.get("provider").and_then(Value::as_str) {
        Some("aws") => {
            let usage = response
                .get("key_usage")
                .and_then(Value::as_str)
                .ok_or(())?;
            let native = match kms::aws_signing_algorithm(algorithm) {
                Ok(native) => native,
                Err(_) => return Ok(false),
            };
            let supported = response
                .get("signing_algorithms")
                .and_then(Value::as_array)
                .ok_or(())?;
            if !supported.iter().all(Value::is_string) {
                return Err(());
            }
            Ok(usage == "SIGN_VERIFY" && supported.iter().any(|item| item == native))
        }
        Some("gcp") => {
            let native = response
                .get("algorithm")
                .and_then(Value::as_str)
                .ok_or(())?;
            Ok(match algorithm {
                "ES256" => native == "EC_SIGN_P256_SHA256",
                "ES384" => native == "EC_SIGN_P384_SHA384",
                "ES512" => native == "EC_SIGN_P521_SHA512",
                "RS256" => native.starts_with("RSA_SIGN_PKCS1_") && native.ends_with("_SHA256"),
                "PS256" => native.starts_with("RSA_SIGN_PSS_") && native.ends_with("_SHA256"),
                "EdDSA" => native == "EC_SIGN_ED25519",
                _ => false,
            })
        }
        Some("azure") => {
            let Some(operations) = jwk.get("key_ops") else {
                return Ok(true);
            };
            let operations = operations.as_array().ok_or(())?;
            if !operations.iter().all(Value::is_string) {
                return Err(());
            }
            Ok(operations.iter().any(|operation| operation == "sign"))
        }
        _ => Ok(true),
    }
}

async fn resolution_keys(
    registry: &Value,
    service: &Value,
    profiles: &[Value],
    _purpose: Option<&str>,
    algorithm: Option<&str>,
) -> (Vec<Value>, bool) {
    let references = resolution_references(registry, service, profiles);
    if algorithm.is_none() {
        return (
            references
                .into_iter()
                .map(|reference| json!({"id": reference}))
                .collect(),
            false,
        );
    }
    let algorithm = algorithm.expect("checked algorithm");
    let mut references = references.into_iter();
    let mut tasks = JoinSet::new();
    for _ in 0..8 {
        if let Some(reference) = references.next() {
            queue_key_discovery(&mut tasks, service, reference, algorithm);
        }
    }
    let mut keys = Vec::new();
    let mut unavailable = false;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(Some(key))) => keys.push(key),
            Ok(Ok(None)) => {}
            _ => unavailable = true,
        }
        if let Some(reference) = references.next() {
            queue_key_discovery(&mut tasks, service, reference, algorithm);
        }
    }
    (keys, unavailable)
}

async fn resolved_mdoc_hints(
    state: &AppState,
    organization_id: &str,
    service: &Value,
) -> Result<Value, PublicSigningError> {
    let Some(service_id) = service.get("id").and_then(Value::as_str) else {
        return Err(public_failure(
            StatusCode::BAD_GATEWAY,
            "Resolved signing service has no identifier.",
        ));
    };
    let overrides = if let Some(store) = state.document_store.as_ref() {
        store
            .certificate_overrides(organization_id)
            .await
            .map_err(|_| {
                public_failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Certificate storage is unavailable.",
                )
            })?
    } else {
        json!({})
    };
    let Some(certificate) = selected_service_certificate(service, &overrides, service_id) else {
        return Ok(Value::Null);
    };
    let reference = service
        .get("key_reference")
        .and_then(Value::as_str)
        .filter(|reference| !reference.is_empty())
        .ok_or_else(|| {
            public_failure(
                StatusCode::CONFLICT,
                "An mDoc certificate requires a resolved KMS key reference.",
            )
        })?;
    let public_jwk = kms::public_key_existing(ProviderRequest {
        service_config: service.clone(),
    })
    .await
    .map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "The service KMS public key is unavailable.",
        )
    })?;
    let public_jwk = documents::sanitize_public_jwk(&public_jwk, None).map_err(|_| {
        public_failure(
            StatusCode::BAD_GATEWAY,
            "The service KMS returned an invalid public key.",
        )
    })?;
    let checked = checked_service_x5c(certificate, &public_jwk, service_id)?;
    Ok(json!({
        "x5c": checked["x5c"],
        "x5c_length": checked["mdoc_cose_header_hints"]["x5c_length"],
        "key_reference": reference,
    }))
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
    let compatible_algorithms = compatible_public_key_algorithms(public_jwk);
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
                .map(|service| {
                    let mut public = public_service_config(service);
                    let enabled = registry
                        .get("did_operation_bindings")
                        .and_then(Value::as_object)
                        .is_some_and(|issuers| {
                            issuers.values().any(|operations| {
                                operations.pointer("/didcomm_authcrypt/service_id")
                                    == service.get("id")
                            })
                        });
                    public["extensions"] = json!({"didcomm_authcrypt": {
                        "enabled": enabled,
                        "basis": if enabled { "registered_binding" } else { "unconfigured" },
                    }});
                    public
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let providers = services
        .iter()
        .filter_map(|service| service.get("provider").and_then(Value::as_str))
        .collect::<std::collections::BTreeSet<_>>();
    let provider = match providers.len() {
        0 => None,
        1 => providers.iter().next().copied(),
        _ => Some("multiple"),
    };
    let native_management = services.iter().any(|service| {
        service.get("id").and_then(Value::as_str) == Some("managed-openbao-transit")
            && service.get("managed").and_then(Value::as_bool) == Some(true)
    });
    json!({
        "provider_metadata": {
            "provider": provider,
            "providers": providers,
            "status": if services.is_empty() { "unconfigured" } else { "registered" },
            "basis": "registration",
            "managed_by": if native_management { Some("Marty service stack") } else { None },
        },
        "domain_config": {"public_domain": state.public_domain},
        "supports_native_key_management": native_management,
        "registration_mode": if native_management { "managed-or-external" } else { "external-only" },
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
        if registry::AUTH_CONNECTION_FIELDS
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
        Err(profiles::ProfileError::Storage(_)) => Err(public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity storage is unavailable.",
        )),
        Err(profiles::ProfileError::Corrupt(_)) => Err(public_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Issuer identity storage is malformed.",
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
    crate::identity_capabilities::managed_did_prefix(public_domain)
        .is_some_and(|prefix| issuer_did.starts_with(&prefix))
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
    registry::managed_key_reference_for_fields(
        organization_id,
        &input.issuer_did,
        &input.key_purpose,
        &input.credential_format,
        &input.algorithm,
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

async fn issuer_did_sign(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<IssuerDidSignRequest>,
) -> Result<Json<serde_json::Value>, CompatibilityError> {
    if !authorize_issuer_sign(&state, &headers) {
        return Err(CompatibilityError::Unauthorized);
    }
    let header = headers
        .get(HEADER_NAME)
        .and_then(|value| value.to_str().ok())
        .ok_or(CompatibilityError::Unauthorized)?;
    let envelope =
        GrantEnvelope::from_header_value(header).map_err(|_| CompatibilityError::Unauthorized)?;
    let key_reference = request
        .key_reference
        .as_deref()
        .filter(|reference| !reference.is_empty())
        .ok_or(CompatibilityError::Unauthorized)?;
    let payload = crate::compat::signing_payload(
        request.payload_b64.as_deref(),
        request.payload_hex.as_deref(),
    )?;
    let binding = GrantBinding {
        origin: envelope.claims.origin,
        operation_id: &envelope.claims.operation_id,
        organization_id: &request.organization_id,
        route: "/internal/compat/issuer-dids/sign",
        service_id: None,
        issuer_did: Some(&request.issuer_did),
        key_reference: Some(key_reference),
        key_purpose: &request.key_purpose,
        algorithm: &request.algorithm,
        payload: &payload,
    };
    let consumed = consume_bound_signing_grant(&state, header, &binding)
        .await
        .map_err(|error| match error {
            GrantAuthorizationError::Denied => CompatibilityError::Unauthorized,
            GrantAuthorizationError::Unavailable => CompatibilityError::Unavailable,
        })?;
    let service = state
        .compatibility
        .as_ref()
        .ok_or(CompatibilityError::Unavailable)?;
    let authorization = SignAuthorization::grant(
        consumed,
        "/internal/compat/issuer-dids/sign",
        Some(request.issuer_did.clone()),
    );
    service
        .sign_with_issuer_did(&request, authorization)
        .await
        .map(Json)
}

async fn consume_bound_signing_grant(
    state: &AppState,
    header: &str,
    binding: &GrantBinding<'_>,
) -> Result<ConsumedGrant, GrantAuthorizationError> {
    let verifier = state
        .grant_verifier
        .as_ref()
        .ok_or(GrantAuthorizationError::Unavailable)?;
    let consumed = verifier.authorize(header, binding).await?;
    Ok(consumed)
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

async fn create_haip_response_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateHaipKeyRequest>,
) -> Result<Json<Value>, FlowEnvelopeError> {
    authorize_internal(&state, &headers).map_err(|_| FlowEnvelopeError::Unauthorized)?;
    let provider = state
        .flow_envelopes
        .as_ref()
        .ok_or(FlowEnvelopeError::CapabilityUnavailable)?;
    provider.create_haip_key(request).await.map(Json)
}

async fn resolve_haip_response_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ResolveHaipKeyRequest>,
) -> Result<Json<Value>, FlowEnvelopeError> {
    authorize_internal(&state, &headers).map_err(|_| FlowEnvelopeError::Unauthorized)?;
    let provider = state
        .flow_envelopes
        .as_ref()
        .ok_or(FlowEnvelopeError::CapabilityUnavailable)?;
    provider.resolve_haip_key(request).await.map(Json)
}

async fn decrypt_haip_response(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DecryptHaipResponseRequest>,
) -> Result<Json<Value>, FlowEnvelopeError> {
    authorize_internal(&state, &headers).map_err(|_| FlowEnvelopeError::Unauthorized)?;
    let provider = state
        .flow_envelopes
        .as_ref()
        .ok_or(FlowEnvelopeError::CapabilityUnavailable)?;
    provider.decrypt_haip_response(request).await.map(Json)
}

async fn encrypt_integration_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<EncryptIntegrationSecretRequest>,
) -> Result<Json<Value>, IntegrationSecretEnvelopeError> {
    if !authorize_integration_secret(&state, &headers) {
        return Err(IntegrationSecretEnvelopeError::Unauthorized);
    }
    let provider = state.integration_secret_envelopes.as_ref().ok_or(
        IntegrationSecretEnvelopeError::CapabilityUnavailable(
            "Integration-secret encryption is not configured.",
        ),
    )?;
    integration_secret_envelope::encrypt(provider, request)
        .await
        .map(Json)
}

async fn decrypt_integration_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DecryptIntegrationSecretRequest>,
) -> Result<Json<Value>, IntegrationSecretEnvelopeError> {
    if !authorize_integration_secret(&state, &headers) {
        return Err(IntegrationSecretEnvelopeError::Unauthorized);
    }
    let provider = state.integration_secret_envelopes.as_ref().ok_or(
        IntegrationSecretEnvelopeError::CapabilityUnavailable(
            "Integration-secret encryption is not configured.",
        ),
    )?;
    integration_secret_envelope::decrypt(provider, request)
        .await
        .map(Json)
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
        .ok_or(ArtifactEnvelopeError::CapabilityUnavailable)?;
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
        .ok_or(ArtifactEnvelopeError::CapabilityUnavailable)?;
    passport_artifact_envelope::decrypt_chunk(provider, &organization_id, request)
        .await
        .map(Json)
}

async fn verify_passport_callback(
    State(state): State<AppState>,
    Path(organization_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<passport_callback_hmac::VerifyRequest>,
) -> Result<Json<Value>, CallbackKmsError> {
    authorize_internal(&state, &headers).map_err(|_| CallbackKmsError::Unauthorized)?;
    let provider = state
        .flow_envelopes
        .as_ref()
        .ok_or(CallbackKmsError::CapabilityUnavailable)?;
    passport_callback_hmac::verify(provider, &organization_id, request)
        .await
        .map(Json)
}

async fn vc_api_holder_proof(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<HolderProofRequest>,
) -> Result<Json<HolderProofResponse>, (StatusCode, Json<Value>)> {
    authorize_internal(&state, &headers).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"detail":"Invalid internal API key"})),
        )
    })?;
    let provider = OpenBaoHolderProofProvider::from_environment().map_err(holder_proof_error)?;
    provider
        .issue(request)
        .await
        .map(Json)
        .map_err(holder_proof_error)
}

fn holder_proof_error(error: HolderProofError) -> (StatusCode, Json<Value>) {
    let status = match error {
        HolderProofError::InvalidRequest | HolderProofError::CapabilityUnavailable => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        HolderProofError::Unavailable | HolderProofError::Provider => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    };
    let mut body = json!({"detail": error.to_string()});
    if matches!(error, HolderProofError::CapabilityUnavailable) {
        body["code"] = json!("capability_unavailable");
        body["capability"] = json!("ephemeral_holder_proof");
    }
    (status, Json(body))
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
    if error == registry::RegistryError::SecretCapabilityUnavailable {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "detail": error.to_string(),
                "code": "capability_unavailable",
                "capability": "integration_secret_encryption",
            })),
        );
    }
    let status = match error {
        registry::RegistryError::Invalid(_)
        | registry::RegistryError::SecretCapabilityUnavailable => StatusCode::UNPROCESSABLE_ENTITY,
        registry::RegistryError::Storage(_) => StatusCode::SERVICE_UNAVAILABLE,
        registry::RegistryError::Corrupt(_) => StatusCode::INTERNAL_SERVER_ERROR,
        registry::RegistryError::Conflict => StatusCode::CONFLICT,
        registry::RegistryError::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
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
    let lease = csca_signing_lease(&state, &organization_id).await?;
    let result = async {
        let profile_revision =
            validate_managed_csca_binding(&state, &organization_id, &request).await?;
        let now = chrono::Utc::now();
        let mut document = load_csca_lifecycle(&state, &organization_id, now).await?;
        let view = document
            .import(&certificate_id, request, now)
            .map_err(csca_lifecycle_error)?;
        csca_lifecycle_store(&state)?
            .save_with_rotation_lease(&document, &lease, profile_revision)
            .await
            .map_err(csca_lifecycle_error)?;
        Ok(Json(view))
    }
    .await;
    let _ = lease.release().await;
    result
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
    let lease = csca_signing_lease(&state, &organization_id).await?;
    let result = async {
        let now = chrono::Utc::now();
        let mut document = load_csca_lifecycle(&state, &organization_id, now).await?;
        let replacement_id = request.replacement_certificate_id.clone();
        let reuse_key = request.reuse_key;
        let replacement = request.into_import();
        let prior = document
            .get(&certificate_id, now)
            .map_err(csca_lifecycle_error)?;
        if prior.certificate.metadata.get("issuer_did") != replacement.metadata.get("issuer_did") {
            return Err(csca_lifecycle_error(CscaLifecycleError::Invalid(
                "replacement CSCA issuer identity must match the existing certificate".into(),
            )));
        }
        let profile_revision =
            validate_managed_csca_binding(&state, &organization_id, &replacement).await?;
        let view = document
            .renew(
                &certificate_id,
                &replacement_id,
                replacement,
                reuse_key,
                now,
            )
            .map_err(csca_lifecycle_error)?;
        csca_lifecycle_store(&state)?
            .save_with_rotation_lease(&document, &lease, profile_revision)
            .await
            .map_err(csca_lifecycle_error)?;
        Ok(Json(view))
    }
    .await;
    let _ = lease.release().await;
    result
}

async fn validate_managed_csca_binding(
    state: &AppState,
    organization_id: &str,
    request: &ImportCscaCertificateRequest,
) -> Result<u64, DocumentHttpError> {
    let invalid = || {
        csca_lifecycle_error(CscaLifecycleError::Invalid(
            "CSCA certificate must match an active managed KMS key".into(),
        ))
    };
    let unavailable = || {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"detail": "Managed CSCA key verification is unavailable"})),
        )
    };
    let issuer_did = request
        .metadata
        .get("issuer_did")
        .and_then(Value::as_str)
        .filter(|did| !did.is_empty() && did.len() <= 2048)
        .ok_or_else(invalid)?;
    let store = state.profile_store.as_ref().ok_or_else(unavailable)?;
    let compatibility = state.compatibility.as_ref().ok_or_else(unavailable)?;
    let profiles = store
        .find(
            organization_id,
            FindProfilesRequest {
                active_only: true,
                issuer_did: Some(issuer_did.into()),
                key_purpose: Some("csca".into()),
                require_signing_service: true,
                require_signing_key_reference: true,
                require_public_identity: true,
                ..FindProfilesRequest::default()
            },
        )
        .await
        .map_err(|_| unavailable())?;
    let mut matching = profiles.iter().filter(|profile| {
        profile.get("signing_key_reference").and_then(Value::as_str)
            == Some(request.key_reference.as_str())
    });
    let profile = matching.next().ok_or_else(invalid)?;
    if matching.any(|candidate| {
        candidate.get("signing_service_id") != profile.get("signing_service_id")
            || candidate.get("algorithm") != profile.get("algorithm")
    }) {
        return Err(invalid());
    }
    let current_public = compatibility
        .provider_public_key_for_profile(organization_id, profile)
        .await
        .map_err(|_| unavailable())?;
    if !documents::same_public_jwk(&current_public, &request.expected_public_jwk) {
        return Err(invalid());
    }
    let profile_document = store
        .list(organization_id)
        .await
        .map_err(|_| unavailable())?;
    if !profile_document
        .get("profiles")
        .and_then(Value::as_array)
        .is_some_and(|profiles| profiles.iter().any(|candidate| candidate == profile))
    {
        return Err(invalid());
    }
    profile_document
        .get("revision")
        .and_then(Value::as_u64)
        .ok_or_else(unavailable)
}

async fn csca_signing_lease(
    state: &AppState,
    organization_id: &str,
) -> Result<RotationLease, DocumentHttpError> {
    let unavailable = || {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"detail": "Tenant signing lease is unavailable"})),
        )
    };
    let store = state.registry_store.as_ref().ok_or_else(unavailable)?;
    store
        .acquire_rotation_lease(organization_id)
        .await
        .map_err(|_| unavailable())?
        .ok_or_else(|| {
            (
                StatusCode::CONFLICT,
                Json(json!({"detail": "Tenant signing state is changing"})),
            )
        })
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

fn authorize_service_sign(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(expected) = state.service_sign_gateway_key.as_ref() else {
        return false;
    };
    if expected.as_ref() == state.internal_api_key.as_ref()
        || state.dsc_issue_gateway_key.as_deref() == Some(expected.as_ref())
        || state.csca_issue_gateway_key.as_deref() == Some(expected.as_ref())
    {
        return false;
    }
    let supplied = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .as_bytes();
    let expected = expected.as_bytes();
    expected.len() == supplied.len() && expected.ct_eq(supplied).unwrap_u8() == 1
}

fn authorize_issuer_sign(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(expected) = state.issuer_sign_key.as_ref() else {
        return false;
    };
    if expected.as_ref() == state.internal_api_key.as_ref()
        || state.service_sign_gateway_key.as_deref() == Some(expected.as_ref())
        || state.dsc_issue_gateway_key.as_deref() == Some(expected.as_ref())
        || state.csca_issue_gateway_key.as_deref() == Some(expected.as_ref())
    {
        return false;
    }
    let supplied = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .as_bytes();
    let expected = expected.as_bytes();
    expected.len() == supplied.len() && expected.ct_eq(supplied).unwrap_u8() == 1
}

fn authorize_integration_secret(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(expected) = state.integration_secret_key.as_ref() else {
        return false;
    };
    if expected.as_ref() == state.internal_api_key.as_ref()
        || state.service_sign_gateway_key.as_deref() == Some(expected.as_ref())
        || state.issuer_sign_key.as_deref() == Some(expected.as_ref())
        || state.dsc_issue_gateway_key.as_deref() == Some(expected.as_ref())
        || state.csca_issue_gateway_key.as_deref() == Some(expected.as_ref())
    {
        return false;
    }
    let supplied = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .as_bytes();
    let expected = expected.as_bytes();
    expected.len() == supplied.len() && expected.ct_eq(supplied).unwrap_u8() == 1
}

fn authorize_dsc_issue(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(expected) = state.dsc_issue_gateway_key.as_ref() else {
        return false;
    };
    if expected.as_ref() == state.internal_api_key.as_ref() {
        return false;
    }
    let supplied = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let supplied = supplied.as_bytes();
    let expected = expected.as_bytes();
    expected.len() == supplied.len() && expected.ct_eq(supplied).unwrap_u8() == 1
}

fn authorize_csca_issue(state: &AppState, headers: &HeaderMap) -> bool {
    if !state.beta_csca_issuance_enabled {
        return false;
    }
    let Some(expected) = state.csca_issue_gateway_key.as_ref() else {
        return false;
    };
    if expected.as_ref() == state.internal_api_key.as_ref()
        || state.dsc_issue_gateway_key.as_deref() == Some(expected.as_ref())
    {
        return false;
    }
    let supplied = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    expected.len() == supplied.len()
        && expected.as_bytes().ct_eq(supplied.as_bytes()).unwrap_u8() == 1
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
            "/v1/signing-keys": {
                "get": {"summary": "List Signing Keys", "responses": {"200": {"description": "Provider-neutral signing-key inventory"}}},
                "post": {"summary": "Create Managed KMS Signing Key", "responses": {
                    "200": {"description": "Tenant-namespaced KMS key created and public metadata returned"},
                    "409": {"description": "Existing KMS key is incompatible with the requested algorithm"},
                    "503": {"description": "Managed KMS or registry unavailable"}
                }}
            },
            "/v1/signing-keys/{key_id}": {
                "get": {"summary": "Get Public Signing Key Metadata", "responses": {"200": {"description": "Tenant signing-key inventory entry"}, "404": {"description": "Signing key not found"}}},
                "patch": {"summary": "Update Published Signing Key Metadata", "responses": {"200": {"description": "JWKS metadata updated without altering KMS key material"}, "404": {"description": "Published key not found"}}},
                "delete": {"summary": "Deregister Published Signing Key", "responses": {"200": {"description": "JWKS entry removed without deleting KMS key material"}, "404": {"description": "Published key not found"}}}
            },
            "/v1/signing-keys/mdoc-crls/{organization_id}/{file}": {
                "get": {"summary":"Get an unexpired governed MDOC IACA CRL from this deployment's configured CDP",
                    "responses":{"200":{"description":"Signed application/pkix-crl bytes"},
                                 "503":{"description":"Absent, expired, or no longer governed CRL"}}}
            },
            "/v1/signing-keys/mdoc-crls/{certificate_id}": {
                "post": {"summary":"Publish or renew an IACA CRL, optionally revoking one managed DSC receipt",
                    "responses":{"200":{"description":"Signed CRL and revocation committed atomically"},
                                 "409":{"description":"Managed issuer or certificate state changed"}}}
            },
            "/v1/signing-keys/issuer-identities": {
                "get": {"summary": "List Public Issuer Identities", "responses": {"200": {"description": "DID-first issuer identity inventory without custody coordinates"}}},
                "post": {"summary": "Create Public Issuer Identity", "responses": {"200": {"description": "Provider-neutral issuer identity provisioning"}}},
                "patch": {"summary": "Move Issuer Identity to Default Signing Service", "responses": {"200": {"description": "Replacement public key is published before active custody changes"}}},
                "delete": {"summary": "Retire Public Issuer Identity", "responses": {"200": {"description": "Issuer identity retired"}}}
            },
            "/v1/signing-keys/issuer-identities/resolve": {
                "post": {"summary": "Resolve Public Issuer Identity", "responses": {"200": {"description": "Exact active tuple and public JWK without custody coordinates"}}}
            },
            "/v1/signing-keys/issuer-identities/capabilities": {
                "get": {"summary":"Discover Organization Issuer Creation Options", "parameters":[{"name":"organization_id","in":"query","required":true,"schema":{"type":"string","minLength":1}}], "responses": {
                    "200": {"description":"Configuration-derived public options, not a provider health or publication guarantee", "content":{"application/json":{"schema":serde_json::from_str::<Value>(include_str!("../../../../contracts/issuer-identity-capabilities-response.json")).expect("capability schema")}}},
                    "400": {"description":"Malformed or unsupported query parameters"},
                    "422": {"description":"Organization scope is blank"},
                    "503": {"description":"Issuer capability discovery unavailable"}
                }}
            },
            "/v1/signing-keys/issuer-identities/inspection": {
                "get": {"summary":"Inspect public DID publication and managed signer matching", "parameters": identity_inspection::parameters(), "responses": {
                    "200":{"description":"Separate current registry, KMS and public HTTPS observations; unavailable checks never imply readiness", "content":{"application/json":{"schema":{"$ref":"#/components/schemas/runtime__issuer_identity_inspection"}}}},
                    "400":{"description":"Missing, malformed or unsupported query fields"},
                    "404":{"description":"No active identity matches the authorized organization and public tuple"},
                    "409":{"description":"Identity tuple is ambiguous"},
                    "422":{"description":"Identity tuple is invalid"},
                    "502":{"description":"Stored DID document is malformed"},
                    "503":{"description":"Identity registry or document storage is unavailable"}
                }}
            },
            "/v1/signing-keys/issuer-identities/csca-certificate": {
                "put": {"summary": "Enroll Public CSCA Certificate for Managed Issuer Identity", "responses": {"200": {"description": "Tenant-scoped public trust anchor enrolled without exposing key coordinates"}}}
            },
            "/v1/signing-keys/issuer-identities/certificate-csr": {
                "put": {"summary": "Generate KMS-backed Certificate Request for Passport Issuer Identity", "responses": {"200": {"description": "Public PKCS#10 request signed in managed custody"}}}
            },
            "/v1/signing-keys/issuer-identities/dsc-certificate": {
                "post": {"summary": "Issue Managed Passport DSC Certificate", "responses": {
                    "200": {"description": "Verified DSC certificate and CSCA chain, with idempotent replay"},
                    "401": {"description": "Dedicated Gateway issuance credential is missing"},
                    "403": {"description": "Organization context is forbidden"},
                    "409": {"description": "Issuer state or idempotency claim changed"},
                    "422": {"description": "Issuance request violates certificate policy"},
                    "503": {"description": "Managed KMS or issuance storage unavailable"}
                }}
            },
            "/v1/signing-keys/issuer-identities/csca-self-signed-certificate": {
                "post": {"summary": "Perform Beta KMS-backed CSCA Self-Signed Certificate Ceremony", "responses": {
                    "200": {"description": "Verified self-signed CSCA certificate enrolled in tenant lifecycle or replayed"},
                    "401": {"description": "Dedicated Gateway CSCA operator credential is missing"},
                    "403": {"description": "Organization context is forbidden"},
                    "409": {"description": "Profile, key, lifecycle, or certificate identifier changed"},
                    "422": {"description": "CSCA ceremony request violates certificate policy"},
                    "503": {"description": "Beta ceremony, KMS, or storage unavailable"}
                }}
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
            "/v1/signing-keys/services/{service_id}/rotate": {
                "post": {"summary": "Rotate Registered Service Key in KMS", "responses": {
                    "200": {"description": "Provider rotation and optional publication results"},
                    "404": {"description": "Signing service not found"},
                    "503": {"description": "Signing registry unavailable"}
                }}
            },
            "/v1/signing-keys/services/vdsnc/register": {
                "post": {"summary": "Register VDS-NC Signing Service", "responses": {
                    "200": {"description": "Tenant service registered with an opaque KMS key reference"},
                    "422": {"description": "Invalid VDS-NC service configuration"},
                    "503": {"description": "Signing registry unavailable"}
                }}
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
            "/v1/signing-keys/config/resolve": {
                "post": {"summary": "Resolve Registered Signing Service", "responses": {
                    "200": {"description": "Tenant service and purpose-bound public KMS key selection"},
                    "404": {"description": "No matching service or purpose-bound key"},
                    "503": {"description": "Signing registry or KMS public-key inventory unavailable"}
                }}
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
        },
        "components":{"schemas":{"runtime__issuer_identity_inspection": serde_json::from_str::<Value>(include_str!("../../../../contracts/issuer-identity-inspection-response.json")).expect("inspection schema")}}
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
mod public_contract_tests;
