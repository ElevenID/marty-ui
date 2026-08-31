//! HTTP boundary for Canvas platform management.

use axum::{
    body::to_bytes,
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::sync::Arc;

use crate::{
    canvas_award_candidate_approval::{
        CanvasApplicationApprovalError, CanvasApplicationApprovalService,
    },
    canvas_binding_domain::{CanvasBindingDomainError, CanvasProgramBindingRecord},
    canvas_catalog::{
        discover_canvas_scope, CanvasCatalogOAuth, CanvasCatalogProvider,
        CanvasCatalogProviderError, CanvasScopeDiscoveryResponse,
    },
    canvas_credentials_validation::CanvasCredentialsValidationResult,
    canvas_management::{
        CanvasApplicationApprovalRequest, CanvasCredentialsValidationRequest,
        CanvasIntegrationSecretCreate,
        CanvasIntegrationSecretUpdate, CanvasLtiInstallationRequest, CanvasPlatformRequest,
        CanvasProgramBindingRequest, CanvasScopeDiscoveryRequest, ValidateCanvasRequest,
    },
    canvas_management_domain::{CanvasManagementDomainError, CanvasPlatformRecord},
    canvas_management_service::{
        CanvasBindingValidationResult, CanvasLtiRegistrationResponse,
        CanvasPlatformManagementError, CanvasPlatformManagementService, CanvasPlatformProbeResult,
        CanvasPlatformReadinessResult,
    },
    canvas_oauth::CanvasOAuthError,
    canvas_readiness::CanvasReadinessCheck,
    integration_secret::ManagedIntegrationSecret,
    transaction_reads::TransactionReadError,
};

const MAX_MANAGEMENT_BODY_BYTES: usize = 64 * 1024;
const SAFE_CONNECTION_CONFIG_KEYS: &[&str] = &[
    "enabled_intent",
    "oauth_client_id",
    "oauth_status",
    "oauth_capabilities",
    "granted_scopes",
    "lti_config_token_status",
];

#[derive(Clone)]
pub struct CanvasPlatformManagementHttpService {
    management: CanvasPlatformManagementService,
    catalog: Option<CanvasCatalogRuntime>,
    application_approval: Option<CanvasApplicationApprovalService>,
}

#[derive(Clone)]
struct CanvasCatalogRuntime {
    oauth: Arc<dyn CanvasCatalogOAuth>,
    provider: Arc<dyn CanvasCatalogProvider>,
    local_admin_token: Option<String>,
}

impl std::fmt::Debug for CanvasPlatformManagementHttpService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CanvasPlatformManagementHttpService")
            .field("management", &self.management)
            .field("catalog_configured", &self.catalog.is_some())
            .field(
                "application_approval_configured",
                &self.application_approval.is_some(),
            )
            .finish()
    }
}

impl CanvasPlatformManagementHttpService {
    #[must_use]
    pub fn new(management: CanvasPlatformManagementService) -> Self {
        Self {
            management,
            catalog: None,
            application_approval: None,
        }
    }

    #[must_use]
    pub fn with_catalog(
        management: CanvasPlatformManagementService,
        oauth: Arc<dyn CanvasCatalogOAuth>,
        provider: Arc<dyn CanvasCatalogProvider>,
    ) -> Self {
        Self::with_catalog_options(management, oauth, provider, None)
    }

    #[must_use]
    pub fn with_catalog_options(
        management: CanvasPlatformManagementService,
        oauth: Arc<dyn CanvasCatalogOAuth>,
        provider: Arc<dyn CanvasCatalogProvider>,
        local_admin_token: Option<String>,
    ) -> Self {
        Self {
            management,
            catalog: Some(CanvasCatalogRuntime {
                oauth,
                provider,
                local_admin_token,
            }),
            application_approval: None,
        }
    }

    #[must_use]
    pub fn with_application_approval(
        mut self,
        application_approval: CanvasApplicationApprovalService,
    ) -> Self {
        self.application_approval = Some(application_approval);
        self
    }

    pub fn authorize(&self, headers: &HeaderMap) -> Result<(), CanvasManagementHttpError> {
        self.management
            .authorize_request(
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .map(|_| ())
            .map_err(Into::into)
    }

    pub async fn approve_application(
        &self,
        headers: &HeaderMap,
        application_id: &str,
        request: CanvasApplicationApprovalRequest,
    ) -> Result<CanvasApplicationApprovalResponse, CanvasManagementHttpError> {
        request.validate().map_err(|error| {
            CanvasManagementHttpError::Validation(vec![json!({
                "type": "value_error",
                "loc": ["body"],
                "msg": error.to_string(),
                "input": null,
            })])
        })?;
        let organization_id = self.management.authorize_request(
            header(headers, "X-API-Key"),
            header(headers, "X-Organization-ID"),
        )?;
        self.application_approval
            .as_ref()
            .ok_or(CanvasApplicationApprovalError::Unavailable)?
            .approve(
                organization_id,
                application_id,
                request.review_notes.as_deref(),
            )
            .await
            .map(CanvasApplicationApprovalResponse::from)
            .map_err(Into::into)
    }

    pub async fn create(
        &self,
        headers: &HeaderMap,
        request: CanvasPlatformRequest,
    ) -> Result<CanvasPlatformResponse, CanvasManagementHttpError> {
        self.management
            .create(
                request,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(CanvasPlatformResponse::from)
            .map_err(Into::into)
    }

    pub async fn list(
        &self,
        headers: &HeaderMap,
        claimed_organization_id: Option<&str>,
    ) -> Result<Vec<CanvasPlatformResponse>, CanvasManagementHttpError> {
        self.management
            .list(
                claimed_organization_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(|platforms| {
                platforms
                    .into_iter()
                    .map(CanvasPlatformResponse::from)
                    .collect()
            })
            .map_err(Into::into)
    }

    pub async fn get(
        &self,
        headers: &HeaderMap,
        platform_id: &str,
    ) -> Result<CanvasPlatformResponse, CanvasManagementHttpError> {
        self.management
            .get(
                platform_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(CanvasPlatformResponse::from)
            .map_err(Into::into)
    }

    pub async fn platform_readiness(
        &self,
        headers: &HeaderMap,
        platform_id: &str,
    ) -> Result<CanvasPlatformReadinessResponse, CanvasManagementHttpError> {
        self.management
            .platform_readiness(
                platform_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(CanvasPlatformReadinessResponse::from)
            .map_err(Into::into)
    }

    pub async fn create_binding(
        &self,
        headers: &HeaderMap,
        platform_id: &str,
        request: CanvasProgramBindingRequest,
    ) -> Result<CanvasProgramBindingResponse, CanvasManagementHttpError> {
        let binding = self
            .management
            .create_binding(
                platform_id,
                request,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await?;
        self.binding_response(headers, binding).await
    }

    pub async fn list_bindings(
        &self,
        headers: &HeaderMap,
        claimed_organization_id: Option<&str>,
        platform_id: Option<&str>,
        application_template_id: Option<&str>,
    ) -> Result<Vec<CanvasProgramBindingResponse>, CanvasManagementHttpError> {
        let bindings = self
            .management
            .list_bindings(
                claimed_organization_id,
                platform_id,
                application_template_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await?;
        let mut responses = Vec::with_capacity(bindings.len());
        for binding in bindings {
            responses.push(self.binding_response(headers, binding).await?);
        }
        Ok(responses)
    }

    pub async fn get_binding(
        &self,
        headers: &HeaderMap,
        binding_id: &str,
    ) -> Result<CanvasProgramBindingResponse, CanvasManagementHttpError> {
        let binding = self
            .management
            .get_binding(
                binding_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await?;
        self.binding_response(headers, binding).await
    }

    pub async fn update_binding(
        &self,
        headers: &HeaderMap,
        binding_id: &str,
        request: CanvasProgramBindingRequest,
    ) -> Result<CanvasProgramBindingResponse, CanvasManagementHttpError> {
        let binding = self
            .management
            .update_binding(
                binding_id,
                request,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await?;
        self.binding_response(headers, binding).await
    }

    pub async fn delete_binding(
        &self,
        headers: &HeaderMap,
        binding_id: &str,
    ) -> Result<(), CanvasManagementHttpError> {
        self.management
            .delete_binding(
                binding_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map_err(Into::into)
    }

    pub async fn validate_binding(
        &self,
        headers: &HeaderMap,
        binding_id: &str,
    ) -> Result<CanvasProgramBindingValidationResponse, CanvasManagementHttpError> {
        self.management
            .validate_binding(
                binding_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(CanvasProgramBindingValidationResponse::from)
            .map_err(Into::into)
    }

    pub async fn activate_binding(
        &self,
        headers: &HeaderMap,
        binding_id: &str,
    ) -> Result<CanvasProgramBindingValidationResponse, CanvasManagementHttpError> {
        self.management
            .activate_binding(
                binding_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(CanvasProgramBindingValidationResponse::from)
            .map_err(Into::into)
    }

    pub async fn deactivate_binding(
        &self,
        headers: &HeaderMap,
        binding_id: &str,
    ) -> Result<CanvasProgramBindingValidationResponse, CanvasManagementHttpError> {
        self.management
            .deactivate_binding(
                binding_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(CanvasProgramBindingValidationResponse::from)
            .map_err(Into::into)
    }

    pub async fn create_integration_secret(
        &self,
        headers: &HeaderMap,
        request: CanvasIntegrationSecretCreate,
    ) -> Result<CanvasIntegrationSecretResponse, CanvasManagementHttpError> {
        self.management
            .create_integration_secret(
                request,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    pub async fn validate_canvas_credentials_provider(
        &self,
        headers: &HeaderMap,
        request: CanvasCredentialsValidationRequest,
    ) -> Result<CanvasCredentialsValidationResult, CanvasManagementHttpError> {
        self.management
            .validate_canvas_credentials_provider(
                request,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map_err(Into::into)
    }

    pub async fn list_integration_secrets(
        &self,
        headers: &HeaderMap,
        organization_id: Option<&str>,
        provider: Option<&str>,
    ) -> Result<Vec<CanvasIntegrationSecretResponse>, CanvasManagementHttpError> {
        self.management
            .list_integration_secrets(
                organization_id,
                provider,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(|secrets| secrets.into_iter().map(Into::into).collect())
            .map_err(Into::into)
    }

    pub async fn update_integration_secret(
        &self,
        headers: &HeaderMap,
        secret_id: &str,
        request: CanvasIntegrationSecretUpdate,
    ) -> Result<CanvasIntegrationSecretResponse, CanvasManagementHttpError> {
        self.management
            .update_integration_secret(
                secret_id,
                request,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(Into::into)
            .map_err(Into::into)
    }

    pub async fn delete_integration_secret(
        &self,
        headers: &HeaderMap,
        secret_id: &str,
    ) -> Result<(), CanvasManagementHttpError> {
        self.management
            .delete_integration_secret(
                secret_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map_err(Into::into)
    }

    async fn binding_response(
        &self,
        headers: &HeaderMap,
        binding: CanvasProgramBindingRecord,
    ) -> Result<CanvasProgramBindingResponse, CanvasManagementHttpError> {
        let platform = self
            .management
            .get(
                &binding.platform_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await?;
        Ok(CanvasProgramBindingResponse::new(
            binding,
            platform.canvas_account_id,
        ))
    }

    pub async fn update(
        &self,
        headers: &HeaderMap,
        platform_id: &str,
        request: CanvasPlatformRequest,
    ) -> Result<CanvasPlatformResponse, CanvasManagementHttpError> {
        self.management
            .update(
                platform_id,
                request,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(CanvasPlatformResponse::from)
            .map_err(Into::into)
    }

    pub async fn delete(
        &self,
        headers: &HeaderMap,
        platform_id: &str,
    ) -> Result<(), CanvasManagementHttpError> {
        self.management
            .delete(
                platform_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map_err(Into::into)
    }

    pub async fn registration_config(
        &self,
        headers: &HeaderMap,
        platform_id: &str,
    ) -> Result<CanvasLtiRegistrationResponse, CanvasManagementHttpError> {
        self.management
            .registration_config(
                platform_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map_err(Into::into)
    }

    pub async fn public_registration_config(
        &self,
        token: &str,
    ) -> Result<Value, CanvasManagementHttpError> {
        self.management
            .public_registration_config(token)
            .await
            .map_err(Into::into)
    }

    pub async fn update_lti_installation(
        &self,
        headers: &HeaderMap,
        platform_id: &str,
        request: CanvasLtiInstallationRequest,
    ) -> Result<CanvasLtiRegistrationResponse, CanvasManagementHttpError> {
        self.management
            .update_lti_installation(
                platform_id,
                request,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map_err(Into::into)
    }

    pub async fn sandbox_probe(
        &self,
        headers: &HeaderMap,
        platform_id: &str,
    ) -> Result<CanvasPlatformSandboxProbeResponse, CanvasManagementHttpError> {
        self.management
            .sandbox_probe(
                platform_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(CanvasPlatformSandboxProbeResponse::from)
            .map_err(Into::into)
    }

    pub async fn refresh_jwks(
        &self,
        headers: &HeaderMap,
        platform_id: &str,
    ) -> Result<CanvasPlatformJwksRefreshResponse, CanvasManagementHttpError> {
        self.management
            .refresh_jwks(
                platform_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map(CanvasPlatformJwksRefreshResponse::from)
            .map_err(Into::into)
    }

    pub async fn discover_scope(
        &self,
        headers: &HeaderMap,
        platform_id: &str,
        request: CanvasScopeDiscoveryRequest,
    ) -> Result<CanvasScopeDiscoveryResponse, CanvasManagementHttpError> {
        let platform = self
            .management
            .get(
                platform_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await?;
        let runtime =
            self.catalog
                .as_ref()
                .ok_or(CanvasManagementHttpError::DiscoveryUnavailable {
                    retry_after_seconds: None,
                })?;
        let token = runtime
            .oauth
            .access_token(
                platform_id,
                header(headers, "X-API-Key"),
                header(headers, "X-Organization-ID"),
            )
            .await
            .map_err(map_discovery_oauth_error)?
            .or_else(|| runtime.local_admin_token.clone())
            .ok_or(CanvasManagementHttpError::DiscoveryOAuthRequired)?;
        let canvas_base_url = platform
            .canvas_base_url
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or(CanvasManagementHttpError::DiscoveryBaseUrlRequired)?;
        match discover_canvas_scope(
            runtime.provider.clone(),
            platform.id,
            platform.organization_id,
            canvas_base_url,
            &token,
            request,
        )
        .await
        {
            Ok(response) => Ok(response),
            Err(CanvasCatalogProviderError::ReauthorizationRequired) => {
                runtime
                    .oauth
                    .mark_rejected_access_token(
                        platform_id,
                        &token,
                        header(headers, "X-API-Key"),
                        header(headers, "X-Organization-ID"),
                    )
                    .await
                    .map_err(map_discovery_oauth_error)?;
                Err(CanvasManagementHttpError::DiscoveryReauthorizationRequired)
            }
            Err(CanvasCatalogProviderError::TemporarilyUnavailable {
                retry_after_seconds,
            }) => Err(CanvasManagementHttpError::DiscoveryUnavailable {
                retry_after_seconds,
            }),
            Err(CanvasCatalogProviderError::BadGateway(detail)) => {
                Err(CanvasManagementHttpError::DiscoveryBadGateway(detail))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasPlatformSandboxProbeResponse {
    pub platform: CanvasPlatformResponse,
    pub probe: crate::canvas_lti_probe::CanvasLtiProbeResponse,
}

impl From<CanvasPlatformProbeResult> for CanvasPlatformSandboxProbeResponse {
    fn from(result: CanvasPlatformProbeResult) -> Self {
        Self {
            platform: CanvasPlatformResponse::from(result.platform),
            probe: result.probe,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasPlatformJwksRefreshResponse {
    pub platform: CanvasPlatformResponse,
    pub refreshed: bool,
    pub probe: crate::canvas_lti_probe::CanvasLtiProbeResponse,
}

impl From<CanvasPlatformProbeResult> for CanvasPlatformJwksRefreshResponse {
    fn from(result: CanvasPlatformProbeResult) -> Self {
        Self {
            platform: CanvasPlatformResponse::from(result.platform),
            refreshed: true,
            probe: result.probe,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasPlatformReadinessResponse {
    pub platform_id: String,
    pub ready: bool,
    pub checks: Vec<CanvasReadinessCheck>,
}

impl From<CanvasPlatformReadinessResult> for CanvasPlatformReadinessResponse {
    fn from(result: CanvasPlatformReadinessResult) -> Self {
        let ready = result.ready();
        Self {
            platform_id: result.platform_id,
            ready,
            checks: result.checks,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasProgramBindingValidationResponse {
    pub binding_id: String,
    pub ready: bool,
    pub valid: bool,
    pub active: bool,
    pub config_version: i64,
    pub evaluated_at: Option<String>,
    pub checks: Vec<CanvasReadinessCheck>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasIntegrationSecretResponse {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub provider: String,
    pub purpose: String,
    pub secret_ref: String,
    pub secret_hint: Option<String>,
    pub metadata: Map<String, Value>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanvasApplicationApprovalResponse {
    pub application_id: String,
    pub status: &'static str,
    pub issuance_transaction_id: String,
}

impl From<crate::canvas_award_candidate_approval::CanvasApplicationApprovalResult>
    for CanvasApplicationApprovalResponse
{
    fn from(
        result: crate::canvas_award_candidate_approval::CanvasApplicationApprovalResult,
    ) -> Self {
        Self {
            application_id: result.application_id,
            status: "approved",
            issuance_transaction_id: result.issuance_transaction_id,
        }
    }
}

impl From<ManagedIntegrationSecret> for CanvasIntegrationSecretResponse {
    fn from(secret: ManagedIntegrationSecret) -> Self {
        Self {
            secret_ref: secret.secret_ref(),
            id: secret.id,
            organization_id: secret.organization_id,
            name: secret.name,
            provider: secret.provider,
            purpose: secret.purpose,
            secret_hint: secret.secret_hint,
            metadata: secret.metadata,
            enabled: secret.enabled,
            created_at: timestamp(secret.created_at),
            updated_at: timestamp(secret.updated_at),
            last_used_at: optional_timestamp(secret.last_used_at),
        }
    }
}

impl From<CanvasBindingValidationResult> for CanvasProgramBindingValidationResponse {
    fn from(result: CanvasBindingValidationResult) -> Self {
        Self {
            binding_id: result.binding.id,
            ready: result.readiness.ready,
            valid: result.readiness.ready,
            active: result.binding.enabled,
            config_version: result.binding.config_version,
            evaluated_at: Some(timestamp(result.readiness.evaluated_at)),
            checks: result.readiness.checks,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasProgramBindingResponse {
    pub id: String,
    pub organization_id: String,
    pub platform_id: String,
    pub canvas_account_id: String,
    pub application_template_id: String,
    pub credential_template_id: String,
    pub display_name: Option<String>,
    pub flow_mode: String,
    pub direct_issue_enabled: bool,
    pub auto_approve_on_evidence: bool,
    pub evidence_requirements: Vec<Value>,
    pub canvas_scope: std::collections::BTreeMap<String, String>,
    pub delivery_mode: String,
    pub issuer_mode: String,
    pub approval_policy_set_id: Option<String>,
    pub deployment_profile_id: Option<String>,
    pub feature_flags: std::collections::BTreeMap<String, bool>,
    pub canvas_credentials: Map<String, Value>,
    pub config_version: i64,
    pub validated_config_version: Option<i64>,
    pub readiness_checks: Vec<Value>,
    pub readiness_validated_at: Option<String>,
    pub activated_at: Option<String>,
    pub archived_at: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl CanvasProgramBindingResponse {
    fn new(binding: CanvasProgramBindingRecord, canvas_account_id: String) -> Self {
        Self {
            id: binding.id,
            organization_id: binding.organization_id,
            platform_id: binding.platform_id,
            canvas_account_id,
            application_template_id: binding.application_template_id,
            credential_template_id: binding.credential_template_id,
            display_name: binding.display_name,
            flow_mode: binding.flow_mode,
            direct_issue_enabled: binding.direct_issue_enabled,
            auto_approve_on_evidence: binding.auto_approve_on_evidence,
            evidence_requirements: binding.evidence_requirements,
            canvas_scope: binding.canvas_scope,
            delivery_mode: binding.delivery_mode,
            issuer_mode: binding.issuer_mode,
            approval_policy_set_id: binding.approval_policy_set_id,
            deployment_profile_id: binding.deployment_profile_id,
            feature_flags: binding.feature_flags,
            canvas_credentials: binding.canvas_credentials,
            config_version: binding.config_version,
            validated_config_version: binding.validated_config_version,
            readiness_checks: binding.readiness_checks,
            readiness_validated_at: optional_timestamp(binding.readiness_validated_at),
            activated_at: optional_timestamp(binding.activated_at),
            archived_at: optional_timestamp(binding.archived_at),
            enabled: binding.enabled,
            created_at: timestamp(binding.created_at),
            updated_at: timestamp(binding.updated_at),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasPlatformResponse {
    pub id: String,
    pub organization_id: String,
    pub canvas_account_id: String,
    pub display_name: Option<String>,
    pub canvas_base_url: Option<String>,
    pub lti_client_id: Option<String>,
    pub lti_deployment_id: Option<String>,
    pub lti_trust_profile: String,
    pub lti_issuer: Option<String>,
    pub lti_jwks_url: Option<String>,
    pub lti_jwks_fetched_at: Option<String>,
    pub lti_jwks_expires_at: Option<String>,
    pub registration_status: String,
    pub connection_config: Map<String, Value>,
    pub capability_snapshot: Map<String, Value>,
    pub last_validated_at: Option<String>,
    pub last_connection_error: Option<String>,
    pub config_version: i64,
    pub archived_at: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<CanvasPlatformRecord> for CanvasPlatformResponse {
    fn from(platform: CanvasPlatformRecord) -> Self {
        let connection_config = SAFE_CONNECTION_CONFIG_KEYS
            .iter()
            .filter_map(|key| {
                platform
                    .connection_config
                    .get(*key)
                    .cloned()
                    .map(|value| ((*key).to_owned(), value))
            })
            .collect();
        Self {
            id: platform.id,
            organization_id: platform.organization_id,
            canvas_account_id: platform.canvas_account_id,
            display_name: platform.display_name,
            canvas_base_url: platform.canvas_base_url,
            lti_client_id: platform.lti_client_id,
            lti_deployment_id: platform.lti_deployment_id,
            lti_trust_profile: platform.lti_trust_profile,
            lti_issuer: platform.lti_issuer,
            lti_jwks_url: platform.lti_jwks_url,
            lti_jwks_fetched_at: optional_timestamp(platform.lti_jwks_fetched_at),
            lti_jwks_expires_at: optional_timestamp(platform.lti_jwks_expires_at),
            registration_status: platform.registration_status,
            connection_config,
            capability_snapshot: platform.capability_snapshot,
            last_validated_at: optional_timestamp(platform.last_validated_at),
            last_connection_error: platform.last_connection_error,
            config_version: platform.config_version,
            archived_at: optional_timestamp(platform.archived_at),
            enabled: platform.enabled,
            created_at: timestamp(platform.created_at),
            updated_at: timestamp(platform.updated_at),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum CanvasManagementHttpError {
    Service(CanvasPlatformManagementError),
    ApplicationApproval(CanvasApplicationApprovalError),
    Validation(Vec<Value>),
    BodyTooLarge,
    DiscoveryOAuthRequired,
    DiscoveryReauthorizationRequired,
    DiscoveryBaseUrlRequired,
    DiscoveryPilotDisabled,
    DiscoveryUnavailable { retry_after_seconds: Option<u64> },
    DiscoveryBadGateway(String),
}

impl From<CanvasPlatformManagementError> for CanvasManagementHttpError {
    fn from(error: CanvasPlatformManagementError) -> Self {
        Self::Service(error)
    }
}

impl From<CanvasApplicationApprovalError> for CanvasManagementHttpError {
    fn from(error: CanvasApplicationApprovalError) -> Self {
        Self::ApplicationApproval(error)
    }
}

impl IntoResponse for CanvasManagementHttpError {
    fn into_response(self) -> Response {
        match self {
            Self::ApplicationApproval(error) => application_approval_failure(error),
            Self::Validation(errors) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"detail": errors})),
            )
                .into_response(),
            Self::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"detail": "Canvas management request body exceeds the size limit"})),
                )
                .into_response(),
            Self::DiscoveryOAuthRequired => (
                StatusCode::BAD_REQUEST,
                Json(json!({"detail": "Canvas scope discovery requires an organization OAuth connection; environment tokens are local compatibility fallbacks"})),
            )
                .into_response(),
            Self::DiscoveryReauthorizationRequired => (
                StatusCode::UNAUTHORIZED,
                Json(json!({"detail": "Canvas OAuth connection requires reauthorization"})),
            )
                .into_response(),
            Self::DiscoveryBaseUrlRequired => (
                StatusCode::BAD_REQUEST,
                Json(json!({"detail": "Canvas platform requires canvas_base_url for admin discovery"})),
            )
                .into_response(),
            Self::DiscoveryPilotDisabled => (
                StatusCode::NOT_FOUND,
                Json(json!({"detail": "Portable Canvas integration is not enabled for this organization"})),
            )
                .into_response(),
            Self::DiscoveryUnavailable {
                retry_after_seconds,
            } => {
                let mut response = (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"detail": "Canvas discovery is temporarily unavailable"})),
                )
                    .into_response();
                if let Some(seconds) = retry_after_seconds {
                    if let Ok(value) = seconds.to_string().parse() {
                        response.headers_mut().insert("retry-after", value);
                    }
                }
                response
            }
            Self::DiscoveryBadGateway(detail) => {
                (StatusCode::BAD_GATEWAY, Json(json!({"detail": detail}))).into_response()
            }
            Self::Service(error) => service_failure(error),
        }
    }
}

fn map_discovery_oauth_error(error: CanvasOAuthError) -> CanvasManagementHttpError {
    match error {
        CanvasOAuthError::PlatformNotFound => {
            CanvasManagementHttpError::Service(CanvasPlatformManagementError::PlatformNotFound)
        }
        CanvasOAuthError::PilotDisabled => CanvasManagementHttpError::DiscoveryPilotDisabled,
        CanvasOAuthError::BaseUrlRequired => CanvasManagementHttpError::DiscoveryBaseUrlRequired,
        CanvasOAuthError::RefreshRateLimited {
            retry_after_seconds,
        } => CanvasManagementHttpError::DiscoveryUnavailable {
            retry_after_seconds: Some(retry_after_seconds),
        },
        CanvasOAuthError::RepositoryUnavailable
        | CanvasOAuthError::SecretUnavailable
        | CanvasOAuthError::InvalidConfiguration => {
            CanvasManagementHttpError::DiscoveryUnavailable {
                retry_after_seconds: None,
            }
        }
        CanvasOAuthError::Security(error) => {
            CanvasManagementHttpError::Service(CanvasPlatformManagementError::Security(error))
        }
        CanvasOAuthError::OriginUntrusted
        | CanvasOAuthError::ConnectionExists
        | CanvasOAuthError::SecretNotFound
        | CanvasOAuthError::ClientIdRequired
        | CanvasOAuthError::CapabilitiesRequired
        | CanvasOAuthError::UnsupportedCapabilities(_)
        | CanvasOAuthError::ConfigurationChanged
        | CanvasOAuthError::ConnectionChanged => CanvasManagementHttpError::DiscoveryUnavailable {
            retry_after_seconds: None,
        },
    }
}

pub async fn parse_platform_request(
    request: axum::extract::Request,
) -> Result<CanvasPlatformRequest, CanvasManagementHttpError> {
    let mut value = parse_management_json(request).await?;
    validate_platform_request_value(&mut value)?;
    serde_json::from_value(value).map_err(|_| {
        CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid Canvas platform request",
            "input": null,
        })])
    })
}

pub async fn parse_lti_installation_request(
    request: axum::extract::Request,
) -> Result<CanvasLtiInstallationRequest, CanvasManagementHttpError> {
    let mut value = parse_management_json(request).await?;
    validate_lti_installation_value(&mut value)?;
    serde_json::from_value(value).map_err(|_| {
        CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid Canvas LTI installation request",
            "input": null,
        })])
    })
}

pub async fn parse_program_binding_request(
    request: axum::extract::Request,
) -> Result<CanvasProgramBindingRequest, CanvasManagementHttpError> {
    let mut value = parse_management_json(request).await?;
    validate_program_binding_request_value(&mut value)?;
    let parsed: CanvasProgramBindingRequest =
        serde_json::from_value(value.clone()).map_err(|_| {
            CanvasManagementHttpError::Validation(vec![json!({
                "type": "model_attributes_type",
                "loc": ["body"],
                "msg": "Input should be a valid Canvas program binding request",
                "input": value,
            })])
        })?;
    parsed.validate().map_err(|error| {
        CanvasManagementHttpError::Validation(vec![json!({
            "type": "value_error",
            "loc": ["body"],
            "msg": error.to_string(),
            "input": value,
        })])
    })?;
    Ok(parsed)
}

pub async fn parse_application_approval(
    request: axum::extract::Request,
) -> Result<CanvasApplicationApprovalRequest, CanvasManagementHttpError> {
    let value = parse_management_json(request).await?;
    let Some(object) = value.as_object() else {
        return Err(CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": value,
        })]));
    };
    let mut errors = Vec::new();
    validate_optional_string(object, "review_notes", 4_000, &mut errors);
    for (field, input) in object {
        if field != "review_notes" {
            errors.push(json!({
                "type": "extra_forbidden",
                "loc": ["body", field],
                "msg": "Extra inputs are not permitted",
                "input": input,
            }));
        }
    }
    if !errors.is_empty() {
        return Err(CanvasManagementHttpError::Validation(errors));
    }
    serde_json::from_value(value).map_err(|_| {
        CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid Canvas application approval request",
            "input": null,
        })])
    })
}

pub async fn parse_integration_secret_create(
    request: axum::extract::Request,
) -> Result<CanvasIntegrationSecretCreate, CanvasManagementHttpError> {
    let mut value = parse_management_json(request).await?;
    normalize_optional_pydantic_bool_field(&mut value, "enabled", false)?;
    let parsed: CanvasIntegrationSecretCreate =
        serde_json::from_value(value.clone()).map_err(|_| {
            CanvasManagementHttpError::Validation(vec![json!({
                "type": "model_attributes_type", "loc": ["body"],
                "msg": "Input should be a valid Canvas integration secret", "input": value,
            })])
        })?;
    parsed.validate().map_err(|error| {
        CanvasManagementHttpError::Validation(vec![json!({
            "type": "value_error", "loc": ["body"], "msg": error.to_string(), "input": value,
        })])
    })?;
    Ok(parsed)
}

pub async fn parse_canvas_credentials_validation_request(
    request: axum::extract::Request,
) -> Result<CanvasCredentialsValidationRequest, CanvasManagementHttpError> {
    let value = parse_management_json(request).await?;
    serde_json::from_value(value.clone()).map_err(|_| {
        CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type", "loc": ["body"],
            "msg": "Input should be a valid Canvas Credentials validation request", "input": value,
        })])
    })
}

pub async fn parse_integration_secret_update(
    request: axum::extract::Request,
) -> Result<CanvasIntegrationSecretUpdate, CanvasManagementHttpError> {
    let mut value = parse_management_json(request).await?;
    normalize_optional_pydantic_bool_field(&mut value, "enabled", true)?;
    serde_json::from_value(value.clone()).map_err(|_| {
        CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type", "loc": ["body"],
            "msg": "Input should be a valid Canvas integration secret update", "input": value,
        })])
    })
}

pub fn integration_secret_query(query: Option<&str>) -> (Option<String>, Option<String>) {
    let mut organization_id = None;
    let mut provider = Some("canvas_credentials".to_owned());
    for (name, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        match name.as_ref() {
            "organization_id" => organization_id = Some(value.into_owned()),
            "provider" => provider = Some(value.into_owned()),
            _ => {}
        }
    }
    (organization_id, provider)
}

fn normalize_optional_pydantic_bool_field(
    value: &mut Value,
    field: &str,
    allow_null: bool,
) -> Result<(), CanvasManagementHttpError> {
    let Some(object) = value.as_object_mut() else {
        return Ok(());
    };
    let Some(input) = object.get(field).cloned() else {
        return Ok(());
    };
    if allow_null && input.is_null() {
        return Ok(());
    }
    if let Some(normalized) = pydantic_bool(&input) {
        object.insert(field.to_owned(), Value::Bool(normalized));
        return Ok(());
    }
    let structured = input.is_array() || input.is_object() || input.is_null();
    Err(CanvasManagementHttpError::Validation(vec![json!({
        "type": if structured { "bool_type" } else { "bool_parsing" },
        "loc": ["body", field],
        "msg": if structured {
            "Input should be a valid boolean"
        } else {
            "Input should be a valid boolean, unable to interpret input"
        },
        "input": input,
    })]))
}

pub async fn parse_scope_discovery_request(
    request: axum::extract::Request,
) -> Result<CanvasScopeDiscoveryRequest, CanvasManagementHttpError> {
    let mut value = parse_management_json(request).await?;
    validate_scope_discovery_value(&mut value, "body", true)?;
    serde_json::from_value(value).map_err(|_| {
        CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid Canvas scope discovery request",
            "input": null,
        })])
    })
}

pub fn parse_scope_discovery_query(
    query: Option<&str>,
) -> Result<CanvasScopeDiscoveryRequest, CanvasManagementHttpError> {
    let mut object = Map::new();
    for (name, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        if matches!(
            name.as_ref(),
            "course_id"
                | "include_courses"
                | "include_assignments"
                | "include_quizzes"
                | "include_modules"
                | "limit"
        ) {
            object.insert(name.into_owned(), Value::String(value.into_owned()));
        }
    }
    let mut value = Value::Object(object);
    validate_scope_discovery_value(&mut value, "query", false)?;
    serde_json::from_value(value).map_err(|_| {
        CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["query"],
            "msg": "Input should be a valid Canvas scope discovery query",
            "input": null,
        })])
    })
}

async fn parse_management_json(
    request: axum::extract::Request,
) -> Result<Value, CanvasManagementHttpError> {
    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase);
    if content_type.as_deref() != Some("application/json") {
        return Err(CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": null,
        })]));
    }
    let bytes = to_bytes(request.into_body(), MAX_MANAGEMENT_BODY_BYTES)
        .await
        .map_err(|_| CanvasManagementHttpError::BodyTooLarge)?;
    serde_json::from_slice(&bytes).map_err(|_| {
        CanvasManagementHttpError::Validation(vec![json!({
            "type": "json_invalid",
            "loc": ["body"],
            "msg": "JSON decode error",
            "input": null,
        })])
    })
}

pub fn organization_id_from_query(query: Option<&str>) -> Option<String> {
    query_value(query, "organization_id")
}

pub fn program_binding_query(
    query: Option<&str>,
) -> (Option<String>, Option<String>, Option<String>) {
    (
        query_value(query, "organization_id"),
        query_value(query, "platform_id"),
        query_value(query, "application_template_id"),
    )
}

fn query_value(query: Option<&str>, expected: &str) -> Option<String> {
    query.and_then(|query| {
        url::form_urlencoded::parse(query.as_bytes())
            .filter(|(name, _)| name == expected)
            .map(|(_, value)| value.into_owned())
            .last()
    })
}

fn validate_platform_request_value(value: &mut Value) -> Result<(), CanvasManagementHttpError> {
    let invalid_input = value.clone();
    let Some(object) = value.as_object_mut() else {
        return Err(CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": invalid_input,
        })]));
    };
    let mut errors = Vec::new();
    validate_optional_string(object, "display_name", 200, &mut errors);
    validate_required_string(object, "canvas_base_url", 2_048, &mut errors);
    validate_optional_string(object, "lti_client_id", 512, &mut errors);
    validate_optional_string(object, "lti_deployment_id", 512, &mut errors);
    if let Some(enabled) = object.get("enabled").cloned() {
        if let Some(normalized) = pydantic_bool(&enabled) {
            object.insert("enabled".to_owned(), Value::Bool(normalized));
        } else {
            let structured = enabled.is_array() || enabled.is_object() || enabled.is_null();
            errors.push(json!({
                "type": if structured { "bool_type" } else { "bool_parsing" },
                "loc": ["body", "enabled"],
                "msg": if structured {
                    "Input should be a valid boolean"
                } else {
                    "Input should be a valid boolean, unable to interpret input"
                },
                "input": enabled,
            }));
        }
    }
    for (name, input) in object.iter().filter(|(name, _)| {
        !matches!(
            name.as_str(),
            "display_name" | "canvas_base_url" | "lti_client_id" | "lti_deployment_id" | "enabled"
        )
    }) {
        errors.push(json!({
            "type": "extra_forbidden",
            "loc": ["body", name],
            "msg": "Extra inputs are not permitted",
            "input": input,
        }));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(CanvasManagementHttpError::Validation(errors))
    }
}

fn validate_program_binding_request_value(
    value: &mut Value,
) -> Result<(), CanvasManagementHttpError> {
    let invalid_input = value.clone();
    let Some(object) = value.as_object_mut() else {
        return Err(CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": invalid_input,
        })]));
    };
    let mut errors = Vec::new();
    validate_required_string(object, "application_template_id", 512, &mut errors);
    validate_optional_string(object, "credential_template_id", 512, &mut errors);
    validate_optional_string(object, "display_name", 200, &mut errors);

    let allowed = [
        "application_template_id",
        "credential_template_id",
        "display_name",
        "auto_approve_on_evidence",
        "evidence_requirements",
        "canvas_scope",
        "delivery_mode",
        "approval_policy_set_id",
        "deployment_profile_id",
        "feature_flags",
        "canvas_credentials",
    ];
    for (name, input) in object.iter() {
        if !allowed.contains(&name.as_str()) {
            errors.push(json!({
                "type": "extra_forbidden",
                "loc": ["body", name],
                "msg": "Extra inputs are not permitted",
                "input": input,
            }));
        }
    }

    let approve = object
        .entry("auto_approve_on_evidence")
        .or_insert(Value::Bool(false));
    match pydantic_bool(approve) {
        Some(value) => *approve = Value::Bool(value),
        None => errors.push(json!({
            "type": if approve.is_array() || approve.is_object() || approve.is_null() {
                "bool_type"
            } else {
                "bool_parsing"
            },
            "loc": ["body", "auto_approve_on_evidence"],
            "msg": "Input should be a valid boolean",
            "input": approve,
        })),
    }

    match object.get_mut("evidence_requirements") {
        None => errors.push(json!({
            "type": "missing",
            "loc": ["body", "evidence_requirements"],
            "msg": "Field required",
            "input": object,
        })),
        Some(Value::Array(requirements)) if requirements.is_empty() => errors.push(json!({
            "type": "too_short",
            "loc": ["body", "evidence_requirements"],
            "msg": "List should have at least 1 item after validation, not 0",
            "input": requirements,
        })),
        Some(Value::Array(requirements)) => {
            for (index, requirement) in requirements.iter_mut().enumerate() {
                let Some(requirement) = requirement.as_object_mut() else {
                    continue;
                };
                let required = requirement.entry("required").or_insert(Value::Bool(true));
                match pydantic_bool(required) {
                    Some(value) => *required = Value::Bool(value),
                    None => errors.push(json!({
                        "type": if required.is_array() || required.is_object() || required.is_null() {
                            "bool_type"
                        } else {
                            "bool_parsing"
                        },
                        "loc": ["body", "evidence_requirements", index, "required"],
                        "msg": "Input should be a valid boolean",
                        "input": required,
                    })),
                }
            }
        }
        Some(input) => errors.push(json!({
            "type": "list_type",
            "loc": ["body", "evidence_requirements"],
            "msg": "Input should be a valid list",
            "input": input,
        })),
    }

    if let Some(input) = object.get_mut("feature_flags") {
        if let Some(flags) = input.as_object_mut() {
            for (name, value) in flags.iter_mut() {
                match pydantic_bool(value) {
                    Some(coerced) => *value = Value::Bool(coerced),
                    None => errors.push(json!({
                        "type": "bool_parsing",
                        "loc": ["body", "feature_flags", name],
                        "msg": "Input should be a valid boolean",
                        "input": value,
                    })),
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(CanvasManagementHttpError::Validation(errors))
    }
}

fn validate_lti_installation_value(value: &mut Value) -> Result<(), CanvasManagementHttpError> {
    let invalid_input = value.clone();
    let Some(object) = value.as_object_mut() else {
        return Err(CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": ["body"],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": invalid_input,
        })]));
    };
    let mut errors = Vec::new();
    validate_required_string(
        object,
        "lti_client_id",
        MAX_MANAGEMENT_BODY_BYTES,
        &mut errors,
    );
    validate_required_string(
        object,
        "lti_deployment_id",
        MAX_MANAGEMENT_BODY_BYTES,
        &mut errors,
    );
    for name in ["rotate_config_token", "revoke_config_token"] {
        if let Some(input) = object.get(name).cloned() {
            if let Some(normalized) = pydantic_bool(&input) {
                object.insert(name.to_owned(), Value::Bool(normalized));
            } else {
                let structured = input.is_array() || input.is_object() || input.is_null();
                errors.push(json!({
                    "type": if structured { "bool_type" } else { "bool_parsing" },
                    "loc": ["body", name],
                    "msg": if structured {
                        "Input should be a valid boolean"
                    } else {
                        "Input should be a valid boolean, unable to interpret input"
                    },
                    "input": input,
                }));
            }
        }
    }
    for (name, input) in object.iter().filter(|(name, _)| {
        !matches!(
            name.as_str(),
            "lti_client_id" | "lti_deployment_id" | "rotate_config_token" | "revoke_config_token"
        )
    }) {
        errors.push(json!({
            "type": "extra_forbidden",
            "loc": ["body", name],
            "msg": "Extra inputs are not permitted",
            "input": input,
        }));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(CanvasManagementHttpError::Validation(errors))
    }
}

fn validate_scope_discovery_value(
    value: &mut Value,
    location: &'static str,
    forbid_extra: bool,
) -> Result<(), CanvasManagementHttpError> {
    let invalid_input = value.clone();
    let Some(object) = value.as_object_mut() else {
        return Err(CanvasManagementHttpError::Validation(vec![json!({
            "type": "model_attributes_type",
            "loc": [location],
            "msg": "Input should be a valid dictionary or object to extract fields from",
            "input": invalid_input,
        })]));
    };
    let mut errors = Vec::new();
    validate_optional_string(object, "course_id", MAX_MANAGEMENT_BODY_BYTES, &mut errors);
    for name in [
        "include_courses",
        "include_assignments",
        "include_quizzes",
        "include_modules",
    ] {
        if let Some(input) = object.get(name).cloned() {
            if let Some(normalized) = pydantic_bool(&input) {
                object.insert(name.to_owned(), Value::Bool(normalized));
            } else {
                let structured = input.is_array() || input.is_object() || input.is_null();
                errors.push(json!({
                    "type": if structured { "bool_type" } else { "bool_parsing" },
                    "loc": [location, name],
                    "msg": if structured {
                        "Input should be a valid boolean"
                    } else {
                        "Input should be a valid boolean, unable to interpret input"
                    },
                    "input": input,
                }));
            }
        }
    }
    if let Some(input) = object.get("limit").cloned() {
        match pydantic_integer(&input) {
            Some(limit) if limit < 1 => errors.push(json!({
                "type": "greater_than_equal",
                "loc": [location, "limit"],
                "msg": "Input should be greater than or equal to 1",
                "input": input,
                "ctx": {"ge": 1},
            })),
            Some(limit) if limit > 100 => errors.push(json!({
                "type": "less_than_equal",
                "loc": [location, "limit"],
                "msg": "Input should be less than or equal to 100",
                "input": input,
                "ctx": {"le": 100},
            })),
            Some(limit) => {
                object.insert("limit".to_owned(), Value::Number(limit.into()));
            }
            None => errors.push(json!({
                "type": if input.is_array() || input.is_object() || input.is_null() || input.is_boolean() {
                    "int_type"
                } else {
                    "int_parsing"
                },
                "loc": [location, "limit"],
                "msg": "Input should be a valid integer, unable to parse string as an integer",
                "input": input,
            })),
        }
    }
    if forbid_extra {
        for (name, input) in object.iter().filter(|(name, _)| {
            !matches!(
                name.as_str(),
                "course_id"
                    | "include_courses"
                    | "include_assignments"
                    | "include_quizzes"
                    | "include_modules"
                    | "limit"
            )
        }) {
            errors.push(json!({
                "type": "extra_forbidden",
                "loc": [location, name],
                "msg": "Extra inputs are not permitted",
                "input": input,
            }));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(CanvasManagementHttpError::Validation(errors))
    }
}

fn pydantic_bool(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Number(value) if value.as_f64() == Some(1.0) => Some(true),
        Value::Number(value) if value.as_f64() == Some(0.0) => Some(false),
        Value::String(value) => match value.to_ascii_lowercase().as_str() {
            "1" | "on" | "t" | "true" | "y" | "yes" => Some(true),
            "0" | "off" | "f" | "false" | "n" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn pydantic_integer(value: &Value) -> Option<i64> {
    match value {
        Value::Number(value) => value.as_i64().or_else(|| {
            value.as_f64().and_then(|value| {
                (value.is_finite()
                    && value.fract() == 0.0
                    && value >= i64::MIN as f64
                    && value <= i64::MAX as f64)
                    .then_some(value as i64)
            })
        }),
        Value::String(value) => value.parse().ok(),
        _ => None,
    }
}

fn validate_required_string(
    object: &Map<String, Value>,
    name: &'static str,
    max: usize,
    errors: &mut Vec<Value>,
) {
    let Some(input) = object.get(name) else {
        errors.push(json!({
            "type": "missing",
            "loc": ["body", name],
            "msg": "Field required",
            "input": object,
        }));
        return;
    };
    validate_string(input, name, true, max, errors);
}

fn validate_optional_string(
    object: &Map<String, Value>,
    name: &'static str,
    max: usize,
    errors: &mut Vec<Value>,
) {
    let Some(input) = object.get(name) else {
        return;
    };
    if input.is_null() {
        return;
    }
    validate_string(input, name, false, max, errors);
}

fn validate_string(
    input: &Value,
    name: &'static str,
    required: bool,
    max: usize,
    errors: &mut Vec<Value>,
) {
    let Some(value) = input.as_str() else {
        errors.push(json!({
            "type": "string_type",
            "loc": ["body", name],
            "msg": "Input should be a valid string",
            "input": input,
        }));
        return;
    };
    let length = value.chars().count();
    if required && length == 0 {
        errors.push(json!({
            "type": "string_too_short",
            "loc": ["body", name],
            "msg": "String should have at least 1 character",
            "input": input,
            "ctx": {"min_length": 1},
        }));
    } else if length > max {
        errors.push(json!({
            "type": "string_too_long",
            "loc": ["body", name],
            "msg": format!("String should have at most {max} characters"),
            "input": input,
            "ctx": {"max_length": max},
        }));
    }
}

fn application_approval_failure(error: CanvasApplicationApprovalError) -> Response {
    let (status, detail) = match error {
        CanvasApplicationApprovalError::NotFound => {
            (StatusCode::NOT_FOUND, "Canvas application not found")
        }
        CanvasApplicationApprovalError::RolloutDisabled => (
            StatusCode::NOT_FOUND,
            "Portable Canvas integration is not enabled for this organization",
        ),
        CanvasApplicationApprovalError::InvalidStatus => (
            StatusCode::CONFLICT,
            "Canvas application cannot be approved in its current status",
        ),
        CanvasApplicationApprovalError::NotReady => (
            StatusCode::CONFLICT,
            "Canvas application is not ready for approval",
        ),
        CanvasApplicationApprovalError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Canvas application approval is temporarily unavailable",
        ),
    };
    (status, Json(json!({"detail": detail}))).into_response()
}

fn service_failure(error: CanvasPlatformManagementError) -> Response {
    if let CanvasPlatformManagementError::ActivationBlocked(checks) = error {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "detail": {
                    "message": "Canvas program binding has blocking readiness checks",
                    "checks": checks,
                }
            })),
        )
            .into_response();
    }
    let (status, detail) = match error {
        CanvasPlatformManagementError::Security(error) => match error {
            TransactionReadError::ApiKeyNotConfigured => (
                StatusCode::SERVICE_UNAVAILABLE,
                "ISSUANCE_API_KEY not configured on server".to_owned(),
            ),
            TransactionReadError::ApiKeyMissing => (
                StatusCode::UNAUTHORIZED,
                "X-API-Key header is missing".to_owned(),
            ),
            TransactionReadError::InvalidApiKey => {
                (StatusCode::UNAUTHORIZED, "Invalid API Key".to_owned())
            }
            TransactionReadError::TrustedOrganizationRequired => (
                StatusCode::BAD_REQUEST,
                "X-Organization-ID is required for Canvas management".to_owned(),
            ),
            TransactionReadError::OrganizationIdRequired => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({
                        "detail": [{
                            "type": "missing",
                            "loc": ["query", "organization_id"],
                            "msg": "Field required",
                            "input": null,
                        }]
                    })),
                )
                    .into_response();
            }
            TransactionReadError::ResourceNotFound | TransactionReadError::OrganizationMismatch => {
                (
                    StatusCode::NOT_FOUND,
                    "Canvas resource not found".to_owned(),
                )
            }
            _ => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Canvas management authentication is unavailable".to_owned(),
            ),
        },
        CanvasPlatformManagementError::Domain(error) => match error {
            CanvasManagementDomainError::InvalidRequest(error) => {
                (StatusCode::UNPROCESSABLE_ENTITY, error.to_string())
            }
            CanvasManagementDomainError::OriginUntrusted => (
                StatusCode::BAD_REQUEST,
                "Invalid Canvas base URL: Canvas base URL is not permitted by operator policy"
                    .to_owned(),
            ),
            CanvasManagementDomainError::VersionExhausted => (
                StatusCode::CONFLICT,
                "Canvas platform configuration version is exhausted".to_owned(),
            ),
            CanvasManagementDomainError::InvalidJwksTtl => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Canvas JWKS cache TTL is invalid".to_owned(),
            ),
        },
        CanvasPlatformManagementError::PlatformNotFound => (
            StatusCode::NOT_FOUND,
            "Canvas platform not found".to_owned(),
        ),
        CanvasPlatformManagementError::LtiConfigurationNotFound => (
            StatusCode::NOT_FOUND,
            "Canvas LTI configuration not found".to_owned(),
        ),
        CanvasPlatformManagementError::ConflictingTokenMutation => (
            StatusCode::BAD_REQUEST,
            "Rotate and revoke are mutually exclusive".to_owned(),
        ),
        CanvasPlatformManagementError::LtiMetadataProbeFailed(error) => (
            StatusCode::CONFLICT,
            format!("Canvas LTI metadata probe failed: {error}"),
        ),
        CanvasPlatformManagementError::LtiMetadataEndpointMismatch => (
            StatusCode::CONFLICT,
            "Canvas metadata probe returned endpoints outside the persisted trust profile"
                .to_owned(),
        ),
        CanvasPlatformManagementError::SandboxProbeBaseUrlRequired => (
            StatusCode::BAD_REQUEST,
            "Canvas platform requires canvas_base_url before probing".to_owned(),
        ),
        CanvasPlatformManagementError::SandboxProbeFailed(error) => (
            StatusCode::BAD_REQUEST,
            format!("Canvas sandbox probe failed: {error}"),
        ),
        CanvasPlatformManagementError::JwksRefreshBaseUrlRequired => (
            StatusCode::BAD_REQUEST,
            "Canvas platform requires canvas_base_url before refreshing JWKS".to_owned(),
        ),
        CanvasPlatformManagementError::JwksRefreshFailed(error) => (
            StatusCode::BAD_REQUEST,
            format!("Canvas JWKS refresh failed: {error}"),
        ),
        CanvasPlatformManagementError::ConfigurationChanged => (
            StatusCode::CONFLICT,
            "Canvas platform configuration changed; retry the request".to_owned(),
        ),
        CanvasPlatformManagementError::ArchivalConfigurationChanged => (
            StatusCode::CONFLICT,
            "Canvas platform configuration changed; retry platform archival".to_owned(),
        ),
        CanvasPlatformManagementError::OAuthConnectionChanged => (
            StatusCode::CONFLICT,
            "Canvas OAuth connection changed; retry platform archival".to_owned(),
        ),
        CanvasPlatformManagementError::Conflict => (
            StatusCode::CONFLICT,
            "Canvas platform conflicts with an existing resource".to_owned(),
        ),
        CanvasPlatformManagementError::RepositoryUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Canvas platform repository is unavailable".to_owned(),
        ),
        CanvasPlatformManagementError::BindingNotFound => (
            StatusCode::NOT_FOUND,
            "Canvas program binding not found".to_owned(),
        ),
        CanvasPlatformManagementError::ReadinessUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Canvas readiness dependencies are unavailable".to_owned(),
        ),
        CanvasPlatformManagementError::ApplicationTemplateNotFound => (
            StatusCode::NOT_FOUND,
            "Application template not found".to_owned(),
        ),
        CanvasPlatformManagementError::CanvasCredentialsSecretRequired => (
            StatusCode::BAD_REQUEST,
            "Canvas Credentials configuration requires an organization-owned API token secret"
                .to_owned(),
        ),
        CanvasPlatformManagementError::CanvasCredentialsSecretNotFound => (
            StatusCode::NOT_FOUND,
            "Canvas Credentials API token secret was not found".to_owned(),
        ),
        CanvasPlatformManagementError::CanvasCredentialsUrlUntrusted => (
            StatusCode::BAD_REQUEST,
            "Canvas Credentials API base URL must be a trusted HTTPS URL".to_owned(),
        ),
        CanvasPlatformManagementError::CanvasCredentialsOriginNotAllowed => (
            StatusCode::BAD_REQUEST,
            "Canvas Credentials API origin is not operator allowlisted".to_owned(),
        ),
        CanvasPlatformManagementError::BindingConflict => (
            StatusCode::CONFLICT,
            "A Canvas program binding already exists for this template and scope".to_owned(),
        ),
        CanvasPlatformManagementError::PilotDisabled => (
            StatusCode::NOT_FOUND,
            "Portable Canvas integration is not enabled for this organization".to_owned(),
        ),
        CanvasPlatformManagementError::IntegrationSecretNotFound => (
            StatusCode::NOT_FOUND,
            "Integration secret not found".to_owned(),
        ),
        CanvasPlatformManagementError::ActivationBlocked(_) => {
            unreachable!("activation failures are projected before scalar service errors")
        }
        CanvasPlatformManagementError::BindingDomain(error) => match error {
            CanvasBindingDomainError::InvalidRequest(error) => {
                (StatusCode::UNPROCESSABLE_ENTITY, error.to_string())
            }
            CanvasBindingDomainError::CredentialTemplateRequired => (
                StatusCode::BAD_REQUEST,
                "Program binding requires a credential template ID".to_owned(),
            ),
            CanvasBindingDomainError::DuplicateRequirementId
            | CanvasBindingDomainError::InvalidEvidence(_) => {
                (StatusCode::BAD_REQUEST, error.to_string())
            }
            CanvasBindingDomainError::VersionExhausted => (StatusCode::CONFLICT, error.to_string()),
            _ => (StatusCode::CONFLICT, error.to_string()),
        },
    };
    (status, Json(json!({"detail": detail}))).into_response()
}

fn header<'headers>(headers: &'headers HeaderMap, name: &str) -> Option<&'headers str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn optional_timestamp(value: Option<DateTime<Utc>>) -> Option<String> {
    value.map(timestamp)
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, false)
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn response_projects_only_the_legacy_public_connection_keys() {
        let now = Utc.with_ymd_and_hms(2026, 8, 30, 22, 0, 0).unwrap();
        let mut connection_config = Map::new();
        connection_config.insert("enabled_intent".to_owned(), json!(true));
        connection_config.insert("oauth_status".to_owned(), json!("connected"));
        connection_config.insert("access_token_secret_ref".to_owned(), json!("secret"));
        connection_config.insert("lti_config_token_hash".to_owned(), json!("digest"));
        let response = CanvasPlatformResponse::from(CanvasPlatformRecord {
            id: "platform-1".to_owned(),
            organization_id: "org-1".to_owned(),
            canvas_account_id: "unverified:platform-1".to_owned(),
            display_name: None,
            canvas_base_url: Some("https://canvas.example.edu".to_owned()),
            lti_client_id: None,
            lti_deployment_id: None,
            lti_trust_profile: "hosted_global".to_owned(),
            lti_issuer: None,
            lti_jwks_url: None,
            lti_jwks_json: Some(json!({"private": "not-public"})),
            lti_jwks_fetched_at: None,
            lti_jwks_expires_at: None,
            lti_openid_configuration: Some(json!({"private": "not-public"})),
            registration_status: "draft".to_owned(),
            connection_config,
            capability_snapshot: Map::new(),
            last_validated_at: None,
            last_connection_error: None,
            config_version: 1,
            archived_at: None,
            enabled: false,
            created_at: now,
            updated_at: now,
        });
        assert_eq!(response.connection_config.len(), 2);
        assert_eq!(response.connection_config["enabled_intent"], true);
        assert!(!response
            .connection_config
            .contains_key("access_token_secret_ref"));
        assert!(!response
            .connection_config
            .contains_key("lti_config_token_hash"));
        assert_eq!(response.created_at, "2026-08-30T22:00:00+00:00");
    }

    #[test]
    fn request_validation_is_strict_and_fastapi_shaped() {
        let mut input = json!({
            "canvas_base_url": "",
            "enabled": "maybe",
            "organization_id": "attacker"
        });
        let error = validate_platform_request_value(&mut input).unwrap_err();
        let CanvasManagementHttpError::Validation(errors) = error else {
            panic!("expected validation errors")
        };
        assert_eq!(errors.len(), 3);
        assert_eq!(errors[0]["type"], "string_too_short");
        assert_eq!(errors[1]["type"], "bool_parsing");
        assert_eq!(errors[2]["type"], "extra_forbidden");
    }

    #[test]
    fn request_validation_preserves_pydantic_boolean_coercion() {
        for (input, expected) in [
            (json!("yes"), true),
            (json!("OFF"), false),
            (json!(1), true),
            (json!(0.0), false),
        ] {
            let mut request = json!({
                "canvas_base_url": "https://canvas.example.edu",
                "enabled": input,
            });
            validate_platform_request_value(&mut request).unwrap();
            assert_eq!(request["enabled"], expected);
        }
    }

    #[test]
    fn binding_validation_preserves_nested_pydantic_boolean_coercion() {
        let mut request = json!({
            "application_template_id": "application-template-1",
            "auto_approve_on_evidence": "yes",
            "evidence_requirements": [{
                "source": "canvas_rest",
                "fact_type": "canvas.course_completion",
                "scope": {"course_id": "course-1"},
                "pass_rule": {"completed": true},
                "required": "off"
            }],
            "feature_flags": {
                "enable_canvas_evidence": 1,
                "enable_background_awards": "false"
            }
        });
        validate_program_binding_request_value(&mut request).unwrap();
        assert_eq!(request["auto_approve_on_evidence"], true);
        assert_eq!(request["evidence_requirements"][0]["required"], false);
        assert_eq!(request["feature_flags"]["enable_canvas_evidence"], true);
        assert_eq!(request["feature_flags"]["enable_background_awards"], false);
        serde_json::from_value::<CanvasProgramBindingRequest>(request).unwrap();
    }

    #[test]
    fn organization_query_uses_the_last_scalar_value() {
        assert_eq!(
            organization_id_from_query(Some("organization_id=forged&x=1&organization_id=org-1")),
            Some("org-1".to_owned())
        );
        assert_eq!(organization_id_from_query(Some("x=1")), None);
    }
}
