use std::collections::BTreeSet;

use async_trait::async_trait;
use mmf_platform::{
    GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial, GrpcTransportSecurity, GrpcTrustMode,
    PlatformError,
};
use mmf_security::{SecurityError, TenantMembership, TenantMembershipProvider};
use serde::de::DeserializeOwned;
use tonic::{metadata::AsciiMetadataValue, transport::Channel, Code, Request, Status};

use crate::{
    credential_template_proto::{
        credential_template_service_client::CredentialTemplateServiceClient, GetTemplateRequest,
    },
    issuance_proto::{
        issuance_service_client::IssuanceServiceClient, InitiateIssuanceRequest as ProtoIssuance,
    },
    organization_proto::{
        organization_service_client::OrganizationServiceClient, GetMemberRequest,
    },
    presentation_policy_proto::{
        presentation_policy_service_client::PresentationPolicyServiceClient,
        EvaluatePresentationRequest, GetPolicyRequest,
    },
    CredentialTemplateProvider, CredentialTemplateReference, FlowProviderError, FlowServiceConfig,
    IssuanceInitiationRequest, IssuanceInitiationResult, IssuanceProvider,
    PresentationEvaluationRequest, PresentationEvaluationResult, PresentationPolicyProvider,
    PresentationPolicyReference,
};

const MAXIMUM_PROVIDER_JSON_BYTES: usize = 1024 * 1024;
const SERVICE_TOKEN_HEADER: &str = "x-service-token";

#[derive(Clone)]
pub struct FlowGrpcChannelFactories {
    pub organization: GrpcChannelFactory,
    pub credential_template: GrpcChannelFactory,
    pub presentation_policy: GrpcChannelFactory,
    pub issuance: GrpcChannelFactory,
}

impl FlowGrpcChannelFactories {
    pub fn from_config(config: &FlowServiceConfig) -> Result<Self, PlatformError> {
        Ok(Self {
            organization: ordinary_factory(&config.organization_grpc_target)?,
            credential_template: ordinary_factory(&config.credential_template_grpc_target)?,
            presentation_policy: workload_factory(
                &config.presentation_policy_grpc_target,
                config.workload_client_tls.as_ref(),
            )?,
            issuance: ordinary_factory(&config.issuance_grpc_target)?,
        })
    }

    pub fn connect_lazy(&self) -> Result<FlowGrpcClients, PlatformError> {
        Ok(FlowGrpcClients::new(
            self.organization.connect_lazy()?,
            self.credential_template.connect_lazy()?,
            self.presentation_policy.connect_lazy()?,
            self.issuance.connect_lazy()?,
        ))
    }

    pub async fn connect(&self) -> Result<FlowGrpcClients, PlatformError> {
        let (organization, credential_template, presentation_policy, issuance) = tokio::try_join!(
            self.organization.connect(),
            self.credential_template.connect(),
            self.presentation_policy.connect(),
            self.issuance.connect(),
        )?;
        Ok(FlowGrpcClients::new(
            organization,
            credential_template,
            presentation_policy,
            issuance,
        ))
    }
}

fn ordinary_factory(target: &str) -> Result<GrpcChannelFactory, PlatformError> {
    let security = if target.starts_with("https://") {
        GrpcTransportSecurity::ServerTls
    } else {
        GrpcTransportSecurity::Plaintext
    };
    GrpcChannelFactory::new(
        GrpcChannelConfig {
            target: target.into(),
            security,
            ..GrpcChannelConfig::default()
        },
        GrpcTlsMaterial::default(),
    )
}

fn workload_factory(
    target: &str,
    files: Option<&crate::WorkloadClientTlsFiles>,
) -> Result<GrpcChannelFactory, PlatformError> {
    let Some(files) = files else {
        return ordinary_factory(target);
    };
    let target = if let Some(authority) = target.strip_prefix("http://") {
        format!("https://{authority}")
    } else {
        target.into()
    };
    let material = GrpcTlsMaterial::from_pem_files(
        Some(&files.ca_certificate),
        Some(&files.certificate),
        Some(&files.private_key),
    )?;
    GrpcChannelFactory::new(
        GrpcChannelConfig {
            target,
            security: GrpcTransportSecurity::MutualTls,
            trust: GrpcTrustMode::CustomCa,
            ..GrpcChannelConfig::default()
        },
        material,
    )
}

#[derive(Clone)]
pub struct FlowGrpcClients {
    pub organization: OrganizationServiceClient<Channel>,
    pub credential_template: CredentialTemplateServiceClient<Channel>,
    pub presentation_policy: PresentationPolicyServiceClient<Channel>,
    pub issuance: IssuanceServiceClient<Channel>,
}

impl FlowGrpcClients {
    #[must_use]
    pub fn new(
        organization: Channel,
        credential_template: Channel,
        presentation_policy: Channel,
        issuance: Channel,
    ) -> Self {
        Self {
            organization: OrganizationServiceClient::new(organization),
            credential_template: CredentialTemplateServiceClient::new(credential_template),
            presentation_policy: PresentationPolicyServiceClient::new(presentation_policy),
            issuance: IssuanceServiceClient::new(issuance),
        }
    }

    pub fn providers(
        self,
        service_token: Option<&str>,
    ) -> Result<FlowGrpcProviders, FlowProviderError> {
        Ok(FlowGrpcProviders {
            tenant_membership: GrpcTenantMembershipProvider::new(self.organization, service_token)?,
            credential_template: GrpcCredentialTemplateProvider::new(
                self.credential_template,
                service_token,
            )?,
            presentation_policy: GrpcPresentationPolicyProvider::new(
                self.presentation_policy,
                service_token,
            )?,
            issuance: GrpcIssuanceProvider::new(self.issuance, service_token)?,
        })
    }
}

pub struct FlowGrpcProviders {
    pub tenant_membership: GrpcTenantMembershipProvider,
    pub credential_template: GrpcCredentialTemplateProvider,
    pub presentation_policy: GrpcPresentationPolicyProvider,
    pub issuance: GrpcIssuanceProvider,
}

#[derive(Clone, Default)]
struct GrpcAuthentication {
    service_token: Option<AsciiMetadataValue>,
}

impl GrpcAuthentication {
    fn new(service_token: Option<&str>) -> Result<Self, FlowProviderError> {
        let service_token = service_token
            .filter(|value| !value.trim().is_empty())
            .map(str::parse)
            .transpose()
            .map_err(|_| FlowProviderError::InvalidResponse {
                provider: "grpc",
                message: "service token is not valid ASCII metadata".into(),
            })?;
        Ok(Self { service_token })
    }

    fn request<T>(&self, message: T) -> Request<T> {
        let mut request = Request::new(message);
        if let Some(token) = &self.service_token {
            request
                .metadata_mut()
                .insert(SERVICE_TOKEN_HEADER, token.clone());
        }
        request
    }
}

#[derive(Clone)]
pub struct GrpcTenantMembershipProvider {
    client: OrganizationServiceClient<Channel>,
    auth: GrpcAuthentication,
}

impl GrpcTenantMembershipProvider {
    pub fn new(
        client: OrganizationServiceClient<Channel>,
        token: Option<&str>,
    ) -> Result<Self, FlowProviderError> {
        Ok(Self {
            client,
            auth: GrpcAuthentication::new(token)?,
        })
    }
}

#[async_trait]
impl TenantMembershipProvider for GrpcTenantMembershipProvider {
    async fn membership(
        &self,
        principal_id: &str,
        tenant_id: &str,
    ) -> Result<Option<TenantMembership>, SecurityError> {
        let mut client = self.client.clone();
        let response = match client
            .get_member(self.auth.request(GetMemberRequest {
                organization_id: tenant_id.into(),
                user_id: principal_id.into(),
            }))
            .await
        {
            Ok(response) => response.into_inner(),
            Err(status) if status.code() == Code::NotFound => return Ok(None),
            Err(_) => {
                return Err(SecurityError::ProviderUnavailable(
                    "organization membership provider".into(),
                ))
            }
        };
        if response.user_id.is_empty() || response.organization_id.is_empty() {
            return Err(SecurityError::InvalidAuthenticationResult);
        }
        Ok(Some(TenantMembership {
            principal_id: response.user_id,
            tenant_id: response.organization_id,
            status: response.status,
            role_names: response.roles.into_iter().map(|role| role.name).collect(),
            permissions: response.permissions.into_iter().collect::<BTreeSet<_>>(),
            is_owner: response.is_owner,
        }))
    }
}

#[derive(Clone)]
pub struct GrpcCredentialTemplateProvider {
    client: CredentialTemplateServiceClient<Channel>,
    auth: GrpcAuthentication,
}

impl GrpcCredentialTemplateProvider {
    pub fn new(
        client: CredentialTemplateServiceClient<Channel>,
        token: Option<&str>,
    ) -> Result<Self, FlowProviderError> {
        Ok(Self {
            client,
            auth: GrpcAuthentication::new(token)?,
        })
    }
}

#[async_trait]
impl CredentialTemplateProvider for GrpcCredentialTemplateProvider {
    async fn get_template(
        &self,
        template_id: &str,
    ) -> Result<CredentialTemplateReference, FlowProviderError> {
        let mut client = self.client.clone();
        let response = client
            .get_template(self.auth.request(GetTemplateRequest {
                template_id: template_id.into(),
            }))
            .await
            .map_err(|status| provider_status("credential_template", template_id, status))?
            .into_inner();
        if response.id != template_id || response.organization_id.trim().is_empty() {
            return Err(invalid_response(
                "credential_template",
                "template identity mismatch",
            ));
        }
        Ok(CredentialTemplateReference {
            id: response.id,
            organization_id: response.organization_id,
            status: response.status,
            issuer_did: response.issuer_did,
            credential_format: response.credential_payload_format,
            issuer_algorithm: nonempty(response.issuer_algorithm),
        })
    }
}

#[derive(Clone)]
pub struct GrpcPresentationPolicyProvider {
    client: PresentationPolicyServiceClient<Channel>,
    auth: GrpcAuthentication,
}

impl GrpcPresentationPolicyProvider {
    pub fn new(
        client: PresentationPolicyServiceClient<Channel>,
        token: Option<&str>,
    ) -> Result<Self, FlowProviderError> {
        Ok(Self {
            client,
            auth: GrpcAuthentication::new(token)?,
        })
    }
}

#[async_trait]
impl PresentationPolicyProvider for GrpcPresentationPolicyProvider {
    async fn get_policy(
        &self,
        policy_id: &str,
    ) -> Result<PresentationPolicyReference, FlowProviderError> {
        let mut client = self.client.clone();
        let response = client
            .get_policy(self.auth.request(GetPolicyRequest {
                policy_id: policy_id.into(),
            }))
            .await
            .map_err(|status| provider_status("presentation_policy", policy_id, status))?
            .into_inner();
        if response.id != policy_id || response.organization_id.trim().is_empty() {
            return Err(invalid_response(
                "presentation_policy",
                "policy identity mismatch",
            ));
        }
        Ok(PresentationPolicyReference {
            id: response.id,
            organization_id: response.organization_id,
            status: response.status,
            credential_requirements: bounded_json(
                &response.credential_requirements_json,
                "presentation_policy",
            )?,
        })
    }

    async fn evaluate(
        &self,
        request: &PresentationEvaluationRequest,
    ) -> Result<PresentationEvaluationResult, FlowProviderError> {
        let mut client = self.client.clone();
        let response = client
            .evaluate_presentation(
                self.auth.request(EvaluatePresentationRequest {
                    policy_id: request.policy_id.clone(),
                    vp_token: request.presentation.clone(),
                    nonce: request.nonce.clone(),
                    audience: request.audience.clone(),
                    trust_profile_id: request
                        .context
                        .get("trust_profile_id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .into(),
                    context_json: serde_json::to_string(&request.context).map_err(|_| {
                        invalid_response(
                            "presentation_policy",
                            "evaluation context is not serializable",
                        )
                    })?,
                }),
            )
            .await
            .map_err(|status| provider_status("presentation_policy", &request.policy_id, status))?
            .into_inner();
        if response.policy_id != request.policy_id || response.nonce != request.nonce {
            return Err(invalid_response(
                "presentation_policy",
                "evaluation identity mismatch",
            ));
        }
        Ok(PresentationEvaluationResult {
            result: response.result,
            decision: response.decision,
            decision_reason: nonempty(response.decision_reason),
            verified_claims: bounded_json(&response.verified_claims_json, "presentation_policy")?,
            credential_results: bounded_json(
                &response.credential_results_json,
                "presentation_policy",
            )?,
            error_codes: Vec::new(),
            warnings: Vec::new(),
        })
    }
}

#[derive(Clone)]
pub struct GrpcIssuanceProvider {
    client: IssuanceServiceClient<Channel>,
    auth: GrpcAuthentication,
}

impl GrpcIssuanceProvider {
    pub fn new(
        client: IssuanceServiceClient<Channel>,
        token: Option<&str>,
    ) -> Result<Self, FlowProviderError> {
        Ok(Self {
            client,
            auth: GrpcAuthentication::new(token)?,
        })
    }
}

#[async_trait]
impl IssuanceProvider for GrpcIssuanceProvider {
    async fn initiate(
        &self,
        request: &IssuanceInitiationRequest,
    ) -> Result<IssuanceInitiationResult, FlowProviderError> {
        let mut client = self.client.clone();
        let response =
            client
                .initiate_issuance(self.auth.request(ProtoIssuance {
                    organization_id: request.organization_id.clone(),
                    credential_template_id: request.credential_template_id.clone(),
                    applicant_id: request.applicant_id.clone().unwrap_or_default(),
                    subject_did: request.subject_did.clone().unwrap_or_default(),
                    claims: Default::default(),
                    holder_did: request.holder_did.clone().unwrap_or_default(),
                    authorized_client_id: request.authorized_client_id.clone().unwrap_or_default(),
                    application_id: request.application_id.clone().unwrap_or_default(),
                    issuer_did: request.issuer_did.clone(),
                    delivery_mode: request.delivery_mode.clone().unwrap_or_default(),
                    idempotency_key: request.idempotency_key.clone().unwrap_or_default(),
                    claims_json:
                        serde_json::to_string(&request.claims).map_err(|_| {
                            invalid_response("issuance", "claims are not serializable")
                        })?,
                }))
                .await
                .map_err(|status| provider_status("issuance", &request.flow_instance_id, status))?
                .into_inner();
        if response.organization_id != request.organization_id
            || response.credential_template_id != request.credential_template_id
            || response.id.trim().is_empty()
        {
            return Err(invalid_response(
                "issuance",
                "issuance response identity mismatch",
            ));
        }
        let expires_at_ms = match nonempty(response.expires_at) {
            Some(value) => Some(
                u64::try_from(
                    chrono::DateTime::parse_from_rfc3339(&value)
                        .map_err(|_| invalid_response("issuance", "invalid expiry timestamp"))?
                        .timestamp_millis(),
                )
                .map_err(|_| invalid_response("issuance", "invalid expiry timestamp"))?,
            ),
            None => None,
        };
        Ok(IssuanceInitiationResult {
            transaction_id: response.id,
            credential_offer_uri: nonempty(response.credential_offer_uri),
            credential_offer_uris: response.credential_offer_uris.into_iter().collect(),
            credential_offer_labels: response.credential_offer_labels.into_iter().collect(),
            pre_authorized_code: nonempty(response.pre_auth_code),
            expires_at_ms,
            status: response.status,
        })
    }
}

fn bounded_json<T: DeserializeOwned>(
    value: &str,
    provider: &'static str,
) -> Result<T, FlowProviderError> {
    if value.len() > MAXIMUM_PROVIDER_JSON_BYTES {
        return Err(invalid_response(
            provider,
            "provider JSON exceeded its size limit",
        ));
    }
    serde_json::from_str(value)
        .map_err(|_| invalid_response(provider, "provider returned malformed JSON"))
}

fn provider_status(provider: &'static str, resource: &str, status: Status) -> FlowProviderError {
    match status.code() {
        Code::NotFound => FlowProviderError::NotFound {
            provider,
            resource: resource.into(),
        },
        Code::AlreadyExists | Code::Aborted => FlowProviderError::Conflict {
            provider,
            message: "provider reported a conflict".into(),
        },
        Code::InvalidArgument
        | Code::FailedPrecondition
        | Code::PermissionDenied
        | Code::Unauthenticated => FlowProviderError::Rejected {
            provider,
            message: "provider rejected the operation".into(),
        },
        _ => FlowProviderError::Unavailable { provider },
    }
}

fn invalid_response(provider: &'static str, message: &str) -> FlowProviderError {
    FlowProviderError::InvalidResponse {
        provider,
        message: message.into(),
    }
}

fn nonempty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}
