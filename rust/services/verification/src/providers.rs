use std::{path::PathBuf, sync::Arc, time::Duration};

use async_trait::async_trait;
use http::uri::PathAndQuery;
use marty_flow::{
    credential_template_proto::credential_template_service_client::CredentialTemplateServiceClient,
    organization_proto::organization_service_client::OrganizationServiceClient,
    presentation_policy_proto::{
        presentation_policy_service_client::PresentationPolicyServiceClient,
        EvaluatePresentationRequest,
    },
    CredentialTemplateProvider, FlowProviderError, FlowProviderRegistry,
    GrpcCredentialTemplateProvider, GrpcPresentationPolicyProvider, GrpcTenantMembershipProvider,
    PresentationEvaluationRequest, PresentationPolicyProvider,
};
use mmf_platform::{
    GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial, GrpcTransportSecurity, GrpcTrustMode,
};
use mmf_security::TenantMembershipProvider;
use prost::Message;
use serde_json::Value;
use tonic::{metadata::AsciiMetadataValue, transport::Channel, Request};

use crate::{EvaluationResult, VerificationError};

const SERVICE_TOKEN_HEADER: &str = "x-service-token";
const MAX_PROVIDER_JSON_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct WorkloadClientTlsFiles {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub ca_certificate: PathBuf,
}

#[derive(Clone, Debug)]
pub struct GrpcProviderConfig {
    pub organization_target: String,
    pub credential_template_target: String,
    pub presentation_policy_target: String,
    pub inspection_target: Option<String>,
    pub inspection_method: String,
    pub service_token: Option<String>,
    pub workload_tls: Option<WorkloadClientTlsFiles>,
    pub timeout: Duration,
}

#[async_trait]
pub trait EvaluationProvider: Send + Sync {
    async fn evaluate(
        &self,
        request: &PresentationEvaluationRequest,
    ) -> Result<EvaluationResult, VerificationError>;
}

#[async_trait]
pub trait InspectionProvider: Send + Sync {
    async fn inspect(&self, item: &str) -> Result<Option<String>, VerificationError>;
}

#[derive(Clone, Debug, Default)]
pub struct NoInspection;

#[async_trait]
impl InspectionProvider for NoInspection {
    async fn inspect(&self, _item: &str) -> Result<Option<String>, VerificationError> {
        Ok(None)
    }
}

#[derive(Clone)]
pub struct VerificationProviders {
    pub flow: FlowProviderRegistry,
    pub membership: Arc<dyn TenantMembershipProvider>,
    pub evaluation: Arc<dyn EvaluationProvider>,
    pub inspection: Arc<dyn InspectionProvider>,
}

impl VerificationProviders {
    pub fn connect_lazy(config: &GrpcProviderConfig) -> Result<Self, VerificationError> {
        if config.timeout.is_zero() {
            return Err(unavailable("gRPC dependency timeout must be positive"));
        }
        let organization = factory(&config.organization_target, config.workload_tls.as_ref())?
            .connect_lazy()
            .map_err(|_| unavailable("organization service channel is invalid"))?;
        let credential_template = factory(
            &config.credential_template_target,
            config.workload_tls.as_ref(),
        )?
        .connect_lazy()
        .map_err(|_| unavailable("credential template service channel is invalid"))?;
        let presentation_policy = factory(
            &config.presentation_policy_target,
            config.workload_tls.as_ref(),
        )?
        .connect_lazy()
        .map_err(|_| unavailable("presentation policy service channel is invalid"))?;
        let membership = Arc::new(
            GrpcTenantMembershipProvider::new(
                OrganizationServiceClient::new(organization),
                config.service_token.as_deref(),
            )
            .map_err(provider_error)?,
        );
        let templates = Arc::new(
            GrpcCredentialTemplateProvider::new(
                CredentialTemplateServiceClient::new(credential_template),
                config.service_token.as_deref(),
            )
            .map_err(provider_error)?,
        );
        let policy_client = PresentationPolicyServiceClient::new(presentation_policy);
        let policies = Arc::new(
            GrpcPresentationPolicyProvider::new(
                policy_client.clone(),
                config.service_token.as_deref(),
            )
            .map_err(provider_error)?,
        );
        let evaluation = Arc::new(GrpcEvaluationProvider::new(
            policy_client,
            config.service_token.as_deref(),
            config.timeout,
        )?);
        let inspection: Arc<dyn InspectionProvider> = match &config.inspection_target {
            Some(target) if !target.trim().is_empty() => Arc::new(GrpcInspectionProvider::new(
                factory(target, config.workload_tls.as_ref())?
                    .connect_lazy()
                    .map_err(|_| unavailable("inspection service channel is invalid"))?,
                &config.inspection_method,
                config.service_token.as_deref(),
                config.timeout,
            )?),
            _ => Arc::new(NoInspection),
        };
        Ok(Self {
            flow: FlowProviderRegistry {
                tenant_membership: Some(membership.clone()),
                credential_template: Some(templates),
                presentation_policy: Some(policies),
                ..FlowProviderRegistry::default()
            },
            membership,
            evaluation,
            inspection,
        })
    }

    #[must_use]
    pub fn from_parts(
        membership: Arc<dyn TenantMembershipProvider>,
        credential_template: Arc<dyn CredentialTemplateProvider>,
        presentation_policy: Arc<dyn PresentationPolicyProvider>,
        evaluation: Arc<dyn EvaluationProvider>,
        inspection: Arc<dyn InspectionProvider>,
    ) -> Self {
        Self {
            flow: FlowProviderRegistry {
                tenant_membership: Some(membership.clone()),
                credential_template: Some(credential_template),
                presentation_policy: Some(presentation_policy),
                ..FlowProviderRegistry::default()
            },
            membership,
            evaluation,
            inspection,
        }
    }
}

#[derive(Clone)]
struct GrpcEvaluationProvider {
    client: PresentationPolicyServiceClient<Channel>,
    service_token: Option<AsciiMetadataValue>,
    timeout: Duration,
}

impl GrpcEvaluationProvider {
    fn new(
        client: PresentationPolicyServiceClient<Channel>,
        token: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, VerificationError> {
        Ok(Self {
            client,
            service_token: token
                .map(str::parse)
                .transpose()
                .map_err(|_| unavailable("service token is invalid gRPC metadata"))?,
            timeout,
        })
    }

    fn request<T>(&self, body: T) -> Request<T> {
        let mut request = Request::new(body);
        request.set_timeout(self.timeout);
        if let Some(token) = &self.service_token {
            request
                .metadata_mut()
                .insert(SERVICE_TOKEN_HEADER, token.clone());
        }
        request
    }
}

#[async_trait]
impl EvaluationProvider for GrpcEvaluationProvider {
    async fn evaluate(
        &self,
        request: &PresentationEvaluationRequest,
    ) -> Result<EvaluationResult, VerificationError> {
        let context_json = serde_json::to_string(&request.context)
            .map_err(|_| unavailable("evaluation context is not serializable"))?;
        let mut client = self.client.clone();
        let response = client
            .evaluate_presentation(
                self.request(EvaluatePresentationRequest {
                    policy_id: request.policy_id.clone(),
                    vp_token: request.presentation.clone(),
                    nonce: request.nonce.clone(),
                    audience: request.audience.clone(),
                    trust_profile_id: request
                        .context
                        .get("trust_profile_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .into(),
                    context_json,
                }),
            )
            .await
            .map_err(|_| unavailable("Presentation policy service unavailable"))?
            .into_inner();
        if response.policy_id != request.policy_id || response.nonce != request.nonce {
            return Err(unavailable(
                "presentation policy response identity mismatch",
            ));
        }
        Ok(EvaluationResult {
            result: response.result,
            decision: response.decision,
            decision_reason: response.decision_reason,
            verified_claims: bounded_json(&response.verified_claims_json)?,
            credential_results: bounded_json(&response.credential_results_json)?,
            holder_binding_evidence: None,
            total_requirements: response.total_requirements,
            satisfied_requirements: response.satisfied_requirements,
            evaluation_timestamp: response.evaluation_timestamp,
            nonce: response.nonce,
        })
    }
}

#[derive(Clone, PartialEq, Message)]
struct InspectRequest {
    #[prost(string, tag = "1")]
    item: String,
}

#[derive(Clone, PartialEq, Message)]
struct InspectResponse {
    #[prost(string, tag = "1")]
    result: String,
}

#[derive(Clone)]
struct GrpcInspectionProvider {
    channel: Channel,
    method: PathAndQuery,
    service_token: Option<AsciiMetadataValue>,
    timeout: Duration,
}

impl GrpcInspectionProvider {
    fn new(
        channel: Channel,
        method: &str,
        token: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, VerificationError> {
        let method = method
            .parse()
            .map_err(|_| unavailable("inspection gRPC method is invalid"))?;
        Ok(Self {
            channel,
            method,
            service_token: token
                .map(str::parse)
                .transpose()
                .map_err(|_| unavailable("service token is invalid gRPC metadata"))?,
            timeout,
        })
    }
}

#[async_trait]
impl InspectionProvider for GrpcInspectionProvider {
    async fn inspect(&self, item: &str) -> Result<Option<String>, VerificationError> {
        let mut client = tonic::client::Grpc::new(self.channel.clone());
        client
            .ready()
            .await
            .map_err(|_| unavailable("Inspection system unavailable"))?;
        let mut request = Request::new(InspectRequest { item: item.into() });
        request.set_timeout(self.timeout);
        if let Some(token) = &self.service_token {
            request
                .metadata_mut()
                .insert(SERVICE_TOKEN_HEADER, token.clone());
        }
        let response: tonic::Response<InspectResponse> = client
            .unary(
                request,
                self.method.clone(),
                tonic_prost::ProstCodec::default(),
            )
            .await
            .map_err(|_| unavailable("Inspection system unavailable"))?;
        Ok((!response.get_ref().result.is_empty()).then(|| response.into_inner().result))
    }
}

fn factory(
    target: &str,
    workload_tls: Option<&WorkloadClientTlsFiles>,
) -> Result<GrpcChannelFactory, VerificationError> {
    let target = normalize_target(target);
    let (target, security, trust, material) = match workload_tls {
        Some(files) => (
            target.replacen("http://", "https://", 1),
            GrpcTransportSecurity::MutualTls,
            GrpcTrustMode::CustomCa,
            GrpcTlsMaterial::from_pem_files(
                Some(&files.ca_certificate),
                Some(&files.certificate),
                Some(&files.private_key),
            )
            .map_err(|_| unavailable("workload TLS material is invalid"))?,
        ),
        None if target.starts_with("https://") => (
            target,
            GrpcTransportSecurity::ServerTls,
            GrpcTrustMode::NativeRoots,
            GrpcTlsMaterial::default(),
        ),
        None => (
            target,
            GrpcTransportSecurity::Plaintext,
            GrpcTrustMode::NativeRoots,
            GrpcTlsMaterial::default(),
        ),
    };
    GrpcChannelFactory::new(
        GrpcChannelConfig {
            target,
            security,
            trust,
            ..GrpcChannelConfig::default()
        },
        material,
    )
    .map_err(|_| unavailable("gRPC channel configuration is invalid"))
}

fn normalize_target(target: &str) -> String {
    if target.contains("://") {
        target.into()
    } else {
        format!("http://{target}")
    }
}

fn bounded_json<T: serde::de::DeserializeOwned>(value: &str) -> Result<T, VerificationError> {
    if value.len() > MAX_PROVIDER_JSON_BYTES {
        return Err(unavailable("presentation policy response is oversized"));
    }
    serde_json::from_str(value).map_err(|_| unavailable("presentation policy response is invalid"))
}

fn provider_error(error: FlowProviderError) -> VerificationError {
    unavailable(&error.to_string())
}

fn unavailable(message: &str) -> VerificationError {
    VerificationError::Dependency(message.into())
}
