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
    read_public_certificates, GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial,
    GrpcTransportSecurity, GrpcTrustMode, KeylessGrpcChannelFactory, KeylessGrpcTransportOptions,
    KeylessTlsIdentity, OpenBaoTlsIdentityFiles,
};
use mmf_security::TenantMembershipProvider;
use prost::Message;
use serde_json::Value;
use tonic::{metadata::AsciiMetadataValue, transport::Channel, Request};
use url::Url;

use crate::{EvaluationResult, VerificationError};

const SERVICE_TOKEN_HEADER: &str = "x-service-token";
const USER_ID_HEADER: &str = "x-user-id";
const MAX_PROVIDER_JSON_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct WorkloadClientTlsFiles {
    pub certificate: PathBuf,
    pub ca_certificate: PathBuf,
    pub kms_endpoint: String,
    pub kms_ca_certificate: PathBuf,
    pub kms_token_file: PathBuf,
    pub kms_key_name: String,
    pub kms_key_version: u32,
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
    pub async fn connect_lazy(config: &GrpcProviderConfig) -> Result<Self, VerificationError> {
        if config.timeout.is_zero() {
            return Err(unavailable("gRPC dependency timeout must be positive"));
        }
        let keyless = keyless_setup(config).await?;
        let organization = channel(
            &config.organization_target,
            keyless.as_ref(),
            config.timeout,
        )?;
        let credential_template = channel(
            &config.credential_template_target,
            keyless.as_ref(),
            config.timeout,
        )?;
        let presentation_policy = channel(
            &config.presentation_policy_target,
            keyless.as_ref(),
            config.timeout,
        )?;
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
                channel(target, keyless.as_ref(), config.timeout)?,
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

    fn request<T>(&self, body: T, principal_id: &str) -> Result<Request<T>, VerificationError> {
        let principal_id = principal_id.trim();
        if principal_id.is_empty() {
            return Err(unavailable("evaluation principal is missing"));
        }
        let principal = principal_id
            .parse()
            .map_err(|_| unavailable("evaluation principal is invalid gRPC metadata"))?;
        let mut request = Request::new(body);
        request.set_timeout(self.timeout);
        if let Some(token) = &self.service_token {
            request
                .metadata_mut()
                .insert(SERVICE_TOKEN_HEADER, token.clone());
        }
        request.metadata_mut().insert(USER_ID_HEADER, principal);
        Ok(request)
    }
}

#[async_trait]
impl EvaluationProvider for GrpcEvaluationProvider {
    async fn evaluate(
        &self,
        request: &PresentationEvaluationRequest,
    ) -> Result<EvaluationResult, VerificationError> {
        let mut client = self.client.clone();
        let response = client
            .evaluate_presentation(
                self.request(policy_evaluation_message(request)?, &request.principal_id)?,
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

fn policy_evaluation_message(
    request: &PresentationEvaluationRequest,
) -> Result<EvaluatePresentationRequest, VerificationError> {
    let context_json = serde_json::to_string(&request.context)
        .map_err(|_| unavailable("evaluation context is not serializable"))?;
    Ok(EvaluatePresentationRequest {
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
        // This legacy service has no emitted verifier query or submission
        // authority to forward. Only Flow may attach the new metadata.
        oid4vp_transport: None,
    })
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

fn factory(target: &str) -> Result<GrpcChannelFactory, VerificationError> {
    let target = normalize_target(target);
    let (target, security, trust, material) = match target.starts_with("https://") {
        true => (
            target,
            GrpcTransportSecurity::ServerTls,
            GrpcTrustMode::NativeRoots,
            GrpcTlsMaterial::default(),
        ),
        false => (
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

async fn keyless_setup(
    config: &GrpcProviderConfig,
) -> Result<Option<(KeylessTlsIdentity, Vec<Vec<u8>>)>, VerificationError> {
    let Some(files) = &config.workload_tls else {
        return Ok(None);
    };
    let ca = read_public_certificates(&files.ca_certificate)
        .map_err(|_| unavailable("workload server CA is invalid"))?;
    let identity = OpenBaoTlsIdentityFiles {
        certificate_chain_file: files.certificate.clone(),
        kms_ca_cert_file: files.kms_ca_certificate.clone(),
        kms_endpoint: files.kms_endpoint.clone(),
        kms_token_file: files.kms_token_file.clone(),
        kms_key_name: files.kms_key_name.clone(),
        kms_key_version: files.kms_key_version,
        request_timeout: config.timeout.min(Duration::from_secs(30)),
        max_concurrent_signs: 64,
    }
    .connect()
    .await
    .map_err(|_| unavailable("workload remote TLS identity is unavailable"))?;
    Ok(Some((identity, ca)))
}

fn channel(
    target: &str,
    keyless: Option<&(KeylessTlsIdentity, Vec<Vec<u8>>)>,
    timeout: Duration,
) -> Result<Channel, VerificationError> {
    let Some((identity, ca)) = keyless else {
        return factory(target)?
            .connect_lazy()
            .map_err(|_| unavailable("gRPC channel is invalid"));
    };
    if !target.starts_with("https://") {
        return Err(unavailable("keyless gRPC target must use explicit HTTPS"));
    }
    let target = target.to_owned();
    let server_name = Url::parse(&target)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .ok_or_else(|| unavailable("workload target is invalid"))?;
    KeylessGrpcChannelFactory::with_options(
        &target,
        &server_name,
        identity,
        ca.clone(),
        KeylessGrpcTransportOptions {
            connect_timeout: timeout,
            request_timeout: timeout,
            ..KeylessGrpcTransportOptions::default()
        },
    )
    .map(|factory| factory.connect_lazy())
    .map_err(|_| unavailable("keyless gRPC channel is invalid"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_verification_provider_does_not_claim_flow_owned_oid4vp_metadata() {
        let request = PresentationEvaluationRequest {
            policy_id: "policy-1".into(),
            organization_id: "org-1".into(),
            principal_id: "user-1".into(),
            presentation: "header.payload.signature".into(),
            nonce: "nonce-1".into(),
            audience: "verifier-1".into(),
            oid4vp_transport: None,
            context: std::collections::BTreeMap::from([(
                "trust_profile_id".into(),
                serde_json::json!("trust-1"),
            )]),
        };
        let wire = policy_evaluation_message(&request).unwrap();
        assert!(wire.oid4vp_transport.is_none());
        assert_eq!(wire.policy_id, request.policy_id);
        assert_eq!(wire.vp_token, request.presentation);
        assert_eq!(wire.nonce, request.nonce);
        assert_eq!(wire.audience, request.audience);
        assert_eq!(wire.trust_profile_id, "trust-1");
        assert_eq!(
            serde_json::from_str::<Value>(&wire.context_json).unwrap(),
            serde_json::json!({"trust_profile_id": "trust-1"})
        );
    }

    #[tokio::test]
    async fn evaluation_requests_carry_service_and_initiating_principal_identity() {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:9").connect_lazy();
        let provider = GrpcEvaluationProvider::new(
            PresentationPolicyServiceClient::new(channel),
            Some("0123456789abcdef0123456789abcdef"),
            Duration::from_secs(2),
        )
        .unwrap();
        let request = provider.request((), " user-1 ").unwrap();
        assert_eq!(
            request.metadata().get(SERVICE_TOKEN_HEADER).unwrap(),
            "0123456789abcdef0123456789abcdef"
        );
        assert_eq!(request.metadata().get(USER_ID_HEADER).unwrap(), "user-1");
        assert!(provider.request((), "").is_err());
        assert!(provider.request((), "invalid\nprincipal").is_err());
    }
}
