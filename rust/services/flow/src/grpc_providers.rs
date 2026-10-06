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
        ListWalletsRequest,
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
    sanitized_diagnostic_text, CredentialClaimReference, CredentialTemplateProvider,
    CredentialTemplateReference, FlowProviderError, FlowServiceConfig, IssuanceInitiationRequest,
    IssuanceInitiationResult, IssuanceProvider, PresentationEvaluationRequest,
    PresentationEvaluationResult, PresentationPolicyProvider, PresentationPolicyReference,
};

const MAXIMUM_PROVIDER_JSON_BYTES: usize = 1024 * 1024;
const SERVICE_TOKEN_HEADER: &str = "x-service-token";
const USER_ID_HEADER: &str = "x-user-id";

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

    pub(crate) fn presentation_policy_workload_transport(&self) -> bool {
        self.presentation_policy.config().security == GrpcTransportSecurity::MutualTls
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
        // Preserve the public direct-client API's previous forwarding behavior.
        self.providers_with_channel_security(service_token, true)
    }

    pub(crate) fn providers_with_channel_security(
        self,
        service_token: Option<&str>,
        presentation_policy_mtls: bool,
    ) -> Result<FlowGrpcProviders, FlowProviderError> {
        let mut presentation_policy =
            GrpcPresentationPolicyProvider::new(self.presentation_policy, service_token)?;
        presentation_policy.workload_mtls = presentation_policy_mtls;
        Ok(FlowGrpcProviders {
            tenant_membership: GrpcTenantMembershipProvider::new(self.organization, service_token)?,
            credential_template: GrpcCredentialTemplateProvider::new(
                self.credential_template,
                service_token,
            )?,
            presentation_policy,
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

    fn request_for_principal<T>(
        &self,
        message: T,
        principal_id: &str,
    ) -> Result<Request<T>, FlowProviderError> {
        let principal =
            principal_id
                .trim()
                .parse()
                .map_err(|_| FlowProviderError::InvalidResponse {
                    provider: "grpc",
                    message: "principal is not valid ASCII metadata".into(),
                })?;
        let mut request = self.request(message);
        request.metadata_mut().insert(USER_ID_HEADER, principal);
        Ok(request)
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
            credential_type: response.credential_type,
            vct: response.vct,
            doctype: response.doctype,
            supported_formats: response.supported_formats,
            claims: response
                .claims
                .into_iter()
                .map(|claim| CredentialClaimReference {
                    name: claim.name,
                    display_name: claim.display_name,
                    description: claim.description,
                    required: claim.required,
                    mdoc_namespace: claim.mdoc_namespace,
                    mdoc_element_identifier: claim.mdoc_element_identifier,
                })
                .collect(),
            issuer_did: response.issuer_did,
            credential_format: response.credential_payload_format,
            issuance_protocol: response.issuance_protocol,
            wallet_configurations: bounded_json(
                &response.wallet_configs_json,
                "credential_template",
            )?,
            issuer_algorithm: nonempty(response.issuer_algorithm),
        })
    }

    async fn wallet_formats(
        &self,
        organization_id: &str,
    ) -> Result<Vec<String>, FlowProviderError> {
        if organization_id.trim().is_empty() {
            return Err(invalid_response(
                "credential_template",
                "wallet registry organization is required",
            ));
        }
        let mut client = self.client.clone();
        let response = client
            .list_wallets(self.auth.request(ListWalletsRequest {
                active_only: true,
                organization_id: organization_id.into(),
            }))
            .await
            .map_err(|status| provider_status("credential_template", "wallets", status))?
            .into_inner();
        let formats = response
            .wallets
            .into_iter()
            .filter(|wallet| wallet.is_active)
            .flat_map(|wallet| wallet.supported_formats)
            .filter(|format| !format.trim().is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if formats.is_empty() {
            return Err(invalid_response(
                "credential_template",
                "wallet registry has no active formats",
            ));
        }
        Ok(formats)
    }
}

#[derive(Clone)]
pub struct GrpcPresentationPolicyProvider {
    client: PresentationPolicyServiceClient<Channel>,
    auth: GrpcAuthentication,
    workload_mtls: bool,
}

impl GrpcPresentationPolicyProvider {
    pub fn new(
        client: PresentationPolicyServiceClient<Channel>,
        token: Option<&str>,
    ) -> Result<Self, FlowProviderError> {
        Ok(Self {
            client,
            auth: GrpcAuthentication::new(token)?,
            // Preserve direct-constructor behavior; configured Flow providers
            // receive the inspected channel capability from their factory.
            workload_mtls: true,
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
                self.auth.request_for_principal(
                    EvaluatePresentationRequest {
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
                        oid4vp_transport: encode_oid4vp_transport_for_channel(
                            request.oid4vp_transport.as_ref(),
                            self.workload_mtls,
                        )?,
                    },
                    &request.principal_id,
                )?,
            )
            .await
            .map_err(|status| {
                tracing::warn!(
                    presentation_policy_id = %request.policy_id,
                    grpc_code = ?status.code(),
                    grpc_detail = %sanitized_diagnostic_text(status.message(), 512),
                    "Presentation Policy gRPC evaluation failed"
                );
                provider_status("presentation_policy", &request.policy_id, status)
            })?
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

fn encode_oid4vp_transport(
    transport: &marty_oid4vp_contract::Oid4vpEvaluationTransportV1,
) -> Result<crate::presentation_policy_proto::Oid4vpEvaluationTransport, FlowProviderError> {
    transport.validate_transport().map_err(|_| {
        invalid_response(
            "presentation_policy",
            "OID4VP transport metadata is invalid",
        )
    })?;
    Ok(
        crate::presentation_policy_proto::Oid4vpEvaluationTransport {
            query_kind: match transport.query_kind {
                marty_oid4vp_contract::QueryKind::Dcql => "dcql",
                marty_oid4vp_contract::QueryKind::PresentationExchange => "presentation_exchange",
            }
            .into(),
            query_document_json: serde_json::to_string(&transport.query_document).map_err(
                |_| invalid_response("presentation_policy", "query is not serializable"),
            )?,
            query_digest: transport.query_digest.clone(),
            presentation_submission_json: transport
                .presentation_submission
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|_| {
                    invalid_response("presentation_policy", "submission is not serializable")
                })?,
            vp_token_raw: transport.vp_token_raw.clone(),
            verifier_client_id: transport.verifier_client_id.clone(),
            request_nonce: transport.request_nonce.clone(),
        },
    )
}

fn encode_oid4vp_transport_for_channel(
    transport: Option<&marty_oid4vp_contract::Oid4vpEvaluationTransportV1>,
    workload_mtls: bool,
) -> Result<Option<crate::presentation_policy_proto::Oid4vpEvaluationTransport>, FlowProviderError>
{
    // Keep validation unchanged, but do not offer workload-only metadata over
    // the pre-existing principal-authenticated plaintext route. The policy
    // service still authorizes the actual peer independently of this flag.
    let encoded = transport.map(encode_oid4vp_transport).transpose()?;
    Ok(if workload_mtls { encoded } else { None })
}

fn nonempty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_oid4vp_transport_serializes_without_promoting_proof() {
        let query = serde_json::json!({"credentials": [{"id": "member"}]});
        let submission = serde_json::json!({"id": "legacy", "descriptor_map": [], "extra": true});
        let metadata = marty_oid4vp_contract::Oid4vpEvaluationTransportV1 {
            query_kind: marty_oid4vp_contract::QueryKind::Dcql,
            query_digest: marty_oid4vp_contract::digest_query_document(&query).unwrap(),
            query_document: query.clone(),
            presentation_submission: Some(submission.clone()),
            vp_token_raw: r#"{"member":["header.payload.signature"]}"#.into(),
            verifier_client_id: "did:web:verifier.example".into(),
            request_nonce: "nonce-with-at-least-32-bytes-1234567890".into(),
        };
        let wire = encode_oid4vp_transport(&metadata).unwrap();
        assert_eq!(wire.query_kind, "dcql");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&wire.query_document_json).unwrap(),
            query
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                wire.presentation_submission_json.as_deref().unwrap()
            )
            .unwrap(),
            submission
        );
        assert_eq!(wire.query_digest, metadata.query_digest);
        assert_eq!(wire.vp_token_raw, metadata.vp_token_raw);
        assert_eq!(wire.verifier_client_id, metadata.verifier_client_id);
        assert_eq!(wire.request_nonce, metadata.request_nonce);
        assert_eq!(
            encode_oid4vp_transport_for_channel(Some(&metadata), true).unwrap(),
            Some(wire)
        );
        assert!(encode_oid4vp_transport_for_channel(Some(&metadata), false)
            .unwrap()
            .is_none());
        let mut invalid = metadata;
        invalid.query_digest = "0".repeat(64);
        assert!(encode_oid4vp_transport(&invalid).is_err());
        assert!(encode_oid4vp_transport_for_channel(Some(&invalid), false).is_err());
    }

    #[tokio::test]
    async fn configured_plaintext_policy_channel_reaches_provider_without_workload_transport() {
        let factory = || ordinary_factory("http://127.0.0.1:9009").unwrap();
        let factories = FlowGrpcChannelFactories {
            organization: factory(),
            credential_template: factory(),
            presentation_policy: factory(),
            issuance: factory(),
        };
        assert!(!factories.presentation_policy_workload_transport());
        let clients = factories.connect_lazy().unwrap();
        let providers = clients
            .providers_with_channel_security(
                None,
                factories.presentation_policy_workload_transport(),
            )
            .unwrap();
        assert!(!providers.presentation_policy.workload_mtls);
    }

    #[test]
    fn principal_request_carries_service_and_user_authentication() {
        let authentication =
            GrpcAuthentication::new(Some("0123456789abcdef0123456789abcdef")).unwrap();
        let request = authentication.request_for_principal((), "user-1").unwrap();

        assert_eq!(
            request.metadata().get(SERVICE_TOKEN_HEADER).unwrap(),
            "0123456789abcdef0123456789abcdef"
        );
        assert_eq!(request.metadata().get(USER_ID_HEADER).unwrap(), "user-1");
        assert!(authentication
            .request_for_principal((), "invalid\nprincipal")
            .is_err());
    }
}
