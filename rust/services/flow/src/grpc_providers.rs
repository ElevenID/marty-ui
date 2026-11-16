use std::{collections::BTreeSet, path::PathBuf};

use async_trait::async_trait;
#[cfg(test)]
use mmf_platform::OpenBaoTlsIdentityFiles;
use mmf_platform::{
    GrpcChannelConfig, GrpcChannelFactory, GrpcTlsMaterial, GrpcTransportSecurity, GrpcTrustMode,
    KeylessGrpcTransportOptions, PlatformError,
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

fn decode_template_reference(
    template_id: &str,
    response: crate::credential_template_proto::TemplateResponse,
) -> Result<CredentialTemplateReference, FlowProviderError> {
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
        jwt_vc_profile: marty_jwt_vc_issuance::parse_optional_policy_json(
            &response.jwt_vc_profile_json,
        )
        .map_err(|_| invalid_response("credential_template", "invalid explicit JWT-VC policy"))?,
        issuance_protocol: response.issuance_protocol,
        wallet_configurations: bounded_json(&response.wallet_configs_json, "credential_template")?,
        issuer_algorithm: nonempty(response.issuer_algorithm),
    })
}

fn decode_policy_reference(
    policy_id: &str,
    response: crate::presentation_policy_proto::PolicyResponse,
) -> Result<PresentationPolicyReference, FlowProviderError> {
    if response.id != policy_id || response.organization_id.trim().is_empty() {
        return Err(invalid_response(
            "presentation_policy",
            "policy identity mismatch",
        ));
    }
    let policy_revision = decode_policy_revision(
        response.policy_revision.as_ref(),
        &response.organization_id,
        policy_id,
    )?;
    if u32::try_from(response.version).ok() != Some(policy_revision.version) {
        return Err(invalid_response(
            "presentation_policy",
            "policy version mismatch",
        ));
    }
    let prerequisite_evidence_profile = match response.prerequisite_evidence_profile.as_str() {
        "" => None,
        "managed_sd_jwt_dcql_v1" => Some(response.prerequisite_evidence_profile.clone()),
        _ => {
            return Err(invalid_response(
                "presentation_policy",
                "unknown prerequisite evidence profile",
            ))
        }
    };
    let credential_authority: Option<
        marty_oid4vp_contract::trust_authority::CredentialAuthoritySnapshotV1,
    > = if response.credential_authority_snapshot_json.is_empty() {
        None
    } else {
        Some(bounded_json(
            &response.credential_authority_snapshot_json,
            "presentation_policy",
        )?)
    };
    if prerequisite_evidence_profile.is_some() != credential_authority.is_some()
        || credential_authority.as_ref().is_some_and(|authority| {
            authority.validate().is_err() || authority.organization_id != response.organization_id
        })
    {
        return Err(invalid_response(
            "presentation_policy",
            "credential authority snapshot mismatch",
        ));
    }
    Ok(PresentationPolicyReference {
        id: response.id,
        organization_id: response.organization_id,
        status: response.status,
        policy_revision,
        holder_binding_required: response.holder_binding_required,
        prerequisite_evidence_profile,
        credential_authority,
        credential_requirements: bounded_json(
            &response.credential_requirements_json,
            "presentation_policy",
        )?,
    })
}

const MAXIMUM_PROVIDER_JSON_BYTES: usize = 1024 * 1024;
const SERVICE_TOKEN_HEADER: &str = "x-service-token";
const USER_ID_HEADER: &str = "x-user-id";

#[derive(Clone)]
pub struct FlowGrpcChannelFactories {
    pub organization: FlowWorkloadChannelFactory,
    pub credential_template: FlowWorkloadChannelFactory,
    pub presentation_policy: FlowWorkloadChannelFactory,
    pub issuance: FlowWorkloadChannelFactory,
}

#[derive(Clone)]
pub enum FlowWorkloadChannelFactory {
    Ordinary(GrpcChannelFactory),
    ServerTls {
        target: String,
        ca_certificate: PathBuf,
    },
    Keyless {
        target: String,
        files: crate::WorkloadClientTlsFiles,
    },
}

impl From<GrpcChannelFactory> for FlowWorkloadChannelFactory {
    fn from(factory: GrpcChannelFactory) -> Self {
        Self::Ordinary(factory)
    }
}

impl FlowWorkloadChannelFactory {
    fn connect_lazy(&self) -> Result<Channel, PlatformError> {
        match self {
            Self::Ordinary(factory) => factory.connect_lazy(),
            Self::ServerTls {
                target,
                ca_certificate,
            } => server_tls_factory(target, ca_certificate)?.connect_lazy(),
            Self::Keyless { .. } => Err(PlatformError::InvalidConfiguration(
                "keyless workload channels require asynchronous KMS setup".into(),
            )),
        }
    }

    async fn connect(&self) -> Result<Channel, PlatformError> {
        match self {
            Self::Ordinary(factory) => factory.connect().await,
            Self::ServerTls {
                target,
                ca_certificate,
            } => server_tls_factory(target, ca_certificate)?.connect().await,
            Self::Keyless { target, files } => {
                let identity = files.identity.clone();
                identity
                    .grpc_channel_connected(
                        target,
                        &files.ca_certificate,
                        KeylessGrpcTransportOptions::default(),
                    )
                    .await
            }
        }
    }

    fn is_keyless(&self) -> bool {
        matches!(self, Self::Keyless { .. })
    }
}

impl FlowGrpcChannelFactories {
    pub fn from_config(config: &FlowServiceConfig) -> Result<Self, PlatformError> {
        Ok(Self {
            organization: if let Some(files) = &config.workload_client_tls {
                FlowWorkloadChannelFactory::ServerTls {
                    target: config.organization_grpc_target.clone(),
                    ca_certificate: files.ca_certificate.clone(),
                }
            } else {
                ordinary_factory(&config.organization_grpc_target)?.into()
            },
            credential_template: if let Some(files) = &config.workload_client_tls {
                FlowWorkloadChannelFactory::ServerTls {
                    target: config.credential_template_grpc_target.clone(),
                    ca_certificate: files.ca_certificate.clone(),
                }
            } else {
                ordinary_factory(&config.credential_template_grpc_target)?.into()
            },
            presentation_policy: workload_factory(
                &config.presentation_policy_grpc_target,
                config.workload_client_tls.as_ref(),
            )?,
            issuance: workload_factory(
                &config.issuance_grpc_target,
                config.workload_client_tls.as_ref(),
            )?,
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
        let mut clients = FlowGrpcClients::new(
            organization,
            credential_template,
            presentation_policy,
            issuance,
        );
        // Keep the inspected capability with the exact client constructed from
        // this connected channel. A raw or replaceable client cannot inherit it.
        clients.presentation_policy_mtls = self.presentation_policy.is_keyless();
        Ok(clients)
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

fn server_tls_factory(
    target: &str,
    ca_certificate: &std::path::Path,
) -> Result<GrpcChannelFactory, PlatformError> {
    GrpcChannelFactory::new(
        GrpcChannelConfig {
            target: target.into(),
            security: GrpcTransportSecurity::ServerTls,
            trust: GrpcTrustMode::CustomCa,
            ..GrpcChannelConfig::default()
        },
        GrpcTlsMaterial::from_ca_pem_file(Some(ca_certificate))?,
    )
}

fn workload_factory(
    target: &str,
    files: Option<&crate::WorkloadClientTlsFiles>,
) -> Result<FlowWorkloadChannelFactory, PlatformError> {
    let Some(files) = files else {
        return ordinary_factory(target).map(FlowWorkloadChannelFactory::Ordinary);
    };
    if !target.starts_with("https://") {
        return Err(PlatformError::InvalidConfiguration(
            "keyless workload target must be an explicit HTTPS origin".into(),
        ));
    }
    Ok(FlowWorkloadChannelFactory::Keyless {
        target: target.into(),
        files: files.clone(),
    })
}

#[derive(Clone)]
pub struct FlowGrpcClients {
    pub organization: OrganizationServiceClient<Channel>,
    pub credential_template: CredentialTemplateServiceClient<Channel>,
    presentation_policy: PresentationPolicyServiceClient<Channel>,
    presentation_policy_mtls: bool,
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
            presentation_policy_mtls: false,
            issuance: IssuanceServiceClient::new(issuance),
        }
    }

    pub fn providers(
        self,
        service_token: Option<&str>,
    ) -> Result<FlowGrpcProviders, FlowProviderError> {
        let mut presentation_policy =
            GrpcPresentationPolicyProvider::new(self.presentation_policy, service_token)?;
        presentation_policy.workload_mtls = self.presentation_policy_mtls;
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
        decode_template_reference(template_id, response)
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

/// A Policy observation acquired by the exact inspected workload-mTLS client.
/// The serialized candidate alone has no authority. A cloned acquisition cannot
/// be attached to a changed request or evaluation.
///
/// ```compile_fail
/// let _: marty_flow::AcquiredManagedPolicyEvidence =
///     serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, PartialEq)]
pub struct AcquiredManagedPolicyEvidence {
    candidate: marty_oid4vp_contract::ManagedPolicyEvidenceProjectionV2,
    acquisition_digest: String,
}

impl std::fmt::Debug for AcquiredManagedPolicyEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcquiredManagedPolicyEvidence")
            .finish_non_exhaustive()
    }
}

impl AcquiredManagedPolicyEvidence {
    fn acquire(
        wire: &str,
        request: &PresentationEvaluationRequest,
        evaluation: &PresentationEvaluationResult,
        counts: [i32; 4],
    ) -> Result<Self, FlowProviderError> {
        let invalid = || {
            invalid_response(
                "presentation_policy",
                "invalid managed evidence acquisition",
            )
        };
        if wire.len() > marty_oid4vp_contract::MAX_EVIDENCE_PROJECTION_BYTES {
            return Err(invalid());
        }
        let candidate = marty_oid4vp_contract::ManagedPolicyEvidenceProjectionV2::from_json(wire)
            .map_err(|_| invalid())?;
        let transport = request.oid4vp_transport.as_ref().ok_or_else(invalid)?;
        let context = serde_json::to_value(&request.context).map_err(|_| invalid())?;
        let mut result = serde_json::to_value(evaluation).map_err(|_| invalid())?;
        for (field, value) in [
            "total_requirements",
            "satisfied_requirements",
            "required_satisfied",
            "required_total",
        ]
        .into_iter()
        .zip(counts)
        {
            result[field] = serde_json::json!(value);
        }
        candidate
            .validate_for_request(
                &marty_oid4vp_contract::PolicyEvaluationValidityRequest {
                    organization_id: &request.organization_id,
                    policy: &request.expected_policy_revision,
                    nonce: &request.nonce,
                    audience: &request.audience,
                    vp_token: &request.presentation,
                    trust_profile_id: request
                        .context
                        .get("trust_profile_id")
                        .and_then(serde_json::Value::as_str),
                    context: &context,
                    oid4vp_transport: transport,
                },
                &result,
            )
            .map_err(|_| invalid())?;
        candidate
            .validate_original_tokens(&[
                request.presentation.as_str(),
                transport.vp_token_raw.as_str(),
            ])
            .map_err(|_| invalid())?;
        Ok(Self {
            candidate,
            acquisition_digest: Self::binding_digest(request, evaluation)?,
        })
    }

    fn binding_digest(
        request: &PresentationEvaluationRequest,
        evaluation: &PresentationEvaluationResult,
    ) -> Result<String, FlowProviderError> {
        marty_oid4vp_contract::digest_domain_json(
            "marty.flow/managed-policy-acquisition/v2",
            &serde_json::json!({"request": request, "evaluation": evaluation}),
        )
        .map_err(|_| invalid_response("presentation_policy", "invalid managed acquisition binding"))
    }

    pub(crate) fn candidate_for(
        &self,
        request: &PresentationEvaluationRequest,
        evaluation: &PresentationEvaluationResult,
    ) -> Result<&marty_oid4vp_contract::ManagedPolicyEvidenceProjectionV2, FlowProviderError> {
        if Self::binding_digest(request, evaluation)? != self.acquisition_digest {
            return Err(invalid_response(
                "presentation_policy",
                "managed acquisition changed",
            ));
        }
        Ok(&self.candidate)
    }
}

impl GrpcPresentationPolicyProvider {
    pub fn new(
        client: PresentationPolicyServiceClient<Channel>,
        token: Option<&str>,
    ) -> Result<Self, FlowProviderError> {
        Ok(Self {
            client,
            auth: GrpcAuthentication::new(token)?,
            // Raw clients carry no inspected workload-identity provenance.
            workload_mtls: false,
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
        decode_policy_reference(policy_id, response)
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
                        expected_policy_revision: Some(encode_policy_revision(
                            &request.expected_policy_revision,
                            &request.organization_id,
                            &request.policy_id,
                        )?),
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
        let evaluation_validity = if response.evaluation_validity_json.is_empty() {
            None
        } else {
            if !self.workload_mtls {
                return Err(invalid_response(
                    "presentation_policy",
                    "uninspected validity channel",
                ));
            }
            Some(
                marty_oid4vp_contract::PolicyEvaluationValidityV1::from_json(
                    &response.evaluation_validity_json,
                )
                .map_err(|_| {
                    invalid_response("presentation_policy", "invalid evaluation validity")
                })?,
            )
        };
        let managed_evidence_json = response.managed_policy_evidence_json;
        let counts = [
            response.total_requirements,
            response.satisfied_requirements,
            response.required_satisfied,
            response.required_total,
        ];
        let mut evaluation = PresentationEvaluationResult {
            managed_evidence: None,
            evaluation_validity,
            evaluation_timestamp: nonempty(response.evaluation_timestamp),
            policy_revision: decode_policy_revision(
                response.policy_revision.as_ref(),
                &request.organization_id,
                &request.policy_id,
            )?,
            result: response.result,
            decision: response.decision,
            decision_reason: nonempty(response.decision_reason),
            verified_claims: bounded_json(&response.verified_claims_json, "presentation_policy")?,
            credential_results: bounded_json(
                &response.credential_results_json,
                "presentation_policy",
            )?,
            authentication_diagnostic:
                marty_oid4vp_contract::BoundAuthenticationDiagnosticV1::from_optional_json(
                    &response.authentication_diagnostic_json,
                    &request.policy_id,
                    &request.nonce,
                    &request.presentation,
                )
                .map_err(|_| {
                    invalid_response(
                        "presentation_policy",
                        "authentication diagnostic binding mismatch",
                    )
                })?,
            error_codes: Vec::new(),
            warnings: Vec::new(),
        };
        evaluation.validate_validity_for(request)?;
        if !managed_evidence_json.is_empty() {
            if !self.workload_mtls {
                return Err(invalid_response(
                    "presentation_policy",
                    "uninspected managed evidence channel",
                ));
            }
            evaluation.managed_evidence = Some(AcquiredManagedPolicyEvidence::acquire(
                &managed_evidence_json,
                request,
                &evaluation,
                counts,
            )?);
        }
        Ok(evaluation)
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
                    offer_ttl_seconds: request.offer_ttl_seconds,
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
    if provider == "presentation_policy"
        && status.code() == Code::FailedPrecondition
        && status.message() == "PRESENTATION_POLICY.CREDENTIAL_AUTHORITY_CHANGED"
    {
        return FlowProviderError::CredentialAuthorityChanged;
    }
    if provider == "presentation_policy"
        && status.code() == Code::FailedPrecondition
        && status.message() == "PRESENTATION_POLICY.POLICY_REVISION_MISMATCH"
    {
        return FlowProviderError::PolicyRevisionMismatch;
    }
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

fn encode_policy_revision(
    revision: &marty_oid4vp_contract::FrozenPolicyIdentity,
    organization_id: &str,
    policy_id: &str,
) -> Result<crate::presentation_policy_proto::PolicyRevision, FlowProviderError> {
    if organization_id.trim().is_empty() || revision.id != policy_id || revision.validate().is_err()
    {
        return Err(invalid_response(
            "presentation_policy",
            "invalid expected policy revision",
        ));
    }
    Ok(crate::presentation_policy_proto::PolicyRevision {
        organization_id: organization_id.into(),
        id: revision.id.clone(),
        version: revision.version,
        content_digest: revision.content_digest.clone(),
    })
}

fn decode_policy_revision(
    wire: Option<&crate::presentation_policy_proto::PolicyRevision>,
    organization_id: &str,
    policy_id: &str,
) -> Result<marty_oid4vp_contract::FrozenPolicyIdentity, FlowProviderError> {
    let wire =
        wire.ok_or_else(|| invalid_response("presentation_policy", "policy revision is missing"))?;
    let revision = marty_oid4vp_contract::FrozenPolicyIdentity {
        id: wire.id.clone(),
        version: wire.version,
        content_digest: wire.content_digest.clone(),
    };
    if wire.organization_id != organization_id
        || organization_id.trim().is_empty()
        || revision.id != policy_id
        || revision.validate().is_err()
    {
        return Err(invalid_response(
            "presentation_policy",
            "policy revision binding mismatch",
        ));
    }
    Ok(revision)
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
            credential_authority_snapshot_json: transport
                .credential_authority
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|_| {
                    invalid_response(
                        "presentation_policy",
                        "credential authority is not serializable",
                    )
                })?
                .unwrap_or_default(),
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
    // Frozen Flow requests require their exact query to reach the workload-
    // authenticated evaluator. Dropping metadata would silently change the
    // evaluation contract. Standalone callers with no Flow transport remain
    // separate and still bind their explicit policy revision.
    let encoded = transport.map(encode_oid4vp_transport).transpose()?;
    if encoded.is_some() && !workload_mtls {
        return Err(FlowProviderError::Rejected {
            provider: "presentation_policy",
            message: "frozen Flow presentation evaluation requires workload mutual TLS".into(),
        });
    }
    Ok(encoded)
}

fn nonempty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_jwt_vc_owner_responses_survive_protobuf_without_legacy_capability_widening() {
        use prost::Message;
        use serde_json::json;
        let revision = marty_oid4vp_contract::FrozenPolicyIdentity {
            id: "policy-1".into(),
            version: 1,
            content_digest: format!("sha256:{}", "a".repeat(64)),
        };
        let mut response=crate::presentation_policy_proto::PolicyResponse {
            id:"policy-1".into(),organization_id:"org-1".into(),status:"active".into(),version:1,
            policy_revision:Some(encode_policy_revision(&revision,"org-1","policy-1").unwrap()),
            credential_requirements_json:json!([{"id":"member","credential_template_id":"template-1","required":true,"expected_securing_profile":"w3c_vc2_jose_2026_v1","credential_payload_format":"VC_JWT_DIRECT_V1","requested_claims":[]}]).to_string(),
            holder_binding_required:true,..Default::default()
        };
        let decoded = crate::presentation_policy_proto::PolicyResponse::decode(
            response.encode_to_vec().as_slice(),
        )
        .unwrap();
        let selected = decode_policy_reference("policy-1", decoded).unwrap();
        assert!(selected.holder_binding_required);
        assert_eq!(
            selected.credential_requirements[0]["expected_securing_profile"],
            "w3c_vc2_jose_2026_v1"
        );
        response.holder_binding_required = false; // Older responses omit the new proto3 field.
        let old = decode_policy_reference(
            "policy-1",
            crate::presentation_policy_proto::PolicyResponse::decode(
                response.encode_to_vec().as_slice(),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!old.holder_binding_required);
        assert!(serde_json::to_value(&old)
            .unwrap()
            .get("holder_binding_required")
            .is_none());

        let mut template = crate::credential_template_proto::TemplateResponse {
            id: "template-1".into(),
            organization_id: "org-1".into(),
            status: "active".into(),
            credential_type: "MemberCredential".into(),
            credential_payload_format: "vc_jwt_direct_v1".into(),
            supported_formats: vec!["VC_JWT_DIRECT_V1".into()],
            jwt_vc_profile_json: serde_json::to_string(
                &marty_jwt_vc_issuance::JwtVcTemplatePolicy::new(300).unwrap(),
            )
            .unwrap(),
            wallet_configs_json: "[]".into(),
            ..Default::default()
        };
        let direct = decode_template_reference(
            "template-1",
            crate::credential_template_proto::TemplateResponse::decode(
                template.encode_to_vec().as_slice(),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(direct.credential_format, "vc_jwt_direct_v1");
        assert_eq!(direct.supported_formats, ["VC_JWT_DIRECT_V1"]);
        assert!(direct.jwt_vc_profile.is_some());
        for malformed in [
            "null",
            "{}",
            r#"{"contract":"marty.jwt-vc-template-profile/v1","securing_profile":"unknown","signature_lifetime_seconds":300}"#,
        ] {
            template.jwt_vc_profile_json = malformed.into();
            assert!(decode_template_reference("template-1", template.clone()).is_err());
        }
        template.jwt_vc_profile_json.clear();
        template.credential_payload_format = "jwt_vc".into();
        template.supported_formats = vec!["VC_JWT".into()];
        let legacy = decode_template_reference("template-1", template).unwrap();
        assert!(legacy.jwt_vc_profile.is_none());
        assert!(serde_json::to_value(legacy)
            .unwrap()
            .get("jwt_vc_profile")
            .is_none());
    }

    fn flow_issuance_fixture(name: &str) -> String {
        std::env::var(format!("MARTY_TEST_FLOW_ISSUANCE_{name}"))
            .unwrap_or_else(|_| panic!("missing disposable Flow/Issuance {name} fixture"))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires scripts/with_disposable_event_stream_kms.py --profile flow-issuance"]
    async fn flow_issuance_channel_requires_remote_key_mutual_tls() {
        use std::time::Duration;
        use tokio::{net::TcpListener, sync::oneshot};
        use tokio_stream::{wrappers::TcpListenerStream, StreamExt};
        use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Server};

        let ca = PathBuf::from(flow_issuance_fixture("WORKLOAD_CA"));
        let server_identity = OpenBaoTlsIdentityFiles {
            certificate_chain_file: PathBuf::from(flow_issuance_fixture("ISSUANCE_SERVER_CERT")),
            kms_ca_cert_file: PathBuf::from(flow_issuance_fixture("KMS_CA")),
            kms_endpoint: flow_issuance_fixture("KMS_URL"),
            kms_token_file: PathBuf::from(flow_issuance_fixture("ISSUANCE_SERVER_KMS_TOKEN_FILE")),
            kms_key_name: flow_issuance_fixture("ISSUANCE_SERVER_KMS_KEY_NAME"),
            kms_key_version: 1,
            request_timeout: Duration::from_secs(10),
            max_concurrent_signs: 16,
        };
        let acceptor = server_identity
            .grpc_acceptor(&ca, 16, Duration::from_secs(10))
            .await
            .expect("Issuance must load its remote TLS signer");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (stop, stopped) = oneshot::channel::<()>();
        let incoming = TcpListenerStream::new(listener).then(move |connection| {
            let acceptor = acceptor.clone();
            async move {
                match connection {
                    Ok(stream) => acceptor.accept(stream).await,
                    Err(error) => Err(error),
                }
            }
        });
        let (_, health_service) = tonic_health::server::health_reporter();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(health_service)
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
        });
        let target = format!("https://localhost:{port}");
        let public_ca_only = Endpoint::from_shared(target.clone())
            .unwrap()
            .tls_config(
                ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(std::fs::read(&ca).unwrap())),
            )
            .unwrap()
            .connect_timeout(Duration::from_secs(5))
            .connect()
            .await;
        if let Ok(channel) = public_ca_only {
            let response = tonic_health::pb::health_client::HealthClient::new(channel)
                .check(tonic::Request::new(tonic_health::pb::HealthCheckRequest {
                    service: String::new(),
                }))
                .await;
            assert!(
                response.is_err(),
                "Issuance must reject a client without its certificate"
            );
        }
        let factory = FlowWorkloadChannelFactory::Keyless {
            target: target.clone(),
            files: crate::WorkloadClientTlsFiles {
                ca_certificate: ca.clone(),
                identity: OpenBaoTlsIdentityFiles {
                    certificate_chain_file: PathBuf::from(flow_issuance_fixture(
                        "FLOW_CLIENT_CERT",
                    )),
                    kms_endpoint: flow_issuance_fixture("KMS_URL"),
                    kms_ca_cert_file: PathBuf::from(flow_issuance_fixture("KMS_CA")),
                    kms_token_file: PathBuf::from(flow_issuance_fixture(
                        "FLOW_CLIENT_KMS_TOKEN_FILE",
                    )),
                    kms_key_name: flow_issuance_fixture("FLOW_CLIENT_KMS_KEY_NAME"),
                    kms_key_version: 1,
                    request_timeout: Duration::from_secs(10),
                    max_concurrent_signs: 64,
                }
                .into(),
            },
        };
        let channel = factory
            .connect()
            .await
            .expect("Flow keyless channel must connect");
        let response = tonic_health::pb::health_client::HealthClient::new(channel)
            .check(tonic::Request::new(tonic_health::pb::HealthCheckRequest {
                service: String::new(),
            }))
            .await
            .expect("Flow must complete an RPC over mutual keyless TLS")
            .into_inner();
        assert_eq!(response.status, 1);
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[test]
    fn typed_oid4vp_transport_serializes_without_promoting_proof() {
        let query = serde_json::json!({"credentials": [{"id": "member"}]});
        let submission = serde_json::json!({"id": "legacy", "descriptor_map": [], "extra": true});
        let metadata = marty_oid4vp_contract::Oid4vpEvaluationTransportV1 {
            credential_authority: None,
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
        assert!(encode_oid4vp_transport_for_channel(Some(&metadata), false).is_err());
        assert!(encode_oid4vp_transport_for_channel(None, false)
            .unwrap()
            .is_none());
        let mut invalid = metadata;
        invalid.query_digest = "0".repeat(64);
        assert!(encode_oid4vp_transport(&invalid).is_err());
        assert!(encode_oid4vp_transport_for_channel(Some(&invalid), false).is_err());
    }

    #[test]
    fn policy_revision_wire_requires_exact_tenant_identity_and_valid_material() {
        let revision = marty_oid4vp_contract::FrozenPolicyIdentity {
            id: "policy-1".into(),
            version: 7,
            content_digest: format!("sha256:{}", "a".repeat(64)),
        };
        let wire = encode_policy_revision(&revision, "org-1", "policy-1").unwrap();
        assert_eq!(
            decode_policy_revision(Some(&wire), "org-1", "policy-1").unwrap(),
            revision
        );
        assert!(decode_policy_revision(None, "org-1", "policy-1").is_err());
        assert!(decode_policy_revision(Some(&wire), "other-org", "policy-1").is_err());
        assert!(decode_policy_revision(Some(&wire), "org-1", "other-policy").is_err());
        assert!(encode_policy_revision(&revision, "", "policy-1").is_err());
        assert!(encode_policy_revision(&revision, "org-1", "other-policy").is_err());
        for mutation in 0..3 {
            let mut invalid = wire.clone();
            match mutation {
                0 => invalid.version = 0,
                1 => invalid.content_digest = format!("sha256:{}", "A".repeat(64)),
                _ => invalid.content_digest.clear(),
            }
            assert!(decode_policy_revision(Some(&invalid), "org-1", "policy-1").is_err());
        }
    }

    #[test]
    fn producer_revision_rejection_is_not_erased_as_provider_unavailability() {
        assert_eq!(
            provider_status(
                "presentation_policy",
                "policy-1",
                Status::failed_precondition("PRESENTATION_POLICY.CREDENTIAL_AUTHORITY_CHANGED")
            ),
            FlowProviderError::CredentialAuthorityChanged
        );
        assert_eq!(
            provider_status(
                "presentation_policy",
                "policy-1",
                Status::failed_precondition("PRESENTATION_POLICY.POLICY_REVISION_MISMATCH")
            ),
            FlowProviderError::PolicyRevisionMismatch
        );
        for status in [
            Status::unavailable("PRESENTATION_POLICY.POLICY_REVISION_MISMATCH"),
            Status::failed_precondition("different rejection"),
        ] {
            assert_ne!(
                provider_status("presentation_policy", "policy-1", status),
                FlowProviderError::PolicyRevisionMismatch
            );
        }
        assert_ne!(
            provider_status(
                "credential_template",
                "template-1",
                Status::failed_precondition("PRESENTATION_POLICY.POLICY_REVISION_MISMATCH")
            ),
            FlowProviderError::PolicyRevisionMismatch
        );
    }

    #[tokio::test]
    async fn configured_plaintext_policy_channel_reaches_provider_without_workload_transport() {
        let factory = || ordinary_factory("http://127.0.0.1:9009").unwrap();
        let factories = FlowGrpcChannelFactories {
            organization: factory().into(),
            credential_template: factory().into(),
            presentation_policy: factory().into(),
            issuance: factory().into(),
        };
        let clients = factories.connect_lazy().unwrap();
        let providers = clients.providers(None).unwrap();
        assert!(!providers.presentation_policy.workload_mtls);
    }

    #[tokio::test]
    async fn raw_clients_never_claim_inspected_workload_identity() {
        for target in ["http://127.0.0.1:9009", "https://policy.example:9009"] {
            let channel = tonic::transport::Endpoint::from_shared(target.to_owned())
                .unwrap()
                .connect_lazy();
            let direct = GrpcPresentationPolicyProvider::new(
                PresentationPolicyServiceClient::new(channel.clone()),
                None,
            )
            .unwrap();
            assert!(!direct.workload_mtls);
            let clients =
                FlowGrpcClients::new(channel.clone(), channel.clone(), channel.clone(), channel);
            assert!(
                !clients
                    .providers(None)
                    .unwrap()
                    .presentation_policy
                    .workload_mtls
            );
        }
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
