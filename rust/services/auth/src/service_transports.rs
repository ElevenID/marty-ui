use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use mmf_messaging::{
    DeliveryGuarantee, EventKind, Message, MessageMetadata, MessagePriority, MessageStatus,
    MessageTransport, MessagingPattern,
};
use mmf_platform::{
    GrpcChannelFactory, OutboundHttpClient, OutboundHttpMethod, OutboundHttpRequest,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tonic::{metadata::AsciiMetadataValue, transport::Channel, Code, Request};
use url::Url;

use crate::{
    flow_proto::{flow_service_client::FlowServiceClient, StartVerificationRequest},
    organization_proto::{
        organization_service_client::OrganizationServiceClient, AddMemberRequest, GetMemberRequest,
        GetOrganizationRequest,
    },
    ApplicantProfile, ApplicantProvisioningStore, ApplicantUpsert, AuthEvent, AuthEventPublisher,
    AuthenticatedUser, CanvasApplicantProfileProvisioner, CredentialVerificationFlow,
    CredentialVerificationStarter, OrganizationContext, OrganizationProvisioning, PortError,
    StartCredentialVerification,
};

const APPLICANT_PROFILE_RESPONSE_LIMIT: usize = 64 * 1024;
const AUTH_EVENT_TOPIC: &str = "auth.events";
const SERVICE_TOKEN_HEADER: &str = "x-service-token";

#[derive(Clone)]
pub struct AuthGrpcChannelFactories {
    pub flow: GrpcChannelFactory,
    pub organization: GrpcChannelFactory,
    pub service_token: String,
}

impl AuthGrpcChannelFactories {
    pub fn connect_lazy(&self) -> Result<AuthGrpcClients, PortError> {
        Ok(AuthGrpcClients::new(
            self.flow
                .connect_lazy()
                .map_err(|error| transport_error("flow_grpc_unavailable", error))?,
            self.organization
                .connect_lazy()
                .map_err(|error| transport_error("organization_grpc_unavailable", error))?,
            self.service_token.clone(),
        ))
    }

    pub async fn connect(&self) -> Result<AuthGrpcClients, PortError> {
        let (flow, organization) =
            tokio::try_join!(self.flow.connect(), self.organization.connect())
                .map_err(|error| transport_error("auth_grpc_unavailable", error))?;
        Ok(AuthGrpcClients::new(
            flow,
            organization,
            self.service_token.clone(),
        ))
    }
}

#[derive(Clone)]
pub struct AuthGrpcClients {
    pub flow: FlowServiceClient<Channel>,
    pub organization: OrganizationServiceClient<Channel>,
    service_token: String,
}

impl AuthGrpcClients {
    #[must_use]
    pub fn new(flow: Channel, organization: Channel, service_token: impl Into<String>) -> Self {
        Self {
            flow: FlowServiceClient::new(flow),
            organization: OrganizationServiceClient::new(organization),
            service_token: service_token.into(),
        }
    }

    #[must_use]
    pub fn credential_verification(&self) -> GrpcCredentialVerificationStarter {
        GrpcCredentialVerificationStarter::new(self.flow.clone(), self.service_token.clone())
    }

    #[must_use]
    pub fn organization_provisioning(
        &self,
        default_organization_id: impl Into<String>,
    ) -> GrpcOrganizationProvisioning {
        GrpcOrganizationProvisioning::new(
            self.organization.clone(),
            default_organization_id,
            self.service_token.clone(),
        )
    }
}

#[derive(Clone)]
pub struct GrpcCredentialVerificationStarter {
    client: FlowServiceClient<Channel>,
    service_token: String,
}

impl GrpcCredentialVerificationStarter {
    #[must_use]
    pub fn new(client: FlowServiceClient<Channel>, service_token: impl Into<String>) -> Self {
        Self {
            client,
            service_token: service_token.into(),
        }
    }
}

#[async_trait]
impl CredentialVerificationStarter for GrpcCredentialVerificationStarter {
    async fn start(
        &self,
        request: &StartCredentialVerification,
    ) -> Result<CredentialVerificationFlow, PortError> {
        let mut client = self.client.clone();
        let response = client
            .start_verification(service_request(
                credential_verification_request(request),
                &self.service_token,
            )?)
            .await
            .map_err(|status| {
                PortError::new(
                    "flow_verification_start_failed",
                    format!("Flow StartVerification failed with {}", status.code()),
                )
            })?
            .into_inner();
        credential_verification_flow(response)
    }
}

#[must_use]
pub fn credential_verification_request(
    request: &StartCredentialVerification,
) -> StartVerificationRequest {
    StartVerificationRequest {
        presentation_policy_id: request.presentation_policy_id.clone(),
        organization_id: request.organization_id.clone(),
        response_type: "vp_token".into(),
        callback_url: request.callback_url.clone(),
        user_id: request.user_id.clone(),
        issuer_did: request.issuer_did.clone(),
        request_transport: "request_uri".into(),
        ..StartVerificationRequest::default()
    }
}

pub fn credential_verification_flow(
    response: crate::flow_proto::VerificationRequestResponse,
) -> Result<CredentialVerificationFlow, PortError> {
    if response.instance_id.trim().is_empty()
        || (response.request_uri.trim().is_empty() && response.qr_code_data.trim().is_empty())
    {
        return Err(PortError::new(
            "flow_verification_response_invalid",
            "Flow StartVerification returned an incomplete response",
        ));
    }
    Ok(CredentialVerificationFlow {
        instance_id: response.instance_id,
        request_uri: response.request_uri,
        qr_code_data: response.qr_code_data,
    })
}

#[derive(Clone)]
pub struct GrpcOrganizationProvisioning {
    client: OrganizationServiceClient<Channel>,
    default_organization_id: String,
    service_token: String,
}

impl GrpcOrganizationProvisioning {
    #[must_use]
    pub fn new(
        client: OrganizationServiceClient<Channel>,
        default_organization_id: impl Into<String>,
        service_token: impl Into<String>,
    ) -> Self {
        Self {
            client,
            default_organization_id: default_organization_id.into(),
            service_token: service_token.into(),
        }
    }
}

#[async_trait]
impl OrganizationProvisioning for GrpcOrganizationProvisioning {
    async fn ensure_default_member(&self, user_id: &str, email: &str) -> Result<(), PortError> {
        if self.default_organization_id.trim().is_empty()
            || user_id.trim().is_empty()
            || email.trim().is_empty()
        {
            return Err(PortError::new(
                "organization_provisioning_invalid",
                "Default organization, user ID and email are required",
            ));
        }
        let mut client = self.client.clone();
        match client
            .add_member(service_request(
                AddMemberRequest {
                    organization_id: self.default_organization_id.clone(),
                    user_id: user_id.into(),
                    email: email.into(),
                    role_ids: Vec::new(),
                },
                &self.service_token,
            )?)
            .await
        {
            Ok(_) => Ok(()),
            Err(status) if status.code() == Code::AlreadyExists => Ok(()),
            Err(status) => Err(PortError::new(
                "organization_member_add_failed",
                format!("Organization AddMember failed with {}", status.code()),
            )),
        }
    }

    async fn resolve_default_context(
        &self,
        user_id: &str,
    ) -> Result<Option<OrganizationContext>, PortError> {
        if self.default_organization_id.trim().is_empty() || user_id.trim().is_empty() {
            return Err(PortError::new(
                "organization_provisioning_invalid",
                "Default organization and user ID are required",
            ));
        }
        let mut client = self.client.clone();
        let member = match client
            .get_member(service_request(
                GetMemberRequest {
                    organization_id: self.default_organization_id.clone(),
                    user_id: user_id.into(),
                },
                &self.service_token,
            )?)
            .await
        {
            Ok(response) => response.into_inner(),
            Err(status) if status.code() == Code::NotFound => return Ok(None),
            Err(status) => {
                return Err(PortError::new(
                    "organization_member_lookup_failed",
                    format!("Organization GetMember failed with {}", status.code()),
                ));
            }
        };
        if member.organization_id.trim().is_empty() {
            return Ok(None);
        }
        let organization_name = client
            .get_organization(service_request(
                GetOrganizationRequest {
                    organization_id: member.organization_id.clone(),
                },
                &self.service_token,
            )?)
            .await
            .ok()
            .map(tonic::Response::into_inner)
            .and_then(|organization| {
                [organization.display_name, organization.name]
                    .into_iter()
                    .find(|value| !value.trim().is_empty())
            });
        Ok(Some(OrganizationContext {
            organization_id: member.organization_id,
            organization_name,
            role_names: member.roles.into_iter().map(|role| role.name).collect(),
            has_org_console_access: member.has_org_console_access,
        }))
    }
}

#[derive(Clone)]
pub struct MmfApplicantProfileProvisioner {
    client: Arc<dyn OutboundHttpClient>,
    service_url: String,
}

impl MmfApplicantProfileProvisioner {
    pub fn new(
        client: Arc<dyn OutboundHttpClient>,
        service_url: impl Into<String>,
    ) -> Result<Self, PortError> {
        let service_url = service_url.into();
        let parsed = Url::parse(&service_url).map_err(|_| {
            PortError::new(
                "applicant_profile_configuration_invalid",
                "Applicant service URL is invalid",
            )
        })?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || !matches!(parsed.path(), "" | "/")
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(PortError::new(
                "applicant_profile_configuration_invalid",
                "Applicant service URL must be an uncredentialed HTTP(S) origin",
            ));
        }
        Ok(Self {
            client,
            service_url: service_url.trim_end_matches('/').into(),
        })
    }

    async fn upsert_profile(
        &self,
        user_id: &str,
        email: &str,
        organization_id: &str,
        given_name: Option<&str>,
        family_name: Option<&str>,
        vetting_data_patch: Option<&Value>,
    ) -> Result<Value, PortError> {
        let mut payload = json!({
            "email": email,
            "given_name": given_name,
            "family_name": family_name,
        });
        if let (Some(payload), Some(patch)) = (payload.as_object_mut(), vetting_data_patch) {
            payload.insert("vetting_data_patch".into(), patch.clone());
        }
        let body = serde_json::to_vec(&payload)
            .map_err(|error| transport_error("applicant_profile_request_invalid", error))?;
        let response = self
            .client
            .execute(OutboundHttpRequest {
                method: OutboundHttpMethod::Patch,
                url: format!("{}/v1/me/applicant-profile", self.service_url),
                headers: BTreeMap::from([
                    ("content-type".into(), "application/json".into()),
                    ("x-user-id".into(), user_id.into()),
                    ("x-user-email".into(), email.into()),
                    ("x-organization-id".into(), organization_id.into()),
                ]),
                body: Some(body),
                maximum_response_bytes: APPLICANT_PROFILE_RESPONSE_LIMIT,
            })
            .await
            .map_err(|error| transport_error("applicant_profile_unavailable", error))?;
        if !(200..300).contains(&response.status) {
            return Err(PortError::new(
                "applicant_profile_rejected",
                format!(
                    "Applicant profile service returned HTTP {}",
                    response.status
                ),
            ));
        }
        response
            .json_object("applicant profile provisioning")
            .map_err(|error| transport_error("applicant_profile_response_invalid", error))
    }
}

#[async_trait]
impl CanvasApplicantProfileProvisioner for MmfApplicantProfileProvisioner {
    async fn ensure_profile(&self, user: &AuthenticatedUser) -> Result<Option<String>, PortError> {
        if user
            .applicant_id
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        {
            return Ok(user.applicant_id.clone());
        }
        let Some(organization_id) = user.organization_id.as_deref() else {
            return Ok(user.applicant_id.clone());
        };
        if user.user_id.trim().is_empty() || user.email.trim().is_empty() {
            return Ok(user.applicant_id.clone());
        }
        let payload = self
            .upsert_profile(
                &user.user_id,
                &user.email,
                organization_id,
                user.given_name.as_deref(),
                user.family_name.as_deref(),
                None,
            )
            .await?;
        Ok(payload
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .or_else(|| user.applicant_id.clone()))
    }
}

#[derive(Clone)]
pub struct MmfApplicantProvisioningStore {
    profiles: MmfApplicantProfileProvisioner,
    default_organization_id: String,
}

impl MmfApplicantProvisioningStore {
    pub fn new(
        profiles: MmfApplicantProfileProvisioner,
        default_organization_id: impl Into<String>,
    ) -> Result<Self, PortError> {
        let default_organization_id = default_organization_id.into();
        if default_organization_id.trim().is_empty() {
            return Err(PortError::new(
                "applicant_profile_configuration_invalid",
                "Default organization ID is required for applicant provisioning",
            ));
        }
        Ok(Self {
            profiles,
            default_organization_id,
        })
    }
}

#[derive(Debug, Deserialize)]
struct ApplicantServiceProfile {
    id: String,
    user_id: Option<String>,
    email: String,
    given_name: Option<String>,
    family_name: Option<String>,
    status: String,
    #[serde(default)]
    application_data: Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[async_trait]
impl ApplicantProvisioningStore for MmfApplicantProvisioningStore {
    async fn upsert(&self, plan: &ApplicantUpsert) -> Result<ApplicantProfile, PortError> {
        let payload = self
            .profiles
            .upsert_profile(
                &plan.account_id,
                &plan.email,
                &self.default_organization_id,
                plan.given_names.as_deref(),
                plan.surname.as_deref(),
                Some(&plan.extra_data_patch),
            )
            .await?;
        let profile: ApplicantServiceProfile = serde_json::from_value(payload)
            .map_err(|error| transport_error("applicant_profile_response_invalid", error))?;
        if profile.id.trim().is_empty()
            || profile.email != plan.email
            || profile.user_id.as_deref() != Some(plan.account_id.as_str())
        {
            return Err(PortError::new(
                "applicant_profile_response_invalid",
                "Applicant profile service returned an inconsistent identity",
            ));
        }
        let identity_proofing_completed = profile
            .application_data
            .get("identity_proofing_completed")
            .and_then(Value::as_bool)
            .unwrap_or({
                matches!(
                    profile.status.as_str(),
                    "APPROVED" | "OFFERED" | "CREDENTIALED"
                )
            });
        let identity_proofing_date = profile
            .application_data
            .get("identity_proofing_date")
            .and_then(Value::as_str)
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&Utc))
            .or_else(|| identity_proofing_completed.then_some(profile.updated_at));
        let date_of_birth = profile
            .application_data
            .get("date_of_birth")
            .and_then(Value::as_str)
            .and_then(|value| NaiveDate::parse_from_str(value, "%Y-%m-%d").ok())
            .unwrap_or(plan.date_of_birth);
        let nationality = profile
            .application_data
            .get("nationality")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(&plan.nationality)
            .to_owned();
        let suspended = profile.status == "SUSPENDED";
        Ok(ApplicantProfile {
            id: profile.id,
            account_id: profile.user_id,
            email: profile.email,
            surname: profile
                .family_name
                .unwrap_or_else(|| plan.fallback_surname.clone()),
            given_names: profile
                .given_name
                .unwrap_or_else(|| plan.fallback_given_names.clone()),
            date_of_birth,
            nationality,
            identity_proofing_completed,
            identity_proofing_date,
            active: !suspended,
            suspended,
            extra_data: profile.application_data,
            created_at: profile.created_at,
            updated_at: profile.updated_at,
        })
    }
}

#[derive(Clone)]
pub struct MmfAuthEventPublisher {
    transport: Arc<dyn MessageTransport>,
}

impl MmfAuthEventPublisher {
    #[must_use]
    pub fn new(transport: Arc<dyn MessageTransport>) -> Self {
        Self { transport }
    }
}

#[async_trait]
impl AuthEventPublisher for MmfAuthEventPublisher {
    async fn publish(&self, event: &AuthEvent) -> Result<(), PortError> {
        self.transport
            .publish(auth_event_message(event)?)
            .await
            .map_err(|error| transport_error("auth_event_publish_failed", error))
    }
}

pub fn auth_event_message(event: &AuthEvent) -> Result<Message, PortError> {
    let now = Utc::now();
    let (message_type, aggregate_id, tenant_id) = match event {
        AuthEvent::UserAuthenticated {
            user_id,
            organization_id,
            ..
        } => ("user_authenticated", user_id, organization_id.clone()),
        AuthEvent::SessionCreated {
            session_id,
            organization_id,
            ..
        } => ("session_created", session_id, organization_id.clone()),
        AuthEvent::UserLoggedOut {
            user_id,
            organization_id,
            ..
        } => ("logout", user_id, organization_id.clone()),
        AuthEvent::SessionRevoked {
            user_id,
            organization_id,
            ..
        } => ("session_revoked", user_id, organization_id.clone()),
    };
    if aggregate_id.trim().is_empty() {
        return Err(PortError::new(
            "auth_event_invalid",
            "Auth events require a non-empty aggregate ID",
        ));
    }
    let created_at_ms = u64::try_from(now.timestamp_millis()).unwrap_or_default();
    let mut metadata = MessageMetadata::new(created_at_ms);
    metadata.tenant_id = tenant_id;
    metadata.source_service = Some("auth".into());
    metadata.partition_key = Some(aggregate_id.clone());
    metadata.ordering_key = Some(aggregate_id.clone());
    metadata.deduplication_key = Some(metadata.message_id.clone());
    Ok(Message {
        metadata,
        kind: EventKind::Domain,
        message_type: message_type.into(),
        pattern: MessagingPattern::PublishSubscribe,
        delivery_guarantee: DeliveryGuarantee::AtLeastOnce,
        priority: MessagePriority::Normal,
        status: MessageStatus::Pending,
        topic: AUTH_EVENT_TOPIC.into(),
        routing_key: message_type.into(),
        reply_to: None,
        payload: serde_json::to_value(event)
            .map_err(|error| transport_error("auth_event_invalid", error))?,
        retry_count: 0,
        max_retries: 3,
    })
}

fn transport_error(code: &str, error: impl std::fmt::Display) -> PortError {
    PortError::new(code, error.to_string())
}

fn service_request<T>(body: T, service_token: &str) -> Result<Request<T>, PortError> {
    let mut token = AsciiMetadataValue::try_from(service_token).map_err(|_| {
        PortError::new(
            "grpc_service_token_invalid",
            "GRPC_SERVICE_TOKEN is not valid gRPC metadata",
        )
    })?;
    token.set_sensitive(true);
    let mut request = Request::new(body);
    request.metadata_mut().insert(SERVICE_TOKEN_HEADER, token);
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::{service_request, SERVICE_TOKEN_HEADER};

    #[test]
    fn service_requests_attach_the_configured_workload_token() {
        let request = service_request((), &"g".repeat(32)).expect("service request");

        assert_eq!(
            request
                .metadata()
                .get(SERVICE_TOKEN_HEADER)
                .expect("service token"),
            "g".repeat(32).as_str()
        );
        assert!(request
            .metadata()
            .get(SERVICE_TOKEN_HEADER)
            .expect("service token")
            .is_sensitive());
    }

    #[test]
    fn service_requests_reject_non_ascii_tokens() {
        let invalid_token = format!("{}\n{}", "g".repeat(16), "g".repeat(16));
        let error = service_request((), &invalid_token).expect_err("invalid token");

        assert_eq!(error.code, "grpc_service_token_invalid");
    }
}
