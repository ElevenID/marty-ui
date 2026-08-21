use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use chrono::Utc;
use mmf_messaging::{
    DeliveryGuarantee, EventKind, Message, MessageMetadata, MessagePriority, MessageStatus,
    MessageTransport, MessagingPattern,
};
use mmf_platform::{
    GrpcChannelFactory, OutboundHttpClient, OutboundHttpMethod, OutboundHttpRequest,
};
use serde_json::{json, Value};
use tonic::{transport::Channel, Code, Request};
use url::Url;

use crate::{
    flow_proto::{flow_service_client::FlowServiceClient, StartVerificationRequest},
    organization_proto::{
        organization_service_client::OrganizationServiceClient, AddMemberRequest, GetMemberRequest,
        GetOrganizationRequest,
    },
    AuthEvent, AuthEventPublisher, AuthenticatedUser, CanvasApplicantProfileProvisioner,
    CredentialVerificationFlow, CredentialVerificationStarter, OrganizationContext,
    OrganizationProvisioning, PortError, StartCredentialVerification,
};

const APPLICANT_PROFILE_RESPONSE_LIMIT: usize = 64 * 1024;
const AUTH_EVENT_TOPIC: &str = "auth.events";

#[derive(Clone)]
pub struct AuthGrpcChannelFactories {
    pub flow: GrpcChannelFactory,
    pub organization: GrpcChannelFactory,
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
        ))
    }

    pub async fn connect(&self) -> Result<AuthGrpcClients, PortError> {
        let (flow, organization) =
            tokio::try_join!(self.flow.connect(), self.organization.connect())
                .map_err(|error| transport_error("auth_grpc_unavailable", error))?;
        Ok(AuthGrpcClients::new(flow, organization))
    }
}

#[derive(Clone)]
pub struct AuthGrpcClients {
    pub flow: FlowServiceClient<Channel>,
    pub organization: OrganizationServiceClient<Channel>,
}

impl AuthGrpcClients {
    #[must_use]
    pub fn new(flow: Channel, organization: Channel) -> Self {
        Self {
            flow: FlowServiceClient::new(flow),
            organization: OrganizationServiceClient::new(organization),
        }
    }

    #[must_use]
    pub fn credential_verification(&self) -> GrpcCredentialVerificationStarter {
        GrpcCredentialVerificationStarter::new(self.flow.clone())
    }

    #[must_use]
    pub fn organization_provisioning(
        &self,
        default_organization_id: impl Into<String>,
    ) -> GrpcOrganizationProvisioning {
        GrpcOrganizationProvisioning::new(self.organization.clone(), default_organization_id)
    }
}

#[derive(Clone)]
pub struct GrpcCredentialVerificationStarter {
    client: FlowServiceClient<Channel>,
}

impl GrpcCredentialVerificationStarter {
    #[must_use]
    pub fn new(client: FlowServiceClient<Channel>) -> Self {
        Self { client }
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
            .start_verification(Request::new(credential_verification_request(request)))
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
}

impl GrpcOrganizationProvisioning {
    #[must_use]
    pub fn new(
        client: OrganizationServiceClient<Channel>,
        default_organization_id: impl Into<String>,
    ) -> Self {
        Self {
            client,
            default_organization_id: default_organization_id.into(),
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
            .add_member(Request::new(AddMemberRequest {
                organization_id: self.default_organization_id.clone(),
                user_id: user_id.into(),
                email: email.into(),
                role_ids: Vec::new(),
            }))
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
            .get_member(Request::new(GetMemberRequest {
                organization_id: self.default_organization_id.clone(),
                user_id: user_id.into(),
            }))
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
            .get_organization(Request::new(GetOrganizationRequest {
                organization_id: member.organization_id.clone(),
            }))
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
}

#[async_trait]
impl CanvasApplicantProfileProvisioner for MmfApplicantProfileProvisioner {
    async fn ensure_profile(&self, user: &AuthenticatedUser) -> Result<Option<String>, PortError> {
        let Some(organization_id) = user.organization_id.as_deref() else {
            return Ok(user.applicant_id.clone());
        };
        if user.user_id.trim().is_empty() || user.email.trim().is_empty() {
            return Ok(user.applicant_id.clone());
        }
        let body = serde_json::to_vec(&json!({
            "organization_id": organization_id,
            "email": user.email,
            "given_name": user.given_name,
            "family_name": user.family_name,
        }))
        .map_err(|error| transport_error("applicant_profile_request_invalid", error))?;
        let response = self
            .client
            .execute(OutboundHttpRequest {
                method: OutboundHttpMethod::Patch,
                url: format!("{}/v1/me/applicant-profile", self.service_url),
                headers: BTreeMap::from([
                    ("content-type".into(), "application/json".into()),
                    ("x-user-id".into(), user.user_id.clone()),
                    ("x-user-email".into(), user.email.clone()),
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
        let payload = response
            .json_object("applicant profile provisioning")
            .map_err(|error| transport_error("applicant_profile_response_invalid", error))?;
        Ok(payload
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .or_else(|| user.applicant_id.clone()))
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
        AuthEvent::SessionCreated { session_id, .. } => ("session_created", session_id, None),
        AuthEvent::UserLoggedOut { user_id, .. } => ("logout", user_id, None),
        AuthEvent::SessionRevoked { user_id, .. } => ("session_revoked", user_id, None),
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
