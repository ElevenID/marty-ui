"""Report conservative Rust package impact without changing CI execution."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections import defaultdict, deque
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / "rust"

# These are observed HTTP/deployment consumers, not a complete runtime graph.
# Keep the service fallback below until every service and its transitive inputs
# have an obligation owner. The paths document the source of each observation.
OBSERVED_NON_CARGO_CONSUMERS = {
    # Auth connects to these services at runtime. Their package changes can
    # affect Auth even though Cargo has no reverse dependency on them.
    "marty-flow": [
        {
            # Applicant submits approved applications to Flow's native webhook.
            "package": "marty-applicant",
            "evidence": "rust/services/applicant/src/main.rs",
            "binding": 'env_value("FLOW_SERVICE_URL", "http://flow:8011")',
            "runtime_marker": "Arc::new(HttpFlowProvider::new(flow_url, application_auth))",
            "request_evidence": "rust/services/applicant/src/providers.rs",
            "request_marker": '"{}/v1/flows/webhooks/application-approved"',
            "callsite_evidence": "rust/services/applicant/src/service.rs",
            "callsite_marker": ".issue(&application, &applicant, &reserved_claims, attempt_id)",
            "provider_evidence": "rust/services/flow/src/http_application.rs",
            "provider_marker": '"/v1/flows/webhooks/application-approved"',
            "route_registration_evidence": "rust/services/flow/src/http_read.rs",
            "route_registration_marker": ".merge(flow_application_routes())",
            "server_evidence": "rust/services/flow/src/main.rs",
            "server_marker": ".merge(flow_read_router(http_state))",
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_service": "flow",
            "deployment_marker": 'FLOW_SERVICE_PORT: "8011"',
            "deployment_consumer_service": "applicant",
            "deployment_consumer_marker": 'APPLICANT_SERVICE_PORT: "8006"',
            "deployment_consumer_absent_marker": "FLOW_SERVICE_URL:",
            "deployment_network_marker": "- marty-network",
        },
        {
            "package": "marty-auth",
            "evidence": "rust/services/auth/src/config.rs",
            "binding": "FLOW_GRPC_TARGET",
            "runtime_evidence": "rust/services/auth/src/connections.rs",
            "runtime_marker": "&config.flow_grpc_target",
        },
        {
            "package": "marty-gateway",
            "evidence": "rust/services/gateway/src/config.rs",
            "binding": "FLOW_SERVICE_URL",
            "runtime_evidence": "rust/services/gateway/src/contract.rs",
            "runtime_marker": '("/v1/flows", "flows")',
        },
    ],
    "marty-organization": [
        {
            # Device registration checks active membership over Organization gRPC
            # when a request is scoped to an organization.
            "package": "marty-device-registration",
            "evidence": "rust/services/device-registration/src/main.rs",
            "binding": 'env_value("ORG_GRPC_TARGET", "organization:9002")',
            "runtime_marker": "OrganizationMembershipClient::connect_lazy(",
            "registration_marker": "router(HttpState {",
            "request_evidence": "rust/services/device-registration/src/control_plane.rs",
            "connection_marker": "OrganizationServiceClient::new(endpoint.connect_lazy())",
            "request_marker": ".get_member(self.request(GetMemberRequest {",
            "response_marker": '!member.status.eq_ignore_ascii_case("active")',
            "callsite_evidence": "rust/services/device-registration/src/http.rs",
            "condition_marker": "if let Some(organization_id) = organization_id {",
            "callsite_marker": ".require_active(user_id, organization_id)",
            "provider_evidence": "rust/services/organization/src/grpc_service.rs",
            "provider_handler_marker": "async fn get_member(",
            "provider_marker": ".get_membership(&input.user_id, organization_id)",
            "provider_registration_evidence": "rust/services/organization/src/main.rs",
            "provider_registration_marker": "OrganizationServiceServer::new(grpc_service)",
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_service": "device-registration",
            "deployment_marker": "ORG_GRPC_TARGET: organization:9002",
        },
        {
            "package": "marty-compliance-profile",
            "evidence": "rust/services/compliance-profile/src/config.rs",
            "binding": '"ORG_GRPC_TARGET"',
            "runtime_evidence": "rust/services/compliance-profile/src/main.rs",
            "runtime_marker": "tenant_membership_provider(&c)?",
            "service_marker": "ComplianceService::new(repo, membership)",
            "request_evidence": "rust/services/compliance-profile/src/provider.rs",
            "target_marker": "c.organization_grpc_target.clone()",
            "connection_marker": "OrganizationServiceClient::new(ch)",
            "registration_marker": "GrpcTenantMembershipProvider::new(",
            "shared_request_evidence": "rust/services/flow/src/grpc_providers.rs",
            "request_marker": ".get_member(self.auth.request(GetMemberRequest {",
            "provider_evidence": "rust/services/organization/src/grpc_service.rs",
            "provider_marker": ".get_membership(&input.user_id, organization_id)",
        },
        {
            "package": "marty-deployment-profile",
            "evidence": "rust/services/deployment-profile/src/config.rs",
            "binding": 'value(&values, "ORG_GRPC_TARGET")',
            "runtime_evidence": "rust/services/deployment-profile/src/main.rs",
            "runtime_marker": "tenant_membership_provider(&config)?",
            "service_marker": "DeploymentService::new(repository, memberships)",
            "request_evidence": "rust/services/deployment-profile/src/provider.rs",
            "target_marker": "config.organization_grpc_target.clone()",
            "connection_marker": "OrganizationServiceClient::new(channel)",
            "registration_marker": "GrpcTenantMembershipProvider::new(client, config.service_token.as_deref())",
            "shared_request_evidence": "rust/services/flow/src/grpc_providers.rs",
            "request_marker": ".get_member(self.auth.request(GetMemberRequest {",
            "provider_evidence": "rust/services/organization/src/grpc_service.rs",
            "provider_marker": ".get_membership(&input.user_id, organization_id)",
        },
        {
            "package": "marty-revocation-profile",
            "evidence": "rust/services/revocation-profile/src/config.rs",
            "binding": 'required(values, "ORG_GRPC_TARGET")?',
            "runtime_evidence": "rust/services/revocation-profile/src/main.rs",
            "runtime_marker": "config.organization_grpc_target.clone()",
            "service_marker": "RevocationProfileHttp::new(service.clone(), Arc::new(authorization.clone()))",
            "request_evidence": "rust/services/revocation-profile/src/authorization.rs",
            "connection_marker": "OrganizationServiceClient::new(channel)",
            "request_marker": "client.get_member(request).await",
            "provider_evidence": "rust/services/organization/src/grpc_service.rs",
            "provider_marker": ".get_membership(&input.user_id, organization_id)",
        },
        {
            "package": "marty-presentation-policy",
            "evidence": "rust/services/presentation-policy/src/config.rs",
            "binding": 'value(&values, "ORG_GRPC_TARGET")',
            "runtime_evidence": "rust/services/presentation-policy/src/main.rs",
            "runtime_marker": "&config.organization_grpc_target",
            "service_marker": "PolicyApplication::new(repository, authorization)",
            "request_evidence": "rust/services/presentation-policy/src/control_plane.rs",
            "connection_marker": "OrganizationServiceClient::new(channel(organization_target, timeout)?)",
            "request_marker": "client.get_member(request).await",
            "provider_evidence": "rust/services/organization/src/grpc_service.rs",
            "provider_marker": ".get_membership(&input.user_id, organization_id)",
        },
        {
            # Issuance initiation validates the organization through a real
            # gRPC client; this is observed reachability, not safe selection.
            "package": "marty-issuance-service",
            "evidence": "rust/services/issuance/src/config.rs",
            "binding": "ORG_GRPC_TARGET",
            "runtime_evidence": "rust/services/issuance/src/main.rs",
            "runtime_marker": "&config.organization_grpc_target",
            "startup_marker": "NativeInitiationControlPlane::connect_lazy(",
            "ports_marker": "organizations: initiation_control_plane.clone()",
            "request_evidence": "rust/services/issuance/src/initiation_dependencies.rs",
            "connection_marker": "OrganizationServiceClient::new(channel(organization_target, timeout)?)",
            "request_marker": ".get_organization(self.grpc_request(GetOrganizationRequest {",
            "response_marker": "response.get_ref().id == organization_id",
            "provider_evidence": "rust/services/organization/src/grpc_service.rs",
            "provider_marker": ".get_organization(organization_id)",
        },
        {
            "package": "marty-verification-service",
            "evidence": "rust/services/verification/src/config.rs",
            "binding": 'value(&values, "ORG_GRPC_TARGET")',
            "runtime_evidence": "rust/services/verification/src/main.rs",
            "runtime_marker": "VerificationProviders::connect_lazy(&config.providers)?",
            "connection_evidence": "rust/services/verification/src/providers.rs",
            "connection_marker": "OrganizationServiceClient::new(organization)",
            "registration_marker": "tenant_membership: Some(membership.clone()),",
            "request_evidence": "rust/services/flow/src/grpc_providers.rs",
            "request_marker": ".get_member(self.auth.request(GetMemberRequest {",
            "provider_evidence": "rust/services/organization/src/grpc_service.rs",
            "provider_marker": ".get_membership(&input.user_id, organization_id)",
        },
        {
            "package": "marty-credential-template",
            "evidence": "rust/services/credential-template/src/config.rs",
            "binding": 'target(&values, "ORG_GRPC_TARGET", "organization:9002")?',
            "runtime_evidence": "rust/services/credential-template/src/main.rs",
            "runtime_marker": "&config.organization_grpc_target",
            "startup_marker": "NativeCredentialTemplateControlPlane::connect_lazy(",
            "request_evidence": "rust/services/credential-template/src/control_plane.rs",
            "connection_marker": "OrganizationServiceClient::new(channel(organization_target, timeout)?)",
            "request_marker": "client.get_organization(request).await",
            "membership_marker": "client.get_member(request).await",
            "identity_marker": "response.id != organization_id",
            "provider_evidence": "rust/services/organization/src/grpc_service.rs",
            "provider_marker": ".get_organization(organization_id)",
        },
        {
            "package": "marty-auth",
            "evidence": "rust/services/auth/src/config.rs",
            "binding": "ORG_GRPC_TARGET",
            "runtime_evidence": "rust/services/auth/src/connections.rs",
            "runtime_marker": "&config.organization_grpc_target",
        },
        {
            "package": "marty-trust-profile",
            "evidence": "rust/services/trust-profile/src/config.rs",
            "binding": "ORG_GRPC_TARGET",
            "runtime_evidence": "rust/services/trust-profile/src/main.rs",
            "runtime_marker": "&config.organization_grpc_target",
        },
        {
            "package": "marty-flow",
            "evidence": "rust/services/flow/src/config.rs",
            "binding": "ORGANIZATION_GRPC_TARGET",
            "runtime_evidence": "rust/services/flow/src/grpc_providers.rs",
            "runtime_marker": "&config.organization_grpc_target",
            "connection_marker": "self.organization.connect()",
            "startup_evidence": "rust/services/flow/src/connections.rs",
            "startup_marker": "FlowGrpcChannelFactories::from_config(config)?",
            "request_evidence": "rust/services/flow/src/grpc_providers.rs",
            "request_marker": ".get_member(self.auth.request(GetMemberRequest {",
            "callsite_evidence": "rust/services/flow/src/providers.rs",
            "callsite_marker": ".membership(principal_id, organization_id)",
            "identity_marker": "response.user_id.is_empty() || response.organization_id.is_empty()",
            "provider_evidence": "rust/services/organization/src/grpc_service.rs",
            "provider_marker": ".get_membership(&input.user_id, organization_id)",
        },
    ],
    "marty-credential-template": [
        {
            "package": "marty-issuance-service",
            "evidence": "rust/services/issuance/src/config.rs",
            "binding": "CT_GRPC_TARGET",
            "runtime_evidence": "rust/services/issuance/src/main.rs",
            "runtime_marker": "&config.credential_template_grpc_target",
            "startup_marker": "NativeInitiationControlPlane::connect_lazy(",
            "ports_marker": "templates: initiation_control_plane.clone()",
            "request_evidence": "rust/services/issuance/src/initiation_dependencies.rs",
            "connection_marker": "templates: CredentialTemplateServiceClient::new(channel(",
            "request_marker": ".get_template(self.grpc_request(GetTemplateRequest {",
            "response_marker": "template_from_grpc(template_id, response.into_inner())",
            "fallback_marker": "self.resolve_template_http(template_id).await",
            "provider_evidence": "rust/services/credential-template/src/grpc_service.rs",
            "provider_marker": ".get_template_for_internal_service(&request.get_ref().template_id)",
        },
        {
            "package": "marty-verification-service",
            "evidence": "rust/services/verification/src/config.rs",
            "binding": 'value(&values, "CT_GRPC_TARGET")',
            "runtime_evidence": "rust/services/verification/src/main.rs",
            "runtime_marker": "VerificationProviders::connect_lazy(&config.providers)?",
            "connection_evidence": "rust/services/verification/src/providers.rs",
            "connection_marker": "CredentialTemplateServiceClient::new(credential_template)",
            "registration_marker": "credential_template: Some(templates),",
            "request_evidence": "rust/services/flow/src/grpc_providers.rs",
            "request_marker": ".get_template(self.auth.request(GetTemplateRequest {",
            "provider_evidence": "rust/services/credential-template/src/grpc_service.rs",
            "provider_marker": ".get_template_for_internal_service(&request.get_ref().template_id)",
        },
        {
            "package": "marty-flow",
            "evidence": "rust/services/flow/src/config.rs",
            "binding": "CT_GRPC_TARGET",
            "runtime_evidence": "rust/services/flow/src/grpc_providers.rs",
            "runtime_marker": "&config.credential_template_grpc_target",
            "request_evidence": "rust/services/flow/src/grpc_providers.rs",
            "request_marker": ".get_template(self.auth.request(GetTemplateRequest {",
            "callsite_evidence": "rust/services/flow/src/reference_validation.rs",
            "callsite_marker": "templates.get_template(template_id).await?",
            "provider_evidence": "rust/services/credential-template/src/grpc_service.rs",
            "provider_marker": ".get_template_for_internal_service(&request.get_ref().template_id)",
            "http_binding": '"CREDENTIAL_TEMPLATE_SERVICE_URL"',
            "http_startup_evidence": "rust/services/flow/src/connections.rs",
            "http_startup_marker": "&config.credential_template_url,",
            "http_request_evidence": "rust/services/flow/src/http_providers.rs",
            "http_request_marker": '"v1/delivery-destinations/{encoded}"',
            "http_response_marker": "if response.id != reference_id {",
            "http_callsite_evidence": "rust/services/flow/src/reference_validation.rs",
            "http_callsite_marker": ".resolve(kind, reference_id, principal_id, organization_id)",
            "http_provider_evidence": "rust/services/credential-template/src/http_service.rs",
            "http_provider_marker": '"/v1/delivery-destinations/{destination_id}"',
        },
    ],
    "marty-revocation-profile": [
        {
            "package": "marty-issuance-service",
            "evidence": "rust/services/issuance/src/config.rs",
            "binding": "RP_GRPC_TARGET",
            "runtime_evidence": "rust/services/issuance/src/main.rs",
            "runtime_marker": "&config.revocation_profile_grpc_target",
            "startup_marker": "NativeInitiationControlPlane::connect_lazy(",
            "ports_marker": "revocation_profiles: initiation_control_plane,",
            "request_evidence": "rust/services/issuance/src/initiation_dependencies.rs",
            "connection_marker": "revocation_profiles: RevocationProfileServiceClient::new(channel(",
            "request_marker": ".get_revocation_profile(self.grpc_request(GetRevocationProfileRequest {",
            "identity_marker": "profile.organization_id != organization_id",
            "status_marker": 'profile.status.trim().eq_ignore_ascii_case("active")',
            "provider_evidence": "rust/services/revocation-profile/src/grpc.rs",
            "provider_marker": ".get(&request.into_inner().profile_id)",
        },
        {
            "package": "marty-credential-template",
            "evidence": "rust/services/credential-template/src/config.rs",
            "binding": 'target(&values, "RP_GRPC_TARGET", "revocation-profile:9013")?',
            "runtime_evidence": "rust/services/credential-template/src/main.rs",
            "runtime_marker": "&config.revocation_grpc_target",
            "startup_marker": "NativeCredentialTemplateControlPlane::connect_lazy(",
            "request_evidence": "rust/services/credential-template/src/control_plane.rs",
            "connection_marker": "RevocationProfileServiceClient::new(channel(revocation_target, timeout)?)",
            "request_marker": "client.get_revocation_profile(request).await",
            "identity_marker": "profile.organization_id != organization_id",
            "status_marker": '!profile.status.eq_ignore_ascii_case("active")',
            "provider_evidence": "rust/services/revocation-profile/src/grpc.rs",
            "provider_marker": ".get(&request.into_inner().profile_id)",
        },
    ],
    "marty-applicant": [
        {
            "package": "marty-auth",
            "evidence": "rust/services/auth/src/config.rs",
            "binding": "APPLICANT_SERVICE_URL",
            "runtime_evidence": "rust/services/auth/src/main.rs",
            "runtime_marker": "config.applicant_service_url.clone()",
        },
    ],
    "marty-issuance-service": [
        {
            # Applicant resolves application templates from native Issuance
            # over HTTP; it has no Cargo dependency on the provider.
            "package": "marty-applicant",
            "evidence": "rust/services/applicant/src/main.rs",
            "binding": 'env::var("ISSUANCE_NATIVE_SERVICE_URL").ok()',
            "runtime_marker": "HttpTemplateProvider::new(",
            "request_evidence": "rust/services/applicant/src/providers.rs",
            "request_call_marker": ".get(format!(",
            "request_marker": '"{}/v1/application-templates/{id}"',
            "provider_evidence": "rust/services/issuance/src/application_template_http.rs",
            "provider_marker": '"/v1/application-templates/{template_id}"',
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_marker": "ISSUANCE_NATIVE_SERVICE_URL: http://issuance-native:8005",
        },
        {
            # The base runtime's Presentation Policy resolver looks up
            # credential status at the native Issuance HTTP endpoint.
            "package": "marty-presentation-policy",
            "evidence": "rust/services/presentation-policy/src/config.rs",
            "binding": 'value(&values, "ISSUANCE_NATIVE_SERVICE_URL")',
            "status_marker": "{issuance_url}/v1/issuance/credentials/{{credential_id}}/status",
            "runtime_evidence": "rust/services/presentation-policy/src/main.rs",
            "runtime_marker": "&config.credential_status_url_template,",
            "request_evidence": "rust/services/presentation-policy/src/control_plane.rs",
            "request_marker": "self.http.get(endpoint)",
            "provider_evidence": "rust/services/issuance/src/http.rs",
            "provider_marker": '"/v1/issuance/credentials/{credential_id}/status"',
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_marker": "ISSUANCE_NATIVE_SERVICE_URL: http://issuance-native:8005",
        },
        {
            "package": "marty-auth",
            "evidence": "rust/services/auth/src/config.rs",
            "binding": "ISSUANCE_NATIVE_SERVICE_URL",
            "runtime_evidence": "rust/services/auth/src/main.rs",
            "runtime_marker": "&config.issuance_native_service_url",
        },
        {
            "package": "marty-flow",
            "evidence": "rust/services/flow/src/config.rs",
            "binding": "ISSUANCE_GRPC_TARGET",
            "runtime_evidence": "rust/services/flow/src/grpc_providers.rs",
            "runtime_marker": "&config.issuance_grpc_target",
            "connection_marker": "self.issuance.connect()",
            "startup_evidence": "rust/services/flow/src/connections.rs",
            "startup_marker": "FlowGrpcChannelFactories::from_config(config)?",
            "request_evidence": "rust/services/flow/src/grpc_providers.rs",
            "request_marker": ".initiate_issuance(self.auth.request(ProtoIssuance {",
            "callsite_evidence": "rust/services/flow/src/instance_side_effects.rs",
            "callsite_marker": ".initiate(&IssuanceInitiationRequest {",
            "identity_marker": "response.credential_template_id != request.credential_template_id",
            "provider_evidence": "rust/services/issuance/src/credential_management_grpc.rs",
            "provider_marker": ".initiate(&request.request, idempotency_key)",
            # The native URL may resolve to the legacy HTTP owner in production;
            # this is only observed reachability, not an active selector.
            "http_binding": '"ISSUANCE_NATIVE_SERVICE_URL"',
            "http_startup_evidence": "rust/services/flow/src/connections.rs",
            "http_startup_marker": "&config.issuance_native_url,",
            "http_request_evidence": "rust/services/flow/src/http_providers.rs",
            "http_request_marker": '"v1/application-templates/{encoded}"',
            "http_response_marker": "if response.id != reference_id {",
            "http_callsite_evidence": "rust/services/flow/src/reference_validation.rs",
            "http_callsite_marker": ".resolve(kind, reference_id, principal_id, organization_id)",
            "http_provider_evidence": "rust/services/issuance/src/application_template_http.rs",
            "http_provider_marker": '"/v1/application-templates/{template_id}"',
        },
    ],
    "marty-notification": [
        {
            "package": "marty-applicant",
            "evidence": "rust/services/applicant/src/main.rs",
            "binding": "NOTIFICATION_EVENT_INGEST_URL",
            "runtime_evidence": "rust/services/applicant/src/providers.rs",
            "runtime_marker": ".post(url)",
        },
        {
            "package": "marty-gateway",
            "evidence": "rust/services/gateway/src/config.rs",
            "binding": "NOTIFICATION_SERVICE_URL",
            "runtime_evidence": "rust/services/gateway/src/contract.rs",
            "runtime_marker": '("/v1/notifications", "notifications")',
        },
        {
            "package": "marty-selfhost-bundle",
            "evidence": "rust/crates/selfhost-bundle/tests/support/resolved_selfhost_runtime.rs",
            "binding": "NOTIFICATION_SERVICE_URL",
        },
    ],
    "marty-event-stream": [
        # Auth and Organization publish through independent generated gRPC
        # clients. These source edges are not proof of test execution.
        {
            "package": "marty-auth",
            "evidence": "rust/services/auth/src/config.rs",
            "binding": 'get("ES_GRPC_TARGET").unwrap_or("event-stream:9015")',
            "runtime_evidence": "rust/services/auth/src/connections.rs",
            "runtime_marker": "workload_channel_factory(&config.event_stream_grpc_target, None)?",
            "connection_marker": "EventStreamServiceClient::new(event_channel)",
            "startup_evidence": "rust/services/auth/src/main.rs",
            "startup_marker": "connections.event_transport.clone() as Arc<dyn MessageTransport>",
            "request_evidence": "rust/services/auth/src/event_transport.rs",
            "request_marker": ".publish(Request::new(PublishEventRequest { event: Some(event) }))",
            "response_marker": "if response.success {",
            "provider_evidence": "rust/services/event-stream/src/grpc.rs",
            "provider_marker": "async fn publish(",
            "server_evidence": "rust/services/event-stream/src/main.rs",
            "server_marker": "EventStreamServiceServer::new(grpc_service)",
            "condition_evidence": "rust/services/event-stream/src/config.rs",
            "condition_marker": 'parse_bool("EVENT_STREAM_GRPC_ENABLED", true)?',
        },
        {
            "package": "marty-organization",
            "evidence": "rust/services/organization/src/config.rs",
            "binding": 'value(&values, "ES_GRPC_TARGET")',
            "runtime_evidence": "rust/services/organization/src/main.rs",
            "runtime_marker": "EventStreamTransport::new(",
            "connection_marker": "event_transport.connect().await",
            "startup_evidence": "rust/services/organization/src/main.rs",
            "startup_marker": "event_transport as Arc<dyn MessageTransport>",
            "request_evidence": "rust/services/organization/src/event_stream_transport.rs",
            "request_marker": "client.publish(PublishEventRequest { event: Some(event) })",
            "response_marker": "if response.success {",
            "provider_evidence": "rust/services/event-stream/src/grpc.rs",
            "provider_marker": "async fn publish(",
            "server_evidence": "rust/services/event-stream/src/main.rs",
            "server_marker": "EventStreamServiceServer::new(grpc_service)",
            "condition_evidence": "rust/services/event-stream/src/config.rs",
            "condition_marker": 'parse_bool("EVENT_STREAM_GRPC_ENABLED", true)?',
        },
        {
            "package": "marty-gateway",
            "evidence": "rust/services/gateway/src/config.rs",
            "binding": '"ES_GRPC_TARGET", "event-stream:9015"',
            "runtime_evidence": "rust/services/gateway/src/main.rs",
            "runtime_marker": "grpc_channel(&config, &config.event_stream_grpc_target)?",
            "request_evidence": "rust/services/gateway/src/providers.rs",
            "request_marker": ".subscribe(request)",
            "callsite_evidence": "rust/services/gateway/src/runtime.rs",
            "route_marker": 'request.uri().path() == "/v1/notifications/events/push"',
            "callsite_marker": "provider.subscribe(subscription).await",
            "provider_evidence": "rust/services/event-stream/src/grpc.rs",
            "provider_marker": "async fn subscribe(",
            "server_evidence": "rust/services/event-stream/src/main.rs",
            "server_marker": "EventStreamServiceServer::new(grpc_service)",
            "condition_evidence": "rust/services/event-stream/src/config.rs",
            "condition_marker": 'parse_bool("EVENT_STREAM_GRPC_ENABLED", true)?',
        },
    ],
    "marty-trust-profile": [
        {
            "package": "marty-flow",
            "evidence": "rust/services/flow/src/config.rs",
            "binding": '"TRUST_PROFILE_SERVICE_URL"',
            "runtime_evidence": "rust/services/flow/src/connections.rs",
            "runtime_marker": "&config.trust_profile_url,",
            "request_evidence": "rust/services/flow/src/http_providers.rs",
            "request_marker": '"v1/trust-profiles/{encoded}"',
            "response_marker": "if response.id != reference_id {",
            "callsite_evidence": "rust/services/flow/src/reference_validation.rs",
            "callsite_marker": ".resolve(kind, reference_id, principal_id, organization_id)",
            "provider_evidence": "rust/services/trust-profile/src/http_service.rs",
            "provider_marker": '"/v1/trust-profiles/{profile_id}"',
        },
        {
            "package": "marty-credential-template",
            "evidence": "rust/services/credential-template/src/config.rs",
            "binding": '"TRUST_PROFILE_SERVICE_URL"',
            "runtime_evidence": "rust/services/credential-template/src/main.rs",
            "runtime_marker": "config.trust_profile_service_url.clone()",
            "request_evidence": "rust/services/credential-template/src/control_plane.rs",
            "request_marker": '"{}/internal/v1/trust-profiles/{profile_id}"',
            "response_marker": "response.status() == StatusCode::NOT_FOUND",
            "provider_evidence": "rust/services/trust-profile/src/http_service.rs",
            "provider_marker": '"/internal/v1/trust-profiles/{profile_id}"',
        },
        {
            "package": "marty-presentation-policy",
            "evidence": "rust/services/presentation-policy/src/config.rs",
            "binding": "TRUST_PROFILE_SERVICE_URL",
            "runtime_evidence": "rust/services/presentation-policy/src/main.rs",
            "runtime_marker": "&config.trust_profile_url",
            "request_evidence": "rust/services/presentation-policy/src/control_plane.rs",
            "request_marker": '"{}/internal/v1/trust-profiles/{profile_id}"',
            "identity_marker": "returned_id != profile_id || returned_organization != organization_id",
        },
    ],
    "marty-deployment-profile": [
        {
            "package": "marty-flow",
            "evidence": "rust/services/flow/src/config.rs",
            "binding": '"DEPLOYMENT_PROFILE_SERVICE_URL"',
            "runtime_evidence": "rust/services/flow/src/connections.rs",
            "runtime_marker": "&config.deployment_profile_url,",
            "request_evidence": "rust/services/flow/src/http_providers.rs",
            "request_marker": '"v1/deployment-profiles/{encoded}"',
            "response_marker": "if response.id != reference_id {",
            "callsite_evidence": "rust/services/flow/src/reference_validation.rs",
            "callsite_marker": ".resolve(kind, reference_id, principal_id, organization_id)",
            "provider_evidence": "rust/services/deployment-profile/src/http.rs",
            "provider_marker": '"/v1/deployment-profiles/{profile_id}"',
        },
    ],
    "marty-signing-keys": [
        {
            # Issuance resolves its issuer identity through the configured
            # signing-keys URL, normally Gateway's authenticated compat route.
            "package": "marty-issuance-service",
            "evidence": "rust/services/issuance/src/config.rs",
            "binding": '"SIGNING_KEYS_INTERNAL_URL"',
            "default_marker": '"signing_keys_internal_url": "http://gateway:8000/internal/signing-keys"',
            "runtime_evidence": "rust/services/issuance/src/main.rs",
            "runtime_marker": "Arc::new(HttpIssuerContextResolver::new(",
            "request_evidence": "rust/services/issuance/src/credential_issuer.rs",
            "request_marker": '"{}/resolve-issuer-did",',
            "response_marker": 'context.get("ok").and_then(Value::as_bool) != Some(true)',
            "gateway_evidence": "rust/services/gateway/src/runtime.rs",
            "gateway_route_marker": 'if request.uri().path().starts_with("/internal/signing-keys") {',
            "gateway_classification_evidence": "rust/services/gateway/src/signing_compat.rs",
            "gateway_classification_marker": '(HttpMethod::Get, "resolve-issuer-did") => {\n            Some(SigningCompatibilityOperation::ResolveIssuerDid)',
            "gateway_dispatch_marker": "if operation == SigningCompatibilityOperation::ResolveIssuerDid {",
            "gateway_marker": 'forward_signing_compatibility_json(state, "/internal/compat/resolve-issuer-did", body).await',
            "provider_evidence": "rust/services/signing-keys/src/http.rs",
            "provider_marker": '"/internal/compat/resolve-issuer-did",',
            "provider_handler_marker": "async fn resolve_issuer_did(",
        },
        {
            "package": "marty-credential-template",
            "evidence": "rust/services/credential-template/src/config.rs",
            "binding": '"SIGNING_KEYS_INTERNAL_URL",',
            "default_marker": '"http://gateway:8000/internal/signing-keys",',
            "runtime_evidence": "rust/services/credential-template/src/main.rs",
            "runtime_marker": "config.signing_keys_internal_url.clone(),",
            "service_marker": "NativeCredentialTemplateControlPlane::connect_lazy(",
            "request_evidence": "rust/services/credential-template/src/control_plane.rs",
            "request_marker": '"{}/resolve-issuer-did",',
            "response_marker": "signing-keys issuer resolution returned {status}",
            "gateway_evidence": "rust/services/gateway/src/runtime.rs",
            "gateway_route_marker": 'if request.uri().path().starts_with("/internal/signing-keys") {',
            "gateway_classification_evidence": "rust/services/gateway/src/signing_compat.rs",
            "gateway_classification_marker": '(HttpMethod::Get, "resolve-issuer-did") => {\n            Some(SigningCompatibilityOperation::ResolveIssuerDid)',
            "gateway_dispatch_marker": "if operation == SigningCompatibilityOperation::ResolveIssuerDid {",
            "gateway_marker": 'forward_signing_compatibility_json(state, "/internal/compat/resolve-issuer-did", body).await',
            "provider_evidence": "rust/services/signing-keys/src/http.rs",
            "provider_marker": '"/internal/compat/resolve-issuer-did",',
            "provider_handler_marker": "async fn resolve_issuer_did(",
        },
        {
            # The Credentials compatibility resolver is conditional, and it
            # can fall back to a public DID under governance policy.
            "package": "marty-verification-service",
            "evidence": "rust/services/verification/src/config.rs",
            "binding": 'value(&values, "SIGNING_KEYS_INTERNAL_URL")',
            "default_marker": '"http://gateway:8000/internal/signing-keys"',
            "runtime_evidence": "rust/services/verification/src/main.rs",
            "conditional_marker": "if config.credentials_compat_enabled {",
            "runtime_marker": "OrganizationIssuerKeyResolver::new(",
            "request_evidence": "rust/services/verification/src/credentials_compat/resolver.rs",
            "request_marker": '.get(format!("{}/resolve-issuer-did", self.base_url))',
            "fallback_marker": "allow_public_did_fallback()",
            "gateway_evidence": "rust/services/gateway/src/runtime.rs",
            "gateway_route_marker": 'if request.uri().path().starts_with("/internal/signing-keys") {',
            "gateway_classification_evidence": "rust/services/gateway/src/signing_compat.rs",
            "gateway_classification_marker": '(HttpMethod::Get, "resolve-issuer-did") => {\n            Some(SigningCompatibilityOperation::ResolveIssuerDid)',
            "gateway_dispatch_marker": "if operation == SigningCompatibilityOperation::ResolveIssuerDid {",
            "gateway_marker": 'forward_signing_compatibility_json(state, "/internal/compat/resolve-issuer-did", body).await',
            "provider_evidence": "rust/services/signing-keys/src/http.rs",
            "provider_marker": '"/internal/compat/resolve-issuer-did",',
            "provider_handler_marker": "async fn resolve_issuer_did(",
        },
        # Flow's request-object signer and HAIP response-key envelope use the
        # same authenticated Signing Keys HTTP provider. This is source-backed
        # reachability, not proof that all service obligations are mapped.
        {
            "package": "marty-flow",
            "evidence": "rust/services/flow/src/config.rs",
            "binding": '"SIGNING_KEYS_INTERNAL_URL"',
            "runtime_evidence": "rust/services/flow/src/connections.rs",
            "runtime_marker": "HttpSigningProvider::new(",
            "startup_marker": "signing.health_check().await?;",
            "signing_registration_marker": "signing_identity: Some(signing.clone()),",
            "envelope_registration_marker": "flow_key_envelope: Some(signing),",
            "request_evidence": "rust/services/flow/src/http_providers.rs",
            "request_marker": '"resolve-issuer-did",',
            "sign_marker": '"issuer-dids/sign",',
            "response_marker": "result.validate_binding(request)?;",
            "wrap_marker": '"flow-key-envelopes/wrap",',
            "unwrap_marker": '"flow-key-envelopes/unwrap",',
            "callsite_evidence": "rust/services/flow/src/request_object.rs",
            "callsite_marker": "let compact_jwt = sign_payload(",
            "envelope_callsite_marker": "response_encryption_key(providers, &instance).await?",
            "callback_evidence": "rust/services/flow/src/verification_submission.rs",
            "callback_marker": ".unwrap(&FlowKeyEnvelope {",
            "provider_evidence": "rust/services/signing-keys/src/http.rs",
            "provider_marker": '"/internal/compat/issuer-dids/sign"',
            "provider_handler_marker": "async fn issuer_did_sign(",
            "provider_wrap_marker": '"/internal/flow-key-envelopes/wrap"',
            "provider_wrap_handler_marker": "async fn wrap_flow_key(",
            "provider_unwrap_marker": '"/internal/flow-key-envelopes/unwrap"',
            "provider_unwrap_handler_marker": "async fn unwrap_flow_key(",
        },
    ],
    "marty-presentation-policy": [
        {
            "package": "marty-verification-service",
            "evidence": "rust/services/verification/src/config.rs",
            "binding": 'value(&values, "PP_GRPC_TARGET")',
            "runtime_evidence": "rust/services/verification/src/main.rs",
            "runtime_marker": "VerificationProviders::connect_lazy(&config.providers)?",
            "connection_evidence": "rust/services/verification/src/providers.rs",
            "connection_marker": "PresentationPolicyServiceClient::new(presentation_policy)",
            "registration_marker": "presentation_policy: Some(policies),",
            "evaluation_marker": ".evaluate_presentation(",
            "identity_marker": "response.policy_id != request.policy_id || response.nonce != request.nonce",
            "request_evidence": "rust/services/flow/src/grpc_providers.rs",
            "request_marker": ".get_policy(self.auth.request(GetPolicyRequest {",
            "provider_evidence": "rust/services/presentation-policy/src/grpc_service.rs",
            "provider_marker": ".get_for_internal_service(parse_uuid(&request.get_ref().policy_id)?)",
        },
        {
            "package": "marty-flow",
            "evidence": "rust/services/flow/src/config.rs",
            "binding": "PP_GRPC_TARGET",
            "runtime_evidence": "rust/services/flow/src/grpc_providers.rs",
            "runtime_marker": "&config.presentation_policy_grpc_target",
            "connection_marker": "self.presentation_policy.connect()",
            "startup_evidence": "rust/services/flow/src/connections.rs",
            "startup_marker": "FlowGrpcChannelFactories::from_config(config)?",
            "request_evidence": "rust/services/flow/src/grpc_providers.rs",
            "request_marker": ".get_policy(self.auth.request(GetPolicyRequest {",
            "evaluation_request_marker": ".evaluate_presentation(",
            "callsite_evidence": "rust/services/flow/src/reference_validation.rs",
            "callsite_marker": "policies.get_policy(policy_id).await?",
            "identity_marker": "response.id != policy_id || response.organization_id.trim().is_empty()",
            "evaluation_identity_marker": "response.policy_id != request.policy_id || response.nonce != request.nonce",
            "provider_evidence": "rust/services/presentation-policy/src/grpc_service.rs",
            "provider_marker": ".get_for_internal_service(parse_uuid(&request.get_ref().policy_id)?)",
        },
    ],
}

# Each row has an actual declared public route with this upstream owner, not
# merely a configured URL. Flow and Notification already have explicit edges
# above; Deployment Profile is a direct Gateway Cargo dependency. Conditional
# issuance-native/provider-ingress selectors are excluded.
GATEWAY_PUBLIC_ROUTE_CONSUMERS = {
    # producer: (configuration binding, published route, ownership rule)
    "marty-auth": ("AUTH_SERVICE_URL", "/v1/auth/{path:path}", '("/v1/auth", "auth")'),
    "marty-organization": (
        "ORGANIZATION_SERVICE_URL",
        "/v1/organizations",
        '("/v1/organizations", "organizations")',
    ),
    "marty-credential-template": (
        "CREDENTIAL_TEMPLATE_SERVICE_URL",
        "/v1/credential-templates",
        '("/v1/credential-templates", "credential-templates")',
    ),
    "marty-trust-profile": (
        "TRUST_PROFILE_SERVICE_URL",
        "/v1/trust-profiles",
        '("/v1/trust-profiles", "trust-profiles")',
    ),
    "marty-issuance-service": (
        "ISSUANCE_SERVICE_URL",
        "/v1/issuance",
        '("/v1/issuance", "issuance")',
    ),
    "marty-applicant": (
        "APPLICANT_SERVICE_URL",
        "/v1/me/applicant-profile",
        '("/v1/me", "applicant")',
    ),
    "marty-compliance-profile": (
        "COMPLIANCE_PROFILE_SERVICE_URL",
        "/v1/compliance-profiles",
        '("/v1/compliance-profiles", "compliance-profiles")',
    ),
    "marty-presentation-policy": (
        "PRESENTATION_POLICY_SERVICE_URL",
        "/v1/presentation-policies",
        '("/v1/presentation-policies", "presentation-policies")',
    ),
    "marty-verification-service": (
        "VERIFICATION_SERVICE_URL",
        "/v1/verify",
        '("/v1/verify", "verification")',
    ),
    "marty-revocation-profile": (
        "REVOCATION_PROFILE_SERVICE_URL",
        "/v1/revocation-profiles",
        '("/v1/revocation-profiles", "revocation-profiles")',
    ),
    "marty-device-registration": (
        "DEVICE_REGISTRATION_SERVICE_URL",
        "/v1/devices",
        '("/v1/devices", "device-registration")',
    ),
    "marty-signing-keys": (
        "SIGNING_KEYS_SERVICE_URL",
        "/v1/signing-keys",
        '("/v1/signing-keys", "signing-keys")',
    ),
}
for producer, (
    binding,
    route_path,
    runtime_marker,
) in GATEWAY_PUBLIC_ROUTE_CONSUMERS.items():
    OBSERVED_NON_CARGO_CONSUMERS.setdefault(producer, []).append(
        {
            "package": "marty-gateway",
            "evidence": "rust/services/gateway/src/config.rs",
            "binding": binding,
            "runtime_evidence": "rust/services/gateway/src/contract.rs",
            "runtime_marker": runtime_marker,
            "route_contract": "contracts/gateway-routes.json",
            "route_path": route_path,
            "dispatch_evidence": "rust/services/gateway/src/main.rs",
            "dispatch_marker": "StaticServiceRegistry::from_urls(&config.service_urls)?",
        }
    )
# Organization also supplies Gateway tenant membership through gRPC. Enrich
# its existing published-HTTP edge instead of duplicating the same consumer.
next(
    edge
    for edge in OBSERVED_NON_CARGO_CONSUMERS["marty-organization"]
    if edge["package"] == "marty-gateway"
).update(
    {
        "grpc_binding": 'grpc_target(values, "ORG_GRPC_TARGET", "organization:9002")?',
        "grpc_runtime_evidence": "rust/services/gateway/src/main.rs",
        "grpc_runtime_marker": "grpc_channel(&config, &config.organization_grpc_target)?",
        "grpc_registration_marker": "let memberships: Arc<dyn OrganizationMembershipProvider> = identity_provider;",
        "grpc_request_evidence": "rust/services/gateway/src/providers.rs",
        "grpc_connection_marker": "OrganizationServiceClient::new(organizations)",
        "grpc_request_marker": "self.organizations.lock().await.get_member(request).await",
        "grpc_provider_evidence": "rust/services/organization/src/grpc_service.rs",
        "grpc_provider_marker": ".get_membership(&input.user_id, organization_id)",
    }
)

# Flow's callback worker sends to Auth's internal credential-verification route
# only when its callback secret and allowlisted destination are configured.
# This is separate from Gateway's public Auth proxy edge above.
OBSERVED_NON_CARGO_CONSUMERS["marty-auth"].append(
    {
        "package": "marty-flow",
        "auth_request_evidence": "rust/services/auth/src/credential_http.rs",
        "auth_url_marker": '"{}/internal/v1/auth/credential-verified?nonce={nonce}"',
        "auth_request_marker": "callback_url: self.config.callback_url(&nonce),",
        "evidence": "rust/services/flow/src/config.rs",
        "binding": 'value(&values, "FLOW_CALLBACK_DESTINATIONS")',
        "grpc_evidence": "rust/services/flow/src/grpc_service.rs",
        "grpc_marker": "callback_url: nonempty(input.callback_url),",
        "runtime_evidence": "rust/services/flow/src/main.rs",
        "conditional_marker": "let callback_worker = callback_secret.map(|secret| {",
        "runtime_marker": "tokio::spawn(run_callback_dispatcher(",
        "selection_evidence": "rust/services/flow/src/verification_start.rs",
        "selection_marker": ".require(&request.organization_id, callback_url)",
        "submission_evidence": "rust/services/flow/src/verification_submission.rs",
        "submission_context_marker": '.get("callback_url")',
        "submission_secret_marker": ".callback_secret",
        "submission_event_marker": "CallbackEvent::new_with_retention(",
        "submission_outbox_marker": ".map(|event| event.into_outbox_message_with_max_attempts(options.callback_max_attempts))",
        "outbox_evidence": "rust/services/flow/src/callback.rs",
        "outbox_marker": "reply_to: Some(self.destination_url)",
        "delivery_evidence": "rust/services/flow/src/callback_delivery.rs",
        "delivery_marker": ".post(&callback.destination_url)",
        "provider_evidence": "rust/services/auth/src/http_service.rs",
        "provider_marker": '"/internal/v1/auth/credential-verified"',
        "provider_registration_marker": "post(credential_verified),",
        "deployment_evidence": "docker-compose.base.yml",
        "deployment_service": "flow",
        "deployment_auth_base_marker": "AUTH_SERVICE_INTERNAL_URL: ${AUTH_SERVICE_INTERNAL_URL:-http://auth:8001}",
        "deployment_secret_marker": "FLOW_WEBHOOK_SECRET:",
        "deployment_binding_marker": "FLOW_CALLBACK_DESTINATIONS:",
        "deployment_marker": "http://auth:8001/internal/v1/auth/credential-verified?nonce=__MARTY_TOKEN__",
    }
)


def changed_paths(base: str, head: str) -> list[str]:
    # Both move endpoints matter, including a deleted package that metadata no
    # longer describes. NUL delimiters preserve whitespace and Unicode names.
    result = subprocess.run(
        ["git", "diff", "--name-only", "-z", "--no-renames", base, head, "--"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [path.decode("utf-8") for path in result.stdout.split(b"\0") if path]


def cargo_metadata() -> dict:
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--offline",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            str(RUST / "Cargo.toml"),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return json.loads(result.stdout)


def plan(paths: list[str], metadata: dict, root: Path = ROOT) -> dict:
    members = set(metadata["workspace_members"])
    packages = [package for package in metadata["packages"] if package["id"] in members]
    if not packages:
        raise ValueError("Cargo metadata contains no workspace packages")
    names = {package["name"] for package in packages}
    roots = {
        package["name"]: PurePosixPath(
            Path(package["manifest_path"]).parent.relative_to(root).as_posix()
        )
        for package in packages
    }

    def full(reason: str, *, observed_consumers: list[dict] | None = None) -> dict:
        result = {"all": True, "packages": sorted(names), "reason": reason}
        if observed_consumers:
            result["observed_non_cargo_consumers"] = observed_consumers
        return result

    direct: set[str] = set()
    for raw in paths:
        path = PurePosixPath(raw.replace("\\", "/"))
        if path == PurePosixPath("rust/Cargo.toml") or path == PurePosixPath(
            "rust/Cargo.lock"
        ):
            return full(f"workspace manifest or lock: {path}")
        if path == PurePosixPath("SELFHOST_BUNDLE.md"):
            # This exact root document is copied into the customer bundle by
            # marty-selfhost-bundle. Keep the Cargo reverse consumers (notably
            # Canvas acceptance). Its ownership must remain declared by the
            # bundle descriptor; an absent/deleted or unowned input fails closed.
            asset = root / path
            descriptor = root / "deploy-config/bundles/selfhost.json"
            if (
                not asset.is_file()
                or asset.is_symlink()
                or not descriptor.is_file()
                or descriptor.is_symlink()
                or descriptor.parent.is_symlink()
                or descriptor.parent.parent.is_symlink()
                or "marty-selfhost-bundle" not in names
            ):
                return full(f"missing known package asset: {path}")
            try:
                declared_assets = json.loads(descriptor.read_text(encoding="utf-8"))[
                    "assets"
                ]
            except (OSError, UnicodeError, ValueError, KeyError, TypeError):
                declared_assets = None
            if (
                not isinstance(declared_assets, list)
                or declared_assets.count(path.as_posix()) != 1
            ):
                return full(f"missing known package asset: {path}")
            direct.add("marty-selfhost-bundle")
            continue
        if not path.parts or path.parts[0] != "rust":
            # Protocol corpora, workflows, Dockerfiles, scripts, release inputs,
            # and undeclared consumers are not represented by Cargo metadata.
            return full(f"external or unknown input: {path}")
        owners = [
            (len(owner.parts), name)
            for name, owner in roots.items()
            if path.is_relative_to(owner)
        ]
        if not owners:
            # Includes third_party, toolchain, .cargo, deleted packages, and
            # workspace-level inputs. The current graph cannot prove isolation.
            return full(f"unowned Rust input: {path}")
        direct.add(max(owners)[1])

    reverse: dict[str, set[str]] = defaultdict(set)
    for package in packages:
        for dependency in package["dependencies"]:
            name = dependency["name"]  # Canonical name, even with a local alias.
            if name in names:
                reverse[name].add(package["name"])

    affected = set(direct)
    queue = deque(direct)
    while queue:
        for consumer in reverse[queue.popleft()]:
            if consumer not in affected:
                affected.add(consumer)
                queue.append(consumer)
    # Services consume one another over HTTP/gRPC and deployment wiring, not
    # only Cargo dependencies. For example, Applicant/Gateway consume
    # Notification and Presentation Policy consumes Trust Profile. Until that
    # runtime graph is proven, no affected service package is narrow evidence.
    services = {
        name
        for name, owner in roots.items()
        if owner.is_relative_to(PurePosixPath("rust/services"))
    }
    if affected & services:
        observed = [
            {"producer": producer, **edge}
            for producer in sorted(affected & services)
            for edge in OBSERVED_NON_CARGO_CONSUMERS.get(producer, [])
            if edge["package"] in names
        ]
        return full(
            "unmapped non-Cargo runtime consumers of service packages",
            observed_consumers=observed,
        )
    return {
        "all": False,
        "packages": sorted(affected),
        "direct": sorted(direct),
        "reason": "workspace package inputs and reverse Cargo consumers",
    }


def main() -> int:
    base = os.environ.get("BASE_SHA", "")
    head = os.environ.get("HEAD_SHA", "")
    if not base or not head:
        result = {"all": True, "packages": ["*"], "reason": "missing base or head SHA"}
    else:
        try:
            subprocess.run(
                ["git", "fetch", "--no-tags", "--depth=1", "origin", base],
                cwd=ROOT,
                check=True,
                capture_output=True,
            )
            result = plan(changed_paths(base, head), cargo_metadata())
        except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
            result = {
                "all": True,
                "packages": ["*"],
                "reason": f"unable to prove affected packages: {type(error).__name__}",
            }
    print("affected-rust-shadow: " + json.dumps(result, sort_keys=True))
    # This remains observational. Existing full Rust lanes are authoritative.
    return 0


if __name__ == "__main__":
    sys.exit(main())
