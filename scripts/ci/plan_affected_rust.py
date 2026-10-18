"""Report conservative Rust package impact without changing CI execution."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from collections import defaultdict, deque
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / "rust"

# The self-host acceptance target includes this Canvas test helper by source
# path, not Cargo dependency. Keep the shadow package graph honest while the
# actual PR/merge-group CI selection remains conservative.
SELFHOST_CLEANUP_INPUT = PurePosixPath(
    "rust/crates/canvas-acceptance/tests/support/owned_cleanup.rs"
)
SELFHOST_CLEANUP_CONSUMER = PurePosixPath(
    "rust/crates/selfhost-acceptance/tests/selfhost_public_image_contract.rs"
)
SELFHOST_CLEANUP_IMPORT = (
    '#[path = "../../canvas-acceptance/tests/support/owned_cleanup.rs"]'
)
SELFHOST_CLEANUP_RELATIVE = "../../canvas-acceptance/tests/support/owned_cleanup.rs"

# This crate ships as a CLI inside a Compose image and drives live services.
# Cargo reverse edges cannot represent that artifact/runtime relationship.
# These witnesses explain a full shadow fallback; they never authorize a skip.
PACKAGED_RUNTIME_PRODUCERS = {
    "marty-canvas-demo-seed": {
        "consumer_kind": "packaged-executable/runtime",
        "consumer": "db-migrate",
        "witnesses": (
            (
                "services/Dockerfile.migrations",
                "&& cargo build --locked --release -p marty-canvas-demo-seed --bin marty-canvas-demo-seed",
            ),
            (
                "services/Dockerfile.migrations",
                "COPY --from=rust-migration-builder /build/rust/target/release/marty-canvas-demo-seed /usr/local/bin/marty-canvas-demo-seed",
            ),
            (
                "docker-compose.base.yml",
                "  db-migrate:\n    build:\n      context: .\n      dockerfile: services/Dockerfile.migrations",
            ),
            (
                "scripts/qualify-canvas-seed-disposable.sh",
                "      db-migrate /usr/local/bin/marty-canvas-demo-seed --env-file /dev/null",
            ),
            (
                "scripts/run-canvas-real-seed.sh",
                "  db-migrate /usr/local/bin/marty-canvas-demo-seed --env-file /dev/null",
            ),
        ),
    },
}
PACKAGED_WITNESS_MAX_BYTES = 1024 * 1024


def _read_packaged_witness(path: Path) -> str:
    """Read only bounded, unchanged regular files; unavailable evidence is empty."""
    descriptor = None
    source = ""
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > PACKAGED_WITNESS_MAX_BYTES
        ):
            return ""
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0),
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size > PACKAGED_WITNESS_MAX_BYTES
        ):
            return ""
        data = bytearray()
        while len(data) <= PACKAGED_WITNESS_MAX_BYTES:
            chunk = os.read(
                descriptor, min(65536, PACKAGED_WITNESS_MAX_BYTES + 1 - len(data))
            )
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        if len(data) > PACKAGED_WITNESS_MAX_BYTES or (
            opened.st_size,
            opened.st_mtime_ns,
        ) != (after.st_size, after.st_mtime_ns):
            return ""
        source = data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except (OSError, UnicodeError):
        return ""
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                source = ""
    return source


# One authenticated Gateway compatibility route serves several issuer-key
# consumers. Keep its source witness shared while each consumer retains its
# own configuration, call-site, and deployment evidence.
GATEWAY_ISSUER_RESOLUTION_ROUTE = {
    "provider_evidence": "rust/services/gateway/src/runtime.rs",
    "provider_route_marker": 'request.uri().path().starts_with("/internal/signing-keys")',
    "provider_dispatch_marker": "forward_resolve_issuer_did(&state, &organization_id, &query).await",
    "provider_auth_marker": "constant_time_header_matches(",
    "provider_operation_evidence": "rust/services/gateway/src/signing_compat.rs",
    "provider_operation_marker": '(HttpMethod::Get, "resolve-issuer-did")',
}

# This beta-only operation uses an already-observed Gateway/Issuance package
# relationship, but a different signed webhook route and deployment profile.
# It is a witness for obligation inventory, not evidence to narrow CI lanes.
PASSPORT_BETA_GATEWAY_CALLBACK_WITNESS = {
    "package": "marty-issuance-service",
    "conditional": "beta passport Gateway callback profile only",
    "config_evidence": "rust/services/issuance/src/bin/passport_beta_bureau.rs",
    "binding": 'required_url("PASSPORT_BUREAU_CALLBACK_URL")?',
    "selection_marker": 'Some("true") => Ok(private_gateway_callback(url))',
    "handoff_evidence": "rust/services/issuance/src/passport_callback_handoff.rs",
    "handoff_marker": ".post(callback_url.clone())",
    "signature_marker": '.header("x-personalization-signature", signature)',
    "route_evidence": "rust/services/gateway/src/issuance_native.rs",
    "route_marker": 'path == "/v1/passport/webhooks/personalization"',
    "forwarding_test_evidence": "rust/services/gateway/src/runtime.rs",
    "forwarding_test_marker": "signed_passport_webhook_preserves_raw_body_and_switches_owner_without_tenant_key",
    "profile_evidence": "docker-compose.profile.passport-native-beta.yml",
    "profile_service": "passport-beta-bureau",
    "profile_gateway_service": "gateway",
    "profile_callback_url": "http://gateway:8000/v1/passport/webhooks/personalization",
}

# The physical-provider beta profile selects an Issuance-owned ingress binary
# for the signed webhook, while both beta profiles select native Issuance for
# public passport routes. These are distinct conditional operations on the
# already-observed Gateway/Issuance relationship, not a new package edge or
# permission to narrow service checks.
PASSPORT_GATEWAY_ISSUANCE_SELECTOR_WITNESSES = (
    {
        "package": "marty-gateway",
        "conditional": "beta passport native Gateway routes only",
        "config_evidence": "rust/services/gateway/src/config.rs",
        "binding": 'boolean(values, "PASSPORT_NATIVE_GATEWAY_ENABLED", false)?',
        "url_binding": 'value(values, "ISSUANCE_NATIVE_SERVICE_URL")',
        "dispatch_evidence": "rust/services/gateway/src/main.rs",
        "dispatch_marker": "config.passport_native_gateway_enabled,",
        "route_evidence": "rust/services/gateway/src/contract.rs",
        "route_marker": "issuance_native::is_passport_public_http(declared.method, upstream_path)",
        "owner_marker": "issuance_native::NATIVE_SERVICE",
        "route_test_marker": "assert_eq!(new.route.upstream_service, issuance_native::NATIVE_SERVICE);",
        "provider_evidence": "rust/services/issuance/Cargo.toml",
        "provider_marker": 'name = "marty-issuance-service"',
        "provider_path_marker": 'path = "src/main.rs"',
        "profile_evidence": "docker-compose.profile.passport-native-beta.yml",
        "profile_gateway_service": "gateway",
    },
    {
        "package": "marty-gateway",
        "conditional": "physical-provider beta signed webhook only",
        "config_evidence": "rust/services/gateway/src/config.rs",
        "binding": 'boolean(values, "PASSPORT_PROVIDER_INGRESS_GATEWAY_ENABLED", false)?',
        "url_binding": 'value(values, "PASSPORT_PROVIDER_INGRESS_SERVICE_URL")',
        "dispatch_evidence": "rust/services/gateway/src/main.rs",
        "dispatch_marker": "config.passport_provider_ingress_gateway_enabled,",
        "route_evidence": "rust/services/gateway/src/contract.rs",
        "route_marker": "&& issuance_native::is_passport_signed_webhook(declared.method, upstream_path)",
        "owner_marker": '"passport-provider-ingress"',
        "route_test_marker": 'assert_eq!(ingress.route.upstream_service, "passport-provider-ingress");',
        "provider_evidence": "rust/services/issuance/Cargo.toml",
        "provider_marker": 'name = "marty-passport-provider-ingress"',
        "provider_path_marker": 'path = "src/bin/passport_provider_ingress.rs"',
        "profile_evidence": "docker-compose.profile.passport-native-physical-beta.yml",
        "profile_gateway_service": "gateway",
        "profile_provider_service": "passport-provider-ingress",
    },
)

PASSPORT_CALLBACK_SIGNING_REQUEST_WITNESS = {
    "request_evidence": "rust/services/issuance/src/passport_callback_handoff.rs",
    "request_marker": ".post(sign_url)",
    "auth_marker": '.header("x-api-key", signing_api_key)',
    "body_marker": '.json(&json!({"body_b64": STANDARD.encode(body)}))',
    "provider_evidence": "rust/services/signing-keys/src/passport_callback_hmac.rs",
    "provider_route_marker": '"/internal/documents/{organization_id}/passport-callbacks/sign"',
    "provider_handler_marker": "post(sign_callback)",
}

# Physical-provider ingress requests a KMS-backed signature from the isolated
# Signing Keys callback binary before forwarding the same body to native
# Issuance. This is a distinct conditional operation on an existing package
# pair, not evidence that the whole runtime graph is mapped.
PASSPORT_PROVIDER_CALLBACK_SIGNER_WITNESS = {
    **PASSPORT_CALLBACK_SIGNING_REQUEST_WITNESS,
    "package": "marty-issuance-service",
    "conditional": "physical-provider ingress callback signing only",
    "consumer_evidence": "rust/services/issuance/src/bin/passport_provider_ingress.rs",
    "binding": '"PASSPORT_PROVIDER_SIGNER_URL"',
    "callback_binding": '"PASSPORT_PROVIDER_NATIVE_CALLBACK_URL"',
    "handoff_evidence": "rust/services/issuance/src/passport_provider_ingress.rs",
    "handoff_marker": "sign_and_deliver(",
    "callback_marker": "&state.native_callback_url,",
    "delivery_marker": ".post(callback_url.clone())",
    "provider_registration_evidence": "rust/services/signing-keys/src/bin/passport_callback_signer_supported.rs",
    "provider_registration_marker": "isolated_supported_signer_router(provider, key)",
    "provider_manifest_evidence": "rust/services/signing-keys/Cargo.toml",
    "provider_binary_marker": 'path = "src/bin/passport_callback_signer_supported.rs"',
    "profile_evidence": "docker-compose.profile.passport-provider-base.yml",
    "profile_consumer_service": "passport-provider-ingress",
    "profile_provider_service": "passport-callback-signer-supported",
    "profile_signer_url": "http://passport-callback-signer-supported:8018/internal/documents",
    "profile_callback_url": "http://issuance-native:8005/v1/passport/webhooks/personalization",
}

# The beta bureau is a separate consumer of that same signed-body request.
# Its private signer and Gateway callback are selected only by the synthetic
# passport beta profile; this observation does not narrow service checks.
PASSPORT_BETA_CALLBACK_SIGNER_WITNESS = {
    **PASSPORT_CALLBACK_SIGNING_REQUEST_WITNESS,
    "package": "marty-issuance-service",
    "conditional": "beta passport bureau callback signing only",
    "consumer_evidence": "rust/services/issuance/src/bin/passport_beta_bureau.rs",
    "gate_marker": "if !beta_gate(",
    "gate_logic_marker": 'environment == Some("beta") && enabled == Some("true")',
    "enable_marker": 'env::var("PASSPORT_BETA_BUREAU_ENABLED").ok().as_deref()',
    "binding": 'required_url("SIGNING_KEYS_INTERNAL_URL")?',
    "private_url_marker": '"http://passport-callback-signer:8018/internal/documents"',
    "callback_binding": 'required_url("PASSPORT_BUREAU_CALLBACK_URL")?',
    "callback_selection_marker": 'env::var("PASSPORT_BETA_BUREAU_GATEWAY_CALLBACK_ENABLED")',
    "handoff_marker": "let receipt = sign_and_deliver(",
    "test_marker": "assert!(deliver_one(&state).await.unwrap());",
    "provider_registration_evidence": "rust/services/signing-keys/src/bin/passport_callback_signer.rs",
    "provider_beta_gate_marker": 'env::var("ENVIRONMENT").as_deref() != Ok("beta")',
    "provider_enable_gate_marker": 'env::var("PASSPORT_CALLBACK_SIGNER_ENABLED").as_deref() != Ok("true")',
    "provider_registration_marker": "isolated_signer_router(provider, key)",
    "provider_manifest_evidence": "rust/services/signing-keys/Cargo.toml",
    "provider_binary_marker": 'path = "src/bin/passport_callback_signer.rs"',
    "profile_evidence": "docker-compose.profile.passport-native-beta.yml",
    "profile_consumer_service": "passport-beta-bureau",
    "profile_provider_service": "passport-callback-signer",
    "profile_signer_url": "http://passport-callback-signer:8018/internal/documents",
    "profile_callback_url": "http://gateway:8000/v1/passport/webhooks/personalization",
}

# These are observed HTTP/deployment consumers, not a complete runtime graph.
# Keep the service fallback below until every service and its transitive inputs
# have an obligation owner. The paths document the source of each observation.
OBSERVED_NON_CARGO_CONSUMERS = {
    "marty-gateway": [
        {
            # Credential Template resolves issuer DIDs through the stack's
            # Gateway signing-compatibility route, not directly through Cargo.
            "package": "marty-credential-template",
            "evidence": "rust/services/credential-template/src/config.rs",
            "binding": '"SIGNING_KEYS_INTERNAL_URL"',
            "auth_binding": '"SIGNING_KEYS_INTERNAL_API_KEY"',
            "runtime_evidence": "rust/services/credential-template/src/main.rs",
            "runtime_marker": "config.signing_keys_internal_url.clone()",
            "auth_runtime_marker": "config.signing_keys_internal_api_key.as_deref()",
            "request_evidence": "rust/services/credential-template/src/control_plane.rs",
            "request_marker": '"{}/resolve-issuer-did"',
            "request_base_marker": "self.signing_keys_internal_url",
            "request_method_marker": "self.http.get(endpoint)",
            "request_auth_marker": 'request.header("x-api-key", api_key.as_ref())',
            "send_marker": ".send()",
            **GATEWAY_ISSUER_RESOLUTION_ROUTE,
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_service": "credential-template",
            "deployment_marker": "SIGNING_KEYS_INTERNAL_URL: http://gateway:8000/internal/signing-keys",
            "deployment_auth_key": "SIGNING_KEYS_INTERNAL_API_KEY",
        },
        {
            # Issuance's configured resolver calls Gateway's authenticated
            # issuer-DID compatibility route in the standard Compose stack.
            "package": "marty-issuance-service",
            "evidence": "rust/services/issuance/src/config.rs",
            "binding": 'values.get("SIGNING_KEYS_INTERNAL_URL")',
            "auth_binding": 'secret_value(&values, "SIGNING_KEYS_INTERNAL_API_KEY")?',
            "runtime_evidence": "rust/services/issuance/src/main.rs",
            "runtime_marker": "Arc::new(HttpIssuerContextResolver::new(",
            "auth_runtime_marker": "config.signing_keys_internal_api_key.as_deref()",
            "request_evidence": "rust/services/issuance/src/credential_issuer.rs",
            "request_marker": '"{}/resolve-issuer-did"',
            "request_method_marker": "self.client.get(self.endpoint()?).query(&query)",
            "request_auth_marker": 'request.header("X-API-Key", api_key)',
            "send_marker": "request.send().await",
            **GATEWAY_ISSUER_RESOLUTION_ROUTE,
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_service": "issuance",
            "deployment_marker": "SIGNING_KEYS_INTERNAL_URL: http://gateway:8000/internal/signing-keys",
            "deployment_auth_key": "SIGNING_KEYS_INTERNAL_API_KEY",
        },
        {
            # Verification's Credentials compatibility mode is conditional;
            # when enabled, its resolver uses the same Gateway route.
            "package": "marty-verification-service",
            "evidence": "rust/services/verification/src/config.rs",
            "binding": 'value(&values, "SIGNING_KEYS_INTERNAL_URL")',
            "auth_binding": 'value(&values, "SIGNING_KEYS_INTERNAL_API_KEY")',
            "runtime_evidence": "rust/services/verification/src/main.rs",
            "conditional_marker": "if config.credentials_compat_enabled {",
            "runtime_marker": "OrganizationIssuerKeyResolver::new(",
            "request_evidence": "rust/services/verification/src/credentials_compat/resolver.rs",
            "request_marker": '.get(format!("{}/resolve-issuer-did", self.base_url))',
            "request_auth_marker": '.header("X-API-Key", &self.api_key)',
            "send_marker": ".send()",
            "fallback_marker": "allow_public_did_fallback()",
            **GATEWAY_ISSUER_RESOLUTION_ROUTE,
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_service": "verification",
            "deployment_marker": "SIGNING_KEYS_INTERNAL_URL: http://gateway:8000/internal/signing-keys",
            "deployment_auth_key": "SIGNING_KEYS_INTERNAL_API_KEY",
            "deployment_conditional_key": "VERIFICATION_CREDENTIALS_COMPAT_ENABLED",
        },
        {
            # Trust Profile resolves issuer did:web documents through the
            # stack-owned Gateway unless the internal base URL is overridden.
            "package": "marty-trust-profile",
            "evidence": "rust/services/trust-profile/src/config.rs",
            "binding": 'value(&values, "DID_RESOLUTION_BASE_URL").unwrap_or("http://gateway:8000")',
            "runtime_evidence": "rust/services/trust-profile/src/main.rs",
            "runtime_marker": "NativeIssuerKeyResolver::new(",
            "registration_marker": ".with_issuer_key_resolver(issuer_key_resolver)",
            "request_evidence": "rust/services/trust-profile/src/issuer_keys.rs",
            "client_marker": ".with_did_web_internal_base_urls(internal_base_urls)",
            "request_marker": ".resolve_with_metadata(did)",
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_service": "trust-profile",
            "deployment_marker": "DID_RESOLUTION_BASE_URL: http://gateway:8000",
        },
        {
            # The standard Compose profile configures Issuance's optional
            # DIDComm recipient did:web resolver against Gateway.
            "package": "marty-issuance-service",
            "evidence": "rust/services/issuance/src/config.rs",
            "binding": '"DIDCOMM_DID_WEB_INTERNAL_BASE_URL"',
            "runtime_evidence": "rust/services/issuance/src/main.rs",
            "runtime_marker": "config.didcomm_did_web_internal_base_url.as_deref()",
            "client_evidence": "rust/services/issuance/src/initiation_didcomm.rs",
            "client_marker": "resolver.with_did_web_internal_base_urls([base_url])",
            "request_marker": ".resolve_with_metadata(holder_did)",
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_service": "issuance",
            "deployment_marker": "DIDCOMM_DID_WEB_INTERNAL_BASE_URL: ${DIDCOMM_DID_WEB_INTERNAL_BASE_URL:-http://gateway:8000}",
        },
        PASSPORT_BETA_GATEWAY_CALLBACK_WITNESS,
    ],
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
            "client_evidence": "rust/services/auth/src/service_transports.rs",
            "client_marker": "FlowServiceClient::new(flow)",
            "client_wiring_marker": "GrpcCredentialVerificationStarter::new(self.flow.clone(), self.service_token.clone())",
            "request_marker": ".start_verification(service_request(",
            "request_auth_marker": "&self.service_token,",
            "registration_evidence": "rust/services/auth/src/main.rs",
            "registration_marker": "connections.grpc_clients.credential_verification()",
            "callsite_evidence": "rust/services/auth/src/credential_http.rs",
            "callsite_marker": ".start(&StartCredentialVerification {",
            "route_evidence": "rust/services/auth/src/http_service.rs",
            "route_marker": '"/v1/auth/credential-login", get(credential_login)',
            "route_handler_marker": "state.credential_login.start_login().await",
            "provider_evidence": "rust/services/flow/src/grpc_service.rs",
            "provider_marker": "async fn start_verification(",
            "provider_auth_marker": "authorize_workload(&request, crate::START_VERIFICATION_METHOD)?",
            "provider_start_marker": "prepare_profiled_verification_start(",
            "provider_registration_evidence": "rust/services/flow/src/main.rs",
            "provider_registration_marker": "FlowServiceServer::new(grpc_service)",
            "provider_serving_marker": ".add_service(flow_server)",
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_marker": "FLOW_GRPC_TARGET: flow:9011",
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
            "runtime_marker": "tenant_membership_provider(&c).await?",
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
            "runtime_marker": "tenant_membership_provider(&config).await?",
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
            "connection_marker": "OrganizationServiceClient::new(channel)",
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
            "connection_marker": "OrganizationServiceClient::new(\n                channel(organization_target, timeout).await?,",
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
            "runtime_marker": "VerificationProviders::connect_lazy(&config.providers).await?",
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
            "connection_marker": "OrganizationServiceClient::new(organization_channel)",
            "request_marker": "client.get_organization(request).await",
            "membership_marker": "client.get_member(request).await",
            "identity_marker": "response.id != organization_id",
            "provider_evidence": "rust/services/organization/src/grpc_service.rs",
            "provider_marker": ".get_organization(organization_id)",
        },
        {
            "package": "marty-auth",
            "evidence": "rust/services/auth/src/config.rs",
            "binding": 'get("ORG_GRPC_TARGET").unwrap_or("organization:9002")',
            "runtime_evidence": "rust/services/auth/src/connections.rs",
            "runtime_marker": "&config.organization_grpc_target",
            "client_evidence": "rust/services/auth/src/service_transports.rs",
            "client_marker": "OrganizationServiceClient::new(organization)",
            "wiring_marker": "GrpcOrganizationProvisioning::new(",
            "wiring_client_marker": "self.organization.clone(),",
            "wiring_token_marker": "self.service_token.clone(),",
            "registration_evidence": "rust/services/auth/src/main.rs",
            "registration_marker": ".organization_provisioning(config.default_organization_id.clone())",
            "jit_registration_marker": "JitUserProvisioner::new(",
            "jit_evidence": "rust/services/auth/src/provisioning.rs",
            "jit_add_marker": ".ensure_default_member(&principal_user_id, &applicant.email)",
            "jit_context_marker": ".resolve_default_context(&principal_user_id)",
            "callback_evidence": "rust/services/auth/src/application.rs",
            "callback_marker": ".provision(&identity)",
            "add_request_marker": ".add_member(service_request(",
            "member_request_marker": ".get_member(service_request(",
            "organization_request_marker": ".get_organization(service_request(",
            "request_auth_marker": "&self.service_token,",
            "provider_evidence": "rust/services/organization/src/grpc_service.rs",
            "provider_auth_marker": "self.authenticate(&request)?;",
            "add_provider_marker": ".add_member_direct(AddMemberDirectCommand {",
            "member_provider_marker": ".get_membership(&input.user_id, organization_id)",
            "organization_provider_marker": ".get_organization(organization_id)",
            "provider_registration_evidence": "rust/services/organization/src/main.rs",
            "provider_registration_marker": "OrganizationServiceServer::new(grpc_service)",
            "provider_serving_marker": ".add_service(organization_server)",
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_marker": "ORG_GRPC_TARGET: organization:9002",
        },
        {
            "package": "marty-trust-profile",
            "evidence": "rust/services/trust-profile/src/config.rs",
            "binding": "ORG_GRPC_TARGET",
            "runtime_evidence": "rust/services/trust-profile/src/main.rs",
            "runtime_marker": "&config.organization_grpc_target",
            "startup_marker": "NativeTrustProfileControlPlane::connect_lazy(",
            "startup_token_marker": "config.service_token.as_deref(),",
            "injection_marker": "TrustProfileApplication::new(Arc::clone(&repository), control)",
            "request_evidence": "rust/services/trust-profile/src/control_plane.rs",
            "connection_marker": "OrganizationServiceClient::new(channel)",
            "authentication_marker": ".insert(SERVICE_TOKEN_HEADER, token.clone())",
            "request_marker": ".get_member(self.request(GetMemberRequest {",
            "request_organization_marker": "organization_id: organization_id.to_owned(),",
            "request_user_marker": "user_id: user_id.to_owned(),",
            "user_identity_marker": "member.user_id != user_id",
            "organization_identity_marker": "member.organization_id != organization_id",
            "active_marker": '!member.status.eq_ignore_ascii_case("active")',
            "owner_permission_marker": "member.is_owner",
            "console_permission_marker": "member.has_org_console_access",
            "permission_marker": "member.permissions.iter().any(|value| value == &required)",
            "callsite_evidence": "rust/services/trust-profile/src/application.rs",
            "callsite_marker": '.require_permission(user_id, organization_id, "trust-profile", "view")',
            "provider_evidence": "rust/services/organization/src/grpc_service.rs",
            "provider_authentication_marker": "self.authenticate(&request)?;",
            "provider_marker": ".get_membership(&input.user_id, organization_id)",
            "provider_registration_evidence": "rust/services/organization/src/main.rs",
            "provider_registration_marker": "OrganizationServiceServer::new(grpc_service)",
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_service": "trust-profile",
            "deployment_marker": "ORG_GRPC_TARGET: organization:9002",
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
            "connection_marker": "templates: CredentialTemplateServiceClient::new(\n                grpc_client_channel::credential_template_channel(",
            "request_marker": ".get_template(self.grpc_request(GetTemplateRequest {",
            "response_marker": "template_from_grpc(template_id, response.into_inner())",
            "provider_evidence": "rust/services/credential-template/src/grpc_service.rs",
            "provider_marker": ".get_template_for_internal_service(&request.get_ref().template_id)",
            "readiness_binding": '"CREDENTIAL_TEMPLATE_SERVICE_URL"',
            "readiness_startup_evidence": "rust/services/issuance/src/main.rs",
            "readiness_startup_marker": "HttpCanvasReadinessDocumentProvider::new(",
            "readiness_url_marker": "&config.credential_template_service_url,",
            "readiness_registration_marker": "canvas_management.with_readiness_input_provider(canvas_readiness)",
            "readiness_request_evidence": "rust/services/issuance/src/canvas_readiness_runtime.rs",
            "readiness_callsite_marker": ".documents(&binding.credential_template_id)",
            "readiness_object_marker": ".object(",
            "readiness_base_marker": "&self.credential_template_base_url,",
            "readiness_endpoint_marker": '"issuance-context",',
            "readiness_get_marker": "request.send().await",
            "readiness_response_marker": "if response.status() != StatusCode::OK",
            "readiness_provider_evidence": "rust/services/credential-template/src/http_service.rs",
            "readiness_provider_route_marker": '"/internal/credential-templates/{template_id}/issuance-context"',
            "readiness_provider_method_marker": "get(get_internal_issuance_context)",
            "readiness_provider_handler_marker": ".template_internal(&template_id)",
            "readiness_deployment_evidence": "docker-compose.base.yml",
            "readiness_deployment_marker": "CREDENTIAL_TEMPLATE_SERVICE_URL: http://credential-template:8003",
            "readiness_native_deployment_evidence": "docker-compose.profile.issuance-native.yml",
        },
        {
            "package": "marty-verification-service",
            "evidence": "rust/services/verification/src/config.rs",
            "binding": 'value(&values, "CT_GRPC_TARGET")',
            "runtime_evidence": "rust/services/verification/src/main.rs",
            "runtime_marker": "VerificationProviders::connect_lazy(&config.providers).await?",
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
            # Issuance also consumes Revocation Profile over HTTP: Canvas
            # readiness uses an authenticated internal profile read, while credential lifecycle
            # reserves an index and publishes revocation through internal routes.
            "package": "marty-issuance-service",
            "evidence": "rust/services/issuance/src/config.rs",
            "binding": 'values.get("REVOCATION_PROFILE_SERVICE_URL")',
            "runtime_evidence": "rust/services/issuance/src/main.rs",
            "readiness_runtime_marker": "HttpCanvasReadinessDocumentProvider::new(",
            "readiness_token_marker": "config.internal_service_token.as_deref(),",
            "lifecycle_runtime_marker": "PostgresCredentialLifecycle::new(",
            "readiness_evidence": "rust/services/issuance/src/canvas_readiness_runtime.rs",
            "readiness_request_marker": '"revocation-profiles",\n                            profile_id,\n                            "issuance-context",',
            "readiness_token_marker_client": "self.status_profile_service_token.as_deref(),",
            "readiness_send_marker": "request.send().await",
            "readiness_header_marker": 'request.header("x-service-token", token)',
            "readiness_rejection_marker": "if response.status() != StatusCode::OK",
            "lifecycle_evidence": "rust/services/issuance/src/credential_lifecycle.rs",
            "allocation_marker": '"{}/internal/revocation-profiles/{profile_id}/reserve-index"',
            "revocation_marker": '"{}/internal/revocation-profiles/{profile_id}/process-revocation"',
            "lifecycle_send_marker": "request.send().await",
            "provider_evidence": "rust/services/revocation-profile/src/http.rs",
            "profile_route_marker": '"/internal/revocation-profiles/{profile_id}/issuance-context"',
            "profile_auth_marker": "state.internal_auth.authorize_required(&headers)?;",
            "profile_auth_delegate_marker": "self.authorize(headers)",
            "profile_user_marker": ".get(SERVICE_TOKEN_HEADER)",
            "profile_unauthorized_status_marker": "Self::Unauthorized(detail) => (StatusCode::UNAUTHORIZED, detail)",
            "allocation_route_marker": '"/internal/revocation-profiles/{profile_id}/reserve-index"',
            "revocation_route_marker": '"/internal/revocation-profiles/{profile_id}/process-revocation"',
            "deployment_evidence": "docker-compose.profile.issuance-native.yml",
            "deployment_service": "issuance-native",
            "deployment_marker": "REVOCATION_PROFILE_SERVICE_URL: http://revocation-profile:8013",
        },
        {
            "package": "marty-issuance-service",
            "evidence": "rust/services/issuance/src/config.rs",
            "binding": "RP_GRPC_TARGET",
            "runtime_evidence": "rust/services/issuance/src/main.rs",
            "runtime_marker": "&config.revocation_profile_grpc_target",
            "startup_marker": "NativeInitiationControlPlane::connect_lazy(",
            "ports_marker": "revocation_profiles: initiation_control_plane,",
            "request_evidence": "rust/services/issuance/src/initiation_dependencies.rs",
            "connection_marker": "revocation_profiles: RevocationProfileServiceClient::new(\n                channel(revocation_profile_target, timeout).await?,",
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
            "connection_marker": "RevocationProfileServiceClient::new(revocation_channel)",
            "request_marker": "client.get_revocation_profile(request).await",
            "identity_marker": "profile.organization_id != organization_id",
            "status_marker": '!profile.status.eq_ignore_ascii_case("active")',
            "provider_evidence": "rust/services/revocation-profile/src/grpc.rs",
            "provider_marker": ".get(&request.into_inner().profile_id)",
        },
    ],
    "marty-applicant": [
        {
            # Auth provisions a profile on OIDC login and Canvas LTI through
            # Applicant's native PATCH route. Compose uses Auth's default URL.
            "package": "marty-auth",
            "evidence": "rust/services/auth/src/config.rs",
            "binding": 'get("APPLICANT_SERVICE_URL").unwrap_or("http://applicant:8006")',
            "runtime_evidence": "rust/services/auth/src/main.rs",
            "runtime_marker": "MmfApplicantProfileProvisioner::new(",
            "runtime_url_marker": "config.applicant_service_url.clone()",
            "store_marker": "MmfApplicantProvisioningStore::new(",
            "jit_marker": "JitUserProvisioner::new(",
            "canvas_marker": "Some(applicant_profile)",
            "canvas_callsite_evidence": "rust/services/auth/src/canvas_transport.rs",
            "canvas_call_marker": "provisioner.ensure_profile(&user).await",
            "callsite_evidence": "rust/services/auth/src/application.rs",
            "callsite_marker": ".provision(&identity)",
            "jit_evidence": "rust/services/auth/src/provisioning.rs",
            "jit_call_marker": ".upsert(&applicant_upsert(oidc_user, now))",
            "request_evidence": "rust/services/auth/src/service_transports.rs",
            "request_method_marker": "method: OutboundHttpMethod::Patch,",
            "request_marker": 'url: format!("{}/v1/me/applicant-profile", self.service_url)',
            "request_identity_marker": '("x-organization-id".into(), organization_id.into())',
            "response_identity_marker": "profile.user_id.as_deref() != Some(plan.account_id.as_str())",
            "provider_evidence": "rust/services/applicant/src/http.rs",
            "provider_route_marker": '.route("/v1/me/applicant-profile", get(get_profile).patch(upsert_profile))',
            "provider_identity_marker": "let identity = identity(&headers)?;",
            "provider_write_marker": ".upsert_profile(",
            "provider_registration_evidence": "rust/services/applicant/src/main.rs",
            "provider_registration_marker": "router(HttpState {",
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_service": "auth",
            "deployment_absent_marker": "APPLICANT_SERVICE_URL:",
            "deployment_provider_service": "applicant",
            "deployment_provider_marker": 'APPLICANT_SERVICE_PORT: "8006"',
        },
    ],
    "marty-issuance-service": [
        *PASSPORT_GATEWAY_ISSUANCE_SELECTOR_WITNESSES,
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
            # Auth finalizes Canvas LTI sessions through Issuance's
            # conditionally registered native HTTP route, without a Cargo edge.
            "package": "marty-auth",
            "evidence": "rust/services/auth/src/config.rs",
            "binding": "ISSUANCE_NATIVE_SERVICE_URL",
            "runtime_evidence": "rust/services/auth/src/main.rs",
            "runtime_marker": "&config.issuance_native_service_url",
            "startup_marker": "HttpCanvasExperienceSessionProvider::new(",
            "request_evidence": "rust/services/auth/src/canvas_transport.rs",
            "request_marker": '"/v1/integrations/canvas/lti/experience-sessions/current"',
            "request_method_marker": "method: OutboundHttpMethod::Get,",
            "request_auth_marker": 'headers.insert("authorization".into(), format!("Bearer {token}"));',
            "callsite_evidence": "rust/services/auth/src/http_service.rs",
            "callsite_route_marker": '"/v1/auth/canvas-lti/finalize"',
            "callsite_marker": ".finalize(&CanvasFinalizeContext {",
            "provider_evidence": "rust/services/issuance/src/http.rs",
            "provider_condition_marker": "if services.canvas_lti_experience_session.is_some() {",
            "provider_marker": "get(get_canvas_lti_experience_session)",
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_marker": "ISSUANCE_NATIVE_SERVICE_URL: http://issuance-native:8005",
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
            # Applicant's event publisher calls the authenticated internal
            # Notification route before publishing to Event Stream. There is
            # no Cargo dependency on the Notification service.
            "package": "marty-applicant",
            "evidence": "rust/services/applicant/src/main.rs",
            "binding": "NOTIFICATION_EVENT_INGEST_URL",
            "default_binding_marker": 'env::var("NOTIFICATION_SERVICE_URL")',
            "default_path_marker": "format!(\"{}/internal/events\", url.trim_end_matches('/'))",
            "token_marker": 'optional_secret("NOTIFICATION_APPLICANT_EVENT_TOKEN")?',
            "startup_marker": "GrpcEventPublisher::new(",
            "startup_url_marker": "notification_url,",
            "startup_token_marker": "notification_token,",
            "runtime_evidence": "rust/services/applicant/src/providers.rs",
            "runtime_marker": ".post(url)",
            "token_header_marker": '.header("x-service-token", token)',
            "producer_header_marker": '.header("x-marty-event-producer", "applicant")',
            "payload_marker": ".json(&notification_wire(event, &event.event_id))",
            "provider_evidence": "rust/services/notification/src/http.rs",
            "provider_identity_marker": 'const APPLICANT_PRODUCER: &str = "applicant";',
            "provider_route_marker": '.route("/internal/events", post(ingest_event))',
            "provider_producer_guard_marker": "!= Some(APPLICANT_PRODUCER)",
            "provider_expected_token_marker": "let expected = match configured_token() {",
            "provider_token_guard_marker": "provided.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1",
            "provider_call_marker": "state.service.ingest_event(request).await",
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_marker": "NOTIFICATION_SERVICE_URL: http://notification:8007",
            "deployment_token_marker": "NOTIFICATION_APPLICANT_EVENT_TOKEN: ${NOTIFICATION_APPLICANT_EVENT_TOKEN:-dev-notification-applicant-event-token}",
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
            "runtime_marker": "target: config.event_stream_grpc_target.clone(),",
            "connection_marker": "EventStreamServiceClient::new(event_channel)",
            "startup_evidence": "rust/services/auth/src/main.rs",
            "startup_marker": "connections.event_transport.clone() as Arc<dyn MessageTransport>",
            "request_evidence": "rust/services/auth/src/event_transport.rs",
            "request_marker": ".publish(self.request(PublishEventRequest { event: Some(event) })?)",
            "response_marker": "if response.success {",
            "provider_evidence": "rust/services/event-stream/src/grpc.rs",
            "provider_marker": "async fn publish(",
            "server_evidence": "rust/services/event-stream/src/main.rs",
            "server_marker": "EventStreamServiceServer::new(grpc_service)",
            "condition_evidence": "rust/services/event-stream/src/config.rs",
            "condition_marker": 'parse_bool(values, "EVENT_STREAM_GRPC_ENABLED", true)?',
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
            "request_marker": "client.publish(self.request(PublishEventRequest { event: Some(event) })?)",
            "response_marker": "if response.success {",
            "provider_evidence": "rust/services/event-stream/src/grpc.rs",
            "provider_marker": "async fn publish(",
            "server_evidence": "rust/services/event-stream/src/main.rs",
            "server_marker": "EventStreamServiceServer::new(grpc_service)",
            "condition_evidence": "rust/services/event-stream/src/config.rs",
            "condition_marker": 'parse_bool(values, "EVENT_STREAM_GRPC_ENABLED", true)?',
        },
        {
            "package": "marty-gateway",
            "evidence": "rust/services/gateway/src/config.rs",
            "binding": '"ES_GRPC_TARGET", "event-stream:9015"',
            "runtime_evidence": "rust/services/gateway/src/main.rs",
            "runtime_marker": "&config.event_stream_grpc_target,\n            config.event_stream_grpc_ca_certificate.as_ref(),",
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
            "condition_marker": 'parse_bool(values, "EVENT_STREAM_GRPC_ENABLED", true)?',
        },
    ],
    "marty-trust-profile": [
        {
            # Device Registration fetches a scoped wallet-issuer trust snapshot
            # over HTTP; its shared policy crate is not this service dependency.
            "package": "marty-device-registration",
            "evidence": "rust/services/device-registration/src/main.rs",
            "binding": 'env_value("TRUST_PROFILE_SERVICE_URL", "http://trust-profile:8004")',
            "runtime_evidence": "rust/services/device-registration/src/main.rs",
            "runtime_marker": "WalletIssuerTrustClient::new(",
            "request_evidence": "rust/services/device-registration/src/wallet_issuer_trust.rs",
            "request_marker": '"{}/internal/v1/trust-profiles/{profile_id}/wallet-issuer-keys",',
            "request_auth_marker": '.header("x-service-token", &self.service_token)',
            "provider_evidence": "rust/services/trust-profile/src/http_service.rs",
            "provider_marker": '"/internal/v1/trust-profiles/{profile_id}/wallet-issuer-keys",',
            "provider_handler_marker": "get(wallet_issuer_keys)",
            "deployment_evidence": "docker-compose.base.yml",
            "deployment_marker": "TRUST_PROFILE_SERVICE_URL: http://trust-profile:8004",
        },
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
        PASSPORT_PROVIDER_CALLBACK_SIGNER_WITNESS,
        PASSPORT_BETA_CALLBACK_SIGNER_WITNESS,
        {
            # Issuance requires Signing Keys' separate authenticated TLS
            # listener even with an empty integration-secret table: startup
            # encrypts and decrypts a proof before serving requests. This
            # direct HTTPS dependency is not represented by Cargo or the
            # Gateway signing-compatibility route below.
            "package": "marty-issuance-service",
            "evidence": "rust/services/issuance/src/integration_secret_kms.rs",
            "binding": 'env::var("INTEGRATION_SECRET_KMS_URL")',
            "ca_marker": 'env::var("INTEGRATION_SECRET_KMS_CA_FILE")',
            "runtime_evidence": "rust/services/issuance/src/main.rs",
            "runtime_marker": "KmsIntegrationSecretCipher::from_environment(",
            "startup_marker": ".verify_storage(&mut integration_secret_connection)",
            "worker_evidence": "rust/services/issuance/src/bin/canvas_sync_worker.rs",
            "worker_runtime_marker": "KmsIntegrationSecretCipher::from_environment(&integration_secret_key)?",
            "worker_startup_marker": "cipher.verify_storage(&mut audit_connection).await?",
            "worker_vault_marker": "PostgresIntegrationSecretVault::new_remote(",
            "request_evidence": "rust/services/issuance/src/integration_secret_kms.rs",
            "startup_encrypt_marker": '.encrypt("marty-system", &proof, "system", "startup_proof", &proof)',
            "startup_decrypt_marker": 'self.decrypt("marty-system", &proof, "system", "startup_proof", &envelope)',
            "request_marker": '"{}/integration-secrets/{operation}"',
            "request_auth_marker": '.header("X-API-Key", &self.api_key)',
            "request_tls_marker": ".https_only(true)",
            "provider_evidence": "rust/services/signing-keys/src/http.rs",
            "provider_encrypt_marker": '"/internal/integration-secrets/encrypt"',
            "provider_decrypt_marker": '"/internal/integration-secrets/decrypt"',
            "provider_handler_marker": "async fn encrypt_integration_secret(",
            "provider_decrypt_handler_marker": "async fn decrypt_integration_secret(",
            "provider_auth_marker": "if !authorize_integration_secret(&state, &headers)",
            "listener_evidence": "rust/services/signing-keys/src/main.rs",
            "listener_marker": "if let Some(tls) = integration_secret_tls {",
            "listener_tls_marker": "axum_server::bind_rustls(tls.addr, tls_config)",
            "provider_config_evidence": "rust/services/signing-keys/src/config.rs",
            "provider_port_marker": "const DEFAULT_INTEGRATION_SECRET_TLS_PORT: u16 = 8018;",
            "provider_cert_marker": 'value(values, "SIGNING_KEYS_INTEGRATION_SECRET_TLS_CERT_FILE")',
            "deployment_evidence": "docker-compose.selfhost.prod.yml",
            "deployment_marker": "INTEGRATION_SECRET_KMS_URL: https://signing-keys:8018/internal",
            "deployment_ca_marker": "INTEGRATION_SECRET_KMS_CA_FILE: /run/secrets/workload_identity_ca_cert",
            "deployment_key_marker": "SIGNING_KEYS_INTEGRATION_SECRET_KEY_FILE: /run/secrets/signing_keys_integration_secret_key",
            "deployment_key_secret_marker": "- signing_keys_integration_secret_key",
            "deployment_ca_secret_marker": "- workload_identity_ca_cert",
            "provider_deployment_marker": "SIGNING_KEYS_INTEGRATION_SECRET_TLS_CERT_FILE: /run/secrets/signing_keys_workload_server_cert",
        },
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
        # Flow's request-object signer and remote HAIP response-key operation use the
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
            "create_marker": '"haip-response-keys/create",',
            "decrypt_marker": '"haip-response-keys/decrypt",',
            "callsite_evidence": "rust/services/flow/src/request_object.rs",
            "callsite_marker": "let compact_jwt = sign_payload(",
            "envelope_callsite_marker": "response_encryption_key(providers, &instance).await?",
            "callback_evidence": "rust/services/flow/src/verification_submission.rs",
            "callback_marker": ".decrypt_haip_response(",
            "provider_evidence": "rust/services/signing-keys/src/http.rs",
            "provider_marker": '"/internal/compat/issuer-dids/sign"',
            "provider_handler_marker": "async fn issuer_did_sign(",
            "provider_create_marker": '"/internal/haip-response-keys/create"',
            "provider_create_handler_marker": "async fn create_haip_response_key(",
            "provider_decrypt_marker": '"/internal/haip-response-keys/decrypt"',
            "provider_decrypt_handler_marker": "async fn decrypt_haip_response(",
        },
    ],
    "marty-presentation-policy": [
        {
            "package": "marty-verification-service",
            "evidence": "rust/services/verification/src/config.rs",
            "binding": 'value(&values, "PP_GRPC_TARGET")',
            "runtime_evidence": "rust/services/verification/src/main.rs",
            "runtime_marker": "VerificationProviders::connect_lazy(&config.providers).await?",
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
# Gateway also validates sessions through Auth gRPC before using identity
# claims. Enrich its existing public-HTTP edge, not a duplicate consumer.
next(
    edge
    for edge in OBSERVED_NON_CARGO_CONSUMERS["marty-auth"]
    if edge["package"] == "marty-gateway"
).update(
    {
        "grpc_binding": 'grpc_target(values, "AUTH_GRPC_TARGET", "localhost:9001")?',
        "grpc_runtime_evidence": "rust/services/gateway/src/main.rs",
        "grpc_runtime_marker": ".grpc_channel_connected(\n            &config.auth_grpc_target,",
        "grpc_registration_marker": "let identities: Arc<dyn GatewayIdentityProvider> = identity_provider.clone();",
        "grpc_request_evidence": "rust/services/gateway/src/providers.rs",
        "grpc_connection_marker": "AuthServiceClient::new(auth)",
        "grpc_request_marker": ".validate_session(request)",
        "grpc_identity_marker": "if user.user_id.trim().is_empty() {",
        "grpc_provider_evidence": "rust/services/auth/src/grpc_service.rs",
        "grpc_provider_marker": ".validate_session(&request.get_ref().session_id)",
        "grpc_provider_registration_evidence": "rust/services/auth/src/main.rs",
        "grpc_provider_registration_marker": "AuthServiceServer::new(AuthGrpcService::new(",
        "grpc_deployment_evidence": "docker-compose.base.yml",
        "grpc_deployment_marker": "AUTH_GRPC_TARGET: auth:9001",
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
        "grpc_runtime_marker": "&config.organization_grpc_target,\n            config.organization_grpc_ca_certificate.as_ref(),",
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

    def full(
        reason: str,
        *,
        observed_consumers: list[dict] | None = None,
        packaged_consumers: list[dict] | None = None,
    ) -> dict:
        result = {"all": True, "packages": sorted(names), "reason": reason}
        if observed_consumers:
            result["observed_non_cargo_consumers"] = observed_consumers
        if packaged_consumers:
            result["observed_packaged_runtime_consumers"] = packaged_consumers
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
        if path in (SELFHOST_CLEANUP_INPUT, SELFHOST_CLEANUP_CONSUMER):
            # The acceptance target imports this source outside its Cargo
            # package. A removed/changed witness cannot grant a narrow plan.
            consumer = root / SELFHOST_CLEANUP_CONSUMER
            source = root / SELFHOST_CLEANUP_INPUT
            try:
                witness = consumer.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                witness = ""
            if (
                "marty-selfhost-acceptance" not in names
                or source.is_symlink()
                or not source.is_file()
                or consumer.is_symlink()
                or SELFHOST_CLEANUP_IMPORT not in witness.splitlines()
                or (consumer.parent / SELFHOST_CLEANUP_RELATIVE).resolve()
                != source.resolve()
            ):
                return full(f"missing cross-package test input witness: {path}")
            if path == SELFHOST_CLEANUP_INPUT:
                direct.add("marty-selfhost-acceptance")

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
    packaged_consumers = []
    for producer in sorted(affected & PACKAGED_RUNTIME_PRODUCERS.keys()):
        edge = PACKAGED_RUNTIME_PRODUCERS[producer]
        witnesses = []
        for relative, marker in edge["witnesses"]:
            source = _read_packaged_witness(root / relative)
            witnesses.append({"evidence": relative, "present": marker in source})
        packaged_consumers.append(
            {
                "producer": producer,
                "consumer_kind": edge["consumer_kind"],
                "consumer": edge["consumer"],
                "witnesses": witnesses,
            }
        )
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
            packaged_consumers=packaged_consumers,
        )
    if packaged_consumers:
        # Missing or changed witnesses stay broad too. Recognizing this one
        # image does not establish its complete runtime/qualification closure.
        return full(
            "unmapped packaged-executable/runtime consumers of crate packages",
            packaged_consumers=packaged_consumers,
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
