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
    "marty-signing-keys": [
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
