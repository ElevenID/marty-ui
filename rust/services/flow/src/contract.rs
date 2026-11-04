pub const HTTP_ROUTES: &[(&str, &str)] = &[
    ("GET", "/v1/flows/capabilities"),
    ("POST", "/v1/flows/definitions"),
    ("GET", "/v1/flows/definitions"),
    ("GET", "/v1/flows/definitions/{flow_id}"),
    ("PATCH", "/v1/flows/definitions/{flow_id}"),
    ("POST", "/v1/flows/definitions/{flow_id}/validate"),
    ("POST", "/v1/flows/definitions/{flow_id}/test"),
    ("POST", "/v1/flows/definitions/{flow_id}/activate"),
    ("DELETE", "/v1/flows/definitions/{flow_id}"),
    ("POST", "/v1/flows/instances"),
    ("GET", "/v1/flows/instances"),
    ("GET", "/v1/flows/instances/{instance_id}"),
    ("GET", "/v1/flows/instances/{instance_id}/result"),
    ("POST", "/v1/flows/instances/{instance_id}/advance"),
    ("POST", "/v1/flows/instances/{instance_id}/cancel"),
    ("GET", "/v1/flows/instances/{instance_id}/artifacts"),
    (
        "GET",
        "/v1/flows/instances/{instance_id}/artifacts/{artifact_id}",
    ),
    ("POST", "/v1/flows/instances/{instance_id}/generate-qr"),
    ("POST", "/v1/flows/verify"),
    ("GET", "/v1/flows/instances/{instance_id}/request"),
    ("POST", "/v1/flows/instances/{instance_id}/request"),
    ("GET", "/oid4vp/did.json"),
    ("POST", "/v1/flows/instances/{instance_id}/submit"),
    ("POST", "/v1/flows/instances/{instance_id}/submit/dc-api"),
    ("POST", "/v1/flows/siop"),
    ("POST", "/v1/flows/siop/submit"),
    ("POST", "/v1/flows/webhooks/application-approved"),
    ("GET", "/health/native-backend"),
];

/// Additive native physical-start recovery surface. The published Flow v1
/// route list above remains frozen for legacy consumers.
pub const PHYSICAL_START_HTTP_ROUTES: &[(&str, &str)] =
    &[("GET", "/v1/flows/physical-start-intents")];

/// Default-disabled website demonstration surface. Visitor capabilities are
/// separate from the protected organization-management routes above.
pub const PUBLIC_VERIFICATION_HTTP_ROUTES: &[(&str, &str)] = &[
    ("GET", "/v1/flows/public/verification/catalog"),
    ("POST", "/v1/flows/public/verification/sessions"),
    ("GET", "/v1/flows/public/verification/sessions/{session_id}"),
    (
        "POST",
        "/v1/flows/public/verification/sessions/{session_id}/cancel",
    ),
];

pub const GRPC_METHODS: &[&str] = &[
    "CreateFlowDefinition",
    "GetFlowDefinition",
    "ListFlowDefinitions",
    "ActivateFlowDefinition",
    "DeleteFlowDefinition",
    "StartFlowInstance",
    "GetFlowInstance",
    "ListFlowInstances",
    "AdvanceFlowInstance",
    "CancelFlowInstance",
    "GetFlowResult",
    "ListFlowArtifacts",
    "StartVerification",
    "ApplicationApproved",
    "StreamFlowUpdates",
    "HealthCheck",
];
