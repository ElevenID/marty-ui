use std::collections::BTreeSet;

use mmf_core::{ErrorCode, MmfError};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const SURFACE: &[u8] = include_bytes!("../../../../contracts/issuance-runtime-surface.json");
const COVERAGE: &str = include_str!("../../../../contracts/issuance-native-coverage.json");
const STATIC_DISCOVERY: &[u8] =
    include_bytes!("../../../../contracts/issuance-static-discovery.json");
const TENANT_DISCOVERY: &[u8] =
    include_bytes!("../../../../contracts/issuance-tenant-discovery.json");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoverageSummary {
    pub native_http: usize,
    pub remaining_http: u64,
    pub remaining_grpc: u64,
}

#[derive(Deserialize)]
struct Coverage {
    schema: String,
    upstream: Upstream,
    behavior_contract: Upstream,
    tenant_behavior_contract: Upstream,
    native_http: Vec<HttpOperation>,
    platform_additive_http: Vec<PlatformOperation>,
    remaining: Remaining,
    native_environment_variables: Vec<String>,
    deployment: String,
}

#[derive(Deserialize)]
struct Upstream {
    repository: String,
    path: String,
    commit: String,
    sha256: String,
}

#[derive(Deserialize)]
struct HttpOperation {
    method: String,
    path: String,
    operation: String,
    #[serde(default)]
    response: Option<ExpectedResponse>,
    #[serde(default)]
    behavior_case: Option<String>,
    #[serde(default)]
    tenant_behavior_case: Option<String>,
}

#[derive(Deserialize)]
struct ExpectedResponse {
    status_code: u16,
    body: Value,
}

#[derive(Deserialize)]
struct DiscoveryContract {
    schema: String,
    transport: Value,
    cases: Vec<DiscoveryCase>,
    rejected_paths: Vec<String>,
    remaining_tenant_backed_operations: Vec<String>,
}

#[derive(Deserialize)]
struct DiscoveryCase {
    operation: String,
    method: String,
    path: String,
    status_code: u16,
    content_type: String,
    body: Value,
}

#[derive(Deserialize)]
struct TenantDiscoveryContract {
    schema: String,
    inputs: Value,
    failure: Value,
    variants: Vec<TenantDiscoveryVariant>,
}

#[derive(Deserialize)]
struct TenantDiscoveryVariant {
    operation: String,
    path: String,
    issuer_suffix: String,
    expected_resolver_calls: Vec<Value>,
    credential_configurations_supported: Value,
}

#[derive(Deserialize)]
struct PlatformOperation {
    method: String,
    path: String,
    owner: String,
}

#[derive(Deserialize)]
struct Remaining {
    http: u64,
    grpc: u64,
    runtime_modes: Vec<String>,
    literal_environment_variables: u64,
    dynamic_configuration_lookups: u64,
    migration_revisions: u64,
    migration_heads: u64,
}

pub fn validate_embedded_contract() -> Result<CoverageSummary, MmfError> {
    let surface: Value = serde_json::from_slice(SURFACE)
        .map_err(|error| contract_error("invalid issuance surface", error))?;
    let coverage: Coverage = serde_json::from_str(COVERAGE)
        .map_err(|error| contract_error("invalid native coverage", error))?;
    let discovery: DiscoveryContract = serde_json::from_slice(STATIC_DISCOVERY)
        .map_err(|error| contract_error("invalid static discovery contract", error))?;
    let tenant_discovery: TenantDiscoveryContract = serde_json::from_slice(TENANT_DISCOVERY)
        .map_err(|error| contract_error("invalid tenant discovery contract", error))?;
    require(
        surface["schema"] == "marty.issuance-runtime-surface/v1",
        "unexpected issuance surface schema",
    )?;
    require(
        discovery.schema == "marty.issuance-static-discovery/v1"
            && discovery.cases.len() == 6
            && discovery.transport["request_id"]["generated_pattern"] == "^[0-9a-f]{8}$"
            && discovery.transport["cors"]["environment_variable"] == "CORS_ALLOWED_ORIGINS"
            && discovery.transport["cors"]["default_allowed_origins"]
                == serde_json::json!(["http://localhost:3000"])
            && discovery.transport["cors"]["wildcard_simple_request"]["configured_origin"] == "*"
            && discovery.transport["cors"]["preflight"]["status_code"] == 200
            && discovery.transport["cors"]["denied_preflight"]["status_code"] == 400
            && discovery.transport["cors"]["denied_method_preflight"]["status_code"] == 400
            && discovery.rejected_paths
                == [
                    "/.well-known/openid-credential-issuer/org/org-a/spruce",
                    "/.well-known/oauth-authorization-server/org/org-a/spruce",
                ]
            && discovery.remaining_tenant_backed_operations
                == [
                    "get_org_issuer_metadata",
                    "get_org_issuer_metadata_credential_manager",
                    "get_org_issuer_metadata_apple_wallet",
                ],
        "unexpected static discovery behavior contract",
    )?;
    require(
        tenant_discovery.schema == "marty.issuance-tenant-discovery/v1"
            && tenant_discovery.inputs["organization_id"] == "org-a"
            && tenant_discovery.variants.len() == 3
            && tenant_discovery.failure["resolver_unavailable"]["status_code"] == 503
            && tenant_discovery.failure["resolver_unavailable"]["body"]
                == serde_json::json!({
                    "detail": "Issuer proof policy is temporarily unavailable"
                })
            && tenant_discovery.variants.iter().all(|variant| {
                !variant.expected_resolver_calls.is_empty()
                    && variant.credential_configurations_supported.is_object()
                    && variant
                        .path
                        .starts_with("/.well-known/openid-credential-issuer/org/org-a")
                    && variant.path.ends_with(&variant.issuer_suffix)
            }),
        "unexpected tenant discovery behavior contract",
    )?;
    require(
        coverage.behavior_contract.repository == "ElevenID/marty-credentials"
            && coverage.behavior_contract.path == "contracts/issuance-static-discovery.json"
            && coverage.behavior_contract.commit.len() == 40
            && coverage
                .behavior_contract
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "invalid static discovery provenance",
    )?;
    require(
        coverage.tenant_behavior_contract.repository == "ElevenID/marty-credentials"
            && coverage.tenant_behavior_contract.path == "contracts/issuance-tenant-discovery.json"
            && coverage.tenant_behavior_contract.commit.len() == 40
            && coverage
                .tenant_behavior_contract
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "invalid tenant discovery provenance",
    )?;
    require(
        coverage.schema == "marty.issuance-native-coverage/v1",
        "unexpected issuance coverage schema",
    )?;
    require(
        coverage.upstream.repository == "ElevenID/marty-credentials"
            && coverage.upstream.path == "contracts/issuance-runtime-surface.json"
            && coverage.upstream.commit.len() == 40
            && coverage
                .upstream
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "invalid issuance surface provenance",
    )?;
    let canonical_surface = canonical_lf(SURFACE);
    let actual_hash = format!("{:x}", Sha256::digest(&canonical_surface));
    require(
        actual_hash == coverage.upstream.sha256,
        "issuance surface hash does not match provenance",
    )?;
    let canonical_discovery = canonical_lf(STATIC_DISCOVERY);
    let actual_discovery_hash = format!("{:x}", Sha256::digest(&canonical_discovery));
    require(
        actual_discovery_hash == coverage.behavior_contract.sha256,
        "static discovery hash does not match provenance",
    )?;
    let canonical_tenant_discovery = canonical_lf(TENANT_DISCOVERY);
    let actual_tenant_discovery = format!("{:x}", Sha256::digest(&canonical_tenant_discovery));
    require(
        actual_tenant_discovery == coverage.tenant_behavior_contract.sha256,
        "tenant discovery hash does not match provenance",
    )?;

    let routes = surface["http"]["routes"]
        .as_array()
        .ok_or_else(|| invalid("issuance HTTP routes are missing"))?;
    let route_count = surface["http"]["route_count"]
        .as_u64()
        .ok_or_else(|| invalid("issuance HTTP route count is missing"))?;
    require(
        route_count == routes.len() as u64,
        "issuance HTTP route count is inconsistent",
    )?;
    let grpc_count = surface["grpc"]["method_count"]
        .as_u64()
        .ok_or_else(|| invalid("issuance gRPC method count is missing"))?;
    let grpc_methods = surface["grpc"]["methods"]
        .as_array()
        .ok_or_else(|| invalid("issuance gRPC methods are missing"))?;
    require(
        grpc_count == grpc_methods.len() as u64,
        "issuance gRPC method count is inconsistent",
    )?;

    let mut native = BTreeSet::new();
    let mut native_behavior_cases = BTreeSet::new();
    let mut native_tenant_behavior_cases = BTreeSet::new();
    for operation in &coverage.native_http {
        require(
            native.insert((operation.method.as_str(), operation.path.as_str())),
            "duplicate native issuance operation",
        )?;
        require(
            routes.iter().any(|route| {
                route["method"] == operation.method
                    && route["path"] == operation.path
                    && route["operation"] == operation.operation
            }),
            "native issuance operation is absent from the frozen surface",
        )?;
        if operation.operation == "health_check" {
            let response = operation
                .response
                .as_ref()
                .ok_or_else(|| invalid("native issuance health response is missing"))?;
            require(
                operation.behavior_case.is_none()
                    && response.status_code == 200
                    && response.body
                        == serde_json::json!({
                            "status": "healthy",
                            "service": "issuance-service"
                        }),
                "native issuance health response diverges from the legacy contract",
            )?;
        } else if let Some(behavior_case) = operation.behavior_case.as_deref() {
            require(
                operation.response.is_none()
                    && operation.tenant_behavior_case.is_none()
                    && behavior_case == operation.operation
                    && native_behavior_cases.insert(behavior_case)
                    && discovery.cases.iter().any(|case| {
                        let expected_case_path = operation
                            .path
                            .replace("{credential_type:path}", "access_badge")
                            .replace("{org_id}", "org-a");
                        case.operation == behavior_case
                            && case.method == operation.method
                            && case.status_code == 200
                            && case.content_type == "application/json"
                            && case.path == expected_case_path
                            && case.body.is_object()
                    }),
                "native issuance operation diverges from its behavior case",
            )?;
        } else if let Some(behavior_case) = operation.tenant_behavior_case.as_deref() {
            require(
                operation.response.is_none()
                    && behavior_case == operation.operation
                    && native_tenant_behavior_cases.insert(behavior_case)
                    && tenant_discovery.variants.iter().any(|variant| {
                        let expected_case_path = operation.path.replace("{org_id}", "org-a");
                        variant.operation == behavior_case
                            && variant.path == expected_case_path
                            && variant.credential_configurations_supported.is_object()
                    }),
                "native issuance operation diverges from its tenant behavior case",
            )?;
        } else {
            return Err(invalid("native issuance behavior case is missing"));
        }
    }
    let frozen_behavior_cases = discovery
        .cases
        .iter()
        .map(|case| case.operation.as_str())
        .collect::<BTreeSet<_>>();
    require(
        native_behavior_cases == frozen_behavior_cases,
        "native issuance behavior coverage is incomplete",
    )?;
    let frozen_tenant_behavior_cases = tenant_discovery
        .variants
        .iter()
        .map(|variant| variant.operation.as_str())
        .collect::<BTreeSet<_>>();
    require(
        native_tenant_behavior_cases == frozen_tenant_behavior_cases,
        "native tenant issuance behavior coverage is incomplete",
    )?;
    for operation in &coverage.platform_additive_http {
        require(
            operation.owner == "mmf-runtime",
            "additive system route must be owned by mmf-runtime",
        )?;
        require(
            !routes.iter().any(|route| {
                route["method"] == operation.method && route["path"] == operation.path
            }),
            "additive system route collides with the legacy issuance surface",
        )?;
    }
    require(
        coverage.remaining.http + coverage.native_http.len() as u64 == route_count,
        "native and remaining issuance HTTP counts are inconsistent",
    )?;
    require(
        coverage.remaining.grpc == grpc_count,
        "remaining issuance gRPC count is inconsistent",
    )?;
    let environment_count = surface["configuration"]["environment_variable_count"]
        .as_u64()
        .ok_or_else(|| invalid("issuance environment count is missing"))?;
    let dynamic_count = surface["configuration"]["dynamic_lookups"]
        .as_array()
        .ok_or_else(|| invalid("issuance dynamic lookups are missing"))?
        .len() as u64;
    let migration_count = surface["migrations"]["revision_count"]
        .as_u64()
        .ok_or_else(|| invalid("issuance migration count is missing"))?;
    let migration_heads = surface["migrations"]["heads"]
        .as_array()
        .ok_or_else(|| invalid("issuance migration heads are missing"))?
        .len() as u64;
    require(
        coverage.native_environment_variables
            == [
                "CORS_ALLOWED_ORIGINS",
                "DATABASE_URL",
                "ISSUANCE_SERVICE_PORT",
                "ISSUANCE_API_KEY",
                "ISSUER_BASE_URL",
                "ISSUER_DISPLAY_NAME",
                "SIGNING_KEYS_INTERNAL_API_KEY",
                "SIGNING_KEYS_INTERNAL_URL",
            ]
            && coverage.remaining.literal_environment_variables + 8 == environment_count
            && coverage.remaining.dynamic_configuration_lookups == dynamic_count
            && coverage.remaining.migration_revisions == migration_count
            && coverage.remaining.migration_heads == migration_heads,
        "issuance configuration or migration coverage is inconsistent",
    )?;
    let modes = surface["runtime"]["modes"]
        .as_array()
        .ok_or_else(|| invalid("issuance runtime modes are missing"))?;
    let frozen_modes = modes
        .iter()
        .filter_map(|mode| mode["name"].as_str())
        .collect::<BTreeSet<_>>();
    let remaining_modes = coverage
        .remaining
        .runtime_modes
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    require(
        frozen_modes == remaining_modes,
        "issuance runtime mode coverage is incomplete",
    )?;
    require(
        coverage.deployment == "candidate-only",
        "incomplete issuance host must remain candidate-only",
    )?;

    Ok(CoverageSummary {
        native_http: coverage.native_http.len(),
        remaining_http: coverage.remaining.http,
        remaining_grpc: coverage.remaining.grpc,
    })
}

fn canonical_lf(bytes: &[u8]) -> Vec<u8> {
    let mut canonical = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
            index += 1;
        }
        canonical.push(bytes[index]);
        index += 1;
    }
    canonical
}

fn require(condition: bool, message: &'static str) -> Result<(), MmfError> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}

fn invalid(message: &'static str) -> MmfError {
    MmfError::new(ErrorCode::InvalidState, message)
}

fn contract_error(message: &'static str, error: serde_json::Error) -> MmfError {
    invalid(message).with_detail("cause", error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{canonical_lf, validate_embedded_contract};

    #[test]
    fn provenance_hash_is_independent_of_checkout_line_endings() {
        assert_eq!(canonical_lf(b"first\r\nsecond\n"), b"first\nsecond\n");
    }

    #[test]
    fn embedded_surface_and_native_coverage_are_consistent() {
        let summary = validate_embedded_contract().expect("contract");
        assert_eq!(summary.native_http, 10);
        assert_eq!(summary.remaining_http, 121);
        assert_eq!(summary.remaining_grpc, 12);
    }
}
