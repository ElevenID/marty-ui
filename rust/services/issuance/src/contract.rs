use std::collections::BTreeSet;

use mmf_core::{ErrorCode, MmfError};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const SURFACE: &[u8] = include_bytes!("../../../../contracts/issuance-runtime-surface.json");
const COVERAGE: &str = include_str!("../../../../contracts/issuance-native-coverage.json");

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
    response: ExpectedResponse,
}

#[derive(Deserialize)]
struct ExpectedResponse {
    status_code: u16,
    body: Value,
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
    require(
        surface["schema"] == "marty.issuance-runtime-surface/v1",
        "unexpected issuance surface schema",
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
        require(
            operation.response.status_code == 200
                && operation.response.body
                    == serde_json::json!({
                        "status": "healthy",
                        "service": "issuance-service"
                    }),
            "native issuance health response diverges from the legacy contract",
        )?;
    }
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
        coverage.native_environment_variables == ["ISSUANCE_SERVICE_PORT"]
            && coverage.remaining.literal_environment_variables + 1 == environment_count
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
        assert_eq!(summary.native_http, 1);
        assert_eq!(summary.remaining_http, 130);
        assert_eq!(summary.remaining_grpc, 12);
    }
}
