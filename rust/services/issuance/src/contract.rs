use std::collections::{BTreeMap, BTreeSet};

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
const TRANSACTION_READS: &[u8] =
    include_bytes!("../../../../contracts/issuance-offer-transaction-reads.json");
const TOKEN_EXCHANGE: &[u8] = include_bytes!("../../../../contracts/issuance-token-exchange.json");
const PROOF_NONCE: &[u8] = include_bytes!("../../../../contracts/issuance-proof-nonce.json");
const CREDENTIAL_ADMISSION: &[u8] =
    include_bytes!("../../../../contracts/issuance-credential-admission.json");
const CREDENTIAL_SIGNING: &[u8] =
    include_bytes!("../../../../contracts/issuance-credential-signing.json");
const CANVAS_LTI: &[u8] =
    include_bytes!("../../../../contracts/issuance-canvas-lti-foundation.json");

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
    transaction_read_behavior_contract: Upstream,
    token_exchange_behavior_contract: Upstream,
    proof_nonce_behavior_contract: Upstream,
    credential_admission_behavior_contract: Upstream,
    credential_signing_behavior_contract: Upstream,
    canvas_lti_behavior_contract: Upstream,
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
    #[serde(default)]
    transaction_read_behavior_case: Option<String>,
    #[serde(default)]
    token_exchange_behavior_case: Option<String>,
    #[serde(default)]
    proof_nonce_behavior_case: Option<String>,
    #[serde(default)]
    credential_behavior_contract: bool,
    #[serde(default)]
    canvas_lti_behavior_case: Option<String>,
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
struct TransactionReadContract {
    schema: String,
    inputs: Value,
    cases: Vec<TransactionReadCase>,
    edge_cases: Vec<TransactionReadOutcome>,
    failures: Vec<TransactionReadOutcome>,
}

#[derive(Deserialize)]
struct TransactionReadOutcome {
    status_code: u16,
    body: Value,
    repository_calls: Vec<Value>,
}

#[derive(Deserialize)]
struct TransactionReadCase {
    operation: String,
    method: String,
    path: String,
    status_code: u16,
    body: Value,
    repository_calls: Vec<Value>,
}

#[derive(Deserialize)]
struct TokenExchangeContract {
    schema: String,
    inputs: Value,
    rate_limit: TokenRateLimit,
    dependency_failures: Vec<TokenDependencyFailure>,
    cases: Vec<TokenExchangeOutcome>,
    failures: Vec<TokenExchangeOutcome>,
}

#[derive(Deserialize)]
struct TokenDependencyFailure {
    status_code: u16,
    content_type: String,
    body: Value,
    repository_calls: Vec<Value>,
}

#[derive(Deserialize)]
struct TokenRateLimit {
    requests: usize,
    window_seconds: u64,
    request: Value,
    allowed_status_code: u16,
    status_code: u16,
    headers: BTreeMap<String, String>,
    body: Value,
}

#[derive(Deserialize)]
struct TokenExchangeOutcome {
    status_code: u16,
    body: Value,
    repository_calls: Vec<Value>,
}

#[derive(Deserialize)]
struct ProofNonceContract {
    schema: String,
    inputs: Value,
    nonce_shape: Value,
    persistence: Value,
    success: Value,
    failures: Vec<Value>,
    rate_limit: Value,
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
    let transaction_reads: TransactionReadContract = serde_json::from_slice(TRANSACTION_READS)
        .map_err(|error| contract_error("invalid transaction read contract", error))?;
    let token_exchange: TokenExchangeContract = serde_json::from_slice(TOKEN_EXCHANGE)
        .map_err(|error| contract_error("invalid token exchange contract", error))?;
    let proof_nonce: ProofNonceContract = serde_json::from_slice(PROOF_NONCE)
        .map_err(|error| contract_error("invalid proof nonce contract", error))?;
    let credential_admission: Value = serde_json::from_slice(CREDENTIAL_ADMISSION)
        .map_err(|error| contract_error("invalid credential admission contract", error))?;
    let credential_signing: Value = serde_json::from_slice(CREDENTIAL_SIGNING)
        .map_err(|error| contract_error("invalid credential signing contract", error))?;
    let canvas_lti: Value = serde_json::from_slice(CANVAS_LTI)
        .map_err(|error| contract_error("invalid Canvas LTI contract", error))?;
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
        transaction_reads.schema == "marty.issuance-offer-transaction-reads/v1"
            && transaction_reads.inputs["organization_id"] == "org-a"
            && transaction_reads.cases.len() == 5
            && transaction_reads.edge_cases.len() == 8
            && transaction_reads.failures.len() == 7
            && transaction_reads.cases.iter().all(|case| {
                case.method == "GET"
                    && case.status_code == 200
                    && !case.repository_calls.is_empty()
                    && (case.body.is_object() || case.body.is_array())
            })
            && transaction_reads
                .edge_cases
                .iter()
                .chain(&transaction_reads.failures)
                .all(|outcome| {
                    (200..600).contains(&outcome.status_code)
                        && (outcome.body.is_object() || outcome.body.is_array())
                        && outcome.repository_calls.iter().all(Value::is_object)
                }),
        "unexpected transaction read behavior contract",
    )?;
    require(
        token_exchange.schema == "marty.issuance-token-exchange/v1"
            && token_exchange.inputs["path"] == "/v1/issuance/token"
            && token_exchange.rate_limit.requests == 2
            && token_exchange.rate_limit.window_seconds == 17
            && token_exchange.rate_limit.request["form"]["grant_type"] == "unsupported"
            && token_exchange.rate_limit.allowed_status_code == 400
            && token_exchange.rate_limit.status_code == 429
            && token_exchange.rate_limit.headers.get("Retry-After") == Some(&"17".to_owned())
            && token_exchange.rate_limit.body
                == serde_json::json!({"detail": "Rate limit exceeded"})
            && token_exchange.dependency_failures.len() == 1
            && token_exchange.dependency_failures.iter().all(|failure| {
                failure.status_code == 500
                    && failure.content_type == "text/plain"
                    && failure.body == "Internal Server Error"
                    && !failure.repository_calls.is_empty()
            })
            && token_exchange.cases.len() == 4
            && token_exchange.failures.len() == 17
            && token_exchange
                .cases
                .iter()
                .chain(&token_exchange.failures)
                .all(|outcome| {
                    (200..600).contains(&outcome.status_code)
                        && outcome.body.is_object()
                        && outcome.repository_calls.iter().all(Value::is_object)
                }),
        "unexpected token exchange behavior contract",
    )?;
    require(
        proof_nonce.schema == "marty.issuance-proof-nonce/v1"
            && proof_nonce.inputs
                == serde_json::json!({
                    "path": "/v1/issuance/nonce",
                    "generated_nonce": "contract-proof-nonce",
                    "ttl_seconds": 300
                })
            && proof_nonce.nonce_shape
                == serde_json::json!({
                    "source_bytes": 32,
                    "encoded_length": 43,
                    "pattern": "^[A-Za-z0-9_-]{43}$"
                })
            && proof_nonce.persistence
                == serde_json::json!({
                    "digest_algorithm": "sha-256",
                    "digest_length": 64,
                    "plaintext_retained": false,
                    "single_use": true
                })
            && proof_nonce.success
                == serde_json::json!({
                    "status_code": 200,
                    "content_type": "application/json",
                    "headers": {"Cache-Control": "no-store"},
                    "body": {"c_nonce": "contract-proof-nonce"},
                    "repository_calls": [{
                        "method": "save_proof_nonce",
                        "value": "contract-proof-nonce",
                        "ttl_seconds": 300
                    }]
                })
            && proof_nonce.failures
                == [
                    serde_json::json!({
                        "name": "nonce_store_rejects_write",
                        "setup": "store_returns_false",
                        "status_code": 503,
                        "content_type": "application/json",
                        "body": {"detail": "Proof nonce storage is unavailable"}
                    }),
                    serde_json::json!({
                        "name": "nonce_store_is_unavailable",
                        "setup": "store_raises",
                        "status_code": 503,
                        "content_type": "application/json",
                        "body": {"detail": "Proof nonce storage is unavailable"}
                    }),
                ]
            && proof_nonce.rate_limit
                == serde_json::json!({
                    "requests": 2,
                    "window_seconds": 17,
                    "allowed_status_code": 200,
                    "status_code": 429,
                    "headers": {"Retry-After": "17"},
                    "body": {"detail": "Rate limit exceeded"},
                    "repository_call_count": 2
                }),
        "unexpected proof nonce behavior contract",
    )?;
    require(
        credential_admission["schema"] == "marty.issuance-credential-admission/v1"
            && credential_admission["cases"]
                .as_array()
                .is_some_and(|cases| cases.len() == 21)
            && credential_admission["inputs"]["path"] == "/v1/issuance/credential",
        "unexpected credential admission behavior contract",
    )?;
    require(
        credential_signing["schema"] == "marty.issuance-credential-signing/v1"
            && credential_signing["formats"]
                .as_array()
                .is_some_and(|formats| formats.len() == 4)
            && credential_signing["critical_order"]
                .as_array()
                .is_some_and(|events| events.len() == 9)
            && credential_signing["authorization_code_only"]["transaction_id"]
                == "dca62a6b-abc0-590d-906b-2582303615e5",
        "unexpected credential signing behavior contract",
    )?;
    require(
        canvas_lti["schema"] == "marty.issuance-canvas-lti-foundation/v1"
            && canvas_lti["scope"]["route_count"] == 12
            && canvas_lti["scope"]["routes"]
                .as_array()
                .is_some_and(|routes| routes.len() == 12)
            && canvas_lti["login"]["success"]["status_code"] == 303
            && canvas_lti["login"]["success"]["state_source_bytes"] == 32
            && canvas_lti["login"]["success"]["state_ttl_minutes"] == 10
            && canvas_lti["login"]["failures"]
                .as_array()
                .is_some_and(|failures| failures.len() == 5)
            && canvas_lti["launch"]["submission"]["accepted_content_types"]
                .as_array()
                .is_some_and(|content_types| content_types.len() == 2)
            && canvas_lti["launch"]["submission"]["failures"]
                .as_array()
                .is_some_and(|failures| failures.len() == 6)
            && canvas_lti["launch"]["private_response_fields"]
                .as_array()
                .is_some_and(|fields| fields.len() == 12)
            && canvas_lti["launch"]["public_response_vector"]["expected"]["verified"].as_bool()
                == Some(true),
        "unexpected Canvas LTI behavior contract",
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
        coverage.transaction_read_behavior_contract.repository == "ElevenID/marty-credentials"
            && coverage.transaction_read_behavior_contract.path
                == "contracts/issuance-offer-transaction-reads.json"
            && coverage.transaction_read_behavior_contract.commit.len() == 40
            && coverage
                .transaction_read_behavior_contract
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "invalid transaction read provenance",
    )?;
    require(
        coverage.token_exchange_behavior_contract.repository == "ElevenID/marty-credentials"
            && coverage.token_exchange_behavior_contract.path
                == "contracts/issuance-token-exchange.json"
            && coverage.token_exchange_behavior_contract.commit.len() == 40
            && coverage
                .token_exchange_behavior_contract
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "invalid token exchange provenance",
    )?;
    require(
        coverage.proof_nonce_behavior_contract.repository == "ElevenID/marty-credentials"
            && coverage.proof_nonce_behavior_contract.path == "contracts/issuance-proof-nonce.json"
            && coverage.proof_nonce_behavior_contract.commit.len() == 40
            && coverage
                .proof_nonce_behavior_contract
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "invalid proof nonce provenance",
    )?;
    require(
        coverage.credential_admission_behavior_contract.repository == "ElevenID/marty-credentials"
            && coverage.credential_admission_behavior_contract.path
                == "contracts/issuance-credential-admission.json"
            && coverage.credential_admission_behavior_contract.commit.len() == 40
            && coverage
                .credential_admission_behavior_contract
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "invalid credential admission provenance",
    )?;
    require(
        coverage.credential_signing_behavior_contract.repository == "ElevenID/marty-credentials"
            && coverage.credential_signing_behavior_contract.path
                == "contracts/issuance-credential-signing.json"
            && coverage.credential_signing_behavior_contract.commit.len() == 40
            && coverage
                .credential_signing_behavior_contract
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "invalid credential signing provenance",
    )?;
    require(
        coverage.canvas_lti_behavior_contract.repository == "ElevenID/marty-credentials"
            && coverage.canvas_lti_behavior_contract.path
                == "contracts/issuance-canvas-lti-foundation.json"
            && coverage.canvas_lti_behavior_contract.commit.len() == 40
            && coverage
                .canvas_lti_behavior_contract
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "invalid Canvas LTI provenance",
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
    let canonical_transaction_reads = canonical_lf(TRANSACTION_READS);
    let actual_transaction_reads = format!("{:x}", Sha256::digest(&canonical_transaction_reads));
    require(
        actual_transaction_reads == coverage.transaction_read_behavior_contract.sha256,
        "transaction read hash does not match provenance",
    )?;
    let canonical_token_exchange = canonical_lf(TOKEN_EXCHANGE);
    let actual_token_exchange = format!("{:x}", Sha256::digest(&canonical_token_exchange));
    require(
        actual_token_exchange == coverage.token_exchange_behavior_contract.sha256,
        "token exchange hash does not match provenance",
    )?;
    let canonical_proof_nonce = canonical_lf(PROOF_NONCE);
    let actual_proof_nonce = format!("{:x}", Sha256::digest(&canonical_proof_nonce));
    require(
        actual_proof_nonce == coverage.proof_nonce_behavior_contract.sha256,
        "proof nonce hash does not match provenance",
    )?;
    let canonical_credential_admission = canonical_lf(CREDENTIAL_ADMISSION);
    let actual_credential_admission =
        format!("{:x}", Sha256::digest(&canonical_credential_admission));
    require(
        actual_credential_admission == coverage.credential_admission_behavior_contract.sha256,
        "credential admission hash does not match provenance",
    )?;
    let canonical_credential_signing = canonical_lf(CREDENTIAL_SIGNING);
    let actual_credential_signing = format!("{:x}", Sha256::digest(&canonical_credential_signing));
    require(
        actual_credential_signing == coverage.credential_signing_behavior_contract.sha256,
        "credential signing hash does not match provenance",
    )?;
    let canonical_canvas_lti = canonical_lf(CANVAS_LTI);
    let actual_canvas_lti = format!("{:x}", Sha256::digest(&canonical_canvas_lti));
    require(
        actual_canvas_lti == coverage.canvas_lti_behavior_contract.sha256,
        "Canvas LTI hash does not match provenance",
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
    let mut native_transaction_read_cases = BTreeSet::new();
    let mut native_token_exchange_cases = BTreeSet::new();
    let mut native_proof_nonce_cases = BTreeSet::new();
    let mut native_credential_contract = false;
    let mut native_canvas_lti_cases = BTreeSet::new();
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
        let behavior_selector_count = usize::from(operation.response.is_some())
            + usize::from(operation.behavior_case.is_some())
            + usize::from(operation.tenant_behavior_case.is_some())
            + usize::from(operation.transaction_read_behavior_case.is_some())
            + usize::from(operation.token_exchange_behavior_case.is_some())
            + usize::from(operation.proof_nonce_behavior_case.is_some())
            + usize::from(operation.credential_behavior_contract)
            + usize::from(operation.canvas_lti_behavior_case.is_some());
        require(
            behavior_selector_count == 1,
            "native issuance operation must select exactly one behavior contract",
        )?;
        if operation.operation == "health_check" {
            let response = operation
                .response
                .as_ref()
                .ok_or_else(|| invalid("native issuance health response is missing"))?;
            require(
                operation.behavior_case.is_none()
                    && operation.proof_nonce_behavior_case.is_none()
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
                    && operation.transaction_read_behavior_case.is_none()
                    && operation.token_exchange_behavior_case.is_none()
                    && operation.proof_nonce_behavior_case.is_none()
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
                    && operation.transaction_read_behavior_case.is_none()
                    && operation.token_exchange_behavior_case.is_none()
                    && operation.proof_nonce_behavior_case.is_none()
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
        } else if let Some(behavior_case) = operation.transaction_read_behavior_case.as_deref() {
            require(
                operation.response.is_none()
                    && operation.behavior_case.is_none()
                    && operation.tenant_behavior_case.is_none()
                    && operation.token_exchange_behavior_case.is_none()
                    && operation.proof_nonce_behavior_case.is_none()
                    && native_transaction_read_cases.insert(behavior_case)
                    && transaction_reads.cases.iter().any(|case| {
                        let expected_path = match behavior_case {
                            "get_credential_offer" => "/v1/issuance/offers/tx-pending",
                            "list_transactions" => {
                                "/v1/issuance/transactions?organization_id=org-a"
                            }
                            "get_transaction" => "/v1/issuance/transactions/tx-revoked",
                            "get_transaction_revocation_status" => {
                                "/v1/issuance/transactions/tx-revoked/revocation-status"
                            }
                            "get_issuance_transaction_owner" => {
                                "/internal/v1/resource-owners/issuance-transactions/tx-pending"
                            }
                            _ => return false,
                        };
                        case.operation == behavior_case
                            && case.method == operation.method
                            && case.path == expected_path
                            && case.status_code == 200
                            && !case.repository_calls.is_empty()
                            && (case.body.is_object() || case.body.is_array())
                    }),
                "native issuance operation diverges from its transaction read case",
            )?;
        } else if let Some(behavior_case) = operation.token_exchange_behavior_case.as_deref() {
            require(
                operation.response.is_none()
                    && operation.behavior_case.is_none()
                    && operation.tenant_behavior_case.is_none()
                    && operation.transaction_read_behavior_case.is_none()
                    && operation.proof_nonce_behavior_case.is_none()
                    && behavior_case == "exchange_token"
                    && operation.operation == behavior_case
                    && operation.method == "POST"
                    && operation.path == "/v1/issuance/token"
                    && native_token_exchange_cases.insert(behavior_case)
                    && token_exchange.cases.len() == 4
                    && token_exchange.failures.len() == 17,
                "native issuance operation diverges from its token exchange contract",
            )?;
        } else if let Some(behavior_case) = operation.proof_nonce_behavior_case.as_deref() {
            require(
                operation.response.is_none()
                    && operation.behavior_case.is_none()
                    && operation.tenant_behavior_case.is_none()
                    && operation.transaction_read_behavior_case.is_none()
                    && operation.token_exchange_behavior_case.is_none()
                    && behavior_case == "nonce_endpoint"
                    && operation.operation == behavior_case
                    && operation.method == "POST"
                    && operation.path == "/v1/issuance/nonce"
                    && native_proof_nonce_cases.insert(behavior_case)
                    && proof_nonce.success["status_code"] == 200
                    && proof_nonce.failures.len() == 2,
                "native issuance operation diverges from its proof nonce contract",
            )?;
        } else if operation.credential_behavior_contract {
            require(
                !native_credential_contract
                    && operation.response.is_none()
                    && operation.behavior_case.is_none()
                    && operation.tenant_behavior_case.is_none()
                    && operation.transaction_read_behavior_case.is_none()
                    && operation.token_exchange_behavior_case.is_none()
                    && operation.proof_nonce_behavior_case.is_none()
                    && operation.operation == "issue_credential"
                    && operation.method == "POST"
                    && operation.path == "/v1/issuance/credential"
                    && credential_admission["cases"]
                        .as_array()
                        .is_some_and(|cases| cases.len() >= 20)
                    && credential_signing["formats"]
                        .as_array()
                        .is_some_and(|formats| formats.len() == 4),
                "native credential endpoint diverges from its admission or signing contract",
            )?;
            native_credential_contract = true;
        } else if let Some(behavior_case) = operation.canvas_lti_behavior_case.as_deref() {
            let expected_operation = match behavior_case {
                "login" => "initiate_canvas_lti_login_route",
                "experience-login" => "initiate_canvas_lti_experience_login_route",
                _ => return Err(invalid("unknown native Canvas LTI behavior case")),
            };
            require(
                operation.operation == expected_operation
                    && operation.method == "POST"
                    && native_canvas_lti_cases.insert(behavior_case)
                    && canvas_lti["scope"]["routes"]
                        .as_array()
                        .is_some_and(|routes| {
                            routes.iter().any(|route| {
                                route["method"] == operation.method
                                    && route["path"] == operation.path
                                    && route["operation"] == operation.operation
                                    && route["authentication"] == "public-lti-login"
                            })
                        }),
                "native Canvas LTI login operation diverges from its behavior contract",
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
    require(
        native_canvas_lti_cases == BTreeSet::from(["experience-login", "login"]),
        "native Canvas LTI login behavior coverage is incomplete",
    )?;
    let frozen_transaction_read_cases = transaction_reads
        .cases
        .iter()
        .map(|case| case.operation.as_str())
        .collect::<BTreeSet<_>>();
    require(
        native_transaction_read_cases == frozen_transaction_read_cases,
        "native transaction read behavior coverage is incomplete",
    )?;
    require(
        native_token_exchange_cases == BTreeSet::from(["exchange_token"]),
        "native token exchange behavior coverage is incomplete",
    )?;
    require(
        native_proof_nonce_cases == BTreeSet::from(["nonce_endpoint"]),
        "native proof nonce behavior coverage is incomplete",
    )?;
    require(
        native_credential_contract,
        "native credential endpoint behavior coverage is incomplete",
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
                "CANVAS_BINDING_READINESS_MAX_AGE_SECONDS",
                "CANVAS_LTI_STATE_TTL_MINUTES",
                "CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS",
                "CANVAS_PILOT_ORGANIZATION_IDS",
                "CANVAS_PORTABLE_INTEGRATION_ENABLED",
                "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST",
                "DATABASE_URL",
                "GRPC_SERVICE_TOKEN",
                "ISSUANCE_SERVICE_PORT",
                "ISSUANCE_API_KEY",
                "ISSUER_BASE_URL",
                "ISSUER_DISPLAY_NAME",
                "REVOCATION_PROFILE_SERVICE_URL",
                "SIGNING_KEYS_INTERNAL_API_KEY",
                "SIGNING_KEYS_INTERNAL_URL",
                "TOKEN_RATE_LIMIT",
                "TOKEN_RATE_WINDOW",
            ]
            && coverage.remaining.literal_environment_variables + 18 == environment_count
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
        coverage.deployment == "beta-path-split",
        "incomplete issuance host must remain beta-path-split",
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
    use sha2::{Digest, Sha256};

    use super::{
        canonical_lf, validate_embedded_contract, CANVAS_LTI, CREDENTIAL_ADMISSION,
        CREDENTIAL_SIGNING,
    };

    #[test]
    fn provenance_hash_is_independent_of_checkout_line_endings() {
        assert_eq!(canonical_lf(b"first\r\nsecond\n"), b"first\nsecond\n");
        assert_eq!(
            format!("{:x}", Sha256::digest(canonical_lf(CREDENTIAL_ADMISSION))),
            "8acbdaab9db036a65d32c377debb69e4415bacf61d417b5fa2b43dc6f5388c1b"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(canonical_lf(CREDENTIAL_SIGNING))),
            "efa4fd2857dd6e2a41d6c0fa1e4909b5614075a5d01b5dcf9694a6d4d7229d52"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(canonical_lf(CANVAS_LTI))),
            "e230e2c41d6df8f5ded4a2b080bb44936a24a9248c89047aa006de5ff5760c61"
        );
    }

    #[test]
    fn embedded_surface_and_native_coverage_are_consistent() {
        let summary = validate_embedded_contract().expect("contract");
        assert_eq!(summary.native_http, 20);
        assert_eq!(summary.remaining_http, 111);
        assert_eq!(summary.remaining_grpc, 12);
    }
}
