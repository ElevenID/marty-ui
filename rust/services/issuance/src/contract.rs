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
const CANVAS_OAUTH: &[u8] =
    include_bytes!("../../../../contracts/issuance-canvas-oauth-lifecycle.json");
const CANVAS_MANAGEMENT: &[u8] =
    include_bytes!("../../../../contracts/issuance-canvas-management.json");
const CANVAS_OPERATIONS: &[u8] =
    include_bytes!("../../../../contracts/issuance-canvas-operations.json");
const CREDENTIAL_LIFECYCLE: &[u8] =
    include_bytes!("../../../../contracts/issuance-credential-lifecycle.json");
const INITIATION: &[u8] = include_bytes!("../../../../contracts/issuance-initiation.json");
const APPLICATION_TEMPLATES: &[u8] =
    include_bytes!("../../../../contracts/issuance-application-templates.json");
const INTERNAL_APPLICATIONS: &[u8] =
    include_bytes!("../../../../contracts/issuance-internal-applications.json");
const RESOURCE_OWNERS: &[u8] =
    include_bytes!("../../../../contracts/issuance-resource-owner-lookups.json");
const DIDCOMM: &[u8] =
    include_bytes!("../../../../contracts/gateway-didcomm-delivery-behavior.json");
const RENEWAL_REFERENCE: &[u8] =
    include_bytes!("../../../../contracts/credential-renewal-python-reference.json");

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
    canvas_oauth_behavior_contract: Upstream,
    canvas_management_behavior_contract: Upstream,
    credential_lifecycle_behavior_contract: Upstream,
    initiation_behavior_contract: Upstream,
    application_template_behavior_contract: Upstream,
    internal_application_behavior_contract: Upstream,
    resource_owner_behavior_contract: ResourceOwnerBehaviorContract,
    renewal_behavior_contract: RenewalBehaviorContract,
    native_http: Vec<HttpOperation>,
    native_grpc: Vec<String>,
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
struct RenewalBehaviorContract {
    path: String,
    sha256: String,
    intentional_native_corrections: Vec<String>,
}

#[derive(Deserialize)]
struct ResourceOwnerBehaviorContract {
    path: String,
    sha256: String,
    source_repository: String,
    source_path: String,
    source_commit: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    credential_lifecycle_behavior_contract: bool,
    #[serde(default)]
    didcomm_behavior_contract: bool,
    #[serde(default)]
    initiation_behavior_contract: bool,
    #[serde(default)]
    renewal_behavior_contract: bool,
    #[serde(default)]
    canvas_lti_behavior_case: Option<String>,
    #[serde(default)]
    canvas_oauth_behavior_case: Option<String>,
    #[serde(default)]
    canvas_management_behavior_case: Option<String>,
    #[serde(default)]
    application_template_behavior_case: Option<String>,
    #[serde(default)]
    internal_application_behavior_case: Option<String>,
    #[serde(default)]
    resource_owner_behavior_contract: bool,
    #[serde(default)]
    canvas_operations_behavior_case: Option<CanvasOperationsCase>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
enum CanvasOperationsCase {
    Enqueue,
    Jobs,
    Job,
    Retry,
    ResolveJob,
    Candidates,
    Reviews,
    ResolveReview,
}

impl CanvasOperationsCase {
    const ALL: [Self; 8] = [
        Self::Enqueue,
        Self::Jobs,
        Self::Job,
        Self::Retry,
        Self::ResolveJob,
        Self::Candidates,
        Self::Reviews,
        Self::ResolveReview,
    ];

    fn route(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Enqueue => (
                "POST",
                "/applications/{application_id}/canvas-sync",
                "enqueue_canvas_application_sync_route",
            ),
            Self::Jobs => ("GET", "/canvas-sync-jobs", "list_canvas_sync_jobs_route"),
            Self::Job => (
                "GET",
                "/canvas-sync-jobs/{job_id}",
                "get_canvas_sync_job_route",
            ),
            Self::Retry => (
                "POST",
                "/canvas-sync-jobs/{job_id}/retry",
                "retry_canvas_sync_job_route",
            ),
            Self::ResolveJob => (
                "POST",
                "/canvas-sync-jobs/{job_id}/resolve",
                "resolve_canvas_sync_job_route",
            ),
            Self::Candidates => (
                "GET",
                "/canvas-award-candidates",
                "list_canvas_award_candidates_route",
            ),
            Self::Reviews => (
                "GET",
                "/evidence-policy-reviews",
                "list_evidence_policy_reviews_route",
            ),
            Self::ResolveReview => (
                "POST",
                "/evidence-policy-reviews/{review_id}/resolve",
                "resolve_evidence_policy_review_route",
            ),
        }
    }
}

impl HttpOperation {
    fn behavior_selector_count(&self) -> usize {
        usize::from(self.response.is_some())
            + usize::from(self.behavior_case.is_some())
            + usize::from(self.tenant_behavior_case.is_some())
            + usize::from(self.transaction_read_behavior_case.is_some())
            + usize::from(self.token_exchange_behavior_case.is_some())
            + usize::from(self.proof_nonce_behavior_case.is_some())
            + usize::from(self.credential_behavior_contract)
            + usize::from(self.credential_lifecycle_behavior_contract)
            + usize::from(self.didcomm_behavior_contract)
            + usize::from(self.initiation_behavior_contract)
            + usize::from(self.renewal_behavior_contract)
            + usize::from(self.canvas_lti_behavior_case.is_some())
            + usize::from(self.canvas_oauth_behavior_case.is_some())
            + usize::from(self.canvas_management_behavior_case.is_some())
            + usize::from(self.application_template_behavior_case.is_some())
            + usize::from(self.internal_application_behavior_case.is_some())
            + usize::from(self.resource_owner_behavior_contract)
            + usize::from(self.canvas_operations_behavior_case.is_some())
    }
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
    let didcomm: Value = serde_json::from_slice(DIDCOMM)
        .map_err(|error| contract_error("invalid DIDComm delivery contract", error))?;
    let initiation: Value = serde_json::from_slice(INITIATION)
        .map_err(|error| contract_error("invalid initiation contract", error))?;
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
    let canvas_oauth: Value = serde_json::from_slice(CANVAS_OAUTH)
        .map_err(|error| contract_error("invalid Canvas OAuth contract", error))?;
    let canvas_management: Value = serde_json::from_slice(CANVAS_MANAGEMENT)
        .map_err(|error| contract_error("invalid Canvas management contract", error))?;
    let credential_lifecycle: Value = serde_json::from_slice(CREDENTIAL_LIFECYCLE)
        .map_err(|error| contract_error("invalid credential lifecycle contract", error))?;
    let application_templates: Value = serde_json::from_slice(APPLICATION_TEMPLATES)
        .map_err(|error| contract_error("invalid application template contract", error))?;
    let internal_applications: Value = serde_json::from_slice(INTERNAL_APPLICATIONS)
        .map_err(|error| contract_error("invalid internal application contract", error))?;
    let resource_owners: Value = serde_json::from_slice(RESOURCE_OWNERS)
        .map_err(|error| contract_error("invalid resource-owner contract", error))?;
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
                == Some(true)
            && canvas_lti["experience"]["bootstrap"]["ordered_stages"]
                .as_array()
                .is_some_and(|stages| stages.len() == 12)
            && canvas_lti["experience"]["bootstrap"]["template"]["failures"]
                .as_array()
                .is_some_and(|failures| failures.len() == 3)
            && canvas_lti["experience"]["bootstrap"]["new_application"]["caller_protected_fields"]
                .as_array()
                .is_some_and(|fields| fields.len() == 3)
            && canvas_lti["experience"]["bootstrap"]["response"]["private_fields_forbidden"]
                .as_array()
                .is_some_and(|fields| fields.len() == 9),
        "unexpected Canvas LTI behavior contract",
    )?;
    require(
        canvas_oauth["schema"] == "marty.issuance-canvas-oauth-lifecycle/v1"
            && canvas_oauth["scope"]["routes"]
                .as_array()
                .is_some_and(|routes| routes.len() == 3)
            && canvas_oauth["start"]["authorization"]["persisted_state"] == "sha256-only"
            && canvas_oauth["start"]["authorization"]["ttl_seconds"] == 600
            && canvas_oauth["callback"]["redirect_status_code"] == 303
            && canvas_oauth["callback"]["publication"]["platform_snapshot_cas"] == true
            && canvas_oauth["callback"]["publication"]["connection_insert_only_cas"] == true
            && canvas_oauth["callback"]["publication"]["browser_token_disclosure"] == false
            && canvas_oauth["disconnect"]["retry"]["maximum_seconds"] == 3600
            && canvas_oauth["disconnect"]["retry"]["durable"] == true
            && canvas_oauth["security_invariants"]
                .as_array()
                .is_some_and(|invariants| invariants.len() == 9),
        "unexpected Canvas OAuth behavior contract",
    )?;
    require(
        canvas_management["schema"] == "marty.issuance-canvas-management/v1"
            && canvas_management["scope"]["route_count"] == 31
            && canvas_management["scope"]["routes"]
                .as_array()
                .is_some_and(|routes| routes.len() == 31)
            && canvas_management["legacy_ingest"]["default_enabled"] == false
            && canvas_management["legacy_ingest"]["disabled_before_body_or_repository_processing"]
                == true
            && canvas_management["application_approval"]["uses_canonical_issuance_guard"] == true
            && canvas_management["canvas_credentials_provider_validation"]
                ["never_publishes_a_credential"]
                == true
            && canvas_management["security_invariants"]
                .as_array()
                .is_some_and(|invariants| invariants.len() == 11),
        "unexpected Canvas management behavior contract",
    )?;
    require(
        credential_lifecycle["schema"] == "marty.issuance-credential-lifecycle/v1"
            && credential_lifecycle["scope"]["http"]
                .as_array()
                .is_some_and(|routes| routes.len() == 4)
            && credential_lifecycle["scope"]["grpc"]
                .as_array()
                .is_some_and(|methods| methods.len() == 4)
            && credential_lifecycle["request"]["reason"]["maximum_characters"] == 2000
            && credential_lifecycle["transitions"]
                .as_array()
                .is_some_and(|transitions| transitions.len() == 3)
            && credential_lifecycle["mutation_order"]
                == serde_json::json!([
                    "load-credential",
                    "enforce-resource-organization-when-http",
                    "validate-transition",
                    "publish-revocation-profile-status",
                    "persist-local-status",
                    "synchronize-canvas-delivery-records",
                    "emit-grpc-stream-event",
                    "return-response"
                ])
            && credential_lifecycle["publication"]["revocation_profile"]
                == "required-before-local-persistence"
            && credential_lifecycle["publication"]["grpc_stream_event"]
                == "after-canonical-handler-success"
            && credential_lifecycle["failures"]
                .as_array()
                .is_some_and(|failures| failures.len() == 7)
            && credential_lifecycle["security_invariants"]
                .as_array()
                .is_some_and(|invariants| invariants.len() == 4),
        "unexpected credential lifecycle behavior contract",
    )?;
    require(
        application_templates["schema"] == "marty.issuance-application-templates/v1"
            && application_templates["surface"]["base_path"] == "/v1/application-templates"
            && application_templates["surface"]["routes"]
                .as_array()
                .is_some_and(|routes| routes.len() == 8)
            && application_templates["security"]["authentication"]
                == "X-API-Key management key on every route"
            && application_templates["security"]["trusted_tenant_header"]
                == "X-Organization-ID"
            && application_templates["native_cutover_repairs"]["atomic_lifecycle"]["required"]
                == true
            && application_templates["native_cutover_repairs"]["catalog_lookup"]
                == "validation uses strict authenticated credential-template gRPC and does not fall back to HTTP",
        "unexpected application template behavior contract",
    )?;
    require(
        internal_applications["schema"] == "marty.issuance-internal-applications/v1"
            && internal_applications["surface"]["base_path"] == "/internal/applications"
            && internal_applications["surface"]["routes"]
                .as_array()
                .is_some_and(|routes| routes.len() == 14)
            && internal_applications["coverage"]["rust_implementation_authorized"] == true
            && internal_applications["coverage"]["required_before_rust_implementation"]
                .as_array()
                .is_some_and(Vec::is_empty)
            && internal_applications["source_revision"]["approved_repairs"]
                == serde_json::json!([
                    "9907d99: read issuance state from IssuanceTransaction while applications remain approved",
                    "843c0e5: restore name, email, then generated applicant identifier precedence",
                    "073b177: redact provider transport exception details from external evidence API responses",
                    "877253d: reserve replayed application offers idempotently",
                    "1dda8ac: map invalid status filters to a stable validation response",
                    "3bee6f7: fail closed on missing offer dependencies and issuer context",
                    "validate active tenant-owned revocation bindings before ordinary approval",
                    "commit manual lifecycle transitions and non-Canvas issuance reservations atomically",
                    "commit external-evidence and reconciliation application, fact, transaction, and audit write sets atomically",
                    "preserve issuance-specific Canvas offer readiness errors separately from approval errors",
                    "retain secret-safe structured diagnostics for provider, Canvas, issuer-context, and wallet-catalog failures"
                ]),
        "unexpected internal application behavior contract",
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
        coverage.canvas_oauth_behavior_contract.repository == "ElevenID/marty-credentials"
            && coverage.canvas_oauth_behavior_contract.path
                == "contracts/issuance-canvas-oauth-lifecycle.json"
            && coverage.canvas_oauth_behavior_contract.commit.len() == 40
            && coverage
                .canvas_oauth_behavior_contract
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "invalid Canvas OAuth provenance",
    )?;
    require(
        coverage.canvas_management_behavior_contract.repository == "ElevenID/marty-credentials"
            && coverage.canvas_management_behavior_contract.path
                == "contracts/issuance-canvas-management.json"
            && coverage.canvas_management_behavior_contract.commit.len() == 40
            && coverage
                .canvas_management_behavior_contract
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "invalid Canvas management provenance",
    )?;
    require(
        coverage.credential_lifecycle_behavior_contract.repository == "ElevenID/marty-credentials"
            && coverage.credential_lifecycle_behavior_contract.path
                == "contracts/issuance-credential-lifecycle.json"
            && coverage.credential_lifecycle_behavior_contract.commit.len() == 40
            && coverage
                .credential_lifecycle_behavior_contract
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "invalid credential lifecycle provenance",
    )?;
    require(
        coverage.initiation_behavior_contract.repository == "ElevenID/marty-credentials"
            && coverage.initiation_behavior_contract.path == "contracts/issuance-initiation.json"
            && coverage.initiation_behavior_contract.commit.len() == 40
            && coverage
                .initiation_behavior_contract
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "invalid initiation provenance",
    )?;
    require(
        coverage.application_template_behavior_contract.repository == "ElevenID/marty-credentials"
            && coverage.application_template_behavior_contract.path
                == "contracts/issuance-application-templates.json"
            && coverage.application_template_behavior_contract.commit.len() == 40
            && coverage
                .application_template_behavior_contract
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "invalid application template provenance",
    )?;
    require(
        coverage.internal_application_behavior_contract.repository == "ElevenID/marty-credentials"
            && coverage.internal_application_behavior_contract.path
                == "contracts/issuance-internal-applications.json"
            && coverage.internal_application_behavior_contract.commit.len() == 40
            && coverage
                .internal_application_behavior_contract
                .commit
                .chars()
                .all(|character| character.is_ascii_hexdigit()),
        "invalid internal application provenance",
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
    let canonical_canvas_oauth = canonical_lf(CANVAS_OAUTH);
    let actual_canvas_oauth = format!("{:x}", Sha256::digest(&canonical_canvas_oauth));
    require(
        actual_canvas_oauth == coverage.canvas_oauth_behavior_contract.sha256,
        "Canvas OAuth hash does not match provenance",
    )?;
    let canonical_canvas_management = canonical_lf(CANVAS_MANAGEMENT);
    let actual_canvas_management = format!("{:x}", Sha256::digest(&canonical_canvas_management));
    require(
        actual_canvas_management == coverage.canvas_management_behavior_contract.sha256,
        "Canvas management hash does not match provenance",
    )?;
    let canonical_credential_lifecycle = canonical_lf(CREDENTIAL_LIFECYCLE);
    let actual_credential_lifecycle =
        format!("{:x}", Sha256::digest(&canonical_credential_lifecycle));
    require(
        actual_credential_lifecycle == coverage.credential_lifecycle_behavior_contract.sha256,
        "credential lifecycle hash does not match provenance",
    )?;
    let canonical_initiation = canonical_lf(INITIATION);
    let actual_initiation = format!("{:x}", Sha256::digest(&canonical_initiation));
    require(
        actual_initiation == coverage.initiation_behavior_contract.sha256,
        "initiation hash does not match provenance",
    )?;
    let canonical_application_templates = canonical_lf(APPLICATION_TEMPLATES);
    let actual_application_templates =
        format!("{:x}", Sha256::digest(&canonical_application_templates));
    require(
        actual_application_templates == coverage.application_template_behavior_contract.sha256,
        "application template hash does not match provenance",
    )?;
    let canonical_internal_applications = canonical_lf(INTERNAL_APPLICATIONS);
    let actual_internal_applications =
        format!("{:x}", Sha256::digest(&canonical_internal_applications));
    require(
        actual_internal_applications == coverage.internal_application_behavior_contract.sha256,
        "internal application hash does not match provenance",
    )?;
    let canonical_resource_owners = canonical_lf(RESOURCE_OWNERS);
    let actual_resource_owners = format!("{:x}", Sha256::digest(&canonical_resource_owners));
    require(
        actual_resource_owners == coverage.resource_owner_behavior_contract.sha256
            && coverage.resource_owner_behavior_contract.path
                == "contracts/issuance-resource-owner-lookups.json"
            && coverage.resource_owner_behavior_contract.source_repository
                == "ElevenID/marty-credentials"
            && coverage.resource_owner_behavior_contract.source_path
                == "services/issuance/infrastructure/api/routes.py"
            && coverage.resource_owner_behavior_contract.source_commit
                == "15af5232df376bb9596b5aed3703110bf890fce5"
            && resource_owners["schema"] == "marty.issuance-resource-owner-lookups/v1"
            && resource_owners["authentication"]["order"]
                == serde_json::json!([
                    "authenticate",
                    "unscoped_lookup",
                    "not_found",
                    "project_owner"
                ])
            && resource_owners["authentication"]["trusted_tenant_header"] == "ignored"
            && resource_owners["authentication"]["header"] == "X-API-Key"
            && resource_owners["authentication"]["server_setting"] == "ISSUANCE_API_KEY"
            && resource_owners["persistence"]
                == serde_json::json!({
                    "read_only": true,
                    "projection": ["organization_id"],
                    "id_scope": "unscoped"
                })
            && resource_owners["responses"]
                == serde_json::json!({
                    "found": {"status_code": 200, "body": {"organization_id": "org-owner"}},
                    "not_found": {"status_code": 404, "body": {"detail": "Resource not found"}},
                    "api_key_unconfigured": {"status_code": 503, "body": {"detail": "ISSUANCE_API_KEY not configured on server"}},
                    "api_key_missing": {"status_code": 401, "body": {"detail": "X-API-Key header is missing"}},
                    "api_key_invalid": {"status_code": 401, "body": {"detail": "Invalid API Key"}},
                    "repository_unavailable": {"status_code": 500, "body": {"detail": "Issuance transaction data is temporarily unavailable"}, "cause_disclosed": false}
                })
            && resource_owners["gateway"]
                == serde_json::json!({
                    "service": "issuance-native",
                    "api_key_source": "ISSUANCE_API_KEY",
                    "foreign_owner_result": 403,
                    "missing_owner_result": "continue ordinary authorization and upstream 404 semantics",
                    "provider_failure_result": {"status_code": 500, "detail": "Authorization service unavailable"}
                })
            && resource_owners["operations"]
                .as_array()
                .is_some_and(|operations| operations.len() == 3),
        "resource-owner contract or provenance is invalid",
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
    let frozen_grpc_methods = grpc_methods
        .iter()
        .filter_map(|method| method["method"].as_str())
        .collect::<BTreeSet<_>>();
    let native_grpc_methods = coverage
        .native_grpc
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    require(
        native_grpc_methods.len() == coverage.native_grpc.len()
            && native_grpc_methods.is_subset(&frozen_grpc_methods),
        "native issuance gRPC coverage is invalid",
    )?;

    let mut native = BTreeSet::new();
    let mut native_behavior_cases = BTreeSet::new();
    let mut native_tenant_behavior_cases = BTreeSet::new();
    let mut native_transaction_read_cases = BTreeSet::new();
    let mut native_token_exchange_cases = BTreeSet::new();
    let mut native_proof_nonce_cases = BTreeSet::new();
    let mut native_credential_contract = false;
    let mut native_credential_lifecycle_operations = BTreeSet::new();
    let mut native_didcomm_contract = false;
    let mut native_initiation_contract = false;
    let mut native_renewal_contract = false;
    require(
        coverage.renewal_behavior_contract.path
            == "contracts/credential-renewal-python-reference.json"
            && coverage.renewal_behavior_contract.sha256
                == "136b046f08c58d2a7fa70982404dabd7265164d91f49ee184cfbc63eb49b3f0f"
            && format!("{:x}", Sha256::digest(canonical_lf(RENEWAL_REFERENCE)))
                == coverage.renewal_behavior_contract.sha256
            && coverage
                .renewal_behavior_contract
                .intentional_native_corrections
                == [
                    "RENEWAL-001:links-before-delivery",
                    "RENEWAL-002:pending-uri-on-unsent-delivery",
                    "RENEWAL-003:atomic-canvas-successor-association",
                ],
        "renewal reference or governed native corrections changed",
    )?;
    let renewal_reference: Value = serde_json::from_slice(RENEWAL_REFERENCE)
        .map_err(|error| contract_error("invalid renewal reference", error))?;
    let mut native_canvas_lti_cases = BTreeSet::new();
    let mut native_canvas_oauth_cases = BTreeSet::new();
    let mut native_canvas_management_cases = BTreeSet::new();
    let mut native_application_template_cases = BTreeSet::new();
    let mut native_internal_application_cases = BTreeSet::new();
    let mut native_resource_owner_operations = BTreeSet::new();
    // Freeze the already-qualified source contract; changing its historical
    // limits/status text is not necessary to select the eight exact operations.
    require(
        format!("{:x}", Sha256::digest(canonical_lf(CANVAS_OPERATIONS)))
            == "73f4ac04e2158f9b84ca69fdfeff74191434d4739cb4252ca0daf98aa3b69120",
        "Canvas operations behavior provenance changed",
    )?;
    let canvas_operations: Value = serde_json::from_slice(CANVAS_OPERATIONS)
        .map_err(|error| contract_error("invalid Canvas operations contract", error))?;
    let mut native_canvas_operations_cases = BTreeSet::new();
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
            operation.behavior_selector_count() == 1,
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
        } else if operation.resource_owner_behavior_contract {
            let frozen = resource_owners["operations"]
                .as_array()
                .ok_or_else(|| invalid("resource-owner operations are missing"))?;
            require(
                operation.response.is_none()
                    && frozen.iter().any(|candidate| {
                        candidate["method"] == operation.method
                            && candidate["path"] == operation.path
                            && candidate["operation"] == operation.operation
                    })
                    && native_resource_owner_operations.insert(operation.operation.as_str()),
                "native resource-owner operation diverges from its behavior contract",
            )?;
        } else if operation.renewal_behavior_contract {
            require(
                !native_renewal_contract,
                "duplicate native renewal contract",
            )?;
            validate_renewal_operation(operation, &renewal_reference)?;
            native_renewal_contract = true;
        } else if operation.initiation_behavior_contract {
            require(
                !native_initiation_contract,
                "duplicate native initiation contract",
            )?;
            validate_initiation_operation(operation, &initiation)?;
            native_initiation_contract = true;
        } else if operation.didcomm_behavior_contract {
            require(
                !native_didcomm_contract,
                "duplicate native DIDComm contract",
            )?;
            validate_didcomm_operation(operation, &didcomm)?;
            native_didcomm_contract = true;
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
        } else if operation.credential_lifecycle_behavior_contract {
            validate_credential_lifecycle_operation(operation, &credential_lifecycle)?;
            require(
                native_credential_lifecycle_operations.insert(operation.operation.as_str()),
                "duplicate native credential lifecycle operation",
            )?;
        } else if let Some(behavior_case) = operation.canvas_lti_behavior_case.as_deref() {
            let expected_operation = match behavior_case {
                "login" => "initiate_canvas_lti_login_route",
                "experience" => "launch_canvas_lti_experience_route",
                "experience-exchange" => "exchange_canvas_lti_experience_code_route",
                "experience-session-current" => "get_canvas_lti_experience_session_route",
                "experience-bootstrap" => "bootstrap_canvas_lti_experience_application_route",
                "experience-deep-linking" => "create_canvas_lti_deep_linking_response_route",
                "experience-evidence-status" => "get_canvas_lti_evidence_status",
                "experience-evidence-sync" => "sync_canvas_lti_evidence",
                "experience-login" => "initiate_canvas_lti_experience_login_route",
                "tool-jwks" => "get_canvas_lti_tool_jwks",
                "launch" => "verify_canvas_lti_launch_route",
                _ => return Err(invalid("unknown native Canvas LTI behavior case")),
            };
            let expected_authentication = match behavior_case {
                "launch" | "experience" => "public-lti-form-post",
                "experience-exchange" => "public-one-time-code",
                "experience-session-current"
                | "experience-bootstrap"
                | "experience-deep-linking"
                | "experience-evidence-status"
                | "experience-evidence-sync" => "lti-session-bearer",
                "tool-jwks" => "public",
                _ => "public-lti-login",
            };
            let expected_method = if matches!(
                behavior_case,
                "experience-session-current" | "experience-evidence-status" | "tool-jwks"
            ) {
                "GET"
            } else {
                "POST"
            };
            require(
                operation.operation == expected_operation
                    && operation.method == expected_method
                    && native_canvas_lti_cases.insert(behavior_case)
                    && canvas_lti["scope"]["routes"]
                        .as_array()
                        .is_some_and(|routes| {
                            routes.iter().any(|route| {
                                route["method"] == operation.method
                                    && route["path"] == operation.path
                                    && route["operation"] == operation.operation
                                    && route["authentication"] == expected_authentication
                            })
                        }),
                "native Canvas LTI operation diverges from its behavior contract",
            )?;
        } else if let Some(behavior_case) = operation.canvas_oauth_behavior_case.as_deref() {
            let (expected_method, expected_operation, expected_authentication) = match behavior_case
            {
                "start" => (
                    "POST",
                    "start_canvas_oauth_connection",
                    "management-api-key-and-trusted-organization",
                ),
                "callback" => (
                    "GET",
                    "complete_canvas_oauth_connection",
                    "public-one-time-state",
                ),
                "disconnect" => (
                    "DELETE",
                    "disconnect_canvas_oauth_connection",
                    "management-api-key-and-trusted-organization",
                ),
                _ => return Err(invalid("unknown native Canvas OAuth behavior case")),
            };
            require(
                operation.operation == expected_operation
                    && operation.method == expected_method
                    && native_canvas_oauth_cases.insert(behavior_case)
                    && canvas_oauth["scope"]["routes"]
                        .as_array()
                        .is_some_and(|routes| {
                            routes.iter().any(|route| {
                                route["method"] == operation.method
                                    && route["path"] == operation.path
                                    && route["operation"] == operation.operation
                                    && route["authentication"] == expected_authentication
                            })
                        }),
                "native Canvas OAuth operation diverges from its behavior contract",
            )?;
        } else if let Some(behavior_case) = operation.canvas_management_behavior_case.as_deref() {
            require(
                behavior_case == operation.operation
                    && native_canvas_management_cases.insert(behavior_case)
                    && canvas_management["scope"]["routes"]
                        .as_array()
                        .is_some_and(|routes| {
                            routes.iter().any(|route| {
                                route["method"] == operation.method
                                    && route["path"] == operation.path
                                    && route["operation"] == operation.operation
                            })
                        }),
                "native Canvas management operation diverges from its behavior contract",
            )?;
        } else if let Some(behavior_case) = operation.application_template_behavior_case.as_deref()
        {
            validate_application_template_operation(operation, &application_templates)?;
            require(
                native_application_template_cases.insert(behavior_case),
                "duplicate native application template behavior case",
            )?;
        } else if let Some(behavior_case) = operation.internal_application_behavior_case.as_deref()
        {
            validate_internal_application_operation(operation, &internal_applications)?;
            require(
                native_internal_application_cases.insert(behavior_case),
                "duplicate native internal application behavior case",
            )?;
        } else if let Some(behavior_case) = operation.canvas_operations_behavior_case {
            validate_canvas_operations_operation(operation, &canvas_operations)?;
            require(
                native_canvas_operations_cases.insert(behavior_case),
                "duplicate native Canvas operations behavior case",
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
        native_canvas_lti_cases
            == BTreeSet::from([
                "experience",
                "experience-exchange",
                "experience-login",
                "experience-session-current",
                "experience-bootstrap",
                "experience-deep-linking",
                "experience-evidence-status",
                "experience-evidence-sync",
                "launch",
                "login",
                "tool-jwks",
            ]),
        "native Canvas LTI behavior coverage is incomplete",
    )?;
    require(
        native_canvas_oauth_cases == BTreeSet::from(["callback", "disconnect", "start"]),
        "native Canvas OAuth behavior coverage is incomplete",
    )?;
    let frozen_canvas_management_routes = canvas_management["scope"]["routes"]
        .as_array()
        .ok_or_else(|| invalid("Canvas management routes are missing"))?;
    let frozen_canvas_management_cases = frozen_canvas_management_routes
        .iter()
        .filter_map(|route| route["operation"].as_str())
        .collect::<BTreeSet<_>>();
    require(
        native_canvas_management_cases == frozen_canvas_management_cases,
        "native Canvas management behavior coverage is incomplete",
    )?;
    require(
        native_canvas_operations_cases == BTreeSet::from(CanvasOperationsCase::ALL),
        "native Canvas operations behavior coverage is incomplete",
    )?;
    let frozen_application_template_cases = application_templates["surface"]["routes"]
        .as_array()
        .ok_or_else(|| invalid("application template routes are missing"))?
        .iter()
        .filter_map(|route| route["operation"].as_str())
        .collect::<BTreeSet<_>>();
    require(
        native_application_template_cases == frozen_application_template_cases,
        "native application template behavior coverage is incomplete",
    )?;
    let frozen_internal_application_cases = internal_applications["surface"]["routes"]
        .as_array()
        .ok_or_else(|| invalid("internal application routes are missing"))?
        .iter()
        .filter_map(|route| route["operation"].as_str())
        .collect::<BTreeSet<_>>();
    require(
        native_internal_application_cases == frozen_internal_application_cases,
        "native internal application behavior coverage is incomplete",
    )?;
    let frozen_resource_owner_operations = resource_owners["operations"]
        .as_array()
        .ok_or_else(|| invalid("resource-owner operations are missing"))?
        .iter()
        .filter_map(|operation| operation["operation"].as_str())
        .collect::<BTreeSet<_>>();
    require(
        native_resource_owner_operations == frozen_resource_owner_operations,
        "native resource-owner behavior coverage is incomplete",
    )?;
    let frozen_transaction_read_cases = transaction_reads
        .cases
        .iter()
        .map(|case| case.operation.as_str())
        .filter(|operation| *operation != "get_issuance_transaction_owner")
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
    let frozen_credential_lifecycle_operations = credential_lifecycle["scope"]["http"]
        .as_array()
        .ok_or_else(|| invalid("credential lifecycle HTTP routes are missing"))?
        .iter()
        .filter_map(|route| route["operation"].as_str())
        .collect::<BTreeSet<_>>();
    require(
        native_credential_lifecycle_operations == frozen_credential_lifecycle_operations,
        "native credential lifecycle behavior coverage is incomplete",
    )?;
    require(
        native_didcomm_contract,
        "native DIDComm endpoint behavior coverage is incomplete",
    )?;
    require(
        native_initiation_contract,
        "native initiation endpoint behavior coverage is incomplete",
    )?;
    require(
        native_renewal_contract,
        "native renewal contract is missing",
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
        coverage.remaining.grpc + coverage.native_grpc.len() as u64 == grpc_count,
        "native and remaining issuance gRPC counts are inconsistent",
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
                "CANVAS_ALLOW_HTTP_LOCALHOST_BASE_URLS",
                "CANVAS_ALLOW_PRIVATE_BASE_URLS",
                "CANVAS_BINDING_READINESS_MAX_AGE_SECONDS",
                "CANVAS_LTI_DEEP_LINKING_ISSUER",
                "CANVAS_LTI_EXPERIENCE_BASE_URL",
                "CANVAS_LTI_EXPERIENCE_CODE_TTL_SECONDS",
                "CANVAS_LTI_EXPERIENCE_SESSION_TTL_MINUTES",
                "CANVAS_LTI_JWKS_TTL_MINUTES",
                "CANVAS_LTI_STATE_TTL_MINUTES",
                "CANVAS_LTI_TOOL_ISSUER_DID",
                "CANVAS_LTI_TOOL_SIGNING_ORGANIZATION_ID",
                "CANVAS_OAUTH_COMPLETION_REDIRECT_URL",
                "CANVAS_ISSUANCE_EVIDENCE_MAX_AGE_SECONDS",
                "CANVAS_PILOT_ORGANIZATION_IDS",
                "CANVAS_PORTABLE_INTEGRATION_ENABLED",
                "CANVAS_PRIVATE_ORIGIN_ALLOWLIST",
                "CANVAS_SELF_MANAGED_ORIGIN_ALLOWLIST",
                "DATABASE_URL",
                "GRPC_SERVICE_TOKEN",
                "INTEGRATION_SECRET_MASTER_KEY_ENV",
                "ISSUANCE_GRPC_ENABLED",
                "ISSUANCE_GRPC_PORT",
                "ISSUANCE_SERVICE_PORT",
                "ISSUANCE_API_KEY",
                "ISSUER_BASE_URL",
                "ISSUER_DISPLAY_NAME",
                "REVOCATION_PROFILE_SERVICE_URL",
                "SIGNING_KEYS_INTERNAL_API_KEY",
                "SIGNING_KEYS_INTERNAL_URL",
                "TOKEN_RATE_LIMIT",
                "TOKEN_RATE_WINDOW",
                "UI_BASE_URL",
            ]
            && coverage.remaining.literal_environment_variables
                + coverage.native_environment_variables.len() as u64
                == environment_count
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

fn validate_application_template_operation(
    operation: &HttpOperation,
    contract: &Value,
) -> Result<(), MmfError> {
    require(
        operation.behavior_selector_count() == 1
            && operation.application_template_behavior_case.as_deref()
                == Some(operation.operation.as_str())
            && contract["schema"] == "marty.issuance-application-templates/v1"
            && contract["surface"]["base_path"] == "/v1/application-templates"
            && contract["surface"]["routes"]
                .as_array()
                .is_some_and(|routes| {
                    routes.len() == 8
                        && routes
                            .iter()
                            .filter(|route| {
                                route["method"] == operation.method
                                    && route["path"] == operation.path
                                    && route["operation"] == operation.operation
                            })
                            .count()
                            == 1
                }),
        "native application template operation diverges from its exact behavior contract",
    )
}

fn validate_credential_lifecycle_operation(
    operation: &HttpOperation,
    contract: &Value,
) -> Result<(), MmfError> {
    require(
        operation.behavior_selector_count() == 1
            && operation.credential_lifecycle_behavior_contract
            && contract["schema"] == "marty.issuance-credential-lifecycle/v1"
            && contract["scope"]["authentication"]["http"]
                == "management-api-key-and-trusted-organization"
            && contract["scope"]["http"].as_array().is_some_and(|routes| {
                routes.len() == 4
                    && routes
                        .iter()
                        .filter(|route| {
                            route["method"] == operation.method
                                && route["path"] == operation.path
                                && route["operation"] == operation.operation
                        })
                        .count()
                        == 1
            }),
        "native credential lifecycle operation diverges from its exact behavior contract",
    )
}

fn validate_internal_application_operation(
    operation: &HttpOperation,
    contract: &Value,
) -> Result<(), MmfError> {
    require(
        operation.behavior_selector_count() == 1
            && operation.internal_application_behavior_case.as_deref()
                == Some(operation.operation.as_str())
            && contract["schema"] == "marty.issuance-internal-applications/v1"
            && contract["surface"]["base_path"] == "/internal/applications"
            && contract["coverage"]["rust_implementation_authorized"] == true
            && contract["coverage"]["required_before_rust_implementation"]
                .as_array()
                .is_some_and(Vec::is_empty)
            && contract["surface"]["routes"]
                .as_array()
                .is_some_and(|routes| {
                    routes.len() == 14
                        && routes
                            .iter()
                            .filter(|route| {
                                route["method"] == operation.method
                                    && route["path"] == operation.path
                                    && route["operation"] == operation.operation
                            })
                            .count()
                            == 1
                }),
        "native internal application operation diverges from its exact behavior contract",
    )
}

fn validate_canvas_operations_operation(
    operation: &HttpOperation,
    contract: &Value,
) -> Result<(), MmfError> {
    let case = operation
        .canvas_operations_behavior_case
        .ok_or_else(|| invalid("native Canvas operations behavior case is missing"))?;
    let (method, suffix, name) = case.route();
    require(
        operation.behavior_selector_count() == 1
            && operation.method == method
            && operation.path == format!("/v1/integrations/canvas{suffix}")
            && operation.operation == name
            && contract["schema"] == "marty.issuance-canvas-operations/v1"
            && contract["route_prefix"] == "/v1/integrations/canvas"
            && contract["routes"].as_array().is_some_and(|routes| {
                routes.len() == 8
                    && routes
                        .iter()
                        .filter(|route| route["method"] == method && route["path"] == suffix)
                        .count()
                        == 1
            })
            && contract["behavior"]["note_max_length"] == 2000
            && contract["behavior"]["post_query_filter_window"] == 500
            && contract["behavior"]["actor_priority"]
                == serde_json::json!(["X-Authenticated-User-ID", "X-User-ID", "X-API-Key-ID"]),
        "native Canvas operation diverges from its exact behavior contract",
    )
}

fn validate_renewal_operation(operation: &HttpOperation, contract: &Value) -> Result<(), MmfError> {
    require(
        operation.renewal_behavior_contract
            && operation.behavior_selector_count() == 1
            && operation.operation == "renew_issued_credential"
            && operation.method == "POST"
            && operation.path == "/v1/issued-credentials/{credential_id}/renew"
            && contract["schema"] == "marty.credential-renewal-python-reference/v1"
            && contract["reference"]["source_commit"] == "87eae30788924921a42848425d315e2f33f7ae41"
            && contract["reference"]["source_blobs"]
                ["services/issuance/infrastructure/api/routes.py"]
                == "6b3a7fa0e169862e815bcb6bca64b0b21a5adf6a"
            && contract["cases"].as_array().is_some_and(|cases| {
                cases.len() == 31
                    && [
                        ("missing-key", 401),
                        ("missing-tenant", 403),
                        ("foreign-tenant", 404),
                        ("anoncrypt-keyed-rejection", 422),
                        ("authcrypt-keyed-rejection", 422),
                        ("anoncrypt-mixed-keyed-rejection", 422),
                        ("authcrypt-mixed-keyed-rejection", 422),
                    ]
                    .iter()
                    .all(|(name, status)| {
                        cases.iter().any(|case| {
                            case["case"] == *name && case["responses"][0]["status"] == *status
                        })
                    })
            }),
        "native renewal operation diverges from its exact governed contract",
    )
}

fn validate_initiation_operation(
    operation: &HttpOperation,
    contract: &Value,
) -> Result<(), MmfError> {
    require(
        operation.initiation_behavior_contract
            && operation.behavior_selector_count() == 1
            && operation.operation == "initiate_issuance"
            && operation.method == "POST"
            && operation.path == "/v1/issuance/initiate"
            && contract["schema"] == "marty.issuance-initiation/v1"
            && contract["surface"]["http"]
                == serde_json::json!({
                    "method": "POST", "path": "/v1/issuance/initiate",
                    "operation": "initiate_issuance", "authentication": "management-api-key",
                    "content_type": "application/json"
                })
            && contract["idempotency"]["http_source"] == "Idempotency-Key header"
            && contract["idempotency"]["plaintext_persisted"] == false
            && contract["idempotency"]["recovery_order"]
                == "after-organization-and-client-validation-before-template-resolution"
            && contract["idempotency"]["same_request"] == "return-committed-transaction-snapshot"
            && contract["idempotency"]["different_request"]
                == serde_json::json!({"http_status": 409, "grpc_status": "ALREADY_EXISTS"})
            && contract["idempotency"]["didcomm_push_with_idempotency"]
                == serde_json::json!({"http_status": 422, "grpc_status": "INVALID_ARGUMENT"})
            && contract["transaction"]["atomic_reservation"] == true
            && contract["response"]["source"] == "committed-transaction-snapshot"
            && contract["response"]["pre_auth_code_visibility"]
                == "internal-only-gateway-removes-publicly"
            && contract["response"]["didcomm"]["native_rust_target"]
                == "same-delivery-semantics-as-http",
        "native initiation operation diverges from its admission contract",
    )
}

fn validate_didcomm_operation(operation: &HttpOperation, contract: &Value) -> Result<(), MmfError> {
    require(
        operation.didcomm_behavior_contract
            && operation.operation == "didcomm_deliver"
            && operation.method == "POST"
            && operation.path == "/v1/issuance/didcomm/deliver"
            && contract["schema_version"] == 1
            && contract["expected_response"]["status"] == "delivered"
            && contract["transport_claim"]["single_active_attempt"] == true
            && contract["transport_claim"]["automatic_resend_from_delivery_unknown"] == false
            && contract["transport_claim"]["completion_fenced_by_attempt_id"] == true,
        "native DIDComm operation diverges from its delivery contract",
    )
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
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    use super::{
        canonical_lf, validate_application_template_operation,
        validate_canvas_operations_operation, validate_credential_lifecycle_operation,
        validate_didcomm_operation, validate_embedded_contract, validate_initiation_operation,
        validate_internal_application_operation, validate_renewal_operation, CanvasOperationsCase,
        Coverage, HttpOperation, APPLICATION_TEMPLATES, CANVAS_LTI, CANVAS_MANAGEMENT,
        CANVAS_OPERATIONS, COVERAGE, CREDENTIAL_ADMISSION, CREDENTIAL_LIFECYCLE,
        CREDENTIAL_SIGNING, DIDCOMM, INITIATION, INTERNAL_APPLICATIONS, RENEWAL_REFERENCE,
        RESOURCE_OWNERS,
    };

    #[test]
    fn application_template_selectors_are_closed_exact_and_exclusive() {
        let coverage: Value = serde_json::from_str(COVERAGE).unwrap();
        let contract: Value = serde_json::from_slice(APPLICATION_TEMPLATES).unwrap();
        let selected: Vec<_> = coverage["native_http"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|operation| {
                operation
                    .get("application_template_behavior_case")
                    .is_some()
            })
            .collect();
        assert_eq!(selected.len(), 8);
        for original in selected {
            let parse = |value: Value| serde_json::from_value::<HttpOperation>(value);
            validate_application_template_operation(&parse(original.clone()).unwrap(), &contract)
                .unwrap();
            for (field, value) in [
                ("method", serde_json::json!("OPTIONS")),
                (
                    "path",
                    serde_json::json!("/v1/application-templates/sibling"),
                ),
                ("operation", serde_json::json!("unknown_operation")),
                (
                    "application_template_behavior_case",
                    serde_json::json!("unknown_operation"),
                ),
                ("initiation_behavior_contract", serde_json::json!(true)),
            ] {
                let mut changed = original.clone();
                changed[field] = value;
                assert!(validate_application_template_operation(
                    &parse(changed).unwrap(),
                    &contract
                )
                .is_err());
            }
            let mut duplicate = contract.clone();
            duplicate["surface"]["routes"]
                .as_array_mut()
                .unwrap()
                .push(original.clone());
            assert!(validate_application_template_operation(
                &parse(original.clone()).unwrap(),
                &duplicate
            )
            .is_err());
        }
    }

    #[test]
    fn internal_application_selectors_are_closed_exact_and_exclusive() {
        let coverage: Value = serde_json::from_str(COVERAGE).unwrap();
        let contract: Value = serde_json::from_slice(INTERNAL_APPLICATIONS).unwrap();
        let selected: Vec<_> = coverage["native_http"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|operation| {
                operation
                    .get("internal_application_behavior_case")
                    .is_some()
            })
            .collect();
        assert_eq!(selected.len(), 14);
        for original in selected {
            let parse = |value: Value| serde_json::from_value::<HttpOperation>(value);
            validate_internal_application_operation(&parse(original.clone()).unwrap(), &contract)
                .unwrap();
            for (field, value) in [
                ("method", serde_json::json!("OPTIONS")),
                (
                    "path",
                    serde_json::json!("/internal/applications/sibling/unknown"),
                ),
                ("operation", serde_json::json!("unknown_operation")),
                (
                    "internal_application_behavior_case",
                    serde_json::json!("unknown_operation"),
                ),
                ("initiation_behavior_contract", serde_json::json!(true)),
            ] {
                let mut changed = original.clone();
                changed[field] = value;
                assert!(validate_internal_application_operation(
                    &parse(changed).unwrap(),
                    &contract
                )
                .is_err());
            }
            let mut duplicate = contract.clone();
            duplicate["surface"]["routes"]
                .as_array_mut()
                .unwrap()
                .push(original.clone());
            assert!(validate_internal_application_operation(
                &parse(original.clone()).unwrap(),
                &duplicate
            )
            .is_err());
        }
    }

    #[test]
    fn canvas_operations_selectors_are_closed_exact_and_exclusive() {
        let coverage: Value = serde_json::from_str(COVERAGE).unwrap();
        let contract: Value = serde_json::from_slice(CANVAS_OPERATIONS).unwrap();
        let selected: Vec<_> = coverage["native_http"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|operation| operation.get("canvas_operations_behavior_case").is_some())
            .collect();
        assert_eq!(selected.len(), CanvasOperationsCase::ALL.len());
        for original in selected {
            let parse = |value: Value| serde_json::from_value::<HttpOperation>(value);
            validate_canvas_operations_operation(&parse(original.clone()).unwrap(), &contract)
                .unwrap();
            for value in [
                serde_json::json!(true),
                serde_json::json!(1),
                serde_json::json!({}),
                serde_json::json!("unknown"),
            ] {
                let mut changed = original.clone();
                changed["canvas_operations_behavior_case"] = value;
                assert!(parse(changed).is_err());
            }
            for (field, value) in [
                ("canvas_operations_behavior_case", Value::Null),
                ("method", serde_json::json!("DELETE")),
                (
                    "path",
                    serde_json::json!("/v1/integrations/canvas/platforms"),
                ),
                ("operation", serde_json::json!("list_canvas_platforms")),
                ("initiation_behavior_contract", Value::Bool(true)),
                (
                    "canvas_management_behavior_case",
                    serde_json::json!("list_canvas_platforms"),
                ),
            ] {
                let mut changed = original.clone();
                changed[field] = value;
                assert!(
                    validate_canvas_operations_operation(&parse(changed).unwrap(), &contract)
                        .is_err()
                );
            }
            let mut removed = original.clone();
            removed
                .as_object_mut()
                .unwrap()
                .remove("canvas_operations_behavior_case");
            assert!(
                validate_canvas_operations_operation(&parse(removed).unwrap(), &contract).is_err()
            );
            let mut extra_segment = original.clone();
            extra_segment["path"] =
                serde_json::json!(format!("{}/extra", original["path"].as_str().unwrap()));
            assert!(validate_canvas_operations_operation(
                &parse(extra_segment).unwrap(),
                &contract
            )
            .is_err());
            for case in CanvasOperationsCase::ALL {
                let mut changed = parse(original.clone()).unwrap();
                if changed.canvas_operations_behavior_case != Some(case) {
                    changed.canvas_operations_behavior_case = Some(case);
                    assert!(validate_canvas_operations_operation(&changed, &contract).is_err());
                }
            }
            for field in [
                "note_max_length",
                "post_query_filter_window",
                "actor_priority",
            ] {
                let mut changed = contract.clone();
                changed["behavior"][field] = Value::Null;
                assert!(validate_canvas_operations_operation(
                    &parse(original.clone()).unwrap(),
                    &changed
                )
                .is_err());
            }
            let mut duplicate = contract.clone();
            duplicate["routes"]
                .as_array_mut()
                .unwrap()
                .push(contract["routes"][0].clone());
            assert!(validate_canvas_operations_operation(
                &parse(original.clone()).unwrap(),
                &duplicate
            )
            .is_err());
        }
    }

    #[test]
    fn credential_lifecycle_selectors_are_closed_exact_and_exclusive() {
        let coverage: Value = serde_json::from_str(COVERAGE).unwrap();
        let contract: Value = serde_json::from_slice(CREDENTIAL_LIFECYCLE).unwrap();
        let selected: Vec<_> = coverage["native_http"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|operation| {
                operation.get("credential_lifecycle_behavior_contract") == Some(&Value::Bool(true))
            })
            .collect();
        assert_eq!(selected.len(), 4);
        for original in selected {
            let parse = |value: Value| serde_json::from_value::<HttpOperation>(value);
            validate_credential_lifecycle_operation(&parse(original.clone()).unwrap(), &contract)
                .unwrap();
            for (field, value) in [
                ("method", serde_json::json!("OPTIONS")),
                (
                    "path",
                    serde_json::json!("/v1/issued-credentials/{credential_id}/revoke"),
                ),
                ("operation", serde_json::json!("unknown_operation")),
                (
                    "credential_lifecycle_behavior_contract",
                    serde_json::json!(false),
                ),
                ("credential_behavior_contract", serde_json::json!(true)),
            ] {
                let mut changed = original.clone();
                changed[field] = value;
                assert!(validate_credential_lifecycle_operation(
                    &parse(changed).unwrap(),
                    &contract
                )
                .is_err());
            }
            let mut duplicate = contract.clone();
            duplicate["scope"]["http"]
                .as_array_mut()
                .unwrap()
                .push(original.clone());
            assert!(validate_credential_lifecycle_operation(
                &parse(original.clone()).unwrap(),
                &duplicate
            )
            .is_err());
        }

        let mut unknown_selector = coverage["native_http"][0].clone();
        unknown_selector["future_behavior_contract"] = Value::Bool(true);
        assert!(serde_json::from_value::<HttpOperation>(unknown_selector).is_err());
    }

    #[test]
    fn resource_owner_selectors_are_closed_exact_and_exclusive() {
        let coverage: Value = serde_json::from_str(COVERAGE).unwrap();
        let contract: Value = serde_json::from_slice(RESOURCE_OWNERS).unwrap();
        let selected = coverage["native_http"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|operation| {
                operation.get("resource_owner_behavior_contract") == Some(&Value::Bool(true))
            })
            .collect::<Vec<_>>();
        assert_eq!(selected.len(), 3);
        for original in selected {
            let parsed: HttpOperation = serde_json::from_value(original.clone()).unwrap();
            assert_eq!(parsed.behavior_selector_count(), 1);
            assert!(contract["operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|frozen| {
                    frozen["method"] == parsed.method
                        && frozen["path"] == parsed.path
                        && frozen["operation"] == parsed.operation
                }));

            let mut missing = original.clone();
            missing
                .as_object_mut()
                .unwrap()
                .remove("resource_owner_behavior_contract");
            let missing: HttpOperation = serde_json::from_value(missing).unwrap();
            assert_eq!(missing.behavior_selector_count(), 0);

            let mut multiple = original.clone();
            multiple["renewal_behavior_contract"] = Value::Bool(true);
            let multiple: HttpOperation = serde_json::from_value(multiple).unwrap();
            assert_eq!(multiple.behavior_selector_count(), 2);

            let mut unknown = original.clone();
            unknown["future_resource_owner_selector"] = Value::Bool(true);
            assert!(serde_json::from_value::<HttpOperation>(unknown).is_err());
        }
    }

    #[test]
    fn renewal_coverage_is_exact_and_rejects_missing_malformed_or_multiple_selectors() {
        let entry = serde_json::json!({
            "method":"POST", "path":"/v1/issued-credentials/{credential_id}/renew",
            "operation":"renew_issued_credential", "renewal_behavior_contract":true
        });
        let contract: Value = serde_json::from_slice(RENEWAL_REFERENCE).unwrap();
        let parse = |value| serde_json::from_value::<HttpOperation>(value);
        validate_renewal_operation(&parse(entry.clone()).unwrap(), &contract).unwrap();
        for malformed in [Value::Null, serde_json::json!("true"), serde_json::json!(1)] {
            let mut changed = entry.clone();
            changed["renewal_behavior_contract"] = malformed;
            assert!(parse(changed).is_err());
        }
        for (field, value) in [
            ("renewal_behavior_contract", serde_json::json!(false)),
            ("initiation_behavior_contract", serde_json::json!(true)),
            ("didcomm_behavior_contract", serde_json::json!(true)),
            ("method", serde_json::json!("GET")),
            ("operation", serde_json::json!("revoke_issued_credential")),
            (
                "path",
                serde_json::json!("/v1/issued-credentials/{credential_id}"),
            ),
            (
                "path",
                serde_json::json!("/v1/issued-credentials/{credential_id}/revoke"),
            ),
            (
                "path",
                serde_json::json!("/v1/issued-credentials/{credential_id}/renew/extra"),
            ),
        ] {
            let mut changed = entry.clone();
            changed[field] = value;
            assert!(validate_renewal_operation(&parse(changed).unwrap(), &contract).is_err());
        }
        let mut missing = entry.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("renewal_behavior_contract");
        assert!(validate_renewal_operation(&parse(missing).unwrap(), &contract).is_err());
        for name in [
            "missing-key",
            "missing-tenant",
            "foreign-tenant",
            "anoncrypt-keyed-rejection",
            "authcrypt-mixed-keyed-rejection",
        ] {
            let mut changed = contract.clone();
            let case = changed["cases"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|case| case["case"] == name)
                .unwrap();
            case["responses"][0]["status"] = serde_json::json!(200);
            assert!(validate_renewal_operation(&parse(entry.clone()).unwrap(), &changed).is_err());
        }
    }

    #[test]
    fn initiation_coverage_rejects_malformed_or_multiple_behavior_selectors() {
        let entry = serde_json::json!({
            "method":"POST", "path":"/v1/issuance/initiate", "operation":"initiate_issuance",
            "initiation_behavior_contract":true
        });
        let contract: Value = serde_json::from_slice(INITIATION).unwrap();
        let operation: HttpOperation = serde_json::from_value(entry.clone()).unwrap();
        validate_initiation_operation(&operation, &contract).unwrap();
        for malformed in [
            Value::Null,
            Value::String("true".into()),
            serde_json::json!(1),
        ] {
            let mut changed = entry.clone();
            changed["initiation_behavior_contract"] = malformed;
            assert!(serde_json::from_value::<HttpOperation>(changed).is_err());
        }
        let mut changed = entry.clone();
        changed
            .as_object_mut()
            .unwrap()
            .remove("initiation_behavior_contract");
        let missing: HttpOperation = serde_json::from_value(changed).unwrap();
        assert_eq!(missing.behavior_selector_count(), 0);
        assert!(validate_initiation_operation(&missing, &contract).is_err());
        let mut changed = entry;
        changed["didcomm_behavior_contract"] = Value::Bool(true);
        let multiple: HttpOperation = serde_json::from_value(changed).unwrap();
        assert_eq!(multiple.behavior_selector_count(), 2);
        assert!(validate_initiation_operation(&multiple, &contract).is_err());
    }

    #[test]
    fn initiation_coverage_cannot_select_siblings_or_relax_admission() {
        let coverage: Coverage = serde_json::from_str(COVERAGE).unwrap();
        let mut operation = coverage
            .native_http
            .into_iter()
            .find(|operation| operation.initiation_behavior_contract)
            .unwrap();
        let contract: Value = serde_json::from_slice(INITIATION).unwrap();
        validate_initiation_operation(&operation, &contract).unwrap();
        for path in [
            "/v1/issuance",
            "/v1/issuance/initiate/extra",
            "/v1/issuance/didcomm/deliver",
        ] {
            operation.path = path.into();
            assert!(validate_initiation_operation(&operation, &contract).is_err());
        }
        operation.path = "/v1/issuance/initiate".into();
        operation.method = "GET".into();
        assert!(validate_initiation_operation(&operation, &contract).is_err());
        operation.method = "POST".into();
        for (pointer, value) in [
            ("/surface/http/authentication", serde_json::json!("none")),
            ("/idempotency/plaintext_persisted", serde_json::json!(true)),
            (
                "/idempotency/recovery_order",
                serde_json::json!("after-template-resolution"),
            ),
            (
                "/idempotency/same_request",
                serde_json::json!("create-new-transaction"),
            ),
            (
                "/idempotency/different_request/http_status",
                serde_json::json!(200),
            ),
            (
                "/idempotency/didcomm_push_with_idempotency/http_status",
                serde_json::json!(200),
            ),
            ("/transaction/atomic_reservation", serde_json::json!(false)),
            ("/response/source", serde_json::json!("request")),
            (
                "/response/pre_auth_code_visibility",
                serde_json::json!("public"),
            ),
        ] {
            let mut changed = contract.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_initiation_operation(&operation, &changed).is_err(),
                "{pointer}"
            );
        }
    }

    #[test]
    fn didcomm_coverage_cannot_select_siblings_or_relax_send_fencing() {
        let coverage: Coverage = serde_json::from_str(COVERAGE).unwrap();
        let mut operation = coverage
            .native_http
            .into_iter()
            .find(|operation| operation.didcomm_behavior_contract)
            .unwrap();
        let contract: Value = serde_json::from_slice(DIDCOMM).unwrap();
        validate_didcomm_operation(&operation, &contract).unwrap();
        for path in [
            "/v1/issuance/initiate",
            "/v1/issuance/didcomm/deliver/extra",
        ] {
            operation.path = path.into();
            assert!(validate_didcomm_operation(&operation, &contract).is_err());
        }
        operation.path = "/v1/issuance/didcomm/deliver".into();
        operation.method = "GET".into();
        assert!(validate_didcomm_operation(&operation, &contract).is_err());
        operation.method = "POST".into();
        for (field, value) in [
            ("single_active_attempt", false),
            ("automatic_resend_from_delivery_unknown", true),
            ("completion_fenced_by_attempt_id", false),
        ] {
            let mut changed = contract.clone();
            changed["transport_claim"][field] = Value::Bool(value);
            assert!(validate_didcomm_operation(&operation, &changed).is_err());
        }
    }

    #[test]
    fn provenance_hash_is_independent_of_checkout_line_endings() {
        let coverage: Coverage = serde_json::from_str(COVERAGE).expect("coverage contract");

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
            coverage.canvas_lti_behavior_contract.sha256
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(canonical_lf(CANVAS_MANAGEMENT))),
            coverage.canvas_management_behavior_contract.sha256
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(canonical_lf(CREDENTIAL_LIFECYCLE))),
            coverage.credential_lifecycle_behavior_contract.sha256
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(canonical_lf(INITIATION))),
            coverage.initiation_behavior_contract.sha256
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(canonical_lf(APPLICATION_TEMPLATES))),
            coverage.application_template_behavior_contract.sha256
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(canonical_lf(INTERNAL_APPLICATIONS))),
            coverage.internal_application_behavior_contract.sha256
        );
    }

    #[test]
    fn embedded_surface_and_native_coverage_are_consistent() {
        let summary = validate_embedded_contract().expect("contract");
        assert_eq!(summary.native_http, 102);
        assert_eq!(summary.remaining_http, 29);
        assert_eq!(summary.remaining_grpc, 0);
    }
}
