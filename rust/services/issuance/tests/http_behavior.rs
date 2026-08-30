use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Method, Request},
};
use chrono::{DateTime, TimeZone, Utc};
use marty_issuance_service::{
    credential_management::{
        CredentialLifecycleAction, CredentialLifecycleEvent, CredentialLifecycleEventSink,
        CredentialManagementPortError, CredentialManagementRepository, CredentialManagementService,
        CredentialStatusPublisher, ManagedCredential, ManagedCredentialStatus,
    },
    credential_management_http::CredentialManagementHttpService,
    http::{
        router, router_with_credential_management, router_with_services,
        router_with_tenant_discovery,
    },
    tenant_discovery::{
        ProofPolicyResolver, TenantDiscoveryError, TenantDiscoveryRepository,
        TenantDiscoveryService,
    },
    transaction_reads::{
        IssuanceTransactionRecord, TransactionReadError, TransactionReadRepository,
        TransactionReadService, TransactionStatus,
    },
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::{
    KeyAttestationRequirements, ProofPolicyRequest, StaticDiscoveryDocuments,
    TenantCredentialMetadata, TenantCredentialTemplate,
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use tower::ServiceExt;

async fn json_body(response: axum::response::Response) -> Value {
    let body = response_body(response).await;
    serde_json::from_slice(&body).expect("json")
}

async fn response_body(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec()
}

#[tokio::test]
async fn native_health_preserves_the_legacy_body_and_mmf_readiness() {
    let coverage: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-native-coverage.json"
    ))
    .expect("coverage");
    let expected = &coverage["native_http"][0]["response"];
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).expect("config");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    let discovery =
        StaticDiscoveryDocuments::new(&config.issuer_base_url, &config.issuer_display_name);
    let transport = TransportPolicy::new(config.cors_allowed_origins.clone());
    let app = router(runtime.state(), discovery, transport);

    let health = app
        .clone()
        .oneshot(
            Request::get("/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(health.status().as_u16(), expected["status_code"]);
    assert_eq!(json_body(health).await, expected["body"]);

    let not_ready = app
        .clone()
        .oneshot(Request::get("/ready").body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(not_ready.status(), 503);

    runtime.mark_listener_healthy().expect("listener");
    runtime.activate().expect("active");
    let ready = app
        .oneshot(Request::get("/ready").body(Body::empty()).expect("request"))
        .await
        .expect("response");
    assert_eq!(ready.status(), 200);
    assert_eq!(json_body(ready).await["ready"], true);
}

#[tokio::test]
async fn native_static_discovery_matches_the_python_oracle_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-static-discovery.json"
    ))
    .expect("discovery contract");
    let inputs = &contract["inputs"];
    let transport_contract = &contract["transport"];
    let request_id_contract = &transport_contract["request_id"];
    let cors_contract = &transport_contract["cors"];
    let config = IssuanceServiceConfig::from_values([
        (
            "ISSUER_BASE_URL".to_owned(),
            inputs["issuer_base_url"]
                .as_str()
                .expect("base URL")
                .to_owned(),
        ),
        (
            "ISSUER_DISPLAY_NAME".to_owned(),
            inputs["issuer_display_name"]
                .as_str()
                .expect("display name")
                .to_owned(),
        ),
        (
            "CORS_ALLOWED_ORIGINS".to_owned(),
            cors_contract["allowed_origin"]
                .as_str()
                .expect("allowed origin")
                .to_owned(),
        ),
    ])
    .expect("config");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    let documents =
        StaticDiscoveryDocuments::new(&config.issuer_base_url, &config.issuer_display_name);
    let transport = TransportPolicy::new(config.cors_allowed_origins.clone());
    let app = router(runtime.state(), documents, transport);

    for case in contract["cases"].as_array().expect("cases") {
        let method = Method::from_bytes(case["method"].as_str().expect("method").as_bytes())
            .expect("valid method");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(case["path"].as_str().expect("path"))
                    .header(
                        request_id_contract["request_header"]
                            .as_str()
                            .expect("request ID header"),
                        request_id_contract["propagated_value"]
                            .as_str()
                            .expect("request ID"),
                    )
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(
            response.status().as_u16(),
            case["status_code"].as_u64().expect("status") as u16,
            "{}",
            case["operation"]
        );
        assert_eq!(
            response
                .headers()
                .get(
                    request_id_contract["response_header"]
                        .as_str()
                        .expect("response ID header"),
                )
                .expect("response request ID"),
            request_id_contract["propagated_value"]
                .as_str()
                .expect("request ID"),
            "{}",
            case["operation"]
        );
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .expect("content type"),
            case["content_type"]
                .as_str()
                .expect("expected content type"),
            "{}",
            case["operation"]
        );
        assert_eq!(
            json_body(response).await,
            case["body"],
            "{}",
            case["operation"]
        );
    }

    let generated = app
        .clone()
        .oneshot(
            Request::get(contract["cases"][0]["path"].as_str().expect("path"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let generated_request_id = generated
        .headers()
        .get(
            request_id_contract["response_header"]
                .as_str()
                .expect("response ID header"),
        )
        .expect("generated request ID")
        .to_str()
        .expect("request ID string");
    assert_eq!(generated_request_id.len(), 8);
    assert!(generated_request_id
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    let empty_request_id = app
        .clone()
        .oneshot(
            Request::get(contract["cases"][0]["path"].as_str().expect("path"))
                .header("x-request-id", "")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    let empty_request_id = empty_request_id
        .headers()
        .get("x-request-id")
        .expect("generated request ID")
        .to_str()
        .expect("request ID string");
    assert_eq!(empty_request_id.len(), 8);
    assert!(empty_request_id
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));

    let simple_cors = app
        .clone()
        .oneshot(
            Request::get(contract["cases"][0]["path"].as_str().expect("path"))
                .header(
                    "origin",
                    cors_contract["allowed_origin"]
                        .as_str()
                        .expect("allowed origin"),
                )
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    for (name, value) in cors_contract["simple_response_headers"]
        .as_object()
        .expect("simple CORS headers")
    {
        assert_eq!(
            simple_cors.headers().get(name).expect("CORS header"),
            value.as_str().expect("CORS header value")
        );
    }

    let wildcard = &cors_contract["wildcard_simple_request"];
    let wildcard_app = router(
        runtime.state(),
        StaticDiscoveryDocuments::new(&config.issuer_base_url, &config.issuer_display_name),
        TransportPolicy::new([wildcard["configured_origin"]
            .as_str()
            .expect("configured wildcard")
            .to_owned()]),
    );
    let wildcard_response = wildcard_app
        .oneshot(
            Request::get(contract["cases"][0]["path"].as_str().expect("path"))
                .header(
                    "origin",
                    wildcard["request_origin"]
                        .as_str()
                        .expect("wildcard request origin"),
                )
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    for (name, value) in wildcard["response_headers"]
        .as_object()
        .expect("wildcard response headers")
    {
        assert_eq!(
            wildcard_response
                .headers()
                .get(name)
                .expect("wildcard CORS header"),
            value.as_str().expect("wildcard CORS value")
        );
    }

    for contract_key in ["preflight", "denied_preflight", "denied_method_preflight"] {
        let case = &cors_contract[contract_key];
        let mut request = Request::builder()
            .method(case["method"].as_str().expect("method"))
            .uri(case["path"].as_str().expect("path"));
        for (name, value) in case["request_headers"]
            .as_object()
            .expect("request headers")
        {
            request = request.header(name, value.as_str().expect("request header value"));
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).expect("request"))
            .await
            .expect("response");
        assert_eq!(
            response.status().as_u16(),
            case["status_code"].as_u64().expect("status") as u16
        );
        for (name, value) in case["response_headers"]
            .as_object()
            .expect("response headers")
        {
            assert_eq!(
                response.headers().get(name).expect("response header"),
                value.as_str().expect("response header value"),
                "{contract_key}: {name}"
            );
        }
        assert_eq!(
            response_body(response).await,
            case["body"].as_str().expect("body").as_bytes(),
            "{contract_key}"
        );
    }

    for path in contract["rejected_paths"]
        .as_array()
        .expect("rejected paths")
    {
        let response = app
            .clone()
            .oneshot(
                Request::get(path.as_str().expect("rejected path"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), 404, "{path}");
    }
}

#[derive(Clone)]
struct ContractTenantRepository {
    templates: Vec<TenantCredentialTemplate>,
    organizations: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl TenantDiscoveryRepository for ContractTenantRepository {
    async fn templates(
        &self,
        organization_id: &str,
    ) -> Result<Vec<TenantCredentialTemplate>, TenantDiscoveryError> {
        self.organizations
            .lock()
            .expect("organization calls")
            .push(organization_id.to_owned());
        Ok(self.templates.clone())
    }
}

#[derive(Clone)]
struct ContractProofPolicies {
    requirements: BTreeMap<String, KeyAttestationRequirements>,
    calls: Arc<Mutex<Vec<ProofPolicyRequest>>>,
    unavailable: bool,
}

#[async_trait]
impl ProofPolicyResolver for ContractProofPolicies {
    async fn resolve(
        &self,
        request: &ProofPolicyRequest,
    ) -> Result<KeyAttestationRequirements, TenantDiscoveryError> {
        self.calls
            .lock()
            .expect("proof policy calls")
            .push(request.clone());
        if self.unavailable {
            return Err(TenantDiscoveryError::ProofPolicyUnavailable);
        }
        Ok(self
            .requirements
            .get(&request.credential_format)
            .cloned()
            .unwrap_or_default())
    }
}

fn contract_templates(inputs: &Value) -> Vec<TenantCredentialTemplate> {
    let formats = inputs["credential_type_formats"]
        .as_array()
        .expect("format rows")
        .iter()
        .map(|row| {
            let row = row.as_array().expect("format row");
            (
                row[0].as_str().expect("credential type").to_owned(),
                serde_json::from_value(row[1].clone()).expect("formats"),
            )
        })
        .collect::<BTreeMap<String, Vec<String>>>();
    inputs["credential_types"]
        .as_array()
        .expect("credential types")
        .iter()
        .map(|credential_type| {
            let credential_type = credential_type.as_str().expect("credential type");
            TenantCredentialTemplate {
                credential_type: credential_type.to_owned(),
                supported_formats: formats.get(credential_type).cloned().unwrap_or_default(),
                metadata: serde_json::from_value(
                    inputs["display_metadata"][credential_type].clone(),
                )
                .unwrap_or_else(|_| TenantCredentialMetadata::default()),
            }
        })
        .collect()
}

fn expected_tenant_body(inputs: &Value, variant: &Value) -> Value {
    let base = inputs["issuer_base_url"].as_str().expect("base URL");
    let organization = inputs["organization_id"].as_str().expect("organization");
    let suffix = variant["issuer_suffix"].as_str().expect("issuer suffix");
    let issuer = format!("{base}/org/{organization}{suffix}");
    serde_json::json!({
        "credential_issuer": issuer,
        "authorization_servers": [issuer],
        "display": [{
            "name": inputs["issuer_display_name"],
            "locale": "en-US"
        }],
        "credential_endpoint": format!("{base}/v1/issuance/credential"),
        "nonce_endpoint": format!("{base}/v1/issuance/nonce"),
        "deferred_credential_endpoint": format!("{base}/v1/issuance/deferred-credential"),
        "notification_endpoint": format!("{base}/v1/issuance/notification"),
        "credential_configurations_supported": variant["credential_configurations_supported"]
    })
}

fn proof_call_value(request: &ProofPolicyRequest) -> Value {
    serde_json::json!({
        "organization_id": request.organization_id,
        "issuer_did": request.issuer_did,
        "credential_format": request.credential_format,
        "key_purpose": request.key_purpose
    })
}

#[tokio::test]
async fn native_tenant_discovery_matches_the_python_oracle_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-tenant-discovery.json"
    ))
    .expect("tenant discovery contract");
    let inputs = &contract["inputs"];
    let requirements = serde_json::from_value(inputs["required_key_attestation_by_format"].clone())
        .expect("proof policy requirements");
    let organizations = Arc::new(Mutex::new(Vec::new()));
    let calls = Arc::new(Mutex::new(Vec::new()));
    let repository = ContractTenantRepository {
        templates: contract_templates(inputs),
        organizations: organizations.clone(),
    };
    let policies = ContractProofPolicies {
        requirements,
        calls: calls.clone(),
        unavailable: false,
    };
    let documents = StaticDiscoveryDocuments::new(
        inputs["issuer_base_url"].as_str().expect("base URL"),
        inputs["issuer_display_name"]
            .as_str()
            .expect("display name"),
    );
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).expect("config");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    let app = router_with_tenant_discovery(
        runtime.state(),
        documents.clone(),
        TransportPolicy::new(config.cors_allowed_origins),
        TenantDiscoveryService::new(documents, Arc::new(repository), Arc::new(policies)),
    );

    for variant in contract["variants"].as_array().expect("variants") {
        organizations.lock().expect("organizations").clear();
        calls.lock().expect("calls").clear();
        let response = app
            .clone()
            .oneshot(
                Request::get(variant["path"].as_str().expect("path"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), 200, "{}", variant["operation"]);
        assert_eq!(
            response.headers()["content-type"],
            "application/json",
            "{}",
            variant["operation"]
        );
        assert_eq!(
            json_body(response).await,
            expected_tenant_body(inputs, variant),
            "{}",
            variant["operation"]
        );
        assert_eq!(
            calls
                .lock()
                .expect("calls")
                .iter()
                .map(proof_call_value)
                .collect::<Vec<_>>(),
            variant["expected_resolver_calls"]
                .as_array()
                .expect("expected resolver calls")
                .clone(),
            "{}",
            variant["operation"]
        );
        assert_eq!(
            organizations.lock().expect("organizations").as_slice(),
            [inputs["organization_id"].as_str().expect("organization")]
        );
    }
}

#[tokio::test]
async fn native_tenant_discovery_fails_closed_when_proof_policy_is_unavailable() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-tenant-discovery.json"
    ))
    .expect("tenant discovery contract");
    let inputs = &contract["inputs"];
    let documents = StaticDiscoveryDocuments::new(
        inputs["issuer_base_url"].as_str().expect("base URL"),
        inputs["issuer_display_name"]
            .as_str()
            .expect("display name"),
    );
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).expect("config");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    let app = router_with_tenant_discovery(
        runtime.state(),
        documents.clone(),
        TransportPolicy::new(config.cors_allowed_origins),
        TenantDiscoveryService::new(
            documents,
            Arc::new(ContractTenantRepository {
                templates: contract_templates(inputs),
                organizations: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(ContractProofPolicies {
                requirements: BTreeMap::new(),
                calls: Arc::new(Mutex::new(Vec::new())),
                unavailable: true,
            }),
        ),
    );
    let failure = &contract["failure"]["resolver_unavailable"];
    for variant in contract["variants"].as_array().expect("variants") {
        let response = app
            .clone()
            .oneshot(
                Request::get(variant["path"].as_str().expect("path"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status().as_u16(), failure["status_code"]);
        assert_eq!(json_body(response).await, failure["body"]);
    }
}

#[derive(Clone)]
struct ContractTransactionRepository {
    transactions: BTreeMap<String, IssuanceTransactionRecord>,
    calls: Arc<Mutex<Vec<Value>>>,
}

#[async_trait]
impl TransactionReadRepository for ContractTransactionRepository {
    async fn get(
        &self,
        transaction_id: &str,
    ) -> Result<Option<IssuanceTransactionRecord>, TransactionReadError> {
        self.calls
            .lock()
            .expect("transaction calls")
            .push(serde_json::json!({"method": "get_transaction", "value": transaction_id}));
        Ok(self.transactions.get(transaction_id).cloned())
    }

    async fn list(
        &self,
        organization_id: &str,
    ) -> Result<Vec<IssuanceTransactionRecord>, TransactionReadError> {
        self.calls
            .lock()
            .expect("transaction calls")
            .push(serde_json::json!({"method": "list_transactions", "value": organization_id}));
        Ok(["tx-pending", "tx-revoked"]
            .into_iter()
            .filter_map(|id| self.transactions.get(id).cloned())
            .filter(|transaction| transaction.organization_id == organization_id)
            .collect())
    }
}

fn transaction_record(value: &Value) -> IssuanceTransactionRecord {
    let optional_time = |name: &str| {
        value[name]
            .as_str()
            .map(|time| DateTime::parse_from_rfc3339(time).expect("time").to_utc())
    };
    IssuanceTransactionRecord {
        id: value["id"].as_str().expect("id").to_owned(),
        organization_id: value["organization_id"]
            .as_str()
            .expect("organization")
            .to_owned(),
        credential_template_id: value["credential_template_id"]
            .as_str()
            .expect("template")
            .to_owned(),
        applicant_id: value["applicant_id"].as_str().map(str::to_owned),
        application_id: value["application_id"].as_str().map(str::to_owned),
        subject_did: value["subject_did"].as_str().map(str::to_owned),
        status: TransactionStatus::try_from(value["status"].as_str().expect("status"))
            .expect("released status"),
        pre_auth_code: value["pre_auth_code"]
            .as_str()
            .expect("pre-authorized code")
            .to_owned(),
        credential_type: value["credential_type"].as_str().map(str::to_owned),
        created_at: optional_time("created_at").expect("created at"),
        expires_at: optional_time("expires_at").expect("expires at"),
        issued_at: optional_time("issued_at"),
        revoked_at: optional_time("revoked_at"),
        revocation_reason: value["revocation_reason"].as_str().map(str::to_owned),
    }
}

fn transaction_app(contract: &Value) -> (axum::Router, Arc<Mutex<Vec<Value>>>) {
    let inputs = &contract["inputs"];
    let documents = StaticDiscoveryDocuments::new(
        inputs["issuer_base_url"].as_str().expect("base URL"),
        "Example Issuer",
    );
    let calls = Arc::new(Mutex::new(Vec::new()));
    let repository = ContractTransactionRepository {
        transactions: inputs["transactions"]
            .as_array()
            .expect("transactions")
            .iter()
            .map(transaction_record)
            .map(|transaction| (transaction.id.clone(), transaction))
            .collect(),
        calls: calls.clone(),
    };
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).expect("config");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    let app = router_with_services(
        runtime.state(),
        documents.clone(),
        TransportPolicy::new(config.cors_allowed_origins),
        TenantDiscoveryService::new(
            documents,
            Arc::new(ContractTenantRepository {
                templates: Vec::new(),
                organizations: Arc::new(Mutex::new(Vec::new())),
            }),
            Arc::new(ContractProofPolicies {
                requirements: BTreeMap::new(),
                calls: Arc::new(Mutex::new(Vec::new())),
                unavailable: false,
            }),
        ),
        TransactionReadService::new(
            Arc::new(repository),
            inputs["management_api_key"].as_str(),
            inputs["issuer_base_url"].as_str().expect("base URL"),
        ),
    );
    (app, calls)
}

fn contract_request(value: &Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method(value["method"].as_str().unwrap_or("GET"))
        .uri(value["path"].as_str().expect("path"));
    if let Some(headers) = value["headers"].as_object() {
        for (name, value) in headers {
            builder = builder.header(name, value.as_str().expect("header value"));
        }
    }
    builder.body(Body::empty()).expect("request")
}

#[tokio::test]
async fn native_offer_transaction_reads_match_the_python_oracle_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-offer-transaction-reads.json"
    ))
    .expect("offer transaction contract");
    let (app, calls) = transaction_app(&contract);

    for case in contract["cases"].as_array().expect("cases") {
        calls.lock().expect("transaction calls").clear();
        let response = app
            .clone()
            .oneshot(contract_request(case))
            .await
            .expect("response");
        assert_eq!(
            response.status().as_u16(),
            case["status_code"],
            "{}",
            case["operation"]
        );
        assert_eq!(
            response.headers()["content-type"],
            "application/json",
            "{}",
            case["operation"]
        );
        assert_eq!(
            json_body(response).await,
            case["body"],
            "{}",
            case["operation"]
        );
        assert_eq!(
            calls.lock().expect("transaction calls").as_slice(),
            case["repository_calls"]
                .as_array()
                .expect("repository calls"),
            "{}",
            case["operation"]
        );
    }
}

#[tokio::test]
async fn native_offer_transaction_read_edges_and_failures_match_the_python_oracle_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-offer-transaction-reads.json"
    ))
    .expect("offer transaction contract");
    let (app, calls) = transaction_app(&contract);

    let edge_cases = contract["edge_cases"].as_array().expect("edge cases");
    let failures = contract["failures"].as_array().expect("failures");
    for failure in edge_cases.iter().chain(failures) {
        calls.lock().expect("transaction calls").clear();
        let response = app
            .clone()
            .oneshot(contract_request(failure))
            .await
            .expect("response");
        assert_eq!(
            response.status().as_u16(),
            failure["status_code"],
            "{}",
            failure["name"]
        );
        assert_eq!(
            json_body(response).await,
            failure["body"],
            "{}",
            failure["name"]
        );
        assert_eq!(
            calls.lock().expect("transaction calls").as_slice(),
            failure["repository_calls"]
                .as_array()
                .expect("repository calls"),
            "{}",
            failure["name"]
        );
    }
}

#[derive(Clone)]
struct CredentialLifecycleHarness {
    credential: Arc<Mutex<ManagedCredential>>,
    calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl CredentialManagementRepository for CredentialLifecycleHarness {
    async fn get(
        &self,
        credential_id: &str,
    ) -> Result<Option<ManagedCredential>, CredentialManagementPortError> {
        self.calls
            .lock()
            .expect("lifecycle calls")
            .push("load-credential".to_owned());
        let credential = self.credential.lock().expect("credential").clone();
        Ok((credential.id == credential_id).then_some(credential))
    }

    async fn persist(
        &self,
        credential: &ManagedCredential,
        expected_status: ManagedCredentialStatus,
    ) -> Result<ManagedCredential, CredentialManagementPortError> {
        self.calls
            .lock()
            .expect("lifecycle calls")
            .push("persist-local-status".to_owned());
        let mut stored = self.credential.lock().expect("credential");
        if stored.status != expected_status {
            return Err(CredentialManagementPortError("stale status".to_owned()));
        }
        *stored = credential.clone();
        Ok(stored.clone())
    }

    async fn synchronize_canvas(
        &self,
        _credential: &ManagedCredential,
        action: CredentialLifecycleAction,
        _reason: Option<&str>,
    ) -> Result<(), CredentialManagementPortError> {
        self.calls
            .lock()
            .expect("lifecycle calls")
            .push(format!("synchronize-canvas:{}", action.as_str()));
        Ok(())
    }
}

#[async_trait]
impl CredentialStatusPublisher for CredentialLifecycleHarness {
    async fn publish(
        &self,
        _credential: &ManagedCredential,
        action: CredentialLifecycleAction,
        _reason: Option<&str>,
    ) -> Result<(), CredentialManagementPortError> {
        self.calls
            .lock()
            .expect("lifecycle calls")
            .push(format!("publish-status:{}", action.as_str()));
        Ok(())
    }
}

#[async_trait]
impl CredentialLifecycleEventSink for CredentialLifecycleHarness {
    async fn emit(&self, event: CredentialLifecycleEvent) {
        self.calls
            .lock()
            .expect("lifecycle calls")
            .push(format!("emit-event:{}", event.event_type));
    }
}

fn credential_lifecycle_app() -> (axum::Router, Arc<Mutex<Vec<String>>>) {
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).expect("config");
    let runtime = IssuanceRuntime::new(&config).expect("runtime");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let harness = CredentialLifecycleHarness {
        credential: Arc::new(Mutex::new(ManagedCredential {
            id: "credential-1".to_owned(),
            organization_id: "org-1".to_owned(),
            credential_template_id: "template-1".to_owned(),
            issuer_did: None,
            status: ManagedCredentialStatus::Active,
            status_updated_at: Utc
                .with_ymd_and_hms(2026, 8, 30, 11, 0, 0)
                .single()
                .expect("timestamp"),
            revoked: false,
            revoked_at: None,
            revocation_reason: None,
            revocation_profile_id: Some("profile-1".to_owned()),
            status_list_entries: vec![serde_json::json!({"index": 7})],
        })),
        calls: calls.clone(),
    };
    let lifecycle = CredentialManagementService::new(
        Arc::new(harness.clone()),
        Arc::new(harness.clone()),
        Arc::new(harness),
    );
    let app = router_with_credential_management(
        runtime.state(),
        StaticDiscoveryDocuments::new(&config.issuer_base_url, &config.issuer_display_name),
        TransportPolicy::new(config.cors_allowed_origins),
        CredentialManagementHttpService::new(lifecycle, Some("management-key")),
    );
    (app, calls)
}

fn lifecycle_mutation_request(path: &str, body: Value) -> Request<Body> {
    Request::post(path)
        .header("content-type", "application/json")
        .header("X-API-Key", "management-key")
        .header("X-Organization-ID", "org-1")
        .body(Body::from(serde_json::to_vec(&body).expect("request JSON")))
        .expect("request")
}

#[tokio::test]
async fn native_credential_lifecycle_http_routes_preserve_auth_parity_and_one_handler_order() {
    let (app, calls) = credential_lifecycle_app();
    let unauthorized = app
        .clone()
        .oneshot(
            Request::post("/v1/issuance/credentials/credential-1/suspend")
                .header("content-type", "application/json")
                .header("X-Organization-ID", "org-1")
                .body(Body::from(r#"{"reason":null}"#))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(unauthorized.status(), 401);
    assert_eq!(
        json_body(unauthorized).await,
        serde_json::json!({"detail": "X-API-Key header is missing"})
    );
    assert!(calls.lock().expect("calls").is_empty());

    let missing_organization = app
        .clone()
        .oneshot(
            Request::get("/v1/issuance/credentials/credential-1/status")
                .header("X-API-Key", "management-key")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(missing_organization.status(), 403);
    assert_eq!(
        json_body(missing_organization).await,
        serde_json::json!({"detail": "Trusted organization context is required"})
    );
    assert!(calls.lock().expect("calls").is_empty());

    let hidden = app
        .clone()
        .oneshot(
            Request::get("/v1/issuance/credentials/credential-1/status")
                .header("X-API-Key", "management-key")
                .header("X-Organization-ID", "org-other")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(hidden.status(), 404);
    assert_eq!(
        json_body(hidden).await,
        serde_json::json!({"detail": "Resource not found"})
    );
    assert_eq!(
        calls.lock().expect("calls").drain(..).collect::<Vec<_>>(),
        ["load-credential"]
    );

    let suspended = app
        .clone()
        .oneshot(lifecycle_mutation_request(
            "/v1/issuance/credentials/credential-1/suspend",
            serde_json::json!({"reason": null}),
        ))
        .await
        .expect("response");
    assert_eq!(suspended.status(), 200);
    let suspended = json_body(suspended).await;
    assert_eq!(suspended["status"], "suspended");
    assert_eq!(suspended["issuer_did"], Value::Null);
    assert_eq!(suspended["reason"], Value::Null);
    assert!(suspended["status_updated_at"]
        .as_str()
        .expect("timestamp")
        .ends_with("+00:00"));
    assert_eq!(
        calls.lock().expect("calls").drain(..).collect::<Vec<_>>(),
        [
            "load-credential",
            "publish-status:suspend",
            "persist-local-status",
            "synchronize-canvas:suspend",
            "emit-event:suspended",
        ]
    );

    let reinstated = app
        .clone()
        .oneshot(lifecycle_mutation_request(
            "/v1/issuance/credentials/credential-1/reinstate",
            serde_json::json!({"reason": "review complete"}),
        ))
        .await
        .expect("response");
    assert_eq!(reinstated.status(), 200);
    assert_eq!(json_body(reinstated).await["status"], "active");
    calls.lock().expect("calls").clear();

    let revoked = app
        .clone()
        .oneshot(lifecycle_mutation_request(
            "/v1/issuance/credentials/credential-1/revoke",
            serde_json::json!({"reason": "policy violation"}),
        ))
        .await
        .expect("response");
    assert_eq!(revoked.status(), 200);
    assert_eq!(json_body(revoked).await["status"], "revoked");
    calls.lock().expect("calls").clear();

    let status = app
        .clone()
        .oneshot(
            Request::get("/v1/issuance/credentials/credential-1/status")
                .header("X-API-Key", "management-key")
                .header("X-Organization-ID", "org-1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(status.status(), 200);
    let status = json_body(status).await;
    assert_eq!(status["status"], "revoked");
    assert_eq!(status["reason"], "policy violation");

    calls.lock().expect("calls").clear();
    let oversized = app
        .oneshot(lifecycle_mutation_request(
            "/v1/issuance/credentials/credential-1/suspend",
            serde_json::json!({"reason": "x".repeat(2001)}),
        ))
        .await
        .expect("response");
    assert_eq!(oversized.status(), 422);
    assert_eq!(calls.lock().expect("calls").as_slice(), ["load-credential"]);
}

#[tokio::test]
async fn native_credential_lifecycle_http_request_schema_is_strict_optional_and_nullable() {
    let (app, calls) = credential_lifecycle_app();
    let unknown_field = app
        .oneshot(lifecycle_mutation_request(
            "/v1/issuance/credentials/credential-1/suspend",
            serde_json::json!({"reason": null, "unexpected": true}),
        ))
        .await
        .expect("response");
    assert_eq!(unknown_field.status(), 422);
    assert!(calls.lock().expect("calls").is_empty());

    for body in [serde_json::json!({}), serde_json::json!({"reason": null})] {
        let (app, calls) = credential_lifecycle_app();
        let response = app
            .oneshot(lifecycle_mutation_request(
                "/v1/issuance/credentials/credential-1/suspend",
                body,
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), 200);
        assert_eq!(json_body(response).await["reason"], Value::Null);
        assert_eq!(
            calls.lock().expect("calls").as_slice(),
            [
                "load-credential",
                "publish-status:suspend",
                "persist-local-status",
                "synchronize-canvas:suspend",
                "emit-event:suspended",
            ]
        );
    }
}
