use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use marty_issuance_service::{
    credential::CredentialTransactionStatus,
    http::router_with_didcomm_delivery,
    initiation_didcomm::{
        NativeDidcommDeliveryStatus, NativeDidcommError, NativeInitiationDidcommDeliveryError,
        NativeInitiationDidcommDeliveryReceipt, DIDCOMM_TRANSPORT_CLAIM_LEASE_SECONDS,
        DIDCOMM_TRANSPORT_READY_STATUS, DIDCOMM_TRANSPORT_RETRYABLE_STATUS,
    },
    initiation_didcomm_http::{DirectDidcommDelivery, InitiationDidcommHttpService},
    transport::TransportPolicy,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::{json, Value};
use tower::ServiceExt;

#[derive(Clone)]
struct ContractDelivery {
    calls: Arc<Mutex<Vec<Value>>>,
    receipt: NativeInitiationDidcommDeliveryReceipt,
}

#[derive(Clone, Copy)]
struct ErrorContractDelivery {
    error: NativeInitiationDidcommDeliveryError,
}

#[async_trait]
impl DirectDidcommDelivery for ErrorContractDelivery {
    async fn deliver_for_organization(
        &self,
        _organization_id: &str,
        _transaction_id: &str,
        _holder_did: &str,
    ) -> Result<NativeInitiationDidcommDeliveryReceipt, NativeInitiationDidcommDeliveryError> {
        Err(self.error)
    }
}

#[async_trait]
impl DirectDidcommDelivery for ContractDelivery {
    async fn deliver_for_organization(
        &self,
        organization_id: &str,
        transaction_id: &str,
        holder_did: &str,
    ) -> Result<NativeInitiationDidcommDeliveryReceipt, NativeInitiationDidcommDeliveryError> {
        self.calls.lock().unwrap().push(json!({
            "organization_id": organization_id,
            "transaction_id": transaction_id,
            "holder_did": holder_did,
        }));
        Ok(self.receipt.clone())
    }
}

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/gateway-didcomm-delivery-behavior.json"
    ))
    .unwrap()
}

fn successful_delivery(expected: &Value) -> ContractDelivery {
    ContractDelivery {
        calls: Arc::new(Mutex::new(Vec::new())),
        receipt: NativeInitiationDidcommDeliveryReceipt {
            transaction_id: expected["transaction_id"].as_str().unwrap().to_owned(),
            credential_id: expected["credential_id"].as_str().unwrap().to_owned(),
            holder_did: expected["holder_did"].as_str().unwrap().to_owned(),
            service_endpoint: expected["service_endpoint"].as_str().unwrap().to_owned(),
            didcomm_message_id: expected["didcomm_message_id"].as_str().unwrap().to_owned(),
            status: NativeDidcommDeliveryStatus::Delivered,
            error: None,
        },
    }
}

fn app(delivery: ContractDelivery) -> axum::Router {
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).unwrap();
    let runtime = IssuanceRuntime::new(&config).unwrap();
    router_with_didcomm_delivery(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example", "Issuer"),
        TransportPolicy::new([]),
        InitiationDidcommHttpService::new(Arc::new(delivery), Some("test-api-key")),
    )
}

fn error_app(error: NativeInitiationDidcommDeliveryError) -> axum::Router {
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).unwrap();
    let runtime = IssuanceRuntime::new(&config).unwrap();
    router_with_didcomm_delivery(
        runtime.state(),
        StaticDiscoveryDocuments::new("https://issuer.example", "Issuer"),
        TransportPolicy::new([]),
        InitiationDidcommHttpService::new(
            Arc::new(ErrorContractDelivery { error }),
            Some("test-api-key"),
        ),
    )
}

fn request(body: Value, api_key: Option<&str>) -> Request<Body> {
    let mut request = Request::post("/v1/issuance/didcomm/deliver")
        .header("content-type", "application/json")
        .header("x-organization-id", "org_123");
    if let Some(api_key) = api_key {
        request = request.header("x-api-key", api_key);
    }
    request
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

async fn body(response: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn direct_didcomm_trusted_tenant_matches_captured_python_before_delivery() {
    let frozen: Value = serde_json::from_str(include_str!(
        "../../../../contracts/didcomm-trusted-tenant-python-reference.json"
    ))
    .unwrap();
    assert_eq!(
        frozen["schema"],
        "marty.didcomm-trusted-tenant-python-reference/v1"
    );
    assert_eq!(
        frozen["shared_contract"],
        "gateway-didcomm-delivery-behavior.json"
    );
    let shared = contract();
    let expected = &shared[frozen["success_body_ref"].as_str().unwrap()];
    let cases = frozen["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 6);
    for case in cases {
        let delivery = successful_delivery(expected);
        let calls = delivery.calls.clone();
        let input = shared[frozen["request_ref"].as_str().unwrap()].clone();
        let mut req = request(input.clone(), Some("test-api-key"));
        req.headers_mut().remove("x-organization-id");
        if let Some(tenant) = case["trusted_organization"].as_str() {
            req.headers_mut()
                .insert("x-organization-id", tenant.parse().unwrap());
        }
        let response = app(delivery).oneshot(req).await.unwrap();
        assert_eq!(
            u64::from(response.status().as_u16()),
            case["status"].as_u64().unwrap(),
            "{}",
            case["name"]
        );
        let expected_body = case.get("body").unwrap_or(expected);
        assert_eq!(&body(response).await, expected_body, "{}", case["name"]);
        let observed = calls.lock().unwrap();
        assert_eq!(
            observed.len() as u64,
            case["delivery_calls"].as_u64().unwrap()
        );
        if !observed.is_empty() {
            assert_eq!(observed.as_slice(), [input]);
        }
        // No invocation of this port also means no downstream repository lookup
        // is possible. Positive repository/crypto behavior is a separate gate.
        assert_eq!(case["lookup_calls"], case["delivery_calls"]);
    }
}

#[tokio::test]
async fn direct_didcomm_ineligible_states_match_captured_python_responses() {
    let frozen: Value = serde_json::from_str(include_str!(
        "../../../../contracts/didcomm-direct-state-python-reference.json"
    ))
    .unwrap();
    assert_eq!(
        frozen["schema"],
        "marty.didcomm-direct-state-python-reference/v1"
    );
    let cases = frozen["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    let input = contract()["valid_request"].clone();
    for case in cases {
        let state = CredentialTransactionStatus::try_from(case["state"].as_str().unwrap()).unwrap();
        let response =
            error_app(NativeInitiationDidcommDeliveryError::InvalidTransactionState(state))
                .oneshot(request(input.clone(), Some("test-api-key")))
                .await
                .unwrap();
        assert_eq!(
            u64::from(response.status().as_u16()),
            case["status"].as_u64().unwrap()
        );
        assert_eq!(body(response).await, case["body"]);
    }
}

#[tokio::test]
async fn direct_didcomm_route_matches_the_language_neutral_contract() {
    let contract = contract();
    let expected = &contract["expected_response"];
    let delivery = successful_delivery(expected);
    let response = app(delivery.clone())
        .oneshot(request(
            contract["valid_request"].clone(),
            Some("test-api-key"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(body(response).await, *expected);
    assert_eq!(
        delivery.calls.lock().unwrap().as_slice(),
        [contract["expected_request"].clone()]
    );
}

#[tokio::test]
async fn direct_didcomm_prerequisite_errors_match_captured_python_without_private_details() {
    let frozen: Value = serde_json::from_str(include_str!(
        "../../../../contracts/didcomm-public-error-python-reference.json"
    ))
    .unwrap();
    assert_eq!(
        frozen["schema"],
        "marty.didcomm-public-error-python-reference/v1"
    );
    let cases = frozen["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    let reasons = [
        NativeDidcommError::MissingEndpoint,
        NativeDidcommError::InvalidEndpoint,
        NativeDidcommError::HttpsRequired,
        NativeDidcommError::EndpointUnresolvable,
        NativeDidcommError::EndpointNotPublic,
        NativeDidcommError::IncompatibleKeyAgreement,
        NativeDidcommError::EncryptionPolicyUnavailable,
        NativeDidcommError::SenderAuthenticationUnavailable,
    ];
    let input = contract()["valid_request"].clone();
    for (case, reason) in cases.iter().zip(reasons) {
        assert_eq!(case["reason"], format!("{reason:?}"));
        let response = error_app(NativeInitiationDidcommDeliveryError::Prerequisite(reason))
            .oneshot(request(input.clone(), Some("test-api-key")))
            .await
            .unwrap();
        assert_eq!(
            u64::from(response.status().as_u16()),
            case["status"].as_u64().unwrap()
        );
        assert_eq!(body(response).await, case["body"]);
    }
    let tls: Value = serde_json::from_str(include_str!(
        "../../../../contracts/didcomm-tls-python-reference.json"
    ))
    .unwrap();
    for case in tls["cases"].as_array().unwrap().iter().take(2) {
        let response = error_app(NativeInitiationDidcommDeliveryError::Prerequisite(
            NativeDidcommError::TlsUnavailable,
        ))
        .oneshot(request(input.clone(), Some("test-api-key")))
        .await
        .unwrap();
        assert_eq!(
            u64::from(response.status().as_u16()),
            case["status"].as_u64().unwrap()
        );
        assert_eq!(body(response).await, case["body"]);
    }
    // No arbitrary resolver/packing/transport diagnostic is public. These
    // reasons were not captured as equivalent Python preflight responses.
    for reason in [
        NativeDidcommError::ResolutionUnavailable,
        NativeDidcommError::MismatchedDocument,
        NativeDidcommError::PackUnavailable,
        NativeDidcommError::TransportUnavailable,
    ] {
        let response = error_app(NativeInitiationDidcommDeliveryError::Prerequisite(reason))
            .oneshot(request(input.clone(), Some("test-api-key")))
            .await
            .unwrap();
        assert_eq!(response.status(), 503);
        assert_eq!(
            body(response).await,
            json!({"detail": "DIDComm delivery is unavailable"})
        );
    }
}

#[tokio::test]
async fn direct_didcomm_route_rejects_private_selectors_and_missing_authentication() {
    let contract = contract();
    let delivery = ContractDelivery {
        calls: Arc::new(Mutex::new(Vec::new())),
        receipt: NativeInitiationDidcommDeliveryReceipt {
            transaction_id: "unused".to_owned(),
            credential_id: "unused".to_owned(),
            holder_did: "did:example:unused".to_owned(),
            service_endpoint: "https://unused.example/didcomm".to_owned(),
            didcomm_message_id: "unused".to_owned(),
            status: NativeDidcommDeliveryStatus::Delivered,
            error: None,
        },
    };
    let missing_auth = app(delivery.clone())
        .oneshot(request(json!({"malformed":"unauthorized"}), None))
        .await
        .unwrap();
    assert_eq!(missing_auth.status(), 401);

    let invalid = app(delivery.clone())
        .oneshot(request(
            contract["invalid_requests"][3].clone(),
            Some("test-api-key"),
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), 422);
    assert!(delivery.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn direct_didcomm_route_replays_the_frozen_transport_claim_failures() {
    let contract = contract();
    assert_eq!(
        contract["transport_claim"]["lease_seconds"].as_i64(),
        Some(i64::from(DIDCOMM_TRANSPORT_CLAIM_LEASE_SECONDS))
    );
    assert_eq!(
        contract["transport_claim"]["claim_aware_statuses"]["ready"],
        DIDCOMM_TRANSPORT_READY_STATUS
    );
    assert_eq!(
        contract["transport_claim"]["claim_aware_statuses"]["definitely_unattempted"],
        DIDCOMM_TRANSPORT_RETRYABLE_STATUS
    );
    assert_eq!(
        contract["transport_claim"]["legacy_unmarked_statuses"],
        json!(["pending", "failed"])
    );
    assert_eq!(
        contract["transport_claim"]["legacy_unmarked_transition"],
        "delivery_unknown"
    );
    assert_eq!(
        contract["transport_claim"]["post_attempt_completion_failure"],
        json!({
            "response": "delivery_outcome_unknown",
            "reconciliation": "attempt_delivery_unknown_transition",
            "automatic_resend": false,
        })
    );
    for failure in contract["transport_claim"]["http_failures"]
        .as_array()
        .unwrap()
    {
        let error = match failure["error"].as_str().unwrap() {
            "concurrent_delivery" => NativeInitiationDidcommDeliveryError::ConcurrentDelivery,
            "delivery_outcome_unknown" => {
                NativeInitiationDidcommDeliveryError::DeliveryOutcomeUnknown
            }
            name => panic!("unsupported frozen DIDComm transport-claim failure: {name}"),
        };
        let response = error_app(error)
            .oneshot(request(
                contract["valid_request"].clone(),
                Some("test-api-key"),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            failure["status"].as_u64().unwrap() as u16
        );
        assert_eq!(
            body(response).await,
            json!({"detail": failure["detail"].as_str().unwrap()})
        );
    }
}
