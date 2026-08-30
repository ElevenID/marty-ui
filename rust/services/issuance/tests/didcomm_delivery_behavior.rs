use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use marty_issuance_service::{
    http::router_with_didcomm_delivery,
    initiation_didcomm::{
        NativeDidcommDeliveryStatus, NativeInitiationDidcommDeliveryError,
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
    let mut request =
        Request::post("/v1/issuance/didcomm/deliver").header("content-type", "application/json");
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
async fn direct_didcomm_route_matches_the_language_neutral_contract() {
    let contract = contract();
    let expected = &contract["expected_response"];
    let delivery = ContractDelivery {
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
    };
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
