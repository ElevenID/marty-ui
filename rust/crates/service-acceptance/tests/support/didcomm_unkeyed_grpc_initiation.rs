//! One unkeyed native protobuf initiation, using the shared actual delivery graph.
//! This is the governed HTTP-equivalent target, not legacy gRPC or keyed Flow.
use std::{sync::Arc, time::Duration};

use marty_issuance_service::{
    credential_management_events::{CredentialLifecycleEventBus, CredentialLifecycleEventFilter},
    issuance_proto::{
        issuance_service_client::IssuanceServiceClient, InitiateIssuanceRequest, IssuanceResponse,
    },
};
use serde_json::{json, Value};
use sqlx::PgPool;

use super::super::didcomm_native_grpc_fixture::{native_server, NativeInitiation, OwnedGrpc};
use super::{
    fresh_initiation::{self, Admission, Scenario},
    ControlledIssuer, NativeInitiationDidcommDelivery, PostgresCredentialRepository, ORGANIZATION,
    SERVICE_TOKEN,
};

pub(super) async fn initiate(
    pool: &PgPool,
    repository: Arc<PostgresCredentialRepository>,
    delivery: Arc<NativeInitiationDidcommDelivery>,
    issuer: Arc<ControlledIssuer>,
    id: &str,
    scenario: Scenario,
) -> (Value, Arc<Admission>) {
    assert!(scenario.historical_status().is_none());
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../contracts/issuance-initiation.json"
    ))
    .unwrap();
    assert_eq!(
        contract["response"]["didcomm"]["legacy_grpc"],
        "openid-offer-only"
    );
    assert_eq!(
        contract["response"]["didcomm"]["native_rust_target"],
        "same-delivery-semantics-as-http"
    );
    let (service, projector, admission) =
        fresh_initiation::services(repository.clone(), delivery, issuer.clone(), id, scenario);
    let events = CredentialLifecycleEventBus::default();
    let mut emitted = events.subscribe(CredentialLifecycleEventFilter::new(
        Some(ORGANIZATION),
        Some("didcomm-template"),
        ["offer_created".into()],
    ));
    let server = OwnedGrpc::start(native_server(
        pool,
        NativeInitiation {
            repository,
            service,
            projector,
            issuer_resolver: issuer,
        },
        events,
        SERVICE_TOKEN,
        b"synthetic-composed-hmac-key",
    ))
    .await;
    let body = fresh_initiation::request_body(scenario);
    let value = |name: &str| body[name].as_str().unwrap_or_default().to_owned();
    let request = InitiateIssuanceRequest {
        organization_id: value("organization_id"),
        credential_template_id: value("credential_template_id"),
        issuer_did: value("issuer_did"),
        holder_did: value("holder_did"),
        subject_did: value("subject_did"),
        claims_json: body["claims"].to_string(),
        ..InitiateIssuanceRequest::default()
    };
    assert!(
        request.idempotency_key.is_empty(),
        "unkeyed service capability, never a modified Flow request"
    );
    let mut request = tonic::Request::new(request);
    request
        .metadata_mut()
        .insert("x-service-token", SERVICE_TOKEN.parse().unwrap());
    let mut client = IssuanceServiceClient::new(server.channel());
    let response = tokio::time::timeout(Duration::from_secs(15), client.initiate_issuance(request))
        .await
        .unwrap()
        .unwrap()
        .into_inner();
    // Exhaustive protobuf destructuring: preserve every internal RPC field,
    // including the capability; gateway privacy projection is a separate gate.
    let IssuanceResponse {
        id: response_id,
        organization_id,
        credential_template_id,
        status,
        credential_offer_uri,
        credential_offer_uris,
        credential_offer_labels,
        pre_auth_code,
        expires_at,
    } = response;
    let full_response = json!({"id":response_id, "organization_id":organization_id,
        "credential_template_id":credential_template_id, "status":status,
        "credential_offer_uri":credential_offer_uri, "credential_offer_uris":credential_offer_uris,
        "credential_offer_labels":credential_offer_labels, "pre_auth_code":pre_auth_code, "expires_at":expires_at});
    let event = tokio::time::timeout(Duration::from_secs(1), emitted.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(event.event_type, contract["events"]["grpc_created"]);
    assert_eq!(event.transaction_id, id);
    assert_eq!(event.organization_id, ORGANIZATION);
    assert_eq!(event.credential_template_id, "didcomm-template");
    assert_eq!(
        event.status, "pending",
        "existing offer-created event, even if delivery subsequently issued the transaction"
    );
    // Post-RPC in-memory event-bus observation, not durable-outbox proof.
    assert!(
        tokio::time::timeout(Duration::from_millis(20), emitted.recv())
            .await
            .is_err()
    );
    drop(client);
    server.close().await;
    // The composed caller now checks full response, crypto and durable effects.
    // It replays direct/projector delivery only: a second unkeyed RPC would be
    // a new admission, not an idempotent replay of this one.
    (full_response, admission)
}
