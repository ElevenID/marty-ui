use std::sync::Arc;

use axum::{body::Body, http::Request};
use marty_flow::{flow_read_router, FlowHttpState, FlowProviderRegistry, PostgresFlowRepository};
use serde::Deserialize;
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    routes: Vec<[String; 3]>,
    principal_header: String,
    pagination: Pagination,
    status_filter: String,
    removed_statuses: Vec<String>,
    result_terminal_statuses: Vec<String>,
    pending_result_status: u16,
    mutations: Mutations,
    stored_private_context: String,
    malformed_stored_state: String,
    capabilities: Capabilities,
}

#[derive(Deserialize)]
struct Pagination {
    default_limit: usize,
    maximum_limit: usize,
    offset_minimum: usize,
}

#[derive(Deserialize)]
struct Capabilities {
    protocol_version: String,
    flow_type_count: usize,
    standard_flow_type_count: usize,
    trigger_count: usize,
    extensible_flow_type_count: usize,
    physical_document_source: String,
}

#[derive(Deserialize)]
struct Mutations {
    definition_delete_status: String,
    instance_cancel: String,
    instance_cancel_replay_status: u16,
    state_history_event: String,
}

fn router() -> axum::Router {
    let pool = PgPoolOptions::new()
        .connect_lazy("postgresql://localhost/flow")
        .expect("lazy pool");
    flow_read_router(FlowHttpState {
        repository: PostgresFlowRepository::new(pool),
        providers: Arc::new(FlowProviderRegistry::default()),
    })
}

#[tokio::test]
async fn rust_read_surface_matches_the_language_neutral_contract() {
    let contract: Contract = serde_json::from_str(include_str!(
        "../../../../contracts/flow-http-read-behavior.json"
    ))
    .expect("read contract");
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.routes.len(), 10);
    assert_eq!(
        contract
            .routes
            .iter()
            .filter(|route| route[0] == "GET")
            .count(),
        8
    );
    assert_eq!(contract.principal_header, "x-user-id");
    assert_eq!(contract.pagination.default_limit, 100);
    assert_eq!(contract.pagination.maximum_limit, 500);
    assert_eq!(contract.pagination.offset_minimum, 0);
    assert_eq!(contract.status_filter, "canonical_case_insensitive");
    assert_eq!(
        contract.removed_statuses,
        ["waiting", "waiting_approval", "canceled"]
    );
    assert_eq!(contract.result_terminal_statuses, ["completed", "failed"]);
    assert_eq!(contract.pending_result_status, 409);
    assert_eq!(contract.mutations.definition_delete_status, "draft_only");
    assert_eq!(
        contract.mutations.instance_cancel,
        "atomic_nonterminal_to_cancelled"
    );
    assert_eq!(contract.mutations.instance_cancel_replay_status, 409);
    assert_eq!(contract.mutations.state_history_event, "flow_cancelled");
    assert_eq!(contract.stored_private_context, "recursively_redacted");
    assert_eq!(contract.malformed_stored_state, "fail_closed");
    assert_eq!(
        contract.capabilities.physical_document_source,
        "required_healthy_provider"
    );

    let response = router()
        .oneshot(
            Request::get("/v1/flows/capabilities")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), 200);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body");
    let body: Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(
        body["protocol_version"],
        contract.capabilities.protocol_version
    );
    assert_eq!(
        body["flow_types"].as_array().expect("flow types").len(),
        contract.capabilities.flow_type_count
    );
    assert_eq!(
        body["standard_flow_types"]
            .as_array()
            .expect("standard flow types")
            .len(),
        contract.capabilities.standard_flow_type_count
    );
    assert_eq!(
        body["triggers"].as_array().expect("triggers").len(),
        contract.capabilities.trigger_count
    );
    assert_eq!(
        body["extensible_steps"]
            .as_object()
            .expect("extensible steps")
            .len(),
        contract.capabilities.extensible_flow_type_count
    );

    let protected = router()
        .oneshot(
            Request::get("/v1/flows/instances?organization_id=org-1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(protected.status(), 401);
}
