use std::collections::BTreeSet;

use serde_json::Value;

fn contract() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/issuance-canvas-management.json"
    ))
    .expect("Canvas management contract")
}

fn runtime_surface() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/issuance-runtime-surface.json"
    ))
    .expect("issuance runtime surface")
}

fn native_coverage() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/issuance-native-coverage.json"
    ))
    .expect("issuance native coverage")
}

#[test]
fn canvas_management_contract_freezes_exactly_the_remaining_router_surface() {
    let contract = contract();
    assert_eq!(contract["schema"], "marty.issuance-canvas-management/v1");
    assert_eq!(contract["scope"]["route_count"], 31);
    assert_eq!(
        contract["scope"]["source"],
        "services/issuance/infrastructure/api/canvas_routes.py"
    );

    let routes = contract["scope"]["routes"]
        .as_array()
        .expect("contract routes");
    assert_eq!(routes.len(), 31);
    let exact_routes = routes
        .iter()
        .map(|route| {
            (
                route["method"].as_str().expect("method").to_owned(),
                route["path"].as_str().expect("path").to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(exact_routes.len(), routes.len(), "routes must be unique");

    let already_native = native_coverage()["native_http"]
        .as_array()
        .expect("native routes")
        .iter()
        .map(|route| {
            (
                route["method"].as_str().expect("method").to_owned(),
                route["path"].as_str().expect("path").to_owned(),
            )
        })
        .collect::<BTreeSet<_>>();
    let upstream_routes = runtime_surface()["http"]["routes"]
        .as_array()
        .expect("runtime routes")
        .iter()
        .filter(|route| route["router"] == "canvas_integration_router")
        .map(|route| {
            (
                route["method"].as_str().expect("method").to_owned(),
                route["path"].as_str().expect("path").to_owned(),
            )
        })
        .filter(|route| !already_native.contains(route))
        .collect::<BTreeSet<_>>();
    assert_eq!(exact_routes, upstream_routes);

    let management = routes
        .iter()
        .filter(|route| route["authentication"] == "management-api-key-and-trusted-organization")
        .count();
    let legacy = routes
        .iter()
        .filter(|route| route["authentication"] == "default-disabled-legacy-ingest")
        .count();
    let public = routes
        .iter()
        .filter(|route| route["authentication"] == "public-revocable-token")
        .count();
    assert_eq!((management, legacy, public), (27, 3, 1));
}

#[test]
fn canvas_management_contract_retains_the_feature_and_security_floor() {
    let contract = contract();
    assert_eq!(
        contract["management_boundary"]["cross_tenant_policy"],
        "hide-as-not-found-before-provider-or-mutation-work"
    );
    assert_eq!(
        contract["platform_lifecycle"]["archive"]["soft_delete"],
        true
    );
    assert_eq!(
        contract["registration"]["public_config"]["persistence"],
        "sha256-only"
    );
    assert_eq!(
        contract["program_binding"]["activation"]["existing_applications_enqueued_for_sync"],
        true
    );
    assert_eq!(
        contract["integration_secrets"]["storage"],
        "encrypted-organization-secret"
    );
    let validation = &contract["canvas_credentials_provider_validation"];
    assert_eq!(validation["never_publishes_a_credential"], true);
    assert_eq!(
        validation["allowed_providers"],
        serde_json::json!(["bridge", "badgr_api", "canvas_credentials_api"])
    );
    assert_eq!(
        validation["tenant_secret"]["never_returned_or_logged"],
        true
    );
    assert_eq!(validation["real_api"]["redirects_followed"], false);
    assert_eq!(
        validation["response_fields"]
            .as_array()
            .expect("provider validation response fields")
            .len(),
        13
    );
    assert_eq!(
        contract["application_approval"]["uses_canonical_issuance_guard"],
        true
    );
    assert_eq!(contract["legacy_ingest"]["default_enabled"], false);
    assert_eq!(
        contract["legacy_ingest"]["disabled_before_body_or_repository_processing"],
        true
    );
    assert_eq!(
        contract["security_invariants"]
            .as_array()
            .expect("security invariants")
            .len(),
        11
    );
}
