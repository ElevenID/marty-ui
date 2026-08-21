use std::collections::BTreeSet;

use marty_credential_template::surface::{
    CREDENTIAL_TEMPLATE_GRPC_METHODS, CREDENTIAL_TEMPLATE_HTTP_ROUTES,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Contract {
    schema_version: u32,
    http_routes: Vec<String>,
    grpc_methods: Vec<String>,
}

fn contract() -> Contract {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/credential-template-service-surface.json"
    )))
    .expect("valid Credential Template service surface")
}

#[test]
fn rust_surface_freezes_every_intended_http_and_grpc_operation() {
    let contract = contract();
    assert_eq!(contract.schema_version, 1);
    assert_eq!(contract.http_routes.len(), 24);
    assert_eq!(contract.grpc_methods.len(), 12);
    assert_eq!(
        contract
            .http_routes
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        CREDENTIAL_TEMPLATE_HTTP_ROUTES
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        contract
            .grpc_methods
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        CREDENTIAL_TEMPLATE_GRPC_METHODS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
    );
}
