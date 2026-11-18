use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use marty_issuance_service::{
    http::router_with_resource_owners,
    resource_owner::{ResourceOwnerKind, ResourceOwnerRepository, ResourceOwnerService},
    transaction_reads::TransactionReadError,
    IssuanceRuntime, IssuanceServiceConfig,
};
use marty_oid4vci::discovery::StaticDiscoveryDocuments;
use serde_json::Value;
use tower::ServiceExt;

#[derive(Clone, Default)]
struct Owners {
    values: BTreeMap<(ResourceOwnerKind, String), String>,
    calls: Arc<Mutex<Vec<(ResourceOwnerKind, String)>>>,
    unavailable: bool,
}

#[async_trait]
impl ResourceOwnerRepository for Owners {
    async fn find_owner(
        &self,
        kind: ResourceOwnerKind,
        resource_id: &str,
    ) -> Result<Option<String>, TransactionReadError> {
        self.calls
            .lock()
            .expect("calls")
            .push((kind, resource_id.to_owned()));
        if self.unavailable {
            return Err(TransactionReadError::RepositoryUnavailable);
        }
        Ok(self.values.get(&(kind, resource_id.to_owned())).cloned())
    }
}

fn app(repository: Owners, api_key: Option<&str>) -> axum::Router {
    let config =
        IssuanceServiceConfig::from_values(std::iter::empty::<(String, String)>()).expect("config");
    router_with_resource_owners(
        IssuanceRuntime::new(&config).expect("runtime").state(),
        StaticDiscoveryDocuments::new("https://issuer.example", "Example"),
        marty_issuance_service::transport::TransportPolicy::new(Vec::new()),
        ResourceOwnerService::new(Arc::new(repository), api_key),
    )
}

async fn request(
    app: axum::Router,
    path: &str,
    key: Option<&str>,
    tenant: Option<&str>,
) -> (u16, Value) {
    let mut builder = Request::get(path);
    if let Some(key) = key {
        builder = builder.header("X-API-Key", key);
    }
    if let Some(tenant) = tenant {
        builder = builder.header("X-Organization-ID", tenant);
    }
    let response = app
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = response.status().as_u16();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, serde_json::from_slice(&body).expect("json"))
}

#[tokio::test]
async fn all_three_owner_routes_follow_the_frozen_language_neutral_contract() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-resource-owner-lookups.json"
    ))
    .expect("contract");
    let kinds = [
        ResourceOwnerKind::ApplicationTemplate,
        ResourceOwnerKind::IssuedCredential,
        ResourceOwnerKind::IssuanceTransaction,
    ];
    let ids = ["template-1", "credential-1", "transaction-1"];
    let mut repository = Owners::default();
    for (kind, id) in kinds.into_iter().zip(ids) {
        repository
            .values
            .insert((kind, id.to_owned()), "org-owner".to_owned());
    }
    for ((operation, kind), id) in contract["operations"]
        .as_array()
        .expect("operations")
        .iter()
        .zip(kinds)
        .zip(ids)
    {
        let path = operation["path"]
            .as_str()
            .expect("path")
            .replace("{template_id}", id)
            .replace("{credential_id}", id)
            .replace("{transaction_id}", id);
        let before = repository.calls.lock().expect("calls").len();
        let (status, body) = request(
            app(repository.clone(), Some("secret")),
            &path,
            Some("secret"),
            Some("org-foreign"),
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(body, contract["responses"]["found"]["body"]);
        {
            let calls = repository.calls.lock().expect("calls");
            assert_eq!(calls.len(), before + 1);
            assert_eq!(calls[before], (kind, id.to_owned()));
        }

        let missing = path.replace(id, "missing");
        let before_missing = repository.calls.lock().expect("calls").len();
        let (status, body) = request(
            app(repository.clone(), Some("secret")),
            &missing,
            Some("secret"),
            None,
        )
        .await;
        assert_eq!(status, 404);
        assert_eq!(body, contract["responses"]["not_found"]["body"]);
        let calls = repository.calls.lock().expect("calls");
        assert_eq!(calls.len(), before_missing + 1);
        assert_eq!(calls[before_missing], (kind, "missing".to_owned()));
    }
}

#[tokio::test]
async fn repository_failure_is_sanitized_without_disclosing_its_cause() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-resource-owner-lookups.json"
    ))
    .expect("contract");
    let repository = Owners {
        unavailable: true,
        ..Owners::default()
    };
    let path = "/internal/v1/resource-owners/issued-credentials/opaque-ID_42";
    let (status, body) = request(
        app(repository.clone(), Some("secret")),
        path,
        Some("secret"),
        Some("org-foreign"),
    )
    .await;
    let expected = &contract["responses"]["repository_unavailable"];
    assert_eq!(u64::from(status), expected["status_code"].as_u64().unwrap());
    assert_eq!(body, expected["body"]);
    let rendered = body.to_string();
    assert!(!rendered.contains("database"));
    assert!(!rendered.contains("sql"));
    assert_eq!(expected["cause_disclosed"], false);
    assert_eq!(
        *repository.calls.lock().expect("calls"),
        vec![(
            ResourceOwnerKind::IssuedCredential,
            "opaque-ID_42".to_owned()
        )]
    );
}

#[tokio::test]
async fn authentication_precedes_repository_access_with_exact_errors() {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-resource-owner-lookups.json"
    ))
    .expect("contract");
    let repository = Owners::default();
    let path = "/internal/v1/resource-owners/application-templates/template-1";
    for (configured, supplied, response_name) in [
        (None, None, "api_key_unconfigured"),
        (Some("secret"), None, "api_key_missing"),
        (Some("secret"), Some(""), "api_key_missing"),
        (Some("secret"), Some("wrong"), "api_key_invalid"),
    ] {
        let (status, body) =
            request(app(repository.clone(), configured), path, supplied, None).await;
        assert_eq!(
            u64::from(status),
            contract["responses"][response_name]["status_code"]
                .as_u64()
                .expect("status")
        );
        assert_eq!(body, contract["responses"][response_name]["body"]);
    }
    assert!(repository.calls.lock().expect("calls").is_empty());
}
