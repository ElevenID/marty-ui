use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use chrono::{TimeZone, Utc};
use http_body_util::BodyExt;
use marty_issuance_service::{
    application_template_domain::{
        ApplicationTemplateRecord, ApplicationTemplateStatus, CredentialTemplateValidationView,
    },
    application_template_http,
    application_template_service::{
        ApplicationTemplateCatalog, ApplicationTemplateCatalogError, ApplicationTemplateClock,
        ApplicationTemplateIdempotencyBinding, ApplicationTemplateRepository,
        ApplicationTemplateRepositoryError, ApplicationTemplateReservation,
        ApplicationTemplateService, ApprovalPolicyRecord,
    },
};
use serde_json::{json, Value};
use tower::ServiceExt;

#[derive(Default)]
struct MemoryState {
    templates: BTreeMap<(String, String), ApplicationTemplateRecord>,
    idempotency: HashMap<(String, String), (String, String)>,
}

#[derive(Default)]
struct MemoryRepository {
    state: Mutex<MemoryState>,
}

impl MemoryRepository {
    fn seed(&self, template: ApplicationTemplateRecord) {
        self.state
            .lock()
            .expect("repository state")
            .templates
            .insert(
                (template.organization_id.clone(), template.id.clone()),
                template,
            );
    }

    fn count(&self) -> usize {
        self.state.lock().expect("repository state").templates.len()
    }
}

#[async_trait]
impl ApplicationTemplateRepository for MemoryRepository {
    async fn reserve_idempotently(
        &self,
        template: &ApplicationTemplateRecord,
        binding: &ApplicationTemplateIdempotencyBinding,
    ) -> Result<ApplicationTemplateReservation, ApplicationTemplateRepositoryError> {
        let mut state = self.state.lock().expect("repository state");
        let binding_key = (template.organization_id.clone(), binding.key_hash.clone());
        if let Some((request_hash, template_id)) = state.idempotency.get(&binding_key) {
            if request_hash != &binding.request_hash {
                return Err(ApplicationTemplateRepositoryError::IdempotencyConflict);
            }
            let template = state
                .templates
                .get(&(template.organization_id.clone(), template_id.clone()))
                .cloned()
                .expect("idempotency record references template");
            return Ok(ApplicationTemplateReservation {
                template,
                created: false,
            });
        }
        state.idempotency.insert(
            binding_key,
            (binding.request_hash.clone(), template.id.clone()),
        );
        state.templates.insert(
            (template.organization_id.clone(), template.id.clone()),
            template.clone(),
        );
        Ok(ApplicationTemplateReservation {
            template: template.clone(),
            created: true,
        })
    }

    async fn list(
        &self,
        organization_id: &str,
    ) -> Result<Vec<ApplicationTemplateRecord>, ApplicationTemplateRepositoryError> {
        let mut templates = self
            .state
            .lock()
            .expect("repository state")
            .templates
            .values()
            .filter(|template| template.organization_id == organization_id)
            .cloned()
            .collect::<Vec<_>>();
        templates.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(templates)
    }

    async fn get(
        &self,
        organization_id: &str,
        template_id: &str,
    ) -> Result<Option<ApplicationTemplateRecord>, ApplicationTemplateRepositoryError> {
        Ok(self
            .state
            .lock()
            .expect("repository state")
            .templates
            .get(&(organization_id.to_owned(), template_id.to_owned()))
            .cloned())
    }

    async fn replace_if_version(
        &self,
        template: &ApplicationTemplateRecord,
        expected_version: i64,
    ) -> Result<(), ApplicationTemplateRepositoryError> {
        let mut state = self.state.lock().expect("repository state");
        let Some(stored) = state
            .templates
            .get_mut(&(template.organization_id.clone(), template.id.clone()))
        else {
            return Err(ApplicationTemplateRepositoryError::ConcurrentModification);
        };
        if stored.version != expected_version {
            return Err(ApplicationTemplateRepositoryError::ConcurrentModification);
        }
        *stored = template.clone();
        Ok(())
    }

    async fn delete_if_version(
        &self,
        organization_id: &str,
        template_id: &str,
        expected_version: i64,
    ) -> Result<(), ApplicationTemplateRepositoryError> {
        let mut state = self.state.lock().expect("repository state");
        let key = (organization_id.to_owned(), template_id.to_owned());
        if state.templates.get(&key).map(|template| template.version) != Some(expected_version) {
            return Err(ApplicationTemplateRepositoryError::ConcurrentModification);
        }
        state.templates.remove(&key);
        Ok(())
    }

    async fn approval_policy(
        &self,
        _organization_id: &str,
        _policy_set_id: &str,
    ) -> Result<Option<ApprovalPolicyRecord>, ApplicationTemplateRepositoryError> {
        Ok(None)
    }
}

struct NoCatalogCalls;

#[async_trait]
impl ApplicationTemplateCatalog for NoCatalogCalls {
    async fn get_strict(
        &self,
        _template_id: &str,
    ) -> Result<Option<CredentialTemplateValidationView>, ApplicationTemplateCatalogError> {
        panic!("the frozen shared cases must not call the credential-template catalog")
    }
}

struct FixedClock;

impl ApplicationTemplateClock for FixedClock {
    fn now(&self) -> chrono::DateTime<Utc> {
        fixed_time()
    }
}

fn fixed_time() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 19, 12, 0, 0)
        .single()
        .expect("fixed timestamp")
}

fn contract() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../contracts/issuance-application-templates.json");
    serde_json::from_slice(&std::fs::read(path).expect("shared application-template contract"))
        .expect("valid shared contract")
}

fn reference(contract: &Value, reference: &str) -> Value {
    contract
        .pointer(reference.strip_prefix('#').expect("local JSON pointer"))
        .cloned()
        .expect("contract reference")
}

fn arranged_template(contract: &Value, value: &Value) -> ApplicationTemplateRecord {
    let mut value = value.as_object().expect("template arrangement").clone();
    if let Some(reference_name) = value
        .remove("overlay_ref")
        .and_then(|value| value.as_str().map(str::to_owned))
    {
        let overlay = reference(contract, &reference_name);
        value.extend(overlay.as_object().expect("template overlay").clone());
    }
    let string = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let optional = |name: &str| value.get(name).and_then(Value::as_str).map(str::to_owned);
    let array = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let object = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default()
    };
    ApplicationTemplateRecord {
        id: string("id"),
        organization_id: string("organization_id"),
        name: value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("Contract template")
            .to_owned(),
        description: optional("description"),
        credential_template_id: optional("credential_template_id"),
        form_fields: array("form_fields"),
        evidence_requirements: array("evidence_requirements"),
        claim_collection_rules: array("claim_collection_rules"),
        required_checks: array("required_checks"),
        approval_strategy: value
            .get("approval_strategy")
            .and_then(Value::as_str)
            .unwrap_or("MANUAL")
            .to_owned(),
        approval_policy_set_id: optional("approval_policy_set_id"),
        application_validity_days: value
            .get("application_validity_days")
            .and_then(Value::as_i64)
            .unwrap_or(30),
        ui_config: object("ui_config"),
        notification_config: object("notification_config"),
        status: match value
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("DRAFT")
        {
            "ACTIVE" => ApplicationTemplateStatus::Active,
            "DEPRECATED" => ApplicationTemplateStatus::Deprecated,
            _ => ApplicationTemplateStatus::Draft,
        },
        version: 1,
        created_at: fixed_time(),
        updated_at: fixed_time(),
    }
}

#[tokio::test]
async fn rust_http_boundary_passes_every_shared_language_neutral_case() {
    let contract = contract();
    for case in contract["cases"].as_array().expect("shared cases") {
        let repository = Arc::new(MemoryRepository::default());
        for template in case["arrange"]["application_templates"]
            .as_array()
            .expect("template arrangements")
        {
            repository.seed(arranged_template(&contract, template));
        }
        let before = repository.count();
        let service = ApplicationTemplateService::new(
            repository.clone(),
            Arc::new(NoCatalogCalls),
            Arc::new(FixedClock),
            Some("valid"),
        );
        let request = &case["request"];
        let mut builder = Request::builder()
            .method(request["method"].as_str().expect("method"))
            .uri(request["path"].as_str().expect("path"));
        for (name, value) in request["headers"].as_object().into_iter().flatten() {
            builder = builder.header(name, value.as_str().expect("header value"));
        }
        let body = if let Some(reference_name) = request.get("json_ref").and_then(Value::as_str) {
            reference(&contract, reference_name)
        } else {
            request.get("json").cloned().unwrap_or(Value::Null)
        };
        let response = application_template_http::router(service)
            .oneshot(
                builder
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).expect("request JSON")))
                    .expect("HTTP request"),
            )
            .await
            .expect("router response");
        let expected = &case["expected"];
        assert_eq!(
            response.status().as_u16(),
            expected["status"].as_u64().expect("expected status") as u16,
            "{}",
            case["name"].as_str().expect("case name")
        );
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        if expected["body_empty"].as_bool().unwrap_or(false) {
            assert!(bytes.is_empty());
        } else {
            let actual: Value = serde_json::from_slice(&bytes).expect("JSON response");
            if let Some(expected_json) = expected.get("json") {
                let mut expected_json = expected_json.clone();
                let errors_ref = expected_json
                    .get("errors_ref")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if let Some(errors_ref) = errors_ref {
                    expected_json
                        .as_object_mut()
                        .expect("expected JSON object")
                        .insert("errors".to_owned(), reference(&contract, &errors_ref));
                }
                if let Some(object) = expected_json.as_object_mut() {
                    object.remove("errors_ref");
                }
                assert_eq!(actual, expected_json, "{}", case["name"]);
            }
            if let Some(reference_name) = expected.get("body_contains_ref").and_then(Value::as_str)
            {
                let subset = reference(&contract, reference_name);
                for (name, value) in subset.as_object().expect("body subset") {
                    assert_eq!(&actual[name], value, "{}: {name}", case["name"]);
                }
            }
        }
        if let Some(expected_count) = expected
            .get("persisted_template_count")
            .and_then(Value::as_u64)
        {
            assert_eq!(
                repository.count(),
                expected_count as usize,
                "{}",
                case["name"]
            );
        }
        if expected.get("persisted_state").and_then(Value::as_str) == Some("unchanged") {
            assert_eq!(repository.count(), before, "{}", case["name"]);
        }
    }
}

#[tokio::test]
async fn missing_query_and_security_failures_match_the_frozen_boundary() {
    let service = ApplicationTemplateService::new(
        Arc::new(MemoryRepository::default()),
        Arc::new(NoCatalogCalls),
        Arc::new(FixedClock),
        Some("valid"),
    );
    for (headers, expected_status, expected_body) in [
        (
            vec![("x-api-key", "valid")],
            400,
            json!({"detail": "X-Organization-ID is required for application management"}),
        ),
        (
            vec![("x-organization-id", "org-123")],
            401,
            json!({"detail": "X-API-Key header is missing"}),
        ),
        (
            vec![("x-api-key", "wrong"), ("x-organization-id", "org-123")],
            401,
            json!({"detail": "Invalid API Key"}),
        ),
    ] {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/application-templates")
            .header("content-type", "application/json")
            .header("idempotency-key", "test-key");
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let response = application_template_http::router(service.clone())
            .oneshot(
                builder
                    .body(Body::from(
                        json!({"organization_id": "org-123", "name": "Template"}).to_string(),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status().as_u16(), expected_status);
        let body: Value = serde_json::from_slice(
            &response
                .into_body()
                .collect()
                .await
                .expect("response body")
                .to_bytes(),
        )
        .expect("JSON body");
        assert_eq!(body, expected_body);
    }

    let response = application_template_http::router(service.clone())
        .oneshot(
            Request::builder()
                .uri("/v1/application-templates")
                .header("x-api-key", "valid")
                .header("x-organization-id", "org-123")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status().as_u16(), 422);

    for (headers, expected_status) in [
        (vec![], 401),
        (vec![("x-api-key", "valid")], 400),
        (
            vec![("x-api-key", "valid"), ("x-organization-id", "org-123")],
            400,
        ),
    ] {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/v1/application-templates")
            .header("content-type", "application/json");
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let response = application_template_http::router(service.clone())
            .oneshot(
                builder
                    .body(Body::from("{"))
                    .expect("malformed preflight request"),
            )
            .await
            .expect("preflight response");
        assert_eq!(response.status().as_u16(), expected_status);
    }

    let response = application_template_http::router(service)
        .oneshot(
            Request::builder()
                .uri("/v1/application-templates?organization_id=%20%20")
                .header("x-api-key", "valid")
                .header("x-organization-id", "org-123")
                .body(Body::empty())
                .expect("blank tenant query"),
        )
        .await
        .expect("blank tenant response");
    assert_eq!(response.status().as_u16(), 404);
}
