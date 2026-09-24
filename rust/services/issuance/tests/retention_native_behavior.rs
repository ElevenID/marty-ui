use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chrono::{DateTime, TimeZone, Utc};
use marty_issuance_service::{
    retention::{
        RetentionClock, RetentionRecordCounts, RetentionRepository, RetentionService,
        RetentionSnapshot,
    },
    retention_http,
};
use serde_json::{json, Value};
use tower::ServiceExt;

const CONTRACT: &str = include_str!("../../../../contracts/issuance-retention-management.json");

#[derive(Clone)]
struct FixedClock(DateTime<Utc>);

impl RetentionClock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

#[derive(Default)]
struct FakeRetentionRepository {
    calls: Mutex<Vec<(String, String)>>,
    purged: Mutex<bool>,
}

impl FakeRetentionRepository {
    fn counts() -> RetentionRecordCounts {
        RetentionRecordCounts {
            issuance_transactions: 1,
            applications: 1,
            authorization_sessions: 1,
            issuance_events: 1,
            issued_credentials: 1,
            total: 5,
        }
    }
}

#[async_trait]
impl RetentionRepository for FakeRetentionRepository {
    async fn summary(
        &self,
        organization_id: &str,
        _cutoff_at: DateTime<Utc>,
    ) -> Result<RetentionSnapshot, sqlx::Error> {
        self.calls
            .lock()
            .unwrap()
            .push(("summary".into(), organization_id.into()));
        Ok(RetentionSnapshot {
            eligible_for_purge: if *self.purged.lock().unwrap() {
                RetentionRecordCounts::default()
            } else {
                Self::counts()
            },
            oldest_retained_record_at: Some(Utc.with_ymd_and_hms(2026, 1, 25, 0, 0, 0).unwrap()),
        })
    }

    async fn purge(
        &self,
        organization_id: &str,
        _cutoff_at: DateTime<Utc>,
    ) -> Result<RetentionRecordCounts, sqlx::Error> {
        self.calls
            .lock()
            .unwrap()
            .push(("purge".into(), organization_id.into()));
        let mut purged = self.purged.lock().unwrap();
        if *purged {
            Ok(RetentionRecordCounts::default())
        } else {
            *purged = true;
            Ok(Self::counts())
        }
    }
}

async fn request(
    method: &str,
    path: &str,
    api_key: Option<&str>,
    organization: Option<&str>,
    repo: Arc<dyn RetentionRepository>,
) -> (StatusCode, Value) {
    let (status, body) = request_raw(method, path, api_key, organization, repo).await;
    (status, serde_json::from_slice(&body).unwrap())
}

async fn request_raw(
    method: &str,
    path: &str,
    api_key: Option<&str>,
    organization: Option<&str>,
    repo: Arc<dyn RetentionRepository>,
) -> (StatusCode, Vec<u8>) {
    request_raw_config(
        method,
        path,
        api_key,
        organization,
        repo,
        Some("management-key"),
    )
    .await
}

async fn request_raw_config(
    method: &str,
    path: &str,
    api_key: Option<&str>,
    organization: Option<&str>,
    repo: Arc<dyn RetentionRepository>,
    configured_api_key: Option<&str>,
) -> (StatusCode, Vec<u8>) {
    let clock = Arc::new(FixedClock(
        Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap(),
    ));
    let service = RetentionService::new(repo, configured_api_key).with_clock(clock);
    let app = retention_http::router(service);
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(api_key) = api_key {
        builder = builder.header("X-API-Key", api_key);
    }
    if let Some(organization) = organization {
        builder = builder.header("X-Organization-ID", organization);
    }
    let response = app
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1_048_576).await.unwrap();
    (status, body.to_vec())
}

struct FailingRetentionRepository;

#[async_trait]
impl RetentionRepository for FailingRetentionRepository {
    async fn summary(
        &self,
        _organization_id: &str,
        _cutoff_at: DateTime<Utc>,
    ) -> Result<RetentionSnapshot, sqlx::Error> {
        Err(sqlx::Error::Protocol(
            "synthetic-private-repository-detail".into(),
        ))
    }

    async fn purge(
        &self,
        _organization_id: &str,
        _cutoff_at: DateTime<Utc>,
    ) -> Result<RetentionRecordCounts, sqlx::Error> {
        Err(sqlx::Error::Protocol(
            "synthetic-private-repository-detail".into(),
        ))
    }
}

#[tokio::test]
async fn frozen_retention_repository_failure_is_generic_for_both_routes() {
    let contract: Value = serde_json::from_str(CONTRACT).unwrap();
    for route in contract["routes"].as_array().unwrap() {
        let method = route["method"].as_str().unwrap();
        let path = route["path"]
            .as_str()
            .unwrap()
            .replace("{organization_id}", "organization-a");
        let (status, body) = request_raw(
            method,
            &path,
            Some("management-key"),
            Some("organization-a"),
            Arc::new(FailingRetentionRepository),
        )
        .await;
        assert_eq!(
            u64::from(status.as_u16()),
            contract["repository_failure"]["status"].as_u64().unwrap()
        );
        assert_eq!(
            String::from_utf8(body).unwrap(),
            contract["repository_failure"]["body"].as_str().unwrap()
        );
    }
}

#[tokio::test]
async fn frozen_retention_boundary_precedes_repository_access() {
    let contract: Value = serde_json::from_str(CONTRACT).unwrap();
    let repo = Arc::new(FakeRetentionRepository::default());
    for route in contract["routes"].as_array().unwrap() {
        let method = route["method"].as_str().unwrap();
        let path = route["path"]
            .as_str()
            .unwrap()
            .replace("{organization_id}", "organization-a");
        for (key, organization, status, detail) in [
            (None, None, StatusCode::UNAUTHORIZED, "missing_api_key"),
            (
                Some("wrong"),
                None,
                StatusCode::UNAUTHORIZED,
                "invalid_api_key",
            ),
            (
                Some("management-key"),
                None,
                StatusCode::FORBIDDEN,
                "missing_trusted_organization",
            ),
            (
                Some("management-key"),
                Some("organization-b"),
                StatusCode::FORBIDDEN,
                "different_trusted_organization",
            ),
        ] {
            let (actual_status, body) =
                request(method, &path, key, organization, repo.clone()).await;
            assert_eq!(actual_status, status);
            assert_eq!(body["detail"], contract["boundary"]["error_detail"][detail]);
            assert!(repo.calls.lock().unwrap().is_empty());
        }
        for case in contract["retention_days"]["invalid_queries"]
            .as_array()
            .unwrap()
        {
            let invalid = case["input"].as_str().unwrap();
            let path = format!("{path}?retention_days={invalid}");
            let (status, body) = request(
                method,
                &path,
                Some("management-key"),
                Some("organization-a"),
                repo.clone(),
            )
            .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(body, json!({"detail": case["detail"]}), "{invalid}");
            assert!(repo.calls.lock().unwrap().is_empty());
            let (without_key, without_key_body) =
                request(method, &path, None, None, repo.clone()).await;
            assert_eq!(without_key, StatusCode::UNAUTHORIZED);
            assert_eq!(
                without_key_body["detail"], contract["boundary"]["error_detail"]["missing_api_key"],
                "API-key dependency precedes query validation"
            );
            let (wrong_key, wrong_key_body) =
                request(method, &path, Some("wrong"), None, repo.clone()).await;
            assert_eq!(wrong_key, StatusCode::UNAUTHORIZED);
            assert_eq!(
                wrong_key_body["detail"],
                contract["boundary"]["error_detail"]["invalid_api_key"]
            );
            let (no_tenant, no_tenant_body) =
                request(method, &path, Some("management-key"), None, repo.clone()).await;
            assert_eq!(no_tenant, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(
                no_tenant_body, body,
                "query validation precedes tenant check"
            );
            assert!(repo.calls.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn frozen_retention_unconfigured_api_key_precedes_query_validation() {
    let contract: Value = serde_json::from_str(CONTRACT).unwrap();
    let repo = Arc::new(FakeRetentionRepository::default());
    for route in contract["routes"].as_array().unwrap() {
        let method = route["method"].as_str().unwrap();
        let path = format!(
            "{}?retention_days=not-a-number",
            route["path"]
                .as_str()
                .unwrap()
                .replace("{organization_id}", "organization-a")
        );
        let (status, body) = request_raw_config(
            method,
            &path,
            Some("management-key"),
            Some("organization-a"),
            repo.clone(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["detail"],
            contract["boundary"]["error_detail"]["api_key_not_configured"]
        );
        assert!(repo.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn frozen_retention_duplicate_query_uses_last_value() {
    let repo = Arc::new(FakeRetentionRepository::default());
    for (query, expected_status, expected_days) in [
        (
            "retention_days=abc&retention_days=2",
            StatusCode::OK,
            Some(2),
        ),
        (
            "retention_days=2&retention_days=abc",
            StatusCode::UNPROCESSABLE_ENTITY,
            None,
        ),
    ] {
        let path = format!("/v1/issuance/organizations/organization-a/retention?{query}");
        let (status, body) = request(
            "GET",
            &path,
            Some("management-key"),
            Some("organization-a"),
            repo.clone(),
        )
        .await;
        assert_eq!(status, expected_status);
        if let Some(days) = expected_days {
            assert_eq!(body["retention_days"], days);
        } else {
            assert_eq!(body["detail"][0]["type"], "int_parsing");
            assert_eq!(body["detail"][0]["input"], "abc");
        }
    }
}

#[tokio::test]
async fn frozen_retention_query_preserves_released_integer_size_errors() {
    let contract: Value = serde_json::from_str(CONTRACT).unwrap();
    let limit = contract["retention_days"]["size_boundary"]["maximum_significant_decimal_digits"]
        .as_u64()
        .unwrap() as usize;
    for (value, expected_type) in [
        ("9".repeat(limit), "less_than_equal"),
        ("9".repeat(limit + 1), "int_parsing_size"),
        ("0".repeat(limit + 1), "greater_than_equal"),
        (format!("0{}", "9".repeat(limit + 1)), "int_parsing"),
    ] {
        let path =
            format!("/v1/issuance/organizations/organization-a/retention?retention_days={value}");
        let (status, body) = request(
            "GET",
            &path,
            Some("management-key"),
            Some("organization-a"),
            Arc::new(FakeRetentionRepository::default()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["detail"][0]["type"], expected_type);
        assert_eq!(body["detail"][0]["loc"], json!(["query", "retention_days"]));
        assert_eq!(body["detail"][0]["input"], value);
        if expected_type == "int_parsing_size" {
            let oracle = &contract["retention_days"]["size_boundary"]["direct_decimal_overflow"];
            assert_eq!(body["detail"][0]["msg"], oracle["msg"]);
            assert_eq!(body["detail"][0]["url"], oracle["url"]);
        }
    }
}

#[tokio::test]
async fn frozen_retention_query_preserves_python_integer_coercions() {
    let contract: Value = serde_json::from_str(CONTRACT).unwrap();
    for case in contract["retention_days"]["accepted_string_coercions"]
        .as_array()
        .unwrap()
    {
        let input = case["input"].as_str().unwrap();
        let path =
            format!("/v1/issuance/organizations/organization-a/retention?retention_days={input}");
        let (status, body) = request(
            "GET",
            &path,
            Some("management-key"),
            Some("organization-a"),
            Arc::new(FakeRetentionRepository::default()),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{input}");
        assert_eq!(body["retention_days"], case["value"], "{input}");
    }
}

#[tokio::test]
async fn frozen_retention_summary_and_repeat_purge_preserve_count_shape() {
    let contract: Value = serde_json::from_str(CONTRACT).unwrap();
    let repo = Arc::new(FakeRetentionRepository::default());
    let path = "/v1/issuance/organizations/organization-a/retention";
    let (status, summary) = request(
        "GET",
        path,
        Some("management-key"),
        Some("organization-a"),
        repo.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(summary["organization_id"], "organization-a");
    assert_eq!(summary["retention_days"], 30);
    assert_eq!(summary["cutoff_at"], "2026-01-02T00:00:00+00:00");
    assert_eq!(summary["next_expiry_at"], "2026-02-24T00:00:00+00:00");
    assert_eq!(summary["tracked_scope"], contract["tracked_scope"]);
    assert_eq!(
        summary["eligible_for_purge"],
        json!({
            "issuance_transactions": 1, "applications": 1,
            "authorization_sessions": 1, "issuance_events": 1,
            "issued_credentials": 1, "total": 5
        })
    );
    for days in [1, 3650] {
        let path = format!("{path}?retention_days={days}");
        assert_eq!(
            request(
                "GET",
                &path,
                Some("management-key"),
                Some("organization-a"),
                repo.clone()
            )
            .await
            .1["retention_days"],
            days
        );
    }
    let purge_path = "/v1/issuance/organizations/organization-a/retention/purge";
    let (status, first) = request(
        "POST",
        purge_path,
        Some("management-key"),
        Some("organization-a"),
        repo.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["purged_records"]["total"], 5);
    assert_eq!(first["tracked_scope"], contract["tracked_scope"]);
    let (status, again) = request(
        "POST",
        purge_path,
        Some("management-key"),
        Some("organization-a"),
        repo.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(again["purged_records"]["total"], 0);
    assert!(repo
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|(_, org)| org == "organization-a"));
}
