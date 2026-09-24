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
    let clock = Arc::new(FixedClock(
        Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap(),
    ));
    let service = RetentionService::new(repo, Some("management-key")).with_clock(clock);
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
        for (key, organization, status) in [
            (None, None, StatusCode::UNAUTHORIZED),
            (Some("wrong"), None, StatusCode::UNAUTHORIZED),
            (Some("management-key"), None, StatusCode::FORBIDDEN),
            (
                Some("management-key"),
                Some("organization-b"),
                StatusCode::FORBIDDEN,
            ),
        ] {
            assert_eq!(
                request(method, &path, key, organization, repo.clone())
                    .await
                    .0,
                status
            );
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
            assert_eq!(without_key, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(
                without_key_body, body,
                "validation precedes route authorization"
            );
            assert!(repo.calls.lock().unwrap().is_empty());
        }
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
