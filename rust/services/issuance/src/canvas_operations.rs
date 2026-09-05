//! Canvas operations candidate. Not registered in the production router yet.
//!
//! Read projections never serialize raw rows. Filtering deliberately follows
//! the published 500-row pre-filter window rather than pushing every filter
//! ahead of LIMIT and silently changing which records callers can observe.

use axum::{
    extract::{Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use mmf_config::numeric_config::PythonConfigInteger;
use serde_json::{json, Map, Value};
use sqlx::PgPool;
use std::collections::BTreeMap;

use crate::{
    canvas_sync_worker::CanvasSyncJobStatus, management_security::ManagementSecurity,
    transaction_reads::TransactionReadError,
};

#[derive(Clone)]
pub struct CanvasOperationsService {
    pool: PgPool,
    security: ManagementSecurity,
}

impl CanvasOperationsService {
    #[must_use]
    pub fn new(pool: PgPool, management_key: Option<&str>) -> Self {
        Self {
            pool,
            security: ManagementSecurity::new(management_key.filter(|key| !key.is_empty())),
        }
    }

    fn authorize(&self, headers: &HeaderMap) -> Result<(), OperationsError> {
        self.security
            .authorize(header(headers, "X-API-Key"))
            .map_err(|error| match error {
                TransactionReadError::ApiKeyNotConfigured => OperationsError::detail(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "ISSUANCE_API_KEY not configured on server",
                ),
                TransactionReadError::ApiKeyMissing => {
                    OperationsError::detail(StatusCode::UNAUTHORIZED, "X-API-Key header is missing")
                }
                _ => OperationsError::detail(StatusCode::UNAUTHORIZED, "Invalid API Key"),
            })
    }

    async fn list(
        &self,
        kind: Collection,
        headers: &HeaderMap,
        query: Option<&str>,
    ) -> Result<Value, OperationsError> {
        self.authorize(headers)?;
        // FastAPI validates typed query parameters before entering the route,
        // while tenant/status validation is performed by the route itself.
        let query = ListQuery::parse(query)?;
        let organization = organization(headers)?;
        if query
            .organization
            .as_deref()
            .is_some_and(|claimed| claimed.trim() != organization)
        {
            return Err(OperationsError::detail(
                StatusCode::NOT_FOUND,
                "Canvas resource not found",
            ));
        }
        let status = kind.status(query.status.as_deref())?;
        let window = match kind {
            Collection::Jobs if nonempty(&query.platform) || nonempty(&query.binding) => 500,
            Collection::Candidates if nonempty(&query.platform) => 500,
            Collection::Reviews if nonempty(&query.binding) => 500,
            _ => query.limit,
        };
        let rows: Vec<Value> = sqlx::query_scalar(kind.list_sql())
            .bind(organization)
            .bind(status)
            .bind(if kind == Collection::Candidates {
                query.binding.as_deref()
            } else {
                None
            })
            .bind(window)
            .fetch_all(&self.pool)
            .await
            .map_err(|_| OperationsError::Internal)?;
        let mut result = Vec::new();
        for row in rows {
            let view = if kind == Collection::Jobs {
                self.job_view(organization, &row).await?
            } else {
                kind.project(&row)?
            };
            if kind != Collection::Reviews
                && nonempty(&query.platform)
                && view["platform_id"].as_str() != query.platform.as_deref()
            {
                continue;
            }
            if kind != Collection::Candidates
                && nonempty(&query.binding)
                && view["binding_id"].as_str() != query.binding.as_deref()
            {
                continue;
            }
            result.push(view);
            if result.len() == query.limit as usize {
                break;
            }
        }
        Ok(Value::Array(result))
    }

    async fn job(&self, headers: &HeaderMap, id: &str) -> Result<Value, OperationsError> {
        self.authorize(headers)?;
        let organization = organization(headers)?;
        let row: Option<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(job) FROM issuance_service.canvas_evidence_sync_jobs job \
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| OperationsError::Internal)?;
        let row = row.ok_or_else(|| {
            OperationsError::detail(
                StatusCode::NOT_FOUND,
                "Canvas synchronization job not found",
            )
        })?;
        self.job_view(organization, &row).await
    }

    async fn job_view(&self, organization: &str, job: &Value) -> Result<Value, OperationsError> {
        let target: Option<Value> = sqlx::query_scalar(
            "SELECT to_jsonb(target) FROM issuance_service.canvas_evidence_sync_targets target \
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization)
        .bind(job["target_id"].as_str().ok_or(OperationsError::Internal)?)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| OperationsError::Internal)?;
        let mut view = project(
            job,
            &[
                "id",
                "organization_id",
                "target_id",
                "status",
                "attempt_count",
                "max_attempts",
                "available_at",
                "started_at",
                "completed_at",
                "last_error_code",
                "created_at",
                "updated_at",
            ],
        )?;
        for field in [
            "platform_id",
            "binding_id",
            "target_type",
            "application_id",
            "candidate_id",
        ] {
            view.insert(
                field.into(),
                target
                    .as_ref()
                    .and_then(|row| row.get(field))
                    .cloned()
                    .unwrap_or(Value::Null),
            );
        }
        view.insert(
            "last_error_summary".into(),
            public_error_summary(job["last_error_summary"].as_str())
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        view.insert("result".into(), public_job_result(&job["result"]));
        Ok(Value::Object(view))
    }
}

/// Deliberately separate from the live issuance/gateway route registration.
pub fn candidate_router(service: CanvasOperationsService) -> Router {
    Router::new()
        .route("/v1/integrations/canvas/canvas-sync-jobs", get(jobs))
        .route("/v1/integrations/canvas/canvas-sync-jobs/{id}", get(job))
        .route(
            "/v1/integrations/canvas/canvas-award-candidates",
            get(candidates),
        )
        .route(
            "/v1/integrations/canvas/evidence-policy-reviews",
            get(reviews),
        )
        .with_state(service)
}

async fn jobs(
    State(service): State<CanvasOperationsService>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Result<Json<Value>, OperationsError> {
    service
        .list(Collection::Jobs, &headers, query.as_deref())
        .await
        .map(Json)
}
async fn candidates(
    State(service): State<CanvasOperationsService>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Result<Json<Value>, OperationsError> {
    service
        .list(Collection::Candidates, &headers, query.as_deref())
        .await
        .map(Json)
}
async fn reviews(
    State(service): State<CanvasOperationsService>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Result<Json<Value>, OperationsError> {
    service
        .list(Collection::Reviews, &headers, query.as_deref())
        .await
        .map(Json)
}
async fn job(
    State(service): State<CanvasOperationsService>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, OperationsError> {
    service.job(&headers, &id).await.map(Json)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Collection {
    Jobs,
    Candidates,
    Reviews,
}

impl Collection {
    fn list_sql(self) -> &'static str {
        match self {
            Self::Jobs => "SELECT to_jsonb(record) FROM issuance_service.canvas_evidence_sync_jobs record
                WHERE organization_id=$1 AND ($2::text IS NULL OR status=$2) AND $3::text IS NULL
                ORDER BY created_at DESC LIMIT $4",
            Self::Candidates => "SELECT to_jsonb(record) FROM issuance_service.canvas_award_candidates record
                WHERE organization_id=$1 AND ($2::text IS NULL OR state=$2) AND ($3::text IS NULL OR binding_id=$3)
                ORDER BY updated_at DESC LIMIT $4",
            Self::Reviews => "SELECT to_jsonb(record) FROM issuance_service.evidence_policy_reviews record
                WHERE organization_id=$1 AND ($2::text IS NULL OR status=$2) AND $3::text IS NULL
                ORDER BY created_at DESC LIMIT $4",
        }
    }
    fn status(self, value: Option<&str>) -> Result<Option<String>, OperationsError> {
        let Some(value) = value.filter(|value| !value.is_empty()) else {
            return Ok(None);
        };
        let normalized = value.trim().to_lowercase();
        let valid = match self {
            Self::Jobs => CanvasSyncJobStatus::from_database(&normalized).is_some(),
            Self::Candidates => matches!(
                normalized.as_str(),
                "observed"
                    | "identity_link_required"
                    | "eligible"
                    | "pending_claim"
                    | "claimed"
                    | "dismissed"
            ),
            Self::Reviews => matches!(
                normalized.as_str(),
                "open" | "dismissed" | "suspended" | "revoked" | "resolved"
            ),
        };
        if valid {
            return Ok(Some(normalized));
        }
        Err(OperationsError::detail(
            StatusCode::UNPROCESSABLE_ENTITY,
            match self {
                Self::Jobs => "Invalid Canvas sync job status",
                Self::Candidates => "Invalid Canvas award candidate status",
                Self::Reviews => "Invalid evidence policy review status",
            },
        ))
    }
    fn project(self, row: &Value) -> Result<Value, OperationsError> {
        let mut result = match self {
            Self::Candidates => project(
                row,
                &[
                    "id",
                    "organization_id",
                    "platform_id",
                    "binding_id",
                    "application_id",
                    "learner_identity_id",
                    "observed_at",
                    "created_at",
                    "updated_at",
                ],
            )?,
            Self::Reviews => project(
                row,
                &[
                    "id",
                    "organization_id",
                    "application_id",
                    "credential_id",
                    "binding_id",
                    "status",
                    "prior_decision",
                    "current_decision",
                    "triggering_fact_id",
                    "resolution_action",
                    "resolution_notes",
                    "resolved_by",
                    "resolved_at",
                    "created_at",
                    "updated_at",
                ],
            )?,
            Self::Jobs => return Err(OperationsError::Internal),
        };
        if self == Self::Candidates {
            result.insert(
                "status".into(),
                row.get("state").cloned().ok_or(OperationsError::Internal)?,
            );
        }
        Ok(Value::Object(result))
    }
}

struct ListQuery {
    organization: Option<String>,
    status: Option<String>,
    platform: Option<String>,
    binding: Option<String>,
    limit: i64,
}

impl ListQuery {
    fn parse(query: Option<&str>) -> Result<Self, OperationsError> {
        let values: BTreeMap<_, _> =
            url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
                .into_owned()
                .collect();
        let limit = if let Some(raw) = values.get("limit") {
            let parse_error = || {
                validation(
                    "int_parsing",
                    "Input should be a valid integer, unable to parse string as an integer",
                    raw,
                    None,
                )
            };
            let trimmed = raw.trim();
            let integer = if let Some((integer, fraction)) = trimmed.split_once('.') {
                if fraction.is_empty() || !fraction.bytes().all(|byte| byte == b'0') {
                    return Err(parse_error());
                }
                integer
            } else {
                trimmed
            };
            // Pydantic's string integer grammar is ASCII, unlike Python int().
            // Reuse the shared lossless integer parser after restricting that
            // grammar; apply the API range before any machine conversion.
            if !integer
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'_'))
            {
                return Err(parse_error());
            }
            let value = integer
                .parse::<PythonConfigInteger>()
                .map_err(|_| parse_error())?;
            if value < 1_u64.into() {
                return Err(validation(
                    "greater_than_equal",
                    "Input should be greater than or equal to 1",
                    raw,
                    Some(json!({"ge": 1})),
                ));
            }
            if value > 500_u64.into() {
                return Err(validation(
                    "less_than_equal",
                    "Input should be less than or equal to 500",
                    raw,
                    Some(json!({"le": 500})),
                ));
            }
            value.to_i64().ok_or(OperationsError::Internal)?
        } else {
            100
        };
        Ok(Self {
            organization: values.get("organization_id").cloned(),
            status: values.get("status").cloned(),
            platform: values.get("platform_id").cloned(),
            binding: values.get("binding_id").cloned(),
            limit,
        })
    }
}

fn validation(kind: &str, message: &str, input: &str, context: Option<Value>) -> OperationsError {
    let mut error = json!({"type": kind, "loc": ["query", "limit"], "msg": message, "input": input, "url": format!("https://errors.pydantic.dev/2.11/v/{kind}")});
    if let Some(context) = context {
        error["ctx"] = context;
    }
    OperationsError::Public(StatusCode::UNPROCESSABLE_ENTITY, json!({"detail": [error]}))
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}
fn organization(headers: &HeaderMap) -> Result<&str, OperationsError> {
    header(headers, "X-Organization-ID")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            OperationsError::detail(
                StatusCode::BAD_REQUEST,
                "X-Organization-ID is required for Canvas management",
            )
        })
}
fn nonempty(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|value| !value.is_empty())
}
fn project(row: &Value, fields: &[&str]) -> Result<Map<String, Value>, OperationsError> {
    fields
        .iter()
        .map(|field| {
            Ok((
                (*field).into(),
                row.get(*field).cloned().ok_or(OperationsError::Internal)?,
            ))
        })
        .collect()
}

fn public_error_summary(value: Option<&str>) -> Option<String> {
    let value = value.filter(|value| !value.is_empty())?;
    let normalized: String = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(500)
        .collect();
    let lowered = normalized.to_lowercase();
    Some(
        if ["bearer ", "access_token", "refresh_token", "secret="]
            .iter()
            .any(|marker| lowered.contains(marker))
        {
            "Canvas synchronization failed; authentication material was redacted".into()
        } else {
            normalized
        },
    )
}

fn public_job_result(value: &Value) -> Value {
    let allowed = [
        "application_id",
        "candidate_id",
        "candidate_state",
        "requirements_checked",
        "sources_checked",
        "facts_observed",
        "facts_changed",
        "facts_created",
        "facts_reused",
        "negative_observations",
        "review_created",
        "candidates_seen",
        "pending_claim",
        "identity_link_required",
        "observations_written",
        "policy_allowed",
        "no_change",
    ];
    Value::Object(
        value
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(key, value)| {
                allowed.contains(&key.as_str())
                    && (value.is_null()
                        || value.is_boolean()
                        || value.is_string()
                        || value.is_i64()
                        || value.is_u64())
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
}

pub enum OperationsError {
    Public(StatusCode, Value),
    Internal,
}
impl OperationsError {
    fn detail(status: StatusCode, detail: &str) -> Self {
        Self::Public(status, json!({"detail": detail}))
    }
}
impl IntoResponse for OperationsError {
    fn into_response(self) -> Response {
        match self {
            Self::Public(status, body) => (status, Json(body)).into_response(),
            Self::Internal => {
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_job_projection_retains_only_legacy_scalar_fields() {
        assert_eq!(
            public_job_result(&json!({
                "facts_observed": 2, "no_change": true, "application_id": null,
                "candidate_id": "candidate", "facts_changed": 1.5,
                "sources_checked": ["private"], "policy_allowed": {"private":true},
                "roster_remaining": 8, "access_token": "synthetic-private",
            })),
            json!({"facts_observed":2,"no_change":true,"application_id":null,"candidate_id":"candidate"})
        );
        assert_eq!(public_job_result(&Value::Null), json!({}));
    }

    #[test]
    fn error_summary_preserves_whitespace_and_character_limits_without_auth_material() {
        assert_eq!(public_error_summary(None), None);
        assert_eq!(public_error_summary(Some("")), None);
        assert_eq!(public_error_summary(Some(" \t ")), Some(String::new()));
        assert_eq!(
            public_error_summary(Some("  rate\nlimited  ")),
            Some("rate limited".into())
        );
        for marker in [
            "BeArEr value",
            "access_token",
            "REFRESH_TOKEN",
            "secret=value",
        ] {
            assert_eq!(
                public_error_summary(Some(marker)).as_deref(),
                Some("Canvas synchronization failed; authentication material was redacted")
            );
        }
        assert_eq!(
            public_error_summary(Some(&"🙂".repeat(501)))
                .unwrap()
                .chars()
                .count(),
            500
        );
    }

    #[tokio::test]
    async fn absent_or_empty_server_key_fails_before_database_access() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .unwrap();
        for key in [None, Some("")] {
            let service = CanvasOperationsService::new(pool.clone(), key);
            let error = service.authorize(&HeaderMap::new()).err().unwrap();
            assert_eq!(
                error.into_response().status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        pool.close().await;
    }
}
