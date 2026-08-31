//! Canvas REST catalog discovery shared by the management POST and GET routes.

use std::{collections::HashSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::{SecondsFormat, Utc};
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use reqwest::{header, Response, StatusCode};
use serde::Serialize;
use serde_json::{Map, Value};
use thiserror::Error;
use url::Url;

use crate::{
    canvas_management::CanvasScopeDiscoveryRequest,
    canvas_oauth::{CanvasOAuthError, CanvasOAuthService},
    canvas_provider_http::{
        canvas_retry_after_seconds, client_for_canvas_origin, CanvasHttpClientPolicy,
    },
};

#[async_trait]
pub trait CanvasCatalogOAuth: Send + Sync {
    async fn access_token(
        &self,
        platform_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<Option<String>, CanvasOAuthError>;

    async fn mark_rejected_access_token(
        &self,
        platform_id: &str,
        rejected_access_token: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<bool, CanvasOAuthError>;
}

#[async_trait]
impl CanvasCatalogOAuth for CanvasOAuthService {
    async fn access_token(
        &self,
        platform_id: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<Option<String>, CanvasOAuthError> {
        CanvasOAuthService::access_token(self, platform_id, api_key, trusted_organization_id).await
    }

    async fn mark_rejected_access_token(
        &self,
        platform_id: &str,
        rejected_access_token: &str,
        api_key: Option<&str>,
        trusted_organization_id: Option<&str>,
    ) -> Result<bool, CanvasOAuthError> {
        CanvasOAuthService::mark_rejected_access_token(
            self,
            platform_id,
            rejected_access_token,
            api_key,
            trusted_organization_id,
        )
        .await
    }
}

const COLLECTION_PAGE_MAX_BYTES: usize = 8 * 1024 * 1024;
const COLLECTION_MAX_PAGES: usize = 200;
const PYTHON_PATH_SEGMENT_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasScopeItem {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub item_type: String,
    pub url: Option<String>,
    pub published: Option<bool>,
    pub points_possible: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CanvasScopeDiscoveryResponse {
    pub platform_id: String,
    pub organization_id: String,
    pub canvas_base_url: String,
    pub course_id: Option<String>,
    pub courses: Vec<CanvasScopeItem>,
    pub assignments: Vec<CanvasScopeItem>,
    pub quizzes: Vec<CanvasScopeItem>,
    pub modules: Vec<CanvasScopeItem>,
    pub warnings: Vec<String>,
    pub fetched_at: String,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CanvasCatalogProviderError {
    #[error("Canvas OAuth connection requires reauthorization")]
    ReauthorizationRequired,
    #[error("Canvas discovery is temporarily unavailable")]
    TemporarilyUnavailable { retry_after_seconds: Option<u64> },
    #[error("{0}")]
    BadGateway(String),
}

#[async_trait]
pub trait CanvasCatalogProvider: Send + Sync {
    async fn collection(
        &self,
        canvas_base_url: &str,
        access_token: &str,
        path: &str,
        limit: u16,
    ) -> Result<Vec<Map<String, Value>>, CanvasCatalogProviderError>;
}

#[derive(Clone)]
pub struct HttpCanvasCatalogProvider {
    policy: CanvasHttpClientPolicy,
}

impl std::fmt::Debug for HttpCanvasCatalogProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpCanvasCatalogProvider")
            .field("policy", &self.policy)
            .finish()
    }
}

impl HttpCanvasCatalogProvider {
    #[must_use]
    pub fn new(
        timeout: Duration,
        private_origin_allowlist: Vec<String>,
        allow_private_networks: bool,
        allow_http_localhost: bool,
    ) -> Self {
        Self {
            policy: CanvasHttpClientPolicy {
                timeout,
                private_origin_allowlist,
                allow_private_networks,
                allow_http_localhost,
            },
        }
    }
}

#[async_trait]
impl CanvasCatalogProvider for HttpCanvasCatalogProvider {
    async fn collection(
        &self,
        canvas_base_url: &str,
        access_token: &str,
        path: &str,
        limit: u16,
    ) -> Result<Vec<Map<String, Value>>, CanvasCatalogProviderError> {
        let (client, origin) = client_for_canvas_origin(canvas_base_url, &self.policy)
            .await
            .map_err(|()| CanvasCatalogProviderError::TemporarilyUnavailable {
                retry_after_seconds: None,
            })?;
        let expected_origin = origin.origin().ascii_serialization();
        let mut url = origin
            .join(&format!("api/v1/{}", path.trim_start_matches('/')))
            .map_err(|_| {
                CanvasCatalogProviderError::BadGateway(
                    "Canvas admin discovery returned an invalid collection URL".to_owned(),
                )
            })?;
        url.query_pairs_mut()
            .append_pair("per_page", &limit.clamp(1, 100).to_string());
        let mut visited = HashSet::new();
        let mut items = Vec::new();
        for _ in 0..COLLECTION_MAX_PAGES {
            if items.len() >= usize::from(limit) {
                break;
            }
            if !visited.insert(url.as_str().to_owned()) {
                return Err(CanvasCatalogProviderError::TemporarilyUnavailable {
                    retry_after_seconds: None,
                });
            }
            let response = client
                .get(url.clone())
                .bearer_auth(access_token)
                .header(header::ACCEPT, "application/json")
                .send()
                .await
                .map_err(|_| CanvasCatalogProviderError::TemporarilyUnavailable {
                    retry_after_seconds: None,
                })?;
            let status = response.status();
            if status.is_redirection() {
                return Err(CanvasCatalogProviderError::TemporarilyUnavailable {
                    retry_after_seconds: None,
                });
            }
            if status == StatusCode::TOO_MANY_REQUESTS {
                return Err(CanvasCatalogProviderError::TemporarilyUnavailable {
                    retry_after_seconds: canvas_retry_after_seconds(&response),
                });
            }
            if status == StatusCode::UNAUTHORIZED
                && response.headers().contains_key(header::WWW_AUTHENTICATE)
            {
                return Err(CanvasCatalogProviderError::ReauthorizationRequired);
            }
            if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
                return Err(CanvasCatalogProviderError::TemporarilyUnavailable {
                    retry_after_seconds: None,
                });
            }
            if !status.is_success() {
                return Err(CanvasCatalogProviderError::BadGateway(format!(
                    "Canvas admin discovery failed with HTTP {}",
                    status.as_u16()
                )));
            }
            let next = next_link(response.headers());
            let payload = limited_json(response).await?;
            let page = match payload {
                Value::Array(values) => values,
                Value::Object(mut object) => object
                    .remove("items")
                    .and_then(|value| value.as_array().cloned())
                    .ok_or_else(|| {
                        CanvasCatalogProviderError::BadGateway(
                            "Canvas admin discovery returned an unexpected response".to_owned(),
                        )
                    })?,
                _ => {
                    return Err(CanvasCatalogProviderError::BadGateway(
                        "Canvas admin discovery returned an unexpected response".to_owned(),
                    ));
                }
            };
            items.extend(
                page.into_iter()
                    .filter_map(|value| value.as_object().cloned()),
            );
            let Some(next) = next.filter(|_| items.len() < usize::from(limit)) else {
                return Ok(truncate(items, limit));
            };
            url = validate_next_url(&next, &expected_origin)?;
        }
        if items.len() < usize::from(limit) {
            return Err(CanvasCatalogProviderError::TemporarilyUnavailable {
                retry_after_seconds: None,
            });
        }
        Ok(truncate(items, limit))
    }
}

pub async fn discover_canvas_scope(
    provider: Arc<dyn CanvasCatalogProvider>,
    platform_id: String,
    organization_id: String,
    canvas_base_url: String,
    access_token: &str,
    request: CanvasScopeDiscoveryRequest,
) -> Result<CanvasScopeDiscoveryResponse, CanvasCatalogProviderError> {
    let course_id = request
        .course_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let mut warnings = Vec::new();
    let mut courses = Vec::new();
    let mut assignments = Vec::new();
    let mut quizzes = Vec::new();
    let mut modules = Vec::new();

    if request.include_courses {
        courses = scope_items(
            provider
                .collection(&canvas_base_url, access_token, "courses", request.limit)
                .await?,
            "course",
        );
    }
    if let Some(course_id) = course_id.as_deref() {
        let quoted = utf8_percent_encode(course_id, PYTHON_PATH_SEGMENT_SET).to_string();
        if request.include_assignments || request.include_quizzes {
            let raw = provider
                .collection(
                    &canvas_base_url,
                    access_token,
                    &format!("courses/{quoted}/assignments"),
                    request.limit,
                )
                .await?;
            let (quiz_assignments, ordinary_assignments): (Vec<_>, Vec<_>) =
                raw.into_iter().partition(|item| {
                    item.get("is_quiz_assignment") == Some(&Value::Bool(true))
                        || item.get("quiz_id").is_some_and(|value| !value.is_null())
                });
            if request.include_assignments {
                assignments = scope_items(ordinary_assignments, "assignment");
            }
            if request.include_quizzes {
                quizzes = scope_items(quiz_assignments, "quiz");
            }
        }
        if request.include_modules {
            modules = scope_items(
                provider
                    .collection(
                        &canvas_base_url,
                        access_token,
                        &format!("courses/{quoted}/modules"),
                        request.limit,
                    )
                    .await?,
                "module",
            );
        }
    } else if request.include_assignments || request.include_quizzes || request.include_modules {
        warnings.push(
            "Set course_id and run discovery again to import assignments, quizzes, and modules."
                .to_owned(),
        );
    }
    Ok(CanvasScopeDiscoveryResponse {
        platform_id,
        organization_id,
        canvas_base_url,
        course_id,
        courses,
        assignments,
        quizzes,
        modules,
        warnings,
        fetched_at: Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, false),
    })
}

fn scope_items(raw_items: Vec<Map<String, Value>>, item_type: &str) -> Vec<CanvasScopeItem> {
    raw_items
        .into_iter()
        .filter_map(|raw| scope_item(&raw, item_type))
        .collect()
}

fn scope_item(raw: &Map<String, Value>, item_type: &str) -> Option<CanvasScopeItem> {
    let raw_id = ["id", "quiz_id", "module_id"]
        .into_iter()
        .filter_map(|key| raw.get(key))
        .find(|value| truthy(value))?;
    let id = scalar_string(raw_id)?;
    let name = ["name", "title", "course_code", "workflow_state"]
        .into_iter()
        .filter_map(|key| raw.get(key))
        .find(|value| truthy(value))
        .and_then(scalar_string)
        .unwrap_or_else(|| id.clone());
    let points_possible = raw.get("points_possible").and_then(float_value);
    let published = raw.get("published").and_then(Value::as_bool).or_else(|| {
        raw.get("workflow_state")
            .map(|value| value.as_str() == Some("available"))
    });
    let url = ["html_url", "url"]
        .into_iter()
        .filter_map(|key| raw.get(key))
        .find(|value| truthy(value))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some(CanvasScopeItem {
        id,
        name,
        item_type: item_type.to_owned(),
        url,
        published,
        points_possible,
    })
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64() != Some(0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(if *value { "True" } else { "False" }.to_owned()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn float_value(value: &Value) -> Option<f64> {
    match value {
        Value::Number(value) => value.as_f64(),
        Value::String(value) => value.parse().ok(),
        Value::Bool(value) => Some(if *value { 1.0 } else { 0.0 }),
        _ => None,
    }
}

async fn limited_json(mut response: Response) -> Result<Value, CanvasCatalogProviderError> {
    if response
        .content_length()
        .is_some_and(|length| length > COLLECTION_PAGE_MAX_BYTES as u64)
    {
        return Err(CanvasCatalogProviderError::TemporarilyUnavailable {
            retry_after_seconds: None,
        });
    }
    let mut body = Vec::new();
    while let Some(chunk) =
        response
            .chunk()
            .await
            .map_err(|_| CanvasCatalogProviderError::TemporarilyUnavailable {
                retry_after_seconds: None,
            })?
    {
        if body.len().saturating_add(chunk.len()) > COLLECTION_PAGE_MAX_BYTES {
            return Err(CanvasCatalogProviderError::TemporarilyUnavailable {
                retry_after_seconds: None,
            });
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| CanvasCatalogProviderError::TemporarilyUnavailable {
        retry_after_seconds: None,
    })
}

fn next_link(headers: &header::HeaderMap) -> Option<String> {
    headers
        .get_all(header::LINK)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .find_map(|entry| {
            let (target, parameters) = entry.trim().split_once('>')?;
            let target = target.trim().strip_prefix('<')?;
            parameters
                .split(';')
                .map(str::trim)
                .any(|parameter| parameter == "rel=\"next\"" || parameter == "rel=next")
                .then(|| target.to_owned())
        })
}

fn validate_next_url(
    value: &str,
    expected_origin: &str,
) -> Result<Url, CanvasCatalogProviderError> {
    let url = Url::parse(value).map_err(|_| {
        CanvasCatalogProviderError::BadGateway("Canvas LTI service URLs must use HTTPS".to_owned())
    })?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.origin().ascii_serialization() != expected_origin
    {
        return Err(CanvasCatalogProviderError::BadGateway(
            "Canvas LTI service URL changed origin".to_owned(),
        ));
    }
    Ok(url)
}

fn truncate(mut items: Vec<Map<String, Value>>, limit: u16) -> Vec<Map<String, Value>> {
    items.truncate(usize::from(limit));
    items
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use axum::{
        extract::RawQuery,
        http::{HeaderValue, StatusCode},
        response::IntoResponse,
        routing::get,
        Json, Router,
    };
    use serde_json::json;

    use super::*;

    #[derive(Default)]
    struct MemoryProvider {
        calls: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl CanvasCatalogProvider for MemoryProvider {
        async fn collection(
            &self,
            _canvas_base_url: &str,
            _access_token: &str,
            path: &str,
            _limit: u16,
        ) -> Result<Vec<Map<String, Value>>, CanvasCatalogProviderError> {
            self.calls.lock().expect("calls").push(path.to_owned());
            let values = if path == "courses" {
                vec![json!({"id": 7, "course_code": "BIO-7", "workflow_state": "available"})]
            } else if path.ends_with("/assignments") {
                vec![
                    json!({"id": 8, "name": "Essay", "points_possible": "10"}),
                    json!({"id": 9, "name": "Quiz", "quiz_id": 44, "is_quiz_assignment": true}),
                ]
            } else {
                vec![json!({"id": 10, "name": "Module"})]
            };
            Ok(values
                .into_iter()
                .map(|value| value.as_object().cloned().expect("object"))
                .collect())
        }
    }

    #[tokio::test]
    async fn one_discovery_kernel_serves_courses_assignments_quizzes_and_modules() {
        let provider = Arc::new(MemoryProvider::default());
        let response = discover_canvas_scope(
            provider.clone(),
            "platform-1".to_owned(),
            "org-1".to_owned(),
            "https://canvas.example.edu".to_owned(),
            "access-token",
            CanvasScopeDiscoveryRequest {
                course_id: Some(" course/7 ".to_owned()),
                include_courses: true,
                include_assignments: true,
                include_quizzes: true,
                include_modules: true,
                limit: 50,
            },
        )
        .await
        .expect("discovery");
        assert_eq!(response.course_id.as_deref(), Some("course/7"));
        assert_eq!(response.courses[0].published, Some(true));
        assert_eq!(response.assignments[0].points_possible, Some(10.0));
        assert_eq!(response.quizzes[0].id, "9");
        assert_eq!(response.modules[0].item_type, "module");
        assert_eq!(
            provider.calls.lock().expect("calls").as_slice(),
            [
                "courses",
                "courses/course%2F7/assignments",
                "courses/course%2F7/modules",
            ]
        );
    }

    #[tokio::test]
    async fn discovery_without_course_id_preserves_the_legacy_warning() {
        let provider = Arc::new(MemoryProvider::default());
        let response = discover_canvas_scope(
            provider.clone(),
            "platform-1".to_owned(),
            "org-1".to_owned(),
            "https://canvas.example.edu".to_owned(),
            "access-token",
            CanvasScopeDiscoveryRequest {
                course_id: None,
                include_courses: false,
                include_assignments: true,
                include_quizzes: true,
                include_modules: true,
                limit: 50,
            },
        )
        .await
        .expect("discovery");
        assert!(provider.calls.lock().expect("calls").is_empty());
        assert_eq!(response.warnings.len(), 1);
    }

    #[tokio::test]
    async fn http_provider_paginates_without_redirects_and_rejects_origin_drift() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let port = listener.local_addr().expect("local address").port();
        let origin = format!("http://localhost:{port}");
        let next_origin = origin.clone();
        let app = Router::new()
            .route(
                "/api/v1/courses",
                get(move |RawQuery(query): RawQuery| {
                    let next_origin = next_origin.clone();
                    async move {
                        if query
                            .as_deref()
                            .is_some_and(|query| query.contains("page=2"))
                        {
                            return Json(json!([{"id": 2}, {"id": 3}])).into_response();
                        }
                        let mut response = Json(json!([{"id": 1}])).into_response();
                        response.headers_mut().insert(
                            header::LINK,
                            HeaderValue::from_str(&format!(
                                "<{next_origin}/api/v1/courses?page=2>; rel=\"next\""
                            ))
                            .expect("link header"),
                        );
                        response
                    }
                }),
            )
            .route(
                "/api/v1/cross-origin",
                get(|| async {
                    let mut response = Json(json!([{"id": 1}])).into_response();
                    response.headers_mut().insert(
                        header::LINK,
                        HeaderValue::from_static(
                            "<https://attacker.example/api/v1/items>; rel=\"next\"",
                        ),
                    );
                    response
                }),
            )
            .route(
                "/api/v1/rate-limited",
                get(|| async {
                    let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
                    response
                        .headers_mut()
                        .insert(header::RETRY_AFTER, HeaderValue::from_static("31"));
                    response
                }),
            );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });
        let provider =
            HttpCanvasCatalogProvider::new(Duration::from_secs(2), Vec::new(), false, true);

        let items = provider
            .collection(&origin, "secret-token", "courses", 3)
            .await
            .expect("paginated collection");
        assert_eq!(
            items
                .iter()
                .filter_map(|item| item.get("id").and_then(Value::as_i64))
                .collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(
            provider
                .collection(&origin, "secret-token", "cross-origin", 2)
                .await,
            Err(CanvasCatalogProviderError::BadGateway(
                "Canvas LTI service URL changed origin".to_owned()
            ))
        );
        assert_eq!(
            provider
                .collection(&origin, "secret-token", "rate-limited", 2)
                .await,
            Err(CanvasCatalogProviderError::TemporarilyUnavailable {
                retry_after_seconds: Some(31),
            })
        );
        server.abort();
    }
}
