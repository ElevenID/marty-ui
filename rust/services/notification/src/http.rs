use crate::{
    domain::{
        DeliveryResult, NotificationStatus, NotificationTemplate, Subscription, WebhookDelivery,
    },
    repository::NotificationRepository,
    service::{
        webhook_response, CreateSubscriptionRequest, CreateWebhookRequest, EventIngestRequest,
        NotificationResponse, NotificationService, ServiceError, SubscriptionResponse,
        UpdateSubscriptionRequest, UpdateWebhookRequest,
    },
};
use axum::{
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{env, fs, sync::Arc};
use subtle::ConstantTimeEq;
use tower_http::trace::TraceLayer;

const PRODUCER_HEADER: &str = "x-marty-event-producer";
const TOKEN_HEADER: &str = "x-service-token";
const APPLICANT_PRODUCER: &str = "applicant";

#[derive(Clone)]
pub struct HttpState {
    pub service: NotificationService,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    detail: String,
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::Invalid(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(ErrorBody {
                detail: self.to_string(),
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Default, Deserialize)]
struct OrganizationQuery {
    organization_id: String,
}

#[derive(Debug, Default, Deserialize)]
struct ListQuery {
    organization_id: String,
    recipient_id: Option<String>,
    status: Option<String>,
    #[serde(default)]
    unread_only: bool,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

const fn default_limit() -> usize {
    100
}

#[derive(Debug, Default, Deserialize)]
struct RecipientQuery {
    organization_id: String,
    recipient_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeleteResponse {
    success: bool,
}

#[derive(Debug, Serialize)]
struct TemplateResponse {
    id: String,
    name: String,
    notification_type: String,
    subject_template: String,
    active: bool,
}

#[derive(Debug, Serialize)]
struct DeliveryResponse {
    notification_id: String,
    channel: String,
    success: bool,
    attempted_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    delivered_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    should_retry: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after: Option<i64>,
}

impl From<DeliveryResult> for DeliveryResponse {
    fn from(value: DeliveryResult) -> Self {
        Self {
            notification_id: value.notification_id,
            channel: value.channel.as_str().into(),
            success: value.success,
            attempted_at: value.attempted_at.to_rfc3339(),
            delivered_at: value.delivered_at.map(|time| time.to_rfc3339()),
            error_code: value.error_code,
            should_retry: value.should_retry,
            retry_after: value.retry_after,
        }
    }
}

pub fn router(repository: Arc<dyn NotificationRepository>) -> Router {
    router_with_service(NotificationService::new(repository))
}

pub fn router_with_service(service: NotificationService) -> Router {
    let state = HttpState { service };
    Router::new()
        .route("/v1/notifications/send", post(send_notification))
        .route("/v1/notifications", get(list_notifications))
        .route("/v1/notifications/unread/count", get(unread_count))
        .route("/v1/notifications/unread-count", get(unread_count))
        .route("/v1/notifications/read-all", post(mark_all_read))
        .route("/v1/notifications/templates", get(list_templates))
        .route(
            "/v1/notifications/{notification_id}/read",
            patch(mark_read).delete(mark_unread),
        )
        .route(
            "/v1/notifications/{notification_id}/delivery-results",
            get(delivery_results),
        )
        .route(
            "/v1/notifications/{notification_id}",
            get(get_notification).delete(delete_notification),
        )
        .route(
            "/v1/subscriptions",
            post(create_subscription).get(list_subscriptions),
        )
        .route(
            "/v1/subscriptions/{subscription_id}",
            get(get_subscription)
                .put(update_subscription)
                .patch(update_subscription)
                .delete(delete_subscription),
        )
        .route("/v1/webhooks", post(create_webhook).get(list_webhooks))
        .route(
            "/v1/webhooks/{webhook_id}/deliveries",
            get(list_webhook_deliveries),
        )
        .route(
            "/v1/webhooks/{webhook_id}",
            get(get_webhook)
                .put(update_webhook)
                .patch(update_webhook)
                .delete(delete_webhook),
        )
        .route("/internal/events", post(ingest_event))
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn send_notification(
    State(state): State<HttpState>,
    Json(request): Json<crate::service::SendNotificationRequest>,
) -> Result<Json<NotificationResponse>, ServiceError> {
    let notification = state.service.send(request).await?;
    Ok(Json(NotificationResponse::from(&notification)))
}

fn parse_status(value: Option<&str>) -> Result<Option<NotificationStatus>, ServiceError> {
    value
        .map(|value| match value.to_ascii_lowercase().as_str() {
            "pending" => Ok(NotificationStatus::Pending),
            "sent" => Ok(NotificationStatus::Sent),
            "delivered" => Ok(NotificationStatus::Delivered),
            "failed" => Ok(NotificationStatus::Failed),
            _ => Err(ServiceError::Invalid("invalid notification status".into())),
        })
        .transpose()
}

async fn list_notifications(
    State(state): State<HttpState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<NotificationResponse>>, ServiceError> {
    let mut values = state
        .service
        .repository()
        .list_notifications(
            Some(&query.organization_id),
            query.recipient_id.as_deref(),
            parse_status(query.status.as_deref())?,
        )
        .await?;
    if query.unread_only {
        values.retain(|item| !item.is_read());
    }
    Ok(Json(
        values
            .into_iter()
            .skip(query.offset)
            .take(query.limit.min(500))
            .map(|value| NotificationResponse::from(&value))
            .collect(),
    ))
}

fn recipient_from(
    query: &RecipientQuery,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<ErrorBody>)> {
    query
        .recipient_id
        .clone()
        .or_else(|| {
            headers
                .get("x-user-id")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    detail: "recipient_id or X-User-Id is required".into(),
                }),
            )
        })
}

async fn unread_count(
    State(state): State<HttpState>,
    Query(query): Query<RecipientQuery>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ErrorBody>)> {
    let recipient = recipient_from(&query, &headers)?;
    let values = state
        .service
        .repository()
        .list_notifications(Some(&query.organization_id), Some(&recipient), None)
        .await
        .map_err(|error| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorBody {
                    detail: error.to_string(),
                }),
            )
        })?;
    Ok(Json(
        json!({"count": values.iter().filter(|item| !item.is_read()).count()}),
    ))
}

async fn get_notification(
    State(state): State<HttpState>,
    Path(id): Path<String>,
    Query(query): Query<OrganizationQuery>,
) -> Result<Json<NotificationResponse>, ServiceError> {
    let item = state
        .service
        .get_notification(&id, &query.organization_id)
        .await?;
    Ok(Json(NotificationResponse::from(&item)))
}

async fn mark_read(
    State(state): State<HttpState>,
    Path(id): Path<String>,
    Query(query): Query<OrganizationQuery>,
) -> Result<Json<NotificationResponse>, ServiceError> {
    let mut item = state
        .service
        .get_notification(&id, &query.organization_id)
        .await?;
    item.read_at = Some(Utc::now());
    state
        .service
        .repository()
        .save_notification(item.clone())
        .await?;
    Ok(Json(NotificationResponse::from(&item)))
}

async fn mark_unread(
    State(state): State<HttpState>,
    Path(id): Path<String>,
    Query(query): Query<OrganizationQuery>,
) -> Result<Json<NotificationResponse>, ServiceError> {
    let mut item = state
        .service
        .get_notification(&id, &query.organization_id)
        .await?;
    item.read_at = None;
    state
        .service
        .repository()
        .save_notification(item.clone())
        .await?;
    Ok(Json(NotificationResponse::from(&item)))
}

async fn mark_all_read(
    State(state): State<HttpState>,
    Query(query): Query<RecipientQuery>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ErrorBody>)> {
    let recipient = recipient_from(&query, &headers)?;
    let values = state
        .service
        .repository()
        .list_notifications(Some(&query.organization_id), Some(&recipient), None)
        .await
        .map_err(|error| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorBody {
                    detail: error.to_string(),
                }),
            )
        })?;
    let mut count = 0;
    for mut item in values {
        if !item.is_read() {
            item.read_at = Some(Utc::now());
            state
                .service
                .repository()
                .save_notification(item)
                .await
                .map_err(|error| {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(ErrorBody {
                            detail: error.to_string(),
                        }),
                    )
                })?;
            count += 1;
        }
    }
    Ok(Json(json!({"marked_read": count})))
}

async fn delete_notification(
    State(state): State<HttpState>,
    Path(id): Path<String>,
    Query(query): Query<OrganizationQuery>,
) -> Result<Json<DeleteResponse>, ServiceError> {
    state
        .service
        .get_notification(&id, &query.organization_id)
        .await?;
    if !state.service.repository().delete_notification(&id).await? {
        return Err(ServiceError::NotFound("Notification"));
    }
    Ok(Json(DeleteResponse { success: true }))
}

async fn list_templates(
    State(state): State<HttpState>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<TemplateResponse>>, ServiceError> {
    let values = state
        .service
        .repository()
        .list_templates(Some(&query.organization_id))
        .await?;
    Ok(Json(
        values
            .into_iter()
            .skip(query.offset)
            .take(query.limit.min(500))
            .map(template_response)
            .collect(),
    ))
}

fn template_response(item: NotificationTemplate) -> TemplateResponse {
    TemplateResponse {
        id: item.id,
        name: item.name,
        notification_type: format!("{:?}", item.notification_type).to_ascii_lowercase(),
        subject_template: item.subject_template,
        active: item.active,
    }
}

async fn delivery_results(
    State(state): State<HttpState>,
    Path(id): Path<String>,
    Query(query): Query<ListQuery>,
) -> Result<Json<Vec<DeliveryResponse>>, ServiceError> {
    let item = state
        .service
        .get_notification(&id, &query.organization_id)
        .await?;
    Ok(Json(
        item.delivery_results
            .into_iter()
            .skip(query.offset)
            .take(query.limit.min(500))
            .map(Into::into)
            .collect(),
    ))
}

async fn create_webhook(
    State(state): State<HttpState>,
    Json(request): Json<CreateWebhookRequest>,
) -> Result<Json<crate::service::WebhookResponse>, ServiceError> {
    Ok(Json(state.service.create_webhook(request).await?))
}

async fn list_webhooks(
    State(state): State<HttpState>,
    Query(query): Query<OrganizationQuery>,
) -> Result<Json<Vec<crate::service::WebhookResponse>>, ServiceError> {
    Ok(Json(
        state
            .service
            .repository()
            .list_webhooks(Some(&query.organization_id))
            .await?
            .iter()
            .map(|item| webhook_response(item, false))
            .collect(),
    ))
}

async fn get_webhook(
    State(state): State<HttpState>,
    Path(id): Path<String>,
    Query(query): Query<OrganizationQuery>,
) -> Result<Json<crate::service::WebhookResponse>, ServiceError> {
    let item = owned_webhook(&state, &id, &query.organization_id).await?;
    Ok(Json(webhook_response(&item, false)))
}

async fn owned_webhook(
    state: &HttpState,
    id: &str,
    organization_id: &str,
) -> Result<crate::domain::WebhookEndpoint, ServiceError> {
    state
        .service
        .repository()
        .get_webhook(id)
        .await?
        .filter(|item| item.organization_id == organization_id)
        .ok_or(ServiceError::NotFound("Webhook"))
}

async fn update_webhook(
    State(state): State<HttpState>,
    Path(id): Path<String>,
    Query(query): Query<OrganizationQuery>,
    Json(request): Json<UpdateWebhookRequest>,
) -> Result<Json<crate::service::WebhookResponse>, ServiceError> {
    Ok(Json(
        state
            .service
            .update_webhook(&id, &query.organization_id, request)
            .await?,
    ))
}

async fn delete_webhook(
    State(state): State<HttpState>,
    Path(id): Path<String>,
    Query(query): Query<OrganizationQuery>,
) -> Result<Json<DeleteResponse>, ServiceError> {
    owned_webhook(&state, &id, &query.organization_id).await?;
    if !state.service.repository().delete_webhook(&id).await? {
        return Err(ServiceError::NotFound("Webhook"));
    }
    Ok(Json(DeleteResponse { success: true }))
}

async fn list_webhook_deliveries(
    State(state): State<HttpState>,
    Path(id): Path<String>,
    Query(query): Query<OrganizationQuery>,
) -> Result<Json<Vec<WebhookDelivery>>, ServiceError> {
    owned_webhook(&state, &id, &query.organization_id).await?;
    Ok(Json(
        state
            .service
            .repository()
            .list_webhook_deliveries(&id)
            .await?,
    ))
}

async fn create_subscription(
    State(state): State<HttpState>,
    Json(request): Json<CreateSubscriptionRequest>,
) -> Result<Json<SubscriptionResponse>, ServiceError> {
    let item = state.service.create_subscription(request).await?;
    Ok(Json(SubscriptionResponse::from(&item)))
}

async fn list_subscriptions(
    State(state): State<HttpState>,
    Query(query): Query<OrganizationQuery>,
) -> Result<Json<Vec<SubscriptionResponse>>, ServiceError> {
    Ok(Json(
        state
            .service
            .repository()
            .list_subscriptions(Some(&query.organization_id))
            .await?
            .iter()
            .map(SubscriptionResponse::from)
            .collect(),
    ))
}

async fn owned_subscription(
    state: &HttpState,
    id: &str,
    organization_id: &str,
) -> Result<Subscription, ServiceError> {
    state
        .service
        .repository()
        .get_subscription(id)
        .await?
        .filter(|item| item.organization_id == organization_id)
        .ok_or(ServiceError::NotFound("Subscription"))
}

async fn get_subscription(
    State(state): State<HttpState>,
    Path(id): Path<String>,
    Query(query): Query<OrganizationQuery>,
) -> Result<Json<SubscriptionResponse>, ServiceError> {
    let item = owned_subscription(&state, &id, &query.organization_id).await?;
    Ok(Json(SubscriptionResponse::from(&item)))
}

async fn update_subscription(
    State(state): State<HttpState>,
    Path(id): Path<String>,
    Query(query): Query<OrganizationQuery>,
    Json(request): Json<UpdateSubscriptionRequest>,
) -> Result<Json<SubscriptionResponse>, ServiceError> {
    let mut item = owned_subscription(&state, &id, &query.organization_id).await?;
    if let Some(name) = request.name {
        if name.is_empty() {
            return Err(ServiceError::Invalid("name must not be empty".into()));
        }
        item.name = name;
    }
    if let Some(description) = request.description {
        item.description = Some(description);
    }
    if let Some(event_types) = request.event_types {
        if event_types.is_empty() {
            return Err(ServiceError::Invalid(
                "event_types must contain at least one event".into(),
            ));
        }
        item.event_types = event_types;
    }
    if request
        .delivery_channel
        .as_deref()
        .is_some_and(|value| value != "WEBHOOK")
    {
        return Err(ServiceError::Invalid(
            "Only WEBHOOK delivery_channel is currently supported".into(),
        ));
    }
    if let Some(filter) = request.filter_config {
        item.filter_config = filter;
    }
    if let Some(policy) = request.retry_policy {
        policy
            .validate()
            .map_err(|error| ServiceError::Invalid(error.into()))?;
        item.retry_policy = policy;
    }
    if let Some(target) = request.delivery_target_id {
        owned_webhook(&state, &target, &item.organization_id)
            .await
            .map_err(|_| ServiceError::Invalid("Referenced webhook endpoint not found".into()))?;
        item.delivery_target_id = Some(target);
    }
    if let Some(enabled) = request.enabled {
        item.enabled = enabled;
    }
    item.updated_at = Utc::now();
    state
        .service
        .repository()
        .save_subscription(item.clone())
        .await?;
    Ok(Json(SubscriptionResponse::from(&item)))
}

async fn delete_subscription(
    State(state): State<HttpState>,
    Path(id): Path<String>,
    Query(query): Query<OrganizationQuery>,
) -> Result<Json<DeleteResponse>, ServiceError> {
    owned_subscription(&state, &id, &query.organization_id).await?;
    if !state.service.repository().delete_subscription(&id).await? {
        return Err(ServiceError::NotFound("Subscription"));
    }
    Ok(Json(DeleteResponse { success: true }))
}

fn configured_token() -> Result<String, StatusCode> {
    let inline = env::var("NOTIFICATION_APPLICANT_EVENT_TOKEN").unwrap_or_default();
    let file = env::var("NOTIFICATION_APPLICANT_EVENT_TOKEN_FILE").unwrap_or_default();
    if !inline.trim().is_empty() && !file.trim().is_empty() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let token = if file.trim().is_empty() {
        inline.trim().to_owned()
    } else {
        fs::read_to_string(file)
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
            .trim()
            .to_owned()
    };
    let lower = token.to_ascii_lowercase();
    if token.len() < 32
        || [
            "change-me",
            "change_me",
            "changeme",
            "replace-me",
            "replace_me",
        ]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
    {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    } else {
        Ok(token)
    }
}

pub fn validate_internal_auth_config() -> Result<(), String> {
    configured_token()
        .map(|_| ())
        .map_err(|_| "Applicant event-producer authentication is not configured safely".into())
}

async fn ingest_event(State(state): State<HttpState>, headers: HeaderMap, body: Bytes) -> Response {
    if headers
        .get(PRODUCER_HEADER)
        .and_then(|value| value.to_str().ok())
        != Some(APPLICANT_PRODUCER)
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                detail: "Missing or invalid event producer credential".into(),
            }),
        )
            .into_response();
    }
    let expected = match configured_token() {
        Ok(value) => value,
        Err(status) => {
            return (
                status,
                Json(ErrorBody {
                    detail: "Notification event ingestion is unavailable".into(),
                }),
            )
                .into_response()
        }
    };
    let provided = headers
        .get(TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if provided.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() != 1 {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                detail: "Missing or invalid event producer credential".into(),
            }),
        )
            .into_response();
    }
    let request: EventIngestRequest = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorBody {
                    detail: "invalid event payload".into(),
                }),
            )
                .into_response()
        }
    };
    match state.service.ingest_event(request).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn health() -> Json<Value> {
    Json(
        json!({"status":"healthy","service":"notification-service","backend":"rust","version":env!("CARGO_PKG_VERSION")}),
    )
}
async fn metrics() -> impl IntoResponse {
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        format!(
            "# HELP marty_notification_backend_info Native notification backend build information.\n# TYPE marty_notification_backend_info gauge\nmarty_notification_backend_info{{backend=\"rust\",version=\"{}\"}} 1\n",
            env!("CARGO_PKG_VERSION")
        ),
    )
}
async fn ready(State(state): State<HttpState>) -> Response {
    match state.service.repository().list_templates(None).await {
        Ok(_) => Json(json!({"status":"ready","backend":"rust"})).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status":"not_ready","backend":"rust"})),
        )
            .into_response(),
    }
}
