use crate::{
    delivery::deliver_notification,
    domain::{
        ChannelType, Notification, NotificationPriority, NotificationStatus, NotificationTarget,
        NotificationType, RetryPolicy, Subscription, WebhookEndpoint,
    },
    outbox::{
        new_webhook_outbox_event, WEBHOOK_TEST_EVENT_ID_PREFIX, WEBHOOK_TEST_EVENT_TYPE,
        WEBHOOK_TEST_SUBSCRIPTION_ID,
    },
    payload_security::{
        validate_internal_event_data, validate_notification_data, validate_notification_text,
    },
    repository::{NotificationRepository, RepositoryError},
    webhook::{generate_webhook_secret, resolve_webhook_destination, WebhookSecretEnvelope},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::HashSet, sync::Arc};
use thiserror::Error;
use uuid::Uuid;

pub const STANDARD_EVENT_TYPES: [&str; 12] = [
    "credential.offered",
    "credential.issued",
    "credential.revoked",
    "verification.requested",
    "application.received",
    "application.approved",
    "application.rejected",
    "applicant.submitted",
    "applicant.approved",
    "applicant.rejected",
    "applicant.status_changed",
    "device.key_expiring",
];

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0} not found")]
    NotFound(&'static str),
    #[error("{0}")]
    Unavailable(String),
}

impl From<RepositoryError> for ServiceError {
    fn from(error: RepositoryError) -> Self {
        Self::Unavailable(error.to_string())
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SendNotificationRequest {
    pub organization_id: String,
    pub recipient_id: Option<String>,
    pub recipient_email: Option<String>,
    #[serde(default = "default_notification_type")]
    pub notification_type: String,
    pub template_id: Option<String>,
    pub subject: Option<String>,
    pub body: Option<String>,
    pub title: Option<String>,
    pub message: Option<String>,
    #[serde(default = "default_severity")]
    pub severity: String,
    pub link: Option<String>,
    #[serde(default)]
    pub data: Map<String, Value>,
    #[serde(default = "default_priority")]
    pub priority: String,
    #[serde(default = "default_event_type")]
    pub event_type: String,
    #[serde(default = "default_ttl")]
    pub ttl_seconds: i64,
    pub collapse_key: Option<String>,
    pub correlation_id: Option<String>,
    pub target: Option<NotificationTargetRequest>,
}

fn default_notification_type() -> String {
    "email".into()
}
fn default_severity() -> String {
    "info".into()
}
fn default_priority() -> String {
    "normal".into()
}
fn default_event_type() -> String {
    "custom".into()
}
const fn default_ttl() -> i64 {
    86_400
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct NotificationTargetRequest {
    pub organization_id: Option<String>,
    pub user_id: Option<String>,
    #[serde(default)]
    pub device_tokens: Vec<String>,
    #[serde(default)]
    pub webhook_endpoints: Vec<String>,
    #[serde(default)]
    pub email_addresses: Vec<String>,
    #[serde(default)]
    pub channels: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NotificationResponse {
    pub id: String,
    pub title: String,
    pub body: String,
    pub data: Map<String, Value>,
    pub event_type: String,
    pub priority: String,
    pub target: NotificationTarget,
    pub ttl_seconds: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collapse_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub created_at: String,
}

impl From<&Notification> for NotificationResponse {
    fn from(value: &Notification) -> Self {
        Self {
            id: value.id.clone(),
            title: value.subject.clone(),
            body: value.body.clone(),
            data: value.data.clone(),
            event_type: value.event_type.clone(),
            priority: format!("{:?}", value.priority).to_ascii_uppercase(),
            target: value.target.clone().unwrap_or_default(),
            ttl_seconds: value.ttl_seconds,
            collapse_key: value.collapse_key.clone(),
            correlation_id: value.correlation_id.clone(),
            created_at: value.created_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateSubscriptionRequest {
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub event_types: Vec<String>,
    #[serde(default = "default_webhook_channel")]
    pub delivery_channel: String,
    #[serde(default, rename = "filter")]
    pub filter_config: Map<String, Value>,
    #[serde(default)]
    pub retry_policy: RetryPolicy,
    pub delivery_target_id: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_webhook_channel() -> String {
    "WEBHOOK".into()
}
const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateSubscriptionRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub event_types: Option<Vec<String>>,
    pub delivery_channel: Option<String>,
    #[serde(rename = "filter")]
    pub filter_config: Option<Map<String, Value>>,
    pub retry_policy: Option<RetryPolicy>,
    pub delivery_target_id: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SubscriptionResponse {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub event_types: Vec<String>,
    pub delivery: Value,
    #[serde(skip_serializing_if = "Option::is_none", rename = "filter")]
    pub filter_config: Option<Map<String, Value>>,
    pub enabled: bool,
    pub retry_policy: RetryPolicy,
    pub created_at: String,
    pub updated_at: String,
}

impl From<&Subscription> for SubscriptionResponse {
    fn from(value: &Subscription) -> Self {
        Self {
            id: value.id.clone(),
            organization_id: value.organization_id.clone(),
            name: value.name.clone(),
            description: value.description.clone(),
            event_types: value.event_types.clone(),
            delivery: serde_json::json!({"channel": "WEBHOOK"}),
            filter_config: (!value.filter_config.is_empty()).then(|| value.filter_config.clone()),
            enabled: value.enabled,
            retry_policy: value.retry_policy.clone(),
            created_at: value.created_at.to_rfc3339(),
            updated_at: value.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateWebhookRequest {
    pub organization_id: String,
    pub name: String,
    pub url: String,
    pub description: Option<String>,
    #[serde(default)]
    pub event_types: Vec<String>,
    pub secret: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateWebhookRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    pub description: Option<String>,
    pub event_types: Option<Vec<String>>,
    #[serde(skip_deserializing)]
    pub secret: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookResponse {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub endpoint_url: String,
    pub events: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_secret_masked: Option<String>,
    pub enabled: bool,
    pub status: String,
    pub failure_count: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_triggered_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TestWebhookResponse {
    pub delivery_id: String,
    pub event_id: String,
    pub status: String,
}

pub fn webhook_response(value: &WebhookEndpoint, include_secret: bool) -> WebhookResponse {
    WebhookResponse {
        id: value.id.clone(),
        organization_id: value.organization_id.clone(),
        name: value.name.clone(),
        description: value.description.clone(),
        endpoint_url: value.url.clone(),
        events: value.event_types.clone(),
        signing_secret: include_secret.then(|| value.secret.clone()),
        signing_secret_masked: value.secret_hint.as_ref().map(|hint| format!("{hint}...")),
        enabled: value.enabled,
        status: if value.enabled { "ACTIVE" } else { "DISABLED" }.into(),
        failure_count: value.failure_count,
        last_triggered_at: value.last_triggered_at.map(|time| time.to_rfc3339()),
        created_at: value.created_at.to_rfc3339(),
        updated_at: value.updated_at.to_rfc3339(),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct EventIngestRequest {
    pub event_id: String,
    pub event_type: String,
    pub aggregate_id: String,
    pub aggregate_type: String,
    pub organization_id: String,
    pub correlation_id: String,
    #[serde(default)]
    pub data: Map<String, Value>,
    pub timestamp: Option<String>,
}

#[derive(Clone)]
pub struct NotificationService {
    repository: Arc<dyn NotificationRepository>,
    envelope: Option<Arc<WebhookSecretEnvelope>>,
}

impl NotificationService {
    pub fn new(repository: Arc<dyn NotificationRepository>) -> Self {
        Self {
            repository,
            envelope: None,
        }
    }

    pub fn with_envelope(
        repository: Arc<dyn NotificationRepository>,
        envelope: Arc<WebhookSecretEnvelope>,
    ) -> Self {
        Self {
            repository,
            envelope: Some(envelope),
        }
    }
    pub fn repository(&self) -> &Arc<dyn NotificationRepository> {
        &self.repository
    }

    pub async fn send(
        &self,
        request: SendNotificationRequest,
    ) -> Result<Notification, ServiceError> {
        require_text(&request.organization_id, "organization_id", 255)?;
        validate_notification_data(&request.data)
            .map_err(|error| ServiceError::Invalid(error.to_string()))?;
        if request
            .target
            .as_ref()
            .and_then(|target| target.organization_id.as_ref())
            .is_some_and(|id| id != &request.organization_id)
        {
            return Err(ServiceError::Invalid(
                "target.organization_id must match organization_id".into(),
            ));
        }
        let mut subject = request
            .title
            .clone()
            .or(request.subject.clone())
            .unwrap_or_default();
        let mut body = request
            .message
            .clone()
            .or(request.body.clone())
            .unwrap_or_default();
        if let Some(template_id) = &request.template_id {
            if let Some(template) = self.repository.get_template(template_id).await? {
                subject = render_template(&template.subject_template, &request.data);
                body = render_template(&template.body_template, &request.data);
            }
        }
        validate_notification_text(&subject, &body)
            .map_err(|error| ServiceError::Invalid(error.to_string()))?;
        let target = build_target(&request)?;
        validate_target(&target, request.ttl_seconds).await?;
        let now = Utc::now();
        let mut notification = Notification {
            organization_id: Some(request.organization_id),
            recipient_id: request.recipient_id,
            recipient_email: request.recipient_email,
            notification_type: notification_type(&target.channels),
            template_id: request.template_id,
            subject,
            body,
            severity: request.severity,
            link: request.link,
            data: request.data,
            priority: NotificationPriority::parse(&request.priority)
                .ok_or_else(|| ServiceError::Invalid("invalid priority".into()))?,
            event_type: request.event_type,
            ttl_seconds: request.ttl_seconds,
            collapse_key: request.collapse_key,
            correlation_id: request.correlation_id,
            target: Some(target),
            created_at: now,
            ..Notification::default()
        };
        notification.delivery_results = deliver_notification(&notification, now).await;
        notification.mark_sent(now);
        if notification
            .delivery_results
            .iter()
            .any(|result| result.success)
        {
            notification.mark_delivered(now);
        } else if let Some(error) = notification
            .delivery_results
            .iter()
            .find_map(|result| result.error_code.clone())
        {
            notification.status = NotificationStatus::Failed;
            notification.error_message = Some(error);
        }
        self.repository
            .save_notification(notification.clone())
            .await?;
        Ok(notification)
    }

    pub async fn get_notification(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Notification, ServiceError> {
        let value = self
            .repository
            .get_notification(id)
            .await?
            .filter(|item| item.organization_id.as_deref() == Some(organization_id));
        value.ok_or(ServiceError::NotFound("Notification"))
    }

    pub async fn create_webhook(
        &self,
        request: CreateWebhookRequest,
    ) -> Result<WebhookResponse, ServiceError> {
        require_text(&request.organization_id, "organization_id", 255)?;
        require_text(&request.name, "name", 255)?;
        resolve_webhook_destination(&request.url)
            .await
            .map_err(|error| ServiceError::Invalid(error.to_string()))?;
        let secret = request.secret.unwrap_or_else(generate_webhook_secret);
        if !(32..=128).contains(&secret.len()) {
            return Err(ServiceError::Invalid(
                "secret must be between 32 and 128 characters".into(),
            ));
        }
        let now = Utc::now();
        let mut webhook = WebhookEndpoint {
            id: Uuid::new_v4().to_string(),
            organization_id: request.organization_id,
            name: request.name,
            url: request.url,
            secret_hint: Some(secret.chars().take(4).collect()),
            secret: secret.clone(),
            secret_envelope: None,
            description: request.description,
            event_types: request.event_types,
            enabled: request.enabled,
            failure_count: 0,
            last_failure_at: None,
            last_triggered_at: None,
            circuit_breaker_open_until: None,
            created_at: now,
            updated_at: now,
        };
        if let Some(envelope) = &self.envelope {
            webhook.secret_envelope = Some(
                envelope
                    .wrap(&webhook.organization_id, &webhook.id, &secret)
                    .await
                    .map_err(|_| {
                        ServiceError::Unavailable(
                            "Webhook signing secret protection is unavailable".into(),
                        )
                    })?,
            );
            webhook.secret.clear();
        }
        self.repository.save_webhook(webhook.clone()).await?;
        let mut response = webhook_response(&webhook, false);
        response.signing_secret = Some(secret);
        Ok(response)
    }

    pub async fn update_webhook(
        &self,
        id: &str,
        organization_id: &str,
        request: UpdateWebhookRequest,
    ) -> Result<WebhookResponse, ServiceError> {
        let mut webhook = self
            .repository
            .get_webhook(id)
            .await?
            .filter(|item| item.organization_id == organization_id)
            .ok_or(ServiceError::NotFound("Webhook"))?;
        if let Some(name) = request.name {
            require_text(&name, "name", 255)?;
            webhook.name = name;
        }
        if let Some(url) = request.url {
            resolve_webhook_destination(&url)
                .await
                .map_err(|error| ServiceError::Invalid(error.to_string()))?;
            webhook.url = url;
        }
        if let Some(description) = request.description {
            webhook.description = Some(description);
        }
        if let Some(event_types) = request.event_types {
            webhook.event_types = event_types;
        }
        let mut rotated_secret = None;
        if let Some(secret) = request.secret {
            if !(32..=128).contains(&secret.len()) {
                return Err(ServiceError::Invalid(
                    "secret must be between 32 and 128 characters".into(),
                ));
            }
            webhook.secret_hint = Some(secret.chars().take(4).collect());
            if let Some(envelope) = &self.envelope {
                webhook.secret_envelope = Some(
                    envelope
                        .wrap(&webhook.organization_id, &webhook.id, &secret)
                        .await
                        .map_err(|_| {
                            ServiceError::Unavailable(
                                "Webhook signing secret protection is unavailable".into(),
                            )
                        })?,
                );
                webhook.secret.clear();
            } else {
                webhook.secret = secret.clone();
            }
            rotated_secret = Some(secret);
        }
        if let Some(enabled) = request.enabled {
            webhook.enabled = enabled;
        }
        webhook.updated_at = Utc::now();
        self.repository.save_webhook(webhook.clone()).await?;
        let mut response = webhook_response(&webhook, false);
        response.signing_secret = rotated_secret;
        Ok(response)
    }

    pub async fn rotate_webhook_secret(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<WebhookResponse, ServiceError> {
        self.update_webhook(
            id,
            organization_id,
            UpdateWebhookRequest {
                secret: Some(generate_webhook_secret()),
                ..UpdateWebhookRequest::default()
            },
        )
        .await
    }

    pub async fn test_webhook(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<TestWebhookResponse, ServiceError> {
        let webhook = self
            .repository
            .get_webhook(id)
            .await?
            .filter(|item| item.organization_id == organization_id)
            .ok_or(ServiceError::NotFound("Webhook"))?;
        if !webhook.enabled {
            return Err(ServiceError::Invalid("Webhook is disabled".into()));
        }
        let now = Utc::now();
        let event_id = format!("{WEBHOOK_TEST_EVENT_ID_PREFIX}{}", Uuid::new_v4());
        let payload = Map::from_iter([
            ("id".into(), Value::String(event_id.clone())),
            ("type".into(), Value::String(WEBHOOK_TEST_EVENT_TYPE.into())),
            ("timestamp".into(), Value::String(now.to_rfc3339())),
            ("aggregate_id".into(), Value::String(webhook.id.clone())),
            ("aggregate_type".into(), Value::String("webhook".into())),
            (
                "organization_id".into(),
                Value::String(webhook.organization_id.clone()),
            ),
            (
                "data".into(),
                Value::Object(Map::from_iter([("test".into(), Value::Bool(true))])),
            ),
        ]);
        let event = new_webhook_outbox_event(
            webhook.organization_id,
            webhook.id,
            WEBHOOK_TEST_SUBSCRIPTION_ID.into(),
            event_id.clone(),
            WEBHOOK_TEST_EVENT_TYPE.into(),
            payload,
            3,
            1,
            30,
            now,
            86_400,
        );
        let delivery_id = event.id.clone();
        if !self.repository.enqueue_webhook_event(event).await? {
            return Err(ServiceError::Unavailable(
                "Webhook test delivery could not be queued".into(),
            ));
        }
        Ok(TestWebhookResponse {
            delivery_id,
            event_id,
            status: "QUEUED".into(),
        })
    }

    pub async fn create_subscription(
        &self,
        request: CreateSubscriptionRequest,
    ) -> Result<Subscription, ServiceError> {
        if request.delivery_channel != "WEBHOOK" {
            return Err(ServiceError::Invalid(
                "Only WEBHOOK delivery_channel is currently supported".into(),
            ));
        }
        validate_event_types(&request.event_types)?;
        request
            .retry_policy
            .validate()
            .map_err(|error| ServiceError::Invalid(error.into()))?;
        let target_id = request.delivery_target_id.ok_or_else(|| {
            ServiceError::Invalid("delivery_target_id is required for WEBHOOK subscriptions".into())
        })?;
        let webhook = self.repository.get_webhook(&target_id).await?;
        if webhook.is_none_or(|value| value.organization_id != request.organization_id) {
            return Err(ServiceError::Invalid(
                "Referenced webhook endpoint not found".into(),
            ));
        }
        let now = Utc::now();
        let subscription = Subscription {
            id: Uuid::new_v4().to_string(),
            organization_id: request.organization_id,
            name: request.name,
            description: request.description,
            event_types: request.event_types,
            filter_config: request.filter_config,
            retry_policy: request.retry_policy,
            delivery_target_id: Some(target_id),
            enabled: request.enabled,
            created_at: now,
            updated_at: now,
        };
        self.repository
            .save_subscription(subscription.clone())
            .await?;
        Ok(subscription)
    }

    pub async fn ingest_event(
        &self,
        event: EventIngestRequest,
    ) -> Result<Map<String, Value>, ServiceError> {
        validate_event(&event)?;
        let subscriptions = self
            .repository
            .list_subscriptions(Some(&event.organization_id))
            .await?;
        let matching = subscriptions
            .into_iter()
            .filter(|subscription| {
                subscription.enabled
                    && match_event_patterns(&subscription.event_types, &event.event_type)
                    && filter_matches(&subscription.filter_config, &event)
            })
            .collect::<Vec<_>>();
        let created_at = event
            .timestamp
            .as_deref()
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map_or_else(Utc::now, |value| value.with_timezone(&Utc));
        let payload = Map::from_iter([
            ("id".into(), Value::String(event.event_id.clone())),
            ("type".into(), Value::String(event.event_type.clone())),
            ("timestamp".into(), Value::String(created_at.to_rfc3339())),
            (
                "aggregate_id".into(),
                Value::String(event.aggregate_id.clone()),
            ),
            (
                "aggregate_type".into(),
                Value::String(event.aggregate_type.clone()),
            ),
            (
                "organization_id".into(),
                Value::String(event.organization_id.clone()),
            ),
            (
                "correlation_id".into(),
                Value::String(event.correlation_id.clone()),
            ),
            ("data".into(), Value::Object(event.data.clone())),
        ]);
        let mut deliveries = 0_i64;
        let mut failures = 0_i64;
        for subscription in &matching {
            let Some(target_id) = &subscription.delivery_target_id else {
                continue;
            };
            let Some(webhook) = self.repository.get_webhook(target_id).await? else {
                continue;
            };
            if !webhook.enabled {
                continue;
            }
            if webhook.organization_id != subscription.organization_id {
                failures += 1;
                continue;
            }
            if !webhook.event_types.is_empty()
                && !match_event_patterns(&webhook.event_types, &event.event_type)
            {
                continue;
            }
            let item = new_webhook_outbox_event(
                event.organization_id.clone(),
                webhook.id,
                subscription.id.clone(),
                event.event_id.clone(),
                event.event_type.clone(),
                payload.clone(),
                subscription.retry_policy.max_attempts,
                subscription.retry_policy.initial_backoff_seconds,
                subscription.retry_policy.max_backoff_seconds,
                created_at,
                86_400,
            );
            deliveries += i64::from(self.repository.enqueue_webhook_event(item).await?);
        }
        Ok(Map::from_iter([
            ("status".into(), Value::String("accepted".into())),
            ("matched_subscriptions".into(), Value::from(matching.len())),
            ("deliveries".into(), Value::from(deliveries)),
            ("failures".into(), Value::from(failures)),
        ]))
    }
}

fn require_text(value: &str, field: &str, max: usize) -> Result<(), ServiceError> {
    if value.is_empty() || value.chars().count() > max {
        Err(ServiceError::Invalid(format!(
            "{field} must be between 1 and {max} characters"
        )))
    } else {
        Ok(())
    }
}

fn render_template(template: &str, data: &Map<String, Value>) -> String {
    data.iter()
        .fold(template.to_owned(), |value, (key, replacement)| {
            value.replace(
                &format!("{{{{{key}}}}}"),
                replacement
                    .as_str()
                    .map_or_else(|| replacement.to_string(), str::to_owned)
                    .as_str(),
            )
        })
}

fn default_channels(event_type: &str) -> Vec<ChannelType> {
    match event_type {
        "credential.offered"
        | "credential.issued"
        | "verification.requested"
        | "applicant.status_changed"
        | "device.key_expiring" => vec![ChannelType::Fcm, ChannelType::Sse],
        "credential.revoked"
        | "application.approved"
        | "application.rejected"
        | "applicant.approved"
        | "applicant.rejected" => vec![ChannelType::Fcm, ChannelType::Sse, ChannelType::Email],
        _ => vec![ChannelType::Email],
    }
}

fn parse_channels(values: &[String]) -> Result<Vec<ChannelType>, ServiceError> {
    values
        .iter()
        .map(|value| match value.trim().to_ascii_uppercase().as_str() {
            "FCM" => Ok(ChannelType::Fcm),
            "SSE" => Ok(ChannelType::Sse),
            "WEBHOOK" => Ok(ChannelType::Webhook),
            "EMAIL" => Ok(ChannelType::Email),
            "SMS" => Ok(ChannelType::Sms),
            _ => Err(ServiceError::Invalid(format!("invalid channel: {value}"))),
        })
        .collect()
}

fn build_target(request: &SendNotificationRequest) -> Result<NotificationTarget, ServiceError> {
    if let Some(target) = &request.target {
        let channels = if target.channels.is_empty() {
            default_channels(&request.event_type)
        } else {
            parse_channels(&target.channels)?
        };
        return Ok(NotificationTarget {
            organization_id: target
                .organization_id
                .clone()
                .or_else(|| Some(request.organization_id.clone())),
            user_id: target
                .user_id
                .clone()
                .or_else(|| request.recipient_id.clone()),
            device_tokens: target.device_tokens.clone(),
            webhook_endpoints: target.webhook_endpoints.clone(),
            email_addresses: target.email_addresses.clone(),
            channels,
        });
    }
    let mut channels = default_channels(&request.event_type);
    match request
        .notification_type
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "webhook" => channels = vec![ChannelType::Webhook],
        "sms" => channels = vec![ChannelType::Sms],
        "push" => channels = vec![ChannelType::Fcm],
        _ if request.recipient_email.is_some() => channels = vec![ChannelType::Email],
        _ => {}
    }
    Ok(NotificationTarget {
        organization_id: Some(request.organization_id.clone()),
        user_id: request.recipient_id.clone(),
        email_addresses: request.recipient_email.iter().cloned().collect(),
        channels,
        ..NotificationTarget::default()
    })
}

async fn validate_target(
    target: &NotificationTarget,
    ttl_seconds: i64,
) -> Result<(), ServiceError> {
    if ttl_seconds <= 0 {
        return Err(ServiceError::Invalid(
            "ttl_seconds must be greater than 0".into(),
        ));
    }
    if target.channels.is_empty() {
        return Err(ServiceError::Invalid(
            "target.channels must contain at least one channel".into(),
        ));
    }
    if target.organization_id.is_none()
        && target.user_id.is_none()
        && target.device_tokens.is_empty()
        && target.webhook_endpoints.is_empty()
        && target.email_addresses.is_empty()
    {
        return Err(ServiceError::Invalid(
            "At least one notification target must be provided".into(),
        ));
    }
    for endpoint in &target.webhook_endpoints {
        resolve_webhook_destination(endpoint)
            .await
            .map_err(|error| ServiceError::Invalid(error.to_string()))?;
    }
    Ok(())
}

fn notification_type(channels: &[ChannelType]) -> NotificationType {
    if channels.contains(&ChannelType::Webhook) {
        NotificationType::Webhook
    } else if channels.contains(&ChannelType::Email) {
        NotificationType::Email
    } else if channels.contains(&ChannelType::Sms) {
        NotificationType::Sms
    } else {
        NotificationType::Push
    }
}

fn validate_event_types(event_types: &[String]) -> Result<(), ServiceError> {
    if event_types.is_empty() {
        return Err(ServiceError::Invalid(
            "event_types must contain at least one event".into(),
        ));
    }
    let allowed = STANDARD_EVENT_TYPES.into_iter().collect::<HashSet<_>>();
    let unknown = event_types
        .iter()
        .filter(|value| !allowed.contains(value.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(ServiceError::Invalid(format!(
            "Unknown event_types: {}",
            unknown.join(", ")
        )))
    }
}

pub fn match_event_patterns(patterns: &[String], event_type: &str) -> bool {
    let category = event_type
        .split_once('.')
        .map_or(event_type, |(value, _)| value);
    patterns.iter().any(|pattern| {
        pattern == "*" || pattern == event_type || pattern.strip_suffix(".*") == Some(category)
    })
}

fn filter_matches(filter: &Map<String, Value>, event: &EventIngestRequest) -> bool {
    let aggregate_matches = filter
        .get("aggregate_types")
        .and_then(Value::as_array)
        .is_none_or(|values| {
            values.is_empty()
                || values
                    .iter()
                    .any(|value| value.as_str() == Some(&event.aggregate_type))
        });
    let keys_match = filter
        .get("required_data_keys")
        .and_then(Value::as_array)
        .is_none_or(|values| {
            values.iter().all(|value| {
                value
                    .as_str()
                    .is_some_and(|key| event.data.contains_key(key))
            })
        });
    aggregate_matches && keys_match
}

fn validate_event(event: &EventIngestRequest) -> Result<(), ServiceError> {
    require_text(&event.event_id, "event_id", 64)?;
    if !event.event_id.chars().enumerate().all(|(index, value)| {
        value.is_ascii_alphanumeric() || (index > 0 && "._:/-".contains(value))
    }) {
        return Err(ServiceError::Invalid(
            "event_id contains unsafe characters".into(),
        ));
    }
    Uuid::parse_str(&event.correlation_id).map_err(|_| {
        ServiceError::Invalid("correlation_id must be a gateway request UUID".into())
    })?;
    validate_internal_event_data(&event.event_type, &event.data)
        .map_err(|error| ServiceError::Invalid(error.to_string()))?;
    if let Some(timestamp) = &event.timestamp {
        DateTime::parse_from_rfc3339(timestamp).map_err(|_| {
            ServiceError::Invalid("timestamp must be an ISO 8601 datetime with a timezone".into())
        })?;
    }
    let expected = match event.event_type.as_str() {
        "application.approved" => Some("APPROVED"),
        "application.rejected" => Some("REJECTED"),
        _ => None,
    };
    if let Some(status) = expected {
        let required = [
            "applicant_id",
            "application_id",
            "credential_template_id",
            "status",
        ];
        let bound = event.aggregate_type == "application"
            && event.data.len() == required.len()
            && required.iter().all(|field| {
                event
                    .data
                    .get(*field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.trim().is_empty())
            })
            && event.data.get("application_id").and_then(Value::as_str)
                == Some(&event.aggregate_id)
            && event.data.get("status").and_then(Value::as_str) == Some(status);
        if !bound {
            return Err(ServiceError::Invalid(
                "Applicant producer is not authorized for this event projection".into(),
            ));
        }
    } else {
        return Err(ServiceError::Invalid(
            "Applicant producer is not authorized for this event type".into(),
        ));
    }
    Ok(())
}
