use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NotificationType {
    #[default]
    Email,
    Push,
    Sms,
    Webhook,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NotificationStatus {
    #[default]
    Pending,
    Sent,
    Delivered,
    Failed,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum NotificationPriority {
    Low,
    #[default]
    Normal,
    High,
    Critical,
}

impl NotificationPriority {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "LOW" => Some(Self::Low),
            "NORMAL" => Some(Self::Normal),
            "HIGH" => Some(Self::High),
            "CRITICAL" | "URGENT" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "UPPERCASE")]
pub enum ChannelType {
    Fcm,
    Sse,
    Webhook,
    Email,
    Sms,
}

impl ChannelType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fcm => "FCM",
            Self::Sse => "SSE",
            Self::Webhook => "WEBHOOK",
            Self::Email => "EMAIL",
            Self::Sms => "SMS",
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct NotificationTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(default)]
    pub device_tokens: Vec<String>,
    #[serde(default)]
    pub webhook_endpoints: Vec<String>,
    #[serde(default)]
    pub email_addresses: Vec<String>,
    #[serde(default)]
    pub channels: Vec<ChannelType>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeliveryResult {
    pub notification_id: String,
    pub channel: ChannelType,
    pub success: bool,
    pub attempted_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub should_retry: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Notification {
    pub id: String,
    pub organization_id: Option<String>,
    pub recipient_id: Option<String>,
    pub recipient_email: Option<String>,
    pub recipient_phone: Option<String>,
    pub notification_type: NotificationType,
    pub template_id: Option<String>,
    pub subject: String,
    pub body: String,
    pub severity: String,
    pub link: Option<String>,
    pub data: Map<String, Value>,
    pub status: NotificationStatus,
    pub priority: NotificationPriority,
    pub event_type: String,
    pub ttl_seconds: i64,
    pub collapse_key: Option<String>,
    pub correlation_id: Option<String>,
    pub target: Option<NotificationTarget>,
    pub delivery_results: Vec<DeliveryResult>,
    pub attempts: i32,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub scheduled_at: Option<DateTime<Utc>>,
    pub read_at: Option<DateTime<Utc>>,
}

impl Default for Notification {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            organization_id: None,
            recipient_id: None,
            recipient_email: None,
            recipient_phone: None,
            notification_type: NotificationType::default(),
            template_id: None,
            subject: String::new(),
            body: String::new(),
            severity: "info".into(),
            link: None,
            data: Map::new(),
            status: NotificationStatus::default(),
            priority: NotificationPriority::default(),
            event_type: "custom".into(),
            ttl_seconds: 86_400,
            collapse_key: None,
            correlation_id: None,
            target: None,
            delivery_results: Vec::new(),
            attempts: 0,
            last_attempt_at: None,
            delivered_at: None,
            error_message: None,
            created_at: Utc::now(),
            scheduled_at: None,
            read_at: None,
        }
    }
}

impl Notification {
    pub fn mark_sent(&mut self, now: DateTime<Utc>) {
        self.status = NotificationStatus::Sent;
        self.attempts += 1;
        self.last_attempt_at = Some(now);
    }

    pub fn mark_delivered(&mut self, now: DateTime<Utc>) {
        self.status = NotificationStatus::Delivered;
        self.delivered_at = Some(now);
    }

    pub fn is_read(&self) -> bool {
        self.read_at.is_some()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct NotificationTemplate {
    pub id: String,
    pub organization_id: Option<String>,
    pub name: String,
    pub notification_type: NotificationType,
    pub subject_template: String,
    pub body_template: String,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RetryPolicy {
    #[serde(default = "default_max_attempts")]
    pub max_attempts: i32,
    #[serde(default = "default_initial_backoff")]
    pub initial_backoff_seconds: i32,
    #[serde(default = "default_max_backoff")]
    pub max_backoff_seconds: i32,
}

const fn default_max_attempts() -> i32 {
    3
}
const fn default_initial_backoff() -> i32 {
    1
}
const fn default_max_backoff() -> i32 {
    30
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            initial_backoff_seconds: default_initial_backoff(),
            max_backoff_seconds: default_max_backoff(),
        }
    }
}

impl RetryPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(1..=10).contains(&self.max_attempts) {
            return Err("max_attempts must be between 1 and 10");
        }
        if !(0..=60).contains(&self.initial_backoff_seconds) {
            return Err("initial_backoff_seconds must be between 0 and 60");
        }
        if !(1..=300).contains(&self.max_backoff_seconds) {
            return Err("max_backoff_seconds must be between 1 and 300");
        }
        if self.initial_backoff_seconds > self.max_backoff_seconds {
            return Err("initial_backoff_seconds must not exceed max_backoff_seconds");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct Subscription {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    pub event_types: Vec<String>,
    pub filter_config: Map<String, Value>,
    pub retry_policy: RetryPolicy,
    pub delivery_target_id: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WebhookEndpoint {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub url: String,
    #[serde(skip)]
    pub secret: String,
    pub secret_envelope: Option<String>,
    pub secret_hint: Option<String>,
    pub description: Option<String>,
    pub event_types: Vec<String>,
    pub enabled: bool,
    pub failure_count: i32,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub last_triggered_at: Option<DateTime<Utc>>,
    pub circuit_breaker_open_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct WebhookDelivery {
    pub id: String,
    pub organization_id: String,
    pub webhook_id: String,
    pub subscription_id: Option<String>,
    pub event_id: String,
    pub event_type: String,
    pub correlation_id: Option<String>,
    pub success: bool,
    pub response_status_code: Option<i32>,
    pub error_message: Option<String>,
    pub retry_count: i32,
    pub response_time_ms: Option<i32>,
    pub created_at: DateTime<Utc>,
}

pub fn default_templates(now: DateTime<Utc>) -> Vec<NotificationTemplate> {
    vec![
        NotificationTemplate {
            id: "invitation".into(),
            organization_id: None,
            name: "Member Invitation".into(),
            notification_type: NotificationType::Email,
            subject_template: "You've been invited to join {{organization_name}}".into(),
            body_template: "Hello,\n\nYou've been invited to join {{organization_name}} on Marty.\n\nClick here to accept: {{invitation_link}}".into(),
            active: true,
            created_at: now,
            updated_at: now,
        },
        NotificationTemplate {
            id: "approval".into(),
            organization_id: None,
            name: "Application Approved".into(),
            notification_type: NotificationType::Email,
            subject_template: "Your application has been approved".into(),
            body_template: "Hello {{given_name}},\n\nYour application for {{credential_type}} has been approved.".into(),
            active: true,
            created_at: now,
            updated_at: now,
        },
        NotificationTemplate {
            id: "credential-ready".into(),
            organization_id: None,
            name: "Credential Ready".into(),
            notification_type: NotificationType::Email,
            subject_template: "Your credential is ready to claim".into(),
            body_template: "Hello {{given_name}},\n\nYour {{credential_type}} credential is ready.\n\nClaim it here: {{claim_link}}".into(),
            active: true,
            created_at: now,
            updated_at: now,
        },
    ]
}
