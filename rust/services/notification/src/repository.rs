use crate::{
    domain::{
        default_templates, Notification, NotificationStatus, NotificationTemplate, Subscription,
        WebhookDelivery, WebhookEndpoint,
    },
    outbox::WebhookOutboxEvent,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("notification storage is unavailable: {0}")]
    Unavailable(String),
    #[error("notification storage rejected invalid state: {0}")]
    Invalid(String),
}

#[async_trait]
pub trait NotificationRepository: Send + Sync {
    async fn save_notification(&self, notification: Notification) -> Result<(), RepositoryError>;
    async fn get_notification(&self, id: &str) -> Result<Option<Notification>, RepositoryError>;
    async fn delete_notification(&self, id: &str) -> Result<bool, RepositoryError>;
    async fn list_notifications(
        &self,
        organization_id: Option<&str>,
        recipient_id: Option<&str>,
        status: Option<NotificationStatus>,
    ) -> Result<Vec<Notification>, RepositoryError>;
    async fn save_template(&self, template: NotificationTemplate) -> Result<(), RepositoryError>;
    async fn get_template(&self, id: &str)
        -> Result<Option<NotificationTemplate>, RepositoryError>;
    async fn list_templates(
        &self,
        organization_id: Option<&str>,
    ) -> Result<Vec<NotificationTemplate>, RepositoryError>;
    async fn save_subscription(&self, subscription: Subscription) -> Result<(), RepositoryError>;
    async fn get_subscription(&self, id: &str) -> Result<Option<Subscription>, RepositoryError>;
    async fn list_subscriptions(
        &self,
        organization_id: Option<&str>,
    ) -> Result<Vec<Subscription>, RepositoryError>;
    async fn delete_subscription(&self, id: &str) -> Result<bool, RepositoryError>;
    async fn save_webhook(&self, webhook: WebhookEndpoint) -> Result<(), RepositoryError>;
    /// Record delivery statistics only on an existing, organization-owned endpoint.
    /// Completion of an in-flight request must never restore deleted configuration.
    async fn record_webhook_attempt(
        &self,
        id: &str,
        organization_id: &str,
        success: bool,
        completed: DateTime<Utc>,
        failure_threshold: i32,
    ) -> Result<bool, RepositoryError>;
    async fn get_webhook(&self, id: &str) -> Result<Option<WebhookEndpoint>, RepositoryError>;
    async fn list_webhooks(
        &self,
        organization_id: Option<&str>,
    ) -> Result<Vec<WebhookEndpoint>, RepositoryError>;
    async fn delete_webhook(&self, id: &str) -> Result<bool, RepositoryError>;
    async fn save_webhook_delivery(&self, delivery: WebhookDelivery)
        -> Result<(), RepositoryError>;
    async fn list_webhook_deliveries(
        &self,
        webhook_id: &str,
    ) -> Result<Vec<WebhookDelivery>, RepositoryError>;
    async fn enqueue_webhook_event(
        &self,
        event: WebhookOutboxEvent,
    ) -> Result<bool, RepositoryError>;
    async fn claim_due_webhook_events(
        &self,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<WebhookOutboxEvent>, RepositoryError>;
    async fn mark_webhook_event_delivered(
        &self,
        id: &str,
        lease_token: &str,
        delivered_at: DateTime<Utc>,
        response_status_code: i32,
    ) -> Result<bool, RepositoryError>;
    async fn mark_webhook_event_failed(
        &self,
        id: &str,
        lease_token: &str,
        next_attempt_at: DateTime<Utc>,
        terminal: bool,
        error_code: &str,
        response_status_code: Option<i32>,
    ) -> Result<bool, RepositoryError>;
    async fn get_webhook_outbox_event(
        &self,
        id: &str,
    ) -> Result<Option<WebhookOutboxEvent>, RepositoryError>;
}

#[derive(Debug, Default)]
struct MemoryState {
    notifications: HashMap<String, Notification>,
    templates: HashMap<String, NotificationTemplate>,
    subscriptions: HashMap<String, Subscription>,
    webhooks: HashMap<String, WebhookEndpoint>,
    deliveries: HashMap<String, WebhookDelivery>,
}

#[derive(Debug, Clone)]
pub struct InMemoryNotificationRepository {
    state: Arc<RwLock<MemoryState>>,
    outbox: Arc<Mutex<HashMap<String, WebhookOutboxEvent>>>,
}

impl Default for InMemoryNotificationRepository {
    fn default() -> Self {
        let templates = default_templates(Utc::now())
            .into_iter()
            .map(|template| (template.id.clone(), template))
            .collect();
        Self {
            state: Arc::new(RwLock::new(MemoryState {
                templates,
                ..MemoryState::default()
            })),
            outbox: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl NotificationRepository for InMemoryNotificationRepository {
    async fn save_notification(&self, notification: Notification) -> Result<(), RepositoryError> {
        reject_private_record(&notification)?;
        self.state
            .write()
            .await
            .notifications
            .insert(notification.id.clone(), notification);
        Ok(())
    }

    async fn get_notification(&self, id: &str) -> Result<Option<Notification>, RepositoryError> {
        Ok(self.state.read().await.notifications.get(id).cloned())
    }

    async fn delete_notification(&self, id: &str) -> Result<bool, RepositoryError> {
        Ok(self.state.write().await.notifications.remove(id).is_some())
    }

    async fn list_notifications(
        &self,
        organization_id: Option<&str>,
        recipient_id: Option<&str>,
        status: Option<NotificationStatus>,
    ) -> Result<Vec<Notification>, RepositoryError> {
        let mut values = self
            .state
            .read()
            .await
            .notifications
            .values()
            .filter(|item| {
                organization_id.is_none_or(|id| item.organization_id.as_deref() == Some(id))
                    && recipient_id.is_none_or(|id| item.recipient_id.as_deref() == Some(id))
                    && status.is_none_or(|value| item.status == value)
            })
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by_key(|item| std::cmp::Reverse(item.created_at));
        Ok(values)
    }

    async fn save_template(&self, template: NotificationTemplate) -> Result<(), RepositoryError> {
        self.state
            .write()
            .await
            .templates
            .insert(template.id.clone(), template);
        Ok(())
    }

    async fn get_template(
        &self,
        id: &str,
    ) -> Result<Option<NotificationTemplate>, RepositoryError> {
        Ok(self.state.read().await.templates.get(id).cloned())
    }

    async fn list_templates(
        &self,
        organization_id: Option<&str>,
    ) -> Result<Vec<NotificationTemplate>, RepositoryError> {
        let mut values = self
            .state
            .read()
            .await
            .templates
            .values()
            .filter(|item| {
                organization_id.is_none_or(|id| {
                    item.organization_id.is_none() || item.organization_id.as_deref() == Some(id)
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(values)
    }

    async fn save_subscription(&self, subscription: Subscription) -> Result<(), RepositoryError> {
        reject_private_record(&subscription)?;
        self.state
            .write()
            .await
            .subscriptions
            .insert(subscription.id.clone(), subscription);
        Ok(())
    }

    async fn get_subscription(&self, id: &str) -> Result<Option<Subscription>, RepositoryError> {
        Ok(self.state.read().await.subscriptions.get(id).cloned())
    }

    async fn list_subscriptions(
        &self,
        organization_id: Option<&str>,
    ) -> Result<Vec<Subscription>, RepositoryError> {
        let mut values = self
            .state
            .read()
            .await
            .subscriptions
            .values()
            .filter(|item| organization_id.is_none_or(|id| item.organization_id == id))
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by_key(|item| std::cmp::Reverse(item.created_at));
        Ok(values)
    }

    async fn delete_subscription(&self, id: &str) -> Result<bool, RepositoryError> {
        Ok(self.state.write().await.subscriptions.remove(id).is_some())
    }

    async fn save_webhook(&self, webhook: WebhookEndpoint) -> Result<(), RepositoryError> {
        self.state
            .write()
            .await
            .webhooks
            .insert(webhook.id.clone(), webhook);
        Ok(())
    }

    async fn record_webhook_attempt(
        &self,
        id: &str,
        organization_id: &str,
        success: bool,
        completed: DateTime<Utc>,
        failure_threshold: i32,
    ) -> Result<bool, RepositoryError> {
        let mut state = self.state.write().await;
        let Some(value) = state
            .webhooks
            .get_mut(id)
            .filter(|value| value.organization_id == organization_id)
        else {
            return Ok(false);
        };
        if success {
            value.failure_count = 0;
            value.last_triggered_at = Some(completed);
            value.circuit_breaker_open_until = None;
        } else {
            value.failure_count += 1;
            value.last_failure_at = Some(completed);
            if value.failure_count >= failure_threshold {
                value.circuit_breaker_open_until = Some(completed + chrono::Duration::hours(1));
            }
        }
        value.updated_at = value.updated_at.max(completed);
        Ok(true)
    }

    async fn get_webhook(&self, id: &str) -> Result<Option<WebhookEndpoint>, RepositoryError> {
        Ok(self.state.read().await.webhooks.get(id).cloned())
    }

    async fn list_webhooks(
        &self,
        organization_id: Option<&str>,
    ) -> Result<Vec<WebhookEndpoint>, RepositoryError> {
        let mut values = self
            .state
            .read()
            .await
            .webhooks
            .values()
            .filter(|item| organization_id.is_none_or(|id| item.organization_id == id))
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by_key(|item| std::cmp::Reverse(item.created_at));
        Ok(values)
    }

    async fn delete_webhook(&self, id: &str) -> Result<bool, RepositoryError> {
        Ok(self.state.write().await.webhooks.remove(id).is_some())
    }

    async fn save_webhook_delivery(
        &self,
        delivery: WebhookDelivery,
    ) -> Result<(), RepositoryError> {
        self.state
            .write()
            .await
            .deliveries
            .insert(delivery.id.clone(), delivery);
        Ok(())
    }

    async fn list_webhook_deliveries(
        &self,
        webhook_id: &str,
    ) -> Result<Vec<WebhookDelivery>, RepositoryError> {
        let mut values = self
            .state
            .read()
            .await
            .deliveries
            .values()
            .filter(|item| item.webhook_id == webhook_id)
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by_key(|item| std::cmp::Reverse(item.created_at));
        Ok(values)
    }

    async fn enqueue_webhook_event(
        &self,
        event: WebhookOutboxEvent,
    ) -> Result<bool, RepositoryError> {
        reject_private_record(&event)?;
        let mut outbox = self.outbox.lock().await;
        if outbox.contains_key(&event.id) {
            return Ok(false);
        }
        outbox.insert(event.id.clone(), event);
        Ok(true)
    }

    async fn claim_due_webhook_events(
        &self,
        now: DateTime<Utc>,
        lease_expires_at: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<WebhookOutboxEvent>, RepositoryError> {
        let mut outbox = self.outbox.lock().await;
        for event in outbox.values_mut() {
            if matches!(event.status.as_str(), "pending" | "retry" | "delivering")
                && event.expires_at <= now
            {
                event.status = "expired".into();
                event.payload.clear();
                event.lease_token = None;
                event.lease_expires_at = None;
                event.last_error_code = Some("retention_expired".into());
            }
        }
        let mut due = outbox
            .values_mut()
            .filter(|event| {
                event.expires_at > now
                    && ((matches!(event.status.as_str(), "pending" | "retry")
                        && event.next_attempt_at <= now)
                        || (event.status == "delivering"
                            && event.lease_expires_at.is_some_and(|value| value <= now)))
            })
            .collect::<Vec<_>>();
        due.sort_by_key(|event| event.created_at);
        let mut claimed = Vec::new();
        for event in due.into_iter().take(limit.clamp(1, 100)) {
            event.status = "delivering".into();
            event.attempt_count += 1;
            event.lease_token = Some(Uuid::new_v4().to_string());
            event.lease_expires_at = Some(lease_expires_at);
            claimed.push(event.clone());
        }
        Ok(claimed)
    }

    async fn mark_webhook_event_delivered(
        &self,
        id: &str,
        lease_token: &str,
        delivered_at: DateTime<Utc>,
        response_status_code: i32,
    ) -> Result<bool, RepositoryError> {
        let mut outbox = self.outbox.lock().await;
        let Some(event) = outbox.get_mut(id) else {
            return Ok(false);
        };
        if event.status != "delivering" || event.lease_token.as_deref() != Some(lease_token) {
            return Ok(false);
        }
        event.status = "delivered".into();
        event.payload.clear();
        event.delivered_at = Some(delivered_at);
        event.response_status_code = Some(response_status_code);
        event.lease_token = None;
        event.lease_expires_at = None;
        event.last_error_code = None;
        Ok(true)
    }

    async fn mark_webhook_event_failed(
        &self,
        id: &str,
        lease_token: &str,
        next_attempt_at: DateTime<Utc>,
        terminal: bool,
        error_code: &str,
        response_status_code: Option<i32>,
    ) -> Result<bool, RepositoryError> {
        let mut outbox = self.outbox.lock().await;
        let Some(event) = outbox.get_mut(id) else {
            return Ok(false);
        };
        if event.status != "delivering" || event.lease_token.as_deref() != Some(lease_token) {
            return Ok(false);
        }
        event.status = if terminal { "dead_letter" } else { "retry" }.into();
        event.next_attempt_at = next_attempt_at;
        event.lease_token = None;
        event.lease_expires_at = None;
        event.last_error_code = Some(error_code.chars().take(128).collect());
        event.response_status_code = response_status_code;
        if terminal {
            event.payload.clear();
        }
        Ok(true)
    }

    async fn get_webhook_outbox_event(
        &self,
        id: &str,
    ) -> Result<Option<WebhookOutboxEvent>, RepositoryError> {
        Ok(self.outbox.lock().await.get(id).cloned())
    }
}

pub(crate) fn reject_private_record<T: Serialize>(record: &T) -> Result<(), RepositoryError> {
    let value = serde_json::to_value(record)
        .map_err(|_| RepositoryError::Invalid("record serialization failed".into()))?;
    if marty_key_material_policy::contains_private_key(&value) {
        return Err(RepositoryError::Invalid(
            "private key material is not allowed in notification records".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod delivery_completion_tests {
    use super::*;

    fn endpoint() -> WebhookEndpoint {
        let now = Utc::now();
        WebhookEndpoint {
            id: "endpoint".into(),
            organization_id: "org".into(),
            name: "callback".into(),
            url: "https://example.com/old".into(),
            secret: String::new(),
            secret_envelope: Some("vault:old".into()),
            secret_hint: Some("old1".into()),
            description: None,
            event_types: vec!["application.approved".into()],
            enabled: true,
            failure_count: 0,
            last_failure_at: None,
            last_triggered_at: None,
            circuit_breaker_open_until: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn delivery_completion_cannot_resurrect_deleted_endpoint() {
        let repo = InMemoryNotificationRepository::default();
        let before = endpoint();
        repo.save_webhook(before.clone()).await.unwrap();
        // The worker already holds `before` when public deletion completes.
        assert!(repo.delete_webhook(&before.id).await.unwrap());
        for success in [true, false] {
            assert!(!repo
                .record_webhook_attempt(&before.id, "org", success, Utc::now(), 2)
                .await
                .unwrap());
            assert!(repo.get_webhook(&before.id).await.unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn delivery_completion_preserves_concurrent_disable_and_rotation() {
        let repo = InMemoryNotificationRepository::default();
        let before = endpoint();
        repo.save_webhook(before.clone()).await.unwrap();
        let mut changed = before.clone();
        changed.enabled = false;
        changed.url = "https://example.com/new".into();
        changed.secret_envelope = Some("vault:rotated".into());
        changed.secret_hint = Some("new1".into());
        changed.event_types = vec!["application.rejected".into()];
        changed.updated_at = Utc::now() + chrono::Duration::seconds(1);
        repo.save_webhook(changed.clone()).await.unwrap();
        assert!(repo
            .record_webhook_attempt(&before.id, "org", false, Utc::now(), 2)
            .await
            .unwrap());
        let stored = repo.get_webhook(&before.id).await.unwrap().unwrap();
        assert!(!stored.enabled);
        assert_eq!(stored.url, changed.url);
        assert_eq!(stored.secret_envelope, changed.secret_envelope);
        assert_eq!(stored.secret_hint, changed.secret_hint);
        assert_eq!(stored.event_types, changed.event_types);
        assert_eq!(stored.updated_at, changed.updated_at);
        assert_eq!(stored.failure_count, 1);
    }

    #[tokio::test]
    async fn delivery_completion_keeps_normal_statistics_and_organization_scope() {
        let repo = InMemoryNotificationRepository::default();
        let value = endpoint();
        repo.save_webhook(value.clone()).await.unwrap();
        let now = Utc::now();
        assert!(!repo
            .record_webhook_attempt(&value.id, "foreign", false, now, 2)
            .await
            .unwrap());
        for _ in 0..2 {
            assert!(repo
                .record_webhook_attempt(&value.id, "org", false, now, 2)
                .await
                .unwrap());
        }
        let stored = repo.get_webhook(&value.id).await.unwrap().unwrap();
        assert_eq!(stored.failure_count, 2);
        assert_eq!(stored.last_failure_at, Some(now));
        assert_eq!(
            stored.circuit_breaker_open_until,
            Some(now + chrono::Duration::hours(1))
        );
        assert!(repo
            .record_webhook_attempt(&value.id, "org", true, now, 2)
            .await
            .unwrap());
        let stored = repo.get_webhook(&value.id).await.unwrap().unwrap();
        assert_eq!(stored.failure_count, 0);
        assert_eq!(stored.last_triggered_at, Some(now));
        assert!(stored.circuit_breaker_open_until.is_none());
    }
}
