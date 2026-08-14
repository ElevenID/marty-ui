use crate::{
    domain::{
        default_templates, Notification, NotificationStatus, NotificationTemplate, Subscription,
        WebhookDelivery, WebhookEndpoint,
    },
    outbox::WebhookOutboxEvent,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
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
