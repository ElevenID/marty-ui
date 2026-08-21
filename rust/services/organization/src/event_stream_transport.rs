use std::{collections::BTreeSet, time::Duration};

use async_trait::async_trait;
use mmf_messaging::{
    DeliveryGuarantee, Message, MessageTransport, MessagingError, MessagingHealth,
    MessagingPattern, Subscription, TransportCapabilities,
};
use serde_json::Value;
use tokio::sync::Mutex;
use tonic::transport::Channel;

use crate::event_stream_proto::{
    event_stream_service_client::EventStreamServiceClient, DomainEvent, HealthCheckRequest,
    PublishEventRequest,
};

pub struct EventStreamTransport {
    endpoint: String,
    timeout: Duration,
    client: Mutex<Option<EventStreamServiceClient<Channel>>>,
}

impl EventStreamTransport {
    #[must_use]
    pub fn new(target: impl Into<String>, timeout: Duration) -> Self {
        let target = target.into();
        let endpoint = if target.starts_with("http://") || target.starts_with("https://") {
            target
        } else {
            format!("http://{target}")
        };
        Self {
            endpoint,
            timeout,
            client: Mutex::new(None),
        }
    }

    async fn connected_client(&self) -> Result<EventStreamServiceClient<Channel>, MessagingError> {
        self.client.lock().await.clone().ok_or_else(|| {
            MessagingError::BackendUnavailable("event stream is disconnected".into())
        })
    }

    async fn probe(
        &self,
        mut client: EventStreamServiceClient<Channel>,
    ) -> Result<(), MessagingError> {
        let response =
            tokio::time::timeout(self.timeout, client.health_check(HealthCheckRequest {}))
                .await
                .map_err(|_| {
                    MessagingError::BackendUnavailable("event-stream health timed out".into())
                })?
                .map_err(|error| MessagingError::BackendUnavailable(error.to_string()))?
                .into_inner();
        if response.status.eq_ignore_ascii_case("serving") {
            Ok(())
        } else {
            Err(MessagingError::BackendUnavailable(format!(
                "event-stream reported {}",
                response.status
            )))
        }
    }
}

#[async_trait]
impl MessageTransport for EventStreamTransport {
    async fn connect(&self) -> Result<(), MessagingError> {
        if let Ok(client) = self.connected_client().await {
            if self.probe(client).await.is_ok() {
                return Ok(());
            }
        }
        let client = EventStreamServiceClient::connect(self.endpoint.clone())
            .await
            .map_err(|error| MessagingError::BackendUnavailable(error.to_string()))?;
        self.probe(client.clone()).await?;
        *self.client.lock().await = Some(client);
        Ok(())
    }

    async fn disconnect(&self) -> Result<(), MessagingError> {
        *self.client.lock().await = None;
        Ok(())
    }

    async fn publish(&self, message: Message) -> Result<(), MessagingError> {
        let event = domain_event(&message)?;
        let mut client = self.connected_client().await?;
        let response = tokio::time::timeout(
            self.timeout,
            client.publish(PublishEventRequest { event: Some(event) }),
        )
        .await
        .map_err(|_| MessagingError::BackendUnavailable("event-stream publish timed out".into()))?
        .map_err(|error| MessagingError::BackendUnavailable(error.to_string()))?
        .into_inner();
        if response.success {
            Ok(())
        } else {
            Err(MessagingError::BackendUnavailable(
                "event-stream rejected the event".into(),
            ))
        }
    }

    async fn publish_batch(&self, messages: Vec<Message>) -> Vec<Result<(), MessagingError>> {
        let mut results = Vec::with_capacity(messages.len());
        for message in messages {
            results.push(self.publish(message).await);
        }
        results
    }

    async fn subscribe(&self, _subscription: Subscription) -> Result<(), MessagingError> {
        Err(MessagingError::Unsupported(
            "event-stream publisher does not subscribe".into(),
        ))
    }

    async fn unsubscribe(&self, _subscription_id: &str) -> Result<bool, MessagingError> {
        Err(MessagingError::Unsupported(
            "event-stream publisher does not subscribe".into(),
        ))
    }

    async fn poll(
        &self,
        _subscription_id: &str,
        _limit: usize,
        _now_ms: u64,
    ) -> Result<Vec<Message>, MessagingError> {
        Err(MessagingError::Unsupported(
            "event-stream publisher does not poll".into(),
        ))
    }

    async fn acknowledge(
        &self,
        _subscription_id: &str,
        _message_id: &str,
    ) -> Result<(), MessagingError> {
        Err(MessagingError::Unsupported(
            "event-stream publisher does not acknowledge".into(),
        ))
    }

    async fn reject(
        &self,
        _subscription_id: &str,
        _message: Message,
        _requeue: bool,
        _reason: &str,
        _now_ms: u64,
    ) -> Result<(), MessagingError> {
        Err(MessagingError::Unsupported(
            "event-stream publisher does not reject".into(),
        ))
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            patterns: vec![MessagingPattern::PublishSubscribe],
            delivery_guarantees: vec![DeliveryGuarantee::AtLeastOnce],
            features: BTreeSet::new(),
            maximum_message_bytes: 4 * 1024 * 1024,
        }
    }

    async fn health(&self) -> Result<MessagingHealth, MessagingError> {
        let client = self.connected_client().await?;
        self.probe(client).await?;
        Ok(MessagingHealth {
            connected: true,
            backend: "event-stream-grpc".into(),
            subscriptions: 0,
            pending_messages: 0,
            pending_outbox: 0,
            dead_letters: 0,
            details: vec![self.endpoint.clone()],
        })
    }
}

fn domain_event(message: &Message) -> Result<DomainEvent, MessagingError> {
    let payload = message.payload.as_object().ok_or_else(|| {
        MessagingError::Serialization("event-stream payload must be an object".into())
    })?;
    let organization_id = payload
        .get("organization_id")
        .and_then(Value::as_str)
        .or(message.metadata.tenant_id.as_deref())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| MessagingError::Unroutable(message.metadata.message_id.clone()))?;
    let data = payload
        .get("data")
        .and_then(Value::as_object)
        .map(|data| {
            data.iter()
                .map(|(key, value)| (key.clone(), stringify(value)))
                .collect()
        })
        .unwrap_or_default();
    Ok(DomainEvent {
        event_id: payload
            .get("event_id")
            .and_then(Value::as_str)
            .unwrap_or(&message.metadata.message_id)
            .to_owned(),
        event_type: payload
            .get("event_type")
            .and_then(Value::as_str)
            .unwrap_or(&message.message_type)
            .to_owned(),
        aggregate_id: payload
            .get("aggregate_id")
            .and_then(Value::as_str)
            .unwrap_or(organization_id)
            .to_owned(),
        aggregate_type: payload
            .get("aggregate_type")
            .and_then(Value::as_str)
            .unwrap_or("organization")
            .to_owned(),
        organization_id: organization_id.to_owned(),
        data,
        timestamp: payload
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        correlation_id: payload
            .get("correlation_id")
            .and_then(Value::as_str)
            .or(message.metadata.correlation_id.as_deref())
            .unwrap_or_default()
            .to_owned(),
    })
}

fn stringify(value: &Value) -> String {
    value.as_str().map_or_else(
        || serde_json::to_string(value).unwrap_or_else(|_| "null".into()),
        str::to_owned,
    )
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use serde_json::{json, Map};
    use uuid::Uuid;

    use super::*;
    use crate::{OrganizationEvent, OrganizationEventKind};

    #[test]
    fn organization_message_projects_to_language_neutral_event_stream_contract() {
        let organization_id = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        let event = OrganizationEvent::new(
            OrganizationEventKind::OrganizationCreated,
            organization_id,
            Map::from_iter([
                ("name".into(), json!("Example")),
                ("owner_user_id".into(), json!("user-1")),
                ("enabled".into(), json!(true)),
            ]),
            Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        )
        .unwrap();
        let message = event.to_message().unwrap();
        let projected = domain_event(&message).unwrap();
        assert_eq!(projected.organization_id, organization_id.to_string());
        assert_eq!(projected.event_type, "organization.created.event");
        assert_eq!(projected.aggregate_type, "organization");
        assert_eq!(projected.data["name"], "Example");
        assert_eq!(projected.data["enabled"], "true");
    }

    #[test]
    fn unscoped_or_malformed_messages_fail_closed() {
        let event = OrganizationEvent::new(
            OrganizationEventKind::OrganizationCreated,
            Uuid::new_v4(),
            Map::from_iter([
                ("name".into(), json!("Example")),
                ("owner_user_id".into(), json!("user-1")),
            ]),
            Utc::now(),
        )
        .unwrap();
        let mut message = event.to_message().unwrap();
        message.payload = json!({});
        message.metadata.tenant_id = None;
        assert!(matches!(
            domain_event(&message),
            Err(MessagingError::Unroutable(_))
        ));
    }
}
