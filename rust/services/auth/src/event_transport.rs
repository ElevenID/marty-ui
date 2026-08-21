use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;
use chrono::{SecondsFormat, TimeZone as _, Utc};
use mmf_messaging::{
    DeliveryGuarantee, Message, MessageTransport, MessagingError, MessagingHealth,
    MessagingPattern, PostgresOutboxStore, Subscription, TransportCapabilities, TransportFeature,
};
use tokio::sync::RwLock;
use tonic::{transport::Channel, Request};

use crate::{
    auth_event_message,
    event_stream_proto::{
        event_stream_service_client::EventStreamServiceClient, DomainEvent, HealthCheckRequest,
        PublishEventRequest,
    },
    AuthEvent, AuthEventPublisher, PortError,
};

const MAXIMUM_EVENT_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct MmfAuthOutboxPublisher {
    outbox: Arc<PostgresOutboxStore>,
}

impl MmfAuthOutboxPublisher {
    #[must_use]
    pub fn new(outbox: Arc<PostgresOutboxStore>) -> Self {
        Self { outbox }
    }
}

#[async_trait]
impl AuthEventPublisher for MmfAuthOutboxPublisher {
    async fn publish(&self, event: &AuthEvent) -> Result<(), PortError> {
        self.outbox
            .enqueue(auth_event_message(event)?)
            .await
            .map(|_| ())
            .map_err(|error| PortError::new("auth_event_outbox_failed", error.to_string()))
    }
}

#[derive(Clone)]
pub struct GrpcEventStreamTransport {
    client: EventStreamServiceClient<Channel>,
    connected: Arc<RwLock<bool>>,
}

impl GrpcEventStreamTransport {
    #[must_use]
    pub fn new(client: EventStreamServiceClient<Channel>) -> Self {
        Self {
            client,
            connected: Arc::new(RwLock::new(false)),
        }
    }
}

#[async_trait]
impl MessageTransport for GrpcEventStreamTransport {
    async fn connect(&self) -> Result<(), MessagingError> {
        let mut client = self.client.clone();
        let response = client
            .health_check(Request::new(HealthCheckRequest {}))
            .await
            .map_err(unavailable)?
            .into_inner();
        if response.status != "healthy" && response.status != "serving" {
            return Err(MessagingError::BackendUnavailable(
                "event-stream health response is not ready".into(),
            ));
        }
        *self.connected.write().await = true;
        Ok(())
    }

    async fn disconnect(&self) -> Result<(), MessagingError> {
        *self.connected.write().await = false;
        Ok(())
    }

    async fn publish(&self, message: Message) -> Result<(), MessagingError> {
        if !*self.connected.read().await {
            return Err(MessagingError::BackendUnavailable(
                "event-stream transport is disconnected".into(),
            ));
        }
        let event = domain_event(message)?;
        let mut client = self.client.clone();
        let response = client
            .publish(Request::new(PublishEventRequest { event: Some(event) }))
            .await
            .map_err(unavailable)?
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

    async fn subscribe(&self, _: Subscription) -> Result<(), MessagingError> {
        Err(unsupported("subscriptions"))
    }

    async fn unsubscribe(&self, _: &str) -> Result<bool, MessagingError> {
        Err(unsupported("subscriptions"))
    }

    async fn poll(&self, _: &str, _: usize, _: u64) -> Result<Vec<Message>, MessagingError> {
        Err(unsupported("polling"))
    }

    async fn acknowledge(&self, _: &str, _: &str) -> Result<(), MessagingError> {
        Err(unsupported("acknowledgements"))
    }

    async fn reject(
        &self,
        _: &str,
        _: Message,
        _: bool,
        _: &str,
        _: u64,
    ) -> Result<(), MessagingError> {
        Err(unsupported("rejections"))
    }

    fn capabilities(&self) -> TransportCapabilities {
        TransportCapabilities {
            patterns: vec![MessagingPattern::PublishSubscribe],
            delivery_guarantees: vec![DeliveryGuarantee::AtLeastOnce],
            features: BTreeSet::from([TransportFeature::BatchPublish]),
            maximum_message_bytes: MAXIMUM_EVENT_BYTES,
        }
    }

    async fn health(&self) -> Result<MessagingHealth, MessagingError> {
        Ok(MessagingHealth {
            connected: *self.connected.read().await,
            backend: "marty-event-stream-grpc".into(),
            subscriptions: 0,
            pending_messages: 0,
            pending_outbox: 0,
            dead_letters: 0,
            details: Vec::new(),
        })
    }
}

pub fn domain_event(message: Message) -> Result<DomainEvent, MessagingError> {
    let organization_id = message
        .metadata
        .tenant_id
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            MessagingError::InvalidConfiguration(
                "event-stream messages require an organization scope".into(),
            )
        })?;
    let aggregate_id = message
        .metadata
        .partition_key
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            MessagingError::InvalidConfiguration(
                "event-stream messages require an aggregate partition key".into(),
            )
        })?;
    let payload = message.payload.as_object().ok_or_else(|| {
        MessagingError::Serialization("event-stream payload must be a JSON object".into())
    })?;
    let data = payload
        .iter()
        .map(|(key, value)| {
            let value = value
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| canonical_json(value));
            (key.clone(), value)
        })
        .collect();
    let timestamp = i64::try_from(message.metadata.created_at_ms)
        .ok()
        .and_then(|milliseconds| Utc.timestamp_millis_opt(milliseconds).single())
        .ok_or_else(|| MessagingError::Serialization("event timestamp is invalid".into()))?
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    Ok(DomainEvent {
        event_id: message.metadata.message_id,
        event_type: message.message_type,
        aggregate_id,
        aggregate_type: "auth".into(),
        organization_id,
        data,
        timestamp,
        correlation_id: message.metadata.correlation_id.unwrap_or_default(),
    })
}

fn canonical_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".into())
}

fn unavailable(status: tonic::Status) -> MessagingError {
    MessagingError::BackendUnavailable(format!("event-stream gRPC returned {}", status.code()))
}

fn unsupported(operation: &str) -> MessagingError {
    MessagingError::Unsupported(format!(
        "event-stream publisher does not support {operation}"
    ))
}
