use std::collections::BTreeMap;

use mmf_messaging::{
    DeliveryGuarantee, EventKind, Message, MessageMetadata, MessagePriority, MessageStatus,
    MessagingPattern,
};
use mmf_push::{sign_event, PushError, WebhookDestinationRegistry};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{CALLBACK_EVENT_TYPE, CALLBACK_MAX_ATTEMPTS, CALLBACK_RETENTION_SECONDS};

pub const CALLBACK_AUDIENCE: &str = "marty-auth-service";

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CallbackEvent {
    pub event_id: String,
    pub flow_instance_id: String,
    pub organization_id: String,
    pub destination_url: String,
    pub audience: String,
    pub event_type: String,
    pub payload: Value,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

impl CallbackEvent {
    pub fn new(
        flow_instance_id: impl Into<String>,
        organization_id: impl Into<String>,
        destination_url: impl Into<String>,
        payload: Value,
        created_at_ms: u64,
        destinations: &WebhookDestinationRegistry,
    ) -> Result<Self, PushError> {
        Self::new_with_retention(
            flow_instance_id,
            organization_id,
            destination_url,
            payload,
            created_at_ms,
            destinations,
            CALLBACK_RETENTION_SECONDS,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_retention(
        flow_instance_id: impl Into<String>,
        organization_id: impl Into<String>,
        destination_url: impl Into<String>,
        payload: Value,
        created_at_ms: u64,
        destinations: &WebhookDestinationRegistry,
        retention_seconds: u64,
    ) -> Result<Self, PushError> {
        let flow_instance_id = flow_instance_id.into();
        let organization_id = organization_id.into();
        let destination_url = destination_url.into();
        if flow_instance_id.trim().is_empty()
            || organization_id.trim().is_empty()
            || !payload.is_object()
        {
            return Err(PushError::InvalidConfiguration(
                "callback requires flow, organization, and object payload".into(),
            ));
        }
        destinations.require(&organization_id, &destination_url)?;
        Ok(Self {
            event_id: flow_instance_id.clone(),
            flow_instance_id,
            organization_id,
            destination_url,
            audience: CALLBACK_AUDIENCE.into(),
            event_type: CALLBACK_EVENT_TYPE.into(),
            payload,
            created_at_ms,
            expires_at_ms: created_at_ms.saturating_add(retention_seconds.saturating_mul(1_000)),
        })
    }

    #[must_use]
    pub fn into_outbox_message(self) -> Message {
        self.into_outbox_message_with_max_attempts(CALLBACK_MAX_ATTEMPTS)
    }

    #[must_use]
    pub fn into_outbox_message_with_max_attempts(self, max_attempts: u32) -> Message {
        Message {
            metadata: MessageMetadata {
                message_id: self.event_id.clone(),
                correlation_id: Some(self.flow_instance_id.clone()),
                causation_id: None,
                tenant_id: Some(self.organization_id),
                source_service: Some("flow".into()),
                target_service: Some(self.audience.clone()),
                trace_parent: None,
                created_at_ms: self.created_at_ms,
                scheduled_at_ms: Some(self.created_at_ms),
                expires_at_ms: Some(self.expires_at_ms),
                schema_version: 1,
                content_type: "application/json".into(),
                content_encoding: "utf-8".into(),
                partition_key: Some(self.flow_instance_id),
                ordering_key: None,
                deduplication_key: Some(self.event_id),
                headers: BTreeMap::from([
                    ("X-MIP-Audience".into(), self.audience),
                    ("X-MIP-Event".into(), self.event_type.clone()),
                ]),
            },
            kind: EventKind::Workflow,
            message_type: self.event_type.clone(),
            pattern: MessagingPattern::PointToPoint,
            delivery_guarantee: DeliveryGuarantee::AtLeastOnce,
            priority: MessagePriority::High,
            status: MessageStatus::Pending,
            topic: "marty.flow.callbacks".into(),
            routing_key: self.event_type,
            reply_to: Some(self.destination_url),
            payload: self.payload,
            retry_count: 0,
            max_retries: max_attempts.saturating_sub(1),
        }
    }

    pub fn delivery_headers(
        &self,
        secret: &str,
        timestamp: &str,
        attempt_count: u32,
    ) -> Result<BTreeMap<String, String>, PushError> {
        let signature = sign_event(
            secret,
            &self.audience,
            &self.event_type,
            &self.event_id,
            timestamp,
            &self.payload,
        )?;
        Ok(BTreeMap::from([
            ("Content-Type".into(), "application/json".into()),
            ("X-MIP-Audience".into(), self.audience.clone()),
            ("X-MIP-Event".into(), self.event_type.clone()),
            ("X-MIP-Event-Id".into(), self.event_id.clone()),
            ("X-MIP-Timestamp".into(), timestamp.into()),
            ("X-MIP-Delivery-Attempt".into(), attempt_count.to_string()),
            ("X-MIP-Signature".into(), signature),
        ]))
    }
}
