use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mmf_messaging::{
    DeliveryGuarantee, EventKind, Message, MessageMetadata, MessagePriority, MessageStatus,
    MessageTransport, MessagingError, MessagingPattern,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::postgres::{PostgresOrganizationStore, RepositoryError};
use crate::AuditEvent;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationEventKind {
    OrganizationCreated,
    OrganizationUpdated,
    MemberInvited,
    MemberAdded,
    MemberRemoved,
    ApiKeyCreated,
    ApiKeyRevoked,
    RoleCreated,
    RoleUpdated,
    RoleDeleted,
    RoleAssigned,
    RoleRemovedFromMember,
}

impl OrganizationEventKind {
    #[must_use]
    pub const fn event_type(self) -> &'static str {
        match self {
            Self::OrganizationCreated => "organization.created.event",
            Self::OrganizationUpdated => "organization.updated.event",
            Self::MemberInvited => "member.invited.event",
            Self::MemberAdded => "member.added.event",
            Self::MemberRemoved => "member.removed.event",
            Self::ApiKeyCreated => "api.key.created.event",
            Self::ApiKeyRevoked => "api.key.revoked.event",
            Self::RoleCreated => "role.created.event",
            Self::RoleUpdated => "role.updated.event",
            Self::RoleDeleted => "role.deleted.event",
            Self::RoleAssigned => "role.assigned.event",
            Self::RoleRemovedFromMember => "role.removed.from.member.event",
        }
    }

    const fn required_fields(self) -> &'static [&'static str] {
        match self {
            Self::OrganizationCreated => &["name", "owner_user_id"],
            Self::OrganizationUpdated => &["updated_fields"],
            Self::MemberInvited => &["member_id", "email", "invited_by"],
            Self::MemberAdded => &["member_id", "user_id", "roles"],
            Self::MemberRemoved => &["member_id", "user_id"],
            Self::ApiKeyCreated => &["api_key_id", "name", "created_by"],
            Self::ApiKeyRevoked => &["api_key_id", "revoked_by"],
            Self::RoleCreated => &["role_id", "role_name", "created_by"],
            Self::RoleUpdated => &["role_id", "role_name", "updated_by"],
            Self::RoleDeleted => &["role_id", "role_name", "deleted_by"],
            Self::RoleAssigned => &["member_id", "role_id", "role_name", "assigned_by"],
            Self::RoleRemovedFromMember => &["member_id", "role_id", "role_name", "removed_by"],
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OrganizationEventError {
    #[error("ORGANIZATION.EVENT_INVALID: organization_id is required")]
    MissingOrganization,
    #[error("ORGANIZATION.EVENT_INVALID: {0} is required")]
    MissingField(&'static str),
    #[error("ORGANIZATION.EVENT_INVALID: timestamp precedes Unix epoch")]
    InvalidTimestamp,
}

#[derive(Debug, Error)]
pub enum OrganizationEventPublisherError {
    #[error(transparent)]
    Projection(#[from] OrganizationEventError),
    #[error(transparent)]
    Audit(#[from] RepositoryError),
    #[error(transparent)]
    Transport(#[from] MessagingError),
}

#[async_trait]
pub trait OrganizationAuditSink: Send + Sync {
    async fn save(&self, event: &AuditEvent) -> Result<(), RepositoryError>;
}

#[async_trait]
impl OrganizationAuditSink for PostgresOrganizationStore {
    async fn save(&self, event: &AuditEvent) -> Result<(), RepositoryError> {
        self.save_audit_event(event).await
    }
}

#[derive(Clone)]
pub struct OrganizationEventPublisher {
    audit: Arc<dyn OrganizationAuditSink>,
    transport: Arc<dyn MessageTransport>,
}

impl OrganizationEventPublisher {
    #[must_use]
    pub fn new(
        audit: Arc<dyn OrganizationAuditSink>,
        transport: Arc<dyn MessageTransport>,
    ) -> Self {
        Self { audit, transport }
    }

    pub async fn publish(
        &self,
        event: &OrganizationEvent,
    ) -> Result<(), OrganizationEventPublisherError> {
        let audit_event = event.to_audit_event()?;
        let message = event.to_message()?;
        self.audit.save(&audit_event).await?;
        self.transport.publish(message).await?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct OrganizationEvent {
    pub event_id: Uuid,
    pub kind: OrganizationEventKind,
    pub organization_id: Uuid,
    pub data: Map<String, Value>,
    pub timestamp: DateTime<Utc>,
    pub correlation_id: Option<String>,
    pub causation_id: Option<String>,
}

impl OrganizationEvent {
    pub fn new(
        kind: OrganizationEventKind,
        organization_id: Uuid,
        mut data: Map<String, Value>,
        timestamp: DateTime<Utc>,
    ) -> Result<Self, OrganizationEventError> {
        if organization_id.is_nil() {
            return Err(OrganizationEventError::MissingOrganization);
        }
        data.insert(
            "organization_id".into(),
            Value::String(organization_id.to_string()),
        );
        for field in kind.required_fields() {
            let present = data.get(*field).is_some_and(|value| match value {
                Value::Null => false,
                Value::String(value) => !value.trim().is_empty(),
                _ => true,
            });
            if !present {
                return Err(OrganizationEventError::MissingField(field));
            }
        }
        Ok(Self {
            event_id: Uuid::new_v4(),
            kind,
            organization_id,
            data,
            timestamp,
            correlation_id: None,
            causation_id: None,
        })
    }

    #[must_use]
    pub const fn event_type(&self) -> &'static str {
        self.kind.event_type()
    }

    #[must_use]
    pub fn aggregate_id(&self) -> String {
        [
            "aggregate_id",
            "application_id",
            "applicant_id",
            "member_id",
            "user_id",
        ]
        .into_iter()
        .find_map(|field| self.data.get(field).and_then(Value::as_str))
        .filter(|value| !value.is_empty())
        .map_or_else(|| self.organization_id.to_string(), str::to_owned)
    }

    pub fn to_message(&self) -> Result<Message, OrganizationEventError> {
        let created_at_ms = u64::try_from(self.timestamp.timestamp_millis())
            .map_err(|_| OrganizationEventError::InvalidTimestamp)?;
        let mut metadata = MessageMetadata::new(created_at_ms);
        metadata.message_id = self.event_id.to_string();
        metadata.correlation_id = self.correlation_id.clone();
        metadata.causation_id = self.causation_id.clone();
        metadata.tenant_id = Some(self.organization_id.to_string());
        metadata.source_service = Some("organization".into());
        metadata.partition_key = Some(self.organization_id.to_string());
        metadata.deduplication_key = Some(self.event_id.to_string());
        Ok(Message {
            metadata,
            kind: EventKind::Domain,
            message_type: self.event_type().into(),
            pattern: MessagingPattern::PublishSubscribe,
            delivery_guarantee: DeliveryGuarantee::AtLeastOnce,
            priority: MessagePriority::Normal,
            status: MessageStatus::Pending,
            topic: "marty.organization.events".into(),
            routing_key: self.event_type().into(),
            reply_to: None,
            payload: json!({
                "event_id": self.event_id,
                "event_type": self.event_type(),
                "aggregate_id": self.aggregate_id(),
                "aggregate_type": "organization",
                "organization_id": self.organization_id,
                "data": self.data,
                "timestamp": self.timestamp.to_rfc3339(),
                "correlation_id": self.correlation_id,
            }),
            retry_count: 0,
            max_retries: 3,
        })
    }

    pub fn to_audit_event(&self) -> Result<AuditEvent, OrganizationEventError> {
        let descriptor = self.audit_descriptor()?;
        Ok(AuditEvent {
            id: Uuid::new_v4(),
            organization_id: self.organization_id,
            event_type: self.event_type().into(),
            action: descriptor.action.into(),
            category: descriptor.category.into(),
            resource_type: descriptor.resource_type.into(),
            resource_id: descriptor.resource_id,
            resource_name: descriptor.resource_name,
            actor_id: descriptor.actor_id.clone(),
            actor_type: if descriptor.actor_id.as_deref().is_some_and(str::is_empty) {
                "system"
            } else {
                descriptor.actor_type
            }
            .into(),
            severity: descriptor.severity.into(),
            message: descriptor.message,
            changes: descriptor.changes,
            metadata: json!({
                "source_service": "organization",
                "source_event_id": self.event_id,
                "source_event_type": self.event_type(),
                "event_data": self.data,
            }),
            timestamp: self.timestamp,
        })
    }

    fn audit_descriptor(&self) -> Result<AuditDescriptor, OrganizationEventError> {
        let organization_id = self.organization_id.to_string();
        let descriptor = match self.kind {
            OrganizationEventKind::OrganizationCreated => AuditDescriptor::new(
                "organization.created",
                "settings",
                "organization",
                Some(organization_id.clone()),
                Some(self.text("name")?.into()),
                Some(self.text("owner_user_id")?.into()),
                "user",
                "info",
                format!("Organization {} created", self.text("name")?),
            ),
            OrganizationEventKind::OrganizationUpdated => {
                let mut descriptor = AuditDescriptor::new(
                    "organization.updated",
                    "settings",
                    "organization",
                    Some(organization_id.clone()),
                    None,
                    None,
                    "system",
                    "info",
                    "Organization settings updated".into(),
                );
                descriptor.changes = Some(json!({"updated_fields": self.value("updated_fields")?}));
                descriptor
            }
            OrganizationEventKind::MemberInvited => AuditDescriptor::new(
                "team.member.invited",
                "team",
                "member",
                Some(self.text("member_id")?.into()),
                Some(self.text("email")?.into()),
                Some(self.text("invited_by")?.into()),
                "user",
                "info",
                format!("Member invitation sent to {}", self.text("email")?),
            ),
            OrganizationEventKind::MemberAdded => AuditDescriptor::new(
                "team.member.added",
                "team",
                "member",
                Some(self.text("member_id")?.into()),
                Some(self.text("user_id")?.into()),
                Some(self.text("user_id")?.into()),
                "user",
                "info",
                "Member added to organization".into(),
            ),
            OrganizationEventKind::MemberRemoved => AuditDescriptor::new(
                "team.member.removed",
                "team",
                "member",
                Some(self.text("member_id")?.into()),
                Some(self.text("user_id")?.into()),
                Some(self.text("user_id")?.into()),
                "user",
                "warning",
                "Member removed from organization".into(),
            ),
            OrganizationEventKind::ApiKeyCreated => AuditDescriptor::new(
                "api_key.created",
                "settings",
                "api_key",
                Some(self.text("api_key_id")?.into()),
                Some(self.text("name")?.into()),
                Some(self.text("created_by")?.into()),
                "user",
                "info",
                format!("API key {} created", self.text("name")?),
            ),
            OrganizationEventKind::ApiKeyRevoked => AuditDescriptor::new(
                "api_key.revoked",
                "settings",
                "api_key",
                Some(self.text("api_key_id")?.into()),
                None,
                Some(self.text("revoked_by")?.into()),
                "user",
                "warning",
                "API key revoked".into(),
            ),
            OrganizationEventKind::RoleCreated => {
                self.role_descriptor("team.role.created", "created_by", "created", false, false)?
            }
            OrganizationEventKind::RoleUpdated => {
                self.role_descriptor("team.role.updated", "updated_by", "updated", false, false)?
            }
            OrganizationEventKind::RoleDeleted => {
                self.role_descriptor("team.role.deleted", "deleted_by", "deleted", true, false)?
            }
            OrganizationEventKind::RoleAssigned => {
                self.role_descriptor("team.role.assigned", "assigned_by", "assigned", false, true)?
            }
            OrganizationEventKind::RoleRemovedFromMember => {
                self.role_descriptor("team.role.removed", "removed_by", "removed", true, true)?
            }
        };
        Ok(descriptor)
    }

    fn role_descriptor(
        &self,
        action: &'static str,
        actor_field: &'static str,
        verb: &str,
        warning: bool,
        member_resource: bool,
    ) -> Result<AuditDescriptor, OrganizationEventError> {
        Ok(AuditDescriptor::new(
            action,
            "team",
            "role",
            Some(
                self.text(if member_resource {
                    "member_id"
                } else {
                    "role_id"
                })?
                .into(),
            ),
            Some(self.text("role_name")?.into()),
            Some(self.text(actor_field)?.into()),
            "user",
            if warning { "warning" } else { "info" },
            format!("Role {} {verb}", self.text("role_name")?),
        ))
    }

    fn value(&self, field: &'static str) -> Result<&Value, OrganizationEventError> {
        self.data
            .get(field)
            .ok_or(OrganizationEventError::MissingField(field))
    }

    fn text(&self, field: &'static str) -> Result<&str, OrganizationEventError> {
        self.value(field)?
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or(OrganizationEventError::MissingField(field))
    }

    #[must_use]
    pub fn event_stream_data(&self) -> BTreeMap<String, String> {
        self.data
            .iter()
            .map(|(key, value)| {
                let value = value.as_str().map_or_else(
                    || serde_json::to_string(value).unwrap_or_else(|_| "null".into()),
                    str::to_owned,
                );
                (key.clone(), value)
            })
            .collect()
    }
}

struct AuditDescriptor {
    action: &'static str,
    category: &'static str,
    resource_type: &'static str,
    resource_id: Option<String>,
    resource_name: Option<String>,
    actor_id: Option<String>,
    actor_type: &'static str,
    severity: &'static str,
    message: String,
    changes: Option<Value>,
}

impl AuditDescriptor {
    #[allow(clippy::too_many_arguments)]
    fn new(
        action: &'static str,
        category: &'static str,
        resource_type: &'static str,
        resource_id: Option<String>,
        resource_name: Option<String>,
        actor_id: Option<String>,
        actor_type: &'static str,
        severity: &'static str,
        message: String,
    ) -> Self {
        Self {
            action,
            category,
            resource_type,
            resource_id,
            resource_name,
            actor_id,
            actor_type,
            severity,
            message,
            changes: None,
        }
    }
}
