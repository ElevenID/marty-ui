use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_organization::postgres::RepositoryError;
use marty_organization::{
    AuditEvent, OrganizationAuditSink, OrganizationEvent, OrganizationEventKind,
    OrganizationEventPublisher,
};
use mmf_messaging::{
    EventFilter, MemoryTransport, MessageTransport, MessagingConfig, Subscription,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use uuid::Uuid;

#[derive(Deserialize)]
struct Fixture {
    schema_version: u32,
    organization_id: Uuid,
    cases: Vec<EventCase>,
}

#[derive(Deserialize)]
struct EventCase {
    kind: OrganizationEventKind,
    event_type: String,
    data: Map<String, Value>,
    action: String,
    category: String,
    resource_type: String,
    resource_id: Option<String>,
    resource_name: Option<String>,
    actor_id: Option<String>,
    severity: String,
    message: String,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/organization-event-behavior.json"
    )))
    .expect("organization event fixture must be valid JSON")
}

fn now() -> DateTime<Utc> {
    "2026-08-20T12:00:00Z".parse().expect("fixed timestamp")
}

#[derive(Default)]
struct RecordingAuditSink {
    events: Mutex<Vec<AuditEvent>>,
}

#[async_trait]
impl OrganizationAuditSink for RecordingAuditSink {
    async fn save(&self, event: &AuditEvent) -> Result<(), RepositoryError> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event.clone());
        Ok(())
    }
}

#[test]
fn every_legacy_event_maps_to_one_canonical_message_and_audit_record() {
    let fixture = fixture();
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.cases.len(), 12);
    for case in fixture.cases {
        let event = OrganizationEvent::new(case.kind, fixture.organization_id, case.data, now())
            .expect("valid event vector");
        assert_eq!(event.event_type(), case.event_type);
        let audit = event.to_audit_event().expect("audit projection");
        assert_eq!(audit.event_type, case.event_type);
        assert_eq!(audit.action, case.action);
        assert_eq!(audit.category, case.category);
        assert_eq!(audit.resource_type, case.resource_type);
        assert_eq!(audit.resource_id, case.resource_id);
        assert_eq!(audit.resource_name, case.resource_name);
        assert_eq!(audit.actor_id, case.actor_id);
        assert_eq!(audit.severity, case.severity);
        assert_eq!(audit.message, case.message);
        assert_eq!(
            audit.metadata["source_event_id"],
            event.event_id.to_string()
        );
        assert_eq!(
            audit.metadata["event_data"],
            Value::Object(event.data.clone())
        );

        let message = event.to_message().expect("MMF message projection");
        assert_eq!(message.metadata.message_id, event.event_id.to_string());
        let organization_id = fixture.organization_id.to_string();
        assert_eq!(
            message.metadata.tenant_id.as_deref(),
            Some(organization_id.as_str())
        );
        assert_eq!(message.message_type, case.event_type);
        assert_eq!(
            message.payload["organization_id"],
            fixture.organization_id.to_string()
        );
        assert_eq!(message.payload["data"], Value::Object(event.data.clone()));
        assert_eq!(message.payload["aggregate_id"], event.aggregate_id());
    }
}

#[test]
fn malformed_or_unscoped_events_fail_closed() {
    let case = fixture().cases.remove(0);
    assert!(OrganizationEvent::new(case.kind, Uuid::nil(), case.data.clone(), now()).is_err());
    assert!(OrganizationEvent::new(
        OrganizationEventKind::OrganizationCreated,
        Uuid::new_v4(),
        Map::new(),
        now(),
    )
    .is_err());
}

#[tokio::test]
async fn audited_publisher_uses_the_canonical_mmf_transport() {
    let fixture = fixture();
    let case = &fixture.cases[0];
    let event =
        OrganizationEvent::new(case.kind, fixture.organization_id, case.data.clone(), now())
            .expect("valid event");
    let audit = Arc::new(RecordingAuditSink::default());
    let transport = Arc::new(MemoryTransport::new(MessagingConfig::default()).expect("transport"));
    transport.connect().await.expect("connect transport");
    transport
        .subscribe(Subscription {
            id: "organization-contract".into(),
            topic: "marty.organization.events".into(),
            consumer_group: Some("contract".into()),
            filter: EventFilter::default(),
        })
        .await
        .expect("subscribe");
    let publisher = OrganizationEventPublisher::new(audit.clone(), transport.clone());

    publisher.publish(&event).await.expect("publish event");

    assert_eq!(
        audit
            .events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        1
    );
    let messages = transport
        .poll("organization-contract", 1, u64::MAX)
        .await
        .expect("poll event");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].metadata.message_id, event.event_id.to_string());
}
