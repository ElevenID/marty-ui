//! Direct native projections against the frozen Credentials v0.1.76 corpus.
#[path = "support/renewal_reference_fixture.rs"]
#[allow(dead_code)]
#[allow(clippy::duplicate_mod)]
mod reference_rows;

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chrono::{DateTime, Utc};
use marty_issuance_service::{
    canvas_mirror_automation::{
        run_canvas_mirror_automation_loop, CanvasMirrorAutomationBatchOutcome,
        CanvasMirrorAutomationConfig, CanvasMirrorAutomationError, CanvasMirrorAutomationPort,
        CanvasMirrorAutomationRuntime,
    },
    canvas_mirror_domain::{
        CanvasMirrorAlertEvent, CanvasMirrorAlertThresholds, CanvasMirrorDeliveryRecord,
    },
    canvas_mirror_http::{router_with_clock, CanvasMirrorHttpClock},
    canvas_mirror_provider::{
        CanvasMirrorAlertWebhook, CanvasMirrorAlertWebhookError, CanvasMirrorProviderError,
        CanvasMirrorPublicationOutcome, CanvasMirrorPublicationProvider,
        CanvasMirrorStatusProvider, TransportCanvasMirrorAlertWebhook,
    },
    canvas_mirror_repository::{
        CanvasMirrorDeliveryQuery, CanvasMirrorRepository, CanvasMirrorRepositoryError,
    },
    canvas_mirror_service::{
        CanvasMirrorProvenanceSelector, CanvasMirrorService, CanvasMirrorServiceError,
    },
    canvas_provider_http::CanvasHttpClientPolicy,
    credential::CredentialTransaction,
    credential_management::CredentialLifecycleAction,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tower::ServiceExt;
use tracing::{field::Visit, instrument::WithSubscriber, Event, Metadata, Subscriber};
use tracing_subscriber::{layer::Context, prelude::*, Layer};

#[derive(Clone, Default)]
struct TraceCapture(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

#[derive(Default)]
struct TraceFields(BTreeMap<String, String>);

impl Visit for TraceFields {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.0.insert(
            field.name().to_owned(),
            format!("{value:?}").trim_matches('"').to_owned(),
        );
    }
}

impl<S: Subscriber> Layer<S> for TraceCapture {
    fn enabled(&self, metadata: &Metadata<'_>, _context: Context<'_, S>) -> bool {
        metadata
            .target()
            .starts_with("marty_issuance_service::canvas_mirror")
    }

    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut fields = TraceFields::default();
        event.record(&mut fields);
        fields
            .0
            .insert("level".to_owned(), event.metadata().level().to_string());
        self.0.lock().unwrap().push(fields.0);
    }
}

fn captured_event<'a>(
    events: &'a [BTreeMap<String, String>],
    message: &str,
    operation: Option<&str>,
) -> &'a BTreeMap<String, String> {
    events
        .iter()
        .find(|event| {
            event.get("message").is_some_and(|value| value == message)
                && operation.is_none_or(|expected| {
                    event
                        .get("canvas_mirror_operation")
                        .is_some_and(|value| value == expected)
                })
        })
        .unwrap_or_else(|| panic!("missing {message:?} event for {operation:?}: {events:#?}"))
}

#[test]
fn frozen_http_observation_inventory_is_exhaustively_owned() {
    let reference = reference();
    let actual = reference["http"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["id"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    let expected = [
        "bridge_publish",
        "badgr_publish",
        "canvas_api_publish",
        "publish_http_failure",
        "publish_transport_failure",
        "publish_repository_failure",
        "publish_empty_success",
        "publish_scalar_success",
        "badgr_missing_assertion",
        "publish_missing_credential",
        "publish_missing_transaction",
        "publish_missing_delivery",
        "publish_missing_binding",
        "publish_missing_platform",
        "publish_disabled_binding",
        "publish_disabled_platform",
        "publish_gate_disabled",
        "publish_operations_disabled",
        "publish_foreign_context",
        "publish_missing_context",
        "pending_default",
        "pending_repository_failure",
        "pending_failed_excluded",
        "pending_failed_retry",
        "pending_all_organizations",
        "pending_zero_limit",
        "pending_excess_limit",
        "pending_invalid_retry",
        "pending_failed_alert_webhook",
        "pending_webhook_refusal",
        "pending_warning_no_webhook",
        "status_bridge_revoke",
        "status_repository_failure",
        "status_badgr_revoke",
        "status_badgr_suspend",
        "status_badgr_reinstate",
        "status_missing_credential",
        "status_gate_disabled",
        "status_no_failure",
        "automation_both_batches",
        "automation_repository_failure",
        "automation_failed_default_retry",
        "health_pending",
        "health_repository_failure",
        "health_mixed_alerts",
        "health_foreign_context",
        "provenance_by_record",
        "provenance_repository_failure",
        "provenance_by_external",
        "provenance_by_credential",
        "provenance_missing_selector",
        "provenance_missing_context",
        "provenance_context_mismatch",
        "provenance_foreign_record",
        "provenance_missing_credential",
        "provenance_missing_transaction",
        "provenance_wrong_account",
        "badgr_missing_recipient",
        "auth_publish_missing",
        "auth_publish_wrong",
        "auth_pending_missing",
        "auth_pending_wrong",
        "auth_resync_missing",
        "auth_resync_wrong",
        "auth_cycle_missing",
        "auth_cycle_wrong",
        "auth_health_missing",
        "auth_health_wrong",
        "auth_provenance_missing",
        "auth_provenance_wrong",
        "auth_publish_before_tenant",
        "auth_pending_before_validation",
        "auth_provenance_before_tenant",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(actual.len(), 73);
    assert_eq!(
        actual, expected,
        "new frozen observations require native ownership proof"
    );
}

#[derive(Clone)]
struct FixedHttpClock(DateTime<Utc>);

impl CanvasMirrorHttpClock for FixedHttpClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

#[derive(Default)]
struct Repository {
    records: Vec<CanvasMirrorDeliveryRecord>,
    credential: Option<Value>,
    transaction: Option<Value>,
    ignore_delivery_query: bool,
    fail_first_read: bool,
    calls: Mutex<Vec<String>>,
    events: Mutex<Vec<CanvasMirrorAlertEvent>>,
}

#[async_trait]
impl CanvasMirrorRepository for Repository {
    async fn delivery_record(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        self.calls.lock().unwrap().push("delivery_record".into());
        if self.fail_first_read {
            return Err(CanvasMirrorRepositoryError);
        }
        Ok(self
            .records
            .iter()
            .find(|record| record.id == id && record.organization_id == organization_id)
            .cloned())
    }

    async fn delivery_by_external_credential(
        &self,
        external_credential_id: &str,
        canvas_account_id: Option<&str>,
        organization_id: &str,
    ) -> Result<Option<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        self.calls
            .lock()
            .unwrap()
            .push("delivery_by_external_credential".into());
        Ok(self
            .records
            .iter()
            .find(|record| {
                record.external_credential_id.as_deref() == Some(external_credential_id)
                    && record.is_canvas_record_for(organization_id, canvas_account_id)
            })
            .cloned())
    }

    async fn deliveries_for_credential(
        &self,
        credential_id: &str,
        organization_id: &str,
    ) -> Result<Vec<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        self.calls
            .lock()
            .unwrap()
            .push("deliveries_for_credential".into());
        Ok(self
            .records
            .iter()
            .filter(|record| {
                record.credential_id == credential_id
                    && record.organization_id == organization_id
                    && record.delivery_target == "canvas_credentials"
            })
            .cloned()
            .collect())
    }

    async fn canvas_deliveries(
        &self,
        query: CanvasMirrorDeliveryQuery,
    ) -> Result<Vec<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        self.calls.lock().unwrap().push("canvas_deliveries".into());
        if self.fail_first_read {
            return Err(CanvasMirrorRepositoryError);
        }
        if self.ignore_delivery_query {
            return Ok(self.records.clone());
        }
        Ok(self
            .records
            .iter()
            .filter(|record| {
                record.delivery_target == "canvas_credentials"
                    && query
                        .organization_id
                        .as_deref()
                        .is_none_or(|organization| record.organization_id == organization)
                    && (query.statuses.is_empty()
                        || query
                            .statuses
                            .iter()
                            .any(|status| status.as_str() == record.status))
            })
            .take(query.limit.unwrap_or(u32::MAX) as usize)
            .cloned()
            .collect())
    }

    async fn credential(
        &self,
        _id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        self.calls.lock().unwrap().push("credential".into());
        Ok(self
            .credential
            .clone()
            .filter(|value| value["organization_id"] == organization_id))
    }

    async fn credential_unscoped(
        &self,
        id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        self.calls
            .lock()
            .unwrap()
            .push("credential_unscoped".into());
        if self.fail_first_read {
            return Err(CanvasMirrorRepositoryError);
        }
        Ok(self.credential.clone().filter(|value| value["id"] == id))
    }

    async fn transaction(
        &self,
        _id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        self.calls.lock().unwrap().push("transaction".into());
        Ok(self
            .transaction
            .clone()
            .filter(|value| value["organization_id"] == organization_id))
    }

    async fn publication_transaction(
        &self,
        _id: &str,
        _organization_id: &str,
    ) -> Result<Option<CredentialTransaction>, CanvasMirrorRepositoryError> {
        Ok(None)
    }

    async fn application(
        &self,
        _id: &str,
        _organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        Ok(None)
    }

    async fn canvas_program_binding(
        &self,
        _id: &str,
        _organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        Ok(None)
    }

    async fn canvas_platform(
        &self,
        _id: &str,
        _organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        Ok(None)
    }

    async fn save_delivery(
        &self,
        _record: &CanvasMirrorDeliveryRecord,
    ) -> Result<(), CanvasMirrorRepositoryError> {
        self.calls.lock().unwrap().push("save_delivery".into());
        Ok(())
    }

    async fn save_alert_event(
        &self,
        event: &CanvasMirrorAlertEvent,
    ) -> Result<(), CanvasMirrorRepositoryError> {
        self.calls.lock().unwrap().push("save_alert_event".into());
        self.events.lock().unwrap().push(event.clone());
        Ok(())
    }
}

#[tokio::test]
async fn health_and_provenance_match_the_frozen_success_bodies() {
    let reference: Value = serde_json::from_str(include_str!(
        "../../../../contracts/canvas-mirror-python-reference.json"
    ))
    .unwrap();
    let pending = record("pending");
    let health_repository = Arc::new(Repository {
        records: vec![pending],
        ..Default::default()
    });
    let health_service = service(health_repository.clone());
    assert_eq!(
        health_service.health("org-1").await.unwrap(),
        response_body(&reference, "health_pending")
    );
    assert_eq!(
        *health_repository.calls.lock().unwrap(),
        ["canvas_deliveries"]
    );
    let mut foreign = record("failed");
    foreign.organization_id = "org-foreign".into();
    foreign
        .metadata
        .insert("publish_attempts".into(), json!(99));
    let hostile_repository = Arc::new(Repository {
        records: vec![record("pending"), foreign],
        ignore_delivery_query: true,
        ..Default::default()
    });
    assert_eq!(
        service(hostile_repository).health("org-1").await.unwrap(),
        response_body(&reference, "health_pending")
    );

    let provenance_repository = Arc::new(Repository {
        records: vec![record("delivered")],
        credential: Some(credential()),
        transaction: Some(transaction()),
        calls: Mutex::new(Vec::new()),
        ..Default::default()
    });
    let provenance_service = service(provenance_repository.clone());
    assert_eq!(
        provenance_service
            .provenance(
                "org-1",
                CanvasMirrorProvenanceSelector {
                    delivery_record_id: Some("delivery-001".into()),
                    ..Default::default()
                },
                now(),
            )
            .await
            .unwrap(),
        response_body(&reference, "provenance_by_record")
    );
    assert_eq!(
        *provenance_repository.calls.lock().unwrap(),
        ["delivery_record", "credential", "transaction"]
    );
}

#[tokio::test]
async fn mixed_health_and_all_successful_provenance_selectors_match_frozen_bodies() {
    let reference = reference();
    let snapshot = before_snapshot(&reference, "health_mixed_alerts");
    let records = snapshot["delivery_records"]
        .as_object()
        .unwrap()
        .values()
        .cloned()
        .map(serde_json::from_value)
        .collect::<Result<Vec<CanvasMirrorDeliveryRecord>, _>>()
        .unwrap();
    let health_repository = Arc::new(Repository {
        records,
        ..Default::default()
    });
    assert_eq!(
        service(health_repository).health("org-1").await.unwrap(),
        response_body(&reference, "health_mixed_alerts")
    );

    for (observation_id, selector) in [
        (
            "provenance_by_external",
            CanvasMirrorProvenanceSelector {
                external_credential_id: Some("external-1".into()),
                ..Default::default()
            },
        ),
        (
            "provenance_by_credential",
            CanvasMirrorProvenanceSelector {
                credential_id: Some("cred-001".into()),
                ..Default::default()
            },
        ),
    ] {
        let snapshot = before_snapshot(&reference, observation_id);
        let records = snapshot["delivery_records"]
            .as_object()
            .unwrap()
            .values()
            .cloned()
            .map(serde_json::from_value)
            .collect::<Result<Vec<CanvasMirrorDeliveryRecord>, _>>()
            .unwrap();
        let repository = Arc::new(Repository {
            records,
            credential: Some(credential()),
            transaction: Some(transaction()),
            ..Default::default()
        });
        assert_eq!(
            service(repository)
                .provenance("org-1", selector, now())
                .await
                .unwrap(),
            response_body(&reference, observation_id),
            "{observation_id}"
        );
    }

    let missing_transaction_snapshot =
        before_snapshot(&reference, "provenance_missing_transaction");
    let missing_transaction_records = missing_transaction_snapshot["delivery_records"]
        .as_object()
        .unwrap()
        .values()
        .cloned()
        .map(serde_json::from_value)
        .collect::<Result<Vec<CanvasMirrorDeliveryRecord>, _>>()
        .unwrap();
    let missing_transaction = Arc::new(Repository {
        records: missing_transaction_records,
        credential: Some(credential()),
        transaction: None,
        ..Default::default()
    });
    assert_eq!(
        service(missing_transaction)
            .provenance(
                "org-1",
                CanvasMirrorProvenanceSelector {
                    delivery_record_id: Some("delivery-001".into()),
                    ..Default::default()
                },
                now(),
            )
            .await
            .unwrap(),
        response_body(&reference, "provenance_missing_transaction")
    );
}

#[tokio::test]
async fn provenance_selector_precedence_and_tenant_filters_fail_closed() {
    let repository = Arc::new(Repository {
        records: vec![record("delivered")],
        credential: Some(credential()),
        transaction: Some(transaction()),
        calls: Mutex::new(Vec::new()),
        ..Default::default()
    });
    let service = service(repository.clone());
    assert_eq!(
        service
            .provenance(
                "org-foreign",
                CanvasMirrorProvenanceSelector {
                    delivery_record_id: Some("delivery-001".into()),
                    external_credential_id: Some("external-1".into()),
                    ..Default::default()
                },
                now(),
            )
            .await,
        Err(CanvasMirrorServiceError::NotFound)
    );
    assert_eq!(*repository.calls.lock().unwrap(), ["delivery_record"]);
    repository.calls.lock().unwrap().clear();
    assert_eq!(
        service
            .provenance("org-1", CanvasMirrorProvenanceSelector::default(), now(),)
            .await,
        Err(CanvasMirrorServiceError::SelectorRequired)
    );
    assert!(repository.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn provenance_never_projects_cross_tenant_or_mislinked_canonical_rows() {
    let cross_tenant = Arc::new(Repository {
        records: vec![record("delivered")],
        credential: Some({
            let mut value = credential();
            value["organization_id"] = json!("org-foreign");
            value
        }),
        transaction: Some(transaction()),
        calls: Mutex::new(Vec::new()),
        ..Default::default()
    });
    assert_eq!(
        service(cross_tenant.clone())
            .provenance(
                "org-1",
                CanvasMirrorProvenanceSelector {
                    delivery_record_id: Some("delivery-001".into()),
                    ..Default::default()
                },
                now(),
            )
            .await,
        Err(CanvasMirrorServiceError::CanonicalCredentialMissing)
    );
    assert_eq!(
        *cross_tenant.calls.lock().unwrap(),
        ["delivery_record", "credential"]
    );

    let mislinked = Arc::new(Repository {
        records: vec![record("delivered")],
        credential: Some({
            let mut value = credential();
            value["transaction_id"] = json!("tx-foreign");
            value
        }),
        transaction: Some(transaction()),
        calls: Mutex::new(Vec::new()),
        ..Default::default()
    });
    assert_eq!(
        service(mislinked.clone())
            .provenance(
                "org-1",
                CanvasMirrorProvenanceSelector {
                    delivery_record_id: Some("delivery-001".into()),
                    ..Default::default()
                },
                now(),
            )
            .await,
        Err(CanvasMirrorServiceError::CanonicalOwnershipMismatch)
    );
    assert_eq!(
        *mislinked.calls.lock().unwrap(),
        ["delivery_record", "credential"]
    );
}

fn service(repository: Arc<Repository>) -> CanvasMirrorService {
    CanvasMirrorService::new(
        repository,
        "https://issuer.example".into(),
        CanvasMirrorAlertThresholds {
            warning_attempts: 3,
            critical_attempts: 5,
        },
    )
}

fn record(status: &str) -> CanvasMirrorDeliveryRecord {
    serde_json::from_value(json!({
        "id": "delivery-001",
        "credential_id": "cred-001",
        "transaction_id": "tx-001",
        "organization_id": "org-1",
        "delivery_target": "canvas_credentials",
        "delivery_mode": "wallet_plus_canvas_mirror",
        "status": status,
        "canvas_account_id": "canvas-account-1",
        "external_credential_id": if status == "delivered" { json!("external-1") } else { Value::Null },
        "external_issuer_id": null,
        "last_error": null,
        "metadata": {
            "queue": "canvas_credentials_mirror",
            "canvas_platform_id": "platform-1",
            "canvas_program_binding_id": "binding-1",
            "publish_attempts": 0,
            "private_fixture_marker": "must-not-enter-public-provenance-metadata"
        },
        "created_at": "2026-03-01T00:00:00+00:00",
        "updated_at": "2026-09-01T12:00:00+00:00"
    }))
    .unwrap()
}

fn credential() -> Value {
    json!({
        "id": "cred-001",
        "transaction_id": "tx-001",
        "organization_id": "org-1",
        "credential_template_id": "tmpl-1",
        "applicant_id": "applicant-1",
        "subject_did": "did:key:z6Mk_subject",
        "issuer_did": "did:web:issuer.example",
        "revocation_profile_id": null,
        "status_list_entries": [],
        "credential_hash": "62971d440b33f7dd58117df0ea1fb45ac424913c8b74b497869b50914568f7aa",
        "status": "active",
        "issued_at": "2026-03-01T00:00:00+00:00",
        "expires_at": "2027-03-01T00:00:00+00:00",
        "status_updated_at": "2026-09-01T12:00:00+00:00",
        "revocation_reason": null
    })
}

fn transaction() -> Value {
    json!({
        "id": "tx-001",
        "organization_id": "org-1",
        "application_id": null,
        "applicant_id": "applicant-1",
        "subject_did": "did:key:z6Mk_subject",
        "credential_type": "VerifiableCredential",
        "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
        "delivery_mode": "wallet_plus_canvas_mirror",
        "issuer_did_override": null
    })
}

fn now() -> DateTime<Utc> {
    "2026-09-01T12:00:00Z".parse().unwrap()
}

fn response_body(reference: &Value, id: &str) -> Value {
    reference["http"]
        .as_array()
        .unwrap()
        .iter()
        .find(|observation| observation["id"] == id)
        .unwrap()["responses"][0]["body"]
        .clone()
}

fn before_snapshot<'a>(reference: &'a Value, id: &str) -> &'a Value {
    let observation = reference["http"]
        .as_array()
        .unwrap()
        .iter()
        .find(|observation| observation["id"] == id)
        .unwrap();
    let digest = observation["before"]["snapshot_sha256"].as_str().unwrap();
    &reference["snapshots"][digest]
}

struct PublishingRepository {
    credential: Value,
    transaction: CredentialTransaction,
    transaction_projection: Value,
    record: Mutex<CanvasMirrorDeliveryRecord>,
    binding: Value,
    platform: Value,
    saves: Mutex<Vec<CanvasMirrorDeliveryRecord>>,
    events: Mutex<Vec<CanvasMirrorAlertEvent>>,
    queries: Mutex<Vec<CanvasMirrorDeliveryQuery>>,
    lookups: Mutex<Vec<String>>,
    effects: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl CanvasMirrorRepository for PublishingRepository {
    async fn delivery_record(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        Ok(Some(self.record.lock().unwrap().clone())
            .filter(|record| record.id == id && record.organization_id == organization_id))
    }

    async fn delivery_by_external_credential(
        &self,
        external_credential_id: &str,
        canvas_account_id: Option<&str>,
        organization_id: &str,
    ) -> Result<Option<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        Ok(Some(self.record.lock().unwrap().clone()).filter(|record| {
            record.external_credential_id.as_deref() == Some(external_credential_id)
                && record.is_canvas_record_for(organization_id, canvas_account_id)
        }))
    }

    async fn deliveries_for_credential(
        &self,
        credential_id: &str,
        organization_id: &str,
    ) -> Result<Vec<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        Ok(Some(self.record.lock().unwrap().clone())
            .filter(|record| {
                record.credential_id == credential_id && record.organization_id == organization_id
            })
            .into_iter()
            .collect())
    }

    async fn canvas_deliveries(
        &self,
        query: CanvasMirrorDeliveryQuery,
    ) -> Result<Vec<CanvasMirrorDeliveryRecord>, CanvasMirrorRepositoryError> {
        self.queries.lock().unwrap().push(query.clone());
        Ok(Some(self.record.lock().unwrap().clone())
            .filter(|record| {
                query
                    .organization_id
                    .as_deref()
                    .is_none_or(|organization| record.organization_id == organization)
                    && query
                        .statuses
                        .iter()
                        .any(|status| status.as_str() == record.status)
            })
            .into_iter()
            .take(query.limit.unwrap_or(u32::MAX) as usize)
            .collect())
    }

    async fn credential(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        self.lookups.lock().unwrap().push("credential".into());
        Ok(
            (self.credential["id"] == id && self.credential["organization_id"] == organization_id)
                .then(|| self.credential.clone()),
        )
    }

    async fn credential_unscoped(
        &self,
        id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        self.lookups
            .lock()
            .unwrap()
            .push("credential_unscoped".into());
        Ok((self.credential["id"] == id).then(|| self.credential.clone()))
    }

    async fn transaction(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        Ok(
            (self.transaction.id == id && self.transaction.organization_id == organization_id)
                .then(|| self.transaction_projection.clone()),
        )
    }

    async fn publication_transaction(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<CredentialTransaction>, CanvasMirrorRepositoryError> {
        self.lookups
            .lock()
            .unwrap()
            .push("publication_transaction".into());
        Ok(
            (self.transaction.id == id && self.transaction.organization_id == organization_id)
                .then(|| self.transaction.clone()),
        )
    }

    async fn application(
        &self,
        _id: &str,
        _organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        Ok(None)
    }

    async fn canvas_program_binding(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        Ok(
            (self.binding["id"] == id && self.binding["organization_id"] == organization_id)
                .then(|| self.binding.clone()),
        )
    }

    async fn canvas_platform(
        &self,
        id: &str,
        organization_id: &str,
    ) -> Result<Option<Value>, CanvasMirrorRepositoryError> {
        Ok(
            (self.platform["id"] == id && self.platform["organization_id"] == organization_id)
                .then(|| self.platform.clone()),
        )
    }

    async fn save_delivery(
        &self,
        record: &CanvasMirrorDeliveryRecord,
    ) -> Result<(), CanvasMirrorRepositoryError> {
        *self.record.lock().unwrap() = record.clone();
        self.saves.lock().unwrap().push(record.clone());
        self.effects.lock().unwrap().push("save_delivery".into());
        Ok(())
    }

    async fn save_alert_event(
        &self,
        event: &CanvasMirrorAlertEvent,
    ) -> Result<(), CanvasMirrorRepositoryError> {
        self.events.lock().unwrap().push(event.clone());
        self.effects.lock().unwrap().push("save_event".into());
        Ok(())
    }
}

struct PublicationProvider {
    outcome: CanvasMirrorPublicationOutcome,
    failure: Option<String>,
    calls: AtomicUsize,
    hold: bool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

struct AlertWebhook {
    payloads: Mutex<Vec<Value>>,
    fail: bool,
    effects: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl CanvasMirrorAlertWebhook for AlertWebhook {
    async fn post(&self, payload: Value) -> Result<(), CanvasMirrorAlertWebhookError> {
        self.payloads.lock().unwrap().push(payload);
        self.effects.lock().unwrap().push("webhook".into());
        if self.fail {
            Err(CanvasMirrorAlertWebhookError::HttpStatus)
        } else {
            Ok(())
        }
    }
}

struct StatusProvider {
    metadata: serde_json::Map<String, Value>,
    calls: AtomicUsize,
}

#[async_trait]
impl CanvasMirrorStatusProvider for StatusProvider {
    async fn synchronize(
        &self,
        _credential: &Value,
        _transaction_id: &str,
        _platform: &Value,
        _delivery: &Value,
        _action: CredentialLifecycleAction,
        _reason: Option<&str>,
    ) -> Result<serde_json::Map<String, Value>, CanvasMirrorProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.metadata.clone())
    }
}

#[async_trait]
impl CanvasMirrorPublicationProvider for PublicationProvider {
    async fn publish(
        &self,
        _credential: &Value,
        _transaction: &CredentialTransaction,
        _platform: &Value,
        _delivery: &Value,
    ) -> Result<CanvasMirrorPublicationOutcome, CanvasMirrorProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.hold {
            self.entered.notify_one();
            self.release.notified().await;
        }
        match &self.failure {
            Some(failure) => Err(CanvasMirrorProviderError(failure.clone())),
            None => Ok(self.outcome.clone()),
        }
    }
}

#[tokio::test]
async fn publication_orchestration_matches_frozen_success_and_gate_side_effects() {
    let reference = reference();
    let expected = response_body(&reference, "bridge_publish");
    let (repository, provider) = publishing_fixture(&reference, false);
    let service = service_for_publication(repository.clone(), provider.clone());
    let actual = service.publish("cred-001", "org-1", now()).await.unwrap();
    assert_eq!(actual.public_projection(), expected);
    assert_eq!(repository.saves.lock().unwrap().len(), 1);
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);

    let (blocked_repository, blocked_provider) = publishing_fixture(&reference, false);
    blocked_repository.record.lock().unwrap().metadata.insert(
        "canvas_feature_flags".into(),
        json!({"enable_canvas_mirror_publish":false,"enable_canvas_mirror_ops":true}),
    );
    let blocked = service_for_publication(blocked_repository.clone(), blocked_provider.clone())
        .publish("cred-001", "org-1", now())
        .await
        .unwrap();
    assert_eq!(blocked.status, "failed");
    assert_eq!(blocked.metadata["canvas_feature_gate_blocked"], true);
    assert_eq!(blocked.metadata["retryable"], false);
    assert_eq!(blocked.metadata["publish_attempts"], 0);
    assert_eq!(blocked_provider.calls.load(Ordering::SeqCst), 0);
    assert_eq!(blocked_repository.saves.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn publish_admission_reads_the_credential_before_hiding_foreign_tenants() {
    let reference = reference();

    for (trusted_organization_id, expected) in [
        (None, CanvasMirrorServiceError::TrustedOrganizationRequired),
        (Some("org-foreign"), CanvasMirrorServiceError::NotFound),
    ] {
        let (repository, provider) = publishing_fixture(&reference, false);
        let service = service_for_publication(repository.clone(), provider);
        assert_eq!(
            service
                .publish_admitted("cred-001", trusted_organization_id, now())
                .await,
            Err(expected)
        );
        assert_eq!(*repository.lookups.lock().unwrap(), ["credential_unscoped"]);
        assert!(repository.effects.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn native_http_mounts_all_six_routes_and_keeps_authentication_first() {
    let repository = Arc::new(Repository::default());
    let app = router_with_clock(
        service(repository.clone()),
        Some("management-secret"),
        Arc::new(FixedHttpClock(now())),
    );

    let unauthenticated = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/issuance/delivery-records/canvas-credentials/process-pending?limit=bad")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), 401);
    assert_eq!(
        response_json(unauthenticated).await,
        json!({"detail":"X-API-Key header is missing"})
    );
    assert!(repository.calls.lock().unwrap().is_empty());

    let cases = [
        (
            "POST",
            "/v1/issued-credentials/missing/deliveries/canvas-credentials/publish",
            Some("org-1"),
            StatusCode::NOT_FOUND,
        ),
        (
            "POST",
            "/v1/issuance/delivery-records/canvas-credentials/process-pending",
            None,
            StatusCode::OK,
        ),
        (
            "POST",
            "/v1/issuance/delivery-records/canvas-credentials/process-status-sync-failures",
            None,
            StatusCode::OK,
        ),
        (
            "POST",
            "/v1/issuance/delivery-records/canvas-credentials/run-automation-cycle",
            None,
            StatusCode::OK,
        ),
        (
            "GET",
            "/v1/issuance/organizations/org-1/canvas-mirror-health",
            None,
            StatusCode::OK,
        ),
        (
            "GET",
            "/v1/issuance/delivery-records/canvas-credentials/provenance?organization_id=org-1&delivery_record_id=missing",
            Some("org-1"),
            StatusCode::NOT_FOUND,
        ),
    ];
    for (method, uri, organization_id, expected) in cases {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-api-key", "management-secret");
        if let Some(organization_id) = organization_id {
            request = request.header("x-organization-id", organization_id);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{method} {uri}");
    }

    let wrong_method = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/issuance/delivery-records/canvas-credentials/process-pending")
                .header("x-api-key", "management-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn native_http_preserves_the_frozen_authentication_and_validation_matrix() {
    let routes = [
        (
            "POST",
            "/v1/issued-credentials/missing/deliveries/canvas-credentials/publish",
        ),
        (
            "POST",
            "/v1/issuance/delivery-records/canvas-credentials/process-pending",
        ),
        (
            "POST",
            "/v1/issuance/delivery-records/canvas-credentials/process-status-sync-failures",
        ),
        (
            "POST",
            "/v1/issuance/delivery-records/canvas-credentials/run-automation-cycle",
        ),
        (
            "GET",
            "/v1/issuance/organizations/org-1/canvas-mirror-health",
        ),
        (
            "GET",
            "/v1/issuance/delivery-records/canvas-credentials/provenance?organization_id=org-1",
        ),
    ];
    for (method, uri) in routes {
        for supplied_key in [None, Some("wrong-secret")] {
            let repository = Arc::new(Repository::default());
            let app = router_with_clock(
                service(repository.clone()),
                Some("management-secret"),
                Arc::new(FixedHttpClock(now())),
            );
            let mut request = Request::builder().method(method).uri(uri);
            if let Some(key) = supplied_key {
                request = request.header("x-api-key", key);
            }
            let response = app
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {uri}"
            );
            assert!(repository.calls.lock().unwrap().is_empty());
        }
    }

    let validation_cases = [
        (
            "POST",
            "/v1/issuance/delivery-records/canvas-credentials/process-pending?limit=0",
            None,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "POST",
            "/v1/issuance/delivery-records/canvas-credentials/process-pending?limit=201",
            None,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "POST",
            "/v1/issuance/delivery-records/canvas-credentials/process-pending?retry_failed=perhaps",
            None,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "GET",
            "/v1/issuance/delivery-records/canvas-credentials/provenance?organization_id=org-1",
            Some("org-1"),
            StatusCode::BAD_REQUEST,
        ),
        (
            "GET",
            "/v1/issuance/delivery-records/canvas-credentials/provenance?delivery_record_id=missing&organization_id=org-1",
            None,
            StatusCode::FORBIDDEN,
        ),
        (
            "GET",
            "/v1/issuance/delivery-records/canvas-credentials/provenance?delivery_record_id=missing&organization_id=org-1",
            Some("org-foreign"),
            StatusCode::FORBIDDEN,
        ),
    ];
    for (method, uri, organization_id, expected) in validation_cases {
        let repository = Arc::new(Repository::default());
        let app = router_with_clock(
            service(repository.clone()),
            Some("management-secret"),
            Arc::new(FixedHttpClock(now())),
        );
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-api-key", "management-secret");
        if let Some(organization_id) = organization_id {
            request = request.header("x-organization-id", organization_id);
        }
        let response = app
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{method} {uri}");
        assert!(repository.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn native_http_preserves_generic_repository_failures_for_every_route() {
    let cases = [
        (
            "POST",
            "/v1/issued-credentials/cred-001/deliveries/canvas-credentials/publish",
            Some("org-1"),
        ),
        (
            "POST",
            "/v1/issuance/delivery-records/canvas-credentials/process-pending",
            None,
        ),
        (
            "POST",
            "/v1/issuance/delivery-records/canvas-credentials/process-status-sync-failures",
            None,
        ),
        (
            "POST",
            "/v1/issuance/delivery-records/canvas-credentials/run-automation-cycle",
            None,
        ),
        (
            "GET",
            "/v1/issuance/organizations/org-1/canvas-mirror-health",
            None,
        ),
        (
            "GET",
            "/v1/issuance/delivery-records/canvas-credentials/provenance?organization_id=org-1&delivery_record_id=delivery-001",
            Some("org-1"),
        ),
    ];
    for (method, uri, organization_id) in cases {
        let repository = Arc::new(Repository {
            credential: Some(credential()),
            fail_first_read: true,
            ..Default::default()
        });
        let app = router_with_clock(
            service(repository.clone()),
            Some("management-secret"),
            Arc::new(FixedHttpClock(now())),
        );
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-api-key", "management-secret");
        if let Some(organization_id) = organization_id {
            request = request.header("x-organization-id", organization_id);
        }
        let response = app
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            "Internal Server Error"
        );
        assert_eq!(repository.calls.lock().unwrap().len(), 1, "{method} {uri}");
    }
}

#[tokio::test]
async fn publish_http_hides_foreign_tenants_after_only_the_admission_lookup() {
    let reference = reference();
    let (repository, provider) = publishing_fixture(&reference, false);
    let app = router_with_clock(
        service_for_publication(repository.clone(), provider),
        Some("management-secret"),
        Arc::new(FixedHttpClock(now())),
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/issued-credentials/cred-001/deliveries/canvas-credentials/publish")
                .header("x-api-key", "management-secret")
                .header("x-organization-id", "org-foreign")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response_json(response).await,
        json!({"detail":"Issued credential not found"})
    );
    assert_eq!(*repository.lookups.lock().unwrap(), ["credential_unscoped"]);
    assert!(repository.effects.lock().unwrap().is_empty());
}

async fn response_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}

#[tokio::test]
async fn batch_keeps_optional_organization_and_provider_cancellation_before_save() {
    let reference = reference();
    let (repository, provider) = publishing_fixture(&reference, false);
    let result = service_for_publication(repository.clone(), provider)
        .process_pending(None, 25, false, now())
        .await
        .unwrap();
    assert_eq!(result["organization_id"], Value::Null);
    assert_eq!(result["processed_count"], 1);
    assert_eq!(repository.queries.lock().unwrap()[0].organization_id, None);

    let (held_repository, held_provider) = publishing_fixture(&reference, true);
    let held_service = service_for_publication(held_repository.clone(), held_provider.clone());
    let mut action = Box::pin(held_service.publish("cred-001", "org-1", now()));
    tokio::select! {
        _ = &mut action => panic!("provider-held publication completed before cancellation"),
        entered = tokio::time::timeout(std::time::Duration::from_secs(2), held_provider.entered.notified()) => entered.expect("provider entry deadline"),
    }
    assert!(held_repository.saves.lock().unwrap().is_empty());
    drop(action);
    held_provider.release.notify_waiters();
    tokio::task::yield_now().await;
    assert!(held_repository.saves.lock().unwrap().is_empty());
}

#[tokio::test]
async fn automation_cycle_uses_the_same_publish_and_status_orchestrators() {
    let reference = reference();
    let (repository, provider) = publishing_fixture(&reference, false);
    repository.record.lock().unwrap().status = "failed".into();
    let actual = service_for_publication(repository.clone(), provider)
        .run_automation_cycle(Some("org-1"), 25, true, now(), now())
        .await
        .unwrap();
    assert_eq!(
        actual,
        response_body(&reference, "automation_failed_default_retry")
    );
    assert_eq!(repository.queries.lock().unwrap().len(), 2);
    assert_eq!(
        repository.queries.lock().unwrap()[0]
            .statuses
            .iter()
            .map(|status| status.as_str())
            .collect::<Vec<_>>(),
        ["pending", "failed"]
    );
    assert_eq!(
        repository.queries.lock().unwrap()[1]
            .statuses
            .iter()
            .map(|status| status.as_str())
            .collect::<Vec<_>>(),
        ["delivered"]
    );
}

#[tokio::test]
async fn status_resync_matches_frozen_success_and_gate_side_effects() {
    let reference = reference();
    let (repository, status) = status_fixture(&reference, "status_bridge_revoke");
    let service = CanvasMirrorService::new(
        repository.clone(),
        "https://issuer.example".into(),
        CanvasMirrorAlertThresholds {
            warning_attempts: 3,
            critical_attempts: 5,
        },
    )
    .with_status_provider(status.clone());
    assert_eq!(
        service
            .process_status_sync_failures(Some("org-1"), 25, now())
            .await
            .unwrap(),
        response_body(&reference, "status_bridge_revoke")
    );
    assert_eq!(status.calls.load(Ordering::SeqCst), 1);
    assert_eq!(repository.saves.lock().unwrap().len(), 1);

    let (blocked_repository, blocked_status) = status_fixture(&reference, "status_bridge_revoke");
    blocked_repository.record.lock().unwrap().metadata.insert(
        "canvas_feature_flags".into(),
        json!({"enable_canvas_mirror_publish":true,"enable_canvas_mirror_ops":false}),
    );
    let blocked = CanvasMirrorService::new(
        blocked_repository.clone(),
        "https://issuer.example".into(),
        CanvasMirrorAlertThresholds {
            warning_attempts: 3,
            critical_attempts: 5,
        },
    )
    .with_status_provider(blocked_status.clone())
    .process_status_sync_failures(Some("org-1"), 25, now())
    .await
    .unwrap();
    assert_eq!(blocked["blocked_count"], 1);
    assert_eq!(blocked["failed_count"], 1);
    assert_eq!(blocked_status.calls.load(Ordering::SeqCst), 0);
    assert_eq!(blocked_repository.saves.lock().unwrap().len(), 1);

    let (mut missing_repository, missing_status) =
        status_fixture(&reference, "status_missing_credential");
    Arc::get_mut(&mut missing_repository).unwrap().credential["organization_id"] =
        json!("org-missing");
    let missing = CanvasMirrorService::new(
        missing_repository.clone(),
        "https://issuer.example".into(),
        CanvasMirrorAlertThresholds {
            warning_attempts: 3,
            critical_attempts: 5,
        },
    )
    .with_status_provider(missing_status.clone())
    .process_status_sync_failures(Some("org-1"), 25, now())
    .await
    .unwrap();
    assert_eq!(
        missing,
        response_body(&reference, "status_missing_credential")
    );
    assert_eq!(missing_status.calls.load(Ordering::SeqCst), 0);
    let missing_events = missing_repository.events.lock().unwrap();
    assert_eq!(missing_events.len(), 1);
    assert_eq!(
        missing_events[0].metadata["alert_type"],
        "lifecycle_sync_failure"
    );
    assert_eq!(missing_events[0].metadata["severity"], "warning");
}

#[tokio::test]
async fn batch_alert_events_precede_advisory_critical_webhooks() {
    let reference = reference();
    let (repository, mut provider) = publishing_fixture(&reference, false);
    repository
        .record
        .lock()
        .unwrap()
        .metadata
        .insert("publish_attempts".into(), json!(4));
    Arc::get_mut(&mut provider).unwrap().failure = Some(
        "Canvas Credentials publish failed (HTTP 503): {\"id\": \"external-1\", \"issuer_id\": \"issuer-elevenid\"}"
            .into(),
    );
    let webhook = Arc::new(AlertWebhook {
        payloads: Mutex::new(Vec::new()),
        fail: true,
        effects: repository.effects.clone(),
    });
    let actual = service_for_publication(repository.clone(), provider)
        .with_alert_webhook(webhook.clone())
        .process_pending(Some("org-1"), 25, false, now())
        .await
        .expect("webhook refusal remains advisory");
    assert_eq!(actual, response_body(&reference, "pending_webhook_refusal"));
    assert_eq!(
        *repository.effects.lock().unwrap(),
        ["save_delivery", "save_event", "webhook"]
    );
    let events = repository.events.lock().unwrap().clone();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "canvas_mirror_alert_emitted");
    assert_eq!(events[0].transaction_id, "tx-001");
    assert_eq!(events[0].application_id, None);
    assert_eq!(events[0].created_at, "2026-09-01T12:00:00+00:00");
    assert_eq!(events[0].metadata["organization_id"], "org-1");
    assert_eq!(events[0].metadata["severity"], "critical");
    let payloads = webhook.payloads.lock().unwrap().clone();
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0]["event"], "canvas_mirror_critical_alert");
    assert_eq!(payloads[0]["organization_id"], "org-1");
    assert_eq!(payloads[0]["alerts"][0]["severity"], "critical");

    let (warning_repository, mut warning_provider) = publishing_fixture(&reference, false);
    warning_repository
        .record
        .lock()
        .unwrap()
        .metadata
        .insert("publish_attempts".into(), json!(2));
    Arc::get_mut(&mut warning_provider).unwrap().failure = Some(
        "Canvas Credentials publish failed (HTTP 503): {\"id\": \"external-1\", \"issuer_id\": \"issuer-elevenid\"}"
            .into(),
    );
    let warning_webhook = Arc::new(AlertWebhook {
        payloads: Mutex::new(Vec::new()),
        fail: false,
        effects: warning_repository.effects.clone(),
    });
    let warning = service_for_publication(warning_repository.clone(), warning_provider)
        .with_alert_webhook(warning_webhook.clone())
        .process_pending(Some("org-1"), 25, false, now())
        .await
        .unwrap();
    assert_eq!(
        warning,
        response_body(&reference, "pending_warning_no_webhook")
    );
    assert_eq!(
        *warning_repository.effects.lock().unwrap(),
        ["save_delivery", "save_event"]
    );
    assert!(warning_webhook.payloads.lock().unwrap().is_empty());

    let (global_repository, mut global_provider) = publishing_fixture(&reference, false);
    global_repository
        .record
        .lock()
        .unwrap()
        .metadata
        .insert("publish_attempts".into(), json!(4));
    Arc::get_mut(&mut global_provider).unwrap().failure = Some("sanitized provider failure".into());
    let global_webhook = Arc::new(AlertWebhook {
        payloads: Mutex::new(Vec::new()),
        fail: false,
        effects: global_repository.effects.clone(),
    });
    service_for_publication(global_repository.clone(), global_provider)
        .with_alert_webhook(global_webhook.clone())
        .process_pending(None, 25, false, now())
        .await
        .unwrap();
    assert_eq!(global_repository.events.lock().unwrap().len(), 1);
    let global_payloads = global_webhook.payloads.lock().unwrap().clone();
    assert_eq!(global_payloads.len(), 1);
    assert_eq!(global_payloads[0]["organization_id"], "org-1");
}

#[tokio::test]
async fn structured_observability_preserves_metrics_alerts_and_safe_webhook_causes() {
    let reference = reference();
    let capture = TraceCapture::default();
    let events = capture.0.clone();
    let subscriber = tracing_subscriber::registry().with(capture);

    async {
        let (automation_repository, automation_provider) = publishing_fixture(&reference, false);
        automation_repository.record.lock().unwrap().status = "failed".into();
        service_for_publication(automation_repository, automation_provider)
            .run_automation_cycle(Some("org-1"), 25, true, now(), now())
            .await
            .unwrap();

        let (alert_repository, mut alert_provider) = publishing_fixture(&reference, false);
        alert_repository
            .record
            .lock()
            .unwrap()
            .metadata
            .insert("publish_attempts".into(), json!(4));
        Arc::get_mut(&mut alert_provider).unwrap().failure =
            Some("provider detail retained only in the protected alert projection".into());
        let webhook = Arc::new(AlertWebhook {
            payloads: Mutex::new(Vec::new()),
            fail: true,
            effects: alert_repository.effects.clone(),
        });
        service_for_publication(alert_repository, alert_provider)
            .with_alert_webhook(webhook)
            .process_pending(Some("org-1"), 25, false, now())
            .await
            .unwrap();
    }
    .with_subscriber(subscriber)
    .await;

    let events = events.lock().unwrap();
    let publish = captured_event(&events, "canvas_mirror_metrics", Some("publish"));
    assert_eq!(publish["level"], "INFO");
    assert_eq!(publish["mip_event"], "canvas_mirror_metrics");
    assert_eq!(publish["organization_id"], "org-1");
    assert_eq!(publish["processed"], "1");
    assert!(serde_json::from_str::<Value>(&publish["metrics"]).is_ok());

    let status = captured_event(&events, "canvas_mirror_metrics", Some("status_sync"));
    assert_eq!(status["processed"], "0");
    let automation = captured_event(&events, "canvas_mirror_metrics", Some("automation_cycle"));
    assert_eq!(automation["processed"], "1");
    assert_eq!(automation["failed"], "0");

    let alert = captured_event(&events, "canvas_mirror_alert", None);
    assert_eq!(alert["level"], "WARN");
    assert_eq!(alert["mip_event"], "canvas_mirror_alert");
    assert_eq!(alert["severity"], "critical");
    assert_eq!(alert["alert_type"], "publish_failure");
    assert_eq!(alert["delivery_record_id"], "delivery-001");
    assert_eq!(alert["attempt_count"], "5");
    let alert_json: Value = serde_json::from_str(&alert["canvas_mirror_alert"]).unwrap();
    assert_eq!(alert_json["organization_id"], "org-1");
    let alert_index = events
        .iter()
        .position(|event| std::ptr::eq(event, alert))
        .unwrap();
    assert_eq!(
        events[alert_index - 1]["canvas_mirror_operation"],
        "publish"
    );

    let webhook = captured_event(&events, "Canvas mirror alert webhook delivery failed", None);
    assert_eq!(webhook["level"], "WARN");
    assert_eq!(webhook["mip_event"], "canvas_mirror_alert_webhook");
    assert_eq!(webhook["failure_cause"], "non_success_status");
    let rendered = format!("{webhook:?}");
    assert!(!rendered.contains("provider detail"));
    assert!(!rendered.contains("https://"));
}

#[test]
fn webhook_failure_categories_are_stable_and_do_not_echo_inputs() {
    assert_eq!(
        CanvasMirrorAlertWebhookError::InvalidUrl.category(),
        "invalid_url"
    );
    assert_eq!(
        CanvasMirrorAlertWebhookError::EmbeddedCredentials.category(),
        "embedded_credentials_refused"
    );
    assert_eq!(
        CanvasMirrorAlertWebhookError::Transport.category(),
        "transport_failed"
    );
    assert_eq!(
        CanvasMirrorAlertWebhookError::Serialization.category(),
        "serialization_failed"
    );
    assert_eq!(
        CanvasMirrorAlertWebhookError::HttpStatus.category(),
        "non_success_status"
    );
}

#[test]
fn automation_failure_categories_preserve_safe_service_distinctions() {
    for (error, expected) in [
        (
            CanvasMirrorServiceError::SelectorRequired,
            "selector_required",
        ),
        (
            CanvasMirrorServiceError::NotFound,
            "delivery_record_not_found",
        ),
        (
            CanvasMirrorServiceError::CanonicalCredentialMissing,
            "canonical_credential_missing",
        ),
        (
            CanvasMirrorServiceError::CanonicalOwnershipMismatch,
            "canonical_ownership_mismatch",
        ),
        (
            CanvasMirrorServiceError::TrustedOrganizationRequired,
            "trusted_organization_required",
        ),
        (
            CanvasMirrorServiceError::TransactionNotFound,
            "transaction_not_found",
        ),
        (
            CanvasMirrorServiceError::DeliveryNotFound,
            "delivery_not_found",
        ),
        (
            CanvasMirrorServiceError::DeliveryInProgress,
            "delivery_in_progress",
        ),
        (
            CanvasMirrorServiceError::Repository(CanvasMirrorRepositoryError),
            "repository_unavailable",
        ),
    ] {
        assert_eq!(
            CanvasMirrorAutomationError::from(error).category(),
            expected
        );
    }
}

#[tokio::test]
async fn webhook_transport_refuses_credential_urls_with_a_safe_category() {
    let policy = CanvasHttpClientPolicy {
        timeout: Duration::from_secs(1),
        private_origin_allowlist: Vec::new(),
        allow_private_networks: false,
        allow_http_localhost: false,
    };
    let webhook = TransportCanvasMirrorAlertWebhook::new(
        policy,
        "https://private-user:private-password@alerts.example/hook".into(),
    );
    let error = webhook.post(json!({"safe":"payload"})).await.unwrap_err();
    assert_eq!(error, CanvasMirrorAlertWebhookError::EmbeddedCredentials);
    assert_eq!(error.category(), "embedded_credentials_refused");
    assert!(!error.to_string().contains("private-user"));
    assert!(!error.to_string().contains("private-password"));
}

#[tokio::test]
async fn global_batch_keeps_alert_events_and_webhooks_tenant_isolated() {
    let mut org_one = record("pending");
    org_one.metadata.insert("publish_attempts".into(), json!(4));
    let mut org_two = org_one.clone();
    org_two.id = "delivery-002".into();
    org_two.credential_id = "cred-002".into();
    org_two.transaction_id = "tx-002".into();
    org_two.organization_id = "org-2".into();
    let repository = Arc::new(Repository {
        records: vec![org_one, org_two],
        ..Default::default()
    });
    let webhook = Arc::new(AlertWebhook {
        payloads: Mutex::new(Vec::new()),
        fail: false,
        effects: Arc::new(Mutex::new(Vec::new())),
    });

    let result = service(repository.clone())
        .with_alert_webhook(webhook.clone())
        .process_pending(None, 25, false, now())
        .await
        .unwrap();

    assert_eq!(result["processed_count"], 2);
    assert_eq!(result["failed_count"], 2);
    let events = repository.events.lock().unwrap().clone();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].metadata["organization_id"], "org-1");
    assert_eq!(events[0].metadata["delivery_record_id"], "delivery-001");
    assert_eq!(events[1].metadata["organization_id"], "org-2");
    assert_eq!(events[1].metadata["delivery_record_id"], "delivery-002");

    let payloads = webhook.payloads.lock().unwrap().clone();
    assert_eq!(payloads.len(), 2);
    assert_eq!(payloads[0]["organization_id"], "org-1");
    assert_eq!(payloads[0]["alerts"].as_array().unwrap().len(), 1);
    assert_eq!(
        payloads[0]["alerts"][0]["delivery_record_id"],
        "delivery-001"
    );
    assert_eq!(payloads[1]["organization_id"], "org-2");
    assert_eq!(payloads[1]["alerts"].as_array().unwrap().len(), 1);
    assert_eq!(
        payloads[1]["alerts"][0]["delivery_record_id"],
        "delivery-002"
    );
}

fn service_for_publication(
    repository: Arc<PublishingRepository>,
    provider: Arc<PublicationProvider>,
) -> CanvasMirrorService {
    CanvasMirrorService::new(
        repository,
        "https://issuer.example".into(),
        CanvasMirrorAlertThresholds {
            warning_attempts: 3,
            critical_attempts: 5,
        },
    )
    .with_publication_provider(provider)
}

fn publishing_fixture(
    reference: &Value,
    hold: bool,
) -> (Arc<PublishingRepository>, Arc<PublicationProvider>) {
    let observation = reference["http"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["id"] == "bridge_publish")
        .unwrap();
    let snapshot =
        &reference["snapshots"][observation["before"]["snapshot_sha256"].as_str().unwrap()];
    let first = |key: &str| snapshot[key].as_object().unwrap().values().next();
    let transaction_projection = first("transactions").unwrap().clone();
    let outcome_metadata = json!({
        "publish_url":"https://bridge.example/publish",
        "published_at":"2026-09-01T12:00:00+00:00",
        "http_status":201,
        "request_id":"synthetic-request-1",
        "publish_response":{"id":"external-1","issuer_id":"issuer-elevenid"}
    });
    (
        Arc::new(PublishingRepository {
            credential: first("credentials").cloned().unwrap_or_else(|| json!({})),
            transaction: reference_rows::transaction(&transaction_projection),
            transaction_projection,
            record: Mutex::new(
                serde_json::from_value(first("delivery_records").unwrap().clone()).unwrap(),
            ),
            binding: first("canvas_program_bindings").unwrap().clone(),
            platform: first("canvas_platforms").unwrap().clone(),
            saves: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
            queries: Mutex::new(Vec::new()),
            lookups: Mutex::new(Vec::new()),
            effects: Arc::new(Mutex::new(Vec::new())),
        }),
        Arc::new(PublicationProvider {
            outcome: CanvasMirrorPublicationOutcome {
                external_credential_id: Some("external-1".into()),
                external_issuer_id: Some("issuer-elevenid".into()),
                metadata: outcome_metadata.as_object().unwrap().clone(),
            },
            failure: None,
            calls: AtomicUsize::new(0),
            hold,
            entered: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        }),
    )
}

fn status_fixture(
    reference: &Value,
    observation_id: &str,
) -> (Arc<PublishingRepository>, Arc<StatusProvider>) {
    let observation = reference["http"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["id"] == observation_id)
        .unwrap();
    let snapshot =
        &reference["snapshots"][observation["before"]["snapshot_sha256"].as_str().unwrap()];
    let first = |key: &str| snapshot[key].as_object().unwrap().values().next();
    let transaction_projection = first("transactions").unwrap().clone();
    let metadata = json!({
        "status_sync_url":"https://bridge.example/status",
        "status_synced_at":"2026-09-01T12:00:00+00:00",
        "status_sync_http_status":201,
        "status_sync_request_id":"synthetic-request-1",
        "status_sync_response":{"id":"external-1","issuer_id":"issuer-elevenid"}
    });
    (
        Arc::new(PublishingRepository {
            credential: first("credentials").cloned().unwrap_or_else(|| json!({})),
            transaction: reference_rows::transaction(&transaction_projection),
            transaction_projection,
            record: Mutex::new(
                serde_json::from_value(first("delivery_records").unwrap().clone()).unwrap(),
            ),
            binding: first("canvas_program_bindings").unwrap().clone(),
            platform: first("canvas_platforms").unwrap().clone(),
            saves: Mutex::new(Vec::new()),
            events: Mutex::new(Vec::new()),
            queries: Mutex::new(Vec::new()),
            lookups: Mutex::new(Vec::new()),
            effects: Arc::new(Mutex::new(Vec::new())),
        }),
        Arc::new(StatusProvider {
            metadata: metadata.as_object().unwrap().clone(),
            calls: AtomicUsize::new(0),
        }),
    )
}

fn reference() -> Value {
    serde_json::from_str(include_str!(
        "../../../../contracts/canvas-mirror-python-reference.json"
    ))
    .unwrap()
}

#[derive(Default)]
struct AutomationPort {
    calls: Mutex<Vec<String>>,
    fail_publish: bool,
    publish_outcome: CanvasMirrorAutomationBatchOutcome,
    status_outcome: CanvasMirrorAutomationBatchOutcome,
}

#[async_trait]
impl CanvasMirrorAutomationPort for AutomationPort {
    async fn publish(
        &self,
        organization_id: Option<&str>,
        limit: u32,
        retry_failed: bool,
    ) -> Result<CanvasMirrorAutomationBatchOutcome, CanvasMirrorAutomationError> {
        self.calls.lock().unwrap().push(format!(
            "publish:{organization_id:?}:{limit}:{retry_failed}"
        ));
        if self.fail_publish {
            Err(CanvasMirrorAutomationError::RepositoryUnavailable)
        } else {
            Ok(self.publish_outcome)
        }
    }

    async fn status_sync(
        &self,
        organization_id: Option<&str>,
        limit: u32,
    ) -> Result<CanvasMirrorAutomationBatchOutcome, CanvasMirrorAutomationError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("status:{organization_id:?}:{limit}"));
        Ok(self.status_outcome)
    }
}

#[derive(Default)]
struct AutomationRuntime {
    tick: AtomicU64,
    sleeps: Mutex<Vec<Duration>>,
    sleeping: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl CanvasMirrorAutomationRuntime for AutomationRuntime {
    fn monotonic_seconds(&self) -> f64 {
        self.tick.fetch_add(1, Ordering::SeqCst) as f64
    }

    async fn sleep(&self, duration: Duration) {
        self.sleeps.lock().unwrap().push(duration);
        self.sleeping.notify_one();
        self.release.notified().await;
    }
}

#[test]
fn automation_configuration_preserves_defaults_and_fail_closed_fallbacks() {
    assert_eq!(
        CanvasMirrorAutomationConfig::from_values(&BTreeMap::new()),
        CanvasMirrorAutomationConfig::default()
    );
    let values = BTreeMap::from([
        ("CANVAS_MIRROR_WORKER_ENABLED".into(), "yes".into()),
        (
            "CANVAS_MIRROR_WORKER_ORGANIZATION_ID".into(),
            " org-1 ".into(),
        ),
        ("CANVAS_MIRROR_PUBLISH_INTERVAL_SECONDS".into(), "0".into()),
        (
            "CANVAS_MIRROR_STATUS_SYNC_INTERVAL_SECONDS".into(),
            "31".into(),
        ),
        ("CANVAS_MIRROR_WORKER_BATCH_LIMIT".into(), "7".into()),
        ("CANVAS_MIRROR_WORKER_RETRY_FAILED".into(), "false".into()),
        (
            "CANVAS_MIRROR_WORKER_RUN_ON_STARTUP".into(),
            "invalid".into(),
        ),
    ]);
    let parsed = CanvasMirrorAutomationConfig::from_values(&values);
    assert!(parsed.enabled);
    assert_eq!(parsed.organization_id.as_deref(), Some("org-1"));
    assert_eq!(parsed.publish_interval_seconds, 300);
    assert_eq!(parsed.status_sync_interval_seconds, 31);
    assert_eq!(parsed.batch_limit, 7);
    assert!(!parsed.retry_failed_publish);
    assert!(parsed.run_on_startup);

    let python_integer = CanvasMirrorAutomationConfig::from_values(&BTreeMap::from([(
        "CANVAS_MIRROR_WORKER_BATCH_LIMIT".into(),
        " +٣_٠ ".into(),
    )]));
    assert_eq!(python_integer.batch_limit, 30);

    let oversized = CanvasMirrorAutomationConfig::from_values(&BTreeMap::from([(
        "CANVAS_MIRROR_WORKER_BATCH_LIMIT".into(),
        "4294967296".into(),
    )]));
    assert_eq!(oversized.batch_limit, u32::MAX);
}

#[tokio::test]
async fn automation_loop_continues_independent_cycles_and_propagates_cancellation() {
    let port = Arc::new(AutomationPort {
        fail_publish: true,
        ..Default::default()
    });
    let runtime = Arc::new(AutomationRuntime::default());
    let task = tokio::spawn(run_canvas_mirror_automation_loop(
        port.clone(),
        runtime.clone(),
        CanvasMirrorAutomationConfig {
            enabled: true,
            organization_id: Some("org-1".into()),
            publish_interval_seconds: 10,
            status_sync_interval_seconds: 20,
            batch_limit: 7,
            retry_failed_publish: true,
            run_on_startup: true,
        },
    ));
    tokio::time::timeout(Duration::from_secs(2), runtime.sleeping.notified())
        .await
        .expect("scheduler sleep deadline");
    assert_eq!(
        *port.calls.lock().unwrap(),
        ["publish:Some(\"org-1\"):7:true", "status:Some(\"org-1\"):7"]
    );
    assert!(runtime.sleeps.lock().unwrap()[0] >= Duration::from_secs(1));
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());

    let disabled_port = Arc::new(AutomationPort::default());
    run_canvas_mirror_automation_loop(
        disabled_port.clone(),
        Arc::new(AutomationRuntime::default()),
        CanvasMirrorAutomationConfig::default(),
    )
    .await;
    assert!(disabled_port.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn automation_worker_observability_reports_counts_and_categorical_failures() {
    let capture = TraceCapture::default();
    let events = capture.0.clone();

    let success_port = Arc::new(AutomationPort {
        publish_outcome: CanvasMirrorAutomationBatchOutcome {
            processed: 3,
            succeeded: 2,
            failed: 1,
            blocked: 1,
        },
        status_outcome: CanvasMirrorAutomationBatchOutcome {
            processed: 2,
            succeeded: 2,
            failed: 0,
            blocked: 0,
        },
        ..Default::default()
    });
    let success_runtime = Arc::new(AutomationRuntime::default());
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let success_task = tokio::spawn(
        run_canvas_mirror_automation_loop(
            success_port,
            success_runtime.clone(),
            CanvasMirrorAutomationConfig {
                enabled: true,
                organization_id: Some("org-1".into()),
                publish_interval_seconds: 10,
                status_sync_interval_seconds: 20,
                batch_limit: 7,
                retry_failed_publish: true,
                run_on_startup: true,
            },
        )
        .with_subscriber(subscriber),
    );
    tokio::time::timeout(Duration::from_secs(2), success_runtime.sleeping.notified())
        .await
        .unwrap();
    success_task.abort();
    assert!(success_task.await.unwrap_err().is_cancelled());

    let failed_port = Arc::new(AutomationPort {
        fail_publish: true,
        ..Default::default()
    });
    let failed_runtime = Arc::new(AutomationRuntime::default());
    let subscriber = tracing_subscriber::registry().with(capture);
    let failed_task = tokio::spawn(
        run_canvas_mirror_automation_loop(
            failed_port,
            failed_runtime.clone(),
            CanvasMirrorAutomationConfig {
                enabled: true,
                organization_id: Some("org-1".into()),
                publish_interval_seconds: 10,
                status_sync_interval_seconds: 20,
                batch_limit: 7,
                retry_failed_publish: true,
                run_on_startup: true,
            },
        )
        .with_subscriber(subscriber),
    );
    tokio::time::timeout(Duration::from_secs(2), failed_runtime.sleeping.notified())
        .await
        .unwrap();
    failed_task.abort();
    assert!(failed_task.await.unwrap_err().is_cancelled());

    let events = events.lock().unwrap();
    let publish_success = captured_event(
        &events,
        "Canvas mirror publish worker cycle completed",
        Some("publish_worker"),
    );
    assert_eq!(publish_success["level"], "INFO");
    assert_eq!(publish_success["mip_event"], "canvas_mirror_worker_cycle");
    assert_eq!(publish_success["processed"], "3");
    assert_eq!(publish_success["succeeded"], "2");
    assert_eq!(publish_success["failed"], "1");
    assert_eq!(publish_success["blocked"], "1");

    let status_success = captured_event(
        &events,
        "Canvas mirror status-sync worker cycle completed",
        Some("status_sync_worker"),
    );
    assert_eq!(status_success["processed"], "2");
    assert_eq!(status_success["succeeded"], "2");

    let publish_failure = captured_event(
        &events,
        "Canvas mirror publish worker cycle failed",
        Some("publish_worker"),
    );
    assert_eq!(publish_failure["level"], "ERROR");
    assert_eq!(publish_failure["mip_event"], "canvas_mirror_worker_cycle");
    assert_eq!(publish_failure["failure_cause"], "repository_unavailable");
    assert!(!format!("{publish_failure:?}").contains("secret"));
}

struct ReferenceLoopRuntime {
    now: AtomicU64,
    trace: Mutex<Vec<String>>,
    sleep_count: AtomicUsize,
    stop_after: usize,
    stopped: tokio::sync::Notify,
}

impl ReferenceLoopRuntime {
    fn new(stop_after: usize) -> Self {
        Self {
            now: AtomicU64::new(0),
            trace: Mutex::new(Vec::new()),
            sleep_count: AtomicUsize::new(0),
            stop_after,
            stopped: tokio::sync::Notify::new(),
        }
    }

    fn advance(&self, seconds: u64) {
        self.now.fetch_add(seconds, Ordering::SeqCst);
    }
}

#[async_trait]
impl CanvasMirrorAutomationRuntime for ReferenceLoopRuntime {
    fn monotonic_seconds(&self) -> f64 {
        self.now.load(Ordering::SeqCst) as f64
    }

    async fn sleep(&self, duration: Duration) {
        let seconds = duration.as_secs();
        self.trace.lock().unwrap().push(format!(
            "sleep@{}:{seconds}",
            self.now.load(Ordering::SeqCst)
        ));
        let count = self.sleep_count.fetch_add(1, Ordering::SeqCst) + 1;
        if count >= self.stop_after {
            self.stopped.notify_one();
            std::future::pending::<()>().await;
        }
        self.advance(seconds);
    }
}

struct ReferenceLoopPort {
    runtime: Arc<ReferenceLoopRuntime>,
    publish_duration: u64,
    status_duration: u64,
    fail_publish: bool,
    fail_status: bool,
    hold: Option<&'static str>,
    entered: tokio::sync::Notify,
}

#[async_trait]
impl CanvasMirrorAutomationPort for ReferenceLoopPort {
    async fn publish(
        &self,
        _organization_id: Option<&str>,
        _limit: u32,
        _retry_failed: bool,
    ) -> Result<CanvasMirrorAutomationBatchOutcome, CanvasMirrorAutomationError> {
        self.runtime.trace.lock().unwrap().push(format!(
            "publish@{}",
            self.runtime.now.load(Ordering::SeqCst)
        ));
        if self.hold == Some("publish") {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        self.runtime.advance(self.publish_duration);
        if self.fail_publish {
            Err(CanvasMirrorAutomationError::RepositoryUnavailable)
        } else {
            Ok(CanvasMirrorAutomationBatchOutcome::default())
        }
    }

    async fn status_sync(
        &self,
        _organization_id: Option<&str>,
        _limit: u32,
    ) -> Result<CanvasMirrorAutomationBatchOutcome, CanvasMirrorAutomationError> {
        self.runtime.trace.lock().unwrap().push(format!(
            "status@{}",
            self.runtime.now.load(Ordering::SeqCst)
        ));
        if self.hold == Some("status") {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        self.runtime.advance(self.status_duration);
        if self.fail_status {
            Err(CanvasMirrorAutomationError::RepositoryUnavailable)
        } else {
            Ok(CanvasMirrorAutomationBatchOutcome::default())
        }
    }
}

fn loop_config(run_on_startup: bool) -> CanvasMirrorAutomationConfig {
    CanvasMirrorAutomationConfig {
        enabled: true,
        organization_id: Some("org-1".into()),
        publish_interval_seconds: 5,
        status_sync_interval_seconds: 7,
        batch_limit: 3,
        retry_failed_publish: true,
        run_on_startup,
    }
}

async fn loop_trace(
    run_on_startup: bool,
    publish_duration: u64,
    status_duration: u64,
    fail_publish: bool,
    fail_status: bool,
    stop_after: usize,
) -> Vec<String> {
    let runtime = Arc::new(ReferenceLoopRuntime::new(stop_after));
    let port = Arc::new(ReferenceLoopPort {
        runtime: runtime.clone(),
        publish_duration,
        status_duration,
        fail_publish,
        fail_status,
        hold: None,
        entered: tokio::sync::Notify::new(),
    });
    let task = tokio::spawn(run_canvas_mirror_automation_loop(
        port.clone(),
        runtime.clone(),
        loop_config(run_on_startup),
    ));
    tokio::time::timeout(Duration::from_secs(2), runtime.stopped.notified())
        .await
        .expect("reference loop reached requested sleep");
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let trace = runtime.trace.lock().unwrap().clone();
    trace
}

#[tokio::test]
async fn automation_loop_matches_all_frozen_scheduling_shapes() {
    assert_eq!(
        loop_trace(true, 0, 0, false, false, 3).await,
        [
            "publish@0",
            "status@0",
            "sleep@0:5",
            "publish@5",
            "sleep@5:2",
            "status@7",
            "sleep@7:3",
        ]
    );
    assert_eq!(
        loop_trace(false, 0, 0, false, false, 3).await,
        [
            "sleep@0:5",
            "publish@5",
            "sleep@5:2",
            "status@7",
            "sleep@7:3",
        ]
    );
    assert_eq!(
        loop_trace(true, 4, 7, false, false, 3).await,
        [
            "publish@0",
            "status@4",
            "sleep@11:1",
            "publish@12",
            "sleep@16:2",
            "status@18",
            "sleep@25:1",
        ]
    );
    assert_eq!(
        loop_trace(true, 0, 0, true, false, 2).await,
        [
            "publish@0",
            "status@0",
            "sleep@0:5",
            "publish@5",
            "sleep@5:2"
        ]
    );
    assert_eq!(
        loop_trace(true, 0, 0, false, true, 2).await,
        [
            "publish@0",
            "status@0",
            "sleep@0:5",
            "publish@5",
            "sleep@5:2"
        ]
    );

    for phase in ["publish", "status"] {
        let runtime = Arc::new(ReferenceLoopRuntime::new(1));
        let port = Arc::new(ReferenceLoopPort {
            runtime: runtime.clone(),
            publish_duration: 0,
            status_duration: 0,
            fail_publish: false,
            fail_status: false,
            hold: Some(phase),
            entered: tokio::sync::Notify::new(),
        });
        let task = tokio::spawn(run_canvas_mirror_automation_loop(
            port.clone(),
            runtime,
            loop_config(true),
        ));
        tokio::time::timeout(Duration::from_secs(2), port.entered.notified())
            .await
            .expect("reference loop entered cancellable phase");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(
            *port.runtime.trace.lock().unwrap(),
            if phase == "publish" {
                vec!["publish@0"]
            } else {
                vec!["publish@0", "status@0"]
            }
        );
    }
}
