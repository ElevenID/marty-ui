//! Route-neutral Canvas mirror projections frozen from Credentials v0.1.76.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::cmp::Reverse;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CanvasMirrorDeliveryRecord {
    pub id: String,
    pub credential_id: String,
    pub transaction_id: String,
    pub organization_id: String,
    pub delivery_target: String,
    pub delivery_mode: String,
    pub status: String,
    pub canvas_account_id: Option<String>,
    pub external_credential_id: Option<String>,
    pub external_issuer_id: Option<String>,
    pub last_error: Option<String>,
    #[serde(default)]
    pub metadata: Map<String, Value>,
    pub created_at: String,
    pub updated_at: String,
}

impl CanvasMirrorDeliveryRecord {
    #[must_use]
    pub fn public_projection(&self) -> Value {
        json!({
            "id": self.id,
            "delivery_target": self.delivery_target,
            "delivery_mode": self.delivery_mode,
            "status": self.status,
            "canvas_account_id": self.canvas_account_id,
            "external_credential_id": self.external_credential_id,
            "external_issuer_id": self.external_issuer_id,
            "last_error": self.last_error,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        })
    }

    #[must_use]
    pub fn is_canvas_record_for(
        &self,
        organization_id: &str,
        canvas_account_id: Option<&str>,
    ) -> bool {
        self.delivery_target == "canvas_credentials"
            && self.organization_id == organization_id
            && canvas_account_id
                .is_none_or(|expected| self.canvas_account_id.as_deref() == Some(expected))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanvasMirrorAlert {
    pub alert_type: String,
    pub severity: String,
    pub delivery_record_id: String,
    pub credential_id: String,
    pub transaction_id: String,
    pub canvas_account_id: Option<String>,
    pub attempt_count: i64,
    pub last_error: Option<String>,
    pub last_error_at: Option<String>,
    pub message: String,
    pub recommended_action: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CanvasMirrorAlertEvent {
    pub id: String,
    pub transaction_id: String,
    pub application_id: Option<String>,
    pub event_type: String,
    pub metadata: Value,
    pub created_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanvasMirrorAlertThresholds {
    pub warning_attempts: i64,
    pub critical_attempts: i64,
}

impl CanvasMirrorAlertThresholds {
    #[must_use]
    pub fn normalized(self) -> Self {
        let warning_attempts = self.warning_attempts.max(1);
        Self {
            warning_attempts,
            critical_attempts: self.critical_attempts.max(warning_attempts),
        }
    }
}

#[must_use]
pub fn canvas_mirror_health(
    organization_id: &str,
    records: &[CanvasMirrorDeliveryRecord],
    thresholds: CanvasMirrorAlertThresholds,
) -> Value {
    let thresholds = thresholds.normalized();
    let pending = records
        .iter()
        .filter(|record| record.status == "pending")
        .count();
    let failed = records
        .iter()
        .filter(|record| record.status == "failed")
        .collect::<Vec<_>>();
    let delivered = records
        .iter()
        .filter(|record| record.status == "delivered")
        .collect::<Vec<_>>();
    let blocked = records
        .iter()
        .filter(|record| metadata_truthy(record.metadata.get("canvas_feature_gate_blocked")))
        .count();
    let status_failed = delivered
        .iter()
        .copied()
        .filter(|record| metadata_truthy(record.metadata.get("last_status_sync_error")))
        .collect::<Vec<_>>();
    let status_ok = delivered.len() - status_failed.len();
    let mut alerts = failed
        .iter()
        .filter_map(|record| canvas_mirror_alert_for_record(record, true, thresholds))
        .chain(
            status_failed
                .iter()
                .filter_map(|record| canvas_mirror_alert_for_record(record, false, thresholds)),
        )
        .collect::<Vec<_>>();
    alerts.sort_by_key(|alert| {
        (
            if alert.severity == "critical" { 0 } else { 1 },
            Reverse(alert.attempt_count),
            alert.delivery_record_id.clone(),
        )
    });
    let publish_attempts = failed
        .iter()
        .map(|record| metadata_integer(&record.metadata, "publish_attempts"))
        .collect::<Vec<_>>();
    let status_attempts = status_failed
        .iter()
        .map(|record| metadata_integer(&record.metadata, "status_sync_attempts"))
        .collect::<Vec<_>>();
    let publish_alerts = alerts
        .iter()
        .filter(|alert| alert.alert_type == "publish_failure")
        .count();
    let status_alerts = alerts.len() - publish_alerts;
    let critical = alerts
        .iter()
        .filter(|alert| alert.severity == "critical")
        .count();
    let warning = alerts.len() - critical;
    json!({
        "organization_id": organization_id,
        "pending_publish_count": pending,
        "failed_publish_count": failed.len(),
        "delivered_count": delivered.len(),
        "lifecycle_sync_failed_count": status_failed.len(),
        "lifecycle_sync_ok_count": status_ok,
        "repeated_publish_failure_count": publish_alerts,
        "repeated_lifecycle_sync_failure_count": status_alerts,
        "warning_alert_count": warning,
        "critical_alert_count": critical,
        "alert_count": alerts.len(),
        "alert_thresholds": {
            "warning_attempts": thresholds.warning_attempts,
            "critical_attempts": thresholds.critical_attempts,
        },
        "metrics": {
            "publish.pending": pending,
            "publish.failed": failed.len(),
            "publish.delivered": delivered.len(),
            "publish.blocked": blocked,
            "status_sync.retry_pending": status_failed.len(),
            "status_sync.ok": status_ok,
            "publish_failure_attempts_total": publish_attempts.iter().sum::<i64>(),
            "status_sync_failure_attempts_total": status_attempts.iter().sum::<i64>(),
            "max_publish_failure_attempts": publish_attempts.iter().copied().max().unwrap_or(0),
            "max_status_sync_failure_attempts": status_attempts.iter().copied().max().unwrap_or(0),
            "repeated_publish_failure_count": publish_alerts,
            "repeated_lifecycle_sync_failure_count": status_alerts,
        },
        "alerts": alerts,
        "last_successful_publish_at": maximum_timestamp(&delivered, "published_at"),
        "last_lifecycle_sync_failure_at": maximum_timestamp(&status_failed, "last_status_sync_error_at"),
        "last_lifecycle_sync_success_at": maximum_timestamp(&delivered.iter().copied().filter(|record| !metadata_truthy(record.metadata.get("last_status_sync_error"))).collect::<Vec<_>>(), "status_synced_at"),
    })
}

#[must_use]
pub fn canvas_mirror_provenance(
    record: &CanvasMirrorDeliveryRecord,
    credential: &Value,
    transaction: Option<&Value>,
    issuer_base_url: &str,
    now: DateTime<Utc>,
) -> Value {
    let subject_id = string(credential, "subject_did")
        .or_else(|| string(credential, "applicant_id"))
        .or_else(|| transaction.and_then(|value| string(value, "subject_did")))
        .or_else(|| transaction.and_then(|value| string(value, "applicant_id")));
    let credential_status = credential_status(credential, now);
    let issuer_did = string(credential, "issuer_did")
        .or_else(|| transaction.and_then(|value| string(value, "issuer_did_override")));
    let organization_consistent = string(credential, "organization_id")
        == Some(record.organization_id.as_str())
        && transaction.is_none_or(|value| {
            string(value, "organization_id") == Some(record.organization_id.as_str())
        });
    let public_metadata = public_metadata(&record.metadata);
    json!({
        "delivery_record_id": record.id,
        "organization_id": record.organization_id,
        "canvas_account_id": record.canvas_account_id,
        "mirror": {
            "provider": "canvas",
            "delivery_target": record.delivery_target,
            "delivery_status": record.status,
            "delivery_mode": record.delivery_mode,
            "external_credential_id": record.external_credential_id,
            "external_issuer_id": record.external_issuer_id,
            "metadata": public_metadata,
            "last_error": record.last_error,
        },
        "canonical_credential": {
            "credential_id": credential["id"],
            "credential_template_id": credential["credential_template_id"],
            "credential_format": credential_format(transaction),
            "credential_status": credential_status,
            "credential_hash": credential["credential_hash"],
            "revocation_profile_id": credential["revocation_profile_id"],
            "status_list_entries": credential.get("status_list_entries").cloned().unwrap_or_else(|| json!([])),
            "subject_id_hash": subject_id.map(subject_hash),
            "issued_at": credential["issued_at"],
            "valid_until": credential.get("expires_at").cloned().unwrap_or(Value::Null),
            "status_updated_at": credential["status_updated_at"],
            "revocation_reason": credential.get("revocation_reason").cloned().unwrap_or(Value::Null),
        },
        "canonical_issuance": {
            "transaction_id": credential["transaction_id"],
            "application_id": transaction.and_then(|value| value.get("application_id")).cloned().unwrap_or(Value::Null),
            "credential_type": transaction.and_then(|value| value.get("credential_type")).cloned().filter(|value| !value.is_null()).unwrap_or_else(|| json!("unknown")),
            "delivery_mode": transaction.and_then(|value| value.get("delivery_mode")).cloned().filter(|value| !value.is_null()).unwrap_or_else(|| json!(record.delivery_mode)),
        },
        "issuer": {
            "issuer_did": issuer_did,
            "credential_issuer_url": format!("{}/org/{}", issuer_base_url.trim_end_matches('/'), record.organization_id),
        },
        "trust_basis": {
            "canonical_issuance_backed": true,
            "mirror_backed_by_delivery_record": true,
            "organization_consistent": organization_consistent,
            "distribution_channel": "canvas_credentials",
            "status_source": "canonical_credential_status",
            "credential_status": credential_status,
            "issuer_trust_anchor": issuer_did,
        },
        "delivery_record": record.public_projection(),
    })
}

#[must_use]
pub fn canvas_mirror_alert_for_record(
    record: &CanvasMirrorDeliveryRecord,
    publish: bool,
    thresholds: CanvasMirrorAlertThresholds,
) -> Option<CanvasMirrorAlert> {
    let (alert_type, attempt_key, error_at_key, noun, action) = if publish {
        (
            "publish_failure",
            "publish_attempts",
            "last_error_at",
            "publish",
            "Check Canvas Credentials publish configuration and rerun the Canvas mirror automation cycle.",
        )
    } else {
        (
            "lifecycle_sync_failure",
            "status_sync_attempts",
            "last_status_sync_error_at",
            "lifecycle status sync",
            "Check Canvas Credentials lifecycle status sync configuration and rerun failed status syncs.",
        )
    };
    let attempt_count = metadata_integer(&record.metadata, attempt_key);
    (attempt_count >= thresholds.warning_attempts).then(|| CanvasMirrorAlert {
        alert_type: alert_type.to_owned(),
        severity: if attempt_count >= thresholds.critical_attempts {
            "critical"
        } else {
            "warning"
        }
        .to_owned(),
        delivery_record_id: record.id.clone(),
        credential_id: record.credential_id.clone(),
        transaction_id: record.transaction_id.clone(),
        canvas_account_id: record.canvas_account_id.clone(),
        attempt_count,
        last_error: record.last_error.clone().or_else(|| {
            record
                .metadata
                .get("last_status_sync_error")
                .and_then(Value::as_str)
                .map(str::to_owned)
        }),
        last_error_at: record
            .metadata
            .get(error_at_key)
            .and_then(Value::as_str)
            .map(str::to_owned),
        message: format!(
            "Canvas mirror {noun} has failed {attempt_count} times for delivery record {}.",
            record.id
        ),
        recommended_action: action.to_owned(),
    })
}

fn public_metadata(metadata: &Map<String, Value>) -> Map<String, Value> {
    const KEYS: &[&str] = &[
        "published_at",
        "publish_attempts",
        "request_id",
        "canvas_response_status",
        "last_attempted_at",
        "status_synced_at",
        "status_sync_attempts",
        "last_status_sync_action",
        "last_status_sync_attempted_at",
        "last_status_sync_error",
        "last_status_sync_error_at",
        "last_synced_credential_status",
    ];
    KEYS.iter()
        .filter_map(|key| {
            metadata
                .get(*key)
                .cloned()
                .map(|value| ((*key).to_owned(), value))
        })
        .collect()
}

fn credential_format(transaction: Option<&Value>) -> &'static str {
    match transaction
        .and_then(|value| value.get("credential_payload_format"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "mso_mdoc" | "mdoc" => "MDOC",
        "vds_nc" | "vdsnc" => "VDS_NC",
        "json_ld" | "ldp_vc" | "w3c_vcdm_v2_di" => "JSON_LD",
        "jwt_vc" | "jwt_vc_json" | "w3c_vcdm_v2_jwt" | "w3c_vcdm_v2_jwt_vc" => "VC_JWT",
        _ => "SD_JWT_VC",
    }
}

fn credential_status(credential: &Value, now: DateTime<Utc>) -> String {
    let status = string(credential, "status").unwrap_or_default();
    if status == "active"
        && credential
            .get("expires_at")
            .and_then(Value::as_str)
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .is_some_and(|expires| expires < now)
    {
        "EXPIRED".to_owned()
    } else {
        status.to_ascii_uppercase()
    }
}

fn maximum_timestamp(records: &[&CanvasMirrorDeliveryRecord], key: &str) -> Option<String> {
    records
        .iter()
        .filter_map(|record| record.metadata.get(key).and_then(Value::as_str))
        .filter_map(|value| {
            DateTime::parse_from_rfc3339(value)
                .ok()
                .map(|parsed| (parsed, value))
        })
        .max_by_key(|(parsed, _)| *parsed)
        .map(|(_, value)| value.to_owned())
}

fn metadata_integer(metadata: &Map<String, Value>, key: &str) -> i64 {
    metadata
        .get(key)
        .and_then(|value| value.as_i64().or_else(|| value.as_str()?.parse().ok()))
        .unwrap_or(0)
}

fn metadata_truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|value| value != 0.0),
        Some(Value::String(value)) => !value.is_empty(),
        Some(Value::Array(value)) => !value.is_empty(),
        Some(Value::Object(value)) => !value.is_empty(),
        Some(Value::Bool(true)) => true,
    }
}

fn string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn subject_hash(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
