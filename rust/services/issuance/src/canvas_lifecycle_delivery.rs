//! Canvas lifecycle delivery candidate. Provider wiring/cutover remains gated.
//! Credential policy/persistence belongs to CredentialManagementService; this
//! owner performs the published delivered-record selection, profile gating,
//! target resolution, provider call, and durable retry/success projection.
use async_trait::async_trait;
use serde_json::{json, Map, Value};
use sqlx::PgPool;
use std::sync::Arc;

use crate::{
    canvas_binding_domain::CANVAS_FEATURE_FLAGS,
    credential_management::{
        CanvasLifecycleSyncError, CredentialLifecycleAction, CredentialManagementPortError,
        ManagedCredential,
    },
    lossless_json::{LosslessJson, LosslessObject},
    owned_json_value::OwnedJsonValue,
    python_text::PythonText,
    python_value::{python_string, python_truthy, strip},
};

#[async_trait]
pub trait CanvasLifecycleStatusProvider: Send + Sync {
    /// Errors must be safe to persist as public delivery diagnostics.
    async fn synchronize(
        &self,
        context: CanvasLifecycleCredential<'_>,
        platform: &Value,
        delivery: &Value,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<LosslessObject, CanvasLifecycleProviderError>;
}

#[derive(Clone, Debug)]
pub struct CanvasLifecycleProviderError(pub PythonText);

impl From<CredentialManagementPortError> for CanvasLifecycleProviderError {
    fn from(error: CredentialManagementPortError) -> Self {
        Self(error.0.into())
    }
}

/// Transaction identity comes from the credential row, never the delivery row.
#[derive(Clone, Copy)]
pub struct CanvasLifecycleCredential<'a> {
    pub credential: &'a ManagedCredential,
    pub transaction_id: &'a str,
}

#[async_trait]
trait CanvasLifecycleDeliveryStore: Send + Sync {
    async fn context(
        &self,
        credential: &ManagedCredential,
    ) -> Result<(String, Option<OwnedJsonValue>), CredentialManagementPortError>;

    async fn delivered(
        &self,
        credential: &ManagedCredential,
    ) -> Result<Vec<OwnedJsonValue>, CredentialManagementPortError>;

    async fn binding(
        &self,
        id: &str,
    ) -> Result<Option<OwnedJsonValue>, CredentialManagementPortError>;

    async fn platform(
        &self,
        id: &str,
    ) -> Result<Option<OwnedJsonValue>, CredentialManagementPortError>;

    async fn save(
        &self,
        record: &Value,
        metadata: Box<serde_json::value::RawValue>,
        last_error: Option<&str>,
        now: chrono::DateTime<chrono::FixedOffset>,
    ) -> Result<u64, CredentialManagementPortError>;
}

struct PostgresCanvasLifecycleDeliveryStore(PgPool);

#[async_trait]
impl CanvasLifecycleDeliveryStore for PostgresCanvasLifecycleDeliveryStore {
    async fn context(
        &self,
        credential: &ManagedCredential,
    ) -> Result<(String, Option<OwnedJsonValue>), CredentialManagementPortError> {
        Ok(sqlx::query_as("SELECT c.transaction_id,to_jsonb(a) FROM issuance_service.issued_credentials c JOIN issuance_service.issuance_transactions t ON t.id=c.transaction_id LEFT JOIN issuance_service.applications a ON a.id=t.application_id WHERE c.id=$1 AND c.organization_id=$2")
            .bind(&credential.id).bind(&credential.organization_id).fetch_optional(&self.0).await.map_err(error)?
            .unwrap_or_default())
    }

    async fn delivered(
        &self,
        credential: &ManagedCredential,
    ) -> Result<Vec<OwnedJsonValue>, CredentialManagementPortError> {
        sqlx::query_scalar("SELECT to_jsonb(d) FROM issuance_service.credential_delivery_records d WHERE credential_id=$1 AND organization_id=$2 AND delivery_target='canvas_credentials' AND status='delivered' ORDER BY created_at,delivery_target")
            .bind(&credential.id).bind(&credential.organization_id).fetch_all(&self.0).await.map_err(error)
    }

    async fn binding(
        &self,
        id: &str,
    ) -> Result<Option<OwnedJsonValue>, CredentialManagementPortError> {
        sqlx::query_scalar(
            "SELECT to_jsonb(b) FROM issuance_service.canvas_program_bindings b WHERE id=$1",
        )
        .bind(id)
        .fetch_optional(&self.0)
        .await
        .map_err(error)
    }

    async fn platform(
        &self,
        id: &str,
    ) -> Result<Option<OwnedJsonValue>, CredentialManagementPortError> {
        sqlx::query_scalar(
            "SELECT to_jsonb(p) FROM issuance_service.canvas_platforms p WHERE id=$1",
        )
        .bind(id)
        .fetch_optional(&self.0)
        .await
        .map_err(error)
    }

    async fn save(
        &self,
        record: &Value,
        metadata: Box<serde_json::value::RawValue>,
        last_error: Option<&str>,
        now: chrono::DateTime<chrono::FixedOffset>,
    ) -> Result<u64, CredentialManagementPortError> {
        Ok(sqlx::query("UPDATE issuance_service.credential_delivery_records SET metadata=$3,last_error=$4,canvas_account_id=$5,updated_at=$6 WHERE id=$1 AND organization_id=$2")
            .bind(record["id"].as_str()).bind(record["organization_id"].as_str()).bind(sqlx::types::Json(metadata))
            .bind(last_error).bind(record["canvas_account_id"].as_str()).bind(now)
            .execute(&self.0).await.map_err(error)?.rows_affected())
    }
}

#[derive(Clone)]
pub struct CanvasLifecycleDeliverySynchronizer {
    store: Arc<dyn CanvasLifecycleDeliveryStore>,
    provider: Arc<dyn CanvasLifecycleStatusProvider>,
}

impl CanvasLifecycleDeliverySynchronizer {
    pub fn new(pool: PgPool, provider: Arc<dyn CanvasLifecycleStatusProvider>) -> Self {
        Self {
            store: Arc::new(PostgresCanvasLifecycleDeliveryStore(pool)),
            provider,
        }
    }

    pub async fn synchronize(
        &self,
        credential: &ManagedCredential,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<(), CanvasLifecycleSyncError> {
        let (transaction_id, application) = self.store.context(credential).await?;
        let records = self.store.delivered(credential).await?;
        for mut record in records {
            let now = crate::canvas_legacy_ingest::timestamp_string(chrono::Utc::now());
            let mut metadata_owner = match record
                .get("metadata")
                .filter(|value| python_truthy(value))
            {
                None => OwnedJsonValue::new(json!({})),
                Some(value) if value.is_object() => OwnedJsonValue::copy(value),
                Some(_) => return Err(error("Canvas delivery metadata is not an object").into()),
            };
            let metadata = metadata_owner.as_object_mut().unwrap();
            if !(metadata
                .get("deployment_profile_id")
                .is_some_and(python_truthy)
                && metadata
                    .get("canvas_feature_flags")
                    .is_some_and(python_truthy))
            {
                if let Some(canvas) = application
                    .as_ref()
                    .and_then(|app| app["integration_context"]["canvas"].as_object())
                {
                    for (source, destination) in [
                        ("canvas_platform_id", "canvas_platform_id"),
                        ("canvas_program_binding_id", "canvas_program_binding_id"),
                        ("deployment_profile_id", "deployment_profile_id"),
                        ("delivery_mode", "canvas_binding_delivery_mode"),
                    ] {
                        if let Some(value) = canvas.get(source).filter(|value| python_truthy(value))
                        {
                            OwnedJsonValue::insert_map(
                                metadata,
                                destination.into(),
                                json!(python_string(value).ok_or_else(|| error(
                                    "Canvas profile value cannot be projected"
                                ))?),
                            );
                        }
                    }
                    let flags = flags(canvas.get("feature_flags"));
                    if !flags.is_empty() {
                        OwnedJsonValue::insert_map(
                            metadata,
                            "canvas_feature_flags".into(),
                            json!(flags),
                        );
                    }
                }
            }
            let active_flags = flags(metadata.get("canvas_feature_flags"));
            if !active_flags.is_empty()
                && active_flags.get("enable_canvas_mirror_ops") != Some(&Value::Bool(true))
            {
                let detail = "Canvas mirror operations are disabled by deployment profile";
                OwnedJsonValue::extend_map(metadata, json!({"canvas_feature_gate_blocked":true,
                    "canvas_feature_gate":"enable_canvas_mirror_ops","canvas_feature_gate_blocked_at":now,
                    "retryable":false,"last_status_sync_error":detail,"last_status_sync_error_at":now}).as_object().unwrap().clone());
                self.save(
                    &record,
                    crate::lossless_json::object(std::mem::take(metadata)),
                    Some(&detail.to_owned().into()),
                    &now,
                )
                .await?;
                continue;
            }
            let target = self.target(&mut record, metadata).await?;
            let attempts = increment_attempts(metadata.get("status_sync_attempts"))?;
            OwnedJsonValue::extend_map(metadata, json!({"status_sync_attempts":attempts,"last_status_sync_action":action.as_str(),
                "last_status_sync_attempted_at":now,"last_synced_credential_status":credential.status.as_str()}).as_object().unwrap().clone());
            let outcome = match target {
                Ok(platform) => {
                    // The provider sees hydrated target metadata, but not the
                    // new attempt projection until it has returned successfully.
                    self.provider
                        .synchronize(
                            CanvasLifecycleCredential {
                                credential,
                                transaction_id: &transaction_id,
                            },
                            &platform,
                            &record,
                            action,
                            reason,
                        )
                        .await
                }
                Err(detail) => {
                    Err(error(format!("Canvas lifecycle sync skipped: {detail}")).into())
                }
            };
            let mut metadata = crate::lossless_json::object(std::mem::take(metadata));
            match outcome {
                Ok(result) => {
                    metadata.extend(result);
                    metadata.insert("last_status_sync_error".into(), Value::Null.into());
                    self.save(&record, metadata, None, &now).await?;
                }
                Err(failure) => {
                    metadata.insert(
                        "last_status_sync_error".into(),
                        LosslessJson::Text(failure.0.clone()),
                    );
                    metadata.insert("last_status_sync_error_at".into(), json!(now).into());
                    self.save(&record, metadata, Some(&failure.0), &now).await?;
                }
            }
        }
        Ok(())
    }

    async fn target(
        &self,
        record: &mut OwnedJsonValue,
        metadata: &mut Map<String, Value>,
    ) -> Result<Result<OwnedJsonValue, String>, CredentialManagementPortError> {
        let id = metadata
            .get("canvas_program_binding_id")
            .filter(|value| !value.is_null())
            .and_then(python_string)
            .map(|value| strip(&value).to_owned())
            .filter(|value| !value.is_empty());
        let Some(id) = id else {
            return Ok(Err(
                "Canvas mirror delivery record is missing canvas_program_binding_id".into(),
            ));
        };
        let binding = self.store.binding(&id).await?;
        let Some(binding) = binding else {
            return Ok(Err(format!("Canvas program binding {id} was not found")));
        };
        if binding["enabled"] != true {
            return Ok(Err(format!("Canvas program binding {id} is disabled")));
        }
        if python_truthy(&binding["canvas_credentials"]) {
            OwnedJsonValue::insert_map(
                metadata,
                "canvas_credentials".into(),
                OwnedJsonValue::copy(&binding["canvas_credentials"]).take(),
            );
        }
        let platform_id = binding["platform_id"]
            .as_str()
            .ok_or_else(|| error("Canvas binding platform missing"))?;
        let platform = self.store.platform(platform_id).await?;
        let Some(platform) = platform else {
            return Ok(Err(format!("Canvas platform {platform_id} was not found")));
        };
        if platform["enabled"] != true {
            return Ok(Err(format!("Canvas platform {platform_id} is disabled")));
        }
        record["canvas_account_id"] = platform["canvas_account_id"].clone();
        OwnedJsonValue::insert_map(
            metadata,
            "canvas_platform_id".into(),
            platform["id"].clone(),
        );
        OwnedJsonValue::insert_map(
            metadata,
            "canvas_program_binding_id".into(),
            binding["id"].clone(),
        );
        record.replace_field("metadata", OwnedJsonValue::copy_map(metadata));
        Ok(Ok(platform))
    }

    async fn save(
        &self,
        record: &Value,
        metadata: LosslessObject,
        last_error: Option<&PythonText>,
        now: &str,
    ) -> Result<(), CanvasLifecycleSyncError> {
        // Encoding is deliberately checked here, after publication, canonical
        // persistence and provider completion, not while decoding response text.
        let metadata = crate::lossless_json::postgres_object_raw(&metadata)
            .map_err(|_| CanvasLifecycleSyncError::TextEncoding)?;
        let last_error = last_error
            .map(|text| {
                text.as_scalar()
                    .ok_or(CanvasLifecycleSyncError::TextEncoding)
            })
            .transpose()?;
        let rows = self
            .store
            .save(
                record,
                metadata,
                last_error,
                chrono::DateTime::parse_from_rfc3339(now).map_err(error)?,
            )
            .await?;
        if rows != 1 {
            return Err(error(
                "Canvas delivery record disappeared before synchronization could be persisted",
            )
            .into());
        }
        Ok(())
    }
}

fn flags(value: Option<&Value>) -> Map<String, Value> {
    value
        .and_then(Value::as_object)
        .map(|flags| {
            CANVAS_FEATURE_FLAGS
                .iter()
                .filter_map(|key| {
                    flags
                        .get(*key)
                        .map(|value| ((*key).into(), json!(python_truthy(value))))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn increment_attempts(value: Option<&Value>) -> Result<Value, CredentialManagementPortError> {
    // Python int conversion is lossless and does not impose a machine-sized
    // metadata counter. Reuse MMF's decimal grammar, then add one in decimal.
    let value = value.filter(|value| python_truthy(value));
    let lexical = match value {
        None => "0".into(),
        Some(Value::Bool(true)) => "1".into(),
        Some(Value::Number(number)) if number.to_string().contains(['.', 'e', 'E']) => format!(
            "{:.0}",
            number
                .as_f64()
                .ok_or_else(|| error("Invalid Canvas status attempt count"))?
                .trunc()
        ),
        Some(value) => {
            python_string(value).ok_or_else(|| error("Invalid Canvas status attempt count"))?
        }
    };
    let integer: mmf_config::numeric_config::PythonConfigInteger =
        lexical.parse().map_err(error)?;
    let mut bytes = integer
        .as_decimal()
        .trim_start_matches('-')
        .as_bytes()
        .to_vec();
    let negative = integer.as_decimal().starts_with('-');
    let mut carry = true;
    for digit in bytes.iter_mut().rev() {
        if !carry {
            break;
        }
        if negative {
            if *digit == b'0' {
                *digit = b'9';
            } else {
                *digit -= 1;
                carry = false;
            }
        } else if *digit == b'9' {
            *digit = b'0';
        } else {
            *digit += 1;
            carry = false;
        }
    }
    if carry && !negative {
        bytes.insert(0, b'1');
    }
    let digits = String::from_utf8(bytes).map_err(error)?;
    let magnitude = digits.trim_start_matches('0');
    let result = if magnitude.is_empty() {
        "0".into()
    } else if negative {
        format!("-{magnitude}")
    } else {
        magnitude.into()
    };
    serde_json::from_str(&result).map_err(error)
}

fn error(value: impl std::fmt::Display) -> CredentialManagementPortError {
    CredentialManagementPortError(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct MemoryStore {
        calls: Mutex<Vec<String>>,
        records: Mutex<Vec<OwnedJsonValue>>,
        binding: Mutex<Option<OwnedJsonValue>>,
        platform: Mutex<Option<OwnedJsonValue>>,
        saves: Mutex<Vec<Value>>,
        saved_rows: u64,
    }

    impl MemoryStore {
        fn new(metadata: Value) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                records: Mutex::new(vec![OwnedJsonValue::new(json!({
                    "id":"delivery-a", "organization_id":"org-a", "canvas_account_id":null,
                    "metadata":metadata
                }))]),
                binding: Mutex::new(Some(OwnedJsonValue::new(json!({
                    "id":"binding-a", "enabled":true, "platform_id":"platform-a",
                    "canvas_credentials":{}
                })))),
                platform: Mutex::new(Some(OwnedJsonValue::new(json!({
                    "id":"platform-a", "enabled":true, "canvas_account_id":"account-a"
                })))),
                saves: Mutex::new(Vec::new()),
                saved_rows: 1,
            }
        }
    }

    #[async_trait]
    impl CanvasLifecycleDeliveryStore for MemoryStore {
        async fn context(
            &self,
            credential: &ManagedCredential,
        ) -> Result<(String, Option<OwnedJsonValue>), CredentialManagementPortError> {
            assert_eq!(
                (&*credential.id, &*credential.organization_id),
                ("credential-a", "org-a")
            );
            self.calls.lock().unwrap().push("context".into());
            Ok(("transaction-a".into(), None))
        }

        async fn delivered(
            &self,
            credential: &ManagedCredential,
        ) -> Result<Vec<OwnedJsonValue>, CredentialManagementPortError> {
            assert_eq!(
                (&*credential.id, &*credential.organization_id),
                ("credential-a", "org-a")
            );
            self.calls.lock().unwrap().push("delivered".into());
            Ok(std::mem::take(&mut *self.records.lock().unwrap()))
        }

        async fn binding(
            &self,
            id: &str,
        ) -> Result<Option<OwnedJsonValue>, CredentialManagementPortError> {
            assert_eq!(id, "binding-a");
            self.calls.lock().unwrap().push("binding".into());
            Ok(self.binding.lock().unwrap().take())
        }

        async fn platform(
            &self,
            id: &str,
        ) -> Result<Option<OwnedJsonValue>, CredentialManagementPortError> {
            assert_eq!(id, "platform-a");
            self.calls.lock().unwrap().push("platform".into());
            Ok(self.platform.lock().unwrap().take())
        }

        async fn save(
            &self,
            record: &Value,
            metadata: Box<serde_json::value::RawValue>,
            last_error: Option<&str>,
            now: chrono::DateTime<chrono::FixedOffset>,
        ) -> Result<u64, CredentialManagementPortError> {
            assert_eq!(record["id"], "delivery-a");
            assert_eq!(record["organization_id"], "org-a");
            assert_eq!(now.offset().local_minus_utc(), 0);
            self.calls.lock().unwrap().push("save".into());
            self.saves.lock().unwrap().push(json!({
                "metadata":serde_json::from_str::<Value>(metadata.get()).unwrap(),
                "last_error":last_error,
                "canvas_account_id":record["canvas_account_id"]
            }));
            Ok(self.saved_rows)
        }
    }

    #[derive(Default)]
    struct MemoryProvider(Mutex<Vec<Value>>);

    #[async_trait]
    impl CanvasLifecycleStatusProvider for MemoryProvider {
        async fn synchronize(
            &self,
            context: CanvasLifecycleCredential<'_>,
            platform: &Value,
            delivery: &Value,
            action: CredentialLifecycleAction,
            reason: Option<&str>,
        ) -> Result<LosslessObject, CanvasLifecycleProviderError> {
            self.0.lock().unwrap().push(json!({
                "transaction_id":context.transaction_id,
                "platform_id":platform["id"],
                "account_id":delivery["canvas_account_id"],
                "action":action.as_str(),
                "reason":reason,
            }));
            Ok(crate::lossless_json::object(
                json!({"provider_result":"ok"}).as_object().unwrap().clone(),
            ))
        }
    }

    fn credential() -> ManagedCredential {
        use crate::credential_management::ManagedCredentialStatus;
        ManagedCredential {
            id: "credential-a".into(),
            transaction_id: "transaction-a".into(),
            organization_id: "org-a".into(),
            credential_template_id: "template-a".into(),
            issuer_did: None,
            status: ManagedCredentialStatus::Suspended,
            status_updated_at: chrono::Utc::now(),
            revoked: false,
            revoked_at: None,
            revocation_reason: None,
            revocation_profile_id: None,
            status_list_entries: vec![],
        }
    }

    #[tokio::test]
    async fn mock_store_checks_profile_gate_before_provider_or_target_lookup() {
        let store = Arc::new(MemoryStore::new(json!({
            "canvas_program_binding_id":"binding-a",
            "canvas_feature_flags":{"enable_canvas_mirror_ops":false}
        })));
        let provider = Arc::new(MemoryProvider::default());
        let synchronizer = CanvasLifecycleDeliverySynchronizer {
            store: store.clone(),
            provider: provider.clone(),
        };
        synchronizer
            .synchronize(&credential(), CredentialLifecycleAction::Suspend, None)
            .await
            .unwrap();
        assert_eq!(
            *store.calls.lock().unwrap(),
            ["context", "delivered", "save"]
        );
        assert!(provider.0.lock().unwrap().is_empty());
        let saved = store.saves.lock().unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0]["metadata"]["canvas_feature_gate_blocked"], true);
        assert_eq!(
            saved[0]["last_error"],
            "Canvas mirror operations are disabled by deployment profile"
        );
    }

    #[tokio::test]
    async fn mock_store_checks_target_provider_and_durable_success_order() {
        let store = Arc::new(MemoryStore::new(json!({
            "canvas_program_binding_id":"binding-a", "status_sync_attempts":4
        })));
        let provider = Arc::new(MemoryProvider::default());
        let synchronizer = CanvasLifecycleDeliverySynchronizer {
            store: store.clone(),
            provider: provider.clone(),
        };
        synchronizer
            .synchronize(
                &credential(),
                CredentialLifecycleAction::Reinstate,
                Some("reason"),
            )
            .await
            .unwrap();
        assert_eq!(
            *store.calls.lock().unwrap(),
            ["context", "delivered", "binding", "platform", "save"]
        );
        assert_eq!(
            provider.0.lock().unwrap()[0],
            json!({
                "transaction_id":"transaction-a", "platform_id":"platform-a",
                "account_id":"account-a", "action":"reinstate", "reason":"reason"
            })
        );
        let saved = store.saves.lock().unwrap();
        assert_eq!(saved[0]["metadata"]["status_sync_attempts"], 5);
        assert_eq!(saved[0]["metadata"]["provider_result"], "ok");
        assert_eq!(saved[0]["metadata"]["last_status_sync_error"], Value::Null);
        assert_eq!(saved[0]["last_error"], Value::Null);
        assert_eq!(saved[0]["canvas_account_id"], "account-a");
    }

    #[tokio::test]
    async fn mock_store_records_missing_binding_as_retry_without_provider_call() {
        let store = Arc::new(MemoryStore::new(json!({
            "canvas_program_binding_id":"binding-a"
        })));
        store.binding.lock().unwrap().take();
        let provider = Arc::new(MemoryProvider::default());
        let synchronizer = CanvasLifecycleDeliverySynchronizer {
            store: store.clone(),
            provider: provider.clone(),
        };
        synchronizer
            .synchronize(&credential(), CredentialLifecycleAction::Suspend, None)
            .await
            .unwrap();
        assert_eq!(
            *store.calls.lock().unwrap(),
            ["context", "delivered", "binding", "save"]
        );
        assert!(provider.0.lock().unwrap().is_empty());
        let saved = store.saves.lock().unwrap();
        assert_eq!(saved[0]["metadata"]["status_sync_attempts"], 1);
        assert_eq!(saved[0]["metadata"]["last_status_sync_action"], "suspend");
        assert_eq!(
            saved[0]["last_error"],
            "Canvas lifecycle sync skipped: Canvas program binding binding-a was not found"
        );
    }

    #[tokio::test]
    async fn mock_store_rejects_missing_durable_save_after_provider_success() {
        let mut store = MemoryStore::new(json!({
            "canvas_program_binding_id":"binding-a"
        }));
        store.saved_rows = 0;
        let store = Arc::new(store);
        let provider = Arc::new(MemoryProvider::default());
        let synchronizer = CanvasLifecycleDeliverySynchronizer {
            store: store.clone(),
            provider: provider.clone(),
        };
        let failure = synchronizer
            .synchronize(&credential(), CredentialLifecycleAction::Reinstate, None)
            .await
            .unwrap_err();
        assert_eq!(
            failure.to_string(),
            "Canvas delivery record disappeared before synchronization could be persisted"
        );
        assert_eq!(provider.0.lock().unwrap().len(), 1);
        assert_eq!(store.saves.lock().unwrap().len(), 1);
    }

    #[test]
    fn attempt_projection_preserves_signed_and_lossless_decimal_counters() {
        for (input, expected) in [
            (Value::Null, json!(1)),
            (json!(false), json!(1)),
            (json!(true), json!(2)),
            (json!(""), json!(1)),
            (json!([]), json!(1)),
            (json!({}), json!(1)),
            (json!(-1), json!(0)),
            (json!(-10), json!(-9)),
            (json!(9), json!(10)),
            (json!(2.9), json!(3)),
            (json!(-2.9), json!(-1)),
            (json!("  +００９  "), json!(10)),
            (
                json!("18446744073709551616"),
                serde_json::from_str("18446744073709551617").unwrap(),
            ),
        ] {
            assert_eq!(
                increment_attempts(Some(&input)).unwrap(),
                expected,
                "{input}"
            );
        }
        for input in [json!("2.5"), json!([1]), json!({"count":1})] {
            assert!(increment_attempts(Some(&input)).is_err());
        }
        assert_eq!(
            increment_attempts(Some(&json!("18446744073709551616")))
                .unwrap()
                .to_string(),
            "18446744073709551617"
        );
        assert_eq!(
            increment_attempts(Some(&json!("-18446744073709551616")))
                .unwrap()
                .to_string(),
            "-18446744073709551615"
        );
    }

    #[test]
    fn known_profile_flags_use_shared_names_and_python_truthiness() {
        assert!(flags(Some(&json!({"future_flag":true}))).is_empty());
        assert_eq!(
            flags(Some(
                &json!({"enable_canvas_mirror_ops":"false", "enable_canvas_evidence":0})
            )),
            json!({"enable_canvas_mirror_ops":true,"enable_canvas_evidence":false})
                .as_object()
                .unwrap()
                .clone()
        );
    }
}
