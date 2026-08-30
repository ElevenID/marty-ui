use std::time::Duration;

use async_trait::async_trait;
use chrono::{Duration as ChronoDuration, Utc};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::canvas_issuance_guard::{CanvasGuardConfig, PostgresCanvasIssuanceGuard};
use crate::credential::{
    AllocatedCredentialStatus, CredentialIssuanceError, CredentialLifecycle, CredentialTransaction,
    IssuedCredential, IssuerContext,
};
use crate::credential_management::{
    CredentialLifecycleAction, CredentialManagementPortError, CredentialStatusPublisher,
    ManagedCredential,
};

#[derive(Clone)]
pub struct HttpCredentialStatusAllocator {
    client: Client,
    base_url: Url,
    service_token: Option<String>,
}

impl std::fmt::Debug for HttpCredentialStatusAllocator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpCredentialStatusAllocator")
            .field("base_url", &self.base_url)
            .field("has_service_token", &self.service_token.is_some())
            .finish_non_exhaustive()
    }
}

impl HttpCredentialStatusAllocator {
    pub fn new(
        base_url: Url,
        service_token: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, CredentialIssuanceError> {
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| {
                lifecycle_error(format!("Unable to configure status allocator: {error}"))
            })?;
        Ok(Self {
            client,
            base_url,
            service_token: service_token.map(str::to_owned),
        })
    }

    pub async fn allocate(
        &self,
        transaction: &CredentialTransaction,
        credential_id: &str,
        credential_format: &str,
    ) -> Result<AllocatedCredentialStatus, CredentialIssuanceError> {
        let profile_id = transaction
            .revocation_profile_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or(CredentialIssuanceError::RevocationProfileRequired)?;
        let normalized_format = revocation_credential_format(credential_format);
        let mut request = self
            .client
            .post(self.endpoint(profile_id))
            .json(&ReserveIndexRequest {
                organization_id: &transaction.organization_id,
                credential_format: normalized_format,
                credential_id,
            });
        if let Some(token) = self.service_token.as_deref() {
            request = request.header("x-service-token", token);
        }
        let response = request.send().await.map_err(|error| {
            lifecycle_error(format!("Credential status allocation failed: {error}"))
        })?;
        let status = response.status();
        if !status.is_success() {
            return Err(lifecycle_error(format!(
                "Credential status allocation failed (HTTP {status})"
            )));
        }
        let response: ReserveIndexResponse = response.json().await.map_err(|error| {
            lifecycle_error(format!(
                "Credential status allocation returned invalid JSON: {error}"
            ))
        })?;
        if response.organization_id != transaction.organization_id {
            return Err(lifecycle_error(
                "Credential status allocation returned the wrong organization",
            ));
        }
        let status_list_url = response
            .status_list_url
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                lifecycle_error("Credential status allocation returned an incomplete response")
            })?;
        Ok(AllocatedCredentialStatus {
            revocation_profile_id: Some(profile_id.to_owned()),
            entries: vec![json!({
                "status_list_id": profile_id,
                "index": response.index,
                "status_list_uri": status_list_url,
                "status_list_credential": status_list_url,
                "type": if normalized_format == "mdoc" {
                    "TokenStatusListEntry"
                } else {
                    "BitstringStatusListEntry"
                },
                "status_purpose": "revocation",
            })],
        })
    }

    fn endpoint(&self, profile_id: &str) -> Url {
        let mut endpoint = self.base_url.clone();
        endpoint.set_path(&format!(
            "{}/internal/revocation-profiles/{profile_id}/reserve-index",
            self.base_url.path().trim_end_matches('/')
        ));
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        endpoint
    }

    async fn publish_lifecycle_status(
        &self,
        organization_id: &str,
        credential_id: &str,
        profile_id: &str,
        entries: &[Value],
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<(), CredentialIssuanceError> {
        let entry = entries
            .iter()
            .filter_map(Value::as_object)
            .find(|entry| {
                entry
                    .get("status_purpose")
                    .or_else(|| entry.get("statusPurpose"))
                    .and_then(Value::as_str)
                    .unwrap_or("revocation")
                    == "revocation"
            })
            .ok_or_else(|| lifecycle_error("Credential has no allocated status-list entry"))?;
        let entry_profile = entry
            .get("status_list_id")
            .or_else(|| entry.get("revocation_profile_id"))
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or_default();
        let index = entry
            .get("index")
            .and_then(Value::as_i64)
            .filter(|index| *index >= 0)
            .ok_or_else(|| {
                lifecycle_error("Credential has an invalid allocated status-list entry")
            })?;
        if entry_profile.is_empty() || entry_profile != profile_id {
            return Err(lifecycle_error(
                "Credential status-list entry does not match its revocation profile",
            ));
        }
        let credential_format = if entry
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("tokenstatuslist")
        {
            "mdoc"
        } else {
            "sd_jwt_vc"
        };
        let mut endpoint = self.base_url.clone();
        endpoint.set_path(&format!(
            "{}/internal/revocation-profiles/{profile_id}/process-revocation",
            self.base_url.path().trim_end_matches('/')
        ));
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        let mut request = self.client.post(endpoint).json(&json!({
            "organization_id": organization_id,
            "credential_id": credential_id,
            "index": index,
            "status": action.event_type(),
            "credential_format": credential_format,
            "reason": reason,
        }));
        if let Some(token) = self.service_token.as_deref() {
            request = request.header("x-service-token", token);
        }
        let response = request
            .send()
            .await
            .map_err(|error| lifecycle_error(format!("Credential revocation failed: {error}")))?;
        if !response.status().is_success() {
            return Err(lifecycle_error(format!(
                "Credential revocation failed (HTTP {})",
                response.status()
            )));
        }
        let response: ProcessRevocationResponse = response.json().await.map_err(|error| {
            lifecycle_error(format!(
                "Credential revocation returned invalid JSON: {error}"
            ))
        })?;
        if !response.success
            || response.organization_id != organization_id
            || response.index != index
            || response.status_list_url.trim().is_empty()
        {
            return Err(lifecycle_error(
                "Credential revocation service rejected the status change",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl CredentialStatusPublisher for HttpCredentialStatusAllocator {
    async fn publish(
        &self,
        credential: &ManagedCredential,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<(), CredentialManagementPortError> {
        let profile_id = credential
            .revocation_profile_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CredentialManagementPortError(
                    "Credential has no active credential-status profile binding".to_owned(),
                )
            })?;
        self.publish_lifecycle_status(
            &credential.organization_id,
            &credential.id,
            profile_id,
            &credential.status_list_entries,
            action,
            reason,
        )
        .await
        .map_err(|error| CredentialManagementPortError(error.to_string()))
    }
}

#[derive(Serialize)]
struct ReserveIndexRequest<'a> {
    organization_id: &'a str,
    credential_format: &'a str,
    credential_id: &'a str,
}

#[derive(Deserialize)]
struct ReserveIndexResponse {
    organization_id: String,
    index: i64,
    status_list_url: Option<String>,
}

#[derive(Deserialize)]
struct ProcessRevocationResponse {
    success: bool,
    organization_id: String,
    index: i64,
    status_list_url: String,
}

#[derive(Clone, Debug)]
pub struct PostgresCredentialLifecycle {
    pool: PgPool,
    canvas_guard: PostgresCanvasIssuanceGuard,
    status: HttpCredentialStatusAllocator,
}

impl PostgresCredentialLifecycle {
    pub fn new(
        pool: PgPool,
        revocation_base_url: Url,
        service_token: Option<&str>,
        timeout: Duration,
        canvas_config: CanvasGuardConfig,
    ) -> Result<Self, CredentialIssuanceError> {
        let canvas_guard = PostgresCanvasIssuanceGuard::new(pool.clone(), canvas_config);
        Ok(Self {
            pool,
            canvas_guard,
            status: HttpCredentialStatusAllocator::new(
                revocation_base_url,
                service_token,
                timeout,
            )?,
        })
    }

    async fn record_canvas_drift(
        &self,
        transaction: &CredentialTransaction,
        credential_id: &str,
    ) -> Result<(), CredentialIssuanceError> {
        let Some(application_id) = transaction.application_id.as_deref() else {
            return Ok(());
        };
        let row = sqlx::query(
            "SELECT app.organization_id, app.integration_context,
                    binding.id AS binding_id, binding.platform_id,
                    binding.config_version
             FROM issuance_service.applications AS app
             JOIN issuance_service.canvas_program_bindings AS binding
               ON binding.organization_id = app.organization_id
              AND binding.id = app.integration_context->'canvas'->>'canvas_program_binding_id'
             JOIN issuance_service.canvas_platforms AS platform
               ON platform.organization_id = app.organization_id
              AND platform.id = app.integration_context->'canvas'->>'canvas_platform_id'
              AND binding.platform_id = platform.id
             WHERE app.id = $1 AND app.organization_id = $2",
        )
        .bind(application_id)
        .bind(&transaction.organization_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?;
        let Some(row) = row else {
            return Ok(());
        };
        let organization_id: String = row.try_get("organization_id").map_err(database_error)?;
        let binding_id: String = row.try_get("binding_id").map_err(database_error)?;
        let platform_id: String = row.try_get("platform_id").map_err(database_error)?;
        let config_version: i32 = row.try_get("config_version").map_err(database_error)?;
        let now = Utc::now();
        let metadata = json!({
            "drift_until": (now + ChronoDuration::days(90)).to_rfc3339(),
            "claimed_credential_id": credential_id,
        });
        let logical_key = format!("application:{application_id}");
        sqlx::query(
            "INSERT INTO issuance_service.canvas_evidence_sync_targets
                 (id, organization_id, platform_id, binding_id, target_type,
                  logical_key, application_id, enabled, schedule_seconds,
                  next_run_at, config_version, metadata, created_at, updated_at)
             VALUES ($1, $2, $3, $4, 'issued_drift', $5, $6, true, 21600,
                     $7, $8, $9, $10, $10)
             ON CONFLICT (organization_id, logical_key) DO UPDATE SET
                 platform_id = EXCLUDED.platform_id,
                 binding_id = EXCLUDED.binding_id,
                 target_type = 'issued_drift',
                 application_id = EXCLUDED.application_id,
                 enabled = true,
                 schedule_seconds = 21600,
                 next_run_at = EXCLUDED.next_run_at,
                 config_version = EXCLUDED.config_version,
                 metadata = (
                     COALESCE(canvas_evidence_sync_targets.metadata, '{}'::json)::jsonb
                     || EXCLUDED.metadata::jsonb
                 )::json,
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(organization_id)
        .bind(platform_id)
        .bind(binding_id)
        .bind(logical_key)
        .bind(application_id)
        .bind(now + ChronoDuration::hours(6))
        .bind(config_version)
        .bind(metadata)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        Ok(())
    }

    async fn finalize_renewal(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
    ) -> Result<(), CredentialIssuanceError> {
        let Some(source_id) = transaction
            .renewal_of_credential_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return Ok(());
        };
        let source = sqlx::query(
            "SELECT organization_id, status, revocation_profile_id, status_list_entries
             FROM issuance_service.issued_credentials WHERE id = $1",
        )
        .bind(source_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?
        .ok_or_else(|| lifecycle_error("Renewal source credential no longer exists"))?;
        let source_organization: String =
            source.try_get("organization_id").map_err(database_error)?;
        if source_organization != credential.organization_id {
            return Err(lifecycle_error("Renewal source organization mismatch"));
        }
        let status: String = source.try_get("status").map_err(database_error)?;
        if status != "active" {
            return Err(lifecycle_error(
                "Only an active credential can complete renewal",
            ));
        }
        let profile_id: Option<String> = source
            .try_get("revocation_profile_id")
            .map_err(database_error)?;
        let profile_id = profile_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                lifecycle_error("Credential has no active credential-status profile binding")
            })?;
        let entries: Value = source
            .try_get("status_list_entries")
            .map_err(database_error)?;
        let entries = entries.as_array().ok_or_else(|| {
            lifecycle_error("Credential has an invalid allocated status-list entry")
        })?;
        const REASON: &str = "Superseded by renewed credential";
        self.status
            .publish_lifecycle_status(
                &source_organization,
                source_id,
                profile_id,
                entries,
                CredentialLifecycleAction::Revoke,
                Some(REASON),
            )
            .await?;

        let mut database = self.pool.begin().await.map_err(database_error)?;
        let updated = sqlx::query(
            "UPDATE issuance_service.issued_credentials
             SET status = 'revoked', status_updated_at = clock_timestamp(),
                 revoked = true, revoked_at = clock_timestamp(),
                 revocation_reason = $1, renewed_to_credential_id = $2
             WHERE id = $3 AND organization_id = $4 AND status = 'active'",
        )
        .bind(REASON)
        .bind(&credential.id)
        .bind(source_id)
        .bind(&credential.organization_id)
        .execute(&mut *database)
        .await
        .map_err(database_error)?;
        if updated.rows_affected() != 1 {
            return Err(lifecycle_error(
                "Only an active credential can complete renewal",
            ));
        }
        sqlx::query(
            "UPDATE issuance_service.issued_credentials
             SET renewed_from_credential_id = $1 WHERE id = $2 AND organization_id = $3",
        )
        .bind(source_id)
        .bind(&credential.id)
        .bind(&credential.organization_id)
        .execute(&mut *database)
        .await
        .map_err(database_error)?;
        database.commit().await.map_err(database_error)?;
        Ok(())
    }

    async fn record_event_and_deliveries(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
        response_format: &str,
    ) -> Result<(), CredentialIssuanceError> {
        sqlx::query(
            "INSERT INTO issuance_service.issuance_events
                 (id, transaction_id, application_id, event_type, metadata, created_at)
             VALUES ($1, $2, $3, 'credential_issued', $4, clock_timestamp())",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&transaction.id)
        .bind(&transaction.application_id)
        .bind(json!({
            "credential_id": credential.id,
            "credential_type": transaction.credential_type,
        }))
        .execute(&self.pool)
        .await
        .map_err(database_error)?;

        let wallet_id = delivery_record_id(&credential.id, "wallet", None);
        self.upsert_delivery(
            &wallet_id,
            transaction,
            credential,
            "wallet",
            "delivered",
            None,
            None,
            json!({"protocol":"oid4vci","requested_format":response_format}),
        )
        .await?;
        if transaction.delivery_mode == "wallet_plus_canvas_mirror" {
            self.record_canvas_delivery(transaction, credential).await?;
        }
        Ok(())
    }

    async fn record_didcomm_event_and_deliveries(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
        service_endpoint: &str,
        message_id: &str,
    ) -> Result<(), CredentialIssuanceError> {
        sqlx::query(
            "INSERT INTO issuance_service.issuance_events
                 (id, transaction_id, application_id, event_type, metadata, created_at)
             VALUES ($1, $2, $3, 'credential_issued', $4, clock_timestamp())",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&transaction.id)
        .bind(&transaction.application_id)
        .bind(json!({
            "credential_id": credential.id,
            "credential_type": transaction.credential_type,
            "delivery_protocol": "didcomm_v2",
            "service_endpoint": service_endpoint,
        }))
        .execute(&self.pool)
        .await
        .map_err(database_error)?;

        let delivery_id = delivery_record_id(&credential.id, "didcomm_v2", None);
        self.upsert_delivery(
            &delivery_id,
            transaction,
            credential,
            "didcomm_v2",
            "delivered",
            None,
            None,
            json!({
                "protocol": "didcomm_v2",
                "service_endpoint": service_endpoint,
                "didcomm_message_id": message_id,
            }),
        )
        .await?;
        if transaction.delivery_mode == "wallet_plus_canvas_mirror" {
            self.record_canvas_delivery(transaction, credential).await?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn upsert_delivery(
        &self,
        id: &str,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
        target: &str,
        status: &str,
        canvas_account_id: Option<&str>,
        last_error: Option<&str>,
        metadata: Value,
    ) -> Result<(), CredentialIssuanceError> {
        sqlx::query(
            "INSERT INTO issuance_service.credential_delivery_records
                 (id, credential_id, transaction_id, organization_id, delivery_target,
                  delivery_mode, status, canvas_account_id, last_error, metadata,
                  created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                     clock_timestamp(), clock_timestamp())
             ON CONFLICT (id) DO UPDATE SET
                 credential_id = EXCLUDED.credential_id,
                 transaction_id = EXCLUDED.transaction_id,
                 organization_id = EXCLUDED.organization_id,
                 delivery_target = EXCLUDED.delivery_target,
                 delivery_mode = EXCLUDED.delivery_mode,
                 status = EXCLUDED.status,
                 canvas_account_id = EXCLUDED.canvas_account_id,
                 last_error = EXCLUDED.last_error,
                 metadata = EXCLUDED.metadata,
                 updated_at = clock_timestamp()",
        )
        .bind(id)
        .bind(&credential.id)
        .bind(&transaction.id)
        .bind(&credential.organization_id)
        .bind(target)
        .bind(&transaction.delivery_mode)
        .bind(status)
        .bind(canvas_account_id)
        .bind(last_error)
        .bind(metadata)
        .execute(&self.pool)
        .await
        .map_err(database_error)?;
        Ok(())
    }

    async fn record_canvas_delivery(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
    ) -> Result<(), CredentialIssuanceError> {
        let application = if let Some(application_id) = transaction.application_id.as_deref() {
            sqlx::query_scalar::<_, Value>(
                "SELECT integration_context FROM issuance_service.applications
                 WHERE id = $1 AND organization_id = $2",
            )
            .bind(application_id)
            .bind(&transaction.organization_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(database_error)?
        } else {
            None
        };
        let canvas = application
            .as_ref()
            .and_then(|value| value.get("canvas"))
            .and_then(Value::as_object);
        let binding_id = canvas
            .and_then(|value| value.get("canvas_program_binding_id"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let mut metadata = canvas_delivery_metadata(canvas);
        let flags = metadata
            .get("canvas_feature_flags")
            .and_then(Value::as_object);
        let publish_enabled = flags.is_none_or(Map::is_empty)
            || flags.and_then(|flags| flags.get("enable_canvas_mirror_publish"))
                == Some(&Value::Bool(true));
        let (enabled, canvas_account_id, error) = if !publish_enabled {
            (
                false,
                None,
                Some("Canvas mirror publish is disabled by deployment profile".to_owned()),
            )
        } else if let Some(binding_id) = binding_id {
            let row = sqlx::query(
                "SELECT binding.id, binding.enabled AS binding_enabled,
                        binding.canvas_credentials,
                        binding.platform_id AS binding_platform_id,
                        platform.id AS platform_id,
                        platform.enabled AS platform_enabled, platform.canvas_account_id
                 FROM issuance_service.canvas_program_bindings AS binding
                 LEFT JOIN issuance_service.canvas_platforms AS platform
                   ON platform.id = binding.platform_id
                  AND platform.organization_id = binding.organization_id
                 WHERE binding.id = $1 AND binding.organization_id = $2",
            )
            .bind(binding_id)
            .bind(&transaction.organization_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(database_error)?;
            match row {
                None => (
                    false,
                    None,
                    Some(format!("Canvas program binding {binding_id} was not found")),
                ),
                Some(row) if !row.try_get::<bool, _>("binding_enabled").unwrap_or(false) => (
                    false,
                    None,
                    Some(format!("Canvas program binding {binding_id} is disabled")),
                ),
                Some(row) => {
                    let binding_platform_id: String =
                        row.try_get("binding_platform_id").map_err(database_error)?;
                    let platform_id = row
                        .try_get::<Option<String>, _>("platform_id")
                        .map_err(database_error)?;
                    let account = row
                        .try_get::<Option<String>, _>("canvas_account_id")
                        .map_err(database_error)?;
                    if platform_id.is_none() {
                        (
                            false,
                            None,
                            Some(format!(
                                "Canvas platform {binding_platform_id} was not found"
                            )),
                        )
                    } else if !row.try_get::<bool, _>("platform_enabled").unwrap_or(false) {
                        (
                            false,
                            account,
                            Some(format!(
                                "Canvas platform {} is disabled",
                                platform_id.as_deref().unwrap_or_default()
                            )),
                        )
                    } else {
                        metadata["canvas_platform_id"] =
                            Value::String(platform_id.unwrap_or_default());
                        metadata["canvas_program_binding_id"] =
                            Value::String(binding_id.to_owned());
                        let credentials: Value =
                            row.try_get("canvas_credentials").map_err(database_error)?;
                        if credentials
                            .as_object()
                            .is_some_and(|value| !value.is_empty())
                        {
                            metadata["canvas_credentials"] = credentials;
                        }
                        (true, account, None)
                    }
                }
            }
        } else {
            (
                false,
                None,
                Some(
                    "Canvas mirroring requested but no canvas_program_binding_id was provided"
                        .to_owned(),
                ),
            )
        };
        metadata["application_id"] = transaction
            .application_id
            .as_ref()
            .map_or(Value::Null, |value| Value::String(value.clone()));
        metadata["source_delivery_target"] = Value::String("wallet".to_owned());
        metadata["queue"] = Value::String("canvas_credentials_mirror".to_owned());
        metadata["delivery_destination_id"] =
            Value::String("dd-canvas-credentials-institutional".to_owned());
        metadata["delivery_destination_mode"] = Value::String("organization_mirror".to_owned());
        metadata["delivery_destination_provider"] = Value::String("canvas_credentials".to_owned());
        if !publish_enabled {
            metadata["canvas_feature_gate_blocked"] = Value::Bool(true);
            metadata["canvas_feature_gate"] =
                Value::String("enable_canvas_mirror_publish".to_owned());
            metadata["retryable"] = Value::Bool(false);
        }
        let id = delivery_record_id(&credential.id, "canvas_credentials", binding_id);
        self.upsert_delivery(
            &id,
            transaction,
            credential,
            "canvas_credentials",
            if enabled { "pending" } else { "failed" },
            canvas_account_id.as_deref(),
            error.as_deref(),
            metadata,
        )
        .await
    }
}

#[async_trait]
impl CredentialLifecycle for PostgresCredentialLifecycle {
    async fn ensure_ready(
        &self,
        transaction: &CredentialTransaction,
        issuer: &IssuerContext,
    ) -> Result<(), CredentialIssuanceError> {
        self.canvas_guard
            .ensure_ready(transaction, issuer)
            .await
            .map(|_| ())
    }

    async fn allocate_status(
        &self,
        transaction: &CredentialTransaction,
        credential_id: &str,
        credential_format: &str,
    ) -> Result<AllocatedCredentialStatus, CredentialIssuanceError> {
        self.status
            .allocate(transaction, credential_id, credential_format)
            .await
    }

    async fn after_issued(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
        response_format: &str,
    ) -> Result<(), CredentialIssuanceError> {
        self.record_canvas_drift(transaction, &credential.id)
            .await?;
        self.finalize_renewal(transaction, credential).await?;
        self.record_event_and_deliveries(transaction, credential, response_format)
            .await
    }

    async fn after_didcomm_issued(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
        service_endpoint: &str,
        message_id: &str,
    ) -> Result<(), CredentialIssuanceError> {
        self.record_canvas_drift(transaction, &credential.id)
            .await?;
        self.finalize_renewal(transaction, credential).await?;
        self.record_didcomm_event_and_deliveries(
            transaction,
            credential,
            service_endpoint,
            message_id,
        )
        .await
    }
}

fn canvas_delivery_metadata(canvas: Option<&Map<String, Value>>) -> Value {
    let mut metadata = Map::new();
    let Some(canvas) = canvas else {
        return Value::Object(metadata);
    };
    for (source, target) in [
        ("canvas_platform_id", "canvas_platform_id"),
        ("canvas_program_binding_id", "canvas_program_binding_id"),
        ("deployment_profile_id", "deployment_profile_id"),
        ("delivery_mode", "canvas_binding_delivery_mode"),
    ] {
        if let Some(value) = canvas
            .get(source)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            metadata.insert(target.to_owned(), Value::String(value.to_owned()));
        }
    }
    if let Some(flags) = canvas.get("feature_flags").and_then(Value::as_object) {
        let allowed = [
            "enable_canvas_evidence",
            "enable_canvas_lti",
            "enable_canvas_mirror_publish",
            "enable_canvas_mirror_ops",
            "enable_canvas_deep_linking",
            "enable_canvas_ags",
            "enable_canvas_nrps",
            "enable_background_awards",
        ];
        let normalized = flags
            .iter()
            .filter(|(key, _)| allowed.contains(&key.as_str()))
            .map(|(key, value)| (key.clone(), Value::Bool(value.as_bool().unwrap_or(false))))
            .collect::<Map<_, _>>();
        if !normalized.is_empty() {
            metadata.insert("canvas_feature_flags".to_owned(), Value::Object(normalized));
        }
    }
    Value::Object(metadata)
}

fn delivery_record_id(credential_id: &str, target: &str, scope_id: Option<&str>) -> String {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("{credential_id}:{target}:{}", scope_id.unwrap_or("-")).as_bytes(),
    )
    .to_string()
}

fn database_error(error: impl std::fmt::Display) -> CredentialIssuanceError {
    lifecycle_error(format!(
        "Credential lifecycle database unavailable: {error}"
    ))
}

fn revocation_credential_format(format: &str) -> &'static str {
    match format {
        "mso_mdoc" | "mdoc" => "mdoc",
        "ldp_vc" | "json_ld" | "w3c_vcdm_v2_di" => "json_ld",
        _ => "sd_jwt_vc",
    }
}

fn lifecycle_error(message: impl Into<String>) -> CredentialIssuanceError {
    CredentialIssuanceError::LifecycleUnavailable(message.into())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use axum::{
        extract::{Path, State},
        http::HeaderMap,
        routing::post,
        Json, Router,
    };
    use serde_json::{json, Map, Value};
    use tokio::sync::Mutex;

    use super::*;
    use crate::credential::{CredentialTransaction, CredentialTransactionStatus};

    type CapturedRequest = (String, HeaderMap, Value);

    #[derive(Clone, Debug, Default)]
    struct Capture(Arc<Mutex<Option<CapturedRequest>>>);

    async fn reserve(
        State(capture): State<Capture>,
        Path(profile_id): Path<String>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        *capture.0.lock().await = Some((profile_id, headers, body.clone()));
        Json(json!({
            "organization_id": body["organization_id"],
            "index": 42,
            "status_list_url": "https://status.example/lists/active",
        }))
    }

    async fn revoke(
        State(capture): State<Capture>,
        Path(profile_id): Path<String>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        *capture.0.lock().await = Some((profile_id, headers, body.clone()));
        Json(json!({
            "success": true,
            "organization_id": body["organization_id"],
            "index": body["index"],
            "status_list_url": "https://status.example/lists/active",
        }))
    }

    fn transaction() -> CredentialTransaction {
        CredentialTransaction {
            id: "tx-a".to_owned(),
            organization_id: "org-a".to_owned(),
            credential_template_id: "template-a".to_owned(),
            revocation_profile_id: Some("profile-a".to_owned()),
            renewal_of_credential_id: None,
            applicant_id: None,
            application_id: None,
            subject_did: None,
            idempotency_key_hash: None,
            idempotency_request_hash: None,
            status: CredentialTransactionStatus::Signing,
            pre_authorized_code: "pre-auth".to_owned(),
            nonce: None,
            claims: Map::new(),
            credential_type: Some("AccessBadge".to_owned()),
            selective_disclosure_claims: Vec::new(),
            zk_predicate_claims: Vec::new(),
            credential_payload_format: "dc+sd-jwt".to_owned(),
            wallet_configs: Vec::new(),
            validity_days: 365,
            renewable: false,
            renewal_window_days: 30,
            delivery_mode: "wallet_only".to_owned(),
            issuer_profile_id: Some("profile".to_owned()),
            issuer_mode: "org_managed".to_owned(),
            issuer_did: Some("did:web:issuer.example".to_owned()),
            issuer_algorithm: Some("ES256".to_owned()),
            signing_service_id: Some("service".to_owned()),
            reserved_credential_id: None,
            oid4vci_client_id: None,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(7),
        }
    }

    async fn allocator() -> (
        HttpCredentialStatusAllocator,
        Capture,
        tokio::task::JoinHandle<()>,
    ) {
        let capture = Capture::default();
        let app = Router::new()
            .route(
                "/revocation/internal/revocation-profiles/{profile_id}/reserve-index",
                post(reserve),
            )
            .route(
                "/revocation/internal/revocation-profiles/{profile_id}/process-revocation",
                post(revoke),
            )
            .with_state(capture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("test server");
        });
        let allocator = HttpCredentialStatusAllocator::new(
            Url::parse(&format!("http://{address}/revocation")).expect("URL"),
            Some("service-token"),
            Duration::from_secs(2),
        )
        .expect("allocator");
        (allocator, capture, server)
    }

    #[tokio::test]
    async fn allocation_preserves_tenant_identity_and_mdoc_semantics() {
        let (allocator, capture, server) = allocator().await;

        let allocated = allocator
            .allocate(&transaction(), "credential-a", "mso_mdoc")
            .await
            .expect("allocation");

        assert_eq!(
            allocated.revocation_profile_id.as_deref(),
            Some("profile-a")
        );
        assert_eq!(allocated.entries[0]["type"], "TokenStatusListEntry");
        assert_eq!(allocated.entries[0]["index"], 42);
        let (profile, headers, body) = capture.0.lock().await.take().expect("captured request");
        assert_eq!(profile, "profile-a");
        assert_eq!(
            headers.get("x-service-token").expect("service token"),
            "service-token"
        );
        assert_eq!(body["organization_id"], "org-a");
        assert_eq!(body["credential_format"], "mdoc");
        assert_eq!(body["credential_id"], "credential-a");
        server.abort();
    }

    #[tokio::test]
    async fn missing_profile_fails_before_network_access() {
        let (allocator, _capture, server) = allocator().await;
        let mut transaction = transaction();
        transaction.revocation_profile_id = Some(" ".to_owned());

        let error = allocator
            .allocate(&transaction, "credential-a", "dc+sd-jwt")
            .await
            .expect_err("profile is required");

        assert_eq!(error, CredentialIssuanceError::RevocationProfileRequired);
        server.abort();
    }

    #[test]
    fn signing_formats_map_to_the_legacy_revocation_contract() {
        let expected = HashMap::from([
            ("mso_mdoc", "mdoc"),
            ("mdoc", "mdoc"),
            ("ldp_vc", "json_ld"),
            ("json_ld", "json_ld"),
            ("dc+sd-jwt", "sd_jwt_vc"),
            ("jwt_vc_json", "sd_jwt_vc"),
        ]);
        for (format, normalized) in expected {
            assert_eq!(revocation_credential_format(format), normalized);
        }
    }

    #[tokio::test]
    async fn renewal_revocation_preserves_the_bound_status_entry_contract() {
        let (allocator, capture, server) = allocator().await;
        let entries = vec![json!({
            "status_list_id":"profile-a",
            "index":19,
            "type":"TokenStatusListEntry",
            "status_purpose":"revocation"
        })];

        allocator
            .publish_lifecycle_status(
                "org-a",
                "credential-old",
                "profile-a",
                &entries,
                CredentialLifecycleAction::Revoke,
                Some("Superseded by renewed credential"),
            )
            .await
            .expect("revocation");

        let (profile, headers, body) = capture.0.lock().await.take().expect("captured request");
        assert_eq!(profile, "profile-a");
        assert_eq!(headers["x-service-token"], "service-token");
        assert_eq!(body["organization_id"], "org-a");
        assert_eq!(body["credential_id"], "credential-old");
        assert_eq!(body["index"], 19);
        assert_eq!(body["status"], "revoked");
        assert_eq!(body["credential_format"], "mdoc");
        assert_eq!(body["reason"], "Superseded by renewed credential");
        server.abort();
    }

    #[tokio::test]
    async fn renewal_revocation_rejects_a_status_entry_from_another_profile() {
        let (allocator, capture, server) = allocator().await;
        let error = allocator
            .publish_lifecycle_status(
                "org-a",
                "credential-old",
                "profile-a",
                &[json!({"status_list_id":"profile-b","index":19})],
                CredentialLifecycleAction::Revoke,
                Some("Superseded by renewed credential"),
            )
            .await
            .expect_err("profile mismatch");

        assert!(matches!(
            error,
            CredentialIssuanceError::LifecycleUnavailable(_)
        ));
        assert!(capture.0.lock().await.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn management_publication_preserves_actions_and_nullable_reasons() {
        let (allocator, capture, server) = allocator().await;
        let credential = ManagedCredential {
            id: "credential-a".to_owned(),
            organization_id: "org-a".to_owned(),
            credential_template_id: "template-a".to_owned(),
            issuer_did: Some("did:web:issuer.example".to_owned()),
            status: crate::credential_management::ManagedCredentialStatus::Active,
            status_updated_at: Utc::now(),
            revoked: false,
            revoked_at: None,
            revocation_reason: None,
            revocation_profile_id: Some("profile-a".to_owned()),
            status_list_entries: vec![json!({
                "status_list_id": "profile-a",
                "index": 19,
                "type": "BitstringStatusListEntry",
                "status_purpose": "revocation"
            })],
        };

        for (action, expected_status, reason) in [
            (
                CredentialLifecycleAction::Revoke,
                "revoked",
                Some("retired"),
            ),
            (CredentialLifecycleAction::Suspend, "suspended", None),
            (
                CredentialLifecycleAction::Reinstate,
                "reinstated",
                Some("restored"),
            ),
        ] {
            CredentialStatusPublisher::publish(&allocator, &credential, action, reason)
                .await
                .expect("publication");
            let (_, _, body) = capture.0.lock().await.take().expect("captured request");
            assert_eq!(body["status"], expected_status);
            assert_eq!(
                body["reason"],
                reason.map_or(Value::Null, |value| json!(value))
            );
        }
        server.abort();
    }
}
