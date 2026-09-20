use async_trait::async_trait;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

use crate::credential_management::{
    CanvasLifecycleSyncError, CredentialLifecycleAction, CredentialManagementPortError,
    CredentialManagementRepository, ManagedCredential, ManagedCredentialStatus,
};

#[derive(Clone)]
pub struct PostgresCredentialManagementRepository {
    pool: PgPool,
    canvas_lifecycle: Option<crate::canvas_lifecycle_delivery::CanvasLifecycleDeliverySynchronizer>,
}

impl std::fmt::Debug for PostgresCredentialManagementRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresCredentialManagementRepository")
            .finish_non_exhaustive()
    }
}

impl PostgresCredentialManagementRepository {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            canvas_lifecycle: None,
        }
    }

    /// Candidate provider adoption is explicit until whole-consumer cutover.
    #[must_use]
    pub fn with_canvas_lifecycle(
        mut self,
        provider: std::sync::Arc<
            dyn crate::canvas_lifecycle_delivery::CanvasLifecycleStatusProvider,
        >,
    ) -> Self {
        self.canvas_lifecycle = Some(
            crate::canvas_lifecycle_delivery::CanvasLifecycleDeliverySynchronizer::new(
                self.pool.clone(),
                provider,
            ),
        );
        self
    }
}

#[async_trait]
impl CredentialManagementRepository for PostgresCredentialManagementRepository {
    async fn get(
        &self,
        credential_id: &str,
    ) -> Result<Option<ManagedCredential>, CredentialManagementPortError> {
        sqlx::query(
            "SELECT id, organization_id, credential_template_id, issuer_did, status,
                    status_updated_at, revoked, revoked_at, revocation_reason,
                    revocation_profile_id, status_list_entries
             FROM issuance_service.issued_credentials WHERE id = $1",
        )
        .bind(credential_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(port_error)?
        .map(|row| managed_credential(&row))
        .transpose()
    }

    async fn persist(
        &self,
        credential: &ManagedCredential,
        expected_status: ManagedCredentialStatus,
    ) -> Result<ManagedCredential, CredentialManagementPortError> {
        let row = sqlx::query(
            "UPDATE issuance_service.issued_credentials
             SET status = $1, status_updated_at = $2, revoked = $3,
                 revoked_at = $4, revocation_reason = $5
             WHERE id = $6 AND status = $7 AND organization_id = $8
             RETURNING id, organization_id, credential_template_id, issuer_did, status,
                       status_updated_at, revoked, revoked_at, revocation_reason,
                       revocation_profile_id, status_list_entries",
        )
        .bind(credential.status.as_str())
        .bind(credential.status_updated_at)
        .bind(credential.revoked)
        .bind(credential.revoked_at)
        .bind(&credential.revocation_reason)
        .bind(&credential.id)
        .bind(expected_status.as_str())
        .bind(&credential.organization_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(port_error)?
        .ok_or_else(|| {
            CredentialManagementPortError(
                "Credential status changed concurrently or credential no longer exists".to_owned(),
            )
        })?;
        managed_credential(&row)
    }

    async fn synchronize_canvas(
        &self,
        credential: &ManagedCredential,
        action: CredentialLifecycleAction,
        reason: Option<&str>,
    ) -> Result<(), CanvasLifecycleSyncError> {
        if let Some(lifecycle) = &self.canvas_lifecycle {
            return lifecycle.synchronize(credential, action, reason).await;
        }
        let request = json!({
            "status_sync_state": "pending",
            "last_status_sync_action": action.as_str(),
            "requested_credential_status": credential.status.as_str(),
            "requested_status_sync_reason": reason,
            "status_sync_requested_at": credential.status_updated_at.to_rfc3339(),
        });
        sqlx::query(
            "UPDATE issuance_service.credential_delivery_records
             SET metadata = COALESCE(metadata, '{}'::jsonb) || $1::jsonb,
                 updated_at = clock_timestamp()
             WHERE credential_id = $2 AND organization_id = $3
               AND delivery_target = 'canvas_credentials'",
        )
        .bind(request)
        .bind(&credential.id)
        .bind(&credential.organization_id)
        .execute(&self.pool)
        .await
        .map_err(port_error)?;
        Ok(())
    }
}

fn managed_credential(
    row: &sqlx::postgres::PgRow,
) -> Result<ManagedCredential, CredentialManagementPortError> {
    let status = match row
        .try_get::<String, _>("status")
        .map_err(port_error)?
        .as_str()
    {
        "active" => ManagedCredentialStatus::Active,
        "suspended" => ManagedCredentialStatus::Suspended,
        "revoked" => ManagedCredentialStatus::Revoked,
        value => {
            return Err(CredentialManagementPortError(format!(
                "Credential has unsupported status {value}"
            )))
        }
    };
    let entries = row
        .try_get::<Value, _>("status_list_entries")
        .map_err(port_error)?
        .as_array()
        .cloned()
        .ok_or_else(|| {
            CredentialManagementPortError("Credential has invalid status-list entries".to_owned())
        })?;
    Ok(ManagedCredential {
        id: row.try_get("id").map_err(port_error)?,
        organization_id: row.try_get("organization_id").map_err(port_error)?,
        credential_template_id: row.try_get("credential_template_id").map_err(port_error)?,
        issuer_did: row.try_get("issuer_did").map_err(port_error)?,
        status,
        status_updated_at: row.try_get("status_updated_at").map_err(port_error)?,
        revoked: row.try_get("revoked").map_err(port_error)?,
        revoked_at: row.try_get("revoked_at").map_err(port_error)?,
        revocation_reason: row.try_get("revocation_reason").map_err(port_error)?,
        revocation_profile_id: row.try_get("revocation_profile_id").map_err(port_error)?,
        status_list_entries: entries,
    })
}

fn port_error(error: impl std::fmt::Display) -> CredentialManagementPortError {
    CredentialManagementPortError(error.to_string())
}
