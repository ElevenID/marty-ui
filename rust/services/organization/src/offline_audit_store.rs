//! Atomic offline-event receipts in the existing Organization audit store.

use chrono::Utc;
use serde_json::json;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    authorize_forwarded_principal,
    offline_audit::{
        OfflineAuditAcknowledgement, OfflineAuditError, OfflineAuditReceipt, ValidatedOfflineEvent,
        CONTRACT, EVENT_TYPE, PERMISSION, RECEIPT_KIND, SCOPE,
    },
    AuditEvent, ForwardedPrincipal, OrganizationApplication,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OfflineAuditAuthority {
    pub organization_id: Uuid,
    pub producer_id: Uuid,
}

impl OfflineAuditAuthority {
    pub fn from_principal(
        organization_id: Uuid,
        principal: &ForwardedPrincipal,
    ) -> Result<Self, OfflineAuditError> {
        authorize_forwarded_principal(organization_id, principal, PERMISSION, false, None)
            .map_err(|_| OfflineAuditError::Forbidden)?;
        let ForwardedPrincipal::ApiKey { api_key_id, .. } = principal else {
            return Err(OfflineAuditError::Forbidden);
        };
        let producer_id = api_key_id
            .parse()
            .map_err(|_| OfflineAuditError::Forbidden)?;
        Ok(Self {
            organization_id,
            producer_id,
        })
    }

    fn actor_id(self) -> String {
        format!("api_key:{}", self.producer_id)
    }
}

impl OrganizationApplication {
    /// Keep the key lock until commit/read completion so concurrent revocation
    /// cannot authorize a receipt using a stale gateway identity snapshot.
    pub(crate) async fn offline_audit_transaction(
        &self,
        authority: OfflineAuditAuthority,
    ) -> Result<Transaction<'_, Postgres>, OfflineAuditError> {
        let mut transaction = self.store.begin_transaction().await.map_err(persistence)?;
        let key = self
            .store
            .api_key_by_id_for_update_in_transaction(&mut transaction, authority.producer_id)
            .await
            .map_err(persistence)?
            .ok_or(OfflineAuditError::Forbidden)?;
        if key.organization_id != authority.organization_id
            || !key.is_valid_at(Utc::now())
            || !key.scopes.iter().any(|scope| scope == SCOPE)
            // A profile-restricted key must not be widened to organization-wide
            // reporting when the native event carries no authenticated profile.
            || key.scope_type != "ORGANIZATION"
            || key.deployment_profile_id.is_some()
        {
            return Err(OfflineAuditError::Forbidden);
        }
        Ok(transaction)
    }

    pub(crate) async fn ingest_offline_audit(
        &self,
        authority: OfflineAuditAuthority,
        events: Vec<ValidatedOfflineEvent>,
    ) -> Result<OfflineAuditAcknowledgement, OfflineAuditError> {
        let mut transaction = self.offline_audit_transaction(authority).await?;
        let mut receipts = Vec::with_capacity(events.len());
        let mut accepted = 0;
        for event in events {
            let receipt = OfflineAuditReceipt {
                kind: RECEIPT_KIND.into(),
                audit_event_id: Uuid::new_v4(),
                organization_id: authority.organization_id,
                producer_id: authority.producer_id,
                event_id: event.event.event_id,
                verification_id: event.event.payload.verification_id,
                payload_sha256: event.payload_sha256.clone(),
                received_at: Utc::now(),
                event: event.event.clone(),
            };
            let audit = AuditEvent {
                id: receipt.audit_event_id,
                organization_id: authority.organization_id,
                event_type: EVENT_TYPE.into(),
                action: "ingest".into(),
                category: "verification".into(),
                resource_type: "offline-verification".into(),
                resource_id: Some(receipt.verification_id.to_string()),
                resource_name: None,
                actor_id: Some(authority.actor_id()),
                actor_type: "api_key".into(),
                severity: "info".into(),
                message: "Authenticated offline verification report received".into(),
                changes: None,
                metadata: json!({"offline_receipt": receipt}),
                timestamp: receipt.received_at,
            };
            // Partial unique indexes cover only this event type. The existing
            // append-only audit writer is shared with other organization events.
            let existing = load_conflicting_receipt(&mut transaction, authority, &event).await?;
            if let Some(existing) = existing {
                if !existing.matches(&event) {
                    return Err(OfflineAuditError::Conflict);
                }
                receipts.push(existing);
                continue;
            }
            self.store
                .save_audit_event_in_transaction(&mut transaction, &audit)
                .await
                .map_err(insertion_error)?;
            let stored = sqlx::query("SELECT id,metadata FROM organization_service.audit_events WHERE id=$1 AND organization_id=$2 AND actor_id=$3 AND event_type=$4")
                .bind(receipt.audit_event_id).bind(authority.organization_id).bind(authority.actor_id()).bind(EVENT_TYPE)
                .fetch_optional(&mut *transaction).await.map_err(persistence)?.ok_or(OfflineAuditError::Persistence)?;
            if receipt_from_row(&stored, authority)? != receipt {
                return Err(OfflineAuditError::Persistence);
            }
            accepted += 1;
            receipts.push(receipt);
        }
        // No acknowledgement leaves this method until every event is durable.
        transaction.commit().await.map_err(persistence)?;
        Ok(OfflineAuditAcknowledgement {
            kind: CONTRACT,
            accepted,
            duplicates: receipts.len() - accepted,
            receipts,
        })
    }

    pub(crate) async fn offline_audit_receipt(
        &self,
        authority: OfflineAuditAuthority,
        verification_id: Uuid,
    ) -> Result<OfflineAuditReceipt, OfflineAuditError> {
        let mut transaction = self.offline_audit_transaction(authority).await?;
        let row = sqlx::query(
            "SELECT id,metadata FROM organization_service.audit_events
             WHERE organization_id=$1 AND actor_id=$2 AND event_type=$3 AND resource_id=$4",
        )
        .bind(authority.organization_id)
        .bind(authority.actor_id())
        .bind(EVENT_TYPE)
        .bind(verification_id.to_string())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(persistence)?
        .ok_or(OfflineAuditError::NotFound)?;
        let receipt = receipt_from_row(&row, authority)?;
        if receipt.verification_id != verification_id {
            return Err(OfflineAuditError::Persistence);
        }
        transaction.commit().await.map_err(persistence)?;
        Ok(receipt)
    }
}

async fn load_conflicting_receipt(
    transaction: &mut Transaction<'_, Postgres>,
    authority: OfflineAuditAuthority,
    event: &ValidatedOfflineEvent,
) -> Result<Option<OfflineAuditReceipt>, OfflineAuditError> {
    // The locked producer key serializes concurrent/reordered batches from that
    // producer; database uniqueness independently protects both identity keys.
    let rows = sqlx::query(
        "SELECT id,actor_id,metadata FROM organization_service.audit_events
         WHERE organization_id=$1 AND event_type=$2
           AND (metadata->'offline_receipt'->>'event_id'=$3 OR resource_id=$4)",
    )
    .bind(authority.organization_id)
    .bind(EVENT_TYPE)
    .bind(event.event.event_id.to_string())
    .bind(event.event.payload.verification_id.to_string())
    .fetch_all(&mut **transaction)
    .await
    .map_err(persistence)?;
    if rows.len() > 1 {
        return Err(OfflineAuditError::Conflict);
    }
    if rows.first().is_some_and(|row| {
        row.try_get::<String, _>("actor_id").ok().as_deref() != Some(authority.actor_id().as_str())
    }) {
        // IDs cannot be re-accounted or reassigned by rotating a key. Another
        // producer learns only conflict, never the original private receipt.
        return Err(OfflineAuditError::Conflict);
    }
    rows.first()
        .map(|row| receipt_from_row(row, authority))
        .transpose()
}

fn receipt_from_row(
    row: &sqlx::postgres::PgRow,
    authority: OfflineAuditAuthority,
) -> Result<OfflineAuditReceipt, OfflineAuditError> {
    let id: Uuid = row.try_get("id").map_err(persistence)?;
    let metadata: serde_json::Value = row.try_get("metadata").map_err(persistence)?;
    let receipt: OfflineAuditReceipt =
        serde_json::from_value(metadata["offline_receipt"].clone()).map_err(persistence)?;
    let validated = receipt
        .event
        .clone()
        .validate(Utc::now())
        .map_err(persistence)?;
    if receipt.kind != RECEIPT_KIND
        || receipt.audit_event_id != id
        || receipt.organization_id != authority.organization_id
        || receipt.producer_id != authority.producer_id
        || !receipt.matches(&validated)
    {
        return Err(OfflineAuditError::Persistence);
    }
    Ok(receipt)
}

fn persistence<T>(_: T) -> OfflineAuditError {
    // Never reflect submitted metadata, credentials, or database details.
    OfflineAuditError::Persistence
}

fn insertion_error(error: crate::postgres::RepositoryError) -> OfflineAuditError {
    match error {
        crate::postgres::RepositoryError::Database(sqlx::Error::Database(error))
            if error.code().as_deref() == Some("23505") =>
        {
            OfflineAuditError::Conflict
        }
        _ => OfflineAuditError::Persistence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_audit_authority_requires_exact_tenant_key_and_permission() {
        let org = Uuid::new_v4();
        let key = Uuid::new_v4();
        let principal = ForwardedPrincipal::ApiKey {
            user_id: format!("api_key:{key}"),
            api_key_id: key.to_string(),
            organization_id: org,
            authorized_permission: PERMISSION.into(),
        };
        assert_eq!(
            OfflineAuditAuthority::from_principal(org, &principal).unwrap(),
            OfflineAuditAuthority {
                organization_id: org,
                producer_id: key
            }
        );
        assert!(OfflineAuditAuthority::from_principal(Uuid::new_v4(), &principal).is_err());
        let mut wrong = principal;
        if let ForwardedPrincipal::ApiKey {
            authorized_permission,
            ..
        } = &mut wrong
        {
            *authorized_permission = "audit:view".into();
        }
        assert!(OfflineAuditAuthority::from_principal(org, &wrong).is_err());
        assert!(OfflineAuditAuthority::from_principal(
            org,
            &ForwardedPrincipal::User {
                user_id: "owner".into()
            }
        )
        .is_err());
    }
}
