// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded canonical administrator snapshots. These are neither admission
//! decisions nor automatic retry/requeue instructions. No writes are performed.
use crate::external_observation_admin::{database_error, lock_admin, AdminError};
use crate::external_observation_admission::{id, text};
use crate::external_observation_membership_admin::{valid_selection, BindingSelection};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgConnection, PgPool, Row};
use uuid::Uuid;

const MAX_SAFE: i64 = 9007199254740991;
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantPage {
    pub after_binding_id: Option<String>,
    pub expected_revision: Option<i64>,
}
impl GrantPage {
    pub fn valid(&self) -> bool {
        self.after_binding_id.as_ref().is_none_or(|v| id(v))
            && self
                .expected_revision
                .is_none_or(|v| (1..=MAX_SAFE).contains(&v))
            && (self.after_binding_id.is_none() || self.expected_revision.is_some())
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCursor {
    pub created_at: DateTime<Utc>,
    pub id: Uuid,
}
impl AuditCursor {
    pub fn valid(&self) -> bool {
        !self.id.is_nil()
            && (1..=MAX_SAFE).contains(&self.created_at.timestamp_millis())
            && self
                .created_at
                .timestamp_subsec_nanos()
                .is_multiple_of(1000)
    }
}
#[derive(Clone, Copy)]
pub enum ResourceKind {
    Producer,
    Binding,
}
impl ResourceKind {
    fn stored(self) -> &'static str {
        match self {
            Self::Producer => "external-observation-producer",
            Self::Binding => "external-observation-binding",
        }
    }
}
pub enum AdminRead {
    Grant {
        grant: Uuid,
        page: GrantPage,
    },
    Binding {
        binding: String,
    },
    Receipt {
        source: String,
        observation: String,
    },
    Audit {
        kind: ResourceKind,
        resource: String,
        cursor: Option<AuditCursor>,
    },
}
impl AdminRead {
    pub fn valid(&self) -> bool {
        match self {
            Self::Grant { grant, page } => !grant.is_nil() && page.valid(),
            Self::Binding { binding } => id(binding),
            Self::Receipt {
                source,
                observation,
            } => id(source) && id(observation),
            Self::Audit {
                kind,
                resource,
                cursor,
            } => {
                id(resource)
                    && cursor.as_ref().is_none_or(AuditCursor::valid)
                    && (!matches!(kind, ResourceKind::Producer)
                        || Uuid::parse_str(resource)
                            .is_ok_and(|v| !v.is_nil() && v.to_string() == *resource))
            }
        }
    }
}
pub async fn inspect(
    pool: &PgPool,
    organization: Uuid,
    actor: &str,
    query: AdminRead,
) -> Result<Value, AdminError> {
    if !query.valid() {
        return Err(AdminError::Conflict);
    }
    // Row locks used by canonical permission checks cannot run in PostgreSQL's
    // READ ONLY mode. This regular SERIALIZABLE transaction issues SELECT only
    // and always rolls back, preserving a consistent authorized snapshot.
    let mut tx = pool.begin().await.map_err(database_error)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
    sqlx::query("SET LOCAL lock_timeout='5s'")
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
    sqlx::query("SET LOCAL statement_timeout='10s'")
        .execute(&mut *tx)
        .await
        .map_err(database_error)?;
    let at: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(&mut *tx)
            .await
            .map_err(database_error)?;
    if !(1..=MAX_SAFE).contains(&at) {
        return Err(AdminError::Unavailable);
    }
    lock_admin(&mut tx, organization, actor).await?;
    let mut value = match query {
        AdminRead::Grant { grant, page } => {
            grant_snapshot(&mut tx, organization, grant, page).await?
        }
        AdminRead::Binding { binding } => binding_snapshot(&mut tx, organization, &binding).await?,
        AdminRead::Receipt {
            source,
            observation,
        } => receipt_snapshot(&mut tx, organization, &source, &observation).await?,
        AdminRead::Audit {
            kind,
            resource,
            cursor,
        } => audit_page(&mut tx, organization, kind, &resource, cursor).await?,
    };
    value
        .as_object_mut()
        .ok_or(AdminError::Unavailable)?
        .insert("snapshot_at_ms".into(), json!(at));
    if serde_json::to_vec(&value)
        .map_err(|_| AdminError::Unavailable)?
        .len()
        > 131072
    {
        return Err(AdminError::Unavailable);
    }
    tx.rollback().await.map_err(database_error)?;
    Ok(value)
}
async fn grant_snapshot(
    connection: &mut PgConnection,
    org: Uuid,
    grant: Uuid,
    page: GrantPage,
) -> Result<Value, AdminError> {
    let row=sqlx::query("SELECT revision,jsonb_build_object('id',id,'source_id',source_id,'api_key_id',api_key_id,'active',active,'revision',revision,
      'expires_at_ms',floor(extract(epoch FROM expires_at)*1000)::bigint,'created_by',created_by,'approved_by',approved_by,
      'approved_at_ms',floor(extract(epoch FROM approved_at)*1000)::bigint,'created_at',created_at,'updated_at',updated_at) AS record
      FROM issuance_service.external_observation_producer_grants WHERE id=$1 AND organization_id=$2 FOR SHARE")
      .bind(grant).bind(org).fetch_optional(&mut *connection).await.map_err(database_error)?;
    let Some(row) = row else {
        return Ok(json!({"found":false,"record":null,"next_binding_id":null}));
    };
    let revision: i64 = row.try_get("revision").map_err(database_error)?;
    if page.expected_revision.is_some_and(|r| r != revision) {
        return Err(AdminError::Conflict);
    }
    let mut record: Value = row.try_get("record").map_err(database_error)?;
    let mut bindings:Vec<String>=sqlx::query_scalar("SELECT binding_id FROM issuance_service.external_observation_grant_bindings WHERE grant_id=$1 AND organization_id=$2 AND ($3::text IS NULL OR binding_id COLLATE \"C\">$3 COLLATE \"C\") ORDER BY binding_id COLLATE \"C\" LIMIT 33")
      .bind(grant).bind(org).bind(&page.after_binding_id).fetch_all(connection).await.map_err(database_error)?;
    if bindings.iter().any(|v| !id(v)) {
        return Err(AdminError::Unavailable);
    }
    let next = if bindings.len() > 32 {
        bindings.truncate(32);
        bindings.last().cloned()
    } else {
        None
    };
    record
        .as_object_mut()
        .ok_or(AdminError::Unavailable)?
        .insert("bindings".into(), json!(bindings));
    Ok(json!({"found":true,"record":record,"next_binding_id":next}))
}
async fn binding_snapshot(
    connection: &mut PgConnection,
    org: Uuid,
    binding: &str,
) -> Result<Value, AdminError> {
    let row=sqlx::query("SELECT CASE WHEN octet_length(b.resource_scope::text)<=16384 AND octet_length(b.claim_rules::text)<=16384 THEN
      jsonb_build_object('id',b.id,'source_id',b.source_id,'application_id',b.application_id,'subject_id',b.subject_id,'provider',b.provider,
      'fact_type',b.fact_type,'resource_scope',b.resource_scope,'claim_rules',b.claim_rules,'max_age_ms',b.max_age_ms,'max_clock_skew_ms',b.max_clock_skew_ms,
      'active',b.active,'revision',b.revision,'created_by',b.created_by,'updated_by',b.updated_by,'created_at',b.created_at,'updated_at',b.updated_at,
      'application_revision',(extract(epoch FROM a.updated_at)*1000000)::bigint,'application_status',a.status,
      'application_expires_at_ms',floor(extract(epoch FROM a.expires_at)*1000)::bigint) END AS record
      FROM issuance_service.external_observation_bindings b LEFT JOIN issuance_service.applications a ON a.id=b.application_id AND a.organization_id=$2
      WHERE b.id=$1 AND b.organization_id=$3")
      .bind(binding).bind(org.to_string()).bind(org).fetch_optional(connection).await.map_err(database_error)?;
    match row {
        None => Ok(json!({"found":false,"record":null})),
        Some(row) => {
            let record: Option<Value> = row.try_get("record").map_err(database_error)?;
            Ok(json!({"found":true,"record":record.ok_or(AdminError::Unavailable)?}))
        }
    }
}
async fn receipt_snapshot(
    connection: &mut PgConnection,
    org: Uuid,
    source: &str,
    observation: &str,
) -> Result<Value, AdminError> {
    let row=sqlx::query("SELECT r.receipt_id,r.api_key_id,r.binding_id,r.binding_revision,r.sequence,r.received_at_ms,
      CASE WHEN octet_length(r.envelope::text)<=65536 THEN r.envelope END AS envelope,
      a.event_type,a.received_at_ms AS audit_received_at_ms,h.sequence AS head_sequence,h.receipt_id AS head_receipt_id,hr.receipt_id AS matched_head_receipt_id
      FROM issuance_service.external_observation_receipts r
      LEFT JOIN issuance_service.external_observation_audit a ON a.receipt_id=r.receipt_id
      LEFT JOIN issuance_service.external_observation_heads h ON h.organization_id=r.organization_id AND h.source_id=r.source_id AND h.binding_id=r.binding_id
      LEFT JOIN issuance_service.external_observation_receipts hr ON hr.receipt_id=h.receipt_id AND hr.organization_id=h.organization_id AND hr.source_id=h.source_id AND hr.binding_id=h.binding_id AND hr.sequence=h.sequence
      WHERE r.organization_id=$1 AND r.source_id=$2 AND r.observation_id=$3")
      .bind(org.to_string()).bind(source).bind(observation).fetch_optional(connection).await.map_err(database_error)?;
    let Some(row) = row else {
        return Ok(json!({"found":false,"record":null}));
    };
    let envelope: Option<Value> = row.try_get("envelope").map_err(database_error)?;
    let envelope = envelope.ok_or(AdminError::Unavailable)?;
    let decoded = decode_receipt(&envelope, observation)?;
    let receipt: Uuid = row.try_get("receipt_id").map_err(database_error)?;
    let key: String = row.try_get("api_key_id").map_err(database_error)?;
    let binding: String = row.try_get("binding_id").map_err(database_error)?;
    let revision: i64 = row.try_get("binding_revision").map_err(database_error)?;
    let sequence: i64 = row.try_get("sequence").map_err(database_error)?;
    let received: i64 = row.try_get("received_at_ms").map_err(database_error)?;
    let audit: Option<String> = row.try_get("event_type").map_err(database_error)?;
    let audit_time: Option<i64> = row
        .try_get("audit_received_at_ms")
        .map_err(database_error)?;
    let head: Option<i64> = row.try_get("head_sequence").map_err(database_error)?;
    let head_receipt: Option<Uuid> = row.try_get("head_receipt_id").map_err(database_error)?;
    let matched_head: Option<Uuid> = row
        .try_get("matched_head_receipt_id")
        .map_err(database_error)?;
    if head_receipt != matched_head
        || receipt.is_nil()
        || !Uuid::parse_str(&key).is_ok_and(|v| !v.is_nil() && v.to_string() == key)
        || decoded.binding_id != binding
        || decoded.binding_revision
            != u64::try_from(revision).map_err(|_| AdminError::Unavailable)?
        || decoded.sequence != u64::try_from(sequence).map_err(|_| AdminError::Unavailable)?
        || audit.as_deref() != Some("external_observation_admitted")
        || audit_time != Some(received)
        || !(1..=MAX_SAFE).contains(&received)
        || !head.is_some_and(|v| v >= sequence && v <= MAX_SAFE)
        || head_receipt.is_none_or(|v| v.is_nil())
    {
        return Err(AdminError::Unavailable);
    }
    Ok(
        json!({"found":true,"record":{"kind":"unsigned_producer_attestation","receipt_id":receipt,"source_id":source,"observation_id":observation,
      "api_key_id":key,"binding_id":binding,"binding_revision":revision,"sequence":sequence,"received_at_ms":received,"envelope":envelope,
      "head_sequence":head,"head_receipt_id":head_receipt}}),
    )
}
fn audit_changes(changes: Value) -> Result<Value, AdminError> {
    let object = changes.as_object().ok_or(AdminError::Unavailable)?;
    let mut result = serde_json::Map::new();
    for (name, value) in object {
        let valid = match name.as_str() {
            "revision" | "expires_at_ms" => {
                value.as_i64().is_some_and(|v| (1..=MAX_SAFE).contains(&v))
            }
            "previous_revision" => {
                value.is_null() || value.as_i64().is_some_and(|v| (0..=MAX_SAFE).contains(&v))
            }
            "deactivated_grant_count" => {
                value.as_i64().is_some_and(|v| (0..=MAX_SAFE).contains(&v))
            }
            "active" => value.is_boolean(),
            "api_key_id" | "previous_api_key_id" => value.as_str().is_some_and(|s| {
                Uuid::parse_str(s).is_ok_and(|v| !v.is_nil() && v.to_string() == s)
            }),
            "bindings" => serde_json::from_value::<Vec<BindingSelection>>(value.clone())
                .is_ok_and(|v| valid_selection(&v)),
            _ => continue,
        };
        if !valid {
            return Err(AdminError::Unavailable);
        }
        result.insert(name.clone(), value.clone());
    }
    if !result.contains_key("revision") {
        return Err(AdminError::Unavailable);
    }
    Ok(Value::Object(result))
}
async fn audit_page(
    connection: &mut PgConnection,
    org: Uuid,
    kind: ResourceKind,
    resource: &str,
    cursor: Option<AuditCursor>,
) -> Result<Value, AdminError> {
    let time = cursor.as_ref().map(|v| v.created_at);
    let after = cursor.as_ref().map(|v| v.id);
    let mut rows=sqlx::query("SELECT id,event_type,action,actor_id,created_at,CASE WHEN octet_length(changes::text)<=8192 THEN changes END AS changes
      FROM organization_service.audit_events WHERE organization_id=$1 AND resource_type=$2 AND resource_id=$3
      AND event_type IN ('external_observation_grant_created','external_observation_grant_revoked','external_observation_grant_approved',
        'external_observation_grant_key_rotated','external_observation_grant_expiry_changed','external_observation_grant_bindings_replaced',
        'external_observation_binding_created','external_observation_binding_activated','external_observation_binding_deactivated','external_observation_binding_definition_replaced')
      AND ($4::timestamptz IS NULL OR (created_at,id)>($4,$5::uuid)) ORDER BY created_at,id LIMIT 9")
      .bind(org).bind(kind.stored()).bind(resource).bind(time).bind(after).fetch_all(connection).await.map_err(database_error)?;
    let more = rows.len() > 8;
    if more {
        rows.truncate(8);
    }
    let mut events = Vec::new();
    let mut next = Value::Null;
    for row in rows {
        let event: Uuid = row.try_get("id").map_err(database_error)?;
        let created: DateTime<Utc> = row.try_get("created_at").map_err(database_error)?;
        let actor: String = row.try_get("actor_id").map_err(database_error)?;
        if event.is_nil()
            || !text(&actor, 255)
            || !(AuditCursor {
                created_at: created,
                id: event,
            })
            .valid()
        {
            return Err(AdminError::Unavailable);
        }
        let changes: Option<Value> = row.try_get("changes").map_err(database_error)?;
        let changes = audit_changes(changes.ok_or(AdminError::Unavailable)?)?;
        let event_type: String = row.try_get("event_type").map_err(database_error)?;
        let action: String = row.try_get("action").map_err(database_error)?;
        if !id(&action.replace('-', "_")) {
            return Err(AdminError::Unavailable);
        }
        next = json!({"created_at":created,"id":event});
        events.push(json!({"id":event,"event_type":event_type,"action":action,"actor_id":actor,"created_at":created,"changes":changes}));
    }
    Ok(json!({"events":events,"next_cursor":if more{next}else{Value::Null}}))
}

/// Reuse the strict original protocol constraints for immutable stored envelopes.
pub(crate) fn decode_receipt(
    envelope: &Value,
    observation: &str,
) -> Result<crate::external_observation_admission::Observation, AdminError> {
    let bytes = serde_json::to_vec(envelope).map_err(|_| AdminError::Unavailable)?;
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "content-type",
        http::HeaderValue::from_static("application/json"),
    );
    headers.insert(
        "idempotency-key",
        http::HeaderValue::from_str(observation).map_err(|_| AdminError::Unavailable)?,
    );
    crate::external_observation_wire::decode_submission(&headers, &bytes)
        .map_err(|_| AdminError::Unavailable)
}
