// SPDX-License-Identifier: AGPL-3.0-only
//! Explicit Core attachment of an admitted unsigned observation. This module
//! never evaluates approval policy, prepares a transaction, signs, or issues.
//! Use the canonical application-writer pool, never the observation role pool.
use crate::external_observation_admin::{database_error, lock_admin, AdminError};
use crate::external_observation_admin_read::decode_receipt;
use crate::external_observation_admission::{
    id, label, text, valid_claims, valid_rules, EvidenceBinding, MAX_SAFE_INTEGER,
};
use crate::external_observation_authority_postgres::parse_claim_rules;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, Row};
use uuid::Uuid;

const KIND: &str = "external-observation:unsigned:v1";
pub(crate) fn unsigned_verification() -> Value {
    json!({"status":"UNVERIFIED","method":"UNSIGNED_PRODUCER_ATTESTATION"})
}
#[derive(Debug, Serialize, PartialEq)]
pub struct Materialization {
    pub receipt_id: Uuid,
    pub fact_id: String,
    pub application_id: String,
    pub application_revision: i64,
    pub materialized_by: String,
    pub replayed: bool,
}
fn fact_id(org: Uuid, receipt: Uuid) -> String {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("urn:elevenid:external-observation-fact:v1:{org}:{receipt}").as_bytes(),
    )
    .to_string()
}
fn event_id(org: Uuid, receipt: Uuid) -> String {
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("urn:elevenid:external-observation-materialization-event:v1:{org}:{receipt}")
            .as_bytes(),
    )
    .to_string()
}
fn digest(value: &Value) -> Result<String, AdminError> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).map_err(|_| AdminError::Unavailable)?)
    ))
}
async fn begin(
    pool: &PgPool,
    org: Uuid,
    actor: &str,
) -> Result<sqlx::Transaction<'static, sqlx::Postgres>, AdminError> {
    let mut tx = pool.begin().await.map_err(database_error)?;
    for statement in [
        "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
        "SET LOCAL lock_timeout='5s'",
        "SET LOCAL statement_timeout='10s'",
    ] {
        sqlx::query(statement)
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
    }
    lock_admin(&mut tx, org, actor).await?;
    Ok(tx)
}
async fn existing(
    connection: &mut PgConnection,
    org: Uuid,
    receipt: Uuid,
) -> Result<Option<(Materialization, i64)>, AdminError> {
    let row = sqlx::query("SELECT f.application_id,f.verification,f.source,
      EXISTS(SELECT 1 FROM issuance_service.external_observation_receipts r JOIN issuance_service.external_observation_audit a ON a.receipt_id=r.receipt_id AND a.event_type='external_observation_admitted' AND a.received_at_ms=r.received_at_ms
        WHERE r.receipt_id=$3 AND r.organization_id=f.organization_id AND r.application_id=f.application_id AND r.subject_id=f.subject_id AND r.provider=f.provider AND r.fact_type=f.fact_type AND r.resource_scope=f.scope AND r.envelope->'claims'=f.assertion AND r.sequence::text=f.source_revision
        AND f.source->>'source_id'=r.source_id AND f.source->>'binding_id'=r.binding_id AND f.source->>'observation_id'=r.observation_id AND f.source->>'api_key_id'=r.api_key_id) AS receipt_valid,
      EXISTS(SELECT 1 FROM issuance_service.issuance_events e WHERE e.id=$4 AND e.organization_id=f.organization_id AND e.application_id=f.application_id AND e.transaction_id IS NULL AND e.event_type='external_observation_materialized' AND e.created_at=f.created_at
        AND e.metadata::jsonb=jsonb_build_object('receipt_id',$3::uuid,'fact_id',f.id,'actor_id',f.source->>'materialized_by','verification_status','UNVERIFIED')) AS event_valid
      FROM issuance_service.evidence_facts f WHERE f.id=$1 AND f.organization_id=$2")
        .bind(fact_id(org, receipt)).bind(org.to_string()).bind(receipt).bind(event_id(org,receipt)).fetch_optional(connection).await.map_err(database_error)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let verification: Value = row.try_get("verification").map_err(database_error)?;
    let source: Value = row.try_get("source").map_err(database_error)?;
    let application_id: String = row.try_get("application_id").map_err(database_error)?;
    let expected = source["expected_application_revision"]
        .as_i64()
        .filter(|v| (1..=MAX_SAFE_INTEGER as i64).contains(v))
        .ok_or(AdminError::Unavailable)?;
    let revision = source["application_revision"]
        .as_i64()
        .filter(|v| *v > expected && *v <= MAX_SAFE_INTEGER as i64)
        .ok_or(AdminError::Unavailable)?;
    let actor = source["materialized_by"]
        .as_str()
        .filter(|v| text(v, 255))
        .ok_or(AdminError::Unavailable)?;
    if !row
        .try_get::<bool, _>("receipt_valid")
        .map_err(database_error)?
        || !row
            .try_get::<bool, _>("event_valid")
            .map_err(database_error)?
        || source["kind"] != KIND
        || source["receipt_id"] != receipt.to_string()
        || verification != unsigned_verification()
        || !id(&application_id)
    {
        return Err(AdminError::Unavailable);
    }
    Ok(Some((
        Materialization {
            receipt_id: receipt,
            fact_id: fact_id(org, receipt),
            application_id,
            application_revision: revision,
            materialized_by: actor.into(),
            replayed: true,
        },
        expected,
    )))
}

/// Read only, current administrator authorization. Absence is a snapshot, never
/// permission to retry with a new identity or infer that COMMIT cannot occur.
pub async fn inspect_materialization(
    pool: &PgPool,
    org: Uuid,
    actor: &str,
    source: &str,
    observation: &str,
) -> Result<Value, AdminError> {
    if !id(source) || !id(observation) {
        return Err(AdminError::Conflict);
    }
    let mut tx = begin(pool, org, actor).await?;
    let receipt: Option<Uuid> = sqlx::query_scalar("SELECT receipt_id FROM issuance_service.external_observation_receipts WHERE organization_id=$1 AND source_id=$2 AND observation_id=$3")
        .bind(org.to_string()).bind(source).bind(observation).fetch_optional(&mut *tx).await.map_err(database_error)?;
    let record = match receipt {
        Some(receipt) => existing(&mut tx, org, receipt).await?.map(|v| v.0),
        None => None,
    };
    let snapshot: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(&mut *tx)
            .await
            .map_err(database_error)?;
    tx.rollback().await.map_err(database_error)?;
    Ok(json!({"found":record.is_some(),"record":record,"snapshot_at_ms":snapshot}))
}

/// Receipt identity and all evidence identity come from the immutable journal.
/// First materialization requires current binding and pending application CAS.
/// A matching retry returns the historical result and never moves a fact head.
pub async fn materialize(
    pool: &PgPool,
    org: Uuid,
    actor: &str,
    source: &str,
    observation: &str,
    expected_revision: i64,
) -> Result<Materialization, AdminError> {
    if !id(source)
        || !id(observation)
        || !(1..=MAX_SAFE_INTEGER as i64).contains(&expected_revision)
    {
        return Err(AdminError::Conflict);
    }
    let mut tx = begin(pool, org, actor).await?;
    // Immutable metadata discovery is not authority. The binding and application
    // locks below precede receipt/head locks, matching admission's lock order.
    let receipt = sqlx::query("SELECT receipt_id,binding_id,application_id FROM issuance_service.external_observation_receipts WHERE organization_id=$1 AND source_id=$2 AND observation_id=$3")
        .bind(org.to_string()).bind(source).bind(observation).fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(AdminError::Conflict)?;
    let receipt_id: Uuid = receipt.try_get("receipt_id").map_err(database_error)?;
    if let Some((result, original_revision)) = existing(&mut tx, org, receipt_id).await? {
        if original_revision != expected_revision {
            return Err(AdminError::Conflict);
        }
        tx.rollback().await.map_err(database_error)?;
        return Ok(result);
    }
    let binding_id: String = receipt.try_get("binding_id").map_err(database_error)?;
    let application_id: String = receipt.try_get("application_id").map_err(database_error)?;
    let binding = sqlx::query("SELECT revision,active,application_id,subject_id,provider,fact_type,resource_scope,claim_rules,max_age_ms,max_clock_skew_ms FROM issuance_service.external_observation_bindings WHERE organization_id=$1 AND source_id=$2 AND id=$3 FOR SHARE")
        .bind(org).bind(source).bind(&binding_id).fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(AdminError::Conflict)?;
    let app = sqlx::query("SELECT applicant_identifier,(extract(epoch FROM updated_at)*1000000)::bigint AS revision,status IN ('pending','under_review') AND expires_at>clock_timestamp() AS eligible FROM issuance_service.applications WHERE organization_id=$1 AND id=$2 FOR UPDATE")
        .bind(org.to_string()).bind(&application_id).fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(AdminError::NotAuthorized)?;
    if app.try_get::<i64, _>("revision").map_err(database_error)? != expected_revision {
        return Err(AdminError::Conflict);
    }
    if !app.try_get::<bool, _>("eligible").map_err(database_error)?
        || !binding
            .try_get::<bool, _>("active")
            .map_err(database_error)?
    {
        return Err(AdminError::NotAuthorized);
    }
    let row = sqlx::query("SELECT r.*,to_jsonb(r) AS receipt_snapshot,a.event_type AS admission_event,a.received_at_ms AS admission_received_at_ms FROM issuance_service.external_observation_receipts r JOIN issuance_service.external_observation_audit a ON a.receipt_id=r.receipt_id WHERE r.receipt_id=$1 AND r.organization_id=$2 FOR SHARE OF r,a")
        .bind(receipt_id).bind(org.to_string()).fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(AdminError::Unavailable)?;
    let receipt_snapshot: Value = row.try_get("receipt_snapshot").map_err(database_error)?;
    let binding_snapshot: Value = sqlx::query_scalar("SELECT to_jsonb(b) FROM issuance_service.external_observation_bindings b WHERE id=$1 AND organization_id=$2").bind(&binding_id).bind(org).fetch_one(&mut *tx).await.map_err(database_error)?;
    let envelope: Value = row.try_get("envelope").map_err(database_error)?;
    if serde_json::to_vec(&envelope)
        .map_err(|_| AdminError::Unavailable)?
        .len()
        > 65536
    {
        return Err(AdminError::Unavailable);
    }
    let input = decode_receipt(&envelope, observation)?;
    let scope: Value = row.try_get("resource_scope").map_err(database_error)?;
    let provider: String = row.try_get("provider").map_err(database_error)?;
    let fact_type: String = row.try_get("fact_type").map_err(database_error)?;
    let subject: String = row.try_get("subject_id").map_err(database_error)?;
    let binding_revision: i64 = row.try_get("binding_revision").map_err(database_error)?;
    let sequence: i64 = row.try_get("sequence").map_err(database_error)?;
    let received: i64 = row.try_get("received_at_ms").map_err(database_error)?;
    let api_key_id: String = row.try_get("api_key_id").map_err(database_error)?;
    let rules = parse_claim_rules(binding.try_get("claim_rules").map_err(database_error)?)
        .map_err(|_| AdminError::Unavailable)?;
    let constraints = EvidenceBinding {
        id: binding_id.clone(),
        revision: binding_revision as u64,
        active: true,
        organization_id: org.to_string(),
        source_id: source.into(),
        provider: provider.clone(),
        application_id: application_id.clone(),
        subject_id: subject.clone(),
        fact_type: fact_type.clone(),
        resource_scope: serde_json::from_value(scope.clone())
            .map_err(|_| AdminError::Unavailable)?,
        claims: rules,
        max_age_ms: binding
            .try_get::<i64, _>("max_age_ms")
            .map_err(database_error)? as u64,
        max_clock_skew_ms: binding
            .try_get::<i64, _>("max_clock_skew_ms")
            .map_err(database_error)? as u64,
    };
    if input.binding_id != binding_id
        || input.binding_revision != binding_revision as u64
        || input.observation_id != observation
        || input.sequence != sequence as u64
        || !(1..=MAX_SAFE_INTEGER).contains(&input.observed_at_ms)
        || !(1..=MAX_SAFE_INTEGER).contains(&input.effective_at_ms)
        || marty_key_material_policy::contains_private_key(&envelope)
        || marty_key_material_policy::contains_private_key(&scope)
        || !(1..=MAX_SAFE_INTEGER as i64).contains(&sequence)
        || !(1..=MAX_SAFE_INTEGER as i64).contains(&binding_revision)
        || !(1..=MAX_SAFE_INTEGER as i64).contains(&received)
        || !id(&binding_id)
        || !id(&application_id)
        || !text(&subject, 1024)
        || !label(&provider)
        || provider.len() > 80
        || !label(&fact_type)
        || !valid_rules(&constraints.claims)
        || !valid_claims(&input, &constraints)
        || scope.as_object().is_none_or(|v| {
            v.is_empty()
                || v.len() > 16
                || v.iter()
                    .any(|(k, v)| !label(k) || !v.as_str().is_some_and(|s| text(s, 512)))
        })
        || row
            .try_get::<i64, _>("admission_received_at_ms")
            .map_err(database_error)?
            != received
        || receipt_id.is_nil()
        || !Uuid::parse_str(&api_key_id).is_ok_and(|v| !v.is_nil() && v.to_string() == api_key_id)
        || row
            .try_get::<String, _>("admission_event")
            .map_err(database_error)?
            != "external_observation_admitted"
    {
        return Err(AdminError::Unavailable);
    }
    if binding
        .try_get::<i64, _>("revision")
        .map_err(database_error)?
        != binding_revision
        || binding
            .try_get::<String, _>("application_id")
            .map_err(database_error)?
            != application_id
        || binding
            .try_get::<String, _>("subject_id")
            .map_err(database_error)?
            != subject
        || app
            .try_get::<String, _>("applicant_identifier")
            .map_err(database_error)?
            != subject
        || binding
            .try_get::<String, _>("provider")
            .map_err(database_error)?
            != provider
        || binding
            .try_get::<String, _>("fact_type")
            .map_err(database_error)?
            != fact_type
        || binding
            .try_get::<Value, _>("resource_scope")
            .map_err(database_error)?
            != scope
    {
        return Err(AdminError::Conflict);
    }
    let head: Option<(Uuid,i64)> = sqlx::query_as("SELECT receipt_id,sequence FROM issuance_service.external_observation_heads WHERE organization_id=$1 AND source_id=$2 AND binding_id=$3 FOR SHARE")
        .bind(org.to_string()).bind(source).bind(&binding_id).fetch_optional(&mut *tx).await.map_err(database_error)?;
    if head != Some((receipt_id, sequence)) {
        return Err(AdminError::Conflict);
    }
    let logical_key = digest(&json!([KIND, org, source, binding_id]))?;
    let old = sqlx::query("SELECT f.id,f.verification,f.source,f.source_revision FROM issuance_service.evidence_fact_heads h JOIN issuance_service.evidence_facts f ON f.id=h.fact_id AND f.organization_id=h.organization_id AND f.application_id=h.application_id AND f.logical_key=h.logical_key WHERE h.organization_id=$1 AND h.application_id=$2 AND h.logical_key=$3 FOR UPDATE OF h")
        .bind(org.to_string()).bind(&application_id).bind(&logical_key).fetch_optional(&mut *tx).await.map_err(database_error)?;
    let superseded: Option<String> = if let Some(old) = old {
        let old_source: Value = old.try_get("source").map_err(database_error)?;
        let old_sequence: String = old.try_get("source_revision").map_err(database_error)?;
        if old
            .try_get::<Value, _>("verification")
            .map_err(database_error)?
            != unsigned_verification()
            || old_source["kind"] != KIND
            || old_source["binding_id"] != binding_id
            || old_source["source_id"] != source
            || !old_sequence
                .parse::<i64>()
                .is_ok_and(|n| n > 0 && n < sequence)
        {
            return Err(AdminError::Conflict);
        }
        Some(old.try_get("id").map_err(database_error)?)
    } else {
        None
    };
    // Bump even if the database clock has not advanced. Stale approval snapshots
    // must conflict; application lifecycle and submitted evidence remain intact.
    let revision: i64 = sqlx::query_scalar("UPDATE issuance_service.applications SET updated_at=GREATEST(clock_timestamp(),updated_at+interval '1 microsecond') WHERE id=$1 AND organization_id=$2 AND (extract(epoch FROM updated_at)*1000000)::bigint=$3 AND status IN ('pending','under_review') AND expires_at>clock_timestamp() RETURNING (extract(epoch FROM updated_at)*1000000)::bigint")
        .bind(&application_id).bind(org.to_string()).bind(expected_revision).fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(AdminError::Conflict)?;
    if revision <= expected_revision || revision > MAX_SAFE_INTEGER as i64 {
        return Err(AdminError::Unavailable);
    }
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await
        .map_err(database_error)?;
    let source_record = json!({"kind":KIND,"receipt_id":receipt_id,"source_id":source,"binding_id":binding_id,"binding_revision":binding_revision,"observation_id":observation,"api_key_id":api_key_id,"received_at_ms":received,"materialized_by":actor,"expected_application_revision":expected_revision,"application_revision":revision});
    let observed = i64::try_from(input.observed_at_ms)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_millis)
        .ok_or(AdminError::Unavailable)?;
    let effective = i64::try_from(input.effective_at_ms)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_millis)
        .ok_or(AdminError::Unavailable)?;
    let fact = fact_id(org, receipt_id);
    let hash = digest(
        &json!({"receipt_id":receipt_id,"scope":scope,"envelope":envelope,"provider":provider,"fact_type":fact_type,"subject_id":subject}),
    )?;
    sqlx::query("INSERT INTO issuance_service.evidence_facts(id,organization_id,application_id,subject_id,provider,fact_type,scope,assertion,verification,source,requirement_id,logical_key,source_revision,payload_hash,observed_at,effective_at,superseded_fact_id,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,$11,$12,$13,$14,$15,$16,$17)")
        .bind(&fact).bind(org.to_string()).bind(&application_id).bind(&subject).bind(&provider).bind(&fact_type).bind(&scope).bind(envelope["claims"].clone())
        .bind(unsigned_verification()).bind(&source_record).bind(&logical_key).bind(sequence.to_string()).bind(&hash).bind(observed).bind(effective).bind(&superseded).bind(now)
        .execute(&mut *tx).await.map_err(database_error)?;
    sqlx::query("INSERT INTO issuance_service.evidence_fact_heads(organization_id,application_id,logical_key,fact_id,updated_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT(application_id,logical_key) DO UPDATE SET fact_id=EXCLUDED.fact_id,updated_at=EXCLUDED.updated_at WHERE evidence_fact_heads.organization_id=EXCLUDED.organization_id")
        .bind(org.to_string()).bind(&application_id).bind(&logical_key).bind(&fact).bind(now).execute(&mut *tx).await.map_err(database_error)?;
    let event_id = event_id(org, receipt_id);
    let event_metadata = json!({"receipt_id":receipt_id,"fact_id":fact,"actor_id":actor,"verification_status":"UNVERIFIED"});
    sqlx::query("INSERT INTO issuance_service.issuance_events(id,organization_id,application_id,event_type,metadata,created_at) VALUES ($1,$2,$3,'external_observation_materialized',$4,$5)")
        .bind(&event_id).bind(org.to_string()).bind(&application_id).bind(&event_metadata).bind(now).execute(&mut *tx).await.map_err(database_error)?;
    // Revalidate after every write: expiry can cross while an event trigger or
    // lock waits; same-transaction changes must not defeat the authority fence.
    lock_admin(&mut tx, org, actor).await?;
    let app_valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM issuance_service.applications WHERE id=$1 AND organization_id=$2 AND applicant_identifier=$3 AND (extract(epoch FROM updated_at)*1000000)::bigint=$4 AND status IN ('pending','under_review') AND expires_at>clock_timestamp())")
        .bind(&application_id).bind(org.to_string()).bind(&subject).bind(revision).fetch_one(&mut *tx).await.map_err(database_error)?;
    let binding_valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM issuance_service.external_observation_bindings b WHERE id=$1 AND organization_id=$2 AND to_jsonb(b)=$3)")
        .bind(&binding_id).bind(org).bind(&binding_snapshot).fetch_one(&mut *tx).await.map_err(database_error)?;
    let receipt_valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM issuance_service.external_observation_receipts r JOIN issuance_service.external_observation_audit a ON a.receipt_id=r.receipt_id AND a.event_type='external_observation_admitted' AND a.received_at_ms=r.received_at_ms JOIN issuance_service.external_observation_heads h ON h.receipt_id=r.receipt_id AND h.organization_id=r.organization_id AND h.source_id=r.source_id AND h.binding_id=r.binding_id AND h.sequence=r.sequence WHERE r.receipt_id=$1 AND to_jsonb(r)=$2)")
        .bind(receipt_id).bind(&receipt_snapshot).fetch_one(&mut *tx).await.map_err(database_error)?;
    let fact_valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM issuance_service.evidence_facts f JOIN issuance_service.evidence_fact_heads h ON h.fact_id=f.id AND h.organization_id=f.organization_id AND h.application_id=f.application_id AND h.logical_key=f.logical_key WHERE f.id=$1 AND f.organization_id=$2 AND f.application_id=$3 AND f.subject_id=$4 AND f.provider=$5 AND f.fact_type=$6 AND f.scope=$7 AND f.assertion=$8 AND f.verification=$9 AND f.source=$10 AND f.requirement_id IS NULL AND f.logical_key=$11 AND f.source_revision=$12 AND f.payload_hash=$13 AND f.observed_at=$14 AND f.effective_at=$15 AND f.superseded_fact_id IS NOT DISTINCT FROM $16 AND f.created_at=$17 AND h.updated_at=$17)")
        .bind(&fact).bind(org.to_string()).bind(&application_id).bind(&subject).bind(&provider).bind(&fact_type).bind(&scope).bind(&envelope["claims"])
        .bind(unsigned_verification()).bind(&source_record).bind(&logical_key).bind(sequence.to_string()).bind(&hash).bind(observed).bind(effective).bind(&superseded).bind(now)
        .fetch_one(&mut *tx).await.map_err(database_error)?;
    let event_valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM issuance_service.issuance_events WHERE id=$1 AND organization_id=$2 AND application_id=$3 AND transaction_id IS NULL AND event_type='external_observation_materialized' AND metadata::jsonb=$4 AND created_at=$5)")
        .bind(event_id).bind(org.to_string()).bind(&application_id).bind(event_metadata).bind(now).fetch_one(&mut *tx).await.map_err(database_error)?;
    if !app_valid || !binding_valid || !receipt_valid || !fact_valid || !event_valid {
        return Err(AdminError::Conflict);
    }
    tx.commit().await.map_err(|_| AdminError::CommitUnknown)?;
    Ok(Materialization {
        receipt_id,
        fact_id: fact,
        application_id,
        application_revision: revision,
        materialized_by: actor.into(),
        replayed: false,
    })
}

/// Read-only qualification of the canonical writer pool. Never performs DDL,
/// creates credentials, grants privileges, or changes the isolated ingress pool.
pub async fn verify_materialization_storage(pool: &PgPool) -> Result<(), &'static str> {
    const FAILURE: &str = "Canonical observation materialization storage preflight failed";
    let mut tx = pool.begin().await.map_err(|_| FAILURE)?;
    sqlx::query("SET LOCAL statement_timeout='5s'")
        .execute(&mut *tx)
        .await
        .map_err(|_| FAILURE)?;
    for query in [
        "SELECT id,organization_id,application_id,subject_id,provider,fact_type,scope,assertion,verification,source,requirement_id,logical_key,source_revision,payload_hash,observed_at,effective_at,superseded_fact_id,created_at FROM issuance_service.evidence_facts LIMIT 0",
        "SELECT organization_id,application_id,logical_key,fact_id,updated_at FROM issuance_service.evidence_fact_heads LIMIT 0 FOR UPDATE",
        "SELECT id,organization_id,application_id,transaction_id,event_type,metadata,created_at FROM issuance_service.issuance_events LIMIT 0",
        "SELECT receipt_id FROM issuance_service.external_observation_receipts LIMIT 0 FOR SHARE",
    ] { sqlx::query(query).execute(&mut *tx).await.map_err(|_| FAILURE)?; }
    let allowed:bool=sqlx::query_scalar("SELECT has_table_privilege(current_user,'issuance_service.evidence_facts','INSERT') AND has_table_privilege(current_user,'issuance_service.evidence_fact_heads','INSERT') AND has_column_privilege(current_user,'issuance_service.evidence_fact_heads','fact_id','UPDATE') AND has_column_privilege(current_user,'issuance_service.evidence_fact_heads','updated_at','UPDATE') AND has_column_privilege(current_user,'issuance_service.applications','updated_at','UPDATE') AND has_table_privilege(current_user,'issuance_service.issuance_events','INSERT')").fetch_one(&mut *tx).await.map_err(|_| FAILURE)?;
    tx.rollback().await.map_err(|_| FAILURE)?;
    if allowed {
        Ok(())
    } else {
        Err(FAILURE)
    }
}
