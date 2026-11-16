// SPDX-License-Identifier: AGPL-3.0-only
//! Canonical binding creation and activation. Subjects come from applications;
//! changing binding state invalidates every linked producer grant's approval.
use crate::external_observation_admin::{database_error, lock_admin, AdminError};
use crate::external_observation_admission::{id, label, text, valid_rules};
use crate::external_observation_authority_postgres::parse_claim_rules;
use crate::external_observation_grant_lifecycle::GrantMutation;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sqlx::{PgConnection, PgPool, Row};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub struct UniqueMap<T>(pub BTreeMap<String, T>);
impl<'de, T: Deserialize<'de>> Deserialize<'de> for UniqueMap<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Object<T>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for Object<T> {
            type Value = UniqueMap<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a bounded object with unique keys")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut result = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if result.len() >= 32 || result.contains_key(&key) {
                        return Err(serde::de::Error::custom("invalid binding object"));
                    }
                    result.insert(key, map.next_value()?);
                }
                Ok(UniqueMap(result))
            }
        }
        deserializer.deserialize_map(Object(std::marker::PhantomData))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingClaimRule {
    pub kind: String,
    pub required: bool,
    pub nullable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<usize>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingDefinition {
    pub source_id: String,
    pub application_id: String,
    pub expected_application_revision: i64,
    pub provider: String,
    pub fact_type: String,
    pub resource_scope: UniqueMap<String>,
    pub claim_rules: UniqueMap<BindingClaimRule>,
    pub max_age_ms: i64,
    pub max_clock_skew_ms: i64,
}
pub fn valid_definition(value: &BindingDefinition) -> bool {
    let rules = serde_json::to_value(&value.claim_rules)
        .ok()
        .and_then(|v| parse_claim_rules(v).ok());
    id(&value.source_id)
        && id(&value.application_id)
        && label(&value.provider)
        && label(&value.fact_type)
        && (1..=9007199254740991).contains(&value.expected_application_revision)
        && (1..=900000).contains(&value.max_age_ms)
        && (0..=30000).contains(&value.max_clock_skew_ms)
        && !value.resource_scope.0.is_empty()
        && value.resource_scope.0.len() <= 16
        && value
            .resource_scope
            .0
            .iter()
            .all(|(k, v)| label(k) && text(v, 512))
        && rules.is_some_and(|v| valid_rules(&v))
}
async fn application(
    connection: &mut PgConnection,
    organization: Uuid,
    application_id: &str,
    expected_revision: i64,
) -> Result<String, AdminError> {
    let row = sqlx::query(
        "SELECT applicant_identifier,(extract(epoch FROM updated_at)*1000000)::bigint AS revision,
      (status IN ('pending','under_review') AND expires_at>clock_timestamp()) AS eligible
      FROM issuance_service.applications WHERE id=$1 AND organization_id=$2 FOR UPDATE",
    )
    .bind(application_id)
    .bind(organization.to_string())
    .fetch_optional(connection)
    .await
    .map_err(database_error)?
    .ok_or(AdminError::NotAuthorized)?;
    let subject: String = row
        .try_get("applicant_identifier")
        .map_err(database_error)?;
    if row.try_get::<i64, _>("revision").map_err(database_error)? != expected_revision {
        return Err(AdminError::Conflict);
    }
    if !row.try_get::<bool, _>("eligible").map_err(database_error)? || !text(&subject, 1024) {
        return Err(AdminError::NotAuthorized);
    }
    Ok(subject)
}
pub async fn create_binding(
    pool: &PgPool,
    organization: Uuid,
    actor: &str,
    binding: &str,
    definition: &BindingDefinition,
) -> Result<GrantMutation, AdminError> {
    if !id(binding) || !valid_definition(definition) {
        return Err(AdminError::Conflict);
    }
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
    lock_admin(&mut tx, organization, actor).await?;
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT id FROM issuance_service.external_observation_bindings WHERE id=$1 FOR UPDATE",
    )
    .bind(binding)
    .fetch_optional(&mut *tx)
    .await
    .map_err(database_error)?;
    if existing.is_some() {
        return Err(AdminError::Conflict);
    }
    // A new binding has no grant/membership rows. Lock the canonical application
    // before inserting a previously absent binding; competing UUID reuse conflicts.
    let subject = application(
        &mut tx,
        organization,
        &definition.application_id,
        definition.expected_application_revision,
    )
    .await?;
    let scope =
        serde_json::to_value(&definition.resource_scope).map_err(|_| AdminError::Conflict)?;
    let rules = serde_json::to_value(&definition.claim_rules).map_err(|_| AdminError::Conflict)?;
    let revision:i64=sqlx::query_scalar("INSERT INTO issuance_service.external_observation_bindings
      (id,organization_id,source_id,application_id,subject_id,provider,fact_type,resource_scope,claim_rules,max_age_ms,max_clock_skew_ms,active,created_by,updated_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,false,$12,$12) RETURNING revision")
      .bind(binding).bind(organization).bind(&definition.source_id).bind(&definition.application_id).bind(&subject)
      .bind(&definition.provider).bind(&definition.fact_type).bind(&scope).bind(&rules).bind(definition.max_age_ms).bind(definition.max_clock_skew_ms).bind(actor)
      .fetch_one(&mut *tx).await.map_err(database_error)?;
    let audit_id = Uuid::new_v4();
    audit(
        &mut tx,
        organization,
        actor,
        binding,
        audit_id,
        "external_observation_binding_created",
        "create",
        revision,
        false,
        0,
    )
    .await?;
    if application(
        &mut tx,
        organization,
        &definition.application_id,
        definition.expected_application_revision,
    )
    .await?
        != subject
    {
        return Err(AdminError::Conflict);
    }
    let unchanged:bool=sqlx::query_scalar("SELECT count(*)=1 FROM issuance_service.external_observation_bindings WHERE id=$1 AND organization_id=$2 AND revision=$3 AND NOT active AND source_id=$4 AND application_id=$5 AND subject_id=$6 AND provider=$7 AND fact_type=$8 AND resource_scope=$9 AND claim_rules=$10 AND max_age_ms=$11 AND max_clock_skew_ms=$12")
      .bind(binding).bind(organization).bind(revision).bind(&definition.source_id).bind(&definition.application_id).bind(&subject).bind(&definition.provider).bind(&definition.fact_type).bind(scope).bind(rules).bind(definition.max_age_ms).bind(definition.max_clock_skew_ms)
      .fetch_one(&mut *tx).await.map_err(database_error)?;
    if !unchanged {
        return Err(AdminError::Conflict);
    }
    tx.commit().await.map_err(|_| AdminError::CommitUnknown)?;
    Ok(GrantMutation { revision, audit_id })
}

/// Activation requires the exact current application revision and subject.
/// Deactivation remains possible after application expiry/closure. Both revoke
/// linked grant approvals, even when the requested active state is unchanged.
pub async fn set_binding_active(
    pool: &PgPool,
    organization: Uuid,
    actor: &str,
    binding: &str,
    expected_revision: i64,
    application_revision: Option<i64>,
) -> Result<GrantMutation, AdminError> {
    if !id(binding)
        || !(1..=9007199254740991).contains(&expected_revision)
        || application_revision.is_some_and(|r| !(1..=9007199254740991).contains(&r))
    {
        return Err(AdminError::Conflict);
    }
    let active = application_revision.is_some();
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
    lock_admin(&mut tx, organization, actor).await?;
    // Discovery grants no authority. Lock all linked keys, then grants, then
    // membership, binding and application. SERIALIZABLE also fences a concurrent
    // insertion absent from this initial membership snapshot.
    let links=sqlx::query("SELECT g.id,g.api_key_id FROM issuance_service.external_observation_grant_bindings m JOIN issuance_service.external_observation_producer_grants g ON g.id=m.grant_id AND g.organization_id=m.organization_id AND g.source_id=m.source_id WHERE m.binding_id=$1 AND m.organization_id=$2 ORDER BY g.id")
      .bind(binding).bind(organization).fetch_all(&mut *tx).await.map_err(database_error)?;
    let mut grants = BTreeMap::new();
    let mut keys = BTreeSet::new();
    for link in links {
        let grant: Uuid = link.try_get("id").map_err(database_error)?;
        let key: Uuid = link.try_get("api_key_id").map_err(database_error)?;
        grants.insert(grant, key);
        keys.insert(key);
    }
    let key_ids: Vec<Uuid> = keys.into_iter().collect();
    let grant_ids: Vec<Uuid> = grants.keys().copied().collect();
    let locked_keys:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM organization_service.api_keys WHERE organization_id=$1 AND id=ANY($2) ORDER BY id FOR UPDATE")
      .bind(organization).bind(&key_ids).fetch_all(&mut *tx).await.map_err(database_error)?;
    if locked_keys.len() != key_ids.len() {
        return Err(AdminError::Conflict);
    }
    let locked_grants=sqlx::query("SELECT id,api_key_id FROM issuance_service.external_observation_producer_grants WHERE organization_id=$1 AND id=ANY($2) ORDER BY id FOR UPDATE")
      .bind(organization).bind(&grant_ids).fetch_all(&mut *tx).await.map_err(database_error)?;
    if locked_grants.len() != grants.len() {
        return Err(AdminError::Conflict);
    }
    for row in locked_grants {
        let grant: Uuid = row.try_get("id").map_err(database_error)?;
        if grants.get(&grant)
            != Some(
                &row.try_get::<Uuid, _>("api_key_id")
                    .map_err(database_error)?,
            )
        {
            return Err(AdminError::Conflict);
        }
    }
    let memberships:Vec<Uuid>=sqlx::query_scalar("SELECT grant_id FROM issuance_service.external_observation_grant_bindings WHERE binding_id=$1 AND organization_id=$2 ORDER BY grant_id FOR UPDATE")
      .bind(binding).bind(organization).fetch_all(&mut *tx).await.map_err(database_error)?;
    if memberships != grant_ids {
        return Err(AdminError::Conflict);
    }
    let row=sqlx::query("SELECT source_id,application_id,subject_id,provider,fact_type,resource_scope,claim_rules,max_age_ms,max_clock_skew_ms,revision FROM issuance_service.external_observation_bindings WHERE id=$1 AND organization_id=$2 FOR UPDATE")
      .bind(binding).bind(organization).fetch_optional(&mut *tx).await.map_err(database_error)?.ok_or(AdminError::NotAuthorized)?;
    if row.try_get::<i64, _>("revision").map_err(database_error)? != expected_revision {
        return Err(AdminError::Conflict);
    }
    let app: String = row.try_get("application_id").map_err(database_error)?;
    let subject: String = row.try_get("subject_id").map_err(database_error)?;
    if let Some(app_revision) = application_revision {
        let definition = BindingDefinition {
            source_id: row.try_get("source_id").map_err(database_error)?,
            application_id: app.clone(),
            expected_application_revision: app_revision,
            provider: row.try_get("provider").map_err(database_error)?,
            fact_type: row.try_get("fact_type").map_err(database_error)?,
            resource_scope: serde_json::from_value(
                row.try_get("resource_scope").map_err(database_error)?,
            )
            .map_err(|_| AdminError::Conflict)?,
            claim_rules: serde_json::from_value(
                row.try_get("claim_rules").map_err(database_error)?,
            )
            .map_err(|_| AdminError::Conflict)?,
            max_age_ms: row.try_get("max_age_ms").map_err(database_error)?,
            max_clock_skew_ms: row.try_get("max_clock_skew_ms").map_err(database_error)?,
        };
        if !valid_definition(&definition)
            || application(&mut tx, organization, &app, app_revision).await? != subject
        {
            return Err(AdminError::NotAuthorized);
        }
    }
    let revisions=sqlx::query("UPDATE issuance_service.external_observation_producer_grants SET active=false,approved_by=NULL,approved_at=NULL WHERE organization_id=$1 AND id=ANY($2) RETURNING id,revision")
      .bind(organization).bind(&grant_ids).fetch_all(&mut *tx).await.map_err(database_error)?;
    let mut grant_revisions = BTreeMap::new();
    for row in revisions {
        grant_revisions.insert(
            row.try_get::<Uuid, _>("id").map_err(database_error)?,
            row.try_get::<i64, _>("revision").map_err(database_error)?,
        );
    }
    let revision:i64=sqlx::query_scalar("UPDATE issuance_service.external_observation_bindings SET active=$3,updated_by=$4 WHERE id=$1 AND organization_id=$2 RETURNING revision")
      .bind(binding).bind(organization).bind(active).bind(actor).fetch_one(&mut *tx).await.map_err(database_error)?;
    let audit_id = Uuid::new_v4();
    let (event, action) = if active {
        ("external_observation_binding_activated", "activate")
    } else {
        ("external_observation_binding_deactivated", "deactivate")
    };
    audit(
        &mut tx,
        organization,
        actor,
        binding,
        audit_id,
        event,
        action,
        revision,
        active,
        grant_ids.len(),
    )
    .await?;
    let final_links:Vec<Uuid>=sqlx::query_scalar("SELECT grant_id FROM issuance_service.external_observation_grant_bindings WHERE binding_id=$1 AND organization_id=$2 ORDER BY grant_id")
      .bind(binding).bind(organization).fetch_all(&mut *tx).await.map_err(database_error)?;
    if final_links != grant_ids {
        return Err(AdminError::Conflict);
    }
    let final_grants=sqlx::query("SELECT id,api_key_id,revision,active,approved_by,approved_at FROM issuance_service.external_observation_producer_grants WHERE organization_id=$1 AND id=ANY($2)")
      .bind(organization).bind(&grant_ids).fetch_all(&mut *tx).await.map_err(database_error)?;
    if final_grants.len() != grants.len() {
        return Err(AdminError::Conflict);
    }
    for row in final_grants {
        let grant: Uuid = row.try_get("id").map_err(database_error)?;
        if grants.get(&grant)
            != Some(
                &row.try_get::<Uuid, _>("api_key_id")
                    .map_err(database_error)?,
            )
            || grant_revisions.get(&grant)
                != Some(&row.try_get::<i64, _>("revision").map_err(database_error)?)
            || row.try_get::<bool, _>("active").map_err(database_error)?
            || row
                .try_get::<Option<String>, _>("approved_by")
                .map_err(database_error)?
                .is_some()
            || row
                .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("approved_at")
                .map_err(database_error)?
                .is_some()
        {
            return Err(AdminError::Conflict);
        }
    }
    let unchanged:bool=sqlx::query_scalar("SELECT count(*)=1 FROM issuance_service.external_observation_bindings WHERE id=$1 AND organization_id=$2 AND revision=$3 AND active=$4 AND application_id=$5 AND subject_id=$6")
      .bind(binding).bind(organization).bind(revision).bind(active).bind(&app).bind(&subject).fetch_one(&mut *tx).await.map_err(database_error)?;
    if !unchanged {
        return Err(AdminError::Conflict);
    }
    if let Some(app_revision) = application_revision {
        if application(&mut tx, organization, &app, app_revision).await? != subject {
            return Err(AdminError::Conflict);
        }
    }
    tx.commit().await.map_err(|_| AdminError::CommitUnknown)?;
    Ok(GrantMutation { revision, audit_id })
}
#[allow(clippy::too_many_arguments)]
async fn audit(
    connection: &mut PgConnection,
    organization: Uuid,
    actor: &str,
    binding: &str,
    audit_id: Uuid,
    event: &str,
    action: &str,
    revision: i64,
    active: bool,
    grants: usize,
) -> Result<(), AdminError> {
    sqlx::query("INSERT INTO organization_service.audit_events (id,organization_id,event_type,action,category,resource_type,resource_id,actor_id,actor_type,severity,message,changes,metadata,created_at) VALUES ($1,$2,$3,$4,'evidence','external-observation-binding',$5,$6,'user','info','External observation binding changed',$7,'{}'::jsonb,clock_timestamp())")
      .bind(audit_id).bind(organization).bind(event).bind(action).bind(binding).bind(actor).bind(serde_json::json!({"revision":revision,"active":active,"deactivated_grant_count":grants})).execute(connection).await.map_err(database_error)?;
    Ok(())
}
