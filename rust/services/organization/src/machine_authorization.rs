//! Explicit, attributable MACHINE_AUTHORIZATION policy ownership. The ordinary
//! policy CRUD cannot create or mutate this type. No HTTP route is installed.
//! The fixed schema intentionally provides no role hierarchy or entity attrs;
//! decisions use the already authenticated exact machine/operation context.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use mmf_security::cedar::{CedarConfig, CedarEntityTypes, CedarPolicyEngine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    authorize_forwarded_principal, postgres::PostgresOrganizationStore, CedarPolicyDocument,
    ForwardedPrincipal, PolicySetStatus,
};

pub const MACHINE_AUTHORIZATION_SCHEMA_VERSION: &str = "MartyMachine/1.0";
pub const MACHINE_AUTHORIZATION_SCHEMA: &str =
    include_str!("machine_authorization_schema.cedarschema");
pub const MACHINE_AUTHORIZATION_POLICY_TYPE: &str = "MACHINE_AUTHORIZATION";
pub const MACHINE_AUTHORIZATION_POLICY_ACTION: &str = "urn:marty:machine:authenticate";

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MachineAuthorizationPolicyError {
    #[error("machine authorization policy request is invalid")]
    Invalid,
    #[error("machine authorization policy access is denied")]
    AccessDenied,
    #[error("machine authorization policy revision or state conflicts")]
    Conflict,
    #[error("machine authorization policy is unavailable")]
    Unavailable,
}
use MachineAuthorizationPolicyError as Error;

#[derive(Clone, Debug)]
pub struct MachineAuthorizationPolicyInput {
    pub name: String,
    pub description: Option<String>,
    pub policies: Vec<CedarPolicyDocument>,
}

/// Immutable owner history. A snapshot is not a current-source observation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineAuthorizationPolicySnapshot {
    pub organization_id: Uuid,
    pub policy_set_id: Uuid,
    pub revision: u64,
    pub policy_type: String,
    pub status: PolicySetStatus,
    pub name: String,
    pub description: Option<String>,
    pub policies: Vec<CedarPolicyDocument>,
    pub schema_version: String,
    pub schema_digest: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
impl MachineAuthorizationPolicySnapshot {
    pub fn policy_source(&self) -> String {
        self.policies
            .iter()
            .filter(|p| p.enabled)
            .map(|p| p.cedar_text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n")
    }
    /// One digest binds the exact selected text and schema, not an unverified
    /// policy identifier or just its revision counter.
    pub fn policy_digest(&self) -> Result<String, Error> {
        digest(&json!({"policy_source":self.policy_source(),"schema":MACHINE_AUTHORIZATION_SCHEMA}))
    }
    fn validate(&self) -> Result<(), Error> {
        if self.organization_id.is_nil()
            || self.policy_set_id.is_nil()
            || !(1..=9_007_199_254_740_991).contains(&self.revision)
            || self.policy_type != MACHINE_AUTHORIZATION_POLICY_TYPE
            || self.schema_version != MACHINE_AUTHORIZATION_SCHEMA_VERSION
            || self.schema_digest != schema_digest()
            || !bounded_text(&self.created_by, 255)
            || self.updated_at < self.created_at
        {
            return Err(Error::Invalid);
        }
        validate_policy_input(&MachineAuthorizationPolicyInput {
            name: self.name.clone(),
            description: self.description.clone(),
            policies: self.policies.clone(),
        })
    }
}

/// A current read from the actual owner. No constructor or Deserialize exists;
/// historical policy documents cannot be promoted into this observation.
pub struct CurrentMachineAuthorizationPolicy {
    snapshot: MachineAuthorizationPolicySnapshot,
    snapshot_bytes: Vec<u8>,
    history_ref: String,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}
impl CurrentMachineAuthorizationPolicy {
    pub fn snapshot(&self) -> &MachineAuthorizationPolicySnapshot {
        &self.snapshot
    }
    pub fn snapshot_bytes(&self) -> &[u8] {
        &self.snapshot_bytes
    }
    pub fn history_ref(&self) -> &str {
        &self.history_ref
    }
    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
    pub fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }
}

#[derive(Clone)]
pub struct MachineAuthorizationPolicyOwner {
    store: PostgresOrganizationStore,
}

enum Mutation {
    Create(MachineAuthorizationPolicyInput),
    Replace(MachineAuthorizationPolicyInput),
    Activate,
    Archive,
}
impl Mutation {
    fn action(&self) -> &'static str {
        match self {
            Self::Create(_) => "CREATE",
            Self::Replace(_) => "REPLACE",
            Self::Activate => "ACTIVATE",
            Self::Archive => "ARCHIVE",
        }
    }
    fn permission(&self) -> &'static str {
        match self {
            Self::Create(_) => "machine-authorization-policy:create",
            Self::Replace(_) => "machine-authorization-policy:update",
            Self::Activate => "machine-authorization-policy:activate",
            Self::Archive => "machine-authorization-policy:archive",
        }
    }
}

impl MachineAuthorizationPolicyOwner {
    pub fn new(store: PostgresOrganizationStore) -> Self {
        Self { store }
    }

    pub async fn create(
        &self,
        organization: Uuid,
        actor: &ForwardedPrincipal,
        input: MachineAuthorizationPolicyInput,
    ) -> Result<MachineAuthorizationPolicySnapshot, Error> {
        validate_policy_input(&input)?;
        self.mutate(organization, actor, None, Mutation::Create(input))
            .await
    }
    pub async fn replace(
        &self,
        organization: Uuid,
        actor: &ForwardedPrincipal,
        policy: Uuid,
        expected_revision: u64,
        input: MachineAuthorizationPolicyInput,
    ) -> Result<MachineAuthorizationPolicySnapshot, Error> {
        validate_policy_input(&input)?;
        self.mutate(
            organization,
            actor,
            Some((policy, expected_revision)),
            Mutation::Replace(input),
        )
        .await
    }
    pub async fn activate(
        &self,
        organization: Uuid,
        actor: &ForwardedPrincipal,
        policy: Uuid,
        expected_revision: u64,
    ) -> Result<MachineAuthorizationPolicySnapshot, Error> {
        self.mutate(
            organization,
            actor,
            Some((policy, expected_revision)),
            Mutation::Activate,
        )
        .await
    }
    pub async fn archive(
        &self,
        organization: Uuid,
        actor: &ForwardedPrincipal,
        policy: Uuid,
        expected_revision: u64,
    ) -> Result<MachineAuthorizationPolicySnapshot, Error> {
        self.mutate(
            organization,
            actor,
            Some((policy, expected_revision)),
            Mutation::Archive,
        )
        .await
    }
    pub async fn inspect(
        &self,
        organization: Uuid,
        actor: &ForwardedPrincipal,
        policy: Uuid,
    ) -> Result<MachineAuthorizationPolicySnapshot, Error> {
        let mut tx = self.begin().await?;
        self.authorize(
            &mut tx,
            organization,
            actor,
            "machine-authorization-policy:view",
        )
        .await?;
        let snapshot = load_current(&mut tx, organization, policy, true).await?.0;
        self.authorize(
            &mut tx,
            organization,
            actor,
            "machine-authorization-policy:view",
        )
        .await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(snapshot)
    }
    async fn begin(&self) -> Result<Transaction<'_, Postgres>, Error> {
        let mut tx = self.store.pool().begin().await.map_err(unavailable)?;
        sqlx::raw_sql("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        Ok(tx)
    }
    async fn authorize(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        organization: Uuid,
        actor: &ForwardedPrincipal,
        permission: &str,
    ) -> Result<(), Error> {
        let ForwardedPrincipal::User { user_id } = actor else {
            return Err(Error::AccessDenied);
        };
        if organization.is_nil() || !bounded_text(user_id, 255) {
            return Err(Error::AccessDenied);
        }
        let status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM organization_service.organizations WHERE id=$1 FOR SHARE",
        )
        .bind(organization)
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?;
        if status.as_deref() != Some("active") {
            return Err(Error::AccessDenied);
        }
        let member = crate::locked_membership::load(&self.store, tx, user_id, organization)
            .await
            .map_err(unavailable)?
            .ok_or(Error::AccessDenied)?;
        authorize_forwarded_principal(organization, actor, permission, false, Some(&member))
            .map_err(|_| Error::AccessDenied)?;
        Ok(())
    }
    async fn mutate(
        &self,
        organization: Uuid,
        actor: &ForwardedPrincipal,
        expected: Option<(Uuid, u64)>,
        mutation: Mutation,
    ) -> Result<MachineAuthorizationPolicySnapshot, Error> {
        let ForwardedPrincipal::User { user_id } = actor else {
            return Err(Error::AccessDenied);
        };
        let mut tx = self.begin().await?;
        self.authorize(&mut tx, organization, actor, mutation.permission())
            .await?;
        let previous = match expected {
            Some((id, revision)) => {
                let snapshot = load_current(&mut tx, organization, id, true).await?.0;
                if snapshot.revision != revision || revision >= 9_007_199_254_740_991 {
                    return Err(Error::Conflict);
                }
                Some(snapshot)
            }
            None => None,
        };
        self.authorize(&mut tx, organization, actor, mutation.permission())
            .await?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
        if previous.as_ref().is_some_and(|p| p.updated_at >= now) {
            return Err(Error::Unavailable);
        }
        let mut next = match (&mutation, previous) {
            (Mutation::Create(input), None) => MachineAuthorizationPolicySnapshot {
                organization_id: organization,
                policy_set_id: Uuid::new_v4(),
                revision: 1,
                policy_type: MACHINE_AUTHORIZATION_POLICY_TYPE.into(),
                status: PolicySetStatus::Draft,
                name: input.name.clone(),
                description: input.description.clone(),
                policies: input.policies.clone(),
                schema_version: MACHINE_AUTHORIZATION_SCHEMA_VERSION.into(),
                schema_digest: schema_digest(),
                created_by: user_id.clone(),
                created_at: now,
                updated_at: now,
            },
            (Mutation::Replace(input), Some(mut p)) if p.status != PolicySetStatus::Active => {
                p.name = input.name.clone();
                p.description = input.description.clone();
                p.policies = input.policies.clone();
                p.status = PolicySetStatus::Draft;
                p
            }
            (Mutation::Activate, Some(mut p)) if p.status != PolicySetStatus::Active => {
                p.status = PolicySetStatus::Active;
                p
            }
            (Mutation::Archive, Some(mut p)) if p.status == PolicySetStatus::Active => {
                p.status = PolicySetStatus::Archived;
                p
            }
            _ => return Err(Error::Conflict),
        };
        if expected.is_some() {
            next.revision += 1;
            next.updated_at = now;
        }
        next.validate()?;
        let policies = serde_json::to_string(&next.policies).map_err(unavailable)?;
        if expected.is_none() {
            sqlx::query("INSERT INTO organization_service.policy_sets(id,organization_id,name,description,policy_type,status,cedar_policies,cedar_schema_version,created_by,created_at,updated_at,machine_policy_revision) VALUES($1,$2,$3,$4,'MACHINE_AUTHORIZATION',$5,$6,$7,$8,$9,$9,$10)")
                .bind(next.policy_set_id).bind(organization).bind(&next.name).bind(&next.description).bind(next.status.as_str()).bind(policies).bind(&next.schema_version).bind(&next.created_by).bind(now).bind(next.revision as i64)
                .execute(&mut *tx).await.map_err(unavailable)?;
        } else {
            sqlx::query("UPDATE organization_service.policy_sets SET name=$3,description=$4,status=$5,cedar_policies=$6,updated_at=$7,machine_policy_revision=$8 WHERE organization_id=$1 AND id=$2 AND policy_type='MACHINE_AUTHORIZATION'")
                .bind(organization).bind(next.policy_set_id).bind(&next.name).bind(&next.description).bind(next.status.as_str()).bind(policies).bind(now).bind(next.revision as i64)
                .execute(&mut *tx).await.map_err(unavailable)?;
        }
        let bytes = serde_json::to_vec(&next).map_err(unavailable)?;
        let document = serde_json::to_value(&next).map_err(unavailable)?;
        sqlx::query("INSERT INTO organization_service.machine_authorization_policy_history(organization_id,policy_set_id,revision,action,actor_user_id,occurred_at,snapshot_bytes,snapshot,snapshot_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(organization).bind(next.policy_set_id).bind(next.revision as i64).bind(mutation.action()).bind(user_id).bind(now).bind(&bytes).bind(document).bind(byte_digest(&bytes))
            .execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(next)
    }
}

/// Read-only adapter for a separately provisioned owner reader. Caller hints
/// select an exact tenant/policy; a generic CUSTOM policy never qualifies.
#[derive(Clone)]
pub struct PgMachineAuthorizationPolicySource {
    pool: PgPool,
}
impl PgMachineAuthorizationPolicySource {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    pub async fn readiness(&self) -> Result<(), Error> {
        let mut connection = self.pool.acquire().await.map_err(unavailable)?;
        validate_machine_authorization_schema(&mut connection).await?;
        let allowed = [
            "rust_schema_versions",
            "organizations",
            "policy_sets",
            "machine_authorization_policy_history",
        ];
        let valid:bool=sqlx::query_scalar("SELECT current_user=session_user AND NOT pg_is_in_recovery()
          AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE (r.rolname=current_user OR pg_has_role(current_user,r.oid,'MEMBER')) AND (
            r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolbypassrls OR r.rolreplication
            OR left(r.rolname::text,3)='pg_'
            OR EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid AND m.admin_option)
            OR EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND d.datdba=r.oid)
            OR has_database_privilege(r.oid,current_database(),'CREATE,CREATE WITH GRANT OPTION,CONNECT WITH GRANT OPTION,TEMPORARY WITH GRANT OPTION')
            OR EXISTS(SELECT 1 FROM pg_namespace n WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema'
                AND (n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE,CREATE WITH GRANT OPTION,USAGE WITH GRANT OPTION')))
            OR EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
                WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema' AND t.relkind IN('r','p','v','m','f','S') AND (
                  t.relowner=r.oid OR has_table_privilege(r.oid,t.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,DELETE WITH GRANT OPTION,TRUNCATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION,TRIGGER WITH GRANT OPTION')
                  OR CASE WHEN current_setting('server_version_num')::INT>=170000 THEN has_table_privilege(r.oid,t.oid,'MAINTAIN') ELSE false END
                  OR has_any_column_privilege(r.oid,t.oid,'INSERT,UPDATE,REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION')
                  OR ((n.nspname<>'organization_service' OR NOT(t.relname=ANY($1))) AND (has_table_privilege(r.oid,t.oid,'SELECT') OR has_any_column_privilege(r.oid,t.oid,'SELECT')))))
            OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema' AND
                  (p.proowner=r.oid OR has_function_privilege(r.oid,p.oid,'EXECUTE WITH GRANT OPTION') OR (p.prosecdef AND has_function_privilege(r.oid,p.oid,'EXECUTE'))))))
          AND has_schema_privilege(current_user,'organization_service','USAGE')
          AND NOT EXISTS(SELECT 1 FROM unnest($1::TEXT[]) name WHERE NOT has_table_privilege(current_user,'organization_service.'||name,'SELECT'))")
            .bind(allowed.as_slice()).fetch_one(&mut *connection).await.map_err(unavailable)?;
        if !valid {
            return Err(Error::AccessDenied);
        }
        Ok(())
    }
    pub async fn observe_current(
        &self,
        organization: Uuid,
        policy: Uuid,
        original_now: DateTime<Utc>,
    ) -> Result<CurrentMachineAuthorizationPolicy, Error> {
        if organization.is_nil() || policy.is_nil() {
            return Err(Error::Invalid);
        }
        // Constructor/startup success is not a lasting privilege or schema
        // permit. Recheck the actual owner reader before every current read.
        self.readiness().await?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        sqlx::raw_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY; SET LOCAL statement_timeout='5s'").execute(&mut *tx).await.map_err(unavailable)?;
        let observed_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM organization_service.organizations WHERE id=$1")
                .bind(organization)
                .fetch_optional(&mut *tx)
                .await
                .map_err(unavailable)?;
        if status.as_deref() != Some("active") {
            return Err(Error::AccessDenied);
        }
        let (snapshot, snapshot_bytes, history_digest) =
            load_current(&mut tx, organization, policy, false).await?;
        let original_deadline = original_now
            .checked_add_signed(Duration::seconds(30))
            .ok_or(Error::Invalid)?;
        // Shorten to PostgreSQL precision; rounding must never extend the
        // original upper bound, including in a deferred database guard.
        let valid_until = DateTime::from_timestamp_micros(original_deadline.timestamp_micros())
            .ok_or(Error::Invalid)?;
        if snapshot.status != PolicySetStatus::Active
            || snapshot.updated_at > observed_at
            || observed_at < original_now
            || observed_at >= valid_until
        {
            return Err(Error::Unavailable);
        }
        let completed_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
        if completed_at < observed_at || completed_at >= valid_until {
            return Err(Error::Unavailable);
        }
        tx.commit().await.map_err(unavailable)?;
        let after = Utc::now();
        if after < completed_at || after >= valid_until {
            return Err(Error::Unavailable);
        }
        let history_ref = format!(
            "urn:marty:machine-authorization-policy:{organization}:{policy}:{}:{}",
            snapshot.revision,
            history_digest
                .strip_prefix("sha256:")
                .ok_or(Error::Unavailable)?
        );
        Ok(CurrentMachineAuthorizationPolicy {
            snapshot,
            snapshot_bytes,
            history_ref,
            observed_at,
            valid_until,
        })
    }
}

async fn load_current(
    connection: &mut PgConnection,
    organization: Uuid,
    policy: Uuid,
    lock: bool,
) -> Result<(MachineAuthorizationPolicySnapshot, Vec<u8>, String), Error> {
    // The query is selected from literals; it never interpolates caller SQL.
    let query = if lock {
        "SELECT p.*,h.snapshot_bytes,h.snapshot,h.snapshot_digest FROM organization_service.policy_sets p JOIN organization_service.machine_authorization_policy_history h ON h.organization_id=p.organization_id AND h.policy_set_id=p.id AND h.revision=p.machine_policy_revision WHERE p.organization_id=$1 AND p.id=$2 AND p.policy_type='MACHINE_AUTHORIZATION' FOR UPDATE OF p"
    } else {
        "SELECT p.*,h.snapshot_bytes,h.snapshot,h.snapshot_digest FROM organization_service.policy_sets p JOIN organization_service.machine_authorization_policy_history h ON h.organization_id=p.organization_id AND h.policy_set_id=p.id AND h.revision=p.machine_policy_revision WHERE p.organization_id=$1 AND p.id=$2 AND p.policy_type='MACHINE_AUTHORIZATION'"
    };
    let row = sqlx::query(query)
        .bind(organization)
        .bind(policy)
        .fetch_optional(connection)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unavailable)?;
    let bytes: Vec<u8> = row.try_get("snapshot_bytes").map_err(unavailable)?;
    let snapshot: MachineAuthorizationPolicySnapshot =
        serde_json::from_slice(&bytes).map_err(unavailable)?;
    snapshot.validate()?;
    let digest: String = row.try_get("snapshot_digest").map_err(unavailable)?;
    let stored: Value = row.try_get("snapshot").map_err(unavailable)?;
    let revision: i64 = row
        .try_get("machine_policy_revision")
        .map_err(unavailable)?;
    let policies: String = row.try_get("cedar_policies").map_err(unavailable)?;
    if snapshot.organization_id != organization
        || snapshot.policy_set_id != policy
        || snapshot.revision != revision as u64
        || digest != byte_digest(&bytes)
        || stored != serde_json::to_value(&snapshot).map_err(unavailable)?
        || snapshot.status.as_str() != row.try_get::<String, _>("status").map_err(unavailable)?
        || snapshot.name != row.try_get::<String, _>("name").map_err(unavailable)?
        || snapshot.description
            != row
                .try_get::<Option<String>, _>("description")
                .map_err(unavailable)?
        || serde_json::to_value(&snapshot.policies).map_err(unavailable)?
            != serde_json::from_str::<Value>(&policies).map_err(unavailable)?
        || snapshot.schema_version
            != row
                .try_get::<String, _>("cedar_schema_version")
                .map_err(unavailable)?
        || Some(snapshot.created_by.clone())
            != row
                .try_get::<Option<String>, _>("created_by")
                .map_err(unavailable)?
        || snapshot.created_at
            != row
                .try_get::<DateTime<Utc>, _>("created_at")
                .map_err(unavailable)?
        || snapshot.updated_at
            != row
                .try_get::<DateTime<Utc>, _>("updated_at")
                .map_err(unavailable)?
    {
        return Err(Error::Unavailable);
    }
    Ok((snapshot, bytes, digest))
}

pub fn machine_entity_types() -> CedarEntityTypes {
    CedarEntityTypes {
        principal: "MartyMachine::Principal".into(),
        action: "MartyMachine::Action".into(),
        resource: "MartyMachine::Identity".into(),
    }
}
pub fn compile_machine_policy(source: &str) -> Result<CedarPolicyEngine, Error> {
    CedarPolicyEngine::from_human_schema(
        source,
        MACHINE_AUTHORIZATION_SCHEMA,
        CedarConfig {
            entity_types: machine_entity_types(),
            ..CedarConfig::default()
        },
    )
    .map_err(|_| Error::Invalid)
}
pub fn validate_policy_input(input: &MachineAuthorizationPolicyInput) -> Result<(), Error> {
    if !bounded_text(&input.name, 255)
        || input
            .description
            .as_ref()
            .is_some_and(|s| !bounded_text(s, 4096))
        || input.policies.is_empty()
        || input.policies.len() > 32
    {
        return Err(Error::Invalid);
    }
    let mut ids = BTreeSet::new();
    let mut enabled = Vec::new();
    for policy in &input.policies {
        if !bounded_text(&policy.policy_id, 128)
            || !ids.insert(&policy.policy_id)
            || !matches!(policy.effect.as_str(), "permit" | "forbid")
            || policy.cedar_text.len() > 65536
            || policy.cedar_text.trim().is_empty()
            || policy
                .description
                .as_ref()
                .is_some_and(|s| !bounded_text(s, 4096))
        {
            return Err(Error::Invalid);
        }
        if policy.enabled {
            enabled.push(policy.cedar_text.as_str());
        }
    }
    let source = enabled.join("\n\n");
    if source.is_empty() || source.len() > 196608 {
        return Err(Error::Invalid);
    }
    let validator = mmf_security::CedarPolicyValidator::from_human_schema(
        MACHINE_AUTHORIZATION_SCHEMA,
        CedarConfig {
            entity_types: machine_entity_types(),
            ..CedarConfig::default()
        },
    )
    .map_err(|_| Error::Invalid)?;
    if !crate::validate_policy_documents(&input.policies, &validator).is_empty() {
        return Err(Error::Invalid);
    }
    compile_machine_policy(&source)?;
    Ok(())
}
fn bounded_text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn byte_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn schema_digest() -> String {
    byte_digest(MACHINE_AUTHORIZATION_SCHEMA.as_bytes())
}
fn digest(document: &Value) -> Result<String, Error> {
    Ok(byte_digest(
        &serde_json::to_vec(document).map_err(unavailable)?,
    ))
}
fn unavailable<E>(_: E) -> Error {
    Error::Unavailable
}

pub async fn validate_machine_authorization_schema(
    connection: &mut PgConnection,
) -> Result<(), Error> {
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organization_service.rust_schema_versions WHERE version='rust_organization_machine_authorization_0006') AND to_regclass('organization_service.machine_authorization_policy_history') IS NOT NULL AND EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='organization_service.policy_sets'::regclass AND attname='machine_policy_revision' AND atttypid='int8'::regtype AND NOT attisdropped)").fetch_one(&mut *connection).await.map_err(unavailable)?;
    let guards:i64=sqlx::query_scalar("WITH expected(table_name,trigger_name,function_name,trigger_type,deferred) AS (VALUES ('policy_sets','machine_policy_guard','guard_machine_authorization_policy',31,false),('policy_sets','machine_policy_history_complete','check_machine_authorization_policy_history',21,true),('machine_authorization_policy_history','machine_policy_history_guard','guard_machine_authorization_policy_history',7,false),('machine_authorization_policy_history','machine_policy_history_immutable','reject_machine_authorization_history_mutation',58,false)) SELECT count(*) FROM expected e JOIN pg_trigger t ON t.tgrelid=to_regclass('organization_service.'||e.table_name) AND t.tgname=e.trigger_name JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_language l ON l.oid=p.prolang WHERE NOT t.tgisinternal AND t.tgenabled='O' AND t.tgqual IS NULL AND t.tgtype=e.trigger_type AND t.tgnargs=0 AND t.tgattr=''::int2vector AND t.tgdeferrable=e.deferred AND t.tginitdeferred=e.deferred AND (t.tgconstraint<>0)=e.deferred AND t.tgfoid=to_regprocedure('organization_service.'||e.function_name||'()') AND NOT p.prosecdef AND p.prorettype='trigger'::regtype AND p.prokind='f' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog']::TEXT[]")
        .fetch_one(&mut *connection).await.map_err(unavailable)?;
    let constraints:i64=sqlx::query_scalar("WITH expected(name,expression) AS (VALUES
        ('machine_policy_history_bytes','((convert_from(snapshot_bytes, ''UTF8''::name))::jsonb = snapshot)'),
        ('machine_policy_history_digest','(snapshot_digest = (''sha256:''::text || encode(sha256(snapshot_bytes), ''hex''::text)))'))
        SELECT count(*) FROM expected e JOIN pg_constraint c ON c.conname=e.name AND c.conrelid='organization_service.machine_authorization_policy_history'::regclass
        WHERE c.contype='c' AND c.convalidated AND c.conislocal AND pg_get_expr(c.conbin,c.conrelid)=e.expression")
        .fetch_one(&mut *connection).await.map_err(unavailable)?;
    let unique:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_index i JOIN pg_constraint c ON c.conindid=i.indexrelid
        WHERE i.indrelid='organization_service.machine_authorization_policy_history'::regclass AND c.contype='p'
          AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive AND i.indpred IS NULL AND i.indexprs IS NULL
          AND i.indnkeyatts=3 AND i.indnatts=3
          AND (SELECT array_agg(a.attname::TEXT ORDER BY k.ordinality) FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ordinality)
            JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum)=ARRAY['organization_id','policy_set_id','revision'])")
        .fetch_one(&mut *connection).await.map_err(unavailable)?;
    if !valid || guards != 4 || constraints != 2 || !unique {
        return Err(Error::Unavailable);
    }
    let migration = include_str!("../migrations/0006_machine_authorization_policy.sql");
    for function in [
        "guard_machine_authorization_policy",
        "guard_machine_authorization_policy_history",
        "check_machine_authorization_policy_history",
        "reject_machine_authorization_history_mutation",
    ] {
        let marker = format!("FUNCTION organization_service.{function}()");
        let expected = migration
            .split_once(&marker)
            .and_then(|(_, s)| s.split_once("AS $$"))
            .and_then(|(_, s)| s.split_once("$$;"))
            .map(|(body, _)| body)
            .ok_or(Error::Unavailable)?;
        let actual:String=sqlx::query_scalar("SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='organization_service' AND p.proname=$1 AND p.pronargs=0")
            .bind(function).fetch_one(&mut *connection).await.map_err(unavailable)?;
        if actual != expected {
            return Err(Error::Unavailable);
        }
    }
    Ok(())
}
