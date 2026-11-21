//! Explicit Organization ownership for exact-operation delegated-use policy.
//!
//! These tables and human permissions are separate from ordinary policy CRUD,
//! machine authentication and consumer-owned business/domain authorization.

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

pub const DELEGATION_USE_POLICY_SCHEMA_VERSION: &str = "MartyDelegatedUse/1.0";
pub const DELEGATION_USE_POLICY_TYPE: &str = "DELEGATION_USE";
const OBSERVATION_PROFILE: &str = "urn:marty:delegation-use-policy-source:v1";
const MAX_REVISION: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DelegationUsePolicyError {
    #[error("delegation use policy request is invalid")]
    Invalid,
    #[error("delegation use policy access is denied")]
    AccessDenied,
    #[error("delegation use policy revision or state conflicts")]
    Conflict,
    #[error("delegation use policy source is unavailable")]
    Unavailable,
}
use DelegationUsePolicyError as Error;

#[derive(Clone, Debug)]
pub struct DelegationUsePolicyInput {
    pub name: String,
    pub description: Option<String>,
    /// Explicit owner-approved Action IDs. No wildcard action or request-owned
    /// schema is accepted. The principal/resource/context schema is fixed.
    pub actions: Vec<String>,
    pub policies: Vec<CedarPolicyDocument>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationUsePolicySnapshot {
    pub organization_id: Uuid,
    pub policy_id: Uuid,
    pub revision: u64,
    pub policy_type: String,
    pub status: PolicySetStatus,
    pub name: String,
    pub description: Option<String>,
    pub actions: Vec<String>,
    pub policies: Vec<CedarPolicyDocument>,
    pub schema_version: String,
    pub schema: String,
    pub policy_source: String,
    pub policy_digest: String,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
impl DelegationUsePolicySnapshot {
    fn refresh_material(&mut self) -> Result<(), Error> {
        self.schema = delegation_use_schema(&self.actions)?;
        self.policy_source = policy_source(&self.policies);
        self.policy_digest = material_digest(&self.policy_source, &self.schema)?;
        Ok(())
    }
    fn validate(&self) -> Result<(), Error> {
        if self.organization_id.is_nil()
            || self.policy_id.is_nil()
            || !(1..=MAX_REVISION).contains(&self.revision)
            || self.policy_type != DELEGATION_USE_POLICY_TYPE
            || self.schema_version != DELEGATION_USE_POLICY_SCHEMA_VERSION
            || !bounded_text(&self.created_by, 255)
            || self.updated_at < self.created_at
            || self.schema != delegation_use_schema(&self.actions)?
            || self.policy_source != policy_source(&self.policies)
            || self.policy_digest != material_digest(&self.policy_source, &self.schema)?
        {
            return Err(Error::Invalid);
        }
        validate_policy_input(&DelegationUsePolicyInput {
            name: self.name.clone(),
            description: self.description.clone(),
            actions: self.actions.clone(),
            policies: self.policies.clone(),
        })
    }
}

/// Exact actor projection used only for source binding, never a login token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationPolicyPrincipal {
    #[serde(rename = "type")]
    pub principal_type: String,
    pub id: String,
}
impl DelegationPolicyPrincipal {
    fn validate(&self) -> bool {
        matches!(
            self.principal_type.as_str(),
            "USER" | "ORGANIZATION" | "SERVICE_ACCOUNT" | "MACHINE_IDENTITY" | "EXTERNAL"
        ) && valid_uri(&self.id)
    }
}

/// The whole current Cedar request. No arbitrary entity attributes, role graph
/// or external-domain evidence is manufactured by this source.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationUsePolicyScope {
    pub organization_id: Uuid,
    pub grant_id: Uuid,
    pub grant_revision: u64,
    pub actor: DelegationPolicyPrincipal,
    pub grantor: DelegationPolicyPrincipal,
    pub subject: DelegationPolicyPrincipal,
    pub delegate: DelegationPolicyPrincipal,
    pub action: String,
    pub audience: String,
    pub resource: String,
    pub operation_profile: String,
    pub operation_digest: String,
    pub constraint_context: Value,
    pub constraint_evidence_digest: String,
}
impl DelegationUsePolicyScope {
    pub fn validate(&self) -> Result<(), Error> {
        if self.organization_id.is_nil()
            || self.grant_id.is_nil()
            || !(1..=MAX_REVISION).contains(&self.grant_revision)
            || self.actor != self.delegate
            || [&self.actor, &self.grantor, &self.subject, &self.delegate]
                .iter()
                .any(|p| !p.validate())
            || [
                &self.action,
                &self.audience,
                &self.resource,
                &self.operation_profile,
            ]
            .iter()
            .any(|v| !valid_uri(v))
            || !valid_digest(&self.operation_digest)
            || self.constraint_evidence_digest != self.operation_digest
            || self.constraint_context
                != json!({"mode":"EXACT_OPERATION", "request_profile":self.operation_profile,"request_digest":self.operation_digest})
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub fn entities(&self) -> Value {
        json!([
            {"uid":{"type":"MartyDelegatedUse::Principal","id":self.actor.id},"attrs":{},"parents":[]},
            {"uid":{"type":"MartyDelegatedUse::Resource","id":self.resource},"attrs":{},"parents":[]}
        ])
    }
}

/// Original committed source observation. Its constructor and Deserialize are
/// deliberately unavailable: historical records cannot become fresh authority.
pub struct CurrentDelegationUsePolicy {
    snapshot: DelegationUsePolicySnapshot,
    scope: DelegationUsePolicyScope,
    evidence_ref: String,
    evidence_bytes: Vec<u8>,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}
impl CurrentDelegationUsePolicy {
    pub fn snapshot(&self) -> &DelegationUsePolicySnapshot {
        &self.snapshot
    }
    pub fn scope(&self) -> &DelegationUsePolicyScope {
        &self.scope
    }
    pub fn evidence_ref(&self) -> &str {
        &self.evidence_ref
    }
    pub fn evidence_bytes(&self) -> &[u8] {
        &self.evidence_bytes
    }
    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
    pub fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }
}

#[derive(Clone)]
pub struct DelegationUsePolicyOwner {
    store: PostgresOrganizationStore,
}
enum Mutation {
    Create(DelegationUsePolicyInput),
    Replace(DelegationUsePolicyInput),
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
            Self::Create(_) => "delegation-use-policy:create",
            Self::Replace(_) => "delegation-use-policy:update",
            Self::Activate => "delegation-use-policy:activate",
            Self::Archive => "delegation-use-policy:archive",
        }
    }
}
impl DelegationUsePolicyOwner {
    pub fn new(store: PostgresOrganizationStore) -> Self {
        Self { store }
    }
    pub async fn create(
        &self,
        organization: Uuid,
        actor: &ForwardedPrincipal,
        input: DelegationUsePolicyInput,
    ) -> Result<DelegationUsePolicySnapshot, Error> {
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
        input: DelegationUsePolicyInput,
    ) -> Result<DelegationUsePolicySnapshot, Error> {
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
    ) -> Result<DelegationUsePolicySnapshot, Error> {
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
    ) -> Result<DelegationUsePolicySnapshot, Error> {
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
    ) -> Result<DelegationUsePolicySnapshot, Error> {
        let mut tx = self.begin().await?;
        self.authorize(&mut tx, organization, actor, "delegation-use-policy:view")
            .await?;
        let snapshot = load_current(&mut tx, organization, policy, true).await?.0;
        self.authorize(&mut tx, organization, actor, "delegation-use-policy:view")
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
        let member = self
            .store
            .member_by_user_and_organization_for_update_in_transaction(tx, user_id, organization)
            .await
            .map_err(unavailable)?
            .ok_or(Error::AccessDenied)?;
        sqlx::query("SELECT r.id FROM organization_service.member_roles mr JOIN organization_service.roles r ON r.id=mr.role_id WHERE mr.member_id=$1 AND r.organization_id=$2 ORDER BY r.id FOR SHARE OF mr,r").bind(member.id).bind(organization).fetch_all(&mut **tx).await.map_err(unavailable)?;
        sqlx::query("SELECT p.id FROM organization_service.member_roles mr JOIN organization_service.roles r ON r.id=mr.role_id JOIN organization_service.role_permissions rp ON rp.role_id=r.id JOIN organization_service.permissions p ON p.id=rp.permission_id WHERE mr.member_id=$1 AND r.organization_id=$2 ORDER BY p.id FOR SHARE OF rp,p").bind(member.id).bind(organization).fetch_all(&mut **tx).await.map_err(unavailable)?;
        let member = self
            .store
            .member_by_user_and_organization_for_update_in_transaction(tx, user_id, organization)
            .await
            .map_err(unavailable)?
            .ok_or(Error::AccessDenied)?;
        if member
            .roles
            .iter()
            .any(|r| r.organization_id != organization)
        {
            return Err(Error::AccessDenied);
        }
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
    ) -> Result<DelegationUsePolicySnapshot, Error> {
        let ForwardedPrincipal::User { user_id } = actor else {
            return Err(Error::AccessDenied);
        };
        let mut tx = self.begin().await?;
        self.authorize(&mut tx, organization, actor, mutation.permission())
            .await?;
        let previous = if let Some((id, revision)) = expected {
            let p = load_current(&mut tx, organization, id, true).await?.0;
            if p.revision != revision || revision >= MAX_REVISION {
                return Err(Error::Conflict);
            }
            Some(p)
        } else {
            None
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
            (Mutation::Create(input), None) => DelegationUsePolicySnapshot {
                organization_id: organization,
                policy_id: Uuid::new_v4(),
                revision: 1,
                policy_type: DELEGATION_USE_POLICY_TYPE.into(),
                status: PolicySetStatus::Draft,
                name: input.name.clone(),
                description: input.description.clone(),
                actions: input.actions.clone(),
                policies: input.policies.clone(),
                schema_version: DELEGATION_USE_POLICY_SCHEMA_VERSION.into(),
                schema: String::new(),
                policy_source: String::new(),
                policy_digest: String::new(),
                created_by: user_id.clone(),
                created_at: now,
                updated_at: now,
            },
            (Mutation::Replace(input), Some(mut p)) if p.status != PolicySetStatus::Active => {
                p.name = input.name.clone();
                p.description = input.description.clone();
                p.actions = input.actions.clone();
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
        next.refresh_material()?;
        next.validate()?;
        let bytes = serde_json::to_vec(&next).map_err(unavailable)?;
        if bytes.len() > 262_144 {
            return Err(Error::Invalid);
        }
        let document = serde_json::to_value(&next).map_err(unavailable)?;
        let digest = byte_digest(&bytes);
        if expected.is_none() {
            sqlx::query("INSERT INTO organization_service.delegation_use_policies(organization_id,policy_id,revision,status,snapshot_bytes,snapshot,snapshot_digest) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(organization).bind(next.policy_id).bind(next.revision as i64).bind(next.status.as_str()).bind(&bytes).bind(&document).bind(&digest).execute(&mut *tx).await.map_err(unavailable)?;
        } else {
            sqlx::query("UPDATE organization_service.delegation_use_policies SET revision=$3,status=$4,snapshot_bytes=$5,snapshot=$6,snapshot_digest=$7 WHERE organization_id=$1 AND policy_id=$2").bind(organization).bind(next.policy_id).bind(next.revision as i64).bind(next.status.as_str()).bind(&bytes).bind(&document).bind(&digest).execute(&mut *tx).await.map_err(unavailable)?;
        }
        sqlx::query("INSERT INTO organization_service.delegation_use_policy_history(organization_id,policy_id,revision,action,actor_user_id,occurred_at,snapshot_bytes,snapshot,snapshot_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)").bind(organization).bind(next.policy_id).bind(next.revision as i64).bind(mutation.action()).bind(user_id).bind(now).bind(&bytes).bind(&document).bind(digest).execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(next)
    }
}

async fn load_current(
    connection: &mut PgConnection,
    organization: Uuid,
    policy: Uuid,
    lock: bool,
) -> Result<(DelegationUsePolicySnapshot, Vec<u8>, String), Error> {
    let query = if lock {
        "SELECT p.*,h.snapshot_bytes AS history_bytes,h.snapshot AS history_document,h.snapshot_digest AS history_digest FROM organization_service.delegation_use_policies p JOIN organization_service.delegation_use_policy_history h USING(organization_id,policy_id,revision) WHERE p.organization_id=$1 AND p.policy_id=$2 FOR UPDATE OF p"
    } else {
        "SELECT p.*,h.snapshot_bytes AS history_bytes,h.snapshot AS history_document,h.snapshot_digest AS history_digest FROM organization_service.delegation_use_policies p JOIN organization_service.delegation_use_policy_history h USING(organization_id,policy_id,revision) WHERE p.organization_id=$1 AND p.policy_id=$2"
    };
    let row = sqlx::query(query)
        .bind(organization)
        .bind(policy)
        .fetch_optional(connection)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unavailable)?;
    let bytes: Vec<u8> = row.try_get("snapshot_bytes").map_err(unavailable)?;
    let document: Value = row.try_get("snapshot").map_err(unavailable)?;
    let digest: String = row.try_get("snapshot_digest").map_err(unavailable)?;
    let snapshot: DelegationUsePolicySnapshot =
        serde_json::from_slice(&bytes).map_err(unavailable)?;
    snapshot.validate()?;
    if snapshot.organization_id != organization
        || snapshot.policy_id != policy
        || snapshot.revision != row.try_get::<i64, _>("revision").map_err(unavailable)? as u64
        || snapshot.status.as_str() != row.try_get::<String, _>("status").map_err(unavailable)?
        || document != serde_json::to_value(&snapshot).map_err(unavailable)?
        || digest != byte_digest(&bytes)
        || bytes
            != row
                .try_get::<Vec<u8>, _>("history_bytes")
                .map_err(unavailable)?
        || document
            != row
                .try_get::<Value, _>("history_document")
                .map_err(unavailable)?
        || digest
            != row
                .try_get::<String, _>("history_digest")
                .map_err(unavailable)?
    {
        return Err(Error::Unavailable);
    }
    Ok((snapshot, bytes, digest))
}

pub fn delegation_use_entity_types() -> CedarEntityTypes {
    CedarEntityTypes {
        principal: "MartyDelegatedUse::Principal".into(),
        action: "MartyDelegatedUse::Action".into(),
        resource: "MartyDelegatedUse::Resource".into(),
    }
}

/// Only the finite action identifiers vary; their quoted form comes from the
/// JSON string encoder. Owners cannot supply Cedar schema fragments.
pub fn delegation_use_schema(actions: &[String]) -> Result<String, Error> {
    if actions.is_empty() || actions.len() > 64 {
        return Err(Error::Invalid);
    }
    let mut unique = BTreeSet::new();
    let mut quoted = Vec::new();
    for action in actions {
        if !valid_uri(action) || !unique.insert(action) {
            return Err(Error::Invalid);
        }
        quoted.push(serde_json::to_string(action).map_err(unavailable)?);
    }
    Ok(format!("namespace MartyDelegatedUse {{\n  entity Principal;\n  entity Resource;\n  action {} appliesTo {{\n    principal: [Principal],\n    resource: [Resource],\n    context: {{\n      organization_id: String, grant_id: String, grant_revision: Long, actor_type: String,\n      grantor: String, grantor_type: String, subject: String, subject_type: String,\n      delegate: String, delegate_type: String, audience: String,\n      operation_profile: String, operation_digest: String,\n      constraint_context: {{mode: String, request_profile: String, request_digest: String}},\n      constraint_evidence_digest: String, delegate_proof_verified: Bool, consent_and_authority_verified: Bool\n    }}\n  }};\n}}\n",quoted.join(", ")))
}
pub fn compile_delegation_use_policy(
    source: &str,
    actions: &[String],
) -> Result<CedarPolicyEngine, Error> {
    CedarPolicyEngine::from_human_schema(
        source,
        &delegation_use_schema(actions)?,
        CedarConfig {
            entity_types: delegation_use_entity_types(),
            ..CedarConfig::default()
        },
    )
    .map_err(|_| Error::Invalid)
}
pub fn validate_policy_input(input: &DelegationUsePolicyInput) -> Result<(), Error> {
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
    let schema = delegation_use_schema(&input.actions)?;
    let mut ids = BTreeSet::new();
    for p in &input.policies {
        if !bounded_text(&p.policy_id, 128)
            || !ids.insert(&p.policy_id)
            || !matches!(p.effect.as_str(), "permit" | "forbid")
            || p.cedar_text.trim().is_empty()
            || p.cedar_text.len() > 65_536
            || p.description
                .as_ref()
                .is_some_and(|s| !bounded_text(s, 4096))
        {
            return Err(Error::Invalid);
        }
    }
    let source = policy_source(&input.policies);
    if source.is_empty() || source.len() > 196_608 {
        return Err(Error::Invalid);
    }
    let validator = mmf_security::CedarPolicyValidator::from_human_schema(
        &schema,
        CedarConfig {
            entity_types: delegation_use_entity_types(),
            ..CedarConfig::default()
        },
    )
    .map_err(|_| Error::Invalid)?;
    if !crate::validate_policy_documents(&input.policies, &validator).is_empty() {
        return Err(Error::Invalid);
    }
    compile_delegation_use_policy(&source, &input.actions)?;
    Ok(())
}
fn policy_source(policies: &[CedarPolicyDocument]) -> String {
    policies
        .iter()
        .filter(|p| p.enabled)
        .map(|p| p.cedar_text.as_str())
        .collect::<Vec<_>>()
        .join("\n\n")
}
fn material_digest(source: &str, schema: &str) -> Result<String, Error> {
    Ok(byte_digest(
        &serde_json::to_vec(&json!({"policy_source":source,"schema":schema}))
            .map_err(unavailable)?,
    ))
}
fn byte_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}
fn bounded_text(v: &str, max: usize) -> bool {
    !v.trim().is_empty() && v.len() <= max && !v.chars().any(char::is_control)
}
fn valid_uri(v: &str) -> bool {
    bounded_text(v, 2048)
        && !v.chars().any(char::is_whitespace)
        && !v.contains('*')
        && url::Url::parse(v).is_ok()
}
fn valid_digest(v: &str) -> bool {
    v.strip_prefix("sha256:").is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn unavailable<E>(_: E) -> Error {
    Error::Unavailable
}

/// Bounded owner reader with INSERT only on its private observation table.
/// This does not possess human policy mutation or any delegated-use ledger right.
#[derive(Clone)]
pub struct PgDelegationUsePolicySource {
    pool: PgPool,
}
impl PgDelegationUsePolicySource {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    pub async fn readiness(&self) -> Result<(), Error> {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut connection = self.pool.acquire().await.map_err(unavailable)?;
            validate_delegation_use_policy_schema(&mut connection).await?;
            validate_source_role(&mut connection).await
        })
        .await
        .map_err(unavailable)?
    }
    pub async fn observe_current(
        &self,
        policy: Uuid,
        scope: &DelegationUsePolicyScope,
        original_now: DateTime<Utc>,
    ) -> Result<CurrentDelegationUsePolicy, Error> {
        scope.validate()?;
        if policy.is_nil() {
            return Err(Error::Invalid);
        }
        // This timeout may drop a pending source. Only an already-started final
        // COMMIT is detached below; a timed-out caller never receives authority.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.observe_inner(policy, scope, original_now),
        )
        .await
        .map_err(unavailable)?
    }
    async fn observe_inner(
        &self,
        policy: Uuid,
        scope: &DelegationUsePolicyScope,
        original_now: DateTime<Utc>,
    ) -> Result<CurrentDelegationUsePolicy, Error> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        sqlx::raw_sql("SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='4s'")
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        validate_delegation_use_policy_schema(&mut tx).await?;
        validate_source_role(&mut tx).await?;
        let observed_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
        let original_at = DateTime::from_timestamp_micros(original_now.timestamp_micros())
            .ok_or(Error::Invalid)?;
        let valid_until = original_at
            .checked_add_signed(Duration::seconds(30))
            .ok_or(Error::Invalid)?;
        if observed_at < original_now || observed_at >= valid_until {
            return Err(Error::Unavailable);
        }
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM organization_service.organizations WHERE id=$1")
                .bind(scope.organization_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(unavailable)?;
        if status.as_deref() != Some("active") {
            return Err(Error::AccessDenied);
        }
        let (snapshot, _, history_digest) =
            load_current(&mut tx, scope.organization_id, policy, false).await?;
        if snapshot.status != PolicySetStatus::Active
            || snapshot.updated_at > observed_at
            || !snapshot.actions.contains(&scope.action)
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
        let document = json!({
            "profile":OBSERVATION_PROFILE,"scope":scope,"policy_snapshot":snapshot,"history_digest":history_digest,
            "policy_digest":snapshot.policy_digest,"schema":snapshot.schema,"entities":scope.entities(),
            "original_at":original_at,"observed_at":observed_at,"completed_at":completed_at,"valid_until":valid_until,
        });
        let evidence_bytes = serde_json::to_vec(&document).map_err(unavailable)?;
        if evidence_bytes.len() > 1_048_576 {
            return Err(Error::Invalid);
        }
        let digest = byte_digest(&evidence_bytes);
        let evidence_ref = format!("urn:marty:delegation-use-policy-source:{digest}");
        sqlx::query("INSERT INTO organization_service.delegation_use_policy_observations(organization_id,evidence_ref,policy_id,policy_revision,evidence_bytes,evidence_document,evidence_digest,original_at,observed_at,completed_at,valid_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(organization_id,evidence_ref) DO NOTHING")
            .bind(scope.organization_id).bind(&evidence_ref).bind(policy).bind(snapshot.revision as i64).bind(&evidence_bytes).bind(&document).bind(&digest).bind(original_at).bind(observed_at).bind(completed_at).bind(valid_until).execute(&mut *tx).await.map_err(unavailable)?;
        let retained=sqlx::query("SELECT evidence_bytes,evidence_document,evidence_digest,original_at,observed_at,completed_at,valid_until,retained_at FROM organization_service.delegation_use_policy_observations WHERE organization_id=$1 AND evidence_ref=$2").bind(scope.organization_id).bind(&evidence_ref).fetch_one(&mut *tx).await.map_err(unavailable)?;
        if retained
            .try_get::<Vec<u8>, _>("evidence_bytes")
            .map_err(unavailable)?
            != evidence_bytes
            || retained
                .try_get::<Value, _>("evidence_document")
                .map_err(unavailable)?
                != document
            || retained
                .try_get::<String, _>("evidence_digest")
                .map_err(unavailable)?
                != digest
            || retained
                .try_get::<DateTime<Utc>, _>("original_at")
                .map_err(unavailable)?
                != original_at
            || retained
                .try_get::<DateTime<Utc>, _>("observed_at")
                .map_err(unavailable)?
                != observed_at
            || retained
                .try_get::<DateTime<Utc>, _>("completed_at")
                .map_err(unavailable)?
                != completed_at
            || retained
                .try_get::<DateTime<Utc>, _>("valid_until")
                .map_err(unavailable)?
                != valid_until
            || retained
                .try_get::<DateTime<Utc>, _>("retained_at")
                .map_err(unavailable)?
                < completed_at
        {
            return Err(Error::Unavailable);
        }
        tokio::spawn(async move { tx.commit().await })
            .await
            .map_err(unavailable)?
            .map_err(unavailable)?;
        let after = Utc::now();
        if after < completed_at || after >= valid_until {
            return Err(Error::Unavailable);
        }
        Ok(CurrentDelegationUsePolicy {
            snapshot,
            scope: scope.clone(),
            evidence_ref,
            evidence_bytes,
            observed_at,
            valid_until,
        })
    }
    /// Private historical evidence only. It cannot be converted into a current
    /// source observation or used to refresh authority after revocation/expiry.
    pub async fn recover(
        &self,
        organization: Uuid,
        evidence_ref: &str,
    ) -> Result<Option<HistoricalDelegationUsePolicyEvidence>, Error> {
        if organization.is_nil()
            || !evidence_ref
                .strip_prefix("urn:marty:delegation-use-policy-source:")
                .is_some_and(valid_digest)
        {
            return Err(Error::Invalid);
        }
        self.readiness().await?;
        tokio::time::timeout(std::time::Duration::from_secs(5),async {
            let row=sqlx::query("SELECT evidence_bytes,evidence_document,evidence_digest,retained_at,valid_until FROM organization_service.delegation_use_policy_observations WHERE organization_id=$1 AND evidence_ref=$2").bind(organization).bind(evidence_ref).fetch_optional(&self.pool).await.map_err(unavailable)?;
            let Some(row)=row else {return Ok(None)};
            let bytes:Vec<u8>=row.try_get("evidence_bytes").map_err(unavailable)?;
            let document:Value=serde_json::from_slice(&bytes).map_err(unavailable)?;
            let digest=byte_digest(&bytes);
            if row.try_get::<Value,_>("evidence_document").map_err(unavailable)?!=document
                || row.try_get::<String,_>("evidence_digest").map_err(unavailable)?!=digest
                || evidence_ref!=format!("urn:marty:delegation-use-policy-source:{digest}") {return Err(Error::Unavailable)}
            Ok(Some(HistoricalDelegationUsePolicyEvidence {bytes,document,retained_at:row.try_get("retained_at").map_err(unavailable)?,valid_until:row.try_get("valid_until").map_err(unavailable)?}))
        }).await.map_err(unavailable)?
    }
}
pub struct HistoricalDelegationUsePolicyEvidence {
    bytes: Vec<u8>,
    document: Value,
    retained_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}
impl HistoricalDelegationUsePolicyEvidence {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn document(&self) -> &Value {
        &self.document
    }
    pub fn retained_at(&self) -> DateTime<Utc> {
        self.retained_at
    }
    pub fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }
}
async fn validate_source_role(connection: &mut PgConnection) -> Result<(), Error> {
    let tables = [
        "rust_schema_versions",
        "organizations",
        "delegation_use_policies",
        "delegation_use_policy_history",
        "delegation_use_policy_observations",
    ];
    let valid:bool=sqlx::query_scalar("SELECT current_user=session_user AND NOT pg_is_in_recovery()
        AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE (r.rolname=current_user OR pg_has_role(current_user,r.oid,'MEMBER')) AND (
          r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolbypassrls OR r.rolreplication OR left(r.rolname::TEXT,3)='pg_'
          OR EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid AND m.admin_option)
          OR EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND d.datdba=r.oid)
          OR has_database_privilege(r.oid,current_database(),'CREATE,CREATE WITH GRANT OPTION,CONNECT WITH GRANT OPTION,TEMPORARY WITH GRANT OPTION')
          OR EXISTS(SELECT 1 FROM pg_namespace n WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema'
              AND (n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE,CREATE WITH GRANT OPTION,USAGE WITH GRANT OPTION')))
          OR EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
              WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema' AND t.relkind IN('r','p','v','m','f','S') AND (
                t.relowner=r.oid OR has_table_privilege(r.oid,t.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,DELETE WITH GRANT OPTION,TRUNCATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION,TRIGGER WITH GRANT OPTION')
                OR CASE WHEN current_setting('server_version_num')::INT>=170000 THEN has_table_privilege(r.oid,t.oid,'MAINTAIN') ELSE false END
                OR has_any_column_privilege(r.oid,t.oid,'UPDATE,REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION')
                OR ((has_table_privilege(r.oid,t.oid,'INSERT') OR has_any_column_privilege(r.oid,t.oid,'INSERT')) AND NOT (n.nspname='organization_service' AND t.relname='delegation_use_policy_observations'))
                OR ((has_table_privilege(r.oid,t.oid,'SELECT') OR has_any_column_privilege(r.oid,t.oid,'SELECT')) AND NOT (n.nspname='organization_service' AND t.relname=ANY($1::TEXT[])))))
          OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
              WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema' AND (p.proowner=r.oid OR has_function_privilege(r.oid,p.oid,'EXECUTE WITH GRANT OPTION') OR (p.prosecdef AND has_function_privilege(r.oid,p.oid,'EXECUTE'))))))
        AND has_schema_privilege(current_user,'organization_service','USAGE')
        AND has_table_privilege(current_user,'organization_service.delegation_use_policy_observations','INSERT')
        AND NOT EXISTS(SELECT 1 FROM unnest($1::TEXT[]) name WHERE NOT has_table_privilege(current_user,format('%I.%I','organization_service',name),'SELECT'))")
        .bind(tables.as_slice()).fetch_one(connection).await.map_err(unavailable)?;
    if !valid {
        return Err(Error::AccessDenied);
    }
    Ok(())
}

/// Validate exact bindings and function bodies, including on empty tables.
/// Readiness never installs, repairs or backfills policy/source evidence.
pub async fn validate_delegation_use_policy_schema(
    connection: &mut PgConnection,
) -> Result<(), Error> {
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM organization_service.rust_schema_versions WHERE version='rust_organization_delegation_use_policy_0008') AND to_regclass('organization_service.delegation_use_policies') IS NOT NULL AND to_regclass('organization_service.delegation_use_policy_history') IS NOT NULL AND to_regclass('organization_service.delegation_use_policy_observations') IS NOT NULL").fetch_one(&mut *connection).await.map_err(unavailable)?;
    if !valid {
        return Err(Error::Unavailable);
    }
    let guards:i64=sqlx::query_scalar("WITH expected(table_name,trigger_name,function_name,trigger_type,deferred) AS (VALUES
        ('delegation_use_policies','delegation_policy_guard','guard_delegation_use_policy',31,false),
        ('delegation_use_policies','delegation_policy_no_truncate','reject_delegation_use_policy_mutation',34,false),
        ('delegation_use_policies','delegation_policy_history_complete','check_delegation_use_policy_history',21,true),
        ('delegation_use_policy_history','delegation_policy_history_guard','guard_delegation_use_policy_history',7,false),
        ('delegation_use_policy_history','delegation_policy_history_immutable','reject_delegation_use_policy_mutation',58,false),
        ('delegation_use_policy_observations','delegation_policy_observation_guard','guard_delegation_use_policy_observation',7,false),
        ('delegation_use_policy_observations','delegation_policy_observation_immutable','reject_delegation_use_policy_mutation',58,false),
        ('delegation_use_policy_observations','delegation_policy_observation_commit','check_delegation_use_policy_observation_commit',5,true))
        SELECT count(*) FROM expected e JOIN pg_trigger t ON t.tgrelid=to_regclass('organization_service.'||e.table_name) AND t.tgname=e.trigger_name
        JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_language l ON l.oid=p.prolang
        WHERE NOT t.tgisinternal AND t.tgenabled='O' AND t.tgqual IS NULL AND t.tgtype=e.trigger_type AND t.tgnargs=0 AND t.tgattr=''::int2vector
          AND t.tgdeferrable=e.deferred AND t.tginitdeferred=e.deferred AND (t.tgconstraint<>0)=e.deferred
          AND t.tgfoid=to_regprocedure('organization_service.'||e.function_name||'()') AND NOT p.prosecdef AND p.prorettype='trigger'::regtype
          AND p.prokind='f' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog']::TEXT[]")
        .fetch_one(&mut *connection).await.map_err(unavailable)?;
    let constraints:i64=sqlx::query_scalar("WITH expected(table_name,name,expression) AS (VALUES
        ('delegation_use_policies','delegation_policy_current_bytes','((convert_from(snapshot_bytes, ''UTF8''::name))::jsonb = snapshot)'),
        ('delegation_use_policies','delegation_policy_current_digest','(snapshot_digest = (''sha256:''::text || encode(sha256(snapshot_bytes), ''hex''::text)))'),
        ('delegation_use_policy_history','delegation_policy_history_bytes','((convert_from(snapshot_bytes, ''UTF8''::name))::jsonb = snapshot)'),
        ('delegation_use_policy_history','delegation_policy_history_digest','(snapshot_digest = (''sha256:''::text || encode(sha256(snapshot_bytes), ''hex''::text)))'),
        ('delegation_use_policy_observations','delegation_policy_observation_bytes','((convert_from(evidence_bytes, ''UTF8''::name))::jsonb = evidence_document)'),
        ('delegation_use_policy_observations','delegation_policy_observation_digest','(evidence_digest = (''sha256:''::text || encode(sha256(evidence_bytes), ''hex''::text)))'),
        ('delegation_use_policy_observations','delegation_policy_observation_reference','(evidence_ref = (''urn:marty:delegation-use-policy-source:''::text || evidence_digest))'),
        ('delegation_use_policy_observations','delegation_policy_observation_times','((original_at <= observed_at) AND (observed_at <= completed_at) AND (completed_at <= retained_at) AND (retained_at < valid_until) AND (valid_until <= (original_at + ''00:00:30''::interval)))'))
        SELECT count(*) FROM expected e JOIN pg_constraint c ON c.conname=e.name AND c.conrelid=to_regclass('organization_service.'||e.table_name)
        WHERE c.contype='c' AND c.convalidated AND c.conislocal AND pg_get_expr(c.conbin,c.conrelid)=e.expression")
        .fetch_one(&mut *connection).await.map_err(unavailable)?;
    let keys:i64=sqlx::query_scalar("WITH expected(table_name,columns) AS (VALUES
        ('delegation_use_policies',ARRAY['organization_id','policy_id']),
        ('delegation_use_policy_history',ARRAY['organization_id','policy_id','revision']),
        ('delegation_use_policy_observations',ARRAY['organization_id','evidence_ref']))
        SELECT count(*) FROM expected e JOIN pg_index i ON i.indrelid=to_regclass('organization_service.'||e.table_name) JOIN pg_constraint c ON c.conindid=i.indexrelid
        WHERE c.contype='p' AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive AND i.indpred IS NULL AND i.indexprs IS NULL
          AND i.indnkeyatts=cardinality(e.columns) AND i.indnatts=cardinality(e.columns)
          AND (SELECT array_agg(a.attname::TEXT ORDER BY k.ordinality) FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ordinality)
            JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum)=e.columns")
        .fetch_one(&mut *connection).await.map_err(unavailable)?;
    let links:i64=sqlx::query_scalar("WITH expected(table_name,columns,target,target_columns) AS (VALUES
        ('delegation_use_policies',ARRAY['organization_id'],'organizations',ARRAY['id']),
        ('delegation_use_policy_history',ARRAY['organization_id','policy_id'],'delegation_use_policies',ARRAY['organization_id','policy_id']),
        ('delegation_use_policy_observations',ARRAY['organization_id','policy_id','policy_revision'],'delegation_use_policy_history',ARRAY['organization_id','policy_id','revision']))
        SELECT count(*) FROM expected e JOIN pg_constraint c ON c.conrelid=to_regclass('organization_service.'||e.table_name) AND c.confrelid=to_regclass('organization_service.'||e.target)
        WHERE c.contype='f' AND c.convalidated AND NOT c.condeferrable AND c.confupdtype='a' AND c.confdeltype='a'
          AND (SELECT array_agg(a.attname::TEXT ORDER BY k.ordinality) FROM unnest(c.conkey) WITH ORDINALITY k(attnum,ordinality) JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum)=e.columns
          AND (SELECT array_agg(a.attname::TEXT ORDER BY k.ordinality) FROM unnest(c.confkey) WITH ORDINALITY k(attnum,ordinality) JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum)=e.target_columns")
        .fetch_one(&mut *connection).await.map_err(unavailable)?;
    if guards != 8 || constraints != 8 || keys != 3 || links != 3 {
        return Err(Error::Unavailable);
    }
    let migration = include_str!("../migrations/0008_delegation_use_policy.sql");
    for function in [
        "guard_delegation_use_policy",
        "guard_delegation_use_policy_history",
        "check_delegation_use_policy_history",
        "reject_delegation_use_policy_mutation",
        "guard_delegation_use_policy_observation",
        "check_delegation_use_policy_observation_commit",
    ] {
        let marker = format!("FUNCTION organization_service.{function}()");
        let expected = migration
            .split_once(&marker)
            .and_then(|(_, s)| s.split_once("AS $$"))
            .and_then(|(_, s)| s.split_once("$$;"))
            .map(|(s, _)| s)
            .ok_or(Error::Unavailable)?;
        let actual:String=sqlx::query_scalar("SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='organization_service' AND p.proname=$1 AND p.pronargs=0").bind(function).fetch_one(&mut *connection).await.map_err(unavailable)?;
        if actual != expected {
            return Err(Error::Unavailable);
        }
    }
    Ok(())
}
