//! Concrete current Organization MACHINE_AUTHORIZATION source, actual MMF
//! evaluation and append-only evidence. Reader and writer credentials are
//! distinct. No public host, policy mutation or permission fallback is supplied.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use marty_organization::machine_authorization::{
    compile_machine_policy, machine_entity_types, PgMachineAuthorizationPolicySource,
    MACHINE_AUTHORIZATION_SCHEMA,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    domain::{valid_digest, valid_uri},
    machine_auth::{
        MachineAuthenticationScope, MachineAuthorizationVerifier, MachineEvidenceError,
        MachineEvidenceRequest, VerifiedMachineAuthorization,
    },
    machine_cedar::{
        MachineCedarPolicySource, MmfMachineAuthorizationVerifier, ResolvedMachineCedarPolicy,
    },
    DelegationClock, PrincipalType, SystemDelegationClock,
};

const SOURCE_PROFILE: &str = "urn:marty:machine-policy-source-evidence:v1";
const SOURCE_PREFIX: &str = "urn:marty:machine-policy-source:";
const EVALUATION_PREFIX: &str = "urn:marty:machine-authorization:";

/// Source construction pins both tenant and deployment. The exact policy UUID
/// still comes from the already qualified current MAP; a request cannot choose
/// an issuer, arbitrary URL, Cedar source, entities or a policy type.
#[derive(Clone)]
pub struct OrganizationMachineCedarPolicySource {
    owner: PgMachineAuthorizationPolicySource,
    evidence: PgMachineAuthorizationEvidenceRepository,
    organization_id: Uuid,
    deployment_profile_id: Uuid,
    clock: Arc<dyn DelegationClock>,
}
impl OrganizationMachineCedarPolicySource {
    pub fn new(
        owner: PgMachineAuthorizationPolicySource,
        evidence: PgMachineAuthorizationEvidenceRepository,
        organization_id: Uuid,
        deployment_profile_id: Uuid,
    ) -> Result<Self, MachineEvidenceError> {
        Self::with_clock(
            owner,
            evidence,
            organization_id,
            deployment_profile_id,
            Arc::new(SystemDelegationClock),
        )
    }
    pub fn with_clock(
        owner: PgMachineAuthorizationPolicySource,
        evidence: PgMachineAuthorizationEvidenceRepository,
        organization_id: Uuid,
        deployment_profile_id: Uuid,
        clock: Arc<dyn DelegationClock>,
    ) -> Result<Self, MachineEvidenceError> {
        if organization_id.is_nil() || deployment_profile_id.is_nil() {
            return Err(MachineEvidenceError);
        }
        Ok(Self {
            owner,
            evidence,
            organization_id,
            deployment_profile_id,
            clock,
        })
    }
    pub async fn readiness(&self) -> Result<(), MachineEvidenceError> {
        self.owner.readiness().await.map_err(unavailable)?;
        self.evidence.readiness().await
    }
}
#[async_trait]
impl MachineCedarPolicySource for OrganizationMachineCedarPolicySource {
    async fn resolve_current(
        &self,
        scope: &MachineAuthenticationScope,
        policy_set_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<ResolvedMachineCedarPolicy, MachineEvidenceError> {
        validate_scope(scope)?;
        if scope.organization_id != self.organization_id
            || scope.deployment_profile_id != self.deployment_profile_id
            || policy_set_id.is_nil()
        {
            return Err(MachineEvidenceError);
        }
        let owner = self
            .owner
            .observe_current(self.organization_id, policy_set_id, now)
            .await
            .map_err(unavailable)?;
        let snapshot = owner.snapshot();
        let observed_at = owner.observed_at();
        let valid_until = owner.valid_until();
        let completed_at = self.clock.now();
        check_time(now, observed_at, completed_at, valid_until)?;
        let policy_source = snapshot.policy_source();
        let policy_digest = snapshot.policy_digest().map_err(unavailable)?;
        let engine = compile_machine_policy(&policy_source).map_err(unavailable)?;
        // The schema deliberately has no role/group/permission attributes.
        // These two IDs are supplied only by the preceding concrete machine
        // authentication gate, not by untrusted policy request metadata.
        let entities = json!([
            {"uid":{"type":"MartyMachine::Principal","id":scope.principal.id},"attrs":{},"parents":[]},
            {"uid":{"type":"MartyMachine::Identity","id":scope.machine_identity_id.to_string()},"attrs":{},"parents":[]}
        ]);
        let document = json!({
            "profile":SOURCE_PROFILE,
            "scope":scope,
            "policy_set_id":policy_set_id,
            "policy_revision":snapshot.revision,
            "policy_digest":policy_digest,
            "policy_snapshot":snapshot,
            "history_ref":owner.history_ref(),
            "policy_source":policy_source,
            "schema":MACHINE_AUTHORIZATION_SCHEMA,
            "entities":entities,
            "observed_at":observed_at.to_rfc3339(),
            "completed_at":completed_at.to_rfc3339(),
            "valid_until":valid_until.to_rfc3339(),
        });
        let source_evidence_ref = self
            .evidence
            .retain("SOURCE", &document, observed_at, completed_at, valid_until)
            .await?;
        // No timeout cancels COMMIT and there is no automatic retry. A committed
        // history row can outlive its authority; post-COMMIT time is decisive.
        check_time(completed_at, observed_at, self.clock.now(), valid_until)?;
        Ok(ResolvedMachineCedarPolicy {
            scope: scope.clone(),
            policy_set_id,
            policy_type: "MACHINE_AUTHORIZATION".into(),
            status: "ACTIVE".into(),
            revision: snapshot.revision,
            policy_digest,
            source_evidence_ref,
            observed_at,
            valid_until,
            entity_types: machine_entity_types(),
            entities,
            engine: Arc::new(engine),
        })
    }
}

/// Concrete audited composition. It cannot substitute a caller-authored
/// policy-source implementation or an arbitrary successful evaluator. Source
/// and evaluation records always use the same append-only evidence owner.
#[derive(Clone)]
pub struct AuditedMmfMachineAuthorizationVerifier {
    source: Arc<OrganizationMachineCedarPolicySource>,
    inner: MmfMachineAuthorizationVerifier,
    clock: Arc<dyn DelegationClock>,
}
impl AuditedMmfMachineAuthorizationVerifier {
    pub fn new(source: Arc<OrganizationMachineCedarPolicySource>) -> Self {
        Self::with_clock(source, Arc::new(SystemDelegationClock))
    }
    pub fn with_clock(
        source: Arc<OrganizationMachineCedarPolicySource>,
        clock: Arc<dyn DelegationClock>,
    ) -> Self {
        Self {
            inner: MmfMachineAuthorizationVerifier::with_clock(source.clone(), clock.clone()),
            source,
            clock,
        }
    }
    pub async fn readiness(&self) -> Result<(), MachineEvidenceError> {
        self.source.readiness().await
    }
}
#[async_trait]
impl MachineAuthorizationVerifier for AuditedMmfMachineAuthorizationVerifier {
    async fn verify_permitted(
        &self,
        request: MachineEvidenceRequest<'_>,
    ) -> Result<VerifiedMachineAuthorization, MachineEvidenceError> {
        let original = request.now;
        let result = self.inner.verify_with_evidence(request).await?;
        let verified = result.verified;
        check_time(
            original,
            verified.observed_at,
            self.clock.now(),
            verified.valid_until,
        )?;
        let reference = self
            .source
            .evidence
            .retain(
                "EVALUATION",
                &result.evidence,
                verified.observed_at,
                result.evaluated_at,
                verified.valid_until,
            )
            .await?;
        if reference != verified.evidence_ref {
            return Err(MachineEvidenceError);
        }
        check_time(
            result.evaluated_at,
            verified.observed_at,
            self.clock.now(),
            verified.valid_until,
        )?;
        Ok(verified)
    }
}

/// Historical private bytes only. Recovery does not read a source, evaluate
/// Cedar or return an authorization proof; a host separately authorizes access.
pub struct HistoricalMachineAuthorizationEvidence {
    organization_id: Uuid,
    evidence_ref: String,
    bytes: Vec<u8>,
    document: Value,
    retained_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}
impl HistoricalMachineAuthorizationEvidence {
    pub fn organization_id(&self) -> Uuid {
        self.organization_id
    }
    pub fn evidence_ref(&self) -> &str {
        &self.evidence_ref
    }
    pub fn evidence_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn evidence_document(&self) -> &Value {
        &self.document
    }
    pub fn retained_at(&self) -> DateTime<Utc> {
        self.retained_at
    }
    pub fn original_valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }
}
impl fmt::Debug for HistoricalMachineAuthorizationEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HistoricalMachineAuthorizationEvidence { <private> }")
    }
}

#[derive(Clone)]
pub struct PgMachineAuthorizationEvidenceRepository {
    pool: PgPool,
}
impl PgMachineAuthorizationEvidenceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    pub async fn readiness(&self) -> Result<(), MachineEvidenceError> {
        validate_machine_authorization_evidence_schema(&self.pool).await?;
        let role = crate::approval_postgres::check_role(
            &self.pool,
            "delegated_authority_service",
            &["machine_authorization_evidence"],
            &["schema_migrations", "machine_authorization_evidence"],
        )
        .await
        .map_err(unavailable)?;
        let excessive:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_roles r WHERE (r.rolname=$1 OR pg_has_role($1::TEXT,r.oid,'MEMBER')) AND (EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND t.relkind IN('r','p','v','m','f','S') AND NOT(n.nspname='delegated_authority_service' AND t.relname IN('schema_migrations','machine_authorization_evidence')) AND (t.relowner=r.oid OR has_table_privilege(r.oid,t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r.oid,t.oid,'SELECT,INSERT,UPDATE,REFERENCES'))) OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND (n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE'))) OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND p.prosecdef AND has_function_privilege(r.oid,p.oid,'EXECUTE'))))")
            .bind(role).fetch_one(&self.pool).await.map_err(unavailable)?;
        if excessive {
            return Err(MachineEvidenceError);
        }
        let changed_identity:bool=sqlx::query_scalar("SELECT current_user<>session_user OR EXISTS(SELECT 1 FROM pg_roles r WHERE (r.rolname=current_user OR pg_has_role(current_user,r.oid,'MEMBER')) AND (r.rolreplication OR left(r.rolname::text,3)='pg_' OR EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid AND m.admin_option)))")
            .fetch_one(&self.pool).await.map_err(unavailable)?;
        if changed_identity {
            return Err(MachineEvidenceError);
        }
        Ok(())
    }
    async fn retain(
        &self,
        kind: &str,
        document: &Value,
        observed_at: DateTime<Utc>,
        completed_at: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Result<String, MachineEvidenceError> {
        self.readiness().await?;
        let organization = Uuid::parse_str(
            document
                .pointer("/scope/organization_id")
                .and_then(Value::as_str)
                .ok_or(MachineEvidenceError)?,
        )
        .map_err(unavailable)?;
        let bytes = serde_json::to_vec(document).map_err(unavailable)?;
        if organization.is_nil() || bytes.is_empty() || bytes.len() > 524288 {
            return Err(MachineEvidenceError);
        }
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        let prefix = match kind {
            "SOURCE" => SOURCE_PREFIX,
            "EVALUATION" => EVALUATION_PREFIX,
            _ => return Err(MachineEvidenceError),
        };
        let reference = format!("{prefix}{digest}");
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let retained_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
        check_time(completed_at, observed_at, retained_at, valid_until)?;
        let result=sqlx::query("INSERT INTO delegated_authority_service.machine_authorization_evidence(organization_id,evidence_ref,kind,evidence_bytes,evidence_document,evidence_digest,observed_at,completed_at,valid_until,retained_at) VALUES($1,$2,$3,$4,$5,$6,($7::TEXT)::TIMESTAMPTZ,($8::TEXT)::TIMESTAMPTZ,($9::TEXT)::TIMESTAMPTZ,$10) ON CONFLICT(organization_id,evidence_ref) DO NOTHING")
            .bind(organization).bind(&reference).bind(kind).bind(&bytes).bind(document).bind(&digest).bind(observed_at.to_rfc3339()).bind(completed_at.to_rfc3339()).bind(valid_until.to_rfc3339()).bind(retained_at)
            .execute(&mut *tx).await.map_err(unavailable)?;
        if result.rows_affected() == 0 {
            let row=sqlx::query("SELECT kind,evidence_bytes,evidence_document,evidence_digest,observed_at,completed_at,valid_until FROM delegated_authority_service.machine_authorization_evidence WHERE organization_id=$1 AND evidence_ref=$2")
                .bind(organization).bind(&reference).fetch_one(&mut *tx).await.map_err(unavailable)?;
            if row.try_get::<String, _>("kind").map_err(unavailable)? != kind
                || row
                    .try_get::<Vec<u8>, _>("evidence_bytes")
                    .map_err(unavailable)?
                    != bytes
                || row
                    .try_get::<Value, _>("evidence_document")
                    .map_err(unavailable)?
                    != *document
                || row
                    .try_get::<String, _>("evidence_digest")
                    .map_err(unavailable)?
                    != digest
            {
                return Err(MachineEvidenceError);
            }
        }
        // Shield only the final COMMIT from the enclosing machine provider
        // timeout. Dropping this await detaches completion; it cannot return a
        // positive result or trigger another attempt. Pre-COMMIT errors roll back.
        tokio::spawn(async move { tx.commit().await })
            .await
            .map_err(unavailable)?
            .map_err(unavailable)?;
        check_time(retained_at, observed_at, Utc::now(), valid_until)?;
        Ok(reference)
    }
    pub async fn recover(
        &self,
        organization: Uuid,
        reference: &str,
    ) -> Result<Option<HistoricalMachineAuthorizationEvidence>, MachineEvidenceError> {
        if organization.is_nil()
            || ![SOURCE_PREFIX, EVALUATION_PREFIX].iter().any(|prefix| {
                reference
                    .strip_prefix(prefix)
                    .is_some_and(|s| valid_digest(Some(s)))
            })
        {
            return Err(MachineEvidenceError);
        }
        let row=sqlx::query("SELECT evidence_bytes,evidence_document,evidence_digest,kind,retained_at,valid_until FROM delegated_authority_service.machine_authorization_evidence WHERE organization_id=$1 AND evidence_ref=$2")
            .bind(organization).bind(reference).fetch_optional(&self.pool).await.map_err(unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let bytes: Vec<u8> = row.try_get("evidence_bytes").map_err(unavailable)?;
        let stored_document: Value = row.try_get("evidence_document").map_err(unavailable)?;
        // PostgreSQL JSONB may reorder object members. Return the document
        // parsed from the original hash-bound bytes, preserving its exact
        // serialization rather than minting a differently ordered duplicate.
        let document: Value = serde_json::from_slice(&bytes).map_err(unavailable)?;
        let digest: String = row.try_get("evidence_digest").map_err(unavailable)?;
        let kind: String = row.try_get("kind").map_err(unavailable)?;
        let prefix = match kind.as_str() {
            "SOURCE" => SOURCE_PREFIX,
            "EVALUATION" => EVALUATION_PREFIX,
            _ => return Err(MachineEvidenceError),
        };
        if digest != format!("sha256:{:x}", Sha256::digest(&bytes))
            || reference != format!("{prefix}{digest}")
            || stored_document != document
            || document
                .pointer("/scope/organization_id")
                .and_then(Value::as_str)
                != Some(organization.to_string().as_str())
        {
            return Err(MachineEvidenceError);
        }
        Ok(Some(HistoricalMachineAuthorizationEvidence {
            organization_id: organization,
            evidence_ref: reference.into(),
            bytes,
            document,
            retained_at: row.try_get("retained_at").map_err(unavailable)?,
            valid_until: row.try_get("valid_until").map_err(unavailable)?,
        }))
    }
}
fn check_time(
    started: DateTime<Utc>,
    observed: DateTime<Utc>,
    now: DateTime<Utc>,
    deadline: DateTime<Utc>,
) -> Result<(), MachineEvidenceError> {
    if now < started
        || now < observed
        || now >= deadline
        || deadline <= observed
        || observed
            .checked_add_signed(chrono::Duration::seconds(30))
            .is_none_or(|max| deadline > max)
    {
        return Err(MachineEvidenceError);
    }
    Ok(())
}
fn validate_scope(scope: &MachineAuthenticationScope) -> Result<(), MachineEvidenceError> {
    if scope.principal.principal_type != PrincipalType::MachineIdentity
        || [
            scope.organization_id,
            scope.machine_identity_id,
            scope.deployment_profile_id,
            scope.policy_id,
            scope.grant_id,
            scope.challenge_id,
        ]
        .iter()
        .any(Uuid::is_nil)
        || !(1..=9_007_199_254_740_991).contains(&scope.grant_revision)
        || [
            &scope.policy_digest,
            &scope.challenge_digest,
            &scope.operation_digest,
        ]
        .iter()
        .any(|d| !valid_digest(Some(d)))
        || [
            &scope.principal.id,
            &scope.runtime_instance_ref,
            &scope.proof_evidence_ref,
            &scope.action,
            &scope.audience,
            &scope.resource,
            &scope.operation_profile,
        ]
        .iter()
        .any(|v| !valid_uri(Some(v)))
        || scope.key_id.is_empty()
        || scope.key_id.len() > 1024
        || scope.key_id.chars().any(char::is_control)
        || !valid_digest(Some(&scope.key_thumbprint))
    {
        return Err(MachineEvidenceError);
    }
    Ok(())
}
fn unavailable<E>(_: E) -> MachineEvidenceError {
    MachineEvidenceError
}

pub async fn validate_machine_authorization_evidence_schema(
    pool: &PgPool,
) -> Result<(), MachineEvidenceError> {
    let guards:i64=sqlx::query_scalar("WITH expected(table_name,trigger_name,function_name,trigger_type,deferred) AS (VALUES ('machine_authorization_evidence','machine_authorization_evidence_binding','guard_machine_authorization_evidence',7,false),('machine_authorization_evidence','machine_authorization_evidence_commit','check_machine_authorization_evidence_commit',5,true),('machine_authorization_evidence','machine_authorization_evidence_immutable','reject_lifecycle_event_mutation',58,false),('machine_authentication_evidence','machine_authentication_authorization_binding','guard_machine_authentication_authorization',7,false)) SELECT count(*) FROM expected e JOIN pg_trigger t ON t.tgrelid=to_regclass('delegated_authority_service.'||e.table_name) AND t.tgname=e.trigger_name JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_language l ON l.oid=p.prolang WHERE NOT t.tgisinternal AND t.tgenabled='O' AND t.tgqual IS NULL AND t.tgtype=e.trigger_type AND t.tgnargs=0 AND t.tgattr=''::int2vector AND t.tgdeferrable=e.deferred AND t.tginitdeferred=e.deferred AND (t.tgconstraint<>0)=e.deferred AND t.tgfoid=to_regprocedure('delegated_authority_service.'||e.function_name||'()') AND NOT p.prosecdef AND p.prorettype='trigger'::regtype AND p.prokind='f' AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog']::TEXT[]")
        .fetch_one(pool).await.map_err(unavailable)?;
    let constraints:i64=sqlx::query_scalar("WITH expected(name,expression) AS (VALUES
        ('machine_authorization_evidence_bytes','((convert_from(evidence_bytes, ''UTF8''::name))::jsonb = evidence_document)'),
        ('machine_authorization_evidence_digest','(evidence_digest = (''sha256:''::text || encode(sha256(evidence_bytes), ''hex''::text)))'),
        ('machine_authorization_evidence_reference','(evidence_ref = (CASE kind WHEN ''SOURCE''::text THEN ''urn:marty:machine-policy-source:''::text ELSE ''urn:marty:machine-authorization:''::text END || evidence_digest))'))
        SELECT count(*) FROM expected e JOIN pg_constraint c ON c.conname=e.name AND c.conrelid='delegated_authority_service.machine_authorization_evidence'::regclass
        WHERE c.contype='c' AND c.convalidated AND c.conislocal AND regexp_replace(pg_get_expr(c.conbin,c.conrelid),'[[:space:]]','','g')=regexp_replace(e.expression,'[[:space:]]','','g')")
        .fetch_one(pool).await.map_err(unavailable)?;
    let unique:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_index i JOIN pg_constraint c ON c.conindid=i.indexrelid
        WHERE i.indrelid='delegated_authority_service.machine_authorization_evidence'::regclass AND c.contype='p'
          AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive AND i.indpred IS NULL AND i.indexprs IS NULL
          AND i.indnkeyatts=2 AND i.indnatts=2
          AND (SELECT array_agg(a.attname::TEXT ORDER BY k.ordinality) FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ordinality)
            JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum)=ARRAY['organization_id','evidence_ref'])")
        .fetch_one(pool).await.map_err(unavailable)?;
    if guards != 4 || constraints != 3 || !unique {
        return Err(MachineEvidenceError);
    }
    let migration = include_str!("../migrations/0008_machine_authorization_evidence.sql");
    for (function, source) in [
        ("guard_machine_authorization_evidence", migration),
        ("check_machine_authorization_evidence_commit", migration),
        ("guard_machine_authentication_authorization", migration),
        (
            "reject_lifecycle_event_mutation",
            include_str!("../migrations/0002_atomic_lifecycle_journal.sql"),
        ),
    ] {
        let marker = format!("FUNCTION delegated_authority_service.{function}()");
        let expected = source
            .split_once(&marker)
            .and_then(|(_, s)| s.split_once("AS $$"))
            .and_then(|(_, s)| s.split_once("$$;"))
            .map(|(body, _)| body)
            .ok_or(MachineEvidenceError)?;
        let actual:String=sqlx::query_scalar("SELECT p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='delegated_authority_service' AND p.proname=$1 AND p.pronargs=0")
            .bind(function).fetch_one(pool).await.map_err(unavailable)?;
        if actual != expected {
            return Err(MachineEvidenceError);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "machine_policy_source_tests.rs"]
mod tests;
