//! Exact durable retention for the selected machine-authentication gate.
//! Audit rows are private historical evidence, never deserializable proofs or
//! bearer authority. The audited composition uses the concrete PostgreSQL owner
//! and returns a proof only after COMMIT and a fresh original-deadline check.

use std::{fmt, sync::Arc};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, PgPool, Row};
use uuid::Uuid;

use crate::{
    machine_auth::{
        AuthenticatedMachineProof, MachineEvidenceError, MartyMachineOid4vpProofVerifier,
        MACHINE_AUTHENTICATION_EVIDENCE_PROFILE,
    },
    DelegateProofError, DelegateProofVerifier, DelegationClock, DelegationGrant,
    DelegationUseRequest, RepositoryError, SystemDelegationClock, VerifiedDelegateProof,
};

pub const MACHINE_AUTHENTICATION_EVIDENCE_REF_PREFIX: &str =
    "urn:marty:machine-authentication:sha256:";

/// Private retained history. No conversion to authenticated proof is provided.
/// A host must authorize historical inspection independently of this repository.
pub struct HistoricalMachineAuthenticationEvidence {
    organization_id: Uuid,
    evidence_ref: String,
    evidence_digest: String,
    document: Value,
    bytes: Vec<u8>,
    retained_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}
impl HistoricalMachineAuthenticationEvidence {
    pub fn organization_id(&self) -> Uuid {
        self.organization_id
    }
    pub fn evidence_ref(&self) -> &str {
        &self.evidence_ref
    }
    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }
    pub fn evidence_document(&self) -> &Value {
        &self.document
    }
    pub fn evidence_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn retained_at(&self) -> DateTime<Utc> {
        self.retained_at
    }
    pub fn original_valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }
}
impl fmt::Debug for HistoricalMachineAuthenticationEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HistoricalMachineAuthenticationEvidence { <private> }")
    }
}

#[derive(Clone)]
pub struct PgMachineAuthenticationEvidenceRepository {
    pool: PgPool,
}
impl PgMachineAuthenticationEvidenceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    /// Check schema plus the actual connected append-only audit writer. Existing
    /// lifecycle, approval and source-reader roles must not acquire audit access.
    pub async fn readiness(&self) -> Result<(), MachineEvidenceError> {
        crate::PgDelegationGrantRepository::new(self.pool.clone())
            .readiness()
            .await
            .map_err(unavailable)?;
        let role = crate::approval_postgres::check_role(
            &self.pool,
            "delegated_authority_service",
            &["machine_authentication_evidence"],
            &["schema_migrations", "machine_authentication_evidence"],
        )
        .await
        .map_err(unavailable)?;
        let excessive:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_roles r
            WHERE (r.rolname=$1 OR pg_has_role($1::TEXT,r.oid,'MEMBER')) AND (
              EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
                WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND t.relkind IN ('r','p','v','m','f','S')
                  AND NOT (n.nspname='delegated_authority_service' AND t.relname IN ('schema_migrations','machine_authentication_evidence'))
                  AND (t.relowner=r.oid OR has_table_privilege(r.oid,t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                    OR has_any_column_privilege(r.oid,t.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
              OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema'
                  AND (n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE')))
              OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                  WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND p.prosecdef
                    AND has_function_privilege(r.oid,p.oid,'EXECUTE'))))")
            .bind(role).fetch_one(&self.pool).await.map_err(unavailable)?;
        if excessive {
            return Err(MachineEvidenceError);
        }
        Ok(())
    }

    /// Retain one already verified opaque result. Exact duplicate insertion is
    /// idempotent; conflict never rewrites history or refreshes its timestamps.
    /// COMMIT is not put under a cancellation timeout or automatically retried.
    pub async fn retain(
        &self,
        proof: &AuthenticatedMachineProof,
    ) -> Result<(), MachineEvidenceError> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
        proof.ensure_current(now)?;
        let scope = proof.scope();
        let bytes = proof.evidence_bytes();
        let evidence_digest = format!("sha256:{:x}", Sha256::digest(bytes));
        let reference = format!("urn:marty:machine-authentication:{evidence_digest}");
        if reference != proof.evidence_ref() || bytes.len() > 65_536 {
            return Err(MachineEvidenceError);
        }
        sqlx::query("INSERT INTO delegated_authority_service.machine_authentication_evidence
            (organization_id,evidence_ref,evidence_digest,actor_type,actor_id,machine_identity_id,grant_id,grant_revision,challenge_id,
             audit_bytes,audit_document,completed_at,valid_until,retained_at)
            VALUES($1,$2,$3,'MACHINE_IDENTITY',$4,$5,$6,$7,$8,$9,$10,($11::text)::TIMESTAMPTZ,($12::text)::TIMESTAMPTZ,$13)
            ON CONFLICT(organization_id,evidence_ref) DO NOTHING")
            .bind(scope.organization_id).bind(&reference).bind(&evidence_digest).bind(&scope.principal.id)
            .bind(scope.machine_identity_id).bind(scope.grant_id).bind(i64::try_from(scope.grant_revision).map_err(unavailable)?)
            .bind(scope.challenge_id).bind(bytes).bind(proof.evidence_document()).bind(proof.completed_at().to_rfc3339())
            .bind(proof.valid_until().to_rfc3339()).bind(now).execute(&mut *tx).await.map_err(unavailable)?;
        let row = sqlx::query(SELECT_EVIDENCE)
            .bind(scope.organization_id)
            .bind(&reference)
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
        let retained = decode(row)?;
        if retained.bytes != bytes || retained.document != *proof.evidence_document() {
            return Err(MachineEvidenceError);
        }
        let after: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
        if after < now {
            return Err(MachineEvidenceError);
        }
        proof.ensure_current(after)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(())
    }

    /// History is returned even after expiry. This does not run providers,
    /// recreate a proof, authorize a new command or renew a deadline.
    pub async fn recover(
        &self,
        organization_id: Uuid,
        evidence_ref: &str,
    ) -> Result<Option<HistoricalMachineAuthenticationEvidence>, MachineEvidenceError> {
        if organization_id.is_nil() || !valid_reference(evidence_ref) {
            return Err(MachineEvidenceError);
        }
        sqlx::query(SELECT_EVIDENCE)
            .bind(organization_id)
            .bind(evidence_ref)
            .fetch_optional(&self.pool)
            .await
            .map_err(unavailable)?
            .map(decode)
            .transpose()
    }
}

/// The original bounded proof together with completed concrete durable storage.
/// Neither deserialization nor historical audit lookup can manufacture it.
pub struct RetainedMachineAuthenticationProof {
    proof: AuthenticatedMachineProof,
}
impl RetainedMachineAuthenticationProof {
    pub fn authenticated(&self) -> &AuthenticatedMachineProof {
        &self.proof
    }
    pub fn into_delegate_proof(self) -> VerifiedDelegateProof {
        self.proof.into_delegate_proof()
    }
}
impl fmt::Debug for RetainedMachineAuthenticationProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RetainedMachineAuthenticationProof { <private> }")
    }
}

#[derive(Clone)]
pub struct AuditedMachineOid4vpProofVerifier {
    verifier: Arc<MartyMachineOid4vpProofVerifier>,
    evidence: PgMachineAuthenticationEvidenceRepository,
    clock: Arc<dyn DelegationClock>,
}
impl AuditedMachineOid4vpProofVerifier {
    pub fn new(
        verifier: Arc<MartyMachineOid4vpProofVerifier>,
        evidence: PgMachineAuthenticationEvidenceRepository,
    ) -> Self {
        Self::with_clock(verifier, evidence, Arc::new(SystemDelegationClock))
    }
    pub fn with_clock(
        verifier: Arc<MartyMachineOid4vpProofVerifier>,
        evidence: PgMachineAuthenticationEvidenceRepository,
        clock: Arc<dyn DelegationClock>,
    ) -> Self {
        Self {
            verifier,
            evidence,
            clock,
        }
    }
    pub async fn readiness(&self) -> Result<(), MachineEvidenceError> {
        self.evidence.readiness().await
    }
    pub async fn verify_retained(
        &self,
        grant: &DelegationGrant,
        request: &DelegationUseRequest,
        now: DateTime<Utc>,
    ) -> Result<RetainedMachineAuthenticationProof, MachineEvidenceError> {
        if self.clock.now() < now {
            return Err(MachineEvidenceError);
        }
        let proof = self.verifier.verify_machine(grant, request, now).await?;
        let before = self.clock.now();
        proof.ensure_current(before)?;
        self.evidence.retain(&proof).await?;
        let after = self.clock.now();
        if after < before {
            return Err(MachineEvidenceError);
        }
        proof.ensure_current(after)?;
        Ok(RetainedMachineAuthenticationProof { proof })
    }
}
#[async_trait]
impl DelegateProofVerifier for AuditedMachineOid4vpProofVerifier {
    async fn verify(
        &self,
        grant: &DelegationGrant,
        request: &DelegationUseRequest,
        now: DateTime<Utc>,
    ) -> Result<VerifiedDelegateProof, DelegateProofError> {
        self.verify_retained(grant, request, now)
            .await
            .map(RetainedMachineAuthenticationProof::into_delegate_proof)
            .map_err(|_| DelegateProofError)
    }
}

fn unavailable(_: impl fmt::Debug) -> MachineEvidenceError {
    MachineEvidenceError
}
const SELECT_EVIDENCE:&str="SELECT *, completed_at=(audit_document->>'completed_at')::TIMESTAMPTZ
    AND valid_until=(audit_document->>'valid_until')::TIMESTAMPTZ AS timestamps_match
    FROM delegated_authority_service.machine_authentication_evidence WHERE organization_id=$1 AND evidence_ref=$2";
fn valid_reference(reference: &str) -> bool {
    reference
        .strip_prefix(MACHINE_AUTHENTICATION_EVIDENCE_REF_PREFIX)
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}
fn decode(row: PgRow) -> Result<HistoricalMachineAuthenticationEvidence, MachineEvidenceError> {
    let organization_id = row
        .try_get::<Uuid, _>("organization_id")
        .map_err(unavailable)?;
    let evidence_ref = row
        .try_get::<String, _>("evidence_ref")
        .map_err(unavailable)?;
    let evidence_digest = row
        .try_get::<String, _>("evidence_digest")
        .map_err(unavailable)?;
    let bytes = row
        .try_get::<Vec<u8>, _>("audit_bytes")
        .map_err(unavailable)?;
    let document = row
        .try_get::<Value, _>("audit_document")
        .map_err(unavailable)?;
    let retained_at = row
        .try_get::<DateTime<Utc>, _>("retained_at")
        .map_err(unavailable)?;
    let valid_until = row
        .try_get::<DateTime<Utc>, _>("valid_until")
        .map_err(unavailable)?;
    let completed_at = row
        .try_get::<DateTime<Utc>, _>("completed_at")
        .map_err(unavailable)?;
    let scope = &document["scope"];
    if organization_id.is_nil()
        || bytes.is_empty()
        || bytes.len() > 65_536
        || !valid_reference(&evidence_ref)
        || evidence_digest != format!("sha256:{:x}", Sha256::digest(&bytes))
        || evidence_ref != format!("urn:marty:machine-authentication:{evidence_digest}")
        || serde_json::from_slice::<Value>(&bytes).map_err(unavailable)? != document
        || document["profile"] != MACHINE_AUTHENTICATION_EVIDENCE_PROFILE
        || scope["organization_id"] != organization_id.to_string()
        || scope["principal"]["type"] != "MACHINE_IDENTITY"
        || row
            .try_get::<String, _>("actor_type")
            .map_err(unavailable)?
            != "MACHINE_IDENTITY"
        || scope["principal"]["id"] != row.try_get::<String, _>("actor_id").map_err(unavailable)?
        || scope["machine_identity_id"]
            != row
                .try_get::<Uuid, _>("machine_identity_id")
                .map_err(unavailable)?
                .to_string()
        || scope["grant_id"]
            != row
                .try_get::<Uuid, _>("grant_id")
                .map_err(unavailable)?
                .to_string()
        || scope["challenge_id"]
            != row
                .try_get::<Uuid, _>("challenge_id")
                .map_err(unavailable)?
                .to_string()
        || scope["grant_revision"].as_i64()
            != Some(
                row.try_get::<i64, _>("grant_revision")
                    .map_err(unavailable)?,
            )
        || scope["proof_evidence_ref"] != document["proof"]["evidence_ref"]
        || !row
            .try_get::<bool, _>("timestamps_match")
            .map_err(unavailable)?
        || completed_at > retained_at
        || retained_at >= valid_until
    {
        return Err(MachineEvidenceError);
    }
    // Preserve the original nanosecond deadline, not the database projection.
    let valid_until = DateTime::parse_from_rfc3339(
        document["valid_until"]
            .as_str()
            .ok_or(MachineEvidenceError)?,
    )
    .map_err(unavailable)?
    .with_timezone(&Utc);
    Ok(HistoricalMachineAuthenticationEvidence {
        organization_id,
        evidence_ref,
        evidence_digest,
        document,
        bytes,
        retained_at,
        valid_until,
    })
}

pub(crate) async fn verify_machine_evidence_schema(pool: &PgPool) -> Result<(), RepositoryError> {
    let okay:bool=sqlx::query_scalar("SELECT to_regclass('delegated_authority_service.machine_authentication_evidence') IS NOT NULL")
        .fetch_one(pool).await.map_err(|_|RepositoryError::SchemaNotReady)?;
    if !okay {
        return Err(RepositoryError::SchemaNotReady);
    }
    let guards:i64=sqlx::query_scalar("WITH expected(table_name,name,function_name,kind,deferred) AS (VALUES
        ('machine_authentication_evidence','machine_authentication_evidence_binding','guard_machine_authentication_evidence',7,false),
        ('machine_authentication_evidence','machine_authentication_evidence_commit','check_machine_authentication_evidence_commit',5,true),
        ('machine_authentication_evidence','machine_authentication_evidence_immutable','reject_lifecycle_event_mutation',27,false),
        ('machine_authentication_evidence','machine_authentication_evidence_no_truncate','reject_lifecycle_event_mutation',34,false),
        ('use_receipts','use_receipts_machine_evidence','guard_use_machine_evidence',7,false))
        SELECT count(*) FROM expected e JOIN pg_trigger t ON t.tgrelid=to_regclass('delegated_authority_service.'||e.table_name) AND t.tgname=e.name
        JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_language l ON l.oid=p.prolang
        WHERE NOT t.tgisinternal AND t.tgenabled='O' AND t.tgqual IS NULL AND t.tgtype=e.kind
          AND t.tgnargs=0 AND t.tgattr=''::int2vector AND t.tgdeferrable=e.deferred AND t.tginitdeferred=e.deferred
          AND (t.tgconstraint<>0)=e.deferred AND t.tgfoid=to_regprocedure('delegated_authority_service.'||e.function_name||'()')
          AND NOT p.prosecdef AND p.prorettype='trigger'::regtype AND p.prokind='f' AND l.lanname='plpgsql'
          AND p.proconfig=ARRAY['search_path=pg_catalog']::TEXT[]")
        .fetch_one(pool).await.map_err(|_|RepositoryError::SchemaNotReady)?;
    let unique:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_index i JOIN pg_constraint c ON c.conindid=i.indexrelid
        WHERE i.indrelid='delegated_authority_service.machine_authentication_evidence'::regclass
          AND c.contype='p' AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive AND i.indpred IS NULL AND i.indexprs IS NULL
          AND i.indnkeyatts=2 AND i.indnatts=2
          AND (SELECT array_agg(a.attname::TEXT ORDER BY k.ordinality) FROM unnest(i.indkey) WITH ORDINALITY k(attnum,ordinality)
            JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum)=ARRAY['organization_id','evidence_ref'])")
        .fetch_one(pool).await.map_err(|_|RepositoryError::SchemaNotReady)?;
    let constraints:i64=sqlx::query_scalar("WITH expected(name,expression) AS (VALUES
        ('machine_evidence_digest_matches_bytes','(evidence_digest = (''sha256:''::text || encode(sha256(audit_bytes), ''hex''::text)))'),
        ('machine_evidence_document_matches_bytes','((convert_from(audit_bytes, ''UTF8''::name))::jsonb = audit_document)'),
        ('machine_evidence_reference_matches_digest','(evidence_ref = (''urn:marty:machine-authentication:''::text || evidence_digest))'))
        SELECT count(*) FROM expected e JOIN pg_constraint c ON c.conname=e.name
          AND c.conrelid='delegated_authority_service.machine_authentication_evidence'::regclass
        WHERE c.contype='c' AND c.convalidated AND c.conislocal AND pg_get_expr(c.conbin,c.conrelid)=e.expression")
        .fetch_one(pool).await.map_err(|_|RepositoryError::SchemaNotReady)?;
    if guards != 5 || !unique || constraints != 3 {
        return Err(RepositoryError::SchemaNotReady);
    }
    Ok(())
}
