use super::*;

pub const MACHINE_CREDENTIAL_SOURCE_MIGRATION: &str =
    include_str!("../migrations/0001_machine_credential_source.sql");
const MIGRATION_VERSION: &str = "machine-credential-source-v1";
const MAX_EVIDENCE_BYTES: usize = 2_200_000;
const SELECT_EVIDENCE: &str = "SELECT *,
    observed_at=(evidence_document->>'observed_at')::timestamptz
    AND completed_at=(evidence_document->>'completed_at')::timestamptz
    AND valid_until=(evidence_document->>'valid_until')::timestamptz AS times_match
    FROM machine_credential_source.observations WHERE organization_id=$1 AND evidence_ref=$2";

/// Installation is a separate operator operation. Runtime constructors only
/// inspect schema and permissions and never migrate or provision an owner.
pub async fn run_migrations(pool: &PgPool) -> Result<(), MachineEvidenceError> {
    let mut transaction = pool.begin().await.map_err(unavailable)?;
    sqlx::query("SELECT pg_advisory_xact_lock(80042026112141)")
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;
    let exists: bool =
        sqlx::query_scalar("SELECT to_regnamespace('machine_credential_source') IS NOT NULL")
            .fetch_one(&mut *transaction)
            .await
            .map_err(unavailable)?;
    let digest = migration_digest();
    if exists {
        let recorded: Option<String> = sqlx::query_scalar(
            "SELECT content_digest FROM machine_credential_source.schema_migrations WHERE version=$1",
        ).bind(MIGRATION_VERSION).fetch_optional(&mut *transaction).await.map_err(unavailable)?;
        if recorded.as_deref() != Some(digest.as_str()) {
            return Err(MachineEvidenceError);
        }
    } else {
        sqlx::raw_sql(MACHINE_CREDENTIAL_SOURCE_MIGRATION)
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        sqlx::query("INSERT INTO machine_credential_source.schema_migrations(version,content_digest) VALUES($1,$2)")
            .bind(MIGRATION_VERSION).bind(digest).execute(&mut *transaction).await.map_err(unavailable)?;
    }
    transaction.commit().await.map_err(unavailable)?;
    Ok(())
}

/// Historical private evidence. It has no conversion into a current source
/// result, issuer authorization, verified credential, or machine proof.
pub struct HistoricalMachineCredentialSourceEvidence {
    organization_id: Uuid,
    evidence_ref: String,
    bytes: Vec<u8>,
    document: Value,
    retained_at: DateTime<Utc>,
}
impl HistoricalMachineCredentialSourceEvidence {
    pub fn organization_id(&self) -> Uuid {
        self.organization_id
    }
    pub fn evidence_ref(&self) -> &str {
        &self.evidence_ref
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn document(&self) -> &Value {
        &self.document
    }
    pub fn retained_at(&self) -> DateTime<Utc> {
        self.retained_at
    }
}
impl std::fmt::Debug for HistoricalMachineCredentialSourceEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HistoricalMachineCredentialSourceEvidence { <private> }")
    }
}

#[derive(Clone)]
pub struct PgMachineCredentialSourceEvidence {
    pool: PgPool,
}

impl PgMachineCredentialSourceEvidence {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn readiness(&self) -> Result<(), MachineEvidenceError> {
        check_isolated_role(
            &self.pool,
            &[
                ("machine_credential_source", "observations", "append"),
                ("machine_credential_source", "schema_migrations", "read"),
            ],
        )
        .await?;
        let privileges: bool = sqlx::query_scalar(
            "SELECT has_table_privilege(current_user,'machine_credential_source.observations','SELECT')
             AND has_table_privilege(current_user,'machine_credential_source.observations','INSERT')
             AND has_table_privilege(current_user,'machine_credential_source.schema_migrations','SELECT')",
        ).fetch_one(&self.pool).await.map_err(unavailable)?;
        if !privileges {
            return Err(MachineEvidenceError);
        }
        let digest: Option<String> = sqlx::query_scalar(
            "SELECT content_digest FROM machine_credential_source.schema_migrations WHERE version=$1",
        ).bind(MIGRATION_VERSION).fetch_optional(&self.pool).await.map_err(unavailable)?;
        if digest.as_deref() != Some(migration_digest().as_str()) {
            return Err(MachineEvidenceError);
        }
        let functions = sqlx::query(
            "SELECT p.proname,p.prosrc,p.prosecdef,p.proconfig,l.lanname,
                p.pronargs=0 AND p.prorettype='trigger'::regtype AND p.prokind='f' AND p.provolatile='v' AS function_shape
             FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
             JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='machine_credential_source'
             AND p.proname IN ('check_observation','check_observation_commit','reject_mutation')",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(unavailable)?;
        if functions.len() != 3 {
            return Err(MachineEvidenceError);
        }
        for function in functions {
            let name: String = function.try_get("proname").map_err(unavailable)?;
            let source: String = function.try_get("prosrc").map_err(unavailable)?;
            let config: Option<Vec<String>> = function.try_get("proconfig").map_err(unavailable)?;
            if function
                .try_get::<bool, _>("prosecdef")
                .map_err(unavailable)?
                || !function
                    .try_get::<bool, _>("function_shape")
                    .map_err(unavailable)?
                || function
                    .try_get::<String, _>("lanname")
                    .map_err(unavailable)?
                    != "plpgsql"
                || config.as_deref() != Some(&["search_path=pg_catalog".into()])
                || source != expected_body(&name)?
            {
                return Err(MachineEvidenceError);
            }
        }
        let triggers = sqlx::query(
            "SELECT t.tgname,t.tgenabled::text,t.tgtype,t.tgdeferrable,t.tginitdeferred,p.proname,
                t.tgqual IS NULL AND t.tgnargs=0 AND octet_length(t.tgargs)=0 AND t.tgattr::text=''
                AND t.tgoldtable IS NULL AND t.tgnewtable IS NULL AND t.tgconstrrelid=0 AS plain_shape,
                t.tgconstraint<>0 AS constraint_trigger,
                n.nspname FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
                JOIN pg_namespace n ON n.oid=p.pronamespace
             WHERE t.tgrelid='machine_credential_source.observations'::regclass AND NOT t.tgisinternal",
        ).fetch_all(&self.pool).await.map_err(unavailable)?;
        if triggers.len() != 4 {
            return Err(MachineEvidenceError);
        }
        for trigger in triggers {
            let name: String = trigger.try_get("tgname").map_err(unavailable)?;
            let (kind, deferred, function) = match name.as_str() {
                "machine_credential_source_binding" => (7_i16, false, "check_observation"),
                "machine_credential_source_commit" => (5, true, "check_observation_commit"),
                "machine_credential_source_immutable" => (27, false, "reject_mutation"),
                "machine_credential_source_no_truncate" => (34, false, "reject_mutation"),
                _ => return Err(MachineEvidenceError),
            };
            if trigger
                .try_get::<String, _>("tgenabled")
                .map_err(unavailable)?
                != "O"
                || trigger.try_get::<i16, _>("tgtype").map_err(unavailable)? != kind
                || trigger
                    .try_get::<bool, _>("tgdeferrable")
                    .map_err(unavailable)?
                    != deferred
                || trigger
                    .try_get::<bool, _>("tginitdeferred")
                    .map_err(unavailable)?
                    != deferred
                || trigger
                    .try_get::<String, _>("proname")
                    .map_err(unavailable)?
                    != function
                || trigger
                    .try_get::<String, _>("nspname")
                    .map_err(unavailable)?
                    != "machine_credential_source"
                || !trigger
                    .try_get::<bool, _>("plain_shape")
                    .map_err(unavailable)?
                || trigger
                    .try_get::<bool, _>("constraint_trigger")
                    .map_err(unavailable)?
                    != deferred
            {
                return Err(MachineEvidenceError);
            }
        }
        let constraints = sqlx::query(
            "SELECT conname,pg_get_expr(conbin,conrelid) AS expression FROM pg_constraint WHERE conrelid='machine_credential_source.observations'::regclass
                AND contype='c' AND convalidated AND conname IN ('machine_credential_source_digest',
                  'machine_credential_source_reference','machine_credential_source_bytes','machine_credential_source_window')",
        ).fetch_all(&self.pool).await.map_err(unavailable)?;
        if constraints.len() != 4 {
            return Err(MachineEvidenceError);
        }
        for constraint in constraints {
            let name: String = constraint.try_get("conname").map_err(unavailable)?;
            let expected=match name.as_str() {
                "machine_credential_source_bytes" => "((convert_from(evidence_bytes, 'UTF8'::name))::jsonb = evidence_document)",
                "machine_credential_source_digest" => "(evidence_digest = ('sha256:'::text || encode(sha256(evidence_bytes), 'hex'::text)))",
                "machine_credential_source_reference" => "(evidence_ref = ('urn:marty:machine-credential-source:'::text || evidence_digest))",
                "machine_credential_source_window" => "((observed_at <= completed_at) AND (completed_at <= retained_at) AND (retained_at < valid_until) AND (valid_until <= (observed_at + '00:00:30'::interval)))",
                _ => return Err(MachineEvidenceError),
            };
            if constraint
                .try_get::<String, _>("expression")
                .map_err(unavailable)?
                != expected
            {
                return Err(MachineEvidenceError);
            }
        }
        let primary:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_constraint c JOIN pg_index i ON i.indexrelid=c.conindid
            WHERE c.conrelid='machine_credential_source.observations'::regclass AND c.contype='p' AND c.convalidated
            AND NOT c.condeferrable AND NOT c.condeferred AND i.indisvalid AND i.indisready
            AND (SELECT array_agg(a.attname::text ORDER BY k.ord) FROM unnest(c.conkey) WITH ORDINALITY k(num,ord)
              JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.num)=ARRAY['organization_id','evidence_ref'])")
            .fetch_one(&self.pool).await.map_err(unavailable)?;
        if !primary {
            return Err(MachineEvidenceError);
        }
        Ok(())
    }

    pub(crate) async fn retain(
        &self,
        record: &SourceEvidence,
    ) -> Result<String, MachineEvidenceError> {
        let bytes = serde_json::to_vec(record).map_err(unavailable)?;
        if bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(MachineEvidenceError);
        }
        let document: Value = serde_json::from_slice(&bytes).map_err(unavailable)?;
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        let reference = format!("urn:marty:machine-credential-source:{digest}");
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        sqlx::raw_sql("SET LOCAL lock_timeout='5s'; SET LOCAL statement_timeout='5s'")
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        let retained_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(unavailable)?;
        record.validate(retained_at)?;
        sqlx::query(
            "INSERT INTO machine_credential_source.observations
                (organization_id,evidence_ref,evidence_digest,scope_digest,credential_id,credential_digest,
                 evidence_bytes,evidence_document,observed_at,completed_at,valid_until,retained_at)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,($9::text)::timestamptz,($10::text)::timestamptz,($11::text)::timestamptz,$12)
             ON CONFLICT(organization_id,evidence_ref) DO NOTHING",
        ).bind(record.selection.organization_id).bind(&reference).bind(&digest)
            .bind(&record.selection.scope_digest).bind(record.selection.credential_id)
            .bind(&record.selection.credential_digest).bind(&bytes).bind(&document)
            .bind(record.observed_at.to_rfc3339()).bind(record.completed_at.to_rfc3339())
            .bind(record.valid_until.to_rfc3339()).bind(retained_at)
            .execute(&mut *transaction).await.map_err(unavailable)?;
        let row = sqlx::query(SELECT_EVIDENCE)
            .bind(record.selection.organization_id)
            .bind(&reference)
            .fetch_one(&mut *transaction)
            .await
            .map_err(unavailable)?;
        let retained = decode(row)?;
        if retained.bytes != bytes || retained.document != document {
            return Err(MachineEvidenceError);
        }
        let after: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *transaction)
            .await
            .map_err(unavailable)?;
        if after < retained_at {
            return Err(MachineEvidenceError);
        }
        record.validate(after)?;
        // Shield only COMMIT from a caller's source timeout. Dropping the
        // JoinHandle lets COMMIT finish, without returning authority or retrying.
        sqlx::raw_sql("SET LOCAL statement_timeout=0; SET LOCAL lock_timeout=0")
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        tokio::spawn(async move { transaction.commit().await })
            .await
            .map_err(unavailable)?
            .map_err(unavailable)?;
        Ok(reference)
    }

    pub async fn recover(
        &self,
        organization_id: Uuid,
        evidence_ref: &str,
    ) -> Result<Option<HistoricalMachineCredentialSourceEvidence>, MachineEvidenceError> {
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

fn decode(
    row: sqlx::postgres::PgRow,
) -> Result<HistoricalMachineCredentialSourceEvidence, MachineEvidenceError> {
    let bytes: Vec<u8> = row.try_get("evidence_bytes").map_err(unavailable)?;
    if bytes.is_empty() || bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(MachineEvidenceError);
    }
    let record: SourceEvidence = serde_json::from_slice(&bytes).map_err(unavailable)?;
    record.validate(record.completed_at)?;
    let document: Value = row.try_get("evidence_document").map_err(unavailable)?;
    let organization_id: Uuid = row.try_get("organization_id").map_err(unavailable)?;
    let reference: String = row.try_get("evidence_ref").map_err(unavailable)?;
    let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
    let retained_at: DateTime<Utc> = row.try_get("retained_at").map_err(unavailable)?;
    let completed_at: DateTime<Utc> = row.try_get("completed_at").map_err(unavailable)?;
    let valid_until: DateTime<Utc> = row.try_get("valid_until").map_err(unavailable)?;
    if document != serde_json::from_slice::<Value>(&bytes).map_err(unavailable)?
        || organization_id != record.selection.organization_id
        || reference != format!("urn:marty:machine-credential-source:{digest}")
        || row
            .try_get::<String, _>("evidence_digest")
            .map_err(unavailable)?
            != digest
        || row
            .try_get::<String, _>("scope_digest")
            .map_err(unavailable)?
            != record.selection.scope_digest
        || row
            .try_get::<Uuid, _>("credential_id")
            .map_err(unavailable)?
            != record.selection.credential_id
        || row
            .try_get::<String, _>("credential_digest")
            .map_err(unavailable)?
            != record.selection.credential_digest
        || !row.try_get::<bool, _>("times_match").map_err(unavailable)?
        || retained_at < completed_at
        || retained_at >= valid_until
    {
        return Err(MachineEvidenceError);
    }
    Ok(HistoricalMachineCredentialSourceEvidence {
        organization_id,
        evidence_ref: reference,
        bytes,
        document,
        retained_at,
    })
}

fn migration_digest() -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(MACHINE_CREDENTIAL_SOURCE_MIGRATION.as_bytes())
    )
}

fn expected_body(name: &str) -> Result<&'static str, MachineEvidenceError> {
    MACHINE_CREDENTIAL_SOURCE_MIGRATION
        .split_once(&format!(
            "CREATE FUNCTION machine_credential_source.{name}()"
        ))
        .and_then(|(_, rest)| rest.split_once("AS $$"))
        .and_then(|(_, rest)| rest.split_once("$$;"))
        .map(|(body, _)| body)
        .ok_or(MachineEvidenceError)
}

fn valid_reference(reference: &str) -> bool {
    reference
        .strip_prefix(MACHINE_CREDENTIAL_EVIDENCE_REF_PREFIX)
        .is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}
