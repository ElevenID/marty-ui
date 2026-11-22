use std::fmt;

use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use sqlx::{postgres::PgRow, PgConnection, PgPool, Row};
use uuid::Uuid;

use super::{
    database_error,
    domain::{digest, valid_digest},
    owner::{database_now, decode},
    MachineRegistryDocuments, MachineRegistryError as Error, MachineRegistrySelection,
    MachineRegistryUseScope, MACHINE_REGISTRY_MIGRATION, MACHINE_REGISTRY_SOURCE_PROFILE,
    MACHINE_REGISTRY_SOURCE_REF_PREFIX,
};

/// One committed source observation. It is not a holder proof or permission.
pub struct MachineRegistryObservation {
    documents: MachineRegistryDocuments,
    evidence_ref: String,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}
impl MachineRegistryObservation {
    pub fn documents(&self) -> &MachineRegistryDocuments {
        &self.documents
    }
    pub fn evidence_ref(&self) -> &str {
        &self.evidence_ref
    }
    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
    pub fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }
}

/// History deliberately has no conversion into a current source observation.
pub struct HistoricalMachineRegistryObservation {
    document: Value,
    bytes: Vec<u8>,
    evidence_ref: String,
    retained_at: DateTime<Utc>,
}
impl HistoricalMachineRegistryObservation {
    pub fn document(&self) -> &Value {
        &self.document
    }
    pub fn evidence_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn evidence_ref(&self) -> &str {
        &self.evidence_ref
    }
    pub fn retained_at(&self) -> DateTime<Utc> {
        self.retained_at
    }
}

#[derive(Clone)]
pub struct PgMachineRegistrySource {
    pool: PgPool,
    selection: MachineRegistrySelection,
}
impl PgMachineRegistrySource {
    pub fn new(pool: PgPool, selection: MachineRegistrySelection) -> Self {
        Self { pool, selection }
    }
    pub fn selection(&self) -> MachineRegistrySelection {
        self.selection
    }

    /// The source identity is a nonowner reader of registry/status/history and
    /// INSERT-only producer of its own observations. It cannot administer a
    /// machine, policy, credential, grant or use ledger, even via SET ROLE.
    pub async fn readiness(&self) -> Result<(), Error> {
        let mut connection = self.pool.acquire().await.map_err(database_error)?;
        validate_schema(&mut connection).await?;
        validate_source_role(&mut connection).await
    }

    pub async fn observe(
        &self,
        scope: MachineRegistryUseScope,
        now: DateTime<Utc>,
    ) -> Result<MachineRegistryObservation, Error> {
        scope.validate(self.selection)?;
        let original_deadline = now
            .checked_add_signed(Duration::seconds(30))
            .ok_or(Error::InvalidRequest)?;
        let mut tx = self.pool.begin().await.map_err(database_error)?;
        // One MVCC snapshot covers organization status, current entry and its
        // immutable history. No write privilege is granted merely to take a lock.
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        sqlx::query("SET LOCAL TIME ZONE 'UTC'")
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        sqlx::query("SET LOCAL lock_timeout='5s'")
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        validate_schema(&mut tx).await?;
        validate_source_role(&mut tx).await?;
        check_window(database_now(&mut tx).await?, now, original_deadline)?;
        let mut rows = sqlx::query("SELECT r.*,to_jsonb(r) AS source_snapshot,h.snapshot AS historical_snapshot
            FROM organization_service.machine_registry_entries r
            JOIN organization_service.organizations o ON o.id=r.organization_id AND o.status='active'
            JOIN organization_service.machine_registry_history h ON h.organization_id=r.organization_id
              AND h.machine_identity_id=r.machine_identity_id AND h.revision=r.revision
            WHERE r.organization_id=$1 AND r.deployment_profile_id=$2 AND r.principal_id=$3 AND r.status='ACTIVE' LIMIT 2")
            .bind(self.selection.organization_id()).bind(self.selection.deployment_profile_id()).bind(&scope.principal_id)
            .fetch_all(&mut *tx).await.map_err(database_error)?;
        if rows.len() != 1 {
            return Err(Error::NotFound);
        }
        let row = rows.pop().ok_or(Error::NotFound)?;
        let snapshot: Value = row
            .try_get("source_snapshot")
            .map_err(|_| Error::CorruptData)?;
        let historical: Value = row
            .try_get("historical_snapshot")
            .map_err(|_| Error::CorruptData)?;
        let record = decode(row)?;
        if snapshot != historical || record.projection.key_thumbprint != scope.key_thumbprint {
            return Err(Error::AccessDenied);
        }
        let observed_at = database_now(&mut tx).await?;
        check_window(observed_at, now, original_deadline)?;
        if observed_at < record.updated_at {
            return Err(Error::Unavailable);
        }
        let documents = MachineRegistryDocuments::from_document(&record.documents)?;
        let qualified = documents
            .validate(scope.organization_id, observed_at)
            .map_err(|_| Error::AccessDenied)?;
        let deadline = qualified
            .key_valid_until
            .unwrap_or(original_deadline)
            .min(original_deadline);
        // PostgreSQL stores microseconds. Round down so the bytes, SQL value
        // and original deadline agree without ever extending source authority.
        let valid_until = DateTime::from_timestamp_micros(deadline.timestamp_micros())
            .ok_or(Error::Unavailable)?;
        check_window(observed_at, now, valid_until)?;
        let evidence = json!({
            "profile":MACHINE_REGISTRY_SOURCE_PROFILE,
            "organization_id":scope.organization_id,
            "machine_identity_id":record.machine_identity_id(),
            "deployment_profile_id":self.selection.deployment_profile_id(),
            "registry_revision":record.revision,
            "scope":scope,
            "source_snapshot":snapshot,
            "started_at":now,
            "observed_at":observed_at,
            "valid_until":valid_until,
        });
        let bytes = serde_json::to_vec(&evidence).map_err(|_| Error::CorruptData)?;
        let evidence_digest = digest(&bytes);
        let evidence_ref = format!(
            "{MACHINE_REGISTRY_SOURCE_REF_PREFIX}{}",
            &evidence_digest[7..]
        );
        let inserted = sqlx::query("INSERT INTO organization_service.machine_registry_observations
            (organization_id,machine_identity_id,revision,evidence_ref,evidence_digest,document,evidence_bytes,observed_at,valid_until)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(record.organization_id()).bind(record.machine_identity_id()).bind(record.revision as i64)
            .bind(&evidence_ref).bind(evidence_digest).bind(&evidence).bind(&bytes).bind(observed_at).bind(valid_until)
            .execute(&mut *tx).await.map_err(database_error)?;
        if inserted.rows_affected() != 1 {
            return Err(Error::Unavailable);
        }
        let retained = decode_history(
            sqlx::query("SELECT * FROM organization_service.machine_registry_observations WHERE organization_id=$1 AND evidence_ref=$2")
                .bind(record.organization_id()).bind(&evidence_ref).fetch_one(&mut *tx).await.map_err(database_error)?
        )?;
        if retained.bytes != bytes || retained.document != evidence {
            return Err(Error::CorruptData);
        }
        check_window(database_now(&mut tx).await?, observed_at, valid_until)?;
        // No cancellation timeout around COMMIT: an unknown outcome must not
        // be replayed or converted into a successful source assertion.
        // The machine gate bounds provider work, so its future may be dropped.
        // Detaching this one final commit preserves a database decision already
        // in progress; cancellation yields no positive observation and no retry.
        sqlx::query("SET LOCAL statement_timeout=0")
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        sqlx::query("SET LOCAL lock_timeout=0")
            .execute(&mut *tx)
            .await
            .map_err(database_error)?;
        tokio::spawn(async move { tx.commit().await })
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(database_error)?;
        check_window(Utc::now(), observed_at, valid_until)?;
        Ok(MachineRegistryObservation {
            documents,
            evidence_ref,
            observed_at,
            valid_until,
        })
    }

    /// A consuming host separately authorizes historical inspection. No new
    /// source read or renewed authority results from this method.
    pub async fn recover(
        &self,
        evidence_ref: &str,
    ) -> Result<HistoricalMachineRegistryObservation, Error> {
        let Some(suffix) = evidence_ref.strip_prefix(MACHINE_REGISTRY_SOURCE_REF_PREFIX) else {
            return Err(Error::InvalidRequest);
        };
        if !valid_digest(&format!("sha256:{suffix}")) {
            return Err(Error::InvalidRequest);
        }
        let row = sqlx::query(
            "SELECT * FROM organization_service.machine_registry_observations
            WHERE organization_id=$1 AND evidence_ref=$2 AND document->>'deployment_profile_id'=$3",
        )
        .bind(self.selection.organization_id())
        .bind(evidence_ref)
        .bind(self.selection.deployment_profile_id().to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(database_error)?
        .ok_or(Error::NotFound)?;
        decode_history(row)
    }
}

fn check_window(
    now: DateTime<Utc>,
    from: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<(), Error> {
    if now < from || now >= until {
        return Err(Error::Unavailable);
    }
    Ok(())
}

fn decode_history(row: PgRow) -> Result<HistoricalMachineRegistryObservation, Error> {
    let invalid = |_| Error::CorruptData;
    let document: Value = row.try_get("document").map_err(invalid)?;
    let bytes: Vec<u8> = row.try_get("evidence_bytes").map_err(invalid)?;
    let evidence_ref: String = row.try_get("evidence_ref").map_err(invalid)?;
    let stored_digest: String = row.try_get("evidence_digest").map_err(invalid)?;
    let organization: Uuid = row.try_get("organization_id").map_err(invalid)?;
    let machine: Uuid = row.try_get("machine_identity_id").map_err(invalid)?;
    let revision: i64 = row.try_get("revision").map_err(invalid)?;
    let observed_at: DateTime<Utc> = row.try_get("observed_at").map_err(invalid)?;
    let valid_until: DateTime<Utc> = row.try_get("valid_until").map_err(invalid)?;
    let retained_at: DateTime<Utc> = row.try_get("retained_at").map_err(invalid)?;
    if digest(&bytes) != stored_digest
        || evidence_ref
            != format!(
                "{MACHINE_REGISTRY_SOURCE_REF_PREFIX}{}",
                &stored_digest[7..]
            )
        || serde_json::from_slice::<Value>(&bytes).map_err(|_| Error::CorruptData)? != document
        || document["profile"] != MACHINE_REGISTRY_SOURCE_PROFILE
        || document["organization_id"] != organization.to_string()
        || document["machine_identity_id"] != machine.to_string()
        || document["registry_revision"].as_i64() != Some(revision)
        || serde_json::from_value::<DateTime<Utc>>(document["observed_at"].clone())
            .map_err(|_| Error::CorruptData)?
            != observed_at
        || serde_json::from_value::<DateTime<Utc>>(document["valid_until"].clone())
            .map_err(|_| Error::CorruptData)?
            != valid_until
        || retained_at < observed_at
        || retained_at >= valid_until
        || valid_until > observed_at + Duration::seconds(30)
    {
        return Err(Error::CorruptData);
    }
    Ok(HistoricalMachineRegistryObservation {
        document,
        bytes,
        evidence_ref,
        retained_at,
    })
}

/// Validate exact reviewed guard bodies as well as trigger timing and shape.
pub(crate) async fn validate_schema(connection: &mut PgConnection) -> Result<(), Error> {
    let version: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organization_service.rust_schema_versions WHERE version=$1)",
    )
    .bind(MACHINE_REGISTRY_MIGRATION)
    .fetch_one(&mut *connection)
    .await
    .map_err(database_error)?;
    if !version {
        return Err(Error::Unavailable);
    }
    let guards: i64 = sqlx::query_scalar("WITH expected(table_name,trigger_name,function_name,trigger_type,deferred) AS (VALUES
        ('machine_registry_entries','machine_registry_entry_guard','guard_machine_registry_entry',23,false),
        ('machine_registry_entries','machine_registry_entry_no_removal','reject_machine_registry_mutation',42,false),
        ('machine_registry_entries','machine_registry_entry_complete','check_machine_registry_complete',21,true),
        ('machine_registry_history','machine_registry_history_guard','guard_machine_registry_history',7,false),
        ('machine_registry_history','machine_registry_history_immutable','reject_machine_registry_mutation',58,false),
        ('machine_registry_observations','machine_registry_observation_guard','guard_machine_registry_observation',7,false),
        ('machine_registry_observations','machine_registry_observation_immutable','reject_machine_registry_mutation',58,false),
        ('machine_registry_observations','machine_registry_observation_commit','check_machine_registry_observation_commit',5,true))
      SELECT count(*) FROM expected e JOIN pg_trigger t
        ON t.tgrelid=to_regclass('organization_service.'||e.table_name) AND t.tgname=e.trigger_name
      JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_language l ON l.oid=p.prolang
      WHERE NOT t.tgisinternal AND t.tgenabled='O' AND t.tgqual IS NULL AND t.tgtype=e.trigger_type
        AND t.tgnargs=0 AND t.tgattr=''::int2vector AND t.tgdeferrable=e.deferred AND t.tginitdeferred=e.deferred
        AND (t.tgconstraint<>0)=e.deferred AND t.tgfoid=to_regprocedure('organization_service.'||e.function_name||'()')
        AND NOT p.prosecdef AND p.prorettype='trigger'::regtype AND p.prokind='f' AND l.lanname='plpgsql'
        AND p.proconfig=ARRAY['search_path=pg_catalog']::text[]")
        .fetch_one(&mut *connection).await.map_err(database_error)?;
    if guards != 8 {
        return Err(Error::Unavailable);
    }
    let keys: i64 = sqlx::query_scalar("WITH expected(table_name,key_columns,kind) AS (VALUES
        ('machine_registry_entries',ARRAY['organization_id','machine_identity_id'],'p'),
        ('machine_registry_entries',ARRAY['organization_id','principal_id'],'u'),
        ('machine_registry_history',ARRAY['organization_id','machine_identity_id','revision'],'p'),
        ('machine_registry_observations',ARRAY['evidence_ref'],'p'))
        SELECT count(*) FROM expected e JOIN pg_constraint c ON c.conrelid=to_regclass('organization_service.'||e.table_name)
        JOIN pg_index i ON i.indexrelid=c.conindid
        WHERE c.contype::text=e.kind AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
          AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
          AND i.indpred IS NULL AND i.indexprs IS NULL
          AND ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(attnum,position)
            JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum ORDER BY k.position)=e.key_columns")
        .fetch_one(&mut *connection).await.map_err(database_error)?;
    if keys != 4 {
        return Err(Error::Unavailable);
    }
    let constraints: i64 = sqlx::query_scalar("WITH expected(table_name,name,expression) AS (VALUES
        ('machine_registry_entries','machine_registry_document_bytes','((convert_from(document_bytes, ''UTF8''::name))::jsonb = documents)'),
        ('machine_registry_entries','machine_registry_document_digest','(document_digest = (''sha256:''::text || encode(sha256(document_bytes), ''hex''::text)))'),
        ('machine_registry_observations','machine_registry_observation_bytes','((convert_from(evidence_bytes, ''UTF8''::name))::jsonb = document)'),
        ('machine_registry_observations','machine_registry_observation_digest','(evidence_digest = (''sha256:''::text || encode(sha256(evidence_bytes), ''hex''::text)))'),
        ('machine_registry_observations','machine_registry_observation_ref','(evidence_ref = (''urn:marty:machine-registry:sha256:''::text || encode(sha256(evidence_bytes), ''hex''::text)))'),
        ('machine_registry_observations','machine_registry_observation_window','((valid_until > observed_at) AND (valid_until <= (observed_at + ''00:00:30''::interval)))'),
        ('machine_registry_observations','machine_registry_observation_retention_window','((retained_at >= observed_at) AND (retained_at < valid_until))'))
        SELECT count(*) FROM expected e JOIN pg_constraint c
          ON c.conrelid=to_regclass('organization_service.'||e.table_name) AND c.conname=e.name
        WHERE c.contype='c' AND c.convalidated AND c.conislocal AND pg_get_expr(c.conbin,c.conrelid)=e.expression")
        .fetch_one(&mut *connection).await.map_err(database_error)?;
    if constraints != 7 {
        return Err(Error::Unavailable);
    }
    let migration = include_str!("../../migrations/0005_machine_registry.sql");
    for name in [
        "reject_machine_registry_mutation",
        "guard_machine_registry_entry",
        "guard_machine_registry_history",
        "check_machine_registry_complete",
        "guard_machine_registry_observation",
        "check_machine_registry_observation_commit",
    ] {
        let marker = format!("CREATE OR REPLACE FUNCTION organization_service.{name}()");
        let expected = migration
            .split_once(&marker)
            .and_then(|(_, t)| t.split_once("AS $$"))
            .and_then(|(_, t)| t.split_once("$$;"))
            .map(|(body, _)| body)
            .ok_or(Error::Unavailable)?;
        let actual: String =
            sqlx::query_scalar("SELECT prosrc FROM pg_proc WHERE oid=to_regprocedure($1)")
                .bind(format!("organization_service.{name}()"))
                .fetch_one(&mut *connection)
                .await
                .map_err(database_error)?;
        if expected != actual {
            return Err(Error::Unavailable);
        }
    }
    Ok(())
}

async fn validate_source_role(connection: &mut PgConnection) -> Result<(), Error> {
    let allowed: bool = sqlx::query_scalar("SELECT current_user=session_user AND NOT pg_is_in_recovery()
        AND has_schema_privilege(current_user,'organization_service','USAGE')
        AND has_table_privilege(current_user,'organization_service.rust_schema_versions','SELECT')
        AND has_table_privilege(current_user,'organization_service.organizations','SELECT')
        AND has_table_privilege(current_user,'organization_service.machine_registry_entries','SELECT')
        AND has_table_privilege(current_user,'organization_service.machine_registry_history','SELECT')
        AND has_table_privilege(current_user,'organization_service.machine_registry_observations','SELECT')
        AND has_table_privilege(current_user,'organization_service.machine_registry_observations','INSERT')
        AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE (r.rolname=current_user OR pg_has_role(current_user,r.oid,'MEMBER')) AND (
            r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls
            OR left(r.rolname::text,3)='pg_'
            OR EXISTS(SELECT 1 FROM pg_database d WHERE d.datname=current_database() AND d.datdba=r.oid)
            OR has_database_privilege(r.oid,current_database(),'CREATE,CONNECT WITH GRANT OPTION,TEMPORARY WITH GRANT OPTION')
            OR EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid AND m.admin_option)
            OR EXISTS(SELECT 1 FROM pg_namespace n WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema'
                AND (n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE,USAGE WITH GRANT OPTION')))
            OR EXISTS(SELECT 1 FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
                WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema' AND t.relkind IN ('r','p','v','m','f','S') AND (
                  t.relowner=r.oid OR has_table_privilege(r.oid,t.oid,'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,DELETE WITH GRANT OPTION,TRUNCATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION,TRIGGER WITH GRANT OPTION')
                  OR CASE WHEN current_setting('server_version_num')::INT>=170000 THEN has_table_privilege(r.oid,t.oid,'MAINTAIN') ELSE false END
                  OR has_any_column_privilege(r.oid,t.oid,'UPDATE,REFERENCES,SELECT WITH GRANT OPTION,INSERT WITH GRANT OPTION,UPDATE WITH GRANT OPTION,REFERENCES WITH GRANT OPTION')
                  OR ((n.nspname<>'organization_service' OR t.relname<>'machine_registry_observations')
                    AND (has_table_privilege(r.oid,t.oid,'INSERT') OR has_any_column_privilege(r.oid,t.oid,'INSERT')))
                  OR ((n.nspname<>'organization_service' OR t.relname NOT IN
                      ('rust_schema_versions','organizations','machine_registry_entries','machine_registry_history','machine_registry_observations'))
                    AND (has_table_privilege(r.oid,t.oid,'SELECT') OR has_any_column_privilege(r.oid,t.oid,'SELECT')))))
            OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                WHERE left(n.nspname::TEXT,3)<>'pg_' AND n.nspname<>'information_schema'
                  AND (p.proowner=r.oid OR has_function_privilege(r.oid,p.oid,'EXECUTE WITH GRANT OPTION')
                    OR (p.prosecdef AND has_function_privilege(r.oid,p.oid,'EXECUTE'))))))")
        .fetch_one(connection).await.map_err(database_error)?;
    if !allowed {
        return Err(Error::AccessDenied);
    }
    Ok(())
}

macro_rules! private_debug {
    ($($name:ident),+ $(,)?) => {$(
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { <private> }"))
            }
        }
    )+};
}
private_debug!(
    MachineRegistryObservation,
    HistoricalMachineRegistryObservation,
    PgMachineRegistrySource
);
