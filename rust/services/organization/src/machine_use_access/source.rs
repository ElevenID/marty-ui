use super::{
    digest, unavailable, Error, MachineUseAccessRecord, MachineUseAccessRequest,
    MachineUseAccessScope, MachineUseAccessSelection, MACHINE_USE_ACCESS_MIGRATION,
};
use crate::machine_registry::MachineRegistryDocuments;
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use sqlx::{PgConnection, PgPool, Row};
use std::{fmt, time::Duration as Timeout};

/// Opaque bounded result from current owner state. No Deserialize or public
/// constructor can promote historical administration into current access.
pub struct CurrentMachineUseAccess {
    scope: MachineUseAccessScope,
    record: MachineUseAccessRecord,
    snapshot_bytes: Vec<u8>,
    registry_revision: u64,
    history_ref: String,
    observed_at: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}
impl CurrentMachineUseAccess {
    pub fn scope(&self) -> &MachineUseAccessScope {
        &self.scope
    }
    pub fn record(&self) -> &MachineUseAccessRecord {
        &self.record
    }
    pub fn snapshot_bytes(&self) -> &[u8] {
        &self.snapshot_bytes
    }
    pub fn registry_revision(&self) -> u64 {
        self.registry_revision
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
impl fmt::Debug for CurrentMachineUseAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CurrentMachineUseAccess { <private> }")
    }
}
#[derive(Clone)]
pub struct PgMachineUseAccessSource {
    pool: PgPool,
    selection: MachineUseAccessSelection,
}
impl fmt::Debug for PgMachineUseAccessSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PgMachineUseAccessSource { <private> }")
    }
}
impl PgMachineUseAccessSource {
    pub fn new(pool: PgPool, selection: MachineUseAccessSelection) -> Self {
        Self { pool, selection }
    }
    pub fn selection(&self) -> MachineUseAccessSelection {
        self.selection
    }
    pub async fn readiness(&self) -> Result<(), Error> {
        tokio::time::timeout(Timeout::from_secs(5), async {
            let mut connection = self.pool.acquire().await.map_err(unavailable)?;
            validate_machine_use_access_schema(&mut connection).await?;
            crate::machine_registry::validate_schema(&mut connection)
                .await
                .map_err(unavailable)?;
            validate_source_role(&mut connection).await
        })
        .await
        .map_err(unavailable)?
    }
    pub async fn observe(
        &self,
        scope: MachineUseAccessScope,
        started_at: DateTime<Utc>,
    ) -> Result<CurrentMachineUseAccess, Error> {
        scope.validate(self.selection)?;
        tokio::time::timeout(
            Timeout::from_secs(5),
            self.observe_bounded(scope, started_at),
        )
        .await
        .map_err(unavailable)?
    }
    async fn observe_bounded(
        &self,
        scope: MachineUseAccessScope,
        started_at: DateTime<Utc>,
    ) -> Result<CurrentMachineUseAccess, Error> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        sqlx::raw_sql("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY; SET LOCAL TIME ZONE 'UTC'; SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='5s'")
            .execute(&mut *tx).await.map_err(unavailable)?;
        validate_machine_use_access_schema(&mut tx).await?;
        crate::machine_registry::validate_schema(&mut tx)
            .await
            .map_err(unavailable)?;
        validate_source_role(&mut tx).await?;
        let observed_at = super::owner::database_now(&mut tx).await?;
        let original_end = started_at
            .checked_add_signed(Duration::seconds(30))
            .ok_or(Error::Invalid)?;
        let mut valid_until = DateTime::from_timestamp_micros(original_end.timestamp_micros())
            .ok_or(Error::Invalid)?;
        if observed_at < started_at || observed_at >= valid_until {
            return Err(Error::AccessDenied);
        }
        let row=sqlx::query("SELECT a.*,h.snapshot_bytes AS history_bytes,h.snapshot_digest AS history_digest,h.snapshot AS history_snapshot,
            r.revision AS registry_revision,r.document_bytes AS registry_bytes,r.document_digest AS registry_digest,r.documents AS registry_documents,
            r.documents_recorded_at AS registry_recorded_at,r.updated_at AS registry_updated_at,r.key_thumbprint AS registry_key_thumbprint,
            (rh.snapshot=to_jsonb(r)) AS registry_history_matches
          FROM organization_service.machine_use_access a
          JOIN organization_service.organizations o ON o.id=a.organization_id AND o.status='active'
          JOIN organization_service.machine_use_access_history h ON h.organization_id=a.organization_id AND h.machine_identity_id=a.machine_identity_id AND h.revision=a.revision
          JOIN organization_service.machine_registry_entries r ON r.organization_id=a.organization_id AND r.machine_identity_id=a.machine_identity_id
            AND r.principal_id=a.principal_id AND r.deployment_profile_id=a.deployment_profile_id AND r.status='ACTIVE'
          JOIN organization_service.machine_registry_history rh ON rh.organization_id=r.organization_id AND rh.machine_identity_id=r.machine_identity_id AND rh.revision=r.revision
          WHERE a.organization_id=$1 AND a.principal_id=$2 AND a.deployment_profile_id=$3 AND a.status='ACTIVE'")
            .bind(self.selection.organization_id()).bind(&scope.principal_id).bind(self.selection.deployment_profile_id())
            .fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or(Error::AccessDenied)?;
        let (record, snapshot_bytes, history_digest) = super::owner::decode(&row)?;
        let registry_bytes: Vec<u8> = row.try_get("registry_bytes").map_err(unavailable)?;
        let registry_documents: Value = row.try_get("registry_documents").map_err(unavailable)?;
        let recorded_at: DateTime<Utc> =
            row.try_get("registry_recorded_at").map_err(unavailable)?;
        let registry_updated_at: DateTime<Utc> =
            row.try_get("registry_updated_at").map_err(unavailable)?;
        let registry_revision: i64 = row.try_get("registry_revision").map_err(unavailable)?;
        let is_recovery = matches!(scope.request, MachineUseAccessRequest::Recover { .. });
        // Historical recovery keeps current identity/access requirements but
        // deliberately does not renew or require the old proof/key lifetime.
        let registry = MachineRegistryDocuments::from_document(&registry_documents)
            .map_err(unavailable)?
            .validate(
                self.selection.organization_id(),
                if is_recovery {
                    recorded_at
                } else {
                    observed_at
                },
            )
            .map_err(|_| Error::AccessDenied)?;
        if record.organization_id != scope.organization_id
            || record.principal_id != scope.principal_id
            || record.deployment_profile_id != self.selection.deployment_profile_id()
            || !record.permissions.contains(&scope.request.permission())
            || record.valid_from > observed_at
            || record.valid_until <= observed_at
            || record.updated_at > observed_at
            || snapshot_bytes
                != row
                    .try_get::<Vec<u8>, _>("history_bytes")
                    .map_err(unavailable)?
            || history_digest
                != row
                    .try_get::<String, _>("history_digest")
                    .map_err(unavailable)?
            || serde_json::to_value(&record).map_err(unavailable)?
                != row
                    .try_get::<Value, _>("history_snapshot")
                    .map_err(unavailable)?
            || !row
                .try_get::<bool, _>("registry_history_matches")
                .map_err(unavailable)?
            || digest(&registry_bytes)
                != row
                    .try_get::<String, _>("registry_digest")
                    .map_err(unavailable)?
            || serde_json::from_slice::<Value>(&registry_bytes).map_err(unavailable)?
                != registry_documents
            || registry.projection.organization_id != record.organization_id
            || registry.projection.machine_identity_id != record.machine_identity_id
            || registry.projection.principal_id != record.principal_id
            || registry.projection.deployment_profile_id != record.deployment_profile_id
            || registry_updated_at > observed_at
            || recorded_at > observed_at
            || registry_revision <= 0
            || registry.projection.key_thumbprint
                != row
                    .try_get::<String, _>("registry_key_thumbprint")
                    .map_err(unavailable)?
            || scope
                .request
                .expected_key()
                .is_some_and(|k| k != registry.projection.key_thumbprint)
        {
            return Err(Error::AccessDenied);
        }
        valid_until = valid_until.min(record.valid_until);
        if !is_recovery {
            if let Some(end) = registry.key_valid_until {
                valid_until = valid_until.min(end);
            }
        }
        // A later SQL consumer must never round a sub-microsecond key bound up.
        valid_until = DateTime::from_timestamp_micros(valid_until.timestamp_micros())
            .ok_or(Error::Unavailable)?;
        let completed_at = super::owner::database_now(&mut tx).await?;
        if completed_at < observed_at || completed_at >= valid_until {
            return Err(Error::AccessDenied);
        }
        // Read-only transaction; cancellation has no externally visible work.
        tx.commit().await.map_err(unavailable)?;
        let after = Utc::now();
        if after < completed_at || after >= valid_until {
            return Err(Error::AccessDenied);
        }
        let history_ref = format!(
            "urn:marty:machine-use-access:{}:{}:{}:{}",
            record.organization_id,
            record.machine_identity_id,
            record.revision,
            &history_digest[7..]
        );
        Ok(CurrentMachineUseAccess {
            scope,
            record,
            snapshot_bytes,
            registry_revision: registry_revision as u64,
            history_ref,
            observed_at,
            valid_until,
        })
    }
}

async fn validate_source_role(connection: &mut PgConnection) -> Result<(), Error> {
    let allowed = [
        "rust_schema_versions",
        "organizations",
        "machine_registry_entries",
        "machine_registry_history",
        "machine_use_access",
        "machine_use_access_history",
    ];
    let valid:bool=sqlx::query_scalar("SELECT current_user=session_user AND NOT pg_is_in_recovery()
      AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE (r.rolname=current_user OR pg_has_role(current_user,r.oid,'MEMBER')) AND (
        r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolbypassrls OR r.rolreplication OR left(r.rolname::text,3)='pg_'
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
        .bind(allowed.as_slice()).fetch_one(connection).await.map_err(unavailable)?;
    if valid {
        Ok(())
    } else {
        Err(Error::AccessDenied)
    }
}

pub async fn validate_machine_use_access_schema(
    connection: &mut PgConnection,
) -> Result<(), Error> {
    let version: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organization_service.rust_schema_versions WHERE version=$1)",
    )
    .bind(MACHINE_USE_ACCESS_MIGRATION)
    .fetch_one(&mut *connection)
    .await
    .map_err(unavailable)?;
    let guards:i64=sqlx::query_scalar("WITH expected(table_name,trigger_name,function_name,trigger_type,deferred) AS (VALUES
        ('machine_use_access','machine_use_access_guard','guard_machine_use_access',23,false),
        ('machine_use_access','machine_use_access_no_removal','reject_machine_use_access_history_mutation',42,false),
        ('machine_use_access','machine_use_access_complete','check_machine_use_access_complete',21,true),
        ('machine_use_access_history','machine_use_access_history_guard','guard_machine_use_access_history',7,false),
        ('machine_use_access_history','machine_use_access_history_immutable','reject_machine_use_access_history_mutation',58,false))
      SELECT count(*) FROM expected e JOIN pg_trigger t ON t.tgrelid=to_regclass('organization_service.'||e.table_name) AND t.tgname=e.trigger_name
      JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_language l ON l.oid=p.prolang
      WHERE NOT t.tgisinternal AND t.tgenabled='O' AND t.tgqual IS NULL AND t.tgtype=e.trigger_type
        AND t.tgnargs=0 AND t.tgattr=''::int2vector AND t.tgdeferrable=e.deferred AND t.tginitdeferred=e.deferred
        AND (t.tgconstraint<>0)=e.deferred AND t.tgfoid=to_regprocedure('organization_service.'||e.function_name||'()')
        AND NOT p.prosecdef AND p.prorettype='trigger'::regtype AND p.prokind='f' AND l.lanname='plpgsql'
        AND p.proconfig=ARRAY['search_path=pg_catalog']::text[]")
        .fetch_one(&mut *connection).await.map_err(unavailable)?;
    let keys:i64=sqlx::query_scalar("WITH expected(table_name,key_columns) AS (VALUES
        ('machine_use_access',ARRAY['organization_id','machine_identity_id']),
        ('machine_use_access_history',ARRAY['organization_id','machine_identity_id','revision']))
      SELECT count(*) FROM expected e JOIN pg_constraint c ON c.conrelid=to_regclass('organization_service.'||e.table_name)
      JOIN pg_index i ON i.indexrelid=c.conindid WHERE c.contype='p' AND c.convalidated AND NOT c.condeferrable AND NOT c.condeferred
        AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive AND i.indpred IS NULL AND i.indexprs IS NULL
        AND ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(attnum,position)
          JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum ORDER BY k.position)=e.key_columns")
        .fetch_one(&mut *connection).await.map_err(unavailable)?;
    let checks:i64=sqlx::query_scalar("WITH expected(table_name,name,expression) AS (VALUES
        ('machine_use_access','machine_use_access_bytes','((convert_from(snapshot_bytes, ''UTF8''::name))::jsonb = snapshot)'),
        ('machine_use_access','machine_use_access_digest','(snapshot_digest = (''sha256:''::text || encode(sha256(snapshot_bytes), ''hex''::text)))'),
        ('machine_use_access','machine_use_access_window','(valid_until > valid_from)'),
        ('machine_use_access','machine_use_access_permissions','(((cardinality(permissions) >= 1) AND (cardinality(permissions) <= 5)) AND (permissions <@ ARRAY[''START_USE''::text, ''FINALIZE_USE''::text, ''RECOVER_RESULT''::text, ''RETRIEVE_REQUEST''::text, ''SUBMIT_PROOF''::text]))'),
        ('machine_use_access_history','machine_use_access_history_bytes','((convert_from(snapshot_bytes, ''UTF8''::name))::jsonb = snapshot)'),
        ('machine_use_access_history','machine_use_access_history_digest','(snapshot_digest = (''sha256:''::text || encode(sha256(snapshot_bytes), ''hex''::text)))'))
      SELECT count(*) FROM expected e JOIN pg_constraint c ON c.conrelid=to_regclass('organization_service.'||e.table_name) AND c.conname=e.name
      WHERE c.contype='c' AND c.convalidated AND c.conislocal AND pg_get_expr(c.conbin,c.conrelid)=e.expression")
        .fetch_one(&mut *connection).await.map_err(unavailable)?;
    if !version || guards != 5 || keys != 2 || checks != 6 {
        return Err(Error::Unavailable);
    }
    let migration = include_str!("../../migrations/0007_machine_use_access.sql");
    for name in [
        "reject_machine_use_access_history_mutation",
        "guard_machine_use_access",
        "guard_machine_use_access_history",
        "check_machine_use_access_complete",
    ] {
        let marker = format!("FUNCTION organization_service.{name}()");
        let expected = migration
            .split_once(&marker)
            .and_then(|(_, s)| s.split_once("AS $$"))
            .and_then(|(_, s)| s.split_once("$$;"))
            .map(|(s, _)| s)
            .ok_or(Error::Unavailable)?;
        let actual: String =
            sqlx::query_scalar("SELECT prosrc FROM pg_proc WHERE oid=to_regprocedure($1)")
                .bind(format!("organization_service.{name}()"))
                .fetch_one(&mut *connection)
                .await
                .map_err(unavailable)?;
        if actual != expected {
            return Err(Error::Unavailable);
        }
    }
    Ok(())
}
