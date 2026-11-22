use sqlx::{PgConnection, PgPool, Row};
use thiserror::Error;

const MIGRATION_VERSION: &str = "rust_organization_0001";
const ADVISORY_LOCK_ID: i64 = 718_431_212;

#[derive(Debug, Error)]
pub enum OrganizationMigrationError {
    #[error("ORGANIZATION.MIGRATION_DATABASE: {0}")]
    Database(#[from] sqlx::Error),
    #[error("ORGANIZATION.MIGRATION_INCOMPATIBLE: {0}")]
    Incompatible(String),
}

pub async fn migrate_organization_schema(pool: &PgPool) -> Result<(), OrganizationMigrationError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_ID)
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(include_str!("../migrations/0001_organization_schema.sql"))
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0002_offline_audit_receipts.sql"
    ))
    .execute(&mut *transaction)
    .await?;
    sqlx::raw_sql(include_str!("../migrations/0003_agent_directory.sql"))
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0004_managed_agent_enrollment.sql"
    ))
    .execute(&mut *transaction)
    .await?;
    sqlx::raw_sql(include_str!("../migrations/0005_machine_registry.sql"))
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0006_machine_authorization_policy.sql"
    ))
    .execute(&mut *transaction)
    .await?;
    sqlx::raw_sql(include_str!("../migrations/0007_machine_use_access.sql"))
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(include_str!("../migrations/0008_delegation_use_policy.sql"))
        .execute(&mut *transaction)
        .await?;
    validate_connection(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn validate_organization_schema(pool: &PgPool) -> Result<(), OrganizationMigrationError> {
    let mut connection = pool.acquire().await?;
    validate_connection(&mut connection).await
}

pub async fn validate_organization_outbox_schema(
    pool: &PgPool,
) -> Result<(), OrganizationMigrationError> {
    let columns = sqlx::query(
        "SELECT table_name, column_name FROM information_schema.columns
         WHERE table_schema='mmf_messaging'
           AND table_name IN ('outbox_messages', 'inbox_messages')",
    )
    .fetch_all(pool)
    .await?;
    let expected_columns = [
        ("outbox_messages", "message_id"),
        ("outbox_messages", "source_service"),
        ("outbox_messages", "tenant_id"),
        ("outbox_messages", "partition"),
        ("outbox_messages", "priority"),
        ("outbox_messages", "message"),
        ("outbox_messages", "status"),
        ("outbox_messages", "attempt_count"),
        ("outbox_messages", "max_attempts"),
        ("outbox_messages", "next_attempt_at_ms"),
        ("outbox_messages", "last_error"),
        ("outbox_messages", "processed_at_ms"),
        ("outbox_messages", "lease_token"),
        ("outbox_messages", "lease_expires_at_ms"),
        ("outbox_messages", "created_at_ms"),
        ("outbox_messages", "scheduled_at_ms"),
        ("outbox_messages", "expires_at_ms"),
        ("inbox_messages", "source_service"),
        ("inbox_messages", "message_id"),
        ("inbox_messages", "processed_at_ms"),
    ];
    for (table, column) in expected_columns {
        if !columns.iter().any(|row| {
            row.get::<String, _>("table_name") == table
                && row.get::<String, _>("column_name") == column
        }) {
            return Err(incompatible(&format!("mmf_messaging.{table}.{column} is missing")));
        }
    }

    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes WHERE schemaname='mmf_messaging'",
    )
    .fetch_all(pool)
    .await?;
    for required in [
        "ix_mmf_outbox_due",
        "ix_mmf_outbox_lease",
        "ix_mmf_outbox_tenant",
        "ix_mmf_inbox_retention",
    ] {
        if !indexes.iter().any(|index| index == required) {
            return Err(incompatible(&format!("outbox index {required} is missing")));
        }
    }

    // These zero-row reads prove the runtime identity can reach both owner
    // tables without mutating them.
    sqlx::query("SELECT message_id FROM mmf_messaging.outbox_messages LIMIT 0")
        .fetch_all(pool)
        .await?;
    sqlx::query("SELECT message_id FROM mmf_messaging.inbox_messages LIMIT 0")
        .fetch_all(pool)
        .await?;
    Ok(())
}

async fn validate_connection(
    connection: &mut PgConnection,
) -> Result<(), OrganizationMigrationError> {
    let version: Option<String> = sqlx::query_scalar(
        "SELECT version FROM organization_service.rust_schema_versions WHERE version=$1",
    )
    .bind(MIGRATION_VERSION)
    .fetch_optional(&mut *connection)
    .await?;
    if version.as_deref() != Some(MIGRATION_VERSION) {
        return Err(incompatible("Rust migration head is missing"));
    }

    let expected_tables = [
        "organizations",
        "members",
        "api_keys",
        "console_context_preferences",
        "join_codes",
        "permissions",
        "roles",
        "role_permissions",
        "member_roles",
        "policy_sets",
        "audit_events",
        "agent_identities",
        "agent_identity_keys",
        "agent_identity_history",
        "agent_enrollment_challenges",
        "agent_enrollment_outcomes",
        "agent_enrollment_invalidations",
    ];
    let table_rows = sqlx::query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema='organization_service'",
    )
    .fetch_all(&mut *connection)
    .await?;
    for table in expected_tables {
        if !table_rows
            .iter()
            .any(|row| row.get::<String, _>("table_name") == table)
        {
            return Err(incompatible(&format!("table {table} is missing")));
        }
    }

    let expected_columns = [
        ("organizations", "owner_id"),
        ("organizations", "join_mechanism"),
        ("organizations", "plan"),
        ("members", "user_id"),
        ("api_keys", "scope_type"),
        ("api_keys", "deployment_profile_id"),
        ("api_keys", "enabled"),
        ("api_keys", "updated_at"),
        ("roles", "is_default_for_new_members"),
        ("policy_sets", "cedar_schema_version"),
        ("audit_events", "metadata"),
    ];
    let column_rows = sqlx::query(
        "SELECT table_name, column_name FROM information_schema.columns \
         WHERE table_schema='organization_service'",
    )
    .fetch_all(&mut *connection)
    .await?;
    for (table, column) in expected_columns {
        if !column_rows.iter().any(|row| {
            row.get::<String, _>("table_name") == table
                && row.get::<String, _>("column_name") == column
        }) {
            return Err(incompatible(&format!("{table}.{column} is missing")));
        }
    }
    let offline_indexes: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_index i ON i.indexrelid=c.oid WHERE n.nspname='organization_service' AND i.indrelid='organization_service.audit_events'::regclass AND i.indisunique AND i.indisvalid AND i.indnkeyatts=2 AND i.indpred IS NOT NULL",
    ).fetch_all(&mut *connection).await?;
    for required in [
        "uq_offline_audit_organization_event",
        "uq_offline_audit_organization_verification",
    ] {
        if !offline_indexes.iter().any(|index| index == required) {
            return Err(incompatible(&format!(
                "offline audit index {required} is missing"
            )));
        }
    }
    let agent_version: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organization_service.rust_schema_versions WHERE version='rust_organization_agent_directory_0003')",
    ).fetch_one(&mut *connection).await?;
    // A matching trigger name does not establish its protected operations or
    // execution timing. In particular, inventory completeness must run at commit
    // and must be bound to the reviewed function, not an unrelated trigger.
    // pg_trigger.tgtype uses ROW=1, BEFORE=2, INSERT=4, DELETE=8, UPDATE=16,
    // TRUNCATE=32. These explicit shapes match migration 0003.
    let agent_guards: i64 = sqlx::query_scalar(
        "WITH expected(table_name, trigger_name, function_name, trigger_type, deferred) AS (VALUES
            ('agent_identities','agent_identity_guard','guard_agent_identity',23,false),
            ('agent_identities','agent_identity_no_removal','reject_agent_directory_mutation',42,false),
            ('agent_identities','agent_identity_complete','check_agent_inventory_complete',21,true),
            ('agent_identity_keys','agent_key_guard','guard_agent_key',23,false),
            ('agent_identity_keys','agent_key_no_removal','reject_agent_directory_mutation',42,false),
            ('agent_identity_keys','agent_keys_complete','check_agent_inventory_complete',21,true),
            ('agent_identity_history','agent_history_guard','guard_agent_history',7,false),
            ('agent_identity_history','agent_history_immutable','reject_agent_directory_mutation',58,false)
         )
         SELECT count(*) FROM expected e
         JOIN pg_trigger t ON t.tgrelid=to_regclass('organization_service.' || e.table_name)
             AND t.tgname=e.trigger_name
         JOIN pg_proc p ON p.oid=t.tgfoid
         JOIN pg_language l ON l.oid=p.prolang
         WHERE NOT t.tgisinternal AND t.tgenabled='O' AND t.tgqual IS NULL
             AND t.tgtype=e.trigger_type AND t.tgnargs=0 AND t.tgattr=''::int2vector
             AND t.tgdeferrable=e.deferred AND t.tginitdeferred=e.deferred
             AND (t.tgconstraint<>0)=e.deferred
             AND t.tgfoid=to_regprocedure('organization_service.' || e.function_name || '()')
             AND NOT p.prosecdef AND p.prorettype='trigger'::regtype AND p.prokind='f'
             AND l.lanname='plpgsql'
             AND p.proconfig=ARRAY['search_path=pg_catalog']::text[]",
    ).fetch_one(&mut *connection).await?;
    let active_key_index: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_index i
            JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am am ON am.oid=c.relam
            WHERE i.indexrelid=to_regclass('organization_service.agent_identity_one_active_key')
                AND i.indrelid='organization_service.agent_identity_keys'::regclass
                AND i.indisunique AND i.indisvalid AND i.indisready AND i.indislive
                AND NOT i.indisexclusion AND i.indnkeyatts=2 AND i.indnatts=2
                AND i.indexprs IS NULL AND am.amname='btree'
                AND pg_get_indexdef(i.indexrelid,1,true)='organization_id'
                AND pg_get_indexdef(i.indexrelid,2,true)='agent_id'
                AND pg_get_expr(i.indpred,i.indrelid)='(status = ''ACTIVE''::text)')",
    )
    .fetch_one(&mut *connection)
    .await?;
    if !agent_version || agent_guards != 8 || !active_key_index {
        return Err(incompatible(
            "agent directory migration or lifecycle guards are missing",
        ));
    }
    let enrollment_version: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organization_service.rust_schema_versions WHERE version='rust_organization_managed_enrollment_0004')",
    ).fetch_one(&mut *connection).await?;
    let enrollment_guards: i64 = sqlx::query_scalar(
        "WITH expected(table_name,trigger_name,function_name,trigger_type,deferred) AS (VALUES
            ('agent_enrollment_challenges','agent_enrollment_challenge_guard','guard_agent_enrollment_challenge',7,false),
            ('agent_enrollment_challenges','agent_enrollment_challenge_immutable','reject_agent_directory_mutation',58,false),
            ('agent_enrollment_challenges','agent_enrollment_challenge_commit','check_agent_enrollment_commit',5,true),
            ('agent_enrollment_outcomes','agent_enrollment_outcome_guard','guard_agent_enrollment_outcome',7,false),
            ('agent_enrollment_outcomes','agent_enrollment_outcome_immutable','reject_agent_directory_mutation',58,false),
            ('agent_enrollment_outcomes','agent_enrollment_outcome_commit','check_agent_enrollment_commit',5,true),
            ('agent_enrollment_invalidations','agent_enrollment_invalidation_guard','guard_agent_enrollment_invalidation',7,false),
            ('agent_enrollment_invalidations','agent_enrollment_invalidation_immutable','reject_agent_directory_mutation',58,false)
        ) SELECT count(*) FROM expected e
          JOIN pg_trigger t ON t.tgrelid=to_regclass('organization_service.'||e.table_name) AND t.tgname=e.trigger_name
          JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_language l ON l.oid=p.prolang
          WHERE NOT t.tgisinternal AND t.tgenabled='O' AND t.tgqual IS NULL AND t.tgtype=e.trigger_type
            AND t.tgnargs=0 AND t.tgattr=''::int2vector AND t.tgdeferrable=e.deferred AND t.tginitdeferred=e.deferred
            AND (t.tgconstraint<>0)=e.deferred
            AND t.tgfoid=to_regprocedure('organization_service.'||e.function_name||'()')
            AND NOT p.prosecdef AND p.prorettype='trigger'::regtype AND p.prokind='f'
            AND l.lanname='plpgsql' AND p.proconfig=ARRAY['search_path=pg_catalog']::text[]",
    ).fetch_one(&mut *connection).await?;
    if !enrollment_version || enrollment_guards != 8 {
        return Err(incompatible(
            "managed enrollment retention or commit guards are missing",
        ));
    }
    crate::machine_registry::validate_schema(connection)
        .await
        .map_err(|_| incompatible("full machine registry schema or guards are missing"))?;
    crate::machine_authorization::validate_machine_authorization_schema(connection)
        .await
        .map_err(|_| incompatible("machine authorization policy schema or guards are missing"))?;
    crate::machine_use_access::validate_machine_use_access_schema(connection)
        .await
        .map_err(|_| incompatible("machine use access schema or guards are missing"))?;
    crate::delegation_use_policy::validate_delegation_use_policy_schema(connection)
        .await
        .map_err(|_| incompatible("delegation use policy schema or guards are missing"))?;
    Ok(())
}

fn incompatible(message: &str) -> OrganizationMigrationError {
    OrganizationMigrationError::Incompatible(message.to_owned())
}
