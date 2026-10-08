use serde_json::Value;
use sqlx::{PgPool, Row};

const ALEMBIC_FINAL_HEAD: &str = "issuance_event_owner";
const RUST_BASELINE_VERSION: &str = "issuance_service_baseline_v1";
const BASE_CATALOG: &str = include_str!("../migrations/0000_issuance_service_catalog.json");
const NATIVE_MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_oid4vci_public_protocol",
        include_str!("../migrations/0001_oid4vci_public_protocol.sql"),
    ),
    (
        "0002_physical_document_jobs",
        include_str!("../migrations/0002_physical_document_jobs.sql"),
    ),
    (
        "0003_passport_bureau_provider_binding",
        include_str!("../migrations/0003_passport_bureau_provider_binding.sql"),
    ),
    (
        "0004_passport_submission_intent",
        include_str!("../migrations/0004_passport_submission_intent.sql"),
    ),
    (
        "0005_passport_submission_provenance",
        include_str!("../migrations/0005_passport_submission_provenance.sql"),
    ),
    (
        "0006_passport_beta_batch_identity",
        include_str!("../migrations/0006_passport_beta_batch_identity.sql"),
    ),
    (
        "0007_passport_beta_batch_provenance",
        include_str!("../migrations/0007_passport_beta_batch_provenance.sql"),
    ),
    (
        "0008_passport_beta_batch_wire_evidence",
        include_str!("../migrations/0008_passport_beta_batch_wire_evidence.sql"),
    ),
];
const BASE_TABLES: &[&str] = &[
    "application_templates",
    "applications",
    "authorization_sessions",
    "canvas_award_candidates",
    "canvas_candidate_observations",
    "canvas_event_receipts",
    "canvas_evidence_sync_jobs",
    "canvas_evidence_sync_targets",
    "canvas_learner_identities",
    "canvas_lti_launch_states",
    "canvas_oauth_authorizations",
    "canvas_oauth_connections",
    "canvas_platform_state_backups",
    "canvas_platforms",
    "canvas_program_binding_requirement_backups",
    "canvas_program_bindings",
    "canvas_worker_heartbeats",
    "credential_delivery_records",
    "evidence_fact_heads",
    "evidence_facts",
    "evidence_policy_reviews",
    "issuance_events",
    "issuance_transactions",
    "issued_credentials",
    "oid4vci_client_assertions",
    "oid4vci_ephemeral_capabilities",
    "oid4vci_registered_clients",
    "organization_integration_secrets",
    "physical_document_jobs",
];

/// Claim the final issuance schema under one database lock. A fresh database
/// receives the checked-in baseline; an existing database must have completed
/// the exact published Alembic head before Rust can take ownership.
pub async fn migrate_owned_schema(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('issuance_schema_owner_v1', 0))")
        .execute(&mut *transaction)
        .await?;

    let has_schema: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'issuance_service')",
    )
    .fetch_one(&mut *transaction)
    .await?;
    // The shared db-migrate job pre-creates service namespaces before this
    // owner runs. An otherwise empty namespace is still a fresh database.
    let empty_schema: bool = if has_schema {
        sqlx::query_scalar(
            "SELECT NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'issuance_service')
                 AND NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'issuance_service')
                 AND NOT EXISTS (SELECT 1 FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace WHERE n.nspname = 'issuance_service')",
        )
        .fetch_one(&mut *transaction)
        .await?
    } else {
        true
    };
    if empty_schema {
        sqlx::raw_sql(include_str!(
            "../migrations/0000_issuance_service_baseline.sql"
        ))
        .execute(&mut *transaction)
        .await?;
        crate::migration_seed::seed_marty_application_templates(&mut transaction).await?;
    } else {
        let has_alembic: bool = sqlx::query_scalar(
            "SELECT to_regclass('issuance_service.alembic_version') IS NOT NULL",
        )
        .fetch_one(&mut *transaction)
        .await?;
        let has_ledger: bool = sqlx::query_scalar(
            "SELECT to_regclass('issuance_service.rust_schema_migrations') IS NOT NULL",
        )
        .fetch_one(&mut *transaction)
        .await?;
        if has_alembic {
            let heads: Vec<String> =
                sqlx::query_scalar("SELECT version_num FROM issuance_service.alembic_version")
                    .fetch_all(&mut *transaction)
                    .await?;
            if heads.as_slice() != [ALEMBIC_FINAL_HEAD] {
                return Err(sqlx::Error::Protocol(format!(
                    "issuance Alembic head must be exactly {ALEMBIC_FINAL_HEAD}; observed {heads:?}"
                )));
            }
        } else if !has_ledger {
            return Err(sqlx::Error::Protocol(
                "issuance schema has neither the final Alembic head nor a Rust ledger".into(),
            ));
        } else {
            let baseline_claimed: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM issuance_service.rust_schema_migrations
                 WHERE version = $1)",
            )
            .bind(RUST_BASELINE_VERSION)
            .fetch_one(&mut *transaction)
            .await?;
            if !baseline_claimed {
                return Err(sqlx::Error::Protocol(
                    "issuance Rust ledger has no baseline claim".into(),
                ));
            }
        }
    }

    validate_base_tables(&mut transaction).await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS issuance_service.rust_schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(&mut *transaction)
    .await?;
    let existing_versions: Vec<String> =
        sqlx::query_scalar("SELECT version FROM issuance_service.rust_schema_migrations")
            .fetch_all(&mut *transaction)
            .await?;
    if existing_versions.iter().any(|version| {
        version != RUST_BASELINE_VERSION
            && !NATIVE_MIGRATIONS.iter().any(|(known, _)| version == known)
    }) {
        return Err(sqlx::Error::Protocol(format!(
            "unknown issuance Rust schema versions: {existing_versions:?}"
        )));
    }
    sqlx::query(
        "INSERT INTO issuance_service.rust_schema_migrations (version)
         VALUES ($1) ON CONFLICT (version) DO NOTHING",
    )
    .bind(RUST_BASELINE_VERSION)
    .execute(&mut *transaction)
    .await?;

    for &(version, migration) in NATIVE_MIGRATIONS {
        if existing_versions.iter().any(|applied| applied == version) {
            continue;
        }
        sqlx::raw_sql(migration).execute(&mut *transaction).await?;
        sqlx::query("INSERT INTO issuance_service.rust_schema_migrations (version) VALUES ($1)")
            .bind(version)
            .execute(&mut *transaction)
            .await?;
    }
    validate_oid4vci(&mut transaction).await?;
    validate_passport_connection(&mut transaction).await?;
    transaction.commit().await
}

async fn validate_base_tables(connection: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let actual: Vec<String> =
        sqlx::query_scalar("SELECT tablename FROM pg_tables WHERE schemaname = 'issuance_service'")
            .fetch_all(&mut *connection)
            .await?;
    for table in BASE_TABLES {
        if !actual.iter().any(|name| name == table) {
            return Err(sqlx::Error::Protocol(format!(
                "issuance baseline table {table} is missing"
            )));
        }
    }
    validate_base_catalog(connection).await?;
    Ok(())
}

async fn validate_base_catalog(connection: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let expected: Value = serde_json::from_str(BASE_CATALOG)
        .map_err(|error| sqlx::Error::Protocol(format!("invalid issuance catalog: {error}")))?;
    let actual: Value = sqlx::query_scalar(
        r#"WITH columns AS (
            SELECT jsonb_agg(jsonb_build_object(
                'table', table_name, 'name', column_name, 'udt', udt_name,
                'nullable', is_nullable, 'default', column_default,
                'length', character_maximum_length,
                'precision', numeric_precision, 'scale', numeric_scale
            )) AS value
            FROM information_schema.columns
            WHERE table_schema = 'issuance_service'
              AND table_name NOT IN ('alembic_version', 'rust_schema_migrations')
        ), constraints AS (
            SELECT jsonb_agg(jsonb_build_object(
                'table', t.relname, 'name', c.conname, 'type', c.contype,
                'validated', c.convalidated, 'deferrable', c.condeferrable,
                'definition', pg_get_constraintdef(c.oid)
            )) AS value
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE n.nspname = 'issuance_service'
              AND t.relname NOT IN ('alembic_version', 'rust_schema_migrations')
        ), indexes AS (
            SELECT jsonb_agg(jsonb_build_object(
                'table', t.relname, 'name', i.relname, 'unique', x.indisunique,
                'valid', x.indisvalid, 'ready', x.indisready,
                'primary', x.indisprimary, 'key_count', x.indnkeyatts,
                'definition', CASE WHEN i.relname = 'ux_canvas_sync_jobs_one_active_target'
                    THEN NULL ELSE pg_get_indexdef(i.oid) END
            )) AS value
            FROM pg_index x
            JOIN pg_class i ON i.oid = x.indexrelid
            JOIN pg_class t ON t.oid = x.indrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE n.nspname = 'issuance_service'
              AND t.relname NOT IN ('alembic_version', 'rust_schema_migrations')
        )
        SELECT jsonb_build_object(
            'columns', columns.value, 'constraints', constraints.value,
            'indexes', indexes.value
        ) FROM columns, constraints, indexes"#,
    )
    .fetch_one(&mut *connection)
    .await?;
    for group in ["columns", "constraints", "indexes"] {
        let required = expected[group].as_array().ok_or_else(|| {
            sqlx::Error::Protocol(format!("issuance baseline catalog {group} is invalid"))
        })?;
        let found = actual[group].as_array().ok_or_else(|| {
            sqlx::Error::Protocol(format!("issuance database catalog {group} is missing"))
        })?;
        for object in required {
            let alternate = object.get("alternate_definition").cloned();
            let mut canonical = object.clone();
            if let Some(map) = canonical.as_object_mut() {
                map.remove("alternate_definition");
            }
            let present = found.iter().any(|candidate| {
                candidate["table"] == object["table"]
                    && candidate["name"] == object["name"]
                    && (candidate == &canonical
                        || alternate.as_ref().is_some_and(|definition| {
                            let mut variant = canonical.clone();
                            variant["definition"] = definition.clone();
                            candidate == &variant
                        }))
            });
            if !present {
                return Err(sqlx::Error::Protocol(format!(
                    "issuance baseline {group} object changed or is missing: {}.{}",
                    object["table"], object["name"]
                )));
            }
        }
    }
    validate_canvas_sync_index(connection).await
}

async fn validate_canvas_sync_index(
    connection: &mut sqlx::PgConnection,
) -> Result<(), sqlx::Error> {
    let index: Option<(String, String)> = sqlx::query_as(
        "SELECT pg_get_indexdef(x.indexrelid, 1, false),
                pg_get_expr(x.indpred, x.indrelid)
         FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid
         WHERE i.oid = to_regclass('issuance_service.ux_canvas_sync_jobs_one_active_target')",
    )
    .fetch_optional(&mut *connection)
    .await?;
    let accepted_predicates = [
        "((status)::text = ANY ((ARRAY['queued'::character varying, 'leased'::character varying, 'retry'::character varying])::text[]))",
        "((status)::text = ANY (ARRAY[('queued'::character varying)::text, ('leased'::character varying)::text, ('retry'::character varying)::text]))",
    ];
    if !index.is_some_and(|(key, predicate)| {
        key == "target_id" && accepted_predicates.contains(&predicate.as_str())
    }) {
        return Err(sqlx::Error::Protocol(
            "Canvas sync one-active-target index changed".into(),
        ));
    }
    Ok(())
}

const REQUIRED_COLUMNS: &[(&str, &str)] = &[
    ("issuance_transactions", "access_token_expires_at"),
    ("authorization_sessions", "access_token_expires_at"),
];

const PASSPORT_REQUIRED_COLUMNS: &[&str] = &[
    "id",
    "organization_id",
    "flow_execution_id",
    "application_id",
    "application_template_id",
    "credential_template_id",
    "revocation_profile_id",
    "delivery_destination_profile_id",
    "document_type",
    "country_code",
    "issuer_did",
    "secure_artifact_ciphertext",
    "secure_artifact_reference",
    "sod_sha256",
    "bureau_job_id",
    "bureau_provider_profile_id",
    "submission_intent_id",
    "submission_intent_started_at",
    "submission_intent_provider_profile_id",
    "submission_intent_bureau_endpoint_sha256",
    "submission_intent_signing_provenance",
    "submission_batch_id",
    "submission_batch_selected_flow_instance_id",
    "submission_batch_selected_job_id",
    "submission_batch_companion_job_id",
    "submission_batch_signing_provenance",
    "submission_batch_bureau_endpoint_sha256",
    "submission_batch_material_digests",
    "tracking_number",
    "status",
    "quality_result",
    "error_code",
    "error_message",
    "submitted_at",
    "completed_at",
    "created_at",
    "updated_at",
];

const BATCH_REQUIRED_COLUMNS: &[(&str, &str)] = &[
    ("batch_id", "uuid"),
    ("organization_id", "text"),
    ("selected_flow_instance_id", "varchar"),
    ("selected_job_id", "text"),
    ("companion_job_id", "text"),
    ("created_at", "timestamptz"),
    ("last_send_started_at", "timestamptz"),
    ("send_attempts", "int2"),
    ("last_receipt_completion_started_at", "timestamptz"),
    ("receipt_completion_attempts", "int8"),
    ("first_dispatch_response_seen_at", "timestamptz"),
    ("first_dispatch_wire_ciphertext", "text"),
    ("first_dispatch_request_commitment", "text"),
    ("first_dispatch_response_commitment", "text"),
    ("first_dispatch_wire_key_sha256", "text"),
];

// PostgreSQL 15 canonical definitions. The two batch-identity hashes cover
// the released Python varchar ID and a fresh Rust text ID respectively.
const PASSPORT_REQUIRED_CHECKS: &[(&str, &str, &[&str])] = &[
    (
        "physical_document_jobs",
        "ck_physical_document_jobs_bureau_provider_binding",
        &["e60c22bee2eb6afeb00c8c004d8fc81d"],
    ),
    (
        "physical_document_jobs",
        "ck_physical_document_jobs_submission_intent_pair",
        &["a74f1c20745f053beef95dd60e8b8789"],
    ),
    (
        "physical_document_jobs",
        "ck_physical_document_jobs_submission_provenance_intent",
        &["25ed6ef0a104d3e10c31f4ac531a03ec"],
    ),
    (
        "physical_document_jobs",
        "ck_physical_document_jobs_submission_batch_identity",
        &[
            "bfbe9a0308c2d9593af5ee10393f83cc",
            "6948f18c79146c671a0589c8e53fda78",
        ],
    ),
    (
        "physical_document_jobs",
        "ck_physical_document_jobs_batch_provenance_identity",
        &["dccf75fd58810c8444258b069e1e9102"],
    ),
    (
        "passport_beta_batch_intents",
        "ck_passport_beta_batch_distinct_jobs",
        &["1b7ce4fd845d4154e28f4c21abc628e0"],
    ),
    (
        "passport_beta_batch_intents",
        "ck_passport_beta_batch_send_attempts",
        &["aff09f544ce7945092a277ae62760407"],
    ),
    (
        "passport_beta_batch_intents",
        "ck_passport_beta_batch_wire_evidence",
        &["85bc12edf6f5c6ec031b5ea444fcd78d"],
    ),
];

pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('issuance_oid4vci_public_v1', 0))")
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0001_oid4vci_public_protocol.sql"
    ))
    .execute(&mut *transaction)
    .await?;
    validate_oid4vci(&mut transaction).await?;
    transaction.commit().await
}

/// Validate a pre-migrated schema without acquiring a write transaction.
pub async fn validate(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *transaction)
        .await?;
    validate_oid4vci(&mut transaction).await?;
    transaction.commit().await
}

async fn validate_oid4vci(connection: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        "SELECT table_name, column_name, udt_name
         FROM information_schema.columns
         WHERE table_schema = 'issuance_service'
           AND column_name = 'access_token_expires_at'",
    )
    .fetch_all(&mut *connection)
    .await?;
    for &(table, column) in REQUIRED_COLUMNS {
        if !rows.iter().any(|row| {
            matches!(row.try_get::<String, _>("table_name"), Ok(value) if value == table)
                && matches!(row.try_get::<String, _>("column_name"), Ok(value) if value == column)
                && matches!(row.try_get::<String, _>("udt_name"), Ok(value) if value == "timestamptz")
        }) {
            return Err(sqlx::Error::Protocol(format!(
                "OID4VCI migration did not create compatible timestamptz {table}.{column}"
            )));
        }
    }

    let binding_index = sqlx::query(
        "SELECT index.indisunique, index.indisvalid, index.indisready,
                index.indnkeyatts,
                pg_get_indexdef(index.indexrelid, 1, false) AS indexed_expression,
                pg_get_expr(index.indpred, index.indrelid) AS predicate
         FROM pg_index AS index
         JOIN pg_class AS relation ON relation.oid = index.indexrelid
         JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         WHERE namespace.nspname = 'issuance_service'
           AND relation.relname = 'ux_issuance_events_oid4vci_notification_id'
           AND index.indrelid = 'issuance_service.issuance_events'::regclass",
    )
    .fetch_optional(&mut *connection)
    .await?;
    let Some(binding_index) = binding_index else {
        return Err(sqlx::Error::Protocol(
            "OID4VCI notification binding index is missing".into(),
        ));
    };
    let expression = binding_index.try_get::<String, _>("indexed_expression")?;
    let predicate = binding_index
        .try_get::<Option<String>, _>("predicate")?
        .unwrap_or_default();
    if !binding_index.try_get::<bool, _>("indisunique")?
        || !binding_index.try_get::<bool, _>("indisvalid")?
        || !binding_index.try_get::<bool, _>("indisready")?
        || binding_index.try_get::<i16, _>("indnkeyatts")? != 1
        || normalize_catalog_expression(&expression) != "metadata->>'notification_id'"
        || normalize_catalog_expression(&predicate) != "event_type='oid4vci_notification_binding'"
    {
        return Err(sqlx::Error::Protocol(
            "OID4VCI notification binding index is incompatible".into(),
        ));
    }
    Ok(())
}

/// Upgrade the physical-document table only when native passport HTTP is
/// enabled. The released Python table remains in place during the cutover.
pub async fn migrate_passport(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('issuance_passport_native_v1', 0))")
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0002_physical_document_jobs.sql"
    ))
    .execute(&mut *transaction)
    .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0003_passport_bureau_provider_binding.sql"
    ))
    .execute(&mut *transaction)
    .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0004_passport_submission_intent.sql"
    ))
    .execute(&mut *transaction)
    .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0005_passport_submission_provenance.sql"
    ))
    .execute(&mut *transaction)
    .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0006_passport_beta_batch_identity.sql"
    ))
    .execute(&mut *transaction)
    .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0007_passport_beta_batch_provenance.sql"
    ))
    .execute(&mut *transaction)
    .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0008_passport_beta_batch_wire_evidence.sql"
    ))
    .execute(&mut *transaction)
    .await?;
    validate_passport_connection(&mut transaction).await?;
    transaction.commit().await
}

/// Validate the passport schema after the official migration image has run.
pub async fn validate_passport(pool: &PgPool) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *transaction)
        .await?;
    validate_passport_connection(&mut transaction).await?;
    transaction.commit().await
}

async fn validate_passport_connection(
    connection: &mut sqlx::PgConnection,
) -> Result<(), sqlx::Error> {
    let columns = sqlx::query_scalar::<_, String>(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema='issuance_service' AND table_name='physical_document_jobs'",
    )
    .fetch_all(&mut *connection)
    .await?;
    for column in PASSPORT_REQUIRED_COLUMNS {
        if !columns.iter().any(|existing| existing.as_str() == *column) {
            return Err(sqlx::Error::Protocol(format!(
                "physical_document_jobs is missing required column {column}"
            )));
        }
    }
    let batch_columns = sqlx::query(
        "SELECT column_name, udt_name FROM information_schema.columns
         WHERE table_schema='issuance_service' AND table_name='passport_beta_batch_intents'",
    )
    .fetch_all(&mut *connection)
    .await?;
    for &(column, udt) in BATCH_REQUIRED_COLUMNS {
        if !batch_columns.iter().any(|row| {
            matches!(row.try_get::<String, _>("column_name"), Ok(value) if value == column)
                && matches!(row.try_get::<String, _>("udt_name"), Ok(value) if value == udt)
        }) {
            return Err(sqlx::Error::Protocol(format!(
                "passport beta batch intents is missing compatible {column}"
            )));
        }
    }
    let batch_access: bool = sqlx::query_scalar(
        "SELECT has_table_privilege(current_user, \
                    'issuance_service.passport_beta_batch_intents', 'SELECT')
                AND has_table_privilege(current_user, \
                    'issuance_service.passport_beta_batch_intents', 'INSERT')
                AND has_table_privilege(current_user, \
                    'issuance_service.passport_beta_batch_intents', 'UPDATE')
                AND has_table_privilege(current_user, \
                    'issuance_service.passport_beta_batch_intents', 'DELETE')",
    )
    .fetch_one(&mut *connection)
    .await?;
    if !batch_access {
        return Err(sqlx::Error::Protocol(
            "passport beta batch intents lacks application CRUD privileges".into(),
        ));
    }
    let checks = sqlx::query_as::<_, (String, String, String)>(
        "SELECT relation.relname, con.conname,
                md5(pg_get_constraintdef(con.oid))
         FROM pg_constraint AS con
         JOIN pg_class AS relation ON relation.oid=con.conrelid
         JOIN pg_namespace AS namespace ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname='issuance_service'
           AND relation.relname IN ('physical_document_jobs', 'passport_beta_batch_intents')
           AND con.convalidated AND con.contype='c'",
    )
    .fetch_all(&mut *connection)
    .await?;
    for &(table, name, expected_definitions) in PASSPORT_REQUIRED_CHECKS {
        if !checks
            .iter()
            .any(|(actual_table, actual_name, definition)| {
                actual_table == table
                    && actual_name == name
                    && expected_definitions.contains(&definition.as_str())
            })
        {
            return Err(sqlx::Error::Protocol(format!(
                "passport migration check {name} is missing or incompatible"
            )));
        }
    }
    const REQUIRED_KEYS: &[(&str, &str, &str)] = &[
        ("physical_document_jobs", "id", "p"),
        ("physical_document_jobs", "application_id", "u"),
        ("passport_beta_batch_intents", "batch_id", "p"),
    ];
    let keys = sqlx::query(
        "SELECT relation.relname AS table_name, rule.contype::text AS key_type,
                index.indisunique, index.indisprimary, index.indisvalid,
                index.indisready, index.indnkeyatts, index.indnatts,
                index.indpred IS NULL AS unfiltered,
                index.indexprs IS NULL AS plain_columns,
                pg_get_indexdef(index.indexrelid, 1, false) AS first_key
         FROM pg_constraint AS rule
         JOIN pg_class AS relation ON relation.oid = rule.conrelid
         JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
         JOIN pg_index AS index ON index.indexrelid = rule.conindid
         WHERE namespace.nspname = 'issuance_service'
           AND relation.relname IN ('physical_document_jobs', 'passport_beta_batch_intents')
           AND rule.contype IN ('p', 'u')",
    )
    .fetch_all(&mut *connection)
    .await?;
    for &(table, column, kind) in REQUIRED_KEYS {
        if !keys.iter().any(|key| {
            matches!(key.try_get::<String, _>("table_name"), Ok(value) if value == table)
                && matches!(key.try_get::<String, _>("key_type"), Ok(value) if value == kind)
                && matches!(key.try_get::<String, _>("first_key"), Ok(value) if normalize_catalog_expression(&value) == column)
                && matches!(key.try_get::<bool, _>("indisunique"), Ok(true))
                && matches!(key.try_get::<bool, _>("indisprimary"), Ok(value) if value == (kind == "p"))
                && matches!(key.try_get::<bool, _>("indisvalid"), Ok(true))
                && matches!(key.try_get::<bool, _>("indisready"), Ok(true))
                && matches!(key.try_get::<bool, _>("unfiltered"), Ok(true))
                && matches!(key.try_get::<bool, _>("plain_columns"), Ok(true))
                && matches!(key.try_get::<i16, _>("indnkeyatts"), Ok(1))
                && matches!(key.try_get::<i16, _>("indnatts"), Ok(1))
        }) {
            return Err(sqlx::Error::Protocol(format!(
                "passport schema is missing compatible {table}.{column} key"
            )));
        }
    }
    let intent_guard = sqlx::query(
        "SELECT t.tgenabled::text AS tgenabled, t.tgtype::integer AS trigger_type,
                md5(pg_get_triggerdef(t.oid)) AS trigger_md5,
                md5(replace(pg_get_functiondef(p.oid), E'\r\n', E'\n')) AS function_md5
         FROM pg_trigger AS t
         JOIN pg_proc AS p ON p.oid=t.tgfoid
         JOIN pg_namespace AS namespace ON namespace.oid=p.pronamespace
         WHERE t.tgrelid=to_regclass('issuance_service.physical_document_jobs')
           AND t.tgname='trg_physical_document_submission_intent'
           AND NOT t.tgisinternal
           AND namespace.nspname='issuance_service'
           AND p.proname='guard_physical_document_submission_intent'",
    )
    .fetch_optional(&mut *connection)
    .await?;
    let Some(intent_guard) = intent_guard else {
        return Err(sqlx::Error::Protocol(
            "passport submission intent guard trigger is missing".into(),
        ));
    };
    let enabled = intent_guard.try_get::<String, _>("tgenabled")?;
    if !["O", "A"].contains(&enabled.as_str())
        || intent_guard.try_get::<i32, _>("trigger_type")? != 19
        || intent_guard.try_get::<String, _>("trigger_md5")? != "2cf46bf0d5d5d2794b8eb6346ef30622"
        || intent_guard.try_get::<String, _>("function_md5")? != "936f63e7df56a3d116b98dadc7645158"
    {
        return Err(sqlx::Error::Protocol(
            "passport submission intent guard trigger is incompatible".into(),
        ));
    }
    let batch_index: Option<bool> = sqlx::query_scalar(
        "SELECT indisvalid AND indisready FROM pg_index
         WHERE indexrelid=to_regclass('issuance_service.ix_physical_document_jobs_submission_batch')
           AND indrelid=to_regclass('issuance_service.physical_document_jobs')",
    )
    .fetch_optional(&mut *connection)
    .await?;
    if batch_index != Some(true) {
        return Err(sqlx::Error::Protocol(
            "passport submission batch index is missing or invalid".into(),
        ));
    }
    let binding_index = sqlx::query(
        "SELECT index.indisunique, index.indisvalid, index.indisready,
                index.indnkeyatts, index.indnatts,
                pg_get_indexdef(index.indexrelid, 1, false) AS first_key,
                pg_get_indexdef(index.indexrelid, 2, false) AS second_key,
                pg_get_expr(index.indpred, index.indrelid) AS predicate
         FROM pg_index AS index
         WHERE index.indrelid = 'issuance_service.physical_document_jobs'::regclass
           AND index.indexrelid = to_regclass(
               'issuance_service.ux_physical_document_jobs_bureau_provider_job'
           )",
    )
    .fetch_optional(&mut *connection)
    .await?;
    let Some(binding_index) = binding_index else {
        return Err(sqlx::Error::Protocol(
            "passport bureau provider/job index is missing".into(),
        ));
    };
    let first_key = binding_index.try_get::<String, _>("first_key")?;
    let second_key = binding_index.try_get::<String, _>("second_key")?;
    let predicate = binding_index
        .try_get::<Option<String>, _>("predicate")?
        .unwrap_or_default();
    if !binding_index.try_get::<bool, _>("indisunique")?
        || !binding_index.try_get::<bool, _>("indisvalid")?
        || !binding_index.try_get::<bool, _>("indisready")?
        || binding_index.try_get::<i16, _>("indnkeyatts")? != 2
        || binding_index.try_get::<i16, _>("indnatts")? != 2
        || normalize_catalog_expression(&first_key) != "bureau_provider_profile_id"
        || normalize_catalog_expression(&second_key) != "bureau_job_id"
        || ![
            "bureau_provider_profile_idISNOTNULLANDbureau_job_idISNOTNULL",
            "bureau_job_idISNOTNULLANDbureau_provider_profile_idISNOTNULL",
        ]
        .contains(&normalize_catalog_expression(&predicate).as_str())
    {
        return Err(sqlx::Error::Protocol(
            "passport bureau provider/job index is incompatible".into(),
        ));
    }
    Ok(())
}

fn normalize_catalog_expression(value: &str) -> String {
    value
        .replace("::text", "")
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && !matches!(character, '(' | ')'))
        .collect()
}
