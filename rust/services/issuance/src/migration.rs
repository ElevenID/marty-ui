use sqlx::{PgPool, Row};

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
    let batch_key: Option<String> = sqlx::query_scalar(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint
         WHERE conrelid=to_regclass('issuance_service.passport_beta_batch_intents')
           AND contype='p' AND convalidated",
    )
    .fetch_optional(&mut *connection)
    .await?;
    if batch_key.as_deref() != Some("PRIMARY KEY (batch_id)") {
        return Err(sqlx::Error::Protocol(
            "passport beta batch claim primary key is missing".into(),
        ));
    }
    let intent_guard = sqlx::query(
        "SELECT t.tgenabled::text AS tgenabled, t.tgtype::integer AS trigger_type,
                md5(pg_get_triggerdef(t.oid)) AS trigger_md5,
                md5(pg_get_functiondef(p.oid)) AS function_md5
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
        || intent_guard.try_get::<String, _>("function_md5")? != "467fa85f76fc97b3aa55ec62ad6b0e45"
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
