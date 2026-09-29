use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

const REQUIRED_COLUMNS: &[(&str, &str)] = &[
    ("issuance_transactions", "access_token_expires_at"),
    ("authorization_sessions", "access_token_expires_at"),
];

pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::Error> {
    run_oid4vci(pool, true).await
}

pub async fn validate(pool: &PgPool) -> Result<(), sqlx::Error> {
    run_oid4vci(pool, false).await
}

async fn run_oid4vci(pool: &PgPool, apply_ddl: bool) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    if apply_ddl {
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('issuance_oid4vci_public_v1', 0))",
        )
        .execute(&mut *transaction)
        .await?;
        sqlx::raw_sql(include_str!(
            "../migrations/0001_oid4vci_public_protocol.sql"
        ))
        .execute(&mut *transaction)
        .await?;
    }

    let rows = sqlx::query(
        "SELECT table_name, column_name, udt_name
         FROM information_schema.columns
         WHERE table_schema = 'issuance_service'
           AND column_name = 'access_token_expires_at'",
    )
    .fetch_all(&mut *transaction)
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
    .fetch_optional(&mut *transaction)
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
    transaction.commit().await
}

/// Upgrade the physical-document table only when native passport HTTP is
/// enabled. The released Python table remains in place during the cutover.
pub async fn migrate_passport(pool: &PgPool) -> Result<(), sqlx::Error> {
    run_passport(pool, true).await
}

pub async fn validate_passport(pool: &PgPool) -> Result<(), sqlx::Error> {
    run_passport(pool, false).await
}

async fn run_passport(pool: &PgPool, apply_ddl: bool) -> Result<(), sqlx::Error> {
    const REQUIRED_COLUMNS: &[&str] = &[
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
    let mut transaction = pool.begin().await?;
    if apply_ddl {
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('issuance_passport_native_v1', 0))",
        )
        .execute(&mut *transaction)
        .await?;
        for script in [
            include_str!("../migrations/0002_physical_document_jobs.sql"),
            include_str!("../migrations/0003_passport_bureau_provider_binding.sql"),
            include_str!("../migrations/0004_passport_submission_intent.sql"),
            include_str!("../migrations/0005_passport_submission_provenance.sql"),
            include_str!("../migrations/0006_passport_beta_batch_identity.sql"),
            include_str!("../migrations/0007_passport_beta_batch_provenance.sql"),
            include_str!("../migrations/0008_passport_beta_batch_wire_evidence.sql"),
        ] {
            sqlx::raw_sql(script).execute(&mut *transaction).await?;
        }
    }
    let columns = sqlx::query_scalar::<_, String>(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema='issuance_service' AND table_name='physical_document_jobs'",
    )
    .fetch_all(&mut *transaction)
    .await?;
    for column in REQUIRED_COLUMNS {
        if !columns.iter().any(|existing| existing.as_str() == *column) {
            return Err(sqlx::Error::Protocol(format!(
                "physical_document_jobs is missing required column {column}"
            )));
        }
    }
    const REQUIRED_BATCH_COLUMNS: &[(&str, &str)] = &[
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
    let batch_columns = sqlx::query(
        "SELECT column_name, udt_name FROM information_schema.columns \
         WHERE table_schema='issuance_service' AND table_name='passport_beta_batch_intents'",
    )
    .fetch_all(&mut *transaction)
    .await?;
    for &(column, kind) in REQUIRED_BATCH_COLUMNS {
        if !batch_columns.iter().any(|existing| {
            matches!(existing.try_get::<String, _>("column_name"), Ok(value) if value == column)
                && matches!(existing.try_get::<String, _>("udt_name"), Ok(value) if value == kind)
        }) {
            return Err(sqlx::Error::Protocol(format!(
                "passport_beta_batch_intents is missing compatible {column}"
            )));
        }
    }
    // pg_get_constraintdef output was qualified on the pinned beta PostgreSQL
    // 15 runtime. Names and convalidated alone admit a same-name CHECK (true).
    // The batch identity has two hashes for the equivalent text/varchar id
    // expression generated by the supported existing and fresh schemas.
    const REQUIRED_CHECKS: &[(&str, &str, &str)] = &[
        (
            "physical_document_jobs",
            "ck_physical_document_jobs_bureau_provider_binding",
            "46d88b76986ab94b93ce65c70646eabde4cf47a7f31ec88530a5a7e7f48c556e",
        ),
        (
            "physical_document_jobs",
            "ck_physical_document_jobs_submission_intent_pair",
            "fffe50974d0280d8ee6a92c3d6a159b615ac00126e711d21cbb16fbdd77fe39d",
        ),
        (
            "physical_document_jobs",
            "ck_physical_document_jobs_submission_provenance_intent",
            "13effae70ce17140ae545c98b96960feda6bef0ae21e7320fb465dad6775c2e3",
        ),
        (
            "physical_document_jobs",
            "ck_physical_document_jobs_submission_batch_identity",
            "fc2c1f33631d8897b1a169390652f4fca166a2bc6d71e686fe8738753b305fcb|4a4610ae44a2afd8a71e59929417ca356602edd99801ac0cbcef4816f14cf3a8",
        ),
        (
            "physical_document_jobs",
            "ck_physical_document_jobs_batch_provenance_identity",
            "e5a3ad6802f5327924e1097897aab00422a17b4c92daaa12a8a2e3a30aaaff60",
        ),
        (
            "passport_beta_batch_intents",
            "ck_passport_beta_batch_distinct_jobs",
            "c13da2e843b682695231103e006d88f2c5847e8f90f0e4586f366c098cbcdda8",
        ),
        (
            "passport_beta_batch_intents",
            "ck_passport_beta_batch_send_attempts",
            "58279b5745e46d929143d54ba30d62cde684cc11a83afbed3d0211516eee9934",
        ),
        (
            "passport_beta_batch_intents",
            "ck_passport_beta_batch_wire_evidence",
            "a36a9fe5501b6ee43d323e29f5bb9ac7efb0d73ddd91bcb214d1d1e7c2f40b6b",
        ),
    ];
    let checks = sqlx::query(
        "SELECT relation.relname AS table_name, rule.conname, rule.convalidated, \
                pg_get_constraintdef(rule.oid) AS definition \
         FROM pg_constraint AS rule \
         JOIN pg_class AS relation ON relation.oid = rule.conrelid \
         JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace \
         WHERE namespace.nspname = 'issuance_service' \
           AND relation.relname IN ('physical_document_jobs', 'passport_beta_batch_intents') \
           AND rule.contype = 'c'",
    )
    .fetch_all(&mut *transaction)
    .await?;
    for &(table, name, definition_sha256) in REQUIRED_CHECKS {
        if !checks.iter().any(|check| {
            matches!(check.try_get::<String, _>("table_name"), Ok(value) if value == table)
                && matches!(check.try_get::<String, _>("conname"), Ok(value) if value == name)
                && matches!(check.try_get::<bool, _>("convalidated"), Ok(true))
                && matches!(check.try_get::<String, _>("definition"), Ok(value) if
                    definition_sha256.split('|').any(|expected|
                        format!("{:x}", Sha256::digest(value.as_bytes())) == expected))
        }) {
            let observed = checks
                .iter()
                .filter(|check| matches!(check.try_get::<String, _>("conname"), Ok(value) if value == name))
                .filter_map(|check| check.try_get::<String, _>("definition").ok())
                .map(|value| format!("{:x}", Sha256::digest(value.as_bytes())))
                .collect::<Vec<_>>();
            return Err(sqlx::Error::Protocol(format!(
                "passport schema is missing compatible validated constraint {name}: {observed:?}"
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
    .fetch_all(&mut *transaction)
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
    .fetch_optional(&mut *transaction)
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
    transaction.commit().await
}

fn normalize_catalog_expression(value: &str) -> String {
    value
        .replace("::text", "")
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && !matches!(character, '(' | ')'))
        .collect()
}
