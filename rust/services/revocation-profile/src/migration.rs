use chrono::Utc;
use serde_json::json;
use sqlx::{Executor, PgPool, Postgres, Transaction};

pub const DEFAULT_ORGANIZATION_ID: &str = "00000000-0000-0000-0000-000000000001";
pub const DEFAULT_REVOCATION_PROFILE_ID: &str = "70000000-0000-0000-0000-000000000001";

const MIGRATION_LOCK_ID: i64 = 7_001_801_300_000_001;

const BOOTSTRAP_SQL: &str = r#"
CREATE SCHEMA IF NOT EXISTS revocation_profile_service;
CREATE TABLE IF NOT EXISTS revocation_profile_service.rust_schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

const PROFILE_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS revocation_profile_service.revocation_profiles (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft',
    issuer_config JSON NOT NULL DEFAULT '{}',
    verifier_config JSON NOT NULL DEFAULT '{}',
    automation_config JSON NOT NULL DEFAULT '{}',
    supported_formats JSON NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_revocation_profiles_organization_id
    ON revocation_profile_service.revocation_profiles (organization_id);
CREATE INDEX IF NOT EXISTS ix_revocation_profiles_status
    ON revocation_profile_service.revocation_profiles (status);
"#;

const CANONICAL_URL_BACKFILL_SQL: &str = r#"
WITH candidate_profiles AS (
    SELECT
        id,
        organization_id,
        issuer_config::jsonb AS issuer_cfg,
        issuer_config::jsonb ->> 'status_list_base_url' AS status_list_base_url
    FROM revocation_profile_service.revocation_profiles
),
rewritten_profiles AS (
    SELECT
        id,
        jsonb_set(
            issuer_cfg,
            '{status_list_base_url}',
            to_jsonb(
                regexp_replace(status_list_base_url, '^(https?://[^/]+).*$','\1')
                || '/v1/organizations/' || organization_id
                || '/revocation-profiles/' || id
                || '/status-lists/{mechanism}/{purpose}'
            ),
            true
        ) AS new_issuer_cfg
    FROM candidate_profiles
    WHERE status_list_base_url ~* '^https?://[^/]+/(lists|status-lists)/?$'
)
UPDATE revocation_profile_service.revocation_profiles AS target
SET
    issuer_config = rewritten_profiles.new_issuer_cfg::json,
    updated_at = NOW()
FROM rewritten_profiles
WHERE target.id = rewritten_profiles.id;
"#;

const OPERATION_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS revocation_profile_service.cascade_revocation_operations (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    operation_type TEXT NOT NULL,
    trigger_entity_type TEXT NOT NULL,
    trigger_entity_id TEXT NOT NULL,
    status TEXT NOT NULL,
    affected_credential_count BIGINT NOT NULL,
    affected_credential_ids JSON NOT NULL,
    requires_confirmation BOOLEAN NOT NULL,
    confirmed_at TIMESTAMPTZ,
    confirmed_by TEXT,
    max_cascade_depth SMALLINT NOT NULL,
    current_depth SMALLINT NOT NULL,
    circuit_breaker_threshold BIGINT NOT NULL,
    circuit_breaker_triggered BOOLEAN NOT NULL,
    can_rollback BOOLEAN NOT NULL,
    rollback_snapshot JSON,
    rolled_back_at TIMESTAMPTZ,
    rolled_back_by TEXT,
    error_message TEXT,
    metadata JSON,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_cascade_revocation_operations_org_created
    ON revocation_profile_service.cascade_revocation_operations (organization_id, created_at);
CREATE INDEX IF NOT EXISTS ix_cascade_revocation_operations_org_status
    ON revocation_profile_service.cascade_revocation_operations (organization_id, status);

CREATE TABLE IF NOT EXISTS revocation_profile_service.revocation_batches (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    revocation_profile_id TEXT NOT NULL
        REFERENCES revocation_profile_service.revocation_profiles(id) ON DELETE CASCADE,
    batch_interval TEXT NOT NULL,
    credential_format TEXT NOT NULL,
    credential_ids JSON NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_revocation_batches_org_created
    ON revocation_profile_service.revocation_batches (organization_id, created_at);
CREATE INDEX IF NOT EXISTS ix_revocation_batches_org_status
    ON revocation_profile_service.revocation_batches (organization_id, status);
"#;

const STATUS_ALLOCATION_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS revocation_profile_service.status_list_allocation_counters (
    organization_id TEXT NOT NULL,
    -- Retain the high-water mark if a profile is deleted and later restored.
    profile_id TEXT NOT NULL,
    status_list_format TEXT NOT NULL
        CHECK (status_list_format IN ('bitstring', 'token_status_list')),
    next_index BIGINT NOT NULL CHECK (next_index >= 0),
    PRIMARY KEY (organization_id, profile_id, status_list_format)
);

CREATE TABLE IF NOT EXISTS revocation_profile_service.status_list_allocations (
    credential_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    -- This is an immutable allocation ledger, not profile-owned cache state.
    -- Retain the original scope after profile deletion so a globally stable
    -- credential ID can never be rebound to another tenant or profile.
    profile_id TEXT NOT NULL,
    status_list_format TEXT NOT NULL
        CHECK (status_list_format IN ('bitstring', 'token_status_list')),
    status_list_index BIGINT NOT NULL CHECK (status_list_index >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, profile_id, status_list_format, status_list_index)
);
CREATE INDEX IF NOT EXISTS ix_status_list_allocations_scope
    ON revocation_profile_service.status_list_allocations
        (organization_id, profile_id, status_list_format);

DO $backfill$
BEGIN
    IF to_regclass('issuance_service.issued_credentials') IS NOT NULL THEN
        EXECUTE $sql$
            WITH candidates AS (
                SELECT
                    credential.id AS credential_id,
                    credential.organization_id,
                    credential.revocation_profile_id AS profile_id,
                    CASE
                        WHEN entry.value ->> 'type' = 'TokenStatusListEntry'
                            THEN 'token_status_list'
                        ELSE 'bitstring'
                    END AS status_list_format,
                    (entry.value ->> 'index')::BIGINT AS status_list_index,
                    credential.issued_at,
                    entry.ordinality AS entry_ordinality
                FROM issuance_service.issued_credentials AS credential
                JOIN revocation_profile_service.revocation_profiles AS profile
                  ON profile.id = credential.revocation_profile_id
                 AND profile.organization_id = credential.organization_id
                CROSS JOIN LATERAL jsonb_array_elements(
                    COALESCE(credential.status_list_entries::jsonb, '[]'::jsonb)
                ) WITH ORDINALITY AS entry(value, ordinality)
                WHERE credential.revocation_profile_id IS NOT NULL
                  AND COALESCE(
                        entry.value ->> 'status_purpose',
                        entry.value ->> 'statusPurpose',
                        'revocation'
                      ) = 'revocation'
                  AND entry.value ->> 'index' ~ '^[0-9]+$'
            ),
            credential_winners AS (
                SELECT DISTINCT ON (credential_id)
                    credential_id, organization_id, profile_id,
                    status_list_format, status_list_index, issued_at
                FROM candidates
                ORDER BY credential_id, entry_ordinality
            ),
            slot_winners AS (
                SELECT DISTINCT ON (
                    organization_id, profile_id, status_list_format,
                    status_list_index
                )
                    credential_id, organization_id, profile_id,
                    status_list_format, status_list_index, issued_at
                FROM credential_winners
                ORDER BY
                    organization_id, profile_id, status_list_format,
                    status_list_index, issued_at NULLS LAST, credential_id
            )
            INSERT INTO revocation_profile_service.status_list_allocations (
                credential_id, organization_id, profile_id, status_list_format,
                status_list_index, created_at
            )
            SELECT
                credential_id, organization_id, profile_id, status_list_format,
                status_list_index, COALESCE(issued_at, NOW())
            FROM slot_winners
            ON CONFLICT DO NOTHING
        $sql$;
    END IF;
END
$backfill$;

INSERT INTO revocation_profile_service.status_list_allocation_counters (
    organization_id, profile_id, status_list_format, next_index
)
SELECT
    organization_id,
    profile_id,
    status_list_format,
    MAX(status_list_index) + 1
FROM revocation_profile_service.status_list_allocations
GROUP BY organization_id, profile_id, status_list_format
ON CONFLICT (organization_id, profile_id, status_list_format)
DO UPDATE SET next_index = GREATEST(
    revocation_profile_service.status_list_allocation_counters.next_index,
    EXCLUDED.next_index
);
"#;

const MIGRATIONS: [(&str, &str); 4] = [
    ("001-profile-schema", PROFILE_SCHEMA_SQL),
    ("002-canonical-status-list-url", CANONICAL_URL_BACKFILL_SQL),
    ("003-operation-schema", OPERATION_SCHEMA_SQL),
    (
        "004-idempotent-status-list-allocation",
        STATUS_ALLOCATION_SCHEMA_SQL,
    ),
];

pub async fn migrate_and_seed(
    pool: &PgPool,
    organization_id: &str,
    public_base_url: &str,
) -> Result<(), sqlx::Error> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(MIGRATION_LOCK_ID)
        .execute(&mut *transaction)
        .await?;
    transaction.execute(sqlx::raw_sql(BOOTSTRAP_SQL)).await?;

    for (version, sql) in MIGRATIONS {
        apply_once(&mut transaction, version, sql).await?;
    }

    ensure_default_profile(&mut transaction, organization_id, public_base_url).await?;
    transaction.commit().await
}

async fn apply_once(
    transaction: &mut Transaction<'_, Postgres>,
    version: &str,
    sql: &'static str,
) -> Result<(), sqlx::Error> {
    let applied = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM revocation_profile_service.rust_schema_migrations WHERE version = $1)",
    )
    .bind(version)
    .fetch_one(&mut **transaction)
    .await?;
    if applied {
        return Ok(());
    }

    transaction.execute(sqlx::raw_sql(sql)).await?;
    sqlx::query(
        "INSERT INTO revocation_profile_service.rust_schema_migrations (version) VALUES ($1)",
    )
    .bind(version)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn ensure_default_profile(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    public_base_url: &str,
) -> Result<(), sqlx::Error> {
    let status_list_url = format!(
        "{}/v1/organizations/{organization_id}/revocation-profiles/{DEFAULT_REVOCATION_PROFILE_ID}/status-lists/{{mechanism}}/{{purpose}}",
        public_base_url.trim_end_matches('/')
    );
    let issuer_config = json!({
        "status_list_strategy": "auto",
        "status_list_base_url": status_list_url,
        "status_list_size": 131_072,
        "update_mode": "sync",
        "batch_interval_seconds": 300,
        "enable_rotation": true,
        "rotation_threshold_percent": 80,
        "enable_bitstring_status_list": true,
        "enable_token_status_list": true,
        "enable_legacy_revocation_list": false
    });
    let verifier_config = json!({
        "check_mode": "HARD_FAIL",
        "timing_mode": "ALWAYS",
        "mechanism_priority": ["BITSTRING_STATUS_LIST", "TOKEN_STATUS_LIST"],
        "cache_status_lists": true,
        "cache_ttl_seconds": 3_600,
        "offline_grace_seconds": 43_200,
        "check_timeout_seconds": 5,
        "max_retries": 2,
        "require_issuer_signature_on_status_list": true,
        "allow_third_party_registries": false
    });
    let automation_config = json!({
        "auto_allocate_indices": true,
        "auto_publish": true,
        "auto_generate_status_list_credentials": true,
        "auto_discover_endpoints": true,
        "use_format_defaults": true
    });
    let supported_formats = json!(["SD_JWT_VC", "MDOC", "VC_JWT"]);
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO revocation_profile_service.revocation_profiles (
            id, organization_id, name, status, issuer_config, verifier_config,
            automation_config, supported_formats, created_at, updated_at
        ) VALUES ($1, $2, $3, 'active', $4, $5, $6, $7, $8, $8)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(DEFAULT_REVOCATION_PROFILE_ID)
    .bind(organization_id)
    .bind("Marty Default Revocation")
    .bind(issuer_config)
    .bind(verifier_config)
    .bind(automation_config)
    .bind(supported_formats)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_contract_keeps_released_ids_and_schema_objects() {
        assert_eq!(
            DEFAULT_ORGANIZATION_ID,
            "00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(
            DEFAULT_REVOCATION_PROFILE_ID,
            "70000000-0000-0000-0000-000000000001"
        );
        assert!(PROFILE_SCHEMA_SQL.contains("revocation_profiles"));
        assert!(OPERATION_SCHEMA_SQL.contains("cascade_revocation_operations"));
        assert!(OPERATION_SCHEMA_SQL.contains("revocation_batches"));
        assert!(CANONICAL_URL_BACKFILL_SQL.contains("/status-lists/{mechanism}/{purpose}"));
        assert!(STATUS_ALLOCATION_SCHEMA_SQL.contains("status_list_allocations"));
        assert!(STATUS_ALLOCATION_SCHEMA_SQL.contains(
            "UNIQUE (organization_id, profile_id, status_list_format, status_list_index)"
        ));
        assert!(STATUS_ALLOCATION_SCHEMA_SQL.contains("issuance_service.issued_credentials"));
    }
}
