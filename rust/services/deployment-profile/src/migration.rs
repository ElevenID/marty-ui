use sqlx::PgPool;
use thiserror::Error;

const ADVISORY_LOCK: i64 = 801_020_260_821;
const VERSION: &str = "deployment-profile-rust-v2-api-auth-canonicalization";

pub const DEPLOYMENT_PROFILE_SCHEMA: &str = r#"
CREATE SCHEMA IF NOT EXISTS deployment_profile_service;
CREATE TABLE IF NOT EXISTS deployment_profile_service.deployment_profiles (
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, name TEXT NOT NULL,
 description TEXT, status TEXT NOT NULL, environment TEXT NOT NULL, site_id TEXT,
 trust_profile_id TEXT, presentation_policy_ids JSONB NOT NULL DEFAULT '[]',
 credential_template_ids JSONB NOT NULL DEFAULT '[]', default_policy_id TEXT,
 network_mode TEXT NOT NULL DEFAULT 'ONLINE', key_access_mode TEXT NOT NULL DEFAULT 'KEY_VAULT',
 environment_config JSONB NOT NULL DEFAULT '{}', enabled_flow_ids JSONB NOT NULL DEFAULT '[]',
 update_channel TEXT NOT NULL DEFAULT 'stable', update_policy JSONB NOT NULL DEFAULT '{}',
 offline_cache_ttl_hours INTEGER NOT NULL DEFAULT 24,
 operator_biometric_authentication_required BOOLEAN NOT NULL DEFAULT FALSE,
 audit_all_events BOOLEAN NOT NULL DEFAULT TRUE, api_key TEXT, api_key_prefix TEXT NOT NULL DEFAULT '',
 callbacks JSONB NOT NULL DEFAULT '{}', api_auth JSONB NOT NULL DEFAULT '{}',
 rate_limits JSONB NOT NULL DEFAULT '{}', feature_flags JSONB NOT NULL DEFAULT '{}',
 branding JSONB NOT NULL DEFAULT '{}', created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_deployment_profiles_organization_id ON deployment_profile_service.deployment_profiles(organization_id);
CREATE INDEX IF NOT EXISTS ix_deployment_profiles_org_status ON deployment_profile_service.deployment_profiles(organization_id,status);
CREATE INDEX IF NOT EXISTS ix_deployment_profiles_status ON deployment_profile_service.deployment_profiles(status);
CREATE TABLE IF NOT EXISTS deployment_profile_service.lanes (
 id TEXT PRIMARY KEY, deployment_profile_id TEXT NOT NULL REFERENCES deployment_profile_service.deployment_profiles(id),
 name TEXT NOT NULL, description TEXT, location TEXT, device_type TEXT NOT NULL DEFAULT 'kiosk',
 default_policy_id TEXT, metadata JSONB NOT NULL DEFAULT '{}', device_ids JSONB NOT NULL DEFAULT '[]',
 created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_lanes_deployment_profile_id ON deployment_profile_service.lanes(deployment_profile_id);
CREATE TABLE IF NOT EXISTS deployment_profile_service.native_migrations (
 version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"#;

#[derive(Debug, Error)]
pub enum DeploymentMigrationError {
    #[error("DEPLOYMENT_PROFILE.MIGRATION_DATABASE: {0}")]
    Database(#[from] sqlx::Error),
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), DeploymentMigrationError> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK)
        .execute(&mut *tx)
        .await?;
    sqlx::raw_sql(DEPLOYMENT_PROFILE_SCHEMA)
        .execute(&mut *tx)
        .await?;
    // Upgrade databases created by the Python revisions without data loss.
    sqlx::raw_sql(
        "ALTER TABLE deployment_profile_service.deployment_profiles ADD COLUMN IF NOT EXISTS operator_biometric_authentication_required BOOLEAN NOT NULL DEFAULT FALSE;
         ALTER TABLE deployment_profile_service.deployment_profiles ADD COLUMN IF NOT EXISTS callbacks JSONB NOT NULL DEFAULT '{}';
         ALTER TABLE deployment_profile_service.deployment_profiles ADD COLUMN IF NOT EXISTS api_auth JSONB NOT NULL DEFAULT '{}';
         ALTER TABLE deployment_profile_service.deployment_profiles ADD COLUMN IF NOT EXISTS rate_limits JSONB NOT NULL DEFAULT '{}';
         ALTER TABLE deployment_profile_service.deployment_profiles ADD COLUMN IF NOT EXISTS feature_flags JSONB NOT NULL DEFAULT '{}';
         ALTER TABLE deployment_profile_service.deployment_profiles ADD COLUMN IF NOT EXISTS branding JSONB NOT NULL DEFAULT '{}';"
    ).execute(&mut *tx).await?;
    // The final Python migration renamed this column. Copy it only when the legacy column exists.
    sqlx::raw_sql(
        "DO $$ BEGIN
           IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='deployment_profile_service' AND table_name='deployment_profiles' AND column_name='biometric_required') THEN
             EXECUTE 'UPDATE deployment_profile_service.deployment_profiles SET operator_biometric_authentication_required=biometric_required';
           END IF;
         END $$;"
    ).execute(&mut *tx).await?;
    // Rust's initial enum spelling emitted `apikey`; preserve reads of those
    // records while converging persisted data on the language-neutral contract.
    sqlx::query(
        "UPDATE deployment_profile_service.deployment_profiles
         SET api_auth=jsonb_set(api_auth::jsonb, '{auth_method}', '\"api_key\"'::jsonb, false)
         WHERE api_auth->>'auth_method'='apikey'",
    )
    .execute(&mut *tx)
    .await?;
    seed_marty_login(&mut tx).await?;
    sqlx::query("INSERT INTO deployment_profile_service.native_migrations(version) VALUES($1) ON CONFLICT(version) DO NOTHING")
        .bind(VERSION).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

async fn seed_marty_login(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO deployment_profile_service.deployment_profiles
         (id,organization_id,name,description,status,environment,site_id,trust_profile_id,presentation_policy_ids,
          credential_template_ids,default_policy_id,network_mode,key_access_mode,environment_config,enabled_flow_ids,
          update_channel,update_policy,offline_cache_ttl_hours,operator_biometric_authentication_required,audit_all_events,
          api_key,api_key_prefix,callbacks,api_auth,rate_limits,feature_flags,branding,created_at,updated_at)
         VALUES('70000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
          'Marty Credential Login Deployment','Default deployment profile used for Marty credential-based login preview flows.',
          'active','production','marty-login','60000000-0000-0000-0000-000000000001',
          '[\"50000000-0000-0000-0000-000000000004\"]','[\"50000000-0000-0000-0000-000000000040\"]',
          '50000000-0000-0000-0000-000000000004','ONLINE','KEY_VAULT',
          '{\"language\":\"en-US\",\"offline_cache_ttl_seconds\":86400}', '[]','stable',
          '{\"channel\":\"stable\",\"auto_update\":true}',24,FALSE,TRUE,NULL,'','{}',
          '{\"auth_method\":\"api_key\",\"api_key_header\":\"X-API-Key\"}',
          '{\"enabled\":true,\"requests_per_minute\":300,\"requests_per_hour\":5000,\"requests_per_day\":50000,\"burst_size\":50,\"endpoint_limits\":{}}',
          '{}','{}',now(),now())
         ON CONFLICT(id) DO UPDATE SET presentation_policy_ids=EXCLUDED.presentation_policy_ids,
          credential_template_ids=EXCLUDED.credential_template_ids,default_policy_id=EXCLUDED.default_policy_id,
          trust_profile_id=EXCLUDED.trust_profile_id,updated_at=now()"
    ).execute(&mut **tx).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn schema_owns_final_columns_and_current_open_badge_seed() {
        for field in [
            "operator_biometric_authentication_required",
            "callbacks",
            "api_auth",
            "rate_limits",
            "feature_flags",
            "branding",
        ] {
            assert!(DEPLOYMENT_PROFILE_SCHEMA.contains(field));
        }
        let source = include_str!("migration.rs");
        assert_eq!(
            VERSION,
            "deployment-profile-rust-v2-api-auth-canonicalization"
        );
        assert!(source.contains("50000000-0000-0000-0000-000000000040"));
        // Python-created databases own this column as `json`, while fresh
        // Rust databases own it as `jsonb`. The normalizer must accept both.
        assert!(source.contains("jsonb_set(api_auth::jsonb"));
        assert!(source.contains("api_auth->>'auth_method'='apikey'"));
        assert!(!DEPLOYMENT_PROFILE_SCHEMA.contains("default_compliance_profile_id"));
    }
}
