use sqlx::{PgConnection, PgPool, Row};
use thiserror::Error;

const MIGRATION_VERSIONS: &[&str] = &[
    "rust_credential_template_0001",
    "rust_credential_template_0002",
];
const ADVISORY_LOCK_ID: i64 = 718_431_214;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialTemplateDataReconciliationConfig {
    pub marty_organization_id: String,
    pub public_api_origin: String,
    pub public_hostname: String,
    pub selfhost_production: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CredentialTemplateDataReconciliationSummary {
    pub public_vcts_repaired: u64,
    pub issuer_dids_repaired: u64,
    pub revocation_profiles_repaired: u64,
    pub templates_deprecated: u64,
    pub selfhost_templates_archived: u64,
}

#[derive(Debug, Error)]
pub enum CredentialTemplateMigrationError {
    #[error("CREDENTIAL_TEMPLATE.MIGRATION_DATABASE: {0}")]
    Database(#[from] sqlx::Error),
    #[error("CREDENTIAL_TEMPLATE.MIGRATION_INCOMPATIBLE: {0}")]
    Incompatible(String),
}

pub async fn migrate_credential_template_schema(
    pool: &PgPool,
) -> Result<(), CredentialTemplateMigrationError> {
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_ID)
        .execute(&mut *transaction)
        .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0001_credential_template_schema.sql"
    ))
    .execute(&mut *transaction)
    .await?;
    sqlx::raw_sql(include_str!(
        "../migrations/0002_legacy_data_reconciliation.sql"
    ))
    .execute(&mut *transaction)
    .await?;
    validate_connection(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}

pub async fn validate_credential_template_schema(
    pool: &PgPool,
) -> Result<(), CredentialTemplateMigrationError> {
    let mut connection = pool.acquire().await?;
    validate_connection(&mut connection).await
}

pub async fn reconcile_credential_template_data(
    pool: &PgPool,
    config: &CredentialTemplateDataReconciliationConfig,
) -> Result<CredentialTemplateDataReconciliationSummary, CredentialTemplateMigrationError> {
    validate_reconciliation_config(config)?;
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_ID)
        .execute(&mut *transaction)
        .await?;
    let mut summary = CredentialTemplateDataReconciliationSummary::default();

    let badge_vct = format!(
        "{}/credentials/marty-verified-member-badge",
        config.public_api_origin.trim_end_matches('/')
    );
    let badge_image_url = format!("{badge_vct}/image.svg");
    let issuer_did = format!("did:web:{}:orgs:marty", config.public_hostname);

    sqlx::query(
        "UPDATE credential_template_service.credential_templates
         SET name='Marty Verified Member Badge',
             description='Open Badge 3.0 membership badge issued by Marty Identity Platform; presents verified membership for wallet-based passwordless login/sign-in.',
             vct=$1,
             display_style=jsonb_build_object(
                 'background_color','#3B1C8F','text_color','#FFFFFF',
                 'border_color',NULL,'logo_url',$2,'background_image_url',NULL
             ),
             updated_at=now()
         WHERE id='50000000-0000-0000-0000-000000000040'
           AND organization_id=$3",
    )
    .bind(&badge_vct)
    .bind(&badge_image_url)
    .bind(&config.marty_organization_id)
    .execute(&mut *transaction)
    .await?;

    sqlx::query(
        "UPDATE credential_template_service.credential_templates
         SET vct=$1,version=coalesce(version,0)+1,updated_at=now()
         WHERE id='50000000-0000-0000-0000-000000000010'
           AND organization_id=$2
           AND credential_type='MemberCredential'
           AND (vct='https://marty.example/credentials/MemberCredential'
                OR nullif(trim(vct),'') IS NULL)",
    )
    .bind(&badge_vct)
    .bind(&config.marty_organization_id)
    .execute(&mut *transaction)
    .await?;

    summary.public_vcts_repaired += sqlx::query(
        "UPDATE credential_template_service.credential_templates
         SET vct=$1 || substring(vct from 35),
             version=coalesce(version,0)+1,updated_at=now()
         WHERE lower(status)='active'
           AND vct LIKE 'https://marty.example/credentials/%'",
    )
    .bind(format!(
        "{}/credentials/",
        config.public_api_origin.trim_end_matches('/')
    ))
    .execute(&mut *transaction)
    .await?
    .rows_affected();

    if config.selfhost_production {
        summary.selfhost_templates_archived = sqlx::query(
            "UPDATE credential_template_service.credential_templates
             SET status='archived',updated_at=now()
             WHERE organization_id=$1
               AND id=ANY($2::text[])
               AND status<>'archived'",
        )
        .bind(&config.marty_organization_id)
        .bind(vec![
            "50000000-0000-0000-0000-000000000010",
            "50000000-0000-0000-0000-000000000020",
            "50000000-0000-0000-0000-000000000030",
            "50000000-0000-0000-0000-000000000050",
            "50000000-0000-0000-0000-000000000060",
            "50000000-0000-0000-0000-000000000070",
            "50000000-0000-0000-0000-000000000080",
            "50000000-0000-0000-0000-000000000090",
            "50000000-0000-0000-0000-0000000000a0",
        ])
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        sqlx::query(
            "UPDATE credential_template_service.credential_templates
             SET status='active',updated_at=now()
             WHERE organization_id=$1
               AND id='50000000-0000-0000-0000-000000000040'
               AND status<>'active'",
        )
        .bind(&config.marty_organization_id)
        .execute(&mut *transaction)
        .await?;
    }

    let revocation_table_exists: bool = sqlx::query_scalar(
        "SELECT to_regclass('revocation_profile_service.revocation_profiles') IS NOT NULL",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let missing_active_revocation: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM credential_template_service.credential_templates
         WHERE lower(status)='active'
           AND nullif(trim(revocation_profile_id),'') IS NULL",
    )
    .fetch_one(&mut *transaction)
    .await?;
    if missing_active_revocation > 0 && !revocation_table_exists {
        return Err(incompatible(
            "active templates need revocation profiles but the revocation-profile schema is unavailable",
        ));
    }
    if revocation_table_exists {
        summary.revocation_profiles_repaired = sqlx::query(
            "WITH sole_active_profile AS (
                SELECT organization_id,min(id) AS profile_id
                FROM revocation_profile_service.revocation_profiles
                WHERE lower(status)='active'
                GROUP BY organization_id HAVING count(*)=1
             )
             UPDATE credential_template_service.credential_templates AS template
             SET revocation_profile_id=profile.profile_id,updated_at=now()
             FROM sole_active_profile AS profile
             WHERE template.organization_id=profile.organization_id
               AND lower(template.status)='active'
               AND nullif(trim(template.revocation_profile_id),'') IS NULL",
        )
        .execute(&mut *transaction)
        .await?
        .rows_affected();
    }
    summary.templates_deprecated = sqlx::query(
        "UPDATE credential_template_service.credential_templates
         SET status='deprecated',updated_at=now()
         WHERE lower(status)='active'
           AND nullif(trim(revocation_profile_id),'') IS NULL",
    )
    .execute(&mut *transaction)
    .await?
    .rows_affected();

    summary.issuer_dids_repaired = sqlx::query(
        "UPDATE credential_template_service.credential_templates
         SET issuer_did=$1,version=coalesce(version,0)+1,updated_at=now()
         WHERE organization_id=$2
           AND lower(status)='active'
           AND nullif(trim(issuer_did),'') IS NULL",
    )
    .bind(&issuer_did)
    .bind(&config.marty_organization_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();

    let unresolved_vcts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM credential_template_service.credential_templates
         WHERE lower(status)='active'
           AND vct LIKE 'https://marty.example/credentials/%'",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let unresolved_issuer_dids: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM credential_template_service.credential_templates
         WHERE organization_id=$1 AND lower(status)='active'
           AND nullif(trim(issuer_did),'') IS NULL",
    )
    .bind(&config.marty_organization_id)
    .fetch_one(&mut *transaction)
    .await?;
    if unresolved_vcts != 0 || unresolved_issuer_dids != 0 {
        return Err(incompatible(
            "active Marty templates retain placeholder VCT or missing issuer DID state",
        ));
    }

    transaction.commit().await?;
    Ok(summary)
}

fn validate_reconciliation_config(
    config: &CredentialTemplateDataReconciliationConfig,
) -> Result<(), CredentialTemplateMigrationError> {
    let origin = url::Url::parse(&config.public_api_origin)
        .map_err(|_| incompatible("public API origin is invalid"))?;
    if !matches!(origin.scheme(), "http" | "https")
        || origin.host_str() != Some(config.public_hostname.as_str())
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || config.marty_organization_id.trim().is_empty()
    {
        return Err(incompatible("data reconciliation configuration is invalid"));
    }
    Ok(())
}

async fn validate_connection(
    connection: &mut PgConnection,
) -> Result<(), CredentialTemplateMigrationError> {
    for migration_version in MIGRATION_VERSIONS {
        let version: Option<String> = sqlx::query_scalar(
            "SELECT version FROM credential_template_service.rust_schema_versions WHERE version=$1",
        )
        .bind(migration_version)
        .fetch_optional(&mut *connection)
        .await?;
        if version.as_deref() != Some(*migration_version) {
            return Err(incompatible(&format!(
                "Rust migration {migration_version} is missing"
            )));
        }
    }

    let expected_tables = [
        "credential_templates",
        "wallet_registry",
        "delivery_destinations",
        "rust_schema_versions",
    ];
    let table_rows = sqlx::query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema='credential_template_service'",
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
        ("credential_templates", "zk_predicate_claims"),
        ("credential_templates", "credential_payload_format"),
        ("credential_templates", "wallet_configs"),
        ("credential_templates", "compliance_profile"),
        ("credential_templates", "compliance_profile_id"),
        ("credential_templates", "application_template_id"),
        ("credential_templates", "trust_profile_id"),
        ("credential_templates", "revocation_profile_id"),
        ("credential_templates", "issuer_algorithm"),
        ("credential_templates", "issuer_did"),
        ("credential_templates", "issuance_protocol"),
        ("wallet_registry", "routing_templates"),
        ("wallet_registry", "install_urls"),
        ("wallet_registry", "supports_digital_credentials"),
        ("wallet_registry", "supports_haip"),
    ];
    let column_rows = sqlx::query(
        "SELECT table_name, column_name FROM information_schema.columns \
         WHERE table_schema='credential_template_service'",
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
    for forbidden in [
        "auto_generate_artifacts",
        "issuer_certificate_chain_pem",
        "remote_signing_config",
        "issuer_key_id",
        "key_access_mode",
        "issuer_profile_id",
    ] {
        if column_rows.iter().any(|row| {
            row.get::<String, _>("table_name") == "credential_templates"
                && row.get::<String, _>("column_name") == forbidden
        }) {
            return Err(incompatible(&format!(
                "retired credential_templates.{forbidden} is still present"
            )));
        }
    }
    let compliance_nullable: String = sqlx::query_scalar(
        "SELECT is_nullable FROM information_schema.columns
         WHERE table_schema='credential_template_service'
           AND table_name='credential_templates'
           AND column_name='compliance_profile_id'",
    )
    .fetch_one(&mut *connection)
    .await?;
    if compliance_nullable != "NO" {
        return Err(incompatible(
            "credential_templates.compliance_profile_id must be required",
        ));
    }
    Ok(())
}

fn incompatible(message: &str) -> CredentialTemplateMigrationError {
    CredentialTemplateMigrationError::Incompatible(message.to_owned())
}
