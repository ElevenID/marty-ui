//! Explicit, reset-friendly vendor seed. No production migration calls this crate.

use serde_json::Value;
use sqlx::{Connection, PgConnection};
use std::env;
use url::Url;

pub const ORGANIZATION_ID: &str = "22222222-2222-2222-2222-222222222222";
const REFERENCE: &str = include_str!("../../../../contracts/demo-seed-reference-v1.json");

pub fn normalize_profile(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" | "local" | "development" => "dev".into(),
        "experiment" | "experimental" | "beta-experiment" | "beta_experiment"
        | "beta-experiments" | "beta_experiments" => "experiments".into(),
        "prod" => "production".into(),
        "selfhost-prod" | "selfhost_prod" | "selfhostproduction" | "selfhost_production" => {
            "selfhost-production".into()
        }
        "qa" | "ci" => "test".into(),
        _ => normalized,
    }
}

pub fn persistent_profile(profile: &str) -> bool {
    matches!(profile, "production" | "selfhost-production")
}

fn env_first(names: &[&str], default: &str) -> String {
    let value = names
        .iter()
        .find_map(|name| env::var(name).ok().filter(|value| !value.is_empty()))
        .unwrap_or_default();
    let trimmed = value.trim();
    if trimmed.is_empty() {
        default.to_owned()
    } else {
        trimmed.to_owned()
    }
}

pub fn database_url() -> Result<String, String> {
    let supplied = env::var("DATABASE_URL").unwrap_or_default();
    let supplied = supplied.trim();
    let user = env_first(&["MARTY_DB_USER"], "marty");
    let password = env_first(&["MARTY_DB_PASSWORD"], "marty_dev_password");
    let host = env_first(
        &["DATABASE_HOST", "POSTGRES_HOST", "MARTY_DB_HOST"],
        "localhost",
    );
    let port = env_first(
        &[
            "DATABASE_PORT",
            "POSTGRES_PORT",
            "POSTGRES_HOST_PORT",
            "MARTY_DB_PORT",
        ],
        "5433",
    );
    let name = env_first(&["DATABASE_NAME", "POSTGRES_DB", "MARTY_DB_NAME"], "marty");
    let mut url = if supplied.is_empty() {
        Url::parse("postgresql://localhost/marty").map_err(|e| e.to_string())?
    } else {
        let normalized = supplied
            .replacen("postgresql+asyncpg://", "postgresql://", 1)
            .replacen("postgres://", "postgresql://", 1);
        Url::parse(&normalized).map_err(|_| "invalid DATABASE_URL".to_owned())?
    };
    if url.scheme() != "postgresql" {
        return Err("DATABASE_URL must use PostgreSQL".into());
    }
    let local = matches!(
        url.host_str(),
        None | Some("postgres" | "marty-postgres" | "localhost" | "127.0.0.1")
    );
    let effective_host = if local {
        host.as_str()
    } else {
        url.host_str().unwrap_or(host.as_str())
    };
    let effective_port = if local {
        port.parse::<u16>().map_err(|_| "invalid database port")?
    } else {
        url.port()
            .unwrap_or(port.parse::<u16>().map_err(|_| "invalid database port")?)
    };
    let effective_user = if local || url.username().is_empty() {
        user.as_str()
    } else {
        url.username()
    };
    let effective_name = if local || url.path().trim_start_matches('/').is_empty() {
        name.as_str()
    } else {
        url.path().trim_start_matches('/')
    };
    let effective_host = effective_host.to_owned();
    let effective_user = effective_user.to_owned();
    let effective_name = effective_name.to_owned();
    url.set_host(Some(&effective_host))
        .map_err(|_| "invalid database host")?;
    url.set_port(Some(effective_port))
        .map_err(|_| "invalid database port")?;
    url.set_username(&effective_user)
        .map_err(|_| "invalid database user")?;
    url.set_password(Some(&password))
        .map_err(|_| "invalid database password")?;
    url.set_path(&format!("/{effective_name}"));
    Ok(url.to_string())
}

pub fn reference() -> Result<Value, String> {
    let value: Value = serde_json::from_str(REFERENCE).map_err(|e| e.to_string())?;
    if value["schema"] != "marty.demo-seed-reference/v1"
        || value["vendor_bundle"]["organization"]["id"] != ORGANIZATION_ID
    {
        return Err("unexpected demo seed reference".into());
    }
    Ok(value)
}

pub fn payload_format(row: &Value) -> String {
    if let Some(explicit) = row["credential_payload_format"]
        .as_str()
        .filter(|s| !s.is_empty())
    {
        return explicit.to_owned();
    }
    let formats = row["supported_formats"].as_array();
    if formats.is_some_and(|items| items.iter().any(|item| item == "mso_mdoc")) {
        "mso_mdoc".into()
    } else if formats.is_some_and(|items| items.iter().any(|item| item == "sd_jwt_vc")) {
        "w3c_vcdm_v2_sd_jwt".into()
    } else if let Some(first) = formats
        .and_then(|items| items.first())
        .and_then(Value::as_str)
    {
        first.to_owned()
    } else {
        "w3c_vcdm_v2_sd_jwt".into()
    }
}

fn string<'a>(row: &'a Value, key: &str) -> Result<&'a str, String> {
    row[key]
        .as_str()
        .ok_or_else(|| format!("demo fixture missing {key}"))
}

fn json_text(row: &Value, key: &str) -> Result<String, String> {
    serde_json::to_string(&row[key]).map_err(|e| e.to_string())
}

async fn table_exists(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    table: &str,
) -> Result<bool, String> {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(table)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| e.to_string())
}

async fn column_exists(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    table: &str,
    column: &str,
) -> Result<bool, String> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'credential_template_service' AND table_name = $1 AND column_name = $2)")
        .bind(table).bind(column).fetch_one(&mut **tx).await.map_err(|e| e.to_string())
}

async fn seed_organization(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    row: &Value,
) -> Result<(), String> {
    let id = string(row, "id")?;
    let name = string(row, "name")?;
    let slug = string(row, "slug")?;
    let settings = json_text(row, "settings")?;
    sqlx::query("UPDATE organization_service.organizations SET name=$2,display_name=$3,slug=$4,description=$5,org_type=$6,status=$7,join_mechanism=$8,requires_approval=$9,is_discoverable=$10,settings=$11::jsonb,updated_at=NOW() WHERE id=$1::uuid OR slug=$4 OR LOWER(name)=LOWER($2)")
        .bind(id).bind(name).bind(string(row,"display_name")?).bind(slug)
        .bind(string(row,"description")?).bind(string(row,"org_type")?).bind(string(row,"status")?)
        .bind(string(row,"join_mechanism")?).bind(row["requires_approval"].as_bool().unwrap_or(false))
        .bind(row["is_discoverable"].as_bool().unwrap_or(false)).bind(&settings)
        .execute(&mut **tx).await.map_err(|e| e.to_string())?;
    sqlx::query("INSERT INTO organization_service.organizations(id,name,display_name,slug,description,org_type,status,join_mechanism,requires_approval,is_discoverable,settings,created_at,updated_at) SELECT $1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,NOW(),NOW() WHERE NOT EXISTS (SELECT 1 FROM organization_service.organizations WHERE id=$1::uuid OR slug=$4 OR LOWER(name)=LOWER($2))")
        .bind(id).bind(name).bind(string(row,"display_name")?).bind(slug)
        .bind(string(row,"description")?).bind(string(row,"org_type")?).bind(string(row,"status")?)
        .bind(string(row,"join_mechanism")?).bind(row["requires_approval"].as_bool().unwrap_or(false))
        .bind(row["is_discoverable"].as_bool().unwrap_or(false)).bind(&settings)
        .execute(&mut **tx).await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn seed_types(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    rows: &[Value],
) -> Result<(), String> {
    for row in rows {
        let id = string(row, "id")?;
        let name = string(row, "name")?;
        let description = string(row, "description")?;
        let format = string(row, "format")?;
        let schema = json_text(row, "schema_definition")?;
        let display = json_text(row, "display_config")?;
        sqlx::query("UPDATE credential_service.credential_types SET description=$3,format=$4,status='active',schema_definition=$5::jsonb,display_config=$6::jsonb,validity_days=365,revocable=true,updated_at=NOW() WHERE organization_id=$1 AND name=$2")
            .bind(ORGANIZATION_ID).bind(name).bind(description).bind(format).bind(&schema).bind(&display)
            .execute(&mut **tx).await.map_err(|e| e.to_string())?;
        sqlx::query("INSERT INTO credential_service.credential_types(id,organization_id,name,description,format,status,schema_definition,display_config,validity_days,revocable,created_at,updated_at) SELECT $1,$2,$3,$4,$5,'active',$6::jsonb,$7::jsonb,365,true,NOW(),NOW() WHERE NOT EXISTS (SELECT 1 FROM credential_service.credential_types WHERE organization_id=$2 AND name=$3)")
            .bind(id).bind(ORGANIZATION_ID).bind(name).bind(description).bind(format).bind(&schema).bind(&display)
            .execute(&mut **tx).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn seed_templates(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    rows: &[Value],
    wallet: bool,
    payload: bool,
) -> Result<(), String> {
    // SQL fragments are constants selected by schema inspection, never user input.
    let payload_position = 18;
    let wallet_position = if payload { 19 } else { 18 };
    let wallet_update = if wallet {
        format!(",wallet_configs=${wallet_position}::jsonb")
    } else {
        String::new()
    };
    let payload_update = if payload {
        format!(",credential_payload_format=${payload_position}")
    } else {
        String::new()
    };
    let wallet_column = if wallet { ",wallet_configs" } else { "" };
    let wallet_value = if wallet {
        format!(",${wallet_position}::jsonb")
    } else {
        String::new()
    };
    let payload_column = if payload {
        ",credential_payload_format"
    } else {
        ""
    };
    let payload_value = if payload {
        format!(",${payload_position}")
    } else {
        String::new()
    };
    let update = format!("UPDATE credential_template_service.credential_templates SET name=$3,description=$4,status=$5,vct=$7,doctype=$8,claims=$9::jsonb,privacy_posture=$10,selective_disclosure_fields=$11::jsonb,derived_attributes=$12::jsonb,display_style=$13::jsonb,validity_rules=$14::jsonb,issuer_requirements=$15::jsonb,supported_formats=$16::jsonb,version=$17{payload_update}{wallet_update},updated_at=NOW() WHERE organization_id=$2 AND credential_type=$6 AND $1::varchar IS NOT NULL");
    let insert = format!("INSERT INTO credential_template_service.credential_templates(id,organization_id,name,description,status,credential_type,vct,doctype,claims,privacy_posture,selective_disclosure_fields,derived_attributes,display_style,validity_rules,issuer_requirements,supported_formats,version{payload_column}{wallet_column},created_at,updated_at) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11::jsonb,$12::jsonb,$13::jsonb,$14::jsonb,$15::jsonb,$16::jsonb,$17{payload_value}{wallet_value},NOW(),NOW() WHERE NOT EXISTS (SELECT 1 FROM credential_template_service.credential_templates WHERE organization_id=$2 AND credential_type=$6)");
    for row in rows {
        let id = string(row, "id")?;
        let name = string(row, "name")?;
        let description = string(row, "description")?;
        let status = string(row, "status")?;
        let credential_type = string(row, "credential_type")?;
        let privacy = string(row, "privacy_posture")?;
        let claims = json_text(row, "claims")?;
        let selective = json_text(row, "selective_disclosure_fields")?;
        let derived = json_text(row, "derived_attributes")?;
        let display = json_text(row, "display_style")?;
        let validity = json_text(row, "validity_rules")?;
        let issuer = json_text(row, "issuer_requirements")?;
        let formats = json_text(row, "supported_formats")?;
        let wallet_config = if row["wallet_configs"].is_null() {
            "[]".into()
        } else {
            json_text(row, "wallet_configs")?
        };
        let version = row["version"]
            .as_i64()
            .ok_or("demo fixture missing version")?;
        let format = payload_format(row);
        macro_rules! bind_template {
            ($sql:expr) => {{
                let mut query = sqlx::query(sqlx::AssertSqlSafe($sql.as_str()))
                    .bind(id)
                    .bind(ORGANIZATION_ID)
                    .bind(name)
                    .bind(description)
                    .bind(status)
                    .bind(credential_type)
                    .bind(row["vct"].as_str())
                    .bind(row["doctype"].as_str())
                    .bind(&claims)
                    .bind(privacy)
                    .bind(&selective)
                    .bind(&derived)
                    .bind(&display)
                    .bind(&validity)
                    .bind(&issuer)
                    .bind(&formats)
                    .bind(version);
                if payload {
                    query = query.bind(&format);
                }
                if wallet {
                    query = query.bind(&wallet_config);
                }
                query
            }};
        }
        bind_template!(&update)
            .execute(&mut **tx)
            .await
            .map_err(|e| e.to_string())?;
        bind_template!(&insert)
            .execute(&mut **tx)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct Summary {
    pub credential_types_seeded: usize,
    pub credential_templates_seeded: usize,
    pub wallet_configs_applied: bool,
}

pub async fn seed(url: &str) -> Result<Summary, String> {
    let reference = reference()?;
    let bundle = &reference["vendor_bundle"];
    let mut connection = PgConnection::connect(url)
        .await
        .map_err(|e| e.to_string())?;
    let mut tx = connection.begin().await.map_err(|e| e.to_string())?;
    if !table_exists(&mut tx, "organization_service.organizations").await? {
        return Err("organization_service.organizations is missing. Run schema/stable migrations before seeding demo fixtures.".into());
    }
    seed_organization(&mut tx, &bundle["organization"]).await?;
    let types = bundle["credential_types"]
        .as_array()
        .ok_or("invalid credential type fixture")?;
    let templates = bundle["credential_templates"]
        .as_array()
        .ok_or("invalid credential template fixture")?;
    let mut summary = Summary {
        credential_types_seeded: 0,
        credential_templates_seeded: 0,
        wallet_configs_applied: false,
    };
    if table_exists(&mut tx, "credential_service.credential_types").await? {
        seed_types(&mut tx, types).await?;
        summary.credential_types_seeded = types.len();
    }
    if table_exists(&mut tx, "credential_template_service.credential_templates").await? {
        let wallet = column_exists(&mut tx, "credential_templates", "wallet_configs").await?;
        let payload =
            column_exists(&mut tx, "credential_templates", "credential_payload_format").await?;
        seed_templates(&mut tx, templates, wallet, payload).await?;
        summary.credential_templates_seeded = templates.len();
        summary.wallet_configs_applied = wallet;
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(summary)
}
