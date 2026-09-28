//! Issue one disposable passport acceptance key through Organization's normal application path.

use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::Path,
    sync::Arc,
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use chrono::{DateTime, Duration, Utc};
use marty_organization::{
    postgres::PostgresOrganizationStore, ApiKey, ApiKeyScopeType, ApiKeyStatus,
    CreateApiKeyCommand, OrganizationApplication, OrganizationCache, RevokeApiKeyCommand,
};
use mmf_data::MemoryCache;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Postgres, Transaction};
use url::Url;
use uuid::Uuid;

const OUTPUT_DIR: &str = "/app/data";
const OUTPUT_FILE: &str = "/app/data/passport-acceptance-api-key";
const ORGANIZATION_ID: &str = "00000000-0000-0000-0000-000000000001";
const KEY_LIFETIME_HOURS: i64 = 2;

#[derive(Debug)]
struct AcceptanceContext {
    project: String,
    run_id: String,
    source_commit: String,
    organization_id: Uuid,
    expires_at: DateTime<Utc>,
}

impl AcceptanceContext {
    fn from_environment(values: &BTreeMap<String, String>) -> io::Result<Self> {
        let run_id = required(values, "PASSPORT_ACCEPTANCE_RUN_ID")?;
        if run_id.len() > 20
            || run_id.starts_with('0')
            || !run_id.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(invalid("PASSPORT_ACCEPTANCE_RUN_ID"));
        }
        let project = required(values, "PASSPORT_ACCEPTANCE_PROJECT")?;
        let suffix = project
            .strip_prefix("marty-passport-acceptance-")
            .and_then(|value| value.rsplit_once('-'));
        let Some((surface, project_suffix)) = suffix else {
            return Err(invalid("PASSPORT_ACCEPTANCE_PROJECT"));
        };
        let nonce = project_suffix.strip_prefix(&run_id);
        if !matches!(surface, "base" | "selfhost")
            || nonce.is_none_or(|nonce| {
                nonce.len() != 6
                    || !nonce
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
        {
            return Err(invalid("PASSPORT_ACCEPTANCE_PROJECT"));
        }
        let source_commit = required(values, "PASSPORT_ACCEPTANCE_SOURCE_COMMIT")?;
        if source_commit.len() != 40
            || !source_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid("PASSPORT_ACCEPTANCE_SOURCE_COMMIT"));
        }
        let organization_id = required(values, "MARTY_ORG_ID")?;
        if organization_id != ORGANIZATION_ID {
            return Err(invalid("MARTY_ORG_ID"));
        }
        if required(values, "MARTY_DB_PASSWORD_FILE")? != "/run/secrets/marty_db_password" {
            return Err(invalid("MARTY_DB_PASSWORD_FILE"));
        }
        let expires_at =
            DateTime::parse_from_rfc3339(&required(values, "PASSPORT_ACCEPTANCE_EXPIRES_AT")?)
                .map_err(|_| invalid("PASSPORT_ACCEPTANCE_EXPIRES_AT"))?
                .with_timezone(&Utc);
        Ok(Self {
            project,
            run_id,
            source_commit,
            organization_id: Uuid::parse_str(&organization_id)
                .map_err(|_| invalid("MARTY_ORG_ID"))?,
            expires_at,
        })
    }
}

fn required(values: &BTreeMap<String, String>, name: &'static str) -> io::Result<String> {
    values
        .get(name)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| invalid(name))
}

fn invalid(name: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("invalid {name}"))
}

fn output_file() -> io::Result<File> {
    let directory = Path::new(OUTPUT_DIR);
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("passport acceptance output directory"));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(OUTPUT_FILE)
}

fn disposable_database_url() -> io::Result<String> {
    let path = Path::new("/run/secrets/marty_db_password");
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(invalid("MARTY_DB_PASSWORD_FILE"));
    }
    let password = fs::read_to_string(path)?;
    let password = password.trim_end_matches(['\r', '\n']);
    if password.is_empty() || password.bytes().any(|byte| matches!(byte, b'\r' | b'\n')) {
        return Err(invalid("MARTY_DB_PASSWORD_FILE"));
    }
    let mut url = Url::parse("postgresql://marty@postgres:5432/marty")
        .map_err(|_| invalid("DATABASE_URL"))?;
    url.set_password(Some(password))
        .map_err(|()| invalid("MARTY_DB_PASSWORD_FILE"))?;
    Ok(url.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let context = AcceptanceContext::from_environment(&env::vars().collect())?;
    let revoke = match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [argument] if argument == "--revoke-run" => true,
        _ => return Err(Box::<dyn Error>::from(invalid("command"))),
    };
    let database_url = disposable_database_url()?;
    if revoke {
        return revoke_run(&context, &database_url).await;
    }
    let mut output = output_file()?;
    let result = issue(&context, &database_url, &mut output).await;
    if result.is_err() {
        drop(output);
        let _ = fs::remove_file(OUTPUT_FILE);
    }
    result
}

async fn issue(
    context: &AcceptanceContext,
    database_url: &str,
    output: &mut File,
) -> Result<(), Box<dyn Error>> {
    let (application, _run_lock) = locked_application(context, database_url).await?;
    let now = Utc::now();
    let command = key_command(context, now)?;
    let created_by = command.created_by.clone();
    let creation = application.create_api_key(command).await?;
    let result = (|| -> io::Result<()> {
        output.write_all(creation.value.raw_key.as_bytes())?;
        output.write_all(b"\n")?;
        output.sync_all()
    })();
    if let Err(error) = result {
        application
            .revoke_api_key(RevokeApiKeyCommand {
                organization_id: context.organization_id,
                api_key_id: creation.value.api_key.id,
                revoked_by: created_by,
                now: Utc::now(),
            })
            .await?;
        return Err(Box::new(error));
    }
    Ok(())
}

async fn locked_application(
    context: &AcceptanceContext,
    database_url: &str,
) -> Result<(OrganizationApplication, Transaction<'static, Postgres>), Box<dyn Error>> {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(database_url)
        .await?;
    let mut run_lock = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(run_lock_key(context))
        .execute(&mut *run_lock)
        .await?;
    let cache = OrganizationCache::new(
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
    );
    let application = OrganizationApplication::new(PostgresOrganizationStore::new(pool), cache)?;
    Ok((application, run_lock))
}

async fn revoke_run(context: &AcceptanceContext, database_url: &str) -> Result<(), Box<dyn Error>> {
    let (application, _run_lock) = locked_application(context, database_url).await?;
    for key in application.list_api_keys(context.organization_id).await? {
        if belongs_to_run(&key, context) && key.status == ApiKeyStatus::Active {
            application
                .revoke_api_key(RevokeApiKeyCommand {
                    organization_id: context.organization_id,
                    api_key_id: key.id,
                    revoked_by: format!(
                        "passport-acceptance:{}:{}",
                        context.project, context.run_id
                    ),
                    now: Utc::now(),
                })
                .await?;
        }
    }
    Ok(())
}

fn run_lock_key(context: &AcceptanceContext) -> i64 {
    let identity = format!("{}/{}", context.project, context.run_id);
    let digest = Sha256::digest(identity.as_bytes());
    i64::from_be_bytes(digest[..8].try_into().expect("SHA-256 has eight bytes"))
}

fn belongs_to_run(key: &ApiKey, context: &AcceptanceContext) -> bool {
    key.organization_id == context.organization_id
        && key.name == format!("passport-acceptance-{}", context.run_id)
        && key.created_by == format!("passport-acceptance:{}:{}", context.project, context.run_id)
        && key.description.as_deref()
            == Some(&format!("Disposable source {}", context.source_commit))
        && key.key_prefix == "mk_test_"
        && key.scopes == ["credentials:read", "credentials:issue"]
        && key
            .expires_at
            .is_some_and(|expires| expires <= context.expires_at)
}

fn key_command(context: &AcceptanceContext, now: DateTime<Utc>) -> io::Result<CreateApiKeyCommand> {
    if context.expires_at <= now {
        return Err(invalid("PASSPORT_ACCEPTANCE_EXPIRES_AT"));
    }
    Ok(CreateApiKeyCommand {
        organization_id: context.organization_id,
        name: format!("passport-acceptance-{}", context.run_id),
        created_by: format!("passport-acceptance:{}:{}", context.project, context.run_id),
        scopes: Some(vec!["credentials:read".into(), "credentials:issue".into()]),
        description: Some(format!("Disposable source {}", context.source_commit)),
        is_test: true,
        scope_type: ApiKeyScopeType::Organization,
        deployment_profile_id: None,
        rate_limit: None,
        expires_at: Some(
            context
                .expires_at
                .min(now + Duration::hours(KEY_LIFETIME_HOURS)),
        ),
        now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use marty_organization::ApiKeySpec;

    fn values() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "PASSPORT_ACCEPTANCE_PROJECT".into(),
                "marty-passport-acceptance-base-123456abcdef".into(),
            ),
            ("PASSPORT_ACCEPTANCE_RUN_ID".into(), "123456".into()),
            ("PASSPORT_ACCEPTANCE_SOURCE_COMMIT".into(), "a".repeat(40)),
            (
                "PASSPORT_ACCEPTANCE_EXPIRES_AT".into(),
                (Utc::now() + Duration::hours(1)).to_rfc3339(),
            ),
            ("MARTY_ORG_ID".into(), ORGANIZATION_ID.into()),
            (
                "MARTY_DB_PASSWORD_FILE".into(),
                "/run/secrets/marty_db_password".into(),
            ),
        ])
    }

    #[test]
    fn only_disposable_project_and_database_are_accepted() {
        assert!(AcceptanceContext::from_environment(&values()).is_ok());
        for (name, replacement) in [
            ("PASSPORT_ACCEPTANCE_PROJECT", "marty-selfhost-prod"),
            ("PASSPORT_ACCEPTANCE_RUN_ID", "123457"),
            ("PASSPORT_ACCEPTANCE_SOURCE_COMMIT", "not-a-commit"),
            ("MARTY_ORG_ID", "00000000-0000-0000-0000-000000000002"),
            ("MARTY_DB_PASSWORD_FILE", "/run/secrets/prod_password"),
            ("PASSPORT_ACCEPTANCE_EXPIRES_AT", "not-a-date"),
        ] {
            let mut invalid = values();
            invalid.insert(name.into(), replacement.into());
            assert!(
                AcceptanceContext::from_environment(&invalid).is_err(),
                "{name}"
            );
        }
    }

    #[test]
    fn key_request_is_test_only_scoped_and_short_lived() {
        let context = AcceptanceContext::from_environment(&values()).unwrap();
        let now = Utc::now();
        let command = key_command(&context, now).unwrap();
        assert!(command.is_test);
        assert_eq!(command.scope_type, ApiKeyScopeType::Organization);
        assert_eq!(
            command.scopes.unwrap(),
            ["credentials:read", "credentials:issue"]
        );
        assert_eq!(command.expires_at, Some(context.expires_at));
        assert_eq!(command.organization_id, context.organization_id);
        assert_eq!(
            command.created_by,
            "passport-acceptance:marty-passport-acceptance-base-123456abcdef:123456"
        );
    }

    #[test]
    fn expired_lease_cannot_issue_a_key() {
        let mut environment = values();
        environment.insert(
            "PASSPORT_ACCEPTANCE_EXPIRES_AT".into(),
            (Utc::now() - Duration::seconds(1)).to_rfc3339(),
        );
        let context = AcceptanceContext::from_environment(&environment).unwrap();
        assert!(key_command(&context, Utc::now()).is_err());
    }

    #[test]
    fn cleanup_selects_only_the_attested_run_key() {
        let context = AcceptanceContext::from_environment(&values()).unwrap();
        let command = key_command(&context, Utc::now()).unwrap();
        let (key, _) = ApiKey::create(
            ApiKeySpec {
                organization_id: command.organization_id,
                name: command.name,
                created_by: command.created_by,
                scopes: command.scopes,
                description: command.description,
                expires_at: command.expires_at,
                now: command.now,
            },
            true,
        );
        assert!(belongs_to_run(&key, &context));
        let mut unrelated = key.clone();
        unrelated.created_by.push_str("-other");
        assert!(!belongs_to_run(&unrelated, &context));
        let mut unrelated = key.clone();
        unrelated.description = Some("Disposable source other".into());
        assert!(!belongs_to_run(&unrelated, &context));
        let mut unrelated = key.clone();
        unrelated.scopes.push("admin".into());
        assert!(!belongs_to_run(&unrelated, &context));
    }
}
