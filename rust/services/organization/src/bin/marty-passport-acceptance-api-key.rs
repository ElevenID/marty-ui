//! Issue disposable passport keys through Organization's normal application path.

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
    postgres::PostgresOrganizationStore, AddMemberDirectCommand, ApiKey, ApiKeyScopeType,
    ApiKeyStatus, CreateApiKeyCommand, CreateOrganizationCommand, CreateRoleCommand,
    DeleteRoleCommand, JoinMechanism, MemberStatus, OrganizationApplication, OrganizationCache,
    OrganizationType, Permission, RemoveMemberCommand, RevokeApiKeyCommand, Role,
};
use mmf_data::MemoryCache;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Postgres, Transaction};
use url::Url;
use uuid::Uuid;

const OUTPUT_DIR: &str = "/app/data";
const OUTPUT_FILE: &str = "/app/data/passport-acceptance-api-key";
const OPERATOR_OUTPUT_FILE: &str = "/app/data/passport-acceptance-operator-api-key";
const TENANT_PROBE_OUTPUT_FILE: &str = "/app/data/passport-acceptance-tenant-probe-api-key";
const ORGANIZATION_ID: &str = "00000000-0000-0000-0000-000000000001";
const KEY_LIFETIME_HOURS: i64 = 2;
const OPERATOR_SCOPES: &[&str] = &["flows:write", "templates:write", "applications:write"];
const OPERATOR_PERMISSIONS: &[&str] = &[
    "flow-definition:view",
    "flow-definition:create",
    "flow-definition:edit",
    "flow-definition:activate",
    "flow-instance:view",
    "flow-instance:start",
    "flow-instance:advance",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Command {
    IssueCredential,
    IssueOperator,
    IssueTenantProbe,
    RevokeRun,
}

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

fn output_file(path: &str) -> io::Result<File> {
    let directory = Path::new(OUTPUT_DIR);
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("passport acceptance output directory"));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)
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
    let command = match env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => Command::IssueCredential,
        [argument] if argument == "--operator" => Command::IssueOperator,
        [argument] if argument == "--tenant-probe" => Command::IssueTenantProbe,
        [argument] if argument == "--revoke-run" => Command::RevokeRun,
        _ => return Err(Box::<dyn Error>::from(invalid("command"))),
    };
    let database_url = disposable_database_url()?;
    if command == Command::RevokeRun {
        return revoke_run(&context, &database_url).await;
    }
    let path = match command {
        Command::IssueCredential => OUTPUT_FILE,
        Command::IssueOperator => OPERATOR_OUTPUT_FILE,
        Command::IssueTenantProbe => TENANT_PROBE_OUTPUT_FILE,
        Command::RevokeRun => unreachable!("handled above"),
    };
    let mut output = output_file(path)?;
    let result = match command {
        Command::IssueCredential => issue(&context, &database_url, &mut output).await,
        Command::IssueOperator => issue_operator(&context, &database_url, &mut output).await,
        Command::IssueTenantProbe => issue_tenant_probe(&context, &database_url, &mut output).await,
        Command::RevokeRun => unreachable!("handled above"),
    };
    if result.is_err() {
        drop(output);
        let _ = fs::remove_file(path);
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
    let existing = application.list_api_keys(context.organization_id).await?;
    if existing.iter().any(|key| claims_run_name(key, context)) {
        return Err(Box::new(invalid(
            "PASSPORT_ACCEPTANCE_RUN_ID already issued",
        )));
    }
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

fn tenant_probe_key_command(
    context: &AcceptanceContext,
    organization_id: Uuid,
    now: DateTime<Utc>,
) -> io::Result<CreateApiKeyCommand> {
    if organization_id == context.organization_id {
        return Err(invalid("tenant probe organization"));
    }
    let mut command = key_command(context, now)?;
    command.organization_id = organization_id;
    command.name = tenant_probe_name(context);
    Ok(command)
}

fn tenant_probe_name(context: &AcceptanceContext) -> String {
    format!("passport-tenant-probe-{}", context.run_id)
}

async fn issue_tenant_probe(
    context: &AcceptanceContext,
    database_url: &str,
    output: &mut File,
) -> Result<(), Box<dyn Error>> {
    let (application, _run_lock) = locked_application(context, database_url).await?;
    let now = Utc::now();
    if context.expires_at <= now {
        return Err(Box::new(invalid("PASSPORT_ACCEPTANCE_EXPIRES_AT")));
    }
    if application
        .store()
        .organization_by_name_case_insensitive(&tenant_probe_name(context))
        .await?
        .is_some()
    {
        return Err(Box::new(invalid("tenant probe already issued")));
    }
    let organization = application
        .create_organization(CreateOrganizationCommand {
            name: tenant_probe_name(context),
            owner_id: run_actor(context),
            org_type: OrganizationType::Education,
            display_name: Some("Disposable passport tenant isolation probe".into()),
            description: Some(operator_description(context)),
            contact_email: Some("disposable-tenant-probe@acceptance.invalid".into()),
            visibility: "PRIVATE".into(),
            join_mechanism: JoinMechanism::Invite,
            requires_approval: false,
            now,
        })
        .await?
        .value;
    let command = tenant_probe_key_command(context, organization.id, now)?;
    let created = application.create_api_key(command).await?.value;
    let result = (|| -> io::Result<()> {
        writeln!(output, "{}", organization.id)?;
        writeln!(output, "{}", created.raw_key)?;
        output.sync_all()
    })();
    if let Err(error) = result {
        application
            .revoke_api_key(RevokeApiKeyCommand {
                organization_id: organization.id,
                api_key_id: created.api_key.id,
                revoked_by: run_actor(context),
                now: Utc::now(),
            })
            .await?;
        return Err(Box::new(error));
    }
    Ok(())
}

fn run_actor(context: &AcceptanceContext) -> String {
    format!("passport-acceptance:{}:{}", context.project, context.run_id)
}

fn operator_name(context: &AcceptanceContext) -> String {
    format!("passport-flow-operator-{}", context.run_id)
}

fn operator_role_name(context: &AcceptanceContext) -> String {
    format!("passport-flow-operator-role-{}", context.run_id)
}

fn operator_description(context: &AcceptanceContext) -> String {
    format!(
        "Disposable source {} project {}",
        context.source_commit, context.project
    )
}

fn operator_key_command(
    context: &AcceptanceContext,
    now: DateTime<Utc>,
) -> io::Result<CreateApiKeyCommand> {
    if context.expires_at <= now {
        return Err(invalid("PASSPORT_ACCEPTANCE_EXPIRES_AT"));
    }
    Ok(CreateApiKeyCommand {
        organization_id: context.organization_id,
        name: operator_name(context),
        created_by: run_actor(context),
        scopes: Some(
            OPERATOR_SCOPES
                .iter()
                .map(|scope| (*scope).into())
                .collect(),
        ),
        description: Some(operator_description(context)),
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

fn operator_permission_ids(permissions: &[Permission]) -> io::Result<Vec<Uuid>> {
    OPERATOR_PERMISSIONS
        .iter()
        .map(|key| {
            let mut matches = permissions
                .iter()
                .filter(|permission| permission.key() == *key);
            match (matches.next(), matches.next()) {
                (Some(permission), None) => Ok(permission.id),
                _ => Err(invalid("operator permission catalog")),
            }
        })
        .collect()
}

fn owned_operator_role(role: &Role, context: &AcceptanceContext) -> bool {
    role.organization_id == context.organization_id
        && role.name == operator_role_name(context)
        && role.description.as_deref() == Some(operator_description(context).as_str())
        && !role.is_system
        && !role.is_default_for_new_members
        && role.permission_keys()
            == OPERATOR_PERMISSIONS
                .iter()
                .map(|key| (*key).to_owned())
                .collect()
}

fn owned_operator_key(key: &ApiKey, context: &AcceptanceContext) -> bool {
    operator_key_identity(key, context)
        && key.name == operator_name(context)
        && key.scopes == OPERATOR_SCOPES
}

fn operator_key_identity(key: &ApiKey, context: &AcceptanceContext) -> bool {
    key.organization_id == context.organization_id
        && key.created_by == run_actor(context)
        && key.description.as_deref() == Some(operator_description(context).as_str())
        && key.key_prefix == "mk_test_"
        && key
            .expires_at
            .is_some_and(|expires| expires <= context.expires_at)
}

async fn issue_operator(
    context: &AcceptanceContext,
    database_url: &str,
    output: &mut File,
) -> Result<(), Box<dyn Error>> {
    let (application, _run_lock) = locked_application(context, database_url).await?;
    let now = Utc::now();
    let key_command = operator_key_command(context, now)?;
    if application
        .list_api_keys(context.organization_id)
        .await?
        .iter()
        .any(|key| key.name == operator_name(context))
        || application
            .list_roles(context.organization_id)
            .await?
            .iter()
            .any(|role| role.name == operator_role_name(context))
    {
        return Err(Box::new(invalid("operator already issued")));
    }
    let role = application
        .create_role(CreateRoleCommand {
            organization_id: context.organization_id,
            name: operator_role_name(context),
            created_by: run_actor(context),
            display_name: Some("Disposable passport Flow operator".into()),
            description: Some(operator_description(context)),
            permission_ids: operator_permission_ids(&application.list_permissions().await?)?,
            is_default_for_new_members: false,
            now,
        })
        .await?
        .value;
    let result: Result<(), Box<dyn Error>> = async {
        let creation = application.create_api_key(key_command).await?.value;
        let key = &creation.api_key;
        let principal = format!("api_key:{}", key.id);
        if application
            .list_members(context.organization_id)
            .await?
            .iter()
            .any(|member| member.user_id == principal)
        {
            return Err(Box::new(invalid("operator principal already exists")) as Box<dyn Error>);
        }
        let member = application
            .add_member_direct(AddMemberDirectCommand {
                organization_id: context.organization_id,
                user_id: principal,
                email: None,
                role_ids: Some(vec![role.id]),
                now,
            })
            .await?
            .value;
        if member.status != MemberStatus::Active
            || member.roles.len() != 1
            || member.roles[0].id != role.id
        {
            return Err(Box::new(invalid("operator membership")) as Box<dyn Error>);
        }
        output.write_all(creation.raw_key.as_bytes())?;
        output.write_all(b"\n")?;
        output.sync_all()?;
        Ok(())
    }
    .await;
    if let Err(error) = result {
        cleanup_operator(&application, context).await?;
        return Err(error);
    }
    Ok(())
}

async fn cleanup_operator(
    application: &OrganizationApplication,
    context: &AcceptanceContext,
) -> Result<(), Box<dyn Error>> {
    let keys = application.list_api_keys(context.organization_id).await?;
    let roles = application.list_roles(context.organization_id).await?;
    let matching_keys = keys
        .iter()
        .filter(|key| key.name == operator_name(context) || operator_key_identity(key, context))
        .collect::<Vec<_>>();
    let matching_roles = roles
        .iter()
        .filter(|role| role.name == operator_role_name(context))
        .collect::<Vec<_>>();
    for key in matching_keys
        .iter()
        .filter(|key| operator_key_identity(key, context) && key.status == ApiKeyStatus::Active)
    {
        application
            .revoke_api_key(RevokeApiKeyCommand {
                organization_id: context.organization_id,
                api_key_id: key.id,
                revoked_by: run_actor(context),
                now: Utc::now(),
            })
            .await?;
    }
    if matching_keys
        .iter()
        .any(|key| !owned_operator_key(key, context))
        || matching_roles
            .iter()
            .any(|role| !owned_operator_role(role, context))
        || matching_keys.len() > 1
        || matching_roles.len() > 1
    {
        return Err(Box::new(invalid("operator ownership")));
    }
    let members = application.list_members(context.organization_id).await?;
    for key in matching_keys {
        let principal = format!("api_key:{}", key.id);
        for member in members.iter().filter(|member| member.user_id == principal) {
            if member.roles.len() != 1
                || matching_roles
                    .first()
                    .is_none_or(|role| member.roles[0].id != role.id)
            {
                return Err(Box::new(invalid("operator member ownership")));
            }
            application
                .remove_member(RemoveMemberCommand {
                    organization_id: context.organization_id,
                    member_id: member.id,
                    removed_by: run_actor(context),
                    now: Utc::now(),
                })
                .await?;
        }
    }
    for role in matching_roles {
        if members.iter().any(|member| {
            member.roles.iter().any(|assigned| assigned.id == role.id)
                && !keys.iter().any(|key| {
                    member.user_id == format!("api_key:{}", key.id)
                        && owned_operator_key(key, context)
                })
        }) {
            return Err(Box::new(invalid("operator role has foreign member")));
        }
        application
            .delete_role(DeleteRoleCommand {
                role_id: role.id,
                organization_id: context.organization_id,
                deleted_by: run_actor(context),
                replacement_role_id: None,
                now: Utc::now(),
            })
            .await?;
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
    let keys = application.list_api_keys(context.organization_id).await?;
    let mut errors = Vec::new();
    for key in keys.iter().filter(|key| {
        key.status == ApiKeyStatus::Active
            && (operator_key_identity(key, context) || credential_key_identity(key, context))
    }) {
        if let Err(error) = application
            .revoke_api_key(RevokeApiKeyCommand {
                organization_id: context.organization_id,
                api_key_id: key.id,
                revoked_by: run_actor(context),
                now: Utc::now(),
            })
            .await
        {
            errors.push(format!("key {} revocation failed: {error}", key.id));
        }
    }
    if let Err(error) = cleanup_operator(&application, context).await {
        errors.push(format!("operator cleanup failed: {error}"));
    }
    if let Err(error) = cleanup_tenant_probe(&application, context).await {
        errors.push(format!("tenant probe cleanup failed: {error}"));
    }
    let matching = keys
        .iter()
        .filter(|key| claims_run_name(key, context) || credential_key_identity(key, context))
        .collect::<Vec<_>>();
    if matching.len() > 1 || matching.iter().any(|key| !belongs_to_run(key, context)) {
        errors.push("credential key ownership drift".into());
    }
    if !errors.is_empty() {
        return Err(Box::new(io::Error::other(errors.join("; "))));
    }
    Ok(())
}

async fn cleanup_tenant_probe(
    application: &OrganizationApplication,
    context: &AcceptanceContext,
) -> Result<(), Box<dyn Error>> {
    let Some(organization) = application
        .store()
        .organization_by_name_case_insensitive(&tenant_probe_name(context))
        .await?
    else {
        return Ok(());
    };
    if organization.name != tenant_probe_name(context)
        || organization.owner_id != run_actor(context)
        || organization.description.as_deref() != Some(operator_description(context).as_str())
        || organization.id == context.organization_id
    {
        return Err(Box::new(invalid("tenant probe organization ownership")));
    }
    let keys = application.list_api_keys(organization.id).await?;
    if keys.len() > 1
        || keys.iter().any(|key| {
            key.name != tenant_probe_name(context)
                || key.organization_id != organization.id
                || key.created_by != run_actor(context)
                || key.key_prefix != "mk_test_"
                || key.scopes != ["credentials:read", "credentials:issue"]
                || key
                    .expires_at
                    .is_none_or(|expires| expires > context.expires_at)
        })
    {
        return Err(Box::new(invalid("tenant probe key ownership")));
    }
    for key in keys.iter().filter(|key| key.status == ApiKeyStatus::Active) {
        application
            .revoke_api_key(RevokeApiKeyCommand {
                organization_id: organization.id,
                api_key_id: key.id,
                revoked_by: run_actor(context),
                now: Utc::now(),
            })
            .await?;
    }
    Ok(())
}

fn run_lock_key(context: &AcceptanceContext) -> i64 {
    let identity = format!("{}/{}", context.project, context.run_id);
    let digest = Sha256::digest(identity.as_bytes());
    i64::from_be_bytes(digest[..8].try_into().expect("SHA-256 has eight bytes"))
}

fn belongs_to_run(key: &ApiKey, context: &AcceptanceContext) -> bool {
    claims_run_name(key, context)
        && credential_key_identity(key, context)
        && key.scopes == ["credentials:read", "credentials:issue"]
}

fn credential_key_identity(key: &ApiKey, context: &AcceptanceContext) -> bool {
    key.organization_id == context.organization_id
        && key.created_by == run_actor(context)
        && key.description.as_deref()
            == Some(&format!("Disposable source {}", context.source_commit))
        && key.key_prefix == "mk_test_"
        && key
            .expires_at
            .is_some_and(|expires| expires <= context.expires_at)
}

fn claims_run_name(key: &ApiKey, context: &AcceptanceContext) -> bool {
    key.organization_id == context.organization_id
        && key.name == format!("passport-acceptance-{}", context.run_id)
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
    fn tenant_probe_key_requires_a_distinct_organization() {
        let context = AcceptanceContext::from_environment(&values()).unwrap();
        let other = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        let command = tenant_probe_key_command(&context, other, Utc::now()).unwrap();
        assert_eq!(command.organization_id, other);
        assert_eq!(command.name, "passport-tenant-probe-123456");
        assert_eq!(
            command.scopes.unwrap(),
            ["credentials:read", "credentials:issue"]
        );
        assert!(command.is_test);
        assert!(command.expires_at.unwrap() <= context.expires_at);
        assert!(tenant_probe_key_command(&context, context.organization_id, Utc::now()).is_err());
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
        assert!(claims_run_name(&key, &context));
        let mut unrelated = key.clone();
        unrelated.created_by.push_str("-other");
        assert!(!belongs_to_run(&unrelated, &context));
        let mut unrelated = key.clone();
        unrelated.description = Some("Disposable source other".into());
        assert!(!belongs_to_run(&unrelated, &context));
        let mut unrelated = key.clone();
        unrelated.scopes.push("admin".into());
        assert!(!belongs_to_run(&unrelated, &context));
        assert!(credential_key_identity(&unrelated, &context));
        assert!(claims_run_name(&unrelated, &context));
        let mut unrelated = key.clone();
        unrelated.name.push_str("-another-run");
        assert!(!claims_run_name(&unrelated, &context));
    }

    #[test]
    fn operator_is_separate_from_issuance_and_has_only_flow_setup_authority() {
        let context = AcceptanceContext::from_environment(&values()).unwrap();
        let now = Utc::now();
        let command = operator_key_command(&context, now).unwrap();
        let narrow = key_command(&context, now).unwrap();
        assert_ne!(command.name, narrow.name);
        assert_eq!(
            command.scopes.as_ref().unwrap(),
            &OPERATOR_SCOPES
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(command.expires_at, Some(context.expires_at));
        assert!(command.is_test);
        assert_eq!(command.scope_type, ApiKeyScopeType::Organization);
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
        assert!(owned_operator_key(&key, &context));
        let mut overprivileged = key.clone();
        overprivileged.scopes.push("admin:full".into());
        assert!(!owned_operator_key(&overprivileged, &context));
        assert!(operator_key_identity(&overprivileged, &context));
        let mut foreign = key;
        foreign.description = Some("foreign project".into());
        assert!(!owned_operator_key(&foreign, &context));
    }

    #[test]
    fn operator_permission_catalog_must_be_exact_and_complete() {
        let seeded = marty_organization::catalog::permission_catalog()
            .unwrap()
            .into_iter()
            .map(|definition| Permission::new(definition.resource, definition.action))
            .collect::<Vec<_>>();
        assert_eq!(operator_permission_ids(&seeded).unwrap().len(), 7);
        let permissions = OPERATOR_PERMISSIONS
            .iter()
            .map(|key| {
                let (resource, action) = key.split_once(':').unwrap();
                Permission::new(resource, action)
            })
            .collect::<Vec<_>>();
        assert_eq!(operator_permission_ids(&permissions).unwrap().len(), 7);
        assert!(operator_permission_ids(&permissions[..6]).is_err());
        let mut duplicate = permissions;
        duplicate.push(Permission::new("flow-instance", "advance"));
        assert!(operator_permission_ids(&duplicate).is_err());
    }
}
