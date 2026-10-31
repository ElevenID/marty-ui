//! Installation-scoped credential handoff through Organization's application owner.
//!
//! This is an internal setup executable, not a network authorization endpoint.
//! The authenticated installer owns admission of the image, job, immutable input
//! snapshots, database credential and private output mount. These checks bind
//! that job's scope; caller-supplied JSON is not release or installer authority.
//! Run only after ordinary Organization startup. Never migrate, create an
//! organization/member, or mint again after a surviving issue intent.

use std::{sync::Arc, time::Duration};

use chrono::{DateTime, Utc};
use mmf_data::MemoryCache;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    api_keys::{ApiKeyActor, INSTALLER_KEY_LIFETIME_SECONDS},
    postgres::PostgresOrganizationStore,
    ApiKey, ApiKeyCreation, ApiKeyScopeType, ApiKeyStatus, CreateApiKeyCommand,
    OrganizationApplication, OrganizationCache, OrganizationStatus, RevokeApiKeyCommand,
};

#[path = "installer_bootstrap_files.rs"]
mod files;

const REQUEST_SCHEMA: &str = "elevenid.installer-organization-bootstrap-request/v1";
const INTENT_SCHEMA: &str = "elevenid.installer-organization-bootstrap-intent/v1";
const RECEIPT_SCHEMA: &str = "elevenid.installer-organization-bootstrap-receipt/v1";
const REQUEST_LIFETIME_SECONDS: i64 = 5 * 60;
const KEY_FILE: &str = "api-key";
const INTENT_FILE: &str = "issue-intent.json";

/// Errors contain fixed classifications only, never SQL/provider/input values.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("installer organization credential {0}; preserve the operation evidence")]
pub struct BootstrapError(&'static str);

type Result<T> = std::result::Result<T, BootstrapError>;

fn need(condition: bool, code: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(BootstrapError(code))
    }
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn uuid(value: &str, version_four: bool) -> Result<Uuid> {
    let parsed = Uuid::parse_str(value).map_err(|_| BootstrapError("identity refused"))?;
    need(
        !parsed.is_nil()
            && parsed.to_string() == value
            && (!version_four || parsed.get_version_num() == 4),
        "identity refused",
    )?;
    Ok(parsed)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    request_id: String,
    created_at: DateTime<Utc>,
    installation_sha256: String,
    compose_session_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    installation_id: Uuid,
    organization_id: Uuid,
    request_id: Uuid,
    request_sha256: String,
    installation_sha256: String,
    compose_session_sha256: String,
    requested_at: DateTime<Utc>,
}

impl Context {
    fn read(request: &[u8], installation: &[u8], session: &[u8]) -> Result<Self> {
        let request_value: Request =
            serde_json::from_slice(request).map_err(|_| BootstrapError("request refused"))?;
        need(
            request_value.schema == REQUEST_SCHEMA
                && request_value.installation_sha256 == hash(installation)
                && request_value.compose_session_sha256 == hash(session),
            "input binding refused",
        )?;
        let journal: Value = serde_json::from_slice(installation)
            .map_err(|_| BootstrapError("installation refused"))?;
        let saved: Value =
            serde_json::from_slice(session).map_err(|_| BootstrapError("session refused"))?;
        let text = |value: &Value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(BootstrapError("startup identity refused"))
        };
        let installation_id = uuid(&text(&journal["installation_id"])?, true)?;
        let project = format!("marty-install-{}", installation_id.simple());
        let organization_id = uuid(
            &text(&saved["model"]["services"]["organization"]["environment"]["MARTY_ORG_ID"])?,
            false,
        )?;
        need(
            journal["schema"] == "elevenid.installer-state/v1"
                && matches!(
                    journal["phase"].as_str(),
                    Some("provisioning" | "provisioned")
                )
                && saved["schema"] == "elevenid.installer-compose-session/v1"
                && saved["installation_id"] == installation_id.to_string()
                && saved["inputs"]["project"] == project
                && saved["receipt"]["project"] == project
                && saved["receipt"]["engine_id"] == journal["runtime"]["engine_id"]
                && journal["runtime"]["engine_id"]
                    .as_str()
                    .is_some_and(|v| !v.is_empty())
                && saved["receipt"]["command_succeeded"] == true
                && saved["receipt"]["observation_validated"] == true
                && saved["model"]["services"]["db-migrate"]["environment"]["MARTY_ORG_ID"]
                    == organization_id.to_string(),
            "completed organization startup required",
        )?;
        Ok(Self {
            installation_id,
            organization_id,
            request_id: uuid(&request_value.request_id, true)?,
            request_sha256: hash(request),
            installation_sha256: request_value.installation_sha256,
            compose_session_sha256: request_value.compose_session_sha256,
            requested_at: DateTime::from_timestamp_micros(
                request_value.created_at.timestamp_micros(),
            )
            .ok_or(BootstrapError("clock refused"))?,
        })
    }

    fn actor(&self) -> String {
        format!("installer:{}", self.installation_id)
    }

    fn name(&self) -> String {
        format!("installer-kms-registration-{}", self.installation_id)
    }

    fn description(&self) -> String {
        format!("Installer KMS registration request {}", self.request_id)
    }

    fn actor_kind(&self) -> ApiKeyActor {
        ApiKeyActor::InstallerBootstrap {
            installation_id: self.installation_id,
        }
    }

    fn fresh(&self, now: DateTime<Utc>) -> Result<()> {
        let age = now.signed_duration_since(self.requested_at);
        need(
            age >= chrono::Duration::zero()
                && age <= chrono::Duration::seconds(REQUEST_LIFETIME_SECONDS),
            "request expired",
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    context: Context,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl Intent {
    fn new(context: &Context, now: DateTime<Utc>) -> Result<Self> {
        // PostgreSQL timestamps retain microseconds. Bind the same precise
        // instant before persistence so recovery compares exact owner records.
        let now = DateTime::from_timestamp_micros(now.timestamp_micros())
            .ok_or(BootstrapError("clock refused"))?;
        context.fresh(now)?;
        let expires_at = now
            .checked_add_signed(chrono::Duration::seconds(INSTALLER_KEY_LIFETIME_SECONDS))
            .ok_or(BootstrapError("clock refused"))?;
        Ok(Self {
            schema: INTENT_SCHEMA.into(),
            context: context.clone(),
            created_at: now,
            expires_at,
        })
    }

    fn validate(&self, context: &Context) -> Result<()> {
        need(
            self.schema == INTENT_SCHEMA
                && &self.context == context
                && self
                    .created_at
                    .timestamp_subsec_nanos()
                    .is_multiple_of(1000)
                && self.expires_at.signed_duration_since(self.created_at)
                    == chrono::Duration::seconds(INSTALLER_KEY_LIFETIME_SECONDS),
            "recorded intent differs",
        )?;
        self.context.fresh(self.created_at)
    }

    fn command(&self) -> CreateApiKeyCommand {
        CreateApiKeyCommand {
            organization_id: self.context.organization_id,
            name: self.context.name(),
            created_by: self.context.actor(),
            scopes: Some(vec!["keys:write".into()]),
            description: Some(self.context.description()),
            is_test: false,
            scope_type: ApiKeyScopeType::Organization,
            deployment_profile_id: None,
            rate_limit: None,
            expires_at: Some(self.expires_at),
            now: self.created_at,
        }
    }

    fn owns(&self, key: &ApiKey) -> bool {
        key.organization_id == self.context.organization_id
            && key.created_by == self.context.actor()
            && key.name == self.context.name()
            && key.description.as_deref() == Some(self.context.description().as_str())
            && key.scopes == ["keys:write"]
            && key.scope_type == ApiKeyScopeType::Organization.as_str()
            && key.deployment_profile_id.is_none()
            && key.rate_limit.is_none()
            && key.expires_at == Some(self.expires_at)
            && key.created_at == self.created_at
    }
}

/// Public metadata only. The raw credential is returned only through KEY_FILE.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    schema: String,
    operation: String,
    installation_id: Uuid,
    organization_id: Uuid,
    request_id: Uuid,
    intent_sha256: String,
    api_key_id: Option<Uuid>,
    scopes: Vec<String>,
    expires_at: DateTime<Utc>,
    revoked: bool,
    automatic_replay_allowed: bool,
}

fn receipt(intent: &Intent, operation: &str, key: Option<Uuid>, revoked: bool) -> Result<Receipt> {
    Ok(Receipt {
        schema: RECEIPT_SCHEMA.into(),
        operation: operation.into(),
        installation_id: intent.context.installation_id,
        organization_id: intent.context.organization_id,
        request_id: intent.context.request_id,
        intent_sha256: hash(&json(intent)?),
        api_key_id: key,
        scopes: vec!["keys:write".into()],
        expires_at: intent.expires_at,
        revoked,
        automatic_replay_allowed: false,
    })
}

fn json(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| BootstrapError("receipt unavailable"))
}

// A narrow application port permits failure-path tests without a second
// persistence, key-generation or authorization implementation.
trait Keys {
    async fn active_organization(&self, organization: Uuid) -> Result<bool>;
    async fn list(&self, organization: Uuid) -> Result<Vec<ApiKey>>;
    async fn create(&self, intent: &Intent) -> Result<ApiKeyCreation>;
    async fn revoke(&self, intent: &Intent, key: Uuid, now: DateTime<Utc>) -> Result<ApiKey>;
}

impl Keys for OrganizationApplication {
    async fn active_organization(&self, organization: Uuid) -> Result<bool> {
        Ok(self
            .get_organization(organization)
            .await
            .map_err(|_| BootstrapError("organization lookup failed"))?
            .is_some_and(|value| value.status == OrganizationStatus::Active))
    }

    async fn list(&self, organization: Uuid) -> Result<Vec<ApiKey>> {
        self.list_api_keys(organization)
            .await
            .map_err(|_| BootstrapError("key lookup failed"))
    }

    async fn create(&self, intent: &Intent) -> Result<ApiKeyCreation> {
        self.create_api_key_as(intent.command(), intent.context.actor_kind())
            .await
            .map(|result| result.value)
            .map_err(|_| BootstrapError("key creation uncertain"))
    }

    async fn revoke(&self, intent: &Intent, key: Uuid, now: DateTime<Utc>) -> Result<ApiKey> {
        self.revoke_api_key_as(
            RevokeApiKeyCommand {
                organization_id: intent.context.organization_id,
                api_key_id: key,
                revoked_by: intent.context.actor(),
                now,
            },
            intent.context.actor_kind(),
        )
        .await
        .map(|result| result.value)
        .map_err(|_| BootstrapError("key revocation uncertain"))
    }
}

fn claims_installation(key: &ApiKey, context: &Context) -> bool {
    key.created_by == context.actor() || key.name == context.name()
}

async fn revoke_owned(keys: &impl Keys, intent: &Intent) -> Result<Option<ApiKey>> {
    let candidates = keys
        .list(intent.context.organization_id)
        .await?
        .into_iter()
        .filter(|key| claims_installation(key, &intent.context))
        .collect::<Vec<_>>();
    need(candidates.len() <= 1, "key identity ambiguous")?;
    let Some(key) = candidates.into_iter().next() else {
        return Ok(None);
    };
    need(intent.owns(&key), "foreign key refused")?;
    if key.status == ApiKeyStatus::Revoked && !key.enabled {
        return Ok(Some(key));
    }
    let revoked = keys.revoke(intent, key.id, Utc::now()).await?;
    need(
        intent.owns(&revoked)
            && revoked.id == key.id
            && revoked.status == ApiKeyStatus::Revoked
            && !revoked.enabled,
        "revocation not confirmed",
    )?;
    Ok(Some(revoked))
}

async fn issue(keys: &impl Keys, output: &files::Output, intent: &Intent) -> Result<Receipt> {
    need(
        keys.active_organization(intent.context.organization_id)
            .await?,
        "existing active organization required",
    )?;
    need(
        !keys
            .list(intent.context.organization_id)
            .await?
            .iter()
            .any(|key| claims_installation(key, &intent.context)),
        "installation already issued",
    )?;
    let mut created_key_id = None;
    let result = async {
        let creation = keys.create(intent).await?;
        need(
            intent.owns(&creation.api_key),
            "created key binding differs",
        )?;
        created_key_id = Some(creation.api_key.id);
        output.write(KEY_FILE, creation.raw_key.as_bytes())?;
        let result = receipt(intent, "issued", Some(creation.api_key.id), false)?;
        output.write("issued.json", &json(&result)?)?;
        Ok(result)
    }
    .await;
    if result.is_err() {
        // Even a lost create response is reconciled by the exact recorded
        // installation/request identity. Never mint a replacement credential.
        let cleanup = revoke_owned(keys, intent).await;
        let key = created_key_id.or_else(|| {
            cleanup
                .as_ref()
                .ok()
                .and_then(|key| key.as_ref())
                .map(|key| key.id)
        });
        let confirmed = cleanup.as_ref().is_ok_and(|key| key.is_some());
        let failure = receipt(intent, "issue_failed", key, confirmed)?;
        output.write("failed.json", &json(&failure)?)?;
        if let Ok(Some(key)) = &cleanup {
            output.remove_key_if_matching(key)?;
        }
        cleanup?;
    }
    result
}

async fn revoke(keys: &impl Keys, output: &files::Output, intent: &Intent) -> Result<Receipt> {
    if let Some(record) = output.optional("issued.json")? {
        let issued: Receipt =
            serde_json::from_slice(&record).map_err(|_| BootstrapError("issue receipt refused"))?;
        let expected = receipt(intent, "issued", issued.api_key_id, false)?;
        need(
            issued == expected && issued.api_key_id.is_some(),
            "issue receipt differs",
        )?;
        let candidates = keys.list(intent.context.organization_id).await?;
        need(
            candidates
                .iter()
                .any(|key| Some(key.id) == issued.api_key_id && intent.owns(key)),
            "recorded key absent or foreign",
        )?;
    }
    let key = revoke_owned(keys, intent).await?;
    let result = receipt(
        intent,
        if key.is_some() {
            "revoked"
        } else {
            "revoke_absent"
        },
        key.as_ref().map(|key| key.id),
        key.is_some(),
    )?;
    // An explicit repeat may reconcile a response lost after normal owner
    // revocation. Never overwrite or replace any durable record.
    record_revoke(output, "revoked.json", &result)?;
    if let Some(key) = key {
        output.remove_key_if_matching(&key)?;
    }
    Ok(result)
}

fn record_revoke(output: &files::Output, name: &str, expected: &Receipt) -> Result<()> {
    if let Some(bytes) = output.optional(name)? {
        let existing: Receipt =
            serde_json::from_slice(&bytes).map_err(|_| BootstrapError("revoke receipt refused"))?;
        need(existing == *expected, "revoke receipt differs")
    } else {
        output.write(name, &json(expected)?)
    }
}

async fn application(
    context: &Context,
    database_url: &str,
) -> Result<(OrganizationApplication, Transaction<'static, Postgres>)> {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(10))
        .connect(database_url)
        .await
        .map_err(|_| BootstrapError("database unavailable"))?;
    let mut lock = pool
        .begin()
        .await
        .map_err(|_| BootstrapError("database unavailable"))?;
    let identity = format!(
        "elevenid.installer-organization:{}:{}",
        context.organization_id, context.installation_id
    );
    let digest = Sha256::digest(identity.as_bytes());
    let lock_id = i64::from_be_bytes(digest[..8].try_into().expect("fixed digest size"));
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(lock_id)
        .fetch_one(&mut *lock)
        .await
        .map_err(|_| BootstrapError("installation key lock unavailable"))?;
    need(locked, "installation key operation active")?;
    let cache = OrganizationCache::new(
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
        Arc::new(MemoryCache::default()),
    );
    let application = OrganizationApplication::new(PostgresOrganizationStore::new(pool), cache)
        .map_err(|_| BootstrapError("application unavailable"))?;
    // Startup already owns schema/outbox initialization and organization
    // identity. This adapter deliberately invokes neither reconciliation nor
    // migrations and never creates a human principal.
    Ok((application, lock))
}

/// Fixed setup-job entrypoint. No environment-selected database, organization,
/// scopes, credential lifetime, actor, output path or network listener exists.
pub async fn run(command: &str) -> Result<Receipt> {
    need(matches!(command, "issue" | "revoke"), "command refused")?;
    let inputs = files::Inputs::load()?;
    let context = Context::read(&inputs.request, &inputs.installation, &inputs.session)?;
    let output = files::Output::open(std::path::Path::new("/output"))?;
    let intent = if command == "issue" {
        output.require_empty()?;
        let intent = Intent::new(&context, Utc::now())?;
        output.write(INTENT_FILE, &json(&intent)?)?;
        intent
    } else {
        let intent: Intent = serde_json::from_slice(&output.read(INTENT_FILE)?)
            .map_err(|_| BootstrapError("recorded intent refused"))?;
        intent.validate(&context)?;
        record_revoke(
            &output,
            "revoke-intent.json",
            &receipt(&intent, "revoke_requested", None, false)?,
        )?;
        intent
    };
    let (application, _lock) = application(&context, &inputs.database_url).await?;
    if command == "issue" {
        issue(&application, &output, &intent).await
    } else {
        revoke(&application, &output, &intent).await
    }
}

#[cfg(test)]
#[path = "installer_bootstrap_tests.rs"]
mod tests;
