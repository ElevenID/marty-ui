//! Register existing AWS KMS keys through the console's public signing registry API.
//! This client owns no provider policy, key lifecycle, registry store, or DID routing.
#![cfg(target_os = "linux")]

use crate::{
    installer_host_fs, installer_json,
    installer_state::{InstallerState, LockedMaintenance, Phase},
    installer_trust,
};
use reqwest::{
    header::{HeaderValue, ETAG, IF_MATCH},
    Method,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Duration,
};

type Result<T> = std::result::Result<T, String>;
const CONFIG_PATH: &str = "/v1/signing-keys/config";
const MAX_BODY: usize = 65536;
const INPUT_REFUSED: &str = "KMS registration input is invalid; use private owned files and existing AWS keys with IAM-role authentication";
pub const USAGE: &str = "usage: marty-deploy kms register --install-dir ABSOLUTE_PATH --organization-id UUID --registration-file ABSOLUTE_PATH --api-key-file ABSOLUTE_PATH";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    id: String,
    name: String,
    service_type: String,
    region: String,
    auth_mode: String,
    key_reference: String,
    algorithms: Vec<String>,
    key_purposes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolutionCheck {
    credential_format: String,
    key_purpose: String,
    algorithm: String,
    expected_service_id: String,
    expected_key_reference: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationPlan {
    services: Vec<Registration>,
    #[serde(default)]
    default_service_id: Option<String>,
    #[serde(default)]
    resolution_checks: Vec<ResolutionCheck>,
}

impl RegistrationPlan {
    fn decode(bytes: &[u8]) -> Result<Self> {
        let plan: Self =
            serde_json::from_value(installer_json::decode(bytes).map_err(|_| INPUT_REFUSED)?)
                .map_err(|_| INPUT_REFUSED)?;
        if plan.services.is_empty() || plan.services.len() > 16 || plan.resolution_checks.len() > 32
        {
            return Err(INPUT_REFUSED.into());
        }
        let mut ids = BTreeSet::new();
        for service in &plan.services {
            if [&service.id, &service.name, &service.key_reference]
                .into_iter()
                .chain(service.algorithms.iter())
                .chain(service.key_purposes.iter())
                .any(|value| value.is_empty() || value.trim() != value.as_str())
                || service.region.trim() != service.region
                || !ids.insert(&service.id)
                || service.service_type != "aws-kms"
                || service.auth_mode != "iam_role"
                || service.algorithms.is_empty()
                || service.key_purposes.is_empty()
                || service.algorithms.iter().collect::<BTreeSet<_>>().len()
                    != service.algorithms.len()
                || service.key_purposes.iter().collect::<BTreeSet<_>>().len()
                    != service.key_purposes.len()
            {
                return Err(INPUT_REFUSED.into());
            }
        }
        if plan
            .default_service_id
            .as_ref()
            .is_some_and(|id| !ids.contains(id))
        {
            return Err(INPUT_REFUSED.into());
        }
        Ok(plan)
    }
}

pub(crate) fn validate_registration(bytes: &[u8]) -> Result<()> {
    RegistrationPlan::decode(bytes).map(|_| ())
}

struct ApiResponse {
    document: Value,
    revision: Option<String>,
}

trait RegistryApi {
    async fn request(
        &mut self,
        method: Method,
        path: &'static str,
        body: Option<&Value>,
        revision: Option<&str>,
    ) -> Result<ApiResponse>;
}

// The existing install writer can lend its lock for first-boot registration.
// Ordinary CLI registration continues to use the maintenance owner. Neither
// path reacquires the installation lock or writes registry persistence itself.
trait RegistrationOwner {
    fn check(&self, installation: &Path) -> Result<()>;
    fn installation_id(&self) -> uuid::Uuid;
    fn record(&mut self, name: &str, bytes: &[u8]) -> Result<()>;
}

impl RegistrationOwner for LockedMaintenance {
    fn check(&self, installation: &Path) -> Result<()> {
        self.inspection().require_path_binding(installation)?;
        self.require_unchanged()
    }
    fn installation_id(&self) -> uuid::Uuid {
        self.journal().installation_id()
    }
    fn record(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        self.write_evidence_exclusive(name, bytes)
    }
}

impl RegistrationOwner for InstallerState {
    fn check(&self, installation: &Path) -> Result<()> {
        self.require_live_phase(Phase::Provisioning)?;
        self.with_inspection(|inspection| inspection.require_path_binding(installation))
    }
    fn installation_id(&self) -> uuid::Uuid {
        self.journal().installation_id()
    }
    fn record(&mut self, name: &str, bytes: &[u8]) -> Result<()> {
        self.write_evidence(name, bytes)
    }
}

struct PublicRegistryApi<'a, Owner> {
    client: reqwest::Client,
    origin: String,
    organization_id: String,
    api_key: HeaderValue,
    installation: &'a Path,
    state: &'a mut Owner,
    operation: String,
    mutation_attempted: bool,
}

impl<'a, Owner: RegistrationOwner> PublicRegistryApi<'a, Owner> {
    fn new(
        installation: &'a Path,
        state: &'a mut Owner,
        trust: installer_trust::TrustInfo,
        organization_id: String,
        credential: &[u8],
    ) -> Result<Self> {
        state.check(installation)?;
        let key = std::str::from_utf8(credential)
            .map_err(|_| INPUT_REFUSED)?
            .trim();
        if key.is_empty()
            || key.len() > 4096
            || key
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err(INPUT_REFUSED.into());
        }
        let mut api_key = HeaderValue::from_str(key).map_err(|_| INPUT_REFUSED)?;
        api_key.set_sensitive(true);
        Ok(Self {
            client: crate::installer_transport::client(&trust, Duration::from_secs(15))?,
            origin: trust.origin,
            organization_id,
            api_key,
            installation,
            state,
            operation: uuid::Uuid::new_v4().to_string(),
            mutation_attempted: false,
        })
    }

    async fn send(
        &self,
        method: Method,
        path: &'static str,
        body: Option<&Value>,
        revision: Option<&str>,
    ) -> Result<reqwest::Response> {
        self.state.check(self.installation)?;
        let mut url = url::Url::parse(&format!("{}{path}", self.origin))
            .map_err(|_| "invalid bound KMS registration origin")?;
        url.query_pairs_mut()
            .append_pair("organization_id", &self.organization_id);
        let mut request = self
            .client
            .request(method, url)
            .header("X-API-Key", self.api_key.clone())
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(revision) = revision {
            request = request.header(IF_MATCH, revision);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|_| "KMS registration request failed; inspect the registry before retrying")?;
        self.state.check(self.installation)?;
        Ok(response)
    }
}

impl<Owner: RegistrationOwner> RegistryApi for PublicRegistryApi<'_, Owner> {
    async fn request(
        &mut self,
        method: Method,
        path: &'static str,
        body: Option<&Value>,
        revision: Option<&str>,
    ) -> Result<ApiResponse> {
        self.state.check(self.installation)?;
        if method == Method::PATCH {
            // Persist intent before the one write. A lost response is never retried automatically.
            self.state.record(
                &format!("kms-registration-{}-intent.json", self.operation),
                &serde_json::to_vec(&json!({
                    "schema":"elevenid.kms-registration-intent/v1", "operation_id":self.operation,
                    "installation_id":self.state.installation_id(),
                    "organization_id":self.organization_id, "registry_revision":revision,
                    "path":CONFIG_PATH, "automatic_retry":false,
                }))
                .map_err(|_| "cannot encode KMS registration intent")?,
            )?;
            self.mutation_attempted = true;
        }
        let mut response = self.send(method, path, body, revision).await?;
        if !response.status().is_success() {
            return Err(match response.status().as_u16() {
                401 | 403 => "KMS registration was not authorized for this organization",
                409 | 412 => "KMS registry changed; no automatic overwrite or retry was attempted",
                _ => "KMS registration API rejected the operation; inspect the registry before retrying",
            }.into());
        }
        let revision = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        if response
            .content_length()
            .is_some_and(|size| size > MAX_BODY as u64)
        {
            return Err("KMS registration response exceeds bounds".into());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| "KMS registration response is incomplete")?
        {
            if bytes.len() + chunk.len() > MAX_BODY {
                return Err("KMS registration response exceeds bounds".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        let document =
            installer_json::decode(&bytes).map_err(|_| "KMS registration response is invalid")?;
        self.state.check(self.installation)?;
        Ok(ApiResponse { document, revision })
    }
}

fn revision(response: &ApiResponse) -> Result<&str> {
    // Gateway may replace a GET ETag for its representation. The public
    // registry's body revision is the canonical CAS value used by the UI.
    let revision = match response.document.get("config_revision") {
        Some(value) => value
            .as_str()
            .ok_or("KMS registry returned an invalid revision")?,
        None => response
            .revision
            .as_deref()
            .ok_or("KMS registry omitted its revision")?,
    };
    let id = revision
        .strip_prefix("\"r-")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or("KMS registry returned an invalid revision")?;
    uuid::Uuid::parse_str(id).map_err(|_| "KMS registry returned an invalid revision")?;
    Ok(revision)
}

fn writable_registry(document: &Value) -> Result<Value> {
    if !document["services"].is_array()
        || document.get("default_service_id").is_none()
        || !(document["default_service_id"].is_null() || document["default_service_id"].is_string())
        || ["type_defaults", "format_defaults", "key_reference_purposes"]
            .iter()
            .any(|name| !document[name].is_object())
    {
        return Err("KMS registry response is incomplete".into());
    }
    let mut ids = BTreeSet::new();
    if document["services"]
        .as_array()
        .unwrap()
        .iter()
        .any(|service| {
            service
                .get("id")
                .and_then(Value::as_str)
                .is_none_or(|id| id.is_empty() || !ids.insert(id))
        })
    {
        return Err("KMS registry response has invalid or duplicate service identities".into());
    }
    let mut registry = serde_json::Map::new();
    for name in [
        "services",
        "default_service_id",
        "type_defaults",
        "format_defaults",
        "key_reference_purposes",
    ] {
        registry.insert(name.into(), document[name].clone());
    }
    Ok(Value::Object(registry))
}

fn matches_registration(stored: &Value, requested: &Value) -> bool {
    requested.as_object().is_some_and(|fields| {
        fields
            .iter()
            .all(|(name, value)| stored.get(name) == Some(value))
    })
}

fn matches_purposes(stored: &Value, requested: &[String]) -> bool {
    // Canonical binding operations may reorder the same purpose membership.
    let Some(stored) = stored.as_array().and_then(|values| {
        values
            .iter()
            .map(Value::as_str)
            .collect::<Option<BTreeSet<_>>>()
    }) else {
        return false;
    };
    stored == requested.iter().map(String::as_str).collect()
}

// This is a client-side additive edit of the same public document the console edits.
// Normalization, credential protection, key policy, and routing stay on the server.
fn add_registrations(current: &Value, plan: &RegistrationPlan) -> Result<(Value, usize)> {
    let mut updated = writable_registry(current)?;
    let mut added = 0;
    for registration in &plan.services {
        let requested = serde_json::to_value(registration).map_err(|_| INPUT_REFUSED)?;
        let services = updated["services"]
            .as_array_mut()
            .ok_or("KMS registry response is incomplete")?;
        let matching = services
            .iter()
            .filter(|service| service["id"] == registration.id)
            .collect::<Vec<_>>();
        if matching.len() > 1 {
            return Err("KMS registry has duplicate service identities".into());
        }
        if let Some(existing) = matching.first() {
            if !matches_registration(existing, &requested)
                || !matches_purposes(
                    &updated["key_reference_purposes"][&registration.id]
                        [&registration.key_reference],
                    &registration.key_purposes,
                )
            {
                return Err("KMS service identity is already registered with different settings; use the console to change it".into());
            }
            continue;
        }
        if updated["key_reference_purposes"]
            .get(&registration.id)
            .is_some()
        {
            return Err(
                "KMS service identity already owns key bindings; no overwrite was attempted".into(),
            );
        }
        updated["services"].as_array_mut().unwrap().push(requested);
        updated["key_reference_purposes"][&registration.id] =
            json!({registration.key_reference.clone():registration.key_purposes});
        added += 1;
    }
    if let Some(default) = &plan.default_service_id {
        if added == 0 && updated["default_service_id"] != *default {
            return Err("KMS services are already registered and defaults have changed; no overwrite was attempted".into());
        }
        updated["default_service_id"] = json!(default);
    } else if added > 0
        && current["services"].as_array().is_some_and(Vec::is_empty)
        && updated["default_service_id"].is_null()
    {
        updated["default_service_id"] = json!(plan.services[0].id);
    }
    Ok((updated, added))
}

fn existing_configuration_preserved(original: &Value, observed: &Value, requested: &Value) -> bool {
    let Some(services) = observed["services"].as_array() else {
        return false;
    };
    original["services"].as_array().is_some_and(|previous| {
        previous.iter().all(|service| {
            services
                .iter()
                .filter(|candidate| candidate["id"] == service["id"])
                .count()
                == 1
                && services.iter().any(|candidate| candidate == service)
        })
    }) && ["type_defaults", "format_defaults"]
        .iter()
        .all(|name| original[name] == observed[name])
        && original["key_reference_purposes"]
            .as_object()
            .is_some_and(|bindings| {
                bindings
                    .iter()
                    .all(|(id, value)| observed["key_reference_purposes"].get(id) == Some(value))
            })
        && observed["default_service_id"] == requested["default_service_id"]
}

async fn register(api: &mut impl RegistryApi, plan: &RegistrationPlan) -> Result<Value> {
    let original = api.request(Method::GET, CONFIG_PATH, None, None).await?;
    let expected_revision = revision(&original)?.to_owned();
    let (requested, added) = add_registrations(&original.document, plan)?;
    for registration in &plan.services {
        // Probe the document that will actually run. Existing registrations may
        // retain runtime settings (for example an endpoint override) beyond the
        // installer's typed attachment input.
        let mut validation = requested["services"]
            .as_array()
            .and_then(|services| {
                services
                    .iter()
                    .find(|service| service["id"] == registration.id)
            })
            .cloned()
            .ok_or("KMS registration omitted its validation target")?;
        validation["live_probe"] = json!(true);
        let result = api
            .request(
                Method::POST,
                "/v1/signing-keys/config/validate",
                Some(&validation),
                None,
            )
            .await?;
        // Older validators could report success after a failed live probe with
        // only warnings. Registration requires an explicit successful live result.
        if result.document["ok"] != true || result.document["basis"] != "live" {
            return Err(
                "Successful live KMS provider validation is required; the registry was not changed"
                    .into(),
            );
        }
    }
    let changed = requested != writable_registry(&original.document)?;
    let original_registry = writable_registry(&original.document)?;
    let saved = if changed {
        api.request(
            Method::PATCH,
            CONFIG_PATH,
            Some(&requested),
            Some(&expected_revision),
        )
        .await?
    } else {
        original
    };
    let saved_revision = revision(&saved)?.to_owned();
    let observed = api.request(Method::GET, CONFIG_PATH, None, None).await?;
    if revision(&observed)? != saved_revision
        || writable_registry(&observed.document)? != writable_registry(&saved.document)?
    {
        return Err(
            "KMS registry changed during registration readback; inspect the current configuration"
                .into(),
        );
    }
    if !existing_configuration_preserved(&original_registry, &observed.document, &requested) {
        return Err(
            "KMS registry readback no longer preserves the observed configuration; inspect the current registry"
                .into(),
        );
    }
    let (_, remaining) = add_registrations(&observed.document, plan)?;
    if remaining != 0
        || (plan.default_service_id.is_some()
            && observed.document["default_service_id"] != requested["default_service_id"])
    {
        return Err(
            "KMS registration readback did not preserve the requested registrations".into(),
        );
    }
    for check in &plan.resolution_checks {
        let request = json!({"credential_format":check.credential_format, "key_purpose":check.key_purpose, "algorithm":check.algorithm});
        let result = api
            .request(
                Method::POST,
                "/v1/signing-keys/config/resolve",
                Some(&request),
                None,
            )
            .await?;
        if result.document["service"]["id"] != check.expected_service_id
            || result.document["service"]["key_reference"] != check.expected_key_reference
        {
            return Err("KMS resolution does not match the requested binding; existing identities were not rebound".into());
        }
    }
    // Resolution probes can overlap another UI edit. Detect it before reporting success.
    if !plan.resolution_checks.is_empty() {
        let after = api.request(Method::GET, CONFIG_PATH, None, None).await?;
        if revision(&after)? != saved_revision {
            return Err("KMS registry changed during resolution checks".into());
        }
    }
    Ok(
        json!({"schema":"elevenid.kms-registration/v1", "registered_services":plan.services.iter().map(|service| &service.id).collect::<Vec<_>>(),
        "added_services":added,"registry_changed":changed,"config_revision":saved_revision,
        "resolution_checks_passed":plan.resolution_checks.len(),"provider_key_mutations":false,"installation_ready":false}),
    )
}

fn private_input(path: &Path) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        return Err(INPUT_REFUSED.into());
    }
    let parent = path.parent().ok_or(INPUT_REFUSED)?;
    let directory = installer_host_fs::directory(parent, INPUT_REFUSED)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(INPUT_REFUSED)?;
    installer_host_fs::read_entry(&directory, name, 0o600, false, INPUT_REFUSED)
}

fn execute(
    installation: &Path,
    state: &mut impl RegistrationOwner,
    trust: installer_trust::TrustInfo,
    organization_id: String,
    registration: RegistrationPlan,
    credential: &[u8],
) -> Result<Value> {
    let mut api = PublicRegistryApi::new(installation, state, trust, organization_id, credential)?;
    let runtime =
        tokio::runtime::Runtime::new().map_err(|_| "KMS registration runtime unavailable")?;
    let result = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(180), register(&mut api, &registration))
            .await
            .map_err(|_| {
                "KMS registration deadline exceeded; inspect the registry before retrying"
                    .to_string()
            })?
    });
    let record = match &result {
        Ok(report) => report.clone(),
        Err(_) => {
            json!({"schema":"elevenid.kms-registration/v1","status":"failed","mutation_attempted":api.mutation_attempted,"automatic_retry":false,"installation_ready":false})
        }
    };
    api.state.record(
        &format!("kms-registration-{}-result.json", api.operation),
        &serde_json::to_vec(&record).map_err(|_| "cannot encode KMS registration result")?,
    )?;
    result
}

/// Fresh first boot lends the existing installation writer. The ordinary
/// Organization startup and pinned application session must already exist.
/// Caller owns issuance and unconditional revocation of the short-lived key.
pub(crate) fn register_locked(
    installation: &Path,
    state: &mut InstallerState,
    organization_id: uuid::Uuid,
    registration: &[u8],
    credential: &[u8],
) -> Result<Value> {
    state.require_live_phase(Phase::Provisioning)?;
    let plan = RegistrationPlan::decode(registration)?;
    let trust = state
        .with_inspection(|inspection| installer_trust::inspect_locked(installation, inspection))?;
    execute(
        installation,
        state,
        trust,
        organization_id.to_string(),
        plan,
        credential,
    )
}

/// Prove revocation through the same pinned public endpoint, including the
/// Gateway's authentication cache. Only bounded read-only observations retry.
pub(crate) fn verify_revoked_locked(
    installation: &Path,
    state: &mut InstallerState,
    organization_id: uuid::Uuid,
    credential: &[u8],
) -> Result<()> {
    let trust = state
        .with_inspection(|inspection| installer_trust::inspect_locked(installation, inspection))?;
    let api = PublicRegistryApi::new(
        installation,
        state,
        trust,
        organization_id.to_string(),
        credential,
    )?;
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|_| "KMS revocation observation runtime unavailable")?;
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), async {
            for attempt in 0..6 {
                let status = api
                    .send(Method::GET, CONFIG_PATH, None, None)
                    .await?
                    .status();
                if status == reqwest::StatusCode::UNAUTHORIZED {
                    return Ok(());
                }
                if !status.is_success() || attempt == 5 {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Err("Installer credential revocation was not observed at the public API".into())
        })
        .await
        .map_err(|_| "Installer credential revocation observation deadline exceeded".to_string())?
    })
}

pub fn run(args: &[String]) -> Result<()> {
    if args == ["--help"] || args == ["register", "--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    if args.len() != 9 || args[0] != "register" {
        return Err(USAGE.into());
    }
    let mut options = std::collections::BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        if ![
            "--install-dir",
            "--organization-id",
            "--registration-file",
            "--api-key-file",
        ]
        .contains(&pair[0].as_str())
            || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err(USAGE.into());
        }
    }
    let organization_id = uuid::Uuid::parse_str(options["--organization-id"])
        .map_err(|_| INPUT_REFUSED)?
        .to_string();
    let installation = PathBuf::from(options["--install-dir"]);
    let registration =
        RegistrationPlan::decode(&private_input(Path::new(options["--registration-file"]))?)?;
    let credential = private_input(Path::new(options["--api-key-file"]))?;
    let mut state = LockedMaintenance::open(&installation)?;
    let trust = installer_trust::inspect_locked(&installation, state.inspection())?;
    let report = execute(
        &installation,
        &mut state,
        trust,
        organization_id,
        registration,
        &credential,
    )?;
    println!(
        "{}",
        serde_json::to_string(&report).map_err(|_| "cannot encode KMS registration result")?
    );
    Ok(())
}

#[cfg(test)]
#[path = "installer_kms_tests.rs"]
mod tests;
