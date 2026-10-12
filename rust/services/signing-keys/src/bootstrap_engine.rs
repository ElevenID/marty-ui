//! Shared bootstrap state machine, independent of live or in-memory adapters.

use std::collections::BTreeMap;

use serde_json::{json, Value};
use thiserror::Error;

use crate::bootstrap::{
    backfill_scoped_did_documents, did_key, issuer_profiles_key, jwks_key, seed_did_and_jwks,
    seed_issuer_profiles, seed_signing_registry, signing_registry_key, KeyRecord, KeySpec,
    FLOW_ENVELOPE_KEY, NOTIFICATION_ENVELOPE_KEY, STANDARD_KEYS,
};
use crate::documents;

pub const DEFAULT_ORG: &str = "00000000-0000-0000-0000-000000000001";
pub const SCHEMAS: &[&str] = &[
    "organization_service",
    "auth_service",
    "credential_template_service",
    "issuance_service",
    "presentation_policy_service",
    "notification_service",
    "device_registration_service",
    "revocation_profile_service",
];

#[derive(Clone, Default)]
pub struct Config {
    pub environment: BTreeMap<String, String>,
    pub verify_only: bool,
}

impl Config {
    pub fn get(&self, name: &str) -> &str {
        self.environment.get(name).map(String::as_str).unwrap_or("")
    }
    pub fn secret(&self, name: &str) -> &str {
        self.get(name)
    }
    pub fn enabled(&self, name: &str) -> bool {
        !matches!(
            self.get(name).trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off" | "disabled"
        )
    }
    pub fn org(&self) -> String {
        let org = self.get("MARTY_ORG_ID").trim();
        if org.is_empty() {
            DEFAULT_ORG.into()
        } else {
            org.into()
        }
    }
    pub fn slug(&self) -> String {
        let configured = self.get("MARTY_ORG_SLUG").trim().to_lowercase();
        let source = if configured.is_empty() {
            "marty"
        } else {
            &configured
        };
        let safe: String = source
            .chars()
            .filter(|ch| ch.is_alphanumeric() || "._-".contains(*ch))
            .collect();
        if safe.is_empty() {
            "marty".into()
        } else {
            safe
        }
    }
    pub fn domain(&self) -> String {
        let configured = self.get("PUBLIC_DOMAIN").trim();
        if !configured.is_empty() {
            return configured
                .split_once("://")
                .map(|(_, tail)| tail.split('/').next().unwrap_or(tail))
                .unwrap_or(configured)
                .trim_matches('/')
                .into();
        }
        for name in ["MARTY_ISSUER_BASE_URL", "ISSUER_BASE_URL", "PUBLIC_API_URL"] {
            let candidate = self.get(name).trim();
            if candidate.is_empty() {
                continue;
            }
            let with_scheme = if candidate.contains("://") {
                candidate.to_string()
            } else {
                format!("https://{candidate}")
            };
            if let Ok(url) = reqwest::Url::parse(&with_scheme) {
                if let Some(host) = url.host_str() {
                    return url
                        .port()
                        .map(|port| format!("{host}:{port}"))
                        .unwrap_or_else(|| host.into());
                }
            }
        }
        "beta.elevenidllc.com".into()
    }
    pub fn did(&self) -> String {
        let configured = self.get("MARTY_ISSUER_DID").trim();
        if !configured.is_empty() {
            return configured.into();
        }
        format!(
            "did:web:{}:orgs:{}",
            self.domain().replace(':', "%3A").replace('/', ":"),
            self.slug()
        )
    }
    pub fn url(&self) -> String {
        let configured = ["MARTY_ISSUER_BASE_URL", "ISSUER_BASE_URL", "PUBLIC_API_URL"]
            .iter()
            .map(|name| self.get(name))
            .find(|value| !value.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("https://{}", self.domain()));
        configured.trim_end_matches('/').into()
    }
    pub fn redis_url(&self) -> Result<Option<String>, String> {
        let configured = self.get("REDIS_URL").trim();
        if configured.is_empty() {
            return Ok(None);
        }
        let mut url = reqwest::Url::parse(configured).map_err(|error| error.to_string())?;
        if url.path().trim_matches('/').parse::<u32>().is_err() {
            let db = self.get("REDIS_DB_GATEWAY").trim();
            url.set_path(&format!("/{}", if db.is_empty() { "2" } else { db }));
        }
        Ok(Some(url.to_string()))
    }
    pub fn disposable(&self, org: &str, did: &str, url: &str) -> Result<Vec<KeySpec>, String> {
        let Some(flag) = self.environment.get("PASSPORT_DISPOSABLE_ICAO_BOOTSTRAP") else {
            return Ok(vec![]);
        };
        if flag != "true" {
            return Err("Disposable ICAO bootstrap flag must be true".into());
        }
        let project = self.get("PASSPORT_ACCEPTANCE_PROJECT");
        let suffix = project
            .strip_prefix("marty-passport-acceptance-base-")
            .or_else(|| project.strip_prefix("marty-passport-acceptance-selfhost-"));
        if !suffix.is_some_and(|suffix| {
            (6..=32).contains(&suffix.len())
                && suffix
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        }) {
            return Err("Disposable ICAO project is invalid".into());
        }
        let port: u16 = self
            .get("PASSPORT_ACCEPTANCE_GATEWAY_PORT")
            .parse()
            .map_err(|_| "Disposable ICAO Gateway port is invalid")?;
        if port < 1024
            || org != DEFAULT_ORG
            || did != format!("did:web:localhost%3A{port}:orgs:marty")
            || url != format!("https://localhost:{port}")
            || self.domain() != format!("localhost:{port}")
        {
            return Err("Disposable ICAO issuer scope is invalid".into());
        }
        let mut specs = vec![];
        for (purpose, format) in [("csca", "mso_mdoc"), ("x509_doc_signer", "icao_emrtd")] {
            let tuple = format!("{DEFAULT_ORG}|{did}|{purpose}|ICAO_EMRTD|ES256");
            let id = format!(
                "cred-dsc-{}-es256",
                &uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, tuple.as_bytes())
                    .simple()
                    .to_string()[..20]
            );
            // A bootstrap invocation creates at most two protected fixture specs.
            let id: &'static str = Box::leak(id.into_boxed_str());
            let name: &'static str =
                Box::leak(format!("Disposable passport {purpose} key").into_boxed_str());
            let purposes: &'static [&'static str] = Box::leak(vec![purpose].into_boxed_slice());
            let formats: &'static [&'static str] = Box::leak(vec![format].into_boxed_slice());
            specs.push(KeySpec {
                id,
                name,
                key_type: "ecdsa-p256",
                algorithm: "ES256",
                purposes,
                formats,
            });
        }
        Ok(specs)
    }
}

#[derive(Debug, Error)]
pub enum RunError {
    #[error("DATABASE_URL environment variable not set")]
    MissingDatabase,
    #[error("Error creating schemas: {0}")]
    Schemas(String),
    #[error("OpenBao address/token are required for webhook secret protection")]
    MissingNotificationKms,
    #[error("Notification webhook KMS preparation failed: {0}")]
    Notification(String),
    #[error("BAO_TOKEN/OPENBAO_SERVICE_TOKEN is not configured")]
    MissingIdentityKms,
    #[error("Failed Marty KMS/DID bootstrap: {0}")]
    Identity(String),
}

#[derive(Clone, Copy)]
pub enum StampKind {
    Registry,
    IssuerDid,
    Jwks,
    SeededProfiles,
}

// The adapter trait is implemented only within this crate; no external trait
// object or Send bound is part of its API.
#[allow(async_fn_in_trait)]
pub trait Backend {
    async fn schemas(&mut self, database_url: &str, schemas: &[&str]) -> Result<(), String>;
    async fn mount(&mut self, address: &str, token: &str) -> Result<(), String>;
    async fn symmetric(
        &mut self,
        address: &str,
        token: &str,
        key: &str,
        description: &str,
    ) -> Result<(), String>;
    async fn ping(&mut self, redis_url: &str) -> Result<(), String>;
    async fn sleep(&mut self, seconds: u64);
    async fn key(
        &mut self,
        address: &str,
        token: &str,
        spec: KeySpec,
        create: bool,
    ) -> Result<KeyRecord, String>;
    async fn load(&mut self, key: &str) -> Result<Option<Value>, String>;
    async fn save(&mut self, key: &str, document: &Value) -> Result<(), String>;
    async fn slug(&mut self, key: &str, org: &str) -> Result<(), String>;
    fn stamp(&mut self, kind: StampKind, document: &mut Value);
}

pub async fn run<B: Backend>(config: &Config, backend: &mut B) -> Result<(), RunError> {
    let database = config.get("DATABASE_URL");
    if database.is_empty() {
        return Err(RunError::MissingDatabase);
    }
    if config.verify_only {
        return Ok(());
    }
    backend
        .schemas(&database.replace("+asyncpg", ""), SCHEMAS)
        .await
        .map_err(RunError::Schemas)?;
    let address = config.get("BAO_ADDR").trim();
    let service_token = config.secret("OPENBAO_SERVICE_TOKEN");
    let dedicated_token = config.secret("BAO_TOKEN");
    let notification_token = if service_token.is_empty() {
        dedicated_token
    } else {
        service_token
    };
    if address.is_empty() || notification_token.is_empty() {
        return Err(RunError::MissingNotificationKms);
    }
    backend
        .mount(address, notification_token)
        .await
        .map_err(RunError::Notification)?;
    backend
        .symmetric(
            address,
            notification_token,
            NOTIFICATION_ENVELOPE_KEY,
            "notification webhook envelope",
        )
        .await
        .map_err(RunError::Notification)?;

    if !config.enabled("MARTY_KMS_BOOTSTRAP_ENABLED") {
        return Ok(());
    }
    let Some(redis_url) = config.redis_url().map_err(RunError::Identity)? else {
        return Ok(());
    };
    if address.is_empty() {
        return Ok(());
    }
    let identity_token = if dedicated_token.is_empty() {
        service_token
    } else {
        dedicated_token
    };
    if identity_token.is_empty() {
        return Err(RunError::MissingIdentityKms);
    }
    for attempt in 1..=5 {
        match backend.ping(&redis_url).await {
            Ok(()) => break,
            Err(error) if attempt == 5 => return Err(RunError::Identity(error)),
            Err(_) => backend.sleep(1).await,
        }
    }
    let org = config.org();
    let did = config.did();
    let url = config.url();
    let disposable = config
        .disposable(&org, &did, &url)
        .map_err(RunError::Identity)?;
    backend
        .mount(address, identity_token)
        .await
        .map_err(RunError::Identity)?;
    backend
        .symmetric(address, identity_token, FLOW_ENVELOPE_KEY, "flow envelope")
        .await
        .map_err(RunError::Identity)?;
    let mut disposable_records = vec![];
    for spec in &disposable {
        disposable_records.push(
            backend
                .key(address, identity_token, *spec, false)
                .await
                .map_err(RunError::Identity)?,
        );
    }
    let mut records = vec![];
    for spec in STANDARD_KEYS {
        records.push(
            backend
                .key(address, identity_token, *spec, true)
                .await
                .map_err(RunError::Identity)?,
        );
    }
    records.extend(disposable_records);

    let registry_key = signing_registry_key(&org);
    let mut registry = seed_signing_registry(
        backend
            .load(&registry_key)
            .await
            .map_err(RunError::Identity)?,
        &org,
        &records,
    )
    .map_err(|error| RunError::Identity(error.to_string()))?;
    backend.stamp(StampKind::Registry, &mut registry);
    backend
        .save(&registry_key, &registry)
        .await
        .map_err(RunError::Identity)?;

    let legacy_key = did_key(&org, None);
    let legacy = backend
        .load(&legacy_key)
        .await
        .map_err(RunError::Identity)?
        .unwrap_or_else(|| json!({}));
    let backfill = backfill_scoped_did_documents(&legacy, &org, |_| None)
        .map_err(|error| RunError::Identity(error.to_string()))?;
    for (key, document) in backfill {
        if let Some(existing) = backend.load(&key).await.map_err(RunError::Identity)? {
            if existing
                .as_object()
                .is_some_and(|object| !object.is_empty())
            {
                if existing["id"] != document["id"] {
                    return Err(RunError::Identity(
                        "Scoped DID document identity does not match its storage key".into(),
                    ));
                }
                continue;
            }
        }
        backend
            .save(&key, &document)
            .await
            .map_err(RunError::Identity)?;
    }
    let scoped_key = did_key(&org, Some(&did));
    let (mut did_doc, mut jwks) = seed_did_and_jwks(
        backend
            .load(&scoped_key)
            .await
            .map_err(RunError::Identity)?,
        &org,
        &did,
        &records,
    );
    backend.stamp(StampKind::IssuerDid, &mut did_doc);
    backend.stamp(StampKind::Jwks, &mut jwks);
    backend
        .save(&scoped_key, &did_doc)
        .await
        .map_err(RunError::Identity)?;
    backend
        .save(&legacy_key, &did_doc)
        .await
        .map_err(RunError::Identity)?;
    backend
        .save(&jwks_key(&org), &jwks)
        .await
        .map_err(RunError::Identity)?;
    if did.starts_with("did:web:") {
        backend
            .slug(&documents::slug_storage_key(&config.slug()), &org)
            .await
            .map_err(RunError::Identity)?;
    }
    let profile_key = issuer_profiles_key(&org);
    let mut profiles = seed_issuer_profiles(
        backend
            .load(&profile_key)
            .await
            .map_err(RunError::Identity)?,
        &org,
        &did,
        &url,
    );
    backend.stamp(StampKind::SeededProfiles, &mut profiles);
    backend
        .save(&profile_key, &profiles)
        .await
        .map_err(RunError::Identity)?;
    Ok(())
}
