//! Canonical signing-service registry normalization and routing decisions.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::Utc;
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use thiserror::Error;
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::domain::{key_purposes, service_capabilities, service_type, service_types};
use crate::kms;
use crate::profiles::ProfileStore;

const SUPPORTED_ALGORITHMS: &[&str] = &["ES256", "ES384", "ES512", "RS256", "EdDSA"];
const MANAGED_OPENBAO_SERVICE_ID: &str = "managed-openbao-transit";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("{0}")]
    Invalid(String),
    #[error("signing registry storage is unavailable: {0}")]
    Storage(String),
    #[error("stored signing registry is malformed: {0}")]
    Corrupt(String),
}

#[derive(Clone)]
struct ManagedInventorySnapshot {
    refreshed_at: Instant,
    keys: Vec<ManagedKey>,
    complete: bool,
    profile_references: BTreeMap<String, bool>,
}

type ManagedInventoryCache = Arc<RwLock<BTreeMap<String, ManagedInventorySnapshot>>>;

#[derive(Clone)]
pub struct RegistryStore {
    connection: ConnectionManager,
    managed_openbao_endpoint: Option<String>,
    managed_inventory: ManagedInventoryCache,
}

impl RegistryStore {
    pub async fn connect(redis_url: &str) -> Result<Self, RegistryError> {
        let client = redis::Client::open(redis_url)
            .map_err(|error| RegistryError::Storage(error.to_string()))?;
        let connection = client
            .get_connection_manager()
            .await
            .map_err(|error| RegistryError::Storage(error.to_string()))?;
        let mut probe = connection.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut probe)
            .await
            .map_err(|error| RegistryError::Storage(error.to_string()))?;
        Ok(Self {
            connection,
            managed_openbao_endpoint: None,
            managed_inventory: Arc::new(RwLock::new(BTreeMap::new())),
        })
    }

    #[must_use]
    pub fn with_managed_openbao(mut self, endpoint: Option<String>) -> Self {
        self.managed_openbao_endpoint = endpoint;
        self
    }

    pub async fn load(&self, organization_id: &str) -> Result<Value, RegistryError> {
        let mut connection = self.connection.clone();
        let payload: Option<String> = connection
            .get(storage_key(organization_id))
            .await
            .map_err(|error| RegistryError::Storage(error.to_string()))?;
        let registry = match payload {
            Some(payload) => {
                let parsed = serde_json::from_str(&payload)
                    .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
                normalize_stored_registry(&parsed)?
            }
            None => empty_registry(),
        };
        Ok(self.with_managed_service(organization_id, registry).await)
    }

    pub async fn save(
        &self,
        organization_id: &str,
        registry: &Value,
    ) -> Result<Value, RegistryError> {
        let normalized = normalize_requested_registry(registry)?;
        let payload = serde_json::to_string(&normalized)
            .map_err(|error| RegistryError::Invalid(error.to_string()))?;
        let mut connection = self.connection.clone();
        connection
            .set::<_, _, ()>(storage_key(organization_id), payload)
            .await
            .map_err(|error| RegistryError::Storage(error.to_string()))?;
        self.managed_inventory.write().await.remove(organization_id);
        Ok(self.with_managed_service(organization_id, normalized).await)
    }

    pub async fn bind_profile(
        &self,
        organization_id: &str,
        profile: &Value,
    ) -> Result<Value, RegistryError> {
        let profile = profile.as_object().ok_or_else(|| {
            RegistryError::Invalid("Issuer profile must be an object.".to_string())
        })?;
        let required = |name: &str| {
            profile
                .get(name)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    RegistryError::Invalid(
                        "Issuer profile has an incomplete KMS purpose binding.".to_string(),
                    )
                })
        };
        let service_id = required("signing_service_id")?;
        let key_reference = required("signing_key_reference")?;
        let key_purpose = required("key_purpose")?;
        if !is_key_purpose(&key_purpose) {
            return Err(RegistryError::Invalid(format!(
                "Invalid key_purpose '{key_purpose}'."
            )));
        }

        let mut registry = self.load(organization_id).await?;
        let bindings = registry
            .as_object_mut()
            .expect("normalized registry object")
            .entry("key_reference_purposes")
            .or_insert_with(|| json!({}));
        let bindings = bindings
            .as_object_mut()
            .expect("normalized registry bindings object");
        let references = bindings
            .entry(service_id.clone())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("normalized service bindings object");
        let purposes = references
            .entry(key_reference)
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("normalized purpose bindings array");
        if !purposes
            .iter()
            .any(|value| value.as_str() == Some(&key_purpose))
        {
            purposes.push(Value::String(key_purpose.clone()));
        }
        purposes.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
        let normalized_bindings = normalize_bindings(registry.get("key_reference_purposes"));
        validate_lti_bindings(&normalized_bindings)?;
        registry["key_reference_purposes"] = json!(normalized_bindings);

        set_default(&mut registry, "type_defaults", &key_purpose, &service_id);
        for format in formats_for_purposes(std::slice::from_ref(&key_purpose)) {
            set_default(&mut registry, "format_defaults", &format, &service_id);
        }
        if registry
            .get("default_service_id")
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            registry["default_service_id"] = Value::String(service_id);
        }
        self.save(organization_id, &registry).await
    }

    pub fn connection(&self) -> ConnectionManager {
        self.connection.clone()
    }

    async fn with_managed_service(&self, organization_id: &str, mut registry: Value) -> Value {
        let Some(endpoint) = self.managed_openbao_endpoint.as_deref() else {
            return registry;
        };
        let profiles = ProfileStore::from_connection(self.connection.clone())
            .list(organization_id)
            .await;
        let profiles_available = profiles.is_ok();
        let profiles = profiles.unwrap_or_else(|_| json!({"profiles": []}));
        let profile_references = active_managed_profile_references(organization_id, &profiles);
        let active_tuple_references = profile_references
            .keys()
            .filter(|reference| issuer_tuple_key_name(reference))
            .cloned()
            .collect::<BTreeSet<_>>();
        let cached = self
            .managed_inventory
            .read()
            .await
            .get(organization_id)
            .cloned();
        let (mut managed_keys, mut inventory_complete) = match cached {
            Some(snapshot)
                if snapshot.refreshed_at.elapsed()
                    < Duration::from_secs(if snapshot.complete { 30 } else { 5 })
                    && (!profiles_available
                        || snapshot.profile_references == profile_references) =>
            {
                (snapshot.keys, snapshot.complete)
            }
            _ => {
                let mut discovered =
                    managed_live_keys(organization_id, &registry, &profile_references, endpoint)
                        .await;
                discovered.1 &= profiles_available;
                self.managed_inventory.write().await.insert(
                    organization_id.to_owned(),
                    ManagedInventorySnapshot {
                        refreshed_at: Instant::now(),
                        keys: discovered.0.clone(),
                        complete: discovered.1,
                        profile_references: profile_references.clone(),
                    },
                );
                discovered
            }
        };
        // Profile mutations do not write the registry. Check the cheap Redis
        // profile document on every load so a cached tuple key stops being
        // selectable as soon as its last active profile is retired or deleted.
        managed_keys.retain(|key| {
            !issuer_tuple_key_name(&key.reference)
                || active_tuple_references.contains(&key.reference)
        });
        inventory_complete &= profiles_available;
        let requested_default = registry
            .get("default_service_id")
            .and_then(Value::as_str)
            .map(str::to_owned);
        {
            let services = registry["services"]
                .as_array_mut()
                .expect("normalized signing registry services");
            services.retain(|service| {
                service.get("id").and_then(Value::as_str) != Some(MANAGED_OPENBAO_SERVICE_ID)
            });
            services.insert(
                0,
                managed_openbao_service(endpoint, &managed_keys, inventory_complete),
            );
        }
        let configured_default = requested_default.as_deref().is_some_and(|id| {
            registry["services"]
                .as_array()
                .expect("normalized signing registry services")
                .iter()
                .any(|service| service.get("id").and_then(Value::as_str) == Some(id))
        });
        if !configured_default {
            registry["default_service_id"] = Value::String(MANAGED_OPENBAO_SERVICE_ID.into());
        }
        registry
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ManagedKey {
    reference: String,
    algorithm: String,
    lti_only: bool,
}

fn tenant_managed_key_name(organization_id: &str, reference: &str) -> bool {
    let tenant = Uuid::new_v5(&Uuid::NAMESPACE_URL, organization_id.as_bytes())
        .simple()
        .to_string();
    ["cred-issuer-", "cred-dsc-", "lti-tool-"]
        .iter()
        .any(|prefix| reference.starts_with(&format!("{prefix}{tenant}-")))
}

fn foreign_namespaced_key(organization_id: &str, reference: &str) -> bool {
    ["cred-issuer-", "cred-dsc-", "lti-tool-"]
        .iter()
        .filter_map(|prefix| reference.strip_prefix(prefix))
        .any(|suffix| {
            suffix.len() > 32
                && suffix.as_bytes().get(32) == Some(&b'-')
                && suffix.as_bytes()[..32].iter().all(u8::is_ascii_hexdigit)
                && !tenant_managed_key_name(organization_id, reference)
        })
}

fn issuer_tuple_key_name(reference: &str) -> bool {
    ["cred-issuer-", "cred-dsc-", "oid4vp-verifier-", "lti-tool-"]
        .iter()
        .filter_map(|prefix| reference.strip_prefix(prefix))
        .any(|suffix| {
            let Some((token, algorithm)) = suffix.split_once('-') else {
                return false;
            };
            token.len() == 20
                && token.bytes().all(|byte| byte.is_ascii_hexdigit())
                && ["es256", "es384", "es512", "rs256", "eddsa"].contains(&algorithm)
        })
}

fn managed_key_algorithm(jwk: &Value) -> Option<&'static str> {
    match (
        jwk.get("kty").and_then(Value::as_str),
        jwk.get("crv").and_then(Value::as_str),
    ) {
        (Some("EC"), Some("P-256")) => Some("ES256"),
        (Some("EC"), Some("P-384")) => Some("ES384"),
        (Some("EC"), Some("P-521")) => Some("ES512"),
        (Some("RSA"), _) => Some("RS256"),
        (Some("OKP"), Some("Ed25519")) => Some("EdDSA"),
        _ => None,
    }
}

async fn managed_live_keys(
    organization_id: &str,
    registry: &Value,
    profile_references: &BTreeMap<String, bool>,
    endpoint: &str,
) -> (Vec<ManagedKey>, bool) {
    let bindings = normalize_bindings(registry.get("key_reference_purposes"))
        .remove(MANAGED_OPENBAO_SERVICE_ID)
        .unwrap_or_default();
    // Profile references were loaded from the tenant-scoped canonical store.
    let mut references = bindings
        .keys()
        .filter(|reference| {
            !foreign_namespaced_key(organization_id, reference)
                && (!issuer_tuple_key_name(reference)
                    || profile_references.contains_key(*reference))
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    references.extend(profile_references.keys().cloned());
    let mut inventory_complete = match kms::list_managed_openbao_key_names(endpoint).await {
        Ok(names) => {
            references.extend(
                names
                    .into_iter()
                    .filter(|name| tenant_managed_key_name(organization_id, name)),
            );
            true
        }
        Err(_) => false,
    };
    let mut pending = references.into_iter();
    let mut tasks = JoinSet::new();
    let queue = |tasks: &mut JoinSet<Result<Option<ManagedKey>, ()>>, reference: String| {
        let endpoint = endpoint.to_owned();
        let lti_only = bindings
            .get(&reference)
            .is_some_and(|purposes| purposes.as_slice() == ["lti_tool_signing"])
            || profile_references.get(&reference) == Some(&true)
            || reference.starts_with("lti-tool-");
        tasks.spawn(async move {
            let public = match kms::managed_openbao_public_key_existing(&endpoint, &reference).await
            {
                Ok(public) => public,
                Err(kms::KmsError::ProviderStatus {
                    status: reqwest::StatusCode::NOT_FOUND,
                    ..
                }) => return Ok(None),
                Err(_) => return Err(()),
            };
            Ok(managed_key_algorithm(&public).map(|algorithm| ManagedKey {
                reference,
                algorithm: algorithm.to_owned(),
                lti_only,
            }))
        });
    };
    for _ in 0..8 {
        if let Some(reference) = pending.next() {
            queue(&mut tasks, reference);
        }
    }
    let mut live = Vec::new();
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(Some(key))) => live.push(key),
            Ok(Ok(None)) => {}
            _ => inventory_complete = false,
        }
        if let Some(reference) = pending.next() {
            queue(&mut tasks, reference);
        }
    }
    live.sort_by(|left, right| left.reference.cmp(&right.reference));
    (live, inventory_complete)
}

fn active_managed_profile_references(
    organization_id: &str,
    profiles: &Value,
) -> BTreeMap<String, bool> {
    let mut references = BTreeMap::new();
    for (reference, lti_only) in profiles
        .get("profiles")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|profile| {
            profile.get("status").and_then(Value::as_str) == Some("active")
                && profile.get("signing_service_id").and_then(Value::as_str)
                    == Some(MANAGED_OPENBAO_SERVICE_ID)
        })
        .filter_map(|profile| {
            Some((
                profile.get("signing_key_reference")?.as_str()?.to_owned(),
                profile.get("key_purpose").and_then(Value::as_str) == Some("lti_tool_signing"),
            ))
        })
        .filter(|(reference, _)| !foreign_namespaced_key(organization_id, reference))
    {
        *references.entry(reference).or_insert(false) |= lti_only;
    }
    references
}

fn managed_openbao_service(endpoint: &str, keys: &[ManagedKey], inventory_complete: bool) -> Value {
    let purposes = key_purposes()
        .into_iter()
        .map(|purpose| purpose.id)
        .collect::<Vec<_>>();
    let default_reference = keys
        .iter()
        .find(|key| !key.lti_only)
        .map(|key| key.reference.as_str())
        .unwrap_or_default();
    let references = keys
        .iter()
        .map(|key| key.reference.as_str())
        .collect::<Vec<_>>();
    let key_algorithms = keys
        .iter()
        .map(|key| (key.reference.as_str(), key.algorithm.as_str()))
        .collect::<BTreeMap<_, _>>();
    json!({
        "id": MANAGED_OPENBAO_SERVICE_ID,
        "name": "Marty managed OpenBao transit",
        "description": "Managed by the Marty service stack.",
        "service_type": "openbao-transit",
        "provider": "openbao",
        "provider_label": "OpenBao Transit",
        "protocol": "vault-transit",
        "category": "service-hsm",
        "endpoint": endpoint,
        "region": "",
        "mount": "transit",
        "namespace": "",
        "auth_mode": "service_token",
        "auth_reference": "Managed by Marty service stack",
        "key_reference": default_reference,
        "key_aliases": references,
        "key_algorithms": key_algorithms,
        "algorithms": SUPPORTED_ALGORITHMS,
        "key_purposes": purposes,
        "credential_formats": ["jwt_vc_json", "dc+sd-jwt", "mso_mdoc", "zk_mdoc", "icao_emrtd", "vds_nc", "oauth-authz-req+jwt", "lti_tool_jwt"],
        "status": if inventory_complete { "configured" } else { "degraded" },
        "managed": true,
        "read_only": true,
        "managed_by": "Marty service stack",
        "key_count": keys.len(),
        "capabilities": {
            "discover_keys": true,
            "sign": true,
            "rotate_keys": false,
            "upload_public_keys": false,
            "delete_keys": false,
            "multiple_key_references": true
        }
    })
}

#[derive(Debug, Clone, Deserialize)]
pub struct SaveRegistryRequest {
    pub registry: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BindProfileRequest {
    pub profile: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NormalizeServiceRequest {
    pub service: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NormalizeServiceResponse {
    pub service: Option<Value>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryMode {
    Requested,
    Stored,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NormalizeRegistryRequest {
    pub registry: Value,
    pub mode: RegistryMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NormalizeRegistryResponse {
    pub registry: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResolveRequest {
    pub registry: Value,
    #[serde(default)]
    pub service: Option<Value>,
    #[serde(default)]
    pub keys: Vec<Value>,
    #[serde(default)]
    pub credential_format: Option<String>,
    #[serde(default)]
    pub key_purpose: Option<String>,
    #[serde(default)]
    pub algorithm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResolveResponse {
    pub service: Option<Value>,
    pub key_reference: Option<String>,
}

pub fn normalize_service(
    request: NormalizeServiceRequest,
) -> Result<NormalizeServiceResponse, RegistryError> {
    Ok(NormalizeServiceResponse {
        service: normalize_service_value(&request.service)?,
    })
}

pub fn normalize_registry(
    request: NormalizeRegistryRequest,
) -> Result<NormalizeRegistryResponse, RegistryError> {
    let registry = match request.mode {
        RegistryMode::Requested => normalize_requested_registry(&request.registry)?,
        RegistryMode::Stored => normalize_stored_registry(&request.registry)?,
    };
    Ok(NormalizeRegistryResponse { registry })
}

pub fn resolve(request: ResolveRequest) -> Result<ResolveResponse, RegistryError> {
    let service = request.service.or_else(|| {
        resolve_service(
            &request.registry,
            request.credential_format.as_deref(),
            request.key_purpose.as_deref(),
            request.algorithm.as_deref(),
        )
    });
    let key_reference = service.as_ref().and_then(|service| {
        resolve_key_reference(
            &request.registry,
            service,
            &request.keys,
            request.key_purpose.as_deref(),
            request.algorithm.as_deref(),
        )
    });
    Ok(ResolveResponse {
        service,
        key_reference,
    })
}

pub fn service_catalog() -> Value {
    json!(service_types())
}

pub fn empty_registry() -> Value {
    json!({
        "services": [],
        "default_service_id": null,
        "format_defaults": {},
        "type_defaults": {},
        "key_reference_purposes": {},
    })
}

pub fn storage_key(organization_id: &str) -> String {
    format!("org:{organization_id}:signing-key-services")
}

fn normalize_service_value(service: &Value) -> Result<Option<Value>, RegistryError> {
    let Some(service) = service.as_object() else {
        return Ok(None);
    };
    let definition = service_type(
        service
            .get("service_type")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    );
    let now = Utc::now().to_rfc3339();
    let key_aliases = dedupe_strings(service.get("key_aliases"));
    let mut algorithms = supported_algorithms(service.get("algorithms"));
    if algorithms.is_empty() && service.get("algorithm").is_some() {
        algorithms = supported_algorithms(Some(&json!([service
            .get("algorithm")
            .cloned()
            .unwrap_or(Value::Null)])));
    }
    let auth_mode = service
        .get("auth_mode")
        .and_then(Value::as_str)
        .filter(|mode| definition.auth_modes.contains(mode))
        .or_else(|| definition.auth_modes.first().copied())
        .unwrap_or("custom");
    let provider = nonblank_string(service.get("provider")).unwrap_or(definition.provider);
    let provider_label = nonblank_string(service.get("provider_label")).unwrap_or(definition.label);
    let created_at = service
        .get("created_at")
        .and_then(Value::as_str)
        .unwrap_or(&now);
    let updated_at = service
        .get("updated_at")
        .and_then(Value::as_str)
        .unwrap_or(&now);

    let purposes = service
        .get("key_purposes")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter(|purpose| is_key_purpose(purpose))
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let credential_formats = match service.get("credential_formats").and_then(Value::as_array) {
        Some(values) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect(),
        None => formats_for_purposes(&purposes),
    };

    let capabilities = service_capabilities()
        .into_iter()
        .find(|capability| capability.service_type_id == definition.id)
        .or_else(|| {
            service_capabilities()
                .into_iter()
                .find(|capability| capability.service_type_id == "custom-transit-compatible")
        })
        .expect("custom provider capabilities");
    let static_capabilities = capabilities.capabilities;
    algorithms.retain(|algorithm| {
        static_capabilities
            .supported_algorithms
            .contains(&algorithm.as_str())
    });
    let rotation_policy = service.get("rotation_policy").and_then(Value::as_object);
    let key_reference_present = service.get("key_reference").is_some_and(truthy);
    let id = service
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("svc-{}", Uuid::new_v4().simple()));

    Ok(Some(json!({
        "id": id,
        "name": nonblank_string(service.get("name")).unwrap_or(definition.label),
        "description": string_or(service.get("description"), ""),
        "service_type": definition.id,
        "provider": provider,
        "provider_label": provider_label,
        "protocol": nonblank_string(service.get("protocol")).unwrap_or(definition.protocol),
        "category": definition.category,
        "endpoint": string_or(service.get("endpoint"), ""),
        "region": string_or(service.get("region"), ""),
        "mount": string_or(service.get("mount"), ""),
        "namespace": string_or(service.get("namespace"), ""),
        "auth_mode": auth_mode,
        "auth_reference": string_or(service.get("auth_reference"), ""),
        "key_reference": string_or(service.get("key_reference"), ""),
        "country_code": string_or(service.get("country_code"), ""),
        "authority_name": string_or(service.get("authority_name"), ""),
        "key_aliases": key_aliases,
        "algorithms": algorithms,
        "status": string_or(service.get("status"), "registered"),
        "managed": false,
        "read_only": false,
        "managed_by": null,
        "key_count": if key_aliases.is_empty() { usize::from(key_reference_present) } else { key_aliases.len() },
        "capabilities": {
            "discover_keys": definition.supports_inventory,
            "sign": true,
            "rotate_keys": static_capabilities.rotation,
            "upload_public_keys": static_capabilities.key_import,
            "delete_keys": static_capabilities.key_delete,
            "multiple_key_references": true,
            "public_key_export": static_capabilities.public_key_export,
            "hardware_attestation": static_capabilities.hardware_attestation,
            "supported_algorithms": static_capabilities.supported_algorithms,
        },
        "signature_encoding": static_capabilities.signature_encoding,
        "key_purposes": purposes,
        "credential_formats": credential_formats,
        "rotation_policy": {
            "rotation_interval_days": integer_or_zero(rotation_policy.and_then(|value| value.get("rotation_interval_days")))?,
            "overlap_days": integer_or_zero(rotation_policy.and_then(|value| value.get("overlap_days")))?,
            "auto_publish": rotation_policy.and_then(|value| value.get("auto_publish")).is_some_and(truthy),
        },
        "rotation_state": object_or_empty(service.get("rotation_state")),
        "created_at": created_at,
        "updated_at": updated_at,
        "discovered_capabilities": object_or_empty(service.get("discovered_capabilities")),
        "cert_pem": optional_string(service.get("cert_pem")),
        "cert_chain_pem": optional_string(service.get("cert_chain_pem")),
        "cert_expires_at": optional_string(service.get("cert_expires_at")),
    })))
}

fn normalize_requested_registry(value: &Value) -> Result<Value, RegistryError> {
    let Some(body) = value.as_object() else {
        return Ok(empty_registry());
    };
    let Some(raw_services) = body.get("services").and_then(Value::as_array) else {
        let mut legacy = normalize_legacy_registry(body)?;
        let bindings = normalize_bindings(body.get("key_reference_purposes"));
        validate_lti_bindings(&bindings)?;
        legacy["key_reference_purposes"] = json!(bindings);
        return Ok(legacy);
    };
    let mut services = Vec::new();
    for service in raw_services {
        let Some(raw) = service.as_object() else {
            continue;
        };
        if raw.get("managed").is_some_and(truthy)
            || raw.get("read_only").is_some_and(truthy)
            || raw.get("id").and_then(Value::as_str) == Some(MANAGED_OPENBAO_SERVICE_ID)
        {
            continue;
        }
        if let Some(service) = normalize_service_value(service)? {
            services.push(service);
        }
    }
    let bindings = normalize_bindings(body.get("key_reference_purposes"));
    validate_lti_bindings(&bindings)?;
    Ok(json!({
        "services": services,
        "default_service_id": optional_string(body.get("default_service_id")),
        "format_defaults": string_map(body.get("format_defaults")),
        "type_defaults": string_map(body.get("type_defaults")),
        "key_reference_purposes": bindings,
    }))
}

fn normalize_stored_registry(value: &Value) -> Result<Value, RegistryError> {
    let Some(body) = value.as_object() else {
        return Ok(empty_registry());
    };
    let mut services = Vec::new();
    if let Some(raw_services) = body.get("services").and_then(Value::as_array) {
        for service in raw_services {
            if let Some(service) = normalize_service_value(service)? {
                services.push(service);
            }
        }
    }
    Ok(json!({
        "services": services,
        "default_service_id": optional_string(body.get("default_service_id")),
        "format_defaults": string_map(body.get("format_defaults")),
        "type_defaults": string_map(body.get("type_defaults")),
        "key_reference_purposes": normalize_bindings(body.get("key_reference_purposes")),
    }))
}

fn normalize_legacy_registry(body: &Map<String, Value>) -> Result<Value, RegistryError> {
    if !body.get("hsm_enabled").is_some_and(truthy) {
        return Ok(empty_registry());
    }
    let Some(settings) = body.get("hsm_settings").and_then(Value::as_object) else {
        return Ok(empty_registry());
    };
    if settings.get("managed_by").is_some_and(truthy) {
        let mut registry = empty_registry();
        registry["default_service_id"] = Value::String(MANAGED_OPENBAO_SERVICE_ID.to_string());
        return Ok(registry);
    }
    let service = json!({
        "name": first_nonempty(&[settings.get("provider_label"), settings.get("provider")]).unwrap_or("Registered KMS/HSM"),
        "service_type": "custom-transit-compatible",
        "provider": nonblank_string(settings.get("provider")).unwrap_or("custom"),
        "protocol": "vault-transit-compatible",
        "endpoint": settings.get("service_url").cloned().unwrap_or(Value::Null),
        "mount": settings.get("mount").cloned().unwrap_or(Value::Null),
        "namespace": settings.get("namespace").cloned().unwrap_or(Value::Null),
        "region": settings.get("region").cloned().unwrap_or(Value::Null),
        "auth_mode": settings.get("auth_mode").cloned().unwrap_or(Value::Null),
        "key_reference": settings.get("key_reference").cloned().unwrap_or(Value::Null),
        "key_aliases": settings.get("signing_key_names").cloned().unwrap_or(Value::Null),
    });
    let Some(normalized) = normalize_service_value(&service)? else {
        return Ok(empty_registry());
    };
    let id = normalized["id"].clone();
    let mut registry = empty_registry();
    registry["services"] = Value::Array(vec![normalized]);
    registry["default_service_id"] = id;
    Ok(registry)
}

fn resolve_service(
    registry: &Value,
    credential_format: Option<&str>,
    key_purpose: Option<&str>,
    algorithm: Option<&str>,
) -> Option<Value> {
    let body = registry.as_object()?;
    let services = body.get("services")?.as_array()?;
    let by_id = |id: Option<&Value>| {
        let id = id.and_then(Value::as_str)?;
        services
            .iter()
            .find(|service| service.get("id").and_then(Value::as_str) == Some(id))
            .cloned()
    };
    let type_defaults = body.get("type_defaults").and_then(Value::as_object);
    for lookup in [credential_format, key_purpose].into_iter().flatten() {
        if let Some(service) = by_id(type_defaults.and_then(|values| values.get(lookup))) {
            return Some(service);
        }
    }
    if let Some(service) = by_id(credential_format.and_then(|format| {
        body.get("format_defaults")
            .and_then(Value::as_object)
            .and_then(|values| values.get(format))
    })) {
        return Some(service);
    }
    if let Some(service) = by_id(body.get("default_service_id")) {
        return Some(service);
    }
    services
        .iter()
        .find(|service| {
            contains_if_set(service.get("credential_formats"), credential_format)
                && contains_if_set(service.get("key_purposes"), key_purpose)
                && contains_if_set(service.get("algorithms"), algorithm)
        })
        .cloned()
}

fn resolve_key_reference(
    registry: &Value,
    service: &Value,
    keys: &[Value],
    key_purpose: Option<&str>,
    algorithm: Option<&str>,
) -> Option<String> {
    let current = service
        .get("key_reference")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let Some(key_purpose) = key_purpose else {
        return current;
    };
    let Some(service_id) = service.get("id").and_then(Value::as_str) else {
        return current;
    };
    let bindings = normalize_bindings(registry.get("key_reference_purposes"));
    let service_bindings = bindings.get(service_id).cloned().unwrap_or_default();
    let mut aliases = dedupe_strings(service.get("key_aliases"))
        .into_iter()
        .collect::<BTreeSet<_>>();
    if let Some(reference) = &current {
        aliases.insert(reference.clone());
    }
    let mut candidates = service_bindings
        .iter()
        .filter(|(reference, purposes)| {
            purposes.iter().any(|purpose| purpose == key_purpose)
                && (aliases.is_empty() || aliases.contains(*reference))
        })
        .map(|(reference, _)| reference.clone())
        .collect::<Vec<_>>();
    if candidates.is_empty() && service_id == MANAGED_OPENBAO_SERVICE_ID {
        candidates = keys
            .iter()
            .filter_map(|key| {
                let reference = key
                    .get("provider_key_name")
                    .or_else(|| key.get("id"))?
                    .as_str()?;
                (managed_key_purposes(reference).contains(&key_purpose)
                    && (aliases.is_empty() || aliases.contains(reference)))
                .then(|| reference.to_string())
            })
            .collect();
    }
    if candidates.is_empty() {
        return if service_bindings.is_empty() {
            current
        } else {
            None
        };
    }
    if let Some(algorithm) = algorithm {
        let algorithms = keys
            .iter()
            .filter_map(|key| {
                let reference = key
                    .get("provider_key_name")
                    .or_else(|| key.get("id"))?
                    .as_str()?;
                Some((reference, key.get("algorithm").and_then(Value::as_str)))
            })
            .collect::<BTreeMap<_, _>>();
        candidates.retain(|reference| {
            algorithms.get(reference.as_str()).copied().flatten() == Some(algorithm)
        });
    }
    if current
        .as_ref()
        .is_some_and(|reference| candidates.contains(reference))
    {
        return current;
    }
    candidates.sort();
    candidates.into_iter().next()
}

fn normalize_bindings(value: Option<&Value>) -> BTreeMap<String, BTreeMap<String, Vec<String>>> {
    let mut normalized = BTreeMap::new();
    let Some(services) = value.and_then(Value::as_object) else {
        return normalized;
    };
    for (raw_service_id, raw_references) in services {
        let service_id = raw_service_id.trim();
        let Some(references) = raw_references.as_object() else {
            continue;
        };
        if service_id.is_empty() {
            continue;
        }
        let mut normalized_references = BTreeMap::new();
        for (raw_reference, raw_purposes) in references {
            let reference = raw_reference.trim();
            if reference.is_empty() {
                continue;
            }
            let purposes = dedupe_strings(Some(raw_purposes))
                .into_iter()
                .filter(|purpose| is_key_purpose(purpose))
                .collect::<Vec<_>>();
            if !purposes.is_empty() {
                normalized_references.insert(reference.to_string(), purposes);
            }
        }
        if !normalized_references.is_empty() {
            normalized.insert(service_id.to_string(), normalized_references);
        }
    }
    normalized
}

fn validate_lti_bindings(
    bindings: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
) -> Result<(), RegistryError> {
    for (service_id, references) in bindings {
        for (reference, purposes) in references {
            if purposes.iter().any(|purpose| purpose == "lti_tool_signing")
                && purposes.as_slice() != ["lti_tool_signing"]
            {
                return Err(RegistryError::Invalid(format!(
                    "Key reference '{reference}' in service '{service_id}' cannot combine lti_tool_signing with credential-signing purposes."
                )));
            }
        }
    }
    Ok(())
}

fn dedupe_strings(value: Option<&Value>) -> Vec<String> {
    let candidates = match value {
        Some(Value::String(value)) => value.split(',').map(Value::from).collect(),
        Some(Value::Array(values)) => values.clone(),
        _ => Vec::new(),
    };
    let mut seen = BTreeSet::new();
    candidates
        .into_iter()
        .filter_map(|value| value.as_str().map(str::trim).map(str::to_string))
        .filter(|value| !value.is_empty() && seen.insert(value.clone()))
        .collect()
}

fn supported_algorithms(value: Option<&Value>) -> Vec<String> {
    dedupe_strings(value)
        .into_iter()
        .filter(|algorithm| SUPPORTED_ALGORITHMS.contains(&algorithm.as_str()))
        .collect()
}

fn formats_for_purposes(purposes: &[String]) -> Vec<String> {
    let definitions = key_purposes();
    let mut formats = Vec::new();
    for purpose in purposes {
        if let Some(definition) = definitions.iter().find(|value| value.id == purpose) {
            for format in definition.credential_formats {
                if !formats.iter().any(|existing| existing == format) {
                    formats.push((*format).to_string());
                }
            }
        }
    }
    formats
}

fn is_key_purpose(value: &str) -> bool {
    key_purposes().iter().any(|purpose| purpose.id == value)
}

pub(crate) fn managed_key_purposes(reference: &str) -> &'static [&'static str] {
    if reference.starts_with("oid4vp-verifier-") {
        &["oid4vp_request_signing"]
    } else if reference.starts_with("lti-tool-") {
        &["lti_tool_signing"]
    } else if reference.starts_with("cred-dsc-") {
        &["mdoc_dsc", "x509_doc_signer", "vdsnc_signing", "csca"]
    } else if reference.starts_with("cred-issuer-") {
        &["vc_jwt_issuer", "jwks_signing"]
    } else {
        &[]
    }
}

fn contains_if_set(value: Option<&Value>, required: Option<&str>) -> bool {
    required.is_none_or(|required| {
        value
            .and_then(Value::as_array)
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(required)))
    })
}

fn string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_string())))
        .collect()
}

fn set_default(registry: &mut Value, field: &str, key: &str, value: &str) {
    let values = registry
        .as_object_mut()
        .expect("normalized registry object")
        .entry(field)
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .expect("normalized registry defaults object");
    values
        .entry(key.to_string())
        .or_insert_with(|| Value::String(value.to_string()));
}

fn string_or<'a>(value: Option<&'a Value>, default: &'a str) -> &'a str {
    value.and_then(Value::as_str).unwrap_or(default)
}

fn optional_string(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

fn nonblank_string(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

fn first_nonempty<'a>(values: &[Option<&'a Value>]) -> Option<&'a str> {
    values.iter().find_map(|value| nonblank_string(*value))
}

fn object_or_empty(value: Option<&Value>) -> Value {
    value
        .and_then(Value::as_object)
        .cloned()
        .map(Value::Object)
        .unwrap_or_else(|| json!({}))
}

fn integer_or_zero(value: Option<&Value>) -> Result<i64, RegistryError> {
    match value {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Bool(value)) => Ok(i64::from(*value)),
        Some(Value::Number(value)) => value
            .as_i64()
            .ok_or_else(|| RegistryError::Invalid("rotation policy must contain integers".into())),
        Some(Value::String(value)) if value.trim().is_empty() => Ok(0),
        Some(Value::String(value)) => value
            .parse::<i64>()
            .map_err(|_| RegistryError::Invalid("rotation policy must contain integers".into())),
        _ => Err(RegistryError::Invalid(
            "rotation policy must contain integers".into(),
        )),
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_i64() != Some(0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{Path, State},
        http::StatusCode,
        routing::get,
        Json, Router,
    };
    use std::sync::{Arc, Mutex};

    static BAO_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[test]
    fn public_config_resolve_frozen_selection_cases() {
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/signing-public-config-resolve-behavior.json"
        ))
        .expect("frozen public resolve contract");
        for case in contract["cases"].as_array().expect("resolve cases") {
            let mut request = case["request"].clone();
            request["registry"] = case["registry"].clone();
            request["keys"] = case["keys"].clone();
            let request: ResolveRequest = serde_json::from_value(request).expect("resolve input");
            let requires_bound_key = request.key_purpose.is_some();
            let resolved = resolve(request).expect("registry resolution");
            if case["expected_status"] == 404 {
                assert!(
                    resolved.service.is_none()
                        || (requires_bound_key && resolved.key_reference.is_none()),
                    "{} must not resolve",
                    case["name"]
                );
                continue;
            }
            assert_eq!(
                resolved.service.as_ref().map(|service| &service["id"]),
                Some(&case["expected_service_id"]),
                "{} service",
                case["name"]
            );
            assert_eq!(
                resolved.key_reference.as_deref(),
                case["expected_key_reference"].as_str(),
                "{} key",
                case["name"]
            );
        }
    }

    #[test]
    fn managed_openbao_accepts_passport_profile_wire_format() {
        let managed = managed_openbao_service("http://openbao:8200", &[], true);
        assert!(managed["credential_formats"]
            .as_array()
            .unwrap()
            .contains(&json!("icao_emrtd")));
        assert!(managed["key_purposes"]
            .as_array()
            .unwrap()
            .contains(&json!("x509_doc_signer")));
    }

    #[test]
    fn managed_service_uses_only_live_public_keys_and_never_defaults_to_lti() {
        let keys = vec![
            ManagedKey {
                reference: "lti-tool-1".into(),
                algorithm: "RS256".into(),
                lti_only: true,
            },
            ManagedKey {
                reference: "cred-issuer-2".into(),
                algorithm: "ES256".into(),
                lti_only: false,
            },
        ];
        let service = managed_openbao_service("http://openbao:8200", &keys, true);
        assert_eq!(service["key_reference"], "cred-issuer-2");
        assert_eq!(
            service["key_aliases"],
            json!(["lti-tool-1", "cred-issuer-2"])
        );
        assert_eq!(service["key_count"], 2);
        assert!(service["algorithms"]
            .as_array()
            .unwrap()
            .contains(&json!("EdDSA")));
        let only_lti = managed_openbao_service("http://openbao:8200", &keys[..1], true);
        assert_eq!(only_lti["key_reference"], "");
    }

    #[test]
    fn managed_key_scope_keeps_legacy_bound_names_but_rejects_foreign_namespaces() {
        let own = format!(
            "cred-issuer-{}-demo-es256",
            Uuid::new_v5(&Uuid::NAMESPACE_URL, b"org-a").simple()
        );
        let foreign = format!(
            "cred-issuer-{}-demo-es256",
            Uuid::new_v5(&Uuid::NAMESPACE_URL, b"org-b").simple()
        );
        assert!(tenant_managed_key_name("org-a", &own));
        assert!(!tenant_managed_key_name("org-a", &foreign));
        assert!(foreign_namespaced_key("org-a", &foreign));
        assert!(!foreign_namespaced_key("org-a", "cred-issuer-legacy-es256"));
        assert!(issuer_tuple_key_name(
            "cred-issuer-0123456789abcdef0123-es256"
        ));
        assert!(issuer_tuple_key_name(
            "oid4vp-verifier-0123456789abcdef0123-eddsa"
        ));
        assert!(!issuer_tuple_key_name(&own));
        assert!(!issuer_tuple_key_name("cred-issuer-legacy-es256"));
        assert_eq!(
            managed_key_algorithm(&json!({"kty":"EC", "crv":"P-384"})),
            Some("ES384")
        );
    }

    #[test]
    fn shared_profile_reference_preserves_lti_only_restriction() {
        let profiles = json!({"profiles": [
            {"status": "active", "signing_service_id": MANAGED_OPENBAO_SERVICE_ID,
                "signing_key_reference": "legacy-shared-key", "key_purpose": "lti_tool_signing"},
            {"status": "active", "signing_service_id": MANAGED_OPENBAO_SERVICE_ID,
                "signing_key_reference": "legacy-shared-key", "key_purpose": "vc_jwt_issuer"}
        ]});
        assert!(active_managed_profile_references("org-a", &profiles)["legacy-shared-key"]);
    }

    #[tokio::test]
    async fn managed_inventory_discards_stale_and_foreign_keys_and_recovers_tenant_key() {
        #[derive(Clone)]
        struct Fixture {
            own: String,
            foreign: String,
            reads: Arc<Mutex<Vec<String>>>,
        }
        async fn list(State(state): State<Fixture>) -> Json<Value> {
            Json(json!({"data": {"keys": [state.own, state.foreign]}}))
        }
        async fn read(
            State(state): State<Fixture>,
            Path(reference): Path<String>,
        ) -> Result<Json<Value>, StatusCode> {
            state.reads.lock().unwrap().push(reference.clone());
            if reference == "a-stale" || reference == state.foreign {
                return Err(StatusCode::NOT_FOUND);
            }
            const PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt\n6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==\n-----END PUBLIC KEY-----\n";
            Ok(Json(json!({"data": {
                "latest_version": 1, "type": "ecdsa-p256",
                "keys": {"1": {"public_key": PEM}}
            }})))
        }
        let own = format!(
            "cred-issuer-{}-unbound-es256",
            Uuid::new_v5(&Uuid::NAMESPACE_URL, b"org-a").simple()
        );
        let foreign = format!(
            "cred-issuer-{}-foreign-es256",
            Uuid::new_v5(&Uuid::NAMESPACE_URL, b"org-b").simple()
        );
        let fixture = Fixture {
            own: own.clone(),
            foreign: foreign.clone(),
            reads: Arc::new(Mutex::new(Vec::new())),
        };
        let app = Router::new()
            .route("/v1/transit/keys", get(list))
            .route("/v1/transit/keys/{reference}", get(read))
            .with_state(fixture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let _guard = BAO_ENV_LOCK.lock().await;
        let previous = std::env::var("BAO_TOKEN").ok();
        std::env::set_var("BAO_TOKEN", "test-only");
        let revoked = "cred-issuer-00000000000000000000-es256";
        let deleted = "cred-dsc-11111111111111111111-es256";
        let registry = json!({"key_reference_purposes": {"managed-openbao-transit": {
            "a-stale": ["vc_jwt_issuer"],
            "cred-issuer-legacy": ["vc_jwt_issuer"],
            revoked: ["vc_jwt_issuer"],
            deleted: ["mdoc_dsc"],
            foreign.clone(): ["vc_jwt_issuer"]
        }}});
        let profile_only = "oid4vp-verifier-01234567890123456789-es256";
        let profiles = json!({"profiles": [
            {
                "status": "active", "signing_service_id": "managed-openbao-transit",
                "signing_key_reference": profile_only,
                "key_purpose": "oid4vp_request_signing"
            },
            {
                "status": "revoked", "signing_service_id": "managed-openbao-transit",
                "signing_key_reference": revoked,
                "key_purpose": "vc_jwt_issuer"
            }
        ]});
        let active = active_managed_profile_references("org-a", &profiles);
        let (keys, complete) = managed_live_keys("org-a", &registry, &active, &endpoint).await;
        match previous {
            Some(value) => std::env::set_var("BAO_TOKEN", value),
            None => std::env::remove_var("BAO_TOKEN"),
        }
        server.abort();
        assert!(complete);
        assert_eq!(
            keys.iter()
                .map(|key| key.reference.as_str())
                .collect::<Vec<_>>(),
            [own.as_str(), "cred-issuer-legacy", profile_only]
        );
        let reads = fixture.reads.lock().unwrap();
        assert!(reads.contains(&"a-stale".into()));
        assert!(!reads.contains(&foreign));
        assert!(!reads.contains(&revoked.to_owned()));
        assert!(!reads.contains(&deleted.to_owned()));
        let service = managed_openbao_service(&endpoint, &keys, complete);
        assert_eq!(service["key_reference"], own);
        assert_eq!(service["key_count"], 3);
        assert!(service["algorithms"]
            .as_array()
            .unwrap()
            .contains(&json!("ES384")));
        let resolved = resolve(ResolveRequest {
            registry: json!({"key_reference_purposes": {}, "services": [service.clone()], "default_service_id": "managed-openbao-transit"}),
            service: Some(service),
            keys: keys.iter().map(|key| json!({"id": key.reference, "algorithm": key.algorithm})).collect(),
            credential_format: None,
            key_purpose: Some("oid4vp_request_signing".into()),
            algorithm: Some("ES256".into()),
        }).unwrap();
        assert_eq!(resolved.key_reference.as_deref(), Some(profile_only));
    }

    #[tokio::test]
    #[ignore = "requires disposable MARTY_TEST_REDIS_URL"]
    async fn cached_managed_inventory_tracks_immediate_profile_create_and_delete() {
        #[derive(Clone)]
        struct Fixture {
            listings: Arc<Mutex<usize>>,
        }
        async fn list(State(state): State<Fixture>) -> Json<Value> {
            *state.listings.lock().unwrap() += 1;
            Json(json!({"data": {"keys": []}}))
        }
        async fn read(Path(_reference): Path<String>) -> Json<Value> {
            const PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaxfR8uEsQkf4vOblY6RA8ncDfYEt\n6zOg9KE5RdiYwpZP40Li/hp/m47n60p8D54WK84zV2sxXs7LtkBoN79R9Q==\n-----END PUBLIC KEY-----\n";
            Json(
                json!({"data": {"latest_version": 1, "type": "ecdsa-p256", "keys": {"1": {"public_key": PEM}}}}),
            )
        }
        let fixture = Fixture {
            listings: Arc::new(Mutex::new(0)),
        };
        let app = Router::new()
            .route("/v1/transit/keys", get(list))
            .route("/v1/transit/keys/{reference}", get(read))
            .with_state(fixture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let _guard = BAO_ENV_LOCK.lock().await;
        let previous = std::env::var("BAO_TOKEN").ok();
        std::env::set_var("BAO_TOKEN", "test-only");
        let redis_url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
        let organization_id = format!("rust-signing-cache-{}", Uuid::new_v4().simple());
        let reference = "cred-issuer-0123456789abcdef0123-es256";
        let store = RegistryStore::connect(&redis_url)
            .await
            .unwrap()
            .with_managed_openbao(Some(endpoint));
        let profiles = ProfileStore::from_connection(store.connection());
        let saved = store.save(&organization_id, &json!({
            "services": [],
            "key_reference_purposes": {"managed-openbao-transit": {reference: ["vc_jwt_issuer"]}}
        })).await.unwrap();
        assert_eq!(saved["services"][0]["key_reference"], "");
        let listings_after_save = *fixture.listings.lock().unwrap();
        assert_eq!(
            store.load(&organization_id).await.unwrap()["services"][0]["key_count"],
            0
        );
        assert_eq!(*fixture.listings.lock().unwrap(), listings_after_save);

        let fixture_profile: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/issuer_profile_vectors.json"
        ))
        .unwrap();
        let mut profile = fixture_profile["normalize"]["expected"].clone();
        profile["organization_id"] = json!(organization_id);
        profile["signing_service_id"] = json!(MANAGED_OPENBAO_SERVICE_ID);
        profile["signing_key_reference"] = json!(reference);
        let profile_id = profile["id"].as_str().unwrap();
        profiles
            .put(&organization_id, profile_id, profile.clone())
            .await
            .unwrap();
        let created = store.load(&organization_id).await.unwrap();
        assert_eq!(created["services"][0]["key_reference"], reference);
        assert_eq!(created["services"][0]["key_count"], 1);
        let listings_after_create = *fixture.listings.lock().unwrap();
        assert!(listings_after_create > listings_after_save);
        profiles.delete(&organization_id, profile_id).await.unwrap();
        let deleted = store.load(&organization_id).await.unwrap();
        assert_eq!(deleted["services"][0]["key_reference"], "");
        assert_eq!(deleted["services"][0]["key_aliases"], json!([]));
        assert_eq!(deleted["services"][0]["key_count"], 0);
        let listings_after_delete = *fixture.listings.lock().unwrap();
        assert!(listings_after_delete > listings_after_create);
        assert_eq!(
            store.load(&organization_id).await.unwrap()["services"][0]["key_count"],
            0
        );
        assert_eq!(*fixture.listings.lock().unwrap(), listings_after_delete);
        let mut connection = store.connection();
        let _: () = redis::cmd("DEL")
            .arg(storage_key(&organization_id))
            .arg(crate::profiles::storage_key(&organization_id))
            .query_async(&mut connection)
            .await
            .unwrap();
        match previous {
            Some(value) => std::env::set_var("BAO_TOKEN", value),
            None => std::env::remove_var("BAO_TOKEN"),
        }
        server.abort();
    }

    #[test]
    fn malformed_service_is_not_silently_registered() {
        assert_eq!(
            normalize_service(NormalizeServiceRequest {
                service: Value::Null
            })
            .unwrap(),
            NormalizeServiceResponse { service: None }
        );
    }

    #[test]
    fn lti_key_reuse_fails_closed() {
        let error = normalize_registry(NormalizeRegistryRequest {
            mode: RegistryMode::Requested,
            registry: json!({
                "services": [],
                "key_reference_purposes": {
                    "service": {"key": ["lti_tool_signing", "vc_jwt_issuer"]}
                }
            }),
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("cannot combine lti_tool_signing"));
    }

    #[test]
    fn storage_key_preserves_the_python_keyspace() {
        assert_eq!(storage_key("org-a"), "org:org-a:signing-key-services");
    }

    #[test]
    fn service_algorithms_follow_the_selected_provider_contract() {
        let aws = normalize_service_value(&json!({
            "service_type": "aws-kms",
            "algorithms": ["ES512"]
        }))
        .unwrap()
        .unwrap();
        assert_eq!(aws["algorithms"], json!(["ES512"]));

        let gcp = normalize_service_value(&json!({
            "service_type": "gcp-cloud-kms",
            "algorithms": ["ES512", "EdDSA"]
        }))
        .unwrap()
        .unwrap();
        assert_eq!(gcp["algorithms"], json!(["EdDSA"]));
    }
}
