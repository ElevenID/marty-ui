//! Canonical signing-service registry normalization and routing decisions.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use uuid::Uuid;

use crate::domain::{key_purposes, service_capabilities, service_type, service_types};
use crate::flow_envelope::OpenBaoEnvelopeProvider;
use crate::integration_secret_envelope::{self, DecryptRequest, EncryptRequest};
use crate::kms;
use crate::profiles::ProfileStore;

const SUPPORTED_ALGORITHMS: &[&str] = &["ES256", "ES384", "ES512", "RS256", "EdDSA"];
pub(crate) const MANAGED_OPENBAO_SERVICE_ID: &str = "managed-openbao-transit";
const ROTATION_LEASE_TTL_MS: u64 = 120_000;
const GLOBAL_ROTATION_FENCE_KEY: &str = "signing-service:global-rotation-fence";

fn rotation_lease_key(organization_id: &str) -> String {
    format!(
        "signing-service:rotation-lease:{}:{}",
        organization_id.len(),
        organization_id
    )
}

fn rotation_marker_key(organization_id: &str, service: &Value) -> Result<String, RegistryError> {
    let identity = transit_identity(
        service,
        service
            .get("key_reference")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;
    let digest = Sha256::digest(serde_json::to_vec(&identity).expect("KMS identity serializes"));
    Ok(format!(
        "signing-service:rotation-reconcile:{}:{}:{digest:x}",
        organization_id.len(),
        organization_id
    ))
}

fn transit_identity(service: &Value, reference: &str) -> Result<Value, RegistryError> {
    let field = |name: &str| {
        service
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    let endpoint = canonical_transit_endpoint(&field("endpoint"))?;
    let key_reference = reference.trim();
    if endpoint.is_empty() || key_reference.is_empty() {
        return Err(RegistryError::Invalid(
            "Transit endpoint and key reference are required for rotation.".into(),
        ));
    }
    Ok(json!({
        "endpoint": endpoint,
        "mount": if field("mount").is_empty() { "transit".into() } else { field("mount").trim_matches('/').to_owned() },
        "namespace": field("namespace"),
        "key_reference": key_reference,
    }))
}

fn canonical_transit_endpoint(endpoint: &str) -> Result<String, RegistryError> {
    let parsed = reqwest::Url::parse(endpoint.trim())
        .map_err(|_| RegistryError::Invalid("Transit endpoint is invalid for rotation".into()))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(RegistryError::Invalid(
            "Transit endpoint is invalid for rotation".into(),
        ));
    }
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

fn rotation_marker_index_key(organization_id: &str, service_id: &str) -> String {
    format!(
        "signing-service:rotation-reconcile-index:{}:{}:{}:{}",
        organization_id.len(),
        organization_id,
        service_id.len(),
        service_id
    )
}

fn preserve_rotation_fields(requested: &mut Value, current: &Value) {
    let Some(services) = requested.get_mut("services").and_then(Value::as_array_mut) else {
        return;
    };
    let current_services = current.get("services").and_then(Value::as_array);
    for service in services {
        let existing = service.get("id").and_then(Value::as_str).and_then(|id| {
            current_services?
                .iter()
                .find(|candidate| candidate.get("id").and_then(Value::as_str) == Some(id))
        });
        let Some(fields) = service.as_object_mut() else {
            continue;
        };
        let same_key = existing.is_some_and(|existing| {
            [
                "service_type",
                "provider",
                "endpoint",
                "mount",
                "namespace",
                "key_reference",
            ]
            .iter()
            .all(|field| fields.get(*field) == existing.get(*field))
        });
        if same_key {
            let existing = existing.expect("same key has a stored service");
            let stale_rotation = fields.get("rotation_state") != existing.get("rotation_state");
            fields.insert(
                "rotation_state".into(),
                existing
                    .get("rotation_state")
                    .cloned()
                    .unwrap_or_else(|| json!({})),
            );
            if stale_rotation {
                for field in ["rotation_policy", "updated_at"] {
                    if let Some(value) = existing.get(field) {
                        fields.insert(field.into(), value.clone());
                    }
                }
            }
        } else {
            fields.insert("rotation_state".into(), json!({}));
        }
    }
}

pub struct RotationLease {
    connection: ConnectionManager,
    key: String,
    owner: String,
    released: bool,
}

impl RotationLease {
    pub(crate) fn covers_organization(&self, organization_id: &str) -> bool {
        self.key == rotation_lease_key(organization_id)
    }

    pub(crate) fn redis_key(&self) -> &str {
        &self.key
    }

    pub(crate) fn owner(&self) -> &str {
        &self.owner
    }

    pub async fn renew(&self) -> Result<bool, RegistryError> {
        let mut connection = self.connection.clone();
        let renewed: i32 = redis::Script::new(
            "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
             return redis.call('PEXPIRE', KEYS[1], ARGV[2])",
        )
        .key(&self.key)
        .arg(&self.owner)
        .arg(ROTATION_LEASE_TTL_MS)
        .invoke_async(&mut connection)
        .await
        .map_err(|error| RegistryError::Storage(error.to_string()))?;
        Ok(renewed == 1)
    }

    pub async fn release(mut self) -> Result<(), RegistryError> {
        release_rotation_lease(&mut self.connection, &self.key, &self.owner).await?;
        self.released = true;
        Ok(())
    }
}

impl Drop for RotationLease {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let mut connection = self.connection.clone();
            let key = self.key.clone();
            let owner = self.owner.clone();
            runtime.spawn(async move {
                let _ = release_rotation_lease(&mut connection, &key, &owner).await;
            });
        }
    }
}

async fn release_rotation_lease(
    connection: &mut ConnectionManager,
    key: &str,
    owner: &str,
) -> Result<(), RegistryError> {
    redis::Script::new(
        "if redis.call('GET', KEYS[1]) == ARGV[1] then
            return redis.call('DEL', KEYS[1])
         end
         return 0",
    )
    .key(key)
    .arg(owner)
    .invoke_async::<i32>(connection)
    .await
    .map_err(|error| RegistryError::Storage(error.to_string()))?;
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("{0}")]
    Invalid(String),
    #[error("signing registry storage is unavailable: {0}")]
    Storage(String),
    #[error("stored signing registry is malformed: {0}")]
    Corrupt(String),
    #[error("signing registry update is in progress for this tenant")]
    Conflict,
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
    auth_envelopes: Option<OpenBaoEnvelopeProvider>,
}

const AUTH_ENVELOPE_FIELD: &str = "auth_reference_envelope";
const AUTH_ENVELOPE_PURPOSE: &str = "signing-service-auth";
pub(crate) const AUTH_CONNECTION_FIELDS: [&str; 8] = [
    "provider",
    "service_type",
    "protocol",
    "endpoint",
    "region",
    "auth_mode",
    "mount",
    "namespace",
];

fn auth_secret_id(service: &Value) -> Result<String, RegistryError> {
    let id = service
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if id.trim().is_empty() {
        return Err(RegistryError::Corrupt("signing service has no ID".into()));
    }
    let binding = std::iter::once(service.get("id").cloned().unwrap_or(Value::Null))
        .chain(
            AUTH_CONNECTION_FIELDS
                .iter()
                .map(|field| service.get(*field).cloned().unwrap_or(Value::Null)),
        )
        .collect::<Vec<_>>();
    let digest = Sha256::digest(
        serde_json::to_vec(&binding)
            .map_err(|_| RegistryError::Corrupt("signing credential binding is invalid".into()))?,
    );
    Ok(format!("signing-service-auth:{digest:x}"))
}

async fn seal_auth_references(
    registry: &Value,
    organization_id: &str,
    provider: Option<&OpenBaoEnvelopeProvider>,
) -> Result<Value, RegistryError> {
    let mut sealed = registry.clone();
    let Some(services) = sealed.get_mut("services").and_then(Value::as_array_mut) else {
        return Ok(sealed);
    };
    for service in services {
        let reference = service
            .get("auth_reference")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if reference.is_empty() {
            continue;
        }
        let provider = provider.ok_or_else(|| {
            RegistryError::Storage("KMS credential envelope is unavailable".into())
        })?;
        let secret_id = auth_secret_id(service)?;
        let service_type = service
            .get("service_type")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let envelope = integration_secret_envelope::encrypt(
            provider,
            EncryptRequest {
                organization_id: organization_id.into(),
                secret_id,
                provider: service_type,
                purpose: AUTH_ENVELOPE_PURPOSE.into(),
                plaintext_b64: STANDARD.encode(reference),
            },
        )
        .await
        .map_err(|_| RegistryError::Storage("KMS credential encryption failed".into()))?;
        service["auth_reference"] = Value::String(String::new());
        service[AUTH_ENVELOPE_FIELD] = envelope;
    }
    Ok(sealed)
}

async fn unseal_auth_references(
    registry: &Value,
    organization_id: &str,
    provider: Option<&OpenBaoEnvelopeProvider>,
) -> Result<Value, RegistryError> {
    let mut unsealed = registry.clone();
    let Some(services) = unsealed.get_mut("services").and_then(Value::as_array_mut) else {
        return Ok(unsealed);
    };
    for service in services {
        if service
            .get("auth_reference")
            .and_then(Value::as_str)
            .is_some_and(|reference| !reference.is_empty())
        {
            return Err(RegistryError::Corrupt(
                "plaintext signing credential is unsupported".into(),
            ));
        }
        let Some(envelope) = service.get(AUTH_ENVELOPE_FIELD).cloned() else {
            continue;
        };
        let provider = provider.ok_or_else(|| {
            RegistryError::Storage("KMS credential envelope is unavailable".into())
        })?;
        let response = integration_secret_envelope::decrypt(
            provider,
            DecryptRequest {
                organization_id: organization_id.into(),
                secret_id: auth_secret_id(service)?,
                provider: service
                    .get("service_type")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .into(),
                purpose: AUTH_ENVELOPE_PURPOSE.into(),
                envelope,
            },
        )
        .await
        .map_err(|_| RegistryError::Storage("KMS credential decryption failed".into()))?;
        let encoded = response
            .get("plaintext_b64")
            .and_then(Value::as_str)
            .ok_or_else(|| RegistryError::Corrupt("signing credential is malformed".into()))?;
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| RegistryError::Corrupt("signing credential is malformed".into()))?;
        let reference = String::from_utf8(bytes)
            .map_err(|_| RegistryError::Corrupt("signing credential is malformed".into()))?;
        service["auth_reference"] = Value::String(reference);
        service
            .as_object_mut()
            .expect("service object")
            .remove(AUTH_ENVELOPE_FIELD);
    }
    Ok(unsealed)
}

impl RegistryStore {
    pub async fn rotation_markers_for_service(
        &self,
        organization_id: &str,
        service_id: &str,
    ) -> Result<Vec<Value>, RegistryError> {
        let mut connection = self.connection.clone();
        let marker_keys: Vec<String> = connection
            .smembers(rotation_marker_index_key(organization_id, service_id))
            .await
            .map_err(|error| RegistryError::Storage(error.to_string()))?;
        let mut markers = Vec::with_capacity(marker_keys.len());
        for marker_key in marker_keys {
            let payload: Option<String> = connection
                .get(marker_key)
                .await
                .map_err(|error| RegistryError::Storage(error.to_string()))?;
            let payload = payload.ok_or_else(|| {
                RegistryError::Corrupt("Rotation marker index has no matching marker".into())
            })?;
            let marker: Value = serde_json::from_str(&payload)
                .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
            if marker["service_id"] != service_id {
                return Err(RegistryError::Corrupt(
                    "Rotation marker index has a different service".into(),
                ));
            }
            markers.push(marker);
        }
        markers.sort_by(|left, right| {
            left["started_at"]
                .as_str()
                .cmp(&right["started_at"].as_str())
        });
        Ok(markers)
    }

    pub async fn rotation_marker(
        &self,
        organization_id: &str,
        service: &Value,
    ) -> Result<Option<Value>, RegistryError> {
        let key = rotation_marker_key(organization_id, service)?;
        let mut connection = self.connection.clone();
        let payload: Option<String> = connection
            .get(key)
            .await
            .map_err(|error| RegistryError::Storage(error.to_string()))?;
        payload
            .map(|payload| {
                serde_json::from_str(&payload)
                    .map_err(|error| RegistryError::Corrupt(error.to_string()))
            })
            .transpose()
    }

    pub async fn create_rotation_marker(
        &self,
        organization_id: &str,
        service: &Value,
        marker: &Value,
        lease: &RotationLease,
    ) -> Result<(), RegistryError> {
        if lease.key != rotation_lease_key(organization_id) {
            return Err(RegistryError::Conflict);
        }
        let key = rotation_marker_key(organization_id, service)?;
        let service_id = marker["service_id"]
            .as_str()
            .ok_or_else(|| RegistryError::Invalid("Rotation marker has no service ID".into()))?;
        let index_key = rotation_marker_index_key(organization_id, service_id);
        let payload = serde_json::to_string(marker)
            .map_err(|error| RegistryError::Invalid(error.to_string()))?;
        let mut connection = self.connection.clone();
        let created: i32 = redis::Script::new(
            "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
             if redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
             local index_type = redis.call('TYPE', KEYS[3]).ok
             if index_type ~= 'none' and index_type ~= 'set' then return 0 end
             redis.call('SADD', KEYS[3], KEYS[2])
             redis.call('SET', KEYS[2], ARGV[2])
             return 1",
        )
        .key(&lease.key)
        .key(key)
        .key(index_key)
        .arg(&lease.owner)
        .arg(payload)
        .invoke_async(&mut connection)
        .await
        .map_err(|error| RegistryError::Storage(error.to_string()))?;
        if created != 1 {
            return Err(RegistryError::Conflict);
        }
        Ok(())
    }

    pub async fn save_pending_rotation_with_marker(
        &self,
        organization_id: &str,
        service: &Value,
        registry: &Value,
        marker: &Value,
        lease: &RotationLease,
    ) -> Result<Value, RegistryError> {
        if lease.key != rotation_lease_key(organization_id) {
            return Err(RegistryError::Conflict);
        }
        let marker_key = rotation_marker_key(organization_id, service)?;
        let service_id = marker["service_id"]
            .as_str()
            .ok_or_else(|| RegistryError::Invalid("Rotation marker has no service ID".into()))?;
        let index_key = rotation_marker_index_key(organization_id, service_id);
        let normalized = normalize_requested_registry(registry)?;
        let registry_payload = serde_json::to_string(&normalized)
            .map_err(|error| RegistryError::Invalid(error.to_string()))?;
        let marker_payload = serde_json::to_string(marker)
            .map_err(|error| RegistryError::Invalid(error.to_string()))?;
        let mut connection = self.connection.clone();
        let saved: i32 = redis::Script::new(
            "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
             if redis.call('GET', KEYS[5]) ~= ARGV[1] then return 0 end
             if redis.call('EXISTS', KEYS[3]) == 1 then return 0 end
             local index_type = redis.call('TYPE', KEYS[4]).ok
             if index_type ~= 'none' and index_type ~= 'set' then return 0 end
             redis.call('SADD', KEYS[4], KEYS[3])
             redis.call('SET', KEYS[3], ARGV[3])
             redis.call('SET', KEYS[2], ARGV[2])
             return 1",
        )
        .key(&lease.key)
        .key(storage_key(organization_id))
        .key(marker_key)
        .key(index_key)
        .key(GLOBAL_ROTATION_FENCE_KEY)
        .arg(&lease.owner)
        .arg(registry_payload)
        .arg(marker_payload)
        .invoke_async(&mut connection)
        .await
        .map_err(|error| RegistryError::Storage(error.to_string()))?;
        if saved != 1 {
            return Err(RegistryError::Conflict);
        }
        self.managed_inventory.write().await.remove(organization_id);
        Ok(normalized)
    }

    pub async fn clear_rotation_marker(
        &self,
        organization_id: &str,
        service: &Value,
        marker: &Value,
        lease: &RotationLease,
    ) -> Result<(), RegistryError> {
        if lease.key != rotation_lease_key(organization_id) {
            return Err(RegistryError::Conflict);
        }
        let key = rotation_marker_key(organization_id, service)?;
        let service_id = marker["service_id"]
            .as_str()
            .ok_or_else(|| RegistryError::Invalid("Rotation marker has no service ID".into()))?;
        let index_key = rotation_marker_index_key(organization_id, service_id);
        let payload = serde_json::to_string(marker)
            .map_err(|error| RegistryError::Invalid(error.to_string()))?;
        let mut connection = self.connection.clone();
        let cleared: i32 = redis::Script::new(
            "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
             if redis.call('GET', KEYS[2]) ~= ARGV[2] then return 0 end
             if redis.call('TYPE', KEYS[3]).ok ~= 'set' then return 0 end
             if redis.call('SISMEMBER', KEYS[3], KEYS[2]) ~= 1 then return 0 end
             redis.call('DEL', KEYS[2])
             redis.call('SREM', KEYS[3], KEYS[2])
             return 1",
        )
        .key(&lease.key)
        .key(key)
        .key(index_key)
        .arg(&lease.owner)
        .arg(payload)
        .invoke_async(&mut connection)
        .await
        .map_err(|error| RegistryError::Storage(error.to_string()))?;
        if cleared != 1 {
            return Err(RegistryError::Conflict);
        }
        Ok(())
    }
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
            auth_envelopes: None,
        })
    }

    #[must_use]
    pub fn with_managed_openbao(mut self, endpoint: Option<String>) -> Self {
        self.managed_openbao_endpoint = endpoint;
        self
    }

    #[must_use]
    pub fn with_auth_envelopes(mut self, provider: Option<OpenBaoEnvelopeProvider>) -> Self {
        self.auth_envelopes = provider;
        self
    }

    pub async fn acquire_rotation_lease(
        &self,
        organization_id: &str,
    ) -> Result<Option<RotationLease>, RegistryError> {
        let key = rotation_lease_key(organization_id);
        let owner = Uuid::new_v4().to_string();
        let mut connection = self.connection.clone();
        let acquired: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(&owner)
            .arg("NX")
            .arg("PX")
            .arg(ROTATION_LEASE_TTL_MS)
            .query_async(&mut connection)
            .await
            .map_err(|error| RegistryError::Storage(error.to_string()))?;
        Ok(acquired.map(|_| RotationLease {
            connection,
            key,
            owner,
            released: false,
        }))
    }

    /// Freeze all registry writes while checking whether a physical Transit key
    /// is used by another tenant and rotating it. The owner may still persist
    /// its pending and completed rotation state through the fenced save scripts.
    pub async fn acquire_global_rotation_fence(
        &self,
        tenant_lease: &RotationLease,
    ) -> Result<Option<RotationLease>, RegistryError> {
        let mut connection = self.connection.clone();
        let acquired: Option<String> = redis::cmd("SET")
            .arg(GLOBAL_ROTATION_FENCE_KEY)
            .arg(&tenant_lease.owner)
            .arg("NX")
            .arg("PX")
            .arg(ROTATION_LEASE_TTL_MS)
            .query_async(&mut connection)
            .await
            .map_err(|error| RegistryError::Storage(error.to_string()))?;
        Ok(acquired.map(|_| RotationLease {
            connection,
            key: GLOBAL_ROTATION_FENCE_KEY.to_owned(),
            owner: tenant_lease.owner.clone(),
            released: false,
        }))
    }

    /// Called only while the global fence is held. Existing registry documents
    /// predate this route, so inspect them rather than trusting a new index.
    pub async fn ensure_exclusive_rotation_identity(
        &self,
        organization_id: &str,
        service: &Value,
        fence: &RotationLease,
    ) -> Result<(), RegistryError> {
        if fence.key != GLOBAL_ROTATION_FENCE_KEY {
            return Err(RegistryError::Conflict);
        }
        if service.get("auth_mode").and_then(Value::as_str) == Some("service_token") {
            return Err(RegistryError::Conflict);
        }
        if self
            .managed_openbao_endpoint
            .as_deref()
            .is_some_and(|managed| {
                canonical_transit_endpoint(managed).ok()
                    == canonical_transit_endpoint(
                        service
                            .get("endpoint")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    )
                    .ok()
                    && service
                        .get("mount")
                        .and_then(Value::as_str)
                        .unwrap_or("transit")
                        .trim_matches('/')
                        == "transit"
                    && service
                        .get("namespace")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .trim()
                        .is_empty()
            })
        {
            return Err(RegistryError::Conflict);
        }
        let identity = transit_identity(
            service,
            service
                .get("key_reference")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )?;
        let mut connection = self.connection.clone();
        let owner: Option<String> = connection
            .get(GLOBAL_ROTATION_FENCE_KEY)
            .await
            .map_err(|error| RegistryError::Storage(error.to_string()))?;
        if owner.as_deref() != Some(fence.owner.as_str()) {
            return Err(RegistryError::Conflict);
        }
        let mut cursor = 0_u64;
        let mut scanned = 0_usize;
        loop {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg("org:*:signing-key-services")
                .arg("COUNT")
                .arg(100)
                .query_async(&mut connection)
                .await
                .map_err(|error| RegistryError::Storage(error.to_string()))?;
            scanned += keys.len();
            if scanned > 100_000 {
                return Err(RegistryError::Storage(
                    "Rotation ownership scan exceeded its limit".into(),
                ));
            }
            for key in keys {
                let other = key
                    .strip_prefix("org:")
                    .and_then(|suffix| suffix.strip_suffix(":signing-key-services"))
                    .ok_or_else(|| RegistryError::Corrupt("Invalid signing registry key".into()))?;
                if other == organization_id {
                    continue;
                }
                let payload: Option<String> = connection
                    .get(&key)
                    .await
                    .map_err(|error| RegistryError::Storage(error.to_string()))?;
                let Some(payload) = payload else { continue };
                let registry: Value = serde_json::from_str(&payload)
                    .map_err(|error| RegistryError::Corrupt(error.to_string()))?;
                for registered in registry
                    .get("services")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if !matches!(
                        registered.get("service_type").and_then(Value::as_str),
                        Some(
                            "openbao-transit"
                                | "hashicorp-vault-transit"
                                | "custom-transit-compatible"
                        )
                    ) {
                        continue;
                    }
                    let references = registered
                        .get("key_reference")
                        .and_then(Value::as_str)
                        .into_iter()
                        .chain(
                            registered
                                .get("key_aliases")
                                .and_then(Value::as_array)
                                .into_iter()
                                .flatten()
                                .filter_map(Value::as_str),
                        );
                    for reference in references {
                        if transit_identity(registered, reference).ok().as_ref() == Some(&identity)
                        {
                            return Err(RegistryError::Conflict);
                        }
                    }
                }
            }
            if next == 0 {
                break;
            }
            cursor = next;
        }
        Ok(())
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
                let unsealed =
                    unseal_auth_references(&parsed, organization_id, self.auth_envelopes.as_ref())
                        .await?;
                normalize_stored_registry(&unsealed)?
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
        let lease = self
            .acquire_rotation_lease(organization_id)
            .await?
            .ok_or(RegistryError::Conflict)?;
        let existing = self.load(organization_id).await?;
        let saved = self
            .save_requested_with_rotation_lease(organization_id, registry, &existing, &lease)
            .await;
        let _ = lease.release().await;
        let normalized = saved?;
        Ok(self.with_managed_service(organization_id, normalized).await)
    }

    pub async fn save_requested_with_rotation_lease(
        &self,
        organization_id: &str,
        requested: &Value,
        existing: &Value,
        lease: &RotationLease,
    ) -> Result<Value, RegistryError> {
        let mut merged = normalize_requested_registry(requested)?;
        preserve_rotation_fields(&mut merged, existing);
        self.save_with_rotation_lease(organization_id, &merged, lease)
            .await
    }

    pub async fn save_with_rotation_lease(
        &self,
        organization_id: &str,
        registry: &Value,
        lease: &RotationLease,
    ) -> Result<Value, RegistryError> {
        if lease.key != rotation_lease_key(organization_id) {
            return Err(RegistryError::Conflict);
        }
        let normalized = normalize_requested_registry(registry)?;
        let sealed =
            seal_auth_references(&normalized, organization_id, self.auth_envelopes.as_ref())
                .await?;
        let payload = serde_json::to_string(&sealed)
            .map_err(|error| RegistryError::Invalid(error.to_string()))?;
        let mut connection = self.connection.clone();
        let saved: i32 = redis::Script::new(
            "if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
             local fence = redis.call('GET', KEYS[3])
             if fence and fence ~= ARGV[1] then return 0 end
             redis.call('SET', KEYS[2], ARGV[2])
             return 1",
        )
        .key(&lease.key)
        .key(storage_key(organization_id))
        .key(GLOBAL_ROTATION_FENCE_KEY)
        .arg(&lease.owner)
        .arg(payload)
        .invoke_async(&mut connection)
        .await
        .map_err(|error| RegistryError::Storage(error.to_string()))?;
        if saved != 1 {
            return Err(RegistryError::Conflict);
        }
        self.managed_inventory.write().await.remove(organization_id);
        Ok(normalized)
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
        self.bind_reference_purpose(
            organization_id,
            &service_id,
            &key_reference,
            &key_purpose,
            true,
        )
        .await
    }

    /// Bind a managed key to its purpose without changing organization service defaults.
    pub async fn bind_key_purpose(
        &self,
        organization_id: &str,
        service_id: &str,
        key_reference: &str,
        key_purpose: &str,
    ) -> Result<Value, RegistryError> {
        self.bind_reference_purpose(
            organization_id,
            service_id,
            key_reference,
            key_purpose,
            false,
        )
        .await
    }

    async fn bind_reference_purpose(
        &self,
        organization_id: &str,
        service_id: &str,
        key_reference: &str,
        key_purpose: &str,
        set_defaults: bool,
    ) -> Result<Value, RegistryError> {
        if service_id.trim().is_empty() || key_reference.trim().is_empty() {
            return Err(RegistryError::Invalid(
                "Incomplete KMS purpose binding.".into(),
            ));
        }
        if !is_key_purpose(key_purpose) {
            return Err(RegistryError::Invalid(format!(
                "Invalid key_purpose '{key_purpose}'."
            )));
        }

        // Every whole-registry writer shares this lease. Retry briefly so two
        // successful KMS creates can both persist their independent bindings.
        let lease = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                if let Some(lease) = self.acquire_rotation_lease(organization_id).await? {
                    break Ok::<_, RegistryError>(lease);
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .map_err(|_| RegistryError::Conflict)??;
        let result = async {
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
                .entry(service_id.to_owned())
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .expect("normalized service bindings object");
            let purposes = references
                .entry(key_reference.to_owned())
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .expect("normalized purpose bindings array");
            if !purposes
                .iter()
                .any(|value| value.as_str() == Some(key_purpose))
            {
                purposes.push(Value::String(key_purpose.to_owned()));
            }
            purposes.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
            let normalized_bindings = normalize_bindings(registry.get("key_reference_purposes"));
            validate_lti_bindings(&normalized_bindings)?;
            registry["key_reference_purposes"] = json!(normalized_bindings);

            if set_defaults {
                set_default(&mut registry, "type_defaults", key_purpose, service_id);
                for format in formats_for_purposes(&[key_purpose.to_owned()]) {
                    set_default(&mut registry, "format_defaults", &format, service_id);
                }
                if registry
                    .get("default_service_id")
                    .and_then(Value::as_str)
                    .is_none_or(|value| value.trim().is_empty())
                {
                    registry["default_service_id"] = Value::String(service_id.to_owned());
                }
            }
            self.save_with_rotation_lease(organization_id, &registry, &lease)
                .await
        }
        .await;
        let release = lease.release().await;
        let normalized = result?;
        release?;
        Ok(self.with_managed_service(organization_id, normalized).await)
    }

    pub fn connection(&self) -> ConnectionManager {
        self.connection.clone()
    }

    pub async fn with_managed_service(&self, organization_id: &str, mut registry: Value) -> Value {
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

pub(crate) fn tenant_managed_key_name(organization_id: &str, reference: &str) -> bool {
    let tenant = Uuid::new_v5(&Uuid::NAMESPACE_URL, organization_id.as_bytes())
        .simple()
        .to_string();
    crate::domain::MANAGED_KEY_PREFIXES
        .iter()
        .any(|prefix| reference.starts_with(&format!("{prefix}{tenant}-")))
}

pub(crate) fn managed_key_reference_for_fields(
    organization_id: &str,
    issuer_did: &str,
    key_purpose: &str,
    credential_format: &str,
    algorithm: &str,
) -> String {
    let tuple =
        format!("{organization_id}|{issuer_did}|{key_purpose}|{credential_format}|{algorithm}");
    let token = Uuid::new_v5(&Uuid::NAMESPACE_URL, tuple.as_bytes())
        .simple()
        .to_string();
    let prefix =
        crate::domain::managed_key_prefix_for_purpose(key_purpose).unwrap_or("cred-issuer-");
    format!(
        "{prefix}{}-{}",
        &token[..20],
        algorithm.to_ascii_lowercase()
    )
}

pub(crate) fn managed_profile_key_belongs_to_tenant(
    organization_id: &str,
    profile: &Value,
    reference: &str,
) -> bool {
    if profile.get("organization_id").and_then(Value::as_str) != Some(organization_id) {
        return false;
    }
    let Some(key_purpose) = profile.get("key_purpose").and_then(Value::as_str) else {
        return false;
    };
    if !managed_key_purposes(reference).contains(&key_purpose) {
        return false;
    }
    if tenant_managed_key_name(organization_id, reference) {
        return true;
    }
    let (Some(issuer_did), Some(credential_format), Some(algorithm)) = (
        profile.get("issuer_did").and_then(Value::as_str),
        profile.get("credential_format").and_then(Value::as_str),
        profile.get("algorithm").and_then(Value::as_str),
    ) else {
        return false;
    };
    managed_key_reference_for_fields(
        organization_id,
        issuer_did,
        key_purpose,
        credential_format,
        algorithm,
    ) == reference
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
            tenant_managed_key_name(organization_id, reference)
                || profile_references.contains_key(*reference)
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
            let metadata = match kms::managed_openbao_metadata_existing(&endpoint, &reference).await
            {
                Ok(metadata) => metadata,
                Err(kms::KmsError::ProviderStatus {
                    status: reqwest::StatusCode::NOT_FOUND,
                    ..
                }) => return Ok(None),
                Err(_) => return Err(()),
            };
            if metadata.get("status").and_then(Value::as_str) != Some("active") {
                return Err(());
            }
            let public = metadata.get("public_jwk").ok_or(())?;
            Ok(
                kms::managed_public_key_algorithm(public).map(|algorithm| ManagedKey {
                    reference,
                    algorithm: algorithm.to_owned(),
                    lti_only,
                }),
            )
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
            let reference = profile.get("signing_key_reference")?.as_str()?;
            managed_profile_key_belongs_to_tenant(organization_id, profile, reference).then(|| {
                (
                    reference.to_owned(),
                    profile.get("key_purpose").and_then(Value::as_str) == Some("lti_tool_signing"),
                )
            })
        })
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
    let lti_only_references = keys
        .iter()
        .filter(|key| key.lti_only)
        .map(|key| key.reference.as_str())
        .collect::<Vec<_>>();
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
        "lti_only_references": lti_only_references,
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
    if service.get("auth_mode").and_then(Value::as_str) == Some("service_token") {
        return Err(RegistryError::Invalid(
            "Only the managed OpenBao service may use the mounted service token.".into(),
        ));
    }
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
    if crate::private_material::contains_private_key(value) {
        return Err(RegistryError::Invalid(
            "signing configuration must not include private key material".into(),
        ));
    }
    let Some(body) = value.as_object() else {
        return Ok(empty_registry());
    };
    reject_legacy_registry_fields(body)?;
    let Some(raw_services) = body.get("services").and_then(Value::as_array) else {
        let mut registry = empty_registry();
        let bindings = normalize_bindings(body.get("key_reference_purposes"));
        validate_lti_bindings(&bindings)?;
        registry["key_reference_purposes"] = json!(bindings);
        return Ok(registry);
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
    reject_legacy_registry_fields(body)?;
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

fn reject_legacy_registry_fields(body: &Map<String, Value>) -> Result<(), RegistryError> {
    if [
        "hsm_enabled",
        "hsm_settings",
        "vault_enabled",
        "vault_settings",
    ]
    .iter()
    .any(|field| body.contains_key(*field))
    {
        return Err(RegistryError::Invalid(
            "legacy flat key-management configuration is unsupported; use services".into(),
        ));
    }
    Ok(())
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
        let Some(algorithm) = algorithm else {
            return current;
        };
        let service_id = service.get("id").and_then(Value::as_str)?;
        let lti_only_references = dedupe_strings(service.get("lti_only_references"))
            .into_iter()
            .collect::<BTreeSet<_>>();
        let bindings = normalize_bindings(registry.get("key_reference_purposes"));
        let service_bindings = bindings.get(service_id);
        let mut references = dedupe_strings(service.get("key_aliases"))
            .into_iter()
            .collect::<BTreeSet<_>>();
        if let Some(reference) = &current {
            references.insert(reference.clone());
        }
        if service_id != MANAGED_OPENBAO_SERVICE_ID {
            if let Some(bound) = service_bindings {
                references.extend(bound.keys().cloned());
            }
        }
        let mut candidates = keys
            .iter()
            .filter(|key| key.get("algorithm").and_then(Value::as_str) == Some(algorithm))
            .filter_map(|key| {
                let reference = key
                    .get("provider_key_name")
                    .or_else(|| key.get("id"))
                    .and_then(Value::as_str)
                    .filter(|reference| references.contains(*reference))?;
                if key
                    .get("service_id")
                    .and_then(Value::as_str)
                    .is_some_and(|key_service_id| key_service_id != service_id)
                {
                    return None;
                }
                if service_bindings
                    .and_then(|bound| bound.get(reference))
                    .is_some_and(|purposes| purposes.as_slice() == ["lti_tool_signing"])
                    || lti_only_references.contains(reference)
                    || (service_id == MANAGED_OPENBAO_SERVICE_ID
                        && managed_key_purposes(reference) == ["lti_tool_signing"])
                {
                    return None;
                }
                Some(reference.to_owned())
            })
            .collect::<Vec<_>>();
        if current
            .as_ref()
            .is_some_and(|reference| candidates.contains(reference))
        {
            return current;
        }
        candidates.sort();
        return candidates.into_iter().next();
    };
    let Some(service_id) = service.get("id").and_then(Value::as_str) else {
        return current;
    };
    let bindings = normalize_bindings(registry.get("key_reference_purposes"));
    let service_bindings = bindings.get(service_id).cloned().unwrap_or_default();
    let lti_only_references = dedupe_strings(service.get("lti_only_references"))
        .into_iter()
        .collect::<BTreeSet<_>>();
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
                && (key_purpose == "lti_tool_signing" || !lti_only_references.contains(*reference))
                && (service_id != MANAGED_OPENBAO_SERVICE_ID
                    || managed_key_purposes(reference).is_empty()
                    || managed_key_purposes(reference).contains(&key_purpose))
                && (aliases.contains(*reference)
                    || (service_id != MANAGED_OPENBAO_SERVICE_ID && aliases.is_empty()))
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
                ((managed_key_purposes(reference).contains(&key_purpose)
                    || (key_purpose == "lti_tool_signing"
                        && lti_only_references.contains(reference)))
                    && (key_purpose == "lti_tool_signing"
                        || !lti_only_references.contains(reference))
                    && aliases.contains(reference))
                .then(|| reference.to_string())
            })
            .collect();
    }
    if candidates.is_empty() {
        if service_id == MANAGED_OPENBAO_SERVICE_ID {
            return None;
        }
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
    crate::domain::managed_key_purposes(reference)
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
        routing::{get, post},
        Json, Router,
    };
    use std::sync::{Arc, Mutex};

    static BAO_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn signing_credentials_are_sealed_and_bound_to_tenant_and_service() {
        #[derive(Clone, Default)]
        struct Fixture(Arc<Mutex<String>>);
        async fn key_metadata() -> Json<Value> {
            Json(json!({"data": {
                "type": "aes256-gcm96", "exportable": false,
                "allow_plaintext_backup": false
            }}))
        }
        async fn encrypt(State(fixture): State<Fixture>, Json(body): Json<Value>) -> Json<Value> {
            *fixture.0.lock().unwrap() = body["plaintext"].as_str().unwrap().into();
            Json(json!({"data": {"ciphertext": "vault:v1:fixture"}}))
        }
        async fn decrypt(State(fixture): State<Fixture>) -> Json<Value> {
            Json(json!({"data": {"plaintext": fixture.0.lock().unwrap().clone()}}))
        }
        let app = Router::new()
            .route(
                "/v1/transit/keys/integration-secret-envelope-marty-aes256",
                get(key_metadata),
            )
            .route(
                "/v1/transit/encrypt/integration-secret-envelope-marty-aes256",
                post(encrypt),
            )
            .route(
                "/v1/transit/decrypt/integration-secret-envelope-marty-aes256",
                post(decrypt),
            )
            .with_state(Fixture::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let provider = OpenBaoEnvelopeProvider::new(endpoint, "fixture-token").unwrap();
        let plain = json!({"services": [{
            "id": "service-1", "service_type": "openbao-transit",
            "provider": "openbao", "protocol": "vault-transit",
            "endpoint": "https://bao.example", "region": "",
            "auth_mode": "token", "mount": "transit", "namespace": "",
            "auth_reference": "tenant-token"
        }]});
        let sealed = seal_auth_references(&plain, "org-1", Some(&provider))
            .await
            .unwrap();
        assert!(!sealed.to_string().contains("tenant-token"));
        assert_eq!(sealed["services"][0]["auth_reference"], "");
        assert_eq!(
            unseal_auth_references(&sealed, "org-1", Some(&provider))
                .await
                .unwrap(),
            plain
        );
        assert!(unseal_auth_references(&sealed, "org-2", Some(&provider))
            .await
            .is_err());
        let mut rebound = sealed.clone();
        rebound["services"][0]["endpoint"] = json!("https://other.example");
        assert!(unseal_auth_references(&rebound, "org-1", Some(&provider))
            .await
            .is_err());
        assert!(unseal_auth_references(&plain, "org-1", Some(&provider))
            .await
            .is_err());
        assert!(unseal_auth_references(&sealed, "org-1", None)
            .await
            .is_err());
        assert!(seal_auth_references(&plain, "org-1", None).await.is_err());
        server.abort();
    }

    #[test]
    fn requested_registry_rejects_private_material_before_normalization() {
        for request in [
            json!({"services": [], "private_key_pem": "synthetic-secret"}),
            json!({"services": [{"managed": true, "privateKey": "synthetic-secret"}]}),
            json!({"services": [{"key_reference": "-----BEGIN PRIVATE KEY-----"}]}),
            json!({"services": [], "unexpected": {"kty": "EC", "d": "synthetic-secret"}}),
            json!({"services": [], "metadata": {"privateKeyJwk": "synthetic-secret"}}),
            json!({"services": [], "metadata": "{\"kty\":\"EC\",\"d\":\"synthetic-secret\"}"}),
        ] {
            assert!(matches!(
                normalize_requested_registry(&request),
                Err(RegistryError::Invalid(message)) if message.contains("private key material")
            ));
        }

        assert!(normalize_requested_registry(&json!({
            "services": [],
            "auth_reference": "vault-token-reference",
            "cert_pem": "-----BEGIN CERTIFICATE-----"
        }))
        .is_ok());
    }

    #[test]
    fn flat_key_management_settings_fail_closed_for_requested_and_stored_configs() {
        for legacy in [
            json!({"hsm_enabled": false}),
            json!({"hsm_enabled": true, "hsm_settings": {"managed_by": "Marty"}}),
            json!({"services": [], "hsm_settings": {"key_reference": "old-key"}}),
            json!({"vault_enabled": false, "vault_settings": {}}),
        ] {
            for normalize in [
                normalize_requested_registry as fn(&Value) -> Result<Value, RegistryError>,
                normalize_stored_registry,
            ] {
                assert!(matches!(
                    normalize(&legacy),
                    Err(RegistryError::Invalid(message)) if message.contains("legacy flat")
                ));
            }
        }
        let modern = json!({"services": [], "key_reference_purposes": {}});
        assert!(normalize_requested_registry(&modern).is_ok());
        assert!(normalize_stored_registry(&modern).is_ok());
    }

    async fn disposable_redis_url() -> String {
        let url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
        let parsed = reqwest::Url::parse(&url).expect("disposable Redis URL syntax");
        assert!(matches!(
            parsed.host_str(),
            Some("127.0.0.1" | "localhost" | "::1")
        ));
        assert!(parsed
            .path()
            .trim_start_matches('/')
            .parse::<u8>()
            .is_ok_and(|db| db >= 13));
        let nonce = std::env::var("MARTY_TEST_REDIS_DISPOSABLE_NONCE")
            .expect("disposable Redis sentinel value");
        assert!(nonce.len() >= 16, "disposable Redis sentinel is too short");
        let client = redis::Client::open(url.as_str()).expect("disposable Redis client");
        let mut connection = client
            .get_multiplexed_async_connection()
            .await
            .expect("disposable Redis connection");
        let observed: Option<String> = connection
            .get("marty:tests:disposable-guard")
            .await
            .expect("disposable Redis sentinel read");
        assert_eq!(observed.as_deref(), Some(nonce.as_str()));
        url
    }

    #[tokio::test]
    #[ignore = "requires disposable Redis and OpenBao with integration-secret Transit key"]
    async fn persisted_registry_credentials_use_real_openbao_ciphertext() {
        let redis_url = disposable_redis_url().await;
        let bao_url = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
        let parsed = reqwest::Url::parse(&bao_url).expect("disposable OpenBao URL syntax");
        assert!(matches!(
            parsed.host_str(),
            Some("127.0.0.1" | "localhost" | "::1")
        ));
        let token = std::env::var("BAO_TOKEN").expect("disposable OpenBao token");
        let nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE")
            .expect("disposable OpenBao sentinel value");
        assert!(nonce.len() >= 16);
        let marker = reqwest::Client::new()
            .get(format!(
                "{bao_url}/v1/secret/data/marty-test-disposable-guard"
            ))
            .header("X-Vault-Token", &token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<Value>()
            .await
            .unwrap();
        assert_eq!(
            marker.pointer("/data/data/nonce").and_then(Value::as_str),
            Some(nonce.as_str())
        );
        let organization_id = format!("registry-auth-{}", Uuid::new_v4().simple());
        let secret = format!("test-token-{}", Uuid::new_v4().simple());
        let provider = OpenBaoEnvelopeProvider::new(bao_url, token).unwrap();
        let store = RegistryStore::connect(&redis_url)
            .await
            .unwrap()
            .with_auth_envelopes(Some(provider));
        let config = json!({"services": [{
            "id": "provider-a", "service_type": "openbao-transit",
            "endpoint": "https://external.example", "auth_mode": "token",
            "auth_reference": secret, "key_reference": "issuer-a",
            "algorithms": ["ES256"]
        }]});
        store.save(&organization_id, &config).await.unwrap();
        let mut connection = store.connection();
        let stored: String = connection.get(storage_key(&organization_id)).await.unwrap();
        assert!(!stored.contains(&secret));
        let stored: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(stored["services"][0]["auth_reference"], "");
        assert!(stored["services"][0][AUTH_ENVELOPE_FIELD]["ciphertext"]
            .as_str()
            .is_some_and(|value| value.starts_with("vault:v")));
        assert_eq!(
            store.load(&organization_id).await.unwrap()["services"][0]["auth_reference"],
            secret
        );
        let _: () = connection.del(storage_key(&organization_id)).await.unwrap();
    }

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
        for prefix in crate::domain::MANAGED_KEY_PREFIXES {
            let own = format!(
                "{prefix}{}-demo-es256",
                Uuid::new_v5(&Uuid::NAMESPACE_URL, b"org-a").simple()
            );
            let foreign = format!(
                "{prefix}{}-demo-es256",
                Uuid::new_v5(&Uuid::NAMESPACE_URL, b"org-b").simple()
            );
            assert!(tenant_managed_key_name("org-a", &own), "{prefix}");
            assert!(!tenant_managed_key_name("org-a", &foreign), "{prefix}");
        }
        assert!(issuer_tuple_key_name(
            "cred-issuer-0123456789abcdef0123-es256"
        ));
        assert!(issuer_tuple_key_name(
            "oid4vp-verifier-0123456789abcdef0123-eddsa"
        ));
        let own = format!(
            "cred-issuer-{}-demo-es256",
            Uuid::new_v5(&Uuid::NAMESPACE_URL, b"org-a").simple()
        );
        assert!(!issuer_tuple_key_name(&own));
        assert!(!issuer_tuple_key_name("cred-issuer-legacy-es256"));
        assert_eq!(
            kms::managed_public_key_algorithm(&json!({"kty":"EC", "crv":"P-384"})),
            Some("ES384")
        );
    }

    #[test]
    fn shared_profile_reference_preserves_lti_only_restriction() {
        let reference = managed_key_reference_for_fields(
            "org-a",
            "did:example:issuer",
            "lti_tool_signing",
            "LTI",
            "ES256",
        );
        let profiles = json!({"profiles": [
            {"status": "active", "organization_id": "org-a", "signing_service_id": MANAGED_OPENBAO_SERVICE_ID,
                "signing_key_reference": reference, "key_purpose": "lti_tool_signing",
                "issuer_did": "did:example:issuer", "credential_format": "LTI", "algorithm": "ES256"},
            {"status": "active", "organization_id": "org-a", "signing_service_id": MANAGED_OPENBAO_SERVICE_ID,
                "signing_key_reference": reference, "key_purpose": "vc_jwt_issuer",
                "issuer_did": "did:example:issuer", "credential_format": "LTI", "algorithm": "ES256"}
        ]});
        assert!(active_managed_profile_references("org-a", &profiles)[&reference]);
    }

    #[tokio::test]
    async fn managed_inventory_discards_unscoped_and_foreign_keys_and_recovers_tenant_key() {
        #[derive(Clone)]
        struct Fixture {
            own: String,
            foreign: String,
            unsafe_key: String,
            reads: Arc<Mutex<Vec<String>>>,
        }
        async fn list(State(state): State<Fixture>) -> Json<Value> {
            Json(json!({"data": {"keys": [state.own, state.foreign, state.unsafe_key]}}))
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
                "supports_signing": true, "soft_deleted": false,
                "exportable": reference.ends_with("unsafe-es256"),
                "allow_plaintext_backup": false, "deletion_allowed": false,
                "imported_key": false,
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
        let unsafe_key = format!(
            "cred-issuer-{}-unsafe-es256",
            Uuid::new_v5(&Uuid::NAMESPACE_URL, b"org-a").simple()
        );
        let fixture = Fixture {
            own: own.clone(),
            foreign: foreign.clone(),
            unsafe_key: unsafe_key.clone(),
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
        let profile_only = managed_key_reference_for_fields(
            "org-a",
            "did:example:verifier",
            "oid4vp_request_signing",
            "JWT",
            "ES256",
        );
        let foreign_tuple = managed_key_reference_for_fields(
            "org-b",
            "did:example:verifier",
            "oid4vp_request_signing",
            "JWT",
            "ES256",
        );
        let profiles = json!({"profiles": [
            {
                "status": "active", "signing_service_id": "managed-openbao-transit",
                "organization_id": "org-a", "signing_key_reference": profile_only,
                "key_purpose": "oid4vp_request_signing", "issuer_did": "did:example:verifier",
                "credential_format": "JWT", "algorithm": "ES256"
            },
            {
                "status": "active", "signing_service_id": "managed-openbao-transit",
                "organization_id": "org-a", "signing_key_reference": foreign_tuple,
                "key_purpose": "oid4vp_request_signing", "issuer_did": "did:example:verifier",
                "credential_format": "JWT", "algorithm": "ES256"
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
        assert!(!complete, "exportable managed key must degrade inventory");
        assert_eq!(
            keys.iter()
                .map(|key| key.reference.as_str())
                .collect::<Vec<_>>(),
            [own.as_str(), profile_only.as_str()]
        );
        let reads = fixture.reads.lock().unwrap();
        assert!(!reads.contains(&"a-stale".into()));
        assert!(!reads.contains(&foreign));
        assert!(!reads.contains(&foreign_tuple));
        assert!(!reads.contains(&revoked.to_owned()));
        assert!(!reads.contains(&deleted.to_owned()));
        assert!(reads.contains(&unsafe_key));
        let service = managed_openbao_service(&endpoint, &keys, complete);
        assert_eq!(service["key_reference"], own);
        assert_eq!(service["key_count"], 2);
        assert_eq!(service["status"], "degraded");
        assert!(!service["key_aliases"]
            .as_array()
            .unwrap()
            .contains(&json!(unsafe_key)));
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
        assert_eq!(
            resolved.key_reference.as_deref(),
            Some(profile_only.as_str())
        );
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
        let redis_url = disposable_redis_url().await;
        let _guard = BAO_ENV_LOCK.lock().await;
        let previous = std::env::var("BAO_TOKEN").ok();
        std::env::set_var("BAO_TOKEN", "test-only");
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
    fn external_registration_cannot_use_mounted_openbao_token() {
        let service = json!({
            "service_type": "openbao-transit",
            "auth_mode": "service_token",
            "endpoint": "https://external.example",
            "key_reference": "signer"
        });
        assert!(normalize_service(NormalizeServiceRequest {
            service: service.clone(),
        })
        .is_err());
        assert!(normalize_registry(NormalizeRegistryRequest {
            mode: RegistryMode::Requested,
            registry: json!({"services": [service]}),
        })
        .is_err());
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

    #[tokio::test]
    #[ignore = "requires disposable MARTY_TEST_REDIS_URL"]
    async fn concurrent_purpose_bindings_remain_atomic_with_rotation_lease() {
        let redis_url = disposable_redis_url().await;
        let store = RegistryStore::connect(&redis_url).await.unwrap();
        let organization_id = format!("managed-bind-race-{}", Uuid::new_v4().simple());
        let key = storage_key(&organization_id);
        let mut connection = store.connection();
        let mut tasks = tokio::task::JoinSet::new();
        for index in 0..24 {
            let store = store.clone();
            let organization_id = organization_id.clone();
            tasks.spawn(async move {
                store
                    .bind_key_purpose(
                        &organization_id,
                        MANAGED_OPENBAO_SERVICE_ID,
                        &format!("cred-issuer-race-{index:02}"),
                        "vc_jwt_issuer",
                    )
                    .await
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap().unwrap();
        }
        let registry = store.load(&organization_id).await.unwrap();
        assert_eq!(
            registry["key_reference_purposes"][MANAGED_OPENBAO_SERVICE_ID]
                .as_object()
                .unwrap()
                .len(),
            24
        );
        let _: () = connection.del(&key).await.unwrap();
    }
}
