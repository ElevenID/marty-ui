//! Canonical signing-service registry normalization and routing decisions.

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::domain::{key_purposes, service_capabilities, service_type, service_types};

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
pub struct RegistryStore {
    connection: ConnectionManager,
    managed_openbao_endpoint: Option<String>,
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
        Ok(self.with_managed_service(registry))
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
        Ok(self.with_managed_service(normalized))
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

    fn with_managed_service(&self, mut registry: Value) -> Value {
        let Some(endpoint) = self.managed_openbao_endpoint.as_deref() else {
            return registry;
        };
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
            services.insert(0, managed_openbao_service(endpoint));
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

fn managed_openbao_service(endpoint: &str) -> Value {
    let purposes = key_purposes()
        .into_iter()
        .map(|purpose| purpose.id)
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
        "key_reference": "",
        "key_aliases": [],
        "algorithms": SUPPORTED_ALGORITHMS,
        "key_purposes": purposes,
        "credential_formats": ["jwt_vc_json", "dc+sd-jwt", "mso_mdoc", "zk_mdoc", "vds_nc", "oauth-authz-req+jwt", "lti_tool_jwt"],
        "status": "configured",
        "managed": true,
        "read_only": true,
        "managed_by": "Marty service stack",
        "key_count": 0,
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
        return normalize_legacy_registry(body);
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

fn managed_key_purposes(reference: &str) -> &'static [&'static str] {
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
