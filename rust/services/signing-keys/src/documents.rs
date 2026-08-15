//! Canonical certificate metadata and public-key publication documents.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use marty_crypto::certificate::{get_certificate_info, load_certificate_pem};
use marty_crypto::jwk::certificate_pem_to_jwk;
use percent_encoding::percent_decode_str;
use redis::{aio::ConnectionManager, AsyncCommands};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

const PRIVATE_JWK_FIELDS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k", "rsa_d"];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DocumentError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    NotFound(String),
    #[error("signing document storage is unavailable: {0}")]
    Storage(String),
    #[error("stored signing document is malformed: {0}")]
    Corrupt(String),
}

#[derive(Clone)]
pub struct DocumentStore {
    connection: ConnectionManager,
}

impl DocumentStore {
    pub fn from_connection(connection: ConnectionManager) -> Self {
        Self { connection }
    }

    async fn load_optional(&self, key: &str) -> Result<Option<Value>, DocumentError> {
        let mut connection = self.connection.clone();
        let payload: Option<String> = connection
            .get(key)
            .await
            .map_err(|error| DocumentError::Storage(error.to_string()))?;
        payload
            .map(|payload| {
                serde_json::from_str::<Value>(&payload)
                    .map_err(|error| DocumentError::Corrupt(error.to_string()))
                    .and_then(|value| {
                        value.as_object().ok_or_else(|| {
                            DocumentError::Corrupt("document must be a JSON object".to_string())
                        })?;
                        Ok(value)
                    })
            })
            .transpose()
    }

    async fn save(&self, key: &str, value: &Value) -> Result<(), DocumentError> {
        let payload = serde_json::to_string(value)
            .map_err(|error| DocumentError::Invalid(error.to_string()))?;
        let mut connection = self.connection.clone();
        connection
            .set::<_, _, ()>(key, payload)
            .await
            .map_err(|error| DocumentError::Storage(error.to_string()))
    }

    pub async fn certificate_overrides(
        &self,
        organization_id: &str,
    ) -> Result<Value, DocumentError> {
        Ok(self
            .load_optional(&certificate_storage_key(organization_id))
            .await?
            .unwrap_or_else(|| json!({"services": {}})))
    }

    pub async fn store_certificate(
        &self,
        organization_id: &str,
        service_id: &str,
        request: InspectCertificateRequest,
    ) -> Result<StoredCertificate, DocumentError> {
        let inspected = inspect_certificate(&request)?;
        let updated_at = now_iso();
        let attachment = StoredCertificate {
            cert_pem: request.cert_pem,
            cert_chain_pem: request.cert_chain_pem.unwrap_or_default(),
            cert_expires_at: inspected.expires_at,
            updated_at,
            public_jwk: inspected.public_jwk,
            x5c: inspected.x5c,
        };
        let mut document = self.certificate_overrides(organization_id).await?;
        let services = document
            .as_object_mut()
            .expect("certificate document is an object")
            .entry("services")
            .or_insert_with(|| json!({}));
        let services = services.as_object_mut().ok_or_else(|| {
            DocumentError::Corrupt("certificate services must be an object".to_string())
        })?;
        services.insert(service_id.to_string(), json!(attachment));
        document["updated_at"] = Value::String(now_iso());
        self.save(&certificate_storage_key(organization_id), &document)
            .await?;
        Ok(attachment)
    }

    pub async fn jwks(&self, organization_id: &str) -> Result<Value, DocumentError> {
        Ok(self
            .load_optional(&jwks_storage_key(organization_id))
            .await?
            .unwrap_or_else(|| {
                json!({
                    "keys": [],
                    "organization_id": organization_id,
                    "updated_at": now_iso(),
                })
            }))
    }

    pub async fn publish_jwk(
        &self,
        organization_id: &str,
        service_id: &str,
        request: PublishJwkRequest,
    ) -> Result<PublishJwkResponse, DocumentError> {
        let existing = self.jwks(organization_id).await?;
        let response = build_jwks_document(existing, organization_id, service_id, request)?;
        self.save(&jwks_storage_key(organization_id), &response.document)
            .await?;
        Ok(response)
    }

    pub async fn update_jwk(
        &self,
        organization_id: &str,
        key_id: &str,
        request: UpdateJwkRequest,
    ) -> Result<UpdateJwkResponse, DocumentError> {
        let document = self.jwks(organization_id).await?;
        let (document, response) = update_jwks_document(document, key_id, request)?;
        self.save(&jwks_storage_key(organization_id), &document)
            .await?;
        Ok(response)
    }

    pub async fn delete_jwk(
        &self,
        organization_id: &str,
        key_id: &str,
    ) -> Result<DeleteJwkResponse, DocumentError> {
        let document = self.jwks(organization_id).await?;
        let (document, response) = delete_jwks_document(document, key_id)?;
        self.save(&jwks_storage_key(organization_id), &document)
            .await?;
        Ok(response)
    }

    pub async fn load_did(
        &self,
        organization_id: &str,
        request: LoadDidRequest,
    ) -> Result<LoadDidResponse, DocumentError> {
        let key = did_storage_key(organization_id, request.did_id.as_deref());
        let stored = self.load_optional(&key).await?;
        let found = stored.is_some();
        let document = stored.unwrap_or_else(|| {
            let did = request.fallback_did.or(request.did_id).unwrap_or_default();
            json!({
                "id": did,
                "controller": did,
                "verificationMethod": [],
                "assertionMethod": [],
                "updated_at": now_iso(),
            })
        });
        Ok(LoadDidResponse { document, found })
    }

    pub async fn publish_did(
        &self,
        organization_id: &str,
        service_id: &str,
        request: PublishDidRequest,
    ) -> Result<PublishDidResponse, DocumentError> {
        let prepared = prepare_did_publication(service_id, request)?;
        let key = did_storage_key(organization_id, Some(&prepared.did_id));
        let existing = self.load_optional(&key).await?;
        let response = build_prepared_did_document(existing, prepared)?;

        if let Some(slug) = &response.org_slug {
            self.claim_slug(slug, organization_id).await?;
        }
        self.save(&key, &response.document).await?;
        self.save(&did_storage_key(organization_id, None), &response.document)
            .await?;
        Ok(response)
    }

    pub async fn resolve_slug(&self, slug: &str) -> Result<Option<String>, DocumentError> {
        if !slug_pattern().is_match(slug) || slug != slug.to_lowercase() {
            return Err(DocumentError::Invalid(
                "DID web slug is malformed".to_string(),
            ));
        }
        let mut connection = self.connection.clone();
        connection
            .get::<_, Option<String>>(slug_storage_key(slug))
            .await
            .map_err(|error| DocumentError::Storage(error.to_string()))
    }

    async fn claim_slug(&self, slug: &str, organization_id: &str) -> Result<(), DocumentError> {
        let key = slug_storage_key(slug);
        let mut connection = self.connection.clone();
        let claimed: bool = connection
            .set_nx(&key, organization_id)
            .await
            .map_err(|error| DocumentError::Storage(error.to_string()))?;
        if claimed {
            return Ok(());
        }
        let existing: Option<String> = connection
            .get(&key)
            .await
            .map_err(|error| DocumentError::Storage(error.to_string()))?;
        match existing.as_deref() {
            Some(existing) if existing == organization_id => Ok(()),
            Some(_) => Err(DocumentError::Conflict(format!(
                "DID web slug '{slug}' is already in use."
            ))),
            None => Err(DocumentError::Storage(
                "DID web slug claim could not be confirmed".to_string(),
            )),
        }
    }
}

pub fn build_jwks_document(
    mut document: Value,
    organization_id: &str,
    service_id: &str,
    request: PublishJwkRequest,
) -> Result<PublishJwkResponse, DocumentError> {
    let mut stored_jwk = sanitize_public_jwk(&request.jwk, request.key_reference.as_deref())?;
    let kid = stored_jwk
        .get("kid")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or(request.key_reference.clone())
        .unwrap_or_else(|| service_id.to_string());
    stored_jwk["kid"] = Value::String(kid.clone());
    stored_jwk["service_id"] = Value::String(service_id.to_string());
    stored_jwk["key_reference"] = request
        .key_reference
        .clone()
        .map(Value::String)
        .unwrap_or(Value::Null);
    let x5c = certificate_chain(
        request.cert_pem.as_deref(),
        request.cert_chain_pem.as_deref(),
    )?;
    if !x5c.is_empty() {
        stored_jwk["x5c"] = json!(x5c);
    }

    let existing = document
        .get("keys")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut keys = existing
        .into_iter()
        .filter(|value| {
            value.as_object().is_none_or(|key| {
                key.get("kid").and_then(Value::as_str) != Some(kid.as_str())
                    && key.get("service_id").and_then(Value::as_str) != Some(service_id)
            })
        })
        .collect::<Vec<_>>();
    keys.push(stored_jwk.clone());
    document["keys"] = Value::Array(keys.clone());
    document["organization_id"] = Value::String(organization_id.to_string());
    document["updated_at"] = Value::String(now_iso());
    Ok(PublishJwkResponse {
        jwk: stored_jwk,
        document,
        key_count: keys.len(),
    })
}

#[derive(Debug, Clone, Deserialize)]
pub struct InspectCertificateRequest {
    pub cert_pem: String,
    #[serde(default)]
    pub cert_chain_pem: Option<String>,
    #[serde(default)]
    pub expected_public_jwk: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InspectCertificateResponse {
    pub expires_at: String,
    pub public_jwk: Value,
    pub x5c: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_matches: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredCertificate {
    pub cert_pem: String,
    pub cert_chain_pem: String,
    pub cert_expires_at: String,
    pub updated_at: String,
    #[serde(skip_serializing)]
    pub public_jwk: Value,
    #[serde(skip_serializing)]
    pub x5c: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublishJwkRequest {
    pub jwk: Value,
    #[serde(default)]
    pub key_reference: Option<String>,
    #[serde(default)]
    pub cert_pem: Option<String>,
    #[serde(default)]
    pub cert_chain_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublishJwkResponse {
    pub jwk: Value,
    pub document: Value,
    pub key_count: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateJwkRequest {
    pub updates: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateJwkResponse {
    pub updated: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeleteJwkResponse {
    pub removed: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoadDidRequest {
    #[serde(default)]
    pub did_id: Option<String>,
    #[serde(default)]
    pub fallback_did: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoadDidResponse {
    pub document: Value,
    pub found: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublishDidRequest {
    pub jwk: Value,
    pub public_domain: String,
    #[serde(default)]
    pub did_id: Option<String>,
    #[serde(default)]
    pub org_slug: Option<String>,
    #[serde(default)]
    pub fragment: Option<String>,
    #[serde(default)]
    pub key_reference: Option<String>,
    #[serde(default)]
    pub cert_pem: Option<String>,
    #[serde(default)]
    pub cert_chain_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublishDidResponse {
    pub verification_method: Value,
    pub document: Value,
    pub verification_method_count: usize,
    pub did_id: String,
    pub org_slug: Option<String>,
}

#[derive(Debug, Clone)]
struct PreparedDidPublication {
    did_id: String,
    org_slug: Option<String>,
    verification_method: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertificateAlertsRequest {
    pub services: Vec<Value>,
    pub days_until_expiry: i64,
    #[serde(default)]
    pub now: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateAlert {
    pub service_id: Option<String>,
    pub service_name: Option<String>,
    pub cert_expires_at: String,
    pub days_until_expiry: i64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateAlertsResponse {
    pub alerts: Vec<CertificateAlert>,
    pub alert_threshold_days: i64,
    pub checked_at: String,
}

pub fn inspect_certificate(
    request: &InspectCertificateRequest,
) -> Result<InspectCertificateResponse, DocumentError> {
    if request.cert_pem.trim().is_empty() {
        return Err(DocumentError::Invalid("cert_pem is required.".to_string()));
    }
    let der = load_certificate_pem(&request.cert_pem)
        .map_err(|error| DocumentError::Invalid(format!("invalid cert_pem: {error}")))?;
    let info = get_certificate_info(&der)
        .map_err(|error| DocumentError::Invalid(format!("invalid cert_pem: {error}")))?;
    let public_jwk = serde_json::to_value(
        certificate_pem_to_jwk(&request.cert_pem)
            .map_err(|error| DocumentError::Invalid(format!("invalid cert_pem: {error}")))?,
    )
    .map_err(|error| DocumentError::Invalid(error.to_string()))?;
    let public_jwk = sanitize_public_jwk(&public_jwk, None)?;
    let x5c = certificate_chain(Some(&request.cert_pem), request.cert_chain_pem.as_deref())?;
    let public_key_matches = request
        .expected_public_jwk
        .as_ref()
        .map(|expected| same_public_jwk(&public_jwk, expected));
    Ok(InspectCertificateResponse {
        expires_at: info.not_after,
        public_jwk,
        x5c,
        public_key_matches,
    })
}

pub fn certificate_alerts(
    request: CertificateAlertsRequest,
) -> Result<CertificateAlertsResponse, DocumentError> {
    let now = match request.now.as_deref() {
        Some(value) => DateTime::parse_from_rfc3339(value)
            .map_err(|_| DocumentError::Invalid("now must be RFC 3339".to_string()))?
            .with_timezone(&Utc),
        None => Utc::now(),
    };
    let threshold = now + Duration::days(request.days_until_expiry);
    let mut alerts = Vec::new();
    for service in request.services {
        let Some(expires_at) = service.get("cert_expires_at").and_then(Value::as_str) else {
            continue;
        };
        let Ok(expiry) = DateTime::parse_from_rfc3339(expires_at) else {
            continue;
        };
        let expiry = expiry.with_timezone(&Utc);
        if expiry > threshold {
            continue;
        }
        let days_left = (expiry - now).num_days();
        alerts.push(CertificateAlert {
            service_id: service
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string),
            service_name: service
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string),
            cert_expires_at: expires_at.to_string(),
            days_until_expiry: days_left.max(0),
            status: if days_left <= 7 {
                "critical"
            } else {
                "warning"
            }
            .to_string(),
        });
    }
    alerts.sort_by_key(|alert| alert.days_until_expiry);
    Ok(CertificateAlertsResponse {
        alerts,
        alert_threshold_days: request.days_until_expiry,
        checked_at: now.to_rfc3339_opts(SecondsFormat::Micros, true),
    })
}

pub fn sanitize_public_jwk(
    candidate: &Value,
    key_reference_hint: Option<&str>,
) -> Result<Value, DocumentError> {
    let object = candidate.as_object().ok_or_else(|| {
        DocumentError::Invalid("provider did not return a public JWK".to_string())
    })?;
    let nested = ["public_jwk", "publicKeyJwk", "jwk", "key"]
        .iter()
        .find_map(|key| object.get(*key).and_then(Value::as_object))
        .unwrap_or(object);
    if nested.get("kty").and_then(Value::as_str).is_none() {
        return Err(DocumentError::Invalid(
            "provider did not return a usable public JWK".to_string(),
        ));
    }
    let mut sanitized = nested
        .iter()
        .filter(|(key, value)| !PRIVATE_JWK_FIELDS.contains(&key.as_str()) && !value.is_null())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Map<_, _>>();
    if sanitized.get("kid").and_then(Value::as_str).is_none() {
        if let Some(hint) = key_reference_hint.filter(|value| !value.is_empty()) {
            sanitized.insert("kid".to_string(), Value::String(hint.to_string()));
        }
    }
    Ok(Value::Object(sanitized))
}

pub fn update_jwks_document(
    mut document: Value,
    key_id: &str,
    request: UpdateJwkRequest,
) -> Result<(Value, UpdateJwkResponse), DocumentError> {
    let keys = document
        .get_mut("keys")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| DocumentError::Corrupt("JWKS keys must be an array".to_string()))?;
    let key = keys
        .iter_mut()
        .find(|key| {
            key.get("kid").and_then(Value::as_str) == Some(key_id)
                || key.get("provider_key_name").and_then(Value::as_str) == Some(key_id)
        })
        .ok_or_else(|| {
            DocumentError::NotFound(format!("Signing key '{key_id}' not found in org JWKS."))
        })?;
    let updates = request
        .updates
        .as_object()
        .ok_or_else(|| DocumentError::Invalid("updates must be a JSON object".to_string()))?;
    let allowed = ["aliases", "key_aliases", "name", "status"];
    let mut updated = Vec::new();
    for field in allowed {
        if let Some(value) = updates.get(field) {
            key[field] = value.clone();
            updated.push(field.to_string());
        }
    }
    document["updated_at"] = Value::String(now_iso());
    Ok((document, UpdateJwkResponse { updated }))
}

pub fn delete_jwks_document(
    mut document: Value,
    key_id: &str,
) -> Result<(Value, DeleteJwkResponse), DocumentError> {
    let keys = document
        .get_mut("keys")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| DocumentError::Corrupt("JWKS keys must be an array".to_string()))?;
    let previous = keys.len();
    keys.retain(|key| {
        key.get("kid").and_then(Value::as_str) != Some(key_id)
            && key.get("provider_key_name").and_then(Value::as_str) != Some(key_id)
    });
    if keys.len() == previous {
        return Err(DocumentError::NotFound(format!(
            "Signing key '{key_id}' not found in org JWKS."
        )));
    }
    document["updated_at"] = Value::String(now_iso());
    Ok((document, DeleteJwkResponse { removed: true }))
}

fn same_public_jwk(left: &Value, right: &Value) -> bool {
    let Some(key_type) = left.get("kty").and_then(Value::as_str) else {
        return false;
    };
    let fields: &[&str] = match key_type {
        "EC" => &["kty", "crv", "x", "y"],
        "RSA" => &["kty", "n", "e"],
        "OKP" => &["kty", "crv", "x"],
        _ => return false,
    };
    right.get("kty").and_then(Value::as_str) == Some(key_type)
        && fields
            .iter()
            .all(|field| left.get(*field) == right.get(*field))
}

fn certificate_chain(
    cert_pem: Option<&str>,
    cert_chain_pem: Option<&str>,
) -> Result<Vec<String>, DocumentError> {
    let pattern = Regex::new(r"(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----")
        .expect("certificate regex");
    let mut encoded = Vec::new();
    for pem in [cert_pem, cert_chain_pem].into_iter().flatten() {
        for certificate in pattern.find_iter(pem) {
            let der = load_certificate_pem(certificate.as_str()).map_err(|error| {
                DocumentError::Invalid(format!("invalid certificate chain: {error}"))
            })?;
            encoded.push(STANDARD.encode(der));
        }
    }
    Ok(encoded)
}

fn prepare_did_publication(
    service_id: &str,
    request: PublishDidRequest,
) -> Result<PreparedDidPublication, DocumentError> {
    let public_domain = normalize_domain(&request.public_domain).ok_or_else(|| {
        DocumentError::Invalid("PUBLIC_DOMAIN is not a valid did:web domain.".to_string())
    })?;
    let mut org_slug = request.org_slug.map(|slug| slug.to_lowercase());
    if let Some(slug) = &org_slug {
        if !slug_pattern().is_match(slug) {
            return Err(DocumentError::Invalid(
                "org_slug must contain only letters, numbers, '.', '_' or '-'.".to_string(),
            ));
        }
    }
    let did_id = match request.did_id {
        Some(did_id) => {
            if did_id.trim() != did_id || did_id.is_empty() {
                return Err(DocumentError::Invalid(
                    "did_id must be a non-empty DID without surrounding whitespace.".to_string(),
                ));
            }
            if did_id.starts_with("did:web:") {
                let local_slug = did_web_org_slug(&did_id, Some(&public_domain));
                let domain = did_web_domain(&did_id);
                if domain.as_deref() == Some(public_domain.as_str())
                    && did_id.split(':').count() != 3
                    && local_slug.is_none()
                {
                    return Err(DocumentError::Invalid(
                        "Local did:web identifiers must use did:web:<PUBLIC_DOMAIN>:orgs:<slug>."
                            .to_string(),
                    ));
                }
                if org_slug.is_some() && org_slug != local_slug {
                    return Err(DocumentError::Invalid(
                        "org_slug must match a path-scoped DID on the configured PUBLIC_DOMAIN."
                            .to_string(),
                    ));
                }
                org_slug = org_slug.or(local_slug);
            } else if org_slug.is_some() {
                return Err(DocumentError::Invalid(
                    "org_slug is only valid for a local path-scoped did:web identifier."
                        .to_string(),
                ));
            }
            did_id
        }
        None => {
            let slug = org_slug.clone().ok_or_else(|| {
                DocumentError::Invalid("org_slug is required when did_id is omitted.".to_string())
            })?;
            format!("did:web:{}:orgs:{slug}", public_domain.replace(':', "%3A"))
        }
    };
    let jwk = sanitize_public_jwk(&request.jwk, request.key_reference.as_deref())?;
    let fragment = request
        .fragment
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| did_fragment(service_id, request.key_reference.as_deref()));
    if !slug_pattern().is_match(&fragment) {
        return Err(DocumentError::Invalid(
            "fragment must contain only letters, numbers, '.', '_' or '-'.".to_string(),
        ));
    }
    let mut verification_method = json!({
        "id": format!("{did_id}#{fragment}"),
        "type": "JsonWebKey",
        "controller": did_id,
        "publicKeyJwk": jwk,
    });
    let x5c = certificate_chain(
        request.cert_pem.as_deref(),
        request.cert_chain_pem.as_deref(),
    )?;
    if !x5c.is_empty() {
        verification_method["x5c"] = json!(x5c);
    }
    Ok(PreparedDidPublication {
        did_id,
        org_slug,
        verification_method,
    })
}

fn upsert_did_document(
    existing: Option<Value>,
    prepared: &PreparedDidPublication,
) -> Result<Value, DocumentError> {
    let mut document = existing.unwrap_or_else(|| {
        json!({
            "id": prepared.did_id,
            "controller": prepared.did_id,
            "verificationMethod": [],
            "assertionMethod": [],
            "updated_at": now_iso(),
        })
    });
    if document.get("id").and_then(Value::as_str) != Some(prepared.did_id.as_str()) {
        return Err(DocumentError::Corrupt(
            "scoped DID document identity does not match its registry key".to_string(),
        ));
    }
    document["controller"] = Value::String(prepared.did_id.clone());
    let method_id = prepared.verification_method["id"]
        .as_str()
        .expect("verification method id")
        .to_string();
    let mut methods = document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    methods.retain(|method| method.get("id").and_then(Value::as_str) != Some(&method_id));
    methods.push(prepared.verification_method.clone());
    document["verificationMethod"] = Value::Array(methods);
    let mut assertions = document
        .get("assertionMethod")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    assertions.retain(|entry| entry.as_str() != Some(&method_id));
    assertions.push(Value::String(method_id));
    document["assertionMethod"] = Value::Array(assertions);
    document["updated_at"] = Value::String(now_iso());
    Ok(document)
}

pub fn build_did_document(
    existing: Option<Value>,
    service_id: &str,
    request: PublishDidRequest,
) -> Result<PublishDidResponse, DocumentError> {
    let prepared = prepare_did_publication(service_id, request)?;
    build_prepared_did_document(existing, prepared)
}

fn build_prepared_did_document(
    existing: Option<Value>,
    prepared: PreparedDidPublication,
) -> Result<PublishDidResponse, DocumentError> {
    let document = upsert_did_document(existing, &prepared)?;
    Ok(PublishDidResponse {
        verification_method: prepared.verification_method,
        verification_method_count: document["verificationMethod"]
            .as_array()
            .map_or(0, Vec::len),
        document,
        did_id: prepared.did_id,
        org_slug: prepared.org_slug,
    })
}

fn normalize_domain(value: &str) -> Option<String> {
    if value.trim() != value || value.is_empty() {
        return None;
    }
    let decoded = percent_decode_str(value).decode_utf8().ok()?;
    let decoded = decoded.as_ref();
    let pattern = Regex::new(r"^[a-zA-Z0-9.-]+(?::[0-9]{1,5})?$").ok()?;
    if !pattern.is_match(decoded) {
        return None;
    }
    let (host, port) = decoded
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|character| character.is_ascii_digit()))
        .map_or((decoded, None), |(host, port)| (host, Some(port)));
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let label = Regex::new(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$").ok()?;
    if host.split('.').any(|part| !label.is_match(part)) {
        return None;
    }
    if let Some(port) = port {
        let port = port.parse::<u16>().ok()?;
        if port == 0 {
            return None;
        }
        return Some(format!("{}:{port}", host.to_lowercase()));
    }
    Some(host.to_lowercase())
}

fn did_web_domain(did_id: &str) -> Option<String> {
    let parts = did_id.split(':').collect::<Vec<_>>();
    (parts.len() >= 3 && parts[0] == "did" && parts[1] == "web")
        .then(|| normalize_domain(parts[2]))
        .flatten()
}

fn did_web_org_slug(did_id: &str, public_domain: Option<&str>) -> Option<String> {
    let parts = did_id.split(':').collect::<Vec<_>>();
    if parts.len() != 5 || parts[0] != "did" || parts[1] != "web" || parts[3] != "orgs" {
        return None;
    }
    let domain = normalize_domain(parts[2])?;
    if public_domain.is_some_and(|expected| normalize_domain(expected).as_deref() != Some(&domain))
    {
        return None;
    }
    let slug = parts[4].to_lowercase();
    slug_pattern().is_match(&slug).then_some(slug)
}

fn did_fragment(service_id: &str, key_reference: Option<&str>) -> String {
    let source = key_reference
        .map(str::to_string)
        .unwrap_or_else(|| format!("{service_id}-vm"));
    let unsafe_character = Regex::new(r"[^a-zA-Z0-9._-]").expect("fragment regex");
    let fragment = unsafe_character.replace_all(&source, "-");
    let fragment = fragment.trim_matches('-');
    if fragment.is_empty() {
        format!("{service_id}-vm")
    } else {
        fragment.to_string()
    }
}

fn slug_pattern() -> Regex {
    Regex::new(r"^[a-zA-Z0-9._-]{1,128}$").expect("slug regex")
}

pub fn jwks_storage_key(organization_id: &str) -> String {
    format!("org:{organization_id}:signing-key-jwks")
}

pub fn certificate_storage_key(organization_id: &str) -> String {
    format!("org:{organization_id}:signing-key-service-certificates")
}

pub fn did_storage_key(organization_id: &str, did_id: Option<&str>) -> String {
    let legacy = format!("org:{organization_id}:signing-key-did-document");
    let Some(did_id) = did_id else {
        return legacy;
    };
    let digest = Sha256::digest(did_id.as_bytes());
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{legacy}:did:{hex}")
}

pub fn slug_storage_key(slug: &str) -> String {
    format!("did-web-slug:{slug}")
}

fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}

pub fn normalize_certificate_overrides(document: &Value) -> BTreeMap<String, Value> {
    document
        .get("services")
        .and_then(Value::as_object)
        .map(|services| {
            services
                .iter()
                .filter_map(|(service_id, attachment)| {
                    attachment.as_object().map(|attachment| {
                        let allowed = [
                            "cert_pem",
                            "cert_chain_pem",
                            "cert_expires_at",
                            "updated_at",
                        ];
                        let filtered = attachment
                            .iter()
                            .filter(|(key, value)| {
                                allowed.contains(&key.as_str()) && value.is_string()
                            })
                            .map(|(key, value)| (key.clone(), value.clone()))
                            .collect::<Map<_, _>>();
                        (service_id.clone(), Value::Object(filtered))
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_keys_preserve_the_python_keyspace() {
        assert_eq!(jwks_storage_key("org-a"), "org:org-a:signing-key-jwks");
        assert_eq!(
            certificate_storage_key("org-a"),
            "org:org-a:signing-key-service-certificates"
        );
        assert_eq!(slug_storage_key("acme"), "did-web-slug:acme");
        assert!(did_storage_key("org-a", Some("did:web:example.test"))
            .starts_with("org:org-a:signing-key-did-document:did:"));
    }

    #[test]
    fn private_jwk_material_is_removed() {
        let sanitized = sanitize_public_jwk(
            &json!({"kty": "EC", "crv": "P-256", "x": "x", "y": "y", "d": "secret"}),
            Some("key-1"),
        )
        .unwrap();
        assert_eq!(sanitized["kid"], "key-1");
        assert!(sanitized.get("d").is_none());
    }
}
