//! Redis commit boundary for governed passport DSC issuance.
//! Certificate material and receipts are public; signing coordinates stay in
//! the existing managed profile and registry documents.

use chrono::Utc;
use redis::{aio::ConnectionManager, AsyncCommands};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    csca_lifecycle, documents, private_material::contains_private_key, profiles, registry,
    registry::RotationLease,
};

const PENDING_TTL_MS: u64 = 120_000;
const RECEIPTS: &str = "passport_dsc_issuance";
const SERIALS: &str = "passport_dsc_serials";

#[derive(Debug, Error)]
pub enum DscIssuanceStoreError {
    #[error("DSC issuance input is invalid: {0}")]
    Invalid(&'static str),
    #[error("DSC issuance conflicts with current state: {0}")]
    Conflict(&'static str),
    #[error("DSC issuance storage is unavailable: {0}")]
    Storage(String),
    #[error("DSC issuance storage is malformed: {0}")]
    Corrupt(&'static str),
}

#[derive(Clone)]
pub struct DscIssuanceStore {
    connection: ConnectionManager,
}

pub struct DscClaim {
    organization_id: String,
    receipt_id: String,
    pending_key: String,
    owner: String,
    request_digest: String,
}

impl DscClaim {
    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }
}

pub enum BeginDscIssuance {
    Claim(DscClaim),
    Completed(Value),
    Pending,
}

pub enum CommitDscIssuance {
    Committed(Value),
    Completed(Value),
}

/// The parsed values are for caller validation. Raw bytes are retained so the
/// final Redis script can reject even a same-value profile rewrite/revision.
pub struct DscIssuanceSnapshot {
    pub profiles: Value,
    pub registry: Value,
    pub lifecycle: Value,
    pub certificates: Value,
    raw: Vec<Option<String>>,
}

impl DscIssuanceStore {
    pub fn from_connection(connection: ConnectionManager) -> Self {
        Self { connection }
    }

    pub async fn begin(
        &self,
        organization_id: &str,
        idempotency_key: &str,
        request_digest: &str,
    ) -> Result<BeginDscIssuance, DscIssuanceStoreError> {
        if [organization_id, idempotency_key, request_digest]
            .iter()
            .any(|part| part.is_empty() || part.len() > 512 || part.chars().any(char::is_control))
        {
            return Err(DscIssuanceStoreError::Invalid(
                "bounded identifiers and digest are required",
            ));
        }
        let receipt_id = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&json!([organization_id, idempotency_key]))
                    .expect("idempotency tuple serializes")
            )
        );
        let pending_key = format!(
            "signing:passport-dsc-pending:{}:{}:{receipt_id}",
            organization_id.len(),
            organization_id
        );
        if let Some(result) = self
            .completed(organization_id, &receipt_id, request_digest)
            .await?
        {
            return Ok(BeginDscIssuance::Completed(result));
        }
        let owner = Uuid::new_v4().to_string();
        let pending = json!({"owner": owner, "request_digest": request_digest}).to_string();
        let mut connection = self.connection.clone();
        let claimed: Option<String> = redis::cmd("SET")
            .arg(&pending_key)
            .arg(&pending)
            .arg("NX")
            .arg("PX")
            .arg(PENDING_TTL_MS)
            .query_async(&mut connection)
            .await
            .map_err(|error| DscIssuanceStoreError::Storage(error.to_string()))?;
        if claimed.is_none() {
            let current: Option<String> = connection
                .get(&pending_key)
                .await
                .map_err(|error| DscIssuanceStoreError::Storage(error.to_string()))?;
            if let Some(current) = current {
                let current: Value = serde_json::from_str(&current)
                    .map_err(|_| DscIssuanceStoreError::Corrupt("pending claim"))?;
                if current.get("request_digest").and_then(Value::as_str) != Some(request_digest) {
                    return Err(DscIssuanceStoreError::Conflict(
                        "idempotency key was reused with changed input",
                    ));
                }
            }
            return Ok(BeginDscIssuance::Pending);
        }
        let claim = DscClaim {
            organization_id: organization_id.into(),
            receipt_id,
            pending_key,
            owner,
            request_digest: request_digest.into(),
        };
        // A prior owner can commit between the first receipt read and SET NX.
        if let Some(result) = self
            .completed(organization_id, &claim.receipt_id, request_digest)
            .await?
        {
            let _ = self.release(&claim).await;
            return Ok(BeginDscIssuance::Completed(result));
        }
        Ok(BeginDscIssuance::Claim(claim))
    }

    async fn completed(
        &self,
        organization_id: &str,
        receipt_id: &str,
        digest: &str,
    ) -> Result<Option<Value>, DscIssuanceStoreError> {
        let mut connection = self.connection.clone();
        let payload: Option<String> = connection
            .get(documents::certificate_storage_key(organization_id))
            .await
            .map_err(|error| DscIssuanceStoreError::Storage(error.to_string()))?;
        let Some(payload) = payload else {
            return Ok(None);
        };
        let document: Value = serde_json::from_str(&payload)
            .map_err(|_| DscIssuanceStoreError::Corrupt("certificate document"))?;
        if !document.is_object()
            || [RECEIPTS, SERIALS]
                .iter()
                .any(|field| document.get(*field).is_some_and(|value| !value.is_object()))
        {
            return Err(DscIssuanceStoreError::Corrupt(
                "certificate issuance ledger",
            ));
        }
        let Some(receipt) = document.pointer(&format!("/{RECEIPTS}/{receipt_id}")) else {
            return Ok(None);
        };
        if receipt.get("request_digest").and_then(Value::as_str) != Some(digest) {
            return Err(DscIssuanceStoreError::Conflict(
                "idempotency key was reused with changed input",
            ));
        }
        receipt
            .get("result")
            .filter(|value| value.is_object())
            .cloned()
            .map(Some)
            .ok_or(DscIssuanceStoreError::Corrupt("issuance receipt result"))
    }

    pub async fn snapshot(
        &self,
        organization_id: &str,
    ) -> Result<DscIssuanceSnapshot, DscIssuanceStoreError> {
        let mut connection = self.connection.clone();
        let keys = [
            profiles::storage_key(organization_id),
            registry::storage_key(organization_id),
            csca_lifecycle::csca_lifecycle_storage_key(organization_id),
            documents::certificate_storage_key(organization_id),
        ];
        let raw: Vec<Option<String>> = redis::cmd("MGET")
            .arg(&keys)
            .query_async(&mut connection)
            .await
            .map_err(|error| DscIssuanceStoreError::Storage(error.to_string()))?;
        if raw.len() != 4 {
            return Err(DscIssuanceStoreError::Corrupt("snapshot size"));
        }
        let parsed = raw
            .iter()
            .map(|part| match part {
                Some(payload) => serde_json::from_str::<Value>(payload)
                    .map_err(|_| DscIssuanceStoreError::Corrupt("snapshot JSON")),
                None => Ok(Value::Null),
            })
            .collect::<Result<Vec<_>, _>>()?;
        if parsed
            .iter()
            .any(|value| !value.is_null() && !value.is_object())
        {
            return Err(DscIssuanceStoreError::Corrupt("snapshot document"));
        }
        Ok(DscIssuanceSnapshot {
            profiles: parsed[0].clone(),
            registry: parsed[1].clone(),
            lifecycle: parsed[2].clone(),
            certificates: parsed[3].clone(),
            raw,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn commit(
        &self,
        claim: &DscClaim,
        snapshot: &DscIssuanceSnapshot,
        lease: &RotationLease,
        dsc_profile_id: &str,
        csca_profile_id: &str,
        csca_certificate_id: &str,
        actor_id: &str,
        serial_hex: &str,
        attachment: Value,
        public_result: Value,
    ) -> Result<CommitDscIssuance, DscIssuanceStoreError> {
        if !lease.covers_organization(&claim.organization_id) {
            return Err(DscIssuanceStoreError::Conflict(
                "tenant signing lease is unavailable",
            ));
        }
        if !valid_serial(serial_hex)
            || dsc_profile_id.is_empty()
            || csca_profile_id.is_empty()
            || csca_certificate_id.is_empty()
            || actor_id.trim().is_empty()
            || actor_id.len() > 256
            || actor_id.chars().any(char::is_control)
        {
            return Err(DscIssuanceStoreError::Invalid(
                "certificate identity or serial",
            ));
        }
        if !attachment.is_object()
            || !public_result.is_object()
            || forbidden_public_data(&public_result)
            || contains_private_key(&public_result)
            || contains_private_key(&attachment)
            || attachment
                .get("cert_pem")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                != public_result.get("certificate_pem").and_then(Value::as_str)
            || attachment.get("cert_chain_pem").and_then(Value::as_str)
                != public_result.get("chain_pem").and_then(Value::as_str)
        {
            return Err(DscIssuanceStoreError::Invalid(
                "public certificate result contains signing coordinates",
            ));
        }
        if let Some(receipt) = snapshot
            .certificates
            .pointer(&format!("/{RECEIPTS}/{}", claim.receipt_id))
        {
            if receipt.get("request_digest").and_then(Value::as_str) != Some(&claim.request_digest)
            {
                return Err(DscIssuanceStoreError::Conflict(
                    "idempotency key was reused with changed input",
                ));
            }
            return receipt
                .get("result")
                .filter(|value| value.is_object())
                .cloned()
                .map(CommitDscIssuance::Completed)
                .ok_or(DscIssuanceStoreError::Corrupt("issuance receipt result"));
        }
        // A renewed CSCA certificate can retain the same signing profile/key.
        // Reserve across that profile, not just within one certificate ID.
        let serial_id = format!("{csca_profile_id}:{serial_hex}");
        let mut document = if snapshot.certificates.is_null() {
            json!({"services": {}})
        } else {
            snapshot.certificates.clone()
        };
        if document
            .get(SERIALS)
            .and_then(Value::as_object)
            .is_some_and(|serials| serials.contains_key(&serial_id))
        {
            return Err(DscIssuanceStoreError::Conflict(
                "CSCA serial is already reserved",
            ));
        }
        let Some(object) = document.as_object_mut() else {
            return Err(DscIssuanceStoreError::Corrupt("certificate document"));
        };
        object.insert("updated_at".into(), Value::String(Utc::now().to_rfc3339()));
        let profiles = object
            .entry("profiles")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or(DscIssuanceStoreError::Corrupt("certificate profiles"))?;
        if profiles.get(dsc_profile_id).is_some_and(|prior| {
            [
                "cert_pem",
                "cert_chain_pem",
                "cert_expires_at",
                "public_jwk",
                "x5c",
                "signing_key_reference",
            ]
            .iter()
            .any(|field| prior.get(*field) != attachment.get(*field))
        }) {
            return Err(DscIssuanceStoreError::Conflict(
                "DSC profile already has a different certificate",
            ));
        }
        profiles.insert(dsc_profile_id.into(), attachment);
        let receipt = json!({
            "request_digest": claim.request_digest,
            "dsc_profile_id": dsc_profile_id,
            "csca_profile_id": csca_profile_id,
            "csca_certificate_id": csca_certificate_id,
            "actor_id": actor_id,
            "authorized_permission": "passport-certificate:issue",
            "issued_at": Utc::now().to_rfc3339(),
            "serial": serial_hex,
            "result": public_result,
        });
        object
            .entry(RECEIPTS)
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or(DscIssuanceStoreError::Corrupt("issuance receipts"))?
            .insert(claim.receipt_id.clone(), receipt);
        object
            .entry(SERIALS)
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or(DscIssuanceStoreError::Corrupt("issuance serials"))?
            .insert(serial_id, Value::String(claim.receipt_id.clone()));
        let replacement = serde_json::to_string(&document)
            .map_err(|_| DscIssuanceStoreError::Invalid("certificate document cannot serialize"))?;
        let pending =
            json!({"owner": claim.owner, "request_digest": claim.request_digest}).to_string();
        let script = redis::Script::new(
            "if redis.call('GET', KEYS[5]) ~= ARGV[9] then return -1 end
             if redis.call('GET', KEYS[6]) ~= ARGV[10] then return -2 end
             for i = 1, 4 do
               local current = redis.call('GET', KEYS[i])
               local expected = ARGV[(i - 1) * 2 + 1]
               local prior = ARGV[(i - 1) * 2 + 2]
               if expected == '0' then
                 if current then return 0 end
               elseif current ~= prior then
                 return 0
               end
             end
             redis.call('SET', KEYS[4], ARGV[11])
             return 1",
        );
        let mut invocation = script.prepare_invoke();
        invocation
            .key(profiles::storage_key(&claim.organization_id))
            .key(registry::storage_key(&claim.organization_id))
            .key(csca_lifecycle::csca_lifecycle_storage_key(
                &claim.organization_id,
            ))
            .key(documents::certificate_storage_key(&claim.organization_id))
            .key(lease.redis_key())
            .key(&claim.pending_key);
        for prior in &snapshot.raw {
            invocation.arg(if prior.is_some() { "1" } else { "0" });
            invocation.arg(prior.as_deref().unwrap_or_default());
        }
        let mut connection = self.connection.clone();
        let saved: i32 = invocation
            .arg(lease.owner())
            .arg(pending)
            .arg(replacement)
            .invoke_async(&mut connection)
            .await
            .map_err(|error| DscIssuanceStoreError::Storage(error.to_string()))?;
        match saved {
            1 => {
                let _ = self.release(claim).await;
                Ok(CommitDscIssuance::Committed(public_result))
            }
            0 => {
                if let Some(result) = self
                    .completed(
                        &claim.organization_id,
                        &claim.receipt_id,
                        &claim.request_digest,
                    )
                    .await?
                {
                    Ok(CommitDscIssuance::Completed(result))
                } else {
                    Err(DscIssuanceStoreError::Conflict(
                        "profile, registry, CSCA, or certificate state changed",
                    ))
                }
            }
            -1 => Err(DscIssuanceStoreError::Conflict(
                "tenant signing lease expired",
            )),
            -2 => Err(DscIssuanceStoreError::Conflict("idempotency claim expired")),
            _ => Err(DscIssuanceStoreError::Corrupt("commit result")),
        }
    }

    pub async fn release(&self, claim: &DscClaim) -> Result<(), DscIssuanceStoreError> {
        let mut connection = self.connection.clone();
        let pending =
            json!({"owner": claim.owner, "request_digest": claim.request_digest}).to_string();
        let _: i32 = redis::Script::new(
            "if redis.call('GET', KEYS[1]) == ARGV[1] then
               return redis.call('DEL', KEYS[1])
             end
             return 0",
        )
        .key(&claim.pending_key)
        .arg(pending)
        .invoke_async(&mut connection)
        .await
        .map_err(|error| DscIssuanceStoreError::Storage(error.to_string()))?;
        Ok(())
    }
}

fn valid_serial(value: &str) -> bool {
    if value.is_empty() || value.len() > 40 || !value.len().is_multiple_of(2) {
        return false;
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(digits, 16).ok()
        })
        .collect::<Option<Vec<_>>>();
    let Some(bytes) = bytes else {
        return false;
    };
    if bytes.iter().all(|byte| *byte == 0) {
        return false;
    }
    // DER INTEGER must be positive and minimally encoded.
    bytes[0] & 0x80 == 0 && (bytes.len() == 1 || bytes[0] != 0 || bytes[1] & 0x80 != 0)
}

fn forbidden_public_data(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(key, value)| {
            [
                "key_reference",
                "service_config",
                "auth_reference",
                "token",
            ]
            .contains(&key.as_str())
                || forbidden_public_data(value)
        }),
        Value::Array(items) => items.iter().any(forbidden_public_data),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        documents::{DocumentStore, InspectCertificateRequest},
        profiles::ProfileStore,
        registry::RegistryStore,
    };

    fn disposable_redis_url() -> String {
        let url = std::env::var("MARTY_TEST_REDIS_URL").expect("disposable Redis URL");
        let parsed = reqwest::Url::parse(&url).expect("Redis URL");
        assert!(
            matches!(parsed.host_str(), Some("127.0.0.1" | "localhost" | "::1")),
            "Redis must be loopback"
        );
        assert!(
            parsed
                .path()
                .trim_start_matches('/')
                .parse::<u8>()
                .is_ok_and(|db| db >= 13),
            "Redis test must use DB >= 13"
        );
        url
    }

    #[test]
    fn serials_are_positive_minimal_der_integers() {
        for serial in ["01", "7f", "00ff", "0100"] {
            assert!(valid_serial(serial));
        }
        let too_long = "01".repeat(21);
        for serial in [
            "",
            "00",
            "80",
            "ff",
            "007f",
            "0001",
            "zz",
            "1",
            too_long.as_str(),
        ] {
            assert!(!valid_serial(serial), "accepted {serial}");
        }
    }

    #[tokio::test]
    #[ignore = "requires disposable MARTY_TEST_REDIS_URL on loopback DB >= 13"]
    async fn profile_cas_preserves_unrelated_edits_and_upgrades_legacy_revision() {
        let url = disposable_redis_url();
        let registry = RegistryStore::connect(&url).await.unwrap();
        let store = ProfileStore::from_connection(registry.connection());
        let organization_id = format!("test-dsc-profile-cas-{}", Uuid::new_v4().simple());
        let mut connection = registry.connection();
        let key = profiles::storage_key(&organization_id);
        connection
            .set::<_, _, ()>(&key, json!({"profiles": []}).to_string())
            .await
            .unwrap();
        let first = store.put(
            &organization_id,
            "a",
            json!({"id":"a","organization_id":organization_id}),
        );
        let second = store.put(
            &organization_id,
            "b",
            json!({"id":"b","organization_id":organization_id}),
        );
        let (first, second) = tokio::join!(first, second);
        first.unwrap();
        second.unwrap();
        let document = store.list(&organization_id).await.unwrap();
        assert_eq!(document["revision"], 2);
        assert_eq!(document["profiles"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    #[ignore = "requires disposable MARTY_TEST_REDIS_URL on loopback DB >= 13"]
    async fn issued_certificate_commit_is_idempotent_and_preserved_by_parallel_writers() {
        let url = disposable_redis_url();
        let registry = RegistryStore::connect(&url).await.unwrap();
        let connection = registry.connection();
        let store = DscIssuanceStore::from_connection(connection.clone());
        let profiles = ProfileStore::from_connection(connection.clone());
        let documents = DocumentStore::from_connection(connection.clone());
        let organization_id = format!("test-dsc-issuance-{}", Uuid::new_v4().simple());
        profiles
            .put(
                &organization_id,
                "dsc",
                json!({"id":"dsc","organization_id":organization_id}),
            )
            .await
            .unwrap();
        profiles
            .put(
                &organization_id,
                "csca",
                json!({"id":"csca","organization_id":organization_id}),
            )
            .await
            .unwrap();
        let mut connection = connection.clone();
        connection
            .set::<_, _, ()>(
                registry::storage_key(&organization_id),
                json!({"services":[]}).to_string(),
            )
            .await
            .unwrap();
        connection
            .set::<_, _, ()>(
                csca_lifecycle::csca_lifecycle_storage_key(&organization_id),
                json!({"revision":1}).to_string(),
            )
            .await
            .unwrap();
        let lease = registry
            .acquire_rotation_lease(&organization_id)
            .await
            .unwrap()
            .unwrap();
        let claim = match store
            .begin(&organization_id, "request-1", "digest-1")
            .await
            .unwrap()
        {
            BeginDscIssuance::Claim(claim) => claim,
            _ => panic!("first request must claim"),
        };
        assert!(matches!(
            store
                .begin(&organization_id, "request-1", "digest-1")
                .await
                .unwrap(),
            BeginDscIssuance::Pending
        ));
        assert!(matches!(
            store.begin(&organization_id, "request-1", "changed").await,
            Err(DscIssuanceStoreError::Conflict(_))
        ));
        let snapshot = store.snapshot(&organization_id).await.unwrap();
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/document_vectors.json")).unwrap();
        let cert = fixture["certificate"]["cert_pem"]
            .as_str()
            .unwrap()
            .to_owned();
        let inspected = crate::documents::inspect_certificate(&InspectCertificateRequest {
            cert_pem: cert.clone(),
            cert_chain_pem: None,
            expected_public_jwk: None,
        })
        .unwrap();
        let attachment = json!({
            "cert_pem":cert.clone(),"cert_chain_pem":"","cert_expires_at":inspected.expires_at,
            "public_jwk":inspected.public_jwk,"x5c":inspected.x5c,
            "signing_key_reference":"private-internal-ref"
        });
        let result = json!({"certificate_pem":cert.clone(),"chain_pem":"","status":"issued"});
        let mut private_attachment = attachment.clone();
        private_attachment["metadata"] =
            json!({"nested": "{\"kty\":\"EC\",\"d\":\"forbidden-private-scalar\"}"});
        assert!(matches!(
            store
                .commit(
                    &claim,
                    &snapshot,
                    &lease,
                    "dsc",
                    "csca",
                    "csca-1",
                    "operator-test",
                    "01",
                    private_attachment,
                    result.clone()
                )
                .await,
            Err(DscIssuanceStoreError::Invalid(_))
        ));
        let mut private_result = result.clone();
        private_result["metadata"] = json!({"kty":"EC","d":"forbidden-private-scalar"});
        assert!(matches!(
            store
                .commit(
                    &claim,
                    &snapshot,
                    &lease,
                    "dsc",
                    "csca",
                    "csca-1",
                    "operator-test",
                    "01",
                    attachment.clone(),
                    private_result
                )
                .await,
            Err(DscIssuanceStoreError::Invalid(_))
        ));
        assert!(matches!(
            store
                .commit(
                    &claim,
                    &snapshot,
                    &lease,
                    "dsc",
                    "csca",
                    "csca-1",
                    "operator-test",
                    "01",
                    attachment,
                    result.clone()
                )
                .await
                .unwrap(),
            CommitDscIssuance::Committed(_)
        ));
        assert!(
            matches!(store.begin(&organization_id, "request-1", "digest-1").await.unwrap(), BeginDscIssuance::Completed(value) if value == result)
        );
        assert!(matches!(
            store.begin(&organization_id, "request-1", "changed").await,
            Err(DscIssuanceStoreError::Conflict(_))
        ));
        profiles.delete(&organization_id, "dsc").await.unwrap();
        assert!(
            matches!(store.begin(&organization_id, "request-1", "digest-1").await.unwrap(), BeginDscIssuance::Completed(value) if value == result)
        );

        let mut writes = tokio::task::JoinSet::new();
        for index in 0..12 {
            let documents = documents.clone();
            let organization_id = organization_id.clone();
            let cert = cert.clone();
            writes.spawn(async move {
                documents
                    .store_certificate(
                        &organization_id,
                        &format!("service-{index}"),
                        InspectCertificateRequest {
                            cert_pem: cert,
                            cert_chain_pem: None,
                            expected_public_jwk: None,
                        },
                    )
                    .await
                    .unwrap();
            });
        }
        while let Some(result) = writes.join_next().await {
            result.unwrap();
        }
        let document = documents
            .certificate_overrides(&organization_id)
            .await
            .unwrap();
        assert_eq!(document[RECEIPTS].as_object().unwrap().len(), 1);
        assert_eq!(document[SERIALS].as_object().unwrap().len(), 1);
        assert_eq!(document["services"].as_object().unwrap().len(), 12);
        assert!(matches!(
            documents
                .store_profile_certificate(
                    &organization_id,
                    "dsc",
                    "different-internal-ref",
                    InspectCertificateRequest {
                        cert_pem: cert.clone(),
                        cert_chain_pem: None,
                        expected_public_jwk: None,
                    }
                )
                .await,
            Err(crate::documents::DocumentError::Conflict(_))
        ));
        assert!(matches!(
            documents
                .store_profile_certificate(
                    &organization_id,
                    "dsc",
                    "private-internal-ref",
                    InspectCertificateRequest {
                        cert_pem: cert.clone(),
                        cert_chain_pem: Some(cert.clone()),
                        expected_public_jwk: None,
                    }
                )
                .await,
            Err(crate::documents::DocumentError::Conflict(_))
        ));
        documents
            .store_profile_certificate(
                &organization_id,
                "dsc",
                "private-internal-ref",
                InspectCertificateRequest {
                    cert_pem: cert,
                    cert_chain_pem: None,
                    expected_public_jwk: None,
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires disposable MARTY_TEST_REDIS_URL on loopback DB >= 13"]
    async fn stale_profile_and_existing_attachment_cannot_commit() {
        let url = disposable_redis_url();
        let registry = RegistryStore::connect(&url).await.unwrap();
        let connection = registry.connection();
        let store = DscIssuanceStore::from_connection(connection.clone());
        let profiles = ProfileStore::from_connection(connection.clone());
        let organization_id = format!("test-dsc-stale-{}", Uuid::new_v4().simple());
        profiles
            .put(
                &organization_id,
                "dsc",
                json!({"id":"dsc","organization_id":organization_id}),
            )
            .await
            .unwrap();
        let mut connection = connection.clone();
        connection
            .set::<_, _, ()>(
                registry::storage_key(&organization_id),
                json!({"services":[]}).to_string(),
            )
            .await
            .unwrap();
        connection
            .set::<_, _, ()>(
                csca_lifecycle::csca_lifecycle_storage_key(&organization_id),
                json!({"revision":1}).to_string(),
            )
            .await
            .unwrap();
        let lease = registry
            .acquire_rotation_lease(&organization_id)
            .await
            .unwrap()
            .unwrap();
        let claim = match store
            .begin(&organization_id, "request-1", "digest-1")
            .await
            .unwrap()
        {
            BeginDscIssuance::Claim(claim) => claim,
            _ => panic!("first request must claim"),
        };
        let stale = store.snapshot(&organization_id).await.unwrap();
        profiles
            .put(
                &organization_id,
                "other",
                json!({"id":"other","organization_id":organization_id}),
            )
            .await
            .unwrap();
        assert!(matches!(
            store
                .commit(
                    &claim,
                    &stale,
                    &lease,
                    "dsc",
                    "csca",
                    "csca-1",
                    "operator-test",
                    "01",
                    json!({"cert_pem":"CERT-A"}),
                    json!({"certificate_pem":"CERT-A"})
                )
                .await,
            Err(DscIssuanceStoreError::Conflict(_))
        ));
        let cert_key = documents::certificate_storage_key(&organization_id);
        connection
            .set::<_, _, ()>(
                &cert_key,
                json!({"profiles":{"dsc":{"cert_pem":"OTHER"}}}).to_string(),
            )
            .await
            .unwrap();
        let current = store.snapshot(&organization_id).await.unwrap();
        assert!(matches!(
            store
                .commit(
                    &claim,
                    &current,
                    &lease,
                    "dsc",
                    "csca",
                    "csca-1",
                    "operator-test",
                    "03",
                    json!({"cert_pem":"CERT-A"}),
                    json!({"certificate_pem":"CERT-A"})
                )
                .await,
            Err(DscIssuanceStoreError::Conflict(_))
        ));
        assert!(store
            .completed(&organization_id, &claim.receipt_id, "digest-1")
            .await
            .unwrap()
            .is_none());
    }
}
