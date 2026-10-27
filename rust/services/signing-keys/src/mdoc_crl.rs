//! Public MDOC CRL state. A revoked serial and its signed CRL are one Redis commit.
//! No private key or untrusted publication URL is stored here.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD, Engine};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{csca_lifecycle, documents, profiles, registry, registry::RotationLease};

const SCHEMA: u32 = 1;

pub struct MdocCrlIdentity<'a> {
    pub organization_id: &'a str,
    pub issuer_did: &'a str,
    pub certificate_id: &'a str,
    pub cert_pem: &'a str,
    pub distribution_uri: &'a str,
}

pub fn valid_resource_id(organization_id: &str, certificate_id: &str) -> bool {
    uuid::Uuid::parse_str(organization_id)
        .ok()
        .map(|id| id.to_string())
        .as_deref()
        == Some(organization_id)
        && !certificate_id.is_empty()
        && certificate_id.len() <= 128
        && certificate_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedMdocDsc {
    pub receipt_id: String,
    pub serial_hex: String,
    pub revoked_at_unix: u64,
    pub reason: String,
    pub revoked_by: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GovernedMdocCrl {
    pub schema_version: u32,
    pub organization_id: String,
    pub issuer_did: String,
    pub iaca_certificate_id: String,
    pub iaca_certificate_sha256: String,
    pub distribution_uri: String,
    pub number: u64,
    pub this_update_unix: u64,
    pub next_update_unix: u64,
    pub revoked: BTreeMap<String, RevokedMdocDsc>,
    pub der_b64: String,
    pub published_by: String,
}

impl GovernedMdocCrl {
    pub fn new(
        identity: MdocCrlIdentity<'_>,
        this_update_unix: u64,
        next_update_unix: u64,
        actor_id: &str,
    ) -> Self {
        Self {
            schema_version: SCHEMA,
            organization_id: identity.organization_id.into(),
            issuer_did: identity.issuer_did.into(),
            iaca_certificate_id: identity.certificate_id.into(),
            iaca_certificate_sha256: format!("{:x}", Sha256::digest(identity.cert_pem.as_bytes())),
            distribution_uri: identity.distribution_uri.into(),
            number: 0,
            this_update_unix,
            next_update_unix,
            revoked: BTreeMap::new(),
            der_b64: String::new(),
            published_by: actor_id.into(),
        }
    }

    pub fn bound_to(
        &self,
        organization_id: &str,
        issuer_did: &str,
        certificate_id: &str,
        cert_pem: &str,
        distribution_uri: &str,
    ) -> bool {
        self.schema_version == SCHEMA
            && self.organization_id == organization_id
            && self.issuer_did == issuer_did
            && self.iaca_certificate_id == certificate_id
            && self.iaca_certificate_sha256 == format!("{:x}", Sha256::digest(cert_pem.as_bytes()))
            && self.distribution_uri == distribution_uri
            && self.next_update_unix > self.this_update_unix
            && self
                .revoked
                .iter()
                .all(|(id, entry)| id == &entry.receipt_id)
            && !self.published_by.is_empty()
            && self
                .revoked
                .values()
                .all(|entry| !entry.revoked_by.is_empty())
    }

    /// A missing or expired CRL cannot be interpreted as a good status.
    pub fn available_der(&self, now_unix: u64) -> Option<Vec<u8>> {
        if now_unix < self.this_update_unix || now_unix >= self.next_update_unix {
            return None;
        }
        STANDARD
            .decode(&self.der_b64)
            .ok()
            .filter(|der| !der.is_empty())
    }

    pub fn is_successor_of(&self, prior: &Self) -> bool {
        self.organization_id == prior.organization_id
            && self.issuer_did == prior.issuer_did
            && self.iaca_certificate_id == prior.iaca_certificate_id
            && self.iaca_certificate_sha256 == prior.iaca_certificate_sha256
            && self.distribution_uri == prior.distribution_uri
            && prior.number.checked_add(1) == Some(self.number)
            && self.this_update_unix > prior.this_update_unix
            && self.next_update_unix > prior.next_update_unix
            && prior
                .revoked
                .iter()
                .all(|(id, entry)| self.revoked.get(id) == Some(entry))
    }
}

#[derive(Debug, Error)]
pub enum MdocCrlError {
    #[error("MDOC CRL state changed")]
    Conflict,
    #[error("MDOC CRL state is malformed")]
    Corrupt,
    #[error("MDOC CRL storage unavailable")]
    Storage,
}

pub struct MdocCrlSnapshot {
    pub lifecycle: Value,
    pub certificates: Value,
    pub crl: Option<GovernedMdocCrl>,
    raw: Vec<Option<String>>,
}

impl MdocCrlSnapshot {
    pub fn same_raw(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

#[derive(Clone)]
pub struct MdocCrlStore {
    connection: ConnectionManager,
}

impl MdocCrlStore {
    pub fn from_connection(connection: ConnectionManager) -> Self {
        Self { connection }
    }

    pub async fn snapshot(
        &self,
        organization_id: &str,
        certificate_id: &str,
    ) -> Result<MdocCrlSnapshot, MdocCrlError> {
        if !valid_resource_id(organization_id, certificate_id) {
            return Err(MdocCrlError::Corrupt);
        }
        let keys = self.keys(organization_id, certificate_id);
        let mut connection = self.connection.clone();
        let raw: Vec<Option<String>> = redis::cmd("MGET")
            .arg(&keys)
            .query_async(&mut connection)
            .await
            .map_err(|_| MdocCrlError::Storage)?;
        if raw.len() != 5 {
            return Err(MdocCrlError::Corrupt);
        }
        let mut parsed = Vec::with_capacity(4);
        for part in &raw[..4] {
            let value = part
                .as_ref()
                .map(|raw| serde_json::from_str::<Value>(raw))
                .transpose()
                .map_err(|_| MdocCrlError::Corrupt)?
                .unwrap_or(Value::Null);
            if !value.is_null() && !value.is_object() {
                return Err(MdocCrlError::Corrupt);
            }
            parsed.push(value);
        }
        let crl = raw[4]
            .as_ref()
            .map(|raw| serde_json::from_str::<GovernedMdocCrl>(raw))
            .transpose()
            .map_err(|_| MdocCrlError::Corrupt)?;
        if crl.as_ref().is_some_and(|doc| {
            doc.schema_version != SCHEMA
                || doc.organization_id != organization_id
                || doc.iaca_certificate_id != certificate_id
        }) {
            return Err(MdocCrlError::Corrupt);
        }
        Ok(MdocCrlSnapshot {
            lifecycle: parsed[2].clone(),
            certificates: parsed[3].clone(),
            crl,
            raw,
        })
    }

    /// All four authorities and the prior CRL are compared by exact raw bytes
    /// under the same tenant rotation lease that governs certificate issuance.
    pub async fn commit(
        &self,
        lease: &RotationLease,
        snapshot: &MdocCrlSnapshot,
        replacement: &GovernedMdocCrl,
    ) -> Result<(), MdocCrlError> {
        if !lease.covers_organization(&replacement.organization_id)
            || !valid_resource_id(
                &replacement.organization_id,
                &replacement.iaca_certificate_id,
            )
            || replacement.schema_version != SCHEMA
            || replacement.next_update_unix <= replacement.this_update_unix
            || replacement.published_by.is_empty()
            || replacement.published_by.len() > 128
            || replacement.revoked.iter().any(|(id, entry)| {
                id != &entry.receipt_id
                    || entry.revoked_by.is_empty()
                    || entry.revoked_by.len() > 128
            })
            || replacement
                .available_der(replacement.this_update_unix)
                .is_none()
            || (snapshot.crl.is_none() && replacement.number != 0)
            || snapshot
                .crl
                .as_ref()
                .is_some_and(|prior| !replacement.is_successor_of(prior))
        {
            return Err(MdocCrlError::Corrupt);
        }
        let keys = self.keys(
            &replacement.organization_id,
            &replacement.iaca_certificate_id,
        );
        let script = redis::Script::new(
            "if redis.call('GET', KEYS[6]) ~= ARGV[11] then return -1 end
             for i = 1, 5 do
               local current = redis.call('GET', KEYS[i])
               local prior = ARGV[(i - 1) * 2 + 2]
               if ARGV[(i - 1) * 2 + 1] == '0' then
                 if current then return 0 end
               elseif current ~= prior then return 0 end
             end
             redis.call('SET', KEYS[5], ARGV[12])
             return 1",
        );
        let mut invoke = script.prepare_invoke();
        for key in &keys {
            invoke.key(key);
        }
        invoke.key(lease.redis_key());
        for prior in &snapshot.raw {
            invoke.arg(if prior.is_some() { "1" } else { "0" });
            invoke.arg(prior.as_deref().unwrap_or_default());
        }
        let replacement = serde_json::to_string(replacement).map_err(|_| MdocCrlError::Corrupt)?;
        let mut connection = self.connection.clone();
        let result: i32 = invoke
            .arg(lease.owner())
            .arg(replacement)
            .invoke_async(&mut connection)
            .await
            .map_err(|_| MdocCrlError::Storage)?;
        match result {
            1 => Ok(()),
            0 | -1 => Err(MdocCrlError::Conflict),
            _ => Err(MdocCrlError::Corrupt),
        }
    }

    fn keys(&self, organization_id: &str, certificate_id: &str) -> [String; 5] {
        [
            profiles::storage_key(organization_id),
            registry::storage_key(organization_id),
            csca_lifecycle::authority_lifecycle_storage_key(
                organization_id,
                marty_signing_grant::certificate_profile::CertificateFamily::Mdoc,
            ),
            documents::certificate_storage_key(organization_id),
            format!("signing:mdoc-crl:{organization_id}:{certificate_id}"),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbered_crl_successor_preserves_issuer_revocations_and_monotonic_time() {
        let identity = MdocCrlIdentity {
            organization_id: "00000000-0000-0000-0000-000000000001",
            issuer_did: "did:example:iaca",
            certificate_id: "iaca-1",
            cert_pem: "public certificate",
            distribution_uri: "https://issuer.example/iaca.crl",
        };
        let mut first = GovernedMdocCrl::new(identity, 100, 200, "operator");
        first.revoked.insert(
            "receipt".into(),
            RevokedMdocDsc {
                receipt_id: "receipt".into(),
                serial_hex: "01".into(),
                revoked_at_unix: 100,
                reason: "key_compromise".into(),
                revoked_by: "operator".into(),
            },
        );
        let mut next = first.clone();
        next.number = 1;
        next.this_update_unix = 101;
        next.next_update_unix = 201;
        assert!(next.is_successor_of(&first));
        next.this_update_unix = 100;
        assert!(!next.is_successor_of(&first));
        next.this_update_unix = 101;
        next.revoked.clear();
        assert!(!next.is_successor_of(&first));
        next = first.clone();
        next.number = 1;
        next.this_update_unix = 101;
        next.next_update_unix = 201;
        next.iaca_certificate_id = "foreign".into();
        assert!(!next.is_successor_of(&first));
    }
}
