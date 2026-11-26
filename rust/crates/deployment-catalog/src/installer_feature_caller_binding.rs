//! Carry only an already owner-bound native caller across certificate renewal.
//! The material owner authenticates the previous bytes and validates the new
//! helper leaf/chain before calling this pure projection. No principal, key or
//! governed authority is created here, and no provider operation is performed.
#![cfg(target_os = "linux")]

use marty_selfhost_identity::features::NATIVE_CALLER;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::collections::{BTreeMap, BTreeSet};
use x509_cert::{
    der::{DecodePem, Encode},
    ext::pkix::{name::GeneralName, SubjectAltName},
    Certificate,
};

type Result<T> = std::result::Result<T, String>;
const REFUSED: &str =
    "native caller renewal does not preserve its existing owner binding; preserve feature evidence";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RotationReceipt {
    pub(crate) schema: String,
    pub(crate) workload_uri: String,
    pub(crate) principal_id: String,
    pub(crate) previous_leaf_sha256: String,
    pub(crate) renewed_leaf_sha256: String,
    pub(crate) public_key_sha256: String,
    pub(crate) subject_sha256: String,
    pub(crate) previous_bindings_sha256: String,
    pub(crate) renewed_bindings_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    workload_uri: String,
    leaf_sha256: String,
    principal_id: String,
}

fn require(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(REFUSED.into())
    }
}

fn digest(bytes: &[u8]) -> String {
    crate::installer_release::sha256(bytes)
}

fn uri(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.is_ascii()
        && value.trim() == value
        && !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '\'' | '\\' | '$' | '`'))
        && url::Url::parse(value).is_ok_and(|url| {
            !url.scheme().is_empty()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
        })
}

fn native_leaf(bytes: &[u8]) -> Result<Certificate> {
    require(!bytes.is_empty() && bytes.len() <= 65_536)?;
    let certificate = Certificate::from_pem(bytes).map_err(|_| REFUSED)?;
    let body = &certificate.tbs_certificate;
    require(body.subject.to_string() == format!("CN={}", NATIVE_CALLER.common_name))?;
    let names = body
        .get::<SubjectAltName>()
        .map_err(|_| REFUSED)?
        .ok_or(REFUSED)?
        .1;
    let mut dns = BTreeSet::new();
    let mut uris = BTreeSet::new();
    for name in names.0 {
        match name {
            GeneralName::DnsName(value) if dns.insert(value.as_str().to_owned()) => {}
            GeneralName::UniformResourceIdentifier(value)
                if uris.insert(value.as_str().to_owned()) => {}
            _ => return Err(REFUSED.into()),
        }
    }
    require(
        dns == BTreeSet::from([NATIVE_CALLER.common_name.to_owned()])
            && uris == BTreeSet::from([NATIVE_CALLER.uri.to_owned()]),
    )?;
    Ok(certificate)
}

/// Only a matching prior native leaf may change its pin. Every byte outside
/// that one JSON string token is copied verbatim, including other entries,
/// principal spelling, field order and whitespace. The returned receipt is
/// authenticated by the caller's immutable material/parent receipt chain.
pub(crate) fn rotate(
    bindings: &[u8],
    previous_leaf: &[u8],
    renewed_leaf: &[u8],
) -> Result<(Vec<u8>, Option<RotationReceipt>)> {
    require(!bindings.is_empty() && bindings.len() <= 65_536)?;
    crate::installer_json::decode(bindings).map_err(|_| REFUSED)?;
    let entries: Vec<&RawValue> = serde_json::from_slice(bindings).map_err(|_| REFUSED)?;
    require((1..=128).contains(&entries.len()))?;
    let previous = native_leaf(previous_leaf)?;
    let renewed = native_leaf(renewed_leaf)?;
    let previous_key = previous
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| REFUSED)?;
    let renewed_key = renewed
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| REFUSED)?;
    require(
        previous_key == renewed_key
            && previous.tbs_certificate.subject == renewed.tbs_certificate.subject,
    )?;
    let previous_pin = format!(
        "sha256:{}",
        digest(&previous.to_der().map_err(|_| REFUSED)?)
    );
    let renewed_pin = format!("sha256:{}", digest(&renewed.to_der().map_err(|_| REFUSED)?));
    let mut native = None;
    let mut uris = BTreeSet::new();
    let mut pins = BTreeSet::new();
    for entry in entries {
        let binding: Binding = serde_json::from_str(entry.get()).map_err(|_| REFUSED)?;
        require(
            uri(&binding.workload_uri)
                && binding.workload_uri.starts_with("spiffe://")
                && uri(&binding.principal_id)
                && uris.insert(binding.workload_uri.clone())
                && binding
                    .leaf_sha256
                    .strip_prefix("sha256:")
                    .is_some_and(marty_selfhost_identity::features::hash)
                && pins.insert(binding.leaf_sha256.clone()),
        )?;
        if binding.workload_uri == NATIVE_CALLER.uri {
            require(binding.leaf_sha256 == previous_pin && native.is_none())?;
            let fields: BTreeMap<String, &RawValue> =
                serde_json::from_str(entry.get()).map_err(|_| REFUSED)?;
            native = Some((binding, fields.get("leaf_sha256").ok_or(REFUSED)?.get()));
        } else {
            // A native owned leaf cannot be relabeled as an external workload,
            // and the replacement may not collide with an unrelated binding.
            require(binding.leaf_sha256 != previous_pin && binding.leaf_sha256 != renewed_pin)?;
        }
    }
    let Some((binding, old_token)) = native else {
        return Ok((bindings.to_vec(), None));
    };
    if previous_pin == renewed_pin {
        return Ok((bindings.to_vec(), None));
    }
    let start = (old_token.as_ptr() as usize)
        .checked_sub(bindings.as_ptr() as usize)
        .ok_or(REFUSED)?;
    let end = start.checked_add(old_token.len()).ok_or(REFUSED)?;
    require(bindings.get(start..end) == Some(old_token.as_bytes()))?;
    let token = serde_json::to_vec(&renewed_pin).map_err(|_| REFUSED)?;
    let mut updated = Vec::with_capacity(bindings.len() - old_token.len() + token.len());
    updated.extend_from_slice(&bindings[..start]);
    updated.extend_from_slice(&token);
    updated.extend_from_slice(&bindings[end..]);
    require(updated.len() <= 65_536)?;
    let receipt = RotationReceipt {
        schema: "elevenid.installer-native-caller-binding-renewal/v1".into(),
        workload_uri: binding.workload_uri,
        principal_id: binding.principal_id,
        previous_leaf_sha256: previous_pin,
        renewed_leaf_sha256: renewed_pin,
        public_key_sha256: digest(&previous_key),
        subject_sha256: digest(
            &previous
                .tbs_certificate
                .subject
                .to_der()
                .map_err(|_| REFUSED)?,
        ),
        previous_bindings_sha256: digest(bindings),
        renewed_bindings_sha256: digest(&updated),
    };
    Ok((updated, Some(receipt)))
}

#[cfg(test)]
#[path = "installer_feature_caller_binding_tests.rs"]
mod tests;
