//! Closed negotiation for the initial whole-credential JWT-VC DCQL slice.
//! These values describe a request; they are never authentication evidence.

use std::collections::BTreeSet;

pub use marty_oid4vci::{JwtVcProfileBinding, JwtVcSecuringProfile};
use serde::{Deserialize, Deserializer};
use serde_json::Value;

use crate::Oid4vpContractError;

/// Omission is legacy. A present null is not an omitted opt-in.
pub fn deserialize_optional_profile<'de, D>(
    deserializer: D,
) -> Result<Option<JwtVcSecuringProfile>, D::Error>
where
    D: Deserializer<'de>,
{
    JwtVcSecuringProfile::deserialize(deserializer).map(Some)
}

/// Authorization identities remain distinct even though both are JWTs.
pub const fn policy_credential_format(profile: JwtVcSecuringProfile) -> &'static str {
    match profile {
        JwtVcSecuringProfile::MartyNestedVc2JwtV1 => "VC_JWT",
        JwtVcSecuringProfile::W3cVc2Jose2026V1 => "VC_JWT_DIRECT_V1",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfiledJwtVcQuery {
    pub id: String,
    pub binding: JwtVcProfileBinding,
    /// Canonical sets exclude the base VerifiableCredential type, as the
    /// existing frozen contract does. The exact raw query stays separately frozen.
    pub type_sets: Vec<Vec<String>>,
}

impl ProfiledJwtVcQuery {
    pub fn matches_types(&self, authenticated: &[String]) -> bool {
        self.type_sets
            .iter()
            .any(|types| types.iter().all(|kind| authenticated.contains(kind)))
    }
}

/// Inspect the complete raw document before any lossy typed projection.
/// A marked or direct request must be exactly one required type-only query.
/// An unmarked document returns None so its existing admission stays unchanged.
pub fn profiled_jwt_vc_query(
    document: &Value,
) -> Result<Option<ProfiledJwtVcQuery>, Oid4vpContractError> {
    let marked = document
        .get("credentials")
        .and_then(Value::as_array)
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry.pointer("/meta/marty_securing_profile").is_some()
                    || entry.get("format").and_then(Value::as_str) == Some("application/vc+jwt")
            })
        });
    if !marked {
        return Ok(None);
    }
    let invalid = || Oid4vpContractError::InvalidQueryDocument;
    if document.as_object().is_none_or(|object| object.len() != 1) {
        return Err(invalid());
    }
    let entries = document["credentials"]
        .as_array()
        .filter(|entries| entries.len() == 1)
        .ok_or_else(invalid)?;
    let entry = entries[0].as_object().ok_or_else(invalid)?;
    if entry.keys().any(|key| {
        ![
            "id",
            "format",
            "meta",
            "claims",
            "require_cryptographic_holder_binding",
        ]
        .contains(&key.as_str())
    }) || entry.get("require_cryptographic_holder_binding") != Some(&Value::Bool(true))
        || entry
            .get("claims")
            .is_some_and(|claims| claims.as_array().is_none_or(|claims| !claims.is_empty()))
    {
        return Err(invalid());
    }
    let id = entry
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| {
            !id.is_empty()
                && id.len() <= 128
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        })
        .ok_or_else(invalid)?;
    let meta = entry
        .get("meta")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    if meta.len() != 2 || !meta.contains_key("type_values") {
        return Err(invalid());
    }
    let binding = JwtVcProfileBinding::negotiate(
        meta.get("marty_securing_profile")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?,
        entry
            .get("format")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?,
    )
    .map_err(|_| invalid())?;
    let alternatives = meta["type_values"]
        .as_array()
        .filter(|sets| !sets.is_empty() && sets.len() <= 64)
        .ok_or_else(invalid)?;
    let mut type_sets = BTreeSet::new();
    for alternative in alternatives {
        let types = alternative
            .as_array()
            .filter(|types| !types.is_empty() && types.len() <= 64)
            .ok_or_else(invalid)?;
        let mut values = BTreeSet::new();
        for kind in types {
            let kind = kind
                .as_str()
                .filter(|kind| {
                    !kind.is_empty()
                        && kind.len() <= 2048
                        && kind.trim() == *kind
                        && !kind.chars().any(char::is_control)
                })
                .ok_or_else(invalid)?;
            if !values.insert(kind.to_owned()) {
                return Err(invalid());
            }
        }
        values.remove("VerifiableCredential");
        if values.is_empty() || !type_sets.insert(values.into_iter().collect::<Vec<_>>()) {
            return Err(invalid());
        }
    }
    Ok(Some(ProfiledJwtVcQuery {
        id: id.into(),
        binding,
        type_sets: type_sets.into_iter().collect(),
    }))
}
