//! Shared, side-effect-free Marty issuer bootstrap projections.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use marty_crypto::jwk::public_key_pem_to_jwk;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use thiserror::Error;

use crate::{documents, profiles, registry};

pub const MANAGED_SERVICE_ID: &str = "managed-openbao-transit";
pub const STANDARD_ISSUER_ES256_KEY_ID: &str = "cred-issuer-marty-es256";
pub const FLOW_ENVELOPE_KEY: &str = "flow-response-envelope-marty-aes256";
pub const NOTIFICATION_ENVELOPE_KEY: &str = "notification-webhook-envelope-marty-aes256";

#[derive(Debug, Error)]
pub enum BootstrapError {
    #[error("managed signing key has conflicting purpose bindings: {0}")]
    ConflictingPurpose(String),
    #[error("invalid bootstrap document: {0}")]
    InvalidDocument(&'static str),
    #[error("unsupported public key for {0}: {1}")]
    PublicKey(String, String),
}

#[derive(Clone, Copy, Debug)]
pub struct KeySpec {
    pub id: &'static str,
    pub name: &'static str,
    pub key_type: &'static str,
    pub algorithm: &'static str,
    pub purposes: &'static [&'static str],
    pub formats: &'static [&'static str],
}

pub const STANDARD_KEYS: &[KeySpec] = &[
    KeySpec {
        id: STANDARD_ISSUER_ES256_KEY_ID,
        name: "Marty ES256 issuer key",
        key_type: "ecdsa-p256",
        algorithm: "ES256",
        purposes: &["vc_jwt_issuer", "jwks_signing"],
        formats: &["jwt_vc_json", "dc+sd-jwt"],
    },
    KeySpec {
        id: "cred-issuer-marty-es384",
        name: "Marty ES384 issuer key",
        key_type: "ecdsa-p384",
        algorithm: "ES384",
        purposes: &["vc_jwt_issuer"],
        formats: &["jwt_vc_json", "dc+sd-jwt"],
    },
    KeySpec {
        id: "cred-issuer-marty-rs256",
        name: "Marty RS256 issuer key",
        key_type: "rsa-2048",
        algorithm: "RS256",
        purposes: &["vc_jwt_issuer"],
        formats: &["jwt_vc_json"],
    },
    KeySpec {
        id: "lti-tool-marty-rs256",
        name: "Marty LTI tool signing key",
        key_type: "rsa-2048",
        algorithm: "RS256",
        purposes: &["lti_tool_signing"],
        formats: &["lti_tool_jwt"],
    },
    KeySpec {
        id: "oid4vp-verifier-marty-es256",
        name: "Marty OID4VP verifier request key",
        key_type: "ecdsa-p256",
        algorithm: "ES256",
        purposes: &["oid4vp_request_signing"],
        formats: &["oauth-authz-req+jwt"],
    },
    KeySpec {
        id: "cred-issuer-marty-eddsa",
        name: "Marty EdDSA issuer key",
        key_type: "ed25519",
        algorithm: "EdDSA",
        purposes: &["vc_jwt_issuer", "jwks_signing"],
        formats: &["jwt_vc_json", "dc+sd-jwt", "ldp_vc"],
    },
    KeySpec {
        id: "cred-dsc-marty-primary",
        name: "Marty document signer key",
        key_type: "ecdsa-p256",
        algorithm: "ES256",
        purposes: &["mdoc_dsc", "vdsnc_signing"],
        formats: &["mso_mdoc", "vds_nc"],
    },
];

#[derive(Clone, Debug)]
pub struct KeyRecord {
    pub spec: KeySpec,
    pub reference: String,
    pub public_jwk: Value,
    pub latest_version: Value,
}

pub fn tenant_standard_key_reference(org: &str, id: &str) -> String {
    let prefix = crate::domain::MANAGED_KEY_PREFIXES
        .iter()
        .find(|prefix| id.starts_with(**prefix))
        .expect("standard bootstrap key has a managed prefix");
    let tenant = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, org.as_bytes())
        .simple()
        .to_string();
    format!("{prefix}{tenant}-{}", &id[prefix.len()..])
}

pub fn public_jwk_from_pem(spec: KeySpec, public_pem: &str) -> Result<Value, BootstrapError> {
    let parsed = public_key_pem_to_jwk(public_pem)
        .map_err(|error| BootstrapError::PublicKey(spec.id.into(), error.to_string()))?;
    let mut value = serde_json::to_value(parsed)
        .map_err(|error| BootstrapError::PublicKey(spec.id.into(), error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or(BootstrapError::InvalidDocument("public JWK"))?;
    object.insert("kid".into(), json!(spec.id));
    object.insert("alg".into(), json!(spec.algorithm));
    object.insert("use".into(), json!("sig"));
    object.retain(|_, value| !value.is_null());
    Ok(value)
}

pub fn public_jwk_from_openbao(spec: KeySpec, material: &str) -> Result<Value, BootstrapError> {
    if material.contains("BEGIN PUBLIC KEY") {
        return public_jwk_from_pem(spec, material);
    }
    if spec.key_type == "ed25519" {
        let raw = STANDARD
            .decode(material)
            .map_err(|error| BootstrapError::PublicKey(spec.id.into(), error.to_string()))?;
        if raw.len() != 32 {
            return Err(BootstrapError::PublicKey(
                spec.id.into(),
                "Ed25519 public key must have 32 bytes".into(),
            ));
        }
        return Ok(
            json!({"kty":"OKP", "crv":"Ed25519", "x":URL_SAFE_NO_PAD.encode(raw),
            "kid":spec.id, "alg":spec.algorithm, "use":"sig"}),
        );
    }
    Err(BootstrapError::PublicKey(
        spec.id.into(),
        "unsupported OpenBao public key format".into(),
    ))
}

pub fn signing_registry_key(org: &str) -> String {
    registry::storage_key(org)
}
pub fn issuer_profiles_key(org: &str) -> String {
    profiles::storage_key(org)
}
pub fn did_key(org: &str, did: Option<&str>) -> String {
    documents::did_storage_key(org, did)
}
pub fn jwks_key(org: &str) -> String {
    documents::jwks_storage_key(org)
}

fn object_or_empty(existing: Option<Value>) -> Map<String, Value> {
    existing
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
}

pub fn seed_signing_registry(
    existing: Option<Value>,
    records: &[KeyRecord],
) -> Result<Value, BootstrapError> {
    let mut doc = object_or_empty(existing);
    let purposes: BTreeSet<&str> = records
        .iter()
        .flat_map(|record| record.spec.purposes.iter().copied())
        .collect();
    let formats: BTreeSet<&str> = records
        .iter()
        .flat_map(|record| record.spec.formats.iter().copied())
        .collect();
    // Signing Keys derives the managed OpenBao service from live inventory on
    // read. Storing it here would make the registry fail its own stored-service
    // validation, which correctly forbids persisted mounted service tokens.
    let mut services = Vec::new();
    if let Some(existing) = doc.get("services").and_then(Value::as_array) {
        services.extend(
            existing
                .iter()
                .filter(|service| {
                    service.as_object().is_some()
                        && service.get("id").and_then(Value::as_str) != Some(MANAGED_SERVICE_ID)
                })
                .cloned(),
        );
    }
    doc.insert("services".into(), Value::Array(services));
    if !doc.get("default_service_id").is_some_and(python_truthy) {
        doc.insert("default_service_id".into(), json!(MANAGED_SERVICE_ID));
    }
    for (field, values) in [("format_defaults", &formats), ("type_defaults", &purposes)] {
        let mut defaults = object_or_empty(doc.remove(field));
        for value in values {
            defaults
                .entry(*value)
                .or_insert_with(|| json!(MANAGED_SERVICE_ID));
        }
        doc.insert(field.into(), Value::Object(defaults));
    }
    let mut all_bindings = object_or_empty(doc.remove("key_reference_purposes"));
    let mut managed_bindings = object_or_empty(all_bindings.remove(MANAGED_SERVICE_ID));
    for record in records {
        let purposes = json!(record.spec.purposes);
        if let Some(previous) = managed_bindings.get(&record.reference) {
            // The registry normalizes purpose lists into sorted, deduplicated
            // arrays. A restart must accept that representation of the same
            // binding while still rejecting a changed or malformed binding.
            let stored_purposes = previous.as_array().and_then(|values| {
                values
                    .iter()
                    .map(Value::as_str)
                    .collect::<Option<BTreeSet<_>>>()
            });
            let expected_purposes: BTreeSet<&str> = record.spec.purposes.iter().copied().collect();
            if stored_purposes.as_ref() != Some(&expected_purposes) {
                return Err(BootstrapError::ConflictingPurpose(record.reference.clone()));
            }
        }
        managed_bindings.insert(record.reference.clone(), purposes);
    }
    all_bindings.insert(MANAGED_SERVICE_ID.into(), Value::Object(managed_bindings));
    doc.insert("key_reference_purposes".into(), Value::Object(all_bindings));
    Ok(Value::Object(doc))
}

fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|number| number != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}

pub fn backfill_scoped_did_documents(
    legacy: &Value,
    org: &str,
    mut load: impl FnMut(&str) -> Option<Value>,
) -> Result<Vec<(String, Value)>, BootstrapError> {
    let Some(methods) = legacy.get("verificationMethod").and_then(Value::as_array) else {
        return Ok(vec![]);
    };
    let mut controllers: Vec<(String, Vec<Value>)> = vec![];
    for method in methods {
        let (Some(controller), Some(id)) = (
            method.get("controller").and_then(Value::as_str),
            method.get("id").and_then(Value::as_str),
        ) else {
            continue;
        };
        if !controller.starts_with("did:")
            || !(id == controller || id.starts_with(&format!("{controller}#")))
        {
            continue;
        }
        if let Some((_, values)) = controllers.iter_mut().find(|(name, _)| name == controller) {
            values.push(method.clone());
        } else {
            controllers.push((controller.into(), vec![method.clone()]));
        }
    }
    let mut writes = vec![];
    for (controller, controller_methods) in controllers {
        let key = did_key(org, Some(&controller));
        if let Some(existing) = load(&key) {
            if existing
                .as_object()
                .is_some_and(|object| !object.is_empty())
            {
                if existing.get("id").and_then(Value::as_str) != Some(&controller) {
                    return Err(BootstrapError::InvalidDocument(
                        "scoped DID identity mismatch",
                    ));
                }
                continue;
            }
        }
        let mut scoped = json!({"id": controller, "controller": controller,
            "verificationMethod": controller_methods});
        for relationship in [
            "authentication",
            "assertionMethod",
            "capabilityInvocation",
            "capabilityDelegation",
        ] {
            if let Some(entries) = legacy.get(relationship).and_then(Value::as_array) {
                let selected: Vec<Value> = entries
                    .iter()
                    .filter(|entry| {
                        let id = entry
                            .get("id")
                            .and_then(Value::as_str)
                            .or_else(|| entry.as_str());
                        id.is_some_and(|id| {
                            id == controller || id.starts_with(&format!("{controller}#"))
                        })
                    })
                    .cloned()
                    .collect();
                if !selected.is_empty() {
                    scoped[relationship] = json!(selected);
                }
            }
        }
        if legacy
            .get("@context")
            .is_some_and(|value| value.is_string() || value.is_array() || value.is_object())
        {
            scoped["@context"] = legacy["@context"].clone();
        }
        if legacy.get("updated_at").is_some_and(Value::is_string) {
            scoped["updated_at"] = legacy["updated_at"].clone();
        }
        writes.push((key, scoped));
    }
    Ok(writes)
}

pub fn seed_did_and_jwks(
    existing: Option<Value>,
    org: &str,
    issuer_did: &str,
    records: &[KeyRecord],
) -> (Value, Value) {
    let mut doc = object_or_empty(existing);
    doc.insert("id".into(), json!(issuer_did));
    doc.insert("controller".into(), json!(issuer_did));
    let key_ids: BTreeSet<&str> = records
        .iter()
        .flat_map(|record| [record.reference.as_str(), record.spec.id])
        .collect();
    let mut methods: Vec<Value> = vec![];
    if let Some(existing) = doc.get("verificationMethod").and_then(Value::as_array) {
        for method in existing {
            let is_managed = method
                .get("publicKeyJwk")
                .and_then(|jwk| jwk.get("kid"))
                .and_then(Value::as_str)
                .is_some_and(|kid| key_ids.contains(kid));
            if method.get("id").and_then(Value::as_str).is_some() && !is_managed {
                if let Some(position) = methods
                    .iter()
                    .position(|prior| prior.get("id") == method.get("id"))
                {
                    methods[position] = method.clone();
                } else {
                    methods.push(method.clone());
                }
            }
        }
    }
    let mut assertion: Vec<Value> = doc
        .get("assertionMethod")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| {
                    entry.as_str().is_some_and(|id| {
                        !key_ids.iter().any(|key| {
                            id.ends_with(&format!("#{}", documents::did_fragment("", Some(key))))
                        })
                    })
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let mut keys = vec![];
    for record in records {
        let vm_id = format!(
            "{issuer_did}#{}",
            documents::did_fragment("", Some(&record.reference))
        );
        let mut jwk = record.public_jwk.clone();
        if let Some(object) = jwk.as_object_mut() {
            object.insert("kid".into(), json!(record.reference));
        }
        let method = json!({"id": vm_id, "type": "JsonWebKey", "controller": issuer_did,
            "publicKeyJwk": jwk});
        if let Some(position) = methods
            .iter()
            .position(|prior| prior.get("id") == method.get("id"))
        {
            methods[position] = method;
        } else {
            methods.push(method);
        }
        if !assertion.contains(&json!(vm_id)) {
            assertion.push(json!(vm_id));
        }
        if !record.spec.purposes.contains(&"lti_tool_signing") {
            keys.push(jwk);
        }
    }
    doc.insert("verificationMethod".into(), json!(methods));
    doc.insert("assertionMethod".into(), json!(assertion));
    (
        Value::Object(doc),
        json!({"keys": keys, "organization_id": org}),
    )
}

#[derive(Clone, Copy)]
pub struct ProfileSpec {
    pub id: &'static str,
    pub name: &'static str,
    pub key: &'static str,
    pub purpose: &'static str,
    pub format: &'static str,
    pub algorithm: &'static str,
}

pub const STANDARD_PROFILES: &[ProfileSpec] = &[
    ProfileSpec {
        id: "ip-marty-vc-jwt-issuer",
        name: "Marty VC issuer",
        key: "cred-issuer-marty-es256",
        purpose: "vc_jwt_issuer",
        format: "VC_JWT",
        algorithm: "ES256",
    },
    ProfileSpec {
        id: "ip-marty-sd-jwt-issuer",
        name: "Marty SD-JWT VC issuer",
        key: "cred-issuer-marty-es256",
        purpose: "vc_jwt_issuer",
        format: "SD_JWT_VC",
        algorithm: "ES256",
    },
    ProfileSpec {
        id: "ip-marty-oid4vp-verifier",
        name: "Marty OID4VP verifier",
        key: "oid4vp-verifier-marty-es256",
        purpose: "oid4vp_request_signing",
        format: "SD_JWT_VC",
        algorithm: "ES256",
    },
    ProfileSpec {
        id: "ip-marty-canvas-lti-tool",
        name: "Marty Canvas LTI tool",
        key: "lti-tool-marty-rs256",
        purpose: "lti_tool_signing",
        format: "VC_JWT",
        algorithm: "RS256",
    },
    ProfileSpec {
        id: "ip-marty-mdoc-dsc",
        name: "Marty mDoc document signer",
        key: "cred-dsc-marty-primary",
        purpose: "mdoc_dsc",
        format: "MDOC",
        algorithm: "ES256",
    },
    ProfileSpec {
        id: "ip-marty-vdsnc-issuer",
        name: "Marty VDS-NC document signer",
        key: "cred-dsc-marty-primary",
        purpose: "vdsnc_signing",
        format: "MDOC",
        algorithm: "ES256",
    },
];

pub fn seed_issuer_profiles(
    existing: Option<Value>,
    org: &str,
    issuer_did: &str,
    issuer_url: &str,
) -> Value {
    let mut doc = object_or_empty(existing);
    let mut by_id: Vec<Value> = vec![];
    if let Some(profiles) = doc.get("profiles").and_then(Value::as_array) {
        for profile in profiles {
            if let Some(id) = profile.get("id").and_then(Value::as_str) {
                if let Some(position) = by_id
                    .iter()
                    .position(|prior| prior.get("id").and_then(Value::as_str) == Some(id))
                {
                    by_id[position] = profile.clone();
                } else {
                    by_id.push(profile.clone());
                }
            }
        }
    }
    for spec in STANDARD_PROFILES {
        let existing = by_id
            .iter()
            .position(|profile| profile.get("id").and_then(Value::as_str) == Some(spec.id));
        let key_reference = tenant_standard_key_reference(org, spec.key);
        let mut profile = json!({
            "id": spec.id, "organization_id": org, "name": spec.name,
            "issuer_did": issuer_did, "issuer_url": issuer_url,
            "signing_service_id": MANAGED_SERVICE_ID,
            "signing_key_reference": key_reference,
            "verification_method_id": format!("{issuer_did}#{}", documents::did_fragment("", Some(&key_reference))),
            "key_purpose": spec.purpose, "credential_format": spec.format,
            "algorithm": spec.algorithm, "status": "active",
        });
        if let Some(position) = existing {
            profile["created_at"] = by_id[position]
                .get("created_at")
                .cloned()
                .unwrap_or(Value::Null);
            by_id[position] = profile;
        } else {
            by_id.push(profile);
        }
    }
    by_id.sort_by_key(|profile| {
        if STANDARD_PROFILES
            .iter()
            .any(|spec| profile.get("id").and_then(Value::as_str) == Some(spec.id))
        {
            0
        } else {
            1
        }
    });
    let mut bindings: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut result = vec![];
    for profile in by_id {
        if profile
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case("active"))
        {
            let fields = [
                "organization_id",
                "issuer_did",
                "signing_service_id",
                "signing_key_reference",
                "key_purpose",
                "credential_format",
                "algorithm",
            ];
            let binding: Vec<String> = fields
                .iter()
                .map(|field| {
                    profile
                        .get(*field)
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string()
                })
                .collect();
            if binding.iter().all(|value| !value.is_empty()) && !bindings.insert(binding) {
                continue;
            }
        }
        result.push(profile);
    }
    doc.insert("profiles".into(), json!(result));
    Value::Object(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> Value {
        serde_json::from_str(include_str!(
            "../../../../contracts/migration-bootstrap-python-reference.json"
        ))
        .expect("committed Python reference corpus")
    }

    fn case(name: &str) -> Value {
        corpus()["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|case| case["name"] == name)
            .expect("named case")
            .clone()
    }

    fn records(clean: &Value) -> Vec<KeyRecord> {
        let pems = &clean["input"]["public_pem_by_type"];
        let org = clean["input"]["environment"]["MARTY_ORG_ID"]
            .as_str()
            .unwrap();
        STANDARD_KEYS
            .iter()
            .map(|spec| {
                let public_jwk =
                    public_jwk_from_pem(*spec, pems[spec.key_type].as_str().unwrap()).unwrap();
                KeyRecord {
                    spec: *spec,
                    reference: tenant_standard_key_reference(org, spec.id),
                    public_jwk,
                    latest_version: json!(1),
                }
            })
            .collect()
    }

    fn scoped_historical_expected(value: &Value, org: &str) -> Value {
        fn replace(value: &str, org: &str) -> String {
            STANDARD_KEYS.iter().fold(value.to_owned(), |text, spec| {
                text.replace(spec.id, &tenant_standard_key_reference(org, spec.id))
            })
        }
        match value {
            Value::String(text) => json!(replace(text, org)),
            Value::Array(values) => json!(values
                .iter()
                .map(|value| scoped_historical_expected(value, org))
                .collect::<Vec<_>>()),
            Value::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(key, value)| (replace(key, org), scoped_historical_expected(value, org)))
                    .collect(),
            ),
            _ => value.clone(),
        }
    }

    #[test]
    fn clean_registry_did_jwks_and_profiles_match_python_except_derived_managed_service() {
        let clean = case("clean_apply");
        let env = &clean["input"]["environment"];
        let org = env["MARTY_ORG_ID"].as_str().unwrap();
        let did = env["MARTY_ISSUER_DID"].as_str().unwrap();
        let url = env["MARTY_ISSUER_BASE_URL"].as_str().unwrap();
        let expected = &clean["state"]["redis"];
        let records = records(&clean);
        let mut expected_registry = expected[signing_registry_key(org)].clone();
        let managed = &expected_registry["services"][0];
        assert_eq!(
            managed["auth_reference"], "Managed by Marty service stack",
            "the historical Python corpus must remain unchanged"
        );
        expected_registry["services"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        let registry = seed_signing_registry(None, &records).unwrap();
        assert!(registry["services"].as_array().unwrap().is_empty());
        assert_eq!(
            registry,
            scoped_historical_expected(&expected_registry, org)
        );
        let (did_doc, jwks) = seed_did_and_jwks(None, org, did, &records);
        assert_eq!(
            did_doc,
            scoped_historical_expected(&expected[did_key(org, Some(did))], org)
        );
        assert_eq!(
            jwks,
            scoped_historical_expected(&expected[jwks_key(org)], org)
        );
        assert_eq!(
            seed_issuer_profiles(None, org, did, url),
            scoped_historical_expected(&expected[issuer_profiles_key(org)], org)
        );
    }

    #[test]
    fn raw_openbao_ed25519_public_key_is_published_without_private_material() {
        let spec = STANDARD_KEYS
            .iter()
            .find(|spec| spec.key_type == "ed25519")
            .unwrap();
        let raw: Vec<u8> = (0..32).collect();
        let jwk = public_jwk_from_openbao(*spec, &STANDARD.encode(raw)).unwrap();
        assert_eq!(
            jwk,
            records(&case("clean_apply"))
                .iter()
                .find(|record| record.spec.id == spec.id)
                .unwrap()
                .public_jwk
        );
    }

    #[test]
    fn preserves_customer_profile_and_backfills_legacy_did() {
        let clean = case("clean_apply");
        let records = records(&clean);
        let customer = case("preserve_customer_profile");
        let org = customer["input"]["environment"]["MARTY_ORG_ID"]
            .as_str()
            .unwrap();
        let did = customer["input"]["environment"]["MARTY_ISSUER_DID"]
            .as_str()
            .unwrap();
        let url = customer["input"]["environment"]["MARTY_ISSUER_BASE_URL"]
            .as_str()
            .unwrap();
        let initial = &customer["input"]["initial_redis"];
        assert_eq!(
            seed_issuer_profiles(
                Some(initial[issuer_profiles_key(org)].clone()),
                org,
                did,
                url
            ),
            scoped_historical_expected(&customer["state"]["redis"][issuer_profiles_key(org)], org)
        );

        let backfill = case("backfill_mixed_did");
        let initial = &backfill["input"]["initial_redis"];
        let legacy = &initial[did_key(org, None)];
        let writes = backfill_scoped_did_documents(legacy, org, |_| None).unwrap();
        let current = writes
            .iter()
            .find(|(key, _)| key == &did_key(org, Some(did)))
            .map(|(_, value)| value.clone());
        for (key, value) in writes {
            if key != did_key(org, Some(did)) {
                assert_eq!(value, backfill["state"]["redis"][key]);
            }
        }
        let (did_doc, jwks) = seed_did_and_jwks(current, org, did, &records);
        assert_eq!(
            did_doc,
            scoped_historical_expected(&backfill["state"]["redis"][did_key(org, Some(did))], org)
        );
        assert_eq!(
            jwks,
            scoped_historical_expected(&backfill["state"]["redis"][jwks_key(org)], org)
        );
    }

    #[test]
    fn falsey_registry_defaults_are_repaired_without_losing_customer_services() {
        let records = records(&case("clean_apply"));
        for default in [
            Value::Null,
            json!(false),
            json!(0),
            json!(""),
            json!([]),
            json!({}),
        ] {
            let initial =
                json!({"default_service_id": default, "services": [{"id":"customer-hsm"}]});
            let result = seed_signing_registry(Some(initial), &records).unwrap();
            assert_eq!(result["default_service_id"], MANAGED_SERVICE_ID);
            assert_eq!(result["services"][0]["id"], "customer-hsm");
        }
    }

    #[test]
    fn stale_bootstrap_managed_entry_is_removed_without_dropping_customer_service() {
        let records = records(&case("clean_apply"));
        let initial = json!({"services": [
            {"id": MANAGED_SERVICE_ID, "auth_mode": "service_token",
                "auth_reference": "Managed by Marty service stack"},
            {"id": "customer-hsm", "service_type": "aws-kms"}
        ]});
        let result = seed_signing_registry(Some(initial), &records).unwrap();
        assert_eq!(
            result["services"],
            json!([{"id": "customer-hsm", "service_type": "aws-kms"}])
        );
    }

    #[test]
    fn normalized_existing_purposes_are_idempotent_but_changed_bindings_fail() {
        let records = records(&case("clean_apply"));
        let seeded = seed_signing_registry(None, &records).unwrap();
        let reference = &records[0].reference;
        let mut normalized = seeded.clone();
        normalized["key_reference_purposes"][MANAGED_SERVICE_ID][reference] =
            json!(["jwks_signing", "vc_jwt_issuer"]);
        assert!(seed_signing_registry(Some(normalized.clone()), &records).is_ok());

        normalized["key_reference_purposes"][MANAGED_SERVICE_ID][reference] =
            json!(["vc_jwt_issuer"]);
        assert!(matches!(
            seed_signing_registry(Some(normalized), &records),
            Err(BootstrapError::ConflictingPurpose(key)) if key == *reference
        ));
    }

    #[test]
    fn standard_bootstrap_references_are_tenant_bound_and_shared_profiles_stay_shared() {
        let org = "00000000-0000-0000-0000-000000000001";
        for spec in STANDARD_KEYS {
            let reference = tenant_standard_key_reference(org, spec.id);
            assert!(crate::registry::tenant_managed_key_name(org, &reference));
            assert!(!crate::registry::tenant_managed_key_name(
                "another-org",
                &reference
            ));
            assert_ne!(reference, spec.id);
        }
        let profiles =
            seed_issuer_profiles(None, org, "did:example:issuer", "https://issuer.example");
        let vc = &profiles["profiles"][0]["signing_key_reference"];
        let sd_jwt = &profiles["profiles"][1]["signing_key_reference"];
        assert_eq!(vc, sd_jwt);
    }
}
