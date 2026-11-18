//! Public `did:web` compatibility behavior owned by the gateway.

use std::sync::LazyLock;

use percent_encoding::percent_decode_str;
use regex::Regex;
use serde_json::{json, Map, Value};

static SLUG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9._-]{1,128}$").expect("static organization slug regex")
});
static DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9.-]+(?::[0-9]{1,5})?$").expect("static did:web domain regex")
});
static DOMAIN_LABEL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
        .expect("static domain-label regex")
});

/// Normalize the externally published host and encode a port for `did:web`.
#[must_use]
pub fn public_authority(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed != value || trimmed.is_empty() {
        return None;
    }
    let decoded = percent_decode_str(value).decode_utf8().ok()?;
    if !DOMAIN.is_match(&decoded) {
        return None;
    }
    let decoded = decoded.as_ref();
    let (raw_host, port) = match decoded.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (decoded, None),
    };
    let host = raw_host.trim_end_matches('.');
    if host.is_empty()
        || host.len() > 253
        || host.split('.').any(|label| !DOMAIN_LABEL.is_match(label))
    {
        return None;
    }
    if port.is_some_and(|port| port.parse::<u16>().map_or(true, |port| port == 0)) {
        return None;
    }
    let host = host.to_ascii_lowercase();
    Some(port.map_or(host.clone(), |port| format!("{host}%3A{port}")))
}

/// Apply the Python compatibility adapter's trim-and-lowercase slug behavior.
#[must_use]
pub fn organization_slug(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    SLUG.is_match(&normalized).then_some(normalized)
}

#[must_use]
pub fn empty_document(did: &str) -> Value {
    json!({
        "id": did,
        "controller": did,
        "verificationMethod": [],
        "assertionMethod": []
    })
}

/// Retarget a legacy organization document to the public DID being resolved.
///
/// Only identifiers rooted at the source DID are rewritten. External service
/// endpoints, controllers, and verification relationships remain untouched.
#[must_use]
pub fn retarget_document(document: &Value, did: &str) -> Value {
    let Some(source) = document.as_object() else {
        return empty_document(did);
    };
    let source_did = source.get("id").and_then(Value::as_str).unwrap_or(did);
    if source_did == did {
        return document.clone();
    }
    let mut output = source.clone();
    output.insert("id".into(), Value::String(did.into()));
    output.insert("controller".into(), Value::String(did.into()));

    let methods = source
        .get("verificationMethod")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
        .map(|method| rewrite_method(method, source_did, did))
        .map(Value::Object)
        .collect();
    output.insert("verificationMethod".into(), Value::Array(methods));

    for relationship in [
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
    ] {
        let Some(entries) = source.get(relationship).and_then(Value::as_array) else {
            continue;
        };
        let rewritten = entries
            .iter()
            .map(|entry| {
                if let Some(method) = entry.as_object() {
                    Value::Object(rewrite_method(method, source_did, did))
                } else if let Some(identifier) = entry.as_str() {
                    Value::String(rewrite_identifier(identifier, source_did, did))
                } else {
                    entry.clone()
                }
            })
            .collect();
        output.insert(relationship.into(), Value::Array(rewritten));
    }
    Value::Object(output)
}

fn rewrite_method(method: &Map<String, Value>, source_did: &str, did: &str) -> Map<String, Value> {
    let mut rewritten = method.clone();
    if let Some(identifier) = method.get("id").and_then(Value::as_str) {
        rewritten.insert(
            "id".into(),
            Value::String(rewrite_identifier(identifier, source_did, did)),
        );
    }
    if method.get("controller").and_then(Value::as_str) == Some(source_did) {
        rewritten.insert("controller".into(), Value::String(did.into()));
    }
    rewritten
}

fn rewrite_identifier(identifier: &str, source_did: &str, did: &str) -> String {
    identifier
        .strip_prefix(source_did)
        .filter(|suffix| suffix.starts_with('#'))
        .map_or_else(|| identifier.into(), |suffix| format!("{did}{suffix}"))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Contract {
        schema_version: u8,
        authority_cases: Vec<AuthorityCase>,
        slug_cases: Vec<SlugCase>,
        retarget_cases: Vec<RetargetCase>,
    }

    #[derive(Deserialize)]
    struct AuthorityCase {
        input: String,
        expected: Option<String>,
    }

    #[derive(Deserialize)]
    struct SlugCase {
        input: String,
        expected: Option<String>,
    }

    #[derive(Deserialize)]
    struct RetargetCase {
        target: String,
        input: Value,
        expected: Value,
    }

    #[test]
    fn shared_did_web_behavior_contract() {
        let contract: Contract = serde_json::from_str(include_str!(
            "../../../../contracts/gateway-did-web-behavior.json"
        ))
        .expect("DID Web contract");
        assert_eq!(contract.schema_version, 1);
        for case in contract.authority_cases {
            assert_eq!(
                public_authority(&case.input),
                case.expected,
                "{}",
                case.input
            );
        }
        for case in contract.slug_cases {
            assert_eq!(
                organization_slug(&case.input),
                case.expected,
                "{}",
                case.input
            );
        }
        for case in contract.retarget_cases {
            assert_eq!(retarget_document(&case.input, &case.target), case.expected);
        }
    }
}
