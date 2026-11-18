//! Bounded decoding for Delegated Authority v1 snapshots.
//!
//! Decode untrusted bytes here before constructing a DTO or storing JSONB. A
//! `serde_json::Value` that was decoded elsewhere has already lost duplicate
//! fields and therefore cannot establish that the original wire was valid.
//!
//! This managed-service adapter accepts the canonical string spellings emitted
//! by its Rust DTOs. Alternate UUID or timestamp spellings are rejected, never
//! silently normalized before digest verification. Supporting every protocol
//! spelling requires preserving those strings in the domain model first.

use std::{cell::Cell, fmt};

use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use crate::{domain::canonical_json, DelegationGrant, GrantValidationError};

pub const MAX_GRANT_WIRE_BYTES: usize = crate::MAX_GRANT_DOCUMENT_BYTES;
const MAX_JSON_DEPTH: usize = 24;
const MAX_JSON_NODES: usize = 8_192;

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GrantWireError {
    #[error("delegation grant document exceeds the byte limit")]
    DocumentTooLarge,
    #[error("delegation grant JSON encoding, structure, or field types are invalid")]
    InvalidDocument,
    #[error("delegation grant uses an unsupported noncanonical UUID or timestamp spelling")]
    NonCanonicalEncoding,
    #[error(transparent)]
    Validation(#[from] GrantValidationError),
}

/// Decode and validate a snapshot; success is not authentication or authority.
///
/// Limits and duplicate detection apply during decoding. The digest is checked
/// against the original JSON strings before DTO validation can normalize them.
/// Errors deliberately omit submitted values, identities, and evidence refs.
pub fn decode_grant_snapshot(raw: &[u8]) -> Result<DelegationGrant, GrantWireError> {
    let document = read_document(raw)?;
    let projection = terms_projection(&document)?;
    let expected_digest = format!("sha256:{:x}", Sha256::digest(canonical_json(&projection)?));
    if document.get("terms_digest").and_then(Value::as_str) != Some(expected_digest.as_str()) {
        return Err(GrantValidationError::TermsDigestMismatch.into());
    }

    let grant: DelegationGrant =
        serde_json::from_value(document.clone()).map_err(|_| GrantWireError::InvalidDocument)?;
    let serialized = serde_json::to_value(&grant).map_err(|_| GrantWireError::InvalidDocument)?;
    if serialized != document {
        return Err(GrantWireError::NonCanonicalEncoding);
    }
    validate_timestamp_spellings(&document)?;
    grant.validate()?;
    Ok(grant)
}

fn validate_timestamp_spellings(document: &Value) -> Result<(), GrantWireError> {
    for path in [
        "/created_at",
        "/updated_at",
        "/terms/valid_from",
        "/terms/valid_until",
        "/authority/source_expires_at",
        "/approval/approved_at",
    ] {
        if let Some(value) = document.pointer(path) {
            let value = value.as_str().ok_or(GrantWireError::InvalidDocument)?;
            let bytes = value.as_bytes();
            if !(20..=64).contains(&bytes.len())
                || bytes[4] != b'-'
                || bytes[7] != b'-'
                || bytes[10] != b'T'
                || bytes[13] != b':'
                || bytes[16] != b':'
                || bytes[bytes.len() - 1] != b'Z'
                || ![
                    &bytes[0..4],
                    &bytes[5..7],
                    &bytes[8..10],
                    &bytes[11..13],
                    &bytes[14..16],
                    &bytes[17..19],
                ]
                .iter()
                .all(|part| part.iter().all(u8::is_ascii_digit))
                || (bytes.len() > 20
                    && (bytes[19] != b'.'
                        || bytes.len() == 21
                        || !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit)))
            {
                return Err(GrantWireError::InvalidDocument);
            }
        }
    }
    Ok(())
}

fn terms_projection(document: &Value) -> Result<Value, GrantWireError> {
    let mut projection = Map::new();
    for key in ["profile", "id", "organization_id", "authority", "terms"] {
        projection.insert(
            key.to_owned(),
            document
                .get(key)
                .ok_or(GrantWireError::InvalidDocument)?
                .clone(),
        );
    }
    Ok(Value::Object(projection))
}

fn read_document(raw: &[u8]) -> Result<Value, GrantWireError> {
    if raw.len() > MAX_GRANT_WIRE_BYTES {
        return Err(GrantWireError::DocumentTooLarge);
    }
    let remaining_nodes = Cell::new(MAX_JSON_NODES);
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let document = BoundedValue {
        remaining_nodes: &remaining_nodes,
        depth: 0,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| GrantWireError::InvalidDocument)?;
    deserializer
        .end()
        .map_err(|_| GrantWireError::InvalidDocument)?;
    if !document.is_object() {
        return Err(GrantWireError::InvalidDocument);
    }
    Ok(document)
}

struct BoundedValue<'a> {
    remaining_nodes: &'a Cell<usize>,
    depth: usize,
}

impl BoundedValue<'_> {
    fn count_node<E: Error>(&self, depth: usize) -> Result<(), E> {
        if depth > MAX_JSON_DEPTH {
            return Err(E::custom("JSON nesting limit"));
        }
        let remaining = self.remaining_nodes.get();
        if remaining == 0 {
            return Err(E::custom("JSON node limit"));
        }
        self.remaining_nodes.set(remaining - 1);
        Ok(())
    }

    fn child(&self) -> BoundedValue<'_> {
        BoundedValue {
            remaining_nodes: self.remaining_nodes,
            depth: self.depth + 1,
        }
    }
}

impl<'de> DeserializeSeed<'de> for BoundedValue<'_> {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        self.count_node(self.depth)?;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for BoundedValue<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded Delegated Authority v1 JSON")
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E: Error>(self, _value: f64) -> Result<Value, E> {
        Err(E::custom("floating-point JSON number not supported"))
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        // Every optional field in the v1 grant schema is absent or typed;
        // none accepts JSON null, even when the Rust DTO uses Option.
        Err(E::custom("null is not a delegation grant field value"))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(self.child())? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            self.count_node(self.depth + 1)?;
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate JSON field"));
            }
            let value = object.next_value_seed(self.child())?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::pending_grant;

    // Source: ElevenID/marty-protocol at a9ce6a1d912f22a5627faebb482c44b9104d840d,
    // conformance/delegated-authority/v1/valid/delegation-grant-managed.json,
    // blob 1f85558755e783567f9ad5337260373b661f6ab3. This expected digest was
    // not calculated by the service under test; it is a historical snapshot.
    const MANAGED: &str = r#"{
      "profile":"urn:marty:delegation-grant:v1",
      "id":"00000000-0000-4000-8000-000000000001",
      "organization_id":"00000000-0000-4000-8000-000000000002",
      "authority":{"mode":"MANAGED","issuer":{"type":"SERVICE_ACCOUNT","id":"urn:example:authority"},"status_ref":"https://authority.example/grants/1"},
      "terms":{
        "grantor":{"type":"USER","id":"urn:example:customer"},
        "subject":{"type":"USER","id":"urn:example:customer"},
        "delegate":{"type":"SERVICE_ACCOUNT","id":"urn:example:agent"},
        "binding":{"method":"KEY","key_thumbprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        "actions":["urn:example:checkout:prepare"],
        "audiences":["https://merchant.example"],
        "resources":["urn:example:checkout:1"],
        "valid_from":"2026-11-17T17:00:00Z",
        "valid_until":"2026-11-17T18:00:00Z",
        "subdelegation_allowed":false,
        "constraints":{"mode":"EXACT_OPERATION","request_profile":"urn:example:checkout:v1","request_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
      },
      "terms_digest":"sha256:246febf8b6c26aa095bc1e83fcfcb131c8dff65c067d95f446a704aff92ac4b9",
      "status":"ACTIVE","revision":1,
      "created_at":"2026-11-17T16:59:00Z","updated_at":"2026-11-17T17:00:00Z",
      "approval":{
        "profile":"urn:example:trusted-surface:v1",
        "grant_id":"00000000-0000-4000-8000-000000000001",
        "approver":{"type":"USER","id":"urn:example:customer"},
        "evidence_ref":"urn:example:approval:1",
        "authority_evidence_ref":"urn:example:authority-evidence:1",
        "terms_digest":"sha256:246febf8b6c26aa095bc1e83fcfcb131c8dff65c067d95f446a704aff92ac4b9",
        "approved_at":"2026-11-17T17:00:00Z"
      }
    }"#;

    fn fixture() -> Value {
        serde_json::from_str(MANAGED).unwrap()
    }

    fn decode_value(document: &Value) -> Result<DelegationGrant, GrantWireError> {
        decode_grant_snapshot(&serde_json::to_vec(document).unwrap())
    }

    fn rebind(document: &mut Value) {
        let bytes = canonical_json(&terms_projection(document).unwrap()).unwrap();
        let digest = format!("sha256:{:x}", Sha256::digest(bytes));
        document["terms_digest"] = Value::from(digest.clone());
        document["approval"]["terms_digest"] = Value::from(digest);
    }

    #[test]
    fn accepts_reference_digest_and_server_snapshot() {
        let grant = decode_grant_snapshot(MANAGED.as_bytes()).unwrap();
        assert_eq!(
            grant.terms_digest,
            "sha256:246febf8b6c26aa095bc1e83fcfcb131c8dff65c067d95f446a704aff92ac4b9"
        );
        let pending = pending_grant();
        assert_eq!(
            decode_grant_snapshot(&serde_json::to_vec(&pending).unwrap()).unwrap(),
            pending
        );
    }

    #[test]
    fn rejects_duplicate_fields_before_dto_construction() {
        for raw in [
            r#"{"profile":"a","profile":"b"}"#,
            r#"{"terms":{"id":"a","id":"b"}}"#,
            r#"{"profile":"a","\u0070rofile":"b"}"#,
        ] {
            assert_eq!(
                read_document(raw.as_bytes()),
                Err(GrantWireError::InvalidDocument)
            );
        }
    }

    #[test]
    fn rejects_explicit_null_even_for_optional_members() {
        for path in [
            "/authority/source_profile",
            "/terms/binding/session_ref",
            "/terms/constraints/profile",
        ] {
            let mut document = fixture();
            let (parent, field) = path.rsplit_once('/').unwrap();
            document
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(field.into(), Value::Null);
            assert_eq!(
                decode_value(&document),
                Err(GrantWireError::InvalidDocument)
            );
        }
        let mut pending = serde_json::to_value(pending_grant()).unwrap();
        pending["approval"] = Value::Null;
        assert_eq!(decode_value(&pending), Err(GrantWireError::InvalidDocument));
    }

    #[test]
    fn enforces_byte_depth_and_node_limits_during_decoding() {
        assert_eq!(
            read_document(&vec![b' '; MAX_GRANT_WIRE_BYTES + 1]),
            Err(GrantWireError::DocumentTooLarge)
        );
        for (arrays, accepted) in [(23, true), (24, false)] {
            let raw = format!("{{\"x\":{}0{}}}", "[".repeat(arrays), "]".repeat(arrays));
            assert_eq!(read_document(raw.as_bytes()).is_ok(), accepted);
        }
        for (elements, accepted) in [(MAX_JSON_NODES - 3, true), (MAX_JSON_NODES - 2, false)] {
            let raw = format!("{{\"x\":[{}0]}}", "0,".repeat(elements - 1));
            assert_eq!(read_document(raw.as_bytes()).is_ok(), accepted);
        }
    }

    #[test]
    fn rejects_float_lexemes_nonfinite_values_and_invalid_unicode() {
        for raw in [
            r#"{"revision":1.0}"#,
            r#"{"revision":1e0}"#,
            r#"{"revision":1e999}"#,
            r#"{"x":NaN}"#,
            r#"{"x":-Infinity}"#,
            r#"{"x":"\ud800"}"#,
            "[]",
            "{}{}",
            "{",
        ] {
            assert_eq!(
                read_document(raw.as_bytes()),
                Err(GrantWireError::InvalidDocument)
            );
        }
        assert_eq!(
            read_document(b"{\"x\":\"\xff\"}"),
            Err(GrantWireError::InvalidDocument)
        );
    }

    #[test]
    fn rejects_unknown_fields_and_revision_outside_protocol_integer_range() {
        let mut document = fixture();
        document["approval"]["agent_says_approved"] = Value::Bool(true);
        assert_eq!(
            decode_value(&document),
            Err(GrantWireError::InvalidDocument)
        );
        let mut document = fixture();
        document["revision"] = Value::from(9_007_199_254_740_991_u64);
        assert!(decode_value(&document).is_ok());
        document["revision"] = Value::from(9_007_199_254_740_992_u64);
        assert!(decode_value(&document).is_err());
    }

    #[test]
    fn checks_digest_over_original_strings_before_rejecting_normalization() {
        let mut document = fixture();
        document["terms"]["valid_from"] = Value::from("2026-11-17T17:00:00+00:00");
        assert_eq!(
            decode_value(&document),
            Err(GrantWireError::Validation(
                GrantValidationError::TermsDigestMismatch
            ))
        );
        // Expected digest computed independently with the Python protocol reference.
        let digest = "sha256:1dfab1a92dd9a8fd5d10f795f6763b31d3e83a17e2cbb499643e14293f1bd2cd";
        document["terms_digest"] = Value::from(digest);
        document["approval"]["terms_digest"] = Value::from(digest);
        assert_eq!(
            decode_value(&document),
            Err(GrantWireError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn rejects_uuid_and_envelope_timestamp_normalization() {
        let mut document = fixture();
        document["id"] = Value::from("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA");
        document["approval"]["grant_id"] = document["id"].clone();
        let digest = "sha256:d57c0ee73695f9606b4a567b2eb20f71323419e5a144f509da567da1788e2475";
        document["terms_digest"] = Value::from(digest);
        document["approval"]["terms_digest"] = Value::from(digest);
        assert_eq!(
            decode_value(&document),
            Err(GrantWireError::NonCanonicalEncoding)
        );

        let mut document = fixture();
        document["approval"]["approved_at"] = Value::from("2026-11-17T17:00:00+00:00");
        assert_eq!(
            decode_value(&document),
            Err(GrantWireError::NonCanonicalEncoding)
        );
    }

    #[test]
    fn rejects_expanded_years_accepted_by_chrono_but_outside_wire_schema() {
        let mut document = fixture();
        document["terms"]["valid_until"] = Value::from("+12026-11-17T18:00:00Z");
        rebind(&mut document);
        assert!(decode_value(&document).is_err());
    }

    #[test]
    fn rejects_malformed_principal_uris_even_when_digest_is_recomputed() {
        for identifier in [
            "1urn:example:actor",
            "urn:example:bad space",
            "urn:example:bad\n",
            "urn:example:%QZ",
            "https://",
            "https://example.test\\admin",
            "urn:example:*",
            "urn:example:[actor]",
            "https://example.test/path[1]",
            "https://example.test?q=[actor]",
            "https://example.test#actor[1]",
            "https://user[1]@example.test/actor",
            "https://[::1]/path[1]",
            "https://user@@host.example/actor",
            "urn://user@@host.example/actor",
            "urn:example:actor#x#y",
            "https://host.example/actor#x#y",
            "https:///host.example",
            "HTTPS:////host.example",
            "http:host.example",
            "https://user@/actor",
            "https://:443/actor",
        ] {
            let mut document = fixture();
            document["terms"]["delegate"]["id"] = Value::from(identifier);
            rebind(&mut document);
            assert_eq!(
                decode_value(&document),
                Err(GrantWireError::Validation(
                    GrantValidationError::InvalidPrincipal
                ))
            );
        }
    }

    #[test]
    fn permits_ipv6_and_reserved_characters_in_their_valid_components() {
        for identifier in [
            "https://[2001:db8::1]/actor",
            "https://user:pass@[2001:db8::1]:8443/actor",
            "urn:example:%5Bactor%5D",
            "https://example.test/path%5B1%5D",
            "https://user%40name@host.example/actor",
            "https://host.example/actors@@?query=@@#fragment@@",
            "urn:example:actor@@#fragment%23part",
            "https://host.example/actor#fragment%23part",
        ] {
            let mut document = fixture();
            document["terms"]["delegate"]["id"] = Value::from(identifier);
            rebind(&mut document);
            assert!(decode_value(&document).is_ok());
        }
    }

    #[test]
    fn error_messages_do_not_include_submitted_identity_or_evidence() {
        let raw = br#"{"private_evidence_reference":"urn:secret:record","private_evidence_reference":"urn:secret:record"}"#;
        let error = decode_grant_snapshot(raw).unwrap_err().to_string();
        assert!(!error.contains("urn:secret:record"));
        assert!(!error.contains("private_evidence_reference"));
    }
}
