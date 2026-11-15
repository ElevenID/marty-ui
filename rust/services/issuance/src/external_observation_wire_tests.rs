// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use http::HeaderValue;
use serde_json::{json, Value};

const ID: &str = "observation-one";

fn headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("idempotency-key", HeaderValue::from_static(ID));
    headers
}

fn valid() -> Value {
    json!({
        "binding_id": "binding-one",
        "binding_revision": 1,
        "observation_id": ID,
        "sequence": 1,
        "observed_at_ms": 1_800_000_000_000_u64,
        "effective_at_ms": 1_799_999_999_000_u64,
        "claims": {"completed": false, "score": null}
    })
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

fn rejected(body: &[u8], expected: WireError) {
    assert_eq!(decode_submission(&headers(), body).err(), Some(expected));
}

#[test]
fn negative_and_null_claims_decode_without_granting_trust() {
    let observation = decode_submission(&headers(), &bytes(&valid())).unwrap();
    assert_eq!(observation.binding_id, "binding-one");
    assert_eq!(observation.sequence, 1);
    assert!(matches!(observation.claims["completed"], Scalar::Boolean(false)));
    assert!(matches!(observation.claims["score"], Scalar::Null));
}

#[test]
fn scalar_numbers_and_text_survive_without_boolean_or_string_coercion() {
    let mut value = valid();
    value["claims"] = json!({"score": 9.125, "offset": -1, "name": "Synthetic"});
    let observation = decode_submission(&headers(), &bytes(&value)).unwrap();
    assert!(matches!(observation.claims["score"], Scalar::Number(v) if v == 9.125));
    assert!(matches!(observation.claims["offset"], Scalar::Number(v) if v == -1.0));
    assert!(matches!(&observation.claims["name"], Scalar::Text(v) if v == "Synthetic"));
}

#[test]
fn every_top_level_field_is_required() {
    for field in valid().as_object().unwrap().keys() {
        let mut value = valid();
        value.as_object_mut().unwrap().remove(field);
        rejected(&bytes(&value), WireError::InvalidEnvelope);
    }
}

#[test]
fn every_top_level_field_rejects_duplicates_in_original_bytes() {
    let value = valid();
    let original = serde_json::to_string(&value).unwrap();
    for (field, content) in value.as_object().unwrap() {
        let duplicate = format!("{{{}:{},{}", serde_json::to_string(field).unwrap(), content, &original[1..]);
        rejected(duplicate.as_bytes(), WireError::InvalidEnvelope);
    }
}

#[test]
fn unicode_escaped_names_do_not_hide_duplicate_fields_or_claims() {
    let original = serde_json::to_string(&valid()).unwrap();
    rejected(
        format!("{{\"binding_\\u0069d\":\"binding-one\",{}", &original[1..]).as_bytes(),
        WireError::InvalidEnvelope,
    );
    let duplicate = original.replace(
        "\"claims\":{\"completed\":false,\"score\":null}",
        "\"claims\":{\"completed\":false,\"compl\\u0065ted\":true,\"score\":null}",
    );
    assert_ne!(duplicate, original);
    rejected(duplicate.as_bytes(), WireError::InvalidEnvelope);
}

#[test]
fn conflicting_identical_and_null_duplicate_claims_are_all_invalid() {
    let original = serde_json::to_string(&valid()).unwrap();
    for claims in [
        r#"{"score":1,"score":2}"#,
        r#"{"score":1,"score":1}"#,
        r#"{"score":null,"score":null}"#,
        r#"{"completed":false,"completed":true}"#,
    ] {
        let body = original.replace(r#"{"completed":false,"score":null}"#, claims);
        rejected(body.as_bytes(), WireError::InvalidEnvelope);
    }
}

#[test]
fn caller_selected_authority_and_other_unknown_envelope_fields_fail() {
    for field in ["organization_id", "subject_id", "source_id", "api_key_id", "scopes",
        "provider", "application_id", "fact_type", "resource_scope", "verification", "policy_allowed",
        "approved", "issuer_key", "signing_key", "__proto__", "schema_version", "other"] {
        let mut value = valid();
        value[field] = json!("synthetic-untrusted");
        rejected(&bytes(&value), WireError::InvalidEnvelope);
    }
}

#[test]
fn ids_are_exact_bounded_ascii_and_not_paths() {
    for field in ["binding_id", "observation_id"] {
        for id in ["", "..", "../foreign", "foreign/path", "%2f", "with space", "é", "line\nbreak"] {
            let mut value = valid();
            value[field] = json!(id);
            rejected(&bytes(&value), WireError::InvalidEnvelope);
        }
        let mut value = valid();
        value[field] = json!("x".repeat(129));
        rejected(&bytes(&value), WireError::InvalidEnvelope);
        value[field] = Value::Null;
        rejected(&bytes(&value), WireError::InvalidEnvelope);
    }
    let mut value = valid();
    value["binding_id"] = json!("_".repeat(128));
    assert!(decode_submission(&headers(), &bytes(&value)).is_ok());
}

#[test]
fn identity_revision_sequence_and_times_require_safe_positive_integer_tokens() {
    for field in ["binding_revision", "sequence", "observed_at_ms", "effective_at_ms"] {
        for token in ["0", "-1", "1.0", "1e0", "true", "null", "\"1\"", "9007199254740992", "18446744073709551616"] {
            let mut value = valid();
            value[field] = json!("REPLACE-TOKEN");
            let body = serde_json::to_string(&value).unwrap().replace("\"REPLACE-TOKEN\"", token);
            rejected(body.as_bytes(), WireError::InvalidEnvelope);
        }
    }
    let mut value = valid();
    value["binding_revision"] = json!(MAX_SAFE_INTEGER);
    value["sequence"] = json!(MAX_SAFE_INTEGER);
    value["observed_at_ms"] = json!(MAX_SAFE_INTEGER);
    value["effective_at_ms"] = json!(MAX_SAFE_INTEGER);
    let observation = decode_submission(&headers(), &bytes(&value)).unwrap();
    assert_eq!(observation.sequence, MAX_SAFE_INTEGER);
}

#[test]
fn effective_time_cannot_exceed_observation_time() {
    let mut value = valid();
    value["effective_at_ms"] = json!(1_800_000_000_001_u64);
    rejected(&bytes(&value), WireError::InvalidEnvelope);
}

#[test]
fn claims_are_a_nonempty_bounded_object_with_valid_names() {
    for claims in [json!({}), Value::Null, json!([]), json!([false]), json!("false"), json!(true)] {
        let mut value = valid();
        value["claims"] = claims;
        rejected(&bytes(&value), WireError::InvalidEnvelope);
    }
    for name in ["", "with space", "line\nbreak", "é", "path/to"] {
        let mut value = valid();
        value["claims"] = json!({name: false});
        rejected(&bytes(&value), WireError::InvalidEnvelope);
    }
    let mut value = valid();
    value["claims"] = json!({"x".repeat(129): false});
    rejected(&bytes(&value), WireError::InvalidEnvelope);
    value["claims"] = Value::Object((0..32).map(|i| (format!("claim_{i}"), json!(false))).collect());
    assert!(decode_submission(&headers(), &bytes(&value)).is_ok());
    value["claims"]["one_too_many"] = json!(false);
    rejected(&bytes(&value), WireError::InvalidEnvelope);
}

#[test]
fn nested_claims_and_recursive_payloads_fail_without_becoming_observations() {
    for claim in [json!({"verified": true}), json!([1]), json!([]), json!({}),
        json!({"$serde_json::private::Number": "95"}), json!({"$serde_json::private::RawValue": "95"})] {
        let mut value = valid();
        value["claims"]["score"] = claim;
        rejected(&bytes(&value), WireError::InvalidEnvelope);
    }
    let body = serde_json::to_string(&valid()).unwrap().replace("\"score\":null",
        &format!("\"score\":{}0{}", "[".repeat(500), "]".repeat(500)));
    rejected(body.as_bytes(), WireError::InvalidEnvelope);
}

#[test]
fn claim_numbers_are_finite_and_bounded_before_conversion() {
    for token in ["9007199254740992", "9007199254740993", "-9007199254740993",
        "1e309", "1e100", "1e-999", "NaN", "Infinity", "-Infinity"] {
        let body = serde_json::to_string(&valid()).unwrap().replace("\"score\":null", &format!("\"score\":{token}"));
        rejected(body.as_bytes(), WireError::InvalidEnvelope);
    }
    for token in ["9007199254740991", "-9007199254740991", "0", "-0.0", "1.25e2", "0.0e-999"] {
        let body = serde_json::to_string(&valid()).unwrap().replace("\"score\":null", &format!("\"score\":{token}"));
        assert!(decode_submission(&headers(), body.as_bytes()).is_ok());
    }
}

#[test]
fn text_limits_count_utf8_bytes_and_reject_controls() {
    for text in [String::new(), "x".repeat(513), "é".repeat(257), "private\ntext".into(),
        "private\u{007f}text".into(), "private\u{0085}text".into(), "private\0text".into()] {
        let mut value = valid();
        value["claims"]["name"] = json!(text);
        rejected(&bytes(&value), WireError::InvalidEnvelope);
    }
    for text in ["x".repeat(512), "é".repeat(256), "😀".repeat(128)] {
        let mut value = valid();
        value["claims"]["name"] = json!(text);
        assert!(decode_submission(&headers(), &bytes(&value)).is_ok());
    }
}

#[test]
fn invalid_utf8_unpaired_surrogates_and_trailing_json_fail() {
    let original = serde_json::to_string(&valid()).unwrap();
    for body in [format!("{original}{{}}"), format!("{original} true"), format!("{original}\0"),
        format!("\u{feff}{original}"), "[]".into(), "null".into(), "true".into(), String::new(),
        " ".into(), original.replace("binding-one", r#"\uD800"#), original[..original.len() - 1].into()] {
        rejected(body.as_bytes(), WireError::InvalidEnvelope);
    }
    let mut body = bytes(&valid());
    body[0] = 0xff;
    rejected(&body, WireError::InvalidEnvelope);
    assert!(decode_submission(&headers(), format!(" \r\n{original}\t ").as_bytes()).is_ok());
}

#[test]
fn body_limit_is_enforced_on_original_bytes_including_whitespace() {
    let mut body = bytes(&valid());
    body.resize(MAX_BODY_BYTES, b' ');
    assert!(decode_submission(&headers(), &body).is_ok());
    body.push(b' ');
    rejected(&body, WireError::BodyTooLarge);
}

#[test]
fn idempotency_key_is_required_unique_and_exact() {
    let body = bytes(&valid());
    for key in ["", "other", " observation-one", "observation-one ", "observation-one,observation-one"] {
        let mut h = headers();
        h.insert("idempotency-key", HeaderValue::from_str(key).unwrap());
        assert_eq!(decode_submission(&h, &body).err(), Some(WireError::InvalidIdempotencyKey));
    }
    let mut h = headers();
    h.remove("idempotency-key");
    assert_eq!(decode_submission(&h, &body).err(), Some(WireError::InvalidIdempotencyKey));
    h.insert("idempotency-key", HeaderValue::from_static(ID));
    h.append("idempotency-key", HeaderValue::from_static(ID));
    assert_eq!(decode_submission(&h, &body).err(), Some(WireError::InvalidHeaders));
}

#[test]
fn only_json_and_unambiguous_utf8_content_types_are_supported() {
    let body = bytes(&valid());
    for accepted in ["application/json", "Application/JSON", "application/json; charset=utf-8",
        "application/json; Charset=\"UTF-8\""] {
        let mut h = headers();
        h.insert("content-type", HeaderValue::from_str(accepted).unwrap());
        assert!(decode_submission(&h, &body).is_ok());
    }
    for rejected in ["", "text/json", "text/plain", "application/problem+json", "application/json,application/json",
        "application/json; charset=latin1", "application/json;", "application/json; charset=utf-8; charset=utf-8",
        "application/json; boundary=synthetic", "application/json; charset=\"utf-8"] {
        let mut h = headers();
        h.insert("content-type", HeaderValue::from_str(rejected).unwrap());
        assert_eq!(decode_submission(&h, &body).err(), Some(WireError::UnsupportedMediaType));
    }
    let mut h = headers();
    h.remove("content-type");
    assert_eq!(decode_submission(&h, &body).err(), Some(WireError::UnsupportedMediaType));
}

#[test]
fn duplicate_framing_and_encoding_headers_are_not_coalesced() {
    let body = bytes(&valid());
    for name in ["content-type", "content-length", "content-encoding", "transfer-encoding"] {
        let mut h = headers();
        h.remove(name);
        let value = match name {
            "content-type" => "application/json".to_string(),
            "content-length" => body.len().to_string(),
            "content-encoding" => "identity".to_string(),
            _ => "chunked".to_string(),
        };
        h.append(name, HeaderValue::from_str(&value).unwrap());
        h.append(name, HeaderValue::from_str(&value).unwrap());
        assert_eq!(decode_submission(&h, &body).err(), Some(WireError::InvalidHeaders));
    }
}

#[test]
fn encoded_bodies_and_ambiguous_message_framing_fail_closed() {
    let body = bytes(&valid());
    for encoding in ["gzip", "br", "identity,identity", ""] {
        let mut h = headers();
        h.insert("content-encoding", HeaderValue::from_str(encoding).unwrap());
        assert_eq!(decode_submission(&h, &body).err(), Some(WireError::UnsupportedEncoding));
    }
    for length in ["0".to_string(), (body.len() + 1).to_string(), "+1".into(), "1,1".into(),
        "-1".into(), "184467440737095516160".into(), " 1".into()] {
        let mut h = headers();
        h.insert("content-length", HeaderValue::from_str(&length).unwrap());
        assert_eq!(decode_submission(&h, &body).err(), Some(WireError::InvalidHeaders));
    }
    let mut h = headers();
    h.insert("content-length", HeaderValue::from_str(&body.len().to_string()).unwrap());
    assert!(decode_submission(&h, &body).is_ok());
    h.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    assert_eq!(decode_submission(&h, &body).err(), Some(WireError::InvalidHeaders));
    h.remove("content-length");
    assert!(decode_submission(&h, &body).is_ok());
    h.insert("trailer", HeaderValue::from_static("Idempotency-Key"));
    assert_eq!(decode_submission(&h, &body).err(), Some(WireError::InvalidHeaders));
}

#[test]
fn errors_do_not_echo_claims_headers_or_credentials() {
    let marker = "SYNTHETIC-PRIVATE-DO-NOT-ECHO";
    let mut value = valid();
    value["claims"]["unknown"] = json!({"access_token": marker});
    let error = decode_submission(&headers(), &bytes(&value)).err().unwrap();
    assert!(!format!("{error:?} {error}").contains(marker));
    let mut h = headers();
    h.insert("content-type", HeaderValue::from_str(marker).unwrap());
    let error = decode_submission(&h, &bytes(&valid())).err().unwrap();
    assert!(!format!("{error:?} {error}").contains(marker));
}
