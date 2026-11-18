//! Verify an authenticated public signing-service challenge using the native
//! public issuer-resolution contract and marty-crypto. This proves one exact
//! signing capability; it does not issue a credential or qualify a deployment.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_crypto::{ecdsa, jwk::PublicJwk};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const SCHEMA: &str = "marty.signing-capability/v1";
pub const MAX_PROBE_BYTES: usize = 64 * 1024;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedSigningCapability {
    pub run_id: String,
    pub nonce: String,
    pub organization_id: String,
    pub service_id: String,
    pub issuer_did: String,
    pub key_reference: String,
    pub key_purpose: String,
    pub credential_format: String,
    pub algorithm: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicResponse {
    pub status: u16,
    pub body: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningCapabilityInput {
    pub expected: ExpectedSigningCapability,
    pub service_response: PublicResponse,
    pub identity_response: PublicResponse,
    pub signing_response: Option<PublicResponse>,
}

fn sha256(bytes: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(bytes.as_ref()))
}

fn text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn json_hash(value: &Value) -> Result<String, &'static str> {
    serde_json::to_vec(value)
        .map(sha256)
        .map_err(|_| "invalid public response")
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or("missing public contract field")
}

fn decode(value: &str) -> Result<Vec<u8>, &'static str> {
    // Signing API responses allow padded standard base64 or unpadded base64url.
    let normalized = value
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_");
    URL_SAFE_NO_PAD
        .decode(normalized)
        .map_err(|_| "invalid public signature encoding")
}

fn includes(value: &Value, key: &str, expected: &str) -> bool {
    value
        .get(key)
        .and_then(Value::as_array)
        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(expected)))
}

struct PreparedCapability {
    payload: Vec<u8>,
    point: Vec<u8>,
    binding: String,
    public_key: String,
}

fn prepared(input: &SigningCapabilityInput) -> Result<PreparedCapability, &'static str> {
    let expected = &input.expected;
    if !text(&expected.run_id, 128)
        || !hash(&expected.nonce)
        || !text(&expected.organization_id, 255)
        || !text(&expected.service_id, 255)
        || !text(&expected.issuer_did, 1024)
        || !expected.issuer_did.starts_with("did:web:")
        || !text(&expected.key_reference, 512)
        || !matches!(
            expected.key_purpose.as_str(),
            "vc_jwt_issuer" | "oid4vp_request_signing"
        )
        || expected.credential_format != "SD_JWT_VC"
        || expected.algorithm != "ES256"
    {
        return Err("invalid expected signing capability");
    }
    if input.service_response.status != 200 || input.identity_response.status != 200 {
        return Err("public signing and identity resolution must both succeed");
    }
    let service = &input.service_response.body["service"];
    let resolved_by = &input.service_response.body["resolved_by"];
    if service
        .get("auth_reference")
        .is_some_and(|value| value.as_str() != Some(""))
    {
        return Err("public service resolution contains credential material");
    }
    if field(service, "id")? != expected.service_id
        || field(service, "key_reference")? != expected.key_reference
        || !matches!(
            field(service, "status")?,
            "active" | "configured" | "registered"
        )
        || !includes(service, "algorithms", &expected.algorithm)
        || !includes(service, "key_purposes", &expected.key_purpose)
        || field(resolved_by, "algorithm")? != expected.algorithm
        || field(resolved_by, "key_purpose")? != expected.key_purpose
    {
        return Err("resolved service differs from the exact requested key, purpose, or algorithm");
    }
    let resolution = &input.identity_response.body;
    let identity = &resolution["identity"];
    for (key, wanted) in [
        ("issuer_did", expected.issuer_did.as_str()),
        ("key_purpose", expected.key_purpose.as_str()),
        ("credential_format", expected.credential_format.as_str()),
        ("algorithm", expected.algorithm.as_str()),
        ("status", "active"),
    ] {
        if field(identity, key)? != wanted {
            return Err("public identity differs from the exact active tuple");
        }
    }
    // Verify the opaque public binding defined by signing-keys/http.rs
    // managed_key_binding_sha256. The service keeps raw custody out of the
    // identity DTO; this comparison binds that DTO to the selected tenant/key.
    let binding = [
        "marty-managed-key-binding-v1",
        &expected.organization_id,
        &expected.service_id,
        &expected.key_reference,
    ]
    .join("\0")
        + "\0";
    let binding_sha256 = sha256(binding);
    if field(resolution, "managed_key_binding_sha256")? != binding_sha256 {
        return Err("public identity is not bound to the expected organization, service, and key");
    }
    let public = &resolution["public_jwk"];
    if [
        "kid",
        "key_reference",
        "auth_reference",
        "auth_token",
        "access_token",
        "secret",
    ]
    .iter()
    .any(|name| public.get(name).is_some())
    {
        return Err("issuer resolution contains non-public custody fields");
    }
    let key =
        PublicJwk::from_json(&public.to_string()).map_err(|_| "invalid public-only issuer key")?;
    if key.kty != "EC"
        || key.crv.as_deref() != Some("P-256")
        || key.alg.as_deref().is_some_and(|value| value != "ES256")
        || key.use_.as_deref().is_some_and(|value| value != "sig")
        || key
            .key_ops
            .as_ref()
            .is_some_and(|ops| !ops.iter().any(|op| op == "verify"))
    {
        return Err("issuer key does not support the requested ES256 signature");
    }
    let x = decode(key.x.as_deref().ok_or("issuer key has no coordinate")?)?;
    let y = decode(key.y.as_deref().ok_or("issuer key has no coordinate")?)?;
    if x.len() != 32 || y.len() != 32 {
        return Err("invalid P-256 public key coordinates");
    }
    let mut point = vec![4];
    point.extend(&x);
    point.extend(&y);
    let public_key_sha256 = sha256(&point);
    let payload = [
        SCHEMA,
        &expected.run_id,
        &expected.nonce,
        &expected.organization_id,
        &expected.service_id,
        &expected.issuer_did,
        &expected.key_reference,
        &expected.key_purpose,
        &expected.credential_format,
        &expected.algorithm,
        &binding_sha256,
        &public_key_sha256,
    ]
    .join("\0")
        + "\0";
    Ok(PreparedCapability {
        payload: payload.into_bytes(),
        point,
        binding: binding_sha256,
        public_key: public_key_sha256,
    })
}

pub fn prepare_signing_capability(input: &SigningCapabilityInput) -> Result<Value, &'static str> {
    let PreparedCapability { payload, .. } = prepared(input)?;
    Ok(json!({
        "schema": SCHEMA,
        "challenge_sha256": sha256(&payload),
        "request": {
            "payload_b64": URL_SAFE_NO_PAD.encode(payload),
            "key_reference": input.expected.key_reference,
            "key_purpose": input.expected.key_purpose,
            "algorithm": input.expected.algorithm,
        }
    }))
}

pub fn verify_signing_capability(input: &SigningCapabilityInput) -> Result<Value, &'static str> {
    let PreparedCapability {
        payload,
        point,
        binding,
        public_key,
    } = prepared(input)?;
    let response = input
        .signing_response
        .as_ref()
        .ok_or("missing signing response")?;
    let body = &response.body;
    if response.status != 200
        || body["ok"] != true
        || field(body, "service_id")? != input.expected.service_id
        || field(body, "algorithm")? != input.expected.algorithm
        || body["payload_length"].as_u64() != Some(payload.len() as u64)
        || !matches!(field(body, "signature_encoding")?, "der" | "raw")
        || chrono::DateTime::parse_from_rfc3339(field(body, "signed_at")?).is_err()
    {
        return Err("signing response does not establish the requested operation");
    }
    let signature = decode(field(body, "signature_b64")?)?;
    let normalized =
        ecdsa::normalize_signature(&signature, "ES256").map_err(|_| "invalid ES256 signature")?;
    let hex: String = signature.iter().map(|byte| format!("{byte:02x}")).collect();
    let raw_hex: String = normalized
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if field(body, "signature_hex")? != hex
        || body.get("signature_raw_b64").is_some_and(|raw| {
            raw.as_str().and_then(|value| decode(value).ok()).as_ref() != Some(&normalized)
        })
        || body
            .get("signature_raw_hex")
            .is_some_and(|raw| raw.as_str() != Some(raw_hex.as_str()))
    {
        return Err("public signature representations disagree");
    }
    if ecdsa::verify_p256_sha256(&point, &payload, &signature).ok() != Some(true) {
        return Err("signature does not verify against the exact issuer key and fresh challenge");
    }
    Ok(json!({
        "schema": SCHEMA, "verified": true,
        "scope": "EXACT_PUBLIC_SERVICE_SIGNING_CAPABILITY_ONLY",
        "run_id": input.expected.run_id,
        "organization_id": input.expected.organization_id,
        "service_id": input.expected.service_id,
        "issuer_did": input.expected.issuer_did,
        "key_purpose": input.expected.key_purpose,
        "credential_format": input.expected.credential_format,
        "algorithm": input.expected.algorithm,
        "challenge_sha256": sha256(payload),
        "key_binding_sha256": binding,
        "public_key_sha256": public_key,
        "signature_sha256": sha256(signature),
        "service_response_sha256": json_hash(&input.service_response.body)?,
        "identity_response_sha256": json_hash(&input.identity_response.body)?,
        "signing_response_sha256": json_hash(body)?,
        "signed_at": body["signed_at"],
    }))
}
