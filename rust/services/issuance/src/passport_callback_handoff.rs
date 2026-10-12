//! Shared KMS callback handoff for the beta bureau and physical provider ingress.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use marty_passport_auth::valid_provider_profile_id;
use reqwest::{Client, Url};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::passport_bureau::valid_kms_callback_signature;

const MAX_CALLBACK_BODY_BYTES: usize = 64 * 1024;
const RECEIPT_DOMAIN: &[u8] = b"marty.passport-callback-receipt/v1\0";

/// Digest of the exact callback body and KMS signature accepted by the callback route.
/// The signature and body must not be stored in the beta simulator's job table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedCallbackReceipt {
    pub sha256: [u8; 32],
}

fn receipt_digest(
    body: &[u8],
    signature: &str,
) -> Result<SignedCallbackReceipt, CallbackHandoffError> {
    let body_len = u32::try_from(body.len()).map_err(|_| CallbackHandoffError::InvalidBody)?;
    let signature_len =
        u32::try_from(signature.len()).map_err(|_| CallbackHandoffError::InvalidBody)?;
    let mut hash = Sha256::new();
    hash.update(RECEIPT_DOMAIN);
    hash.update(body_len.to_be_bytes());
    hash.update(body);
    hash.update(signature_len.to_be_bytes());
    hash.update(signature.as_bytes());
    Ok(SignedCallbackReceipt {
        sha256: hash.finalize().into(),
    })
}

#[derive(Debug, thiserror::Error)]
pub enum CallbackHandoffError {
    #[error("invalid passport callback body")]
    InvalidBody,
    #[error("invalid private callback signing endpoint")]
    InvalidSigningEndpoint,
    #[error("KMS callback signing unavailable")]
    SigningUnavailable,
    #[error("passport callback unavailable")]
    CallbackUnavailable,
}

/// Verify the external provider's exact callback bytes with a profile-scoped
/// imported HMAC key. The ingress never receives or computes with that key.
pub async fn verify_provider_callback(
    http: &Client,
    signing_base_url: &Url,
    signing_api_key: &str,
    provider_profile_id: &str,
    key_version: u32,
    body: &[u8],
    signature_hex: &str,
) -> Result<bool, CallbackHandoffError> {
    if !valid_provider_profile_id(provider_profile_id)
        || key_version == 0
        || body.is_empty()
        || body.len() > MAX_CALLBACK_BODY_BYTES
        || signature_hex.len() != 64
        || !signature_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CallbackHandoffError::InvalidBody);
    }
    let mut verify_url = signing_base_url.clone();
    verify_url
        .path_segments_mut()
        .map_err(|()| CallbackHandoffError::InvalidSigningEndpoint)?
        .push(provider_profile_id)
        .push("passport-provider-callbacks")
        .push("verify");
    let response = http
        .post(verify_url)
        .header("x-api-key", signing_api_key)
        .json(&json!({
            "body_b64": STANDARD.encode(body),
            "signature_hex": signature_hex,
            "key_version": key_version
        }))
        .send()
        .await
        .map_err(|_| CallbackHandoffError::SigningUnavailable)?;
    if !response.status().is_success() {
        return Err(CallbackHandoffError::SigningUnavailable);
    }
    response
        .json::<Value>()
        .await
        .map_err(|_| CallbackHandoffError::SigningUnavailable)?
        .get("valid")
        .and_then(Value::as_bool)
        .ok_or(CallbackHandoffError::SigningUnavailable)
}

/// Sign the exact internal body bytes, then deliver those same bytes to the
/// selected private callback route. Neither caller receives KMS material.
pub async fn sign_and_deliver(
    http: &Client,
    signing_base_url: &Url,
    signing_api_key: &str,
    callback_url: &Url,
    organization_id: &str,
    body: &[u8],
) -> Result<SignedCallbackReceipt, CallbackHandoffError> {
    if organization_id.trim().is_empty() || body.is_empty() || body.len() > MAX_CALLBACK_BODY_BYTES
    {
        return Err(CallbackHandoffError::InvalidBody);
    }
    let mut sign_url = signing_base_url.clone();
    sign_url
        .path_segments_mut()
        .map_err(|()| CallbackHandoffError::InvalidSigningEndpoint)?
        .push(organization_id)
        .push("passport-callbacks")
        .push("sign");
    let signed = http
        .post(sign_url)
        .header("x-api-key", signing_api_key)
        .json(&json!({"body_b64": STANDARD.encode(body)}))
        .send()
        .await
        .map_err(|_| CallbackHandoffError::SigningUnavailable)?;
    if !signed.status().is_success() {
        return Err(CallbackHandoffError::SigningUnavailable);
    }
    let signature = signed
        .json::<Value>()
        .await
        .map_err(|_| CallbackHandoffError::SigningUnavailable)?
        .get("signature")
        .and_then(Value::as_str)
        .filter(|signature| valid_kms_callback_signature(signature))
        .ok_or(CallbackHandoffError::SigningUnavailable)?
        .to_owned();
    let receipt = receipt_digest(body, &signature)?;
    let delivered = http
        .post(callback_url.clone())
        .header("x-personalization-signature", signature)
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|_| CallbackHandoffError::CallbackUnavailable)?;
    if !delivered.status().is_success() {
        return Err(CallbackHandoffError::CallbackUnavailable);
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_digest_binds_exact_body_and_signature_without_revealing_them() {
        let signature = "vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert!(valid_kms_callback_signature(signature));
        let first = receipt_digest(br#"{"status":"SHIPPED"}"#, signature).unwrap();
        // Independently calculated from the language-neutral u32-length preimage.
        let expected = "c509d5f0acf805a581db9430b376d4ec99c3bc017853e3c7bc7ca37954b4d3cd";
        assert_eq!(hex::encode(first.sha256), expected);
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/passport-beta-bureau-behavior.json"
        ))
        .unwrap();
        let vector = &contract["callback"]["signed_receipt_digest"]["test_vector"];
        assert_eq!(vector["body_utf8"], r#"{"status":"SHIPPED"}"#);
        assert_eq!(vector["signature_utf8"], signature);
        assert_eq!(vector["digest_hex"], expected);
        assert_ne!(
            first,
            receipt_digest(br#"{"status":"PRINTING"}"#, signature).unwrap()
        );
        assert_ne!(
            first,
            receipt_digest(
                br#"{"status":"SHIPPED"}"#,
                "vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=",
            )
            .unwrap()
        );
        assert_eq!(first.sha256.len(), 32);
    }
}
