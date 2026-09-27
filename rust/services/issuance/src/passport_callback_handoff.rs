//! Shared KMS callback handoff for the beta bureau and physical provider ingress.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{Client, Url};
use serde_json::{json, Value};

use crate::passport_bureau::valid_kms_callback_signature;

const MAX_CALLBACK_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CallbackHandoffError {
    #[error("invalid passport callback body")]
    InvalidBody,
    #[error("invalid private callback signing endpoint")]
    InvalidSigningEndpoint,
    #[error("KMS callback signing unavailable")]
    SigningUnavailable,
    #[error("native passport callback unavailable")]
    NativeUnavailable,
}

/// Sign the exact internal body bytes, then deliver those same bytes to native
/// issuance. Neither the bureau nor the public ingress receives KMS material.
pub async fn sign_and_deliver(
    http: &Client,
    signing_base_url: &Url,
    signing_api_key: &str,
    native_callback_url: &Url,
    organization_id: &str,
    body: &[u8],
) -> Result<(), CallbackHandoffError> {
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
    let delivered = http
        .post(native_callback_url.clone())
        .header("x-personalization-signature", signature)
        .header("content-type", "application/json")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|_| CallbackHandoffError::NativeUnavailable)?;
    if !delivered.status().is_success() {
        return Err(CallbackHandoffError::NativeUnavailable);
    }
    Ok(())
}
