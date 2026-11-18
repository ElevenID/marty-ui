use regex::Regex;
use serde_json::{Map, Value};
use std::{collections::HashMap, sync::LazyLock};
use thiserror::Error;

pub const MAX_NOTIFICATION_DATA_BYTES: usize = 4_096;
const MAX_NOTIFICATION_DATA_DEPTH: usize = 5;
const MAX_NOTIFICATION_COLLECTION_ITEMS: usize = 64;
const MAX_NOTIFICATION_KEY_LENGTH: usize = 128;

static COMPACT_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[^A-Za-z0-9_-])[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:$|[^A-Za-z0-9_-])")
        .expect("compact-token regex is valid")
});

const RAW_TEXT_MARKERS: [&str; 5] = [
    "\"credentialSubject\"",
    "\"presentation_submission\"",
    "\"privateKey\"",
    "\"proof\"",
    "\"vp_token\"",
];

const FORBIDDEN_KEYS: [&str; 25] = [
    "accesstoken",
    "claims",
    "clientsecret",
    "credential",
    "credentialjwt",
    "credentialpayload",
    "idtoken",
    "mdoc",
    "msomdoc",
    "payload",
    "presentation",
    "presentationsubmission",
    "privatekey",
    "proof",
    "rawcredential",
    "refreshtoken",
    "sdjwt",
    "sdjwtvc",
    "signedcredential",
    "subjectclaims",
    "token",
    "verifiablecredential",
    "verifiablepresentation",
    "vptoken",
    "secret",
];

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{0}")]
pub struct PayloadSecurityError(pub &'static str);

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

fn validate_value(value: &Value, depth: usize) -> Result<(), PayloadSecurityError> {
    if depth > MAX_NOTIFICATION_DATA_DEPTH {
        return Err(PayloadSecurityError(
            "notification data is too deeply nested",
        ));
    }
    match value {
        Value::Object(map) => {
            if map.len() > MAX_NOTIFICATION_COLLECTION_ITEMS {
                return Err(PayloadSecurityError(
                    "notification data contains too many object fields",
                ));
            }
            for (key, child) in map {
                if key.len() > MAX_NOTIFICATION_KEY_LENGTH {
                    return Err(PayloadSecurityError(
                        "notification data contains an invalid field name",
                    ));
                }
                let normalized = normalized_key(key);
                if FORBIDDEN_KEYS.contains(&normalized.as_str())
                    || normalized.ends_with("privatekey")
                    || normalized.ends_with("secret")
                {
                    return Err(PayloadSecurityError(
                        "notification data contains protected credential material",
                    ));
                }
                validate_value(child, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > MAX_NOTIFICATION_COLLECTION_ITEMS {
                return Err(PayloadSecurityError(
                    "notification data contains too many list items",
                ));
            }
            for child in values {
                validate_value(child, depth + 1)?;
            }
        }
        Value::String(value) if COMPACT_TOKEN.is_match(value) => {
            return Err(PayloadSecurityError(
                "notification data contains protected credential material",
            ));
        }
        Value::Number(number) if !number.is_i64() && !number.is_u64() && !number.is_f64() => {
            return Err(PayloadSecurityError(
                "notification data contains a non-JSON value",
            ));
        }
        _ => {}
    }
    Ok(())
}

pub fn validate_notification_data(data: &Map<String, Value>) -> Result<(), PayloadSecurityError> {
    let value = Value::Object(data.clone());
    validate_value(&value, 1)?;
    let encoded = serde_json::to_vec(&value)
        .map_err(|_| PayloadSecurityError("notification data is not valid JSON"))?;
    if encoded.len() > MAX_NOTIFICATION_DATA_BYTES {
        return Err(PayloadSecurityError(
            "notification data exceeds the 4 KB protocol limit",
        ));
    }
    Ok(())
}

pub fn validate_notification_text(title: &str, body: &str) -> Result<(), PayloadSecurityError> {
    if title.chars().count() > 256 {
        return Err(PayloadSecurityError(
            "notification title exceeds the 256 character protocol limit",
        ));
    }
    if body.chars().count() > 2_048 {
        return Err(PayloadSecurityError(
            "notification body exceeds the 2048 character protocol limit",
        ));
    }
    if [title, body].iter().any(|value| {
        COMPACT_TOKEN.is_match(value)
            || RAW_TEXT_MARKERS.iter().any(|marker| value.contains(marker))
    }) {
        return Err(PayloadSecurityError(
            "notification content contains protected credential material",
        ));
    }
    Ok(())
}

fn event_fields() -> HashMap<&'static str, &'static [&'static str]> {
    HashMap::from([
        (
            "credential.offered",
            &[
                "application_id",
                "credential_template_id",
                "credential_type",
                "offer_uri",
            ] as &[_],
        ),
        (
            "credential.issued",
            &[
                "application_id",
                "credential_id",
                "credential_template_id",
                "credential_type",
                "status",
            ],
        ),
        (
            "credential.revoked",
            &[
                "application_id",
                "credential_id",
                "credential_template_id",
                "credential_type",
                "reason_code",
                "status",
            ],
        ),
        (
            "verification.requested",
            &["expires_at", "policy_id", "request_uri", "verification_id"],
        ),
        (
            "application.received",
            &[
                "applicant_id",
                "application_id",
                "credential_template_id",
                "status",
            ],
        ),
        (
            "application.approved",
            &[
                "applicant_id",
                "application_id",
                "credential_template_id",
                "status",
            ],
        ),
        (
            "application.rejected",
            &[
                "applicant_id",
                "application_id",
                "credential_template_id",
                "status",
            ],
        ),
        (
            "applicant.submitted",
            &[
                "applicant_id",
                "application_id",
                "credential_template_id",
                "status",
            ],
        ),
        (
            "applicant.approved",
            &[
                "applicant_id",
                "application_id",
                "credential_template_id",
                "status",
            ],
        ),
        (
            "applicant.rejected",
            &[
                "applicant_id",
                "application_id",
                "credential_template_id",
                "status",
            ],
        ),
        (
            "applicant.status_changed",
            &[
                "applicant_id",
                "application_id",
                "credential_template_id",
                "status",
            ],
        ),
        (
            "device.key_expiring",
            &["device_id", "expires_at", "key_id"],
        ),
    ])
}

pub fn validate_internal_event_data(
    event_type: &str,
    data: &Map<String, Value>,
) -> Result<(), PayloadSecurityError> {
    let fields = event_fields();
    let allowed = fields.get(event_type).ok_or(PayloadSecurityError(
        "event_type is not supported for notification fan-out",
    ))?;
    if data.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(PayloadSecurityError(
            "event data contains fields outside the minimized event contract",
        ));
    }
    validate_notification_data(data)?;
    for (field, value) in data {
        let Value::String(value) = value else {
            if value.is_null() {
                continue;
            }
            if value.is_array() || value.is_object() {
                return Err(PayloadSecurityError(
                    "internal event data must contain scalar projection values",
                ));
            }
            return Err(PayloadSecurityError(
                "internal event projection values must be strings",
            ));
        };
        let max_length = if field.ends_with("_uri") { 2_048 } else { 256 };
        if value.chars().count() > max_length {
            return Err(PayloadSecurityError(
                "internal event projection value exceeds its size limit",
            ));
        }
    }
    Ok(())
}
