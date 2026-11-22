//! Opt-in application email delivery. Provider acceptance is not inbox delivery.
//! The endpoint is fixed; credentials and provider response bodies never enter
//! delivery errors. Authentication mail remains owned by the selected OIDC IdP.

use crate::domain::{ChannelType, DeliveryResult, Notification};
use chrono::{DateTime, Utc};
use reqwest::{header::HeaderValue, Client, StatusCode};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, env, fs::File, io::Read, time::Duration};

const ENDPOINT: &str = "https://api.resend.com/emails";
const CONFIG_ERROR: &str =
    "notification email requires a supported provider, sender and private API-key file";
const MAX_RECIPIENTS: usize = 50;

struct ResendEmail {
    client: Client,
    endpoint: String,
    sender: String,
    authorization: HeaderValue,
}

pub(crate) fn valid_address(value: &str) -> bool {
    value.len() <= 254
        && value.is_ascii()
        && value.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && local.len() <= 64
                && local
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".!#$%&*+-/=?^_`{|}~".contains(&b))
                && !local.starts_with('.')
                && !local.ends_with('.')
                && !local.contains("..")
                && domain.contains('.')
                && domain.split('.').all(|part| {
                    !part.is_empty()
                        && part.len() <= 63
                        && !part.starts_with('-')
                        && !part.ends_with('-')
                        && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
        })
}

fn read_key(path: &str) -> Result<String, &'static str> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| CONFIG_ERROR)?
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|_| CONFIG_ERROR)?;
    if bytes.len() > 4096 {
        return Err(CONFIG_ERROR);
    }
    String::from_utf8(bytes).map_err(|_| CONFIG_ERROR)
}

fn configured(
    values: &BTreeMap<String, String>,
    read: impl Fn(&str) -> Result<String, &'static str>,
) -> Result<Option<ResendEmail>, &'static str> {
    let value = |name: &str| values.get(name).map_or("", String::as_str);
    // File-only credentials: reject direct environment values even if a file
    // also exists. The installer imports this file through scalar-file custody.
    if !value("NOTIFICATION_RESEND_API_KEY").is_empty() {
        return Err(CONFIG_ERROR);
    }
    let sender = value("NOTIFICATION_EMAIL_FROM");
    let path = value("NOTIFICATION_RESEND_API_KEY_FILE");
    let raw = if path.is_empty() {
        String::new()
    } else {
        read(path)?
    };
    let key = raw.trim_end_matches(['\r', '\n']);
    match value("NOTIFICATION_EMAIL_PROVIDER") {
        "" | "disabled" if sender.is_empty() && key.is_empty() => Ok(None),
        "resend"
            if valid_address(sender)
                && (16..=4096).contains(&key.len())
                && key.starts_with("re_")
                && key.bytes().all(|b| b.is_ascii_graphic()) =>
        {
            ResendEmail::new(sender, key, ENDPOINT).map(Some)
        }
        _ => Err(CONFIG_ERROR),
    }
}

fn from_environment() -> Result<Option<ResendEmail>, &'static str> {
    configured(&env::vars().collect(), read_key)
}

pub fn validate_environment() -> Result<(), &'static str> {
    from_environment().map(|_| ())
}

fn outcome(
    notification: &Notification,
    now: DateTime<Utc>,
    error_code: Option<&str>,
    should_retry: bool,
) -> DeliveryResult {
    DeliveryResult {
        notification_id: notification.id.clone(),
        channel: ChannelType::Email,
        success: error_code.is_none(),
        attempted_at: now,
        delivered_at: error_code.is_none().then(Utc::now),
        error_code: error_code.map(str::to_owned),
        should_retry: Some(should_retry),
        retry_after: None,
    }
}

fn idempotency_key(notification: &Notification, recipient: &str) -> String {
    let mut digest = Sha256::new();
    for value in [
        notification.organization_id.as_deref().unwrap_or(""),
        &notification.id,
        recipient,
    ] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    format!("elevenid-email-{:x}", digest.finalize())
}

impl ResendEmail {
    fn new(sender: &str, api_key: &str, endpoint: &str) -> Result<Self, &'static str> {
        let mut authorization =
            HeaderValue::from_str(&format!("Bearer {api_key}")).map_err(|_| CONFIG_ERROR)?;
        authorization.set_sensitive(true);
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| CONFIG_ERROR)?;
        Ok(Self {
            client,
            endpoint: endpoint.into(),
            sender: sender.into(),
            authorization,
        })
    }

    async fn send(
        &self,
        notification: &Notification,
        recipient: &str,
        now: DateTime<Utc>,
    ) -> DeliveryResult {
        if !valid_address(recipient) {
            return outcome(notification, now, Some("EMAIL_RECIPIENT_INVALID"), false);
        }
        if notification.subject.is_empty()
            || notification.subject.len() > 998
            || notification.subject.chars().any(char::is_control)
            || notification.body.is_empty()
            || notification.body.len() > 1_048_576
        {
            return outcome(notification, now, Some("EMAIL_CONTENT_INVALID"), false);
        }
        // Separate messages avoid revealing other recipients in a To header.
        let response = self
            .client
            .post(&self.endpoint)
            .header(reqwest::header::AUTHORIZATION, self.authorization.clone())
            .header("Idempotency-Key", idempotency_key(notification, recipient))
            .json(&serde_json::json!({
                "from": self.sender,
                "to": [recipient],
                "subject": notification.subject,
                "text": notification.body,
            }))
            .send()
            .await;
        let mut response = match response {
            Ok(value) => value,
            Err(_) => return outcome(notification, now, Some("EMAIL_DELIVERY_FAILED"), true),
        };
        let status = response.status();
        if !status.is_success() {
            let (code, retry) = if status.is_redirection() {
                ("EMAIL_PROVIDER_REDIRECT_REJECTED", false)
            } else if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
                ("EMAIL_PROVIDER_AUTH_FAILED", false)
            } else if status == StatusCode::TOO_MANY_REQUESTS {
                ("EMAIL_PROVIDER_RATE_LIMITED", true)
            } else if status.is_server_error() || matches!(status.as_u16(), 408 | 425) {
                ("EMAIL_PROVIDER_UNAVAILABLE", true)
            } else {
                ("EMAIL_PROVIDER_REJECTED", false)
            };
            return outcome(notification, now, Some(code), retry);
        }
        // A 2xx without a bounded provider message ID is not delivery evidence.
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if body.len() + chunk.len() <= 4096 => {
                    body.extend_from_slice(&chunk)
                }
                Ok(None) => break,
                _ => return outcome(notification, now, Some("EMAIL_RESPONSE_INVALID"), true),
            }
        }
        #[derive(Deserialize)]
        struct Accepted {
            id: String,
        }
        let accepted = serde_json::from_slice::<Accepted>(&body)
            .is_ok_and(|value| uuid::Uuid::parse_str(&value.id).is_ok());
        if accepted {
            outcome(notification, now, None, false)
        } else {
            outcome(notification, now, Some("EMAIL_RESPONSE_INVALID"), true)
        }
    }
}

pub(crate) async fn deliver(
    notification: &Notification,
    now: DateTime<Utc>,
) -> Vec<DeliveryResult> {
    let recipients = notification
        .target
        .as_ref()
        .map(|target| target.email_addresses.as_slice())
        .unwrap_or(&[]);
    if recipients.is_empty() {
        return vec![outcome(notification, now, Some("NO_EMAIL_TARGETS"), false)];
    }
    if recipients.len() > MAX_RECIPIENTS {
        return vec![outcome(
            notification,
            now,
            Some("EMAIL_RECIPIENT_LIMIT"),
            false,
        )];
    }
    let adapter = match from_environment() {
        Ok(Some(value)) => value,
        Ok(None) => {
            return vec![outcome(
                notification,
                now,
                Some("EMAIL_ADAPTER_UNAVAILABLE"),
                false,
            )]
        }
        Err(_) => {
            return vec![outcome(
                notification,
                now,
                Some("EMAIL_CONFIGURATION_INVALID"),
                false,
            )]
        }
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut results = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let result = if tokio::time::Instant::now() >= deadline {
            outcome(notification, now, Some("EMAIL_BATCH_TIMEOUT"), true)
        } else {
            tokio::time::timeout_at(deadline, adapter.send(notification, recipient, now))
                .await
                .unwrap_or_else(|_| outcome(notification, now, Some("EMAIL_BATCH_TIMEOUT"), true))
        };
        results.push(result);
    }
    results
}

#[cfg(test)]
#[path = "email_tests.rs"]
mod tests;
