use std::{collections::BTreeMap, time::Duration as StdDuration};

use chrono::{Duration, Utc};
use mmf_push::WebhookDestinationRegistry;
use thiserror::Error;
use tokio::sync::watch;

use crate::{
    CallbackEvent, ClaimedCallback, PostgresFlowRepository, RepositoryError,
    CALLBACK_LEASE_SECONDS, CALLBACK_MAX_ATTEMPTS, CALLBACK_POLL_MILLISECONDS,
};

const DEFAULT_BATCH_SIZE: u32 = 10;
const CONNECT_TIMEOUT_SECONDS: u64 = 3;
const REQUEST_TIMEOUT_SECONDS: u64 = 10;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackDeliveryConfig {
    pub max_attempts: u32,
    pub lease_seconds: u64,
    pub poll_milliseconds: u64,
    pub batch_size: u32,
    pub retention_seconds: u64,
    pub retry_base_seconds: u64,
    pub retry_cap_seconds: u64,
}

impl Default for CallbackDeliveryConfig {
    fn default() -> Self {
        Self {
            max_attempts: CALLBACK_MAX_ATTEMPTS,
            lease_seconds: CALLBACK_LEASE_SECONDS,
            poll_milliseconds: CALLBACK_POLL_MILLISECONDS,
            batch_size: DEFAULT_BATCH_SIZE,
            retention_seconds: crate::CALLBACK_RETENTION_SECONDS,
            retry_base_seconds: crate::CALLBACK_RETRY_BASE_SECONDS,
            retry_cap_seconds: crate::CALLBACK_RETRY_CAP_SECONDS,
        }
    }
}

impl CallbackDeliveryConfig {
    pub fn from_env() -> Result<Self, CallbackDeliveryError> {
        Self::from_values(std::env::vars())
    }

    pub fn from_values(
        values: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, CallbackDeliveryError> {
        let values = values.into_iter().collect::<BTreeMap<_, _>>();
        Ok(Self {
            max_attempts: bounded(
                &values,
                "FLOW_CALLBACK_MAX_ATTEMPTS",
                CALLBACK_MAX_ATTEMPTS,
                1,
                32,
            )?,
            lease_seconds: u64::from(bounded(
                &values,
                "FLOW_CALLBACK_LEASE_SECONDS",
                u32::try_from(CALLBACK_LEASE_SECONDS).unwrap_or(30),
                5,
                300,
            )?),
            poll_milliseconds: u64::from(bounded(
                &values,
                "FLOW_CALLBACK_POLL_MILLISECONDS",
                u32::try_from(CALLBACK_POLL_MILLISECONDS).unwrap_or(1_000),
                100,
                60_000,
            )?),
            batch_size: bounded(
                &values,
                "FLOW_CALLBACK_BATCH_SIZE",
                DEFAULT_BATCH_SIZE,
                1,
                100,
            )?,
            retention_seconds: u64::from(bounded(
                &values,
                "FLOW_CALLBACK_OUTBOX_RETENTION_SECONDS",
                u32::try_from(crate::CALLBACK_RETENTION_SECONDS).unwrap_or(900),
                60,
                86_400,
            )?),
            retry_base_seconds: u64::from(bounded(
                &values,
                "FLOW_CALLBACK_RETRY_BASE_SECONDS",
                u32::try_from(crate::CALLBACK_RETRY_BASE_SECONDS).unwrap_or(1),
                1,
                60,
            )?),
            retry_cap_seconds: u64::from(bounded(
                &values,
                "FLOW_CALLBACK_RETRY_CAP_SECONDS",
                u32::try_from(crate::CALLBACK_RETRY_CAP_SECONDS).unwrap_or(60),
                1,
                900,
            )?),
        })
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CallbackDeliveryReport {
    pub claimed: usize,
    pub delivered: usize,
    pub retry_scheduled: usize,
    pub dead_lettered: usize,
}

#[derive(Debug, Error)]
pub enum CallbackDeliveryError {
    #[error("FLOW.CALLBACK_CONFIGURATION: {0}")]
    Configuration(String),
    #[error("FLOW.CALLBACK_REPOSITORY_UNAVAILABLE")]
    Repository(#[from] RepositoryError),
    #[error("FLOW.CALLBACK_HTTP_CONFIGURATION")]
    HttpConfiguration,
}

pub async fn deliver_due_callbacks(
    repository: &PostgresFlowRepository,
    destinations: &WebhookDestinationRegistry,
    secret: &str,
    config: &CallbackDeliveryConfig,
) -> Result<CallbackDeliveryReport, CallbackDeliveryError> {
    if secret.len() < 32 {
        return Err(CallbackDeliveryError::Configuration(
            "FLOW_WEBHOOK_SECRET must contain at least 32 bytes".into(),
        ));
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(StdDuration::from_secs(CONNECT_TIMEOUT_SECONDS))
        .timeout(StdDuration::from_secs(REQUEST_TIMEOUT_SECONDS))
        .build()
        .map_err(|_| CallbackDeliveryError::HttpConfiguration)?;
    let now = Utc::now();
    let lease_expires_at = now
        .checked_add_signed(Duration::seconds(
            i64::try_from(config.lease_seconds).map_err(|_| {
                CallbackDeliveryError::Configuration("lease duration is invalid".into())
            })?,
        ))
        .ok_or_else(|| CallbackDeliveryError::Configuration("system clock is invalid".into()))?;
    let claimed = repository
        .claim_due_callbacks(now, lease_expires_at, config.batch_size)
        .await?;
    let mut report = CallbackDeliveryReport {
        claimed: claimed.len(),
        ..CallbackDeliveryReport::default()
    };
    for callback in claimed {
        deliver_claimed_callback(
            repository,
            destinations,
            secret,
            config,
            &client,
            &callback,
            &mut report,
        )
        .await?;
    }
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
async fn deliver_claimed_callback(
    repository: &PostgresFlowRepository,
    destinations: &WebhookDestinationRegistry,
    secret: &str,
    config: &CallbackDeliveryConfig,
    client: &reqwest::Client,
    callback: &ClaimedCallback,
    report: &mut CallbackDeliveryReport,
) -> Result<(), CallbackDeliveryError> {
    if destinations
        .require(&callback.organization_id, &callback.destination_url)
        .is_err()
    {
        mark_failed(
            repository,
            callback,
            config,
            "destination_rejected",
            true,
            report,
        )
        .await?;
        return Ok(());
    }
    let attempted_at = Utc::now();
    let timestamp = attempted_at.to_rfc3339();
    let event = CallbackEvent {
        event_id: callback.event_id.clone(),
        flow_instance_id: callback.flow_instance_id.clone(),
        organization_id: callback.organization_id.clone(),
        destination_url: callback.destination_url.clone(),
        audience: callback.audience.clone(),
        event_type: callback.event_type.clone(),
        payload: callback.payload.clone(),
        created_at_ms: 0,
        expires_at_ms: 0,
    };
    let headers = event
        .delivery_headers(secret, &timestamp, callback.attempt_count)
        .map_err(|_| CallbackDeliveryError::Configuration("callback signing failed".into()))?;
    let mut request = client
        .post(&callback.destination_url)
        .json(&callback.payload);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let outcome = match request.send().await {
        Ok(response) if response.status().is_success() => None,
        Ok(response) => Some(format!("http_{}", response.status().as_u16())),
        Err(error) if error.is_timeout() => Some("timeout".into()),
        Err(_) => Some("network_error".into()),
    };
    if let Some(error_code) = outcome {
        mark_failed(repository, callback, config, &error_code, false, report).await?;
    } else if repository
        .mark_callback_delivered(&callback.event_id, &callback.lease_token, Utc::now())
        .await?
    {
        report.delivered += 1;
    }
    Ok(())
}

async fn mark_failed(
    repository: &PostgresFlowRepository,
    callback: &ClaimedCallback,
    config: &CallbackDeliveryConfig,
    error_code: &str,
    force_terminal: bool,
    report: &mut CallbackDeliveryReport,
) -> Result<(), RepositoryError> {
    let terminal = force_terminal || callback.attempt_count >= config.max_attempts;
    let now = Utc::now();
    let exponent = callback.attempt_count.saturating_sub(1).min(16);
    let delay = config
        .retry_base_seconds
        .saturating_mul(2_u64.saturating_pow(exponent))
        .min(config.retry_cap_seconds);
    let next_attempt_at = now
        .checked_add_signed(Duration::seconds(i64::try_from(delay).unwrap_or(i64::MAX)))
        .unwrap_or(now);
    if repository
        .mark_callback_failed(
            &callback.event_id,
            &callback.lease_token,
            next_attempt_at,
            terminal,
            error_code,
        )
        .await?
    {
        if terminal {
            report.dead_lettered += 1;
        } else {
            report.retry_scheduled += 1;
        }
    }
    Ok(())
}

pub async fn run_callback_dispatcher(
    repository: PostgresFlowRepository,
    destinations: WebhookDestinationRegistry,
    secret: String,
    config: CallbackDeliveryConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), CallbackDeliveryError> {
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        if let Err(error) =
            deliver_due_callbacks(&repository, &destinations, &secret, &config).await
        {
            tracing::error!(error = %error, "Flow callback dispatcher iteration failed");
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            () = tokio::time::sleep(StdDuration::from_millis(config.poll_milliseconds)) => {}
        }
    }
}

fn bounded(
    values: &BTreeMap<String, String>,
    name: &'static str,
    default: u32,
    minimum: u32,
    maximum: u32,
) -> Result<u32, CallbackDeliveryError> {
    let Some(raw) = values.get(name).filter(|value| !value.trim().is_empty()) else {
        return Ok(default);
    };
    let value = raw
        .parse::<u32>()
        .map_err(|_| CallbackDeliveryError::Configuration(format!("{name} must be an integer")))?;
    if (minimum..=maximum).contains(&value) {
        Ok(value)
    } else {
        Err(CallbackDeliveryError::Configuration(format!(
            "{name} must be between {minimum} and {maximum}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_worker_configuration_preserves_released_bounds() {
        assert_eq!(
            CallbackDeliveryConfig::from_values(Vec::<(String, String)>::new()).unwrap(),
            CallbackDeliveryConfig::default()
        );
        let configured = CallbackDeliveryConfig::from_values([
            ("FLOW_CALLBACK_MAX_ATTEMPTS".into(), "32".into()),
            ("FLOW_CALLBACK_LEASE_SECONDS".into(), "300".into()),
            ("FLOW_CALLBACK_POLL_MILLISECONDS".into(), "60000".into()),
            ("FLOW_CALLBACK_BATCH_SIZE".into(), "100".into()),
            (
                "FLOW_CALLBACK_OUTBOX_RETENTION_SECONDS".into(),
                "86400".into(),
            ),
            ("FLOW_CALLBACK_RETRY_BASE_SECONDS".into(), "60".into()),
            ("FLOW_CALLBACK_RETRY_CAP_SECONDS".into(), "900".into()),
        ])
        .unwrap();
        assert_eq!(configured.max_attempts, 32);
        assert_eq!(configured.lease_seconds, 300);
        assert_eq!(configured.poll_milliseconds, 60_000);
        assert_eq!(configured.batch_size, 100);
        assert_eq!(configured.retention_seconds, 86_400);
        assert_eq!(configured.retry_base_seconds, 60);
        assert_eq!(configured.retry_cap_seconds, 900);
        assert!(CallbackDeliveryConfig::from_values([(
            "FLOW_CALLBACK_LEASE_SECONDS".into(),
            "4".into()
        )])
        .is_err());
    }
}
