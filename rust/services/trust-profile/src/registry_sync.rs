use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use chrono::Utc;
use mmf_platform::{
    OutboundDestinationPolicy, OutboundHttpClient, OutboundHttpMethod, OutboundHttpRequest,
    OutboundQueryPolicy, ReqwestOutboundHttpClient,
};
use serde_json::{json, Map, Value};

use crate::{
    TrustProfile, TrustProfileRepository, TrustRegistrySyncError, TrustRegistrySynchronizer,
    TrustSourceType,
};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PAGES: usize = 100;

#[derive(Clone)]
pub struct NativeTrustRegistrySynchronizer {
    repository: Arc<dyn TrustProfileRepository>,
    http: Arc<dyn OutboundHttpClient>,
}

impl std::fmt::Debug for NativeTrustRegistrySynchronizer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeTrustRegistrySynchronizer")
            .finish_non_exhaustive()
    }
}

impl NativeTrustRegistrySynchronizer {
    pub fn new(
        repository: Arc<dyn TrustProfileRepository>,
        timeout: Duration,
        approved_private_hosts: impl IntoIterator<Item = String>,
        operator_ca_bundle: Option<&[u8]>,
    ) -> Result<Self, TrustRegistrySyncError> {
        let mut policy =
            OutboundDestinationPolicy::public_https().with_query_policy(OutboundQueryPolicy::Allow);
        policy.allowed_non_public_hosts = approved_private_hosts
            .into_iter()
            .map(|host| host.trim().to_ascii_lowercase())
            .filter(|host| !host.is_empty())
            .collect();
        let http = ReqwestOutboundHttpClient::new_guarded_with_ca_bundle(
            timeout,
            policy,
            operator_ca_bundle,
        )
        .map_err(|error| TrustRegistrySyncError::Failed(error.to_string()))?;
        Ok(Self {
            repository,
            http: Arc::new(http),
        })
    }

    #[must_use]
    pub fn with_http_client(
        repository: Arc<dyn TrustProfileRepository>,
        http: Arc<dyn OutboundHttpClient>,
    ) -> Self {
        Self { repository, http }
    }

    async fn synchronize_source(
        &self,
        source: &mut crate::TrustSource,
        now: chrono::DateTime<Utc>,
    ) -> Result<Value, TrustRegistrySyncError> {
        let url = source
            .url
            .as_deref()
            .ok_or_else(|| failed("registry source URL is missing"))?;
        marty_verification::trust_sync::validate_registry_url(url)
            .map_err(|error| failed(error.to_string()))?;
        let previous = state(source)?;
        let mut pages = Vec::new();
        let mut token = previous.sync_token.clone();
        let completed = loop {
            if pages.len() == MAX_PAGES {
                return Err(failed("registry pagination exceeded the page limit"));
            }
            let plan = marty_verification::trust_sync::plan_request(url, token.as_deref(), None)
                .map_err(|error| failed(error.to_string()))?;
            let response = self
                .http
                .execute(OutboundHttpRequest {
                    method: OutboundHttpMethod::Get,
                    url: plan.request_url,
                    headers: BTreeMap::from([("accept".into(), "application/json".into())]),
                    body: None,
                    maximum_response_bytes: MAX_RESPONSE_BYTES,
                })
                .await
                .map_err(|error| failed(error.to_string()))?;
            if !(200..300).contains(&response.status) {
                return Err(failed(format!(
                    "registry request returned HTTP {}",
                    response.status
                )));
            }
            if !response
                .headers
                .get("content-type")
                .is_some_and(|value| value.to_ascii_lowercase().contains("application/json"))
            {
                return Err(failed("registry response must be application/json"));
            }
            let body = std::str::from_utf8(&response.body)
                .map_err(|_| failed("registry response violates the sync contract"))?;
            pages.push(
                marty_verification::trust_sync::parse_feed_json(body)
                    .map_err(|error| failed(error.to_string()))?,
            );
            let evaluation = marty_verification::trust_sync::evaluate_pages(&previous, &pages, now)
                .map_err(|error| failed(error.to_string()))?;
            if evaluation.complete {
                break evaluation;
            }
            token = Some(evaluation.next_token);
        };
        let state = completed
            .state
            .ok_or_else(|| failed("completed registry result omitted state"))?;
        let csca_entries = state
            .entries
            .values()
            .filter(|entry| entry.anchor_type == marty_verification::trust_sync::AnchorType::Csca)
            .count();
        let dsc_entries = state.entries.len().saturating_sub(csca_entries);
        source.registry_sync_token = state.sync_token;
        source.registry_sequence = state.sequence;
        source.registry_entries = state
            .entries
            .into_iter()
            .map(|(id, entry)| {
                serde_json::to_value(entry)
                    .map(|entry| (id, entry))
                    .map_err(|_| failed("registry state serialization failed"))
            })
            .collect::<Result<Map<_, _>, _>>()?;
        source.registry_last_synced_at = state.synchronized_at;
        Ok(json!({
            "url": url,
            "protocol": marty_verification::trust_sync::SYNC_PROTOCOL,
            "sequence": source.registry_sequence,
            "csca_entries": csca_entries,
            "dsc_entries": dsc_entries,
            "synchronized_at": source.registry_last_synced_at,
        }))
    }
}

#[async_trait]
impl TrustRegistrySynchronizer for NativeTrustRegistrySynchronizer {
    async fn synchronize(
        &self,
        mut profile: TrustProfile,
    ) -> Result<Value, TrustRegistrySyncError> {
        let expected_updated_at = profile.updated_at;
        let now = Utc::now();
        let mut summaries = Vec::new();
        for source in profile.trust_sources.iter_mut().filter(|source| {
            source.enabled
                && source.registry_sync.is_some()
                && matches!(
                    source.source_type,
                    TrustSourceType::TrustList | TrustSourceType::PkdUrl
                )
        }) {
            summaries.push(self.synchronize_source(source, now).await?);
        }
        if summaries.is_empty() {
            return Err(failed(
                "Trust Profile has no enabled native registry sources",
            ));
        }
        profile.updated_at = now;
        let saved = self
            .repository
            .save_profile(&profile, Some(expected_updated_at))
            .await
            .map_err(|error| failed(error.to_string()))?;
        if !saved {
            return Err(failed("Trust Profile changed during registry sync"));
        }
        Ok(json!({
            "trust_profile_id": profile.id,
            "sources": summaries,
            "synchronized_at": now,
        }))
    }
}

fn state(
    source: &crate::TrustSource,
) -> Result<marty_verification::trust_sync::RegistryImportState, TrustRegistrySyncError> {
    let candidate = marty_verification::trust_sync::RegistryImportState {
        sync_token: source.registry_sync_token.clone(),
        sequence: source.registry_sequence,
        entries: source
            .registry_entries
            .iter()
            .map(|(id, value)| {
                serde_json::from_value(value.clone())
                    .map(|entry| (id.clone(), entry))
                    .map_err(|_| failed("stored registry state is invalid"))
            })
            .collect::<Result<_, _>>()?,
        synchronized_at: source.registry_last_synced_at,
    };
    let json = serde_json::to_string(&candidate)
        .map_err(|_| failed("stored registry state is invalid"))?;
    marty_verification::trust_sync::parse_state_json(&json)
        .map_err(|error| failed(error.to_string()))
}

fn failed(message: impl Into<String>) -> TrustRegistrySyncError {
    TrustRegistrySyncError::Failed(message.into())
}
