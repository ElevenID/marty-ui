use std::{collections::VecDeque, sync::Arc};

use async_trait::async_trait;
use chrono::Utc;
use marty_trust_profile::{
    MemoryTrustProfileRepository, NativeTrustRegistrySynchronizer, TrustProfile,
    TrustProfileRepository, TrustProfileStatus, TrustProfileType, TrustRegistrySynchronizer,
    TrustSource, TrustSourceType,
};
use mmf_platform::{OutboundHttpClient, OutboundHttpRequest, OutboundHttpResponse, PlatformError};
use serde_json::{json, Map};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug)]
struct HttpStub {
    responses: Mutex<VecDeque<OutboundHttpResponse>>,
    requests: Mutex<Vec<OutboundHttpRequest>>,
}

#[async_trait]
impl OutboundHttpClient for HttpStub {
    async fn execute(
        &self,
        request: OutboundHttpRequest,
    ) -> Result<OutboundHttpResponse, PlatformError> {
        self.requests.lock().await.push(request);
        self.responses
            .lock()
            .await
            .pop_front()
            .ok_or_else(|| PlatformError::Operation("missing stub response".into()))
    }
}

fn response(token: &str, sequence: u64, has_more: bool) -> OutboundHttpResponse {
    OutboundHttpResponse {
        status: 200,
        headers: [(
            "content-type".into(),
            "application/json; charset=utf-8".into(),
        )]
        .into_iter()
        .collect(),
        body: serde_json::to_vec(&json!({
            "sync_token": token,
            "sequence": sequence,
            "entries": [],
            "has_more": has_more,
            "generated_at": Utc::now(),
        }))
        .unwrap(),
    }
}

fn profile() -> TrustProfile {
    let now = Utc::now();
    TrustProfile {
        id: Uuid::new_v4(),
        organization_id: "org-1".into(),
        name: "Registry profile".into(),
        description: None,
        status: TrustProfileStatus::Draft,
        profile_type: TrustProfileType::Custom,
        compliance_status: marty_trust_profile::ComplianceStatus::SetupRequired,
        trust_sources: vec![TrustSource {
            id: Uuid::new_v4(),
            name: "Registry".into(),
            source_type: TrustSourceType::TrustList,
            url: Some("https://registry.example/sync".into()),
            certificate_pem: None,
            issuer_did: None,
            description: None,
            pinned_certificates: vec![],
            refresh_interval_hours: 24,
            enabled: true,
            registry_sync: Some(json!({
                "protocol": "MARTY_TRUST_REGISTRY_SYNC_V1",
                "refresh_interval_hours": 24
            })),
            registry_sync_token: None,
            registry_sequence: 0,
            registry_entries: Map::new(),
            registry_last_synced_at: None,
            extensions: Map::new(),
        }],
        validation_rules: Default::default(),
        allowed_issuers: None,
        denied_issuers: None,
        system_issuer_overrides: Map::new(),
        compatible_compliance_codes: vec![],
        verification_policy_set_id: None,
        auto_generated: false,
        revocation_policy: Default::default(),
        revocation_profile_id: None,
        time_policy: Default::default(),
        supported_formats: vec!["MDOC".into()],
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn native_sync_paginates_through_mmf_and_commits_one_atomic_profile_state() {
    let repository = Arc::new(MemoryTrustProfileRepository::default());
    let profile = profile();
    repository.save_profile(&profile, None).await.unwrap();
    let http = Arc::new(HttpStub {
        responses: Mutex::new(VecDeque::from([
            response("page-2", 0, true),
            response("complete", 1, false),
        ])),
        requests: Mutex::new(vec![]),
    });
    let synchronizer = NativeTrustRegistrySynchronizer::with_http_client(
        Arc::clone(&repository) as Arc<dyn TrustProfileRepository>,
        Arc::clone(&http) as Arc<dyn OutboundHttpClient>,
    );

    let result = synchronizer.synchronize(profile.clone()).await.unwrap();
    assert_eq!(result["sources"][0]["sequence"], 1);
    let saved = repository.profile_by_id(profile.id).await.unwrap().unwrap();
    assert_eq!(saved.trust_sources[0].registry_sequence, 1);
    assert_eq!(
        saved.trust_sources[0].registry_sync_token.as_deref(),
        Some("complete")
    );
    let requests = http.requests.lock().await;
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].url, "https://registry.example/sync");
    assert_eq!(
        requests[1].url,
        "https://registry.example/sync?since=page-2"
    );
    assert!(requests
        .iter()
        .all(|request| request.maximum_response_bytes == 2 * 1024 * 1024));
}

#[tokio::test]
async fn failed_later_page_leaves_the_previous_profile_state_unchanged() {
    let repository = Arc::new(MemoryTrustProfileRepository::default());
    let profile = profile();
    repository.save_profile(&profile, None).await.unwrap();
    let http = Arc::new(HttpStub {
        responses: Mutex::new(VecDeque::from([
            response("page-2", 0, true),
            OutboundHttpResponse {
                status: 200,
                headers: [("content-type".into(), "text/html".into())]
                    .into_iter()
                    .collect(),
                body: b"not JSON".to_vec(),
            },
        ])),
        requests: Mutex::new(vec![]),
    });
    let synchronizer = NativeTrustRegistrySynchronizer::with_http_client(
        Arc::clone(&repository) as Arc<dyn TrustProfileRepository>,
        http as Arc<dyn OutboundHttpClient>,
    );

    assert!(synchronizer.synchronize(profile.clone()).await.is_err());
    let saved = repository.profile_by_id(profile.id).await.unwrap().unwrap();
    assert_eq!(saved.trust_sources[0].registry_sequence, 0);
    assert!(saved.trust_sources[0].registry_last_synced_at.is_none());
}
