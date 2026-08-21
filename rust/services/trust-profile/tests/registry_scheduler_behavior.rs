use std::sync::Arc;

use async_trait::async_trait;
use chrono::{Duration, TimeZone, Utc};
use marty_trust_profile::{
    MemoryTrustProfileRepository, NativeTrustRegistrySynchronizer, TrustProfile,
    TrustProfileRepository, TrustProfileStatus, TrustProfileType, TrustRegistryScheduler,
    TrustSource, TrustSourceType,
};
use mmf_platform::{OutboundHttpClient, OutboundHttpRequest, OutboundHttpResponse, PlatformError};
use serde_json::{json, Map};
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug)]
struct RecordingHttp {
    requests: Mutex<Vec<OutboundHttpRequest>>,
    response: OutboundHttpResponse,
}

#[async_trait]
impl OutboundHttpClient for RecordingHttp {
    async fn execute(
        &self,
        request: OutboundHttpRequest,
    ) -> Result<OutboundHttpResponse, PlatformError> {
        self.requests.lock().await.push(request);
        Ok(self.response.clone())
    }
}

fn profile(name: &str, synchronized_at: chrono::DateTime<Utc>) -> TrustProfile {
    let created_at = Utc.with_ymd_and_hms(2026, 8, 20, 0, 0, 0).unwrap();
    TrustProfile {
        id: Uuid::new_v4(),
        organization_id: "org-1".into(),
        name: name.into(),
        description: None,
        status: TrustProfileStatus::Draft,
        profile_type: TrustProfileType::Custom,
        compliance_status: marty_trust_profile::ComplianceStatus::SetupRequired,
        trust_sources: vec![TrustSource {
            id: Uuid::new_v4(),
            name: format!("{name} registry"),
            source_type: TrustSourceType::TrustList,
            url: Some(format!("https://registry.example/{name}/sync")),
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
            registry_sync_token: Some("1".into()),
            registry_sequence: 1,
            registry_entries: Map::new(),
            registry_last_synced_at: Some(synchronized_at),
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
        created_at,
        updated_at: created_at,
    }
}

#[tokio::test]
async fn scheduler_refreshes_at_eighty_percent_and_isolates_profile_failures() {
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 0, 0, 0).unwrap();
    let repository = Arc::new(MemoryTrustProfileRepository::default());
    let due = profile("due", now - Duration::hours(20));
    let fresh = profile("fresh", now - Duration::hours(1));
    let mut invalid = profile("invalid", now - Duration::hours(20));
    invalid.trust_sources[0].registry_sync = Some(json!({"protocol": "unknown"}));
    for candidate in [&due, &fresh, &invalid] {
        repository.save_profile(candidate, None).await.unwrap();
    }
    let http = Arc::new(RecordingHttp {
        requests: Mutex::new(vec![]),
        response: OutboundHttpResponse {
            status: 200,
            headers: [("content-type".into(), "application/json".into())]
                .into_iter()
                .collect(),
            body: serde_json::to_vec(&json!({
                "sync_token": "2",
                "sequence": 2,
                "entries": [],
                "has_more": false,
                "generated_at": now,
            }))
            .unwrap(),
        },
    });
    let synchronizer = Arc::new(NativeTrustRegistrySynchronizer::with_http_client(
        Arc::clone(&repository) as Arc<dyn TrustProfileRepository>,
        Arc::clone(&http) as Arc<dyn OutboundHttpClient>,
    ));
    let scheduler = TrustRegistryScheduler::new(
        Arc::clone(&repository) as Arc<dyn TrustProfileRepository>,
        synchronizer,
        std::time::Duration::from_secs(300),
    );

    let report = scheduler.run_once_at(now).await.unwrap();

    assert_eq!(report.due_profiles, 2);
    assert_eq!(report.synchronized_profiles, 1);
    assert_eq!(report.failed_profiles, 1);
    assert_eq!(report.synchronized_sources, 1);
    let requests = http.requests.lock().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url, "https://registry.example/due/sync?since=1");
    let stored_due = repository.profile_by_id(due.id).await.unwrap().unwrap();
    let stored_fresh = repository.profile_by_id(fresh.id).await.unwrap().unwrap();
    assert_eq!(stored_due.trust_sources[0].registry_sequence, 2);
    assert_eq!(stored_fresh.trust_sources[0].registry_sequence, 1);
}
