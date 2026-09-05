//! Real Linux HTTPS with child-scoped trust; no production TLS hook or policy change.
use super::fixture;
use async_trait::async_trait;
use chrono::Utc;
use marty_issuance_service::{
    canvas_lti_tool_signing::{CanvasLtiToolJwtSigner, CanvasLtiToolSigningError},
    canvas_provider_http::CanvasHttpClientPolicy,
    canvas_sync_processor::{
        CanvasAuthoritativeProvider, CanvasProviderReadError, CanvasSyncPlatformSnapshot,
        CanvasSyncResources,
    },
    canvas_sync_provider_http::HttpCanvasAuthoritativeProvider,
    canvas_sync_worker::{CanvasSyncTarget, CanvasSyncTargetType},
};
use marty_oid4vci::lti::{canvas_lti_trust_profile, CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN};
use serde_json::{json, Value};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Default)]
struct Signer {
    claims: Mutex<Vec<Value>>,
}

#[async_trait]
impl CanvasLtiToolJwtSigner for Signer {
    async fn sign_jwt(&self, claims: &Value) -> Result<String, CanvasLtiToolSigningError> {
        self.claims.lock().unwrap().push(claims.clone());
        Ok("synthetic-lti-assertion".into())
    }
    async fn public_jwks(&self) -> Result<Value, CanvasLtiToolSigningError> {
        panic!("Provider must use the signing port, not request private signing material")
    }
}

#[cfg(target_os = "linux")]
#[test]
fn actual_ags_nrps_https_uses_child_scoped_trust() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap();
    let output = std::process::Command::new("python3")
        .arg(root.join("scripts/test_canvas_lti_https.py"))
        .arg(std::env::current_exe().unwrap())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "HTTPS fixture failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("{}", String::from_utf8_lossy(&output.stdout));
}

#[tokio::test]
async fn https_child() {
    let Ok(origin) = std::env::var("MARTY_CANVAS_LTI_HTTPS_ORIGIN") else {
        return;
    };
    assert!(origin.starts_with("https://127.0.0.1:"));
    let trust = canvas_lti_trust_profile(
        &origin,
        CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN,
        std::slice::from_ref(&origin),
    )
    .unwrap();
    let (oauth, _, _, _) = fixture();
    let signer = Arc::new(Signer::default());
    let provider = HttpCanvasAuthoritativeProvider::new(
        Arc::new(oauth),
        "management-key",
        signer.clone(),
        CanvasHttpClientPolicy {
            timeout: Duration::from_secs(5),
            private_origin_allowlist: vec![origin.clone()],
            allow_private_networks: false,
            allow_http_localhost: false,
        },
        vec![origin.clone()],
    );
    let resources = CanvasSyncResources {
        platform: CanvasSyncPlatformSnapshot {
            id: "platform-1".into(),
            organization_id: "org-1".into(),
            canvas_base_url: origin.clone(),
            lti_trust_profile: CANVAS_LTI_TRUST_SELF_MANAGED_SAME_ORIGIN.into(),
            lti_issuer: trust.issuer,
            lti_client_id: "synthetic-client".into(),
            lti_deployment_id: "deployment".into(),
            lti_auth_token_url: trust.token_endpoint.clone(),
            config_version: 1,
        },
        binding: json!({"id":"binding-1","config_version":1})
            .as_object()
            .unwrap()
            .clone(),
        application: None,
        application_template: None,
    };
    let requirement = |item: &str| json!({"requirement_id":"ags","source":"ags_result","fact_type":"canvas.assignment_score","scope":{"course_id":"42","line_item_url":format!("{origin}/api/lti/courses/42/line_items/{item}")},"required":true});
    if std::env::var("MARTY_CANVAS_LTI_HTTPS_UNTRUSTED").as_deref() == Ok("1") {
        assert!(matches!(
            provider
                .read_requirement(&resources, &requirement("5"), None, Some("subject-7"))
                .await,
            Err(CanvasProviderReadError::Unavailable)
        ));
        assert_eq!(signer.claims.lock().unwrap().len(), 1);
        eprintln!("Untrusted synthetic TLS certificate rejected");
        return;
    }
    let observation = provider
        .read_requirement(&resources, &requirement("5"), None, Some("subject-7"))
        .await
        .unwrap();
    assert_eq!(observation.assertion, json!({"completed":true,"score":90.0,"score_maximum":100.0,"score_percent":90.0,"result_status":"FullyGraded"}).as_object().unwrap().clone());
    assert_eq!(observation.source_payload, json!({"id":"result-7","resultScore":90,"resultMaximum":100,"resultStatus":"FullyGraded","timestamp":"2026-09-01T00:00:00Z"}).as_object().unwrap().clone());
    assert_eq!(observation.verification_method, "LTI_AGS_RESULT_READ");
    assert_eq!(
        observation.effective_at.unwrap().to_rfc3339(),
        "2026-09-01T00:00:00+00:00"
    );
    let empty = provider
        .read_requirement(&resources, &requirement("empty"), None, Some("subject-7"))
        .await
        .unwrap();
    assert_eq!(empty.assertion["completed"], false);
    assert!(empty.source_payload.is_empty());
    assert!(matches!(
        provider
            .read_requirement(&resources, &requirement("rate"), None, Some("subject-7"))
            .await,
        Err(CanvasProviderReadError::RateLimited {
            retry_after_seconds: 37
        })
    ));
    let mut target = CanvasSyncTarget {
        id: "target".into(),
        organization_id: "org-1".into(),
        platform_id: "platform-1".into(),
        binding_id: "binding-1".into(),
        target_type: CanvasSyncTargetType::BackgroundRoster,
        logical_key: "roster".into(),
        application_id: None,
        candidate_id: None,
        enabled: true,
        schedule_seconds: 900,
        config_version: 1,
        metadata: Default::default(),
        created_at: Utc::now(),
    };
    assert!(matches!(
        provider
            .roster(&target, &resources, &[requirement("5")], 10)
            .await,
        Err(CanvasProviderReadError::NrpsRosterUnavailable)
    ));
    assert_eq!(signer.claims.lock().unwrap().len(), 3);
    target.metadata = json!({"verified_binding_id":"binding-1","verified_binding_config_version":1,"nrps_context_memberships_url":format!("{origin}/api/lti/courses/42/memberships")}).as_object().unwrap().clone();
    let roster = provider
        .roster(&target, &resources, &[requirement("5")], 10)
        .await
        .unwrap();
    assert_eq!(roster.lti_subjects, ["subject-7"]);
    assert!(roster.canvas_user_ids.is_empty() && roster.preloaded_observations.is_empty());
    let claims = signer.claims.lock().unwrap();
    assert_eq!(claims.len(), 4);
    let mut nonces = std::collections::BTreeSet::new();
    for claim in claims.iter() {
        assert_eq!(claim["iss"], "synthetic-client");
        assert_eq!(claim["sub"], "synthetic-client");
        assert_eq!(claim["aud"], trust.token_endpoint);
        assert_eq!(
            claim["exp"].as_i64().unwrap() - claim["iat"].as_i64().unwrap(),
            300
        );
        assert!(nonces.insert(claim["jti"].as_str().unwrap()));
    }
    eprintln!("Native HTTPS child verified actual AGS/NRPS provider requests and observations");
}
