use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use marty_presentation_policy::{
    PolicyApplication, PolicyApplicationError, PolicyAuthorization, PolicyRepository, PolicyStatus,
    PresentationPolicy,
};
use serde_json::json;
use uuid::Uuid;

#[derive(Default)]
struct Repository(Mutex<BTreeMap<Uuid, PresentationPolicy>>);

#[async_trait]
impl PolicyRepository for Repository {
    async fn save(&self, policy: &PresentationPolicy) -> Result<(), String> {
        self.0.lock().unwrap().insert(policy.id, policy.clone());
        Ok(())
    }
    async fn get(&self, id: Uuid) -> Result<Option<PresentationPolicy>, String> {
        Ok(self.0.lock().unwrap().get(&id).cloned())
    }
    async fn list(&self, org: Uuid) -> Result<Vec<PresentationPolicy>, String> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .values()
            .filter(|p| p.organization_id == org)
            .cloned()
            .collect())
    }
    async fn delete(&self, id: Uuid) -> Result<(), String> {
        self.0.lock().unwrap().remove(&id);
        Ok(())
    }
}

struct Authorization(Uuid);

#[async_trait]
impl PolicyAuthorization for Authorization {
    async fn require(&self, principal: &str, org: Uuid, _: &'static str) -> Result<(), String> {
        (principal == "user-1" && org == self.0)
            .then_some(())
            .ok_or_else(|| "denied".into())
    }
}

fn policy(org: Uuid) -> PresentationPolicy {
    serde_json::from_value(json!({
        "id":Uuid::new_v4(), "organization_id":org, "name":"Login", "description":null, "status":"draft",
        "display_metadata":{"title":"Login","description":"","purpose":"identity_verification","purpose_description":null,"verifier_name":"Marty","verifier_logo_url":null,"privacy_policy_url":null,"terms_of_service_url":null},
        "required_claims":[], "accepted_credential_types":[], "credential_requirements":[], "alternative_requirements":[], "presentation_proof_required":true,
        "trust_profile_id":null, "holder_binding":{"required":true,"binding_methods":["DEVICE_KEY"],"proof_profiles":["OID4VP_VERIFIABLE_PRESENTATION"],"proof_freshness":{"challenge_required":true}},
        "freshness":null, "issuer_constraints":null, "credential_ranking_strategy":"FRESHEST_FIRST", "credential_ranking_weights":null, "purpose":"Login",
        "compliance_profile_id":null, "prefer_predicates":false, "fallback_policy":null, "supported_circuits":[], "version":1,
        "created_at":"2026-08-21T00:00:00Z", "updated_at":"2026-08-21T00:00:00Z"
    })).unwrap()
}

#[tokio::test]
async fn lifecycle_is_tenant_bound_lossless_and_draft_only() {
    let org = Uuid::new_v4();
    let app = PolicyApplication::new(
        Arc::new(Repository::default()),
        Arc::new(Authorization(org)),
    );
    let draft = app.create("user-1", policy(org)).await.unwrap();
    let now = Utc.with_ymd_and_hms(2026, 8, 21, 1, 0, 0).unwrap();
    let active = app.activate("user-1", draft.id, now).await.unwrap();
    assert_eq!(active.status, PolicyStatus::Active);
    assert_eq!(
        app.delete("user-1", active.id).await.unwrap_err(),
        PolicyApplicationError::Conflict("only draft policies can be deleted")
    );
    let suspended = app.suspend("user-1", active.id, now).await.unwrap();
    let version = app
        .new_version("user-1", suspended.id, Uuid::new_v4(), now)
        .await
        .unwrap();
    assert_eq!(version.status, PolicyStatus::Draft);
    assert_eq!(version.holder_binding, suspended.holder_binding);
    app.delete("user-1", version.id).await.unwrap();
}

#[tokio::test]
async fn authorization_and_immutable_identity_fail_closed_before_writes() {
    let org = Uuid::new_v4();
    let app = PolicyApplication::new(
        Arc::new(Repository::default()),
        Arc::new(Authorization(org)),
    );
    assert_eq!(
        app.create("other", policy(org)).await.unwrap_err(),
        PolicyApplicationError::Forbidden
    );
    let draft = app.create("user-1", policy(org)).await.unwrap();
    let mut replacement = draft.clone();
    replacement.organization_id = Uuid::new_v4();
    assert_eq!(
        app.update("user-1", replacement).await.unwrap_err(),
        PolicyApplicationError::Conflict("immutable policy identity changed")
    );
    assert_eq!(
        app.get("", draft.id).await.unwrap_err(),
        PolicyApplicationError::Forbidden
    );
}
