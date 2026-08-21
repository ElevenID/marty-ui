use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use marty_presentation_policy::{
    presentation_policy_router, EvaluatePresentationRequest, PolicyApplication,
    PolicyAuthorization, PolicyRepository, PresentationPolicy, PresentationPolicyHttpState,
    PresentationVerificationError, PresentationVerificationOrchestrator,
};
use mmf_security::ServiceTokenAuthenticator;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

#[derive(Default)]
struct Repository(Mutex<BTreeMap<Uuid, PresentationPolicy>>);

#[async_trait]
impl PolicyRepository for Repository {
    async fn save(&self, policy: &PresentationPolicy) -> Result<(), String> {
        self.0.lock().unwrap().insert(policy.id, policy.clone());
        Ok(())
    }

    async fn get(&self, policy_id: Uuid) -> Result<Option<PresentationPolicy>, String> {
        Ok(self.0.lock().unwrap().get(&policy_id).cloned())
    }

    async fn list(&self, organization_id: Uuid) -> Result<Vec<PresentationPolicy>, String> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .values()
            .filter(|policy| policy.organization_id == organization_id)
            .cloned()
            .collect())
    }

    async fn delete(&self, policy_id: Uuid) -> Result<(), String> {
        self.0.lock().unwrap().remove(&policy_id);
        Ok(())
    }
}

struct Authorization(Uuid);

#[async_trait]
impl PolicyAuthorization for Authorization {
    async fn require(
        &self,
        principal_id: &str,
        organization_id: Uuid,
        _action: &'static str,
    ) -> Result<(), String> {
        if principal_id == "user-1" && organization_id == self.0 {
            Ok(())
        } else {
            Err("denied".into())
        }
    }
}

struct VerifiedFacts;

#[async_trait]
impl PresentationVerificationOrchestrator for VerifiedFacts {
    async fn verify(
        &self,
        policy: &PresentationPolicy,
        _request: &EvaluatePresentationRequest,
    ) -> Result<Value, PresentationVerificationError> {
        let template_id = &policy.credential_requirements[0].credential_template_id;
        Ok(json!({
            "policy": {},
            "credentials": [{
                "credential_id": "credential-1",
                "credential_template_ids": [template_id],
                "credential_format": "sd-jwt",
                "claims": {"email": "member@example.com"},
                "issuer_id": "did:example:issuer",
                "signature_verified": true,
                "signature_failure_reason": null,
                "trust_profile_verified": true,
                "trust_failure_reason": null,
                "trust_level": 80,
                "compliance_statuses": [],
                "accreditations": [],
                "issued_at_epoch_seconds": 999,
                "revocation_checked_at_epoch_seconds": null,
                "not_revoked": null,
                "credential_status": "active",
                "warnings": []
            }],
            "evaluation_time_epoch_seconds": 1000,
            "holder_binding_verified": false,
            "holder_binding_method": null,
            "proof_profile": null,
            "challenge_verified": false,
            "audience_verified": false,
            "replay_check_verified": false,
            "proof_epoch_seconds": null,
            "external_authorization": {"evaluated": true, "allowed": true, "reasons": [], "errors": []},
            "presentation_count": 1
        }))
    }
}

struct Unavailable;

#[async_trait]
impl PresentationVerificationOrchestrator for Unavailable {
    async fn verify(
        &self,
        _policy: &PresentationPolicy,
        _request: &EvaluatePresentationRequest,
    ) -> Result<Value, PresentationVerificationError> {
        Err(PresentationVerificationError::Unavailable)
    }
}

fn router(
    organization_id: Uuid,
    verifier: Arc<dyn PresentationVerificationOrchestrator>,
) -> axum::Router {
    presentation_policy_router(PresentationPolicyHttpState {
        application: Arc::new(PolicyApplication::new(
            Arc::new(Repository::default()),
            Arc::new(Authorization(organization_id)),
        )),
        verification: verifier,
        service_authenticator: Arc::new(
            ServiceTokenAuthenticator::new(Some(TOKEN.into()), true).unwrap(),
        ),
    })
}

fn create_body(organization_id: Uuid) -> Value {
    json!({
        "organization_id": organization_id,
        "name": "Member login",
        "purpose": "Sign in",
        "accepted_credential_types": ["member"],
        "credential_requirements": [{
            "credential_template_id": "member",
            "credential_payload_format": "w3c_vcdm_v2_sd_jwt",
            "requested_claims": [{
                "claim_name": "email",
                "constraints": [{"claim_name": "email", "constraint_type": "presence"}]
            }]
        }]
    })
}

fn request(method: &str, uri: &str, body: Value, authenticated: bool) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if authenticated {
        builder = builder
            .header("x-service-token", TOKEN)
            .header("x-user-id", "user-1");
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn body(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

#[tokio::test]
async fn all_ten_http_operations_preserve_lifecycle_and_evaluation_behavior() {
    let organization_id = Uuid::new_v4();
    let app = router(organization_id, Arc::new(VerifiedFacts));

    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/presentation-policies",
            create_body(organization_id),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let created = body(response).await;
    let policy_id = created["id"].as_str().unwrap();
    assert_eq!(created["status"], "draft");
    assert_eq!(
        created["credential_requirements"][0]["requested_claims"][0]["claim_name"],
        "email"
    );
    assert!(created["credential_requirements"][0].get("id").is_none());

    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/v1/presentation-policies?organization_id={organization_id}"),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(body(response).await.as_array().unwrap().len(), 1);

    let response = app
        .clone()
        .oneshot(request(
            "PATCH",
            &format!("/v1/presentation-policies/{policy_id}"),
            json!({"name": "Updated login"}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(body(response).await["name"], "Updated login");

    let response = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/v1/presentation-policies/{policy_id}"),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(body(response).await["name"], "Updated login");

    let response = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/v1/presentation-policies/{policy_id}/activate"),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(body(response).await["status"], "active");

    let evaluation = json!({"vp_token": "header.payload.signature", "nonce": "challenge-1"});
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/v1/presentation-policies/{policy_id}/evaluate"),
            evaluation.clone(),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let evaluated = body(response).await;
    assert_eq!(evaluated["decision"], "allow");
    assert_eq!(evaluated["verified_claims"]["email"], "member@example.com");
    assert_eq!(evaluated["nonce"], "challenge-1");

    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/presentation-policies/evaluate",
            json!({
                "organization_id": organization_id,
                "vp_token": "header.payload.signature",
                "credential_requirements": create_body(organization_id)["credential_requirements"]
            }),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(body(response).await["decision"], "allow");

    let response = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/v1/presentation-policies/{policy_id}/suspend"),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(body(response).await["status"], "suspended");

    let response = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/v1/presentation-policies/{policy_id}/new-version"),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    let version = body(response).await;
    let version_id = version["id"].as_str().unwrap();
    assert_eq!(version["version"], 2);
    assert_eq!(version["status"], "draft");
    assert_eq!(version["holder_binding"], created["holder_binding"]);

    let response = app
        .oneshot(request(
            "DELETE",
            &format!("/v1/presentation-policies/{version_id}"),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await["success"], true);
}

#[tokio::test]
async fn missing_service_identity_and_native_verifier_fail_closed() {
    let organization_id = Uuid::new_v4();
    let app = router(organization_id, Arc::new(Unavailable));
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/presentation-policies",
            create_body(organization_id),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/presentation-policies",
            create_body(organization_id),
            true,
        ))
        .await
        .unwrap();
    let policy_id = body(response).await["id"].as_str().unwrap().to_owned();
    app.clone()
        .oneshot(request(
            "POST",
            &format!("/v1/presentation-policies/{policy_id}/activate"),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    let response = app
        .oneshot(request(
            "POST",
            &format!("/v1/presentation-policies/{policy_id}/evaluate"),
            json!({"vp_token": "header.payload.signature"}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body(response).await["detail"],
        "PRESENTATION_POLICY.NATIVE_BACKEND_UNAVAILABLE"
    );
}
