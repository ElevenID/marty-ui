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

#[test]
fn http_json_cannot_claim_internal_oid4vp_transport_or_trust() {
    let base = json!({
        "vp_token": "header.payload.signature",
        "trust_profile_id": null,
        "nonce": null,
        "audience": null,
        "context": {"oid4vp_verifier_context": true}
    });
    let parsed: EvaluatePresentationRequest = serde_json::from_value(base.clone()).unwrap();
    assert!(!parsed.trusted_internal_context);
    assert!(parsed.oid4vp_transport.is_none());
    let mut spoofed = base;
    spoofed["trusted_internal_context"] = json!(true);
    spoofed["oid4vp_transport"] = json!({"query_kind": "dcql"});
    assert!(serde_json::from_value::<EvaluatePresentationRequest>(spoofed).is_err());
}

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

struct VerifiedMdocFacts {
    extra_disclosure: bool,
    authenticated: bool,
    duplicate_match: bool,
}

#[async_trait]
impl PresentationVerificationOrchestrator for VerifiedMdocFacts {
    async fn verify(
        &self,
        policy: &PresentationPolicy,
        request: &EvaluatePresentationRequest,
    ) -> Result<Value, PresentationVerificationError> {
        let mut facts = VerifiedFacts.verify(policy, request).await?;
        facts["presentation_verified"] = json!(self.authenticated);
        facts["holder_binding_verified"] = json!(self.authenticated);
        facts["holder_binding_method"] = json!("DEVICE_KEY");
        facts["proof_profile"] = json!("OID4VP_VERIFIABLE_PRESENTATION");
        facts["credentials"][0]["credential_format"] = json!("mdoc");
        facts["credentials"][0]["signature_verified"] = json!(self.authenticated);
        let mut disclosed = json!({"age_over_21": true});
        if self.extra_disclosure {
            disclosed["birth_date"] = json!("1990-01-01");
        }
        facts["credentials"][0]["claims"] = json!({
            "age_over_21": true,
            "birth_date": "1990-01-01",
            "_mdoc": {"documents": [{
                "doc_type": "org.iso.18013.5.1.mDL",
                "namespaces": {"org.iso.18013.5.1": disclosed}
            }]}
        });
        if self.duplicate_match {
            let duplicate = facts["credentials"][0].clone();
            facts["credentials"].as_array_mut().unwrap().push(duplicate);
        }
        Ok(facts)
    }
}

async fn evaluate_mdoc_disclosures(
    extra_disclosure: bool,
    authenticated: bool,
    duplicate_match: bool,
) -> Value {
    let organization_id = Uuid::new_v4();
    let app = router(
        organization_id,
        Arc::new(VerifiedMdocFacts {
            extra_disclosure,
            authenticated,
            duplicate_match,
        }),
    );
    let response = app
        .oneshot(request(
            "POST",
            "/v1/presentation-policies/evaluate",
            json!({
                "organization_id": organization_id,
                "vp_token": "mdoc:untrusted-transport-is-not-the-evidence-source",
                "credential_requirements": [{
                    "credential_template_id": "age-template",
                    "credential_payload_format": "MDOC",
                    "requested_claims": [{
                        "claim_name": "age_over_21",
                        "constraints": [{"claim_name": "age_over_21", "constraint_type": "presence"}]
                    }]
                }]
            }),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    body(response).await
}

#[tokio::test]
async fn authenticated_mdoc_disclosure_names_include_unrequested_fields_without_their_values() {
    let result = evaluate_mdoc_disclosures(true, true, false).await;
    assert_eq!(result["decision"], "allow", "{result}");
    assert_eq!(result["verified_claims"], json!({"age_over_21": true}));
    let disclosures = &result["credential_results"][0]["authenticated_disclosures"];
    assert_eq!(
        disclosures,
        &json!({"format": "mso_mdoc", "documents": [{
            "doc_type": "org.iso.18013.5.1.mDL",
            "namespaces": {"org.iso.18013.5.1": ["age_over_21", "birth_date"]}
        }]})
    );
    assert!(!disclosures.to_string().contains("1990-01-01"));
}

#[tokio::test]
async fn authenticated_mdoc_disclosure_names_do_not_come_from_flat_or_policy_claims() {
    let result = evaluate_mdoc_disclosures(false, true, false).await;
    assert_eq!(
        result["credential_results"][0]["authenticated_disclosures"]["documents"][0]["namespaces"]
            ["org.iso.18013.5.1"],
        json!(["age_over_21"])
    );
}

#[tokio::test]
async fn unauthenticated_mdoc_data_never_produces_disclosure_evidence() {
    let result = evaluate_mdoc_disclosures(true, false, false).await;
    assert_eq!(result["decision"], "deny", "{result}");
    assert!(result["credential_results"][0]
        .get("authenticated_disclosures")
        .is_none());
}

#[tokio::test]
async fn ambiguous_authenticated_credentials_never_produce_a_guessed_disclosure_inventory() {
    let result = evaluate_mdoc_disclosures(true, true, true).await;
    for credential in result["credential_results"].as_array().unwrap() {
        assert!(credential.get("authenticated_disclosures").is_none());
    }
}

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
fn scoped_policy_request(
    method: &str,
    uri: &str,
    payload: Value,
    org: Uuid,
    scopes: &str,
) -> Request<Body> {
    let mut value = request(method, uri, payload, true);
    value.headers_mut().insert(
        "x-api-key-id",
        "11111111-1111-4111-8111-111111111111".parse().unwrap(),
    );
    value
        .headers_mut()
        .insert("x-organization-id", org.to_string().parse().unwrap());
    value
        .headers_mut()
        .insert("x-api-key-scopes", scopes.parse().unwrap());
    value
}

async fn owned_policy(app: &axum::Router, org: Uuid) -> String {
    let response = app
        .clone()
        .oneshot(request(
            "POST",
            "/v1/presentation-policies",
            create_body(org),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    body(response).await["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn scoped_api_policy_reader_obeys_exact_organization_and_existing_grants() {
    let org = Uuid::new_v4();
    let app = router(org, Arc::new(VerifiedFacts));
    let id = owned_policy(&app, org).await;
    let path = format!("/v1/presentation-policies/{id}");
    for (actor_org, scopes, expected) in [
        (org, "trust:read", StatusCode::OK),
        (org, "templates:read", StatusCode::FORBIDDEN),
        (Uuid::new_v4(), "trust:read", StatusCode::FORBIDDEN),
    ] {
        let response = app
            .clone()
            .oneshot(scoped_policy_request(
                "GET",
                &path,
                json!({}),
                actor_org,
                scopes,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    let response = app
        .clone()
        .oneshot(scoped_policy_request(
            "GET",
            &format!("/v1/presentation-policies?organization_id={org}"),
            json!({}),
            org,
            "trust:read",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await.as_array().unwrap().len(), 1);
    // Human identity continues through the membership authorization implementation.
    assert_eq!(
        app.oneshot(request("GET", &path, json!({}), true))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn scoped_api_policy_reader_cannot_gain_any_policy_mutation() {
    let org = Uuid::new_v4();
    let app = router(org, Arc::new(VerifiedFacts));
    let id = owned_policy(&app, org).await;
    for (method, path, payload) in [
        ("POST", "/v1/presentation-policies".into(), create_body(org)),
        (
            "PATCH",
            format!("/v1/presentation-policies/{id}"),
            json!({"name":"changed"}),
        ),
        (
            "DELETE",
            format!("/v1/presentation-policies/{id}"),
            json!({}),
        ),
        (
            "POST",
            format!("/v1/presentation-policies/{id}/activate"),
            json!({}),
        ),
        (
            "POST",
            format!("/v1/presentation-policies/{id}/suspend"),
            json!({}),
        ),
        (
            "POST",
            format!("/v1/presentation-policies/{id}/new-version"),
            json!({}),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(scoped_policy_request(
                method,
                &path,
                payload,
                org,
                "trust:read",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
    }
    let response = app
        .oneshot(request(
            "GET",
            &format!("/v1/presentation-policies/{id}"),
            json!({}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(body(response).await["name"], "Member login");
}

#[tokio::test]
async fn scoped_api_policy_headers_require_service_authentication_and_complete_identity() {
    let org = Uuid::new_v4();
    let app = router(org, Arc::new(VerifiedFacts));
    let id = owned_policy(&app, org).await;
    let path = format!("/v1/presentation-policies/{id}");
    for missing in ["x-service-token", "x-organization-id", "x-api-key-id"] {
        let mut request = scoped_policy_request("GET", &path, json!({}), org, "trust:read");
        request.headers_mut().remove(missing);
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
    for invalid in ["", "not-a-key-uuid"] {
        let mut request = scoped_policy_request("GET", &path, json!({}), org, "trust:read");
        request
            .headers_mut()
            .insert("x-api-key-id", invalid.parse().unwrap());
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn scoped_api_policy_owner_is_authenticated_minimal_projection() {
    let org = Uuid::new_v4();
    let app = router(org, Arc::new(VerifiedFacts));
    let id = owned_policy(&app, org).await;
    let path = format!("/internal/v1/resource-owners/presentation-policies/{id}");
    let mut value = request("GET", &path, json!({}), true);
    value.headers_mut().remove("x-user-id");
    let response = app.clone().oneshot(value).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await, json!({"id":id,"organization_id":org}));
    assert_eq!(
        app.clone()
            .oneshot(request("GET", &path, json!({}), false))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.oneshot(request(
            "GET",
            &format!(
                "/internal/v1/resource-owners/presentation-policies/{}",
                Uuid::new_v4()
            ),
            json!({}),
            true
        ))
        .await
        .unwrap()
        .status(),
        StatusCode::NOT_FOUND
    );
}
