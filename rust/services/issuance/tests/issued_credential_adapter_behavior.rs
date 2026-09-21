use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use chrono::{DateTime, TimeZone, Utc};
use http_body_util::BodyExt;
use marty_issuance_service::{
    credential_management::{
        CanvasLifecycleSyncError, CredentialLifecycleAction, CredentialLifecycleAuditRecord,
        CredentialLifecycleEvent, CredentialLifecycleEventSink, CredentialManagementPortError,
        CredentialManagementRepository, CredentialManagementService, CredentialStatusPublisher,
        ManagedCredential, ManagedCredentialStatus,
    },
    issued_credential_http,
    issued_credential_records::{
        IssuedCredentialAdapterService, IssuedCredentialClock, IssuedCredentialProjectionSource,
        IssuedCredentialRecordRepository, IssuedCredentialRepositoryError,
        IssuedCredentialTransactionProjection,
    },
};
use serde_json::{json, Value};
use tower::ServiceExt;

#[derive(Clone)]
struct Harness {
    source: Arc<Mutex<IssuedCredentialProjectionSource>>,
    audits: Arc<Mutex<Vec<CredentialLifecycleAuditRecord>>>,
}

impl Harness {
    fn new() -> Self {
        Self {
            source: Arc::new(Mutex::new(IssuedCredentialProjectionSource {
                id: "credential-1".into(),
                transaction_id: "transaction-1".into(),
                organization_id: "org-1".into(),
                credential_template_id: "template-1".into(),
                applicant_id: Some("applicant-1".into()),
                subject_did: Some("did:example:holder".into()),
                issuer_did: Some("did:web:issuer.example".into()),
                revocation_profile_id: Some("profile-1".into()),
                renewed_from_credential_id: None,
                renewed_to_credential_id: None,
                status_list_entries: vec![
                    json!({"status_list_id":"skip-null-index","index":null}),
                    json!({
                        "status_list_id":"profile-1","index":" 1_0 ",
                        "status_list_uri":"https://issuer.example/status/1",
                        "type":null
                    }),
                ],
                credential_hash: Some("public-hash".into()),
                status: "active".into(),
                status_updated_at: timestamp(1),
                revoked_at: None,
                revocation_reason: None,
                issued_at: timestamp(1),
                expires_at: Some(timestamp(30)),
                transaction: Some(IssuedCredentialTransactionProjection {
                    applicant_id: Some("applicant-1".into()),
                    application_id: Some("application-1".into()),
                    subject_did: Some("did:example:holder".into()),
                    issuer_did_override: None,
                    claims: json!({"given_name":"Ada","pre_auth_code":"not-excluded-source"}),
                    credential_type: Some("EmployeeCredential".into()),
                    credential_payload_format: Some("vds_nc".into()),
                    renewable: true,
                    renewal_window_days: 7,
                }),
            })),
            audits: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn app(&self) -> axum::Router {
        let management = CredentialManagementService::new(
            Arc::new(self.clone()),
            Arc::new(self.clone()),
            Arc::new(self.clone()),
        );
        issued_credential_http::router(IssuedCredentialAdapterService::new(
            Arc::new(self.clone()),
            management,
            Some("secret"),
            Arc::new(FixedClock(timestamp(25))),
        ))
    }
}

#[async_trait]
impl IssuedCredentialRecordRepository for Harness {
    async fn get(
        &self,
        credential_id: &str,
    ) -> Result<Option<IssuedCredentialProjectionSource>, IssuedCredentialRepositoryError> {
        Ok((credential_id == "credential-1").then(|| self.source.lock().unwrap().clone()))
    }

    async fn list_by_organization(
        &self,
        organization_id: &str,
    ) -> Result<Vec<IssuedCredentialProjectionSource>, IssuedCredentialRepositoryError> {
        Ok((organization_id == "org-1")
            .then(|| self.source.lock().unwrap().clone())
            .into_iter()
            .collect())
    }
}

struct FailingIssuedRepository;

#[async_trait]
impl IssuedCredentialRecordRepository for FailingIssuedRepository {
    async fn get(
        &self,
        _credential_id: &str,
    ) -> Result<Option<IssuedCredentialProjectionSource>, IssuedCredentialRepositoryError> {
        Err(IssuedCredentialRepositoryError)
    }

    async fn list_by_organization(
        &self,
        _organization_id: &str,
    ) -> Result<Vec<IssuedCredentialProjectionSource>, IssuedCredentialRepositoryError> {
        Err(IssuedCredentialRepositoryError)
    }
}

#[async_trait]
impl CredentialManagementRepository for Harness {
    async fn get(
        &self,
        credential_id: &str,
    ) -> Result<Option<ManagedCredential>, CredentialManagementPortError> {
        let source = self.source.lock().unwrap().clone();
        Ok((credential_id == source.id).then(|| ManagedCredential {
            id: source.id,
            transaction_id: source.transaction_id,
            organization_id: source.organization_id,
            credential_template_id: source.credential_template_id,
            issuer_did: source.issuer_did,
            status: match source.status.as_str() {
                "active" => ManagedCredentialStatus::Active,
                "suspended" => ManagedCredentialStatus::Suspended,
                _ => ManagedCredentialStatus::Revoked,
            },
            status_updated_at: source.status_updated_at,
            revoked: source.status == "revoked",
            revoked_at: source.revoked_at,
            revocation_reason: source.revocation_reason,
            revocation_profile_id: source.revocation_profile_id,
            status_list_entries: source.status_list_entries,
        }))
    }

    async fn persist(
        &self,
        credential: &ManagedCredential,
        expected_status: ManagedCredentialStatus,
        audit: &CredentialLifecycleAuditRecord,
    ) -> Result<ManagedCredential, CredentialManagementPortError> {
        let mut source = self.source.lock().unwrap();
        if source.status != expected_status.as_str() {
            return Err(CredentialManagementPortError("stale".into()));
        }
        source.status = credential.status.as_str().into();
        source.status_updated_at = credential.status_updated_at;
        source.revoked_at = credential.revoked_at;
        source.revocation_reason = credential.revocation_reason.clone();
        self.audits.lock().unwrap().push(audit.clone());
        Ok(credential.clone())
    }

    async fn synchronize_canvas(
        &self,
        _credential: &ManagedCredential,
        _action: CredentialLifecycleAction,
        _reason: Option<&str>,
    ) -> Result<(), CanvasLifecycleSyncError> {
        Ok(())
    }
}

#[async_trait]
impl CredentialStatusPublisher for Harness {
    async fn publish(
        &self,
        _credential: &ManagedCredential,
        _action: CredentialLifecycleAction,
        _reason: Option<&str>,
    ) -> Result<(), CredentialManagementPortError> {
        Ok(())
    }
}

#[async_trait]
impl CredentialLifecycleEventSink for Harness {
    async fn emit(&self, _event: CredentialLifecycleEvent) {}
}

#[derive(Clone, Copy)]
struct FixedClock(DateTime<Utc>);

impl IssuedCredentialClock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

fn timestamp(day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, day, 0, 0, 0).unwrap()
}

async fn response_json(response: axum::response::Response) -> (u16, Value) {
    let status = response.status().as_u16();
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json"),
        "every public adapter success and error remains JSON"
    );
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn list_and_detail_preserve_auth_tenant_query_and_full_public_projection() {
    let harness = Harness::new();
    let (status, body) = response_json(
        harness
            .app()
            .oneshot(
                Request::get("/v1/issued-credentials")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(
        (status, body),
        (401, json!({"detail":"X-API-Key header is missing"}))
    );

    let missing_organization = Request::get("/v1/issued-credentials")
        .header("x-api-key", "secret")
        .header("x-organization-id", "org-1")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        response_json(harness.app().oneshot(missing_organization).await.unwrap()).await,
        (
            422,
            json!({"detail":[{
                "type":"missing", "loc":["query","organization_id"],
                "msg":"Field required", "input":null
            }]})
        )
    );

    let wrong_tenant = Request::get("/v1/issued-credentials?organization_id=org-1")
        .header("x-api-key", "secret")
        .header("x-organization-id", "other-org")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        response_json(harness.app().oneshot(wrong_tenant).await.unwrap()).await,
        (
            403,
            json!({"detail":"Organization context does not match requested organization"})
        )
    );

    let request = Request::get("/v1/issued-credentials?organization_id=org-1&status=active")
        .header("x-api-key", "secret")
        .header("x-organization-id", "org-1")
        .body(Body::empty())
        .unwrap();
    let (status, body) = response_json(harness.app().oneshot(request).await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["credential_format"], "VDS_NC");
    assert_eq!(body[0]["status"], "ACTIVE");
    assert_eq!(body[0]["status_list_entries"].as_array().unwrap().len(), 1);
    assert_eq!(body[0]["status_list_entries"][0]["index"], 10);
    assert_eq!(body[0]["status_list_entries"][0]["type"], Value::Null);
    assert!(body[0].get("comments").is_none());
    assert!(body[0].get("claims").is_none());

    let detail = Request::get("/v1/issued-credentials/credential-1")
        .header("x-api-key", "secret")
        .header("x-organization-id", "org-1")
        .body(Body::empty())
        .unwrap();
    let (status, body) = response_json(harness.app().oneshot(detail).await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(body["status_list_entries"].as_array().unwrap().len(), 1);
    assert_eq!(body["status_list_entries"][0]["index"], 10);
    assert_eq!(body["status_list_entries"][0]["type"], Value::Null);

    let request = Request::get("/v1/issued-credentials/credential-1")
        .header("x-api-key", "secret")
        .header("x-organization-id", "other-org")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        response_json(harness.app().oneshot(request).await.unwrap()).await,
        (404, json!({"detail":"Issued credential not found"}))
    );
}

#[tokio::test]
async fn lifecycle_preserves_comments_trusted_actor_full_response_and_validation_order() {
    let harness = Harness::new();
    let request = Request::post("/v1/issued-credentials/credential-1/revoke")
        .header("content-type", "application/json")
        .header("x-api-key", "secret")
        .header("x-organization-id", "org-1")
        .header("x-user-id", "operator-1")
        .body(Body::from(
            r#"{"reason":"affiliationChanged","comments":"HR ticket 42"}"#,
        ))
        .unwrap();
    let (status, body) = response_json(harness.app().oneshot(request).await.unwrap()).await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "REVOKED");
    assert_eq!(body["revocation_reason"], "affiliationChanged");
    assert_eq!(body["status_list_entries"].as_array().unwrap().len(), 1);
    assert_eq!(body["status_list_entries"][0]["index"], 10);
    assert_eq!(body["status_list_entries"][0]["type"], Value::Null);
    assert!(body.get("comments").is_none());
    assert_eq!(
        harness.audits.lock().unwrap()[0].comments.as_deref(),
        Some("HR ticket 42")
    );
    assert_eq!(
        harness.audits.lock().unwrap()[0].actor_id.as_deref(),
        Some("operator-1")
    );

    let malformed = Request::post("/v1/issued-credentials/credential-1/suspend")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"unknown":true}"#))
        .unwrap();
    assert_eq!(
        response_json(harness.app().oneshot(malformed).await.unwrap())
            .await
            .0,
        401,
        "authentication wins over request-body validation"
    );
}

#[tokio::test]
async fn repository_failures_are_sanitized_without_losing_json_error_shape() {
    let harness = Harness::new();
    let lifecycle = CredentialManagementService::new(
        Arc::new(harness.clone()),
        Arc::new(harness.clone()),
        Arc::new(harness),
    );
    let app = issued_credential_http::router(IssuedCredentialAdapterService::new(
        Arc::new(FailingIssuedRepository),
        lifecycle,
        Some("secret"),
        Arc::new(FixedClock(timestamp(25))),
    ));
    let request = Request::get("/v1/issued-credentials/credential-secret")
        .header("x-api-key", "secret")
        .header("x-organization-id", "org-1")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        response_json(app.oneshot(request).await.unwrap()).await,
        (
            503,
            json!({"detail":"Issued credential data is temporarily unavailable"})
        )
    );
}
