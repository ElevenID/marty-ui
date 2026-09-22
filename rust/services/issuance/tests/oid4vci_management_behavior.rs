use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{TimeZone, Utc};
use marty_issuance_service::{
    credential_management::{
        CanvasLifecycleSyncError, CredentialLifecycleAction, CredentialLifecycleAuditRecord,
        CredentialLifecycleEvent, CredentialLifecycleEventSink, CredentialManagementPortError,
        CredentialManagementRepository, CredentialManagementService, CredentialStatusPublisher,
        ManagedCredential, ManagedCredentialStatus,
    },
    issued_credential_records::{
        IssuedCredentialProjectionSource, IssuedCredentialRecordRepository,
        IssuedCredentialRepositoryError,
    },
    oid4vci_management::{
        ManagementTransaction, Oid4vciManagementRepository, Oid4vciManagementRepositoryError,
        Oid4vciManagementService, RegisteredClientRecord, RegisteredClientWrite,
        TransactionCredentialBinding,
    },
    oid4vci_management_http,
};
use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use serde_json::{json, Value};
use tower::ServiceExt;

#[derive(Default)]
struct ManagementState {
    calls: Mutex<Vec<String>>,
    persist_registration: Mutex<bool>,
    registered: Mutex<Option<RegisteredClientRecord>>,
}

struct ManagementRepository(Arc<ManagementState>);

#[async_trait]
impl Oid4vciManagementRepository for ManagementRepository {
    async fn save_registered_client(
        &self,
        client: &RegisteredClientWrite,
    ) -> Result<(), Oid4vciManagementRepositoryError> {
        self.0.calls.lock().unwrap().push(format!(
            "save:{}:{}",
            client.organization_id, client.client_id
        ));
        if *self.0.persist_registration.lock().unwrap() {
            let now = Utc.with_ymd_and_hms(2026, 9, 21, 12, 34, 56).unwrap();
            *self.0.registered.lock().unwrap() = Some(RegisteredClientRecord {
                organization_id: client.organization_id.clone(),
                client_id: client.client_id.clone(),
                jwks: client.jwks.clone(),
                redirect_uris: client.redirect_uris.clone(),
                token_endpoint_auth_method: "private_key_jwt".to_owned(),
                active: client.active,
                created_at: now,
                updated_at: now,
            });
        }
        Ok(())
    }

    async fn registered_client(
        &self,
        organization_id: &str,
        client_id: &str,
    ) -> Result<Option<RegisteredClientRecord>, Oid4vciManagementRepositoryError> {
        self.0
            .calls
            .lock()
            .unwrap()
            .push(format!("get:{organization_id}:{client_id}"));
        Ok(self.0.registered.lock().unwrap().clone())
    }

    async fn transaction(
        &self,
        _transaction_id: &str,
    ) -> Result<Option<ManagementTransaction>, Oid4vciManagementRepositoryError> {
        Ok(None)
    }

    async fn credential_for_transaction(
        &self,
        _transaction_id: &str,
    ) -> Result<Option<TransactionCredentialBinding>, Oid4vciManagementRepositoryError> {
        Ok(None)
    }

    async fn revoke_transaction(
        &self,
        _transaction_id: &str,
        _reason: Option<&str>,
    ) -> Result<ManagementTransaction, Oid4vciManagementRepositoryError> {
        Err(Oid4vciManagementRepositoryError)
    }
}

struct CredentialRepository {
    calls: Arc<Mutex<Vec<String>>>,
    records: Vec<IssuedCredentialProjectionSource>,
    fails: bool,
}

#[async_trait]
impl IssuedCredentialRecordRepository for CredentialRepository {
    async fn get(
        &self,
        _credential_id: &str,
    ) -> Result<Option<IssuedCredentialProjectionSource>, IssuedCredentialRepositoryError> {
        Ok(None)
    }

    async fn list_by_organization(
        &self,
        organization_id: &str,
    ) -> Result<Vec<IssuedCredentialProjectionSource>, IssuedCredentialRepositoryError> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("list:{organization_id}"));
        if self.fails {
            return Err(IssuedCredentialRepositoryError);
        }
        Ok(self.records.clone())
    }
}

struct UnusedLifecycleRepository;

#[async_trait]
impl CredentialManagementRepository for UnusedLifecycleRepository {
    async fn get(
        &self,
        _credential_id: &str,
    ) -> Result<Option<ManagedCredential>, CredentialManagementPortError> {
        Ok(None)
    }

    async fn persist(
        &self,
        _credential: &ManagedCredential,
        _expected_status: ManagedCredentialStatus,
        _audit: &CredentialLifecycleAuditRecord,
    ) -> Result<ManagedCredential, CredentialManagementPortError> {
        Err(CredentialManagementPortError("unused".to_owned()))
    }

    async fn synchronize_canvas(
        &self,
        _credential: &ManagedCredential,
        _action: CredentialLifecycleAction,
        _reason: Option<&str>,
    ) -> Result<(), CanvasLifecycleSyncError> {
        Err(CredentialManagementPortError("unused".to_owned()).into())
    }
}

struct UnusedPublisher;

#[async_trait]
impl CredentialStatusPublisher for UnusedPublisher {
    async fn publish(
        &self,
        _credential: &ManagedCredential,
        _action: CredentialLifecycleAction,
        _reason: Option<&str>,
    ) -> Result<(), CredentialManagementPortError> {
        Err(CredentialManagementPortError("unused".to_owned()))
    }
}

struct UnusedEvents;

#[async_trait]
impl CredentialLifecycleEventSink for UnusedEvents {
    async fn emit(&self, _event: CredentialLifecycleEvent) {}
}

fn lifecycle() -> CredentialManagementService {
    CredentialManagementService::new(
        Arc::new(UnusedLifecycleRepository),
        Arc::new(UnusedPublisher),
        Arc::new(UnusedEvents),
    )
}

fn source(id: &str, status: &str) -> IssuedCredentialProjectionSource {
    let issued_at = Utc.with_ymd_and_hms(2026, 9, 21, 12, 34, 56).unwrap();
    IssuedCredentialProjectionSource {
        id: id.to_owned(),
        transaction_id: format!("tx-{id}"),
        organization_id: "org-a".to_owned(),
        credential_template_id: "template-a".to_owned(),
        applicant_id: Some("applicant-a".to_owned()),
        subject_did: Some("did:example:alice".to_owned()),
        issuer_did: None,
        revocation_profile_id: None,
        renewed_from_credential_id: None,
        renewed_to_credential_id: None,
        status_list_entries: vec![],
        credential_hash: None,
        status: status.to_owned(),
        status_updated_at: issued_at,
        revoked_at: None,
        revocation_reason: None,
        issued_at,
        expires_at: None,
        transaction: None,
    }
}

fn app(
    management: Arc<ManagementState>,
    credential_calls: Arc<Mutex<Vec<String>>>,
) -> axum::Router {
    app_with_credential_failure(management, credential_calls, false)
}

fn app_with_credential_failure(
    management: Arc<ManagementState>,
    credential_calls: Arc<Mutex<Vec<String>>>,
    credential_repository_fails: bool,
) -> axum::Router {
    let service = Oid4vciManagementService::new(
        Arc::new(ManagementRepository(management)),
        Arc::new(CredentialRepository {
            calls: credential_calls,
            records: vec![source("active", "active"), source("revoked", "revoked")],
            fails: credential_repository_fails,
        }),
        lifecycle(),
        Some("management-key"),
    );
    oid4vci_management_http::router(service)
}

async fn response(request: Request<Body>, app: axum::Router) -> (StatusCode, Value) {
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

fn public_jwks() -> Value {
    let public = SecretKey::from_slice(&[7_u8; 32])
        .unwrap()
        .public_key()
        .to_encoded_point(false);
    json!({"keys":[{
        "kty":"EC", "crv":"P-256", "alg":"ES256", "use":"sig", "kid":"key-a",
        "x":URL_SAFE_NO_PAD.encode(public.x().unwrap()),
        "y":URL_SAFE_NO_PAD.encode(public.y().unwrap())
    }]})
}

#[tokio::test]
async fn list_authenticates_and_binds_tenant_before_repository_access() {
    let management = Arc::new(ManagementState::default());
    let calls = Arc::new(Mutex::new(vec![]));
    for (request, status, detail) in [
        (
            Request::get("/v1/issuance/credentials?organization_id=org-a")
                .body(Body::empty())
                .unwrap(),
            StatusCode::UNAUTHORIZED,
            "X-API-Key header is missing",
        ),
        (
            Request::get("/v1/issuance/credentials?organization_id=org-a")
                .header("x-api-key", "management-key")
                .body(Body::empty())
                .unwrap(),
            StatusCode::FORBIDDEN,
            "Trusted organization context is required",
        ),
        (
            Request::get("/v1/issuance/credentials?organization_id=org-a")
                .header("x-api-key", "management-key")
                .header("x-organization-id", "org-b")
                .body(Body::empty())
                .unwrap(),
            StatusCode::FORBIDDEN,
            "Organization context does not match requested organization",
        ),
    ] {
        let (actual, body) = response(request, app(management.clone(), calls.clone())).await;
        assert_eq!(actual, status);
        assert_eq!(body, json!({"detail":detail}));
        assert!(calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn list_authenticates_before_parsing_the_query() {
    let management = Arc::new(ManagementState::default());
    let calls = Arc::new(Mutex::new(vec![]));
    let request = Request::get("/v1/issuance/credentials?organization_id=%ZZ")
        .body(Body::empty())
        .unwrap();
    let (status, body) = response(request, app(management.clone(), calls.clone())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"detail":"X-API-Key header is missing"}));
    assert!(management.calls.lock().unwrap().is_empty());
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn list_sanitizes_repository_failure() {
    let management = Arc::new(ManagementState::default());
    let calls = Arc::new(Mutex::new(vec![]));
    let request = Request::get("/v1/issuance/credentials?organization_id=org-a")
        .header("x-api-key", "management-key")
        .header("x-organization-id", "org-a")
        .body(Body::empty())
        .unwrap();
    let (status, body) = response(
        request,
        app_with_credential_failure(management, calls.clone(), true),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body,
        json!({"detail":"OID4VCI management service is temporarily unavailable"})
    );
    assert_eq!(*calls.lock().unwrap(), vec!["list:org-a"]);
}

#[tokio::test]
async fn list_preserves_order_projection_and_case_sensitive_filter() {
    let management = Arc::new(ManagementState::default());
    let calls = Arc::new(Mutex::new(vec![]));
    let request = Request::get("/v1/issuance/credentials?organization_id=org-a&status=active")
        .header("x-api-key", "management-key")
        .header("x-organization-id", "org-a")
        .body(Body::empty())
        .unwrap();
    let (status, body) = response(request, app(management.clone(), calls.clone())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert_eq!(body[0]["id"], "active");
    assert_eq!(body[0].as_object().unwrap().len(), 7);
    assert_eq!(*calls.lock().unwrap(), vec!["list:org-a"]);

    calls.lock().unwrap().clear();
    let request = Request::get("/v1/issuance/credentials?organization_id=org-a&status=ACTIVE")
        .header("x-api-key", "management-key")
        .header("x-organization-id", "org-a")
        .body(Body::empty())
        .unwrap();
    let (_, body) = response(request, app(management, calls.clone())).await;
    assert_eq!(body, json!([]));
    assert_eq!(*calls.lock().unwrap(), vec!["list:org-a"]);
}

#[tokio::test]
async fn registration_rejects_private_material_and_tenant_mismatch_before_save() {
    let management = Arc::new(ManagementState::default());
    let calls = Arc::new(Mutex::new(vec![]));
    let private = json!({
        "organization_id":"org-a", "client_id":"wallet-a",
        "jwks":{"keys":[{"kty":"EC","d":"private-secret"}]}
    });
    let request = Request::put("/v1/issuance/oid4vci-clients")
        .header("x-api-key", "management-key")
        .header("x-organization-id", "org-a")
        .header("content-type", "application/json")
        .body(Body::from(private.to_string()))
        .unwrap();
    let (status, body) = response(request, app(management.clone(), calls.clone())).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["detail"][0]["input"], private);
    assert_eq!(
        body["detail"][0]["msg"],
        "Value error, jwks.keys[0] contains private key material"
    );
    assert!(management.calls.lock().unwrap().is_empty());

    let request = Request::put("/v1/issuance/oid4vci-clients")
        .header("x-api-key", "management-key")
        .header("x-organization-id", "org-b")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "organization_id":"org-a", "client_id":"wallet-a",
                "jwks":public_jwks(), "redirect_uris":[]
            })
            .to_string(),
        ))
        .unwrap();
    let (status, _) = response(request, app(management.clone(), calls)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(management.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn registration_authenticates_before_parsing_the_body() {
    let management = Arc::new(ManagementState::default());
    let calls = Arc::new(Mutex::new(vec![]));
    let request = Request::put("/v1/issuance/oid4vci-clients")
        .header("content-type", "application/json")
        .body(Body::from("not-json"))
        .unwrap();
    let (status, body) = response(request, app(management.clone(), calls.clone())).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"detail":"X-API-Key header is missing"}));
    assert!(management.calls.lock().unwrap().is_empty());
    assert!(calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn registration_saves_then_reads_and_reports_missing_read_after_write() {
    let management = Arc::new(ManagementState::default());
    let calls = Arc::new(Mutex::new(vec![]));
    let request_body = json!({
        "organization_id":"org-a", "client_id":"wallet-a",
        "jwks":public_jwks(), "redirect_uris":[]
    });
    let request = Request::put("/v1/issuance/oid4vci-clients")
        .header("x-api-key", "management-key")
        .header("x-organization-id", "org-a")
        .header("content-type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    let (status, body) = response(request, app(management.clone(), calls.clone())).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        body,
        json!({"detail":"Registered client was not persisted"})
    );
    assert_eq!(
        *management.calls.lock().unwrap(),
        vec!["save:org-a:wallet-a", "get:org-a:wallet-a"]
    );

    management.calls.lock().unwrap().clear();
    *management.persist_registration.lock().unwrap() = true;
    let request = Request::put("/v1/issuance/oid4vci-clients")
        .header("x-api-key", "management-key")
        .header("x-organization-id", "org-a")
        .header("content-type", "application/json")
        .body(Body::from(request_body.to_string()))
        .unwrap();
    let (status, body) = response(request, app(management.clone(), calls)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["organization_id"], "org-a");
    assert_eq!(body["client_id"], "wallet-a");
    assert_eq!(body["token_endpoint_auth_method"], "private_key_jwt");
}

#[tokio::test]
async fn registration_persists_and_returns_canonical_jose_defaults() {
    let management = Arc::new(ManagementState::default());
    *management.persist_registration.lock().unwrap() = true;
    let calls = Arc::new(Mutex::new(vec![]));
    let mut jwks = public_jwks();
    jwks["keys"][0].as_object_mut().unwrap().remove("alg");
    jwks["keys"][0].as_object_mut().unwrap().remove("use");
    let request = Request::put("/v1/issuance/oid4vci-clients")
        .header("x-api-key", "management-key")
        .header("x-organization-id", "org-a")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "organization_id":"org-a", "client_id":"wallet-a",
                "jwks":jwks, "redirect_uris":[]
            })
            .to_string(),
        ))
        .unwrap();

    let (status, body) = response(request, app(management, calls)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["jwks"]["keys"][0]["alg"], "ES256");
    assert_eq!(body["jwks"]["keys"][0]["use"], "sig");
}

struct RevocationManagementRepository {
    order: Arc<Mutex<Vec<&'static str>>>,
    transaction: Option<ManagementTransaction>,
    binding: Option<TransactionCredentialBinding>,
}

#[async_trait]
impl Oid4vciManagementRepository for RevocationManagementRepository {
    async fn save_registered_client(
        &self,
        _client: &RegisteredClientWrite,
    ) -> Result<(), Oid4vciManagementRepositoryError> {
        unreachable!()
    }

    async fn registered_client(
        &self,
        _organization_id: &str,
        _client_id: &str,
    ) -> Result<Option<RegisteredClientRecord>, Oid4vciManagementRepositoryError> {
        unreachable!()
    }

    async fn transaction(
        &self,
        _transaction_id: &str,
    ) -> Result<Option<ManagementTransaction>, Oid4vciManagementRepositoryError> {
        self.order.lock().unwrap().push("transaction:get");
        Ok(self.transaction.clone())
    }

    async fn credential_for_transaction(
        &self,
        _transaction_id: &str,
    ) -> Result<Option<TransactionCredentialBinding>, Oid4vciManagementRepositoryError> {
        self.order.lock().unwrap().push("credential-binding:get");
        Ok(self.binding.clone())
    }

    async fn revoke_transaction(
        &self,
        transaction_id: &str,
        reason: Option<&str>,
    ) -> Result<ManagementTransaction, Oid4vciManagementRepositoryError> {
        self.order.lock().unwrap().push("transaction:save");
        Ok(ManagementTransaction {
            id: transaction_id.to_owned(),
            organization_id: "org-a".to_owned(),
            status: "revoked".to_owned(),
            revoked_at: Some(Utc.with_ymd_and_hms(2026, 9, 21, 13, 0, 0).unwrap()),
            revocation_reason: reason.map(str::to_owned),
        })
    }
}

struct RevocationLifecycleRepository {
    order: Arc<Mutex<Vec<&'static str>>>,
    credential: ManagedCredential,
}

#[async_trait]
impl CredentialManagementRepository for RevocationLifecycleRepository {
    async fn get(
        &self,
        _credential_id: &str,
    ) -> Result<Option<ManagedCredential>, CredentialManagementPortError> {
        self.order.lock().unwrap().push("credential:get");
        Ok(Some(self.credential.clone()))
    }

    async fn persist(
        &self,
        credential: &ManagedCredential,
        _expected_status: ManagedCredentialStatus,
        _audit: &CredentialLifecycleAuditRecord,
    ) -> Result<ManagedCredential, CredentialManagementPortError> {
        self.order.lock().unwrap().push("credential:persist");
        Ok(credential.clone())
    }

    async fn synchronize_canvas(
        &self,
        _credential: &ManagedCredential,
        _action: CredentialLifecycleAction,
        _reason: Option<&str>,
    ) -> Result<(), CanvasLifecycleSyncError> {
        self.order.lock().unwrap().push("canvas:sync");
        Ok(())
    }
}

struct RevocationPublisher {
    order: Arc<Mutex<Vec<&'static str>>>,
    fail: bool,
}

#[async_trait]
impl CredentialStatusPublisher for RevocationPublisher {
    async fn publish(
        &self,
        _credential: &ManagedCredential,
        _action: CredentialLifecycleAction,
        _reason: Option<&str>,
    ) -> Result<(), CredentialManagementPortError> {
        self.order.lock().unwrap().push("canonical:publish");
        if self.fail {
            Err(CredentialManagementPortError("sensitive cause".to_owned()))
        } else {
            Ok(())
        }
    }
}

struct RevocationEvents(Arc<Mutex<Vec<&'static str>>>);

#[async_trait]
impl CredentialLifecycleEventSink for RevocationEvents {
    async fn emit(&self, _event: CredentialLifecycleEvent) {
        self.0.lock().unwrap().push("event:emit");
    }
}

fn revocation_app(
    order: Arc<Mutex<Vec<&'static str>>>,
    transaction: Option<ManagementTransaction>,
    binding: Option<TransactionCredentialBinding>,
    credential_organization: &str,
    publication_fails: bool,
) -> axum::Router {
    let now = Utc.with_ymd_and_hms(2026, 9, 21, 12, 34, 56).unwrap();
    let lifecycle = CredentialManagementService::new(
        Arc::new(RevocationLifecycleRepository {
            order: order.clone(),
            credential: ManagedCredential {
                id: "credential-a".to_owned(),
                transaction_id: "tx-a".to_owned(),
                organization_id: credential_organization.to_owned(),
                credential_template_id: "template-a".to_owned(),
                issuer_did: None,
                status: ManagedCredentialStatus::Active,
                status_updated_at: now,
                revoked: false,
                revoked_at: None,
                revocation_reason: None,
                revocation_profile_id: Some("profile-a".to_owned()),
                status_list_entries: vec![],
            },
        }),
        Arc::new(RevocationPublisher {
            order: order.clone(),
            fail: publication_fails,
        }),
        Arc::new(RevocationEvents(order.clone())),
    );
    let service = Oid4vciManagementService::new(
        Arc::new(RevocationManagementRepository {
            order,
            transaction,
            binding,
        }),
        Arc::new(CredentialRepository {
            calls: Arc::default(),
            records: vec![],
            fails: false,
        }),
        lifecycle,
        Some("management-key"),
    );
    oid4vci_management_http::router(service)
}

fn transaction(organization_id: &str) -> ManagementTransaction {
    ManagementTransaction {
        id: "tx-a".to_owned(),
        organization_id: organization_id.to_owned(),
        status: "issued".to_owned(),
        revoked_at: None,
        revocation_reason: None,
    }
}

fn binding(organization_id: &str) -> TransactionCredentialBinding {
    TransactionCredentialBinding {
        id: "credential-a".to_owned(),
        transaction_id: "tx-a".to_owned(),
        organization_id: organization_id.to_owned(),
    }
}

fn revoke_request(organization_id: &str) -> Request<Body> {
    revoke_request_with_reason(organization_id, "holder request")
}

fn revoke_request_with_reason(organization_id: &str, reason: &str) -> Request<Body> {
    Request::post("/v1/issuance/transactions/tx-a/revoke")
        .header("x-api-key", "management-key")
        .header("x-organization-id", organization_id)
        .header("content-type", "application/json")
        .body(Body::from(json!({"reason":reason}).to_string()))
        .unwrap()
}

#[tokio::test]
async fn revocation_authenticates_before_parsing_the_body() {
    let order = Arc::new(Mutex::new(vec![]));
    let app = revocation_app(
        order.clone(),
        Some(transaction("org-a")),
        Some(binding("org-a")),
        "org-a",
        false,
    );
    let request = Request::post("/v1/issuance/transactions/tx-a/revoke")
        .header("content-type", "application/json")
        .body(Body::from("not-json"))
        .unwrap();
    let (status, body) = response(request, app).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"detail":"X-API-Key header is missing"}));
    assert!(order.lock().unwrap().is_empty());
}

#[tokio::test]
async fn revocation_orders_canonical_and_local_credential_before_transaction_commit() {
    let order = Arc::new(Mutex::new(vec![]));
    let app = revocation_app(
        order.clone(),
        Some(transaction("org-a")),
        Some(binding("org-a")),
        "org-a",
        false,
    );
    let (status, body) = response(revoke_request("org-a"), app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "tx-a");
    assert_eq!(body["status"], "revoked");
    assert_eq!(body["revocation_reason"], "holder request");
    assert_eq!(
        *order.lock().unwrap(),
        vec![
            "transaction:get",
            "credential-binding:get",
            "credential:get",
            "canonical:publish",
            "credential:persist",
            "canvas:sync",
            "event:emit",
            "transaction:save"
        ]
    );
}

#[tokio::test]
async fn revocation_preserves_the_legacy_unbounded_reason_capability() {
    let order = Arc::new(Mutex::new(vec![]));
    let app = revocation_app(
        order,
        Some(transaction("org-a")),
        Some(binding("org-a")),
        "org-a",
        false,
    );
    let reason = "r".repeat(2_001);
    let (status, body) = response(revoke_request_with_reason("org-a", &reason), app).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revocation_reason"], reason);
}

#[tokio::test]
async fn revocation_fails_closed_and_sanitizes_canonical_publication_failure() {
    let order = Arc::new(Mutex::new(vec![]));
    let app = revocation_app(
        order.clone(),
        Some(transaction("org-a")),
        Some(binding("org-a")),
        "org-a",
        true,
    );
    let (status, body) = response(revoke_request("org-a"), app).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body,
        json!({"detail":"Revocation service rejected the status change"})
    );
    assert_eq!(
        *order.lock().unwrap(),
        vec![
            "transaction:get",
            "credential-binding:get",
            "credential:get",
            "canonical:publish"
        ]
    );
}

#[tokio::test]
async fn revocation_hides_foreign_transaction_and_rejects_credential_tenant_mismatch() {
    let foreign_order = Arc::new(Mutex::new(vec![]));
    let app = revocation_app(
        foreign_order.clone(),
        Some(transaction("org-a")),
        Some(binding("org-a")),
        "org-a",
        false,
    );
    let (status, body) = response(revoke_request("org-b"), app).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({"detail":"Resource not found"}));
    assert_eq!(*foreign_order.lock().unwrap(), vec!["transaction:get"]);

    let mismatch_order = Arc::new(Mutex::new(vec![]));
    let app = revocation_app(
        mismatch_order.clone(),
        Some(transaction("org-a")),
        Some(binding("org-b")),
        "org-b",
        false,
    );
    let (status, body) = response(revoke_request("org-a"), app).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body,
        json!({"detail":"Issued credential organization does not match its transaction"})
    );
    assert_eq!(
        *mismatch_order.lock().unwrap(),
        vec!["transaction:get", "credential-binding:get"]
    );
}

#[tokio::test]
async fn revocation_reports_a_missing_transaction_without_other_repository_access() {
    let order = Arc::new(Mutex::new(vec![]));
    let app = revocation_app(order.clone(), None, None, "org-a", false);
    let (status, body) = response(revoke_request("org-a"), app).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({"detail":"Transaction not found"}));
    assert_eq!(*order.lock().unwrap(), vec!["transaction:get"]);
}
