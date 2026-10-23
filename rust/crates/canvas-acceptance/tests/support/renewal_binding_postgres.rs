//! Real published-schema renewal binding and finalizer boundaries.
//!
//! Rows below are explicitly seeded historical/recovery inputs, not newly
//! admitted offers or actual wallet sends. The repository and finalizer are real.
//! A controlled HTTP publisher counts attempts separately from atomic DB links.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::time::Duration;

use axum::{
    extract::{Path, Request, State},
    http::HeaderMap,
    middleware::{from_fn_with_state, Next},
    response::Response,
    routing::post,
    Json, Router,
};
use marty_issuance_service::{
    canvas_issuance_guard::CanvasGuardConfig,
    credential::{
        CredentialLifecycle, CredentialTransaction, CredentialTransactionStatus, IssuedCredential,
    },
    credential_lifecycle::PostgresCredentialLifecycle,
    credential_postgres::PostgresCredentialRepository,
    credential_renewal::{RenewalRepository, RenewalRepositoryError, RenewalSource},
    initiation::{idempotency_binding, InitiationRepository, InitiationRequest},
};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tokio::sync::Barrier;
use uuid::Uuid;

use super::renewal_reference_fixture as reference;

#[path = "renewal_canvas_binding.rs"]
mod canvas;

const ENDPOINT: &str = "https://synthetic-wallet.example/renewal";
const MESSAGE: &str = "synthetic-renewal-message";
const TOKEN: &str = "synthetic-renewal-status-token";

struct Fixture {
    pool: PgPool,
    repository: PostgresCredentialRepository,
    organization: String,
}

impl Fixture {
    fn transaction(&self) -> CredentialTransaction {
        let corpus = reference::corpus();
        let before = reference::snapshot(
            &corpus,
            reference::case(&corpus, "ordinary-offer"),
            "before",
        );
        let source = reference::source(before).unwrap();
        let row = before["transactions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == source.transaction_id)
            .unwrap();
        let mut transaction = reference::transaction(row);
        transaction.id = Uuid::new_v4().to_string();
        transaction.organization_id.clone_from(&self.organization);
        transaction.pre_authorized_code = format!("synthetic-code-{}", transaction.id);
        transaction.status = CredentialTransactionStatus::Pending;
        transaction.application_id = None;
        transaction.renewal_of_credential_id = None;
        transaction.reserved_credential_id = None;
        let request = InitiationRequest {
            organization_id: transaction.organization_id.clone(),
            issuer_did: transaction.issuer_did.clone().unwrap(),
            credential_template_id: Some(transaction.credential_template_id.clone()),
            claims: Some(transaction.claims.clone()),
            ..InitiationRequest::default()
        };
        let binding = idempotency_binding(Some(&transaction.id), &request)
            .unwrap()
            .unwrap();
        transaction.idempotency_key_hash = Some(binding.key_hash);
        transaction.idempotency_request_hash = Some(binding.request_hash);
        transaction
    }

    async fn reserve(&self, transaction: &CredentialTransaction) {
        let reservation = self
            .repository
            .reserve_idempotently(transaction)
            .await
            .unwrap();
        assert!(reservation.created);
        assert_eq!(reservation.transaction, *transaction);
    }

    async fn credential(&self, transaction: &CredentialTransaction) -> IssuedCredential {
        let credential = IssuedCredential {
            id: Uuid::new_v4().to_string(),
            transaction_id: transaction.id.clone(),
            organization_id: transaction.organization_id.clone(),
            credential_template_id: transaction.credential_template_id.clone(),
            applicant_id: transaction.applicant_id.clone(),
            subject_did: transaction.subject_did.clone(),
            issuer_did: transaction.issuer_did.clone().unwrap(),
            revocation_profile_id: transaction.revocation_profile_id.clone(),
            renewed_from_credential_id: None,
            status_list_entries: vec![
                json!({"status_list_id":transaction.revocation_profile_id,"index":7}),
            ],
            credential: "synthetic-historical-credential".into(),
            credential_hash: "synthetic-historical-hash".into(),
            issued_at: transaction.created_at,
            expires_at: transaction.expires_at,
        };
        sqlx::query(
            "INSERT INTO issuance_service.issued_credentials
             (id,transaction_id,organization_id,credential_template_id,applicant_id,subject_did,
              issuer_did,revocation_profile_id,status_list_entries,credential_jwt,credential_hash,
              status,status_updated_at,revoked,issued_at,expires_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'active',$12,false,$12,$13)",
        )
        .bind(&credential.id)
        .bind(&credential.transaction_id)
        .bind(&credential.organization_id)
        .bind(&credential.credential_template_id)
        .bind(&credential.applicant_id)
        .bind(&credential.subject_did)
        .bind(&credential.issuer_did)
        .bind(&credential.revocation_profile_id)
        .bind(json!(credential.status_list_entries))
        .bind(&credential.credential)
        .bind(&credential.credential_hash)
        .bind(credential.issued_at)
        .bind(credential.expires_at)
        .execute(&self.pool)
        .await
        .unwrap();
        credential
    }

    async fn source(&self) -> RenewalSource {
        let mut transaction = self.transaction();
        transaction.status = CredentialTransactionStatus::Issued;
        self.reserve(&transaction).await;
        let credential = self.credential(&transaction).await;
        self.repository
            .source(&credential.id)
            .await
            .unwrap()
            .unwrap()
    }

    async fn transported(
        &self,
        transaction: &CredentialTransaction,
        credential: &IssuedCredential,
    ) {
        // Existing durable delivery identity: fixture only, no fake finalizer.
        let id = Uuid::new_v5(
            &Uuid::NAMESPACE_URL,
            format!("{}:didcomm_v2:-", credential.id).as_bytes(),
        )
        .to_string();
        sqlx::query(
            "INSERT INTO issuance_service.credential_delivery_records
             (id,credential_id,transaction_id,organization_id,delivery_target,delivery_mode,status,metadata,created_at,updated_at)
             VALUES ($1,$2,$3,$4,'didcomm_v2','wallet_only','transported',$5,clock_timestamp(),clock_timestamp())")
            .bind(id).bind(&credential.id).bind(&transaction.id).bind(&transaction.organization_id)
            .bind(json!({"service_endpoint":ENDPOINT,"didcomm_message_id":MESSAGE}))
            .execute(&self.pool).await.unwrap();
    }

    async fn successor(&self, source: &RenewalSource) -> (CredentialTransaction, IssuedCredential) {
        let mut transaction = self.transaction();
        transaction.renewal_of_credential_id = Some(source.id.clone());
        transaction.status = CredentialTransactionStatus::Issued;
        self.reserve(&transaction).await;
        let credential = self.credential(&transaction).await;
        self.transported(&transaction, &credential).await;
        (transaction, credential)
    }

    async fn snapshot(&self) -> Value {
        sqlx::query_scalar(
            "SELECT jsonb_build_object(
              'transactions',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id),'[]') FROM issuance_service.issuance_transactions t WHERE organization_id=$1),
              'credentials',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY id),'[]') FROM issuance_service.issued_credentials c WHERE organization_id=$1),
              'deliveries',(SELECT COALESCE(jsonb_agg(to_jsonb(d) ORDER BY id),'[]') FROM issuance_service.credential_delivery_records d WHERE organization_id=$1),
              'events',(SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]') FROM issuance_service.issuance_events e JOIN issuance_service.issuance_transactions t ON t.id=e.transaction_id WHERE t.organization_id=$1))")
            .bind(&self.organization).fetch_one(&self.pool).await.unwrap()
    }
}

#[derive(Clone, Default)]
struct PublisherState {
    attempts: Arc<AtomicUsize>,
    calls: Arc<Mutex<Vec<Value>>>,
    barrier: Arc<Mutex<Option<Arc<Barrier>>>>,
}

struct Publisher {
    state: PublisherState,
    url: url::Url,
    task: tokio::task::JoinHandle<()>,
}

impl Publisher {
    fn app(state: PublisherState) -> Router {
        async fn count_attempt(
            State(state): State<PublisherState>,
            request: Request,
            next: Next,
        ) -> Response {
            // Counts even an unknown route, wrong method, malformed JSON or
            // rejected handler input. No request values enter diagnostics.
            state.attempts.fetch_add(1, Ordering::SeqCst);
            next.run(request).await
        }
        async fn publish(
            State(state): State<PublisherState>,
            Path(profile): Path<String>,
            headers: HeaderMap,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            assert!(
                headers
                    .get("x-service-token")
                    .and_then(|value| value.to_str().ok())
                    == Some(TOKEN),
                "Publisher authentication differs"
            );
            assert!(
                profile == "synthetic-revocation-profile",
                "Publisher profile differs"
            );
            assert!(body["status"] == "revoked", "Publisher status differs");
            assert!(
                body["reason"] == "Superseded by renewed credential",
                "Publisher reason differs"
            );
            state.calls.lock().unwrap().push(body.clone());
            let barrier = state.barrier.lock().unwrap().clone();
            if let Some(barrier) = barrier {
                tokio::time::timeout(Duration::from_secs(5), barrier.wait())
                    .await
                    .expect("both finalizers must reach controlled publisher");
            }
            Json(
                json!({"success":true,"organization_id":body["organization_id"],"index":body["index"],"status_list_url":"https://synthetic-status.example/list"}),
            )
        }
        Router::new()
            .route(
                "/internal/revocation-profiles/{profile}/process-revocation",
                post(publish),
            )
            .with_state(state.clone())
            .layer(from_fn_with_state(state, count_attempt))
    }

    async fn start() -> Self {
        let state = PublisherState::default();
        let app = Self::app(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { state, url, task }
    }

    fn count(&self) -> usize {
        self.state.attempts.load(Ordering::SeqCst)
    }

    fn assert_no_unexpected_requests(&self) {
        assert_eq!(
            self.count(),
            self.state.calls.lock().unwrap().len(),
            "Every HTTP attempt must have reached the validated publisher"
        );
    }

    async fn close(mut self) {
        self.task.abort();
        assert!((&mut self.task).await.unwrap_err().is_cancelled());
    }
}

impl Drop for Publisher {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn binding_cases(fixture: &Fixture) {
    let source = fixture.source().await;
    let other = fixture.source().await;
    let missing = fixture.transaction();
    let before = fixture.snapshot().await;
    assert_eq!(
        fixture
            .repository
            .bind_reservation(&missing, &source, None)
            .await
            .unwrap_err(),
        RenewalRepositoryError::ReservationMissing
    );
    assert_eq!(fixture.snapshot().await, before);
    let pending = fixture.transaction();
    fixture.reserve(&pending).await;
    let bound = fixture
        .repository
        .bind_reservation(&pending, &source, Some("synthetic-application"))
        .await
        .unwrap();
    let mut expected = pending.clone();
    expected.renewal_of_credential_id = Some(source.id.clone());
    expected.application_id = Some("synthetic-application".into());
    assert_eq!(
        bound, expected,
        "historical pending binding changes trusted links only"
    );
    let before = fixture.snapshot().await;
    assert_eq!(
        fixture
            .repository
            .bind_reservation(&pending, &source, Some("synthetic-application"))
            .await
            .unwrap(),
        bound
    );
    assert_eq!(
        fixture.snapshot().await,
        before,
        "exact same-source replay is unchanged"
    );
    let (same_first, same_second) = tokio::join!(
        fixture
            .repository
            .bind_reservation(&pending, &source, Some("synthetic-application")),
        fixture
            .repository
            .bind_reservation(&pending, &source, Some("synthetic-application")),
    );
    assert_eq!(same_first.unwrap(), bound);
    assert_eq!(same_second.unwrap(), bound);
    assert_eq!(fixture.snapshot().await, before);
    for (source, application) in [
        (&other, Some("synthetic-application")),
        (&source, None),
        (&source, Some("different-application")),
    ] {
        assert_eq!(
            fixture
                .repository
                .bind_reservation(&pending, source, application)
                .await
                .unwrap_err(),
            RenewalRepositoryError::BindingConflict
        );
        assert_eq!(fixture.snapshot().await, before);
    }
    let mut bad_hash = pending.clone();
    bad_hash.idempotency_request_hash = Some("f".repeat(64));
    assert_eq!(
        fixture
            .repository
            .bind_reservation(&bad_hash, &source, Some("synthetic-application"))
            .await
            .unwrap_err(),
        RenewalRepositoryError::BindingConflict
    );
    assert_eq!(fixture.snapshot().await, before);
    let mut foreign = source.clone();
    foreign.organization_id = "foreign-organization".into();
    assert_eq!(
        fixture
            .repository
            .bind_reservation(&pending, &foreign, Some("synthetic-application"))
            .await
            .unwrap_err(),
        RenewalRepositoryError::BindingConflict
    );
    assert_eq!(fixture.snapshot().await, before);

    // A reused ordinary request must never relabel completed/claimed work.
    for kind in [
        "issued",
        "signing",
        "reserved",
        "credential",
        "credential-and-delivery",
        "application",
    ] {
        let mut transaction = fixture.transaction();
        if kind == "issued" {
            transaction.status = CredentialTransactionStatus::Issued;
        }
        if kind == "signing" {
            transaction.status = CredentialTransactionStatus::Signing;
        }
        if kind == "reserved" {
            transaction.reserved_credential_id = Some(Uuid::new_v4().to_string());
        }
        if kind == "application" {
            transaction.application_id = Some("ordinary-application".into());
        }
        fixture.reserve(&transaction).await;
        if kind == "credential" || kind == "credential-and-delivery" {
            let credential = fixture.credential(&transaction).await;
            // The published schema requires a credential FK. This combined
            // guard case does not independently prove delivery-only exclusion.
            if kind == "credential-and-delivery" {
                fixture.transported(&transaction, &credential).await;
            }
        }
        let before = fixture.snapshot().await;
        assert_eq!(
            fixture
                .repository
                .bind_reservation(&transaction, &source, None)
                .await
                .unwrap_err(),
            RenewalRepositoryError::BindingConflict,
            "{kind}"
        );
        assert_eq!(fixture.snapshot().await, before, "{kind}");
    }

    let transaction = fixture.transaction();
    fixture.reserve(&transaction).await;
    let (first, second) = tokio::join!(
        fixture
            .repository
            .bind_reservation(&transaction, &source, None),
        fixture
            .repository
            .bind_reservation(&transaction, &other, None),
    );
    assert_ne!(
        first.is_ok(),
        second.is_ok(),
        "one source wins the same pending reservation"
    );
    let (winner, loser) = match (first, second) {
        (Ok(winner), Err(loser)) | (Err(loser), Ok(winner)) => (winner, loser),
        _ => panic!("exactly one source must win the pending reservation"),
    };
    assert_eq!(loser, RenewalRepositoryError::BindingConflict);
    let observed: Option<String> = sqlx::query_scalar(
        "SELECT renewal_of_credential_id FROM issuance_service.issuance_transactions WHERE id=$1",
    )
    .bind(&transaction.id)
    .fetch_one(&fixture.pool)
    .await
    .unwrap();
    assert_eq!(observed, winner.renewal_of_credential_id);
}

async fn finalizer_cases(fixture: &Fixture, publisher: &Publisher) {
    let lifecycle = PostgresCredentialLifecycle::new(
        fixture.pool.clone(),
        publisher.url.clone(),
        Some(TOKEN),
        Duration::from_secs(8),
        CanvasGuardConfig {
            enabled: false,
            pilot_organizations: Default::default(),
            evidence_max_age: Duration::from_secs(900),
            readiness_max_age: Duration::from_secs(900),
        },
    )
    .unwrap();
    for mismatch in [
        "transaction-source",
        "backlink",
        "organization",
        "missing-successor",
        "persisted-source-organization",
        "source-inactive",
        "source-other-successor",
    ] {
        let source = fixture.source().await;
        let (mut transaction, mut credential) = fixture.successor(&source).await;
        match mismatch {
            "transaction-source" => {
                sqlx::query("UPDATE issuance_service.issuance_transactions SET renewal_of_credential_id=NULL WHERE id=$1").bind(&transaction.id).execute(&fixture.pool).await.unwrap();
            }
            "backlink" => {
                sqlx::query("UPDATE issuance_service.issued_credentials SET renewed_from_credential_id='different-source' WHERE id=$1").bind(&credential.id).execute(&fixture.pool).await.unwrap();
            }
            "organization" => transaction.organization_id = "foreign-organization".into(),
            "missing-successor" => credential.id = Uuid::new_v4().to_string(),
            "persisted-source-organization" => {
                sqlx::query("UPDATE issuance_service.issued_credentials SET organization_id='foreign-organization' WHERE id=$1").bind(&source.id).execute(&fixture.pool).await.unwrap();
            }
            "source-inactive" => {
                sqlx::query(
                    "UPDATE issuance_service.issued_credentials SET status='suspended' WHERE id=$1",
                )
                .bind(&source.id)
                .execute(&fixture.pool)
                .await
                .unwrap();
            }
            "source-other-successor" => {
                sqlx::query("UPDATE issuance_service.issued_credentials SET renewed_to_credential_id='different-successor' WHERE id=$1").bind(&source.id).execute(&fixture.pool).await.unwrap();
            }
            _ => unreachable!(),
        }
        let before = fixture.snapshot().await;
        let calls = publisher.count();
        assert!(
            lifecycle
                .after_didcomm_issued(&transaction, &credential, ENDPOINT, MESSAGE)
                .await
                .is_err(),
            "{mismatch}"
        );
        assert_eq!(
            publisher.count(),
            calls,
            "{mismatch} must fail before external publication"
        );
        assert_eq!(
            fixture.snapshot().await,
            before,
            "{mismatch} has no durable side effects"
        );
    }

    // Historical post-commit/pre-projection recovery: links are already durable,
    // but the transported delivery still needs its event/receipt projection.
    let source = fixture.source().await;
    let (transaction, credential) = fixture.successor(&source).await;
    sqlx::query("UPDATE issuance_service.issued_credentials SET status='revoked',revoked=true,renewed_to_credential_id=$2 WHERE id=$1")
        .bind(&source.id).bind(&credential.id).execute(&fixture.pool).await.unwrap();
    sqlx::query(
        "UPDATE issuance_service.issued_credentials SET renewed_from_credential_id=$2 WHERE id=$1",
    )
    .bind(&credential.id)
    .bind(&source.id)
    .execute(&fixture.pool)
    .await
    .unwrap();
    let calls = publisher.count();
    lifecycle
        .after_didcomm_issued(&transaction, &credential, ENDPOINT, MESSAGE)
        .await
        .unwrap();
    assert_eq!(
        publisher.count(),
        calls,
        "same durable successor must not republish revocation"
    );
    let delivered: i64 = sqlx::query_scalar("SELECT count(*) FROM issuance_service.credential_delivery_records WHERE transaction_id=$1 AND status='delivered'")
        .bind(&transaction.id).fetch_one(&fixture.pool).await.unwrap();
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM issuance_service.issuance_events WHERE transaction_id=$1 AND event_type='credential_issued'")
        .bind(&transaction.id).fetch_one(&fixture.pool).await.unwrap();
    assert_eq!((delivered, events), (1, 1));

    // Force both distinct successors through preflight before either publisher
    // responds. Two external attempts are observable; exactly one DB link wins.
    let source = fixture.source().await;
    let (first_tx, first_credential) = fixture.successor(&source).await;
    let (second_tx, second_credential) = fixture.successor(&source).await;
    // A legacy empty link is falsey, not a different nonempty successor.
    sqlx::query(
        "UPDATE issuance_service.issued_credentials SET renewed_to_credential_id='' WHERE id=$1",
    )
    .bind(&source.id)
    .execute(&fixture.pool)
    .await
    .unwrap();
    *publisher.state.barrier.lock().unwrap() = Some(Arc::new(Barrier::new(2)));
    let calls = publisher.count();
    let (first, second) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(
            lifecycle.after_didcomm_issued(&first_tx, &first_credential, ENDPOINT, MESSAGE),
            lifecycle.after_didcomm_issued(&second_tx, &second_credential, ENDPOINT, MESSAGE),
        )
    })
    .await
    .unwrap();
    *publisher.state.barrier.lock().unwrap() = None;
    assert_ne!(first.is_ok(), second.is_ok());
    assert_eq!(
        publisher.count() - calls,
        2,
        "publication attempts are not an at-most-once guarantee"
    );
    let expected_publication = json!({
        "organization_id":source.organization_id,
        "credential_id":source.id,
        "index":7,
        "status":"revoked",
        "credential_format":"sd_jwt_vc",
        "reason":"Superseded by renewed credential",
    });
    assert_eq!(
        &publisher.state.calls.lock().unwrap()[calls..],
        &[expected_publication.clone(), expected_publication]
    );
    let winner = if first.is_ok() {
        &first_credential
    } else {
        &second_credential
    };
    let linked: Option<String> = sqlx::query_scalar("SELECT renewed_to_credential_id FROM issuance_service.issued_credentials WHERE id=$1 AND status='revoked' AND revoked=true")
        .bind(&source.id).fetch_one(&fixture.pool).await.unwrap();
    assert_eq!(linked.as_deref(), Some(winner.id.as_str()));
    let backlinks: Vec<String> = sqlx::query_scalar("SELECT id FROM issuance_service.issued_credentials WHERE renewed_from_credential_id=$1 ORDER BY id")
        .bind(&source.id).fetch_all(&fixture.pool).await.unwrap();
    assert_eq!(backlinks, vec![winner.id.clone()]);
}

pub(super) async fn run(database_url: &str) {
    let pool = PgPoolOptions::new()
        .max_connections(6)
        .connect(database_url)
        .await
        .unwrap();
    let fixture = Fixture {
        repository: PostgresCredentialRepository::new(pool.clone(), b"synthetic-renewal-pg-hmac"),
        pool,
        organization: format!("renewal-pg-{}", Uuid::new_v4()),
    };
    binding_cases(&fixture).await;
    canvas::run(&fixture).await;
    let publisher = Publisher::start().await;
    finalizer_cases(&fixture, &publisher).await;
    publisher.assert_no_unexpected_requests();
    publisher.close().await;
    fixture.pool.close().await;
}

#[tokio::test]
async fn publisher_counts_rejected_requests_before_routing_and_validation() {
    use axum::{
        body::Body,
        http::{Method, StatusCode},
    };
    use tower::ServiceExt;

    let state = PublisherState::default();
    let app = Publisher::app(state.clone());
    let route = "/internal/revocation-profiles/synthetic-revocation-profile/process-revocation";
    for (index, (method, path, body, expected)) in [
        (Method::POST, "/wrong-path", "{}", StatusCode::NOT_FOUND),
        (Method::GET, route, "{}", StatusCode::METHOD_NOT_ALLOWED),
        (Method::POST, route, "{", StatusCode::BAD_REQUEST),
    ]
    .into_iter()
    .enumerate()
    {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .header("x-service-token", TOKEN)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        assert_eq!(state.attempts.load(Ordering::SeqCst), index + 1);
        assert!(state.calls.lock().unwrap().is_empty());
    }

    // Handler authentication rejection also occurs after the attempt counter.
    // Catch only the controlled fixed-message fixture assertion, never log data.
    use futures_util::FutureExt;
    let rejected = std::panic::AssertUnwindSafe(
        app.oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(route)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"status":"revoked","reason":"Superseded by renewed credential"}"#,
                ))
                .unwrap(),
        ),
    )
    .catch_unwind()
    .await;
    assert!(rejected.is_err());
    assert_eq!(state.attempts.load(Ordering::SeqCst), 4);
    assert!(state.calls.lock().unwrap().is_empty());
}
