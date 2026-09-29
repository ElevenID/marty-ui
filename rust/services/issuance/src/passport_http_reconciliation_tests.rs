use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Duration as ChronoDuration;
use hmac::{Hmac, Mac};
use marty_emrtd_issuance::{prepare_sod, SodSignatureAlgorithm};
use marty_passport_auth::PassportTenantCredentialSource;
use num_bigint::BigUint;
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256,
};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tower::ServiceExt;

use super::*;
use crate::{migration, passport_artifact::PassportSensitiveArtifact};

static RECONCILIATION_DATABASE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone)]
struct BureauMock {
    pool: PgPool,
    calls: Arc<AtomicUsize>,
    clear_intent_for: Arc<Mutex<Option<String>>>,
    reject_single_for: Arc<Mutex<Option<String>>>,
    misreport_batch_mapping: Arc<AtomicBool>,
    omit_batch_companion_row: Arc<AtomicBool>,
}

async fn beta_bureau_submit(
    State(mock): State<BureauMock>,
    Json(payload): Json<Value>,
) -> (StatusCode, Json<Value>) {
    mock.calls.fetch_add(1, Ordering::SeqCst);
    let organization = payload["organization_id"].as_str().unwrap();
    let source = payload["job_id"].as_str().unwrap();
    if mock.reject_single_for.lock().unwrap().as_deref() == Some(source) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"detail": "temporary bureau outage"})),
        );
    }
    let country = payload["country_code"].as_str().unwrap();
    let document_type = payload["document_type"].as_str().unwrap();
    let digests =
        material_digests(&payload, organization, source, country, Some(document_type)).unwrap();
    let proposed = Uuid::new_v4();
    let row = sqlx::query(
        "INSERT INTO issuance_service.passport_beta_bureau_jobs
         (bureau_job_id, organization_id, source_job_id, request_sha256,
          content_sha256, sod_der_sha256, dsc_der_sha256, dsc_pem_wire_sha256,
          document_type, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'QUEUED')
         ON CONFLICT (organization_id, source_job_id) DO UPDATE
         SET document_type = COALESCE(
             issuance_service.passport_beta_bureau_jobs.document_type,
             EXCLUDED.document_type)
         WHERE issuance_service.passport_beta_bureau_jobs.content_sha256 = EXCLUDED.content_sha256
         RETURNING bureau_job_id",
    )
    .bind(proposed)
    .bind(organization)
    .bind(source)
    .bind(digests.legacy_request_sha256)
    .bind(digests.content_sha256)
    .bind(digests.sod_der_sha256)
    .bind(digests.dsc_der_sha256)
    .bind(digests.dsc_pem_wire_sha256)
    .bind(document_type)
    .fetch_optional(&mock.pool)
    .await
    .unwrap();
    let Some(row) = row else {
        return (StatusCode::CONFLICT, Json(json!({"detail": "conflict"})));
    };
    let id: Uuid = row.try_get("bureau_job_id").unwrap();
    let clear_intent = mock.clear_intent_for.lock().unwrap().as_deref() == Some(source);
    if clear_intent {
        sqlx::query(
            "UPDATE issuance_service.physical_document_jobs
             SET submission_intent_id=NULL, submission_intent_started_at=NULL,
                 submission_intent_provider_profile_id=NULL,
                 submission_intent_bureau_endpoint_sha256=NULL,
                 submission_intent_signing_provenance=NULL
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(organization)
        .bind(source)
        .execute(&mock.pool)
        .await
        .unwrap();
    }
    (
        StatusCode::ACCEPTED,
        Json(json!({"bureau_job_id": id.to_string(), "status": "QUEUED"})),
    )
}

async fn beta_bureau_batch_submit(
    State(mock): State<BureauMock>,
    Json(payload): Json<Value>,
) -> (StatusCode, Json<Value>) {
    mock.calls.fetch_add(1, Ordering::SeqCst);
    let organization = payload["organization_id"].as_str().unwrap();
    let mut mapped = Vec::new();
    for (index, source) in payload["jobs"].as_array().unwrap().iter().enumerate() {
        let source_id = source["job_id"].as_str().unwrap();
        if index == 1 && mock.omit_batch_companion_row.load(Ordering::SeqCst) {
            mapped.push(json!({
                "job_id": source_id,
                "bureau_job_id": Uuid::new_v4(),
                "status": "QUEUED"
            }));
            continue;
        }
        let country = source["country_code"].as_str().unwrap();
        let digests = material_digests(source, organization, source_id, country, None).unwrap();
        let proposed = Uuid::new_v4();
        let row = sqlx::query(
            "INSERT INTO issuance_service.passport_beta_bureau_jobs
             (bureau_job_id, organization_id, source_job_id, request_sha256,
              content_sha256, sod_der_sha256, dsc_der_sha256,
              dsc_pem_wire_sha256, document_type, status)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULL,'QUEUED')
             ON CONFLICT (organization_id, source_job_id) DO UPDATE
             SET document_type = issuance_service.passport_beta_bureau_jobs.document_type
             WHERE issuance_service.passport_beta_bureau_jobs.content_sha256 = EXCLUDED.content_sha256
             RETURNING bureau_job_id",
        )
        .bind(proposed)
        .bind(organization)
        .bind(source_id)
        .bind(digests.legacy_request_sha256)
        .bind(digests.content_sha256)
        .bind(digests.sod_der_sha256)
        .bind(digests.dsc_der_sha256)
        .bind(digests.dsc_pem_wire_sha256)
        .fetch_optional(&mock.pool)
        .await
        .unwrap();
        let Some(row) = row else {
            return (StatusCode::CONFLICT, Json(json!({"detail": "conflict"})));
        };
        let id: Uuid = row.try_get("bureau_job_id").unwrap();
        mapped.push(json!({"job_id": source_id, "bureau_job_id": id, "status": "QUEUED"}));
    }
    if mock.misreport_batch_mapping.load(Ordering::SeqCst) {
        mapped[0]["bureau_job_id"] = json!(Uuid::new_v4());
    }
    (
        StatusCode::ACCEPTED,
        Json(json!({"status": "QUEUED", "jobs": mapped})),
    )
}

async fn kms_decrypt(
    State(artifact): State<Arc<Vec<u8>>>,
    Json(_request): Json<Value>,
) -> Json<Value> {
    Json(json!({"plaintext_b64": STANDARD.encode(artifact.as_slice())}))
}

async fn kms_encrypt_batch_wire(
    axum::Extension(observed): axum::Extension<Arc<Mutex<Option<Vec<u8>>>>>,
    axum::Extension(fail): axum::Extension<Arc<AtomicBool>>,
    Json(request): Json<Value>,
) -> (StatusCode, Json<Value>) {
    if fail.load(Ordering::SeqCst) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "test outage"})),
        );
    }
    assert!(request["artifact_id"]
        .as_str()
        .unwrap()
        .starts_with("passport-beta-batch-"));
    let plaintext = STANDARD
        .decode(request["plaintext_b64"].as_str().unwrap())
        .unwrap();
    *observed.lock().unwrap() = Some(plaintext);
    (
        StatusCode::OK,
        Json(json!({"ciphertext": "vault:v1:synthetic-batch-wire"})),
    )
}

async fn kms_decrypt_batch_wire_or_artifact(
    State(artifact): State<Arc<Vec<u8>>>,
    axum::Extension(observed): axum::Extension<Arc<Mutex<Option<Vec<u8>>>>>,
    Json(request): Json<Value>,
) -> Json<Value> {
    let plaintext = if request["artifact_id"]
        .as_str()
        .is_some_and(|id| id.starts_with("passport-beta-batch-"))
    {
        observed.lock().unwrap().clone().unwrap()
    } else {
        artifact.as_ref().clone()
    };
    Json(json!({"plaintext_b64": STANDARD.encode(plaintext)}))
}

async fn kms_verify_callback(Json(request): Json<Value>) -> Json<Value> {
    let body = STANDARD
        .decode(request["body_b64"].as_str().unwrap())
        .unwrap();
    let event: Value = serde_json::from_slice(&body).unwrap();
    Json(json!({
        "valid": event["organization_id"] == "org-a"
            && request["signature"]
                == "vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    }))
}

fn signed_material() -> SignedMaterial {
    let mut csca = CertificateParams::default();
    csca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    csca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    csca.distinguished_name
        .push(DnType::CommonName, "Synthetic CSCA");
    csca.distinguished_name.push(DnType::CountryName, "US");
    let csca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let csca_cert = csca.self_signed(&csca_key).unwrap();
    let issuer = Issuer::from_params(&csca, &csca_key);

    let mut dsc = CertificateParams::default();
    dsc.is_ca = IsCa::ExplicitNoCa;
    dsc.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    dsc.distinguished_name
        .push(DnType::CommonName, "Synthetic Passport DSC");
    dsc.distinguished_name.push(DnType::CountryName, "US");
    let dsc_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let dsc_cert = dsc.signed_by(&dsc_key, &issuer).unwrap();
    let signer = SigningKey::from_pkcs8_der(dsc_key.serialized_der()).unwrap();
    let prepared = prepare_sod(
        &[(1, vec![1]), (2, vec![2])],
        dsc_cert.der(),
        SodSignatureAlgorithm::Es256,
    )
    .unwrap();
    let signature: Signature = signer.sign(prepared.signing_input());
    let certificate_pem = |der: &[u8]| {
        let encoded = STANDARD.encode(der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    };
    let signed = SignedMaterial {
        sod_der_base64: STANDARD.encode(prepared.assemble(signature.to_der().as_bytes()).unwrap()),
        dsc_cert_pem: certificate_pem(dsc_cert.der()),
        csca_cert_pem: Some(certificate_pem(csca_cert.der())),
        issuer_profile_id: Some("issuer-profile-test".into()),
    };
    signed
        .verify_data_groups(&std::collections::BTreeMap::from([
            (BigUint::from(1_u8), STANDARD.encode([1])),
            (BigUint::from(2_u8), STANDARD.encode([2])),
        ]))
        .unwrap();
    signed
}

async fn reserved_job(
    repository: &PostgresPassportRepository,
    principal: &PassportTenantPrincipal,
    suffix: &str,
    encrypted: &str,
    signed: &SignedMaterial,
    endpoint_sha256: &str,
) -> PassportJob {
    let created_at = Utc::now() - ChronoDuration::seconds(50);
    let job = repository
        .insert(
            principal,
            &PassportJobInsert {
                id: format!("reconciliation-job-{suffix}"),
                application_id: format!("reconciliation-application-{suffix}"),
                flow_execution_id: format!("reconciliation-flow-{suffix}"),
                application_template_id: "template".into(),
                credential_template_id: "credential".into(),
                revocation_profile_id: None,
                delivery_destination_profile_id: "destination".into(),
                document_type: "TD3".into(),
                country_code: "USA".into(),
                issuer_did: Some("did:web:issuer.example:orgs:org-a".into()),
                secure_artifact_ciphertext: encrypted.into(),
                secure_artifact_reference: format!(
                    "physical-artifact://reconciliation-job-{suffix}"
                ),
            },
            created_at,
        )
        .await
        .unwrap();
    let reserved_at = database_precision_now() - ChronoDuration::seconds(40);
    let provenance = serde_json::to_value(
        SubmissionSigningProvenance::managed_kms(&job, signed, reserved_at).unwrap(),
    )
    .unwrap();
    repository
        .reserve_submission(
            principal,
            &job,
            &PassportSubmissionReservation {
                intent_id: Uuid::new_v4(),
                sod_sha256: &signed_sod_sha256(signed).unwrap(),
                signed_artifact_ciphertext: None,
                provider_profile_id: Some("passport-beta-bureau"),
                bureau_endpoint_sha256: endpoint_sha256,
                signing_provenance: Some(&provenance),
                now: reserved_at,
            },
        )
        .await
        .unwrap()
        .unwrap()
}

async fn call_reconciler(app: &Router, application_id: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!(
                    "/internal/passport/applications/{application_id}/reconcile-submission"
                ))
                .header("x-organization-id", "org-a")
                .header("x-api-key", "synthetic-internal-service-token-00000001")
                .header(
                    "x-passport-reconciliation-token",
                    "synthetic-operator-reconciliation-token-00000001",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn beta_reconciliation_replays_only_exact_material_and_binds_first_receipt() {
    let Ok(database_url) = std::env::var("MARTY_PASSPORT_RECONCILIATION_TEST_URL") else {
        return;
    };
    let _database_guard = RECONCILIATION_DATABASE_LOCK.lock().await;
    assert_eq!(
        url::Url::parse(&database_url)
            .unwrap()
            .path()
            .trim_start_matches('/'),
        "marty_passport_reconciliation_test"
    );
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    migration::migrate_passport(&pool).await.unwrap();
    sqlx::raw_sql(include_str!("bin/passport_beta_bureau_schema.sql"))
        .execute(&pool)
        .await
        .unwrap();

    let signed = signed_material();
    let artifact = PassportSensitiveArtifact {
        applicant: json!({"synthetic": "person"}),
        mrz: std::collections::BTreeMap::from([
            ("line_1".into(), "P<TEST".into()),
            ("line_2".into(), "PERSON".into()),
        ]),
        data_groups: std::collections::BTreeMap::from([
            ("DG1".into(), STANDARD.encode([1])),
            ("DG2".into(), STANDARD.encode([2])),
        ]),
        signed_material: Some(signed.clone()),
    };
    let encrypted = json!({
        "schema": "marty.passport-artifact-manifest/v1",
        "chunks": ["vault:v1:synthetic"]
    })
    .to_string();
    let kms = Router::new()
        .route(
            "/internal/signing-keys/passport-artifacts/decrypt",
            post(kms_decrypt),
        )
        .route(
            "/internal/signing-keys/passport-callbacks/verify",
            post(kms_verify_callback),
        )
        .with_state(Arc::new(serde_json::to_vec(&artifact).unwrap()));
    let kms_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let kms_address = kms_listener.local_addr().unwrap();
    let kms_server = tokio::spawn(async move { axum::serve(kms_listener, kms).await.unwrap() });

    let mock = BureauMock {
        pool: pool.clone(),
        calls: Arc::new(AtomicUsize::new(0)),
        clear_intent_for: Arc::new(Mutex::new(None)),
        reject_single_for: Arc::new(Mutex::new(None)),
        misreport_batch_mapping: Arc::new(AtomicBool::new(false)),
        omit_batch_companion_row: Arc::new(AtomicBool::new(false)),
    };
    let bureau = Router::new()
        .route("/v1/personalization/jobs", post(beta_bureau_submit))
        .with_state(mock.clone());
    let bureau_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bureau_address = bureau_listener.local_addr().unwrap();
    let bureau_server =
        tokio::spawn(async move { axum::serve(bureau_listener, bureau).await.unwrap() });

    let repository = PostgresPassportRepository::new(pool.clone());
    let service_token = "synthetic-internal-service-token-00000001";
    let source = PassportTenantCredentialSource::internal_service_token(service_token).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-organization-id", "org-a".parse().unwrap());
    headers.insert("x-api-key", service_token.parse().unwrap());
    let principal = source
        .authenticate(
            header(&headers, "x-organization-id"),
            header(&headers, "x-api-key"),
        )
        .unwrap();
    let kms_url = url::Url::parse(&format!("http://{kms_address}/internal/signing-keys")).unwrap();
    let client =
        BureauClient::new(&format!("http://{bureau_address}"), "bureau-key", None).unwrap();
    let endpoint_sha256 = client.endpoint_sha256();
    let mut service = PassportHttpService::with_artifact_availability(
        source,
        repository.clone(),
        ArtifactAvailability::Ready(ArtifactCryptor::Kms(
            KmsPassportArtifactCipher::new(kms_url.clone(), "synthetic-kms-key").unwrap(),
        )),
        Some(PassportSigner::Managed(Box::new(
            ManagedProfileSigner::new(kms_url, Some("synthetic-kms-key")).unwrap(),
        ))),
        Some(client),
    );
    service.bureau_provider_profile_id = Some("passport-beta-bureau".into());
    service.beta_reconciliation_enabled = true;
    service.beta_reconciliation_operator_token =
        Some("synthetic-operator-reconciliation-token-00000001".into());
    service.webhook_kms = Some(
        KmsWebhookVerifier::new(
            url::Url::parse(&format!("http://{kms_address}/internal/signing-keys")).unwrap(),
            "synthetic-kms-key",
        )
        .unwrap(),
    );
    let app = router(service.clone());

    let absent = reserved_job(
        &repository,
        &principal,
        "absent",
        &encrypted,
        &signed,
        &endpoint_sha256,
    )
    .await;
    assert_eq!(
        call_reconciler(&app, &absent.application_id).await,
        StatusCode::OK
    );
    assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    let bound = repository
        .get(&principal, &absent.application_id)
        .await
        .unwrap()
        .unwrap();
    assert!(bound.bureau_job_id.is_some());
    assert!(bound.submission_intent_id.is_none());
    let first = repository
        .beta_material_receipt(&principal, &absent.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bound.submitted_at, Some(first.first_accepted_at));
    let callback = json!({
        "organization_id": "org-a",
        "provider_profile_id": "passport-beta-bureau",
        "bureau_job_id": bound.bureau_job_id,
        "status": "PRINTING"
    });
    let callback_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/passport/webhooks/personalization")
                .header("content-type", "application/json")
                .header(
                    "x-personalization-signature",
                    "vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                )
                .body(Body::from(callback.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(callback_response.status(), StatusCode::OK);
    assert_eq!(
        repository
            .get(&principal, &absent.application_id)
            .await
            .unwrap()
            .unwrap()
            .status,
        "IN_PRODUCTION"
    );
    assert_eq!(
        call_reconciler(&app, &absent.application_id).await,
        StatusCode::OK
    );
    assert_eq!(mock.calls.load(Ordering::SeqCst), 1);

    let batch = reserved_job(
        &repository,
        &principal,
        "batch",
        &encrypted,
        &signed,
        &endpoint_sha256,
    )
    .await;
    let (prepared, _, _, _) = prepared_personalization_job(
        &service,
        &batch,
        true,
        Some(
            &serde_json::from_value(batch.submission_intent_signing_provenance.clone().unwrap())
                .unwrap(),
        ),
    )
    .await
    .unwrap();
    let digests = material_digests(
        &prepared.payload(),
        &batch.organization_id,
        &batch.id,
        &batch.country_code,
        Some(&batch.document_type),
    )
    .unwrap();
    let batch_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO issuance_service.passport_beta_bureau_jobs
         (bureau_job_id, organization_id, source_job_id, request_sha256,
          content_sha256, sod_der_sha256, dsc_der_sha256, dsc_pem_wire_sha256,
          document_type, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULL,'QUEUED')",
    )
    .bind(batch_id)
    .bind(&batch.organization_id)
    .bind(&batch.id)
    .bind(&digests.legacy_request_sha256)
    .bind(&digests.content_sha256)
    .bind(&digests.sod_der_sha256)
    .bind(&digests.dsc_der_sha256)
    .bind(&digests.dsc_pem_wire_sha256)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        call_reconciler(&app, &batch.application_id).await,
        StatusCode::OK
    );
    assert_eq!(mock.calls.load(Ordering::SeqCst), 2);
    let batch_bound = repository
        .get(&principal, &batch.application_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        batch_bound.bureau_job_id.as_deref(),
        Some(batch_id.to_string().as_str())
    );

    let mismatch = reserved_job(
        &repository,
        &principal,
        "mismatch",
        &encrypted,
        &signed,
        &endpoint_sha256,
    )
    .await;
    sqlx::query(
        "INSERT INTO issuance_service.passport_beta_bureau_jobs
         (bureau_job_id, organization_id, source_job_id, request_sha256,
          content_sha256, sod_der_sha256, dsc_der_sha256, dsc_pem_wire_sha256,
          document_type, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULL,'QUEUED')",
    )
    .bind(Uuid::new_v4())
    .bind(&mismatch.organization_id)
    .bind(&mismatch.id)
    .bind(vec![1_u8; 32])
    .bind(vec![2_u8; 32])
    .bind(vec![3_u8; 32])
    .bind(vec![4_u8; 32])
    .bind(vec![5_u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        call_reconciler(&app, &mismatch.application_id).await,
        StatusCode::CONFLICT
    );
    assert_eq!(mock.calls.load(Ordering::SeqCst), 2);
    assert!(repository
        .get(&principal, &mismatch.application_id)
        .await
        .unwrap()
        .unwrap()
        .submission_intent_id
        .is_some());

    let raced = reserved_job(
        &repository,
        &principal,
        "raced",
        &encrypted,
        &signed,
        &endpoint_sha256,
    )
    .await;
    *mock.clear_intent_for.lock().unwrap() = Some(raced.id.clone());
    assert_eq!(
        call_reconciler(&app, &raced.application_id).await,
        StatusCode::CONFLICT
    );
    assert_eq!(mock.calls.load(Ordering::SeqCst), 3);
    assert!(repository
        .get(&principal, &raced.application_id)
        .await
        .unwrap()
        .unwrap()
        .bureau_job_id
        .is_none());
    kms_server.abort();
    bureau_server.abort();
}

#[tokio::test]
async fn beta_batch_http_binds_exact_flow_pair_and_replays_after_artifact_scrub() {
    run_beta_batch_http_recovery(false, false, false).await;
}

#[tokio::test]
async fn beta_batch_http_completes_receipts_when_wire_kms_fails() {
    run_beta_batch_http_recovery(true, false, false).await;
}

#[tokio::test]
async fn beta_batch_http_rejects_retained_response_with_wrong_receipt_mapping() {
    run_beta_batch_http_recovery(false, true, false).await;
}

#[tokio::test]
async fn beta_batch_http_never_creates_a_missing_batch_row_through_single_submit() {
    run_beta_batch_http_recovery(false, false, true).await;
}

async fn run_beta_batch_http_recovery(
    fail_wire_kms: bool,
    misreport_batch_mapping: bool,
    omit_batch_companion_row: bool,
) {
    let Ok(database_url) = std::env::var("MARTY_PASSPORT_RECONCILIATION_TEST_URL") else {
        return;
    };
    let _database_guard = RECONCILIATION_DATABASE_LOCK.lock().await;
    assert_eq!(
        url::Url::parse(&database_url)
            .unwrap()
            .path()
            .trim_start_matches('/'),
        "marty_passport_reconciliation_test"
    );
    let pool = PgPoolOptions::new().connect(&database_url).await.unwrap();
    sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DROP SCHEMA IF EXISTS flow_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    migration::migrate_passport(&pool).await.unwrap();
    sqlx::raw_sql(include_str!("bin/passport_beta_bureau_schema.sql"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("../../flow/migrations/0001_flow_schema.sql"))
        .execute(&pool)
        .await
        .unwrap();

    let signed = signed_material();
    let artifact = PassportSensitiveArtifact {
        applicant: json!({"synthetic": "person"}),
        mrz: std::collections::BTreeMap::from([
            ("line_1".into(), "P<TEST".into()),
            ("line_2".into(), "PERSON".into()),
        ]),
        data_groups: std::collections::BTreeMap::from([
            ("DG1".into(), STANDARD.encode([1])),
            ("DG2".into(), STANDARD.encode([2])),
        ]),
        signed_material: Some(signed.clone()),
    };
    let encrypted = json!({
        "schema": "marty.passport-artifact-manifest/v1",
        "chunks": ["vault:v1:synthetic"]
    })
    .to_string();
    let dsc = STANDARD.encode(load_certificate_pem(&signed.dsc_cert_pem).unwrap());
    let csca =
        STANDARD.encode(load_certificate_pem(signed.csca_cert_pem.as_ref().unwrap()).unwrap());
    let resolve = {
        let dsc = dsc.clone();
        let csca = csca.clone();
        move || {
            let dsc = dsc.clone();
            let csca = csca.clone();
            async move {
                Json(json!({
                    "ok": true,
                    "organization_id": "org-a",
                    "issuer_did": "did:web:issuer.example:orgs:org-a",
                    "issuer_profile_id": "issuer-profile-test",
                    "issuer_profile": {"id": "issuer-profile-test", "credential_format": "ICAO_EMRTD"},
                    "key_purpose": "x509_doc_signer",
                    "algorithm": "ES256",
                    "verification_method_id": "did:web:issuer.example:orgs:org-a#dsc",
                    "issuer_x5c": [dsc, csca]
                }))
            }
        }
    };
    let trust = {
        let csca_pem = signed.csca_cert_pem.clone().unwrap();
        move || {
            let csca_pem = csca_pem.clone();
            async move {
                Json(json!([{
                    "certificate_id": "test-csca",
                    "certificate_data": csca_pem,
                    "status": "VALID"
                }]))
            }
        }
    };
    let wire_capture: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let wire_kms_failure = Arc::new(AtomicBool::new(fail_wire_kms));
    let kms = Router::new()
        .route(
            "/internal/signing-keys/passport-artifacts/decrypt",
            post(kms_decrypt_batch_wire_or_artifact),
        )
        .route(
            "/internal/signing-keys/passport-artifacts/encrypt",
            post(kms_encrypt_batch_wire),
        )
        .route(
            "/internal/signing-keys/resolve-issuer-did",
            axum::routing::get(resolve),
        )
        .route(
            "/internal/signing-keys/csca-trust-anchors",
            axum::routing::get(trust),
        )
        .with_state(Arc::new(serde_json::to_vec(&artifact).unwrap()))
        .layer(axum::Extension(wire_capture.clone()))
        .layer(axum::Extension(wire_kms_failure));
    let kms_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let kms_address = kms_listener.local_addr().unwrap();
    let kms_server = tokio::spawn(async move { axum::serve(kms_listener, kms).await.unwrap() });

    let mock = BureauMock {
        pool: pool.clone(),
        calls: Arc::new(AtomicUsize::new(0)),
        clear_intent_for: Arc::new(Mutex::new(None)),
        reject_single_for: Arc::new(Mutex::new(None)),
        misreport_batch_mapping: Arc::new(AtomicBool::new(misreport_batch_mapping)),
        omit_batch_companion_row: Arc::new(AtomicBool::new(omit_batch_companion_row)),
    };
    let bureau = Router::new()
        .route(
            "/v1/personalization/batches",
            post(beta_bureau_batch_submit),
        )
        .route("/v1/personalization/jobs", post(beta_bureau_submit))
        .with_state(mock.clone());
    let bureau_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bureau_address = bureau_listener.local_addr().unwrap();
    let bureau_server =
        tokio::spawn(async move { axum::serve(bureau_listener, bureau).await.unwrap() });

    let service_token = "synthetic-internal-service-token-00000001";
    let source = PassportTenantCredentialSource::internal_service_token(service_token).unwrap();
    let principal = source
        .authenticate(Some("org-a"), Some(service_token))
        .unwrap();
    let repository = PostgresPassportRepository::new(pool.clone());
    let mut jobs = Vec::new();
    for suffix in ["selected", "companion"] {
        let insert = PassportJobInsert {
            id: format!("batch-http-job-{suffix}"),
            application_id: format!("batch-http-application-{suffix}"),
            flow_execution_id: if suffix == "selected" {
                "batch-http-flow".into()
            } else {
                "companion-flow".into()
            },
            application_template_id: "template".into(),
            credential_template_id: "credential".into(),
            revocation_profile_id: None,
            delivery_destination_profile_id: "destination".into(),
            document_type: "TD3".into(),
            country_code: "USA".into(),
            issuer_did: Some("did:web:issuer.example:orgs:org-a".into()),
            secure_artifact_ciphertext: encrypted.clone(),
            secure_artifact_reference: format!("physical-artifact://batch-http-job-{suffix}"),
        };
        let draft = repository
            .insert(&principal, &insert, Utc::now())
            .await
            .unwrap();
        let mut patch = PassportJobPatch::new(PassportJobStatus::SodSigned);
        patch.sod_sha256 = Some(Some(signed_sod_sha256(&signed).unwrap()));
        jobs.push(
            repository
                .update(
                    &principal,
                    &draft.application_id,
                    &draft.status,
                    &patch,
                    Utc::now(),
                )
                .await
                .unwrap()
                .unwrap(),
        );
    }
    let steps = [
        "accept_application",
        "validate_evidence",
        "approval_decision",
        "generate_data_groups",
        "sign_sod",
        "submit_to_personalization",
        "track_production",
        "quality_verify",
        "activate_credential",
    ];
    let steps = steps
        .iter()
        .map(|name| json!({"id": name, "config": {"protocol_step": name}}))
        .collect::<Vec<_>>();
    sqlx::query(
        "INSERT INTO flow_service.flow_definitions
         (id, organization_id, name, status, flow_type, steps,
          credential_template_id, application_template_id, delivery_destination_profile_id)
         VALUES ('batch-http-definition','org-a','Batch HTTP','ACTIVE',
                 'physical_document_issuance',$1,'credential','template','destination')",
    )
    .bind(json!(steps))
    .execute(&pool)
    .await
    .unwrap();
    let context = json!({
        "application_id": jobs[0].application_id,
        "physical_document_job": {
            "id": jobs[0].id,
            "organization_id": "org-a",
            "flow_execution_id": jobs[0].flow_execution_id,
            "application_id": jobs[0].application_id,
            "issuer_did": jobs[0].issuer_did,
            "sod_sha256": jobs[0].sod_sha256,
            "sod_signature_verified": true,
            "status": "SOD_SIGNED"
        },
        "step_results": {"sign_sod": {"result": "success", "completed_at": Utc::now().to_rfc3339()}}
    });
    let history = json!([
        {"step_id": "sign_sod", "status": "entered", "result": "success", "completed_at": Utc::now().to_rfc3339()},
        {"step_id": "submit_to_personalization", "status": "entered", "entered_at": Utc::now().to_rfc3339()}
    ]);
    sqlx::query(
        "INSERT INTO flow_service.flow_instances
         (id, flow_definition_id, organization_id, status, current_step_id, context, step_history)
         VALUES ('batch-http-flow','batch-http-definition','org-a','in_progress',
                 'submit_to_personalization',$1,$2)",
    )
    .bind(context)
    .bind(history)
    .execute(&pool)
    .await
    .unwrap();

    let kms_url = url::Url::parse(&format!("http://{kms_address}/internal/signing-keys")).unwrap();
    let mut service = PassportHttpService::with_artifact_availability(
        source,
        repository.clone(),
        ArtifactAvailability::Ready(ArtifactCryptor::Kms(
            KmsPassportArtifactCipher::new(kms_url.clone(), "synthetic-kms-key").unwrap(),
        )),
        Some(PassportSigner::Managed(Box::new(
            ManagedProfileSigner::new(kms_url, Some("synthetic-kms-key")).unwrap(),
        ))),
        Some(BureauClient::new(&format!("http://{bureau_address}"), "bureau-key", None).unwrap()),
    );
    service.bureau_provider_profile_id = Some("passport-beta-bureau".into());
    service.beta_reconciliation_enabled = true;
    service.beta_reconciliation_operator_token =
        Some("synthetic-operator-reconciliation-token-00000001".into());
    let app = router(service);
    for (key, operator, expected) in [
        (service_token, "wrong-operator", StatusCode::UNAUTHORIZED),
        (
            "wrong-service-token",
            "synthetic-operator-reconciliation-token-00000001",
            StatusCode::UNAUTHORIZED,
        ),
        (
            service_token,
            "synthetic-operator-reconciliation-token-00000001",
            StatusCode::OK,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/internal/passport/beta-batches/preflight")
                    .header("x-organization-id", "org-a")
                    .header("x-api-key", key)
                    .header("x-passport-reconciliation-token", operator)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert_eq!(mock.calls.load(Ordering::SeqCst), 0);
    let batch_id = Uuid::new_v4();
    let body = json!({
        "selected_flow_instance_id": "batch-http-flow",
        "selected_application_id": jobs[0].application_id,
        "companion_application_id": jobs[1].application_id
    });
    let wire_key = STANDARD.encode([0x5au8; 32]);
    let invalid_key = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/internal/passport/beta-batches/{batch_id}/submit"))
                .header("content-type", "application/json")
                .header("x-organization-id", "org-a")
                .header("x-api-key", service_token)
                .header(
                    "x-passport-reconciliation-token",
                    "synthetic-operator-reconciliation-token-00000001",
                )
                .header("x-passport-batch-wire-key", "invalid")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_key.status(), StatusCode::CONFLICT);
    assert_eq!(mock.calls.load(Ordering::SeqCst), 0);
    let call = |app: &Router| {
        app.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/internal/passport/beta-batches/{batch_id}/submit"))
                .header("content-type", "application/json")
                .header("x-organization-id", "org-a")
                .header("x-api-key", service_token)
                .header(
                    "x-passport-reconciliation-token",
                    "synthetic-operator-reconciliation-token-00000001",
                )
                .header("x-passport-batch-wire-key", wire_key.as_str())
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
    };
    *mock.reject_single_for.lock().unwrap() = Some(jobs[0].id.clone());
    let first = call(&app).await.unwrap();
    assert_eq!(first.status(), StatusCode::CONFLICT);
    assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    let pending = repository
        .beta_batch_jobs(&principal, batch_id)
        .await
        .unwrap()
        .unwrap();
    assert!(pending.iter().all(|job| job.submission_intent_id.is_some()));
    assert!(pending.iter().all(|job| job.bureau_job_id.is_none()));
    assert!(repository
        .beta_material_receipt(&principal, &pending[0].id)
        .await
        .unwrap()
        .unwrap()
        .document_type
        .is_none());
    if omit_batch_companion_row {
        assert!(repository
            .beta_material_receipt(&principal, &pending[1].id)
            .await
            .unwrap()
            .is_none());
        sqlx::query(
            "UPDATE issuance_service.passport_beta_batch_intents
             SET last_send_started_at=$2 WHERE batch_id=$1",
        )
        .bind(batch_id)
        .bind(Utc::now() - ChronoDuration::seconds(131))
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(call(&app).await.unwrap().status(), StatusCode::CONFLICT);
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
        assert!(repository
            .beta_material_receipt(&principal, &pending[1].id)
            .await
            .unwrap()
            .is_none());
        assert!(repository
            .beta_batch_jobs(&principal, batch_id)
            .await
            .unwrap()
            .unwrap()
            .iter()
            .all(|job| job.bureau_job_id.is_none() && job.submission_intent_id.is_some()));
        kms_server.abort();
        bureau_server.abort();
        return;
    }
    if misreport_batch_mapping {
        let retained = wire_capture.lock().unwrap().clone().unwrap();
        let request_len = u32::from_be_bytes(retained[4..8].try_into().unwrap()) as usize;
        let reported: Value = serde_json::from_slice(&retained[8 + request_len..]).unwrap();
        let actual = repository
            .beta_material_receipt(&principal, &pending[0].id)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            reported["jobs"][0]["bureau_job_id"],
            actual.bureau_job_id.to_string()
        );
        sqlx::query(
            "UPDATE issuance_service.passport_beta_batch_intents
             SET last_send_started_at=$2 WHERE batch_id=$1",
        )
        .bind(batch_id)
        .bind(Utc::now() - ChronoDuration::seconds(131))
        .execute(&pool)
        .await
        .unwrap();
        let retry = call(&app).await.unwrap();
        assert_eq!(retry.status(), StatusCode::CONFLICT);
        assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
        let pending = repository
            .beta_batch_jobs(&principal, batch_id)
            .await
            .unwrap()
            .unwrap();
        assert!(pending.iter().all(|job| job.bureau_job_id.is_none()));
        assert!(pending.iter().all(|job| job.submission_intent_id.is_some()));
        kms_server.abort();
        bureau_server.abort();
        return;
    }
    sqlx::query(
        "UPDATE issuance_service.passport_beta_bureau_jobs
         SET document_type='TD1' WHERE organization_id='org-a' AND source_job_id=$1",
    )
    .bind(&pending[1].id)
    .execute(&pool)
    .await
    .unwrap();
    *mock.reject_single_for.lock().unwrap() = None;
    let incompatible_type = call(&app).await.unwrap();
    assert_eq!(incompatible_type.status(), StatusCode::CONFLICT);
    assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    sqlx::query(
        "UPDATE issuance_service.passport_beta_bureau_jobs
         SET document_type='TD3' WHERE organization_id='org-a' AND source_job_id=$1",
    )
    .bind(&pending[1].id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE flow_service.flow_instances SET status='cancelled' WHERE id='batch-http-flow'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let cancelled = call(&app).await.unwrap();
    assert_eq!(cancelled.status(), StatusCode::CONFLICT);
    assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    sqlx::query(
        "UPDATE flow_service.flow_instances SET status='in_progress' WHERE id='batch-http-flow'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let early_retry = call(&app).await.unwrap();
    assert_eq!(early_retry.status(), StatusCode::CONFLICT);
    assert_eq!(mock.calls.load(Ordering::SeqCst), 1);
    sqlx::query(
        "UPDATE issuance_service.passport_beta_batch_intents
         SET last_send_started_at=$2 WHERE batch_id=$1",
    )
    .bind(batch_id)
    .bind(Utc::now() - ChronoDuration::seconds(131))
    .execute(&pool)
    .await
    .unwrap();
    if fail_wire_kms {
        sqlx::query(
            "UPDATE issuance_service.passport_beta_batch_intents
             SET first_dispatch_response_seen_at=$2 WHERE batch_id=$1",
        )
        .bind(batch_id)
        .bind(Utc::now() - ChronoDuration::seconds(66))
        .execute(&pool)
        .await
        .unwrap();
    }
    let recovered = call(&app).await.unwrap();
    assert_eq!(recovered.status(), StatusCode::OK);
    assert_eq!(mock.calls.load(Ordering::SeqCst), 2);
    let recovered_body = axum::body::to_bytes(recovered.into_body(), 64 * 1024)
        .await
        .unwrap();
    let recovered_body: Value = serde_json::from_slice(&recovered_body).unwrap();
    let stored_wire: Option<String> = sqlx::query_scalar(
        "SELECT first_dispatch_wire_ciphertext
         FROM issuance_service.passport_beta_batch_intents WHERE batch_id=$1",
    )
    .bind(batch_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    if fail_wire_kms {
        assert!(wire_capture.lock().unwrap().is_none());
        assert!(stored_wire.is_none());
        assert_eq!(recovered_body["wire_evidence_status"], "unavailable");
        assert!(recovered_body.get("wire_commitments").is_none());
    } else {
        let retained_wire = wire_capture.lock().unwrap().clone().unwrap();
        assert_eq!(&retained_wire[..4], b"PBW1");
        let request_len = u32::from_be_bytes(retained_wire[4..8].try_into().unwrap()) as usize;
        let request_bytes = &retained_wire[8..8 + request_len];
        let response_bytes = &retained_wire[8 + request_len..];
        let sent: Value = serde_json::from_slice(request_bytes).unwrap();
        assert_eq!(sent["jobs"][0]["job_id"], jobs[0].id);
        assert_eq!(sent["jobs"][1]["job_id"], jobs[1].id);
        assert!(sent["jobs"][0].get("document_type").is_none());
        let accepted: Value = serde_json::from_slice(response_bytes).unwrap();
        assert_eq!(accepted["status"], "QUEUED");
        let key = STANDARD.decode(&wire_key).unwrap();
        for (field, bytes) in [("request", request_bytes), ("response", response_bytes)] {
            let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
            mac.update(format!("passport-retirement/v2:{field}\0").as_bytes());
            mac.update(bytes);
            assert_eq!(
                recovered_body["wire_commitments"][format!("{field}_commitment")],
                hex::encode(mac.finalize().into_bytes())
            );
        }
        assert_eq!(recovered_body["wire_evidence_status"], "verified");
        let stored_wire = stored_wire.unwrap();
        assert!(stored_wire.contains("marty.passport-artifact-manifest/v1"));
        assert!(!stored_wire.contains(&jobs[0].id));
    }
    let bound = repository
        .beta_batch_jobs(&principal, batch_id)
        .await
        .unwrap()
        .unwrap();
    assert!(bound.iter().all(|job| job.bureau_job_id.is_some()));
    assert!(bound.iter().all(|job| job.submission_intent_id.is_none()));
    for job in &bound {
        let receipt = repository
            .beta_material_receipt(&principal, &job.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            job.bureau_job_id.as_deref(),
            Some(receipt.bureau_job_id.to_string().as_str())
        );
        assert_eq!(receipt.document_type.as_deref(), Some("TD3"));
        assert_eq!(job.submitted_at, Some(receipt.first_accepted_at));
    }
    // Simulate a mixed durable state after the selected job has progressed
    // and its encrypted artifact is no longer readable. Only the companion
    // may be rebound, using its existing first-accepted batch receipt.
    sqlx::query(
        "UPDATE issuance_service.physical_document_jobs
         SET secure_artifact_ciphertext='scrubbed-bound-selected'
         WHERE id=$1",
    )
    .bind(&bound[0].id)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE issuance_service.physical_document_jobs
         SET status='SOD_SIGNED', bureau_job_id=NULL, bureau_provider_profile_id=NULL,
             submission_intent_id=$2, submission_intent_started_at=$3,
             submission_intent_provider_profile_id='passport-beta-bureau',
             submission_intent_bureau_endpoint_sha256=submission_batch_bureau_endpoint_sha256,
             submission_intent_signing_provenance=submission_batch_signing_provenance,
             submission_batch_signing_provenance=NULL,
             submission_batch_bureau_endpoint_sha256=NULL,
             submission_batch_material_digests=NULL, submitted_at=NULL
         WHERE id=$1",
    )
    .bind(&bound[1].id)
    .bind(Uuid::new_v4())
    .bind(Utc::now())
    .execute(&pool)
    .await
    .unwrap();
    let mixed = call(&app).await.unwrap();
    assert_eq!(mixed.status(), StatusCode::OK);
    assert_eq!(mock.calls.load(Ordering::SeqCst), 2);
    let rebound = repository
        .beta_batch_jobs(&principal, batch_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rebound[0].bureau_job_id, bound[0].bureau_job_id);
    assert_eq!(rebound[1].bureau_job_id, bound[1].bureau_job_id);
    assert!(rebound.iter().all(|job| job.submission_intent_id.is_none()));
    let replay = call(&app).await.unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(mock.calls.load(Ordering::SeqCst), 2);
    for job in &bound {
        let mut patch = PassportJobPatch::new(PassportJobStatus::Active);
        patch.secure_artifact_ciphertext = Some("scrubbed-after-activation".into());
        repository
            .update(
                &principal,
                &job.application_id,
                &job.status,
                &patch,
                Utc::now(),
            )
            .await
            .unwrap()
            .unwrap();
    }
    let after_scrub = call(&app).await.unwrap();
    assert_eq!(after_scrub.status(), StatusCode::OK);
    assert_eq!(mock.calls.load(Ordering::SeqCst), 2);
    kms_server.abort();
    bureau_server.abort();
}
