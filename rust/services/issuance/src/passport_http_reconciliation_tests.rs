use std::sync::{
    atomic::{AtomicUsize, Ordering},
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

#[derive(Clone)]
struct BureauMock {
    pool: PgPool,
    calls: Arc<AtomicUsize>,
    clear_intent_for: Arc<Mutex<Option<String>>>,
}

async fn beta_bureau_submit(
    State(mock): State<BureauMock>,
    Json(payload): Json<Value>,
) -> (StatusCode, Json<Value>) {
    mock.calls.fetch_add(1, Ordering::SeqCst);
    let organization = payload["organization_id"].as_str().unwrap();
    let source = payload["job_id"].as_str().unwrap();
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

async fn kms_decrypt(
    State(artifact): State<Arc<Vec<u8>>>,
    Json(_request): Json<Value>,
) -> Json<Value> {
    Json(json!({"plaintext_b64": STANDARD.encode(artifact.as_slice())}))
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
