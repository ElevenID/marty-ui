use std::sync::{Arc, Mutex};

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Request, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chrono::{TimeZone, Utc};
use hmac::{Hmac, Mac};
use marty_issuance_service::migration;
use marty_issuance_service::passport_artifact::{
    PassportArtifactCipher, PassportSensitiveArtifact,
};
use marty_issuance_service::passport_bureau::BureauClient;
use marty_issuance_service::passport_http::{router as passport_router, PassportHttpService};
use marty_issuance_service::passport_repository::{
    PassportJobInsert, PassportJobPatch, PassportJobStatus, PassportWebhookRepositoryError,
    PostgresPassportRepository,
};
#[cfg(feature = "passport-self-signed-test")]
use marty_issuance_service::passport_signer::PassportSigner;
use marty_issuance_service::passport_signer::RemoteSigner;
use marty_passport_auth::PassportTenantKeyring;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

#[cfg(feature = "passport-self-signed-test")]
#[path = "support/issuance_process.rs"]
mod issuance_process;

#[cfg(feature = "passport-self-signed-test")]
async fn exercise_packaged_self_signed_test_mode(database_url: &str, key_a: &str) {
    use std::time::Duration;

    use issuance_process::{
        bounded_http_client, isolated_smoke_command, reserve_port, wait_for_health_with_client,
        ChildGuard,
    };

    assert!(
        url::Url::parse(database_url)
            .unwrap()
            .path()
            .trim_start_matches('/')
            .ends_with("_test"),
        "packaged passport test mode requires a dedicated *_test database"
    );
    let (http_reservation, http_port) = reserve_port();
    let (_grpc_reservation, grpc_port) = reserve_port();
    let mut command = isolated_smoke_command(http_port, grpc_port);
    command
        .env("DATABASE_URL", database_url)
        .env("ISSUANCE_API_KEY", key_a)
        .env("PASSPORT_NATIVE_HTTP_ENABLED", "true")
        .env("PHYSICAL_DOCUMENT_ALLOW_SELF_SIGNED", "true")
        .env(
            "PASSPORT_TENANT_API_KEYS",
            format!("{{\"org-a\":\"{key_a}\"}}"),
        )
        .env(
            "PHYSICAL_DOCUMENT_ARTIFACT_KEY",
            fernet::Fernet::generate_key(),
        )
        .env("PERSONALIZATION_BUREAU_URL", "http://127.0.0.1:1")
        .env("RUST_LOG", "info")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    drop(http_reservation);
    let child = ChildGuard(
        command
            .spawn()
            .expect("start packaged passport test-mode service"),
    );
    let client = bounded_http_client(Duration::from_secs(5));
    assert_eq!(
        tokio::time::timeout(
            Duration::from_secs(10),
            wait_for_health_with_client(http_port, &client)
        )
        .await
        .expect("packaged passport readiness deadline"),
        Some(json!({"status":"healthy", "service":"issuance-service"}))
    );
    let base = format!("http://127.0.0.1:{http_port}");
    let capabilities = client
        .get(format!("{base}/v1/passport/capabilities"))
        .send()
        .await
        .unwrap();
    assert_eq!(capabilities.status(), StatusCode::OK);
    let capabilities: Value = capabilities.json().await.unwrap();
    assert_eq!(capabilities["supported"], true);
    assert_eq!(capabilities["signer"]["mode"], "SELF_SIGNED_TEST");

    let created = client
        .post(format!("{base}/v1/passport/applications"))
        .header("x-organization-id", "org-a")
        .header("x-api-key", key_a)
        .json(&json!({
            "organization_id":"org-a", "flow_execution_id":"flow-packaged-test",
            "application_template_id":"template-packaged-test",
            "credential_template_id":"credential-packaged-test",
            "delivery_destination_profile_id":"destination-packaged-test",
            "country_code":"USA", "applicant":{"name":"Synthetic Packaged Test"},
            "mrz":{"line_1":"P<TEST", "line_2":"SYNTHETIC"},
            "data_groups":{"DG1":"YQ==", "DG2":"Yg=="}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: Value = created.json().await.unwrap();
    assert!(!created.to_string().contains("Synthetic Packaged Test"));
    let application_id = created["application_id"].as_str().unwrap();
    let signed = client
        .post(format!(
            "{base}/v1/passport/applications/{application_id}/generate-sod"
        ))
        .header("x-organization-id", "org-a")
        .header("x-api-key", key_a)
        .send()
        .await
        .unwrap();
    assert_eq!(signed.status(), StatusCode::OK);
    let signed: Value = signed.json().await.unwrap();
    assert_eq!(signed["status"], "SOD_SIGNED");
    assert_eq!(signed["sod_sha256"].as_str().unwrap().len(), 64);
    drop(child);
    let pool = PgPoolOptions::new().connect(database_url).await.unwrap();
    migration::migrate_passport(&pool).await.unwrap();
    let persisted: String = sqlx::query_scalar(
        "SELECT status FROM issuance_service.physical_document_jobs WHERE application_id=$1",
    )
    .bind(application_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(persisted, "SOD_SIGNED");
}

async fn passport_http_request(
    app: &Router,
    method: &str,
    path: &str,
    organization: Option<&str>,
    key: Option<&str>,
    body: Value,
    signature: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(organization) = organization {
        request = request.header("x-organization-id", organization);
    }
    if let Some(key) = key {
        request = request.header("x-api-key", key);
    }
    if let Some(signature) = signature {
        request = request.header("x-personalization-signature", signature);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn exercise_native_passport_http(
    repository: PostgresPassportRepository,
    keyring: PassportTenantKeyring,
    cipher: PassportArtifactCipher,
    key_a: &str,
    key_b: &str,
) {
    async fn sign(Json(body): Json<Value>) -> Json<Value> {
        assert_eq!(body["country_code"], "USA");
        assert_eq!(body["organization"], "org-a");
        assert_eq!(body["data_groups"], json!({"DG1":"YQ==","DG2":"Yg=="}));
        Json(json!({"sod_der_base64":"U09E", "dsc_cert_pem":"synthetic-cert"}))
    }
    async fn submit(
        State(observed): State<Arc<Mutex<Vec<Value>>>>,
        Json(body): Json<Value>,
    ) -> (StatusCode, Json<Value>) {
        observed.lock().unwrap().push(body);
        (
            StatusCode::ACCEPTED,
            Json(json!({"bureau_job_id":"bureau-http", "status":"QUEUED"})),
        )
    }
    async fn poll() -> Json<Value> {
        Json(json!({"status":"SHIPPED", "tracking_number":"tracking-http"}))
    }
    let observed = Arc::new(Mutex::new(Vec::new()));
    let mock = Router::new()
        .route("/v1/icao/emrtd/sign", post(sign))
        .route("/v1/personalization/jobs", post(submit))
        .route("/v1/personalization/jobs/{job_id}", get(poll))
        .with_state(observed.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
    let secret = "synthetic-bureau-webhook-secret";
    let app = passport_router(PassportHttpService::new(
        keyring.clone(),
        repository.clone(),
        Some(cipher.clone()),
        Some(RemoteSigner::new(&base_url, "signer-key").unwrap().into()),
        Some(BureauClient::new(&base_url, "bureau-key", Some(secret)).unwrap()),
    ));
    let payload = json!({
        "organization_id":"org-a", "flow_execution_id":"flow-http",
        "application_template_id":"template-http", "credential_template_id":"credential-http",
        "delivery_destination_profile_id":"destination-http", "document_type":"TD1",
        "country_code":"USA", "applicant":{"name":"Synthetic Sensitive"},
        "mrz":{"line_1":"P<TEST", "line_2":"SYNTHETIC"},
        "data_groups":{"DG1":"YQ==", "DG2":"Yg=="}
    });
    let (status, _) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/applications",
        None,
        Some(key_a),
        payload.clone(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/applications",
        Some("org-b"),
        Some(key_b),
        payload.clone(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, created) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/applications",
        Some("org-a"),
        Some(key_a),
        payload,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["status"], "DRAFT");
    assert_eq!(created["document_type"], "TD1");
    assert!(!created.to_string().contains("Synthetic Sensitive"));
    let application_id = created["application_id"].as_str().unwrap();
    let job = repository
        .get(
            &keyring.authenticate(Some("org-a"), Some(key_a)).unwrap(),
            application_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(!job
        .secure_artifact_ciphertext
        .contains("Synthetic Sensitive"));
    let path = format!("/v1/passport/applications/{application_id}");
    let (status, _) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/generate-data-groups"),
        Some("org-b"),
        Some(key_b),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, generated) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/generate-data-groups"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(generated["status"], "DATA_GENERATED");
    let (status, signed) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/generate-sod"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(signed["status"], "SOD_SIGNED");
    assert_eq!(
        signed["sod_sha256"],
        hex::encode(sha2::Sha256::digest(b"SOD"))
    );
    let (status, submitted) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/submit-personalization"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(submitted["status"], "SUBMITTED");
    assert_eq!(observed.lock().unwrap()[0]["document_type"], "TD1");
    let (status, _) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/quality-verify"),
        Some("org-a"),
        Some(key_a),
        json!({"passed":true}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, polled) = passport_http_request(
        &app,
        "GET",
        &format!("{path}/production-status"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(polled["status"], "READY_FOR_ACTIVATION");
    let webhook = json!({"bureau_job_id":"bureau-http", "status":"SHIPPED", "tracking_number":"webhook-tracking"});
    let (status, _) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/webhooks/personalization",
        None,
        None,
        webhook.clone(),
        Some("invalid"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(webhook.to_string().as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());
    let (status, accepted) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/webhooks/personalization",
        None,
        None,
        webhook,
        Some(&signature),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(accepted, json!({"accepted":true}));
    let (status, quality) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/quality-verify"),
        Some("org-a"),
        Some(key_a),
        json!({"passed":true,"failure_codes":[]}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(quality["status"], "READY_FOR_ACTIVATION");
    let (status, active) = passport_http_request(
        &app,
        "POST",
        &format!("{path}/activate"),
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(active["status"], "ACTIVE");
    let job = repository
        .get(
            &keyring.authenticate(Some("org-a"), Some(key_a)).unwrap(),
            application_id,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(cipher.decrypt(&job.secure_artifact_ciphertext).is_err());
    let frozen: Value = serde_json::from_str(include_str!(
        "../../../../contracts/issuance-physical-passport-native.json"
    ))
    .unwrap();
    let wide_name = frozen["wide_data_group_number_observation"]["input_name"]
        .as_str()
        .unwrap();
    let mut wide_payload = json!({
        "organization_id":"org-a", "flow_execution_id":"wide-data-group-test",
        "application_template_id":"template-test", "credential_template_id":"credential-test",
        "delivery_destination_profile_id":"destination-test", "country_code":"USA",
        "applicant":{}, "mrz":{}, "data_groups":{"DG1":"YQ==", "DG2":"Yg=="}
    });
    wide_payload["data_groups"][wide_name] = json!("Yw==");
    let (status, wide_created) = passport_http_request(
        &app,
        "POST",
        "/v1/passport/applications",
        Some("org-a"),
        Some(key_a),
        wide_payload,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let wide_path = format!(
        "/v1/passport/applications/{}/generate-data-groups",
        wide_created["application_id"].as_str().unwrap()
    );
    let (status, wide_generated) = passport_http_request(
        &app,
        "POST",
        &wide_path,
        Some("org-a"),
        Some(key_a),
        json!({}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(wide_generated["status"], "DATA_GENERATED");
    #[cfg(feature = "passport-self-signed-test")]
    {
        let local = passport_router(PassportHttpService::new(
            keyring,
            repository,
            Some(cipher),
            Some(PassportSigner::SelfSignedTest),
            None,
        ));
        let (status, created) = passport_http_request(
            &local,
            "POST",
            "/v1/passport/applications",
            Some("org-a"),
            Some(key_a),
            json!({
                "organization_id":"org-a", "flow_execution_id":"self-signed-test",
                "application_template_id":"template-test", "credential_template_id":"credential-test",
                "delivery_destination_profile_id":"destination-test", "country_code":"UTO",
                "applicant":{}, "mrz":{}, "data_groups":{"DG1":"YQ==", "DG2":"Yg=="}
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let application_id = created["application_id"].as_str().unwrap();
        let (status, signed) = passport_http_request(
            &local,
            "POST",
            &format!("/v1/passport/applications/{application_id}/generate-sod"),
            Some("org-a"),
            Some(key_a),
            json!({}),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(signed["status"], "SOD_SIGNED");
        assert_eq!(signed["sod_sha256"].as_str().unwrap().len(), 64);
    }
    server.abort();
}

#[tokio::test]
async fn passport_jobs_survive_restart_without_cross_tenant_reads() {
    let Ok(database_url) = std::env::var("MARTY_PASSPORT_POSTGRES_TEST_URL") else {
        return;
    };
    let database_name = url::Url::parse(&database_url)
        .expect("passport contract URL must parse")
        .path()
        .trim_start_matches('/')
        .to_owned();
    assert_eq!(
        database_name, "marty_passport_contract_test",
        "passport contract requires its dedicated disposable database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("passport contract database must connect");
    sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    migration::migrate_passport(&pool).await.unwrap();
    migration::migrate_passport(&pool).await.unwrap(); // startup is idempotent

    let key_a = "a".repeat(32);
    let key_b = "b".repeat(32);
    let keyring = PassportTenantKeyring::from_json(&format!(
        "{{\"org-a\":\"{key_a}\",\"org-b\":\"{key_b}\"}}"
    ))
    .unwrap();
    let org_a = keyring.authenticate(Some("org-a"), Some(&key_a)).unwrap();
    let org_b = keyring.authenticate(Some("org-b"), Some(&key_b)).unwrap();
    let repository = PostgresPassportRepository::new(pool.clone());
    let now = Utc
        .with_ymd_and_hms(2026, 9, 24, 12, 0, 0)
        .single()
        .unwrap();
    let cipher = PassportArtifactCipher::from_key(&fernet::Fernet::generate_key()).unwrap();
    let artifact: PassportSensitiveArtifact = serde_json::from_value(serde_json::json!({
        "applicant": {"synthetic": "test-person"},
        "mrz": {"line_1": "P<TEST", "line_2": "SYNTHETIC"},
        "data_groups": {"DG1": "UkR4", "DG2": "UkR5"}
    }))
    .unwrap();
    let encrypted_artifact = cipher.encrypt(&artifact).unwrap();
    let job = PassportJobInsert {
        id: "job-a".into(),
        application_id: "application-a".into(),
        flow_execution_id: "flow-a".into(),
        application_template_id: "template-a".into(),
        credential_template_id: "credential-a".into(),
        revocation_profile_id: Some("revocation-a".into()),
        delivery_destination_profile_id: "destination-a".into(),
        document_type: "TD2".into(),
        country_code: "USA".into(),
        secure_artifact_ciphertext: encrypted_artifact.clone(),
        secure_artifact_reference: "physical-artifact://job-a".into(),
    };
    let inserted = repository.insert(&org_a, &job, now).await.unwrap();
    assert_eq!(inserted.organization_id, "org-a");
    assert_eq!(inserted.status, "DRAFT");
    assert_eq!(inserted.document_type, "TD2");
    assert!(!inserted.secure_artifact_ciphertext.contains("test-person"));
    assert_eq!(
        inserted.revocation_profile_id.as_deref(),
        Some("revocation-a")
    );
    assert!(repository
        .get(&org_b, "application-a")
        .await
        .unwrap()
        .is_none());

    pool.close().await;
    let restarted_pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .unwrap();
    let restarted = PostgresPassportRepository::new(restarted_pool.clone());
    let recovered = restarted
        .get(&org_a, "application-a")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.secure_artifact_ciphertext, encrypted_artifact);
    assert_eq!(
        cipher
            .decrypt(&recovered.secure_artifact_ciphertext)
            .unwrap()
            .mrz,
        artifact.mrz
    );
    assert_eq!(recovered.created_at, now);
    assert!(restarted
        .get(&org_b, "application-a")
        .await
        .unwrap()
        .is_none());

    let next = now + chrono::Duration::minutes(1);
    let patch = PassportJobPatch::new(PassportJobStatus::DataGenerated);
    assert!(restarted
        .update(&org_b, "application-a", "DRAFT", &patch, next)
        .await
        .unwrap()
        .is_none());
    assert!(restarted
        .update(&org_a, "application-a", "SOD_SIGNED", &patch, next)
        .await
        .unwrap()
        .is_none());
    let generated = restarted
        .update(&org_a, "application-a", "DRAFT", &patch, next)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(generated.status, "DATA_GENERATED");
    assert_eq!(generated.updated_at, next);
    assert!(restarted
        .update(&org_a, "application-a", "DRAFT", &patch, next)
        .await
        .unwrap()
        .is_none());

    let mut signed = PassportJobPatch::new(PassportJobStatus::SodSigned);
    signed.sod_sha256 = Some(Some("a".repeat(64)));
    let updated = restarted
        .update(&org_a, "application-a", "DATA_GENERATED", &signed, next)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated.sod_sha256.as_deref(), Some("a".repeat(64).as_str()));
    assert!(restarted
        .get(&org_b, "application-a")
        .await
        .unwrap()
        .is_none());

    let mut submitted = PassportJobPatch::new(PassportJobStatus::Submitted);
    submitted.bureau_job_id = Some(Some("bureau-a".into()));
    restarted
        .update(&org_a, "application-a", "SOD_SIGNED", &submitted, next)
        .await
        .unwrap()
        .unwrap();
    let secret = "synthetic-bureau-webhook-secret";
    let bureau = BureauClient::new("http://127.0.0.1:1", "synthetic-key", Some(secret)).unwrap();
    let body = serde_json::to_vec(&serde_json::json!({
        "bureau_job_id": "bureau-a",
        "status": "SHIPPED",
        "tracking_number": "tracking-a"
    }))
    .unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(&body);
    let signature = hex::encode(mac.finalize().into_bytes());
    assert!(bureau.parse_webhook(&body, "invalid").is_err());
    assert_eq!(
        restarted
            .get(&org_a, "application-a")
            .await
            .unwrap()
            .unwrap()
            .status,
        "SUBMITTED"
    );
    let event = bureau.parse_webhook(&body, &signature).unwrap();
    let webhook_updated = restarted
        .apply_verified_webhook(&event, next)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(webhook_updated.status, "READY_FOR_ACTIVATION");
    assert_eq!(
        webhook_updated.tracking_number.as_deref(),
        Some("tracking-a")
    );
    let mut quality = PassportJobPatch::new(PassportJobStatus::ReadyForActivation);
    quality.quality_result = Some(Some(serde_json::json!({"passed": true})));
    restarted
        .update(
            &org_a,
            "application-a",
            "READY_FOR_ACTIVATION",
            &quality,
            next,
        )
        .await
        .unwrap()
        .unwrap();
    let mut activated = PassportJobPatch::new(PassportJobStatus::Active);
    activated.completed_at = Some(next);
    activated.secure_artifact_ciphertext = Some(cipher.encrypted_scrubbed_artifact());
    let active = restarted
        .update(
            &org_a,
            "application-a",
            "READY_FOR_ACTIVATION",
            &activated,
            next,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active.status, "ACTIVE");
    assert_eq!(active.completed_at, Some(next));
    assert!(cipher.decrypt(&active.secure_artifact_ciphertext).is_err());

    let second_job = PassportJobInsert {
        id: "job-b".into(),
        application_id: "application-b".into(),
        flow_execution_id: "flow-b".into(),
        application_template_id: "template-b".into(),
        credential_template_id: "credential-b".into(),
        revocation_profile_id: None,
        delivery_destination_profile_id: "destination-b".into(),
        document_type: "TD1".into(),
        country_code: "CAN".into(),
        secure_artifact_ciphertext: cipher.encrypt(&artifact).unwrap(),
        secure_artifact_reference: "physical-artifact://job-b".into(),
    };
    restarted.insert(&org_b, &second_job, now).await.unwrap();
    restarted
        .update(&org_b, "application-b", "DRAFT", &submitted, next)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        restarted.apply_verified_webhook(&event, next).await,
        Err(PassportWebhookRepositoryError::AmbiguousBureauJob)
    ));
    assert_eq!(
        restarted
            .get(&org_b, "application-b")
            .await
            .unwrap()
            .unwrap()
            .status,
        "SUBMITTED"
    );
    assert_eq!(
        restarted
            .get(&org_a, "application-a")
            .await
            .unwrap()
            .unwrap()
            .status,
        "ACTIVE"
    );
    exercise_native_passport_http(restarted, keyring, cipher, &key_a, &key_b).await;
    #[cfg(feature = "passport-self-signed-test")]
    if let Ok(packaged_url) = std::env::var("MARTY_PASSPORT_PACKAGED_TEST_URL") {
        exercise_packaged_self_signed_test_mode(&packaged_url, &key_a).await;
    } else {
        eprintln!("packaged passport test mode requires MARTY_PASSPORT_PACKAGED_TEST_URL");
    }

    // Upgrade a populated released Python table rather than only testing a
    // fresh Rust table. The existing row and its original column type survive.
    sqlx::raw_sql(include_str!(
        "fixtures/physical_document_jobs_python_base.sql"
    ))
    .execute(&restarted_pool)
    .await
    .unwrap();
    migration::migrate_passport(&restarted_pool).await.unwrap();
    migration::migrate_passport(&restarted_pool).await.unwrap();
    let released: (String, Option<String>, String) = sqlx::query_as(
        "SELECT status, revocation_profile_id, document_type \
         FROM issuance_service.physical_document_jobs WHERE id='released-python-job'",
    )
    .fetch_one(&restarted_pool)
    .await
    .unwrap();
    assert_eq!(released, ("DRAFT".into(), None, "TD2".into()));
    let id_type: String = sqlx::query_scalar(
        "SELECT data_type FROM information_schema.columns \
         WHERE table_schema='issuance_service' AND table_name='physical_document_jobs' \
           AND column_name='id'",
    )
    .fetch_one(&restarted_pool)
    .await
    .unwrap();
    assert_eq!(id_type, "character varying");
    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes \
         WHERE schemaname='issuance_service' AND tablename='physical_document_jobs'",
    )
    .fetch_all(&restarted_pool)
    .await
    .unwrap();
    for index in [
        "ix_physical_document_jobs_organization_id",
        "ix_physical_document_jobs_flow_execution_id",
        "ix_physical_document_jobs_status",
        "ix_physical_document_jobs_bureau_job_id",
    ] {
        assert!(indexes.iter().any(|existing| existing == index));
    }
}
