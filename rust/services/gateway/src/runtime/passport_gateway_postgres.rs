// Opt-in, disposable PostgreSQL proof of the public webhook handoff.

use super::*;
use chrono::Utc;
use hmac::{Hmac, Mac};
use marty_issuance_service::{
    migration,
    passport_bureau::BureauClient,
    passport_http::{router as passport_router, PassportHttpService},
    passport_repository::{
        PassportJobInsert, PassportJobPatch, PassportJobStatus, PostgresPassportRepository,
    },
};
use marty_passport_auth::PassportTenantKeyring;
use sha2::Sha256;
use sqlx::postgres::PgPoolOptions;

struct PassportRouterUpstream(Router);

#[async_trait]
impl UpstreamClient for PassportRouterUpstream {
    async fn send(
        &self,
        instance: &ServiceInstance,
        request: GatewayRequest,
    ) -> Result<GatewayResponse, PlatformError> {
        assert_eq!(instance.service_name, issuance_native::NATIVE_SERVICE);
        assert_eq!(request.method, HttpMethod::Post);
        let mut builder = Request::builder().method("POST").uri(&request.path);
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let response = self
            .0
            .clone()
            .oneshot(
                builder
                    .body(Body::from(request.body.unwrap_or_default()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status_code = response.status().as_u16();
        let body = to_bytes(response.into_body(), DEFAULT_MAXIMUM_BODY_BYTES)
            .await
            .unwrap();
        Ok(GatewayResponse {
            status_code,
            headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
            body: Some(body.to_vec()),
            response_time_ms: None,
            upstream_service: None,
        })
    }
}

fn signature(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

async fn send_webhook(router: &Router, body: &[u8], signature: &str) -> StatusCode {
    router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/passport/webhooks/personalization")
                .header("content-type", "application/json")
                .header("x-personalization-signature", signature)
                .body(Body::from(body.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn native_passport_gateway_signed_webhook_updates_durable_tenant_job() {
    let Ok(database_url) = std::env::var("MARTY_PASSPORT_GATEWAY_TEST_URL") else {
        return;
    };
    let database = url::Url::parse(&database_url).expect("gateway passport test URL must parse");
    assert!(
        matches!(database.host_str(), Some("127.0.0.1" | "localhost")),
        "gateway passport contract requires a loopback PostgreSQL host"
    );
    let database_name = database.path().trim_start_matches('/');
    assert_eq!(
        database_name, "marty_passport_gateway_test",
        "gateway passport contract requires its dedicated disposable database"
    );
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await
        .expect("gateway passport test database must connect");
    sqlx::query("DROP SCHEMA IF EXISTS issuance_service CASCADE")
        .execute(&pool)
        .await
        .unwrap();
    migration::migrate_passport(&pool).await.unwrap();

    let keyring = PassportTenantKeyring::from_json(
        r#"{"org-1":"native-passport-key-for-org-1-00000001","org-2":"native-passport-key-for-org-2-00000002"}"#,
    )
    .unwrap();
    let repository = PostgresPassportRepository::new(pool.clone());
    for organization_id in ["org-1", "org-2"] {
        let principal = keyring
            .authenticate(
                Some(organization_id),
                Some(if organization_id == "org-1" {
                    "native-passport-key-for-org-1-00000001"
                } else {
                    "native-passport-key-for-org-2-00000002"
                }),
            )
            .unwrap();
        let job = PassportJobInsert {
            id: format!("job-{organization_id}"),
            application_id: format!("application-{organization_id}"),
            flow_execution_id: format!("flow-{organization_id}"),
            application_template_id: "template-test".into(),
            credential_template_id: "credential-test".into(),
            revocation_profile_id: None,
            delivery_destination_profile_id: "destination-test".into(),
            document_type: "TD3".into(),
            country_code: "USA".into(),
            issuer_did: None,
            secure_artifact_ciphertext: "synthetic-encrypted-artifact".into(),
            secure_artifact_reference: format!("physical-artifact://job-{organization_id}"),
        };
        repository
            .insert(&principal, &job, Utc::now())
            .await
            .unwrap();
        let mut submitted = PassportJobPatch::new(PassportJobStatus::Submitted);
        submitted.bureau_job_id = Some(Some("bureau-shared".into()));
        repository
            .update(
                &principal,
                &job.application_id,
                "DRAFT",
                &submitted,
                Utc::now(),
            )
            .await
            .unwrap()
            .unwrap();
    }

    let secret = "synthetic-personalization-webhook-secret";
    let bureau = BureauClient::new("http://127.0.0.1:1", "unused", Some(secret)).unwrap();
    let issuance = passport_router(PassportHttpService::new(
        keyring.clone(),
        repository.clone(),
        None,
        None,
        Some(bureau),
    ));
    let gateway = gateway_router(runtime_state_with_upstream_and_passport(
        Arc::new(NoOwner),
        Arc::new(PassportRouterUpstream(issuance)),
        true,
    ));

    let raw = br#"{ "organization_id" : "org-1", "bureau_job_id":"bureau-shared", "status":"PRINTING", "tracking_number":"tracking-org-1" }"#;
    let signed = signature(secret, raw);
    assert_eq!(send_webhook(&gateway, raw, &signed).await, StatusCode::OK);
    let org_1 = keyring
        .authenticate(
            Some("org-1"),
            Some("native-passport-key-for-org-1-00000001"),
        )
        .unwrap();
    let org_2 = keyring
        .authenticate(
            Some("org-2"),
            Some("native-passport-key-for-org-2-00000002"),
        )
        .unwrap();
    let first = repository
        .get(&org_1, "application-org-1")
        .await
        .unwrap()
        .unwrap();
    let other = repository
        .get(&org_2, "application-org-2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.status, "IN_PRODUCTION");
    assert_eq!(first.tracking_number.as_deref(), Some("tracking-org-1"));
    assert_eq!(other.status, "SUBMITTED");
    assert_eq!(other.tracking_number, None);

    let altered = br#"{ "organization_id" : "org-2", "bureau_job_id":"bureau-shared", "status":"PRINTING", "tracking_number":"tracking-org-1" }"#;
    assert_eq!(
        send_webhook(&gateway, altered, &signed).await,
        StatusCode::UNAUTHORIZED
    );
    let rejected_owner = repository
        .get(&org_1, "application-org-1")
        .await
        .unwrap()
        .unwrap();
    let rejected_other = repository
        .get(&org_2, "application-org-2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rejected_owner.status, "IN_PRODUCTION");
    assert_eq!(rejected_owner.tracking_number.as_deref(), Some("tracking-org-1"));
    assert_eq!(rejected_other.status, "SUBMITTED");
    assert_eq!(rejected_other.tracking_number, None);
    let shipped =
        br#"{"organization_id":"org-1","bureau_job_id":"bureau-shared","status":"SHIPPED"}"#;
    assert_eq!(
        send_webhook(&gateway, shipped, &signature(secret, shipped)).await,
        StatusCode::OK
    );
    let completed = repository
        .get(&org_1, "application-org-1")
        .await
        .unwrap()
        .unwrap();
    let untouched = repository
        .get(&org_2, "application-org-2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed.status, "READY_FOR_ACTIVATION");
    assert_eq!(completed.tracking_number.as_deref(), Some("tracking-org-1"));
    assert_eq!(untouched.status, "SUBMITTED");
}
