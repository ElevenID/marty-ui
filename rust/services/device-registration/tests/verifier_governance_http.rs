//! Actual Device HTTP/SQL execution against an owned paused TLS authority
//! fixture. Membership and owner responses are controlled, not deployed PDP.
use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use chrono::{Duration, Utc};
use marty_device_registration::{
    control_plane::MembershipAuthorizer,
    holder_credential,
    holder_credential_repository::{
        HolderCredentialRepository, PostgresHolderCredentialRepository,
    },
    holder_key::new_reference,
    http::{router, HttpState},
    migration,
    pairing_confirmation::PostgresPairingConfirmations,
    pairing_ticket::MemoryPairingTickets,
    postgres::PostgresDeviceRepository,
    wallet_issuer_trust::WalletIssuerTrustClient,
    wallet_verifier_trust::WalletVerifierTrustClient,
    CreateRegistration, DeviceError, DeviceRegistration, DeviceRepository, DeviceService, Platform,
};
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use tower::ServiceExt;
use uuid::Uuid;

const ORG: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const PROFILE: &str = "00000000-0000-4000-8000-000000000002";
const CLIENT: &str = "decentralized_identifier:did:web:verifier.example";
const LOCATOR: &str =
    "https://verifier.example/v1/flows/instances/11111111-2222-4333-8444-555555555555/request";
const CASES: &[&str] = &[
    "unchanged",
    "device_id",
    "user_id",
    "organization_id",
    "inactive",
    "issuer_profile",
    "verifier_profile",
    "pairing_expired",
    "binding_revoked",
    "signing_revoked",
    "key_version",
    "bearer_rotated",
    "credential_revoked",
    "membership_revoked",
];

#[derive(Default)]
struct Membership {
    revoked: AtomicBool,
    calls: AtomicUsize,
}
#[async_trait]
impl MembershipAuthorizer for Membership {
    async fn require_active(&self, user: &str, org: &str) -> Result<(), DeviceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if user != "browser-user" || org != ORG || self.revoked.load(Ordering::SeqCst) {
            return Err(DeviceError::Forbidden(
                "fixture membership no longer active".into(),
            ));
        }
        Ok(())
    }
}

async fn seed(
    pool: &PgPool,
) -> (
    DeviceRegistration,
    holder_credential::IssuedHolderCredential,
    String,
) {
    let now = Utc::now();
    let device = DeviceRegistration::new(
        "browser-user".into(),
        CreateRegistration {
            user_id: None,
            organization_id: Some(ORG.into()),
            device_id: Uuid::new_v4().to_string(),
            platform: Platform::Android,
            fcm_token: None,
            app_version: None,
            os_version: None,
            device_model: None,
            preferences: Default::default(),
            is_active: true,
        },
        now,
    );
    PostgresDeviceRepository::new(pool.clone())
        .save(device.clone())
        .await
        .unwrap();
    let credential = holder_credential::issue(&device, now, Duration::hours(1)).unwrap();
    PostgresHolderCredentialRepository::new(pool.clone())
        .replace(credential.record.clone(), now)
        .await
        .unwrap();
    let pairing = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO device_registration_service.device_pairing_confirmations (pairing_id,user_id,organization_id,trust_profile_id,verifier_trust_profile_id,registration_id,issued_at,expires_at,confirmed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$7)")
        .bind(&pairing).bind(&device.user_id).bind(ORG).bind("00000000-0000-4000-8000-000000000003").bind(PROFILE).bind(&device.id)
        .bind(now).bind(now+Duration::minutes(10)).execute(pool).await.unwrap();
    for (purpose, algorithm, x, y) in [
        (
            "holder_binding",
            "EdDSA",
            "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            None,
        ),
        (
            "presentation_signing",
            "ES256",
            "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
            Some("T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"),
        ),
    ] {
        sqlx::query("INSERT INTO device_registration_service.device_holder_keys (id,registration_id,user_id,organization_id,purpose,algorithm,provider_reference,remote_version,public_x,public_y,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10)")
            .bind(Uuid::new_v4().to_string()).bind(&device.id).bind(&device.user_id).bind(ORG).bind(purpose).bind(algorithm)
            .bind(new_reference(ORG,&device.id,purpose).unwrap()).bind(x).bind(y).bind(now).execute(pool).await.unwrap();
    }
    (device, credential, pairing)
}

async fn change(
    pool: &PgPool,
    case: &str,
    device: &DeviceRegistration,
    credential: &holder_credential::IssuedHolderCredential,
    pairing: &str,
    membership: &Membership,
) {
    match case {
        "unchanged" | "issuer_only" => (),
        "membership_revoked" => membership.revoked.store(true, Ordering::SeqCst),
        "bearer_rotated" => {
            let next = holder_credential::issue(device, Utc::now(), Duration::hours(1)).unwrap();
            PostgresHolderCredentialRepository::new(pool.clone())
                .replace(next.record, Utc::now())
                .await
                .unwrap();
        }
        "credential_revoked" => {
            sqlx::query("UPDATE device_registration_service.device_holder_credentials SET revoked_at=clock_timestamp() WHERE id=$1").bind(&credential.record.id).execute(pool).await.unwrap();
        }
        "pairing_expired" => {
            sqlx::query("UPDATE device_registration_service.device_pairing_confirmations SET expired_at=clock_timestamp() WHERE pairing_id=$1").bind(pairing).execute(pool).await.unwrap();
        }
        "issuer_profile" | "verifier_profile" => {
            let sql = if case == "issuer_profile" {
                "UPDATE device_registration_service.device_pairing_confirmations SET trust_profile_id=$2 WHERE pairing_id=$1"
            } else {
                "UPDATE device_registration_service.device_pairing_confirmations SET verifier_trust_profile_id=$2 WHERE pairing_id=$1"
            };
            sqlx::query(sql)
                .bind(pairing)
                .bind(Uuid::new_v4().to_string())
                .execute(pool)
                .await
                .unwrap();
        }
        "binding_revoked" | "signing_revoked" => {
            let purpose = if case == "binding_revoked" {
                "holder_binding"
            } else {
                "presentation_signing"
            };
            sqlx::query("UPDATE device_registration_service.device_holder_keys SET revoked_at=clock_timestamp() WHERE registration_id=$1 AND purpose=$2").bind(&device.id).bind(purpose).execute(pool).await.unwrap();
        }
        "key_version" => {
            sqlx::query("UPDATE device_registration_service.device_holder_keys SET remote_version=2 WHERE registration_id=$1 AND purpose='presentation_signing'").bind(&device.id).execute(pool).await.unwrap();
        }
        "device_id" | "user_id" | "organization_id" | "inactive" => {
            let sql = match case {
                "device_id" => "UPDATE device_registration_service.device_registrations SET device_id='substituted-' || id WHERE id=$1",
                "user_id" => "UPDATE device_registration_service.device_registrations SET user_id='substituted-user' WHERE id=$1",
                "organization_id" => "UPDATE device_registration_service.device_registrations SET organization_id='bbbbbbbb-cccc-4ddd-8eee-ffffffffffff' WHERE id=$1",
                _ => "UPDATE device_registration_service.device_registrations SET is_active=false WHERE id=$1",
            };
            sqlx::query(sql)
                .bind(&device.id)
                .execute(pool)
                .await
                .unwrap();
        }
        _ => panic!("unknown controlled mutation"),
    }
}

#[tokio::test]
#[ignore = "requires newly owned PostgreSQL and paused TLS authority fixture"]
async fn device_http_governance_rereads_scope_after_paused_managed_authority() {
    let database = std::env::var("DEVICE_REGISTRATION_POSTGRES_TEST_URL").expect("owned database");
    let database_nonce =
        std::env::var("MARTY_TEST_POSTGRES_DISPOSABLE_NONCE").expect("owned database nonce");
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database)
        .await
        .unwrap();
    let guard: String = sqlx::query_scalar("SELECT nonce FROM public.marty_disposable_guard")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(database_nonce.len() >= 32 && database_nonce == guard);
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM information_schema.schemata WHERE schema_name='device_registration_service')").fetch_one(&pool).await.unwrap();
    assert!(!exists, "HTTP fixture must start with a fresh schema");
    migration::migrate(&pool).await.unwrap();
    let origin = std::env::var("MARTY_VERIFIER_TLS_FIXTURE_ORIGIN").unwrap();
    let parsed = reqwest::Url::parse(&origin).unwrap();
    assert_eq!(parsed.scheme(), "https");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert!(
        parsed.port().is_some()
            && parsed.path() == "/"
            && parsed.username().is_empty()
            && parsed.password().is_none()
    );
    let ca = std::fs::read(std::env::var("MARTY_VERIFIER_TLS_FIXTURE_CA").unwrap()).unwrap();
    let token = std::env::var("MARTY_VERIFIER_TLS_FIXTURE_TOKEN").unwrap();
    let nonce = std::env::var("MARTY_VERIFIER_TLS_FIXTURE_NONCE").unwrap();
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5));
    for cert in reqwest::Certificate::from_pem_bundle(&ca).unwrap() {
        builder = builder.add_root_certificate(cert);
    }
    let control = builder.build().unwrap();
    let verified = control
        .get(format!("{origin}fixture-guard/{nonce}"))
        .send()
        .await
        .unwrap();
    assert_eq!(verified.status(), StatusCode::OK);
    assert_eq!(verified.text().await.unwrap(), nonce);
    let trust = Arc::new(WalletVerifierTrustClient::new(&origin, &token, Some(&ca)).unwrap());
    let issuer_trust = Arc::new(WalletIssuerTrustClient::new(&origin, &token, Some(&ca)).unwrap());
    let cases = CASES
        .iter()
        .flat_map(|&case| [("managed", case), ("issuer", case)])
        .chain([
            ("issuer", "issuer_only"),
            ("registered", "unchanged"),
            ("registered", "bearer_rotated"),
            ("registered", "membership_revoked"),
        ]);
    for (profile, case) in cases {
        let issuer = profile == "issuer";
        let registered = profile == "registered";
        let controlled_case = if profile == "managed" {
            case.to_owned()
        } else {
            format!("{profile}_{case}")
        };
        let (device, credential, pairing) = seed(&pool).await;
        if case == "issuer_only" {
            sqlx::query("UPDATE device_registration_service.device_pairing_confirmations SET verifier_trust_profile_id=NULL WHERE pairing_id=$1")
                .bind(&pairing).execute(&pool).await.unwrap();
        }
        let confirmations = Arc::new(PostgresPairingConfirmations::new(pool.clone()));
        let expected = confirmations
            .issuer_governance_for_bearer(&credential.bearer)
            .await
            .unwrap();
        let membership = Arc::new(Membership::default());
        let gateway = "g".repeat(32);
        let app = router(HttpState {
            service: Arc::new(DeviceService::new(Arc::new(PostgresDeviceRepository::new(
                pool.clone(),
            )))),
            memberships: membership.clone(),
            pairing_tickets: Arc::new(MemoryPairingTickets::new(300)),
            wallet_issuer_trust: Some(issuer_trust.clone()),
            wallet_verifier_trust: Some(trust.clone()),
            pairing_confirmations: Some(confirmations),
            pairing_enrollment: None,
            holder_signer: None,
            holder_credential_rotator: None,
            release_version: "test".into(),
            build_revision: "test".into(),
            gateway_key: gateway.clone(),
        });
        let armed = control
            .get(format!(
                "{origin}fixture-control/{nonce}/arm/{controlled_case}"
            ))
            .header("x-service-token", &token)
            .send()
            .await
            .unwrap();
        assert_eq!(armed.status(), StatusCode::OK);
        let mut query =
            reqwest::Url::parse("https://device.fixture/v1/devices/wallet-verifier-authority")
                .unwrap();
        if registered {
            query
                .query_pairs_mut()
                .append_pair("client_id", "registered-client")
                .append_pair("device_scope", "true");
        } else {
            query
                .query_pairs_mut()
                .append_pair("client_id", CLIENT)
                .append_pair("request_uri", LOCATOR);
        }
        let request_uri = if issuer {
            "/v1/devices/wallet-issuer-keys".to_owned()
        } else {
            format!("{}?{}", query.path(), query.query().unwrap())
        };
        let request = Request::get(request_uri)
            .header("x-service-token", &gateway)
            .header("authorization", format!("Bearer {}", credential.bearer))
            .header("x-user-id", "forged-caller")
            .header("x-organization-id", "forged-organization")
            .body(Body::empty())
            .unwrap();
        let pending = tokio::spawn(async move { app.oneshot(request).await.unwrap() });
        let mut arrived = false;
        for _ in 0..100 {
            let response = control
                .get(format!(
                    "{origin}fixture-control/{nonce}/arrived/{controlled_case}"
                ))
                .header("x-service-token", &token)
                .send()
                .await
                .unwrap();
            if response.status() == StatusCode::OK {
                arrived = true;
                break;
            }
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            arrived,
            "Device HTTP must reach the paused managed-owner fetch"
        );
        assert!(
            !pending.is_finished(),
            "authority response must remain paused"
        );
        change(&pool, case, &device, &credential, &pairing, &membership).await;
        let released = control
            .get(format!(
                "{origin}fixture-control/{nonce}/release/{controlled_case}"
            ))
            .header("x-service-token", &token)
            .send()
            .await
            .unwrap();
        assert_eq!(released.status(), StatusCode::OK);
        let response = tokio::time::timeout(std::time::Duration::from_secs(10), pending)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            membership.calls.load(Ordering::SeqCst),
            2,
            "membership must be repeated after fetch"
        );
        let status = response.status();
        let no_store = response.headers().get("cache-control").cloned();
        let bytes = to_bytes(response.into_body(), 65536).await.unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains(&credential.bearer) && !text.contains("cred-presenter-"));
        if case == "unchanged" || case == "issuer_only" {
            assert_eq!(status, StatusCode::OK);
            assert_eq!(no_store.unwrap(), "no-store");
            assert_eq!(
                body["contract"],
                if issuer {
                    "marty.wallet/device-issuer-governance/v2"
                } else {
                    "marty.wallet/device-verifier-governance/v2"
                }
            );
            assert_eq!(body["scope"], serde_json::to_value(&expected).unwrap());
            if issuer {
                if case == "issuer_only" {
                    assert!(body["scope"]["verifier_trust_profile_id"].is_null());
                }
                assert_eq!(
                    body["issuer"]["contract"],
                    "marty.wallet/issuer-authority/v2"
                );
                assert_eq!(
                    body["issuer"]["trust_profile_id"],
                    expected.issuer_trust_profile_id
                );
            } else if registered {
                assert_eq!(
                    body["verifier"]["contract"],
                    "marty.wallet/verifier-authority/v1"
                );
                assert_eq!(
                    body["verifier"]["authority"]["registration"]["client_id"],
                    "registered-client"
                );
                assert!(body["verifier"].get("request").is_none());
            } else {
                assert_eq!(body["verifier"]["request"]["request_uri"], LOCATOR);
            }
        } else {
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "paused mutation {case} must defeat read"
            );
            assert!(
                body.get("scope").is_none()
                    && body.get("verifier").is_none()
                    && body.get("issuer").is_none()
            );
        }
    }
    pool.close().await;
}
