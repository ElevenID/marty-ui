//! Guarded holder-key lifecycle and real Trust Profile→keyless HTTPS→Device authority.
//! Membership/PDP decisions and public issuer metadata remain controlled fixtures.

#[path = "support/holder_issuer_authority.rs"]
mod holder_issuer_authority;

use marty_trust_profile::TrustProfileRepository;

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ecdsa_core::signature::Verifier as _;
use ed25519_dalek::{Signature, VerifyingKey};
use marty_device_registration::{
    control_plane::MembershipAuthorizer,
    holder_credential_repository::PostgresHolderCredentialRepository,
    holder_credential_rotation::HolderCredentialRotator,
    holder_key_cleanup::HolderKeyCleanup,
    holder_key_client::HolderKeyClient,
    holder_key_provisioner::HolderKeyProvisioner,
    holder_key_repository::PostgresHolderKeyRepository,
    holder_signer::HolderSigner,
    http::{router, HttpState},
    migration::migrate,
    pairing_confirmation::PostgresPairingConfirmations,
    pairing_enrollment::{PairingEnrollment, PairingRedeemResult},
    pairing_ticket::{MemoryPairingTickets, PairingTicketRepository},
    postgres::PostgresDeviceRepository,
    wallet_issuer_trust::WalletIssuerTrustClient,
    DeviceError, DeviceRepository, DeviceService,
};
use marty_holder_key_reference::HolderSignature;
use marty_signing_keys::{
    kms::{read_managed_openbao, ProviderRequest},
    managed_holder_http,
    managed_holder_key::OpenBaoManagedHolderKeys,
};
type P256Signature = ecdsa_core::Signature<p256::NistP256>;
type P256VerifyingKey = ecdsa_core::VerifyingKey<p256::NistP256>;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use uuid::Uuid;

#[derive(Default)]
struct SwitchMembership(AtomicBool);

#[async_trait]
impl MembershipAuthorizer for SwitchMembership {
    async fn require_active(
        &self,
        _user_id: &str,
        _organization_id: &str,
    ) -> Result<(), DeviceError> {
        if self.0.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(DeviceError::Forbidden("membership inactive".into()))
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires guarded disposable OpenBao, fresh PostgreSQL and non-exportable owner TLS"]
async fn registration_provision_sign_and_deactivate_delete_remote_key() {
    let endpoint = std::env::var("MARTY_TEST_OPENBAO_URL").expect("disposable OpenBao URL");
    let parsed = reqwest::Url::parse(&endpoint).expect("OpenBao URL syntax");
    assert_eq!(parsed.scheme(), "https");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    let token = std::env::var("MARTY_TEST_OPENBAO_TOKEN").expect("scoped OpenBao token");
    let root_token = std::env::var("MARTY_TEST_OPENBAO_ROOT_TOKEN").expect("root guard token");
    assert_ne!(token, root_token);
    let nonce = std::env::var("MARTY_TEST_OPENBAO_DISPOSABLE_NONCE").expect("guard nonce");
    let ca_file = std::env::var("BAO_CACERT").expect("disposable public OpenBao CA");
    let ca_pem = std::fs::read(ca_file).expect("read public OpenBao CA");
    let ca = reqwest::Certificate::from_pem(&ca_pem).expect("parse public OpenBao CA");
    let marker = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .tls_certs_only([ca])
        .build()
        .expect("guarded OpenBao HTTPS client")
        .get(format!(
            "{endpoint}/v1/secret/data/marty-test-disposable-guard"
        ))
        .header("X-Vault-Token", root_token)
        .send()
        .await
        .expect("read disposable sentinel");
    assert!(marker.status().is_success());
    let marker: serde_json::Value = marker.json().await.expect("sentinel JSON");
    assert_eq!(marker["data"]["data"]["nonce"], nonce);

    let database_url =
        std::env::var("DEVICE_REGISTRATION_POSTGRES_TEST_URL").expect("disposable PostgreSQL URL");
    let database = reqwest::Url::parse(&database_url).expect("PostgreSQL URL syntax");
    assert_eq!(database.host_str(), Some("127.0.0.1"));
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect(&database_url)
        .await
        .expect("disposable PostgreSQL");
    let guard: String = sqlx::query_scalar("SELECT nonce FROM public.marty_disposable_guard")
        .fetch_one(&pool)
        .await
        .expect("owned SQL marker");
    assert_eq!(guard, nonce);
    let fresh: bool = sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname NOT IN ('public','information_schema') AND nspname NOT LIKE 'pg_%') AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname='public' AND c.relname<>'marty_disposable_guard')")
        .fetch_one(&pool).await.unwrap();
    assert!(
        fresh,
        "holder/issuer fixture requires fresh owned schemas before any migration"
    );
    migrate(&pool).await.expect("fresh Rust schema");

    let devices: Arc<dyn DeviceRepository> = Arc::new(PostgresDeviceRepository::new(pool.clone()));
    let user_id = format!("user-{}", Uuid::new_v4());
    let organization_id = Uuid::new_v4().to_string();
    let tickets = Arc::new(MemoryPairingTickets::new(300));
    let ticket = tickets
        .issue(
            &user_id,
            &organization_id,
            "11111111-2222-4333-8444-555555555555",
        )
        .await
        .unwrap();
    let pairing_id = ticket.scope.pairing_id.clone();
    let bound_profile_id = ticket.scope.trust_profile_id.clone();
    let confirmations = PostgresPairingConfirmations::new(pool.clone());
    confirmations.record_issued(&ticket.scope).await.unwrap();

    let service_key = "disposable-device-registration-signing-key-32-chars";
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Signing Keys listener");
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let provider =
        OpenBaoManagedHolderKeys::new(endpoint.clone()).expect("managed OpenBao provider");
    let app = managed_holder_http::router(service_key.into(), provider);
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let client = HolderKeyClient::new(&origin, service_key.into()).expect("dedicated client");
    let keys = PostgresHolderKeyRepository::new(pool.clone());
    let provisioner = HolderKeyProvisioner::new(devices.clone(), keys.clone(), client.clone());
    let credentials = PostgresHolderCredentialRepository::new(pool.clone());
    let device_service = Arc::new(DeviceService::new(devices.clone()));
    let memberships = Arc::new(SwitchMembership(AtomicBool::new(true)));
    let signer = Arc::new(HolderSigner::new(
        pool.clone(),
        client.clone(),
        memberships.clone(),
    ));
    let enrollment = Arc::new(PairingEnrollment::new(
        tickets.clone(),
        memberships.clone(),
        device_service.clone(),
        provisioner,
        credentials.clone(),
        confirmations.clone(),
    ));
    let mut issuer_owner = holder_issuer_authority::Owner::start(
        &pool,
        Uuid::parse_str(&bound_profile_id).unwrap(),
        &user_id,
        &organization_id,
        &nonce,
    )
    .await;
    let trust_client = Arc::new(
        WalletIssuerTrustClient::new(&issuer_owner.origin, &nonce, Some(&issuer_owner.ca)).unwrap(),
    );
    assert!(
        WalletIssuerTrustClient::new(&issuer_owner.origin, &nonce, None)
            .unwrap()
            .fetch(&bound_profile_id, &organization_id, &user_id)
            .await
            .is_err(),
        "owner HTTPS requires its trusted CA"
    );
    let gateway_key = "disposable-gateway-device-registration-key-32-chars";
    let device_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Device Registration listener");
    let device_origin = format!("http://{}", device_listener.local_addr().unwrap());
    let app = router(HttpState {
        service: device_service,
        memberships: memberships.clone(),
        pairing_tickets: tickets.clone(),
        wallet_issuer_trust: Some(trust_client),
        wallet_verifier_trust: None,
        pairing_confirmations: Some(Arc::new(confirmations.clone())),
        pairing_enrollment: Some(enrollment),
        holder_signer: Some(signer.clone()),
        holder_credential_rotator: Some(Arc::new(HolderCredentialRotator::new(
            pool.clone(),
            memberships.clone(),
        ))),
        release_version: "test".into(),
        build_revision: "disposable".into(),
        gateway_key: gateway_key.into(),
    });
    let device_server = tokio::spawn(async move { axum::serve(device_listener, app).await });
    let pairing_body = json!({
        "pairing_code": ticket.token,
        "platform": "android",
    });
    let http = reqwest::Client::new();
    let paired = http
        .post(format!("{device_origin}/v1/devices/pair"))
        .header("x-service-token", gateway_key)
        .json(&pairing_body)
        .send()
        .await
        .expect("wallet pairing HTTP response");
    assert!(paired.status().is_success());
    assert_eq!(paired.headers()["cache-control"], "no-store");
    let enrolled: PairingRedeemResult = paired.json().await.expect("wallet pairing JSON");
    assert_eq!(enrolled.pairing_id, pairing_id);
    let replay = http
        .post(format!("{device_origin}/v1/devices/pair"))
        .header("x-service-token", gateway_key)
        .json(&pairing_body)
        .send()
        .await
        .expect("ticket replay response");
    assert_eq!(replay.status(), reqwest::StatusCode::FORBIDDEN);
    let registration = devices
        .get(&enrolled.registration_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(registration.fcm_token, None);
    let key = keys
        .current(&registration.id, "holder_binding")
        .await
        .unwrap()
        .unwrap();
    let presentation = keys
        .current(&registration.id, "presentation_signing")
        .await
        .unwrap()
        .unwrap();
    assert!(key.valid_for(&registration));
    assert!(presentation.valid_for(&registration));
    assert_eq!(enrolled.holder_binding_public_jwk, key.public_jwk());
    assert_eq!(
        enrolled.presentation_signing_public_jwk,
        presentation.public_jwk()
    );
    assert!(credentials
        .issue_for_registration(
            &registration.id,
            "wrong-user",
            key.organization_id.as_str(),
            chrono::Duration::hours(1),
        )
        .await
        .is_err());
    let payload = b"exact managed holder proof";
    let premature = http
        .post(format!("{device_origin}/v1/devices/holder-signatures"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .json(&json!({"purpose":"holder_binding","payload_b64":URL_SAFE_NO_PAD.encode(payload)}))
        .send()
        .await
        .expect("premature holder signing response");
    assert_eq!(premature.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(confirmations
        .profile_for_bearer(&enrolled.device_credential)
        .await
        .is_err());
    let status = http
        .get(format!(
            "{device_origin}/v1/devices/pairing-confirmations/{pairing_id}"
        ))
        .header("x-service-token", gateway_key)
        .header("x-user-id", &user_id)
        .send()
        .await
        .expect("pending pairing status");
    assert_eq!(
        status.json::<serde_json::Value>().await.unwrap()["state"],
        "pending"
    );
    let confirmed = http
        .post(format!("{device_origin}/v1/devices/pairing-ack"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .json(&json!({"pairing_id":pairing_id}))
        .send()
        .await
        .expect("remote confirmation proof");
    assert!(confirmed.status().is_success());
    let retried = http
        .post(format!("{device_origin}/v1/devices/pairing-ack"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .json(&json!({"pairing_id":pairing_id}))
        .send()
        .await
        .expect("lost-response confirmation retry");
    assert!(retried.status().is_success(), "{}", retried.status());
    let status = http
        .get(format!(
            "{device_origin}/v1/devices/pairing-confirmations/{pairing_id}"
        ))
        .header("x-service-token", gateway_key)
        .header("x-user-id", &user_id)
        .send()
        .await
        .expect("paired status");
    assert_eq!(
        status.json::<serde_json::Value>().await.unwrap()["state"],
        "paired"
    );
    let bound = confirmations
        .profile_for_bearer(&enrolled.device_credential)
        .await
        .expect("confirmed bearer profile binding");
    assert_eq!(bound.user_id, user_id);
    assert_eq!(bound.organization_id, organization_id);
    assert_eq!(bound.trust_profile_id, bound_profile_id);
    let snapshot = http
        .get(format!("{device_origin}/v1/devices/wallet-issuer-keys"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .send()
        .await
        .expect("paired wallet trust snapshot");
    assert!(snapshot.status().is_success());
    assert_eq!(snapshot.headers()["cache-control"], "no-store");
    let snapshot: serde_json::Value = snapshot.json().await.unwrap();
    assert_eq!(snapshot["issuer"]["organization_id"], organization_id);
    assert_eq!(snapshot["issuer"]["trust_profile_id"], bound_profile_id);
    assert_eq!(
        snapshot["contract"],
        "marty.wallet/device-issuer-governance/v2"
    );
    assert_eq!(
        snapshot["scope"]["verifier_trust_profile_id"],
        serde_json::Value::Null
    );
    assert_eq!(snapshot["scope"]["pairing_id"], pairing_id);
    assert_eq!(snapshot["scope"]["registration_id"], registration.id);
    assert_eq!(
        snapshot["issuer"]["issuer_keys"][0]["credential_authorizations"],
        issuer_owner.relationship.metadata["marty_credential_authorizations_v1"]
    );
    assert_eq!(
        snapshot["issuer"]["issuer_keys"][0]["issuance_authorizations"],
        issuer_owner.relationship.metadata["marty_wallet_issuance_authorizations_v1"]
    );
    let persisted = issuer_owner
        .repository
        .wallet_issuer_authority_snapshot(
            &organization_id,
            Uuid::parse_str(&bound_profile_id).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot["issuer"]["revision"],
        serde_json::to_value(persisted.revision).unwrap()
    );
    let observed: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(snapshot["observed_at"].clone()).unwrap();
    let expires: chrono::DateTime<chrono::Utc> =
        serde_json::from_value(snapshot["expires_at"].clone()).unwrap();
    assert!(expires > observed && expires <= observed + chrono::Duration::seconds(60));
    let encoded = snapshot.to_string();
    for forbidden in [
        &enrolled.device_credential,
        "provider_reference",
        "KMS_TOKEN",
        "private_key",
    ] {
        assert!(
            !encoded.contains(forbidden),
            "public issuer evidence leaked a custody capability"
        );
    }
    // Persist a service-only edit. The actual owner must allocate a new wallet
    // revision; Device must return that edit rather than a cached projection.
    issuer_owner.relationship.metadata["marty_wallet_issuance_authorizations_v1"][0]
        ["credential_configuration_id"] = json!("identity-v2");
    issuer_owner
        .repository
        .save_profile_issuer(&issuer_owner.relationship)
        .await
        .unwrap();
    let next = http
        .get(format!("{device_origin}/v1/devices/wallet-issuer-keys"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .send()
        .await
        .unwrap();
    assert_eq!(next.status(), reqwest::StatusCode::OK);
    assert_eq!(next.headers()["cache-control"], "no-store");
    let next: serde_json::Value = next.json().await.unwrap();
    assert_eq!(
        next["issuer"]["issuer_keys"][0]["issuance_authorizations"][0]
            ["credential_configuration_id"],
        "identity-v2"
    );
    assert!(
        next["issuer"]["revision"]["version"].as_u64().unwrap()
            > snapshot["issuer"]["revision"]["version"].as_u64().unwrap()
    );
    assert_ne!(
        next["issuer"]["revision"]["content_digest"],
        snapshot["issuer"]["revision"]["content_digest"]
    );
    for denial in ["relationship", "canonical_vct", "pdp"] {
        let original = issuer_owner.relationship.clone();
        match denial {
            "relationship" => {
                issuer_owner.relationship.relationship_status =
                    marty_trust_profile::TrustRelationshipStatus::Denied
            }
            "canonical_vct" => {
                issuer_owner.relationship.metadata["marty_credential_authorizations_v1"] = json!([])
            }
            _ => issuer_owner.pdp.allowed.store(false, Ordering::SeqCst),
        }
        issuer_owner
            .repository
            .save_profile_issuer(&issuer_owner.relationship)
            .await
            .unwrap();
        let denied = http
            .get(format!("{device_origin}/v1/devices/wallet-issuer-keys"))
            .header("x-service-token", gateway_key)
            .bearer_auth(&enrolled.device_credential)
            .send()
            .await
            .unwrap();
        assert!(
            !denied.status().is_success(),
            "{denial} must deny public issuer evidence"
        );
        let denied: serde_json::Value = denied.json().await.unwrap();
        assert!(denied.get("issuer").is_none() && denied.get("issuer_keys").is_none());
        issuer_owner.relationship = original;
        issuer_owner
            .repository
            .save_profile_issuer(&issuer_owner.relationship)
            .await
            .unwrap();
        issuer_owner.pdp.allowed.store(true, Ordering::SeqCst);
    }
    assert!(
        confirmations
            .governance_for_bearer(&enrolled.device_credential)
            .await
            .is_err(),
        "issuer-only enrollment must not acquire verifier authority"
    );
    assert!(signer
        .sign(
            "invalid",
            &registration.user_id,
            key.organization_id.as_str(),
            "holder_binding",
            payload
        )
        .await
        .is_err());
    let signed = http
        .post(format!("{device_origin}/v1/devices/holder-signatures"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .json(&json!({"purpose":"holder_binding","payload_b64":URL_SAFE_NO_PAD.encode(payload)}))
        .send()
        .await
        .expect("holder signing HTTP response");
    assert!(signed.status().is_success());
    assert_eq!(signed.headers()["cache-control"], "no-store");
    let signature: HolderSignature = signed.json().await.unwrap();
    assert_eq!(signature.signature_encoding, "raw");
    let coordinate: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&key.public_x)
        .unwrap()
        .try_into()
        .unwrap();
    let verifying = VerifyingKey::from_bytes(&coordinate).unwrap();
    let signature =
        Signature::from_slice(&URL_SAFE_NO_PAD.decode(signature.signature_b64).unwrap()).unwrap();
    verifying.verify_strict(payload, &signature).unwrap();

    let signed = http
        .post(format!("{device_origin}/v1/devices/holder-signatures"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .json(&json!({"purpose":"presentation_signing","payload_b64":URL_SAFE_NO_PAD.encode(payload)}))
        .send()
        .await
        .expect("presentation signing HTTP response");
    assert!(signed.status().is_success());
    let presentation_signature: HolderSignature = signed.json().await.unwrap();
    assert_eq!(presentation_signature.signature_encoding, "der");
    let mut public_point = vec![4_u8];
    public_point.extend(URL_SAFE_NO_PAD.decode(&presentation.public_x).unwrap());
    public_point.extend(
        URL_SAFE_NO_PAD
            .decode(presentation.public_y.as_deref().unwrap())
            .unwrap(),
    );
    let verifier = P256VerifyingKey::from_sec1_bytes(&public_point).unwrap();
    let signature = P256Signature::from_der(
        &URL_SAFE_NO_PAD
            .decode(presentation_signature.signature_b64)
            .unwrap(),
    )
    .unwrap();
    verifier.verify(payload, &signature).unwrap();

    memberships.0.store(false, Ordering::SeqCst);
    let denied_trust = http
        .get(format!("{device_origin}/v1/devices/wallet-issuer-keys"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .send()
        .await
        .expect("revoked membership trust response");
    assert_eq!(denied_trust.status(), reqwest::StatusCode::FORBIDDEN);
    let revoked_membership = http
        .post(format!("{device_origin}/v1/devices/holder-signatures"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .json(&json!({"purpose":"holder_binding","payload_b64":URL_SAFE_NO_PAD.encode(payload)}))
        .send()
        .await
        .expect("revoked membership signing response");
    assert_eq!(revoked_membership.status(), reqwest::StatusCode::FORBIDDEN);
    let denied_rotation = http
        .post(format!(
            "{device_origin}/v1/devices/holder-credential-rotations"
        ))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .json(&json!({"replacement_credential":URL_SAFE_NO_PAD.encode([41_u8;32])}))
        .send()
        .await
        .expect("revoked membership rotation response");
    assert_eq!(denied_rotation.status(), reqwest::StatusCode::FORBIDDEN);
    memberships.0.store(true, Ordering::SeqCst);

    let replacement = URL_SAFE_NO_PAD.encode([42_u8; 32]);
    let rotation_body = json!({"replacement_credential":replacement});
    let rotated = http
        .post(format!(
            "{device_origin}/v1/devices/holder-credential-rotations"
        ))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .json(&rotation_body)
        .send()
        .await
        .expect("holder credential rotation response");
    assert!(rotated.status().is_success());
    assert!(confirmations
        .profile_for_bearer(&enrolled.device_credential)
        .await
        .is_err());
    let stale_snapshot = http
        .get(format!("{device_origin}/v1/devices/wallet-issuer-keys"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .send()
        .await
        .expect("old bearer trust denial");
    assert_eq!(stale_snapshot.status(), reqwest::StatusCode::FORBIDDEN);
    let stale_signature = http
        .post(format!("{device_origin}/v1/devices/holder-signatures"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .json(&json!({"purpose":"holder_binding","payload_b64":URL_SAFE_NO_PAD.encode(payload)}))
        .send()
        .await
        .expect("old bearer signing HTTP response");
    assert_eq!(stale_signature.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(
        confirmations
            .profile_for_bearer(&replacement)
            .await
            .expect("rotated bearer retains selected profile")
            .trust_profile_id,
        bound_profile_id
    );
    assert_eq!(rotated.headers()["cache-control"], "no-store");
    let rotated: serde_json::Value = rotated.json().await.unwrap();
    assert_eq!(rotated["registration_id"], registration.id);
    let retry = http
        .post(format!(
            "{device_origin}/v1/devices/holder-credential-rotations"
        ))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .json(&rotation_body)
        .send()
        .await
        .expect("lost-response rotation retry");
    assert!(retry.status().is_success());
    assert_eq!(retry.json::<serde_json::Value>().await.unwrap(), rotated);
    let altered = http
        .post(format!(
            "{device_origin}/v1/devices/holder-credential-rotations"
        ))
        .header("x-service-token", gateway_key)
        .bearer_auth(&enrolled.device_credential)
        .json(&json!({"replacement_credential":URL_SAFE_NO_PAD.encode([43_u8;32])}))
        .send()
        .await
        .expect("different replay response");
    assert_eq!(altered.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(signer
        .sign(
            &enrolled.device_credential,
            &registration.user_id,
            key.organization_id.as_str(),
            "holder_binding",
            payload,
        )
        .await
        .is_err());
    signer
        .sign(
            &replacement,
            &registration.user_id,
            key.organization_id.as_str(),
            "holder_binding",
            payload,
        )
        .await
        .expect("rotated bearer signs through KMS");
    let rotated_signature = http
        .post(format!("{device_origin}/v1/devices/holder-signatures"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&replacement)
        .json(&json!({"purpose":"holder_binding","payload_b64":URL_SAFE_NO_PAD.encode(payload)}))
        .send()
        .await
        .expect("rotated bearer signing HTTP response");
    assert!(rotated_signature.status().is_success());
    assert_eq!(rotated_signature.headers()["cache-control"], "no-store");
    let rotated_signature: HolderSignature = rotated_signature.json().await.unwrap();
    assert_eq!(rotated_signature.signature_encoding, "raw");
    let signature = Signature::from_slice(
        &URL_SAFE_NO_PAD
            .decode(rotated_signature.signature_b64)
            .unwrap(),
    )
    .unwrap();
    verifying.verify_strict(payload, &signature).unwrap();

    let rotated_presentation = http
        .post(format!("{device_origin}/v1/devices/holder-signatures"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&replacement)
        .json(&json!({"purpose":"presentation_signing","payload_b64":URL_SAFE_NO_PAD.encode(payload)}))
        .send()
        .await
        .expect("rotated presentation signing HTTP response");
    assert!(rotated_presentation.status().is_success());
    let rotated_presentation: HolderSignature = rotated_presentation.json().await.unwrap();
    assert_eq!(rotated_presentation.signature_encoding, "der");
    let signature = P256Signature::from_der(
        &URL_SAFE_NO_PAD
            .decode(rotated_presentation.signature_b64)
            .unwrap(),
    )
    .unwrap();
    verifier.verify(payload, &signature).unwrap();

    devices
        .deactivate(&registration.id)
        .await
        .expect("device deactivation")
        .expect("registered device");
    assert!(confirmations
        .profile_for_bearer(&replacement)
        .await
        .is_err());
    assert!(signer
        .sign(
            &replacement,
            &registration.user_id,
            key.organization_id.as_str(),
            "holder_binding",
            payload
        )
        .await
        .is_err());
    let deactivated_signature = http
        .post(format!("{device_origin}/v1/devices/holder-signatures"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&replacement)
        .json(&json!({"purpose":"holder_binding","payload_b64":URL_SAFE_NO_PAD.encode(payload)}))
        .send()
        .await
        .expect("deactivated bearer signing HTTP response");
    assert_eq!(
        deactivated_signature.status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let cleanup = HolderKeyCleanup::new(keys.clone(), client);
    assert_eq!(cleanup.run_once().await.expect("remote cleanup"), (2, 0));
    let read = read_managed_openbao(ProviderRequest {
        service_config: json!({
            "id":"managed-openbao-transit", "service_type":"openbao-transit",
            "endpoint":endpoint, "mount":"transit",
            "key_reference":key.provider_reference, "algorithm":"EdDSA",
            "auth_mode":"service_token"
        }),
    })
    .await;
    let error = read.expect_err("remote key must be absent after deactivation");
    assert!(matches!(
        error,
        marty_signing_keys::kms::KmsError::ProviderStatus {
            status: reqwest::StatusCode::NOT_FOUND,
            ..
        }
    ));
    let remaining = marty_signing_keys::kms::list_managed_openbao_key_names(&endpoint)
        .await
        .expect("scoped inventory after deletion");
    assert!(!remaining.contains(&key.provider_reference));
    assert!(!remaining.contains(&presentation.provider_reference));

    let wrong_organization = http
        .post(format!("{device_origin}/v1/devices/pairing-tickets"))
        .header("x-service-token", gateway_key)
        .header("x-user-id", &user_id)
        .json(&json!({"organization_id":Uuid::new_v4().to_string(),"trust_profile_id":bound_profile_id}))
        .send()
        .await
        .expect("cross-organization profile denial");
    assert_eq!(wrong_organization.status(), reqwest::StatusCode::FORBIDDEN);
    let orphan_ticket = http
        .post(format!("{device_origin}/v1/devices/pairing-tickets"))
        .header("x-service-token", gateway_key)
        .header("x-user-id", &user_id)
        .json(&json!({"organization_id":organization_id,"trust_profile_id":bound_profile_id}))
        .send()
        .await
        .expect("server-owned ticket with selected Trust Profile");
    assert!(orphan_ticket.status().is_success());
    let orphan_ticket: serde_json::Value = orphan_ticket.json().await.unwrap();
    let orphan_pairing_id = orphan_ticket["pairing_id"].as_str().unwrap().to_owned();
    let orphan = http
        .post(format!("{device_origin}/v1/devices/pair"))
        .header("x-service-token", gateway_key)
        .json(&json!({"pairing_code":orphan_ticket["pairing_code"],"platform":"android"}))
        .send()
        .await
        .expect("unconfirmed enrollment response");
    assert!(orphan.status().is_success());
    let orphan: PairingRedeemResult = orphan.json().await.unwrap();
    sqlx::query("UPDATE device_registration_service.device_pairing_confirmations SET issued_at=clock_timestamp()-interval '2 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE pairing_id=$1")
        .bind(&orphan_pairing_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(confirmations.expire_once(&devices).await.unwrap(), 1);
    assert!(
        !devices
            .get(&orphan.registration_id)
            .await
            .unwrap()
            .unwrap()
            .is_active
    );
    let rejected = http
        .post(format!("{device_origin}/v1/devices/pairing-ack"))
        .header("x-service-token", gateway_key)
        .bearer_auth(&orphan.device_credential)
        .json(&json!({"pairing_id":orphan_pairing_id}))
        .send()
        .await
        .expect("expired enrollment acknowledgment response");
    assert_eq!(rejected.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(
        cleanup.run_once().await.expect("orphan key cleanup"),
        (2, 0)
    );
    device_server.abort();
    server.abort();
    issuer_owner.stop().await;
}
