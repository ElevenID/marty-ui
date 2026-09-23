//! Fresh renewal through the packaged binary. Shared named peers are test ports;
//! admission, Core assembly/encryption, durable delivery and assertions stay real.
use std::sync::Arc;

use axum::http::StatusCode;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

use super::issuance_named_peers::{
    counts, start_peers, PeerState, API_KEY, FORMAT, HOLDER, ISSUER, ORGANIZATION, PROFILE,
    SIGNING_KEY, TEMPLATE, TOKEN,
};

use super::renewal_reference_fixture as reference;

const TOKEN_HMAC_KEY: &str = "synthetic-fresh-main-hmac";
const LEGACY_ACCESS_TOKEN: &str = "synthetic-legacy-access-token";

fn access_token_digest(token: &str) -> String {
    let mut hmac = Hmac::<Sha256>::new_from_slice(TOKEN_HMAC_KEY.as_bytes()).unwrap();
    hmac.update(token.as_bytes());
    hex::encode(hmac.finalize().into_bytes())
}

pub(super) async fn stored(pool: &sqlx::PgPool, id: &str) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object(
      'transaction',(SELECT to_jsonb(t) FROM issuance_service.issuance_transactions t WHERE id=$1),
      'credentials',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY id),'[]') FROM issuance_service.issued_credentials c WHERE transaction_id=$1),
      'deliveries',(SELECT COALESCE(jsonb_agg(to_jsonb(d) ORDER BY id),'[]') FROM issuance_service.credential_delivery_records d WHERE transaction_id=$1),
      'events',(SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY id),'[]') FROM issuance_service.issuance_events e WHERE transaction_id=$1))")
        .bind(id).fetch_one(pool).await.unwrap()
}

pub(super) fn assert_offer(uri: &str, pre_auth_code: &Value) {
    let offer = url::Url::parse(uri).unwrap();
    assert_eq!(offer.scheme(), "openid-credential-offer");
    let parameters: Vec<_> = offer.query_pairs().collect();
    assert_eq!(parameters.len(), 1);
    assert_eq!(parameters[0].0, "credential_offer");
    let offer: Value = serde_json::from_str(&parameters[0].1).unwrap();
    assert_eq!(
        offer,
        json!({"credential_issuer":"https://issuer.example/org/synthetic-org","credential_configuration_ids":["EmployeeCredential#sd-jwt"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":pre_auth_code}}})
    );
}

pub(super) async fn run(database_url: &str) {
    run_with_profile(database_url, None, Ingress::Direct).await;
}

pub(super) async fn run_rendered(database_url: &str, redis_url: &str) {
    run_with_profile(database_url, Some(redis_url), Ingress::Direct).await;
}

pub(super) async fn run_gateway(database_url: &str, redis_url: &str) {
    run_with_profile(database_url, Some(redis_url), Ingress::Gateway).await;
}

pub(super) async fn run_envoy(database_url: &str, redis_url: &str) {
    run_with_profile(database_url, Some(redis_url), Ingress::Envoy).await;
}

pub(super) async fn run_kubernetes(database_url: &str, redis_url: &str, gateway: bool) {
    run_with_profile(
        database_url,
        Some(redis_url),
        if gateway {
            Ingress::KubernetesGateway
        } else {
            Ingress::KubernetesDirect
        },
    )
    .await;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ingress {
    Direct,
    Gateway,
    Envoy,
    KubernetesDirect,
    KubernetesGateway,
}

struct CaseDatabaseKeys {
    mode: &'static str,
    source_id: String,
    source_tx_id: String,
    pre_authorized_code: String,
}

fn case_database_keys(authenticated: bool, allow_private_ips: bool) -> CaseDatabaseKeys {
    let mode = if authenticated {
        "authcrypt"
    } else {
        "anoncrypt"
    };
    let suffix = if allow_private_ips {
        ""
    } else {
        "-default-refusal"
    };
    CaseDatabaseKeys {
        mode,
        source_id: format!("fresh-main-source-{mode}{suffix}"),
        source_tx_id: format!("fresh-main-source-tx-{mode}{suffix}"),
        pre_authorized_code: format!("historical-{mode}{suffix}"),
    }
}

async fn run_with_profile(database_url: &str, rendered_redis: Option<&str>, ingress: Ingress) {
    let gateway = matches!(
        ingress,
        Ingress::Gateway | Ingress::Envoy | Ingress::KubernetesGateway
    );
    let envoy = ingress == Ingress::Envoy;
    let kubernetes = matches!(
        ingress,
        Ingress::KubernetesDirect | Ingress::KubernetesGateway
    );
    use super::{
        didcomm_test_fixtures::authcrypt_parties_with_ids,
        didcomm_wallet_fixture::WalletFixture,
        issuance_process::{
            bounded_http_client, isolated_smoke_command, reserve_port, wait_for_health_with_client,
            ChildGuard,
        },
    };
    use marty_issuance_service::{
        credential::CredentialTransactionStatus, credential_postgres::PostgresCredentialRepository,
        initiation::InitiationRepository,
    };
    use std::time::Duration;

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(database_url)
        .await
        .unwrap();
    let cases: &[(bool, bool)] = if gateway {
        &[(false, false), (true, false), (false, true), (true, true)]
    } else {
        &[(false, true), (true, true)]
    };
    for &(authenticated, allow_private_ips) in cases {
        let CaseDatabaseKeys {
            mode,
            source_id,
            source_tx_id,
            pre_authorized_code,
        } = case_database_keys(authenticated, allow_private_ips);
        let wallet = WalletFixture::start(200);
        let endpoint = format!("{}/inbox", wallet.origin);
        let (sender, sender_secret, mut recipient, recipient_secret) =
            authcrypt_parties_with_ids(ISSUER, HOLDER);
        // Reuse the shared document's distinct, fixed synthetic signing key.
        let signer = Arc::new(SigningKey::from_bytes(&[11; 32]));
        let signing_methods: Vec<_> = sender
            .verification_method
            .iter()
            .filter(|method| method.id == format!("{ISSUER}#signing-1"))
            .collect();
        assert_eq!(signing_methods.len(), 1);
        assert_eq!(
            signing_methods[0]
                .public_key_jwk
                .as_ref()
                .unwrap()
                .x
                .as_deref(),
            Some(
                URL_SAFE_NO_PAD
                    .encode(signer.verifying_key().as_bytes())
                    .as_str()
            )
        );
        recipient.service.push(
            serde_json::from_value(
                json!({"id":"#didcomm","type":"DIDCommMessaging","serviceEndpoint":endpoint}),
            )
            .unwrap(),
        );
        let state = PeerState {
            source_id: source_id.clone(),
            sender,
            recipient,
            signer,
            attempts: Arc::default(),
            accepted: Arc::default(),
            signed: Arc::default(),
            allocations: Arc::default(),
            publications: Arc::default(),
            base_gateway: gateway,
            ordinary_wallets: Arc::default(),
        };
        let peers = start_peers(state.clone()).await;
        let legacy = if gateway {
            Some(super::base_runtime_gateway::LegacyFixture::start().await)
        } else {
            None
        };
        let origin = format!("http://127.0.0.1:{}", peers.port);
        let policy = wallet
            .ca_file
            .parent()
            .unwrap()
            .join(if rendered_redis.is_some() {
                "didcomm-encryption-policy.json"
            } else {
                "fresh-main-policy.json"
            });
        let encryption = if authenticated {
            json!({"mode":"authcrypt","sender_x25519_private_key":URL_SAFE_NO_PAD.encode(sender_secret)})
        } else {
            json!({"mode":"anoncrypt"})
        };
        // Inside the exact-owned synthetic wallet directory, removed by its owner.
        std::fs::write(
            &policy,
            json!({"version":1,"issuers":{(ISSUER):encryption}}).to_string(),
        )
        .unwrap();

        let corpus = reference::corpus();
        let initial =
            reference::snapshot(&corpus, reference::case(&corpus, "missing-key"), "before");
        let original = reference::source(initial).unwrap();
        let mut source = reference::transaction(
            initial["transactions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["id"] == original.transaction_id)
                .unwrap(),
        );
        source.id = source_tx_id.clone();
        source.pre_authorized_code = pre_authorized_code;
        source.organization_id = ORGANIZATION.into();
        source.credential_template_id = TEMPLATE.into();
        source.issuer_did = Some(ISSUER.into());
        source.issuer_algorithm = Some("EdDSA".into());
        source.revocation_profile_id = Some(PROFILE.into());
        source.subject_did = Some(HOLDER.into());
        source.application_id = None;
        source.applicant_id = None;
        source.status = CredentialTransactionStatus::Issued;
        source.renewable = true;
        source.reserved_credential_id = Some(source_id.clone());
        source.idempotency_key_hash = None;
        source.idempotency_request_hash = None;
        source.claims = json!({"given_name":"Synthetic"})
            .as_object()
            .unwrap()
            .clone();
        source.delivery_mode = "wallet_only".into();
        source.credential_payload_format = FORMAT.into();
        let repository = PostgresCredentialRepository::new(pool.clone(), TOKEN_HMAC_KEY.as_bytes());
        assert!(
            repository
                .reserve_idempotently(&source)
                .await
                .unwrap()
                .created
        );
        let legacy_access_token_digest = access_token_digest(LEGACY_ACCESS_TOKEN);
        let seeded = sqlx::query(
            "UPDATE issuance_service.issuance_transactions
             SET access_token=$1
             WHERE id=$2 AND organization_id=$3",
        )
        .bind(&legacy_access_token_digest)
        .bind(&source_tx_id)
        .bind(ORGANIZATION)
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(
            seeded.rows_affected(),
            1,
            "legacy access token fixture must update its owned transaction"
        );
        sqlx::query("INSERT INTO issuance_service.issued_credentials
          (id,transaction_id,organization_id,credential_template_id,subject_did,issuer_did,
           revocation_profile_id,status_list_entries,credential_jwt,credential_hash,status,status_updated_at,revoked,issued_at,expires_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,'synthetic-historical-source','synthetic-source-hash','active',$9,false,$9,$10)")
            .bind(&source_id).bind(&source_tx_id).bind(ORGANIZATION).bind(TEMPLATE).bind(HOLDER).bind(ISSUER)
            .bind(PROFILE).bind(json!([{"status_list_id":PROFILE,"index":7}]))
            .bind(source.created_at).bind(source.expires_at).execute(&pool).await.unwrap();
        let source_before_startup = stored(&pool, &source_tx_id).await;
        assert_eq!(
            source_before_startup["transaction"]["access_token"], legacy_access_token_digest,
            "seeded legacy token digest must exercise the startup expiry backfill"
        );
        assert_ne!(
            source_before_startup["transaction"]["access_token"], LEGACY_ACCESS_TOKEN,
            "legacy access token must remain one-way hashed at rest"
        );
        assert!(
            source_before_startup["transaction"]["access_token_expires_at"].is_null(),
            "seeded legacy token must begin without a bounded lifetime"
        );
        let startup_migration_not_before: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&pool)
                .await
                .unwrap();
        let (http_listener, http_port) = reserve_port();
        let (grpc_listener, grpc_port) = if envoy {
            (
                std::net::TcpListener::bind("127.0.0.1:9005")
                    .expect("owned Envoy native port is free"),
                9005,
            )
        } else {
            reserve_port()
        };
        let (gateway_reservation, gateway_port) = reserve_port();
        let mut rendered_model = None;
        let mut command = if let Some(redis_url) = rendered_redis {
            let spec = json!({
                "inputs": {
                    "ISSUANCE_API_KEY":API_KEY, "GRPC_SERVICE_TOKEN":TOKEN,
                    "SIGNING_KEYS_INTERNAL_API_KEY":SIGNING_KEY,
                    "TOKEN_HMAC_KEY":TOKEN_HMAC_KEY,
                    "INTEGRATION_SECRET_MASTER_KEY":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                    "PUBLIC_API_URL":"https://issuer.example", "UI_BASE_URL":"http://localhost:3000",
                    "ISSUANCE_OFFER_TTL_MINUTES":"10080", "TOKEN_RATE_LIMIT":"30",
                    "CANVAS_PORTABLE_INTEGRATION_ENABLED":"false", "CANVAS_PILOT_ORGANIZATION_IDS":""
                },
                "http_port":http_port, "grpc_port":grpc_port, "gateway_port":gateway_port,
                "database_url":database_url, "redis_url":redis_url,
                "peer_origin":origin, "legacy_origin":legacy.as_ref().map_or_else(|| format!("http://127.0.0.1:{gateway_port}"), super::base_runtime_gateway::LegacyFixture::origin),
                "ca_file":wallet.ca_file, "policy_directory":wallet.ca_file.parent().unwrap(),
                "authcrypt":authenticated, "allow_private_ips":allow_private_ips
            });
            // Native-only stage reserves but does not launch the gateway. The
            // final composed gate supplies its actual legacy peer and binary.
            let model = if kubernetes {
                super::resolved_kubernetes_runtime::render(&spec)
                    .expect("actual composed Kubernetes model and closed reference resolution")
            } else {
                super::rendered_base_process::RenderedBase::render(&spec).resolved()
            };
            let command = model.native_command();
            rendered_model = Some(model);
            command
        } else {
            let mut command = isolated_smoke_command(http_port, grpc_port);
            command
                .env("DATABASE_URL", database_url)
                .env("ISSUANCE_API_KEY", API_KEY)
                .env("GRPC_SERVICE_TOKEN", TOKEN)
                .env("TOKEN_HMAC_KEY", TOKEN_HMAC_KEY)
                .env("ORG_GRPC_TARGET", &origin)
                .env("CT_GRPC_TARGET", &origin)
                .env("RP_GRPC_TARGET", &origin)
                .env("CREDENTIAL_TEMPLATE_SERVICE_URL", &origin)
                .env("REVOCATION_PROFILE_SERVICE_URL", &origin)
                .env("SIGNING_KEYS_INTERNAL_URL", &origin)
                .env("SIGNING_KEYS_INTERNAL_API_KEY", SIGNING_KEY)
                .env("DIDCOMM_DID_WEB_INTERNAL_BASE_URL", &origin)
                .env("DIDCOMM_ALLOW_PRIVATE_IPS", "true")
                .env("DIDCOMM_ENCRYPTION_POLICY_FILE", &policy)
                .env("DIDCOMM_TLS_CA_FILE", &wallet.ca_file);
            command
        };
        drop((http_listener, grpc_listener, gateway_reservation));
        let mut child = ChildGuard(command.spawn().unwrap());
        let client = bounded_http_client(Duration::from_secs(20));
        assert_eq!(
            tokio::time::timeout(
                Duration::from_secs(15),
                wait_for_health_with_client(http_port, &client)
            )
            .await
            .unwrap(),
            Some(json!({"status":"healthy","service":"issuance-service"}))
        );
        let startup_migration_not_after: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&pool)
                .await
                .unwrap();
        // Startup grants a legacy token one bounded 30-minute lifetime. Prove
        // that backfill against database time, then preserve the pre-start
        // snapshot so every other source mutation remains exactly visible.
        let source_before = stored(&pool, &source_tx_id).await;
        let backfilled_expiry: chrono::DateTime<chrono::Utc> = source_before["transaction"]
            ["access_token_expires_at"]
            .as_str()
            .expect("startup migration must bound the seeded legacy token")
            .parse()
            .unwrap();
        let legacy_token_lifetime = chrono::Duration::seconds(1800);
        assert!(
            backfilled_expiry >= startup_migration_not_before + legacy_token_lifetime
                && backfilled_expiry <= startup_migration_not_after + legacy_token_lifetime,
            "startup migration must grant exactly one bounded 30-minute legacy-token lifetime"
        );
        let mut expected_after_startup = source_before_startup;
        expected_after_startup["transaction"]["access_token_expires_at"] =
            source_before["transaction"]["access_token_expires_at"].clone();
        assert_eq!(
            source_before, expected_after_startup,
            "startup migration changed seeded renewal domain state"
        );
        let gateway_fixture = if gateway {
            let fixture = super::base_runtime_gateway::GatewayFixture::start(
                rendered_model.as_ref().unwrap(),
                gateway_port,
            )
            .await;
            fixture.deny_invalid_client().await;
            fixture.deny_foreign_owner(&source_id).await;
            Some(fixture)
        } else {
            None
        };
        let request_port = if gateway { gateway_port } else { http_port };
        let request_key = if gateway {
            super::issuance_named_peers::CLIENT_KEY
        } else {
            API_KEY
        };
        let response = client
            .post(format!(
                "http://127.0.0.1:{request_port}/v1/issued-credentials/{source_id}/renew"
            ))
            .header("x-api-key", request_key)
            .header("x-organization-id", ORGANIZATION)
            .send()
            .await
            .unwrap();
        let status = response.status();
        let response: Value = response.json().await.unwrap();
        assert_eq!(status, StatusCode::OK, "{mode}: {response}");
        let id = response["transaction_id"].as_str().unwrap();
        assert!(uuid::Uuid::parse_str(id).is_ok());
        let result = stored(&pool, id).await;
        assert_offer(
            response["credential_offer_uri"].as_str().unwrap(),
            &result["transaction"]["pre_auth_code"],
        );
        if !allow_private_ips {
            assert_eq!(
                response,
                json!({
                    "source_credential_id":source_id,"transaction_id":id,
                    "credential_offer_uri":response["credential_offer_uri"],
                    "credential_offer_uris":{"didcomm":format!("didcomm://pending?transaction_id={id}")},
                    "credential_offer_labels":{"didcomm":"Synthetic Wallet"},
                    "expires_at":response["expires_at"]
                })
            );
            assert_eq!(
                response["expires_at"]
                    .as_str()
                    .unwrap()
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap(),
                result["transaction"]["expires_at"]
                    .as_str()
                    .unwrap()
                    .parse::<chrono::DateTime<chrono::Utc>>()
                    .unwrap()
            );
            assert_eq!(stored(&pool, &source_tx_id).await, source_before);
            let capture = wallet.captures().await;
            assert_eq!(capture["messages"], json!([]));
            assert_eq!(capture["failures"], 0);
            assert_eq!(result["events"], json!([]));
            assert!(state.publications.lock().unwrap().is_empty());
            legacy.as_ref().unwrap().assert_no_fallback();
            gateway_fixture.unwrap().close();
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            peers.close().await;
            legacy.unwrap().close().await;
            wallet.close_verified();
            continue;
        }
        assert_eq!(
            result["transaction"]["status"],
            "issued",
            "mode={mode}; peer paths={:?}; signing attempts={}; delivery rows={}",
            state.attempts.lock().unwrap(),
            state.signed.lock().unwrap().len(),
            result["deliveries"].as_array().unwrap().len()
        );
        assert_eq!(result["transaction"]["renewal_of_credential_id"], source_id);
        assert!(result["transaction"]["application_id"].is_null());
        assert_eq!(result["credentials"].as_array().unwrap().len(), 1);
        assert_eq!(result["deliveries"].as_array().unwrap().len(), 1);
        assert_eq!(result["deliveries"][0]["status"], "delivered");
        assert_eq!(result["events"].as_array().unwrap().len(), 1);
        assert_eq!(result["events"][0]["event_type"], "credential_issued");
        assert_eq!(result["events"][0]["transaction_id"], id);
        assert!(result["events"][0]["application_id"].is_null());
        assert_eq!(
            response,
            json!({"source_credential_id":source_id,"transaction_id":id,
            "credential_offer_uri":response["credential_offer_uri"],
            "credential_offer_uris":{"didcomm":format!("didcomm://{endpoint}")},
            "credential_offer_labels":{"didcomm":"Synthetic Wallet"},
            "expires_at":response["expires_at"]})
        );
        let expiry: chrono::DateTime<chrono::Utc> =
            response["expires_at"].as_str().unwrap().parse().unwrap();
        let persisted_expiry: chrono::DateTime<chrono::Utc> = result["transaction"]["expires_at"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(expiry, persisted_expiry);
        let captures = wallet.captures().await;
        assert_eq!(captures["failures"], 0);
        assert_eq!(captures["messages"].as_array().unwrap().len(), 1);
        let encrypted = captures["messages"][0].as_str().unwrap();
        let plaintext = if authenticated {
            let envelope = marty_didcomm::decrypt_authenticated_jwe(
                encrypted,
                &recipient_secret,
                &state.recipient,
                &state.sender,
            )
            .unwrap();
            assert_eq!(envelope.sender_kid, format!("{ISSUER}#key-1"));
            assert_eq!(envelope.recipient_kid, format!("{HOLDER}#key-1"));
            envelope.plaintext
        } else {
            marty_didcomm::decrypt_jwe(encrypted, &recipient_secret).unwrap()
        };
        let message = marty_didcomm::unpack_didcomm_message(&plaintext).unwrap();
        assert_eq!(message.from.as_deref(), Some(ISSUER));
        assert_eq!(message.to, Some(vec![HOLDER.into()]));
        assert_eq!(message.thid.as_deref(), Some(id));
        assert_eq!(
            message.r#type,
            "https://didcomm.org/issue-credential/3.0/issue-credential"
        );
        assert_eq!(
            message.body,
            json!({"goal_code":"issue-vc","comment":"Here is your credential"})
        );
        assert_eq!(message.attachments.len(), 1);
        let attachment = &message.attachments[0];
        assert_eq!(
            attachment.id.as_deref(),
            result["credentials"][0]["id"].as_str()
        );
        assert_eq!(attachment.format.as_deref(), Some(FORMAT));
        assert_eq!(
            attachment.media_type.as_deref(),
            Some("application/vc+sd-jwt")
        );
        assert!(attachment.data.json.is_none() && attachment.data.links.is_none());
        let signed = URL_SAFE_NO_PAD
            .decode(attachment.data.base64.as_deref().unwrap())
            .unwrap();
        assert_eq!(
            signed,
            result["credentials"][0]["credential_jwt"]
                .as_str()
                .unwrap()
                .as_bytes()
        );
        let signed = std::str::from_utf8(&signed).unwrap();
        let jws = signed.split('~').next().unwrap();
        let parts: Vec<_> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        let input = format!("{}.{}", parts[0], parts[1]);
        let signature =
            ed25519_dalek::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap())
                .unwrap();
        state
            .signer
            .verifying_key()
            .verify_strict(input.as_bytes(), &signature)
            .unwrap();
        assert_eq!(*state.signed.lock().unwrap(), vec![input.into_bytes()]);
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], ISSUER);
        // materialize_credential makes all ordinary claims selectively
        // disclosable when no explicit list is configured. Verify the actual
        // disclosure against the digest protected by the signed JWT.
        use sha2::{Digest, Sha256};
        let disclosures: Vec<_> = signed
            .split('~')
            .skip(1)
            .filter(|value| !value.is_empty())
            .collect();
        assert_eq!(disclosures.len(), 1);
        let disclosure: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(disclosures[0]).unwrap()).unwrap();
        assert_eq!(disclosure.as_array().unwrap().len(), 3);
        assert!(disclosure[0].as_str().is_some_and(|salt| !salt.is_empty()));
        assert_eq!(disclosure[1], "given_name");
        assert_eq!(disclosure[2], "Synthetic");
        assert_eq!(claims["_sd_alg"], "sha-256");
        assert_eq!(
            claims["_sd"],
            json!([URL_SAFE_NO_PAD.encode(Sha256::digest(disclosures[0].as_bytes()))])
        );
        assert!(claims.get("given_name").is_none());
        assert_eq!(claims["sub"], HOLDER);
        assert_eq!(
            claims["vct"],
            "https://issuer.example/credentials/EmployeeCredential"
        );
        assert_eq!(
            result["deliveries"][0]["metadata"]["didcomm_message_id"],
            message.id
        );
        assert_eq!(
            result["credentials"][0]["renewed_from_credential_id"],
            source_id
        );
        let source_after = stored(&pool, &source_tx_id).await;
        assert_eq!(source_after["transaction"], source_before["transaction"]);
        assert_eq!(source_after["credentials"][0]["status"], "revoked");
        assert_eq!(source_after["credentials"][0]["revoked"], true);
        assert_eq!(
            source_after["credentials"][0]["renewed_to_credential_id"],
            result["credentials"][0]["id"]
        );
        assert_eq!(state.allocations.lock().unwrap().len(), 1);
        assert_eq!(
            state.allocations.lock().unwrap()[0]["credential_id"],
            result["credentials"][0]["id"]
        );
        assert_eq!(
            result["credentials"][0]["status_list_entries"][0]["index"],
            8
        );
        assert_eq!(claims["credentialStatus"]["statusListIndex"], "8");
        assert_eq!(state.publications.lock().unwrap().len(), 1);
        let attempts = state.attempts.lock().unwrap().clone();
        let accepted = state.accepted.lock().unwrap().clone();
        assert_eq!(
            counts(&attempts),
            counts(&accepted),
            "all attempted peer requests validated"
        );
        for path in [
            "/marty.ui.organization.v1.OrganizationService/GetOrganization",
            "/marty.ui.credential_template.v1.CredentialTemplateService/GetTemplate",
            "/marty.ui.revocation_profile.v1.RevocationProfileService/GetRevocationProfile",
        ] {
            assert_eq!(
                counts(&accepted).get(path),
                Some(&1),
                "healthy exact admission dependency"
            );
        }
        if let Some(gateway_fixture) = gateway_fixture {
            let envoy_fixture = if envoy {
                Some(super::envoy_runtime::EnvoyFixture::start().await)
            } else {
                None
            };
            if let Some(fixture) = &envoy_fixture {
                fixture.boundaries(&pool, &state).await;
            }
            super::base_runtime_didcomm::run(super::base_runtime_didcomm::Input {
                pool: &pool,
                gateway: &gateway_fixture,
                peers: &state,
                wallet: &wallet,
                authenticated,
                recipient_secret: &recipient_secret,
                renewal_id: id,
                envoy: envoy_fixture.as_ref(),
            })
            .await;
            super::base_runtime_ordinary::run(&pool, &gateway_fixture, &state).await;
            super::base_runtime_canvas::run(&pool, &gateway_fixture, !authenticated).await;
            if let Some(fixture) = &envoy_fixture {
                fixture.ordinary_rpc(&pool, &state).await;
            }
            gateway_fixture
                .native_issued_credential_control(&source_id)
                .await;
            gateway_fixture.legacy_control().await;
            legacy.as_ref().unwrap().assert_no_fallback();
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            if let Some(fixture) = envoy_fixture {
                fixture.native_unavailable(&pool, &state).await;
                fixture.close().await;
            }
            gateway_fixture
                .native_owner_unavailable(&source_id, legacy.as_ref().unwrap())
                .await;
            gateway_fixture.close();
        } else {
            assert!(child.0.try_wait().unwrap().is_none());
            child.0.kill().unwrap();
            child.0.wait().unwrap();
        }
        assert_eq!(
            counts(&state.attempts.lock().unwrap()),
            counts(&state.accepted.lock().unwrap()),
            "every final-stage peer request must be validated"
        );
        peers.close().await;
        if let Some(legacy) = legacy {
            legacy.close().await;
        }
        wallet.close_verified();
    }
    pool.close().await;
}

#[test]
fn composed_gateway_cases_have_unique_database_keys() {
    let mut source_ids = std::collections::BTreeSet::new();
    let mut transaction_ids = std::collections::BTreeSet::new();
    let mut pre_authorized_codes = std::collections::BTreeSet::new();
    for (authenticated, allow_private_ips) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let keys = case_database_keys(authenticated, allow_private_ips);
        assert!(source_ids.insert(keys.source_id));
        assert!(transaction_ids.insert(keys.source_tx_id));
        assert!(pre_authorized_codes.insert(keys.pre_authorized_code));
    }
    assert_eq!(source_ids.len(), 4);
    assert_eq!(transaction_ids.len(), 4);
    assert_eq!(pre_authorized_codes.len(), 4);
}
