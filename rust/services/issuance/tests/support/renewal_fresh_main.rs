//! Fresh renewal through the packaged binary. Only named control-plane/signing
//! peers are synthetic; admission, Core assembly/encryption and delivery are real.
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex},
};

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::StreamBody;
use hyper::body::Frame;
use marty_didcomm::DidDocument;
use marty_issuance_service::{
    credential_template_proto as template, organization_proto as organization,
    revocation_profile_proto as revocation,
};
use prost::Message;
use serde_json::{json, Value};

use super::didcomm_gateway_replay::OwnedHttp;

const ORGANIZATION: &str = "synthetic-org";
const ISSUER: &str = "did:web:issuer.example:issuer";
const HOLDER: &str = "did:web:issuer.example:holder";
const TEMPLATE: &str = "didcomm-template";
const PROFILE: &str = "didcomm-status";
const TOKEN: &str = "synthetic-renewal-fresh-main-service-token";
const API_KEY: &str = "synthetic-renewal-fresh-main-management-key";
const SIGNING_KEY: &str = "synthetic-renewal-fresh-main-signing-key";
const FORMAT: &str = "w3c_vcdm_v2_sd_jwt";

#[derive(Clone)]
struct PeerState {
    source_id: String,
    sender: DidDocument,
    recipient: DidDocument,
    signer: Arc<SigningKey>,
    // Record before decoding or validation so failed requests cannot disappear.
    attempts: Arc<Mutex<Vec<String>>>,
    accepted: Arc<Mutex<Vec<String>>>,
    signed: Arc<Mutex<Vec<Vec<u8>>>>,
    allocations: Arc<Mutex<Vec<Value>>>,
    publications: Arc<Mutex<Vec<Value>>>,
}

fn decode_request<M: Message + Default>(bytes: &[u8]) -> M {
    assert!(bytes.len() >= 5, "complete unary gRPC frame");
    assert_eq!(bytes[0], 0, "uncompressed synthetic unary request");
    let length = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
    assert_eq!(bytes.len(), length + 5, "exactly one request frame");
    M::decode(&bytes[5..]).unwrap()
}

fn grpc_response(message: impl Message) -> Response {
    let payload = message.encode_to_vec();
    let mut encoded = vec![0];
    encoded.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    encoded.extend_from_slice(&payload);
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().unwrap());
    let frames: Vec<Result<Frame<Bytes>, Infallible>> = vec![
        Ok(Frame::data(Bytes::from(encoded))),
        Ok(Frame::trailers(trailers)),
    ];
    Response::builder()
        .header("content-type", "application/grpc")
        .body(Body::new(StreamBody::new(futures_util::stream::iter(
            frames,
        ))))
        .unwrap()
}

fn query(request: &Request<Body>) -> BTreeMap<String, String> {
    url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

async fn peer(State(state): State<PeerState>, request: Request<Body>) -> Response {
    let path = request.uri().path().to_owned();
    state.attempts.lock().unwrap().push(path.clone());
    let method = request.method().clone();
    let args = query(&request);
    let headers = request.headers().clone();
    if path.starts_with("/marty.ui.") {
        assert_eq!(request.version(), axum::http::Version::HTTP_2);
        assert_eq!(headers["content-type"], "application/grpc");
        assert!(args.is_empty());
    }
    let bytes = to_bytes(request.into_body(), 128 * 1024).await.unwrap();
    let response = match path.as_str() {
        "/marty.ui.organization.v1.OrganizationService/GetOrganization" => {
            assert_eq!(method, "POST");
            assert_eq!(headers["x-service-token"], TOKEN);
            let request: organization::GetOrganizationRequest = decode_request(&bytes);
            assert_eq!(
                request,
                organization::GetOrganizationRequest {
                    organization_id: ORGANIZATION.into()
                }
            );
            grpc_response(organization::OrganizationResponse {
                id: ORGANIZATION.into(),
                ..Default::default()
            })
        }
        "/marty.ui.credential_template.v1.CredentialTemplateService/GetTemplate" => {
            assert_eq!(method, "POST");
            assert_eq!(headers["x-service-token"], TOKEN);
            let request: template::GetTemplateRequest = decode_request(&bytes);
            assert_eq!(
                request,
                template::GetTemplateRequest {
                    template_id: TEMPLATE.into()
                }
            );
            grpc_response(template::TemplateResponse {
                id: TEMPLATE.into(), organization_id: ORGANIZATION.into(), status: "active".into(),
                credential_type: "EmployeeCredential".into(),
                vct: "https://issuer.example/credentials/EmployeeCredential".into(),
                credential_payload_format: FORMAT.into(), issuer_did: ISSUER.into(),
                issuer_algorithm: "EdDSA".into(), revocation_profile_id: PROFILE.into(),
                wallet_configs_json: json!([{"wallet_id":"didcomm","format_variant":"didcomm_v2","display_name":"Synthetic Wallet"}]).to_string(),
                validity_rules: Some(template::ValidityRules { default_validity_days: 365, renewable: true, renewal_window_days: 30, ..Default::default() }),
                ..Default::default()
            })
        }
        "/marty.ui.revocation_profile.v1.RevocationProfileService/GetRevocationProfile" => {
            assert_eq!(method, "POST");
            assert_eq!(headers["x-service-token"], TOKEN);
            let request: revocation::GetRevocationProfileRequest = decode_request(&bytes);
            assert_eq!(
                request,
                revocation::GetRevocationProfileRequest {
                    profile_id: PROFILE.into()
                }
            );
            grpc_response(revocation::RevocationProfileResponse {
                id: PROFILE.into(),
                organization_id: ORGANIZATION.into(),
                status: "active".into(),
                ..Default::default()
            })
        }
        "/issuer/did.json" | "/holder/did.json" => {
            assert_eq!(method, "GET");
            assert!(bytes.is_empty());
            assert!(args.is_empty());
            Json(if path.starts_with("/issuer/") {
                state.sender.clone()
            } else {
                state.recipient.clone()
            })
            .into_response()
        }
        "/resolve-issuer-did" => {
            assert_eq!(method, "GET");
            assert_eq!(headers["x-api-key"], SIGNING_KEY);
            assert_eq!(
                args.get("organization_id").map(String::as_str),
                Some(ORGANIZATION)
            );
            assert_eq!(args.get("issuer_did").map(String::as_str), Some(ISSUER));
            assert_eq!(args.get("algorithm").map(String::as_str), Some("EdDSA"));
            assert!(bytes.is_empty());
            Json(json!({"ok":true,"issuer_did":ISSUER,"algorithm":"EdDSA",
                "issuer_profile":{"id":"synthetic-fresh-main-profile","status":"active"},
                "signing_service_id":"synthetic-fresh-main-signer","signing_key_reference":"synthetic-opaque-signing-key",
                "verification_method_id":format!("{ISSUER}#signing-1"),
                "public_jwk":{"kty":"OKP","crv":"Ed25519","x":URL_SAFE_NO_PAD.encode(state.signer.verifying_key().as_bytes())}})).into_response()
        }
        "/issuer-dids/sign" => {
            assert_eq!(method, "POST");
            assert_eq!(headers["x-api-key"], SIGNING_KEY);
            assert_eq!(
                args,
                BTreeMap::from([("organization_id".into(), ORGANIZATION.into())])
            );
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["issuer_did"], ISSUER);
            assert_eq!(body["algorithm"], "EdDSA");
            let payload = URL_SAFE_NO_PAD
                .decode(body["payload_b64"].as_str().unwrap())
                .unwrap();
            let signature = state.signer.sign(&payload);
            state.signed.lock().unwrap().push(payload);
            Json(json!({"ok":true,"issuer_did":ISSUER,"algorithm":"EdDSA",
                "verification_method_id":format!("{ISSUER}#signing-1"),
                "signature_b64":URL_SAFE_NO_PAD.encode(signature.to_bytes())}))
            .into_response()
        }
        "/internal/revocation-profiles/didcomm-status/reserve-index" => {
            assert_eq!(method, "POST");
            assert_eq!(headers["x-service-token"], TOKEN);
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["organization_id"], ORGANIZATION);
            assert_eq!(body["credential_format"], "sd_jwt_vc");
            assert!(body["credential_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty()));
            state.allocations.lock().unwrap().push(body);
            Json(json!({"organization_id":ORGANIZATION,"index":8,"status_list_url":"https://status.example/synthetic"})).into_response()
        }
        "/internal/revocation-profiles/didcomm-status/process-revocation" => {
            assert_eq!(method, "POST");
            assert_eq!(headers["x-service-token"], TOKEN);
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                body,
                json!({"organization_id":ORGANIZATION,"credential_id":state.source_id,"index":7,"status":"revoked","credential_format":"sd_jwt_vc","reason":"Superseded by renewed credential"})
            );
            state.publications.lock().unwrap().push(body);
            Json(json!({"success":true,"organization_id":ORGANIZATION,"index":7,"status_list_url":"https://status.example/synthetic"})).into_response()
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    state.accepted.lock().unwrap().push(path);
    response
}

async fn start_peers(state: PeerState) -> OwnedHttp {
    OwnedHttp::start(Router::new().fallback(peer).with_state(state)).await
}

use super::renewal_reference_fixture as reference;

async fn stored(pool: &sqlx::PgPool, id: &str) -> Value {
    sqlx::query_scalar("SELECT jsonb_build_object(
      'transaction',(SELECT to_jsonb(t) FROM issuance_service.issuance_transactions t WHERE id=$1),
      'credentials',(SELECT COALESCE(jsonb_agg(to_jsonb(c) ORDER BY id),'[]') FROM issuance_service.issued_credentials c WHERE transaction_id=$1),
      'deliveries',(SELECT COALESCE(jsonb_agg(to_jsonb(d) ORDER BY id),'[]') FROM issuance_service.credential_delivery_records d WHERE transaction_id=$1),
      'events',(SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY id),'[]') FROM issuance_service.issuance_events e WHERE transaction_id=$1))")
        .bind(id).fetch_one(pool).await.unwrap()
}

fn counts(values: &[String]) -> BTreeMap<&str, usize> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value.as_str()).or_default() += 1;
    }
    counts
}

pub(super) async fn run(database_url: &str) {
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
    for authenticated in [false, true] {
        let mode = if authenticated {
            "authcrypt"
        } else {
            "anoncrypt"
        };
        let source_id = format!("fresh-main-source-{mode}");
        let source_tx_id = format!("fresh-main-source-tx-{mode}");
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
        };
        let peers = start_peers(state.clone()).await;
        let origin = format!("http://127.0.0.1:{}", peers.port);
        let policy = wallet
            .ca_file
            .parent()
            .unwrap()
            .join("fresh-main-policy.json");
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
        source.pre_authorized_code = format!("historical-{mode}");
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
        let repository =
            PostgresCredentialRepository::new(pool.clone(), b"synthetic-fresh-main-hmac");
        assert!(
            repository
                .reserve_idempotently(&source)
                .await
                .unwrap()
                .created
        );
        sqlx::query("INSERT INTO issuance_service.issued_credentials
          (id,transaction_id,organization_id,credential_template_id,subject_did,issuer_did,
           revocation_profile_id,status_list_entries,credential_jwt,credential_hash,status,status_updated_at,revoked,issued_at,expires_at)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,'synthetic-historical-source','synthetic-source-hash','active',$9,false,$9,$10)")
            .bind(&source_id).bind(&source_tx_id).bind(ORGANIZATION).bind(TEMPLATE).bind(HOLDER).bind(ISSUER)
            .bind(PROFILE).bind(json!([{"status_list_id":PROFILE,"index":7}]))
            .bind(source.created_at).bind(source.expires_at).execute(&pool).await.unwrap();
        let source_before = stored(&pool, &source_tx_id).await;
        let (http_listener, http_port) = reserve_port();
        let (grpc_listener, grpc_port) = reserve_port();
        let mut command = isolated_smoke_command(http_port, grpc_port);
        command
            .env("DATABASE_URL", database_url)
            .env("ISSUANCE_API_KEY", API_KEY)
            .env("GRPC_SERVICE_TOKEN", TOKEN)
            .env("TOKEN_HMAC_KEY", "synthetic-fresh-main-hmac")
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
        drop((http_listener, grpc_listener));
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
        let response = client
            .post(format!(
                "http://127.0.0.1:{http_port}/v1/issued-credentials/{source_id}/renew"
            ))
            .header("x-api-key", API_KEY)
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
        let offer = url::Url::parse(response["credential_offer_uri"].as_str().unwrap()).unwrap();
        assert_eq!(offer.scheme(), "openid-credential-offer");
        let parameters: Vec<_> = offer.query_pairs().collect();
        assert_eq!(parameters.len(), 1);
        assert_eq!(parameters[0].0, "credential_offer");
        let offer: Value = serde_json::from_str(&parameters[0].1).unwrap();
        assert_eq!(
            offer,
            json!({"credential_issuer":"https://issuer.example/org/synthetic-org","credential_configuration_ids":["EmployeeCredential#sd-jwt"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":result["transaction"]["pre_auth_code"]}}})
        );

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
        assert!(child.0.try_wait().unwrap().is_none());
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        peers.close().await;
        wallet.close_verified();
    }
    pool.close().await;
}
