//! Receipt-origin qualification with real TLS Transit, Redis and the HTTP router.
//! Run only through scripts/with_disposable_delegated_receipt_kms.py. No private
//! signing/MAC key or administrative provider token enters this test process.

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, SecondsFormat, Utc};
use marty_signing_grant::{
    delegated_decision::{
        EVALUATION_PROFILE, KEY_PURPOSE, PROFILE_FORMAT, RECEIPT_PROFILE, SIGN_ROUTE, WIRE_FORMAT,
    },
    mint_bound,
    minter::GrantMinter,
    replay::RedisGrantReplayStore,
    transit::TransitGrantClient,
    verifier::GrantVerifier,
    GrantBinding, SigningOrigin, HEADER_NAME,
};
use marty_signing_keys::{
    documents::{DidVerificationRelationship, DocumentStore, PublishDidRequest},
    kms::{public_key, ProviderRequest},
    profiles::{FindProfilesRequest, ProfileStore},
    registry::{storage_key, RegistryStore},
};
use redis::AsyncCommands;
use serde_json::{json, Value};
use std::{fs, path::PathBuf};
use tower::ServiceExt;
use uuid::Uuid;

#[path = "support/disposable_backends.rs"]
mod disposable_backends;

const READ_CREDENTIAL: &str = "fixture-receipt-resolve-api-key-00000001";
const SIGN_CREDENTIAL: &str = "fixture-receipt-issuer-sign-api-key-0001";
const GATEWAY_CREDENTIAL: &str = "fixture-receipt-gateway-sign-api-key-001";
const SERVICE: &str = "receipt-custody";
const PROFILE: &str = "receipt-profile";

fn setting(name: &str) -> String {
    std::env::var(name).expect("owned receipt fixture setting")
}

fn token_file(role: &str) -> PathBuf {
    let path = PathBuf::from(setting(&format!("MARTY_TEST_RECEIPT_{role}_TOKEN_FILE")));
    assert!(path.is_absolute());
    path
}

fn token(role: &str) -> String {
    fs::read_to_string(token_file(role)).expect("owned fixture leaf token")
}

fn provider_client() -> reqwest::Client {
    let ca = reqwest::Certificate::from_pem(
        &fs::read(setting("BAO_CACERT")).expect("disposable public CA"),
    )
    .unwrap();
    reqwest::Client::builder()
        .https_only(true)
        .tls_certs_only([ca])
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn provider_sign_calls(key: &str) -> usize {
    let audit = fs::read_to_string(setting("MARTY_TEST_RECEIPT_AUDIT_FILE"))
        .expect("private fixture provider audit");
    let path = format!("transit/sign/{key}");
    audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("complete provider audit record"))
        .filter(|record| record["type"] == "request" && record["request"]["path"] == path)
        .count()
}

async fn call(
    app: &Router,
    route: &str,
    credential: &str,
    body: &Value,
    grant: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::post(route)
        .header("content-type", "application/json")
        .header("x-api-key", credential);
    if let Some(grant) = grant {
        request = request.header(HEADER_NAME, grant);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = serde_json::from_slice(&to_bytes(response.into_body(), 262_144).await.unwrap())
        .expect("bounded JSON router response");
    (status, body)
}

struct Fixture {
    endpoint: String,
    organization: String,
    issuer: String,
    kid: String,
    key: String,
    algorithm: String,
    jwk: Value,
    service: Value,
    profile: Value,
    registry: RegistryStore,
    profiles: ProfileStore,
    documents: DocumentStore,
    minter: GrantMinter,
}

impl Fixture {
    async fn new(algorithm: &str) -> Self {
        let redis_url = disposable_backends::disposable_redis_url().await;
        let envelope = disposable_backends::disposable_openbao_envelope().await;
        let endpoint = setting("MARTY_TEST_OPENBAO_URL");
        assert_eq!(setting("BAO_ADDR"), endpoint);
        let organization = Uuid::new_v4().to_string();
        let issuer = format!("did:web:receipt.example:orgs:{}", Uuid::new_v4().simple());
        let kid = format!("{issuer}#receipt-key");
        let key = setting(if algorithm == "ES256" {
            "MARTY_TEST_RECEIPT_ES256_KEY"
        } else {
            "MARTY_TEST_RECEIPT_ED25519_KEY"
        });
        let service = json!({
            "id": SERVICE, "name": SERVICE, "service_type": "custom-transit-compatible",
            "provider": "openbao", "endpoint": endpoint, "ca_cert_file": setting("BAO_CACERT"),
            "mount": "transit", "auth_mode": "token", "auth_reference": token("SIGNER"),
            "key_reference": key, "algorithm": algorithm, "algorithms": [algorithm],
            "key_purposes": [KEY_PURPOSE, "vc_jwt_issuer"],
            "credential_formats": [WIRE_FORMAT, "dc+sd-jwt"]
        });
        let metadata = public_key(ProviderRequest {
            service_config: service.clone(),
        })
        .await
        .expect("actual scoped Transit public-key read");
        let jwk = metadata.get("public_jwk").unwrap_or(&metadata).clone();
        assert!(jwk.is_object() && jwk.get("d").is_none());
        let registry = RegistryStore::connect(&redis_url)
            .await
            .unwrap()
            .with_auth_envelopes(Some(envelope));
        let profiles = ProfileStore::from_connection(registry.connection());
        let documents = DocumentStore::from_connection(registry.connection());
        let profile = json!({
            "id": PROFILE, "organization_id": organization, "status": "active",
            "issuer_did": issuer, "verification_method_id": kid,
            "signing_service_id": SERVICE, "signing_key_reference": key,
            "credential_format": PROFILE_FORMAT, "key_purpose": KEY_PURPOSE,
            "algorithm": algorithm, "issuer_mode": "org_managed"
        });
        let fixture = Self {
            minter: GrantMinter::for_managed_openbao(
                &endpoint,
                SigningOrigin::DelegatedDecision,
                token_file("MINT"),
            )
            .unwrap(),
            endpoint,
            organization,
            issuer,
            kid,
            key,
            algorithm: algorithm.into(),
            jwk,
            service,
            profile,
            registry,
            profiles,
            documents,
        };
        fixture.save_service(fixture.service.clone()).await;
        fixture
            .profiles
            .put(&fixture.organization, PROFILE, fixture.profile.clone())
            .await
            .unwrap();
        fixture
            .documents
            .publish_did(
                &fixture.organization,
                SERVICE,
                PublishDidRequest {
                    jwk: fixture.jwk.clone(),
                    public_domain: "receipt.example".into(),
                    did_id: Some(fixture.issuer.clone()),
                    org_slug: None,
                    fragment: Some("receipt-key".into()),
                    key_reference: Some(fixture.key.clone()),
                    cert_pem: None,
                    cert_chain_pem: None,
                    relationship: DidVerificationRelationship::AssertionMethod,
                },
            )
            .await
            .unwrap();
        fixture
    }

    async fn save_service(&self, service: Value) {
        self.registry
            .save(
                &self.organization,
                &json!({
                    "services": [service], "default_service_id": SERVICE,
                    "key_reference_purposes": {(SERVICE): {(self.key.clone()): [KEY_PURPOSE]}}
                }),
            )
            .await
            .unwrap();
    }

    fn router(&self, enabled: bool) -> Router {
        let verifier = GrantVerifier::for_managed_openbao_with_delegated_decisions(
            &self.endpoint,
            token_file("VERIFY"),
            RedisGrantReplayStore::new(self.registry.connection()),
            enabled,
        )
        .unwrap();
        marty_signing_keys::http::router_with_all_keys_and_grants(
            READ_CREDENTIAL.into(),
            Some(GATEWAY_CREDENTIAL.into()),
            Some(SIGN_CREDENTIAL.into()),
            None,
            None,
            None,
            false,
            Some(self.registry.clone()),
            Some(self.documents.clone()),
            None,
            Some(self.profiles.clone()),
            None,
            None,
            Some(verifier),
        )
    }

    fn signing_input(&self, receipt: &str) -> Vec<u8> {
        let now = Utc::now();
        let stamp =
            |offset| (now + Duration::seconds(offset)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let digest = format!("sha256:{}", "1".repeat(64));
        let grant = json!({"id":Uuid::new_v4(),"revision":2,"terms_digest":digest});
        let body = json!({
            "profile":RECEIPT_PROFILE,"id":receipt,
            "issuer":{"type":"ORGANIZATION","id":self.issuer},"decision":"PERMIT",
            "evaluation":{
                "profile":EVALUATION_PROFILE,"organization_id":self.organization,"grant":grant,
                "actor":{"type":"SERVICE_ACCOUNT","id":"urn:example:agent"},
                "subject":{"type":"ORGANIZATION","id":"urn:example:subject"},
                "binding":{"method":"KEY","key_thumbprint":digest},
                "operation":{"action":"urn:example:buy","resource_id":"urn:example:item","audience":"https://shop.example","request_profile":"urn:example:order:v1","request_digest":digest},
                "approval_evidence_ref":"urn:example:approval","authority_evidence_ref":"urn:example:authority","proof_evidence_ref":"urn:example:proof",
                "challenge":"synthetic_nonce_0123456789","proof_verified_at":stamp(0),"proof_valid_until":stamp(60),
                "status":{"issuer":{"type":"ORGANIZATION","id":"urn:example:authority-owner"},"grant":grant,"state":"ACTIVE","checked_at":stamp(0),"valid_until":stamp(60),"evidence_ref":"urn:example:status"},
                "evaluated_at":stamp(0)
            },
            "policy":{"id":"urn:example:policy","version_digest":digest},
            "issued_at":stamp(0),"expires_at":stamp(30)
        });
        let header = json!({"alg":self.algorithm,"typ":WIRE_FORMAT,"kid":self.kid});
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(body.to_string())
        )
        .into_bytes()
    }

    fn binding<'a>(&'a self, receipt: &'a str, input: &'a [u8]) -> GrantBinding<'a> {
        GrantBinding {
            origin: SigningOrigin::DelegatedDecision,
            operation_id: receipt,
            organization_id: &self.organization,
            route: SIGN_ROUTE,
            service_id: None,
            issuer_did: Some(&self.issuer),
            key_reference: Some(&self.key),
            key_purpose: KEY_PURPOSE,
            algorithm: &self.algorithm,
            payload: input,
        }
    }

    async fn request(&self) -> (Vec<u8>, Value, String) {
        let receipt = Uuid::new_v4().to_string();
        let input = self.signing_input(&receipt);
        let grant = self
            .minter
            .mint(&self.binding(&receipt, &input))
            .await
            .expect("actual dedicated Transit receipt grant")
            .to_header_value()
            .unwrap();
        let body = json!({
            "organization_id":self.organization,"issuer_did":self.issuer,
            "verification_method_id":self.kid,"expected_public_jwk":self.jwk,
            "credential_format":PROFILE_FORMAT,"key_purpose":KEY_PURPOSE,
            "algorithm":self.algorithm,"key_reference":self.key,
            "payload_b64":URL_SAFE_NO_PAD.encode(&input)
        });
        (input, body, grant)
    }

    async fn rotation(&self) {
        let response = provider_client()
            .post(format!(
                "{}/v1/transit/keys/{}/rotate",
                self.endpoint, self.key
            ))
            .header("X-Vault-Token", token("ROTATOR"))
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "owned key rotation failed");
    }
}

#[tokio::test]
#[ignore = "requires independently marked native Redis and TLS OpenBao receipt fixtures"]
async fn delegated_receipts_use_real_custody_and_fail_closed_across_rotation_and_replay() {
    for algorithm in ["EdDSA", "ES256"] {
        let fixture = Fixture::new(algorithm).await;
        let app = fixture.router(true);
        let mut connection = fixture.registry.connection();
        let stored: String = connection
            .get(storage_key(&fixture.organization))
            .await
            .unwrap();
        assert!(
            !stored.contains(&token("SIGNER")),
            "provider credential must be encrypted at rest"
        );
        let stored: Value = serde_json::from_str(&stored).unwrap();
        assert!(
            stored["services"][0]["auth_reference_envelope"]["ciphertext"]
                .as_str()
                .is_some_and(|value| value.starts_with("vault:v"))
        );
        assert!(
            fixture
                .profiles
                .find(
                    &fixture.organization,
                    FindProfilesRequest {
                        active_only: true,
                        require_public_identity: true,
                        ..Default::default()
                    }
                )
                .await
                .unwrap()
                .is_empty(),
            "receipt purpose must remain outside public identity selection"
        );

        let resolve = json!({
            "organization_id":fixture.organization,"issuer_did":fixture.issuer,
            "verification_method_id":fixture.kid,"credential_format":PROFILE_FORMAT,
            "key_purpose":KEY_PURPOSE,"algorithm":algorithm
        });
        let (status, resolved) = call(
            &app,
            "/internal/compat/resolve-issuer-did",
            READ_CREDENTIAL,
            &resolve,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{resolved}");
        assert_eq!(resolved["resolver"]["public_fallback_used"], false);
        assert_eq!(resolved["signing_key_reference"], fixture.key);
        assert_eq!(
            call(
                &app,
                "/internal/compat/resolve-issuer-did",
                SIGN_CREDENTIAL,
                &resolve,
                None
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );

        let (input, body, grant) = fixture.request().await;
        let before = provider_sign_calls(&fixture.key);
        assert_eq!(
            call(
                &fixture.router(false),
                SIGN_ROUTE,
                SIGN_CREDENTIAL,
                &body,
                Some(&grant)
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&app, SIGN_ROUTE, READ_CREDENTIAL, &body, Some(&grant))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let mut changed = body.clone();
        changed["organization_id"] = json!(Uuid::new_v4());
        assert_eq!(
            call(&app, SIGN_ROUTE, SIGN_CREDENTIAL, &changed, Some(&grant))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(provider_sign_calls(&fixture.key), before);

        let (status, signed) = call(&app, SIGN_ROUTE, SIGN_CREDENTIAL, &body, Some(&grant)).await;
        assert_eq!(status, StatusCode::OK, "{signed}");
        assert_eq!(signed["issuer_did"], fixture.issuer);
        assert_eq!(signed["verification_method_id"], fixture.kid);
        let encoded = signed["signature_raw_b64"]
            .as_str()
            .or_else(|| signed["signature_b64"].as_str())
            .unwrap();
        let signature = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        for (payload, expected) in [
            (input.as_slice(), true),
            (b"substituted-receipt".as_slice(), false),
        ] {
            assert_eq!(
                marty_oid4vci::jose::verify_detached_signature_with_public_jwk(
                    payload,
                    &signature,
                    &fixture.jwk.to_string(),
                    algorithm,
                )
                .unwrap(),
                expected
            );
        }
        assert_eq!(provider_sign_calls(&fixture.key), before + 1);
        assert_eq!(
            call(&app, SIGN_ROUTE, SIGN_CREDENTIAL, &body, Some(&grant))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            provider_sign_calls(&fixture.key),
            before + 1,
            "replay reached provider signing"
        );

        // The registry refuses dual purpose binding before any signing call.
        assert!(fixture.registry.save(&fixture.organization, &json!({
            "services":[fixture.service],"default_service_id":SERVICE,
            "key_reference_purposes":{(SERVICE):{(fixture.key.clone()):[KEY_PURPOSE,"vc_jwt_issuer"]}}
        })).await.is_err());
        let route = format!("/v1/signing-keys/services/{SERVICE}/sign");
        let gateway =
            TransitGrantClient::for_origin(&fixture.endpoint, SigningOrigin::GatewayService)
                .unwrap();
        let receipt = Uuid::new_v4().to_string();
        let input = fixture.signing_input(&receipt);
        let mut wrong_origin = fixture.binding(&receipt, &input);
        wrong_origin.origin = SigningOrigin::GatewayService;
        assert!(mint_bound(&gateway, &token("GATEWAY_MINT"), &wrong_origin)
            .await
            .is_err());
        let generic_input = b"synthetic-generic-sign-attempt";
        let generic = GrantBinding {
            origin: SigningOrigin::GatewayService,
            operation_id: &receipt,
            organization_id: &fixture.organization,
            route: &route,
            service_id: Some(SERVICE),
            issuer_did: None,
            key_reference: Some(&fixture.key),
            key_purpose: "vc_jwt_issuer",
            algorithm,
            payload: generic_input,
        };
        let generic_grant = mint_bound(&gateway, &token("GATEWAY_MINT"), &generic)
            .await
            .unwrap()
            .to_header_value()
            .unwrap();
        let generic_body = json!({"organization_id":fixture.organization,"key_reference":fixture.key,
            "key_purpose":"vc_jwt_issuer","algorithm":algorithm,"payload_b64":URL_SAFE_NO_PAD.encode(generic_input)});
        assert_eq!(
            call(
                &app,
                &format!("{route}?organization_id={}", fixture.organization),
                GATEWAY_CREDENTIAL,
                &generic_body,
                Some(&generic_grant)
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            provider_sign_calls(&fixture.key),
            before + 1,
            "generic origin reused receipt key"
        );

        // A real provider authorization failure consumes the grant. Provider
        // audit proves one attempt, then no resend after the key becomes usable.
        let mut read_only = fixture.service.clone();
        read_only["auth_reference"] = json!(token("READ_ONLY"));
        fixture.save_service(read_only).await;
        let (_, body, grant) = fixture.request().await;
        let before = provider_sign_calls(&fixture.key);
        let (status, failed) = call(&app, SIGN_ROUTE, SIGN_CREDENTIAL, &body, Some(&grant)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{failed}");
        assert_eq!(
            provider_sign_calls(&fixture.key),
            before + 1,
            "provider error was retried"
        );
        fixture.save_service(fixture.service.clone()).await;
        assert_eq!(
            call(&app, SIGN_ROUTE, SIGN_CREDENTIAL, &body, Some(&grant))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(provider_sign_calls(&fixture.key), before + 1);

        let (_, body, grant) = fixture.request().await;
        let mut revoked = fixture.profile.clone();
        revoked["status"] = json!("revoked");
        fixture
            .profiles
            .put(&fixture.organization, PROFILE, revoked)
            .await
            .unwrap();
        assert_eq!(
            call(&app, SIGN_ROUTE, SIGN_CREDENTIAL, &body, Some(&grant))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(provider_sign_calls(&fixture.key), before + 1);
        fixture
            .profiles
            .put(&fixture.organization, PROFILE, fixture.profile.clone())
            .await
            .unwrap();

        // Rotate only the owned Transit key, leaving the prepared public pin
        // and DID untouched. The final kernel must reject before remote sign.
        let (_, body, grant) = fixture.request().await;
        fixture.rotation().await;
        let (status, rotated) = call(&app, SIGN_ROUTE, SIGN_CREDENTIAL, &body, Some(&grant)).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "provider rotation escaped final binding: {rotated}"
        );
        assert_eq!(
            provider_sign_calls(&fixture.key),
            before + 1,
            "rotated provider key signed stale pin"
        );
        assert_eq!(
            call(&app, SIGN_ROUTE, SIGN_CREDENTIAL, &body, Some(&grant))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        println!("{algorithm}: real Transit signature, encrypted auth, role separation, default-off, exclusivity, replay, provider failure and rotation verified");
    }
}
