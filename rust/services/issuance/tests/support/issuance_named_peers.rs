//! Fresh renewal through the packaged binary. Only named control-plane/signing
//! peers are synthetic; admission, Core assembly/encryption and delivery are real.
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use bytes::Bytes;
use ed25519_dalek::VerifyingKey;
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

pub(super) const ORGANIZATION: &str = "synthetic-org";
pub(super) const ISSUER: &str = "did:web:issuer.example:issuer";
pub(super) const HOLDER: &str = "did:web:issuer.example:holder";
pub(super) const TEMPLATE: &str = "didcomm-template";
pub(super) const PROFILE: &str = "didcomm-status";
pub(super) const TOKEN: &str = "synthetic-renewal-fresh-main-service-token";
pub(super) const API_KEY: &str = "synthetic-renewal-fresh-main-management-key";
// Issuance uses this same internal service token for Signing Keys and its
// remote integration-secret endpoint. Keep both owned peers on one token.
pub(super) const SIGNING_KEY: &str = super::issuance_process::remote_integration_secret::API_KEY;
pub(super) const FORMAT: &str = "w3c_vcdm_v2_sd_jwt";
pub(super) const CLIENT_KEY: &str = "synthetic-base-gateway-client-key";
pub(super) const CANVAS_CLIENT_KEY: &str = "synthetic-base-canvas-client-key";
pub(super) const FOREIGN_CLIENT_KEY: &str = "synthetic-base-foreign-client-key";

#[derive(Clone)]
pub(super) struct RemoteIssuerSigner {
    client: reqwest::Client,
    base_url: String,
    token: String,
    key_name: String,
    verifying_key: VerifyingKey,
}

impl RemoteIssuerSigner {
    pub(super) async fn create(base_url: &str, root_token: &str) -> Self {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let key_name = format!("canvas_issuer_{}", uuid::Uuid::new_v4().simple());
        client
            .post(format!("{base_url}/v1/transit/keys/{key_name}"))
            .header("X-Vault-Token", root_token)
            .json(&json!({"type":"ed25519","exportable":false,"allow_plaintext_backup":false}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let metadata: Value = client
            .get(format!("{base_url}/v1/transit/keys/{key_name}"))
            .header("X-Vault-Token", root_token)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(metadata["data"]["type"], "ed25519");
        assert_eq!(metadata["data"]["exportable"], false);
        assert_eq!(metadata["data"]["allow_plaintext_backup"], false);
        let version = metadata["data"]["latest_version"]
            .as_u64()
            .unwrap()
            .to_string();
        let public_key = metadata["data"]["keys"][&version]["public_key"]
            .as_str()
            .unwrap();
        let public_bytes: [u8; 32] = STANDARD.decode(public_key).unwrap().try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&public_bytes).unwrap();

        let policy_name = format!("canvas-issuer-{}", uuid::Uuid::new_v4().simple());
        client
            .put(format!("{base_url}/v1/sys/policies/acl/{policy_name}"))
            .header("X-Vault-Token", root_token)
            .json(&json!({"policy":format!("path \"transit/sign/{key_name}\" {{ capabilities = [\"update\"] }}")}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let issued: Value = client
            .post(format!("{base_url}/v1/auth/token/create"))
            .header("X-Vault-Token", root_token)
            .json(&json!({"policies":[policy_name],"no_default_policy":true,"ttl":"1h"}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let token = issued["auth"]["client_token"].as_str().unwrap().to_owned();
        Self {
            client,
            base_url: base_url.to_owned(),
            token,
            key_name,
            verifying_key,
        }
    }

    pub(super) fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    pub(super) async fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let response: Value = self
            .client
            .post(format!(
                "{}/v1/transit/sign/{}",
                self.base_url, self.key_name
            ))
            .header("X-Vault-Token", &self.token)
            .json(&json!({"input":STANDARD.encode(payload),"prehashed":false}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let signature = response["data"]["signature"].as_str().unwrap();
        let (prefix, encoded) = signature.rsplit_once(':').unwrap();
        assert!(prefix.starts_with("vault:v"));
        let bytes = STANDARD.decode(encoded).unwrap();
        assert_eq!(bytes.len(), 64);
        bytes
    }
}

#[cfg(test)]
mod kms_tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires the disposable Canvas OpenBao Transit backend"]
    async fn scoped_transit_signer_verifies_without_key_read_authority() {
        let base_url = std::env::var("MARTY_CANVAS_OPENBAO_URL").unwrap();
        let root_token = std::env::var("MARTY_CANVAS_OPENBAO_ROOT_TOKEN").unwrap();
        let signer = RemoteIssuerSigner::create(&base_url, &root_token).await;
        let payload = b"canvas managed issuer signing proof";
        let signature = ed25519_dalek::Signature::from_slice(&signer.sign(payload).await).unwrap();
        signer
            .verifying_key()
            .verify_strict(payload, &signature)
            .unwrap();
        let metadata = signer
            .client
            .get(format!("{base_url}/v1/transit/keys/{}", signer.key_name))
            .header("X-Vault-Token", &signer.token)
            .send()
            .await
            .unwrap();
        assert_eq!(metadata.status(), StatusCode::FORBIDDEN);
    }
}

#[derive(Clone)]
pub(super) struct PeerState {
    pub(super) source_id: String,
    pub(super) sender: DidDocument,
    pub(super) recipient: DidDocument,
    pub(super) signer: Arc<RemoteIssuerSigner>,
    // Record before decoding or validation so failed requests cannot disappear.
    pub(super) attempts: Arc<Mutex<Vec<String>>>,
    pub(super) accepted: Arc<Mutex<Vec<String>>>,
    pub(super) signed: Arc<Mutex<Vec<Vec<u8>>>>,
    pub(super) allocations: Arc<Mutex<Vec<Value>>>,
    pub(super) publications: Arc<Mutex<Vec<Value>>>,
    // Closed test-only additions are disabled for the original fresh-main gate.
    pub(super) base_gateway: bool,
    pub(super) ordinary_wallets: Arc<AtomicBool>,
}

pub(super) fn decode_request<M: Message + Default>(bytes: &[u8]) -> M {
    assert!(bytes.len() >= 5, "complete unary gRPC frame");
    assert_eq!(bytes[0], 0, "uncompressed synthetic unary request");
    let length = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
    assert_eq!(bytes.len(), length + 5, "exactly one request frame");
    M::decode(&bytes[5..]).unwrap()
}

pub(super) fn grpc_response(message: impl Message) -> Response {
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
        "/health" | "/health/ready" if state.base_gateway => {
            assert_eq!(method, "GET");
            assert!(bytes.is_empty());
            Json(json!({"status":"healthy"})).into_response()
        }
        "/v1/organizations" if state.base_gateway => {
            // The actual gateway starts its hosted-pilot retention sweep
            // immediately. Keep that lifecycle enabled and validate its first
            // bounded page instead of hiding it in this composed-runtime gate.
            assert_eq!(method, "GET");
            assert_eq!(headers["x-service-token"], TOKEN);
            assert_eq!(
                args,
                BTreeMap::from([
                    ("limit".into(), "100".into()),
                    ("offset".into(), "0".into()),
                ])
            );
            assert!(bytes.is_empty());
            Json(json!([])).into_response()
        }
        "/marty.ui.organization.v1.OrganizationService/ValidateApiKey" if state.base_gateway => {
            assert_eq!(method, "POST");
            assert_eq!(headers["x-service-token"], TOKEN);
            let request: organization::ValidateApiKeyRequest = decode_request(&bytes);
            assert!(matches!(
                request.api_key.as_str(),
                CLIENT_KEY
                    | CANVAS_CLIENT_KEY
                    | FOREIGN_CLIENT_KEY
                    | "synthetic-invalid-client-key"
            ));
            grpc_response(organization::ValidateApiKeyResponse {
                valid: matches!(
                    request.api_key.as_str(),
                    CLIENT_KEY | CANVAS_CLIENT_KEY | FOREIGN_CLIENT_KEY
                ),
                api_key_id: "synthetic-base-client".into(),
                organization_id: match request.api_key.as_str() {
                    CANVAS_CLIENT_KEY => "org-review",
                    FOREIGN_CLIENT_KEY => "foreign-organization",
                    _ => ORGANIZATION,
                }
                .into(),
                key_prefix: "synthetic".into(),
                scopes: vec!["admin:full".into()],
            })
        }
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
                id: TEMPLATE.into(),
                organization_id: ORGANIZATION.into(),
                status: "active".into(),
                credential_type: "EmployeeCredential".into(),
                vct: "https://issuer.example/credentials/EmployeeCredential".into(),
                credential_payload_format: FORMAT.into(),
                issuer_did: ISSUER.into(),
                issuer_algorithm: "EdDSA".into(),
                revocation_profile_id: PROFILE.into(),
                wallet_configs_json: if state.ordinary_wallets.load(Ordering::SeqCst) {
                    "[]".into()
                } else {
                    json!([{"wallet_id":"didcomm","format_variant":"didcomm_v2","display_name":"Synthetic Wallet"}]).to_string()
                },
                validity_rules: Some(template::ValidityRules {
                    default_validity_days: 365,
                    renewable: true,
                    renewal_window_days: 30,
                    ..Default::default()
                }),
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
        "/v1/credential-templates/didcomm%2Dtemplate" if state.base_gateway => {
            assert_eq!(method, "GET");
            assert_eq!(headers["x-organization-id"], ORGANIZATION);
            assert_eq!(headers["x-api-key-id"], "synthetic-base-client");
            assert!(args.is_empty());
            assert!(bytes.is_empty());
            Json(json!({
                "id": TEMPLATE,
                "organization_id": ORGANIZATION,
                "status": "active",
                "credential_type": "EmployeeCredential",
                "vct": "https://issuer.example/credentials/EmployeeCredential",
                "credential_payload_format": FORMAT,
                "issuer_did": ISSUER
            }))
            .into_response()
        }
        "/internal/compat/resolve-issuer-did" if state.base_gateway => {
            assert_eq!(method, "POST");
            assert_eq!(headers["x-api-key"], SIGNING_KEY);
            assert!(args.is_empty());
            assert_eq!(
                serde_json::from_slice::<Value>(&bytes).unwrap(),
                json!({
                    "organization_id": ORGANIZATION,
                    "issuer_did": ISSUER,
                    "credential_format": "dc+sd-jwt",
                    "key_purpose": "vc_jwt_issuer"
                })
            );
            Json(json!({
                "ok": true,
                "organization_id": ORGANIZATION,
                "issuer_did": ISSUER,
                "verification_method_id": format!("{ISSUER}#signing-1"),
                "key_purpose": "vc_jwt_issuer",
                "algorithm": "EdDSA",
                "public_jwk": {
                    "kty": "OKP", "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode(state.signer.verifying_key().as_bytes())
                }
            }))
            .into_response()
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
            let signature = state.signer.sign(&payload).await;
            state.signed.lock().unwrap().push(payload);
            Json(json!({"ok":true,"issuer_did":ISSUER,"algorithm":"EdDSA",
                "verification_method_id":format!("{ISSUER}#signing-1"),
                "signature_b64":URL_SAFE_NO_PAD.encode(signature)}))
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

pub(super) async fn start_peers(state: PeerState) -> OwnedHttp {
    OwnedHttp::start(
        Router::new()
            .fallback(peer)
            .with_state(state)
            .merge(super::issuance_process::remote_integration_secret::router_for(SIGNING_KEY)),
    )
    .await
}

pub(super) fn counts(values: &[String]) -> BTreeMap<&str, usize> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value.as_str()).or_default() += 1;
    }
    counts
}
