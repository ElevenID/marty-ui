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

pub(super) const ORGANIZATION: &str = "synthetic-org";
pub(super) const ISSUER: &str = "did:web:issuer.example:issuer";
pub(super) const HOLDER: &str = "did:web:issuer.example:holder";
pub(super) const TEMPLATE: &str = "didcomm-template";
pub(super) const PROFILE: &str = "didcomm-status";
pub(super) const TOKEN: &str = "synthetic-renewal-fresh-main-service-token";
pub(super) const API_KEY: &str = "synthetic-renewal-fresh-main-management-key";
pub(super) const SIGNING_KEY: &str = "synthetic-renewal-fresh-main-signing-key";
pub(super) const FORMAT: &str = "w3c_vcdm_v2_sd_jwt";
pub(super) const CLIENT_KEY: &str = "synthetic-base-gateway-client-key";
pub(super) const CANVAS_CLIENT_KEY: &str = "synthetic-base-canvas-client-key";

#[derive(Clone)]
pub(super) struct PeerState {
    pub(super) source_id: String,
    pub(super) sender: DidDocument,
    pub(super) recipient: DidDocument,
    pub(super) signer: Arc<SigningKey>,
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
                CLIENT_KEY | CANVAS_CLIENT_KEY | "synthetic-invalid-client-key"
            ));
            grpc_response(organization::ValidateApiKeyResponse {
                valid: matches!(request.api_key.as_str(), CLIENT_KEY | CANVAS_CLIENT_KEY),
                api_key_id: "synthetic-base-client".into(),
                organization_id: if request.api_key == CANVAS_CLIENT_KEY {
                    "org-review"
                } else {
                    ORGANIZATION
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

pub(super) async fn start_peers(state: PeerState) -> OwnedHttp {
    OwnedHttp::start(Router::new().fallback(peer).with_state(state)).await
}

pub(super) fn counts(values: &[String]) -> BTreeMap<&str, usize> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value.as_str()).or_default() += 1;
    }
    counts
}
