//! Network-only caller mechanics and independent bootstrap expectations.
//! No function below reads a retained challenge or receipt from owner storage.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use axum::{http::HeaderMap, routing::get, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use marty_delegated_authority::{
    DelegationGrant, DelegationUseCommandResponse, DelegationUseCommandResult,
    DelegationUseOperation, RetainedUseChallenge, DELEGATION_COMMAND_PROFILE,
    DELEGATION_COMMAND_RESPONSE_PROFILE,
};
use marty_delegated_use_client::{
    CallerVerifiedRequest, ClientConfig, DelegatedUseClient, GrantReference, MtlsConfig, Operation,
    PreparedFinalize, PreparedStart, StartedUse,
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use uuid::Uuid;

use super::live_support::{caller, identity, provider_calls, setting, ISSUANCE_KEY, SERVICE_TOKEN};
use crate::support::{
    owned::{operation_digest, ACTION, AUDIENCE, OPERATION_PROFILE, RESOURCE, VERIFIER_CLIENT_ID},
    TestResult,
};

pub fn start(grant: &DelegationGrant) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "profile":DELEGATION_COMMAND_PROFILE,"command":"START_USE",
        "command_id":Uuid::new_v4(),
        "grant":{"id":grant.id,"revision":grant.revision,"terms_digest":grant.terms_digest},
        "operation":{"action":ACTION,"resource_id":RESOURCE,"audience":AUDIENCE,
            "request_profile":OPERATION_PROFILE,"request_digest":operation_digest()}
    }))
    .unwrap()
}

pub fn finalization(challenge: Uuid, proof: Uuid) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "profile":DELEGATION_COMMAND_PROFILE,"command":"FINALIZE_USE",
        "command_id":Uuid::new_v4(),"challenge_id":challenge,"proof_submission_id":proof
    }))
    .unwrap()
}

pub fn recovery(response: &DelegationUseCommandResponse) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "profile":DELEGATION_COMMAND_PROFILE,"command":"RECOVER_RESULT",
        "original_command_id":response.original_command_id,
        "expected_command_digest":response.command_digest
    }))
    .unwrap()
}

/// This DTO conveys bytes, not a verified receipt or proof of authorization.
/// Deliberately no Debug: failures must not print the original signed artifact.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptArtifact {
    pub original_response: DelegationUseCommandResponse,
    pub receipt_ref: String,
    pub receipt_digest: String,
    pub compact_jws: String,
    pub semantics: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofSubmission {
    pub submission_id: Uuid,
    pub challenge_id: Uuid,
    pub proof_digest: String,
    pub received_at: DateTime<Utc>,
    pub recovered: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Surface {
    Internal,
    Public,
}

#[derive(Clone)]
enum PreparedCommand {
    Start(Arc<PreparedStart>),
    Finalize(Arc<PreparedFinalize>),
}
impl PreparedCommand {
    fn digest(&self) -> &str {
        match self {
            Self::Start(command) => command.command_digest(),
            Self::Finalize(command) => command.command_digest(),
        }
    }
}

struct PublicCaller {
    client: DelegatedUseClient,
    prepared: Mutex<BTreeMap<Uuid, PreparedCommand>>,
    started: Mutex<BTreeMap<Uuid, Arc<StartedUse>>>,
}

pub struct WalletChallenge {
    pub challenge: RetainedUseChallenge,
    pub verified: CallerVerifiedRequest,
}

pub struct Network {
    pub client: Client,
    pub origin: String,
    pub organization: Uuid,
    pub surface: Surface,
    public: Option<PublicCaller>,
}
impl Network {
    pub async fn connect(
        origin: String,
        organization: Uuid,
        surface: Surface,
        certificate: Option<String>,
    ) -> TestResult<Self> {
        // Raw negative probes use the same authenticated leaf, key and trust as
        // the independent client. Positive public operations use the client's
        // own bounded transport with its fixed redirect/retry/proxy policy.
        let client = caller(certificate.clone()).await?;
        let public = if surface == Surface::Public {
            let identity = identity("MARTY_TEST_USE_CALLER_TLS", certificate)?
                .connect()
                .await?;
            let ca = std::fs::read(setting("MARTY_TEST_USE_CA_DER_FILE"))?;
            let tls = mmf_platform::keyless_grpc_client_config(&identity, vec![ca.clone()])?;
            let mut mtls = MtlsConfig {
                roots: rustls::RootCertStore::empty(),
                client_certificate: tls.client_auth_cert_resolver.clone(),
            };
            mtls.roots.add(ca.into())?;
            Some(PublicCaller {
                client: DelegatedUseClient::new(ClientConfig {
                    origin: origin.clone(),
                    organization,
                    tls: mtls,
                    timeout: Duration::from_secs(20),
                })?,
                prepared: Mutex::new(BTreeMap::new()),
                started: Mutex::new(BTreeMap::new()),
            })
        } else {
            None
        };
        Ok(Self {
            client,
            origin,
            organization,
            surface,
            public,
        })
    }

    fn command_prefix(&self) -> &'static str {
        match self.surface {
            Surface::Internal => "/internal/v1",
            Surface::Public => "/v1",
        }
    }

    pub async fn assert_route_selection(&self) -> TestResult {
        // Probe malformed inputs only. Route selection must neither create an
        // operation nor reach a signer, and each public surface stays absent
        // unless the separate caller feature is explicitly selected.
        let command = format!(
            "/v1/organizations/{}/delegated-use-commands",
            self.organization
        );
        let receipt = format!(
            "/v1/organizations/{}/delegated-use/receipts/recover",
            self.organization
        );
        let challenge = Uuid::nil();
        for (method, path, content_type, detail) in [
            (
                reqwest::Method::POST,
                command,
                "application/json",
                "invalid_delegation_use_command",
            ),
            (
                reqwest::Method::POST,
                receipt,
                "application/json",
                "invalid_delegation_use_command",
            ),
            (
                reqwest::Method::GET,
                format!("/v1/flows/instances/{challenge}/request"),
                "application/json",
                "invalid_delegated_flow_request",
            ),
            (
                reqwest::Method::POST,
                format!("/v1/flows/instances/{challenge}/submit"),
                "application/x-www-form-urlencoded",
                "invalid_delegated_flow_request",
            ),
        ] {
            let mut request = self
                .client
                .request(method.clone(), format!("{}{path}", self.origin));
            if method == reqwest::Method::POST {
                request = request.header("content-type", content_type).body("{}");
            }
            match self.surface {
                Surface::Internal => {
                    let response = request.send().await?;
                    assert_eq!(
                        response.status(),
                        StatusCode::NOT_FOUND,
                        "unselected public path {path}"
                    );
                }
                Surface::Public => {
                    denied_for(
                        request,
                        StatusCode::BAD_REQUEST,
                        detail,
                        "selected public route",
                    )
                    .await?;
                }
            }
        }
        // The public selection adds its routes without displacing the internal
        // machine host; malformed internal commands still reach its guard.
        denied_for(
            self.client
                .post(format!(
                    "{}/internal/v1/organizations/{}/delegated-use-commands",
                    self.origin, self.organization
                ))
                .header("content-type", "application/json")
                .body("{}"),
            StatusCode::BAD_REQUEST,
            "invalid_delegation_use_command",
            "preserved internal route",
        )
        .await
    }

    pub async fn assert_no_certificate(&self) -> TestResult {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(std::fs::read(setting("MARTY_TEST_USE_CA_DER_FILE"))?.into())?;
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let client = Client::builder()
            .use_preconfigured_tls(tls)
            .https_only(true)
            .http1_only()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(5))
            .build()?;
        assert!(
            client
                .post(format!(
                    "{}{}/organizations/{}/delegated-use-commands",
                    self.origin,
                    self.command_prefix(),
                    self.organization
                ))
                .header("content-type", "application/json")
                .body("{}")
                .send()
                .await
                .is_err(),
            "selected use listener accepted a caller without its certificate"
        );
        Ok(())
    }

    pub fn command_request(&self, raw: &[u8]) -> RequestBuilder {
        self.client
            .post(format!(
                "{}{}/organizations/{}/delegated-use-commands",
                self.origin,
                self.command_prefix(),
                self.organization
            ))
            .header("content-type", "application/json")
            .body(raw.to_vec())
    }
    pub fn receipt_request(&self, raw: &[u8]) -> RequestBuilder {
        self.client
            .post(format!(
                "{}{}/organizations/{}/delegated-use/receipts/recover",
                self.origin,
                self.command_prefix(),
                self.organization
            ))
            .header("content-type", "application/json")
            .body(raw.to_vec())
    }
    pub fn request(&self, challenge: Uuid) -> RequestBuilder {
        let path = match self.surface {
            Surface::Internal => format!(
                "/internal/v1/organizations/{}/delegated-use/challenges/{challenge}/request",
                self.organization
            ),
            Surface::Public => format!("/v1/flows/instances/{challenge}/request"),
        };
        self.client.get(format!("{}{path}", self.origin))
    }
    pub fn proof_request(&self, wallet: &WalletChallenge, proof: &[u8]) -> RequestBuilder {
        match self.surface {
            Surface::Internal => self.client
                .post(format!(
                    "{}/internal/v1/organizations/{}/delegated-use/challenges/{}/proof",
                    self.origin, self.organization, wallet.challenge.challenge_id
                ))
                .header("content-type", "application/octet-stream")
                .body(proof.to_vec()),
            Surface::Public => self.form_request(
                &wallet.verified.response_uri,
                &[
                    ("state", wallet.verified.state.clone()),
                    ("vp_token", json!({wallet.verified.query_id.clone(): [std::str::from_utf8(proof).expect("locally produced compact VP")]}).to_string()),
                ],
            ),
        }
    }
    pub fn form_request(&self, response_uri: &str, fields: &[(&str, String)]) -> RequestBuilder {
        let body: String = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().map(|(key, value)| (*key, value.as_str())))
            .finish();
        self.client
            .post(response_uri)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body)
    }
    pub async fn command(&self, raw: &[u8]) -> TestResult<DelegationUseCommandResponse> {
        if let Some(public) = &self.public {
            return public.command(raw).await;
        }
        let command: Option<Value> = serde_json::from_slice(raw).ok();
        let label = match command.as_ref().and_then(|value| value["command"].as_str()) {
            Some("START_USE") => "START_USE",
            Some("FINALIZE_USE") => "FINALIZE_USE",
            Some("RECOVER_RESULT") => "RECOVER_RESULT",
            _ => "delegated-use command",
        };
        let result: DelegationUseCommandResponse =
            json_response(self.command_request(raw), label).await?;
        assert_eq!(result.profile, DELEGATION_COMMAND_RESPONSE_PROFILE);
        Ok(result)
    }
    pub async fn receipt(&self, raw: &[u8]) -> TestResult<ReceiptArtifact> {
        if let Some(public) = &self.public {
            let command = public.recovery_command(raw)?;
            let PreparedCommand::Finalize(command) = command else {
                return Err("receipt recovery requires a locally prepared finalization".into());
            };
            let artifact = public.client.recover_receipt(&command).await?;
            return Ok(ReceiptArtifact {
                original_response: serde_json::from_value(serde_json::to_value(
                    artifact.original_response(),
                )?)?,
                receipt_ref: artifact.receipt_ref().into(),
                receipt_digest: artifact.receipt_digest().into(),
                compact_jws: artifact.compact_jws().into(),
                semantics: artifact.semantics().into(),
            });
        }
        json_response(self.receipt_request(raw), "original receipt recovery").await
    }
    pub async fn signed_request(&self, challenge: Uuid) -> TestResult<String> {
        if let Some(public) = &self.public {
            let started = public.started(challenge)?;
            let artifact = public.client.fetch_request(&started).await?;
            return Ok(artifact.compact_jws().into());
        }
        let (response, context) = checked_response(
            self.request(challenge),
            StatusCode::OK,
            "signed request retrieval",
        )
        .await?;
        protected(&response, StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "application/oauth-authz-req+jwt"
        );
        let bytes = bounded_body(response, 262_144)
            .await
            .map_err(|_| format!("{context}: signed request body unavailable or oversized"))?;
        if bytes.is_empty() {
            return Err(format!("{context}: signed request body is empty").into());
        }
        String::from_utf8(bytes)
            .map_err(|_| format!("{context}: signed request is not UTF-8").into())
    }
    pub async fn submit(
        &self,
        wallet: &WalletChallenge,
        proof: &[u8],
    ) -> TestResult<ProofSubmission> {
        if let Some(public) = &self.public {
            let started = public.started(wallet.challenge.challenge_id)?;
            let proof =
                std::str::from_utf8(proof).map_err(|_| "locally produced VP is not UTF-8")?;
            let submitted = public
                .client
                .submit_direct_post(&started, &wallet.verified, proof)
                .await?;
            return Ok(ProofSubmission {
                submission_id: submitted.submission_id,
                challenge_id: submitted.challenge_id,
                proof_digest: submitted.proof_digest,
                received_at: submitted.received_at,
                recovered: submitted.recovered,
            });
        }
        json_response(
            self.proof_request(wallet, proof),
            "machine proof submission",
        )
        .await
    }
}

impl PublicCaller {
    fn remember(&self, id: Uuid, prepared: PreparedCommand) -> TestResult {
        let mut commands = self
            .prepared
            .lock()
            .map_err(|_| "local command cache unavailable")?;
        if commands
            .get(&id)
            .is_some_and(|original| original.digest() != prepared.digest())
        {
            return Err("local command identity was reused with different intent".into());
        }
        commands.insert(id, prepared);
        Ok(())
    }

    fn recovery_command(&self, raw: &[u8]) -> TestResult<PreparedCommand> {
        let document: Value =
            serde_json::from_slice(raw).map_err(|_| "invalid locally prepared recovery command")?;
        if document["profile"] != DELEGATION_COMMAND_PROFILE
            || document["command"] != "RECOVER_RESULT"
        {
            return Err("expected a locally prepared recovery command".into());
        }
        let id = local_uuid(&document, "original_command_id")?;
        let commands = self
            .prepared
            .lock()
            .map_err(|_| "local command cache unavailable")?;
        let original = commands
            .get(&id)
            .ok_or("recovery has no locally prepared original command")?;
        if document["expected_command_digest"].as_str() != Some(original.digest()) {
            return Err(
                "recovery digest differs from the locally prepared original command".into(),
            );
        }
        Ok(original.clone())
    }

    fn started(&self, challenge: Uuid) -> TestResult<Arc<StartedUse>> {
        self.started
            .lock()
            .map_err(|_| "local started-use cache unavailable")?
            .get(&challenge)
            .cloned()
            .ok_or_else(|| "challenge has no validated returned request URI".into())
    }

    fn remember_started(&self, started: StartedUse) -> TestResult<DelegationUseCommandResponse> {
        let response = checked_public_response(started.response())?;
        self.started
            .lock()
            .map_err(|_| "local started-use cache unavailable")?
            .insert(started.challenge_id(), Arc::new(started));
        Ok(response)
    }

    async fn command(&self, raw: &[u8]) -> TestResult<DelegationUseCommandResponse> {
        // These fields are the caller's original local command inputs. A
        // recovered server DTO can name only a previously retained local ID
        // and digest; it never supplies its own expected command binding.
        let document: Value = serde_json::from_slice(raw)
            .map_err(|_| "invalid locally prepared delegated-use command")?;
        if document["profile"] != DELEGATION_COMMAND_PROFILE {
            return Err("invalid locally prepared delegated-use profile".into());
        }
        match document["command"].as_str() {
            Some("START_USE") => {
                let id = local_uuid(&document, "command_id")?;
                let grant: GrantReference = serde_json::from_value(document["grant"].clone())
                    .map_err(|_| "invalid locally prepared grant reference")?;
                let operation: Operation = serde_json::from_value(document["operation"].clone())
                    .map_err(|_| "invalid locally prepared operation")?;
                let prepared = Arc::new(PreparedStart::new(id, grant, operation)?);
                self.remember(id, PreparedCommand::Start(prepared.clone()))?;
                self.remember_started(self.client.start(&prepared).await?)
            }
            Some("FINALIZE_USE") => {
                let id = local_uuid(&document, "command_id")?;
                let prepared = Arc::new(PreparedFinalize::new(
                    id,
                    local_uuid(&document, "challenge_id")?,
                    local_uuid(&document, "proof_submission_id")?,
                )?);
                self.remember(id, PreparedCommand::Finalize(prepared.clone()))?;
                checked_public_response(self.client.finalize(&prepared).await?.response())
            }
            Some("RECOVER_RESULT") => match self.recovery_command(raw)? {
                PreparedCommand::Start(prepared) => {
                    self.remember_started(self.client.recover_start(&prepared).await?)
                }
                PreparedCommand::Finalize(prepared) => {
                    checked_public_response(self.client.recover_final(&prepared).await?.response())
                }
            },
            _ => Err("unsupported locally prepared delegated-use command".into()),
        }
    }
}

fn local_uuid(document: &Value, field: &str) -> TestResult<Uuid> {
    document[field]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        .filter(|value| !value.is_nil())
        .ok_or_else(|| "invalid locally prepared command identifier".into())
}

fn checked_public_response(
    response: &marty_delegated_use_client::CommandResponse,
) -> TestResult<DelegationUseCommandResponse> {
    // The independent client has already checked profile, identity, digest,
    // operation and result bindings. Conversion exists only to reuse the
    // legacy acceptance assertions and never supplies client expectations.
    let response: DelegationUseCommandResponse =
        serde_json::from_value(serde_json::to_value(response)?)?;
    assert_eq!(response.profile, DELEGATION_COMMAND_RESPONSE_PROFILE);
    Ok(response)
}

pub fn protected(response: &Response, status: StatusCode) {
    assert_eq!(
        response.status(),
        status,
        "protected HTTP response for {}",
        response.url().path()
    );
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    assert_eq!(response.headers().get("pragma").unwrap(), "no-cache");
    assert_eq!(
        response.headers().get("x-content-type-options").unwrap(),
        "nosniff"
    );
}

async fn json_response<T: DeserializeOwned>(
    request: RequestBuilder,
    label: &'static str,
) -> TestResult<T> {
    let (response, context) = checked_response(request, StatusCode::OK, label).await?;
    protected(&response, StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
    let bytes = bounded_body(response, 262_144)
        .await
        .map_err(|_| format!("{context}: JSON body unavailable or oversized"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| format!("{context}: invalid bounded response DTO").into())
}

pub async fn denied(request: RequestBuilder, status: StatusCode, code: &str) -> TestResult {
    denied_for(request, status, code, "expected denial").await
}

pub async fn denied_for(
    request: RequestBuilder,
    status: StatusCode,
    code: &str,
    label: &'static str,
) -> TestResult {
    let (response, context) = checked_response(request, status, label).await?;
    protected(&response, status);
    let actual = generic_detail(response).await;
    if actual != code {
        return Err(
            format!("{context}: HTTP {status}; expected detail {code}; got {actual}").into(),
        );
    }
    Ok(())
}

/// Report only a static operation label, HTTP method, route path, status and a
/// closed public detail code. Queries, headers, arbitrary upstream diagnostics
/// and request/proof/receipt bodies never enter an error or panic message.
async fn checked_response(
    builder: RequestBuilder,
    expected: StatusCode,
    label: &'static str,
) -> TestResult<(Response, String)> {
    let (client, request) = builder.build_split();
    let request = request.map_err(|_| format!("{label}: HTTP request construction failed"))?;
    let context = format!("{label}: {} {}", request.method(), request.url().path());
    let response = client
        .execute(request)
        .await
        .map_err(|_| format!("{context}: HTTP transport failed"))?;
    let status = response.status();
    if status != expected {
        let detail = generic_detail(response).await;
        return Err(format!(
            "{context}: expected HTTP {expected}; got HTTP {status}; detail {detail}"
        )
        .into());
    }
    Ok((response, context))
}

async fn bounded_body(mut response: Response, maximum: usize) -> Result<Vec<u8>, ()> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
        if chunk.len() > maximum.saturating_sub(bytes.len()) {
            return Err(());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

async fn generic_detail(response: Response) -> &'static str {
    let Ok(bytes) = bounded_body(response, 4096).await else {
        return "unavailable-or-oversized-error-body";
    };
    let Ok(body) = serde_json::from_slice::<Value>(&bytes) else {
        return "unrecognized-error-body";
    };
    if body.as_object().is_none_or(|object| object.len() != 1) {
        return "unrecognized-error-body";
    }
    match body["detail"].as_str() {
        Some("invalid_delegation_use_command") => "invalid_delegation_use_command",
        Some("delegation_use_access_denied") => "delegation_use_access_denied",
        Some("delegation_use_service_authentication_required") => {
            "delegation_use_service_authentication_required"
        }
        Some("delegation_use_workload_denied") => "delegation_use_workload_denied",
        Some("delegation_use_conflict") => "delegation_use_conflict",
        Some("delegation_use_preparation_pending") => "delegation_use_preparation_pending",
        Some("delegation_use_result_not_found") => "delegation_use_result_not_found",
        Some("delegation_use_evidence_expired") => "delegation_use_evidence_expired",
        Some("delegation_use_unavailable") => "delegation_use_unavailable",
        Some("unsupported_delegation_use_command") => "unsupported_delegation_use_command",
        Some("delegation_use_json_required") => "delegation_use_json_required",
        Some("delegation_use_body_timeout") => "delegation_use_body_timeout",
        Some("delegation_use_body_too_large") => "delegation_use_body_too_large",
        Some("invalid_delegated_flow_request") => "invalid_delegated_flow_request",
        Some("delegated_flow_body_timeout") => "delegated_flow_body_timeout",
        Some("delegated_flow_request_body_forbidden") => "delegated_flow_request_body_forbidden",
        Some("delegated_flow_proof_bytes_required") => "delegated_flow_proof_bytes_required",
        Some("delegated_flow_direct_post_required") => "delegated_flow_direct_post_required",
        Some("delegated_flow_body_too_large") => "delegated_flow_body_too_large",
        _ => "unrecognized-error-detail",
    }
}

pub fn original(
    received: &DelegationUseCommandResponse,
    expected: &DelegationUseCommandResponse,
) -> TestResult {
    assert!(received.recovered);
    assert_eq!(received.profile, DELEGATION_COMMAND_RESPONSE_PROFILE);
    assert_eq!(received.profile, expected.profile);
    assert_eq!(received.original_command_id, expected.original_command_id);
    assert_eq!(received.command_digest, expected.command_digest);
    assert_eq!(
        serde_json::to_value(&received.result)?,
        serde_json::to_value(&expected.result)?
    );
    Ok(())
}

/// Authenticate the request using the independently provisioned request key.
/// The wallet challenge comes from authenticated START_USE and this signature,
/// never a database snapshot or the receipt that will later be verified.
pub fn wallet_challenge(
    compact: &str,
    public_jwk: &Value,
    key_id: &str,
    grant: &DelegationGrant,
    started: &DelegationUseCommandResponse,
    public_base_url: &str,
    requirement_id: &str,
) -> TestResult<WalletChallenge> {
    let parts = compact.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
    assert_eq!(header.as_object().unwrap().len(), 3);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "oauth-authz-req+jwt");
    assert_eq!(header["kid"], key_id);
    assert_eq!(public_jwk["kty"], "EC");
    assert_eq!(public_jwk["crv"], "P-256");
    let x: [u8; 32] = URL_SAFE_NO_PAD
        .decode(public_jwk["x"].as_str().unwrap())?
        .try_into()
        .map_err(|_| "invalid independently selected request x coordinate")?;
    let y: [u8; 32] = URL_SAFE_NO_PAD
        .decode(public_jwk["y"].as_str().unwrap())?
        .try_into()
        .map_err(|_| "invalid independently selected request y coordinate")?;
    let mut point = [0u8; 65];
    point[0] = 4;
    point[1..33].copy_from_slice(&x);
    point[33..].copy_from_slice(&y);
    let verifier = VerifyingKey::from_sec1_bytes(&point)?;
    let signature = Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2])?)?;
    verifier.verify(
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &signature.normalize_s(),
    )?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1])?)?;
    let DelegationUseCommandResult::Challenge {
        challenge_id,
        grant: reference,
        operation,
        created_at,
        expires_at,
    } = &started.result
    else {
        return Err("START_USE did not return a challenge".into());
    };
    assert_eq!(reference.id, grant.id);
    assert_eq!(reference.revision, grant.revision);
    assert_eq!(reference.terms_digest, grant.terms_digest);
    assert_eq!(
        operation,
        &DelegationUseOperation {
            action: ACTION.into(),
            resource_id: RESOURCE.into(),
            audience: AUDIENCE.into(),
            request_profile: OPERATION_PROFILE.into(),
            request_digest: operation_digest(),
        }
    );
    assert_eq!(claims["client_id"], VERIFIER_CLIENT_ID);
    assert_eq!(claims["iss"], VERIFIER_CLIENT_ID);
    assert_eq!(claims["aud"], "https://self-issued.me/v2");
    assert_eq!(claims["state"], challenge_id.to_string());
    assert_eq!(claims["response_type"], "vp_token");
    assert_eq!(claims["response_mode"], "direct_post");
    assert_eq!(
        claims["response_uri"],
        format!("{public_base_url}/v1/flows/instances/{challenge_id}/submit")
    );
    assert_eq!(claims["exp"].as_i64(), Some(expires_at.timestamp()));
    let issued_at = claims["iat"]
        .as_i64()
        .ok_or("missing signed request issuance time")?;
    assert!(issued_at >= created_at.timestamp() && issued_at <= Utc::now().timestamp());
    assert!(issued_at < expires_at.timestamp());
    let query =
        marty_oid4vp_contract::jwt_vc_profile::profiled_jwt_vc_query(&claims["dcql_query"])?
            .ok_or("signed request omitted the explicitly selected securing profile")?;
    assert_eq!(query.id, requirement_id);
    assert_eq!(
        query.binding.securing_profile(),
        marty_oid4vp_contract::jwt_vc_profile::JwtVcSecuringProfile::MartyNestedVc2JwtV1
    );
    assert_eq!(query.type_sets, vec![vec!["MachineCredential".to_owned()]]);
    assert_eq!(
        claims["dcql_query"]["credentials"][0]["meta"]["type_values"],
        json!([["VerifiableCredential", "MachineCredential"]])
    );
    assert_eq!(
        claims["dcql_query"]["credentials"][0]["require_cryptographic_holder_binding"],
        true
    );
    let nonce = claims["nonce"]
        .as_str()
        .ok_or("missing signed request nonce")?;
    assert!(!nonce.is_empty() && nonce.len() <= 256);
    Ok(WalletChallenge {
        challenge: RetainedUseChallenge {
            organization_id: grant.organization_id,
            challenge_id: *challenge_id,
            grant: grant.clone(),
            operation: operation.clone(),
            verifier_id: VERIFIER_CLIENT_ID.into(),
            nonce: nonce.into(),
            created_at: *created_at,
            expires_at: *expires_at,
        },
        verified: CallerVerifiedRequest {
            response_uri: claims["response_uri"]
                .as_str()
                .ok_or("missing verified response URI")?
                .into(),
            state: claims["state"]
                .as_str()
                .ok_or("missing verified response state")?
                .into(),
            query_id: query.id,
        },
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningCounts {
    pub request_sign: usize,
    pub credential_sign: usize,
    pub receipt_sign: usize,
    pub request_grant: usize,
    pub credential_grant: usize,
    pub receipt_grant: usize,
}
impl SigningCounts {
    pub fn capture() -> TestResult<Self> {
        Ok(Self {
            request_sign: provider_calls("transit/sign/lifecycle-request-es256")?,
            credential_sign: provider_calls("transit/sign/lifecycle-machine-es256")?,
            receipt_sign: provider_calls("transit/sign/lifecycle-receipt-es256")?,
            request_grant: provider_calls("transit/hmac/marty-sign-grant-flow-wallet-v1/sha2-256")?,
            credential_grant: provider_calls(
                "transit/hmac/marty-sign-grant-issuance-credential-v1/sha2-256",
            )?,
            receipt_grant: provider_calls(
                "transit/hmac/marty-sign-grant-delegated-decision-v1/sha2-256",
            )?,
        })
    }
}

/// The four catalog origins are required by host readiness but unused by this
/// selected operation. This named fixture serves authenticated health only;
/// any attempted record resolution is counted and fails. Actual template and
/// policy RPCs, issuance, owner state and custody are provided elsewhere.
#[derive(Default)]
pub struct CatalogHealthFixture {
    pub health_reads: Arc<AtomicUsize>,
    pub attempted_record_reads: Arc<AtomicUsize>,
}
impl CatalogHealthFixture {
    pub fn router(&self) -> Router {
        let health_reads = self.health_reads.clone();
        let attempted = self.attempted_record_reads.clone();
        Router::new().route("/health", get(move |headers: HeaderMap| {
            let health_reads = health_reads.clone();
            async move {
                let service = headers.get("x-service-token").and_then(|v| v.to_str().ok());
                let issuance = headers.get("x-api-key").and_then(|v| v.to_str().ok());
                if (service == Some(SERVICE_TOKEN) && issuance.is_none())
                    || (issuance == Some(ISSUANCE_KEY) && service.is_none()) {
                    health_reads.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, Json(json!({"status":"healthy","fixture":"unused-catalog-health-only"})))
                } else {
                    (StatusCode::UNAUTHORIZED, Json(json!({"error":"fixture credential required"})))
                }
            }
        })).fallback(move || {
            let attempted = attempted.clone();
            async move {
                attempted.fetch_add(1, Ordering::SeqCst);
                StatusCode::NOT_FOUND
            }
        })
    }
}
