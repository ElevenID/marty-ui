use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, SecondsFormat, Utc};
use marty_oid4vci::{
    formats::{jwt_vc::assemble_jwt_vc, mdoc::assemble_mdoc, sd_jwt::assemble_sd_jwt},
    jose::normalize_ecdsa_signature,
    remote_credential::{
        prepare_remote_jwt_vc, prepare_remote_mdoc, prepare_remote_sd_jwt, RemoteJwtVcRequest,
        RemoteMdocRequest, RemoteSdJwtRequest,
    },
    types::SignedCredential,
};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::credential::{
    BuiltCredential, CredentialBuildRequest, CredentialBuilder, CredentialBuilderKind,
    CredentialIssuanceError,
};

const VCDM_CONTEXT: &str = "https://www.w3.org/ns/credentials/v2";
const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const VCDM_PROTECTED_TERMS: &[&str] = &[
    "@context",
    "credentialSchema",
    "credentialStatus",
    "credentialSubject",
    "description",
    "digestMultibase",
    "digestSRI",
    "evidence",
    "id",
    "issuer",
    "name",
    "proof",
    "refreshService",
    "relatedResource",
    "termsOfUse",
    "type",
    "validFrom",
    "validUntil",
];

#[derive(Clone)]
pub struct HttpCredentialBuilder {
    signer: Arc<dyn DidSigner>,
}

impl std::fmt::Debug for HttpCredentialBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HttpCredentialBuilder")
            .finish_non_exhaustive()
    }
}

impl HttpCredentialBuilder {
    pub fn new(
        base_url: Url,
        api_key: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, CredentialIssuanceError> {
        Ok(Self {
            signer: Arc::new(HttpDidSigner::new(base_url, api_key, timeout)?),
        })
    }

    #[cfg(test)]
    fn with_signer(signer: Arc<dyn DidSigner>) -> Self {
        Self { signer }
    }

    async fn sign(
        &self,
        request: &CredentialBuildRequest,
        payload: &[u8],
        algorithm: &str,
    ) -> Result<Vec<u8>, CredentialIssuanceError> {
        let response = self
            .signer
            .sign(SignRequest {
                organization_id: request.organization_id.clone(),
                issuer_did: request.issuer.issuer_did.clone(),
                credential_format: request.remote_credential_format.clone(),
                key_purpose: key_purpose(&request.remote_credential_format).to_owned(),
                payload: payload.to_vec(),
                algorithm: algorithm.to_owned(),
                verification_method_id: verification_method(request)?.to_owned(),
            })
            .await?;
        URL_SAFE_NO_PAD
            .decode(response.signature_b64)
            .map_err(|error| {
                signing_error(format!(
                    "DID-mediated signer returned invalid signature encoding: {error}"
                ))
            })
    }

    async fn build_sd_jwt(
        &self,
        request: &CredentialBuildRequest,
        claims: HashMap<String, Value>,
    ) -> Result<BuiltCredential, CredentialIssuanceError> {
        let prepared = prepare_remote_sd_jwt(RemoteSdJwtRequest {
            issuer_id: request.issuer.issuer_did.clone(),
            verification_method_id: verification_method(request)?.to_owned(),
            algorithm: request.issuer.algorithm.clone(),
            subject_id: request.subject_did.clone(),
            credential_type: request.credential_type.clone(),
            claims,
            expiration_seconds: Some(request.validity_seconds),
            selective_disclosure_claims: request.selective_disclosure_claims.clone(),
            credential_format: Some(request.response_format.clone()),
            credential_id: Some(request.credential_id.clone()),
            holder_jwk: request.holder_jwk.clone(),
            issuer_certificate_chain: request.issuer.certificate_chain.clone(),
        })
        .map_err(native_error)?;
        let signature = self
            .sign(
                request,
                prepared.signing_input.as_bytes(),
                &request.issuer.algorithm,
            )
            .await?;
        match assemble_sd_jwt(prepared, &signature) {
            SignedCredential::SdJwt {
                compact,
                credential_id,
            } => Ok(BuiltCredential {
                credential_id,
                credential: compact,
            }),
            _ => Err(signing_error(
                "Native SD-JWT assembly returned a different format",
            )),
        }
    }

    async fn build_jwt_vc(
        &self,
        request: &CredentialBuildRequest,
        claims: HashMap<String, Value>,
    ) -> Result<BuiltCredential, CredentialIssuanceError> {
        let open_badge = is_open_badge_type(&request.credential_type);
        let prepared = prepare_remote_jwt_vc(RemoteJwtVcRequest {
            issuer_id: request.issuer.issuer_did.clone(),
            verification_method_id: verification_method(request)?.to_owned(),
            algorithm: request.issuer.algorithm.clone(),
            subject_id: request.subject_did.clone(),
            credential_type: request.credential_type.clone(),
            claims,
            expiration_seconds: Some(request.validity_seconds),
            credential_id: Some(request.credential_id.clone()),
            credential_subject: request.credential_subject.clone(),
            credential_profile: open_badge.then(|| "open_badge_v3".to_owned()),
            achievement_id: if open_badge {
                request.achievement_id.clone()
            } else {
                None
            },
        })
        .map_err(native_error)?;
        let signature = self
            .sign(
                request,
                prepared.signing_input.as_bytes(),
                &request.issuer.algorithm,
            )
            .await?;
        match assemble_jwt_vc(prepared, &signature) {
            SignedCredential::JwtVcJson { jwt, credential_id } => Ok(BuiltCredential {
                credential_id,
                credential: jwt,
            }),
            _ => Err(signing_error(
                "Native JWT-VC assembly returned a different format",
            )),
        }
    }

    async fn build_mdoc(
        &self,
        request: &CredentialBuildRequest,
        mut claims: HashMap<String, Value>,
    ) -> Result<BuiltCredential, CredentialIssuanceError> {
        claims.remove("_mdoc_x5c");
        if !request.issuer.certificate_chain.is_empty() {
            claims.insert(
                "_mdoc_x5c".to_owned(),
                json!(request.issuer.certificate_chain),
            );
        }
        let prepared = prepare_remote_mdoc(RemoteMdocRequest {
            issuer_id: request.issuer.issuer_did.clone(),
            algorithm: request.issuer.algorithm.clone(),
            credential_type: request.credential_type.clone(),
            namespace: mdoc_namespace(&request.credential_type)?.to_owned(),
            claims,
            expiration_seconds: Some(request.validity_seconds),
            credential_id: Some(request.credential_id.clone()),
            holder_jwk: request.holder_jwk.clone(),
        })
        .map_err(native_error)?;
        let signature = self
            .sign(request, &prepared.tbs_data, &request.issuer.algorithm)
            .await?;
        let signature = normalize_ecdsa_signature(&signature, &request.issuer.algorithm)
            .map_err(native_error)?;
        match assemble_mdoc(prepared, &signature).map_err(native_error)? {
            SignedCredential::MsoMdoc {
                issuer_signed_b64,
                credential_id,
            } => Ok(BuiltCredential {
                credential_id,
                credential: issuer_signed_b64,
            }),
            _ => Err(signing_error(
                "Native mdoc assembly returned a different format",
            )),
        }
    }

    async fn build_data_integrity(
        &self,
        request: &CredentialBuildRequest,
        mut claims: Map<String, Value>,
    ) -> Result<BuiltCredential, CredentialIssuanceError> {
        if request.issuer.algorithm != "EdDSA" {
            return Err(signing_error(
                "ldp_vc with eddsa-rdfc-2022 requires an EdDSA issuer profile",
            ));
        }
        let verification_method_id = verification_method(request)?;
        let public_jwk =
            public_ed25519_jwk(request.issuer.public_jwk.clone(), verification_method_id)?;
        let status = claims.remove("credentialStatus");
        let credential = data_integrity_document(request, claims, status)?;
        let prepared_json =
            marty_verification::vcdm::prepare_vcdm_data_integrity_credential_json_async(
                &json!({
                    "credential": credential,
                    "issuer_did": request.issuer.issuer_did,
                    "verification_method_id": verification_method_id,
                    "public_jwk": public_jwk,
                })
                .to_string(),
            )
            .await
            .map_err(native_error)?;
        let prepared: Value = serde_json::from_str(&prepared_json).map_err(|error| {
            signing_error(format!(
                "Native Data Integrity preparation returned invalid JSON: {error}"
            ))
        })?;
        if prepared.get("algorithm").and_then(Value::as_str) != Some("EdDSA") {
            return Err(signing_error(
                "Native Data Integrity preparation returned an invalid algorithm",
            ));
        }
        let signing_input = prepared
            .get("signing_input_b64")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                signing_error("Native Data Integrity preparation returned no signing input")
            })?;
        let signing_input = URL_SAFE_NO_PAD.decode(signing_input).map_err(|error| {
            signing_error(format!(
                "Native Data Integrity signing input is invalid: {error}"
            ))
        })?;
        let signature = self.sign(request, &signing_input, "EdDSA").await?;
        let completed_json =
            marty_verification::vcdm::complete_vcdm_data_integrity_credential_json_async(
                &json!({
                    "prepared": prepared,
                    "signature_b64": URL_SAFE_NO_PAD.encode(signature),
                })
                .to_string(),
            )
            .await
            .map_err(native_error)?;
        let completed: Value = serde_json::from_str(&completed_json).map_err(|error| {
            signing_error(format!(
                "Native Data Integrity completion returned invalid JSON: {error}"
            ))
        })?;
        validate_completed_data_integrity(request, &completed)?;
        Ok(BuiltCredential {
            credential_id: request.credential_id.clone(),
            credential: completed.to_string(),
        })
    }
}

#[async_trait]
impl CredentialBuilder for HttpCredentialBuilder {
    async fn build(
        &self,
        request: &CredentialBuildRequest,
    ) -> Result<BuiltCredential, CredentialIssuanceError> {
        if request.organization_id.trim().is_empty() {
            return Err(signing_error(
                "organization_id is required for DID-mediated signing",
            ));
        }
        let mut claims = request.claims.clone();
        if let Some(status) = credential_status_claim(&request.status_list_entries) {
            claims.insert("credentialStatus".to_owned(), status);
        }
        match request.kind {
            CredentialBuilderKind::SdJwt => {
                self.build_sd_jwt(request, claims.into_iter().collect())
                    .await
            }
            CredentialBuilderKind::JwtVcJson => {
                self.build_jwt_vc(request, claims.into_iter().collect())
                    .await
            }
            CredentialBuilderKind::DataIntegrity => {
                self.build_data_integrity(request, claims).await
            }
            CredentialBuilderKind::Mdoc => {
                self.build_mdoc(request, claims.into_iter().collect()).await
            }
        }
    }
}

#[derive(Clone, Debug)]
struct SignRequest {
    organization_id: String,
    issuer_did: String,
    credential_format: String,
    key_purpose: String,
    payload: Vec<u8>,
    algorithm: String,
    verification_method_id: String,
}

#[derive(Debug)]
struct SignResponse {
    signature_b64: String,
}

#[async_trait]
trait DidSigner: Send + Sync {
    async fn sign(&self, request: SignRequest) -> Result<SignResponse, CredentialIssuanceError>;
}

#[derive(Clone)]
struct HttpDidSigner {
    client: Client,
    base_url: Url,
    api_key: Option<String>,
}

impl HttpDidSigner {
    fn new(
        base_url: Url,
        api_key: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, CredentialIssuanceError> {
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| signing_error(format!("Unable to configure DID signer: {error}")))?;
        Ok(Self {
            client,
            base_url,
            api_key: api_key.map(str::to_owned),
        })
    }

    fn endpoint(&self) -> Url {
        let mut endpoint = self.base_url.clone();
        endpoint.set_path(&format!(
            "{}/issuer-dids/sign",
            self.base_url.path().trim_end_matches('/')
        ));
        endpoint.set_query(None);
        endpoint.set_fragment(None);
        endpoint
    }
}

#[derive(Serialize)]
struct SignBody<'a> {
    issuer_did: &'a str,
    credential_format: &'a str,
    key_purpose: &'a str,
    payload_b64: String,
    algorithm: &'a str,
}

#[derive(Deserialize)]
struct SignResponseBody {
    ok: Option<bool>,
    issuer_did: Option<String>,
    algorithm: Option<String>,
    verification_method_id: Option<String>,
    signature_raw_b64: Option<String>,
    signature_b64: Option<String>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[async_trait]
impl DidSigner for HttpDidSigner {
    async fn sign(&self, request: SignRequest) -> Result<SignResponse, CredentialIssuanceError> {
        let mut http_request = self
            .client
            .post(self.endpoint())
            .query(&[("organization_id", request.organization_id.as_str())])
            .json(&SignBody {
                issuer_did: &request.issuer_did,
                credential_format: &request.credential_format,
                key_purpose: &request.key_purpose,
                payload_b64: URL_SAFE_NO_PAD.encode(&request.payload),
                algorithm: &request.algorithm,
            });
        if let Some(api_key) = self.api_key.as_deref() {
            http_request = http_request.header("X-API-Key", api_key);
        }
        let response = http_request
            .send()
            .await
            .map_err(|error| signing_error(format!("DID-mediated signing failed: {error}")))?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(signing_error(
                "Internal signing API rejected the service API key",
            ));
        }
        let status = response.status();
        if !status.is_success() {
            let detail = response.text().await.unwrap_or_default();
            return Err(signing_error(format!(
                "DID-mediated signing failed (HTTP {status}): {}",
                detail.chars().take(500).collect::<String>()
            )));
        }
        let body: SignResponseBody = response.json().await.map_err(|error| {
            signing_error(format!(
                "DID-mediated signer returned invalid JSON: {error}"
            ))
        })?;
        if body.ok != Some(true) {
            return Err(signing_error(
                "DID-mediated signer returned an invalid response",
            ));
        }
        if body.issuer_did.as_deref() != Some(request.issuer_did.as_str()) {
            return Err(signing_error(
                "DID-mediated signer returned a different issuer DID",
            ));
        }
        if body.algorithm.as_deref() != Some(request.algorithm.as_str()) {
            return Err(signing_error(
                "DID-mediated signer returned a different algorithm",
            ));
        }
        if body.verification_method_id.as_deref() != Some(request.verification_method_id.as_str()) {
            return Err(signing_error(
                "DID-mediated signer returned a different DID verification method",
            ));
        }
        if body.extra.contains_key("issuer_profile_id") || body.extra.contains_key("service_id") {
            return Err(signing_error(
                "DID-mediated signer exposed private signing routing",
            ));
        }
        let signature_b64 = body
            .signature_raw_b64
            .or(body.signature_b64)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| signing_error("DID-mediated signer did not return a signature"))?;
        Ok(SignResponse { signature_b64 })
    }
}

fn credential_status_claim(entries: &[Value]) -> Option<Value> {
    let mut claims = Vec::new();
    for entry in entries {
        let Some(entry) = entry.as_object() else {
            continue;
        };
        let index = entry.get("index").and_then(json_integer).unwrap_or(0);
        let uri = entry
            .get("status_list_uri")
            .or_else(|| entry.get("status_list_credential"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        claims.push(json!({
            "id": if uri.is_empty() {
                format!("urn:marty:status-list-entry:{index}")
            } else {
                format!("{uri}#{index}")
            },
            "type": entry.get("type").and_then(Value::as_str).unwrap_or("BitstringStatusListEntry"),
            "statusPurpose": entry.get("status_purpose").and_then(Value::as_str).unwrap_or("revocation"),
            "statusListIndex": index.to_string(),
            "statusListCredential": uri,
        }));
    }
    match claims.len() {
        0 => None,
        1 => claims.pop(),
        _ => Some(Value::Array(claims)),
    }
}

fn json_integer(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn data_integrity_document(
    request: &CredentialBuildRequest,
    claims: Map<String, Value>,
    credential_status: Option<Value>,
) -> Result<Value, CredentialIssuanceError> {
    if let Some(document) = request.credential_document.clone() {
        if request.credential_subject.is_some() || !claims.is_empty() {
            return Err(signing_error(
                "credential_document cannot be combined with subject claims",
            ));
        }
        let mut document = document
            .as_object()
            .filter(|document| !document.is_empty())
            .cloned()
            .ok_or_else(|| signing_error("credential_document must be a non-empty object"))?;
        if document.contains_key("proof") {
            return Err(signing_error("credential_document must be unsigned"));
        }
        let valid_context = document
            .get("@context")
            .and_then(Value::as_array)
            .and_then(|context| context.first())
            .and_then(Value::as_str)
            == Some(VCDM_CONTEXT);
        if !valid_context {
            return Err(signing_error(
                "credential_document must use the VCDM v2 base context first",
            ));
        }
        if !has_type(&document, "VerifiableCredential") {
            return Err(signing_error(
                "credential_document type must include VerifiableCredential",
            ));
        }
        validate_subject(document.get("credentialSubject"))?;
        match document.get("issuer").and_then(identifier) {
            None => {
                document.insert("issuer".to_owned(), json!(request.issuer.issuer_did));
            }
            Some(issuer) if issuer != request.issuer.issuer_did => {
                return Err(signing_error(
                    "credential_document issuer does not match the resolved issuer DID",
                ));
            }
            Some(_) => {}
        }
        match document.get("id").and_then(Value::as_str) {
            None => {
                document.insert("id".to_owned(), json!(request.credential_id));
            }
            Some(id) if id != request.credential_id => {
                return Err(signing_error(
                    "credential_document id does not match the reserved credential ID",
                ));
            }
            Some(_) => {}
        }
        let now = Utc::now();
        document
            .entry("validFrom")
            .or_insert_with(|| json!(date_time(now)));
        document.entry("validUntil").or_insert_with(|| {
            json!(date_time(
                now + chrono::Duration::seconds(request.validity_seconds)
            ))
        });
        if let Some(status) = credential_status {
            validate_status(&status)?;
            document.insert("credentialStatus".to_owned(), status);
        }
        return Ok(Value::Object(document));
    }

    let subject = if let Some(subject) = request.credential_subject.clone() {
        if !claims.is_empty() {
            return Err(signing_error(
                "explicit credential_subject cannot be combined with subject claims",
            ));
        }
        validate_subject(Some(&subject))?;
        subject
    } else {
        let mut subject = claims;
        if let Some(subject_id) = request.subject_did.as_deref() {
            subject.entry("id").or_insert_with(|| json!(subject_id));
        }
        Value::Object(subject)
    };
    let now = Utc::now();
    let mut types = vec![json!("VerifiableCredential")];
    if !request.credential_type.is_empty() && request.credential_type != "VerifiableCredential" {
        types.push(json!(request.credential_type));
    }
    let mut document = Map::from_iter([
        (
            "@context".to_owned(),
            data_integrity_context(&subject, &request.credential_type),
        ),
        ("id".to_owned(), json!(request.credential_id)),
        ("type".to_owned(), Value::Array(types)),
        ("issuer".to_owned(), json!(request.issuer.issuer_did)),
        ("validFrom".to_owned(), json!(date_time(now))),
        (
            "validUntil".to_owned(),
            json!(date_time(
                now + chrono::Duration::seconds(request.validity_seconds)
            )),
        ),
        ("credentialSubject".to_owned(), subject),
    ]);
    if let Some(status) = credential_status {
        validate_status(&status)?;
        document.insert("credentialStatus".to_owned(), status);
    }
    Ok(Value::Object(document))
}

fn data_integrity_context(subject: &Value, credential_type: &str) -> Value {
    let mut terms = std::collections::BTreeSet::new();
    collect_json_ld_terms(subject, &mut terms);
    if !credential_type.contains(':') && credential_type != "VerifiableCredential" {
        terms.insert(credential_type.to_owned());
    }
    let mut context = vec![json!(VCDM_CONTEXT)];
    if !terms.is_empty() {
        context.push(Value::Object(
            terms
                .into_iter()
                .map(|term| {
                    let iri = format!(
                        "https://credentials.marty.dev/claims/{}",
                        URL_SAFE_NO_PAD.encode(term.as_bytes())
                    );
                    (term, json!(iri))
                })
                .collect(),
        ));
    }
    Value::Array(context)
}

fn collect_json_ld_terms(value: &Value, terms: &mut std::collections::BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                if !key.is_empty()
                    && !key.starts_with('@')
                    && !VCDM_PROTECTED_TERMS.contains(&key.as_str())
                {
                    terms.insert(key.clone());
                }
                collect_json_ld_terms(child, terms);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_json_ld_terms(item, terms);
            }
        }
        _ => {}
    }
}

fn public_ed25519_jwk(
    public_jwk: Option<Value>,
    verification_method_id: &str,
) -> Result<Value, CredentialIssuanceError> {
    let jwk = public_jwk
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| signing_error("issuer DID resolution returned no public JWK"))?;
    let mut private = PRIVATE_JWK_MEMBERS
        .iter()
        .filter(|member| jwk.contains_key(**member))
        .copied()
        .collect::<Vec<_>>();
    private.sort_unstable();
    if !private.is_empty() {
        return Err(signing_error(format!(
            "issuer DID resolution exposed prohibited private JWK members: {}",
            private.join(", ")
        )));
    }
    if jwk.get("kty").and_then(Value::as_str) != Some("OKP")
        || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
        || jwk
            .get("x")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(signing_error(
            "eddsa-rdfc-2022 requires an Ed25519 public JWK from the issuer profile",
        ));
    }
    if jwk
        .get("kid")
        .and_then(Value::as_str)
        .is_some_and(|kid| kid != verification_method_id)
    {
        return Err(signing_error(
            "issuer public JWK kid does not match the DID verification method",
        ));
    }
    Ok(Value::Object(jwk))
}

fn validate_completed_data_integrity(
    request: &CredentialBuildRequest,
    completed: &Value,
) -> Result<(), CredentialIssuanceError> {
    let proof = completed.get("proof").and_then(Value::as_object);
    if completed.get("id").and_then(Value::as_str) != Some(request.credential_id.as_str())
        || completed.get("issuer").and_then(identifier) != Some(request.issuer.issuer_did.as_str())
        || proof
            .and_then(|proof| proof.get("cryptosuite"))
            .and_then(Value::as_str)
            != Some("eddsa-rdfc-2022")
        || proof
            .and_then(|proof| proof.get("verificationMethod"))
            .and_then(Value::as_str)
            != request.issuer.verification_method_id.as_deref()
    {
        return Err(signing_error(
            "completed Data Integrity credential changed its signed identity",
        ));
    }
    Ok(())
}

fn identifier(value: &Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.as_object()?.get("id")?.as_str())
}

fn has_type(document: &Map<String, Value>, expected: &str) -> bool {
    match document.get("type") {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    }
}

fn validate_subject(subject: Option<&Value>) -> Result<(), CredentialIssuanceError> {
    let valid = match subject {
        Some(Value::Object(subject)) => !subject.is_empty(),
        Some(Value::Array(subjects)) => {
            !subjects.is_empty()
                && subjects.iter().all(|subject| {
                    subject
                        .as_object()
                        .is_some_and(|subject| !subject.is_empty())
                })
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(signing_error(
            "credential_subject must be a non-empty object or list of non-empty objects",
        ))
    }
}

fn validate_status(status: &Value) -> Result<(), CredentialIssuanceError> {
    if status.is_object() || status.is_array() {
        Ok(())
    } else {
        Err(signing_error("credentialStatus must be an object or list"))
    }
}

fn mdoc_namespace(credential_type: &str) -> Result<&'static str, CredentialIssuanceError> {
    if credential_type.starts_with("com.icao.dtc") {
        Ok("com.icao.dtc")
    } else if credential_type == "org.iso.18013.5.1.mDL"
        || credential_type.starts_with("org.iso.18013.5.1.")
    {
        Ok("org.iso.18013.5.1")
    } else {
        Err(signing_error(format!(
            "Unsupported mdoc credential namespace for {credential_type}"
        )))
    }
}

fn verification_method(request: &CredentialBuildRequest) -> Result<&str, CredentialIssuanceError> {
    request
        .issuer
        .verification_method_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| signing_error("issuer DID resolution returned no verification method"))
}

fn key_purpose(format: &str) -> &'static str {
    if format == "mso_mdoc" {
        "mdoc_dsc"
    } else {
        "vc_jwt_issuer"
    }
}

fn is_open_badge_type(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "open_badge" | "open_badge_v3" | "openbadgecredential"
    )
}

fn date_time(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn native_error(error: impl std::fmt::Display) -> CredentialIssuanceError {
    signing_error(format!("Native credential operation failed: {error}"))
}

fn signing_error(message: impl Into<String>) -> CredentialIssuanceError {
    CredentialIssuanceError::SigningUnavailable(message.into())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use axum::{
        extract::{Query, State},
        http::HeaderMap,
        routing::post,
        Json, Router,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    use super::*;
    use crate::credential::IssuerContext;

    #[derive(Debug)]
    struct RecordingSigner {
        requests: Mutex<Vec<SignRequest>>,
        ed25519: Option<SigningKey>,
    }

    impl RecordingSigner {
        fn fixed() -> Arc<Self> {
            Arc::new(Self {
                requests: Mutex::new(Vec::new()),
                ed25519: None,
            })
        }

        fn ed25519(key: SigningKey) -> Arc<Self> {
            Arc::new(Self {
                requests: Mutex::new(Vec::new()),
                ed25519: Some(key),
            })
        }
    }

    #[async_trait]
    impl DidSigner for RecordingSigner {
        async fn sign(
            &self,
            request: SignRequest,
        ) -> Result<SignResponse, CredentialIssuanceError> {
            let signature = if request.algorithm == "EdDSA" {
                self.ed25519
                    .as_ref()
                    .expect("Ed25519 test signer")
                    .sign(&request.payload)
                    .to_bytes()
                    .to_vec()
            } else {
                vec![0x11; 64]
            };
            self.requests.lock().expect("request lock").push(request);
            Ok(SignResponse {
                signature_b64: URL_SAFE_NO_PAD.encode(signature),
            })
        }
    }

    fn request(kind: CredentialBuilderKind) -> CredentialBuildRequest {
        CredentialBuildRequest {
            organization_id: "org-a".to_owned(),
            kind,
            response_format: match kind {
                CredentialBuilderKind::SdJwt => "dc+sd-jwt",
                CredentialBuilderKind::JwtVcJson => "jwt_vc_json",
                CredentialBuilderKind::DataIntegrity => "ldp_vc",
                CredentialBuilderKind::Mdoc => "mso_mdoc",
            }
            .to_owned(),
            remote_credential_format: match kind {
                CredentialBuilderKind::SdJwt => "dc+sd-jwt",
                CredentialBuilderKind::JwtVcJson => "jwt_vc_json",
                CredentialBuilderKind::DataIntegrity => "ldp_vc",
                CredentialBuilderKind::Mdoc => "mso_mdoc",
            }
            .to_owned(),
            credential_id: "urn:uuid:00000000-0000-0000-0000-000000000123".to_owned(),
            credential_type: if kind == CredentialBuilderKind::Mdoc {
                "org.iso.18013.5.1.mDL"
            } else {
                "AccessBadge"
            }
            .to_owned(),
            achievement_id: None,
            subject_did: (kind != CredentialBuilderKind::Mdoc).then(|| "did:key:holder".to_owned()),
            holder_jwk: None,
            claims: Map::from_iter([("name".to_owned(), json!("Alice"))]),
            credential_subject: None,
            credential_document: None,
            selective_disclosure_claims: vec!["name".to_owned()],
            validity_seconds: 3600,
            issuer: IssuerContext {
                issuer_profile_id: "private-profile".to_owned(),
                issuer_did: "did:web:issuer.example".to_owned(),
                signing_service_id: "private-service".to_owned(),
                algorithm: "ES256".to_owned(),
                verification_method_id: Some("did:web:issuer.example#key-1".to_owned()),
                public_jwk: None,
                certificate_chain: Vec::new(),
                raw_context: json!({}),
            },
            status_list_entries: vec![json!({
                "index": 7,
                "status_list_uri": "https://issuer.example/status/1",
            })],
        }
    }

    #[tokio::test]
    async fn sd_jwt_signs_exact_native_input_and_strips_holder_secrets() {
        let signer = RecordingSigner::fixed();
        let builder = HttpCredentialBuilder::with_signer(signer.clone());
        let mut request = request(CredentialBuilderKind::SdJwt);
        request.holder_jwk = Some(json!({
            "kty":"EC", "crv":"P-256", "x":"x", "y":"y", "d":"secret"
        }));

        let built = builder.build(&request).await.expect("SD-JWT build");

        assert_eq!(built.credential_id, request.credential_id);
        let signed_input = built
            .credential
            .split('~')
            .next()
            .expect("issuer JWT")
            .rsplit_once('.')
            .expect("signature segment")
            .0;
        let recorded = signer.requests.lock().expect("request lock");
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].payload, signed_input.as_bytes());
        assert_eq!(recorded[0].organization_id, "org-a");
        let payload_segment = signed_input.split('.').nth(1).expect("payload segment");
        let payload: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(payload_segment)
                .expect("base64 payload"),
        )
        .expect("JWT payload");
        assert!(payload["cnf"]["jwk"].get("d").is_none());
        assert_eq!(payload["credentialStatus"]["statusListIndex"], "7");
    }

    #[tokio::test]
    async fn jwt_vc_preserves_open_badge_profile_and_reserved_id() {
        let signer = RecordingSigner::fixed();
        let builder = HttpCredentialBuilder::with_signer(signer);
        let mut request = request(CredentialBuilderKind::JwtVcJson);
        request.credential_type = "open_badge".to_owned();
        request.achievement_id = Some("https://issuer.example/credentials/open_badge".to_owned());
        request
            .claims
            .insert("achievement_name".to_owned(), json!("Verified Member"));
        request.claims.insert(
            "achievement_description".to_owned(),
            json!("Membership verified by Marty"),
        );

        let built = builder.build(&request).await.expect("JWT-VC build");

        assert_eq!(built.credential_id, request.credential_id);
        let payload: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(built.credential.split('.').nth(1).expect("payload"))
                .expect("base64 payload"),
        )
        .expect("JWT payload");
        assert_eq!(payload["jti"], request.credential_id);
        assert_eq!(
            payload["vc"]["credentialSubject"]["achievement"]["id"],
            request.achievement_id.as_deref().expect("achievement")
        );
    }

    #[tokio::test]
    async fn mdoc_ignores_request_controlled_certificate_chain() {
        let signer = RecordingSigner::fixed();
        let builder = HttpCredentialBuilder::with_signer(signer.clone());
        let mut request = request(CredentialBuilderKind::Mdoc);
        request.claims.insert(
            "_mdoc_x5c".to_owned(),
            json!(["attacker-selected-certificate"]),
        );
        request.holder_jwk = Some(json!({
            "kty":"EC", "crv":"P-256", "alg":"ES256",
            "x": URL_SAFE_NO_PAD.encode([0x11; 32]),
            "y": URL_SAFE_NO_PAD.encode([0x22; 32]),
            "d": URL_SAFE_NO_PAD.encode([0x33; 32]),
        }));

        let built = builder.build(&request).await.expect("mdoc build");

        assert_eq!(built.credential_id, request.credential_id);
        assert!(!built.credential.is_empty());
        assert_eq!(
            signer.requests.lock().expect("request lock")[0].key_purpose,
            "mdoc_dsc"
        );
    }

    #[tokio::test]
    async fn data_integrity_uses_native_canonicalization_and_verifies_completion() {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let verifying_key = signing_key.verifying_key();
        let signer = RecordingSigner::ed25519(signing_key);
        let builder = HttpCredentialBuilder::with_signer(signer.clone());
        let mut request = request(CredentialBuilderKind::DataIntegrity);
        request.issuer.algorithm = "EdDSA".to_owned();
        request.issuer.public_jwk = Some(json!({
            "kty":"OKP", "crv":"Ed25519",
            "x": URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
            "kid":"did:web:issuer.example#key-1",
        }));

        let built = builder.build(&request).await.expect("Data Integrity build");

        assert_eq!(built.credential_id, request.credential_id);
        let document: Value = serde_json::from_str(&built.credential).expect("credential JSON");
        assert_eq!(document["id"], request.credential_id);
        assert_eq!(document["proof"]["cryptosuite"], "eddsa-rdfc-2022");
        assert_eq!(
            signer.requests.lock().expect("request lock")[0].algorithm,
            "EdDSA"
        );
    }

    #[tokio::test]
    async fn data_integrity_rejects_a_non_eddsa_issuer_before_signing() {
        let signer = RecordingSigner::fixed();
        let builder = HttpCredentialBuilder::with_signer(signer.clone());
        let request = request(CredentialBuilderKind::DataIntegrity);

        let error = builder
            .build(&request)
            .await
            .expect_err("ES256 Data Integrity must fail closed");

        assert!(error
            .to_string()
            .contains("requires an EdDSA issuer profile"));
        assert!(signer.requests.lock().expect("request lock").is_empty());
    }

    type CapturedHttpRequest = (HashMap<String, String>, HeaderMap, Value);

    #[derive(Clone, Debug, Default)]
    struct HttpCapture(Arc<Mutex<Option<CapturedHttpRequest>>>);

    async fn sign_handler(
        State(capture): State<HttpCapture>,
        Query(query): Query<HashMap<String, String>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        *capture.0.lock().expect("capture lock") = Some((query, headers, body.clone()));
        Json(json!({
            "ok": true,
            "issuer_did": body["issuer_did"],
            "algorithm": body["algorithm"],
            "verification_method_id": "did:web:issuer.example#key-1",
            "signature_raw_b64": URL_SAFE_NO_PAD.encode([0x11; 64]),
        }))
    }

    async fn private_routing_handler(Json(body): Json<Value>) -> Json<Value> {
        Json(json!({
            "ok": true,
            "issuer_did": body["issuer_did"],
            "algorithm": body["algorithm"],
            "verification_method_id": "did:web:issuer.example#key-1",
            "signature_raw_b64": URL_SAFE_NO_PAD.encode([0x11; 64]),
            "issuer_profile_id": null,
        }))
    }

    #[tokio::test]
    async fn http_signer_sends_the_language_neutral_contract() {
        let capture = HttpCapture::default();
        let app = Router::new()
            .route(
                "/internal/signing-keys/issuer-dids/sign",
                post(sign_handler),
            )
            .with_state(capture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let signer = HttpDidSigner::new(
            Url::parse(&format!("http://{address}/internal/signing-keys")).expect("URL"),
            Some("service-secret"),
            Duration::from_secs(2),
        )
        .expect("HTTP signer");

        let response = signer
            .sign(SignRequest {
                organization_id: "org-a".to_owned(),
                issuer_did: "did:web:issuer.example".to_owned(),
                credential_format: "dc+sd-jwt".to_owned(),
                key_purpose: "vc_jwt_issuer".to_owned(),
                payload: b"exact-signing-input".to_vec(),
                algorithm: "ES256".to_owned(),
                verification_method_id: "did:web:issuer.example#key-1".to_owned(),
            })
            .await
            .expect("sign response");

        assert!(!response.signature_b64.is_empty());
        let (query, headers, body) = capture
            .0
            .lock()
            .expect("capture lock")
            .take()
            .expect("captured request");
        assert_eq!(
            query.get("organization_id").map(String::as_str),
            Some("org-a")
        );
        assert_eq!(headers.get("X-API-Key").expect("API key"), "service-secret");
        assert_eq!(
            body["payload_b64"],
            URL_SAFE_NO_PAD.encode(b"exact-signing-input")
        );
        assert!(body.get("issuer_profile_id").is_none());
        assert!(body.get("service_id").is_none());
        server.abort();
    }

    #[tokio::test]
    async fn http_signer_rejects_even_null_private_routing_fields() {
        let app = Router::new().route("/issuer-dids/sign", post(private_routing_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let signer = HttpDidSigner::new(
            Url::parse(&format!("http://{address}")).expect("URL"),
            None,
            Duration::from_secs(2),
        )
        .expect("HTTP signer");

        let error = signer
            .sign(SignRequest {
                organization_id: "org-a".to_owned(),
                issuer_did: "did:web:issuer.example".to_owned(),
                credential_format: "dc+sd-jwt".to_owned(),
                key_purpose: "vc_jwt_issuer".to_owned(),
                payload: b"exact-signing-input".to_vec(),
                algorithm: "ES256".to_owned(),
                verification_method_id: "did:web:issuer.example#key-1".to_owned(),
            })
            .await
            .expect_err("private routing must be rejected");

        assert!(error.to_string().contains("private signing routing"));
        server.abort();
    }
}
