//! The bounded native producer for one holder-bound SD-JWT/DCQL requirement.
//!
//! This is evidence of the exact query, signed subject and holder key only. It
//! does not assert issuer authorization for a credential type, status, durable
//! replay consumption, applicant identity or permission to issue a credential.

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use marty_oid4vci::{
    formats::sd_jwt::{verify_sd_jwt_with_policy, SdJwtVerificationPolicy},
    types::SigningAlgorithm,
};
use marty_oid4vp_contract::{
    digest_audience, digest_domain_json, digest_nonce, digest_response_item, FrozenPolicyIdentity,
    QueryKind, MAX_CLAIMS_PER_CREDENTIAL, MAX_CLAIM_VALUE_BYTES, MAX_IDENTIFIER_BYTES,
    MAX_TOKEN_BYTES, MIN_NONCE_BYTES,
};
use marty_verification::credential_format::DetectedCredentialFormat;
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    policy_revision, EvaluatePresentationRequest, PolicyStatus, PresentationPolicy,
    PresentationVerificationError, ResolvedIssuerKey,
};

const PROFILE_ERROR: &str = "PRESENTATION_POLICY.UNSUPPORTED_SD_JWT_DCQL_PROFILE";

/// Prepared only from a saved policy and workload-authenticated query transport.
/// It retains digests, not the wallet token. This type has no JSON constructor.
#[derive(Clone, PartialEq)]
pub struct SdJwtDcqlRequest {
    organization_id: String,
    policy: FrozenPolicyIdentity,
    selected_trust_profile_id: Option<Uuid>,
    credential_template_id: String,
    query_id: String,
    query_digest: String,
    response_token_digest: String,
    nonce: String,
    audience: String,
    vct: String,
    claims: Vec<String>,
    checked_at_epoch_seconds: u64,
}

impl std::fmt::Debug for SdJwtDcqlRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SdJwtDcqlRequest")
            .field("query_id", &self.query_id)
            .field("query_digest", &self.query_digest)
            .finish_non_exhaustive()
    }
}

/// Native proof of query/subject/key binding, separate from policy acceptance.
///
/// No raw subject, credential, disclosure, public key or claim value is retained
/// in this projection. It cannot be deserialized or constructed by consumers.
/// In particular it cannot become `AuthenticatedOid4vpEvidenceV1` or an issuance
/// continuation without the remaining authoritative trust/status/replay work.
///
/// ```compile_fail
/// let _: marty_presentation_policy::AuthenticatedSdJwtQueryEvidence =
///     serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, PartialEq, Serialize)]
pub struct AuthenticatedSdJwtQueryEvidence {
    contract: &'static str,
    organization_id: String,
    policy: FrozenPolicyIdentity,
    credential_template_id: String,
    query_id: String,
    query_digest: String,
    response_token_digest: String,
    nonce_digest: String,
    audience_digest: String,
    issuer_id: String,
    issuer_scoped_subject_digest: String,
    holder_key_thumbprint: String,
    vct: String,
    issuer_algorithm: String,
    matched_claims: Vec<String>,
    checked_at_epoch_seconds: u64,
    /// Internal consistency fence for the adjacent native policy facts. The
    /// public projection intentionally carries no claim values or their hashes.
    #[serde(skip)]
    policy_claims_digest: String,
    #[serde(skip)]
    valid_from_epoch_seconds: u64,
    #[serde(skip)]
    expires_at_epoch_seconds: u64,
    #[serde(skip)]
    holder_proof_issued_at: f64,
    #[serde(skip)]
    holder_proof_not_before: Option<f64>,
    #[serde(skip)]
    holder_proof_expires_at: Option<f64>,
    #[serde(skip)]
    selected_trust_profile_id: Option<Uuid>,
}

impl std::fmt::Debug for AuthenticatedSdJwtQueryEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedSdJwtQueryEvidence")
            .field("query_id", &self.query_id)
            .field("query_digest", &self.query_digest)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedSdJwtQueryEvidence {
    pub(crate) fn credential_template_id(&self) -> &str {
        &self.credential_template_id
    }

    pub(crate) fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    pub(crate) fn matches_request(
        &self,
        policy: &PresentationPolicy,
        request: &EvaluatePresentationRequest,
    ) -> bool {
        SdJwtDcqlRequest::prepare(
            policy,
            request,
            DetectedCredentialFormat::SdJwt,
            self.checked_at_epoch_seconds,
        )
        .ok()
        .flatten()
        .is_some_and(|prepared| prepared.matches_evidence(self))
    }

    pub(crate) fn matches_claims(&self, claims: &Map<String, Value>) -> bool {
        digest_domain_json("marty.oid4vp/selected-claims/v1", claims)
            .is_ok_and(|digest| digest == self.policy_claims_digest)
    }

    /// Refresh the observation after awaited key/trust/status work. A native
    /// library's JWT leeway must not extend this profile's live validity window.
    pub(crate) fn revalidate_at(&mut self, now: u64) -> Result<(), PresentationVerificationError> {
        if now < self.checked_at_epoch_seconds
            || now < self.valid_from_epoch_seconds
            || now >= self.expires_at_epoch_seconds
        {
            return Err(PresentationVerificationError::Failed(
                "PRESENTATION_POLICY.SD_JWT_EXPIRED_DURING_EVALUATION".into(),
            ));
        }
        // Match the pinned Core verifier's NumericDate window, including
        // fractional seconds. Trust/status awaits must not age a holder proof
        // past that window while refreshing its final observation time.
        if !holder_proof_is_live(
            now,
            self.holder_proof_issued_at,
            self.holder_proof_not_before,
            self.holder_proof_expires_at,
        ) {
            return Err(PresentationVerificationError::Failed(
                "PRESENTATION_POLICY.SD_JWT_HOLDER_PROOF_EXPIRED_DURING_EVALUATION".into(),
            ));
        }
        self.checked_at_epoch_seconds = now;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DcqlQuery {
    credentials: Vec<DcqlCredential>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DcqlCredential {
    id: String,
    format: String,
    meta: DcqlMeta,
    #[serde(default)]
    claims: Vec<DcqlClaim>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DcqlMeta {
    vct_values: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DcqlClaim {
    id: Option<String>,
    path: Vec<String>,
}

/// Reject duplicate query keys as well as extra responses before selecting any
/// token. A generic JSON object parser would silently replace duplicate keys.
struct SingleResponse {
    query_id: String,
    tokens: Vec<String>,
}

impl<'de> Deserialize<'de> for SingleResponse {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = SingleResponse;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("one DCQL response key with one token")
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let (query_id, tokens) = map
                    .next_entry::<String, Vec<String>>()?
                    .ok_or_else(|| de::Error::custom("missing DCQL response"))?;
                if tokens.len() != 1 || map.next_key::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("ambiguous DCQL response"));
                }
                Ok(SingleResponse { query_id, tokens })
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

impl SdJwtDcqlRequest {
    pub(crate) fn prepare(
        policy: &PresentationPolicy,
        request: &EvaluatePresentationRequest,
        format: DetectedCredentialFormat,
        checked_at_epoch_seconds: u64,
    ) -> Result<Option<Self>, PresentationVerificationError> {
        let Some(transport) = request.oid4vp_transport.as_ref() else {
            return Ok(None);
        };
        if transport.query_kind != QueryKind::Dcql {
            return Ok(None);
        }
        let selected_profile = format == DetectedCredentialFormat::SdJwt
            || policy
                .credential_requirements
                .iter()
                .any(|requirement| requirement.credential_payload_format == "SD_JWT_VC")
            || transport.query_document["credentials"]
                .as_array()
                .is_some_and(|credentials| {
                    credentials
                        .iter()
                        .any(|credential| credential["format"] == "dc+sd-jwt")
                });
        if !selected_profile {
            return Ok(None);
        }
        let invalid = || PresentationVerificationError::Failed(PROFILE_ERROR.into());
        transport.validate_transport().map_err(|_| invalid())?;
        // The first profile is the normal client-ID OID4VP binding. DC API has
        // a different origin-based audience and requires its own typed adapter.
        if format != DetectedCredentialFormat::SdJwt
            || !request.trusted_internal_context
            || request.nonce.as_deref() != Some(transport.request_nonce.as_str())
            || request.audience.as_deref() != Some(transport.verifier_client_id.as_str())
            || transport.request_nonce.len() < MIN_NONCE_BYTES
            || transport.presentation_submission.is_some()
            || policy.status != PolicyStatus::Active
            || policy.credential_requirements.len() != 1
            || !policy.alternative_requirements.is_empty()
        {
            return Err(invalid());
        }
        let requirement = &policy.credential_requirements[0];
        if !requirement.required
            || requirement.credential_payload_format != "SD_JWT_VC"
            || requirement
                .requested_claims
                .iter()
                .any(|claim| claim.accept_derived || claim.predicate_spec.is_some())
        {
            return Err(invalid());
        }
        let query: DcqlQuery =
            serde_json::from_value(transport.query_document.clone()).map_err(|_| invalid())?;
        if query.credentials.len() != 1 {
            return Err(invalid());
        }
        let credential = query.credentials.into_iter().next().ok_or_else(invalid)?;
        if credential.id != requirement.id.to_string()
            || credential.format != "dc+sd-jwt"
            || credential.meta.vct_values.len() != 1
            || credential.claims.len() > MAX_CLAIMS_PER_CREDENTIAL
        {
            return Err(invalid());
        }
        if transport.query_document["credentials"][0]
            .get("claims")
            .is_some()
            && credential.claims.is_empty()
        {
            return Err(invalid());
        }
        let vct = credential.meta.vct_values[0].clone();
        if !bounded_text(&vct, 2048) || url::Url::parse(&vct).is_err() {
            return Err(invalid());
        }
        // Follow the Core producer's selected-claims rule and retain literal
        // top-level names. Dotted names are not reinterpreted as nested paths.
        let has_required = requirement
            .requested_claims
            .iter()
            .any(|claim| claim.required);
        let selected_claims = requirement
            .requested_claims
            .iter()
            .filter(|claim| !has_required || claim.required)
            .collect::<Vec<_>>();
        let expected = selected_claims
            .iter()
            .map(|claim| claim.claim_name.clone())
            .collect::<BTreeSet<_>>();
        if expected.len() != selected_claims.len() {
            return Err(invalid());
        }
        let mut names = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for claim in &credential.claims {
            if claim.path.len() != 1
                || !bounded_text(&claim.path[0], MAX_IDENTIFIER_BYTES)
                || !names.insert(claim.path[0].clone())
                || claim.id.as_ref().is_some_and(|id| {
                    !bounded_text(id, MAX_IDENTIFIER_BYTES) || !ids.insert(id.clone())
                })
            {
                return Err(invalid());
            }
        }
        if names != expected || names.len() != credential.claims.len() {
            return Err(invalid());
        }
        let response: SingleResponse =
            serde_json::from_str(&transport.vp_token_raw).map_err(|_| invalid())?;
        let token = &response.tokens[0];
        if response.query_id != credential.id
            || token.len() > MAX_TOKEN_BYTES
            || request.vp_token.as_str() != Some(token.as_str())
        {
            return Err(invalid());
        }
        Ok(Some(Self {
            organization_id: policy.organization_id.to_string(),
            policy: policy_revision(policy).map_err(|_| invalid())?,
            selected_trust_profile_id: crate::verification::selected_trust_profile(
                policy, request,
            )?,
            credential_template_id: requirement.credential_template_id.clone(),
            query_id: credential.id.clone(),
            query_digest: transport.query_digest.clone(),
            response_token_digest: digest_response_item(token, &credential.id, "0")
                .map_err(|_| invalid())?,
            nonce: transport.request_nonce.clone(),
            audience: transport.verifier_client_id.clone(),
            vct,
            claims: names.into_iter().collect(),
            checked_at_epoch_seconds,
        }))
    }

    pub(crate) fn nonce(&self) -> &str {
        &self.nonce
    }

    pub(crate) fn audience(&self) -> &str {
        &self.audience
    }

    pub(crate) fn matches_evidence(&self, evidence: &AuthenticatedSdJwtQueryEvidence) -> bool {
        evidence.organization_id == self.organization_id
            && evidence.policy == self.policy
            && evidence.selected_trust_profile_id == self.selected_trust_profile_id
            && evidence.credential_template_id == self.credential_template_id
            && evidence.query_id == self.query_id
            && evidence.query_digest == self.query_digest
            && evidence.response_token_digest == self.response_token_digest
            && digest_nonce(&self.nonce).is_ok_and(|digest| digest == evidence.nonce_digest)
            && digest_audience(&self.audience)
                .is_ok_and(|digest| digest == evidence.audience_digest)
            && evidence.vct == self.vct
            && evidence.matched_claims == self.claims
            && evidence.checked_at_epoch_seconds == self.checked_at_epoch_seconds
    }

    pub(crate) fn policy_claims(&self, verified: &Map<String, Value>) -> Map<String, Value> {
        self.claims
            .iter()
            .filter_map(|name| {
                verified
                    .get(name)
                    .map(|value| (name.clone(), value.clone()))
            })
            .collect()
    }

    /// The constructor and the call supplying *both* verifier bindings stay in
    /// one function. Receiving an AuthenticatedSdJwt from another call is not
    /// sufficient to construct this more specific evidence.
    pub(crate) fn verify(
        &self,
        key: &ResolvedIssuerKey,
        token: &str,
    ) -> Result<(Map<String, Value>, AuthenticatedSdJwtQueryEvidence), &'static str> {
        if digest_response_item(token, &self.query_id, "0").map_err(|_| PROFILE_ERROR)?
            != self.response_token_digest
        {
            return Err(PROFILE_ERROR);
        }
        let issuer_algorithm = selected_algorithm(&key.public_jwk)?;
        let policy = SdJwtVerificationPolicy {
            expected_issuer: key.issuer_id.clone(),
            issuer_algorithm,
            holder_algorithms: vec![SigningAlgorithm::ES256, SigningAlgorithm::EdDSA],
        };
        let verified = verify_sd_jwt_with_policy(
            token,
            &key.public_jwk.to_string(),
            &policy,
            Some(self.audience.clone()),
            Some(self.nonce.clone()),
        )
        .map_err(|_| "SD-JWT signature or holder binding rejected")?;
        // Core also supports generic SD-JWT. This selected DCQL format is the
        // VC profile, so authenticate its protected type as well as its VCT.
        let header_bytes = URL_SAFE_NO_PAD
            .decode(token.split('.').next().ok_or(PROFILE_ERROR)?)
            .map_err(|_| PROFILE_ERROR)?;
        let header: Value = serde_json::from_slice(&header_bytes).map_err(|_| PROFILE_ERROR)?;
        if header["typ"] != "dc+sd-jwt" {
            return Err("SD-JWT protected type does not match the DCQL format");
        }
        let claims = verified.claims().as_object().ok_or(PROFILE_ERROR)?;
        // Parse only after native signature/binding verification. Generic
        // SD-JWT can reconstruct these members, but the selected VC profile
        // requires them to remain in the authenticated issuer payload.
        let issuer_payload = authenticated_payload(token.split('~').next().ok_or(PROFILE_ERROR)?)?;
        for name in [
            "iss",
            "nbf",
            "exp",
            "cnf",
            "vct",
            "vct#integrity",
            "aka_vcts",
            "status",
        ] {
            if issuer_payload.get(name) != claims.get(name) {
                return Err("SD-JWT VC security metadata must not be selectively disclosed");
            }
        }
        let holder_payload = authenticated_payload(
            token
                .rsplit('~')
                .find(|part| !part.is_empty())
                .ok_or(PROFILE_ERROR)?,
        )?;
        let holder_proof_issued_at = holder_payload
            .get("iat")
            .and_then(Value::as_f64)
            .ok_or(PROFILE_ERROR)?;
        let holder_proof_not_before = optional_numeric_date(&holder_payload, "nbf")?;
        let holder_proof_expires_at = optional_numeric_date(&holder_payload, "exp")?;
        if !holder_proof_is_live(
            self.checked_at_epoch_seconds,
            holder_proof_issued_at,
            holder_proof_not_before,
            holder_proof_expires_at,
        ) {
            return Err("SD-JWT holder proof freshness rejected");
        }
        let subject = claims
            .get("sub")
            .and_then(Value::as_str)
            .ok_or(PROFILE_ERROR)?;
        if !bounded_text(subject, MAX_IDENTIFIER_BYTES)
            || claims.get("vct").and_then(Value::as_str) != Some(self.vct.as_str())
        {
            return Err("SD-JWT subject or exact VCT is missing or mismatched");
        }
        let issued_at = claims
            .get("iat")
            .and_then(Value::as_u64)
            .ok_or(PROFILE_ERROR)?;
        let expires_at = claims
            .get("exp")
            .and_then(Value::as_u64)
            .ok_or(PROFILE_ERROR)?;
        if issued_at > self.checked_at_epoch_seconds
            || expires_at <= self.checked_at_epoch_seconds
            || expires_at <= issued_at
            || claims.get("nbf").is_some_and(|value| {
                value
                    .as_u64()
                    .is_none_or(|not_before| not_before > self.checked_at_epoch_seconds)
            })
        {
            return Err("SD-JWT credential lifetime rejected");
        }
        for name in &self.claims {
            let value = claims.get(name).ok_or("SD-JWT requested claim is absent")?;
            if !(value.is_string() || value.is_number() || value.is_boolean())
                || serde_json::to_vec(value).map_err(|_| PROFILE_ERROR)?.len()
                    > MAX_CLAIM_VALUE_BYTES
            {
                return Err("SD-JWT requested claim is outside the scalar profile");
            }
        }
        let confirmation = claims
            .get("cnf")
            .and_then(Value::as_object)
            .ok_or(PROFILE_ERROR)?;
        if confirmation.len() != 1 {
            return Err("SD-JWT holder confirmation is ambiguous");
        }
        let holder = confirmation.get("jwk").ok_or(PROFILE_ERROR)?;
        let holder_key_thumbprint = public_key_thumbprint(holder)?;
        let evidence = AuthenticatedSdJwtQueryEvidence {
            contract: "marty.sd-jwt-dcql-query-evidence/v1",
            organization_id: self.organization_id.clone(),
            policy: self.policy.clone(),
            credential_template_id: self.credential_template_id.clone(),
            query_id: self.query_id.clone(),
            query_digest: self.query_digest.clone(),
            response_token_digest: self.response_token_digest.clone(),
            nonce_digest: digest_nonce(&self.nonce).map_err(|_| PROFILE_ERROR)?,
            audience_digest: digest_audience(&self.audience).map_err(|_| PROFILE_ERROR)?,
            issuer_id: verified.issuer().to_owned(),
            issuer_scoped_subject_digest: digest_domain_json(
                "marty.oid4vp/issuer-scoped-subject/v1",
                &json!({"issuer_id":verified.issuer(), "subject_id":subject}),
            )
            .map_err(|_| PROFILE_ERROR)?,
            holder_key_thumbprint,
            vct: self.vct.clone(),
            issuer_algorithm: issuer_algorithm.as_str().to_owned(),
            matched_claims: self.claims.clone(),
            checked_at_epoch_seconds: self.checked_at_epoch_seconds,
            policy_claims_digest: digest_domain_json(
                "marty.oid4vp/selected-claims/v1",
                &self.policy_claims(claims),
            )
            .map_err(|_| PROFILE_ERROR)?,
            valid_from_epoch_seconds: issued_at.max(
                claims
                    .get("nbf")
                    .and_then(Value::as_u64)
                    .unwrap_or(issued_at),
            ),
            expires_at_epoch_seconds: expires_at,
            holder_proof_issued_at,
            holder_proof_not_before,
            holder_proof_expires_at,
            selected_trust_profile_id: self.selected_trust_profile_id,
        };
        Ok((claims.clone(), evidence))
    }
}

fn authenticated_payload(compact_jwt: &str) -> Result<Map<String, Value>, &'static str> {
    let bytes = URL_SAFE_NO_PAD
        .decode(compact_jwt.split('.').nth(1).ok_or(PROFILE_ERROR)?)
        .map_err(|_| PROFILE_ERROR)?;
    serde_json::from_slice::<Value>(&bytes)
        .map_err(|_| PROFILE_ERROR)?
        .as_object()
        .cloned()
        .ok_or(PROFILE_ERROR)
}

fn optional_numeric_date(
    payload: &Map<String, Value>,
    name: &str,
) -> Result<Option<f64>, &'static str> {
    payload
        .get(name)
        .map(|value| {
            value
                .as_f64()
                .filter(|value| value.is_finite())
                .ok_or(PROFILE_ERROR)
        })
        .transpose()
}

fn holder_proof_is_live(
    now: u64,
    issued_at: f64,
    not_before: Option<f64>,
    expires_at: Option<f64>,
) -> bool {
    let now = now as f64;
    issued_at.is_finite()
        && (-60.0..=300.0).contains(&(now - issued_at))
        && not_before.is_none_or(|start| now >= start)
        && expires_at.is_none_or(|end| now < end)
}

fn bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value == value.trim()
        && !value.chars().any(char::is_control)
}

/// Select the role algorithm from the governed key, never the wallet header.
fn selected_algorithm(jwk: &Value) -> Result<SigningAlgorithm, &'static str> {
    let object = jwk.as_object().ok_or(PROFILE_ERROR)?;
    if marty_key_material_policy::private_jwk_members(object)
        .next()
        .is_some()
    {
        return Err("Private key material is forbidden");
    }
    let algorithm = match (jwk["kty"].as_str(), jwk["crv"].as_str()) {
        (Some("EC"), Some("P-256")) => SigningAlgorithm::ES256,
        (Some("OKP"), Some("Ed25519")) => SigningAlgorithm::EdDSA,
        _ => return Err("SD-JWT key is outside the supported algorithm profile"),
    };
    if object
        .get("alg")
        .is_some_and(|value| value.as_str() != Some(algorithm.as_str()))
    {
        return Err("SD-JWT governed key algorithm is inconsistent");
    }
    Ok(algorithm)
}

/// RFC 7638 uses only the required public members in lexicographic order. The
/// native verifier has already verified the KB-JWT with this issuer-signed key.
fn public_key_thumbprint(jwk: &Value) -> Result<String, &'static str> {
    let algorithm = selected_algorithm(jwk)?;
    let members: &[&str] = match algorithm {
        SigningAlgorithm::ES256 => &["crv", "kty", "x", "y"],
        SigningAlgorithm::EdDSA => &["crv", "kty", "x"],
        _ => return Err(PROFILE_ERROR),
    };
    let mut canonical = BTreeMap::new();
    for member in members {
        let value = jwk[*member].as_str().ok_or(PROFILE_ERROR)?;
        if matches!(*member, "x" | "y") {
            let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| PROFILE_ERROR)?;
            if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != value {
                return Err(PROFILE_ERROR);
            }
        }
        canonical.insert(*member, value);
    }
    let bytes = serde_json::to_vec(&canonical).map_err(|_| PROFILE_ERROR)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
}
