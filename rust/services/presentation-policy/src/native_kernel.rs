use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::DateTime;
use marty_verification::credential_format::DetectedCredentialFormat;
use marty_verification::mdoc::{
    disclosed_claims, verify_mdoc_presentation, MdocDocumentVerificationEvidence,
    MdocPresentationVerificationResult,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    CredentialStatusEvidence, CredentialVerificationContext, CredentialVerificationEvidence,
    CredentialVerificationKernel, PresentationVerificationError,
};

type JsonObject = Map<String, Value>;
type VerifiedJwtMaterial = (CredentialVerificationEvidence, Option<JsonObject>);
type OpenBadgeDocument = (JsonObject, JsonObject);

/// Direct adapter over the canonical Marty Rust credential verifiers.
#[derive(Clone, Debug, Default)]
pub struct RustCredentialKernel;

#[async_trait]
impl CredentialVerificationKernel for RustCredentialKernel {
    async fn verify(
        &self,
        context: &CredentialVerificationContext,
    ) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
        match context.format {
            DetectedCredentialFormat::W3cVc => verify_vc_jwt(context, false).await,
            DetectedCredentialFormat::W3cVcdmDi => verify_data_integrity(context).await,
            DetectedCredentialFormat::SdJwt => verify_sd_jwt(context),
            DetectedCredentialFormat::OpenbadgeV2 => verify_open_badge(context, 2).await,
            DetectedCredentialFormat::OpenbadgeV3 => verify_open_badge(context, 3).await,
            DetectedCredentialFormat::Mdoc => verify_mdoc(context),
            DetectedCredentialFormat::Unknown => {
                Ok(rejected("Unsupported or malformed credential presentation"))
            }
        }
    }
}

fn verify_mdoc(
    context: &CredentialVerificationContext,
) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
    let mdoc_bytes = match decode_mdoc_token(token_string(&context.token)?) {
        Ok(bytes) => bytes,
        Err(reason) => return Ok(rejected_mdoc(reason)),
    };
    let session_transcript = match context
        .verifier_context
        .get("mdoc_session_transcript_b64url")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .and_then(|value| decode_base64url(value).ok())
        .filter(|value| !value.is_empty())
    {
        Some(value) => value,
        None => {
            return Ok(rejected_mdoc(
                "Verifier-owned mdoc session transcript is required",
            ))
        }
    };
    if context.audience.as_deref().is_some_and(|audience| {
        context
            .verifier_context
            .get("oid4vp_client_id")
            .and_then(Value::as_str)
            .filter(|client_id| !client_id.is_empty())
            .is_some_and(|client_id| client_id != audience)
    }) {
        return Ok(rejected_mdoc(
            "mdoc verifier audience does not match request state",
        ));
    }
    let (roots, pinned_issuers) = mdoc_trust_certificates(context);
    if roots.is_empty() && pinned_issuers.is_empty() {
        return Ok(rejected_mdoc(
            "No trusted mdoc issuer certificates are configured",
        ));
    }

    let result =
        verify_mdoc_presentation(&mdoc_bytes, &session_transcript, &roots, &pinned_issuers);
    let error_kind = classify_mdoc_error(result.error.as_deref());
    tracing::info!(
        transcript_sha256 = %hex::encode(Sha256::digest(&session_transcript)),
        device_response_sha256 = %hex::encode(Sha256::digest(&mdoc_bytes)),
        issuer_signature_valid = result.issuer_signature_valid,
        issuer_trusted = result.issuer_trusted,
        device_authentication_valid = result.device_authentication_valid,
        device_auth_error_kind = error_kind,
        "mDoc verification completed"
    );
    project_mdoc_result(&mdoc_bytes, result, context)
}

fn project_mdoc_result(
    mdoc_bytes: &[u8],
    result: MdocPresentationVerificationResult,
    context: &CredentialVerificationContext,
) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
    let authentication_valid = result.issuer_signature_valid
        && result.issuer_trusted
        && result.device_authentication_valid;
    let Some(document) = authenticated_mdoc_document(&result) else {
        return Ok(rejected_mdoc(result.error.as_deref().unwrap_or(
            if authentication_valid {
                "Authenticated mdoc evidence is incomplete"
            } else {
                "mDoc authentication failed"
            },
        )));
    };
    if !authentication_valid {
        return Ok(rejected_mdoc(
            result
                .error
                .as_deref()
                .unwrap_or("mDoc authentication failed"),
        ));
    }
    let claims = disclosed_claims(mdoc_bytes)
        .map_err(|_| invalid_native("mDoc claim extraction rejected authenticated CBOR"))?
        .as_object()
        .cloned()
        .ok_or_else(|| invalid_native("mDoc claims were not a JSON object"))?;
    Ok(project_authenticated_mdoc(document, claims, context))
}

fn project_authenticated_mdoc(
    document: &MdocDocumentVerificationEvidence,
    claims: Map<String, Value>,
    context: &CredentialVerificationContext,
) -> CredentialVerificationEvidence {
    let issued_at_epoch_seconds = parse_epoch(&document.signed_at);
    let issuer_id = format!("x509-sha256:{}", document.issuer_certificate_sha256);
    CredentialVerificationEvidence {
        verified: true,
        claims,
        issuer_id: Some(issuer_id),
        issued_at_epoch_seconds,
        algorithm: Some(document.signature_algorithm.clone()),
        validity_checked: true,
        is_expired: Some(false),
        presentation_verified: true,
        presentation_count: Some(1),
        holder_binding_verified: true,
        holder_binding_method: Some("DEVICE_KEY".into()),
        proof_profile: Some("OID4VP_VERIFIABLE_PRESENTATION".into()),
        challenge_verified: context.nonce.is_some(),
        audience_verified: context.audience.is_some(),
        ..Default::default()
    }
}

fn authenticated_mdoc_document(
    result: &MdocPresentationVerificationResult,
) -> Option<&MdocDocumentVerificationEvidence> {
    if result.document_types.len() != 1
        || result.document_evidence.len() != 1
        || result.revocation_checked
        || result.not_revoked.is_some()
    {
        return None;
    }
    let document = &result.document_evidence[0];
    (result.document_types[0] == document.document_type
        && !document.document_type.is_empty()
        && !document.signature_algorithm.is_empty()
        && !document.digest_algorithm.is_empty()
        && parse_epoch(&document.signed_at).is_some()
        && parse_epoch(&document.valid_from).is_some()
        && parse_epoch(&document.valid_until).is_some()
        && document.issuer_certificate_sha256.len() == 64
        && document
            .issuer_certificate_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && document.validity_checked
        && document.valid_at_verification_time
        && !document.revocation_checked
        && document.not_revoked.is_none())
    .then_some(document)
}

fn mdoc_trust_certificates(context: &CredentialVerificationContext) -> (Vec<String>, Vec<String>) {
    let Some(sources) = context
        .trust_profile
        .as_ref()
        .and_then(|profile| profile.document.get("trust_sources"))
        .and_then(Value::as_array)
    else {
        return (Vec::new(), Vec::new());
    };
    let mut roots = Vec::new();
    let mut pinned_issuers = Vec::new();
    for source in sources.iter().filter_map(Value::as_object) {
        if source.get("enabled") == Some(&Value::Bool(false)) {
            continue;
        }
        let target = match source
            .get("source_type")
            .and_then(Value::as_str)
            .map(str::to_ascii_uppercase)
            .as_deref()
        {
            Some("ROOT_CA") => &mut roots,
            Some("PINNED_ISSUER") => &mut pinned_issuers,
            _ => continue,
        };
        for candidate in source
            .get("certificate_pem")
            .into_iter()
            .chain(
                source
                    .get("pinned_certificates")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten(),
            )
            .filter_map(Value::as_str)
            .filter(|pem| pem.contains("-----BEGIN CERTIFICATE-----"))
        {
            if !target.iter().any(|existing| existing == candidate) {
                target.push(candidate.to_owned());
            }
        }
    }
    (roots, pinned_issuers)
}

fn decode_mdoc_token(token: &str) -> Result<Vec<u8>, &'static str> {
    let encoded = token.trim();
    if let Some(value) = encoded.strip_prefix("\\x") {
        return hex::decode(value).map_err(|_| "mDoc token is not valid hexadecimal CBOR");
    }
    let encoded = encoded
        .strip_prefix("mso_mdoc:")
        .or_else(|| encoded.strip_prefix("mdoc:"))
        .unwrap_or(encoded);
    decode_base64url(encoded).map_err(|_| "mDoc token is not valid base64url CBOR")
}

fn decode_base64url(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(value.trim_end_matches('='))
}

fn classify_mdoc_error(error: Option<&str>) -> &'static str {
    let Some(error) = error else {
        return "none";
    };
    let normalized = error.to_ascii_lowercase();
    [
        ("unsupported", "device-auth-method-unsupported"),
        ("missing coordinates", "device-key-coordinates-missing"),
        ("algorithm", "device-signature-algorithm-mismatch"),
        ("digest mismatch", "issuer-disclosure-digest-mismatch"),
        ("signature", "device-signature-invalid"),
        ("mso is expired", "mso-expired"),
        ("cryptographic", "device-key-invalid"),
        ("cbor", "device-auth-cbor-error"),
    ]
    .into_iter()
    .find_map(|(marker, category)| normalized.contains(marker).then_some(category))
    .unwrap_or("unclassified")
}

fn rejected_mdoc(reason: &str) -> CredentialVerificationEvidence {
    CredentialVerificationEvidence {
        verified: false,
        failure_reason: Some(reason.into()),
        presentation_count: Some(1),
        holder_binding_method: Some("DEVICE_KEY".into()),
        proof_profile: Some("OID4VP_VERIFIABLE_PRESENTATION".into()),
        ..Default::default()
    }
}

async fn verify_vc_jwt(
    context: &CredentialVerificationContext,
    open_badge_v3: bool,
) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
    let (evidence, _) = verify_vc_jwt_material(context, open_badge_v3).await?;
    Ok(evidence)
}

async fn verify_vc_jwt_material(
    context: &CredentialVerificationContext,
    open_badge_v3: bool,
) -> Result<VerifiedJwtMaterial, PresentationVerificationError> {
    let token = token_string(&context.token)?;
    let mut request = json!({"token": token});
    if let Some(public_jwk) = governed_public_jwk(context, token) {
        request["issuer_public_jwk"] = public_jwk;
    }
    let raw = if open_badge_v3 {
        marty_verification::vcdm::verify_open_badge_v3_jwt_json_async(&request.to_string()).await
    } else {
        marty_verification::vcdm::verify_vcdm_jwt_json_async(&request.to_string()).await
    };
    let result = internal_json(&raw, "VC-JWT")?;
    let valid = result.get("valid").and_then(Value::as_bool) == Some(true);
    if !valid {
        return Ok((
            rejected_counted(
                if open_badge_v3 {
                    "Open Badges v3 VC-JWT"
                } else {
                    "VCDM VC-JWT"
                },
                error_count(&result),
            ),
            None,
        ));
    }
    let claims = result
        .get("claims")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_native("VC-JWT verifier omitted authenticated claims"))?;
    let credential = claims
        .get("vc")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_native("VC-JWT verifier omitted the credential object"))?;
    let mut evidence = credential_evidence(
        credential,
        result.get("issuer").and_then(Value::as_str),
        false,
        1,
    );
    bind_authenticated_jwt_credential_id(&mut evidence, claims);
    evidence.algorithm = jwt_algorithm(token);
    evidence.validity_checked = true;
    evidence.is_expired = Some(false);
    Ok((evidence, Some(credential.clone())))
}

async fn verify_data_integrity(
    context: &CredentialVerificationContext,
) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
    let document = context
        .token
        .as_object()
        .ok_or_else(|| invalid_input("Data Integrity presentation must be a JSON object"))?;
    let request = json!({
        "document": document,
        "expected_challenge": context.nonce,
        "expected_domain": context.audience,
        "resolved_verification_methods": trust_value(context, "resolved_verification_methods")
            .cloned()
            .unwrap_or_else(|| json!([])),
    });
    let raw =
        marty_verification::vcdm::verify_vcdm_data_integrity_json_async(&request.to_string()).await;
    let result = internal_json(&raw, "VCDM Data Integrity")?;
    if result.get("valid").and_then(Value::as_bool) != Some(true) {
        return Ok(rejected_counted(
            "VCDM Data Integrity",
            error_count(&result),
        ));
    }
    let is_presentation = result.get("kind").and_then(Value::as_str) == Some("presentation");
    let credential_count = result
        .get("verified_credentials")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(1);
    let credential = if is_presentation {
        let credentials = document
            .get("verifiableCredential")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid_native("Verified presentation omitted credentials"))?;
        if credentials.len() != 1 {
            return Ok(rejected(
                "Presentation must contain exactly one independently verified credential",
            ));
        }
        credentials[0]
            .as_object()
            .ok_or_else(|| invalid_native("Verified credential was not an object"))?
    } else {
        document
    };
    let mut evidence = credential_evidence(
        credential,
        issuer_id(credential),
        is_presentation,
        credential_count,
    );
    evidence.holder_binding_verified = is_presentation;
    evidence.holder_binding_method = is_presentation.then(|| "DEVICE_KEY".into());
    evidence.proof_profile = is_presentation.then(|| "OID4VP_VERIFIABLE_PRESENTATION".into());
    evidence.challenge_verified = is_presentation && context.nonce.is_some();
    evidence.audience_verified = is_presentation && context.audience.is_some();
    evidence.algorithm = result
        .get("algorithm")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| proof_algorithm(credential));
    evidence.validity_checked = true;
    evidence.is_expired = Some(false);
    Ok(evidence)
}

fn verify_sd_jwt(
    context: &CredentialVerificationContext,
) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
    let token = token_string(&context.token)?;
    let Some(public_jwk) = governed_public_jwk(context, token) else {
        return Ok(rejected(
            "No governed issuer public JWK is available for SD-JWT",
        ));
    };
    let verified = marty_oid4vci::formats::sd_jwt::verify_sd_jwt(
        token,
        &public_jwk.to_string(),
        context.audience.clone(),
        context.nonce.clone(),
    );
    let claims = match verified {
        Ok(Value::Object(claims)) => claims,
        Ok(_) => return Err(invalid_native("SD-JWT verifier returned non-object claims")),
        Err(_) => return Ok(rejected("SD-JWT verification rejected the credential")),
    };
    let credential = claims
        .get("vc")
        .and_then(Value::as_object)
        .or_else(|| claims.get("credential").and_then(Value::as_object));
    let disclosed = credential
        .and_then(|value| value.get("credentialSubject"))
        .and_then(Value::as_object)
        .cloned()
        .or_else(|| {
            claims
                .get("credentialSubject")
                .and_then(Value::as_object)
                .cloned()
        })
        .unwrap_or_else(|| claims.clone());
    let issuer = claims.get("iss").and_then(Value::as_str).map(str::to_owned);
    let credential_id = claims
        .get("jti")
        .and_then(Value::as_str)
        .or_else(|| {
            credential
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
        })
        .map(str::to_owned);
    let issued_at = claims
        .get("iat")
        .and_then(Value::as_u64)
        .or_else(|| credential.and_then(issued_at));
    let bound = context.nonce.is_some() || context.audience.is_some();
    Ok(CredentialVerificationEvidence {
        verified: true,
        credential_id: credential_id.clone(),
        credential_status_ids: credential_id.into_iter().collect(),
        claims: disclosed,
        issuer_id: issuer,
        issued_at_epoch_seconds: issued_at,
        algorithm: jwt_algorithm(token),
        validity_checked: true,
        is_expired: Some(false),
        presentation_verified: bound,
        presentation_count: Some(1),
        holder_binding_verified: bound,
        holder_binding_method: bound.then(|| "DEVICE_KEY".into()),
        proof_profile: bound.then(|| "OID4VP_VERIFIABLE_PRESENTATION".into()),
        challenge_verified: context.nonce.is_some(),
        audience_verified: context.audience.is_some(),
        ..Default::default()
    })
}

async fn verify_open_badge(
    context: &CredentialVerificationContext,
    version: u8,
) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
    if context.token.as_str().is_some() {
        let (jwt, credential) = verify_vc_jwt_material(context, version == 3).await?;
        if !jwt.verified || version == 3 {
            return Ok(jwt);
        }
        // OB2 profile semantics are still checked below against the credential
        // authenticated by the outer VC-JWT.
        let credential = credential.ok_or_else(|| {
            invalid_native("VC-JWT verifier omitted the authenticated credential")
        })?;
        return verify_open_badge_document(context, version, Some((jwt, credential))).await;
    }
    verify_open_badge_document(context, version, None).await
}

async fn verify_open_badge_document(
    context: &CredentialVerificationContext,
    version: u8,
    authenticated_jwt: Option<(CredentialVerificationEvidence, JsonObject)>,
) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
    let (credential, document_store) = if let Some((_, credential)) = authenticated_jwt.as_ref() {
        (credential.clone(), Map::new())
    } else {
        open_badge_document(
            &context.token,
            if version == 2 {
                "assertion"
            } else {
                "credential"
            },
        )?
    };
    let mut store = document_store;
    if let Some(profile_store) = trust_value(context, "document_store").and_then(Value::as_object) {
        for (key, value) in profile_store {
            store.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }
    let request = if version == 2 {
        json!({"assertion": credential, "document_store": store})
    } else {
        json!({"credential": credential, "document_store": store})
    };
    let raw = if version == 2 {
        marty_verification::open_badges::verify_ob2_json(&request.to_string())
            .map_err(|_| invalid_input("Open Badges v2 verification rejected the credential"))?
    } else {
        marty_verification::open_badges::verify_ob3_json_async(&request.to_string())
            .await
            .map_err(|_| invalid_input("Open Badges v3 verification rejected the credential"))?
    };
    let result = internal_json(&raw, "Open Badges")?;
    if result.get("valid").and_then(Value::as_bool) != Some(true) {
        return Ok(rejected_counted("Open Badges", error_count(&result)));
    }
    let mut claims = result
        .get("normalized")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let subject = claims
        .get("credential_subject")
        .or_else(|| claims.get("credentialSubject"))
        .or_else(|| credential.get("credentialSubject"))
        .or_else(|| credential.get("recipient"))
        .and_then(Value::as_object)
        .cloned();
    if let Some(subject) = subject {
        claims
            .entry("credential_subject".to_string())
            .or_insert_with(|| Value::Object(subject.clone()));
        for (key, value) in subject {
            if !matches!(key.as_str(), "achievement" | "identifier" | "type" | "id")
                && (value.is_number() || value.is_boolean() || value.is_string())
            {
                claims.entry(key).or_insert(value);
            }
        }
    }
    let mut evidence = credential_evidence(&credential, issuer_id(&credential), false, 1);
    evidence.claims = claims;
    evidence.warnings = result
        .get("warnings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    if let Some((jwt, _)) = authenticated_jwt {
        evidence.credential_id = jwt.credential_id;
        evidence.issuer_id = jwt.issuer_id;
        evidence.issued_at_epoch_seconds = jwt.issued_at_epoch_seconds;
        evidence.algorithm = jwt.algorithm;
        evidence.validity_checked = jwt.validity_checked;
        evidence.is_expired = jwt.is_expired;
    } else {
        evidence.algorithm = result
            .get("algorithm")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| proof_algorithm(&credential));
        evidence.validity_checked = true;
        evidence.is_expired = Some(false);
    }
    apply_open_badge_status(&mut evidence, &result);
    Ok(evidence)
}

fn credential_evidence(
    credential: &Map<String, Value>,
    verified_issuer: Option<&str>,
    presentation_verified: bool,
    credential_count: usize,
) -> CredentialVerificationEvidence {
    let claims = credential
        .get("credentialSubject")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let credential_id = credential
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut status_ids = credential_id.iter().cloned().collect::<Vec<_>>();
    collect_status_ids(credential.get("credentialStatus"), &mut status_ids);
    CredentialVerificationEvidence {
        verified: true,
        credential_id,
        credential_status_ids: status_ids,
        claims,
        issuer_id: verified_issuer
            .map(str::to_owned)
            .or_else(|| issuer_id(credential).map(str::to_owned)),
        issued_at_epoch_seconds: issued_at(credential),
        presentation_verified,
        presentation_count: Some(credential_count),
        ..Default::default()
    }
}

fn bind_authenticated_jwt_credential_id(
    evidence: &mut CredentialVerificationEvidence,
    claims: &Map<String, Value>,
) {
    let Some(credential_id) = claims
        .get("jti")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };
    evidence.credential_id = Some(credential_id.to_owned());
    evidence
        .credential_status_ids
        .retain(|candidate| candidate != credential_id);
    evidence
        .credential_status_ids
        .insert(0, credential_id.to_owned());
}

fn open_badge_document(
    token: &Value,
    default_key: &str,
) -> Result<OpenBadgeDocument, PresentationVerificationError> {
    let object = token
        .as_object()
        .ok_or_else(|| invalid_input("Open Badge presentation must be a JSON object"))?;
    let store = object
        .get("document_store")
        .or_else(|| object.get("documentStore"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for key in [default_key, "credential", "assertion"] {
        if let Some(value) = object.get(key).and_then(Value::as_object) {
            return Ok((value.clone(), store));
        }
    }
    if let Some(vp) = object.get("vp").and_then(Value::as_object).or(Some(object)) {
        if let Some(value) = vp.get("verifiableCredential") {
            if let Some(credentials) = value.as_array() {
                if credentials.len() != 1 {
                    return Err(invalid_input(
                        "Open Badge presentation must contain exactly one credential",
                    ));
                }
                if let Some(credential) = credentials[0].as_object() {
                    return Ok((credential.clone(), store));
                }
            } else if let Some(credential) = value.as_object() {
                return Ok((credential.clone(), store));
            }
        }
    }
    Ok((object.clone(), store))
}

fn apply_open_badge_status(evidence: &mut CredentialVerificationEvidence, result: &Value) {
    let Some(checks) = result.get("status_checks").and_then(Value::as_array) else {
        return;
    };
    let Some(latest) = checks
        .iter()
        .max_by_key(|check| check.get("checked_at").and_then(Value::as_str))
    else {
        return;
    };
    let outcome = latest
        .get("outcome")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN");
    evidence.status = CredentialStatusEvidence {
        checked_at_epoch_seconds: latest
            .get("checked_at")
            .and_then(Value::as_str)
            .and_then(parse_epoch),
        not_revoked: match outcome {
            "GOOD" => Some(true),
            "REVOKED" | "SUSPENDED" => Some(false),
            _ => None,
        },
        credential_status: Some(outcome.to_ascii_lowercase()),
        warnings: Vec::new(),
    };
}

fn collect_status_ids(value: Option<&Value>, output: &mut Vec<String>) {
    let values = match value {
        Some(Value::Array(values)) => values.as_slice(),
        Some(value) => std::slice::from_ref(value),
        None => return,
    };
    for value in values {
        if let Some(identifier) = value
            .as_object()
            .and_then(|status| status.get("id"))
            .and_then(Value::as_str)
        {
            if !output.iter().any(|existing| existing == identifier) {
                output.push(identifier.to_owned());
            }
        }
    }
}

fn trust_value<'a>(context: &'a CredentialVerificationContext, key: &str) -> Option<&'a Value> {
    context
        .trust_profile
        .as_ref()
        .and_then(|profile| profile.document.get(key))
}

fn governed_public_jwk(context: &CredentialVerificationContext, token: &str) -> Option<Value> {
    if let Some(jwk) = trust_value(context, "issuer_public_jwk").and_then(Value::as_object) {
        return public_jwk(jwk).then(|| Value::Object(jwk.clone()));
    }
    let profile = context.trust_profile.as_ref()?.document.as_object()?;
    if profile
        .get("status")
        .and_then(Value::as_str)
        .is_none_or(|status| !status.eq_ignore_ascii_case("active"))
    {
        return None;
    }
    let (issuer, kid) = jwt_selector(token)?;
    let normalized_issuer = normalize_issuer(&issuer);

    let overrides = profile
        .get("system_issuer_overrides")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|values| values.iter())
        .filter(|(identifier, _)| normalize_issuer(identifier) == normalized_issuer)
        .filter_map(|(_, value)| value.get("public_jwk").and_then(Value::as_object))
        .filter(|jwk| public_jwk(jwk) && kid_matches(jwk, kid.as_deref()))
        .collect::<Vec<_>>();
    if overrides.len() == 1 {
        return Some(Value::Object(overrides[0].clone()));
    }
    if !overrides.is_empty() {
        return None;
    }

    let relationships = profile
        .get("issuer_relationships")
        .and_then(Value::as_array)?;
    let matching_relationships = relationships
        .iter()
        .filter_map(Value::as_object)
        .filter(|relationship| {
            relationship
                .get("issuer_id")
                .and_then(Value::as_str)
                .is_some_and(|value| normalize_issuer(value) == normalized_issuer)
                && relationship
                    .get("relationship_status")
                    .and_then(Value::as_str)
                    == Some("TRUSTED")
                && matches!(
                    relationship
                        .get("compliance_status")
                        .and_then(Value::as_str),
                    Some("ACCREDITED" | "COMPLIANT")
                )
                && relationship.get("revoked_at").is_none_or(Value::is_null)
        })
        .collect::<Vec<_>>();
    if matching_relationships.len() != 1 {
        return None;
    }
    let keys = matching_relationships[0]
        .get("verification_keys")
        .and_then(Value::as_array)?;
    let public_keys = keys
        .iter()
        .filter_map(Value::as_object)
        .filter(|jwk| public_jwk(jwk))
        .collect::<Vec<_>>();
    let matching_keys = public_keys
        .iter()
        .copied()
        .filter(|jwk| kid_matches(jwk, kid.as_deref()))
        .collect::<Vec<_>>();
    let selected = if matching_keys.len() == 1 {
        matching_keys[0]
    } else if kid.is_some()
        && public_keys.len() == 1
        && public_keys[0].get("kid").is_none_or(Value::is_null)
    {
        public_keys[0]
    } else {
        return None;
    };
    Some(Value::Object(selected.clone()))
}

fn jwt_selector(token: &str) -> Option<(String, Option<String>)> {
    let jwt = token.split('~').next()?;
    let mut parts = jwt.split('.');
    let header = decode_jwt_object(parts.next()?)?;
    let payload = decode_jwt_object(parts.next()?)?;
    parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let issuer = payload.get("iss")?.as_str()?.trim();
    if issuer.is_empty() {
        return None;
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    Some((issuer.to_owned(), kid))
}

fn decode_jwt_object(segment: &str) -> Option<Map<String, Value>> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.as_object().cloned())
}

fn jwt_algorithm(token: &str) -> Option<String> {
    let jwt = token.split('~').next()?;
    let header = decode_jwt_object(jwt.split('.').next()?)?;
    header
        .get("alg")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
}

fn proof_algorithm(document: &Map<String, Value>) -> Option<String> {
    let proofs = match document.get("proof") {
        Some(Value::Array(proofs)) => proofs.as_slice(),
        Some(proof) => std::slice::from_ref(proof),
        None => return None,
    };
    proofs
        .iter()
        .filter_map(Value::as_object)
        .find_map(|proof| {
            proof
                .get("cryptosuite")
                .or_else(|| proof.get("type"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
        })
}

fn public_jwk(jwk: &Map<String, Value>) -> bool {
    jwk.get("kty")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
        && ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
            .iter()
            .all(|parameter| !jwk.contains_key(*parameter))
}

fn kid_matches(jwk: &Map<String, Value>, expected: Option<&str>) -> bool {
    expected.is_none_or(|expected| jwk.get("kid").and_then(Value::as_str) == Some(expected))
}

fn normalize_issuer(value: &str) -> String {
    value.trim().trim_end_matches('/').to_ascii_lowercase()
}

fn token_string(token: &Value) -> Result<&str, PresentationVerificationError> {
    token
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid_input("Credential token must be a non-empty string"))
}

fn issuer_id(credential: &Map<String, Value>) -> Option<&str> {
    credential.get("issuer").and_then(|issuer| match issuer {
        Value::String(value) => Some(value.as_str()),
        Value::Object(value) => value
            .get("id")
            .or_else(|| value.get("url"))
            .and_then(Value::as_str),
        _ => None,
    })
}

fn issued_at(credential: &Map<String, Value>) -> Option<u64> {
    for key in ["validFrom", "issuanceDate", "issuedOn"] {
        if let Some(epoch) = credential
            .get(key)
            .and_then(Value::as_str)
            .and_then(parse_epoch)
        {
            return Some(epoch);
        }
    }
    None
}

fn parse_epoch(value: &str) -> Option<u64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .and_then(|value| u64::try_from(value.timestamp()).ok())
}

fn internal_json(raw: &str, verifier: &str) -> Result<Value, PresentationVerificationError> {
    serde_json::from_str(raw).map_err(|_| {
        invalid_native(&format!(
            "{verifier} returned malformed internal verification evidence"
        ))
    })
}

fn error_count(result: &Value) -> usize {
    result
        .get("errors")
        .and_then(Value::as_array)
        .map_or(1, Vec::len)
}

fn rejected_counted(verifier: &str, errors: usize) -> CredentialVerificationEvidence {
    rejected(&format!(
        "{verifier} verification rejected the credential ({errors} error(s))"
    ))
}

fn rejected(reason: &str) -> CredentialVerificationEvidence {
    CredentialVerificationEvidence {
        verified: false,
        failure_reason: Some(reason.into()),
        ..Default::default()
    }
}

fn invalid_input(detail: &str) -> PresentationVerificationError {
    PresentationVerificationError::Failed(detail.into())
}

fn invalid_native(detail: &str) -> PresentationVerificationError {
    PresentationVerificationError::Failed(format!(
        "PRESENTATION_POLICY.INVALID_NATIVE_EVIDENCE: {detail}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResolvedTrustProfile;
    use uuid::Uuid;

    fn mdoc_contract() -> Value {
        serde_json::from_str(include_str!(
            "../../../../contracts/presentation-mdoc-verification-behavior.json"
        ))
        .unwrap()
    }

    fn compact_jwt(issuer: &str, kid: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(json!({"alg": "EdDSA", "kid": kid}).to_string());
        let payload = URL_SAFE_NO_PAD.encode(json!({"iss": issuer}).to_string());
        format!("{header}.{payload}.signature")
    }

    fn context(document: Value) -> CredentialVerificationContext {
        CredentialVerificationContext {
            format: DetectedCredentialFormat::SdJwt,
            token: Value::Null,
            nonce: None,
            audience: None,
            verifier_context: Map::new(),
            trust_profile: Some(ResolvedTrustProfile {
                id: Uuid::from_u128(1),
                organization_id: Uuid::from_u128(2),
                document,
            }),
        }
    }

    #[test]
    fn governed_key_selection_requires_one_exact_public_relationship_key() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../contracts/presentation-control-plane-behavior.json"
        ))
        .unwrap();
        let profile = fixture["trust_profile"].clone();
        let issuer = fixture["issuer_id"].as_str().unwrap();
        let kid = format!("{issuer}#key-1");
        let token = compact_jwt(issuer, &kid);
        let selected = governed_public_jwk(&context(profile.clone()), &token).unwrap();
        assert_eq!(selected["kid"], kid);
        assert!(selected.get("d").is_none());

        let mut ambiguous = profile.clone();
        let relationship = ambiguous["issuer_relationships"][0].clone();
        ambiguous["issuer_relationships"]
            .as_array_mut()
            .unwrap()
            .push(relationship);
        assert!(governed_public_jwk(&context(ambiguous), &token).is_none());

        let mut private = profile;
        private["issuer_relationships"][0]["verification_keys"][0]["d"] = json!("secret");
        assert!(governed_public_jwk(&context(private), &token).is_none());
    }

    #[test]
    fn authenticated_jwt_id_precedes_embedded_status_entry_ids() {
        let contract: Value = serde_json::from_str(include_str!(
            "../../../../contracts/presentation-control-plane-behavior.json"
        ))
        .unwrap();
        let status_id = "https://issuer.example/status/revocation#21";
        let credential = json!({
            "credentialStatus": {
                "id": status_id,
                "type": "BitstringStatusListEntry"
            }
        });
        let mut evidence = credential_evidence(
            credential.as_object().unwrap(),
            Some("did:web:issuer.example"),
            false,
            1,
        );
        let claims = json!({"jti": "urn:uuid:credential-1"});
        bind_authenticated_jwt_credential_id(&mut evidence, claims.as_object().unwrap());

        assert_eq!(
            evidence.credential_id.as_deref(),
            Some("urn:uuid:credential-1")
        );
        assert_eq!(
            evidence.credential_status_ids,
            ["urn:uuid:credential-1", status_id]
        );
        assert_eq!(
            contract["status_resolution"]["canonical_credential_identifier"],
            "authenticated_outer_jwt_jti_precedes_embedded_status_entry_ids"
        );
    }

    #[test]
    fn mdoc_adapter_projects_only_complete_authenticated_evidence() {
        let contract = mdoc_contract();
        let result: MdocPresentationVerificationResult =
            serde_json::from_value(contract["authenticated_result"].clone()).unwrap();
        let document = authenticated_mdoc_document(&result).unwrap();
        let claims = contract["claims"].as_object().unwrap().clone();
        let mut verification_context = context(contract["trust_profile"].clone());
        verification_context.format = DetectedCredentialFormat::Mdoc;
        verification_context.nonce = Some("behavioral-challenge".into());
        verification_context.audience = Some("https://verifier.example".into());

        let evidence = project_authenticated_mdoc(document, claims.clone(), &verification_context);
        let expected = &contract["expected_evidence"];
        assert!(evidence.verified);
        assert_eq!(evidence.claims, claims);
        assert_eq!(
            evidence.issuer_id.as_deref(),
            expected["issuer_id"].as_str()
        );
        assert_eq!(
            evidence.issued_at_epoch_seconds,
            expected["issued_at_epoch_seconds"].as_u64()
        );
        assert!(evidence.presentation_verified);
        assert_eq!(
            evidence.presentation_count,
            expected["presentation_count"]
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
        );
        assert!(evidence.holder_binding_verified);
        assert_eq!(
            evidence.holder_binding_method.as_deref(),
            expected["holder_binding_method"].as_str()
        );
        assert_eq!(
            evidence.proof_profile.as_deref(),
            expected["proof_profile"].as_str()
        );
        assert!(evidence.challenge_verified);
        assert!(evidence.audience_verified);

        let mut incomplete = result;
        incomplete.document_evidence.clear();
        assert!(authenticated_mdoc_document(&incomplete).is_none());
    }

    #[test]
    fn mdoc_trust_material_preserves_root_and_direct_pin_semantics() {
        let contract = mdoc_contract();
        let mut verification_context = context(contract["trust_profile"].clone());
        verification_context.format = DetectedCredentialFormat::Mdoc;
        let (roots, pinned) = mdoc_trust_certificates(&verification_context);
        assert_eq!(roots.len(), 1);
        assert!(roots[0].contains("cm9vdA=="));
        assert_eq!(pinned.len(), 1);
        assert!(pinned[0].contains("cGlubmVk"));
    }

    #[test]
    fn mdoc_token_encodings_and_error_categories_match_the_contract() {
        assert_eq!(decode_mdoc_token("mdoc:AQID").unwrap(), [1, 2, 3]);
        assert_eq!(decode_mdoc_token("mso_mdoc:AQID=").unwrap(), [1, 2, 3]);
        assert_eq!(decode_mdoc_token("\\x010203").unwrap(), [1, 2, 3]);
        assert!(decode_mdoc_token("mdoc:***").is_err());

        for case in mdoc_contract()["error_categories"].as_array().unwrap() {
            assert_eq!(
                classify_mdoc_error(case["error"].as_str()),
                case["expected"].as_str().unwrap()
            );
        }
    }
}
