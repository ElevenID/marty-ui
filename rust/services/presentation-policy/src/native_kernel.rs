use async_trait::async_trait;
use chrono::DateTime;
use marty_verification::credential_format::DetectedCredentialFormat;
use serde_json::{json, Map, Value};

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
            DetectedCredentialFormat::Mdoc => Err(PresentationVerificationError::Unavailable),
            DetectedCredentialFormat::Unknown => {
                Ok(rejected("Unsupported or malformed credential presentation"))
            }
        }
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
    if let Some(public_jwk) = trust_value(context, "issuer_public_jwk") {
        request["issuer_public_jwk"] = public_jwk.clone();
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
    Ok((
        credential_evidence(
            credential,
            result.get("issuer").and_then(Value::as_str),
            false,
            1,
        ),
        Some(credential.clone()),
    ))
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
    Ok(evidence)
}

fn verify_sd_jwt(
    context: &CredentialVerificationContext,
) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
    let token = token_string(&context.token)?;
    let public_jwk = trust_value(context, "issuer_public_jwk")
        .ok_or_else(|| invalid_input("No governed issuer public JWK is available for SD-JWT"))?;
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
