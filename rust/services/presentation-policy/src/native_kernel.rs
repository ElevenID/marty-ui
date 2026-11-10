use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::DateTime;
use marty_verification::credential_format::DetectedCredentialFormat;
use marty_verification::mdoc::{
    disclosed_claims, verify_mdoc_presentation, MdocDocumentVerificationEvidence,
    MdocPresentationVerificationResult,
};
use marty_verification::open_badges::is_retired_ob2;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::verification::OB2_RETIRED;
use crate::{
    AuthenticatedIssuerEvidence, CredentialStatusEvidence, CredentialVerificationContext,
    CredentialVerificationEvidence, CredentialVerificationKernel, IssuerKeyMechanism,
    IssuerKeyProvenance, PresentationVerificationError, ResolvedIssuerKey,
};

type JsonObject = Map<String, Value>;

struct DataIntegrityDocument<'a> {
    is_presentation: bool,
    credentials: Vec<&'a JsonObject>,
}

/// Resolves public signature keys through deployment-bounded transport. This does
/// not alter the policy's trust profile or mark any issuer as trusted.
pub struct ResolvingCredentialKernel {
    resolver: std::sync::Arc<dyn marty_issuer_key_resolution::IssuerKeyResolver>,
    registry: Option<
        std::sync::Arc<dyn marty_issuer_key_resolution::governed::OrganizationIssuerResolver>,
    >,
}

impl ResolvingCredentialKernel {
    async fn prepare_document_sources(
        &self,
        context: &mut CredentialVerificationContext,
    ) -> Result<(), &'static str> {
        let Some(profile) = context.trust_profile.as_ref() else {
            return Ok(());
        };
        let credentials: Vec<_> = match context.format {
            DetectedCredentialFormat::OpenbadgeV3 => {
                // Resolve the exact credential the Open Badge verifier will consume,
                // including its supported VP wrapper. Never inspect
                // an outer envelope or reinterpret a field inside the selected VC.
                vec![open_badge_credential(&context.token)
                    .map_err(|_| "Invalid Open Badge credential selection")?]
            }
            DetectedCredentialFormat::W3cVcdmDi => {
                let document = context
                    .token
                    .as_object()
                    .ok_or("Invalid Data Integrity document")?;
                data_integrity_document(document)?.credentials
            }
            _ => return Ok(()),
        };
        let mut resolved_methods = Vec::new();
        let mut governed_issuers = Vec::new();
        for credential in credentials {
            let Some(issuer) = issuer_id(credential) else {
                continue;
            };
            let sources: Vec<_> = profile
                .document
                .get("trust_sources")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|source| source.get("enabled") != Some(&Value::Bool(false)))
                .filter(|source| source.get("issuer_did").and_then(Value::as_str) == Some(issuer))
                .collect();
            if sources.is_empty() {
                continue;
            }
            if sources.len() != 1 {
                return Err("Ambiguous issuer DID trust sources");
            }
            governed_issuers.push(issuer.to_owned());
            let proofs = match credential.get("proof") {
                Some(Value::Array(values)) => values.iter().collect::<Vec<_>>(),
                Some(value) => vec![value],
                None => return Err("Issuer DID assertion proof is required"),
            };
            if proofs.is_empty() {
                return Err("Issuer DID assertion proof is required");
            }
            for proof in proofs {
                if proof.get("proofPurpose").and_then(Value::as_str) != Some("assertionMethod") {
                    return Err("Issuer DID assertion proof is required");
                }
                let method = proof
                    .get("verificationMethod")
                    .and_then(Value::as_str)
                    .ok_or("Issuer DID signing method is required")?;
                let algorithm = if proof.get("cryptosuite").and_then(Value::as_str)
                    == Some("eddsa-rdfc-2022")
                {
                    "EdDSA".to_owned()
                } else {
                    proof
                        .get("jws")
                        .and_then(Value::as_str)
                        .and_then(|jws| jws.split('.').next())
                        .and_then(decode_jwt_object)
                        .and_then(|h| h.get("alg").and_then(Value::as_str).map(str::to_owned))
                        .ok_or("Unsupported issuer DID proof algorithm")?
                };
                let key = self
                    .resolve_source_key(sources[0], issuer, method, "JSON_LD", &algorithm)
                    .await?;
                let entry = json!({"id":method,"controller":issuer,"public_jwk":key.public_jwk});
                if let Some(existing) = resolved_methods
                    .iter()
                    .find(|entry: &&Value| entry.get("id").and_then(Value::as_str) == Some(method))
                {
                    if existing != &entry {
                        return Err("Issuer DID method changed during verification");
                    }
                } else {
                    resolved_methods.push(entry);
                }
            }
        }
        if !governed_issuers.is_empty() {
            let profile = context
                .trust_profile
                .as_mut()
                .ok_or("Trust profile is unavailable")?;
            let mut methods = profile
                .document
                .get("resolved_verification_methods")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            methods.retain(|entry| {
                !entry
                    .get("controller")
                    .and_then(Value::as_str)
                    .is_some_and(|issuer| governed_issuers.iter().any(|value| value == issuer))
            });
            methods.extend(resolved_methods);
            profile.document["resolved_verification_methods"] = Value::Array(methods);
        }
        Ok(())
    }
    async fn resolve_source_key(
        &self,
        source: &Value,
        issuer: &str,
        method: &str,
        format: &str,
        algorithm: &str,
    ) -> Result<ResolvedIssuerKey, &'static str> {
        let organization_id = match source.get("organization_id") {
            Some(Value::String(value)) => Some(value.clone()),
            Some(_) => return Err("Invalid issuer organization scope"),
            None => None,
        };
        let policy =
            serde_json::from_value(source.get("did_resolution").cloned().unwrap_or_else(|| {
                if organization_id.is_some() {
                    json!({})
                } else {
                    json!({"resolver_type":"PUBLIC_DID"})
                }
            }))
            .map_err(|_| "Invalid issuer DID resolution policy")?;
        let pins = source
            .get("verification_method_ids")
            .map(|value| serde_json::from_value::<Vec<String>>(value.clone()))
            .transpose()
            .map_err(|_| "Invalid issuer DID method pins")?
            .unwrap_or_default();
        let request = marty_issuer_key_resolution::governed::IssuerResolutionRequest {
            organization_id,
            issuer_did: issuer.into(),
            verification_method_ids: pins,
            credential_format: format.into(),
            key_purpose: "vc_jwt_issuer".into(),
            algorithm: algorithm.into(),
            policy,
        };
        let material = if request
            .policy
            .registry_first(request.organization_id.as_deref())
        {
            let registry = self
                .registry
                .as_ref()
                .ok_or("Organization issuer registry is unavailable")?;
            marty_issuer_key_resolution::governed::resolve_governed_issuer(
                &request,
                registry.as_ref(),
                self.resolver.as_ref(),
            )
            .await
        } else {
            marty_issuer_key_resolution::policy::validate_source_controls(
                &request.issuer_did,
                None,
                &request.verification_method_ids,
            )
            .map_err(|_| "Invalid issuer DID method pins")?;
            self.resolver
                .resolve(issuer)
                .await
                .and_then(|mut material| {
                    material.verification_keys =
                        marty_issuer_key_resolution::policy::pin_assertion_keys(
                            issuer,
                            &request.verification_method_ids,
                            &material.verification_keys,
                        )?;
                    Ok(material)
                })
        }
        .map_err(|_| "Issuer DID trust resolution failed")?;
        let mut keys = material
            .verification_keys
            .iter()
            .filter(|key| key.get("kid").and_then(Value::as_str) == Some(method));
        let key = keys
            .next()
            .ok_or("Issuer DID signing method is not authorized")?;
        if keys.next().is_some() {
            return Err("Issuer DID signing method is not authorized");
        }
        Ok(resolved_did_key(
            issuer,
            key.clone(),
            &material,
            request.organization_id,
        ))
    }
    pub fn new(
        resolver: std::sync::Arc<dyn marty_issuer_key_resolution::IssuerKeyResolver>,
    ) -> Self {
        Self {
            resolver,
            registry: None,
        }
    }

    pub fn with_registry(
        mut self,
        registry: std::sync::Arc<
            dyn marty_issuer_key_resolution::governed::OrganizationIssuerResolver,
        >,
    ) -> Self {
        self.registry = Some(registry);
        self
    }
}

#[async_trait]
impl CredentialVerificationKernel for ResolvingCredentialKernel {
    async fn verify(
        &self,
        context: &CredentialVerificationContext,
    ) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
        if is_retired_ob2(&context.token)
            || (matches!(
                context.format,
                DetectedCredentialFormat::Unknown | DetectedCredentialFormat::OpenbadgeV3
            ) && context.token.get("assertion").is_some())
        {
            return Ok(rejected(OB2_RETIRED));
        }
        let mut resolved = context.clone();
        // The public request map cannot supply this field. Clear even caller
        // hints so this adapter only admits its own bounded resolver result.
        resolved.resolved_issuer_key = None;
        if context.token.is_object()
            && matches!(
                context.format,
                DetectedCredentialFormat::W3cVcdmDi | DetectedCredentialFormat::OpenbadgeV3
            )
        {
            if let Err(reason) = self.prepare_document_sources(&mut resolved).await {
                return Ok(rejected(reason));
            }
        }
        if matches!(
            context.format,
            DetectedCredentialFormat::W3cVc
                | DetectedCredentialFormat::OpenbadgeV3
                | DetectedCredentialFormat::SdJwt
        ) {
            if let Some(token) = context.token.as_str() {
                if let Some((issuer, kid)) = jwt_selector(token) {
                    let sources: Vec<_> = context
                        .trust_profile
                        .as_ref()
                        .and_then(|p| p.document.get("trust_sources"))
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter(|source| source.get("enabled") != Some(&Value::Bool(false)))
                        .filter(|source| {
                            source.get("issuer_did").and_then(Value::as_str)
                                == Some(issuer.as_str())
                        })
                        .collect();
                    if !sources.is_empty() {
                        let Some(kid) = kid else {
                            return Ok(rejected("Issuer DID signing method is required"));
                        };
                        if sources.len() != 1 {
                            return Ok(rejected("Ambiguous issuer DID trust sources"));
                        }
                        let algorithm = token
                            .split('.')
                            .next()
                            .and_then(decode_jwt_object)
                            .and_then(|h| h.get("alg").and_then(Value::as_str).map(str::to_owned));
                        let Some(algorithm) = algorithm else {
                            return Ok(rejected("Issuer algorithm is required"));
                        };
                        let format = if context.format == DetectedCredentialFormat::SdJwt {
                            "SD_JWT_VC"
                        } else {
                            "VC_JWT"
                        };
                        let mut key = match self
                            .resolve_source_key(sources[0], &issuer, &kid, format, &algorithm)
                            .await
                        {
                            Ok(key) => key,
                            Err(reason) => return Ok(rejected(reason)),
                        };
                        bind_key_profile(&mut key, &resolved);
                        resolved.resolved_issuer_key = Some(key);
                        return RustCredentialKernel.verify(&resolved).await;
                    }
                }
                if governed_issuer_key(context, token).is_none() {
                    if let Some((issuer, _)) = jwt_selector(token) {
                        if has_profile_key_authority(context, &issuer) {
                            return Ok(rejected(
                                "Trust Profile does not authorize this issuer signing key",
                            ));
                        }
                    }
                    if let Some((issuer, Some(kid))) = jwt_selector(token) {
                        if issuer.starts_with("did:web:") && kid.starts_with(&format!("{issuer}#"))
                        {
                            if let Ok(material) = self.resolver.resolve(&issuer).await {
                                let matches: Vec<_> = material
                                    .verification_keys
                                    .iter()
                                    .filter(|key| {
                                        key.get("kid").and_then(Value::as_str) == Some(kid.as_str())
                                    })
                                    .filter(|key| key.as_object().is_some_and(public_jwk))
                                    .collect();
                                if matches.len() == 1 {
                                    let mut key = resolved_did_key(
                                        &issuer,
                                        matches[0].clone(),
                                        &material,
                                        None,
                                    );
                                    bind_key_profile(&mut key, &resolved);
                                    resolved.resolved_issuer_key = Some(key);
                                }
                            }
                        }
                    }
                }
            }
        }
        RustCredentialKernel.verify(&resolved).await
    }
}

/// Direct adapter over the canonical Marty Rust credential verifiers.
#[derive(Clone, Debug, Default)]
pub struct RustCredentialKernel;

#[async_trait]
impl CredentialVerificationKernel for RustCredentialKernel {
    async fn verify(
        &self,
        context: &CredentialVerificationContext,
    ) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
        if is_retired_ob2(&context.token)
            || (matches!(
                context.format,
                DetectedCredentialFormat::Unknown | DetectedCredentialFormat::OpenbadgeV3
            ) && context.token.get("assertion").is_some())
        {
            return Ok(rejected(OB2_RETIRED));
        }
        match context.format {
            DetectedCredentialFormat::W3cVc => verify_vc_jwt(context, false).await,
            DetectedCredentialFormat::W3cVcdmDi => verify_data_integrity(context).await,
            DetectedCredentialFormat::SdJwt => verify_sd_jwt(context),
            DetectedCredentialFormat::OpenbadgeV3 => verify_open_badge(context).await,
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
    let diagnostic = rejected_mdoc_diagnostic(&result);
    let authentication_valid = result.issuer_signature_valid
        && result.issuer_trusted
        && result.device_authentication_valid;
    let Some(document) = authenticated_mdoc_document(&result) else {
        let mut rejected =
            rejected_mdoc(result.error.as_deref().unwrap_or(if authentication_valid {
                "Authenticated mdoc evidence is incomplete"
            } else {
                "mDoc authentication failed"
            }));
        rejected.mdoc_authentication_diagnostic = diagnostic;
        return Ok(rejected);
    };
    if !authentication_valid {
        let mut rejected = rejected_mdoc(
            result
                .error
                .as_deref()
                .unwrap_or("mDoc authentication failed"),
        );
        rejected.mdoc_authentication_diagnostic = diagnostic;
        return Ok(rejected);
    }
    let claims = disclosed_claims(mdoc_bytes)
        .map_err(|_| invalid_native("mDoc claim extraction rejected authenticated CBOR"))?
        .as_object()
        .cloned()
        .ok_or_else(|| invalid_native("mDoc claims were not a JSON object"))?;
    // These exact bytes have passed complete issuer and device authentication.
    // Bind the issuer-signed MSO, not selectively disclosed claim values.
    let reference =
        marty_mdoc_status_binding::MdocStatusReference::from_authenticated_presentation(
            mdoc_bytes,
            &document.document_type,
            &document.issuer_certificate_sha256,
        )
        .map_err(|_| invalid_native("Authenticated mdoc lifecycle binding is invalid"))?;
    let mut evidence = project_authenticated_mdoc(document, claims, context);
    evidence.credential_status_ids.push(reference.to_string());
    Ok(evidence)
}

fn rejected_mdoc_diagnostic(
    result: &MdocPresentationVerificationResult,
) -> Option<marty_oid4vp_contract::MdocAuthenticationDiagnosticV1> {
    use marty_oid4vp_contract::{
        CertificateTrustFailure, MdocAuthenticationDiagnosticV1, MdocDiagnosticFormat,
    };
    use marty_verification::mdoc::MdocCertificateTrustFailure as CoreFailure;
    // Count ALL documents, including those that failed authentication. One valid
    // MSO alongside a second invalid document must not inherit its fingerprint.
    if !result.issuer_signature_valid
        || (result.issuer_trusted && result.device_authentication_valid)
    {
        return None;
    }
    let document = authenticated_mdoc_document(result)?;
    let diagnostic = MdocAuthenticationDiagnosticV1 {
        format: MdocDiagnosticFormat::MsoMdoc,
        document_count: u32::try_from(result.document_types.len()).ok()?,
        document_type: document.document_type.clone(),
        issuer_signature_valid: result.issuer_signature_valid,
        certificate_trust_passed: result.issuer_trusted,
        device_authentication_valid: result.device_authentication_valid,
        certificate_trust_failures: result
            .certificate_trust_failures
            .iter()
            .map(|failure| match failure {
                CoreFailure::MissingTrustAnchors => CertificateTrustFailure::MissingTrustAnchors,
                CoreFailure::InvalidTrustConfiguration => {
                    CertificateTrustFailure::InvalidTrustConfiguration
                }
                CoreFailure::CertificateChainRejected => {
                    CertificateTrustFailure::CertificateChainRejected
                }
            })
            .collect(),
        issuer_certificate_sha256: document.issuer_certificate_sha256.clone(),
    };
    diagnostic.validate().ok()?;
    Some(diagnostic)
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
        credential_types: vec![document.document_type.clone()],
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
    let token = token_string(&context.token)?;
    let mut request = json!({"token": token});
    let issuer_key = context
        .resolved_issuer_key
        .clone()
        .or_else(|| governed_issuer_key(context, token));
    if let Some(key) = &issuer_key {
        request["issuer_public_jwk"] = key.public_jwk.clone();
    }
    let raw = if open_badge_v3 {
        marty_verification::vcdm::verify_open_badge_v3_jwt_json_async(&request.to_string()).await
    } else {
        marty_verification::vcdm::verify_vcdm_jwt_json_async(&request.to_string()).await
    };
    let result = internal_json(&raw, "VC-JWT")?;
    let valid = result.get("valid").and_then(Value::as_bool) == Some(true);
    if !valid {
        return Ok(rejected_counted(
            if open_badge_v3 {
                "Open Badges v3 VC-JWT"
            } else {
                "VCDM VC-JWT"
            },
            error_count(&result),
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
    let authenticated = if let Some(key) = &issuer_key {
        let Some(issuer) = authenticated_issuer(
            context,
            key,
            result.get("issuer").and_then(Value::as_str),
            jwt_algorithm(token),
        ) else {
            return Ok(rejected(
                "Verified issuer authority or provenance is invalid",
            ));
        };
        Some(issuer)
    } else {
        None
    };
    let mut evidence = credential_evidence(
        credential,
        authenticated
            .as_ref()
            .map(|issuer| issuer.issuer_id.as_str())
            .or_else(|| result.get("issuer").and_then(Value::as_str)),
        false,
        1,
    );
    evidence.authenticated_issuer = authenticated;
    evidence.authenticated_document = Some(Value::Object(claims.clone()));
    bind_authenticated_jwt_credential_id(&mut evidence, claims);
    evidence.algorithm = jwt_algorithm(token);
    evidence.validity_checked = true;
    evidence.is_expired = Some(false);
    Ok(evidence)
}

fn data_integrity_document(
    document: &JsonObject,
) -> Result<DataIntegrityDocument<'_>, &'static str> {
    let has_type = |expected: &str| match document.get("type") {
        Some(Value::String(value)) => value == expected,
        Some(Value::Array(values)) => values.iter().any(|value| value.as_str() == Some(expected)),
        _ => false,
    };
    let is_presentation = has_type("VerifiablePresentation");
    let is_credential = has_type("VerifiableCredential");
    if is_presentation == is_credential {
        return Err(
            "Document must identify exactly one Data Integrity credential or presentation type",
        );
    }
    if is_credential {
        return Ok(DataIntegrityDocument {
            is_presentation: false,
            credentials: vec![document],
        });
    }
    let credentials = match document.get("verifiableCredential") {
        None => Vec::new(),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_object()
                    .ok_or("Data Integrity presentation credentials must be objects")
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err("Data Integrity presentation credentials must be an array"),
    };
    Ok(DataIntegrityDocument {
        is_presentation: true,
        credentials,
    })
}

async fn verify_data_integrity(
    context: &CredentialVerificationContext,
) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
    let document = context
        .token
        .as_object()
        .ok_or_else(|| invalid_input("Data Integrity presentation must be a JSON object"))?;
    let selected = data_integrity_document(document).map_err(invalid_input)?;
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
    data_integrity_evidence_for_selected(context, &selected, &result)
}

#[cfg(test)]
fn data_integrity_evidence(
    context: &CredentialVerificationContext,
    document: &Map<String, Value>,
    result: &Value,
) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
    let selected = data_integrity_document(document).map_err(invalid_native)?;
    data_integrity_evidence_for_selected(context, &selected, result)
}

fn data_integrity_evidence_for_selected(
    context: &CredentialVerificationContext,
    selected: &DataIntegrityDocument<'_>,
    result: &Value,
) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
    if result.get("valid").and_then(Value::as_bool) != Some(true) {
        return Ok(rejected_counted("VCDM Data Integrity", error_count(result)));
    }
    let is_presentation = result.get("kind").and_then(Value::as_str) == Some("presentation");
    if is_presentation != selected.is_presentation {
        return Err(invalid_native(
            "Data Integrity verifier kind did not match the selected document type",
        ));
    }
    let credential_count = result
        .get("verified_credentials")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(1);
    if is_presentation && context.presentation_only {
        // The native VCDM kernel has verified the holder proof and every
        // embedded credential. A presentation-only policy does not invent a
        // credential, issuer, claims, or a trust relationship when none exists.
        return Ok(CredentialVerificationEvidence {
            verified: true,
            presentation_verified: true,
            presentation_count: Some(1),
            holder_binding_verified: true,
            holder_binding_method: Some("DEVICE_KEY".into()),
            proof_profile: Some("OID4VP_VERIFIABLE_PRESENTATION".into()),
            challenge_verified: context.nonce.is_some(),
            audience_verified: context.audience.is_some(),
            algorithm: result
                .get("algorithm")
                .and_then(Value::as_str)
                .map(str::to_owned),
            ..Default::default()
        });
    }
    let credential = if is_presentation {
        if selected.credentials.len() != 1 {
            return Ok(rejected(
                "Presentation must contain exactly one independently verified credential",
            ));
        }
        selected.credentials[0]
    } else {
        selected.credentials[0]
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
    let Some(issuer_key) = context
        .resolved_issuer_key
        .clone()
        .or_else(|| governed_issuer_key(context, token))
    else {
        return Ok(rejected(
            "No governed issuer public JWK is available for SD-JWT",
        ));
    };
    let Some(algorithm) = jwt_algorithm(token) else {
        return Ok(rejected("SD-JWT signature algorithm is missing"));
    };
    let Some(issuer_algorithm) = sd_jwt_algorithm(&algorithm) else {
        return Ok(rejected("SD-JWT signature algorithm is unsupported"));
    };
    let allowed_algorithms = match sd_jwt_allowed_algorithms(context) {
        Ok(allowed) if allowed.contains(&issuer_algorithm) => allowed,
        _ => {
            return Ok(rejected(
                "SD-JWT algorithm is not allowed by the Trust Profile",
            ))
        }
    };
    let (claims, authenticated_sd_jwt_query) = if let Some(query) = &context.sd_jwt_dcql {
        match query.verify(&issuer_key, token, &allowed_algorithms) {
            Ok((claims, evidence)) => (claims, Some(evidence)),
            Err(reason) => return Ok(rejected(reason)),
        }
    } else {
        let policy = marty_oid4vci::formats::sd_jwt::SdJwtVerificationPolicy {
            expected_issuer: issuer_key.issuer_id.clone(),
            issuer_algorithm,
            holder_algorithms: allowed_algorithms,
        };
        let verified = marty_oid4vci::formats::sd_jwt::verify_sd_jwt_with_policy(
            token,
            &issuer_key.public_jwk.to_string(),
            &policy,
            context.audience.clone(),
            context.nonce.clone(),
        );
        match verified {
            Ok(authenticated) => match authenticated.into_claims() {
                Value::Object(claims) => (claims, None),
                _ => return Err(invalid_native("SD-JWT verifier returned non-object claims")),
            },
            Err(_) => return Ok(rejected("SD-JWT verification rejected the credential")),
        }
    };
    let Some(authenticated) = authenticated_issuer(
        context,
        &issuer_key,
        claims.get("iss").and_then(Value::as_str),
        jwt_algorithm(token),
    ) else {
        return Ok(rejected(
            "Verified issuer authority or provenance is invalid",
        ));
    };
    let credential = claims
        .get("vc")
        .and_then(Value::as_object)
        .or_else(|| claims.get("credential").and_then(Value::as_object));
    let disclosed = if let Some(query) = &context.sd_jwt_dcql {
        query.policy_claims(&claims)
    } else {
        credential
            .and_then(|value| value.get("credentialSubject"))
            .and_then(Value::as_object)
            .cloned()
            .or_else(|| {
                claims
                    .get("credentialSubject")
                    .and_then(Value::as_object)
                    .cloned()
            })
            .unwrap_or_else(|| claims.clone())
    };
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
        authenticated_sd_jwt_query,
        credential_types: claims
            .get("vct")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .into_iter()
            .collect(),
        authenticated_document: Some(Value::Object(claims.clone())),
        credential_id: credential_id.clone(),
        credential_status_ids: credential_id.into_iter().collect(),
        claims: disclosed,
        issuer_id: Some(authenticated.issuer_id.clone()),
        authenticated_issuer: Some(authenticated),
        issued_at_epoch_seconds: issued_at,
        algorithm: jwt_algorithm(token),
        holder_algorithm: bound
            .then(|| token.rsplit('~').next().and_then(jwt_algorithm))
            .flatten(),
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

fn sd_jwt_algorithm(value: &str) -> Option<marty_oid4vci::types::SigningAlgorithm> {
    use marty_oid4vci::types::SigningAlgorithm;
    match value {
        "ES256" => Some(SigningAlgorithm::ES256),
        "ES384" => Some(SigningAlgorithm::ES384),
        "EdDSA" => Some(SigningAlgorithm::EdDSA),
        "RS256" => Some(SigningAlgorithm::RS256),
        _ => None,
    }
}

fn sd_jwt_allowed_algorithms(
    context: &CredentialVerificationContext,
) -> Result<Vec<marty_oid4vci::types::SigningAlgorithm>, ()> {
    let Some(profile) = &context.trust_profile else {
        // No Trust Profile means no configured restriction. These are the
        // algorithms supported by Core's explicit SD-JWT verification policy.
        return Ok(["ES256", "ES384", "EdDSA", "RS256"]
            .into_iter()
            .filter_map(sd_jwt_algorithm)
            .collect());
    };
    let values = profile
        .document
        .get("allowed_algorithms")
        .or_else(|| {
            profile
                .document
                .pointer("/validation_rules/allowed_algorithms")
        })
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty())
        .ok_or(())?;
    let mut allowed = Vec::new();
    for value in values {
        let algorithm = sd_jwt_algorithm(value.as_str().ok_or(())?).ok_or(())?;
        if !allowed.contains(&algorithm) {
            allowed.push(algorithm);
        }
    }
    Ok(allowed)
}

async fn verify_open_badge(
    context: &CredentialVerificationContext,
) -> Result<CredentialVerificationEvidence, PresentationVerificationError> {
    if context.token.as_str().is_some() {
        return verify_vc_jwt(context, true).await;
    }
    let credential = open_badge_credential(&context.token)?.clone();
    let store = governed_open_badge_methods(context)?;
    let request = json!({"credential": credential, "document_store": store});
    let raw = marty_verification::open_badges::verify_ob3_json_async(&request.to_string())
        .await
        .map_err(|_| invalid_input("Open Badges v3 verification rejected the credential"))?;
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
    evidence.algorithm = result
        .get("algorithm")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| proof_algorithm(&credential));
    evidence.validity_checked = true;
    evidence.is_expired = Some(false);
    apply_open_badge_status(&mut evidence, &result);
    Ok(evidence)
}

fn governed_open_badge_methods(
    context: &CredentialVerificationContext,
) -> Result<JsonObject, PresentationVerificationError> {
    let mut methods = Map::new();
    let Some(entries) =
        trust_value(context, "resolved_verification_methods").and_then(Value::as_array)
    else {
        return Ok(methods);
    };
    for entry in entries {
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            return Err(invalid_native("Governed Open Badge method omitted id"));
        };
        let Some(controller) = entry.get("controller").and_then(Value::as_str) else {
            return Err(invalid_native(
                "Governed Open Badge method omitted controller",
            ));
        };
        let Some(jwk) = entry.get("public_jwk").and_then(Value::as_object) else {
            return Err(invalid_native(
                "Governed Open Badge method omitted public JWK",
            ));
        };
        if id.trim().is_empty()
            || controller.trim().is_empty()
            || !public_jwk(jwk)
            || jwk
                .get("kid")
                .and_then(Value::as_str)
                .is_some_and(|kid| kid != id)
        {
            return Err(invalid_native("Governed Open Badge method is invalid"));
        }
        let method = json!({
            "id": id,
            "type": "JsonWebKey2020",
            "controller": controller,
            "publicKeyJwk": jwk,
        });
        if methods.insert(id.to_owned(), method).is_some() {
            return Err(invalid_native("Governed Open Badge method id is ambiguous"));
        }
    }
    Ok(methods)
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
        credential_types: authenticated_credential_types(credential),
        authenticated_document: Some(Value::Object(credential.clone())),
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

fn authenticated_credential_types(credential: &Map<String, Value>) -> Vec<String> {
    match credential.get("type") {
        Some(Value::String(value)) if !value.is_empty() => vec![value.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect(),
        _ => Vec::new(),
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
    // Keep the established status-lookup identifier behavior. Projection has
    // stricter public identity bounds and requires the signed bytes unchanged.
    evidence.authenticated_outer_jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|raw| *raw == credential_id && raw.len() <= 2048)
        .filter(|raw| !raw.chars().any(char::is_control))
        .map(str::to_owned);
    evidence
        .credential_status_ids
        .retain(|candidate| candidate != credential_id);
    evidence
        .credential_status_ids
        .insert(0, credential_id.to_owned());
}

fn open_badge_credential(token: &Value) -> Result<&JsonObject, PresentationVerificationError> {
    let object = token
        .as_object()
        .ok_or_else(|| invalid_input("Open Badge presentation must be a JSON object"))?;
    if let Some(value) = object.get("credential").and_then(Value::as_object) {
        return Ok(value);
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
                    return Ok(credential);
                }
            } else if let Some(credential) = value.as_object() {
                return Ok(credential);
            }
        }
    }
    Ok(object)
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

fn governed_issuer_key(
    context: &CredentialVerificationContext,
    token: &str,
) -> Option<ResolvedIssuerKey> {
    let profile = context.trust_profile.as_ref()?.document.as_object()?;
    if profile
        .get("status")
        .and_then(Value::as_str)
        .is_none_or(|status| !status.eq_ignore_ascii_case("active"))
    {
        return None;
    }
    let (issuer, kid) = jwt_selector(token)?;

    if let Some(value) = profile
        .get("system_issuer_overrides")
        .and_then(Value::as_object)
        .and_then(|overrides| overrides.get(&issuer))
        .and_then(|entry| entry.get("public_jwk"))
    {
        // An explicit override remains the authority even when its key is
        // invalid or does not match the presented kid. Neither a relationship
        // key nor public discovery may replace a failed configured override.
        let jwk = value.as_object()?;
        if !public_jwk(jwk) || !kid_matches(jwk, kid.as_deref()) {
            return None;
        }
        return Some(profile_issuer_key(
            context,
            issuer,
            Value::Object(jwk.clone()),
            "trust_profile_system_override",
        ));
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
                .is_some_and(|value| value == issuer)
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
    Some(profile_issuer_key(
        context,
        issuer,
        Value::Object(selected.clone()),
        "trust_profile_issuer_relationship",
    ))
}

fn has_profile_key_authority(context: &CredentialVerificationContext, issuer: &str) -> bool {
    let Some(profile) = context.trust_profile.as_ref() else {
        return false;
    };
    profile
        .document
        .get("system_issuer_overrides")
        .and_then(Value::as_object)
        .and_then(|overrides| overrides.get(issuer))
        .is_some_and(|entry| entry.get("public_jwk").is_some())
        || profile
            .document
            .get("issuer_relationships")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|entry| {
                entry.get("issuer_id").and_then(Value::as_str) == Some(issuer)
                    && entry.get("verification_keys").is_some()
            })
}

fn profile_issuer_key(
    context: &CredentialVerificationContext,
    issuer_id: String,
    public_jwk: Value,
    source: &str,
) -> ResolvedIssuerKey {
    let mut key = ResolvedIssuerKey {
        issuer_id,
        public_jwk,
        provenance: IssuerKeyProvenance {
            mechanism: IssuerKeyMechanism::TrustProfileKey,
            trust_profile_id: None,
            organization_id: None,
            issuer_organization_id: None,
            source: source.into(),
            retrieved_at: None,
            content_sha256: None,
        },
    };
    bind_key_profile(&mut key, context);
    key
}

fn resolved_did_key(
    issuer_id: &str,
    public_jwk: Value,
    material: &marty_issuer_key_resolution::IssuerKeyResolution,
    issuer_organization_id: Option<String>,
) -> ResolvedIssuerKey {
    ResolvedIssuerKey {
        issuer_id: issuer_id.into(),
        public_jwk,
        provenance: IssuerKeyProvenance {
            mechanism: IssuerKeyMechanism::DidAssertionMethod,
            trust_profile_id: None,
            organization_id: None,
            issuer_organization_id,
            source: material.source.clone(),
            retrieved_at: Some(material.retrieved_at.clone()),
            content_sha256: Some(material.content_sha256.clone()),
        },
    }
}

fn bind_key_profile(key: &mut ResolvedIssuerKey, context: &CredentialVerificationContext) {
    key.provenance.trust_profile_id = context.trust_profile.as_ref().map(|profile| profile.id);
    key.provenance.organization_id = context
        .trust_profile
        .as_ref()
        .map(|profile| profile.organization_id);
}

fn authenticated_issuer(
    context: &CredentialVerificationContext,
    key: &ResolvedIssuerKey,
    verified_issuer: Option<&str>,
    algorithm: Option<String>,
) -> Option<AuthenticatedIssuerEvidence> {
    // The signed claim must name the authority that selected the key. A valid
    // signature under a governed key does not authenticate an arbitrary iss.
    if verified_issuer != Some(key.issuer_id.as_str())
        || key.provenance.trust_profile_id != context.trust_profile.as_ref().map(|p| p.id)
        || key.provenance.organization_id
            != context.trust_profile.as_ref().map(|p| p.organization_id)
    {
        return None;
    }
    let evidence = AuthenticatedIssuerEvidence {
        issuer_id: key.issuer_id.clone(),
        key_id: key
            .public_jwk
            .get("kid")
            .and_then(Value::as_str)
            .map(str::to_owned),
        algorithm: algorithm?,
        provenance: key.provenance.clone(),
    };
    evidence.satisfies_contract().then_some(evidence)
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
    let issuer = payload.get("iss")?.as_str()?;
    if issuer.is_empty() || issuer != issuer.trim() {
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
            presentation_only: false,
            sd_jwt_dcql: None,
            resolved_issuer_key: None,
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
    fn data_integrity_evidence_keeps_presentation_and_credential_obligations_separate() {
        let document = json!({
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"]
        });
        let mut context = context(json!({}));
        context.format = DetectedCredentialFormat::W3cVcdmDi;
        let verified = json!({"valid": true, "kind": "presentation", "verified_credentials": 0});
        for with_empty_array in [false, true] {
            let mut document = document.clone();
            if with_empty_array {
                document["verifiableCredential"] = json!([]);
            }
            let document = document.as_object().unwrap();
            context.presentation_only = false;
            assert!(
                !data_integrity_evidence(&context, document, &verified)
                    .unwrap()
                    .verified
            );
            context.presentation_only = true;
            let evidence = data_integrity_evidence(&context, document, &verified).unwrap();
            assert!(evidence.verified);
            assert!(evidence.presentation_verified);
            assert!(evidence.holder_binding_verified);
            assert_eq!(evidence.presentation_count, Some(1));
            assert!(evidence.issuer_id.is_none());
            assert!(evidence.credential_id.is_none());
            assert!(evidence.claims.is_empty());
            let invalid =
                json!({"valid": false, "kind": "presentation", "errors": ["invalid proof"]});
            assert!(
                !data_integrity_evidence(&context, document, &invalid)
                    .unwrap()
                    .verified
            );
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
        let selected = governed_issuer_key(&context(profile.clone()), &token).unwrap();
        assert_eq!(selected.public_jwk["kid"], kid);
        assert!(selected.public_jwk.get("d").is_none());

        let mut unnamed = profile.clone();
        unnamed["issuer_relationships"][0]["verification_keys"][0]
            .as_object_mut()
            .unwrap()
            .remove("kid");
        assert!(governed_issuer_key(&context(unnamed.clone()), &token).is_some());
        let second_key = unnamed["issuer_relationships"][0]["verification_keys"][0].clone();
        unnamed["issuer_relationships"][0]["verification_keys"]
            .as_array_mut()
            .unwrap()
            .push(second_key);
        assert!(governed_issuer_key(&context(unnamed), &token).is_none());

        let mut ambiguous = profile.clone();
        let relationship = ambiguous["issuer_relationships"][0].clone();
        ambiguous["issuer_relationships"]
            .as_array_mut()
            .unwrap()
            .push(relationship);
        assert!(governed_issuer_key(&context(ambiguous), &token).is_none());

        let mut private = profile;
        private["issuer_relationships"][0]["verification_keys"][0]["d"] = json!("secret");
        assert!(governed_issuer_key(&context(private), &token).is_none());
    }

    #[test]
    fn governed_key_selection_preserves_issuer_identity_and_rejects_unscoped_keys() {
        let issuer = "did:web:issuer.example:Org:Acme";
        let kid = format!("{issuer}#key");
        let key = json!({"kty":"OKP", "crv":"Ed25519", "x":"public", "kid":kid});
        let profile = json!({
            "status":"active",
            "issuer_relationships":[{
                "issuer_id":issuer, "relationship_status":"TRUSTED",
                "compliance_status":"COMPLIANT", "verification_keys":[key]
            }]
        });
        let selected =
            governed_issuer_key(&context(profile.clone()), &compact_jwt(issuer, &kid)).unwrap();
        assert_eq!(selected.issuer_id, issuer);
        assert_eq!(
            selected.provenance.trust_profile_id,
            Some(Uuid::from_u128(1))
        );
        assert_eq!(
            selected.provenance.organization_id,
            Some(Uuid::from_u128(2))
        );
        for other in [
            "did:web:issuer.example:org:acme",
            "did:web:issuer.example:Org:Acme/",
            " did:web:issuer.example:Org:Acme",
        ] {
            assert!(
                governed_issuer_key(&context(profile.clone()), &compact_jwt(other, &kid)).is_none()
            );
        }
        let unscoped = json!({"status":"active", "issuer_public_jwk":key});
        assert!(governed_issuer_key(&context(unscoped), &compact_jwt(issuer, &kid)).is_none());

        let url = "https://issuer.example/Org/Acme";
        let override_profile =
            json!({"status":"active", "system_issuer_overrides": {url: {"public_jwk":key}}});
        assert!(
            governed_issuer_key(&context(override_profile.clone()), &compact_jwt(url, &kid))
                .is_some()
        );
        for other in [
            "https://issuer.example/org/acme",
            "https://issuer.example/Org/Acme/",
        ] {
            assert!(governed_issuer_key(
                &context(override_profile.clone()),
                &compact_jwt(other, &kid)
            )
            .is_none());
        }
    }

    #[test]
    fn authenticated_issuer_contract_counts_unicode_scalars_and_bounds_provenance() {
        let context = context(json!({"status":"active"}));
        let maximal = json!({
            "issuer_id":"界".repeat(2048),
            "key_id":"🔑".repeat(2048),
            "algorithm":"A".repeat(64),
            "provenance":{
                "mechanism":"DID_ASSERTION_METHOD",
                "trust_profile_id":Uuid::from_u128(1),
                "organization_id":Uuid::from_u128(2),
                "issuer_organization_id":"組".repeat(128),
                "source":"源".repeat(256),
                "retrieved_at":format!("2026-11-07T12:00:00.{}Z", "0".repeat(43)),
                "content_sha256":"a".repeat(64)
            }
        });
        let authenticate = |value: Value| {
            let evidence: AuthenticatedIssuerEvidence = serde_json::from_value(value).unwrap();
            let key = ResolvedIssuerKey {
                issuer_id: evidence.issuer_id.clone(),
                public_jwk: json!({"kid":evidence.key_id}),
                provenance: evidence.provenance,
            };
            authenticated_issuer(
                &context,
                &key,
                Some(&evidence.issuer_id),
                Some(evidence.algorithm),
            )
        };
        // JSON Schema maxLength counts Unicode scalar values, not UTF-8 bytes.
        assert!(authenticate(maximal.clone()).is_some());
        for (pointer, bound) in [
            ("/issuer_id", 2048),
            ("/key_id", 2048),
            ("/algorithm", 64),
            ("/provenance/source", 256),
            ("/provenance/issuer_organization_id", 128),
        ] {
            for length in [0, bound + 1] {
                let mut invalid = maximal.clone();
                *invalid.pointer_mut(pointer).unwrap() = json!("界".repeat(length));
                assert!(authenticate(invalid).is_none(), "{pointer} length {length}");
            }
        }
        for (pointer, invalid_value) in [
            ("/provenance/retrieved_at", "2026-11-07 12:00:00Z".into()),
            ("/provenance/retrieved_at", "2026-02-30T12:00:00Z".into()),
            ("/provenance/retrieved_at", "2026-11-07T12:00:00".into()),
            ("/provenance/retrieved_at", "2026-11-07T12:00:00Z\n".into()),
            ("/provenance/retrieved_at", "0000-11-07T12:00:00Z".into()),
            ("/provenance/retrieved_at", "2016-12-31T23:59:60Z".into()),
            (
                "/provenance/retrieved_at",
                format!("2026-11-07T12:00:00.{}Z", "0".repeat(44)),
            ),
            ("/provenance/content_sha256", "a".repeat(63)),
            ("/provenance/content_sha256", "a".repeat(65)),
            ("/provenance/content_sha256", "A".repeat(64)),
            (
                "/provenance/content_sha256",
                format!("{}\n", "a".repeat(63)),
            ),
        ] {
            let mut invalid = maximal.clone();
            *invalid.pointer_mut(pointer).unwrap() = json!(invalid_value);
            assert!(authenticate(invalid).is_none(), "{pointer}={invalid_value}");
        }
        let mut optional = maximal;
        for pointer in [
            "/key_id",
            "/provenance/issuer_organization_id",
            "/provenance/retrieved_at",
            "/provenance/content_sha256",
        ] {
            *optional.pointer_mut(pointer).unwrap() = Value::Null;
        }
        assert!(authenticate(optional).is_some());
    }

    #[test]
    fn sd_jwt_authenticates_the_selected_issuer_and_retains_scoped_provenance() {
        use ed25519_dalek::{Signer, SigningKey};
        let signer = SigningKey::from_bytes(&[27; 32]);
        let issuer = "did:web:issuer.example:Org:Acme";
        let kid = format!("{issuer}#assertion");
        let public_key = json!({
            "kty":"OKP", "crv":"Ed25519", "kid":kid,
            "x":URL_SAFE_NO_PAD.encode(signer.verifying_key().to_bytes())
        });
        let signed = |claim_issuer: &str| {
            let header = URL_SAFE_NO_PAD
                .encode(json!({"alg":"EdDSA", "typ":"vc+sd-jwt", "kid":kid}).to_string());
            let payload = URL_SAFE_NO_PAD.encode(
                json!({
                    "iss":claim_issuer, "iat":chrono::Utc::now().timestamp()-60,
                    "exp":chrono::Utc::now().timestamp()+3600,
                    "vct":"urn:example:member", "_sd_alg":"sha-256", "_sd":[], "role":"member"
                })
                .to_string(),
            );
            let input = format!("{header}.{payload}");
            format!(
                "{input}.{}~",
                URL_SAFE_NO_PAD.encode(signer.sign(input.as_bytes()).to_bytes())
            )
        };
        let mut context = context(json!({"status":"active", "allowed_algorithms":["EdDSA"]}));
        let mut selected = resolved_did_key(
            issuer,
            public_key,
            &marty_issuer_key_resolution::IssuerKeyResolution {
                verification_keys: vec![],
                source: "organization_signing_registry".into(),
                retrieved_at: "2026-11-07T12:00:00Z".into(),
                content_sha256: "a".repeat(64),
            },
            Some("issuer-org".into()),
        );
        bind_key_profile(&mut selected, &context);
        context.resolved_issuer_key = Some(selected.clone());
        context.token = json!(signed(issuer));
        let evidence = verify_sd_jwt(&context).unwrap();
        assert!(evidence.verified, "{:?}", evidence.failure_reason);
        let authentication = evidence.authenticated_issuer.unwrap();
        assert_eq!(evidence.issuer_id.as_deref(), Some(issuer));
        assert_eq!(authentication.issuer_id, issuer);
        assert_eq!(authentication.key_id.as_deref(), Some(kid.as_str()));
        assert_eq!(authentication.algorithm, "EdDSA");
        assert_eq!(authentication.provenance, selected.provenance);

        // The signature remains valid under the same key. Its authority is
        // unchanged even when a different issuer claim is signed.
        context.token = json!(signed("did:web:another-issuer.example"));
        let rejected = verify_sd_jwt(&context).unwrap();
        assert!(!rejected.verified);
        assert!(rejected.claims.is_empty() && rejected.issuer_id.is_none());
        assert!(rejected.authenticated_issuer.is_none());

        context.token = json!(signed(issuer));
        for wrong_tenant in [false, true] {
            let mut foreign = selected.clone();
            if wrong_tenant {
                foreign.provenance.organization_id = Some(Uuid::from_u128(9));
            } else {
                foreign.provenance.trust_profile_id = Some(Uuid::from_u128(9));
            }
            context.resolved_issuer_key = Some(foreign);
            let rejected = verify_sd_jwt(&context).unwrap();
            assert!(!rejected.verified);
            assert!(rejected.authenticated_issuer.is_none());
        }

        // The signed credential is unchanged. Malformed resolver provenance
        // must not produce verified claims or a nonconforming response object.
        for malformed in ["source", "timestamp", "digest"] {
            let mut invalid = selected.clone();
            match malformed {
                "source" => invalid.provenance.source.clear(),
                "timestamp" => invalid.provenance.retrieved_at = Some("yesterday".into()),
                _ => invalid.provenance.content_sha256 = Some("unknown".into()),
            }
            context.resolved_issuer_key = Some(invalid);
            let rejected = verify_sd_jwt(&context).unwrap();
            assert!(!rejected.verified, "{malformed}");
            assert!(rejected.claims.is_empty() && rejected.issuer_id.is_none());
            assert!(rejected.authenticated_issuer.is_none());
        }
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
            evidence.authenticated_outer_jti.as_deref(),
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
        let mut without_jti = credential_evidence(
            credential.as_object().unwrap(),
            Some("did:web:issuer.example"),
            false,
            1,
        );
        bind_authenticated_jwt_credential_id(&mut without_jti, json!({}).as_object().unwrap());
        assert!(without_jti.authenticated_outer_jti.is_none());
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

        // Authentication denial must happen before parsing or indexing any
        // holder-provided status identity, even when document evidence exists.
        for failure in 0..3 {
            let mut rejected = result.clone();
            match failure {
                0 => rejected.issuer_signature_valid = false,
                1 => rejected.issuer_trusted = false,
                _ => rejected.device_authentication_valid = false,
            }
            let denied =
                project_mdoc_result(b"untrusted holder bytes", rejected, &verification_context)
                    .unwrap();
            assert!(!denied.verified);
            assert!(denied.credential_status_ids.is_empty());
        }
        let mut incomplete = result;
        incomplete.document_evidence.clear();
        assert!(authenticated_mdoc_document(&incomplete).is_none());
    }

    #[test]
    fn authenticated_mdoc_signed_fixture_preserves_status_identity_after_selective_disclosure() {
        use isomdl::definitions::{device_response::DeviceResponse, helpers::NonEmptyVec};
        use marty_mdoc_status_binding::MdocStatusReference;
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/mdoc_presentation_signed_public.json"
        ))
        .unwrap();
        let decode = |field: &str| {
            base64::engine::general_purpose::STANDARD
                .decode(fixture[field].as_str().unwrap())
                .unwrap()
        };
        let full_bytes = decode("response_b64");
        let transcript = decode("transcript_b64");
        let certificate = fixture["certificate_pem"].as_str().unwrap().to_owned();
        let mut response: DeviceResponse = isomdl::cbor::from_slice(&full_bytes).unwrap();
        assert_eq!(response.documents.as_ref().unwrap().len(), 1);
        let mut document = response.documents.as_ref().unwrap()[0].clone();
        // This is the same IssuerSigned representation returned by issuance.
        let issued = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(isomdl::cbor::to_vec(&document.issuer_signed).unwrap());
        let expected = MdocStatusReference::from_issuer_signed_base64(&issued).unwrap();
        let mut namespaces = document.issuer_signed.namespaces.take().unwrap();
        let (namespace, items) = namespaces.iter().next().unwrap();
        let namespace = namespace.clone();
        assert_eq!(items.len(), 2);
        let disclosed = items[0].clone();
        namespaces.insert(namespace, NonEmptyVec::new(disclosed));
        document.issuer_signed.namespaces = Some(namespaces);
        response.documents = Some(NonEmptyVec::new(document));
        let selective_bytes = isomdl::cbor::to_vec(&response).unwrap();
        let mut verification_context = context(Value::Null);
        verification_context.format = DetectedCredentialFormat::Mdoc;
        for bytes in [&full_bytes, &selective_bytes] {
            let result = verify_mdoc_presentation(
                bytes,
                &transcript,
                &[],
                std::slice::from_ref(&certificate),
            );
            assert!(
                result.issuer_signature_valid
                    && result.issuer_trusted
                    && result.device_authentication_valid,
                "Real signed fixture authentication failed: {:?}",
                result.error
            );
            let evidence = project_mdoc_result(bytes, result, &verification_context).unwrap();
            assert!(evidence.verified);
            assert_eq!(evidence.credential_status_ids, [expected.to_string()]);
        }
        let foreign: Value = serde_json::from_str(include_str!(
            "../../../../contracts/presentation-mdoc-lifecycle-behavior.json"
        ))
        .unwrap();
        let result = verify_mdoc_presentation(
            &selective_bytes,
            &transcript,
            &[],
            &[foreign["certificate_pem"].as_str().unwrap().to_owned()],
        );
        assert!(result.issuer_signature_valid && result.device_authentication_valid);
        assert!(!result.issuer_trusted);
        let mut ambiguous = result.clone();
        ambiguous
            .document_types
            .push("second.invalid.document".into());
        assert_eq!(ambiguous.document_evidence.len(), 1);
        assert!(rejected_mdoc_diagnostic(&ambiguous).is_none());
        let denied = project_mdoc_result(&selective_bytes, result, &verification_context).unwrap();
        assert!(!denied.verified);
        assert!(
            denied.claims.is_empty()
                && denied.issuer_id.is_none()
                && denied.credential_status_ids.is_empty()
        );
        let diagnostic = denied.mdoc_authentication_diagnostic.unwrap();
        assert!(diagnostic.issuer_signature_valid && diagnostic.device_authentication_valid);
        assert!(!diagnostic.certificate_trust_passed);
        assert_eq!(
            diagnostic.certificate_trust_failures,
            [marty_oid4vp_contract::CertificateTrustFailure::CertificateChainRejected]
        );
        let mut corrupt: isomdl::definitions::device_response::DeviceResponse =
            isomdl::cbor::from_slice(&selective_bytes).unwrap();
        let mut documents = corrupt.documents.take().unwrap().into_inner();
        documents[0].issuer_signed.issuer_auth.signature[0] ^= 1;
        corrupt.documents = Some(documents.try_into().unwrap());
        let corrupted = isomdl::cbor::to_vec(&corrupt).unwrap();
        let result = verify_mdoc_presentation(
            &corrupted,
            &transcript,
            &[],
            std::slice::from_ref(&certificate),
        );
        assert!(!result.issuer_signature_valid);
        assert!(rejected_mdoc_diagnostic(&result).is_none());
        let selective_claims = disclosed_claims(&selective_bytes).unwrap();
        assert_eq!(selective_claims["given_name"], "Ada");
        assert!(selective_claims.get("family_name").is_none());
        let mut wrong_transcript = transcript;
        *wrong_transcript.last_mut().unwrap() ^= 1;
        let result =
            verify_mdoc_presentation(&selective_bytes, &wrong_transcript, &[], &[certificate]);
        assert!(result.issuer_signature_valid);
        assert!(!result.device_authentication_valid);
        let diagnostic = rejected_mdoc_diagnostic(&result).unwrap();
        assert!(diagnostic.issuer_signature_valid && diagnostic.certificate_trust_passed);
        assert!(!diagnostic.device_authentication_valid);
        let denied = project_mdoc_result(&selective_bytes, result, &verification_context).unwrap();
        assert!(!denied.verified);
        assert!(denied.credential_status_ids.is_empty());
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
