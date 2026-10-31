//! KMS-backed certificate lifecycle and publication operations.
//! The parent router owns transport state; distinct authority and grant paths remain here.
use super::*;

use marty_signing_grant::certificate_profile::{CertificateFamily, ManagedCertificateProfile};

fn certificate_role(
    format: &str,
    authority: bool,
    metadata: Option<&marty_signing_grant::certificate_profile::MdocCertificateMetadata>,
) -> Result<ManagedCertificateProfile, PublicSigningError> {
    let role = match (format.to_ascii_uppercase().as_str(), authority) {
        ("ICAO_EMRTD", true) => ManagedCertificateProfile::IcaoCsca,
        ("ICAO_EMRTD", false) => ManagedCertificateProfile::IcaoDocumentSigner,
        ("MDOC", true) => ManagedCertificateProfile::MdocIaca,
        ("MDOC", false) => ManagedCertificateProfile::MdocDocumentSigner,
        _ => {
            return Err(public_failure(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Certificate family is unsupported.",
            ))
        }
    };
    if role.family() == CertificateFamily::Mdoc {
        metadata
            .ok_or_else(|| {
                public_failure(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "MDOC_ISSUER_CONFIGURATION_REQUIRED",
                )
            })?
            .validate()
            .map_err(|_| {
                public_failure(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "MDOC_ISSUER_CONFIGURATION_INVALID",
                )
            })?;
    } else if metadata.is_some() {
        return Err(public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Certificate family configuration does not match.",
        ));
    }
    Ok(role)
}

/// This authority is independent from the passport operators and shared service key.
pub(super) fn mdoc_operator<'a>(
    state: &AppState,
    headers: &'a HeaderMap,
    authority: bool,
) -> Result<&'a str, PublicSigningError> {
    let options = &state.mdoc_certificates;
    let expected = if authority {
        options.iaca_gateway_key.as_deref()
    } else {
        options.dsc_gateway_key.as_deref()
    };
    let Some(expected) = expected else {
        return Err(public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "MDOC operator authority is not configured.",
        ));
    };
    let forbidden = [
        Some(state.internal_api_key.as_ref()),
        state.service_sign_gateway_key.as_deref(),
        state.issuer_sign_key.as_deref(),
        state.integration_secret_key.as_deref(),
        state.dsc_issue_gateway_key.as_deref(),
        state.csca_issue_gateway_key.as_deref(),
        if authority {
            options.dsc_gateway_key.as_deref()
        } else {
            options.iaca_gateway_key.as_deref()
        },
    ];
    if expected.len() < 32 || forbidden.contains(&Some(expected)) {
        return Err(public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "MDOC operator authority must be distinct.",
        ));
    }
    let supplied = headers
        .get("x-api-key")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if expected.len() != supplied.len()
        || expected.as_bytes().ct_eq(supplied.as_bytes()).unwrap_u8() != 1
    {
        return Err(public_failure(
            StatusCode::UNAUTHORIZED,
            "MDOC operator authority is required.",
        ));
    }
    headers
        .get("x-user-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            public_failure(
                StatusCode::UNAUTHORIZED,
                "Trusted operator identity is required.",
            )
        })
}

pub(super) fn mdoc_publication(
    state: &AppState,
    organization_id: &str,
    issuer_did: &str,
) -> Result<
    marty_signing_grant::certificate_profile::MdocCertificateMetadata,
    (StatusCode, Json<Value>),
> {
    state.mdoc_certificates.metadata_for(organization_id, issuer_did).map_err(|code| {
        (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error": code,
            "detail": "Governed issuer contact and CRL publication configuration is required before this ceremony."})))
    })
}

pub(super) async fn issue_public_mdoc_iaca_certificate(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    headers: HeaderMap,
    Json(input): Json<MdocIacaIssueRequest>,
) -> Response {
    let actor = match mdoc_operator(&state, &headers, true) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let metadata = match mdoc_publication(&state, &scope.organization_id, &input.issuer_did) {
        Ok(metadata) => metadata,
        Err(error) => return error.into_response(),
    };
    let request = CscaSelfSignedIssueRequest {
        mdoc_metadata: Some(metadata),
        organization_id: input.organization_id,
        issuer_did: input.issuer_did,
        certificate_id: input.certificate_id,
        credential_format: "MDOC".into(),
        country: input.country,
        organization: input.organization,
        common_name: input.common_name,
        validity_days: input.validity_days,
    };
    match issue_managed_csca_self_signed(&state, &scope.organization_id, actor, &request).await {
        Ok(result) => Json(result).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(super) async fn issue_public_mdoc_dsc_certificate(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    headers: HeaderMap,
    Json(input): Json<MdocDscIssueRequest>,
) -> Response {
    let actor = match mdoc_operator(&state, &headers, false) {
        Ok(actor) => actor,
        Err(error) => return error.into_response(),
    };
    let metadata = match mdoc_publication(&state, &scope.organization_id, &input.iaca_issuer_did) {
        Ok(metadata) => metadata,
        Err(error) => return error.into_response(),
    };
    let request = DscCertificateIssueRequest {
        mdoc_metadata: Some(metadata),
        organization_id: input.organization_id,
        dsc_issuer_did: input.dsc_issuer_did,
        csca_issuer_did: input.iaca_issuer_did,
        csca_certificate_id: input.iaca_certificate_id,
        credential_format: "MDOC".into(),
        country: input.country,
        organization: input.organization,
        common_name: input.common_name,
        validity_days: input.validity_days,
        idempotency_key: input.idempotency_key,
    };
    match issue_managed_dsc_certificate(&state, &scope.organization_id, actor, &request).await {
        Ok(result) => Json(result).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(super) async fn store_public_issuer_certificate(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    Json(input): Json<IssuerIdentityRequest>,
) -> Response {
    if let Err(error) = validate_identity_scope(&scope.organization_id, &input) {
        return error.into_response();
    }
    if let Err(error) = validate_identity_operation_fields(&input, false, true) {
        return error.into_response();
    }
    let profile = match one_matching_profile(&state, &scope.organization_id, &input).await {
        Ok(profile) => profile,
        Err(error) => return error.into_response(),
    };
    let Some(profile_id) = profile.get("id").and_then(Value::as_str) else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity storage is malformed.",
        );
    };
    let Some(compatibility) = state.compatibility.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity service is unavailable.",
        );
    };
    match compatibility
        .attach_profile_certificate(
            profile_id,
            &ProfileWriteRequest {
                organization_id: scope.organization_id,
                body: json!({
                    "cert_pem": input.cert_pem,
                    "cert_chain_pem": input.cert_chain_pem,
                }),
                expected_registry_revision: None,
            },
        )
        .await
    {
        Ok(_) => Json(identity_projection(&profile)).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(super) fn managed_csca_import(
    input: &CscaCertificateEnrollment,
    profile: &Value,
    resolved: &Value,
    provider_public_jwk: &Value,
) -> Result<ImportCscaCertificateRequest, PublicSigningError> {
    let purpose = profile
        .get("key_purpose")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // Preserve the legacy CSCA enrollment contract, including its historical
    // format selectors. Only the new mdoc IACA takes the closed MDOC profile.
    let authority = purpose == "csca"
        || ManagedCertificateProfile::from_identity(purpose, &input.credential_format)
            == Some(ManagedCertificateProfile::MdocIaca);
    if !same_managed_identity(profile, resolved) || !authority {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Resolved CSCA identity does not match its active managed profile.",
        ));
    }
    let key_reference = profile
        .get("signing_key_reference")
        .and_then(Value::as_str)
        .filter(|reference| !reference.trim().is_empty())
        .ok_or_else(|| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Managed CSCA key reference is unavailable.",
            )
        })?;
    let expected_public_jwk = resolved
        .get("public_jwk")
        .filter(|jwk| jwk.is_object())
        .cloned()
        .ok_or_else(|| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Managed CSCA public key is unavailable.",
            )
        })?;
    if !same_current_managed_key(resolved, provider_public_jwk) {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Published CSCA identity does not match its current managed KMS key.",
        ));
    }
    Ok(ImportCscaCertificateRequest {
        cert_pem: input.cert_pem.clone(),
        cert_chain_pem: input.cert_chain_pem.clone(),
        key_reference: key_reference.to_owned(),
        expected_public_jwk,
        metadata: json!({"issuer_did": input.issuer_did}),
    })
}

pub(super) fn same_managed_identity(profile: &Value, resolved: &Value) -> bool {
    ["id", "signing_service_id", "signing_key_reference"]
        .iter()
        .all(|field| {
            profile
                .get(*field)
                .and_then(Value::as_str)
                .is_some_and(|value| {
                    !value.trim().is_empty()
                        && resolved
                            .pointer(&format!("/issuer_profile/{field}"))
                            .and_then(Value::as_str)
                            == Some(value)
                })
        })
}

pub(super) fn same_current_managed_key(resolved: &Value, current: &Value) -> bool {
    resolved
        .get("public_jwk")
        .is_some_and(|published| documents::same_public_jwk(published, current))
}

pub(super) fn finish_managed_csr(
    csr: certificate_csr::PreparedCsr,
    encoding: Option<&str>,
    signature: Option<&str>,
    provider: &str,
) -> Result<String, String> {
    use certificate_csr::ManagedSignatureError;
    csr.finish_managed(encoding, signature)
        .map_err(|error| match error {
            ManagedSignatureError::Encoding => {
                format!("{provider} returned an incompatible CSR signature.")
            }
            ManagedSignatureError::Base64 => {
                format!("{provider} returned an invalid CSR signature.")
            }
            ManagedSignatureError::Verification => {
                format!("{provider} CSR signature did not verify.")
            }
        })
}

pub(super) async fn generate_public_issuer_csr(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    headers: HeaderMap,
    Json(input): Json<IssuerCsrIntent>,
) -> Response {
    if !authorize_issuer_sign(&state, &headers) {
        return public_error(StatusCode::UNAUTHORIZED, "Issuer CSR authority required.");
    }
    if !input.supports_certificate_purpose() {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Issuer CSR purpose or format is unsupported.",
        );
    }
    let identity = passport_csr_identity(&input);
    if let Err(error) = validate_identity_scope(&scope.organization_id, &identity) {
        return error.into_response();
    }
    let profile = match one_matching_profile(&state, &scope.organization_id, &identity).await {
        Ok(profile) => profile,
        Err(error) => return error.into_response(),
    };
    let Some(compatibility) = state.compatibility.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity service is unavailable.",
        );
    };
    let algorithm = canonical_algorithm(&input.algorithm);
    if input.algorithm != algorithm {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Issuer CSR algorithm is invalid.",
        );
    }
    let resolved = match compatibility
        .resolve_issuer_did(&ResolveIssuerDidRequest {
            organization_id: scope.organization_id.clone(),
            issuer_did: input.issuer_did.clone(),
            verification_method_id: None,
            credential_format: Some(input.credential_format.clone()),
            key_purpose: Some(input.key_purpose.clone()),
            algorithm: Some(algorithm.clone()),
        })
        .await
    {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    if !same_managed_identity(&profile, &resolved) {
        return public_error(
            StatusCode::CONFLICT,
            "Resolved issuer identity does not match its active managed profile.",
        );
    }
    let current_jwk = match compatibility
        .provider_public_key_for_profile(&scope.organization_id, &profile)
        .await
    {
        Ok(jwk) => jwk,
        Err(error) => return error.into_response(),
    };
    if !same_current_managed_key(&resolved, &current_jwk) {
        return public_error(
            StatusCode::CONFLICT,
            "Published issuer identity does not match its current managed KMS key.",
        );
    }
    let subject = CsrSubject {
        country: &input.country,
        organization: &input.organization,
        common_name: &input.common_name,
    };
    let csr = match certificate_csr::prepare(&current_jwk, &algorithm, &subject) {
        Ok(csr) => csr,
        Err(error) => return public_error(StatusCode::UNPROCESSABLE_ENTITY, &error.to_string()),
    };
    let signing_request = IssuerDidSignRequest {
        organization_id: scope.organization_id.clone(),
        issuer_did: input.issuer_did.clone(),
        credential_format: input.credential_format.clone(),
        key_purpose: input.key_purpose.clone(),
        algorithm: algorithm.clone(),
        key_reference: None,
        payload_b64: Some(URL_SAFE_NO_PAD.encode(csr.signing_bytes())),
        verification_method_id: None,
        expected_public_jwk: None,
        payload_hex: None,
    };
    let Some(header) = headers
        .get(HEADER_NAME)
        .and_then(|value| value.to_str().ok())
    else {
        return public_error(
            StatusCode::UNAUTHORIZED,
            "Issuer CSR signing grant required.",
        );
    };
    let Ok(envelope) = GrantEnvelope::from_header_value(header) else {
        return public_error(
            StatusCode::UNAUTHORIZED,
            "Issuer CSR signing grant is invalid.",
        );
    };
    let route = "/v1/signing-keys/issuer-identities/certificate-csr";
    let payload = input.bound_payload();
    let intent = input.grant_binding(
        &envelope.claims.operation_id,
        &scope.organization_id,
        route,
        &payload,
    );
    let consumed = match consume_bound_signing_grant(&state, header, &intent).await {
        Ok(consumed) => consumed,
        Err(GrantAuthorizationError::Denied) => {
            return public_error(
                StatusCode::UNAUTHORIZED,
                "Issuer CSR signing grant is denied.",
            )
        }
        Err(GrantAuthorizationError::Unavailable) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Issuer CSR verifier is unavailable.",
            )
        }
    };
    let service_id = profile.get("signing_service_id").and_then(Value::as_str);
    let key_reference = profile.get("signing_key_reference").and_then(Value::as_str);
    let actual = marty_signing_grant::replay::FinalSignBinding {
        organization_id: &scope.organization_id,
        route,
        service_id,
        issuer_did: Some(&input.issuer_did),
        key_reference,
        key_purpose: &input.key_purpose,
        algorithm: &algorithm,
        payload: csr.signing_bytes(),
    };
    let Some(approved) = consumed.approve_issuer_csr(&intent, &actual) else {
        return public_error(
            StatusCode::UNAUTHORIZED,
            "Issuer CSR signing intent changed.",
        );
    };
    let authorization = SignAuthorization::issuer_csr(approved, input.issuer_did.clone());
    let signed = match compatibility
        .sign_with_issuer_did(&signing_request, authorization)
        .await
    {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let csr_pem = match finish_managed_csr(
        csr,
        signed.get("signature_encoding").and_then(Value::as_str),
        signed.get("signature_b64").and_then(Value::as_str),
        "Managed issuer",
    ) {
        Ok(pem) => pem,
        Err(error) => return public_error(StatusCode::BAD_GATEWAY, &error),
    };
    Json(json!({
        "csr_pem": csr_pem,
        "issuer_did": input.issuer_did,
        "subject": {"country": input.country, "organization": input.organization, "common_name": input.common_name}
    })).into_response()
}

pub(super) async fn issue_public_csca_self_signed_certificate(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    headers: HeaderMap,
    Json(input): Json<CscaSelfSignedIssueRequest>,
) -> Response {
    if !input.credential_format.eq_ignore_ascii_case("ICAO_EMRTD") {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Passport certificate family is required.",
        );
    }

    if !state.beta_csca_issuance_enabled || state.csca_issue_gateway_key.is_none() {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Beta CSCA ceremony is disabled.",
        );
    }
    if !authorize_csca_issue(&state, &headers) {
        return public_error(
            StatusCode::UNAUTHORIZED,
            "CSCA operator authority is required.",
        );
    }
    let Some(actor_id) = headers
        .get("x-user-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
        })
    else {
        return public_error(
            StatusCode::UNAUTHORIZED,
            "Trusted operator identity is required.",
        );
    };
    match issue_managed_csca_self_signed(&state, &scope.organization_id, actor_id, &input).await {
        Ok(result) => Json(result).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(super) async fn issue_managed_csca_self_signed(
    state: &AppState,
    organization_id: &str,
    actor_id: &str,
    input: &CscaSelfSignedIssueRequest,
) -> Result<Value, PublicSigningError> {
    let role = certificate_role(&input.credential_format, true, input.mdoc_metadata.as_ref())?;

    let identity = IssuerIdentityRequest {
        organization_id: input.organization_id.clone(),
        issuer_did: input.issuer_did.clone(),
        key_purpose: role.key_purpose().into(),
        credential_format: input.credential_format.clone(),
        algorithm: "ES256".into(),
        key_attestation_policy: None,
        cert_pem: None,
        cert_chain_pem: None,
    };
    validate_identity_scope(organization_id, &identity)?;
    if !(1..=3650).contains(&input.validity_days)
        || input.certificate_id.is_empty()
        || input.certificate_id.len() > 128
        || !input
            .certificate_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:".contains(&byte))
    {
        return Err(public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "CSCA ceremony request is invalid.",
        ));
    }
    let mut digest_body = json!({
        "organization_id": organization_id,
        "issuer_did": input.issuer_did,
        "certificate_id": input.certificate_id,
        "credential_format": role.credential_format(),
        "country": input.country,
        "organization": input.organization,
        "common_name": input.common_name,
        "validity_days": input.validity_days,
    });
    if let Some(metadata) = &input.mdoc_metadata {
        digest_body["mdoc_certificate_configuration"] =
            json!({"profile": role, "version": 1, "publication": metadata});
    }
    let request_digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&digest_body).expect("CSCA request serializes"))
    );
    let lifecycle_store = state
        .csca_lifecycle_store
        .as_ref()
        .ok_or_else(|| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "CSCA lifecycle storage is unavailable.",
            )
        })?
        .for_family(role.family());
    let registry = state.registry_store.as_ref().ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        )
    })?;
    let replay = |document: &CscaLifecycleDocument| -> Result<Option<Value>, PublicSigningError> {
        let Some(record) = document.certificates.get(&input.certificate_id) else {
            return Ok(None);
        };
        if record
            .metadata
            .pointer("/csca_ceremony/request_digest")
            .and_then(Value::as_str)
            != Some(&request_digest)
        {
            return Err(public_failure(
                StatusCode::CONFLICT,
                "CSCA certificate identifier is already used.",
            ));
        }
        record
            .metadata
            .pointer("/csca_ceremony/public_result")
            .cloned()
            .ok_or_else(|| {
                public_failure(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Stored CSCA ceremony result is malformed.",
                )
            })
            .map(Some)
    };
    let now = chrono::Utc::now();
    let mut document = lifecycle_store
        .load(organization_id, now)
        .await
        .map_err(csca_public_failure)?;
    if let Some(result) = replay(&document)? {
        return Ok(result);
    }
    let lease = registry
        .acquire_rotation_lease(organization_id)
        .await
        .map_err(|_| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Tenant signing lease is unavailable.",
            )
        })?
        .ok_or_else(|| public_failure(StatusCode::CONFLICT, "Tenant signing state is changing."))?;
    document = lifecycle_store
        .load(organization_id, now)
        .await
        .map_err(csca_public_failure)?;
    if let Some(result) = replay(&document)? {
        return Ok(result);
    }
    let profile = one_matching_profile(state, organization_id, &identity).await?;
    let compatibility = state.compatibility.as_ref().ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity service is unavailable.",
        )
    })?;
    let current_jwk =
        checked_dsc_profile_key(compatibility, organization_id, &profile, &identity).await?;
    let subject = CsrSubject {
        country: &input.country,
        organization: &input.organization,
        common_name: &input.common_name,
    };
    let csr = certificate_csr::prepare(&current_jwk, "ES256", &subject).map_err(|_| {
        public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "CSCA subject or managed key is invalid.",
        )
    })?;
    let sign = |payload: &[u8]| IssuerDidSignRequest {
        organization_id: organization_id.into(),
        issuer_did: input.issuer_did.clone(),
        credential_format: role.credential_format().into(),
        key_purpose: role.key_purpose().into(),
        algorithm: "ES256".into(),
        key_reference: None,
        payload_b64: Some(URL_SAFE_NO_PAD.encode(payload)),
        verification_method_id: None,
        expected_public_jwk: None,
        payload_hex: None,
    };
    let csr_request = sign(csr.signing_bytes());
    let csr_authorization =
        SignAuthorization::certificate(&csr_request, &profile).map_err(dsc_compat_failure)?;
    let csr_signed = compatibility
        .sign_with_issuer_did(&csr_request, csr_authorization)
        .await
        .map_err(dsc_compat_failure)?;
    let csr_signature = managed_der_signature(&csr_signed)?;
    let csr_pem = csr.finish(&csr_signature).map_err(|_| {
        public_failure(
            StatusCode::BAD_GATEWAY,
            "Managed CSCA CSR signature did not verify.",
        )
    })?;
    let verified = VerifiedDscSubject::from_csr_pem(&csr_pem, &current_jwk).map_err(|_| {
        public_failure(
            StatusCode::BAD_GATEWAY,
            "Managed CSCA CSR proof did not verify.",
        )
    })?;
    if verified.country().as_deref() != Some(input.country.as_str()) {
        return Err(public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "CSCA country is invalid.",
        ));
    }
    let mut serial = uuid::Uuid::new_v4().into_bytes();
    serial[0] &= 0x7f;
    if serial[0] == 0 {
        serial[0] = 1;
    }
    let now = std::time::SystemTime::now();
    let prepared = if let Some(metadata) = input.mdoc_metadata.as_ref() {
        certificate_issuance::prepare_mdoc_iaca(
            &verified,
            &serial,
            input.validity_days,
            now,
            metadata,
        )
    } else {
        certificate_issuance::prepare_csca(&verified, &serial, input.validity_days, now)
    }
    .map_err(|_| {
        public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "CSCA certificate policy is invalid.",
        )
    })?;
    let metadata = prepared.metadata().map_err(|_| {
        public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "CSCA certificate metadata is invalid.",
        )
    })?;
    let certificate_request = sign(prepared.signing_bytes());
    let certificate_authorization = SignAuthorization::certificate(&certificate_request, &profile)
        .map_err(dsc_compat_failure)?;
    let certificate_signed = compatibility
        .sign_with_issuer_did(&certificate_request, certificate_authorization)
        .await
        .map_err(dsc_compat_failure)?;
    let certificate_signature = managed_der_signature(&certificate_signed)?;
    let certificate_pem = prepared.finish(&certificate_signature).map_err(|_| {
        public_failure(
            StatusCode::BAD_GATEWAY,
            "Managed CSCA certificate signature did not verify.",
        )
    })?;
    if role.family() == CertificateFamily::Mdoc {
        crate::mdoc_certificate::validate_attachment(&certificate_pem, "", role)
            .map_err(|detail| public_failure(StatusCode::BAD_GATEWAY, detail))?;
    }
    let current_profile = one_matching_profile(state, organization_id, &identity).await?;
    if current_profile != profile {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "CSCA issuer profile changed during ceremony.",
        ));
    }
    let latest_jwk =
        checked_dsc_profile_key(compatibility, organization_id, &current_profile, &identity)
            .await?;
    if !documents::same_public_jwk(&current_jwk, &latest_jwk) {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Managed CSCA key rotated during ceremony.",
        ));
    }
    let mut result = json!({
        "certificate_id": input.certificate_id,
        "certificate_pem": certificate_pem,
        "chain_pem": "",
        "issuer_did": input.issuer_did,
        "subject": {"country": input.country, "organization": input.organization, "common_name": input.common_name},
        "serial": metadata.serial_hex,
        "not_before": metadata.not_before,
        "not_after": metadata.not_after,
        "status": "issued",
    });
    if role.family() == CertificateFamily::Mdoc {
        result["certificate_profile"] = json!(role);
    }
    let enrollment = CscaCertificateEnrollment {
        organization_id: input.organization_id.clone(),
        issuer_did: input.issuer_did.clone(),
        credential_format: role.credential_format().into(),
        algorithm: "ES256".into(),
        certificate_id: input.certificate_id.clone(),
        cert_pem: certificate_pem.clone(),
        cert_chain_pem: String::new(),
    };
    let resolved = compatibility
        .resolve_issuer_did(&ResolveIssuerDidRequest {
            organization_id: organization_id.into(),
            issuer_did: input.issuer_did.clone(),
            verification_method_id: None,
            credential_format: Some(role.credential_format().into()),
            key_purpose: Some(role.key_purpose().into()),
            algorithm: Some("ES256".into()),
        })
        .await
        .map_err(dsc_compat_failure)?;
    let mut imported = managed_csca_import(&enrollment, &current_profile, &resolved, &latest_jwk)?;
    let profile_document = state
        .profile_store
        .as_ref()
        .ok_or_else(|| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Issuer identity storage is unavailable.",
            )
        })?
        .list(organization_id)
        .await
        .map_err(|_| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Issuer identity storage is unavailable.",
            )
        })?;
    let profile_still_current = profile_document
        .get("profiles")
        .and_then(Value::as_array)
        .is_some_and(|profiles| profiles.iter().any(|candidate| candidate == &profile));
    if !profile_still_current {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "CSCA issuer profile changed during ceremony.",
        ));
    }
    let profile_revision = profile_document
        .get("revision")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            public_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Issuer profile revision is malformed.",
            )
        })?;
    imported.metadata = json!({
        "issuer_did": input.issuer_did,
        "csca_ceremony": {"request_digest": request_digest, "public_result": result, "actor_id": actor_id},
    });
    if role.family() == CertificateFamily::Mdoc {
        imported.metadata["certificate_profile"] = json!(role);
        imported.metadata["publication_configuration"] = json!(input.mdoc_metadata);
    }
    document
        .import(&input.certificate_id, imported, chrono::Utc::now())
        .map_err(csca_public_failure)?;
    lifecycle_store
        .save_with_rotation_lease(&document, &lease, profile_revision)
        .await
        .map_err(csca_public_failure)?;
    Ok(result)
}

pub(super) fn csca_public_failure(error: CscaLifecycleError) -> PublicSigningError {
    let (status, detail) = match error {
        CscaLifecycleError::Conflict(_) | CscaLifecycleError::ConcurrentModification => (
            StatusCode::CONFLICT,
            "CSCA lifecycle changed during ceremony.",
        ),
        CscaLifecycleError::Invalid(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "CSCA certificate is invalid.",
        ),
        CscaLifecycleError::Storage(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "CSCA lifecycle storage is unavailable.",
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "CSCA lifecycle storage is malformed.",
        ),
    };
    public_failure(status, detail)
}

pub(super) async fn issue_public_dsc_certificate(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    headers: HeaderMap,
    Json(input): Json<DscCertificateIssueRequest>,
) -> Response {
    if !input.credential_format.eq_ignore_ascii_case("ICAO_EMRTD") {
        return public_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Passport certificate family is required.",
        );
    }

    // Only Gateway holds this distinct credential, which it attaches after
    // its dedicated passport-certificate:issue policy check.
    if state.dsc_issue_gateway_key.is_none() {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Operator issuance is not configured.",
        );
    }
    if !authorize_dsc_issue(&state, &headers) {
        return public_error(
            StatusCode::UNAUTHORIZED,
            "Operator issuance authority is required.",
        );
    }
    let Some(actor_id) = headers
        .get("x-user-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
        })
    else {
        return public_error(
            StatusCode::UNAUTHORIZED,
            "Trusted operator identity is required.",
        );
    };
    match issue_managed_dsc_certificate(&state, &scope.organization_id, actor_id, &input).await {
        Ok(result) => Json(result).into_response(),
        Err(error) => error.into_response(),
    }
}

pub(super) fn dsc_identity(
    input: &DscCertificateIssueRequest,
    purpose: &str,
    issuer_did: &str,
) -> IssuerIdentityRequest {
    IssuerIdentityRequest {
        organization_id: input.organization_id.clone(),
        issuer_did: issuer_did.into(),
        key_purpose: purpose.into(),
        credential_format: input.credential_format.clone(),
        algorithm: "ES256".into(),
        key_attestation_policy: None,
        cert_pem: None,
        cert_chain_pem: None,
    }
}

pub(super) fn dsc_store_failure(error: DscIssuanceStoreError) -> PublicSigningError {
    let (status, detail) = match error {
        DscIssuanceStoreError::Invalid(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "DSC issuance input is invalid.",
        ),
        DscIssuanceStoreError::Conflict(_) => (
            StatusCode::CONFLICT,
            "DSC issuance state conflicts with the current request.",
        ),
        DscIssuanceStoreError::Storage(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "DSC issuance storage is unavailable.",
        ),
        DscIssuanceStoreError::Corrupt(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "DSC issuance storage is malformed.",
        ),
    };
    public_failure(status, detail)
}

pub(super) fn dsc_compat_failure(error: CompatibilityError) -> PublicSigningError {
    let (status, detail) = match error {
        CompatibilityError::Unauthorized => (
            StatusCode::UNAUTHORIZED,
            "Managed issuer authority is unavailable.",
        ),
        CompatibilityError::ProfileNotFound
        | CompatibilityError::ServiceNotFound
        | CompatibilityError::NotFound(_) => (
            StatusCode::NOT_FOUND,
            "Managed issuer identity was not found.",
        ),
        CompatibilityError::BadRequest(_) => (
            StatusCode::BAD_REQUEST,
            "Managed issuer request is invalid.",
        ),
        CompatibilityError::AmbiguousProfile | CompatibilityError::Conflict(_) => (
            StatusCode::CONFLICT,
            "Managed issuer binding conflicts with current state.",
        ),
        CompatibilityError::PreconditionFailed => (
            StatusCode::PRECONDITION_FAILED,
            "Managed issuer binding changed since the supplied revision.",
        ),
        CompatibilityError::Invalid(_) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Managed issuer binding is invalid.",
        ),
        CompatibilityError::SecretCapabilityUnavailable => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Integration secret encryption capability is unavailable.",
        ),
        CompatibilityError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Managed issuer backend is unavailable.",
        ),
    };
    public_failure(status, detail)
}

pub(super) async fn issue_managed_dsc_certificate(
    state: &AppState,
    organization_id: &str,
    actor_id: &str,
    input: &DscCertificateIssueRequest,
) -> Result<Value, PublicSigningError> {
    let role = certificate_role(
        &input.credential_format,
        false,
        input.mdoc_metadata.as_ref(),
    )?;

    let dsc_request_identity = dsc_identity(input, role.key_purpose(), &input.dsc_issuer_did);
    let csca_request_identity = dsc_identity(
        input,
        role.authority().key_purpose(),
        &input.csca_issuer_did,
    );
    validate_identity_scope(organization_id, &dsc_request_identity)?;
    validate_identity_scope(organization_id, &csca_request_identity)?;
    if !(1..=90).contains(&input.validity_days)
        || input.csca_certificate_id.is_empty()
        || input.csca_certificate_id.len() > 128
        || input.idempotency_key.is_empty()
        || input.idempotency_key.len() > 128
        || !input
            .idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
    {
        return Err(public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "DSC issuance request is invalid.",
        ));
    }
    let store = state
        .dsc_issuance_store
        .as_ref()
        .ok_or_else(|| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "DSC issuance storage is unavailable.",
            )
        })?
        .for_family(role.family());
    let mut digest_body = json!({
        "organization_id": organization_id,
        "dsc_issuer_did": input.dsc_issuer_did,
        "csca_issuer_did": input.csca_issuer_did,
        "csca_certificate_id": input.csca_certificate_id,
        "credential_format": role.credential_format(),
        "country": input.country,
        "organization": input.organization,
        "common_name": input.common_name,
        "validity_days": input.validity_days,
    });
    if let Some(metadata) = &input.mdoc_metadata {
        digest_body["mdoc_certificate_configuration"] =
            json!({"profile": role, "version": 1, "publication": metadata});
    }
    let request_digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&digest_body).expect("DSC request serializes"))
    );
    let claim = match store
        .begin(organization_id, &input.idempotency_key, &request_digest)
        .await
        .map_err(dsc_store_failure)?
    {
        BeginDscIssuance::Completed(result) => return Ok(result),
        BeginDscIssuance::Pending => {
            return Err(public_failure(
                StatusCode::CONFLICT,
                "DSC issuance is already in progress.",
            ))
        }
        BeginDscIssuance::Claim(claim) => claim,
    };
    let result =
        issue_claimed_dsc_certificate(state, &store, &claim, organization_id, actor_id, input)
            .await;
    if result.is_err() {
        let _ = store.release(&claim).await;
    }
    result
}

pub(super) async fn checked_dsc_profile_key(
    compatibility: &SigningCompatibilityService,
    organization_id: &str,
    profile: &Value,
    identity: &IssuerIdentityRequest,
) -> Result<Value, PublicSigningError> {
    let resolved = compatibility
        .resolve_issuer_did(&ResolveIssuerDidRequest {
            organization_id: organization_id.into(),
            issuer_did: identity.issuer_did.clone(),
            verification_method_id: None,
            credential_format: Some(identity.credential_format.clone()),
            key_purpose: Some(identity.key_purpose.clone()),
            algorithm: Some("ES256".into()),
        })
        .await
        .map_err(dsc_compat_failure)?;
    if !same_managed_identity(profile, &resolved) {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Resolved identity differs from its active issuer profile.",
        ));
    }
    let current = compatibility
        .provider_public_key_for_profile(organization_id, profile)
        .await
        .map_err(dsc_compat_failure)?;
    if !same_current_managed_key(&resolved, &current) {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Published identity differs from its current managed KMS key.",
        ));
    }
    Ok(current)
}

pub(super) async fn issue_claimed_dsc_certificate(
    state: &AppState,
    store: &DscIssuanceStore,
    claim: &DscClaim,
    organization_id: &str,
    actor_id: &str,
    input: &DscCertificateIssueRequest,
) -> Result<Value, PublicSigningError> {
    let role = certificate_role(
        &input.credential_format,
        false,
        input.mdoc_metadata.as_ref(),
    )?;

    let registry = state.registry_store.as_ref().ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        )
    })?;
    let lease = registry
        .acquire_rotation_lease(organization_id)
        .await
        .map_err(|_| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Tenant signing lease is unavailable.",
            )
        })?
        .ok_or_else(|| public_failure(StatusCode::CONFLICT, "Tenant signing state is changing."))?;
    let snapshot = store
        .snapshot(organization_id)
        .await
        .map_err(dsc_store_failure)?;
    let dsc_request_identity = dsc_identity(input, role.key_purpose(), &input.dsc_issuer_did);
    let csca_request_identity = dsc_identity(
        input,
        role.authority().key_purpose(),
        &input.csca_issuer_did,
    );
    let dsc_profile = one_matching_profile(state, organization_id, &dsc_request_identity).await?;
    let csca_profile = one_matching_profile(state, organization_id, &csca_request_identity).await?;
    let dsc_profile_id = dsc_profile
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "DSC issuer profile is malformed.",
            )
        })?;
    let csca_profile_id = csca_profile
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "CSCA issuer profile is malformed.",
            )
        })?;
    let snapshot_matches = |profile: &Value, id: &str| {
        snapshot
            .profiles
            .get("profiles")
            .and_then(Value::as_array)
            .and_then(|profiles| {
                profiles
                    .iter()
                    .find(|candidate| candidate.get("id").and_then(Value::as_str) == Some(id))
            })
            == Some(profile)
    };
    if !snapshot_matches(&dsc_profile, dsc_profile_id)
        || !snapshot_matches(&csca_profile, csca_profile_id)
    {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Issuer profiles changed during DSC issuance.",
        ));
    }
    let dsc_key_reference = dsc_profile
        .get("signing_key_reference")
        .and_then(Value::as_str);
    let csca_key_reference = csca_profile
        .get("signing_key_reference")
        .and_then(Value::as_str);
    if dsc_profile_id == csca_profile_id
        || dsc_key_reference.is_none()
        || csca_key_reference.is_none()
        || dsc_key_reference == csca_key_reference
    {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "CSCA and DSC require distinct active managed keys.",
        ));
    }
    let compatibility = state.compatibility.as_ref().ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity service is unavailable.",
        )
    })?;
    let dsc_jwk = checked_dsc_profile_key(
        compatibility,
        organization_id,
        &dsc_profile,
        &dsc_request_identity,
    )
    .await?;
    let csca_jwk = checked_dsc_profile_key(
        compatibility,
        organization_id,
        &csca_profile,
        &csca_request_identity,
    )
    .await?;
    let lifecycle_store = state
        .csca_lifecycle_store
        .as_ref()
        .ok_or_else(|| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "CSCA lifecycle storage is unavailable.",
            )
        })?
        .for_family(role.family());
    let now_utc = chrono::Utc::now();
    let lifecycle = lifecycle_store
        .load(organization_id, now_utc)
        .await
        .map_err(|_| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "CSCA lifecycle storage is unavailable.",
            )
        })?;
    if serde_json::to_value(&lifecycle).ok().as_ref() != Some(&snapshot.lifecycle) {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "CSCA lifecycle changed during DSC issuance.",
        ));
    }
    let csca_view = lifecycle
        .get(&input.csca_certificate_id, now_utc)
        .map_err(|_| {
            public_failure(
                StatusCode::NOT_FOUND,
                "Active CSCA certificate was not found.",
            )
        })?;
    if csca_view.status != csca_lifecycle::CscaCertificateStatus::Valid
        || csca_view.certificate.key_reference != csca_key_reference.unwrap_or_default()
        || !documents::same_public_jwk(&csca_view.certificate.public_jwk, &csca_jwk)
        || csca_view
            .certificate
            .metadata
            .get("issuer_did")
            .and_then(Value::as_str)
            != Some(input.csca_issuer_did.as_str())
        || certificate_issuance::certificate_country(&csca_view.certificate.cert_pem).as_deref()
            != Some(input.country.as_str())
    {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Selected CSCA certificate is not the active managed issuer for this country.",
        ));
    }
    let subject = CsrSubject {
        country: &input.country,
        organization: &input.organization,
        common_name: &input.common_name,
    };
    let csr = certificate_csr::prepare(&dsc_jwk, "ES256", &subject)
        .map_err(|error| public_failure(StatusCode::UNPROCESSABLE_ENTITY, &error.to_string()))?;
    let csr_request = IssuerDidSignRequest {
        organization_id: organization_id.into(),
        issuer_did: input.dsc_issuer_did.clone(),
        credential_format: input.credential_format.clone(),
        key_purpose: role.key_purpose().into(),
        algorithm: "ES256".into(),
        key_reference: None,
        payload_b64: Some(URL_SAFE_NO_PAD.encode(csr.signing_bytes())),
        verification_method_id: None,
        expected_public_jwk: None,
        payload_hex: None,
    };
    let csr_authorization =
        SignAuthorization::certificate(&csr_request, &dsc_profile).map_err(dsc_compat_failure)?;
    let csr_signature = compatibility
        .sign_with_issuer_did(&csr_request, csr_authorization)
        .await
        .map_err(dsc_compat_failure)?;
    let csr_signature = managed_der_signature(&csr_signature)?;
    let csr_pem = csr.finish(&csr_signature).map_err(|_| {
        public_failure(
            StatusCode::BAD_GATEWAY,
            "Managed DSC CSR signature did not verify.",
        )
    })?;
    let verified = VerifiedDscSubject::from_csr_pem(&csr_pem, &dsc_jwk).map_err(|_| {
        public_failure(
            StatusCode::BAD_GATEWAY,
            "Managed DSC CSR proof did not verify.",
        )
    })?;
    if verified.country().as_deref() != Some(input.country.as_str()) {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "DSC certificate country differs from the selected CSCA.",
        ));
    }
    issue_signed_dsc_certificate(
        state,
        store,
        claim,
        &lease,
        &snapshot,
        organization_id,
        actor_id,
        input,
        &dsc_profile,
        &csca_profile,
        dsc_profile_id,
        csca_profile_id,
        &dsc_jwk,
        &csca_jwk,
        &csca_view.certificate,
        &verified,
    )
    .await
}

pub(super) fn managed_der_signature(signed: &Value) -> Result<Vec<u8>, PublicSigningError> {
    if signed.get("signature_encoding").and_then(Value::as_str) != Some("der") {
        return Err(public_failure(
            StatusCode::BAD_GATEWAY,
            "Managed issuer returned an incompatible certificate signature.",
        ));
    }
    signed
        .get("signature_b64")
        .and_then(Value::as_str)
        .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
        .filter(|signature| !signature.is_empty())
        .ok_or_else(|| {
            public_failure(
                StatusCode::BAD_GATEWAY,
                "Managed issuer returned an invalid certificate signature.",
            )
        })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn issue_signed_dsc_certificate(
    state: &AppState,
    store: &DscIssuanceStore,
    claim: &DscClaim,
    lease: &RotationLease,
    snapshot: &DscIssuanceSnapshot,
    organization_id: &str,
    actor_id: &str,
    input: &DscCertificateIssueRequest,
    dsc_profile: &Value,
    csca_profile: &Value,
    dsc_profile_id: &str,
    csca_profile_id: &str,
    dsc_jwk: &Value,
    csca_jwk: &Value,
    csca_record: &csca_lifecycle::CscaCertificateRecord,
    verified: &VerifiedDscSubject,
) -> Result<Value, PublicSigningError> {
    let role = certificate_role(
        &input.credential_format,
        false,
        input.mdoc_metadata.as_ref(),
    )?;

    let compatibility = state.compatibility.as_ref().ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Issuer identity service is unavailable.",
        )
    })?;
    let mut serial = uuid::Uuid::new_v4().into_bytes();
    serial[0] &= 0x7f;
    if serial[0] == 0 {
        serial[0] = 1;
    }
    let now = std::time::SystemTime::now();
    let prepared = if let Some(metadata) = input.mdoc_metadata.as_ref() {
        certificate_issuance::prepare_mdoc_dsc(
            verified,
            &csca_record.cert_pem,
            &csca_record.cert_chain_pem,
            csca_jwk,
            &serial,
            input.validity_days,
            now,
            metadata,
        )
    } else {
        certificate_issuance::prepare_dsc(
            verified,
            &csca_record.cert_pem,
            &csca_record.cert_chain_pem,
            csca_jwk,
            &serial,
            input.validity_days,
            now,
        )
    }
    .map_err(|error| public_failure(StatusCode::UNPROCESSABLE_ENTITY, &error.to_string()))?;
    let metadata = prepared
        .metadata()
        .map_err(|error| public_failure(StatusCode::UNPROCESSABLE_ENTITY, &error.to_string()))?;
    let certificate_request = IssuerDidSignRequest {
        organization_id: organization_id.into(),
        issuer_did: input.csca_issuer_did.clone(),
        credential_format: input.credential_format.clone(),
        key_purpose: role.authority().key_purpose().into(),
        algorithm: "ES256".into(),
        key_reference: None,
        payload_b64: Some(URL_SAFE_NO_PAD.encode(prepared.signing_bytes())),
        verification_method_id: None,
        expected_public_jwk: None,
        payload_hex: None,
    };
    let certificate_authorization =
        SignAuthorization::certificate(&certificate_request, csca_profile)
            .map_err(dsc_compat_failure)?;
    let signed = compatibility
        .sign_with_issuer_did(&certificate_request, certificate_authorization)
        .await
        .map_err(dsc_compat_failure)?;
    let signature = managed_der_signature(&signed)?;
    let certificate_pem = prepared.finish(&signature).map_err(|_| {
        public_failure(
            StatusCode::BAD_GATEWAY,
            "Managed CSCA signature did not verify against the enrolled certificate.",
        )
    })?;
    let chain_pem = if csca_record.cert_chain_pem.trim().is_empty() {
        csca_record.cert_pem.clone()
    } else {
        format!(
            "{}\n{}",
            csca_record.cert_pem.trim(),
            csca_record.cert_chain_pem.trim()
        )
    };
    let inspected = documents::inspect_certificate(&InspectCertificateRequest {
        cert_pem: certificate_pem.clone(),
        cert_chain_pem: Some(chain_pem.clone()),
        expected_public_jwk: Some(dsc_jwk.clone()),
    })
    .map_err(|_| {
        public_failure(
            StatusCode::BAD_GATEWAY,
            "Issued DSC certificate is invalid.",
        )
    })?;
    if inspected.public_key_matches != Some(true) {
        return Err(public_failure(
            StatusCode::BAD_GATEWAY,
            "Issued DSC certificate does not match the managed DSC key.",
        ));
    }
    // Recheck provider keys immediately before the Redis snapshot-fenced
    // commit. An external KMS rotation cannot be fenced by Redis alone.
    let dsc_request_identity = dsc_identity(input, role.key_purpose(), &input.dsc_issuer_did);
    let csca_request_identity = dsc_identity(
        input,
        role.authority().key_purpose(),
        &input.csca_issuer_did,
    );
    let current_dsc = checked_dsc_profile_key(
        compatibility,
        organization_id,
        dsc_profile,
        &dsc_request_identity,
    )
    .await?;
    let current_csca = checked_dsc_profile_key(
        compatibility,
        organization_id,
        csca_profile,
        &csca_request_identity,
    )
    .await?;
    if !documents::same_public_jwk(dsc_jwk, &current_dsc)
        || !documents::same_public_jwk(csca_jwk, &current_csca)
    {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Managed certificate key rotated during issuance.",
        ));
    }
    let lifecycle = state
        .csca_lifecycle_store
        .as_ref()
        .ok_or_else(|| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "CSCA lifecycle storage is unavailable.",
            )
        })?
        .for_family(role.family())
        .load(organization_id, chrono::Utc::now())
        .await
        .map_err(|_| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "CSCA lifecycle storage is unavailable.",
            )
        })?;
    let current_csca_view = lifecycle
        .get(&input.csca_certificate_id, chrono::Utc::now())
        .map_err(|_| {
            public_failure(
                StatusCode::CONFLICT,
                "Selected CSCA certificate changed during issuance.",
            )
        })?;
    if current_csca_view.status != csca_lifecycle::CscaCertificateStatus::Valid
        || current_csca_view.certificate != *csca_record
    {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Selected CSCA certificate changed during issuance.",
        ));
    }
    let mut attachment = json!({
        "cert_pem": certificate_pem,
        "cert_chain_pem": chain_pem,
        "cert_expires_at": inspected.expires_at,
        "updated_at": chrono::Utc::now().to_rfc3339(),
        "x5c": inspected.x5c,
        "public_jwk": inspected.public_jwk,
        "signing_key_reference": dsc_profile["signing_key_reference"],
    });
    if role.family() == CertificateFamily::Mdoc {
        let x5c = crate::mdoc_certificate::validate_attachment(&certificate_pem, &chain_pem, role)
            .map_err(|error| public_failure(StatusCode::BAD_GATEWAY, error))?;
        attachment["x5c"] = json!(x5c);
        attachment["certificate_profile"] = json!(role);
    }
    let mut public_result = json!({
        "certificate_pem": certificate_pem,
        "chain_pem": chain_pem,
        "dsc_issuer_did": input.dsc_issuer_did,
        "csca_issuer_did": input.csca_issuer_did,
        "subject": {"country": input.country, "organization": input.organization, "common_name": input.common_name},
        "serial": metadata.serial_hex,
        "not_before": metadata.not_before,
        "not_after": metadata.not_after,
        "status": "issued",
    });
    if role.family() == CertificateFamily::Mdoc {
        public_result
            .as_object_mut()
            .expect("fixed certificate result")
            .remove("csca_issuer_did");
        public_result["iaca_issuer_did"] = json!(input.csca_issuer_did);
        public_result["certificate_profile"] = json!(role);
    }
    match store
        .commit(
            claim,
            snapshot,
            lease,
            dsc_profile_id,
            csca_profile_id,
            &input.csca_certificate_id,
            actor_id,
            &metadata.serial_hex,
            attachment,
            public_result,
        )
        .await
        .map_err(dsc_store_failure)?
    {
        CommitDscIssuance::Committed(result) | CommitDscIssuance::Completed(result) => Ok(result),
    }
}

pub(super) fn service_certificate_projection(service: &Value, certificate: &Value) -> Value {
    json!({
        "id": service.get("id"),
        "name": service.get("name"),
        "service_type": service.get("service_type"),
        "provider": service.get("provider"),
        "status": service.get("status"),
        "cert_pem": certificate.get("cert_pem"),
        "cert_chain_pem": certificate.get("cert_chain_pem"),
        "cert_expires_at": certificate.get("cert_expires_at"),
    })
}

pub(super) fn service_certificate_key_config(service: &Value) -> Result<Value, PublicSigningError> {
    let mut config = service.clone();
    let reference = service
        .get("key_reference")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|reference| !reference.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            let aliases = service.get("key_aliases")?.as_array()?;
            if aliases.len() == 1 {
                aliases[0]
                    .as_str()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
            } else {
                None
            }
        })
        .ok_or_else(|| {
            public_failure(
                StatusCode::CONFLICT,
                "A service certificate requires one configured KMS signing key.",
            )
        })?;
    config["key_reference"] = json!(reference);
    Ok(config)
}

pub(super) async fn current_service_public_jwk(
    service: &Value,
) -> Result<(Value, Value), PublicSigningError> {
    let config = service_certificate_key_config(service)?;
    let response = kms::public_key(ProviderRequest {
        service_config: config.clone(),
    })
    .await
    .map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "The service KMS public key is unavailable.",
        )
    })?;
    let public_jwk = documents::sanitize_public_jwk(&response, None).map_err(|_| {
        public_failure(
            StatusCode::BAD_GATEWAY,
            "The service KMS returned an invalid public key.",
        )
    })?;
    Ok((config, public_jwk))
}

pub(super) async fn verify_public_service_key(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
) -> Response {
    if let Err(error) = validate_service_scope(&scope.organization_id, None) {
        return error.into_response();
    }
    let service =
        match registered_certificate_service(&state, &scope.organization_id, &service_id).await {
            Ok(service) => service,
            Err(error) => return error.into_response(),
        };
    let public_jwk = match current_service_public_jwk(&service).await {
        Ok((_, jwk)) => jwk,
        Err(error) => return error.into_response(),
    };
    Json(verify_service_key_result(
        &service_id,
        &service,
        &public_jwk,
        chrono::Utc::now().to_rfc3339(),
    ))
    .into_response()
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublicServiceJwksPublicationRequest {}

pub(super) async fn checked_stored_service_certificate(
    documents: &DocumentStore,
    organization_id: &str,
    service_id: &str,
    service: &Value,
    public_jwk: &Value,
) -> Result<Option<Value>, PublicSigningError> {
    let overrides = documents
        .certificate_overrides(organization_id)
        .await
        .map_err(|_| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Certificate storage is unavailable.",
            )
        })?;
    let certificate = selected_service_certificate(service, &overrides, service_id).cloned();
    if let Some(certificate) = certificate.as_ref() {
        checked_service_x5c(certificate, public_jwk, service_id)?;
    }
    Ok(certificate)
}

pub(super) fn public_publication_error(error: documents::DocumentError) -> Response {
    match error {
        documents::DocumentError::Invalid(detail) => {
            public_error(StatusCode::UNPROCESSABLE_ENTITY, &detail)
        }
        documents::DocumentError::Conflict(detail) => public_error(StatusCode::CONFLICT, &detail),
        documents::DocumentError::NotFound(detail) => public_error(StatusCode::NOT_FOUND, &detail),
        documents::DocumentError::Storage(_) => public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing document storage is unavailable.",
        ),
        documents::DocumentError::Corrupt(_) => public_error(
            StatusCode::BAD_GATEWAY,
            "Stored signing document is malformed.",
        ),
    }
}

pub(super) async fn publish_public_service_jwks(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
    _body: Option<Json<PublicServiceJwksPublicationRequest>>,
) -> Response {
    if let Err(error) = validate_service_scope(&scope.organization_id, None) {
        return error.into_response();
    }
    let Some(store) = state.registry_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        );
    };
    let lease = match store.acquire_rotation_lease(&scope.organization_id).await {
        Ok(Some(lease)) => lease,
        Ok(None) | Err(registry::RegistryError::Conflict) => {
            return public_error(
                StatusCode::CONFLICT,
                "Signing registry update is already in progress.",
            )
        }
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing registry is unavailable.",
            )
        }
    };
    let outcome = async {
        let service =
            match registered_certificate_service(&state, &scope.organization_id, &service_id).await
            {
                Ok(service) => service,
                Err(error) => return error.into_response(),
            };
        let Some(documents) = state.document_store.as_ref() else {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing document storage is unavailable.",
            );
        };
        let (config, public_jwk) = match current_service_public_jwk(&service).await {
            Ok(material) => material,
            Err(error) => return error.into_response(),
        };
        let certificate = match checked_stored_service_certificate(
            documents,
            &scope.organization_id,
            &service_id,
            &service,
            &public_jwk,
        )
        .await
        {
            Ok(certificate) => certificate,
            Err(error) => return error.into_response(),
        };
        let publication = match documents
            .publish_jwk_with_lease(
                &scope.organization_id,
                &service_id,
                PublishJwkRequest {
                    jwk: public_jwk,
                    key_reference: config["key_reference"].as_str().map(str::to_owned),
                    cert_pem: certificate
                        .as_ref()
                        .and_then(|value| value.get("cert_pem"))
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    cert_chain_pem: certificate
                        .as_ref()
                        .and_then(|value| value.get("cert_chain_pem"))
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                },
                &lease,
            )
            .await
        {
            Ok(publication) => publication,
            Err(error) => return public_publication_error(error),
        };
        if let Err(error) = mark_service_publication_discovered(
            &state,
            &scope.organization_id,
            &service_id,
            &[("last_jwk_fetch_ok", json!(true))],
            &lease,
        )
        .await
        {
            return error.into_response();
        }
        let public = match public_jwk_projection(&publication.jwk) {
            Ok(public) => public,
            Err(_) => return public_error(StatusCode::BAD_GATEWAY, "Published JWK is malformed."),
        };
        Json(json!({
            "ok": true,
            "service_id": service_id,
            "message": "Public key published to organization JWKS document",
            "jwk": public,
            "jwks_document": {
                "organization_id": scope.organization_id,
                "key_count": publication.key_count,
            },
            "published_at": chrono::Utc::now().to_rfc3339(),
        }))
        .into_response()
    }
    .await;
    let _ = lease.release().await;
    outcome
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublicServiceDidPublicationRequest {
    #[serde(default)]
    pub(super) did_id: Option<String>,
    #[serde(default)]
    pub(super) org_slug: Option<String>,
    #[serde(default)]
    pub(super) fragment: Option<String>,
}

pub(super) async fn publish_public_service_did_vm(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
    body: Option<Json<PublicServiceDidPublicationRequest>>,
) -> Response {
    if let Err(error) = validate_service_scope(&scope.organization_id, None) {
        return error.into_response();
    }
    let Some(store) = state.registry_store.as_ref() else {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        );
    };
    let lease = match store.acquire_rotation_lease(&scope.organization_id).await {
        Ok(Some(lease)) => lease,
        Ok(None) | Err(registry::RegistryError::Conflict) => {
            return public_error(
                StatusCode::CONFLICT,
                "Signing registry update is already in progress.",
            )
        }
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing registry is unavailable.",
            )
        }
    };
    let outcome = async {
        let body = body.map(|Json(body)| body).unwrap_or_default();
        let service =
            match registered_certificate_service(&state, &scope.organization_id, &service_id).await
            {
                Ok(service) => service,
                Err(error) => return error.into_response(),
            };
        let Some(documents) = state.document_store.as_ref() else {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Signing document storage is unavailable.",
            );
        };
        let Some(public_domain) = state
            .public_domain
            .as_deref()
            .map(str::trim)
            .filter(|domain| !domain.is_empty())
        else {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Public DID authority is unavailable.",
            );
        };
        let (config, public_jwk) = match current_service_public_jwk(&service).await {
            Ok(material) => material,
            Err(error) => return error.into_response(),
        };
        let certificate = match checked_stored_service_certificate(
            documents,
            &scope.organization_id,
            &service_id,
            &service,
            &public_jwk,
        )
        .await
        {
            Ok(certificate) => certificate,
            Err(error) => return error.into_response(),
        };
        let org_slug = body.org_slug.or_else(|| {
            body.did_id
                .is_none()
                .then(|| scope.organization_id.to_lowercase())
        });
        let publication = match documents
            .publish_did_with_lease(
                &scope.organization_id,
                &service_id,
                PublishDidRequest {
                    jwk: public_jwk,
                    public_domain: public_domain.to_owned(),
                    did_id: body.did_id,
                    org_slug,
                    fragment: body.fragment,
                    key_reference: config["key_reference"].as_str().map(str::to_owned),
                    cert_pem: certificate
                        .as_ref()
                        .and_then(|value| value.get("cert_pem"))
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    cert_chain_pem: certificate
                        .as_ref()
                        .and_then(|value| value.get("cert_chain_pem"))
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    relationship: DidVerificationRelationship::AssertionMethod,
                },
                &lease,
            )
            .await
        {
            Ok(publication) => publication,
            Err(error) => return public_publication_error(error),
        };
        let public_document = match public_did_document(publication.document) {
            Ok(document) => document,
            Err(error) => return error.into_response(),
        };
        let method_id = publication.verification_method["id"].as_str();
        let Some(method) = public_document
            .get("verificationMethod")
            .and_then(Value::as_array)
            .and_then(|methods| {
                methods
                    .iter()
                    .find(|method| method.get("id").and_then(Value::as_str) == method_id)
            })
            .cloned()
        else {
            return public_error(
                StatusCode::BAD_GATEWAY,
                "Published DID method is malformed.",
            );
        };
        let has_x5c = method
            .get("x5c")
            .and_then(Value::as_array)
            .is_some_and(|chain| !chain.is_empty());
        if let Err(error) = mark_service_publication_discovered(
            &state,
            &scope.organization_id,
            &service_id,
            &[
                ("did_verification_method_publish", json!(true)),
                ("last_did_publish_ok", json!(true)),
                ("has_x5c", json!(has_x5c)),
            ],
            &lease,
        )
        .await
        {
            return error.into_response();
        }
        Json(json!({
            "ok": true,
            "service_id": service_id,
            "message": "Verification method published to organization DID document",
            "verification_method": method,
            "did_document": {
                "id": public_document.get("id"),
                "verification_method_count": publication.verification_method_count,
            },
            "published_at": chrono::Utc::now().to_rfc3339(),
        }))
        .into_response()
    }
    .await;
    let _ = lease.release().await;
    outcome
}

pub(super) async fn mark_service_publication_discovered(
    state: &AppState,
    organization_id: &str,
    service_id: &str,
    publication_capabilities: &[(&str, Value)],
    lease: &RotationLease,
) -> Result<(), PublicSigningError> {
    let store = state.registry_store.as_ref().ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        )
    })?;
    let mut registry = store.load(organization_id).await.map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Signing registry is unavailable.",
        )
    })?;
    let service = registry
        .get_mut("services")
        .and_then(Value::as_array_mut)
        .and_then(|services| {
            services
                .iter_mut()
                .find(|service| service.get("id").and_then(Value::as_str) == Some(service_id))
        })
        .ok_or_else(|| public_failure(StatusCode::NOT_FOUND, "Signing service is unavailable."))?;
    let provider = service["provider"].clone();
    let capabilities = service
        .as_object_mut()
        .expect("registered service is an object")
        .entry("discovered_capabilities")
        .or_insert_with(|| json!({}));
    let capabilities = capabilities
        .as_object_mut()
        .expect("normalized discovered capabilities are an object");
    capabilities.insert("public_key_export".into(), json!(true));
    capabilities.insert("provider".into(), provider);
    for (name, value) in publication_capabilities {
        capabilities.insert((*name).into(), value.clone());
    }
    service["updated_at"] = json!(chrono::Utc::now().to_rfc3339());
    store
        .save_with_rotation_lease(organization_id, &registry, lease)
        .await
        .map_err(|error| {
            public_failure(
                if error == registry::RegistryError::Conflict {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                },
                "Signing registry is unavailable.",
            )
        })?;
    Ok(())
}

pub(super) async fn generate_public_service_csr(
    State(state): State<AppState>,
    Path(service_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
    headers: HeaderMap,
    Json(input): Json<ServiceCsrIntent>,
) -> Response {
    if !authorize_service_sign(&state, &headers) {
        return public_error(
            StatusCode::UNAUTHORIZED,
            "CSR service authentication required.",
        );
    }
    if let Err(error) =
        validate_service_scope(&scope.organization_id, input.organization_id.as_deref())
    {
        return error.into_response();
    }
    let service =
        match registered_certificate_service(&state, &scope.organization_id, &service_id).await {
            Ok(service) => service,
            Err(error) => return error.into_response(),
        };
    let (mut service_config, public_jwk) = match current_service_public_jwk(&service).await {
        Ok(result) => result,
        Err(error) => return error.into_response(),
    };
    let algorithm = match public_jwk.get("crv").and_then(Value::as_str) {
        Some("P-256") => "ES256",
        Some("P-384") => "ES384",
        Some("P-521") => "ES512",
        _ => {
            return public_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "The service KMS key cannot sign an X.509 CSR.",
            )
        }
    };
    if service_config.get("key_reference").and_then(Value::as_str)
        != Some(input.key_reference.as_str())
        || input.algorithm != algorithm
    {
        return public_error(
            StatusCode::CONFLICT,
            "CSR key or algorithm changed after authorization.",
        );
    }
    let csr = match certificate_csr::prepare(
        &public_jwk,
        algorithm,
        &CsrSubject {
            country: &input.country,
            organization: &input.organization,
            common_name: &input.common_name,
        },
    ) {
        Ok(csr) => csr,
        Err(error) => return public_error(StatusCode::UNPROCESSABLE_ENTITY, &error.to_string()),
    };
    let Some(header) = headers
        .get(HEADER_NAME)
        .and_then(|value| value.to_str().ok())
    else {
        return public_error(StatusCode::UNAUTHORIZED, "CSR signing grant required.");
    };
    let Ok(envelope) = GrantEnvelope::from_header_value(header) else {
        return public_error(StatusCode::UNAUTHORIZED, "CSR signing grant is invalid.");
    };
    let route = format!("/v1/signing-keys/services/{service_id}/certificate-csr");
    let intent_payload = input.bound_payload();
    let intent = input.grant_binding(
        &envelope.claims.operation_id,
        &scope.organization_id,
        &route,
        &service_id,
        &intent_payload,
    );
    let consumed = match consume_bound_signing_grant(&state, header, &intent).await {
        Ok(consumed) => consumed,
        Err(GrantAuthorizationError::Denied) => {
            return public_error(StatusCode::UNAUTHORIZED, "CSR signing grant is denied.")
        }
        Err(GrantAuthorizationError::Unavailable) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "CSR signing grant verifier is unavailable.",
            )
        }
    };
    let actual_sign = marty_signing_grant::replay::FinalSignBinding {
        organization_id: &scope.organization_id,
        route: &route,
        service_id: Some(&service_id),
        issuer_did: None,
        key_reference: Some(&input.key_reference),
        key_purpose: "x509_csr",
        algorithm,
        payload: csr.signing_bytes(),
    };
    let Some(approved) = consumed.approve_service_csr(&intent, &actual_sign) else {
        return public_error(StatusCode::UNAUTHORIZED, "CSR signing intent changed.");
    };
    service_config["algorithm"] = json!(algorithm);
    if !approved.authorizes(&actual_sign) {
        return public_error(
            StatusCode::UNAUTHORIZED,
            "CSR signing authorization expired or changed.",
        );
    }
    let signed = match kms::sign(SignRequest {
        service_config,
        payload_b64: URL_SAFE_NO_PAD.encode(csr.signing_bytes()),
    })
    .await
    {
        Ok(signed) => signed,
        Err(_) => {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "The service KMS could not sign the CSR.",
            )
        }
    };
    let csr_pem = match finish_managed_csr(
        csr,
        Some(signed.signature_encoding),
        Some(&signed.signature_b64),
        "The service KMS",
    ) {
        Ok(pem) => pem,
        Err(error) => return public_error(StatusCode::BAD_GATEWAY, &error),
    };
    Json(json!({
        "ok": true,
        "service_id": service_id,
        "csr_pem": csr_pem,
        "generated_at": chrono::Utc::now().to_rfc3339(),
    }))
    .into_response()
}

pub(super) async fn enroll_public_csca_certificate(
    State(state): State<AppState>,
    Query(scope): Query<OrganizationScope>,
    Json(input): Json<CscaCertificateEnrollment>,
) -> Response {
    let identity = input.identity();
    if let Err(error) = validate_identity_scope(&scope.organization_id, &identity) {
        return error.into_response();
    }
    if state.csca_lifecycle_store.is_none() {
        return public_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "CSCA lifecycle storage is unavailable.",
        );
    }
    let lease = match csca_signing_lease(&state, &scope.organization_id).await {
        Ok(lease) => lease,
        Err(error) => return error.into_response(),
    };
    let result = async {
        let profile = match one_matching_profile(&state, &scope.organization_id, &identity).await {
            Ok(profile) => profile,
            Err(error) => return error.into_response(),
        };
        let Some(compatibility) = state.compatibility.as_ref() else {
            return public_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Issuer identity service is unavailable.",
            );
        };
        let resolved = match compatibility
            .resolve_issuer_did(&ResolveIssuerDidRequest {
                organization_id: scope.organization_id.clone(),
                issuer_did: input.issuer_did.clone(),
                verification_method_id: None,
                credential_format: Some(input.credential_format.clone()),
                key_purpose: Some("csca".into()),
                algorithm: Some(canonical_algorithm(&input.algorithm)),
            })
            .await
        {
            Ok(resolved) => resolved,
            Err(error) => return error.into_response(),
        };
        let provider_public_jwk = match compatibility
            .provider_public_key_for_profile(&scope.organization_id, &profile)
            .await
        {
            Ok(jwk) => jwk,
            Err(error) => return error.into_response(),
        };
        let request = match managed_csca_import(&input, &profile, &resolved, &provider_public_jwk) {
            Ok(request) => request,
            Err(error) => return error.into_response(),
        };
        let profile_revision =
            match validate_managed_csca_binding(&state, &scope.organization_id, &request).await {
                Ok(revision) => revision,
                Err(error) => return error.into_response(),
            };
        let now = chrono::Utc::now();
        let mut document = match load_csca_lifecycle(&state, &scope.organization_id, now).await {
            Ok(document) => document,
            Err(error) => return error.into_response(),
        };
        let view = match document.import(&input.certificate_id, request, now) {
            Ok(view) => view,
            Err(error) => return csca_lifecycle_error(error).into_response(),
        };
        let store = state
            .csca_lifecycle_store
            .as_ref()
            .expect("CSCA storage checked above");
        if let Err(error) = store
            .save_with_rotation_lease(&document, &lease, profile_revision)
            .await
            .map_err(csca_lifecycle_error)
        {
            return error.into_response();
        }
        Json(json!({
            "certificate_id": view.certificate.certificate_id,
            "subject": view.certificate.subject,
            "not_after": view.certificate.not_after,
            "status": view.status,
        }))
        .into_response()
    }
    .await;
    let _ = lease.release().await;
    result
}
