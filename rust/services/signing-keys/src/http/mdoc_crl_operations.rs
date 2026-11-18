//! Governed MDOC CRL publication and the exact deployment-owned CDP resource.
use super::*;
use crate::mdoc_crl::{
    GovernedMdocCrl, MdocCrlError, MdocCrlIdentity, MdocCrlSnapshot, MdocCrlStore, RevokedMdocDsc,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use der::{Decode, DecodePem, Encode};
use marty_crypto::crl_preparation::{prepare_crl, CrlRevocation, PreparedCrl};
use spki::AlgorithmIdentifierOwned;
use x509_cert::{crl::CertificateList, ext::pkix::CrlReason, Certificate};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublishMdocCrlRequest {
    organization_id: String,
    issuer_did: String,
    #[serde(default)]
    revoke_receipt_id: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

fn store(state: &AppState) -> Result<MdocCrlStore, PublicSigningError> {
    state
        .registry_store
        .as_ref()
        .map(|registry| MdocCrlStore::from_connection(registry.connection()))
        .ok_or_else(|| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "MDOC CRL storage is unavailable.",
            )
        })
}

fn store_error(error: MdocCrlError) -> PublicSigningError {
    match error {
        MdocCrlError::Conflict => public_failure(
            StatusCode::CONFLICT,
            "MDOC CRL inputs changed; retry with fresh authority.",
        ),
        MdocCrlError::Corrupt => public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "MDOC CRL state is malformed.",
        ),
        MdocCrlError::Storage => public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "MDOC CRL storage is unavailable.",
        ),
    }
}

/// The configured CDP may only name a resource owned by this deployment.
/// IDs are canonical and unambiguous path segments; no redirect or URL alias
/// is accepted as proof of publication.
fn controlled_cdp(
    public_domain: Option<&str>,
    organization_id: &str,
    certificate_id: &str,
    configured: &str,
) -> Result<(), PublicSigningError> {
    if !crate::mdoc_crl::valid_resource_id(organization_id, certificate_id) {
        return Err(public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "MDOC CRL resource identity is invalid.",
        ));
    }
    let authority = public_domain.ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Public CDP origin is unavailable.",
        )
    })?;
    let origin = reqwest::Url::parse(&format!("https://{authority}/")).map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Public CDP origin is invalid.",
        )
    })?;
    if origin.scheme() != "https"
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.host_str().is_none()
        || origin.as_str() != format!("https://{authority}/")
    {
        return Err(public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Public CDP origin is invalid.",
        ));
    }
    let expected = format!(
        "https://{authority}/v1/signing-keys/mdoc-crls/{organization_id}/{certificate_id}.crl"
    );
    if configured != expected {
        return Err(public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Configured MDOC CDP is outside the deployment-owned resource.",
        ));
    }
    Ok(())
}

fn active_iaca(
    snapshot: &MdocCrlSnapshot,
    org: &str,
    issuer_did: &str,
    certificate_id: &str,
    configured_uri: &str,
    now: chrono::DateTime<Utc>,
) -> Result<csca_lifecycle::CscaCertificateRecord, PublicSigningError> {
    let lifecycle: CscaLifecycleDocument = serde_json::from_value(snapshot.lifecycle.clone())
        .map_err(|_| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "MDOC IACA lifecycle is unavailable.",
            )
        })?;
    if lifecycle.organization_id != org {
        return Err(public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "MDOC IACA lifecycle tenant changed.",
        ));
    }
    let view = lifecycle
        .get(certificate_id, now)
        .map_err(|_| public_failure(StatusCode::NOT_FOUND, "Managed MDOC IACA was not found."))?;
    let record = view.certificate;
    if view.status != csca_lifecycle::CscaCertificateStatus::Valid
        || record.renewed_to.is_some()
        || record.metadata.get("certificate_profile")
            != Some(&json!(
                marty_signing_grant::certificate_profile::ManagedCertificateProfile::MdocIaca
            ))
        || record.metadata.get("issuer_did").and_then(Value::as_str) != Some(issuer_did)
        || record
            .metadata
            .pointer("/publication_configuration/crl_distribution_uri")
            .and_then(Value::as_str)
            != Some(configured_uri)
    {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Managed MDOC IACA is not current for this CDP.",
        ));
    }
    Ok(record)
}

fn receipt_serial(
    certificates: &Value,
    receipt_id: &str,
    certificate_id: &str,
    issuer_did: &str,
) -> Result<String, PublicSigningError> {
    // The issuance store derives this ID as SHA-256(org, idempotency key).
    if receipt_id.len() != 64 || !receipt_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Managed DSC receipt ID is invalid.",
        ));
    }
    let receipt = certificates
        .get("mdoc_dsc_issuance")
        .and_then(Value::as_object)
        .and_then(|map| map.get(receipt_id))
        .ok_or_else(|| {
            public_failure(StatusCode::NOT_FOUND, "Managed DSC receipt was not found.")
        })?;
    if receipt.get("csca_certificate_id").and_then(Value::as_str) != Some(certificate_id)
        || receipt.get("authorized_permission").and_then(Value::as_str)
            != Some("mdoc-certificate:issue")
        || receipt.pointer("/result/status").and_then(Value::as_str) != Some("issued")
        || receipt.pointer("/result/certificate_profile")
            != Some(&json!(marty_signing_grant::certificate_profile::ManagedCertificateProfile::MdocDocumentSigner))
        || receipt
            .pointer("/result/iaca_issuer_did")
            .and_then(Value::as_str)
            != Some(issuer_did)
    {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Managed DSC receipt does not belong to this IACA.",
        ));
    }
    let serial = receipt
        .get("serial")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Managed DSC serial is malformed.",
            )
        })?;
    if serial.is_empty()
        || serial.len() > 40
        || serial.len() % 2 != 0
        || !serial.bytes().all(|byte| byte.is_ascii_hexdigit())
        || receipt.pointer("/result/serial").and_then(Value::as_str) != Some(serial)
    {
        return Err(public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Managed DSC serial is malformed.",
        ));
    }
    let csca_profile_id = receipt
        .get("csca_profile_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Managed DSC IACA profile is malformed.",
            )
        })?;
    let dsc_profile_id = receipt
        .get("dsc_profile_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Managed DSC profile is malformed.",
            )
        })?;
    if certificates.get("mdoc_dsc_serials")
        .and_then(Value::as_object)
        .and_then(|serials| serials.get(&format!("{csca_profile_id}:{serial}")))
        .and_then(Value::as_str) != Some(receipt_id)
        || certificates.get("profiles").and_then(Value::as_object)
            .and_then(|profiles| profiles.get(dsc_profile_id))
            .and_then(|profile| profile.get("certificate_profile"))
            != Some(&json!(marty_signing_grant::certificate_profile::ManagedCertificateProfile::MdocDocumentSigner)) {
        return Err(public_failure(StatusCode::CONFLICT,
            "Managed DSC serial is not indexed to this governed issuance receipt."));
    }
    Ok(serial.to_ascii_lowercase())
}

fn reason(value: &str) -> Option<CrlReason> {
    match value {
        "unspecified" => Some(CrlReason::Unspecified),
        "key_compromise" => Some(CrlReason::KeyCompromise),
        "affiliation_changed" => Some(CrlReason::AffiliationChanged),
        "superseded" => Some(CrlReason::Superseded),
        "cessation_of_operation" => Some(CrlReason::CessationOfOperation),
        "certificate_hold" => Some(CrlReason::CertificateHold),
        "privilege_withdrawn" => Some(CrlReason::PrivilegeWithdrawn),
        _ => None,
    }
}

fn prepare_document_crl(
    document: &GovernedMdocCrl,
    issuer_der: &[u8],
) -> Result<PreparedCrl, PublicSigningError> {
    let serials = document
        .revoked
        .values()
        .map(|entry| {
            let serial = hex::decode(&entry.serial_hex).map_err(|_| {
                public_failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Managed DSC serial is malformed.",
                )
            })?;
            let reason = reason(&entry.reason).ok_or_else(|| {
                public_failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Stored CRL reason is invalid.",
                )
            })?;
            Ok((serial, entry.revoked_at_unix, reason))
        })
        .collect::<Result<Vec<_>, PublicSigningError>>()?;
    let revocations = serials
        .iter()
        .map(|(serial, at, reason)| CrlRevocation {
            serial,
            revoked_at_unix: *at,
            reason: *reason,
        })
        .collect::<Vec<_>>();
    prepare_crl(
        issuer_der,
        AlgorithmIdentifierOwned {
            oid: certificate_issuance::ECDSA_SHA256,
            parameters: None,
        },
        document.number,
        document.this_update_unix,
        document.next_update_unix,
        &revocations,
    )
    .map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Managed CRL construction or stored metadata is invalid.",
        )
    })
}

pub(super) async fn publish_mdoc_crl(
    State(state): State<AppState>,
    Path(certificate_id): Path<String>,
    Query(scope): Query<OrganizationScope>,
    headers: HeaderMap,
    Json(input): Json<PublishMdocCrlRequest>,
) -> Response {
    match publish_mdoc_crl_inner(
        &state,
        &certificate_id,
        &scope.organization_id,
        &headers,
        &input,
    )
    .await
    {
        Ok((number, revoked_count)) => Json(json!({"certificate_id":certificate_id,
            "number":number,"revoked_count":revoked_count,"status":"published"}))
        .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn publish_mdoc_crl_inner(
    state: &AppState,
    certificate_id: &str,
    org: &str,
    headers: &HeaderMap,
    input: &PublishMdocCrlRequest,
) -> Result<(u64, usize), PublicSigningError> {
    let actor = mdoc_operator(state, headers, true)?;
    if input.organization_id != org || input.revoke_receipt_id.is_some() != input.reason.is_some() {
        return Err(public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "MDOC CRL request is invalid.",
        ));
    }
    let metadata = mdoc_publication(state, org, &input.issuer_did).map_err(|_| {
        public_failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Governed MDOC publication is unavailable.",
        )
    })?;
    controlled_cdp(
        state.public_domain.as_deref(),
        org,
        certificate_id,
        &metadata.crl_distribution_uri,
    )?;
    let registry = state.registry_store.as_ref().ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Managed issuer registry is unavailable.",
        )
    })?;
    let lease = registry
        .acquire_rotation_lease(org)
        .await
        .map_err(|_| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Managed issuer lease is unavailable.",
            )
        })?
        .ok_or_else(|| public_failure(StatusCode::CONFLICT, "Managed issuer is busy."))?;
    let store = store(state)?;
    let snapshot = store
        .snapshot(org, certificate_id)
        .await
        .map_err(store_error)?;
    if snapshot.crl.is_none() && input.revoke_receipt_id.is_some() {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Publish the governed initial empty CRL before revoking a DSC.",
        ));
    }
    let now = Utc::now();
    let record = active_iaca(
        &snapshot,
        org,
        &input.issuer_did,
        certificate_id,
        &metadata.crl_distribution_uri,
        now,
    )?;
    if record.metadata.get("publication_configuration") != Some(&json!(metadata)) {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Governed MDOC IACA publication configuration changed.",
        ));
    }
    let identity = IssuerIdentityRequest {
        organization_id: Some(org.into()),
        issuer_did: input.issuer_did.clone(),
        key_purpose: "mdoc_iaca".into(),
        credential_format: "MDOC".into(),
        algorithm: "ES256".into(),
        key_attestation_policy: None,
        cert_pem: None,
        cert_chain_pem: None,
    };
    let profile = one_matching_profile(state, org, &identity).await?;
    let compatibility = state.compatibility.as_ref().ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Managed issuer compatibility is unavailable.",
        )
    })?;
    let current_key = checked_dsc_profile_key(compatibility, org, &profile, &identity).await?;
    if !documents::same_public_jwk(&record.public_jwk, &current_key)
        || profile.get("signing_key_reference").and_then(Value::as_str)
            != Some(record.key_reference.as_str())
    {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Managed IACA key changed.",
        ));
    }
    let this_update_unix = u64::try_from(now.timestamp())
        .map_err(|_| public_failure(StatusCode::SERVICE_UNAVAILABLE, "Clock is invalid."))?;
    let next_update_unix = this_update_unix
        .checked_add(86_400)
        .ok_or_else(|| public_failure(StatusCode::SERVICE_UNAVAILABLE, "Clock is invalid."))?;
    let mut next = match snapshot.crl.as_ref() {
        Some(previous)
            if previous.bound_to(
                org,
                &input.issuer_did,
                certificate_id,
                &record.cert_pem,
                &metadata.crl_distribution_uri,
            ) =>
        {
            if this_update_unix <= previous.this_update_unix {
                return Err(public_failure(
                    StatusCode::CONFLICT,
                    "CRL publication time must advance beyond the current number.",
                ));
            }
            let mut next = previous.clone();
            next.number = previous
                .number
                .checked_add(1)
                .ok_or_else(|| public_failure(StatusCode::CONFLICT, "CRL number exhausted."))?;
            next.this_update_unix = this_update_unix;
            next.next_update_unix = next_update_unix;
            next.der_b64.clear();
            next.published_by = actor.into();
            next
        }
        Some(_) => {
            return Err(public_failure(
                StatusCode::CONFLICT,
                "MDOC CRL issuer changed.",
            ))
        }
        None => GovernedMdocCrl::new(
            MdocCrlIdentity {
                organization_id: org,
                issuer_did: &input.issuer_did,
                certificate_id,
                cert_pem: &record.cert_pem,
                distribution_uri: &metadata.crl_distribution_uri,
            },
            this_update_unix,
            next_update_unix,
            actor,
        ),
    };
    if let (Some(receipt_id), Some(reason_name)) = (&input.revoke_receipt_id, &input.reason) {
        let _ = reason(reason_name).ok_or_else(|| {
            public_failure(StatusCode::UNPROCESSABLE_ENTITY, "CRL reason is invalid.")
        })?;
        let serial_hex = receipt_serial(
            &snapshot.certificates,
            receipt_id,
            certificate_id,
            &input.issuer_did,
        )?;
        if next.revoked.contains_key(receipt_id)
            || next
                .revoked
                .values()
                .any(|entry| entry.serial_hex == serial_hex)
        {
            return Err(public_failure(
                StatusCode::CONFLICT,
                "Managed DSC is already revoked.",
            ));
        }
        next.revoked.insert(
            receipt_id.clone(),
            RevokedMdocDsc {
                receipt_id: receipt_id.clone(),
                serial_hex,
                revoked_at_unix: this_update_unix,
                reason: reason_name.clone(),
                revoked_by: actor.into(),
            },
        );
    }
    let cert = Certificate::from_pem(&record.cert_pem).map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Managed IACA certificate is malformed.",
        )
    })?;
    let cert_der = cert.to_der().map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Managed IACA certificate is malformed.",
        )
    })?;
    for entry in next.revoked.values() {
        if receipt_serial(
            &snapshot.certificates,
            &entry.receipt_id,
            certificate_id,
            &input.issuer_did,
        )? != entry.serial_hex
        {
            return Err(public_failure(
                StatusCode::CONFLICT,
                "Stored MDOC revocation lost its managed DSC binding.",
            ));
        }
    }
    let prepared = prepare_document_crl(&next, &cert_der)?;
    let request = IssuerDidSignRequest {
        organization_id: org.into(),
        issuer_did: input.issuer_did.clone(),
        credential_format: "MDOC".into(),
        key_purpose: "mdoc_iaca".into(),
        algorithm: "ES256".into(),
        key_reference: None,
        payload_b64: Some(URL_SAFE_NO_PAD.encode(prepared.signing_bytes())),
        verification_method_id: None,
        expected_public_jwk: None,
        payload_hex: None,
    };
    let authorization = SignAuthorization::crl(&request, &profile).map_err(dsc_compat_failure)?;
    let signed = compatibility
        .sign_with_issuer_did(&request, authorization)
        .await
        .map_err(dsc_compat_failure)?;
    let signature = managed_der_signature(&signed)?;
    let der = prepared
        .finalize(prepared.signing_bytes(), &signature)
        .map_err(|_| {
            public_failure(
                StatusCode::BAD_GATEWAY,
                "Remote CRL signature did not verify against the active IACA.",
            )
        })?;
    let current_key = checked_dsc_profile_key(compatibility, org, &profile, &identity).await?;
    if !documents::same_public_jwk(&record.public_jwk, &current_key) {
        return Err(public_failure(
            StatusCode::CONFLICT,
            "Managed IACA key rotated during CRL signing.",
        ));
    }
    next.der_b64 = STANDARD.encode(der);
    store
        .commit(&lease, &snapshot, &next)
        .await
        .map_err(store_error)?;
    Ok((next.number, next.revoked.len()))
}

pub(super) async fn public_mdoc_crl(
    State(state): State<AppState>,
    Path((org, leaf)): Path<(String, String)>,
) -> Response {
    let certificate_id = match leaf.strip_suffix(".crl") {
        Some(id) => id,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    match public_mdoc_crl_inner(&state, &org, certificate_id).await {
        Ok(der) => (
            [
                (axum::http::header::CONTENT_TYPE, "application/pkix-crl"),
                (axum::http::header::CACHE_CONTROL, "no-store"),
            ],
            der,
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
}

async fn public_mdoc_crl_inner(
    state: &AppState,
    org: &str,
    certificate_id: &str,
) -> Result<Vec<u8>, PublicSigningError> {
    let store = store(state)?;
    let snapshot = store
        .snapshot(org, certificate_id)
        .await
        .map_err(store_error)?;
    let crl = snapshot.crl.as_ref().ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Governed MDOC CRL is not published.",
        )
    })?;
    controlled_cdp(
        state.public_domain.as_deref(),
        org,
        certificate_id,
        &crl.distribution_uri,
    )?;
    let metadata = mdoc_publication(state, org, &crl.issuer_did).map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Governed MDOC publication is unavailable.",
        )
    })?;
    if metadata.crl_distribution_uri != crl.distribution_uri {
        return Err(public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Governed MDOC CDP changed.",
        ));
    }
    let record = active_iaca(
        &snapshot,
        org,
        &crl.issuer_did,
        certificate_id,
        &crl.distribution_uri,
        Utc::now(),
    )?;
    if record.metadata.get("publication_configuration") != Some(&json!(metadata)) {
        return Err(public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Governed MDOC IACA publication configuration changed.",
        ));
    }
    let identity = IssuerIdentityRequest {
        organization_id: Some(org.into()),
        issuer_did: crl.issuer_did.clone(),
        key_purpose: "mdoc_iaca".into(),
        credential_format: "MDOC".into(),
        algorithm: "ES256".into(),
        key_attestation_policy: None,
        cert_pem: None,
        cert_chain_pem: None,
    };
    let profile = one_matching_profile(state, org, &identity).await?;
    let compatibility = state.compatibility.as_ref().ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Managed issuer compatibility is unavailable.",
        )
    })?;
    let key = checked_dsc_profile_key(compatibility, org, &profile, &identity).await?;
    if !documents::same_public_jwk(&record.public_jwk, &key)
        || profile.get("signing_key_reference").and_then(Value::as_str)
            != Some(record.key_reference.as_str())
    {
        return Err(public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Governed MDOC IACA key changed.",
        ));
    }
    if !crl.bound_to(
        org,
        &crl.issuer_did,
        certificate_id,
        &record.cert_pem,
        &metadata.crl_distribution_uri,
    ) {
        return Err(public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Governed MDOC CRL issuer changed.",
        ));
    }
    let now = u64::try_from(Utc::now().timestamp())
        .map_err(|_| public_failure(StatusCode::SERVICE_UNAVAILABLE, "Clock is invalid."))?;
    let der = crl.available_der(now).ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Governed MDOC CRL is absent or expired.",
        )
    })?;
    let parsed = CertificateList::from_der(&der).map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Governed MDOC CRL DER is malformed.",
        )
    })?;
    let signature = parsed.signature.as_bytes().ok_or_else(|| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Governed MDOC CRL signature is malformed.",
        )
    })?;
    let cert = Certificate::from_pem(&record.cert_pem).map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Managed IACA certificate is malformed.",
        )
    })?;
    let cert_der = cert.to_der().map_err(|_| {
        public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Managed IACA certificate is malformed.",
        )
    })?;
    let expected = prepare_document_crl(crl, &cert_der)?;
    let verified = expected
        .finalize(expected.signing_bytes(), signature)
        .map_err(|_| {
            public_failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "Governed MDOC CRL signature is invalid.",
            )
        })?;
    if verified != der {
        return Err(public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Governed MDOC CRL does not match the committed revocation state.",
        ));
    }
    let fresh = store
        .snapshot(org, certificate_id)
        .await
        .map_err(store_error)?;
    if !snapshot.same_raw(&fresh) {
        return Err(public_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            "Governed MDOC CRL authority changed during the read.",
        ));
    }
    Ok(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORG: &str = "00000000-0000-0000-0000-000000000001";

    #[test]
    fn cdp_accepts_only_the_exact_deployment_resource() {
        let expected = format!("https://issuer.example/v1/signing-keys/mdoc-crls/{ORG}/iaca_1.crl");
        assert!(controlled_cdp(Some("issuer.example"), ORG, "iaca_1", &expected).is_ok());
        for foreign in [
            expected.replace("issuer.example", "elsewhere.example"),
            expected.replace("iaca_1.crl", "iaca_1.crl?x=1"),
            expected.replace("/iaca_1.crl", "/iaca_2.crl"),
            expected.replace("https:", "http:"),
        ] {
            assert!(controlled_cdp(Some("issuer.example"), ORG, "iaca_1", &foreign).is_err());
        }
        assert!(controlled_cdp(Some("issuer.example"), ORG, "../iaca", &expected).is_err());
        assert!(controlled_cdp(None, ORG, "iaca_1", &expected).is_err());
    }

    #[test]
    fn revoked_serial_requires_the_managed_receipt_and_exact_iaca() {
        let receipt_id = "a".repeat(64);
        let mut certificates = json!({"mdoc_dsc_issuance": {},
            "mdoc_dsc_serials": {"iaca-profile:0A01": receipt_id},
            "profiles": {"dsc-profile": {"certificate_profile":"mdoc_document_signer"}}});
        certificates["mdoc_dsc_issuance"][&receipt_id] = json!({
            "csca_certificate_id":"iaca_1", "authorized_permission":"mdoc-certificate:issue",
            "csca_profile_id":"iaca-profile", "dsc_profile_id":"dsc-profile",
            "serial":"0A01", "result":{"iaca_issuer_did":"did:example:iaca", "serial":"0A01",
                "status":"issued", "certificate_profile":"mdoc_document_signer"}
        });
        assert_eq!(
            receipt_serial(&certificates, &receipt_id, "iaca_1", "did:example:iaca")
                .ok()
                .as_deref(),
            Some("0a01")
        );
        assert!(receipt_serial(&certificates, &receipt_id, "iaca_2", "did:example:iaca").is_err());
        assert!(
            receipt_serial(&certificates, &receipt_id, "iaca_1", "did:example:foreign").is_err()
        );
        assert!(
            receipt_serial(&certificates, &"b".repeat(64), "iaca_1", "did:example:iaca").is_err()
        );
        certificates["mdoc_dsc_issuance"][&receipt_id]["result"]["serial"] = json!("0B01");
        assert!(receipt_serial(&certificates, &receipt_id, "iaca_1", "did:example:iaca").is_err());
        certificates["mdoc_dsc_issuance"][&receipt_id]["result"]["serial"] = json!("0A01");
        certificates["mdoc_dsc_serials"]["iaca-profile:0A01"] = json!("foreign-receipt");
        assert!(receipt_serial(&certificates, &receipt_id, "iaca_1", "did:example:iaca").is_err());
    }

    #[test]
    fn absent_or_expired_crl_is_never_a_good_status() {
        let mut state = GovernedMdocCrl::new(
            MdocCrlIdentity {
                organization_id: "org",
                issuer_did: "did:example:x",
                certificate_id: "iaca",
                cert_pem: "pem",
                distribution_uri: "https://example.test/a.crl",
            },
            10,
            20,
            "operator",
        );
        assert!(state.available_der(10).is_none());
        state.der_b64 = STANDARD.encode([1u8, 2, 3]);
        assert!(state.available_der(9).is_none());
        assert!(state.available_der(20).is_none());
        assert_eq!(state.available_der(19), Some(vec![1, 2, 3]));
    }
}
