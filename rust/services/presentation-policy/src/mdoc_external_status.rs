//! Native mdoc proof retention and governed external CWT/CRL transport.
use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use coset::Label;
use der::Decode;
use isomdl::definitions::x509::revocation::{CrlError, RevocationFetcher};
use marty_verification::mdoc::{
    prepare_mdoc_status_requests_at, verify_mdoc_external_status, verify_mdoc_presentation_at,
    AuthenticatedMdocStatusRequest, MdocExternalStatus, MdocStatusReference,
};
use time::OffsetDateTime;
use x509_cert::crl::CertificateList;

use crate::{
    CredentialStatusEvidence, ExternalStatusFixtureTransport, PresentationVerificationError,
};

/// Only the native verifier can construct this proof; caller JSON cannot.
#[derive(Clone)]
pub struct AuthenticatedMdocPresentationEvidence {
    bytes: Arc<[u8]>,
    transcript: Arc<[u8]>,
    roots: Arc<[String]>,
    pins: Arc<[String]>,
    requests: Arc<Vec<AuthenticatedMdocStatusRequest>>,
}

impl std::fmt::Debug for AuthenticatedMdocPresentationEvidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedMdocPresentationEvidence")
            .finish_non_exhaustive()
    }
}
impl PartialEq for AuthenticatedMdocPresentationEvidence {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
            && self.transcript == other.transcript
            && self.roots == other.roots
            && self.pins == other.pins
            && self
                .requests
                .iter()
                .map(|request| request.source_binding_digest())
                .eq(other
                    .requests
                    .iter()
                    .map(|request| request.source_binding_digest()))
    }
}

impl AuthenticatedMdocPresentationEvidence {
    pub(crate) fn revalidate_at(&self, epoch: u64) -> Result<(), PresentationVerificationError> {
        // The policy clock exposes whole seconds. Check the upper endpoint so
        // a fractional MSO/certificate deadline cannot be extended by rounding.
        let second = epoch
            .checked_add(1)
            .and_then(|epoch| i64::try_from(epoch).ok())
            .ok_or(PresentationVerificationError::Unavailable)?;
        let now = OffsetDateTime::from_unix_timestamp(second)
            .map_err(|_| PresentationVerificationError::Unavailable)?;
        self.revalidate_exact(now).map_err(|_| {
            PresentationVerificationError::Failed("PRESENTATION_POLICY.MDOC_PROOF_EXPIRED".into())
        })
    }

    fn revalidate_exact(&self, now: OffsetDateTime) -> Result<(), ()> {
        let result = verify_mdoc_presentation_at(
            &self.bytes,
            &self.transcript,
            &self.roots,
            &self.pins,
            now,
        );
        if !result.issuer_signature_valid
            || !result.issuer_trusted
            || !result.device_authentication_valid
            || result.document_types.len() != 1
        {
            return Err(());
        }
        Ok(())
    }
}

/// Resource-only parsing before any issuer/holder cryptography. No reference or
/// certificate encountered here is granted authority or network permission.
pub(crate) fn bounded_presentation(bytes: &[u8], transcript: &[u8]) -> bool {
    if bytes.len() > 2 * 1024 * 1024 || transcript.len() > 64 * 1024 {
        return false;
    }
    let Ok(response) =
        isomdl::cbor::from_slice::<isomdl::definitions::device_response::DeviceResponse>(bytes)
    else {
        return false;
    };
    let Some(documents) = response.documents else {
        return false;
    };
    let documents = documents.into_inner();
    if documents.len() != 1 {
        return false;
    }
    let auth = &documents[0].issuer_signed.issuer_auth;
    let chains: Vec<_> = auth
        .protected
        .header
        .rest
        .iter()
        .chain(auth.unprotected.rest.iter())
        .filter(|(label, _)| label == &Label::Int(33))
        .collect();
    if chains.len() != 1 {
        return false;
    }
    match &chains[0].1 {
        coset::cbor::value::Value::Bytes(der) => !der.is_empty() && der.len() <= 65536,
        coset::cbor::value::Value::Array(certificates) => {
            !certificates.is_empty()
                && certificates.len() <= 8
                && certificates.iter().all(|certificate| {
                    certificate
                        .as_bytes()
                        .is_some_and(|der| !der.is_empty() && der.len() <= 65536)
                })
        }
        _ => false,
    }
}

/// Inspect only the exact already-authenticated MSO. Explicit null/empty or
/// unsupported status declarations must not collapse into missing status.
pub(crate) fn declares_status(bytes: &[u8]) -> bool {
    let result = (|| {
        let response: isomdl::definitions::device_response::DeviceResponse =
            isomdl::cbor::from_slice(bytes).ok()?;
        let documents = response.documents?.into_inner();
        let payload = documents
            .first()?
            .issuer_signed
            .issuer_auth
            .payload
            .as_ref()?;
        let mso: isomdl::definitions::helpers::Tag24<coset::cbor::value::Value> =
            isomdl::cbor::from_slice(payload).ok()?;
        Some(
            mso.into_inner()
                .as_map()?
                .iter()
                .any(|(key, _)| key.as_text() == Some("status")),
        )
    })();
    result.unwrap_or(true)
}

/// Called only after the original presentation has authenticated completely.
pub(crate) async fn resolve(
    bytes: &[u8],
    transcript: &[u8],
    roots: &[String],
    pins: &[String],
    declared: bool,
    fixture: Option<&ExternalStatusFixtureTransport>,
) -> Result<
    (
        AuthenticatedMdocPresentationEvidence,
        CredentialStatusEvidence,
        Option<u64>,
    ),
    (),
> {
    let requests =
        prepare_mdoc_status_requests_at(bytes, transcript, roots, pins, OffsetDateTime::now_utc())
            .unwrap_or_default();
    let proof = AuthenticatedMdocPresentationEvidence {
        bytes: Arc::from(bytes),
        transcript: Arc::from(transcript),
        roots: Arc::from(roots),
        pins: Arc::from(pins),
        requests: Arc::new(requests),
    };
    let checked = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).map_err(|_| ())?;
    let outcome = if !declared {
        (CredentialStatusEvidence::default(), None)
    } else {
        // Keep every independently authenticated observation. A later failure
        // or timeout cannot erase an already observed, still-current denial.
        let mut observations = Vec::new();
        let completed = tokio::time::timeout(Duration::from_secs(20), async {
            let fetcher = CrlTransport {
                fixture: fixture.cloned(),
            };
            for request in proof.requests.iter() {
                let observation = async {
                    let (uri, content_type) = match request.reference() {
                        MdocStatusReference::StatusList { uri, .. } => {
                            (uri, "application/statuslist+cwt")
                        }
                        MdocStatusReference::IdentifierList { uri, .. } => {
                            (uri, "application/identifierlist+cwt")
                        }
                    };
                    let token =
                        crate::external_status::fetch_bytes(uri, &[content_type], fixture).await?;
                    let verified = verify_mdoc_external_status(
                        request,
                        &token,
                        &fetcher,
                        OffsetDateTime::now_utc,
                    )
                    .await
                    .map_err(|_| ())?;
                    Ok::<_, ()>((
                        verified.status_for(request).map_err(|_| ())?
                            == MdocExternalStatus::Revoked,
                        u64::try_from(verified.valid_until().unix_timestamp()).map_err(|_| ())?,
                        u64::try_from(verified.checked_at().unix_timestamp()).map_err(|_| ())?,
                    ))
                }
                .await
                .ok();
                observations.push(observation);
            }
        })
        .await
        .is_ok();
        let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).map_err(|_| ())?;
        summarize_status(proof.requests.len(), &observations, completed, now, checked)
    };
    // Even a failed fetch must not extend the original presentation lifetime.
    proof.revalidate_exact(OffsetDateTime::now_utc())?;
    Ok((proof, outcome.0, outcome.1))
}

fn summarize_status(
    request_count: usize,
    observations: &[Option<(bool, u64, u64)>],
    completed: bool,
    now: u64,
    checked: u64,
) -> (CredentialStatusEvidence, Option<u64>) {
    let denial = observations
        .iter()
        .flatten()
        .filter(|(denied, until, _)| *denied && *until > now)
        .max_by_key(|(_, until, _)| *until);
    if let Some((_, until, observed)) = denial {
        return (
            CredentialStatusEvidence {
                checked_at_epoch_seconds: Some(*observed),
                not_revoked: Some(false),
                credential_status: Some("REVOKED".into()),
                warnings: Vec::new(),
            },
            Some(*until),
        );
    }
    if completed
        && request_count != 0
        && observations.len() == request_count
        && observations
            .iter()
            .all(|observation| observation.is_some_and(|(denied, until, _)| !denied && until > now))
    {
        if let (Some(until), Some(observed)) = (
            observations
                .iter()
                .flatten()
                .map(|(_, until, _)| *until)
                .min(),
            observations
                .iter()
                .flatten()
                .map(|(_, _, observed)| *observed)
                .min(),
        ) {
            return (
                CredentialStatusEvidence {
                    checked_at_epoch_seconds: Some(observed),
                    not_revoked: Some(true),
                    credential_status: Some("VALID".into()),
                    warnings: Vec::new(),
                },
                Some(until),
            );
        }
    }
    (
        CredentialStatusEvidence {
            checked_at_epoch_seconds: Some(checked),
            not_revoked: None,
            credential_status: Some("UNKNOWN".into()),
            warnings: vec!["External mdoc status is unavailable or invalid".into()],
        },
        None,
    )
}

struct CrlTransport {
    fixture: Option<ExternalStatusFixtureTransport>,
}
#[async_trait]
impl RevocationFetcher for CrlTransport {
    async fn fetch_crl(&self, uri: &str) -> Result<CertificateList, CrlError> {
        let bytes = crate::external_status::fetch_bytes(
            uri,
            &[
                "application/pkix-crl",
                "application/pkcs7-crl",
                "application/x-pkcs7-crl",
                "application/octet-stream",
            ],
            self.fixture.as_ref(),
        )
        .await
        .map_err(|_| CrlError::NoDistributionPoint)?;
        CertificateList::from_der(&bytes).map_err(CrlError::Parse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::{json, Value};

    fn public_fixture() -> (Vec<u8>, Vec<u8>, String) {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/mdoc_presentation_signed_public.json"
        ))
        .unwrap();
        (
            STANDARD
                .decode(fixture["response_b64"].as_str().unwrap())
                .unwrap(),
            STANDARD
                .decode(fixture["transcript_b64"].as_str().unwrap())
                .unwrap(),
            fixture["certificate_pem"].as_str().unwrap().into(),
        )
    }

    #[test]
    fn every_declared_mechanism_must_clear_and_current_denial_survives_failures() {
        let (status, until) = summarize_status(2, &[Some((true, 100, 80)), None], false, 90, 70);
        assert_eq!(status.not_revoked, Some(false));
        assert_eq!(until, Some(100));
        let (status, until) = summarize_status(2, &[Some((true, 100, 80)), None], false, 100, 70);
        assert_eq!(status.not_revoked, None);
        assert_eq!(until, None);
        let (status, until) = summarize_status(
            2,
            &[Some((false, 110, 80)), Some((false, 100, 85))],
            true,
            90,
            70,
        );
        assert_eq!(status.not_revoked, Some(true));
        assert_eq!(until, Some(100));
        assert_eq!(status.checked_at_epoch_seconds, Some(80));
        for (observed, complete) in [
            (vec![Some((false, 100, 80)), None], true),
            (vec![Some((false, 100, 80))], false),
            (Vec::new(), true),
        ] {
            let (status, until) = summarize_status(2, &observed, complete, 90, 70);
            assert_eq!(status.not_revoked, None);
            assert_eq!(until, None);
        }
    }

    #[tokio::test]
    async fn retained_native_proof_is_not_json_promotable_or_extended_by_status_absence() {
        let (bytes, transcript, certificate) = public_fixture();
        assert!(bounded_presentation(&bytes, &transcript));
        assert!(!declares_status(&bytes));
        let (proof, status, until) = resolve(
            &bytes,
            &transcript,
            &[],
            &[certificate.clone()],
            false,
            None,
        )
        .await
        .unwrap();
        assert_eq!(status, CredentialStatusEvidence::default());
        assert_eq!(until, None);
        assert!(proof.revalidate_at(253402300798).is_err());
        let evidence = crate::CredentialVerificationEvidence {
            authenticated_mdoc_presentation: Some(proof),
            ..Default::default()
        };
        assert!(serde_json::to_value(evidence)
            .unwrap()
            .get("authenticated_mdoc_presentation")
            .is_none());
        if let Ok(evidence) = serde_json::from_value::<crate::CredentialVerificationEvidence>(
            json!({"authenticated_mdoc_presentation":{}}),
        ) {
            assert!(evidence.authenticated_mdoc_presentation.is_none());
        }
        assert!(resolve(
            &bytes,
            b"wrong transcript",
            &[],
            &[certificate],
            false,
            None
        )
        .await
        .is_err());
    }

    #[test]
    fn unsupported_status_presence_and_resource_bounds_do_not_authorize_fetching() {
        let (bytes, transcript, _) = public_fixture();
        assert!(!bounded_presentation(
            &vec![0; 2 * 1024 * 1024 + 1],
            &transcript
        ));
        assert!(!bounded_presentation(&bytes, &vec![0; 64 * 1024 + 1]));
        let mut response: isomdl::definitions::device_response::DeviceResponse =
            isomdl::cbor::from_slice(&bytes).unwrap();
        let mut documents = response.documents.take().unwrap().into_inner();
        let auth = &mut documents[0].issuer_signed.issuer_auth;
        let tagged: isomdl::definitions::helpers::Tag24<coset::cbor::value::Value> =
            isomdl::cbor::from_slice(auth.payload.as_ref().unwrap()).unwrap();
        let mut mso = tagged.into_inner();
        mso.as_map_mut().unwrap().push((
            coset::cbor::value::Value::Text("status".into()),
            coset::cbor::value::Value::Null,
        ));
        auth.payload = Some(
            isomdl::cbor::to_vec(&isomdl::definitions::helpers::Tag24::new(mso).unwrap()).unwrap(),
        );
        response.documents = Some(documents.try_into().unwrap());
        let unsigned_mutation = isomdl::cbor::to_vec(&response).unwrap();
        assert!(declares_status(&unsigned_mutation));
        // Presence detection grants no proof: this deliberately invalid issuer
        // signature must still fail before any URI can acquire authority.
        let verified = marty_verification::mdoc::verify_mdoc_presentation(
            &unsigned_mutation,
            &transcript,
            &[],
            &[],
        );
        assert!(!verified.issuer_signature_valid);
    }

    #[tokio::test]
    #[ignore = "requires owned HTTPS fixture with fresh non-exportable MSO/CWT/CRL signatures"]
    async fn live_native_mdoc_https_status_and_owner_freshness() {
        use crate::{
            CredentialStatusResolver, IssuerTrustEvidence, PresentationTrustResolver,
            ResolvedCredentialTemplate, ResolvedTrustProfile, VerifiedFactsOrchestrator,
        };
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use marty_oid4vp_contract::{
            digest_query_document, Oid4vpEvaluationTransportV1, QueryKind,
        };
        use marty_verification::credential_format::DetectedCredentialFormat;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        use uuid::Uuid;

        let input: Value = serde_json::from_slice(
            &std::fs::read(std::env::var("MDOC_HTTPS_TEST_INPUT").unwrap()).unwrap(),
        )
        .unwrap();
        let origin = input["origin"].as_str().unwrap();
        let ca = std::fs::read(std::env::var("MDOC_HTTPS_TEST_CA").unwrap()).unwrap();
        let transport = ExternalStatusFixtureTransport::new(origin, ca).unwrap();
        let transcript = STANDARD
            .decode(input["transcript_base64"].as_str().unwrap())
            .unwrap();
        let now = input["now_epoch_seconds"].as_u64().unwrap();
        let doctype = "org.iso.18013.5.1.mDL";
        struct Trust {
            profile: Value,
            clock: Arc<AtomicU64>,
            initial: u64,
            loads: AtomicUsize,
            changed: bool,
            expire: bool,
        }
        #[async_trait]
        impl PresentationTrustResolver for Trust {
            async fn load_profile(
                &self,
                id: Uuid,
                organization_id: Uuid,
            ) -> Result<ResolvedTrustProfile, PresentationVerificationError> {
                let mut document = self.profile.clone();
                if self.loads.fetch_add(1, Ordering::SeqCst) > 0 && self.changed {
                    document["status"] = json!("INACTIVE");
                }
                Ok(ResolvedTrustProfile {
                    id,
                    organization_id,
                    document,
                })
            }
            async fn evaluate_issuer(
                &self,
                profile: &ResolvedTrustProfile,
                issuer: &str,
                format: DetectedCredentialFormat,
            ) -> Result<IssuerTrustEvidence, PresentationVerificationError> {
                Ok(crate::control_plane::evaluate_issuer_document(
                    &profile.document,
                    issuer,
                    format,
                    chrono::Utc::now(),
                ))
            }
            async fn load_credential_template(
                &self,
                id: &str,
                organization_id: Uuid,
            ) -> Result<ResolvedCredentialTemplate, PresentationVerificationError> {
                if self.expire {
                    self.clock.store(self.initial + 601, Ordering::SeqCst);
                }
                Ok(ResolvedCredentialTemplate {
                    id: id.into(),
                    organization_id,
                    credential_type: "org.iso.18013.5.1.mDL".into(),
                    vct: None,
                    doctype: Some("org.iso.18013.5.1.mDL".into()),
                    status: "ACTIVE".into(),
                })
            }
        }
        struct Status(AtomicUsize);
        #[async_trait]
        impl CredentialStatusResolver for Status {
            async fn resolve(
                &self,
                _: Uuid,
                _: &str,
                _: &[String],
            ) -> Result<CredentialStatusEvidence, PresentationVerificationError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(CredentialStatusEvidence::default())
            }
        }
        // The server serves clear then revoked for each mechanism. Later bit
        // responses are clear, so governance/expiry tests cannot pass by denial.
        for (kind, expected, changed, expire) in [
            ("bit", Some(true), false, false),
            ("bit", Some(false), false, false),
            ("identifier", Some(true), false, false),
            ("identifier", Some(false), false, false),
            ("bit", None, true, false),
            ("bit", None, false, true),
        ] {
            let raw = STANDARD
                .decode(
                    input[format!("{kind}_presentation_base64")]
                        .as_str()
                        .unwrap(),
                )
                .unwrap();
            let profile = json!({"status":"ACTIVE","allowed_algorithms":["ES256"],"trust_sources":[
                {"source_type":"ROOT_CA","enabled":true,"certificate_pem":input["root_a_pem"]},
            ]});
            let token = URL_SAFE_NO_PAD.encode(raw);
            let mut policy = crate::verification_tests::policy();
            policy.credential_requirements[0].credential_payload_format = "MDOC".into();
            policy.credential_requirements[0].requested_claims[0].claim_name = "given_name".into();
            policy.credential_requirements[0].requested_claims[0]
                .constraints
                .clear();
            let id = policy.credential_requirements[0].id.to_string();
            let query = json!({"credentials":[{"id":id,"format":"mso_mdoc","meta":{"doctype_value":doctype},
                "claims":[{"path":["org.iso.18013.5.1","given_name"],"intent_to_retain":false}]}]});
            let request = crate::EvaluatePresentationRequest {
                vp_token: json!(token),
                trust_profile_id: None,
                nonce: Some("fixture-nonce".into()),
                audience: Some("https://fixture-verifier.invalid".into()),
                context: serde_json::Map::from_iter([
                    ("oid4vp_verifier_context".into(), json!(true)),
                    ("replay_check_verified".into(), json!(true)),
                    (
                        "oid4vp_client_id".into(),
                        json!("https://fixture-verifier.invalid"),
                    ),
                    (
                        "mdoc_session_transcript_b64url".into(),
                        json!(URL_SAFE_NO_PAD.encode(&transcript)),
                    ),
                ]),
                trusted_internal_context: true,
                oid4vp_transport: Some(Oid4vpEvaluationTransportV1 {
                    credential_authority: None,
                    query_kind: QueryKind::Dcql,
                    query_digest: digest_query_document(&query).unwrap(),
                    query_document: query,
                    presentation_submission: None,
                    vp_token_raw: json!({(id):[token]}).to_string(),
                    verifier_client_id: "https://fixture-verifier.invalid".into(),
                    request_nonce: "fixture-nonce".into(),
                }),
            };
            let clock = Arc::new(AtomicU64::new(now));
            let trust = Arc::new(Trust {
                profile,
                clock: clock.clone(),
                initial: now,
                loads: AtomicUsize::new(0),
                changed,
                expire,
            });
            let status = Arc::new(Status(AtomicUsize::new(0)));
            let kernel = crate::ResolvingCredentialKernel::new(Arc::new(
                marty_issuer_key_resolution::NativeIssuerKeyResolver::new(Vec::new(), Vec::new()),
            ))
            .with_external_status_fixture_transport(transport.clone());
            let orchestrator = VerifiedFactsOrchestrator::with_clock(
                Arc::new(kernel),
                trust.clone(),
                status.clone(),
                Arc::new(move || {
                    let configured = clock.load(Ordering::SeqCst);
                    if configured == now {
                        chrono::Utc::now().timestamp().max(0) as u64
                    } else {
                        configured
                    }
                }),
            )
            .unwrap();
            let result = crate::PresentationVerificationOrchestrator::verify_material(
                &orchestrator,
                &policy,
                &request,
            )
            .await;
            if let Some(expected) = expected {
                let material = result.unwrap();
                let facts = material.policy_facts();
                assert_eq!(facts["credentials"][0]["signature_verified"], true);
                assert_eq!(facts["credentials"][0]["trust_profile_verified"], true);
                assert_eq!(facts["credentials"][0]["not_revoked"], expected);
                assert_eq!(
                    status.0.load(Ordering::SeqCst),
                    1,
                    "external status must not bypass managed lookup"
                );
                assert_eq!(
                    trust.loads.load(Ordering::SeqCst),
                    2,
                    "current owner snapshot must be checked"
                );
            } else {
                assert!(
                    matches!(result,Err(PresentationVerificationError::Failed(reason))
                    if reason==if changed {"PRESENTATION_POLICY.MDOC_AUTHORITY_CHANGED"}else{"PRESENTATION_POLICY.MDOC_PROOF_EXPIRED"})
                );
            }
        }
    }
}
