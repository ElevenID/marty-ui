//! eMRTD signing for the native physical-document service. Production signing
//! material remains remote; local single-use keys require an explicit
//! non-default test-only build feature and runtime flag.

use std::{collections::BTreeMap, time::Duration};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use marty_crypto::certificate::{load_certificate_der, load_certificate_pem};
use marty_emrtd_issuance::{prepare_sod, SodSignatureAlgorithm};
use marty_verification::{
    trust_anchor::CscaRegistry,
    verification::emrtd::{verify_dsc_chain, ChainStatus, DocumentSignerCertificate},
};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    credential_builder::{HttpDidSigner, SignRequest},
    credential_issuer::HttpIssuerContextResolver,
};

const SIGNER_PATH: &str = "v1/icao/emrtd/sign";

use crate::passport_contract::decode_python_validated_base64;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedMaterial {
    pub sod_der_base64: String,
    pub dsc_cert_pem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csca_cert_pem: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error(
        "Configure ICAO_DOCUMENT_SIGNER_URL. Self-signed document certificates are permitted only in explicit test mode."
    )]
    NotConfigured,
    #[error("ICAO document signer URL is invalid")]
    InvalidUrl,
    #[error("ICAO document signer transport failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("ICAO document signer returned incomplete signing material")]
    IncompleteMaterial,
    #[error("Explicit self-signed passport test mode is not compiled into this service")]
    TestModeUnavailable,
    #[error("Self-signed passport test signing failed")]
    TestSigningFailed,
    #[error("A managed passport issuer DID is required")]
    MissingIssuerDid,
    #[error("Managed passport issuer signing is unavailable")]
    ManagedUnavailable,
    #[error("Managed passport issuer returned invalid signing material")]
    InvalidManagedMaterial,
    #[error("Document signer certificate is not trusted by an active organization CSCA")]
    UntrustedDsc,
}

#[derive(Clone)]
pub enum PassportSigner {
    Remote(RemoteSigner),
    Managed(Box<ManagedProfileSigner>),
    #[cfg(feature = "passport-self-signed-test")]
    SelfSignedTest,
}

impl From<RemoteSigner> for PassportSigner {
    fn from(signer: RemoteSigner) -> Self {
        Self::Remote(signer)
    }
}

impl PassportSigner {
    #[must_use]
    pub const fn mode(&self) -> &'static str {
        match self {
            Self::Remote(_) => "REMOTE",
            Self::Managed(_) => "MANAGED_ISSUER_PROFILE",
            #[cfg(feature = "passport-self-signed-test")]
            Self::SelfSignedTest => "SELF_SIGNED_TEST",
        }
    }

    pub async fn sign(
        &self,
        country_code: &str,
        organization: &str,
        data_groups: &BTreeMap<BigUint, String>,
    ) -> Result<SignedMaterial, SignerError> {
        self.sign_for_identity(country_code, organization, None, data_groups)
            .await
    }

    pub async fn sign_for_identity(
        &self,
        country_code: &str,
        organization: &str,
        issuer_did: Option<&str>,
        data_groups: &BTreeMap<BigUint, String>,
    ) -> Result<SignedMaterial, SignerError> {
        match self {
            Self::Remote(remote) => remote.sign(country_code, organization, data_groups).await,
            Self::Managed(managed) => {
                managed
                    .sign(
                        country_code,
                        organization,
                        issuer_did.ok_or(SignerError::MissingIssuerDid)?,
                        data_groups,
                    )
                    .await
            }
            #[cfg(feature = "passport-self-signed-test")]
            Self::SelfSignedTest => {
                let country_code = country_code.to_owned();
                let organization = organization.to_owned();
                let data_groups = data_groups.clone();
                tokio::task::spawn_blocking(move || {
                    self_signed_test_sign(&country_code, &organization, &data_groups)
                })
                .await
                .map_err(|_| SignerError::TestSigningFailed)?
            }
        }
    }
}

#[cfg(feature = "passport-self-signed-test")]
fn self_signed_test_sign(
    country_code: &str,
    organization: &str,
    data_groups: &BTreeMap<BigUint, String>,
) -> Result<SignedMaterial, SignerError> {
    use marty_verification::issuance::CscaAuthority;

    let decoded_groups = data_groups
        .iter()
        .map(|(number, content)| {
            let number = number.to_u8().ok_or(SignerError::TestSigningFailed)?;
            let content = decode_python_validated_base64(content)
                .map_err(|_| SignerError::TestSigningFailed)?;
            Ok((number, content))
        })
        .collect::<Result<Vec<_>, SignerError>>()?;
    let csca = CscaAuthority::new(country_code, organization, 3650)
        .map_err(|_| SignerError::TestSigningFailed)?;
    let dsc = csca
        .issue_dsc(organization, 730)
        .map_err(|_| SignerError::TestSigningFailed)?;
    let mut personalizer = dsc.personalizer();
    for (number, content) in decoded_groups {
        personalizer = personalizer.set_data_group(number, content);
    }
    let passport = personalizer
        .build()
        .map_err(|_| SignerError::TestSigningFailed)?;
    Ok(SignedMaterial {
        sod_der_base64: STANDARD.encode(passport.sod_der),
        dsc_cert_pem: dsc.cert_pem().map_err(|_| SignerError::TestSigningFailed)?,
        csca_cert_pem: Some(
            csca.cert_pem()
                .map_err(|_| SignerError::TestSigningFailed)?,
        ),
    })
}

/// Uses the same DID-mediated signing client as other credentials. Only a
/// public issuer selector and certificate chain cross this boundary; the DSC
/// signing key remains inside the configured KMS.
#[derive(Clone)]
pub struct ManagedProfileSigner {
    resolver: HttpIssuerContextResolver,
    signer: HttpDidSigner,
    trust: CscaTrustAnchorClient,
}

#[derive(Clone)]
struct CscaTrustAnchorClient {
    client: Client,
    endpoint: Url,
    api_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveCscaTrustAnchor {
    certificate_id: String,
    certificate_data: String,
    status: String,
}

impl CscaTrustAnchorClient {
    fn new(mut base_url: Url, api_key: Option<&str>) -> Result<Self, SignerError> {
        let path = format!(
            "{}/csca-trust-anchors",
            base_url.path().trim_end_matches('/')
        );
        base_url.set_path(&path);
        base_url.set_query(None);
        base_url.set_fragment(None);
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| SignerError::ManagedUnavailable)?,
            endpoint: base_url,
            api_key: api_key.map(str::to_owned),
        })
    }

    async fn active(
        &self,
        organization_id: &str,
    ) -> Result<Vec<ActiveCscaTrustAnchor>, SignerError> {
        let mut request = self
            .client
            .get(self.endpoint.clone())
            .query(&[("organization_id", organization_id)]);
        if let Some(api_key) = self.api_key.as_deref() {
            request = request.header("X-API-Key", api_key);
        }
        let response = request
            .send()
            .await
            .map_err(|_| SignerError::ManagedUnavailable)?
            .error_for_status()
            .map_err(|_| SignerError::ManagedUnavailable)?;
        response
            .json::<Vec<ActiveCscaTrustAnchor>>()
            .await
            .map_err(|_| SignerError::InvalidManagedMaterial)
    }
}

impl ManagedProfileSigner {
    pub fn new(base_url: Url, api_key: Option<&str>) -> Result<Self, SignerError> {
        Ok(Self {
            resolver: HttpIssuerContextResolver::new(
                base_url.clone(),
                api_key,
                Duration::from_secs(15),
            )
            .map_err(|_| SignerError::ManagedUnavailable)?,
            signer: HttpDidSigner::new(base_url.clone(), api_key, Duration::from_secs(30))
                .map_err(|_| SignerError::ManagedUnavailable)?,
            trust: CscaTrustAnchorClient::new(base_url, api_key)?,
        })
    }

    pub async fn sign(
        &self,
        country_code: &str,
        organization_id: &str,
        issuer_did: &str,
        data_groups: &BTreeMap<BigUint, String>,
    ) -> Result<SignedMaterial, SignerError> {
        let identity = self
            .resolver
            .resolve_raw(
                organization_id,
                issuer_did,
                None,
                "ICAO_EMRTD",
                "x509_doc_signer",
                "",
            )
            .await
            .map_err(|_| SignerError::ManagedUnavailable)?;
        if identity.get("organization_id").and_then(Value::as_str) != Some(organization_id)
            || identity.get("issuer_did").and_then(Value::as_str) != Some(issuer_did)
            || identity
                .pointer("/issuer_profile/credential_format")
                .and_then(Value::as_str)
                != Some("ICAO_EMRTD")
            || identity.get("key_purpose").and_then(Value::as_str) != Some("x509_doc_signer")
        {
            return Err(SignerError::InvalidManagedMaterial);
        }
        let algorithm = identity
            .get("algorithm")
            .and_then(Value::as_str)
            .and_then(|value| SodSignatureAlgorithm::try_from(value).ok())
            .ok_or(SignerError::InvalidManagedMaterial)?;
        let method_id = identity
            .get("verification_method_id")
            .and_then(Value::as_str)
            .filter(|value| value.starts_with(&format!("{issuer_did}#")))
            .ok_or(SignerError::InvalidManagedMaterial)?;
        let chain = identity
            .get("issuer_x5c")
            .and_then(Value::as_array)
            .filter(|chain| !chain.is_empty())
            .ok_or(SignerError::InvalidManagedMaterial)?;
        let leaf = chain[0]
            .as_str()
            .ok_or(SignerError::InvalidManagedMaterial)?;
        let certificate_der = STANDARD
            .decode(leaf)
            .map_err(|_| SignerError::InvalidManagedMaterial)?;
        let trusted_csca = trusted_csca_for_dsc(
            &certificate_der,
            country_code,
            chain.get(1).and_then(Value::as_str),
            &self.trust.active(organization_id).await?,
        )?;
        let groups = data_groups
            .iter()
            .map(|(number, content)| {
                let number = number.to_u8().ok_or(SignerError::InvalidManagedMaterial)?;
                let content = decode_python_validated_base64(content)
                    .map_err(|_| SignerError::InvalidManagedMaterial)?;
                Ok((number, content))
            })
            .collect::<Result<Vec<_>, SignerError>>()?;
        let prepared = prepare_sod(&groups, &certificate_der, algorithm)
            .map_err(|_| SignerError::InvalidManagedMaterial)?;
        let signature = self
            .signer
            .sign_did(SignRequest {
                organization_id: organization_id.into(),
                issuer_did: issuer_did.into(),
                credential_format: "ICAO_EMRTD".into(),
                key_purpose: "x509_doc_signer".into(),
                payload: prepared.signing_input().to_vec(),
                algorithm: algorithm.as_str().into(),
                verification_method_id: method_id.into(),
            })
            .await
            .map_err(|_| SignerError::ManagedUnavailable)?;
        // CMS requires the provider-native signature: ASN.1 DER for ECDSA,
        // not the JOSE/P1363 signature used by VC and JWT consumers.
        let signature = signature
            .signature_native_b64
            .ok_or(SignerError::InvalidManagedMaterial)?;
        let signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| SignerError::InvalidManagedMaterial)?;
        let signature = cms_signature(&signature, algorithm)?;
        let sod = prepared
            .assemble(&signature)
            .map_err(|_| SignerError::InvalidManagedMaterial)?;
        Ok(SignedMaterial {
            sod_der_base64: STANDARD.encode(sod),
            dsc_cert_pem: pem_certificate(leaf),
            csca_cert_pem: Some(trusted_csca),
        })
    }
}

fn trusted_csca_for_dsc(
    dsc_der: &[u8],
    country_code: &str,
    supplied_csca: Option<&str>,
    anchors: &[ActiveCscaTrustAnchor],
) -> Result<String, SignerError> {
    let certificate =
        load_certificate_der(dsc_der).map_err(|_| SignerError::InvalidManagedMaterial)?;
    let dsc = DocumentSignerCertificate {
        serial_number: certificate.tbs_certificate.serial_number.to_string(),
        certificate,
        country: Some(country_code.to_owned()),
    };
    let supplied_csca = supplied_csca
        .map(|encoded| STANDARD.decode(encoded))
        .transpose()
        .map_err(|_| SignerError::InvalidManagedMaterial)?;
    for anchor in anchors {
        if anchor.status != "VALID" || anchor.certificate_id.trim().is_empty() {
            return Err(SignerError::InvalidManagedMaterial);
        }
        let der = load_certificate_pem(&anchor.certificate_data)
            .map_err(|_| SignerError::InvalidManagedMaterial)?;
        if supplied_csca
            .as_ref()
            .is_some_and(|supplied| supplied != &der)
        {
            continue;
        }
        let mut registry = CscaRegistry::new();
        registry
            .add_country_csca(
                country_code,
                load_certificate_der(&der).map_err(|_| SignerError::InvalidManagedMaterial)?,
            )
            .map_err(|_| SignerError::InvalidManagedMaterial)?;
        if matches!(verify_dsc_chain(&dsc, &registry), Ok(ChainStatus::Valid)) {
            return Ok(anchor.certificate_data.clone());
        }
    }
    Err(SignerError::UntrustedDsc)
}

fn pem_certificate(encoded: &str) -> String {
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for (index, character) in encoded.chars().enumerate() {
        if index > 0 && index % 64 == 0 {
            pem.push('\n');
        }
        pem.push(character);
    }
    pem.push_str("\n-----END CERTIFICATE-----\n");
    pem
}

fn cms_signature(
    signature: &[u8],
    algorithm: SodSignatureAlgorithm,
) -> Result<Vec<u8>, SignerError> {
    match algorithm {
        SodSignatureAlgorithm::Es256 => p256::ecdsa::Signature::from_der(signature)
            .or_else(|_| p256::ecdsa::Signature::from_slice(signature))
            .map(|signature| signature.to_der().as_bytes().to_vec())
            .map_err(|_| SignerError::InvalidManagedMaterial),
        SodSignatureAlgorithm::Es384 => p384::ecdsa::Signature::from_der(signature)
            .or_else(|_| p384::ecdsa::Signature::from_slice(signature))
            .map(|signature| signature.to_der().as_bytes().to_vec())
            .map_err(|_| SignerError::InvalidManagedMaterial),
        SodSignatureAlgorithm::Rs256 | SodSignatureAlgorithm::Ed25519 => Ok(signature.to_vec()),
    }
}

#[derive(Clone)]
pub struct RemoteSigner {
    endpoint: Url,
    api_key: String,
    http: Client,
}

impl RemoteSigner {
    pub fn new(base_url: &str, api_key: &str) -> Result<Self, SignerError> {
        if base_url.trim().is_empty() {
            return Err(SignerError::NotConfigured);
        }
        let base_url = Url::parse(&format!("{}/", base_url.trim_end_matches('/')))
            .map_err(|_| SignerError::InvalidUrl)?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(SignerError::InvalidUrl);
        }
        Ok(Self {
            endpoint: base_url
                .join(SIGNER_PATH)
                .map_err(|_| SignerError::InvalidUrl)?,
            api_key: api_key.to_owned(),
            http: Client::new(),
        })
    }

    pub async fn sign(
        &self,
        country_code: &str,
        organization: &str,
        data_groups: &BTreeMap<BigUint, String>,
    ) -> Result<SignedMaterial, SignerError> {
        let data_groups: BTreeMap<_, _> = data_groups
            .iter()
            .map(|(number, content)| (format!("DG{number}"), content))
            .collect();
        let response = self
            .http
            .post(self.endpoint.clone())
            .bearer_auth(&self.api_key)
            .json(&json!({
                "country_code": country_code,
                "organization": organization,
                "data_groups": data_groups,
            }))
            .timeout(Duration::from_secs(30))
            .send()
            .await?
            .error_for_status()?;
        let body: Value = response.json().await?;
        let required = |field| {
            body.get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or(SignerError::IncompleteMaterial)
        };
        Ok(SignedMaterial {
            sod_der_base64: required("sod_der_base64")?,
            dsc_cert_pem: required("dsc_cert_pem")?,
            csca_cert_pem: body
                .get("csca_cert_pem")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
    };

    use axum::{
        extract::{Query, State},
        http::{HeaderMap, StatusCode},
        routing::{get, post},
        Json, Router,
    };
    use p256::{
        ecdsa::{signature::Signer, Signature, SigningKey},
        pkcs8::DecodePrivateKey,
    };
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        PKCS_ECDSA_P256_SHA256,
    };
    use serde_json::{json, Value};

    use super::*;

    fn synthetic_dsc_chain() -> (String, String, String, SigningKey) {
        let mut csca = CertificateParams::default();
        csca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        csca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        csca.distinguished_name
            .push(DnType::CommonName, "Synthetic CSCA");
        csca.distinguished_name.push(DnType::CountryName, "US");
        let csca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let csca_certificate = csca.self_signed(&csca_key).unwrap();
        let issuer = Issuer::from_params(&csca, &csca_key);

        let mut dsc = CertificateParams::default();
        dsc.is_ca = IsCa::ExplicitNoCa;
        dsc.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        dsc.distinguished_name
            .push(DnType::CommonName, "Synthetic Passport DSC");
        dsc.distinguished_name.push(DnType::CountryName, "US");
        let dsc_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let dsc_certificate = dsc.signed_by(&dsc_key, &issuer).unwrap();
        let csca_b64 = STANDARD.encode(csca_certificate.der());
        (
            STANDARD.encode(dsc_certificate.der()),
            csca_b64.clone(),
            pem_certificate(&csca_b64),
            SigningKey::from_pkcs8_der(dsc_key.serialized_der()).unwrap(),
        )
    }

    #[test]
    fn cms_normalizes_jose_ecdsa_signatures_without_accepting_malformed_bytes() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let signer = SigningKey::from_pkcs8_der(key.serialized_der()).unwrap();
        let signature: Signature = signer.sign(b"synthetic CMS attributes");
        let der = signature.to_der();
        assert_eq!(
            cms_signature(&signature.to_bytes(), SodSignatureAlgorithm::Es256).unwrap(),
            der.as_bytes()
        );
        assert_eq!(
            cms_signature(der.as_bytes(), SodSignatureAlgorithm::Es256).unwrap(),
            der.as_bytes()
        );
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let signer = p384::ecdsa::SigningKey::from_pkcs8_der(key.serialized_der()).unwrap();
        let signature: p384::ecdsa::Signature = signer.sign(b"synthetic CMS attributes");
        assert_eq!(
            cms_signature(&signature.to_bytes(), SodSignatureAlgorithm::Es384).unwrap(),
            signature.to_der().as_bytes()
        );
        assert!(matches!(
            cms_signature(&[1, 2, 3], SodSignatureAlgorithm::Es256),
            Err(SignerError::InvalidManagedMaterial)
        ));
    }

    #[test]
    fn managed_dsc_requires_a_matching_active_csca_and_chain() {
        let (dsc_b64, csca_b64, csca_pem, _) = synthetic_dsc_chain();
        let dsc = STANDARD.decode(dsc_b64).unwrap();
        let active = ActiveCscaTrustAnchor {
            certificate_id: "csca-1".into(),
            certificate_data: csca_pem.clone(),
            status: "VALID".into(),
        };
        assert_eq!(
            trusted_csca_for_dsc(&dsc, "USA", Some(&csca_b64), &[active]).unwrap(),
            csca_pem
        );
        assert!(matches!(
            trusted_csca_for_dsc(&dsc, "USA", None, &[]),
            Err(SignerError::UntrustedDsc)
        ));
        let revoked = ActiveCscaTrustAnchor {
            certificate_id: "csca-1".into(),
            certificate_data: csca_pem.clone(),
            status: "REVOKED".into(),
        };
        assert!(matches!(
            trusted_csca_for_dsc(&dsc, "USA", None, &[revoked]),
            Err(SignerError::InvalidManagedMaterial)
        ));
        assert!(matches!(
            trusted_csca_for_dsc(
                &dsc,
                "USA",
                Some(&STANDARD.encode([0, 1, 2])),
                &[ActiveCscaTrustAnchor {
                    certificate_id: "csca-1".into(),
                    certificate_data: csca_pem,
                    status: "VALID".into(),
                }]
            ),
            Err(SignerError::UntrustedDsc)
        ));
    }

    #[tokio::test]
    async fn managed_signer_uses_profile_dsc_and_provider_native_signature() {
        #[derive(Clone)]
        struct ManagedMock {
            dsc_b64: String,
            csca_b64: String,
            csca_pem: String,
            signer: SigningKey,
            requests: Arc<Mutex<Vec<Value>>>,
            trust_available: Arc<AtomicBool>,
        }
        async fn resolve(State(state): State<ManagedMock>, headers: HeaderMap) -> Json<Value> {
            assert_eq!(headers["x-api-key"], "existing-internal-auth");
            Json(json!({
                "ok": true,
                "organization_id": "org-1",
                "issuer_did": "did:web:issuer.example:orgs:org-1",
                "key_purpose": "x509_doc_signer",
                "algorithm": "ES256",
                "verification_method_id": "did:web:issuer.example:orgs:org-1#dsc",
                "issuer_profile": {"credential_format": "ICAO_EMRTD"},
                "issuer_x5c": [state.dsc_b64, state.csca_b64]
            }))
        }
        async fn trust(
            State(state): State<ManagedMock>,
            Query(query): Query<HashMap<String, String>>,
            headers: HeaderMap,
        ) -> Json<Value> {
            assert_eq!(headers["x-api-key"], "existing-internal-auth");
            assert_eq!(
                query.get("organization_id").map(String::as_str),
                Some("org-1")
            );
            if !state.trust_available.load(Ordering::SeqCst) {
                return Json(json!([]));
            }
            Json(
                json!([{"certificate_id": "csca-1", "certificate_data": state.csca_pem, "status": "VALID"}]),
            )
        }
        async fn sign(
            State(state): State<ManagedMock>,
            headers: HeaderMap,
            Json(request): Json<Value>,
        ) -> Json<Value> {
            assert_eq!(headers["x-api-key"], "existing-internal-auth");
            state.requests.lock().unwrap().push(request.clone());
            let input = URL_SAFE_NO_PAD
                .decode(request["payload_b64"].as_str().unwrap())
                .unwrap();
            let signature: Signature = state.signer.sign(&input);
            Json(json!({
                "ok": true,
                "issuer_did": request["issuer_did"],
                "algorithm": request["algorithm"],
                "verification_method_id": "did:web:issuer.example:orgs:org-1#dsc",
                "signature_b64": URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes()),
                // The VC/JOSE variant is deliberately wrong: CMS must choose
                // the separate provider-native DER response above.
                "signature_raw_b64": URL_SAFE_NO_PAD.encode([0_u8; 64])
            }))
        }
        let (dsc_b64, csca_b64, csca_pem, signer) = synthetic_dsc_chain();
        let state = ManagedMock {
            dsc_b64,
            csca_b64,
            csca_pem,
            signer,
            requests: Arc::new(Mutex::new(Vec::new())),
            trust_available: Arc::new(AtomicBool::new(true)),
        };
        let app = Router::new()
            .route("/internal/signing-keys/resolve-issuer-did", get(resolve))
            .route("/internal/signing-keys/csca-trust-anchors", get(trust))
            .route("/internal/signing-keys/issuer-dids/sign", post(sign))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let signer = ManagedProfileSigner::new(
            Url::parse(&format!("http://{address}/internal/signing-keys/")).unwrap(),
            Some("existing-internal-auth"),
        )
        .unwrap();
        let groups = BTreeMap::from([
            (BigUint::from(1u8), "AQ==".into()),
            (BigUint::from(2u8), "Ag==".into()),
        ]);
        let signed = signer
            .sign("USA", "org-1", "did:web:issuer.example:orgs:org-1", &groups)
            .await
            .unwrap();
        let sod = STANDARD.decode(&signed.sod_der_base64).unwrap();
        assert!(marty_verification::asn1::sod::verify_sod_signature(&sod).unwrap());
        assert_eq!(
            load_certificate_pem(&signed.dsc_cert_pem).unwrap(),
            STANDARD.decode(&state.dsc_b64).unwrap()
        );
        assert_eq!(
            signed.csca_cert_pem.as_deref(),
            Some(state.csca_pem.as_str())
        );
        {
            let requests = state.requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(
                requests[0]["issuer_did"],
                "did:web:issuer.example:orgs:org-1"
            );
            assert_eq!(requests[0]["key_purpose"], "x509_doc_signer");
            assert_eq!(requests[0]["credential_format"], "ICAO_EMRTD");
        }
        state.trust_available.store(false, Ordering::SeqCst);
        assert!(matches!(
            signer
                .sign("USA", "org-1", "did:web:issuer.example:orgs:org-1", &groups)
                .await,
            Err(SignerError::UntrustedDsc)
        ));
        assert_eq!(state.requests.lock().unwrap().len(), 1);
        server.abort();
    }

    #[tokio::test]
    async fn managed_signer_rejects_an_identity_without_its_dsc_before_kms_signing() {
        async fn resolve(headers: HeaderMap) -> Json<Value> {
            assert_eq!(headers["x-api-key"], "existing-internal-auth");
            Json(json!({
                "ok": true,
                "organization_id": "org-1",
                "issuer_did": "did:web:issuer.example:orgs:org-1",
                "key_purpose": "x509_doc_signer",
                "algorithm": "ES256",
                "verification_method_id": "did:web:issuer.example:orgs:org-1#dsc",
                "issuer_profile": {"credential_format": "ICAO_EMRTD"},
                "issuer_x5c": []
            }))
        }
        let app = Router::new().route("/internal/signing-keys/resolve-issuer-did", get(resolve));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let signer = ManagedProfileSigner::new(
            Url::parse(&format!("http://{address}/internal/signing-keys/")).unwrap(),
            Some("existing-internal-auth"),
        )
        .unwrap();
        let groups = BTreeMap::from([(BigUint::from(1u8), "AQ==".into())]);
        assert!(matches!(
            signer
                .sign("USA", "org-1", "did:web:issuer.example:orgs:org-1", &groups)
                .await,
            Err(SignerError::InvalidManagedMaterial)
        ));
        server.abort();
    }

    #[tokio::test]
    async fn managed_signer_rejects_a_cross_tenant_or_wrong_format_identity_before_signing() {
        async fn resolve(State(identity): State<Value>) -> Json<Value> {
            Json(identity)
        }
        let valid = json!({
            "ok": true,
            "organization_id": "org-1",
            "issuer_did": "did:web:issuer.example:orgs:org-1",
            "key_purpose": "x509_doc_signer",
            "algorithm": "ES256",
            "verification_method_id": "did:web:issuer.example:orgs:org-1#dsc",
            "issuer_profile": {"credential_format": "ICAO_EMRTD"},
            "issuer_x5c": ["not-reached"]
        });
        for (pointer, replacement) in [
            ("/organization_id", json!("org-2")),
            ("/issuer_did", json!("did:web:issuer.example:orgs:org-2")),
            ("/key_purpose", json!("vc_jwt_issuer")),
            ("/issuer_profile/credential_format", json!("JWT_VC")),
            (
                "/verification_method_id",
                json!("did:web:other.example#dsc"),
            ),
        ] {
            let mut identity = valid.clone();
            *identity.pointer_mut(pointer).unwrap() = replacement;
            let app = Router::new()
                .route("/internal/signing-keys/resolve-issuer-did", get(resolve))
                .with_state(identity);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let signer = ManagedProfileSigner::new(
                Url::parse(&format!("http://{address}/internal/signing-keys/")).unwrap(),
                None,
            )
            .unwrap();
            let groups = BTreeMap::from([(BigUint::from(1u8), "AQ==".into())]);
            assert!(matches!(
                signer
                    .sign("USA", "org-1", "did:web:issuer.example:orgs:org-1", &groups)
                    .await,
                Err(SignerError::InvalidManagedMaterial)
            ));
            server.abort();
        }
    }

    #[cfg(feature = "passport-self-signed-test")]
    #[tokio::test]
    async fn explicit_self_signed_test_mode_issues_ephemeral_sod_and_dsc() {
        let signer = PassportSigner::SelfSignedTest;
        assert_eq!(signer.mode(), "SELF_SIGNED_TEST");
        let groups = BTreeMap::from([
            (BigUint::from(1u8), "YQ==".to_owned()),
            (BigUint::from(2u8), "Yg==".to_owned()),
        ]);
        let signed = signer
            .sign("UTO", "synthetic-test-issuer", &groups)
            .await
            .unwrap();
        assert!(
            !crate::passport_contract::decode_python_validated_base64(&signed.sod_der_base64)
                .unwrap()
                .is_empty()
        );
        assert!(signed.dsc_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(signed
            .csca_cert_pem
            .as_deref()
            .unwrap()
            .contains("BEGIN CERTIFICATE"));
        let invalid = BTreeMap::from([(BigUint::from(256u16), "YQ==".to_owned())]);
        assert!(matches!(
            signer.sign("UTO", "synthetic-test-issuer", &invalid).await,
            Err(SignerError::TestSigningFailed)
        ));
    }

    #[test]
    fn remote_signer_rejects_missing_or_unsafe_endpoint() {
        let reference: Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-physical-passport-native.json"
        ))
        .unwrap();
        assert_eq!(
            reference["remote_signer"]["path"],
            format!("/{SIGNER_PATH}")
        );
        assert_eq!(reference["remote_signer"]["timeout_seconds"], 30);
        assert_eq!(
            reference["remote_signer"]["incomplete_error"],
            SignerError::IncompleteMaterial.to_string()
        );
        assert!(matches!(
            RemoteSigner::new("", "key"),
            Err(SignerError::NotConfigured)
        ));
        assert!(matches!(
            RemoteSigner::new("file:///tmp/signer", "key"),
            Err(SignerError::InvalidUrl)
        ));
        for url in [
            "https://user:password@signer.example.test",
            "https://signer.example.test?token=secret",
            "https://signer.example.test#fragment",
        ] {
            assert!(matches!(
                RemoteSigner::new(url, "key"),
                Err(SignerError::InvalidUrl)
            ));
        }
    }

    #[tokio::test]
    async fn signer_http_preserves_payload_auth_and_incomplete_error() {
        type Observed = Arc<Mutex<Vec<(String, Value)>>>;
        async fn sign(
            State(observed): State<Observed>,
            headers: HeaderMap,
            Json(payload): Json<Value>,
        ) -> (StatusCode, Json<Value>) {
            observed.lock().unwrap().push((
                headers["authorization"].to_str().unwrap().into(),
                payload.clone(),
            ));
            if payload["organization"] == "incomplete" {
                return (StatusCode::OK, Json(json!({"sod_der_base64": "U09E"})));
            }
            if payload["organization"] == "unavailable" {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "private"})),
                );
            }
            (
                StatusCode::OK,
                Json(json!({"sod_der_base64":"U09E","dsc_cert_pem":"synthetic-cert"})),
            )
        }
        let observed: Observed = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/v1/icao/emrtd/sign", post(sign))
            .with_state(observed.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let signer = RemoteSigner::new(&format!("http://{address}"), "signer-key").unwrap();
        let data_groups = BTreeMap::from([
            (BigUint::from(2u8), "Ag==".into()),
            (BigUint::from(1u8), "AQ==".into()),
        ]);

        let signed = signer.sign("UTO", "org-1", &data_groups).await.unwrap();
        assert_eq!(signed.sod_der_base64, "U09E");
        assert_eq!(signed.dsc_cert_pem, "synthetic-cert");
        {
            let requests = observed.lock().unwrap();
            assert_eq!(requests[0].0, "Bearer signer-key");
            assert_eq!(
                requests[0].1,
                json!({
                    "country_code": "UTO",
                    "organization": "org-1",
                    "data_groups": {"DG1":"AQ==","DG2":"Ag=="}
                })
            );
        }
        let reference: Value = serde_json::from_str(include_str!(
            "../../../../contracts/issuance-physical-passport-native.json"
        ))
        .unwrap();
        let wide = &reference["wide_data_group_number_observation"];
        let large_number =
            BigUint::parse_bytes(wide["normalized_number"].as_str().unwrap().as_bytes(), 10)
                .unwrap();
        let mut wide_groups = data_groups.clone();
        wide_groups.insert(large_number, "Aw==".into());
        signer.sign("UTO", "org-1", &wide_groups).await.unwrap();
        {
            let requests = observed.lock().unwrap();
            assert_eq!(
                requests.last().unwrap().1["data_groups"][wide["input_name"].as_str().unwrap()],
                "Aw=="
            );
        }
        assert!(matches!(
            signer.sign("UTO", "incomplete", &data_groups).await,
            Err(SignerError::IncompleteMaterial)
        ));
        assert!(matches!(
            signer.sign("UTO", "unavailable", &data_groups).await,
            Err(SignerError::Transport(_))
        ));
        server.abort();
    }
}
