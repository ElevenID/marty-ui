//! eMRTD signing for the native physical-document service. Production signing
//! material remains remote; local single-use keys require an explicit
//! non-default test-only build feature and runtime flag.

use std::{collections::BTreeMap, time::Duration};

#[cfg(feature = "passport-self-signed-test")]
use base64::{engine::general_purpose::STANDARD, Engine as _};
use num_bigint::BigUint;
#[cfg(feature = "passport-self-signed-test")]
use num_traits::ToPrimitive;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SIGNER_PATH: &str = "v1/icao/emrtd/sign";

#[cfg(feature = "passport-self-signed-test")]
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
}

#[derive(Clone)]
pub enum PassportSigner {
    Remote(RemoteSigner),
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
        match self {
            Self::Remote(remote) => remote.sign(country_code, organization, data_groups).await,
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
    use std::sync::{Arc, Mutex};

    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
        Json, Router,
    };
    use serde_json::{json, Value};

    use super::*;

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
