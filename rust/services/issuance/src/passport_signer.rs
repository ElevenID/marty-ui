//! Remote eMRTD signer transport for the native physical-document service.
//! Production signing material remains outside this service process.

use std::{collections::BTreeMap, time::Duration};

use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SIGNER_PATH: &str = "v1/icao/emrtd/sign";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SignedMaterial {
    pub sod_der_base64: String,
    pub dsc_cert_pem: String,
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
        data_groups: &BTreeMap<u16, String>,
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
        let data_groups = BTreeMap::from([(2, "Ag==".into()), (1, "AQ==".into())]);

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
