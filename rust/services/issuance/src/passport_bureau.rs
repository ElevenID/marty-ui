//! Personalization bureau transport for the native physical-document service.
//! The Python reference is pinned by Credentials PR #296. Unlike that reference,
//! the document type is forwarded from the durable job instead of forced to TD3.

use std::{collections::BTreeMap, time::Duration};

use hmac::{Hmac, Mac};
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductionStatus {
    Queued,
    Printing,
    Encoding,
    QualityCheck,
    Shipped,
    Delivered,
    Failed,
    Cancelled,
}

impl ProductionStatus {
    #[must_use]
    pub const fn issuance_status(self) -> &'static str {
        match self {
            Self::Queued => "SUBMITTED",
            Self::Printing | Self::Encoding => "IN_PRODUCTION",
            Self::QualityCheck => "QUALITY_CHECK",
            Self::Shipped | Self::Delivered => "READY_FOR_ACTIVATION",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DocumentType {
    TD1,
    TD2,
    TD3,
}

#[derive(Clone, Debug)]
pub struct PersonalizationJob {
    pub id: String,
    pub application_id: String,
    pub organization_id: String,
    pub country_code: String,
    pub document_type: DocumentType,
    pub data_groups: BTreeMap<u16, String>,
    pub sod_der_base64: String,
    pub dsc_cert_pem: String,
    pub mrz_line_1: String,
    pub mrz_line_2: String,
}

impl PersonalizationJob {
    fn payload(&self) -> Value {
        let data_groups: BTreeMap<_, _> = self
            .data_groups
            .iter()
            .map(|(number, content)| (format!("DG{number}"), content))
            .collect();
        json!({
            "job_id": self.id,
            "application_id": self.application_id,
            "organization_id": self.organization_id,
            "country_code": self.country_code,
            "document_type": self.document_type,
            "data_groups": data_groups,
            "sod_der_base64": self.sod_der_base64,
            "dsc_cert_pem": self.dsc_cert_pem,
            "mrz": {"line_1": self.mrz_line_1, "line_2": self.mrz_line_2},
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionOutcome {
    pub bureau_job_id: Option<String>,
    pub status: ProductionStatus,
    pub tracking_number: Option<String>,
    pub error_message: Option<String>,
}

impl SubmissionOutcome {
    fn accepted(body: &Value) -> Result<Self, BureauError> {
        let status = match body.get("status").and_then(Value::as_str) {
            Some(status) => serde_json::from_value(Value::String(status.to_owned()))
                .map_err(|_| BureauError::InvalidResponse("unknown production status".into()))?,
            None => ProductionStatus::Queued,
        };
        Ok(Self {
            bureau_job_id: body
                .get("bureau_job_id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .or_else(|| body.get("job_id").and_then(Value::as_str))
                .map(str::to_owned),
            status,
            tracking_number: body
                .get("tracking_number")
                .and_then(Value::as_str)
                .map(str::to_owned),
            error_message: None,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct PollOutcome {
    pub status: ProductionStatus,
    pub tracking_number: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
struct WebhookEvent {
    bureau_job_id: String,
    status: ProductionStatus,
    #[serde(flatten)]
    metadata: BTreeMap<String, Value>,
}

/// Only `BureauClient::parse_webhook` can construct this after HMAC validation.
#[derive(Clone, Debug)]
pub struct VerifiedWebhookEvent(WebhookEvent);

impl VerifiedWebhookEvent {
    #[must_use]
    pub fn bureau_job_id(&self) -> &str {
        &self.0.bureau_job_id
    }

    #[must_use]
    pub fn status(&self) -> ProductionStatus {
        self.0.status
    }

    #[must_use]
    pub fn tracking_number(&self) -> Option<&str> {
        self.0
            .metadata
            .get("tracking_number")
            .and_then(Value::as_str)
    }

    #[must_use]
    pub fn error_message(&self) -> Option<&str> {
        self.0.metadata.get("error_message").and_then(Value::as_str)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BureauError {
    #[error(
        "Personalization bureau not configured. Set PERSONALIZATION_BUREAU_URL environment variable."
    )]
    NotConfigured,
    #[error("Personalization bureau URL is invalid")]
    InvalidUrl,
    #[error("Personalization bureau transport failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("Personalization bureau returned invalid response: {0}")]
    InvalidResponse(String),
    #[error("Invalid personalization webhook signature")]
    InvalidWebhookSignature,
    #[error("Invalid personalization webhook event")]
    InvalidWebhookEvent,
}

#[derive(Clone)]
pub struct BureauClient {
    base_url: Url,
    api_key: String,
    webhook_secret: Option<Vec<u8>>,
    http: Client,
}

impl BureauClient {
    pub fn new(
        base_url: &str,
        api_key: &str,
        webhook_secret: Option<&str>,
    ) -> Result<Self, BureauError> {
        if base_url.is_empty() {
            return Err(BureauError::NotConfigured);
        }
        let base_url = Url::parse(&format!("{}/", base_url.trim_end_matches('/')))
            .map_err(|_| BureauError::InvalidUrl)?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(BureauError::InvalidUrl);
        }
        Ok(Self {
            base_url,
            api_key: api_key.to_owned(),
            webhook_secret: webhook_secret
                .filter(|secret| !secret.is_empty())
                .map(str::as_bytes)
                .map(<[u8]>::to_vec),
            http: Client::new(),
        })
    }

    fn endpoint(&self, path: &str) -> Result<Url, BureauError> {
        self.base_url
            .join(path)
            .map_err(|_| BureauError::InvalidUrl)
    }

    pub async fn submit(&self, job: &PersonalizationJob) -> Result<SubmissionOutcome, BureauError> {
        let response = self
            .http
            .post(self.endpoint("v1/personalization/jobs")?)
            .bearer_auth(&self.api_key)
            .json(&job.payload())
            .timeout(Duration::from_secs(30))
            .send()
            .await?;
        let status = response.status();
        if !matches!(
            status,
            StatusCode::OK | StatusCode::CREATED | StatusCode::ACCEPTED
        ) {
            return Ok(SubmissionOutcome {
                bureau_job_id: None,
                status: ProductionStatus::Failed,
                tracking_number: None,
                error_message: Some(format!("Bureau returned HTTP {}", status.as_u16())),
            });
        }
        let body: Value = response.json().await?;
        SubmissionOutcome::accepted(&body)
    }

    pub async fn poll(&self, bureau_job_id: &str) -> Result<PollOutcome, BureauError> {
        let mut url = self.endpoint("v1/personalization/jobs")?;
        url.path_segments_mut()
            .map_err(|_| BureauError::InvalidUrl)?
            .push(bureau_job_id);
        Ok(self
            .http
            .get(url)
            .bearer_auth(&self.api_key)
            .timeout(Duration::from_secs(15))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }

    #[must_use]
    pub fn verify_webhook(&self, body: &[u8], signature: &str) -> bool {
        let Some(secret) = &self.webhook_secret else {
            return false;
        };
        // The released webhook accepts the lowercase hexdigest, not alternate
        // encodings of the same MAC.
        if signature.len() != 64
            || !signature
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return false;
        }
        let Ok(signature) = hex::decode(signature) else {
            return false;
        };
        let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
            return false;
        };
        mac.update(body);
        mac.verify_slice(&signature).is_ok()
    }

    pub fn parse_webhook(
        &self,
        body: &[u8],
        signature: &str,
    ) -> Result<VerifiedWebhookEvent, BureauError> {
        if !self.verify_webhook(body, signature) {
            return Err(BureauError::InvalidWebhookSignature);
        }
        serde_json::from_slice(body)
            .map(VerifiedWebhookEvent)
            .map_err(|_| BureauError::InvalidWebhookEvent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference() -> Value {
        serde_json::from_str(include_str!(
            "../../../../contracts/issuance-physical-passport-native.json"
        ))
        .unwrap()
    }

    fn job(document_type: DocumentType) -> PersonalizationJob {
        PersonalizationJob {
            id: "job-1".into(),
            application_id: "application-1".into(),
            organization_id: "organization-1".into(),
            country_code: "UTO".into(),
            document_type,
            data_groups: BTreeMap::from([(1, "ZzE=".into()), (2, "ZzI=".into())]),
            sod_der_base64: "c29k".into(),
            dsc_cert_pem: "certificate".into(),
            mrz_line_1: "line-1".into(),
            mrz_line_2: "line-2".into(),
        }
    }

    #[test]
    fn all_accepted_document_types_reach_bureau_payload() {
        for (document_type, expected) in [
            (DocumentType::TD1, "TD1"),
            (DocumentType::TD2, "TD2"),
            (DocumentType::TD3, "TD3"),
        ] {
            let payload = job(document_type).payload();
            assert_eq!(payload["document_type"], expected);
            assert!(reference()["document_types"]
                .as_array()
                .unwrap()
                .contains(&Value::String(expected.into())));
            assert_eq!(payload["data_groups"], json!({"DG1":"ZzE=","DG2":"ZzI="}));
        }
    }

    #[test]
    fn bureau_status_projection_matches_frozen_route() {
        for (status, expected) in [
            (ProductionStatus::Queued, "SUBMITTED"),
            (ProductionStatus::Printing, "IN_PRODUCTION"),
            (ProductionStatus::Encoding, "IN_PRODUCTION"),
            (ProductionStatus::QualityCheck, "QUALITY_CHECK"),
            (ProductionStatus::Shipped, "READY_FOR_ACTIVATION"),
            (ProductionStatus::Delivered, "READY_FOR_ACTIVATION"),
            (ProductionStatus::Failed, "FAILED"),
            (ProductionStatus::Cancelled, "CANCELLED"),
        ] {
            assert_eq!(status.issuance_status(), expected);
            let wire_status = serde_json::to_value(status).unwrap();
            assert_eq!(
                reference()["bureau_status_projection"][wire_status.as_str().unwrap()],
                expected
            );
        }
    }

    #[test]
    fn accepted_submission_preserves_fallback_and_rejects_unknown_status() {
        let fallback =
            SubmissionOutcome::accepted(&json!({"bureau_job_id": null, "job_id": "provider-1"}))
                .unwrap();
        assert_eq!(fallback.bureau_job_id.as_deref(), Some("provider-1"));
        assert_eq!(fallback.status, ProductionStatus::Queued);
        assert!(matches!(
            SubmissionOutcome::accepted(&json!({"status": "UNRECOGNIZED"})),
            Err(BureauError::InvalidResponse(_))
        ));
    }

    #[test]
    fn webhook_signature_fails_closed() {
        for url in [
            "https://user:password@bureau.example",
            "https://bureau.example?token=secret",
            "https://bureau.example#fragment",
        ] {
            assert!(matches!(
                BureauClient::new(url, "key", Some("secret")),
                Err(BureauError::InvalidUrl)
            ));
        }
        let missing = BureauClient::new("https://bureau.example", "key", None).unwrap();
        assert!(!missing.verify_webhook(b"{}", ""));
        let configured =
            BureauClient::new("https://bureau.example", "key", Some("secret")).unwrap();
        let body = br#"{"bureau_job_id":"job-1","status":"SHIPPED"}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(body);
        let signature = hex::encode(mac.finalize().into_bytes());
        assert!(configured.verify_webhook(body, &signature));
        assert!(!configured.verify_webhook(b"{}", &signature));
        assert!(!configured.verify_webhook(body, &signature.to_uppercase()));
        assert!(!configured.verify_webhook(body, "not-hex"));
        let event = configured.parse_webhook(body, &signature).unwrap();
        assert_eq!(event.bureau_job_id(), "job-1");
        assert_eq!(event.status(), ProductionStatus::Shipped);
        assert_eq!(event.tracking_number(), None);
        assert!(matches!(
            configured.parse_webhook(b"{}", &signature),
            Err(BureauError::InvalidWebhookSignature)
        ));
    }

    #[tokio::test]
    async fn bureau_http_preserves_auth_payload_status_and_private_error_boundary() {
        use std::sync::{Arc, Mutex};

        use axum::{
            extract::{Path, State},
            http::{HeaderMap, StatusCode},
            routing::{get, post},
            Json, Router,
        };

        type Observed = Arc<Mutex<Vec<(String, String, Value)>>>;
        async fn submit(
            State(observed): State<Observed>,
            headers: HeaderMap,
            Json(payload): Json<Value>,
        ) -> (StatusCode, Json<Value>) {
            let rejected = payload["job_id"] == "private-job";
            observed.lock().unwrap().push((
                "POST".into(),
                headers["authorization"].to_str().unwrap().into(),
                payload,
            ));
            if rejected {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "private applicant details"})),
                );
            }
            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "bureau_job_id": "bureau-1",
                    "status": "SHIPPED",
                    "tracking_number": "track-1"
                })),
            )
        }
        async fn poll(
            State(observed): State<Observed>,
            Path(job_id): Path<String>,
            headers: HeaderMap,
        ) -> Json<Value> {
            observed.lock().unwrap().push((
                "GET".into(),
                headers["authorization"].to_str().unwrap().into(),
                json!({"job_id": job_id}),
            ));
            Json(json!({"status": "PRINTING", "tracking_number": "track-2"}))
        }

        let observed: Observed = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/v1/personalization/jobs", post(submit))
            .route("/v1/personalization/jobs/{job_id}", get(poll))
            .with_state(observed.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client =
            BureauClient::new(&format!("http://{address}"), "bureau-key", Some("hmac")).unwrap();

        let submitted = client.submit(&job(DocumentType::TD2)).await.unwrap();
        assert_eq!(submitted.status, ProductionStatus::Shipped);
        assert_eq!(submitted.bureau_job_id.as_deref(), Some("bureau-1"));
        assert_eq!(submitted.tracking_number.as_deref(), Some("track-1"));
        let polled = client.poll("bureau-1").await.unwrap();
        assert_eq!(polled.status, ProductionStatus::Printing);
        let mut rejected_job = job(DocumentType::TD3);
        rejected_job.id = "private-job".into();
        let rejected = client.submit(&rejected_job).await.unwrap();
        assert_eq!(rejected.status, ProductionStatus::Failed);
        assert_eq!(
            rejected.error_message.as_deref(),
            Some("Bureau returned HTTP 503")
        );
        let requests = observed.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].0, "POST");
        assert_eq!(requests[0].1, "Bearer bureau-key");
        assert_eq!(requests[0].2["document_type"], "TD2");
        assert_eq!(requests[0].2["mrz"]["line_1"], "line-1");
        assert_eq!(requests[1].0, "GET");
        assert_eq!(requests[1].1, "Bearer bureau-key");
        assert_eq!(requests[1].2["job_id"], "bureau-1");
        server.abort();
    }
}
